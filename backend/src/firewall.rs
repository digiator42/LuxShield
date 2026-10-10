use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lux_common::{BlockRule, LUX_ACTION_DROP};

/// Bridge to the kernel `blocklist_map`. The null implementation is used in
/// simulator mode; the aya implementation (Linux, feature `ebpf`) performs the
/// `bpf_map_update_elem` / `bpf_map_delete_elem` calls that make the XDP
/// program drop traffic at the NIC.
pub trait KernelBridge: Send + Sync {
    fn attached(&self) -> bool;
    fn name(&self) -> &'static str;
    /// Returns `Ok(true)` when the entry reached the kernel.
    fn upsert(&self, key: u32, rule: &BlockRule) -> Result<bool, String>;
    fn remove(&self, key: u32) -> Result<bool, String>;
}

/// Simulator / probe-not-loaded bridge: user-space only.
pub struct NullBridge;

impl KernelBridge for NullBridge {
    fn attached(&self) -> bool {
        false
    }
    fn name(&self) -> &'static str {
        "simulated"
    }
    fn upsert(&self, _key: u32, _rule: &BlockRule) -> Result<bool, String> {
        Ok(false)
    }
    fn remove(&self, _key: u32) -> Result<bool, String> {
        Ok(false)
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct RuleInfo {
    pub ip: String,
    pub prefix_len: u8,
    pub reason: String,
    pub added_by: String,
    pub added_at_ms: f64,
    /// `None` = never expires.
    pub expires_at_ms: Option<f64>,
    /// True when the rule currently exists in the kernel `blocklist_map`.
    pub kernel_synced: bool,
}

pub struct Firewall {
    rules: Mutex<HashMap<String, RuleInfo>>,
    bridge: Mutex<Arc<dyn KernelBridge>>,
    /// Total kernel map mutations performed (updates + deletes).
    map_ops: AtomicU64,
    bridge_ops: AtomicU64,
}

impl Firewall {
    pub fn new(bridge: Arc<dyn KernelBridge>) -> Self {
        Self {
            rules: Mutex::new(HashMap::new()),
            bridge: Mutex::new(bridge),
            map_ops: AtomicU64::new(0),
            bridge_ops: AtomicU64::new(0),
        }
    }

    /// Swap in the real kernel bridge once the XDP probe has been loaded.
    #[cfg_attr(not(all(feature = "ebpf", target_os = "linux")), allow(dead_code))]
    pub fn set_bridge(&self, bridge: Arc<dyn KernelBridge>) {
        if let Ok(mut slot) = self.bridge.lock() {
            *slot = bridge;
        }
    }

    fn bridge(&self) -> Arc<dyn KernelBridge> {
        self.bridge
            .lock()
            .map(|b| b.clone())
            .unwrap_or_else(|_| Arc::new(NullBridge))
    }

    /// IPv4 key matching the probe's `u32` big-endian network-order key.
    fn v4_key(ip: &str) -> Option<u32> {
        Ipv4Addr::from_str(ip).ok().map(u32::from)
    }

    /// Add (or refresh) a rule. `duration_secs = 0` means permanent.
    ///
    /// The kernel entry is scheduled for deletion when it expires — the probe
    /// stores `expires_at_ns = 0` because wall-clock time in user space is not
    /// the same clock as `bpf_ktime_get_ns()`, so this side owns expiry.
    pub fn add(
        self: &Arc<Self>,
        ip: &str,
        prefix_len: u8,
        duration_secs: u64,
        reason: &str,
        added_by: &str,
    ) -> Result<RuleInfo, String> {
        let ip = ip.trim();
        if ip.is_empty() {
            return Err("ip must not be empty".to_string());
        }
        // Validate the address; IPv6 is enforced user-space only for now.
        if Ipv4Addr::from_str(ip).is_err() && std::net::Ipv6Addr::from_str(ip).is_err() {
            return Err(format!("invalid ip address: {ip}"));
        }
        if prefix_len > 32 {
            return Err("prefix_len must be <= 32".to_string());
        }

        let now = crate::types::now_ms_f64();
        let expires_at_ms = (duration_secs > 0).then_some(now + duration_secs as f64 * 1000.0);

        let mut kernel_synced = false;
        if let Some(key) = Self::v4_key(ip) {
            let rule = BlockRule {
                prefix_len,
                action: LUX_ACTION_DROP,
                expires_at_ns: 0, // user-space scheduler owns expiry
                reason: {
                    let mut r = [0u8; 32];
                    for (dst, src) in r.iter_mut().zip(reason.as_bytes()) {
                        *dst = *src;
                    }
                    r
                },
                _pad: [0; 7],
            };
            let bridge = self.bridge();
            kernel_synced = bridge.upsert(key, &rule).unwrap_or(false);
            self.map_ops.fetch_add(1, Ordering::Relaxed);
            if kernel_synced {
                self.bridge_ops.fetch_add(1, Ordering::Relaxed);
            }
        }

        let info = RuleInfo {
            ip: ip.to_string(),
            prefix_len,
            reason: reason.to_string(),
            added_by: added_by.to_string(),
            added_at_ms: now,
            expires_at_ms,
            kernel_synced,
        };

        if let Ok(mut rules) = self.rules.lock() {
            rules.insert(ip.to_string(), info.clone());
        }

        // Expiry: sleep then delete from both the shadow map and the kernel.
        if let Some(expiry) = expires_at_ms {
            let remaining = (expiry - now).max(0.0) as u64;
            let this = self.clone();
            let owned_ip = ip.to_string();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(remaining)).await;
                let _ = this.remove(&owned_ip);
            });
        }

        Ok(info)
    }

    /// Remove a rule. Returns `true` if it existed.
    pub fn remove(&self, ip: &str) -> Result<bool, String> {
        let removed = self
            .rules
            .lock()
            .ok()
            .and_then(|mut rules| rules.remove(ip));
        let Some(rule) = removed else {
            return Ok(false);
        };

        if let Some(key) = Self::v4_key(ip) {
            let bridge = self.bridge();
            let synced = bridge.remove(key).unwrap_or(false);
            self.map_ops.fetch_add(1, Ordering::Relaxed);
            if synced {
                self.bridge_ops.fetch_add(1, Ordering::Relaxed);
            }
            let _ = rule;
        }
        Ok(true)
    }

    /// User-space membership test (drives WAF/firewall middleware + sim drops).
    pub fn contains(&self, ip: &str) -> bool {
        let Ok(rules) = self.rules.lock() else {
            return false;
        };
        match rules.get(ip) {
            Some(rule) => rule
                .expires_at_ms
                .map(|e| crate::types::now_ms_f64() < e)
                .unwrap_or(true),
            None => false,
        }
    }

    /// Reason text for an active rule (used to label drop events).
    pub fn reason(&self, ip: &str) -> Option<String> {
        if !self.contains(ip) {
            return None;
        }
        self.rules
            .lock()
            .ok()
            .and_then(|rules| rules.get(ip).map(|r| r.reason.clone()))
    }

    pub fn list(&self) -> Vec<RuleInfo> {
        let now = crate::types::now_ms_f64();
        let Ok(rules) = self.rules.lock() else {
            return Vec::new();
        };
        let mut all: Vec<RuleInfo> = rules
            .values()
            .filter(|r| r.expires_at_ms.map(|e| now < e).unwrap_or(true))
            .cloned()
            .collect();
        all.sort_by(|a, b| a.added_at_ms.partial_cmp(&b.added_at_ms).unwrap());
        all
    }

    pub fn entry_count(&self) -> usize {
        self.list().len()
    }

    pub fn kernel(&self) -> (String, bool) {
        let bridge = self.bridge();
        (bridge.name().to_string(), bridge.attached())
    }

    pub fn map_ops(&self) -> u64 {
        self.map_ops.load(Ordering::Relaxed)
    }

    pub fn bridge_ops(&self) -> u64 {
        self.bridge_ops.load(Ordering::Relaxed)
    }
}