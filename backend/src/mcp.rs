use gritshield::mcp_tool;
use gritshield::routing::engine::RequestContext;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::state;

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct AddRuleArgs {
    pub ip: String,
    /// Seconds the rule stays active; 0 = permanent.
    #[serde(default)]
    pub duration_secs: u64,
    #[serde(default)]
    pub reason: String,
    #[serde(default = "prefix32")]
    pub prefix_len: u8,
}

fn prefix32() -> u8 {
    32
}

/// `tools/call add_firewall_rule` — insert a rule into the kernel
/// `blocklist_map` on the fly; the XDP probe starts dropping matching
/// packets at the NIC from the very next frame.
#[mcp_tool(
    name = "add_firewall_rule",
    service = "LuxShield",
    description = "Block an IP/subnet at the XDP layer for a fixed duration; packets are dropped at the NIC before the kernel stack",
    schema = r#"{
        "type": "object",
        "properties": {
            "ip":            { "type": "string", "description": "IPv4 or IPv6 address to block" },
            "duration_secs": { "type": "integer", "description": "How long the rule stays active (0 = permanent)", "minimum": 0 },
            "reason":        { "type": "string", "description": "Why the rule is being added" },
            "prefix_len":    { "type": "integer", "description": "IPv4 prefix length 0-32", "minimum": 0, "maximum": 32 }
        },
        "required": ["ip"]
    }"#,
)]
pub async fn add_firewall_rule(_ctx: &RequestContext, args: AddRuleArgs) -> Result<Value, String> {
    let st = state::resolve();

    let reason = if args.reason.is_empty() {
        "added via MCP".to_string()
    } else {
        args.reason.clone()
    };

    let rule = st
        .firewall
        .add(&args.ip, args.prefix_len, args.duration_secs, &reason, "mcp")?;

    st.store
        .ingest(&crate::types::NetEvent::block(&rule.ip, &rule.reason, "mcp"))
        .await;

    Ok(json!({ "blocked": true, "rule": rule }))
}

#[derive(Debug, Deserialize)]
pub struct ListRulesArgs {}

/// `tools/call list_firewall_rules` — active entries in the blocklist map.
#[mcp_tool(
    name = "list_firewall_rules",
    service = "LuxShield",
    description = "List the active firewall rules currently loaded into the eBPF blocklist map",
    schema = r#"{ "type": "object", "properties": {}, "required": [] }"#,
)]
pub async fn list_firewall_rules(
    _ctx: &RequestContext,
    _args: ListRulesArgs,
) -> Result<Value, String> {
    let st = state::resolve();
    let rules = st.firewall.list();
    Ok(json!({ "count": rules.len(), "rules": rules }))
}

#[derive(Debug, Deserialize)]
pub struct StatsArgs {}

/// `tools/call get_kernel_stats` — drop/pass counts, bandwidth counters and
/// map entries for desktop AI agents watching the firewall.
#[mcp_tool(
    name = "get_kernel_stats",
    service = "LuxShield",
    description = "Read XDP drop/pass counters, bandwidth totals, live stream count and blocklist map entries",
    schema = r#"{ "type": "object", "properties": {}, "required": [] }"#,
)]
pub async fn get_kernel_stats(_ctx: &RequestContext, _args: StatsArgs) -> Result<Value, String> {
    let st = state::resolve();
    let s = st.store.stats().await;
    let (kernel_name, kernel_attached) = st.firewall.kernel();

    Ok(json!({
        "ring_source": st.ring_source,
        "kernel": { "bridge": kernel_name, "attached": kernel_attached },
        "packets_total": s.pass_total + s.drop_total,
        "pass_total": s.pass_total,
        "drop_total": s.drop_total,
        "spike_total": s.spike_total,
        "block_total": s.block_total,
        "bytes_total": s.bytes_total,
        "dropped_bytes_total": s.dropped_bytes_total,
        "live_streams": s.live_streams,
        "firewall": {
            "entries": st.firewall.entry_count(),
            "map_ops": st.firewall.map_ops(),
            "kernel_ops": st.firewall.bridge_ops(),
        }
    }))
}