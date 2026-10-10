use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use gritshield::http::SseStream;
use tokio::sync::Mutex;

use crate::types::NetEvent;

/// Maximum number of records retained for replay on stream attach.
pub const HISTORY_CAPACITY: usize = 20_000;

/// A newly-registered SSE stream is given this long to attach a subscriber
/// before it becomes a prune candidate (mirrors logs-soc's grace period).
const STREAM_ATTACH_GRACE: Duration = Duration::from_secs(5);

struct RegisteredStream {
    sse: SseStream,
    since: Instant,
}

struct NetStoreInner {
    history: VecDeque<NetEvent>,
    streams: Vec<RegisteredStream>,
    attached_total: u64,
    pass_total: u64,
    drop_total: u64,
    spike_total: u64,
    block_total: u64,
    bytes_total: u64,
    dropped_bytes_total: u64,
}

/// Aggregate counters surfaced by `/api/v1/network/stats`.
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct NetStoreStats {
    pub history_count: usize,
    pub live_streams: usize,
    pub attached_total: u64,
    pub pass_total: u64,
    pub drop_total: u64,
    pub spike_total: u64,
    pub block_total: u64,
    pub bytes_total: u64,
    pub dropped_bytes_total: u64,
}

/// Shared in-memory pipeline: bounded replay buffer plus live SSE fan-out.
#[derive(Clone)]
pub struct NetStore {
    inner: Arc<Mutex<NetStoreInner>>,
}

impl NetStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(NetStoreInner {
                history: VecDeque::with_capacity(HISTORY_CAPACITY),
                streams: Vec::new(),
                attached_total: 0,
                pass_total: 0,
                drop_total: 0,
                spike_total: 0,
                block_total: 0,
                bytes_total: 0,
                dropped_bytes_total: 0,
            })),
        }
    }

    /// Most recent first, newest at index 0.
    pub async fn history(&self, limit: usize) -> Vec<NetEvent> {
        let guard = self.inner.lock().await;
        guard
            .history
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    /// Attach a new consumer stream (the caller also hands its copy to
    /// `Response::sse`); `ingest` broadcasts on this copy.
    pub async fn attach(&self, stream: SseStream) {
        let mut guard = self.inner.lock().await;
        guard.streams.push(RegisteredStream {
            sse: stream,
            since: Instant::now(),
        });
        guard.attached_total += 1;
    }

    /// Push a record into the ring buffer and fan it out to live consumers.
    /// The SSE event name is the record's `kind`. Returns consumer count.
    pub async fn ingest(&self, event: &NetEvent) -> usize {
        let mut guard = self.inner.lock().await;
        match event.kind.as_str() {
            "packet" => {
                guard.pass_total += 1;
                if let Some(b) = event.bytes {
                    guard.bytes_total += b as u64;
                }
            }
            "drop" => {
                guard.drop_total += 1;
                guard.dropped_bytes_total += event.bytes.unwrap_or(0) as u64;
            }
            "spike" => guard.spike_total += 1,
            "block" => guard.block_total += 1,
            _ => {}
        }

        if guard.history.len() >= HISTORY_CAPACITY {
            guard.history.pop_front();
        }
        guard.history.push_back(event.clone());

        guard
            .streams
            .retain(|s| s.since.elapsed() < STREAM_ATTACH_GRACE || s.sse.listeners() > 0);

        let payload = serde_json::to_string(event).unwrap_or_default();
        let mut live = 0usize;
        for registered in &guard.streams {
            if let Ok(n) = registered.sse.send(&event.kind, &payload) {
                live += n;
            }
        }
        live
    }

    pub async fn stats(&self) -> NetStoreStats {
        let guard = self.inner.lock().await;
        NetStoreStats {
            history_count: guard.history.len(),
            live_streams: guard.streams.len(),
            attached_total: guard.attached_total,
            pass_total: guard.pass_total,
            drop_total: guard.drop_total,
            spike_total: guard.spike_total,
            block_total: guard.block_total,
            bytes_total: guard.bytes_total,
            dropped_bytes_total: guard.dropped_bytes_total,
        }
    }
}

impl Default for NetStore {
    fn default() -> Self {
        Self::new()
    }
}