// Dedicated Web Worker that runs the LuxShield packet-aggregation engine
// off the UI thread.
//
// Trunk copies this file next to the hashed wasm glue. The main thread sends
// {type:"init", jsUrl, wasmUrl} so the hashed module/filename never needs to be
// hardcoded here; every message that arrives before the module finishes loading
// is queued and replayed in order once it is ready.
//
// Scoring batches arrive as JSON strings: {type:"score", rows:[...]}.

let mod = null;
let pending = [];

// A control message is either an already-parsed object or a JSON string.
function asMessage(data) {
  if (typeof data === "string") {
    try {
      return JSON.parse(data);
    } catch {
      return null;
    }
  }
  return data;
}

function dispatch(data) {
  const msg = asMessage(data);
  if (!msg) return;

  if (msg.type === "reset") {
    mod.worker_reset();
  } else if (msg.type === "score") {
    // Hand the raw JSON straight through; the wasm side parses it.
    const out = mod.worker_score(typeof data === "string" ? data : JSON.stringify(data));
    if (out) self.postMessage(out);
  }
}

self.onmessage = async function (e) {
  if (mod) {
    dispatch(e.data);
    return;
  }

  pending.push(e.data);

  const msg = asMessage(e.data);
  if (msg && msg.type === "init") {
    try {
      mod = await import(new URL(msg.jsUrl, self.location.href).href);
      const wasmUrl = msg.wasmUrl
        ? new URL(msg.wasmUrl, self.location.href).href
        : undefined;
      await mod.default(wasmUrl ? { module_or_path: wasmUrl } : undefined);
      mod.worker_start();
      self.postMessage(JSON.stringify({ type: "ready" }));

      const queued = pending;
      pending = [];
      for (const m of queued) {
        if (asMessage(m)?.type === "init") continue;
        dispatch(m);
      }
    } catch (err) {
      self.postMessage(JSON.stringify({ type: "error", message: String(err) }));
    }
  }
};
