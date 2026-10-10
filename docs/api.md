# LuxShield API contract

Backend: GritShield manager at `backend/`. Port 8020 by default (`LUX_PORT`).
All JSON endpoints. `api_key` via `X-API-Key` header or `?api_key=` query
(only when `LUX_API_KEY` is set).

## Endpoints

### `GET /health`

```json
{
  "service": "luxshield-backend",
  "status": "ok",
  "ring_source": "sim",
  "kernel": { "bridge": "simulated", "attached": false },
  "buffers": {
    "history_count": 56,
    "history_capacity": 20000,
    "live_streams": 0,
    "attached_total": 0
  },
  "firewall": { "entries": 0, "map_ops": 0 }
}
```

200 = up. `kernel.attached` is `true` only when the XDP probe is live
(feature `ebpf` + `LUX_RING=ebpf`).

### `GET /api/v1/network/stream`

Server-Sent Events tail. Replays the newest `history` records
(default 50, max 1000, optional `since=<epoch-ms>`) then live records. The SSE
event name equals the record `kind`.

**`event: packet`** — an accepted frame:

```json
{"ts_ms":1720524000000,"kind":"packet","ip":"10.0.0.12","port":443,
 "protocol":"tcp","bytes":742,"action":"pass","source":"sim"}
```

**`event: drop`** — a frame dropped (firewall match, sim or xdp):

```json
{"ts_ms":1720524000000,"kind":"drop","ip":"10.0.0.44","port":443,
 "protocol":"tcp","bytes":1400,"action":"drop","reason":"demo ban","source":"xdp"}
```

**`event: spike`** — a bandwidth spike crossing `LUX_SPIKE_BPS`:

```json
{"ts_ms":1720524000000,"kind":"spike","bps":672000,"pps":60,
 "reason":"bandwidth threshold exceeded","source":"pipeline"}
```

**`event: block`** — a firewall rule just landed (API / MCP / WAF):

```json
{"ts_ms":1720524000000,"kind":"block","ip":"127.0.0.1","action":"drop",
 "reason":"waf: request burst (>10 req/s)","source":"waf"}
```

`ip` formats: dotted-quad for IPv4 (probe stores IPv4 as IPv4-mapped IPv6),
colon-hex for IPv6. `ts_ms` is epoch milliseconds as float.

### `GET /api/v1/network/stats`

```json
{
  "packets_total": 240,
  "pass_total": 229,
  "drop_total": 11,
  "spike_total": 2,
  "block_total": 2,
  "bytes_total": 191479,
  "dropped_bytes_total": 8252,
  "live_streams": 0,
  "history_count": 244,
  "kernel": { "bridge": "simulated", "attached": false },
  "firewall": { "entries": 1, "map_ops": 3, "kernel_ops": 0 }
}
```

### `GET /api/v1/firewall/rules`

```json
{
  "count": 1,
  "rules": [
    {
      "ip": "10.0.0.44",
      "prefix_len": 32,
      "reason": "demo ban",
      "added_by": "api",
      "added_at_ms": 1720524000000.0,
      "expires_at_ms": 1720524120000.0,
      "kernel_synced": false
    }
  ]
}
```

`expires_at_ms` is `null` for permanent rules; `kernel_synced` is `true` when
the rule actually reached `blocklist_map` in the kernel.

### `POST /api/v1/firewall/rules`

Body:

```json
{ "ip": "203.0.113.66", "duration_secs": 120, "reason": "incident xyz", "prefix_len": 32 }
```

201 → the created `{ "rule": { ... } }`. 400 for invalid IP/prefix.
The rule is immediately pushed into the kernel `blocklist_map` (feature `ebpf`,
Linux), where the XDP program starts dropping matching packets at the NIC from
the next frame. A `block` SSE event is emitted. `duration_secs = 0` = permanent.

### `DELETE /api/v1/firewall/rules?ip=203.0.113.66`

```json
{ "removed": true, "ip": "203.0.113.66" }
```

`removed: false` when no such rule existed. Also deletes the kernel entry.

## MCP (`POST /mcp`, JSON-RPC 2.0)

### tools/list

`add_firewall_rule`, `get_kernel_stats`, `list_firewall_rules`.

### tools/call add_firewall_rule

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call",
 "params":{"name":"add_firewall_rule",
           "arguments":{"ip":"203.0.113.66","duration_secs":60,"reason":"mcp ban"}}}
```

### tools/call get_kernel_stats

Same shape as `/api/v1/network/stats`, returned inside the MCP result envelope
(`structuredContent` for machine readers, `content[].text` for LLM previews).

## Error semantics

- `401 unauthorized` — missing/bad API key.
- `403 firewall_blocked` — source IP is in the firewall (mirror of the kernel drop).
- `403 waf_blocked` — the WAF just banned this client.
- `400 invalid_rule` / `invalid_json` — malformed request.
- `413` — payload too large (not currently exposed; bodies are capped at 1 MiB).
- Non-GET request bodies larger than 1 MiB are rejected by the framework.

## Notes for the frontend

- **Base URL.** The console calls the backend directly at
  `BASE_URL = "http://127.0.0.1:8020"` (`frontend/src/api.rs`), which works with
  the default compose (backend published on `8020:8020`). nginx only serves the
  static console — it does **not** proxy the API, so relative/same-origin paths
  will 404 unless a proxy is added. There is no nginx `/api` proxy today.
- **Live-XDP overlay caveat (Linux only).** `docker-compose.ebpf.yml` runs the
  backend with `network_mode: host`, which drops the published port; under
  Docker Desktop/WSL2 the browser then cannot reach `127.0.0.1:8020` and the
  console shows `rules sync: Failed to fetch`. Use the overlay only on a real
  Linux host (browser and backend share the host netns), or point `BASE_URL` at
  the host the backend is reachable on.
- Derive URLs with `with_base(path)` (empty base → path unchanged, so a future
  same-origin deploy only needs `BASE_URL = ""` + an nginx proxy). API key
  travels as `?api_key=` because `EventSource` cannot carry the `X-API-Key` header.
- `history` replay is **newest-first**; the terminal shows the stream tail
  directly, but reverse before charting/ordering.
- Compare `ts_ms` numerically (float). SSE keep-alive comment frames (15 s) are
  noise and can be ignored.
- `EventSource` (browser) reconnects on its own; track `open`/`error` only.
- WAF bans apply per source IP; a banned viewer gets `403` on *every* endpoint,
  including the stream. Unban via `DELETE /api/v1/firewall/rules?ip=...` (or MCP).
- Response shapes consumed by the console: `GET /health` →
  `ring_source`, `kernel.{bridge,attached}`; `GET /stats` →
  `{pass_total, drop_total, spike_total, block_total, bytes_total}`;
  `GET /firewall/rules` → `{ rules: [ {ip, prefix_len, reason, added_by,
  added_at_ms, expires_at_ms, kernel_synced} ] }` (tolerate missing fields).
- Rules are polled (no push channel) — re-fetch on a timer and after
  add/delete; the SSE `block` event is the only live rule signal.