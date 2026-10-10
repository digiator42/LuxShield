# LuxShield

eBPF/XDP network firewall manager on the **GritShield** backend, with a metrics
pipeline that streams packet drops, passes and bandwidth spikes to connected
clients and desktop AI agents.

Layer diagram:

```
                      LINUX KERNEL SPACE
 [ Raw packets ] -->  xdp_prog (NIC)
                      ├── BLOCKLIST map   (lookup -> XDP_DROP before sk_buff)
                      └── METRICS ringbuf (every inspected packet)
                                          |
                            aya ring-buffer pump (feature `ebpf`, Linux)
                                          v
+--------------------------------------------------------------------+
| GritShield manager (backend)                                       |
| ├─ NetStore (20k ring buffer + SSE fan-out)                        |
| ├─ WAF middleware (request-burst -> blocklist map write)           |
| ├─ Firewall (user-space shadow + kernel bridge)                    |
| ├─ MCP tools (add_firewall_rule / get_kernel_stats / list rules)   |
| └─ SSE + HTTP API                                                  |
+----|---------------------------------------------------------------+
     v (SSE)
   Velo WASM frontend (future)
```

## Workspace layout

| Path          | What                                                                                                        |
| ------------- | ----------------------------------------------------------------------------------------------------------- |
| `backend/`    | GritShield manager — HTTP API, SSE stream, WAF middleware, firewall + kernel bridge, MCP tools. Works **cross-platform** with a simulator source. |
| `lux-common/` | `no_std` `#[repr(C)]` ABI (`PacketEvent`, `BlockRule`, `ABI_VERSION`) shared by probe and manager.           |
| `xdp-probe/`  | aya-bpf XDP program (Linux only). Included as a **standalone** crate so non-Linux hosts never resolve aya.   |

```bash
cargo build          # backend + lux-common (default-members); simulator source
cargo build -p luxshield-backend --features ebpf   # Linux only, adds aya bridge
```

> `xdp-probe` is its own crate on purpose. On a Linux box:
> ```bash
> cd xdp-probe && cargo +nightly build --release -Z build-std=core
> cp target/bpfel-unknown-none/release/xdp-probe target/xdp-probe.o
> cd ../backend && cargo build --features ebpf
> LUX_XDP_IFACE=eth0 LUX_XDP_OBJ=target/xdp-probe.o LUX_RING=ebpf cargo run
> ```
> Requires `bpf-linker` on PATH and root/CAP_BPF. The `aya` crate only compiles
> on Unix, so `--features ebpf` is intentionally Linux-only — **Windows/macOS**
> default builds never touch it (verified: `cargo check` of the default feature
> set is clean everywhere).

## Quick start (simulator — no kernel required)

```bash
cd backend
cargo run                        # http://127.0.0.1:8020
```

The simulator mimics the XDP probe: ordinary flows pass, anything that hits the
firewall becomes a `drop`, bursts trigger `spike` records.

```bash
# Block one synthetic client, then watch its traffic die on the SSE stream:
curl -X POST localhost:8020/api/v1/firewall/rules \
  -H 'Content-Type: application/json' \
  -d '{"ip":"10.0.0.44","duration_secs":120,"reason":"demo ban"}'
curl -N localhost:8020/api/v1/network/stream?history=20
```

To see the WAF auto-ban: keep `curl localhost:8020/health` hammering in a loop —
after `LUX_WAF_BURST` req/s the client gets written into the firewall and every
subsequent response is `403 firewall_blocked`.

## API

| Method & path                      | Purpose                                        |
| ---------------------------------- | ---------------------------------------------- |
| `GET /health`                      | Boot status, ring source (`sim`/`xdp`), kernel bridge state, counters. |
| `GET /api/v1/network/stream`       | SSE tail. Event names = `packet`/`drop`/`spike`/`block`. |
| `GET /api/v1/network/stats`        | Drop/pass counts, bytes, bandwidth spikes, map entries. |
| `GET /api/v1/firewall/rules`       | Active (non-expired) rules.                    |
| `POST /api/v1/firewall/rules`      | `{"ip","duration_secs","reason","prefix_len"}` → writes `blocklist_map`. |
| `DELETE /api/v1/firewall/rules?ip=`| Remove a rule.                                |
| `POST /mcp`                        | JSON-RPC 2.0 — see MCP tools.                  |

Full contract: [`docs/api.md`](docs/api.md).

### SSE frame

```
event: packet
data: {"ts_ms":1720524000000,"kind":"packet","ip":"10.0.0.12","port":443,
       "protocol":"tcp","bytes":742,"action":"pass","source":"sim"}
...
event: drop
data: {"ts_ms":...,"kind":"drop","ip":"10.0.0.44","action":"drop","reason":"demo ban","source":"xdp"}
event: spike
data: {"ts_ms":...,"kind":"spike","bps":672000,"pps":60}
event: block
data: {"ts_ms":...,"kind":"block","ip":"203.0.113.66","reason":"waf: request burst (>10 req/s)","source":"waf"}
```

Query params: `history` (default 50, max 1000), `since` (epoch-ms), `api_key`.
History is replayed **newest-first** on attach.

### MCP tools (desktop AI agents)

| Tool                 | Args                                          |
| -------------------- | --------------------------------------------- |
| `add_firewall_rule`  | `ip`, `duration_secs`, `reason`, `prefix_len` — on-the-fly kernel map mutation. |
| `get_kernel_stats`   | `{}` — counters, spikes, stream count, map entries. |
| `list_firewall_rules`| `{}` — active entries.                        |

### WAF behaviour

`WafMiddleware::on_request` counts requests per source IP over a 1 s window.
Over the threshold, the IP is added to the firewall (⇒ `blocklist_map`),
a `block` SSE event is emitted, and the response is `403 waf_blocked`.
`FirewallMiddleware` separately 403s any request whose source is already in the
firewall, so an XDP-blocked client can never even reach the HTTP listener.

## Configuration

| Env var            | Default        | Meaning                                         |
| ------------------ | -------------- | ----------------------------------------------- |
| `LUX_BIND`         | `127.0.0.1`    | Bind address.                                   |
| `LUX_PORT`         | `8020`         | Bind port.                                      |
| `LUX_API_KEY`      | *(none)*       | When set, require `X-API-Key` or `?api_key=`.   |
| `LUX_RING`         | `sim`          | `sim` or `ebpf` (feature + Linux).              |
| `LUX_SIM_PPS`      | `20`           | Simulator baseline packets/sec.                 |
| `LUX_SPIKE_BPS`    | `250000`       | Bandwidth threshold that triggers `spike`.      |
| `LUX_WAF_BURST`    | `60`           | Requests/sec that trips the WAF.                |
| `LUX_WAF_BAN_SECS` | `60`           | WAF ban duration (0 = permanent).               |
| `LUX_XDP_IFACE`    | *(required)*   | NIC to attach the probe (`ebpf` mode).          |
| `LUX_XDP_OBJ`      | `target/xdp-probe.o` | Built probe object file (`ebpf` mode).    |

## Security posture

- CORS: `*` preflight short-circuits before authentication.
- `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`,
  `Cache-Control`, `Server` hardening via `HttpSecurityMiddleware`.
- Firewall + WAF operate at the kernel layer on Linux — the HTTP layer is a
  consistency mirror, not the enforcement point.