# Performance and scale

Measured behaviour against the 1.0 scale targets (ASR-P1: 1000 virtual
hosts and 10 000 upstream endpoints; ASR-P2: sustained high request
rates). Numbers are from the reference runs described below; rerun them
with `make scale`, `make bench` and `make load` and update this file when
the hot path changes.

## Reference environment

| Item | Value |
|------|-------|
| Host | 4 vCPU Intel Xeon 2.10 GHz, 15 GiB, Linux 6.18, container |
| Go | 1.25.0, `CGO_ENABLED=0`, `-trimpath` |
| Commit | see CHANGELOG (phase 3 scale validation) |
| Layout | load generator, backend and proxy on the same 4 cores (see the caveat below) |

The 100 000 requests per second on 8 cores figure in ASR-P2 is a target
for the reference hardware (a dedicated 8 core host with the generator
and the backend elsewhere); it has not been measured yet and is recorded
as open in ROADMAP.md. Everything below was measured.

## Configuration scale (`make scale`)

`TestScale` with `XPROXY_SCALE=full` generates 1000 hosts over 500
upstreams of 20 endpoints (10 000 distinct loopback addresses, active
health checks every 2 s), loads it into a real `Server`, checks routing
across the table, reads the management views, reloads, then drives
traffic over random hosts. The backend runs in a child process so that
its accepted sockets do not share the proxy's descriptor limit.

| Measurement | 100 hosts, 1000 endpoints | 1000 hosts, 10 000 endpoints |
|-------------|---------------------------|------------------------------|
| Configuration size | 52 KiB YAML | 535 KiB YAML |
| Parse and validate | 51 ms | 46 ms |
| Build generation and start | 10 ms | 22 ms |
| Heap after load | +1 MiB | +15 MiB |
| Goroutines after load | +1003 | +10 058 (one health loop per endpoint) |
| Descriptors after load | 12 | 39 (probes hold none between runs) |
| Reload (full generation rebuild) | 8 ms | 9 ms |
| `/v1/upstreams` | 120 KiB, 8 ms | 1.2 MiB, 6 ms |
| `/metrics` with `endpoint_series` | 1.0 MiB, 15 541 lines, 101 ms | 10.6 MiB, 154 141 lines, 374 ms |
| `/metrics` without `endpoint_series` | 28 KiB, 541 lines, 11 ms | 229 KiB, 4141 lines, 3 ms |
| Heap after 5 s of traffic across all hosts | 19 MiB | 159 MiB (10 000 idle upstream connections) |
| Descriptors after traffic | 1048 | 10 054 |

What this establishes:

- Loading and reloading are linear and fast at the target size; a reload
  costs a few milliseconds regardless of table size because the old
  generation is swapped atomically and drained in the background.
- Memory at rest is dominated by health loops (about 1.5 KiB each). Under
  traffic it is dominated by idle upstream connections: budget about
  15 KiB per endpoint the proxy has talked to (two goroutines and two
  4 KiB buffers per pooled connection), bounded by
  `max_idle_conns_per_host` times endpoints per pool and released after
  `timeouts.idle`.
- Descriptors: one per idle upstream connection plus one per client
  connection. The unit sets `LimitNOFILE=1048576`; a source install must
  raise the limit itself (HARDENING.md).
- Per-endpoint metrics cost about 1 KiB per endpoint per scrape; above a
  few thousand endpoints set `metrics.endpoint_series: false` and use the
  per-pool `xproxy_upstream_endpoints_healthy` gauge.

Two defects found and fixed by this run: a superseded generation kept
probing every endpoint until it was drained (now probing stops at the
swap), and probes had no process-wide bound (now 512 in flight across all
pools, plus `max_concurrent` per pool).

## Routing (`make bench`)

| Benchmark | Result |
|-----------|--------|
| `BenchmarkMatch` (small table) | about 20 ns/op, 0 allocations |
| `BenchmarkMatch1000Hosts` | 21.7 ns/op, 0 allocations |
| `BenchmarkNew1000Hosts` (compile 3000 entries) | 0.64 ms, 565 KiB |

Host lookup is two map probes and path matching a scan of that host's
few prefixes, so the table size does not show in the per-request cost.

## Throughput and latency (`make load`)

vegeta against the real binary, `test/load/xproxy.yaml` (plaintext
HTTP/1.1, keep-alive, 1 KiB responses, access log off, no WAF), 128
connections, 10 s per rate, generator and backend on the same 4 cores as
the proxy.

| Offered rate | Achieved | p50 | p90 | p99 | max | Errors |
|--------------|----------|-----|-----|-----|-----|--------|
| 5 000 req/s | 5 000 | 0.44 ms | 0.98 ms | 2.7 ms | 38.6 ms | 0 |
| 10 000 req/s | 10 000 | 1.26 ms | 3.67 ms | 9.7 ms | 44.9 ms | 0 |
| 20 000 req/s | 12 900 (saturated) | 8.7 ms | 14.9 ms | 21.4 ms | 34.6 ms | 0 |
| open loop, 64 workers | 11 900 | 4.9 ms | 8.1 ms | 11.7 ms | 19.2 ms | 0 |

Proxy resident memory during the runs: 32 MiB. The proxy, the generator
and the backend each took roughly a third of the four cores, so the
proxy's own ceiling on this box is above 12 900 req/s; the per-request
CPU cost is what transfers to other hardware, about 80 µs of one core per
request here including the kernel's share of two TCP connections. The
in-process run of `TestScale` (16 client goroutines competing with the
proxy and 10 000 health loops) reached 8 500 req/s at p50 1.2 ms.

## What is not measured yet

- The 8 core reference number with the generator on another host.
- TLS and HTTP/2 termination cost, HTTP/3, WAF cost per request (CRS on
  a request with a body), access log on, rate limits on every request.
- The 24 hour soak (`test/load/soak.sh`); the script and the runtime
  metrics it needs (`go_goroutines`, `go_memstats_*`, `process_open_fds`)
  are in place.

These are the load test items that stay open in ROADMAP.md.
