# Load tests

External load generation against the real binary. The in-process scale
test (`make scale`, `internal/proxy/scale_test.go`) covers the
configuration size targets; this directory covers throughput and latency,
and the soak run for leaks. Results are recorded in
[docs/PERFORMANCE.md](../../docs/PERFORMANCE.md).

## Layout

| File | Purpose |
|------|---------|
| `backend/main.go` | Minimal upstream: fixed body, echoes `Host`, binds the wildcard address so `127.x.y.z` endpoints all reach it |
| `xproxy.yaml` | Proxy configuration for the runs: one plaintext listener on `127.0.0.1:18080`, four endpoints on the backend, access log off, no WAF |
| `vegeta.sh` | Constant rate run with [vegeta](https://github.com/tsenart/vegeta) |
| `k6.js` | The same as a [k6](https://k6.io) scenario with thresholds |
| `soak.sh` | Hours of moderate load with a per-minute sample of heap, goroutines and descriptors from `/metrics` |

## Running

```sh
go install github.com/tsenart/vegeta/v12@latest
make load RATE=10000 DURATION=30s        # backend + proxy + vegeta, then stats
```

By hand, to vary the configuration (WAF on, access log on, TLS, HTTP/2):

```sh
mkdir -p /tmp/xproxy-load/logs
go run ./test/load/backend -listen 0.0.0.0:9001 &
./bin/xproxy -config test/load/xproxy.yaml &
test/load/vegeta.sh 10000 30s 128
k6 run -e RATE=10000 -e DURATION=30s test/load/k6.js
./bin/xproxyctl -socket /tmp/xproxy-load/mgmt.sock stats
```

Find the ceiling with an open loop: `echo 'GET http://127.0.0.1:18080/' |
vegeta attack -rate=0 -max-workers=64 -duration=30s | vegeta report`.

Soak: `test/load/soak.sh 24 2000` writes `/tmp/xproxy-load/soak.csv`;
heap and goroutines must plateau, descriptors settle at the idle
connection count.

## Rules for a number that means something

- Load generator, backend and proxy on separate hosts or at least pinned
  to separate cores (`taskset`); on a shared box the generator and the
  backend take most of the CPU and the proxy's ceiling is understated.
- Keep-alive on; the target is the proxy path, not TCP handshakes. Run a
  second series with `-keepalive=false` if connection churn matters.
- Record kernel, CPU model, core count, Go version, the commit and the
  exact configuration next to every result.
- Sustained runs of at least 30 seconds; discard the first run after a
  start (health checks and pools warm up).
