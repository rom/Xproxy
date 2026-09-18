# Tests

The test harness covers unit, integration, end-to-end, fuzz, race, lint
and vulnerability checks. This document describes what exists, how to run
it, what each layer is responsible for and what is added in later phases.

## Running

| Command | What it does |
|---------|--------------|
| `make test` | Unit and integration tests |
| `make test-race` | Same under the race detector (the CI default) |
| `make cover` | Coverage profile under race; prints total |
| `make fuzz FUZZTIME=30s` | Runs every `Fuzz*` target for the given budget |
| `make lint` | `golangci-lint` with the configuration in `.golangci.yml` |
| `make vet`, `make fmt` | `go vet`, formatting check |
| `make vuln` | `govulncheck` |
| `make check` | fmt, vet, race tests, lint |
| `go test -run TestProxyBasics -v ./internal/proxy/` | One test with output |
| `go test -bench . -benchmem ./internal/router/` | Router benchmark |

Tests need no network access beyond loopback and no root. They pick free
ports by listening on port 0 and reading the bound address back from the
server.

## Layers

### Unit tests

| Package | Tests | Focus |
|---------|-------|-------|
| `internal/config` | `TestMinimalDefaults`, `TestRejects` (25 rejection cases), `TestMultipleErrorsReported`, `TestZeroTimeoutMeansDefault`, `TestDuration`, `TestRateLimitDefaults`, `TestHostPattern`, `TestExampleConfig` | Defaults, every validation rule, error aggregation, the shipped example |
| `internal/router` | `TestMatch`, `TestNoMatch`, `BenchmarkMatch` | Exact versus wildcard host precedence, longest prefix, segment boundaries, methods, priority |
| `internal/netutil` | `TestClientIP`, `TestCleanPath`, `TestHost` | Trusted proxy algorithm including malformed hops and IPv4 mapped addresses; traversal normalisation; host normalisation |
| `internal/limits` | `TestKeyedLimiter`, `TestKeyedLimiterBound`, `TestConcurrency`, `TestConnLimiter` | Refill arithmetic with a fake clock, memory bound and eviction, release idempotency, real sockets dropped at accept |
| `internal/tlsconf` | `TestServer`, `TestClient` | SNI selection, hardening flags, insecure suite rejection, double opt-in |
| `internal/upstream` | `TestRoundRobin`, `TestWeighted`, `TestLeastConn`, `TestHashRing`, `TestAffinity`, `TestOutlierEjection`, `TestActiveHealthCheck` | Balancer semantics including smooth weighting and minimal key movement on the ring; cookie tamper and expiry; ejection percentage; health state transitions against a real HTTP server |
| `internal/logging` | `TestOpenAndWrite`, `TestRotate` | JSON single line, level filter, file mode, injection safety, rotation chain |
| `internal/mgmt` | `TestManagementAPI`, `TestBanAPI` | Socket mode, status, actions, error propagation, 501 for missing actions, in-use socket refusal; ban list, add, refuse loopback and bad durations, remove, counters |
| `internal/ban` | `TestTriggerAndEscalation`, `TestWindowReset`, `TestExemptAndManual`, `TestBound`, `TestPersistence`, `TestReconfigure` | Trigger thresholds and reason filters, escalation and cap with a fake clock, window reset, exemptions, refusal of loopback and wide prefixes, CIDR bans, IPv4 mapped lookups, table bound, bbolt round trip including expiry and unban, reconfiguration keeps state |
| `internal/waf` | `TestBlockSQLi`, `TestDetectMode`, `TestCleanRequestPasses`, `TestBodyInspectionAndReplay`, `TestBodyLimitReject`, `TestResponseInspection`, `TestCustomDirectivesAndBadRules`, `TestOnlyNeededModesCompiled` | CRS blocks injection in query and body, detect mode logs without denying, clean traffic produces no attributes, inspected bodies are replayed intact, 413 above the body limit, response leakage blocked and clean or oversize responses pass intact, custom SecLang rules, compile errors surface, lazy compilation per mode |

### Integration tests (in `internal/proxy`)

These start a full `Server` on loopback with real `httptest` backends and
drive it with `net/http` and raw TCP.

| Test | Covers |
|------|--------|
| `TestProxyBasics` | Routing, strip prefix, header operations, forwarding headers with trusted and untrusted peers, traversal, no route, method filter, round robin distribution, dead upstream 502, rate limit 429 with `Retry-After`, tarpit delay, ACL 403, WebSocket refusal, redirect and respond actions, body limit 413, sticky cookie attributes and stickiness, URI length 414, counters and upstream statistics |
| `TestRetryOnDeadEndpoint` | Retry to a second endpoint, outlier ejection of the dead one, no replay of POST |
| `TestReload` | Generation swap changes routing, listener change refused, reload counters |
| `TestTLSAndRedirect` | HTTP to HTTPS 308 preserving path and query, TLS 1.3 with HTTP/2 negotiated, `X-Forwarded-Proto`, TLS 1.2 refused when the minimum is 1.3 |
| `TestConnectionLimits` | Concurrency 503 on a live connection, third connection dropped at accept, counters |
| `TestSlowHeaderTimeout` | Slowloris connection closed by the header timeout |
| `TestWAFIntegration` | Block, detect and off modes per route, custom profile status, body inspected and forwarded, injection in body blocked, counters |
| `TestBanIntegration` | WAF denies trigger a ban that applies before routing, other clients unaffected, exempt range never banned, rate limit denies feed the catch-all trigger, manual CIDR ban and unban |
| `TestBanDropsConnectionAtAccept` | Accept hook sees bans; loopback refusal |
| `TestBansSurviveReload` | Reload keeps active bans; removing the section drops the list |

### Fuzz targets

| Target | Input | Property |
|--------|-------|----------|
| `config.FuzzParse` | arbitrary bytes | never panics; nil config implies error |
| `router.FuzzMatch` | host, path, method | never panics on any strings |
| `netutil.FuzzCleanPath` | path | output always starts with `/` |
| `netutil.FuzzHost` | host header | never panics |

Fuzz corpora that find failures are committed under `testdata/fuzz`.

### Static and supply chain

`golangci-lint` (errcheck, gosec, staticcheck, govet, bodyclose, noctx,
errorlint, gocritic and more), `go vet`, `gofmt`, `govulncheck`. All run in
CI (`.github/workflows/ci.yml`) on every push and pull request.

## Coverage

Current statement coverage from `make cover` (race enabled):

| Package | Coverage |
|---------|----------|
| `internal/router` | 96 % |
| `internal/limits` | 94 % |
| `internal/netutil` | 92 % |
| `internal/waf` | 85 % |
| `internal/upstream` | 84 % |
| `internal/mgmt` | 84 % |
| `internal/ban` | 78 % |
| `internal/config` | 72 % |
| `internal/proxy` | 72 % |
| `internal/logging` | 66 % |
| `internal/tlsconf` | 56 % |

Not covered: `cmd/` binaries (covered by the manual smoke procedure below
and by binary level tests in phase 3), socket activation paths (need
systemd), error branches for file system failures.

## Manual smoke procedure

Used before every merge to `main` until binary level tests exist:

```sh
make build
python3 -m http.server 18080 --bind 127.0.0.1 &
cat > /tmp/x.yaml <<'EOF2'
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:18081"}]
management: {socket: /tmp/xproxy-mgmt.sock, socket_mode: "0600"}
logging: {directory: /tmp/xproxy-logs}
rate_limits: [{name: rl, rate: 5, burst: 3}]
upstreams: [{name: py, endpoints: [{address: 127.0.0.1:18080}], health_check: {path: /, interval: 1s, timeout: 500ms}}]
routes: [{name: all, upstream: py, rate_limits: [rl]}]
EOF2
mkdir -p /tmp/xproxy-logs
./bin/xproxy -config /tmp/x.yaml &
curl -i http://127.0.0.1:18081/                          # 200, X-Request-Id, no Server header
for i in 1 2 3 4 5; do curl -s -o /dev/null -w "%{http_code} " http://127.0.0.1:18081/; done   # 200 200 429 429 429
./bin/xproxyctl -socket /tmp/xproxy-mgmt.sock status
./bin/xproxyctl -socket /tmp/xproxy-mgmt.sock upstreams
./bin/xproxyctl -socket /tmp/xproxy-mgmt.sock -config /tmp/x.yaml reload
tail -1 /tmp/xproxy-logs/security.log; cat /tmp/xproxy-logs/audit.log
kill %2; kill %1
```

## Planned additions

Phase 2:

- WAF corpus tests: the CRS regression suite run through the proxy in
  detect mode, asserting scores per rule family; a false positive suite from
  sample applications. (The engine level tests above cover the integration;
  the corpus run is still open.)
- Cluster tests: two in-process nodes exchanging counters over loopback
  mTLS, asserting convergence bounds and behaviour when a peer is lost.
- HTTP/3 interoperability with `quic-go` clients and a curl build.
- Load tests under `test/load` using k6 and vegeta with published baseline
  numbers for the reference hardware; soak test of 24 hours with leak
  detection through `runtime.MemStats` sampling.
- Fuzz targets for ICAP framing, WAF transaction building, redaction rules
  and the cluster wire format.

Phase 3:

- Binary level end-to-end suite in `test/e2e` that runs `bin/xproxy` with
  socket activation emulated via `LISTEN_FDS`, exercises `xproxyctl` and
  checks logs.
- Chaos tests: upstream flapping, certificate expiry during runtime,
  configuration reload storms, disk full on the log directory, SIGKILL of
  an upstream mid-response.
- Coverage gate at 80 percent on core packages; mutation testing pass with
  `gremlins` or equivalent on `limits`, `router` and `netutil`.
- Fedora CI runner: install RPM, enable units, run traffic, assert no AVC
  denials and a passing `systemd-analyze security` band.
