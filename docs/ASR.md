# Architecturally Significant Requirements (ASR)

This document lists the requirements that shape the architecture of xproxy.
Each requirement has an identifier, a priority, the release in which it must be
satisfied, and the design consequence it imposes. Requirements without an
architectural consequence live in USAGE.md or the roadmap instead.

Priorities: **M** must have, **S** should have, **C** could have.
Releases: **MVP** (phase 1), **1.0** (phases 2 and 3), **1.x** (after 1.0).

Decisions taken to satisfy these requirements are recorded in [AMR.md](AMR.md).

## 1. Functional scope

| ID | Requirement | Prio | Release | Architectural consequence |
|----|-------------|------|---------|---------------------------|
| ASR-F1 | Act as an L7 HTTP reverse proxy for HTTP/1.1 and HTTP/2 clients, HTTP/1.1 and HTTP/2 upstreams | M | MVP | Built on `net/http`; protocol selection via TLS ALPN; h2c only where a listener or upstream opts in (1.2) |
| ASR-F2 | Serve HTTP/3 over QUIC on the same certificates as TLS listeners | M | 1.0 (delivered in phase 2) | UDP listener per TLS listener, `quic-go` dependency, Alt-Svc advertisement, shared handler pipeline |
| ASR-F3 | Load balance across upstream endpoints with round robin, weighted, least connections and consistent hashing | M | MVP | Balancer interface per pool; ring hash with virtual nodes so endpoint loss moves only that endpoint's keys |
| ASR-F4 | Session affinity by cookie | M | MVP | Cookie carries a signed endpoint index, never an address; HMAC key per pool, persisted in the state directory |
| ASR-F5 | Active health checks and passive outlier ejection | M | MVP | Per endpoint goroutine with jitter; ejection with exponential back-off and a maximum ejection percentage |
| ASR-F6 | Web application firewall with a rule set, anomaly scoring, shadow mode and per route thresholds | M | 1.0 (delivered in phase 2) | WAF is a filter with a bounded body buffer; the engine sits behind the filter interface so it can be swapped |
| ASR-F7 | ICAP client (RFC 3507) for REQMOD and RESPMOD against external scanners | M | 1.0 (delivered in phase 3) | ICAP encapsulation with preview, fail-open or fail-closed per service, bounded in-memory bodies |
| ASR-F8 | WebSocket passthrough only where a route allows it | M | MVP | Upgrade requests are refused unless `websocket: true`; hijack path bypasses body limits so it is opt-in |
| ASR-F9 | Mutual TLS to clients and to upstreams | M | 1.0 (client CA at MVP, upstream side delivered in phase 2) | `crypto/tls` client auth modes; certificate identity exposed to routing and logging; upstream client certificate reloadable, SPKI pins |
| ASR-F10 | JWT validation at the edge | S | 1.0 (delivered in phase 2) | Key set loading from file or JWKS URL with pinned CA; algorithm allow list; no `none` |
| ASR-F11 | ACME certificate issuance (HTTP-01, TLS-ALPN-01) | S | 1.0 (delivered in phase 3) | Separate account key storage; challenge responder inside the listener; renewals on a timer with reload of `Reloadable` certificates |
| ASR-F12 | Forward proxy and L4 TCP/TLS passthrough | C | 1.1 (delivered) | Not in the request pipeline; separate listener kinds `tcp` and `forward` |
| ASR-F15 | Response caching with per route key policies | S | 1.1 (delivered) | In-process store bounded in bytes; hits pass the admission pipeline; no shared cache between nodes |
| ASR-F14 | Bot classification from TLS fingerprints, headers and behaviour, with log, challenge and deny actions | S | 1.1 (delivered) | Fingerprints observed in the TLS handshake and carried to the request; classification is a filter so it composes with the challenge and the ban list |
| ASR-F13 | Country based policy: allow, deny and rate by country | S | 1.1 (delivered) | Country lookup in the admission pipeline from a local database, no network lookups on the request path, no new dependency |
| ASR-F16 | Honeypot routes with decoy responses that mark and ban probing clients | C | 1.2 (delivered) | A route action outside the proxy path; a bounded mark table on the server; bans only through triggers |
| ASR-F17 | Mirror sampled requests to a second upstream without affecting the client | C | 1.2 (delivered) | Copies are asynchronous, bounded and fire-and-forget; bodies are buffered up to a bound so both requests can read them |
| ASR-F18 | Route gRPC by service and method, answer errors as gRPC statuses, probe the standard health service | S | 1.2 (delivered) | gRPC rank in the router; h2c opt-in on listeners and upstreams; health protocol hand encoded, no protobuf dependency |

## 2. Security

| ID | Requirement | Prio | Release | Architectural consequence |
|----|-------------|------|---------|---------------------------|
| ASR-S1 | Withstand malicious clients: no input may cause unbounded memory, CPU or goroutine growth | M | MVP | Every table is bounded (rate limit keys, connection table); every read has a limit and a deadline; no queueing on overload, immediate rejection |
| ASR-S2 | DDoS protection is a central feature: the proxy must degrade gracefully under connection floods, request floods and slow clients | M | MVP, extended in 1.0 | Connection limits at accept time, global and per IP; concurrency ceiling; header, body and idle timeouts; tarpit; temporary bans with decay; adaptive shedding and priority classes in 1.0 |
| ASR-S3 | Distributed rate limiting and shared ban state across a fleet of proxies | M | 1.0 (delivered in phase 2) | Peer gossip over mTLS with approximate counters; no external datastore; local limiter stays authoritative when peers are unreachable |
| ASR-S4 | Minimal attack surface | M | MVP | Standard library first; short dependency allow list; no cgo; static binary; management plane on a Unix socket, never on a data plane listener; no dynamic plugin loading |
| ASR-S5 | Fail closed: a configuration error or a missing security control must stop the proxy from starting or reloading, never silently degrade | M | MVP | Strict YAML with unknown field rejection; all validation errors reported at once; reload keeps the previous generation on any failure |
| ASR-S6 | Do not trust forwarding headers from arbitrary peers | M | MVP | `trusted_proxies` list; right-most untrusted X-Forwarded-For algorithm; forged headers dropped before forwarding |
| ASR-S7 | Route decisions must be immune to path normalisation tricks | M | MVP | Routing uses a cleaned path (dot segments and duplicate slashes resolved); the original path is forwarded unless the route rewrites it |
| ASR-S8 | Run unprivileged on Fedora with systemd hardening and a confined SELinux domain | M | MVP unit, SELinux policy and RPM delivered in phase 3; AVC validation on an enforcing host is a known limitation of 1.0.0 | Socket activation removes the need for any capability; policy module confines file and network access to four labelled directories and http ports |
| ASR-S9 | Every deny, ban, tarpit and management action is logged with enough context to investigate | M | MVP | Dedicated security and audit streams; request identifiers propagate to upstream and back; kernel peer credentials on the management socket |
| ASR-S10 | Logs must not leak secrets or more personal data than configured | M | 1.0 (delivered in phase 2) | Query strings are not logged by default; redaction rules for addresses, user agents, referers, claims and named fields, switchable per stream |
| ASR-S11 | TLS configuration is secure by default and cannot be made insecure by accident | M | MVP | TLS 1.2 minimum, AEAD suites with forward secrecy only, renegotiation disabled, insecure suites rejected by validation, upstream verification skip requires a double opt-in |
| ASR-S12 | Response leakage control | M | MVP | Error pages are reason phrases only; `Server` header removed; upstream error text never reaches the client |
| ASR-S13 | Reproducible, verifiable builds with a software bill of materials and vulnerability scanning | M | MVP | `-trimpath`, stripped, `CGO_ENABLED=0`, `govulncheck` in CI, module information embedded in the binary |

## 3. Performance and scale

| ID | Requirement | Prio | Release | Architectural consequence |
|----|-------------|------|---------|---------------------------|
| ASR-P1 | 1000 virtual hosts and 10 000 upstream endpoints in one configuration | M | 1.0 (validated in phase 3) | Hash based host tables, per host sorted prefix lists; per pool transports; health checks jittered and bounded in concurrency |
| ASR-P2 | Sustained high request rates on commodity hardware (target: 100k requests per second on 8 cores for small responses) | M | 1.0 (10 000 req/s at p99 under 10 ms measured on a shared 4 core container in phase 3; the 8 core reference number is open, RELEASE_NOTES_1.0.md) | Zero allocation routing path; atomic counters; no locks on the hot path except sharded limiter buckets; connection pooling to upstreams |
| ASR-P3 | Configuration reload without dropping connections | M | MVP | Immutable runtime generation swapped atomically; old generation drained on a timer |
| ASR-P4 | Certificate reload without restart | M | MVP | `GetCertificate` reads an atomic pointer |
| ASR-P5 | Graceful shutdown and restart without losing the listening socket | M | MVP | systemd socket activation, `Type=notify`, drain within `shutdown_timeout` |

## 4. Operability

| ID | Requirement | Prio | Release | Architectural consequence |
|----|-------------|------|---------|---------------------------|
| ASR-O1 | Single YAML configuration file, validated before use | M | MVP | Schema in Go types; `xproxy -validate` and `xproxyctl validate` |
| ASR-O2 | Four log streams (access, error, security, audit) as JSON, to files, journald and syslog | M | MVP files, sinks delivered in phase 2 | Sink abstraction behind `log/slog` handlers; native journald datagram protocol and RFC 5424 syslog without cgo |
| ASR-O3 | Management via CLI, TUI and web GUI | M | MVP CLI, TUI delivered in phase 2, GUI delivered in phase 3 | One management API on a Unix socket serves all three; GUI is a separate binary serving embedded static assets over the same API, never inside the data plane |
| ASR-O4 | Metrics for graphs and statistics | M | 1.0 (delivered in phase 2) | Prometheus text endpoint on the management socket and an optional TCP endpoint, plus a local ring buffer of time series for the GUI without external storage |
| ASR-O5 | Persisted state for bans and statistics across restarts | S | 1.0 for bans (delivered in phase 2); statistics moved to 1.x | Embedded key-value store (bbolt) in the state directory |
| ASR-O6 | Extensible without recompiling the core for common cases | S | 1.0 interface (delivered in phase 3), 1.x WASM | Middleware interface with a registry at 1.0; WebAssembly extension ABI in 1.x; never Go plugins |

## 5. Quality

| ID | Requirement | Prio | Release | Architectural consequence |
|----|-------------|------|---------|---------------------------|
| ASR-Q1 | Every parser and matcher has a fuzz target | M | MVP | Go native fuzzing; targets run in CI |
| ASR-Q2 | Core packages hold at least 80 percent statement coverage, measured under the race detector | M | 1.0 (delivered in phase 3) | Coverage gate in CI (`make cover-gate`), mutation testing on the admission packages, chaos tests |
| ASR-Q3 | End-to-end tests drive the real binary | M | MVP (in package tests), binary tests at 1.0 | Tests start listeners on port 0 and read back addresses from the server |
| ASR-Q4 | Load and soak tests with published numbers | S | 1.0 (scripts and container baseline delivered in phase 3, PERFORMANCE.md; reference hardware and the 24 hour soak open) | k6 or vegeta scripts in `test/load`; results in TESTS.md |
| ASR-Q5 | Documentation is part of the definition of done | M | MVP | `docs/` is versioned with the code; CONFIG.md is checked against the example configuration by a test |

## 6. Constraints

| ID | Constraint |
|----|------------|
| ASR-C1 | Implementation language is Go, latest stable release, minimum the previous minor release. |
| ASR-C2 | Primary platform is Fedora Linux with systemd and SELinux enforcing. Other Linux distributions must work but are not tested in CI. |
| ASR-C3 | No cgo. The binaries must be statically linked. |
| ASR-C4 | No component of the data plane may listen on a network port for management. |
| ASR-C5 | Third party modules must be vetted and listed in AMR-004 with a reason; transitive additions require a decision record. |

## Traceability

| Requirement | Implemented in | Verified by |
|-------------|----------------|-------------|
| ASR-F1, F3, F4, F5, F8 | `internal/proxy`, `internal/upstream` | `internal/proxy/proxy_test.go`, `internal/upstream/upstream_test.go` |
| ASR-S1, S2 | `internal/limits`, server timeouts in `internal/proxy/server.go` | `internal/limits/limits_test.go`, `TestConnectionLimits`, `TestSlowHeaderTimeout` |
| ASR-S5, O1 | `internal/config` | `internal/config/config_test.go`, `FuzzParse` |
| ASR-S6, S7 | `internal/netutil` | `internal/netutil/netutil_test.go`, `TestProxyBasics` |
| ASR-S8 | `deploy/systemd`, `deploy/selinux`, `deploy/rpm` | CI `package` job (policy compile, RPM build, rpmlint, install); AVC check on a Fedora host per the release checklist |
| ASR-F6 | `internal/waf`, `internal/filter` | `internal/waf/waf_test.go`, `TestWAFIntegration` |
| ASR-S2 (bans) | `internal/ban`, accept hook in `internal/limits` | `internal/ban/ban_test.go`, `TestBanIntegration`, `TestConnLimiterBanned` |
| ASR-O5 | `internal/ban` persistence (bbolt) | `TestPersistence` |
| ASR-S3 | `internal/cluster`, peer accounting in `internal/limits` | `internal/cluster/cluster_test.go`, `TestPeerRates`, `TestClusterSharesLimitsAndBans` |
| ASR-F2 | `internal/h3`, listener wiring in `internal/proxy/server.go` | `TestHTTP3`, `TestHTTP3ConnectionLimit` |
| ASR-F9 (upstream) | `tlsconf.Client`, `Pool.ReloadClientCertificate` | `TestUpstreamMutualTLS`, `TestUpstreamSPKIPin` |
| ASR-O2, ASR-S10 | `internal/logging` (redact.go, sinks.go, journald.go, syslog.go) | `internal/logging/sinks_test.go`, `TestRedactedAccessLog` |
| ASR-F7 | `internal/icap` | `internal/icap/icap_test.go`, `TestICAPIntegration`, `TestICAPFailOpen` |
| ASR-F11 | `internal/acme`, `internal/tlsconf` | `internal/acme/acme_test.go`, `TestACMEEndToEnd` |
| ASR-O3 (TUI) | `internal/tui`, `xproxyctl tui` | `internal/tui/render_test.go`, pseudo terminal check in TESTS.md |
| ASR-O3 (GUI) | `internal/admin`, `cmd/xproxy-admin` | `internal/admin/admin_test.go`, browser check in TESTS.md |
| ASR-O4 | `internal/metrics`, `Server.WriteMetrics`, `mgmt.MetricsListener` | `internal/metrics/metrics_test.go`, `TestWriteMetrics`, `TestMetricsEndpoints`, `TestMetricsListener` |
| ASR-F10 | `internal/jwt` | `internal/jwt/jwt_test.go`, `TestJWTRoutes`, `TestJWTFromJWKSURL` |
| ASR-S2 (shedding, challenge) | `internal/shed`, `internal/challenge` | `internal/shed/shed_test.go`, `internal/challenge/challenge_test.go`, `TestAdaptiveShedding`, `TestChallengeGate` |
| ASR-S9, O2 | `internal/logging`, `internal/mgmt` | `internal/logging/logging_test.go`, `internal/mgmt/mgmt_test.go` |
| ASR-S11, P4 | `internal/tlsconf` | `internal/tlsconf/tlsconf_test.go`, `TestTLSAndRedirect` |
| ASR-F12 (L4) | `internal/proxy/tcp.go`, `netutil.ClientHelloSNI` | `TestClientHelloSNI`, `TestTCPPassthrough`, `TestTCPProxyProtocol` |
| ASR-F12 (forward) | `internal/proxy/forward.go`, `passwd.LoadUsers` | `TestForwardProxy`, `TestForwardPolicy`, `TestListenerKinds` |
| ASR-F15 | `internal/cache`, `internal/proxy/cache.go` | `TestStoreAndBounds`, `TestVary`, `TestHelpers`, `TestResponseCache` |
| ASR-F14 | `tlsconf.Compute`, `internal/filters/botscore` | `TestFingerprint`, `TestSignals`, `TestBehaviour`, `TestBotScoreOverTLS` |
| ASR-F13 | `internal/geoip`, `routes[].geo`, rate key `country` | `TestMMDB`, `TestCSVAndDB`, `TestGeoPolicy` |
| ASR-F16 | `internal/proxy/honeypot.go`, `routes[].honeypot` | `TestHoneypot`, `TestHoneypotMarks` |
| ASR-F17 | `internal/proxy/mirror.go`, `routes[].mirror` | `TestMirror`, `TestRouteActions` |
| ASR-F18 | `internal/proxy/grpc.go`, `internal/upstream/grpchealth.go`, router gRPC rank | `TestGRPC`, `TestGRPCHelpers`, `TestMatchGRPC`, `TestGRPCHealthEncoding`, `TestGRPCConfig` |
| ASR-Q2 | `test/covergate`, `.gremlins.yaml`, `internal/proxy/chaos_test.go` | CI `test` job (`make cover-gate`), CI `mutate` job, `TestChaos*` |
| ASR-O6 | `internal/filter` registry, `internal/filters` | `TestRegistry`, `TestFilters`, `TestFiltersConfig`, EXTENDING.md |
| ASR-P1 | `internal/router`, `internal/upstream` health bounds, `internal/proxy` generations | `TestScale` (`make scale`), `BenchmarkMatch1000Hosts`, PERFORMANCE.md |
| ASR-P2 | handler path, `test/load` | `make load` baseline in PERFORMANCE.md; 8 core reference run open |
| ASR-P3 | `Server.Reload` | `TestReload` |
| ASR-Q1 | `Fuzz*` functions | `make fuzz` |
