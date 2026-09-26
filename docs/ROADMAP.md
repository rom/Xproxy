# Roadmap

Phases to 1.0 and the candidate list beyond it. Each phase has an exit
criterion; a phase is not done until its tests and documentation are in.
Requirement identifiers refer to [ASR.md](ASR.md), decisions to [AMR.md](AMR.md).

## Phase 1: MVP (this branch)

Goal: a hardened reverse proxy an operator can put in front of a web
application today, with the security posture that later phases build on.

Delivered:

- HTTP/1.1 and HTTP/2 listeners, TLS 1.2 and 1.3 with hardened defaults, SNI
  certificate selection, certificate hot reload, optional client
  certificates (ASR-F1, ASR-S11, ASR-P4)
- Host and longest prefix routing with method filters and priorities,
  redirects and static responses, path stripping and rewriting, header
  operations (ASR-F1, ASR-S7)
- Upstream pools with round robin, weighted, least connections and
  consistent hashing; active health checks; passive outlier ejection with
  back-off; retries on connection failure for replayable requests; signed
  cookie session affinity (ASR-F3, F4, F5)
- Limits: connection limits at accept, concurrency ceiling, header, body,
  idle and write timeouts, URI length, body size per route, keyed token
  bucket rate limits with reject or tarpit (ASR-S1, S2, AMR-007)
- Trusted proxy handling for forwarding headers, CIDR allow and deny lists
  per route, WebSocket opt-in (ASR-S6, F8)
- Four JSON log streams with rotation and a request identifier end to end
  (ASR-S9, O2)
- Management API on a Unix socket with peer credentials and an audit log;
  `xproxyctl` with status, stats, upstreams, config, validate, reload,
  reload-certs, reopen-logs and tail (ASR-O3)
- Strict configuration with exhaustive validation, hot reload by SIGHUP or
  API, graceful shutdown, systemd socket activation and `Type=notify`
  (ASR-O1, S5, P3, P5)
- Hardened systemd unit, sysctl profile, SELinux policy skeleton, logrotate
  configuration, example configuration (ASR-S8)
- Unit, integration and fuzz tests; CI with race detector, lint, vulnerability
  scan and fuzz smoke; documentation set (ASR-Q1, Q3, Q5)

Exit criterion: `make check` is green, the example configuration validates,
and a manual deployment on Fedora following SETUP.md serves traffic under
the hardened unit.

## Phase 2: Defence (complete)

Goal: the proxy detects and deflects attacks, not only limits them.

Delivered:

- Filter (middleware) interface with per request instances, request and
  response phases and access log attributes (AMR-013 groundwork)
- WAF engine (Coraza) with the bundled OWASP CRS, anomaly scoring, paranoia
  level and thresholds per profile, `block`, `detect` and `off` per route,
  operator exclusions and custom rules, bounded request body inspection
  with replay, optional bounded response inspection, compile-at-load so a
  bad rule set fails the reload (ASR-F6, AMR-008, AMR-020)
- Ban list with triggers per deny category, sliding windows, escalating
  durations with a cap, exemptions, drop at accept or 403, bounded tables,
  bbolt persistence, survival across reloads, management API and CLI
  (ASR-S2, AMR-012, AMR-019)
- Cluster: mutual TLS peer connections, consumption reports that make rate
  limits approximately cluster wide (1.3: exact per key ownership as an
  option, sliding window policies), ban and unban propagation with
  snapshots for new peers, bounded protocol, reload of peers in place,
  management view (ASR-S3, AMR-009, AMR-021)
- Adaptive load shedding by priority class from in-flight ratio and
  windowed upstream latency, with hysteresis and drain (AMR-022)
- Browser proof-of-work challenge, always or under load, with signed
  single-use nonces and address-bound cookies (AMR-023)
- HTTP/3 over QUIC on TLS listeners with `Alt-Svc`, shared certificates,
  shared connection admission and bans, mandatory address validation,
  no 0-RTT, UDP socket activation (ASR-F2, AMR-002, AMR-024)
- Upstream mutual TLS completed: reloadable client certificate, minimum
  version, SPKI pins, `xproxyctl spki` (ASR-F9)
- JWT validation as a filter on the standard library, with JWKS from file
  or URL, claim forwarding and token stripping (ASR-F10, AMR-025)
- Log sinks: native journald with indexed fields, syslog over UDP, TCP,
  TLS and Unix socket behind a bounded queue; per-stream redaction rules
  for addresses, user agents, referers, claims and arbitrary fields
  (ASR-O2, ASR-S10, AMR-014)
- Prometheus exposition on the management socket and an optional
  hardened TCP endpoint, request and upstream latency histograms,
  per-route counters, and an in-process sampled series buffer for graphs
  (ASR-O4, AMR-026)
- TUI mode of `xproxyctl` with six live screens, ban management and
  sparkline graphs (ASR-O3, AMR-027)

Deferred to phase 3 or later:
- Upstream HTTP/2 tuning
- Fuzz targets for every new parser (WAF transaction, ICAP framing, QUIC
  configuration), WAF regression corpus, load test scripts (ASR-Q1, Q4)

Exit criterion (status): the WAF blocks injection in the engine and
integration tests and a CRS corpus run remains a phase 3 test item; a two
node cluster shares limits (tested in process and with real binaries);
HTTP/3 is tested with a QUIC client and browser interoperability is a
phase 3 checklist item; the challenge was verified in headless Chromium.

## Phase 3: 1.0 (released as 1.0.0)

Goal: operable at fleet scale by a team, packaged for Fedora, reviewed.

Delivered so far:

- ICAP client with REQMOD and RESPMOD, preview, block pages, modified
  requests with protected headers, body limits and fail policies, per
  service status and metrics (ASR-F7, AMR-015, AMR-028)
- ACME with http-01 and tls-alpn-01, one certificate per host group,
  automatic renewal with back-off, state directory, status and forced
  renewal on the management socket (ASR-F11, AMR-029)
- Web GUI (`xproxy-admin`): separate process and user, viewer and
  operator roles, password or client certificate login, every screen of
  the TUI plus configuration editing with validation, atomic save and
  reload, restart through polkit, graphs from the series buffer, ban
  management, live logs (ASR-O3, AMR-011, AMR-030)
- SELinux policy with two domains (`xproxy_t`, `xproxy_admin_t`), file,
  port and unit types, two booleans and an interface file; RPM packaging
  (`xproxy`, `xproxy-admin`, `xproxy-selinux`) from a vendored tarball
  with sysusers, units, sysctl, logrotate and polkit; a Fedora container
  job in CI that compiles the policy against the Fedora headers, builds,
  lints and installs the packages (ASR-S8, AMR-017, AMR-031)
- Scale validation: `TestScale` at 1000 hosts and 10 000 endpoints with
  timings, memory, descriptor and goroutine bounds; routing benchmarks at
  1000 hosts; `test/load` suite (backend, vegeta, k6, soak) with measured
  throughput and latency in PERFORMANCE.md; health probe bounds
  (`max_concurrent`, process-wide cap, `keep_alive`), old generations stop
  probing at the swap, `metrics.endpoint_series`, runtime metrics
  (ASR-P1, ASR-P2 in part)
- Stable middleware interface (API version 1, EXTENDING.md): kind
  registry with load-time validation, stages relative to the built-in
  chain, `filters[]` and `routes[].filters`, deny counters and metrics,
  `/v1/filters` and `xproxyctl filters`, `filtertest` harness, reference
  kinds `header_guard` and `basic_auth` with `xproxyctl htpasswd`
  (ASR-O6, AMR-013)

- Quality gates: `make cover-gate` (whole suite coverage under race, core
  packages 80 % together and 60 % each, in CI), `make mutate` (gremlins
  on limits, router and netutil at 87 %, 81 % and 98 % efficacy after
  tests for the survivors), chaos tests (reload storm, flapping endpoint,
  upstream death mid response, full log disk, certificate rotation) with
  the two observability fixes they produced (ASR-Q2)

- Security review against THREAT_MODEL.md (SECURITY_REVIEW.md): five
  findings, two medium (tarpits holding concurrency slots, header keyed
  rate limit bypass by value rotation), fixed with regression tests;
  residual risks recorded

Remaining:

- External security review and release signing (checksums and a signed
  tag) at the 1.0 cut
- Fedora VM runner with SELinux enforcing for AVC checks and
  `systemd-analyze security` (the container job cannot load policy)
- The 8 core reference throughput number with a remote load generator,
  TLS, HTTP/2, HTTP/3 and WAF cost per request, the 24 hour soak
  (ASR-P2)

Exit criterion: release checklist in SECURITY.md complete; all ASR entries
marked 1.0 satisfied and traced to tests.

Status at 1.0.0: every item above is delivered except the three under
"Remaining", which need resources outside the development environment (a
Fedora host with SELinux enforcing, dedicated reference hardware, an
external reviewer). They are recorded as known limitations in
RELEASE_NOTES_1.0.md and stay at the top of the 1.x list. The release
procedure is in RELEASING.md.

## 1.1 (in progress)

- GeoIP policy: delivered (`geoip`, `routes[].geo`, rate by country,
  AMR-032)
- Bot classification with JA3 and JA4 fingerprints and behavioural
  scoring: delivered (`bot_score` filter kind, AMR-033)
- Response caching with cache key policies: delivered (`cache`,
  `routes[].cache`, AMR-034)
- L4 TCP and TLS passthrough with SNI routing: delivered (`kind: tcp`
  listeners, AMR-035)
- Forward proxy mode with CONNECT and authentication: delivered
  (`kind: forward` listeners, AMR-036)

## 1.2 (in progress)

- Honeypot routes and decoy responses: delivered (`routes[].honeypot`,
  AMR-037)
- Request mirroring: delivered (`routes[].mirror`, AMR-038)
- gRPC aware routing and health checks: delivered (`routes[].grpc`,
  `h2c`, `health_check.type: grpc`, AMR-039)
- OIDC login flows with session cookies: delivered (`oidc` filter
  kind, AMR-040)
- DNS proxy: delivered (`kind: dns` listeners, AMR-041)
- WebAssembly extension ABI: delivered (`wasm` filter kind, ABI v1,
  AMR-013 and AMR-042)
- Kubernetes ingress controller mode: delivered (`ingress` section,
  `deploy/kubernetes`, AMR-043)

## 1.3 (in progress)

- Configuration directory with includes: delivered (`includes`,
  AMR-003 update)
- HTTP/2 CONNECT on forward listeners: delivered (AMR-036 update)
- Body access in the WebAssembly ABI: delivered (`body_limit`, AMR-042
  update)
- OIDC front channel logout: delivered (`frontchannel_logout_path`,
  AMR-040 update)
- OpenTelemetry exporter behind the metrics snapshot: delivered
  (`metrics.otlp`, AMR-026 update)
- DNS over TLS and HTTPS to upstream resolvers, DNS over HTTPS for
  clients on an http listener: delivered (`tls://`, `https://`
  upstreams, `routes[].doh`, AMR-041 update)
- Kubernetes Gateway API next to the Ingress translator, and API
  watches instead of polling: delivered (AMR-043 update)
- QUIC passthrough on layer 4 listeners with a UDP relay: delivered
  (`tcp.quic`, AMR-035 update)
- Inbound PROXY protocol on http listeners (reserved key since 0.x):
  delivered
- Cluster sharing of honeypot marks and OIDC revocations (protocol
  version 2, `filter.Env.Events`): delivered (AMR-021 update)
- gRPC-web translation for browsers (`routes[].grpc.web`): delivered
  (AMR-039 update)
- Static file serving (`routes[].static`): delivered
- Response compression (`compression`, `routes[].compress`): delivered
- Regular expression, header and cookie routing (`path_regex`,
  `headers`, `cookies`): delivered
- `retry_on` status policy for upstream retries: delivered
- Access log formats beyond JSON (`common`, `combined`, `custom`
  template): delivered
- Request and response body rewriting outside WebAssembly
  (`body_rewrite` filter kind): delivered
- Circuit breaker with half open probing, per upstream concurrency
  limits and request queueing with deadlines: delivered
- Canary by header or cookie beyond weights (`upstreams[].canary`):
  delivered
- Per tenant and per route quota reporting (`tenant`, `/v1/quotas`,
  `xproxyctl quotas`): delivered
- Configuration dry run, diff between generations, history and rollback
  beyond the previous file: delivered
- Key rotation for the affinity, OIDC and challenge secrets (keyring
  files, `xproxyctl rotate-secret`): delivered
- OCSP stapling and Certificate Transparency log checks
  (`tls.ocsp_stapling`, `tls.ct`, `xproxyctl tls`): delivered
- Distributed tracing (W3C trace context, OTLP spans) and OTLP for
  logs (`tracing`, `logging.otlp`, `xproxyctl telemetry`): delivered
- DNS over TLS and HTTPS for clients on dns listeners (`tls` on `kind:
  dns`, `doh_path`): delivered
- DNSSEC validation on dns listeners (`dns.dnssec`): delivered
- WAF operations: learning mode with exclusion proposals, per rule
  statistics, rule set updates from a directory (`waf.learning`,
  `crs.dir`, `xproxyctl waf`): delivered
- WAF: CRS plugin loading, JSON body schema enforcement, behavioural
  anomaly detection beyond rule scoring (`crs.plugins_dir`,
  `json_schemas`, `waf.anomaly`): delivered
- API discovery and inventory with shadow, zombie and superseded
  detection (`api_inventory`, `xproxyctl api`): delivered
- Sensitive data detection in requests and responses (`sensitive_data`
  filter): delivered
- Account protection: credential stuffing, brute force, registration,
  reset, hoarding and scraping abuse with progressive actions and
  distributed campaign detection (`account_guard` filter): delivered
- CAPTCHA providers as a challenge tier and device identifiers in the
  challenge cookie (`challenge.captcha`, `challenge.device`, rate limit
  key `device`): delivered
- Distributed attack response: network and fingerprint aggregated bans
  (`bans.triggers[].aggregate`, `ja4:` ban targets): delivered
- Bypass protection: origin request signatures and the origin locking
  guide (`upstreams[].origin_signature`, HARDENING.md 5c): delivered
- WAF operating modes with gradual enforcement (`block_percent`,
  `block_cidrs`): delivered
- Upload protection (`upload_guard` filter): delivered
- Request normalisation before analysis (`server.normalization`):
  delivered
- Rate limit keys per session, account, token, network, endpoint and
  fingerprint (`rate_limits[].key`): delivered
- Positive security model per route and structured virtual patches
  (`routes[].policy`, `virtual_patches`): delivered
- Fleet operation: central configuration push and status collection
  (`xproxy-fleet`, `fleet`), Grafana dashboards and alert rules shipped
  with the product, SIEM export beyond syslog (`logging.siem`, CEF and
  LEEF): delivered
- In-process sandbox (Landlock, seccomp, capabilities, no_new_privs,
  non dumpable), systemd unit additions, macOS target with launchd,
  Seatbelt and pf: delivered (AMR-044, AMR-045)
- Validated `examples/` (WAF rules, block lists, filters, a WebAssembly
  module, rewriting, routing), a documentation syntax test, CLI end to
  end tests, new fuzz targets, benchmarks and a golden configuration
  dump: delivered
- Every management endpoint visible in the CLI, the TUI (nine screens)
  and the GUI (twelve pages): delivered

## 1.4 (in progress)

The theme is the split: one binary that terminates ten protocols is a
process that links ten protocol implementations, and a flaw in any one
of them is a flaw in front of all of them.

- Listener kinds as separately linkable packages: delivered
  (`internal/kinds/*`, the `proxy.Kind` registry, the five-method
  `proxy.Host`, and `internal/listener` as the static roster)
- A listener whose kind this binary did not link is refused by name
  rather than falling through to the HTTP data plane: delivered
  (`TestUnlinkedKindRefused`)
- Three daemons — `xproxy` (edge: http, forward, tcp, udp, dns),
  `xgate` (gate: ssh, telnet, vnc, rdp), `xrelay` (relay: smtp, mqtt,
  ftp, syslog, modbus, ntp, ntske) — sharing one module, one
  configuration format and one control plane, with the common body in
  `internal/daemon`: delivered
- Each daemon validates the whole configuration and binds only its own
  role's listeners, so an estate shares a set of includes: delivered
- A cluster over Unix sockets for the daemons of one machine, with no
  certificate and `SO_PEERCRED` in place of one: delivered
  (`cluster.listen: unix:`, `cluster.local`, AMR-021 update)
- TLS interception on the forward proxy: delivered
  (`forward.intercept`)
- DNS tunnelling and exfiltration detection: delivered
  (`dns.tunnel_detection`)
- The fifth audit round, over every parser: delivered
- Every open finding carried out of rounds one to four: delivered, each
  with a regression test. Four of them changed a default rather than
  adding a setting -- `cluster.tls.bind_node_id` and
  `tracing.redact_client_address` are on, compression leaves an
  authenticated response alone unless
  `compression.compress_authenticated` says otherwise, and a daemon
  refuses to start as uid 0 without `-allow-root`
- The HTTP data plane itself as a kind, so that `xgate` and `xrelay`
  stop linking it: delivered (`internal/kinds/http` and
  `internal/kinds/forward`). The shared compiled generation became `proxy.Plane` with a
  two-phase `Prepare`/`commit`; the management status surface became
  `proxy.PlaneStatus`, with the WAF report moved to the leaf package
  `internal/waf/wafstatus` so Coraza stays out of the daemons that run
  no WAF. Stripped: `xproxy` 28.4 MiB, `xgate` 15.3, `xrelay` 14.9
- The per-package coverage floor, which the split had left three
  packages under: delivered (`internal/daemon` 14 % to 70 %,
  `internal/kinds/ftp` 54 % to 70 %, `internal/kinds/dns` 58 % to
  89 %), and `test/covergate` now excludes every `main` package by
  where it lives rather than by a list that goes stale
- The kinds the split was for, each costing only the daemon that serves
  it: the remote access gateways `telnet`, `vnc` (RFB 3.3 to 3.8,
  VeNCrypt and the vendor security types) and `rdp` (TLS, network level
  authentication or the protocol's own encryption), all three with
  session recording and the shared second factor: delivered
- A generic datagram relay (`kind: udp`) for the services with no parser
  here, with a session table in place of a connection, bounds per source
  as well as in total, and a connected socket towards the endpoint:
  delivered
- The operational technology kinds: `modbus` in both directions, with
  the policy in the protocol's own terms, Modbus/TCP Security and
  learning mode; and `ntp` with `ntske` — a time gateway that reads
  every packet, compares its servers and passes NTS through without
  pretending to have verified it: delivered

- Health checking with dynamic pool membership: delivered (an announced
  endpoint waits for its first probe; `discovery.max_endpoints`)
- Just-in-time, four-eyes, time-boxed bastion access: delivered
  (`access`, `require_grant` on the five gate kinds, a hash-chained
  ledger, `xproxyctl access`)
- Key custody: delivered. A certificate names `key_file`, `key` (a
  reference, resolved from the environment or HashiCorp Vault and
  refreshed into a running proxy) or `signer` (a helper that holds the
  key outside this process). `xsigner`(8) is that helper, and
  [SIGNER.md](SIGNER.md) specifies the protocol so a helper for an HSM,
  a TPM, a smartcard or a KMS can be written. FIPS 140-3 as a refusal to
  start plus a probe that *measures* which configured algorithms the
  active module will do.

  PKCS#11 itself is deliberately not in any shipped binary: it needs cgo
  to dlopen a vendor module, which is ASR-C3, and the protocol is how
  that constraint is honoured rather than worked around.

  Not yet: an SELinux domain for `xsigner`, `xgate` and `xrelay`. All
  three run as `unconfined_service_t`, which is recorded in
  HARDENING.md §2 and is the next thing to close, `xsigner` first --
  it holds the keys and is the easiest domain to write, because it reads
  a handful of files, binds one Unix socket and needs no network.

## After 1.4 (candidates, unranked)

- The remote access protocols this release did not take (Citrix ICA,
  PCoIP, NX) as gate kinds, and OPC UA as a relay kind beside Modbus.
  The split exists so that adding them costs the daemon that serves
  them and nothing else.
- WinRM and WS-Management as HTTP filters rather than a kind: they are
  SOAP over HTTP, so the edge already terminates them.
- WireGuard and IPSec are not planned here. MASQUE already is the TLS
  VPN this product offers; a kernel-datapath VPN is a different
  product, not a listener kind.
- A request replay tool from the access log, if the log policy ever
  admits bodies (AMR-038)

## Not planned

- Go plugins (AMR-013)
- TLS 1.0 and 1.1
- Management endpoints on data plane listeners (ASR-C4)
- cgo dependencies (ASR-C3)
