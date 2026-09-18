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
  limits approximately cluster wide, ban and unban propagation with
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

## Phase 3: 1.0 (in progress)

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

Remaining:

- Full SELinux policy validated on Fedora (including a domain for
  `xproxy-admin`), RPM packaging with the units, policy and sysctl
  profile, a Fedora CI runner (ASR-S8, AMR-017)
- Scale validation: 1000 hosts and 10 000 endpoints in configuration and
  in tests, published throughput and latency numbers (ASR-P1, P2)
- Stable middleware interface and registry (ASR-O6, AMR-013)
- Coverage gate at 80 percent under race, mutation testing pass on the
  limiters and the router, chaos tests (upstream flaps, certificate
  expiry, disk full on logs) (ASR-Q2)
- Security review against THREAT_MODEL.md, hardening guide, config
  reference generator, changelog, release signing

Exit criterion: release checklist in SECURITY.md complete; all ASR entries
marked 1.0 satisfied and traced to tests.

## After 1.0 (candidates, unranked)

- Forward proxy mode with CONNECT and authentication (ASR-F12)
- L4 TCP and TLS passthrough with SNI routing
- WebAssembly extension ABI (AMR-013)
- OIDC login flows with session cookies
- Bot classification with JA3 and JA4 fingerprints and behavioural scoring
- Honeypot routes and decoy responses
- GeoIP policy (allow, deny, rate by country)
- Request mirroring and replay for testing
- gRPC aware routing and health checks
- Kubernetes ingress controller mode
- Response caching with cache key policies

## Not planned

- Go plugins (AMR-013)
- TLS 1.0 and 1.1
- Management endpoints on data plane listeners (ASR-C4)
- cgo dependencies (ASR-C3)
