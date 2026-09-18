# Changelog

All notable changes to Xproxy. The format follows Keep a Changelog; the
project uses semantic versioning once 1.0 is released. Until then every
entry is under "Unreleased" and is grouped by the roadmap phase that
delivered it (see [ROADMAP.md](ROADMAP.md)).

## Unreleased

### Phase 2: Defence (in progress)

#### Added
- Log sinks: per-stream `sinks` with `file`, `journald` (native protocol,
  `MESSAGE` plus indexed `XPROXY_*` fields) and `syslog` (RFC 5424 or
  3164 over UDP, TCP, TLS with pinned CA, or Unix socket; bounded queue,
  background writer, drop counters). New `logging.journald` and
  `logging.syslog` sections; `log_syslog_sent`, `log_syslog_dropped`,
  `log_journald_dropped` and `log_redaction` in status.
- Redaction: `logging.redaction` with address truncation or keyed
  pseudonyms, user agent drop, referer origin, claim hashing and a field
  drop list, applied per stream before every sink.
- JWT validation: `jwt.providers` with RS/PS/ES/EdDSA/HS algorithms on an
  allow list, JWKS from file or HTTPS URL with a pinned CA and rotation
  handling, HMAC secret files, claim checks with bounded skew, claim
  forwarding with spoof protection, token stripping, per-route required
  or optional mode, `denied_jwt` counter, `jwt` ban category.
- Upstream mutual TLS completed: reloadable client certificate (rotated by
  `reload-certs`), `min_version`, `spki_pins`, and `xproxyctl spki` to
  print pins.
- HTTP/3 over QUIC: list `h3` in a TLS listener's protocols to serve the
  same routes on UDP at the same port, with `Alt-Svc` on TLS responses,
  shared certificates, shared connection ceilings and ban list, mandatory
  source address validation, bounded streams, no 0-RTT, and UDP socket
  activation (`xproxy-h3.socket`). New `server.listeners[].h3` block and
  `<listener>/udp` in status.
- Adaptive load shedding: a load level from the in-flight ratio and
  windowed upstream latency; routes carry a `priority_class` (low, normal,
  high, critical) and are shed with 503 and `Retry-After` by class with
  hysteresis; critical is never shed. New `shedding` section, `shed`,
  `load_level`, `upstream_latency_ms` and `shedding_classes` in status.
- Browser proof-of-work challenge: signed single-use nonces, a static page
  with a strict Content Security Policy and an embedded SHA-256 script,
  address-bound signed cookies, `always` or `load` mode per route,
  exemptions, persisted key. Reserved paths `/.xproxy/challenge` and
  `/.xproxy/challenge.js`. Failed proofs feed ban triggers under the
  `challenge` category. New `challenge` section and `routes[].challenge`.
- Cluster: mutual TLS peer connections sharing rate limit consumption and
  bans; a policy's rate becomes approximately cluster wide per key; bans
  and unbans propagate with a snapshot for new peers; bounded protocol;
  `xproxyctl cluster` and `/v1/cluster`. New `cluster` section.
- Ban list: triggers per deny category with sliding windows, escalating
  durations with a cap, exemptions, drop at accept or 403, bounded tables,
  bbolt persistence, reload survival; `xproxyctl bans`, `ban`, `unban` and
  `/v1/bans`. New `bans` section.
- Web application firewall: Coraza engine with the embedded OWASP Core
  Rule Set; profiles with paranoia level, thresholds, exclusion files and
  inline rules; `block`, `detect` and `off` per route; bounded request body
  inspection with replay; optional bounded response inspection; compile at
  load so a broken rule set fails the reload. New `waf` section and
  `routes[].waf`.
- Filter interface (`internal/filter`) for per-route middleware with
  request and response phases and access log attributes.
- Proprietary licence (Sysctl AB) and product name Xproxy (AMR-018).
- Documents: CHANGELOG.md (this file), AMR-018 to AMR-023.

#### Changed
- Minimum Go toolchain is 1.25 (required by Coraza).
- Rate limiter buckets account for peer consumption when clustering is on.
- `denied_ban`, `denied_waf`, `waf_detected`, `bans_active`, `bans_total`,
  `cluster_peers`, `cluster_connected`, `challenges_*` added to status.

#### Security
- Peer input can only tighten limits or add bans, never loosen anything.
- Challenge return paths are restricted to same-origin absolute paths.

### Phase 1: MVP

#### Added
- HTTP/1.1 and HTTP/2 listeners with hardened TLS 1.2/1.3 defaults, SNI
  certificate selection, certificate hot reload and client certificates.
- Host and longest-prefix routing with method filters and priorities,
  redirects, static responses, path strip and rewrite, header operations.
- Upstream pools with round robin, smooth weighted, least connections and
  consistent hashing; active health checks; passive outlier ejection with
  back-off; retries for replayable requests; HMAC signed cookie affinity.
- Defences: connection limits at accept (global and per address),
  concurrency ceiling, header, body, idle and write timeouts, URI and body
  size limits, bounded keyed token bucket rate limits with reject or
  tarpit, per-route CIDR allow and deny lists, trusted proxy handling for
  forwarding headers, path canonicalisation for routing, WebSocket opt-in,
  `Server` header removal, reason-phrase-only error pages.
- Strict YAML configuration with all validation errors reported together
  and secure defaults; atomic generation swap on reload; graceful shutdown;
  systemd socket activation and notify.
- Four JSON log streams (access, error, security, audit) with size
  rotation and a request identifier propagated end to end.
- Management API on a Unix socket with `SO_PEERCRED` audit logging;
  `xproxyctl` with status, stats, upstreams, config, validate, reload,
  reload-certs, reopen-logs and tail.
- Deployment: hardened systemd service and socket units, sysctl profile,
  SELinux policy skeleton, logrotate configuration, example configuration.
- Tests under the race detector, fuzz targets for every custom parser,
  golangci-lint with gosec, CI with govulncheck and fuzz smoke.
- Documentation: ASR, AMR, ARCHITECTURE, SECURITY, THREAT_MODEL, CONFIG,
  USAGE, SETUP, HARDENING, TESTS, ROADMAP.
