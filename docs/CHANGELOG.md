# Changelog

All notable changes to Xproxy. The format follows Keep a Changelog and
the project uses semantic versioning from 1.0.0. Entries are grouped by
the roadmap phase that delivered them (see [ROADMAP.md](ROADMAP.md)).

## Unreleased

### Added (1.3)
- Configuration includes: `includes` globs of fragment files whose
  `upstreams`, `routes`, `rate_limits` and `filters` are appended in
  lexical order; fragments may contain nothing else and names must be
  unique across the set.
- HTTP/2 CONNECT on TLS forward listeners that list `h2`: the stream
  carries the tunnel.
- WebAssembly ABI body access: `get` kinds 13 to 15 and `set_body`
  behind a per filter `body_limit`; bodies over the limit stream
  through unexposed.
- QUIC passthrough: `kind: tcp` listeners with `quic: true` relay QUIC
  flows by the server name read from the version 1 Initial packet,
  with `quic_idle_timeout`, `quic_*` counters and `xproxy_quic_*`
  metrics.
- Kubernetes Gateway API: Gateways and HTTPRoutes of the ingress class
  translate next to Ingress resources (hostnames, prefix and exact
  paths, methods, header modifiers, URL rewrite, redirects, weighted
  backends, listener certificates); watch streams on every collection
  trigger a debounced sync so changes propagate within a second, with
  the resync poll as fallback; `watch` and `debounce` settings,
  `gateway_api`, `watching` and `watch_events` in the status.
- DNS over TLS and HTTPS: dns listener `upstreams` accept
  `tls://host:port` and `https://host/path` with `upstream_ca_file`;
  a `doh` route action answers RFC 8484 for clients through a dns
  listener's policy and cache.
- OpenTelemetry exporter: `metrics.otlp` pushes every metric family as
  OTLP/HTTP with JSON encoding on an interval, with headers, pinned CA,
  resource attributes and gzip; `GET /v1/otlp`, `xproxyctl otlp`.
- OIDC front channel logout: sessions carry the provider's `sid`,
  `frontchannel_logout_path` revokes it into a bounded index, a logout
  at the proxy revokes it too; `logouts` and `revoked` in the status.
- Inbound PROXY protocol: `proxy_protocol: true` on `http` listeners
  reads a v1 or v2 header from peers in `trusted_proxies` and makes the
  carried address the client for limits, bans, ACLs, logs and
  forwarding headers; trusted peers without a header are dropped,
  other peers are served unchanged. The key was reserved since 0.x.
- Cluster events (protocol version 2): honeypot marks and unmarks and
  OIDC session revocations are shared between nodes; `share_events`
  switches the channel; `events_sent`, `events_received` and
  `ignored_messages` in `xproxyctl cluster`; unknown message types are
  skipped instead of closing the connection.
- `filter.Env.Events`: an event bus for compiled-in filters to share
  facts with cluster peers (middleware API version 1, additive).
- `bot_score` signal `honeypot_marked` (weight 40) for clients marked
  by a honeypot here or on a peer.
- Static file serving: `routes[].static` serves a directory through
  `os.Root` with index files, optional listings, a single page
  application fallback, `Cache-Control`, dot file refusal, a size
  bound, weak `ETag`s, ranges and conditional requests;
  `static_served`, `static_not_found`, `xproxy_static_responses_total`.

### Fixed (1.3)
- Ingress merge on a configuration with `includes` expanded the
  fragments a second time, failing the merge on duplicate names.
- Reloading a dns listener's policy leaked the previous resolver's
  idle DNS over TLS connections; the old resolver is now closed, and
  shutdown closes the last one.
- Ingress watch streams had no response header timeout, so an API
  server that accepted the connection and never answered held the
  watcher forever.
- `xproxyctl config` output on a configuration with `includes` was not
  loadable as a main file without expanding the fragments twice; it now
  prints one self-contained document with the fragment paths in a
  comment.

### Added (1.2)
- GeoIP policy: `geoip` section with a built-in MaxMind DB reader (no
  external library) or a CSV prefix table; `routes[].geo` allow and deny
  lists with an `unknown` choice; rate limits keyed on `country`;
  `country` in the access log and in `filter.Info`; `denied_geo`,
  `xproxy_geoip_*` metrics; `GET /v1/geoip`, `xproxyctl geoip`.
- Bot classification: JA3 and JA4 fingerprints computed from every
  ClientHello (`tlsconf.Compute`), logged as `ja4` and passed to filters;
  the `bot_score` filter kind scores user agent, browser headers,
  fingerprint mismatch and behaviour (error rate, path spread, timing
  regularity, rate) with configurable weights, JA4 allow and deny lists,
  and log, challenge or deny thresholds; the score can be forwarded in a
  header. Middleware API additions: `Info.Country`, `Info.JA3`,
  `Info.JA4`, `Info.ALPN`, `Info.ChallengeVerified`, `Verdict.Challenge`.
- Response caching: `cache` section (byte bound, object bound) and
  `routes[].cache` (ttl, methods, statuses, query and header key policy,
  cookies, ignore_cache_control); `Cache-Control`, `Expires` and `Vary`
  honoured; conditional requests answered with 304; `X-Cache` and `Age`
  headers, `cache` in the access log; `GET /v1/cache`, `DELETE
  /v1/cache`, `xproxyctl cache` and `cache purge`; `xproxy_cache_*`
  metrics. The cache survives reloads.
- Layer 4 passthrough: `kind: tcp` listeners route TLS connections by
  server name (peeked, not terminated) to upstream pools, with a default
  for non-TLS and unmatched connections, PROXY protocol v2 to the
  upstream, idle timeout, per listener connection bound, pool accounting
  and retries across endpoints, a `tcp` access log line per connection
  and `xproxy_tcp_*` metrics.
- Forward proxy: `kind: forward` listeners accept `CONNECT` tunnels and
  absolute `http://` requests from clients, with a destination policy
  (ports, allow and deny by name, address or CIDR, private ranges
  refused by default, the checked address dialled), optional
  `Proxy-Authorization` Basic credentials from a users file re-read on
  reload, tunnel bound, idle timeout, response size bound, `Via`, a
  `forward` access log line per request, `forward_*` security events
  and ban reasons, `xproxy_forward_*` metrics.
- Ban triggers accept the reasons `geo`, `tcp_no_route`,
  `forward_denied` and `forward_auth`.
- Honeypot routes: `routes[].honeypot` serves a built-in decoy
  (`wp-login`, `env`, `git-config`, `phpinfo`, `admin-login`, `robots`),
  an inline body or a file, with a tarpit delay; hits are `honeypot`
  security events and a ban reason, the client is marked for `mark` and
  its later requests carry `honeypot_marked` in the access log and
  `Info.HoneypotMarked` in filters; `GET/DELETE /v1/honeypot`,
  `xproxyctl honeypot`, `xproxy_honeypot_*` metrics.
- Request mirroring: `routes[].mirror` copies sampled requests to a
  second upstream in the background with `X-Xproxy-Mirror: 1`, bounded
  in body size, time and copies in flight; the client never sees the
  mirror's response; `mirror` in the access log, `mirror_*` counters
  and `xproxy_mirror_total{outcome}`.
- gRPC: `routes[].grpc` matches gRPC requests by service or method with
  precedence over plain routes on the same path; proxy errors on gRPC
  requests are trailers-only responses with a mapped `grpc-status`;
  `grpc-timeout` tightens the route deadline; `listeners[].h2c` accepts
  HTTP/2 without TLS and `upstreams[].h2c` speaks it to backends;
  `health_check.type: grpc` probes the standard health service;
  `grpc_status` in the access log and `xproxy_grpc_responses_total`.
- OpenID Connect login: the `oidc` filter kind runs the authorization
  code flow with PKCE and a nonce against a discovered provider,
  verifies the ID token with the JWT verifier, keeps an AES-GCM sealed
  session cookie, forwards claims as headers, strips the cookie
  upstream, checks `require_claims`, logs out through the provider.
  `Verdict.Silent` lets a filter answer flow redirects without
  security bookkeeping.
- DNS proxy: `kind: dns` listeners answer over UDP and TCP from a
  bounded cache, apply a block list (inline and file, NXDOMAIN, REFUSED
  or sinkhole), a client allow list and per client rate limits, and
  forward to upstream resolvers with a fresh id and source port per
  query; `dns_blocked` security events and ban reason; `GET/DELETE
  /v1/dns`, `xproxyctl dns`, `xproxy_dns_*` metrics.
- WebAssembly extension ABI version 1: the `wasm` filter kind runs a
  module per request in a wazero sandbox with memory and time bounds;
  guests export `xproxy_abi_version`, `xproxy_alloc`,
  `xproxy_on_request` and optionally `xproxy_on_response` and import
  `get`, `set_header`, `remove_header`, `deny`, `log` and `log_attr`
  from module `xproxy`. New dependency `github.com/tetratelabs/wazero`.
- Kubernetes ingress controller mode: the `ingress` section reads
  Ingress, Service, EndpointSlice and TLS Secret resources of one class
  with the pod's service account and merges routes, upstreams and
  certificates into the file configuration, reloading on change;
  `xproxy.sysctl.se/*` annotations set route options; `GET
  /v1/ingress`, `xproxyctl ingress`; `deploy/kubernetes` manifests and
  Containerfile.

## 1.0.0 - 2026-09-18

First release. Highlights and known limitations are in
[RELEASE_NOTES_1.0.md](RELEASE_NOTES_1.0.md).

### Phase 3: 1.0

#### Security
- SR-1: tarpitted requests no longer hold a concurrency slot; a separate
  bound `server.limits.max_tarpits` (default 1024) applies and requests
  above it are rejected immediately (`tarpit_overflow`, `tarpit_active`).
- SR-2: a header keyed rate limit falls back to the client address once
  its key table is full, so rotating header values cannot obtain a fresh
  burst per value.
- SR-3: the GUI's configuration backup and the users and htpasswd files
  are written without following symbolic links.
- The internal review is recorded in `docs/SECURITY_REVIEW.md`.

#### Added
- Quality gates: `make cover-gate` (whole suite coverage under race,
  `test/covergate` enforcing 80 % over the core packages and 60 % per
  package, in CI), `make mutate` with gremlins on limits, router and
  netutil (`.gremlins.yaml`, CI job), chaos tests for reload storms,
  flapping endpoints, upstream death mid response, a full log disk and
  certificate rotation. Log write failures are counted
  (`log_write_errors`, `xproxy_log_write_errors_total`) and warned about
  once a minute; `xproxy_certificate_expiry_seconds{listener}` exposes
  the earliest file certificate expiry. Tests added for validation
  branches, the GUI's listeners and certificate login, log rotation and
  reopening, and the boundaries mutation testing found unobserved.
- Middleware interface at API version 1 (`docs/EXTENDING.md`): kind
  registry with load-time validation and per-generation construction,
  `filters[]` with `stage` and kind specific `options`, `routes[].filters`,
  deny counting (`denied_filter`, `xproxy_filter_denied_total`), ban
  categories by filter name, `Closer` for resources, `filtertest`
  harness; built-in kinds `header_guard` and `basic_auth`; `/v1/filters`,
  `xproxyctl filters` and `xproxyctl htpasswd`; `internal/passwd` shared
  with the GUI.
- Scale validation: `TestScale` at 1000 hosts and 10 000 endpoints
  (`make scale`), routing benchmarks at 1000 hosts (`make bench`),
  `test/load` with a backend, vegeta and k6 scripts and a soak script
  (`make load`), results in `docs/PERFORMANCE.md`. Health checks:
  `max_concurrent` per pool, a process-wide cap of 512 probes in flight,
  `keep_alive` (default off: fresh connection per probe). Superseded
  generations stop probing at the swap. `metrics.endpoint_series` to drop
  per-endpoint series; per-pool `xproxy_upstream_endpoints` and
  `xproxy_upstream_endpoints_healthy`; `go_goroutines`,
  `go_memstats_heap_alloc_bytes`, `go_memstats_sys_bytes`,
  `go_gc_cycles_total`, `process_open_fds`.
- SELinux policy: confined domains `xproxy_t` and `xproxy_admin_t`, types
  for configuration, logs, runtime, state and unit files, port types for
  upstreams, cluster, metrics and the GUI, booleans `xproxy_connect_any`
  and `xproxy_admin_manage_service`, interface file for other policies;
  compiles against Fedora and reference policy headers.
- RPM packaging: `xproxy`, `xproxy-admin` and `xproxy-selinux` built
  offline from a vendored tarball (`make dist`, `make rpm`, `make
  rpmlint`); sysusers, units, sysctl, logrotate, polkit and documentation
  installed; the policy loaded and paths relabelled on install. `VERSION`
  file for the package version. Fedora container job in CI.
- Web GUI `xproxy-admin`: separate process and service user; users file
  with PBKDF2 hashes (`user add|del|list`, `passwd`), viewer and operator
  roles, client certificate login on a mutual TLS listener, loopback only
  otherwise; screens for overview, upstreams, bans (add and remove),
  graphs from the series buffer, cluster, certificates (with renew), ICAP,
  configuration (active view, editor with validation, atomic save with
  backup and entity tag, reload) and live logs; restart through a
  configurable command with a polkit rule; strict Content Security Policy,
  CSRF checks, login lockout, audited actions. `xproxy-admin.service` and
  `50-xproxy-admin.rules` in `deploy/`.
- ACME (RFC 8555): `acme` section and `tls.acme` host groups on listeners;
  `http-01` answered on plaintext listeners ahead of the redirect and
  `tls-alpn-01` on the TLS listener; one certificate per group with
  automatic renewal, hourly back-off, verified chains and a state directory
  under `/var/lib/xproxy/acme`; `/v1/acme`, `/v1/acme/renew`,
  `xproxyctl acme` and `xproxyctl acme renew`; fake CA for tests
  (`internal/acme/acmetest`).
- ICAP client (RFC 3507): `icap.services` with `icap://` and `icaps://`
  transports, OPTIONS probing, preview, REQMOD and RESPMOD, block pages,
  modified requests with protected headers, body limits with reject or
  bypass, fail open or closed, connection pooling; `routes[].icap`;
  `/v1/icap`, `xproxyctl icap`, `denied_icap`, `xproxy_icap_*` metrics,
  `icap` ban category.

### Phase 2: Defence (complete)

#### Added
- TUI: `xproxyctl tui` with overview, upstreams, bans (ban and unban),
  cluster, graphs and security log screens, refreshed from the management
  socket; colours honour `NO_COLOR`. Built on `golang.org/x/term` instead
  of the planned bubbletea (AMR-027).
- Metrics: Prometheus text exposition at `/metrics` on the management
  socket and on an optional TCP listener with allow list and mutual TLS
  (`metrics` section); request duration and upstream time to first byte
  histograms; per-route outcome counters; sampled series buffer served at
  `/v1/series`; `xproxyctl metrics` and `xproxyctl series`.
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
