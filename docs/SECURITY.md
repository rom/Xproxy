# Security

This document states the security posture of xproxy: the principles, the
controls that exist today, how the software is built and released, and how
to report a vulnerability. The threat analysis behind the controls is in
[THREAT_MODEL.md](THREAT_MODEL.md); host hardening steps are in
[HARDENING.md](HARDENING.md).

## Principles

1. **Fail closed.** A configuration that cannot be validated does not load. A
   reload that fails leaves the previous configuration running. A missing
   file, an unknown field or an insecure setting is an error, not a warning.
2. **Bounded everything.** Every buffer, table, timeout and retry has a cap.
   Overload is met with rejection at the cheapest point, never with a queue.
3. **Least privilege.** One unprivileged process with no capabilities, a read
   only view of the system, a confined SELinux domain, and a management
   channel that the kernel authenticates.
4. **Minimal surface.** Standard library first, a short dependency allow list
   (AMR-004), no cgo, no dynamic loading, no management on data listeners.
5. **Secure defaults.** Omitting a setting gives the safer value. Making
   something less safe requires an explicit and sometimes double opt-in.
6. **Observable.** Every deny and every management action is logged with the
   context needed to investigate it.

## Controls in this release

### Transport

- TLS 1.2 minimum, TLS 1.3 preferred; TLS 1.0 and 1.1 cannot be configured.
- TLS 1.2 suites restricted to ECDHE with AES-GCM or ChaCha20-Poly1305.
  Insecure suites are rejected by validation with their name.
- X25519, P-256, P-384 key exchange in that order.
- Renegotiation disabled. Session tickets rotated by the Go runtime.
- ALPN offers `h2` then `http/1.1`; h2c (cleartext HTTP/2) is never enabled.
- HTTP/3 (QUIC) shares certificates and limits with its TLS listener; new
  client addresses must complete a Retry round trip before state is
  allocated (amplification defence), 0-RTT is disabled, streams per
  connection are bounded, and QUIC connections count against the same
  connection ceilings and ban list as TCP.
- SNI based certificate selection; certificates reload without restart.
- ACME issued certificates: ES256 account key and P-256 certificate keys
  generated in the process and stored `0600` in a `0700` state directory;
  the returned chain is verified against the configured hosts before use;
  the `http-01` responder answers only known tokens with `GET` and returns
  404 otherwise; the `acme-tls/1` ALPN is answered only while a challenge
  is pending and never with a production certificate; the directory server
  can be pinned to a CA file; responses are size bounded.
- Optional client certificate verification (`request` or `require`) against
  a configured CA bundle.
- Upstream TLS verifies against the system pool or a pinned `ca_file`,
  with a configurable minimum version, optional public key pins on the
  upstream leaf, and mutual TLS with a client certificate that rotates on
  `reload-certs`; skipping verification needs `insecure_skip_verify` and
  `allow_insecure` and cannot be combined with pins.

### Request handling

- Connection limits enforced immediately after accept, globally and per
  source address.
- Header read timeout, read, write and idle timeouts, all with non-zero
  defaults that cannot be set to zero.
- Header size, URI length and body size limits; the body limit can be
  lowered per route.
- Concurrency ceiling with immediate 503.
- Keyed token bucket rate limits by client address, route or header, with
  reject or tarpit actions; bucket tables are bounded in memory.
- Routing on a canonicalised path so dot segments cannot bypass a policy.
- Host header normalisation and strict host matching.
- CIDR deny and allow lists per route.
- WebSocket upgrades refused unless a route opts in.
- Forwarding headers trusted only from configured proxy addresses; forged
  values replaced; `Forwarded` removed.
- `Server` header removed from all responses; error responses carry only
  the status reason.
- Request identifier generated per request, returned to the client, sent to
  the upstream and present in every log line.
- Environment proxy variables ignored for upstream connections.
- No response decompression, so no decompression bombs in the proxy.

### Token validation

- JSON Web Tokens are verified on the standard library with an explicit
  per-provider algorithm allow list; `none` does not exist and HMAC
  secrets never come from a key set, which removes the classic algorithm
  confusion attacks.
- Signatures are checked before claims are parsed; ECDSA curves must
  match the algorithm; keys are selected by identifier with a bounded
  fallback.
- `exp` is mandatory; `nbf`, `iat`, `iss`, `aud` and required claims are
  enforced with a bounded clock skew.
- Key sets come from a file or an HTTPS URL with a pinned CA, refreshed
  on a timer and on unknown key identifiers with rate limiting; a provider
  without keys fails closed with 503.
- Client supplied copies of forwarded claim headers are always removed;
  tokens are stripped before forwarding by default; failures are logged
  by category and feed ban triggers.

### Web application firewall

- OWASP Core Rule Set (bundled, no network fetch) through the Coraza
  engine, anomaly scoring with configurable paranoia level and thresholds.
- Per route `block`, `detect` (shadow) or `off`; profiles per route so an
  API can run a stricter paranoia level than a marketing site.
- Request headers and bodies inspected; bodies above the limit are
  rejected with 413 by default, or inspected partially when configured.
  Inspected bodies are replayed to the upstream unchanged.
- Optional response inspection for data leakage rules, bounded by a size
  limit; larger bodies pass uninspected and that fact is visible in the
  configuration, never silent.
- Operator exclusions and custom SecLang rules load between CRS setup and
  CRS rules; a rule set that fails to compile fails the reload.
- Every block and every detection is logged with matched rule identifiers,
  the CRS total score and the WAF phase.

### Ban list

- Repeated denies (WAF, rate limit, ACL and others, selectable per
  trigger) within a window ban the client address for an escalating
  duration with a cap.
- Banned peers are closed at accept before any byte is read, or answered
  403 when the client address is derived from a trusted proxy chain.
- Exempt ranges can never be banned. Loopback, unspecified and overly wide
  prefixes are refused.
- Tables are bounded; bans optionally persist across restarts in a
  `0600` bbolt file in the state directory.
- Operators ban and unban through the audited management API.

### External scanning (ICAP)

- Requests and responses can be handed to anti-virus or data loss
  prevention scanners over ICAP, with preview so most traffic costs a few
  bytes, and TLS with a pinned CA for the scanner link.
- The scanner can block (its page is returned) or modify, but never change
  the origin: `Host`, the forwarding headers, `Authorization` and `Cookie`
  are protected from modification.
- Bodies are bounded; over the limit the route rejects or bypasses as
  configured, and a scanner failure fails closed by default. Every bypass
  is counted and visible, so a misbehaving scanner is never silent.
- Encapsulated responses are size bounded (4 MiB) and parsed with the
  standard library; malformed answers close the connection.

### Load shedding and challenge

- Under pressure, routes are shed by priority class with immediate 503 and
  `Retry-After`, never queued; critical routes are never shed. The signal
  combines in-flight ratio and upstream latency, drains when no samples
  arrive, and has hysteresis.
- The browser challenge makes a client spend CPU (a SHA-256 proof of work)
  before a gated route is served, either always or only under load. The
  proxy spends one HMAC per page and one HMAC plus one hash per
  verification.
- Nonces are signed, bound to the client address by default, expire after
  ten minutes and are single use. Cookies are signed, bound to the client
  address by default, `HttpOnly`, `SameSite=Lax`, `Secure` on TLS.
- The challenge page carries a strict Content Security Policy (no inline
  scripts), `X-Frame-Options: DENY`, `noindex`, and returns to same-origin
  paths only. Failed verifications are security events that feed ban
  triggers under the `challenge` category.

### Metrics

- The management socket serves `/metrics` with the kernel enforced access
  of the socket. The optional TCP endpoint serves nothing but `/metrics`,
  refuses sources outside `allow_cidrs`, can require mutual TLS, and
  cannot be bound to all interfaces without a client CA.
- Label cardinality is bounded by configuration (routes, upstreams,
  endpoints); no client controlled value becomes a label.

### Cluster

- Mutual TLS 1.3 only; every peer must present a certificate from the
  cluster CA, optionally restricted to named identities. No other
  credential exists, so there is no shared secret to leak.
- The listener must bind a specific internal address; validation refuses
  all-interfaces binds.
- Messages are size bounded (1 MiB), count bounded (keys and bans per
  message), version checked and rejected on the first malformed line;
  inbound connections are capped and idle peers are disconnected.
- Peer input can only tighten local limits (refill is reduced, never
  increased), add or remove bans, mark or unmark honeypot clients and
  revoke OIDC sessions; exemptions still apply to peer bans, loopback
  and wide prefixes are refused as for manual bans, and every event is
  bounded and applied within the receiver's own table limits. Each
  channel has its own `share_*` switch.
- Losing every peer degrades to local limiting; stale reports expire after
  `peer_stale`.

### Upstreams

- Connect, response header, idle and total timeouts per pool.
- Response header size capped at 64 KiB.
- Active health checks with jitter; passive ejection with back-off and a
  maximum ejection percentage.
- Retries only for connection level failures of replayable requests.
- Affinity cookies are HMAC signed indexes with expiry, `HttpOnly`,
  `SameSite=Lax`, `Secure` on TLS.

### Layer 4 and forward listeners

- `kind: tcp` listeners reach only configured upstream endpoints; the
  ClientHello parser checks every length and reads at most 16 KiB.
  QUIC relaying decrypts only the client's Initial packets (public
  keys by construction), authenticates them, bounds the reassembled
  ClientHello, and drops everything else that is not part of a known
  flow; flows are bounded and idle closed.
- `kind: forward` listeners check every destination before connecting:
  listed ports only, private and loopback ranges refused unless
  `allow_private`, deny and allow by name and by every resolved address,
  and the checked address is the one dialled. Proxy credentials are
  PBKDF2 hashes from `xproxyctl htpasswd`, verified with a bounded
  worker count and a digest cache. Refusals and credential failures are
  security events and ban reasons. Tunnels are bounded and idle closed;
  plain responses are size bounded.

### Kubernetes ingress mode

- Read-only cluster access (get, list, watch on Ingresses, Services,
  EndpointSlices, Secrets) with the pod's service account; the proxy
  never writes to the API.
- Generated routes pass the same validation as the file; the file's
  names win and collisions are errors; TLS secrets are written `0600`
  into a controller owned directory and removed when unreferenced.
- The container runs as a non root user on a scratch image with a read
  only root file system and no capabilities.

### DNS

- Fresh transaction id and source port per upstream query; answers
  must match id and question; TC answers are refetched over TCP.
- Compression pointers only backwards, bounded hops; every length
  checked; no record data decoded.
- Client allow list, per client rate limit that drops, in-flight
  bound, truncation to the client's UDP size: no open resolver, no
  amplification.
- DNS over TLS and HTTPS upstreams with a pinned CA; DoH for clients
  behind the route pipeline, bodies and parameters bounded.

### gRPC and HTTP/2 cleartext

- `h2c` is opt-in on listeners and upstreams and meant for trusted
  networks; streams per connection and frame size are bounded.
- gRPC health probes and error responses are hand encoded with bounded
  reads; no protobuf library is linked.

### WebAssembly filters

- Modules run in wazero (pure Go, no cgo, no JIT escape to the host):
  no file system, sockets or environment; memory bounded per instance;
  every call under a deadline; traps and timeouts fail closed by
  default and discard the instance.
- The host reads and writes guest memory only through bounded,
  validated strings; header names and values are checked.

### OpenID Connect

- Authorization code flow only, with PKCE (S256) and a nonce; the
  implicit flow is not supported.
- Sessions are AES-GCM sealed cookies with an expiry inside the
  payload, `HttpOnly`, `SameSite=Lax`, `Secure` on TLS; the state
  cookie is bound to the `state` parameter by digest and lives ten
  minutes; ciphertexts carry a purpose so one cannot stand in for the
  other.
- ID tokens are verified for signature, issuer, audience, expiry and
  nonce; `require_claims` refuses logins with 403; identity headers
  from clients are removed before the session's are set.
- Return URLs are same-origin paths only; the client secret and cookie
  key files must not be world readable.
- Front channel logout revokes provider session ids into a bounded
  index checked on every request; the issuer in the request must match.

### Honeypots

- Decoy routes never proxy; built-in decoys contain fabricated values
  only. Hits are security events, marks are bounded and expire, delays
  use tarpit slots, bans need a trigger.

### Configuration and process

- Strict YAML: unknown fields, duplicate names, dangling references,
  malformed CIDRs, control characters in header values and unsafe modes are
  all rejected, and all problems are reported together.
- World writable configuration files are refused.
- Configuration size capped at 8 MiB; a second YAML document is an error.
- Runs as a dedicated user under a systemd unit with `NoNewPrivileges`,
  `ProtectSystem=strict`, `PrivateTmp`, `PrivateDevices`,
  `MemoryDenyWriteExecute`, `RestrictAddressFamilies`, a system call filter
  and an empty capability bounding set.
- Socket activation removes the need for any privilege to bind ports.
- A start as root is logged on the security stream as a warning.

### Management and logging

- Management API only on a Unix domain socket; directory `0750`, socket mode
  defaults to `0660` and validation refuses any `other` permission.
- Caller identity (uid, gid, pid) taken from `SO_PEERCRED` and written to the
  audit log for every mutating action.
- Reload through the API re-reads the operator's file; the API never accepts
  a configuration body.
- The web GUI is a separate process and user; it forwards actions to the
  socket (so they are audited with its uid) and adds its own audit line
  with the GUI user name. Strict Content Security Policy without inline
  code, `HttpOnly` `SameSite=Strict` session cookies, three independent
  cross-site request forgery checks, server side role enforcement, PBKDF2
  password hashes with per-source login lockout, mutual TLS required for
  any non-loopback listener. Configuration edits are validated before they
  are written, written atomically with a backup, and guarded by an entity
  tag.
- Four separate JSON streams. Log files are created `0640`. Attacker
  controlled values are JSON encoded, which defeats log injection. Query
  strings are not logged.
- Redaction rules, switchable per stream, run before every sink: client
  addresses truncated or replaced by a keyed pseudonym, user agents and
  referers reduced or dropped, token claims hashed or dropped, arbitrary
  fields removed. The audit stream keeps full detail by default for
  accountability.
- Off-host delivery over journald's native socket or syslog (UDP, TCP,
  TLS with a pinned CA and optional client certificate, or a Unix socket).
  Sending is asynchronous behind a bounded queue, so a collector outage
  can never stall or exhaust the proxy; drops are counted and visible.

## Planned controls (see ROADMAP.md)

Phase 2 (remaining): TUI.

Phase 3 (ICAP, ACME, the GUI, the SELinux policy, the RPMs, scale
validation, the middleware interface, the quality gates and the internal
security review delivered, see SECURITY_REVIEW.md): external security
review, AVC validation on a Fedora VM in CI.

## Secure development

- **Language and toolchain.** Go, latest stable, `CGO_ENABLED=0`. Builds are
  `-trimpath`, stripped and reproducible for a given toolchain and module
  set; `go version -m` prints the embedded module list (SBOM).
- **Static analysis.** `go vet`, `staticcheck` and `gosec` through
  `golangci-lint` on every push. Any `nolint` carries a written reason.
- **Race detector.** All tests run with `-race` in CI.
- **Fuzzing.** Every custom parser and matcher has a native fuzz target
  (`FuzzParse`, `FuzzMatch`, `FuzzCleanPath`, `FuzzHost`); CI runs each for
  a short budget, and longer runs are part of the release checklist. The
  WAF engine and rule parser are third party (Coraza) and are fuzzed
  upstream; xproxy fuzzes its own glue through the configuration fuzzer.
- **Vulnerability scanning.** `govulncheck` in CI fails the build on a
  reachable vulnerability.
- **Dependency review.** New modules require an AMR record and a review of
  the module's own security history.
- **Review.** Changes to `internal/limits`, `internal/netutil`,
  `internal/tlsconf`, `internal/config/validate.go` and the systemd or
  SELinux files require a second reviewer.

## Release checklist

1. `make check`, `make cover-gate` and `make mutate` green; `make fuzz
   FUZZTIME=5m` green.
2. `govulncheck` clean (CI `security` job); dependency versions reviewed.
3. THREAT_MODEL.md reviewed against the change log; new threats have
   mitigations or accepted risks; SECURITY_REVIEW.md updated with the
   findings of the release's review.
4. Example configuration validates; CONFIG.md matches the schema.
5. Deployed on a Fedora host with SELinux enforcing; `systemd-analyze
   security xproxy.service` scores in the "OK" band; `ausearch -m AVC` is
   empty after a traffic run.
6. Binaries built with `make build`, checksums published, tag signed.

## Reporting a vulnerability

Report privately to the repository owner (see the repository profile). Do
not open a public issue. Include the version, a reproduction and the impact
you believe it has. Expect an acknowledgement within three working days and
a fix or a mitigation plan within thirty days for issues confirmed as
security relevant. Credit is given in the change log unless you prefer
otherwise.
