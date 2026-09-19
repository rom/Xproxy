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
- Renegotiation disabled. Session ticket keys are per process and
  rotated by the Go runtime, or, with `server.session_tickets`, derived
  from a `0600` master keyring and the time epoch (HKDF-SHA256) so a
  cluster shares them; only the current and previous epoch's keys exist,
  so a ticket is decryptable for at most two epochs and a compromised
  key exposes at most that window. Peers publish a key set fingerprint
  and a disagreement is logged.
- A verified client certificate's fields reach the upstream only
  through header operations the operator writes (`${cert:cn}`,
  `${cert:fingerprint}`, `${cert:xfcc}`...), which discard a client
  supplied copy of the header; without a verified certificate the
  variables are empty.
- WebTransport sessions are relayed, never interpreted: the CONNECT
  passes every route control (limits, bans, ACLs, expressions), the
  upstream session is opened before the client's is accepted, streams
  and datagrams are copied byte for byte with the session's flow
  control, and the `Origin` header reaches the upstream for its own
  policy. HTTP/3 to upstreams uses the pool's pinned CA and client
  certificate like TCP; a QUIC failure falls back to TCP only on the
  same endpoint and only before a response was received.
- ALPN offers `h2` then `http/1.1`; h2c (cleartext HTTP/2) is never enabled.
- HTTP/3 (QUIC) shares certificates and limits with its TLS listener; new
  client addresses must complete a Retry round trip before state is
  allocated (amplification defence), 0-RTT is disabled, streams per
  connection are bounded, and QUIC connections count against the same
  connection ceilings and ban list as TCP.
- SNI based certificate selection; certificates reload without restart.
- DNS listeners validate DNSSEC when configured: signatures and denial
  proofs are checked up to the root trust anchors, bogus answers are
  refused and logged, DNSSEC records never leak to clients that did not
  ask, and lookups per answer are bounded.
- OCSP stapling per listener: responses fetched in the background from
  the responder the certificate names, refreshed at half their validity,
  never blocking a handshake, revoked answers stapled and logged.
- Certificate Transparency: embedded SCTs parsed at load and verified
  against a configured log list (RFC 6962 precertificate entry); a
  shortfall is logged or, with `enforce`, refuses the certificate.
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
- Keyed rate limits (token bucket or sliding window) by client address,
  client network, route, endpoint template, country, TLS fingerprint,
  header, cookie or token claim, with reject or tarpit actions; keys a
  request may lack fall back to the client address; bucket tables are
  bounded in memory.
- Positive security model per route: allowed methods, media types and
  query parameters with types, lengths, patterns and repeat counts, and
  bounds on the URI, query and headers, refused before any other
  processing with the failed check named in the log.
- Upload protection (`upload_guard` filter): file count and sizes,
  extension chains (double extensions), file names without paths or
  control characters, executables and server side code recognised by
  content, and bytes checked against the name and the declared type,
  before the application stores anything; malware scanning through
  ICAP combines with it.
- Account protection (`account_guard` filter): failed logins counted
  per address, account, pair, accounts per address and addresses per
  account, registrations, resets, cart and catalogue requests counted
  per class, progressive delay, challenge and timed block actions with
  cluster-shared blocks, campaign detection over many addresses,
  disposable registration domains; identities hashed before use.
- Sensitive data detection (`sensitive_data` filter): validated
  detectors for payment cards, Swedish personal identity numbers, IBANs,
  US social security numbers, e-mail addresses, JWTs, private keys, API
  keys and passwords in query strings, plus operator regular
  expressions, in both directions, with log, mask or block per direction;
  the log and the block response name the kinds, never the values.
- Virtual patches: known vulnerabilities blocked by request shape (host,
  route, path, method, parameter, header, cookie and body conditions),
  before rate limits, filters and the WAF, with per patch counters, a
  shadow action and an expiry date.
- Routing on a canonicalised path so dot segments cannot bypass a policy;
  request normalisation refuses control characters and invalid UTF-8 in
  the target by default, can refuse double encoding, encoded separators
  and backslashes, folds Unicode spellings for routing, and closes the
  ambiguous framing cases the parser lets through.
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
- Token introspection (RFC 7662) reaches the authorization server over
  HTTPS with a pinned CA and the proxy's own credentials; answers are
  cached no longer than `cache_ttl` and never past the token's `exp`,
  negative answers included, and the same issuer, audience and claim
  rules apply to introspected claims as to a JWT payload.
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
- Three operating modes per route (`off`, `detect`, `block`) and a
  gradual roll-out of block mode: a stable share of clients by address,
  plus canary prefixes always enforced, so a false positive surfaces
  on a few clients before it reaches all of them.
- Optional response inspection for data leakage rules, bounded by a size
  limit; larger bodies pass uninspected and that fact is visible in the
  configuration, never silent.
- Operator exclusions and custom SecLang rules load between CRS setup and
  CRS rules; a rule set that fails to compile fails the reload.
- Every block and every detection is logged with matched rule identifiers,
  the CRS total score and the WAF phase.
- Per rule statistics over the management socket show which rules fire
  and how often, so a rule set is tuned from evidence rather than by
  lowering the paranoia level. Optional learning proposes exclusions
  scoped to a route's path for repeatedly matched (rule, variable)
  pairs; proposals are never applied automatically, the output states
  that a proposal is not a judgement of legitimacy, and the tables are
  bounded in rules, entries and clients per entry.
- The rule set can be loaded from an operator directory (`crs.dir`)
  instead of the embedded copy, so a CRS security release is applied
  with a reload. The directory is read only at load, validated for
  layout, and a file that fails to compile keeps the running rules.
  CRS plugins load from a directory the same way and compile with the
  profile.
- JSON body schemas refuse request bodies that do not match the shape
  an endpoint documents before any rule or the application parses
  them, within the same body limit; block and detect modes apply.
- Behavioural anomaly detection flags clients whose rate, rule match
  ratio, error ratio or path spread departs from the population by a
  configured number of standard deviations, so credential stuffing,
  scraping and scanning that never trips a rule still gets logged,
  challenged or blocked. It needs a population (eight scored clients
  per window) before it flags anyone, flags expire, the tracker is
  bounded and the action defaults to logging.

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

### API security

- API keys are stored as SHA-256 digests; the plaintext exists only in
  the output of `xproxyctl apikey add`. Keys carry scopes, an expiry
  and a state, rotate with a bounded grace for the previous secret and
  are revoked in place so an id is never reused; the filter forwards
  the id and scopes in headers it first strips from the client.
- The API inventory discovers the exposed surface from traffic (host,
  method, path template, credentials, versions), and against an
  OpenAPI description reports shadow endpoints, zombies and superseded
  versions, recording templates and counts only, never parameter
  values or bodies.
- OpenAPI validation is an allow list derived from the API description:
  undocumented paths, methods, parameters and media types and bodies
  that do not satisfy the schema are refused before the application,
  with bounded body buffering, a bounded schema nesting depth and a
  bounded pattern cache.
- GraphQL bounds (depth, complexity with list multipliers, aliases,
  batches, size, introspection) are computed by a parser with a token
  budget, so a hostile query is refused in bounded time and never
  reaches a resolver.

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

### Fleet

- Nodes pull; the controller never connects to a node and holds no
  credential for one. Both directions use mutual TLS 1.3 from a private
  fleet CA, and a node id is bound to the certificate's name, so a node
  can fetch only its own bundle and report only as itself.
- Bundle paths are validated against traversal, hidden names, depth and
  size; files are written through a directory handle that never follows
  a link out of the configuration directory, and the configuration
  goes through the same validation and sandbox check as any reload,
  with the previous files restored on refusal.
- The controller serves only bundles that parse; an invalid edit keeps
  the last good bundle in service and is visible, never silently
  applied. `apply: false` gives a review posture per node.
- Compromise of the controller host means control of every node's
  configuration: treat it as a tier zero system (HARDENING.md), keep
  its directory under version control with review, and restrict who
  may write it and who may use its operator socket.

### Upstreams

- Connect, response header, idle and total timeouts per pool.
- Response header size capped at 64 KiB.
- Active health checks with jitter; passive ejection with back-off and a
  maximum ejection percentage.
- Retries only for connection level failures of replayable requests.
- Affinity cookies are HMAC signed indexes with expiry, `HttpOnly`,
  `SameSite=Lax`, `Secure` on TLS.
- Bypass protection for origins: mutual TLS to the upstream with a
  client certificate and SPKI pinning, and a per request HMAC signature
  (`origin_signature`) over method, host, path, query, time, client
  address, request id and chosen headers that the origin verifies, with
  key rotation through a keyring; HARDENING.md pairs both with network
  filtering so an origin accepts nothing that did not pass the proxy.


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
- Every symmetric secret file (affinity, challenge, OIDC cookie,
  redaction hash) is a keyring: `xproxyctl rotate-secret` adds a fresh
  primary key and keeps a bounded number of old ones for verification,
  so keys rotate on a schedule without logging users out or dropping
  sessions; files are written `0600` through a rename.
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

### Process confinement

- After start the daemon confines itself (`sandbox`, on by default):
  Landlock rules derived from the configuration leave only the
  configured directories reachable and refuse new TCP binds; a seccomp
  deny list on every thread refuses tracing, module loading, mounts,
  namespaces, keyrings, BPF, io_uring, identity changes and exec; every
  capability set is cleared; `no_new_privs` is set; the process is non
  dumpable with no core files. `strict` makes an unavailable mechanism a
  failed start. A reload naming a file outside the rules is refused.
- On macOS the process denies debugger attachment and core files; the
  launchd job runs it under a Seatbelt profile with the same file
  system view, as a hidden system user, and pf fronts it
  (docs/HARDENING_MACOS.md).
- The WebAssembly engine uses the interpreter wherever executable memory
  is refused, so W^X policies never have to be relaxed for a filter.
- Bounded tables never fail silently: reaching a cap is counted, warned
  about (throttled) and visible in the status views, so an attack that
  fills a table is seen rather than absorbed.

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
  any non-loopback listener. Single sign-on, when configured, is the
  authorization code flow with PKCE and a nonce against a pinned
  provider; the ID token is verified for signature, issuer, audience,
  expiry and nonce, the role comes from a claim mapped by the operator
  and an unmapped user is refused. Configuration edits are validated before they
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
- SIEM export over HTTPS in newline delimited JSON, the Splunk HTTP
  Event Collector envelope, CEF or LEEF (the last two also over syslog),
  with the credential read from a file rather than the configuration,
  a pinned CA and an optional client certificate, the same bounded
  asynchronous queue, and redaction applied before export.

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
