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
- SNI based certificate selection; certificates reload without restart.
- Optional client certificate verification (`request` or `require`) against
  a configured CA bundle.
- Upstream TLS verifies against the system pool or a pinned `ca_file`;
  skipping verification needs `insecure_skip_verify` and `allow_insecure`.

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

### Upstreams

- Connect, response header, idle and total timeouts per pool.
- Response header size capped at 64 KiB.
- Active health checks with jitter; passive ejection with back-off and a
  maximum ejection percentage.
- Retries only for connection level failures of replayable requests.
- Affinity cookies are HMAC signed indexes with expiry, `HttpOnly`,
  `SameSite=Lax`, `Secure` on TLS.

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
- Four separate JSON streams. Log files are created `0640`. Attacker
  controlled values are JSON encoded, which defeats log injection. Query
  strings are not logged.

## Planned controls (see ROADMAP.md)

Phase 2: WAF with OWASP CRS and shadow mode, temporary bans with decay and
cluster sharing, adaptive shedding with priority classes, HTTP/3 with
address validation, mutual TLS to upstreams, JWT validation, PII redaction
rules, journald and syslog sinks.

Phase 3: ICAP scanning, ACME, full SELinux policy in an RPM, GUI with role
separation, coverage and mutation gates, external security review.

## Secure development

- **Language and toolchain.** Go, latest stable, `CGO_ENABLED=0`. Builds are
  `-trimpath`, stripped and reproducible for a given toolchain and module
  set; `go version -m` prints the embedded module list (SBOM).
- **Static analysis.** `go vet`, `staticcheck` and `gosec` through
  `golangci-lint` on every push. Any `nolint` carries a written reason.
- **Race detector.** All tests run with `-race` in CI.
- **Fuzzing.** Every custom parser and matcher has a native fuzz target
  (`FuzzParse`, `FuzzMatch`, `FuzzCleanPath`, `FuzzHost`); CI runs each for
  a short budget, and longer runs are part of the release checklist.
- **Vulnerability scanning.** `govulncheck` in CI fails the build on a
  reachable vulnerability.
- **Dependency review.** New modules require an AMR record and a review of
  the module's own security history.
- **Review.** Changes to `internal/limits`, `internal/netutil`,
  `internal/tlsconf`, `internal/config/validate.go` and the systemd or
  SELinux files require a second reviewer.

## Release checklist

1. `make check` green; `make fuzz FUZZTIME=5m` green.
2. `govulncheck` clean; dependency versions reviewed.
3. THREAT_MODEL.md reviewed against the change log; new threats have
   mitigations or accepted risks.
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
