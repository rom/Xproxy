# Security review (phase 3)

A review of the code against [THREAT_MODEL.md](THREAT_MODEL.md), done at
the end of phase 3 before the 1.0 release. It records what was examined,
how, what was found, what changed, and what is accepted as residual risk.
The findings are numbered SR-n and referenced from the tests and the
changelog.

## Scope and method

Reviewed, in order of exposure:

1. The request path from accept to upstream and back:
   `internal/kinds/http/handler.go` (admission pipeline, deny paths, tarpit,
   forwarding headers, error handling, access logging), `writer.go`,
   `transport.go`, `internal/netutil` (client address, host, path).
2. Admission state: `internal/limits` (connection, concurrency and keyed
   limiters), `internal/ban`, `internal/shed`, `internal/challenge`.
3. Parsers of attacker supplied bytes: cluster wire protocol, ICAP
   responses, ACME responses, JWKS, JWT, the challenge form, the GUI's
   JSON API.
4. Privileged surfaces: the management socket and its peer credentials,
   the GUI (sessions, roles, CSRF, TLS, file writes), the configuration
   loader, the daemon's start-up checks, the systemd units, the SELinux
   policy and the packaging scriptlets.
5. Secrets on disk: ACME account key, challenge and affinity keys, GUI
   users file, basic authentication users files, logs.

Method: reading with the threat model open and, for each mitigation it
claims, locating the code and the test that exercises it; a grep sweep
for the classic weaknesses (non-cryptographic randomness in security
paths, disabled certificate verification, shell execution, loose file
modes, servers without timeouts, `unsafe`); the existing fuzz targets;
and `govulncheck` (see below). Each finding was reproduced with a test
before it was fixed, and the test stays as the regression check.

## Findings

| ID | Area | Severity | Finding | Resolution |
|----|------|----------|---------|------------|
| SR-1 | Rate limiting, tarpit | Medium | A tarpitted request held its `max_concurrent_requests` slot for the whole tarpit delay while doing nothing. Requests over a tarpit limit are cheap to produce, so an attacker could fill the concurrency ceiling with held requests and starve legitimate traffic: the tarpit turned a per-client penalty into a global one. | A tarpit now releases its concurrency slot first and takes a slot from a separate bound, `server.limits.max_tarpits` (default 1024); above that bound the request is rejected at once with 429. `tarpit_overflow` and `tarpit_active` are exposed. `TestTarpitDoesNotHoldConcurrency`. |
| SR-2 | Rate limiting, header keys | Medium | A limit keyed on a header gives each distinct value its own bucket with a full burst. Once the bounded key table was full of active keys, a new key was allowed untracked (bounded only by burst), so a client rotating header values obtained a fresh burst per value and, after filling the table, was not limited at all. The design assumed such limits are paired with a per address limit; the example configuration does that, the schema did not require it. | When a key's shard is full, the decision is made on the client address instead (`AllowFallback`), so a rotating client is bounded by its address bucket. The handler passes the address for every keyed limit. `TestAllowFallback`, `TestHeaderRateLimitRotation`. |
| SR-3 | GUI, file writes | Low | The GUI's configuration backup (`xproxy.yaml.bak`) and the users file's temporary file were written by name with `os.WriteFile`, which follows a symbolic link. A member of the `xproxy` group able to create a link in `/etc/xproxy` could have redirected a write into another file the GUI user may write. | Backups open with `O_NOFOLLOW`; temporary files are created with `os.CreateTemp` (`O_EXCL`, random name) in the GUI, the users file and `xproxyctl htpasswd`. |
| SR-4 | Logging | Low | Failed log writes (full disk) were silent: the event was lost and nothing recorded that it had been. Found by the chaos tests. | Counted in `log_write_errors` and `xproxy_log_write_errors_total`; one stderr warning per minute. |
| SR-5 | TLS | Low | The expiry of file certificates was not observable from the proxy; an expired certificate was found by clients. | `xproxy_certificate_expiry_seconds{listener}`; ACME certificates report through the ACME status. |

No critical or high finding. SR-1 and SR-2 are the ones a public
deployment would have met first, both in the rate limiting code, both
in the difference between the design's intent and the code's behaviour
under a full table or a slow client; the tests now pin the intent.

## Verified as claimed

The threat model's mitigations were located in code and tests for:
client address derivation (right-most untrusted hop, malformed chain
falls back to the peer, `X-Forwarded-For` from an untrusted peer is
dropped by the reverse proxy's rewrite path before the chain is
re-attached for trusted peers); path cleaning before routing; host
normalisation; connection limits at accept; no queueing above the
concurrency ceiling; header, URI and body bounds; the challenge's signed
single use nonces bound to the client address, constant time
comparisons and the same-origin return path; affinity cookie signatures
in constant time; JWT algorithm allow lists, `alg: none` rejection,
header spoof removal; ban targets refusing loopback and wide prefixes;
cluster line and connection bounds, mutual TLS, no message that raises a
limit; ICAP, ACME and JWKS response size bounds; the management socket's
mode, umask and kernel peer credentials; the GUI's cookie attributes,
three CSRF checks, role enforcement by method, PBKDF2 with lockout; the
loader's refusal of a world writable configuration; `insecure_skip_verify`
requiring `allow_insecure`; no shell in the restart command; every
listener with header and idle timeouts.

## Residual risks (accepted, documented)

- A slow client can hold a request for up to the upstream `total`
  timeout (5 minutes by default) while sending its body; the concurrency
  ceiling bounds how many, and `server.limits.max_buffered_body_bytes`
  bounds the heap they can hold between them. Lowering `timeouts.total`
  on routes that accept uploads from the Internet is the operator's
  lever.
- A consistent hash keyed on a header or cookie lets a client choose its
  endpoint and therefore concentrate load on one backend. Use `client_ip`
  hashing on routes exposed to untrusted clients.
- Group members can read logs, which carry client addresses unless
  redaction is on; that is the documented purpose of the group.
- The proxy does not itself refuse to serve an expired certificate;
  clients do. The expiry gauge exists to alert before that.
- `govulncheck` could not fetch the vulnerability database from the
  review environment (outbound policy); the CI `security` job runs it
  against every push. The dependency set was reviewed by hand against
  the versions in `go.mod` (AMR-004) at the time of the review.

## Later rounds

Four more audit rounds followed this one, each in disciplines the
previous ones did not cover, a fifth over every parser the data plane
runs, and a sixth over the parsers added after that — the RDP
connection sequence and its two encryption layers, the RFB handshake
with the vendors’ own security types, NTLM and CredSSP, the QR
encoder, and the second factors the control plane can now change. Their
findings and resolutions are in the changelog rather than here; this
document is the phase 3 review and stays what it was.

Every open finding carried out of rounds one to four is closed. Where a
resolution changed a default rather than only adding a setting, the
default is the one this document and the threat model now describe:
`cluster.tls.bind_node_id` is on, `tracing.redact_client_address` is on,
compression no longer touches an authenticated response unless
`compression.compress_authenticated` says so, and the daemon refuses to
start as uid 0 without `-allow-root`.

## What the review did not cover

- A running Fedora host with SELinux enforcing (the policy compiles; AVC
  validation is the remaining phase 3 item).
- The WAF rule set itself (OWASP CRS is taken as reviewed upstream; the
  integration is covered).
- Cryptographic protocol review of the ACME and JWT implementations
  beyond conformance tests; both use the standard library primitives.
- Third party review. This document is the internal review; an external
  one is planned before 1.0 as the release checklist states.
