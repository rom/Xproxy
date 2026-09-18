# Threat Model

Scope: the xproxy data plane, its management plane, its configuration and
its deployment on a Fedora host. Method: STRIDE per trust boundary, with
mitigations mapped to code and to deployment controls, and a list of what is
explicitly out of scope. This document is reviewed at every phase exit
(ROADMAP.md) and before every release.

## Assets

| Asset | Why it matters |
|-------|----------------|
| Availability of the proxied applications | The proxy is the single entry point |
| Private keys and client certificates | Compromise breaks TLS for every host |
| Configuration file | Controls every security policy |
| Logs | Contain client data; tampering hides attacks |
| Upstream network position | The proxy can reach internal services |
| Management socket | Full control of the running process |
| Affinity HMAC keys, cluster credentials (1.0) | Steering and cross-node trust |

## Actors

| Actor | Capability |
|-------|------------|
| Anonymous internet client | Any bytes on any accepted connection, any volume, many source addresses |
| Authenticated client (1.0, mTLS or JWT) | As above plus a valid identity |
| Compromised upstream | Arbitrary responses, slow responses, connection abuse |
| Local unprivileged user on the host | Can reach files and sockets their permissions allow |
| Operator | Trusted; mistakes are in scope, malice is out of scope |
| Peer proxy in a cluster | Holds a cluster certificate |

## Boundary 1: Internet to data plane

### Spoofing

| Threat | Mitigation |
|--------|------------|
| Forged `X-Forwarded-For` to evade IP based limits or ACLs | Only peers in `trusted_proxies` may supply it; right-most untrusted algorithm; header replaced when the peer is untrusted (`netutil.ClientIP`, `TestClientIP`) |
| Forged PROXY protocol header to choose a client address | Parsed only on listeners with `proxy_protocol: true` and only from peers in `trusted_proxies`; any other peer's bytes go to the HTTP parser as they are, where a header is a malformed request; a trusted peer must send one, so a balancer misconfiguration fails closed (`TestProxyProtocolInbound`, `TestProxyProtocolUntrustedPeer`) |
| Forged `Host` to reach a different virtual host | Host normalised and matched exactly or by single label wildcard; unmatched hosts get 404 |
| Forged affinity cookie to pick a backend | HMAC signed index with expiry (`affinity.verify`, `TestAffinity`) |
| Forged identity headers (`X-User` and similar) | Forwarded claim headers are deleted from every request before the token is examined, so only the validator can set them |
| Token forgery: `alg: none`, algorithm confusion, wrong curve, unknown key | No `none`; per-provider allow list; HMAC only from a secret file; ECDSA curve must match; unknown key ids cause one rate limited refresh and otherwise rejection |
| Replay of expired or premature tokens | `exp` mandatory, `nbf` and `iat` checked, bounded skew |
| Key set poisoning | JWKS fetched only over HTTPS with a pinned CA, bounded in size, no redirects; an empty refresh keeps the previous keys |
| Forged or altered DNS answers from a compromised path or upstream reach clients of the dns listener | `dnssec` validates every answer up to a trust anchor before it is cached or served; bogus answers become SERVFAIL and `dns_bogus` events feed the ban list (`TestDNSSECValidation`) |
| Revoked server certificate keeps being trusted by clients that cannot reach the responder | OCSP stapling delivers the responder's answer in the handshake, refreshed in the background; a revoked answer is stapled rather than hidden (`TestOCSPStapling`) |
| Misissued or unlogged certificate deployed unnoticed | Embedded SCTs are counted and, with a log list, verified at every load; `ct.enforce` refuses the certificate and the previous one keeps serving (`TestCertificateTransparency`) |
| TLS SNI mismatch with `Host` | Routing uses `Host`; certificate is chosen by SNI. 1.0 adds an optional strict SNI equals Host check |

### Tampering

| Threat | Mitigation |
|--------|------------|
| Path traversal through routing (`/admin/../public`) | Routing on the cleaned path (`netutil.CleanPath`, `FuzzCleanPath`) |
| Header injection through configured header values | Validation rejects CR, LF and NUL in configured values; `net/http` rejects them in requests |
| Request smuggling (CL.TE, TE.CL) | `net/http` parser rejects ambiguous framing; HTTP/1.1 to upstream is re-serialised by `ReverseProxy`, never forwarded byte for byte; hop-by-hop headers stripped |
| HTTP/2 specific attacks (rapid reset, HPACK bombs, settings floods) | Go `http2` server limits: max concurrent streams, header list size (`max_header_bytes`), read timeouts; Go's rapid reset mitigation is present in the supported toolchain versions |
| Log injection | JSON encoding of every attacker controlled value (`TestOpenAndWrite`) |

### Repudiation

| Threat | Mitigation |
|--------|------------|
| Attacker activity not attributable | Every request has an identifier returned to the client, sent upstream and logged; denies go to the security stream with client address, method, host, path and user agent; WAF events carry matched rule identifiers and scores; bans carry their trigger and count |

### Information disclosure

| Threat | Mitigation |
|--------|------------|
| Server fingerprinting | `Server` header removed from responses; error bodies are reason phrases only |
| Upstream error details reaching clients | `ErrorHandler` writes a generic status; details go to the error log |
| Backend address in affinity cookies | Cookie carries an index, not an address |
| Secrets and personal data in logs | Query strings not logged; redaction rules per stream (address truncation or keyed pseudonyms, user agent and referer reduction, claim hashing, field drop list) applied before every sink |
| Log collector outage used to stall the proxy | Syslog sends from a bounded queue on a background goroutine; journald writes have a short deadline; both drop and count rather than block |
| TLS downgrade | TLS 1.0 and 1.1 refused by validation; insecure suites cannot be configured |

### Denial of service

| Threat | Mitigation |
|--------|------------|
| Connection flood | Kernel SYN cookies (sysctl profile); `max_connections`, `max_connections_per_ip` enforced right after accept, before any goroutine does work beyond the accept loop (`TestConnectionLimits`) |
| Slowloris (slow headers) | `read_header_timeout`, default 10 s (`TestSlowHeaderTimeout`) |
| Slow body / slow read | `read_timeout`, `write_timeout`, `idle_timeout`; upstream `total` timeout |
| Request flood | `max_concurrent_requests` (503, no queue); keyed rate limits; tarpit bounded by the client context so a disconnected attacker frees the goroutine |
| Tarpits used to fill the concurrency ceiling | A tarpitted request releases its concurrency slot and is bounded by `max_tarpits`; above that it is rejected immediately (SR-1, `TestTarpitDoesNotHoldConcurrency`) |
| Memory exhaustion via many rate limit keys | Bounded shards with eviction (`TestKeyedLimiterBound`) |
| Traffic from a country the service does not serve | `routes[].geo` allow and deny lists with a choice for unknown addresses; per country rate limits; evaluated after the address ACL and before the challenge, so the cost is one cached lookup. The country of a forged `X-Forwarded-For` is only trusted from trusted proxies, as the address itself |
| Rate limit bypass by rotating a header keyed value | A missing header falls back to the client address; once a shard is full of active keys the client address decides instead of a fresh burst per value (SR-2, `TestHeaderRateLimitRotation`) |
| Large bodies | `max_body_bytes` globally and per route, checked on `Content-Length` and enforced by `MaxBytesReader` |
| Long URIs and huge headers | `max_uri_length` (414), `max_header_bytes` (431) |
| Health check amplification against upstreams | Jittered probes, bounded drain of probe responses |
| Regular expression denial of service | Operator supplied regular expressions exist only in WAF rules; they compile once at load, the CRS is curated, and Go's `regexp` is linear time |
| WAF body buffering as a memory attack | Request bodies are inspected up to `waf.request_body_limit` (default 1 MiB) and rejected or partially inspected above it; response inspection is bounded by `waf.response_body_limit`; both sit under the global body and concurrency limits |
| Ban table exhaustion by spoofed sources | Bans key on the derived client address; tables are bounded with eviction of the soonest expiring entries; trigger windows are bounded per trigger |
| Decompression bombs | The proxy never decompresses; `DisableCompression` on the transport passes encodings through |
| QUIC amplification and spoofed Initials | Source address validation by Retry for every unvalidated address (default); stateless reset key; handshake bounded by `read_header_timeout` |
| QUIC connection floods | QUIC connections pass the same admission as TCP (ban list, per address and global limits) in the transport's connection hook, before the handshake completes |
| QUIC stream floods inside a connection | `h3.max_streams` per connection; header size and idle timeouts from the listener limits |
| 0-RTT replay | 0-RTT is never enabled |
| Upstream overload (slow backend, thundering herd) | Adaptive shedding by priority class keeps critical routes responsive and rejects low classes early with 503; the concurrency ceiling still bounds the rest |
| Layer 4 listener as a relay to arbitrary hosts | Destinations are only the configured upstream endpoints chosen by server name; unmatched names are closed and logged (`tcp_no_route`, bannable); the ClientHello parser checks every length and reads at most 16 KiB before deciding; the listener has its own connection bound and an idle timeout, and the global accept limits and bans apply |
| Forward proxy as an open relay or SSRF hop (reach internal services, scan through the proxy) | Destinations pass a policy before any connection: listed ports only, private and loopback ranges refused by default, deny and allow lists by name and by resolved address, the checked address is the one dialled (no rebinding between check and connect); optional proxy credentials with 407, verification bounded and cached; refusals and credential failures are security events and ban reasons; tunnels are bounded per listener with an idle deadline; plain responses are size bounded; nothing is inspected inside a tunnel, so the WAF does not apply |
| A malicious or buggy WebAssembly module (memory growth, infinite loop, host escape, header injection) | wazero sandbox with a per instance page limit, a per call deadline that traps the guest, no WASI file system or socket access; strings across the boundary bounded at 64 KiB and validated; header operations bounded per call; a trapped instance is discarded and the request fails closed by default; modules are operator installed files read at load, never fetched |
| Login flow attacks (CSRF on the callback, code injection, open redirect, session forgery, token replay) | `state` bound to an encrypted state cookie with a ten minute life and a nonce carried into the ID token; PKCE stops code injection; return URLs are same-origin paths; sessions are AES-GCM sealed with expiry and purpose, so forging or replaying a state cookie as a session fails; identity headers from clients are dropped; failed callbacks are `oidc` security events and a ban reason |
| Honeypot used against the operator (decoy leaks real data, mark table exhausted, delay ties up slots) | Built-in decoys contain only fabricated values; inline and file bodies are the operator's and are size bounded; the mark table is bounded at 65536 addresses with expiry sweeps and never blocks a request; a delay is spent in a tarpit slot after the request slot is released; marks only label and count, a ban needs a trigger |
| A tenant's Ingress steering traffic or reading secrets of another (ingress mode) | Only Ingresses of the configured class are read; routes and upstreams are named by namespace so two tenants cannot collide, and a collision with the file is an error; TLS secrets are read only when an Ingress in the same namespace references them (Kubernetes RBAC still decides who may create such an Ingress); annotations can only reference rate limits and filters the operator defined in the file; regular expression paths and unknown options are ignored with a warning |
| DNS proxy abused for cache poisoning, amplification or as an open resolver | Every upstream query uses a fresh random transaction id and a fresh socket (random source port) and the answer must echo id and question; only NOERROR and NXDOMAIN answers without TC are cached, TTLs clamped; `allow_clients` and per client rate limits (drop, never answer) keep the listener from being an open resolver or an amplifier; answers over the client's UDP size are truncated to header and question; queries in flight are bounded; malformed packets and responses masquerading as queries are dropped without a reply; blocked names are security events and a ban reason |
| QUIC relay abused (spoofed Initial packets exhaust flows, packets for unknown flows relayed, other versions confuse routing) | Initial packets are authenticated with the derived keys, so a forged packet is dropped; flows are bounded by `max_connections`, expire after `quic_idle_timeout` and incomplete ClientHellos after five seconds; datagrams that belong to no flow and are not a readable Initial are dropped, never relayed; only version 1 is read, others dropped; unknown names are `tcp_no_route` events and a ban reason |
| DNS over HTTPS route as a covert channel or amplifier (any client asks anything) | The route passes the same admission pipeline as every route (rate limits, ACLs, bans) and then the dns listener's policy (allow list, per client limit, block list); queries and answers are bounded at the DNS message size; dropped queries get 403 with no DNS payload; upstream answers over TLS and HTTPS are verified against a pinned CA and must match the question |
| Plaintext HTTP/2 (`h2c`) abused for stream floods or used outside a trusted network | `h2c` is off by default on listeners and upstreams and documented for trusted networks only; the h2c server caps concurrent streams at 250 and frame size at 1 MiB; the same accept limits, bans and request pipeline apply as for HTTP/1.1; gRPC errors are answered without a body so nothing is reflected |
| Mirroring as an amplifier or a leak (copies flood the mirror, sensitive bodies duplicated) | Copies are bounded per route in flight, in body size and in time, sampled by percent and limited to listed methods; the mirror is an operator configured upstream inside the same trust boundary and copies are marked `X-Xproxy-Mirror`; mirror responses are discarded, so a compromised mirror cannot answer clients |
| Cache poisoning (a response for one client served to others) | Keys include host, path and the selected query and headers; `Vary` is honoured per combination; responses with `Set-Cookie`, `private`, `no-store` or `no-cache` are never stored; requests with `Authorization` are not served from or stored into the cache unless the response is explicitly `public`; requests with cookies bypass the cache unless the route opts in; hits still pass the address, ban, ACL, country, challenge, rate limit and request filter stages |
| Scripted clients impersonating browsers | `bot_score` filter: user agent and header consistency, JA3 and JA4 fingerprint of the connection against the claimed browser, behaviour over a window (error rate, path spread, timing regularity, rate), allow and deny lists of fingerprints; the verdict logs, challenges or denies by threshold, and the score can be forwarded to the application |
| Bot floods on browser routes | Challenge gate (always or under load): unverified clients get a cheap static page and must spend CPU on a proof of work before being served |
| Challenge bypass: replaying a solved proof or sharing a cookie | Nonces are signed, single use and expire; cookies are signed and bound to the client address by default; both use a per-installation key |
| Challenge as a DoS vector against the proxy | Page is templated once, costs one HMAC; verification costs one HMAC and one SHA-256; the seen table is bounded; the reserved paths sit behind the connection and concurrency limits |
| Open redirect through the challenge return path | Return values are restricted to same-origin absolute paths; protocol-relative and backslash forms are replaced by `/` |

### Elevation of privilege

| Threat | Mitigation |
|--------|------------|
| Memory safety bug in the parser | Go memory safety; no cgo; fuzzing of every custom parser |
| Compromise of the process leading to host compromise | Unprivileged user, empty capability set, `NoNewPrivileges`, `ProtectSystem=strict`, `MemoryDenyWriteExecute`, syscall filter, SELinux confinement |
| Reaching internal services through the proxy | Only configured upstreams are dialled; the `Host` header never selects an address; `Proxy` function on the transport is nil so environment proxies are ignored |

## Boundary 2: Data plane to upstream

| Threat | Mitigation |
|--------|------------|
| Malicious upstream keeps connections open | `response_header` timeout, `total` timeout, `idle` timeout; `write_timeout` on the client side |
| Upstream returns oversized headers | `MaxResponseHeaderBytes` 64 KiB |
| Upstream impersonation | HTTPS with CA pinning via `ca_file`, `server_name`, minimum version and optional SPKI pins on the leaf; verification skip requires double opt-in and is logged |
| Upstream accepts traffic from anything on the network | Mutual TLS: the proxy presents a client certificate the upstream can require; rotation without restart |
| Upstream pushes a backend into a poisoned state | Outlier ejection removes failing endpoints; `max_ejection_percent` prevents ejecting everything and stampeding the rest |
| Credentials leaking to the wrong upstream | Route level `request_headers.remove` (for example `Cookie` on an API route) |

## Boundary 2a: ICAP scanners

| Threat | Mitigation |
|--------|------------|
| Scanner redirects a request to another host | `Host` and the forwarding headers are protected from modification; only method, path, unprotected headers and body can change |
| Scanner strips or injects credentials | `Authorization` and `Cookie` are protected |
| Scanner returns an oversized or malformed answer | Encapsulated header blocks and bodies are size bounded; parse errors close the connection and count as errors |
| Scanner outage | Per-service `fail: closed` (default) answers 502 with `Retry-After`; `fail: open` passes and counts `bypassed` so it is visible |
| Large uploads used to exhaust the scanner or the proxy | `max_body` per service with reject or bypass; bodies are buffered once, in memory, bounded |
| Eavesdropping on the scanner link | `icaps://` with a pinned CA |

## Boundary 2b: Cluster peers

| Threat | Mitigation |
|--------|------------|
| Rogue host joins the cluster | TLS 1.3 with client certificates from the cluster CA required; `allowed_names` pins identities; the listener is bound to an internal address |
| Compromised peer relaxes limits | Impossible by construction: peer reports only reduce refill; there is no message that raises a limit or unbans except an explicit removal, which is visible in logs with the peer identity |
| Compromised peer bans legitimate users | Accepted risk within the trust domain; exemptions still apply, wide prefixes and loopback are refused, `xproxyctl bans` shows `peer:<node>` sources, and `share_bans: false` disables the channel |
| Compromised peer marks clients as honeypot visitors or revokes sessions | Same trust domain; marks only raise the bot score and label requests (they never ban by themselves, AMR-037), revocations only end sessions, both are bounded per message and by the receiver's tables, marks show `peer:<node>/<route>`, and `share_events: false` disables the channel |
| Session identifiers cross the network in events | Revocations carry the provider's session id (not a cookie or token) under mTLS between hosts of the same operator, keyed by filter name so one provider's ids never touch another's index |
| Compromised peer floods the listener | Message size, key and ban counts bounded; inbound connection cap; oversized or malformed input closes the connection |
| Client addresses cross the network in reports | Reports carry rate limit keys (addresses or header values) under mTLS between hosts of the same operator; documented in AMR-021 |
| Peer identity spoofing in messages | The `node` field is informational; authorisation is the certificate, and the certificate name is logged next to it |

## Boundary 2c: ACME certificate authority

| Threat | Mitigation |
|--------|------------|
| Attacker answers a challenge for a name the proxy serves | `http-01` responses come only from the manager's token table for orders the proxy itself placed; `tls-alpn-01` certificates are minted per challenge and forgotten when the authorization completes; the account key never leaves the state directory |
| Rogue or spoofed CA directory | `https` required; the CA of the directory can be pinned with `ca_file`; the issued chain must cover exactly the group's hosts or it is discarded |
| CA compromise or mis-issuance | Outside the proxy's control; issuance is logged on the error stream (component `acme`) with the issuer and expiry, and the audit stream records every certificate change so CT monitoring can be reconciled |
| Denial of service against renewal (CA outage, rate limits) | Existing certificates keep serving; renewal starts `renew_before` (30 days by default) ahead with hourly back-off, status carries the last error, and `xproxyctl acme` exposes it for alerting |
| Challenge path used to reach the application | `/.well-known/acme-challenge/` never reaches routing: known tokens get the key authorisation, anything else a 404, both before the WAF and upstreams |
| State directory disclosure | `0700` directory and `0600` files under `StateDirectory`; `ProtectSystem=strict` limits writes to it; SELinux confines the process |

## Boundary 2d: Web GUI

The GUI is reachable by browsers, which brings the web attack classes to a
management surface. It is therefore a separate process and user, and the
data plane does not trust it more than any other socket client.

| Threat | Mitigation |
|--------|------------|
| Exposure to untrusted networks | Loopback only by default; a non-loopback bind is refused without server TLS and a client CA (mutual TLS); the unit's `IPAddressAllow=localhost` |
| Password guessing | PBKDF2-HMAC-SHA256 at 600 000 iterations, twelve character minimum, per-source lockout after five failures, uniform timing for unknown users, bounded concurrent verifications |
| Session theft | 256 bit random tokens, `HttpOnly`, `SameSite=Strict`, `Secure` and `__Host-` over TLS, idle and absolute expiry, in-memory store lost on restart |
| Cross-site request forgery | Custom header required on every state change, `Sec-Fetch-Site` and `Origin` checked, `SameSite=Strict` cookie |
| Cross-site scripting and injection | No inline script or style, `script-src 'self'` only, all data rendered through `textContent`, JSON responses `nosniff`, `frame-ancestors 'none'` |
| Viewer escalates to operator | Roles enforced on the server by method: non-`GET` requires the operator role, independent of anything in the page |
| Group member plants a symbolic link in `/etc/xproxy` | Backups open with `O_NOFOLLOW`, temporary files are created exclusively with random names (SR-3) |
| Compromised GUI process edits the configuration | Accepted within the design: the GUI user owns the file for that purpose; every save is validated, atomic, backed up and audited; the data plane still validates on reload and keeps the old generation on error; listeners, cluster and ACME changes need a restart the polkit rule limits to one verb on one unit |
| Compromised GUI process reaches the data plane | Only through the same socket and API as `xproxyctl`, with its own uid in the audit log; it cannot bind data ports, read the account key or change the units |
| Log disclosure through the GUI | Logs are readable by viewers by design (same as the `xproxy` group); redaction applies before the file is written, so the GUI sees redacted data |

## Boundary 3: Management plane

| Threat | Mitigation |
|--------|------------|
| Local user issues commands | Unix socket in a `0750` runtime directory, socket mode `0660` by default, `other` bits refused; kernel `SO_PEERCRED` recorded in the audit log |
| Stale socket hijack | Existing socket is dialled before removal; a live socket aborts start-up |
| Reload of a malicious configuration | The API only reloads the operator's configuration file, it does not accept configuration bodies; the file must not be world writable |
| Denial of service on the management socket | Separate `http.Server` with its own timeouts and a 1 MiB body cap; not reachable from the network |
| Scraping metrics from the network | Optional listener serves only `/metrics`, has a source allow list, optional mutual TLS, and validation refuses all-interfaces binds without a client CA; metrics contain counts and configuration names, never client data |
| Metric label cardinality explosion | Labels come from configuration only (routes, upstreams, endpoints, fixed reasons); per-route counters can be switched off |

## Boundary 4: Host and files

| Threat | Mitigation |
|--------|------------|
| World writable configuration | Loader refuses `o+w` files |
| Key exposure | Keys in `/etc/xproxy/certs` labelled `xproxy_conf_t`, mode `0640` `root:xproxy`; unit mounts `/etc/xproxy` read only |
| Log tampering by the service account | Logs are append opened; SELinux allows append and rename inside the log directory only; the security and audit streams can be sent to journald or a remote syslog collector, which moves the record out of the service account's reach |
| Binary replacement | `ProtectSystem=strict`; SELinux `xproxy_exec_t`; RPM verification in 1.0 |

## Residual risks and accepted limitations

| Risk | Status |
|------|--------|
| Rate limit buckets reset on reload | Accepted; a flood cannot exploit it without also triggering reloads, which require operator access |
| Volumetric attacks above the host's link capacity | Out of scope; requires upstream scrubbing or anycast |
| A full rate limit table fails open for the rate dimension | Accepted and documented; connection and concurrency ceilings still hold; table size is generous |
| WAF false positives can block legitimate traffic | Mitigated by `detect` mode for roll-out, per route profiles and exclusion files; residual risk is operational |
| An attacker can get a shared NAT address banned | Accepted; `exempt_cidrs` for known shared egress, `reject` action and short durations reduce impact; bans never apply to exempt ranges |
| `WriteTimeout` may cut long downloads | Operator tunes per deployment; 1.0 adds per route write deadlines |
| Certificate private keys readable by the service user | Inherent in a single process design (AMR-005); mitigated by file modes, SELinux and no shell in the unit |

## Out of scope

- Physical and hypervisor security of the host
- Vulnerabilities in proxied applications (the WAF reduces, never removes)
- Malicious operators
- Side channels across tenants on shared hardware
