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
| Forged `Host` to reach a different virtual host | Host normalised and matched exactly or by single label wildcard; unmatched hosts get 404 |
| Forged affinity cookie to pick a backend | HMAC signed index with expiry (`affinity.verify`, `TestAffinity`) |
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
| Secrets in logs | Query strings not logged; 1.0 redaction rules |
| TLS downgrade | TLS 1.0 and 1.1 refused by validation; insecure suites cannot be configured |

### Denial of service

| Threat | Mitigation |
|--------|------------|
| Connection flood | Kernel SYN cookies (sysctl profile); `max_connections`, `max_connections_per_ip` enforced right after accept, before any goroutine does work beyond the accept loop (`TestConnectionLimits`) |
| Slowloris (slow headers) | `read_header_timeout`, default 10 s (`TestSlowHeaderTimeout`) |
| Slow body / slow read | `read_timeout`, `write_timeout`, `idle_timeout`; upstream `total` timeout |
| Request flood | `max_concurrent_requests` (503, no queue); keyed rate limits; tarpit bounded by the client context so a disconnected attacker frees the goroutine |
| Memory exhaustion via many rate limit keys | Bounded shards with eviction (`TestKeyedLimiterBound`) |
| Large bodies | `max_body_bytes` globally and per route, checked on `Content-Length` and enforced by `MaxBytesReader` |
| Long URIs and huge headers | `max_uri_length` (414), `max_header_bytes` (431) |
| Health check amplification against upstreams | Jittered probes, bounded drain of probe responses |
| Regular expression denial of service | Operator supplied regular expressions exist only in WAF rules; they compile once at load, the CRS is curated, and Go's `regexp` is linear time |
| WAF body buffering as a memory attack | Request bodies are inspected up to `waf.request_body_limit` (default 1 MiB) and rejected or partially inspected above it; response inspection is bounded by `waf.response_body_limit`; both sit under the global body and concurrency limits |
| Ban table exhaustion by spoofed sources | Bans key on the derived client address; tables are bounded with eviction of the soonest expiring entries; trigger windows are bounded per trigger |
| Decompression bombs | The proxy never decompresses; `DisableCompression` on the transport passes encodings through |
| QUIC amplification (1.0) | Retry tokens and address validation enabled; UDP receive buffer bounds |

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
| Upstream impersonation | HTTPS with CA pinning via `ca_file`, `server_name`; verification skip requires double opt-in and is logged |
| Upstream pushes a backend into a poisoned state | Outlier ejection removes failing endpoints; `max_ejection_percent` prevents ejecting everything and stampeding the rest |
| Credentials leaking to the wrong upstream | Route level `request_headers.remove` (for example `Cookie` on an API route) |

## Boundary 2b: Cluster peers

| Threat | Mitigation |
|--------|------------|
| Rogue host joins the cluster | TLS 1.3 with client certificates from the cluster CA required; `allowed_names` pins identities; the listener is bound to an internal address |
| Compromised peer relaxes limits | Impossible by construction: peer reports only reduce refill; there is no message that raises a limit or unbans except an explicit removal, which is visible in logs with the peer identity |
| Compromised peer bans legitimate users | Accepted risk within the trust domain; exemptions still apply, wide prefixes and loopback are refused, `xproxyctl bans` shows `peer:<node>` sources, and `share_bans: false` disables the channel |
| Compromised peer floods the listener | Message size, key and ban counts bounded; inbound connection cap; oversized or malformed input closes the connection |
| Client addresses cross the network in reports | Reports carry rate limit keys (addresses or header values) under mTLS between hosts of the same operator; documented in AMR-021 |
| Peer identity spoofing in messages | The `node` field is informational; authorisation is the certificate, and the certificate name is logged next to it |

## Boundary 3: Management plane

| Threat | Mitigation |
|--------|------------|
| Local user issues commands | Unix socket in a `0750` runtime directory, socket mode `0660` by default, `other` bits refused; kernel `SO_PEERCRED` recorded in the audit log |
| Stale socket hijack | Existing socket is dialled before removal; a live socket aborts start-up |
| Reload of a malicious configuration | The API only reloads the operator's configuration file, it does not accept configuration bodies; the file must not be world writable |
| Denial of service on the management socket | Separate `http.Server` with its own timeouts and a 1 MiB body cap; not reachable from the network |

## Boundary 4: Host and files

| Threat | Mitigation |
|--------|------------|
| World writable configuration | Loader refuses `o+w` files |
| Key exposure | Keys in `/etc/xproxy/certs` labelled `xproxy_conf_t`, mode `0640` `root:xproxy`; unit mounts `/etc/xproxy` read only |
| Log tampering by the service account | Logs are append opened; SELinux allows append and rename inside the log directory only; forwarding to journald or syslog (1.0) moves the record off the host account |
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
