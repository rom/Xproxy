# Architecture

xproxy is a single static Go binary that terminates HTTP at the edge, applies
security policy and forwards to upstream pools, plus a control binary that
manages it over a local socket. This document describes the components, the
request path, the data flows and the reasoning behind the shape. Decision
records are in [AMR.md](AMR.md); requirements in [ASR.md](ASR.md).

## 1. System context

```
                     internet
                        |
            +-----------v-----------+
            |  kernel: nftables,    |   sysctl profile, SYN cookies,
            |  conntrack, SYN queue |   optional per-source connection rate
            +-----------+-----------+
                        | accept (systemd owned sockets)
            +-----------v-----------+        +-------------------+
            |        xproxy         |<-------| xproxyctl (CLI,   |
            |  data plane process   | unix   |  TUI), xproxy-    |
            |  user: xproxy         | socket |  admin (web GUI)  |
            +--+------+------+------+        +-------------------+
               |      |      |
        access | err  | sec  | audit      -> files, journald, syslog
               v      v      v
            +--------------------------+
            | upstream pools           |  http / https, health checks,
            | app-1 app-2 ... api-n    |  affinity, ejection
            +--------------------------+
```

Trust boundaries:

1. Internet to xproxy: hostile. Everything read from a client connection is
   attacker controlled, including TLS ClientHello, headers, body and timing.
2. xproxy to upstream: semi-trusted. Upstreams may be compromised; response
   headers and bodies are not executed but are size and time bounded.
3. Operator to management socket: trusted, authenticated by the kernel
   (Unix socket permissions and `SO_PEERCRED`), audited.
4. Configuration and certificate files: trusted, must be root or `xproxy`
   owned and not world writable (the loader refuses world writable
   configuration).

## 2. Repository layout

```
cmd/xproxy          data plane daemon (flags, signals, systemd notify)
cmd/xproxyctl       management CLI and TUI
cmd/xproxy-admin    web GUI process (users, sessions, embedded assets)
internal/config     schema, defaults, loader, validation
internal/router     host and path matching
internal/netutil    client IP derivation, path cleaning, host normalisation
internal/limits     token buckets, connection limiter, concurrency limiter
internal/tlsconf    hardened tls.Config construction and certificate reload
internal/upstream   endpoints, balancers, health checks, affinity, ejection
internal/proxy      server, listeners, handler pipeline, transport, stats
internal/logging    four slog streams, file rotation
internal/mgmt       management API server and client
internal/filter     middleware interface, kind registry, options decoding; filtertest harness
internal/filters    built-in kinds (header_guard, basic_auth, bot_score, oidc, wasm) and the registration list
internal/filters/wasm  WebAssembly ABI v1 on wazero (the only package importing wazero)
internal/passwd     PBKDF2 password hashing shared by basic_auth and the GUI
internal/geoip      MaxMind DB reader and CSV prefix table for country lookups
internal/cache      in-memory response cache (LRU, byte bound, Vary)
internal/proxy/tcp.go  kind: tcp listeners (SNI routing, PROXY v2, splice)
internal/proxy/forward.go  kind: forward listeners (CONNECT tunnels, plain relay, destination policy)
internal/dns        DNS proxy: message framing, cache, block list, resolver, UDP and TCP server
internal/ingress    Kubernetes ingress controller: API client, translation, merge, polling
internal/proxy/dnslistener.go  kind: dns listeners bound to the proxy's logs and bans
internal/proxy/static.go  routes[].static: files through os.Root, index, listing, fallback
internal/waf        Coraza + OWASP CRS engine as a filter
internal/ban        ban list with triggers, escalation and persistence
internal/cluster    peer sharing of limits and bans over mutual TLS
internal/shed       adaptive load shedding by priority class
internal/challenge  browser proof-of-work challenge
internal/h3         HTTP/3 over QUIC (the only package importing quic-go)
internal/jwt        JSON Web Token validation on the standard library
internal/icap       ICAP client (RFC 3507) as a filter; icaptest fake server
internal/metrics    Prometheus text encoder, histogram, sampled series
internal/tui        terminal UI of xproxyctl (pure renderer plus a raw-mode loop)
internal/admin      web GUI server: users file, sessions, API over the management client, static/ assets
internal/version    build information
deploy/             systemd units, sysusers, sysctl, SELinux policy, polkit, logrotate, RPM spec, example config
docs/               this documentation
test/               cross package and binary level tests (grows in 1.0)
```

Packages under `internal/` cannot be imported from outside the module, which
keeps the API surface at exactly three binaries.

Dependency direction (arrows point at the importer's dependency):

```
cmd/xproxy -> mgmt -> proxy -> {router, upstream, limits, netutil, tlsconf, logging, config, filter, waf, ban, cluster, shed, challenge, h3, jwt, metrics, icap}
                       icap     -> {filter, config}
                       metrics  -> (standard library only)
                       jwt      -> {filter, config}
                       h3       -> {limits, config}
                       cluster  -> {ban, limits, config}
                       waf      -> {filter, config}
                       ban      -> {netutil, config}
                       upstream -> {tlsconf, config}
                       router   -> config
                       logging  -> config
```

No package imports `proxy` except `mgmt` and the commands. `config` imports
only `filter` (to validate `filters[].options` against the registry);
`filter` imports nothing from the module. `admin` imports only `mgmt` (the client), `config`
(validation of edited files) and `tlsconf`; it never links the data plane.

## 3. Process model

One process, one user, no capabilities. systemd passes the listening sockets
(`LISTEN_FDS`), the process matches them to configured listeners by name or
address and binds any listener that was not passed. Datagram sockets are
matched the same way (name `<listener>-udp` or address) for HTTP/3. The process sends
`READY=1`, `RELOADING=1` and `STOPPING=1` over `NOTIFY_SOCKET`.

Signals: `SIGHUP` reloads the configuration, `SIGUSR1` reopens log files,
`SIGTERM` and `SIGINT` drain and stop within `server.shutdown_timeout`.

Goroutines: one per accepted connection (owned by `net/http`), one per
endpoint with an active health check, one per HTTP/2 stream. There is no
worker pool and no unbounded queue; back-pressure is applied by refusing
work (AMR-007).

## 4. Configuration generations

```
   config file --Load--> *config.Config --newRuntime--> *runtime
                          (validated,                     router
                           defaulted,                     pools (transports, health)
                           immutable)                     rate limiters
                                                          trusted prefixes
                                                          compiled routes

   Server.rt : atomic.Pointer[runtime]
```

`Server.Reload` builds a complete new runtime, reloads certificates, then
swaps the pointer. In-flight requests hold the runtime they started with.
The old runtime's pools are stopped after `shutdown_timeout`. Any failure
before the swap leaves the old generation active and increments
`reload_failures`.

Listener changes (address, TLS mode, protocols, client auth) are refused by
`Reload` because sockets may be systemd owned; they need a restart.

## 5. Request path

Every request passes through the following stages in order. The stage that
rejects a request writes a security log entry and the access log records
the `denied` reason.

| # | Stage | Rejects with | Counter |
|---|-------|--------------|---------|
| 0 | Accept: `ConnLimiter.Wrap` closes connections beyond `max_connections` or `max_connections_per_ip` before any byte is read | connection closed | `rejected_connections` |
| 1 | `net/http` reads headers under `read_header_timeout` and `max_header_bytes` | 408 / 431 by the server | (server) |
| 0b | Accept: banned peers are closed when `bans.action` is `drop` | connection closed | `rejected_connections` |
| 2 | Concurrency: `Concurrency.Acquire` | 503 + `Retry-After` | `denied_concurrency` |
| 2b | Ban list lookup on the derived client address | 403 | `denied_ban` |
| 3 | Plaintext redirect listener: 308 to https | 308 | |
| 4 | URI length | 414 | `denied_uri_length` |
| 5 | Host normalisation (`netutil.Host`) | 400 | `denied_bad_host` |
| 5b | Reserved paths `/.xproxy/challenge` (proof verification) and `/.xproxy/challenge.js` | 303 / 403 | `challenges_*` |
| 6 | Path cleaning (`netutil.CleanPath`) and route match (host, path prefix or anchored pattern, method, header and cookie conditions) | 404 | `denied_no_route` |
| 7 | CIDR deny then allow | 403 | `denied_acl` |
| 7b | Challenge gate: unverified clients on routes with `challenge` (always, or in `load` mode above the level) receive the page | 503 page | `challenges_issued` |
| 7c | Adaptive shedding: the route's priority class against the load level | 503 + `Retry-After` | `shed` |
| 8 | Rate limits in route order; reject or tarpit | 429 | `denied_rate_limit`, `tarpitted` |
| 9 | Body limit: declared length checked, then `MaxBytesReader` | 413 | `denied_body_size` |
| 9b | Filter chain request phase: JWT (401 with `WWW-Authenticate`, claims forwarded as headers, token stripped), then WAF (headers, then body, buffered and replayed to the upstream), then ICAP REQMOD (block page, modified request, or pass) | 401 / 403 / scanner status | `denied_jwt`, `denied_waf`, `denied_icap`, `waf_detected` |
| 10 | Route timeout context | 504 | `upstream_timeouts` |
| 11 | Action: redirect, respond, or proxy | | |
| 12 | Proxy: WebSocket gate | 403 | `denied_websocket` |
| 13 | Proxy: `httputil.ReverseProxy` with `poolTransport` | 502 / 503 / 504 | `upstream_*` |
| 13b | Filter chain response phase: WAF response rules when `inspect_responses`, then ICAP RESPMOD when enabled | 403 / scanner status | `denied_waf`, `denied_icap` |
| 14 | Response: header operations, `Server` removal, affinity cookie | | |
| 15 | Access log | | `responses_*`, `bytes_*` |

Every deny at stages 2 to 13 is reported to the ban list (`Observe`) with
its category, so triggers can turn repeated denies into bans.

Upstream time to first byte is observed in `ModifyResponse` (and on
timeouts) and feeds the shedder.

A deny verdict may carry a complete response (a scanner's block page),
which the handler writes verbatim apart from its own hygiene headers.

### Client address

`netutil.ClientIP` returns the TCP peer unless the peer is inside
`trusted_proxies`, in which case it walks `X-Forwarded-For` from the right
and returns the first address that is not a trusted proxy. A malformed hop
falls back to the peer. When forwarding, the inbound `X-Forwarded-For` is
kept only from trusted peers; otherwise it is replaced by the peer address.
`Forwarded` is always removed. This is the only correct construction when
the proxy is behind a known chain and the strictest one when it is the
edge.

Listeners with `proxy_protocol: true` establish the peer one layer
lower. `proxyListener` (`internal/proxy/proxyproto.go`) wraps the
limited listener; its connections parse a PROXY protocol v1 or v2 header
(`netutil.ReadProxyHeader`) lazily, on the first `Read` or `RemoteAddr`
call, which `net/http` makes in the connection's own goroutine, so the
accept loop never waits on a slow balancer. Only a peer inside
`trusted_proxies` is parsed; the header's source becomes `RemoteAddr`,
the connection limiter re-keys the per address count to it (`Rekey`),
and everything above (TLS fingerprinting, `ClientIP`, bans, logs) sees
the client. A trusted peer without a header, or with a bad one, gets its
connection closed silently and a `drop_connection` event; the parse has
a five second deadline.

### Path handling

Routing uses `path.Clean` semantics on the request path so that
`/admin/../public` matches the `public` route and cannot bypass a policy on
`/admin`. The upstream receives the original path unless the route strips or
rewrites it. Prefixes match on segment boundaries: `/api` matches `/api/x`
but not `/apix`.

### Upstream selection and retries

A response whose status is listed in the pool's `retry_on` is treated by
`poolTransport` like a connection error: its body is drained and
closed, the endpoint is marked as failed for outlier ejection, and the
next attempt goes to another endpoint while the `retries` budget and
the replayability rule allow; the last attempt's response is returned
unchanged. The attempt count and the number of status retries travel
back in `pickInfo` for the access log and the counters.

`poolTransport.RoundTrip` picks an endpoint per attempt:

1. If the pool has affinity and the request carries a valid cookie for an
   available endpoint, use it.
2. Otherwise ask the balancer, excluding endpoints already tried.
3. On a connection level error (dial, reset, EOF before response) with a
   replayable request (GET, HEAD, OPTIONS, TRACE without a body), try the
   next endpoint, up to `retries` times.
4. Record the outcome on the endpoint for outlier ejection; a 503 counts as
   a failure signal, other statuses do not.

The response body is wrapped so that the in-flight counter is decremented
exactly once when the body is closed, which keeps `least_conn` accurate for
streaming responses.

## 6. Upstream pools

```
Pool
 ├── Endpoints[]      address, weight, healthy(atomic), ejectedUntil(atomic), active(atomic)
 ├── balancer         roundRobin | weighted (smooth WRR) | leastConn | ring (consistent hash)
 ├── affinity         HMAC key, cookie name, TTL
 ├── Transport        *http.Transport: dial timeout, response header timeout,
 │                    idle pool per host, no environment proxy, no compression changes
 └── health loop      per endpoint, jittered start, thresholds
```

Endpoint availability is `healthy && !ejected`. Active checks flip
`healthy`; passive failures set `ejectedUntil` with `base_ejection_time`
multiplied by the ejection count (capped at 10) subject to
`max_ejection_percent`. Both are lock free reads on the hot path.

The consistent hash ring uses 128 virtual nodes per weight unit. Removing
an endpoint moves only its keys (`TestHashRing` asserts this).

## 7. Limits

- `KeyedLimiter`: 64 shards, each a map of lazily refilled token buckets.
  Keys per shard are capped; on a full shard, buckets that have fully
  refilled are evicted; if none can be, the request is allowed without
  tracking. Memory is therefore bounded at `64 * maxKeys` buckets per policy.
  With clustering, each bucket also holds up to 64 peer rate reports with
  timestamps; refill uses `rate - sum(fresh peer rates)`, clamped at zero,
  and `Flush` returns and resets per key consumption for gossip.
- `ConnLimiter`: wraps the listener; counts per IP in a map guarded by one
  mutex (accept rate, not request rate) and globally with an atomic. Limits
  are adjustable on reload.
- `Concurrency`: an atomic counter with a ceiling. No waiting.
- Timeouts come from `net/http` (`ReadHeaderTimeout`, `ReadTimeout`,
  `WriteTimeout`, `IdleTimeout`) and from contexts (route timeout, upstream
  total).

## 8. TLS

`tlsconf.Server` produces a `tls.Config` with TLS 1.2 minimum (or 1.3),
X25519 first, AEAD forward secret suites only, renegotiation disabled and
ALPN listing `h2` before `http/1.1` because Go honours server preference.
Certificates live behind an atomic pointer read by `GetCertificate`, which
selects by SNI and falls back to the first certificate. Client CA and auth
mode are fixed for the life of a listener.

`GetCertificate` consults three sources in order: the file certificates,
the `Managed` callback (certificates issued by ACME, read from the ACME
manager's own atomic snapshot) and, only for a handshake whose ALPN is
`acme-tls/1`, the `Challenge` callback that returns the self-signed
validation certificate for a pending `tls-alpn-01` challenge; without a
pending challenge such a handshake is refused rather than answered with a
real certificate. Listeners with ACME groups add `acme-tls/1` to their
ALPN list.

### Layer 4 passthrough

A `kind: tcp` listener (`internal/proxy/tcp.go`) accepts through the same
limiter as every listener (bans, per address and global connection
limits), peeks the first record with `netutil.ClientHelloSNI` (a
defensive parser that never copies and checks every length), resolves
the upstream by name or default, dials an endpoint chosen by the pool's
balancer with retries across endpoints, optionally writes a PROXY v2
header, replays the peeked bytes and splices both directions with an
idle deadline and half-close. Connections are accounted on the pool like
requests so ejection and health apply. The listener has its own
connection bound and is drained on shutdown like the HTTP servers.
With `quic` the listener also owns a UDP socket: `netutil.QUICCryptoData`
decrypts a version 1 Initial packet with the keys derived from its
destination connection id (HKDF over the published salt, header
protection removed, AES-GCM opened, frames walked), a
`QUICHelloAssembler` reassembles CRYPTO data across the client's first
datagrams, the server name is read with the same ClientHello parser,
and the relay keeps one flow per client address (an upstream UDP
socket and a pump goroutine) until it is idle. Datagrams after the
Initial are forwarded without being read.

### Metrics collection and export

`Server.Collect` runs one collection of every metric family into a
`metrics.Collector`; the Prometheus encoder implements it for
`/metrics`, and the OTLP exporter implements it to build an
OTLP/HTTP JSON request (counters as cumulative monotonic sums from the
process start time, gauges, histograms with explicit bounds) that it
pushes on an interval with a bounded client, gzip and pinned CA. No
metrics library is linked on either path.

### Kubernetes ingress mode

`internal/ingress` is a polling controller with no client library: a
small REST client with the service account token and CA lists
Ingresses, Services and EndpointSlices (and fetches referenced TLS
Secrets), `Translate` turns them into `config.Route` and
`config.Upstream` values plus certificate material as a pure function
with per object warnings (Ingress rules and, through `translateGateway`
sharing the same endpoint resolver, Gateway API Gateways and
HTTPRoutes), the controller writes certificate files atomically into
`cert_dir` and removes stale ones, and `Merge` appends the snapshot to
the operator's configuration and runs the result through the ordinary
parser (YAML round trip) so every default and validation rule applies.
The main binary computes the effective configuration as file plus
snapshot at start and on every reload; the controller asks for a
reload when the snapshot's digest changes. Change detection is a watch
stream per collection (JSON events decoded and counted, never
interpreted: any event kicks a debounced full sync) reconnecting with
backoff, with the resync poll as the fallback, so translation stays a
function of one consistent list. The data plane knows nothing about
Kubernetes.

### DNS proxy

`internal/dns` handles messages as bytes. The parser reads the header,
the single question (with compression pointers that may only point
backwards, never into the header, at most sixteen hops) and the
framing of resource records (to find TTLs, the OPT record's UDP size
and where a message can be cut); it never decodes record data. The
server serves one UDP socket and one TCP listener with a shared
semaphore on queries in flight; each query passes bans, the per client
rate limit, the client allow list, the block list (exact and suffix
lookups per label), then the cache (responses stored with TTLs adjusted
by age on the way out) and finally the resolver, which forwards with a
fresh id on a fresh socket and accepts only an answer that echoes the
id and the question; `tls://` upstreams keep a small pool of DNS over
TLS connections per server and `https://` upstreams post
`application/dns-message` through one HTTP client with the pinned CA.
A `kind: dns` listener wraps this in
`internal/proxy/dnslistener.go`, binding the access log, security
events and the ban list; its policy is an immutable value swapped on
reload while the cache survives.

A `doh` route (`internal/proxy/doh.go`) decodes an RFC 8484 request on
an http listener and hands the query to the named dns listener's
`Handle`, so DNS over HTTPS clients get the same policy and cache as
UDP clients plus the route's own admission pipeline.

### Forward proxy

A `kind: forward` listener (`internal/proxy/forward.go`) is an
`http.Server` on the same accept limiter whose handler is the forward
server instead of the request pipeline. The policy (ports, allow and
deny rules compiled to name matchers and prefixes, users) is an
immutable value swapped on reload. A request is authenticated first
(`Proxy-Authorization` Basic against the users file, verified
credentials cached by digest, at most four verifications at once), then
the destination is checked: port listed, name resolved with the connect
timeout, resolved addresses not private, deny then allow. The approved
addresses travel in the request context to the dialer, which connects
to them rather than to the name. CONNECT hijacks the client connection,
writes `200 Connection Established`, forwards any bytes the client sent
early and splices with the same idle deadline and half-close as the tcp
listener; tunnels are counted per listener and force closed when a
shutdown exceeds its context. Plain requests go through one
`http.Transport` per listener with the checked dialer, hop-by-hop
headers removed both ways and the response body bounded. Refusals are
security events with a `forward_` reason and feed the ban list.

### WebAssembly filters

The `wasm` kind (`internal/filters/wasm`) owns one wazero runtime per
configured filter with a memory limit and close-on-context-done, the
host module `xproxy`, WASI preview 1, and the compiled module. Guest
instances are pooled; a call takes one (or instantiates a fresh one),
runs the export under a deadline with the per request state in the
context so host functions can reach the request, response and verdict,
and returns the instance to the pool unless it trapped. Strings cross
the boundary through the guest's `xproxy_alloc`, bounded at 64 KiB.
The verdict the guest builds with `deny` is an ordinary
`filter.Verdict`, so wasm denies are logged, counted and observed by
the ban list like every other.

### OpenID Connect login

The `oidc` filter kind (`internal/filters/oidc`) is a state machine
over three paths. Any other path without a valid session cookie gets a
302 to the provider's authorization endpoint with a PKCE challenge and
a nonce; the verifier, nonce and return URL travel in a short lived
state cookie encrypted with the cookie key, and the `state` parameter
is a prefix of that cookie plus a digest of it, so the callback can
bind the two without server side storage. The callback exchanges the
code, verifies the ID token with a `jwt.Provider` built from the
discovered JWKS (the same verifier as `routes[].jwt`), checks the
nonce and required claims, and seals the session (subject, selected
claims, issue and expiry times) with AES-GCM under a purpose string
that keeps state and session ciphertexts apart. Redirects are
`Verdict.Silent` denies: sent as responses without the security
bookkeeping of a refusal.

### Static files

A `static` route (`internal/proxy/static.go`) holds an `os.Root` opened
at generation build (a missing directory fails the reload) and closed
with the generation. Every open goes through the root, so the kernel
refuses paths that escape it through symbolic links, and the request
path is cleaned before it arrives; dot segments are refused in the
handler. Regular files are served with `http.ServeContent` (ranges,
conditional requests, HEAD) under a weak `ETag` from size and
modification time and a fixed content type table; directories serve
their index, a listing or 404; any open failure is a 404. A single page
fallback is one more open inside the same root.

### Response compression

When a route compresses and the client accepts gzip, the handler slips a
`compressWriter` (`internal/proxy/compress.go`) between the logging
`responseWriter` and the connection before the action runs, so every
action writes through it. The writer decides when the header is
committed (status, existing encoding, `no-transform`, media type,
length), buffers an unknown-length body up to `min_bytes`, decides at
the first flush for streamed bodies, and is closed by a deferred call
when the handler returns, which writes the gzip trailer or releases a
small buffered body unchanged. gzip writers are pooled per generation.
The cache stores upstream bodies before this layer, so one entry serves
both encodings.

### Honeypots

A honeypot is a route action next to redirect and respond. The compiled
route holds the decoy bytes (built-in, inline or read from a file at
generation build, so a missing file fails a reload). Serving one
records a security event, adds the address to a bounded mark table
owned by the `Server` (not a generation, so marks survive reloads),
observes the `honeypot` ban reason and answers; a delay is spent in a
tarpit slot after the request slot is released. The mark is read once
per request after routing and exposed to the access log and to filters.

### gRPC

gRPC rides the ordinary pipeline. The router carries a gRPC rank per
entry so that routes with a `grpc` section match only gRPC requests
(by content type) and rank above plain routes on the same path; the
service and method come from the request path. Plaintext HTTP/2 uses
the standard library's `Protocols` setting: an `h2c` listener enables
unencrypted HTTP/2 on its `http.Server` with the same stream and frame
bounds as TLS listeners, and an `h2c` upstream gets a clone of the pool
transport that speaks only unencrypted HTTP/2, which `Pool.RoundTripper`
selects; no HTTP/2 library outside `net/http` is linked. The reverse
proxy already relays `TE: trailers` and trailers, so streaming works
without special casing. `plainStatus` answers a gRPC request over
HTTP/2 with a trailers-only response and a mapped `grpc-status` instead
of a text page; the client's `grpc-timeout` tightens the route
deadline. Health checks of type `grpc` post a hand encoded
`HealthCheckRequest` to `grpc.health.v1.Health/Check` and read the
status from the response, so the standard health service works without
a protobuf library. The upstream response's `grpc-status` is captured
at end of body for the access log and a per code counter.

### Request mirroring

`prepareMirror` runs in `proxyTo` before the live request is handed to
the reverse proxy: it samples, buffers the body up to the bound (the
live request reads the buffer; over the bound the live request reads
the prefix followed by the rest and no copy is made), and builds the
copy through the same `rewrite` as the live request. `sendMirror`
takes a slot from the route's in-flight semaphore or drops the copy,
then delivers it in a goroutine through a `poolTransport` with no
retries and its own timeout, discarding the response. Nothing on the
mirror path can block or fail the client's request.

### Response cache

`internal/cache` is a byte bounded LRU of stored responses keyed by a
hash of method, host, path, the selected query and header values, with a
second level per `Vary` combination. The handler consults it after the
request filters and before the proxy action, so every admission rule
and the WAF request phase apply to hits too; a miss proxies as usual and
`ModifyResponse` wraps the body so that a response that turns out
storable (status, `Cache-Control`, no `Set-Cookie`, within the object
bound) is captured as it streams to the client and stored on a clean
end. The cache belongs to the `Server`, not to a generation, so reloads
resize rather than empty it.

### TLS fingerprints

`GetConfigForClient` observes every ClientHello without changing the
configuration and records the JA3 and JA4 fingerprints
(`tlsconf.Compute`, GREASE values ignored, JA4 marked `q` on QUIC) in a
bounded table keyed by remote address; the connection state hook removes
the entry when the connection closes. The handler passes the fingerprint
to filters through `Info.JA3`, `Info.JA4` and `Info.ALPN` and logs `ja4`.
The `bot_score` kind uses it for the fingerprint mismatch signal and the
allow and deny lists.

### ACME

`internal/acme` is a small RFC 8555 client on the standard library
(`internal/acme/jose` does the ES256 JWS, thumbprint and key
authorisation). The `Manager` owns one account per process, one
certificate per host group, the state directory
(`account.key`, `account.url`, `certs/<name>.pem` and `-key.pem`, all
written to a temporary file and renamed) and the challenge tables that the
data plane answers from: `HTTP01(token)` for the handler's
`/.well-known/acme-challenge/` path, served before the HTTPS redirect,
routing and every filter, and `TLSALPN01(serverName)` for the ALPN hook.
A check runs at start and every `check_interval`; a group is due when its
certificate is missing or inside `renew_before`, with an hour of back-off
after a failure. Callers arriving while an order for the same group is in
flight join it and receive its outcome, so a forced renewal from the
management socket never races the timer. An issued chain is verified
against the group's hosts before it is installed and published to every
listener through `OnChange`. Requests are bounded (1 MiB responses, the
directory CA can be pinned) and a `badNonce` is retried once with the
nonce from the error response.

`tlsconf.Client` produces the upstream configuration: minimum version,
pinned CA, an optional client certificate served through
`GetClientCertificate` from an atomic pointer so `reload-certs` rotates it
without rebuilding the transport, and optional SPKI pins checked in
`VerifyConnection` on top of chain verification. Verification can only be
disabled with two flags (`insecure_skip_verify` and `allow_insecure`).

## 9. Logging

Four `slog` loggers with a `stream` attribute. Each stream is a handler
chain:

```
logger -> [redactHandler] -> multiHandler -> JSON handler -> file (0640, rotated), stdout
                                          -> lineHandler  -> journaldSink (native datagram protocol)
                                          -> lineHandler  -> syslogSink   (bounded queue, background writer)
```

The redaction handler rewrites attributes by key before any sink sees the
record: client addresses are truncated or replaced by a keyed pseudonym,
user agents dropped, referers cut to their origin, token claims hashed or
dropped, plus an operator list of fields to remove. Attacker controlled
strings are JSON encoded, which neutralises log injection. The access log
does not record query strings (only their length) because they commonly
carry tokens. Files are reopened on `SIGUSR1` or the API. The journald
sink writes `MESSAGE` plus indexed `XPROXY_*` fields; the syslog sink
formats RFC 5424 or 3164 with the stream as MSGID and never blocks the
request path: a slow or unreachable collector fills a bounded queue and
then drops with a counter visible in status.

## 10. Management plane

`internal/mgmt` serves a JSON API on a Unix socket created with umask `077`
and then chmodded to `socket_mode` (default `0660`, `other` bits refused by
validation). `ConnContext` captures `SO_PEERCRED`; every mutating call logs
`peer_uid`, `peer_gid`, `peer_pid` to the audit stream. The API has no
authentication of its own by design: the kernel enforces who may connect,
and adding a token would only add a secret to manage.

Endpoints:

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/v1/health` | liveness |
| GET | `/v1/status` | version, pid, generation, listeners, counters |
| GET | `/v1/stats` | counters |
| GET | `/v1/upstreams` | endpoint health and load |
| GET | `/v1/config` | active configuration as YAML |
| POST | `/v1/reload` | validate and apply the configuration file |
| POST | `/v1/reload-certs` | re-read certificates |
| POST | `/v1/logs/reopen` | reopen log files |
| GET | `/v1/bans`, POST `/v1/bans`, DELETE `/v1/bans?target=` | ban list |
| GET | `/v1/cluster` | cluster peers and counters |
| GET | `/v1/acme`, POST `/v1/acme/renew` | managed certificate status; forced renewal (audited) |
| GET | `/metrics` | Prometheus exposition |
| GET | `/v1/series?since=10m&limit=60` | sampled series for graphs |

The TUI is a mode of `xproxyctl`: a pure renderer (`tui.Render`, data and
terminal size in, lines out, tested without a terminal) driven by a raw
mode loop on `golang.org/x/term` that fetches all views concurrently with
a deadline each refresh and reads keys from stdin. It uses the same client
and therefore the same audited API for bans.

An optional TCP listener (`metrics.listen`) serves `/metrics` only, with a
source allow list and optional TLS with client certificates; it never
carries the management API.

### Web GUI

`xproxy-admin` (`internal/admin`) is the third front end and the only one
that is itself a network service, so it is built as a separate process
with its own user, and the data plane knows nothing about it. It serves
embedded static assets (one HTML page, one stylesheet, one script, no
framework and no external resource) under a strict Content Security
Policy (`default-src 'none'`, scripts and styles from `'self'` only, no
inline code, `frame-ancestors 'none'`), and a JSON API under `/api/` that
forwards to the management client: read endpoints pass the socket's
responses through unchanged, actions post to the same audited endpoints,
and the two things the socket does not offer, editing the configuration
file and following log files, are done by the GUI process itself on files
it owns or may read. Configuration edits go through the full validator
with file checks before anything is written; writes are atomic with a
`.bak` of the previous content and an entity tag so two operators cannot
silently overwrite each other. Restart is an operator configured command
run without a shell (under systemd, `systemctl restart` authorised by a
polkit rule).

Authentication is a users file of PBKDF2-HMAC-SHA256 hashes (600 000
iterations, standard library) or, on a mutual TLS listener, the client
certificate's common name. Sessions are random 256 bit tokens in an
`HttpOnly`, `SameSite=Strict` cookie (`__Host-` prefixed over TLS) with
idle and absolute limits. Cross-site request forgery is refused by three
independent checks on every state change: a custom request header that a
cross-origin page cannot add without a preflight the server never
permits, the `Sec-Fetch-Site` metadata when the browser sends it, and the
`Origin` header when present. Roles are enforced server side by method:
viewers may only `GET`. Failed logins are rate limited per source and
password checks are bounded in concurrency so the hash cost cannot be
turned against the process. A non-loopback listener is refused unless
server certificate, key and client CA are all configured.

### Metrics and series

Counters live in atomics that the request path already updates; the
exposition (`Server.WriteMetrics`) is assembled on each scrape from the
status snapshot, upstream statistics, shedder, cluster, two histograms
(request duration, upstream time to first byte) and per-route outcome
counters, with a small text encoder in `internal/metrics` (no client
library, per AMR-004). Label cardinality is bounded by configuration:
routes, upstreams and endpoints. A sampler goroutine reads the same
snapshot every `sample_interval`, turns counters into per-second rates and
stores a fixed set of series in a ring buffer sized by `retention`; the
TUI and GUI graph from it without external storage (AMR-026).

## 11. Filters (middleware)

`internal/filter` defines the per-route middleware interface:

```
Filter    Name() ; Begin(ctx, *Info) Instance         shared state, built per generation
Instance  Request(*http.Request) Verdict              runs after limits, before the action
          Response(*http.Response) Verdict            runs in ModifyResponse
          End() []any                                 always called; returns access log attributes
Chain     []Filter with Begin -> Instances
Verdict   Deny, Status, Reason, Detail, Attrs
```

A route's chain is compiled into `compiledRoute.filters`. The handler
begins instances once per request, runs the request phase before the route
action, the response phase inside the reverse proxy's `ModifyResponse`
(a deny there travels through the error handler as `filterDenied`), and
always calls `End`, whose attributes land in the access log line.

Built-in filters run in the order JWT, WAF, ICAP: unauthenticated
requests are refused before rule evaluation, and only requests that pass
the WAF are sent to an external scanner. Configured filters
(`filters[]`, attached by `routes[].filters`) slot in by stage:
`before_auth`, `after_auth`, `after_waf`, `after_scan`.

The interface is the stable extension contract (EXTENDING.md, API
version 1). A *kind* registers at start (`filter.Register` from an init
function; the list of built-ins is `internal/filters/all.go`) with a
`Validate` used by the configuration loader and a `New` called once per
generation. The runtime wraps each configured instance so that a deny
counts in `denied_filter` and `xproxy_filter_denied_total{filter,kind}`,
defaults its reason to the instance name, and closes filters that
implement `Closer` when the generation is torn down. `/v1/filters` and
`xproxyctl filters` show the kinds and instances.

### ICAP filter

`icap.Service` keeps a pool of connections, each with its own buffered
reader so bytes read ahead survive between exchanges, and the OPTIONS
results (preview size, ISTag, 204 support). REQMOD sends the request line
and headers (hop-by-hop removed) and the body as chunks; with preview the
first bytes go first and the rest only after `100 Continue`. RESPMOD sends
the original request headers, the response headers and the bounded
response body. Verdicts: `204` unmodified; `200` with an encapsulated
response is a replacement the client receives verbatim; `200` with an
encapsulated request rewrites method, path, headers and body while
protected headers (`Host`, forwarding headers, `Authorization`, `Cookie`)
are kept, so a scanner can never redirect the request to another origin.
Bodies over `max_body` and service failures follow the per-service
policies (reject or bypass, closed or open), and every outcome is counted
per service and exposed in status and metrics.

### JWT filter

`jwt.Provider` holds the allow list of algorithms, an atomic pointer to
the current key set (from a file, or fetched over HTTPS with a pinned CA
and refreshed on a timer and on unknown key ids, rate limited), and an
optional HMAC secret. Verification checks compact form and size, decodes
the header, refuses algorithms outside the allow list, selects keys by
`kid` (or by key type when absent, bounded), verifies the signature with
the algorithm's own primitive and, for ECDSA, insists that the curve
matches the algorithm, then checks `exp`, `nbf`, `iat`, `iss`, `aud` and
required claims. The filter removes client supplied copies of forwarded
claim headers before anything else, so a claim header can never be
spoofed even on optional routes.

### WAF filter

One `waf.Engine` per generation compiles each profile that some route uses
into a blocking Coraza instance, a detection-only instance, or both. The
SecLang is assembled in a fixed order: Coraza recommended settings, body
limits from the configuration, CRS setup, paranoia level and thresholds,
operator directive files and inline directives (exclusions), CRS rules,
and finally the engine mode. Per request the instance mirrors Coraza's own
middleware: connection and URI, request headers, request body read into
the transaction and replayed to the upstream from Coraza's buffer, then
optionally response headers and a bounded response body. Matched attack
rules, the blocking rule's total score and the interruption are logged;
initialisation and reporting rules are filtered out.

### Ban list

`ban.List` is owned by the `Server`, not by the runtime, so bans survive
reloads. It is consulted twice: in the accept path through
`ConnLimiter.Banned` (only when `action` is `drop`, because at accept only
the TCP peer is known) and in the handler on the derived client address.
Triggers keep a bounded per-address window per trigger; reaching the
threshold bans the address for `duration` multiplied by `escalation` for
each earlier ban within twice `max_duration`. Entries live in a map for
addresses and a small slice for CIDRs; both are bounded and purged every
minute. With `state_file` set, every ban and unban is written to bbolt and
live entries are loaded on start.

## 12. Cluster

```
 node A                                   node B
 +-----------------------------+          +-----------------------------+
 | limiters  --Flush--> gossip |--mTLS--> | accept -> Report -> limiters|
 | ban list  --OnChange-> queue|  (A->B)  |          Apply  -> ban list |
 |                             |          |                             |
 | accept <-Report/Apply       | <--mTLS--| gossip <--Flush/OnChange    |
 +-----------------------------+  (B->A)  +-----------------------------+
```

Each node dials every configured peer and sends on that connection; it
receives on the connections peers dialled to it. Both directions are TLS
1.3 with client certificates from the cluster CA, optionally restricted to
`allowed_names`. Messages are newline-delimited JSON, at most 1 MiB, with
bounded counts of keys and bans per message and a read deadline of
`peer_stale` plus five seconds; a silent peer is disconnected and
redialled with back-off.

Every `gossip_interval` the node flushes consumption from all limiters of
the live generation (policy, key, tokens) and sends one `rates` message
carrying the measured interval; the receiver converts counts to rates and
calls `ReportPeer` on the matching policy. Buckets refill at the configured
rate minus the sum of fresh peer rates (section 7), which makes the
configured rate approximately cluster wide. Ban changes originating locally
(manual or trigger) are queued by the ban list's change hook and sent in
the same cycle; peers apply them with source `peer:<node>` and never
re-announce them, so there are no loops. A newly connected peer receives a
snapshot of all active bans. Idle cycles send a ping so deadlines hold.

Protocol version 2 (1.3) adds an `events` message: bounded facts with a
kind, a key, an optional route and an expiry. The server publishes
honeypot marks and unmarks and applies peers' marks to its own table;
filters reach the channel through `filter.Env.Events`, a per generation
bus (`internal/proxy/events.go`) whose subscriptions die with the
generation, so a reload never leaves a stale filter listening. The OIDC
filter shares session revocations under the kind `oidc_revoke/<filter
name>`. Events queue without blocking and are dropped and counted when
the queue is full; a receiver applies them with its own bounds (the mark
table size, the revocation index size, a lifetime clamp of one year).
Unknown message types are now skipped and counted rather than closing
the connection, so a newer node can join an older cluster; version 1
nodes still close on an events message, hence `share_events: false`
during a rolling upgrade.

The node is owned by the `Server` like the ban list and reads limiters
through the live runtime pointer, so reloads neither detach it nor lose
peer state. Listen address, node identity and TLS material need a restart;
peers and intervals reload in place.

## 13. Load shedding and challenge

`shed.Shedder` keeps a ring of 20 latency buckets covering `window`; the
latency level is derived from the average of buckets still inside the
window, so a window with no admitted upstream traffic drains to zero and
the classes are readmitted for a fresh measurement. The in-flight ratio is
read from the concurrency limiter. Each class keeps a shedding flag with
hysteresis so admission does not flap around the threshold. Critical is
never shed; the concurrency ceiling still applies to it.

`challenge.Challenger` holds an HMAC key (persisted when `secret_file` is
set). A nonce is `ts || random || HMAC(key, "nonce", ts, random, ip)`;
a cookie is `expiry || HMAC(key, "cookie", expiry, ip)`. The page ships a
small script (served from a reserved path so the page's Content Security
Policy can forbid inline scripts) that searches for a counter such that
SHA-256 of `nonce ":" counter` has `difficulty` leading zero bits and posts
it back. Verification checks the nonce signature and age, the proof, and
single use (bounded seen table), then sets the cookie and redirects to the
sanitised original path. The gate runs after routing (it needs the route's
mode) and before shedding, so under load unverified clients are turned
away cheaply and verified browsers compete only with each other.

## 14. HTTP/3

A listener whose protocols include `h3` gets a QUIC endpoint on UDP at
the same port, served by `internal/h3` with the same `listenerHandler`,
the same TLS certificates (through the shared `GetCertificate`) and the
same limits. Responses on the TCP side carry `Alt-Svc` so browsers
upgrade. The QUIC transport's `ConnContext` hook runs the same admission
as the TCP accept path (`ConnLimiter.Admit`: ban list, per address and
global limits) and releases when the connection's context ends, so
`open_connections` and `rejected_connections` count both transports.
Address validation by Retry is on for every unvalidated address by
default; handshake and idle timeouts, streams per connection and header
size come from the listener limits; 0-RTT is disabled. Requests arrive as
`HTTP/3.0` with `r.TLS` set, so logging, forwarding headers and every
pipeline stage behave as for HTTP/2.

## 15. Scale properties (measured, see PERFORMANCE.md)

1000 hosts and 10 000 endpoints (ASR-P1) are validated by `TestScale` at
full size and rest on these properties:

- Host lookup is two map probes (exact, then wildcard suffix); path match
  is a linear scan of that host's prefixes, which are few per host. 22 ns
  and no allocation per match at 1000 hosts.
- Configuration parse, validation and generation build are linear in the
  number of objects and run off the hot path: 46 ms and 22 ms at the
  target size; a reload is a pointer swap plus background drain, 9 ms.
- Health checks are one goroutine per endpoint (about 1.5 KiB each, 15 MiB
  at 10 000), jittered at start, bounded by `max_concurrent` per pool and
  by a process-wide cap of 512 probes in flight, and open a fresh
  connection per probe unless `keep_alive` is set, so probing holds no
  descriptors between runs. A superseded generation stops probing at the
  swap; only its in-flight requests are drained.
- Transports are per pool, not per endpoint, so idle upstream connections
  are bounded by `max_idle_conns_per_host * endpoints` and released after
  `timeouts.idle`; under traffic they dominate memory (about 15 KiB and
  one descriptor each).
- Management views stay proportional to the table: 1.2 MiB for the
  endpoint list; the Prometheus exposition drops from 10.6 MiB to 229 KiB
  with `metrics.endpoint_series: false`, which is the setting above a few
  thousand endpoints.

Throughput on the reference container (ASR-P2) is 10 000 req/s at p99
under 10 ms with the load generator on the same four cores; the 8 core
figure with a remote generator is still to be measured. Remaining
performance work: allocation in the handler (header map copies in
`ReverseProxy`), an asynchronous access log writer with a bounded buffer
and drop counter, and `GOMAXPROCS` and `GOGC` guidance.
