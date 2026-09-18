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
            |        xproxy         |<-------| xproxyctl / TUI   |
            |  data plane process   | unix   | xproxy-admin GUI  |
            |  user: xproxy         | socket | (1.0)             |
            +--+------+------+------+        +-------------------+
               |      |      |
        access | err  | sec  | audit      -> files, journald, syslog (1.0)
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
cmd/xproxyctl       management CLI (and TUI in 1.0)
internal/config     schema, defaults, loader, validation
internal/router     host and path matching
internal/netutil    client IP derivation, path cleaning, host normalisation
internal/limits     token buckets, connection limiter, concurrency limiter
internal/tlsconf    hardened tls.Config construction and certificate reload
internal/upstream   endpoints, balancers, health checks, affinity, ejection
internal/proxy      server, listeners, handler pipeline, transport, stats
internal/logging    four slog streams, file rotation
internal/mgmt       management API server and client
internal/filter     per-route middleware interface (Filter, Instance, Chain)
internal/waf        Coraza + OWASP CRS engine as a filter
internal/ban        ban list with triggers, escalation and persistence
internal/version    build information
deploy/             systemd units, sysctl, SELinux, logrotate, example config
docs/               this documentation
test/               cross package and binary level tests (grows in 1.0)
```

Packages under `internal/` cannot be imported from outside the module, which
keeps the API surface at exactly two binaries.

Dependency direction (arrows point at the importer's dependency):

```
cmd/xproxy -> mgmt -> proxy -> {router, upstream, limits, netutil, tlsconf, logging, config, filter, waf, ban}
                       waf      -> {filter, config}
                       ban      -> {netutil, config}
                       upstream -> {tlsconf, config}
                       router   -> config
                       logging  -> config
```

No package imports `proxy` except `mgmt` and the commands. `config` imports
nothing from the module.

## 3. Process model

One process, one user, no capabilities. systemd passes the listening sockets
(`LISTEN_FDS`), the process matches them to configured listeners by name or
address and binds any listener that was not passed. The process sends
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
| 6 | Path cleaning (`netutil.CleanPath`) and route match | 404 | `denied_no_route` |
| 7 | CIDR deny then allow | 403 | `denied_acl` |
| 8 | Rate limits in route order; reject or tarpit | 429 | `denied_rate_limit`, `tarpitted` |
| 9 | Body limit: declared length checked, then `MaxBytesReader` | 413 | `denied_body_size` |
| 9b | Filter chain request phase (WAF): headers, then body, which is buffered and replayed to the upstream | 403 or rule status | `denied_waf`, `waf_detected` |
| 10 | Route timeout context | 504 | `upstream_timeouts` |
| 11 | Action: redirect, respond, or proxy | | |
| 12 | Proxy: WebSocket gate | 403 | `denied_websocket` |
| 13 | Proxy: `httputil.ReverseProxy` with `poolTransport` | 502 / 503 / 504 | `upstream_*` |
| 13b | Filter chain response phase (WAF response rules when `inspect_responses`) | 403 | `denied_waf` |
| 14 | Response: header operations, `Server` removal, affinity cookie | | |
| 15 | Access log | | `responses_*`, `bytes_*` |

Every deny at stages 2 to 13 is reported to the ban list (`Observe`) with
its category, so triggers can turn repeated denies into bans.

Planned stages (1.0): ICAP REQMOD after the WAF request phase and ICAP
RESPMOD after the WAF response phase, JWT validation before the filter
chain, adaptive shedding at 2.

### Client address

`netutil.ClientIP` returns the TCP peer unless the peer is inside
`trusted_proxies`, in which case it walks `X-Forwarded-For` from the right
and returns the first address that is not a trusted proxy. A malformed hop
falls back to the peer. When forwarding, the inbound `X-Forwarded-For` is
kept only from trusted peers; otherwise it is replaced by the peer address.
`Forwarded` is always removed. This is the only correct construction when
the proxy is behind a known chain and the strictest one when it is the
edge.

### Path handling

Routing uses `path.Clean` semantics on the request path so that
`/admin/../public` matches the `public` route and cannot bypass a policy on
`/admin`. The upstream receives the original path unless the route strips or
rewrites it. Prefixes match on segment boundaries: `/api` matches `/api/x`
but not `/apix`.

### Upstream selection and retries

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

`tlsconf.Client` produces the upstream configuration; verification can only
be disabled with two flags (`insecure_skip_verify` and `allow_insecure`).

## 9. Logging

Four `slog` JSON loggers with a `stream` attribute. Files are opened `0640`,
rotated by size when configured, reopened on `SIGUSR1` or the API. Attacker
controlled strings are JSON encoded, which neutralises log injection. The
access log does not record query strings (only their length) because they
commonly carry tokens; 1.0 adds configurable redaction and additional sinks.

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

1.0 adds `/metrics` (Prometheus), ban management, the time series ring
buffer and configuration editing with validation, all on the same socket.

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

The WAF is the first filter. ICAP and JWT follow in 1.0; the interface is
declared stable for external middleware once those exist (AMR-013).

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

## 12. Scale considerations for 1.0 targets

1000 hosts and 10 000 endpoints (ASR-P1) drive these properties:

- Host lookup is two map probes (exact, then wildcard suffix); path match is
  a linear scan of that host's prefixes, which are few per host.
- Health checks: 10 000 goroutines sleeping on timers is acceptable in Go,
  but the 1.0 implementation will move to a shared timer wheel with a
  concurrency cap so that a fleet of proxies does not probe in bursts.
- Transports are per pool, not per endpoint, so idle connection pools are
  bounded by `max_idle_conns_per_host * endpoints`.
- Configuration parse and validation are linear in the number of objects
  and run off the hot path.

Performance work in 1.0 (ASR-P2) focuses on allocation in the handler
(header map copies in `ReverseProxy`), on making the access log writer
asynchronous with a bounded buffer that drops with a counter rather than
blocking the request, and on `GOMAXPROCS` and `GOGC` guidance.
