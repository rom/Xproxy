# Architecture

xproxy terminates protocols, applies security policy and forwards to
upstream pools. It is not one program but three, split by who is on the
other end of the socket — **xproxy** faces the internet, **xgate** faces
people, **xrelay** faces machines — plus a control binary that manages
any of them over a local socket. This document describes the split, the
components, the request path, the data flows and the reasoning behind
the shape. Decision records are in [AMR.md](AMR.md); requirements in
[ASR.md](ASR.md).

## 1. System context

```
        internet                 operators              devices, services
            |                        |                          |
 +----------v----------+  +----------v----------+  +------------v----------+
 | kernel: nftables,   |  | kernel              |  | kernel                |
 | conntrack, SYN queue|  |                     |  |                       |
 +----------+----------+  +----------+----------+  +------------+----------+
            | accept                 | accept                   | accept
 +----------v----------+  +----------v----------+  +------------v----------+
 |       xproxy        |  |        xgate        |  |        xrelay         |
 |  http tcp forward   |  |        ssh          |  | smtp mqtt ftp syslog  |
 |        dns          |  |                     |  |                       |
 |  user: xproxy       |  |  user: xgate        |  |  user: xrelay         |
 +--+---------------+--+  +--+---------------+--+  +--+----------------+---+
    |               |        |               |        |                |
    | mgmt socket   |        | mgmt socket   |        | mgmt socket    |
    v               |        v               |        v                |
 +------------------|--------+---------------|--------+------+         |
 | xproxyctl (CLI, TUI), xproxy-admin (web GUI)              |         |
 +-----------------------------------------------------------+         |
                    |                        |                         |
                    +-----> /run/xproxy-cluster <---------------------- +
                       local cluster: bans, marks, revocations
                    |                        |                         |
                    v                        v                         v
 +---------------------------------------------------------------------+
 | upstream pools: applications, bastion targets, mail, brokers        |
 +---------------------------------------------------------------------+
```

The three are the same engine with different protocol code linked into
them (section 3). Each runs as its own user, under its own systemd unit
and its own sandbox, reads its own configuration file, and is reached on
its own management socket. They share a ban list over a Unix socket
cluster, so an address one of them refuses is refused by all three.

Trust boundaries:

1. Internet to xproxy: hostile. Everything read from a client connection
   is attacker controlled, including TLS ClientHello, headers, body and
   timing.
2. People to xgate: authenticated but not trusted. A session belongs to a
   named principal and is recorded, and what it may do inside SSH is a
   policy rather than a destination list.
3. Machines to xrelay: semi-trusted and unattended. Credentials are
   long-lived and often shared, so the policy is written in each
   protocol's own terms and the traffic is bounded rather than believed.
4. Any daemon to its upstream: semi-trusted. Upstreams may be
   compromised; responses are not executed but are size and time
   bounded.
5. Operator to a management socket: trusted, authenticated by the kernel
   (Unix socket permissions and `SO_PEERCRED`), audited.
6. Daemon to sibling daemon, over the local cluster socket: trusted
   completely — a peer places bans and is named in the audit trail —
   and admitted by the socket's permissions plus the user id the kernel
   reports, never by anything the peer announces.
7. Configuration and certificate files: trusted, must be root or the
   daemon's user owned and not world writable (the loader refuses world
   writable configuration).

A compromise of one daemon is a compromise of that daemon: it does not
carry the others' protocol implementations, it cannot read their files,
and the one thing it can do to them is place a ban, which is the
authority a cluster peer has by design.

## 2. Repository layout

```
cmd/xproxy          edge daemon: links the http, forward, tcp and dns kinds
cmd/xgate           gate daemon: links the ssh kind
cmd/xrelay          relay daemon: links the smtp, mqtt, ftp and syslog kinds
cmd/xproxyctl       management CLI and TUI (talks to any of the three)
cmd/xproxy-admin    web GUI process (users, sessions, embedded assets)
cmd/xproxy-fleet    fleet controller

internal/daemon     the body of all three daemons: flags, loading, sandbox,
                    management and metrics, fleet agent, signals, systemd notify
internal/listener   the roster: every listener kind and the role that serves it
internal/proxy      the engine: accept path, listener lifecycle and reload, the
                    kind registry, the Host and Plane interfaces, bans, pools,
                    counters, TLS material. No protocol at all (section 3)
internal/kinds/http    kind: http -- routing, filters, the WAF, the cache, the
                       whole request path, as the process's data plane
internal/kinds/tcp     kind: tcp -- layer 4 relay, SNI and QUIC routing, YARA
internal/kinds/dns     kind: dns -- resolver, cache, block list, DoT/DoH/DoQ
internal/kinds/forward kind: forward -- CONNECT, SOCKS5, MASQUE, interception
internal/kinds/ssh     kind: ssh -- bastion, policy, SFTP mediation, recording
internal/kinds/smtp    kind: smtp -- mail and submission with STARTTLS
internal/kinds/mqtt    kind: mqtt -- broker front end with a topic policy
internal/kinds/ftp     kind: ftp -- control and data channel mediation
internal/kinds/syslog  kind: syslog -- RFC 5424 and RFC 3164 relay
internal/kinds/telnet  kind: telnet -- NVT option policy, recording, MFA
internal/kinds/vnc     kind: vnc -- RFB handshake mediation, recording, MFA
internal/rfb           the RFB wire format the vnc kind reads and writes

internal/config     schema, defaults, loader, validation
internal/router     host and path matching
internal/netutil    client IP derivation, path cleaning, host normalisation
internal/httpx      the HTTP message rules more than one kind needs
internal/relay      the byte copy between two connections, with deadlines
internal/streamscan YARA over a stream, shared by the kinds that scan one
internal/textsafe   bounding and de-controlling text that came from a peer
internal/unixsock   binding a listening Unix socket, safely, in one place
internal/limits     token buckets, connection limiter, concurrency limiter
internal/tlsconf    hardened tls.Config construction and certificate reload
internal/upstream   endpoints, balancers, health checks, affinity, ejection
internal/logging    four slog streams, file rotation
internal/mgmt       management API server and client
internal/filter     middleware interface, kind registry, options decoding
internal/filters    built-in filter kinds and the registration list
internal/jsonschema JSON Schema evaluator (openapi filter, WAF body schemas)
internal/apiinv     API inventory: discovery, shadow, zombie, superseded
internal/filters/wasm  WebAssembly ABI v1 on wazero (the only wazero importer)
internal/passwd     PBKDF2 password hashing shared by basic_auth and the GUI
internal/secret     keyring files for the symmetric secrets, rotation
internal/otlp       OTLP/HTTP JSON client for metrics, traces and logs
internal/tracing    W3C trace context, spans, OTLP trace export
internal/geoip      MaxMind DB reader and CSV prefix table
internal/cache      in-memory response cache (LRU, byte bound, Vary)
internal/dns        DNS wire codec, cache, block list, resolver, servers
internal/smtp internal/mqtt internal/ftp internal/syslog internal/sftp
                    the wire codecs of the relay and gate protocols
internal/masque internal/mitm internal/grpcmsg internal/asciicast
                    the wire formats the kinds above are built on
internal/ingress    Kubernetes ingress controller
internal/waf        Coraza + OWASP CRS engine as a filter; its wafstatus
                    subpackage is the report, as a leaf every daemon can serve
internal/ban        ban list with triggers, escalation and persistence
internal/cluster    peer sharing of limits, bans and events: mutual TLS
                    between hosts, a Unix socket between the daemons of one
internal/fleet      fleet bundles, the node agent and the controller
internal/shed       adaptive load shedding by priority class
internal/challenge  browser proof-of-work challenge
internal/h3         HTTP/3 over QUIC (the only package importing quic-go)
internal/jwt        JSON Web Token validation on the standard library
internal/icap       ICAP client (RFC 3507) as a filter; icaptest fake server
internal/metrics    Prometheus text encoder, histogram, sampled series
internal/sandbox    Landlock, seccomp, capabilities; Seatbelt on macOS
internal/tui        terminal UI of xproxyctl
internal/admin      web GUI server
internal/paths      platform default locations, per daemon
internal/version    build information
internal/expr       condition language of routes[].when and header when
internal/proxytest  starting a server from YAML, for the kinds' tests
internal/testutil   certificates, echo servers and rule sets the tests share
internal/config/schema  JSON schema of the configuration, generated
internal/manpage    Markdown to troff renderer and the generation of docs/man
docs/man/           manual pages (sources *.md, generated *.8 and *.5)
deploy/             systemd units, sysusers, tmpfiles, sysctl, SELinux, polkit,
                    logrotate, RPM spec, example configuration
docs/               this documentation
examples/           configuration fragments, one per feature, all test-validated
test/               cross package and binary level tests
```

Packages under `internal/` cannot be imported from outside the module,
which keeps the API surface at exactly the binaries.

Dependency direction (arrows point at the importer's dependency):

```
cmd/xproxy ─┐
cmd/xgate  ─┼─> daemon -> {proxy, mgmt, config, logging, sandbox, fleet,
cmd/xrelay ─┘             metrics, ingress, listener, paths, version}
    │
    └─ blank imports of its own kinds, and nothing else:
         kinds/{tcp,dns,forward} | kinds/ssh | kinds/{smtp,mqtt,ftp,syslog}

kinds/<k> -> {proxy, config, listener, and that protocol's wire package}
proxy     -> {listener, router, upstream, limits, netutil, tlsconf, logging,
              config, filter, waf, ban, cluster, shed, challenge, h3, jwt,
              metrics, icap, cache, geoip, apiinv, capture, httpx, relay,
              streamscan, unixsock}
mgmt      -> {proxy, config, logging, unixsock}
cluster   -> {ban, limits, config}
listener  -> (standard library only)
config    -> {filter, listener}
filter    -> (nothing from the module)
```

Two directions are load-bearing. A kind imports the engine and the
engine imports no kind: everything the engine needs back from one is an
interface (section 3), so linking a kind is the only thing that puts its
code in a binary. And `internal/listener` imports nothing at all, which
is what lets `internal/config` validate a `kind:` value that this binary
does not implement.

`admin` imports only `mgmt` (the client), `config` (validation of edited
files) and `tlsconf`; it never links a data plane.
## 3. Three daemons, one engine

A proxy that terminates ten protocols is a process that links ten
protocol implementations, and a flaw in any one of them is a flaw in
front of all of them. An SSH bastion has no business carrying an MQTT
parser; a mail relay has no business carrying a WebAssembly runtime.

So the binary is split by who is on the other end of the socket:

| Daemon | Faces | Listener kinds |
|--------|-------|----------------|
| `xproxy` | the open internet | `http`, `forward`, `tcp`, `dns` |
| `xgate` | people | `ssh` |
| `xrelay` | machines | `smtp`, `mqtt`, `ftp`, `syslog` |

One repository, one module, one version and one configuration format;
three programs, three users, three systemd units, three sandboxes, three
management sockets. A host that is not a bastion does not have the SSH
and SFTP implementation on it, rather than having it present and
unconfigured.

### The kind registry

A listener kind is a package that registers itself:

```go
// internal/kinds/ssh/kind.go
func init() {
        proxy.Register(proxy.Kind{
                Name:        "ssh",
                ProxyHeader: true,
                New:         build,
        })
}
```

and a daemon is a package doc, a role and the blank imports of its own
kinds:

```go
// cmd/xgate/main.go
import (
        "github.com/rom/xproxy/internal/daemon"
        _ "github.com/rom/xproxy/internal/kinds/ssh" // listener kind: ssh
        "github.com/rom/xproxy/internal/listener"
)

func main() { os.Exit(daemon.Run(listener.RoleGate, os.Args[1:])) }
```

That import line is the whole of the mechanism that decides what code is
in which binary. `cmd/*/main_test.go` asserts the exact set each one
links, because a stray blank import is how that quietly stops being
true.

### What the engine asks of a kind, and the other way round

The engine gives a kind a `Setup`: the bound socket, the listener's
configuration, a `*tls.Config` where the kind asked for one, and a way
to open a datagram socket on the same address. The kind returns an
`Instance` with `Serve` and `Shutdown`.

Everything a kind needs back from the engine is one small interface:

```go
type Host interface {
        Logs() *logging.Logs          // access, security, audit, error
        Counters() *Stats             // the shared counter set
        Bans() *ban.List              // observe and consult
        Pool(name string) *upstream.Pool
        Limits() config.Limits
}
```

Five methods for what every kind touches. `Host` carries a second group
beside them — the fingerprint table, the connection limiter, the ACME
manager, the packet capture, the cluster connection — for the
process-wide facilities a kind may not build for itself, because a
second one would be wrong rather than merely wasteful.

A kind that wants more than that says so with an optional interface the
engine type-asserts, never with a field the engine has to know about:
`Applier` replaces a policy in place on reload, `Closer` releases what
the socket held, `ExtraAddrs` names a second socket the kind opened
(the HTTP/3 endpoint, DNS over QUIC), `FlowCounter` reports open
datagram flows for the snapshot, `DNSInstance` and `MasqueReporter` hand
the management views a handle on something only that kind has. The
engine names no kind, and `internal/proxy` imports no kind package.

### The roster, and why it is static

`internal/listener` holds a table of every kind this project implements
and the role that serves it. It is deliberately a table rather than a
view of the registry.

A daemon has to tell "that listener is not mine" from "that is not a
listener kind at all". It cannot do that from a registry holding only
what it linked: every foreign kind would read as a typing mistake, and a
configuration the estate shares would fail to load on two daemons out of
three. So every binary knows every kind's name and owner, which costs a
few hundred bytes, and links only the implementations it serves, which
is the part that carries the code, the dependencies and the risk.

Configuration validation reads the roster, so `kind: ssh` is a valid
value in every daemon's file. Building a listener reads the registry.

### The refusal

A listener whose kind this binary did not link is refused by name, with
the daemon that does serve it:

```
listener bastion: kind "ssh" is served by xgate, not by this daemon
```

This is the point of the split rather than a detail of it. Before the
kinds were separable, an unknown `kind:` fell through to the HTTP data
plane, and a port meant to speak SSH answered HTTP — a port answering
the wrong protocol is worse than a port that does not answer.
`TestUnlinkedKindRefused` holds it for every kind in the roster, driven
through a valid configuration so the refusal is reached in the engine
rather than short of it in validation.

### One estate, three files

Every daemon validates the whole configuration it is given, including
the listeners its siblings serve — a mistake in the gate's SSH policy is
caught by whichever daemon reloads first — and binds only the listeners
of its own role, naming the rest in the error log under `listeners left
to a sibling daemon`.

What the three cannot share is a file. `management.socket`,
`metrics.listen` and `logging.directory` each name something only one
process can own, so each daemon reads `/etc/xproxy/<daemon>.yaml` and
pulls the common part — upstreams, routes, rate limits, filters — out of
`includes` all three name. `examples/estate/` is a worked set.

### The data plane is a kind too

`http` is a listener kind like the others, in `internal/kinds/http`, and
only `xproxy` links it. That is where the routing, the WAF, the filters,
the cache, the challenge engine and everything else that takes a request
apart now live; `internal/proxy` is the engine around them — sockets,
TLS, the reload, the counters, the cluster and the management surface.

It needs one thing the other kinds do not. Every http listener of a
process shares one compiled generation: one route table, one WAF engine,
one response cache, one set of rate limiters. A per-listener `Instance`
has nowhere to keep that, so the kind also registers a `Plane`:

```go
func init() {
        proxy.Register(proxy.Kind{Name: "http", TLS: true, ProxyHeader: true, New: newListener})
        proxy.RegisterPlane(newEngine)
}
```

The engine builds the plane once, before any listener binds, and hands
each `http` listener a handle on it in `Setup.Plane`. A reload is two
phases so that one generation is swapped rather than two:

```go
Prepare(g Generation) (commit, discard func(), err error)
```

`Prepare` compiles everything that can fail — the routes, the rule sets,
a challenge secret that has to be readable before a route in `mode:
always` is served — against the pools the engine built for the same
generation. The engine then binds its listeners. Only when every one of
them is bound does it call `commit`, which installs the new generation
under the same lock as the listener swap; any failure calls `discard`
and the old configuration is still running, untouched.

`Generation.Retire` is the other half of that handover. The engine owns
the upstream pools but cannot see the requests still on them, so the
plane calls it when the last request compiled against the superseded
generation has finished — a pool closed under a long upload or an SSE
stream cuts it.

The management API is served by all three daemons, which decides how
the plane's status crosses the boundary. `PlaneStatus` is a plain
interface the engine's own `WAF`, `Filters`, `Quotas` and the rest
delegate to, answering zero values where no plane is linked, so
`xproxyctl waf` against the bastion reports a WAF that is not enabled —
which is true — instead of failing in a way an operator has to look up.
Its types are the data plane's own, except for the WAF report: that one
lives in the leaf package `internal/waf/wafstatus`, because a Coraza
type in the management surface would link the rule engine into the
bastion and the mail relay. The types are aliased back into
`internal/waf`, so nothing that reads the report had to change.

### What the split buys, in bytes

| Daemon | Before the split | After | After the data plane moved |
|--------|-----------------|-------|----------------------------|
| `xproxy` | 41.9 MB | 40.0 MB | 40.1 MB |
| `xgate`  | 42.7 MB | 40.5 MB | **21.8 MB** |
| `xrelay` | 42.2 MB | 40.0 MB | **21.2 MB** |

(`CGO_ENABLED=0`, unstripped; `make build` strips to 28.4, 15.3 and
14.9 MiB.) The spread is the number that matters, not the total. The
bastion and the relay carry none of the HTTP request path: no route
compiler, no Coraza and no rule sets, no load shedder, no challenge or
CAPTCHA engine, no gRPC, WebSocket or WebTransport inspection, no
response cache, no HTTP/3. A few small packages are still linked into
all three because the management API they all serve speaks their status
types — the cache, the GeoIP reader, the ICAP client, the API inventory
— but with none of the code that fills them in reachable, the linker
keeps little more than the structs.

What the three still share is the engine, the configuration package, the
TLS and logging machinery and the management API, which is the point:
those are the parts all three are meant to agree on.

## 4. Process model

One daemon is one process, one user, no capabilities; a host runs one,
two or three of them side by side, and nothing about this section
differs between them — it is all `internal/daemon`, so how a daemon
starts is one implementation rather than three. systemd passes the
listening sockets (`LISTEN_FDS`), the process matches them to
configured listeners by name or address and binds any listener that was
not passed. Datagram sockets are
matched the same way (name `<listener>-udp` or address) for HTTP/3. The process sends
`READY=1`, `RELOADING=1` (with `MONOTONIC_USEC`, as `Type=notify-reload`
requires) and `STOPPING=1` over `NOTIFY_SOCKET`.

Start order: configuration, logs, ingress controller, proxy runtime and
listeners, configuration history, management socket, metrics listener,
then the sandbox (`internal/sandbox`), then `READY=1`. The sandbox is
last because it can only narrow what the process may do afterwards: on
Linux it derives Landlock rules from the configuration (the directory of
every configured file for reading; log, state, history and certificate
directories for writing; the resolver and trust store paths the standard
library opens), installs them together with a refusal of new TCP binds,
installs a seccomp deny list on every thread, clears the capability
sets, sets `no_new_privs` and makes the process non dumpable. On macOS
it denies debugger attachment and core files, and reports the Seatbelt
profile the launchd job runs it under. Each mechanism records applied,
unavailable, failed or disabled; `strict` turns unavailable into a
failed start. Because Landlock cannot be widened, the reload path checks
a candidate configuration against the rules in force and refuses one
that names a path outside them with "restart to apply". Tests never
apply the sandbox: it is applied from `internal/daemon`, and the
package's own test confines a child process instead.

The Landlock rules follow the configuration, so they differ per daemon:
xgate writes session recordings under its state directory and xproxy
does not, and a local cluster adds the directory its socket and its
peers' sockets sit in. A peer added to `cluster.peers` without a restart
is a peer the sandbox has not heard of, which is why the reload path
checks a candidate against the rules in force.

Signals: `SIGHUP` reloads the configuration, `SIGUSR1` reopens log files,
`SIGTERM` and `SIGINT` drain and stop within `server.shutdown_timeout`.

Goroutines: one per accepted connection (owned by `net/http`), one per
endpoint with an active health check, one per HTTP/2 stream. There is no
worker pool and no unbounded queue; back-pressure is applied by refusing
work (AMR-007).

## 5. Configuration generations

```
   config file --Load--> *config.Config --newRuntime--> *runtime
                          (validated,                     pools (transports, health)
                           defaulted,                     trusted prefixes
                           immutable)                |
                                                     | proxy.Generation
                                                     v
                                              Plane.Prepare --> plane runtime
                                                                  router
                                                                  rate limiters
                                                                  compiled routes

   Server.rt : atomic.Pointer[runtime]     engine (every daemon)
   engine.rt : atomic.Pointer[runtime]     http plane (xproxy only)
```

A generation is compiled in two halves. The engine owns what every
daemon has -- the upstream pools and the trusted prefix set -- and hands
them to the data plane as a `proxy.Generation`; the plane compiles the
router, the rate limiters and the routes against those pools. A daemon
that links no plane (xgate, xrelay) stops after the first half.

`Server.Reload` builds a complete new runtime, asks the plane to prepare
its half, reloads certificates, then swaps the pointers. Preparing is
two phase: `Prepare` returns a `commit` and a `discard`, so a listener
that fails to bind after the plane is ready throws the plane's
generation away without either half having been swapped. In-flight
requests hold the generation they started with. Any failure before the
swap leaves the old generation active and increments `reload_failures`.

The old generation stops health checking at the swap, but its pools stay
open until the plane reports that the last request compiled against it
has finished (`Generation.Retire`) -- a pool closed under a long upload
or an SSE stream cuts it. The plane waits `shutdown_timeout`, then polls
until the generation is idle, under a hard cap of ten times that (at
least five minutes) so a request that never ends cannot hold a
generation forever. In a daemon with no plane the pools are stopped
after `shutdown_timeout`, because nothing there holds a request across
the swap.

Listeners are part of the reload. Each accept socket is owned by an
`acceptor` (`internal/proxy/acceptor.go`) whose goroutine hands
connections over an unbuffered channel to the current `front`, the
`net.Listener` a listener generation serves from; closing a front stops
that generation without touching the socket. `Reload` plans the listener
set by name, then by address for renames: unchanged listeners keep
running (certificate files apply in place, and so does a kind's own
policy where the kind implements `Applier` -- the forward proxy's
destination rules, the resolver's block list),
added ones are bound, and changed ones are rebuilt, on the old acceptor
when the address is the same so a systemd owned or privileged socket is
never re-bound and no connection is refused. Every bind and build
happens before the runtime swap; a failure releases what was built and
leaves the old set serving. After the swap, replaced and removed
listeners close their front and drain (`http.Server.Shutdown` and the
per kind equivalents) for `shutdown_timeout`; the socket is closed only
when no replacement inherited it. A listener with a UDP socket cannot be
rebuilt on the same address because the old socket stays bound until
the drain ends, so that change still needs a restart.

## 6. Request path

This is the HTTP data plane, which `xproxy` serves; the other kinds have
their own paths, under "Layer 4 passthrough", "DNS proxy", "Forward
proxy", "The gate" and "The relay" below. Every
request passes through the following stages in order. The stage that
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
| 4b | Normalisation: control characters, invalid UTF-8, double encoding, encoded separators, backslashes, ambiguous framing; Unicode folding of the routing path | 400 | `denied_normalization` |
| 5 | Host normalisation (`netutil.Host`) | 400 | `denied_bad_host` |
| 5b | Reserved paths `/.xproxy/challenge` (proof verification) and `/.xproxy/challenge.js` | 303 / 403 | `challenges_*` |
| 5c | Virtual `security.txt`: `/.well-known/security.txt` and `/security.txt` when an entry in `security_txt[]` selects the host, client range or listener | 200 document / 405 | `security_txt` |
| 6 | Path cleaning (`netutil.CleanPath`) and route match (host, path prefix or anchored pattern, method, header and cookie conditions) | 404 | `denied_no_route` |
| 6b | Virtual patches: host, route, method, path, parameter, header, cookie and body conditions; block with the configured status, or log and continue | 4xx / 5xx | `denied_virtual_patch`, per patch hits |
| 6c | Route policy: methods, media types, URI, query and header bounds, query parameter types | 405 / 415 / 400 / 414 / 431 | `denied_policy` |
| 7 | CIDR deny then allow | 403 | `denied_acl` |
| 7b | Challenge gate: the cookie is read once (tier and device identifier); unverified clients on routes with `challenge` (always, or in `load` mode above the level) receive the page, the proof of work or the CAPTCHA widget | 503 page | `challenges_issued` |
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

Two pool wide controls sit in front of endpoint selection. The gate
(`upstream.Gate`, `max_concurrent` and `queue`) is a semaphore taken in
`proxyTo` for the whole exchange, with a bounded number of waiters and
a per waiter deadline; a refused request is a 503 with `Retry-After`
and an `upstream_error` of `queue_full` or `queue_timeout`, never a
security event. The breaker (`upstream.Breaker`, `circuit_breaker`) is
consulted in `poolTransport.RoundTrip` around the attempt loop: closed
it counts consecutive failed attempts, open it refuses with the
remaining time, half open it admits a bounded number of trials whose
outcome closes or reopens it with a growing back-off. Both report
through `Pool.Status` to `GET /v1/pools` and the metrics.

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

## 7. Upstream pools

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

### Latency outliers

Besides consecutive failures, `Pool.End` folds the time to first byte
of every attempt into an exponential moving average per endpoint
(factor 0.2, atomics, no allocation). With `latency_threshold` an
endpoint whose average exceeds the bound is ejected; with
`latency_factor` one whose average exceeds the mean of the other
endpoints' averages by the factor is, so the outlier does not move its
own reference. Both wait for
`latency_min_samples` responses since the endpoint last became
available, respect `max_ejection_percent` and the back-off of the
failure rule, and reset the endpoint's average so that it is judged
afresh on return. Health probes can require a body (`body_contains`,
`body_regex` on the first 64 KiB) so that an application that answers
200 while its dependencies are down is not considered healthy. Every
compiled route owns a duration histogram (the same buckets as the
global one), exposed per route with `metrics.per_route` and summarised
as p50, p95 and p99 in the quota report.

### Expressions

`internal/expr` parses `routes[].when` and the `when` of header
operations into a small tree (or, and, not, comparisons, `in` over a
literal list or a `cidr()` prefix set, `matches` with a pattern compiled
at load, and functions over strings) and evaluates it per request
against the same `Resolver` the header templates use (`tvars`), so the
variable set is one. Unknown names, functions, arities, patterns and
capture groups are rejected by validation; evaluation cannot fail (a
missing value is the empty string, a non-address in `cidr` is not
contained). The router evaluates a route's expression after its static
matches and counts it as one condition for specificity; the handler
passes a `tvars` bound to the request before the route is known, which
resolves `country` on demand through the runtime's GeoIP database.

### Templates and error pages

Header values, redirect targets, regex rewrite replacements and error
documents share one placeholder syntax (`internal/tmpl`): `${name}`
with a fixed set of names checked at load, so a typo is a validation
error rather than an empty header in production. Templates are parsed
once per generation into literal and variable parts; a value without
placeholders costs nothing at request time. The proxy resolves
variables from the request and its state, including the groups of the
route's `rewrite_regex` or `path_regex` match, which are recorded
before header operations run. Error documents are read at load, parsed
leniently (unknown `${...}` stays literal, so script code survives) and
rendered by the same status writer every denial and failure already
uses; a route's section shadows the server's; upstream bodies are
replaced only for the statuses listed in `intercept_upstream`, with the
body describing headers corrected.

### Dynamic endpoint sets

A pool's endpoint list is an atomically replaced slice. Discovery
resolves the configured name (A/AAAA with a fixed port, or SRV with
target, port and weight from the records, lowest priority group only)
once synchronously in `Start` and then on an interval, and merges the
result by address: static endpoints and addresses that persist keep
their `Endpoint` objects, so statistics, health state and in-flight
counts continue; new addresses get a fresh object with a slow start
ramp and, when active checks are on, their own probe loop under the
pool's context; removed addresses lose their loop and drop out of the
next pick. The hash ring is rebuilt on every change. Affinity cookies
carry a pool-unique endpoint index rather than a position, so a cookie
survives set changes. Slow start is a per endpoint ramp start time:
weighted and least connection balancers scale the weight by the ramp,
round robin and hash keep a ramping pick with the ramp's probability
and otherwise pick again among the others.

## 8. Limits

- `KeyedLimiter`: 64 shards, each a map of lazily refilled token buckets.
  Keys per shard are capped; on a full shard, buckets that have fully
  refilled are evicted; if none can be, the request is allowed without
  tracking. Memory is therefore bounded at `64 * maxKeys` buckets per policy.
  With clustering, each bucket also holds up to 64 peer rate reports with
  timestamps; refill uses `rate - sum(fresh peer rates)`, clamped at zero,
  and `Flush` returns and resets per key consumption for gossip.
  `NewWindowLimiter` builds the same structure as a sliding window
  counter: each key keeps the count of the current and the previous
  fixed window; the estimate weights the previous count by the part of
  it still inside the sliding window, and peers count as their reported
  rate over one window.
- `ConnLimiter`: wraps the listener; counts per IP in a map guarded by one
  mutex (accept rate, not request rate) and globally with an atomic. Limits
  are adjustable on reload.
- `Concurrency`: an atomic counter with a ceiling. No waiting.
- Timeouts come from `net/http` (`ReadHeaderTimeout`, `ReadTimeout`,
  `WriteTimeout`, `IdleTimeout`) and from contexts (route timeout, upstream
  total).

### Bounded tables

Every in-memory table grows with attacker controlled input (client
addresses, rate limit keys, matched rule targets) and is therefore
capped. What happens at the cap is a security decision: a rate limit
shard whose keys are all live falls back to a coarser key — the client
address, then its /24 or /48 — and refuses when there is nothing
coarser left, because admitting an untracked request made the bound
itself the way past the limit; a shard is swept for expired buckets a
bounded number at a time rather than scanned whole on every miss, and
a live bucket is never evicted to make room for a new key. Ban triggers stop
tracking new addresses, honeypot marks and challenge nonces refuse new
entries, bot score histories and admin sessions evict the oldest, WAF
statistics stop recording new rules and learning entries, and export
queues drop. None of this is silent: each site holds a `bound.Notice`
that counts every occurrence and warns at most once per minute with the
count since the previous warning, and the count is exposed where the
subsystem has a status view. Configured limits that cannot be satisfied
(a file too large, a value out of range) fail validation instead.

## 9. TLS

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

With `ocsp_stapling`, a `stapler` goroutine per listener fetches an OCSP
response for every served certificate (file and managed) and keeps them
in a map by leaf digest; `GetCertificate` returns a copy of the selected
certificate with the current response attached, so the shared
certificate is never written and a handshake never waits. Fetches use
`golang.org/x/crypto/ocsp`, the issuer from the chain file, a bounded
client and a refresh at half the response validity. With `ct`, `Load`
parses the SCT extension of each file certificate (`internal/tlsconf/ct.go`),
rebuilds the precertificate TBS with `cryptobyte` and verifies each SCT
signature against the log list; the verdict is kept per certificate for
`GET /v1/tls` and, with `enforce`, fails the load.

`tlsconf.Tickets` (`internal/tlsconf/tickets.go`) replaces the runtime's
per process session ticket keys when `server.session_tickets` is set.
Every key is `HKDF-SHA256(master, info = "xpticket" || epoch)` for the
current and the previous epoch (`epoch = now / rotate`) and for every
key of the master keyring, so nodes that share the file derive the same
set without a message; the current epoch's first key encrypts new
tickets, the rest only decrypt. The set is installed on every listener's
`tls.Config` (and the QUIC one) with `SetSessionTicketKeys` and a
one-minute loop re-derives it when the epoch changes. A fingerprint of
the set (`sha256` of the keys, 16 hex digits) is published as the
cluster event `ticket_keys` on start and after every rotation; a peer's
fingerprint that differs is recorded and warned about through a bounded
notice.

### Layer 4 passthrough

A `kind: tcp` listener (`internal/kinds/tcp`) accepts through the same
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

### Traces and logs export

`internal/otlp` is the one OTLP/HTTP client (bounded, pinned CA, gzip,
fixed headers) and the JSON attribute shapes; the metrics, trace and log
exporters share it. `internal/tracing` parses and issues W3C trace
context and keeps finished, sampled spans in a bounded queue that a
goroutine batches by size and interval; the handler starts the server
span with the request, the upstream client span in `proxyTo`, ends them
in `ModifyResponse`, the error path and the access log, and `rewrite`
sets `traceparent` on the outbound request. The `otlp` log sink
(`internal/logging/otlp.go`) is a `lineSink` like journald and syslog:
it turns the record's attributes into typed OTLP attributes and pushes
batches the same way. All three report through `GET /v1/telemetry`.

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
`internal/kinds/dns`, binding the access log, security
events and the ban list; its policy is an immutable value swapped on
reload while the cache survives.

A `doh` route (`internal/kinds/http/doh.go`) decodes an RFC 8484 request on
an http listener and hands the query to the named dns listener's
`Handle`, so DNS over HTTPS clients get the same policy and cache as
UDP clients plus the route's own admission pipeline.

An encrypted dns listener (`tls` on `kind: dns`) wraps the TCP listener
in TLS with the ALPN list `dot`, `h2`, `http/1.1` and binds no UDP.
`serveConn` completes the handshake and demultiplexes: DoT and no ALPN
stay on the DNS stream loop, HTTP goes to an `http.Server` inside the
dns server through a channel listener (`internal/dns/doh.go`), whose
handler answers RFC 8484 on the configured path with the same
`handle` path and the client address of the connection. The route
based `doh` action shares the request and response helpers.

With `dnssec`, `internal/dns/dnssec.go` validates each upstream answer
before caching: records are parsed with decompressed rdata (`rr.go`),
grouped into RRsets with their RRSIGs, and every signature is checked
over the RFC 4034 canonical form with the keys of the signer zone. Keys
come from a bounded per zone cache built on demand: the DNSKEY set of a
zone is accepted when a DS from the parent (or a trust anchor) matches
one of its keys and the set is self signed; a NODATA DS answer with a
verified NSEC or NSEC3 proof marks the delegation insecure. Denial
proofs implement NSEC name error and no data, NSEC3 closest encloser,
opt-out and wildcard cases. Lookups reuse the listener's resolver with
the DO bit and are bounded per answer. The result sets AD, turns bogus
answers into SERVFAIL (unless CD) and strips DNSSEC records for clients
without DO.

### Forward proxy

A `kind: forward` listener (`internal/kinds/forward`) is an
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

### The gate: SSH

A `kind: ssh` listener (`internal/kinds/ssh`) is an SSH server to the
client and an SSH client to the target, not a jump host that forwards a
stream. That is the whole reason it exists: a proxy that forwards the
stream cannot see which channel is a shell and which is a port forward,
so the only policy it can hold is "may connect", and the target sees the
client's key. Here every channel and every request inside the session is
a decision, and the target is reached with a credential no client holds.

A session is matched to a principal by its key fingerprint or its
certificate's principals, and the principal's policy — allowed channels,
requests, subsystems, command patterns, environment variables, forward
destinations — is compiled once and applied per request. `exec` is
checked for file transfer helpers as well as against the command
patterns, because `scp` and `rsync` never open the SFTP subsystem and
would otherwise walk past every path rule it has. SFTP itself is
mediated packet by packet (`internal/sftp`), with per-user path
templating, an operation policy and YARA over what is written. Sessions
are recorded to asciicast files (`internal/asciicast`) bounded by count
and size, and a second factor can be demanded after the key.

### The relay: SMTP, MQTT, FTP, syslog

The relay kinds (`internal/kinds/{smtp,mqtt,ftp,syslog}`) share a shape:
each parses its protocol rather than forwarding bytes, holds a policy in
that protocol's own terms, and bounds what a peer may say.

- `smtp` takes the session to the client and opens its own to the mail
  server: STARTTLS on 587 or implicit TLS on 465, `require_tls` before
  AUTH or MAIL, a replaced banner, recipient, message and error bounds,
  and XCLIENT so the server still sees the real client. Deciding the
  framing once is the point — SMTP smuggling is two readings of where a
  message ends.
- `mqtt` fronts a broker with a topic policy: which topics a client id
  may publish and subscribe to, whether `$SYS` is reachable, whether
  retained messages are allowed, and a pattern the client id must match.
- `ftp` mediates the control channel and brokers the data one, so no
  client learns a data address of its own: passive and active transfers
  are both set up by the proxy, and the command and path policy applies
  to each.
- `syslog` parses RFC 5424 and the RFC 3164 records most estates still
  send, over UDP, TCP and TLS, with bounds on every field and a policy
  over the facilities and severities a sender may claim.

All four reach the engine through `Host` alone, which is why they link
into `xrelay` and nowhere else.

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

A `static` route (`internal/kinds/http/static.go`) holds an `os.Root` opened
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

When a route compresses and the client accepts one of the offered
encodings (Brotli, zstd or gzip, negotiated by quality and then by the
configured order), the handler slips a `compressWriter`
(`internal/kinds/http/compress.go`) between the logging `responseWriter` and
the connection before the action runs, so every action writes through
it. The writer decides when the header is
committed (status, existing encoding, `no-transform`, media type,
length), buffers an unknown-length body up to `min_bytes`, decides at
the first flush for streamed bodies, and is closed by a deferred call
when the handler returns, which writes the encoder's trailer or releases
a small buffered body unchanged. Encoders are pooled per encoding and
generation; Brotli comes from `andybalholm/brotli` and zstd from
`klauspost/compress`, both pure Go.
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

gRPC-web (`internal/kinds/http/grpcweb.go`) is a translation at the edge of
the same pipeline: `isGRPCWeb` marks the request (it counts as gRPC for
routing), the rewrite turns the content type into the gRPC one, adds
`TE: trailers` and decodes a text body chunk by chunk (clients send one
padded base64 chunk per frame); `ModifyResponse` restores the web
content type and wraps the body in `grpcWebBody`, which streams the
data frames (whole frames base64 encoded in text mode) and appends the
trailer frame from the upstream trailers, or from the headers of a
trailers-only response, when the body ends. CORS preflights for routes
with `web_origins` are answered before admission, and proxy errors on
gRPC-web requests are written as trailers-only responses with the web
content type.

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

## 10. Logging

Four `slog` loggers with a `stream` attribute. Each stream is a handler
chain (the access stream swaps the JSON handler for `textHandler` when a
text `format` is configured; it renders the record's attributes through
the format's template with Apache style escaping and feeds the same
sinks):

```
logger -> [redactHandler] -> multiHandler -> JSON handler -> file (0640, rotated), stdout
                                          -> lineHandler  -> journaldSink (native datagram protocol)
                                          -> lineHandler  -> syslogSink   (bounded queue, background writer)
                                          -> lineHandler  -> otlpSink     (batched OTLP/HTTP pushes)
                                          -> lineHandler  -> siemSink     (batched HTTPS pushes: NDJSON, HEC, CEF, LEEF)
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
then drops with a counter visible in status. The SIEM sink
(`internal/logging/siem.go`) batches like the OTLP sink and renders
each record per its format; the CEF and LEEF renderers
(`siemfmt.go`) flatten the record's attributes once, map the known
ones to the format's standard and labelled custom keys, derive the
event class from the stream and the `action` attribute and the
severity from the status class, the action or the level, and emit the
rest under their own names. The syslog sink uses the same renderers
for its `cef` and `leef` formats.

## 11. Management plane

`internal/mgmt` serves a JSON API on a Unix socket, bound by
`internal/unixsock`: created under a umask that permits nothing beyond
the owner and then widened to `socket_mode` (default `0660`, `other`
bits refused by validation), so it never exists in the file system more
open than it will end up. `ConnContext` captures `SO_PEERCRED`; every
mutating call logs `peer_uid`, `peer_gid`, `peer_pid` to the audit
stream. The API has no authentication of its own by design: the kernel
enforces who may connect, and adding a token would only add a secret to
manage.

Each daemon serves its own socket — `/run/xproxy/mgmt.sock`,
`/run/xgate/mgmt.sock`, `/run/xrelay/mgmt.sock` — and one `xproxyctl`
talks to any of them with `-socket`. The endpoints are the same set;
what differs is which of them have anything to report, since a daemon
that serves no HTTP listener has no routes, no WAF and no API
inventory.

Endpoints:

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/v1/health` | liveness; also `degraded` with `degraded_reasons` when a sandbox mechanism is unavailable or failed and `sandbox.strict` is off |
| GET | `/v1/status` | version, pid, generation, listeners, counters |
| GET | `/v1/stats` | counters |
| GET | `/v1/upstreams` | endpoint health and load |
| GET | `/v1/pools` | pool level state: circuit breaker, concurrency gate and queue |
| GET | `/v1/tls` | served certificates per listener with OCSP staple and CT state |
| GET | `/v1/tls/tickets` | session ticket key epoch, fingerprint and peer agreement (404 without `server.session_tickets`) |
| GET | `/v1/telemetry` | OpenTelemetry exporters (metrics, traces, logs) with counters |
| GET | `/v1/quotas` | usage per tenant, route and rate limit policy; `?top=N` consumers per policy |
| GET | `/v1/waf` | WAF profiles (plugins, schemas), route assignments, per rule statistics (`?top=N`), learned exclusion proposals, schema violations and the anomaly baseline with flagged clients |
| GET | `/v1/waf/exclusions` | the proposals as a SecLang file (text/plain) |
| POST | `/v1/waf/reset` | clear WAF statistics and the learning table (audited) |
| GET | `/v1/api` | API inventory (`?view=all|shadow|zombie|versions|documented|undocumented&top=N`) |
| GET | `/v1/fleet` | fleet agent state: controller, applied bundle and result, pending digest, counters |
| GET | `/v1/sandbox` | in-process hardening: mechanisms with state, Landlock rules and ABI |
| GET | `/v1/config` | active configuration as YAML |
| POST | `/v1/reload` | validate and apply the configuration file; `?dry_run=1` returns the changes without applying |
| GET | `/v1/diff` | compare `from` and `to` (`active`, `file` or a history id) |
| GET | `/v1/history` | recorded configurations, newest first |
| POST | `/v1/rollback` | apply the recorded configuration `id` (audited) |
| POST | `/v1/reload-certs` | re-read certificates |
| POST | `/v1/logs/reopen` | reopen log files |
| GET | `/v1/bans`, POST `/v1/bans`, DELETE `/v1/bans?target=` | ban list |
| GET | `/v1/cluster` | cluster peers and counters |
| GET | `/v1/deceive` | the routes that answer distrusted clients with a plausible response, and how often |
| GET | `/v1/degradation` | the slow-lane levels and how often each applied |
| GET | `/v1/handshake` | the pre-handshake refusal policy and how many ClientHellos it turned down |
| GET | `/v1/capture`, POST `/v1/capture` | packet capture state (recording, window, current file, per rule counters); `{"active":true,"duration":"10m"}` opens a bounded window and `{"active":false}` closes it (audited; 404 without a `capture` section) |
| GET | `/v1/acme`, POST `/v1/acme/renew` | managed certificate status; forced renewal (audited) |
| GET | `/metrics` | Prometheus exposition |
| GET | `/v1/series?since=10m&limit=60` | sampled series for graphs |

The TUI is a mode of `xproxyctl`: a pure renderer (`tui.Render`, data and
terminal size in, lines out, tested without a terminal) driven by a raw
mode loop on `golang.org/x/term` that fetches all views concurrently with
a deadline each refresh and reads keys from stdin. It uses the same client
and therefore the same audited API for bans. Nine screens cover the
management API: overview (with sandbox, telemetry and dns lines),
upstreams with pool state, bans, cluster, graphs, the security log,
routes (the quota report), WAF statistics and served certificates; a
fetch that fails leaves its screen empty and names the error.

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
responses through unchanged (status, pools, quotas, WAF with the SecLang
download, certificates, telemetry, sandbox, dns, history, diff and every
subsystem status), actions post to the same audited endpoints (reload,
certificates, logs, ACME renewal, WAF reset, rollback by id; a dry run
posts to the reload endpoint without applying),
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

With OIDC options the GUI adds `GET /api/auth` (which logins exist),
`GET /api/oidc/login` and `GET /api/oidc/callback`
(`internal/admin/oidc.go`). The flow mirrors the OIDC filter's:
discovery with an issuer check, a state cookie sealed with AES-GCM
under a per-process key and bound to the `state` parameter by digest,
PKCE S256, a nonce, the code exchange with basic client authentication,
ID token verification by a `jwt.Provider` built from the discovered
JWKS, then a role from the configured claim and an ordinary session
(`via=oidc`) under the same idle and absolute limits. Failures redirect
to the login page with a short reason code and are logged with the
source address.

### Fleet

`internal/fleet` has three parts. A bundle is a sorted list of files
(relative paths checked against traversal, hidden names, depth and
size; the configuration must be `xproxy.yaml`) with a SHA-256 digest
over paths, modes and contents; `Read` builds one from a common and a
node directory through `os.Root`, `Validate` parses the configuration
without file checks, and `Write` replaces files inside the node's
configuration directory through `os.Root` (temporary file, fsync,
rename; never following a link out of the directory) and returns a
restore closure. The agent runs in the proxy: it long polls
`GET /v1/fleet/nodes/{id}/config?digest=&wait=` with the node's client
certificate, applies a differing bundle (`Write`, then the same reload
closure the management API uses, then restore on refusal), records the
applied digest in a marker file so a restart knows it, and posts the
node's status after every poll; failures back off up to the interval.
The controller (`xproxy-fleet serve`) scans its directory on an
interval, keeps the last good bundle per node and the scan error,
wakes waiting long polls through a channel it replaces on change,
binds a node id to the certificate name, persists each report under
`status/`, and serves operators over a local socket (`nodes`, `node`,
`bundle`, `scan`). The sandbox derives a write rule for the bundle
directory when the agent applies.

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

## 12. Filters (middleware)

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

A provider with an `introspection` section owns an `introspector`
(`internal/jwt/introspect.go`): a bounded HTTPS client with a pinned CA
that posts the token with the proxy's basic credentials and maps the
answer's fields to `Claims`; decisions are cached by SHA-256 of the
token for `cache_ttl` capped by `exp`, positive and negative alike, in
a table bounded at 65536 entries with a throttled warning when full.
`Provider.Verify` routes a token to the introspector when the provider
has no keys, when `always` is set, or when the token is not a compact
JWS; the filter answers 503 with `Retry-After` while the endpoint is
unreachable, as for missing keys.

### WAF filter

One `waf.Engine` per generation compiles each profile that some route uses
into a blocking Coraza instance, a detection-only instance, or both. The
SecLang is assembled in a fixed order: Coraza recommended settings, body
limits from the configuration, CRS setup, paranoia level and thresholds,
plugin config and before files, operator directive files and inline
directives (exclusions), CRS rules, plugin after files, and finally the
engine mode. Per request the instance mirrors Coraza's own
middleware: connection and URI, request headers, the anomaly flag
check and the JSON schema check (below), request body read into
the transaction and replayed to the upstream from Coraza's buffer, then
optionally response headers and a bounded response body. Matched attack
rules, the blocking rule's total score and the interruption are logged;
initialisation and reporting rules are filtered out.

Plugins (`plugins.go`) are discovered under `crs.plugins_dir` by file
name suffix, directly, one directory down or in that directory's
`plugins/` folder, and inlined into the assembled SecLang rather than
included, so the rule set file system needs no layout change; a
`pluginFS` layers the plugin directories over the rule set so data
files resolve by bare name and under `plugins/`. JSON body schemas
(`schemas.go`) compile through `internal/jsonschema` at load; a
matching request's body is buffered within the request body limit,
validated, and reset for Coraza. Anomaly detection (`anomaly.go`)
lives in `waf.Stats`: `End` attributes every transaction to its client
in a table sharded 64 ways (requests, rule matches, errors, up to 64
distinct paths); the first observation after the window closes rolls
it under a single mutex, turns clients at or above `min_requests` into
four features, scores them against the previous baseline (z-score with
a per feature floor on the standard deviation) and folds the window's
mean and variance into the baseline with a weight of 0.3. Flags sit in
a concurrent map read lock free on the request path; `Request` applies
the action before the body is read.

The rule set comes from a `ruleSet`: the embedded `coreruleset.FS` or,
with `crs.dir`, an `os.DirFS` over the operator's directory. The
engine recommendations that the embedded copy ships are inlined into
the assembled SecLang so both sources compile the same way; the setup
file's `crs_setup_version` and the number of rule files are recorded
for the status. Every instance reports to one `waf.Stats` owned by the
`Server` and passed into each generation's engine, so counts survive
reloads: `End` walks the transaction's matched rules and, per rule,
increments matches, blocks and detects with the last URI, bounded to
8192 rules. With learning on, the matched data of every detection rule
(variable name and key) is aggregated by (rule, target, route) in a
table bounded by `max_entries`, with a bounded set of distinct clients
and the first sample value. `Report` sorts rules by matches and turns
entries at or above `min_hits` into proposals: a `SecRule REQUEST_URI
"@beginsWith <path>"` with `ctl:ruleRemoveTargetById` when the route has
a path prefix, otherwise an unconditional `SecAction` with the same
`ctl` (directive files load before the CRS rules, where
`SecRuleUpdateTargetById` would not find its rule); ids are allocated
from 10000 upwards in sorted order so a saved file is stable.

The API security kinds follow the same shape. `api_key` keeps the keys
file as an immutable table behind an atomic pointer (hash to key,
previous hashes included), re-read when the file's digest changes and
at most every `reload`; a file that fails to parse keeps the previous
table and logs. `openapi` compiles the description at load into exact
and templated path items (templates become anchored regular
expressions, concrete paths win, longer literal prefixes first) with
per operation parameters and request bodies, and validates with a
small JSON Schema evaluator (`internal/jsonschema`, shared with the
WAF body schemas): local `$ref` resolution with
a cycle guard, a nesting limit, a bounded regular expression cache and
at most twenty reported issues. `graphql` parses queries with a
tolerant recursive descent parser under a token budget and measures
depth, complexity (list argument multipliers capped by `max_list`),
aliases and introspection with fragments expanded and cycles detected;
denials are GraphQL error documents.

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

## 13. Cluster

```
 node A                                   node B
 +-----------------------------+          +-----------------------------+
 | limiters  --Flush--> gossip |--------> | accept -> Report -> limiters|
 | ban list  --OnChange-> queue|  (A->B)  |          Apply  -> ban list |
 |                             |          |                             |
 | accept <-Report/Apply       | <--------| gossip <--Flush/OnChange    |
 +-----------------------------+  (B->A)  +-----------------------------+
```

Each node dials every configured peer and sends on that connection; it
receives on the connections peers dialled to it. Messages are
newline-delimited JSON, at most 1 MiB, with bounded counts of keys and
bans per message and a read deadline of `peer_stale` plus five seconds;
a silent peer is disconnected and redialled with back-off.

A cluster is one transport or the other, decided by the form of
`cluster.listen`, and every peer address must agree with it. A node
listening on a socket and dialling a host would be reachable by its
siblings and not by the peers it dials, which is half a cluster that
looks like a whole one.

**Networked**, `host:port`. Both directions are TLS 1.3 with client
certificates from the cluster CA, optionally restricted to
`allowed_names`. A peer's actions are recorded under its certificate
common name, never under the node id it announces, and with
`bind_node_id` (the default) the announced id must be a name that
certificate carries — the id is not a label, since key ownership for
`distributed: exact` is a rendezvous hash over node ids.

**Local**, `unix:/path`. The peers are the daemons of this machine, and
there is no TLS: a certificate would authenticate processes the kernel
can already name, and it would have to be issued and rotated for a
conversation that never leaves the host. Two things admit a peer
instead. The sockets live in a directory the shipped `tmpfiles.d` entry
creates `0770 root:xproxy-cluster`, with the three daemons in that
group and nothing else; and `cluster.local.allow_uids` lists the user
ids, read from the connected socket with `SO_PEERCRED` rather than
announced. A local peer is then recorded under that user id
(`uid:991`), which is the same rule `bind_node_id` enforces with a
certificate, reached the way a Unix socket reaches it. `internal/
unixsock` binds the socket: refuse a path something still answers on,
clear one a killed process left, create it under a umask that permits
nothing beyond the owner and widen it afterwards, so it never exists in
the file system more open than it will end up.

A local cluster is what the split uses to keep one ban list across three
daemons: an address xgate refuses at the SSH port is refused by xproxy
at :443 within a gossip interval, and by xrelay at :587. Rate limits are
usually left unshared there (`share_rate_limits: false`), because the
three serve different protocols on different ports and a shared count
would only add noise.

Every `gossip_interval` the node flushes consumption from all limiters of
the live generation (policy, key, tokens) and sends one `rates` message
carrying the measured interval; the receiver converts counts to rates and
calls `ReportPeer` on the matching policy. Buckets refill at the configured
rate minus the sum of fresh peer rates (section 8), which makes the
configured rate approximately cluster wide. Ban changes originating locally
(manual or trigger) are queued by the ban list's change hook and sent in
the same cycle; peers apply them with source `peer:<node>` and never
re-announce them, so there are no loops. A newly connected peer receives a
snapshot of all active bans. Idle cycles send a ping so deadlines hold.

Exact rate limits ride the same connections. The accepting side now
answers a `hello` with its own, so the dialler learns the peer's node
id; the members are this node plus every peer whose id is known on a
live outbound connection, and `Owner(key)` is the member with the
highest rendezvous hash of member and key, which every node computes
alike from the same membership. `Take` sends a `take` (policy, key,
amount, request id) to the owner on the outbound connection and waits
for the `took` the owner writes back on that connection (the only
traffic in that direction) for at most `exact_timeout`; the owner's
`RateSource.Decide` runs its local limiter. No answer in time, an
unknown owner or a full pending table (65536) means a local decision
and an `exact_fallbacks` count, so the failure mode is over-admission,
never a refused request. Older nodes ignore `take` and never answer a
hello, so they are simply not members.

Protocol version 2 (1.3) adds an `events` message: bounded facts with a
kind, a key, an optional route and an expiry. The server publishes
honeypot marks and unmarks and applies peers' marks to its own table;
filters reach the channel through `filter.Env.Events`, a per generation
bus (`internal/kinds/http/events.go`) whose subscriptions die with the
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
peer state. Listen address, node identity, TLS material and the `local`
section need a restart — the socket's mode and the user ids allowed on
it are settled when the socket is created and when a peer connects, so
changing either in place would leave the running node admitting what the
file no longer says it should. Peers and intervals reload.

## 14. Load shedding and challenge

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

## 15. HTTP/3

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

HTTP/3 is also spoken upstream. `h3.NewClientTransport` wraps quic-go's
`http3.Transport` with the pool's client TLS configuration (server
name, roots, client certificate) and timeouts; `Pool.RoundTripper`
returns it when `h3` is set, health probes share it, and
`poolTransport` retries a request whose QUIC connection failed before
a response over the TCP transport of the same endpoint when
`h3_fallback` allows (`h3.IsTransportError` recognises the QUIC error
types), counting the fallback. A listener with `h3.webtransport`
builds its `http3.Server` inside a `webtransport.Server`
(quic-go's webtransport-go): datagrams and the WebTransport settings
are enabled and each accepted QUIC connection is served through it so
that session streams are demultiplexed. An extended CONNECT with the
webtransport protocol on a route with `webtransport: true` reaches
`relayWebTransport`: the upstream session is dialled first
(`h3.DialWebTransport`, the CONNECT carrying the forwarding headers and
the route's header operations), then the client's is accepted with
`Upgrade`, and `h3.RelayWebTransport` pipes bidirectional streams,
unidirectional streams and datagrams both ways, mirroring closes and
resets with their codes, until either session ends.

## 16. Scale properties (measured, see PERFORMANCE.md)

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
- The three daemons are 28.4, 15.3 and 14.9 MiB as `make build` produces
  them (`xproxy`, `xgate`, `xrelay`). The spread is the number that
  matters, not the total: the bastion and the relay carry neither the
  other daemons' protocol implementations nor the HTTP data plane, which
  is most of what `xproxy` is (section 3). What they still share is the
  engine, the configuration package, TLS and logging, and the management
  API.

Throughput on the reference container (ASR-P2) is 10 000 req/s at p99
under 10 ms with the load generator on the same four cores; the 8 core
figure with a remote generator is still to be measured. Remaining
performance work: allocation in the handler (header map copies in
`ReverseProxy`), an asynchronous access log writer with a bounded buffer
and drop counter, and `GOMAXPROCS` and `GOGC` guidance.
