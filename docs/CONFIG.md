# Configuration reference

Three daemons read this format: **xproxy** (the edge: `http`, `forward`,
`tcp`, `dns`), **xgate** (the gate: `ssh`) and **xrelay** (the relay:
`smtp`, `mqtt`, `ftp`, `syslog`). Every one of them validates the whole
file — a listener kind a sibling serves is checked as carefully here as
at home — and binds only the listeners of its own role, saying in the
log which it left to whom. That is what lets an estate keep its common
parts in `includes` that all three pull in.

What the three cannot share is a file: `management.socket`,
`metrics.listen` and `logging.directory` each name something only one
process can own. So each daemon reads a file of its own —
`/etc/xproxy/xproxy.yaml`, `/etc/xproxy/xgate.yaml`,
`/etc/xproxy/xrelay.yaml` — carrying those three sections and pulling
the rest in with `includes`. Nothing stops you pointing two daemons at
one file; they will then fight over the socket, and the second to start
will lose.

Each of them reads one YAML document. Unknown keys are errors. Every omitted value
takes the default listed here; a zero duration or count means "default",
never "disabled". Paths must be absolute. Durations use Go syntax: `500ms`,
`10s`, `5m`, `1h`. Names match `[A-Za-z0-9][A-Za-z0-9_.-]{0,63}`.

Validate with `xproxy -config FILE -validate` (or `xgate`/`xrelay`, which
check the same file and additionally report how much of it they would
serve); all problems are reported at once. The example in `deploy/config/xproxy.yaml` exercises most keys.

This reference is also installed as the manual page `xproxy.yaml(5)`,
and a JSON schema generated from the same types
(`/usr/share/xproxy/xproxy.schema.json`, `xproxyctl schema`) gives
editors completion and inline documentation; put
`# yaml-language-server: $schema=/usr/share/xproxy/xproxy.schema.json`
on the first line of the file to enable it.

## Top level

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `version` | int | required | Schema version. Must be `1`. |
| `includes` | list of globs | `[]` | Absolute paths or globs of fragment files whose `upstreams`, `routes`, `rate_limits` and `filters` are appended in lexical order of path; a fragment may contain nothing else, names must not repeat, a pattern that matches no file is an error, fragments must not be world writable; read at every load and reload |
| `server` | object | | Listeners and global limits |
| `management` | object | | Control socket |
| `logging` | object | | Log streams |
| `trusted_proxies` | list of CIDR | `[]` | Peers whose `X-Forwarded-For` is believed, and whose PROXY protocol header is parsed on listeners with `proxy_protocol: true`. Empty means never. `0.0.0.0/0`, `::/0` and any prefix shorter than `/8` are refused: trusting every address would let any client choose its own address and defeat bans, rate limits, ACLs and the audit trail; list the balancer networks |
| `rate_limits` | list | `[]` | Named rate limit policies |
| `upstreams` | list | `[]` | Named endpoint pools |
| `routes` | list | `[]` | Request matching and actions |
| `compression` | object | none | gzip of eligible responses; see `compression` |
| `tracing` | object | none | W3C trace context and span export; see `tracing` |
| `capture` | object | none | pcapng capture of the exchanges the proxy handled; see `capture` |
| `scim` | object | none | A SCIM 2.0 provisioning endpoint for the second factor and the API keys; see `scim` |
| `policy` | object | `{mode: enforce}` | Whether the listeners enforce their policies or only evaluate them and write down what they would have refused; see `policy` |
| `secrets` | object | none | Where the secrets this file names come from: a path, the environment, or a vault; see `secrets` |
| `fips` | object | none | Whether this daemon insists on the FIPS 140-3 module, and what it says about the algorithms configured; see `fips` |

## policy

A policy nobody dares switch on is not a control, and the reason nobody
dares is always the same: no one knows what it would refuse at three in
the morning. Shadow mode is the answer the WAF has had for years,
generalised to every protocol — the policy is evaluated on real traffic,
every decision it would have made is written down, and nothing is refused
for policy.

```yaml
policy:
  mode: shadow          # enforce (default) or shadow
  max_reasons: 4096
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `mode` | enum | `enforce` | `enforce` or `shadow`, for every listener that does not name its own in `server.listeners[].policy`. `shadow` warns at validation |
| `max_reasons` | int | `4096` | The ledger's bound: distinct combinations of kind, listener, reason and rule. Past it the report says it is full rather than quietly stopping |

Read it with `xproxyctl policy report` (`-top N`, `-json`), which lists
what each listener would have refused, most frequent first, with the rule
that decided, an example of what was asked for, and when it was first and
last seen. `xproxyctl policy reset` empties the ledger, which is what an
operator runs after fixing a policy so the next week's report is about the
new one. `GET /v1/policy` and `DELETE /v1/policy` are the endpoints; the
totals are in `xproxyctl status` as `would_refusals` beside `refusals`,
and `shadow` carries the ledger's own state.

**What shadow mode does and does not stop.** It applies to *policy*: the
statements an estate writes about what its own traffic may do. It never
applies to integrity, identity or a bound, because forwarding those would
mean acting on bytes the code could not read, or admitting somebody who
did not authenticate — a trial instead of a door.

| Kind | Evaluated and recorded | Still refused |
|------|------------------------|---------------|
| `modbus` | every rule: function, unit, address range, value bounds, rate and window | malformed frames, the unit table, the queue bound, rate limits, bans |
| `iec104` | every rule: type, class, cause, station, originator, point range and the select half; `monitor_only`; the common-address list; `require_select` | malformed frames, the frame bound, rate limits (frame and command), a station commanding its own control centre, bans |
| `ldap` | every rule: the bound identity, the bind method, the operation, the access class, the subtree, the scope and the attributes; `methods`, `sasl_mechanisms`, `min_version`; `read_only`; `base_dns`; the attribute lists; the filter and entry bounds | a simple bind carrying a password on an unprotected connection, malformed messages, the message bound, message identifier zero, rate limits (request and bind), the client list, an answer no request matched, bans |
| `snmp` | every rule: version, community or user, security level, operation, access class, object subtree and context; `versions`, `communities`, `users`, `min_security_level`; `read_only`; the message direction | malformed messages, the message and response bounds, the GETBULK repetition bound, the response ratio, an answer nobody asked for, rate limits, the client list, bans |
| `dhcp` | every rule: the client network, the hardware address, the message type and the vendor class; `message_types`; the option lists and the address lists on a reply | a reply from an address that is not in `allow_servers`, malformed messages and malformed option values, an option hidden in a header field or split across instances, the hop bound, the lease bounds, the pending bound, rate limits, a message type arriving from the wrong side, bans |
| `tftp` | every rule: the direction, the mode, the directory, the filename pattern and the path class; `operations`, `modes`, `allow_path_classes`, `directories`, `filenames` | a filename in the nul, control or empty class, the filename and depth bounds, the block, window and transfer bounds, a packet on the request port that is not a request, a datagram from an address with no part in the transfer, rate limits, the client list, bans |
| `ntp` | the client list and every request rule (versions, modes, extension fields, the identity it demands), and every answer rule (stratum, distances, timestamps, identifier, leap) | mode 6 and 7, version 5, malformed packets, bans, rate limits, the association and outstanding bounds |
| `mqtt` | the client list, the CONNECT policy (version, client id, username, keep alive, will), the publish and subscribe policies, retain | malformed packets, a first packet that is not CONNECT, a second CONNECT, the packet bound, the connection limit, TLS failures |
| `syslog` | the sender list, the facility, severity and pattern rules | malformed messages, the rate limit, a full queue |
| `dns` | the client list, the block list, response policy zones, tunnel cooldowns | malformed queries, bans, the rate limit, the worker bound, the cookie requirement |
| `ssh` | the client list and the command, subsystem, environment and file-transfer rules | an unknown host key, a key that does not authenticate, a certificate extension that itself refuses, MFA, bans, the connection limit, a request it could not parse |
| `telnet`, `vnc`, `rdp`, `ftp` | the client list; telnet's option list; ftp's verb list | bans, connection limits, MFA, malformed input, the protocol's own version and encryption negotiation |
| `smtp` | the verb list | the protocol-state refusals, the encryption and authentication requirements, the size bound, malformed commands |
| `forward` | the destination lists: ports, deny, allow | `private` (which protects the estate *from* the client — shadowing it would turn a trial into a server-side request forgery), a destination that does not resolve, credentials, tunnel bounds |
| `http` | the route's positive security model (methods, media types, query parameters, shape bounds); a blocking WAF profile runs as a detecting one, and `xproxyctl waf -top` says which rule would have blocked what | bans, rate limits, virtual patches, authentication and authorisation filters, the normalisation guard, the request and body bounds |
| `tcp`, `udp`, `ntske` | nothing: their refusals are either "no destination exists for this" or a bound, and neither is a policy a shadow run could answer | all of them |

## server

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `listeners` | list | required, at least one | See below |
| `limits` | object | | Global protections |
| `server_header` | string | `""` | Value of the `Server` response header. Empty removes it. |
| `zone` | name | `""` | The failure domain this node is in — an availability zone, a rack, a site. It is what an upstream's `locality` policy compares an endpoint's `zone` against, so a node prefers the endpoints beside it. Empty means the node does not know where it is, and a locality policy then prefers nothing |
| `error_pages` | object | none | Replace the proxy's plain status bodies (denials, unknown routes, upstream failures, static misses) with documents; see "server.error_pages" below |
| `session_tickets` | object | none (keys per process, rotated by the Go runtime) | Derive the TLS session ticket keys of every TLS listener from a shared secret file so that a ticket issued by one node resumes on every node; see "server.session_tickets" below. Changing the section needs a restart |
| `shutdown_timeout` | duration | `30s` | Drain time on stop, and the minimum an old generation is kept for after a reload. A generation still serving a request when it expires is kept until that request ends, so a long upload or an SSE stream is not cut; a hard cap of ten times this (at least five minutes) bounds one that never ends |

### server.session_tickets

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `secret_file` | absolute path | required | Master keyring, created with mode `0600` when missing; a keyring readable by other accounts, or writable by its group, is refused at load (`0600` and `0640` are accepted). Deploy the same file to every node; rotate the master with `xproxyctl rotate-secret` (the kept keys still open tickets sealed under the old master for one more epoch) |
| `rotate` | duration | `24h` | Epoch length, `1h` to `168h`. Each epoch's key is derived from the master and the epoch number, so nodes with synchronised clocks switch keys together without exchanging messages; the previous epoch's key is kept for decryption, so a ticket lives at most two epochs |

The key set's fingerprint is shown by `xproxyctl tls tickets` and `GET
/v1/tls/tickets`; a cluster publishes it and a node whose peers derive a
different set (a different secret file or a clock more than an epoch
off) logs a warning and lists them under `mismatched_peers`.

### server.listeners[]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | name | required, unique | Also used to match systemd socket names |
| `address` | host:port | required | `":443"`, `"0.0.0.0:80"`, `"[::1]:8080"`. Port `0` picks a free port (tests): a kind that serves datagrams as well takes the same port on both transports, and if the port the kernel chose is held by something else on the other one, another pair is asked for. |
| `protocols` | list | `[h1, h2]` with TLS, `[h1]` without | `h2` and `h3` require `tls`. `h3` adds a QUIC endpoint on UDP at the same port and requires `h1` or `h2` alongside it (clients discover HTTP/3 through `Alt-Svc`). |
| `h3` | object | defaults when `h3` is listed | QUIC tuning; see below |
| `h2c` | bool | `false` | Accept HTTP/2 without TLS (prior knowledge and Upgrade) on a plaintext listener, for gRPC clients inside a trusted network |
| `tls` | object | none | TLS termination; see below |
| `proxy_protocol` | bool | `false` | Read a PROXY protocol v1 or v2 header at the start of every connection from a peer in `trusted_proxies`: the client address it carries becomes the peer for limits, bans, ACLs, logs and forwarding headers, and the per address connection count moves to it. A trusted peer that sends no header, or a malformed one, is dropped without a response (`drop_connection` with reason `proxy_protocol`, counted in `rejected_connections`); `LOCAL` headers keep the balancer's address; connections from other peers are served unchanged, so a client cannot choose its own address. Requires `trusted_proxies`; read on `kind:` `http`, `forward`, `ssh`, `telnet`, `vnc`, `rdp`, `smtp`, `mqtt`, `ftp`, `syslog` and `modbus`, and not on `tcp` (which reads the first bytes itself to route by server name, and forwards a header instead), `dns`, `udp`, `ntp` or `ntske` -- the datagram kinds have no connection to put a header at the start of, and the key establishment relay reads the ClientHello. |
| `kind` | `http`, `tcp`, `udp`, `forward`, `dns`, `smtp`, `mqtt`, `ftp`, `syslog`, `modbus`, `ntp`, `ntske`, `ssh`, `telnet`, `vnc`, `rdp` | `http` | `tcp` is a layer 4 stream listener and `udp` its datagram counterpart, `forward` an explicit proxy for clients, `dns` a DNS proxy, `smtp` a protocol-aware SMTP and submission proxy, `mqtt` an MQTT proxy, `ftp` an FTP proxy, `syslog` a syslog relay, `modbus` a Modbus relay, `ntp` an NTP and NTS time gateway with `ntske` its key establishment relay, and `ssh`, `telnet`, `vnc` and `rdp` the access gateways; see below. The kind also decides which daemon serves the listener: `http`, `forward`, `tcp`, `udp` and `dns` are xproxy's, `ssh`, `telnet`, `vnc` and `rdp` are xgate's, and `smtp`, `mqtt`, `ftp`, `syslog`, `modbus`, `ntp` and `ntske` are xrelay's. A daemon handed a listener of another kind validates it and leaves it alone; it is never served by the wrong data plane |
| `redirect_to_https` | bool | `false` | Answer every request with 308 to `https://host/path?query`. Plaintext listeners only. |
| `connection_rate` | object | none | `{per_second, burst}`: how fast this listener accepts, replacing `server.limits.connection_rate` for it. See below |
| `connection_rate_per_source` | object | none | `{per_second, burst, ipv4_prefix, ipv6_prefix, max_sources}`: how fast one source network may connect to this listener |
| `policy` | object | the estate's `policy` | `{mode: enforce|shadow}` for this listener alone; see `policy` |

### server.listeners[].tcp (kind: tcp)

A `kind: tcp` listener forwards connections at layer 4. TLS connections
are routed by the server name of the ClientHello, which is peeked and
passed through unchanged, so the upstream terminates TLS with its own
certificate and the client verifies that one. Connections that are not
TLS, or whose name matches no route, go to `default` when set and are
closed otherwise. A tcp listener takes no `tls`, `protocols`, `h3` or
`redirect_to_https`; bans and the global connection limits apply at
accept as on every listener.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `routes` | list of `{sni: [names], upstream}` | | Names are exact or `*.suffix`; first match wins |
| `default` | upstream | none | Upstream for unmatched and non-TLS connections; without it they are closed and logged as `tcp_no_route` (a ban category) |
| `idle_timeout` | duration | `10m` | Close after no bytes in either direction; at most 24h. It is a property of the connection, not of one direction: a connection whose server side speaks rarely while the client is busy is not idle |
| `session_timeout` | duration | `0` | Close after this long however active; at most 168h, and not shorter than `idle_timeout` |
| `max_bytes_in` | int | `0` | Bytes one connection may relay from the client; `0` is no bound |
| `max_bytes_out` | int | `0` | Bytes it may relay back; `0` is no bound. Past either the connection is closed, not truncated: a relay that kept the socket open and stopped forwarding would look to both peers like a network that had gone quiet |
| `proxy_protocol` | bool | `false` | Send a PROXY protocol v2 header with the client address to the upstream |
| `max_connections` | int | `10000` | Open connections on this listener; also bounds QUIC flows |
| `quic` | bool | `false` | Also relay QUIC: UDP on the same address, the ClientHello read from the version 1 Initial packet (decrypted with the Initial keys every observer can derive), the flow routed by server name to the same upstreams and every later datagram of that client address forwarded unread; not with `proxy_protocol` |
| `quic_idle_timeout` | duration | `30s` | End a QUIC flow with no datagrams either way; at most 1h |
| `connect_timeout` | duration | `10s` | Bound on the dial to an original destination, which has no pool to take one from |
| `transparent` | bool | `false` | Dial the upstream **as the client**: `IP_TRANSPARENT` on the outgoing socket and a bind to the client's address, so an upstream with no PROXY protocol still sees who is calling. Linux, and needs `CAP_NET_ADMIN`; see below |
| `original_destination` | bool | `false` | Take the destination from the socket rather than from `routes` or `default`, for a transparently intercepted connection. Linux; requires `allow_destinations` |
| `allow_destinations` | list | `[]` | CIDRs an original destination may be in. Required with `original_destination`, and an empty list allows nothing |
| `destination_ports` | list of int | `[]` (any) | Ports an original destination may have |
| `yara` | object | none | Apply YARA rules to the bytes of each connection; see below |

Endpoints are picked with the upstream's balancer (hash on the client
address for `hash`), dial failures try the next endpoint and feed outlier
ejection; active health checks run as configured on the upstream — for a
pool with no HTTP behind it, `health_check.type: tcp` is the probe that
fits.

**A server that speaks first is relayed on a default-only listener.** When
no SNI routes are configured, the listener waits about a second for a
ClientHello before selecting the default, so SSH, SMTP, FTP, MySQL and
PostgreSQL — all of which greet the client before it says anything —
reach their client rather than deadlocking against a peek that is waiting
for bytes the client is waiting to be greeted before sending. A listener
with SNI routes waits for the ClientHello hard timeout instead: initial
silence cannot select the default and bypass those routes. Every
connection writes one `tcp` line to the access log with the name,
upstream, endpoint, bytes and duration (`proto: quic` for QUIC flows).
Counters: `tcp_connections`, `tcp_rejected`, `tcp_errors`,
`tcp_bounded` (ended by `session_timeout` or a byte bound rather than by
a peer; the access log's `closed` field says which), `tcp_bytes_in`,
`tcp_bytes_out`, `quic_flows`, `quic_rejected`, `quic_flows_open`;
`xproxy_tcp_*` and `xproxy_quic_*` metrics. QUIC
flows are keyed by client address, so a client that migrates to a new
address starts a new flow (its first packet is not an Initial and is
dropped; the client falls back or retries); QUIC versions other than 1
are dropped. Changing a tcp listener needs a restart.

#### Transparent interception

Two socket tricks for the deployment where the client does not know the
proxy is there. Both are **Linux only** and refused at load elsewhere,
and `transparent` needs `CAP_NET_ADMIN`, which is checked at load rather
than discovered on the first connection.

**`original_destination`** answers "which upstream" from the socket. The
client dialled some service and a routing rule put the packets on this
listener, so there is no configuration question to answer:

- With **TPROXY** the socket keeps the original destination as its own
  local address.
- With **iptables REDIRECT** the kernel rewrote it, and the original is
  read with `getsockopt SO_ORIGINAL_DST`.

The proxy reads REDIRECT's first and falls back to the local address, so
it covers both without an operator having to tell it which rule they
wrote — and keep that in step with the firewall. The option is read for
**IPv4** only; IPv6 interception is done with TPROXY in practice, where
the destination is the socket's own address and no option is read at all.
An IPv6 REDIRECT therefore falls through to that path, reads the
listener's own address, and is refused by the loop check below rather
than relayed somewhere wrong — incomplete in the safe direction.

Three checks run before such a connection is relayed, cheapest first:

1. **There is a destination to read.** Without one the connection arrived
   by some other route (`no_original_destination`).
2. **It is not this listener's own address.** A firewall rule that sends
   a listener's port to itself makes a loop that consumes descriptors
   until the process dies, from one client packet. This is the only place
   in the proxy with a destination it did not choose, so it is the only
   place that needs the check; it counts in `tcp_errors` and warns in the
   error log, because the client did nothing wrong and an operator
   hunting a misconfiguration should not have to find it in a deny log
   full of real refusals (`destination_loop`).
3. **It is inside `allow_destinations`** (and `destination_ports`, when
   set). An empty policy allows nothing, so forgetting the list means
   "nothing works" rather than "everything does"; it is required at load
   for the same reason (`destination_not_allowed`, a `tcp_no_route` deny
   event, so bans apply).

**`transparent`** makes the upstream see the client's own address, for a
service that needs it and has no PROXY protocol to read it from: the
outgoing socket gets `IP_TRANSPARENT` (and `IP_FREEBIND`, because the
address being bound is not this machine's) and binds the client's
address.

The return traffic then has to be routed back to this host, which is the
firewall's business and not something the proxy can check — so the
listener **warns at load**, because without it every connection fails in
a way that looks exactly like a dead upstream. `transparent` together
with `proxy_protocol` is refused: the upstream would be told the client's
address twice, in the header and in the source, and the two can disagree.

#### server.listeners[].tcp.yara

YARA rules over the bytes a layer 4 listener relays. The engine is a
subset of the language implemented in Go — this proxy links no C library
into the data plane, and `CGO_ENABLED=0` is a property worth more here
than the last few features of the grammar. What is supported:

- **strings**: text with `nocase`, `wide`, `ascii`, `fullword` and
  `private`; hex with `??` and `4?` wildcards and `[n]` or `[n-m]`
  jumps; regular expressions (RE2, with the `i` and `s` flags).
- **conditions**: `$a`, `not`, `and`, `or`, parentheses, `N of them`,
  `any of them`, `all of them`, `N of ($a*)`, `#a` and `filesize`
  compared with a number, `true`, `false`.
- **not supported**: modules and `import`, `at`, `in`, `for` loops,
  `entrypoint`, unbounded jumps (`[2-]`), alternation inside a hex
  string, string offsets and lengths (`@a`, `!a`), and the `xor` and
  `base64` modifiers.

Anything outside that is **refused at load**, with the line number. A
rule that silently matched nothing would be worse than one that will not
start.

Two things differ from scanning a file, and both are deliberate. A rule
is reported the first time its condition becomes true, not at the end:
a decision that arrives after the last byte is a decision about a
transfer that already happened. And `filesize` means the bytes seen so
far, which is the only honest reading when there is no end yet.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `rules_file` | path | one of these | One rule file, compiled at load |
| `rules_dir` | path | one of these | Every `.yar` and `.yara` file in the directory, in name order, as one set. A file that does not compile fails the load |
| `action` | `close`, `log` | `close` | `close` ends the connection and observes a `yara` ban reason; `log` records the match and lets the bytes through, which is how a rule set is tried out before it decides anything |
| `directions` | list | `[client, upstream]` | Which sides are scanned: what the client sends, what comes back |
| `max_window` | int | `262144` | The buffer one direction scans in, and the bound on the overlap carried between windows. The overlap is what lets a match straddling two reads still be found; a pattern wider than a quarter of the window cannot be matched reliably across reads |
| `max_bytes` | int | `33554432` | Stop scanning a direction after this many bytes; the connection carries on unscanned. `0` scans everything and warns, because a long transfer then costs arbitrarily much |

Nothing is held back waiting for a verdict: the bytes scanned are the
bytes forwarded, because a stream cannot be paused without the peer
noticing. What a match decides is whether the connection continues.
QUIC flows on the same listener are not scanned and validation says so:
they are encrypted, and a rule over ciphertext matches nothing.

Counters: `yara_matches`, `yara_scanned`; `xproxy_yara_matches_total`
and `xproxy_yara_bytes_total`. A match is a `yara_match` security event
with the rules, their tags and the offset.

### server.listeners[].udp (kind: udp)

A `kind: udp` listener is a generic datagram relay: the symmetric
primitive to `kind: tcp` for services this proxy has no parser for.
Nothing in the payload is read. What it provides is an endpoint pool
with a balancer and health checks in front of a UDP service, a set of
bounds, and the telemetry the rest of the proxy has.

**There is no connection, so there is a session table.** The first
datagram from a client address picks an endpoint through the pool's
balancer and opens a connected socket towards it; every later datagram
from that address takes the same path, and what the endpoint answers
goes back to that address. A session ends when it has been idle for
`idle_timeout`, when it reaches one of its bounds, or at shutdown. The
socket towards the endpoint is *connected*, so the kernel drops anything
arriving from another address: an answer forged by a third party never
reaches the client.

**A datagram cannot be refused.** There is no reply that means "no", and
an error sent to a source address that did not really send anything is
itself an attack on whoever owns that address. So everything this relay
will not forward is **dropped**, counted in `udp_dropped` and written to
the security log as `udp_denied` with the reason in `detail` — which
means bans apply to it. That is the whole difference in feel from
`kind: tcp`, where a refusal is a closed connection the client sees.

**A source address is whatever the sender wrote**, which is why this
listener needs an admission policy more than a stream one does:

- `allow_clients`, or `rate_limit`, or both. Validation **warns** when a
  listener on a non-loopback address has neither, because an open
  datagram relay is somebody else's amplifier: it answers a victim with
  traffic the victim never asked for, at whatever gain the service
  behind it provides.
- `max_sessions_per_ip` as well as `max_sessions`. Without the per
  source bound, a few forged datagrams a second fill the table and the
  service stops for every client that is real.

**No accept socket at all.** This is the one kind that binds only a
datagram socket, so nothing holds the matching TCP port and a client
that connects to it is refused by the kernel rather than left hanging.
Everything that applies to accepted connections therefore does not apply
here — the shared connection limiter, `proxy_protocol` (which has no
datagram form and is refused at load), a `tls` section (there is no
handshake on a datagram to secure) — and the bounds below are the whole
of the admission policy. Any change to such a listener restarts the
daemon rather than being applied in place, as it does for every listener
that owns a UDP socket.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `upstream` | string | required | The pool of endpoints |
| `idle_timeout` | duration | `30s` | No datagram in either direction ends the session. It stands in for a connection close, since nothing in the protocol says a client has finished |
| `session_timeout` | duration | `0` | Bound on a whole session however active. Must not be shorter than `idle_timeout` |
| `max_sessions` | int | `10000` | The session table. A datagram from a new client when it is full is dropped and counted in `udp_rejected` |
| `max_sessions_per_ip` | int | `64` | Sessions from one address; `0` removes the bound. This is what keeps one source, or one forged source, from filling the table |
| `max_datagram_bytes` | int | `65535` | The largest datagram relayed either way. A larger one is dropped whole rather than truncated, because half a datagram is not a shorter datagram |
| `max_datagrams` | int | `0` | Datagrams in one session, both directions; `0` is no bound |
| `max_bytes_in` | int | `0` | Bytes one session relays from the client; `0` is no bound |
| `max_bytes_out` | int | `0` | Bytes it relays back; `0` is no bound |
| `rate_limit.pps` | float | none | Datagrams per second from one source address |
| `rate_limit.burst` | int | `pps` rounded up | How many may arrive at once |
| `allow_clients` | list | `[]` (any) | CIDRs a client must come from |

Counters: `udp_sessions`, `udp_sessions_open`, `udp_datagrams_in`,
`udp_datagrams_out`, `udp_bytes_in`, `udp_bytes_out`, `udp_dropped`
(a datagram the policy would not relay), `udp_rejected` (a new client
the table bounds refused) and `udp_errors` (a session that found no
reachable endpoint); the matching `xproxy_udp_*` metrics. Every session
writes one `udp` access line with the client, the endpoint, the
datagrams and bytes each way and how it ended. Refusals are
`udp_denied` deny events, so bans apply.

### server.listeners[].forward (kind: forward)

A `kind: forward` listener is an explicit proxy that clients configure
in their browser or `HTTPS_PROXY`. `CONNECT host:port` opens a tunnel
(TLS stays end to end between the client and the destination; nothing
is inspected) and absolute `http://` request lines are relayed with
hop-by-hop headers removed and `Via: 1.1 xproxy` added. Requests that
are neither (an ordinary origin-form request, an `https://` URI) get
400. Every destination passes the policy below before a connection is
made: the port must be listed, the name is resolved, the resolved
addresses must not be private unless `allow_private` is set, `deny`
wins, and a non-empty `allow` must match. The address that passed the
check is the one dialled, so a name cannot rebind between check and
connect. Refusals answer 403, are logged as security events
(`forward_port`, `forward_private`, `forward_deny`, `forward_not_allowed`,
`forward_resolve`) and count towards the `forward_denied` ban reason.
A forward listener may terminate TLS from the client (`tls`), and with
TLS may list `h2` so clients tunnel `CONNECT` over an HTTP/2 stream
(the stream carries the tunnel, one per request, ending when the
destination closes or the client resets); it takes no `tcp`,
`redirect_to_https`, `h3` or `h2c`. Bans, the
connection limits and the header timeouts apply as on every listener.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `ports` | list of int | `[80, 443]` | Destination ports clients may reach, for CONNECT and plain requests alike |
| `allow` | list | `[]` (any) | Destination names (exact or `*.suffix`), addresses or CIDRs; when set, a destination must match by name or by a resolved address |
| `deny` | list | `[]` | Same forms; a match by name or by any resolved address refuses the request, before `allow` |
| `allow_private` | bool | `false` | Permit loopback, link local, RFC 1918, CGNAT, unique local, multicast and unspecified destination addresses (the SSRF guard) |
| `auth` | object | none | Require `Proxy-Authorization: Basic` credentials; without it the listener is open to every client the bans and limits admit |
| `auth.users_file` | path | required | `name:hash` lines from `xproxyctl htpasswd`; re-read on reload and a bad file fails the reload; verified credentials are cached for five minutes and the cache is dropped on reload |
| `auth.realm` | string | `proxy` | Sent in `Proxy-Authenticate` with 407 |
| `connect_timeout` | duration | `10s` | Name resolution and dial bound per destination; at most 5m |
| `idle_timeout` | duration | `10m` | Close a tunnel after no bytes in either direction; at most 24h |
| `max_tunnels` | int | `10000` | Open CONNECT tunnels on this listener; over it CONNECT answers 503 |
| `max_response_bytes` | int | `67108864` | Largest plain response body relayed; a larger one is cut off and the connection closed; 0 disables |
| `socks5` | bool | `false` | Also speak SOCKS5 (RFC 1928) on this port; see below |
| `socks_udp` | bool | `false` | Allow SOCKS5 `UDP ASSOCIATE` (requires `socks5`) |
| `masque` | object | none | UDP and IP proxying over extended CONNECT (RFC 9298, RFC 9484); see below |
| `intercept` | object | none | Terminate TLS inside a CONNECT tunnel and read what passes through it; see below |

#### TLS interception on a forward listener

A CONNECT tunnel is opaque by design: the proxy sees a name and a byte
count and nothing else, so a destination policy is the only policy it
can apply. `intercept` changes that. The proxy answers the client's
handshake with a certificate it signs itself, opens its own TLS
connection to the destination, and relays the plaintext between the two
— which is what lets YARA rules, and everything else that reads bytes,
see inside HTTPS.

This is the one feature here that makes a proxy *less* safe if it is
built carelessly, because it replaces a connection the client verified
end to end with two connections the client cannot see past. Three
things follow from that, and none of them is optional.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `ca_cert_file` | path | required | The signing certificate clients have to trust; it must be a CA with `keyCertSign` and must not have expired |
| `ca_key_file` | path | required | Its private key; refused, at validation and at load, if anybody but its owner can read it |
| `hosts` | list | `[]` (all) | Destinations to intercept: a name, `*.suffix`, an address or a CIDR; empty intercepts everything the listener allows, which warns |
| `bypass_hosts` | list | `[]` | Destinations never intercepted, whatever `hosts` says; checked first and wins |
| `verify_upstream` | bool | `true` | Verify the destination's own certificate with the ordinary rules; `false` warns loudly |
| `ca_file` | path | system store | Roots the destination is verified against |
| `min_version` | `1.2`\|`1.3` | `1.2` | Lowest TLS version the proxy speaks to the destination |
| `leaf_ttl` | duration | `24h` | Validity of an issued certificate; at most 720h |
| `max_cache` | int | `1024` | Issued certificates kept in memory; the oldest are dropped |
| `alpn` | list | `["http/1.1"]` | Offered to the destination and accepted from the client; `h2` warns |
| `yara` | object | none | Rules over the decrypted stream, with the same keys as everywhere else |

**The destination is verified first, and only then is a certificate
forged.** A client never sees a forged certificate for a server whose
own certificate did not verify — it sees the handshake fail, which is
what it would have seen with no proxy in the way. An interception proxy
that gets this backwards turns every verified connection through it
into an unverified one while leaving the padlock in place, which is
worse than not intercepting at all. `verify_upstream: false` exists as
a key so that turning it off is a decision somebody wrote down.

**The signing key can impersonate every site to every client that
trusts the CA.** It is refused if its mode allows anyone but its owner
to read it, both by `xproxy check` and at startup.

**Some traffic must not be read at all**, whatever the estate's policy
says: banking, health, anything carrying somebody's own credentials.
`bypass_hosts` is where that is written, and it is consulted before
anything is decrypted — a rule that another rule can overtake is not
that rule.

Two more things the proxy refuses rather than guesses. A tunnel whose
first bytes are not a TLS ClientHello is spliced through untouched:
CONNECT carries SSH, database protocols and anything else, and
answering a handshake to something that was not offering one breaks it
for no reason (`forward_intercept_passed`). And a handshake whose
server name disagrees with the host in the CONNECT is refused
(`forward_sni_mismatch`), because a tunnel opened to one name and a
handshake for another is somebody reaching a destination the policy
checked against a different one. A tunnel opened to an *address* is the
exception and not a hole: there the policy checked the address, the
bytes reach that address whatever the handshake says, and the name only
picks a virtual host once they arrive.

The issued certificate carries the *real* certificate's names — its
SANs, its IP addresses, its common name — so a client that pins a name
still works and one that pins a key still fails, as it should. The
cache is keyed on the name and on the real certificate's fingerprint,
so a destination that rotates its certificate gets a fresh forgery
rather than a stale one. `alpn` defaults to `http/1.1` alone: a stream
the proxy relays is one it has to be able to read, and offering `h2`
without parsing HTTP/2 is how an interception proxy breaks a site.

`socks5` tunnels on the same listener are intercepted by the same
rules: a destination reachable in either protocol on one port under one
policy is not a policy if one of the two walks past it.

An intercepted connection writes a `forward_intercept` access line with
the client, user, destination, negotiated ALPN and the TLS version
reached upstream. Counters: `forward_intercepted`,
`forward_intercept_refused`, `forward_intercept_passed` and
`forward_intercept_bytes`.

```yaml
- name: egress
  address: "0.0.0.0:3128"
  kind: forward
  forward:
    ports: [80, 443]
    auth: {users_file: /etc/xproxy/proxy.htpasswd}
    intercept:
      ca_cert_file: /etc/xproxy/mitm-ca.pem
      ca_key_file: /etc/xproxy/mitm-ca-key.pem
      hosts: ["*.example.com", "*.cdn.test"]
      bypass_hosts: ["*.bank.test", "*.health.test"]
      yara: {rules_dir: /etc/xproxy/yara}
```

#### MASQUE on a forward listener

HTTP `CONNECT` tunnels TCP, and that is all it tunnels. Everything else
an estate sends — DNS, QUIC, NTP, WireGuard, telemetry — either leaves
the network outside this policy or does not leave at all, and the first
is the usual answer. CONNECT-UDP (RFC 9298) is the same explicit proxy
for datagrams, with the same destination rules, credentials, logs and
bans; CONNECT-IP (RFC 9484) carries IP packets, which is how a MASQUE
VPN is built.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `udp` | bool | `false` | Accept `connect-udp` |
| `ip` | bool | `false` | Accept `connect-ip`; needs `ip_device`, `ip_assign` and `ip_routes` |
| `max_sessions` | int | `1024` | Concurrent MASQUE sessions on this listener; over it, 503 |
| `ip_device` | name | | An existing `tun` interface the operator created, addressed, routed and firewalled (Linux only) |
| `ip_assign` | list of CIDR | | The source addresses a client is told to use; a packet from anything else is dropped |
| `ip_routes` | list of CIDR | | The ranges a client may send to; a packet to anything else is dropped |

Both need **HTTP/2 or HTTP/3**, because an extended CONNECT carries a
`:protocol` pseudo-header that HTTP/1.1 has no way to express: the
listener needs `tls` with `h2` in its `protocols`. Datagrams travel as
capsules (RFC 9297) rather than HTTP datagrams — the fallback RFC 9298
requires, reliable and ordered, which for a proxy applying a policy to
each datagram is a feature: an unreliable path would make a refused
datagram indistinguishable from a lost one.

Every extended CONNECT is answered here, not only the two protocols
implemented: an unimplemented one gets 501 rather than falling through
to the ordinary `CONNECT` path, where a request carrying a path and no
authority would otherwise be treated as a TCP tunnel to whatever its
`:authority` said.

**CONNECT-IP needs a tunnel device**, and the proxy does not create
one. A userspace process cannot put an arbitrary IP packet on the wire;
a raw socket would need `CAP_NET_RAW`, would not receive the replies a
session needs, and would let a bug here forge any packet on the
network. A `tun` interface is the honest mechanism: the operator
creates, addresses, routes and firewalls it (`ip tuntap add mode tun
xproxy0`, and the rest), and the proxy only opens it. The network
policy of a VPN belongs to the host's configuration, not to this file.
Where no device is available the request is refused with 501 and a
reason in the error log rather than failing obscurely.

Packets are checked before forwarding: the source must be inside
`ip_assign` and the destination inside `ip_routes`, or the packet is
dropped and counted. That is the anti-spoofing rule, and it is why both
lists are required — a client that has not been told a source address
and a destination range has no business sending anything.

#### SOCKS5 on a forward listener

`socks5: true` accepts SOCKS5 on the same port as the HTTP proxy. The
two cannot be confused: a SOCKS greeting starts with the version byte
`0x05` and an HTTP request starts with a method, so the first byte
decides and nothing is configured twice.

Everything the HTTP side applies applies here: the port list, `allow`,
`deny`, `allow_private`, the checked address being the one dialled, the
tunnel bound, the idle timeout, the ban list and the counters. `auth`
is enforced with RFC 1929 username/password against the same users
file, sharing the same credential cache and the same bounded hashing —
so a listener with `auth` refuses a SOCKS client that offers only
"no authentication" (reply `0xFF`), and one without `auth` is an open
proxy for both protocols, which validation says out loud.

A policy refusal is answered with the closest SOCKS reply code rather
than a blanket failure: `0x02` (connection not allowed) for a port,
name, address or private-range refusal, `0x04` (host unreachable) for
a name that does not resolve. SOCKS4 is refused — it has no
authentication and no names — and `BIND` is not implemented, because it
asks the proxy to open a listening socket on a client's say-so.

**Why bother.** SOCKS5 is what everything that is not a browser speaks:
`ssh -o ProxyCommand`, `git`, `curl --socks5-hostname`, database
clients, package managers. Without it that traffic goes around the
proxy; with it, it is under the same destination policy, the same logs
and the same bans.

**UDP associations** (`socks_udp: true`) are how DNS and QUIC travel
through a SOCKS proxy. Each association binds its own socket, is fixed
to the client address that opened it (the first datagram sets it), only
relays answers from destinations that client has actually sent to, and
dies with its TCP control connection — which is what RFC 1928 requires
and what keeps the socket from becoming an open reflector. Datagram
headers are parsed with the same care as the handshake: fragments are
dropped rather than reassembled, and the peer table is bounded.
`forward_udp_associations`, `forward_udp_open` and
`forward_udp_dropped` count the association and everything refused.

Each request writes one `forward` line to the access log with the
client address, user, method, destination, status, bytes and duration.
SOCKS connections write the same line with `protocol: socks5`.
Counters: `forward_requests`, `forward_tunnels`, `forward_tunnels_open`,
`forward_denied`, `forward_auth_failed`, `forward_rejected`,
`forward_errors`, `forward_bytes_in`, `forward_bytes_out`,
`forward_socks`, `forward_udp_associations`, `forward_udp_open`,
`forward_udp_dropped`, `forward_intercepted`,
`forward_intercept_refused`, `forward_intercept_passed`,
`forward_intercept_bytes`;
`xproxy_forward_*` metrics. The policy and the users file reload; the
address and TLS settings need a restart like every listener.

### server.listeners[].dns (kind: dns)

A `kind: dns` listener is a forwarding DNS proxy on the listener address
over UDP and TCP. Queries are answered from a bounded cache when they
can be, refused or blocked by policy, and otherwise forwarded to the
upstream resolvers with a fresh transaction id on a fresh socket
(random source port) per query; the answer must echo the id and the
question. A truncated UDP answer is retried over TCP to the upstream,
and an answer larger than the client's UDP size (512 bytes or its EDNS
advertisement, honoured up to 1232 bytes per RFC 9715 so a spoofed
source cannot draw a large reply) is truncated so the client retries
over TCP. Only one
question per query and the QUERY opcode are handled (FORMERR and
NOTIMP otherwise); responses arriving as queries and packets from
banned clients are dropped. A dns listener takes `address`, `dns` and
optionally `tls`; bans and the global connection limits apply to TCP
clients as on every listener. The policy, upstreams and cache bounds
reload (the cache is kept); the address needs a restart.

With `tls` (certificates only, no ACME) the listener is encrypted: no
plain UDP is bound, the TCP port serves DNS over TLS (RFC 7858, ALPN
`dot` or none) and DNS over HTTPS (RFC 8484, ALPN `h2` or `http/1.1`)
at `doh_path`, chosen per connection by the negotiated protocol. The
same policy, cache and counters serve both; `queries_dot` and
`queries_doh` count them, and `xproxyctl tls` shows the certificate.
Run a plain listener on 53 and an encrypted one on 853 (and 443 when
browsers should use it) side by side.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `upstreams` | list | required | Resolvers tried in turn, rotating the first choice per query: `host:port` (UDP, TCP on truncation), `tls://host:port` (DNS over TLS, connections reused), `quic://host:port` (DNS over QUIC, RFC 9250, connection reused, id 0), `https://host[:port]/path` (DNS over HTTPS, POST `application/dns-message` with id 0) |
| `upstream_ca_file` | path | system pool | Pins the CA of `tls://` and `https://` upstreams; the host in the upstream string is the name verified |
| `upstream_resumption` | bool | `true` | Keep TLS session tickets for encrypted upstreams, so a reconnect resumes instead of running a full handshake. That handshake is most of what DoT and DoQ cost a resolver whose idle connection is dropped between queries. Nothing is replayable: the client offers no early data and DoQ keeps 0-RTT off. Turn it off for an upstream whose tickets are broken, or for a policy that forbids resumption. `upstream_resumed` counts the connections that resumed (`xproxy_dns_upstream_resumed_total`); DoH resumption happens inside the HTTP transport and is not counted separately |
| `timeout` | duration | `2s` | One upstream attempt; at most 30s |
| `allow_clients` | list of CIDR | `[]` (any) | Other clients get REFUSED |
| `block` | list | `[]` | `name` blocks the name and its subdomains, `*.suffix` subdomains only, `=name` that name only |
| `block_file` | path | none | Names added from a file: one per line, `#` comments, hosts file lines (`0.0.0.0 name`) accepted; read at load and reload, a missing file fails the reload; at most 2 million entries |
| `block_action` | `nxdomain`, `refuse`, `sinkhole` | `nxdomain` | A blocked query is a `dns_blocked` security event and ban reason whatever the action |
| `sinkhole_ipv4` | address | `0.0.0.0` | A answer for blocked names with `sinkhole` (TTL 60) |
| `sinkhole_ipv6` | address | `::` | AAAA answer for blocked names with `sinkhole`; other types get an empty answer |
| `cache.max_entries` | int | `10000` | LRU bound |
| `cache.min_ttl` | duration | `5s` | Floor applied to upstream TTLs |
| `cache.max_ttl` | duration | `1h` | Ceiling applied to upstream TTLs; at most 168h |
| `cache.negative_ttl` | duration | `60s` | NXDOMAIN and empty answers; 0 disables |
| `cache.serve_stale` | duration | `0` (off) | Keep an expired entry this much longer and serve it when the upstream has nothing (RFC 8767); at most 24h |
| `cache.stale_ttl` | duration | `30s` | The TTL a stale answer carries, so the client comes back soon; at most 5m |
| `cache.prefetch` | bool | `false` | Refresh a nearly expired entry when a query arrives for it |
| `cache.prefetch_threshold` | float | `0.1` | The share of the TTL that must be left for a query to start a refresh; at most 0.5 |
| `rate_limit` | `{qps, burst}` | none | Per client token bucket (defaults 50 and 100 when the section is present); over it queries are dropped, not answered |
| `max_in_flight` | int | `1024` | Queries being handled at once; beyond it UDP queries are dropped |
| `log_queries` | bool | `false` | One `dns` access log line per query (client, name, type, rcode, source, bytes, duration). Query logs are personal data; leave off unless needed |
| `doh_path` | path | `/dns-query` | DNS over HTTPS path on an encrypted listener; other paths answer 404 |
| `doq` | bool | `false` | Also serve DNS over QUIC (RFC 9250) on this listener's UDP port; see below |
| `discovery` | list | `[]` | Advertise this resolver's encrypted endpoints at `_dns.resolver.arpa` (RFC 9462); see below |
| `records` | list | `[]` | SVCB and HTTPS records this resolver answers itself; see below |
| `dnssec` | object | none | Validate answers; see below |
| `tunnel_detection` | object | none | Watch for data leaving inside the query names; see below |
| `answer_policy` | object | none | Screen where an answer points, not only what was asked; see below |
| `ecs` | `strip`, `forward` | `strip` | What happens to a client's EDNS Client Subnet option on the way upstream |
| `cookies` | `off`, `respond`, `require` | `respond` | DNS cookies (RFC 7873): see below |
| `cookie_lifetime` | duration | `1h` | How long a server cookie stays valid; at most 24h |

#### server.listeners[].dns.cache: serve-stale and prefetch

Two settings about what happens at the edges of a TTL, and neither
changes what is cached -- only when the cache is allowed to answer.

**`serve_stale`** (RFC 8767) keeps an expired entry for that much longer
and serves it when the upstream has nothing to say. It is the difference
between a resolver outage taking the network with it and a resolver
outage nobody notices for an hour: the answer is out of date by
definition, and a name almost always still resolves where it did a
minute ago, while a client that cannot be told anything cannot reach the
upstream itself either. A stale answer carries `stale_ttl` (30 seconds by
default, RFC 8767's recommendation) rather than the TTL the zone
published, so the client comes back soon instead of keeping an answer
this resolver already knows is old. It is counted as
`xproxy_dns_stale_total` and logged with `source=stale`, so an operator
can see that a resolver is running on stale answers rather than
discovering it later.

A stale entry is not a cache hit: the upstream is asked first, every
time, and the expired answer is used only when that produced nothing.
This proxy waits out the whole upstream budget before falling back,
rather than RFC 8767's optional short client-response timeout -- a
slower answer that is current beats a fast one that is not.

"Nothing to say" means no answer at all, and also a SERVFAIL when
`dnssec` is off. With validation on a SERVFAIL is the code a resolver
returns for an answer it *rejected*, and covering that with an expired
answer of our own would undo the validation: the client would be handed,
as a last resort, exactly the answer somebody decided not to trust. So
with `dnssec` on, only an upstream that answers nothing at all falls
back to stale.

**`prefetch`** refreshes an entry when a query arrives for it and less
than `prefetch_threshold` of its TTL is left, so a popular name is
answered from the cache continuously instead of one client per TTL
waiting for the upstream. The client that triggered it is answered from
the cache immediately and waits for nothing.

The refresh is claimed on the cache entry itself, so a burst of queries
for the same nearly-expired name starts one refresh and not a hundred --
which is the stampede this setting exists to prevent and would otherwise
cause. Refreshes have a budget of their own (64 at a time) rather than a
share of `max_in_flight`: a resolver that answered clients more slowly
because it was busy refreshing would have the feature backwards. A
refresh that comes back with nothing, or with an answer validation
rejects, leaves the entry as it was to expire or be served stale on its
own terms. `xproxy_dns_prefetch_total` counts the refreshes started.

The two work well together: `prefetch` keeps the names that are in use
current, and `serve_stale` covers the ones that are not when the
upstream goes away.

#### server.listeners[].dns.answer_policy

A block list decides by name, and the name is the part an attacker picks
last: blocking one costs them a registration. The address in the answer
is the part they cannot move, because it is where they want the client to
go. Two attacks live entirely in that gap, and neither is a bad name.

**DNS rebinding.** A name the attacker owns answers with a public
address while the page loads and with `127.0.0.1` or `10.0.0.5` a second
later. The browser's same-origin policy keeps treating the two answers
as one origin, so the page reads whatever is listening on the loopback
interface of the machine that opened it — a development server, a
printer's admin page, a container's unauthenticated API.

**The metadata endpoint.** Every cloud provider serves instance
credentials at `169.254.169.254` to any process that can make an HTTP
request. A name that resolves there turns "fetch this URL for me" into
"read my keys", which is how a server-side request forgery becomes a key
compromise. Blocking the name does nothing: the next one is free.

`answer_policy` screens the answer section of every upstream reply and
of every cache hit, before the answer is cached and before it is sent.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `deny_private` | bool | `true` | Deny every range RFC 6890 calls not globally reachable, and the IPv4-mapped IPv6 range with them (see the list below) |
| `deny` | list of CIDR | `[]` | Further ranges to refuse, in either family |
| `allow` | list of CIDR | `[]` | Carved back out of the denied set: the ranges this network really does resolve names into |
| `allow_names` | list | `[]` | Names allowed to point into a denied range, in the forms `block` takes |
| `action` | `nxdomain`, `refuse`, `servfail`, `strip` | `nxdomain` | What a denied answer becomes |

A section that denies nothing — `deny_private: false` with an empty
`deny` — is refused at load. It reads like rebinding protection and is
not one, and the operator who wrote it meant to get something for it.

`deny_private` stands for `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`,
`127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.0.0.0/24`,
`192.0.2.0/24`, `192.168.0.0/16`, `198.18.0.0/15`, `198.51.100.0/24`,
`203.0.113.0/24`, `224.0.0.0/4`, `240.0.0.0/4`, `255.255.255.255/32`,
`::/128`, `::1/128`, `::ffff:0:0/96`, `100::/64`, `2001:db8::/32`,
`fc00::/7`, `fe80::/10` and `ff00::/8`.

The IPv4-mapped range earns its place: an AAAA record may hold
`::ffff:127.0.0.1`, which is not inside `::1/128` and which every socket
API connects to `127.0.0.1` anyway. Screening unmaps an address before
testing it and keeps the range denied as well, so the address is caught
whichever way it was written. 6to4 (`2002::/16`) and Teredo
(`2001::/32`) embed an IPv4 address the same way and are deliberately
not in the list: reaching the embedded address takes a relay most
networks do not have, and denying them by default would refuse names
that resolve legitimately. Add the two prefixes to `deny` on a network
that does carry them.

Both the name asked for and the owner name of the record are matched
against `allow_names`, so a public name that is a CNAME into an internal
zone is covered by exempting either end.

`action` is about what the client is left with:

- `nxdomain` (the default) and `refuse` say the name has no answer here.
  Nothing is cached, so the policy is re-applied to the next query
  rather than frozen into the cache.
- `servfail` says the resolver would not stand behind the answer, which
  is what a resolver says about an answer it rejected.
- `strip` removes the denied records and keeps the rest, for the name
  that legitimately has a public address as well as an internal one: a
  split-horizon zone seen from the wrong side, an appliance that
  publishes its management address beside its service address. What is
  left may be an answer with no addresses in it, which is a NODATA and
  the correct thing to say — the name exists and has nothing this client
  may be told. The stripped answer is what the cache keeps, so the
  removed address does not come back on the next query. Records whose
  set lost a member have their RRSIGs removed with them: a signature
  over a set one record short does not verify, and a client that checked
  it would call the answer bogus rather than short.

Only the answer section is screened. Glue in the additional section is a
resolver's business — a stub client connects to what it was answered,
not to what the delegation mentioned — and a delegation whose name
servers sit on private addresses is ordinary in a split network, so
screening glue would refuse names that work. Names this listener answers
itself (`records`, `discovery`) and sinkhole answers are not screened
either: they are this proxy's own answers, and `sinkhole_ipv4: 0.0.0.0`
is deliberately inside a denied range.

A denied answer raises the `dns_answer_denied` security event with the
address that tripped it, counts `xproxy_dns_answer_denied_total`, and is
available as a ban reason. `strip` counts
`xproxy_dns_answer_stripped_total` and is not a refusal: the client got
an answer.

The screen also runs on the way out of the cache, not only on the way
in, because a reload can deny a range that an entry already in the cache
points into. Such an entry is dropped rather than served.

#### server.listeners[].dns.cookies

A UDP datagram proves nothing about where it came from, and everything
unpleasant about an open resolver follows from that: an answer sent to an
address that did not ask, a small question drawing a large reply for
somebody else's link, a cache poisoned by a race the attacker enters with
no packets of their own to lose, and a security event recorded against an
address chosen by whoever sent the packet.

A DNS cookie (RFC 7873, with RFC 9018's server cookie layout) fixes the
one thing underneath all of them: it makes the client prove it can
*receive* what it asked for. The client sends eight bytes of its own; the
server returns them with a keyed hash over the client's address and those
bytes, and expects that back next time. Nothing about it is secret and
nothing about it is authentication — an on-path attacker sees the cookie
— but an off-path one cannot produce it for an address it does not hold,
which is exactly the attacker every item above depends on.

- `respond` (the default) answers a client that sent a cookie with one,
  and treats a cookie this listener issued as proof of the address. It
  never refuses a query for the want of one, so a client that has never
  heard of cookies is unaffected.
- `require` additionally refuses a UDP query that carries no valid
  cookie: BADCOOKIE (rcode 23) with a fresh cookie, so a cookie-aware
  client retries once and succeeds, and nothing is looked up for the
  first attempt — which is the whole saving. A client that sends no
  COOKIE option at all gets REFUSED, because there is nothing to echo and
  no retry to invite. **That breaks every client that does not implement
  cookies, which is most stub resolvers**; validation warns about it on a
  listener with no `allow_clients`. It belongs on a listener whose
  clients are known.
- `off` ignores cookies entirely, which is also how to avoid the small
  cost below.

A stream transport is exempt from `require`: the peer completed a
handshake to get here, which is what a cookie exists to establish (RFC
7873 section 5.2.3). A cookie is still echoed over TCP, DoT, DoH and
DoQ, so a client can collect one there and use it over UDP.

**What a verified cookie buys.** A security event from a UDP query is
normally not attributed to the address the datagram claims — counting it
towards a ban would let anybody have a third party banned by spoofing
them, and logging one per datagram is a log flood at packet rate — so
those events are aggregated and attributed to nobody. A UDP query
carrying a cookie this listener issued *has* completed a round trip, so
its events are attributed and can drive a ban like a TCP client's.
Turning cookies on is therefore what makes `dns_blocked` and
`dns_tunnel` bans work for UDP clients.

`cookie_lifetime` (1h by default) is how long a server cookie stays
valid. A cookie past half its life is replaced in the answer, so a client
that keeps asking never reaches the end of one. The secret is per
listener and per process: it is never written anywhere, so a restart
costs each client one extra round trip, and two nodes of a cluster do not
accept each other's cookies — a client moving between them also costs one
BADCOOKIE round trip and then works.

`xproxy_dns_cookies_total` counts the exchange by result (`issued`,
`verified`, `refused`), and the refusals appear as `cookie_required`,
`cookie_missing` and `cookie_malformed`.

**The cost.** Putting a cookie into a response means rebuilding the
message, which loses the name compression the upstream used, so a
cookie-carrying client's answers are a little larger and a large answer
is a little more likely to be truncated into a TCP retry. The cookie's
own space is reserved before that decision, so the datagram is never
oversize — but on a listener where this matters, `cookies: off` is the
setting.

#### server.listeners[].dns.ecs

EDNS Client Subnet (RFC 7871) lets a resolver tell an authoritative
server which network a query is really for, so the answer can be the one
nearest the client. It exists for a recursive resolver talking to a
content network, and this listener is neither: it forwards to a resolver
that adds its own option describing this proxy, which is the correct
thing for that resolver to describe.

Forwarding a client's own option breaks the cache instead. The cache key
here is the question — name, type and class — and nothing else, as it is
in every forwarder of this shape. An answer tailored to one client's
subnet is therefore stored for every client of the listener: one client
asking for a name on behalf of `203.0.113.0/24` decides which address
the next thousand get. A client that can pick the subnet can pick the
answer, which is cache poisoning with no spoofing and no race in it, and
it is also a way to have this proxy ask an upstream about somebody
else's network a query at a time.

So `ecs: strip` (the default) removes the option from the forwarded
query and counts `xproxy_dns_ecs_stripped_total`. The rest of the OPT
record — a cookie, padding, anything else the client sent — is kept:
dropping the record wholesale would forward a different query than the
one the client asked. `ecs: forward` passes the option through, and is
for the deployment whose clients are one network. With `dnssec` on the
option is gone regardless, because validation replaces the OPT record
with one of its own.

#### server.listeners[].dns.tunnel_detection

DNS tunnelling is the oldest way out of a network that filters
everything else, and it still works, because a resolver is usually the
one thing every host may talk to. The payload goes up in the query name
— a few dozen encoded characters per label — and comes back down in the
answer, most often TXT. The tunnel's domain is delegated to the other
end, so every query reaches them whatever this resolver forwards to:
blocking the upstream does nothing, and a block list only helps if
somebody already knew the name.

What gives it away is not any one query but the shape of a client's
traffic under one registered domain: names carrying more information per
character than words do, hundreds of distinct subdomains where a service
has a handful, answers that are mostly TXT, and a high rate of NXDOMAIN
from the probing and the encoding that produce names nothing resolves.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `window` | duration | `5m` | The period the signals are measured over; 10s to 1h |
| `min_queries` | int | `50` | Queries a client must send under one domain before any judgement; below it there is not enough to be wrong about |
| `min_signals` | int | `2` | How many signals must fire together; `1` warns |
| `entropy` | float | `3.6` | Bits per character at which a label counts as encoded rather than named; words sit below it, base32 and base64 run near 5 and 6 |
| `entropy_share` | float | `0.5` | Share of a domain's queries that must reach it; an explicit `0` switches the signal off |
| `min_label_length` | int | `12` | Shortest label measured; a short string's entropy is mostly noise |
| `distinct_subdomains` | int | `50` | Cardinality under one domain that belongs to a tunnel rather than a service; `0` switches the signal off |
| `txt_share` | float | `0.5` | Share asking for the types a tunnel returns data in (TXT, NULL, CNAME, MX, SRV); `0` switches the signal off |
| `nxdomain_share` | float | `0.5` | Share answering NXDOMAIN; `0` switches the signal off |
| `payload_bytes` | int | `4096` | Encoded bytes below the domain in a window, counting each name once; `0` switches the signal off |
| `allow_domains` | list | `[]` | Never judged, in the same forms as `block` |
| `action` | `log`\|`block` | `log` | `block` answers NXDOMAIN for the detected domain, for the client it was detected for, until the cooldown ends |
| `cooldown` | duration | `10m` | How long that lasts, and how long before the same domain is reported again |
| `max_tracked` | int | `65536` | Windows held; 64 to 10000000 |

**No single signal decides**, and that is the point of `min_signals`.
Each one alone has honest traffic behind it: a content delivery
network's hostnames really are random, a reputation service really does
encode a hash into a name and answer TXT, and a laptop waking up really
does produce a burst of NXDOMAIN. What does not happen by accident is
several of them at once, under one registered domain, from one client.
Setting `min_signals: 1` is allowed and warns, because it turns each of
those into a false positive.

Any of the five can be switched off by writing `0` against it, and a
`0` written there means off: the keys that take one are read through a
pointer so that an explicit zero is not mistaken for an absent key and
quietly given its default back. A policy that switches signals off and
still asks for more agreement than it has left is refused at load rather
than silently never firing.

Queries are grouped by the name somebody registered — the last two
labels, or three under a known registry suffix like `co.uk` — so a
thousand subdomains of one tunnel domain count together rather than as a
thousand unrelated names. A query for the registered name itself is not
measured: there is nothing below it to carry a payload.

`payload_bytes` counts each name once per window. Asking for the same
long name twice carries no second copy of anything — it is a cache miss,
not an export — and counting it would turn any client that polls a long
name into an exfiltration of megabytes. That is what keeps this signal
independent of the entropy one rather than a second reading of it.

Every answered query is measured, whatever answered it: from the cache,
refused, or failed upstream. A detector that only saw the queries
reaching an upstream would be one a client could hide from by being
noisy.

`max_tracked` is not a tuning knob. The table is keyed on a client and a
domain and both are chosen by whoever sends the queries, so the bound is
what stops the detector being the denial of service it exists to catch.
Windows that have gone quiet are dropped first; when every window is
live, further queries go unmeasured and are counted as such
(`dns_tunnel_tracked`, and the evictions in `xproxyctl dns`).

A detection is a `dns_tunnel` security event naming the domain, the
signals that fired, the queries and the bytes — and `dns_tunnel` is a
ban reason, so a trigger can act on it. Counters: `dns_tunnels`,
`dns_tunnel_blocked`, `dns_tunnel_tracked`; `xproxy_dns_tunnel*` metrics.

```yaml
dns:
  upstreams: ["9.9.9.9:53"]
  tunnel_detection:
    action: log
    allow_domains: ["*.avts.mcafee.com", "*.spamhaus.org", "*.sophosxl.net"]
```

#### server.listeners[].dns.doq

DNS over QUIC. DoT and DoH both carry DNS over TCP, so they inherit its
head-of-line blocking: one slow answer holds up every query behind it
on the same connection, which is precisely the shape of a resolver's
traffic. DoQ puts each query on its own QUIC stream, so the answers are
independent, while keeping DoT's privacy properties — the same
certificate, the same server name, no HTTP layer.

It shares the listener's address and certificate, on UDP where DoT and
DoH use TCP, and is separated from HTTP/3 by its ALPN (`doq`). Each
stream carries one query and one answer with a two byte length prefix,
as over TCP. The message id is zero on the wire, which RFC 9250
requires: the stream identifies the exchange, so an id would only leak
something about the client. `queries_doq` counts them.

`quic://host:port` is the matching upstream transport, so a chain of
resolvers can be QUIC end to end.

#### server.listeners[].dns.discovery

Discovery of Designated Resolvers (RFC 9462). A client handed this
proxy's address by DHCP has no way to know it also speaks DoT, DoH or
DoQ. DDR is the answer: the client asks `_dns.resolver.arpa` for SVCB
records, this resolver answers with its own encrypted endpoints, the
client verifies the certificate against the name in the record, and
upgrades itself. Nothing is configured on the client.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `transport` | `dot`, `doh`, `doq` | required | Which encrypted transport this entry advertises |
| `name` | name | required | The name the endpoint's certificate covers; a client that cannot verify it stays on plaintext rather than trusting the record |
| `port` | int | 853 (`dot`, `doq`), 443 (`doh`) | The endpoint's port |
| `doh_path` | URI template | `/dns-query{?dns}` | For `doh`; RFC 9461's `dohpath` parameter |
| `ipv4`, `ipv6` | lists of addresses | `[]` | Address hints, so a client need not resolve the name it was just handed |
| `ttl` | int | `300` | TTL of the records |

Entries are advertised in the order listed: the first gets priority 1,
which is what a client prefers. The verification is the point — a
record that names a certificate this endpoint cannot present makes
clients fall back to plaintext, so the name has to be one the listener
really serves.

#### server.listeners[].dns.records

Records this resolver answers itself, without asking an upstream. Two
things need them: ECH — a client cannot encrypt its ClientHello until it
has read the `ech` parameter from an HTTPS record, so an estate running
its own resolver publishes it here — and split horizon, where a name
resolves to an internal address for the clients a view covers.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | name | required | The name the record is published for |
| `type` | `https`, `svcb`, `a`, `aaaa`, `txt`, `ptr` | `https` | Record type |
| `address` | IP | required for `a`, `aaaa` | The address. The family must match the type: an `a` record holding an IPv6 address is one no client can read, so it is a load error |
| `text` | string | required for `txt`, `ptr` | The string of a `txt` record (1 to 255 bytes, one character string), or the name a `ptr` record points to |
| `priority` | int | `0` | `svcb`/`https` only: 0 is an alias record (no parameters); 1 and up are service records, lowest first |
| `target` | name | `.` | `svcb`/`https` only: the endpoint name; `.` means the owner name itself |
| `ttl` | int | `300` | Seconds |
| `params` | mapping | `{}` | `svcb`/`https` only: service parameters in presentation form: `alpn: "h3,h2"`, `port: "443"`, `ech: "AEr+DQ..."` (the value `xproxyctl ech keygen` prints), `ipv4hint`, `ipv6hint`, `dohpath`, `mandatory`, `no-default-alpn`, or `keyNNNNN` for one this build does not name |

`target`, `params` and `priority` belong to `svcb` and `https` records and
`address`/`text` to the others; a record mixing them is a load error rather
than a record that loads ignoring half of itself.

A name listed here is **owned**: it is answered from this set and never
forwarded, and a type it does not have gets NOERROR with no answers
rather than an upstream lookup, because a forwarded answer would
contradict the local one. Answers carry the AA bit. `queries_local`
counts them and `xproxyctl dns` lists the names.

#### server.listeners[].dns.dns64

RFC 6147 address synthesis: an AAAA answer for a name that has only an A
record, so an IPv6-only client can reach an IPv4-only service through a
translator.

The client asks for AAAA, the name has none, and this resolver asks for A
instead and answers with that IPv4 address embedded in a prefix (RFC 6052)
routed to the translator. Nothing on the client changes — it believes it is
speaking IPv6 throughout, which is the point.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `prefix` | IPv6 CIDR | `64:ff9b::/96` | The translation prefix. A network-specific prefix must be a `/32`, `/40`, `/48`, `/56`, `/64` or `/96` — the only lengths RFC 6052 gives a place to put the address — with no bits set past its length |
| `clients` | list of IPv6 CIDR | every client | The networks this applies to. Name the IPv6-only ones: a dual-stack client handed a synthesised address reaches the service through the translator for no reason. An IPv4 network here is a load error, since a client with IPv4 does not need the translation |
| `ttl` | int | the A record's | Override the TTL of a synthesised record |

Two things about it are security decisions rather than protocol, and both
are worth knowing before turning it on.

**The address policy sees the IPv4 address, not the synthesised one.**
`64:ff9b::7f00:1` is not inside `127.0.0.0/8` and no prefix list would
catch it, but it is `127.0.0.1` to everything past the translator. So the A
lookup runs through the ordinary path — the same one a client's own A query
takes — which screens it against `answer_policy` and caches it; an address
that policy denies is not embedded. Without that, DNS64 would be a way
around rebinding protection rather than a feature beside it.

**A synthesised answer is never signed and never says it is.** The reply is
built from the client's question, so the AD bit is clear by construction
(RFC 6147 section 5.5). A validating client that wants the truth about the
name asks for A itself, which this resolver answers and validates
normally.

A name with an AAAA record of its own is answered with it, and a name that
does not exist stays NXDOMAIN: synthesising over either would be this
resolver inventing a second answer. At most 32 records are synthesised from
one A answer, so an upstream with hundreds of addresses does not decide the
size of this listener's reply. `queries_synthesised` counts them
(`xproxy_dns_synthesised_total`) and the access log source ends in
`:dns64`.

#### server.listeners[].dns.views

Split horizon: the same name answered differently by who asked.

One name with two answers is an ordinary requirement rather than a trick.
`app.example.com` is a private address from inside the estate and a public
one from outside; a laboratory network resolves a name to the test system
while everybody else reaches production; a guest network is held to a
stricter block list than the staff network. Without views the answer is two
resolvers on two addresses and a routing decision somewhere else.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | name | required | Identifies the view in the access log (as `view`) and in `xproxyctl dns` |
| `clients` | list of CIDR | required | The networks this view serves. **The first view whose networks contain the client wins**, so the order of the list is the policy. A view with no networks is refused: one that matched everybody would be the listener's own policy under another name |
| `records` | list | the listener's | Replaces the listener's record set while this view is selected (same shape as `dns.records`) |
| `block`, `block_file` | list, path | the listener's | Replaces the listener's block list |
| `block_action` | `nxdomain`, `refuse`, `sinkhole` | the listener's | What a block answers in this view |
| `sinkhole_ipv4`, `sinkhole_ipv6` | IP | the listener's | The addresses of this view's own `block_action` |

A view must change something — records, a block list or a block action —
or it is a section an operator wrote expecting something for it, and that
is a load error.

**A view has no upstream of its own, on purpose.** Two views with
different upstreams would answer the same question differently out of one
shared cache, and a cache per view is a second resolver with a second
memory — which is a second listener, said plainly in the configuration,
rather than hidden inside a view. So a view decides only what this
resolver settles before it asks anything: the records it answers itself
and the names it refuses. That is also why the cache cannot leak one
view's answer to another client — a local answer is never cached, and a
block is decided before the cache is read.

```yaml
views:
  # Order matters: the laboratory is inside 10.0.0.0/8 too.
  - name: lab
    clients: [10.9.0.0/16]
    records:
      - {name: app.example.com, type: a, address: 10.9.0.20}
  - name: estate
    clients: [10.0.0.0/8, 192.168.0.0/16]
    records:
      - {name: app.example.com, type: a, address: 10.0.5.10}
      - {name: app.example.com, type: aaaa, address: "2001:db8::5"}
  - name: guest
    clients: [192.168.50.0/24]
    block_file: /etc/xproxy/guest-blocklist.txt
    block_action: sinkhole
    sinkhole_ipv4: 192.0.2.1
```

`queries_viewed` counts the queries a view answered
(`xproxy_dns_viewed_total`), and the access log line carries `view` for
them (and nothing for a client in no view).

#### server.listeners[].dns.rpz

Response policy zones: the file format a DNS threat feed actually ships
in.

`block` and `block_file` take a flat list of names, which is what an
operator writes by hand. A feed publishes a zone file instead, and the
policy is in the records — so one file says "this name does not exist",
"this one answers 10.0.0.1" and "this one is an exception", and the file
is transferred and diffed by tools that already exist. Reading it here
means a subscription is dropped in rather than converted every hour by a
script somebody wrote once and nobody owns.

```yaml
server:
  listeners:
    - name: resolver
      kind: dns
      address: "0.0.0.0:53"
      dns:
        upstreams: ["tls://1.1.1.1:853"]
        rpz:
          # How often a zone file's size and modification time are
          # checked. 0 means never, and then a reload picks a feed up.
          refresh: 5m
          zones:
            # Order is the policy: the first zone with a rule for the
            # name decides, so the estate's own exceptions go first and
            # nothing below can take them back.
            - name: our-own
              file: /etc/xproxy/rpz/exceptions.rpz
            - name: malware-feed
              file: /var/lib/xproxy/rpz/malware.rpz
            - name: new-feed
              file: /var/lib/xproxy/rpz/trial.rpz
              # Every rule of this zone becomes this action, which is how
              # a feed is tried out before it is trusted.
              action: passthru
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `refresh` | duration | `5m` | How often a zone file's size and modification time are checked; at least 10s, or `0` for never |
| `zones[].name` | name | required, unique | Identifies the zone in the access log, the security log and `xproxyctl dns` |
| `zones[].file` | path | required | The zone file, in the master format a feed publishes |
| `zones[].action` | `zone`, `nxdomain`, `nodata`, `passthru`, `drop`, `tcp_only` | `zone` | Replaces every rule's own action; `zone` honours the file |
| `zones[].ignore_unsupported` | bool | `false` | Load a zone that carries a trigger this resolver does not implement, skipping those rules and counting them |

**The records, and what each one means.** A rule is written as the name
with the zone's own name after it (`evil.example.rpz.local` in a zone
whose origin is `rpz.local`), and that suffix comes off before the rule
is matched:

| Record | Action |
|--------|--------|
| `CNAME .` | NXDOMAIN: the name does not exist |
| `CNAME *.` | NODATA: it exists and has nothing of the type asked for |
| `CNAME rpz-passthru.` | An exception: the query is answered normally |
| `CNAME rpz-drop.` | No answer at all, counted as a drop |
| `CNAME rpz-tcp-only.` | Truncated over UDP, so the client retries over TCP; refused if it is already TCP |
| `A`, `AAAA`, `TXT` | Local data: this answer instead of the upstream's |
| `CNAME name.example.` | Local data: the CNAME is answered, and the client resolves the target itself |

A wildcard rule (`*.evil.example…`) covers the names *under* one and not
the name itself, and matching is what a zone lookup does: the name, then
a wildcard on each parent, longest first. So `good.bank.example CNAME
rpz-passthru.` is an exception for that host while `*.bank.example CNAME
.` still denies everything else below it — and, as in any zone, a rule
without a wildcard covers that one name and nothing under it.

`$ORIGIN` and `$TTL` are read, an `SOA` and `NS` records say whose zone
it is rather than being rules, and the zone's apex carries neither. A
record continued over lines in parentheses is refused rather than half
read: a feed writes one record per line, and a reader that guesses at the
rest applies a rule nobody wrote. A file with neither an `$ORIGIN` nor an
SOA owner of its own — which a plain download of a feed sometimes is — is
read as a list of absolute names.

**The triggers this does not implement**, and a zone carrying one fails
the load naming it: `rpz-client-ip`, `rpz-ip`, `rpz-nsdname` and
`rpz-nsip` select on the client, on the addresses inside an answer, and
on the name servers of the delegation — the last two needing the resolver
to police a path this one forwards. `ignore_unsupported: true` loads such
a zone without those rules and counts them (`xproxyctl dns` shows the
tally), which is a decision to make deliberately rather than a default,
because a policy that half applies is one the operator believes is
working. Where the addresses in an answer are the concern,
`answer_policy` screens them already, and by range rather than by feed.

A zone file that cannot be read or parsed **fails the load**, and so
does a reload: a policy zone that silently matches nothing is worse than
none, because the operator believes the feed is in force. A file that
disappears or stops parsing *after* the load keeps the rules already
read and says so in the error log, since a feed being rewritten in place
must not empty the policy for the moment that takes.

Every decision writes a security event (`dns_rpz`, with the zone, the
rule and the action) and a deny event under the `dns_rpz` reason, which a
ban trigger can name: a client walking a feed's names is one to stop at
the edge. `rpz_matched` and `rpz_passthru` are in `xproxyctl dns` with
the zones, their rule counts and when each was read
(`xproxy_dns_rpz_total{result="acted"|"passthru"}`,
`xproxy_dns_rpz_rules`).

#### server.listeners[].dns.dnssec

With the section present the listener is a validating resolver in front
of its upstreams: every upstream query carries the DO bit, and each
answer is checked before it reaches the client or the cache. Positive
answers need a verified RRSIG on every RRset, chained through DNSKEY
and DS records up to a trust anchor; negative answers need a verified
NSEC or NSEC3 proof (NXDOMAIN, NODATA, wildcard, opt-out); an insecure
delegation proven by the parent makes answers below it insecure. The
outcome shapes the answer: secure answers carry AD when the client set
AD or DO, bogus answers become SERVFAIL (a `dns_bogus` security event)
unless the client set CD, insecure and indeterminate answers pass
without AD. Clients without DO never receive RRSIG, NSEC or NSEC3
records. Algorithms 5, 7, 8, 10, 13, 14 and 15 and DS digests 1, 2 and
4 are supported; a zone signed only with others counts as insecure (RFC
4035). DNSKEY and DS lookups go to the same upstreams and are cached per
zone until the shorter of their TTL and signature validity, bounded to
10000 zones. `xproxyctl dns` shows secure, insecure, bogus and
indeterminate counts, the key cache size and lookups.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Switch for the section |
| `trust_anchors` | list | the IANA root keys (KSK-2017 20326, KSK-2024 38696) | DS records as `zone keytag algorithm digesttype digest` (`IN DS` accepted); setting any replaces the built-in list |
| `trust_anchors_file` | path | none | More DS lines from a file (`#` comments), read at load and reload |
| `max_lookups` | int | `48` | DNSKEY and DS queries per answer (4 to 1000); beyond it the answer is bogus |
| `aggressive_nsec` | bool | `false` | Answer a sibling of a name a validated NSEC record already placed in an empty gap without asking the upstream again (RFC 8198) |
| `nsec_entries` | int | `8192` | Parents whose proofs are remembered (0 to 1000000); the oldest is dropped past it |

With `aggressive_nsec` a validated NXDOMAIN is not just an answer to one
question: the NSEC record that proved it names a gap in the zone, and
every name in that gap does not exist either. The resolver keeps the gap
and answers the next name inside it from the proof it already has, which
is what RFC 8198 is for. The traffic it saves is the traffic that
produces it -- a random-subdomain flood, or junk queries under a
top-level name -- where each name is a sibling of the last and one signed
proof covers them all.

It is narrowed twice on purpose:

- A gap is reused only for a **sibling** of the name it was collected
  for: the same parent, therefore the same closest encloser, therefore
  the same wildcard denial the validator already checked. A name deeper
  or elsewhere in the zone needs its own proof, because a wildcard that
  covers it may exist without covering the name the gap came from.
- Only for a client that did **not** set DO. A synthesised NXDOMAIN
  carries no signatures, and a client that asked for the proof should
  get the proof; it goes upstream. A client that set CD does too.

Only NSEC is used. NSEC3 hashes the owner names, so the gap says nothing
about which names it holds without re-hashing each candidate, and an
opt-out gap does not deny existence at all. Gaps are held for the
shorter of the NSEC record's TTL and `cache.max_ttl`, keyed by the
parent name, and `nsec_entries` parents are kept at most; `xproxyctl dns
purge` empties the store with the caches, since a gap left behind would
deny a name the cache no longer has anything to say about. `xproxyctl
dns` shows `queries_nsec` (answers served from a held proof) and
`denials_held`; the metrics are `xproxy_dns_nsec_denied_total` and
`xproxy_dns_denials_held`.

`GET /v1/dns` and `xproxyctl dns` show per listener counters (queries,
cache hits and entries, blocked, refused, dropped, SERVFAIL, truncated,
upstream failures); `DELETE /v1/dns` and `xproxyctl dns purge` empty
the caches. Metrics: `xproxy_dns_*{listener}`.

### server.listeners[].smtp (kind: smtp)

A `kind: smtp` listener is a protocol-aware SMTP proxy. It speaks one
session to the client and a second one to the upstream, and decides for
itself where every command and every message ends, writing each one out
again rather than passing bytes through. That is the whole point of it:
a layer 4 splice carries the same octets, but then the client and the
mail server each parse them on their own, and every SMTP smuggling bug
there has ever been lives in the gap between two such parses.

What follows from that:

- A line must end with CRLF. A bare LF is refused (`bare_newlines:
  reject`) or repaired to CRLF (`convert`); a bare CR inside a line is
  always refused. Either way the two ends see the same line structure.
- The end of a message is `CRLF.CRLF` and nothing else, decided once,
  on the stream the proxy itself writes. Dot stuffing is passed through
  untouched, so only the terminator is interpreted.
- `CHUNKING` and `BDAT` are never advertised or relayed: BDAT carries a
  length instead of a terminator, so relaying it would put the decision
  back in two places.
- A reply the proxy cannot parse is never passed on. The client gets
  `421` and the session ends, because a reply the proxy did not
  understand is exactly the one the client would read differently.
- Anything pipelined behind `STARTTLS` ends the session with `554`
  (`starttls_injection`, a `smtp_denied` ban reason). Those octets were
  written before the client could see the `220`, so they were meant to
  be plaintext for one side and ciphertext for the other —
  CVE-2011-0411. After the handshake the session forgets its greeting
  and its authentication, as RFC 3207 section 4.2 requires, and the
  upstream leg is reset with it.

The listener takes `address`, `smtp`, and `tls` when a TLS mode needs a
certificate; `proxy_protocol` works as on an HTTP listener. Bans and the
global connection limits apply at accept. Changing the `smtp` section
rebinds the listener on reload.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `upstream` | upstream | required | The mail server pool. Endpoints are picked with the upstream's balancer, dial failures try the next and feed outlier ejection |
| `tls_mode` | `starttls`, `implicit`, `none` | `starttls` with `tls`, else `none` | How the client reaches the listener: upgraded by the STARTTLS command (25, 587), TLS from the first octet (465, RFC 8314), or never. `starttls` and `implicit` need the listener's `tls` |
| `require_tls` | bool | `true` when a TLS mode is set | Refuse AUTH (`538`), MAIL and VRFY (`530`) until the session is encrypted. This is the difference between offering TLS and requiring it |
| `require_auth` | bool | `false` | Refuse MAIL (`530`) until the session has authenticated. A submission listener wants this; a listener taking inbound mail has no authentication to require |
| `banner` | string | none | Replace the upstream greeting. Without it, every prober learns which mail server is behind this address, version and all |
| `hostname` | name | the banner's first word, else `xproxy` | The name the proxy gives in its own EHLO to the upstream |
| `max_command_line` | int | `512` | Command line including CRLF, the bound of RFC 5321 section 4.5.3.1.1; 64..4096. Over it: `500` and the session ends, with the rest of the line consumed so its tail is never read as a command |
| `max_text_line` | int | `1000` | Message line including CRLF; at least `max_command_line`, at most 1048576 |
| `max_message_size` | int | `0` (the upstream's own limit) | One message in octets, advertised as `SIZE` and replacing the upstream's. A `SIZE=` on MAIL over it is refused before the body is sent; a body that runs over it is refused with `552` and the upstream connection is dropped without its terminator, so a truncated message is never delivered as a whole one |
| `max_recipients` | int | `100` | RCPT commands per message; over it `452` |
| `max_messages` | int | `100` | Messages per connection; over it `421` |
| `max_errors` | int | `10` | Refused commands before the session ends with `421`. This is what stops a prober walking the command space |
| `max_connections` | int | `1000` | Sessions on this listener; over it `421` |
| `read_timeout` | duration | `5m` | One command or message line, the minimum RFC 5321 section 4.5.3.2 asks for; at most 1h |
| `session_timeout` | duration | `30m` | A whole session; at most 24h, and not shorter than `read_timeout` |
| `commands` | list | `EHLO, HELO, MAIL, RCPT, DATA, RSET, NOOP, QUIT, AUTH, STARTTLS` | Verbs a client may send; anything else is `502` and counts towards `max_errors`. `QUIT` and one of `EHLO`/`HELO` are required. `VRFY` and `EXPN` are left out by default and warn when added: they let a prober test whether an address exists |
| `hide_capabilities` | list | `[]` | EHLO keywords stripped from the upstream's answer, on top of `STARTTLS`, `CHUNKING` and `BDAT`, which are always removed |
| `bare_newlines` | `reject`, `convert` | `reject` | A line ended by LF alone: refuse the session, or repair it to CRLF. Repair is safe only because the proxy re-emits every line itself |
| `upstream_tls_mode` | `none`, `starttls`, `implicit` | `none` | How the proxy reaches the upstream. `none` is right when the hop is inside a trusted network and wrong everywhere else; with `starttls` an upstream that does not offer it fails the session rather than continuing in clear |
| `upstream_tls` | object | none | Verification for the upstream leg: same keys as `upstreams[].tls`. Without `server_name` the endpoint's host is verified |
| `proxy_protocol` | bool | `false` | Send a PROXY protocol v2 header with the client address to the upstream |
| `allow_clients` | list of CIDR | `[]` (any) | Others get `554` before any session starts (`client_not_allowed`). Empty is right for inbound mail and wrong for submission |
| `xclient` | bool | `false` | After the proxy's own EHLO, send `XCLIENT ADDR= PORT=` (the Postfix extension) when the upstream advertises it, so the mail server's logs and policies see the real client |

Every session writes one `smtp` line to the access log with the client
address, whether it was encrypted, messages, octets, refusals, the
endpoint and why it closed. AUTH arguments, challenges and responses are
never logged: they carry the password. Counters: `smtp_sessions`,
`smtp_sessions_open`, `smtp_messages`, `smtp_refused`, `smtp_rejected`,
`smtp_tls_upgrades`, `smtp_protocol_errors`, `smtp_bytes_in`; the
matching `xproxy_smtp_*` metrics. Protocol violations are `smtp_denied`
deny events, so a `bans.triggers` entry on that reason turns a prober
into a ban.

### server.listeners[].mqtt (kind: mqtt)

A `kind: mqtt` listener is a protocol-aware MQTT proxy for 3.1.1 (OASIS,
also ISO/IEC 20922) and 5.0. Every control packet is read; the ones that
carry a policy question — who is connecting, what they publish, what
they subscribe to — are decided before they reach the broker, and the
rest are forwarded untouched.

The reason it is not a layer 4 listener: an MQTT broker's authorisation
is per topic, and a topic is a string inside a packet. Without reading
the packets there is nowhere to say that a device may publish its own
telemetry and nothing else, and a device holding a broker credential
holds the whole tree.

What that gets you beyond a splice:

- **A subscription is a filter, not a topic.** `sensors/#` is allowed
  only when an entry of `subscribe_allow` covers everything that filter
  could deliver, and refused when it could reach anything in
  `subscribe_deny`. Matching a filter as though it were a topic is how
  `#` slips through an allow list of `sensors/+`.
- **The will goes through the publish policy.** A will is a message the
  broker publishes for the client after it is gone; checking it at
  CONNECT is the only moment there is.
- **A malformed packet ends the session, forwarding nothing.** Its
  remaining length is what the next read depends on, so a packet the
  proxy could not parse is a stream it can no longer frame — in either
  direction.
- **A session begins with CONNECT and has exactly one.** A first packet
  of another type never reaches the broker, and a second CONNECT would
  take a new identity on a session already authorised as another.
- **Only the versions the proxy parses are accepted.** A version it
  cannot parse is a packet it cannot check, so there is no "accept
  anything" setting.

MQTT has no in-band upgrade, so `tls_mode` is `implicit` or nothing; a
plaintext listener stays plaintext for the life of the session. The
listener takes `address`, `mqtt` and `tls`; `proxy_protocol` works as on
an HTTP listener, and bans and the global connection limits apply at
accept. Changing the `mqtt` section rebinds the listener on reload.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `upstream` | upstream | required | The broker pool. Endpoints are picked with the upstream's balancer, dial failures try the next and feed outlier ejection |
| `tls_mode` | `implicit`, `none` | `implicit` with `tls`, else `none` | TLS from the first octet (8883), or never. `implicit` needs the listener's `tls`; `none` warns, because there is no upgrade to fall back on |
| `upstream_tls_mode` | `none`, `implicit` | `none` | How the proxy reaches the broker |
| `upstream_tls` | object | none | Verification for the broker leg: same keys as `upstreams[].tls`. Without `server_name` the endpoint's host is verified |
| `versions` | list | `["3.1.1", "5.0"]` | Protocol versions accepted. Anything else is refused at CONNECT with the code that version spells it with (`0x01` in 3.1.1, `0x84` in 5.0) |
| `require_auth` | bool | `false` | Refuse a CONNECT without a username. The broker still verifies the password; this stops an anonymous session reaching it |
| `allow_empty_client_id` | bool | `true` | The empty client id, which 3.1.1 allows with a clean session and 5.0 answers with an assigned one. Turning it off is what makes every session identifiable in the logs |
| `max_client_id` | int | `128` | Client id length; 1..65535 |
| `client_id_pattern` | RE2 | none | The client id must match, anchored as written |
| `max_packet_size` | int | `1048576` | One control packet including its header, in either direction; 1024..268435460. Refused **before** the body is read, so the bound is on what the proxy allocates |
| `max_topic_length` | int | `512` | A topic name or filter |
| `max_topic_levels` | int | `16` | Levels in a topic or filter |
| `publish_allow` | list of filters | `[]` (any) | Checked against the topic of every client PUBLISH and against the will topic |
| `publish_deny` | list of filters | `[]` | Checked the same way; deny wins |
| `subscribe_allow` | list of filters | `[]` (any) | A subscription is allowed only when one entry subsumes it |
| `subscribe_deny` | list of filters | `[]` | A subscription is refused when it overlaps one entry |
| `max_subscriptions` | int | `64` | Live subscriptions per session |
| `allow_retain` | bool | `true` | PUBLISH with the retain flag, and a retained will. A retained message outlives the session that set it |
| `allow_wildcard_subscribe` | bool | `true` | `+` and `#` in a subscription at all. With an allow list this rarely needs turning off |
| `keep_alive_max` | duration | `0` (any) | The largest keep alive a client may ask for; `0` from the client is also refused, since it asks the broker never to time the session out. At most 18h12m15s, the range of the uint16 the protocol carries it in |
| `max_connections` | int | `10000` | Sessions on this listener; over it the connection is closed (MQTT has no reply before CONNECT) |
| `connect_timeout` | duration | `30s` | Waiting for the CONNECT packet, as 3.1.1 section 3.1 asks |
| `idle_timeout` | duration | `10m` | No packet in either direction |
| `action` | `disconnect`, `drop` | `disconnect` | On a refused PUBLISH or SUBSCRIBE. `drop` refuses the one packet and acknowledges it — PUBACK or PUBREC with `0x87` at QoS 1 and 2, a SUBACK of `0x80` for every filter — so a fleet does not fall off the network over one misconfigured device. A PUBREL for a refused QoS 2 publication is answered by the proxy, since the broker never saw the PUBLISH |
| `proxy_protocol` | bool | `false` | Send a PROXY protocol v2 header with the client address to the broker |
| `allow_clients` | list of CIDR | `[]` (any) | Others are closed before the CONNECT is read |
| `max_payload_bytes` | int | `0` (`max_packet_size` decides) | The payload of one PUBLISH. Not the same bound as `max_packet_size`: a policy about payloads is a policy about what a device sends, and a fleet whose telemetry is two hundred octets has no business sending a megabyte |
| `max_qos` | int | `2` | The highest quality of service a publication or a subscription may ask for. QoS 2 costs a broker four packets and a stored state per message, which is what makes it worth bounding on a fleet that does not need it |
| `topics` | list | `[]` | Per-topic bounds, below |
| `sparkplug` | object | | The Sparkplug B policy, below |

**`topics[]`** is where the payload, QoS and retain bounds belong, because
all three are properties of the *topic* rather than of the listener: a
command topic wants QoS at least 1 and a payload of tens of octets, a
firmware topic wants a large payload and retain, telemetry wants QoS 0 and
neither. One bound for the listener has to be the loosest of the three,
which is the same as no bound. The first entry whose filters match decides;
a topic no entry matches falls back to the listener's own bounds.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | name | required, unique | Carried into the logs and the counters when the rule decides |
| `filters` | list | required | MQTT topic filters (`plant/+/control`, `spBv1.0/#`) |
| `max_payload_bytes` | int | `0` (the listener's) | The payload of a publication to these topics |
| `min_qos`, `max_qos` | int | | The quality of service window. `min_qos: 1` on a command topic is "a command must be acknowledged", which is a statement about the process rather than about the transport |
| `allow_retain` | bool | the listener's | Retain for these topics. `true` overrides a listener that refuses retain, which is how a configuration topic keeps the one case where a retained message is the point |

**`sparkplug`** is the Sparkplug B policy. Sparkplug B is the convention
that makes MQTT an industrial protocol, and it belongs in a proxy for one
reason: of its message types, two — `NCMD` and `DCMD` — are **commands to
equipment**, the MQTT equivalent of a Modbus write, and the topic says
which is which. In most estates the publishers with any business sending
one are a short and known list, and a broker's own topic ACLs usually
cannot tell a command from a reading.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Read Sparkplug topics and apply this section |
| `namespace` | string | `spBv1.0` | The first topic level |
| `require_namespace` | bool | `false` | Refuse a publication whose topic is not a Sparkplug topic at all, which is how a listener is declared to carry nothing else |
| `allow_message_types` | list | `[]` (all) | `NBIRTH`, `NDEATH`, `DBIRTH`, `DDEATH`, `NDATA`, `DDATA`, `NCMD`, `DCMD`, `STATE` |
| `command_clients` | list of CIDR | `[]` | The networks that may publish `NCMD` and `DCMD`. Empty leaves commands to the ordinary publish policy, and warns: naming them is what this section is for |
| `require_birth_before_data` | bool | `false` | Refuse `NDATA` or `DDATA` from an edge node no birth has been seen from — the convention's own ordering, which the broker does not enforce |
| `check_sequence` | bool | `false` | Refuse a message whose sequence number is not the next one for its edge node (it increments by one and wraps at 255, and a birth resets it to zero). A gap or a repeat is a lost message, a duplicated publisher, or somebody replaying one |
| `max_nodes` | int | `8192` | Edge nodes remembered for the birth and sequence checks; the identifiers come off the network. Past the bound those two checks are not made for a node the table does not hold rather than the node being refused |

**The metrics are not decoded.** A Sparkplug payload is protobuf and the
metric set is the plant's own; carrying a schema per estate is not this
proxy's business. The two top-level fields — the timestamp and the sequence
number, two varints at a fixed place in every payload — are read, and the
rest is forwarded untouched.

Every session writes one `mqtt` line to the access log with the client
address, client id, username, version, subscriptions, publications and
why it closed. Counters: `mqtt_sessions`, `mqtt_sessions_open`,
`mqtt_published`, `mqtt_subscribed`, `mqtt_refused`, `mqtt_rejected`,
`mqtt_protocol_errors`; the matching `xproxy_mqtt_*` metrics. The refusal
reasons a `topics` rule or the Sparkplug policy adds are
`payload_too_large`, `qos_too_high`, `qos_too_low`, `retain_refused`,
`sparkplug_not_sparkplug`, `sparkplug_namespace`,
`sparkplug_message_type`, `sparkplug_command_refused`,
`sparkplug_no_birth` and `sparkplug_sequence`. Refusals
are `mqtt_denied` deny events, so a `bans.triggers` entry on that reason
turns a device walking the topic tree into a ban.

A note on `$`: a wildcard at the first level of a filter never matches a
topic beginning with `$` (MQTT 3.1.1 section 4.7), so `#` does not hand a
client the broker's own `$SYS` tree. `subscribe_deny: ["$SYS/#"]` is
still worth writing, because it refuses the client that asks for it by
name.

### server.listeners[].syslog (kind: syslog)

A `kind: syslog` listener is a relay that reads what it forwards.

Reading it is the point. Almost every field in a syslog record is
written by the sender and believed by the collector: the host name, the
facility, the severity, the time. A message claiming to be `auth.emerg`
from another machine costs nothing to send. And a message whose text
carries a newline becomes **two** records in any collector that frames
on newlines — the second one saying whatever the sender wanted a record
to say, with a priority of its own.

So every message is parsed, and every message is re-emitted as RFC 5424
in one framing, whatever arrived. One dialect out is what makes the
record a collector stores the record this relay decided about: a
newline in the text is written as a visible symbol, a line ending in a
structured data value is escaped, and a field that cannot appear in a
header is replaced.

Both transports: TCP (RFC 6587 framing, either kind) and UDP (RFC 5426,
one datagram per message), on the same address. TLS is RFC 5425.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `upstream` | upstream | required | The collector pool |
| `udp` | bool | `true` | Also take datagrams on the same address, which is what most senders still send |
| `framing` | enum | `auto` | What the stream side accepts: `octet_counting`, `non_transparent` or `auto`, decided per message by whether it starts with a digit |
| `upstream_framing` | enum | `octet_counting` | What the relay writes. Octet counting cannot be confused by what a message contains, and is the only framing RFC 5425 allows over TLS; `non_transparent` warns |
| `tls_mode` | enum | `implicit` with `tls`, else `none` | TLS from the first octet on the stream side |
| `upstream_tls_mode` | enum | `none` | `none` or `implicit` towards the collector |
| `upstream_tls` | object | | Verification of the collector |
| `hostname` | enum | `annotate` | `keep` takes the sender's word, `observed` replaces the field with the address the message arrived from, `annotate` keeps both and records which is which. `keep` warns |
| `allow_facilities` | list | `[]` (any) | Facilities by name: `kern`, `user`, `auth`, `authpriv`, `local0`… |
| `deny_facilities` | list | `[]` | Refused whatever the allow list says |
| `min_severity` | name | `debug` | Drop anything less severe: `warning` keeps `emerg` through `warning` |
| `allow_senders` | list of CIDR | `[]` (any) | On UDP this is the only authentication there is, so leaving it empty with `udp: true` warns |
| `deny_patterns` | list of RE2 | `[]` | Drop a message whose text matches. A filter, not a redaction: it does not arrive |
| `redact` | list | `[]` | `{name, pattern, with}`: replace what matches and record that a rule did, in structured data |
| `max_message_bytes` | int | `8192` | One message; 480..1048576. RFC 5426 requires every receiver to take 480 |
| `rate_limit` | int | `0` (none) | Messages a second from one sender. Unset with `udp: true` warns |
| `rate_burst` | int | `rate_limit` | What one sender may send at once |
| `max_senders` | int | `65536` | The rate limit table. When it is full a new sender is refused rather than evicting the entries doing the limiting |
| `max_connections` | int | `1000` | Stream connections |
| `idle_timeout` | duration | `5m` | No traffic on a stream connection |
| `queue` | int | `4096` | Parsed messages waiting for the collector. When it is full the relay drops and counts, rather than holding every sender behind one slow collector |

**The secure upgrade** is `tls_mode: none` with
`upstream_tls_mode: implicit`: a device that can only send clear syslog
over UDP writes to this listener, and the records leave it as RFC 5425
TLS. It does not make the sender trustworthy — between the device and
this port the records are still in clear and still forgeable — so put
the port where only those devices can reach it, keep `allow_senders`
tight, and use `hostname: observed`.

A message the relay cannot parse is refused, not forwarded: its
facility, severity and host are exactly the fields every rule here
decides on, and a record nobody could read is a record nobody can
filter. A message with no timestamp is given the time the relay saw it,
because a record nobody can order is a record that is hard to use.

On a delimited stream a message over the bound is dropped and the
connection carries on — the reader skips to the next line ending, so
one long line does not cost every record behind it. On a counted stream
it ends the connection, because refusing to read the octets a frame
declared leaves the reader at an offset nobody knows.

Counters: `syslog_received`, `syslog_forwarded`, `syslog_dropped`,
`syslog_refused`, `syslog_rate_limited`, `syslog_redacted`,
`syslog_queue_dropped`, `syslog_send_failed`, `syslog_connections`,
`syslog_rejected`. Refusals are `syslog_denied` for the ban triggers.

### server.listeners[].modbus (kind: modbus)

A `kind: modbus` listener is a Modbus relay that reads every frame and
decides about it.

Modbus is the protocol that runs the plant floor and has no security
properties at all: no authentication, no integrity, no session. A frame
says which device it is for, what to do and where, and the device does
it. The devices cannot be fixed — they are a decade old, the vendor is
gone, and the process they run does not stop — so the only place a policy
can exist is in the path.

It works in both directions:

- **reverse** (the default): masters connect here and the relay dials the
  devices. This is how a PLC that cannot be patched gets an allow list, a
  read-only historian, a value bound on a setpoint and an audit trail.
- **forward**: the plant's masters use this listener as the controlled
  egress to reach devices elsewhere, and the `routes` say which
  destination each unit identifier may reach at all. A unit no route
  claims is refused with a gateway exception rather than sent somewhere
  invented.

All three framings, in either direction: Modbus/TCP (MBAP), and the two
serial framings every "Modbus gateway" ever sold tunnels over TCP —
Modbus RTU and Modbus ASCII. `framing` is what arrives, `upstream_framing`
is what leaves, and setting them differently makes this listener a
protocol converter, which is what a serial device behind a terminal
server needs.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `mode` | enum | `reverse` | `reverse` (masters connect here) or `forward` (this is the plant's egress). `forward` requires `routes` or an `upstream` |
| `upstream` | upstream | required unless every destination is a route | The device pool a frame goes to when no route claims its unit identifier |
| `framing` | enum | `tcp` | What arrives from the master: `tcp` (MBAP), `rtu` or `ascii` |
| `upstream_framing` | enum | `framing` | What the relay writes to the device |
| `routes` | list | `[]` | Unit identifier to pool, below |
| `tls_mode` | enum | `implicit` with `tls`, else `none` | `implicit` is Modbus/TCP Security: TLS from the first octet, conventionally on port 802 |
| `upstream_tls_mode` | enum | `none` | `none` or `implicit` towards the device |
| `upstream_tls` | object | | Verification of the device |
| `security` | object | | The Modbus/TCP Security role policy, below |
| `allow_clients` | list of CIDR | `[]` (any) | Networks a master may connect from. Empty warns: this listener reaches a PLC |
| `deny_clients` | list of CIDR | `[]` | Refused whatever the allow list says |
| `units` | list | `[]` (any) | Unit identifiers the listener accepts at all, as `3` or `1-16` |
| `read_only` | bool | `false` | Refuse every function code that changes anything, for every client, before any rule is read. A rule cannot override it |
| `rules` | list | `[]` | The policy, in order, first match wins. Below |
| `default_action` | enum | `deny` | What happens to a frame no rule matched |
| `deny_response` | enum | `exception` | How a refusal is answered: `exception` (the master reads it as the device's own refusal), `drop` (no answer, which a master reads as a timeout) or `close` |
| `learn` | object | | Learning mode, below |
| `trace` | object | | The frame trace, below |
| `max_connections` | int | `64` | Live sessions; past it a connection is closed and counted |
| `max_pending` | int | `16` MBAP, `1` serial | Requests one session may have outstanding towards a device |
| `idle_timeout` | duration | `120s` | Close a session that says nothing |
| `request_timeout` | duration | `5s` | How long the device has to answer one request |
| `connect_timeout` | duration | `5s` | Dialling the device |
| `max_frame_bytes` | int | `260` | One ADU; 8..260. The specification's longest is 260 |
| `rate_limit` | int | `0` (none) | Requests a second per client address |
| `rate_burst` | int | `rate_limit` | What one master may ask at once |
| `log_frames` | bool | `false` | An access line per frame rather than per session: the audit trail a plant is asked for. Off warns |
| `alert_on_deny` | bool | `true` | A security event for every refusal |
| `proxy_protocol` | bool | `false` | Send a PROXY protocol v2 header to the device |

**`routes[]`** send a unit identifier to a pool of its own, which is what
a gateway multiplexing several devices onto one address does:

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | name | required | Identifies the route in the logs and the counters |
| `units` | list | required | The unit identifiers this route claims: `5` or `1-16` |
| `upstream` | upstream | required | The pool they go to |
| `framing` | enum | `upstream_framing` | Override the framing for this route, so one listener can front a Modbus/TCP PLC and a serial device at once |
| `unit_override` | int | none | Rewrite the unit identifier sent to the device. A gateway that presents unit 5 to a device answering only to unit 1 needs it |

**`security`** is Modbus/TCP Security (the Modbus Organization's
MB-TCP-Security specification): TLS with mutual authentication, and
authorisation by the role the client certificate carries.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `mode` | enum | `off` | `off`, `allow` (a role is read when the client presents one, and rules naming a role only match then) or `require` (a client with no usable role is refused). `require` is what the specification describes; `allow` is the migration |
| `role_source` | enum | `extension` | `extension` is the x.509 extension under the Modbus arc, `1.3.6.1.4.1.50316.802.1`, which is what the specification defines. `cn` and `ou` read the subject instead and warn |
| `roles` | list | `[]` (any the rules name) | The allow list of role names |
| `require_client_cert` | bool | `true` with `mode: require` | Refuse a connection presenting no client certificate |

**`rules[]`** decide each frame. Every selector that is set must match; a
rule with no selectors matches everything, which is how the last rule in
a list is written.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | name | required | In the logs, the counters and the learning report |
| `action` | enum | `allow` | `allow`, `deny` or `observe`. `observe` logs and counts and then keeps looking, which is how a rule is tried on live traffic before it decides anything |
| `clients` | list of CIDR | `[]` (any) | Networks the master is in |
| `roles` | list | `[]` (any) | Modbus/TCP Security roles. A rule naming a role never matches a session that has none |
| `units` | list | `[]` (any) | Unit identifiers, as numbers or ranges |
| `functions` | list | `[]` (any) | Function codes by name (`read_holding_registers`) or number |
| `access` | list | `[]` (any) | What the code does: `read`, `write`, `diagnostic`, `identify` or `vendor`. The durable way to write "no writing" without listing every code that writes |
| `addresses` | list | `[]` (any) | Register or coil ranges the request may name, as `0-999`. A request whose range is not **entirely** inside one of them does not match: splitting a read is not the relay's decision |
| `write_addresses` | list | `[]` | The write half of function code 23, and every writing code when set, so one rule can allow a wide read and a narrow write |
| `max_quantity` | int | `0` (the protocol's own bound) | Registers or coils one request may name; 0..2000 |
| `values` | list | `[]` | Bound what may be written, below |
| `schedule` | object | | When the rule is in force, below |
| `comment` | string | | Carried into the logs when the rule decides, for the change record a plant keeps |

**`values[]`** is the deep inspection a plant actually needs: a setpoint
register that may hold 0 to 100 and nothing else.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `registers` | range | every address the rule covers | The address range this bound applies to, as `400-499` or a single address |
| `min`, `max` | int | required unless `coils` is set | Bound each 16-bit value written into that range, inclusive |
| `signed` | bool | `false` | Read the value as a signed 16-bit integer, which is how most setpoints are encoded |
| `coils` | bool | | Bound a coil write instead: `true` allows setting a coil in the range, `false` allows only clearing it. "This client may stop the pump but not start it" |
| `max_delta` | int | `0` (off) | How far one write may move the value from the last one this relay saw at that address: a setpoint that may be nudged and not jumped |
| `transitions` | list | `[]` (any) | The value changes permitted, as `from->to` with numbers or `*` on either side: `["0->1", "1->0"]` is a state register that may be started and stopped and not driven anywhere else. `*->*` is refused as a list that permits everything |
| `rate` | object | | `{max, period, per_client}`: how often this range may be written, counted per unit identifier and address (`per_client` counts each master's writes separately instead). Not the listener's rate limit, which is about frames from a client: this is about one address, and a master that moves a setpoint sixty times a minute is either broken or not the master it claims to be |
| `require_before` | object | | Select-before-operate: `{registers, equals, within (default 30s), unit}`. The write is refused unless that register was **written** to that value within the window. IEC 60870-5-104 has this in the protocol; Modbus does not, so a plant that wants it either implements it in every client — where the frame that skips it looks exactly like the frame that did not — or has the relay enforce it |
| `on_unknown` | enum | `allow` | What happens when a check needs the address's current value and this relay has not seen one: `allow` (counted, with `min` and `max` still in force) or `refuse`. It warns while `max_delta` or `transitions` are set with `allow` |

**The three bounds that are about a change**, and the honest limit of all
three: `max_delta`, `transitions` and `require_before` need to know what
the value *is*, and what this relay knows is the last value it **saw** — a
write it forwarded, or a read it relayed back. A value changed by another
master, by a local panel or by the process itself was never on this path.
So `on_unknown` says what to do when there is no value, the number of such
checks is counted (`modbus_value_unknown`), and `min`/`max`, which need
nothing, are the bounds that always hold. A masked write (function code
22) makes the relay *forget* the address rather than guess: the result
depends on what the register held inside the device.

`max_value_points` on the listener bounds how many addresses are
remembered (default 65536; a plant has hundreds), because the addresses
come off the network.

```yaml
rules:
  - name: setpoint
    action: allow
    clients: ["10.30.7.13/32"]        # HMI-3 and nothing else
    units: ["2"]
    functions: [write_single_register]
    addresses: ["40001"]
    schedule: {days: [sat], from: "06:00", to: "14:00", timezone: Europe/Stockholm}
    values:
      - registers: "40001"
        min: 0
        max: 1500                      # the range
        max_delta: 100                 # and not in one jump
        rate: {max: 1, period: 1m}     # and not more than once a minute
        require_before: {registers: "40000", equals: 1, within: 30s}
        on_unknown: refuse
```

**`schedule`** limits a rule to a time window. A rule with no schedule is
always in force, so "these rules during the shift and those outside it"
is written as the scheduled rules first and the unscheduled ones after
them.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `days` | list | `[]` (every day) | `mon`, `tue`, `wed`, `thu`, `fri`, `sat`, `sun`, or the long form (`monday`). Every listener kind reads both |
| `from`, `to` | `HH:MM` | | The window in `timezone`. A `to` before its `from` spans midnight, and the window then **belongs to the day it started on**: `{days: [fri], from: "22:00", to: "06:00"}` runs Friday 22:00 to Saturday 06:00, and covers neither Friday's own small hours nor Saturday evening. The end is exclusive, so two adjacent windows do not overlap on the minute they meet |
| `timezone` | IANA name | `UTC` | A schedule in the host's local time is a schedule that moves when somebody fixes the host's time zone |

**`learn`** records what actually crosses the listener — the clients, the
roles, the units, the function codes, the address ranges and the values
written — and writes it out as a rule set to start from. Nobody knows what
a plant's Modbus traffic is: the drawings say what it was meant to be,
the traffic says what the integrator left behind. Run it for a week and
the file is the answer.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Turn the recording on |
| `file` | path | required when enabled | Where the report is written, as YAML. Replaced atomically, owner readable only |
| `interval` | duration | `5m` | How often it is rewritten; 10s..24h. It is also written at shutdown |
| `max_subjects` | int | `8192` | Observations held: one per client, role, unit and function code. Past it the oldest goes and the drops are counted, in the report |
| `enforce` | bool | `false` | Keep the policy in force while learning. Off — the default — means this listener records and decides nothing, which is the only honest way to find out what a policy would have broken, and warns so it is not left on by accident |

**`trace`** writes one JSON object per frame for as long as it is
enabled: the engineer's tool for "what is this master actually doing". It
is a different thing from the audit log, which answers "who was refused
and why", keeps forever and is shipped off the machine.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `file` | path | required | The trace file, one object per line |
| `max_bytes` | int | `104857600` (100 MiB) | 1MiB..64GiB. At the bound the trace writes one line saying it stopped and then stops, rather than filling the disk the plant's historian is also on |
| `include_data` | bool | `false` | Write the frame's data bytes as hex. That is process data, and it warns |
| `requests`, `responses` | bool | `true` | The directions traced |

#### What the relay decides, and in what order

1. The client address, against `deny_clients` then `allow_clients`.
2. TLS and the role, when `security` asks for one. A role can only come
   from a certificate and a certificate can only come from TLS, so a
   listener asking for roles without TLS refuses every session and says
   `security_requires_tls` rather than leaving a mystery.
3. The frame, whole. A frame that does not parse is refused: a relay that
   forwarded what it could not read would be forwarding what it could not
   decide about, and the device behind it will read those bytes somehow.
4. `read_only`, which no rule can override.
5. `units`.
6. The rules, in order. The first `allow` or `deny` decides; an `observe`
   rule records and the search continues. A frame that matches no rule
   takes `default_action`.
7. The value bounds of the rule that matched. A value outside them is
   refused **by that rule** rather than falling through to a later rule
   that would permit it, because a bound that can be escaped by writing
   another rule underneath it is not a bound.

#### Architectural decisions

**Requests are serialised towards each device.** A Modbus slave has one
scan. A relay that pipelined into it would be turning a policy engine
into a load generator, so each session holds one connection per route and
one request in flight at a time, with `max_pending` bounding the queue
behind it. A master whose queue is full is answered with exception 06
(server busy), which is the protocol's own way of saying what happened.
The serial framings default to `max_pending: 1` because they have no
transaction identifier: a second request in flight could not be told from
the first.

**A forwarded frame keeps its bytes.** The frame that reaches the device
is the frame that arrived, byte for byte, and the answer that reaches the
master is the answer that arrived. The relay re-encodes only when it must
— the framings differ, or `unit_override` rewrote the identifier — because
re-encoding a frame is how a relay and a device come to disagree about
what was said. The MBAP transaction identifier is the one exception in
the other direction: the master's own value is put back on the answer,
whatever the relay used towards the device, because that is the field the
master matches on.

**A refusal is Modbus, not a disconnection.** `deny_response: exception`
answers with the exception a master already understands — illegal function
for a code the policy does not permit, illegal data address for a range
it does not, illegal data value for a value outside a bound, gateway path
unavailable for a unit with no route — so a master's diagnostics say
something true and the session carries on. `drop` and `close` are there
for the cases where a master must not learn anything from the answer.

**The device's own answer is checked too.** A response the relay cannot
parse, or one answering for a different unit identifier, is not handed to
the master: the two would read the same bytes differently, which is the
whole class of bug this relay exists to prevent. The master gets
exception 04 (server failure) and the event is logged.

**Learning is observe-only unless it says otherwise.** `learn.enforce`
defaults to false, and validation warns while it is off, because a
learning run left on by accident is a relay that decides nothing.

Counters: `modbus_sessions`, `modbus_sessions_open`, `modbus_requests`,
`modbus_responses`, `modbus_denied`, `modbus_would_deny`,
`modbus_exceptions`, `modbus_malformed`, `modbus_refused`,
`modbus_rejected`, `modbus_rate_limited`, `modbus_queue_full`,
`modbus_upstream_failed`, `modbus_traced`, `modbus_learned`. Refusals are
`modbus_denied` for the ban triggers, and the fine-grained reason is in
the refusal counters: `client_not_allowed`, `tls_handshake`,
`no_client_certificate`, `no_role`, `role_not_allowed`,
`security_requires_tls`, `framing`, `frame_too_large`, `malformed`,
`malformed_response`, `response_unit_mismatch`, `no_route_for_unit`,
`max_connections`, `rate_limit`, `queue_full`, `read_only`,
`read_only_unknown_function`, `unit_not_allowed`, `rule_deny`, `no_rule`,
`value_out_of_range`, `value_delta`, `value_transition`, `value_rate`,
`value_no_select`, `value_unknown`, `value_masked_write`, `coil_set_not_allowed`,
`coil_clear_not_allowed`. A selector that does not match is not a refusal
of its own: the frame falls through to the next rule, and to `no_rule` if
none matches.

### server.listeners[].iec104 (kind: iec104)

IEC 60870-5-104 is the protocol that operates electricity transmission and
distribution, and it is the grid's Modbus: a controlling station (the SCADA
master) and a controlled station (a substation gateway or an RTU) exchange
application service data units over a plain TCP connection on port 2404,
with no authentication, no integrity and no confidentiality anywhere in the
standard. Anyone who can reach the gateway can trip a breaker on it.
IEC 62351-3 adds TLS and is almost nowhere deployed, because the controlled
stations are substation equipment with twenty-year service lives.

What the protocol *does* have, and Modbus does not, is a structure that says
what a message means, and that structure is what this relay enforces:

- Every I-format frame carries a **type identification** (what this is), a
  **cause of transmission** (why it was sent), an **originator address**
  (which control centre) and a **common address** (which station).
- The **process commands** -- single, double, regulating step, setpoint,
  bitstring -- are a small numbered set, and so are the **system commands**,
  two of which reset a station and move its clock.
- The dangerous commands have a **two-step form**: *select* (an activation
  with the S/E bit set) then *execute*. The standard describes it; the
  equipment mostly does not enforce it.
- Every I frame is **sequence numbered in both directions**, which is the
  only thing in the protocol that can detect a lost, duplicated or replayed
  frame.

So the policy here is written in those terms rather than in ports: which
stations may be addressed, which commands may be sent to which points by
whom, whether a command has to be selected before it is executed, and
whether the numbering adds up.

**There is no per-address routing on this kind, on purpose.** An IEC 104
connection is a long-lived *association* between one controlling station and
one controlled station, and the first frame a control centre sends is
`STARTDT_act` -- a U-format frame with no common address in it. A relay that
chose a pool from the common address could not choose one until the first I
frame, by which time the association is up and the handshake answered. One
listener per association is the honest shape; `common_addresses` is what
bounds which stations may be addressed through it.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `mode` | `reverse`, `forward` | `reverse` | `reverse`: a control centre connects here and the relay dials the station. `forward`: this listener is the controlled egress a centre uses to reach stations elsewhere |
| `upstream` | string | required | The station pool this listener relays to |
| `tls_mode` | `implicit`, `none` | `implicit` with a `tls` section | IEC 62351-3: TLS from the first octet. There is no in-band upgrade to negotiate |
| `upstream_tls_mode` | `none`, `implicit` | `none` | Whether this listener speaks TLS to the station |
| `upstream_tls` | object | | Verification of the station when `upstream_tls_mode` is not `none` |
| `allow_clients` | list of CIDR | all | Networks a controlling station may connect from |
| `deny_clients` | list of CIDR | | Evaluated before `allow_clients` |
| `common_addresses` | list | all | The stations that may be addressed at all, as numbers or `"1-16"` ranges. A control centre that may address one substation and reaches ten is the commonest finding in this protocol |
| `monitor_only` | bool | `false` | Refuse every command and system command, for every client, before any rule is read: telemetry up and nothing down. **No rule can override it** |
| `rules` | list | | Per-frame rules, first match wins; see below |
| `default_action` | `deny`, `allow` | `deny` | What a frame no rule matched gets |
| `deny_response` | `negative`, `drop`, `close` | `negative` | `negative` returns the same ASDU with the negative-confirm bit and cause `actcon`, which is what a station does and what a control centre's alarm list understands |
| `require_select` | bool | `false` | Make the two-step form mandatory for every command type that has one |
| `select_timeout` | duration | `30s` | How long a selection stays valid (1s to 10m) |
| `max_selections` | int | `4096` | Outstanding selections this relay remembers |
| `allow_controls` | list | all | The U-format control functions a client may send: `STARTDT_act`, `STARTDT_con`, `STOPDT_act`, `STOPDT_con`, `TESTFR_act`, `TESTFR_con`. Naming an activation names its confirmation |
| `k` | int | `12` | The sending window: how many I frames may be unacknowledged |
| `w` | int | `8` | After how many received frames a station acknowledges. Must not exceed `k` |
| `check_sequence` | bool | `true` | Refuse an I frame whose send sequence number is not the next one |
| `max_unacknowledged` | bool | `true` | Refuse a station with more than `k` frames outstanding, and one acknowledging frames nobody sent |
| `max_connections` | int | `32` | Live sessions |
| `idle_timeout` | duration | `120s` | Longer than the standard's t3, so a station's own keepalive keeps a quiet link open |
| `connect_timeout` | duration | `5s` | Dialling the station |
| `max_frame_bytes` | int | `255` | A policy bound below the protocol's own; the length field is one octet, so no APDU can exceed 257 octets whatever a station claims |
| `rate_limit`, `rate_burst` | int | `0` | Frames per second per client address |
| `command_rate_limit`, `command_rate_burst` | int | `0` | *Commands* per second per client, separately: a control centre that sends a thousand breaker commands a second is not a busy control centre, and a frame limit loose enough for telemetry says nothing about that |
| `log_frames` | bool | `false` | An access line per frame. On this protocol periodic telemetry is most of the traffic, so this is a lot of lines |
| `log_commands` | bool | `true` | An access line for every command and system command, in both directions, leaving the telemetry alone: a record of what was commanded is the thing a grid operator is asked for after an incident |
| `alert_on_deny` | bool | `true` | A security event per refusal |
| `proxy_protocol` | bool | `false` | Send a PROXY protocol v2 header to the station |

#### server.listeners[].iec104.rules[]

| Key | Type | Description |
|-----|------|-------------|
| `name` | string | Required; names the rule in the logs and the counters |
| `action` | `allow`, `deny`, `observe` | Default `allow`. `observe` records the frame and keeps looking, which is how a rule is tried on live traffic before it decides anything |
| `clients` | list of CIDR | Networks the controlling station is in |
| `common_addresses` | list | The stations this rule covers |
| `originators` | list | Originator addresses (0 to 255): which control centre, where a station serves several |
| `types` | list | Type identifications by the standard's name (`C_SC_NA_1`) or by number. The names are the standard's own because that is what the substation documentation says |
| `class` | list | `monitoring`, `command`, `system`, `parameter`, `file`: what a type *does*. The durable way to write a policy, because a class outlives a standard revision that adds a type |
| `causes` | list | Causes of transmission by name (`act`, `actcon`, `spont`, `introgroup1`) or number. A rule naming none matches any cause, which is usually wrong for a rule about commands: `act` is the centre commanding and `actcon` is the station answering |
| `addresses` | list | Information object address ranges (0 to 16777215). A frame naming an address outside all of them does not match |
| `max_objects` | int | Information objects one ASDU may carry (0 leaves the protocol's own 127) |
| `select` | `select`, `execute` | Which half of a two-step command this rule is about. `select` on one client and `execute` on another is a four-eyes control: one operator arms and another fires |
| `schedule` | object | `{days, from, to, timezone}`; a window whose `to` is before its `from` spans midnight and belongs to the day it started on |

**What is checked before the rules, and cannot be shadowed.** A frame the
relay could not read is refused whether or not the listener is enforcing:
forwarding what it cannot decide about would hand the substation octets it
will read somehow. So are the rate limits, and so is a *station* sending an
activation to its own control centre -- not a shape the standard has, and
what a compromised substation gateway pivoting upstream looks like.

**Select-before-operate is narrow on purpose.** A selection belongs to the
connection that made it, to one common address, one information object
address and one type identification, and it expires. A selection that
outlived its connection would let a later client execute on an earlier one's
intention; one that never expired would let an execute sent hours later
operate a breaker somebody selected and thought better of. A selection
authorises one execution, a deactivation withdraws it, and the bitstring
commands -- which have no two-step form in the standard -- are exempt,
because requiring a selection for them would refuse every use of them for
ever.

**A sequence gap is one refusal.** The state moves to what arrived, so a
single lost frame does not take a substation off the air until somebody
restarts the link.

**The metric payloads are never decoded.** A measurement's scaled value,
quality descriptor and timestamp are forwarded untouched. Decoding every one
of the hundred-odd type identifications would be a second implementation of
the standard, and a relay that got one wrong would corrupt a reading nobody
could trace. What is read is the ASDU header, the object addresses and a
command's qualifier -- which is what a policy is written about. On a
*sequence* ASDU only the first information object address is on the wire, so
that is the one an `addresses` rule checks.

Counters: `iec104_sessions`, `iec104_sessions_open`, `iec104_frames`,
`iec104_commands`, `iec104_system_commands`, `iec104_denied`,
`iec104_would_deny`, `iec104_malformed`, `iec104_rejected`,
`iec104_rate_limited`, `iec104_selects`, `iec104_executes`,
`iec104_unselected`, `iec104_selects_held`, `iec104_sequence_gaps`,
`iec104_window_full`, `iec104_upstream_failed`. Refusals are
`iec104_denied` for the ban triggers, and the fine-grained reason is in the
refusal counters: `client_not_allowed`, `tls_handshake`, `malformed`,
`frame_too_long`, `max_connections`, `rate_limited`,
`command_rate_limited`, `monitor_only`, `common_address`, `rule`,
`default_deny`, `control`, `station_command`, `sequence`, `window`,
`ack_ahead`, `unselected`, `select_unavailable`.

### server.listeners[].ldap (kind: ldap)

A directory is the one service in an estate that knows who everybody is, and
LDAP is how everything asks. That makes it two things at once: the
authentication path for every application that has not moved to OIDC, and the
most complete map of an organisation that exists anywhere on its network --
every person, every group, every service account, every machine, with the
memberships that say who is an administrator.

Five things are deliberate in the data path.

**A bind with a name and an empty password is refused by default.** RFC 4513
§5.1.2 calls it an *unauthenticated bind* and says it is anonymous. A great
many directories answer it with **success**, and a great many applications are
written as "bind as the user, and if it worked the password was right". That
is an authentication bypass in the application, reachable with an empty string,
and the directory cannot tell the difference between it and a correct login.
The relay can. `methods` is the list, and it defaults to `simple` and `sasl`
-- the two that actually authenticate.

**A password in the clear is refused by default.** LDAP on port 389 with a
simple bind puts a directory password on the wire in plaintext, and the client
library that did it will not tell anyone. `require_tls` (default true) stops
it, and it is **not shadowable**: by the time a policy could be consulted the
password has already gone past, so a listener in `policy: {mode: shadow}`
refuses it anyway. SASL `PLAIN` counts as a password, because it is a simple
bind with extra steps.

**The attribute policy applies to the answer, not only to the question.** A
search that asks for `*` never names `userPassword`, and the directory sends it
anyway. So a denied attribute is **removed from the entry on its way back** --
which is the half a request-side access list cannot do -- while a request that
names one plainly is refused, because stripping it would answer a plain
question with a silence the client cannot tell from an empty directory. A
*filter* naming one is refused too: `(userPassword=a*)` is a password oracle,
one character at a time.

**A subtree is a suffix compared one relative name at a time.** A string suffix
test admits `dc=notexample,dc=com` under `example,dc=com`, and a string prefix
test admits `ou=peoplex` under `ou=people`. Distinguished names are a tree and
are compared as one, with RFC 4514's escaping resolved, the attribute type
folded to lower case and the insignificant space removed.

**The entries are counted and the filter is measured.** An unbounded subtree
search with `(objectClass=*)` is how a directory is copied, and a filter of a
hundred substring terms with leading wildcards is a hundred full scans from a
request two hundred octets long. `max_entries` cuts the search with the
directory's own `sizeLimitExceeded`, so the client knows it got part of an
answer rather than hanging; `max_filter_terms`, `max_filter_depth` and
`allow_leading_wildcard` bound the filter.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `mode` | `reverse`, `forward` | `reverse` | `reverse`: clients connect here and the relay forwards to the directory. `forward`: this listener is the controlled egress an application uses to reach a directory elsewhere |
| `upstream` | string | required | The directory pool |
| `tls_mode` | `implicit`, `starttls`, `none` | `implicit` with a `tls` section | `implicit` is LDAPS: TLS from the first octet, port 636. `starttls` is the extended operation of RFC 4513 on port 389, which this relay **terminates itself** rather than forwarding, because the two legs of the connection are separate decisions |
| `require_tls` | bool | `true` | Refuse a bind that carries a password on an unprotected connection. Not shadowable |
| `upstream_tls_mode` | `none`, `implicit`, `starttls` | `none` | How this listener reaches the directory. With `tls_mode` this is the secure upgrade: TLS towards the client, whatever the directory will take towards the directory |
| `upstream_tls` | object | | Verification of the directory when `upstream_tls_mode` is not `none` |
| `allow_clients` | list of CIDR | all | Networks a client may connect from |
| `deny_clients` | list of CIDR | | Evaluated before `allow_clients` |
| `min_version` | int | `3` | The lowest LDAP version accepted. LDAPv2 is a different protocol wearing the same tags and has no SASL bind |
| `methods` | list | `[simple, sasl]` | Bind methods: `anonymous`, `unauthenticated`, `simple`, `sasl`. The default leaves out the two that are anonymous binds, one of them wearing a user's name |
| `sasl_mechanisms` | list | any | SASL mechanisms by name (`GSSAPI`, `EXTERNAL`, `DIGEST-MD5`, `PLAIN`). The comparison ignores case |
| `base_dns` | list of DN | any | The naming contexts this listener fronts. A request naming an object outside all of them is refused **before the rules and before `default_action: allow`**, which is what stops one listener from being a way into a directory's other trees |
| `read_only` | bool | `false` | Refuse add, delete, modify and modifyDN, for every client, before any rule is read. **No rule can override it** |
| `deny_attributes` | list | the built-in list | Attributes this relay will not carry, in either direction; see below for the built-in list. Setting the list **replaces** it |
| `on_denied_attribute` | `strip`, `deny` | `strip` | `strip` removes it from the answer and carries the rest, so an application that asked for everything still works and no longer receives a password hash. `deny` refuses the whole operation |
| `max_entries` | int | `500` | Entries one search may return. The client's own size limit is a request rather than a bound |
| `max_filter_terms` | int | `64` | Assertions one filter may contain |
| `max_filter_depth` | int | `12` | Levels of `and`/`or`/`not` one filter may nest |
| `allow_leading_wildcard` | bool | `true` | Permit a substring filter whose first component is a wildcard -- `(cn=*smith)` -- which no index can serve. Every address book does it; set it false on a listener fronting a large directory |
| `extended_operations` | list of OID | StartTLS only | Extended operations allowed. The two worth naming if you allow more are `1.3.6.1.4.1.4203.1.11.1` (password modify) and `1.3.6.1.4.1.4203.1.11.3` (who am I) |
| `deny_controls` | list of OID | | Controls this relay refuses to carry. Empty carries any: a control this relay does not know is one the directory decides about, and RFC 4511 already refuses an unrecognised critical control there |
| `rules` | list | | Per-request rules, first match wins; see below |
| `default_action` | `deny`, `allow` | `deny` | What a request no rule matched gets |
| `deny_response` | `insufficient`, `unwilling`, `drop`, `close` | `insufficient` | `insufficient` is result code 50, which is what a directory sends and what every client displays; a refused **bind** is always answered `invalidCredentials` instead, because that is the only code a client treats as a failed login rather than a server fault. `drop` is a hang to the client, and a hang looks like a directory that died |
| `max_outstanding` | int | `32` | Requests one connection may have in flight. LDAP is asynchronous and multiplexed, so this bounds the table that pairs a response with its request |
| `max_connections` | int | `256` | Live sessions |
| `idle_timeout` | duration | `300s` | A session that says nothing. A pooled directory connection is idle by design |
| `request_timeout` | duration | `30s` | How long the directory has to answer before its answer is too late to pair |
| `connect_timeout` | duration | `5s` | Dialling the directory |
| `max_message_bytes` | int | `262144` | One message. A directory entry with a photograph or a certificate in it is real. A message past this is refused unread |
| `rate_limit`, `rate_burst` | int | `0` | Requests per second per client address. A request past the limit is refused with `busy` and the connection is kept: LDAP clients hold pooled connections, and closing one on a rate spike makes the application reconnect and retry, which is more load rather than less |
| `bind_rate_limit`, `bind_rate_burst` | int | `0` | **Binds** per second per client address, separately, because a rate loose enough for an application's searches says nothing about somebody working through a password list. Unlike the request rate, this one **ends the session**: that rate is a credential attack, and leaving the connection open is leaving it somewhere to keep trying |
| `log_requests` | bool | `false` | An access line per request. A directory front carries a great many searches |
| `log_binds` | bool | `true` | An access line for every bind and its outcome: who authenticated, from where, as whom, and whether it worked |
| `log_writes` | bool | `true` | An access line for every operation that changes the directory, and for every refusal |
| `alert_on_deny` | bool | `true` | A security event per refusal |
| `proxy_protocol` | bool | `false` | Send a PROXY protocol v2 header to the directory |

#### server.listeners[].ldap.rules[]

| Key | Type | Description |
|-----|------|-------------|
| `name` | string | Required; names the rule in the logs and the counters |
| `action` | `allow`, `deny`, `observe` | Default `allow`. `observe` records the request and keeps looking |
| `clients` | list of CIDR | Networks the client is in |
| `bind_dns` | list of DN | The identities this rule covers. A name covers itself and everything below it, so `ou=services,dc=example,dc=com` covers every service account in that container. The **empty** name matches an unbound or anonymous connection, which is how "before you authenticate, you may do this and no more" is written |
| `methods` | list | The bind methods this rule covers, for a rule about *how* the connection authenticated rather than as whom |
| `operations` | list | `bind`, `search`, `compare`, `modify`, `add`, `delete`, `modify_dn`, `extended`, `abandon`, `unbind` |
| `access` | list | `read`, `write`, `bind`: what the operation *does*. The durable way to write a policy, because it does not change when a later revision adds an operation |
| `base_dns` | list of DN | The suffixes the request may name |
| `deny_dns` | list of DN | Suffixes this rule does not cover even when `base_dns` would match: all of the directory except the administrators container |
| `scopes` | list | `base`, `one`, `sub`. A rule that omits them covers any scope, which on a wide base is usually not what was meant |
| `attributes` | list | The attributes a request may name and an answer may carry. Naming them turns the answer policy inside out: anything outside the list is removed from an entry |
| `deny_attributes` | list | Refused or stripped for this rule's traffic, **in addition to** the listener's list |
| `max_entries` | int | This rule's own bound on entries returned |
| `max_filter_terms`, `max_filter_depth` | int | This rule's own filter bounds. A rule does not cover a filter past its own bound, so the next rule -- or the default -- decides; matching and then allowing would make the bound a suggestion |
| `allow_leading_wildcard` | bool | This rule's own setting |
| `schedule` | object | `{days, from, to, timezone}`; a window whose `to` is before its `from` spans midnight and belongs to the day it started on |

**The built-in `deny_attributes` list** is the password and key material of the
directories people actually run:

```
userPassword  unicodePwd  dBCSPwd  ntPwdHistory  lmPwdHistory  pwdHistory
supplementalCredentials  msDS-ManagedPassword  ms-Mcs-AdmPwd
ms-Mcs-AdmPwdExpirationTime  krbPrincipalKey  sambaNTPassword
sambaLMPassword  sambaPasswordHistory  userPKCS12
```

Naming `deny_attributes` replaces it rather than adding to it, and validation
warns if the replacement drops `userPassword`. A rule's own `deny_attributes`
adds to whichever list is in force. An attribute's transfer option is not part
of its name, so a policy about `userCertificate` covers
`userCertificate;binary`.

**What is checked before the rules, and cannot be shadowed.** A message the
relay could not parse; a message past `max_message_bytes`; message identifier
zero, which is reserved for the server's unsolicited notification; the request
and bind rate limits; the client list; a response the directory sent against a
message identifier no request used; and a bind carrying a password on an
unprotected connection.

**`read_only` and `base_dns` are checked before any rule and cannot be
overridden by one.** A read-only listener one rule could write through is not a
read-only listener, and a listener for one naming context that could be asked
about another is not a listener for one naming context.

**The identity is the directory's to grant.** The relay watches the bind
*response*, not the request: the identity a rule names is adopted only when the
directory answers success, because believing the request would let anyone be
anybody by binding with the wrong password. A StartTLS upgrade discards it, as
RFC 4513 §5.1.7 requires -- and because keeping it would let a client bind in
the clear and then hide behind TLS with what that bind gave it.

**A password never reaches a log**, and neither does a filter's assertion
value. The filter's *shape* is logged -- how many terms, how deep, whether a
leading wildcard -- and what it was looking for is not: a search for a person's
name is that person's business, and a log of every one is a surveillance record
the estate did not ask for.

Counters: `ldap_sessions`, `ldap_sessions_open`, `ldap_requests`, `ldap_binds`,
`ldap_bind_failures`, `ldap_searches`, `ldap_writes`, `ldap_entries`,
`ldap_stripped`, `ldap_truncated`, `ldap_starttls`, `ldap_denied`,
`ldap_would_deny`, `ldap_malformed`, `ldap_rejected`, `ldap_rate_limited`,
`ldap_upstream_failed`, `ldap_outstanding`. Refusals are `ldap_denied` for the
ban triggers, and the fine-grained reason is in the refusal counters:
`client_not_allowed`, `tls_handshake`, `upstream_tls`, `max_connections`,
`rate_limited`, `bind_rate_limited`, `malformed`, `malformed_response`,
`message_too_large`, `framing`, `message_id_zero`, `wrong_direction`,
`wrong_direction_response`, `anonymous_bind`, `unauthenticated_bind`,
`bind_method`, `sasl_mechanism`, `bind_in_clear`, `bind_failed`, `version`,
`read_only`, `base_dn`, `extended`, `control`, `filter_terms`, `filter_depth`,
`leading_wildcard`, `filter_attribute`, `attribute`,
`attribute_not_allowed`, `rule`, `default_deny`, `max_entries`,
`unsolicited_entry`, `too_many_outstanding`, `starttls_unavailable`,
`starttls_twice`, `starttls_outstanding`.

### server.listeners[].snmp (kind: snmp)

SNMP runs every switch, router, printer, uninterruptible supply and building
controller in an estate, and versions 1 and 2c authenticate with a community
string: a cleartext password in every datagram, `public` to read and
`private` to write on anything nobody reconfigured, with no integrity, no
replay protection and no confidentiality. One datagram reads a device's whole
configuration; one changes it. Version 3 has a real security model and also
has `noAuthNoPriv`, which is version 2c with more fields.

The devices cannot be fixed -- they are switches and printers and building
controllers with firmware nobody ships updates for -- so the relay is the
only place a policy can live.

Five things are deliberate in the data path.

**Every message is parsed whole.** A relay that forwarded what it could not
read would be forwarding what it could not decide about, and the agent behind
it will read those octets somehow.

**The amplification is bounded in two directions.** SNMP is a classic
reflection vector: a forty-octet GETBULK with a repetition count of ten
thousand asks for a response of megabytes, to whatever address the datagram
claimed to come from. So a repetition count past `max_repetitions` is
*lowered* rather than refused -- a poller asking for more than it should get
still gets an answer, which is what keeps the bound deployable in an estate
whose pollers nobody can reconfigure -- and a response past
`max_response_bytes`, or more than `max_response_ratio` times the size of the
request that asked for it, is refused outright.

**A response is matched to its request.** The request identifier is the only
thing in the protocol that pairs them, so an answer nobody asked for is
recognisable -- and on UDP that is the shape of a response-spoofing attack on
the manager: an answer to a question it did ask, from somewhere else,
arriving first. The table of outstanding requests is bounded by
`max_pending`, and a full table refuses the new request rather than
forgetting an old one, because forgetting would make that pairing unreliable.

**The version can be rewritten downwards.** `upgrade_version` is the secure
upgrade: a manager speaks v3 with authentication to this relay, or TLS on the
stream side, and the relay speaks v2c to a switch whose firmware has neither,
with an `upstream_community` the manager never needs to know. A response is
rebuilt in the version its request arrived in, so the manager sees the version
it spoke.

Two rewrites this relay will not do, both because it holds no USM keys and
will not forge an authentication that did not happen. It cannot *produce* v3,
which is refused at load. And it cannot downgrade a v3 **request**: the
answer would come back as v2c and handing that to a v3 manager means
authenticating it with a key that is not here, so such a request is refused
rather than half-translated. A v3 **notification** downgrades cleanly,
because nothing comes back -- a modern device sending v3 traps to a collector
that understands only v2c is exactly what `traps: true` with
`upgrade_version: v2c` is for.

**The values are not interpreted.** A binding's type and extent are read;
what a `Counter64` *means* is not. A policy about values would need a MIB per
estate, and a relay that mis-decoded one would corrupt a reading nobody could
trace.

A listener always accepts the streams of RFC 3430 on its port, and
`transport: udp` (the default) adds the datagram socket every poller and
every agent actually speaks. RFC 6353 TLS is the stream half, on port 10161;
DTLS on 10162 is not implemented, so a listener that is TLS throughout is
`transport: tcp`.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `mode` | `reverse`, `forward` | `reverse` | `reverse`: managers send here and the relay forwards to the agents. `forward`: this listener is the controlled egress a management station uses to reach agents elsewhere |
| `upstream` | string | required | The agent pool a request goes to |
| `transport` | `udp`, `tcp` | `udp` | Whether the datagram socket is opened as well as the stream one. Streams are always accepted |
| `traps` | bool | `false` | A trap listener rather than an agent front: the messages arrive from agents and go to a collector, which is the opposite direction and a different policy. Port 162 rather than 161 |
| `tls_mode` | `implicit`, `none` | `implicit` with a `tls` section | RFC 6353: TLS from the first octet on the stream side. This is the half of the secure upgrade that faces the management station |
| `upstream_tls_mode` | `none`, `implicit` | `none` | Whether this listener speaks RFC 6353 TLS to the agent |
| `upstream_tls` | object | | Verification of the agent when `upstream_tls_mode` is not `none` |
| `allow_clients` | list of CIDR | all | Networks a manager may send from. On this protocol this is the most valuable line in the file after `read_only`, because a community string is not a secret in any useful sense |
| `deny_clients` | list of CIDR | | Evaluated before `allow_clients` |
| `versions` | list | all | `v1`, `v2c`, `v3`. "v3 only" is the single most useful line an operator can write here |
| `communities` | list | any | The community strings v1 and v2c may use. Empty allows any, which validation warns about: the defaults are known to everyone and scanned for constantly |
| `users` | list | any | The v3 USM user names |
| `min_security_level` | `noAuthNoPriv`, `authNoPriv`, `authPriv` | `noAuthNoPriv` | The lowest v3 level accepted. `noAuthNoPriv` refuses nothing, so a listener that went to the trouble of requiring v3 usually wants `authNoPriv` at least |
| `read_only` | bool | `false` | Refuse every SetRequest, for every client, before any rule is read. SNMP has exactly one writing operation, so this is a one-line policy covering the whole of "nobody reconfigures anything through this relay". **No rule can override it** |
| `upgrade_version` | `v1`, `v2c` | | Rewrite the version a message is forwarded in. `v3` is refused at load |
| `upstream_community` | string | the arriving one | The community string sent to the agent, which is what lets the manager stop knowing it |
| `rules` | list | | Per-message rules, first match wins; see below |
| `default_action` | `deny`, `allow` | `deny` | What a message no rule matched gets |
| `deny_response` | `error`, `drop`, `close` | `error` | `error` sends the Response PDU an agent would send -- `noAccess` on v2c and v3, `noSuchName` on v1, which is the only word v1 has for it -- and every manager already knows how to display that. `drop` is a timeout to the manager, and a timeout is what a dead device looks like. `close` ends a stream session |
| `max_repetitions` | int | `100` | A GETBULK's repetition count, which is the amplification factor of the best-known SNMP reflection attack. `0` leaves it unbounded, which validation warns about |
| `max_var_binds` | int | `128` | Variable bindings one message may carry |
| `max_response_bytes` | int | `8192` | One response. The other half of the amplification bound: `max_repetitions` bounds what was asked for and this bounds what came back, and an agent that ignores the first still cannot get past the second |
| `max_response_ratio` | int | `50` | Refuse a response more than this many times the size of its request. The bound that is about *reflection* rather than size: a large answer to a large question is a walk, and a large answer to a tiny question is an amplifier |
| `max_pending` | int | `32` | Requests outstanding towards agents, per datagram listener and per stream session |
| `max_connections` | int | `32` | Live stream sessions |
| `idle_timeout` | duration | `60s` | A stream session that says nothing |
| `request_timeout` | duration | `5s` | How long the agent has to answer before its answer is too late to forward |
| `connect_timeout` | duration | `5s` | Dialling the agent on the stream path |
| `max_message_bytes` | int | `8192` | One message; the protocol's own floor is 484 octets and 1472 is what fits an Ethernet datagram. A message past this is refused unread |
| `rate_limit`, `rate_burst` | int | `0` | Messages per second per client address. An SNMP poll is periodic and its rate is known, so this bound is unusually easy to set correctly |
| `log_messages` | bool | `false` | An access line per message. A poller asks the same questions every thirty seconds, so this is a lot of lines |
| `log_writes` | bool | `true` | An access line for every SetRequest and every refusal, leaving the polling alone: what was *changed* through this relay is the record an estate is asked for |
| `alert_on_deny` | bool | `true` | A security event per refusal |
| `proxy_protocol` | bool | `false` | Send a PROXY protocol v2 header to the agent on the stream path |

#### server.listeners[].snmp.rules[]

| Key | Type | Description |
|-----|------|-------------|
| `name` | string | Required; names the rule in the logs and the counters |
| `action` | `allow`, `deny`, `observe` | Default `allow`. `observe` records the message and keeps looking, which is how a rule is tried on live traffic before it decides anything |
| `clients` | list of CIDR | Networks the manager is in |
| `versions` | list | The protocol versions this rule covers |
| `communities` | list | The community strings (v1 and v2c) this rule covers. A rule naming communities cannot match a v3 message, and one naming users cannot match a v2c one: letting either cross over would make a rule written about one authentication scheme apply to another |
| `users` | list | The v3 USM user names this rule covers |
| `min_security_level` | string | The lowest v3 level this rule covers, so that "this subtree only with authPriv" is one rule |
| `pdus` | list | Operations by name: `get`, `get_next`, `get_bulk`, `set`, `trap`, `trap_v1`, `inform`, `response`, `report` |
| `access` | list | `read`, `write`, `notify`: what the operation *does*. The durable way to write a policy, because it does not change when a later revision adds an operation |
| `oids` | list | Object identifier subtrees, as `1.3.6.1.2.1` or a single object. A message naming an object outside all of them does not match. The comparison is per sub-identifier, so `1.3.6.1.2.1` does not cover `1.3.6.1.2.11` -- a policy written with string prefixes allows a subtree nobody named |
| `deny_oids` | list | Subtrees this rule does not cover even when `oids` would match, which is how an exception inside an allowed subtree is written: all of mib-2 except the ARP table |
| `write_oids` | list | Apply instead of `oids` to a SetRequest, so one rule can allow a wide read and a narrow write. The write list *replaces* the read list rather than adding to it |
| `max_repetitions` | int | This rule's own GETBULK bound. A rule does not cover traffic past its own bound, so the next rule -- or the default -- decides; matching and then allowing would make the bound a suggestion |
| `contexts` | list | The v3 context names this rule covers, for an engine that fronts several agents |
| `schedule` | object | `{days, from, to, timezone}`; a window whose `to` is before its `from` spans midnight and belongs to the day it started on |

**What is checked before the rules, and cannot be shadowed.** A message the
relay could not parse is refused whether or not the listener is enforcing:
forwarding what it cannot decide about would hand the agent octets it will
read somehow. So are the message and response bounds, the repetition bound,
the response ratio, an answer no request matched, a message arriving from the
agent side that is not an answer, the rate limit and the client list. A relay
whose amplification bounds were in shadow mode would be a working amplifier.

**`read_only` is checked before any rule and cannot be overridden by one.**
A read-only listener that a single rule could write through is not a
read-only listener.

**An encrypted v3 payload is decided about, not inspected.** When the
security level is `authPriv` the scoped PDU is ciphertext: the header parses,
the user and the level are checked, and there is no operation and no object
identifier to decide about. The decision says `snmp_encrypted` rather than
refusing traffic the listener was configured to carry or pretending it was
inspected.

**A community string is never written to a log.** It is a credential, and an
access log or security event that printed every guessed one would be a list
of the estate's passwords with a timestamp beside each. The v3 user name *is*
logged, because it is an identity rather than a secret.

Counters: `snmp_messages`, `snmp_sessions`, `snmp_sessions_open`,
`snmp_reads`, `snmp_writes`, `snmp_traps`, `snmp_denied`, `snmp_would_deny`,
`snmp_malformed`, `snmp_rejected`, `snmp_rate_limited`, `snmp_amplified`,
`snmp_truncated`, `snmp_upgraded`, `snmp_timed_out`, `snmp_upstream_failed`,
`snmp_unsolicited`, `snmp_pending`. Refusals are `snmp_denied` for the ban triggers, and the
fine-grained reason is in the refusal counters: `client_not_allowed`,
`tls_handshake`, `upstream_tls`, `malformed`, `malformed_response`, `message_too_large`,
`framing`, `max_connections`, `rate_limited`, `version`, `community`, `user`,
`security_level`, `read_only`, `direction`, `var_binds`, `rule`,
`default_deny`, `max_repetitions`, `response_too_large`, `response_ratio`,
`response_too_late`, `unsolicited_response`, `encrypted_response`,
`wrong_direction`, `too_many_pending`, `upgrade_failed`.

### server.listeners[].dhcp (kind: dhcp)

DHCP is the one protocol where **answering** is the attack. A client broadcasts
"who will configure me", and it believes whatever answers first: its address, its
**default route**, its **resolvers**, its **proxy** (option 252) and, on a
machine that boots from the network, the **file it boots** (options 66 and 67).
Nothing in the exchange authenticates anybody -- a transaction identifier and a
hardware address, both visible to everyone on the segment -- and the client has
no address yet, so it cannot even be told apart by one.

That makes this the one relay kind here whose interesting half faces *upstream*.
Five things are deliberate.

**A reply from an address this listener does not admit as a server is dropped
before it is read.** Every switch vendor sells this as DHCP snooping and
implements it as a trusted port; here it is `allow_servers`, and it is **not
shadowable**: a listener that evaluated the list without enforcing it would be a
listener that relays a rogue server's answer and writes it down. Leaving the list
out is not leaving it open -- it is filled in from the `upstream` pool's own
endpoints at load, because an operator who wrote none meant "the servers I
configured".

**The options a server sends are a configuration, not data.** Option 121 and
Microsoft's 249 are a routing table in a broadcast reply -- the most direct
interception in the protocol. Option 252 is a proxy. Options 66, 67 and 43 are
what a machine boots. Each is an option some estate legitimately needs, so each
is a decision: `deny_options` has a built-in list, `allow_options` turns the
policy inside out, and `on_denied_option` defaults to `strip` because a client
that still gets its address and no longer gets a route it should not have is a
client that works.

**The addresses in a reply are checked against the estate's own.** An operator
knows their gateways, their resolvers and their boot servers; a reply naming
anything else is wrong *whoever sent it*, and that check catches a compromised
real server as surely as a rogue one. The boot server is checked in both places
it lives -- option 66 and the `siaddr` header field -- because a check on one has
a way round it.

**A client does not get to say which segment it is on.** RFC 3046 §2.1 says a
relay discards the agent information option arriving from a client, because the
option exists so that the *relay* tells the server which circuit the request came
from. So option 82 from a client is stripped and this relay adds its own; on the
way back it removes what it added, because the option is a note between the relay
and the server.

**The starvation bound is keyed on the hardware address.** Pool exhaustion is one
host sending thousands of DISCOVERs with a made-up address in each, and a rate
limit keyed on the source address would see one sender doing nothing unusual.
`max_clients` bounds the table that does the keying, because otherwise the flood
of new addresses would exhaust that instead.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `mode` | `reverse`, `forward` | `reverse` | `reverse`: clients send here and the relay forwards to the servers. `forward`: this listener is the controlled egress a downstream relay agent uses to reach a server elsewhere |
| `upstream` | string | required | The server pool |
| `allow_servers` | list of CIDR | the pool's endpoints | The addresses a reply may come from, and the most valuable line in the file. Empty means the endpoints of `upstream`, so it is never open by accident; a pool whose endpoints are named by hostname makes this required, because guessing is the wrong kind of helpful on the one check this kind most depends on |
| `allow_clients` | list of CIDR | all | Networks a message may arrive from. On a segment this is every client -- a client with no address sends from `0.0.0.0`, and the unspecified address is admitted whatever the list says, because refusing it would refuse every first-time client. It is the useful control on a listener that fronts **other relay agents** |
| `deny_clients` | list of CIDR | | Evaluated before `allow_clients`, and it beats the unspecified address too |
| `message_types` | list | `[discover, request, decline, release, inform]` | Types a client may send. The default leaves out the **lease-query family** (RFC 4388): that is a relay agent's own diagnostic, and an inventory of every lease in the estate to anything else |
| `deny_options` | list | the built-in list | Options a **server** may not send; see below for the built-in list. Setting the list **replaces** it. An option may be named or numbered, so an estate's own vendor option can be named |
| `allow_options` | list | | The positive model: an option outside the list is removed. On a network whose clients need six options this is shorter and safer than a deny list. The message type and the server identifier are always carried, because a reply without them is not a reply |
| `on_denied_option` | `strip`, `deny` | `strip` | `strip` removes the option and forwards the rest. `deny` refuses the whole reply, which leaves the client with **no address at all** -- which is why it is not the default |
| `deny_requested_options` | list | | Options a client may not **ask** for, in its option 55 parameter list. The ask is trimmed rather than the message refused: a client that asked for a proxy and is not told about one is a client that works |
| `allow_gateways` | list of IPv4 | any | The addresses option 3 may name |
| `allow_resolvers` | list of IPv4 | any | The addresses option 6 may name |
| `allow_boot_servers` | list of IPv4 | any | The addresses option 66 and `siaddr` may name |
| `allow_routes` | list of CIDR | none | The destinations options 121 and 249 may carry, for an estate that uses them. Containment, not equality: `10.0.0.0/8` allows a route to `10.1.0.0/16` and **not** a default route. A route outside the list is refused and the refusal names the route |
| `boot_files` | list of pattern | any | Shell patterns the boot filename may match, checked in both places it lives (option 67 and the `file` field) |
| `min_lease_time`, `max_lease_time` | duration | `0` | Bound the lease a server may hand out. A lease past the bound is **shortened**, not refused, so the client still boots. A very long lease is an address pool exhausted by every device that ever visited |
| `require_client_id_match` | bool | `false` | Refuse a message whose option 61 names a different hardware address from the header. Only the Ethernet form is compared, because RFC 2132 allows any opaque value; a real signal, and there are real clients that get it wrong, so it is a decision rather than a default |
| `refuse_hidden_options` | bool | `true` | Refuse a message that carried an option in the `sname` or `file` field (option 52) or split across instances (RFC 3396). Both are legal, almost nothing sends them, and both make one message say different things to different parsers. **Not shadowable** |
| `max_hops` | int | `4` | The hops field, which counts the relay agents a message has crossed. RFC 2131 makes 16 the outer limit |
| `relay_address` | IPv4 | required in reverse mode | What this relay puts in `giaddr`, which tells the server which segment to allocate from. A relay agent that left it empty would be asking the server to answer a broadcast it never saw. An existing `giaddr` from a downstream agent is **not** overwritten, because that is where the reply has to go back to |
| `circuit_id`, `remote_id` | string | | The two suboptions of RFC 3046's option 82. Empty leaves the option out |
| `on_client_agent_option` | `strip`, `deny` | `strip` | What to do when a client sends option 82. `strip` is what RFC 3046 §2.1 requires |
| `rules` | list | | Per-message rules, first match wins; see below |
| `default_action` | `allow`, `deny` | `allow` | Unlike the other relay kinds here the default is **allow**. DHCP is infrastructure: a listener that refused every request until somebody wrote a rule would stop an estate booting, and the protections in this kind are the answer policy and the server list, which are on by default and do not depend on a rule existing |
| `deny_response` | `drop`, `nak` | `drop` | `drop` leaves the client retrying, which is what it does when nothing answers. `nak` sends a DHCPNAK, which makes a client stop and start over -- honest, and also a way to stop a client dead, so not the default. Only a REQUEST is NAKed: DHCPNAK is defined as the answer to a request for a particular address |
| `max_pending` | int | `256` | Requests outstanding towards servers. A full table refuses the new request rather than forgetting an old one, because forgetting is what would make a reply undeliverable to the client that actually asked |
| `request_timeout` | duration | `10s` | How long a server has to answer before its answer is too late to pair |
| `max_message_bytes` | int | `1500` | One message. A message past this is refused unread |
| `rate_limit`, `rate_burst` | int | `0` | Messages per second per **hardware address** |
| `max_clients` | int | `8192` | Distinct hardware addresses tracked at once |
| `log_messages` | bool | `false` | An access line per message |
| `log_leases` | bool | `true` | A line for every address handed out: which hardware address, which vendor prefix, which address, for how long, from which server, what it was told and what it asked for. The record an estate is asked for, and the beginning of an asset inventory |
| `alert_on_deny` | bool | `true` | A security event per refusal |

#### server.listeners[].dhcp.rules[]

| Key | Type | Description |
|-----|------|-------------|
| `name` | string | Required; names the rule in the logs and the counters |
| `action` | `allow`, `deny`, `observe` | Default `allow`. `observe` records the message and keeps looking |
| `clients` | list of CIDR | Networks the message arrived from |
| `hardware_addresses` | list | Each either a whole address (`02:11:22:33:44:55`) or a **vendor prefix** (`02:11:22`), which is what a rule about "the telephones" is actually written with |
| `message_types` | list | The types this rule covers |
| `vendor_classes`, `user_classes` | list of pattern | Options 60 and 77 as shell patterns. `PXEClient*` is what every PXE client sends |
| `deny_options` | list | Refused for this rule's traffic, **in addition to** the listener's list, and a rule's own deny beats its own permission below |
| `allow_gateways`, `allow_resolvers`, `allow_boot_servers` | list of IPv4 | This rule's own address lists, replacing the listener's for its traffic |
| `allow_routes` | list of CIDR | This rule's own route list |
| `boot_files` | list of pattern | This rule's own boot filename patterns |
| `max_lease_time` | duration | This rule's own lease bound |
| `circuit_id` | string | Overrides the listener's circuit identifier, so a rule about one segment can tell the server which segment it is |
| `schedule` | object | `{days, from, to, timezone}`; a window whose `to` is before its `from` spans midnight and belongs to the day it started on |

**Saying what an option may contain is how a rule allows it.** This is the one
turn in the kind worth reading twice, and it is the same one the LDAP attribute
policy makes. The built-in `deny_options` list strips the boot options from every
reply -- which is right for a network with no PXE clients and wrong for the one
segment that has them. A rule with `allow_boot_servers` or `boot_files` is a rule
about machines that boot from the network, so those options are *not* stripped
from its traffic: they are checked against the list instead. The same holds for
`allow_routes` and the two route options. Without that, "the build segment may be
told a boot server and nothing else may" could not be written at all.

**The built-in `deny_options` list** is the options that carry a machine's
configuration rather than a value it displays:

```
121 classless_static_route   249 ms_classless_static_route   33 static_route
252 wpad_url                 66 tftp_server                  67 boot_file
43 vendor_specific
```

Naming `deny_options` replaces it rather than adding to it, and validation warns
if the replacement drops the route option or WPAD. A rule's own `deny_options`
adds to whichever list is in force.

**What is checked before the rules, and cannot be shadowed.** A reply from an
address that is not in `allow_servers`; a message the relay could not parse; a
message past `max_message_bytes`; a message carrying an option in a header field
or split across instances; the hop bound; the rate limit; the pending bound; the
lease bounds; a message type arriving from the wrong side (a DHCPOFFER from the
client side, or a DHCPDISCOVER from a server); and a malformed option value,
because a client would read it somehow and "somehow" is where two readings
differ.

**A reply is broadcast only when there is nowhere to unicast to.** RFC 2131 §4.1
says to honour the broadcast flag, and a client that sent from `0.0.0.0` has no
address to unicast to whatever its flags say. A request relayed from another agent,
or a renewal from a client that already has an address, is answered where it came
from. Broadcasting needs a route for `255.255.255.255` on the listener's own
interface: on Linux that is usually `ip route add 255.255.255.255/32 dev <iface>`,
and it is a deployment matter rather than something the proxy can arrange.

**A listener takes no `tls` section and binds no TCP port.** DHCP has no stream
transport and no transport security of any kind, so a listener carrying a
certificate would be promising something the protocol cannot do; validation
refuses it.

**DHCPv6 (RFC 8415) is not implemented**, and this kind does not pretend
otherwise. It is a different packet format with different message types, a
different relay mechanism and its own options; reading it as if it were DHCPv4
would be worse than not reading it. A segment that runs both needs its v6
relaying done elsewhere, and `docs/RFC.md` says so in the table.

Counters: `dhcp_messages`, `dhcp_discovers`, `dhcp_requests`, `dhcp_replies`,
`dhcp_leases`, `dhcp_releases`, `dhcp_denied`, `dhcp_would_deny`, `dhcp_rogue`,
`dhcp_stripped`, `dhcp_malformed`, `dhcp_rejected`, `dhcp_rate_limited`,
`dhcp_timed_out`, `dhcp_upstream_failed`, `dhcp_unsolicited`, `dhcp_pending`,
`dhcp_clients`. **`dhcp_rogue` is the one to alert on**: it counts the replies
from an address this listener does not admit as a server, which is somebody
answering on the segment. `dhcp_stripped` is the one to read next -- a route, a
proxy or a boot file removed from a reply. Refusals are `dhcp_denied` for the ban
triggers, and the fine-grained reason is in the refusal counters:
`client_not_allowed`, `rogue_server`, `malformed`, `malformed_reply`,
`malformed_option`, `message_too_large`, `reply_too_large`,
`reply_from_client_side`, `wrong_direction`, `unsolicited_reply`,
`hidden_options`, `client_id_mismatch`, `message_type`, `too_many_hops`,
`too_many_pending`, `rate_limited`, `client_agent_option`, `option_stripped`,
`option_denied`, `boot_server_not_allowed`, `boot_file_not_allowed`, `rule`,
`default_deny`, `unencodable`, `unencodable_reply`.

### server.listeners[].tftp (kind: tftp)

TFTP is the protocol under provisioning. A switch pulls its firmware over it, a
machine with no operating system yet pulls a boot image, a telephone pulls its
configuration, and an engineer pushes a running configuration off a router with
it. It has **no authentication of any kind**: no user, no password, no token, no
transport security, and no extension that adds one. A request is a filename and
a mode, and a server that receives one answers it.

The clients are switches, telephones and boot ROMs, so none of that can be
fixed where it lives. The relay is the only place a policy can be, and there
are exactly four things such a policy can be about.

**The filename is read as a path and refused by shape.** There is no identity,
so the decision is the address it came from and the path it asked for -- and a
path is where this protocol has been exploited for forty years. A deny list of
*strings* is a list of the spellings somebody thought of: it stops
`../../etc/shadow` and not `..\..\etc\shadow`, stops that one and not
`/etc/shadow`, stops that one and not `secret.txt.`, which Windows opens as
`secret.txt`. So the name is classified and the **class** is refused:

| Class | What it is |
|-------|------------|
| `traversal` | a `..` element anywhere, over either separator. Any of them, not only the ones that escape: `firmware/../firmware/x` resolves inside the directory on a server that normalises the name and somewhere else on one that walks it a symbolic link at a time |
| `absolute` | rooted at the top of the file system, by either separator |
| `drive` | a Windows drive letter (`c:\x`) or a UNC prefix (`\\host\share\x`), the second of which is a request the server makes to a third machine |
| `backslash` | a backslash elsewhere in the name, which is a separator on a server running on Windows and an ordinary character on one that is not |
| `trailing` | an element ending in a space or a dot, both of which Windows strips when it opens the file |
| `non_ascii` | a byte above 0x7f. RFC 1350 says the filename is netascii, so this is outside the standard -- but devices that send UTF-8 names exist |
| `nul`, `control`, `empty` | a name this relay and the server would read differently. **These three can never be allowed**, and they are refused in `policy: {mode: shadow}` too: a decision about a name the server will not see is not a decision |

`allow_path_classes` names the ones this listener accepts besides an ordinary
relative path; a rule's own list widens it for that rule's traffic only, which
is how one legacy server that really does serve absolute paths is written down
without opening the class for everything.

**A write is a separate decision from a read, and the default is no.** A write
is a device putting a file onto the server, which is how a configuration leaves
an estate and how firmware arrives in it. `operations` defaults to `[read]`.

**The amplification is bounded by rewriting rather than by refusing.** A
twenty-octet read request yields a whole file to whatever address the datagram
claimed to come from, and RFC 7440's `windowsize` multiplies it: a window of
sixty-four is sixty-four data packets per acknowledgement. A request asking for
more than `max_window_size` or `max_block_size` is **rewritten to the bound and
forwarded**, because a switch whose TFTP client nobody can reconfigure is the
normal case and a bound that only refuses is a bound somebody turns off. Two
things cannot be lowered and are refused instead: a `tsize` on a write
declaring more than `max_transfer_bytes`, because the client has said in
advance how much it intends to send; and a server that acknowledges a *larger*
block or window than it was offered, because the two ends would then disagree
about how much is coming.

**A transfer speaks to exactly two addresses.** TFTP moves to an ephemeral port
pair after the first packet: the server answers from a new port, and the rest of
the transfer runs between that port and the client's. So each transfer here gets
a socket of its own, and only the client's transfer identifier and the first
port the server answered from may use it. A datagram from anywhere else is
dropped and counted rather than answered -- answering is how a relay becomes a
reflector -- and on a protocol with no integrity protection that third address
is the whole attack, because a packet injected into a firmware transfer *is*
firmware.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `mode` | `reverse`, `forward` | `reverse` | `reverse`: clients send here and the relay forwards to the servers. `forward`: this listener is the controlled egress a device uses to reach a server elsewhere |
| `upstream` | string | required | The server pool |
| `allow_clients` | list of CIDR | all | Networks a client may send from. On this protocol it is the only identity there is, and validation warns when it is empty |
| `deny_clients` | list of CIDR | | Evaluated before `allow_clients` |
| `operations` | list | `[read]` | `read`, `write`. The default is deliberate: see above |
| `modes` | list | `[octet, netascii]` | `octet`, `netascii`, `mail`. `mail` is obsolete -- RFC 1350 removed it -- and asked the server to deliver the file as mail to the address in the filename field, so a server that still implements it is a mail injection vector reachable with one datagram |
| `allow_path_classes` | list | plain only | Path classes accepted besides an ordinary relative path: `absolute`, `backslash`, `drive`, `traversal`, `trailing`, `non_ascii`. `nul`, `control` and `empty` are refused at load |
| `directories` | list | any | The directories a filename may name, compared **element by element** from the top of what the server serves, so `firmware` does not cover `firmware-staging`. A name outside all of them is refused before the rules and before `default_action: allow` |
| `deny_directories` | list | | Directories no rule can allow, which is how an exception inside an allowed tree is written |
| `filenames` | list of pattern | any | Shell patterns (`firmware/*.bin`), matched against the whole cleaned path and against its last element, so either spelling says what it looks like |
| `deny_filenames` | list of pattern | | Evaluated first; no rule can override it |
| `max_depth` | int | `8` | Path elements one name may have |
| `max_filename_bytes` | int | `256` | The filename field |
| `max_transfer_bytes` | int | `67108864` | One transfer, in either direction. This is the bound that matters on a write, because a write has no natural end: the client stops when it stops |
| `max_block_size` | int | `1468` | RFC 2348's `blksize`. The default is a data packet that still fits an Ethernet frame; a larger block fragments at the IP layer, which is a lever rather than a feature |
| `max_window_size` | int | `4` | RFC 7440's `windowsize`: data packets per acknowledgement, and this protocol's amplification factor |
| `max_transfers` | int | `64` | Transfers in flight on this listener. Each one holds a socket |
| `max_transfers_per_client` | int | `8` | Transfers in flight per client address. A device with eight is a device that has stopped reading its answers |
| `rules` | list | | Per-transfer rules, first match wins; see below |
| `default_action` | `deny`, `allow` | `deny` | What a request no rule matched gets |
| `deny_response` | `error`, `drop` | `error` | `error` sends an error packet, which every client displays and stops on. `drop` sends nothing, so the client retransmits until it times out -- which is why `error` is the default: a device that is told no stops |
| `transfer_timeout` | duration | `5m` | One whole transfer |
| `idle_timeout` | duration | `15s` | A transfer that has gone quiet, which is a few of the protocol's own retransmissions |
| `rate_limit`, `rate_burst` | int | `0` | Requests per second per client address |
| `log_transfers` | bool | `true` | An access line per transfer: who, which direction, which path, how much moved, how it ended. This is the record an estate is asked for when somebody wants to know which switch got which firmware |
| `alert_on_deny` | bool | `true` | A security event per refusal |

#### server.listeners[].tftp.rules[]

| Key | Type | Description |
|-----|------|-------------|
| `name` | string | Required; names the rule in the logs and the counters |
| `action` | `allow`, `deny`, `observe` | Default `allow`. `observe` records the request and keeps looking, which is how a rule is tried on live traffic before it decides anything |
| `clients` | list of CIDR | Networks the client is in |
| `operations` | list | `read`, `write` |
| `modes` | list | The transfer modes this rule covers |
| `directories` | list | The directories this rule covers |
| `deny_directories` | list | Directories this rule does not cover even when `directories` would match |
| `filenames`, `deny_filenames` | list of pattern | This rule's own patterns, against the cleaned path |
| `allow_path_classes` | list | Widens the listener's list for this rule's traffic only. The three classes the listener cannot allow, a rule cannot allow either |
| `max_transfer_bytes` | int | This rule's own transfer bound |
| `max_block_size`, `max_window_size` | int | This rule's own amplification bounds, so "this directory at a window of one" is one rule |
| `schedule` | object | `{days, from, to, timezone}`; a window whose `to` is before its `from` spans midnight and belongs to the day it started on. A firmware window is a schedule: writes allowed during the change window and refused outside it |

**What is checked before the rules, and cannot be shadowed.** A client outside
the address list; the rate limit; a packet the relay could not parse; a packet
on the request port whose opcode is not a request, because RFC 1350 gives that
port one job; a filename in the `nul`, `control` or `empty` class;
`max_filename_bytes` and `max_depth`; `max_block_size`, `max_window_size` and
`max_transfer_bytes`; a data packet larger than the block size the transfer
negotiated; and a datagram from an address that has no part in the transfer.

**A listener takes no `tls` section.** The protocol has no transport security
and no extension that adds one, so a listener carrying a certificate would be
promising something it cannot do; validation refuses it. There is no TCP port
either: `kind: tftp` binds UDP and nothing else.

**What this relay does not do is look inside a transfer.** What is in a
firmware image is the estate's business; that the image is one the policy
allows, of a size the policy allows, to a path the policy allows, is the
relay's. For content inspection of a file moving through an estate, the ICAP
and YARA paths on `sftp` and `ftp` are where that lives -- and both of those
protocols have a user.

Counters: `tftp_requests`, `tftp_transfers`, `tftp_transfers_open`,
`tftp_reads`, `tftp_writes`, `tftp_bytes_in`, `tftp_bytes_out`, `tftp_denied`,
`tftp_would_deny`, `tftp_path_refused`, `tftp_lowered`, `tftp_oversize`,
`tftp_malformed`, `tftp_rejected`, `tftp_rate_limited`, `tftp_timed_out`,
`tftp_upstream_failed`, `tftp_unsolicited`. `tftp_lowered` is the one to watch
first: it counts the requests whose block size or window this relay rewrote,
which says the amplification bound is working without anything being refused.
Refusals are `tftp_denied` for the ban triggers, and the fine-grained reason is
in the refusal counters: `client_not_allowed`, `rate_limited`, `malformed`,
`malformed_response`, `not_a_request`, `not_in_transfer`, `wrong_source`,
`wrong_direction`, `packet_too_large`, `block_too_large`, `path_traversal`,
`path_absolute`, `path_drive`, `path_backslash`, `path_trailing`,
`path_non_ascii`, `path_control`, `path_nul`, `path_empty`, `path_too_deep`,
`filename_too_long`, `directory_denied`, `directory_not_allowed`,
`filename_denied`, `filename_not_allowed`, `operation_not_allowed`,
`mode_not_allowed`, `rule`, `default_deny`, `block_size_invalid`,
`block_size_malformed`, `window_size_invalid`, `window_size_malformed`,
`timeout_malformed`, `transfer_size_malformed`, `transfer_too_large`,
`oack_malformed`, `oack_block_too_large`, `oack_window_too_large`,
`request_unencodable`, `too_many_transfers`, `too_many_per_client`,
`shutting_down`, `not_udp`.

### server.listeners[].ntp (kind: ntp)

A `kind: ntp` listener is an NTP and NTS security gateway: it reads every
packet, decides about it in the protocol's own terms, and compares the
servers behind it with each other.

Three jobs live on this port and only one of them is "forward a packet",
so they are kept apart deliberately:

- **forwarding** time packets between clients and servers, which is what
  this listener does;
- **authenticating** them, which belongs to whoever holds the key —
  symmetric keys this listener can check, and NTS it deliberately cannot;
- **keeping an accurate clock**, which is the local time daemon's job and
  not this relay's. A relay that tried to be a time source would be a
  time source nobody calibrated.

What a relay can do that a client cannot is **compare**. It sees every
server the estate has, measures each the same way, and can refuse to pass
on an answer from a server whose time disagrees with its peers or whose
own dispersion says not to trust it. A server that is reachable,
synchronised, authenticated and *wrong* is the case every other check
passes.

It works in both directions. `mode: reverse` (the default) fronts the
estate's own time servers: the devices point at this listener and it
forwards to them. `mode: forward` is the controlled egress towards
servers somewhere else, where `allow_servers` bounds the destinations.

Datagram only: no TCP port is bound, so nothing can connect to one and
hang. NTS key establishment is TCP and is a listener of its own
(`kind: ntske`, below).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `mode` | enum | `reverse` | `reverse` (clients here, servers upstream) or `forward` (this is the estate's egress) |
| `upstream` | upstream | required | The pool of time servers. Fewer than three warns: with two, a disagreement can be reported but the wrong clock cannot be identified |
| `versions` | list of int | `[3, 4]` | The protocol versions accepted. Versions 1 and 2 are accepted only when named, because a version 1 packet has no mode field; version 5 is `allow_version5` |
| `modes` | list | `[client, server]` | `client`, `server`, `symmetric_active`, `symmetric_passive`, `broadcast`. Modes 6 (control) and 7 (private, which `monlist` belongs to) are **always refused** and cannot be named |
| `allow_version5` | bool | `false` | Forward NTPv5 as opaque bytes, on a transaction socket of its own. It is never parsed with the version 4 parser |
| `peers` | list of CIDR | `[]` | The networks a symmetric or broadcast association may come from. Required when such a mode is accepted |
| `allow_manycast` | bool | `false` | Opt into manycast discovery |
| `manycast_responders` | list of CIDR | `[]` | The addresses a manycast answer may come from. Required with `allow_manycast` |
| `allow_clients` | list of CIDR | `[]` (any) | The networks a client may ask from. Empty warns: an open NTP port is also an amplifier |
| `deny_clients` | list of CIDR | `[]` | Refused whatever the allow list says |
| `allow_servers` | list of CIDR | `[]` (any) | The addresses this listener will send to, whatever the pool resolves to. The egress policy: a pool whose name starts resolving somewhere new does not quietly become a new destination, and an NTS key exchange that names another server cannot move the time traffic outside this list |
| `auth` | object | | Symmetric authentication with pre-shared keys, below |
| `nts` | object | | How Network Time Security is handled, below |
| `extensions` | object | | What extension fields a packet may carry, below |
| `quality` | object | | What is required of a server's answer, and how the servers are compared, below |
| `holdover` | object | | How long a server whose time cannot be verified is still used, below |
| `change_detection` | object | | Watch each server for a change in **what it is** rather than in what it answered, below |
| `kod` | object | | The kiss-o'-death policy, below |
| `interleaved` | bool | `true` | Accept interleaved mode, where a server's answer echoes its own previous transmit timestamp rather than the client's. It is how a server hands out a hardware-quality transmit timestamp; refusing it means refusing the most accurate exchange the protocol has |
| `learn` | object | | Learning mode, below |
| `trace` | object | | One line per packet, below |
| `max_packet_bytes` | int | `1280` | One packet; 48..9000. The header is 48 octets and NTS makes a packet a few hundred |
| `max_extensions` | int | `8` | Extension fields in one packet; 1..32 |
| `max_associations` | int | `16384` | Client associations held. An association is an address **and port**, so this is also what stops forged sources filling the table |
| `max_outstanding` | int | `4096` | Requests waiting for an answer. A separate table from the associations on purpose |
| `idle_timeout` | duration | `30m` | Forget an association that has said nothing |
| `request_timeout` | duration | `3s` | How long a server has to answer |
| `rate_limit`, `rate_burst` | int | `0` (none) | Packets a second from one client address. Unset warns |
| `prefix_rate_limit`, `prefix_rate_burst` | int | `0` (none) | The same for a network, because a subnet asking in unison is one problem rather than many |
| `rate_prefix_length` | int | `24` v4, `56` v6 | The network the prefix limit counts by |
| `log_packets` | bool | `false` | An access line per packet rather than per association |
| `alert_on_deny` | bool | `true` | A security event for every refusal |

**`auth`** is symmetric authentication. RFC 8573 makes AES-CMAC the
algorithm: the older construction is MD5 over the key followed by the
packet, which is a length-extension shape with a broken hash in it. The
legacy algorithms are an explicit exception rather than a default,
because a device from 2006 cannot be taught a new one and pretending
otherwise ends with no authentication at all rather than weak
authentication somebody knows about. **Autokey (RFC 5906) is not
implemented and will not be**; its extension fields fall under the
unknown-field policy like anything else this relay cannot reason about.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `require` | bool | `false` | Refuse a packet carrying no authentication this listener can check. NTS counts — and the listener says plainly it has not verified it, because only the party holding the key can |
| `allow_legacy_algorithms` | bool | `false` | Accept a key whose algorithm is `md5` or `sha1`. It warns |
| `probe_key_id` | int | `0` | The key the listener signs its own monitoring probes with, for a server that requires authentication |
| `keys` | list | `[]` | `{id, algorithm, key_file}`: the identifier the packet carries (1..65535), `aes-cmac` (the default), `md5` or `sha1`, and an absolute path holding the key as hexadecimal or as the ASCII a `ntp.keys` file uses |

**`nts`** is Network Time Security. The time exchanges are UDP 123 with
authentication in extension fields; the key establishment is TLS on TCP
4460 with the ALPN `ntske/1`, and that is the `ntske` listener.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `mode` | enum | `passthrough` | `passthrough` or `off`. Pass-through forwards NTS-protected packets whole and unaltered, which is the only honest thing a relay that does not hold the keys can do with them |
| `require` | bool | `false` | Refuse a packet with no NTS fields. It is how a listener says "this estate is NTS only", and it is what makes the no-downgrade rule visible: an answer arriving without NTS fields for a request that had them is refused, **never** passed on as plain NTP |

**Termination is deliberately absent rather than approximated.** Doing it
honestly means deriving the NTS keys from the TLS exporter, holding the
same cookie keys the time servers hold, rotating them with an overlap so
a cookie issued before a rotation still works after it, and recovering
all of that across a restart. An implementation that faked any part would
be telling clients their time was authenticated when nobody had checked.
And **the visible NTS fields prove nothing to this relay**: a unique
identifier, a cookie and an authenticator field are all readable by
anybody on the path, so "NTS is present" is a routing and preservation
fact here, never an authentication one.

**`extensions`** bounds what a packet may carry.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `allow_unknown` | bool | `false` | Forward a field whose type this relay does not know. Off by default: a relay cannot decide about an instruction it cannot read |
| `refuse_ambiguous_mac` | bool | `true` | Refuse a packet whose tail is both a valid MAC and a valid extension field — the ambiguity RFC 7822 documents and cannot remove. A packet whose meaning depends on which reading the receiver picks is one two implementations will disagree about |
| `max` | int | `8` | Fields in one packet |

**`quality`** is what the listener requires of a server's answer, and how
it compares the servers. Every bound here is about **responses**: a
client's request carries a stratum, a root delay and a root dispersion
too, and they mean nothing — the protocol does not ask a client to fill
them in — so applying these to requests would refuse clients for empty
fields.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `compare_sources` | bool | `true` | Run the monitor: the listener sends its own probes to every server, measures each the same way, and compares them. Off warns |
| `probe_interval` | duration | `64s` | How often each server is measured; 1s..1h |
| `max_disagreement` | duration | `100ms` | How far apart two sources may be before the listener says so |
| `max_offset`, `max_delay` | duration | `0` (off) | Refuse an answer whose measured offset or round trip is past them |
| `max_root_delay`, `max_root_dispersion` | duration | `0` (off) | Refuse an answer whose own statement of its error is past them |
| `max_stratum` | int | `0` (the protocol's 15) | Refuse an answer from too far down the tree |
| `allow_strata` | list of int | `[]` (any) | The exhaustive list of strata accepted, 1..15. A bound admits everything below it and a list does not: a plant whose servers are a reference clock and its own two followers has no stratum 5 in it, and an answer claiming one is not a server that got worse |
| `max_root_distance` | duration | `0` (off) | Refuse an answer whose **synchronisation distance** — half the root delay plus the root dispersion, RFC 5905's own measure — is past it. It is the bound that cannot be satisfied by reporting a small delay and a large dispersion or the other way about |
| `refuse_bogus_timestamps` | bool | `true` | Refuse an answer whose four timestamps cannot describe an exchange: a zero transmit or receive timestamp, an answer sent before the request arrived, a last synchronisation later than the request. The check is between the packet's own fields, **never against this relay's clock**, so a relay whose own time is wrong does not refuse correct answers; it is not applied to an interleaved answer, whose transmit timestamp is the server's previous one on purpose. Off warns |
| `refuse_bogus_refid` | bool | `true` | Refuse an answer whose reference identifier does not match the stratum that says how to read it: a stratum 1 answer whose identifier is not a reference clock's name, or a stratum 2-or-worse answer with none at all. At stratum 2 and above only the unset value is called wrong, because the field may be four octets of a hash of an IPv6 address. Off warns |
| `expect_refid` | list | `[]` (any) | The reference identifiers a server may report: the four-character name at stratum 0 and 1 (`GPS`, `PPS`, `DCFa`) and the dotted quad above. It is the cheapest statement of server identity the protocol allows without a key — a GPS-backed clock that starts answering as something else is either a different device or the same device with a different upstream |
| `leap_policy` | enum | `alert` | What happens when an answer announces a leap second: `alert` (forward it and raise a security event when it is outside the window a leap second can happen in), `allow` (say nothing — warns), `window` (refuse an announcement outside that window) or `refuse` (refuse every announcement). An announcement makes every client that hears it plan to move its clock, and the IERS only ever uses the end of June, December, March or September |
| `leap_window` | duration | `744h` (a month) | How long before the end of such a month an announcement is plausible; 1h..2160h. RFC 5905 sets the indicator during the last day and some servers announce from the start of the month |
| `refuse_unsynchronised` | bool | `true` | Refuse an answer from a server that says its own clock is not synchronised — by the leap indicator **or** by stratum 16, which are two separate statements |
| `healthy_after`, `unhealthy_after` | int | `3` | The hysteresis: how many probes in a row it takes to change a server's state |
| `on_all_suspect` | enum | `pass` | What happens when no server is usable: `pass` (keep forwarding and keep saying so) or `refuse`. A blanket fail-closed stops the estate's clocks, which is itself an outage, so `refuse` warns |

The monitor keeps four states apart, because the operator's next action
differs: **unreachable** (no answer), **unsynchronised** (it answers and
says not to use its time), **suspect** (it answers, claims to be fine and
disagrees with its peers) and **healthy**. With three or more sources the
median is the estate's opinion and the outlier is named; with two that
disagree neither can be called wrong, so both are marked and the event
says exactly that.

**`holdover`** bounds how long a server whose time cannot be verified is
still used: `max_duration` (0 disables it). Past it the listener says the
holdover has expired, and the estate's `on_all_suspect` decides whether
that stops the answers.

**`change_detection`** asks a different question from every bound in
`quality`. Those ask whether one answer is good enough; this asks whether
the server is still the same server, answering the same way — which is
the question the interesting attack leaves open, because it passes every
static bound. A source that was a GPS clock at stratum 1 and now answers
as something else at stratum 4 is inside `max_stratum: 8`. An offset that
steps by fourteen seconds between two polls is inside `max_offset: 30s`. A
dispersion that grows from a millisecond to a second is inside
`max_root_dispersion: 2s`. A server that stops carrying NTS is carrying
valid NTP.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Watch each server. Off warns: nothing else here notices a source being replaced, re-pointed or stood in front of |
| `max_step` | duration | `1s` | How far the measured offset to one server may move between two measurements. A real clock drifts; it does not step |
| `max_stratum_jump` | int | `2` | How far a server's stratum may move at once. A server whose own upstream failed over moves by one or two; one that moved by eight is answering for somebody else |
| `dispersion_growth` | int | `8` | The factor by which a server's root dispersion may grow between measurements before it is said |
| `action` | enum | `alert` | `alert` (a security event and a counter) or `refuse` (that, and the answer does not reach the client). `refuse` warns: it stops the corrections rather than merely reporting them |

Six detections, each with a counter and a security event of its own:
`ntp_source_changed` (the reference identifier), `ntp_stratum_jumped`,
`ntp_offset_stepped`, `ntp_dispersion_grew`, `ntp_nts_lost` and
`ntp_leap_announced`. They are fed by both the monitor's own probes and
the exchanges the relay forwards, so an estate whose devices poll once an
hour still notices within a probe interval. The baseline moves to what
was measured whether or not the change was reported, so one change is one
alert rather than one per poll for ever; a kiss-o'-death and an
unsynchronised answer never become the baseline, since neither carries a
measurement of the server's time.

**`kod`** is the kiss-o'-death: a stratum-0 answer whose four reference
identifier octets are a code. It is the protocol's own way of saying "not
now", and a client that gets one backs off.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `on_rate_limit` | bool | `true` | Answer a rate-limited client with a `RATE` kiss rather than dropping its packet. A drop teaches a client nothing and it asks again |
| `on_deny` | bool | `false` | Answer a policy refusal with a `DENY` kiss. Off by default: a refusal usually should not tell the client what the policy is |
| `forward` | bool | `true` | Pass a server's own kiss-o'-death on to the client, which is the thing that has to back off |

**`learn`** records what actually asks this listener for the time — the
clients, the versions, the modes, whether any of it is authenticated, and
the poll intervals it really uses — and writes it out as the three lists a
policy is made of, ready to paste. `{enabled, file, interval (10s..24h,
default 5m), max_subjects (default 8192), enforce}`. `enforce` is false
by default and validation warns while it is off; a learning run also does
not apply `allow_clients`, because a run written to discover the clients
cannot be stopped from seeing them by the list it is discovering.

**`trace`** writes one JSON object per packet:
`{file, max_bytes (1MiB..64GiB, default 100MiB), requests, responses}`.
At the bound it writes one line saying it stopped rather than filling the
disk.

#### Architectural decisions

**Packets are forwarded as the bytes that arrived.** Never re-encoded. An
NTS-protected packet re-encoded is a packet the client will reject; an
authenticated one re-encoded is worse. So the client's own transmit
timestamp reaches the server and the server's own answer reaches the
client, which is what lets the client verify the exchange itself — the
relay is in the path, not in the middle of the cryptography.

**Every timeout, expiry and rate limit is on the monotonic clock.** This
is a relay for the protocol that changes the wall clock. Wall-clock
arithmetic here would be a timeout that fires when the time is set: every
association expiring at once when the clock jumps forward, and none of
them ever when it jumps back.

**The association table and the outstanding-request table are separate.**
An association is a client address and port, and its server is chosen
once and kept: a client that asked a different server every poll would
see a different offset every poll, and the jitter it measured would be
the relay's doing. Nothing here is round robin per packet, and nothing
hedges. The outstanding table is keyed by the backend and the client's
transmit timestamp, because a client may have several requests in flight,
an answer may arrive after its association moved, and a server may answer
something nobody asked — and each of those is a counter rather than a
confusion.

**An answer is tied to its question by the origin timestamp.** That is
the only thing in NTP that ties them, so an answer whose origin matches
no outstanding request is dropped and counted (`ntp_unsolicited`), even
though it came from the right address on a connected socket. Interleaved
mode is the documented exception: there the server echoes its own
previous transmit timestamp, which is a second table and a switch of its
own.

**Version and mode dispatch happen before the parser.** A mode 6 or mode
7 packet is not a time packet with an odd number in it — it is the control
protocol and the vendor-private protocol, whose headers are not this one,
and whose `monlist` request is the amplifier this port is famous for. A
version 5 packet is a different layout again. All three are refused from
the first octet, before any field of the body is read; `allow_version5`
forwards version 5 as opaque bytes rather than parsing it.

**The relay adds asymmetry, and that is a number.** A packet through a
relay takes one path out and another back, and the offset a client
computes is wrong by half the difference between them: `(forward −
reverse delay) / 2`. Nothing can remove it, so the data path is kept
short — the policy is compiled, the logging and the learning are off the
forwarding path, the queues are bounded, and there is no deep inspection
of anything, because there is nothing in a time packet to inspect deeply.
An estate that needs better than the asymmetry allows puts a time server
near its consumers rather than a relay.

Counters: `ntp_requests`, `ntp_forwarded`, `ntp_responses`,
`ntp_answered`, `ntp_denied`, `ntp_would_deny`, `ntp_dropped`,
`ntp_malformed`, `ntp_unsolicited`, `ntp_rate_limited`, `ntp_kiss_sent`,
`ntp_timed_out`, `ntp_associations`, `ntp_associations_open`,
`ntp_upstream_failed`, `ntp_upstream_unavailable`, `ntp_send_failed`,
`ntp_interleaved`, `ntp_nts_forwarded`, `ntp_version5`, `ntp_probes`,
`ntp_probe_failed`, `ntp_disagreements`, `ntp_source_healthy`,
`ntp_source_unhealthy`, `ntp_holdover_expired`, `ntp_source_changed`,
`ntp_stratum_jumped`, `ntp_offset_stepped`, `ntp_dispersion_grew`,
`ntp_nts_lost`, `ntp_leap_announced`, `ntp_leap_unexpected`. Refusals are `ntp_denied`
for the ban triggers, and the fine-grained reason is in the refusal
counters: `banned`, `client_not_allowed`, `rate_limit`, `control_mode`,
`private_mode`, `version5`, `version`, `version_not_allowed`,
`mode_not_allowed`, `not_a_peer`, `broadcast_not_allowed`, `malformed`,
`packet_too_large`, `too_many_extensions`, `unknown_extension`,
`ambiguous_mac`, `nts_required`, `auth_required`, `auth_failed`,
`max_associations`, `outstanding_full`, `no_server`,
`server_not_allowed`, `malformed_response`, `unsolicited`,
`response_mode`, `kiss_of_death`, `unsynchronised`,
`unsynchronised_stratum`, `stratum_too_high`, `stratum_not_allowed`,
`root_delay`, `root_dispersion`, `root_distance`, `delay`, `offset`,
`bogus_timestamps`, `bogus_refid`, `refid_not_allowed`,
`leap_announced`, `leap_unexpected`, `source_changed`, `nts_stripped`,
`auth_stripped`.

### server.listeners[].ntske (kind: ntske)

A `kind: ntske` listener is NTS key establishment (RFC 8915) on TCP 4460:
TLS with the ALPN `ntske/1`, relayed to the key establishment servers
whose keys it is.

It is a separate listener from `kind: ntp` because it is a separate port,
a separate transport and a separate security property. A deployment that
wants NTS runs both, and having to write both down is the point: an
estate with a time listener and no key establishment listener has clients
that cannot get cookies, and that is better seen in the configuration
than found in the logs.

It **relays** rather than terminates, for the reasons under `nts` above.
What it does is the part a relay can do honestly: read the one thing a
TLS handshake shows in the clear — the server name and the application
protocol the client offers — refuse a connection that is not an NTS
client, bound the handshakes in flight, and hand the rest to the server.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `upstream` | upstream | required | The pool of key establishment servers |
| `allow_clients`, `deny_clients` | list of CIDR | `[]` | The networks a client may connect from. Deny first |
| `server_names` | list | `[]` (any) | The server names a client may ask for, as exact names or `*.example` patterns |
| `require_alpn` | bool | `true` | Refuse a connection that does not offer `ntske/1`. Off warns: the application protocol is the only thing the handshake shows that says what a connection is for |
| `max_connections` | int | `256` | Live sessions |
| `max_concurrent_handshakes` | int | `32` | Handshakes in flight. A TLS handshake is the expensive part of NTS and a flood of them is this port's denial of service; a client that cannot get a slot is refused rather than queued, because a queue here is a queue of handshakes |
| `handshake_timeout` | duration | `10s` | How long a client has to get through the handshake |
| `idle_timeout` | duration | `30s` | A key establishment is a handshake and a short exchange, not a session anybody holds open |
| `max_bytes` | int | `65536` | One session's traffic each way |
| `log_sessions` | bool | `false` | An access line per session |
| `alert_on_deny` | bool | `true` | A security event for every refusal |

A deployment on a port other than 4460 warns: a client that found this
service through a server's own key establishment record will look for
4460.

Counters: `ntske_sessions`, `ntske_relayed`, `ntske_refused`,
`ntske_rejected`, `ntske_not_nts`, `ntske_handshake_limited`,
`ntske_upstream_failed`, and `ntske_handshakes`, which is a gauge of the
handshakes holding a slot right now: it says how close
`max_concurrent_handshakes` is to being reached, which the limited
counter only answers once clients are already being turned away.
Refusals are `ntske_denied` for the ban triggers, with the reasons `banned`, `client_not_allowed`,
`max_connections`, `handshake_limit`, `not_tls`, `no_hello`,
`incomplete_hello`, `hello_too_large`, `alpn_not_offered` and
`server_name_not_allowed`.

### server.listeners[].vnc (kind: vnc)

A `kind: vnc` listener is a VNC gateway: the proxy is an RFB server to
the client and an RFB client to the target, terminating the handshake
of RFC 6143 on both legs.

**Why this is not a `tcp` listener.** RFB's whole policy surface is in
the handshake. Which security type is used, whether the session is
encrypted and how, what the desktop is called — all of it is settled in
the first few hundred bytes. A proxy that does not sit in that
negotiation cannot decide any of it, and cannot record what follows.

Terminating both legs is also what separates the two credentials. What
a person proves to the gateway is not the desktop's password: the
gateway opens the target's leg with its own, so the shared VNC password
of a machine never has to be given to the people who use it.

#### What is supported

**Protocol versions.** 3.3, 3.7 and 3.8, on either leg and
independently: a 3.3 client can reach a 3.8 server through here. A
client announcing a version nobody defines (Apple's 3.889, or anything
above 3.8) is treated as the highest defined version at or below it.
Below 3.3 is refused.

The versions differ in one place that matters to a gateway: before 3.8,
a successful `none` carries no `SecurityResult` at all (RFC 6143
§7.1.3). Each leg follows the rule of the version settled on that leg,
so a 3.3 viewer is not sent four bytes it would read as the start of
the desktop's dimensions, and a 3.7 target is not waited on for a
message it will never send.

**Security types.** Only the ones with a published specification are
mediated — that is, completed on both legs, which is what makes the
session recordable:

| Type | Name | What it is | Status |
|------|------|-----------|--------|
| 1 | `none` | No authentication | Mediated |
| 2 | `vncauth` | The DES challenge of RFC 6143 §7.2.2 | Mediated |
| 19 | `vencrypt` | The open TLS and X.509 negotiation | Mediated |
| 18 | `tls` | Anonymous-TLS, VeNCrypt's predecessor | Mediated, warned about |
| 16 | `tight` | TightVNC's capability negotiation | Reimplemented, warned about |
| 30 | `ard` | Apple Remote Desktop | Reimplemented, warned about |
| 113 | `mslogon2` | UltraVNC's MS-Logon II | Reimplemented, warned about |
| 129 | `rsa-aes` | RealVNC's RSA with AES-128-EAX | Reimplemented, warned about |
| 130 | `rsa-aes-ne` | The same handshake, session in clear | Reimplemented, warned about |
| 133 | `rsa-aes-256` | RealVNC's RSA with AES-256-EAX | Reimplemented, warned about |

`tls` is warned about because it is anonymous Diffie-Hellman with no
certificate to check: it stops a reader and not an active attacker.
`vencrypt` with an X.509 subtype is the one to use.

**VeNCrypt subtypes**: `x509-none`, `x509-vnc`, `x509-plain`,
`tls-none`, `tls-vnc`, `tls-plain`. The `tls-*` ones are warned about
for the same reason. The bare `plain` subtype (no TLS at all) is
refused: it would send the credential in clear.

**Reimplemented, which is not the same as supported.** `mslogon2` is
UltraVNC's own type. There is no specification for it; what is
implemented here follows the shape of UltraVNC's `vncauth.cpp` and
`DH.cpp` and the public reimplementations that agree with them, and
**interoperability against a real UltraVNC server is not verified by
this project's tests**. Enabling it produces a warning at load that
says so.

What it is worth is worth stating plainly, because the name sounds
like security: MS-Logon II is Diffie-Hellman over **64 bits** with the
shared secret used as a **DES** key. Both have been breakable for
decades, and anyone who records the exchange can recover the Windows
credential inside it. It is here because the desktops exist — reaching
them through a gateway that records the session, asks for a factor and
holds the policy is better than reaching them directly — and not
because the type protects anything. Put a TLS-wrapped or SSH-tunnelled
leg around it (`tls_mode: wrap`, or `ssh`) if the credential matters,
which it does.

Two things follow from it carrying a **name** as well as a password,
which most of RFB does not:

- It can carry a second factor without a certificate, which is the one
  practical advantage it has over VeNCrypt's plain subtype: `mfa` is
  allowed with `mslogon2` in `security_types`.
- Towards a target it needs both halves of a credential, so
  `upstream_user` and `upstream_password_file` are required when
  `upstream_security: mslogon2` — refused at load rather than at the
  first session.

**TightVNC's type 16** is the easiest of these to be confident about,
because it is not a cipher at all. It is a negotiation: the server
offers a list of *tunnels* and a list of *authentications*, each named
by a capability record, and the two ends pick one of each. What
actually protects anything is whichever authentication it settles on.

- This gateway **offers no tunnels**, and refuses a target that offers
  only tunnels. A tunnel is another protocol wrapped around this one,
  which would be a session the gateway can neither read nor record.
- It offers `NOAUTH__` and, where `password_file` is set, `VNCAUTH_` —
  the same DES challenge as the `vncauth` type, checked against the
  gateway's own password. An authentication outside the list it
  offered is refused, as with any other type.
- Tight sends one more block **after `ServerInit`**, listing the
  message types and encodings the server has beyond the standard ones.
  A target's is read and dropped, and a Tight client is told there are
  none. That is deliberate rather than a gap: what is advertised there
  is TightVNC's extensions, including **file transfer**, and a gateway
  that cannot see inside them has no business passing them through.

**Apple Remote Desktop's type 30** is Diffie-Hellman over a prime the
server chooses, MD5 of the shared secret as an AES-128 key, and a
fixed credential blob encrypted under it in ECB. Apple's own servers
offer a **512-bit** prime, the key derivation is MD5 and the mode is
ECB, so the credential is protected against very little; the warning
at load says so. In the server role this gateway uses the fixed 1024-bit
Oakley group 2 prime instead — the length is on the wire and a client
reads it, but a client that assumes 512 would not interoperate. Its
credential carries a name, so `mfa` works with it and `upstream_user`
is required to use it towards a target.

**RealVNC's RSA-AES**, types 129, 130 and 133, is reimplemented on the
same terms and with a different balance of risk. Each end sends an RSA
public key, each seals a random under the other's key, the session
keys are hashed out of the two randoms, and everything after that
travels in AES-EAX boxes with a counter for a nonce.

- The **cryptography is not guessed at**: RSA and the hashes are Go's
  standard library, and EAX is implemented in `internal/eax` against
  the published vectors of the EAX paper and NIST SP 800-38B, which
  the tests run. What is reconstructed is the **order and framing of
  the messages**, from TigerVNC's implementation and its `rfbproto`.
  Getting that wrong shows up as a handshake that does not complete
  and a log line naming the step — not as a session that looks
  encrypted and is not.
- `rsa-aes` is AES-128 with SHA-1, `rsa-aes-256` is AES-256 with
  SHA-256, and **`rsa-aes-ne` protects the handshake only: the session
  after it is in clear.** That is the one thing about this family
  easiest to get wrong, so validation warns about it and the access
  log names the security type of both legs.
- **The listener needs an RSA key of its own** (`rsa_key_file`, PEM,
  PKCS#1 or PKCS#8, at least 2048 bits, not readable by anyone else),
  because each end is identified by a key.
- **Towards a target the key is pinned** (`upstream_rsa_fingerprint`),
  and validation requires it. Nothing else authenticates the far end of
  that exchange, and unlike a viewer there is nobody at a proxy to show
  a fingerprint to and ask. The fingerprint is this project's own
  spelling — the SHA-256 of the key as the protocol encodes it — and
  the gateway logs the one a target offered, which is where the setting
  is copied from.
- Its credential carries a name, so `mfa` works with it and
  `upstream_user` is required to use it towards a target.

**What is not supported, and why.** These are the vendors' own, with no
published specification to write against and none reimplemented here:

| Type | Name | Vendor |
|------|------|--------|
| 5, 6 | `ra2`, `ra2ne` | RealVNC |
| 17 | `ultra` | UltraVNC |
| 20, 21, 22 | `sasl`, `md5`, `xvp` | others |

Naming one in `security_types` is a configuration error rather than a
setting that quietly does nothing. A gateway cannot sit in the middle
of a handshake it cannot complete, and reimplementing a cipher from
guesswork is worse than not having it: it would look like support while
being wrong. Where a public description exists that is good enough to
write against — as for `mslogon2` above — the type moves into the table
before this one and carries a warning instead.

**UltraVNC's DSM plugin encryption is a separate case.** It is not a
security type at all — the plugin wraps the whole connection before RFB
begins, so this listener cannot even read the version string. There is
nothing to configure here. An estate that needs it uses a `kind: tcp`
listener, which relays the bytes without looking at them: the
connection works, the access log records who reached which target, and
there is no recording, because the stream is encrypted with keys this
proxy does not hold.

#### Options

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `upstream` | string | required | The pool of targets |
| `security_types` | list | `[none, vncauth, vencrypt]` | The types a client may use, by name |
| `vencrypt_subtypes` | list | `[x509-vnc, x509-none]` | The subtypes offered when `vencrypt` is in use |
| `password_file` | string | none | The password this gateway answers its own `vncauth` challenge with. Required if `vncauth` is offered, and refused if anyone but the proxy user can read it |
| `upstream_password_file` | string | none | The password this gateway uses towards the target |
| `upstream_user` | string | none | The login this gateway presents to a target whose security type carries a name (`mslogon2`, `ard`, `rsa-aes*`). Required with those |
| `rsa_key_file` | string | none | This listener's own RSA key for the `rsa-aes` types, PEM, at least 2048 bits. Required with any of them, and refused if anyone but the proxy user can read it |
| `upstream_rsa_fingerprint` | string | none | Pins the target's `rsa-aes` public key. Required with `upstream_security: rsa-aes*`; the key a target offers is printed in the log |
| `upstream_security` | string | strongest available | The type to use towards the target, by name |
| `tls_mode` | string | `negotiated` | What the listener's `tls` section is for: `negotiated` presents the certificate inside RFB, `wrap` makes the socket itself TLS. See below |
| `upstream_tls_mode` | string | `none` | `none` or `vencrypt` |
| `upstream_tls` | object | none | CA and name for the target's leg |
| `ssh` | object | none | Reach the target through an SSH connection the gateway makes; see below |
| `view_only` | bool | `false` | Drop the client's key, pointer and cut-text messages, so a session is watched and not driven |
| `pixel_stream` | string | `framed` | `framed` reads the desktop's picture and applies `bounds`; `opaque` forwards it unread, which is what a desktop that must use the `tight` encoding needs. See below |
| `bounds` | object | see below | What the desktop may ask the viewer to allocate |
| `clipboard` | string | `both` | Which way a clipboard transfer may travel: `both`, `to_client`, `to_target` or `none` |
| `allow_resize` | bool | `true` | Let a client ask the desktop to change size. The size asked for is bounded by `bounds.max_framebuffer_pixels` whatever this says |
| `recording` | object | none | As `server.listeners[].ssh.recording`; see below for the format |
| `mfa` | object | none | See below: it needs `x509-plain` |
| `require_grant` | bool | `false` | Admit a session only against a live grant from the [access](#access) ledger: one somebody asked for, somebody else approved, and that ends by itself |
| `idle_timeout` | duration | `5m` | No traffic in either direction |
| `session_timeout` | duration | `0` | Bound on a whole session however active |
| `handshake_timeout` | duration | `30s` | Bound on the negotiation before the session begins |
| `max_connections` | int | `200` | Sessions on this listener |
| `proxy_protocol` | bool | `false` | PROXY protocol v2 header to the target |
| `allow_clients` | list | `[]` (any) | CIDRs a client must come from |

#### Reading the picture: `pixel_stream` and `bounds`

An image protocol's numbers are the viewer's allocations. A
`ServerInit` says the desktop is so many pixels wide and high, and the
viewer allocates a framebuffer from it; a rectangle's twelve byte
header says how much of the screen it covers, and the viewer sizes a
decode buffer from that. A desktop that says 4096x4096 in twelve bytes
of zlib is not sending a picture, it is asking the machine on somebody's
desk for sixty-four megabytes, and it can ask again immediately. This is
what makes an image protocol the cheapest place to aim a decompression
bomb.

With `pixel_stream: framed` (the default) the gateway reads every
message the desktop sends and every rectangle inside it, so it can
refuse one. Nothing is decompressed to do this: each bound compares what
was declared with what arrived.

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `bounds.max_framebuffer_pixels` | int | `33177600` (7680x4320) | The desktop size in pixels: the one the target announces, the one a resize changes it to, and the one a client asks for |
| `bounds.max_rectangles_per_update` | int | `4096` | Rectangles in one framebuffer update. A thousand one-pixel rectangles cost the viewer a thousand decode calls for one screen |
| `bounds.max_encoded_rectangle` | int | `16777216` | One rectangle's encoded payload, in bytes |
| `bounds.max_decode_ratio` | int | `1000` | The declared picture over the bytes that carry it, for the compressed encodings. A thousandfold is past any real screen |
| `bounds.max_cut_text` | int | `1048576` | One clipboard transfer, in either direction |

A zero is no bound. Two checks apply whatever `bounds` says: a
rectangle must lie inside the framebuffer it belongs to (a viewer
writes a rectangle's pixels at the offset the rectangle gives, and one
reaching past the end is a write past the end of the buffer the viewer
made for it), and a pixel format must be 8, 16 or 32 bits, because every
length in the picture is measured in whole pixels.

**Framing decides what a client may ask for.** A gateway can only frame
an encoding whose payload length it can compute, so the encodings it
cannot are removed from the client's `SetEncodings` list and the desktop
never uses one. What survives: `raw`, `copyrect`, `rre`, `corre`,
`hextile`, `zlib`, `zrle`, the cursor and desktop-size pseudo-encodings,
the compression and quality hints, `fence`, continuous updates and the
extended clipboard. What is removed: **`tight`** and `trle`, whose
lengths depend on a filter, a palette size and a pixel width that is not
the pixel format's; `cursor-with-alpha`; and anything unregistered. A
client asks for every encoding it has, so a filtered list still leaves a
session that draws -- `zrle` is the usual survivor, and `raw` is added
if nothing else is left.

A listener that must have `tight` sets `pixel_stream: opaque`. The
desktop's bytes are then forwarded unread: `max_framebuffer_pixels` and
`max_cut_text` still apply, and the three bounds that need the stream
read do not. Validation warns, because that is the trade.

The **client's** messages are framed either way. A message is only as
long as its type says, so framing is what lets a gateway drop one and
forward the next -- which is how `view_only` and `clipboard` work -- and
a message type whose length the gateway does not know cannot be
forwarded at all without losing the stream after it. **That is why a
file transfer cannot cross this gateway**: TightVNC's and UltraVNC's
transfers are client messages 252 and 255, whose lengths are the
vendors' own, so a session that sends one ends. It is a consequence of
framing rather than a rule, which is the strongest kind.

One restriction comes with framing: a `SetPixelFormat` is allowed before
the first framebuffer update request and refused after it. RFB has no
message that says "the next rectangle is in the new format", so a
gateway that kept framing past a mid-stream change would be guessing
where the rectangles are. Viewers that re-negotiate colour depth
automatically (TigerVNC's automatic mode) need a fixed depth configured,
or `pixel_stream: opaque`.

Every refusal on this path is counted under
`xproxy_refusals_total{kind="vnc"}` with a reason of its own
(`framebuffer_too_large`, `decode_ratio`, `too_many_rectangles`,
`encoded_rectangle_too_large`, `rectangle_outside_framebuffer`,
`unframable`, `cut_text_too_large`, `resize_refused`,
`pixel_format_changed`) and logged as a `vnc_denied` security event with
the numbers that caused it.

#### VNC over TLS, and VNC over SSH

Three ways to stop the session crossing a network in clear. The two
that encrypt the client's leg are alternatives; the third is the
target's leg and composes with either.

- **VeNCrypt**, negotiated inside RFB (`tls_mode: negotiated`, the
  default). The socket carries RFB from the first byte, and the
  certificate in the listener's `tls` section is presented inside the
  handshake. This is the one a modern viewer offers by itself, and the
  `x509-*` subtypes are the ones with a certificate to check. The
  security type `tls` (18) works the same way, with no certificate
  checked.
- **A socket that is TLS from the first byte** (`tls_mode: wrap`). The
  client connects with TLS and speaks RFB inside it, which is what a
  viewer reaching a `stunnel`-wrapped port does.

  `wrap` together with the `vencrypt` or `tls` security type is a
  configuration error rather than two layers: the first byte a client
  sends is either a TLS record or `RFB 003.008`, so a port is one or
  the other. An estate with both kinds of viewer uses one listener for
  each, which is what the viewers are already pointed at.
- **`ssh`**, for the target's leg. The gateway opens an SSH connection
  and reaches the VNC server through it, so the RFB never crosses the
  network in clear even when the server itself speaks only RFB. This is
  the usual `ssh -L` arrangement, done once by the gateway rather than
  by every operator.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `ssh.user` | string | required | The login on the SSH host |
| `ssh.key_file` | string | required | The private key the gateway authenticates with |
| `ssh.known_hosts` | string | required | Pins the SSH host keys. An unpinned tunnel authenticates nothing, which is the whole reason for the tunnel |
| `ssh.address` | string | the endpoint's host, port 22 | The SSH host |
| `ssh.target` | string | `127.0.0.1:5900` | What to reach from the SSH host |

An operator who prefers to tunnel themselves still can: `ssh -L` to the
`kind: ssh` bastion and point the viewer at the forwarded port. That
needs nothing here. The `ssh` section is for doing it once, centrally,
so the recording and the policy still apply.

#### The second factor

`mfa` needs a security type whose credential carries a user name, and
validation refuses the section without one. The reason is in the
protocol: a DES challenge proves knowledge of one shared desktop
password and says nothing about who is holding it, so there is nothing
to look an enrolment up by. Four things carry a name — a VeNCrypt
**plain** subtype, `mslogon2`, `ard`, and the `rsa-aes` types — and any
of them satisfies it. The name
identifies the person and the password field carries their one-time
code; with a plain subtype both are inside the TLS tunnel, which is the
arrangement to prefer.

`x509-plain` is added to `vencrypt_subtypes` automatically when `mfa`
is configured and no plain subtype is listed.

The code is checked inside the handshake, before the security result is
sent: a wrong code is a failed authentication the viewer can show,
rather than a session that is told it succeeded and then closes. The
desktop is not dialled either way. A viewer that authenticates with a
type carrying no name — where one is also offered — is refused for the
same reason: there is nothing to look an enrolment up by.

#### The recording

The file holds the server-to-client RFB stream — what was on the screen
— with the timing of it, in the asciicast v2 container the other
recordings use, named `*.rfb.cast`. Its header carries
`XPROXY_PROTOCOL: rfb`, the framebuffer size and the RFB version, and
the first mark names the desktop, both versions and both security
types.

With `recording.input` the viewer's own stream is kept as well, as
asciicast `i` events beside the `o` ones: every key and pointer event,
the clipboard writes and the encoding and format negotiations. It is off
by default for the same reason a terminal's keystroke recording is, and
a message the policy refused is written as a mark rather than as bytes —
a replay then shows that the viewer tried and the gateway said no, which
is the part an investigation is looking for.

**It is not a video.** The event data is the protocol stream, so
replaying it needs a player that speaks RFB rather than a terminal:
`xproxy-replay`(8), which is shipped with the product and decodes what
RFC 6143 specifies. The data is base64 inside the container, because a
pixel is any byte at all and JSON cannot hold one that is not valid
UTF-8; the header says so with `XPROXY_ENCODING: base64`, and the pixel
format the desktop announced is in it too, since the handshake that
carried it happened before the recording began.
Recording the stream is what keeps the cost bounded and loses nothing:
a decoder can be written against this file afterwards, and one that
decoded at capture time would have to understand every encoding a
server might choose and would silently lose whatever it did not.

Counters: `vnc_sessions`, `vnc_sessions_open`, `vnc_rejected`,
`vnc_refused`, `vnc_recorded`, `vnc_mfa_ok`, `vnc_mfa_failed`. Every
session writes one `vnc` access line with both versions, both security
types, the desktop name and size, and how it ended. Refusals are
`vnc_denied` deny events, so bans apply.

### server.listeners[].rdp (kind: rdp)

A `kind: rdp` listener is a Remote Desktop gateway: the proxy
terminates the connection sequence of MS-RDPBCGR on both legs, so it
is an RDP server to the client and an RDP client to the desktop.

**Why this is not a `tcp` listener.** Everything worth deciding about
an RDP session is settled in the connection sequence, before a single
pixel moves: which security protocol is used, which virtual channels
exist, who is connecting and with what credential. A relay that does
not sit in that sequence decides none of it and can record none of
what follows.

The channel list is the important part. Every redirection RDP has —
drives, printers, serial and parallel ports, smart cards, the
clipboard, audio — rides a virtual channel, and nothing can be used
that was not both announced and granted. A gateway that rewrites that
list decides what a session is able to do before it does it.

#### What is supported

**Protocol versions.** All of them. This gateway does not decode
graphics, input, capability sets or any of the session's own traffic —
it relays those as they arrive — so an RDP 4 client and a Windows
Server 2025 desktop work the same way. What it decodes is the
connection sequence, the channel list, the device announcement and the
credential packet, and those have been stable since the protocol was
documented.

**Security protocols**, which are negotiated at the very start:

| Protocol | Towards a client | Towards a desktop |
|----------|------------------|-------------------|
| TLS (`tls`, `PROTOCOL_SSL`) | Supported, the default | Supported, the default |
| Network level authentication (`nla`, `PROTOCOL_HYBRID`) | **Not offered, and cannot be** — see below | Supported: CredSSP over NTLMv2 |
| The protocol's own encryption (`rdp`, `PROTOCOL_RDP`) | Supported, and it authenticates nothing — see below | Supported, and worth what the section below says it is |

**A client that asks for network level authentication is answered with
TLS.** That is not a gap, it is how the gateway works at all, and it is
what every remote desktop gateway does. Network level authentication
proves the person's Windows credential to the server *before* the RDP
connection sequence starts, using CredSSP. For a gateway to accept that
from a client it would have to verify that credential itself, which
means holding every person's Windows password — the one credential a
gateway should never hold. Answering with TLS moves the credential into
the connection sequence, where the gateway can check a second factor
against it and substitute its own. The cost is stated plainly: between
the client and the gateway, authentication happens after the connection
is established rather than before it, so the gateway itself must be
reachable only by the people who should reach it (`allow_clients`, and
a network that agrees).

**Network level authentication towards a desktop** (`upstream_security:
nla`) is what a current Windows install requires by default. The
gateway proves a credential with CredSSP (MS-CSSP) carrying NTLM
version 2 (MS-NLMP) inside the TLS tunnel, before the connection
sequence starts.

- It needs `upstream_user` and `upstream_password_file`, and validation
  says so. There is no way to pass the person's own credential through
  it: the exchange happens before the person has sent anything at all,
  which is the whole reason network level authentication exists.
- The exchange is **bound to the tunnel it runs in**. Each end proves
  it saw the same certificate, from CredSSP version 5 onwards as a hash
  over a fresh nonce, so tokens relayed into another connection fail.
  A desktop whose binding does not match gets no credential.
- The gateway insists on **extended session security** and a key
  exchange. A server offering neither is refused rather than fallen
  back to: the credential's protection rests on those session keys.
- Only the client half is implemented — this proves a credential, it
  never checks one. Checking would mean the gateway holding a password
  hash for whoever connects, which is the thing it exists to avoid.

The NTLM key derivation is tested against the worked example of MS-NLMP
§4.2.4, and the whole exchange against a stand-in for the Windows side.
It has **not** been verified against a real Windows desktop in this
repository's tests.

**The protocol's own encryption** — RC4 under keys derived from two
random values, one of them sent under an RSA key the server puts in the
connection sequence — is where the two directions differ.

- **Towards a desktop** (`upstream_security: rdp`) it works. The
  desktop's certificate is walked to its key, this end's random is
  sealed under it and sent as the security exchange, the session keys
  are derived, and from there everything the client sends is signed and
  encrypted on the way out while everything the desktop sends is
  decrypted on the way in — on both framings, the connection
  sequence's data units and the fast path the session itself runs on.
  The key rolls over every 4096 packets as the protocol requires.
  Setting it logs a warning at load, because it is a downgrade an
  operator should have meant.
- **Towards a client** (`security: [rdp]`) it works too. The listener
  draws a 512-bit RSA key at start — the size the protocol carries, not
  a choice — puts it in a proprietary certificate, and signs that
  certificate with the **Terminal Services signing key published in
  MS-RDPBCGR §5.3.3.1.1**. The strongest method the client offered is
  chosen, at encryption level *client compatible*, so both directions
  are encrypted. The client's random arrives sealed under the
  listener's key, the session keys follow, and from there the gateway
  decrypts what the client sends before the policy sees it and encrypts
  what it sends back.

  **That signature authenticates nothing.** Microsoft published the
  private key, which is what lets any implementation sign one — so a
  client verifying it has learned that the other end read the
  specification, and nothing about who it is talking to. There is no
  server authentication on such a leg, and no way to add any: the
  protocol has nowhere to put it. A listener offering this is protected
  by the network it sits on, `allow_clients`, and nothing else.

  Setting it warns at load. A client that can use TLS should be made to
  (`security: [rdp, tls]` offers both and TLS is preferred whenever the
  client asks for it), and a listener that offers only `rdp` needs no
  `tls` section at all.

Three things follow from the gateway being *inside* that encryption
rather than outside it, and they are the reason to be there: the
channel and device policy still applies, the second factor is still
checked, and the recording holds the session rather than ciphertext.

The two legs are independent. An old client and an old desktop each
get their own key exchange, their own method and their own key
schedule; nothing is forwarded from one to the other. A client on the
protocol's own encryption can reach a desktop on TLS or on network
level authentication, and the other way round.

Session traffic towards a legacy client **waits** for that client's key
exchange rather than going out in the clear: a client that agreed to
encryption cannot read an unencrypted packet, so sending one early
would end the session rather than degrade it. The wait is bounded by
`handshake_timeout`.

What the encryption itself is worth is nothing, against anyone on the
path: MD5 and SHA-1 derivation, RC4 — 40, 56 or 128 bit, whichever the
desktop asks for — and a certificate a client has no way to check,
because the protocol never had anywhere to check it against. This
gateway reads the key out of that certificate without checking it,
which is the same position every client is in. FIPS mode (3DES with a
different derivation and a different packet layout) is not implemented:
a desktop that insists on it is refused rather than downgraded.

So it is here for equipment that speaks nothing else — an appliance, an
embedded console, a Windows install too old to offer TLS. Such a
desktop reached through this gateway is better off than reached
directly, because of the three things above. It is not better off
because the connection is protected.

A desktop that asks for no encryption at all (`ENCRYPTION_LEVEL_NONE`)
is served, and the gateway writes a warning naming it, because a
session nobody encrypts looks exactly like one everybody does.

**What the gateway does not decode**: the graphics, input, clipboard
contents, audio, licensing and capability exchange. Those are relayed
byte for byte. A recording is therefore the protocol stream, not a
video — see below.

#### The channel policy

`channels.allow` names the static virtual channels a session may have,
and **the default is none**: a session that can see the desktop and
drive it, and nothing else. The usual names are `rdpdr` (device
redirection), `cliprdr` (clipboard, including file copy), `rdpsnd`
(audio out), `audin` (microphone), `drdynvc` (dynamic channels) and
`rail` (seamless applications).

A refused channel is **not removed from the list**, and the reason is
worth knowing: the desktop answers with one identifier per channel the
client asked for, in the order it asked, and a client that gets back a
different number of identifiers does not recover. So the gateway
replaces the *name* of a refused channel with one nothing speaks —
the name field is a fixed eight bytes, so the lengths do not move. The
desktop registers a channel no software has a handler for, the
identifiers still line up, and the gateway drops whatever the client
sends on it. The desktop never registers the real channel, which is the
property that matters.

`drdynvc` is warned about: dynamic channels carry more redirection
inside them, and what rides one is decided by the two ends rather than
by this list.

#### File transfer and ports

Both are device redirection, which rides `rdpdr`, and both are decided
by `devices.allow`:

| Name | What it is | What allowing it means |
|------|-----------|------------------------|
| `drive` | Filesystem redirection | **File upload and download between the client and the desktop** |
| `printer` | Printer redirection | Printing from the desktop to the client's printers |
| `serial` | Serial port redirection | The desktop reaches the client's COM ports |
| `parallel` | Parallel port redirection | The desktop reaches the client's LPT ports |
| `smartcard` | Smart card redirection | The desktop uses the client's smart card reader |

The default is none, so `channels.allow: [rdpdr]` on its own gives a
session the channel and no redirection on it. The policy is applied to
the **device announcement**: nothing can be redirected that was not
announced, so filtering that one message decides the whole of it
without the gateway having to understand the traffic that follows. A
refused device is taken out of the announcement, counted, written to
the security log and marked in the recording. Refusing all of them
leaves a valid announcement of no devices rather than a broken channel.

A device announcement the gateway cannot read — a compressed one —
ends the session rather than passing through, because a redirection
policy that quietly did not apply is worse than a session that stops.

#### Options

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `upstream` | string | required | The pool of desktops |
| `security` | list | `[tls]` | What a client may use: `tls`, `rdp`, or both. See the table above; `rdp` warns at load |
| `upstream_security` | string | `tls` | What this proxy uses towards the desktop: `tls`, `nla` with a credential to prove, or `rdp` for equipment that speaks nothing else |
| `upstream_tls` | object | none | CA and name for the desktop's leg |
| `upstream_user` | string | none | The login this proxy opens the desktop with. With it, the person's own credential never reaches the desktop |
| `upstream_domain` | string | none | The domain that goes with `upstream_user` |
| `upstream_password_file` | string | none | Its password, refused if anyone but the proxy user can read it |
| `channels.allow` | list | `[]` (none) | The static virtual channels a session may have |
| `devices.allow` | list | `[]` (none) | The redirected device kinds, where `rdpdr` is allowed |
| `recording` | object | none | As `server.listeners[].ssh.recording`; see below for the format |
| `mfa` | object | none | See below |
| `require_grant` | bool | `false` | Admit a session only against a live grant from the [access](#access) ledger: one somebody asked for, somebody else approved, and that ends by itself |
| `idle_timeout` | duration | `5m` | No traffic in either direction |
| `session_timeout` | duration | `0` | Bound on a whole session however active |
| `handshake_timeout` | duration | `30s` | Bound on the connection sequence |
| `max_connections` | int | `200` | Sessions on this listener |
| `proxy_protocol` | bool | `false` | PROXY protocol v2 header to the desktop |
| `allow_clients` | list | `[]` (any) | CIDRs a client must come from |

#### The two credentials

With `upstream_user`, `upstream_domain` and `upstream_password_file`,
the desktop is opened with the gateway's own account and the person's
credential stops at the gateway. Without them, what the person typed is
forwarded as it arrived, which is what an estate that wants its own
accounts audited on the desktop needs. Either way the gateway sees the
credential, which is the price of being able to check anything about
it — and the reason the listener should be reachable only over a
network you trust.

#### The second factor

`mfa` checks a one-time code **before the credential reaches the
desktop**. RDP has nowhere to ask a question — there is no prompt in
the protocol and the client is waiting for a desktop rather than a
dialogue — so the code travels with the password, after a comma:

```
Password: hunter2,492013
```

The same arrangement the FTP relay uses, and one that works with every
client because it asks nothing of the client. The code is taken off
before the password goes anywhere, so the desktop never sees it.

One honest difference from the other gateways here: the factor is
checked before the **credential** reaches the desktop, not before the
desktop is dialled. RDP's connection sequence requires the desktop to
answer before the client sends its credential, so the TCP connection is
already open by then. What the desktop never receives without a
verified factor is the credential.

#### The recording

The file holds the desktop-to-client stream — what was on the screen —
with the timing of it, in the asciicast v2 container the other
recordings use, named `*.rdp.cast`. Its header carries
`XPROXY_PROTOCOL: rdp` and the security protocol of the desktop's leg,
the first mark names the session and the channels it was granted, and
every refused device is marked where it happened.

With `recording.input` the client's own stream is kept as well, as
asciicast `i` events beside the `o` ones. On this protocol that is more
than keystrokes and pointer moves: the virtual channels ride the same
stream, so it is also what a redirected drive carried. It is off by
default, and a unit the policy dropped is written as a mark rather than
as bytes — the refusal is in the file, the refused bytes are not.

**It is not a video.** The event data is the protocol stream, so
replaying it needs a player that speaks RDP rather than a terminal.
`xproxy-replay`(8) reads these files: it decodes the framing, the
channels and the marks and prints the timeline, and it says plainly that
the graphics are not decoded rather than drawing something nobody sent.
The data is base64 inside the container (`XPROXY_ENCODING: base64`),
because a graphics order is any byte at all.
That is the deliberate choice: decoding at capture time would mean
implementing every graphics encoding a desktop might choose — and
silently losing whatever was not implemented — while a decoder written
against this file later loses nothing.

Counters: `rdp_sessions`, `rdp_sessions_open`, `rdp_rejected`,
`rdp_refused`, `rdp_recorded`, `rdp_mfa_ok`, `rdp_mfa_failed`,
`rdp_channels_refused`, `rdp_devices_refused`, `rdp_legacy_sessions`
(desktop legs opened with the protocol's own encryption),
`rdp_legacy_clients` (client legs served with it). Every session writes one
`rdp` access line with both security protocols, the routing token, the
user and domain, the channels asked for and granted, and how it ended.
Refusals are `rdp_denied` deny events, so bans apply.

### server.listeners[].telnet (kind: telnet)

A `kind: telnet` listener is a telnet gateway: the proxy is a telnet
server to the client and a telnet client to the target, reading the NVT
protocol of RFC 854 in both directions.

**Telnet carries everything in clear.** The session, every password
typed into the target's own login, and the one-time code if this
listener asks for one all cross the network as plain bytes. Wrapping
the listener in TLS (a `tls` section, which is what `telnets` on 992
is) is the only thing that changes that, and validation warns every
time it is left off. This listener exists because the equipment that
speaks only telnet exists, not because telnet is acceptable.

**Why this is not a `tcp` listener.** Telnet's options are commands
escaped into the byte stream: `IAC` (255) begins one, `IAC IAC` is a
literal 255, and everything else is data. A proxy that does not parse
that cannot tell a window-size negotiation from the characters a person
typed — which it has to, to record the session as it was seen, to
decide which options a client may turn on, and to write a prompt of its
own into the stream before the target is dialled.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `upstream` | string | required | The pool of targets |
| `banner` | string | none | What the proxy says before the target is dialled. A banner naming the equipment is one that saves an attacker a question |
| `allow_options` | list | see below | The telnet options a session may negotiate, by name |
| `deny_options` | list | `[]` | Removed from `allow_options`, for changing one thing without restating the list |
| `max_subnegotiation` | int | `4096` | Bound on one subnegotiation; 64..1048576. A peer that sends `IAC SB` and never sends `IAC SE` is cut off here rather than allowed to grow a buffer |
| `recording` | object | none | As `server.listeners[].ssh.recording` |
| `mfa` | object | none | As `server.listeners[].ssh.mfa`; see below for how the code is asked for |
| `require_grant` | bool | `false` | Admit a session only against a live grant from the [access](#access) ledger: one somebody asked for, somebody else approved, and that ends by itself |
| `idle_timeout` | duration | `5m` | No traffic in either direction |
| `session_timeout` | duration | `0` | Bound on a whole session however active; 0 is no bound |
| `max_connections` | int | `1000` | Sessions on this listener |
| `proxy_protocol` | bool | `false` | Send a PROXY protocol v2 header with the client address to the target |
| `allow_clients` | list | `[]` (any) | CIDRs a client must come from |

**Options.** The default list is what an interactive session needs and
nothing else: `echo`, `suppress-go-ahead`, `binary`, `terminal-type`,
`naws`, `terminal-speed`, `end-of-record`, `timing-mark`, `status`.

The others this proxy can name, none of them on by default:

| Option | Why it is not default |
|--------|-----------------------|
| `environ`, `new-environ` | Carry variables of the client's choosing to the target, which is how a login shell is given a different `PATH`. Validation warns when either is allowed |
| `x-display` | Names an X display the target will try to reach, which is a connection back out of the estate |
| `authentication` | Negotiated differently by every implementation that has it; the proxy would relay it without understanding it |
| `encryption` | Would encrypt the session end to end — a session this proxy can no longer record or hold to a policy |
| `linemode`, `flow-control` | Accepted if you name them; left out because the default is character-at-a-time, which is what a recording wants |

An option this proxy has no name for is always refused, whatever the
lists say: one whose effect it cannot name is one it cannot hold to a
policy. A refusal is answered to the side that asked (`WILL` and `WONT`
are declined with `DONT`, `DO` and `DONT` with `WONT`) rather than
dropped, because a refusal the asker never hears is a negotiation that
repeats forever. Each one writes a `telnet_option_refused` line and a
mark in the recording, so an operator asked why a terminal behaves
oddly can see that the proxy is why.

**The second factor.** Telnet has no authentication for a proxy to
read, so `mfa` is a prompt the proxy writes into the stream and an
answer it reads back, before the target is dialled at all — a client
that cannot answer never reaches the equipment. It asks for a login
name, then for a code, with the code not echoed. The name is only what
the enrolment is looked up by: the target's own login happens
afterwards and is untouched, and whether the two names agree is the
target's business rather than this proxy's. A name with no enrolment is
refused where `require_enrolment` is on.

While the proxy is asking its own questions it agrees to no options:
anything the client negotiates then is declined, since the only thing
at the far end so far is the proxy.

**The recording** is the asciicast v2 format the ssh bastion writes, so
the same player replays it. `naws` gives it the window size, and a
resize during the session is recorded as one. `input: true` records
what was typed as well as what was shown, and on telnet that means
every password typed into the target's own login — which the proxy does
not otherwise see. The warning that applies to the bastion applies here
more strongly.

Counters: `telnet_sessions`, `telnet_sessions_open`, `telnet_rejected`,
`telnet_refused`, `telnet_options_refused`, `telnet_recorded`,
`telnet_mfa_ok`, `telnet_mfa_failed`. Every session writes one `telnet`
access line with the client, the name the factor was checked against,
the target, how it ended and how many options were refused. Refusals
are `telnet_denied` deny events, so bans apply.

### server.listeners[].ftp (kind: ftp)

A `kind: ftp` listener is a protocol-aware FTP proxy: the proxy is an
FTP server to the client and an FTP client to the target, and it is one
end of every data connection as well.

**The data connection is why this cannot be a `tcp` listener.** Every
transfer in FTP happens on a second connection whose address one side
announces to the other, in the body of a reply. A proxy that forwards
that reply has told the client to go round it: the file then travels
between the client and the target with nothing in the middle, and the
control connection it did read is a list of instructions for a transfer
it never saw. So the address is replaced with the proxy's own, and the
proxy listens on one side and dials the other.

Only the *port* the target announced is used. The proxy dials the host
its control connection is already talking to, so a target that answers
with an address of its choosing cannot send the proxy somewhere else.

**FTP is old enough to have an attack named after it.** `PORT` and
`EPRT` ask the server to connect back to an address the client names,
and a server that obeys is a port scanner and a relay for anyone who can
log in — the bounce attack of CERT CA-1997-27. Active mode is off by
default. With `allow_active: true` the announced address must be the
client's own and the port must not be privileged; that check is the
whole of the defence, which is why it is stated here rather than
assumed.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `upstream` | upstream | required | The pool of FTP servers |
| `banner` | string | the target's | Replaces the 220 greeting. A banner is a legal notice; the target's own greeting usually names its software and version, which is a different thing |
| `tls_mode` | enum | `starttls` with `tls`, else `none` | `starttls` accepts `AUTH TLS` (RFC 4217), `implicit` is TLS from the first octet (as on 990), `none` is clear |
| `require_tls` | bool | on wherever TLS is reachable | Refuse every command but the ones that get to TLS until the control connection is encrypted. A control connection in clear carries the password |
| `upstream_tls_mode` | enum | `none` | `none`, `starttls` or `implicit` towards the target |
| `upstream_tls` | object | | Verification of the target; the same shape as elsewhere |
| `commands` | list | every command this proxy can read | Verbs a client may send; everything else is 502. A verb whose effect the proxy cannot name is a verb it cannot hold to a policy, so the list cannot be widened past what it understands |
| `read_only` | bool | `false` | Refuse `STOR`, `STOU`, `APPE`, `DELE`, `RNFR`, `RNTO`, `MKD`, `RMD`, `SITE`, `ALLO` |
| `allow_paths` | list | `[]` (any) | Paths a command may name, matched as the sftp policy matches them, and resolved against the working directory the proxy has been following. May carry `{user}` |
| `deny_paths` | list | `[]` | Refused whatever the allow list says |
| `allow_extensions` | list | `[]` (any) | What a file may be called, on the commands that settle a name. Every extension in the name is read, so `invoice.pdf.exe` is an exe |
| `deny_extensions` | list | `[]` | Refused whatever the allow list says |
| `max_file_bytes` | int | `0` (none) | Bounds one transfer either way. It acts by cutting the data connection, because a transfer cannot be un-sent, and the client is told 426 rather than 226 |
| `yara` | object | none | Rules over what is uploaded; the same section as elsewhere, minus `directions` |
| `allow_active` | bool | `false` | Accept `PORT` and `EPRT`, with the address check above |
| `data_address` | address | the control connection's | What passive replies advertise. Set it where the proxy is itself behind a NAT |
| `data_ports` | range | `0-0` (any free port) | `"low-high"` for the passive listeners, so a firewall in front of the proxy can be narrow |
| `data_timeout` | duration | `30s` | How long a data connection may be arranged and not used |
| `max_command_line` | int | `4096` | One control line; 512..1048576 |
| `max_errors` | int | `10` | Refused commands before the session ends |
| `max_connections` | int | `1000` | Control connections on this listener |
| `idle_timeout` | duration | `5m` | No traffic on the control connection |
| `require_grant` | bool | `false` | Admit a session only against a live grant from the [access](#access) ledger: one somebody asked for, somebody else approved, and that ends by itself |
| `session_timeout` | duration | `0` (none) | A whole session, however active |
| `proxy_protocol` | bool | `false` | Send a PROXY protocol v2 header with the client address to the target |
| `allow_clients` | list of CIDR | `[]` (any) | Others are closed at accept |

A control line that is not exactly CRLF-terminated is refused, and so is
one carrying a telnet `IAC`. Each of them is a way for the proxy and the
target to disagree about where a command ends, which is how one command
becomes two: the proxy reads `NOOP` and the target reads `NOOP` and the
`DELE` hidden after a bare newline.

Only the side that arranged a data connection may use it: a passive
connection has to come from the client's own address, an active one from
the target's. The address in a passive reply is *not* used: the proxy
dials the target it already has a control connection to, with the port
from the reply, so a server that answers with somebody else's address
cannot redirect it. `PROT P` is terminated on both sides rather than
tunnelled, so a protected transfer is still a transfer this proxy can
hold to `max_file_bytes` and to its rules. `CCC` is refused twice over:
it is not in the default `commands` list, and a listener whose operator
adds it still gets a 534, because clearing the control channel after
`AUTH TLS` puts the rest of the session, including every path, back in
clear on the wire.

##### The commands that are only half a decision

Two FTP commands mean nothing on their own, and a proxy that read each
command in isolation would hold a policy over both halves and miss what
the pair does.

**`REST`** sets a byte offset for the next transfer. `REST 1000` then
`STOR /pub/x` is not an upload of the bytes that arrive: it is an edit of
a file at an offset, and the bytes that arrive are a fragment. Two
consequences, both of which this proxy acts on:

- A scanner sees what crosses the proxy. With an offset, that is a
  fragment, so `yara` or `icap` rules that would match the whole file
  never see it -- upload the first half, `REST` to the middle, upload the
  second, and each half passes. A resumed transfer on a listener with
  either is refused with 451 (`rest_unscannable`): the proxy cannot scan
  bytes it will never be shown, and pretending otherwise would be a hole
  in the rule set rather than a limitation of it.
- `max_file_bytes` is about the file, so the offset counts towards it. A
  resumed upload of ten bytes at offset sixty is seventy bytes against
  the bound, not ten.

The marker must be a plain non-negative decimal (RFC 3659 lets a server
define its own marker format, which is a value this proxy cannot reason
about and will not carry), it is bounded at 2^40, and it is spent by the
transfer it was for -- refused or not -- and cleared by any command
outside the transfer setup (`PASV`, `EPSV`, `PORT`, `EPRT`, `TYPE`,
`MODE`, `STRU`, `PBSZ`, `PROT`), which is what a server does too.

**`RNFR`** names a file to rename and `RNTO` the new name. An `RNTO`
without an `RNFR` the server accepted with 350 is half a decision, so it
is refused with 503 (`rename_out_of_order`) rather than forwarded -- and
an `RNFR` the path policy refused never reaches the server, so the
`RNTO` that would have completed it is refused too. Anything in between
breaks the pair, as RFC 959 requires.

##### Path shapes the proxy will not guess about

A path argument is refused outright, before the allow and deny lists are
consulted, when the proxy and the server would read it differently.
Each of these is a way for the path the policy matched and the path the
server opened to be two different files:

| Refused | Reason | Why |
|---------|--------|-----|
| A backslash anywhere | `path_separator` | A separator on a Windows server and an ordinary character in a pattern here, so `/srv/exports\..\..\etc` is inside the allowed tree as far as this proxy can tell and outside it as far as the server is concerned. There is no escaping that works for both |
| A control character | `path_control` | Not part of a name anybody needs, and a carriage return is the first half of a command the server reads and the proxy did not (a telnet `IAC` is already refused by the line reader) |
| Bytes that are not valid UTF-8 | `path_encoding` | An overlong sequence decodes to `/` on a lenient decoder and is not a separator to a strict one; a truncated one is a different name depending on who reads it. `OPTS UTF8 ON` is relayed, and matching is on bytes either way, so a path that is valid UTF-8 means the same thing on both sides |

Paths in other scripts are unaffected: this refuses the shapes that
cannot be compared, not everything above ASCII.

#### server.listeners[].ftp.recording

Writes the control channel -- every command and every reply -- to one
file per session, in the asciicast v2 format the ssh bastion uses, so
the same player replays it. The fields are the ones documented under
`server.listeners[].ssh.recording`: `enabled`, `directory`,
`file_prefix`, `max_file_bytes`, `max_files`. (`input` and `commands`
are ssh's and are ignored here: an ftp dialogue has one stream, and the
proxy already sees both halves of it.)

The file is opened when the login is accepted, so a connection that
never authenticates writes none. `PASS` and `ACCT` arguments are
written as `<redacted>`: a recording an operator cannot safely keep is
one that gets turned off. The transferred bytes are not in the file
either -- each transfer leaves a one-line mark saying what moved, how
much and how it ended -- because a copy of every file that crossed the
proxy is a second copy of the data to look after.

#### server.listeners[].ftp.icap

Hands transferred files to a scanning service (RFC 3507) named in
`icap.services`.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `service` | string | required | The name of an entry in `icap.services`. Validation refuses a name that is not there |
| `uploads` | bool | `true` | Scan `STOR`, `STOU` and `APPE` through REQMOD |
| `downloads` | bool | `false` | Scan `RETR` through RESPMOD. Off by default because it doubles the bytes on the wire and most deployments trust what their own server already holds |

A transfer is not an HTTP message, so the file is wrapped in the one a
scanner expects: a `PUT` for an upload, a `GET` and its response for a
download, with the `ftp://` URL of the real file so the scanner's own
log names something findable, the client address in `X-Client-IP` and
the login in `X-Authenticated-User`. Directory listings are not sent:
they are not files.

Scanning means holding the file until the service answers, because a
verdict that arrives after the bytes have gone is not a control. The
service's own `max_body`, `body_limit_action` and `fail` apply exactly
as they do to an HTTP body: a file past `max_body` is refused, or
passed unscanned with a warning in the security log where
`body_limit_action: bypass` says so; a service that cannot be reached
refuses the transfer unless `fail: open`, which also logs. A blocked
transfer is cut and the client gets `426` naming the reason.

#### server.listeners[].ftp.mfa

Asks for a second factor after the target accepts the password, on the
control channel, before any other command is allowed. The fields are
the ones documented under `server.listeners[].ssh.mfa`.

FTP has no prompt of its own, so the code is taken the only two ways
the protocol allows:

- **`ACCT`**, which RFC 959 defines for exactly this. The proxy answers
  the accepted password with `332` and takes the code as the argument
  of the `ACCT` that follows. `ACCT` is added to the relayed commands
  automatically when this section is present.
- **Appended to the password**, after a comma: `PASS secret,123456`.
  The proxy takes the code off and the target sees only the password.
  This needs nothing of the client at all, which is what most
  one-time-password FTP deployments rely on.

Until the factor is verified the session is not logged in: every
command but `ACCT`, `QUIT`, `NOOP`, `FEAT`, `HELP`, `STAT`, `SYST` and
`REIN` is refused with `530`. A user with no enrolment is refused where
`require_enrolment` is on, because an optional second factor is one an
attacker can decline by using an account that never enrolled. Wrong
codes count against `max_errors` and feed the ban triggers, since a
client working through codes is doing what one working through
passwords does.

Validation warns when `mfa` is set with `tls_mode: none`: the code then
crosses the network in clear beside the password it is meant to back
up.

Counters: `ftp_sessions`, `ftp_sessions_open`, `ftp_transfers`,
`ftp_refused`, `ftp_rejected`, `ftp_auth_failed`, `ftp_scanned`,
`ftp_scan_blocked`, `ftp_recorded`, `ftp_mfa_ok`, `ftp_mfa_failed`.
Every session writes an `ftp` access line and every transfer an
`ftp_transfer` line with the command, the path, the octets and whether
it was cut; a finished recording writes `ftp_recording` with the file
and its size. Refusals are `ftp_denied` for the ban triggers, and a
refused factor is `ftp_mfa_failed`.

### server.listeners[].ssh (kind: ssh)

A `kind: ssh` listener is an SSH bastion: the proxy is an SSH server to
the client and an SSH client to the target, with its own host key, its
own authentication and its own credential onwards.

The two connections are the point. A jump host that forwards the stream
cannot see which channel is a shell and which is a port forward, so the
only policy it can hold is "may connect". Here every channel and every
request inside the session is a decision: a service account can be given
sftp to one directory and nothing else, and a port forward to a database
is a rule rather than an assumption.

It also means the target never sees the client's key. The client
authenticates to the proxy; the proxy authenticates to the target with a
credential the client never holds, so a key that leaves the estate is
not a key that opens a server in it. `upstream_known_hosts` is what makes
the bastion the one place that can notice a machine in the middle.

**Host certificates.** An estate that rebuilds machines signs each new
host key with a host CA precisely so that nobody has to edit
`known_hosts` everywhere, and an `@cert-authority` line is how the file
says so. The certificate is then checked as OpenSSH checks it: the
signature against that authority, that it is a **host** certificate
rather than a user one, its validity window, and that its principals
cover the host being reached (the name without the port, as OpenSSH
does). An authority is trusted only for the hosts its own line names.

**Revocation wins.** `@revoked` refuses the key it names whatever else
the file says — the case the marker exists for is a key that is still
listed as trusted somewhere — and for a certificate it covers the key
inside it and the authority that signed it.


An ssh listener takes `address` and `ssh` and no `tls`: SSH carries its
own transport security. Bans and the global connection limits apply at
accept. Changing the `ssh` section rebinds the listener on reload, and
the credentials are read then — not per connection, so a key added to
`authorized_keys` takes effect on reload rather than mid-session.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `upstream` | upstream | required | The pool of target hosts, picked with the upstream's balancer |
| `host_keys` | list of paths | required | The bastion's own host keys, OpenSSH or PEM. Clients pin these |
| `authorized_keys` | path | | OpenSSH authorized_keys of the clients that may connect. Options in the file are ignored; the policy lives here. A line that does not parse fails the load rather than silently shortening the list |
| `trusted_user_ca_keys` | path | | OpenSSH public keys, one per line, that may sign user certificates. A client offering a certificate is accepted when the signature verifies, the validity window covers now and the principal list names the login it is connecting as; without this key a certificate is refused rather than treated as a plain key. What else the certificate says is read too: see below |
| `revoked_keys` | path | | Public keys, in authorized_keys format, refused whatever else says otherwise: the key itself, a certificate carrying it, and every certificate signed by it. It is the one list that overrides the CA, which is what makes a certificate revocable before it expires |
| `max_certificate_lifetime` | duration | `0` (none) | Refuse a user certificate whose validity window is longer than this, and any that never expires. The point of certificates over `authorized_keys` is that they expire; a CA issuing for a year has made a credential nobody can take back for a year |
| `max_forwards` | int | `8` | Port forwards one connection may hold open at once. A session that may forward at all can otherwise open one per descriptor the proxy has |
| `max_sessions_per_principal` | int | `0` (none) | Connections one principal (or, with no `principals`, one login) may hold at once. `max_sessions` is the whole fleet's: a bound of a thousand is a thousand for one key as much as for everybody |
| `rekey_bytes` | int | `0` | Bytes before the transport agrees a fresh key; the crypto library's own threshold when unset. A bastion session lasts a working day on one key otherwise |
| `allow_shell_syntax` | bool | `false` | Let an `exec` command carry shell operators. See below: `allow_commands` is a list of patterns, and a pattern is a weak thing to hold a shell to |
| `users_file` | path | | A users file (as in `forward.auth`) for password authentication. Warned about on its own: a bastion behind one guessable secret is one guess from the estate |
| `banner` | string | none | Sent before authentication. A legal notice belongs here; a version string does not |
| `server_version` | string | `SSH-2.0-xproxy` | The identification string; must begin with `SSH-2.0-` |
| `max_auth_tries` | int | `3` | Authentication attempts per connection |
| `max_sessions` | int | `1000` | Connections on this listener |
| `max_channels` | int | `16` | Open channels per connection |
| `handshake_timeout` | duration | `30s` | Key exchange and authentication together |
| `idle_timeout` | duration | `30m` | No traffic either way |
| `session_timeout` | duration | `0` (none) | A whole connection, however active |
| `allow_channels` | list | `[session]` | Channel types a client may open: `session`, `direct-tcpip`, `direct-streamlocal@openssh.com` |
| `allow_requests` | list | `pty-req, env, shell, exec, subsystem, window-change, signal` | Session requests a client may send. `x11-req` and `auth-agent-req@openssh.com` are left out and warn when added: each hands whatever runs on the target a channel back into the client, and agent forwarding lets it sign with the client's keys for the life of the session |
| `allow_subsystems` | list | `[sftp]` | Subsystems a client may start, checked even when `subsystem` is allowed |
| `allow_commands` | list of RE2 | `[]` (any) | An `exec` command must match one, anchored as written. Every allowed exec is a security event with the command line |
| `allow_env` | list | `TERM, LANG, LC_*` | Environment variables a client may set, as names or as prefixes ending in `*`. Everything else is refused with the request. The loader and interpreter variables (`LD_*`, `DYLD_*`, `BASH_ENV`, `ENV`, `SHELLOPTS`, `IFS`, `PS4`, `PERL5OPT`, `PERL5LIB`, `PYTHONPATH`, `PYTHONSTARTUP`, `PYTHONHOME`, `RUBYOPT`, `NODE_OPTIONS`, `GLIBC_TUNABLES`, `GCONV_PATH`, `LOCPATH`, `TMPDIR`, `GIT_SSH*`, `PATH` and their kin) are refused whatever this says, and naming one fails the load: each is a way to run code before the command the policy approved |
| `allow_file_transfer_commands` | bool | `false` with an `sftp` section, `true` without | Accept `exec` commands that are file transfer helpers: `scp`, `rsync`, `sftp-server`, `internal-sftp`, `lftp`, `rclone`. They move files without ever opening the `sftp` subsystem, so every path and operation rule there is off their path; setting this beside an `sftp` section warns, because it is exactly the bypass that section exists to close. Every word of the command is read, not only the first, each with any directory part removed and a `VAR=value` prefix skipped, so a wrapper (`env scp -t`, `sudo rsync`, `sh -c "scp …"`) is refused too |
| `command_rules` | list | `[]` | Hold the file transfer families to what they *mean* rather than to a pattern: the direction, recursion, deletions and the paths in reach, read the way `scp`, `rsync`, the sftp server and `git` read their own arguments. See below |
| `principals` | list | `[]` | Per-key policy; see below. Empty means the listener's own policy applies to everyone |
| `forward` | list | `[]` | Destinations `direct-tcpip` may reach: `host:port`, `*.suffix:port`, `10.0.0.0/8:port`, `*` for any port. Required when `direct-tcpip` is allowed, and refused without it: a forward with no destination policy is a tunnel to anything the target can reach |
| `remote_forward` | bool | `false` | Accept `tcpip-forward`, which asks the target to listen on the client's behalf and turns the session into an inbound path |
| `upstream_user` | name | the authenticated name | The account on the target |
| `upstream_key_file` | path | required | The private key the proxy authenticates to the target with |
| `upstream_known_hosts` | path | required unless insecure | OpenSSH known_hosts the target's key is checked against, read once at bind. All three kinds of line are honoured: a plain entry trusts that key, an `@cert-authority` entry trusts a host CA (so a target presenting a host certificate that CA signed is accepted without its own key being listed), and an `@revoked` entry refuses the key it names before any other line is consulted — including the authority, which takes back every certificate that CA ever signed. A file that trusts nothing is a bind error |
| `upstream_insecure_host_key` | bool | `false` | Accept any host key from the target. Refused unless `allow_insecure` is also set, and warned about: it is the one setting here that leaves nothing to notice a machine in the middle |
| `recording` | object | none | Record what a session showed, to a file per channel; see below |
| `mfa` | object | none | Require a second factor after the key or the password; see below |
| `require_grant` | bool | `false` | Admit a session only against a live grant from the [access](#access) ledger: one somebody asked for, somebody else approved, and that ends by itself |
| `sftp` | object | none | Inspect the SFTP protocol inside an sftp subsystem channel; see below |
| `proxy_protocol` | bool | `false` | Send a PROXY protocol v2 header with the client address to the target |
| `allow_clients` | list of CIDR | `[]` (any) | Others are closed before the handshake |

#### server.listeners[].ssh.principals

Without this list a bastion has one policy for everyone in
`authorized_keys`: the deployment robot may run what the on-call
engineer may run. Each entry names who it covers and what they may do,
and the listener's own settings are what an entry leaves unset — so an
entry that only moves someone to another account on the target says only
that.

The list is the policy. Once there is one entry, a key no entry covers
is refused at authentication rather than served under the listener's
default, because falling back would be the opposite of what the list
says.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | name | required | What the access log and the security events call this principal, so a refusal names a person rather than a fingerprint |
| `fingerprints` | list | `[]` | SHA256 fingerprints of the keys this entry covers, in the form `ssh-keygen -lf` prints: `SHA256:` and the base64 of the digest |
| `cert_principals` | list | `[]` | Certificate principals this entry covers. Needs `trusted_user_ca_keys`: a certificate is matched by the names its CA signed into it, and by the key it carries |
| `users` | list | `[]` (any) | Login names the entry applies to, so one key can be one thing as `deploy` and another as `root` |
| `policy` | object | inherit | What this principal may do; see below |

An entry that names neither a fingerprint nor a certificate principal
matches every key, which is how a list ends in a default. It must be the
last entry, because an entry after it could never be reached.

The policy object takes `upstream_user`, `allow_channels`,
`allow_requests`, `allow_subsystems`, `allow_commands`, `command_rules`,
`allow_env`, `forward`, `remote_forward` and `sftp`, each meaning what it
means on the listener and each falling back to the listener when unset,
plus:

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `deny` | bool | `false` | Refuse this principal outright. It is how a key stays in `authorized_keys` while the person it belongs to is on leave, without the list losing the record that they exist |

A denied principal never reaches the target: the refusal is at
authentication, before a channel or an upstream connection exists.

A principal's `recording` replaces the listener's, which is how one
entry is recorded and another is not; `recording: {enabled: false}` is
how a principal is spared where the listener records.

An entry that brings its own `sftp` section to a listener that has none
also inherits the default that section implies: file transfer helpers
are refused for that principal, because `scp` beside a careful `sftp`
policy is the policy with a door next to it.

##### What the certificate says, beyond the signature

A user certificate is not only a signature over a key and a list of
principals. It carries the CA's own restrictions, and a gateway that
checks the signature and ignores the rest is a gateway where those
restrictions do not exist. All of these are enforced:

- **`source-address`**, the critical option naming the networks the
  certificate may be used from. It is enforced here because it is the
  one option whose check needs the client's address, which is why the
  Go library deliberately leaves it to the caller. A list this gateway
  cannot parse refuses the certificate rather than being treated as
  absent.
- **`force-command`**, the critical option fixing what the session runs.
  The client's command is *replaced* by it, as OpenSSH does — a
  certificate issued to run one thing is issued for a reason — and a
  `shell` request becomes that command too. Both are written to the
  security log as `ssh_force_command`, with what was asked and what ran.
- **The extensions are permissions, and their absence is a denial.**
  `permit-pty`, `permit-port-forwarding`, `permit-agent-forwarding`,
  `permit-X11-forwarding`. A certificate made with `ssh-keygen -O clear
  -O permit-pty` grants a terminal and nothing else, whatever this
  listener's `allow_channels` and `allow_requests` would otherwise
  allow. A certificate issued the ordinary way carries all five, so
  nothing changes for one.
- **Any other critical option refuses the certificate.** A critical
  option is critical: the CA meant it to be honoured or the credential
  refused, so an option this gateway does not implement must not be
  quietly ignored.

Both policies apply and the narrower wins: the CA says what this
credential may do, the listener says what anybody may do here. A session
authenticated by a plain key is restricted by the listener alone.

##### `allow_commands` is patterns, and a shell is not

`allow_commands` is a list of RE2 patterns over the command line, and a
pattern is a weak thing to hold a shell to: `^journalctl .*$` matches
`journalctl -u x; rm -rf /` exactly as happily as what it was written
for. So the line is read the way a shell would split it *first*, and one
carrying an operator — `;` `&` `|` `<` `>` a backquote, a `$(`, a brace,
a glob, a control character, an unbalanced quote — is refused with
`shell_syntax` before any pattern is tried.

This is deliberately crude and deliberately broad. A bastion does not
need to know what a line would do; it needs to know that the line is a
command with arguments, which is the only shape a list of patterns can be
written against. `allow_shell_syntax: true` turns the check off for a
listener that genuinely needs shell syntax, and warns, because the
patterns then have to be written knowing it.

The strong form of a command policy is `force-command` on the
certificate: the CA fixes the command and the client's own is replaced,
so there is no line to pattern-match at all.

##### server.listeners[].ssh.command_rules

A pattern is a weak boundary, and for the commands that move files it is
the wrong shape of statement. `^scp -t /srv/incoming$` is somebody
writing *"uploads into that directory, nothing else"*, and each of these
is past it:

| The line | What a pattern misses |
|----------|-----------------------|
| `scp -f /srv/incoming` | The other direction, spelled with the same words |
| `scp -rt /srv/incoming` | Bundled flags, so the pattern does not match — and recursion is a different permission |
| `/usr/bin/scp -t /srv/incoming` | A path, so the pattern does not match |
| `scp  -t  /srv/incoming` | Two spaces |
| `scp -t /srv/incoming/../../etc/ssh` | A path inside `/srv/incoming` to a pattern, `/etc` to the target |
| `LD_PRELOAD=/tmp/x.so scp -t /srv/incoming` | An environment the `allow_env` policy never sees, because it is a shell assignment and not an `env` request |

Tighten the pattern against any one of them and it is still wrong about
the next. What the policy means to say is a statement about the
command's *meaning*, so that is what a rule says: the direction, whether
recursion is allowed, whether deletions are, and which paths are in
reach. The command line is split the way a shell splits it, the options
are read the way the program reads them, and the rule is applied to
that.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `command` | `scp`, `rsync`, `sftp_server`, `git` | required | The family this rule decides. One rule per family; a second is a load error, since which of the two was silent would be the policy |
| `directions` | list of `upload`, `download` | required (not for `sftp_server`) | The file movements allowed. `upload` puts files **on** the target, `download` takes them **off** it — the movement, not the program's own verb: a git fetch is `upload-pack` because that name is the server's, and it is a `download` here |
| `paths` | list | `[]` (every path) | The paths in reach, as the `sftp` policy's patterns (`/srv/incoming/**`). Absolute; a relative pattern is a load error, because the path it is matched against is resolved from the root |
| `deny_paths` | list | `[]` | Refused whatever `paths` says |
| `recursive` | bool | `false` | Allow `scp -r`. Only scp takes it |
| `delete` | bool | `false` | Allow the rsync options that remove files at the far end: `--delete` and its family, `--remove-source-files`, `--force`. Only rsync has them |
| `enforce_sftp_policy` | bool | `false` | Relay an approved exec of the sftp server binary through the `sftp` policy. Required for a `sftp_server` rule and refused for the others |

```yaml
sftp: {read_only: true, allow_paths: ["/srv/data/**"]}
command_rules:
  # The deployment robot puts artefacts in one directory and takes
  # nothing out. No recursion: a file is a file.
  - command: scp
    directions: [upload]
    paths: ["/srv/incoming/**"]
    deny_paths: ["/srv/incoming/keys/**"]
  # Backups pull, and may not delete what they pull from.
  - command: rsync
    directions: [download]
    paths: ["/srv/data/**"]
  # Clones and fetches, no pushes.
  - command: git
    directions: [download]
    paths: ["/srv/git/**"]
  # And the sftp server binary run as a command is the sftp subsystem
  # under another name, so it is allowed only inspected.
  - command: sftp_server
    enforce_sftp_policy: true
```

**With any rule present, a family named by no rule is refused.** A rule
for scp must not quietly leave rsync to the patterns, so the families
this gateway can read are a positive model once the list exists
(`command_no_rule`). Everything else — every command with no parser here
— stays with `allow_commands` exactly as before.

**A rule allows what `allow_file_transfer_commands: false` refuses.**
That switch is "scp and rsync, yes or no"; a rule is "scp, uploads, into
this directory", which is the decision an operator wanted to make. So a
rule wins over the blanket refusal for the family it names, and over
`allow_commands` too: a command a rule allows is not also pattern
matched, because the rule is the narrower statement.

**A line that cannot be read is refused, never guessed at**
(`command_syntax`): a substitution, an unbalanced quote, an option no
version of the program takes. This applies to the families the rules
cover even where `allow_shell_syntax` is on — `scp -t $(cat /etc/x)` is
refused as an scp whose words cannot be trusted — while a command of no
family keeps whatever behaviour that setting gives it.

**A wrapper is not read through.** `env scp -t /etc`, `sudo rsync`,
`sh -c "scp -t /etc"`: the command is `env`, `sudo` and `sh`, so no rule
covers it and the blanket check refuses it as it did before. A rule is
never a way to reach scp through something else.

What each refusal is counted and logged as:

| Label | What it means |
|-------|---------------|
| `command_direction` | The movement the rule does not allow (`scp -f` where only uploads are allowed, a push where only fetches are) |
| `command_path` | A path outside `paths`, inside `deny_paths`, above its own root, or a glob whose expansion cannot be proven inside an allowed subtree |
| `command_recursive` | `scp -r` without `recursive: true` |
| `command_delete` | An rsync option that removes files, without `delete: true` |
| `command_server` | Not the far side of a client's transfer at all: an scp with neither `-t` nor `-f`, an rsync with no `--server` (which would dial out of the target) |
| `command_env` | A `VAR=value` assignment in front of a transfer command |
| `command_no_rule` | A family this gateway reads, with no rule of its own |
| `command_syntax` | A transfer line that could not be read as one simple command |

Two honest limits, because a boundary that is believed to be somewhere
it is not is worse than a narrow one:

- **rsync's file list is inside rsync's own protocol.** In server mode
  the arguments carry the transfer root and the options; which files
  move is negotiated afterwards, in a stream this gateway relays but
  does not parse. So an rsync rule decides the direction, the deletions
  and the root — and everything under that root is in reach of the
  transfer. Where a per-file rule is the requirement, `sftp` is the
  protocol that can carry one.
- **A glob is the target shell's to expand.** `scp -f /srv/data/*` is
  admitted only when `paths` covers a whole subtree that contains the
  directory the pattern sits in (`/srv/data/**`), since a shell's `*`
  does not cross a `/`. With a single-level pattern, or with any
  `deny_paths` — which a glob cannot be proven clear of — it is refused.
  Globs need `allow_shell_syntax` to reach a rule at all.

#### server.listeners[].ssh.recording

The access log says a session happened. It cannot say what was done in
it, because what was done is a stream of control sequences inside the
channel. This writes that stream to a file per channel, in the
asciicast v2 format, so "what did they actually run" is a question with
an answer that is watched rather than reconstructed:

```
xproxyctl session show /var/log/xproxy/sessions/session-20260921-143022.100-alice.cast
```

The format is line oriented, so a recording cut short by a crash or by
`max_file_bytes` still plays up to where it stops, and it is text, so
the usual tools work on it. It is a stream, not a transcript: what the
person saw is what a terminal makes of it, which means **reading one is
replaying it** — a terminal is an interpreter, and the bytes in the file
were written by the person recorded. `xproxyctl session show`, `show
-safe` and `play` read one with the sequences that reach outside the
replay taken out: the clipboard writes, the title changes, and the
device reports a terminal answers on its own input, which a shell then
reads as a command line. `asciinema play` and `cat` do not. See
[USAGE.md](USAGE.md#reading-a-recording-without-running-it).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Present so a principal can turn a listener's recording off; there is no reason to write it as `true` |
| `directory` | path | required | Where the files go. It must exist: the proxy does not create it, because where these files live is a decision to make rather than to inherit |
| `file_prefix` | name | `session` | Begins each file name, which is then the time and the login, and always ends `.cast` |
| `input` | bool | `false` | Record what was typed as well as what was shown, as asciicast `i` events beside the `o` ones. It warns, and the warning is the point: a terminal's input stream carries what the screen never showed, which includes every password typed into a `sudo` or `su` prompt. On the graphical gates (`vnc`, `rdp`) it means the viewer's or client's own stream -- every key and pointer event, and on RDP the channel traffic a file would leave through -- and a message or unit the policy refused is written as a mark rather than as bytes, so a replay shows that the client tried and the gateway said no |
| `max_file_bytes` | int | `33554432` | Bounds one recording, counted in session bytes; 4096..4294967296. Past it the session carries on and the file says it stopped |
| `max_files` | int | `1000` | Recordings this listener keeps, removing the oldest it wrote. It bounds what the proxy leaves behind; anything that must be kept belongs somewhere the proxy does not prune |
| `commands` | bool | `true` | Record `exec` sessions too, not only the ones with a terminal |

The header carries the terminal size from `pty-req`, the login and the
target, and for an `exec` the command. A `window-change` becomes a
resize event, so a session that was widened replays at both widths
rather than wrapping everything after it in the wrong place. Both of
the target's streams are recorded: a terminal does not keep stdout and
stderr apart either, and a recording without stderr would be missing
exactly the errors.

An `sftp` channel is not recorded. It is not a terminal, and its own
`sftp` log line already says what each request did.

**These files hold everything the session showed.** On an
administrative session that is a list of everything worth having — keys
printed, configuration read, tokens echoed. They are written `0600` by
the proxy user, with `O_EXCL` and proxy-chosen names, in a directory the
operator names; the directory deserves the care the credentials in it
will deserve. `input: true` goes further still, and is the difference
between watching over a shoulder and running a keylogger: it is off by
default, it warns when set, and whether it is lawful where you are is
not a question this configuration can answer.

A recording that cannot be opened does not stop the session: it is an
error in the log and an `ssh_recording_failed` event, because a bastion
that refuses work when a disk fills is its own outage. One that stops
part way is logged as short, with the reason.

#### server.listeners[].ssh.mfa

A second factor after the key or the password. The client is told
authentication partially succeeded (RFC 4252 partial success) and is
then asked, over keyboard-interactive, for a one-time code (RFC 6238
TOTP over the HMAC-OTP of RFC 4226). Nothing about the session exists
until the code verifies: a key alone opens no channel.

The same section shape, the same enrolment file and the same rules serve
the HTTP `mfa` filter. That is deliberate — a second factor that means
different things on different ports is not a second factor, because the
weakest door decides.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `file` | path | required | The enrolment file (`xproxyctl mfa enrol` writes the lines). Refused if world readable: it holds every second factor. Re-read when it changes on disk, at most once a second, so enrolling and removing take effect without a reload |
| `issuer` | name | `xproxy` | The name an authenticator application shows |
| `prompt` | string | `One-time code: ` | What the user is asked |
| `skew` | int | `1` | Steps either side of now that are accepted, for a clock that is a little off. Each step is a window an observed code can be replayed in, so above 2 it warns |
| `require_enrolment` | bool | `true` | Refuse a user with no enrolment. `false` warns: the account that never enrolled is the one an attacker will use |
| `max_failures` | int | `5` | Failures within `window` before the user is locked out |
| `window` | duration | `5m` | The window failures are counted in |
| `lockout` | duration | `15m` | How long a locked user stays locked |
| `max_users` | int | `10000` | The table that remembers spent codes and recent failures. When it is full the least recently seen entries are dropped, which loses replay memory for idle users rather than refusing everyone |

A code is spent when it is used: a later attempt at the same step, or at
an earlier one, is refused even though it verifies. The memory is per
process, so in a cluster a code can be replayed once per node — put the
listener behind one node where that matters, or keep `skew` at 0.

What the client is told never distinguishes a wrong code from a replayed
one, from a locked account, or from a name that never enrolled. The
prompt is shown even to a user with no enrolment, because refusing
before asking says the name is not enrolled.

The file can also be changed while the proxy runs, through the
management API (`/v1/mfa*`), the GUI's MFA page or the TUI's MFA
screen — enrol, replace recovery codes, remove, unlock. An enrolment is
shared by every listener reading the same file; a lockout is not, since
it lives in the process that counted the wrong codes. See
`docs/USAGE.md`.

#### server.listeners[].ssh.sftp

Without this section the proxy can say only that a session may use
`sftp`. That is the difference between reading a file and deleting a
tree: the whole of it happens inside the channel. With it, each SFTP
request is decided, and a refusal is answered with a permission-denied
status, so the session continues and the client is told which operation
was refused rather than losing its connection.

Only version 3 is parsed. A client that negotiates higher is refused at
the version exchange, because packets this cannot read are packets whose
policy would be guesswork.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `read_only` | bool | `false` | Refuse everything that changes the server: write, setstat, remove, mkdir, rmdir, rename, symlink, an open with any writing flag, and the extensions whose meaning the proxy does not know |
| `allow_paths` | list | `[]` (any) | Paths a request may name: a glob where `*` does not cross a slash, or a prefix ending in `/` or `/**` for a whole tree |
| `deny_paths` | list | `[]` | Refused whatever the allow list says |
| `deny_operations` | list | `[]` | Operations refused by name: `open`, `read`, `write`, `remove`, `rename`, `symlink`, `setstat`, `readlink`, `extended`, … |
| `allow_extensions` | list | `[]` (any) | File extensions a name may carry, written without the dot and compared without case. Checked on `open`, and on both names of a `rename` or a `symlink` — the requests that decide what a file is called. A name claiming no extension claims nothing to refuse and passes |
| `deny_extensions` | list | `[]` | Refused whatever the allow list says. Every extension a name carries is read, not only the last, so `invoice.pdf.exe` is an exe |
| `max_file_bytes` | int | `0` (none) | What one open file may be written. Counted from the highest offset a write reaches, not from the bytes sent, so writing out of order does not walk past it |
| `max_open_files` | int | `256` | Handles one session may have open at once, which is what the per-file state costs |
| `yara` | object | none | Rules over what is written, per file; the same section as a `tcp` listener's `yara` minus `directions`, which is not read here. See below |
| `max_packet_size` | int | `262144` | One SFTP packet; 4096..16777216 |

`allow_paths` and `deny_paths` may carry `{user}` and `{principal}`,
substituted once per session from the login the client authenticated as
and the `principals` entry covering its key. That is how one listener
says "your own directory and no other" instead of one list naming
everybody's. A name that could change what a pattern means — anything
outside letters, digits, `-`, `_` and `.`, anything over 64 characters,
or a name that is only dots — refuses the session rather than being
substituted or escaped: a login of `../..` expanded into an allow list
is an allow list for somebody else's directory. `{principal}` on a
listener with no `principals` fails the load, since no session would
have a name to put there. An unknown substitution is a load error too,
not a literal: `{usr}` left as it stands matches nothing, which on an
allow list refuses everybody and on a deny list refuses nobody.

**Writes get two more checks, because a write is the one request whose
content the proxy can see.** `max_file_bytes` bounds the file the writes
make. `yara` runs the rule set over what goes into each file separately:
a rule about a file's first bytes is a rule about a file, and two
uploads interleaved on one channel are two files, so each open handle
gets its own scanner. A match refuses that write with permission denied
and writes a `yara_match` security event naming the path; with the
section's `action: close` the transfer ends there rather than only the
one packet. Both need to know which handle is which file, so a write on
a handle whose `open` this proxy never decided on is refused: a write
that cannot be held to a bound is not a write to pass on.

A path that climbs above its own root after cleaning (`../../etc/shadow`)
is refused rather than matched: what it means depends on a working
directory the proxy cannot see, and a check on a path whose meaning is
unknown is not a check. Absolute paths always work, so nothing legitimate
needs the other form.

##### server.listeners[].ssh.sftp.icap

Hands written files to a scanning service (RFC 3507) named in
`icap.services`.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `service` | string | required | The name of an entry in `icap.services`. Validation refuses a name that is not there |
| `uploads` | bool | `true` | Scan what the client writes |
| `downloads` | bool | refused here | See below: SFTP has nothing to scan a download at |

**A scanned upload is held, not forwarded.** SFTP has no whole-file
transfer: a file is an `open`, a run of `write`s at offsets, and a
`close`. A scanner wants the file. So the proxy answers each `write`
itself with a success status, keeps the packets, assembles what the
file turns out to be, and asks the service only when the handle is
closed. A clean file's writes are then replayed to the server in the
order the client made them, and the `close` is forwarded; a refused
file's writes are dropped and the `close` is answered with a failure.
The file never reaches the server.

Three consequences worth knowing before turning it on:

- The file is in memory until the `close`, bounded by the service's
  `max_body`. Past that, `body_limit_action` decides: `reject` refuses
  the write, `bypass` releases what was held and stops holding, with a
  warning in the security log naming the path.
- The success a client sees for a `write` is the proxy's, not the
  server's. A server that would have refused the write for its own
  reasons — no space, no permission — says so at the `close` instead,
  which is where a client that checks only the final status will see it
  anyway.
- The `open` is forwarded when it happens, so a refused file can leave
  an empty file behind. The proxy does not remove it: that would be a
  write it was never asked to make.

**Downloads are not scanned here, and the section refuses to pretend
otherwise.** A download in SFTP is a run of `read`s at offsets that the
client stops making when it has what it wants; there is no packet that
means "the file is finished", so there is no point to scan at. Scanning
one would mean the proxy fetching the whole file itself and serving the
client's reads from that copy, which is a different feature with
different costs. `downloads: true` is a configuration error here rather
than a setting that quietly does nothing. The `ftp` listener, where a
`RETR` is one whole-file transfer, does scan downloads.

Every session writes one `ssh` line to the access log (client, user,
authentication method, principal, target, channels, refusals, duration) and each
inspected SFTP request writes one `sftp` line with the operation and the
path; the `close` of a scanned file carries a `scan` field saying how
many bytes were released or why they were blocked. Counters:
`ssh_sessions`, `ssh_sessions_open`, `ssh_channels`, `ssh_refused`,
`ssh_rejected`, `ssh_auth_failed`, `ssh_bytes_in`, `ssh_bytes_out`,
`sftp_requests`, `sftp_refused`, `sftp_scanned`, `sftp_scan_blocked`;
the matching `xproxy_ssh_*` and `xproxy_sftp_*` metrics. Refusals and
failed authentication are `ssh_denied` deny events, so bans apply, and
a file the scanner refuses is an `sftp_icap` observation on the ban
ladder.

### server.listeners[].h3

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `max_streams` | int | `100` | Concurrent request streams per QUIC connection; 1 to 10000 |
| `validate_addresses` | `always`, `under_load` | `always` | `always` makes every unvalidated client address complete a Retry round trip before the server allocates connection state; `under_load` does so only when open connections exceed a quarter of `max_connections` |
| `alt_svc_max_age` | duration | `24h` | Reserved for the `Alt-Svc` `ma` value (currently the library default) |
| `webtransport` | bool | `false` | Accept WebTransport sessions on this endpoint: HTTP/3 datagrams and the WebTransport settings are enabled and routes with `webtransport: true` relay them. The `Origin` header is forwarded for the upstream to check |

QUIC connections share the listener's `max_connections`,
`max_connections_per_ip`, ban list, header size and idle timeout;
`read_header_timeout` bounds the handshake. `read_timeout` and
`write_timeout` do not apply to HTTP/3 streams; use route `timeout` and
upstream `total` for those. 0-RTT is never enabled.

### server.listeners[].tls

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `certificates` | list | one of `certificates` or `acme` | PEM certificates with a private key, selected by SNI, first is the fallback. Each entry names `cert_file` and then exactly one of `key_file`, `key` or `signer` to say where the private key comes from -- see [Where a private key lives](#where-a-private-key-lives) |
| `acme` | list | | `{hosts: [...]}` groups issued and renewed through the top-level `acme` section; one certificate per group, named after its first host. Hosts are fully qualified names without wildcards and unique across the listener. Selected by SNI after the file certificates |
| `min_version` | `"1.2"` or `"1.3"` | `"1.2"` | TLS 1.0 and 1.1 cannot be configured |
| `client_auth` | `none`, `request`, `require` | `none` | Client certificates; `request` verifies if presented |
| `client_ca_file` | path | | Required for `request` and `require` |
| `cipher_suites` | list of names | ECDHE AEAD suites | TLS 1.2 suites, crypto/tls names. Insecure suites are rejected. TLS 1.3 suites are not configurable. |
| `key_exchange` | list of group names | `X25519MLKEM768`, `X25519`, `P-256`, `P-384` | Key agreement groups this listener accepts; see below |
| `ech` | object | none | Accept Encrypted Client Hello; see below |
| `ocsp_stapling` | object | none | Fetch OCSP responses for the served certificates in the background and staple them into handshakes; see below |
| `ct` | object | none | Check the Certificate Transparency SCTs embedded in file certificates at load; see below |
| `expiry` | object | none | What an expired or nearly expired certificate does; see below |

#### server.listeners[].tls.key_exchange

The accepted key agreement groups, in preference order:
`X25519MLKEM768`, `X25519`, `P-256`, `P-384`, `P-521`. The default
leads with `X25519MLKEM768`, the hybrid that combines X25519 (RFC 7748)
with the ML-KEM lattice KEM of FIPS 203, as
`draft-kwiatkowski-tls-ecdhe-mlkem` defines it for TLS and as Chrome,
Firefox and every major CDN deploy it.

Why it is a setting at all: Go chooses a good set by itself, but *only*
while the list is left unset, and naming any group replaces the whole
list. A configuration written to prefer X25519 therefore drops the
post-quantum hybrid silently, and nothing in a handshake says so. Making
the list explicit means the choice is validated, documented and visible
in `xproxyctl tls`, rather than a side effect of a line nobody re-read
after a toolchain upgrade.

Why the hybrid leads: traffic recorded today is decrypted by whoever
holds a quantum computer in ten years — the data does not have to be
interesting now, only later. A hybrid exchange costs about a kilobyte
in the ClientHello and removes that trade entirely, and its classical
half keeps the exchange at least as strong as X25519 alone if the
lattice half is ever broken.

Note what the list is: the set the server *accepts*. In TLS 1.3 the
client sends a key share, and the server takes the first offered share
it accepts rather than forcing its own favourite with a retry — so a
server that accepts several groups usually ends up on the client's
first choice, and a client that offers nothing acceptable is sent a
HelloRetryRequest naming one it can use. Restricting the list to one
group is how you force it, at the cost of a round trip for clients that
guessed differently.

A list that names groups but no post-quantum one loads with an advice
line rather than an error: a client fleet that cannot negotiate the
hybrid exists, and that is an operator's decision, not the proxy's.

The negotiated group is in the access log as `tls_group`, counted by
`xproxy_tls_key_exchange_total{group}`, and summarised by `xproxyctl
tls` with the post-quantum share — which is the number a rollout is
actually measured by, because it moves as client fleets upgrade and not
as this file changes.

#### server.listeners[].tls.ech

Encrypted Client Hello. A TLS 1.3 handshake still names its destination
in the clear — the SNI is the last plaintext identifier in a modern
connection, and the one that monitoring and blocking actually use. ECH
encrypts the real ClientHello (SNI, ALPN, everything) to a public key
the client fetched from DNS, and wraps it in an outer hello naming a
*public name* shared by everything behind that key. An observer sees a
connection to the public name and cannot tell which site it was for.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `keys` | list | required | The configurations this listener can decrypt; 1 to 8. Several are live during a rotation |
| `keys[].config_file` | path | required | The ECHConfig: raw bytes, base64, or the `ech=` value pasted from a record |
| `keys[].key_file` | path | required | The X25519 private key: raw 32 bytes, base64, hex or PKCS#8 PEM. Must not be world readable |
| `keys[].retry` | bool | `true` | Offer this config to a client whose key was stale, which is how a rotation heals itself |
| `require` | bool | `false` | Refuse a handshake that did not use ECH |

Generate a key and the record to publish with `xproxyctl ech keygen`;
the configuration and key files it writes are what `config_file` and
`key_file` point at. Enabling ECH raises the listener to TLS 1.3, since
a 1.2 handshake has no encrypted hello to carry it.

**The public name needs a certificate here.** A client whose key is
stale — a cached DNS answer, a record that has not propagated — falls
back to an ordinary handshake with the public name, and meets a
certificate error unless this listener can serve it. Validation warns
when no configured certificate covers it. That fallback is not a
failure mode to be avoided; it is what makes rotation safe.

**Rotating.** Generate the new key, add it to `keys` with `retry: true`,
publish an `ech=` list containing both, wait out the old record's TTL
everywhere, then drop the old key. `xproxyctl tls` prints the list the
listener is actually serving, so the published value and the served
value cannot drift apart unnoticed. `xproxyctl reload-certs` re-reads
ECH keys along with certificates.

**`require` is a blunt instrument.** It refuses every client that did
not use ECH, including one whose DNS answer was stripped by a resolver
that does not know the record, and one whose platform does not
implement ECH at all. It is for a listener that exists only for ECH
clients; validation prints an advice line saying so.

**ECH and layer 4 routing.** A `kind: tcp` listener routes on the SNI
it can see, which with ECH is the *outer* name: every ECH client looks
like a connection to the public name, so a passthrough listener in
front of an ECH listener cannot split them. Terminate TLS where ECH is
accepted, or give the public name its own backend.

**Fingerprints.** The outer hello is what JA3 and JA4 are computed
from, so fingerprinting keeps working; what changes is that the SNI in
`sni` is the public name for every ECH client. The access log carries
`ech: true` when ECH was accepted, which is how to tell the two apart.

#### server.listeners[].tls.expiry

A certificate outliving its validity is the single most common way a
working service stops working, and by default this proxy serves an
expired certificate: the client is the one that decides whether to trust
it, so serving one is not a security hole — it is an outage nobody can
read, because every client discovers it separately.

This section says so in one place instead. What it can do is bounded, and
the boundary is deliberate:

- `refuse_expired` makes an already expired certificate a **load error**.
  At start the listener does not come up and the message names the file.
  On a reload the new configuration is refused and **the certificate
  already in use keeps working**, which is the case where refusing is
  strictly better than serving: a botched renewal that wrote an expired
  file no longer replaces a working one.
- `warn` is a window before expiry. Certificates inside it are reported,
  worst first, by `xproxyctl tls` (an `EXPIRY` line each), by
  `GET /v1/tls/expiring`, and in the security log at every load and
  reload.

A certificate that expires while the proxy is running is **never**
unloaded, whatever this section says: a listener that stops answering is
worse than one answering with a certificate the client will reject for
itself, and unloading it would turn a renewal that ran late into an
outage. It is reported and counted, and `docs/HA.md` covers why that
report matters more than the refusal on a pair of nodes.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `refuse_expired` | bool | `false` | An expired certificate is a load error rather than something to serve |
| `warn` | duration | `0` | Report certificates this close to expiry (0 for none, otherwise 1h to 8760h) |

```yaml
tls:
  certificates: [{cert_file: /etc/xproxy/tls/site.pem, key_file: /etc/xproxy/tls/site-key.pem}]
  expiry:
    refuse_expired: true
    warn: 336h          # fourteen days
```

#### server.listeners[].tls.ocsp_stapling

A stapled OCSP response spares clients the responder round trip and
keeps working when the responder is down or firewalled from them. The
proxy fetches a response for every served certificate (file and ACME
alike) from the responder named in the certificate, using the issuer
that follows the leaf in the chain file, and refreshes it at half its
validity, at `refresh` at the latest, and one minute after a failure.
A handshake never waits: it carries the current response when there is
one and none otherwise, and a still valid response is kept through
fetch failures. A `revoked` answer is stapled as well, since clients
must see it, and logged as an error. `xproxyctl tls` and `GET /v1/tls`
show the state per certificate.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Switch for the section |
| `timeout` | duration | `5s` | One responder request (1s to 1m) |
| `refresh` | duration | `1h` | Longest interval between fetches (5m to 24h) |

#### server.listeners[].tls.ct

Browsers refuse certificates that were not logged in Certificate
Transparency logs; a certificate issued without the signed certificate
timestamps (SCTs) then breaks a site quietly at the next reload. The
proxy parses the SCTs embedded in every file certificate at load and,
with a log list, verifies each signature over the precertificate entry
(the certificate without its SCT extension and the issuer's key hash)
against the log's key. The verdict appears in `xproxyctl tls`; a
shortfall is a security log event, or a failed load with `enforce`.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `require` | int | `0` (report only) | Embedded SCTs a certificate must carry, verified ones when `log_list_file` is set (0 to 10) |
| `log_list_file` | path | none | A log list in the JSON format Google publishes (`log_list.json`, v3 with `operators[].logs[]` and `tiled_logs[]`); the logs' keys verify the SCT signatures |
| `enforce` | bool | `false` | Fail the load or reload of a certificate below `require` instead of logging it |

SCTs delivered through the TLS extension or the OCSP response rather
than embedded are not counted. ACME certificates are reported but not
checked at load (the ACME client already requires embedded SCTs from a
public CA).

### server.limits

| Key | Type | Default | Range | Description |
|-----|------|---------|-------|-------------|
| `max_header_bytes` | int | `65536` | 1024 to 1 MiB | Request header block, including HTTP/2 header list |
| `max_body_bytes` | int | `10485760` | 0 or more | Request body; `0` disables the global cap (routes can still set one) |
| `max_uri_length` | int | `8192` | 256 to 65536 | Request line target length; 414 above |
| `read_header_timeout` | duration | `10s` | positive | Slowloris defence |
| `read_timeout` | duration | `60s` | positive | Whole request including body |
| `write_timeout` | duration | `60s` | positive | Whole response |
| `idle_timeout` | duration | `120s` | positive | Keep-alive idle |
| `max_connections` | int | `65536` | positive | Open connections across all listeners |
| `max_connections_per_ip` | int | `256` | positive, at most `max_connections` | Per source address |
| `max_concurrent_requests` | int | `16384` | positive | In-flight requests; 503 above |
| `max_tarpits` | int | `1024` | 1 to 1000000 | Requests held in a tarpit at once. A tarpitted request releases its concurrency slot; above this bound it is rejected with 429 immediately (`tarpit_overflow` counts those) |
| `max_buffered_body_bytes` | bytes | `536870912` | 0 (unbounded) or 1 MiB to 64 GiB | Ceiling on request bodies held in memory at once across the process; a request on a route that inspects bodies and does not fit is refused with `503` and reason `body_budget` |
| `connection_rate` | object | none | | `{per_second, burst}`: accepts per second across every listener. See below |
| `connection_rate_per_source` | object | none | | `{per_second, burst, ipv4_prefix, ipv6_prefix, max_sources}`: accepts per second from one source network |

#### Connection rate: the bound `max_connections` does not give

`max_connections` and `max_connections_per_ip` say how many connections
may be **open at once**. They say nothing about churn, and churn is what
most attacks on a service look like: a client that connects, makes the
server do the expensive half of a handshake and disconnects never holds
two connections and can still spend a core. It is also what an
accidental flood looks like — a restarting client fleet reconnecting in
lock-step.

That matters most exactly where the handshake is dearest and happens
**before** the proxy knows who is calling: an SSH key exchange, a TLS
handshake, an RDP connection sequence. Those listeners should have a
rate.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `connection_rate.per_second` | float | required | Sustained accepts per second |
| `connection_rate.burst` | int | `per_second` rounded up | How many may arrive at once |
| `connection_rate_per_source.per_second` | float | required | Sustained accepts per second from one source network |
| `connection_rate_per_source.burst` | int | `per_second` rounded up | |
| `connection_rate_per_source.ipv4_prefix` | int | `32` | The network the rate is counted over; 8 to 32 |
| `connection_rate_per_source.ipv6_prefix` | int | `64` | 16 to 128, and a warning above /96 |
| `connection_rate_per_source.max_sources` | int | `65536` | Networks tracked at once; 1 to 4194304 |

Two bounds, because they answer different attackers. The **total** rate
protects the accept path itself whatever the traffic is spread across.
The **per source** rate protects everyone else from one source, and it
is keyed by a **network rather than an address** on purpose: an attacker
with a /64 of IPv6 has more addresses than any table could hold, so a
per address bound would be no bound at all while the per address table
would itself be the thing that filled up. The default /64 is the
smallest block an operator is normally given; above /96 validation warns,
because counting single addresses costs memory and stops nothing.

A refused connection is **closed immediately after accept, before a byte
is read**, which is all a listener can do about a connection the kernel
has already handed it, and it is cheap. Refusals are counted in
`rate_refused_connections` and `xproxy_connections_rate_refused_total`,
and reported in the error log through the same aggregation as the other
accept refusals — a client looping connections must not make each
refusal cost a synchronous log write.

A listener's own `connection_rate` sections **replace** these for that
listener rather than adding to them, so one number is the answer to
"what bounds this port". A rate change on reload rebinds no socket.

`max_buffered_body_bytes` covers every feature that materialises a
whole request body: `upload_guard`, `sensitive_data`, `account_guard`,
`openapi`, `graphql`, `body_rewrite`, `wasm`, the WAF's body
inspection, ICAP, a virtual patch's body pattern and a mirrored
request. Each of those is bounded per request, and the product was the
real ceiling: `max_connections_per_ip` (256) times `max_body_bytes`
(10 MiB) is about 2.5 GiB of heap from one address, sent slowly enough
to stay inside `read_timeout`. A request whose body cannot be charged
is refused before it is read; `xproxyctl stats` shows what is held, the
high-water mark and the refusals.

### server.normalization

What the proxy does with encoding tricks in the request target before
routing, rate limits, filters and the WAF look at it. Routing already
decodes the path once and resolves dot segments and duplicate slashes;
these checks refuse the forms that make two components read a request
differently, and optionally fold Unicode spellings for routing. A
refusal answers 400 with reason `normalization` and the check as
`detail`, counts in `denied_normalization` and feeds ban triggers under
`normalization`. The WAF still inspects the raw request line, so its
rules see what the client sent.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `reject_control_chars` | bool | `true` | A decoded path or query with a control character (below 0x20, or 0x7f), NUL included (`path_control_char`, `query_control_char`) |
| `reject_invalid_utf8` | bool | `true` | A decoded path that is not valid UTF-8: overlong (`%c0%af`) and truncated sequences (`path_invalid_utf8`) |
| `reject_double_encoding` | bool | `false` | A path that still holds a percent escape after one decoding (`%252e%252e`), the classic way past a filter that decodes once (`path_double_encoding`) |
| `reject_encoded_slashes` | bool | `false` | `%2F` or `%5C` in the raw path: the routing decoder turns them into separators that the upstream may treat as data (`path_encoded_slash`) |
| `reject_backslashes` | bool | `true` | A backslash anywhere in the decoded path (`path_backslash`). IIS, Apache on Windows and .NET read it as a separator while this proxy reads it as an ordinary character, so `/static\..\admin` is one opaque segment under `/static` here and `/admin` there, skipping that route's access lists, filters, WAF profile and rate limits |
| `reject_path_params` | bool | `true` | A `;` anywhere in the decoded path (`path_parameter`). Tomcat, Jetty, JBoss and Spring strip a path parameter from every segment before mapping, so `/admin;x` or `/admin;jsessionid=…` misses this proxy's `/admin` route and its policy while the origin serves `/admin`. Turn it off for an API that genuinely uses matrix parameters |
| `reject_dot_segments` | bool | `true` | A `.` or `..` segment in the decoded path, including the `..;` form servlet containers resolve (`path_dot_segment`). Routing resolves dot segments while the upstream receives the path as sent, so `/static/../admin` would be routed as `/admin` but reach the origin unchanged; browsers never send such paths |
| `reject_ambiguous_framing` | bool | `true` | HTTP/1 requests with several differing `Content-Length` values, a `Content-Length` next to a transfer coding, or a coding other than chunked (`framing_content_length`, `framing_te_cl`, `framing_transfer_encoding`). The Go parser already refuses most of these before the proxy sees them; the check closes the rest and makes them visible |
| `unicode` | `off`, `nfc`, `nfkc` | `off` | Fold the decoded path to that form for routing: `nfc` makes composed and decomposed spellings (`café` either way) match one route, `nfkc` also compatibility forms such as fullwidth letters (`ｕsers`). The upstream receives the original path |

Turn the strict checks on for applications that never use encoded
separators or double encoding legitimately (most APIs), and leave them
off in front of applications that carry encoded identifiers in the
path; `examples/security/positive-model.yaml` shows the strict set.

### server.error_pages and routes[].error_pages

Documents are read at load (at most 1 MiB each) and chosen by exact
status (`"404"`), class (`"4xx"`, `"5xx"`) or `"default"`. A route section
replaces the server section entirely for that route. Every status the
proxy writes itself goes through the pages: denials (ACL, rate limit,
WAF, ban, JWT), unknown host or route, upstream failures (502, 503,
504), static file misses and the like; a gRPC request keeps its gRPC
status. Upstream responses pass through unchanged unless their status is
listed in `intercept_upstream`.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `dir` | absolute path | none | Directory of the documents; required for relative page names |
| `pages` | map | required | Status, class or `default` to a file name in `dir` or an absolute path; documents may use the variables below and keep unknown `${...}` sequences as they are (script code is safe) |
| `content_type` | string | `text/html; charset=utf-8` | Content type of the documents |
| `json` | bool | `true` | Answer clients whose `Accept` prefers `application/json` over `text/html` with `{"status":404,"error":"Not Found","request_id":"..."}` instead of the document |
| `intercept_upstream` | list of int | `[]` | Upstream statuses (400 to 599) whose bodies are replaced by the matching page; headers describing the old body (`Content-Length`, `Content-Encoding`, `ETag`) are replaced |

### Variables

Header values, `rewrite_regex.replace`, `redirect.to` and error pages
may use `${name}`; a misspelt name fails validation for headers,
rewrites and redirects and is kept literally in pages.

| Variable | Value |
|----------|-------|
| `client_ip` | client address after trusted proxy handling |
| `request_id` | request identifier |
| `host` | request host without port |
| `path`, `raw_query`, `method`, `scheme` | request line parts (`scheme` is `http` or `https` as seen by the client) |
| `route`, `upstream`, `tenant` | the matched route, its pool and tenant label |
| `country`, `ja4` | GeoIP country code and TLS client fingerprint, empty when unknown |
| `tls_version`, `tls_cipher` | TLS parameters of the client connection |
| `header:Name`, `cookie:name`, `query:name` | a request header, cookie or query parameter |
| `cert:field` | the client certificate of a listener with `client_auth` (empty without one): `cn`, `subject` and `issuer` (RFC 2253), `serial` (hex), `fingerprint` (SHA-256 of the DER, hex), `sans` (DNS names, addresses, emails and URIs, comma separated), `not_after` (RFC 3339), `client_cert` (RFC 9440's Structured Fields Byte Sequence: standard base64 of the DER between colons), `xfcc` (an Envoy style `X-Forwarded-Client-Cert` value with `Hash`, `Subject`, `URI` and `DNS`) and `pem` (URL encoded PEM). Set the header with `request_headers.set`, which also discards a client supplied copy |
| `1` to `9`, `name` | groups of `rewrite_regex.pattern` or, without one, of the matching `path_regex` (numbered and named) |
| `status`, `status_text`, `reason` | error pages only: the status, its phrase and the denial category (`acl`, `rate_limit`, `waf`, `banned`, `upstream`...) |
| `time` | current time, RFC 3339, UTC |
| `date`, `hour`, `minute`, `weekday` | current date (`2026-09-19`), hour (`0` to `23`), minute and weekday (`Mon` to `Sun`), UTC |

### Client certificate identity headers

A backend behind a TLS-terminating proxy cannot see the handshake, so the
proxy tells it. RFC 9440 standardises `Client-Cert` and
`Client-Cert-Chain` for that; Envoy has used `X-Forwarded-Client-Cert`
for years; and nginx and Apache deployments read a handful of
`X-SSL-Client-*` names their own configurations set. Every one of them is
a statement about something only the terminating proxy can know.

Which makes every one of them an authentication bypass when a client can
send it. The backend has no way to tell the proxy's header from the
client's — they are the same bytes in the same field — so a request
carrying its own `Client-Cert` is a request that chooses its own
identity. RFC 9440 section 3 says so in as many words: the terminating
proxy must sanitise the header.

So **all of them are removed from every forwarded request**, unless the
immediate peer is inside `trusted_proxies` — the one case where the header
belongs to a proxy that did terminate a handshake. The list is
`Client-Cert`, `Client-Cert-Chain`, `X-Forwarded-Client-Cert`,
`X-Client-Cert`, `X-Client-Cert-Chain`, `X-Client-Verify`,
`X-Client-Subject-DN`, `X-Client-Issuer-DN`, `X-SSL-Client-Cert`,
`X-SSL-Client-Verify`, `X-SSL-Client-S-DN`, `X-SSL-Client-I-DN`,
`X-SSL-Client-Serial`, `X-SSL-Client-Fingerprint`, `SSL-Client-Cert`,
`SSL-Client-Verify` and `SSL-Client-Subject-DN`. A backend that reads one
of these therefore reads what this proxy said or nothing at all.

`routes[].client_cert_headers` then writes the truth over the blank:
`rfc9440` sets `Client-Cert` to the leaf and `Client-Cert-Chain` to the
rest of the chain in order, each as a Structured Fields Byte Sequence
(RFC 8941: standard base64 with padding, between colons, which a
structured-fields parser accepts and anything else it rejects); `xfcc`
sets Envoy's header. A route that wants a different shape sets its own
header from `${cert:...}`, which strips a client copy of that name too.

### Expressions

`routes[].when`, `request_headers.when` and `response_headers.when`
hold a condition that is parsed at load (unknown names, functions,
arities, patterns and capture groups are errors) and evaluated per
request. Values are strings; a variable without a value is the empty
string. `==` and `!=` compare as strings; `<`, `<=`, `>` and `>=`
compare numerically when both sides are numbers and by string otherwise.
A bare string is true when it is neither empty, `0` nor `false`.

| Element | Meaning |
|---------|---------|
| `a && b`, `a and b`, `a \|\| b`, `a or b`, `!a`, `not a`, `(a)` | Boolean operators, lowest precedence first: or, and, not |
| `"text"`, `'text'`, `42`, `true`, `false` | Literals; strings take `\"`, `\'`, `\\`, `\n` and `\t` escapes |
| `client_ip`, `host`, `path`, `raw_query`, `method`, `scheme`, `country`, `ja4`, `tls_version`, `tls_cipher`, `request_id`, `route`, `upstream`, `tenant`, `time`, `date`, `hour`, `minute`, `weekday` | The variables of the table above, as bare names (`route`, `upstream` and `tenant` are empty in `routes[].when`, which runs before the route is chosen) |
| `header("Name")`, `cookie("name")`, `query("name")`, `capture("name")` | A request header (case insensitive, first value), cookie, query parameter or regular expression group by name or number; empty when absent |
| `has_header("Name")`, `has_cookie("name")`, `has_query("name")` | Presence, also of an empty value |
| `cert("field")` | A client certificate field as in the variable table (`cert("cn") == "billing-batch"`, `cert("fingerprint") in [...]`); empty without a client certificate |
| `x in ["a", "b"]`, `x not in [...]` | Membership in a list of literals |
| `client_ip in cidr("10.0.0.0/8", "2001:db8::/32", "203.0.113.7")` | Address containment in prefixes or single addresses; a value that is not an address is never contained |
| `x matches "pattern"`, `matches(x, "pattern")` | RE2 match anywhere in the value; anchor with `^` and `$` for the whole value. Patterns are literals, compiled at load |
| `starts_with(x, "p")`, `ends_with(x, "s")`, `contains(x, "part")` | Substring tests |
| `lower(x)`, `upper(x)`, `trim(x)`, `len(x)` | Case folding, whitespace trimming and byte length |

Examples: `method in ["GET", "HEAD"] and hour >= 22 or hour < 6`
(read-only traffic in the night window), `country in ["SE", "NO", "DK"]
&& not has_cookie("consent")`, `path matches "^/api/v[0-9]+/" &&
header("Content-Length") > 1048576`, `capture("id") != "" && ja4 == ""`.

## management

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `socket` | path | `""` (disabled) | Unix socket for `xproxyctl` |
| `socket_mode` | octal string | `"0660"` | Any `other` permission is rejected |
| `history_dir` | path | none (history off) | Directory (created `0700`) where every applied configuration is recorded as a self-contained YAML file (`0600`) for `xproxyctl history`, `diff` and `rollback`; `/var/lib/xproxy/history` on Fedora |
| `history_keep` | int | `20` | Entries kept; older ones are removed (1 to 1000) |

## logging

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `directory` | path | `/var/log/xproxy` | Must exist and be writable |
| `level` | `debug`, `info`, `warn`, `error` | `info` | Minimum level for the error stream |
| `stdout` | bool | `false` | Mirror all streams to stdout (journald, containers) |
| `access`, `error`, `security`, `audit` | stream | | Per stream settings |
| `journald` | object | none | journald sink, used by streams listing `journald` |
| `syslog` | object | none | syslog sink, used by streams listing `syslog` |
| `redaction` | object | none | Personal data rules applied before every sink |
| `otlp` | object | none | OpenTelemetry log sink, used by streams listing `otlp`; see `logging.otlp` |
| `siem` | object | none | HTTPS batch sink for a SIEM (NDJSON, Splunk HEC, CEF or LEEF), used by streams listing `siem`; see `logging.siem` |

### logging.<stream>

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | |
| `file` | file name | `access.log` etc. | Bare name inside `directory` |
| `max_size_mb` | int | `0` (no internal rotation) | Rotate to `.1`, `.2`, ... when exceeded |
| `max_files` | int | `5` | Archives kept |
| `sinks` | list | `[file]` | Any of `file`, `journald`, `syslog`, `otlp`, `siem`; a stream can go to several |
| `format` | `json`, `common`, `combined`, `custom` | `json` | Access stream only for the text formats: `common` is the Common Log Format (`%h %l %u %t "%r" %>s %b`), `combined` adds the quoted referer and user agent, `custom` uses `template`. The error, security and audit streams stay JSON. Text lines go to every sink of the stream; redaction runs before formatting |
| `sample_percent` | float | `100` | Access stream only: log this percentage of lines. Every request is still counted in the metrics; only the written line is sampled |
| `always_log` | bool | `true` | Access stream only: log a line whatever the sampling when the response is 4xx/5xx or the request was denied |
| `fields` | list | all | Access stream only: keep only these attributes on the line (`request_id`, `client_ip`, `status`, `route`, ...); empty keeps them all |
| `template` | string | | For `format: custom`: literal text with `{field}` placeholders. Fields are the access log attributes (`request_id`, `client_ip`, `method`, `host`, `path`, `query_len`, `proto`, `status`, `bytes_in`, `bytes_out`, `duration_ms`, `route`, `upstream`, `endpoint`, `attempts`, `user_agent`, `referer`, `tls`, `sni`, `client_cn`, `country`, `ja4`, `cache`, `encoding`, `honeypot_marked`, `mirror`, `grpc`, `grpc_status`, `denied`, `upstream_error`, filter attributes such as `jwt_sub`, `oidc_sub`, `bot_score`) plus `time_clf` (`10/Oct/2000:13:55:36 -0700`), `time_iso`, `time_unix`, `request` (`METHOD path PROTO`), `user` (the first of `oidc_sub`, `basic_user`, `jwt_sub`, `jwt_preferred_username`, else `-`) and `bytes_out_clf` (`-` for zero). A missing or empty field prints `-`. Values are escaped Apache style (`\"`, `\\`, `\n`, `\xHH`), so one request is always one line; at most 1024 bytes |

### logging.journald

Native journald protocol over the journal's datagram socket, no cgo. The
JSON line is `MESSAGE`; the level maps to `PRIORITY`; the stream and every
top-level attribute become `XPROXY_*` fields, so
`journalctl XPROXY_CLIENT_IP=203.0.113.9` works without parsing.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `socket` | path | `/run/systemd/journal/socket` | |
| `identifier` | name | `xproxy` | `SYSLOG_IDENTIFIER` |

### logging.syslog

Messages are queued and sent by a background writer; the request path
never waits for a collector. A full queue drops and counts. Stream
transports use RFC 6587 octet counting and reconnect with back-off.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `network` | `unix`, `udp`, `tcp`, `tcp+tls` | `unix` | |
| `address` | path or host:port | `/dev/log` for unix | |
| `format` | `rfc5424`, `rfc3164`, `cef`, `leef` | `rfc3164` for unix, else `rfc5424` | With the RFC formats the JSON line is the message and the stream the RFC 5424 MSGID. `cef` and `leef` render the record in that format (see `logging.siem`) behind an RFC 5424 header, or an RFC 3164 header on `unix`, for collectors that parse CEF or LEEF from syslog |
| `facility` | name | `local0` | `kern`, `user`, `mail`, `daemon`, `auth`, `syslog`, `lpr`, `news`, `uucp`, `cron`, `authpriv`, `ftp`, `local0` to `local7` |
| `app_name` | name | `xproxy` | APP-NAME or tag |
| `hostname` | string | OS host name | |
| `ca_file`, `cert_file`, `key_file`, `server_name` | | | `tcp+tls`: pinned CA, optional client certificate, verified name |
| `queue_size` | int | `8192` | Messages held for a slow collector; 64 to 1000000 |

Datagram transports truncate messages at 8 KiB.

### logging.otlp

Ships log records to an OpenTelemetry collector as OTLP/HTTP with JSON
encoding. Each record carries the time, the severity (`DEBUG` 5,
`INFO` 9, `WARN` 13, `ERROR` 17), the message as the body, every
attribute of the line (integers, booleans and floats typed, the rest as
strings), `xproxy.stream`, and the trace and span ids of access lines
when tracing is on, so a collector links logs to traces. Records queue
without blocking the request path; a full queue drops and counts; a
batching goroutine pushes by size and interval and flushes at shutdown.
Redaction runs before the sink like for every other sink. `xproxyctl
telemetry` and `GET /v1/telemetry` show the counters.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `endpoint` | URL | required | The collector's logs URL (`https://otel.example.com:4318/v1/logs`); `http://` only with `allow_http` |
| `allow_http` | bool | `false` | |
| `timeout` | duration | `10s` | One push; at most 1m |
| `headers` | map | `{}` | Request headers, for example `Authorization` |
| `ca_file` | path | system pool | Pins the collector's CA |
| `service_name` | string | `xproxy` | `service.name` resource attribute; `service.version` and `host.name` are added |
| `attributes` | map | `{}` | Extra resource attributes |
| `compress` | bool | `true` | gzip the request body |
| `batch` | int | `512` | Records per push (1 to 10000) |
| `interval` | duration | `5s` | Longest wait before a push (100ms to 5m) |
| `queue` | int | `8192` | Records held while a push is in flight; more are dropped and counted (1 to 1000000) |

### logging.siem

Ships log records to a security information and event management
system over HTTPS: Splunk's HTTP Event Collector, Elastic and
OpenSearch ingest endpoints, Microsoft Sentinel's data collector, or any
receiver of newline delimited JSON, CEF or LEEF. Records queue without
blocking the request path, a full queue drops and counts, and a
batching goroutine posts by size and interval and flushes at shutdown,
the same way the `otlp` sink works. Redaction runs before the sink.
`xproxyctl telemetry` and `GET /v1/telemetry` show the counters,
`xproxyctl status` `log_siem_sent` and `log_siem_dropped`, and the
metrics `xproxy_log_sent_total{sink="siem"}` and
`xproxy_log_dropped_total{sink="siem"}`.

Formats:

- `json`: one JSON line per record, `application/x-ndjson`, the line
  every other sink sees (with `stream`).
- `hec`: the Splunk HTTP Event Collector envelope per record (`time`,
  `host`, `source: xproxy`, `sourcetype: xproxy:<stream>`, `event`
  holding the JSON object), `application/json`; put `Splunk <token>` in
  `auth_file`.
- `cef`: ArcSight Common Event Format, a header of the vendor, product,
  version, event id (`stream` or `stream:action`), name and severity
  followed by the extension. Severity is 1, 3 or 5 for access lines by status class, 7 for
  security events (8 for bans), 3 for audit and 2, 4 or 6 for the error
  stream by level. Extensions use the standard keys where one exists
  (`rt`, `dvchost`, `cat`, `outcome`, `suser` from the identified user,
  `src`, `dst` and `dpt` from the upstream endpoint, `requestMethod`,
  `dhost`, `request`, `requestClientApplication`, `requestContext`,
  `app`, `in`, `out`, `act`, `reason`, `msg`), the labelled custom
  fields for `status` (`cn1`), `duration_ms` (`cn2`), `attempts`
  (`cn3`), `request_id` (`cs1`), `route` (`cs2`), `upstream` (`cs3`),
  `country` (`cs4`), `ja4` (`cs5`) and `detail` (`cs6`), and every other
  attribute under its own name. Header fields escape `|` and `\`,
  extension values `=`, `\` and line breaks.
- `leef`: IBM QRadar Log Event Extended Format 2.0 with a tab
  delimiter (`x09` in the header) and the same header fields except
  name and severity, followed by `devTime`, `devTimeFormat`, `sev`, `cat`, `identHostName`,
  `usrName`, `dst`, `dstPort`, `name` for non access events, then
  `src`, `url`, `proto`, `userAgent`, `reason`, `action`, `msg` and the
  remaining attributes under their own names.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `endpoint` | URL | required | The collector URL: the Splunk HEC `services/collector/event` path, an Elastic or OpenSearch ingest endpoint, a Logstash, Vector or Fluent Bit http input; `http://` only with `allow_http` |
| `allow_http` | bool | `false` | |
| `format` | `json`, `hec`, `cef`, `leef` | `json` | |
| `headers` | map | `{}` | Request headers |
| `auth_file` | path | none | File whose trimmed content is the `Authorization` header value (`Splunk <token>`, `Bearer <token>`, `ApiKey <key>`), so the secret stays out of the configuration |
| `timeout` | duration | `10s` | One push; at most 1m |
| `ca_file` | path | system pool | Pins the collector's CA |
| `cert_file`, `key_file` | paths | none | Client certificate, both or neither |
| `compress` | bool | `true` | gzip the request body |
| `batch` | int | `512` | Records per push (1 to 10000) |
| `interval` | duration | `5s` | Longest wait before a push (100ms to 5m) |
| `queue` | int | `8192` | Records held while a push is in flight; more are dropped and counted (1 to 1000000) |
| `vendor`, `product` | strings | `Sysctl`, `Xproxy` | CEF and LEEF header fields, 1 to 63 characters without `|` |
| `hostname` | string | OS host name | `dvchost`, `identHostName` and the HEC `host` |

### logging.redaction

Presence enables the rules; `enabled: false` switches them off while
keeping the configuration. Rules run before every log sink, so files,
journald, syslog and the SIEM export all receive the same redacted
record. They do **not** cover OpenTelemetry traces: a span carries the
client address, the host and the path as the request had them, and the
access log records the trace and span ids, so anyone holding both the
logs and the trace store can join a pseudonym back to the address it
stands for. Treat the trace collector as holding unredacted data, or
leave `tracing.otlp` unset where that matters.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | |
| `streams` | list | `[access, security, error]` | The audit stream keeps full detail unless listed |
| `client_ip` | `keep`, `truncate`, `hash` | `truncate` | `truncate` masks to /24 (IPv4) or /48 (IPv6); `hash` writes a keyed pseudonym (`h:` + 16 hex) that is stable per key and lets you correlate one client across lines without storing the address |
| `hash_secret_file` | path | ephemeral | Key (or the primary key of a keyring) for `hash`; set it so pseudonyms survive restarts and match across nodes. Rotating it starts a new series of pseudonyms at the next restart |
| `user_agent` | `keep`, `drop` | `keep` | |
| `referer` | `keep`, `origin`, `drop` | `origin` | `origin` keeps scheme and host only |
| `claims` | `keep`, `hash`, `drop` | `hash` | Applies to `jwt_*` (except `jwt_provider`) and `client_cn` |
| `drop_fields` | list | `[]` | Further attribute names removed from lines; `time`, `level`, `msg` and `stream` cannot be dropped |

## rate_limits[]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | name | required, unique | Referenced by routes |
| `key` | see below | `client_ip` | Bucket identity |
| `net_v4`, `net_v6` | int | `24`, `48` | Prefix lengths for `key: client_net` |
| `algorithm` | `token_bucket`, `sliding_window` | `token_bucket` | `token_bucket` admits bursts up to `burst` and refills at `rate`; `sliding_window` admits at most `limit` requests in any window of length `window`, estimated from the current and the previous fixed window weighted by their overlap (no burst above `limit` at a window edge, an error bounded by the unevenness of arrivals inside one window) |
| `rate` | float | required for `token_bucket`, positive | Tokens per second |
| `burst` | int | `rate` rounded, at least 1 | Bucket capacity |
| `limit` | int | required for `sliding_window` | Requests per `window`, 1 to 1000000000 |
| `window` | duration | `1s` | Sliding window length, 100ms to 24h |
| `distributed` | `approximate`, `exact` | `approximate` | Cluster semantics. `approximate`: every node decides locally and refills at the rate minus its peers' gossiped consumption (one interval of delay). `exact`: one member owns each key (rendezvous hash of member and key over the connected members), the others ask it over the cluster connection and wait at most `cluster.exact_timeout`; the owner's bucket or window is the single count. A node that cannot reach the owner in time decides on its own limiter and counts an `exact_fallback`. Needs the `cluster` section |
| `action` | `reject`, `tarpit` | `reject` | `reject` answers 429 at once |
| `tarpit_delay` | duration | `10s` | Hold before answering 429 (released on client disconnect) |

Keys:

| Key | Bucket per | Without the identifier |
|-----|------------|------------------------|
| `client_ip` | client address | |
| `client_net` | client network: the address truncated to `net_v4` or `net_v6` bits, so a distributed client rotating addresses inside one allocation shares a bucket | |
| `route` | route | |
| `endpoint` | method, route and path template (identifiers such as numbers, UUIDs, hashes and opaque tokens replaced by `*`, so `/users/42` and `/users/43` are one endpoint) | |
| `country` | client country (needs `geoip`) | client address |
| `ja4` | TLS client fingerprint | client address (plaintext listeners) |
| `device` | device identifier from the challenge cookie (`challenge.device`), so a client rotating addresses keeps one bucket once it has passed a challenge | client address (no cookie yet) |
| `header:<Name>` | first value of the header (256 bytes) | client address |
| `cookie:<name>` | value of the cookie (256 bytes), a session or device identifier | client address |
| `jwt:<claim>` | a string, number or boolean claim of the bearer token in `Authorization`, read without verification (the value only names a bucket; the `jwt` route setting still rejects a forged token) | client address |
| `identity` | the identity a preceding auth filter verified this request against, preferring `oidc`, `jwt`, `api_key` then `basic`; unlike `jwt:<claim>` it cannot be spoofed, because the filter proved it. Evaluated after the filter chain, so the limiter sees the authenticated principal | client address (unauthenticated) |
| `identity:<kind>` | the verified identity of one kind: `jwt` (the `sub` claim), `oidc` (the session subject), `saml` (the session name identifier), `api_key` (the key id), `basic` (the user) or `ldap` (the user) | client address |

The fallback keeps a limit from being avoided by omitting the
identifier; rotating it still buys fresh buckets, so pair an identifier
key with a `client_ip` or `client_net` policy on the same route. An
`identity` key cannot be rotated within one authenticated principal:
the value is what the `jwt`, `oidc`, `api_key` or `basic` filter
verified, so a per-account or per-API-key limit holds regardless of the
headers a client sends. Attach such a policy to a route that also runs
the matching auth filter (or the `jwt` route setting); a request that
fails authentication is refused by the filter before the limiter.

Memory: at most 64 x 8192 buckets per policy.

## upstreams[]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | name | required, unique | |
| `balancer` | `round_robin`, `weighted`, `least_conn`, `hash`, `p2c`, `ewma` | `round_robin` | See below for the last two |
| `hash_on` | `client_ip`, `header:<Name>`, `cookie:<Name>` | `client_ip` | For `hash`; missing input falls back to the client address |
| `endpoints` | list | required, at least one | `{address: host:port, weight: 1..1000, canary: bool, drain: bool, max_connections: int, priority: 0..99, zone: name}`; `canary` marks the endpoints the `canary` policy selects, `drain` takes one out of rotation, `max_connections` bounds what is in flight to it, and `priority` and `zone` tier it — see below. An address may instead be `unix:/path/to/socket` |
| `locality` | object | none | `{prefer_zone: bool, min_local: int}`: prefer the endpoints of this node's own `server.zone` |
| `address_family` | `any`, `ipv4`, `ipv6` | `any` | Which of a dual-stack endpoint's addresses may be dialled. `any` races the two families as RFC 8305 describes |
| `fallback_delay` | duration | `300ms` | How long the second family is held back in that race; at most 10s, and a negative value tries the families in order instead |
| `max_connections_per_endpoint` | int | `0` (none) | Default for every endpoint's own `max_connections` |
| `max_connection_age` | duration | `0` (none) | How long one upstream connection is kept; at least 1s, at most 24h. See below |
| `maintenance` | bool | `false` | Take the whole pool out of rotation: it offers no endpoint, so a route over it answers as it does when everything is unhealthy |
| `canary` | object | none | Route selected requests to the canary endpoints; see below |
| `scheme` | `http`, `https` | `http` | |
| `h2c` | bool | `false` | Speak HTTP/2 without TLS to `http` endpoints (gRPC backends); `https` negotiates HTTP/2 with ALPN on its own |
| `h3` | bool | `false` | Speak HTTP/3 (QUIC over UDP) to `https` endpoints; health probes use it too. Exclusive with `h2c`. `xproxyctl upstreams` shows the pool protocol |
| `h3_fallback` | bool | `true` | With `h3`, retry a request whose QUIC connection fails before a response (UDP blocked, handshake timeout) over TCP on the same endpoint; counted as `h3_fallbacks` in the pool status. Off, such failures are errors like any other |
| `tls` | object | | Only with `https`; see below |
| `health_check` | object | none | Active probing; see below |
| `outlier_ejection` | object | none | Passive ejection; see below |
| `circuit_breaker` | object | none | Pool wide breaker with half open probing; see below |
| `max_concurrent` | int | `0` (unbounded) | Requests in flight to the pool; the excess waits in `queue` or is refused with 503 |
| `queue` | `{size, timeout}` | none | With `max_concurrent`: requests waiting for a slot (`size` 1 to 1000000, default 100) and how long each waits (`timeout` 10ms to 5m, default 1s) before 503 with `Retry-After: 1`; a full queue refuses at once |
| `affinity` | object | none | Cookie stickiness; see below |
| `timeouts.connect` | duration | `5s` | Dial and TLS handshake |
| `timeouts.response_header` | duration | `30s` | Time to first response byte |
| `timeouts.idle` | duration | `90s` | Pooled connection idle |
| `timeouts.total` | duration | `5m` | Whole exchange |
| `max_idle_conns_per_host` | int | `64` | Pooled connections per endpoint |
| `retries` | int | `1` | 0 to 5; only replayable requests (GET, HEAD, OPTIONS, TRACE without a body), each attempt on a different endpoint; connection errors always, statuses per `retry_on` |
| `rewrite_regex.pattern` | RE2 | none | Rewrite the outbound path by regular expression (see `rewrite_regex.replace`); applied to the cleaned path after `strip_prefix`, exclusive with `rewrite_path`; a path that does not match is sent unchanged |
| `rewrite_regex.replace` | template | | New path, starting with `/`; `${1}` to `${9}` and `${name}` are the pattern's groups, and the request variables (below) may be used |
| `error_pages` | object | inherits `server.error_pages` | Route override of the error pages, same keys as `server.error_pages` |
| `discovery` | object | none | Endpoints resolved from DNS or an HTTP registry (Consul, etcd gateways, custom) and re-resolved periodically; see below. Static `endpoints` and discovered ones coexist; a pool needs at least one of the two |
| `slow_start` | duration | `0` (off) | An endpoint that joins the pool (discovered) or returns to service (healthy again, ejection over) gets a share ramping from 10 % to its full weight over this time; at most 1h |
| `retry_on` | list | `[]` | Response statuses treated as a failed attempt: `5xx`, `500`, `502`, `503`, `504`, `429`. The response is discarded, the endpoint marked as failed for outlier ejection, and the next endpoint tried within the `retries` budget; the last attempt's response is returned as it is. Needs `retries` above 0 |
| `retry_budget` | object | none | Caps retries (and hedged copies) against live traffic so a struggling pool is not buried under a retry storm; see below. Without it, every retry `retries` allows is sent |
| `hedge` | object | none | Sends staggered copies of a slow idempotent request to other endpoints and keeps the first usable answer; see below |

#### Dual-stack endpoints: the race, and restricting it

An endpoint name with both an A and an AAAA record has two ways to be
reached, and the one that is broken costs a connect timeout on every
request that tries it first. With `address_family: any` (the default) the
families are **raced** as RFC 8305 describes: the first is tried, the
other follows after `fallback_delay` (300ms, the value the RFC
recommends), and whichever connects first wins. An estate that has just
turned IPv6 on does not have to know about any of this.

`ipv4` or `ipv6` dials that family **only**. It is for the estate where
one family is the only one that works, and naming it means a name that
also has the other kind of record cannot quietly use the family the
policy meant to exclude — which is the failure a preference would hide.

A negative `fallback_delay` turns the race off, so the families are tried
in order; naming one family makes the delay meaningless and warns.

#### Two balancers that read what the endpoints are doing

`least_conn` scans every endpoint and takes the best, which has a failure
mode of its own: every proxy in a fleet sees the same "best" endpoint at
the same moment and they all send to it together, so the herd moves from
one endpoint to the next.

**`p2c`** — power of two choices — takes two endpoints at random and uses
the better of those, by in-flight count per unit of weight. One
comparison is enough to avoid the worst endpoint, and the randomness
means two proxies rarely agree on where to send, so load spreads instead
of sloshing. It is the one to reach for when the endpoints are equal and
the load varies, and it is the one that fits a pool with no responses to
measure — a layer 4 relay's.

**`ewma`** weighs endpoints by the smoothed time to first byte the pool
already keeps for outlier detection, times the queue a request would
join: an estimate of how long a request sent now would take. An endpoint
answering slowly gets less work **long before** it is slow enough to fail
a health check or be ejected, which is the difference between shedding
load away from a struggling machine and waiting for it to break.

An endpoint with no latency sample yet costs nothing, so a new or
recovered one is tried rather than starved by the fact that nothing is
known about it; `slow_start` is what keeps that from being a flood. On a
quiet pool, where nothing distinguishes the endpoints, both balancers
spread uniformly rather than settling on the first.

#### Tiers: priority, backup and locality

`endpoints[].priority` tiers a pool. The endpoints of the **lowest
priority number that has an available member** carry the traffic and the
rest are ignored; when that tier has nothing left, the next one takes
over, and hands it back when the first returns. A retry that has used up
a tier falls to the next one too.

That is how a failover pool is written, and a **backup endpoint is simply
one in a later tier** — not a special kind of endpoint:

```yaml
upstreams:
  - name: app
    endpoints:
      - {address: "10.0.1.10:8080"}               # priority 0
      - {address: "10.0.1.11:8080"}
      - {address: "10.9.9.9:8080", priority: 1}   # only when both are gone
```

`locality` prefers the endpoints in this node's own `server.zone` over
the ones elsewhere, which keeps traffic off the links between sites and
away from their latency:

```yaml
server:
  zone: east
upstreams:
  - name: app
    locality: {prefer_zone: true, min_local: 2}
    endpoints:
      - {address: "10.0.1.10:8080", zone: east}
      - {address: "10.0.1.11:8080", zone: east}
      - {address: "10.1.1.10:8080", zone: west}
```

It is a **preference, not a pin**. An estate that pinned traffic to one
zone would lose the service when the zone lost it, which is the opposite
of what zones are for — so when the local endpoints are gone, the others
take the traffic. `min_local` is how many local endpoints must be
available before the remote ones are ignored: below it everything is
used, so a zone down to one surviving endpoint does not take the whole
load alone.

An endpoint with **no zone is local to every zone**: "somewhere unknown"
is not a reason to send traffic across a site. `prefer_zone` without
`server.zone` is refused at load — there would be nothing to compare
against — and a pool where no endpoint names a zone warns, because it
would prefer nothing.

Tiering is applied by leaving the other endpoints out of the choice
rather than by shortening the list the balancer sees, which matters for
`hash`: shortening it would move every key, while leaving endpoints out
moves only theirs.

#### Taking something out of rotation: drain and maintenance

Draining is **not** the same as unhealthy, and the difference is the
point. An unhealthy endpoint is one the proxy found broken; a drained one
is one a person decided to stop sending work to. So it is set from
outside — `xproxyctl drain POOL [ADDRESS]`, `POST /v1/drain`, the GUI —
and it **survives a reload**, because a reload builds new pools and an
operator who drained a machine to patch it did not mean "until the next
configuration change".

Nothing is closed. New work stops; the requests, sessions and
connections already there run to their own end. That is what makes it
usable for a rolling restart, and it is why draining is a separate idea
from the connection bounds, which do end things.

- **An endpoint**: `endpoints[].drain: true`, or
  `xproxyctl drain POOL ADDRESS`. It is passed over by every balancer
  and shows as `draining` in `xproxyctl upstreams`, still `healthy`, so
  the two stay distinguishable.
- **A pool**: `maintenance: true`, or `xproxyctl drain POOL`. The pool
  offers nothing at all.
- **Back in**: `xproxyctl drain -restore POOL [ADDRESS]`.

A decision made through the API **overrides the file** until the daemon
restarts, because the person who made it knew something the file did
not. `xproxyctl drain` with no argument lists what has been decided,
including an explicit restore of something the file drains.

A decision about a pool or an address that is not there is recorded
rather than refused, and the answer says so: an endpoint may be about to
arrive from discovery.

#### Bounding one endpoint, and the age of a connection

`endpoints[].max_connections` (or `max_connections_per_endpoint` for a
whole pool) bounds what is in flight to one endpoint. Past it the
endpoint is **passed over** rather than queued behind: the pool has
others, and holding work for one while they are idle is the opposite of
balancing. When every endpoint is at its bound the pool offers nothing,
which is what its own `queue` and `circuit_breaker` are there to answer.
It is for the endpoint that cannot take what the pool can give it — a
small instance beside large ones, a service with a database connection
pool of its own, a machine that answers slowly under load rather than
refusing.

`max_connection_age` bounds how long one upstream connection is kept, so
a pool's traffic follows its endpoints instead of sticking to whichever
ones were there when the connections were made: a keep-alive connection
can outlive a deploy, a scale-out and an endpoint's whole useful life,
and every request on it goes where that connection goes.

**It does not close anything mid-exchange.** Closing a connection at its
age would cut a request that has done nothing wrong, and from inside a
socket there is no way to tell an exchange in progress from an idle
connection — both are a blocked read. So the age marks the connection,
and the layer that does know where an exchange ends closes it once that
exchange is over. The connection is never reused past its age and
nothing in flight is disturbed; `xproxyctl upstreams` counts the
retirements.

That end only exists for **HTTP/1.1**, where a connection carries one
exchange at a time. An HTTP/2 or HTTP/3 connection carries many streams
and is never between exchanges, so the bound does not apply to one:
`h2c` and `h3` refuse it at load, and an `https` pool (which may
negotiate HTTP/2) warns.

#### A Unix domain socket as an endpoint

`address: unix:/run/app.sock` reaches a service that lives beside the
proxy rather than across a network: an application server on the same
host, a local scanner, a sidecar. A socket is the better way to reach
one — there is no port for anything else on the machine to connect to,
file permissions decide who may open it, and nothing about it is
routable.

The path must be absolute. Socket and `host:port` endpoints mix in one
pool, which is what a service moving from a port to a socket needs, and
everything else about a pool applies unchanged: the balancer, weights,
canaries, affinity, outlier ejection, and the `tcp` health check (which
connects to the socket, because a probe to a port would be proving
something about a path nothing uses).

Two things do not work with one, and are refused at load rather than
discovered later:

- **`scheme: https` without `tls.server_name`.** A URL has a host and a
  socket has a path, so the proxy gives a socket endpoint a synthetic
  authority for the URL — which is not a name a certificate can match.
  Naming the one the backend presents makes it verifiable again.
- **`h3`, and `discovery`.** HTTP/3 needs UDP to a host, and discovery
  produces `host:port` records; neither has anything to say about a path.

The synthetic authority ends in `.socket.invalid`, a name that must never
resolve, so a dialler that somehow ignored the socket fails immediately
instead of reaching a machine on the network. It is never sent to the
backend: the `Host` header is the client's own, as with any other
endpoint, so a service that routes on it keeps working.

### upstreams[].retry_budget

A retry (or a hedged copy) is only sent while the retries in flight to the
pool stay below `percent` of the requests in flight, with `min_concurrency`
always allowed so a low-traffic pool can still retry. As live traffic falls
the allowance falls with it, so retries cannot amplify an outage.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `percent` | float | `20` | 1 to 1000; retries in flight capped at this share of requests in flight |
| `min_concurrency` | int | `3` | 1 to 10000; concurrent retries always allowed regardless of `percent` |

### upstreams[].hedge

Hedging trades a little extra load for a shorter tail latency: if the request
in flight has not answered within `delay`, a copy goes to another endpoint,
and whichever returns a usable response first wins while the others are
cancelled. Only replayable requests (GET, HEAD, OPTIONS, TRACE without a
body) are hedged, each copy is keyed to a distinct endpoint, and every copy
beyond the first is gated by `retry_budget` when one is set.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `delay` | duration | required | 1ms to 1m; wait this long for the request in flight before sending the next copy |
| `max` | int | `1` | 1 to 4; extra copies beyond the first |

### upstreams[].tls

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `server_name` | string | endpoint host | SNI and verification name |
| `ca_file` | path | system pool | PEM bundle to verify against |
| `min_version` | `"1.2"`, `"1.3"` | `"1.2"` | Minimum TLS version towards the upstream |
| `key_exchange` | list of group names | `X25519MLKEM768`, `X25519`, `P-256`, `P-384` | As on a listener, for the connection to the origin: the same adversary records both halves of the path |
| `client_cert_file`, `client_key_file` | path | | Mutual TLS to the upstream; set both. Re-read by `xproxyctl reload-certs` and by configuration reload; idle connections are dropped so new ones present the new certificate |
| `origin_signature` | object | none | Sign every forwarded request so the origin can refuse traffic that bypassed the proxy; see `upstreams[].origin_signature` |
| `spki_pins` | list of base64 SHA-256 | `[]` | Pins of the upstream leaf public key; the connection is refused unless the presented leaf matches one, in addition to chain verification. `xproxyctl spki CERT.pem` prints a pin. Cannot be combined with `insecure_skip_verify` |
| `insecure_skip_verify` | bool | `false` | Requires `allow_insecure: true` as well |
| `allow_insecure` | bool | `false` | Second opt-in |

### upstreams[].discovery

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `type` | `dns`, `srv`, `http`, `consul` | `dns` | `dns` resolves the A and AAAA records of `name`, one endpoint per address on `port`; `srv` resolves SRV records, uses the lowest priority group, and takes target, port and weight from each record; `http` polls the registry URL in `name` on the interval (see `format`); `consul` asks a Consul agent about a service with **blocking queries** — see below |
| `name` | DNS name or URL | required | The name to resolve; for `srv` the full `_service._proto.domain` name; for `http` the registry URL to GET |
| `port` | int | required for `dns` | Endpoint port for `dns`, and the default port for `http` entries that omit one |
| `format` | `list`, `consul` | `list` | Response shape for `http`: `list` is a JSON array of `{address｜host,port, weight?, canary?}`; `consul` is the Consul `/v1/health/service` response (only instances whose checks all pass are used, `Weights.Passing` becomes the weight, a blank service address falls back to the node address) |
| `headers` | map | none | Extra request headers for `http`, for example an authentication token (Consul: `X-Consul-Token`) |
| `interval` | duration | `30s` | Time between resolutions; 1s to 1h. Endpoints that disappear are removed, new ones added with their statistics starting at zero, unchanged ones keep theirs |
| `resolver` | host:port | system resolver | DNS server to ask instead of the system resolver (`dns` and `srv` only) |
| `weight` | int | `1` | Weight of discovered endpoints that do not carry their own (`dns`, and `http` `list` entries without a `weight`) |
| `canary` | bool | `false` | Mark discovered endpoints as canaries (needs the pool's `canary` section) |
| `timeout` | duration | `5s` | Bound on one resolution, including the synchronous first one at start and reload; a failed resolution keeps the previous endpoint set and is counted in `xproxyctl upstreams` |
| `max_endpoints` | int | `4096` | How many endpoints one resolution may install; 1 to 65536. A larger answer is truncated to the first addresses in sorted order, warned about (throttled) and counted as `truncations` in `xproxyctl upstreams`. A registry is a remote input, and the answer decides how many health-check goroutines this process runs and how large the hash ring is; the sort makes the subset the same one on every resolution, so a truncated pool does not churn its endpoints every interval |
| `consul` | object | required for `consul` | See below |

#### upstreams[].discovery.consul

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `service` | name | required | The Consul service to ask about |
| `address` | host:port | `127.0.0.1:8500` | The agent. A Consul deployment runs one on every node, and asking the local one is both faster and what survives a partition |
| `tag` | string | none | Only the instances carrying that tag, which is how a Consul estate usually separates environments or versions |
| `datacenter` | name | the agent's own | Ask about another datacenter |
| `token_file` | path | none | File holding the ACL token, sent as `X-Consul-Token`. A token is a credential, so it lives in a file rather than in this document, which the management API dumps and the history keeps; the file must not be readable by more than its owner |
| `tls` | object | none | Reach the agent over HTTPS (CA, server name, pins — as `upstreams[].tls`). Without it the scheme is `http`, which over loopback to a local agent is the usual arrangement |
| `allow_stale` | bool | `false` | Let the agent answer from its own state without asking a server. Faster, and may be a moment behind, so it warns: a balancer acting on stale membership sends traffic to an instance that has gone |
| `wait` | duration | `5m` | How long one blocking query may be held open; 1s to 10m |

**Why a type of its own rather than `http` with `format: consul`.** The
polled form is still there and still works. What this adds is Consul's
**blocking query**: the agent holds the request open until the answer
changes and returns an index the next request carries, so the proxy
learns about an instance that went away in about the time Consul takes to
notice it, instead of up to a polling interval later. For a load balancer
that gap is the whole point — a polled registry keeps sending traffic to
a machine that is already gone for as long as the interval lasts.

The loop therefore waits on the agent rather than on a ticker: after an
answer it asks again at once, because the next answer *is* the next
change. `interval` becomes the pause after a **failure** — without one,
an agent that is down or answering 403 would be asked again immediately
and forever, which is a loop against somebody else's machine. An index
that goes backwards (a Consul server restart) resets to 1 rather than
blocking against an index that will never be reached.

Only instances whose checks all pass are used, and the check is made here
as well as asked for in the query: the filter in the query is the agent's
opinion, and this one is the proxy's. `Weights.Passing` becomes the
endpoint weight, and a blank service address falls back to the node's.

**How large a resolution may be.** `max_endpoints` bounds one
resolution. It is not a limit on the estate — 4096 endpoints in one pool
is more than a load balancer can usefully spread across — but on what a
single answer can do to this process: a DNS response over TCP carries
thousands of A records, and a four megabyte registry response tens of
thousands of entries, each of which would become a health-check goroutine
and a place in the hash ring. Beyond the bound the resolution is
**truncated rather than refused**, because refusing keeps the previous
set, and for a pool whose backends have all moved that is a pool serving
nothing. `xproxyctl upstreams` counts the truncations, and the log line
names how many were returned.

#### An endpoint that arrives while the pool is serving

A registry announces an instance when its process starts, not when it is
ready to answer: the service registers itself, then opens its database
connections, loads its caches and finally listens. An address appearing
in a resolution is therefore a weaker claim than it looks, and a pool that
sends traffic to it immediately produces a burst of failures the proxy
caused — the outlier ejection then has to clean up after a decision that
should not have been made.

So with `health_check` configured, an endpoint that **arrives after the
pool started serving** begins unhealthy and is not picked until it passes
`healthy_threshold` probes. Its first probe runs at once rather than after
the usual jitter, so the wait is one probe rather than up to one
`interval`.

Three cases are deliberately not that:

- **No `health_check`.** There is no probe to wait for, so a discovered
  endpoint serves as soon as it is resolved. Waiting would mean never.
- **Nothing else can carry the traffic.** If every other endpoint in the
  pool is unhealthy, draining, ejected or at its own `max_active`, the new
  one is used immediately: an unprobed endpoint is better than an empty
  pool, and there is no all-unhealthy fallback to catch that case.
- **The endpoints the pool starts with**, both the static `endpoints` and
  discovery's first resolution, start healthy — at process start nothing
  has been probed yet, and making them wait would serve nothing at all
  for a probe interval on every restart.

An address that leaves a resolution and comes back is a new endpoint, so
it waits again; what is listening there now is not the process that was
healthy before. `xproxyctl upstreams` shows `healthy: false` for an
endpoint in this state, the same as for one a probe has failed.

### upstreams[].health_check

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `type` | `http`, `grpc`, `tcp`, `udp` | `http` | `grpc` calls the standard `grpc.health.v1.Health/Check` over HTTP/2 and needs `h2c` or `scheme: https`; `path` and `expected_status` are not used. `tcp` and `udp` are the layer 4 probes, for the pools a `kind: tcp` or `kind: udp` listener uses, where there is no request to make — see below |
| `grpc_service` | string | `""` | Service asked in a grpc check; empty asks about the server as a whole |
| `path` | path | `/` | GET target |
| `interval` | duration | `5s` | At least 500ms; the first probe of each endpoint is jittered across one interval so that a large pool does not probe in lockstep — except for an endpoint discovery announced into a serving pool, which probes at once because it is waiting on that probe to be used at all |
| `timeout` | duration | `2s` | Must be shorter than `interval` |
| `healthy_threshold` | int | `2` | Consecutive successes to mark healthy |
| `unhealthy_threshold` | int | `3` | Consecutive failures to mark unhealthy |
| `expected_status` | list of int | `[200]` | |
| `max_concurrent` | int | `32` | Probes in flight per pool; 1 to 4096. Bounds the burst when a pool has thousands of endpoints |
| `keep_alive` | bool | `false` | Reuse pooled connections for probes. Off opens a fresh connection per probe (verifies the whole connect path, no descriptor held between probes); on saves the handshake at the cost of one idle connection per endpoint |
| `body_contains` | string | none | The first 64 KiB of the probe response must contain this text (type `http`); a status in `expected_status` alone is not enough |
| `body_regex` | RE2 | none | The first 64 KiB must match this pattern anywhere (anchor with `^` and `$`); may be combined with `body_contains`, both must hold. At most 4096 bytes each |
| `send` | string | none | What a `udp` probe sends. Exactly one of `send` or `send_hex` is required for that type |
| `send_hex` | hex | none | The same as hexadecimal, for a service whose smallest question is not text |
| `expect` | string | none | The answer must contain this text. Empty accepts any answer |
| `expect_hex` | hex | none | The same as hexadecimal; exclusive with `expect` |

#### The layer 4 probes

`type: http` and `type: grpc` make a request and read a reply, which is
how an HTTP backend proves it is working rather than merely running.
A pool behind a `kind: tcp` or `kind: udp` listener has no request to
make, so there are two narrower probes — and they are not equally
narrow, which is the thing to understand before choosing one.

**`type: tcp` connects and closes.** It proves that something accepted,
and nothing about what. For a protocol this proxy does not speak that is
usually all there is to know without speaking it, and it is a real
signal: a process that has died, a host that has gone, a port that was
never opened are all found.

**`type: udp` has to prove more, because a UDP socket accepts nothing.**
There is no connect to succeed. A datagram sent to a port with no
listener produces an ICMP port unreachable that the sender may or may
not be told about, that anything on the path may filter, and that says
nothing at all about a process which is bound but wedged — which is the
failure that matters most, because it is the one that keeps taking
traffic. So a `udp` check **sends a question the service answers**, and
silence is the failure:

```yaml
health_check:
  type: udp
  send_hex: "abcd0100000100000000000000"   # a DNS query header
  expect_hex: "abcd8180"                   # the same id, answered
  interval: 5s
  timeout: 1s
```

The probe socket is *connected*, so the kernel drops an answer from any
address but the endpoint's: a third party cannot vouch for a backend.
With no `expect` any answer is accepted, which is still far more than
silence proves; with one, the answer has to contain it, so a service
that has started listening but is still loading fails the check instead
of taking traffic.

### upstreams[].outlier_ejection

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `consecutive_failures` | int | `5` | Connection errors or 503 responses in a row |
| `base_ejection_time` | duration | `30s` | Multiplied by the ejection count, capped at 10x |
| `max_ejection_percent` | int | `50` | Never eject more than this share of the pool |
| `latency_threshold` | duration | `0` (off) | Eject an endpoint whose smoothed time to first byte (exponential moving average, factor 0.2, over responses and failed attempts) exceeds this |
| `latency_factor` | float | `0` (off) | Eject an endpoint whose smoothed latency exceeds the mean smoothed latency of the pool's other endpoints times this factor (1.5 to 100), so the outlier does not move its own reference; needs another endpoint with samples. Either rule ejects for `base_ejection_time` with the same back-off and `max_ejection_percent` bound as failures, the average is reset, and `xproxyctl upstreams` shows `latency_ms` and `latency_ejections` |
| `latency_min_samples` | int | `20` | Responses an endpoint must have answered since it last became available before its latency is judged (1 to 100000) |

### upstreams[].canary

A canary release inside one pool: the endpoints marked `canary: true`
receive the requests the policy selects and no others, so a new version
can be exercised by testers (a header or a cookie), then by a share of
everyone (`percent`), then promoted by marking the old endpoints out.
Selected requests fall back to the ordinary endpoints when no canary is
available, and ordinary requests fall back to the canaries when the
rest is down, unless `fallback: false`. Session affinity and hashing
apply within the chosen side. `canary: true` in the access log marks
responses from a canary endpoint; `GET /v1/pools` counts canary
requests and fallbacks. For a canary on a separate pool selected by
header, use `routes[].headers` instead.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `header` | header name | none | Requests carrying this header go to the canaries |
| `cookie` | cookie name | none | Requests carrying this cookie go to the canaries |
| `values` | list | `[]` (any value) | With `header` or `cookie`: only these values select |
| `percent` | 0 to 100 | `0` | Share of the other requests also sent to the canaries |
| `fallback` | bool | `true` | Use the other side when the selected one has no available endpoint |

At least one of `header`, `cookie` or `percent` is required, at least
one endpoint must be a canary and at least one must not.

### upstreams[].circuit_breaker

Outlier ejection removes one failing endpoint from a healthy pool; the
circuit breaker stops sending to a pool that fails as a whole and
probes it back. Closed, it counts consecutive failed attempts across
the pool (connection errors, timeouts, 503 and `retry_on` statuses; a
success resets the count). At `consecutive_failures` it opens: every
request is refused at once with 503 and `Retry-After` set to the
remaining open time, without touching the upstream, for `open_for`
times the number of consecutive reopens (capped at ten). Then it is
half open: `half_open_requests` trials may be in flight, a success
closes the circuit and resets the back-off, a failure reopens it.
`xproxyctl upstreams` and `GET /v1/pools` show the state, the count,
opens and refusals; `xproxy_upstream_circuit_state` and
`xproxy_upstream_circuit_open_total` export them; refusals appear in
the access log with `upstream_error: circuit_open`.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `consecutive_failures` | int | `5` | Failed attempts in a row that open the circuit (1 to 10000) |
| `open_for` | duration | `10s` | Base open time, multiplied by the reopen count (100ms to 1h) |
| `half_open_requests` | int | `1` | Trials allowed at once while half open (1 to 1000) |

### upstreams[].affinity

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `cookie_name` | token | `XPSESS` | |
| `ttl` | duration | `1h` | Cookie and signature lifetime |
| `secret_file` | path | ephemeral | HMAC key or keyring, created `0600` on first use if absent; rotate with `xproxyctl rotate-secret` (cookies signed with kept keys stay valid) |

### upstreams[].origin_signature

Network filtering keeps most traffic off an origin, but not where the
origin is reachable from the internet by design (a cloud service, a
shared host) or where another tenant sits on the same network. A signed
header lets the origin refuse anything that did not pass through the
proxy. Every forwarded request carries

```
X-Xproxy-Signature: v1;t=<unix seconds>;kid=<key id>;sig=<base64url HMAC-SHA256>
```

where the MAC covers, as newline separated lines: `v1`, the method,
the `Host` sent upstream (lower case), the path, the raw query, the
timestamp, the client address (the `X-Real-Ip` value), the request id
(`X-Request-Id`) and the values of the `include` headers in order
(repeated values joined with commas). The key id is the first eight hex
digits of the SHA-256 of the key. A signature header sent by a client
is always replaced.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `header` | name | `X-Xproxy-Signature` | |
| `secret_file` | path | required | Keyring shared with the origin (mode `0600`, created on first start; `xproxyctl rotate-secret` adds a new primary and keeps the previous key, so the origin verifies with either while it is updated) |
| `ttl` | duration | `5m` | Age the origin should accept; a signature is also refused more than a minute in the future |
| `include` | list of headers | `[]` | Extra request headers covered, for example a tenant header the proxy sets |
| `body_digest` | bool | `false` | Cover the request body as well: the proxy buffers it, appends `sha-256=:<base64>:` as a final signed line, sends it as `Content-Digest` and adds `;bd=1` to the signature header. Without it a signature proves that a request passed through the proxy, not what it carried — anything that can reach the origin can replay a captured header set with a body of its own while the timestamp is inside the TTL. A bodied request larger than 8 MiB is refused with `413` rather than forwarded with a signature that stops at the headers |

At the origin, recompute the MAC with the shared key selected by `kid`,
compare in constant time, and refuse when it differs, the key id is
unknown or `t` is older than the TTL. When the header carries `bd=1`,
the last signed line is the body digest: hash the body and compare.
Dropping `bd=1` does not turn that off, because the digest is part of
what was signed.

Within the TTL a signature is replayable by anything that captured it
(a log, a proxy in front of the origin, a browser extension). Where
that matters, have the origin remember the `X-Request-Id` values it has
already answered for the TTL and refuse a repeat: the proxy sets a
fresh one per request and the id is covered by the signature, so a
replay carries the same id. `body_digest` bounds what a replay can
change; the id dedupe stops the replay itself. HARDENING.md has verifier
snippets; `internal/originsig` has `Verify` for origins written in Go.
Combine with mutual TLS (`tls.client_cert_file`) and with network
filtering: each closes what the others cannot.

## http

`kind: http` has no section of its own here, because it is most of this
document. The other twenty-seven kinds each get one section, since each reads
one protocol and has one policy about it; HTTP is a pipeline of policies, and
they are written up where each belongs.

Where to look, in roughly the order a request passes through:

| What | Section |
|------|---------|
| The listener, its address, TLS and the framing limits | [`server`](#server), [`limits`](#limits) |
| The route, and everything decided per route | [`routes[]`](#routes) |
| Who is asking, and with what | [`filters[]`](#filters) — the identity filters |
| Whether the request is what it claims | [`waf`](#waf) |
| Whether it is a person | [`challenge`](#challenge), and the bot and account filters in [`filters[]`](#filters) |
| How much and how often | [`shedding`](#shedding), the rate limits in [`routes[]`](#routes), and [`bans`](#bans) |
| Where it goes | [`upstreams[]`](#upstreams) |
| What is remembered and what is compressed | [`cache`](#cache), [`compression`](#compression) |
| What an attacker is told | [`decoys`](#decoys), and [docs/DECEPTION.md](DECEPTION.md) |

The protocol itself -- the three wire formats, what each gives you, and the
framing ambiguities this listener refuses rather than normalises -- is
[docs/protocols/http.md](protocols/http.md). Every kind has a page there;
[docs/protocols/README.md](protocols/README.md) is the index.

## routes[]

Matching: exact host, then wildcard host, then hostless routes; within a
host the longest path (a `path_regex` entry counts as the length of its
literal prefix and, at equal length, beats a plain prefix); then the
number of `headers` and `cookies` conditions (more first, so a
conditioned route is tried before the plain route on the same path);
then `priority` (higher wins); then configuration order. `methods` and
the conditions are filters: a route whose method set or conditions do
not match is skipped and the next candidate is tried.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | name | required, unique | Appears in logs |
| `hosts` | list | `[]` (any) | `example.com` or `*.example.com` (one label) |
| `paths` | list | `["/"]` (none when `path_regex` is set) | Prefixes on segment boundaries |
| `path_regex` | list | `[]` | RE2 patterns matched against the whole cleaned path (anchored at both ends by the proxy); must start with `/`; at most 32, each at most 512 bytes. `strip_prefix` and `rewrite_path` apply as usual |
| `headers` | list | `[]` | Conditions on request headers, all of which must hold: `{name, exact | prefix | regex | present}`; names are case insensitive, the first value is examined, `regex` matches the whole value, `present: false` requires absence; at most 16 conditions with `cookies` |
| `cookies` | list | `[]` | The same conditions on cookies by name |
| `when` | expression | none | A condition in the expression language (see "Expressions" below) that must hold as well, for example `client_ip in cidr("10.0.0.0/8") && header("X-Env") == "beta"`; counts as one condition for specificity. At most 4096 bytes |
| `methods` | list | `[]` (any) | Upper-case tokens |
| `priority` | int | `0` | Tie breaker |
| `tenant` | name | none | Free label grouping routes for quota reporting (`xproxyctl quotas`, `GET /v1/quotas`) and added as a `tenant` label to the per route metrics |
| `upstream` | name | | Exactly one of `upstream`, `redirect`, `respond`, `honeypot`, `doh`, `static` |
| `redirect` | `{to, status}` | status `308` | `to` is a URL or path and may use the request variables (below), for example `https://new.example.com${path}?${raw_query}`; status 301, 302, 303, 307 or 308. The destination host must be fixed by the configuration: `to` starts with a literal path (`/x…`) or `scheme://host` (`${host}` and `${scheme}` allowed), so request data can fill the path or query but never pick the host (`/${query:next}` is refused) |
| `respond` | `{status, body}` | status `200` | Static response, body up to 64 KiB |
| `honeypot` | object | | Decoy action; see `routes[].honeypot` |
| `mirror` | object | | Copy requests to a second upstream; see `routes[].mirror` |
| `grpc` | `{services, methods}` | | Restrict the route to gRPC requests; see `routes[].grpc` |
| `doh` | `{listener}` | | DNS over HTTPS action; see `routes[].doh` |
| `static` | object | | Serve files from a directory; see `routes[].static` |
| `compress` | bool | follows `compression` | `false` leaves this route's responses as they are; `true` needs an enabled `compression` section |
| `compress_authenticated` | bool | follows `compression.compress_authenticated` | Compress this route's responses to requests carrying `Authorization` or a `Cookie` (see BREACH under `compression`) |
| `strip_prefix` | path | | Remove this prefix before forwarding |
| `rewrite_path` | path | | Replace the path entirely; exclusive with `strip_prefix` |
| `host_header` | string | client `Host` | Host sent upstream |
| `request_headers` | `{set, add, remove, when}` | | Applied before forwarding; values may not contain CR, LF or NUL |
| `request_headers.when`, `response_headers.when` | expression | none | Apply the block only when the expression holds (see "Expressions" below), for example `query("debug") == "1"` or `not has_cookie("consent")`; `${variable}` values are still expanded |
| `response_headers` | `{set, add, remove}` | | Applied to responses, including redirect and respond actions |
| `client_cert_headers` | `none`, `rfc9440`, `xfcc` | `none` | State the client's TLS certificate to the backend: `rfc9440` sets `Client-Cert` and `Client-Cert-Chain` (RFC 9440), `xfcc` sets Envoy's `X-Forwarded-Client-Cert`. Nothing is sent when the client presented no certificate — an absent header is how the backend is told there was none. See "Client certificate identity headers" below |
| `request_headers.*`, `response_headers.*` values | template | | `set` and `add` values may contain `${variable}` placeholders (see "Variables" below); `$$` is a literal dollar; a placeholder without a value expands to an empty string |
| `rate_limits` | list of names | `[]` | Evaluated in order; first exhausted policy acts |
| `allow_cidrs` | list | `[]` (all) | Client must be inside one |
| `deny_cidrs` | list | `[]` | Evaluated first |
| `max_body_bytes` | int | global | May only lower the global limit |
| `timeout` | duration | none | Whole request deadline for this route (the total, accept to last response byte). The named `timeouts` block is the alternative and adds an idle timeout; set one or the other |
| `timeouts.total` | duration | none | Same as `timeout` |
| `timeouts.idle` | duration | none | Cancels a response that produces no bytes for this long, for streaming or long-poll routes where `total` is too coarse. Connect and response-header timeouts are configured per upstream (`upstreams[].timeouts`), since the connection pool is shared |
| `websocket` | bool | `false` | Allow `Upgrade` requests |
| `websocket_guard` | object | none | Inspect the frames of an upgraded connection; see below |
| `webtransport` | bool | `false` | Relay WebTransport sessions (extended CONNECT over HTTP/3) to the upstream: bidirectional and unidirectional streams and datagrams in both directions, with the request header operations applied to the CONNECT. Needs a listener with `h3.webtransport: true` and an upstream with `h3: true`; on any other listener or protocol the session is refused |
| `grpc.web` | bool | `false` | Accept gRPC-web requests (`application/grpc-web`, `grpc-web+proto`, `grpc-web-text`, `grpc-web-text+proto`, over HTTP/1.1 or HTTP/2) on this gRPC route and translate them: the upstream sees plain gRPC, the response trailers come back as a trailer frame in the body and the text variants are base64. Without it a gRPC-web request is refused with gRPC status 2 |
| `grpc.web_origins` | list | `[]` | Browser origins (`https://app.example.com`, or `*`) whose CORS preflights are answered (`POST`, the requested headers, ten minutes) and whose responses get `Access-Control-Allow-Origin` and the exposed `grpc-status` and `grpc-message`; needs `web: true`. Empty leaves CORS to the upstream or to header operations |

**Routing by API version.** There is no `version` key, because every way
a version is actually expressed is already a matcher here, and a
dedicated key would only cover one of them:

```yaml
routes:
  # In the path, which is most APIs.
  - {name: api-v1, hosts: [api.example.com], paths: ["/v1/"], upstream: orders-v1}
  - {name: api-v2, hosts: [api.example.com], paths: ["/v2/"], upstream: orders-v2}

  # In a media type, the "vendor versioning" style. A conditioned route
  # is tried before the plain route on the same path, so this takes the
  # requests that ask for v2 and the unconditioned route below keeps the
  # rest.
  - name: api-accept-v2
    hosts: [api.example.com]
    paths: ["/orders/"]
    headers: [{name: Accept, regex: ".*vnd\\.example\\.v2(\\+json)?"}]
    upstream: orders-v2

  # In a header, with a default. `priority` decides only ties; the
  # condition count already puts the conditioned route first.
  - name: api-header-v2
    hosts: [api.example.com]
    paths: ["/orders/"]
    headers: [{name: X-API-Version, exact: "2"}]
    upstream: orders-v2
  - {name: api-default, hosts: [api.example.com], paths: ["/orders/"], upstream: orders-v1}

  # Anything else -- a query parameter, a version pinned per client
  # network, a date-based version -- is an expression.
  - name: api-pinned
    hosts: [api.example.com]
    paths: ["/orders/"]
    when: 'query("api-version") == "2024-11-01" || client_ip in cidr("10.9.0.0/16")'
    upstream: orders-v2
```

A version that has to be *removed* before the backend sees it is
`strip_prefix: /v2` or a `request_headers.remove`; one that has to be
*added* is `request_headers.set`. The deprecation of an old version is a
`response_headers.add` of `Deprecation` and `Sunset` on the old route,
and `maintenance` on it when the day comes.

## ingress

Kubernetes ingress controller mode. When enabled, the proxy reads the
Ingress, Service, EndpointSlice and TLS Secret resources of one ingress
class, and the Gateway API resources (Gateway, HTTPRoute) of the same
class when the cluster has them, from the API server with the pod's
service account (no client library), translates them and appends the
result to this file's routes, upstreams and certificates: the running
configuration is the file plus the cluster. The file's own routes and
upstreams are kept and a name collision is an error. Watch streams on
the resources trigger a sync within `debounce` of a change, with a
full poll every `resync` as the fallback; a change reloads the proxy
like a SIGHUP, and a SIGHUP or `xproxyctl reload` re-reads the file
and merges the latest snapshot. The API server being unreachable at
start is a warning, not a failure: the file configuration serves until
the first successful sync.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | |
| `api_server` | URL | `https://kubernetes.default.svc` | `http://` only with `allow_http` (tests, `kubectl proxy`) |
| `token_file` | path | the service account token | Bearer token |
| `ca_file` | path | the service account CA | Verifies the API server |
| `allow_http` | bool | `false` | |
| `class` | name | `xproxy` | `ingressClassName` (or the `kubernetes.io/ingress.class` annotation) served; other classes are ignored |
| `namespaces` | list | `[]` (all) | Namespaces read |
| `listener` | name | none | TLS `http` listener that receives certificates from Ingress TLS secrets; without it TLS secrets are ignored |
| `cert_dir` | path | `/var/lib/xproxy/ingress` | Certificate files written `0600` per secret (`namespace--name.crt/.key`); files of secrets no longer referenced are removed |
| `resync` | duration | `30s` | Full poll interval, 1s to 1h; with watches the fallback, without them the propagation delay |
| `timeout` | duration | `10s` | One API request |
| `watch` | bool | `true` | Open watch streams on Ingresses, Services, EndpointSlices, Secrets, Gateways and HTTPRoutes; streams reconnect with backoff, a resource the cluster does not serve is retried every five minutes |
| `debounce` | duration | `500ms` | A burst of watch events becomes one sync; 50ms to 1m |

Translation: every `rules[].http.paths[]` entry becomes a route named
`k8s-<namespace>-<ingress>-<n>` with the rule's host, the path as a
prefix (`pathType: Exact` gets priority 10 so it wins over a prefix of
the same length; `ImplementationSpecific` paths with wildcards are
skipped with a warning), and an upstream `k8s-<namespace>-<service>-<port>` whose
endpoints are the ready addresses of the service's EndpointSlices on
the port the service maps to (a service without ready endpoints gets
an unreachable placeholder so the route answers 503 rather than
disappearing). `defaultBackend` becomes a hostless `/` route with
priority -100; only the first Ingress with one counts. Annotations
with the prefix `xproxy.sysctl.se/` set route options: `websocket`
(`"true"`), `priority-class`, `rate-limits` and `filters` (comma
separated names from this file), `timeout`, `max-body-bytes`,
`strip-prefix` (`"true"` strips the matched path), `host-header`.
Names over 64 bytes are shortened with a digest.

What a tenant writes is checked before it becomes configuration: a
rule's host must be a DNS name (a leading `*.` label allowed) and its
path a plain prefix with no space or control character, a namespace and
an Ingress name must be DNS labels, and a TLS secret must be of type
`kubernetes.io/tls` and carry `tls.crt` and `tls.key`. Anything else is
skipped with a warning in `GET /v1/ingress` and the log, so one
namespace cannot put a value into the shared configuration that the
other namespaces' routes are matched, logged or counted against.

Gateway API: Gateways whose `gatewayClassName` is `class` and the
HTTPRoutes whose `parentRefs` name them translate as well. Route
hostnames come from the HTTPRoute or, when it has none, from the
parent listeners' hostnames (wildcards allowed). Each rule and match
becomes a route `k8s-gw-<namespace>-<httproute>-<rule>-<match>`:
`PathPrefix` and `Exact` paths (priority 10 for exact),
`RegularExpression` paths as `path_regex`, a `method` match, and
header matches of type `Exact` and `RegularExpression` as `headers`
conditions (a match with an unknown header match type or a pattern that
does not compile is skipped with a warning). Filters: `RequestHeaderModifier`
and `ResponseHeaderModifier` become header operations, `URLRewrite`
with `ReplaceFullPath` becomes `rewrite_path`, with `ReplacePrefixMatch: /`
`strip_prefix`, and a `hostname` `host_header`; `RequestRedirect` with a
`hostname` becomes a redirect action (a redirect without a hostname is
not supported). A rule with one backend uses that service; several
`backendRefs` become one `weighted` upstream over all their endpoints
with the reference weights (weight 0 excluded). Listener
`certificateRefs` install the secrets like Ingress TLS. `GET /v1/ingress`
and `xproxyctl ingress` show syncs, errors, watch streams and events,
counts (Ingresses, Gateways, HTTPRoutes, routes, upstreams,
certificates) and the translation warnings. `deploy/kubernetes/xproxy.yaml` is a complete deployment
with RBAC, an IngressClass and a ConfigMap; `deploy/kubernetes/Containerfile`
builds the image.

## metrics

The management socket always serves `/metrics` in Prometheus text format
and `/v1/series` with sampled series. This section adds an optional TCP
endpoint for scrapers and sizes the series buffer.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `listen` | host:port | `""` (disabled) | Serves only `/metrics`. Binding all interfaces requires `tls` with `client_ca_file` |
| `allow_cidrs` | list | `[]` (any) | Scraper source addresses; others get 403 and a security event |
| `tls.cert_file`, `tls.key_file` | path | | Make the endpoint HTTPS |
| `tls.client_ca_file` | path | | Require client certificates from this CA (mutual TLS) |
| `per_route` | bool | `true` | Expose the per route families: `xproxy_route_requests_total{route,outcome}`, `xproxy_route_bytes_total`, `xproxy_route_rate_limited_total` and the latency histogram `xproxy_route_request_duration_seconds{route}` (one series per route, bucket and outcome; a `tenant` label when set) |
| `endpoint_series` | bool | `true` | Expose five series per upstream endpoint (`xproxy_upstream_endpoint_*`). About 1 KiB per endpoint per scrape; turn off above a few thousand endpoints and rely on the per-pool `xproxy_upstream_endpoints_healthy` |
| `sample_interval` | duration | `10s` | Series sampling period; 1s to 5m |
| `retention` | duration | `1h` | Series kept in memory; at most 100000 points |
| `otlp.endpoint` | URL | none | Enables the OpenTelemetry push exporter: the collector's metrics URL (`https://otel.example.com:4318/v1/metrics`); `http://` only with `otlp.allow_http` |
| `otlp.allow_http` | bool | `false` | |
| `otlp.interval` | duration | `30s` | Push period; 1s to 1h. The last push happens at shutdown |
| `otlp.timeout` | duration | `10s` | One push; at most `interval` |
| `otlp.headers` | map | `{}` | Request headers, for example `Authorization` |
| `otlp.ca_file` | path | system pool | Pins the collector's CA |
| `otlp.service_name` | string | `xproxy` | `service.name` resource attribute; `service.version` and `host.name` are added |
| `otlp.attributes` | map | `{}` | Extra resource attributes |
| `otlp.compress` | bool | `true` | gzip the request body |

The OTLP exporter sends the same families as OTLP/HTTP with JSON
encoding: counters as cumulative monotonic sums since process start,
gauges as gauges, histograms as cumulative explicit bucket histograms;
labels become data point attributes. `GET /v1/otlp` and `xproxyctl
otlp` show pushes, failures, the last error and the size of the last
request.

Exposed families: `xproxy_requests_total`, `xproxy_responses_total{class}`,
`xproxy_denied_total{reason}`,
`xproxy_refusals_total{kind,reason}` (the same breakdown for the
protocols that are not HTTP: the listener kind that refused and the
reason it logged, described in
[TROUBLESHOOTING.md](TROUBLESHOOTING.md#counting-refusals-by-protocol-and-reason)),
`xproxy_refusals_untracked_total`, `xproxy_bytes_in_total`,
`xproxy_bytes_out_total`, `xproxy_waf_detected_total`,
`xproxy_upstream_errors_total`, `xproxy_upstream_timeouts_total`,
`xproxy_upstream_no_healthy_total`, `xproxy_client_aborts_total`,
`xproxy_connections_rejected_total`, `xproxy_reloads_total{result}`,
`xproxy_bans_total`, `xproxy_challenges_total{result}` (`issued`,
`passed`, `failed`, `captcha_passed`),
`xproxy_sensitive_findings_total{kind}`,
`xproxy_sensitive_messages_total{direction,outcome}`,
`xproxy_account_actions_total{class,action}`,
`xproxy_account_events_total`, `xproxy_account_blocks_total`,
`xproxy_account_campaigns_total`, `xproxy_account_disposable_total`,
`xproxy_account_blocks_active`,
`xproxy_log_sent_total{sink}`, `xproxy_log_dropped_total{sink}`,
`xproxy_connections_open`, `xproxy_requests_in_flight`,
`xproxy_bans_active`, `xproxy_sessions_live`,
`xproxy_sessions_total`, `xproxy_sessions_closed_total{by}`,
`xproxy_load_level`,
`xproxy_upstream_latency_seconds`, `xproxy_shedding{class}`,
`xproxy_cluster_peers`, `xproxy_cluster_peers_connected`,
`xproxy_cluster_messages_total{direction,type}`,
`xproxy_cluster_rejected_total`, `xproxy_request_duration_seconds`
(histogram), `xproxy_upstream_ttfb_seconds` (histogram),
`xproxy_upstream_endpoint_{healthy,ejected,active}{upstream,endpoint}`,
`xproxy_upstream_endpoint_{requests,errors}_total{upstream,endpoint}`,
`xproxy_route_requests_total{route,outcome}`, `xproxy_build_info`,
`xproxy_uptime_seconds`, `xproxy_config_generation`,
`xproxy_panics_total` (panics contained on a connection or datagram
goroutine; zero in a healthy process, and anything else is a bug worth a
report).

Series (per-second rates for counters, current values for gauges):
`requests`, `responses_2xx`, `responses_4xx`, `responses_5xx`, `denied`,
`shed`, `bytes_in`, `bytes_out`, `upstream_errors`, `open_connections`,
`in_flight`, `load_level`, `upstream_latency_ms`, `bans_active`,
`cluster_connected`.

## api_inventory

Present means enabled. The proxy discovers the API surface it serves
from traffic: every request of a proxied route (not redirects, static
files or honeypots) is attributed to its host, method and path
template, with first and last seen times, counts per status class, the
kinds of credential clients present (`bearer`, `basic`, `api_key`,
`cookie`, `client_cert`, `none`), request and response media types and
the version segment of the path (`v1`, `v2`). Identifiers in the path
(numbers, UUIDs, hashes, opaque tokens) fold into `*`, so `/users/42`
and `/users/43` are one endpoint; on a route with an `openapi` filter
the description's own template is used and the filter says whether the
operation is documented. `xproxyctl api` and `GET /v1/api` show:

- **shadow** APIs: traffic to a described route outside its
  description (an undocumented path or method), the endpoints nobody
  reviewed;
- **zombie** APIs: documented operations without any traffic for
  `zombie_after`, or never since the inventory started, the endpoints
  nobody uses but everyone still maintains;
- **superseded** versions: a `v1` still receiving traffic next to a
  `v2` of the same host, method and path;
- the plain inventory, sorted by requests, with `versions`,
  `documented` and `undocumented` views;
- any view as an OpenAPI 3.0 skeleton (`xproxyctl api undocumented
  -openapi`, `GET /v1/api?view=undocumented&format=openapi`): one path
  item per observed template with named path parameters, the observed
  methods, request and response media types, response status classes,
  the credential kinds as security schemes, hosts as servers and an
  `x-xproxy` extension with the traffic evidence; schemas and
  descriptions are left for the API team to complete, after which the
  file serves an `openapi` filter.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | |
| `max_endpoints` | int | `10000` | Bound on distinct endpoints; further ones are counted as dropped (100 to 1000000) |
| `hosts` | list of host patterns | every proxied route | Only routes serving these hosts |
| `routes` | list of names | every proxied route | Only these routes |
| `zombie_after` | duration | `720h` | Silence after which a documented endpoint is a zombie; 1h to 8760h |
| `state_file` | path | none | Keeps the inventory across restarts (written every `save_interval` and at shutdown, mode `0600`) |
| `save_interval` | duration | `5m` | 10s to 24h |

The table lives for the process and survives reloads; counts are
cumulative since the start (or since the oldest record in the state
file).

## bans

Present means enabled. Bans apply before routing; banned peers are closed
at accept when `action` is `drop`, and answered 403 when the client address
comes from a trusted proxy chain or `action` is `reject`.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `state_file` | path | `""` (memory only) | bbolt file that persists bans across restarts |
| `max_entries` | int | `100000` | Bound on banned addresses; the soonest expiring are evicted when full |
| `exempt_cidrs` | list | `[]` | Never banned, by trigger or by operator. Adding a range also releases the bans it covers, on the reload that adds it and on a restart that restores them from the state file |
| `action` | `drop`, `reject` | `drop` | Close at accept, or answer 403 only |
| `triggers` | list | `[]` | Automatic bans; see below |

### bans.triggers[]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | name | required, unique | Appears in the ban entry as `trigger:<name>` |
| `reasons` | list | `[]` (all) | Deny categories that count: `acl`, `rate_limit`, `waf`, `body_size`, `uri_length`, `bad_host`, `no_route`, `websocket`, `concurrency`, `challenge`, `jwt`, `icap`, `geo`, `tcp_no_route`, `forward_denied`, `forward_auth`, `honeypot`, `dns_blocked`, `dns_bogus`, `dns_rpz`, `honeytoken`, `account_abuse`, `api_abuse`, `threat_intel`, `scim`, `smtp_denied`, `mqtt_denied`, `ssh_denied`, `ftp_denied`, `syslog_denied`, `telnet_denied`, `vnc_denied`, `rdp_denied`, `forward_sni_mismatch`, `dns_tunnel`, `dns_answer_denied`, `sftp_icap`, `udp_denied`, `modbus_denied`, `iec104_denied`, `snmp_denied`, `ldap_denied`, `tftp_denied`, `dhcp_denied`, `postgres_denied`, `mysql_denied`, `tds_denied`, `redis_denied`, `bacnet_denied`, `amqp_denied`, `s7_denied`, `ntp_denied`, `ntske_denied`, `yara` |
| `threshold` | int | required | Denies within `window` that trigger the ban |
| `window` | duration | required | At most 24h |
| `duration` | duration | required | First ban length |
| `escalation` | float | `2` | Multiplier applied for each repeat ban of the same target |
| `max_duration` | duration | `24h` | Cap on escalated duration; at least `duration` |
| `aggregate` | `address`, `net`, `ja4` | `address` | What the trigger counts and bans. `net` keys the window by the client network (`net_v4` or `net_v6` bits) and bans that network, for an attack spread over one allocation; `ja4` keys it by the TLS client fingerprint and bans the fingerprint (`ja4:<fp>`), for an attack spread over many networks from one tool; plaintext connections do not count towards a `ja4` trigger |
| `net_v4`, `net_v6` | int | `24`, `48` | Prefix lengths for `aggregate: net` (8 to 32, 32 to 128) |
| `min_sources` | int | `1` | For `net` and `ja4`: distinct client addresses that must have contributed to the window before the aggregate is banned, so one noisy host does not ban its neighbours or a common fingerprint; at most `threshold` |

Manual bans (`xproxyctl ban`) accept addresses, CIDRs no wider than /8
(IPv4) or /32 (IPv6) and fingerprints as `ja4:<fp>`; loopback and
unspecified addresses are refused. A network overlapping an exempt
range is never banned, by trigger, operator or peer; a fingerprint ban
is not applied to clients in exempt ranges. Fingerprint bans apply at
the request stage (the fingerprint is known after the TLS handshake),
not at accept; at most 4096 are held.

## threat_intel

Imported lists of client addresses and TLS fingerprints somebody else
attributed, and what to do about a match.

**It is deliberately not the ban list beside it.** A ban is earned here:
this proxy watched a client do something and decided. A list is imported
— a feed of scanner networks, of exit nodes, of addresses seen attacking
somebody else — and it says nothing about what the client did *here*. A
feed with one wrong line in it is an outage nobody can explain from the
logs, which is why `log` is the default action and why `block` warns.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `lists` | list | required | The lists, in order. **The first list that matches decides**, so a narrow list belongs before the broad one it softens |
| `refresh` | duration | `5m` | How often the files are checked; only a file whose size or modification time moved is re-read. At least `10s`, or 0 for never — a reload of the configuration still re-reads every list |
| `log_matches` | bool | `true` | Write a security event for a match whose action is `log` as well. A list nobody can see matching is a list nobody can tune |

### threat_intel.lists[]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | name | required | What the security event, the counters and `xproxyctl status` call this list |
| `kind` | `cidr`, `ja4` | `cidr` | Client addresses and networks, or TLS client fingerprints |
| `file` | path | required | The entries. One per line, with `#`, `;` and `//` comment lines and a trailing comment after whitespace; a network may be written with host bits set and is masked. An address list matches IPv4 and its IPv6-mapped form alike |
| `action` | `log`, `challenge`, `block` | `log` | Record it and serve the request; make the client prove it is a browser (needs the `challenge` section); or refuse it with 403 |

```yaml
threat_intel:
  refresh: 15m
  lists:
    # The office first, so nothing below can take it out.
    - {name: known-good, file: /etc/xproxy/intel/office.txt, action: log}
    - {name: tor-exits, file: /etc/xproxy/intel/tor-exits.txt, action: challenge}
    - {name: scanner-fingerprints, kind: ja4, file: /etc/xproxy/intel/scanners.txt, action: challenge}
    # A feed this estate maintains itself, so blocking on it is a
    # decision somebody here can be asked about.
    - {name: internal-deny, file: /etc/xproxy/intel/deny.txt, action: block}
```

What follows from the shape:

- **A list that cannot be read fails the load**, and a reload that cannot
  read one is refused whole. An imported list that silently matches
  nothing is worse than no list, because the operator believes it works.
  A file that disappears *after* the load keeps the entries already read:
  a feed being rewritten in place must not empty the policy for the
  moment that takes.
- **The check runs after routing**, so `threat_intel: false` on a route
  exempts it — which is what a health endpoint or a status page wants.
  The ban list is checked earlier and applies to everything, because a
  ban is this proxy's own finding.
- **`challenge` with nothing to challenge with serves the request.** A
  list that asks for a challenge on a listener without the `challenge`
  section, or a client that has already proved itself, is not turned into
  a block: that would be a policy the operator did not write. Validation
  refuses the combination at load, so it only arises if the section is
  removed later.
- **An entry is a whole match or nothing.** `cidr` matches the client
  address the proxy decided on (so behind a trusted proxy chain, the
  forwarded one), and `ja4` the fingerprint of the TLS handshake, which a
  plaintext listener does not have.
- **A block hands the ban list `threat_intel`**, so a trigger can
  escalate a client that keeps arriving from a listed network into a real
  ban. `log` and `challenge` do not.

`threat_intel_matched`, `threat_intel_blocked`, `threat_intel_challenged`
and `threat_intel_reloads` are in `xproxyctl status`, which also lists
every list with its entry count, hits and when it was last read;
`xproxy_threat_intel_total{result="logged"|"blocked"|"challenged"}` is
the metric. A match adds `threat_list` to the access log line.

## waf

Present means enabled. Routes without a `waf` block use `default_mode` and
`default_profile`. Profiles compile at load and at reload; a broken rule
set fails the reload.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `profiles` | list | required, at least one | Rule sets; see below |
| `default_mode` | `off`, `detect`, `block` | `block` | `detect` logs what `block` would have done |
| `default_profile` | name | `default` | |
| `request_body_limit` | int | `1048576` | Bytes of request body inspected; 1024 to 1 GiB |
| `request_body_limit_action` | `reject`, `partial` | `reject` | 413 above the limit, or inspect the first bytes and pass the rest |
| `inspect_responses` | bool | `false` | Enable response header and body rules (data leakage) |
| `response_body_limit` | int | `524288` | Larger response bodies pass uninspected |
| `response_mime_types` | list | text and JSON/XML types | Bodies with other content types are not inspected |
| `learning` | object | none | Exclusion learning; see below |
| `anomaly` | object | none | Behavioural anomaly detection per client; see below |

**What decodes a body, and what does not.** There is no list of content
decoders here, deliberately. Decoding is SecLang's own, per rule and per
target: `t:urlDecodeUni`, `t:base64Decode`, `t:base64DecodeExt`,
`t:hexDecode`, `t:jsDecode`, `t:cssDecode`, `t:cmdLine`,
`t:utf8toUnicode`, `t:removeNulls` and the rest, which is how the Core
Rule Set already reads a payload hidden inside an encoding — and which is
right, because a rule knows which of its targets can be encoded and a
gateway-wide decoder does not. Writing one is a rule:

```
SecRule ARGS:payload "@rx (?i)union\s+select" \
    "id:9100,phase:2,t:none,t:urlDecodeUni,t:base64Decode,deny,status:403,\
     msg:'SQL injection inside a base64 parameter'"
```

The bodies the rules see are parsed by content type — urlencoded,
multipart, JSON and XML — up to `request_body_limit`. What they do **not**
see is a body wrapped in a *transfer* encoding: a `Content-Encoding:
gzip` request body is inspected as the compressed bytes it arrived as,
not expanded first. That is a deliberate line, and the reason is
amplification: a decoder at the gateway, applied to every body before any
rule has decided anything, is a second parser and a decompression bomb
away from being the outage. Where a compressed body has to be read, the
`sensitive_data` filter decodes `gzip`, `deflate`, `br` and `zstd` under
an expansion-ratio bound, and ICAP or `yara` scan the stream — each of
them a decision about one route rather than a default for all of them.

**XML targets are two collections, not an XPath engine.** With the XML
body processor selected, the engine fills exactly two: `XML://@*`, every
attribute value in the document, and `XML:/*`, every piece of character
data. A rule over either works, and it is how the Core Rule Set reads an
XML body:

```
SecRule REQUEST_HEADERS:Content-Type "@rx xml" \
    "id:9200,phase:1,pass,nolog,ctl:requestBodyProcessor=XML"
SecRule XML://@* "@rx (?i)\bunion\b.{1,100}?\bselect\b" \
    "id:9201,phase:2,deny,status:403,msg:'injection in an XML attribute'"
```

Any other selector — `XML:/invoice/total`, `XML://item[@id]` — is
**accepted by the parser and then evaluated against nothing**, so a rule
written over it never fires. That is the engine's limitation rather than a
setting, and it is stated here because a rule an operator believes is
running is worse than one they know they have to write differently. Where
a *named* element or a document's shape is the requirement, the
`xml_guard` filter is the one that reads structure: `require_root`,
`require_root_namespace`, `allow_elements` and `deny_elements` are a
positive model over the element names, with the entity, expansion and
depth bounds beside them, and `deny_patterns` covers the text. A test
drives all three selectors, so the sentence above stays true of the
engine this binary links.

### waf.learning

Learning aggregates every match of a detection rule by rule id, matched
variable (for example `ARGS:q`) and route, in block and detect mode
alike. A triple seen `min_hits` times becomes a proposal with a ready to
review SecLang exclusion, scoped to the route's path prefix when it has
one (`GET /v1/waf`, `GET /v1/waf/exclusions`, `xproxyctl waf
proposals`). The table and the per rule statistics live for the process
and survive reloads; `POST /v1/waf/reset` clears them.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Collect matched variables |
| `min_hits` | int | `5` | Matches before a proposal appears; 1 to 1000000 |
| `max_entries` | int | `10000` | Bound on distinct (rule, variable, route) entries; further ones are counted as dropped; 100 to 1000000 |

**Which rules are noise on *this* traffic** is a question the statistics
can answer, and the rule set cannot. Beside each rule's matches,
`xproxyctl waf` shows `ALONE` and `AGREED`: how many of those matches
happened with no other attack rule matching the same request, and the
share where at least one other did.

It is a measurement, not a verdict. A rule that only ever fires alone is
either the one thing noticing something or the one thing crying wolf, and
which of those it is takes a person — but a rule set has hundreds of rules
and this says which few are worth that person's afternoon. The CRS's
paranoia level is a statement about how aggressive a rule is; this is a
statement about what it did here.

The scoring and reporting rules are left out of the arithmetic on both
sides: rule 949110 evaluating the anomaly score is the rule set's own
bookkeeping, not a second opinion about the request. And the exclusion
proposals are ordered by the same number, least agreement first: an
exclusion for a rule nothing ever agreed with is the safest one to write.

### waf.anomaly

The rules judge one request at a time. Anomaly detection judges
clients: every WAF protected request is attributed to its client
address, and at the end of each window a client with at least
`min_requests` becomes a feature vector (request rate, share of
requests that matched a rule, share that ended in an error or a deny,
spread over distinct paths). The population's mean and variance per
feature form a baseline that follows drift across windows; a client
whose largest positive z-score against the previous baseline reaches
`threshold` is flagged and its next requests get `action`, until a
later window scores it normal or it stays away for three windows. A
window with fewer than eight scored clients updates nothing, so a
quiet site never flags its only visitor. Flags, the baseline and the
counters show under `xproxyctl waf anomalies` and `GET /v1/waf`.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | |
| `window` | duration | `5m` | Observation period; 10s to 24h |
| `min_requests` | int | `30` | Requests a client needs in a window before it is scored; 1 to 1000000 |
| `threshold` | float | `4` | z-score at which a client is flagged; 1 to 100 |
| `action` | `log`, `challenge`, `block` | `log` | For requests of a flagged client: log attributes only, serve the browser challenge (a plain 403 without a `challenge` section), or deny with 403 and reason `waf_anomaly` |
| `max_clients` | int | `65536` | Clients tracked per window; further ones are counted as dropped and not scored; 100 to 10000000 |

### waf.profiles[]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | name | required, unique | |
| `crs` | object | none | Enable the bundled OWASP Core Rule Set |
| `crs.dir` | absolute path | embedded copy | Load the Core Rule Set from a directory in the release layout (`crs-setup.conf` or `crs-setup.conf.example`, `rules/*.conf` with their `.data` files); a reload picks up changed files, so rules update without a new binary. The directory is validated at load and a broken file fails the reload |
| `crs.plugins_dir` | absolute path | none | Directory of CRS plugins: files named `<plugin>-config.conf`, `<plugin>-before.conf` and `<plugin>-after.conf` directly in it, in a subdirectory per plugin, or in that subdirectory's `plugins/` folder (a checked out plugin repository); data files next to them resolve by bare name and under `plugins/`. Config and before files load before the CRS rules, after files after them |
| `crs.plugins` | list of names | every plugin found | Load only these plugins; a listed plugin that is missing fails the load |
| `crs.paranoia_level` | int | `1` | 1 to 4 |
| `crs.inbound_threshold` | int | `5` | Anomaly score that blocks a request |
| `crs.outbound_threshold` | int | `4` | Anomaly score that blocks a response |
| `directive_files` | list of paths | `[]` | SecLang files loaded after CRS setup and before CRS rules (exclusions go here) |
| `directives` | string | `""` | Inline SecLang loaded in the same position, at most 1 MiB |
| `json_schemas` | list | `[]` | JSON body schemas enforced before the rules; see below |

A profile needs at least one of `crs`, `directive_files` or `directives`.

### waf.profiles[].json_schemas[]

A schema binds a JSON Schema document to request paths. A matching
request's JSON body is buffered (bounded by `waf.request_body_limit`,
413 above it), validated and then handed to the rules unchanged. In
`block` mode a violation is denied with 400, reason `waf`, detail
`json_schema:<name>:<first problem>` and a JSON problem body listing up
to twenty issues; in `detect` mode it is logged (`waf_schema`,
`waf_schema_issue`) and the request continues. The evaluator is the
one the `openapi` filter uses: types, enums, constants, string
lengths, patterns and formats, numeric bounds, array and object
bounds, `properties`, `patternProperties`, `additionalProperties`,
`allOf`, `anyOf`, `oneOf`, `not` and local `$ref`.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | name | required, unique in the profile | |
| `paths` | list of prefixes | required | Request path prefixes the schema applies to; the first schema whose method and prefix match wins |
| `methods` | list | `[POST, PUT, PATCH]` | Upper-case methods enforced |
| `schema_file` | path | required | JSON Schema document, JSON or YAML, at most 8 MiB, read at load and on reload |
| `required` | bool | `false` | Refuse a matching request without a body (400) or with a non JSON media type (415); otherwise such requests pass to the rules unchecked |

### routes[].honeypot

A honeypot route answers with a decoy that looks like the real thing
(a WordPress login, a leaked `.env`, a `.git/config`) and records the
client: a `honeypot` security event with the full request line, a mark
on the address for `mark` so that its later requests on every route are
logged with `honeypot_marked: true` and reach filters as
`Info.HoneypotMarked`, and a count towards the `honeypot` ban reason.
Nothing is proxied. Put honeypots on paths no legitimate client uses.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `decoy` | name | `admin-login` when nothing else is set | Built-in body, below; it sets the content type too |
| `body` | string | | Inline decoy, at most 64 KiB; exclusive with `decoy` and `body_file` |
| `body_file` | path | | Decoy read at load and on reload (a missing file fails the reload), at most 1 MiB |
| `status` | int | `200` | Response status |
| `content_type` | string | `text/html; charset=utf-8` | For `body` and `body_file` |
| `delay` | duration | `0` | Hold the connection before answering, in a tarpit slot (`max_tarpits`), never in a request slot; at most 60s |
| `mark` | duration | `1h` | How long the client stays marked; at most 720h. An explicit `0s` marks nobody, which is what a decoy served honestly (`robots`, `sitemap`) wants: reading it is what a crawler is meant to do, and asking for what it names is a different route |

The built-in decoys, each a plausible page for the thing a scanner is
looking for and each containing nothing an operator would mind being
read — every credential, key and host name in them is visibly fake, and
a test refuses a decoy that hands out a password, a token or a key
without a marker that says so:

**PHP and WordPress**

| Decoy | Looks like | Typical bait path |
|-------|-----------|-------------------|
| `wp-login` | A WordPress login page | `/wp-login.php` |
| `wp-config` | `wp-config.php` served as text | `/wp-config.php`, `/wp-config.php.bak` |
| `wp-users` | The `wp-json` user list, which is how usernames leak | `/wp-json/wp/v2/users` |
| `phpmyadmin` | A phpMyAdmin login | `/phpmyadmin`, `/pma` |
| `adminer` | An Adminer login, server and database prefilled | `/adminer.php`, `/adm.php` |
| `phpinfo` | `phpinfo()` output | `/phpinfo.php`, `/info.php` |

**Generic and leaked files**

| Decoy | Looks like | Typical bait path |
|-------|-----------|-------------------|
| `admin-login` | A generic administration login | `/admin`, `/administrator` |
| `env` | A Laravel `.env` | `/.env`, `/.env.production` |
| `git-config` | A `.git/config` with an internal remote | `/.git/config` |
| `htpasswd` | An `.htpasswd` | `/.htpasswd` |
| `backup-sql` | A MySQL dump with a users table | `/backup.sql`, `/dump.sql` |
| `s3-listing` | An S3 bucket listing of nightly backups | `/backups/` |
| `laravel-log` | An application log with a stack trace and a password in it | `/storage/logs/laravel.log` |
| `robots` | A `robots.txt` pointing at the paths above | `/robots.txt` |

**Secrets and build files**

The files a laptop or a build agent leaves in a deployment. Nothing
links to them, so a request is never a browser.

| Decoy | Looks like | Typical bait path |
|-------|-----------|-------------------|
| `aws-credentials` | An `~/.aws/credentials` | `/.aws/credentials` |
| `ssh-key` | An OpenSSH private key block (it decodes to a message saying so) | `/.ssh/id_rsa` |
| `kubeconfig` | A kubeconfig with a token | `/.kube/config` |
| `docker-compose` | A compose file with database credentials | `/docker-compose.yml` |
| `npmrc` | An `.npmrc` with a registry auth token | `/.npmrc` |
| `pypirc` | A `.pypirc` with an upload token | `/.pypirc`, `/.netrc` |
| `gitlab-ci` | A CI pipeline with a deploy token and a target host | `/.gitlab-ci.yml` |
| `terraform-state` | A `terraform.tfstate` with sensitive outputs | `/terraform.tfstate` |
| `vscode-sftp` | An editor's SFTP profile with host, user and password | `/.vscode/sftp.json` |
| `appsettings` | An ASP.NET `appsettings.json` with a connection string | `/appsettings.json` |
| `database-yml` | A Rails `config/database.yml` | `/config/database.yml` |
| `nginx-config` | An `nginx.conf` with an internal location and a token | `/nginx.conf` |

**Cloud and orchestration APIs**

A request for one of these on a public proxy is usually a server side
request forgery probe rather than a path scan: the client is asking the
proxy to fetch its own credentials. Mark these hard.

| Decoy | Looks like | Typical bait path |
|-------|-----------|-------------------|
| `imds` | Instance metadata handing out role credentials | `/latest/meta-data/iam/security-credentials/…` |
| `consul` | A Consul service catalogue | `/v1/catalog/services` |
| `vault` | A Vault seal status | `/v1/sys/seal-status` |
| `docker-api` | The Docker daemon's container list | `/containers/json` |
| `kubelet` | An unauthenticated kubelet's pod list, environment and all | `/pods` |
| `gcp-metadata` | A Google metadata server handing out a service account token | `/computeMetadata/v1/instance/service-accounts/default/token` |
| `azure-imds` | An Azure instance metadata document | `/metadata/instance?api-version=2021-02-01` |

**Data stores and dashboards**

| Decoy | Looks like | Typical bait path |
|-------|-----------|-------------------|
| `elasticsearch` | An Elasticsearch root document | `/_cluster/health`, `/` on port 9200 |
| `couchdb` | A CouchDB database list | `/_all_dbs` |
| `solr` | A Solr core listing with document counts | `/solr/admin/cores` |
| `rabbitmq` | A RabbitMQ management overview | `/api/overview` |
| `kibana` | A Kibana bootstrap page | `/app/kibana` |
| `grafana` | A Grafana bootstrap page | `/grafana` |
| `prometheus-config` | A Prometheus scrape config carrying credentials | `/api/v1/status/config` |
| `traefik` | A Traefik router dump with a basic auth hash | `/api/rawdata` |
| `clickhouse` | A ClickHouse database list | `/?query=SHOW%20DATABASES` |
| `minio` | An S3 compatible AccessDenied naming a backup bucket | `/example-backups`, `/minio/health/live` |
| `jupyter` | A Jupyter notebook token prompt | `/tree`, `/lab` |
| `ollama` | A model server listing the models it has pulled | `/api/tags` |

**Application servers and internals**

| Decoy | Looks like | Typical bait path |
|-------|-----------|-------------------|
| `tomcat-manager` | The Tomcat manager application listing | `/manager/html` |
| `jenkins` | A Jenkins sign-in page | `/jenkins`, `/login?from=%2F` |
| `actuator` | A Spring Boot actuator index, `heapdump` and all | `/actuator` |
| `swagger` | An OpenAPI document naming tempting operations | `/swagger.json`, `/v2/api-docs` |
| `graphql` | An introspection reply naming an impersonate mutation | `/graphql`, `/graphiql` |
| `debug-vars` | Go `expvar` output | `/debug/vars` |
| `server-status` | Apache `mod_status` | `/server-status` |
| `webshell` | A web shell someone else supposedly left | `/shell.php`, `/up.php`, `/cmd.php` |
| `weblogic` | The WebLogic administration console login | `/console/login/LoginForm.jsp` |
| `jboss` | A WildFly management console with deployments | `/console/`, `/jmx-console/` |
| `coldfusion` | A ColdFusion administrator login | `/CFIDE/administrator/index.cfm` |
| `aspnet-trace` | `trace.axd` listing recent requests and the physical path | `/trace.axd` |
| `web-config` | An IIS `web.config` with a connection string | `/web.config`, `/web.config.bak` |
| `xmlrpc` | The WordPress XML-RPC method list, `pingback.ping` and all | `/xmlrpc.php` |
| `registry-catalog` | A container registry catalogue | `/v2/_catalog` |
| `argocd` | An Argo CD sign-in page | `/applications`, `/api/v1/session` |
| `keycloak` | A Keycloak realm login | `/realms/master/account`, `/auth/` |
| `sitemap` | A sitemap that lists the decoy paths, like `robots` | `/sitemap.xml` |

**Enterprise front doors**

The login pages a mass scanner fingerprints before it picks an exploit.
Answering costs the scanner a round trip and tells the proxy which
product it came shopping for.

| Decoy | Looks like | Typical bait path |
|-------|-----------|-------------------|
| `confluence` | An Atlassian Confluence login | `/login.action` |
| `gitlab-login` | A GitLab sign-in page | `/users/sign_in` |
| `citrix` | A Citrix Gateway logon page | `/vpn/index.html`, `/cgi/login` |
| `fortinet` | A FortiGate SSL-VPN login | `/remote/login` |
| `esxi` | A VMware ESXi host client login | `/ui/` |
| `exchange-autodiscover` | An Exchange autodiscover reply naming internal hosts | `/autodiscover/autodiscover.xml` |
| `idrac` | A server lights-out controller login | `/login.html` on a management name |
| `webmail` | A webmail login | `/webmail`, `/roundcube` |
| `cgi-bin` | An embedded router or appliance CGI page | `/cgi-bin/mainfunction.cgi`, `/cgi-bin/luci` |
| `ivanti` | A Secure Access (Pulse) VPN sign-in page | `/dana-na/auth/url_default/welcome.cgi` |
| `nextcloud` | A Nextcloud login | `/nextcloud/login`, `/login` |
| `cpanel` | A cPanel login | `/cpanel`, `/whm` |
| `printer` | A network printer status page with toner and page counts | `/hp/device/info_config`, `/printer` |
| `camera` | An IP camera device information document | `/ISAPI/System/deviceInfo`, `/onvif/device_service` |

Source control, build and artefact servers — what a scanner wants is
the credentials inside them, not the service:

| Decoy | Looks like | Typical bait path |
|-------|-----------|-------------------|
| `gitea` | A Gitea sign-in page with its version | `/user/login`, `/gitea` |
| `teamcity` | A TeamCity login with its build number | `/login.html`, `/teamcity` |
| `nexus` | A Sonatype Nexus component listing naming internal artefacts | `/service/rest/v1/components`, `/nexus` |
| `svn-entries` | A Subversion working-copy entries file naming the repository | `/.svn/entries`, `/.svn/wc.db` |
| `idea-workspace` | A JetBrains workspace file with run configurations | `/.idea/workspace.xml` |

Container and cluster management, which mining crawlers scan in bulk:

| Decoy | Looks like | Typical bait path |
|-------|-----------|-------------------|
| `portainer` | A Portainer status document | `/api/status`, `/portainer` |
| `rancher` | A Rancher cluster collection | `/v3/clusters`, `/rancher` |
| `etcd` | An etcd v2 key listing | `/v2/keys`, `/v2/keys/?recursive=true` |
| `nomad` | A Nomad job listing | `/v1/jobs` |
| `spark` | An Apache Spark master page with workers and cores | `/spark`, `/proxy` |
| `hadoop-yarn` | A YARN ResourceManager cluster info document | `/ws/v1/cluster/info`, `/ws/v1/cluster/apps` |
| `airflow` | An Apache Airflow sign-in page | `/airflow`, `/login/` |

Database consoles and analytics front ends:

| Decoy | Looks like | Typical bait path |
|-------|-----------|-------------------|
| `pgadmin` | A pgAdmin 4 login | `/pgadmin`, `/pgadmin4` |
| `mongo-express` | A mongo-express database listing | `/mongo-express`, `/db/admin/` |
| `metabase` | A Metabase session properties document with its version | `/api/session/properties`, `/metabase` |
| `superset` | An Apache Superset sign-in page | `/superset`, `/superset/welcome` |
| `zabbix` | A Zabbix sign-in page | `/zabbix`, `/zabbix.php` |

Content management systems, which are fingerprinted by version before
anything is attempted against them:

| Decoy | Looks like | Typical bait path |
|-------|-----------|-------------------|
| `joomla` | A Joomla administrator login | `/administrator/`, `/administrator/index.php` |
| `drupal` | A Drupal login with its generator meta tag | `/user/login`, `/core/CHANGELOG.txt` |
| `magento` | A Magento admin sign-in page | `/admin`, `/downloader` |
| `moodle` | A Moodle login | `/moodle`, `/login/index.php` |
| `zimbra` | A Zimbra web client sign-in page | `/zimbra`, `/zimbra/public` |

Firewalls and remote access gateways, fingerprinted in bulk before an
exploit is chosen:

| Decoy | Looks like | Typical bait path |
|-------|-----------|-------------------|
| `pfsense` | A pfSense login naming the gateway | `/index.php` on a gateway name |
| `sonicwall` | A SonicWall SMA login with its domain selector | `/cgi-bin/userLogin`, `/sonicwall` |
| `paloalto` | A GlobalProtect portal login | `/global-protect/login.esp`, `/global-protect/portal` |
| `cisco-asa` | An AnyConnect SSL VPN logon page | `/+CSCOE+/logon.html`, `/+webvpn+/index.html` |
| `mikrotik` | A RouterOS webfig login with its version | `/webfig`, `/jsproxy` |

Framework debug consoles and the probes that hunt them. These are the
clearest signal in the set: nothing but a scanner asks for a debugger.

| Decoy | Looks like | Typical bait path |
|-------|-----------|-------------------|
| `werkzeug-console` | A Werkzeug interactive debugger asking for its PIN | `/console`, `/?__debugger__=yes` |
| `symfony-profiler` | A Symfony profiler with recent requests | `/_profiler`, `/_profiler/latest` |
| `laravel-telescope` | A Laravel Telescope entry listing | `/telescope/requests`, `/telescope` |
| `thinkphp` | A ThinkPHP fatal error naming the version | `/index.php?s=/index/think\app/invokefunction` |
| `phpunit-eval` | A PHPUnit `eval-stdin.php` parse error | `/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` |
| `spring-gateway` | A Spring Cloud Gateway route listing naming internal hosts | `/actuator/gateway/routes` |

Files a traversal or a misconfigured server hands over. Each is what
the probe expects to see, and each is a good place for a honeytoken:

| Decoy | Looks like | Typical bait path |
|-------|-----------|-------------------|
| `etc-passwd` | A Unix password file with a deploy account | a traversal probe, e.g. `/download?file=../../etc/passwd` |
| `firebase-config` | A front-end Firebase configuration with keys | `/firebase-config.js`, `/static/js/firebase.js` |
| `wp-json-users` | A WordPress REST user listing | `/wp-json/wp/v2/users` |
| `dockerfile` | A Dockerfile with a build argument and internal hosts | `/Dockerfile`, `/docker/Dockerfile` |
| `rails-secrets` | A Rails secrets file with a database URL | `/config/secrets.yml`, `/config/database.yml` |

**Mail, messaging and remote access** — the surfaces the smtp, mqtt and
ssh listeners put on the network have their own scanners, and their own
habit of leaving configuration files where a web server can reach them:

| Decoy | Looks like | Typical bait path |
|-------|-----------|-------------------|
| `roundcube` | A Roundcube webmail login with its version | `/roundcube/`, `/mail/` |
| `postfixadmin` | A PostfixAdmin login | `/postfixadmin/login.php` |
| `smtp-config` | A Postfix `main.cf` with a relay credential | `/main.cf`, `/etc/postfix/main.cf` |
| `dovecot-users` | A Dovecot passwd-file with hashes | `/dovecot/users`, `/etc/dovecot/users` |
| `mail-queue` | A mail queue listing naming partners and deferrals | `/api/queue`, `/mailq.json` |
| `emqx-dashboard` | An EMQX broker dashboard login | `/dashboard/`, `/api/v5/login` |
| `mosquitto-conf` | A `mosquitto.conf` with a bridge password | `/mosquitto.conf`, `/config/mosquitto.conf` |
| `mqtt-clients` | A broker's connected-client listing | `/api/v5/clients`, `/api/clients` |
| `mqtt-acl` | A broker ACL file naming the topic tree | `/aclfile`, `/etc/mosquitto/aclfile` |
| `teleport` | A Teleport proxy page with its cluster name | `/web/login`, `/webapi/ping` |
| `guacamole` | An Apache Guacamole login naming guacd | `/guacamole/`, `/guacamole/api/tokens` |
| `authorized-keys` | An `authorized_keys` file with forced commands | `/.ssh/authorized_keys` |
| `known-hosts` | A `known_hosts` file naming internal hosts | `/.ssh/known_hosts` |
| `sshd-config` | An `sshd_config` with an sftp chroot block | `/sshd_config`, `/etc/ssh/sshd_config` |
| `sftp-audit` | An SFTP server log showing transfers and paths | `/logs/sftp.log`, `/var/log/sftp.log` |
| `openvpn-config` | A client `.ovpn` profile with inline blocks | `/client.ovpn`, `/vpn/config.ovpn` |
| `wireguard-conf` | A `wg0.conf` with peers | `/wg0.conf`, `/etc/wireguard/wg0.conf` |
| `filezilla-sites` | A FileZilla site manager with saved logins | `/sitemanager.xml`, `/filezilla.xml` |
| `winscp-ini` | A WinSCP session file with saved passwords | `/WinSCP.ini`, `/winscp.ini` |
| `vsftpd-conf` | A `vsftpd.conf` with passive ports and TLS paths | `/vsftpd.conf`, `/etc/vsftpd.conf` |
| `rsync-modules` | An `rsyncd.conf` naming backup modules | `/rsyncd.conf`, `/etc/rsyncd.conf` |
| `webmin` | A Webmin login naming the host | `/session_login.cgi`, `/webmin/` |
| `cockpit` | A Cockpit login naming the host and distribution | `/cockpit/login`, `/cockpit/` |


`robots` and `sitemap` are the two to serve honestly: they name the
decoy paths, so a crawler that reads either and then requests them has
told you what it is. Give those two `mark: 0s`, so that reading the
file marks nobody and only asking for what it names does.
`examples/security/honeypots.yaml` wires the whole table up, one route
per decoy with the paths each is worth serving on; a test fails if a
decoy in the table has no route there. `xproxyctl honeypot` and
`GET /v1/honeypot` both list the names this build carries, which is the
authority when a configuration is refused for an unknown decoy.

`response_headers` apply, so a decoy can carry a `Server` header of its
own. `GET /v1/honeypot` lists marked clients (address, route, hits,
first, last, expires) and the decoy names; `DELETE /v1/honeypot?ip=` and
`xproxyctl honeypot forget IP` remove a mark. The mark table holds at
most 65536 addresses. Counters: `honeypot_hits`, `honeypot_marked`;
metrics `xproxy_honeypot_hits_total`, `xproxy_honeypot_marked`.

### routes[].websocket_guard

An upgraded connection is the one place a request-oriented proxy stops
looking. Everything before the 101 goes through routing, the WAF, the
filters and the logs; everything after it is an opaque byte stream that
happens to be travelling over a connection the proxy opened.
Applications put their real API in there — chat, trading, terminals,
GraphQL subscriptions — so a proxy that stops at the handshake is
guarding the doorway of a building with no walls.

`websocket_guard` parses RFC 6455 frames in **both** directions and
applies structure, bounds and patterns. It never rewrites a frame: a
violation closes the connection with a close code that says why, or is
only recorded, depending on `action`.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `max_frame_bytes` | int | `1048576` | Largest single frame, either direction; 128 to 64 MiB |
| `max_message_bytes` | int | `8388608` | Largest reassembled message; at least `max_frame_bytes`, at most 256 MiB |
| `messages_per_second` | int | `0` (no bound) | Client message rate; the origin is the estate's own application and is not rate limited |
| `allow_opcodes` | list | text, binary, close, ping, pong | Opcodes a peer may use; continuation is always allowed |
| `allow_subprotocols` | list | any | The `Sec-WebSocket-Protocol` the origin may negotiate, checked on the 101 before any frame exists |
| `require_masked` | bool | `true` | Enforce RFC 6455 masking: set on client frames, clear on server frames |
| `validate_utf8` | bool | `true` | Refuse a text message that is not UTF-8 |
| `inspect` | `none`, `text`, `all` | `text` | Which messages are kept for pattern matching |
| `max_inspect_bytes` | int | `65536` | Prefix of a message kept for matching; the rest passes uninspected |
| `deny_patterns` | list of RE2 | `[]` | Patterns matched against inspected messages |
| `action` | `close`, `log` | `close` | Close the connection, or record and forward |
| `close_code` | int | protocol's own | Override the close code; 3000-4999 only |

The structural checks are the half with no false positives, because
they are the protocol's own rules: a reserved bit set without a
negotiated extension, a reserved opcode, an unmasked client frame or a
masked server one, a fragmented or oversize control frame, a
continuation with nothing to continue, a new message before the
previous one finished, a close frame with one byte of status, a close
code that must never appear on the wire, a close reason or text message
that is not UTF-8. A client that does any of these is not a browser.

The bounds are the half worth thinking about: `max_frame_bytes` and
`max_message_bytes` are what stop one connection deciding how much
memory the proxy uses, and `messages_per_second` is what stops it
deciding how much CPU the origin uses. The pattern list is the part
with a real false-positive rate — start with `action: log` and read
`xproxy_websocket_violations_total{route}` for a week.

Messages larger than `max_inspect_bytes` are checked up to that bound
and forwarded: the alternative is buffering whatever a client chooses
to send. Compressed frames (`permessage-deflate`) cannot be inspected
at all, which is why a reserved bit is refused rather than ignored — a
negotiated compression extension would silently turn every check off.

Violations are security events with reason `websocket`, counted per
route by `xproxyctl` and `GET /v1/websocket`, and exported as
`xproxy_websocket_violations_total` and `xproxy_websocket_closed_total`.

### routes[].deceive

A refusal is information. A scanner that gets 403 has learned that the
request it sent was the interesting one, and it will vary that request
until something is not refused — the refusal is the oracle that tells
it when it has found the way through. `deceive` answers a client the
route no longer trusts with something ordinary instead: the crawl
completes, the data is wrong, and the request that would have worked
looks exactly like the one that did not.

The origin is never asked, so a deceived write is discarded. That is
the point for a `POST`, and it is why the conditions are worth being
sure of: a false positive means a real client quietly loses data.

```yaml
routes:
  - name: api
    paths: [/api]
    upstream: app
    deceive:
      marked: true            # a honeypot or honeytoken marked it
      bot_score_at: 80        # or a bot_score filter scored it
      status: 200
      body: '{"items":[],"total":0}'
      content_type: application/json
      mark: 1h                # keep it on the same answer
```

A route must name at least one condition; validation refuses a
`deceive` block that would admit everyone, and warns on every route
that has one, because this is the one control whose failure looks like
success.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `marked` | bool | `false` | Admit a client a honeypot route or a honeytoken marked |
| `bot_score_at` | int | `0` | Admit a request a `bot_score` filter scored at or above this; `0` does not look at the score |
| `client_cidrs` | list of CIDR | | Admit these client networks |
| `methods` | list | any | Narrow the deception to these methods |
| `status` | int | `200` | The answer. A 4xx tells the client what a refusal tells it, which is what deceiving was for; validation says so |
| `decoy` | name | | A built-in decoy body (the table above) |
| `body` | string | `{}` | A literal body, at most 64 KiB |
| `body_file` | path | | A body read at load and on reload, at most 1 MiB |
| `content_type` | string | `application/json` for the default body, else `text/html; charset=utf-8` | Content type of `body` and `body_file`; a decoy brings its own |
| `mark` | duration | `0` | Mark the client for this long, so it keeps getting the same answer rather than seeing the endpoint change its mind |

Every deceived request is loud on the inside and silent on the
outside: `deceived: <route>` in the access log, a `deceive` security
event with the client, path and method, the `deceived` counter,
`xproxy_deceived_total{route}` and `GET /v1/deceive`. Nothing is added
to the response — no header, no marker — because anything added is the
tell.

`deceive` and `honeypot` on the same route are refused: a honeypot
already answers everyone with a decoy.

### routes[].mirror

A mirrored route sends a copy of each request (sampled by `percent`) to
another upstream in the background while the live request proceeds as
usual. The copy is built like the live outbound request (path rules,
`host_header`, forwarding headers, `request_headers`) and carries
`X-Xproxy-Mirror: 1` and the same `X-Request-Id`; its response is read
and discarded, so a slow, failing or absent mirror never changes what
the client sees. Bodies are buffered up to `max_body_bytes` so that
both requests can read them; larger requests are proxied and not
mirrored. Upgrade requests are never mirrored. Only routes with an
`upstream` can mirror.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `upstream` | name | required | Receives the copies; must differ from the route's upstream |
| `percent` | int | `100` | Share of requests copied, 1 to 100 |
| `methods` | list | `[]` (all) | Upper-case tokens; copies are limited to these methods |
| `max_body_bytes` | int | `1048576` | Largest body buffered for mirroring; at most 64 MiB |
| `timeout` | duration | `5s` | Bound on the copy including its response; at most 5m |
| `max_in_flight` | int | `64` | Copies in flight for this route; beyond it copies are dropped and counted |
| `diff` | object | none | Compare the shadow response with the live one and report the differences; see below |

The access log carries `mirror: sent`, `dropped` or `body_too_large`.
Counters: `mirror_sent`, `mirror_dropped`, `mirror_skipped`,
`mirror_failed`; metric `xproxy_mirror_total{outcome}`. Mirror
responses appear in the error log at debug level with their status.

#### routes[].mirror.diff

Turns the mirror into traffic shadowing for validating a new backend
against the current one. The live response is summarised as it streams to
the client — status, the listed headers, body length and a digest of the
first `max_body_bytes` — without buffering it, and the shadow response is
summarised the same way; the two are compared once the client has finished
reading. The status is always compared, then the listed headers, then the
body; the first category that differs is the reported result. Comparison
runs in the background and never affects the client. When the live response
does not finish within the mirror `timeout`, the comparison is skipped.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `sample_percent` | int | `100` | Share of differing exchanges whose detail is logged; the metric counts every comparison |
| `headers` | list | `[]` | Response header names compared between the two responses (pick stable ones; `Date`, `ETag` and the like differ legitimately). Values of cookie, authorization and token headers are never written to the log, only that they differ |
| `max_body_bytes` | int | `65536` | Bytes of each body digested for the comparison; at most 64 MiB |

Outcomes are counted in `xproxy_mirror_diff_total{result}` with `result` one
of `match`, `status`, `header` or `body`, and differences are logged (sampled)
in the error log with the request id, route, result and a short detail.

### routes[].static

A `static` route serves files from a directory: assets next to an
application, a maintenance page, a single page application. The request
path after `strip_prefix` or `rewrite_path` selects the file. Files are
opened through `os.Root`, so neither `..` (removed earlier by path
cleaning) nor a symbolic link pointing outside the root can leave it;
names starting with a dot (`.env`, `.git`) are refused unless
`dot_files` is set; anything that is not a regular file or directory
answers 404, as does every failure to open, so the tree's shape leaks
nothing. `GET` and `HEAD` only (405 otherwise). Responses carry a weak
`ETag` from size and modification time, honour `If-None-Match`,
`If-Modified-Since` and `Range`, and set the content type from a fixed
table for the common web types (`text/javascript`, `text/css`,
`image/svg+xml`, `application/wasm`, ...) with `X-Content-Type-Options:
nosniff`. A directory without a trailing slash redirects to it (301),
then serves `index`, then a listing when enabled, else 404. The route's
admission pipeline (bans, limits, ACLs, WAF, filters) applies before the
file is opened, and `response_headers` apply to every answer.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `root` | path | required | Absolute directory; must exist at load (a missing root fails the reload and the previous generation keeps serving) |
| `index` | file name | `index.html` | Served for a directory; `""` disables |
| `listing` | bool | `false` | Render a directory without an index as an HTML list (dot files hidden unless `dot_files`) |
| `fallback` | path | none | File inside the root served when the requested one does not exist, for single page applications (`/index.html`); assets that do exist are served as themselves |
| `cache_control` | string | none | Sent as `Cache-Control` with every file |
| `dot_files` | bool | `false` | Serve names starting with a dot |
| `max_file_bytes` | int | `0` (no bound) | Larger files answer 404 |

`cache`, `mirror`, `grpc` and `websocket` cannot be combined with
`static`.

### routes[].doh

A `doh` route answers DNS over HTTPS (RFC 8484) for clients: `GET`
with the query in the `dns` parameter (base64url without padding) or
`POST` with an `application/dns-message` body. The query goes through
the named `kind: dns` listener's policy and cache (bans, client allow
list, rate limit, block list) as if it had arrived over UDP, and the
answer is returned as `application/dns-message` with `Cache-Control:
max-age` set to the smallest TTL in it. A query the policy drops
answers 403; bad requests 400, a wrong content type 415, other methods
405. The route's own admission pipeline (rate limits, ACLs, WAF) applies
first, so a DoH endpoint can be limited like any other route.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `listener` | name | required | A `kind: dns` listener whose policy and cache answer |

The access log line carries `dns_rcode`.

### routes[].grpc

A route with a `grpc` section matches only gRPC requests (content type
`application/grpc` or `application/grpc+...`), and with lists only the
named services or `Service/Method` pairs read from the request path
(`/package.Service/Method`). Among routes of equal path length and
priority, one with named services wins over one with an empty `grpc`
section, which wins over a plain route, so a gRPC catch-all and an
HTTP catch-all can share `/`. Only routes with an `upstream` can match
gRPC. Requests and responses stream through unchanged with their
trailers; the client's `grpc-timeout` header tightens the route
`timeout`. When the proxy cannot forward a gRPC request it answers as a
gRPC client expects, a trailers-only response with HTTP 200 and a
`grpc-status`: 7 PERMISSION_DENIED for 403, 16 UNAUTHENTICATED for
401, 12 UNIMPLEMENTED for no route, 8 RESOURCE_EXHAUSTED for rate and
size limits, 14 UNAVAILABLE for no healthy endpoint or a connection
error, 4 DEADLINE_EXCEEDED for a timeout, 13 INTERNAL otherwise, with
the proxy's own status in `grpc-message`.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `services` | list | `[]` | Fully qualified service names, `package.Service` |
| `methods` | list | `[]` | `package.Service/Method` pairs |

The access log carries `grpc: true` and `grpc_status` from the
response; `xproxy_grpc_responses_total{code}` counts responses by
status. gRPC needs HTTP/2 end to end: a TLS listener with `h2`, or a
plaintext listener with `h2c: true`, and an `https` or `h2c` upstream.

### routes[].waf

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `mode` | `off`, `detect`, `block` | `waf.default_mode` | `detect` logs what `block` would have done |
| `profile` | name | `waf.default_profile` | |
| `block_percent` | int | `100` | With `mode: block`, the share of clients that get block mode; the rest get detect mode. The choice is a stable function of the client address, so one client always sees one behaviour. `0` with `block_cidrs` is a test mode: only the canaries are enforced |
| `block_cidrs` | list of CIDRs | `[]` | Clients always in block mode whatever the share (internal testers, a pilot customer) |

Gradual roll-out: detect everywhere, then `block_percent: 0` with the
testers in `block_cidrs`, then raise the share in steps while the
security log's `waf_detected` entries (the requests detect mode would
have blocked) stay explainable, then `100`. `xproxyctl waf` shows the
share and the canary prefixes per route, and the access log carries
`waf_enforced: true` or `false` for every request of such a route.

## degradation

Present means suspect clients are served slowly instead of being
refused.

Every other answer in this file is binary: a client is served, or it is
refused. For a client that has done something wrong but not enough to
ban — touched a decoy, scored badly, arrived from a range with a
history — both are wrong. Serving it in full funds the next request.
Refusing it tells it exactly which request to change, and hands a
scanner a clean signal to tune against: it will try variations until
one is not refused, and the refusal tells it when it has found one.

A degraded client is served, correctly, slowly. The page arrives, so
there is nothing to report as broken and nothing to tune against; it
arrives at eight kilobytes a second on a connection that cannot be
reused, so a crawl that cost the scanner nothing now costs it the one
thing it has least of.

Levels are tried in order and the first that admits the request
decides, so the narrowest goes first.

```yaml
degradation:
  levels:
    # A client a honeypot or a honeytoken marked: slow, held, and no
    # keep-alive.
    - name: marked
      marked: true
      bytes_per_second: 8192
      delay: 500ms
      close: true

    # A high bot score, on the endpoints worth scraping.
    - name: likely-bot
      bot_score_at: 60
      routes: [catalogue, search]
      bytes_per_second: 65536

    # A range with a history, on writes only.
    - name: known-range
      client_cidrs: ["203.0.113.0/24"]
      methods: [POST, PUT, PATCH]
      delay: 2s
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `levels` | list | required | At least one, at most 64 |

### degradation.levels[]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | string | `levels[i]` | Names the level in the access log (`degraded`), the metric label and `GET /v1/degradation` |
| `marked` | bool | `false` | Admit a client a honeypot route or a honeytoken marked |
| `bot_score_at` | int | `0` | Admit a request a `bot_score` filter scored at or above this; `0` does not look at the score. Validation warns when no `bot_score` filter is configured |
| `client_cidrs` | list of CIDR | any | Narrow the level to these client networks |
| `routes` | list of names | any | Narrow it to these routes |
| `methods` | list | any | Narrow it to these methods |
| `bytes_per_second` | int | `0` | Shape the response body to this rate, flushing as it goes so the client sees a slow link rather than a late buffer. `0` leaves it alone; otherwise at least 256 and at most 1 GiB/s |
| `delay` | duration | `0` | Hold the response this long before writing it. Spent in a tarpit slot, not a request slot, so held responses do not consume the concurrency sold to everyone else; when no tarpit slot is free the response is served without the delay. At most 60s |
| `close` | bool | `false` | End the connection after the response, so the client pays for a new one — and a new TLS handshake — every time |

A level must name at least one condition or selector, and must do at
least one of the three things; validation refuses a level that would
degrade every request, and one that degrades nothing.

The effects are observable, which is the point: a degraded response is
a correct response. `degraded: <level>` appears in the access log line,
`xproxy_degraded_total{level}` counts them, and the `degraded` counter
is in the stats. Nothing is added to the response for the client to
read.

## handshake

Present means the proxy can refuse a client before its TLS handshake
completes.

Everything else in this file answers a request: the handshake runs, a
certificate is chosen, keys are agreed, the request is parsed, and then
the proxy says no. For a client already known to be unwelcome that is a
key exchange spent on a refusal — and an answer a scanner can read off:
a status, a page, a header set, a certificate, a supported cipher list.
Refusing in the ClientHello costs one hello and gives back a failed
negotiation, which says nothing.

It applies to every TLS listener, HTTP/3 included, and to nothing else:
a plain HTTP listener has no handshake, and what arrives there is
refused the ordinary way.

```yaml
handshake:
  # A client already on the ban list never gets a handshake.
  refuse_banned: true
  # Fingerprints refused outright, whatever the ban list says: a
  # scanner whose TLS stack is its signature.
  deny_fingerprints:
    - "t13d1516h2_8daaf6152771_02713d6af862"   # JA4, exact
    - "ja4:t13d31*"                            # a JA4 prefix: the family
    - "ja3:579ccef312d18482fc42e2b822ca2430"   # a JA3 hash
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `refuse_banned` | bool | `false` | Refuse a client whose address or TLS fingerprint is on the ban list. Requires a `bans` section |
| `deny_fingerprints` | list | `[]` | TLS fingerprints refused outright. An entry is a JA4 or JA3 string, or one prefixed `ja4:`/`ja3:` to say which it is; a JA4 entry ending in `*` matches by prefix, which names a family of clients without pinning every extension order. At most 4096 entries |
| `log` | bool | `true` | Record each refusal in the security log as reason `handshake`, with the detail (`banned` or `fingerprint`), the client address and both fingerprints |

**What you give up.** A refused connection never becomes a request, so
it is not in the access log, it has no request id, and no route, WAF
profile or filter ever sees it. That is the trade: the cheapest and
quietest refusal is also the one with the least to look at afterwards.
Validation says so as advice when `refuse_banned` is on. The security
log and `xproxy_tls_handshakes_refused_total` are what remain, and
`xproxyctl tls` prints the policy and its count above the certificates.

Fingerprints are not identities. A JA4 names a TLS stack and its
options, so it groups a scanner's runs together and it groups everyone
using the same library — including, for a common prefix, ordinary
browsers. Deny a full fingerprint you have seen in your own security
log; reach for a prefix only when you have checked what else it
matches. `xproxyctl waf` and the access log's `ja4` field are where to
look before adding one.

## honeytokens[]

A decoy hands out a password, an API key, a connection string. Until
something watches for their *use*, the bait has no hook: the scanner
reads the file and the proxy learns only that the file was read. A
honeytoken closes that. Each entry registers values that were planted
somewhere an attacker will find them — in a decoy this proxy serves, in
a repository, in a paste, in a backup, in a document — and any request
presenting one is refused, counted, logged and (by default) marked.

Nothing legitimate ever sends one. That is what makes this different
from every other control in this file: there is no score to tune and no
false-positive rate to trade against a detection rate. A hit is an
attacker replaying what they read, and the only decision is what to do
about it.

Tokens are checked before routing — a stolen credential can be sent to
any path — and before the challenge, so a scanner replaying one is not
offered a browser challenge. A hit raises reason `honeytoken` with the
token name as `detail`, which the ban triggers accept like any other
reason, and marks the client for `mark` so its later requests carry
`honeypot_marked` exactly as a decoy hit does.

```yaml
honeytokens:
  # The AWS key the `env` decoy serves. Anyone sending it read the
  # decoy and tried the credential.
  - name: env-aws-key
    description: planted in the env decoy
    values: ["AKIADECOY000000EXAMPLE"]

  # A session cookie seeded into a database backup that should never
  # have left the estate. Its use says the backup did.
  - name: backup-session
    description: seeded in the 2026-01 database export
    values: ["s%3Adecoy.0000000000000000000000000000"]
    in: [cookies]

  # A document identifier planted in a report, matched anywhere in a
  # value because the client echoes the whole document back.
  - name: leaked-report-id
    description: embedded in the quarterly report PDF
    values: ["decoy-report-id-0123456789abcdef"]
    match: contains
    in: [headers, query]

  # Values generated elsewhere, one per line.
  - name: paste-keys
    values_file: /etc/xproxy/honeytokens/paste-keys
    action: log
```

Where it looks: `headers` (every header value, and again with a
`Bearer `, `Basic `, `Token ` or `ApiKey ` scheme stripped, and a Basic
credential decoded into its user and password), `cookies` (each cookie
value), `query` (each parameter value, decoded) and `path` (the cleaned
path, and each of its segments). Bodies are not searched: every request
would have to be buffered to do it, and a stolen credential is
presented in the head.

The work per request is bounded, because a client chooses how many
headers it sends: at most 256 candidate strings are examined and a
value over 8 KiB is not scanned for a `contains` token.

**The value is not a secret.** Its purpose is to be read, so it is
compared as an ordinary string and no constant-time comparison is
pretended. What the proxy does protect is the log: a hit names the
token, never the value, so finding a plant does not write the
credential into a second place. Plant real credentials here and the
guarantee is gone.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | identifier | required, unique | `a-z`, `0-9`, `.`, `_`, `-`, at most 63 characters. It is what the logs, the metric label and `xproxyctl honeypot` show instead of the value |
| `description` | string | | Where this one was planted, so the alert names the leak and not only the token; at most 512 characters |
| `values` | list | required unless `values_file` | The planted strings. At least 8 characters (16 for `match: contains`), at most 512, no whitespace, and no value planted twice across the section |
| `values_file` | path | | One value per line; `#` comments and blank lines ignored, at most 4096 values. Read at load and on reload |
| `in` | list | `[headers, cookies, query, path]` | Where to look |
| `headers` | list of names | any | Narrow the header search to these names; requires `headers` in `in` |
| `match` | `exact`, `contains` | `exact` | `exact` compares the whole field value once a credential scheme is stripped; `contains` finds the token anywhere in the value, for a token planted inside a document a client echoes back |
| `action` | `block`, `log` | `block` | `log` records the hit and serves the request — for a token whose plant might also be reached legitimately, until it is proven quiet. Validation advises against leaving it there |
| `status` | int | `403` | Response for `block`; 4xx or 5xx |
| `mark` | duration | `24h` | How long the client stays marked, as a honeypot route marks one. Longer than a decoy's default hour: a stolen credential says more about the client than one probe for a decoy path does. At most 720h; an explicit `0s` marks nobody |
| `enabled` | bool | `true` | `false` keeps the token configured without watching for it |

`GET /v1/honeypot` and `xproxyctl honeypot` list the tokens with their
hits, last hit and where each was planted; `xproxy_honeytoken_hits_total{token}`
counts them and `honeytoken_hits` is in the stats. Hits survive a
reload. A hit is worth an alert on its own — unlike almost everything
else the proxy counts, one is enough.

## security_txt[]

A virtual `security.txt` (RFC 9116): the document that tells a finder
where to report a vulnerability. The proxy answers
`/.well-known/security.txt`, and the legacy `/security.txt`, **before
routing**, so a host with no route of its own still has one — which is
the parked name a finder tries first, and the one that otherwise
answers 404.

Entries are tried in order and the first whose selectors all match
answers, so an entry with no selectors placed last is the fallback for
every other host. A request that matches no entry falls through to
routing, so an origin already serving its own file keeps doing so.

**Selecting who sees which document.** An entry has two independent
kinds of selector, and both must hold for it to answer:

- **Which host was asked for** — `hosts` (exact names and `*.` wildcard
  patterns), `host_regex`, and `host_cidrs` for a `Host` that is an
  address literal rather than a name. These are a *union*: an entry
  answers for a host any one of them names. An entry naming none of
  them answers for every host.
- **Who is asking, and where** — `client_cidrs` (the client's own
  address) and `listeners`. These *narrow*: an entry naming them answers
  only inside them.

That covers the whole range from one host to all of them:

| You want | Write |
|----------|-------|
| One host | `hosts: ["shop.example.com"]` |
| A domain and everything under it | `hosts: ["example.com", "*.example.com"]` |
| Several brands in one document | `hosts: ["a.example.com", "*.b.example.net"]` |
| A naming scheme a wildcard cannot express | `host_regex: '^api[0-9]+\.example\.com$'` |
| A range of addresses, for hosts reached by address | `host_cidrs: ["198.51.100.0/24", "2001:db8:1::/48"]` |
| Every address literal, whatever the range | `host_cidrs: ["0.0.0.0/0", "::/0"]` |
| Every host, name or address | no host selector at all |
| A different document for internal clients | `client_cidrs: ["10.0.0.0/8"]` on an earlier entry |
| A different document on the management listener | `listeners: [mgmt]` on an earlier entry |

`host_cidrs` is the selector for a host a finder reached by address
because no name points at it — a parked address, a range a provider
assigned, a machine found in a range scan. It matches the `Host` header
read as an address, in either family and in either spelling
(`::ffff:198.51.100.7` is the IPv4 address it carries), and it never
matches a name: the proxy does not resolve the `Host` header, and a
document that turned on what a name resolves to would be answering on
the client's word.

```yaml
security_txt:
  # Internal clients get the internal contact.
  - name: internal
    client_cidrs: ["10.0.0.0/8", "fd00::/8"]
    contact: ["mailto:appsec@corp.internal", "https://wiki.corp.internal/appsec"]
    preferred_languages: [en, sv]
    valid_for: 720h
  # One brand.
  - name: shop
    hosts: ["shop.example.com", "*.shop.example.com"]
    contact: ["https://example.com/vdp", "mailto:security@example.com"]
    encryption: ["https://example.com/pgp-key.txt"]
    policy: ["https://example.com/vdp"]
    acknowledgments: ["https://example.com/hall-of-fame"]
    canonical: ["https://shop.example.com/.well-known/security.txt"]
  # The addresses themselves: a scanner that found the machine in a
  # range scan has no name to go on, and is the finder most likely to
  # need somewhere to report.
  - name: parked-addresses
    host_cidrs: ["198.51.100.0/24", "2001:db8:1::/48"]
    contact: ["mailto:security@example.com"]
    comment: "This address is not a service. Reports are still welcome."
  # Everything else, including parked names.
  - name: default
    contact: ["mailto:security@example.com"]
    expires: "2027-01-31T00:00:00Z"
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | string | `security_txt[i]` | Names the entry in `xproxyctl stats`, the access log and the security log |
| `hosts` | list | any host | Exact names or wildcard patterns (`*.example.com`, which matches a label or more and not the bare name) |
| `host_regex` | RE2 | none | Matches the host as well, for a naming scheme a wildcard cannot express; at most 512 bytes |
| `host_cidrs` | list | none | Matches a `Host` that is an address literal, in either family; `0.0.0.0/0` and `::/0` together cover every literal. A `Host` that is a name never matches, whatever it resolves to |
| `client_cidrs` | list | any client | Only clients inside these networks see this entry, so an internal document can differ from the public one |
| `listeners` | list | any listener | Only these listener names serve this entry |
| `contact` | list | required | How to report, most preferred first: `mailto:`, `tel:` or `https:`. RFC 9116 requires at least one, and a `security.txt` with no way to report is worse than none |
| `expires` | RFC 3339 | from `valid_for` | When the document stops being valid. Exclusive with `valid_for`; a value in the past is refused, because a finder is told to ignore an expired document |
| `valid_for` | duration | `8760h` (a year) | Sets `Expires` this far ahead of the load and **refreshes it on every reload**, so the document cannot quietly go stale. 1h to three years |
| `encryption` | list | | A key a finder should encrypt to |
| `acknowledgments` | list | | A page thanking finders |
| `preferred_languages` | list | | BCP 47 tags, rendered as one comma-separated field |
| `canonical` | list | | Where this document is expected to live; it is what makes a copy found elsewhere recognisable as a copy |
| `policy` | list | | The disclosure policy |
| `hiring` | list | | Security job openings |
| `csaf` | list | | A `provider-metadata.json` |
| `extra` | mapping | | Fields this build does not know by name (`{Foo: [bar]}`), rendered after the known ones in name order |
| `comment` | string | | Placed at the top, each line prefixed with `# ` |
| `body` | string | | The document verbatim; exclusive with every field above and with `body_file` |
| `body_file` | path | | Read at load and on **every reload**, at most 64 KiB. Use it for a clear-signed document, which cannot be assembled from fields without breaking the signature |
| `cache_for` | duration | `1h` | `Cache-Control: public, max-age=`; `0` sends no `Cache-Control` |

Field values may not contain a line break or a control character: a
newline would end the field and begin another, so a value carrying one
could add a `Contact` of somebody else's choosing to the document this
proxy serves. The response is `text/plain; charset=utf-8` with
`X-Content-Type-Options: nosniff`, and only `GET` and `HEAD` are
answered — a `security.txt` is a file and nothing else.

The signed form is worth the trouble on a public document: sign it
once, put it in `body_file`, and a reload picks up a re-signed file
without a restart. `valid_for` cannot refresh a signed document, so
give a signed one an explicit `Expires` inside the signature and
re-sign before it lapses; `xproxyctl stats` reports how many requests
each entry answered, which is how you notice a document nobody reads.

## scim

A SCIM 2.0 provisioning endpoint (RFC 7644), so the directory that owns
the joiner and leaver process provisions and deprovisions the
credentials this proxy holds: a second-factor enrolment and an API key.

The point is the leaver. An account closed in the directory and not here
is access that still works, and every estate has a story about the
contractor whose key kept opening the door for a year. Doing it by hand
needs somebody to remember at exactly the moment nobody is thinking
about it; doing it over SCIM means the same event that closes the
mailbox closes this.

```yaml
scim:
  # Where the provider reaches it. The endpoints are this plus /Users,
  # /ServiceProviderConfig, /ResourceTypes and /Schemas.
  path: /scim/v2
  external_url: https://admin.example.com/scim/v2

  # Who may reach it at all. An endpoint that creates and destroys
  # credentials is not left to a route's access list.
  hosts: [admin.example.com]
  listeners: [edge]
  client_cidrs: [203.0.113.0/24]

  token_file: /etc/xproxy/scim.token       # the bearer token, >= 16 characters
  state_file: /var/lib/xproxy/scim-users   # the resources, not the credentials

  mfa_users_file: /etc/xproxy/mfa.users    # a second factor is enrolled here
  keys_file: /etc/xproxy/api-keys          # a key is issued and revoked here
  key_scopes: [orders:read]
  key_ttl: 8760h
  issuer: example-estate                   # named in the otpauth URI

  return_secrets: false                    # see below
  max_results: 100
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `path` | string | `/scim/v2` | The base the endpoints hang off, absolute and without a trailing slash |
| `hosts` | list | `[]` (every host) | Exact names or `*.example.com` patterns the endpoint answers on |
| `listeners` | list | `[]` (every listener) | Listener names it answers on |
| `client_cidrs` | list of CIDR | `[]` (every client) | Networks the provider connects from |
| `token_file` | path | required | The bearer token, one line, at least 16 characters. Compared in constant time against a SHA-256 |
| `state_file` | path | required | Where the provisioned resources are kept. Written by the proxy; it need not exist yet |
| `mfa_users_file` | path | none | The enrolment file a second factor is provisioned in — the same file the `mfa` filter and the gate listeners read |
| `keys_file` | path | none | The API key file a key is issued in and revoked in — the same file the `api_key` filter reads |
| `key_scopes` | list | `[]` | Scopes an issued key gets when the request names none |
| `key_ttl` | duration | none | Expiry of an issued key, 1h to 10 years |
| `issuer` | string | `xproxy` | Names this estate in the `otpauth://` enrolment URI |
| `return_secrets` | bool | `false` | Whether a response may carry the credentials it just made |
| `max_results` | int | `100` | Page bound, reported in the service provider configuration |
| `external_url` | URL | none | The base the provider reaches this endpoint at; what `meta.location` and the `Location` header are built from |

At least one of `mfa_users_file` and `keys_file` is required: with
neither there is nothing to provision.

**What is implemented**, and deliberately nothing else — an endpoint
that half-understands an operation is worse than one that refuses it,
because the directory believes the change landed:

| Request | What happens |
|---------|--------------|
| `POST /Users` | Creates the resource, enrols a second factor, issues a key |
| `GET /Users` | Lists, with `filter=userName eq "name"`, `startIndex` and `count` |
| `GET /Users/{id}` | Reads one, with what is *currently* in place rather than what was provisioned once |
| `PUT /Users/{id}` | Replaces `externalId`, `displayName` and `active` |
| `PATCH /Users/{id}` | `replace` of `active`, `externalId` or `displayName`, by path or as a value object |
| `DELETE /Users/{id}` | Deprovisions and forgets the resource |
| `GET /ServiceProviderConfig`, `/ResourceTypes`, `/Schemas` | What a provider fetches before it provisions anything |

Everything else answers a SCIM error object (`urn:ietf:params:scim:api:messages:2.0:Error`)
with the `scimType` RFC 7644 section 3.12 gives it: a filter on another
attribute is `invalidFilter`, a `userName` that would be changed is
`mutability`, an attribute this endpoint does not keep is
`invalidSyntax`, a second create of one name is `uniqueness` (409).

**`active: false` and `DELETE` do the same thing to the credentials**:
every API key of that user is *revoked* — kept in the file as the record
of what it reached and when it stopped — and the enrolment is removed.
The difference is the resource: a deactivated user is still there to be
read, which is what `state_file` is for, and a deleted one is not. There
is no "disabled enrolment" in the enrolment file, so a suspension that
left one in place would be a suspension in name only.

Which makes one setting elsewhere load-bearing: **`require_enrolment`
must be on** wherever the enrolment file this endpoint writes is used —
on a gate listener's `mfa` section and on the `mfa` filter alike. With it
off, a user with no enrolment is let through *unchallenged*, so removing
an enrolment opens the door instead of closing it, and a deprovisioning
would be the opposite of what the directory asked for.

Which means **reactivating mints new credentials.** The old secret is
gone and cannot be handed back, so `active: true` on a deactivated user
enrols again and issues a new key; with `return_secrets: false` nobody
can read them, and the operator delivers a fresh enrolment with
`xproxyctl mfa enrol` and a fresh key with `xproxyctl apikey rotate`.

**`return_secrets` is off by default.** With it on, the response to a
create or a reactivation carries the `otpauth://` URI, the recovery
codes and the key plaintext under the extension attribute `secrets` —
which is what an automated onboarding needs, and which puts them in the
provider's response logs and in whatever it stores. Validation says so
at load. With it off the credentials are still made; they are simply not
in the answer.

**What is not changed here.** `userName` is immutable, because it is
what the credentials are keyed on: a rename is a new user and the old
one deprovisioned, said in the directory rather than inferred here. The
scopes of an issued key cannot be changed either — that is a new
credential, and this endpoint does not replace one nobody asked it to
replace.

**Where it runs.** Before routing, like the virtual `security.txt`: the
provider needs no route, and no route can take the endpoint away by
matching the path first. A request on the endpoint's path that the
selectors refuse is answered 404 and **not** routed on — passing it to a
proxied application would hand it a request meant for the control plane.

`scim` and `scim_user` are in the access log, every change writes a
security event (`scim` with the operation), a refusal writes a deny
event with `scim` as the reason — which a ban trigger can name, and a
bad token feeds it, because somebody trying tokens against a
provisioning endpoint is not a client making a mistake twice.
`scim_requests` and `scim_denied` are in `xproxyctl stats`, and
`xproxy_scim_requests_total{result="answered"|"refused"}` in the
metrics.

## virtual_patches[]

A virtual patch blocks a known vulnerability by the shape of the
requests that exploit it, while the application is being fixed, and
records how often it fired. Patches run right after route matching,
before rate limits, filters and the WAF, so they cost nothing for other
traffic and need no `waf` section. Every listed condition must hold for
a patch to apply; at least one of `paths`, `path_regex`, `query`,
`headers`, `cookies` or `body` is required. A match with `action: block`
answers `status` with reason `virtual_patch` and the id as `detail`
(ban category `virtual_patch`); with `action: log` the request continues
and the security event and the access log carry `virtual_patch: <id>`.
`xproxyctl patches` and `GET /v1/patches` list the patches with hits,
last hit, expiry and state; `xproxy_virtual_patch_hits_total{patch}`
counts per patch and hits survive reloads.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `id` | identifier | required, unique | `a-z`, `0-9`, `.`, `_`, `-`, at most 63 characters (`cve-2024-1234`) |
| `description` | string | | Shown in the status; at most 512 bytes |
| `hosts` | list | any | Host patterns, exact or `*.example.com` |
| `routes` | list of names | any | Only requests matched to these routes |
| `paths` | list of prefixes | | Prefixes of the cleaned path |
| `path_regex` | list of regex | | Patterns matching the whole cleaned path |
| `methods` | list | any | Upper-case methods |
| `query` | list of `{name, pattern}` | | The parameter must be present and, with `pattern`, some value must contain a match |
| `headers` | list of `{name, pattern}` | | Same for header fields (names case insensitive) |
| `cookies` | list of `{name, pattern}` | | Same for cookies |
| `body` | object | none | `pattern` (required) matched anywhere in the body, buffered up to `max_bytes` (default 64 KiB, at most 16 MiB) and replayed to the upstream; `content_types` narrows the inspection, and a body of another media type does not match. `over_limit` decides a body past `max_bytes` or one that could not be read: `match` (default) treats it as matching, `skip` lets it through. A virtual patch is the emergency control that holds a known vulnerability while the application is fixed, and the WAF and ICAP both refuse an oversize body, so `skip` means 64 KiB of padding carries the same payload to the origin |
| `action` | `block`, `log` | `block` | |
| `status` | int | `403` | Response for `block`; 4xx or 5xx (404 hides the patched path) |
| `expires` | date | none | RFC 3339 or `YYYY-MM-DD` (end of that day, UTC); an expired patch no longer applies and shows as expired |
| `enabled` | bool | `true` | `false` keeps the patch without applying it |

Hand-written SecLang in `waf.profiles[].directive_files` remains the
tool for patches that need the rule engine's transformations or
scoring; `examples/security/positive-model.yaml` shows both kinds side
by side with a route policy.

## cluster

Present means enabled. Nodes exchange rate limit consumption and ban
changes (AMR-009, AMR-021). Every node listens and dials every peer;
there is no leader. Enabling or disabling the section, and changing
`listen`, `node_id`, `tls` or `local`, require a restart. Peers,
intervals and sharing flags reload.

A cluster comes in two shapes, decided by the form of `listen`:

- **Networked**, `host:port`. Peers are on other machines and are
  authenticated by mutual TLS: `cluster.tls` is required.
- **Local**, `unix:/path/to/socket`. Peers are the sibling daemons on
  this machine — `xproxy`, `xgate` and `xrelay` — and are authenticated
  by the socket's own permissions plus, optionally, the user id the
  kernel reports for the connection. There is no certificate to issue
  and none to rotate, and `cluster.tls` is refused.

A cluster is one or the other: `listen` and every entry of `peers` must
be all Unix paths or all `host:port`. A node that listened on a socket
and dialled a host would be reachable by its siblings and not by the
peers it dials, which is half a cluster that looks like a whole one. A
host that needs both gives each daemon its own certificate and makes
all three networked members.

A local cluster is what the three daemons of one host use to share a ban
list: an address the gate refuses at the SSH port is refused at the edge
too, without the estate's cluster CA being involved.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `node_id` | name | host name | Identity announced to peers and used as the ban source (`peer:<node_id>`) |
| `listen` | host:port or `unix:`path | required | Cluster listener. A `host:port` must be a specific internal address, not all interfaces; a `unix:` path must be absolute and at most 100 characters |
| `peers` | list | `[]` | Cluster addresses of the other nodes, in the same form as `listen`. This node's own address is not one of them |
| `local.socket_mode` | octal | `"0660"` | Permission mode of the listening socket on a local cluster. Any access for others is refused: on this socket the permissions are the authentication. The socket is created under a umask that permits nothing beyond the owner and then widened, so it never exists more open than this |
| `local.allow_uids` | list of int | `[]` (any process that can open the socket) | User ids that may connect, read from the socket rather than announced by the peer. A cluster peer is trusted completely — it places bans, decides rate limits and is named in the audit trail — so validation advises listing the sibling daemons' user ids. A configuration that lists them on a platform with no peer credentials is refused at start rather than admitting everything |
| `tls.cert_file`, `tls.key_file` | path | required (networked) | This node's certificate, used for both directions |
| `tls.ca_file` | path | required (networked) | Cluster CA; every peer must present a certificate from it |
| `tls.allowed_names` | list | `[]` (any name from the CA) | Restrict peers to these certificate common names or DNS SANs. Leaving it empty means any certificate the CA ever issued is a cluster peer, and a cluster certificate is full trust inside the cluster: validation says so out loud. Use a CA that issues nothing else, and list the names |
| `tls.bind_node_id` | bool | `true` | Require a peer's announced `node_id` to be a name its certificate carries. The id is not only a label: key ownership for `distributed: exact` rate limits is a rendezvous hash over node ids, so a peer free to choose its id chooses which keys it decides for every node. Set it false only for an existing cluster whose certificate names and node ids differ, and fix the certificates: a cluster certificate is full trust inside the cluster. A peer's bans, marks and rate reports are attributed to its certificate common name either way, so the audit trail is not affected by this setting |
| `gossip_interval` | duration | `1s` | How often consumption and ban batches are sent; 100ms to 60s |
| `peer_stale` | duration | 3 x `gossip_interval` | How long a peer report keeps reducing local refill after its last update; at least 2 x the interval |
| `share_rate_limits` | bool | `true` | Exchange consumption reports |
| `share_bans` | bool | `true` | Exchange bans and unbans, and send a snapshot to a newly connected peer |
| `share_events` | bool | `true` | Exchange security events: honeypot marks and unmarks (applied to the peer's mark table with route `peer:<node>/<route>`) and OIDC session revocations (per filter name). Events are bounded (128 byte kind, 512 byte key, lifetime clamped to a year), queued without blocking and dropped when the queue is full. Nodes older than 1.3 close a connection that carries them: set `false` during a rolling upgrade from 1.2 |
| `max_keys_per_report` | int | `4096` | Largest consumers kept per report |
| `exact_timeout` | duration | `50ms` | Longest wait for a key owner's answer under `distributed: exact` (5ms to 2s); on expiry the request is decided locally |

Semantics: with sharing on, a rate limit policy's `rate` becomes an
approximate cluster wide rate per key. Each node refills a key's bucket at
`rate` minus the sum of fresh peer consumption for that key; `burst` stays
per node. Accuracy is bounded by one gossip interval of delay and reports
expire after `peer_stale`, so losing a peer degrades to local limiting.
A policy with `distributed: exact` is instead decided by one owner per
key: the members (this node and every peer whose hello was received on
a live connection, `xproxyctl cluster` lists them) agree on the owner
through rendezvous hashing, requests for a key owned elsewhere carry one
round trip to the owner within `exact_timeout`, and the owner's limiter
is the single count, so the limit holds exactly cluster wide while the
members agree. Membership changes move only the departed member's keys;
during a partition two owners may exist for a key, and a node without an
answer in time decides locally, which over-admits rather than refuses.

The cluster listener can be socket activated with `FileDescriptorName=cluster`.

## fleet

Present means the node is managed by a fleet controller (`xproxy-fleet`).
The agent long polls the controller for a bundle whose digest differs
from the applied one, writes the bundle's files into the directory of
the configuration file, reloads through the ordinary path (validation,
sandbox check) and restores the previous files when the reload is
refused; after every poll it reports the node's status (version,
generation, applied digest and result, request, error, deny, connection,
upstream, endpoint, ban and certificate summary). The controller never
connects to the node. Changing the section requires a restart.
`xproxyctl fleet` and `GET /v1/fleet` show the agent state.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `controller` | URL | required | The controller's base URL, `https` without a path |
| `node_id` | name | `cluster.node_id`, else the host name | The node's name at the controller; must equal the certificate's common name or DNS name, unless the controller's `-name-map` names the exception (or it runs with `-any-name`, which turns the binding off for every node and warns on every authorisation) |
| `tls.cert_file`, `tls.key_file` | path | required | The node's client certificate |
| `tls.ca_file` | path | required | CA that issued the controller's certificate |
| `tls.server_name` | string | host of `controller` | Name verified in the controller's certificate |
| `interval` | duration | `30s` | Long poll length and status report period; 5s to 1h |
| `timeout` | duration | `10s` | Request time allowed beyond the poll length; 1s to 1m |
| `dir` | path | directory of the configuration file | Where bundle files are written; must be the configuration file's directory, and the file must be named `xproxy.yaml` |
| `apply` | bool | `true` | `false` reports status and pending bundles without writing or reloading (a review mode) |
| `tags` | list of names | `[]` | Reported to the controller for grouping |

The sandbox derives a write rule for `dir` when `apply` is on, so the
agent can replace the files under Landlock; everything a bundle
references must still lie within the sandbox's read rules, otherwise
the reload is refused and the bundle rolled back.

## jwt

Present means providers are available; routes opt in with a `jwt` block.
Tokens are validated on the standard library: RSA (PKCS#1 v1.5 and PSS),
ECDSA, Ed25519 and HMAC signatures, JSON Web Key Sets from a file or an
HTTPS URL, and the standard time and audience claims. `none` is never
accepted.

### jwt.providers[]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | name | required, unique | Referenced by routes |
| `issuer` | string | required | Must equal the token's `iss` |
| `audiences` | list | `[]` (any) | The token's `aud` must contain one; set it |
| `algorithms` | list | `[RS256, ES256, EdDSA]` | Allow list from RS256/384/512, PS256/384/512, ES256/384/512, EdDSA, HS256/384/512 |
| `jwks_file` | path | | Key set on disk, re-read on reload |
| `jwks_url` | https URL | | Key set fetched at start, every `jwks_refresh`, and on an unknown key id (at most once a minute) |
| `jwks_ca_file` | path | system pool | CA pinned for the fetch |
| `jwks_refresh` | duration | `1h` | At least 1m |
| `hmac_secret_file` | path | | Shared secret (at least 32 bytes) for HS algorithms; symmetric keys are never taken from a key set |
| `clock_skew` | duration | `30s` | Tolerance on `exp`, `nbf` and `iat`; 0 to 10m |
| `required_claims` | list | `[]` | Claims that must be present; `exp` always is |
| `source` | `bearer`, `header:<Name>`, `cookie:<Name>` | `bearer` | Where the token is read from |
| `forward_claims` | map header -> claim | `{}` | Set upstream headers from claims; client supplied copies of these headers are always removed, token or not. `Authorization`, `Cookie` and `Host` cannot be targets |
| `strip_token` | bool | `true` | Remove the token before forwarding |
| `log_claims` | list | `[]` | Claims copied to the access log as `jwt_<claim>` |
| `introspection` | object | none | Validate tokens at an OAuth 2.0 token introspection endpoint (RFC 7662): every token of a provider without keys, tokens that are not compact JWS otherwise, all tokens with `always`. The answer's claims pass the provider's `issuer`, `audiences` (when present) and `required_claims` rules and feed `forward_claims` and `log_claims` like a JWT payload; `active: false` is refused with reason `inactive`, an unreachable endpoint answers 503 with `Retry-After` |
| `introspection.url` | https URL | required | The endpoint |
| `introspection.client_id`, `introspection.client_secret_file` | string, path | required | HTTP basic credentials of the proxy at the authorization server |
| `introspection.ca_file` | path | system pool | CA pinned for the endpoint |
| `introspection.cache_ttl` | duration | `60s` | How long an answer (positive or negative) is kept, bounded by the token's `exp`; at most 65536 entries per provider; `0` caches nothing |
| `introspection.timeout` | duration | `3s` | Per call, 100ms to 30s |
| `introspection.always` | bool | `false` | Introspect signed tokens too, for revocation |
| `dpop` | object | none | Demonstrating proof of possession (RFC 9449); see below |
| `dpop.mode` | `off`, `allow`, `require` | `off` | `allow` verifies a proof whenever the token says it is bound to a key and refuses a bound token presented without one; `require` also refuses a token that is not bound |
| `dpop.algorithms` | list | `[ES256, ES384, ES512, PS256, PS384, PS512, EdDSA]` | Allowed proof algorithms, from the asymmetric set; nothing symmetric is permitted |
| `dpop.max_age` | duration | `60s` | How old a proof's `iat` may be; `clock_skew` is allowed on top, in both directions; at most 10m |
| `dpop.replay_entries` | int | `65536` | Bound on the table of spent proof identifiers |
| `dpop.external_url` | URL | none | The scheme and authority the client sees, for the `htu` comparison, when another proxy terminates TLS in front |
| `certificate_binding` | object | none | Certificate-bound access tokens (RFC 8705); see below |
| `certificate_binding.mode` | `off`, `allow`, `require` | `off` | `allow` compares the token's `cnf["x5t#S256"]` with the client certificate whenever the token carries one; `require` also refuses a token that is not bound |
| `certificate_binding.trust_forwarded_header` | bool | `false` | Read the certificate from the RFC 9440 `Client-Cert` request header when the peer is inside `trusted_proxies`, for a deployment where TLS is terminated in front |
| `token_exchange` | object | none | Swap the verified client token for one issued to the backend (RFC 8693); see below |
| `token_exchange.url` | https URL | required | The token endpoint |
| `token_exchange.client_id`, `token_exchange.client_secret_file` | string, path | required | HTTP basic credentials of the proxy at the authorization server |
| `token_exchange.ca_file` | path | system pool | CA pinned for the endpoint |
| `token_exchange.audience`, `token_exchange.resource` | string, URI | one is required | Who the new token is for: the backend's identifier, or its URI (RFC 8707) |
| `token_exchange.scopes` | list | `[]` | Ask for a subset; empty leaves the decision to the authorization server |
| `token_exchange.requested_token_type` | URN | server's choice | Only the `access_token` or `jwt` URN; anything else would be forwarded as an access token |
| `token_exchange.header` | header name | `Authorization` | Where the new token goes; `Authorization` carries `Bearer <token>`, any other name the token alone |
| `token_exchange.cache_ttl` | duration | `60s` | One exchange kept this long, bounded by the new token's own expiry; at most 32768 entries; `0` exchanges on every request |
| `token_exchange.timeout` | duration | `3s` | Per exchange, 100ms to 30s |
| `token_exchange.required` | bool | `true` | `false` lets the request through with no token at all when the exchange fails |

#### jwt.providers[].token_exchange: a token the backend cannot reuse

A token the client sent to the gateway is a token the gateway forwards,
and everything behind the gateway then holds a credential that works at
the gateway. That is the confused-deputy problem in one sentence: a backend
with a bug — a log line, an error page, an outbound request to somewhere it
should not go — leaks a token that reaches the front door again with all of
the client's scopes on it.

Exchange replaces it. The proxy presents the verified client token to the
authorization server and asks for one issued for *this* backend: a
different `audience`, usually fewer `scopes`, and no standing anywhere
else. The backend never sees the client's token, so there is nothing there
to leak that would work at the gateway. The client's identity survives —
the authorization server puts the same subject in the new token, which is
what makes this an exchange rather than an impersonation.

The exchange runs **after** the client's token has been verified, never
before: sending an unverified token to the authorization server would spend
its capacity on whatever a client posted, and caching the answer against
the token's digest would let one client's garbage occupy the table. It also
runs after `strip_token`, so the client's token is gone from the forwarded
request whether the exchange succeeded or not.

An exchange that names neither an audience nor a resource is refused at
load: it asks for a token as broad as the one it replaces, which is the
feature undone while the configuration reads as if it were on. The
`issued_token_type` in the answer is checked rather than assumed — a server
that answered with a refresh token would otherwise have it forwarded as an
access token, which is a long-lived credential handed to a backend.

Outcomes: a refusal from the authorization server (400, 401 or 403 there)
is 403 here with detail `exchange_refused`, because the token is valid and
this backend is not somewhere it reaches; an endpoint that cannot be asked
is 503 with `Retry-After` and detail `exchange_unavailable`. Refusals are
cached for `cache_ttl` like successes — they are the authorization server's
decision about this client and this backend, and asking again per request
turns one misconfiguration into load the login flow shares — while an
unreachable endpoint is never cached. `required: false` lets the request
reach the backend with no token, which validation warns about: it is the
control failing open on exactly the requests where it went wrong.

#### jwt.providers[].dpop: proof of possession

A bearer token is a password: whoever holds it is whoever it says. That is
the whole of its security model, and it is why a token stolen from a log,
a browser's storage, a proxy's cache or a crash dump is as good as the
original — nothing about the request says it came from the client the
token was issued to.

DPoP (RFC 9449) adds the missing part. The client keeps a key pair, the
authorization server records the public key's thumbprint in the token as
`cnf.jkt`, and every request carries a small JWT — the proof — signed with
the private key over *this* method, *this* URI and *this* moment. A stolen
token without the key produces no proof, and a proof captured from one
request does not fit another.

What is checked, in this order, because each step is only meaningful once
the one before it holds:

1. The proof is a JWT with `typ: dpop+jwt` and an algorithm from
   `dpop.algorithms`. Nothing symmetric and no `none`: a proof the
   verifier could have written itself proves nothing about the client. A
   key carrying private material is refused too — that is a client that
   has sent its secret.
2. Its signature verifies under the key embedded in its own header. On its
   own that proves nothing, since anybody can generate a key; step 5 is
   why it matters.
3. `htm` and `htu` match the request. The method is compared exactly
   (HTTP methods are case-sensitive); the URI is compared without query or
   fragment, as RFC 9449 section 4.3 says, because the query is not what a
   replay changes. The scheme comes from the connection and the authority
   from the `Host` header — never from `X-Forwarded-Proto`, since a client
   that can set that header could otherwise choose which URI its proof has
   to match. Behind another terminating proxy, `dpop.external_url` says
   what the client sees.
4. `iat` is within `max_age` (plus `clock_skew`, both ways) and the `jti`
   has not been seen. Together they bound replay to a window and then
   remove it. The `jti` is spent *last*, once everything else holds, so a
   proof refused for another reason does not consume the identifier a
   correct retry would use.
5. The RFC 7638 thumbprint of the embedded key equals the token's
   `cnf.jkt`. This is the step the rest exists for: it ties the key that
   signed the proof to the key the authorization server bound the token
   to. The claims are read from a token **this proxy has already
   verified** — reading `cnf` from an unverified token would let an
   attacker write their own thumbprint into it.
6. `ath` equals the base64url SHA-256 of the access token, so a proof
   cannot be moved between two tokens the same client holds.

`mode: allow` costs nothing to turn on: it never refuses an ordinary
bearer token, and it closes the replay hole for every token the
authorization server did constrain. `require` is the stricter statement
that this route takes constrained tokens only.

With DPoP on, the `Authorization: DPoP <token>` scheme RFC 9449 defines is
read as well as `Bearer` — a server that reads only `Bearer ` does not see
a sender-constrained token at all. The proof is removed before forwarding:
it is a signed statement about *this* hop, and a backend verifying it
against its own URI would fail.

Refusals are 401 with `WWW-Authenticate: DPoP error="invalid_dpop_proof",
algs="..."`, or `error="invalid_token"` when the problem is the token
rather than the proof (`dpop_missing`, `dpop_unbound`). The access log
carries `dpop_jkt` with the thumbprint that was proved. The details are
`dpop_proof`, `dpop_binding`, `dpop_replay`, `dpop_missing` and
`dpop_unbound`.

A provider whose key set has never loaded (for example the JWKS URL is
unreachable at start) rejects tokens with 503 and `Retry-After` until a
fetch succeeds; a fetch that returns no keys keeps the previous set.

#### jwt.providers[].certificate_binding: the certificate the token names

The other answer to a stolen bearer token, and the cheaper one. Where
DPoP has the client sign a proof per request, a certificate-bound token
needs no proof at all: the client already proved possession of its
private key in the TLS handshake, and the authorization server recorded
the certificate's SHA-256 thumbprint in the token as `cnf["x5t#S256"]`
(RFC 8705 section 3). So the check is a comparison — the thumbprint of
the certificate on this connection against the one in the token — and a
token lifted out of a log, a crash dump or a proxy's cache is useless on
any other connection.

It is also the more limited one: it works only where the client can
present a certificate, which in practice means machine to machine. A
browser cannot, which is why DPoP exists. The two can be on together, and
a token carrying both confirmations must satisfy both.

```yaml
jwt:
  providers:
    - name: partners
      issuer: https://idp.example.com/
      audiences: [api]
      jwks_url: https://idp.example.com/.well-known/jwks.json
      certificate_binding: {mode: require}
```

The certificate compared is the one from the handshake **this proxy
terminated** (`server.listeners[].tls.client_auth` must ask for it, and
validation warns when no listener does). Where TLS is terminated in front,
`trust_forwarded_header` reads the certificate from RFC 9440's
`Client-Cert` instead — and only when the immediate peer is inside
`trusted_proxies`, because a client that could set that header would
otherwise choose which certificate its own token is checked against, which
is the whole of the check. A certificate on the connection always wins over
a header. The header is parsed as a certificate before it is hashed, so a
header that is not one is no certificate rather than a thumbprint of
something else, and one over 16 KiB is refused before it is decoded.

Like DPoP, the comparison runs on claims **this proxy has already
verified**: `cnf` read out of an unverified token is a value whoever
presented it chose. A padded thumbprint is accepted as the same
thumbprint — RFC 8705's encoding has no padding, but an authorization
server that adds it has not issued a different value, and refusing it
would look exactly like an attack in the log.

Refusals are 401 with `WWW-Authenticate: Bearer error="invalid_token"` and
a detail: `cert_missing` (a bound token presented with no certificate),
`cert_binding` (a bound token on another certificate) or `cert_unbound`
(`require`, and the token carries no binding). The access log carries
`cert_thumbprint` with the thumbprint that matched.

### routes[].jwt

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `provider` | name | required | |
| `required` | bool | `true` | `false` lets requests without a token through (spoofed claim headers still removed) and rejects invalid ones |

Rejections answer 401 with `WWW-Authenticate: Bearer` (`error="invalid_token"`
for a present but invalid token), are logged with the failure category
(expired, signature, issuer, audience, algorithm, unknown_key, claim,
malformed) and feed ban triggers under the `jwt` category. The JWT filter
runs before the WAF on the same route.

## icap

Present means scanning services are available; routes opt in with an
`icap` block. Requests (REQMOD) and responses (RESPMOD) are handed to the
service per RFC 3507 with preview and `204 No Content` support. A
`200` answer with an encapsulated response is sent to the client as is
(a block page); one with an encapsulated request replaces the method, path,
headers and body sent upstream, except the protected headers (`Host`, the
forwarding headers, `Authorization`, `Cookie`).

### icap.services[]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | name | required, unique | Referenced by routes |
| `url` | `icap://host[:port]/service` or `icaps://...` | required | Default ports 1344 and 11344 |
| `tls.ca_file`, `tls.server_name` | | | Pinned CA and verified name for `icaps` |
| `connect_timeout` | duration | `2s` | |
| `timeout` | duration | `5s` | Whole exchange; at most 2m |
| `max_conns` | int | `8` | Pooled idle connections |
| `max_body` | int | `10485760` | Largest body sent for scanning; 1024 to 1 GiB |
| `body_limit_action` | `reject`, `bypass` | `reject` | 413, or pass unscanned and count as bypassed |
| `fail` | `closed`, `open` | `closed` | On a service error or timeout: 502 with `Retry-After`, or pass unscanned and count as bypassed |
| `preview` | `auto`, `off`, bytes | `auto` | Preview size from OPTIONS, none, or a fixed count |

The service is probed with OPTIONS at load and reload; an unreachable
service is logged, not fatal, and behaves according to `fail` until it
answers.

### routes[].icap

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `service` | name | required | |
| `request` | bool | `true` | Send requests (REQMOD) |
| `response` | bool | `false` | Send responses (RESPMOD); the response body is buffered up to `max_body` |

Blocks are logged with reason `icap` and feed ban triggers under the
`icap` category. The ICAP filter runs after JWT and WAF on the same route.

## filters[]

Middleware instances of registered kinds, attached to routes by name
(`routes[].filters`). `xproxyctl filters` lists the kinds compiled into
the binary; [EXTENDING.md](EXTENDING.md) describes how to add one.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | name | required, unique | Referenced by routes; the default deny reason |
| `kind` | name | required | A registered kind: `header_guard`, `basic_auth`, `ldap_auth`, `api_key`, `api_abuse`, `openapi`, `graphql`, `grpc_guard`, `authz`, `upload_guard`, `sensitive_data`, `account_guard`, `body_rewrite`, `bot_score`, `form_guard`, `oidc`, `wasm`, or one added to `internal/filters` |
| `stage` | `before_auth`, `after_auth`, `after_waf`, `after_scan` | `after_auth` | Position relative to the built-in JWT, WAF and ICAP filters |
| `options` | mapping | | Kind specific; unknown keys are rejected |

### Kind `header_guard`

Requires or denies requests by header patterns (RE2 syntax).

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `require` | list of `{header, pattern}` | | Every rule must match every instance of the header (a missing header is the empty string) |
| `deny` | list of `{header, pattern}` | | A match on any instance of the header denies; evaluated before `require`. Every instance is judged, so a payload behind a benign first copy is still caught |
| `status` | int | `403` | 4xx status on deny |
| `reason` | string | the filter name | Deny reason in logs, counters and ban triggers |

### Kind `basic_auth`

HTTP Basic authentication against a file of `name:hash` lines written by
`xproxyctl htpasswd FILE NAME` (PBKDF2-HMAC-SHA256, 600 000 iterations;
the file must not be world readable). Verified credentials are cached by
digest so the hash cost is paid once per client session.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `users_file` | path | required | Users file |
| `realm` | string | `restricted` | `WWW-Authenticate` realm |
| `cache_ttl` | duration | `5m` | Credential cache; `0` disables |
| `forward_user_header` | header | none | Set to the user name on the upstream request |
| `strip` | bool | `true` | Remove `Authorization` before forwarding |

Denies answer 401 with `WWW-Authenticate` and reason `<filter name>`;
the user name is added to the access log line as `auth_user`.

### Kind `mfa`

A second factor on top of whatever established the identity —
`basic_auth`, `ldap_auth`, `oidc`, a JWT or an API key. It uses the same
enrolment file, replay rule and lockout as an ssh listener's `mfa`
section.

It must run **after** the filter that authenticates: it challenges the
identity it is given, and a request with none is refused rather than
challenged, because a second factor with no first factor is a prompt
with no account behind it.

A request without a verified factor gets an HTML form (401, no
redirect, so the request that needed the factor is the one that
resumes). The form posts back to the same path with `?xproxy_mfa=verify`;
on success a signed cookie is set and the client is sent to where it was
going. The cookie names the user it was issued for and is checked
against the identity of each request, so it is worth nothing on another
account; it is verified against every key in the ring, so rotating the
secret does not sign everyone out.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `file` | path | required | The enrolment file; refused if world readable |
| `cookie_secret_file` | path | required | 32+ bytes, created 0600 if absent, rotated with `xproxyctl rotate` |
| `cookie_name` | name | `__Host-xproxy-mfa` | The cookie carrying the verified factor |
| `ttl` | duration | `12h` | How long a verified factor lasts; at most 168h |
| `issuer` | name | `xproxy` | Shown as the page title |
| `prompt` | string | `One-time code` | The form's label |
| `skew` | int | `1` | Steps either side of now that are accepted |
| `require_enrolment` | bool | `true` | Refuse a user with no enrolment |
| `max_failures`, `window`, `lockout` | | `5`, `5m`, `15m` | Guessing bound, as on an ssh listener |
| `identity` | list | `[]` (any) | Which identity kinds to challenge, in order of preference: `basic`, `ldap`, `oidc`, `jwt`, `api_key` |
| `webauthn` | object | none | Offer a security key beside the code (WebAuthn level 2); see below |
| `webauthn.rp_id` | host | required | The relying party identifier: the site's registrable domain, or a subdomain of it |
| `webauthn.origins` | list | required | The exact origins a ceremony may run on; `https` only, except `localhost` |
| `webauthn.credentials_file` | path | required | The registered keys. The proxy **writes** this file: a registration adds a line and every login updates a sign count |
| `webauthn.user_verification` | bool | `false` | Require the authenticator to have verified the user (a PIN or a biometric), not only their presence |
| `webauthn.register` | bool | `false` | Offer the registration ceremony on this gate |
| `webauthn.max_challenges` | int | `4096` | Bound on the outstanding ceremonies |

Every failure gets the same page: a wrong code, a replayed one, a locked
account and a name that never enrolled are one answer. Counters:
`mfa_verified`, `mfa_failed`; `xproxy_mfa_total` by outcome.

#### Kind `mfa`: a security key beside the code

A one-time code is a shared secret typed into whatever page asked for it,
so a convincing copy of that page collects codes that work. WebAuthn does
not have that failure: the assertion is bound to the origin the ceremony
ran on, so a look-alike site gets a signature naming its own origin, which
this refuses. That is the reason to have it, and it is the only reason that
matters — everything else about a key is convenience.

The two live side by side rather than one replacing the other. A code is
how somebody gets in from a machine with no key attached, and it is how a
key is registered in the first place: **registration requires a factor the
user already has**, because a registration endpoint that trusts only the
first factor is a way to add a second factor to an account whose password
has just been stolen. Bootstrap is therefore `xproxyctl mfa enrol` (or the
GUI) for the code, then `register` for the key.

The ceremonies are four POSTs to the path the request was going to:
`?xproxy_mfa=webauthn-options` and `?xproxy_mfa=webauthn` to authenticate,
`?xproxy_mfa=webauthn-register-options` and `?xproxy_mfa=webauthn-register`
to register. The challenge page carries the small script that drives them
and offers the key only to a user who has one registered — a button that
always fails is noise, and offering it to everybody says who has a key.

What is checked on every assertion, and why each one is not a formality:

- the ceremony **type**, so a registration signature cannot be replayed as
  an authentication or the reverse;
- the **challenge**, which this proxy issued, to this account, within
  `3m`, and which is spent on first use whether the ceremony succeeded or
  not — one that survives a failure is an attacker's retry budget;
- the **origin**, exactly, against `origins`: the anti-phishing property;
- the **relying party hash**, which the authenticator computes from
  `rp_id` itself and a page cannot choose;
- **user presence**, and user verification when `user_verification` is
  set — including at registration, so a key cannot be enrolled under the
  weaker rule and used under the stronger one;
- the **signature**, under the key stored for that credential and the
  algorithm stored with it, so an assertion cannot pick a weaker one;
- the **sign count**, which must move forward for an authenticator that
  counts. A count that stands still or goes backwards is what a cloned
  credential looks like. It is written to `credentials_file` before the
  cookie is issued, because a count kept only in memory is a check a
  restart forgets, and a store that cannot be written is a refusal rather
  than a login.

A credential identifier is public — it travels in the allow list on every
login page — so the store looks one up by *account and* identifier: finding
a credential by identifier and using it for whatever account the request
claims would let anybody in as anybody whose identifier they had seen.

**Attestation is deliberately not verified.** Attestation says which
authenticator model produced a credential, which matters when a deployment
allows only certain hardware; it says nothing about whether the person
registering is the person the account belongs to. Here a credential is
trusted because the registration was authenticated by a factor the user
already had. The alternative — a metadata service, a certificate chain per
vendor and a revocation story — is a different feature with a different
name.

The credential file is the record, one line per credential:

```
alice:AQIDBA:pQECAyYgASFYIA...:7:yubikey-5c
```

the user, the credential identifier, the COSE public key (both base64url
without padding), the sign count and an optional label. It is replaced
atomically and re-read when it changes, so removing a lost key with an
editor takes effect without a restart; a line that does not parse fails the
read, because a credential meant to be there and silently not locks
somebody out and one meant to be removed and still there is worse. At most
ten credentials per account.

### Kind `yara`

The same engine as a tcp listener's `yara` section, over request and
response bodies. The supported subset and the reasons for it are
described under `server.listeners[].tcp.yara`.

The difference is that a body is buffered to `max_bytes` before it is
forwarded, so a match can refuse the request rather than only record it.
A body larger than the bound is scanned to the bound and then streamed
on — holding an arbitrary upload in memory is a worse failure than an
unscanned tail — and the access log marks those with `yara_partial`.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `rules_file` | path | one of these | One rule file |
| `rules_dir` | path | one of these | Every `.yar` and `.yara` file in the directory |
| `scan` | list | `[request, response]` | Which bodies are scanned |
| `action` | `block`, `log` | `block` | `block` refuses (403 on a request, 502 on a response, since a client did not ask for what the origin sent); `log` records and forwards |
| `max_bytes` | int | `4194304` | Scanned and buffered per body; 4096..268435456 |
| `max_window` | int | `262144` | The scanner's window |
| `content_types` | list | `[]` (all) | Media types to scan, `type/*` allowed. Empty scans everything, which is the honest default: the type is what the sender claims, not what the bytes are |

### Kind `ldap_auth`

HTTP Basic authentication against an LDAP or Active Directory server. Two
modes: a **direct bind** substitutes the username into `bind_dn_template`
and binds with the password; a **search then bind** binds an optional
service account (`bind_dn`), searches `base_dn` with `user_filter` for the
user's entry, then binds as that entry, optionally requiring group
membership. The username is escaped (RFC 4514 for a DN, RFC 4515 for a
filter) so it cannot alter the query. `ldaps://` and `start_tls` verify the
server certificate against the system roots or `ca_file`. Verified
credentials are cached by digest for `cache_ttl`; a directory or network
error is never cached and denies the request.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `url` | URL | required | `ldap://host:port` or `ldaps://host:port`. Plain `ldap://` needs `start_tls` or `allow_plaintext`: every user password crosses this connection |
| `start_tls` | bool | `false` | Upgrade an `ldap://` connection to TLS before binding |
| `allow_plaintext` | bool | `false` | Accept `ldap://` without `start_tls` (a loopback or IPsec-protected directory only) |
| `ca_file` | path | system roots | PEM roots for the server certificate |
| `insecure_skip_verify` | bool | `false` | Skip certificate verification (test only; exclusive with `ca_file`) |
| `bind_dn_template` | string | | Direct bind: `%s` is replaced by the escaped username, e.g. `uid=%s,ou=people,dc=example,dc=com`; exclusive with the search options |
| `bind_dn` | DN | | Search bind: service account DN to bind before searching (anonymous search when empty) |
| `bind_password_file` | path | required with `bind_dn` | Service account password; trailing newline trimmed; must exist and not be world readable |
| `base_dn` | DN | required for search | Search base |
| `user_filter` | filter | required for search | RFC 4515 filter with `%s` for the escaped username, e.g. `(sAMAccountName=%s)`; supports `&`, `|`, `!`, equality and presence, nested at most 32 levels deep |
| `require_group` | DN | none | Require this DN among the user's `group_attr` values (search mode only) |
| `group_attr` | attribute | `memberOf` | Attribute read from the user entry for `require_group` |
| `realm` | string | `restricted` | `WWW-Authenticate` realm |
| `cache_ttl` | duration | `5m` | Credential cache; `0` disables |
| `forward_user_header` | header | none | Set to the user name on the upstream request |
| `strip` | bool | `true` | Remove `Authorization` before forwarding |
| `timeout` | duration | `5s` | Bound on the dial and each LDAP request; 1s to 1m |

Denies answer 401 with `WWW-Authenticate` and reason `<filter name>`; the
user name is added to the access log line as `auth_user` and set as the
`ldap` identity for identity-keyed rate limits.

### Kind `oidc`

Logs browsers in with OpenID Connect (authorization code flow with PKCE
and a nonce) and keeps the result in an encrypted, HttpOnly, SameSite
Lax session cookie. A request without a session is redirected to the
provider; the callback exchanges the code at the token endpoint,
verifies the ID token against the provider's JWKS (issuer, audience,
expiry, signature, nonce), checks `require_claims`, sets the cookie and
redirects to the page first asked for. Requests with a session carry
the listed claims to the upstream as headers (client supplied values
of those headers are always removed) and the cookie is stripped
upstream. Provider metadata comes from
`issuer/.well-known/openid-configuration`, fetched at load and retried
on demand; while it is unavailable logins answer 503. Login and logout
redirects are not security events; failed callbacks are, with reason
`oidc` and a detail (`state_mismatch`, `nonce`, `id_token`, `exchange`,
`claim:<name>`), and count towards ban triggers.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `issuer` | URL | required | `https://` (plain `http://` only with `allow_http`, for tests) |
| `client_id` | string | required | |
| `client_secret_file` | path | required | Not world readable; sent as `client_secret_basic` (`token_auth: post` sends it in the form) |
| `cookie_secret_file` | path | required | 32 or more random bytes or a keyring, created `0600` if absent; sessions survive reloads and restarts while the key stays, and a rotation with `xproxyctl rotate-secret` keeps sessions sealed under the kept keys |
| `scopes` | list | `[openid]` | Must include `openid` |
| `redirect_path` | path | `/oauth2/callback` | Registered at the provider as `external_url` + path |
| `logout_path` | path | `/oauth2/logout` | Clears the session and sends the browser to the provider's end session endpoint (when it has one) with `logout_redirect` as the return, else to `logout_redirect` |
| `logout_redirect` | path | `/` | |
| `frontchannel_logout_path` | path | `/oauth2/frontchannel-logout` | OpenID Connect Front-Channel Logout endpoint: register `external_url` + path as the `frontchannel_logout_uri` at the provider; a `GET` with `sid` (and `iss`, checked against `issuer`) revokes that provider session so every session carrying it stops working, and clears the cookie when present |
| `revoked_max` | int | `65536` | Bound of the revoked session id index; entries expire with the sessions they end, and over the bound the soonest to expire is dropped |
| `external_url` | URL | derived | `scheme://host` the browser reaches the proxy on. Set it. Unset, it is derived from the request: `Host`, the listener's own TLS, and `X-Forwarded-Proto` only from a peer inside `trusted_proxies` — any client can send that header, and the URL derived from it is the redirect URI the provider sends the authorization code to |
| `cookie_name` | token | `XPOIDC` | The state cookie is `<cookie_name>_state`, ten minutes |
| `cookie_domain` | string | host only | |
| `session_ttl` | duration | `8h` | 1m to 720h; the cookie and its payload expire together |
| `forward_headers` | map | `{}` | Header name to claim (for example `X-Remote-User: sub`) |
| `require_claims` | map | `{}` | Claim to required value; a login whose ID token differs is refused with 403 |
| `log_claims` | list | `[]` | Claims copied to the access log as `oidc_<claim>` |
| `ca_file` | path | system pool | Pins the CA for the provider's endpoints |
| `token_auth` | `basic`, `post` | `basic` | Client authentication at the token endpoint |
| `allow_http` | bool | `false` | Permit a plain `http://` issuer and external URL |

The access log carries `oidc_user` for requests with a session and
`flow: <name>:login`, `login_complete`, `logout` or
`frontchannel_logout` for the flow steps. Sessions record the ID
token's `sid` claim when the provider sends one; a logout at the proxy
revokes it as well, so other browsers sharing that provider session
end too.

### Kind `saml_sp`

Logs browsers in as a SAML 2.0 service provider and keeps the result in
an encrypted, HttpOnly, SameSite Lax session cookie. A request without a
session is redirected to the identity provider with an authentication
request (HTTP Redirect binding, deflated); the provider posts the signed
response back to `acs_path` (HTTP POST binding), where it is verified
against the configured signing key and checked whole before a cookie is
set and the browser is sent back to the page it asked for. Requests with
a session carry the listed attributes to the upstream as headers (client
supplied values of those headers are always removed) and the cookie is
stripped upstream. `metadata_path` serves this service provider's
metadata for the provider to import.

**The profile is deliberately narrow, and the narrowness is the
feature.** Web single sign-on breaks in one place — the reader that
verifies a signature and the reader that consumes the assertion
disagreeing about what was signed — so everything that lets one document
mean two things is refused rather than ignored:

- A document type declaration, an entity declaration, any entity
  reference but the five XML predefines, a processing instruction, a
  CDATA section, a name outside ASCII, an undeclared prefix, a duplicate
  attribute. There is no external entity resolution to disable, because
  there is no entity resolution.
- An encrypted assertion, attribute or name identifier (`EncryptedAssertion`
  and friends). XML Encryption in a responder has been a decryption
  oracle more than once, and TLS already covers the hop the response
  takes. The refusal names itself, so a provider configured to encrypt
  is a clear message rather than a mystery.
- More than one assertion in a response, and two elements sharing an
  `ID`. Those are the shapes signature wrapping needs.
- Any signature in the document that does not verify, including one
  nothing would have read.
- A signature whose single `Reference` is not `#` plus the `ID` of the
  element the signature is enveloped in; more than one reference; a
  transform other than the enveloped-signature transform followed by
  exclusive canonicalization; a canonicalization other than
  `xml-exc-c14n#`; SHA-1, HMAC or DSA.
- A response with no `InResponseTo`, so provider-initiated ("unsolicited")
  single sign-on is not supported: there is no state to bind it to.
- A bearer subject confirmation carrying `NotBefore`, a condition this
  profile does not understand, an attribute value wrapped in markup, a
  timestamp with no zone.

What it accepts, it accepts completely: the issuer, `Destination`,
`InResponseTo` on both the envelope and the subject confirmation, the
`Recipient`, the audience, both condition windows, the confirmation
window, the provider's session bound, the status code, the name
identifier format, and a one-time check on the assertion identifier. The
signing key comes from the configuration; `KeyInfo` in the document is
not read at all, so a response signed by a key it carries is simply an
unverifiable response.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `entity_id` | string | required | This service provider's identifier, and the audience every assertion must name |
| `idp_metadata_file` | path | | The provider's metadata document; `idp_entity_id`, `idp_sso_url` and the signing certificates are read from it. An explicit option below wins over it, so a stale endpoint can be corrected in place. Read at load with the same strict parser as an assertion; its own signature is not checked, because a file an operator installed is configuration, not network input |
| `idp_entity_id` | string | required | The issuer every response and assertion must name |
| `idp_sso_url` | URL | required | Where the authentication request goes (`https://`, plain `http://` only with `allow_http`) |
| `idp_cert_file` | path | required | PEM certificates (at most eight) whose public keys verify signatures. An expired certificate is warned about at load and still trusted: a pinned key is its own trust anchor, and there is no chain to expire |
| `cookie_secret_file` | path | required | 32 or more random bytes or a keyring, created `0600` if absent; sessions survive reloads and restarts while the key stays, and `xproxyctl rotate-secret` keeps sessions sealed under the kept keys |
| `acs_path` | path | `/saml/acs` | The assertion consumer service. Register `external_url` + path at the provider. Only `POST` with a form body is accepted: a response in a query string is a response in a browser history, a proxy log and a `Referer` |
| `metadata_path` | path | `/saml/metadata` | Serves `application/samlmetadata+xml` describing this service provider |
| `logout_path` | path | `/saml/logout` | Clears the session here and redirects to `logout_redirect`. There is no single logout binding: see the note below |
| `logout_redirect` | path | `/` | A path on this host |
| `external_url` | URL | derived | `scheme://host` the browser reaches the proxy on. Set it. Unset, it is derived from the request: `Host`, the listener's own TLS, and `X-Forwarded-Proto` only from a peer inside `trusted_proxies` — any client can send that header, and the URL derived from it is the one the provider is told to post the assertion to |
| `cookie_name` | token | `XPSAML` | The state cookie is `<cookie_name>_state`, ten minutes |
| `cookie_domain` | string | host only | |
| `session_ttl` | duration | `8h` | 1m to 720h. The session never outlives the assertion: the earliest of the condition window, the confirmation window and `SessionNotOnOrAfter` caps it |
| `clock_skew` | duration | `30s` | Tolerance on every timestamp; 0 to 5m |
| `max_assertion_age` | duration | `1h` | How old an assertion may be whatever windows it declares, and the ceiling on a session; 1m to 24h |
| `signed_element` | `assertion`, `response`, `either` | `assertion` | What the signature must cover. `either` accepts a signature on one or the other; a response with neither signed is never accepted, whatever this says |
| `name_id_formats` | list | any | Accepted `NameID` formats; a login with another is refused |
| `request_name_id_format` | URN | none | The format the authentication request asks for |
| `force_authn` | bool | `false` | Ask the provider to re-authenticate rather than reuse its own session |
| `forward_headers` | map | `{}` | Header name to attribute name, or to `nameid`, `nameid_format` or `session_index` (for example `X-Remote-User: nameid`) |
| `require_attributes` | map | `{}` | Attribute to required value; a login whose assertion differs is refused with 403 and detail `attribute:<name>` |
| `groups_attribute` | string | `groups` | The attribute carrying the groups an `authz` policy may decide on |
| `policy_attributes` | list | `[]` | Attributes recorded on the identity for a policy to read |
| `log_attributes` | list | `[]` | Attributes copied to the access log as `saml_<name>` |
| `replay_max` | int | `65536` | Bound of the one-time assertion identifier table; entries expire with the assertions they refuse, and over the bound the soonest to expire is dropped |
| `allow_http` | bool | `false` | Permit a plain `http://` endpoint and external URL (tests) |

The session cookie carries only the attributes something names — a
header, a log field, a policy, a requirement, the groups — because a
cookie is four kilobytes and an assertion can carry far more. It is
sealed under both entity identifiers, so two filters sharing one
`cookie_secret_file` cannot open each other's sessions and a login
through a lenient provider does not satisfy a stricter one.

The access log carries `saml_user` for requests with a session and
`flow: <name>:login`, `login_complete`, `logout` or `metadata` for the
flow steps. Login and logout redirects are not security events; a
refused response is, with reason `<filter name>` and a detail
(`signature`, `refused`, `profile`, `provider_status`, `replay`,
`state_missing`, `state_invalid`, `relay_state`, `attribute:<name>`),
and counts towards ban triggers.

**Single logout is not implemented, on purpose.** `logout_path` clears
the session at this proxy; signing out at the provider is the provider's
own page. A SAML logout request arrives as a cross-site POST or redirect
carrying a name identifier, which is a way to sign other people out, and
the response half needs a signed document sent *to* a provider — a
different set of machinery for a feature whose safe part (forgetting the
session here) needs none of it. Sessions are short and the provider's own
`SessionNotOnOrAfter` caps them.

**Relay state is not the binding.** The filter sends a digest of its own
state cookie as `RelayState` and refuses a response that returns a
different one, but the binding that matters is `InResponseTo` against the
request identifier sealed in that cookie, checked on both the response
element and the subject confirmation. A provider that drops `RelayState`
entirely still works.

### Kind `xml_guard`

Decides whether an XML request body is one the application should see.

The WAF reads bodies as text and the `openapi` filter validates JSON;
between them sits every XML and SOAP API with neither. XML is also the
format with the oldest and most reliable parser attacks, and all of them
arrive the same way:

- an **external entity** that reads a file off the machine
  (`<!ENTITY x SYSTEM "file:///etc/passwd">`) or makes a request from
  inside the network on the application's behalf;
- **entity expansion** — the billion laughs — that turns a kilobyte into
  gigabytes of heap inside the application's parser;
- **parameter entity** loops and external DTD fetches.

Every one of those needs a document type declaration or an entity
reference in the body, and a gateway cannot know how the application's
parser is configured — the defaults of most XML libraries were unsafe for
years. So this refuses the shapes those attacks need before that parser
sees them, and names which shape it refused.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `content_types` | list | `application/xml`, `text/xml`, `application/soap+xml`, `+xml` | Media types to read. An entry beginning `+` matches any type ending in it, which is how the registry marks an XML format. Parameters (`; charset=…`) are ignored |
| `methods` | list | `[POST, PUT, PATCH]` | Methods with a body worth reading |
| `max_bytes` | int | `1048576` | Bound on the document. A larger body is **refused**, not passed uninspected: an oversize document must not be the way past the filter. 64 to 64 MiB |
| `max_depth` | int | `64` | Element nesting: the first thing an expansion attack spends. 1 to 10000 |
| `max_elements` | int | `50000` | Elements in the document |
| `max_attributes` | int | `64` | Attributes on one element |
| `max_name_bytes` | int | `256` | An element or attribute name |
| `max_text_bytes` | int | `65536` | One run of character data, one CDATA section, one attribute value |
| `allow_cdata` | bool | `true` | CDATA sections. On by default because ordinary XML APIs use them |
| `allow_comments` | bool | `true` | Comments |
| `allow_processing_instructions` | bool | `false` | Processing instructions beyond the XML declaration, which is always allowed |
| `require_root` | element name | none | The local name the root element must have |
| `require_root_namespace` | URI | none | With `require_root`, the namespace that name must be in. Needs `require_root`: a namespace with no name allows any element of it |
| `allow_elements` | list | any | When set, every local name the document may use. Must contain `require_root`, or nothing would load |
| `deny_elements` | list | `[]` | Local names no element may have, whatever the allow list says |
| `status` | 4xx | `400` | What a refusal answers |
| `reason` | string | the filter name | Deny reason in logs, counters and ban triggers |
| `report` | bool | `false` | Log what would have been refused (`xml_would_refuse` in the access log) and refuse nothing: for turning the filter on in front of traffic nobody has read yet |

A refusal's detail names the rule: `xml_doctype`, `xml_entity`,
`xml_cdata`, `xml_comment`, `xml_processing_instruction`, `xml_size`,
`xml_depth`, `xml_elements`, `xml_attributes`, `xml_name_length`,
`xml_text_length`, `xml_encoding`, `xml_root`, `xml_element` or
`xml_malformed`. The body is read whole and replayed byte for byte, so the
application receives exactly what the client sent.

A SOAP endpoint, which is the common case:

```yaml
filters:
  - name: soap
    kind: xml_guard
    options:
      content_types: [application/soap+xml, text/xml]
      require_root: Envelope
      require_root_namespace: http://schemas.xmlsoap.org/soap/envelope/
      max_bytes: 262144
      max_depth: 32
      allow_processing_instructions: false
```

**Schema validation is deliberately not implemented.** XSD is a language
with its own parser, its own imports and its own denial-of-service history;
a gateway that fetched and interpreted one would add a larger attack
surface than it removed, and the application already has the schema.
`require_root`, `require_root_namespace`, `allow_elements` and
`deny_elements` are a positive model of the document's shape without a
schema language in the middle — the same trade the positive security policy
makes for the rest of a request. A malformed document is refused rather
than forwarded, because two parsers disagree about what a malformed
document means and that disagreement is where the interesting bugs live.

### Kind `wasm`

Runs a WebAssembly module per request in a sandbox. The module follows
the ABI in EXTENDING.md (exports `xproxy_abi_version`, `xproxy_alloc`,
`xproxy_on_request`, optionally `xproxy_on_response`; imports `get`,
`set_header`, `remove_header`, `deny`, `log`, `log_attr` from module
`xproxy`). It is read and compiled at load and on reload; a broken
module or a wrong ABI version is a load error.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `module` | path | required | Absolute path of the `.wasm` file, at most 64 MiB |
| `config` | string | `""` | Free text the module reads with `get(config)`, at most 64 KiB |
| `timeout` | duration | `50ms` | Per call bound; 1ms to 10s |
| `memory_limit_pages` | int | `256` | 64 KiB pages per instance (16 MiB); 1 to 16384 |
| `instances` | int | `16` | Pooled instances and the bound on concurrent calls: a request beyond it waits for a free instance within `timeout`, then takes `on_error` |
| `on_error` | `deny`, `allow` | `deny` | What a trap, timeout or bad result means: 500 with the filter name as reason, or continue with `wasm_error: allowed` in the access log |
| `engine` | `auto`, `compiler`, `interpreter` | `auto` | The compiler emits machine code into executable memory, which the shipped systemd unit (`MemoryDenyWriteExecute=yes`) and the macOS hardened runtime refuse; `auto` probes once per process and falls back to the interpreter, which needs no executable pages and is several times slower per call |
| `body_limit` | int | `65536` | Bytes of a request or response body a module may read or set; a larger body is not exposed and streams through; 0 disables body access; at most 16 MiB |

Denies carry the status, reason and detail the module set with
`deny`; `log_attr` values appear in the access log as `wasm_<key>`.

### Kind `bot_score`

Scores each request as automation from the user agent, the headers a
browser always sends, the TLS fingerprint of the connection (JA3 and JA4,
computed from the ClientHello) and the client's recent behaviour, then
logs, challenges or denies by threshold.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `deny_at` | 0 to 100 | `0` (off) | Deny with 403 from this score |
| `challenge_at` | 0 to 100 | `0` (off) | Serve the browser challenge from this score (needs a `challenge` section; must be below `deny_at`) |
| `log_at` | 0 to 100 | `30` | Add `bot_score` and `bot_signals` to the access log line from this score |
| `header` | header name | none | Forward the score to the upstream in this header |
| `ja4_deny`, `ja4_allow` | lists of JA4 strings | | Fingerprints scored 100 or 0 regardless of other signals |
| `window` | duration | `60s` | Behaviour window per client address (5s to 1h) |
| `rate_per_window` | int | `300` | Requests in the window above which `high_rate` fires |
| `device_addresses` | int | `5` | Distinct client addresses one device identifier must arrive from within the window before `device_shared` fires (2 to 10000) |
| `weights` | mapping | see below | Override a signal's weight (0 to 100) |
| `reason` | string | the filter name | Deny reason |
| `learn` | bool | `false` | Learning mode: record the per-route score distribution without acting on it. `xproxyctl botscore` then reports each route's percentiles and suggested `challenge_at`/`deny_at`, so thresholds are tuned to real traffic. Combine with `deny_at`/`challenge_at` at `0` to observe first |

Signals and default weights: `ua_bot` 40 (curl, wget, python, Go, Java,
scanners, headless browsers and the like), `ua_missing` 30,
`browser_headers_missing` 25 (a browser user agent without `Accept` or
`Accept-Language`), `fingerprint_mismatch` 35 (a browser user agent on a
hello without `h2` ALPN or with fewer than ten cipher suites),
`error_rate` 30 (more than half of at least ten recent requests were
4xx or denied), `path_spread` 15 (fifty or more distinct paths in the
window), `regular_interval` 20 (eight or more requests with machine-like
timing), `high_rate` 15, `honeypot_marked` 40 (the client touched a
honeypot route on this node or, with cluster sharing, on a peer),
`automation_markers` 45 (the challenge cookie says the script saw
WebDriver, driver globals, chromedriver, a headless user agent, no
languages, no plugins or a zero sized window when the client solved
its challenge) and `device_shared` 25 (the cookie's device identifier
came from `device_addresses` or more addresses in the window: one tool
behind a proxy pool). The last two need a `challenge` section with
`device` on and only apply once the client holds a cookie. The
score is the capped sum; a client that is
already verified by the challenge is never challenged again. The JA4 of
every TLS request is logged as `ja4`.

### Kind `form_guard`

Catches the two things a form-filling bot does and a person does not:
it fills in every field it finds, including the one nobody can see, and
it submits faster than anyone could have read the page.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `fields` | list of field names | | Fields that must arrive empty or absent; a value in any of them denies with detail `field:<name>`. Both the submitted body and the query string are searched |
| `min_seconds` | seconds | `0` (off) | Refuse a submission that arrives sooner than this after the form page was fetched (detail `too_fast`); 0 to 3600 |
| `max_seconds` | seconds | `0` (off) | Refuse a submission from a form page fetched longer ago than this (detail `too_old`); 0 to 2592000 |
| `form_paths` | list of paths | required for timing | GETs of these paths (and anything below them) count as fetching the form |
| `require_fetch` | bool | `false` | Refuse a submission with no form fetch on record (detail `no_form_fetch`) |
| `methods` | list of `POST`, `PUT`, `PATCH` | `[POST]` | What counts as a submission |
| `max_body_bytes` | int | `65536` | Body buffered and replayed for inspection; a larger body passes uninspected (1024 to 8 MiB) |
| `max_clients` | int | `65536` | Fetch times remembered; a full table sweeps its older half (128 to 1048576) |
| `status` | int | `403` | 4xx status on deny |
| `reason` | string | the filter name | Deny reason in logs, counters and ban triggers |

The hidden field is the classic: an input the stylesheet hides and
`autocomplete="off"` keeps a password manager out of, with a name worth
filling in (`contact_reason`, `website`). A person never sees it, so a
value in it is a signal with no false positive to trade away — unlike
timing, which is why `fields` is the option to reach for first.

```html
<div style="position:absolute;left:-9999px" aria-hidden="true">
  <label>Leave this empty<input type="text" name="contact_reason"
         tabindex="-1" autocomplete="off"></label>
</div>
```

The timing check needs no JavaScript and no cookie: the filter remembers
when the client address last fetched a page under `form_paths` and
compares. A client with no fetch on record is allowed, because a form
page can be cached, prerendered or served by another node; set
`require_fetch` only where the deployment makes that impossible. Only
`application/x-www-form-urlencoded` bodies are parsed — a JSON API
sharing the route is none of this filter's business — and the body is
replayed byte for byte, so the application receives exactly what the
client sent.

Denies are logged with the configured reason and a detail, and add
`form_guard` (and `form_seconds` for a timing refusal) to the access log
line. A ban trigger names a built-in reason, so set `reason: honeypot`
to let one pick these denies up; left unset, they are logged under the
filter's own name and ban nobody.

### Kind `account_guard`

Protects the endpoints where accounts are attacked. Each endpoint has
a class with a default ladder of progressive actions over a window:
`login` counts failed attempts (recognised in the response) per client
address, per account, per address and account pair, distinct accounts
per address (credential stuffing) and distinct addresses per account
(spraying, distributed brute force); `register`, `reset`, `cart` and
`scrape` count requests; `custom` needs its own steps. A step fires
when any of its thresholds is reached and the highest firing step acts:
`log` records, `delay` holds the request, `challenge` serves the
browser challenge to unverified clients (a plain 403 without a
`challenge` section), `captcha` serves the CAPTCHA tier
(`challenge.captcha`; the proof of work without one) to clients that
have not passed it, and `block` refuses the key that crossed the
threshold for `duration`, on every node of a cluster. Blocks and
denials use reason `account_abuse` (a ban trigger category) with
status `block_status`; the access log carries `account_endpoint`,
`account_action`, `account_by`, `account_counts`, `account_hash`,
`account_campaign`, `account_device` and `account_outcome`; `xproxyctl accounts` and
`GET /v1/accounts` show the live state (tracked keys, active blocks,
campaigns) and the process wide counters, which the
`xproxy_account_*` metric families export. Identities are trimmed,
lower cased and hashed before they are counted or logged. A campaign
spread over many addresses, each under its own thresholds, is detected
from the endpoint's totals (`distributed`): while it lasts every
unverified request of the endpoint is challenged (or blocked).

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `endpoints` | list | required | 1 to 64 endpoints, unique names |
| `endpoints[].class` | `login`, `register`, `reset`, `cart`, `scrape`, `custom` | `custom` | Selects the default ladder, methods and counting mode |
| `endpoints[].paths` | list | required | Exact paths, or prefixes ending in `*` |
| `endpoints[].methods` | list | `POST` (login, register, reset, cart), `GET` (scrape), any (custom) | |
| `endpoints[].count` | `failures`, `requests` | `failures` for login, `requests` otherwise | What an event is |
| `endpoints[].identity` | mapping | required for login, register and reset | Where the account identifier lives: `header`, `query`, `form` (a field of a form body) or `json` (a field of a JSON body, dots descend), tried in that order; bodies are buffered up to `max_body_bytes` and replayed |
| `endpoints[].failure` | mapping | `{statuses: [401, 403]}` | Failure recognition for `failures` counting: `statuses`, `body_regex` on a 2xx body (up to `max_bytes`, default 65536), `location_regex` on a redirect. A success clears the account's and the pair's failures |
| `endpoints[].window` | duration | `10m` | Counting window (1m to 24h) |
| `endpoints[].steps` | list | per class, below | 1 to 8 steps of `{action, delay, duration, ip, account, pair, ip_accounts, account_ips, ip_paths, device, device_accounts}` (`device` counts events per device identifier from the challenge cookie, `device_accounts` distinct accounts per device; a client without a cookie has no device); `action` is `log`, `delay` (holds `delay`, 10ms to 10s, default 1s), `challenge`, `captcha` or `block` (for `duration`, default the window); at least one threshold per step |
| `endpoints[].distributed` | mapping | `{ips: 50, events: 200}` for login, off otherwise | Campaign detection: both `ips` (distinct addresses with events in the window) and `events` must be reached; `action` `challenge` (default), `captcha` or `block` for `duration` (default the window) |
| `endpoints[].automation` | `off`, `log`, `challenge`, `captcha`, `block` | `off` | What happens to a client whose challenge cookie carries automation markers (`Info.Automation`: WebDriver, driver globals, chromedriver, a headless user agent, no languages, no plugins, a zero sized window); `captcha` sends it through the CAPTCHA tier |
| `endpoints[].disposable` | `off`, `log`, `challenge`, `captcha`, `block` | `off` | What happens to an e-mail identity on a disposable domain (built-in list plus `disposable_domains`, subdomains included) |
| `block_status` | int | `429` | Status of blocks (4xx or 5xx); challenges answer 403 |
| `max_body_bytes` | int | `65536` | Request body buffered to read an identity (up to 8 MiB); a larger body yields no identity |
| `max_delayed` | int | `256` | Requests held in delay steps at once; beyond it the delay is skipped and a throttled warning written |
| `disposable_domains` | list | `[]` | Lower case domains added to the built-in list |
| `secret_file` | path | a key made at start | Keyring whose primary key keys the account hash. The hash stands in for the account in the tables, the access and security logs and every cluster event, and a plain digest of an address or a user name is not an anonymisation — the input space is small enough to enumerate — so anyone who sees one could confirm whether an account exists. Every node of a cluster must read the same file, or a peer event names a hash the other nodes cannot match; without a file the key is node-local and the filter says so at start |

Default ladders (thresholds reached within the window): `login` delays
2s at 5 address, 3 account or 3 pair failures, challenges at 15
address, 5 account, 5 pair, 10 accounts per address, 5 addresses per
account or 10 accounts per device, blocks 15m at 50 address, 20
account, 10 pair, 30 accounts per address, 20 addresses per account, 50
events or 30 accounts per device; `register` delays 2s at 2 requests
per address, challenges at 3 per address or device or 2 per identity,
blocks 1h at 10 per address or device or 5 per identity; `reset`
delays 2s at 3 per address or 2 per account, challenges at 5 per
address or device or 3 per account, blocks 1h at 20 or 10; `cart`
delays 1s at 30, challenges at 60 and blocks 30m at 150 requests per
address, identity or device; `scrape` delays 1s at 200 requests
or 100 distinct paths per address, challenges at 400 or 200 and blocks
1h at 1000. Tables are bounded per endpoint (65536 keys each, oldest
evicted with a throttled warning). A delay holds a request slot, so
keep `max_delayed` under the route's concurrency.

### Kind `api_abuse`

Watches what a caller does with an API rather than what it sends.

Every request in this sequence is valid on its own — the right method, the
right path, an authenticated caller, a well formed identifier — and the
attack is the sequence:

```
GET /api/orders/1041   200
GET /api/orders/1042   403
GET /api/orders/1043   403
GET /api/orders/1044   200   <- somebody else's order
```

That is broken object level authorisation, the first item on the OWASP API
Security Top 10, and nothing that reads one request at a time can see it.
What it is visible in is the shape of the sequence, per caller and per
endpoint, over a window:

| Signal | What was observed |
|--------|-------------------|
| `enumeration` | The caller touched more than `max_objects` **distinct** identifiers on one endpoint. A person reads their own orders; a script reads everybody's |
| `sequential` | The numeric identifiers are consecutive: `sequential.min` of them covering a span they fill to `sequential.density`. A catalogue read in order is a scrape, and that is a different fact from having read a lot |
| `refused` | Of `refused.min_requests`, at least `refused.share` were answered 401, 403 or 404. Probing for objects that are not yours looks exactly like this and little else does |

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `window` | duration | `5m` | The observation period; 1s to 24h. A caller flagged in one window is flagged until it ends, and the counts start again with the next |
| `max_objects` | int | `200` | Distinct identifiers per caller per endpoint; 0 turns the signal off |
| `sequential.min` | int | `20` | Numeric identifiers needed before the density is judged; 0 turns the signal off |
| `sequential.density` | float | `0.8` | Distinct identifiers over the span they cover: 1.0 is a perfect walk |
| `refused.min_requests` | int | `20` | Requests needed before the share is judged; 0 turns the signal off |
| `refused.share` | float | `0.5` | The fraction refused that raises the signal |
| `action` | `log`, `challenge`, `block` | `log` | What a flagged caller gets. `challenge` needs a `challenge` section; without one the verdict falls through to the refusal `block` would have given |
| `paths` | list | `[]` (every path) | Limits the filter to request paths under one of these prefixes |
| `max_subjects` | int | `8192` | (caller, endpoint) pairs held at once; the oldest is dropped and the drops are counted |

```yaml
filters:
  - name: abuse
    kind: api_abuse
    options:
      window: 5m
      max_objects: 200
      sequential: {min: 20, density: 0.8}
      refused: {min_requests: 20, share: 0.5}
      action: challenge
      paths: ["/api/"]
routes:
  - name: api
    hosts: [api.example.com]
    upstream: api
    # After the identity filters, so a caller is an account rather than
    # an address.
    filters: [jwt-auth, abuse]
```

What it counts, and what it does not:

- **A caller is the authenticated identity when the chain established
  one, and the client address otherwise.** An API abused through one
  account is one caller however many addresses it arrives from, which is
  why this filter belongs *after* the identity filters in the chain.
- **Objects, not requests.** A caller re-reading its own order fifty times
  has touched one object. That is what keeps an ordinary page refresh out
  of the `sequential` signal, which counts distinct identifiers over the
  span they cover.
- **An endpoint is the method and the path template**, with identifiers
  folded out (`GET /api/orders/*`), so one busy endpoint never flags a
  caller on another. A path with no identifier in it — a collection
  endpoint — has no object to count.
- **Identifiers are held per (caller, endpoint) up to 1024**, and past
  that the count continues as a lower bound rather than the memory:
  `xproxy_api_abuse_objects` and `xproxy_api_abuse_overflowed` say which.
  An identifier longer than 128 characters is not counted at all.
- **The response is the other half of the probing signal**, so the filter
  reads both phases, and which request the action lands on follows from
  that. A bound crossed on the way in — one object too many, a walk long
  enough to judge — refuses *that* request. The `refused` signal is raised
  by the answer instead, so it applies from the caller's next request: the
  answer that revealed the probing has already been sent.

A flagged request adds `api_abuse` to the access log with the signals that
were raised; `block` and `challenge` also write a security event with the
`api_abuse` reason, which a ban trigger can name — a caller that keeps
walking after a refusal is one to stop at the edge rather than at the
filter.

Per filter, `xproxy_api_abuse_requests_total`, `_flagged_total`,
`_blocked_total`, `_challenged_total` and `_dropped_total` count what it
did, and `xproxy_api_abuse_subjects`, `xproxy_api_abuse_objects` and
`xproxy_api_abuse_overflowed` say how much it is holding: a `subjects`
gauge pinned at `max_subjects` with `_dropped_total` climbing is a filter
watching more callers than it was given room for.

### Kind `api_key`

API keys with a life cycle: issued by `xproxyctl apikey add` (the
plaintext `xpk_<id>_<secret>` is printed once; the file keeps a SHA-256),
scoped, expiring, rotated with a grace period for the previous secret
(`apikey rotate -grace 24h`) and revoked (`apikey revoke`, kept in the
file so the id is never reused). The filter re-reads the file when its
contents change, at most every `reload`, and keeps the previous table
when the new file does not parse.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `keys_file` | path | required | Written by `xproxyctl apikey`; must not be world readable |
| `source` | `header:<Name>`, `bearer`, `query:<name>` | `header:X-Api-Key` | Where the key is read; `bearer` accepts `Authorization: Bearer`, `ApiKey` or `Api-Key` |
| `required_scopes` | list | `[]` | Every listed scope must be granted to the key (a scope `orders` covers `orders:read`, `*` covers all); a key without one is refused with 403 |
| `forward_id_header` | header | `X-Api-Key-Id` | Upstream header carrying the key id; `""` disables. A client supplied copy is always removed |
| `forward_scopes_header` | header | `X-Api-Key-Scopes` | Upstream header with the key's scopes, space separated; `""` disables |
| `strip` | bool | `true` | Remove the key from the forwarded request |
| `reload` | duration | `30s` | How often the file is checked for changes (1s to 1h) |
| `expiry_warning` | duration | `168h` | A key used within this time of its expiry is logged once a day; `0` disables |

Denials: 401 with `WWW-Authenticate: ApiKey` and the detail `missing`,
`unknown`, `revoked`, `expired` or `rotated` (the previous secret after
its grace), 403 `scope:<name>`; the access log carries `api_key` with
the id.

### Kind `openapi`

Validates requests against an OpenAPI 3.0 or 3.1 description (JSON or
YAML): the path must be documented (concrete paths win over templated
ones), the method defined for it (else 405 with `Allow`), path, query,
header and cookie parameters present when required and matching their
schema (strings are coerced to the declared type, in the `style` the
parameter declares), the content type one the operation declares (else
415) and a JSON or urlencoded body valid against its schema. The schema subset covers types and `nullable`, `enum`, `const`,
`required`, `properties`, `additionalProperties`, `patternProperties`,
`items`, `minItems`/`maxItems`/`uniqueItems`, `minLength`/`maxLength`/
`pattern`, `minimum`/`maximum` (exclusive too), `multipleOf`,
`minProperties`/`maxProperties`, `allOf`/`anyOf`/`oneOf`/`not`, local
`$ref` and the formats `date-time`, `date`, `email`, `uuid`, `ipv4`,
`ipv6`, `uri` and `hostname`; other keywords and formats are ignored as
the specification allows. Denials answer JSON with the reason and up
to twenty `details` naming the offending path.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `spec_file` | path | one of `spec_file`, `spec_url` | The description on disk, checked at configuration load; afterwards re-read when its change time or size moves, checked at most every `refresh` on the request path, so a spec update needs no reload; a file that no longer compiles keeps the last good description and is logged |
| `spec_url` | URL | | Fetch the description over HTTPS (plain HTTP only to localhost) at start and every `refresh` in the background with `If-None-Match`; a fetch that fails or does not compile keeps the last good description and is logged. Both filters of the same route expose `Reloads` and `Failures` in the filter log lines |
| `refresh` | duration | `30s` (file), `5m` (URL) | Check or fetch interval, 1s to 24h |
| `timeout` | duration | `10s` | One fetch, 1s to 1m; the fetch uses no environment proxy |
| `ca_file` | path | system roots | Private CA for `spec_url` |
| `cache_file` | path | none | With `spec_url`: the last good description is written here (mode `0600`) and used when the URL is unreachable at start, so a registry outage does not stop the proxy |
| `base_path` | path | from `servers[0].url` | Prefix under which the paths are served |
| `unknown_paths` | `deny`, `allow` | `deny` | `deny` answers 404 for a path the description lacks |
| `strict_query` | bool | `false` | Refuse query parameters the operation does not declare. A `deepObject` parameter's own bracketed names count as declared, since those names belong to it |
| `validate_body` | bool | `true` | Parse and validate JSON and urlencoded form bodies; off checks only the media type |
| `max_body_bytes` | int | `1048576` | A body above this is refused with 413 rather than parsed (1 to 64 MiB) |
| `require_security` | bool | `false` | Refuse a request that carries none of the credentials the operation's `security` asks for; see below |
| `read_only` | `allow`, `log`, `deny` | `allow` | What to do with a body carrying a property the description marks `readOnly`; see below |

**Parameter styles.** A parameter is not always one string, and OpenAPI's
`style` and `explode` say which spelling the operation takes. All of them
are read, because a validator that assumes one refuses every request in
the others — a worse failure than not checking at all, since the request
was correct and the description said so.

| Where | `style` | Spelling |
|-------|---------|----------|
| query | `form` (default) | `?ids=1&ids=2` and `?ids=1,2`; both are read, because both are unambiguous and a client may send either |
| query | `spaceDelimited` | `?ids=1%202` |
| query | `pipeDelimited` | `?ids=1\|2` |
| query | `deepObject` | `?filter[from]=x&filter[size]=10`, assembled into the object the schema declares, each property coerced by its own schema (at most 200 properties, since the keys come from the client) |
| path | `simple` (default), `label`, `matrix` | `1,2,3` (`label` splits on `.`) |
| header | `simple` (default) | `a,b`, and a repeated header adds elements |
| cookie | `form` (default) | `a,b` |

A repeated scalar parameter is validated for *every* value rather than
one. Everything behind a proxy reads `?limit=10&limit=999` differently —
PHP and Rails take the last, ASP.NET joins them with commas, Spring binds
an array — so judging only one of them would leave the application reading
a value nothing had checked.

A **form body** declared as `application/x-www-form-urlencoded` is
validated against its schema like a JSON one. A form carries strings, so
each field is coerced by what its property schema says it is — the same
coercion the query and path parameters get, and for the same reason:
`limit=abc` against `type: integer` has to be a type error rather than a
string that happens not to be a number. A repeated field becomes an array
when the schema says the property is one and stays the last value
otherwise, which is what a form parser behind the proxy does with it. The
body reaches the application byte for byte as the client sent it: it is
validated, not re-encoded. `multipart/form-data` is not validated here —
that is `upload_guard`'s job, and it buffers the parts already.

#### `require_security`: the part of the description that is a control

An operation says which credential it needs — `security: [{bearerAuth:
[]}]` — and `components.securitySchemes` says where that credential lives:
a named header, a query parameter, a cookie, or an `Authorization` header
with a particular scheme. That is a statement about every request the
operation accepts, and it is the one statement a gateway can act on
without knowing anything about the credential itself.

Acting on it catches the failure that keeps happening: an endpoint that
was meant to be authenticated and is not, because the middleware was
registered for one router and not another, or the annotation was left
off, or the check sits behind a flag somebody turned off. The description
already says the endpoint needs a credential; the application is the
thing that might forget.

What is checked is **presence and shape** — the header is there, the
scheme is the declared one, there is something after it — and never
validity. Deciding whether a token is real belongs to the identity
provider and the application, and this filter has no business guessing. A
request with a forged bearer token still reaches the API and is still
refused there; a request with no credential at all does not reach it.

- `apiKey`: the declared header, query parameter or cookie must be
  present and non-empty.
- `http`: `Authorization` must carry the declared scheme (matched
  case-insensitively, as RFC 9110 requires) with something after it.
  `basic` is additionally checked for the shape RFC 7617 defines —
  base64 of something containing a colon — because a value that is not
  that is not a credential the application can read either.
- `oauth2` and `openIdConnect`: `Authorization: Bearer <token>`, which is
  the binding RFC 6750 defines.
- `mutualTLS`: not checked here. Whether the client presented a
  certificate was settled by the listener's `client_auth` before this
  filter ran, and second-guessing it from here would be guessing, so such
  a requirement counts as met.

The alternatives are an OR of ANDs, as OpenAPI defines them: any one
alternative satisfies the operation, and every scheme named inside one
must be present. An operation's own `security` replaces the global one
entirely, `security: []` on an operation means it needs nothing, and an
empty object among the alternatives (`security: [{}, {bearerAuth: []}]`)
is how OpenAPI says the credential is optional. A description whose
`security` names a scheme `components.securitySchemes` never defined is
refused at load, because such a section means nothing and an operator
should find out before the gateway is relied on.

A refusal is 401 with `WWW-Authenticate` naming the scheme where there is
a registered challenge to name (`Bearer`, `Basic`); an API key has none,
and inventing one would tell a client to do something no client
understands. The security log carries `security_schemes` with the names.

The default is off, because turning it on refuses whatever was reaching
the API without a credential — which is the point, and is also a change
worth making deliberately. A description that declares security on any
operation while this is off logs a warning naming the count at every
load, so the control is not silently read as documentation. One ordering
note: if an authentication filter earlier in the chain *consumes* the
credential header rather than leaving it in place, put this filter before
it, or `require_security` will refuse the requests that filter just
authenticated.

#### `read_only`: the fields the client is not supposed to choose

OpenAPI says a `readOnly: true` property "MUST NOT be sent as part of the
request", and the reason is mass assignment: an object with `id`, `owner`
and `role` marked read-only is an object whose server-controlled fields a
client is not supposed to pick. An application that binds the whole body
onto its model — which is what every framework's convenience path does —
lets the client pick them anyway, and the description already names which
fields those are.

The walk follows `properties`, array `items`, `additionalProperties` and
`allOf`, and deliberately does **not** follow `anyOf` or `oneOf`. `allOf`
is a conjunction, so a `readOnly` there applies to the value whatever else
matches; `anyOf` and `oneOf` are alternatives, and a property that is
read-only in one branch and writable in another says nothing certain
about the value in hand — refusing on the strength of a branch the value
may not even be matching would refuse correct requests.

`allow` is the default because a client that GETs an object and PUTs it
back sends the server's own fields, and a great many REST clients are
written exactly that way. `log` lets the request through and records
`openapi_read_only` in the access log with the properties, which is how
to find out whether `deny` would break the clients before turning it on.
`deny` answers 400 with detail `read_only:body.<field>`.

### Kind `graphql`

Bounds GraphQL requests (`POST` with `application/json` or
`application/graphql`, `GET` with `query`) before they reach the API:
depth (nesting of selection sets, fragments expanded, a fragment cycle
fails), complexity (each field costs 1 times the product of the list
arguments of its ancestors), breadth, directives, aliases, operations per
batch, query size and introspection — and what the operation *is*: a
mutation, a subscription, an operation nobody named, or one this filter
cannot read at all. Nothing is executed or forwarded to a schema. Denials
are 400 with a GraphQL `errors` body and the detail `depth`,
`complexity`, `root_fields`, `directives`, `aliases`, `batch`, `size`,
`syntax`, `introspection`, `get_mutation`, `mutation`, `subscription`,
`unnamed`, `operation` or `persisted`.

**A mutation may not arrive by GET**, whatever the options say. The
GraphQL over HTTP specification reserves GET for queries, and the reason
is that a GET is what a link, an image tag, a prefetch and a crawler all
produce: a mutation reachable that way is a mutation anybody can fire
from another origin with the browser attaching the cookies. No
configuration makes that safe, so there is no option to allow it
(`get_mutation`).

**Only the selected operation is measured.** A document may carry a
client's whole query file and select one with `operationName`; only that
one runs, so judging the request by the others would refuse a client for
queries it did not send. With no `operationName` the server picks, so
every operation in the document is measured. What the *document* contains
is still policy: a mutation sitting beside the selected query is a
mutation the server could run, so `mutations`, `subscriptions`,
`allow_operations` and `require_operation_name` look at all of them.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `max_depth` | int | `10` | Deepest selection set allowed (1 to 1000) |
| `max_complexity` | int | `1000` | Weighted field count per operation |
| `max_aliases` | int | `30` | Aliased fields per request (alias floods hide repeated resolvers) |
| `max_batch` | int | `1` | Operations in an array request |
| `max_query_bytes` | int | `65536` | Query text and body size (256 to 16 MiB) |
| `introspection` | bool | `true` | `false` refuses `__schema` and `__type` |
| `list_args` | list | `[first, last, limit]` | Arguments whose integer value multiplies the cost of the fields below |
| `max_list` | int | `1000` | Cap of one multiplier, and the value assumed for a variable the request does not carry. It bounds the cost model, not the page size: `first: 1000000` is scored as `max_list`. The page size itself belongs to the origin, or to an `openapi` route policy |
| `max_root_fields` | int | `20` | Top-level fields of an operation. Depth says nothing about breadth: two hundred root fields are two hundred resolvers at depth one |
| `max_directives` | int | `100` | Directives in the query text. A directive is evaluated per field it decorates, so a field carrying a thousand `@include`s is a thousand evaluations before anything resolves. The count is of the text rather than the expansion, because that is the number an operator can look at their own query and predict |
| `mutations` | `allow`, `deny` | `allow` | `deny` makes the endpoint read-only |
| `subscriptions` | `allow`, `deny` | `allow` | `deny` refuses subscription operations |
| `require_operation_name` | bool | `false` | Refuse an operation with no name (`unnamed`) |
| `allow_operations` | list | any | The only operation names that may run (`operation`). It implies `require_operation_name`, because an anonymous operation is on no list and a list that let it through would be a list in name only. This is the strongest control here for a closed client set: the queries are known, so anything else is not a query this API serves |
| `persisted` | `allow`, `deny` | `allow` | What to do with a request that carries no query text — a persisted query the origin looks up by hash. There is nothing to parse and nothing to measure, so every bound above walks past it. `allow` is the default because the origin only runs documents it already has, which is usually the safest thing a client can send; `deny` is for a deployment whose API is reached through this filter and not otherwise, where an unreadable query should not be an allowed one (`persisted`) |

**Variables are read.** A pagination argument given as a variable —
`friends(first: $count)` with `{"count": 10}` in the request — is a real
number the server will use, and scoring it as `max_list` refuses a query
that costs nothing. That is how a complexity bound ends up switched off by
the operator it kept annoying. A variable the request does not carry, or
carries as something that is not a whole non-negative number (a string, a
null, a fraction, a negative), or that has a schema default this filter
never sees, is still the worst case; and a literal larger than the
variable still wins.

### Kind `upload_guard`

Inspects file uploads before the application stores them: multipart
bodies (and, with `raw_uploads`, any other body of a write request)
are buffered up to `max_total_bytes`, every file part is checked and
the body is replayed to the upstream unchanged. Checks, in order: file
count, the form field, the file name (no path separators, control
characters or traversal, at most `max_filename_length`), the extension
chain (`invoice.pdf.exe` has two; a denied extension anywhere in the
chain refuses, and with an allow list an unexpected extension before
the last one, `photo.html.jpg`, refuses too, while `report.2024.pdf`
passes), the size, the content (PE, ELF and Mach-O images, `#!`
scripts, PHP, JSP and ASP tags are refused whatever the name, unless
`deny_executables` is off), and the bytes against the extension's
family and the declared media type (a PNG named `.jpg`, a PDF declared
as an image). Denials answer 400, 413 or 415 with reason `upload`, a
detail `check:filename` and a JSON body; the access log carries
`upload_files` and `upload_bytes`. Malware scanning stays with ICAP.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `max_files` | int | `10` | File parts per request (1 to 10000) |
| `max_file_bytes` | int | `10485760` | Per file (up to 1 GiB) |
| `max_total_bytes` | int | `67108864` | Per request, buffered; larger requests get 413 (up to 1 GiB, at least `max_file_bytes`) |
| `allowed_extensions` | list | any | Only these final extensions; a file without an extension is refused. An entry overrides the built-in deny list |
| `denied_extensions` | list | `[]` | Added to the built-in list: executables, installers, shell and interpreter scripts, PHP, JSP, ASP, CGI, Java archives, `.htaccess` |
| `double_extensions` | `deny`, `allow` | `deny` | `deny` checks every extension in the chain; `allow` looks at the last one only |
| `check_magic` | bool | `true` | Bytes must match the extension's family (images, PDF, Office and archive containers, media) and the declared media type |
| `strict_magic` | bool | `false` | Also refuse content of an unrecognised type |
| `deny_executables` | bool | `true` | Refuse programs and server side code by content |
| `raw_uploads` | bool | `false` | Treat a non multipart body of a write request as one file, named from `Content-Disposition` or the last path segment |
| `fields` | list | any | Form field names that may carry files |
| `max_filename_length` | int | `255` | |

### Kind `authz`

Decides what a verified identity may do.

Every authenticating filter here answers "who". None of them answers
"what may they do", so each grew its own small allow list — required
scopes on the API key, a required group on the directory bind, required
claims on the session — and an allow list per filter is a policy nobody
can read in one place. This reads the identity those filters verified
and decides once, where the decision can be seen.

It decides nothing on its own authority. The subject, the groups, the
scopes and the claims all come from a filter that verified them, so a
header a client sent cannot reach a rule here. That also means it has
to run **after** the filters that authenticate: put it last in a route's
`filters` list.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `default` | `deny`, `allow` | `deny` | What happens to a request no rule matched |
| `require_authenticated` | bool | `true` | Refuse a request no filter verified. With nothing verified there is nothing to decide about, and the alternative is deciding on values a client supplied |
| `rules` | list | required | Decided in order; the first match wins |
| `forward_groups_header` | name | | Pass the verified groups to the backend. Any client value under that name is removed first |
| `forward_scopes_header` | name | | The same for scopes |
| `status` | `403`, `404` | `403` | What a refusal answers. `404` says nothing at all |

Each rule:

| Option | Type | Description |
|--------|------|-------------|
| `name` | name | Required; what the decision is logged and recorded as |
| `allow` | bool | `true` permits, `false` refuses |
| `methods` | list | Compared without case |
| `paths` | list | A path exactly, or one ending `/**` for a tree. A prefix that is not a path boundary is not a match: `/v1/orders` does not cover `/v1/orders-internal` |
| `subjects` | list | The name the authenticating filter recorded |
| `groups` | list | Any of these; compared without case, as directories treat them |
| `scopes` | list | **All** of these. A credential carrying two of three does not satisfy it |
| `kinds` | list | Which filter verified the identity: `oidc`, `saml`, `ldap`, `api_key`, `basic`, `jwt`, `mfa` |
| `claims` | map | Each named claim must equal the given value |
| `networks` | list of CIDR | The client address |
| `not_subjects`, `not_groups`, `not_networks` | list | "Everybody but". Separate keys rather than a `!` prefix, because a group name can begin with anything |

Every selector a rule names has to hold. A rule that names none matches
everything: as a deny that is a legitimate backstop, and as an allow it
is a policy that says yes to everything, so it fails the load — write
`default: allow` if that is what is meant.

The first matching rule decides, so a deny above an allow carves an
exception out of it:

```yaml
rules:
  - {name: no-deletes-from-the-field, allow: false, methods: [DELETE], not_networks: ["10.0.0.0/8"]}
  - {name: staff, allow: true, groups: ["cn=staff,ou=groups,dc=example,dc=com"]}
```

A refusal tells the client nothing about why: which rule, which group it
would have needed, and whether the path even exists are all things a
prober would like to know. The reason is in the proxy's own log and the
access line carries `authz_rule`, which is the only way to tell a policy
that allowed from one that never matched.

**What feeds it.** `oidc` records the groups from `groups_claim`
(default `groups`), the scopes from the token's `scope`, and whatever
`attr_claims` names; `ldap_auth` records the directory's own groups
from `group_attr`; `api_key` records the key's scopes. A filter that
records nothing still records the subject, so `subjects` and `kinds`
work everywhere.

### Kind `grpc_guard`

Reads gRPC messages rather than passing them through. A proxy that
routes gRPC by its path has read the envelope; the messages are
length-prefixed frames of protobuf inside the body, and without reading
them it cannot say how large one message is (only how large the whole
body is), cannot notice a stream that stops in the middle of a frame,
and cannot see a message nested a thousand deep — which costs the
backend's parser far more than it costs the sender to write.

No schema is used, deliberately. A schema has to be kept in step with
the service, and a check that is only as current as its schema is a
check that quietly stops applying the week somebody adds a field. The
protobuf wire format carries the field number and the wire type, which
is enough for every bound here.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `max_message_bytes` | int | `4194304` | One message, not the whole stream; 1024..268435456. It is what grpc-go defaults its receive limit to, so it is the number the backend already lives with |
| `max_messages` | int | `0` (none) | Messages in one request, which is how a streaming call is bounded |
| `max_depth` | int | `16` | How deeply messages may nest; 1..256 |
| `max_fields` | int | `2000` | Fields at every level together, not per message; 1..1048576 |
| `allow_compressed` | bool | `true` | A compressed message is one this filter does not decompress, so it is passed without being walked. `false` refuses it, which is what a route that must be readable sets |
| `deny_patterns` | list of RE2 | `[]` | Matched against the strings found in a message. Setting them with `allow_compressed: true` fails the load: a compressed message would go past them unread |
| `max_scan_bytes` | int | `1048576` | Of one request, read and walked; beyond it the rest is forwarded unread and the access line says `grpc_partial` |
| `max_string_bytes` | int | `4096` | One string handed to a pattern. Longer ones are truncated on a character boundary rather than dropped, because a rule about the start of a string still works on the start of it |
| `action` | `block`, `log` | `block` | `log` records and forwards, which is how a bound is tried out before it decides anything |

A length-delimited protobuf field is a nested message or a string, and
without a schema there is no way to be certain which. It is tried as a
message first: a nested message read as a string is a subtree the depth
and field bounds never see, and the bounds are the part that matters.

Denials carry the reason `grpc_guard:` and one of `message_too_large`,
`too_many_messages`, `short_frame`, `compressed`, `too_deep`,
`too_many_fields`, `malformed` or `content`; a content refusal names the
field path it matched at. The access line carries `grpc_messages`,
`grpc_depth` and `grpc_fields`, so a route's shape is visible before
anybody has to guess at a bound for it.

What this does not do is understand the fields. `deny_patterns` run
against every string in a message, not against a named field, so they
are the blunt instrument they look like.

### Kind `sensitive_data`

Detects personal and secret data in requests and responses and, per
direction, logs the findings, masks them or blocks the message. The
request phase scans the query string (raw and decoded, plus parameter
names that carry credentials), header values and the body; the
response phase scans header values and the body. Bodies of a listed
media type are buffered up to `max_bytes` and scanned whole; `gzip`,
`deflate`, `br` and `zstd` bodies are decoded first (up to
`max_decoded_bytes`); a body larger than that is streamed through the
scanner as it flows, with 4 KiB held back between reads so a value
split across two reads is still seen; an unlisted media type, an
unknown encoding or a partial (ranged) body passes unscanned. A masked
or streamed compressed body is forwarded decoded (the encoding header
is removed); a streamed body loses its content length. Because the
decoded bytes are what the other side receives, a streamed decode is
also bounded by `max_decompression_ratio`: past 8 MiB decoded, a body
that keeps expanding beyond that multiple of its compressed size has
its transfer cut, so a compression bomb small enough to pass
`max_body_bytes` cannot be amplified through the proxy. Blocking a
streamed body cuts the transfer at the finding, since the head of the
message has already been forwarded. Masking rewrites the value in place (`************1111`,
`a***@example.com`, the first eight characters of a token) and updates
`Content-Length`; blocking answers `block_status` with reason
`sensitive_data`, a detail `response:card,email` and a JSON problem
naming the kinds found, never the values. The access log carries
`sensitive_types`, `sensitive_count` and `sensitive_where` for every
message with a finding, in every mode; blocks count in
`denied_sensitive_data`, findings and message outcomes in the
`xproxy_sensitive_*` metric families.

Built-in detectors: `card` (Luhn checked payment cards), `personnummer`
(Swedish personal and coordination numbers with a valid date and
checksum), `iban` (mod 97), `ssn_us`, `email`, `jwt` (three base64url
parts with a JSON header), `private_key` (PEM headers), `api_keys`
(AWS, Google, GitHub, Slack, Stripe and GitLab formats) and
`password_query` (query parameter names such as `password`, `token`
or `api_key` with a value; requests only).

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `detectors` | list | all built-in | Built-in detector names, each at most once |
| `custom` | list | `[]` | Up to 32 `{name, regex}` operator detectors (RE2 syntax, at most 1024 bytes); a match is masked to its first eight characters |
| `request` | mapping | | Request phase; at least one of `request` and `response` is required |
| `response` | mapping | | Response phase |
| `request.action`, `response.action` | `log`, `mask`, `block` | `log` | |
| `request.scan` | list | all | `query`, `headers`, `body` |
| `response.scan` | list | all | `headers`, `body` |
| `*.types` | list | text, JSON, XML, form, JavaScript types | Body media types scanned, without parameters |
| `*.max_bytes` | int | `1048576` | Body buffered and scanned whole per direction (1 to 64 MiB); larger bodies are streamed |
| `*.max_decoded_bytes` | int | 4 × `max_bytes` | A compressed body that decodes to more than this is streamed instead (up to 1 GiB) |
| `*.max_decompression_ratio` | int | `100` | A streamed decode is cut (the transfer ends in an error) once more than 8 MiB has been decoded and the decoded size passes this multiple of the compressed bytes read. A decoded body is forwarded decoded, so without this bound a body that fits under `max_body_bytes` could become an unbounded plaintext stream toward the upstream or the client (2 to 100000) |
| `*.encoded` | `scan`, `skip` | `scan` | Decode `gzip`, `deflate`, `br` and `zstd` bodies for scanning, or leave compressed bodies unscanned |
| `*.oversize` | `stream`, `skip` | `stream` | Scan bodies larger than `max_bytes` as they flow, or leave them unscanned |
| `*.unscannable` | `refuse`, `skip` | `refuse` (request), `skip` (response) | What happens to a body the filter cannot read at all: a content coding it does not implement, a stream the decompressor refuses, or a partial body (`Content-Range`). An origin does not decompress a request body — it hands the raw bytes to the application — so `Content-Encoding: xyzzy` costs a client nothing and would otherwise turn the whole filter off for that message, `action: block` included. A refusal is `415` with detail `<direction>:unscannable` |
| `*.ignore_headers` | list | request: `Authorization`, `Cookie`, `X-Api-Key`, `Proxy-Authorization`; response: `Set-Cookie` | Headers never scanned or masked |
| `block_status` | int | `403` | Status for `block` (4xx or 5xx) |
| `min_findings` | int | `1` | Findings a message needs before mask or block act; fewer are logged only (1 to 64) |

### routes[].filters

A list of filter names, run in the listed order within each stage. A
route may combine them with `jwt`, `waf` and `icap`.

### Kind `body_rewrite`

Rewrites request and response bodies with literal or regular expression
rules, for the cases that need no WebAssembly module: absolute links an
application emits for its internal name, a field to mask on the way
out, a key to rename on the way in. Each phase is optional and has its
own media type list, size bound and rules, applied in order.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `request`, `response` | phase | | At least one |
| `<phase>.types` | list | text, JSON, XML, JavaScript, SVG and form types | Media types rewritten, without parameters |
| `<phase>.max_bytes` | int | `1048576` (1 MiB) | Bodies above this size pass through unchanged (1 to 64 MiB) |
| `<phase>.rules` | list | required | 1 to 64 rules of `{find, replace}` (literal) or `{regex, replace}` (RE2; `$1` groups in `replace`), each with an optional `max` count (0 means all) |

A body is buffered up to `max_bytes` and rewritten in memory; a larger
body, one the upstream already encoded (`Content-Encoding`), a range
and any media type outside the list pass through untouched, so the
filter never breaks a download. After a change `Content-Length` is set
and `ETag` and `Content-MD5` removed; nothing changes when no rule
matched. The access log carries `body_rewrite: request`, `response` or
`request,response` on lines where a body changed. Response rewriting
runs before compression and after the WAF's response inspection, so
the WAF sees the upstream's bytes and the client sees the rewritten
ones. Put the filter on the routes that need it rather than on every
route: buffering costs memory per request up to the bound.

## tracing

Every request gets a W3C trace context: an incoming `traceparent` is
continued (its trace id kept, a fresh span id issued, `tracestate`
passed through), otherwise a new trace starts. The proxy records one
server span per request (method, path, host, protocol, status, client
address, request id, route, upstream, denial reason) and one client
span per upstream exchange (endpoint, status, attempts, or the error),
sends `traceparent` and `tracestate` to the upstream so its spans hang
under the client span, and writes `trace_id`, `span_id` and
`trace_sampled` into the access log. Spans are exported as OTLP/HTTP
JSON when `otlp` is set; without it the context is propagated and
logged only. Sampling is decided locally by `sample_percent`; an
incoming sampled flag is honoured only with `trust_incoming`, so a
client cannot push every request into the exporter. `xproxyctl
telemetry` and `GET /v1/telemetry` show the counters.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Switch for the section |
| `sample_percent` | 0 to 100 | `100` | Share of traces recorded and exported; propagation happens regardless |
| `propagate` | bool | `true` | Send `traceparent` and `tracestate` to the upstream; off, an incoming header is stripped |
| `trust_incoming` | bool | `false` | Honour the sampled flag of an incoming `traceparent` (behind a trusted balancer that samples) |
| `redact_client_address` | bool | `true` | Run a span's `client.address` through `logging.redaction`'s `client_ip` rule. A span is not a log line, so nothing else takes it through the redactor: without this a deployment that turned redaction on to pseudonymise addresses still exported the full address to its trace collector, beside a trace id the access log also carries. The host and the path on a span are still outside redaction |
| `otlp` | object | none | Span exporter with the same keys as `logging.otlp` (`endpoint` is the traces URL, `/v1/traces`) |

A reload that changes the section rebuilds the tracer; spans in flight
finish on the old exporter, which is flushed and stopped.

## compression

gzip for the responses the proxy writes: proxied, cached, static and
`respond` bodies alike. The decision is made per response when its
header is committed: the client must list `gzip` (or `*`) in
`Accept-Encoding` with a non-zero quality, the request must not be
`HEAD`, an upgrade or gRPC, the status must carry a body (not 1xx, 204,
206, 304), the response must carry no `Content-Encoding` or
`Content-Range`, no `Cache-Control: no-transform`, and a media type from
`types`. A known `Content-Length` below `min_bytes` passes as it is;
without a known length the body is held up to `min_bytes` before
deciding, and a flush (a streamed response, which is how proxied bodies
arrive) decides at once for compression when the type matches.
Compressed responses lose `Content-Length`, gain `Content-Encoding:
gzip`, and a strong `ETag` becomes weak; every response of an eligible
type gains `Vary: Accept-Encoding` so caches keep the variants apart.
Bodies the upstream already encoded pass through untouched. Only gzip
is offered (the standard library has no Brotli); a client that prefers
Brotli still receives gzip when it accepts it. The access log has
`encoding: gzip`; `compressed` and `compressed_raw_bytes` count.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Switch for the section |
| `level` | int | `5` | gzip level 1 (fastest) to 9 (smallest) |
| `encodings` | list | `[br, zstd, gzip]` | Content encodings offered and the server's preference among encodings the client accepts with equal quality; a client's higher `q` wins; `*` in `Accept-Encoding` matches the offered ones |
| `brotli_level` | int | `4` | Brotli quality 0 (fastest) to 11 (smallest); above 6 the CPU cost grows quickly for dynamic responses |
| `zstd_level` | int | `2` | zstd level 1 (fastest), 2 (default), 3 (better) or 4 (best) |
| `min_bytes` | int | `1024` | Bodies below this length are not compressed; 0 to 1 MiB |
| `types` | list | text, script, style, JSON, XML, SVG, wasm and font types | Media types compressed, without parameters |
| `compress_authenticated` | bool | `false` | Compress the response to a request that carried `Authorization` or a `Cookie`. Compressing a body that mixes a secret with attacker-chosen text leaks the secret through its length, one character at a time (BREACH), and a request a browser sends with the victim's cookies is exactly what an attacker can arrange. Turn it on per route (`routes[].compress_authenticated`) where the response holds no secret, or where the application already masks its tokens |

The default `types` are `text/html`, `text/plain`, `text/css`,
`text/csv`, `text/xml`, `text/javascript`, `application/javascript`,
`application/json`, `application/ld+json`,
`application/manifest+json`, `application/xml`,
`application/xhtml+xml`, `application/rss+xml`,
`application/atom+xml`, `image/svg+xml`, `application/wasm`,
`font/ttf`, `font/otf` and `application/vnd.api+json`. Images, video,
archives and fonts in `woff2` are already compressed and are never
listed by default. Compressing responses that mix a secret with
attacker-controlled input in one body exposes the BREACH class of
attacks; keep `compress: false` on routes that render CSRF tokens next
to reflected parameters, or make sure the application masks its tokens.

## cache

An in-memory response cache. The section sizes it; routes opt in with
`routes[].cache`. The cache is owned by the process, not by a
configuration generation, so a reload keeps its contents (and resizes
it); a restart empties it.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `max_bytes` | int | `67108864` (64 MiB) | Total bound; least recently used entries are evicted |
| `max_object_bytes` | int | `1048576` (1 MiB) | Largest response stored; larger ones stream through uncached |

### routes[].cache

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `ttl` | duration | `60s` | Lifetime when the response has no `max-age`, `s-maxage` or `Expires`, or with `ignore_cache_control` |
| `methods` | list | `[GET, HEAD]` | Only GET and HEAD can be cached; HEAD is served from GET's entry |
| `statuses` | list of int | `[200, 203, 204, 300, 301, 404, 410]` | Statuses stored |
| `query` | `all`, `none`, `listed` | `all` | Whether the query string is part of the key, or only the sorted `query_params` |
| `query_params` | list | | Names for `query: listed` |
| `headers` | list | | Request headers whose values join the key (for example `Accept-Encoding` when the upstream sends no `Vary`) |
| `cookies` | bool | `false` | Cache requests that carry a `Cookie` header; off, such requests bypass the cache |
| `ignore_cache_control` | bool | `false` | Store regardless of the response's `Cache-Control` and apply `ttl` |

What is never cached: requests with `Authorization` (unless the response
says `Cache-Control: public`) or `Range`; responses with `Set-Cookie`,
`Cache-Control: no-store`, `no-cache` or `private`, `Vary: *`, or a body
above `max_object_bytes`. `Vary` is honoured: one entry per combination
of the named request headers. Hits carry `X-Cache: HIT` and `Age`,
answer `If-None-Match` and `If-Modified-Since` with 304, and skip the
response filters (which ran when the entry was stored); misses carry
`X-Cache: MISS`; bypassed requests `X-Cache: BYPASS`. The access log has
`cache`. `GET /v1/cache` and `xproxyctl cache` show counters;
`DELETE /v1/cache?host=&path=` and `xproxyctl cache purge [HOST
[PATH-PREFIX]]` remove entries (audited).

## geoip

A country database for `routes[].geo` and for rate limits keyed on
`country`. Exactly one source:

| Key | Type | Description |
|-----|------|-------------|
| `database` | path | A MaxMind DB file with `country.iso_code` (GeoLite2 Country, GeoIP2 Country, DB-IP Lite in MMDB form). Read by the built-in reader, no external library |
| `csv` | path | Lines of `network,country` (CIDR and ISO 3166-1 alpha-2), a header row allowed; longest prefix wins |

The file is read at load and on every reload (replace the file and
reload to update). Lookups are cached per address. Status: `xproxyctl
geoip`, `xproxy_geoip_lookups_total`, `xproxy_geoip_unknown_total`. The
country is written to the access log line as `country` and passed to
filters in `Info.Country`.

### routes[].geo

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `allow` | list of codes | | When set, only these countries are admitted |
| `deny` | list of codes | | Denied first, before `allow` |
| `unknown` | `allow`, `deny` | `allow` | Addresses the database does not know (private ranges, new allocations) |

Denies answer 403 with reason `geo` and feed ban triggers under the `geo`
category. A `rate_limits[].key` of `country` keeps one bucket per
country; an unknown country falls back to the client address.

### routes[].policy

The route's positive security model: what a request may look like.
Everything outside it is refused right after route matching, before
virtual patches' successors (rate limits, filters, the WAF) spend work
on the request, with a terse status, reason `policy` and a `detail`
attribute in the security event naming the check (`method:DELETE`,
`content_type:application/xml`, `query:id:not_int`, `header_count:41`
and so on). Refusals count in `denied_policy` and feed ban triggers
under `policy`. `routes[].methods` selects the route; `policy.methods`
refuses, with 405 and an `Allow` header.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `methods` | list | any | Allowed methods (upper case); others get 405 with `Allow` |
| `content_types` | list | any | Media types allowed for requests with a body, exact (`application/json`) or `type/*`; parameters such as `charset` are ignored; others get 415 |
| `require_content_type` | bool | `false` | A body without `Content-Type` gets 415 |
| `max_uri_length` | int | server limit | Lower bound on the request URI for this route (414) |
| `max_query_bytes` | int | none | Bound on the raw query string (414) |
| `max_query_params` | int | none | Bound on the number of parameters, repeats counted (400) |
| `max_headers` | int | none | Bound on the number of header fields (431) |
| `max_header_bytes` | int | none | Bound on the sum of header names and values (431) |
| `query` | list | `[]` | Parameter descriptions; see below |
| `deny_unknown_query` | bool | `false` | Parameters not in `query` get 400; requires `query` |

Each `query` entry:

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | string | required, unique | |
| `type` | `string`, `int`, `number`, `bool`, `uuid`, `enum` | `string` | `bool` accepts `true`, `false`, `1`, `0`; `uuid` the 8-4-4-4-12 hex form; `enum` needs `values` |
| `required` | bool | `false` | The parameter must be present |
| `max_length` | int | none | Bound on each value in bytes |
| `pattern` | regex | none | Every value must match the whole expression |
| `values` | list | | Allowed values for `enum` (1 to 1024) |
| `max_repeat` | int | `1` | How many times the parameter may appear |

A malformed query string (bad percent encoding) is refused when the
route has a `query` list or `max_query_params`. Bodies are not part of
the policy: `waf.profiles[].json_schemas` and the `openapi` filter
validate them.

## acme

Required when any listener has `tls.acme` groups. One account per proxy;
the account key, account URL and issued certificates live under
`state_dir` (mode `0700`, files `0600`), so a restart serves the existing
certificates immediately and only renews what is due.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `directory` | `https://` URL | required | The CA's directory (RFC 8555) |
| `email` | address | required | Account contact |
| `accept_terms` | bool | must be `true` | Agree to the CA's terms on registration |
| `ca_file` | path | system pool | Pins the CA of the directory server (private CAs, tests) |
| `state_dir` | absolute path | `/var/lib/xproxy/acme` | Account and certificates; must be writable by the service (it is under `StateDirectory` in the shipped unit) |
| `challenge` | `http-01`, `tls-alpn-01` | `http-01` | `http-01` answers `/.well-known/acme-challenge/` on every plaintext listener before the HTTPS redirect and routing; `tls-alpn-01` answers the `acme-tls/1` ALPN on the TLS listener |
| `renew_before` | duration | `720h` | Renew when less than this remains; 24h to 89 days |
| `check_interval` | duration | `12h` | How often expiry is checked; 1m to 7d. A failed order backs off one hour |

Orders use a fresh P-256 key per certificate and an ES256 account key.
A certificate is installed only after the returned chain is verified to
cover every host in the group. Status is at `GET /v1/acme` and
`xproxyctl acme`; `xproxyctl acme renew` forces renewal of every group
and waits for the outcome (a renewal already running is joined, not
duplicated).

## shedding

Present means enabled. The load level is the larger of the in-flight
ratio (`in_flight / max_concurrent_requests`) and the latency level
(`(latency - target) / target`, capped at 1, where latency is the average
upstream time to first byte over `window`). A class is shed with 503 while
the level is at or above its threshold and admitted again once the level
falls below the threshold minus `hysteresis`. Critical routes are never
shed. A window without samples drains the latency signal, so shedding
never locks in.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `target_latency` | duration | `250ms` | Upstream time to first byte the site is designed for |
| `window` | duration | `10s` | Averaging window; 1s to 10m |
| `low`, `normal`, `high` | float | `0.6`, `0.8`, `0.95` | Shed thresholds per class; must be non-decreasing |
| `hysteresis` | float | `0.1` | Readmission margin below the threshold |
| `retry_after` | duration | `2s` | `Retry-After` on shed responses |

### routes[].priority_class

`low`, `normal` (default), `high` or `critical`. Put health checks, login
and payment on `critical` or `high`; search, feeds and exports on `low`.

### routes[].client_priority

`ignore` (default) or `lower`: what to do with a client's RFC 9218
`Priority` request header.

A client knows things about its own requests that this proxy cannot see —
that one fetch is a prefetch for a page nobody has asked for yet, that
another is blocking the render — and RFC 9218 is how it says so: a
`Priority` field carrying an urgency from 0 (most urgent) to 7, default 3,
and an `i` flag for a response that can be used as it arrives.

With `lower`, a stated urgency above the default moves the request **down**
the shedding order: 4 or 5 gives up one class, 6 or 7 goes to `low`, and
0 to 3 change nothing. It can only ever lower. A header that could raise a
request's class would be a promotion anybody can ask for, and the first
thing a client under pressure would do is claim urgency 0 — which would
make shedding protect whoever asked loudest instead of whatever the
operator called important. Lowering is safe in a way raising is not,
because it can only cost the client that asked for it.

The header is forwarded to the upstream unchanged either way, and a
malformed one is ignored rather than refused: a hint that only ever lowers
its own request is not worth failing a request over. `priority_urgency`
appears in the access log when a request stated one, with
`priority_class` beside it when it changed the class. Nothing sheds
without a `shedding` section, and validation says so.

### routes[].early_hints

`pass` (default) or `strip`: what to do with the upstream's 1xx
informational responses, of which 103 Early Hints (RFC 8297) is the one in
use. A 103 lets a server tell the browser which stylesheets and scripts to
start fetching while the real response is still being assembled.

`pass` relays them, which is what a browser wants. `strip` drops them, for
a deployment whose clients or middleboxes mishandle them.

At most eight informational responses are relayed per exchange either way:
each one is a header block the upstream can make this proxy write to the
client, and a flood of them is a response that never ends.

A 1xx is not the final status, and this proxy no longer records it as one —
before, a response preceded by 103 was logged with status 103 and reached
the client only because `net/http` sent an implicit 200 with the
accumulated headers.

### routes[].early_data

`safe_methods` (default), `allow` or `reject`: what to do with a request
that arrived as unconfirmed TLS 1.3 early data.

Early data saves a round trip and gives up what a completed handshake
provided: an attacker who captured those bytes can send them again, and the
server cannot tell the copy from the original. RFC 8470 is how the hops say
so — the request carries `Early-Data: 1` while it is unconfirmed, and a
server that cannot decide whether a replay is safe answers **425 Too
Early**, which tells the client to send it again on the finished
connection.

`safe_methods` serves `GET`, `HEAD`, `OPTIONS` and `TRACE` and answers 425
to everything else, which is RFC 8470's advice for a proxy: this one cannot
know what a second `POST` would do. `reject` answers 425 to all of it, for
a route where even a repeated read matters. `allow` passes it through, and
validation says what that means.

This proxy's own TLS server never accepts early data, so the header only
arrives from a terminator in front — and only from a peer inside
`trusted_proxies` does it count. A client's own `Early-Data: 1` decides
nothing and is removed before the upstream sees it, because the upstream
cannot tell the proxy's copy from the client's. `early_data` appears in the
access log for a request that arrived on it, and a refusal is logged as
`early_data`.

### routes[].ranges

Bounds byte range requests (RFC 9110 section 14). Without the section a
`Range` header is relayed as it arrived.

A `Range` header is a small request asking for a large answer, and a *set*
of ranges is a small request asking for many: each range costs the origin
a read and the response a multipart part, so a header naming two hundred
of them asks one machine to assemble a response dozens of times the size
of the resource from a packet. That is the oldest amplification bug in
HTTP, and the gateway is where it can be judged — before any of that work
is done.

RFC 9110 section 14.2 leaves the decision here: a server **may** coalesce
ranges that overlap or are separated by a gap smaller than the overhead of
another part, "regardless of the order in which the corresponding
byte-range-spec appeared", and a server that will not satisfy a range set
may ignore the header and answer the whole representation. So this rewrites
the set rather than inventing a rule: the same bytes, fewer parts.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `max_ranges` | int | `4` | How many ranges a set may still hold **after** coalescing; 0 means the default, up to 1024 |
| `coalesce` | bool | `true` | Merge overlapping and adjacent ranges into the fewest that cover the same bytes, and sort them. Off, a set is counted as it arrived, so a client that overlaps its ranges is refused for asking twice for the same bytes (validation says so) |
| `action` | `ignore`, `refuse` | `ignore` | What happens to a set still over the bound: `ignore` drops the header, so the whole representation is served, which is what RFC 9110 permits; `refuse` answers **416** with `Accept-Ranges: bytes`, so a client can ask again for fewer |

```yaml
routes:
  - name: downloads
    paths: ["/downloads/"]
    upstream: files
    ranges: {max_ranges: 4}
  - name: media
    paths: ["/media/"]
    upstream: files
    # A player seeks; it does not ask for a hundred pieces at once.
    ranges: {max_ranges: 8, action: refuse}
```

What is not guessed at:

- **Another unit is left alone.** `Range: items=0-9` is passed through:
  an origin that does not implement a unit ignores the header, and this
  proxy has nothing to say about a unit it cannot read.
- **A header that is not a range set is dropped**, once, here — a
  malformed value, a spec with no dash, a descending range, more specs
  than are worth reading (256). RFC 9110 says a recipient that cannot
  parse the header ignores it; deciding that in one place is what keeps
  this proxy and the origin reading the request the same way.
- **A suffix range is kept as it is.** `-500` means the last 500 bytes,
  and how that overlaps `0-99` depends on a length this proxy does not
  know. The largest suffix covers the smaller ones; nothing else about
  them is assumed.

`ranges` and `ranges_sent` appear in the access log for a request the
policy acted on, a refusal is logged as `ranges`, and
`xproxy_ranges_total{result="dropped"|"refused"}` counts them
(`ranges_dropped` and `ranges_refused` in `xproxyctl status`).

### routes[].threat_intel

`true` (default) or `false`: whether the imported `threat_intel` lists
apply to this route.

`false` exempts it. A list is an import, and an import with one wrong
line in it must not take the health endpoint an operator watches the
outage with, or the status page they diagnose it from. The ban list is a
separate decision and still applies: a ban is this proxy's own finding
about that client.

### routes[].trailers

`pass` (default) or `strip`: the fields an upstream sends after the body —
a checksum, a signature, gRPC's status.

`strip` removes both the announcement and the fields. An announced trailer
with nothing behind it leaves a client waiting for a field that never
arrives, so the two go together. It is refused on a gRPC route: gRPC
carries its status in the trailers, and a route that strips them answers
every call with no status at all.

## maintenance

Present means the maintenance gate is available; `enabled` is the state
at start and the runtime toggle (`POST /v1/maintenance`, `xproxyctl
maintenance on|off`) overrides it and survives reloads. While it is on,
every request is answered with `status` and `Retry-After` except an
allowlisted client and a route with `maintenance: false` (health and
status endpoints). The gate runs right after routing, before
authentication, rate limits and filters.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Maintenance on at start |
| `status` | int | `503` | Status of held requests (4xx or 5xx) |
| `retry_after` | duration | `5m` | `Retry-After` header; 0 omits it |
| `message` | string | a short text | Response body |
| `allow_cidrs` | list | `[]` | Clients always served |
| `allow_header` | `Name: value` | none | A request carrying this exact header is served (a shared bypass token) |

A route sets `maintenance: false` to stay up during maintenance or
`maintenance: true` to be held even when the gate is off.

## challenge

Present means the challenge engine is available; routes opt in with a
`challenge` block. Unverified clients receive a 503 page with a signed
nonce and a script that finds a SHA-256 proof of work, posts it to
`/.xproxy/challenge`, and receives a signed cookie. Both reserved paths
(`/.xproxy/challenge` and `/.xproxy/challenge.js`) are served on every
host before routing.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `secret_file` | path | ephemeral | HMAC key or keyring for nonces and cookies; set it so cookies survive restarts and are valid across a cluster; a rotation is picked up on reload and cookies under the kept keys stay valid |
| `difficulty` | int | `16` | Leading zero bits required; 8 to 24. 16 is roughly 65 000 hashes, under a second in a browser |
| `ttl` | duration | `1h` | Validity of a passed challenge; at least 1m |
| `bind_ip` | bool | `true` | Cookie and nonce are bound to the client address |
| `bind_ja4` | bool | `false` | Bind the cookie to the client's JA4 TLS fingerprint (token binding): a cookie earned by one TLS client is refused when replayed by another, even from the same address. TLS only; a request without a fingerprint is treated as a distinct binding |
| `cookie_scope` | `shared`, `host` | `shared` | `host` binds the pass to the host that served the challenge. The nonce is host-bound already, so with `shared` a client can solve the cheapest host's challenge and spend the cookie on the host that asks for the most work. Use `host` when hosts behind one proxy differ in difficulty or tier; leave it `shared` when a pass is meant to cover a site's several names. Changing it invalidates every outstanding cookie once |
| `cookie_name` | token | `XPCHAL` | |
| `exempt_cidrs` | list | `[]` | Never challenged (monitoring, partners) |
| `title` | string | `Checking your browser` | Heading on the page; no HTML characters |
| `device` | bool | `true` | The script derives a device identifier from stable browser properties (user agent, languages, platform, cores, memory, screen, pixel ratio, time zone, a canvas rendering) and the cookie carries its first eight bytes: `device` in the access log, `Info.DeviceID` for filters and the `device` rate limit key; the script also reports automation markers (WebDriver, driver globals, chromedriver, headless user agent, no languages, no plugins, zero sized window), carried as `automation` in the access log and `Info.Automation` for the `bot_score` and `account_guard` filters. Client supplied and therefore advisory, but fixed into the cookie it earned |
| `captcha` | mapping | none | A hosted CAPTCHA tier, below |

### challenge.captcha

Adds a second tier to the challenge. A verdict that asks for it (an
`account_guard` step or `disposable` action `captcha`, a `distributed`
action `captcha`) renders the provider's widget instead of the proof
of work; a client that solved only the proof of work is challenged
again, and a client that passed the CAPTCHA satisfies both tiers. The
token is verified with the provider from the proxy (`siteverify`, with
the client address), fails closed when the provider is unreachable or
rejects it, and the failure is a `challenge_failed` security event
naming the class (`captcha rejected`, `captcha score`, `captcha
unreachable`). The page's Content Security Policy admits the provider's
script and frame origins only. Without this section a CAPTCHA verdict
falls back to the proof of work.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `provider` | `turnstile`, `hcaptcha`, `recaptcha` | required | Cloudflare Turnstile, hCaptcha or Google reCAPTCHA (v2 checkbox, v3 or Enterprise with `min_score`) |
| `site_key` | string | required | Public key rendered into the widget |
| `secret_file` | path | required | The provider secret on one line; re-read on reload |
| `verify_url` | URL | the provider's | Override for enterprise endpoints or tests (https, or http to localhost) |
| `timeout` | duration | `5s` | Verification call (500ms to 30s); the call uses no environment proxy |
| `min_score` | float | `0` | Refuse tokens scored below it (providers that return a score); 0 disables |
| `mode` | `escalation`, `always` | `escalation` | `always` shows the widget on every challenge page, including route gates, in place of the proof of work |
| `hostnames` | list | the hosts the routes name | Host names the provider may report the token was solved on. Empty falls back to the host names `routes[].hosts` configure; a hostname in neither list, and a provider that omits it, are refused. The request host is not an allowlist — the client chooses it, so an attacker who points a name of their own at this proxy would only have to be consistent — so validation refuses a configuration where neither list exists |
| `hostname_check` | bool | `true` | Verify the hostname the provider reports; turn off for providers that do not return one |

### routes[].cors

A Cross-Origin Resource Sharing policy. A preflight `OPTIONS` (one that
carries `Access-Control-Request-Method`) is answered by the proxy with
`204` before authentication, rate limits and filters, since it carries
no credentials; an actual request from an allowed origin gets the
response headers added, and the route's policy replaces any the
upstream set. This is separate from `grpc.web_origins`, which handles
gRPC-web preflights.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `allow_origins` | list | required | Permitted `Origin` values: exact (`https://app.example`), a single `*` (any origin, incompatible with `allow_credentials`), or a wildcard host (`https://*.example.com`, matching one or more whole labels). A wildcard must be a whole leading label followed by at least two more: `https://*example.com` is refused because it would also admit `evilexample.com`, and `https://*.com` or `https://*.co.uk` (a public suffix) because every site under it would be allowed |
| `allow_methods` | list | `GET, HEAD, POST, PUT, PATCH, DELETE` | `Access-Control-Allow-Methods` of a preflight |
| `allow_headers` | list | reflect the request | `Access-Control-Allow-Headers`; `*` or empty reflects the preflight's `Access-Control-Request-Headers` |
| `expose_headers` | list | `[]` | `Access-Control-Expose-Headers` on actual responses |
| `allow_credentials` | bool | `false` | Sets `Access-Control-Allow-Credentials: true` and echoes the exact origin, never `*` |
| `max_age` | duration | `10m` | `Access-Control-Max-Age`, 0 to 24h |

### routes[].challenge

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `mode` | `off`, `always`, `load` | `always` | `load` challenges only while the shedding load level is at or above `level` and requires a `shedding` section |
| `level` | float | `0.5` | Activation level for `load` mode |

The challenge is for browser-facing routes: API clients cannot solve it.

## sandbox

In-process hardening applied once the listeners, log files, state files
and the management socket are open (docs/HARDENING.md section 1a,
docs/HARDENING_MACOS.md on macOS). On by default; `GET /v1/sandbox` and
`xproxyctl sandbox` show what was applied. The Landlock rules are derived
from the configuration: the directory of every configured file is
readable, the log, state, history, capture and certificate directories are
writable, and nothing else is reachable. A reload that names a file
outside those directories is refused with a message to restart.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Apply the sandbox |
| `strict` | bool | `false` | Refuse to start when a mechanism the platform should offer is unavailable or fails, instead of logging a warning |
| `landlock.enabled` | bool | `true` | Landlock file system rules (Linux 5.13 or newer with the LSM enabled) |
| `landlock.read_paths` | list of paths | `[]` | Extra files or directories the process may read (a compiled-in filter that opens files, a directory that reloads will add files to) |
| `landlock.write_paths` | list of paths | `[]` | Extra directories the process may write |
| `landlock.bind` | bool | `true` | Refuse TCP binds after start (Landlock ABI 4, Linux 6.7 or newer); listeners are bound before the sandbox and adding one needs a restart anyway |
| `seccomp.enabled` | bool | `true` | System call deny list: tracing, module loading, mounts, namespaces, keyrings, BPF, io_uring, identity changes, exec and kernel administration return EPERM (Linux amd64 and arm64) |
| `capabilities.drop` | bool | `true` | Clear the bounding, ambient, permitted, effective and inheritable sets (Linux) |
| `no_new_privs` | bool | `true` | Set PR_SET_NO_NEW_PRIVS (required by Landlock and unprivileged seccomp; systemd's `NoNewPrivileges=` sets it too) |
| `debuggable` | bool | `false` | Keep the process attachable by a debugger and able to dump core; the default makes it non dumpable with a zero core size limit (Linux), or denies debugger attachment with a zero core size limit (macOS) |

## capture

Present and `enabled: true` means the proxy can write the exchanges it
handled as pcapng files, which Wireshark, tshark and any other pcap
reader open directly.

The proxy terminates TLS, so there is no point on the wire where the
exchange is both complete and readable: in front of the proxy it is
ciphertext, and behind it the client is gone and the request carries the
proxy's own address. What this section writes is the proxy's view — the
request as it arrived after the header edits, the response as the client
received it — synthesised into a TCP conversation (handshake, data
segments at a 1460 byte MTU, orderly close) between the real client
address and the listener address, so a dissector reads it as HTTP and
`Follow TCP stream` shows the exchange. It is a faithful record of what
the proxy saw and sent, not a byte for byte record of the packets that
carried it: segment boundaries, sequence numbers and the frame
timestamps are the proxy's, and TLS, HTTP/2 framing and HTTP/3 are gone
by the time it is written (an HTTP/2 or HTTP/3 exchange is rendered with
an `HTTP/1.1` start line, because a dissector needs one).

> **The files hold decrypted traffic.** Session cookies, bearer tokens,
> API keys and whatever personal data the application carries are in
> them in the clear. They are created `0600` in a directory the operator
> names, the proxy chooses the file names and writes nothing else there,
> and `redact` blanks the header values that should not be on disk at
> all — but the directory still has to be treated like an access log
> with redaction turned off: not on a shared volume, not in a backup
> that travels, and removed when the investigation is over. Bodies are
> off by default for the same reason.

Recording has two independent switches, and both have to be on for a
byte to be written. The configuration decides *what may be* captured —
`enabled`, and the `rules` that select flows — and it reloads. The
runtime switch decides *whether it is* being captured now, and it is
off unless `start_active` is set: `xproxyctl capture start` turns it on,
`xproxyctl capture stop` turns it off, and it turns itself off after
`max_duration` so a capture started during an incident cannot be left
running for a month (a capture that began at start-up because
`start_active` is set runs until something turns it off: the bound is
on the window an operator opens). That shape is deliberate: the usual deployment
carries a capture section that is ready and idle, and an operator throws
the switch for one reproduction. A reload keeps the switch exactly as it
was, deadline included.

`rules` is where "only a certain flow, or all flows" is decided. A rule
matches when every selector it names holds; a rule that names no
selector matches everything, and a section with rules omitted behaves as
one such rule. The first rule that matches decides, so the broad
catch-all goes last. Selectors that are only known once the exchange is
over — `statuses`, `reasons`, `denied` — hold the request and response
until then and write the whole flow retrospectively, so a rule for "the
403s only" still produces a complete conversation. That includes a
refusal decided before routing (a ban, the maintenance gate, a
malformed `Host`): there is no route to match on, so only the
answer-side selectors can want it, and it is written without bodies
because nothing read them.

```yaml
capture:
  enabled: true
  directory: /var/lib/xproxy/capture
  max_file_bytes: 67108864      # 64 MiB, then rotate
  max_files: 4                  # keep four, oldest removed
  max_duration: 30m             # a window an operator forgets ends itself
  bodies: true
  max_body_bytes: 65536
  redact: [authorization, cookie, set-cookie, x-api-key]
  rules:
    # The reproduction: one client, one API route, everything it does.
    - name: reported-client
      routes: [api]
      client_cidrs: ["198.51.100.7/32"]

    # Every refusal, whatever route it was on and whatever refused it.
    - name: denials
      denied: true
      max_flows: 500

    # The WAF's own decisions, for tuning a rule that is too eager.
    - name: waf
      reasons: [waf]

    # A thousandth of the upload traffic, as a baseline.
    - name: sample-uploads
      methods: [POST, PUT]
      paths: [/upload]
      percent: 1
      max_flows: 200
```

`GET /v1/capture` and `xproxyctl capture status` show whether recording
is on, when the window ends, the current file and the counters below;
`POST /v1/capture` with `{"active": true, "duration": "10m"}` (or
`xproxyctl capture start -duration 10m`) opens a window and
`{"active": false}` closes it. `xproxy_capture_flows_total{result}`
counts `captured`, `skipped`, `dropped` and `failed`,
`xproxy_capture_bytes_total` the bytes written, and
`xproxy_capture_active` is 1 while a capture is running — worth an
alert, since a capture left on keeps writing decrypted traffic to
disk. Both mutations are audited with the caller's uid, gid and pid.

The web GUI does not offer any of this. It is a network service, and
starting a capture writes decrypted traffic to disk; the switch stays
on the management socket, where the kernel decides who may throw it.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Build the subsystem. Without it nothing is recorded and the runtime switch has nothing to turn on |
| `start_active` | bool | `false` | Begin recording at start-up instead of waiting for the switch. Records from the first request, including start-up traffic no operator is there for, and keeps recording until something turns it off: `max_duration` bounds a window an operator opens, not this. The usual shape is a section that is ready and idle. Validation says so as advice |
| `directory` | path | required | Absolute path of an existing directory the proxy owns and nothing else writes to. The proxy chooses the file names inside it and removes its own oldest files |
| `file_prefix` | string | `xproxy` | Begins each file name, the rest being the time the file was opened. No path separators, no leading dot |
| `max_file_bytes` | int | `67108864` | Rotate to a new file past this size (1 MiB to 8 GiB) |
| `max_files` | int | `4` | Keep this many files, removing the oldest (1 to 1000) |
| `max_duration` | duration | `1h` | The longest one recording window may run; a `start` without a duration gets this one, and a longer one is shortened to it. At most 24h |
| `snap_len` | int | `262144` | The snapshot length declared in the file (128 to 1048576) |
| `bodies` | bool | `false` | Capture request and response bodies as well as the heads. The heads answer most questions and carry far less of what should not be on disk; a body is where the personal data is |
| `max_body_bytes` | int | `65536` | Bound each captured body. The rest is left out and the flow's comment says `truncated` (0 to 16 MiB; `0` captures heads only even with `bodies: true`) |
| `redact` | list of header names | `authorization`, `proxy-authorization`, `cookie`, `set-cookie`, `x-api-key`, `api-key` | Replace these request and response header values with `REDACTED` in the captured bytes. A fixed string, not a blanked-out one, so neither the value nor its length is in the file. An explicitly empty list turns redaction off, which is a deliberate choice and not the default |
| `rules` | list | `[]` | Which exchanges to write; empty means all of them |

### capture.rules[]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | string | `rules[i]` | Identifies the rule in `GET /v1/capture` |
| `hosts` | list | any | Host patterns, exact or `*.example.com`, matched against the request authority |
| `routes` | list of names | any | Only requests matched to these routes. A request refused before routing (a ban, the maintenance gate) has no route, so it never matches this selector; an answer-side selector is how those are captured |
| `methods` | list | any | Upper-case methods |
| `paths` | list of prefixes | any | Prefixes of the cleaned path |
| `client_cidrs` | list of CIDR | any | Client networks, the derived client address being the one compared |
| `statuses` | list of int | any | Response statuses, or a class as a single digit: `4` is every 4xx. A refused request has the status the proxy answered |
| `reasons` | list | any | Deny reasons (`waf`, `rate_limit`, `ban`, `acl`, `virtual_patch`, ...), matched against the reason and against `reason:detail` |
| `denied` | bool | `false` | Select every refusal, whatever the reason. `true` alone is the "show me what the proxy is blocking" rule |
| `percent` | int | `100` | Sample this percentage of the exchanges the rule would otherwise take (1 to 100). Sampling is per exchange, and a sampled-out exchange is counted as skipped |
| `max_flows` | int | `0` | Stop after writing this many exchanges for this rule, so a rule left on cannot fill a disk. `0` is unbounded, at most 10000000; the count resets on reload |

Selectors within a rule are AND, values within a selector are OR, and
rules are tried in order. To capture one route for one client, put both
selectors in one rule; to capture two unrelated things, write two rules.

## mysql

`kind: mysql` is a relay in front of a MySQL or MariaDB server.

It has the same four jobs as the [postgres](#postgres) kind -- refuse the
encryption downgrade, refuse the weak credentials, refuse what is not a
statement, decide by the shape of what is -- plus two that are MySQL's
alone.

**On MySQL the dangerous operations are commands, not statements.** After
the handshake every client message begins with a one-octet command code, and
several of those carry no SQL at all, so a statement policy would never see
them. `COM_SHUTDOWN` is one octet and stops the server. The three
replication commands are a copy of every change to every database.
`COM_TABLE_DUMP` is a whole table. `COM_PROCESS_KILL` ends somebody else's
query. `COM_DEBUG` writes the server's internals to its error log.
`COM_CREATE_DB` and `COM_DROP_DB` predate the DDL statements and bypass a
statement policy entirely. Hence `allow_commands`, which the postgres kind
has no equivalent of.

Two commands are subtler and are why a capability policy alone is not
enough. `COM_CHANGE_USER` re-authenticates a *live* connection as somebody
else, so a relay that did not read it would have a user policy that applied
to the first message and nothing after it. And `COM_SET_OPTION` turns
`CLIENT_MULTI_STATEMENTS` on **after the handshake is over** -- a policy a
client lifts with one command, unless the relay reads it.

**The relay rewrites the server's greeting.** MySQL's handshake runs the
opposite way round from PostgreSQL's: the server speaks first and advertises
its capabilities, and the client answers. So the relay reads the greeting,
clears the bits `deny_capabilities` names, and forwards the edited one -- a
client that never sees `CLIENT_LOCAL_FILES` offered cannot negotiate it, so
the server can never ask that client for a file, **and the application still
works**. That is the same move the [tftp](#tftp) kind makes with RFC 7440's
window: rewrite rather than refuse, because a control that breaks every
application on a segment is a control somebody switches off. The strip is
logged as an `alert` rather than a refusal, since nothing was denied.

```yaml
- name: app
  address: "10.0.0.20:3306"
  kind: mysql
  tls:
    certificates: [{cert_file: /etc/xproxy/tls/db.pem, key_file: /etc/xproxy/tls/db-key.pem}]
  mysql:
    upstream: my
    allow_clients: ["10.0.2.0/24"]
    allow_users: [app]
    allow_databases: [sales]
    allow_auth: [caching_sha2_password]
    allow_statements: [select, insert, update, delete, show, set, begin, commit, rollback]
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `upstream` | name | *(required)* | The server pool |
| `allow_clients`, `deny_clients` | list of CIDR | any | Networks a client may connect from; deny first |
| `require_tls` | bool | `true` | Refuse a client that does not set `CLIENT_SSL`. The negotiation is a capability flag and nothing signs the server's greeting, so anything on the path can clear the bit and the client never asks. The listener needs a `tls` section |
| `upstream_tls_mode` | `require`, `prefer`, `disable` | `require` | How the relay speaks to the server. Both legs are upgraded independently, which is the only way a relay that reads the protocol can exist |
| `upstream_tls` | object | *(none)* | Certificate and verification settings for that leg |
| `allow_users`, `deny_users` | list | any | Which users a connection may claim. **Re-checked on `COM_CHANGE_USER`** |
| `allow_databases`, `deny_databases` | list | any | Same, for the database |
| `allow_programs` | list | any | Matches the client's `program_name` connection attribute, trailing `*` allowed |
| `allow_auth` | list | any not weak | Plugins the relay will carry: `caching_sha2_password`, `mysql_native_password`, `sha256_password`, `mysql_clear_password`, `mysql_old_password`, and the enterprise ones |
| `allow_weak_auth` | bool | `false` | Permit `mysql_clear_password` (the password itself) and `mysql_old_password` (the pre-4.1 scramble, removed from the server in 5.7). `mysql_native_password` is deliberately **not** in that set: its challenge-response discloses no reusable secret, and treating it as weak would make this setting one operators turn off wholesale. `mysql_clear_password` on an unencrypted connection is refused even when this is true |
| `allow_commands` | list | the driver set | Protocol commands. Empty allows `query`, `stmt_prepare`, `stmt_execute`, `stmt_send_long_data`, `stmt_close`, `stmt_reset`, `stmt_fetch`, `init_db`, `ping`, `quit`, `statistics`, `reset_connection`, `set_option` and `change_user` — and nothing administrative |
| `deny_commands` | list | `[]` | The deny list, which no rule can override |
| `deny_capabilities` | list | `[local_files, multi_statements, compress]` | Bits stripped from the server's greeting. `ssl` **cannot be named**: stripping it would perform the downgrade this kind exists to prevent |
| `read_only` | bool | `false` | Refuse every statement that can change data, `call` and `do` included |
| `allow_statements`, `deny_statements` | list of kinds | any nameable | As the postgres kind names them |
| `allow_load` | list | `[]` | Which `LOAD DATA` forms may cross: `file` (a path on the server, needing the FILE privilege) or `local` (a path on the **client**). Empty allows neither |
| `max_statements` | int | `1` | Statements per query message. The default is 1 because `multi_statements` is stripped by default, so a message carrying more is a client working around the policy |
| `max_statement_bytes` | int | `65536` | One statement |
| `max_message_bytes` | int | `1048576` | One reassembled message. The protocol has no bound at all: a sender may chain 16 MiB packets for ever |
| `max_sessions`, `max_sessions_per_client` | int | unbounded | Concurrent connections |
| `idle_timeout`, `session_duration`, `handshake_timeout` | duration | `0`, `0`, `30s` | |
| `default_action` | `allow`, `deny` | `deny` | When no rule matched |
| `deny_response` | `error`, `drop` | `error` | `error` sends an error packet: 1142 with SQLSTATE 42000 for a refused statement, 1045 with 28000 for a refused connection, which are what the server itself answers |
| `monitor_only` | bool | `false` | Evaluate and do not enforce, except the hard decisions below |

### rules[]

| Key | Type | Description |
|-----|------|-------------|
| `name` | string | Names the rule in logs and counters |
| `clients`, `users`, `databases`, `programs` | lists | Selectors; AND within a rule, OR within one |
| `schedule` | object | `days`, `from`, `to`, `timezone` |
| `action` | `allow`, `deny`, `observe` | Default `allow` |
| `allow_commands`, `deny_commands`, `allow_statements`, `deny_statements`, `allow_load`, `read_only`, `max_statements` | | The rule's own narrowing. A rule that names a command or a kind **widens** the listener for its own traffic; the deny lists always win |

### What shadow mode never shadows

| Refusal | Why it is hard |
|---------|----------------|
| `client_not_allowed` | An address that may not connect |
| `tls_required`, `upstream_no_tls` | The user name and database are inside the handshake response |
| `weak_auth`, `auth_not_allowed`, `cleartext_password_unencrypted` | A credential an observer can reuse is disclosed by being sent |
| `replication_command` | The connection becomes a stream of every change to every database |
| `local_infile`, `load_local` | Forwarding the request means the client's file has already left |
| `change_user` refusals | Otherwise the connection *is* somebody the policy refused while the relay notes that it noticed |
| `statement_unreadable`, `set_option_unreadable`, `empty_command` | The relay has no opinion to observe |
| `statement_too_long` | A bound |

Capability stripping is not in that table because it is not a refusal:
nothing is denied, the connection goes through, and the client simply never
sees the capability offered.

## postgres

`kind: postgres` is a relay in front of a PostgreSQL server that reads the
frontend/backend protocol (the PostgreSQL manual, part IV chapter 55).

**It is not a SQL firewall, and will not become one.** Knowing which
tables a statement touches means parsing SQL properly -- every alias,
subquery, CTE, view, function body and `search_path` interaction -- and a
relay that got that 95% right would have a policy with a hole in exactly
the place somebody is looking. Restricting a role's tables is the
database's own job, done properly, with `GRANT`.

What a relay can do is everything that happens before the database has an
opinion, two things it does better than the database, and one the database
cannot do at all:

- **Refuse the encryption downgrade.** The protocol negotiates TLS in
  cleartext: the client sends eight octets asking, and the server answers
  with one unsigned octet, `S` or `N`. libpq's default `sslmode` is
  `prefer`, which means "ask for TLS and carry on in the clear if refused,
  without telling anybody" -- so the default configuration of the most
  widely deployed client in the world downgrades silently when something
  on the path rewrites that octet. The relay answers the request itself
  rather than forwarding it, and `require_tls` (on by default) refuses a
  client that will not encrypt at all.
- **Refuse the weak authentication methods.** `password` is the password
  in cleartext. `md5` is worse than it looks: the stored verifier is
  `md5(password+username)`, so the hash *is* a password-equivalent and
  anybody who reads `pg_authid` can authenticate without cracking
  anything. PostgreSQL has shipped SCRAM since version 10. `pg_hba.conf`
  can refuse both too, and on every estate that has been audited, it does
  not.
- **Refuse what is not a statement at all**: a replication connection (a
  startup *parameter*, so no statement policy would ever see it), the
  legacy fast-path function call, a cancel request from an address that has
  no business sending one.
- **Decide by the shape of a statement.** An allow list of statement
  *kinds*, where a statement the classifier cannot name is refused. That is
  a much smaller claim than a SQL firewall and it holds.

```yaml
- name: reporting
  address: "10.0.0.10:5432"
  kind: postgres
  tls:
    certificates: [{cert_file: /etc/xproxy/tls/db.pem, key_file: /etc/xproxy/tls/db-key.pem}]
  postgres:
    upstream: pg
    allow_clients: ["10.0.4.0/24"]
    allow_users: [reporting, dashboards]
    allow_databases: [sales]
    allow_auth: [scram]
    read_only: true
    allow_statements: [select, explain, show, set, begin, commit, rollback, fetch, declare, close_cursor]
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `upstream` | name | *(required)* | The server pool |
| `allow_clients`, `deny_clients` | list of CIDR | any | Networks a client may connect from; deny is evaluated first |
| `require_tls` | bool | `true` | Refuse a client that will not encrypt. **The single most valuable line in a postgres listener.** The listener needs a `tls` section, because the protocol upgrades an existing connection rather than using a second port |
| `upstream_tls_mode` | `require`, `prefer`, `disable` | `require` | How the relay speaks to the server. The default is not "match the client" on purpose: a relay that terminated TLS and then spoke plaintext onward would have moved the exposure rather than removed it. `require` refuses a server that answers `N` |
| `upstream_tls` | object | *(none)* | Certificate and verification settings for the leg to the server |
| `allow_users`, `deny_users` | list | any | Which roles a connection may *claim*. It is a claim, not a credential -- the server decides -- so this says which attempts may be made, which is smaller and still useful: an estate where nothing should ever connect as `postgres` can say so and have it hold before a password is guessed at |
| `allow_databases`, `deny_databases` | list | any | Same, for the database. Absent in the startup packet it defaults to the user name, and the policy applies that default |
| `allow_applications` | list | any | Matches `application_name`, trailing `*` allowed. Client-chosen and not a credential; useful for telling a migration tool from a dashboard when both connect as the same role |
| `allow_auth` | list | any not weak | Methods the relay will carry, named as `pg_hba.conf` names them: `password`, `md5`, `scram`, `gss`, `sspi`, `kerberos`, `scm` |
| `allow_weak_auth` | bool | `false` | Permit `password`, `md5` or `scm` -- the methods whose credential an observer can reuse |
| `read_only` | bool | `false` | Refuse every statement that can change data. This includes `call` and `do`, because a procedure and an anonymous block can do anything the role can, and a relay that counted them reads would have a `read_only` that is decorative |
| `allow_statements` | list of kinds | any nameable | The allow list. Kinds: `select`, `insert`, `update`, `delete`, `merge`, `copy`, `call`, `do`, `explain`, `show`, `set`, `reset`, `begin`, `commit`, `rollback`, `savepoint`, `lock`, `prepare`, `execute`, `deallocate`, `declare`, `fetch`, `move`, `close_cursor`, `listen`, `notify`, `unlisten`, `ddl`, `grant`, `maintenance`, `two_phase`, `empty` |
| `deny_statements` | list of kinds | `[]` | The deny list, which no rule can override |
| `allow_copy` | list | `[in, out]` | Which `COPY` may cross: `in` (FROM STDIN), `out` (TO STDOUT), `file` (a path on the server, needing a privileged role). **`program` cannot be named at all** |
| `allow_replication` | bool | `false` | Permit a startup packet asking for a replication stream, which is a byte-for-byte copy of every database on the server including the role passwords |
| `allow_function_call` | bool | `false` | Permit the legacy fast-path interface, which names a function by object identifier and bypasses the parser |
| `allow_cancel` | bool | `true` | Permit a `CancelRequest`. Worth knowing: the server acts on one with no authentication at all -- the whole credential is a process identifier and a 32-bit secret. The relay cannot check the secret, so it refuses one from an address that is not an admitted client, and counts them |
| `max_statements` | int | `8` | Statements per message. The simple query protocol allows several separated by semicolons, which is how every injection ending in `; DROP TABLE` is delivered |
| `max_statement_bytes` | int | `65536` | One statement |
| `max_message_bytes` | int | `1048576` | One protocol message. The protocol's own limit is the 4-byte length field, which is two gigabytes |
| `max_sessions`, `max_sessions_per_client` | int | unbounded | Concurrent connections |
| `idle_timeout`, `session_duration`, `handshake_timeout` | duration | `0`, `0`, `30s` | |
| `default_action` | `allow`, `deny` | `deny` | When no rule matched |
| `deny_response` | `error`, `drop` | `error` | `error` sends an `ErrorResponse` with SQLSTATE 42501 (insufficient_privilege), which the client's own library reports the way it reports the database's refusals, so an application's existing error handling works |
| `monitor_only` | bool | `false` | Evaluate and do not enforce -- except the hard decisions below |

### rules[]

| Key | Type | Description |
|-----|------|-------------|
| `name` | string | Names the rule in logs and counters |
| `clients`, `users`, `databases`, `applications` | lists | Selectors. Within a rule they are AND; values within one are OR |
| `schedule` | object | `days`, `from`, `to`, `timezone` |
| `action` | `allow`, `deny`, `observe` | Default `allow` |
| `allow_statements`, `deny_statements`, `allow_copy`, `read_only`, `max_statements` | | The rule's own narrowing. A rule that names a kind **widens** the listener for its own traffic, which is what makes one listener serve a reporting account that may only select and a migration account that may also change the schema. The deny lists always win, on the rule and the listener both |

### What shadow mode never shadows

`monitor_only` evaluates the policy and enforces nothing, with these
exceptions -- forwarding any of them and writing it down is not a trial of
anything:

| Refusal | Why it is hard |
|---------|----------------|
| `client_not_allowed` | An address that may not connect |
| `tls_required` | The identity is *inside* the startup packet, so a packet that crossed in the clear has already disclosed the role and database |
| `weak_auth`, `auth_not_allowed` | A credential an observer can reuse is disclosed by being sent |
| `replication_not_allowed` | The connection becomes a copy of the whole server |
| `statement_unreadable` | The classifier could not name the statement, so the relay has no opinion to observe |
| `copy_program` | `COPY ... FROM PROGRAM` runs a shell command as the server's operating-system user |
| `function_call` | The fast-path interface bypasses the parser |
| `statement_too_long` | A bound |

### How a statement is classified

A deny list of strings is a list of the spellings somebody thought of:
`DROP` does not stop `DR/**/OP`, and a statement that merely *mentions*
the word in a string literal is innocent. So the classifier reads the
leading keyword of every statement after stripping comments and quoting
properly -- PostgreSQL's block comments nest, and dollar-quoted strings
have no escaping at all -- and anything it cannot name becomes `unknown`,
which is refused. The failure mode of a spelling nobody thought of is a
refusal rather than a pass.

Three cases it is deliberately conservative about, because when a
classifier must be wrong it must be wrong towards the more restricted
answer:

| Written | Classified as | Why |
|---------|---------------|-----|
| `WITH x AS (DELETE FROM t ...) SELECT ...` | `delete` | A data-modifying CTE is a write wearing a SELECT's leading keyword |
| `EXPLAIN ANALYZE INSERT ...` | `insert` | `ANALYZE` executes the statement it explains. Plain `EXPLAIN` does not, and is `explain` |
| `COPY t FROM PROGRAM '...'` | `copy` + program | Three operations share one keyword and one of them is remote code execution |

Text that cannot be lexed at all -- an unterminated quote, comment or
dollar quote -- is refused rather than classified, because the relay and
the server would disagree about where the statement ends, and disagreeing
about that is how a statement gets past a relay that read a different one.

## tds

`kind: tds` is a relay in front of a Microsoft SQL Server, or anything else
speaking TDS.

It has the [postgres](#postgres) kind's four jobs -- refuse the encryption
downgrade, refuse the credential that crosses in the clear, refuse what is not a
statement, decide by the shape of what is -- and two that belong to SQL Server.
Like the other two, **it is not a SQL firewall and will not become one**:
restricting a login's tables is the database's job, with `GRANT`.

**The password is an encoding, not a secret.** A `LOGIN7` carries the password
with its nibbles swapped and XORed with 0xA5. There is no key. Anybody who read
the packet has the password, so `require_tls` here is not hardening -- it is the
difference between a reusable credential on the wire and none. There is no
equivalent of `allow_weak_auth` on this kind because there is no stronger
method to contrast one with, short of integrated security; the only credential
setting is `allow_cleartext_password`, named for exactly what it permits.

And the negotiation that decides whether the connection is encrypted is one
octet in a `PRELOGIN` option table, answered by the server, signed by nothing:

| Value | Means | On the wire |
|-------|-------|-------------|
| `off` (0x00) | "I would rather not" | plaintext -- and what a great deal of deployed software sends |
| `on` (0x01) | "let us" | encrypted |
| `not_supported` (0x02) | "I cannot" | plaintext -- and what something on the path rewrites the *server's* answer to |
| `required` (0x03) | "I will not continue without it" | encrypted |

`off` reads like a preference and `not_supported` reads like a capability, and
their wire consequence is identical. A client that asked for `off` and hears
`not_supported` proceeds in the clear without complaint, which is the third time
this shape has appeared after PostgreSQL's `SSLRequest` octet and MySQL's
`CLIENT_SSL` bit -- and it gets the same answer. The relay does not forward the
server's value: with `require_tls` on it answers every client `required`, so
every client becomes one the downgrade cannot touch, and it negotiates the leg
to the server separately. Each connection whose negotiation it raised is logged
as `tds_encryption_forced`, which is the list to read **before** turning the
setting on rather than after: every client on it is one that would have gone in
the clear, and one that will fail if it turns out not to speak TLS at all.

**The dangerous operations are procedures.** Not statements, and not one-octet
commands as on MySQL. `xp_cmdshell` is a shell command running as the service
account; the `sp_OA` family instantiates arbitrary COM objects, which is the
same thing with more steps; the registry procedures read and write the host's
configuration; `sp_addlinkedserver` turns one compromised database into a route
to another; `sp_configure` is how `xp_cmdshell` gets turned back on after
somebody disabled it. To a statement classifier every one of those is an
`EXECUTE`, and a statement policy strict enough to catch them would refuse every
stored procedure in the estate. Hence `allow_procedures`, which defaults to what
a client library calls -- the dynamic-SQL family, the cursor family, and the
metadata calls JDBC and ODBC make to describe a result set -- and nothing else.

**The statement an application runs is not a statement.** Every client library
that uses parameters sends `sp_executesql` with the SQL in a parameter, so a
relay that classified only `SQLBATCH` would be inspecting the `SET` statements a
driver emits on connect and nothing an application ever runs. The relay reads
that one parameter -- and only that one, on the six procedures whose documented
signature has a statement in it, because the rest are the caller's data and a
relay that held them would put one in a log line -- and applies the same
statement policy to it as to a batch. A dynamic-SQL call whose statement it
cannot read is refused: it is the one message on this protocol that carries
arbitrary SQL.

One structural oddity, which needs no configuration but explains the code: **the
TLS handshake runs inside TDS packets and then stops.** For the length of the
handshake TDS wraps TLS; afterwards TLS wraps TDS. The nesting inverts once,
part way through a connection.

```yaml
- name: app
  address: "10.0.0.30:1433"
  kind: tds
  tls:
    certificates: [{cert_file: /etc/xproxy/tls/db.pem, key_file: /etc/xproxy/tls/db-key.pem}]
  tds:
    upstream: sql
    allow_clients: ["10.0.2.0/24"]
    allow_users: [svc_sales]
    allow_databases: [sales]
    allow_statements: [select, insert, update, delete, set, begin, commit, rollback]
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `upstream` | name | *(required)* | The server pool |
| `allow_clients`, `deny_clients` | list of CIDR | any | Networks a client may connect from; deny first |
| `require_tls` | bool | `true` | Answer every client's PRELOGIN with `required`, so one that asked for `off` upgrades anyway. The listener needs a `tls` section. A client too old to speak TLS will fail to connect, which is the honest outcome: it was sending a recoverable password in cleartext |
| `upstream_tls_mode` | `require`, `prefer`, `disable` | `require` | How the relay speaks to the server. A separate negotiation from the client's, because a relay that terminated the client's TLS and spoke plaintext onwards would have moved the exposure rather than removed it |
| `upstream_tls` | object | *(none)* | Certificate and verification settings for that leg |
| `allow_cleartext_password` | bool | `false` | Permit a `LOGIN7` carrying a password over an unencrypted connection |
| `allow_users`, `deny_users` | list | any | Which logins a connection may claim |
| `allow_databases`, `deny_databases` | list | any | Same, for the database |
| `allow_apps` | list | any | Matches the client's `APPNAME`, trailing `*` allowed. Chosen by the client and not a credential; it tells a reporting dashboard from a migration tool when both connect as the same login |
| `allow_integrated` | bool | `true`, or `false` once a user list is set | Permit a login using integrated security, where the credential is an SSPI blob and the `LOGIN7` carries **no user name**. A user list cannot be applied to a login that names no user, so naming one turns this off: the alternative is a user policy with a hole exactly the shape of Windows authentication. Set it explicitly to say which you meant |
| `allow_types`, `deny_types` | list | the driver set | Message types: `sql_batch`, `rpc`, `bulk_load`, `transaction_manager`, `attention`, `sspi`, `fedauth_token`, `prelogin`, `login7`, `login`. Empty allows all but `bulk_load` (whose stream is not SQL and carries no policy) and `login` (the pre-TDS7 shape, which the relay does not read) |
| `allow_procedures`, `deny_procedures` | list | the driver set | RPC procedures, lower-cased. Empty allows `sp_executesql`, the prepare and cursor families, `sp_reset_connection` and the driver metadata calls — so every `xp_`, every `sp_oa`, `sp_configure`, `sp_addlinkedserver` and `sp_send_dbmail` are refused until named. A name matches whether the client called the procedure by name or by the numeric identifier the protocol also allows, because they are the same call |
| `read_only` | bool | `false` | Refuse every statement that can change data. `EXEC` is one of them: T-SQL has no prepared-statement syntax, so `EXEC` runs a stored procedure, which can do anything the login can |
| `allow_statements`, `deny_statements` | list of kinds | any nameable | As the postgres kind names them. They apply to a `SQLBATCH` and to the statement inside an `sp_executesql` alike |
| `max_statements` | int | `1` | Statements per batch. T-SQL separates statements with whitespace, so a batch carrying several is ordinary -- which is why the bound belongs here rather than in a capability flag as it does on MySQL |
| `max_statement_bytes` | int | `65536` | One statement |
| `max_message_bytes` | int | `4194304` | One reassembled message. The protocol has no bound: only the EOM status bit ends a message, so a sender may chain 64 KiB packets for ever |
| `max_sessions`, `max_sessions_per_client` | int | unbounded | Concurrent connections |
| `idle_timeout`, `session_duration`, `handshake_timeout` | duration | `0`, `0`, `30s` | |
| `default_action` | `allow`, `deny` | `deny` | When no rule matched |
| `deny_response` | `error`, `drop` | `error` | `error` sends an error token: 229 (permission denied on an object) for a refused message, 18456 (login failed) for a refused connection, which are what the server itself answers |
| `monitor_only` | bool | `false` | Evaluate and do not enforce, except the hard decisions below |

### rules[]

| Key | Type | Description |
|-----|------|-------------|
| `name` | string | Names the rule in logs and counters |
| `clients`, `users`, `databases`, `apps` | lists | Selectors; AND within a rule, OR within one |
| `schedule` | object | `days`, `from`, `to`, `timezone` |
| `action` | `allow`, `deny`, `observe` | Default `allow` |
| `allow_procedures`, `deny_procedures`, `allow_types`, `deny_types`, `allow_statements`, `deny_statements`, `read_only`, `max_statements` | | The rule's own narrowing. A rule that names a procedure, a type or a kind **widens** the listener for its own traffic; the deny lists always win |

### What shadow mode never shadows

| Refusal | Why it is hard |
|---------|----------------|
| `client_not_allowed` | An address that may not connect |
| `tls_required`, `upstream_no_tls` | The login name, the database and a recoverable password are inside the LOGIN7 |
| `cleartext_password` | Anybody who read the packet has the password; there is nothing left to observe |
| `integrated_not_allowed`, `no_user` | A login no user list can be applied to. Admitting it would be a user policy with a hole, noted and permitted |
| `procedure_denied`, `procedure_not_allowed` for a procedure in the dangerous set | Forwarding a shell command, a COM object, a registry write or a linked server and writing down that it was noticed is not a trial of a policy |
| `legacy_login` | The pre-TDS7 login is a message shape the relay does not read, and forwarding octets it has not understood is what this kind exists not to do |
| `batch_unreadable`, `rpc_unreadable`, `statement_unreadable` | The relay has no opinion to observe |
| `statement_too_long` | A bound |

The set whose refusal is never shadowed is `xp_cmdshell`, the OLE automation
family, the registry procedures, `sp_addextendedproc`, `sp_addlinkedserver`,
`sp_serveroption`, `sp_configure`, `xp_servicecontrol`, the mail procedures, the
filesystem procedures, the SQL Agent job procedures and the role-membership
procedures. A procedure that is merely *not on the allow list* is a soft
refusal, because it is most likely an application nobody has listed yet -- which
is what monitor mode is for. An operator who names one of the hard set in
`allow_procedures` has said so, and is not overruled.

Forcing the encryption negotiation upward is not in the table either, because it
is not a refusal: nothing is denied, the connection goes through, and it happens
in shadow mode too. It is logged as an `alert`.

## redis

`kind: redis` is a relay in front of a Redis or Valkey server.

**It is the protocol in this project where a relay earns its place fastest**, and
the reason is Redis's own default: no password. An instance with `requirepass`
unset accepts every command from anybody who can reach the port, so an instance
that is *reachable* is an instance that is *administrable*. And on this protocol
the distance between an administrative command and remote code execution is one
command:

```
CONFIG SET dir /var/spool/cron
CONFIG SET dbfilename root
SAVE
```

writes a file of the attacker's choosing wherever the server can write. Pointed at
a cron directory or an `authorized_keys` it is a shell, and it has been used that
way for a decade.

There is also almost nothing for a relay to reason about. A command is an array of
opaque byte strings: no schema, no statement grammar, nothing to classify by shape
the way the three SQL kinds classify a statement. So the policy is built on four
things, in the order they are decided:

- **Authentication, before anything else.** `require_auth` refuses a command that
  arrives before the connection has authenticated, and the answer is taken from the
  *server's* reply rather than from the relay having seen an `AUTH` -- a relay that
  trusted the attempt would treat a wrong password as a login. What a client may
  legitimately send first is named rather than guessed (`AUTH`, `HELLO`, `PING`,
  `QUIT`, `RESET`, `COMMAND`), because the alternative -- letting everything
  through until an `+OK` arrives -- is a window an attacker fills with one command.

- **The command name, as an allow list**, defaulting to what an application does to
  a cache. The absences are the value; the table below says what each one is.

- **The subcommand, where it decides.** `CONFIG GET` is a read and `CONFIG SET` is
  the paragraph above, so `allow_subcommands` exists to allow the one and not the
  other. A container command allowed with no subcommand listed allows all of them.

- **The key prefix**, which is the closest this protocol has to the
  database-and-table boundary the SQL kinds leave to `GRANT`.

### The key prefix policy, and the commands it refuses

A command's keys sit where its own signature puts them, and the relay reads them
from a table of 202 commands -- including the interleaved ones (`MSET` is key,
value, key, value) and the ones whose last argument is a timeout rather than a key
(`BLPOP`). Fifteen more declare their key count in an argument (`EVAL`, `LMPOP`,
`SINTERCARD`), and that count is read rather than assumed: it is the client's
number and it decides which arguments are keys, so a relay that assumed a position
would check a prefix policy against a Lua script's text.

Ten commands have key positions that depend on an option that may or may not be
present, and while a prefix policy is in force **those are refused** with
`key_position_unknown` rather than checked against a guess:

| Command | Why its keys cannot be located |
|---------|-------------------------------|
| `XREAD`, `XREADGROUP` | the keys follow a `STREAMS` token whose position depends on `COUNT`, `BLOCK`, `GROUP` and `NOACK`, and after it the streams and their identifiers are two halves rather than alternating pairs |
| `SORT`, `SORT_RO` | a `STORE` option adds a destination key at the end, and `BY` and `GET` take key *patterns* rather than keys |
| `GEORADIUS`, `GEORADIUSBYMEMBER` | `STORE` and `STOREDIST` each add a key at the end. The `_RO` variants have neither, so they are locatable and are not on this list |
| `ZUNIONSTORE`, `ZINTERSTORE`, `ZDIFFSTORE` | a destination, then a `numkeys` count, then that many source keys: two different mechanisms in one command |
| `MIGRATE` | the key is the third argument -- unless `KEYS` is used, in which case the third is an empty string and the keys are at the end |

Refusing them is the honest answer and the refusal is hard, because checking some
other argument instead would be a prefix policy that passes exactly what it was
meant to stop, and it would do it silently. With no prefix policy set, all ten are
ordinary commands.

```yaml
- name: cache
  address: "10.0.0.40:6379"
  kind: redis
  tls:
    certificates: [{cert_file: /etc/xproxy/tls/db.pem, key_file: /etc/xproxy/tls/db-key.pem}]
  redis:
    upstream: rd
    allow_clients: ["10.0.2.0/24"]
    allow_key_prefixes: ["app:", "session:"]
    read_only: false
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `upstream` | name | *(required)* | The server pool |
| `allow_clients`, `deny_clients` | list of CIDR | any | Networks a client may connect from; deny first |
| `require_tls` | bool | `true` | Refuse a client that is not speaking TLS. Redis has no in-protocol upgrade, so the port is either TLS or it is not -- which makes this simpler than the SQL kinds and no less important: a Redis `AUTH` sends the password as an argument of an ordinary command |
| `upstream_tls_mode` | `require`, `prefer`, `disable` | `disable` | How the relay speaks to the server. **The one place a default is off**, and deliberately: there is no negotiation to discover whether the server speaks TLS, so requiring it by default would refuse every upstream in the common deployment rather than protect anything |
| `upstream_tls` | object | *(none)* | Certificate and verification settings for that leg |
| `require_auth` | bool | `true` | Refuse any command before the connection has authenticated, taking the answer from the server's reply |
| `allow_users`, `deny_users` | list | any | ACL usernames a connection may authenticate as, from `AUTH user pass` and from `HELLO`'s `AUTH` clause. The one-argument `AUTH` form names no user and authenticates as `default`, which is what this list calls it -- so it is judged rather than bypassing the list |
| `allow_commands` | list | the application set | Command names, case-insensitive. Empty allows the data-type commands, the transaction commands, `AUTH`, `HELLO`, `PING`, `SELECT` and the pub/sub message commands — and nothing else |
| `deny_commands` | list | `[]` | The deny list, which no rule can override |
| `allow_subcommands`, `deny_subcommands` | list | *(none)* | Written `"CONFIG GET"`. A container command allowed without any subcommand listed allows all of them, which for `CONFIG` means `CONFIG SET` |
| `allow_key_prefixes` | list | any | Which keys a connection may name. See above for the commands this refuses |
| `deny_key_prefixes` | list | `[]` | Evaluated first |
| `allow_databases` | list of int | any | Which numbered databases `SELECT` may switch to. A Redis database is not an access boundary -- the password is the same for all of them -- but it is how an estate separates one application's keys from another's |
| `read_only` | bool | `false` | Refuse every command that can change data or the server. A command the relay has never heard of counts as a write, because Redis gains commands every release and a module adds its own. `EVAL` counts as a write because a script can do anything the connection can; the server's own `_RO` variants are honoured as reads |
| `max_message_bytes` | int | `8388608` | One reassembled command |
| `max_bulk_bytes` | int | `1048576` | One argument, which for a `SET` is the value. A value above `max_message_bytes` is brought down to it, because otherwise the message check fires first and the configured value never applies |
| `max_elements` | int | `1024` | Elements in one command's array. An ordinary command has single digits; a pipeline is several commands rather than one long array |
| `max_commands` | int | unbounded | Commands per connection. Off by default because a cache connection is long-lived and chatty; it is here for a bastion front where a session is a person |
| `max_sessions`, `max_sessions_per_client` | int | unbounded | Concurrent connections |
| `idle_timeout`, `session_duration`, `handshake_timeout` | duration | `0`, `0`, `30s` | |
| `allow_inline` | bool | `false` | Permit the space-separated command form. No client library sends it -- it exists for a human with a telnet session -- and a great many exploitation scripts use it because it needs no length arithmetic. The relay reads it either way, so refusing it costs an operator nothing |
| `default_action` | `allow`, `deny` | `deny` | When no rule matched |
| `deny_response` | `error`, `drop` | `error` | `error` sends `-NOPERM`, the kind Redis's own ACL uses for "this user may not run this command", so a client library reports it the way it reports the server's refusals |
| `monitor_only` | bool | `false` | Evaluate and do not enforce, except the hard decisions below |

### rules[]

| Key | Type | Description |
|-----|------|-------------|
| `name` | string | Names the rule in logs and counters |
| `clients`, `users` | lists | Selectors; AND within a rule, OR within one |
| `schedule` | object | `days`, `from`, `to`, `timezone` |
| `action` | `allow`, `deny`, `observe` | Default `allow` |
| `allow_commands`, `deny_commands`, `allow_subcommands`, `deny_subcommands`, `allow_key_prefixes`, `deny_key_prefixes`, `read_only`, `max_commands` | | The rule's own narrowing. A rule that names commands **widens** the listener for its own traffic; the deny lists always win |

### What is off by default, and why

| Command | What it is |
|---------|-----------|
| `CONFIG` | `SET dir` plus `SET dbfilename` plus `SAVE` writes a file wherever the server can write. `CONFIG GET` is a read, which is what `allow_subcommands` is for |
| `MODULE` | loads a shared object into the server |
| `EVAL`, `EVALSHA`, `FUNCTION`, `SCRIPT`, `FCALL` | a Lua interpreter inside the database |
| `REPLICAOF`, `SLAVEOF`, `REPLCONF`, `PSYNC`, `SYNC`, `FAILOVER` | makes this server a replica of one the attacker controls, which replaces its whole dataset |
| `MIGRATE`, `DUMP`, `RESTORE` | moves a key to another server: egress with a key name attached |
| `FLUSHALL`, `FLUSHDB`, `SWAPDB` | deletes everything, unrecoverably |
| `SHUTDOWN` | stops the server; with `NOSAVE` it loses data |
| `SAVE`, `BGSAVE`, `BGREWRITEAOF` | writes a file, and blocks |
| `KEYS`, `RANDOMKEY` | `KEYS` is O(n) **on the single thread that serves every client**, so one `KEYS *` on a large instance is an outage that looks like a slow query |
| `MONITOR` | streams every command every client sends, arguments included -- which is every value written to the database |
| `SLOWLOG`, `LATENCY`, `MEMORY` | the same, in samples |
| `ACL`, `CLIENT`, `CLUSTER`, `DEBUG` | administration of the thing enforcing the policy |
| `PSUBSCRIBE` | `PSUBSCRIBE *` receives every message on the instance, which is `MONITOR` for pub/sub |

### What shadow mode never shadows

| Refusal | Why it is hard |
|---------|----------------|
| `client_not_allowed` | An address that may not connect |
| `tls_required` | An `AUTH` on this connection puts the password on the wire as an ordinary command argument, and so does every value after it |
| `not_authenticated` | Forwarding an unauthenticated command means the command ran. In front of a server whose `requirepass` is unset, that is the whole of what the setting was for |
| `unreadable_command` | The relay has no opinion to observe |
| `key_position_unknown` | Checking the wrong argument against a prefix list is a policy that passes what it was meant to stop |
| `too_many_commands` | A bound |
| any refusal of a command in the table above | Forwarding a `CONFIG SET`, an `EVAL` or a `REPLICAOF` and writing down that it was noticed is not a trial of a policy. `KEYS` is in the set on different grounds: a monitor-mode listener that forwarded one would cause the outage it was installed to prevent |

A command merely *off* the allow list is a **soft** refusal, which is the
distinction that makes monitor mode useful: it is most likely an application nobody
has listed yet, and finding those is what the mode is for. An operator who names
one of the hard set in `allow_commands` has said so, and is not overruled.

## bacnet

`kind: bacnet` is a relay in front of a building. The controllers behind it hold
the setpoints for air handling, chillers, boilers, lighting, lifts, access
control, smoke control and the pressurisation in an operating theatre, and a
great many of them have been in a ceiling void since before the estate had a
security team.

**There is no identity in this protocol.** No user, no session, no password that
means anything, and no transport security. Clause 24's `authenticate` service was
withdrawn from the standard; the network security of the same clause -- the
challenge, the wrapped payloads, the key distribution -- is implemented by almost
nothing in the field. A device answers whoever asks it. So this listener decides
about a datagram from three things and no others: the address it came from, the
service it asks for, and the object and property it names.

Three properties of the protocol shape every control below.

**Writing is a service, not a mode.** `readProperty` and `writeProperty` are
different service choices in the same request shape, so the difference between
reading a zone temperature and setting it is one octet. `reinitializeDevice`
restarts a controller and `deviceCommunicationControl` tells one to stop talking
for a while; both take an optional password that is sent in the clear and that
most devices leave unset. An empty `services` list therefore allows reading,
discovery and the notifications a device sends of its own accord, and nothing
that changes anything.

**Writing has a priority, and the priority is the privilege.** A commandable
object -- an analogue output, a binary output, a lighting output, a lift --
holds sixteen command slots, and the plant follows the highest-priority slot
that is filled. Slots 1 and 2 are manual and automatic life safety: a value
written there cannot be overridden by the management system, by a schedule, or by
an operator at a workstation, and it stands until whoever wrote it relinquishes
it. `max_command_priority` is the bound, it defaults to 8, and a request above it
is refused *hard* -- the refusal stands in monitor mode, because a relay that
shadowed this one would be watching somebody take a piece of plant.

**It is broadcast, and it amplifies.** `who-Is` is a broadcast that every device
answers with an `i-Am`. A BBMD -- a broadcast management device -- forwards
broadcasts between subnets, and its foreign-device registration lets a host ask
to be sent every broadcast on a network it is not even on, from a single
unauthenticated datagram. `Forwarded-NPDU` carries the address a message came
from *inside the payload*, where whoever sent the datagram chose it. So
`allow_broadcast`, `allow_bbmd` and `allow_forwarded` all default to false,
`max_broadcast_replies` bounds the answers one broadcast brings back, and a
`Forwarded-NPDU` whose claimed origin is not the address it arrived from is
refused.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `upstream` | string | -- | The pool of devices, routers or BBMDs. Required |
| `allow_clients` | list | `[]` (any) | Networks a client may send from. Empty warns at load: this list is the only identity a request has |
| `deny_clients` | list | `[]` | Evaluated first |
| `services` | list | reading, discovery and notifications | The services carried, by the standard's own names (`readProperty`, `writeProperty`, `who-Is`) |
| `deny_services` | list | `[]` | Services no rule can allow |
| `max_command_priority` | int | `8` | The most privileged write priority, 1 (highest) to 16 |
| `objects` | list | `[]` (any) | Object types a request may name, by name (`analog-output`) or by number for a vendor's proprietary type |
| `deny_objects` | list | `[]` | Object types no rule can allow |
| `properties` | list | `[]` (any) | Properties a request may name, by name (`present-value`) or by number |
| `deny_properties` | list | `[]` | Properties no rule can allow |
| `deny_sensitive_writes` | bool | `true` | Refuse a write to a property whose value is the device's own behaviour |
| `refuse_unlocated_objects` | bool | `true` | Refuse a request whose object this relay could not find, where object rules exist |
| `allow_broadcast` | bool | `false` | Carry a broadcast from a client |
| `max_broadcast_replies` | int | `64` | Answers one broadcast may bring back to the client that sent it |
| `broadcast_reply_window` | duration | `5s` | How long answers are matched back to the client that broadcast |
| `allow_bbmd` | bool | `false` | Carry the broadcast management functions |
| `allow_forwarded` | bool | `false` | Carry a `Forwarded-NPDU` from a client |
| `allow_network_messages` | bool | `false` | Carry the network layer's own messages |
| `allow_routing` | bool | `false` | Carry `Initialize-Routing-Table` and the two connection messages. Needs `allow_network_messages` |
| `allow_security_messages` | bool | `false` | Carry clause 24's security messages |
| `networks` | list of int | `[]` (local only) | Destination networks (DNET) a request may be routed to. 65535 is refused at load: it is the global broadcast |
| `max_hop_count` | int | `8` | Largest hop count a routed message may carry. A larger one is *lowered*, not refused |
| `max_priority` | string | `urgent` | Highest network priority a client may claim: `normal`, `urgent`, `critical-equipment`, `life-safety` |
| `allow_segmented` | bool | `true` | Carry a segmented request or reply |
| `max_whois_range` | int | `0` (any) | Largest device instance range a `who-Is` may ask about |
| `require_whois_range` | bool | `false` | Refuse a `who-Is` with no range at all |
| `max_message_bytes` | int | `1497` | Largest datagram, and Annex J's own maximum |
| `max_pending` | int | `512` | Confirmed requests waiting for answers. Validation caps it at 256: that is how many invoke identifiers the protocol has |
| `request_timeout` | duration | `10s` | How long a confirmed request's slot is held |
| `rate_limit`, `rate_burst` | int | `0` | Requests per second per client address |
| `rules` | list | `[]` | Per-request rules, in order, first match wins |
| `default_action` | string | `deny` | `deny` or `allow` for a request no rule matched |
| `deny_response` | string | `reject` | `reject`, `error` or `drop`. An unconfirmed request is always dropped: the protocol gives a relay nothing to say back |
| `log_requests` | bool | `true` | An access line per request: who, which service, which object and property |
| `alert_on_deny` | bool | `true` | A security event per refusal |

A rule takes `name`, `action` (`allow`, `deny`, `observe`), `clients`,
`services`, `objects`, `deny_objects`, `instances`, `properties`,
`deny_properties`, `networks`, `max_command_priority` and `schedule`.
`instances` is written as `1-100` or as a single number, and bounds which
object instances the rule covers. `schedule` is the shape the modbus, iec104,
snmp, ldap and tftp rules use, and on a building it is a change window: writes
allowed while the engineers are on site and refused at three in the morning.

The three lists a rule sets *replace* the listener's for its own traffic, which
is how one workstation that really does command at a high priority, or one
integration that really does write to a device object, is written down.
`max_command_priority` on a rule works the same way -- and a rule that sets none
takes the listener's rather than none at all.

### Where the object is, and when it cannot be found

A policy about objects needs to know which object a request is about, and the
first object identifier in a request's parameters is the wrong one often enough
to matter. In a COV notification the first is the device that sent it and the
third is the object that changed; in `subscribeCOV` the first is a process
identifier that is not an object at all. So this relay knows where each service
keeps its object, rather than searching for one -- and `readPropertyMultiple` and
`writePropertyMultiple` carry lists, every object and property of which is
checked. A request reading one property from each of forty objects is one
datagram, and checking the first of them would be checking a fortieth of it.

A handful of services keep their object somewhere no fixed position describes:
`createObject` names a type or an identifier inside a choice, `who-Has` names an
object or a name, the COV-multiple and audit services carry lists of lists. Where
this listener has object or property rules, a request whose object it could not
find is refused, and `refuse_unlocated_objects: false` says otherwise. The two
ways to get this wrong are to check the wrong field and to let the request
through unchecked; saying "I could not find it" is the only answer that is
neither.

### The sensitive properties

`deny_sensitive_writes` refuses a write to `object-identifier`, `object-name`,
`out-of-service`, `program-change`, `relinquish-default`, `reliability`,
`max-master`, `max-info-frames`, `apdu-timeout`, `number-of-apdu-retries`,
`time-synchronization-recipients`, `restart-notification-recipients`,
`device-address-binding`, `database-revision`, `local-date`, `local-time` and
`utc-offset`.

`out-of-service` is the one to understand. Writing it true cuts a point loose
from the physical world: the present value becomes whatever was last written,
and every graphics page, trend and alarm in the estate then reports that number
as the truth. It is how a sensor is made to lie without touching the sensor. The
recipient lists are the other shape of the same idea: they make a device send its
notifications to an address of the writer's choosing.

### Refusal reasons

| `reason` | What it was |
|---|---|
| `client_not_allowed` | The address is outside `allow_clients` or inside `deny_clients` |
| `rate_limited` | The per-client rate. A bound, never shadowed |
| `not_bacnet` | The first octet is not 0x81: something else on the port |
| `malformed` | A BACnet message whose fields contradict each other or the standard |
| `message_too_large`, `reply_too_large` | Past `max_message_bytes`, refused unread |
| `bbmd_not_allowed` | A broadcast management function without `allow_bbmd` |
| `forwarded_not_allowed` | A `Forwarded-NPDU` without `allow_forwarded` |
| `forwarded_origin_mismatch` | A `Forwarded-NPDU` claiming to come from somewhere other than where it arrived from |
| `broadcast_not_allowed` | A broadcast without `allow_broadcast` |
| `security_not_allowed`, `security_message_not_allowed` | Clause 24 without `allow_security_messages` |
| `routing_not_allowed` | A destination network where `networks` names none |
| `network_not_allowed` | A destination network outside `networks` |
| `priority_not_allowed` | A network priority above `max_priority` |
| `network_message_not_allowed` | A network layer message without `allow_network_messages` |
| `routing_message_not_allowed` | `Initialize-Routing-Table` and the two connection messages without `allow_routing` |
| `network_message_unknown` | A network message type no edition defines |
| `service_denied`, `service_not_allowed` | The service lists |
| `service_unknown` | A service choice no edition of the standard defines |
| `segmented_not_allowed` | A segmented message with `allow_segmented: false` |
| `command_priority_too_high` | A write above `max_command_priority`. A bound, never shadowed |
| `whois_unbounded`, `whois_range_too_wide` | The discovery bounds. Bounds, never shadowed |
| `object_denied`, `object_not_allowed` | The object type lists |
| `instance_not_allowed` | A rule's `instances` |
| `property_denied`, `property_not_allowed` | The property lists |
| `sensitive_write` | A write to a property whose value is the device's own behaviour |
| `object_unlocatable` | Object rules exist and this relay could not find the request's object |
| `rule_denied`, `no_rule_matched` | The rules and `default_action` |
| `too_many_pending` | Every invoke identifier is outstanding, which means the devices are not answering |
| `too_many_broadcasts` | The outstanding broadcast table is full |
| `unsolicited_reply` | An answer carrying an invoke identifier nobody used, or from a device the request did not go to |
| `no_such_exchange` | A segment acknowledgement, abort or error from a client naming an exchange this relay is not holding |
| `unsolicited_broadcast` | An unsolicited datagram from the building with no client waiting for one |
| `wrong_direction` | A confirmed request arriving from the building towards a client |
| `hop_count_lowered` | Counted rather than refused: the hop count was rewritten down to `max_hop_count` |

The refusals that are never shadowed are the bounds:
`command_priority_too_high`, `whois_unbounded`, `whois_range_too_wide` and
`rate_limited`. Everything else is a policy choice, and monitor mode is for
finding out what an estate actually sends before refusing any of it.

### Pairing an answer with its question

The standard makes an invoke identifier unique only between one client and one
device. This relay speaks to the building from a socket of its own, so two
clients that both use identifier 1 towards the same controller would be
indistinguishable on the way back, and one client's answer would be delivered to
the other. So the relay allocates an identifier of its own towards the device and
translates it back on the answer, which is what a BACnet router does for the same
reason. There are two hundred and fifty-six of them; when all are outstanding a
request is refused (`too_many_pending`) rather than reusing one, because reusing
one delivers somebody else's answer.

An unconfirmed request has nothing to pair with at all -- an `i-Am` is sent of
the device's own accord -- so those answers are matched to the clients that
broadcast inside `broadcast_reply_window` and bounded by
`max_broadcast_replies`. An answer arriving outside anybody's window is not
forwarded: that bound is this protocol's amplification control, not a
convenience. A virtual link layer request -- a table read, a registration --
gets a window of exactly one reply, since that is what it expects.

A segmented exchange is translated in **both** directions. The reply's segments
carry the identifier this relay chose; the client's segment acknowledgements, and
any abort or error it sends about its own request, carry the one the *client*
chose -- so those are translated back the other way, and one naming an exchange
this relay is not holding is refused (`no_such_exchange`) rather than forwarded.
A segment also renews the exchange's deadline, because a segmented reply is one
exchange however many datagrams it takes and a deadline measured from the request
would expire in the middle of a long trend log download.

`services` applies to the building's direction too, because it is a statement
about which services cross this listener rather than about which a client may
send. The one that matters is `timeSynchronization`: a device, or something on
the plant network wearing a device's address, broadcasting one at a client
network sets the clock on every host that listens, and it is not on the default
list in either direction. The object and property rules are *not* applied to the
building's direction -- they are written about the objects a client may reach,
and applying them backwards would refuse every `i-Am`, which names a device
object.

## amqp

`kind: amqp` is a relay in front of a message broker. It is the only listener
here that reads **two protocols on one port**, because AMQP is two protocols: a
client picks one in its first eight octets.

- **AMQP 0-9-1** is what RabbitMQ speaks and what almost every deployment means
  by AMQP. A frame protocol with a class-and-method catalogue: declaring an
  exchange, binding a queue, publishing, consuming and deleting are each a
  method frame with typed arguments.
- **AMQP 1.0** (ISO/IEC 19464) is a different protocol that kept the name. Nine
  performatives over a self-describing type system, where the thing being
  authorised is the *address a link attaches to* and everything after it is a
  handle.

Both are read, and one policy decides both: the nouns are an exchange, a queue
and a routing key on 0-9-1, and a link address on 1.0, which the brokers that
serve both versions spell `/exchange/X/key` and `/queue/Q`.

### Why a relay in front of a broker

A broker is where an estate's data is in transit -- orders, payments, telemetry,
the events that drive everything else -- and four things about it are worth a
listener.

**A broker's permissions are per user and per virtual host.** RabbitMQ's model
is three regular expressions (configure, write, read) for each user in each
vhost: more than most brokers offer, administered inside the broker, and outside
the estate's own review. This holds the same boundary in the configuration that
is reviewed with everything else, and holds it in front of brokers whose model
is weaker.

**Topology is not work.** Declaring an exchange, deleting a queue, binding,
unbinding and purging are the broker's *configuration*, and an application that
publishes to an exchange somebody else declared needs none of them. So
`allow_topology` is false by default, and a client library that declares its own
queue on connect becomes a decision an operator makes rather than a default
nobody noticed.

**The credential is in the clear.** Both versions authenticate with SASL, and
PLAIN -- what every deployment uses -- is the username and the password in one
field separated by zero octets. `require_tls` is therefore the setting that
matters most. The relay reads the *username* out of the exchange for its rules
and its logs, and never the password: no code path between the wire and a log
line holds a broker credential.

**The dangerous arguments are not the obvious ones.** These four name something
a policy written against the obvious fields would miss:

| Where | What it names | Why it matters |
|-------|---------------|----------------|
| `x-dead-letter-exchange` on `queue.declare` | an exchange | where this queue's rejected and expired messages go. A client that may not publish to an exchange can have the broker deliver to it |
| `alternate-exchange` on `exchange.declare` | an exchange | where this exchange sends what it could not route |
| `reply-to` in a message's properties | a queue | where a request-reply service will send its answer, named inside the message rather than in the publish |
| `/exchange/X/key` as a 1.0 link address | an exchange and a routing key | the same boundary in the other protocol's vocabulary |

All four are checked against the same `allow_exchanges`, `allow_queues` and
`allow_routing_keys` as the fields that carry them.

### The pattern language

The name lists are written in the protocol's own topic language, because that
is the one an operator already knows from writing bindings. A name is words
separated by dots:

| Pattern | Matches | Does not match |
|---------|---------|----------------|
| `orders` | `orders` | `orders.created` |
| `orders.*` | `orders.created`, `orders.paid` | `orders`, `orders.eu.created` |
| `orders.#` | `orders`, `orders.created`, `orders.eu.created` | `payroll.created` |
| `#` | everything | |
| `svc-*` | `svc-a`, `svc-billing` | `svc-a.internal` |
| `app-?` | `app-1` | `app-12` |

`*` is exactly one word and `#` is zero or more, as in a binding. Inside a
word an ordinary shell glob applies, which is what the last two rows are. A
name with no metacharacter matches itself, which is what most of these lists
hold -- and the **default exchange is named by the empty string**, so a policy
that means to allow publishing to a queue by name has to write `""` in
`allow_exchanges` deliberately.

```yaml
- name: broker
  address: "0.0.0.0:5671"
  kind: amqp
  tls:
    certificates: [{cert_file: /etc/xproxy/tls/amqp.pem, key_file: /etc/xproxy/tls/amqp-key.pem}]
  amqp:
    upstream: brokers
    allow_clients: ["10.0.2.0/24"]
    allow_vhosts: ["/orders"]
    allow_exchanges: ["orders", "orders.*"]
    allow_queues: ["orders.*"]
    allow_routing_keys: ["orders.*"]
    require_user_id: true
    rules:
      - name: deployment
        users: [deploy]
        allow_topology: true
        schedule: {days: [mon, tue, wed, thu], from: "18:00", to: "22:00"}
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `upstream` | name | *(required)* | The broker pool |
| `allow_clients`, `deny_clients` | list of CIDR | any | Networks a client may connect from; deny first |
| `require_tls` | bool | `true` | Refuse a client that is not speaking TLS. AMQP has no in-protocol upgrade on 0-9-1 -- TLS is the port, 5671 rather than 5672 -- and 1.0's TLS protocol identifier is refused rather than answered: a client asking this relay to negotiate transport security from its first octet should be given a TLS port instead |
| `upstream_tls_mode` | `require`, `prefer`, `disable` | `disable` | How the relay speaks to the broker. Off by default for the same reason as redis: a great many brokers are reached over a private network with no TLS and there is nothing to negotiate, so requiring it by default would refuse every upstream rather than protect anything |
| `upstream_tls` | object | *(none)* | Certificate and verification settings for that leg |
| `versions` | list | both | `0-9-1`, `1.0`. 0-8 and 0-9 are never allowed: a broker answers them for compatibility, and a policy on a revision from 2006 is not one worth writing |
| `allow_mechanisms` | list | `[PLAIN, EXTERNAL]` | SASL mechanisms a client may choose. ANONYMOUS is not in the default: it is a login with no identity, so the broker has no account to attribute anything to |
| `deny_mechanisms` | list | `[]` | Evaluated first |
| `require_auth` | bool | `true` | Refuse every operation until the **broker** has accepted a credential. The outcome is the broker's answer and not the client's claim: a 0-9-1 broker that refuses a password closes the connection instead of sending `connection.tune`, so tune is the answer; on 1.0 it is the `sasl-outcome` |
| `allow_users`, `deny_users` | list | any | The identities a connection may authenticate *as*, read out of the SASL exchange. The broker decides whether the password is right; this decides which names may be tried |
| `allow_vhosts`, `deny_vhosts` | list of pattern | any | The virtual hosts a connection may open: `connection.open`'s virtual-host on 0-9-1, `open`'s hostname on 1.0. Decided before the exchange and queue lists, because a name means something different in each vhost |
| `allow_methods` | list | the application set | 0-9-1 method names, spelled `basic.publish`, `queue.declare`. Empty allows the handshake, the channel methods, publishing, consuming, acknowledging, publisher confirms and transactions -- and no topology method at all |
| `deny_methods` | list | `[]` | The deny list, which no rule can override |
| `allow_performatives`, `deny_performatives` | list | all nine | The same for AMQP 1.0, spelled `attach`, `transfer`, `flow`. Empty allows all of them, because on that version the policy is about the address a link attaches to rather than about which performative carries it |
| `allow_topology` | bool | `false` | Permit the methods that change the broker's configuration: declare, delete, bind, unbind and purge |
| `allow_publish`, `allow_consume` | bool | `true` | Putting messages in and taking them out. A listener in front of a broker that only ingests events sets consume false; one in front of a read model sets publish false. On 1.0 the same two decide an `attach`, because a sender is publishing and a receiver is consuming |
| `allow_exchanges`, `deny_exchanges` | list of pattern | any | Exchange names. Checked wherever an exchange is named, including the two arguments in the table above |
| `allow_queues`, `deny_queues` | list of pattern | any | Queue names, including a message's `reply-to` |
| `allow_routing_keys`, `deny_routing_keys` | list of pattern | any | Routing keys |
| `allow_addresses`, `deny_addresses` | list of pattern | any | 1.0 link addresses. A listener that names exchanges and queues already covers the addresses whose shape says which they are; these are for the node names that have no shape, which is what Azure Service Bus and Qpid use |
| `deny_management_nodes` | bool | `true` | Refuse the names a broker keeps for administering itself: `$management` and `$cbs` on 1.0, and the `amq.rabbitmq.*` exchanges on 0-9-1 -- the log stream, the trace stream and the event stream. An operator who needs one names it in `allow_exchanges` or `allow_addresses` |
| `require_user_id` | bool | `false` | Refuse a published message with no `user-id` property. It is the one field that ties a message to a person, and nothing makes a publisher set it |
| `match_user_id` | bool | `true` | Refuse a message whose `user-id` is not this connection's identity. Costs nothing when nobody sets the property |
| `allow_no_ack` | bool | `true` | Permit `basic.consume` with `no-ack`, which takes messages off a queue without acknowledging them: whatever was in flight when the consumer died is gone |
| `max_priority` | int | unbounded | Bound on a message's `priority` property. A priority queue serves the highest first, so a publisher that sets the maximum on everything starves the others |
| `max_frame_bytes` | int | `131072` | One frame, and with it the `frame-max` the two sides negotiate. A negotiation that settles above this is **refused rather than rewritten**: rewriting it would make the relay a party to the negotiation, and a connection that agreed a frame size and then had a frame refused mid-message is a harder fault to find than one that failed at the start |
| `max_channels` | int | `256` | Channels per connection (sessions, on 1.0), enforced by **counting the channels that are opened** rather than by refusing the negotiation: a broker's own default channel-max is in the thousands and every client echoes it, so refusing that would refuse every ordinary connection |
| `max_links` | int | `256` | Links per 1.0 session |
| `max_message_bytes` | int | unbounded | One message. On 0-9-1 it is checked against the size the **content header declares**, before the body arrives; on 1.0 it is the sum over a run of transfers, because a message may be split across them |
| `require_heartbeat` | bool | `false` | Refuse a connection that negotiated no heartbeat. One with none holds the broker's resources until the kernel notices the socket is gone, which can be hours -- and off by default because a client behind something that keeps the socket open is not doing anything wrong |
| `max_methods` | int | unbounded | Methods or performatives per connection. Off by default because a broker connection is long-lived; it is here for a bastion front where a session is a person |
| `rate_limit`, `rate_burst` | int | off | Methods per second per client address |
| `max_sessions`, `max_sessions_per_client` | int | unbounded | Concurrent connections |
| `idle_timeout`, `session_duration`, `handshake_timeout` | duration | `0`, `0`, `30s` | |
| `default_action` | `allow`, `deny` | `deny` | When no rule matched |
| `deny_response` | `close`, `drop` | `close` | `close` sends the protocol's own statement -- a `connection.close` with reply code 403 on 0-9-1, a `close` carrying `amqp:unauthorized-access` on 1.0 -- so a client library reports a refusal rather than a dropped socket |
| `log_methods` | bool | `false` | An access line per method, which on a busy broker is a great many lines |
| `alert_on_deny` | bool | `true` | A security event for every refusal |
| `monitor_only` | bool | `false` | Evaluate and do not enforce, except the hard decisions below |

### rules[]

| Key | Type | Description |
|-----|------|-------------|
| `name` | string | Names the rule in logs and counters |
| `clients`, `users`, `vhosts` | lists | Selectors; AND within a rule, OR within one |
| `schedule` | object | `days`, `from`, `to`, `timezone` |
| `action` | `allow`, `deny`, `observe` | Default `allow` |
| `allow_methods`, `deny_methods`, `allow_performatives`, `deny_performatives`, `allow_exchanges`, `deny_exchanges`, `allow_queues`, `deny_queues`, `allow_routing_keys`, `deny_routing_keys`, `allow_addresses`, `deny_addresses`, `allow_topology`, `allow_publish`, `allow_consume`, `max_message_bytes`, `max_methods` | | The rule's own narrowing. A rule that names methods **widens** the listener for its own traffic; the deny lists always win |

### A refusal ends the connection

On the other relay kinds a refused operation is answered and the session
continues. Here it is not, and the reason is the protocol: AMQP is stateful in
both directions, so dropping one frame out of a conversation leaves the two
sides disagreeing about what happened -- the client waiting for a reply the
broker was never asked for, or the broker answering a method the client never
learned was refused. So a refusal sends the protocol's own statement of why and
closes both legs. A client library reports that as an access refusal, which is
what it reports when a broker refuses one of its own.

A refused **protocol header** is answered the way both specifications say
(0-9-1 §4.2.2, 1.0 §2.2): with a header this listener does serve, and then the
socket closes. A client library reports "the server speaks 0-9-1" rather than
"the connection dropped".

### What monitor mode never shadows

| Refusal | Why it is hard |
|---------|----------------|
| `client_not_allowed`, `tls_required` | An address that may not connect; a credential that would go on the wire |
| `protocol_version_not_allowed`, `protocol_version_unknown`, `tls_negotiation_refused` | The header decides the framing of everything after it, so there is no "observe" for it |
| `not_authenticated` | Forwarding an operation before the broker accepted a credential means the operation ran |
| `unreadable_frame`, `frame_type_unknown`, `arguments_unreadable` | The relay has no opinion to observe |
| `mechanism_not_allowed`, `mechanism_missing` | A mechanism is chosen once, at the start, and a downgrade observed is a downgrade |
| `vhost_not_allowed` | The vhost decides what every name after it means |
| `frame_max_unbounded`, `frame_max_too_large`, `heartbeat_disabled`, `too_many_channels`, `too_many_links`, `too_many_methods`, `message_too_large`, `rate_limited`, `body_past_declared_size` | Bounds |
| `management_node_denied` | The broker's own administration |
| `delivery_denied` | The message is already on its way to the client |
| `no_such_link` | A 1.0 transfer on a handle this relay never saw attached, so its address was never checked |
| any refusal of a `queue.delete`, `exchange.delete`, `queue.purge` or `connection.update-secret` | A purge forwarded so that it could be written down is a queue that is empty |

A method merely *off* the allow list is a **soft** refusal, which is what makes
monitor mode useful: it is most likely an application nobody has listed yet.

### The inbound direction

The deny lists apply to what the broker hands the client -- `basic.deliver`,
`basic.get-ok`, `basic.return` -- and the allow lists do not. The difference is
deliberate. An allow list says what a client may *ask for*; a delivery names
where the message came *from*, which the consumer need not be allowed to name:
a queue bound to an exchange by somebody else delivers messages carrying that
exchange's name, and a relay that required it on the allow list would break
every ordinary consumer. A deny list says something else -- this connection must
never see messages from there, whoever routed them -- and that one holds in both
directions.

Refusals are `amqp_denied` for the ban triggers, with the reasons in the table
above plus `method_not_allowed`, `method_denied`, `method_unknown`,
`performative_not_allowed`, `performative_denied`, `performative_unknown`,
`topology_not_allowed`, `publish_not_allowed`, `consume_not_allowed`,
`exchange_not_allowed`, `exchange_denied`, `queue_not_allowed`, `queue_denied`,
`routing_key_not_allowed`, `routing_key_denied`, `address_not_allowed`,
`address_denied`, `reply_to_not_allowed`, `user_not_allowed`,
`user_id_missing`, `user_id_mismatch`, `priority_too_high`,
`no_ack_not_allowed`, `address_missing`, `administrative_not_allowed`,
`no_rule_matched`, `rule_denied`, `outside_schedule`, `too_many_sessions`,
`too_many_sessions_per_client`, `no_protocol_header`, `tls_handshake` and
`upstream_unavailable`.

## s7

`kind: s7` is a relay in front of a Siemens PLC. It is the listener for the
protocol with the least security of any in this project.

S7comm is three layers on TCP 102: **TPKT** (RFC 1006, a four-octet length),
**COTP** (X.224 class 0, whose connection request carries the address of the
CPU) and **S7comm** itself. What matters about it is what it does not have.
There is no transport security at all, which is why this listener takes no
`tls` section -- a certificate here would promise something the protocol cannot
do. And there is no authentication worth the name: the optional password
protects a handful of functions on some CPU families and nothing on others, and
an S7-300 with no password accepts a **stop** from anybody who can open a socket
to it. An engineering station on the same segment can read and write every byte
of memory in every controller on that segment.

The equipment cannot be fixed. A controller in a line is replaced on a capital
cycle, not a release cycle, and its firmware is qualified against the process it
runs. So the boundary has to be somewhere else, and this is somewhere else.

### The vocabulary

A relay's job here is to know what an operation *is*, and this protocol spreads
that across two layers: a **function code** for reading and writing memory and
for the block and control services, and a **user-data group and subfunction**
for everything else -- the diagnostic buffer, the block list, the clock, the
password, the debugger. A policy written against function codes would have
nothing to say about setting the clock; one written against user-data groups
would have nothing to say about a write.

So both are mapped onto one vocabulary of nineteen words, and every list in this
section is written in it:

| Word | What it is |
|------|------------|
| `read` | Reading memory: a data block, the process image, a timer |
| `write` | Writing it -- on a plant, the operation that moves something physical |
| `setup` | The connection negotiation, without which there is no session |
| `upload` | Reading a block **out** of the PLC: the program, as source an engineering tool can open |
| `download` | Writing one in, which is changing the program the machine runs |
| `control` | The control service: a warm restart, inserting or deleting a block, compressing memory |
| `stop` | Stopping the CPU |
| `cpu_services` | Function code 0, which the families in the field answer in ways nobody has documented |
| `szl` | Reading a system status list: the CPU's type, its firmware, its diagnostic buffer |
| `diagnostics` | The rest of the CPU function group: the message service and the alarm machinery |
| `blocks` | Listing the blocks and reading their headers |
| `cyclic` | Subscribing to cyclic data, which is how an HMI reads a screenful of values |
| `time_read` | Reading the CPU clock |
| `time_write` | Setting it -- and the clock is what every log line and batch record is stamped with |
| `security` | The password functions: supplying one, clearing one, asking how protected the CPU is |
| `programmer` | The debugger: forcing a variable, setting a breakpoint, stepping the program |
| `mode` | The mode transitions requested through the user-data layer rather than the control service |
| `pbc` | The programmable block communication a pair of PLCs uses between themselves |
| `nc` | The numerical control layer of a machine tool |

`operations` defaults to `setup`, `read`, `szl`, `blocks`, `cyclic`,
`time_read` and `diagnostics`: what an HMI, a historian and an inventory do, and
nothing that changes anything. **The absences are the policy.** No write, no
download, no control service, no stop, no mode transition, no clock setting, no
password function, no programmer command -- and **no upload**, which is the one
worth pausing on, because an upload changes nothing and is still off. Reading a
block out of a PLC is how a plant's control logic leaves the site.

An engineering station needs several of those. Naming them in the file is a line
a reviewer can see.

### The address is the rack and the slot

Which controller a client asked for arrives in the **COTP connection request**,
before any S7 request exists: the called TSAP's two octets hold a connection
resource, a rack (0-7) and a slot (0-31). So a client that may not reach that
CPU is refused **before the PLC is dialled**, and that ordering is the point
rather than an optimisation -- a CPU has very few connection resources, an
S7-300 sixteen altogether, and a client that may not reach it should not take
one of them.

`resources` is the cheapest useful line in this section. `pg` is the programming
device connection an engineering station opens, `op` is an operator panel and
`basic` is what one PLC opens to another; a listener that admits only `op` has
refused every engineering station without naming a single function.

### The memory is the boundary inside the CPU

`areas` and `dbs` say which memory a client may reach at all, and `addresses`
and `write_addresses` bound it by byte. The areas are `db`, `instance_db`,
`inputs`, `outputs`, `flags` (Siemens calls them merkers), `timer`, `counter`,
`local`, `previous_local`, `peripheral`, and the 200-family areas
`sysinfo_200`, `sysflags_200`, `analog_in_200`, `analog_out_200`,
`counter_200` and `timer_200`.

`peripheral` is the one worth putting on `deny_areas` on any listener that
allows writing: it is direct access to the I/O hardware, past the process image
the program reads.

Two details of how the ranges are applied:

- The protocol carries a **bit** address. The configuration is written in
  **bytes**, because that is how an operator thinks about a data block, and the
  relay divides by eight rather than making anybody else do it.
- A range is checked against the **whole span** a request covers, not its first
  byte. A read of bytes 0 to 200 against a range of `0-99` is a read of bytes
  the policy does not name, and it is refused rather than split: splitting it
  would be this relay deciding which half the operator meant.

```yaml
- name: line-3-plc
  address: "0.0.0.0:102"
  kind: s7
  s7:
    upstream: plc-line-3
    allow_clients: ["10.20.4.0/24"]
    racks: ["0"]
    slots: ["2"]
    resources: ["op"]
    areas: ["db", "inputs", "outputs", "flags"]
    deny_areas: ["peripheral"]
    dbs: ["1-40"]
    addresses: ["0-511"]
    write_addresses: ["100-199"]
    max_items: 20
    max_read_bytes: 480
    max_pdu_length: 480
    max_sessions_per_client: 2
    rules:
      - name: hmi
        clients: ["10.20.4.10"]
        operations: ["setup", "read", "write", "szl", "cyclic", "time_read"]
        comment: "line 3 panel: setpoints in DB1 bytes 100-199"
      - name: integrator
        clients: ["10.20.9.0/28"]
        resources: ["pg"]
        operations: ["setup", "read", "write", "download", "control", "blocks"]
        schedule: {days: [sat], from: "06:00", to: "14:00"}
        comment: "change window CR-2291"
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `upstream` | name | *(required)* | The PLC pool |
| `allow_clients`, `deny_clients` | list of CIDR | any | Networks a client may connect from; deny first. An empty allow list is allowed and advised against, because this listener reaches a controller |
| `racks`, `slots` | list of number or range | any | The rack and slot numbers a client may address, read out of the connection request. A rack is 0-7 and a slot 0-31 |
| `resources` | list | any | `pg`, `op`, `basic`: the connection type a client may ask for |
| `read_only` | bool | `false` | Refuse every operation that changes the PLC, for every client, before any rule is read. **No rule can override it** -- a read-only listener one rule could write through is not a read-only listener |
| `operations` | list | the HMI set | The allow list, in the vocabulary above |
| `deny_operations` | list | `[]` | The deny list, which no rule can override |
| `areas` | list | any | The memory areas a request may name |
| `deny_areas` | list | `[]` | The deny list. `peripheral` belongs here on a listener that allows writing |
| `dbs` | list of number or range | any | The data block numbers a request may name |
| `addresses` | list of byte range | any | The byte ranges a request may name, as `0-255` or a single number. The whole span must be inside one range |
| `write_addresses` | list of byte range | `addresses` | Applies to the writing operations when set, so one listener can allow a wide read and a narrow write |
| `block_types` | list | any | `db`, `fb`, `fc`, `sdb`, `sfb`, `sfc`: the block types an upload or a download may name. It matters only where one of those is allowed at all |
| `max_items` | int | `0` | Items one read or write may carry, 0 for no bound. A read of a hundred items is one PDU that occupies the CPU for as long as a hundred reads |
| `max_read_bytes`, `max_write_bytes` | int | `0` | Octets one request may read or write across all of its items |
| `max_pdu_length` | int | `0` | Bound on the PDU length the two sides negotiate. The families in the field negotiate 240, 480 or 960 and an S7-1500 negotiates 2048. A negotiation above this is **refused rather than rewritten**: rewriting it would make this relay a party to it |
| `max_frame_bytes` | int | `8192` | Bound on one TPKT frame |
| `max_requests` | int | `0` | Requests one connection may send. A plant connection is long-lived, so this is off by default |
| `rate_limit`, `rate_burst` | int | `0` | Requests per second per client address |
| `max_sessions`, `max_sessions_per_client` | int | `0` | Concurrent connections. A CPU has very few connection resources, so a bound here is what stops one client taking them all |
| `idle_timeout`, `session_duration`, `handshake_timeout` | duration | `0`, `0`, `30s` | Bounds on a connection. The handshake timeout is what a client that opens a socket and says nothing costs |
| `rules` | list | `[]` | Per-client rules, first match wins |
| `default_action` | `deny`, `allow` | `deny` | What a request matching no rule gets |
| `deny_response` | `error`, `drop`, `close` | `error` | How a refusal is answered. `error` is an S7 acknowledgement carrying an **access fault** -- what a protected CPU answers -- so the client's own library reports a refusal rather than a timeout |
| `log_requests` | bool | `false` | An access line per request, which on a plant polling every second is a great many lines |
| `alert_on_deny` | bool | `true` | A security event per refusal |
| `monitor_only` | bool | `false` | Evaluate and enforce nothing, except the hard decisions below |

### Rules

| Key | Type | Description |
|-----|------|-------------|
| `name` | string | Names the rule in logs and counters |
| `action` | `allow`, `deny`, `observe` | Default `allow` |
| `clients`, `racks`, `slots`, `resources` | lists | Selectors; AND within a rule, OR within one |
| `schedule` | object | `days`, `from`, `to`, `timezone`. This is how "the integrator may download during the shutdown window" is written |
| `operations`, `deny_operations`, `areas`, `deny_areas`, `dbs`, `addresses`, `write_addresses`, `block_types`, `max_items` | | The rule's own narrowing. A rule that names operations **widens** the listener for its own traffic; the deny lists and `read_only` always win |
| `comment` | string | Carried into every log line the rule decides, for the change record a plant keeps |

### How a refusal is answered

A refused **request** is answered and the connection carries on, which is the
modbus kind's choice and for the same reason: a plant connection is a poll loop,
and dropping it because one request was refused turns a refusal into an outage.
The answer is an acknowledgement with error class `0x87`, *access fault* -- what
a password-protected CPU answers a client that has not supplied one -- so the
client library reports the refusal it would have reported from the controller
itself. A refused **user-data** request is answered in its own layer instead:
the same group and subfunction, with the error code for a function the CPU does
not offer, because that is where a client that asked to set the clock looks.

A refused **connection** is answered with a COTP disconnect request, which is
what a CPU with no free connection resources sends. A silent close reads to an
engineering station as a network fault, and an engineer chasing a network fault
that is really a policy is an afternoon wasted.

The exceptions -- the cases that end the connection -- are the frames the relay
could not read at all: a COTP PDU type it does not know, and a data PDU that is
not an S7 PDU. There is nothing left to be sure of after either.

### What monitor mode never shadows

| Refusal | Why it is hard |
|---------|----------------|
| `client_not_allowed`, `rack_not_allowed`, `slot_not_allowed`, `resource_not_allowed` | An address or a controller a client may not reach. The connection is what would be forwarded |
| `not_a_connection_request`, `destination_unreadable`, `cotp_type_unknown`, `unreadable_frame`, `unreadable_pdu`, `items_unreadable`, `item_not_addressable`, `unexpected_message` | The relay has no opinion to observe. An operation it cannot read is one it cannot have a policy about |
| `operation_unknown` | A function code or user-data group with no name is an operation with no policy |
| `read_only` | The listener said so |
| `too_many_items`, `too_many_bytes`, `too_many_requests`, `pdu_length_too_large`, `rate_limited`, `too_many_sessions`, `too_many_sessions_per_client` | Bounds |
| any refusal of `write`, `download`, `control`, `stop`, `mode`, `time_write`, `security` or `programmer` | A write forwarded so that it could be written down is a moved actuator, and a stop forwarded is a stopped machine. A report afterwards undoes none of it |

An operation merely *off* the allow list -- a read of a data block nobody has
listed, an upload -- is a **soft** refusal, which is what makes monitor mode
useful on a plant nobody has an inventory of.

### What the PLC itself refuses

One record here is not a refusal by this relay and is the one that matters most
after an incident: an **access fault from the controller**, logged as
`s7_plc_refused`. That is the CPU refusing something this listener allowed,
which on this protocol almost always means the controller is
password-protected and the client has not supplied a password. It is the case
where the two policies disagree, and an operator needs to know which one to
change.

What is never logged is a **value**. A write's payload is a process value, and
on a plant those are pressures, temperatures and recipe parameters: not secrets,
but not something a relay should copy into a log file at poll rate either. The
*address* is logged, because an address is what a policy is written about, and a
refusal nobody can attribute to a byte range is a refusal nobody can act on.

Refusals are `s7_denied` for the ban triggers, with the reasons in the table
above plus `operation_not_allowed`, `operation_denied`, `area_not_allowed`,
`area_denied`, `db_not_allowed`, `address_not_allowed`, `block_type_not_allowed`, `no_rule_matched`,
`rule_denied`, `outside_schedule`, `no_connection_request` and
`upstream_unavailable`.

## asset_inventory

One record per device, built from traffic the proxy was already carrying.

An operational estate's oldest problem is that nobody knows what is on the
network: the drawings are out of date, the spreadsheet was abandoned, and
the one thing nobody may do is run a scanner -- an active scan is how a
programmable controller gets knocked over. A security proxy is an unusually
good place to solve that, because it already parses the protocols. The
relay kinds read Modbus function codes, IEC 104 common addresses, SNMP
object identifiers, MQTT client identifiers, DHCP vendor classes and TFTP
filenames, and each of those says something about what sent it.

Nothing here probes, scans or connects to anything.

Off by default. An inventory is a record of somebody's estate, and a proxy
that started keeping one without being asked would be making a decision
about their data for them.

```yaml
asset_inventory:
  enabled: true
  state_file: /var/lib/xproxy/assets.json
  ttl: 720h
  roles: [plc, rtu, hmi, scada_server, field_gateway, network_switch]
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Keep an inventory |
| `state_file` | path | *(none)* | Where the inventory is written and read back. Empty keeps it in memory, which means the whole estate is reported as new after every restart -- the fastest way to teach an operator to ignore the alerts |
| `save_interval` | duration | `5m` | How often the file is written. It is also written once on shutdown, so the last minutes are not lost |
| `max_assets` | int | `8192` | How many devices to hold. Past the bound the least recently seen record goes, and the count is exported as `assets.dropped`. This is the opposite of the pairing tables in the relay kinds, deliberately: forgetting here loses history rather than making a decision wrong, and refusing would stop the inventory noticing the estate at the moment something is filling it up |
| `ttl` | duration | `720h` | How long a device nobody has seen is kept, so a decommissioned device leaves the record instead of being reported for ever |
| `vendor_file` | path | *(none)* | Hardware prefixes and manufacturer names, one per line, added to the built-in seed list rather than replacing it. Format: a prefix, whitespace or a comma, and a name; `#` comments. A malformed line refuses the whole file rather than being skipped, because a list an operator trusted and which silently dropped half its entries is worse than one that would not load. Point this at a copy of the IEEE registry for full coverage |
| `alert_on_new` | bool | `true` | Write a security event (`asset_new_asset`) for a device that was not in the frozen baseline. Does nothing until a baseline exists, because before that everything is new |
| `alert_on_change` | bool | `true` | Write a security event when a device's identity changes: an address taken over by another device, a role that changed, a vendor re-resolved. This is the setting worth leaving on -- a steady-state inventory is a reference document, and the deltas are the security value |
| `roles` | list | any | The roles this estate expects. A device classified as anything else raises `asset_unexpected_role`, which is how "there are no engineering workstations on the process network" gets written down. `unknown` is always accepted, since a role nothing can be classified as would make every unclassified device a finding |

### What each listener kind contributes

| Kind | What it can honestly see |
|------|--------------------------|
| `dhcp` | The lease: the one message in which a device states its own hardware address, vendor class, user class, client identifier, host name and boot file together |
| `modbus` | Unit identifiers and function codes, at most 64 of each per device, and whether the peer asked or answered |
| `iec104` | Common addresses, the same shape over a different protocol |
| `snmp` | The object identifiers a manager asks for and an agent serves -- **not** their values. The SNMP parser keeps no varbind values by design, so `sysDescr` is not available to read; the OID set is weaker evidence and it is the evidence that exists |
| `mqtt` | The client identifier on CONNECT |
| `tftp` | The filename and direction of a transfer, which on a boot segment is often the only thing that names a device at all |

Every other listener kind contributes nothing. An inventory on an estate
with no relay listeners will be empty, which is honest rather than broken.

### Roles

Each role carries the Purdue level it sits at, so a segmentation review
can ask the question it actually asks: what is on this wire that does not
belong at this level.

| Role | Purdue level |
|------|--------------|
| `sensor`, `drive` | 0 |
| `plc`, `rtu` | 1 |
| `hmi`, `scada_server`, `field_gateway` | 2 |
| `historian`, `engineering_workstation` | 3 |
| `printer`, `camera`, `voip_phone`, `server`, `workstation` | 4 |
| `network_switch`, `router`, `embedded_device`, `unknown` | *(none)* -- the network carries every level and sits at none |

### How a guess is made, and why it says so

Behaviour outweighs self-description. A vendor class, a host name and an
SNMP description are strings a device chose, and a hardware address is
three bytes of vendor prefix anybody can set. What a device *does* --
answering Modbus function 3 on unit 1, carrying IEC 104 interrogations,
asking for a firmware image over TFTP -- is much harder to fake without
becoming the thing it is pretending to be. So rules that fire on behaviour
carry more confidence than rules that fire on a string.

Every classification keeps a confidence from 0 to 100 and the evidence
that produced it, strongest first. An inventory that reports "PLC" with no
confidence and no evidence is one an engineer cannot argue with, and being
unable to argue with it is how a wrong entry survives for years. When two
rules of equal weight disagree the asset is marked ambiguous and loses ten
points rather than one of them silently winning.

### The baseline

`xproxyctl assets baseline` takes the current set of devices as what the
estate has. Everything seen afterwards that is not in it is reported as
new. This is what turns the inventory from a reference document into a
detection, so both freezing and forgetting a baseline
(`xproxyctl assets baseline -forget`) are written to the audit log with
the caller's kernel-reported credentials, like a ban.

### Reading it

`GET /v1/assets` answers the summary, the known roles and the devices,
with `role`, `listener`, `proto`, `vendor`, `new=1`, `changed=1` and `top`
as filters, or `id` to look one device up by identifier, address or
hardware address -- whichever a log line happened to carry.
`xproxyctl assets` is the same thing as a table, `xproxyctl assets -long`
one block per device with the evidence, and `xproxyctl assets show KEY`
one device.

## access

Just-in-time access to the gate listeners: nobody opens a session unless
there is a live grant naming them, the listener and the target.

A bastion with standing access is a bastion whose accounts are worth as
much as the machines behind it. The keys sit in the estate all the time,
so whoever reaches a key, a laptop or a session reaches production at a
moment of their choosing. This is the other arrangement: a grant somebody
asked for, somebody else approved, that ends by itself, and that is written
down.

```yaml
access:
  ledger: /var/lib/xgate/access.log
  approvals: 1            # four eyes: the person who asked and one other
  max_duration: 4h
  max_lead: 24h
  max_uses: 0             # the window is the bound
  max_open: 256

server:
  listeners:
    - name: bastion
      kind: ssh
      ssh:
        upstream: prod-hosts
        require_grant: true
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `ledger` | path | none | The append-only file every request, approval, denial, revocation and use is written to, with a hash chain over the records. Absolute. Without it the grants live only in this process -- gone at the next restart, with no trail -- which is warned about rather than refused, because a test estate legitimately runs that way |
| `approvals` | int | `1` | Approvals a grant needs **in addition to** the request. 1 is four eyes: the person who asked and one other. 0 means a request is in force the moment it is made -- still just-in-time and time-boxed, but nobody else has to agree, and it is warned about. At most 8 |
| `max_duration` | duration | `4h` | The longest window a grant may cover; 1m to 24h |
| `max_lead` | duration | `24h` | How far ahead of now a window may start, so an approval today cannot be a key for next quarter; 0 to 720h |
| `max_uses` | int | `0` | Sessions one grant may open. 0 leaves the window as the only bound; 1 is a one-shot grant. 0 to 1000 |
| `max_open` | int | `256` | Grants that may be pending or in force at once. A request queue nobody drains is how an approval system becomes a rubber stamp; 1 to 4096 |
| `self_approval` | bool | `false` | Let the requester approve their own request. It is here for the estate with one operator, where the alternative is switching the requirement off altogether. Warned about every time |

Each gate kind -- `ssh`, `telnet`, `vnc`, `rdp` and `ftp` -- takes
`require_grant: true`, in that one spelling, so an estate does not have to
remember which protocol calls it what. A listener that requires a grant
with no `access` section fails the load; an `access` section no listener
asks is warned about.

### What a grant names

A grant names a **subject**, a **listener** and a **target**.

The subject is the identity the estate knows after authentication -- the
SSH principal entry when a key matched one, otherwise the login -- rather
than a name a client is free to offer. The listener is one listener by
name: a grant on the jump host is not a grant on the bastion. The target
is either the listener's `upstream` pool, which means any machine in it, or
the `host:port` of one endpoint in that pool, which means that machine and
**pins the dial to it** -- otherwise "alice may reach db-2 to restart a
service" would be access to whichever machine the balancer felt like.

An address that leaves the pool and comes back is the same address; a
*grant* that is revoked, denied, spent or expired is finished and cannot be
approved back to life.

### Four eyes

A grant is in force only once `approvals` people have approved it, and
**neither the person who asked nor the person who gains the access may be
one of them**. Names are compared trimmed and case-insensitively, so
`Alice` approving what `alice` asked for is one person rather than two, and
one approver cannot count twice.

The approvals a grant needs are fixed when it is requested. Loosening
`approvals` later does not bring a half-approved grant into force, and the
record says what was required at the time rather than what is required now.

Revocation is not slowed down the same way: anybody who can reach the
management API may revoke a grant, including one in force. Taking access
away is not the decision this requirement exists to guard.

### The time box

Every grant carries a window, checked against the policy when the request
is made rather than left to an approver to notice. `max_duration` bounds
its length and `max_lead` how far ahead it may start.

The window ends the session **that is running**, not only the next one
somebody opens: a gate sets the session's deadline to the earlier of its own
`session_timeout` and the end of the window. Without that, a four-hour grant
used at the last minute is a session that lasts as long as the operator
likes.

A request nobody approved before its window closed is expired rather than
pending: it cannot come into force any more, and leaving it in the queue
would hide the ones that still can.

### Tying a session to its approval

Each gate's access log line carries `grant` -- the identifier of the grant the
session was opened under -- and the ledger's `use` record carries the session's
identifier. So an investigation holding a recording can find the approval that
allowed it, and one holding an approval can find every session opened under it.
One direction alone leaves a reviewer guessing which window produced the
session in front of them.

### The trail

Every act is one line of the ledger, and each line carries a hash over the
previous one. A removed, edited, reordered or forged line is found when the
file is read at start, and the daemon refuses to serve a trail it cannot
stand behind rather than presenting it as intact. One process holds the file
exclusively -- two daemons appending would interleave their chains -- so a
second daemon pointed at the same path fails to start and says so.

A record is written, flushed and synced **before** the grant it describes is
in force. A grant that is in force in memory but not on disk is a grant
nobody approved after the next restart, and an approval the caller was told
about but that was never written is worse than one that was refused.
`max_uses` is durable for the same reason: a one-shot grant that refills
itself on restart is not one shot.

### Asking, approving and taking it back

A grant is asked for, approved by somebody else, and used -- all through the
management socket, so the same audit trail covers every step:

```
# the person who needs it, or somebody on their behalf
xproxyctl access ask -subject alice -listener bastion -target prod-db \
    -reason "incident 4711" -for 2h

# somebody else -- not the requester, not alice
xproxyctl access approve 9f2c4ab1 -note "spoke to alice"

# what is in force now, and one grant in full
xproxyctl access -state active
xproxyctl access show 9f2c4ab1

# and taking it back, which needs nobody else
xproxyctl access revoke 9f2c4ab1 -note "laptop stolen"
```

`-by` is the name the act is recorded under, and it defaults to the account
running the command (`SUDO_USER` first, because somebody who reached the
socket through `sudo` is still a person and `root` is not a name). Four eyes
is enforced on that name; the audit log records the caller's uid, gid and pid
beside it. The two can disagree, which is worth seeing: an estate where
everybody reaches the socket as one account gets its accountability from the
names and from the socket's group rather than from the kernel, and should
know that. An identifier may be given in full or as any unambiguous prefix;
an ambiguous one is refused rather than resolved to the first match.

The same five calls are `GET /v1/access`, `POST /v1/access` and
`POST /v1/access/{approve,deny,revoke}`; see docs/ARCHITECTURE.md.

### What a refusal says

A session turned away is counted under its own reason, because an operator
answering a call needs to know which. They are the listener's ordinary
refusal counters (`xproxyctl status`, the `_refusals_total` metrics) and
each is a deny event on the listener's usual reason (`ssh_denied` and so
on), so bans apply as they always did.

| Reason | What happened |
|--------|---------------|
| `no_grant` | Nobody has asked for access for this subject on this listener |
| `grant_pending` | A request exists and not enough people have approved it |
| `grant_not_yet` | Approved, and its window has not opened |
| `grant_expired` | The window closed, or nobody approved in time |
| `grant_denied` | An approver refused it |
| `grant_revoked` | It was withdrawn |
| `grant_spent` | `max_uses` is used up |
| `grant_wrong_target` | There is a grant for this subject on this listener, for another machine -- named separately because "wrong target" is the mistake an operator makes and "no grant" would send them looking for the wrong thing |

A listener in `policy: {mode: shadow}` records what it would have refused
and carries on, which is how an estate turns this on without locking its
operators out on the first evening.

## secrets

Where the secrets in this configuration come from. Without this section every
one of them is a path on this machine, which is how the proxy has always worked
and stays the default.

A proxy holds a great many secrets: TLS private keys, an upstream client key, a
Consul token, an LDAP bind password, the keyring behind every sealed cookie.
When each is a path, the material is on the file system of the machine --
readable by whatever else can read that machine, present in its backups, and
replaced by whatever can write there. A **reference** says where a secret comes
from instead:

| Reference | Resolves to |
|-----------|-------------|
| `/etc/xproxy/tls/edge.key` | A path, as before. Every configuration written before references existed keeps its meaning |
| `file:/etc/xproxy/tls/edge.key` | The same, said explicitly |
| `env:EDGE_KEY` | A variable in this process's environment |
| `vault:secret/tls/edge#key` | The `key` field of a secret in HashiCorp Vault |

A vault reference must name its field. A secret usually holds several, and
picking one for the operator is how the wrong key gets served.

```yaml
secrets:
  refresh_interval: 5m
  vault:
    address: https://vault.internal:8200
    mount: secret
    kv_version: 2
    token_file: /etc/xproxy/vault-token
    ca_file: /etc/pki/tls/certs/internal-ca.pem
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `refresh_interval` | duration | `5m` | How long a resolved value is used before its source is asked again, and how often a listener re-checks the keys it is serving. A key rotated in the vault reaches a running proxy within one interval, with no reload and no dropped connection -- see [What a rotation does](#what-a-rotation-does). 1m to 24h: below a minute the vault becomes this proxy's hot path, above a day a rotation does not arrive |
| `vault` | object | none | The vault references are read from; without it only `file:` and `env:` resolve and a `vault:` reference is refused at load |

### secrets.vault

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `address` | URL | required | `https://host:8200`. `http://` needs both `insecure` and `allow_insecure`, because plain HTTP puts the token and every secret it reads in clear on the wire |
| `mount` | string | `secret` | The KV mount references are relative to |
| `kv_version` | `1` or `2` | `2` | The KV engine version; version 2 wraps the secret in a `data` envelope and this is what decides how the answer is read |
| `token_file` | path | one of the two | A file holding the token, nothing else. Mode 0400 is the arrangement to want |
| `token_env` | name | one of the two | An environment variable holding the token. Warned about: the environment of a process is readable by anything that can read `/proc` for the same user, and every child process inherits it |
| `namespace` | string | none | Vault Enterprise namespace, sent as `X-Vault-Namespace` |
| `ca_file` | path | system roots | The CA that signs the vault's certificate |
| `server_name` | host | from the address | Override the name verified in the certificate |
| `insecure` | bool | `false` | Do not verify the vault's certificate. Only accepted together with `allow_insecure` and only for an `http://` address; on an `https://` address it is refused, because anything on the path could then hand this proxy its secrets |
| `allow_insecure` | bool | `false` | The second half of saying yes to plain HTTP, so that serving every secret in clear is two decisions rather than one typo |

### What a rotation does

A certificate is read once at load, so a rotated key would reach a listener only
at the next reload -- which is why there is a refresh loop rather than only a
TTL. Once per `refresh_interval`, every listener whose certificate names a `key`
reference re-resolves it. If the material is the same, nothing happens. If it
changed, the certificates are rebuilt and served from then on; connections
already established are untouched, since a TLS connection does not revisit the
certificate it was made with.

The loop exists only where it is needed: a listener whose keys are all
`key_file` or `signer` gets no goroutine and no ticker, and neither does a
daemon with no references at all.

`xproxy_secret_rotations_total` counts the certificates actually replaced, which
is the number to compare against what the vault says it rotated -- and a
`refresh_interval` of 5m with a rotation the vault performed an hour ago and
this counter at zero is the one combination worth investigating.

### What a failed refresh does

**A refresh that fails keeps the previous value and warns.** A vault that is
down must not take a TLS key away from a proxy that is already serving with it;
the whole point of the arrangement is that the estate keeps working while
somebody fixes the vault.

That means the failure mode to watch for is not an outage but silence: a secret
that has quietly stopped rotating. `xproxy_secrets_stale` counts the references
whose last refresh failed, `xproxyctl status` lists them, and the error log
carries a line per failure naming the reference. **A value is never logged,
wrapped in an error, or put in a dump** -- the configuration holds references
rather than material, so `xproxyctl dump`, the history and a diff show where a
secret comes from and never what it is.

### Where a private key lives

Each entry of `server.listeners[].tls.certificates` names `cert_file` and then
exactly one of three keys, which are the three custody arrangements:

| Key | Where the private key is | What an attacker who reads this machine gets |
|-----|--------------------------|----------------------------------------------|
| `key_file` | A PEM file on this machine | The key |
| `key` | Wherever the reference says: a file, the environment, or a vault | The key, if the reference is a file or the environment; the vault token, if it is a vault -- and a token can be revoked |
| `signer` | In another process, which may hold it in a PKCS#11 token, an HSM or a TPM | Nothing, as long as that process's own custody holds |

Two of them being set is refused at load, not resolved by precedence: a
certificate with two keys configured is a certificate whose key nobody can name
by reading the file.

```yaml
server:
  listeners:
    - name: edge
      kind: http
      tls:
        certificates:
          # On disk, as before.
          - cert_file: /etc/xproxy/tls/legacy.pem
            key_file: /etc/xproxy/tls/legacy-key.pem
          # From the vault, rotated without a reload.
          - cert_file: /etc/xproxy/tls/edge.pem
            key: vault:secret/tls/edge#key
          # Never in this process at all.
          - cert_file: /etc/xproxy/tls/hsm.pem
            signer:
              socket: /run/xproxy/signer.sock
              key: edge-rsa
```

### server.listeners[].tls.certificates[].signer

The strongest arrangement here is the one where the private key never enters
this process. A helper holds it -- in a PKCS#11 token, an HSM, a TPM, or simply
in a process with a different user and a tighter sandbox -- and answers signature
requests over a Unix socket. The proxy sends a digest and gets a signature back;
it never sees the key, so neither does anything that reads this proxy's memory.

That is also why the helper is a separate process rather than a linked library:
the daemons are built with `CGO_ENABLED=0`, and a PKCS#11 module is a C library.
Keeping it out of the proxy is both a build fact and the point.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `socket` | path | required | The Unix socket the helper listens on. Absolute. Connecting to it is a *write* under the sandbox, and the rule is derived for you |
| `key` | name | required | Which of the helper's keys to use; one helper may hold several |
| `timeout` | duration | `3s` | Bounds one signature. It is on the handshake path, so a helper that stops answering must fail rather than hold connections open; 100ms to 1m |
| `max_conns` | int | `8` | Connections held open to the helper. Signatures are serialised per connection, so this is the parallel handshake capacity; 1 to 256 |

At start the proxy asks the helper to sign a known value and checks the
signature against the public key in `cert_file`. A helper that cannot prove it
holds the matching key fails the load: the alternative is a listener that comes
up and then fails every handshake, which looks to everyone else like the
listener being down.

## fips

Whether this daemon insists on running with the FIPS 140-3 module active, and
what it says about the algorithms it was configured to offer.

```yaml
fips:
  required: true
  probe: true
  probe_fails: false
```

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `required` | bool | `false` | Refuse to start unless the FIPS 140-3 module is active in this process. Not a warning: the value of the setting is that a deployment which must be FIPS cannot quietly stop being it after a rebuild with the wrong toolchain |
| `probe` | bool | follows `required` | Ask the module at start which of the configured key exchange groups and cipher suites it will actually do, by handshaking over an in-process pipe |
| `probe_fails` | bool | `false` | Refuse to start when the probe finds a configured algorithm the module will not do. Only meaningful with `required` |

The module is not a build flag in this configuration -- it is a property of the
binary and of how it was started. Build with `GOFIPS140=v1.0.0` and run with
`GODEBUG=fips140=on`; `crypto/fips140.Enabled()` is what `required` checks, and
`xproxyctl status` reports it either way.

### Why probe rather than list

It would be easy to ship a list of approved algorithms and check the
configuration against it. That list would be wrong: which algorithms an active
module accepts is a property of the toolchain and the module version, not of
this project's documentation, and a stale list either refuses a configuration
that works or blesses one that does not.

So the probe measures instead. It completes a TLS handshake over an in-process
pipe for each configured group and suite and reports the ones the module
refused. On the toolchain this was written against, a module in FIPS mode
refuses `X25519` and `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256` while
accepting `X25519MLKEM768` and the P-curves -- which is exactly the sort of
detail that would be out of date in a list and is never out of date in a
measurement.

An algorithm the module refuses is not an error by default, because a listener
offering several groups still works for clients that ask for one of the others.
It is a warning, `xproxy_fips_refused_algorithms`, and a line in
`xproxyctl status`. An estate that wants the stricter reading sets
`probe_fails: true`.

## Headers set on forwarded requests

| Header | Value |
|--------|-------|
| `X-Forwarded-For` | client chain (trusted hops preserved) plus peer |
| `X-Forwarded-Host` | original `Host` |
| `X-Forwarded-Proto` | `http` or `https` |
| `X-Real-Ip` | derived client address |
| `X-Request-Id` | per request identifier, also returned to the client |

`Forwarded` and hop-by-hop headers are removed.

## Reload semantics

Changed by `SIGHUP` or `xproxyctl reload` without restart: routes,
upstreams, rate limits, trusted proxies, logging levels, limits other than
listeners, certificate files, WAF profiles and modes, ban triggers and
exemptions (active bans are kept; changing `bans.state_file` opens a new
list), cluster peers, intervals and sharing flags, shedding thresholds,
challenge settings (the key is kept), priority classes, and the
`capture` section (the recording switch and its deadline are carried
over unchanged; a new file is opened for the new configuration). Listeners are
matched by name: an added listener is bound and served by the reload, a
removed one stops accepting and drains its connections for
`shutdown_timeout`, and one whose settings changed beyond certificate
files, forward policy and dns policy is rebuilt with the same drain; on
an unchanged address the accept socket is kept (also when the listener
is renamed), so nothing is refused during the switch and a systemd
owned socket survives. A bind that fails (port in use or privileged)
fails the whole reload with the old set still serving. Requires
restart: a listener with a UDP socket (`h3`, `tcp.quic`, plain `dns`)
changed on the same address, `management.socket`, cluster `listen`,
`node_id` or `tls`, and the `acme` section.

Before applying, `xproxyctl reload -dry-run` (or `POST /v1/reload?dry_run=1`)
loads and validates the file and reports what would change against the
running generation: per named item (listeners, upstreams, routes, rate
limits, filters) added, removed or changed, every other section as a
whole, the items in the list above that need a restart, and a unified
text diff of the two documents. `xproxyctl diff [FROM] [TO]` compares
any two of `active` (running), `file` (on disk) and a history id. With
`management.history_dir` set, every applied generation is recorded
(start, reload, rollback); `xproxyctl history` lists them and
`xproxyctl rollback ID` applies one through the ordinary reload path,
so validation, the restart list and the audit log apply as for a
reload, and the rollback itself becomes a new entry. In ingress
controller mode the recorded document is the merged one; a rollback
restores the routes as they were merged at the time.
