# Configuration reference

xproxy reads one YAML document. Unknown keys are errors. Every omitted value
takes the default listed here; a zero duration or count means "default",
never "disabled". Paths must be absolute. Durations use Go syntax: `500ms`,
`10s`, `5m`, `1h`. Names match `[A-Za-z0-9][A-Za-z0-9_.-]{0,63}`.

Validate with `xproxy -config FILE -validate`; all problems are reported at
once. The example in `deploy/config/xproxy.yaml` exercises most keys.

## Top level

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `version` | int | required | Schema version. Must be `1`. |
| `includes` | list of globs | `[]` | Absolute paths or globs of fragment files whose `upstreams`, `routes`, `rate_limits` and `filters` are appended in lexical order of path; a fragment may contain nothing else, names must not repeat, a pattern that matches no file is an error, fragments must not be world writable; read at every load and reload |
| `server` | object | | Listeners and global limits |
| `management` | object | | Control socket |
| `logging` | object | | Log streams |
| `trusted_proxies` | list of CIDR | `[]` | Peers whose `X-Forwarded-For` is believed, and whose PROXY protocol header is parsed on listeners with `proxy_protocol: true`. Empty means never. |
| `rate_limits` | list | `[]` | Named rate limit policies |
| `upstreams` | list | `[]` | Named endpoint pools |
| `routes` | list | `[]` | Request matching and actions |
| `compression` | object | none | gzip of eligible responses; see `compression` |
| `tracing` | object | none | W3C trace context and span export; see `tracing` |

## server

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `listeners` | list | required, at least one | See below |
| `limits` | object | | Global protections |
| `server_header` | string | `""` | Value of the `Server` response header. Empty removes it. |
| `shutdown_timeout` | duration | `30s` | Drain time on stop and for old generations after reload |

### server.listeners[]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | name | required, unique | Also used to match systemd socket names |
| `address` | host:port | required | `":443"`, `"0.0.0.0:80"`, `"[::1]:8080"`. Port `0` picks a free port (tests). |
| `protocols` | list | `[h1, h2]` with TLS, `[h1]` without | `h2` and `h3` require `tls`. `h3` adds a QUIC endpoint on UDP at the same port and requires `h1` or `h2` alongside it (clients discover HTTP/3 through `Alt-Svc`). |
| `h3` | object | defaults when `h3` is listed | QUIC tuning; see below |
| `h2c` | bool | `false` | Accept HTTP/2 without TLS (prior knowledge and Upgrade) on a plaintext listener, for gRPC clients inside a trusted network |
| `tls` | object | none | TLS termination; see below |
| `proxy_protocol` | bool | `false` | Read a PROXY protocol v1 or v2 header at the start of every connection from a peer in `trusted_proxies`: the client address it carries becomes the peer for limits, bans, ACLs, logs and forwarding headers, and the per address connection count moves to it. A trusted peer that sends no header, or a malformed one, is dropped without a response (`drop_connection` with reason `proxy_protocol`, counted in `rejected_connections`); `LOCAL` headers keep the balancer's address; connections from other peers are served unchanged, so a client cannot choose its own address. Requires `trusted_proxies`; not on `kind: tcp` (which forwards a header instead) or `dns`. |
| `kind` | `http`, `tcp`, `forward`, `dns` | `http` | `tcp` is a layer 4 listener, `forward` an explicit proxy for clients and `dns` a DNS proxy; see below |
| `redirect_to_https` | bool | `false` | Answer every request with 308 to `https://host/path?query`. Plaintext listeners only. |

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
| `idle_timeout` | duration | `10m` | Close after no bytes in either direction; at most 24h |
| `proxy_protocol` | bool | `false` | Send a PROXY protocol v2 header with the client address to the upstream |
| `max_connections` | int | `10000` | Open connections on this listener; also bounds QUIC flows |
| `quic` | bool | `false` | Also relay QUIC: UDP on the same address, the ClientHello read from the version 1 Initial packet (decrypted with the Initial keys every observer can derive), the flow routed by server name to the same upstreams and every later datagram of that client address forwarded unread; not with `proxy_protocol` |
| `quic_idle_timeout` | duration | `30s` | End a QUIC flow with no datagrams either way; at most 1h |

Endpoints are picked with the upstream's balancer (hash on the client
address for `hash`), dial failures try the next endpoint and feed outlier
ejection; active health checks run as configured on the upstream. Every
connection writes one `tcp` line to the access log with the name,
upstream, endpoint, bytes and duration (`proto: quic` for QUIC flows).
Counters: `tcp_connections`, `tcp_rejected`, `tcp_errors`,
`tcp_bytes_in`, `tcp_bytes_out`, `quic_flows`, `quic_rejected`,
`quic_flows_open`; `xproxy_tcp_*` and `xproxy_quic_*` metrics. QUIC
flows are keyed by client address, so a client that migrates to a new
address starts a new flow (its first packet is not an Initial and is
dropped; the client falls back or retries); QUIC versions other than 1
are dropped. Changing a tcp listener needs a restart.

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

Each request writes one `forward` line to the access log with the
client address, user, method, destination, status, bytes and duration.
Counters: `forward_requests`, `forward_tunnels`, `forward_tunnels_open`,
`forward_denied`, `forward_auth_failed`, `forward_rejected`,
`forward_errors`, `forward_bytes_in`, `forward_bytes_out`;
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
advertisement) is truncated so the client retries over TCP. Only one
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
| `upstreams` | list | required | Resolvers tried in turn, rotating the first choice per query: `host:port` (UDP, TCP on truncation), `tls://host:port` (DNS over TLS, connections reused), `https://host[:port]/path` (DNS over HTTPS, POST `application/dns-message` with id 0) |
| `upstream_ca_file` | path | system pool | Pins the CA of `tls://` and `https://` upstreams; the host in the upstream string is the name verified |
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
| `rate_limit` | `{qps, burst}` | none | Per client token bucket (defaults 50 and 100 when the section is present); over it queries are dropped, not answered |
| `max_in_flight` | int | `1024` | Queries being handled at once; beyond it UDP queries are dropped |
| `log_queries` | bool | `false` | One `dns` access log line per query (client, name, type, rcode, source, bytes, duration). Query logs are personal data; leave off unless needed |
| `doh_path` | path | `/dns-query` | DNS over HTTPS path on an encrypted listener; other paths answer 404 |
| `dnssec` | object | none | Validate answers; see below |

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

`GET /v1/dns` and `xproxyctl dns` show per listener counters (queries,
cache hits and entries, blocked, refused, dropped, SERVFAIL, truncated,
upstream failures); `DELETE /v1/dns` and `xproxyctl dns purge` empty
the caches. Metrics: `xproxy_dns_*{listener}`.

### server.listeners[].h3

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `max_streams` | int | `100` | Concurrent request streams per QUIC connection; 1 to 10000 |
| `validate_addresses` | `always`, `under_load` | `always` | `always` makes every unvalidated client address complete a Retry round trip before the server allocates connection state; `under_load` does so only when open connections exceed a quarter of `max_connections` |
| `alt_svc_max_age` | duration | `24h` | Reserved for the `Alt-Svc` `ma` value (currently the library default) |

QUIC connections share the listener's `max_connections`,
`max_connections_per_ip`, ban list, header size and idle timeout;
`read_header_timeout` bounds the handshake. `read_timeout` and
`write_timeout` do not apply to HTTP/3 streams; use route `timeout` and
upstream `total` for those. 0-RTT is never enabled.

### server.listeners[].tls

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `certificates` | list | one of `certificates` or `acme` | `{cert_file, key_file}` PEM pairs; selected by SNI, first is the fallback |
| `acme` | list | | `{hosts: [...]}` groups issued and renewed through the top-level `acme` section; one certificate per group, named after its first host. Hosts are fully qualified names without wildcards and unique across the listener. Selected by SNI after the file certificates |
| `min_version` | `"1.2"` or `"1.3"` | `"1.2"` | TLS 1.0 and 1.1 cannot be configured |
| `client_auth` | `none`, `request`, `require` | `none` | Client certificates; `request` verifies if presented |
| `client_ca_file` | path | | Required for `request` and `require` |
| `cipher_suites` | list of names | ECDHE AEAD suites | TLS 1.2 suites, crypto/tls names. Insecure suites are rejected. TLS 1.3 suites are not configurable. |
| `ocsp_stapling` | object | none | Fetch OCSP responses for the served certificates in the background and staple them into handshakes; see below |
| `ct` | object | none | Check the Certificate Transparency SCTs embedded in file certificates at load; see below |

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

### logging.<stream>

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | |
| `file` | file name | `access.log` etc. | Bare name inside `directory` |
| `max_size_mb` | int | `0` (no internal rotation) | Rotate to `.1`, `.2`, ... when exceeded |
| `max_files` | int | `5` | Archives kept |
| `sinks` | list | `[file]` | Any of `file`, `journald`, `syslog`, `otlp`; a stream can go to several |
| `format` | `json`, `common`, `combined`, `custom` | `json` | Access stream only for the text formats: `common` is the Common Log Format (`%h %l %u %t "%r" %>s %b`), `combined` adds the quoted referer and user agent, `custom` uses `template`. The error, security and audit streams stay JSON. Text lines go to every sink of the stream; redaction runs before formatting |
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
| `format` | `rfc5424`, `rfc3164` | `rfc3164` for unix, else `rfc5424` | The JSON line is the message; the stream is the RFC 5424 MSGID |
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

### logging.redaction

Presence enables the rules; `enabled: false` switches them off while
keeping the configuration. Rules run before every sink, so files, journald
and syslog all receive the same redacted record.

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
| `key` | `client_ip`, `route`, `country`, `header:<Name>` | `client_ip` | Bucket identity. A missing header or an unknown country falls back to the client address. |
| `rate` | float | required, positive | Tokens per second |
| `burst` | int | `rate` rounded, at least 1 | Bucket capacity |
| `action` | `reject`, `tarpit` | `reject` | `reject` answers 429 at once |
| `tarpit_delay` | duration | `10s` | Hold before answering 429 (released on client disconnect) |

Memory: at most 64 x 8192 buckets per policy.

## upstreams[]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | name | required, unique | |
| `balancer` | `round_robin`, `weighted`, `least_conn`, `hash` | `round_robin` | |
| `hash_on` | `client_ip`, `header:<Name>`, `cookie:<Name>` | `client_ip` | For `hash`; missing input falls back to the client address |
| `endpoints` | list | required, at least one | `{address: host:port, weight: 1..1000, canary: bool}`; `canary` marks the endpoints the `canary` policy selects |
| `canary` | object | none | Route selected requests to the canary endpoints; see below |
| `scheme` | `http`, `https` | `http` | |
| `h2c` | bool | `false` | Speak HTTP/2 without TLS to `http` endpoints (gRPC backends); `https` negotiates HTTP/2 with ALPN on its own |
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
| `retry_on` | list | `[]` | Response statuses treated as a failed attempt: `5xx`, `500`, `502`, `503`, `504`, `429`. The response is discarded, the endpoint marked as failed for outlier ejection, and the next endpoint tried within the `retries` budget; the last attempt's response is returned as it is. Needs `retries` above 0 |

### upstreams[].tls

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `server_name` | string | endpoint host | SNI and verification name |
| `ca_file` | path | system pool | PEM bundle to verify against |
| `min_version` | `"1.2"`, `"1.3"` | `"1.2"` | Minimum TLS version towards the upstream |
| `client_cert_file`, `client_key_file` | path | | Mutual TLS to the upstream; set both. Re-read by `xproxyctl reload-certs` and by configuration reload; idle connections are dropped so new ones present the new certificate |
| `spki_pins` | list of base64 SHA-256 | `[]` | Pins of the upstream leaf public key; the connection is refused unless the presented leaf matches one, in addition to chain verification. `xproxyctl spki CERT.pem` prints a pin. Cannot be combined with `insecure_skip_verify` |
| `insecure_skip_verify` | bool | `false` | Requires `allow_insecure: true` as well |
| `allow_insecure` | bool | `false` | Second opt-in |

### upstreams[].health_check

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `type` | `http`, `grpc` | `http` | `grpc` calls the standard `grpc.health.v1.Health/Check` over HTTP/2 and needs `h2c` or `scheme: https`; `path` and `expected_status` are not used |
| `grpc_service` | string | `""` | Service asked in a grpc check; empty asks about the server as a whole |
| `path` | path | `/` | GET target |
| `interval` | duration | `5s` | At least 500ms; start is jittered |
| `timeout` | duration | `2s` | Must be shorter than `interval` |
| `healthy_threshold` | int | `2` | Consecutive successes to mark healthy |
| `unhealthy_threshold` | int | `3` | Consecutive failures to mark unhealthy |
| `expected_status` | list of int | `[200]` | |
| `max_concurrent` | int | `32` | Probes in flight per pool; 1 to 4096. Bounds the burst when a pool has thousands of endpoints |
| `keep_alive` | bool | `false` | Reuse pooled connections for probes. Off opens a fresh connection per probe (verifies the whole connect path, no descriptor held between probes); on saves the handshake at the cost of one idle connection per endpoint |

### upstreams[].outlier_ejection

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `consecutive_failures` | int | `5` | Connection errors or 503 responses in a row |
| `base_ejection_time` | duration | `30s` | Multiplied by the ejection count, capped at 10x |
| `max_ejection_percent` | int | `50` | Never eject more than this share of the pool |

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
| `methods` | list | `[]` (any) | Upper-case tokens |
| `priority` | int | `0` | Tie breaker |
| `tenant` | name | none | Free label grouping routes for quota reporting (`xproxyctl quotas`, `GET /v1/quotas`) and added as a `tenant` label to the per route metrics |
| `upstream` | name | | Exactly one of `upstream`, `redirect`, `respond`, `honeypot`, `doh`, `static` |
| `redirect` | `{to, status}` | status `308` | `to` is a URL or path; status 301, 302, 303, 307 or 308 |
| `respond` | `{status, body}` | status `200` | Static response, body up to 64 KiB |
| `honeypot` | object | | Decoy action; see `routes[].honeypot` |
| `mirror` | object | | Copy requests to a second upstream; see `routes[].mirror` |
| `grpc` | `{services, methods}` | | Restrict the route to gRPC requests; see `routes[].grpc` |
| `doh` | `{listener}` | | DNS over HTTPS action; see `routes[].doh` |
| `static` | object | | Serve files from a directory; see `routes[].static` |
| `compress` | bool | follows `compression` | `false` leaves this route's responses as they are; `true` needs an enabled `compression` section |
| `strip_prefix` | path | | Remove this prefix before forwarding |
| `rewrite_path` | path | | Replace the path entirely; exclusive with `strip_prefix` |
| `host_header` | string | client `Host` | Host sent upstream |
| `request_headers` | `{set, add, remove}` | | Applied before forwarding; values may not contain CR, LF or NUL |
| `response_headers` | `{set, add, remove}` | | Applied to responses, including redirect and respond actions |
| `rate_limits` | list of names | `[]` | Evaluated in order; first exhausted policy acts |
| `allow_cidrs` | list | `[]` (all) | Client must be inside one |
| `deny_cidrs` | list | `[]` | Evaluated first |
| `max_body_bytes` | int | global | May only lower the global limit |
| `timeout` | duration | none | Whole request deadline for this route |
| `websocket` | bool | `false` | Allow `Upgrade` requests |

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
| `per_route` | bool | `true` | Expose `xproxy_route_requests_total{route,outcome}` (one series per route and outcome) |
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
`xproxy_denied_total{reason}`, `xproxy_bytes_in_total`,
`xproxy_bytes_out_total`, `xproxy_waf_detected_total`,
`xproxy_upstream_errors_total`, `xproxy_upstream_timeouts_total`,
`xproxy_upstream_no_healthy_total`, `xproxy_client_aborts_total`,
`xproxy_connections_rejected_total`, `xproxy_reloads_total{result}`,
`xproxy_bans_total`, `xproxy_challenges_total{result}`,
`xproxy_log_sent_total{sink}`, `xproxy_log_dropped_total{sink}`,
`xproxy_connections_open`, `xproxy_requests_in_flight`,
`xproxy_bans_active`, `xproxy_load_level`,
`xproxy_upstream_latency_seconds`, `xproxy_shedding{class}`,
`xproxy_cluster_peers`, `xproxy_cluster_peers_connected`,
`xproxy_cluster_messages_total{direction,type}`,
`xproxy_cluster_rejected_total`, `xproxy_request_duration_seconds`
(histogram), `xproxy_upstream_ttfb_seconds` (histogram),
`xproxy_upstream_endpoint_{healthy,ejected,active}{upstream,endpoint}`,
`xproxy_upstream_endpoint_{requests,errors}_total{upstream,endpoint}`,
`xproxy_route_requests_total{route,outcome}`, `xproxy_build_info`,
`xproxy_uptime_seconds`, `xproxy_config_generation`.

Series (per-second rates for counters, current values for gauges):
`requests`, `responses_2xx`, `responses_4xx`, `responses_5xx`, `denied`,
`shed`, `bytes_in`, `bytes_out`, `upstream_errors`, `open_connections`,
`in_flight`, `load_level`, `upstream_latency_ms`, `bans_active`,
`cluster_connected`.

## bans

Present means enabled. Bans apply before routing; banned peers are closed
at accept when `action` is `drop`, and answered 403 when the client address
comes from a trusted proxy chain or `action` is `reject`.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `state_file` | path | `""` (memory only) | bbolt file that persists bans across restarts |
| `max_entries` | int | `100000` | Bound on banned addresses; the soonest expiring are evicted when full |
| `exempt_cidrs` | list | `[]` | Never banned, by trigger or by operator |
| `action` | `drop`, `reject` | `drop` | Close at accept, or answer 403 only |
| `triggers` | list | `[]` | Automatic bans; see below |

### bans.triggers[]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | name | required, unique | Appears in the ban entry as `trigger:<name>` |
| `reasons` | list | `[]` (all) | Deny categories that count: `acl`, `rate_limit`, `waf`, `body_size`, `uri_length`, `bad_host`, `no_route`, `websocket`, `concurrency`, `challenge`, `jwt`, `icap`, `geo`, `tcp_no_route`, `forward_denied`, `forward_auth`, `honeypot`, `dns_blocked` |
| `threshold` | int | required | Denies within `window` that trigger the ban |
| `window` | duration | required | At most 24h |
| `duration` | duration | required | First ban length |
| `escalation` | float | `2` | Multiplier applied for each repeat ban of the same address |
| `max_duration` | duration | `24h` | Cap on escalated duration; at least `duration` |

Manual bans (`xproxyctl ban`) accept addresses and CIDRs no wider than /8
(IPv4) or /32 (IPv6); loopback and unspecified addresses are refused.

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

### waf.profiles[]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | name | required, unique | |
| `crs` | object | none | Enable the bundled OWASP Core Rule Set |
| `crs.dir` | absolute path | embedded copy | Load the Core Rule Set from a directory in the release layout (`crs-setup.conf` or `crs-setup.conf.example`, `rules/*.conf` with their `.data` files); a reload picks up changed files, so rules update without a new binary. The directory is validated at load and a broken file fails the reload |
| `crs.paranoia_level` | int | `1` | 1 to 4 |
| `crs.inbound_threshold` | int | `5` | Anomaly score that blocks a request |
| `crs.outbound_threshold` | int | `4` | Anomaly score that blocks a response |
| `directive_files` | list of paths | `[]` | SecLang files loaded after CRS setup and before CRS rules (exclusions go here) |
| `directives` | string | `""` | Inline SecLang loaded in the same position, at most 1 MiB |

A profile needs at least one of `crs`, `directive_files` or `directives`.

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
| `decoy` | name | `admin-login` when nothing else is set | Built-in body: `wp-login`, `env`, `git-config`, `phpinfo`, `admin-login`, `robots`; sets the content type |
| `body` | string | | Inline decoy, at most 64 KiB; exclusive with `decoy` and `body_file` |
| `body_file` | path | | Decoy read at load and on reload (a missing file fails the reload), at most 1 MiB |
| `status` | int | `200` | Response status |
| `content_type` | string | `text/html; charset=utf-8` | For `body` and `body_file` |
| `delay` | duration | `0` | Hold the connection before answering, in a tarpit slot (`max_tarpits`), never in a request slot; at most 60s |
| `mark` | duration | `1h` | How long the client stays marked; at most 720h |

`response_headers` apply, so a decoy can carry a `Server` header of its
own. `GET /v1/honeypot` lists marked clients (address, route, hits,
first, last, expires) and the decoy names; `DELETE /v1/honeypot?ip=` and
`xproxyctl honeypot forget IP` remove a mark. The mark table holds at
most 65536 addresses. Counters: `honeypot_hits`, `honeypot_marked`;
metrics `xproxy_honeypot_hits_total`, `xproxy_honeypot_marked`.

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

The access log carries `mirror: sent`, `dropped` or `body_too_large`.
Counters: `mirror_sent`, `mirror_dropped`, `mirror_skipped`,
`mirror_failed`; metric `xproxy_mirror_total{outcome}`. Mirror
responses appear in the error log at debug level with their status.

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
| `mode` | `off`, `detect`, `block` | `waf.default_mode` | |
| `profile` | name | `waf.default_profile` | |

## cluster

Present means enabled. Nodes exchange rate limit consumption and ban
changes over mutual TLS (AMR-009, AMR-021). Every node listens and dials
every peer; there is no leader. Enabling or disabling the section, and
changing `listen`, `node_id` or `tls`, require a restart. Peers, intervals
and sharing flags reload.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `node_id` | name | host name | Identity announced to peers and used as the ban source (`peer:<node_id>`) |
| `listen` | host:port | required | Cluster listener. Must be a specific internal address, not all interfaces |
| `peers` | list of host:port | `[]` | Cluster addresses of the other nodes |
| `tls.cert_file`, `tls.key_file` | path | required | This node's certificate, used for both directions |
| `tls.ca_file` | path | required | Cluster CA; every peer must present a certificate from it |
| `tls.allowed_names` | list | `[]` (any name from the CA) | Restrict peers to these certificate common names or DNS SANs |
| `gossip_interval` | duration | `1s` | How often consumption and ban batches are sent; 100ms to 60s |
| `peer_stale` | duration | 3 x `gossip_interval` | How long a peer report keeps reducing local refill after its last update; at least 2 x the interval |
| `share_rate_limits` | bool | `true` | Exchange consumption reports |
| `share_bans` | bool | `true` | Exchange bans and unbans, and send a snapshot to a newly connected peer |
| `share_events` | bool | `true` | Exchange security events: honeypot marks and unmarks (applied to the peer's mark table with route `peer:<node>/<route>`) and OIDC session revocations (per filter name). Events are bounded (128 byte kind, 512 byte key, lifetime clamped to a year), queued without blocking and dropped when the queue is full. Nodes older than 1.3 close a connection that carries them: set `false` during a rolling upgrade from 1.2 |
| `max_keys_per_report` | int | `4096` | Largest consumers kept per report |

Semantics: with sharing on, a rate limit policy's `rate` becomes an
approximate cluster wide rate per key. Each node refills a key's bucket at
`rate` minus the sum of fresh peer consumption for that key; `burst` stays
per node. Accuracy is bounded by one gossip interval of delay and reports
expire after `peer_stale`, so losing a peer degrades to local limiting.

The cluster listener can be socket activated with `FileDescriptorName=cluster`.

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

A provider whose key set has never loaded (for example the JWKS URL is
unreachable at start) rejects tokens with 503 and `Retry-After` until a
fetch succeeds; a fetch that returns no keys keeps the previous set.

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
| `kind` | name | required | A registered kind: `header_guard`, `basic_auth`, `body_rewrite`, `bot_score`, `oidc`, `wasm`, or one added to `internal/filters` |
| `stage` | `before_auth`, `after_auth`, `after_waf`, `after_scan` | `after_auth` | Position relative to the built-in JWT, WAF and ICAP filters |
| `options` | mapping | | Kind specific; unknown keys are rejected |

### Kind `header_guard`

Requires or denies requests by header patterns (RE2 syntax).

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `require` | list of `{header, pattern}` | | Every rule must match the header's value (a missing header is the empty string) |
| `deny` | list of `{header, pattern}` | | Any match denies; evaluated before `require` |
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
| `external_url` | URL | derived | `scheme://host` the browser reaches the proxy on; derived from the request (`Host`, TLS or `X-Forwarded-Proto`) when unset |
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
| `instances` | int | `16` | Pooled instances; more are created on demand and dropped after use |
| `on_error` | `deny`, `allow` | `deny` | What a trap, timeout or bad result means: 500 with the filter name as reason, or continue with `wasm_error: allowed` in the access log |
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
| `weights` | mapping | see below | Override a signal's weight (0 to 100) |
| `reason` | string | the filter name | Deny reason |

Signals and default weights: `ua_bot` 40 (curl, wget, python, Go, Java,
scanners, headless browsers and the like), `ua_missing` 30,
`browser_headers_missing` 25 (a browser user agent without `Accept` or
`Accept-Language`), `fingerprint_mismatch` 35 (a browser user agent on a
hello without `h2` ALPN or with fewer than ten cipher suites),
`error_rate` 30 (more than half of at least ten recent requests were
4xx or denied), `path_spread` 15 (fifty or more distinct paths in the
window), `regular_interval` 20 (eight or more requests with machine-like
timing), `high_rate` 15, `honeypot_marked` 40 (the client touched a
honeypot route on this node or, with cluster sharing, on a peer). The
score is the capped sum; a client that is
already verified by the challenge is never challenged again. The JA4 of
every TLS request is logged as `ja4`.

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
| `min_bytes` | int | `1024` | Bodies below this length are not compressed; 0 to 1 MiB |
| `types` | list | text, script, style, JSON, XML, SVG, wasm and font types | Media types compressed, without parameters |

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
| `cookie_name` | token | `XPCHAL` | |
| `exempt_cidrs` | list | `[]` | Never challenged (monitoring, partners) |
| `title` | string | `Checking your browser` | Heading on the page; no HTML characters |

### routes[].challenge

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `mode` | `off`, `always`, `load` | `always` | `load` challenges only while the shedding load level is at or above `level` and requires a `shedding` section |
| `level` | float | `0.5` | Activation level for `load` mode |

The challenge is for browser-facing routes: API clients cannot solve it.

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
challenge settings (the key is kept), priority classes. Requires restart: any
change under `server.listeners` other than certificate file contents
(including the `tls.acme` groups), `management.socket`, cluster `listen`,
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
