# Changelog

All notable changes to Xproxy. The format follows Keep a Changelog and
the project uses semantic versioning from 1.0.0. Entries are grouped by
the roadmap phase that delivered them (see [ROADMAP.md](ROADMAP.md)).

## Unreleased

### Security (1.4)

A fifth audit round over every parser the data plane runs — binary and
wire formats, HTTP and text protocols, structured data — and the open
findings of rounds one to four. All with regression tests.

Parsers:

- The JSON Schema validator resolved `$ref` by writing a map on the
  request path. A validator is built once per route and shared by every
  request on it, so two concurrent bodies through one reference were a
  `concurrent map read and map write`: a fatal error, which no `recover`
  and no request guard can contain, from two unauthenticated requests
  (CWE-362). Every reference a document spells is resolved while the
  validator is still private to the goroutine that builds it, and
  `Resolve` is now a pure lookup. The same window also published a
  placeholder with no keywords, so a body could be validated against
  nothing.
- A query parameter spelled `NaN` satisfied every bound: `strconv`
  accepts it, and NaN compares false against each minimum and maximum,
  so a value outside a documented range passed validation and reached
  the origin (CWE-1289). Coercion now takes only numbers as JSON spells
  them — no `NaN`, `Inf`, hexadecimal floats or Go underscore separators
  — and a non-finite number is refused wherever one turns up.
- `upload_guard` treated a part whose `Content-Disposition` Go refuses
  (`filename="a.jpg"; filename="shell.php"`, a trailing bare parameter)
  as a plain form field, skipping the extension list, the
  double-extension rule, magic bytes, `deny_executables` and the size
  and count bounds for a body already replayed to the origin — where
  PHP, Commons FileUpload, busboy and werkzeug all take one of the names
  (CWE-436 into CWE-434). A disposition that names a file and does not
  parse is now a 400.
- Three more consumers threw away a media type Go refuses and carried on
  as if the header were absent: `graphql` (every bound — depth,
  complexity, aliases, batch, introspection — skipped),
  `account_guard` (the login identity, so the ladder and campaign
  detection went blind) and the WAF's body schemas. One
  `Content-Type: application/json; charset=utf-8; charset=ascii` was
  enough, and every lenient server-side parser reads the body anyway.
  All four sites, `sensitive_data` included, now share one rule.
- A path parameter and a backslash gave one resource a second routing
  key: `/admin;x` missed the `/admin` route and was answered by the
  catch-all while Tomcat, Jetty, JBoss and Spring serve `/admin`, and
  `/static\..\admin` is `/admin` to IIS, Apache on Windows and .NET
  (CWE-436, CWE-22). `reject_backslashes` now defaults to on and the new
  `reject_path_params` with it; the dot-segment check also splits on the
  backslash and cuts a path parameter, so it still sees through both
  when an operator turns the refusals off.
- `openapi` validated only the first value of a repeated query
  parameter, so `?limit=10&limit=999` passed a 1..50 schema and the
  whole query was forwarded untouched, while PHP and Rails take the
  last value, ASP.NET joins them and Spring binds an array (CWE-235).
  Every value of every parameter is judged now, as the proxy's own
  `routes[].policy` already did, and repeated headers and cookies with
  it.
- `sensitive_data` skipped the body scan entirely for one unrecognised
  `Content-Encoding`, a coding whose stream the decompressor refuses, a
  body that does not decode, several `Content-Encoding` header lines or
  a `Content-Range`. An origin hands the raw bytes to the application
  whatever the header claimed, so the header cost a client nothing and
  turned off data-loss prevention, `action: block` included (CWE-693).
  The new `unscannable` setting decides, and a request defaults to
  refusing with 415.
- A GraphQL fragment that spreads the next one twice doubles the work
  per level. The active set stops a fragment referring to itself, not
  one referred to twice, so a query of a couple of kilobytes expanded to
  a billion visits with every configured bound respected (CWE-405). The
  expansion has a visit budget and running out refuses the query.
- The response cache's `Vary` index grew for every distinct primary key
  ever stored and only a whole-cache purge cleared it: eviction held the
  byte bound while unauthenticated traffic — one request per query
  string, against any origin that sends `Vary: Accept-Encoding` — kept a
  couple of hundred bytes for good (CWE-401). The index is
  reference-counted and the last entry takes it.
- DNS: a query with the CD bit set installed its unvalidated answer in
  the cache for every other client of the listener. CD means "give me
  the data, I will check it myself"; the cache keys on name, type and
  class alone and the hit path never re-validates, so one query and one
  bit undid DNSSEC for everyone until the TTL expired (CWE-345). Only an
  answer this node stands behind is cached now.
- DNS: a message of compression pointers weighs fourteen wire bytes per
  record and expands to a 255-byte name plus a decompressed rdata name,
  so a 4 KB datagram became megabytes and a 64 KB one tens of megabytes,
  both on the client's own query when validation is on (CWE-409). The
  decompressed size is bounded as a multiple of the wire size, and
  `Pack` has a ceiling — no transport here could have sent the result
  anyway.
- DNS: an upstream UDP answer larger than the read buffer was chopped by
  the kernel with no error at all, accepted (the id and the question
  survive), and cached, denying those names to every client for the TTL
  (CWE-130). A full buffer is now treated as truncation and the query is
  asked again over TCP, and the forwarded query's advertised EDNS
  payload size is clamped to what the buffer holds — until now the
  client, not the proxy, chose it.
- DNS: a FORMERR reply claimed one question and carried none, a message
  this package's own parser refuses.
- QUIC: every coalesced Initial packet in a datagram derived its own key
  schedule — an HKDF extract, four expands and two AES key schedules —
  on the listener's own read goroutine, which also forwards every
  established flow. One 64 KiB datagram is over two thousand of those,
  so about a hundred spoofed packets per second stalled the whole
  listener (CWE-405). The schedule is derived once per connection id and
  at most four coalesced packets are read.
- The layer 4 SNI peek bounded the ClientHello by the first TLS record,
  while every TLS stack behind the proxy reassembles a handshake message
  across records: a client that fragments presented a name to the origin
  and nothing readable here, so its flow stalled until the peek timeout
  or, padded, took the default route with no name at all (CWE-436).
  Consecutive handshake records are joined now.
- The MMDB decoder had no work budget: an array of two pointers into the
  next array costs 2^k decodes for a chain of k arrays, six bytes per
  level, so 192 bytes reach 2^32 values and about a terabyte of
  allocation — and the metadata goes through the same decoder, so the
  whole file can be that small. `geoip.Open` runs at start-up and again
  on every reload, with a database most deployments fetch from a third
  party (CWE-409, CWE-1284). The decoder has a budget proportional to
  the file, and a container whose declared size the remaining bytes
  cannot hold is refused.
- The WAF's body schemas matched on the wire path, so `/v1/./orders`
  missed a schema the origin serves.

Open findings of the earlier rounds:

- `cluster.tls.bind_node_id` now defaults to on: an announced node id
  must be a name the peer's certificate carries, and a second hello on
  one connection is refused. Validation says out loud when
  `cluster.tls.allowed_names` is empty (any certificate the CA ever
  issued is then a cluster peer) or when `bind_node_id` is off. A
  cluster certificate is documented for what it is: full trust inside
  the cluster.
- A peer event no longer outlives what this node would have chosen for
  itself. A peer honeypot mark's lifetime is clamped to the longest
  `honeypot.mark` this node's own routes configure and a peer account
  block to the longest step of the local ladder; peer-sourced marks have
  their own quarter share of the table, so a peer cannot evict local
  ones; and an unmark only concerns a mark from the same peer.
- The sticky-session cookie's endpoint index was two bytes. It is four
  now, versioned by length as verification already was, so both cookie
  layouts stay valid across an upgrade.
- The challenge cookie can be bound to the host that issued it
  (`challenge.cookie_scope: host`), so a pass earned on the cheapest
  host cannot be spent on the host that asks for the most work.
- DNS: an `ANY` query over UDP is answered with TC=1 (RFC 8482), which
  is what an amplifier's favourite question deserves, and validation
  warns when a `kind: dns` listener on a non-loopback address has
  neither `allow_clients` nor `rate_limit`.
- The daemon refuses to start as uid 0 unless `-allow-root` is given;
  the shipped unit already runs as `User=xproxy` with socket activation.
- Compression no longer touches the response to a request that carried
  `Authorization` or a `Cookie`. Compressing a body that mixes a secret
  with attacker-chosen text leaks the secret through its length, a
  character at a time (BREACH), and a request the browser sends with the
  victim's cookies is exactly what an attacker can arrange. New
  `compression.compress_authenticated`, and a per-route override, turn
  it back on where the response holds nothing worth stealing.
- The CAPTCHA hostname check compares the hostname the provider reports
  against `challenge.captcha.hostnames` or the host names the routes
  configure. The request host was never an allowlist — the client
  chooses it, so an attacker who points a name of their own at the proxy
  only had to be consistent — and a configuration with neither list now
  fails validation.
- `/v1/health` reports `degraded` with the mechanisms that did not take
  effect when `sandbox.strict` is off; a missing one used to be a line
  in the start-up log and nothing else.
- Header operation values are redacted in `/v1/config` and in a
  configuration diff's text. A route's `request_headers.set` is where
  the credential the origin expects lives, and those responses travel
  much further than the file on disk. The names stay, the change list
  is still computed from the real documents, and the history keeps
  them, because a rollback writes them back.
- The fleet controller's `-any-name` has an alternative: `-name-map`
  names one node id to certificate name exception at a time. Both are
  counted and warned about on every authorisation that needs them, and
  `-any-name` warns at start too.
- `filter.Info` carries `TrustedPeer`, and the OIDC filter honours
  `X-Forwarded-Proto` only from one. Any client can send that header,
  and the URL derived from it is the redirect URI the identity provider
  sends the authorization code to; `external_url` depends on nothing the
  request carries.
- `upstreams[].origin_signature.body_digest` makes the signature cover
  the request body. Without it a signature proves that a request passed
  through the proxy, not what it carried, so anything that can reach the
  origin could replay a captured header set with a body of its own
  inside the TTL. The documentation adds the `X-Request-Id` dedupe that
  stops the replay itself.
- Token introspection already fails a missing issuer or audience
  (round four), so `audiences` needs no per-provider switch.
- `virtual_patches[].body.over_limit` decides a body the patch could not
  read, and treats it as matching by default. A virtual patch is the
  emergency control that holds a known vulnerability while the
  application is fixed, and 64 KiB of padding used to carry the same
  payload straight to the origin while the WAF and ICAP both refuse an
  oversize body.
- A span's `client.address` goes through the log redactor's `client_ip`
  rule (`tracing.redact_client_address`, on by default). A span is not a
  log line, so nothing took it through the redactor: a deployment that
  turned redaction on still exported the full address to its trace
  collector, beside a trace id the access log also carries.
- `account_guard`'s account hash is an HMAC under a key from a keyring
  (`secret_file`), not a truncated SHA-256 anybody could recompute. The
  cluster needs every node to read the same file.
- The hash ring normalises endpoint weights by their common divisor and
  has a ceiling: a hundred endpoints at weight 1000 built and sorted
  twelve million ring points on every discovery poll.
- The GUI's login limiter keys on the source *and* the account, with a
  global ceiling. Everyone arriving over the Unix socket or an SSH
  tunnel shares one address, so five bad guesses used to lock every
  operator out for five minutes.
- The scalars a reload writes and a request reads are atomics or taken
  under the lock they belong to — the cache's bounds, the shedder's
  bucket span and concurrency ceiling, the inventory's start time and
  logger, a QUIC flow's peeked server name. The new reload-under-load
  test found a real one in the cache's store path on its first run.
- The GUI's `viewer` role is documented for what it is: a trusted
  operator without write access, which reads the whole configuration
  file, the logs and the bans.
- A rate-limit shard whose keys are all live falls back to a coarser
  key — the client address, then its /24 or /48 — and refuses when
  there is nothing coarser left. Admitting an untracked request made
  the bound itself the way past the limit: rotate addresses until the
  table is full and every new key was free, which is cheap over IPv6.
  A full shard is also swept a bounded number of entries at a time
  rather than scanned whole on every miss, and a live bucket is never
  evicted to make room.
- The challenge's replay table is partitioned per client address, so
  one client solving challenges can no longer fill all 65,536 slots and
  have everybody else's verification refused; an entry expires at the
  nonce's own time plus its TTL rather than at the moment it was
  solved; and verification (`/.xproxy/challenge`) and the OIDC
  front-channel logout endpoint are rate limited per client address.
- A ban no longer costs a synchronous `fsync` on the request goroutine:
  state-file updates are batched through a queue, as the cluster's are,
  and a full queue falls back to the old synchronous write rather than
  losing the update. The escalation history is bounded
  least-recently-used instead of scanning the whole table on every
  trigger, and expired counts are swept by the purge loop.
- A reload tears the previous generation down when its last request
  ends, not after a fixed `shutdown_timeout`: a long upload or a gRPC
  or SSE stream older than that was cut or answered 500 although it was
  still making progress. A hard cap bounds one that never ends, and an
  HTTP/3 transport now drops only its idle connections while the
  generation is retired, as the TCP transports beside it always did.
  `max_concurrent_requests` and `max_tarpits` are applied on reload;
  both gates used to be sized once at start.
- New `server.limits.max_buffered_body_bytes` (512 MiB by default) is
  the process-wide ceiling on request bodies held in memory at once.
  Every feature that materialises one was bounded per request, and the
  product was the real ceiling: `max_connections_per_ip` times
  `max_body_bytes` is about 2.5 GiB of heap from one address at the
  defaults. A request that does not fit is refused with 503 before it
  is read.

### Fixed (1.4)

- **Every WebSocket upgrade through the proxy answered 502.** The
  transport wrapped each response body in a `ReadCloser` to account for
  the endpoint when the body closed. For a 101 the body *is* the
  connection, handed back as an `io.ReadWriteCloser` so the caller can
  splice both directions — and the wrapper hid the write half, so
  `httputil.ReverseProxy` refused it with "101 switching protocols
  response with non-writable body" and the client got a bad gateway.
  The idle reader and the capture tee hid it the same way. Upgrades now
  keep a writable body (with `CloseWrite`, which is how one direction
  is half-closed), and the wrappers that only make sense for a response
  body are skipped for a 101. This was found by writing the first end
  to end WebSocket test; `websocket: true` had never been exercised
  against a real origin.

### Added (1.4)

- **UDP and IP proxying over extended CONNECT (`forward.masque`): RFC
  9298 and RFC 9484.** HTTP CONNECT tunnels TCP and nothing else, so
  everything datagram-shaped an estate sends — DNS, QUIC, NTP,
  telemetry — either went around this proxy or did not go at all, and
  going around it was the usual answer. CONNECT-UDP is the same
  explicit proxy for datagrams: the same destination policy, the same
  credentials, the same access log, the same bans. Datagrams travel as
  capsules (RFC 9297), the fallback RFC 9298 requires when HTTP
  datagrams are unavailable — reliable and ordered, which for a proxy
  applying a policy per datagram is a feature rather than a cost.

  Every extended CONNECT is answered by this path, not only the two
  protocols implemented: an unimplemented one gets 501 rather than
  falling through to the ordinary CONNECT handler, where a request
  carrying a path and no authority would have been treated as a TCP
  tunnel to whatever its `:authority` said.

  CONNECT-IP is a VPN endpoint and is treated as one. The proxy does
  not create a tunnel device: a userspace process cannot put an
  arbitrary IP packet on the wire, a raw socket would need CAP_NET_RAW
  and would let a bug here forge any packet on the network, and the
  routing and firewalling of a VPN belong to the host's configuration.
  The operator creates, addresses and firewalls a `tun` interface and
  the proxy opens it; where none is available the request is refused
  with 501 and a reason in the error log. `ip_assign` and `ip_routes`
  are required because they are the anti-spoofing rule — a packet whose
  source is not the assigned address, or whose destination is outside
  the advertised routes, is dropped and counted — and the client is
  told both in ADDRESS_ASSIGN and ROUTE_ADVERTISEMENT capsules before
  it can send anything. `examples/forward/masque.yaml`.

- **DNS over QUIC, discovery, and SVCB/HTTPS records
  (`dns.doq`, `dns.discovery`, `dns.records`, `quic://` upstreams).**
  DoT and DoH both carry DNS over TCP and inherit its head-of-line
  blocking: one slow answer holds up every query behind it on that
  connection, which is the shape of a resolver's traffic. RFC 9250 puts
  each query on its own QUIC stream. It shares the listener's address
  and certificate, is separated from HTTP/3 by the `doq` ALPN, and
  sends the zero message id the RFC requires. `quic://host:port` is the
  matching upstream transport, with the connection reused across
  queries.

  Discovery (RFC 9462) is what makes any of it reach a client. One
  handed this proxy's address by DHCP cannot know the same service
  speaks DoQ; with `discovery` it asks `_dns.resolver.arpa`, gets SVCB
  records naming the encrypted endpoints, verifies their certificate
  and upgrades itself. Nothing is configured on the client, and a
  certificate it cannot verify means it stays on plaintext rather than
  trusting the record.

  `records` publishes SVCB and HTTPS records (RFC 9460) the resolver
  answers itself. The reason it exists is ECH: a client cannot encrypt
  its ClientHello until it has read the `ech` parameter from DNS, so
  for an estate running its own resolver this is the other half of the
  ECH feature. A name listed there is owned — answered locally, never
  forwarded, and NOERROR with no answers for a type it does not have,
  because a forwarded answer would contradict the local one. The
  encoder follows RFC 9460's canonical form (parameters in key order,
  once each) and the parser refuses records that do not.
  `examples/blocklists/dns-encrypted.yaml`.

- **SMTP and submission proxy (`kind: smtp`).** Mail was the traffic
  this proxy could only splice. A `kind: tcp` listener carries the same
  octets to the same mail server, but then the client and the server
  each decide on their own where a command and a message end — and that
  gap is where every SMTP smuggling bug lives. This listener speaks one
  session to the client and a second to the upstream, reads each line
  and each message itself, and writes them out again, so the framing is
  decided once.

  What that buys, concretely. A line must end with CRLF: a bare LF is
  the 2023 smuggling class (`\n.\n` ends a message for a permissive
  parser and not for a strict one) and is refused, or repaired to CRLF
  under `bare_newlines: convert`, which is only safe because the proxy
  re-emits the line. `CHUNKING` and `BDAT` are never advertised or
  relayed, because a length-framed message would put the decision back
  in two places. A reply the proxy cannot parse is never passed
  through: the client gets 421, since a reply the proxy did not
  understand is exactly the one the client would read differently. And
  anything pipelined behind `STARTTLS` ends the session — those octets
  were written before the client could see the 220, which is
  CVE-2011-0411 — with the session's greeting and authentication
  discarded after the handshake as RFC 3207 requires.

  It terminates STARTTLS (RFC 3207) or implicit TLS (RFC 8314, port
  465) for the client and can open its own to the upstream, so the hop
  is never the plaintext one by accident; with `upstream_tls_mode:
  starttls` an upstream that does not offer it fails the session
  instead. `require_tls` and `require_auth` hold AUTH and MAIL until
  the session is encrypted and authenticated. The capability list the
  client sees is the proxy's promise rather than the upstream's:
  hidden keywords stripped, `SIZE` replaced by `max_message_size`,
  `STARTTLS` advertised only while the proxy can still answer it, and
  `banner` in place of a greeting that otherwise names the mail
  server's brand and version. Bounds on recipients, messages, line
  length and refused commands keep one session from becoming a fan-out
  or a free walk through the command space; `VRFY` and `EXPN` are out
  of the default command set because they answer whether an address
  exists. A message past `max_message_size` drops the upstream
  connection without its terminator, so a truncated message is never
  queued as a whole one. Violations are `smtp_denied` deny events, so
  bans apply. `examples/mail/submission.yaml`.

- **WebSocket message inspection (`routes[].websocket_guard`).** An
  upgraded connection was the one place this proxy stopped looking:
  everything before the 101 went through routing, the WAF, the filters
  and the logs, and everything after it was an opaque stream. That is
  where applications put their real API. The guard parses RFC 6455
  frames in both directions and applies three kinds of check with three
  different false-positive profiles — structure (the protocol's own
  rules: reserved bits, reserved opcodes, masking, control frame size
  and fragmentation, continuation state, close codes and UTF-8), bounds
  (frame size, reassembled message size, client message rate), and
  patterns (an RE2 list over inspected messages). It never rewrites a
  frame: a violation closes with a close code that says why, or is
  recorded and forwarded under `action: log`.

  Both directions are inspected because the origin is the side holding
  the data. The negotiated subprotocol is checked on the 101, before a
  frame exists. Messages over `max_inspect_bytes` are checked to that
  bound and forwarded rather than buffered, so a client cannot choose
  the proxy's memory use. `permessage-deflate` is refused rather than
  ignored: a compressed frame cannot be inspected, so accepting the
  extension would turn every check off silently.
  `examples/routes/websocket.yaml`.

- **SOCKS5 and UDP associations on a forward listener
  (`forward.socks5`, `forward.socks_udp`).** An HTTP forward proxy only
  helps clients that speak HTTP proxying. Everything else in an estate
  — `ssh`, `git`, package managers, database clients, anything behind
  `curl --socks5-hostname` — speaks SOCKS5, and without it that traffic
  leaves outside the destination policy, the access log and the ban
  list. RFC 1928 and RFC 1929 are now spoken on the same port as the
  HTTP proxy: a greeting begins with the version byte and an HTTP
  request with a method, so one peeked byte separates them and nothing
  is configured twice.

  It is the same proxy, not a second one: the port list, `allow`,
  `deny`, `allow_private`, dialling the address that passed the check
  rather than re-resolving, the tunnel bound, the idle timeout, the
  security events, the `forward_denied` ban reason and the counters all
  apply unchanged. Credentials are verified against the same users file
  through the same cache and the same bounded hashing, so a listener
  with `auth` refuses a client that offers only "no authentication",
  and one without it is an open proxy for both protocols — which
  validation now says out loud. Policy refusals map to the closest
  SOCKS reply code instead of a blanket failure, so a client reports
  something true. SOCKS4 is refused (no authentication, no names) and
  `BIND` is not implemented, because it asks the proxy to open a
  listening socket on a client's say-so.

  `UDP ASSOCIATE` is how DNS and QUIC travel through a SOCKS proxy, and
  it is opt-in because a UDP relay is a wider exposure than a tunnel.
  Each association binds its own socket, is fixed to the client address
  that opened it, relays answers only from destinations that client has
  actually sent to, and dies with its control connection — the
  properties RFC 1928 requires and the ones that keep it from being an
  open reflector. Fragmented datagrams are dropped rather than
  reassembled and the peer table is bounded.
  `examples/forward/socks.yaml`.

- **Encrypted Client Hello (`tls.ech`), with the tooling to run it.**
  TLS 1.3 encrypts everything about a connection except the one field
  that says where it is going: the SNI, which is what network-level
  monitoring and blocking key on. ECH encrypts the real ClientHello to
  a key published in a DNS HTTPS record and wraps it in an outer hello
  naming a public name shared by everything behind that key. The
  listener accepts several keys at once, hands a client with a stale
  config the current one during the handshake it fails (so a rotation
  heals itself), and reloads keys with `xproxyctl reload-certs`.

  The parts that make it operable are the point. `xproxyctl ech keygen`
  writes the config and key files and prints both the YAML and the
  HTTPS record; `ech record` rebuilds a record from several configs for
  a rotation; `ech show` reads one back; and `xproxyctl tls` prints the
  config list the listener is *actually* serving, so a published record
  that has drifted from the deployment is visible rather than inferred.
  Validation refuses a config and key that do not belong together —
  the fault that otherwise hides perfectly, since every ECH attempt
  then falls back and the site looks healthy while encrypting nothing —
  refuses two keys sharing a config id, and warns when no certificate
  on the listener covers the public name a stale client falls back to.
  `require` refuses handshakes without ECH and says in an advice line
  what that costs. The access log carries `ech: true`, and
  `xproxy_tls_ech_total{listener,outcome}` counts accepted, not_used
  and refused. Enabling ECH raises the listener to TLS 1.3.

  What it changes elsewhere is documented rather than discovered: `sni`
  is the public name for every ECH client, JA3 and JA4 are computed
  from the outer hello and keep working, and a `kind: tcp` listener can
  no longer split ECH clients apart because the outer name is all it
  sees.

- **Post-quantum key exchange, as an explicit setting
  (`tls.key_exchange`, `upstreams[].tls.key_exchange`).** The proxy set
  `CurvePreferences` to `[X25519, P-256, P-384]`, which in Go replaces
  the default list rather than reordering it — so the X25519MLKEM768
  hybrid the toolchain gained was never offered, on any listener or to
  any origin, and no handshake said so. The list is now configuration,
  validated against the known groups, and its default leads with the
  hybrid. The threat it answers is not a quantum computer today but a
  recorder today: traffic captured now is decrypted whenever the key
  exchange falls, and a hybrid exchange costs about a kilobyte to
  remove that trade. A list that names groups but no post-quantum one
  loads with an advice line rather than an error, because a client
  fleet that cannot negotiate the hybrid exists and that is an
  operator's call. The negotiated group is in the access log as
  `tls_group`, counted by `xproxy_tls_key_exchange_total{group}`, and
  summarised with its post-quantum share by `xproxyctl tls` and `GET
  /v1/tls/key-exchange` — a rollout is measured on traffic, since the
  share moves as client fleets upgrade and not as the configuration
  changes.

- **[docs/DECEPTION.md](DECEPTION.md), the chapter behind the whole
  family.** Honeypot routes and decoys, honeytokens, form honeypots,
  the WAF files, the slow lane, deceptive answers and refusal at the
  handshake were each documented where they are configured, and
  nowhere as one thing. They are one thing: a cheap, unambiguous event
  at the top (a client asked for a path that does not exist), a mark
  carrying the judgement, and progressively more consequential actions
  below it. The chapter sets out the rule they all follow — a
  deception must be somewhere no legitimate client goes, or it is an
  outage with a clever name — ranks the controls by the false-positive
  rate they actually have, so the actions with consequences sit behind
  the signals with none, and gives a build-out order in eleven steps
  whose first six cannot refuse anybody. It also says what deception
  is not: not a substitute for a fix, not an attack, not a licence to
  lie to real users, and not free of the retention rules the access
  log lives under.

- **Thirty-eight more decoys, and the routes to serve them on.** The
  table goes from 77 bodies to 115: source control, build and artefact
  servers (`gitea`, `teamcity`, `nexus`, `svn-entries`,
  `idea-workspace`), container and cluster management, which is what
  the mining crawlers scan for (`portainer`, `rancher`, `etcd`,
  `nomad`, `spark`, `hadoop-yarn`, `airflow`), database consoles and
  analytics front ends (`pgadmin`, `mongo-express`, `metabase`,
  `superset`, `zabbix`), content management systems fingerprinted by
  version before anything is attempted (`joomla`, `drupal`, `magento`,
  `moodle`, `zimbra`), firewalls and remote access gateways
  (`pfsense`, `sonicwall`, `paloalto`, `cisco-asa`, `mikrotik`), the
  framework debug consoles and the probes that hunt them — the
  clearest signal in the set, because nothing but a scanner asks for a
  debugger (`werkzeug-console`, `symfony-profiler`,
  `laravel-telescope`, `thinkphp`, `phpunit-eval`, `spring-gateway`) —
  and the files a traversal or a misconfigured server hands over,
  which are also where a honeytoken belongs (`etc-passwd`,
  `firebase-config`, `wp-json-users`, `dockerfile`, `rails-secrets`).
  Every one carries a version string or a name worth reading, none
  carries a real credential, and every one is wired up in
  `examples/security/honeypots.yaml` with the paths and the mark
  duration it is worth serving on.

- **A third custom rule file, `examples/waf/attack-surface-rules.conf`.**
  Twenty-seven rules for the classes of attack that arrive as a
  recognisable shape rather than as a payload the application will
  mis-parse: cloud metadata addresses and non-web schemes in a
  parameter, the files a traversal asks for and the PHP stream
  wrappers that turn an inclusion into execution, serialised Java, PHP
  and YAML objects, external entity declarations, query operators
  where a field name belongs (in the query string and as a JSON key),
  a shell command after a separator, Spring's SpEL routing header and
  Shellshock, the two Transfer-Encoding spellings that let two servers
  disagree about where a request ends, the routing headers that poison
  a cache and the static extension bolted onto a private path,
  prototype pollution parameter names, header injection and off-site
  redirects, debugger parameters, uploads that execute in a browser,
  the scanners that still announce themselves, and interpreter error
  pages and directory listings refused on the way out. Two rules score
  rather than refuse, and two support rules (the 22900 block) make a
  JSON body inspectable without the CRS and an XML body's declarations
  visible at all — with the cost of the latter documented in the file.
  Shape rules are blunter than payload rules, so the file says so and
  the example `waf.yaml` loads it into a detect-mode profile. The
  tests put one request through every rule against an engine with no
  Core Rule Set, so a rule that stops matching cannot hide behind a
  CRS rule that catches the same request.

- **Hidden-field and timing honeypots on forms (filter kind
  `form_guard`).** A form bot does two things a person does not: it
  fills in every field it finds, including the one nobody can see, and
  it submits faster than anyone could have read the page. `fields`
  names inputs that must arrive empty — the classic hidden field, off
  screen and `aria-hidden`, which a person never sees and so cannot
  fill in; it is the rare signal with no false-positive rate to trade
  against a detection rate. `min_seconds` and `max_seconds` compare the
  submission against the last fetch of a page under `form_paths`,
  needing no JavaScript and no cookie, and `require_fetch` refuses a
  submission with no fetch on record for a deployment where the form
  page cannot reach a client any other way. Both halves are searched in
  the query string as well as the body, only
  `application/x-www-form-urlencoded` is parsed, and the body is
  buffered to `max_body_bytes` and replayed byte for byte, so the
  application receives exactly what the client sent. Denies carry a
  detail — `field:<name>`, `too_fast`, `too_old`, `no_form_fetch` — and
  add `form_seconds` to the access log line, which is what tells you
  where the floor belongs before you tighten it. The fetch table is
  bounded by `max_clients` and sweeps its older half when full, in the
  permissive direction: a forgotten fetch is "no record", which is
  allowed, so a busy node never starts refusing people.
  `examples/filters/form-guard.yaml`.

- **Deceptive answers on real routes (`routes[].deceive`).** A refusal
  is information: a scanner that gets 403 has learned that the request
  it sent was the interesting one, and it varies that request until
  something is not refused — the refusal is the oracle that tells it
  when it has found the way through. A route with `deceive` answers a
  client it no longer trusts with something ordinary instead. The crawl
  completes, the data is wrong, and the request that would have worked
  looks exactly like the one that did not.

  Clients are admitted by `marked` (a honeypot or honeytoken mark),
  `bot_score_at` or `client_cidrs`, narrowed by `methods`; the answer
  is a literal body, a file or one of the built-in decoys, with a
  status that defaults to 200. The origin is never asked, so a deceived
  write is discarded — the point for a `POST`, and the reason the
  conditions are worth being sure of.

  It is the one control here whose failure mode looks like success, so
  it is built to be hard to enable by accident and impossible to miss
  once enabled: a route with no condition is refused at validation,
  every route that deceives raises an advice line, and each deceived
  request produces a `deceive` security event, a `deceived: <route>`
  field in the access log, a counter, `xproxy_deceived_total{route}`
  and a row in `GET /v1/deceive`. Nothing is added to the response,
  because anything added is the tell.

- **Graduated degradation (`degradation`).** Every other answer the
  proxy gives is binary: served, or refused. For a client that has done
  something wrong but not enough to ban — touched a decoy, scored
  badly, arrived from a range with a history — both are wrong. Serving
  it in full funds the next request; refusing it tells it exactly which
  request to change, and hands a scanner the signal it tunes against.

  A degradation level serves that client correctly and slowly:
  `bytes_per_second` shapes the body through a token bucket that
  flushes as it goes (so the client sees a slow link rather than a late
  buffer), `delay` holds the response in a tarpit slot rather than a
  request slot, and `close` ends the connection so the next request
  costs a fresh handshake. Levels admit a client by `marked`,
  `bot_score_at`, `client_cidrs`, `routes` or `methods`; the first
  level that admits a request decides.

  Nothing is added to the response for the client to read — the page is
  the real page — so there is nothing to report as broken and nothing
  to tune against. `degraded: <level>` is in the access log,
  `xproxy_degraded_total{level}` counts it, and `GET /v1/degradation`
  reports the levels. Validation refuses a level that would degrade
  every request, and one that degrades nothing.

- **Refusal at the TLS handshake (`handshake`).** A banned client still
  got a full handshake: keys agreed, certificate sent, request parsed,
  and then a 403. That is an asymmetric key exchange spent on a
  refusal, and an answer a scanner can read — the certificate, the
  negotiated cipher, the error page, the header set. The new section
  refuses in the ClientHello instead: `refuse_banned` turns an existing
  address or fingerprint ban into a failed negotiation, and
  `deny_fingerprints` refuses a TLS stack outright, by full JA4 or JA3,
  or by a JA4 prefix ending in `*` for a family of clients. It covers
  every TLS listener including HTTP/3, since QUIC carries the same
  hello.

  What it costs is the record, and the documentation says so where an
  operator will meet it: a refused connection never becomes a request,
  so there is no access log line, no request id, no route and no
  filter. The security log (reason `handshake`, detail `banned` or
  `fingerprint`, both fingerprints and the address),
  `xproxy_tls_handshakes_refused_total`, `GET /v1/handshake` and the
  line `xproxyctl tls` now prints above the certificates are what
  remain. Validation says the same as advice, refuses `refuse_banned`
  without a `bans` section, and warns when no listener has TLS at all.

- **Honeytokens: the hook on the bait (`honeytokens`).** The decoys
  hand out an AWS key, a database password, a connection string, a
  private key block. Nothing watched for their use, so a scanner read
  the file and the proxy learned only that the file was read. A new
  top-level section registers the planted values — in a decoy, a
  repository, a paste, a backup, a document, a staging database — and
  any request presenting one is refused before routing, counted,
  logged and marked.

  It is unlike every other control in the configuration in one
  respect: nothing legitimate ever sends one, so there is no score to
  tune and no false-positive rate to trade against a detection rate. A
  ban trigger on reason `honeytoken` with `threshold: 1` is the right
  threshold, and a single hit is worth an alert.

  Each token names where it was planted, so the alert identifies the
  leak and not only the token. `in` chooses where to look — headers
  (each value, again with a `Bearer `, `Basic `, `Token ` or `ApiKey `
  scheme stripped, and a Basic credential decoded into user and
  password), cookies, query parameters, and the path with each of its
  segments — and `headers` narrows that to named headers. `match:
  contains` finds a token planted inside a document a client echoes
  back; the default compares whole values. Bodies are not searched,
  because every request would have to be buffered to do it and a
  stolen credential is presented in the head. Values come from the
  configuration or from a `values_file`, and the work per request is
  bounded (256 candidate strings, 8 KiB scanned per value) because a
  client chooses how many headers it sends.

  The value is never written to a log: a hit names the token, the
  field and the description, so finding a plant does not copy the
  credential into a second place. Validation refuses a value short
  enough to collide with real traffic (8 characters, 16 for
  `contains`), refuses the same value planted twice, and advises
  against leaving a token in `log` mode. Hits survive a reload;
  `GET /v1/honeypot` and `xproxyctl honeypot` list the plants with
  their hits and last hit, and `xproxy_honeytoken_hits_total{token}`
  counts them. `examples/security/honeytokens.yaml`.

- **Twenty more decoys, and the routes to serve them.** The honeypot
  table goes from 57 bodies to 77, and every one of them is wired up in
  `examples/security/honeypots.yaml`. New: `gcp-metadata` and
  `azure-imds` (the two metadata services a server side request forgery
  probe asks for after it has tried AWS), `registry-catalog`, `argocd`
  and `keycloak`, the application servers with their own exploit
  history (`weblogic`, `jboss`, `coldfusion`, `aspnet-trace`), the
  documents that are XML on the wire (`web-config` with a connection
  string, `xmlrpc` with `pingback.ping`, `minio`, `camera`, and
  `sitemap`, which like `robots` is served honestly and names the decoy
  paths), the newer end of what gets scanned (`jupyter`, `ollama`,
  `clickhouse`), the remote access appliances (`ivanti`, `nextcloud`,
  `cpanel`) and a `printer`. Each is judged by the same table-wide
  tests as the rest: plausible length, a content type that parses, a
  body that parses as what it claims, a visible marker on anything
  shaped like a credential, and a route in the example that serves it.
- **A second custom rule file, `examples/waf/hardening-rules.conf`.**
  Fifteen rules (ids 21001 upward, so they collide with neither the
  20001 block nor the CRS) for the shapes a WAF is better placed to
  refuse than the application is: backup and editor leftovers and
  source-control directories answered 404 rather than 403, template
  expressions scored at warning so one alone is not a refusal, JNDI and
  nested expression lookups denied outright, Spring's class loader
  reached through a bound parameter, `..;/` and path parameters in the
  request line, the diagnostic methods, upload file names the origin
  might execute, bounds on parameters, cookies and byte ranges, GraphQL
  introspection, and — on the way out — private keys, cloud access keys
  and database error messages. Every rule is exercised by
  `TestWAFHardeningRules`, which also puts ordinary traffic through the
  whole file, because a rule set that compiles but no longer matches is
  a control an operator believes is there.

- **Packet capture of the exchanges the proxy handled (`capture`).** A
  new section writes what the proxy saw as pcapng files that Wireshark,
  tshark and every other pcap tool open directly. The proxy terminates
  TLS, so there is no point on the wire where the exchange is both
  complete and readable — in front of it the bytes are ciphertext,
  behind it the client is gone and the request carries the proxy's own
  address. What this writes is the proxy's own view: the request as it
  arrived after the header edits and the response as the client
  received it, synthesised into a TCP conversation (handshake, data
  segments at a 1460 byte MTU, orderly close, correct IPv4/IPv6 and TCP
  checksums) between the real client address and the listener, so a
  dissector reads it as HTTP and `Follow TCP stream` shows the
  exchange. Each frame carries the `X-Request-Id` as a pcapng comment,
  so a frame and an access log line name each other. An HTTP/2 or
  HTTP/3 exchange is rendered with an `HTTP/1.1` start line, because a
  dissector needs one; an exchange the client abandoned is written as
  `HTTP/1.1 000 No Response` rather than an invented 200.

  When a capture is taken is decided along two axes. `rules[]` select
  which flows: by `hosts` (exact or `*.example.com`), `routes`,
  `methods`, `paths`, `client_cidrs`, `statuses` (a status or a class
  as a single digit), `reasons` (a deny reason, matched against both
  `waf` and `waf:942100`), `denied` for every refusal whatever the
  reason, `percent` for sampling and `max_flows` for a bound. Every
  selector a rule names has to hold, the first matching rule decides,
  and a rule naming none — or no `rules` at all — is every flow. The
  selectors on the answer cannot be decided when the request arrives,
  so those exchanges are held and written retrospectively: `denied:
  true` produces a file of exactly what the proxy is refusing. The
  second axis is time: the configuration says what *may* be captured
  and reloads, while a runtime switch says whether anything is being
  captured *now*. `xproxyctl capture start [-duration 10m]`, `stop` and
  `status`, and `GET`/`POST /v1/capture`, drive it; both mutations are
  audited with the caller's credentials, the window closes itself after
  `max_duration` (default 1h, at most 24h), and a reload carries the
  switch and its deadline over unchanged so a capture is not silently
  stopped mid-reproduction.

  The files hold decrypted traffic, and are treated as such throughout:
  created `0600` with `O_EXCL` in a directory the operator names and
  the proxy alone writes to, with proxy-chosen names, rotated at
  `max_file_bytes` and pruned to `max_files`; `redact` replaces the
  listed header values with the fixed string `REDACTED` (a fixed
  string, not a blanked-out value, so neither the value nor its length
  is in the file) and defaults to the authorization, cookie and API key
  headers; CR and LF are stripped from every captured header value, so
  a value carrying a newline cannot write a header of the attacker's
  choosing into the file the next reader parses; bodies are off by
  default and bounded by `max_body_bytes` when on, with a truncated
  body marked in the frame comment rather than silently short. The
  capture is closed on shutdown, so the last exchange — the one being
  investigated — is not the one missing. `xproxy_capture_active`,
  `xproxy_capture_flows_total{result}`, `xproxy_capture_truncated_total`
  and `xproxy_capture_bytes_total` report it, and nothing runs on the
  request path unless a capture is recording and a rule wants the
  exchange. `examples/security/capture.yaml`.

- **Virtual `security.txt`.** A new `security_txt[]` section serves an
  RFC 9116 document from the proxy at `/.well-known/security.txt` and
  the legacy `/security.txt`, before routing, so a host with no
  application behind it (a parked domain, a redirect, a maintenance
  page) still answers the question a finder asks. Each entry selects the
  hosts it answers for by exact name, `*.suffix` wildcard, regular
  expression, client CIDR or listener name, and the first entry that
  matches wins — one document for the brand, another for an internal
  range, a catch-all for everything else. The body is either rendered
  from the fields (`contact`, `expires` or `valid_for`, `encryption`,
  `acknowledgments`, `preferred_languages`, `canonical`, `policy`,
  `hiring`, `csaf`, `extra` and a leading `comment`) or taken verbatim
  from `body`/`body_file`, which is how a clear-signed document is
  served; `body_file` is re-read on reload, so a re-signed document
  needs no restart. Field values are rejected at validation if they
  carry a newline or a control byte, because a newline in a value would
  let it append a `Contact` line of somebody else's choosing. Responses
  are `GET`/`HEAD` only (405 otherwise), cached for `cache_for` and
  counted in `security_txt`.
- **`security_txt[].host_cidrs`: a document selected by address range.**
  The virtual `security.txt` could already be scoped to one host, to a
  wildcard domain, to a regular expression, to a client network, to a
  listener, or to everything. The one host a name-based selector cannot
  reach is the one that has no name: a machine found in a range scan,
  a parked address, a range a provider assigned. That client sends
  `Host: 198.51.100.7`, and it is the finder with the least to go on
  and the most need of somewhere to report.

  `host_cidrs` matches the `Host` header read as an address literal, in
  either family and in either spelling — `::ffff:198.51.100.7` is the
  IPv4 address it carries, so one prefix covers both. It joins the
  other host selectors as a union, so one entry can name the hosts it
  knows and the range everything else sits in;
  `host_cidrs: ["0.0.0.0/0", "::/0"]` is every address literal there
  is. A `Host` that is a name never matches it, whatever that name
  resolves to: the proxy does not resolve the `Host` header, and a
  document that turned on what a name resolves to would be answering
  on the client's word.

  `docs/USAGE.md` gains the section the feature never had, with the
  table that maps one host, a group and all of them onto the selector
  that expresses each; `examples/security/security-txt.yaml` gains the
  parked-address entry and the commented any-address one.

- **Fifty-six honeypot decoys.** `honeypot.decoy` now takes 56 names
  covering the paths scanners actually probe, grouped in
  docs/CONFIG.md by what the scanner is after. Beside the original PHP,
  WordPress and leaked-file set: the secrets a laptop or a build agent
  leaves in a deployment (`npmrc`, `pypirc`, `gitlab-ci`,
  `terraform-state`, `vscode-sftp`, `appsettings`, `database-yml`,
  `nginx-config`, `laravel-log`); the cloud and orchestration APIs a
  server side request forgery probe asks for, where the client is
  asking the proxy to fetch its own credentials (`imds`, `consul`,
  `vault`, `docker-api`, `kubelet`); data stores and dashboards
  (`couchdb`, `solr`, `rabbitmq`, `kibana`, `prometheus-config`,
  `traefik`); the enterprise front doors a mass scanner fingerprints
  before it picks an exploit (`confluence`, `gitlab-login`, `citrix`,
  `fortinet`, `esxi`, `exchange-autodiscover`, `cgi-bin`); and the
  application internals that leak a shape rather than a file
  (`wp-users`, `graphql`, `adminer`).

  Every credential, key and host name in them is visibly fake, and that
  is now a test rather than a convention: a decoy whose body assigns a
  password, a token or a key fails unless the value carries a marker a
  reader recognises, and a private key block fails unless what it holds
  decodes to a message saying it is a decoy. The documentation
  reference and the names the validator accepts are checked against
  each other, so a decoy cannot exist in one and not the other.

  `examples/security/honeypots.yaml` wires up all 56 — one route per
  decoy with the paths each is worth serving on, and the mark scaled to
  what the request means: an hour for a path a confused crawler might
  reach, six hours for a file only a credential hunt asks for, a day
  for a metadata or orchestration probe. A test refuses a decoy the
  example never demonstrates, a path two routes both claim, and a
  catch-all that is not last.

### Tests (1.4)

Security tests for the surfaces this release adds, written as an
attacker would read them rather than as coverage.

`test/bypass` gains two files. The first treats the capture file as
what it is — the one artefact of this proxy that holds decrypted
traffic on disk — and tries to get a secret into it (every spelling of
a redacted header name, a length-preserving placeholder), to get a
header of one's own into it (encoded CRLF in the path and in a query
value, a bare CR in a header value, a body carrying a whole fake HTTP
message, each either refused before the capture or framed so a
dissector cannot mistake it), and to switch it on from the outside
(`/v1/capture` on the data plane is an application path and changes no
state). It also asserts the file mode, that the directory holds nothing
but the proxy's own pcapng files, and that a refusal is captured with
the status the client got and nothing from an origin that was never
asked. The second file is about what a scanner can learn: a decoy
carries no cookie, no redirect and no reflection of what the client
sent, is byte-identical for every client and on every hit, and — the
property that makes a honeypot worth running — a marked client's
ordinary traffic is indistinguishable from anybody else's, header for
header, with the mark visible to the operator and never to the client
or the origin. A last case walks every refusal the harness can produce
and asserts none of them names an origin address, an upstream or an
internal path.

`internal/capture` gains a fuzz target over the flow writer: arbitrary
request bytes, response bytes and comments through every endpoint
pairing, with the result walked block by block the way a reader with no
trust in the file would. A capture that crashes the tool it is opened
with is a capture that cannot be read during the incident it was taken
for.

The JNDI rule of the new hardening file is tested against the
obfuscations the payload is actually written in — `${lower:j}ndi`,
`${::-j}` assembled character by character, the scheme split across
`${env:}` lookups — through the query string, two headers and a JSON
body, because a rule that only catches the plain spelling is a rule
that catches nothing.

A round of adversarial and robustness tests over the parsers, the
protocol clients and the views, written from the outside in: what a
client, a peer, a scanner, a certificate authority or a file on disk
can put in front of each of them. Forty-six packages gained a suite;
`docs/TESTS.md` lists every case. The findings each have their own
entry above.

The categories, and where they landed: expansion and recursion bombs
(the configuration's YAML anchors, JSON Schema `$ref` chains, GraphQL
fragment spreads, MMDB pointer loops); truncation at every length and
single-bit corruption (ClientHello, QUIC Initial, PROXY protocol, MMDB,
the configuration); type confusion and the numbers a format disagrees
about (leading zeros, octal, hex, underscores, int64 edges, NaN, Inf, a
decimal comma); time (every instant around `exp` and `nbf`, the 2038
rollover, the largest exact float64 integer); encodings and i18n
(BOM, CRLF, lone CR, UTF-16, invalid UTF-8, lone surrogates, homoglyphs,
combining marks, the Turkish dotted i, the Kelvin sign, bidi and
zero-width controls); line breaks and separators (nineteen hostile
values through every log format); the file system (permissions,
symlinks, a truncated file, long and non-ASCII names, a failed write);
algorithmic complexity (ReDoS, quadratic `uniqueItems`, alias floods);
resource bounds (in-flight limits, queues that drop rather than block,
tables an attacker fills); concurrency and determinism (shared
validators, shared filters, shared ban lists, byte-identical error
text); and the trust boundaries (a scanner that rewrites a request, a
peer that names itself, an agent that reports its host name, a
WebAssembly module that reaches past its sandbox).

### Fixed (1.4)

- `routes[].honeypot.mark: 0s` was silently replaced by the one-hour
  default, because the field could not tell an absent value from a
  zero one. The shipped example gives the `robots` route exactly that,
  so a search engine that read `robots.txt` — which is what the file
  is for, and what the route serves it honestly for — was marked, and
  with the sweep trigger in the same example, banned. Reading the map
  now marks nobody; asking for what it names still does, which was
  always the point. `mark` is a pointer internally, so `0s` means zero
  for honeypots and honeytokens alike, and a test drives a crawler
  through both routes.

- A `denied: true` capture rule missed the refusals decided before
  routing — a ban, the maintenance gate, a malformed `Host`, the
  concurrency ceiling — because the capture hook runs once the route is
  known and those requests never reach it. They are the refusals an
  operator most wants in the file. An exchange that never reached the
  hook is now offered to the rules at the end instead, without bodies,
  since nothing read them.
- The sandbox gave the capture directory a read rule rather than a
  write one, because the Landlock rules are derived from the
  configuration by key name and nothing knew about `capture.directory`.
  A capture that was configured, enabled and switched on would then
  write nothing on any Linux host with the sandbox on, which is the
  default — the failure counter would climb and the directory stay
  empty. `Derive` now grants the directory of an enabled capture
  section, and `TestDerive` covers it along with the one other key of
  that name, the ACME directory, which is a URL and must produce no
  rule at all.
- `internal/challenge` `TestFlow` asserted that the counter `1` fails a
  difficulty-10 proof. One nonce in a thousand is solved by it, so the
  test failed about that often for no reason. It now looks up a counter
  that provably does not solve the nonce it was given.
- `xproxy_capture_bytes_total` reported the size of the current capture
  file rather than the bytes written in total, so a rotation looked
  like a counter restart to anything reading it as the counter it is
  declared to be. It now accumulates across files. `capture.directory`
  and `capture.start_active` are also documented as they behave: the
  directory must exist and is the proxy's alone, and a capture that
  begins at start-up runs until something turns it off — `max_duration`
  bounds the window an operator opens, not that one.

- `Keyring.All` and `Keyring.Keys` handed out the ring's own key
  material rather than a copy, so a caller working in place would have
  changed what the proxy signs with, and `Primary` panicked on a ring
  with no keys. Both now copy, and the accessors answer for an empty or
  nil ring.
- A password verification whose caller had already gone away still took
  a slot and spent a full hash on an answer nobody would read. The
  select between the semaphore and the context picks either when both
  are ready, so a client that disconnects during a burst of logins
  still cost the proxy the work. `passwd.Acquire` now returns at once
  for a context that is already done.
- The ingress controller built file names under `cert_dir` out of the
  namespace and secret name an API server sent it, and put the same two
  values into the request path it fetched a Secret with. A name
  carrying a separator or a dot segment — which a real API server never
  sends, but a compromised or impersonated one does — would have left
  the directory and overwritten a file the proxy user can write. Both
  are now checked against what the API server itself would have
  accepted, and a name that is not one is refused before the request.
- An Ingress rule's host and path went into the proxy's own
  configuration unchecked. A tenant who can create an Ingress could put
  a space, a carriage return or a NUL into a route host or path, where
  it became a routing key, a metric label and a log field for every
  other tenant on the proxy. A host must now be a DNS name (a leading
  wildcard label allowed) and a path must be a plain prefix with no
  space or control character; anything else is dropped with a warning,
  the way an unresolvable service already was.
- A TLS secret referenced by an Ingress or a Gateway was read whatever
  its type, so a reference to an Opaque secret that happened to carry
  `tls.crt` and `tls.key` published it. The Ingress API requires a
  `kubernetes.io/tls` secret; anything else is now refused with a
  warning.
- The canonical form of a SOA record lowercased only its first name.
  RFC 4034 section 6.2 requires both the MNAME and the RNAME to be
  lowered before a signature is checked, and the helper stops at the
  root label of the name it starts on, so a zone whose RNAME carries
  any upper case letter had its SOA signature computed over the wrong
  bytes. SOA records appear in every negative answer, so the effect was
  a denial proof that could not be verified and a name that reads as
  bogus.
- `lowerName` sliced its input at an offset it had not checked. The
  record types that reach it carry a fixed part before the name (a
  preference, a priority and a port), and rdata shorter than that
  fixed part — which is what a malformed or hostile answer holds —
  panicked the goroutine reading the upstream's reply. It now returns
  nothing to lower.
- An RSA DNSKEY with an exponent of 0 or 1, or an even one, was
  accepted by the key parser. Verification refused it afterwards, so
  nothing was ever verified with it, but a key that cannot be a key is
  refused where it is read.
- `xproxyctl` printed what the daemon told it, byte for byte, including
  the control characters a terminal acts on. Most of what its tables
  carry came off the network — a ban target and its reason, an endpoint
  discovered by DNS, a path the API inventory learned from a request, a
  cluster peer's node id and last error, a certificate subject, a
  honeypot hit's path and user agent — so a client able to get a value
  into one of those tables could clear the operator's screen, set the
  terminal title, or overwrite the line above with a carriage return
  while the operator read it. Everything the tool prints now goes
  through a filter that replaces every C0 byte and DEL with `?`, one
  for one, keeping newline and tab so the columns still line up and
  leaving UTF-8 untouched. The terminal interface and the fleet tool
  already did this; the control tool did not.
- The last-resort rate-limit key took the client's network, and answered
  an invalid client address with the literal text `net:invalid Prefix`.
  `netip` gives the zero address the zero prefix and no error, so the
  guard that was there never fired, and every client whose address the
  listener could not parse shared one bucket named after a stringer's
  error text. The key is now empty for an address that is not one, which
  is the answer the limiter already handles: with nothing coarser left
  it refuses rather than admits.
- `dnsPolicy` dereferenced the `cache` section of a `dns` listener
  without checking it. Parsing always fills it in, so no configuration
  file reached it nil, but the type permits it and a configuration
  assembled another way would have panicked the process at bind time
  instead of reporting a bad listener. The defaults are now used for a
  missing section.
- The LDAP filter parser had no depth bound. It is recursive, and the
  filter template is parsed once per login attempt, so a `user_filter`
  nested a few million levels deep — pasted in, generated, or copied
  from somewhere — met the goroutine stack limit and took the whole
  proxy down at the next login, rather than failing validation. Filters
  now nest at most 32 levels, the same bound the BER decoder applies, so
  a filter that would not survive its own encoding is refused where it
  is written.
- The web interface answered 500 for a log stream whose file did not
  exist yet. That is the ordinary state right after an install, or for a
  stream nothing has written to since the last rotation, and an operator
  opening the log view saw a failure of the proxy where there was none.
  A configured stream with no file is now an empty view; a stream that
  is not configured is still refused.
- The web interface could not answer 413 for an oversize configuration.
  The documented ceiling is 8 MiB of text, but every request body went
  through a 4 MiB reader first, so a document between the two limits was
  refused as a malformed body rather than as an oversize one. The
  configuration endpoints now read up to twice their own text ceiling,
  so the size check is the one that answers.
- A line in the users file with an empty hash was accepted. The user
  existed, appeared in the list and could never log in, because an empty
  hash verifies against nothing; a truncated line or a botched edit read
  as a deliberate account. Such a line is now an error naming the file
  and the line, with the `x509` spelling for a certificate-only user in
  the message. `xproxy-admin user add` already refused it.
- The terminal interface raced with itself. Each view is fetched by two
  goroutines — one waiting, one calling — so that a slow view does not
  hold the others; the waiting one gives up at the refresh deadline and
  the calling one is left running. It then stored its answer into the
  `Data` the fetch had already returned and the renderer was already
  drawing, which is a write to a live map from a goroutine nobody is
  waiting for. A management call slower than the refresh interval was
  enough. The result is now marked as no longer ours once the fetch
  returns, and a late answer is dropped.
- The terminal interface filtered only its security log view. Every
  other cell — a ban reason, a peer's node id and last error, a
  certificate's subject, a WAF rule's message, an upstream address, the
  error text of a subsystem that failed — was drawn as it arrived, so a
  compromised cluster node or a hostile certificate could clear the
  operator's screen, set the terminal title, repaint another row with a
  carriage return or move the cursor. Every rendered line is now
  filtered, keeping only the eight colour codes the renderer itself
  emits; the worst a value can still do is colour a cell.
- `bans.exempt_cidrs` did not release the bans it covers. The
  exemption was consulted when a ban was placed and never afterwards,
  so an operator who added the range for a monitoring probe, a partner
  or their own office found the reload changed nothing — and neither
  did a restart, because the state file restored the ban. Bans covered
  by the exemptions are now dropped when the configuration is applied
  and again after the state file is read, with a log line naming each.
- `tracing.Tracer.StartServer`, `Span.Traceparent`, `Span.TraceIDString`
  and `Span.SpanIDString` panicked on the nil value the rest of the
  package uses to mean "tracing is off", and `Encode` dereferenced an
  exporter a propagate-only tracer never builds. Every caller in the
  proxy checks first, so none of this was reachable; they are nil-safe
  now, like the other methods, so a future call site cannot make it so.
- The GeoIP metadata reader turned a NaN into a number. NaN compares
  false against both ends of a range check, so the guard let it through
  and the conversion produced an implementation-defined value that then
  became a node count, a record size or an index. The range check now
  asks whether the number is a number first. No database in the wild
  carries one, and the counts are re-validated afterwards, so this was
  latent rather than reachable — but it is the same defect the JSON
  Schema coercion was fixed for.
- A bearer token with a trailing newline verified as the token itself.
  Go's base64 decoder skips carriage returns and newlines, so
  `<token>\n` and `<token>` were one credential with two spellings —
  which the introspection cache, a revocation list and every log line
  key on separately. A compact JWS is base64url and dots and nothing
  else, and anything else is now refused before the token is parsed.
- A `Host` header could carry two spellings of one name. Unicode's
  simple lower-case mapping sends U+0130 (Turkish dotted capital I) to
  ASCII `i` and U+212A (Kelvin sign) to ASCII `k`, and the ASCII check
  ran after the fold, so `İnternal.test` folded into
  `internal.test` and became its routing key while the upstream read
  the name the client sent. The same held for anything after the last
  colon: `example.com:https` and `example.com:` were stripped to
  `example.com`. Both are now refused — non-ASCII is rejected before
  folding, and only a numeric port may follow the name — which is the
  rule the bracketed IPv6 form already enforced.
- A JSON Schema `enum` that lists `null` refused `null`. The null check
  ran before the enum and had no way to consult it, so a schema that
  explicitly admits a null field rejected one. The null branch now asks
  the enum, and refuses with the enum's own message instead of a second,
  different one.
- A listener or endpoint address padded with whitespace
  (`" 127.0.0.1:8080 "`) passed validation. `net.SplitHostPort`
  separates on the last colon and never looks at the rest, so
  `xproxy -validate` said OK for a configuration that then failed to
  bind at start. Addresses with leading, trailing or embedded
  whitespace are now a validation error, where the operator sees them.

### Changed (1.4)

- Troubleshooting moved out of `docs/USAGE.md` into a document of its
  own, [`docs/TROUBLESHOOTING.md`](TROUBLESHOOTING.md), and then grew to
  about two and a half times its original size: forty-eight sections in
  five parts.

  New orientation material: what each `xproxyctl` command is for; **where
  a request can die**, the thirty-three stages in the order the proxy
  evaluates them with what each one can refuse (which is the answer to
  "why has this counter not moved"); the **timeout ladder**, all eight
  timeouts across three configuration sections in the order they fire;
  how to prove the problem is not the proxy; and how to reproduce one
  without affecting clients.

  New subsystem sections: the three HTTP versions, WebSockets and
  streaming, gRPC and gRPC-web, static files, virtual patches and the
  positive policy, mirroring and shadowing, bot scoring, the API
  inventory, origin lock, virtual security.txt, Kubernetes ingress mode,
  clocks and expiry, misbehaving clients, capacity and sizing,
  emergencies, upgrades and rollback, when to escalate, and a glossary.
  The existing sections gained about a page each.

  Five things the document said that were not true are fixed: there is
  no `xproxyctl pools` command (it is all in `upstreams`), the cache is
  purged with `cache purge HOST PREFIX` and not with flags,
  `waf-exclusions` is `waf exclusions`, `spki` reads a certificate file
  rather than a live address, and the access log has no `upstream_ms`
  field — the upstream's share of a request comes from the trace or from
  `xproxyctl upstreams`. The access log's `challenge_tier` and the
  cache's `store` value did not exist either.

  The deny reason table now says which reasons a `bans.triggers[]` entry
  may name, and explains the three spellings one refusal has: the access
  log's `denied`, the security log's `reason` plus `detail`, and the
  folded ban category a trigger matches on.

### Security (1.3)

Findings of a fourth audit round, in disciplines the first three did not
use (time and lifetime semantics; observability as an attack surface;
Go integer, aliasing and buffer-reuse hazards; a hostile peer already
inside the cluster's trust boundary; and a systematic sweep of what
every error path does), plus fuzzing of five parsers that had no fuzz
target. All with regression tests:

- One host name no longer has several routing keys. A route is selected
  by an exact match on the normalised host, so `Host: api.example.test..`
  missed every route of that host and was answered by the catch-all,
  skipping its access lists, authentication filters, WAF profile, rate
  limits and policy (CWE-436). Text with an empty label anywhere is
  refused with `bad_host`; a single trailing root dot, a port and any
  case still normalise to the one key. The same rule now applies to the
  server name peeked from a TLS ClientHello, which selects the layer 4
  and QUIC upstream.
- A DNS label may no longer carry a dot, a backslash or a control byte.
  Labels are joined with `.` to make the string used as the block list
  key, the cache key, the name DNSSEC compares and the value written to
  the security log, and that join is only reversible while no label
  contains a separator: the wire names `[www.bank][test]` and
  `[www][bank][test]` produced the same string, so one would have been
  answered from the other's cache entry and would have satisfied the
  other's DNSSEC binding. A control byte in a label reached the security
  log, where a newline ends the record.
- `ParseMessage` sized its record slices from the section counts the
  sender declared, so a 17-byte datagram allocated megabytes: about
  185,000 to one, from a spoofable packet, on any listener with DNSSEC
  validation (CWE-789). The allocation is now bounded by the bytes the
  datagram actually holds.
- Token introspection treated a missing issuer or audience as a pass.
  RFC 7662 lets an authorization server answer with nothing but
  `{"active": true}`, so every live token of that server was accepted,
  including one minted for another client or tenant (CWE-863). Absence
  now fails, as it always did on the JWT path.
- A layer 4 or forward-proxy tunnel whose peer stopped reading was never
  reclaimed: the copy had a read deadline but no write deadline, so
  `idle_timeout` could not close it and the flow held its goroutines,
  its sockets, its connection-limiter slot and its endpoint's active
  count for the life of the process (CWE-1088).
- A cached response's headers were handed to the per-request response
  by reference. The response-header operations end in an append, which
  with spare capacity writes into the shared entry, so one client's
  expanded template value — a cookie, a certificate field, an address —
  could appear in another client's response (CWE-488).
- Cluster: everything a peer's actions are recorded under is now the
  common name of its certificate, which mutual TLS authenticates,
  instead of the node id it announced in a message it wrote itself; a
  peer can no longer place bans or honeypot marks under another node's
  name. A peer cannot answer a rate-limit decision for a key it does not
  own, the amount one message may consume is bounded, a rate report is
  clamped to the policy's own rate (one message used to deny a key on
  every node for the whole stale window), a peer ban's lifetime is
  clamped to the same one-year ceiling the local paths use, peer adds
  and removals are logged, and a peer cannot remove a ban an operator
  placed by hand. New `cluster.tls.bind_node_id` requires an announced
  id to be a name the certificate carries; it is off by default because
  existing certificate names and node ids may differ.
- Observability: a banned client looping connections wrote one
  synchronous security record per connection on the accept loop, and a
  blocked DNS query wrote one per datagram and fed the ban ladder with
  an address nothing had verified, so anybody could have a third party
  banned by spoofing them (CWE-779, CWE-290). Both are aggregated now,
  and an event from an unverified source is attributed to nobody. The
  metrics listener's access-list refusals are aggregated too. CEF and
  LEEF records neutralise control bytes, an attribute can no longer
  overwrite a field the renderer writes itself (a DNS query name arrives
  in one called `name`, which is the LEEF event name), the standard user
  field names the keys the authentication filters actually emit, and
  `redaction.claims` covers the OIDC subject, the basic and LDAP user
  name and the API key id rather than only JWT claims. An incoming
  `Tracestate` is bounded to what the W3C recommendation allows.
- Lifetimes: a cached response's lifetime is clamped to the one-year
  ceiling the configuration validator enforces, instead of taking an
  `Expires` header in the year 9999 at its word. A still-valid OCSP
  staple survives a responder outage rather than being dropped on the
  second consecutive fetch failure. The `bot_score` behaviour window is
  measured from its start rather than the last request, so a client that
  sends one request per window no longer accumulates forever and drift
  into a challenge or a denial.
- The `sensitive_data` filter uses the media type even when a parameter
  is malformed. Go rejects `application/json;q` while the frameworks
  behind the proxy read the body as JSON, so one stray character skipped
  the whole policy (CWE-436).
- A reload installs the ban list and the challenger before the new
  routes, closing the window in which a route the operator had just
  given `challenge: {mode: always}` was served unchallenged.
- A failed challenge counts against the client only for reasons that are
  actually the client's. The third round enumerated two proxy-side
  reasons and missed the CAPTCHA provider ones, so a provider outage
  would have banned every legitimate user who solved the widget; the
  test is an allow list now, so a reason added later is harmless.
- The fleet command strips terminal escapes and bounds the length of
  every string an agent supplies, so one compromised node can no longer
  clear the operator's screen or repaint other nodes' rows.
- New fuzz targets for the ClientHello peeker, the routing expression
  parser, the LDAP BER reader and filter parser, and the cluster
  framing reader. The ClientHello one found the host-spelling defect
  above within twelve seconds; the other four survived ninety seconds
  each. Running the existing targets found one more thing worth
  recording: the PROXY protocol target's own assertion that a header's
  two addresses share a family was wrong, because a dual-stack balancer
  reports an IPv4 client as an IPv4-mapped address beside an IPv6
  destination. The parser was correct; the assertion now checks what
  matters, which is that no mapped or zoned spelling of an address
  escapes to become a second key for access lists and bans.

Findings of a third audit round, taken from disciplines the first two did
not use (supply chain and build reproducibility, cryptographic
engineering, panic reachability, abuse of the security features
themselves, and the operator and tenant privilege boundaries), all with
regression tests:

- A malformed DNS record can no longer end the process. `ParseMessage`
  runs on the listener's own goroutine, where a panic is fatal to every
  connection the proxy holds: a 31-byte UDP datagram whose NSEC rdata is
  shorter than the name it contains sliced backwards and panicked
  (CWE-248, denial of service from one packet). RRSIG, NSEC and SOA
  records whose contents run past their own rdata are errors now, names
  that cannot be repacked are errors instead of silently truncated
  rdata, and an NSEC3 set with no records is no longer indexed. A
  ClientHello body of exactly 34 bytes read one byte past its end on the
  QUIC and layer 4 listeners. As defence in depth, the DNS, layer 4 and
  QUIC per-flow goroutines now contain a panic to that one flow, count it
  in `xproxy_panics_total` and log it with its stack: the counter is zero
  in a healthy process, and anything else is a bug to fix.
- The `sensitive_data` filter bounded a compressed body by its compressed
  size, so a 256 KiB gzip body expanded to 8 GiB in the proxy: about
  32,000 to 1, enough for one request to exhaust a node (CWE-409). The
  new per-phase `max_decompression_ratio` (default 100) stops the decode
  as soon as the expansion passes it. `docs/THREAT_MODEL.md` and
  `docs/SECURITY.md` said the proxy never decompresses response bodies,
  which stopped being true when streamed decoding arrived; both now
  describe what the code does.
- Gateway API: an HTTPRoute in any namespace attached itself to any
  Gateway it named, and a listener's `certificateRef` was fetched from
  any namespace it named. In a shared cluster that is one tenant taking
  over another's hostname, or reading another namespace's TLS private key
  through the controller's own credentials (CWE-862). Attachment now
  honours `allowedRoutes.namespaces` (`Same` by default, as the
  specification says), a cross-namespace `certificateRef` is refused
  rather than silently resolved, and the controller no longer prefetches
  secrets outside the Gateway's namespace.
- Certificate Transparency: a requirement of N signed certificate
  timestamps counted timestamps, not logs, so one compromised or
  colluding log signing N times satisfied the whole policy. Distinct logs
  are counted now, and the status carries `logs` beside `verified`.
- The keyring that signs challenge, affinity and OIDC cookies is refused
  when other accounts can read it or its group can write it, the same
  rule the proxy already applied to password and client-secret files; a
  keyring line too long for the scanner is an error instead of silently
  dropping every key after it, which would have broken cookies sealed
  under those keys with nothing in the logs.
- The admin GUI reads its users file again when it changes and checks the
  account behind a session cookie on every request. Removing a user or
  lowering their role took effect only after a restart, and a live
  session kept the role it was created with for its whole life, so a
  revoked operator kept full access (CWE-613). Sessions from the identity
  provider are unaffected: the provider owns those accounts.
- The proxy's own defences can no longer be turned against a client.
  Failing a challenge because the proxy's verification table was full, or
  because a nonce was already spent (a double-submitted form, a reloaded
  page), counted towards a ban; only faults that are actually the
  client's do now. A honeypot hit a browser made because another site
  told it to (a prefetch, a cross-site sub-resource, a planted link) no
  longer marks or bans the person behind the browser, and decoys carry
  `X-Robots-Tag: noindex, nofollow`. The No default `account_guard`
  block is keyed on the account any more. A count keyed on the account
  belongs to the person being attacked, not to the attacker, because
  anyone can type someone else's name, so a handful of failures against a
  chosen name used to block its owner. Account-keyed counts still raise
  the ladder as far as a challenge, which the real owner can pass;
  blocks key on the address, the address and account pair, and the
  device.
- Build and packaging: release builds derive their date from
  `SOURCE_DATE_EPOCH` or the commit, build with `-mod=readonly`, and
  disable the coraza operators that shell out (`inspectFile`) or pull the
  unmaintained schema and i18n chain (`validateSchema`); `make check`
  refuses a tracked binary, and a 15 MB `xproxy-fleet` executable that
  had been committed is gone. The logrotate fragment declares
  `su xproxy xproxy`, without which logrotate refuses to rotate a
  directory it does not own, and the logs stop being rotated silently.

Findings of a second audit round (data flow, protocol differentials,
authentication and cryptography, concurrency and resource bounds, and an
adversarial re-check of the first round), all with regression tests:

- DNSSEC validation: an NSEC3 NODATA answer for a DS query at an ordinary
  host name no longer counts as an insecure delegation, so an upstream
  could not turn validation off for any name in an NSEC3 zone; denial
  proofs must come from the question's own zone (a signed SOA and NSEC
  records of an unrelated zone proved any name absent), parent-side NSEC
  and NSEC3 records of a delegation cannot deny names below the cut, and
  a positive answer must hold data for the question name itself
  (CWE-345).
- WebTransport CONNECT requests now pass maintenance, virtual patches,
  policy, ACLs, geo, the challenge, shedding, rate limits and the filter
  chain like any other request; they were relayed right after route
  matching (CWE-863).
- Cache poisoning through the request path: only requests whose wire
  path equals the routing path are cached, so `//x`, `/./x`, `/a/../x`,
  percent-encoded or Unicode-folded spellings cannot fill the entry
  every visitor of `/x` reads (CWE-444). Templated `response_headers`
  are applied per request on a hit instead of being cached with the
  first visitor's values.
- `normalization.reject_dot_segments` (default true) refuses `.` and
  `..` segments, including the `..;` servlet form: routing resolved them
  while the upstream received the path as sent, so `/static/..;/admin`
  reached a Tomcat origin as `/admin` under the `/` route's policy
  (CWE-436). Static directory redirects use the cleaned path, so
  `//evil.example` no longer yields a protocol-relative `Location`.
- The challenge nonce binds the host the page was served on, so a
  CAPTCHA token harvested on another site cannot be redeemed by posting
  the verify form with a chosen `Host` (CWE-807).
- The OIDC session cookie is bound to the filter's issuer and client id:
  two `oidc` filters sharing a `cookie_secret_file` could open each
  other's sessions, bypassing the stricter one's `require_claims`
  (CWE-287; existing sessions log in again after the upgrade). ID tokens
  carrying several audiences must name this client in `azp`. Genuine
  front-channel logouts (for session ids this node issued) are recorded
  even when unauthenticated revocations have filled their own, separate
  table; a flood of made-up ids can neither evict nor block a real logout
  and is counted rather than logged per call. Provider discovery runs
  detached from the requesting client's context, so a client cannot
  cancel the shared attempt for everyone.
- `basic_auth` caches a miss for an unknown name like a wrong password,
  so repeating a pair no longer reveals whether the name exists; the
  admin GUI verifies unknown names under the same semaphore. Password
  checks behind the `basic_auth`, `ldap_auth` and forward proxy
  semaphores give up when the client leaves or the queue is deep, so a
  stream of distinct wrong passwords cannot pin every request slot
  (CWE-400).
- Token introspection is bounded to 32 calls in flight per provider;
  the JWT provider warns at load when `audiences` is empty (RFC 8725).
- Header operations whose templates carry `${cert:…}` fields remove a
  client-supplied copy first, whatever `when` decides and whether the
  operation is `set` or `add`; a request without a certificate could
  otherwise present its own identity value (CWE-290).
- `upload_guard` refuses a multipart `Content-Type` Go cannot parse (a
  duplicate `boundary`, a stray parameter) instead of skipping every
  check (CWE-636); `graphql` matches media types case-insensitively and
  bounds `application/graphql-response+json` bodies (CWE-178); `openapi`
  matches the cleaned path.
- WAF `request_body_limit_action: partial` passes the body beyond the
  inspected prefix to the upstream instead of cutting it off, and ICAP
  `body_limit_action: bypass` forwards the whole body rather than the
  stream from the limit onwards.
- Resource bounds: the TLS fingerprint table no longer grows by one entry
  per handshake for the life of the process (CWE-401); network bans are
  capped at 4096 and looked up by prefix length instead of scanned per
  request; the QUIC relay bounds flows without a complete ClientHello
  apart from the connection limit and caps their buffered bytes; the wasm
  `instances` setting bounds concurrent calls rather than only the pool.
- A reload that adds a `challenge` section whose secret cannot be read
  fails as a whole instead of serving routes in mode `always`
  unchallenged (CWE-636).
- Client addresses from `X-Forwarded-For` drop an IPv6 zone, which made
  them miss every CIDR and key their own ban and rate-limit buckets; the
  Host normaliser allows only `:port` after a bracketed literal.
- Error page escaping covers every browser-rendered type (XHTML, SVG,
  XML) and JSON-escapes values in JSON pages; `redirect.to` must fix the
  destination host in the configuration; `trusted_proxies` refuses
  prefixes shorter than `/8`; CORS wildcards need two labels after `*.`
  and are refused under common public suffixes; the wildcard matcher
  stops at `?#@\:`; the gRPC-web preflight answers a fixed header list.
- `ldap_auth` requires `start_tls` or `ldaps://` unless
  `allow_plaintext`; mirror copies drop hop-by-hop headers; a cluster
  node accepts an exact rate-limit answer only from the peer it asked;
  the admin GUI's OIDC role claim matches a string value whole; the TUI
  strips non-printable runes from log lines; an overflowing
  `grpc-timeout` counts as absent.

Findings of the first source code security audit, all with regression
tests:

- Custom HTML error pages HTML-escape request-derived template values
  (`${path}`, `${query:…}`, `${header:…}`, `${cookie:…}`), closing a
  reflected cross-site scripting hole in `text/html` pages (CWE-79).
- With `normalization.unicode` a path whose folded form gains `.`, `/`,
  `\`, `%`, `;`, `?` or `#` (for example U+2025 folding to `..`) is
  refused with `normalization:unicode_fold` instead of being routed by
  the folded path and forwarded raw (CWE-176).
- The challenge return path refuses control bytes; a tab could turn
  `/\t/host` into `//host` in a browser (open redirect, CWE-601).
- The OIDC revocation index no longer lets unauthenticated front-channel
  or peer revocations evict live entries when full, so a flood of made-up
  session ids cannot undo real logouts (CWE-770). OIDC discovery
  endpoints must be `https` unless `allow_http`; forwarded claim headers
  are sanitised like the jwt filter's.
- Cache keys include the raw `Host` (port and case), so a request with
  `Host: example.com:1337` cannot fill the entry served to
  `example.com` (cache poisoning, CWE-444).
- `X-Xproxy-Mirror` is stripped from client requests: only the proxy's
  shadow copies carry it.
- `header_guard` judges every instance of a header, not only the first.
- `basic_auth` and the forward proxy spend the same hash cost on an
  unknown user as on a wrong password (no user enumeration by timing,
  CWE-208).
- The Host normaliser refuses residual `:` or bracket syntax outside a
  bracketed IPv6 literal, so `host:443:x` cannot dodge the exact-host
  route table.
- Forward proxy private ranges now include 0/8, 192.0.0.0/24,
  198.18.0.0/15, 240/4, NAT64, 6to4 and Teredo.
- gRPC-web text mode bounds one buffered frame at 4 MiB.
- DNS listener: the honoured EDNS UDP size is capped at 1232 (RFC 9715)
  to limit amplification.
- `trusted_proxies` refuses `0.0.0.0/0` and `::/0`.
- CORS `allow_origins` wildcards must be whole leading labels
  (`https://*.example.com`); the runtime never reflects an arbitrary
  origin with credentials.
- `ldap_auth` refuses a world-readable `bind_password_file`; the LDAP
  decoder bounds nesting depth (a hostile server could otherwise exhaust
  the stack); a search aborted on its size limit closes the connection.
- `xproxyctl origin-check` builds the probe URL structurally, so a path
  cannot retarget the probe via `@` or `?`.
- Shadow-diff logging redacts values of cookie, authorization and token
  headers.
- The secret keyring writes through an exclusive temp file; fleet bundle
  files may not be group- or world-writable; rollback runs the same
  sandbox check as reload; `DELETE /v1/dns` and `DELETE /v1/honeypot`
  are audited; the maintenance bypass header compares in constant time.

### Added (1.3)
- Configuration includes: `includes` globs of fragment files whose
  `upstreams`, `routes`, `rate_limits` and `filters` are appended in
  lexical order; fragments may contain nothing else and names must be
  unique across the set.
- HTTP/2 CONNECT on TLS forward listeners that list `h2`: the stream
  carries the tunnel.
- WebAssembly ABI body access: `get` kinds 13 to 15 and `set_body`
  behind a per filter `body_limit`; bodies over the limit stream
  through unexposed.
- QUIC passthrough: `kind: tcp` listeners with `quic: true` relay QUIC
  flows by the server name read from the version 1 Initial packet,
  with `quic_idle_timeout`, `quic_*` counters and `xproxy_quic_*`
  metrics.
- Kubernetes Gateway API: Gateways and HTTPRoutes of the ingress class
  translate next to Ingress resources (hostnames, prefix and exact
  paths, methods, header modifiers, URL rewrite, redirects, weighted
  backends, listener certificates); watch streams on every collection
  trigger a debounced sync so changes propagate within a second, with
  the resync poll as fallback; `watch` and `debounce` settings,
  `gateway_api`, `watching` and `watch_events` in the status.
- DNS over TLS and HTTPS: dns listener `upstreams` accept
  `tls://host:port` and `https://host/path` with `upstream_ca_file`;
  a `doh` route action answers RFC 8484 for clients through a dns
  listener's policy and cache.
- OpenTelemetry exporter: `metrics.otlp` pushes every metric family as
  OTLP/HTTP with JSON encoding on an interval, with headers, pinned CA,
  resource attributes and gzip; `GET /v1/otlp`, `xproxyctl otlp`.
- OIDC front channel logout: sessions carry the provider's `sid`,
  `frontchannel_logout_path` revokes it into a bounded index, a logout
  at the proxy revokes it too; `logouts` and `revoked` in the status.
- Inbound PROXY protocol: `proxy_protocol: true` on `http` listeners
  reads a v1 or v2 header from peers in `trusted_proxies` and makes the
  carried address the client for limits, bans, ACLs, logs and
  forwarding headers; trusted peers without a header are dropped,
  other peers are served unchanged. The key was reserved since 0.x.
- Cluster events (protocol version 2): honeypot marks and unmarks and
  OIDC session revocations are shared between nodes; `share_events`
  switches the channel; `events_sent`, `events_received` and
  `ignored_messages` in `xproxyctl cluster`; unknown message types are
  skipped instead of closing the connection.
- `filter.Env.Events`: an event bus for compiled-in filters to share
  facts with cluster peers (middleware API version 1, additive).
- `bot_score` signal `honeypot_marked` (weight 40) for clients marked
  by a honeypot here or on a peer.
- Static file serving: `routes[].static` serves a directory through
  `os.Root` with index files, optional listings, a single page
  application fallback, `Cache-Control`, dot file refusal, a size
  bound, weak `ETag`s, ranges and conditional requests;
  `static_served`, `static_not_found`, `xproxy_static_responses_total`.
- Response compression: a `compression` section gzips eligible
  responses of every kind the proxy writes (proxied, cached, static,
  respond) with a level, a size floor, a media type list and a per
  route `compress` override; `Vary`, weak `ETag`s, pre-encoded bodies,
  ranges and `no-transform` handled; `encoding` in the access log,
  `compressed` and `compressed_raw_bytes` counters and metrics.
- Routing by regular expression (`routes[].path_regex`, anchored RE2
  on the whole path, ranked by literal prefix) and by request header
  and cookie conditions (`routes[].headers`, `routes[].cookies` with
  `exact`, `prefix`, `regex` and `present`); conditioned routes rank
  before plain routes on the same path. Gateway API `RegularExpression`
  paths and header matches now translate instead of warning.
- `upstreams[].retry_on`: response statuses (`5xx`, `500`, `502`,
  `503`, `504`, `429`) retried on another endpoint within the
  `retries` budget for replayable requests, counted as passive
  failures; `upstream_retries` and `upstream_status_retries` counters
  and `xproxy_upstream_retries_total` by reason.
- Access log text formats: `logging.access.format` `common` (Common
  Log Format), `combined` and `custom` with a `template` of `{field}`
  placeholders over every access log attribute plus derived `time_clf`,
  `request`, `user` and `bytes_out_clf`; Apache style escaping; the
  same line to every sink.
- `body_rewrite` filter kind: literal and regular expression rules over
  request and response bodies with media type lists and size bounds,
  `Content-Length` and validators maintained, `body_rewrite` in the
  access log.
- Traffic management: `upstreams[].circuit_breaker` (pool wide breaker
  with half open trials and growing back-off, distinct from outlier
  ejection), `upstreams[].max_concurrent` with `queue` (bounded
  waiters with a deadline); `GET /v1/pools`, pool rows in `xproxyctl
  upstreams`, `upstream_circuit_open`, `upstream_queue_full`,
  `upstream_queue_timeouts` and per pool gauges.
- Canary endpoints: `endpoints[].canary` with `upstreams[].canary`
  (header, cookie, values, percent, fallback) sends selected requests
  to the canary endpoints of a pool and keeps the rest away; `canary`
  in the access log, endpoint stats and `GET /v1/pools`.
- Quota reporting: `routes[].tenant` label, `GET /v1/quotas` and
  `xproxyctl quotas` with usage per tenant, per route (status classes,
  denied, rate limited, bytes) and per rate limit policy (decisions,
  top consumers with tokens left), request share per upstream; metrics
  `xproxy_route_bytes_total`, `xproxy_route_rate_limited_total`,
  `xproxy_rate_limit_decisions_total`, `xproxy_rate_limit_keys` and a
  `tenant` label on per route counters.
- Configuration operations: `xproxyctl reload -dry-run` reports per
  item changes, the restart list and a unified diff without applying;
  `xproxyctl diff` compares the running configuration, the file and
  history entries; `management.history_dir` records every applied
  generation for `xproxyctl history` and `xproxyctl rollback ID`;
  endpoints `POST /v1/reload?dry_run=1`, `GET /v1/diff`, `GET
  /v1/history`, `POST /v1/rollback`. `xproxyctl config` and the history
  use one self-contained dump (`config.Dump`).
- Key rotation: secret files for affinity, the challenge, OIDC cookies
  and log pseudonyms accept a keyring (`internal/secret`), the first
  key signs and seals and every key verifies; `xproxyctl rotate-secret
  FILE` adds a fresh primary key and keeps a bounded number of old
  ones; the challenge re-reads its ring on reload.
- OCSP stapling: `tls.ocsp_stapling` fetches responses in the
  background for file and ACME certificates and staples them without
  blocking handshakes; `GET /v1/tls` and `xproxyctl tls` show the state.
- Certificate Transparency checks: `tls.ct` parses embedded SCTs at
  load, verifies their signatures against a log list file and reports,
  logs or (with `enforce`) refuses certificates below `require`.
- Distributed tracing: `tracing` gives every request a W3C trace
  context, propagates it to the upstream, records a server span and an
  upstream client span and exports them as OTLP/HTTP JSON with local
  sampling (`sample_percent`, `trust_incoming`); `trace_id`, `span_id`
  and `trace_sampled` in the access log.
- OTLP logs: `logging.otlp` and the `otlp` sink ship log records with
  typed attributes and trace ids to a collector; `GET /v1/telemetry`
  and `xproxyctl telemetry` show metrics, traces and logs exporters
  together. The OTLP/HTTP client is shared (`internal/otlp`).
- Encrypted dns listeners: `tls` on `kind: dns` serves DNS over TLS
  and DNS over HTTPS (`doh_path`) on one port by ALPN, with per
  transport counters `queries_udp`, `queries_tcp`, `queries_dot` and
  `queries_doh`.
- DNSSEC validation on dns listeners (`dns.dnssec`): RRSIG
  verification for RSA, ECDSA P-256/P-384 and Ed25519, DS and DNSKEY
  chains from the built-in root anchors or configured ones, NSEC and
  NSEC3 denial proofs with wildcard and opt-out handling, a bounded
  key cache, AD for secure answers, SERVFAIL and `dns_bogus` for bogus
  ones, CD passthrough, DNSSEC records stripped for clients without DO.
- WAF operations: per rule statistics (matches, blocks, detects, last
  seen, severity, tags) and profile status with rule set source and
  CRS version; `waf.learning` aggregates matched variables per rule
  and route and proposes path scoped SecLang exclusions once
  `min_hits` is reached; `crs.dir` loads the Core Rule Set from a
  directory so rules update with a reload instead of a rebuild;
  `GET /v1/waf`, `GET /v1/waf/exclusions`, `POST /v1/waf/reset`,
  `xproxyctl waf [rules|proposals|exclusions|reset]`.
- In-process sandbox (`sandbox` section, on by default): Landlock file
  system rules derived from the configuration with TCP bind refusal on
  ABI 4, a seccomp deny list on every thread, capability clearing,
  `no_new_privs`, non dumpable with no core files; strict mode; a
  reload naming a path outside the rules is refused; `GET /v1/sandbox`,
  `xproxyctl sandbox`, a `sandbox` summary in `status`.
- systemd unit: `Type=notify-reload` with `ReloadSignal=SIGHUP` (no
  helper binary in the sandbox), `NoExecPaths=/` with the binary as the
  only `ExecPaths=`, `KeyringMode=private`, `PrivateMounts=yes`,
  `RestrictFileSystems=`, `@clock @keyring @pkey` filtered; an optional
  `SocketBindDeny` drop-in.
- macOS as a target platform: `make build-darwin`, `dist-darwin` and
  `install-macos`; launchd jobs under hidden system users, a Seatbelt
  profile, a pf anchor, newsyslog rotation and an installer in
  `deploy/macos`; platform defaults under `/usr/local`; management peer
  credentials through `LOCAL_PEERCRED`; debugger denial and core limit
  in process; `make check` type checks the macOS targets.
- `examples/` directory: WAF exclusions and custom rules, a DNS block
  list with a sinkhole listener, CIDR and bad bot include fragments,
  header policy, basic authentication, bot scoring, a WebAssembly
  policy module with text source and generator, path and body
  rewriting, advanced routing; every file validated by
  `go test ./test/examples/`.
- Documentation syntax test: every `yaml` block in the documentation is
  checked against the configuration schema on each `make check`.
- TUI screens 7 to 9 (routes, WAF, TLS), pool state under upstreams,
  sandbox, telemetry and dns lines in the overview; GUI pages Routes,
  WAF (with reset and SecLang download), Subsystems, History (dry run
  and roll back), served certificates on the Certificates page and pool
  state on Upstreams, so every management endpoint is visible in the
  CLI, the TUI and the GUI.
- Tests: `xproxyctl` exercised end to end against a management server
  (every command), fuzz targets for the PROXY protocol header, access
  log templates, DNS messages, trust anchors and the configuration
  differ, benchmarks for the WAF, DNS parsing and PROXY parsing, a
  golden test of the example configuration's dump.
- `wasm` filter `engine` option (`auto`, `compiler`, `interpreter`):
  `auto` probes the compiler once and falls back to the interpreter
  where executable memory is refused (`MemoryDenyWriteExecute`, the
  macOS hardened runtime).

- Brotli and zstd response compression next to gzip: `compression.encodings`
  sets the offer and preference, `brotli_level` and `zstd_level` the
  cost; negotiation follows the client's quality values.
- Regular expression path rewrites (`routes[].rewrite_regex`) with
  numbered and named groups; templated header values, redirect
  targets and rewrite replacements with request variables (client
  address, request id, host, path, query, route, tenant, country,
  fingerprint, TLS parameters, headers, cookies, query parameters,
  captures), validated at load; custom error pages
  (`server.error_pages`, `routes[].error_pages`) by status, class or
  default with JSON negotiation and optional replacement of upstream
  error bodies.
- Endpoint discovery: `upstreams[].discovery` resolves A/AAAA or SRV
  records on an interval (custom resolver, weights from SRV, lowest
  priority group), adds and removes endpoints without a reload while
  surviving ones keep their statistics; failures keep the previous set
  and are counted. `slow_start` ramps a joining or recovering endpoint
  from 10 % to full weight.
- `server.session_tickets`: TLS session ticket keys derived from a
  shared master keyring and the time epoch, so a ticket issued by one
  node of a cluster resumes on every other node and survives restarts;
  the previous epoch's key is kept across a rotation. `xproxyctl tls
  tickets` and `GET /v1/tls/tickets` show the epoch and the peers'
  agreement; the fingerprint travels as the cluster event
  `ticket_keys`.
- Listeners are added, removed, renamed and rebuilt by a reload. A
  changed listener on the same address inherits the accept socket, so
  a systemd owned or privileged socket is never re-bound and no
  connection is refused; the old generation drains for
  `shutdown_timeout`. The dry run reports the drains (`drains`) and
  only a listener with a UDP socket changed on the same address still
  needs a restart.
- API inventory (`api_inventory`): endpoints discovered from traffic
  with counts, credentials, media types and versions; shadow, zombie
  and superseded views against `openapi` filters; `xproxyctl api`,
  `GET /v1/api`, an optional state file.
- Learning bot scoring (`bot_score` `learn: true`): the filter records the
  per-route distribution of the scores it computes without acting on it, and
  `xproxyctl botscore` reports each route's score percentiles, the share of
  traffic the current thresholds would challenge or deny, and suggested
  `challenge_at`/`deny_at` derived from the tail — so thresholds are tuned to
  real traffic rather than guessed. Served at `GET /v1/botscore`.
- Challenge cookie token binding (`challenge.bind_ja4`): the signed
  challenge/CAPTCHA cookie can be bound to the client's JA4 TLS fingerprint,
  so a stolen cookie replayed by a different TLS client is refused even from
  the same address. Off by default; complements `bind_ip`.
- Origin-lock verification command (`xproxyctl origin-check [upstream]`):
  probes the configured origins directly, sending an unsigned and a signed
  request to each endpoint of every upstream with an `origin_signature`, and
  reports whether the origin refuses unsigned traffic (`enforced`) or serves
  it (`not_enforced`). Exits non-zero when any origin is not enforced, so it
  fits a deployment check. Served at `GET /v1/origin-check`.
- Traffic shadowing with response diffing (`routes[].mirror.diff`): compare
  the shadow upstream's response with the live one — status, chosen headers
  and a body digest — to validate a new backend under real traffic. The
  live response is summarised as it streams (no buffering, no client
  impact); outcomes are counted in `xproxy_mirror_diff_total{result}` and
  sampled differences are logged.
- LDAP and Active Directory authentication (`ldap_auth` filter): HTTP Basic
  credentials are verified against an LDAP server, by a direct bind
  (`bind_dn_template`) or a service-account search then bind (`bind_dn`,
  `base_dn`, `user_filter`), with an optional group requirement
  (`require_group`). Usernames are escaped (RFC 4514/4515) against
  injection; `ldaps://`, `start_tls` and `ca_file` secure the transport;
  verified credentials are cached by digest. The user becomes the `ldap`
  identity for identity-keyed rate limits. Built on an in-house minimal
  LDAP client (`internal/ldap`), no new dependency.
- HTTP registry service discovery (`upstreams[].discovery.type: http`):
  poll a registry URL on the interval and feed its endpoints into the pool.
  `format: list` reads a JSON array of `{address｜host,port, weight?,
  canary?}`; `format: consul` reads the Consul `/v1/health/service`
  response (passing instances only, `Weights.Passing` as the weight);
  `headers` carries an auth token. Joins DNS (`dns`) and SRV (`srv`)
  discovery; a failed poll keeps the previous endpoint set.
- Retry budgets (`upstreams[].retry_budget`): cap the retries in flight to
  a pool at `percent` of the requests in flight, with a `min_concurrency`
  floor, so retries cannot amplify an outage; without it every retry the
  `retries` budget allows is still sent.
- Request hedging (`upstreams[].hedge`): after `delay` with no answer, send
  up to `max` extra copies of a replayable request to other endpoints and
  keep the first usable response, cancelling the rest; each hedged copy is
  gated by the retry budget and counts as an upstream retry.
- Access-log sampling and field selection (`logging.access.sample_percent`,
  `always_log`, `fields`): log a fraction of lines while always keeping
  denied and error responses, and trim each line to a chosen set of
  attributes; metrics still count every request.
- Maintenance mode (`maintenance` section): holds every request behind a
  configurable 503 with Retry-After except an allowlist (CIDRs or a
  bypass header) and routes marked `maintenance: false`; toggled at
  runtime with `POST /v1/maintenance` and `xproxyctl maintenance
  on|off`, surviving reloads, and counted as `denied_maintenance`.
- Per-route timeouts (`routes[].timeouts`): a named `total` (the whole
  exchange) and an `idle` timeout that cancels a response stalled with
  no bytes, for streaming and long-poll routes; connect and
  response-header timeouts remain per upstream.
- CAPTCHA hostname binding: the challenge verifies the hostname the
  provider reports the token was solved on against the request host or a
  configured `challenge.captcha.hostnames` allowlist, refusing a token
  solved for another site; `hostname_check` turns it off. A missing
  hostname fails closed.
- Per-route CORS (`routes[].cors`): allowed origins (exact, wildcard
  host, or `*`), methods, headers, exposed headers, credentials and
  max-age; preflight `OPTIONS` answered before authentication and the
  route's policy overriding any the upstream set. Separate from the
  gRPC-web preflight handling.
- Identity-keyed rate limits: `rate_limits[].key` of `identity` or
  `identity:<kind>` (`jwt`, `oidc`, `api_key`, `basic`) keys the bucket
  on the principal an auth filter verified, evaluated after the filter
  chain; filters publish the verified identity through the request
  context (`filter.SetIdentity`).
- Adversarial bypass harness (`test/bypass`): tests that try to evade
  every security control (WAF, normalisation, positive policy, virtual
  patches, rate limits, aggregate and honeypot bans, upload guard,
  sensitive data, account guard, ACLs, header guard, API keys, the
  challenge and the OpenAPI model) and assert each holds before the
  backend, with documented gaps asserted as such.
- `sensitive_data` filter: compressed bodies (`gzip`, `deflate`, `br`,
  `zstd`) are decoded for scanning and bodies over `max_bytes` are
  streamed through the scanner (`encoded`, `oversize`,
  `max_decoded_bytes`); masked or streamed compressed bodies are
  forwarded decoded and a streamed block cuts the transfer.
- API inventory export: `xproxyctl api VIEW -openapi` and
  `GET /v1/api?format=openapi` render a view as an OpenAPI 3.0
  skeleton with named path parameters, methods, media types, status
  classes, security schemes, servers and `x-xproxy` traffic evidence.
- `openapi` filter: `spec_url` fetches the description over HTTPS and
  refreshes it in the background with ETags and a `cache_file` for
  outages; `spec_file` is re-read when it changes without a reload;
  `refresh`, `timeout` and `ca_file` options; a description that fails
  to load keeps the previous one.
- Device identifiers and automation markers in the filters: the
  challenge script reports WebDriver and headless markers, carried in
  the cookie as `Info.Automation` and the `automation` log attribute;
  `account_guard` counts per device (`device`, `device_accounts`
  thresholds, device blocks shared with peers, `account_device` in the
  log) and acts on markers (`automation`); `bot_score` gains
  `automation_markers` and `device_shared` signals with
  `device_addresses`.
- Counters and views for the newest filters: `denied_sensitive_data`
  and `denied_account_abuse` in the status, `xproxy_sensitive_findings_total`,
  `xproxy_sensitive_messages_total`, `xproxy_account_actions_total`,
  `xproxy_account_events_total`, `xproxy_account_blocks_total`,
  `xproxy_account_campaigns_total`, `xproxy_account_disposable_total`
  and `xproxy_account_blocks_active` metrics, `xproxyctl accounts` and
  `GET /v1/accounts` with tracked keys, active blocks and campaigns per
  endpoint; the security dashboard and the alert rules cover account
  abuse, sensitive data and CAPTCHA results.
- Aggregated bans: `bans.triggers[].aggregate` counts and bans per
  client network (`net`, with `net_v4` and `net_v6`) or per TLS client
  fingerprint (`ja4`), with `min_sources` distinct addresses required
  first; fingerprint bans as `ja4:<fp>` targets in triggers, manual
  bans, persistence and cluster propagation, applied at the request
  stage and sparing exempt addresses; networks overlapping exempt
  ranges are never banned.
- Challenge tiers: `challenge.captcha` adds Cloudflare Turnstile,
  hCaptcha or reCAPTCHA as a second tier (escalation from
  `account_guard` `captcha` steps, campaigns and disposable actions, or
  `mode: always`), verified with the provider from the proxy; the
  cookie records its tier and a device identifier the challenge script
  derives (`challenge.device`), exposed as `device` in the access log,
  `Info.DeviceID` and the `device` rate limit key; `Verdict.Captcha`,
  `Info.CaptchaVerified`, `captchas_passed` and the `captcha_passed`
  challenge metric result.
- `account_guard` filter kind: login, registration, reset, cart and
  scrape endpoint classes with default ladders of delay, challenge and
  block per address, account, pair, accounts per address and addresses
  per account, failure recognition from status, body or redirect,
  campaign detection over many addresses, disposable registration
  domains, cluster-shared blocks, the `account_abuse` deny reason and
  ban category, and `account_*` access log attributes.
- `sensitive_data` filter kind: validated detectors for payment cards,
  Swedish personal identity numbers, IBANs, US social security numbers,
  e-mail addresses, JWTs, private keys, API keys and query string
  credentials, plus custom patterns, scanning query, headers and bodies
  in both directions with log, mask or block per direction and
  `sensitive_types`, `sensitive_count` and `sensitive_where` in the log.
- Origin lock: `upstreams[].origin_signature` signs every forwarded
  request with a keyring shared with the origin (`internal/originsig`
  verifies), and HARDENING.md 5c documents network rules, mutual TLS
  and signature verification so an origin accepts only proxied traffic.
- WAF gradual enforcement: `routes[].waf.block_percent` splits clients
  between block and detect mode by address, `block_cidrs` always
  enforces the canaries, `waf_enforced` in the access log and the share
  in `xproxyctl waf`.
- `upload_guard` filter kind: file count and sizes, allowed and denied
  extensions with double extension rules, file name checks, content
  sniffing against the extension and the declared type, executable and
  server side script detection, raw upload support.
- Request normalisation (`server.normalization`): control characters
  and invalid UTF-8 in the target refused by default, double encoding,
  encoded slashes and backslashes refusable, ambiguous HTTP/1 framing
  closed and counted, NFC or NFKC folding of the routing path.
- Rate limit keys `client_net` (with `net_v4` and `net_v6`), `endpoint`
  (method, route and path template), `ja4`, `cookie:<name>` and
  `jwt:<claim>`, each falling back to the client address.
- Positive security model per route (`routes[].policy`: methods,
  media types, query parameter types and bounds, URI, query and header
  limits) and structured virtual patches (`virtual_patches`: host,
  route, path, method, parameter, header, cookie and body conditions,
  block or log, expiry, per patch counters, `xproxyctl patches`,
  `GET /v1/patches`, `xproxy_virtual_patch_hits_total`).
- Fleet operation: `xproxy-fleet`, a controller that serves each node
  its configuration bundle over mutual TLS and collects the nodes'
  status, and the `fleet` agent section in the proxy that long polls,
  applies bundles through the reload path with rollback on refusal and
  reports; `xproxy-fleet nodes|node|bundle|scan|validate`, `xproxyctl
  fleet`, `GET /v1/fleet`, an RPM subpackage and a unit.
- Grafana dashboards (overview, security) and Prometheus alert rules
  shipped with the product under `deploy/grafana` and
  `deploy/prometheus`, installed to `/usr/share/xproxy`, checked by a
  test against the exported metric families.
- SIEM export: a `siem` log sink that posts batches over HTTPS as
  newline delimited JSON, the Splunk HTTP Event Collector envelope, CEF
  or LEEF (`logging.siem`, credential from `auth_file`), and CEF or LEEF
  as syslog message formats (`logging.syslog.format`); counters in
  status, metrics and `xproxyctl telemetry`.
- WAF: Core Rule Set plugins from a directory (`crs.plugins_dir`,
  `crs.plugins`), JSON body schemas enforced per profile and path
  before the rules (`json_schemas`, with block and detect modes and a
  problem body), and behavioural anomaly detection that scores clients
  against the population per window and logs, challenges or blocks
  the outliers (`waf.anomaly`, `xproxyctl waf anomalies`, the
  `waf_anomaly` reason). The JSON Schema evaluator moved to
  `internal/jsonschema`, shared with the `openapi` filter.
- API security filters: `api_key` (keys issued, scoped, rotated with
  grace and revoked by `xproxyctl apikey`, stored hashed, forwarded as
  an id and scopes), `openapi` (requests validated against an OpenAPI 3
  description: paths, methods, parameters, media types and JSON bodies
  with a built-in schema evaluator) and `graphql` (depth, complexity,
  aliases, batch, size and introspection bounds).
- HTTP/3 to upstreams (`upstreams[].h3`, with a TCP fallback on QUIC
  failures), gRPC-web translation for browser clients
  (`routes[].grpc.web`, `web_origins` for CORS) and WebTransport relays
  (`h3.webtransport` on a listener, `routes[].webtransport`) that carry
  streams and datagrams to an HTTP/3 upstream.
- Identity: OAuth 2.0 token introspection on JWT providers
  (`jwt.providers[].introspection`) for opaque tokens or revocation
  checks, with a bounded cache; client certificate fields as template
  variables and an expression function (`${cert:cn}`, `${cert:xfcc}`,
  `cert("fingerprint")`) to forward or route on a verified client
  identity; single sign-on for the web GUI through an OpenID Connect
  provider (`xproxy-admin serve -oidc-*`) with roles from a claim.
- Rate limits beyond token buckets: `algorithm: sliding_window` with
  `limit` per `window` (weighted two-window estimate), and
  `distributed: exact` under which one cluster member owns each key
  (rendezvous hashing over the connected members) and decides for the
  others within `cluster.exact_timeout`, falling back to a local
  decision when it does not answer. The cluster now acknowledges hellos
  so members know each other's ids; `xproxyctl cluster` lists members
  and exact decision counters, `xproxyctl quotas` the algorithm and
  mode per policy.
- Latency based outlier ejection (`outlier_ejection.latency_threshold`,
  `latency_factor`, `latency_min_samples`): an endpoint whose smoothed
  time to first byte is slow in absolute terms or relative to its pool
  is ejected like one that fails; `xproxyctl upstreams` shows the
  smoothed latency and the ejections. Health checks can require a
  response body (`health_check.body_contains`, `body_regex`). Every
  route has a request duration histogram
  (`xproxy_route_request_duration_seconds`) and the quota report and
  `xproxyctl quotas` show p50, p95 and p99 per route.
- Expression language: `routes[].when` and `request_headers.when` /
  `response_headers.when` hold a condition (`and`, `or`, `not`,
  comparisons, `in` lists, `cidr()` address sets, `matches` patterns,
  string functions, `header()`, `cookie()`, `query()`, `capture()` and
  the request variables plus `date`, `hour`, `minute`, `weekday`),
  parsed and checked at load and evaluated per request; a route with
  `when` ranks like a route with one header condition.
- Operator tooling: `xproxyctl completion bash|zsh|fish` prints
  completion scripts for `xproxyctl` and `xproxy` (installed by `make
  install` and the RPM), `xproxyctl help` lists the commands, the manual
  pages `xproxy(8)`, `xproxyctl(8)` and `xproxy.yaml(5)` are generated
  from the documentation and installed, and a JSON schema of the
  configuration generated from the Go types (`xproxyctl schema`,
  `/usr/share/xproxy/xproxy.schema.json`) gives editors completion and
  inline documentation.

### Changed (1.3)
- No bounded table is silent any more. Every cap that evicts, refuses
  or drops (rate limit key shards, ban trigger windows, honeypot marks,
  challenge nonces, bot score client histories, admin sessions, WAF
  rule statistics and learning entries, dns worker slots, trace, log
  and cluster queues) counts each occurrence and writes a warning at
  most once a minute with the count since the previous one
  (`internal/bound`); the counts appear in the status views (`overflow`
  per rate limit policy, `marks_dropped`, `rules_dropped`, `dropped`,
  `missing_paths` for the sandbox). Configured limits that cannot be
  honoured remain hard errors at load. The error log is the process
  default logger.

### Fixed (1.3)
- WAF statistics took one mutex per request; the per rule counters are
  atomics in a concurrent map and the learning table is sharded, so
  concurrent requests no longer serialise on the statistics.
- WAF learning proposals without a route path used
  `SecRuleUpdateTargetById`, which does not compile in a directive file
  loaded before the CRS rules; they are now an unconditional `SecAction`
  with the same `ctl:ruleRemoveTargetById`, and the test compiles both
  forms into an engine.
- Ingress merge on a configuration with `includes` expanded the
  fragments a second time, failing the merge on duplicate names.
- Reloading a dns listener's policy leaked the previous resolver's
  idle DNS over TLS connections; the old resolver is now closed, and
  shutdown closes the last one.
- Ingress watch streams had no response header timeout, so an API
  server that accepted the connection and never answered held the
  watcher forever.
- `xproxyctl config` output on a configuration with `includes` was not
  loadable as a main file without expanding the fragments twice; it now
  prints one self-contained document with the fragment paths in a
  comment.

### Added (1.2)
- GeoIP policy: `geoip` section with a built-in MaxMind DB reader (no
  external library) or a CSV prefix table; `routes[].geo` allow and deny
  lists with an `unknown` choice; rate limits keyed on `country`;
  `country` in the access log and in `filter.Info`; `denied_geo`,
  `xproxy_geoip_*` metrics; `GET /v1/geoip`, `xproxyctl geoip`.
- Bot classification: JA3 and JA4 fingerprints computed from every
  ClientHello (`tlsconf.Compute`), logged as `ja4` and passed to filters;
  the `bot_score` filter kind scores user agent, browser headers,
  fingerprint mismatch and behaviour (error rate, path spread, timing
  regularity, rate) with configurable weights, JA4 allow and deny lists,
  and log, challenge or deny thresholds; the score can be forwarded in a
  header. Middleware API additions: `Info.Country`, `Info.JA3`,
  `Info.JA4`, `Info.ALPN`, `Info.ChallengeVerified`, `Verdict.Challenge`.
- Response caching: `cache` section (byte bound, object bound) and
  `routes[].cache` (ttl, methods, statuses, query and header key policy,
  cookies, ignore_cache_control); `Cache-Control`, `Expires` and `Vary`
  honoured; conditional requests answered with 304; `X-Cache` and `Age`
  headers, `cache` in the access log; `GET /v1/cache`, `DELETE
  /v1/cache`, `xproxyctl cache` and `cache purge`; `xproxy_cache_*`
  metrics. The cache survives reloads.
- Layer 4 passthrough: `kind: tcp` listeners route TLS connections by
  server name (peeked, not terminated) to upstream pools, with a default
  for non-TLS and unmatched connections, PROXY protocol v2 to the
  upstream, idle timeout, per listener connection bound, pool accounting
  and retries across endpoints, a `tcp` access log line per connection
  and `xproxy_tcp_*` metrics.
- Forward proxy: `kind: forward` listeners accept `CONNECT` tunnels and
  absolute `http://` requests from clients, with a destination policy
  (ports, allow and deny by name, address or CIDR, private ranges
  refused by default, the checked address dialled), optional
  `Proxy-Authorization` Basic credentials from a users file re-read on
  reload, tunnel bound, idle timeout, response size bound, `Via`, a
  `forward` access log line per request, `forward_*` security events
  and ban reasons, `xproxy_forward_*` metrics.
- Ban triggers accept the reasons `geo`, `tcp_no_route`,
  `forward_denied` and `forward_auth`.
- Honeypot routes: `routes[].honeypot` serves a built-in decoy
  (`wp-login`, `env`, `git-config`, `phpinfo`, `admin-login`, `robots`),
  an inline body or a file, with a tarpit delay; hits are `honeypot`
  security events and a ban reason, the client is marked for `mark` and
  its later requests carry `honeypot_marked` in the access log and
  `Info.HoneypotMarked` in filters; `GET/DELETE /v1/honeypot`,
  `xproxyctl honeypot`, `xproxy_honeypot_*` metrics.
- Request mirroring: `routes[].mirror` copies sampled requests to a
  second upstream in the background with `X-Xproxy-Mirror: 1`, bounded
  in body size, time and copies in flight; the client never sees the
  mirror's response; `mirror` in the access log, `mirror_*` counters
  and `xproxy_mirror_total{outcome}`.
- gRPC: `routes[].grpc` matches gRPC requests by service or method with
  precedence over plain routes on the same path; proxy errors on gRPC
  requests are trailers-only responses with a mapped `grpc-status`;
  `grpc-timeout` tightens the route deadline; `listeners[].h2c` accepts
  HTTP/2 without TLS and `upstreams[].h2c` speaks it to backends;
  `health_check.type: grpc` probes the standard health service;
  `grpc_status` in the access log and `xproxy_grpc_responses_total`.
- OpenID Connect login: the `oidc` filter kind runs the authorization
  code flow with PKCE and a nonce against a discovered provider,
  verifies the ID token with the JWT verifier, keeps an AES-GCM sealed
  session cookie, forwards claims as headers, strips the cookie
  upstream, checks `require_claims`, logs out through the provider.
  `Verdict.Silent` lets a filter answer flow redirects without
  security bookkeeping.
- DNS proxy: `kind: dns` listeners answer over UDP and TCP from a
  bounded cache, apply a block list (inline and file, NXDOMAIN, REFUSED
  or sinkhole), a client allow list and per client rate limits, and
  forward to upstream resolvers with a fresh id and source port per
  query; `dns_blocked` security events and ban reason; `GET/DELETE
  /v1/dns`, `xproxyctl dns`, `xproxy_dns_*` metrics.
- WebAssembly extension ABI version 1: the `wasm` filter kind runs a
  module per request in a wazero sandbox with memory and time bounds;
  guests export `xproxy_abi_version`, `xproxy_alloc`,
  `xproxy_on_request` and optionally `xproxy_on_response` and import
  `get`, `set_header`, `remove_header`, `deny`, `log` and `log_attr`
  from module `xproxy`. New dependency `github.com/tetratelabs/wazero`.
- Kubernetes ingress controller mode: the `ingress` section reads
  Ingress, Service, EndpointSlice and TLS Secret resources of one class
  with the pod's service account and merges routes, upstreams and
  certificates into the file configuration, reloading on change;
  `xproxy.sysctl.se/*` annotations set route options; `GET
  /v1/ingress`, `xproxyctl ingress`; `deploy/kubernetes` manifests and
  Containerfile.

## 1.0.0 - 2026-09-18

First release. Highlights and known limitations are in
[RELEASE_NOTES_1.0.md](RELEASE_NOTES_1.0.md).

### Phase 3: 1.0

#### Security
- SR-1: tarpitted requests no longer hold a concurrency slot; a separate
  bound `server.limits.max_tarpits` (default 1024) applies and requests
  above it are rejected immediately (`tarpit_overflow`, `tarpit_active`).
- SR-2: a header keyed rate limit falls back to the client address once
  its key table is full, so rotating header values cannot obtain a fresh
  burst per value.
- SR-3: the GUI's configuration backup and the users and htpasswd files
  are written without following symbolic links.
- The internal review is recorded in `docs/SECURITY_REVIEW.md`.

#### Added
- Quality gates: `make cover-gate` (whole suite coverage under race,
  `test/covergate` enforcing 80 % over the core packages and 60 % per
  package, in CI), `make mutate` with gremlins on limits, router and
  netutil (`.gremlins.yaml`, CI job), chaos tests for reload storms,
  flapping endpoints, upstream death mid response, a full log disk and
  certificate rotation. Log write failures are counted
  (`log_write_errors`, `xproxy_log_write_errors_total`) and warned about
  once a minute; `xproxy_certificate_expiry_seconds{listener}` exposes
  the earliest file certificate expiry. Tests added for validation
  branches, the GUI's listeners and certificate login, log rotation and
  reopening, and the boundaries mutation testing found unobserved.
- Middleware interface at API version 1 (`docs/EXTENDING.md`): kind
  registry with load-time validation and per-generation construction,
  `filters[]` with `stage` and kind specific `options`, `routes[].filters`,
  deny counting (`denied_filter`, `xproxy_filter_denied_total`), ban
  categories by filter name, `Closer` for resources, `filtertest`
  harness; built-in kinds `header_guard` and `basic_auth`; `/v1/filters`,
  `xproxyctl filters` and `xproxyctl htpasswd`; `internal/passwd` shared
  with the GUI.
- Scale validation: `TestScale` at 1000 hosts and 10 000 endpoints
  (`make scale`), routing benchmarks at 1000 hosts (`make bench`),
  `test/load` with a backend, vegeta and k6 scripts and a soak script
  (`make load`), results in `docs/PERFORMANCE.md`. Health checks:
  `max_concurrent` per pool, a process-wide cap of 512 probes in flight,
  `keep_alive` (default off: fresh connection per probe). Superseded
  generations stop probing at the swap. `metrics.endpoint_series` to drop
  per-endpoint series; per-pool `xproxy_upstream_endpoints` and
  `xproxy_upstream_endpoints_healthy`; `go_goroutines`,
  `go_memstats_heap_alloc_bytes`, `go_memstats_sys_bytes`,
  `go_gc_cycles_total`, `process_open_fds`.
- SELinux policy: confined domains `xproxy_t` and `xproxy_admin_t`, types
  for configuration, logs, runtime, state and unit files, port types for
  upstreams, cluster, metrics and the GUI, booleans `xproxy_connect_any`
  and `xproxy_admin_manage_service`, interface file for other policies;
  compiles against Fedora and reference policy headers.
- RPM packaging: `xproxy`, `xproxy-admin` and `xproxy-selinux` built
  offline from a vendored tarball (`make dist`, `make rpm`, `make
  rpmlint`); sysusers, units, sysctl, logrotate, polkit and documentation
  installed; the policy loaded and paths relabelled on install. `VERSION`
  file for the package version. Fedora container job in CI.
- Web GUI `xproxy-admin`: separate process and service user; users file
  with PBKDF2 hashes (`user add|del|list`, `passwd`), viewer and operator
  roles, client certificate login on a mutual TLS listener, loopback only
  otherwise; screens for overview, upstreams, bans (add and remove),
  graphs from the series buffer, cluster, certificates (with renew), ICAP,
  configuration (active view, editor with validation, atomic save with
  backup and entity tag, reload) and live logs; restart through a
  configurable command with a polkit rule; strict Content Security Policy,
  CSRF checks, login lockout, audited actions. `xproxy-admin.service` and
  `50-xproxy-admin.rules` in `deploy/`.
- ACME (RFC 8555): `acme` section and `tls.acme` host groups on listeners;
  `http-01` answered on plaintext listeners ahead of the redirect and
  `tls-alpn-01` on the TLS listener; one certificate per group with
  automatic renewal, hourly back-off, verified chains and a state directory
  under `/var/lib/xproxy/acme`; `/v1/acme`, `/v1/acme/renew`,
  `xproxyctl acme` and `xproxyctl acme renew`; fake CA for tests
  (`internal/acme/acmetest`).
- ICAP client (RFC 3507): `icap.services` with `icap://` and `icaps://`
  transports, OPTIONS probing, preview, REQMOD and RESPMOD, block pages,
  modified requests with protected headers, body limits with reject or
  bypass, fail open or closed, connection pooling; `routes[].icap`;
  `/v1/icap`, `xproxyctl icap`, `denied_icap`, `xproxy_icap_*` metrics,
  `icap` ban category.

### Phase 2: Defence (complete)

#### Added
- TUI: `xproxyctl tui` with overview, upstreams, bans (ban and unban),
  cluster, graphs and security log screens, refreshed from the management
  socket; colours honour `NO_COLOR`. Built on `golang.org/x/term` instead
  of the planned bubbletea (AMR-027).
- Metrics: Prometheus text exposition at `/metrics` on the management
  socket and on an optional TCP listener with allow list and mutual TLS
  (`metrics` section); request duration and upstream time to first byte
  histograms; per-route outcome counters; sampled series buffer served at
  `/v1/series`; `xproxyctl metrics` and `xproxyctl series`.
- Log sinks: per-stream `sinks` with `file`, `journald` (native protocol,
  `MESSAGE` plus indexed `XPROXY_*` fields) and `syslog` (RFC 5424 or
  3164 over UDP, TCP, TLS with pinned CA, or Unix socket; bounded queue,
  background writer, drop counters). New `logging.journald` and
  `logging.syslog` sections; `log_syslog_sent`, `log_syslog_dropped`,
  `log_journald_dropped` and `log_redaction` in status.
- Redaction: `logging.redaction` with address truncation or keyed
  pseudonyms, user agent drop, referer origin, claim hashing and a field
  drop list, applied per stream before every sink.
- JWT validation: `jwt.providers` with RS/PS/ES/EdDSA/HS algorithms on an
  allow list, JWKS from file or HTTPS URL with a pinned CA and rotation
  handling, HMAC secret files, claim checks with bounded skew, claim
  forwarding with spoof protection, token stripping, per-route required
  or optional mode, `denied_jwt` counter, `jwt` ban category.
- Upstream mutual TLS completed: reloadable client certificate (rotated by
  `reload-certs`), `min_version`, `spki_pins`, and `xproxyctl spki` to
  print pins.
- HTTP/3 over QUIC: list `h3` in a TLS listener's protocols to serve the
  same routes on UDP at the same port, with `Alt-Svc` on TLS responses,
  shared certificates, shared connection ceilings and ban list, mandatory
  source address validation, bounded streams, no 0-RTT, and UDP socket
  activation (`xproxy-h3.socket`). New `server.listeners[].h3` block and
  `<listener>/udp` in status.
- Adaptive load shedding: a load level from the in-flight ratio and
  windowed upstream latency; routes carry a `priority_class` (low, normal,
  high, critical) and are shed with 503 and `Retry-After` by class with
  hysteresis; critical is never shed. New `shedding` section, `shed`,
  `load_level`, `upstream_latency_ms` and `shedding_classes` in status.
- Browser proof-of-work challenge: signed single-use nonces, a static page
  with a strict Content Security Policy and an embedded SHA-256 script,
  address-bound signed cookies, `always` or `load` mode per route,
  exemptions, persisted key. Reserved paths `/.xproxy/challenge` and
  `/.xproxy/challenge.js`. Failed proofs feed ban triggers under the
  `challenge` category. New `challenge` section and `routes[].challenge`.
- Cluster: mutual TLS peer connections sharing rate limit consumption and
  bans; a policy's rate becomes approximately cluster wide per key; bans
  and unbans propagate with a snapshot for new peers; bounded protocol;
  `xproxyctl cluster` and `/v1/cluster`. New `cluster` section.
- Ban list: triggers per deny category with sliding windows, escalating
  durations with a cap, exemptions, drop at accept or 403, bounded tables,
  bbolt persistence, reload survival; `xproxyctl bans`, `ban`, `unban` and
  `/v1/bans`. New `bans` section.
- Web application firewall: Coraza engine with the embedded OWASP Core
  Rule Set; profiles with paranoia level, thresholds, exclusion files and
  inline rules; `block`, `detect` and `off` per route; bounded request body
  inspection with replay; optional bounded response inspection; compile at
  load so a broken rule set fails the reload. New `waf` section and
  `routes[].waf`.
- Filter interface (`internal/filter`) for per-route middleware with
  request and response phases and access log attributes.
- Proprietary licence (Sysctl AB) and product name Xproxy (AMR-018).
- Documents: CHANGELOG.md (this file), AMR-018 to AMR-023.

#### Changed
- Minimum Go toolchain is 1.25 (required by Coraza).
- Rate limiter buckets account for peer consumption when clustering is on.
- `denied_ban`, `denied_waf`, `waf_detected`, `bans_active`, `bans_total`,
  `cluster_peers`, `cluster_connected`, `challenges_*` added to status.

#### Security
- Peer input can only tighten limits or add bans, never loosen anything.
- Challenge return paths are restricted to same-origin absolute paths.

### Phase 1: MVP

#### Added
- HTTP/1.1 and HTTP/2 listeners with hardened TLS 1.2/1.3 defaults, SNI
  certificate selection, certificate hot reload and client certificates.
- Host and longest-prefix routing with method filters and priorities,
  redirects, static responses, path strip and rewrite, header operations.
- Upstream pools with round robin, smooth weighted, least connections and
  consistent hashing; active health checks; passive outlier ejection with
  back-off; retries for replayable requests; HMAC signed cookie affinity.
- Defences: connection limits at accept (global and per address),
  concurrency ceiling, header, body, idle and write timeouts, URI and body
  size limits, bounded keyed token bucket rate limits with reject or
  tarpit, per-route CIDR allow and deny lists, trusted proxy handling for
  forwarding headers, path canonicalisation for routing, WebSocket opt-in,
  `Server` header removal, reason-phrase-only error pages.
- Strict YAML configuration with all validation errors reported together
  and secure defaults; atomic generation swap on reload; graceful shutdown;
  systemd socket activation and notify.
- Four JSON log streams (access, error, security, audit) with size
  rotation and a request identifier propagated end to end.
- Management API on a Unix socket with `SO_PEERCRED` audit logging;
  `xproxyctl` with status, stats, upstreams, config, validate, reload,
  reload-certs, reopen-logs and tail.
- Deployment: hardened systemd service and socket units, sysctl profile,
  SELinux policy skeleton, logrotate configuration, example configuration.
- Tests under the race detector, fuzz targets for every custom parser,
  golangci-lint with gosec, CI with govulncheck and fuzz smoke.
- Documentation: ASR, AMR, ARCHITECTURE, SECURITY, THREAT_MODEL, CONFIG,
  USAGE, SETUP, HARDENING, TESTS, ROADMAP.
