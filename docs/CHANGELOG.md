# Changelog

All notable changes to Xproxy. The format follows Keep a Changelog and
the project uses semantic versioning from 1.0.0. Entries are grouped by
the roadmap phase that delivered them (see [ROADMAP.md](ROADMAP.md)).

## Unreleased

### Security (1.4)

A **seventh round**, sweeping the sixth's two finding classes across
the gate kinds beside the one they were found on, and one finding of
its own.

- **Four listener kinds reported a refusal nobody could ban on.** The
  telnet, VNC and RDP gateways each hand the ban list a reason of their
  own (`telnet_denied`, `vnc_denied`, `rdp_denied`), as does the SFTP
  scanner when it refuses a file (`sftp_icap`). All four are documented
  as the reason a trigger names -- "Refusals are `rdp_denied` deny
  events, so bans apply" -- and none of them was in the table a trigger
  is validated against, so the configuration the documentation
  describes did not load. The ladder that answers a credential attack
  was, on the four newest protocols, not reachable. All four are
  nameable now, and a test reads the source for every reason a listener
  hands the ban list rather than keeping a second list beside the
  first: a kind added tomorrow fails it until its reason can be named.

- **The sixth round's two classes, swept.** *A peer's answer deciding
  what the gateway inspects* is RDP's alone: VNC checks the factor on
  the client's leg and gates the session on it afterwards, FTP takes
  the requirement from the target's own success reply and refuses every
  command until the code verifies, and telnet and SSH ask from the
  gateway before the target is dialled at all. *A bound that silently
  disables a credential path* was the two callers already fixed; VNC's
  credential bound and telnet's prompt line both have room for a
  recovery code. The FTP half of the recovery fix now has the
  regression test the RDP half already had, driven through an enrolment
  the control plane wrote.

- **An example for each of the three gate kinds that had none**:
  `examples/bastion/rdp.yaml`, `vnc.yaml` and `telnet.yaml`, alongside
  the ssh bastion already there. Each is a deployable file with the
  policy that makes the kind worth putting in the path -- the channel
  and device lists that decide whether an RDP session can move a file,
  the security types and the named credential a VNC factor can be
  looked up by, the telnet options an interactive session needs and no
  others -- and each carries a ban trigger on the reason its kind
  reports, which is what the finding above makes loadable.

A **sixth audit round**, over the parsers and the credential paths added
after the fifth: the RDP connection sequence and both of its encryption
layers, the RFB handshake including the vendors' own security types,
NTLM and CredSSP, the QR encoder, and the second factors the control
plane can now change. Fuzz targets for each, around five million
executions apiece, with fixes and regression tests.

- **An X.224 length indicator shorter than its own header was a panic,
  not an error.** The indicator counts the octets after itself, so the
  unit is one longer than it says; the check was against the far end
  only. An indicator below six made the options slice one whose start
  was past its end. It is the first packet of a connection, from a peer
  that has proved nothing -- eight bytes to a listening port -- and the
  same shape was in the parser that reads a desktop's answer, where a
  hostile or merely broken upstream could do it too. The session
  goroutine's recover kept it to one connection and a stack trace, which
  the earlier rounds already wrote down as not good enough. Both now go
  through one helper that checks both ends.

- **A desktop could turn the second factor off by leaving a block out
  of its answer.** The channel the credential travels on is named by
  the desktop, in the server network block of its conference response.
  A response without that block left the identifier at zero, so the
  credential -- which arrives on the real one -- matched nothing the
  gateway was watching, and went through with no factor checked, no
  credential substituted and nothing in the log to say so. A session
  whose answer does not name that channel is now refused, and the
  refusal is a security event.

- **A recovery code could not be used on FTP or RDP.** Those are the two
  protocols that carry the code inside the password field, because
  neither has anywhere to ask a question. A recovery code is seventeen
  characters with its separators and both would only split off sixteen,
  so it was never seen as a code: it went to the far end as part of the
  password and the refusal was byte for byte the one a wrong code gets.
  The worst shape a bug can have here -- the recovery path is for
  somebody already locked out and in a hurry, and it failed looking
  exactly like them mistyping. The length is now a constant in
  `internal/mfa` that both callers use, pinned to what the generator
  makes.

- **A wrong code cost a second of processor time, and only for names
  that were enrolled.** Every attempt was compared against each of the
  ten recovery hashes, at a password's PBKDF2 iteration count. So a
  wrong six digit code against an enrolled name took about one second
  and against an unenrolled one about twenty microseconds: four and a
  half orders of magnitude, which is not a side channel so much as an
  announcement. Anybody who could reach the prompt could enumerate who
  was enrolled, and the same arithmetic was a denial of service -- one
  packet bought a second of a core, as often as a client cared to send.
  Three changes: recovery codes are hashed at a low iteration count,
  because seventy four random bits do not need stretching and
  stretching them cost this; every attempt does the same number of
  comparisons whatever the enrolment holds, padded with a hash nothing
  matches, so how many codes a person has and how many they have spent
  are not on the clock either; and a name with no enrolment spends what
  a name with one spends. A wrong code is now about two milliseconds,
  the same either way. **Existing files keep the old cost until their
  codes are replaced** -- the iteration count lives in each stored hash
  -- so regenerate recovery codes on an upgrade (the GUI's *New codes*,
  or `/v1/mfa/recovery`).

- **A downgrade only the error log knew about.** A desktop answering
  that it encrypts nothing, on a leg an operator asked to encrypt, was
  noted in the error log. It is a security event now, which is the log
  an estate exports and alerts on.

Two things the fuzzing flagged that were not bugs, recorded because the
bound is worth pinning: the credential packet's strings and NTLM's
target name can be longer than the bytes they arrived in, because wide
text decodes to UTF-8 where a two byte unit becomes three. The
expansion is bounded at half again and the lengths are checked, so the
targets assert that bound rather than the naive one — an unbounded
decoder would be an amplifier.

A fifth audit round over every parser the data plane runs — binary and
wire formats, HTTP and text protocols, structured data — and the open
findings of rounds one to four. All with regression tests.

The round was extended over the parsers added since it began: the TLS
ClientHello reader that feeds certificate issuance, RFC 5424 structured
data, the FTP address negotiations, the gRPC framing and protobuf walk,
and the DNS name handling the tunnel detector added a caller to. Each
got a hostile test file, and the framing and text formats got fuzz
targets with round-trip properties — several million executions each,
which is where the first two below came from.

Parsers:

- **A ClientHello's server name was handed back exactly as the client
  wrote it**, and TLS interception then put it in a certificate's
  subject, its SAN, the server name of the upstream handshake and the
  key of a cache. Nothing checked it was a name: 254 characters, a
  space, a NUL, a newline, an empty label and bytes above ASCII all
  came through. The mismatch check against the CONNECT authority hid
  most of it, but not on a CONNECT to a bare address, where that check
  does not apply — so one tunnel to an intercepted address was an
  arbitrary string into all four (CWE-20). A name is now a name (at
  most 253 bytes, labels at most 63, IA5 or an IP literal) or it is
  not returned, and `Leaf` refuses to sign for anything else rather
  than trusting its caller to have looked. The destination's own SANs
  are filtered the same way before being copied: a server that puts a
  space or three hundred characters in its certificate must not have
  that copied into one this proxy signs.

- **An RFC 5424 structured data element with no parameters could not be
  read, and swallowed the element after it.** `[id]` is valid (section
  6.3) and the relay's own formatter writes it, so two of these in a
  chain dropped the record at the second — but the reason was worse
  than the symptom: the id was taken up to either delimiter and the
  closing bracket then looked for after it had already been consumed,
  which sent the parser into the *next* element to find a parameter
  there. `[a][b@2 k="v"]` became one element `a` with a parameter named
  `[b@2 k`. Structured data is where provenance lives — including the
  element this relay adds recording where a message really came from —
  so a sender could merge that annotation into an element of its own
  and make it unreadable downstream (CWE-115). The parser now reads
  which delimiter ended the id, and ids and parameter names must be
  SD-NAMEs: one to thirty-two printable characters, none of them a
  space, `=`, `]`, `"` or `[`.

- **FTP address parsing returned addresses that cannot be a peer**: the
  unspecified address, multicast, broadcast, and addresses carrying an
  interface zone. The session checks a client's `PORT` and `EPRT`
  against the client's own address, so nothing was reachable through
  it, but a parser that answers "0.0.0.0:1025 is a data connection" is
  a bug waiting for its next caller. `ParsePORT` and `ParseEPRT` — the
  two whose address is acted on — now refuse them. `ParsePASV` stays
  lenient on purpose and says so: its address is advisory, the proxy
  dials the server it is already connected to, and servers behind NAT
  really do advertise `0.0.0.0`.

- **DNS names were folded with `strings.ToLower`.** DNS case
  insensitivity is ASCII only (RFC 4343) and a label may hold any byte
  (RFC 1035 section 3.1), so Unicode folding is wrong twice: it maps
  characters DNS treats as distinct onto one another — the Kelvin sign
  lowers to `k` — and on bytes that are not valid UTF-8 it yields the
  replacement character, so every such byte became the same three and
  two different names folded to one string longer than either. That
  string is the cache key, the block list comparison, the canonical
  name a signature is verified over and the name an NSEC3 denial is
  hashed from. Nothing reached it, because the label check refuses any
  byte outside printable ASCII first — this is the hole that check was
  covering, not a hole — but the check is in a different function from
  every one of those uses, and the registrable-domain helper the tunnel
  detector added is exported with no check in front of it at all. All
  of them now fold in ASCII, and the gate has a test of its own so a
  future loosening of it fails loudly.

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

### Added (1.4)

- **DNS64: an AAAA answer for a name that has only an A record**
  (`server.listeners[].dns.dns64`; RFC 6147 with RFC 6052 addressing).

  An IPv6-only client asks for AAAA, the name has none, and this resolver
  asks for A instead and answers with that address embedded in a prefix
  routed to a translator. Nothing on the client changes -- it believes it is
  speaking IPv6 throughout, which is the point. The address placement is
  RFC 6052's, at all six defined prefix lengths, and the test checks it
  against the worked example in the RFC's own section 2.4 rather than
  against this implementation.

  Two things about it are security decisions rather than protocol.

  The address policy sees the **IPv4** address, before it is embedded.
  `64:ff9b::7f00:1` is not inside `127.0.0.0/8` and no prefix list would
  catch it, but it is 127.0.0.1 to everything past the translator -- so the
  A lookup runs through the ordinary path, which screens and caches it, and
  a cached address is screened again before it is embedded, for the same
  reason a cache hit is re-screened on the way out: a reload may have
  denied the range the entry was stored under. Without that, DNS64 would be
  a way around rebinding protection rather than a feature beside it.

  A synthesised answer is never signed and never claims to be: the reply is
  built from the client's question, so the AD bit is clear by construction
  (RFC 6147 section 5.5).

  A name with an AAAA record of its own is answered with it, a name that
  does not exist stays NXDOMAIN, and at most 32 records are synthesised
  from one A answer so that an upstream does not decide the size of this
  listener's reply. `clients` names the IPv6-only networks, and an IPv4
  network there is a load error: a client with IPv4 does not need the
  translation. Thirteen deliberate weakenings were each caught, four only
  after the tests were extended -- including the one that read a TXT record
  with three characters in it as an address, because its rdata is four
  bytes long.

- **DNS64: an AAAA answer for a name that has only an A record**
  (`server.listeners[].dns.dns64`; RFC 6147 with RFC 6052 addressing).

  An IPv6-only client asks for AAAA, the name has none, and this resolver
  asks for A instead and answers with that address embedded in a prefix
  routed to a translator. Nothing on the client changes -- it believes it is
  speaking IPv6 throughout, which is the point. The address placement is
  RFC 6052's, at all six defined prefix lengths, and the test checks it
  against the worked example in the RFC's own section 2.4 rather than
  against this implementation.

  Two things about it are security decisions rather than protocol.

  The address policy sees the **IPv4** address, before it is embedded.
  `64:ff9b::7f00:1` is not inside `127.0.0.0/8` and no prefix list would
  catch it, but it is 127.0.0.1 to everything past the translator -- so the
  A lookup runs through the ordinary path, which screens and caches it, and
  a cached address is screened again before it is embedded, for the same
  reason a cache hit is re-screened on the way out: a reload may have
  denied the range the entry was stored under. Without that, DNS64 would be
  a way around rebinding protection rather than a feature beside it.

  A synthesised answer is never signed and never claims to be: the reply is
  built from the client's question, so the AD bit is clear by construction
  (RFC 6147 section 5.5).

  A name with an AAAA record of its own is answered with it, a name that
  does not exist stays NXDOMAIN, and at most 32 records are synthesised
  from one A answer so that an upstream does not decide the size of this
  listener's reply. `clients` names the IPv6-only networks, and an IPv4
  network there is a load error: a client with IPv4 does not need the
  translation. Thirteen deliberate weakenings were each caught, four only
  after the tests were extended -- including the one that read a TXT record
  with three characters in it as an address, because its rdata is four
  bytes long.

- **Split horizon: the same name answered by who asked**
  (`server.listeners[].dns.views`), and the record types it needed
  (`dns.records` now takes `a`, `aaaa`, `txt` and `ptr`).

  One name with two answers is an ordinary requirement:
  `app.example.com` is a private address from inside the estate and a
  public one from outside, a laboratory network resolves a name to the
  test system, a guest network is held to a stricter list. The resolver
  could not do any of it, for a simple reason -- its local record set held
  only SVCB and HTTPS records, so it could not answer an A record at all.
  It can now, along with AAAA, TXT and PTR, and a record whose address
  does not match its type (an `a` holding an IPv6 address) is a load error
  rather than a record silently skipped when a client asks for it.

  A view selects the records this resolver answers itself, the names it
  refuses, and what a refusal answers. The first view whose networks
  contain the client wins, so the order of the list is the policy, and a
  view that matched everybody is refused because that is the listener's
  own policy under another name.

  **A view has no upstream of its own, deliberately**, and CONFIG.md says
  why: two views with different upstreams would answer the same question
  differently out of one shared cache, and a cache per view is a second
  resolver with a second memory -- which is a second listener, said plainly
  in the configuration rather than hidden inside a view. It is also what
  makes the feature safe without touching the cache: a view decides only
  what happens before the cache is read, a local answer is never cached,
  and a test asks both clients in both orders to prove neither can see the
  other's answer.

  `queries_viewed` counts them, `xproxyctl dns` lists the views, and the
  access log line carries `view`. Twelve deliberate weakenings were each
  caught by the tests.

- **XML bodies get what JSON already had** (`xml_guard` filter,
  `internal/xmlsafe`).

  The WAF reads bodies as text and the `openapi` filter validates JSON;
  between them sat every XML and SOAP API with neither. XML is also the
  format with the oldest and most reliable parser attacks -- an external
  entity that reads a file off the machine or makes requests from inside
  the network, entity expansion that turns a kilobyte into gigabytes of
  heap, parameter entity loops, external DTD fetches -- and every one of
  them arrives as a document type declaration or an entity reference in the
  body. A gateway cannot know how the application's parser is configured,
  and the defaults of most XML libraries were unsafe for years, so this
  refuses those shapes before that parser sees them and names which shape
  it refused: `xml_doctype`, `xml_entity`, and eleven more.

  `internal/xmlsafe` is a scanner rather than a parser: it reads the
  document once, keeps a stack of open element names and nothing else, and
  reports the first rule broken. Nothing is built, so a document that would
  have expanded to gigabytes is refused at the declaration that would have
  done it, in the bytes it arrived as, and a hundred thousand levels of
  nesting is refused by the depth bound rather than by this process running
  out of stack.

  Bounds on size, depth, elements, attributes, name length and text length;
  CDATA, comments and processing instructions each allowed or not; and a
  document shape policy -- `require_root`, `require_root_namespace`,
  `allow_elements`, `deny_elements` -- which is a positive model without a
  schema language. A body over `max_bytes` is refused rather than passed
  uninspected, because an oversize document must not be the way past the
  filter, and the body is replayed byte for byte so the application reads
  exactly what the client sent. `report: true` says what it would have
  refused and refuses nothing.

  **XSD validation is deliberately not implemented**, and the reason is in
  CONFIG.md: it is a language with its own parser, its own imports and its
  own denial-of-service history, and a gateway that fetched and interpreted
  one would add a larger attack surface than it removed. The application
  has the schema already.

  Thirty-six deliberate weakenings across the scanner and the filter were
  each caught by the tests, two only after the tests were extended for
  them: that a document type declaration is refused *as one* rather than as
  a generic declaration, and that the root-name check is not doing the
  namespace check's work.

- **The four HTTP gateway controls the batch asked for, and one real bug
  among them** (`routes[].early_hints`, `early_data`, `trailers`,
  `client_priority`).

  *Early Hints (RFC 8297) went through and the status did not.* A 1xx is
  informational: it does not end the header phase, and the real status
  still follows. The response writer recorded it as the status and marked
  the response written, so the final header was dropped -- and the client
  still saw 200, because `net/http` sends an implicit one with the
  accumulated headers when the body is written. Every record of such an
  exchange was wrong: the access log said 103 for a page that returned 200,
  and so did everything downstream of the recorded status. Now a 1xx is
  relayed and the final status is the one recorded, with a test that reads
  the access line rather than the client's view, because the client's view
  was the half that already looked right. At most eight informational
  responses are relayed per exchange: each is a header block an upstream
  can make this proxy write. `early_hints: strip` drops them where clients
  or middleboxes mishandle them.

  *Early data (RFC 8470).* A request that arrived in the TLS handshake can
  be replayed by whoever captured it. `early_data` decides what that means
  per route: `safe_methods` (the default) serves GET, HEAD, OPTIONS and
  TRACE and answers 425 Too Early to everything else, which is the RFC's
  own advice for a proxy that cannot know what a second POST would do;
  `reject` answers 425 to all of it; `allow` passes it through. The marker
  counts only from a peer inside `trusted_proxies`, and a client's own is
  removed before the upstream sees it -- the upstream cannot tell the
  proxy's copy from the client's, which is the whole reason the field is
  a hop's statement rather than a request's.

  *Trailers.* `trailers: strip` removes the announcement and the fields
  both, because an announced trailer with nothing behind it leaves a client
  waiting. It has to happen at the end of the body rather than on the
  response header: the transport fills the trailer map after everything
  that inspects a response has run, and the reverse proxy forwards whatever
  is in it, announced or not. Refused on a gRPC route, which carries its
  status there.

  *Priorities (RFC 9218).* `client_priority: lower` reads a client's
  `Priority` urgency and may move that request **down** the shedding order
  -- 4 or 5 gives up a class, 6 or 7 goes to `low` -- and never up. A header
  that could raise a class would be a promotion anybody can ask for, and
  the first thing a client under pressure would do is claim urgency 0,
  which would make shedding protect whoever asked loudest rather than
  whatever the operator called important. Lowering is safe in a way raising
  is not, because it can only cost the client that asked. A malformed field
  is ignored rather than refused, and the field is forwarded either way.

  Thirteen deliberate weakenings of the four controls were each caught by
  the tests.

- **The other answer to a stolen bearer token: the certificate it names**
  (`jwt.providers[].certificate_binding`; RFC 8705 section 3).

  DPoP landed in this batch and has the client sign a proof per request.
  This is the cheaper half of the same idea, for the clients that can do
  it: the client already proved possession of its private key in the TLS
  handshake, the authorization server recorded the certificate's SHA-256
  thumbprint in the token as `cnf["x5t#S256"]`, and the check is a
  comparison against the certificate on this connection. A token lifted
  out of a log or a crash dump is then useless anywhere else, with nothing
  for the client to implement.

  `mode: allow` compares whenever a token carries a binding and leaves an
  ordinary bearer token alone, so it can go on before every client is
  issuing bound tokens; `require` additionally refuses a token with no
  binding at all. Both can run beside `dpop`, and a token carrying both
  confirmations must satisfy both -- checked by a test that fails the
  right key on the wrong connection and the right connection with no
  proof.

  The certificate compared is the one from the handshake this proxy
  terminated. Where TLS is terminated in front, `trust_forwarded_header`
  reads RFC 9440's `Client-Cert` instead, and only from a peer inside
  `trusted_proxies`: a client that could set that header would otherwise
  choose which certificate its own token is checked against, which is the
  whole of the check. A certificate on the connection always wins over a
  header, the header is parsed as a certificate before it is hashed rather
  than after, and one over 16 KiB is refused before it is decoded.

  Both ways this can be configured so that it loads and never fires are
  warnings at every load -- no listener asking for a client certificate,
  and a forwarded header with no trusted proxies -- because a control the
  operator believes is on and is not is worse than one that refuses to
  load.

- **A SAML 2.0 service provider, with a profile narrow enough to be
  readable** (`saml_sp` filter, `internal/saml`).

  The last identity protocol this proxy could not speak, and the one that
  needed the most deciding. SAML's failure mode is not the crypto: it is
  that a response is an XML document, and XML gives an attacker a dozen
  ways to make the reader that verifies the signature and the reader that
  consumes the assertion disagree about what was signed. Signature
  wrapping is the whole family. So the answer here is not a more careful
  check on a general parser — it is a parser and a profile with no room
  for the ambiguity.

  The XML reader refuses a document type declaration, an entity
  declaration, any entity reference but the five predefines, a processing
  instruction, a CDATA section, a name outside ASCII, an undeclared
  prefix and a duplicate attribute. There is no external entity
  resolution to turn off, because there is no entity resolution. It keeps
  prefixes as written, because Exclusive Canonical XML renders them and
  the signature is over that rendering — a parser that resolves prefixes
  away (`encoding/xml` does) cannot reproduce the bytes the signer
  hashed, which is why this one exists.

  The signature profile is one `Reference` whose URI is `#` plus the `ID`
  of the element the signature is enveloped in, the enveloped-signature
  transform followed by exclusive canonicalization and nothing else,
  SHA-256 and above, RSA or ECDSA (as the concatenated `r` and `s` of RFC
  4051, not the ASN.1 sequence), and the key from the configuration.
  `KeyInfo` is not read at all. Wrapping is answered structurally rather
  than by a check: every signature in the document must verify, each
  against its own parent, a response may carry exactly one assertion, and
  two elements sharing an `ID` refuse the document.

  Encryption is refused by name. XML Encryption in a SAML responder has
  been a decryption oracle more than once, TLS already covers the hop,
  and a provider configured to encrypt should get a message saying so
  rather than "no assertion found".

  Everything else is checked completely: the issuer, `Destination`,
  `InResponseTo` on the envelope *and* on the subject confirmation, the
  `Recipient`, the audience, both condition windows, the confirmation
  window, `SessionNotOnOrAfter`, the status code, the name identifier
  format, `max_assertion_age` over all of it, and a bounded one-time
  table on the assertion identifier — an assertion is a bearer credential
  until it expires, so the same one twice is not a second login. A
  session never outlives the earliest expiry the assertion declared.
  Provider-initiated sign-on is not supported and single logout is not
  implemented, both on purpose and both documented with the reason.

  Around it: the HTTP Redirect binding for requests, the POST binding for
  responses (only `POST` with a form body, because a response in a query
  string is a response in a browser history and a `Referer`), a metadata
  endpoint, a metadata reader so the provider can be named by the file it
  publishes, and the same encrypted session cookie as `oidc`, sealed
  under both entity identifiers.

  Every check is pinned by a test that fails when the check is removed:
  thirty-nine deliberate weakenings of the package were each caught,
  including four that were caught only after the tests were extended for
  them. The canonical form itself is asserted against bytes written out
  from the specification by hand, because a wrong canonicalizer agrees
  with itself, and it found the first real bug: the default namespace
  rendered where no element used it.

- **A DNS answer is now screened by where it points, not only by the
  name that was asked.** The block list decides by name, and the name is
  the part an attacker picks last: blocking one costs them a
  registration. Two attacks live entirely in that gap, and neither is a
  name a list can hold. DNS rebinding answers a name the attacker owns
  with a public address while the page loads and `127.0.0.1` a second
  later, and the browser keeps treating the two as one origin, so the
  page reads whatever is listening on the loopback interface of the
  machine that opened it. The cloud metadata endpoint at
  `169.254.169.254` hands instance credentials to any process that can
  make an HTTP request, so a name resolving there turns "fetch this URL
  for me" into "read my keys".

  `dns.answer_policy` screens the answer section of every upstream reply
  *and of every cache hit*, before the answer is cached and before it is
  sent. `deny_private` stands for the twenty-three ranges RFC 6890 calls
  not globally reachable plus `::ffff:0:0/96`, and an address is unmapped
  before it is tested, so an AAAA record holding `::ffff:127.0.0.1` --
  which is not inside `::1/128` and which every socket API connects to
  `127.0.0.1` anyway -- is caught either way. `allow` carves ranges back
  out for the network that really does resolve names into private space,
  and `allow_names` exempts a name at either end of a CNAME. The action
  is `nxdomain`, `refuse`, `servfail` or `strip`; `strip` keeps the
  public address of a name that also has an internal one, drops the
  RRSIGs of any set it shortened (a signature over a set one record short
  does not verify, and a client would call the answer bogus rather than
  short), and is what the cache then stores. The refusing actions cache
  nothing at all, so the screen is re-applied to the next query rather
  than frozen into the cache. A denied answer is a `dns_answer_denied`
  security event naming the address, a ban reason, and
  `xproxy_dns_answer_denied_total`; a stripped one counts
  `xproxy_dns_answer_stripped_total` and is not a refusal. Only the
  answer section is screened, and the proxy's own answers -- `records`,
  `discovery`, the sinkhole addresses -- are not, which is why
  `sinkhole_ipv4: 0.0.0.0` still works inside a denied range.

- **A security key beside the one-time code** (`mfa` filter,
  `webauthn`; WebAuthn level 2, `internal/webauthn`).

  A code is a shared secret typed into whatever page asked for it, so a
  convincing copy of that page collects codes that work. WebAuthn does not
  have that failure: the assertion is bound to the origin the ceremony ran
  on, so a look-alike site gets a signature naming its own origin, which
  this refuses. That is the reason to have it.

  The two live side by side. A code is how somebody gets in from a machine
  with no key attached, and it is how a key is registered: registration
  requires a factor the user already has, because a registration endpoint
  that trusts only the first factor is a way to add a second factor to an
  account whose password has just been stolen.

  Verified on every assertion, each for a reason the signature alone does
  not give: the ceremony type, so a registration signature cannot be
  replayed as an authentication; the challenge, issued to that account,
  short-lived, and spent on first use whether the ceremony succeeded or
  not; the origin, exactly; the relying party hash, which the
  authenticator computes itself and a page cannot choose; user presence,
  and verification when asked, including at registration so a key cannot
  be enrolled under the weaker rule and used under the stronger one; the
  signature, under the stored key and the algorithm stored with it; and the
  sign count, which must move forward for an authenticator that counts,
  written to the credential file before the cookie is issued because a
  count kept only in memory is a clone check a restart forgets.

  A credential identifier is public -- it travels in the allow list on
  every login page -- so the store looks one up by account *and*
  identifier. Attestation is deliberately not verified, and the package
  comment says why: it identifies an authenticator model, not a person, and
  here a credential is trusted because the registration was authenticated
  by a factor the user already had.

  Everything runs on the standard library: a CBOR reader for the shapes the
  specification uses (definite lengths only, no tags, no floats, bounded
  depth, items and strings, duplicate map keys refused), COSE keys for
  ES256/384/512, EdDSA, RS256 and PS256 with the curve checked against the
  algorithm, and a credential file the proxy writes atomically and re-reads
  when it changes.

- **The backend no longer receives a credential that works at the front
  door** (`jwt.providers[].token_exchange`, RFC 8693).

  A token the client sent to the gateway was a token the gateway
  forwarded, so everything behind the gateway held a credential that works
  at the gateway. That is the confused-deputy problem in one sentence: a
  backend with a bug -- a log line, an error page, an outbound request to
  somewhere it should not go -- leaks a token that reaches the front door
  again with all of the client's scopes on it.

  Exchange replaces it. The proxy presents the *verified* client token to
  the authorization server and asks for one issued for this backend: a
  different audience, usually fewer scopes, no standing anywhere else. The
  client's identity survives, because the authorization server puts the
  same subject in the new token, which is what makes this an exchange
  rather than an impersonation.

  The exchange runs after verification and after `strip_token`, so the
  client's token leaves the request whether the exchange succeeded or not.
  A configuration that names neither an audience nor a resource is refused
  at load, since it asks for a token as broad as the one it replaces. The
  answer's `issued_token_type` is checked rather than assumed -- a server
  answering with a refresh token would otherwise have it forwarded as an
  access token, which is a long-lived credential handed to a backend. A
  refusal from the authorization server is the client's 403
  (`exchange_refused`) and is cached like a success, because it is a
  decision about this client and this backend and asking per request turns
  one misconfiguration into load the login flow shares; an endpoint that
  cannot be asked is a 503 with `Retry-After` and is never cached. Calls in
  flight are bounded, so a flood of distinct tokens cannot be amplified
  into an outage of the authorization server.

- **A stolen access token is no longer enough where the authorization
  server bound it to a key** (`jwt.providers[].dpop`, RFC 9449).

  A bearer token is a password: whoever holds it is whoever it says. That
  is the whole of its security model, and it is why a token stolen from a
  log, a browser's storage, a proxy's cache or a crash dump is as good as
  the original -- nothing about the request says it came from the client
  the token was issued to.

  DPoP adds the missing part, and this proxy now verifies it. The client
  keeps a key pair, the authorization server records the public key's
  thumbprint in the token as `cnf.jkt`, and every request carries a small
  JWT signed with the private key over *this* method, *this* URI and
  *this* moment. Six things are checked, in the order that makes each
  meaningful: the proof is a `dpop+jwt` with an asymmetric algorithm from
  the allow list and no private material in its key; its signature
  verifies under the key it embeds; `htm` and `htu` match the request
  (method exactly, URI without query or fragment, scheme from the
  connection and never from `X-Forwarded-Proto`); `iat` is inside the
  window and the `jti` has not been seen; **the RFC 7638 thumbprint of
  that key equals the token's `cnf.jkt`**, read from claims this proxy has
  already verified; and `ath` is the hash of the access token it came
  with.

  `mode: allow` costs nothing to turn on -- it never refuses an ordinary
  bearer token, and it closes the replay hole for every token that was
  constrained; `require` takes constrained tokens only. The `jti` is spent
  last, after every other check holds, so a proof refused for another
  reason does not consume the identifier a correct retry would use, and
  the replay table is bounded because the identifiers come from clients.
  The `Authorization: DPoP` scheme is read as well as `Bearer`, since a
  server that reads only `Bearer ` does not see a sender-constrained token
  at all, and the proof is removed before forwarding: it is a signed
  statement about this hop.

- **A client can no longer send its own certificate identity, and the
  proxy states the real one in RFC 9440's form**
  (`routes[].client_cert_headers`).

  A backend behind a TLS-terminating proxy cannot see the handshake, so
  the proxy tells it: RFC 9440 standardises `Client-Cert` and
  `Client-Cert-Chain`, Envoy has long used `X-Forwarded-Client-Cert`, and
  nginx and Apache deployments read a handful of `X-SSL-Client-*` names
  their own configurations set. Every one of them is a statement about
  something only the terminating proxy can know -- which makes every one
  of them an authentication bypass when a client can send it, because the
  backend has no way to tell the proxy's header from the client's. They
  are the same bytes in the same field.

  All seventeen of those names are now removed from every forwarded
  request, unless the immediate peer is inside `trusted_proxies` -- the
  one case where such a header belongs to a proxy that did terminate a
  handshake. That is what RFC 9440 section 3 asks for in as many words,
  and it was previously true only for the specific header a route
  happened to set from `${cert:...}`. A backend that reads one of these
  therefore reads what this proxy said or nothing at all.

  `routes[].client_cert_headers: rfc9440` then writes the truth over the
  blank: the leaf in `Client-Cert` and the rest of the chain in
  `Client-Cert-Chain`, each as the Structured Fields Byte Sequence RFC
  8941 defines (standard base64, padded, between colons, which a
  structured-fields parser accepts and anything else it rejects). `xfcc`
  sets Envoy's header instead, and `${cert:client_cert}` is available for
  a route that wants the value somewhere else. Nothing is sent when the
  client presented no certificate: an absent header is how the backend is
  told there was none, where an empty one would mean whatever its parser
  makes of emptiness.

- **The GraphQL filter judges what an operation is, not only what it
  costs** (`mutations`, `subscriptions`, `allow_operations`,
  `require_operation_name`, `persisted`, `max_root_fields`,
  `max_directives`).

  - **A mutation could arrive by GET.** The operation type was parsed and
    thrown away, so nothing separated a query from a mutation. The
    GraphQL over HTTP specification reserves GET for queries, and the
    reason is that a GET is what a link, an image tag, a prefetch and a
    crawler all produce: a mutation reachable that way is a mutation
    anybody can fire from another origin with the browser attaching the
    cookies. It is refused unconditionally (`get_mutation`) -- there is no
    option, because no configuration makes it safe. Beside it,
    `mutations: deny` and `subscriptions: deny` make an endpoint
    read-only outright.
  - **Operation names were invisible.** `require_operation_name` refuses
    an anonymous operation and `allow_operations` names the only ones
    that may run, which is the strongest control here for a closed client
    set: the queries are known, so anything else is not a query this API
    serves. The list implies the name requirement, because an anonymous
    operation is on no list and a list that let it through would be a
    list in name only.
  - **A persisted query walked past every bound.** A request with no
    query text -- the origin looks the document up by hash -- had nothing
    to parse and nothing to measure, and the filter returned Continue.
    `persisted: deny` refuses it. `allow` stays the default, because an
    origin that only runs documents it already has is usually the safest
    thing a client can send.
  - **Breadth and directives were unbounded.** `max_root_fields` (20)
    bounds an operation's top-level selection, which is the breadth a
    depth bound says nothing about, and `max_directives` (100) bounds the
    directives in the query text, since a directive is evaluated per
    field it decorates.
  - **Only the selected operation is measured now.** A document may carry
    a client's whole query file and select one with `operationName`; only
    that one runs, so judging the request by the others refused clients
    for queries they did not send. What the document *contains* is still
    policy, so the mutation sitting beside the selected query is still
    caught.
  - **Variables are read.** `friends(first: $count)` with `{"count": 10}`
    in the request is ten things, and scoring it as `max_list` refused a
    query that costs nothing -- which is how a complexity bound ends up
    switched off by the operator it kept annoying. A variable the request
    does not carry, or carries as anything but a whole non-negative
    number, is still the worst case, and a larger literal still wins.

- **The OpenAPI filter enforces the parts of a description it was reading
  as documentation** (`require_security`, `read_only`, and form bodies).

  - **`security` was ignored.** An operation says which credential it
    needs and `components.securitySchemes` says where that credential
    lives -- a named header, a query parameter, a cookie, an
    `Authorization` header with a particular scheme -- and the filter
    checked none of it. `require_security: true` refuses a request that
    carries none of the alternatives the operation asks for, with 401 and
    `WWW-Authenticate` where there is a registered challenge to name.
    That catches the failure that keeps happening: an endpoint meant to
    be authenticated and not, because the middleware was registered for
    one router and not another. Presence and shape are checked, never
    validity -- a forged token still reaches the API and is still refused
    there; a request with no credential does not reach it. The
    alternatives are OpenAPI's OR of ANDs, an operation's own `security`
    replaces the global one, `security: []` opts an operation out, and an
    empty object among the alternatives is how the specification says the
    credential is optional. A description whose `security` names a scheme
    `securitySchemes` never defined is refused at load, since such a
    section means nothing. `mutualTLS` is left to the listener's
    `client_auth`, which settled it before this filter ran. The default
    is off because turning it on refuses whatever was reaching the API
    without a credential, and a description that declares security while
    it is off now logs a warning at every load naming the count.
  - **`readOnly` was ignored.** OpenAPI says such a property "MUST NOT be
    sent as part of the request", and the reason is mass assignment: an
    object with `id`, `owner` and `role` marked read-only is one whose
    server-owned fields a client is not supposed to pick, and an
    application that binds the whole body onto its model lets them.
    `read_only: deny` refuses those bodies and `log` records
    `openapi_read_only` in the access log without refusing, which is how
    to find out whether `deny` would break the clients. The walk follows
    `properties`, `items`, `additionalProperties` and `allOf` and
    deliberately not `anyOf` or `oneOf`: those are alternatives, and a
    property read-only in a branch the value may not be matching says
    nothing certain about the value in hand.
  - **Only one of OpenAPI's parameter styles was read.** A parameter is
    not always one string: an array may arrive repeated
    (`?ids=1&ids=2`), comma-separated, pipe-separated or
    space-separated, and an object may arrive as bracketed names
    (`?filter[from]=x`), with `style` and `explode` saying which. The
    filter assumed the comma form, so a `pipeDelimited` or
    `spaceDelimited` array was one item that was not a number and a
    `deepObject` parameter was missing -- correct requests refused by the
    gateway on the strength of the description that declared them, which
    is how a validating gateway gets taken out of the path. Every style
    is read now, with both spellings of a form array accepted since both
    are unambiguous, a `deepObject` assembled into the object its schema
    declares (bounded, because the keys come from the client), and
    `strict_query` taught that a `deepObject`'s bracketed names belong to
    it. A repeated scalar is still validated for every value, and the
    array is now built from the occurrences rather than joined and split
    again, so a comma inside one of them no longer becomes two elements.
  - **A form body declared with a schema was forwarded unvalidated.**
    `application/x-www-form-urlencoded` is now checked against its
    schema, with each field coerced by what the schema says it is -- the
    same coercion the query parameters get, so `limit=abc` against
    `type: integer` is a type error rather than a string that happens not
    to be a number. The body reaches the application byte for byte as
    sent: it is validated, not re-encoded. `multipart/form-data` stays
    with `upload_guard`, which buffers the parts already.

- **A DNS listener answers and requires DNS cookies** (`dns.cookies`,
  `dns.cookie_lifetime`; RFC 7873 with RFC 9018's server cookie layout).

  A UDP datagram proves nothing about where it came from, and everything
  unpleasant about an open resolver follows from that: an answer sent to
  an address that did not ask, a small question drawing a large reply for
  somebody else's link, a cache poisoned by a race the attacker enters
  with no packets of their own to lose, and a security event recorded
  against an address chosen by whoever sent the packet. A cookie fixes
  the one thing underneath all of them -- it makes the client prove it
  can *receive* what it asked for.

  `respond` (the default) answers a client that sent a cookie with one
  and never refuses a query for the want of one, so a client that has
  never heard of cookies is unaffected. `require` answers a UDP query
  without a valid cookie with BADCOOKIE and a fresh cookie, so a
  cookie-aware client retries once and succeeds while nothing is looked
  up for the first attempt -- the whole saving; a client that sends no
  option at all gets REFUSED, because there is nothing to echo, which
  breaks most stub resolvers and is warned about at load on a listener
  with no `allow_clients`. Stream transports are exempt from `require`,
  since the handshake is the proof a cookie exists to provide, but they
  still hand one out so a client can collect it over TCP and use it over
  UDP.

  The part that matters beyond amplification: **a verified cookie makes a
  UDP client's security events attributable.** Events from a bare
  datagram are aggregated and attributed to nobody, because counting them
  towards a ban would let anybody have a third party banned by spoofing
  them. A UDP query carrying a cookie this listener issued has completed
  a round trip, so `dns_blocked` and `dns_tunnel` from it drive bans like
  a TCP client's. Cookies are the prerequisite for the ban ladder working
  over UDP at all.

  The server cookie binds the client's eight bytes to the client's
  address under a per-listener secret that is never written anywhere, so
  a cookie replayed from another address does not verify, a restart costs
  each client one round trip, and two cluster nodes do not accept each
  other's. `cookie_lifetime` is an hour by default and a cookie past half
  its life is replaced in the answer, so a client that keeps asking never
  reaches the end of one. BADCOOKIE is written as RFC 6891 requires -- the
  low four bits of rcode 23 in the header and the high eight in the OPT
  record -- and logged as 23.

- **A DNS listener can ride out an upstream outage and refresh what is in
  use before it expires** (`dns.cache.serve_stale`,
  `dns.cache.stale_ttl`, `dns.cache.prefetch`,
  `dns.cache.prefetch_threshold`).

  `serve_stale` (RFC 8767) keeps an expired entry that much longer and
  serves it when the upstream has nothing to say, which is the
  difference between a resolver outage taking the network with it and
  one nobody notices for an hour. The answer is out of date by
  definition, and a name almost always still resolves where it did a
  minute ago -- while a client that cannot be told anything cannot reach
  the upstream itself either. A stale answer carries `stale_ttl` (30
  seconds, RFC 8767's recommendation) rather than the TTL the zone
  published, so the client comes back soon; it is counted as
  `xproxy_dns_stale_total` and logged with `source=stale`, so a resolver
  running on expired answers says so rather than being discovered later.
  A stale entry is never a cache hit: the upstream is asked first every
  time. "Nothing to say" means no answer at all, and a SERVFAIL when
  `dnssec` is off -- with validation on, a SERVFAIL is the code for an
  answer that was *rejected*, and standing in for it with an expired
  answer of our own would hand the client, as a last resort, exactly
  what validation refused.

  `prefetch` refreshes an entry when a query arrives for it and less
  than `prefetch_threshold` of its TTL is left, so a popular name is
  answered from the cache continuously instead of one client per TTL
  waiting for the upstream; that client is answered from the cache and
  waits for nothing. The claim lives on the cache entry, so a burst of
  queries for the same nearly-expired name starts one refresh and not a
  hundred -- the stampede the feature exists to prevent and would
  otherwise cause. Refreshes have a budget of their own (64 at a time)
  rather than a share of `max_in_flight`, since a resolver that answered
  clients more slowly because it was busy refreshing would have it
  backwards, and a refresh belongs to nobody: it raises no security
  event against the client whose query happened to trigger it.

- **What the SSH certificate authority said is now enforced.** A user
  certificate is not only a signature over a key and a list of
  principals; it carries the CA's own restrictions, and the gateway
  checked the signature and ignored the rest. So:

  - **`source-address` did nothing.** A certificate the CA restricted to
    one network was accepted from anywhere. It is the one critical
    option x/crypto/ssh deliberately leaves to the caller -- checking it
    needs the client's address, which `CheckCert` does not have -- and
    the caller was not doing it. A list the gateway cannot parse refuses
    the certificate rather than being treated as absent.
  - **The extensions did nothing.** They are permissions and their
    absence is a denial: a certificate made with `ssh-keygen -O clear -O
    permit-pty` grants a terminal and nothing else, and this gateway was
    giving it everything the listener allowed. `permit-pty`,
    `permit-port-forwarding`, `permit-agent-forwarding` and
    `permit-X11-forwarding` are each read now, and each has a refusal
    reason of its own.
  - **`force-command` did nothing**, because the library refuses any
    critical option the caller has not declared support for -- so a
    certificate carrying one was refused outright rather than honoured.
    It is declared and implemented now: the client's command is
    replaced, a `shell` request becomes that command, and both are
    logged as `ssh_force_command` with what was asked and what ran.
    Nothing else is declared, so an option this gateway does not
    implement still refuses the certificate, which is what "critical"
    means.

  With them: `revoked_keys`, the one list that overrides the CA -- a key
  there is refused whether it is offered plainly, carried by a
  certificate, or the authority that signed one -- and
  `max_certificate_lifetime`, because the point of certificates over
  `authorized_keys` is that they expire and a CA issuing for a year has
  made a credential nobody can take back for a year.

  **A CA-only bastion did not load.** Two validation checks disagreed:
  one allowed `authorized_keys`, `users_file` or `trusted_user_ca_keys`
  and the other, earlier and the one an operator meets first, allowed
  only the first two. A fleet that had moved to certificates -- which is
  the point of moving -- could not configure this listener at all. The
  test for the certificate policy is what found it.

- **`allow_commands` is patterns, and a shell is not.** `^journalctl
  .*$` matches `journalctl -u x; rm -rf /` exactly as happily as what it
  was written for, and that pattern is in this repository's own example.
  An `exec` command line is now read the way a shell would split it
  before any pattern is tried, and one carrying an operator -- `;`, `&`,
  a pipe, a redirection, a backquote, a `$(`, a brace, a glob, a control
  character, an unbalanced quote -- is refused with `shell_syntax`.
  Deliberately crude and deliberately broad: a bastion does not need to
  know what a line would do, it needs to know the line is a command with
  arguments, which is the only shape a pattern can be written against.
  `allow_shell_syntax: true` turns it off and warns.

- **Three bounds a bastion did not have.** `max_sessions_per_principal`,
  because `max_sessions` is the whole fleet's and a robot looping
  connections could take the bastion from the people; `max_forwards`,
  because a session that may forward at all could open one per
  descriptor the process has; and `rekey_bytes`, because a bastion
  session lasts a working day and was spending it on one key.

- **The two FTP commands that are only half a decision.** A proxy that
  reads FTP one command at a time can hold a policy over each command and
  still miss what a pair of them does.

  `REST 1000` then `STOR /pub/x` is not an upload of the bytes that
  arrive: it is an edit of a file at an offset, and the bytes that arrive
  are a fragment. **A scanner only sees what crosses the proxy**, so
  `yara` and `icap` rules that would match the whole file never saw it --
  upload the first half, `REST` to the middle, upload the second, and
  each half passed. A resumed transfer on a listener with either is
  refused now (451, `rest_unscannable`), because the proxy cannot scan
  bytes it will never be shown and pretending otherwise is a hole in the
  rule set rather than a limitation of it. And `max_file_bytes` counts
  the offset, so it is a bound on the file rather than on one transfer:
  ten bytes at offset sixty is seventy against the bound. The marker
  itself must be a plain non-negative decimal (RFC 3659 allows a
  server-defined format, which is a value this proxy cannot reason about
  and will not carry), is bounded, and is spent by the transfer it was
  for -- refused or not.

  `RNTO` without an `RNFR` the server accepted with 350 is half a
  rename, and it was relayed. It is refused now (503,
  `rename_out_of_order`), which also means an `RNFR` the path policy
  turned down cannot be followed by an `RNTO` the server would have
  completed against some other pending rename.

- **Path shapes an FTP proxy and its server would read differently.** A
  path argument is refused before the allow and deny lists are
  consulted when the two ends cannot agree on what it names: a backslash
  (a separator on a Windows server, an ordinary character in a pattern
  here, so `/srv/exports\..\..\etc` is inside the allowed tree as far as
  the proxy can tell), a control character, and bytes that are not valid
  UTF-8 (an overlong sequence decodes to `/` on a lenient decoder and is
  not a separator to a strict one). Each has a reason of its own.
  Paths in other scripts are unaffected -- this is about the shapes that
  cannot be compared, not about everything above ASCII.

  Also written down rather than left to be rediscovered: the address in a
  passive reply is not used. The proxy dials the target it already has a
  control connection to, with the port from the reply, so a server that
  answers with somebody else's address cannot redirect it. And `CCC` is
  refused twice over -- it is not in the default `commands` list, and a
  listener whose operator adds it still gets a 534.

- **A recording can be read without being run.** A gate session's
  recording is the bytes the session sent, which is what makes it a
  record -- and a terminal is an interpreter of exactly those bytes, so
  the person recorded has written a program for the terminal of the
  person who reviews it. Some of what a terminal will do on request
  reaches outside the window: `OSC 52` writes the reviewer's clipboard
  and waits for it to be pasted, `OSC 0` and `OSC 7` retitle the window
  and its working directory, `OSC 8` makes a hyperlink whose text and
  target need not agree, and the device reports -- `CSI c`, `CSI n`,
  `DECRQSS`, the window manipulation sequences -- make the terminal write
  back **on its own input**, which in a shell is a command line. That
  last one turns reading a log into running one. Until now the only way
  to read a recording was a player, and a player is the thing that
  interprets it.

  `xproxyctl session list|show|play` reads one instead. `show` keeps the
  text and drops every sequence, which is what reading a session wants;
  `-safe` (the default for `play`) keeps the sequences that draw inside
  the window -- colour, cursor movement, erasing -- and writes the rest
  out inert, so a clipboard write appears as `\e]52;c;cHduZWQ=\x07`
  rather than silently happening or silently going missing. A CSI
  sequence is forwarded only when its final byte is one that draws, so
  the reports are refused by construction rather than by a list of known
  bad ones; the private modes are checked by number, because the mouse
  and focus reporting modes make a terminal send rather than draw.

  The filter is a state machine held across writes, since a sequence
  split over two reads is exactly the one a filter matching on whole
  strings would forward, and the test drives every split point of a
  hostile sequence. The bidirectional overrides, isolates, zero width
  characters and a stray byte order mark are named (`\u202e`) rather
  than passed on: the screen disagreeing with the file is the Trojan
  Source class, and a session recording is a good place for it.

  The file is never rewritten. Sanitising at capture would make the
  record less than a record; the filter belongs between the file and the
  reader, which is the only other place it can be.

  The same policy now covers the two paths that had a narrower version of
  it. Everything `xproxyctl` prints goes through it (it filtered the C0
  controls before, one writer per call, which left the eight bit C1
  forms -- `0x9b` is CSI -- and the bidirectional overrides, and could
  not see a sequence split across two writes). `textsafe.Clip`, which
  guards every log field a peer chose, gained the same two groups, so a
  user name carrying `0x9b` is no longer an escape sequence in a log line
  with no ESC anywhere in it.

- **The VNC gateway reads the picture, and bounds it.** The pixel stream
  was forwarded without being read, which meant the gateway could hold a
  policy about who connected and none about what arrived. What arrives,
  in an image protocol, is a series of numbers that are the viewer's
  allocations: a `ServerInit` says the desktop is so many pixels and the
  viewer allocates a framebuffer from it; a rectangle's twelve byte
  header says how much of the screen it covers and the viewer sizes a
  decode buffer from that. A desktop saying 4096x4096 in twelve bytes of
  zlib is asking the machine on somebody's desk for sixty-four
  megabytes, and it can ask again immediately.

  `bounds` is the policy: `max_framebuffer_pixels`,
  `max_rectangles_per_update`, `max_encoded_rectangle`,
  `max_decode_ratio` and `max_cut_text`, all on by default. Nothing is
  decompressed to apply them -- each one compares what a rectangle
  declared with what arrived -- and two checks apply whatever `bounds`
  says: a rectangle must lie inside its framebuffer (a viewer writes a
  rectangle's pixels at the offset the rectangle gives, so one reaching
  past the end is a write past the end of the buffer the viewer made),
  and a pixel format must be 8, 16 or 32 bits, because every length in
  the picture is a whole number of pixels.

  **Framing decides what a client may ask for.** The gateway can only
  frame an encoding whose payload length it can compute, so the ones it
  cannot are removed from the viewer's `SetEncodings` and the desktop
  never uses one: `tight` and `trle` (whose lengths depend on a filter, a
  palette size and a pixel width that is not the pixel format's),
  `cursor-with-alpha`, and anything unregistered. A viewer asks for every
  encoding it has, so a filtered list still draws; `zrle` is the usual
  survivor and `raw`, which RFB makes mandatory, is added if nothing else
  is left. `pixel_stream: opaque` is the escape hatch for a desktop that
  must have Tight, and it gives up the three bounds that need the stream
  read. Validation warns, because that is the trade.

  The client's messages are now framed too, whatever `pixel_stream`
  says, which is what `view_only` already needed and what the new
  `clipboard` policy (`both`, `to_client`, `to_target`, `none`) and
  `allow_resize` need. **A file transfer cannot cross this gateway**, and
  not because a rule forbids it: TightVNC's and UltraVNC's transfers are
  client messages 252 and 255, whose lengths are the vendors' own, and a
  gateway that forwarded a message whose length it does not know could
  not find the message after it. It is a consequence of framing rather
  than a rule.

  The picture is written onward as it is read, in 64 KiB pieces, rather
  than assembled and then forwarded: a full screen update is tens of
  megabytes, and a gateway holding one per session would be a proxy an
  operator could run out of memory by connecting to it. The test for
  that is a truncated megabyte rectangle, most of which has already left
  when the read fails.

  One restriction comes with framing: a `SetPixelFormat` is allowed
  before the first update request and refused after it, because RFB has
  no message that says "the next rectangle is in the new format" and a
  gateway that kept framing past a mid-stream change would be guessing
  where the rectangles are. Viewers that re-negotiate colour depth by
  themselves need a fixed depth, or an opaque listener. Every refusal on
  this path has a reason of its own in
  `xproxy_refusals_total{kind="vnc"}` and a `vnc_denied` event carrying
  the numbers that caused it, because a bound that fires without saying
  which one and by how much is a bound nobody can tune.

- **A refusal reason per protocol, not one number per protocol.** HTTP
  had twenty-two named refusal counters behind
  `xproxy_denied_total{reason}`; every other protocol had one aggregate
  each. `xproxy_ssh_refused_total` covered a refused channel type, a
  refused command, an environment variable outside the list, a port
  forward to the wrong place and a failed second factor, and an
  operator watching it climb could not tell which of those to widen.
  The DNS listener was the plainest case: `xproxy_dns_dropped_total`
  was documented as "banned, rate limited, malformed, over the
  in-flight bound" -- four causes wanting four different answers, in
  one number.

  `xproxy_refusals_total{kind, reason}` is the breakdown, for `tcp`,
  `udp`, `forward`, `dns`, `ssh`, `telnet`, `vnc`, `rdp`, `smtp`,
  `mqtt`, `ftp` and `syslog`. The reason is the one each kind already
  put in its security log, with the kind's own prefix removed because
  the label carries it, so the series names the log line to go and
  read and there is no second vocabulary to keep in step with the
  first. The aggregates stay: this is the detail under them, and
  `xproxyctl stats | jq .refusals` is the same table.

  Some of those reasons were being thrown away rather than merely
  lumped together. The syslog relay computed why it dropped a message
  -- the facility list, the severity floor, a pattern -- and dropped
  the reason with the message. SMTP's command refusals and VNC's
  security-negotiation refusals answered the client and counted
  nothing an operator could read. The DNS listener's four drop causes
  are now four reasons and the one an operator can act on
  (`workers_busy`, meaning `max_in_flight` is too low) is the only one
  that still warns.

  Deliberately outside the family: refusals by the server-wide accept
  path, which happen before any kind sees the connection and stay in
  `xproxy_connections_rejected_total` and
  `xproxy_connections_rate_refused_total`; and failures that are not
  refusals (an upstream that would not answer, a read that died),
  which stay in each kind's error counter, because an operator hunting
  a policy should not have to read past a broken backend to find it.

  A test reads the source of every kind and fails one that refuses
  connections without naming a reason, or that reports under a
  sibling's name, so a kind added tomorrow arrives with its telemetry.
  `xproxy_refusals_untracked_total` is zero in a healthy process and is
  what a refusal falls into if a kind ever names one the table cannot
  hold; it has an alert of its own, because a bounded table that
  dropped what it could not hold would lose exactly the refusals
  somebody is looking for.

- **Consul as a discovery type of its own, with blocking queries.**
  Discovery already reached Consul by polling its HTTP API
  (`type: http, format: consul`), and DNS A/AAAA and SRV were already
  there. What polling cannot do is notice quickly: a registry asked every
  thirty seconds keeps sending traffic to a machine that is already gone
  for up to thirty seconds.

  `type: consul` uses Consul's **blocking query** — the agent holds the
  request open until the answer changes and returns an index the next
  request carries — so an instance that goes away leaves the pool in about
  the time Consul takes to notice. The loop therefore waits on the agent
  rather than on a ticker, and `interval` becomes the pause after a
  **failure**: without one, an agent that is down or answering 403 would
  be asked again immediately and forever, which is a loop against somebody
  else's machine. An index that goes backwards, which a Consul server
  restart produces, resets rather than blocking on an index that will
  never be reached.

  It also spells the ordinary things: the URL is built from a service
  name, the agent defaults to the local one (which is where a Consul
  deployment puts it, and what survives a partition), and the ACL token
  comes from a **file** — a token in the configuration is a credential in
  the management API's output and in the configuration history. Only
  instances whose checks all pass are used, checked here as well as asked
  for in the query: the filter in the query is the agent's opinion, this
  one is the proxy's.

- **Transparent interception: `original_destination` and
  `transparent`.** For the deployment where the client does not know the
  proxy is there, and a routing rule puts its packets on a listener that
  was not the address it dialled.

  `original_destination` answers "which upstream" from the socket, since
  there is no configuration question to answer: `SO_ORIGINAL_DST` for an
  iptables REDIRECT, falling back to the socket's own local address for
  TPROXY, so both work without an operator having to tell the proxy which
  rule they wrote and keep that in step with the firewall.
  `transparent` dials the upstream **as the client** —
  `IP_TRANSPARENT` and a bind to the client's address — for a service
  that needs to see who is calling and has no PROXY protocol to read it
  from.

  The part worth reading is the loop check. This is the only place in the
  proxy with a destination it did not choose, and a firewall rule that
  sends a listener's port to itself makes a loop that consumes
  descriptors until the process dies, from **one client packet**. So
  before every dial: there is a destination to read, it is not this
  listener's own address, and it is inside `allow_destinations` — which
  is required, and whose empty value allows nothing, so forgetting it
  fails closed rather than making an open relay.

  Both are Linux only and refused elsewhere rather than silently doing
  nothing; `transparent` checks at load that the process may actually set
  the option, because otherwise every connection fails in a way that
  looks like a dead upstream — and warns that the return traffic must be
  routed back, which the proxy cannot check and which fails the same way.

- **Two balancers that read what the endpoints are doing.** `least_conn`
  scans every endpoint and takes the best, which has a failure mode of
  its own: every proxy in a fleet sees the same best endpoint at the same
  moment and they all send to it together, so the herd moves from one
  endpoint to the next.

  `p2c` takes two endpoints at random and uses the better of those. One
  comparison avoids the worst endpoint, and the randomness means two
  proxies rarely agree, so load spreads instead of sloshing. `ewma`
  weighs endpoints by the smoothed time to first byte the pool already
  keeps for outlier detection, times the queue a request would join: an
  endpoint answering slowly gets less work **long before** it is slow
  enough to fail a check or be ejected, which is the difference between
  shedding load away from a struggling machine and waiting for it to
  break. An endpoint with no sample yet costs nothing, so a recovered one
  is tried rather than starved by the fact that nothing is known about
  it.

- **Tiers: priority, backup and locality.** `endpoints[].priority` makes
  the endpoints of the lowest priority number that has an available
  member carry the traffic, with the next tier taking over when it has
  nothing left and handing it back when it returns — so a **backup
  endpoint is simply one in a later tier** rather than a special kind of
  endpoint, and a retry that has used up a tier falls to the next.

  `locality: {prefer_zone: true}` prefers the endpoints in this node's
  own `server.zone`, which keeps traffic off the links between sites. It
  is a **preference, not a pin**: an estate that pinned traffic to one
  zone would lose the service when the zone lost it, which is the
  opposite of what zones are for, so the remote endpoints take over when
  the local ones are gone. `min_local` is how many local endpoints must
  be available before the remote ones are ignored, so a zone down to one
  surviving endpoint does not take the whole load alone; and an endpoint
  with **no zone is local to every zone**, because "somewhere unknown" is
  not a reason to send traffic across a site.

  Tiering leaves the other endpoints out of the choice rather than
  shortening the list the balancer sees, which matters for `hash`:
  shortening it would move every key, while leaving endpoints out moves
  only theirs.

- **A dual-stack policy: `address_family` and `fallback_delay`.** A name
  with both an A and an AAAA record has two ways to be reached, and the
  broken one costs a connect timeout on every request that tries it
  first. The default races the families as RFC 8305 describes, with the
  second held back 300ms; `ipv4` or `ipv6` dials that family only, for
  the estate where one is the only one that works — naming it means a
  name that also has the other kind of record cannot quietly use the
  family the policy meant to exclude, which is the failure a mere
  preference would hide.

- **Drain an endpoint, or put a whole pool in maintenance.** Taking a
  backend out of service meant stopping it and letting the proxy find
  out, which loses the requests in flight on it and the ones that arrive
  before the health check notices.

  `xproxyctl drain POOL [ADDRESS]` (and `POST /v1/drain`,
  `endpoints[].drain`, a pool's `maintenance`) stops new work and **ends
  nothing**: what is already there runs to its own end, so `ACTIVE`
  falling to zero is the signal that the machine is yours. That makes a
  rolling restart a sequence of drains rather than a series of small
  outages.

  Draining is deliberately **not** a health result. An unhealthy endpoint
  is one the proxy found broken; a drained one is one a person decided
  about. So it stays `healthy` in the status with `draining` beside it,
  and it **survives a reload** — a reload builds new pools, and somebody
  who drained a machine to patch it did not mean "until the next
  configuration change". A decision made through the API overrides the
  file until the daemon restarts, because the person who made it knew
  something the file did not.

- **A bound per endpoint, and an age for an upstream connection.**
  `endpoints[].max_connections` (or `max_connections_per_endpoint`)
  bounds what is in flight to one endpoint, for the one that cannot take
  what the pool can give it: a small instance beside large ones, a
  service with a database pool of its own. Past the bound the endpoint is
  passed over rather than queued behind, because holding work for one
  endpoint while the others are idle is the opposite of balancing.

  `max_connection_age` bounds how long one upstream connection is kept,
  so a pool's traffic follows its endpoints rather than sticking to
  whichever ones existed when the connections were made. It does not
  close anything mid-exchange: closing at the age would cut a request
  that has done nothing wrong, and from inside a socket an exchange in
  progress and an idle connection are both a blocked read. The age marks
  the connection and the round trip — which does know where an exchange
  ends — closes it once that exchange is over, so it is never reused past
  its age and nothing in flight is disturbed. That end only exists for
  HTTP/1.1; an HTTP/2 or HTTP/3 connection carries many streams and is
  never between exchanges, so `h2c` and `h3` refuse the setting and an
  `https` pool warns rather than letting it quietly do nothing.

- **A Unix domain socket as an upstream endpoint**
  (`address: unix:/run/app.sock`), for the services that live beside the
  proxy rather than across a network: an application server on the same
  host, a local scanner, a sidecar. A socket is the better way to reach
  one — no port for anything else on the machine to connect to, file
  permissions deciding who may open it, and nothing routable.

  The difficulty is that a URL has a **host** and a socket has a
  **path**, and net/http keys its idle connection pool by the former. So
  an endpoint keeps three things apart: the configured spelling, for logs
  and status; the path, for the dialler; and a synthetic authority for
  the URL, derived from the path so it is stable and distinct, and ending
  in `.socket.invalid` — a name that must never resolve, so a dialler
  that somehow ignored the socket fails immediately rather than reaching
  a machine on the network. It never reaches the backend: the `Host`
  header is the client's own, as for any endpoint, so a service that
  routes on it keeps working.

  Socket and `host:port` endpoints mix in one pool, which is what a
  service moving from one to the other needs, and the balancer, weights,
  canaries, affinity, ejection and the `tcp` health check all apply
  unchanged. Three combinations are refused at load instead of failing
  later: `scheme: https` without `tls.server_name` (a synthetic
  authority is not a name a certificate can match), `h3` (HTTP/3 needs
  UDP to a host) and `discovery` (which produces `host:port` records).

- **A connection rate, per listener and per source network.** The
  process had `max_connections` and `max_connections_per_ip`, which
  bound how many connections are open at once and say nothing about
  churn — and churn is what most attacks look like. A client that
  connects, makes the server do the expensive half of a handshake and
  disconnects never holds two connections and can still spend a core.
  It is also what an accidental flood looks like: a client fleet
  restarting in lock-step.

  `connection_rate` and `connection_rate_per_source` in
  `server.limits`, or on one listener, close what arrives too fast
  immediately after accept, before a byte is read. The per source bound
  is keyed by a **network** rather than an address, because an attacker
  with a /64 of IPv6 has more addresses than any table could hold — a
  per address bound would be no bound at all, and the per address table
  would be the thing that filled up. The defaults are a /32 and a /64,
  and above /96 validation warns.

  It matters most where the handshake is dearest and happens before the
  proxy knows who is calling — an SSH key exchange, a TLS handshake, an
  RDP connection sequence — so the four bastion examples now carry one.
  Refusals are in `rate_refused_connections` and
  `xproxy_connections_rate_refused_total`, aggregated in the error log
  like the other accept refusals. A listener's own sections replace the
  process's rather than adding to them, and a rate change on reload
  rebinds no socket.

- **A session policy for the relays with no parser in the path.** A
  `kind: tcp` listener had an idle timeout and nothing else: no bound on
  how long a connection could last however active, and none on what it
  could move. Those are the only two things a relay can bound, because
  nothing in it knows what the connection is doing, so it should at
  least have both. `session_timeout`, `max_bytes_in` and `max_bytes_out`
  end a connection past their bound and count it in `tcp_bounded`, with
  the bound named in the access log's `closed` field. The connection is
  **closed** rather than quietly stopped: a relay that kept the socket
  open and stopped forwarding would look to both peers like a network
  that had gone quiet, which is the hardest failure there is to
  diagnose. `kind: udp` gained the same two byte bounds in place of its
  single `max_bytes`, so one spelling covers both relays.

- **Layer 4 health checks: `type: tcp` and `type: udp`.** A pool behind
  a `kind: tcp` or `kind: udp` listener has no request to make, so
  active checking used to mean nothing for it.

  `tcp` connects and closes. It proves something accepted and nothing
  about what, which for a protocol this proxy does not speak is usually
  all there is to know without speaking it.

  `udp` has to prove more, because a UDP socket accepts nothing: there
  is no connect to succeed, and the ICMP port unreachable a dead port
  produces may never reach the sender, may be filtered on the path, and
  says nothing at all about a process that is bound but wedged — which
  is the failure that matters, because it is the one that keeps taking
  traffic. So a `udp` check sends a question the service answers
  (`send`, or `send_hex` for the services whose smallest question is not
  text) and requires an answer, optionally one containing `expect` or
  `expect_hex`. Silence is the failure. The probe socket is connected,
  so an answer from any address but the endpoint's is dropped by the
  kernel and a third party cannot vouch for a backend.

- **`kind: udp`, a generic datagram relay.** The symmetric primitive to
  `kind: tcp`, for the services whose protocol this proxy has no parser
  for: an endpoint pool with a balancer and health checks in front of a
  UDP service, bounds on what one client can cost, an access log and
  counters, and nothing read from the payload.

  A datagram has no connection, so there is a session table keyed by the
  client's address instead: the first datagram picks an endpoint, every
  later one from that address takes the same path, and the session ends
  when it is idle, when it hits a bound, or at shutdown. The socket
  towards the endpoint is connected, so the kernel drops anything
  arriving from another address and an answer forged by a third party
  never reaches the client.

  Two properties of UDP shape the rest. **A datagram cannot be refused**
  — there is no reply that means "no", and an error sent to a source that
  did not really send anything is itself an attack on whoever owns that
  address — so everything the relay will not forward is dropped,
  counted, and written to the security log as `udp_denied` with the
  reason, which is what makes the ban ladder apply to it. **A source
  address is whatever the sender wrote**, so the session table is
  bounded per source (`max_sessions_per_ip`, default 64) as well as in
  total, and validation warns about a listener on a public address with
  neither `allow_clients` nor `rate_limit`: an open datagram relay is
  somebody else's amplifier.

  It is also the first kind with **no accept socket**. `proxy.Kind` grew
  a `Datagram` flag that tells the engine to bind only the packet socket
  and hand it to the kind, because a TCP port nothing accepts on is
  worse than no port at all: a client that connected would hang rather
  than be refused. Nothing that belongs to accepted connections applies
  to such a listener — the shared connection limiter, the inbound PROXY
  header, a `tls` section — and `proxy_protocol` on one is refused at
  load, since there is no datagram form of it.

- **The protocol's own encryption towards a client** (`kind: rdp`,
  `security: [rdp]`), for clients too old to offer TLS. The listener
  draws a 512-bit key at start -- the size the protocol carries -- puts
  it in a proprietary certificate and signs that certificate with the
  Terminal Services signing key Microsoft published in MS-RDPBCGR
  5.3.3.1.1, which is the only thing a client can check. The client's
  random arrives sealed under the listener's key, the strongest method
  the client offered is chosen at encryption level client compatible,
  and from there the client's leg is encrypted in both directions.
  - **That signature authenticates nothing**, and the documentation
    says so in those words: the private key is public, so verifying it
    proves the other end read the specification. Such a listener is
    protected by its network and `allow_clients`, not by the protocol.
    It warns at load.
  - The two legs are independent -- their own exchange, method and key
    schedule each -- so an old client can reach a desktop on TLS or on
    network level authentication, and the other way round. A listener
    that offers only `rdp` needs no `tls` section.
  - Traffic towards a legacy client waits for that client's key
    exchange rather than going out in the clear, bounded by
    `handshake_timeout`: a client that agreed to encryption cannot read
    an unencrypted packet, so sending one early ends the session rather
    than degrading it. One direction of the relay ending now unblocks
    the other, which is what keeps that wait from holding a dead
    session open.
  - New counter `rdp_legacy_clients`.

- **The protocol's own encryption towards a desktop** (`kind: rdp`,
  `upstream_security: rdp`). The cryptography was already there and
  tested; what was missing was the session. Now the desktop's security
  block is read out of the conference response, this end's random is
  sealed under the key in its certificate and sent as the security
  exchange -- in front of the first thing the client sends, which is
  where the sequence puts it -- and from there every unit bound for
  the desktop is signed and encrypted and every unit from it is
  decrypted, on both framings, with the key rolling over every 4096
  packets as the protocol requires.
  - Being *inside* that encryption is the whole point: the channel and
    device policy still applies, the second factor is still checked,
    and the recording holds the session rather than ciphertext. The
    encryption itself is worth nothing against anyone on the path --
    RC4 under MD5 and SHA-1, with a certificate nothing can check --
    and the documentation says so rather than implying otherwise. It
    is for equipment that speaks nothing else, and setting it warns at
    load so it is a downgrade somebody meant.
  - A desktop that asks for no encryption at all is served, with a
    warning naming it: a session nobody encrypts looks exactly like
    one everybody does. FIPS mode is refused rather than downgraded.
  - New counter `rdp_legacy_sessions`.

- **Second factors an operator can change while the proxy runs**, in
  the management API, the GUI and the TUI. The enrolment file was read
  once, at load, so adding somebody meant a reload and removing
  somebody meant a reload too -- and until it happened, the person was
  still enrolled while everybody believed they were not. The file is
  now the authority: every listener re-reads it when it changes on
  disk, at most once a second, and a change takes effect on the next
  connection.
  - **The socket gained `/v1/mfa`** -- the listeners that ask for a
    factor, who is enrolled on each with the parameters, the recovery
    codes left, the recent failures and the lockout -- and four audited
    changes beside it: `enrol`, `recovery`, `remove` and `unlock`. The
    engine reaches a listener's guard through an optional interface a
    kind implements, so the enrolments stay where the listener's own
    skew and lockout settings are and nothing had to move into the
    engine.
  - **A QR code of the enrolment URI** (`internal/qr`), because the
    alternative is typing a twenty-six character secret into a
    telephone. The encoder is a small one — byte mode, error
    correction level M, every version from 1 to 40 — written here
    rather than pulled in, since the symbol has to be drawn under a
    content security policy that fetches nothing and runs no library.
    The daemon draws it and the answer carries it as a PNG `data:`
    URI. A QR encoder is the kind of code that runs and is wrong, so
    the test compares 640 symbols — every version, every mask, two
    payload sizes — against an implementation that has nothing to do
    with this one, and pins the error correction to the worked example
    in ISO/IEC 18004.
  - **The GUI has an MFA page.** A viewer sees who is enrolled and who
    is locked out, which holds no secret; an operator enrols, replaces
    recovery codes, removes and unlocks. What an enrolment answers with
    -- the secret, the `otpauth://` URI, the QR code and the recovery
    codes -- is passed through as it arrived and shown once, in a panel that stays
    until it is dismissed, which is why that page is the one with no
    refresh timer: a timer would wipe it while it was still being
    written down.
  - **The TUI has an MFA screen**, the tenth, reached with `0`. It
    shows the same list; `u` unlocks somebody who guessed wrong too
    often and `x` removes their factor, each after a confirmation and
    resolved against the row the cursor is on at that moment, because
    the list refreshes underneath. Enrolling is not there: a secret and
    ten recovery codes need somewhere that can hold them, which is the
    GUI or `xproxyctl mfa enrol`.
  - Two facts about scope are on the screen rather than in a footnote,
    because both surprise: an enrolment belongs to the *file*, so
    enrolling through one listener enrols the person on every listener
    reading it; a lockout belongs to the *process* that counted the
    wrong codes, so unlocking is per listener, and per node in a
    cluster. Unlocking forgives guessing wrong without forgiving
    replay -- a code spent before the lockout is still spent.
  - Every change is audited twice when it comes through the GUI: by
    the daemon with the caller's kernel-reported credentials, and by
    the GUI with the operator's account. Neither line carries what was
    handed out, only who changed whose factor on which listener.

- **A Remote Desktop gateway** (`kind: rdp`, in xgate). The proxy
  terminates the connection sequence of MS-RDPBCGR on both legs, which
  is what makes any of the rest possible: everything worth deciding
  about an RDP session -- the security protocol, the virtual channels,
  who is connecting and with what -- is settled before a pixel moves,
  and a relay that does not sit in that sequence decides none of it.
  - **A channel policy, which is where file transfer lives.** Every
    redirection RDP has rides a virtual channel, and nothing can be
    used that was not granted, so `channels.allow` decides what a
    session can do -- defaulting to none. A refused channel is not
    removed from the list, because the desktop answers with one
    identifier per channel asked for and a client that gets back a
    different number does not recover; its *name* is replaced with one
    nothing speaks, which is the same number of bytes. The desktop
    registers a channel no software has a handler for, the identifiers
    line up, and what the client sends on it is dropped.
  - **A device policy**, which is the enable and disable for file
    uploads and for ports: `devices.allow` names drive, printer,
    serial, parallel and smartcard, and is applied to the device
    announcement, since nothing can be redirected that was not
    announced. Refusing every kind leaves a valid announcement of none
    rather than a broken channel; an announcement the gateway cannot
    read, because it arrived compressed, ends the session rather than
    passing through unfiltered.
  - **A second factor**, carried with the password after a comma --
    RDP has nowhere to ask a question -- and taken off before the
    password goes anywhere. One honest difference from the other
    gateways: the factor is checked before the *credential* reaches
    the desktop, not before the desktop is dialled, because RDP's own
    sequence requires the desktop to answer before the client sends a
    credential at all. CONFIG.md says so.
  - **Two credentials kept apart.** With `upstream_user` the desktop
    is opened with the gateway's own account and the person's stops at
    the gateway; without it, what the person typed is forwarded as it
    arrived, for estates that want their own accounts audited on the
    desktop.
  - **A session recording** of the desktop-to-client stream as
    asciicast v2, named `*.rdp.cast`, with every refused device marked
    where it happened. It is not a video, for the same reason the VNC
    recording is not.
  - **Network level authentication towards a desktop**
    (`upstream_security: nla`), which is what a current Windows install
    requires by default: CredSSP over NTLM version 2, inside the TLS
    tunnel, proving the credential an operator configured. It cannot
    carry the person's own -- the exchange happens before the person
    has sent anything, which is the point of the protocol -- so
    validation requires `upstream_user` and `upstream_password_file`.
    The exchange is bound to the tunnel it runs in, so tokens relayed
    into another connection fail and a desktop whose binding does not
    match gets no credential; extended session security and a key
    exchange are insisted on rather than fallen back from. Only the
    client half exists, in `internal/ntlm`: this proves a credential
    and never checks one, because checking would mean the gateway
    holding a password hash for everyone who connects. The key
    derivation is tested against the worked example of MS-NLMP
    section 4.2.4 and the exchange against a stand-in for the Windows
    side; it is not verified against a real desktop here, and
    CONFIG.md says so.
  - **The protocol's own encryption**, RC4 under keys from two
    randoms, has its cryptography implemented and tested in
    `internal/rdp` -- walking the certificate to its key, sealing the
    random, deriving the session keys, signing and re-keying -- but is
    not yet wired into the session: the session's updates travel on
    the fast path with encryption flags of their own, and that half is
    still to do. Setting it is refused at load rather than failing at
    the first connection. Towards a *client* it is not implemented at
    all, for a reason worth saying plainly: presenting the protocol's
    own certificate means signing it with a private key Microsoft
    published, and shipping that is a decision for whoever needs it
    rather than one to make quietly. CONFIG.md says both, and says
    that what the scheme is worth is nothing against anyone on the
    path.
  - **A client asking for network level authentication is answered
    with TLS**, which is what every remote desktop gateway does and
    the only reason a second factor can be checked at all: accepting
    NLA from a client would mean holding every person's Windows
    password. The cost -- authentication after the connection rather
    than before it, on the client's leg -- is stated in CONFIG.md
    rather than left to be discovered. The protocol's own RC4
    encryption is refused at load for now, with a message saying it is
    not implemented yet rather than failing at the first session.

- **A VNC gateway** (`kind: vnc`, in xgate), speaking RFB on both legs.
  The proxy is an RFB server to the viewer and an RFB client to the
  desktop, terminating the handshake of RFC 6143 on each -- which is
  what makes everything below possible, since RFB settles its whole
  policy surface in the first few hundred bytes and a relay that does
  not sit in that negotiation can decide none of it.
  - **Versions 3.3, 3.7 and 3.8, independently on each leg.** A 3.3
    viewer reaches a 3.8 desktop through here and the other way round.
    A version nobody defines -- Apple's 3.889, anything above 3.8 --
    is treated as the highest defined version at or below it.
  - **The security types with a published specification**: `none`,
    `vncauth`, `vencrypt` and the older anonymous `tls`, each completed
    on both legs. `security_types` is what a viewer may use, and a
    viewer that picks something outside the list is refused rather than
    obliged. The vendors' own types (RealVNC's `ra2*` and `rsa-aes*`,
    `tight`, `ultra`, `mslogon2`, `ard`, `sasl`, `md5`, `xvp`) are a
    configuration error rather than a setting that quietly does
    nothing, and `docs/CONFIG.md` says so in a table with what to do
    instead. UltraVNC's DSM plugins are a separate case again: they
    wrap the socket before RFB starts, so a VNC-aware listener cannot
    read even the version string, and the documented answer is a
    `kind: tcp` listener that relays the bytes without a recording.
  - **The two credentials are separate.** What a person proves to the
    gateway is not the desktop's password: `password_file` is what the
    gateway's own `vncauth` challenge is checked against, and
    `upstream_password_file` what it answers the desktop's with. The
    shared VNC password of a machine never has to be given to the
    people who use it. A password file anyone else can read is refused
    at load.
  - **Three ways to encrypt the leg.** VeNCrypt negotiated inside RFB
    with an `x509-*` subtype, which is what a modern viewer offers by
    itself; `tls_mode: wrap` for a socket that is TLS from the first
    byte, which is what a viewer pointed at an `stunnel` port expects;
    and `ssh`, where the gateway opens an SSH connection of its own and
    reaches the desktop through it, with the host keys pinned. The
    first two are alternatives and asking for both on one port is a
    configuration error: the first byte a client sends is either a TLS
    record or an RFB version string.
  - **A second factor**, carried the only way RFB allows. There is no
    prompt in the protocol and no terminal to draw one on, so the code
    arrives in VeNCrypt's plain credential: the username is the person
    and the password field is the code, inside the TLS tunnel. `mfa`
    therefore requires a plain subtype, which validation says at load
    and defaults fill in, and a wrong code is answered with a failed
    security result before the desktop is dialled rather than a
    connection that closes for no stated reason.
  - **`view_only`**, which drops the key, pointer and cut-text messages
    so a session is watched and not driven. It frames the client's
    stream to do it, because an RFB message is only as long as its type
    says; a message type the gateway cannot frame ends the session
    rather than breaking the promise.
  - **A session recording** of the server-to-client stream, in the same
    asciicast v2 container the other recordings use, named
    `*.rfb.cast`. It is not a video: the event data is the protocol
    stream, so replaying it needs a player that speaks RFB. That is the
    deliberate choice -- decoding at capture time would mean
    understanding every encoding a server might pick and silently
    losing whatever it did not, while a decoder written against this
    file later loses nothing.

- **TightVNC's security type 16 and Apple Remote Desktop's type 30**,
  on both legs, which with the two above covers the vendors' types
  that have a public description good enough to write against.
  - **Tight is a negotiation rather than a cipher**: a list of tunnels
    and a list of authentications, of which the two ends pick one
    each. This gateway offers no tunnels and refuses a target that
    offers only tunnels, because a tunnel is another protocol wrapped
    around this one -- a session it could neither read nor record. It
    offers no-auth and, with a `password_file`, the DES challenge.
    Tight's block after `ServerInit` is read and dropped from a
    target's leg and sent empty to a Tight client: what is advertised
    there is TightVNC's extensions, file transfer among them, and a
    gateway that cannot see inside them has no business passing them
    through. The one case where a Tight target sends no security
    result at all -- when it asks for no authentication -- is handled
    rather than waited on.
  - **ARD** is Diffie-Hellman over a prime the server chooses, MD5 of
    the shared secret as an AES-128 key, and a credential blob in ECB.
    Apple's own servers use a 512 bit prime, so the warning says what
    that is worth; in the server role this gateway generates 1024 bits
    instead. Its credential carries a name, so it carries a factor.
    Parameters that fix the shared secret -- a generator or public
    value of 1, a public value at or above the modulus, an even
    modulus, a prime shorter than Apple's own -- are refused on both
    legs rather than turned into a key.

- **RealVNC's RSA-AES, security types 129, 130 and 133**, on both legs
  of the VNC gateway. Each end sends an RSA public key, each seals a
  random under the other's, the session keys are hashed out of the two
  randoms, and everything after that travels in AES-EAX boxes with a
  counter for a nonce and the message's own length as its associated
  data.
  - **The cryptography is not guessed at.** RSA and the hashes are the
    standard library's, and EAX -- which Go does not have -- is
    implemented in `internal/eax` against the published vectors of the
    EAX paper and of NIST SP 800-38B for the CMAC underneath it, both
    run by its tests. What is reconstructed from TigerVNC's
    implementation is the **order and framing of the messages**. That
    is the failure mode to prefer: getting it wrong is a handshake
    that does not complete and a log line naming the step, not a
    session that looks encrypted and is not. Interoperability with
    RealVNC's own software is not verified here, and the load warning
    and CONFIG.md say so.
  - **`rsa-aes-ne` protects the handshake only and leaves the session
    in clear.** That is the thing about this family easiest to get
    wrong, so it has a warning of its own, the access log names the
    security type of both legs, and a test holds that the channel is
    left after the security result and not before.
  - **Each end is identified by a key**, so the listener needs one
    (`rsa_key_file`, PEM, at least 2048 bits, not readable by anyone
    else) and a target's is **pinned** (`upstream_rsa_fingerprint`,
    required): nothing else authenticates the far end of that
    exchange, and unlike a viewer there is nobody at a proxy to show a
    fingerprint to and ask. The gateway logs the key a target offered,
    which is where the setting is copied from.
  - The transcript hash each end sends is over both public keys in its
    own order, so a third party that swapped them is refused and one
    end's hash cannot be replayed as the other's. A peer key outside
    2048 to 8192 bits, one whose stated length disagrees with the
    modulus it carries, and an even exponent are all refused before any
    arithmetic is done on them.

- **MS-Logon II, UltraVNC's security type 113**, on both legs of the
  VNC gateway (`security_types: [mslogon2]`, `upstream_security:
  mslogon2`). It is reimplemented from the shape of UltraVNC's own
  source and the public reimplementations that agree with it, since
  there is no specification: the load warning and `docs/CONFIG.md`
  both say that interoperability with a real UltraVNC server is not
  verified here, and say what the type is worth -- Diffie-Hellman over
  64 bits with the shared secret as a DES key, which protects the
  Windows credential inside it against nobody. It is here because the
  desktops exist, and reaching them through a gateway that records the
  session and holds the policy beats reaching them directly. Two
  things follow from its credential carrying a name, which most of RFB
  does not: it can carry a second factor with no certificate involved,
  and towards a target it needs `upstream_user` as well as
  `upstream_password_file`, refused at load rather than at the first
  session. Degenerate Diffie-Hellman parameters -- the ones that fix
  the shared secret without breaking anything -- are refused on both
  legs.

- **A telnet gateway** (`kind: telnet`, in xgate), for the equipment
  that speaks nothing else. The proxy is a telnet server to the client
  and a telnet client to the target, reading the NVT protocol of RFC
  854 in both directions — which it has to, because telnet's options
  are commands escaped into the byte stream, so a proxy that does not
  parse them cannot tell a window size from the characters a person
  typed.
  - **An option policy.** A session may negotiate the options named in
    `allow_options`, defaulting to what an interactive session needs
    and nothing else. An option the proxy has no name for is always
    refused, whatever the list says. A refusal is answered to the side
    that asked, because one the asker never hears is a negotiation that
    repeats forever, and it writes a log line and a mark in the
    recording so an operator asked why a terminal behaves oddly can see
    that the proxy is why. Validation warns about the options that
    carry something to the target rather than describing the terminal:
    `environ` and `new-environ` hand it variables, `x-display` names a
    connection back out of the estate, `encryption` would make the
    session one the proxy can no longer record.
  - **A session recording**, in the same asciicast v2 the bastion
    writes, sized from `naws` and resized when the window is.
  - **A second factor before the target is dialled.** Telnet has no
    authentication for a proxy to read, so this is a prompt the proxy
    writes into the stream and an answer it reads back: a login name,
    then a code that is not echoed. A client that cannot answer never
    reaches the equipment. The name is only what the enrolment is
    looked up by; the target's own login happens afterwards, untouched.
  - Telnet carries all of this in clear, so validation warns every time
    the listener has no `tls` section. The listener exists because the
    equipment does, not because telnet is acceptable.

- **The ftp relay records, scans and can ask for a second factor.**
  Three sections, each the same shape as its equivalent elsewhere, so
  an operator who has configured the bastion has configured this:
  - `ftp.recording` writes the control channel -- every command, every
    reply, a mark per transfer -- as asciicast v2, replayable in the
    same player as an ssh session. `PASS` and `ACCT` arguments are
    redacted and the transferred bytes stay out: a recording an
    operator cannot safely keep is one that gets turned off, and a copy
    of every file that crossed the proxy is a second copy of the data
    to look after. The login exchange is held in memory until the
    login succeeds and then written into the file, so the file names
    the person and a connection that never authenticates writes none.
  - `ftp.icap` hands `STOR`, `STOU` and `APPE` to a scanner through
    REQMOD, and `RETR` through RESPMOD where `downloads: true`. The
    file is wrapped in the HTTP message a scanner expects, with the
    `ftp://` URL of the real file so the scanner's log names something
    findable. The transfer is held until the verdict arrives, because
    one that comes after the bytes is not a control; the service's own
    `max_body`, `body_limit_action` and `fail` apply as they do to an
    HTTP body, and both of the ways a file can go unscanned say so in
    the log. Listings are not sent: they are not files.
  - `ftp.mfa` asks for a code after the password, by the two routes the
    protocol allows -- as the argument of `ACCT` after a `332`, or
    appended to the password after a comma for clients that have no
    `ACCT` of their own. Until it is verified the session is not logged
    in. The code never reaches the target.
- **The sftp bastion scans what is written.** `sftp.icap` names a
  service, and a scanned upload is held rather than forwarded: SFTP has
  no whole-file transfer to hand a scanner — a file is an `open`, a run
  of `write`s at offsets and a `close` — so the proxy answers each
  write itself, assembles the file, asks the service at the close, and
  only then replays the writes to the server in the order the client
  made them. A file the scanner refuses never reaches the server; the
  close is answered with a failure instead. The cost is written down
  rather than discovered: the file is in memory until the close under
  the service's `max_body`, the write statuses a client sees are the
  proxy's rather than the server's, and the `open` that was already
  forwarded can leave an empty file behind. Downloads are refused as a
  configuration error, not silently ignored: a download in SFTP is a
  run of reads with no packet that means the file is finished, so there
  is no point to scan at.
- **ICAP services belong to the engine rather than to the HTTP data
  plane.** The kinds that hand a file to a scanner are not all in the
  daemon that has a plane -- ftp is in xrelay, sftp in xgate -- so one
  `icap.services` list now serves whichever daemon reads it, through
  `Host.ICAPService`. `/v1/icap` reports them in every daemon. A
  section naming a service that does not exist is refused at load
  rather than at the first file it tries to scan.

### Changed (1.4)

- **A DNS listener no longer forwards a client's EDNS Client Subnet
  option** (`dns.ecs`, default `strip`). The option exists for a
  recursive resolver telling a content network which network a query is
  really for, and this listener is not one: it forwards to a resolver
  that adds its own option describing this proxy, which is the correct
  thing for that resolver to describe. Forwarding the client's instead
  broke the cache, whose key here is the question and nothing else -- so
  an answer tailored to one client's subnet was stored for every client
  of the listener, and a client that could choose the subnet could
  choose what the next thousand were told, with no spoofing and no race
  in it. The rest of the OPT record is kept: a cookie or padding the
  client sent still goes upstream, because dropping the record wholesale
  would forward a different query than the one that was asked.
  `ecs: forward` restores the previous behaviour for a listener whose
  clients are one network, and `xproxy_dns_ecs_stripped_total` counts
  what was removed. With `dnssec` on the option was already gone, since
  validation replaces the OPT record with one of its own.

- **Session recording is a package of its own** (`internal/sessionrec`),
  lifted out of the ssh bastion: the policy, the file, the byte bound,
  the prune and the truncation mark are the same wherever a session is
  recorded, and only what a session is made of differs. `ssh` runs on
  it unchanged; `ftp`, `telnet` and the graphical gates use it too.
  `config.SSHRecording` is `config.SessionRecording` accordingly — the
  `recording:` key and every field under it are untouched.

### Fixed (1.4)

- **A layer 4 listener deadlocked against a server that speaks first.**
  A `kind: tcp` listener peeks for a ClientHello before it dials, and
  plenty of what such a listener carries is server-first: SSH sends its
  banner before the client says anything, and so do SMTP, FTP, MySQL and
  PostgreSQL. The client waited for a greeting the proxy had not gone to
  fetch while the proxy waited for a hello the client would never send,
  until the peek's ten second bound turned the whole thing into a read
  error. Silence is an answer now: a connection that has sent nothing
  after about a second is relayed on the default route with nothing
  peeked. A connection that has started sending still gets the full
  bound, because a ClientHello split across packets is ordinary.

- **The idle timeout was a property of one direction, not of the
  connection.** Each direction carried its own read deadline, so a
  connection whose server side speaks rarely while the client is busy --
  a database session, a mail session holding IDLE, an interactive
  session carried at layer 4 -- had its return path half closed while it
  was working. The busy side went on sending into a path with nothing
  coming back and nothing telling it, which is worse than a close. A
  read deadline that expires while the other direction has been active
  is no longer an idle connection. Both found while adding the bounds
  above, and both in `internal/relay`, so every kind that relays bytes
  gets the fix.

- **Two sessions for one person in the same millisecond lost one
  recording.** The file name carries the time only to the millisecond
  and the person, and the file is created with `O_EXCL`, so the second
  session's `open` failed and it ran unrecorded — on a busy bastion,
  which is exactly when the recording is wanted. A suffix is added for
  as long as the name is taken. Found by testing the recorder on its
  own once it was a package; it had been in the ssh recorder since
  recording landed.

### Fixed (1.4, tests)

- **An eleventh and a twelfth, both the same eventual consistency
  again.** `TestUpstreamQueue` asserted the pool's final state the
  instant the last body arrived, and the concurrency slot is released by
  the proxy after the response has gone out, so the client can hold its
  status code before the pool shows the request finished. (This is the
  same test as the eighth below, on a different assertion: the earlier
  fix waited for the queue to fill and then still asserted the emptying
  immediately.) `TestAcceptRateWrapClosesRefusedConnections`, new with
  the connection rate, read the refusal count as soon as its dials
  returned, and the gate refuses on the accept loop's own schedule. Both
  wait for the state now.

- **A ninth and a tenth, of the shape that fails as the wrong test.**
  `TestForwardProxy` (`internal/kinds/forward`) has a subtest about a
  two-tunnel bound, which can only mean anything once the earlier
  subtests' tunnels have wound down; it waited two seconds for that and
  then carried on regardless. Under the whole suite's load the bound
  was sometimes already spent, so the subtest's own first tunnel was
  refused and the failure named the wrong thing. `TestMirror`
  (`internal/kinds/http`) waited a second for a counter that lands on
  another goroutine. Both now wait for the condition, with a message
  saying what was waited for.

- **An eighth, which slept fifty milliseconds and hoped.**
  `TestUpstreamQueue` (`internal/kinds/http`) started a second request,
  slept, and asserted that the pool showed one request waiting. Two
  ways to lose that under a loaded machine: the goroutine had not yet
  reached the queue, or it had and the two hundred millisecond queue
  timeout had already taken it out again. It now waits for the state it
  asserts, and the queue timeout is a second, so the window in which
  that state exists is wide rather than a guess.
- **A seventh, which tampered with a cookie into itself.** `TestFlow`
  checks that a changed challenge cookie is refused, and changed it by
  replacing its last two base64 characters with "AA" -- so a cookie
  that already ended that way was "tampered with" into exactly itself
  and was, correctly, accepted. About one run in four thousand, which
  is how often it was seen. It now changes the first character, to one
  it was not already, and asserts the value actually moved: base64's
  final character carries padding bits, so several spellings of it
  decode to the same bytes and a tamper there is sometimes no tamper
  at all.

- **A sixth flaky test, of a different shape: `TestExport` set the
  batch size and the flush interval against each other.** The trace
  exporter flushes when the batch is full *or* when the interval
  fires, and the test asked for a batch of two spans with a 50ms
  interval, then asserted that exactly one push happened carrying
  both. The two spans are finished microseconds apart, so almost
  always they filled the batch first -- but a ticker that fired
  between them pushed the first span alone, and the assertion on the
  push count failed. It now sets an interval long enough that the
  batch is the only thing that flushes, which is what the test is
  about; the interval path was never what it was checking, and the
  flush on `Stop` it also exercises is unaffected.

- **Five tests raced the goroutine that records what they assert on.**
  `CountStatus` is called from `logAccess`, which runs once the response
  body has gone out, so a client can have its whole response before the
  counter moves; the capture file is likewise written after the exchange
  is counted. `TestWriteMetrics` and
  `TestCaptureWritesTheDecryptedExchange` read both the instant the
  request returned, won that race on an idle machine and lost it under
  load — one run in six with the suite contending for four cores. They
  wait for the value now, through a shared `eventually` helper.
  `TestRunStartsReloadsAndStops` was the same shape a level up: `apply`
  reloads the server and then records what it applied, so a reload that
  has taken effect is not yet a reload that is in the history, and the
  test read the history the moment the generation moved.
  `TestAgentAppliesAndReports` was the fourth: the fleet agent writes
  `Applied` inside `apply` and the loop counts the failure once `apply`
  has returned the error, so a status carrying the failed digest is not
  yet a status with the failure counted, and the test waited for the
  first and asserted the second. `TestURLSpec` was the fifth: `install`
  counts a reload and `fetch` writes the cache file after it, so a
  refresh that has been counted has not yet reached the disk. The
  behaviour all five were testing is correct: metrics, captures, the
  history, the failure count and the cache are written after the thing
  they describe has happened, by design.

### Packaging (1.4)

- **The RPM ships all three daemons.** The spec predates the split and
  packaged only `xproxy`, so the packaged path had no way to run a
  bastion or a relay at all: `xproxy-xgate` and `xproxy-xrelay` are new
  subpackages, each with its binary, unit and socket, logrotate entry,
  manual page, example configuration and its own log and state
  directories. Both depend on the base package, which owns `/etc/xproxy`
  and the users. The two `tmpfiles.d` entries the source install has
  always shipped are packaged too — without them a packaged host has
  neither the configuration directory the three share nor the cluster
  socket directory.
- `deploy/config/xgate.yaml` and `deploy/config/xrelay.yaml` are new:
  the units have always named those paths, and nothing created them.
  `make install` lays them down beside `xproxy.yaml`.

### Fixed (1.4)

Three regressions the split introduced, found by re-reading the carve
against what it moved. Each is what a move costs when a guard, an
interface or an owner is left behind rather than carried across.

- **A forward listener logged an error on every clean stop and every
  reload.** A listener is stopped by closing its front and then
  shutting the HTTP server down, so `Serve` ends with `net.ErrClosed`
  from the accept or with `http.ErrServerClosed` from the shutdown,
  whichever goroutine wins. The engine's own `serve()` ignored both;
  the forward proxy kept only the second when it became a kind of its
  own. An operator who sees ERROR on every reload learns to ignore the
  error log, which is the real damage.

- **Open CONNECT tunnels were counted as open QUIC flows.** The forward
  instance implemented `proxy.FlowCounter` with its tunnel counter, and
  the engine folds every `FlowCounter` into `quic_flows_open` — which
  before the carve counted a `tcp` listener's QUIC flows and nothing
  else. `xproxy_quic_flows_open` therefore reported tunnels that
  `xproxy_forward_tunnels_open` was already reporting correctly, so a
  dashboard or alert keyed on QUIC flows fired on forward traffic.

- **A failure late in `New` left the data plane running.** The engine's
  runtime holds only the upstream pools since the data plane became a
  kind; the plane holds the JWKS refreshers, the ICAP pools and the
  filters. `New` commits the plane before it builds ACME and the
  cluster node, and those error paths released only the engine runtime,
  as they could when one runtime held everything. They return no
  `Server`, so nothing would ever have called `Shutdown`: a
  misconfigured ACME section or cluster certificate left the
  refreshers running for the life of the process.

- **The three daemons took `/etc/xproxy` from each other on every
  start.** All three units declared `ConfigurationDirectory=xproxy`,
  which systemd creates and chowns to the unit's own `User=` and
  `Group=` every time the unit starts. Three units doing that in turn
  is three daemons taking the shared configuration directory from one
  another, and at `0750` the two that did not start last cannot read
  their configuration at all — so the estate worked until the second
  daemon was restarted, and then did not. The directory is created by
  `tmpfiles.d` now, `0750 root:xproxy-config`, with the three daemons
  and the GUI in that group; it grants that directory and nothing else,
  as `xproxy-cluster` grants the cluster sockets and nothing else. The
  units keep `ReadOnlyPaths=/etc/xproxy`, so the sandbox is unchanged.

- **A command line one or two octets over the bound swallowed the next
  command.** The reader's buffer is the bound plus two, so a line that
  overshoots by one or two arrives whole rather than filling the buffer.
  The code then skipped to the next line ending anyway — which was
  already behind it — and ate the following command: the client was
  answered 500 for the line it did send and nothing at all for the next
  one. Found while writing the same reader for FTP, fixed in both, with
  a test that pins the two lengths where it happened.

- **An SSH command that ran could be reported to the client as EOF.**
  The bastion closed a channel as soon as the target's side was drained,
  and the target can finish a command and close its channel while the
  reply to the `exec` that started it is still on its way back. Closing
  inside that window takes the reply with it, and a client waiting for
  one is told the channel ended: `ssh host uptime` failing with EOF for
  a command that had in fact run, its output produced and its exit
  status relayed. It reproduced in about one exec in a hundred under
  load, and every time when sessions were opened back to back on one
  connection. A channel now waits for any request that is mid-answer
  before it closes, which is the same invariant the exit-status path
  already had. The regression test runs the exchange four hundred times.

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

- **The HTTP data plane is a listener kind too, so the bastion and the
  relay stop carrying it.** `http` and `forward` now live in
  `internal/kinds/`, and only `xproxy` links them. `internal/proxy` is
  the engine that is left: sockets, TLS, the reload, the counters, the
  cluster and the management surface, and no protocol at all. Stripped,
  `xgate` goes from 26.2 MiB to 15.3 and `xrelay` from 25.9 to 14.9,
  against `xproxy`'s 28.4 — the bastion carries no route compiler, no
  Coraza and no rule sets, no load shedder, no challenge or CAPTCHA
  engine, no gRPC, WebSocket or WebTransport inspection, no response
  cache and no HTTP/3.

  Two things had to be answered first, and they are the interesting
  part.

  Every `http` listener of a process shares one compiled generation —
  one route table, one WAF engine, one cache, one set of rate limiters
  — which a per-listener `Instance` has nowhere to keep. So the kind
  also registers a `Plane`, built once before any listener binds and
  handed to each listener in `Setup.Plane`. A reload is two phases:
  `Prepare` compiles everything that can fail against the pools the
  engine built for the same generation, the engine then binds its
  listeners, and only when every one of them is bound does `commit`
  install the new generation under the same lock as the listener swap.
  Any failure on the way calls `discard`, and the old configuration is
  still running, untouched. The engine owns the upstream pools but
  cannot see the requests still on them, so `Generation.Retire` hands
  the superseded ones back when the plane's last request on them ends
  — a pool closed under a long upload or an SSE stream cuts it.

  The management API is served by all three daemons, so the plane's
  status had to cross the boundary without dragging the plane with it.
  `PlaneStatus` is an interface the engine's own `WAF`, `Filters`,
  `Quotas` and the rest delegate to; where no plane is linked they
  answer zero values, so `xproxyctl waf` against the bastion reports a
  WAF that is not enabled — which is true — instead of failing in a way
  an operator has to look up. The types are the data plane's own,
  except the WAF report: that one moved to the leaf package
  `internal/waf/wafstatus` and is aliased back into `internal/waf`, so
  nothing that reads it changed and Coraza stays out of the two daemons
  that run no WAF.

  Nothing an operator sees changes. The configuration, the management
  API and its JSON, the metric families and the counters are the same;
  `kind: http` was already the default and is now a registered kind
  like any other, refused by name in a daemon that did not link it
  rather than being what every unknown kind fell through to.

- **The architecture is written down.** `docs/ARCHITECTURE.md` gains a
  section on the split — the roles, the kind registry, the `Host`
  interface, why the roster is static rather than derived from what was
  linked, the refusal, and what the split buys — plus
  sections on the gate and relay kinds, which had never had one.
  `AMR-048` is the decision record: why one repository and several
  binaries rather than a shared library or a bigger sandbox. The
  roadmap has a 1.4 section, and `docs/TESTS.md` names the three tests
  that hold the split together.

- **A cluster over Unix sockets, for the daemons of one machine.** The
  three daemons of the split need to share a ban list: an address the
  bastion refuses at the SSH port should be refused at the edge too.
  Doing that over the existing cluster meant issuing three certificates
  from the estate's cluster CA to three processes on one host, and
  rotating them, for a conversation that never leaves the machine.

  `cluster.listen` and `cluster.peers` now take `unix:/path` as well as
  `host:port`. On a Unix socket there is no TLS and none is wanted: the
  peers are processes this kernel can name. What admits one is the
  socket's own permissions — `/run/xproxy-cluster`, created `0770
  root:xproxy-cluster` by a shipped `tmpfiles.d` entry, with the three
  daemons in that group — and, second, `cluster.local.allow_uids`, read
  from the connected socket with `SO_PEERCRED` rather than announced, so
  a peer cannot talk its way past it. A local peer is recorded under
  that user id (`uid:991`), never under the node id it sent, which is
  the same rule `bind_node_id` enforces with a certificate.

  A cluster is one transport or the other: `listen` and every peer must
  be all sockets or all addresses. A node listening on a socket and
  dialling a host would be reachable by its siblings and not by the
  peers it dials, which is half a cluster that looks like a whole one.

  `examples/estate/` is the shape: three daemon files, one shared
  include, one local cluster, `share_rate_limits: false` because the
  three serve different protocols on different ports.

  Two things fell out of it. Binding a listening Unix socket is now one
  implementation, `internal/unixsock`, used by both the management
  socket and this one: refuse a path something still answers on, clear
  one a killed process left, create under a umask that permits nothing
  beyond the owner and widen afterwards so the socket never exists more
  open than it will end up. And a path that is not a socket is now
  reported and left alone rather than deleted — the old management
  socket code would happily remove a regular file at the configured
  path, so a typo in `management.socket` pointing at a key file deleted
  the key.

- **Three daemons instead of one: `xproxy`, `xgate` and `xrelay`.** A
  proxy that terminates ten protocols is a proxy that links ten
  protocol implementations into one address space, and a flaw in any
  one of them is a flaw in front of all of them. The binary is now
  split by who is on the other end of the socket:

  | Daemon | Faces | Listener kinds |
  |--------|-------|----------------|
  | `xproxy` | the open internet | `http`, `forward`, `tcp`, `dns` |
  | `xgate` | people | `ssh` |
  | `xrelay` | machines | `smtp`, `mqtt`, `ftp`, `syslog` |

  One repository, one module, one version and one configuration
  format; three programs, three users, three systemd units, three
  sandboxes. A host that is not a bastion does not have the SSH and
  SFTP implementation on it at all, rather than having it present and
  unconfigured.

  A listener kind is now something a binary chooses to link. Each kind
  lives in its own package under `internal/kinds/` and registers itself
  from `init`; the engine reaches it through a five-method `Host`
  interface (logs, counters, bans, upstream pools, limits) and never
  names a kind. `internal/listener` holds a static roster of every kind
  and its owner — static rather than derived from what was linked, so a
  daemon can tell "not mine" from "not a kind at all" and a shared
  configuration loads everywhere.

  Every daemon validates the whole file, including the kinds its
  siblings serve, and binds only its own, naming the rest in the log.
  A listener whose kind this binary did not link is refused by name,
  with the daemon that does serve it — it used to fall through to the
  HTTP data plane and answer the wrong protocol on the right port,
  which is the failure this split exists to prevent, and
  `TestUnlinkedKindRefused` holds it for every kind in the roster.

  Each daemon reads a file of its own (`/etc/xproxy/xproxy.yaml`,
  `xgate.yaml`, `xrelay.yaml`), because `management.socket`,
  `metrics.listen` and `logging.directory` each name something only one
  process can own; what the estate shares goes in `includes` all three
  pull in. `xproxyctl -socket` picks which daemon to talk to.

  `http` and `forward` followed the others into kinds of their own (see
  the entry above), which is what makes `xgate` and `xrelay` small.

- **DNS tunnelling and exfiltration detection
  (`dns.tunnel_detection`).** A network can block every outbound port
  and still leak, because the resolver is the one thing every host may
  talk to. iodine, dnscat2 and DNSExfiltrator put the payload in the
  query name and take the answer back in a TXT record, and the domain
  is delegated to the other end, so the query reaches them whatever
  `upstreams` says: blocking the upstream does nothing, and a block
  list only helps if somebody already knew the name.

  What gives it away is the shape of one client's traffic under one
  registered domain: names carrying more information per character than
  words do, hundreds of distinct subdomains where a service has a
  handful, answers that are mostly TXT, a high rate of NXDOMAIN, and
  the bytes those names carry. All five are measured per client per
  domain over a window, and `min_signals` (default 2) says how many
  have to agree.

  That setting is the whole design. Each signal alone has honest
  traffic behind it — a content delivery network's hostnames really are
  random, a reputation service really does encode a hash into a name
  and answer TXT, a laptop waking up really does produce a burst of
  NXDOMAIN — so a detector that fires on one is a false positive
  generator. `min_signals: 1` is allowed and warns. The detection
  records which signals fired rather than a score, because a number
  nobody can decompose is a number nobody can argue with.

  Two things keep the signals from being one signal counted twice. The
  payload total counts each name once per window: asking for the same
  long name again carries no second copy of anything, and counting it
  would turn any client polling a long name into an exfiltration of
  megabytes. And entropy is measured per label with the longest
  deciding, because a tunnel hides its payload behind an ordinary
  looking prefix as often as not and an average over the whole name
  would let the prefix hide it.

  Queries are grouped by the name somebody registered, so a thousand
  subdomains of one tunnel domain count together. Every answered query
  is measured whatever answered it — cache, refusal, upstream failure
  — because a detector that only saw what reached an upstream is one a
  client could hide from by being noisy. `allow_domains` names the
  services that legitimately look exactly like this. The table is
  keyed on a client and a domain, both chosen by whoever sends the
  queries, so `max_tracked` is not a tuning knob but the thing that
  stops the detector being the denial of service it exists to catch;
  past it, queries go unmeasured and are counted as such rather than
  evicting a detection in progress.

  The five signals that can be switched off take a pointer, so a `0` an
  operator wrote means off rather than being mistaken for an absent key
  and given its default back — and a policy that switches signals off
  while asking for more agreement than it has left is refused at load
  instead of silently never firing. `action` is `log` by default;
  `block` answers NXDOMAIN for the whole registered domain for that
  client until the cooldown ends, and warns. `dns_tunnel` is a ban
  reason, which is usually the better enforcement: a detection is a
  strong enough signal to act on the client rather than the name.
  `examples/blocklists/dns-tunnel.yaml`.

- **TLS interception on the forward proxy
  (`forward.intercept`).** A CONNECT tunnel is opaque by design: the
  proxy knew a name, a port and a byte count, so the destination policy
  was the only policy it could apply. Every rule an estate actually has
  — this file must not leave, that binary must not arrive — is written
  against bytes, and the bytes were inside TLS. The proxy now answers
  the client's handshake with a certificate it signs itself, opens its
  own TLS connection to the destination, and relays the plaintext
  between the two, where the YARA rules and everything else that reads
  bytes can see it in both directions.

  This is the one feature here that makes a proxy less safe if it is
  built carelessly, because it replaces a connection the client
  verified end to end with two connections the client cannot see past.
  Three things follow, and none of them is optional.

  The destination is dialled and verified first, and only then is a
  certificate forged for it. A client never sees a trusted certificate
  for a server whose own certificate did not verify — it sees the
  handshake fail, which is what it would have seen with no proxy in the
  way. A proxy that gets this backwards takes the padlock away from
  every client behind it and leaves the picture of one.
  `verify_upstream: false` exists as a key so that turning it off is a
  decision somebody wrote down, and it warns at validation.

  The signing key can impersonate every site to every client that
  trusts the CA, so it is refused — at `xproxy check` and again at
  startup — if anybody but its owner can read it. The CA itself has to
  be a CA, has to carry `keyCertSign`, and has to not have expired.

  And some traffic must not be read at all, whatever the estate's
  policy says: banking, health, anything carrying somebody's own
  credentials. `bypass_hosts` is where that is written and it is
  consulted before anything is decrypted, because a rule another rule
  can overtake is not the rule you wanted.

  Two things are refused rather than guessed at. A tunnel whose first
  bytes are not a ClientHello is spliced through untouched — CONNECT
  carries SSH and database protocols too, and answering a handshake to
  one of those breaks it for nothing. And a handshake whose server name
  disagrees with the host in the CONNECT is closed and counted as a ban
  reason: a tunnel opened to one name and a handshake for another is
  somebody reaching a destination the policy checked against a
  different one. Reading that name meant reading the whole ClientHello
  record rather than its first few bytes, which is where the extension
  lives.

  The issued certificate carries the real certificate's names — SANs,
  IP addresses, common name — so a client pinning a name still works
  and one pinning a key still fails, as it should; the bounded cache is
  keyed on the destination's real certificate, so a rotation upstream
  produces a fresh forgery rather than a stale one; and `alpn` defaults
  to `http/1.1` alone, because a stream the proxy relays is one it has
  to be able to read. `forward_intercepted`,
  `forward_intercept_refused`, `forward_intercept_passed` and
  `forward_intercept_bytes` count it, with a `forward_intercept` access
  line per connection. `examples/forward/intercept.yaml`.

- **Authorisation, as one policy rather than one per filter (`kind:
  authz`).** Every authenticating filter here answered "who":
  `basic_auth`, `ldap_auth`, `api_key`, `oidc`, the JWT filter, client
  certificates. None of them answered "what may they do", so each had
  grown its own small allow list — required scopes on the key, a
  required group on the directory bind, required claims on the session.
  An allow list per filter is a policy nobody can read in one place,
  and the one nobody reads is the one with the hole in it.

  The identity a request carries now holds more than a name. Filters
  record what they verified — the directory's groups, the key's scopes,
  the token's claims — and `authz` decides on them: subjects, groups,
  scopes, claims, which filter verified the identity, the method, the
  path and the client network, with negative forms for "everybody but".
  Default deny, first match wins, and the decision is recorded as
  `authz_rule` on the access line, which is the only way to tell a
  policy that allowed from one that never matched.

  It decides nothing on its own authority: every value comes from a
  filter that verified it, so a header a client sent cannot reach a
  rule. That also means it must run after those filters, which
  `require_authenticated` makes obvious rather than subtle — with
  nothing verified there is nothing to decide about, and the
  alternative is deciding on what a client supplied.

  Two shapes are deliberate and worth knowing before writing rules:
  scopes are all-of and groups are any-of, because that is what each
  means in practice; and a rule with no selectors matches everything,
  which is a legitimate backstop as a deny and fails the load as an
  allow — `default: allow` is where that belongs, out loud.

  A refusal tells the client nothing about why. Which rule, which group
  it would have needed and whether the path exists are all things a
  prober would like to know.

  `ldap_auth` also stops throwing away what it read: the group
  attribute is fetched whenever `group_attr` is set rather than only
  when `require_group` is, and the groups are cached with the
  authentication answer rather than fetched again on a hit — a cache
  that remembers the yes and forgets what it was based on is a cache
  that quietly widens a policy.

- **gRPC message inspection (`kind: grpc_guard`).** Routing gRPC by its
  path read the envelope and nothing else. The messages are
  length-prefixed frames of protobuf inside the body, so the proxy
  could not say how large one message was — only how large the whole
  body was, which is a different number on a streaming call — could not
  notice a stream that stopped in the middle of a frame, and could not
  see a message nested a thousand deep. That last one costs the
  backend's parser far more than it costs the sender to write.

  The filter reads the framing and walks the protobuf, bounding one
  message (`max_message_bytes`, defaulting to what grpc-go defaults its
  receive limit to, so it is the number the backend already lives
  with), the messages in a request (`max_messages`), the nesting
  (`max_depth`) and the fields at every level together (`max_fields`).
  `deny_patterns` run over the strings it finds.

  No schema is used, and that is the design rather than a shortcut: a
  schema has to be kept in step with the service, and a check that is
  only as current as its schema is a check that quietly stops applying
  the week somebody adds a field. The protobuf wire format carries the
  field number and the wire type, which is enough for every bound
  above.

  A length-delimited field is a nested message or a string and there is
  no way to be certain which without a schema. It is tried as a message
  first, because a nested message read as a string is a subtree the
  depth and field bounds never see, and the bounds are the part that
  matters.

  `deny_patterns` with `allow_compressed: true` fails the load rather
  than running: a compressed message is bytes this filter does not
  decompress, so the patterns would not run over it, and saying so
  beats finding out. A compressed message that is allowed is passed
  without being walked, because there is nothing honest to say about
  bytes nobody decompressed.

  The access line carries `grpc_messages`, `grpc_depth` and
  `grpc_fields`, so `action: log` for a day answers what the bounds
  should be instead of leaving them to be guessed at. Refusals are gRPC
  statuses, and a content refusal names the field path it matched at.

  One bug was written and caught before it shipped, which is worth
  recording because it is the shape these parsers fail in: the length
  of a protobuf field is a varint and can encode a number larger than a
  signed integer holds. Compared as a signed integer it goes negative,
  the bound check passes, and the slice that follows panics. Every
  length in a message is a client's, so that is a crash per request
  from a body anybody can write. Lengths are compared unsigned, against
  what is actually left, and a test pins the two values that did it.

- **A syslog relay that reads what it forwards (`kind: syslog`).** A
  relay that forwards syslog without reading it is a pipe. The reason to
  read it is that almost every field is written by the sender and
  believed by the collector: the host name, the facility, the severity,
  the time. A message claiming to be `auth.emerg` from another machine
  costs nothing to send.

  And a message whose text carries a newline becomes **two** records in
  any collector that frames on newlines, the second one saying whatever
  the sender wanted a record to say, with a priority of its own. So
  every message is parsed and every message is re-emitted as RFC 5424 in
  one framing, whatever arrived: a newline in the text becomes a visible
  symbol, a line ending in a structured data value is escaped, and a
  field that cannot appear in a header is replaced. One dialect out is
  what makes the record a collector stores the record the relay decided
  about.

  `hostname` is the other half of that. `keep` takes the sender's word,
  which nothing checks and which warns; `observed` replaces the field
  with the address the message arrived from; `annotate`, the default,
  keeps both and states which is which, because the sender's name is
  often the useful one and is never the true one.

  The rest is what a relay in front of a SIEM needs: `allow_facilities`,
  `deny_facilities` and `min_severity`; `allow_senders`, which on UDP is
  the only authentication there is and warns when empty; `deny_patterns`
  that drop a record and `redact` rules that take part of one out and
  record that they did; a per-sender `rate_limit`, because a log flood
  is a denial of service on the collector and a way to push older
  records out of whatever window it keeps; and a bounded `queue` that
  drops and counts rather than holding every sender behind one slow
  collector.

  Both transports on one address: TCP with either RFC 6587 framing, UDP
  one datagram per message (RFC 5426), TLS as RFC 5425 defines it, and
  octet counting towards the collector by default because it is the one
  framing a message's own text cannot be mistaken for.

  The two ends are configured separately, which makes this a **secure
  upgrade** for everything that cannot be taught TLS: `tls_mode: none`
  with `upstream_tls_mode: implicit` takes clear syslog over UDP from a
  switch, a printer or a twenty-year-old application and puts it on the
  wire as RFC 5425. The sender never changes. It does not make the
  sender trustworthy — between the device and the port the records are
  still in clear and still forgeable — which is what `allow_senders`
  and `hostname: observed` are for, and what the documentation says
  beside it.

  `internal/syslog` parses both formats onto one shape — a relay with
  two internal shapes is a relay with two sets of rules — and refuses
  what it cannot re-emit honestly. A message over the bound on a
  delimited stream is dropped and the reader resyncs to the next line
  ending; on a counted stream it ends the connection, because refusing
  to read the octets a frame declared leaves the reader at an offset
  nobody knows.

- **An FTP proxy that is actually in the middle (`kind: ftp`).** FTP is
  two connections, and the second one is the whole problem. Every
  transfer happens on a data connection whose address one side announces
  to the other inside a reply, so a proxy that forwards that reply has
  told the client to go round it: the file travels with nothing in the
  middle, and the control connection it did read is a list of
  instructions for a transfer it never saw. This listener rewrites the
  address to its own, listens on one side and dials the other, and is
  one end of both connections.

  Only the port the target announced is used. The proxy dials the host
  its control connection is already talking to, so a target answering
  with an address of its choosing cannot send the proxy somewhere else.
  And only the side that arranged a connection may use it: a passive
  connection has to come from the client's own address, an active one
  from the target's.

  **`PORT` and `EPRT` are off by default.** They ask the server to
  connect back to an address the client names, which makes it a port
  scanner and a relay for anyone who can log in — the bounce attack of
  CERT CA-1997-27, which is twenty-eight years old and still works
  wherever somebody implemented the RFC and stopped there. With
  `allow_active: true` the announced address must be the client's own
  and the port unprivileged.

  The policy is the vocabulary the sftp policy already had, because the
  questions are the same: `commands` (bounded by what the proxy can
  read the effect of — a verb whose effect it cannot name is a verb it
  cannot hold to a policy, so `SITE EXEC` is not relayable at all),
  `read_only`, `allow_paths` and `deny_paths` resolved against the
  working directory the proxy follows and able to name `{user}`,
  extension lists that read every suffix in a name, `max_file_bytes`,
  and `yara` over uploads. The last two act by cutting the data
  connection and answering 426 rather than 226: a transfer cannot be
  un-sent, and telling the client it completed would be a lie.

  TLS is RFC 4217: `AUTH TLS` on the client side with the pipelining
  check that CVE-2011-0411 is about, `starttls` or `implicit` to the
  target, and `require_tls` on by default wherever TLS is reachable
  because a control connection in clear carries the password. `PROT P`
  data is terminated on both sides rather than tunnelled, so a protected
  transfer is still one this proxy can bound and read. `CCC` is refused:
  clearing the control channel puts every path that follows back in
  clear.

  `internal/ftp` is the protocol layer: commands and replies with hard
  bounds, and the address negotiations. A control line that is not
  exactly CRLF-terminated is refused, and so is one carrying a telnet
  `IAC` — each is a way for the proxy and the target to disagree about
  where a command ends, which is how one command becomes two. The
  address parsers are deliberately forgiving about the sentence around
  the numbers, because servers have written it several ways, and
  deliberately strict about the numbers themselves.

- **SSH session recording (`ssh.recording`), in asciicast v2.** The
  access log said a session happened. It could not say what was done in
  it, because what was done is a stream of control sequences inside the
  channel — which is the same reason this proxy terminates SSH rather
  than forwarding it. Each session channel now writes that stream to a
  file, and `asciinema play` replays it.

  The format was chosen because a recording nobody can play is a
  recording nobody reads: asciicast v2 is what asciinema records and
  plays and what asciinema-player renders in a browser, it is line
  oriented, so a file cut short by a crash or by a bound still plays up
  to where it stops, and it is text. The header carries the terminal
  size from `pty-req`, the login, the target and, for an `exec`, the
  command; a `window-change` becomes a resize event, so a session that
  was widened replays at both widths instead of wrapping everything
  after it in the wrong place. Both of the target's streams are
  recorded, because a terminal does not keep stdout and stderr apart
  either and a recording without stderr would be missing exactly the
  errors. An `sftp` channel is not recorded: it is not a terminal, and
  its own log line already says what each request did.

  `input` records the keystrokes too, and is off by default and warns
  when set. A terminal's input stream carries what the screen never
  showed, which includes every password typed into a `sudo` or `su`
  prompt: recording output is watching over a shoulder, recording input
  is a keylogger, and the difference matters both to the people
  recorded and to whoever ends up holding the files. Those files hold
  everything an administrative session printed — keys, configuration,
  tokens — and are treated the way the capture files are: `0600` with
  `O_EXCL`, proxy-chosen names, in a directory the operator names and
  the proxy does not create, bounded by `max_file_bytes` per recording
  and pruned to `max_files`.

  A principal's `recording` replaces the listener's, so one entry can be
  recorded and another spared with `recording: {enabled: false}` — the
  deployment robot that prints logs by the megabyte and types nothing
  does not need a recording of the log it already writes. A recording
  that cannot be opened does not stop the session: it is an error and an
  `ssh_recording_failed` event, because a bastion that refuses work
  when a disk fills is its own outage. One that stops at the bound says
  so in the file and in the `ssh_recording` log line.

  The format lives in `internal/asciicast`, which is a writer and
  nothing else. The part of it that has to be right is the escaping:
  a session can print anything, and a quote or a newline written raw
  would end the line early and let what a session printed forge events
  of its own. It also carries a character that a read stopped in the
  middle of into the next event, because terminal output arrives in
  whatever sizes the network produced and writing each half on its own
  would put two replacement characters where the session had one.

- **SFTP: per-user paths, file-level policy and rules over what is
  written (`ssh.sftp.allow_paths` templating,
  `allow_extensions`/`deny_extensions`, `max_file_bytes`,
  `max_open_files`, `yara`).** A path list was a list of everybody's
  directories, a file was whatever it was called, and the only thing a
  write was held to was where it went.

  `allow_paths` and `deny_paths` now take `{user}` and `{principal}`,
  substituted once when the subsystem starts, so one listener says "your
  own directory and no other". A name that could change what a pattern
  means refuses the session rather than being escaped into it: a login
  of `../..` expanded into an allow list is an allow list for somebody
  else's directory. `{principal}` without a `principals` list, and any
  unknown substitution, fail the load — `{usr}` left as a literal
  matches nothing, which on an allow list refuses everybody and on a
  deny list refuses nobody, and neither is what was written.

  `allow_extensions` and `deny_extensions` decide `open`, `rename` and
  `symlink` — the requests that settle what a file is called. Every
  extension in a name is read, not only the last, so `invoice.pdf.exe`
  is an exe on a proxy as it is on the server that would run it.

  A write is the one request whose content this can see, so two checks
  live there. `max_file_bytes` bounds the file the writes make, counted
  from the highest offset any write reaches rather than from the bytes
  sent, because a client that writes out of order otherwise stays under
  every total while making a file of any size. And `yara` reads what
  goes into each file separately: a rule about a file's first bytes is a
  rule about a file, and two uploads interleaved on one channel are two
  files, so each handle gets its own scanner. A match refuses that write
  with permission denied and records `yara_match` with the path;
  `action: close` ends the transfer.

  Both need to know which handle is which file, which is why the
  server's direction is now read for one packet — the HANDLE reply that
  says what the `open` this proxy decided on became. A write on a handle
  that pair was never seen for is refused: a write that cannot be held
  to a bound is not a write to pass on. `max_open_files` bounds what
  that state costs.

  The packet layer grew with it: WRITE now yields its handle, offset and
  bytes, the handle-bearing requests yield their handle, and both are
  read as the server's opaque bytes rather than as text — a handle is
  compared, never displayed, and refusing one for not being UTF-8 would
  refuse servers that are within their rights. A truncated WRITE, which
  used to parse as a bare handle, is now the malformed packet it is.

- **Per-principal SSH policy, environment filtering and the scp hole
  (`ssh.principals`, `ssh.allow_env`, `ssh.trusted_user_ca_keys`,
  `ssh.allow_file_transfer_commands`).** A bastion had one policy for
  everyone in `authorized_keys`: the deployment robot could run what the
  on-call engineer could run, and both reached the target as the same
  account. `principals` gives an entry per key or per certificate
  principal — matched by SHA256 fingerprint, by the names a CA signed
  into a certificate, and optionally by login name — with its own
  `upstream_user`, channels, requests, subsystems, commands,
  environment, forwards and `sftp` section. What an entry leaves unset
  is the listener's, so an entry that only moves someone to another
  account says only that.

  Once there is one entry the list is the policy: a key no entry covers
  is refused at authentication rather than served under the listener's
  default, because falling back would be the opposite of what the list
  says. An entry naming neither a fingerprint nor a certificate
  principal is the default and must be last; validation refuses entries
  after it, which could never be reached. `deny: true` refuses a
  principal outright, which is how a key stays in `authorized_keys`
  while the person it belongs to is on leave.

  `trusted_user_ca_keys` accepts OpenSSH user certificates: the
  signature, the validity window and the principal list against the
  login are all checked, so the rota changes at the CA rather than in
  this file. Without it a certificate is refused rather than quietly
  treated as the plain key inside it.

  Two ways to run code that `allow_commands` never saw are now closed.
  The first is the environment: `allow_env` defaults to `TERM`, `LANG`
  and `LC_*`, and the loader and interpreter variables (`LD_*`,
  `DYLD_*`, `BASH_ENV`, `ENV`, `SHELLOPTS`, `IFS`, `PS4`, `PERL5OPT`,
  `PYTHONPATH`, `PYTHONSTARTUP`, `RUBYOPT`, `NODE_OPTIONS`,
  `GLIBC_TUNABLES`, `GCONV_PATH`, `LOCPATH`, `TMPDIR`, `GIT_SSH*`,
  `PATH` and their kin) are refused whatever any allow list says, with
  naming one a load error — a target that reads `LD_PRELOAD` runs the
  attacker's code before it runs the approved command.

  The second is `scp` and `rsync`, which move files without ever opening
  the `sftp` subsystem: a careful read-only `sftp` policy beside an
  allowed `exec` was `scp -t` wide open. `allow_file_transfer_commands`
  therefore defaults to `false` exactly where there is an `sftp` section
  to bypass and `true` where there is not, and setting it beside an
  `sftp` policy warns. Every word of the command is read, not only
  the first, each the way a shell would take it (directory part
  removed, `VAR=value` prefix skipped), because a wrapper is otherwise
  all it takes to walk past the check: `env scp -t`, `sudo rsync`,
  `sh -c 'scp -t /etc'`. It refuses more than it must, which is the
  direction to be wrong in.
  A principal bringing its own `sftp` section to a listener with none
  inherits that default too, so its section is not a policy with a door
  beside it.

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

- **README rewritten for what this has become.** It opened by calling
  itself an HTTP reverse proxy with some listener kinds around it, which
  stopped being the shape of the thing several protocols ago. It now
  leads with the idea the codebase is actually built around — decide the
  framing once, never pass on what you could not read — because that is
  what makes terminating SMTP, MQTT and SSH worth the code, and why an
  unparseable upstream reply is a `421` rather than a relay. Each
  listener kind is described by the decision it makes rather than the
  bytes it moves; ECH, post-quantum key exchange, WebSocket inspection,
  YARA, SOCKS5, MASQUE, DNS over QUIC and the shared second factor are
  in the feature set; two claims that were not true are gone (PKCE, and
  gzip as the only compression), and the decoy count is current.

- **A reload could refuse a connection that arrived during the switch.**
  The accept socket is shared across listener generations precisely so
  that it never has to be closed and re-bound, but a retiring
  generation blocked in `Accept` could win the race for an arriving
  connection against the generation replacing it. Its own server was
  already shutting down, so the connection was accepted and then
  closed: an EOF to a client that did nothing wrong, on every reload
  that rebuilds a listener in place. A connection taken by a front that
  has since closed is now handed to the next generation instead, and
  one taken when the whole listener is going away is closed rather than
  left open with nobody serving it. Two flaky tests are fixed with it:
  the reload test that found this, and an ECH counter read before the
  server had finished the handshake the client had already returned
  from.

- **`docs/RFC.md`: every standard this proxy implements, in part or not
  at all.** A proxy sits between two implementations of a specification
  and has to be right about both. The new document is the list: around
  a hundred rows across HTTP, QUIC, WebSocket and tunnelling, TLS, DNS,
  mail, messaging, SSH and SFTP, proxying, identity, encoding and
  addressing, each marked full, a named subset, or refused.

  The refusals are why it exists. A proxy that quietly ignores a feature
  it does not understand reads a message differently from the peer
  behind it, and every smuggling and desync bug lives in that gap; the
  last table lists thirteen things this one recognises and declines on
  purpose, with the reason for each. The document also names what has no
  RFC — the PROXY protocol, MQTT, SFTP version 3, ECH and the
  post-quantum hybrid, pcapng, OpenID Connect, YARA, SecLang — so an
  absence is not mistaken for an omission, and it states plainly where
  something is *not* implemented (PKCE, RFC 9440's `Client-Cert`,
  stale-while-revalidate).

  Writing it turned up two citations in the code and the reference that
  named the wrong RFC — pcapng is a draft, not RFC 9518, and the TLS
  post-quantum hybrid is `draft-kwiatkowski-tls-ecdhe-mlkem` over FIPS
  203, not RFC 9370 — both corrected. A test keeps the document's own
  shape honest: every row carries a status the document defines, every
  refusal carries a reason, and every heading in the contents exists.

- **Twenty-three more decoys, their honeypot routes, and a fourth WAF
  rule file.** The new listeners put mail, messaging and remote access
  on the network, and each of those comes with its own scanners, its
  own administrative web interface and its own habit of leaving a
  configuration file where a web server can reach it. The decoy table
  now answers for that surface too: webmail and mail administration
  logins, a Postfix `main.cf` and a Dovecot passwd-file, a mail queue,
  a broker dashboard, a `mosquitto.conf` with a bridge password, a
  client listing and an ACL file, a bastion and a remote-desktop
  console, `authorized_keys`, `known_hosts`, an `sshd_config` and an
  SFTP log, an OpenVPN profile and a WireGuard config, the session
  files FileZilla and WinSCP save passwords in, an FTP and an rsync
  configuration, and two host management consoles. 142 decoys in all,
  every one of them demonstrated by a route in
  `examples/security/honeypots.yaml`, which a test enforces.

  `examples/waf/protocol-surface-rules.conf` is the matching rule file
  (ids 23001 upward): the paths that only exist on a mail server, a
  broker or a bastion; mail header injection and SMTP commands behind a
  line break in a form field; `$SYS` and wildcard topics through an
  HTTP bridge; SSH and VPN material and file transfer session files
  asked for over HTTP; a private key in a request body; an absolute URI
  or a MASQUE path reaching a reverse proxy, which is a client looking
  for an open one; the protocol scanners' user agents; and a host with
  a service port in the same form, which is a connect request whatever
  the fields were meant for. Each rule has a test that names it, so a
  CRS rule catching the same request cannot hide one that has rotted,
  and eight shapes an ordinary application sends that must still pass.

- **A second factor, shared by SSH and HTTP (`ssh.mfa`, the `mfa`
  filter, `xproxyctl mfa`).** TOTP (RFC 6238 over the HMAC-OTP of RFC
  4226) against one enrolment file, used by the bastion and by the
  request path. It is one implementation rather than one per protocol
  because a second factor that means different things on different
  ports is not a second factor: the weakest door decides.

  On SSH the key or the password is a partial success (RFC 4252) and
  the code is asked over keyboard-interactive; nothing about the
  session exists until it verifies. On HTTP the filter challenges the
  identity the filter before it established — `basic_auth`,
  `ldap_auth`, `oidc`, a JWT or an API key — with a form and a signed
  cookie afterwards, and refuses a request with no identity rather than
  prompting, because a second factor with no first factor is a prompt
  with no account behind it.

  The three properties that make it a factor rather than a second
  password: a code is spent when used, so a replay inside its own step
  is refused (the memory is per process, and the docs say what that
  means in a cluster); every failure gets the same answer, so a wrong
  code, a replayed one, a locked account and a name that never enrolled
  are indistinguishable, and the SSH prompt is shown even to a user with
  no enrolment; and guessing is bounded, since six digits over a
  thirty-second step is a real chance for a fast client without a
  lockout. The cookie names the user it was issued for and is checked
  against every key in the ring, so it is worthless on another account
  and a rotation does not sign everyone out.

  `xproxyctl mfa enrol` prints the enrolment line, the `otpauth://` URI
  and optional single-use recovery codes, which are stored hashed;
  `mfa verify` and `mfa list` are for checking one and seeing who is
  enrolled. The enrolment file is refused if it is world readable.
  `examples/mfa/second-factor.yaml`.

- **YARA rules over streams and bodies (`tcp.yara`, the `yara`
  filter).** A subset of the YARA language, implemented in Go. Linking
  libyara would mean `CGO_ENABLED=1` and a C parser in the data plane,
  and this proxy's build property is worth more than the last few
  features of the grammar. Supported: text strings with `nocase`,
  `wide`, `ascii`, `fullword` and `private`; hex with `??` and `4?`
  wildcards and bounded jumps; RE2 regular expressions; and conditions
  up to `N of ($a*)`, `#a` and `filesize`. Everything else — modules,
  `at`, `for`, unbounded jumps, hex alternation, `@a`, `xor`, `base64`
  — is refused at load with the line number, because a rule that
  silently matched nothing would be worse than one that will not start.

  Scanning a stream is not scanning a file, and two things follow. A
  rule is reported the first time its condition becomes true, not at the
  end: a decision that arrives after the last byte is a decision about a
  transfer that already happened. And `filesize` means the bytes seen so
  far, which is the only honest reading when there is no end yet. Both
  are documented where rules get written.

  On a `kind: tcp` listener the bytes scanned are the bytes forwarded —
  a stream cannot be paused without the peer noticing — so what a match
  decides is whether the connection continues; QUIC flows on the same
  listener are not scanned and validation says why. In the filter a body
  is buffered to `max_bytes` first, so a match can refuse the request
  rather than only record it, and a body past the bound is forwarded
  with `yara_partial` in the log instead of being held in memory. The
  overlap carried between windows is what makes a match straddling two
  reads still a match; it is capped, so a peer sending one byte at a
  time cannot turn each byte into a full rescan, and a pattern wider
  than the cap is reported rather than half-checked.

  `examples/yara/rules.yar` is a starting set with a test that each rule
  matches what it claims and ordinary traffic matches none of them.

- **SSH bastion with SFTP inspection (`kind: ssh`).** A jump host
  forwards the stream, so it cannot tell a shell from a port forward and
  the only policy it can hold is "may connect". This listener is an SSH
  server to the client and an SSH client to the target, which makes
  every channel and every request inside the session a decision:
  `direct-tcpip` only to the destinations in `forward` (validation
  refuses the channel type without a destination list, because an empty
  one refuses every forward while looking permissive), `exec` only for
  commands matching `allow_commands`, `subsystem` only for the ones
  listed, and `x11-req` and agent forwarding left out by default since
  each hands whatever runs on the target a channel back into the
  client.

  The other half is the credential. The client authenticates to the
  bastion with its own key; the bastion authenticates onwards with one
  no client holds, so a key that leaves the estate on a laptop is not a
  key that opens a server in it, and `upstream_known_hosts` makes the
  bastion the one place that would notice a machine in the middle
  (`upstream_insecure_host_key` exists, needs `allow_insecure`, and
  says what it costs).

  **SFTP is inspected inside the subsystem channel**, because the whole
  difference between reading a file and deleting a tree happens there.
  `read_only` refuses every request that changes the server — including
  an `open` carrying a writing, creating or truncating flag, which is
  where a write is actually decided — and `allow_paths`, `deny_paths`
  and `deny_operations` decide the rest. A refusal is a
  permission-denied status rather than a dropped connection, so the
  client is told which operation was refused. A path that climbs above
  its own root after cleaning is refused rather than matched: what it
  means depends on a working directory the proxy cannot see, and a
  check on a path whose meaning is unknown is not a check. Names
  carrying NUL or invalid UTF-8 are refused for the same reason — the
  server would read them where the proxy stopped.

  Every session writes an `ssh` access line, every allowed `exec` is a
  security event with its command, and every inspected SFTP request
  writes an `sftp` line. That record is the other reason to terminate
  rather than forward: a stream you cannot read is a stream you cannot
  log. Refusals and authentication failures are `ssh_denied` deny
  events. `examples/bastion/ssh.yaml`.

- **MQTT proxy for 3.1.1 and 5.0 (`kind: mqtt`).** An MQTT broker's
  authorisation is per topic, and a topic is a string inside a packet.
  A layer 4 listener carries those packets without looking, so there is
  nowhere to say that a device may publish its own telemetry and
  nothing else — and a device that holds a broker credential holds the
  whole tree, including what every other device publishes. This
  listener reads every control packet and decides the ones that carry a
  policy question before they reach the broker.

  The part worth stating plainly is that a subscription is a filter,
  not a topic. A device asking for `#` is asking for all of them, so
  `subscribe_allow` is checked by subsumption — an entry must cover
  everything the requested filter could deliver — and `subscribe_deny`
  by overlap, refusing a filter that could reach anything denied rather
  than only one that names it. Matching a filter as though it were a
  topic is exactly how `#` slips past an allow list of `sensors/+`.
  `publish_allow` and `publish_deny` apply to concrete topics, and to
  the will, which is checked at CONNECT because that is the only moment
  there is.

  The framing is held to the specification rather than to what brokers
  tolerate: a non-shortest remaining length (two spellings of one
  length are two readings of one packet), QoS 3, DUP on a QoS 0
  publication, a packet id of zero, a string that is not UTF-8 or
  carries NUL or a surrogate, reserved flag bits. A packet that does
  not parse ends the session with nothing forwarded, in either
  direction, because its length is what the next read depends on. A
  session begins with CONNECT and has exactly one; a second would take
  a new identity on a session already authorised as another. Only the
  two versions the proxy parses are accepted, since a version it cannot
  parse is a packet it cannot check.

  `action: drop` refuses one packet instead of the session and answers
  it properly — PUBACK or PUBREC with not-authorized, a SUBACK of
  failures, and the PUBREL of a refused QoS 2 publication answered by
  the proxy, since the broker never saw the PUBLISH — so one
  misconfigured device does not take a fleet off the network. Bounds on
  packet size, topic length and depth, subscriptions per session, keep
  alive and client id shape, with `allow_retain` for the messages that
  outlive the session that set them. MQTT has no STARTTLS, so
  `tls_mode: implicit` on 8883 is the only encrypted shape and
  validation says so rather than leaving it implied. Refusals are
  `mqtt_denied` deny events. `examples/iot/mqtt.yaml`.

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

**The per-package coverage floor holds again after the split.** Three
packages came out of it with code no test reached, and the gate had
been failing on all three.

`internal/daemon` (14 %) is the body of all three programs, and until
now nothing ran it: `Run` installs a process-wide signal handler and
then blocks, which a test binary cannot do to itself. The signal source
and a hook called once the daemon is serving are now parameters of an
unexported `run`, so a test drives a whole daemon — ready, answering
the management socket, reopening its logs on SIGUSR1, reloading on
SIGHUP, rolling back to the generation recorded at start, stopping on
SIGTERM with the socket removed. The failure paths after the listeners
are open are driven too, because a process left serving traffic with no
way to control it is worse than one that did not start. The systemd
protocol is checked over a real `unixgram` socket, including the
monotonic stamp `Type=notify-reload` needs and the case where there is
no service manager at all. Now 70 %.

`internal/kinds/ftp` (54 %) had no test for any of the TLS: `AUTH TLS`
on the client's leg, `require_tls`, the refusal of octets pipelined
across the upgrade, a listener with no certificate, `upstream_tls_mode`
and the 431 a target that will not protect the connection earns before
the client is told its own is protected. Nor for who is let near the
listener — `allow_clients`, `max_connections`, a target that is not
there — nor for the PROXY header the target reads, `{user}` in
`allow_paths`, or YARA over an upload. Now 70 %.

`internal/kinds/dns` (58 %) had none for the three things a resolver
answers about itself: the discovery records that let a client move
itself off plaintext (RFC 9461), the SVCB and HTTPS records it owns
(RFC 9460), and DNS over QUIC (RFC 9250). The records are now asked for
over UDP on one listener and over QUIC on another and required to
agree, and a record that cannot be encoded has to fail the
configuration rather than every query for it. Now 89 %.

The two `go:generate` helpers were 0 % `main` packages inside the gate.
`test/covergate` excluded binaries by listing `cmd/`, which named the
released programs and not these; it now excludes every `main` package
by where it lives, and `internal/config/schema/gen` moved to
`internal/config/schema/cmd/genschema` so that one rule covers both.

And `make cover` could not finish at all: `internal/sandbox` applies
Landlock and seccomp to a child process, which then cannot write the
coverage file the instrumented binary emits on exit, so the run failed
on the one package whose figure the gate already ignores. It is left
out of the coverage run and only that one; `make test` and `make
test-race` run it in full.

Two ECH tests read the listener's counters the instant the client's
`Dial` returned. In TLS 1.3 that is before the server has finished its
own handshake, so the counters were a moment behind the connection the
client already held, and the tests failed occasionally on a listener
that was working. They now wait for the count to catch up with what the
client's own connection state already said.

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
