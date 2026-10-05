# Changelog

All notable changes to Xproxy. The format follows Keep a Changelog and
the project uses semantic versioning from 1.0.0. Entries are grouped by
the roadmap phase that delivered them (see [ROADMAP.md](ROADMAP.md)).

## Unreleased

### Fixed (an eighth audit round: the attack surface, and who controls the data on it)

A review of every network component, parser and protocol implementation,
following the data a peer controls to the decisions it reaches. Fifteen findings,
and they divide into three shapes: a control that ran on one path and not the
sibling path beside it; a policy that read what was offered rather than what was
claimed; and a decision taken before the thing it decides about was known.

Three candidates were chased and dismissed rather than fixed, which is worth
recording because each looked like a bypass: MySQL's `CLIENT_COMPRESS` as a way
past the statement reader (a client that asserts it when the greeting did not
offer it can no longer be read by the server either, so it is a self-inflicted
failure rather than a bypass); an AMQP field table whose duplicate key carries a
non-text second value (RabbitMQ's `table_lookup` is `lists:keysearch`, so the
first value is the one that survives on both sides); and the NTP transmit
timestamp as a predictable nonce (it is seeded from ChaCha8, not the clock).

**The HTTP edge.**

- A **satisfied challenge resumed the chain at the backend.** A filter that
  returned a challenge verdict for a client already holding a cookie good for
  that tier sent the request straight past every filter behind it. One proof of
  work, cached in a cookie for `challenge.ttl`, bought an hour's pass on the
  `openapi`, `graphql`, `grpc_guard` and `upload_guard` instances further down
  the route: the cheapest control in the chain disabling the expensive ones. The
  chain now resumes at the filter after the one that asked.
- A **gRPC-web call went past `grpc_guard` entirely.** The guard matched
  `application/grpc` only, and the gRPC-web translation happens after the filter
  chain -- so the upstream got the identical frames with no bounds and no content
  rules applied. One content-type header was the whole bypass, and it is the one
  a browser client sends. `grpc-web`, `grpc-web-text` and any `;` parameter on
  the header are now inspected, the text variants base64-decoded before the walk.
- The `header:`, `cookie:` and `jwt:` **rate-limit keys named a bucket with the
  credential itself.** Bucket names are not private: they go to the cluster in
  the gossip, into the shared store for `distributed: exact`, into the quota
  report, the `rate_limited` event and `xproxyctl quota`. The key is now a
  truncated SHA-256 of the value, which tells one bucket from another, which is
  all a key has to do.

**The databases.**

- **T-SQL needs no terminator between statements, and the splitter cut only on
  `;`.** `PRINT 'ok' DROP TABLE users` was one statement to the relay and two to
  SQL Server: classified by its leading PRINT as a read, it passed `read_only`,
  passed an allow-list of `select`, and was forwarded for the server to run both
  halves -- while `max_statements` counted separators the dialect does not
  require. Behind a non-writing lead the classifier now finds the juxtaposed
  statement and hands it to the policy as its own, counted by the bound.
- **MySQL requires whitespace after `--`** for it to open a comment, and the
  lexer did not, so `SELECT 1--1; DROP TABLE t` hid its second statement from a
  relay that read a comment where the server read arithmetic.
- **A stripped capability came back in the client's login.** The MySQL relay
  cleared `CLIENT_LOCAL_FILES` from the server's greeting, but the server reads
  the client's own capability field rather than intersecting it with the greeting
  it sent -- so a peer that set the bit anyway could be asked by the server for a
  file from its own host. The denied bits are now cleared from the forwarded
  login as well, and the edit is recorded as `mysql_capabilities_overridden`.

**The desktop gateway.**

- **`SecNone` was offered inside an anonymous-TLS tunnel** even where the
  listener had a password, so a client that chose the VeNCrypt or TLS variant
  skipped the password the gate exists to ask for.
- **The grant's target was not checked against the endpoint dialled.** A
  time-boxed grant for one desktop admitted a session to any endpoint in the
  pool the balancer happened to pick.
- **A pixel format took effect on the server before the reader applied it**, so
  the reader measured one rectangle with the old bytes-per-pixel and lost framing
  for the rest of the session. The format is now applied where a length is
  derived from it, and a change that cannot be measured is refused.

**The OT kinds.**

- **`monitor_only` forwarded OPC UA writes and method calls.** A write forwarded
  so that it could be written down is a moved actuator, which is the one thing a
  trial of a policy may not do; those decisions are now hard, as the
  documentation already said.
- **Shadow mode forwarded the BACnet link layer**: BBMD registration, the
  Secure-BACnet functions and the security messages. Joining a device to a
  distribution list is not a trial of anything either.
- **SNMP paired an answer with a request by identifier alone**, so any host that
  could reach the relay's ephemeral port could answer for the agent. The agent's
  address is now part of the match, and a mismatch leaves the exchange standing
  rather than consuming it.
- **NTS-KE applied the server-name list after the exchange had completed.** The
  name is in the SNI the moment the handshake finishes, so the list is now
  applied before the cookies are issued.

**Everywhere else.**

- An **AMQP field table with a repeated key** was read last-wins by the relay and
  first-wins by the broker, so the policy judged one `alternate-exchange` and the
  broker used another. A repeated key is now refused on the name, before the
  value's type is known.
- The **replay renderer interpolated recorded text into a `<script>` block**
  with Go's `%q` only, which does not escape `<`, so a recorded session
  containing `</script>` closed it. Stored XSS in the page an operator opens to
  review a session.
- **`config dump --redacted` and the diff left three credential fields in**:
  `headers`, `token` and `header_value`. They are now redacted in the node tree
  rather than by key name in the text, so a value that happens to look like YAML
  cannot survive the pass.

### Tests (the policies that were only ever driven end to end)

Coverage work across the components, written as the policies read rather than
as numbers.

**The five kinds added this release had no policy test at all.** radius,
tacacs, kkdcp, imap and pop3 were driven only through sockets, which is the
right way to prove a relay carries what it should and the wrong way to reach a
compile-time refusal or the twentieth branch of a decision: a case costs a
server, a client and a secret file, so the cases nobody wrote were the cheap
ones. That is why those five sat at the bottom of the per-package table, and
what they were missing was not obscure -- it was the validation that turns a
mistyped code name into an error at load rather than at the first login it
refuses. Each now has a `policy_test.go` that starts from the defaults, because
the defaults are what an operator gets by naming an upstream and on these
protocols they are the security; then a table of every name a configuration can
misspell, asserting the error names the field and the rule's index; then the
decisions, one case each, including the orders that matter. Alongside them the
RADIUS pending table, which has two modes rather than two settings -- with a
secret it allocates its own identifier so two switches using identifier 7
cannot be confused, and without one a collision is refused rather than resolved
-- and the KKDCP counting window, where the interesting behaviour is the
bookkeeping: what falls out of the window, what a full table does to a new
client, and the per-client ceiling.

**The two OT policies, which are the largest in the project.** On mms: what a
functional constraint means for the plant, the services that replace what is
inside a protection relay rather than telling it what to do, `read_only` as a
property of the service rather than its name, and select-before-operate -- the
interlock the devices may not be trusted with, because `ctlModel` lives in
`$CF$` and `$CF$` is writable. On opcua: the four layers, and at each the pairs
that have to be decided together, of which the channel is the one that matters:
a listener checking only the security policy would admit Basic256Sha256 with
mode none, which is a strong cipher suite with nothing encrypted.

Three readings turned out to be worth writing down, because the test written
first asserted the opposite and the code was right: a rule's credential list is
a selector as well as a policy (naming `chap` on a RADIUS rule exempts chap, it
does not confine that address to chap); a TACACS+ rule whose command list does
not cover a command does not decide it, so a command on the listener's allow
list and outside the rule's falls through to the default action; and `OR` is
"operate received", a status attribute, so a write to it does not reach the
plant -- `CO` is the constraint that does.

Both OT tests also turned up the same sharp edge, now asserted on both kinds:
the object and node patterns are `path.Match`, where a `*` does not cross a
`/`. So `objects: ["*"]` written to mean everything selects nothing, and
`ns=4;s=Tank*` covers `Tank1` and not `Tank1/Level`. Worth knowing, because
every list in both configurations is written in a form full of slashes.

**And the smaller things that had no test.** The mms naming and classification
tables, where every string is a counter name, a word in a security event or a
spelling a configuration uses. The three DNS sections that answer rather than
forward -- local records, per-client views, and the screen over what an upstream
may point at -- where every refusal is a refusal at load and the alternative is
a name quietly not resolving in production. The validation of the SSE event
policy and of the two mailbox listeners, neither of which had one. The ATT&CK
view over the refusal counters: a refusal is counted under its own reason and
under every technique that reason maps to, and the identifiers come back
sorted, because a list that reordered itself between reads would read as
movement. The DNS prefetch claim, which is what keeps one popular name from
being refreshed by every goroutine that notices it is about to expire -- the
entries worth prefetching are by definition the ones being asked for
constantly, so without it the moment an entry nears expiry is the moment every
in-flight query for it goes upstream at once. The FTP passive port range, where
every wrong reading is a listener that starts and then fails in the field. The
VNC pixel-bound reasons, where the empty one is load-bearing: a stream that
ended is not a refusal. And the forward proxy's `networks` and `not_networks`,
which are how a rule is written about a floor or a build farm rather than about
a user name.

One existing test fixed in each direction. The IMAP auth-injection test waited
three seconds for a counter, which is long enough on an idle machine and not
under load; it now reads to the end of the connection, which is a signal rather
than a timer. The RADIUS end-to-end test read `radius_requests` immediately
after the answer reached the client, and the full run under `-race` caught it:
the counter is incremented after the datagram has gone to the server -- the
right place for a counter meaning "requests this listener forwarded" -- and the
reply arrives on another goroutine, so under load the answer is back before the
counter moves.

**Three more packages that were carried by their end-to-end tests.** On smtp,
the two decisions taken before anything is dialled: the client allow list, which
answers for an address the parser could not even read -- an empty list admits
everything, including an invalid address, so the asymmetry is asserted rather
than assumed -- and the declared size, read the way RFC 1870 writes it, which is
`SIZE=` anywhere in the `MAIL FROM` line in any case, where a line carrying no
declaration must come back as "no size" rather than as a size of zero, because
zero is a declaration a client can make. Then the AUTH exchange, which the fake
MTA could not previously carry at all: it now answers challenge by challenge, so
a multi-round SASL mechanism is relayed a challenge at a time, one that never
ends is ended by the relay rather than by the client, a credential is refused
before it travels when the policy says so, and `XCLIENT` tells the upstream
which client the session is for. All of them upgrade with STARTTLS first,
because `require_tls` is forced on wherever a TLS section exists -- which is the
behaviour, and now has a test that depends on it. On syslog, the message filter:
the facility lists with deny winning, the severity floor read from both ends,
the text patterns, and which of those wins when two disagree. And the Kerberos
DER reader, where the refusals are the product: a `KerberosString` is read under
every string tag the installed base actually sends and under nothing else, an
explicit tag or a SEQUENCE has to be constructed, an INTEGER has one spelling
because a non-minimal encoding is a second message with the same value, and the
options bit string has to be a whole number of octets with its unused-bit count
zero.

**Four protocols had no row in `docs/TESTS.md`.** coap, dhcp6, mms and opcua
were tested as well as their siblings and documented nowhere, so the table now
names every test in all eight packages along with what the protocol's own traps
are: the CoAP option number that carries its handling rules in its own low bits
and the Block2 transfer that declares a size before it sends it; the DHCPv6
lifetime of zero that is a withdrawal rather than a short lease and the prefix
delegation that has to be inside the estate's prefix and not around it; the MMS
functional constraint that decides whether a write reaches a breaker, a
protection setting or a report control; and the four layers an OPC UA session
is decided at, in the order that makes `read_only` mean what it says.

**The per-package table in `docs/TESTS.md` is regenerated from the passing
gate.** The core packages together are at 86.0 % of 108466 statements, up from
85.3 %, and the five kinds this release added are no longer the bottom of the
table: radius 66 % to 80 %, kkdcp 69 % to 82 %, pop3 67 % to 75 %, imap 74 % to
78 %, tacacs 74 % to 84 %. Alongside them smtp 67 % to 74 %, the MMS wire reader
67 % to 74 %, the two OT kinds to 84 % each, and kerberos 79 % to 81 %. The
lowest core package at that point was `internal/daemon` at 70 %, the
signal-handling and rollback path of a whole daemon, which the work below then
took to 78 %. One figure went the other way: the
`cmd/xproxyctl` row claimed 82 % from its own tests and a measurement now gives
68 %, so the row was stale -- the package sits outside the gate, which is exactly
how a figure in a document drifts from the code without anything failing. What the
remainder is has not changed: the formatting of views whose subsystems need a
live peer, authority, resolver or scanner behind them.

### Fixed (an NTS-KE refusal counter read before it was written)

The coverage run failed `TestTerminatingRefusesTermsItCannotMeet` with
`refusals: map[no_terms:1]` after two clients had each been refused. The two
counters on that path are written on either side of the answer: `NTSKENoTerms`
before the error record goes out, and the reason string after the connection is
done with -- so a client that has read its refusal has seen the first and not
necessarily the second. Read once, the assertion was racing the thing it
measured, and it printed a map that was about to hold the count it had just
called missing.

Four assertions in `terminate_test.go` already polled for exactly this reason,
with a comment saying so. That loop is now a `refused` helper, and the seven
places that still read a refusal count once -- the no-terms test and six in
`ntske_test.go`: the application protocol, the server name on both sides, the
plaintext scan, the client list, the handshake bound and the connection bound --
go through it. Where the old assertion said a count was exactly one it still
does, after the wait rather than instead of it.

The relay is unchanged: writing the answer before counting the refusal is the
right order, because the client should not wait on this process's bookkeeping.
Verified by making the terms always negotiable, which leaves the counter at zero
and fails the wait rather than passing it.

### Fixed (eight assertions that could only ever pass)

A sweep of all 878 test files for assertions that cannot fail turned up one
shape in three packages: a test sends something a listener should refuse,
sleeps for a fixed interval, and then asserts that nothing arrived. The sleep is
not synchronisation. It ends where it ends, and on a loaded machine it can end
before the listener has read the datagram at all -- at which point the
collector, the device or the counter is empty for the trivial reason that
nothing has happened yet, and the assertion holds whether the listener refuses
the message or forwards it a moment later. Every one of them would have passed
against a relay with the refusal taken out.

What makes the absence mean something is already in the process: the refusal
counter the listener writes on the path that returns without forwarding. So the
wait is on that counter, and the absence is asserted after it has moved, when
the decision is made and the upstream's emptiness is the answer rather than a
snapshot of work in progress. That deletes the timer in the process -- these
tests are now faster as well as sound.

- **bacnet, nine refusal tests through one helper.** `device.nothingReached`
  slept 150 ms before looking at what reached the fake controller; it now sums
  the listener's `bacnet` refusal reasons and waits for the total to move. Two
  more in the same file -- the shadow-mode test, which asserts a bound still
  holds when the policy is shadowed, and the routed-network test -- wait on the
  one reason that applies, through a new `waitRefusal`.
- **syslog, four.** The facility and severity filters, the sender policy on both
  the stream and the datagram listener, and the per-sender rate limit all slept
  and then read a counter. They now wait for the counter first: the same two
  lines in the other order, which is strictly stronger, and in two of them the
  counter check the sleep was standing in for is now the wait itself.
- **coap, the client-certificate requirement.** It recorded what the device had
  received, drove a handshake with no certificate, and compared -- with nothing
  between the two reads. It now waits for `coap_handshake_failed` to move.

Each was verified by mutation rather than by passing: the refusal was removed
from the relay -- forwarded after being counted, which is exactly the leak the
assertion exists to catch -- and every test failed, naming the message that got
through. For syslog's sender policy that took removing both layers, because the
listener checks the sender at the connection and again at each message; a
defence in depth worth recording.

The bacnet routed-network test also turned out to be refusing the wrong thing.
It rewrote two octets to aim the second request at a network the configuration
does not name, and the second of those two is the destination address *length* --
so every field behind it moved and the relay was refusing a message it could not
parse. It still refused, for a reason that happened to match, which is why
nobody noticed. One octet now, and the mutation check that found this is what
proves the test reads the policy rather than the parser.

### Fixed (an RDP dynamic-channel assertion counted bytes it was racing)

- **`TestDataFromTheClientOnARefusedDynamicChannelIsDropped` snapshotted a byte
  count on the wrong side of a write.** It waited for the refusal to be *counted*
  and then recorded how much the desktop had received -- but the refusal the
  relay sends to the desktop is counted before it is written, so the snapshot
  raced it. When those fourteen octets landed afterwards the count had grown, and
  the failure read "the desktop received 14 more bytes on drdynvc": a test
  reporting that the client's data had been forwarded when what arrived was the
  relay's own refusal.

  The client's payload is now a distinctive string and the assertion is that the
  desktop never saw it, which is the property the test is named for and does not
  depend on when anything else arrives. The failure output shows the smuggled
  bytes rather than a number. Verified twenty runs under the race detector, and
  with the drop removed from the relay the test fails and prints the payload.

### Fixed (the IMAP injection test was betting on a goroutine order)

- **`TestALineTheServerDidNotAskForIsNotCredentialMaterial` raced the response
  reader.** A SASL exchange is open from the client's AUTHENTICATE until the
  server's tagged answer, and the injected line has to arrive inside it; the fake
  server answered immediately, so the window was however long it took the
  goroutine reading the server to call `endAuth`. The assertion was really a bet
  on the client's second line being read first. It usually was, and on a loaded
  machine it was not -- and losing the bet reads as `the line was carried as a
  credential`, which is a test saying credential smuggling was not refused when
  what happened is that the test could not hold the window open.

  The fake server now takes a `silent` set and does not answer the AUTHENTICATE
  at all, which holds the window open for as long as the test needs: a server
  that has not answered yet is exactly the state the check exists for. Verified
  twenty runs under the race detector, and verified the other way too -- with the
  turn check removed from the relay the test fails, so it was made deterministic
  rather than weakened.

### Fixed (a load-sensitive assertion in the terminal interface test)

- **`internal/tui` `TestRunOverAPseudoTerminal` read a frame too early.** It
  failed in a coverage run, which is the same suite under instrumentation and so
  slower: `press` returns on the first frame that arrives after a key, and a
  frame still in flight from the action before it satisfies that, so three
  assertions were reading a snapshot one frame behind the key they were about.
  They now wait for the frame that shows what they assert, which is what the
  second half of the same test already did. No product change: the keys were
  acted on, the test looked too soon.

### Fixed (IMAP: the same upstream upgrade, and two xproxyctl commands)

- **An imap listener with `upstream_tls_mode: starttls` could not carry a
  session either.** The same defect as pop3 below, in `startTLSUpstream`: the
  server's greeting was read to reach the STARTTLS exchange and discarded, and
  the relay then waited for a greeting RFC 3501 never sends -- after STARTTLS
  the server carries on in the state it was in and the client re-issues
  CAPABILITY instead of expecting a second greeting. On IMAP that line costs
  more than the session: it is where this kind refuses a PREAUTH greeting and
  narrows the capability list, so both decisions went with it. The greeting now
  comes back from the upgrade, and the tests assert the narrowing and the
  PREAUTH refusal *on an upgraded leg* rather than only on a plain one.

- **Anything the server pipelines behind its STARTTLS answer is refused**, as
  on pop3: it travelled in clear and would have been read as part of the
  encrypted session.

- **`xproxyctl access approve ID -by NAME` was refused with "one grant id".**
  The usage line, and the hint `access ask` prints, both put the id first --
  and Go's flag package stops parsing at the first argument that is not a flag,
  so the flags after it were never read and the command saw three arguments
  where it wanted one. An operator following the tool's own instructions got a
  refusal. Both orders work now.

- **`xproxyctl access -state nonsense` answered with an empty list.** A typo in
  the filter read as "no grant matched", which reads as "nobody has access" --
  the opposite of what an unfiltered list would have shown. It is refused now,
  naming the states, which is the rule this project already applies to the
  asset filters for the same reason.

- **`xproxyctl ech show` could not read a record pasted out of a zone file.**
  `ech="<base64>"` is the form an operator checking a rotation actually has to
  hand, and the quotes were trimmed before the `ech=` prefix was stripped, which
  leaves the opening quote in place and fails to decode.

### Fixed (POP3: the upstream upgrade never worked)

- **A pop3 listener with `upstream_tls_mode: starttls` could not carry a
  session.** The relay upgrades the server's leg on its own behalf, which means
  reading the server's greeting to get to the STLS exchange -- and it threw that
  line away. It then waited for a greeting the server will never send, because
  RFC 2595 leaves the connection in AUTHORIZATION and does not have it greet
  again: every session hung until the idle timeout and was counted as
  `upstream_failed`. On POP3 the same line is also the APOP challenge, so the
  listener would have lost that mechanism even if the session had survived. The
  greeting now comes back from the upgrade and is the one the client gets.

  This was the one path in the kind with no test at all -- `stlsUpstream` was at
  0 % -- which is what the coverage work above was for, and it is the argument
  for measuring a package rather than reading it: the code looks right.

- **Anything the server pipelines behind its `+OK` to STLS is now refused.**
  It travelled in clear and would have been read as part of the encrypted
  session: the client leg's injection check, pointed the other way. Nothing
  legitimate is lost, because the server has nothing to say until the relay
  speaks.

**`internal/daemon` and `internal/kinds/pop3`, the two lowest packages left
in the table.** On the daemon, the branches that only run when something about
the deployment is unusual: advice said at every start rather than only by
`-validate`, the three failures after the listeners are bound that have to take
the process down with them (an address taken, a metrics address taken, a
listener kind this binary did not link), a history directory that cannot be
written and every action that then has to answer honestly rather than look like
an empty history, the dry run that reads the file without moving the
generation, and the diff that names which of `from` and `to` it could not
resolve. 69.8 % to 78.3 % of the package's own statements. On pop3, the
transport: the client's STLS answered here with this listener's certificate, a
command pipelined behind it refused (CVE-2011-0411 in POP3's spelling), a
handshake that fails ending the connection because the `+OK` has already gone,
and the policy asked about the address before a mailbox server is dialled and
about the name a USER claims before it reaches a server that would check it.
73.6 % to 84.2 %.

**The RDP legacy encryption seam, driven one unit at a time.** The end-to-end
test puts a client, this gateway and a desktop that speaks the protocol's own
encryption together, and proves the three fit. What it cannot do is reach one
direction at a time: `open` is only ever called on what a desktop sends, and a
fake desktop that sends the awkward cases is a fake desktop nobody would write
-- so `open` sat at 0 % while the session it belongs to was covered. The pair is
now driven directly, with keys derived the way the session derives them, and the
asymmetries are what the cases are about: a security header goes back only on
the packet kinds that have one, the encrypt bit never survives the decryption, a
packet the desktop did not encrypt is passed through while one that does not
decrypt ends the session, and fast path input before the key exchange is refused
because it carries keystrokes. `TestWhichUnitsHaveToWaitForTheKeys` is the one
with a wrong answer in each direction -- too eager stalls every connection at
the gateway, too lax sends session traffic before there is a key for it.
73.8 % to 77.0 % of the package's own statements.

**The MMS answer side, which was the half nothing read.** The request readers
had the tests, because requests are what a relay decides about -- so the
answers, where the reports come from, were at 0 % function by function:
`readInvokeOnly`, `readError`, `readNames`, `readDefineList` and
`associationInformation` were never called. A response is now asserted to be
read for its invoke identifier and nothing else (the body is values and this
package keeps none), a device's own refusal as a class and a code, because
"the relay refused" and "the IED refused" are two findings about two pieces of
equipment. The association reads the same thing twice over, and both ways are
now covered: the initiate PDU rides inside an EXTERNAL whose single-ASN1-type
and octet-aligned arms carry it identically, and a title or qualifier arrives
explicitly tagged by the standard and implicitly tagged by some equipment.
Then the fail-closed rule, one case per field: a title, a qualifier or a result
that does not parse is an error and not an absent field, because an association
reported with no title is one a title rule cannot refuse. 69.7 % to 82.7 % of
the package's own statements.

**The three `xproxyctl` command groups that had no test at all.** `ech`, `mfa`
and `access` were between them a fifth of the package and none of them was
reached by a test, which is how the four defects above survived. Each is now
driven as the thing it is rather than as a list of flags: ECH as a rotation
(what keygen wrote, show reads back and record publishes, with the key 0600 and
a second keygen on one id refused), MFA as a round trip (the line enrol prints
has to be one verify accepts a code for, with the code computed in the test the
way the user's telephone computes it), and access as four eyes from the
operator's side (the asker may not approve their own ask, and `-by` defaults to
SUDO_USER before the account, because root is not a name four eyes can tell
apart). 67.5 % to 77.9 % of the package's own statements.

**`cmd/xproxyctl` is in the gate.** It was outside it because every `main`
package is, and that rule is right for a flag parse over a package gated on its
own -- but xproxyctl is the operator interface, nearly three thousand
statements of views and their formatting, and what stood in for a gate was a
figure in `docs/TESTS.md` that nothing checked. It read 82 % and measured 67 %.
`test/covergate` now has a `gated` list that overrides the `cmd/` rule, the
Makefile instruments the package alongside `internal/...`, and the number is in
the table with the others where it cannot drift.

The table is regenerated from the gate that passes on all of this: 86.0 % of
111255 statements, nothing below the 60 % floor. Putting xproxyctl in cost 0.4
points when its 2764 statements entered the denominator at 68 %, and testing the
three command groups has given them back: it reads 78 % now, and the lowest gated
package is `internal/proxytest` at 71 % -- fifty-one statements of test harness.
The lowest one that is not a harness is `internal/kinds/rdp` at 74 %.

### Added (the event stream: a policy for text/event-stream)

- **`sse_guard` on a route is a policy for Server-Sent Events**, which is the
  other long-lived HTTP response an estate runs and the only one nothing else
  in a configuration bounds. One GET, a response with no length, flushed per
  event, held open for hours. Without a guard it is an opaque outbound channel
  on a port that is already open.

  It reads like the WebSocket guard beside it and it answers a different
  question, because two facts about SSE decide what a policy here can be.

  **It is one-directional, and the direction is outward.** The client sends a
  GET and then says nothing; everything after that is the application talking.
  So every event is the estate's own output leaving it, which puts this in the
  same position as the `dhcp` kind -- a policy about answers -- and makes
  `deny_patterns` here a control that reads what is *leaving*. That matters
  because an event stream is the shape of a channel for moving data out
  quietly: arbitrary text, chunked, flushed per event, under a Content-Type a
  dashboard uses, and nothing about it malformed. `max_events`,
  `max_stream_bytes` and `max_duration` are what make a stream finite, and a
  stream has none of them by default because HTTP gives a response with no
  length no bound at all.

  **A single event cannot be refused.** By the time one is read the status line
  has gone and the response is committed; there is no way to say "not that one"
  inside a sequence a client is reading in order. So `action` has two values
  rather than three -- the stream ends, or the event is carried and reported --
  and a refusal is a decision to end the stream *at* that event. The client
  sees a closed body, which is what it sees when an application finishes, and
  reconnects: the right outcome for a dashboard and a dead end for a channel.

  The rest of the settings: bounds on an event, a line and a field count; the
  event names a route carries, with a per-name size, rate and JSON Schema,
  because one `max_event_bytes` for the stream is the bound that lets every
  event be that large and this is where the keepalive and the hourly report get
  different answers; a floor on the `retry:` field, which **rewrites** rather
  than refuses, because `retry: 0` from a misconfigured application is a fleet
  of browsers reconnecting as fast as they can and the stream itself is fine;
  and the compression decision the WebSocket guard already has, for the same
  reason -- a compressed stream cannot be read without being inflated.

- **`Last-Event-ID` is treated as a cursor rather than a header.** It is the
  one piece of client-controlled input on this protocol, and an application
  that replays from it is being told where to start -- so an identifier a
  client was never issued is a request for history it was not shown.
  `last_event_id_pattern` says what an estate's identifiers look like,
  `max_id_bytes` bounds both ends of the round trip (the server's `id:` field
  and the client's header are the same value coming back), and
  `allow_last_event_id: false` stops it crossing at all. A cursor that does not
  pass is **removed** rather than refused: the client gets the stream from the
  beginning, which is what a client with no cursor gets.

- **`internal/sse` reads the format, and the tests are about the traps its
  smallness hides.** All three of the standard's line terminators -- CRLF, LF
  *and a bare CR* -- because a reader that waited for an LF after a CR would
  hold a whole event and deliver nothing, which on this protocol looks exactly
  like a server that has stopped sending. A field with no colon is a field with
  an empty value rather than a malformed line. Exactly one space after the
  colon is stripped. `data` accumulates across lines. The BOM goes once, at the
  start only. An `id` with a NUL is dropped, field and all, which is the one
  value the standard says to ignore rather than carry. Nineteen table tests and
  three fuzz targets.

  The guard reads each event and **writes it out again** rather than splicing,
  which is what makes the rest trustworthy: the framing is resolved once here
  instead of twice at the two ends, so a client cannot read an event boundary
  differently from the way the policy did. A stream whose framing cannot be
  read is not forwarded at all, and that is the one refusal that stands in
  `monitor_only` too -- forwarding it raw would mean forwarding octets nobody
  decided about.

- **Seven counters, twenty-three mappings and two new techniques.**
  `sse_streams`, `sse_events`, `sse_event_bytes`, `sse_comments`,
  `sse_violations`, `sse_unknown_events` and `sse_cursors_stripped`. Refusals
  are counted under the `http` kind with an `sse_` prefix, because an event
  stream is a response on an http listener rather than a listener of its own,
  and every one of them is bannable as `sse_denied`. The ATT&CK catalogue gains
  **T1041 (Exfiltration Over C2 Channel)** and **T1071.001 (Application Layer
  Protocol: Web Protocols)**, which are the right names for this and were not
  there; the bound refusals carry T1041, T1048 and T1567, the framing and
  state refusals carry T1071.001, the cursor refusals carry T1213 and T1190,
  and the compression ones carry T1562.

- **Documentation and examples.** A section in [CONFIG.md](CONFIG.md) with the
  per-name table, a "Server-Sent Events" section in [USAGE.md](USAGE.md),
  [`examples/routes/events.yaml`](../examples/routes/events.yaml) (a dashboard
  feed with its event names written down, a log tail with no list but a hard
  bound on how much one person may take, and a third route under
  `monitor_only`, which is how an estate finds out what its own streams send
  before a bound is set), the protocol in [README.md](../README.md)'s table and
  inspection list, and four rows in
  [THREAT_MODEL.md](THREAT_MODEL.md).

- **Fixed in passing**: `.gitignore`'s fuzz-corpus rule was
  `testdata/fuzz/**/[!R]*`. A pattern containing a slash is anchored to the
  file's own directory, so it only ever matched a corpus at the repository root
  and never one under `internal/<pkg>/testdata/fuzz` -- where every package's
  corpus actually lives. A generated seed would have been committed by
  `git add -A`.

### Fixed (a security review of the five protocols added in this release)

A review of the SSE guard and the five relay kinds added above (`kkdcp`,
`radius`, `tacacs`, `imap`, `pop3`) found twenty issues worth fixing. They have
one shape between them: a control that read a field the attacker writes, or read
one field where the far end reads another. Each is now decided on what can be
shown rather than on what was claimed.

**The event stream.**

- The **cursor policy ran only when the client asked for a stream.** What makes
  a response a stream is its Content-Type, so an application answering a path
  with `text/event-stream` answers it that way for a client that sent no
  `Accept` header -- and `allow_last_event_id`, `max_id_bytes` and
  `last_event_id_pattern` were all skipped for it. The cursor is now decided for
  every request on a route that has a guard; the `Accept-Encoding` rewrite stays
  behind the Accept test, because stripping it from a page request is the thing
  that test exists to prevent.
- A request carrying **two `Last-Event-ID` headers** had the first checked and
  both forwarded. Which one an application reads is its framework's business, so
  a policy that validated one of them validated the wrong one: both are now
  removed (`sse_last_event_id_repeated`).
- **`last_event_id_pattern` was anchored at its ends rather than around the
  whole pattern.** `|` has the lowest precedence in RE2, so
  `[0-9]{1,19}|[0-9A-HJKMNP-TV-Z]{26}` -- the estate whose identifiers are a
  counter or a ULID -- compiled to "starts with a digit, or ends with a ULID",
  which admits `1' UNION SELECT secret FROM audit--`.

**Kerberos over HTTP.**

- **`refuse_weak_etypes` was one integer away from being switched off.** It asked
  whether every type a request offered was on a list of weak ones, so a number
  the registry has never assigned counted as a strong offer: `etype = { 23, 9999 }`
  read as a mixed list, the KDC discarded 9999 and minted the RC4 ticket. It now
  asks whether the request offers a type this estate is content with. `des-cbc-raw`
  and `des3-cbc-raw` joined the weak list while there.
- **`refuse_preauth_exempt` rested on padata the client writes.** This relay holds
  no key, so three random octets under type 2 read exactly like an encrypted
  timestamp; one padata item a KDC passes over was enough to make an AS-REP
  roaster's request look pre-authenticated. The test now pairs the claim with the
  KDC's answer: a type the KDC must decrypt to act on counts, and a PKINIT claim
  counts when the reply carries `PA-PK-AS-REP`.
- **The minted KRB-ERROR named the control that fired**, which made every refusal
  an oracle -- `preauth_not_required` confirms the account exists and is
  roastable, a cleaner answer than the AS-REP it was refused. The text now names
  the proxy and nothing else; the reason stays in the security log and the
  counters.
- **S4U2Self was recognised under one of its two names.** MS-SFU defines
  `PA-S4U-X509-USER` beside `PA-FOR-USER` and a KDC honours either, so
  `allow_s4u2self: false` had a second door, and the impersonated name was not
  read -- which meant principal rules were applied to the service asking rather
  than the user asked for.
- **The DER reader resolved a field named twice instead of refusing it.** A
  req-body with two `realm` fields was decided about as one realm and acted on by
  a KDC as the other, with the audit record wrong in the same direction as the
  decision. A repeated context tag is now refused; no Kerberos structure uses one
  twice. `only()` now requires a constructed tag and `derString` checks the
  universal tag rather than only the class.

**RADIUS and TACACS+.**

- **`max_privilege_level` read the grant through a text-safe accessor**, so a
  Cisco av-pair with a NUL in it -- the pair separator several platforms use --
  read as "this reply grants no privilege" and the bound never applied. Every
  av-pair is now read from its raw octets, every pair inside one, every
  `Service-Type`, and the highest grant found is the one bounded.
- **A TACACS+ deny matched only the exact words it named**, so
  `deny_commands: ["show running-config"]` matched the spelling an operator would
  type and missed `show running-config | include password`. A deny now covers the
  command and whatever is appended to it; an allow stays exact, because allowing
  more than was asked is the unsafe direction.
- **A TACACS+ rule's command lists replaced the listener's rather than adding to
  them**, so any rule carrying a `deny_commands` of its own disarmed every
  estate-wide deny for the traffic it covered. The deny lists are now a union and
  the allow lists an intersection: a rule narrows and never widens.
- **The user lists did not see a name typed at the server's prompt.** RFC 8907
  §5.4.2 lets an ASCII login leave the START's user field empty and supply the
  name in a CONTINUE, which is the ordinary shape of `telnet` to a router -- and
  `users`, `deny_users` and the estate's authorization rules never saw it. The
  name is now read from the CONTINUE that answers a GETUSER, which is the one
  reading this relay takes of that field.

**The mailbox protocols.**

- **A SASL exchange was a hole in every other control.** Between `AUTHENTICATE`
  and its tagged answer the client's lines are credential material and are
  forwarded unparsed -- so `a1 AUTHENTICATE XNOTAMECH` followed by
  `a2 LOGIN victim Hunter2` had the second line forwarded past the command lists,
  the mailbox lists, the user list and the log, while the server, having answered
  the mechanism it does not implement, read it as a command. The exchange is now
  lock-step: a client line is credential material only in answer to a
  continuation request this relay saw the server send (`auth_injection`).
- **An argument sent as a literal was invisible to the policy.** A literal is the
  last token on the line, so `SELECT {21+}` parses as SELECT naming no mailbox:
  `mailboxes`, `deny_mailboxes`, the rule selectors, `users` and the estate's
  authorization question each decided about nothing while the server received the
  name intact. Such a command is now refused (`literal_argument`).
- **A refused command's synchronising literal was read anyway.** `Literal.NonSync`
  was parsed and never consulted, so a refused `{64}` -- which the client is
  waiting to be asked for and must not send -- made this relay block, and then
  swallow the next 64 octets it was sent for any other reason. Only a `{n+}` is
  dropped now, the refusal is written first, and the rest of that line goes with
  the octets.
- **An anomaly refusal dropped the command but not its literal**, so a message
  body became the command stream. It now drops what the client committed, the
  same as a policy refusal.
- **A chained literal was checked against the listener's bound rather than the
  rule's**, so a rule tightening `max_append_bytes` for one account applied to the
  mailbox name and not to the message. The rule that decided the command now
  decides its continuations, and the bound is on the chain's total.
- **`deny_mailboxes` was case-sensitive below INBOX.** RFC 9051 §5.1 makes `INBOX`
  case-insensitive and a server with mail under it folds that component too, so
  `inbox/Finance` and `INBOX/Finance` were two patterns here and one mailbox
  there. The fold now covers the first component; everything below it stays
  case-sensitive.
- **A bare POP3 `AUTH` authenticated the session in this relay's view.** It names
  no mechanism, so neither `require_tls` nor `mechanisms` had anything to decide,
  and the server's `+OK` moved the state to transaction with nobody logged in --
  after which `RETR`, `LIST` and `DELE` all passed the state table. It is refused
  (`auth_no_mechanism`); CAPA is where a client reads the mechanism list.

**And one shared with every kind that has rules.**

- **An `observe` rule decided by allowing what it covered**, which the reference
  has never said: it promises a rule that records and keeps looking. Placed above
  a deny rule it switched that rule off, so trying a rule on live traffic was the
  most dangerous edit in a configuration -- and on a listener whose
  `default_action` is `deny`, a trial rule turned the default off too.

  Fixed in every kind that had it: `radius`, `tacacs` and `kkdcp` first, then
  `amqp`, `mysql`, `postgres`, `redis`, `s7` and `tds`. An observe rule is now
  recorded on the decision (`observed` in the log line) and decides nothing, and
  one piece of code per kind chooses both the rule that decides and the rules
  that are only recorded, so the two cannot drift apart. `bacnet`, `mms`,
  `modbus`, `iec104`, `snmp` and `opcua` already read it the documented way --
  `opcua`'s `match` skips an observe rule with the comment this sweep went on to
  copy -- and the reference rows for all of them now describe the behaviour in
  the same words, including what happens under a deny default, which none of
  them said before.

  Two tests had asserted the old reading, one in `mysql` and one in `postgres`,
  both named "an observing rule decides nothing" while checking that it
  *allowed* the traffic. They now check what the name says: the trial decides
  nothing, the default or the deny rule below it decides, and the rule's name is
  in `Observed` either way.

### Added (the other half of mail: the two mailbox protocols)

- **`kind: imap` is a relay in front of the most complete record an estate
  has.** A mailbox holds every decision, every negotiation, every password
  reset and every attachment somebody sent "just so you have a copy", and IMAP
  is the protocol for reading all of it with one credential, from anywhere, as
  many times as you like. That makes it a different problem from the submission
  relay next door: a proxy in front of SMTP sees one message on its way out and
  can decide about it, and a proxy in front of IMAP sees a client that has
  already authenticated asking for everything that ever arrived. The request
  worth stopping is not malformed, oversized or strange — it is
  `UID FETCH 1:* (BODY[])`, which is what a mail client's first synchronisation
  and an emptied account look like character for character.

  So the bound is on **how much a request names**. `max_fetch_messages` counts
  the messages in a sequence set on the command line — not what comes back —
  and refuses before the mail server has read anything; a set is counted
  without being expanded, so refusing `1:20000` costs nothing. An open-ended
  set (`1:*`, `*`) is refused outright rather than counted, because the size of
  that request belongs to the mailbox and not to the client, and
  `allow_open_sets` plus a `rules` entry for the one account that legitimately
  synchronises everything are the two ways to write the exception down.
  `max_append_bytes` is checked against a literal's **declared** size, because
  RFC 7888's LITERAL+ sends the octets without waiting for anybody to agree —
  and a refused command's octets are then read and dropped rather than left to
  desynchronise the connection, since the client announced them and is going to
  send them whatever it is told. [AMR-054](AMR.md) is the reasoning.

  The rest of the policy is the shape its siblings use, with two details the
  protocol forces. The command set is checked against **RFC 9051 §3's state
  table**, which is the relay's own, so a `FETCH` that arrives before a
  `SELECT` is answered here and the mailbox never sees it; and a mailbox name
  is compared **decoded**, because RFC 3501 §5.1.3 spells a non-ASCII name in a
  modified UTF-7 — `~peter/mail/&U,BTFw-` and `~peter/mail/台北` are one mailbox
  — and a policy that compared the spelling would compare nothing. `*` matches
  across the hierarchy and `%` within one level, exactly as IMAP's own `LIST`
  does, so `Shared/%` admits `Shared/HR` and not `Shared/HR/Payroll`. `UID
  FETCH` is the command it qualifies, so it is not a way to spell something the
  policy refuses.

  Three refusals are about what the *server* said. The **capability list is
  narrowed**: a mechanism `mechanisms` will refuse is removed and
  `LOGINDISABLED` added where `LOGIN` would be refused, which RFC 3501 §6.2.3
  makes the way a server says so — a client that reads it asks for something it
  can use instead of sending a password into a refusal. `COMPRESS=DEFLATE` (RFC
  4978) is removed and refused, because a deflated connection cannot be
  inspected and advertising it would be an offer to stop. And a **`PREAUTH`
  greeting** is refused: it says the connection is authenticated before anybody
  claimed an identity, which would make every later decision here about a name
  this relay never saw.

- **`kind: pop3` is the same five questions, in the shape a protocol with one
  mailbox allows.** POP3 is what IMAP replaced and it is still configured on
  the things nobody revisits — the script that pulls invoices off a mailbox,
  the multifunction printer that mails scans, the integration written before
  anybody asked which protocol it used — and it is the protocol whose whole
  purpose is to move a mailbox somewhere else.

  There is no sequence set here, so the bound is a **running total**, counted as
  the octets pass and enforced *mid-transfer*: `max_retr_bytes` and
  `max_messages` against what this connection has already taken. A bound
  applied only before a command is one a client walks past one message at a
  time, and a single `RETR` of a very large message is a mailbox copy by
  itself. Reaching the message bound is a refusal the connection survives;
  crossing the byte bound inside a message ends the connection, because a
  truncated message presented as whole would be worse.

  Two smaller things are where a relay on this protocol goes wrong. **Whether a
  reply is one line or many depends on the command *and its argument*:** `LIST`
  lists the mailbox and `LIST 3` answers one line about message 3, `UIDL` the
  same, and a relay that guesses reads the next reply as part of this one —
  after which a client is shown somebody else's mail or none of its own. And
  the **greeting is carried unchanged**, because the `<1896.697170952@mail>` in
  it is what an APOP digest is computed over; a relay that minted its own
  greeting would make every APOP digest unverifiable at the server that has to
  check it. §3's dot-stuffing is handled as SMTP's is, and the server's line is
  forwarded verbatim rather than stuffed a second time.

  `read_only` refuses `DELE` and `RSET`, which is what the things that still
  speak POP3 here should be doing anyway and is also what makes the server's
  copy the audit trail.

- **Both kinds refuse a credential on a transport that cannot carry it, and
  neither refusal is shadowable.** `require_tls` defaults on and refuses
  `LOGIN`, `AUTHENTICATE` with a plaintext mechanism, `USER`/`PASS` and `APOP`
  on an unencrypted connection — in `monitor_only` too, because by the time a
  policy could be consulted the password has travelled and observing it does
  not un-send it. On 143 and 110, `tls_mode: starttls` has the relay terminate
  the RFC 2595 upgrade itself rather than forwarding it, which is how the
  devices and scripts nobody can reconfigure get TLS anyway; anything pipelined
  behind the upgrade ends the session, the same reasoning (and the same CVE
  class) as the smtp kind's.

- **Fifteen counters, six refusal families and the ATT&CK mappings.**
  `imap_connections`, `imap_commands`, `imap_auth_failures`,
  `imap_fetched_messages`, `imap_append_bytes`, `imap_plaintext_logins`,
  `imap_capabilities_stripped`, `imap_preauth_refused`; `pop3_connections`,
  `pop3_commands`, `pop3_auth_failures`, `pop3_retrieved_bytes`,
  `pop3_deletes`, `pop3_plaintext_logins`, `pop3_capabilities_stripped`. Every
  refusal is bannable — `imap_denied`, `imap_auth_failed`, `imap_anomaly`,
  `pop3_denied`, `pop3_auth_failed`, `pop3_anomaly` — and carries its
  Enterprise ATT&CK technique: **T1114 (Email Collection)** and **T1114.002
  (Remote Email Collection)** on every bound refusal, which is what these kinds
  are for; T1071.003 (Mail Protocols) on an unknown command or one in the wrong
  state, because a relay that carries what it cannot name is a tunnel; T1556 on
  the PREAUTH greeting, T1562 on the refused compression, T1557 on an upgrade
  injection, and T1110 on the credential bursts the ban ladder acts on. The
  behavioural models get the account, the mailbox, the command and the number
  of messages named, and unlike the TACACS+ kind's a finding here reaches the
  ban ladder — these clients are people's mail applications, and the cost of
  being wrong is a client that reconnects.

- **Documentation and examples.** Two sections in [CONFIG.md](CONFIG.md), two
  protocol pages under [docs/protocols](protocols/README.md) with a new "The
  mailbox protocols" group in the index, [`examples/mail/mailbox.yaml`](../examples/mail/mailbox.yaml)
  (IMAPS, IMAP with the upgrade terminated here, and a read-only POP3S, with
  the archiver's exemption written as a rule and two ban triggers), the two
  kinds in [README.md](../README.md), [ARCHITECTURE.md](ARCHITECTURE.md) and
  [USAGE.md](USAGE.md), a "Mailboxes" section in [RFC.md](RFC.md) for the
  seventeen specifications they implement and the one they refuse, five rows in
  [THREAT_MODEL.md](THREAT_MODEL.md), and [AMR-054](AMR.md) for the decision
  that on a mailbox the bound is on what a request names — and that two of
  these refusals are deliberately outside shadow mode.

### Added (the three authentication protocols an estate's own equipment uses: RADIUS, TACACS+ and Kerberos over HTTP)

- **`kind: radius` is a relay in front of the protocol whose integrity check is
  optional.** A RADIUS Access-Request carries a nonce in its Request
  Authenticator and the reply carries an MD5 digest over that nonce, the body
  and the shared secret -- and CVE-2024-3596 (Blast-RADIUS) is a chosen-prefix
  collision on exactly that digest, which turns an Access-Reject into an
  Access-Accept for anybody on the path. The protocol's own mitigation has
  existed since RFC 3579: a keyed Message-Authenticator attribute. So
  `require_message_authenticator` defaults to **on**, the relay verifies both
  authenticators on both legs before it decides anything, and a rule can admit
  the one piece of equipment too old to send a digest without turning the check
  off for the estate.

  Which authenticator a code carries is part of the check rather than a
  detail. Access-Request, Status-Server and Status-Client carry a nonce;
  Accounting-Request and the RFC 5176 codes carry a *computed* digest over
  sixteen zero octets, so verifying those against the bytes they arrived with
  accepts anything at all. The relay computes what each code must carry.

  The policy is written in the protocol's terms: which codes may cross, which
  authentication methods may be negotiated (`auth_types`, with EAP read where a
  packet carries one), which EAP methods (`eap_types` -- refused whether the
  packet offers one or Naks toward it, because a downgrade asked for the second
  way is still a downgrade), which attributes may appear, and
  **`max_privilege_level`, which is a bound on what a reply may grant**: a
  Cisco av-pair carrying `priv-lvl=15` is how a RADIUS answer hands out enable
  on a switch, and that is a decision about the answer, as the dhcp kind's
  whole policy is. A plaintext User-Password is recognised and counted and
  never undone. RFC 5176 dynamic authorization -- an unsolicited packet that
  logs a session out -- is refused rather than carried.

  It is a datagram kind, and the protocol's identifier is eight bits, so two
  clients using the same identifier would otherwise collide in one upstream
  conversation. The relay keeps a bounded table per client and renumbers, which
  forces it to recompute both authenticators, which it can only do because it
  holds a secret for each leg (`secret_file`, `upstream_secret_file`, owner-only
  modes enforced at load; no secret is ever written in the configuration file).

- **`kind: tacacs` is where a policy can say which command.** TACACS+ asks the
  server about each command line a person types on a switch, so this is the one
  protocol in the estate where authorisation is per command rather than per
  session -- and device administration is what it carries. A rule names the
  users, the devices and the command lines: `commands: ["show ...", "configure
  terminal"]` as an allow list, or `deny_commands` as the narrower statement,
  with `...` as a trailing wildcard and nowhere else, because a pattern whose
  wildcard is in the middle describes a command line that ends where nothing
  follows it. The command arrives split across a `cmd` argument and its
  `cmd-arg` arguments; the policy is written as the single line the engineer
  typed.

  RFC 8907 section 10.3 says of its own body obfuscation that it is "not
  cryptographically sound" -- it is an MD5 pad keyed by the secret and the
  sequence number, and it is also the only confidentiality the protocol has. So
  the kind implements it for what it is, refuses a body sent with the
  unencrypted flag, and offers TLS toward equipment new enough to have it
  (`upstream_tls_mode`). A `FOLLOW` reply, which hands the device another
  server's address, port and key, is never carried -- not in shadow mode
  either, because a compromised server that can redirect the next
  authentication has not been contained by observing it.

  `max_privilege_level` bounds what a response may grant, as on the radius
  kind. Several sessions share one connection in single-connection mode and are
  kept apart by session identifier, with sequence numbers checked in both
  directions. And the configuration, restart, firmware and file-transfer
  commands are mapped to **engineering operations**, so a change to a switch is
  checked against the same work order, grant and ledger a change to a PLC is.

- **`kind: kkdcp` is a Kerberos KDC proxy (MS-KKDCP) that holds no Kerberos
  key.** Everything a policy needs is in the cleartext of a KDC message -- the
  realm, the client and service principals, the encryption types offered, the
  pre-authentication types present, the requested lifetime and options -- and
  everything else is encrypted in keys that belong to the KDC and the service.
  So this kind parses the KDC-PROXY-MESSAGE envelope and the message inside it
  (`internal/kerberos`, with a DER reader that refuses indefinite and
  non-minimal lengths, bounds nesting and depth, and refuses control characters
  in a principal name), decides, and forwards the bytes it received or mints a
  **KRB-ERROR of its own** -- because a Kerberos client reads Kerberos errors,
  not HTTP statuses.

  Three attacks are the reason the kind exists. **Kerberoasting** is a TGS-REQ
  that asks for RC4 and nothing else, so that the service ticket can be cracked
  offline against the service account's hash: `refuse_weak_etypes` refuses a
  request offering nothing but DES or RC4, and a mixed list is not refused,
  because that is the client asking for what it can use. **AS-REP roasting** is
  visible on the *reply* -- an AS-REP to a request that carried no
  pre-authentication is the roastable material -- so `refuse_preauth_exempt`
  decides about an answer. **Password spraying** is bounded per client address
  by `max_preauth_failures`, and service-ticket enumeration by
  `max_distinct_services`; both reach the ban ladder, which on this kind is
  where the anomaly findings go. Constrained delegation is two halves,
  S4U2Self and S4U2Proxy, each separately allowed.

  It is the first kind served by `xproxy` **and** `xrelay` rather than by the
  two service-facing daemons. MS-KKDCP exists so that a client outside the
  network can reach a KDC inside it, so the edge owns it by default and an
  estate that runs one in front of its own domain controllers writes
  `daemon: xrelay`. Its transport is HTTPS on one path and one method, and the
  kind refuses to build without a certificate, because the message it carries
  holds a value derived from the user's password.

- **Eighteen counters, three refusal families and the ATT&CK mappings.**
  `radius_requests`, `radius_bad_digest`, `radius_no_digest`,
  `radius_plaintext_passwords`, `radius_privilege_grants`,
  `radius_unsolicited`; `tacacs_sessions`, `tacacs_commands`,
  `tacacs_accounting`, `tacacs_header_only`, `tacacs_plaintext_passwords`,
  `tacacs_privilege_grants`; `kkdcp_requests`, `kkdcp_preauth_failures`,
  `kkdcp_weak_tickets`, `kkdcp_preauth_exempt`, `kkdcp_delegations`,
  `kkdcp_realm_mismatch`. Every refusal is bannable
  (`radius_denied`, `tacacs_denied`, `kkdcp_denied`) and carries its
  Enterprise ATT&CK technique: T1558 and its Kerberoasting (.003) and AS-REP
  roasting (.004) subtechniques, T1550 for the stolen ticket, T1556 for the
  modified authentication process, T1548 for the privilege grant, T1601 for the
  modified device configuration, T1602 for the configuration repository dump,
  T1529 for the remote restart, and T1562 for the defences a `no logging`
  command turns off. `tacacs` joins the kinds that emit engineering events, so
  four of those mappings are engineering ones.

- **Documentation and examples.** Three sections in
  [CONFIG.md](CONFIG.md), three protocol pages under
  [docs/protocols](protocols/README.md) with a new "Authentication,
  authorisation and accounting" group in the index, three examples
  (`examples/auth/radius.yaml`, `tacacs.yaml`, `kkdcp.yaml`), the three
  listener kinds in [README.md](../README.md), [ARCHITECTURE.md](ARCHITECTURE.md)
  and [USAGE.md](USAGE.md), a new section in [RFC.md](RFC.md) for the
  specifications they implement and refuse, four rows in
  [THREAT_MODEL.md](THREAT_MODEL.md), and
  [AMR-053](AMR.md) for the decision that the two symmetric-secret kinds
  re-originate and the KDC proxy holds no key.

### Fixed (a reload that drops nothing, including on a datagram listener)

- **A datagram listener could not be reloaded at all.** A UDP socket cannot be
  bound twice, and a rebuilt listener opened its own: so a reload that changed
  anything on a `tftp`, `ntp`, `dhcp`, `dhcpv6`, `bacnet` or `coap` listener, or
  on the datagram side of `syslog` or `snmp`, failed with `bind: address already
  in use` — about a port this process was itself holding. For the three cases
  the engine did know bound UDP (`kind: udp`, plain `dns`, and any listener with
  `h3`) it refused the reload up front and asked for a restart instead, which is
  the same hole with a better error. An estate whose OT relays are datagram
  protocols could not change a policy without stopping the daemon.

  The datagram socket is now owned by the engine for the listener's life and
  handed from one generation to the next, exactly as the accept socket has been:
  a `packetSource` holds it and each generation reads a `packetFront`, which can
  be closed without closing the socket. Those fronts are closed before the new
  generation serves, so from the moment of the switch every datagram is answered
  by the generation whose policy decided it — on these protocols a datagram is a
  whole conversation, and one answered under the old rules a moment after a
  reload is the bug an operator would report. Nothing is lost in between: the
  socket is never closed, so what arrives during the handover waits in its
  receive buffer. Writes are not stopped, because a reply the retiring
  generation is composing belongs to a request it accepted.

- **"Restart required" now means QUIC, and nothing else.** A QUIC connection is
  not a datagram: it is cryptographic state inside the transport that holds the
  socket, so handing the socket over would end every connection on it. That is
  the one change a reload still refuses — a listener carrying `h3`, `tcp.quic`
  or `dns.doq` changed on the same address — and the refusal now says why.
  `config.ListenerHasQUIC` is what the engine and the dry run ask, where both
  used to ask whether the listener bound UDP at all.

- **Three documented limits were not limits.** The forward listener's page said
  "the address and TLS settings need a restart like every listener": both
  reload, the TLS settings by rebuilding the listener on the socket it already
  holds and the address by binding the new one while the old drains. The dns
  listener's page said "the address needs a restart"; it is the one change that
  always worked. "Changing a tcp listener needs a restart" was true only with
  `quic: true`. All three are corrected, and `docs/ARCHITECTURE.md` now
  describes the datagram handover beside the stream one.

### Added (WebSocket: a message policy, not only a frame policy)

- **`websocket_guard.types` is the policy the application actually has.** The
  frame bounds beside it answer the protocol's question, which is the same on
  every route; `max_message_bytes` for a connection is the bound of its largest
  message, which is the bound that lets every other message be that large too. A
  route now names the kinds of message it carries — `type_field` is the JSON
  member that names one, `type` by default — and gives each its own `max_bytes`,
  its own `messages_per_second` (per connection and per direction), its own
  `direction`, and a `schema_file` every message of that type must match. A
  keepalive and an order stop sharing one bound.

- **`unknown_types` is the positive half**: `deny` refuses a message whose type
  the route does not name and is the default once `types` names anything, because
  a list of what a route carries that also carries everything else is not a list;
  `observe` records it and forwards it, which is how the list gets written from
  the events and `xproxy_websocket_unknown_type_total` rather than from somebody's
  memory of the API; `allow` ignores it, which is every configuration written
  before this existed. `require_json` is the same question about a text message
  that is not JSON at all.

  Where each check decides is stated rather than implied. A type is read out of a
  complete message: from the client that is still before anything reaches the
  origin, because the guard already holds a client message until the whole of it
  has passed inspection; from the origin it is at the end of the message, because
  each frame is forwarded as it is checked. A schema needs the whole message, so
  one larger than `max_inspect_bytes` is refused rather than passed — a check that
  stops applying above a size the sender chooses is not a check — and validation
  warns where a type's `max_bytes` makes that certain.

- **`websocket_guard.compression` makes compression a decision instead of a
  silent downgrade.** `strip` is what the previous version did and is still the
  default: the client's `permessage-deflate` offer is taken out of the upgrade, so
  both ends fall back to uncompressed frames. `refuse` answers the upgrade with
  400 instead, for an estate that would rather a client's own logs recorded it.
  `inspect` is new ground: the offer forwarded to the origin is narrowed to
  `permessage-deflate; client_no_context_takeover; server_no_context_takeover`,
  which makes every message a DEFLATE stream of its own, and each message is
  inflated before the rest of the policy reads it. An acceptance that is not that
  offer — an origin that kept context takeover, or claimed an extension nothing
  offered — is refused at the 101 with 502, because a stream the guard cannot
  inflate would leave it choosing between closing every connection and reading
  nothing.

  So a route can now be compressed *and* inspected, which it could not be
  before: an estate that wanted its WebSocket messages read had to make every
  client send them uncompressed. `max_inflate_ratio` (default 100) is the bound
  that comes with that — a kilobyte on the wire becoming a megabyte in the
  application is the shape of the attack rather than the size of it, and past it
  the message is refused as `compression_bomb` without being inflated further.
  The sizes, the UTF-8 check, the patterns, the type and the schema are all about
  the inflated message, because that is the message.

- **The report says which type a route is arguing with.** `GET /v1/websocket`
  and `xproxyctl` carry the per-type message and violation counts, the
  compression mode, and how many messages arrived with a type the route does not
  name; the metrics are `xproxy_websocket_type_messages_total{route,type}`,
  `xproxy_websocket_type_violations_total{route,type}` and
  `xproxy_websocket_unknown_type_total{route}`. Every finding names itself in its
  event: `compression`, `compression_bomb`, `json`, `message_type`, `type_size`,
  `type_rate` and `schema` join the frame guard's own reasons.

- **`docs/protocols/http.md` says what happens after the 101**, which it did not
  mention at all: what the guard decides, and that a WebSocket over HTTP/2's
  extended CONNECT is not served (so clients fall back to the upgrade the guard
  reads) while a WebTransport session is relayed rather than inspected.

### Added (forward proxy: HTTP-aware inspection inside intercepted tunnels)

- **`intercept.http` reads the requests inside a tunnel this listener is already
  decrypting, so the egress rules about a method, a path, a content type or a body
  size decide there too.** Those selectors could only ever be decided on a plain
  request through the proxy, which on an estate whose egress is nearly all HTTPS
  meant they were a policy about almost nothing; the previous version said so in
  its validation and its documentation, which is better than pretending otherwise
  and is still not a policy. A decrypted tunnel carries ordinary HTTP messages:
  each request is read, decided about and relayed, each response head is decided
  about before its body travels, and it is the same rules, the same two phases, the
  same events and the same counters as port 80 — because an operator should not
  have to learn that a rule means one thing on one port and another on the next.

  `auto` is the default and reads when there is something to decide, which is when
  the listener has at least one rule needing a visible request: a policy about
  destinations alone gains nothing from parsing, and an upgrade does not change
  what a deployment does. `on` reads every intercepted tunnel, which is what to
  set while writing such rules so the access log carries the requests first. `off`
  relays the plaintext to the stream rules and to nothing else, and validation
  warns when rules that need a request are written on a listener set that way.

- **A refusal inside a tunnel is an HTTP 403 on the connection the client believes
  is end to end**, naming the reason, after which the connection closes — keeping
  it alive would mean reading the rest of a body nobody is allowed to send, which
  is a bound an attacker would be choosing. The access line is
  `forward_intercept_request` with the method, the destination and the status: the
  method and not the path, because this listener logs destinations rather than URLs
  everywhere else, and an intercepted connection is the last place to start
  writing down more of what somebody asked for.

- **The `Host` header is held to the destination the tunnel was opened to**, under
  the same `sni` setting and for the same reason as the server name: otherwise a
  client permitted to reach one name uses the connection to that name's address to
  ask for another. `enforce` answers 403 with reason `host_mismatch`, `observe`
  records `forward_tunnel_host_mismatch` and relays, `off` does not look; a tunnel
  opened to an address is the same exception it is for `sni`. The new reason maps
  to T1572 and T1090, and a ban trigger can name `forward_host_mismatch`.

- **A head the proxy cannot frame is refused rather than passed on.** A request
  carrying both a length and a chunked encoding is the request-smuggling shape, and
  an intercepting proxy is the only place in this project that can see one inside
  TLS at all: 400, reason `bad_request`, event `forward_tunnel_bad_request`, mapped
  to T1190. Requests that are relayed are relayed as they arrived — no `Via`, no
  forwarded headers — because the point of interception here is that the
  destination sees the message the client wrote and the policy judged.

- **Three things are relayed as bytes rather than read, and each is counted**, so
  "nothing was read" is never a silent answer: a tunnel that negotiated `h2`, since
  this reads HTTP/1 and a proxy guessing at HTTP/2 framing corrupts the stream it
  is inspecting; a tunnel whose first bytes are not a request line, since SSH, a
  database session and a line protocol inside TLS all happen and answering one with
  a 400 breaks it for no reason; and everything after a 101, since the connection
  has stopped being request-and-response and a WebSocket through an intercepting
  proxy is ordinary traffic. The counters are `forward_intercept_requests` and
  `forward_intercept_bytes_only`.

  Whether the first bytes are a request line is decided by the version at the end
  of the line and not by a list of methods, so `PROPFIND` and everything else an
  extension invented is still HTTP.

- **`GET /v1/listeners` carries an `egress` section for a forward listener with
  rules**: how many there are, how many of them need a visible request, and
  whether this listener reads inside the tunnels it decrypts. The previous
  version's documentation promised that count and nothing served it — the policy
  built a report that no endpoint reached. The two numbers belong side by side,
  because rules that need a request on a listener that is not reading are a
  policy about the plain path alone.

- **The stream rules still see everything.** The scanning sits on the reads rather
  than on the message bodies, so YARA sees the heads in both directions exactly as
  it did when the tunnel was relayed unread: turning on a policy feature must not
  turn off a detection one. A match in a head stops the request there, before it is
  relayed, which is what the same rule did when this tunnel was bytes.

### Added (forward proxy: an egress policy about who may send what, where and when)

- **`forward.rules` is the egress policy, and `forward.categories` is what it is
  written in.** `allow` and `deny` said whether a destination exists for a
  listener; these say who may reach it, with which method, carrying which content
  type, inside which hours. A rule names any of users, groups, networks,
  categories, hosts, ports, methods, path globs, request and response media types,
  request and response body bounds, and a schedule; first match decides, `observe`
  records and keeps looking, and a destination no rule matched is refused under
  `no_rule` — the same shape the OT relays use, for the same reason. A category
  takes its patterns inline or from a file, because the list an estate actually
  has came from somewhere else and is long.

  An `allow` rule means this policy has nothing to object to; it does not skip
  what follows. The imported threat lists and the estate's own `authorization`
  section still decide, so a listener's rule narrows the estate's policy and can
  never widen it.

- **`forward.auth.groups` gives the listener an identity to write rules about** —
  and gives the estate-wide `authorization` section something to compare its
  `groups` selector against on this listener, which it had had nothing to put in
  since it was written.

- **`forward.sni` checks the server name inside a tunnel nothing is decrypting.**
  A client allowed to reach a CDN could open a tunnel there and then handshake for
  anything else that address serves, which is how domain fronting gets through a
  name-based allow list: the destination policy had decided about a name the
  client then did not use. `intercept` has carried this check for its own tunnels
  since it was written; this is the same check for the ordinary case, and it costs
  a peek at bytes the client was going to send anyway. `enforce` refuses,
  `observe` (the default, so nothing changes for an existing deployment until an
  operator asks) records and relays, `off` does not look. A handshake with no
  server name — which is what Encrypted Client Hello looks like from here — is not
  a mismatch, and neither is a tunnel opened to an address.

- **What a rule can be decided from is stated rather than left to be
  discovered.** A plain request through the proxy carries its method, its path and
  its content types, so every selector decides about it. A CONNECT tunnel carries
  a destination and nothing else, so a rule naming a method or a content type is
  skipped there — and on an estate whose egress is nearly all HTTPS that means
  such a rule covers almost nothing without `intercept` over those destinations.
  Validation names those rules when nothing will read them — a listener with no
  `intercept` section at all, or one that intercepts with `http: off` —
  `GET /v1/listeners` carries the count, and `docs/protocols/forward.md` has a
  section on it. Reading those rules inside an intercepted tunnel is
  `intercept.http`, below.

  The other two limits are in the same places: a response rule is decided when
  the head arrives, which is after the destination was contacted — the body does
  not arrive, the request did leave; and a byte bound on a chunked body is counted
  as it travels and cut past the bound, because what has already gone cannot be
  recalled, which is why a size rule is worth less on egress than a destination
  rule.

- **`rule_deny` and `no_rule` on a forward listener map to T1048, T1567 and
  T1071**, so an egress refusal reads as exfiltration or as a channel in
  `xproxyctl techniques` rather than as a number. T1071 (Application Layer
  Protocol) and T1567 (Exfiltration Over Web Service) are new in the Enterprise
  catalogue.

- **`xproxyctl listeners` shows a kind's rule list as a guard.** Discovered by
  shape rather than listed per kind, so the fifteen kinds that have had a `rules:`
  section all along now say how many rules they are serving, which the inventory
  previously did not mention at all.

### Added (policy simulation: what a change would decide differently)

- **`xproxy-simulate` sends traffic through a configuration and reports what it
  decided; given two configurations it reports only what moved.** It is a
  separate, offline binary next to `xproxy-replay`(8): it opens no management
  socket, needs no running daemon, and every listener kind is linked into it, so
  it answers about a configuration naming any role's listeners without the
  operator working out which daemon would have served it. Exit status is 1
  whenever the two configurations decide anything differently, so a change can be
  gated on it in review or in a pipeline, and `-json` carries the whole answer
  including every security event.

  It is not a linter and it does not reason about the rules: it starts the engine
  and sends the traffic through it, so the answer comes from the code that would
  decide it in production — the same WAF profiles and rule files, the same route
  matching, the same protocol policies, the same filters.

- **Traffic comes from a text corpus of HTTP requests, a text corpus of protocol
  frames as hex, or a pcapng file written by `xproxyctl capture`.** The two text
  formats share a separator, comments and directives, and are text because of
  what an operator has in the minute they need this: a request out of a security
  log, a frame out of a vendor document, a ticket saying the shift supervisor's
  tool stopped working after the change. A format they can type, paste and keep in
  the repository beside the configuration is worth more than a richer one they
  would have to generate. The pcapng reader is round-tripped in its tests against
  the real capture writer rather than against a fixture somebody wrote by hand.

- **Nothing reaches a real upstream, and the output names everything that was
  switched off.** Every pool is pointed at a sink inside the process, keeping the
  pool names and the per-route assignments because which pool a request goes to is
  itself a decision; a TLS listener gets a throwaway certificate and the estate's
  private keys are not read; `cluster`, `fleet`, `acme`, `tracing`, `icap`,
  `scim`, `ingress`, `capture`, `threat_intel`, the OTLP exporter and `sandbox`
  are switched off. A test asserts that every one of the top-level configuration
  sections has a decision recorded about it, so a section added later cannot be
  left unconsidered.

- **Nothing is written outside the simulation's own directory.** The state a
  decision depends on — the ban store, the access ledger, the asset and API
  inventories — is copied into it, so a run starts from what the estate has: a
  banned address stays banned, a grant still approves, a device already in the
  inventory is not a new device. What a run produces — a learning report, a
  session recording — is redirected into it; those change no decision, which is
  why they were the half easy to overlook, and a learning report overwritten with
  a simulation's traffic would be the worst of them because those get promoted
  into policies. The output paths are found by type rather than by listing each
  kind's field, so the eight learning sections and five recording ones are covered
  and so is a kind added later. The configuration a caller passes in is deep
  copied first, since the promise that it is not modified cannot rest on somebody
  remembering to copy each struct before writing to it.

- **`-offline` is required rather than assumed, and what it promises is stated
  exactly.** Neutralising a configuration is not the same as making it inert: the
  policy runs, which means the filters, any WebAssembly modules, the rule files
  and the secrets provider load as the daemon loads them. That is the point — a
  simulation of something other than the real policy answers the wrong question —
  and it is a decision about this machine that belongs to the operator. The flag
  does not sandbox anything. It asserts.

- **An allow is asserted only on evidence.** The listener relayed the input to the
  sink, or answered the client itself; absence of a refusal is not evidence. A
  listener that speaks bytes rather than HTTP answers only when the device does,
  so a frame it could not finish reading produces no reply and no event at all,
  and reading that as `allowed` would put a hole in the report exactly where an
  operator would rely on it. Such an input is reported as `error` with what it
  probably is, and an input only one side could answer is counted as a change
  rather than as agreement. Documented limits: inputs are serial, so policy that
  depends on concurrency is not simulated; and the sink does not synthesise
  device replies, so policy that decides on a reply is not simulated.

- **A client address is delivered where the listener parses a PROXY protocol
  header, and reported as undeliverable where it does not.** `client=` on a
  corpus item, or the address out of a capture file, is sent as a header and
  loopback is added to `trusted_proxies` so it is read; both appear in the
  output. That makes address-based rules testable, which matters most on the
  plant, where an address and a unit identifier are much of what a policy has
  to work with. Where the listener parses no header the run names it and says
  the policy saw the loopback address, rather than answering as though the
  address had been used: an operator reading `allowed` for an input labelled
  with an address their allow list excludes would conclude the allow list does
  not work.

### Added (work orders: the change reference somebody filed, which is not an approval)

- **A work order can be filed against a device, from the Plant screen of the web
  interface, `xproxyctl workorder` or `POST /v1/workorders`.** It is the identifier
  the maintenance system already issued — `WO-2026-0481` — recorded against a
  device for a window, with a note saying what the work is, in the same
  hash-chained ledger as the grants. While it is open, every engineering event on
  that device carries `work_order` and `work_order_by` and says `severity: notice`;
  with nothing on file the same event says `severity: warning` and names no
  reference. `xproxy_engineering_filed_total{kind,operation}` counts the subset
  somebody filed, and the difference between it and `xproxy_engineering_total` is
  the list an operations centre works through.

  An engineering operation is worth an event either way — that has not changed.
  What was missing was the answer to "was anybody expecting this", for the
  estates that cannot yet run four-eyes approval on every program download but do
  already have the work order number.

- **A work order is not a grant and permits nothing.** A listener with
  `engineering.require_grant: true` refuses an operation with no approved grant
  whatever work orders are open, and the end-to-end test asserts exactly that. If
  it were otherwise, the person who wanted the access could file one for
  themselves and the approval requirement would be decoration. The distinction is
  stated in the configuration reference (a table: who agrees, what it permits, what
  it changes), in the command's own usage text, and above the form in the
  interface, which is where somebody is most likely to assume the opposite.

  The documentation used to use "approved work order" as a synonym for a grant,
  and one code path logged the grant's reason under the attribute name
  `work_order`. Both are corrected: a grant is a grant, its reason is
  `grant_reason`, and `work_order` now names a work order. `access.max_work_order`
  (default thirty days) bounds the window, because a work order with no end is the
  one somebody files during a shutdown and never closes.

- **`xproxyctl packs release ADDRESS -note ...` works as documented.** The tool's
  usage puts the name before the flags, which is the order people type, but Go's
  flag package stops parsing at the first non-flag argument — so every flag after
  the address was silently unset and the command printed its usage instead. The
  name is now taken off the front first, for `workorder` and for `packs release`.

### Added (the listener inventory, and a web interface that admits the other thirty-three protocols exist)

- **`GET /v1/listeners` and `xproxyctl listeners`: every listener with its
  protocol, its bound address, its enforcement mode and its guards.** `GET
  /v1/status` reported listeners as a map of name to address, which answers "is
  it up" and nothing after it. A proxy that speaks thirty-four protocols needs
  the kind and the mode beside the address before any other question can be
  asked, and "which of my listeners is not enforcing" could until now only be
  answered by re-reading the configuration file — which is the file somebody may
  have got wrong in the first place.

  The report gives, per listener: the kind, the role and daemon that own it, the
  address it actually bound (so a listener configured on port 0 reports the port
  the kernel handed out) and any further ports the kind took, `enforce`, `shadow`
  or `monitor`, whether it terminates TLS, whether it holds its socket, and the
  protocol's own guards — learning with whether it enforces what it learned,
  anomaly detection with its action, engineering restrictions with theirs,
  deception, session recording, a second factor, YARA, ICAP. Per protocol it
  gives the refusals by reason and, from a separate table that is never added to
  it, what the listeners in shadow mode would have refused.

  A guard row exists for every guard the *protocol* has, not only the ones this
  listener configured, so a listener with anomaly detection available and switched
  off reads as switched off rather than as absent. Engineering is reported as on
  where no block was written, because that is what the code does: an engineering
  operation is an event on an OT listener whether or not anybody configured one.

- **The web interface has a Listeners screen and a Policy screen.** Listeners is
  the inventory above, with the listeners that are *not* enforcing listed first
  and on their own — the one fact about a security proxy that must not be buried
  in a table — and what the refusals meant in ATT&CK terms underneath. Policy is
  the shadow ledger: what would have been refused, by kind, listener, reason and
  rule, with one clipped example each, the ledger's bound stated when it is full,
  and an operator button to empty it after a policy is fixed.

- **Every management read the control tool can make, the web interface can now
  make.** The pass-through table held twenty-five of them, chosen by whichever
  screen had been written, so an estate could be running behaviour packs,
  engineering restrictions, just-in-time grants and a shadow policy and the
  interface would not mention any of it. It is now the whole set: packs, policy,
  access, accounts, the API inventory, the device inventory's advisories, the bot
  score, capture, decoys, degradation, drains, the fleet, handshake refusals,
  maintenance, MASQUE, virtual patches, live sessions, the WebSocket guards and
  the three TLS views. `GET /v1/origin-check` stays out on purpose: it reads like
  a view and is a probe that dials the origins.

- **An Alarms screen: everything that is asking for attention, on one page.**
  Every fact on it was already reachable, in twelve different places, and an
  operator who has to visit twelve pages to find out whether anything is wrong
  visits none of them. A reload that failed, log records dropped, a hardening
  mechanism not in force, a listener configured and not listening, certificates
  near expiry, devices matching a published advisory, quarantined actors, any
  table that hit its bound, cluster peers down — and, kept separate, the states
  somebody chose and may have forgotten: maintenance mode, a drain, a listener
  in shadow mode. Three levels and no more, because a page that painted a chosen
  state red would be crying wolf at its own operator. When nothing is wrong it
  says so, naming what it checked.

- **Security, Plant and Sessions screens, and the fleet on the Cluster screen.**
  Security is the guards that are neither the WAF nor a protocol's own: virtual
  patches, deceptive answers, the WebSocket guards, the degradation levels,
  handshake refusals, the account guard, the bot score, the API inventory and the
  capture window. Plant is the OT half: the packs in force and who signed them,
  the just-in-time grants with their windows and approvals, the device inventory
  with what each device is and speaks, and the advisories matched against those
  firmware versions. Sessions is what is being served right now.

- **The navigation and the views are checked against each other, and so is every
  endpoint the page reads — and every view is now rendered against the real
  management API's own documents.** Nothing at run time noticed a menu entry pointing at
  a view nobody wrote — the reader lands on the overview with no error — or a view
  nothing links to. The second of those was already true: the ICAP page had been
  unreachable, and now has a link from the subsystems screen that reaches it.

  Six hundred lines of page JavaScript had never been run by anything. A test
  now starts a real data plane and a real management server, asks it for every
  document the page fetches, and renders all twenty views against what came
  back, under a DOM small enough to run the page and no smaller. A field renamed
  in Go, a list that is null rather than empty, a helper called with the wrong
  shape: each of those used to be a card that threw in one view, which is
  exactly where nobody looks until an operator needs it. The test skips where
  `node` is not installed, and it does not replace the manual browser check --
  it removes the part of it that was checking whether the code runs at all.

### Fixed (the refusal counter counted engineering operations it had forwarded)

- **An engineering operation outside every approved window is no longer counted as
  a refusal.** On a listener with `engineering.require_grant` and `action: alert`
  — the step every estate takes before it starts refusing — an operation with no
  grant open for it is carried and alerted, reason `engineering_ungranted`. Six of
  the eight kinds that recognise engineering routed that alert through the helper
  that increments `xproxy_refusals_total`, and the other two did not. So the
  refusal counter said the relay had refused a program download it had forwarded,
  and disagreed with itself between protocols for the same event.

  It now has a counter of its own, `xproxy_engineering_outside_window_total{kind,
  operation}`, on all eight kinds, and `engineering_no_grant` — the actual refusal
  — is the only engineering reason left in `xproxy_refusals_total`. The ATT&CK
  technique is still observed, because an operation outside every window is a
  detection whether or not anybody refused it, and the security event is byte for
  byte the one it was, so the behaviour packs that read it are unaffected.

  This surfaced while building the Listeners screen above, which prints refusals
  per protocol: a plant running `action: alert` showed a refusal count for a
  relay that had refused nothing.

### Fixed (an inspected WebSocket route broke every browser that offered compression)

- **The `permessage-deflate` offer is now stripped from an inspected upgrade
  rather than forwarded.** The guard refuses a frame with a reserved bit set,
  because a compressed frame cannot be inspected — but nothing stopped the two
  *endpoints* agreeing compression behind the proxy. Browsers offer the
  extension on every WebSocket by default, a compression-capable origin accepted
  it, the client was told it had succeeded, and then the first data frame tripped
  the reserved-bit check and the connection closed with a protocol error that
  blamed the peer for what this proxy had let through. So turning
  `websocket_guard` on broke every browser client of a compression-capable
  application, in a way that looked like the application's fault.

  Stripping the offer makes both ends fall back to uncompressed frames, which is
  what the extension is designed to do when it is not agreed: the client works,
  and the guard can read what it is inspecting. A reserved bit arriving anyway
  now means what the message says — a peer using an extension nobody negotiated.

- **An origin that claims an extension although none was offered is refused at
  the 101**, with `502` and a `websocket:extension` violation, rather than at the
  first frame. By then the client believes it has a working connection, and the
  frames would be unreadable.

- **The documentation said both things.** README claimed WebSocket "with
  permessage-deflate" as a supported feature; docs/RFC.md said no extension is
  negotiated on an inspected route. The first was false, and the second was true
  only of what the proxy itself did rather than of the path. Both now describe
  the behaviour above, as do the CONFIG, USAGE and TROUBLESHOOTING entries --
  including the troubleshooting advice, which used to tell an operator to drop
  the extension at the application or give up inspecting the route, and no longer
  needs to.

- **Why it is not decompressed instead is written down** in docs/RFC.md rather
  than left implicit: `permessage-deflate` keeps its dictionary across messages,
  so the state is per connection, and `client_max_window_bits` lets the peer
  choose how much of it the proxy holds -- which is exactly the "memory as a
  function of what a client sends" the guard is built to avoid. If it is ever
  added it is an explicit per-route opt-in with its own bounds, not a side effect
  of a client's offer.

### Added (behaviour packs as signed data, not as code and not as configurations)

- **`internal/packs` is a pack format and an evaluator**, and a pack is a file:
  versioned, so a build refuses one it cannot read rather than reading it wrong,
  and signed, so a directory a daemon reads at start is not a way into that
  daemon. Twenty-five ship in `packs/` and install to
  `/usr/share/xproxy/packs`.

- **Why data.** The first behaviour packs here were example listener
  configurations, and they are still in examples/ot/packs because a policy is
  what actually refuses a program download. But a detection that ships as a
  configuration has to be merged by hand into a policy somebody has already
  tuned, which happens once and never again; and one that ships as a *binary*
  cannot reach an estate that is not taking a new binary this quarter, which is
  exactly what a plant is. A pack is the shape that can be kept up to date.

- **What a pack decides about: the event stream, not a frame.** Every kind here
  already decides about frames with a policy an engineer wrote. A pack sits one
  level up, on the refusal reasons, behavioural findings and engineering
  operations those decisions produce -- which is the only layer the named tooling
  is visible at, because none of it exploited a protocol and what separates
  Industroyer from a control centre is the shape of a sequence across a quarter
  of an hour. It is fed from `logging.SecurityEvent`, the one place every such
  event already passes through, so a kind gains pack coverage by having a
  refusal reason rather than by remembering to call anything.

- **A pack cannot claim a detection this build cannot make.** It may only name a
  technique internal/attack has, a reason this build emits, and -- the check that
  matters most -- a reason that at least one listener kind of that signal
  actually emits. A Modbus-only pack naming an OPC UA reason fails to load
  rather than sitting in a directory looking like a detection. It is the same
  rule docs/ATTACK.md is held to, in the other direction.

- **Ten technique packs**, one per ATT&CK for ICS technique and written to be
  true of any tool using it: T0846 a new talker counting devices, T0861 the
  point list walked then a point driven, T0843 a download with no approved work
  order, T0845 logic read out, T0858 a mode change from a client that had never
  used the service, T0857 an image written to the boot server, T0816 a restart
  after refusals, T0832 frozen or replayed telemetry beside a write, T0806
  writes across the address space then a value outside the envelope, T0804
  reporting disabled then a change made behind it.

- **The named malware reworked the same way**: FrostyGoop, Industroyer on IEC 104
  and on MMS, PIPEDREAM's Modicon and OPC UA modules, Stuxnet on S7 -- each now a
  detection document as well as a configuration, with the configuration's own
  README saying which half answers which question.

- **Nine tooling packs**, for the software an estate actually meets including its
  own auditors': Nmap's control-protocol scripts, plcscan, smod, Metasploit's
  modbusclient and findunitid, Digital Bond's Redpoint, Snap7 as a programming
  device, the public OPC UA clients, the hand-driven IEC 104 masters, and
  COSMICENERGY -- which is the pack that needs the cross-listener window, because
  it sent its grid commands from a SQL Server inside the estate and neither
  relay sees it alone.

- **`across_kinds` is the statement no single listener can make.** One host on
  three control protocols in ten minutes is not a control system, and it is the
  cheapest true thing a pack can say. Three of the shipped packs use it.

- **Every pack declares the most it may do, and the file wins.** `alert` can
  never refuse whatever an operator configures, which is the right declaration
  for the twenty-one whose evidence is a shape -- the first legitimate thing a
  plant does after a quiet year looks very like the first illegitimate one. The
  four that declare `deny` rest on something named on the wire and still do
  nothing until `packs.enforce: true`; a test asserts that no pack may deny on
  behavioural findings alone.

- **A pack's deny is a quarantine and not a ban.** The actor is refused at
  admission -- in `internal/admit`, so on every listener of the daemon and not
  only the one that tripped the pack -- for the length of that pack's own window,
  under reason `pack_quarantine`, and then it is over. Nothing reaches the ban
  list, no ladder escalates, no prefix or fingerprint is banned, a restart clears
  it, and `xproxyctl packs release` lifts one early. **OT detections still never
  feed the ban ladder.**

- **The signature is a detached line**, `ed25519 <key name> <base64>`, over the
  pack's exact bytes, in `<pack>.yaml.sig`. Ed25519 and nothing else: a format
  with a choice of algorithm is a format with a downgrade. `xproxyctl packs
  keygen`, `sign` and `verify` are the tooling and none of them touches the
  management socket, because signing a directory happens on a machine that need
  not be running anything -- and verifying needs only the public half, which is
  the case that matters.

- **A file that does not load stops the daemon**, with the file and the reason
  named. That is the opposite of what a rule-set loader usually does and it is
  deliberate: a pack directory is small, curated and signed, so a file in it
  that does not parse is a mistake somebody made minutes ago rather than a
  reason to run with a detection missing.

- **A replay trace per pack**, in `packs/testdata`: the sequence the pack is
  about, which must report, and the same sequence one signal short, which must
  not. The suite replays all twenty-five on every run, so a count raised, a
  reason renamed in a kind or a window shortened past its own signals fails a
  test rather than quietly becoming a detection that never fires. Modbus has the
  end-to-end half: a signed pack in a directory, a real relay, a master that
  trips it, a quarantine at admission, and a release.

- **A finding is its own security event**: `pack_<id>`, with the pack's name and
  severity, the signals in the order they were satisfied, the protocols they
  came from, and the pack's declared technique in the usual four fields. Plus
  `xproxy_pack_match_total{pack,severity}`, the `pack_matches` snapshot field, a
  fact in the cross-listener window, and `xproxyctl packs` / `packs show`.

- **The operational surface with it**: `xproxy_packs_loaded`,
  `xproxy_pack_actors`, `xproxy_pack_quarantined`, `xproxy_pack_enforcing`,
  `xproxy_pack_actors_evicted_total` and
  `xproxy_pack_quarantines_refused_total`; three Prometheus alert rules (a
  high-or-critical finding, a quarantine in force -- which on a plant is a control
  room losing a master and is worth looking at even when the detection was right
  -- and the actor bound being reached, past which a sequence spanning the
  eviction is no longer detectable); four Grafana panels; `GET /v1/packs` and
  `POST /v1/packs/release`; and `pack_quarantine` documented in
  docs/TROUBLESHOOTING.md's deny-reason table with **no** in the Ban column and
  the reason why.

### Added (engineering activity as its own class of event, under the work order)

- **`internal/engineering` is a third question, beside "is this permitted" and
  "is this what this master has been doing": is there an approved work order
  open for it.** A program download, a CPU stop, a protection setting written,
  a firmware image pushed -- legitimate, necessary, and the operations an estate
  is actually compromised through. A relay that could only answer the first
  question has two bad options: a rule that allows downloads, which allows them
  at three in the morning from a laptop nobody knows about, or a rule that
  denies them, which the plant turns off on the first commissioning day.

- **Eight classes, the same names on every protocol**: `program_download`,
  `program_upload`, `mode_change`, `restart`, `configuration`, `firmware`,
  `method_call`, `file_transfer`. An operations centre asking "was anything
  downloaded to a controller this week" is not asking about a protocol, so the
  reason is `engineering_program_download` whether the download was an S7 block,
  a UMAS program write in Modbus function 90 or an MMS domain service.

- **Nine kinds classify their own traffic**: modbus, iec104, s7, mms, bacnet,
  opcua, snmp and tftp each have an `engineering` block, and each protocol page
  carries the table of which of its services this relay reads as engineering and
  why. `coap` deliberately classifies none, and its page says so: a CoAP path's
  meaning is the device's object model, so a relay guessing which URIs were
  engineering would guess per device and be wrong on the one that mattered.

- **The judgement in each table is the same line, drawn nine times**: this
  changes what the machine *is*, not what it is doing. A holding-register write
  is a setpoint and the value rules police it; a UMAS program transfer is not. An
  MMS `$CO$` write is a breaker being operated; a `$SG$` write is a protection
  relay's trip characteristic. An OPC UA `Write` to a value is an HMI; a write to
  `AccessLevel` changes what the *next* client may do. A TFTP read is every
  switch in the estate booting; a TFTP write is the step before all of them run
  something new.

- **It reports whether or not anybody asked for a work order.** The block is
  absent by default and the reporting is not: `action: engineering` security
  events, `xproxy_engineering_total{kind,operation}`, a fact in the
  cross-listener window, and a line in the access ledger's hash-chained record
  where the daemon has one. A relay that stayed quiet about a program download
  until it was configured to speak would be one whose logs did not have the
  download in them; `enabled: false` is how an operator says otherwise.

- **`require_grant: true` ties it to the machinery that already existed.** The
  same `access` ledger, the same four-eyes approvals, the same time-boxed grants
  and the same `xproxyctl access` -- which covered only the bastions, where a
  *session* is the unit of access. On a plant listener a *request* is the unit:
  one Modbus connection carries reads all day and one program write at four in
  the afternoon, and only the second needs a work order. An operation with no
  open grant is refused with `engineering_no_grant`, in the protocol's own
  words, and the device never sees it.

- **`engineering_ungranted` is the step before that.** On a listener that does
  not require a grant, an operation outside every approved window is still
  alerted: an engineering action nobody filed is worth telling somebody about
  even where the policy allows it. `action: alert` keeps the bookkeeping and
  drops the refusal, which is how to run the policy for a fortnight and read the
  report before it can stop a commissioning -- and the validator says so at load.

- **The grant's reason is the change reference**, and it reaches the security
  event as `work_order` and the ledger beside the operation. So "who downloaded
  what, when, under which work order" is answerable a year later out of a
  hash-chained file. A listener with `require_grant: true` on a daemon with no
  ledger fails closed at startup rather than at four in the afternoon, the same
  way the gate kinds do.

- **Engineering refusals never feed the ban ladder**, like the behavioural
  findings: an engineer who forgot to file a change should be told no, not locked
  out of the plant. In shadow mode nothing is refused and the would-be refusals
  go to the shadow report.

- **ATT&CK rows for every class on every kind, in both matrices**: T0843
  *Program Download*, T0845 *Program Upload*, T0858 *Change Operating Mode*,
  T0816 *Device Restart/Shutdown*, T0836 *Modify Parameter*, T0857 *System
  Firmware*, T0871 *Execution through API*, T0867 *Lateral Tool Transfer* with
  T1105, and the missing work order itself as T0859 *Valid Accounts* with T1078.

### Added (every OT kind on the behavioural models, not only modbus)

- **All eight OT listener kinds run the `anomaly` block now**: modbus, iec104,
  s7, mms, bacnet, opcua, coap and snmp. The models are the same on each, which
  is the point -- an operations centre can filter on `anomaly_cycle_changed`
  without knowing which protocol produced it -- and what differs is the
  translation each kind does, which its protocol page states in a table.

- **The translations are where the thought went.** On MMS the functional
  constraint goes in the *symbol* with the service, because a client that has
  always written `$SP$` setpoints and now writes `$CF$` configuration has
  changed what it does and not only where. On OPC UA the device is the session's
  user rather than the address, since this is the one industrial protocol that
  brought an identity, and a `Call`'s symbol carries the method. On SNMP the
  device is the credential, because a management station polls from several
  addresses under one community string. On BACnet it is the object instance, on
  CoAP the security name, on S7 the rack and slot, on IEC 104 the common
  address.

- **The value models are inert where a relay cannot honestly feed them, and the
  documentation says so.** An MMS data value, an OPC UA variant, a BACnet
  property, a CoAP payload and an SNMP binding are typed data whose type lives
  in an SCL file, an address space, a MIB or a vendor's own encoding -- none of
  which this relay has. Feeding a telemetry model the first two octets of
  something would report about a value nobody has. Modbus and IEC 104 are the
  two kinds that decode numbers in both directions, and they are the two where
  `telemetry` and `correlations` work.

- **A behavioural finding answers in the protocol's own words.** The refusal
  path of each kind was factored so the models can answer a client -- a Modbus
  exception, an S7 access fault, an MMS confirmed-error, an OPC UA service
  fault, a CoAP 4.03, a BACnet Error PDU -- **without** the refusal's own
  bookkeeping, because the models have already recorded the finding and, by
  design, never reach the ban ladder.

- **Seventy more rows in the ATT&CK table**, one per behavioural reason per kind
  that can emit it, so a coverage report shows which of the six models each
  protocol actually runs.

### Added (the six behavioural models, as one block every OT kind can run)

- **`internal/anomaly` is the detector without the protocol**, and the
  `anomaly` block is the same on every OT listener kind. Six models: novelty
  ("this peer has never done this"), the poll cycle (a rhythm that changed),
  the order (an operation in a place it has never been), the talkers (a peer
  nobody has seen, a peer on a device it has never addressed), the telemetry
  (a point that stopped moving, a run of readings that repeats) and the
  correlations (two points the process ties together that stopped agreeing).
  What each kind puts into them -- what a symbol, a point and a value are on
  its protocol -- is the kind's business, and its protocol page says.

- **Modbus is the first kind on it**, and its own three-model detector is
  gone in favour of the shared six. The configuration is nested now
  (`novelty: {symbols, write_points, burst, burst_period}` in place of the
  flat `new_function`, `new_write_address`, `write_burst`), and the two
  reasons are renamed with it: `anomaly_new_function` is
  `anomaly_new_symbol` and `anomaly_new_write_address` is
  `anomaly_new_write_point`, which is what an operations centre filtering
  across protocols needs them to be. A dashboard or SIEM query naming the old
  strings has to be updated; the examples and the packs in this tree are.

- **The values are both directions on Modbus**, because this relay already
  decodes read replies for the value policy's deltas: the telemetry model
  sees what the *device* answered as well as what a master wrote, which is
  the half that matters. A frozen or replayed written value says something
  about the master; a frozen or replayed read value is what a control room is
  being shown while the process does something else. A finding in a reply
  never refuses anything -- by the time an answer has arrived there is
  nothing left to refuse.

- **Novelty about writes is keyed on the span**, not on each address in it.
  A master writes the same spans every scan cycle, and one recipe download
  would otherwise fill a bounded set with addresses that are all the same
  traffic. Past the bound the peer's novelty detection is turned off and the
  count says so, rather than the set being widened.

- **`settle: 0s` means "report from this peer's first request"** and an
  unset key means the default ten minutes. They are different, so the models
  spell the first `NoSettle`: a detector that read "nothing was asked for" as
  "no window at all" would alert on every peer's first frame.

- **Three more techniques in the ATT&CK catalogue**, because the models
  reach behaviours the rules could not: T0801 *Monitor Process State* for a
  scan cycle that changed, T0832 *Manipulation of View* and T1565.002
  *Transmitted Data Manipulation* for telemetry that is frozen or replayed.
  Every behavioural reason is mapped for the kinds that emit it, which today
  is Modbus.

- **Shadow mode records one would-be refusal per request**, not one per
  finding. Enforcing would have stopped at the first, and the report exists
  to answer exactly what enforcing costs.

### Added (the same events in Enterprise ATT&CK terms, not only ATT&CK for ICS)

- **Two catalogues, because this proxy stands in two worlds.** ATT&CK for
  ICS is the vocabulary for a plant -- program downloads, operating-mode
  changes, reporting messages -- and it has nothing to say about a brute
  force on a bastion, a forwarded port, a directory read as a list or a
  COPY that runs a program. Enterprise ATT&CK is the vocabulary for those,
  so every technique in `internal/attack` now says which matrix it is from
  and the event carries a `matrix` field beside `technique`,
  `technique_name` and `tactic`. The identifier spaces do not collide (ICS
  is T0xxx, Enterprise T1xxx with sub-techniques written `T1021.004`), so
  one log field holds both and a query can still tell them apart.

- **One refusal, two readings.** An SSH session admitted with no access
  grant is T0886, *Remote Services*, to the plant's assessor and T1133,
  *External Remote Services*, to the enterprise's -- the same refusal, read
  by two teams whose dashboards do not share a vocabulary. Such an event
  now carries the identifiers from both and `matrix: ics,enterprise`, which
  is what stops each team maintaining its own translation table. The gate
  kinds, an OT listener reached from an address the policy does not name,
  a firmware image over TFTP and a file read off an IED are all in this
  class.

- **Every kind this project serves now tags something.** The table grew
  from the eleven OT kinds and four gate `no_grant` rows to all
  thirty-two: the bastion (authentication, what a session may carry, what
  it may forward), the edge (WAF and virtual-patch matches, upgrades to a
  stream protocol, bounds), the directory (anonymous binds, leading
  wildcards, the extended operations that change an account), the stores
  (a statement past the policy, `COPY ... FROM PROGRAM`, `LOAD DATA LOCAL
  INFILE`, `xp_cmdshell`, a Redis `MODULE LOAD`), the brokers, DNS
  (tunnelling, ANY over UDP, a name on a policy zone), NTP (authentication
  stripped, an offset no drift explains, the mode-6 amplifiers) and the
  layer 4 kinds. A test enforces it: a kind with no mapping is a kind whose
  refusals reach a SIEM as strings nobody can catalogue.

- **The access ledger's refusals are expanded across the kinds that ask
  it**, rather than written out once per kind: `no_grant` and the whole
  `grant_*` family -- pending, not yet, expired, denied, revoked, spent,
  wrong target -- on ssh, telnet, vnc, rdp and ftp, all reading as remote
  access outside an approved work order.

- **The two spellings the HTTP side actually logs.** Its events carry a
  bare reason (`waf`, `rate_limit`) rather than one prefixed with the kind,
  and a WAF refusal carries the rule that fired after a colon
  (`waf:942100`); both resolve now, so the edge's refusals are tagged
  without changing a field a SIEM already parses. HTTP refusals remain
  named counters of their own, so an HTTP technique appears in the security
  log and not in `xproxy_attack_technique_total` -- the page says so.

- **`xproxy_attack_technique_total` gained a `matrix` label** and
  `xproxyctl techniques` a `MATRIX` column and a `-matrix ics|enterprise`
  filter, for an estate that reports on the plant and the rest separately,
  because most do: the two catalogues answer to different auditors.

- **Still honest about the gaps.** Protocol hygiene stays untagged, and so
  does a refusal with no counterpart in either catalogue -- an AMQP
  performative, an RDP channel, an LDAP control -- because inventing a
  technique for it would read in a coverage report as a detection this
  proxy does not have. A technique with nothing mapped to it is still not
  in a catalogue, and the package test still fails if one is added. And a
  technique label still decides nothing: the ban ladder sees what it always
  saw, and the OT kinds still never feed it.

### Added (a short cross-listener memory, so the detections that need two listeners exist)

- **`correlation` is the window a listener does not have.** Every policy
  here decides about one message on one listener, which is the right shape
  for a policy and the wrong shape for a whole class of real detections:
  one host on Modbus, then S7, then IEC 104 (three listeners, one actor);
  an OT session a minute after a bastion session to the same jump host (two
  daemons, one machine); an NTP offset step followed by time-tagged 104
  commands (two protocols, one clock). None of those is visible to the
  listener that sees half of it.

- **What a fact is, and what it is not.** A listener writes one when
  something *changes* -- a session opened, a refusal, an engineering
  operation, a clock step -- never per message: a frame every few
  milliseconds for years is what a control network is, and a store taking a
  lock per frame would be a latency tax on the scan cycle. Identical facts
  inside a second collapse into one with a count, so a burst of forty
  refusals is one fact rather than forty.

- **Bounded, and the bounds say when they bit.** 4096 addresses with the
  least recently active evicted, 64 facts each with the oldest dropped, a
  30-minute window, every detail clipped -- and every drop counted, so a
  detector reading a truncated window can say "as far as this relay
  remembers" instead of answering "no" for the wrong reason. The estate's
  own facts (a clock step) are not an actor and are never evicted, so a
  flood of addresses cannot push out the left half of every chain.

- **Facts cross the cluster, because the pivot crosses processes.** On this
  design the bastion is `xgate` and the plant is `xot`, so "an OT session
  right after an interactive session from an external identity" is
  invisible to both alone. The four classes whose other half lives in a
  sibling -- a gate session, a clock step, an engineering operation, a
  credential event -- go over the existing cluster event channel; the rest
  do not, because a session per device per listener across an estate would
  be a gossip flood for something each daemon already sees.

- **Nothing here decides anything.** It records; what reads it decides. In
  particular nothing in it reaches the ban ladder, for the reason OT
  detections never do. `xproxyctl correlation` shows the window and what
  its bounds pushed out, `xproxy_correlation_*` are the counters, and
  [docs/CONFIG.md](CONFIG.md#correlation) is the reference.

- The first consumers are the five control-protocol kinds that admit a
  client once per connection (modbus, iec104, s7, mms, opcua), through the
  shared admission point every kind already calls -- so "this address was
  on this listener" is recorded the same way for all of them rather than
  spelled five ways. The datagram kinds record from their own session
  tables, which is where their once-per-session moment is.

### Added (every refusal says what it means in ATT&CK for ICS terms)

- **`technique`, `technique_name` and `tactic` on the security log line,
  where the reason maps to one.** An operations centre does not read
  `modbus_read_only` or `mms_write_constraint_not_allowed`; it reads a
  case in a SIEM whose detections are catalogued by technique, reports
  coverage by technique, and is asked at an audit which techniques the
  estate can see. A relay saying "a write was refused on a read-only
  listener" is saying T0855, *Unauthorized Command Message*, and the
  alternative to saying it here is a spreadsheet somebody else keeps that
  goes stale the first time a kind gains a reason.

- **Tagged at the two points every event already passes through** --
  `logging.SecurityEvent` and the refusal counter -- rather than at each
  call site in each kind. A kind that had to remember would be a kind
  whose next refusal reason reaches a SIEM as a string nobody can
  catalogue, and there are a hundred and forty of those reasons.

- **What is deliberately not tagged.** A malformed frame, a failed TLS
  handshake, a datagram over the size bound: protocol hygiene and bounds
  an operator set. A technique label on those would appear in a coverage
  report as a detection this proxy does not have, which is worse than an
  empty cell. And a technique nothing here can observe is not in the
  catalogue at all -- the package's own test fails when one is added
  without a detection behind it, so `attack.All()` is an honest answer to
  "what can this relay detect" rather than a copy of MITRE's matrix with
  most of it unreachable.

- **One reason may carry several techniques**, because the behaviours
  overlap by construction: an unsafe Modbus diagnostic sub-function is a
  restart (T0816) and a way to stop a device answering (T0804). Both are
  logged and both are counted, so the technique counters do not sum to the
  refusal count and are not meant to -- the question they answer is "how
  much of this technique did we see".

- **Shadow mode is not tagged.** A listener in shadow mode did not detect
  a technique, it decided not to act on one, and that reading stays in the
  shadow ledger where the two have always been kept apart. Nothing here
  reaches the ban ladder either.

- `xproxyctl techniques` shows what this daemon has seen, most seen first;
  `-catalogue` lists every technique it could observe, which is the honest
  form of a coverage answer -- a zero says "nothing tried", not "nothing
  detectable". `xproxy_attack_technique_total{technique,name,tactic}` is
  the metric, `techniques` the snapshot field, and
  [docs/ATTACK.md](ATTACK.md) is the mapping with a justification per row
  and a parity test that keeps the page and the code the same table.

### Changed (the OT protocols are a daemon of their own: `xot`)

- **A fourth binary, for the box at level 3.5.** `xrelay` served SMTP,
  MQTT, FTP, LDAP, the database wire protocols and AMQP alongside Modbus,
  IEC 60870-5-104, S7, IEC 61850 MMS, BACnet, OPC UA and CoAP. Those are
  not one estate. The proxy in front of a process network is reachable
  from the plant on one side and the enterprise on the other, and it is
  the one whose compromise moves equipment -- and it was carrying a mail
  parser. `xot` links the control protocols and the protocols the field
  equipment itself speaks, and nothing else: no SMTP, no FTP, no LDAP, no
  PostgreSQL, MySQL, TDS or Redis, no AMQP. It is the same argument the
  first split was made for (docs/AMR.md, AMR-048), applied to the daemon
  whose failure mode is a plant.

- **What moved.** `modbus`, `iec104`, `s7`, `mms`, `bacnet`, `opcua` and
  `coap` are `xot`'s wherever they are written; `xrelay` no longer links
  them. An estate running any of those under `xrelay` installs
  `xproxy-xot` and runs `xot`: the configuration itself does not change,
  and `xrelay` says in its log which listeners it left to a sibling.

- **What is served by both, and the new `daemon:` key.** `syslog`,
  `snmp`, `tftp`, `dhcp`, `dhcp6`, `ntp`, `ntske` and `mqtt` are run by a
  plant and by a data centre alike, so both binaries link them and the
  listener says which daemon binds it. **The default is `xrelay`**, so
  every configuration written before this means what it meant. `mqtt` is
  in that set for a narrower reason than the rest: the device inventory
  collects what *one* daemon saw, and Sparkplug B births are among the
  richest sources the fingerprinting has, so an estate whose device
  identities arrive over MQTT and whose process traffic is Modbus would
  otherwise have had two inventories holding half a device each.
  `examples/ot/inventory.yaml` is the file that found that.

- **One owner per listener, and that is the point of the field rather
  than a consequence of it.** A shared estate configuration is read by
  every daemon, each taking what is its own; "served by both" with no
  tiebreak would mean two daemons on one host binding one port and one
  failing to start -- an outage produced by a file that validated
  everywhere. So `daemon:` names the one that binds it, naming a daemon
  that does not carry that kind's code is a load error (a port nobody
  binds is worse than a refusal), and naming the only daemon that serves
  a kind is a warning.

- **It is not a smaller binary than `xrelay`**, and bytes were never the
  argument: measured together, `make build` produces 21.0 MiB of `xrelay`
  and 21.3 of `xot`, because the protocols it keeps replace the ones it
  drops. What changes is what an attacker who reaches one of the two
  processes finds inside it.

- Packaging, units and docs followed: the `xproxy-xot` RPM subpackage,
  `xot.service` and `xot.socket`, the `xot` system user with its own log,
  state and runtime directories and its own management socket
  (`/run/xot/mgmt.sock`), `deploy/config/xot.yaml`, `xot(8)`,
  `examples/estate/xot.yaml`, and the OT examples, which now carry
  `daemon: xot` on their syslog, SNMP, TFTP, DHCP and time listeners.

### Added (coap: the two security modes a constrained device actually has)

- **`coap.psk` serves RFC 7252 §9.1.3.1, and the identity is the point.** The
  kind served DTLS with certificates only, which is the mode a part with sixty
  kilobytes of flash and a coin cell is least able to run: a chain to verify, a
  clock to verify it against, and an asymmetric operation per handshake. The
  pre-shared key mode is what such a device ships with. The listener holds an
  identity-to-key table, the identity the client sent becomes a **security
  name**, and a rule names it in `security_names` — the same shape as the SNMP
  kind's `cert_to_name`, so an operator reading both sees one idea rather than
  two. Several identities may map to one name, which is how a hall of sensors
  gets one line in the policy without sharing a key.

- **A `psk` table turns DTLS on by itself**, with no `tls` section and no
  server certificate. Requiring a certificate in order to serve the mode that
  exists *because* certificates are too expensive would be requiring the thing
  the mode replaces: an estate whose devices have no certificate machinery
  usually has no authority of its own either. A listener may hold both tables
  and then serves both modes.

- **The suites are named rather than inherited.** The four AEAD PSK suites the
  library has, `TLS_PSK_WITH_AES_128_CCM_8` — the one RFC 7252 makes mandatory
  for this mode — among them. What is *not* offered is stated rather than
  discovered: there is no forward secrecy in PSK mode here, because the only
  `ECDHE_PSK` suite the library implements is a CBC one, and taking the
  construction every attack on TLS record padding has been about in order to
  gain a property is not a trade this makes. An estate that wants forward
  secrecy on this listener wants the certificate mode.

- **`coap.public_keys` is §9.1.3.2's raw public key mode as a policy**: the
  SHA-256 of a peer's SubjectPublicKeyInfo, pinned, mapping to a name. What is
  pinned is the *key*, so a certificate reissued around the same key keeps
  working and one reissued with a new key does not — which is the property the
  mode is for. `client_auth: require_any` is the client-certificate mode to
  write for it, and the only place this proxy accepts it: it asks for a
  certificate and verifies it against nothing, which is a credential exactly
  because the table below it pins the key. Validation refuses `require_any`
  anywhere else. `xproxyctl spki CERT.pem` now prints the fingerprint in the
  form the table takes.

- **What that is not is RFC 7250 on the wire**, and the limits say so. The DTLS
  library here does not negotiate the `client_certificate_type` and
  `server_certificate_type` extensions, so the key travels inside a self-signed
  certificate rather than in RFC 7250's own `RawPublicKey` structure. Every way
  the mode matters is the same — the key is the identity, nothing vouches for
  it, the fingerprint is what the rule names — and the handshake is a few
  hundred octets larger. A device that can only speak RFC 7250's structure
  cannot talk to this listener.

- **Two refusals, and a bound on each table.** `unknown_psk_identity` fails the
  handshake and raises an event carrying the name the peer used, because on a
  shared segment the identity is the only thing telling one sensor from
  another: a name nobody enrolled is one device provisioned wrong, repeatedly,
  or somebody trying names, once each. `no_security_name` is a session that
  authenticated some other way on a listener whose policy is written in names —
  true by default exactly where a table exists, since what is left of such a
  policy without a name is a policy about addresses. An empty identity is
  refused at load (it would be the row every client that names nothing
  reaches), an identity is at most 128 octets, a key at least 16, and a table
  at most 8192 rows.

- The identity reaches the logs as well as the policy: one line per established
  session with `security` (the RFC 7252 mode, not this code's word for it),
  `identity` and `cipher_suite`, and `identity` on every message line and
  refusal from a named peer. Counters: `coap_psk_sessions`,
  `coap_unknown_identity`, `coap_unnamed_sessions`.

### Added (the inventory, matched against the vendors' own advisories)

- **`asset_inventory.advisories` answers the question an estate that cannot
  patch actually has.** Not "is there an advisory for this controller" -- a
  newsletter says that -- but "is the version we are running one of the
  affected ones", which today means reading a PDF per advisory against a
  spreadsheet nobody has updated. The inventory already knows what is on the
  network and, where a protocol lets a device say so, what firmware it reports;
  CSAF 2.0 is the machine-readable form Siemens ProductCERT, Schneider Electric
  and the CISA ICS advisories now publish in. This reads a directory of those
  documents and says, per device, which of them name it.

- **Six answers, and five of them are not "affected".** `affected`,
  `under_investigation`, `not_assessed`, `fixed`, `not_affected`,
  `unknown_product`. The two that carry the design: **an unmatched version is
  `not_assessed`, never "not affected"** -- a device whose firmware reads
  `Rel. 04.03`, or whose advisory range says "all versions < V2.9.2 with
  CP1604 fitted", is a device nobody has assessed, and it comes back with the
  text that could not be read so somebody can check it by hand. And
  `unknown_product` says no *loaded* advisory names the product, which depends
  on which documents were loaded and is not the sentence "no advisory affects
  this device". A wrong "not affected" is a device somebody stops looking at,
  and on this kind of estate it would have been most of them.

- **What it will compare, and what it refuses.** An optional `V`,
  dot-separated numbers, and one recognised update or service-pack ordinal
  (`V4.2.1`, `V2.9.2 Update 4`, `V1.2 SP3`, `V4.2 P01`). A missing component is
  zero. Refused: two different ordinal kinds on the same numbers (nothing says
  whether SP3 precedes HF1), and a single number against a dotted one --
  `20240115` is arithmetically larger than `4.2` and says nothing about whether
  the device is below `V4.2`. Ranges are read as `vers` expressions and as the
  English the vendors write instead (`All versions < V4.2`, `prior to V4.2`,
  `V4.0 - V4.2`, `up to and including V1.5`); one this cannot read makes the
  devices that matched the product `not_assessed`, naming the sentence, rather
  than dropping the condition and calling them all affected.

- **Products are tied to devices by name, conservatively**: a contiguous run of
  at least two words, or an exact match. "SIMATIC S7-1200 CPU family" reaches a
  device calling itself "SIMATIC S7-1200 CPU 1212C DC/DC/DC" and does not reach
  an S7-1500. The vendor is reported and *not* required to agree, because an
  inventory's vendor comes from a hardware prefix and an advisory's from a legal
  entity. An advisory that names a product and no version -- how an advisory
  with no fix yet is published -- is about every version, so it reaches the
  device whose version string nobody can read.

- **Nothing fetches.** The documents are read from disk. A relay on a process
  network dialling a vendor's website every hour is a second network dependency
  in the one place that is supposed to have none, and advisory distribution
  already has downloaders -- the CSAF standard defines one, every publisher in
  scope offers a feed -- run on a machine that is allowed out, which is also
  where the detached signatures belong. A source that cannot be read **at load**
  is a startup error, because a proxy reporting no advisories would be claiming
  an estate has nothing against it; a source that fails a *refresh* keeps what
  is loaded and counts the failure.

- **Modbus function code 43, MEI type 14, is where the firmware comes from.**
  The identification response is the one place in that protocol where a device
  names its vendor, its product code and its `MajorMinorRevision`, so it is now
  parsed into fields and put into the inventory (`maker`, `model`, `firmware`).
  The relay reads a master's own request going past and never sends one: a frame
  this proxy invented would be a frame on a process network nobody scheduled.
  A plant whose masters never ask gets `not_assessed`, honestly.

- `xproxyctl assets advisories`, with `-state` for one of the six, `-long` for
  every advisory that names a device and the remediation each gives, and
  `-documents` for what the proxy is actually working from -- the first question
  to ask of a directory somebody else fills. `GET /v1/assets/advisories` is the
  same. Counters: `advisory_affected` and `advisory_not_assessed` as gauges
  (the first goes down as an estate is patched, the second says how much of it
  the matching cannot answer for), `advisory_findings`, `advisory_failures`.

### Fixed (Modbus identification responses were a field short)

- **The RTU and ASCII framing of a Read Device Identification *response* read
  five fields before the object list where the specification has six.** Section
  6.21 puts the identification code, the conformity level, more-follows, the
  object id a walk resumes at and *then* the number of objects after the MEI
  type; taking the resume point for the count ends the frame five bytes in on
  the ordinary answer -- more-follows nought, resume nought -- with the objects
  still on the wire, and the device's answer then reads as malformed and is
  refused. Modbus/TCP was unaffected, because the MBAP header's length delimits
  the PDU.

### Fixed (a DTLS session no longer dies at the handshake bound)

- **A deadline set on a peer's view of a shared DTLS socket now reaches the read
  already waiting on it.** `net.Conn` requires that -- a deadline applies to the
  calls already blocked, not only the next ones -- and here it was load-bearing.
  The handshake bound is set on that connection and cleared once the handshake
  completes, while the library's own reader goroutine is reading it: a pending
  read that kept the deadline it started under would fire at the handshake bound
  and take the established session with it. On the default bound that is every
  DTLS session in the estate, ten seconds in, whenever the clear lands a moment
  too late -- and for a battery-powered sensor a handshake per report is the
  expensive part of the exchange. It surfaced as a coap test failing under load;
  the test added with the fix fails without it.

### Added (snmp: RFC 6353, where the credential is a certificate)

- **`dtls_mode` puts RFC 6353's transport model on the transport SNMP actually
  uses.** `tls_mode` was the stream half (TCP 10161); this is the datagram half
  (UDP 10161), and inside either sits RFC 5591's transport security model: an
  SNMPv3 message with the security parameters taken out. No user, no engine
  identifier, no clock, no digest, because the session authenticated and
  encrypted it before the message existed.

- **`cert_to_name` is RFC 6353 §5.3's `snmpTlstmCertToTSNTable`**: rows in order,
  first match wins, each saying which certificate it is about and how a security
  name is derived from it — `specified`, `san_rfc822`, `san_dns`, `san_ip`,
  `san_any`, or `common_name`, which the standard provides and advises against.
  That name is what a rule's new `security_names` names. `fingerprint: any` is an
  extension to the table for the estate that runs its own authority and would
  otherwise edit this file on every renewal; md5 fingerprints are refused,
  because a fingerprint that can be collided is not an identity.

- **Three things follow from the missing digest, and each is something USM cannot
  do.** The secret per user per engine is gone: a certificate is an identity an
  estate already issues, revokes and rotates. A refusal is *answered* rather than
  timing out, because the session authenticates the answer. And a v3 request
  *can* be downgraded to v2c — the one case where "a v3 request cannot be
  downgraded" does not apply — so a manager holding nothing but a certificate
  reaches a switch that will never speak anything else, and the switch's v2c
  answer comes back rebuilt in the manager's own envelope.

- **`transports` on a rule** names `udp`, `tcp`, `tls` or `dtls`, because on this
  protocol the transport is half the credential: a community string in a plain
  datagram is a cleartext password from an address anybody can claim, and the
  same request inside DTLS came from a peer that proved it holds a private key.
  Empty covers all four, so every policy written before this field means what it
  meant.

- **`dtls_mode: detect` takes records and plain datagrams on one port**, because
  a DTLS content type and a BER SEQUENCE cannot be read as each other. It is not
  RFC 6353's arrangement — the standard gives DTLS a port of its own — and it is
  for the estate whose new managers speak DTLS and whose two hundred field
  switches are not going to be reconfigured. What it costs is stated rather than
  discovered: the client chooses which of the two it speaks, so the *policy* is
  what requires the certificate, and validation says so when a `detect`
  listener's rules name neither `transports` nor `security_names`.

- **Three refusals the model brings.** `tsm_no_name` is a message whose
  certificate mapped to nothing, refused because a transport model message with
  no derived name has no credential at all (`require_security_name: false` is the
  listener saying it wants confidentiality and will decide on the address alone).
  `tsm_level` is a message claiming less than its session gave: the flags are
  supposed to be copied from the transport, so `authNoPriv` inside DTLS is a
  sender that did not implement the model or is probing for a listener that reads
  the flags as policy. And `tsm_transport` is such a message on a transport that
  provides no security at all, where the flags claim authPriv and nothing backs
  the claim; it is refused whatever `require_security_name` says, because that
  switch is about whether a name is needed and this is about whether the
  message's own statement about its transport is true.

- Counters: `snmp_dtls_handshakes`, `snmp_dtls_handshake_failed`,
  `snmp_dtls_sessions`, `snmp_dtls_datagrams_dropped`, `snmp_tsm_messages`,
  `snmp_tsm_unnamed`. The handshake failures are the pair to watch, because the
  count separates an estate whose certificates expired — every handshake fails
  and the sessions count stops climbing — from a scanner sending flights of
  nonsense at the port, which never touches it.

### Added (behaviour packs for the known ICS tooling)

- **Six shipped configurations, one per tool, under
  [`examples/ot/packs/`](../examples/ot/packs/README.md).** FrostyGoop and
  PIPEDREAM's Schneider module on `modbus`, Industroyer and Industroyer2 on
  `iec104`, Industroyer's IEC 61850 module on `mms`, a Stuxnet-shaped attack on
  `s7`, and PIPEDREAM's OPC UA module on `opcua`. Each is a complete, loadable
  document whose comments are most of its content, because the point is that
  nobody should have to read the Industroyer analysis to write a policy that
  would have refused it.

- **None of them is a signature, and the packs say so first.** Every one of
  these tools used the protocol as designed: FrostyGoop wrote holding
  registers, Industroyer sent select-then-execute properly, Stuxnet downloaded
  a block. So a pack is a statement about what the estate's traffic *is* -- the
  hosts, the registers, the information objects, the data blocks -- and a named
  refusal for everything outside it.

- **Each pack has a test that drives the tool's own behaviour through the
  relay.** In the listener kind's own package, loading the file as it ships
  against a fabricated device, substituting nothing but the listener's port and
  the network of the host under test. That found a real mistake in one of them:
  the OPC UA pack first demanded `sign_and_encrypt`, which leaves the relay
  nothing to read and makes its own service and node rules silent -- the pack
  now takes `sign` with `require_readable_bodies`, and says why in place.

- **The technique goes in the rule name**, because that is what the security
  event's `rule` attribute carries and what a SIEM query is written against.
  Where a kind's rule also has a `comment`, the technique is spelled out there
  too. Two kinds differ and the packs are explicit about it: an `iec104` rule
  has no comment field, and an `s7` rule matches a *session* rather than a
  request, so on that kind the finding is the refusal reason with the matched
  rule's comment beside it. Carrying the technique onto the event itself, with
  the matrix release recorded, is separate work and is not done.

- **What is not covered is stated rather than implied.** Two of PIPEDREAM's
  modules speak protocols this proxy does not parse -- CODESYS on UDP 1740-1743
  and TCP 2455, and Omron FINS on UDP 9600. A `kind: udp` listener in front of
  those ports is a bound and a rate limit, not a detection, and segmentation is
  the control there.

### Added (iec104: the redundancy groups of edition 2)

- **`redundancy.groups` declares which connections are one controlling
  station.** A control centre reaches a substation over several connections --
  different routers, different bearers -- and edition 2 of the standard calls
  that set a redundancy group, of which exactly one carries data at a time. The
  relay now tracks which one holds data transfer, and **refuses an I frame from
  a standby connection** (`standby`) before it reaches the station: without a
  group, a second connection from the control centre's own network was just
  another client, and an injected command on it was decided exactly like one on
  the first.

- **A failover is an event.** Taking data transfer from a live connection is
  logged as an `iec104_failover` security event naming both addresses, counted
  in `iec104_failovers`, and refusable outright with `takeover: refuse` for the
  estate where paths are moved deliberately. `iec104_redundancy_active` says how
  many groups have a connection carrying data at all, which is the gauge that
  says a control centre is talking to its substation.

- **`carry_selects` (default on inside a group) keeps a selection across a
  failover**, which is most of the reason to declare a group. A selection
  belongs to the connection that made it, so a failover between the select and
  the execute refused a legitimate two-step command -- and a control room that
  meets that during an outage turns `require_select` off, which loses this
  protocol's one safety property for good. What the concession trusts is the
  group's client list; what bounds it is the rule above, since the selection can
  only be consumed by whichever connection currently holds data transfer, so an
  intruder inside those networks has to win a STARTDT as well.

- **Three refusals where there was one.** `unselected` is a bare execute that
  was never selected, `select_expired` is an operator who selected a point and
  came back to it too late, and `select_other_connection` is a two-step command
  that was done properly and a failover in the middle dropped. That last one is
  the diagnosis nobody can make from outside the relay, and it is the difference
  between "our failover is losing selects" and "somebody is injecting commands".

- **The setpoint memory needed nothing**, and the changelog says so rather than
  claiming a fix: it is keyed on the point and was already per listener, because
  the process does not reset when a control centre reconnects. A delta bound
  that did would be a bound any client could clear by dropping its association.

### Added (modbus: the second code inside a function code)

- **Function code 8's sub-function is now policy.** `diagnostics` on a rule names
  the sub-functions it covers, by name (`force_listen_only`,
  `return_bus_message_count`), number, or range (`11-18`), so "the counters, yes;
  listen-only mode, never" is two rules. Before this, function code 8 could only
  be allowed or refused whole -- and it covers both a counter poll a maintenance
  tool makes all day and the four bytes that take a device off the bus until
  somebody walks out to it.

- **Function code 90 is parsed as Schneider UMAS**, down to the session byte and
  the command, and `umas_commands` names them: `read_variables`, `stop_plc`,
  `upload_block`, the strategy transfers. It used to be an unknown code and it
  carries the two things that matter most on a Modicon estate -- stopping the PLC
  and changing its program. What is known about the commands is published
  research rather than a specification, and the implementation says so where it
  counts: a command absent from the table is `unknown` rather than harmless,
  nothing below the command is parsed (no bound invented for a payload whose
  shape nobody publishes), and a read-only listener refuses every UMAS frame
  whatever the command.

- **`effects` is the durable form of the same rule.** It names what a
  sub-function *does* -- `read`, `write`, `control` (stop, start, restart,
  listen-only), `program` (a control program in either direction), `clear`
  (counters and the event log), `session`, `unknown` -- whichever function code
  carried it. `effects: [control, program, clear, unknown]` is one deny that
  covers function 8, function 90 and the CANopen tunnel in function 43, and it
  keeps covering them when the table learns another vendor's code.

- **The sub-function reaches the trace and the learning report.** The trace line
  carries `sub_function`, `effect` and the UMAS session; a learning subject is
  per sub-function rather than per function code, so the report proposes
  `diagnostics: [return_bus_message_count]` instead of `functions: [diagnostic]`
  -- which is both more exact and what the new default requires.

### Security

- **A rule allowing a Modbus function code no longer allows the worst thing that
  code can do.** `refuse_unsafe_sub_functions`, default **on**, refuses a
  sub-function whose effect is `control`, `program`, `clear` or `unknown` to an
  allow rule that never mentioned the sub-function, and to
  `default_action: allow`. The reason is what a rule means: `functions:
  [diagnostic]` was written by somebody thinking of counter polls, and it used to
  permit Force Listen Only Mode as well. Naming the sub-function -- with
  `diagnostics`, `umas_commands` or `effects` -- is how a policy says it meant
  it. The refusal is `unsafe_sub_function`, answered as an illegal-function
  exception, and `refuse_unsafe_sub_functions: false` hands the whole function
  code back with a validation warning.

  **Two behaviour changes follow, on configurations that load unchanged.** A rule
  allowing function code 8 without naming sub-functions now refuses 1, 3, 4, 10,
  20 and 21 and allows the counters. And a CANopen tunnel (function 43, MEI type
  13) is classified `unknown`, so it too needs a rule that names it -- `effects:
  [unknown]` -- because a tunnel carrying a second protocol is not something this
  relay reads.

- **`golang.org/x/crypto` v0.54.0 -> v0.57.0, past the SSH channel-deadlock
  advisories.** Go's advisories put those issues in versions before v0.56.0, and
  an earlier govulncheck run had found reachable SSH call paths here. A
  reachable path is not by itself a demonstration that this proxy is
  exploitable; the fix is cheap and the SSH gate is the one listener whose whole
  job is to stand between people and the machines they administer.

  The upgrade moves the minimum Go toolchain to **1.26**, because v0.56.0 is the
  first release carrying the fix and its own `go` directive says 1.26.0. There is
  no version of this fix that does not. `BuildRequires: golang >= 1.26` in the
  RPM spec, and the setup documents say so; CI takes its toolchain from `go.mod`
  and needs no edit. The Fedora packaging builds with `GOTOOLCHAIN=local`, so a
  build host whose `golang` package is older than 1.26 now fails at the
  toolchain check rather than silently building something else.

- **A certificate carrying `source-address` was refused outright by the SSH
  gate after that upgrade, whatever its value.** x/crypto up to v0.54.0 skipped
  that one critical option inside `CheckCert`, on the grounds that its own
  `serverAuthenticate` would enforce it later, and a caller calling `CheckCert`
  directly inherited the skip. v0.55.0 removed the special case, so this
  gateway -- which calls `CheckCert` directly and enforces the option itself,
  because the check needs the client's address -- had to name it.

  Fail-closed, and exactly backwards: it refused the certificates an estate had
  hardened and never ran the check that reads them. The option list is now a
  named value, `certOptionsImplemented`, with a test that asserts the gate
  against it in both directions -- the end-to-end tests could not catch this,
  because a certificate restricted to another network is refused either way and
  SSH gives the client no reason.

- **The ALPN reader's test helper had been editing a different extension.**
  The Go 1.26 toolchain the upgrade brings in adds another post-quantum group
  identifier to the client hello, which moved the bytes `00 10` -- the ALPN
  extension type -- into `supported_groups` at an offset whose next two octets
  read as a length in range. `breakALPN` took the first such match, corrupted
  somebody else's extension, and handed back a hello whose ALPN was untouched:
  four assertions then reported a reader that believed a bad length when the
  reader was right. The helper now checks that the body it found has an ALPN
  body's shape -- a list length covering exactly the rest, holding
  length-prefixed names that consume it exactly -- which is what its own comment
  had promised. The reader itself needed no change, and its fuzz properties held
  throughout.

### Changed

- **The DTLS transport moved out of the CoAP kind into `internal/dtlsx`.**
  AMR-050 confined `pion/dtls` to one file on the argument that it served one
  transport on one listener; a second listener needing the same bounded peer
  table, the same handshake bound and the same configuration translation makes
  that confinement a copy. The dependency is now in one package's imports and no
  package outside it names a type from the library. [AMR-051](AMR.md) records the
  move.

### Fixed

- **An `iec104` listener in shadow mode counted a real refusal on the
  select-before-operate path.** The refusal counter sat above the branch that
  records a would-be refusal, so a listener under trial reported a refusal it
  did not make -- and the operator reading a trial listener's refusal count is
  exactly the person who must not be told that enforcement is happening when it
  is not. The project's own invariant test missed it because the two calls
  spelled the same reason differently (`unselected` and `iec104_unselected`,
  which the counter normalises to one name at runtime). The select path now
  counts on the enforced path only; the same shape survives elsewhere in this
  kind and is a sweep of its own rather than part of this change.

- **`TestConfigReferenceComplete` ran the `internal/config` package past the
  ten-minute test timeout under `-race`.** It compiled one regular expression
  per configuration key and scanned the whole reference with each -- a
  thousand-odd scans of a megabyte, which the race detector's overhead turned
  into a timeout rather than a slow test. The document is now tokenised once
  into the identifier runs a key has to appear as, which is the same question
  asked in one pass: 600 seconds and a panic became under three. A key that is
  not itself such a run still goes through the regular expression, so the two
  readings cannot drift.

- **Every binary built on a host whose `date` is not GNU's was stamped
  `BuildDate=1970-01-01T00:00:00Z`.** The Makefile converted an epoch with
  `date -d @N`, which is a GNU extension; BSD date spells it `date -r N` and
  rejects `-d`, so the conversion failed and the expression fell back to the
  epoch. macOS is a supported build host, which means the darwin release
  binaries — the ones a build date is most wanted on — all claimed to predate
  the protocols they proxy. git now formats the commit date itself, so no
  `date(1)` is involved at all; `SOURCE_DATE_EPOCH` still wins where it is set
  and is converted with whichever spelling the host has. Where neither is
  available, the date is `unknown`, which is what it is: the epoch reads as a
  fact.

- The RPM spec no longer converts `SOURCE_DATE_EPOCH` itself before calling
  `make`. It duplicated the Makefile with the same GNU-only spelling and fell
  back to the wall clock, which would have made a package built without
  `SOURCE_DATE_EPOCH` unreproducible for the one reason reproducibility is
  claimed.

- **A DTLS listener's socket buffer was sized to its message bound, so the
  largest messages it was configured to carry were truncated by the read.** A
  record is larger than the plaintext inside it — a header, a nonce and a tag —
  and a truncated record is not a shorter record: the record layer refuses it. So
  a listener with `max_message_bytes` set to the size of its largest real message
  worked for everything except those messages, and said nothing about why. The
  arithmetic now lives in `dtlsx.RecordOverhead` and the transport derives the
  buffer from the listener's message bound, which fixes `kind: coap` inside DTLS
  as well as the new SNMP path. The plaintext is read into a buffer the size of a
  whole record for the same reason, so a message past the bound is refused *by
  the bound* and the session survives it.

- The RFC 6353 port constants in `internal/snmp` were mislabelled: 10161 is the
  command responder and 10162 the notification receiver on *both* transports, so
  there are four names where there were two and DTLS no longer claims to live on
  the trap port.

### Added (mms: IEC 61850, where the names carry the semantics)

- **`kind: mms` is an IEC 61850 relay agent on TCP 102** that reads six layers to
  get at the seventh: TPKT, COTP, ISO 8327 session, ISO 8823 presentation, ACSE
  and the MMS service layer. Three of them exist only to be traversed.

- **What makes this listener different from every other relay kind here is that
  the protocol's own names carry the semantics.** In front of Modbus the relay has
  to be told which register is a setpoint. Here IEC 61850-8-1 maps the data model
  onto MMS object names as `LD/LN$FC$DO$DA`, and the functional constraint is what
  a rule is written about: `XCBR1$CO$Pos$Oper` operates a circuit breaker,
  `PTOC1$SG$StrVal$setMag$f` changes a protection relay's trip characteristic, and
  `LLN0$BR$brcbST$RptEna` decides whether the control centre hears about either.
  So a useful policy can be written for an estate whose SCL files nobody has read.
  Within a control object the attribute distinguishes a select (`SBO`, `SBOw`)
  from an operate (`Oper`), so a rule can let a client reserve a breaker without
  being able to move it.

- **It sees the password, and says so rather than pretending to check it.** IEC
  61850-8-1's ACSE authentication value is a cleartext GraphicString, and on most
  of the installed base it is the only authentication an IED has. So
  `refuse_plaintext_passwords` defaults **off** here — the opposite of the same
  knob on the `opcua` listener, and for the opposite reason: refusing it removes
  the only check the device has. What the listener does by default is count every
  association carrying one (`mms_plaintext_passwords`) and raise a finding, which
  is what an estate needs to know how far from IEC 62351-4 it is. The password's
  *length* is recorded and its value never is — not in a log, not in a learning
  report, not in the parsed association this relay holds — and there is a fuzz
  invariant asserting that, because a relay holding a substation's ACSE passwords
  is worth attacking for them.

- **`require_select_before_operate` is the one check in this protocol a relay can
  make that the device may not.** IEC 61850 leaves select-before-operate to each
  object's `ctlModel`, `ctlModel` lives in `$CF$`, and `$CF$` is writable — so a
  client with configuration access can turn the interlock off and then operate
  directly. This listener tracks the selection itself and records it on the IED's
  **positive answer** rather than on the client's asking, so a client that asked to
  select an object the IED refused holds no selection and its operate is refused.

- **The presentation context list is read at association time** rather than
  assuming context 3 is MMS. A data value on a context the two ends never defined
  is reported as not-MMS (`mms_opaque_contexts`) and refused, instead of being
  forwarded as though a service rule had decided about it.

- New counters: `mms_associations`, `mms_sessions`, `mms_selections`,
  `mms_plaintext_passwords`, `mms_opaque_contexts`, `mms_server_errors`,
  `mms_server_refusals`. `mms_denied` is the ban trigger.

- **`mms.learn`** records what crosses the listener and writes the object rules.
  The report leads with three findings — how many associations carried a cleartext
  password, how many requests operated the plant and whether any of them selected
  first, and how many touched a protection setting — because a reader who adopts
  the proposal without seeing them has adopted a policy for traffic they did not
  understand.

- One defect the wire package's own tests caught: the high-tag-number BER form was
  refused as unnecessary, and MMS numbers its file and domain services up to 77
  where the low form stops at 30 — so every file and download service was
  unreadable. It is supported and bounded now, and a tag padded into the long form
  that did not need it is refused, because that is two encodings of one tag and a
  rule matching on the tag would see only one of them.

- Three the listener's tests caught: `allow_domain_services` did not admit the
  domain service class, so turning it on left the services it names refused by the
  default list; a refusal about a service that changes the substation was not hard,
  so `monitor_only` forwarded a Write it had documented it would refuse; and a file
  service's path was read from whatever element came next, so the octets of the
  position INTEGER became a path no rule was written about.

- And the validator's warnings were tightened until none of them fires on
  `examples/ot/mms.yaml`, which is correct as written. A warning that cries wolf
  teaches people to ignore the others: the interlock warning now reads the rules
  and the default action, and the one about domain services accepts a rule that
  already has the time window it asks for.

### Added (opcua: the protocol that brought its own security)

- **`kind: opcua` is an OPC UA relay agent (IEC 62541) on TCP 4840** that reads the
  chunked UA TCP transport, the secure channel, the session and — where the
  channel's own mode leaves a body readable — the service call inside.

- **This listener has a different job from every other relay kind here.** In front
  of Modbus or S7comm the relay *is* the access control, because the protocol has
  none. OPC UA already checks certificates and users, so this listener is the place
  an estate's rules are written once and enforced for every server behind it,
  including the ones whose own configuration nobody has reviewed since they were
  commissioned.

- **Most of what is worth enforcing is in the handshake, and all of it is in the
  clear by construction.** The Hello names an endpoint and proposes four buffer
  sizes; the OpenSecureChannel names a security policy and carries both
  certificates; the CreateSession/ActivateSession pair names an application and a
  user. Those fields have to be readable — they are how the two ends agree on what
  to encrypt — so `security_policies`, `security_modes`, `application_uris`,
  `token_kinds` and `users` work on every channel whatever it then does to its
  bodies. A listener admitting one current policy from two named applications with
  no anonymous token has excluded most of what goes wrong without naming a single
  node.

- **The two security policies IEC 62541 withdrew have to be named twice.**
  `Basic128Rsa15` and `Basic256` are SHA-1 based and were withdrawn in 1.04, and
  they are the two an estate most often still has switched on because one old
  client needs them. Naming one in `security_policies` is a validation *error*
  unless `allow_deprecated_policies` is also set, so switching SHA-1 back on is
  written down where somebody reviewing the file will read it. `None` is refused
  separately and for a different reason: deprecated means "broken cryptography
  still switched on", `None` means "no cryptography, on purpose", and the log line
  says which.

- **Whether the service-level rules apply at all is a property of the channel, and
  the reference says so rather than hiding it.** `MessageSecurityMode` has three
  values and they mean three different things to a reader. With `none` everything
  is plaintext. With **`sign`** the body is signed and *not* encrypted, so this
  relay reads every node identifier and method argument — and modifies none of
  them, because the signature is over exactly the octets the client sent. With
  `sign_and_encrypt` the body is ciphertext and the relay sees the channel, the
  sizes and the timing. So `nodes`, `services`, `attributes` and `methods` decide
  traffic on a none or sign channel and are silent on a sign_and_encrypt one.
  `require_readable_bodies` is how a listener says which it wants; validation
  **warns** when service rules sit alongside a mode that makes them inert; and
  `opcua_opaque_bodies` counts the messages it happened to.

- **The attribute is the line between moving an actuator and changing who may move
  it.** A write to attribute 13 (`value`) is a setpoint. A write to attribute 17
  (`access_level`) is a privilege change. Both arrive as an ordinary Write, so
  `write_attributes` defaults to `value` alone and a refusal of a permission
  attribute is counted as `permission_write` rather than as a generic attribute
  refusal — because a log line that did not say so would not tell an operator what
  had just been attempted.

- **A Call names two nodes and both are checked.** The object it is on and the
  method itself, because allowing `Reset` on one pump is not allowing it on every
  pump of that model.

- **`min_publishing_interval` is the bound that matters most on this protocol**,
  because the amplification is arithmetic rather than accidental. A
  CreateSubscription asking for a one-millisecond publishing interval over a
  thousand monitored items is a server asked to send a thousand values a
  millisecond — from one legitimate session, in entirely valid protocol, with no
  flood and no spoofing. An interval of zero means "as fast as the server can",
  which is faster than any bound, so it is refused wherever a bound exists rather
  than read as unset.

- **`read_only` refuses what changes the plant and not what an HMI needs.** Write,
  Call, AddNodes, DeleteNodes, AddReferences, DeleteReferences, HistoryUpdate,
  RegisterServer and TransferSubscriptions, with no rule able to override it —
  TransferSubscriptions among them because it moves a subscription from one session
  to another, and on a plant taking over the stream an operator's screen draws from
  is a change to what that operator sees. The subscription services are *not* on
  that list: they change state the server holds rather than anything the plant
  does, and a read-only listener no HMI can subscribe through is a listener no HMI
  can use.

- **A refusal is expressed the way a server expresses one.** A service-level
  refusal is a ServiceFault carrying a bad status code against the request handle
  the client sent, so the client's own library reports the error and the poll loop
  carries on — dropping a session because one Read was refused turns a refusal into
  an outage. A channel-level refusal is an ERR and a close instead, and not by
  preference: a fault answering an OpenSecureChannel would have to be secured with
  the keys that OpenSecureChannel exists to establish, so the client's record layer
  would discard it and the operator would read a timeout.

- **Namespaces are named by index, and the reference states the caveat rather than
  offering a portable form that does not exist.** A namespace URI appears only in
  an ExpandedNodeId, and the node a Read, a Write, a Browse or a Call names is a
  plain NodeId — so on the wire a request identifies its namespace by index and by
  nothing else. Translating would mean reading and keeping the server's own
  NamespaceArray, which is learning rather than policy. An index means something
  only against the table it came from, and a firmware update can reorder that
  table, so a namespace list is one to review after one. The validator refuses a
  URI in that list with the reason, because it is the form an operator will reach
  for.

- **The listener takes no `tls` section**, and that is not an omission. The
  `opc.tcp` transport has no TLS; the security is inside the protocol, negotiated
  per connection in the secure channel. A certificate here would promise something
  the transport cannot do, and terminating the channel would make this relay a man
  in the middle of the one industrial protocol designed to notice — holding the
  plant's private key to do it. Nothing here decrypts, and nothing rewrites a
  body.

- **Nothing here logs a value or holds a password.** A Write's payload is a process
  value: a pressure, a temperature, a recipe parameter. The node, the attribute and
  the value's *type* go in the log; the value does not, and a method's arguments do
  not either. A username token's password is kept only as its length and whether an
  encryption algorithm was named — a relay that held a plant's passwords would be a
  relay worth attacking for them — and `refuse_plaintext_passwords` defaults on
  because under mode `sign` such a password is readable by anything on the path,
  this relay included.

- New counters: `opcua_channels`, `opcua_sessions`, `opcua_opaque_bodies`,
  `opcua_server_errors`, `opcua_server_faults`. `opcua_denied` is the ban trigger.

- One defect found while writing the wire package's tests: `FileTime` and
  `ToFileTime` went through a `time.Duration`, and the gap from OPC UA's 1601
  epoch to now is 1.3e19 nanoseconds where a Duration holds 9.2e18 — so every
  timestamp saturated silently and came out in the wrong century.

- **`opcua.learn` records what crosses the listener and writes the node rules
  for you.** Nobody writes a correct `nodes` list from an address space: it says
  which nodes exist, not which of them an HMI polls every second or which method
  a contractor's laptop calls at three in the morning. A subject is one identity,
  one class of service and one group of nodes — string identifiers grouped by
  their prefix so `ns=4;s=Line1/Pump1/Speed` and its siblings become one row
  proposing `ns=4;s=Line1/Pump1/*`, numeric identifiers listed under their
  namespace because digits have no structure to group by. `enforce` decides
  whether the policy is in force while the run measures, and is off by default
  with a warning, because a run that is also deciding cannot tell you what the
  policy would have broken.

- **The report leads with what it could not read.** A channel in
  `sign_and_encrypt` leaves the relay nothing, so a run over one records no nodes
  at all — and a report that did not say so would read as a run over an idle
  listener. `opaque_messages` is the first finding in the file, with what to
  change to learn from them.

- **A proposal narrower than the class, in three ways the tests forced.** The
  services named are the ones that were called, not the ones the subject's class
  covers, so an identity that read a live value does not get HistoryRead. A
  server fault is counted against the rows the request itself made rather than by
  identity and class alone — without which a fault landed on a row with no node
  in it, the rows the read made still read as traffic the server accepted, and an
  identity the server refused everything for was proposed a rule for it. And the
  handshake is in none of the rules, with the reason in the file: a client has
  sent no identity until it activates, so a rule naming one cannot match the
  messages that establish it, and somebody who added `open_secure_channel` to
  these rules would lock every client out.

- **What a run will never propose**: a security policy, a security mode,
  `allow_deprecated_policies`, or any of the bounds. Seeing a channel in mode
  `none` is not a reason to allow mode `none`, and a report suggesting the
  fastest publishing interval it happened to see would widen the one setting this
  listener exists to hold. They appear as observations under names no rule uses.

### Added (coap: a relay whose policy is a path)

- **`kind: coap` is a CoAP relay agent (RFC 7252) on UDP 5683** that reads what it
  relays: the method, the path and the content format of every request, and the
  size and content format of every answer.

- **This is the one OT-adjacent kind where a positive model is a sentence somebody
  can actually write.** CoAP is REST for devices too small to run TLS comfortably,
  and the request carries a method, a path and a content format — so it says what is
  about to happen in fields a relay can read. Under the LwM2M object registry the
  path *is* the object model: `/3303/0/5700` is a temperature reading and
  `/3311/0/5850` is whether a light is on. "Read anything under `/3303`, write only
  `/3311/0/5850`" is a policy about real equipment, which is why `default_action`
  is **deny** here and `allow` on the DHCP kinds.

- **`Proxy-Uri` and `Proxy-Scheme` are refused by default, and both.** They are two
  spellings of the same request — fetch this URI for me — so a relay that refused
  only the first would have refused nothing. What they turn the device at the far
  end into is an open forward proxy on a network that was segmented for a reason,
  with an amplification stage attached.

- **A refusal is answered rather than dropped.** A Confirmable request is
  retransmitted until something answers it, so silence turns one refused request
  into four or five and leaves the device's own log showing a timeout where a
  refusal happened. The standard supplies the codes, and `answer_refusals: false`
  warns.

- **An option this relay cannot name is refused the way the standard says.** An
  option number's own low bits carry its class (RFC 7252 §5.4.6): odd is Critical,
  bit one is UnSafe to forward. §5.4.1 answers an unrecognised Critical option with
  4.02 Bad Option and §5.7.1 an unrecognised UnSafe one with 5.02 Bad Gateway. That
  is rare in a protocol and a gift to a relay, because "I do not understand this"
  gets a defined answer instead of a judgement call — and the rule holds for options
  nobody has registered yet.

- **A path whose segments would not mean what the joined path looks like is refused,
  not normalised.** On the wire a `Uri-Path` segment is an arbitrary string of
  octets, so one segment may contain a slash and then render as two — and a rule
  about `/3303` is satisfied by a request that reaches `/3311`. Normalising would
  mean guessing what the device would have done with the original.

- **The amplification bounds are never shadowed.** A four-octet `GET` over UDP can
  return a kilobyte, and `/.well-known/core` (RFC 6690) exists to return a list of
  every other resource on the device. `amplification_factor` bounds the answer as a
  *multiple of the question*, which is the check a per-datagram bound cannot make,
  and `max_transfer_bytes` bounds a whole block-wise transfer read from the client's
  own `Size1` declaration — so the intent is refused at the first block rather than
  the sixty-four thousandth. A listener whose policy was being trialled would
  otherwise be a working amplifier with logging.

- **Observe is carried and bounded.** A registration (RFC 7641) is how telemetry
  works here and is the only request whose answer has no end, so `max_observers`
  answers "how many open-ended flows may exist" instead of leaving it to whoever
  asked for the most.

- **In NoSec there is no identity at all.** Most of the field runs CoAP with no
  DTLS, so a rule can name only the source address, and a listener with no `tls`
  section warns rather than letting a deployment find that out.

- **A `tls` section makes it CoAP over DTLS** (RFC 7252 §9), on the address the
  listener was given — 5684 by convention. The certificates, `client_auth` and
  `client_ca_file` are the same configuration every other listener uses,
  translated into DTLS rather than passed through, so a certificate reload
  reaches a running DTLS listener exactly as it reaches a TLS one. What has no
  DTLS equivalent is refused rather than ignored: `min_version: "1.3"` is an
  error, because §9 is DTLS 1.2 and DTLS 1.3 is not implemented here.

- **A session is an identity**, which is the reason to run DTLS in front of
  devices at all: `secure_only` on a rule then means something, and "the
  actuators may only be written by a client that authenticated" becomes a
  sentence the configuration holds. A refusal inside a session comes back
  *inside* the session — an answer written to the socket instead would be
  cleartext to a peer that established a session precisely so that it would not
  be, and the peer's own stack would discard it, so the failure would look like
  a timeout rather than a refusal.

- **The per-peer demultiplexing is this listener's own**, because a UDP socket
  gives one stream of datagrams from everybody where the kernel gives a stream
  listener one connection per peer. Every part of it is bounded — the peers, the
  half-open handshakes and the queue per peer — because on UDP a peer that
  starts a handshake has proved nothing, not even that it can receive. The
  library's own listener is not used: its Accept performs the handshake before
  returning, so one slow or hostile peer would stop every other peer
  establishing.

- `github.com/pion/dtls/v3` enters the tree for this, confined to one file on
  one kind. See [AMR-050](AMR.md) for the reasoning; a listener with no `tls`
  section links the library and never calls it.

- `internal/coap` is the wire package: the message layer, the option layer,
  block-wise transfer, Observe, the content format registry and the encoder the
  relay answers with. Fuzzed on the invariant that a message which parses writes
  back to the octets it was read from, which is what says nothing was read past the
  end of what a peer sent.

- See [`docs/protocols/coap.md`](protocols/coap.md),
  [`server.listeners[].coap`](CONFIG.md#serverlistenerscoap-kind-coap) and
  [`examples/ot/coap.yaml`](../examples/ot/coap.yaml).

### Added (dhcp6: the other half of a dual-stack estate's provisioning path)

- **`kind: dhcp6` is a DHCPv6 relay agent (RFC 8415) on UDP 547 that reads what
  it relays**, in both directions. It is a listener of its own rather than a flag
  on `kind: dhcp` because DHCPv6 is a separate protocol: a different packet
  format, a relay mechanism that nests whole messages rather than filling in a
  field, a client identified by a DUID rather than by a hardware address, and its
  own options — including prefix delegation, which has no DHCPv4 equivalent at
  all. An estate running both runs both listeners, and writing both down is the
  point.

- **It is also the half most estates have left unwatched.** A network that
  polices DHCPv4 carefully and has never looked at UDP 547 is a network where the
  IPv6 path is the way in, and there is *more* in an answer here: a boot file URL
  (RFC 5970), a captive portal a client will open (RFC 8910), an SZTP bootstrap
  server a switch will fetch a configuration from and apply to itself (RFC 8572),
  the S46 containers and AFTR name that put a host's *IPv4* traffic through a
  border relay of the sender's choosing, and the Server Unicast option, which
  tells a client to address the server directly and so switches off every policy
  this listener has. Each is stripped by default while the address itself goes
  through.

- **The resolvers and the search list are deliberately not on that deny list**,
  which is the same choice the DHCPv4 list makes about option 6. They have a
  positive list of their own — `allow_resolvers` and `allow_domains` — and that is
  the better check, because it names what the estate's resolvers *are* and so
  catches a compromised real server as well as a rogue one. Putting an option with
  a positive list on the deny list as well breaks twice over: the positive list
  becomes dead configuration, and handing out resolvers is the whole purpose of
  stateless DHCPv6 on a network that addresses itself by router advertisement — so
  the default would be one an estate has to switch off to get its network working.

- **Prefix delegation is bounded at both ends, and a prefix outside the estate's
  is refused rather than stripped.** A reply delegating `::/0` has handed a host
  the whole of IPv6 to route; a client asking for a /48 where the estate delegates
  /56s is asking a real server to give a segment away. There is no useful half of
  a delegation to keep, so `prefix_delegation` refuses rather than editing. A
  client's own `::/0` *hint* is still carried, because RFC 8415 §21.22 lets a
  client send one to mean "any".

- **A valid lifetime of zero is never bounded up.** Zero is how a server
  withdraws an address (RFC 8415 §18.2.10), and applying `min_lease_time` to it
  would turn a withdrawal into a lease — leaving a device holding an address the
  estate has given to somebody else. The preferred lifetime comes down with the
  valid one, because the reverse makes the option invalid.

- **The starvation bound is keyed on the DUID, not the source address.** Pool
  exhaustion on this protocol is one host sending thousands of SOLICITs with a
  made-up identifier in each, and a limit keyed on the source would see one sender
  doing nothing unusual. `max_clients` is the other half: the rate limit slows one
  identifier down, and that bound stops a flood of new ones filling the table
  doing the limiting.

- **The relay chain is bounded and read all the way down.** A DHCPv6 relay
  encapsulates rather than annotates, so a chain is a message inside a message; a
  reader that stops at the outer layer sees nothing a client said.
  `max_relay_hops` bounds the nesting, and the relay's own options are added on
  the way out and stripped from anything a *client* sent, because a client
  asserting which circuit it is on is asserting exactly what the option exists to
  say on its behalf.

- **`log_leases` is on by default**, and produces a line for every address and
  prefix handed out: which identifier got which lease, for how long, from which
  server, and what else that reply told it — the last being what a DHCPv6 server's
  own log does not have, because the server is the thing being checked. The MAC
  address inside a link-layer DUID goes to the asset inventory, which is what ties
  a DHCPv6 sighting to the device an estate already knows from DHCPv4.

- See [`docs/protocols/dhcp6.md`](protocols/dhcp6.md),
  [`server.listeners[].dhcp6`](CONFIG.md#serverlistenersdhcp6-kind-dhcp6) and
  [`examples/addressing/dhcp6.yaml`](../examples/addressing/dhcp6.yaml).

### Added (nts: terminating Network Time Security in front of a server that cannot speak it)

- **`ntske.terminate` makes the key establishment listener the key establishment
  server**, and **`ntp.nts.mode: terminate`** makes the time listener verify what
  clients send. Together they are the case NTS is awkward for otherwise: a plain
  NTPv4 server that cannot speak NTS and is not going to, in front of clients
  that will. The clients get authenticated time, the source gets a request from
  one address it already knows, and the verification happens where an operator
  can see it counted.

- **In this mode "authenticated" means this relay checked.** That is the whole
  difference from pass-through, where every visible NTS field is readable by
  anybody on the path and proves nothing: a packet whose authenticator does not
  verify is refused rather than forwarded with a note.

- **The answer's time is the source's, octet for octet.** The first forty-eight
  octets are copied, because every field in them is the source's statement about
  its clock and a relay that adjusted one would be inventing time. What is added
  is the client's unique identifier and an authenticator sealed with the client's
  own server-to-client key.

- **The request goes upstream as a bare header.** The extension fields were the
  client's conversation with this relay: the cookie names a key the source does
  not hold, the authenticator covers a packet it will not verify, and a
  placeholder asks for something only the party that issues cookies can give.

- **The cookie keys rotate with an overlap and survive a restart.** A client
  holds days of cookies, so a rotation that invalidated them at once would take
  the estate's time service down until every client re-established — a TLS
  handshake each, all in the same second. `rotate_every` (a day), `keep_keys`
  (two) and `state` (a file, mode 0600, written at the first start rather than
  the first rotation) are each there because the alternative is that outage. A
  state file that is there and cannot be read stops the listener rather than
  being ignored.

- **New packages.** `internal/siv` is AES-SIV-CMAC (RFC 5297), the AEAD NTS
  mandates and the standard library does not have, pinned against the RFC's own
  test vectors. `internal/ntske` is the key establishment record layer (RFC 8915
  §4), the exporter derivation (§5.1) and the cookie format. `internal/ntp`
  gained the authenticator of §5.6: verify, seal, and the refusal of anything
  after the authenticator, because everything before it is authenticated and
  anything after it is not.

- **One detail worth writing down**, because it would have passed every test and
  failed against every real client: an NTP extension field's length is padded to
  a multiple of four with nothing to say how much of it is padding, so a cookie
  that is not a multiple of four comes back longer than it left and does not
  open. The cookie format is sized to fit, and there is a test that says why.

- Counters `ntske_terminated`, `ntske_cookies`, `ntske_no_terms`,
  `ntp_nts_verified`, `ntp_nts_unverified`, `ntp_nts_cookie_unknown` and
  `ntp_nts_cookies_issued`; refusals `nts_no_authenticator`, `nts_no_cookie`,
  `nts_cookie_unknown`, `nts_unverified`, `nts_no_session` and
  `nts_no_cookie_keys`, which are separate because they mean different things to
  an operator — a cookie this relay never issued is a client that established
  keys somewhere else, and an authenticator that did not verify is a packet that
  was tampered with.

- **`ntp.nts.source` is the other side of the same decision: re-origination.**
  Without it the relay asks the time source in plain NTP, which is right when
  the source cannot do better. With it the relay holds an association of its
  own -- its own key establishment with the source's key establishment server,
  its own cookies, its own authenticator on every request, and verification of
  every answer.

- **The cost is stated rather than hidden**, in the configuration reference, the
  protocol page and a validation warning that fires whenever it is on: there is
  no end-to-end authentication between a client and the time source any more.
  The client authenticates to this relay and this relay authenticates to the
  source, so the process is a party to the security rather than a reader of it.
  What it buys is a relay that can compare, police and log what the source says
  while both halves are still authenticated, which a pass-through relay cannot
  do at all.

- **A request that arrives before the relay holds keys is dropped**, with the
  reason `nts_source_not_ready`, rather than sent in plain NTP: a relay that
  quietly downgraded its own request would be doing the thing the setting exists
  to prevent, and a time client retries. An answer that does not echo the
  identifier the request carried is refused too -- the keys are the same for the
  whole association, so without that check an answer to another of this relay's
  requests would verify.

- **The source's own key establishment cannot move the time traffic.** A
  response naming another server or port is logged and not followed: where the
  relay sends time traffic is the upstream pool and `allow_servers`, which is
  the estate's decision.

- **A plain client behind a re-originating relay gets a plain answer.** The
  source's NTS fields are the relay's conversation with the source and carry the
  relay's own replacement cookies, so they are not forwarded to a client that
  did not ask for them.

- `internal/ntske` gained the client half: a `Client` that does one whole
  exchange, insisting on TLS 1.3 and the `ntske/1` application protocol whatever
  the caller's configuration says, and refusing a response that chose terms the
  relay did not offer, that carries no cookies, or that is not a whole message.
  It is tested against this package's own server half rather than a recording of
  one.

- A worked configuration in `examples/ot/nts-gateway.yaml`, with the
  re-origination it would use once the old server is replaced.

### Added (snmp: version 3 toward the agent, with an identity of the relay's own)

- **`upgrade_version: v3` works, with `upstream_usm`.** It was refused at load,
  for a true reason: there was no user, engine or key to authenticate a message
  with, and the relay will not forge an authentication that did not happen.
  `upstream_usm` supplies one, and the relay then **terminates** the manager's
  security and **re-originates** its own toward the agent.

- **The deployment this is for**: the agents were replaced and the polling system
  was not. A v1 or v2c poller now reaches a v3-only agent with authentication and
  privacy the poller cannot speak, using a pass phrase it never holds — so the
  credential that opens the agent lives in one place, and v1 does not have to
  stay enabled on the equipment for ever.

- **The cost is documented rather than hidden**, in the configuration reference,
  the protocol page and a validation warning: there is no end-to-end
  authentication between the manager and the agent any more. The manager
  authenticates to the relay and the relay authenticates to the agent, so the
  process is a party to the security rather than a reader of it. An estate that
  wants USM end to end wants `usm_users` and no upgrade.

- **The agent's engine is discovered, not configured.** USM authenticates against
  the authoritative engine's clock, and that engine is the agent's. A first
  request to a cold agent draws an RFC 3414 §4 discovery that carries the
  manager's own request identifier, so the report pairs with the waiting question
  and it is that question which then gets asked properly. A burst to a cold agent
  sends one discovery. `upstream_usm.engine_id` pins the identifier where it is
  known, and an engine calling itself something else is not believed.

- `internal/snmp` gained the encode half of USM: `BuildV3`, `ScopedPDU` and the
  DES and AES encryption that mirror the decryption already there. The digest is
  computed over the finished message with its own field zeroed, which is what RFC
  3414 §6.3.1 says it covers, and the field's offset is computed during assembly
  rather than searched for afterwards. The tests round-trip through `Verify`,
  `Decrypt` and `ParseScoped` — written for other implementations' messages and
  sharing no code with the builder — and one of them changes every octet of a
  signed message in turn and requires the digest to notice.

- The end-to-end test's fake agent derives its keys from the pass phrase itself
  and verifies what arrives, so the assertion is that a party holding only the
  pass phrase accepts the relay's message, not that the relay can read back its
  own.

- New counters `snmp_discoveries` and `snmp_originated`: discoveries that climb
  beside a flat originated count are an agent not answering them.

### Added (a `flow` filter: the request that is valid in the wrong order)

- **`kind: flow` enforces the order of a business flow**: a step may be reached
  only by a caller already seen at the steps it depends on. It is the other half
  of cross-request detection. `api_abuse` watches the *shape* of a sequence — how
  many objects, how consecutive, how often refused — and answers questions nobody
  wrote down; this answers one somebody did.

- A payment taken for a cart nobody filled is three valid requests and one wrong
  order. A WAF sees nothing, an OpenAPI schema sees nothing, a rate limit sees
  nothing and a positive security policy sees nothing, because each request is
  individually permitted. This is OWASP API Security Top 10 **API6:2023**,
  unrestricted access to sensitive business flows — and the same control the
  `modbus` kind spells `require_before`: a plant will not let a valve be driven
  without the select that precedes it.

- **The caller is the authenticated identity when the chain established one**, and
  the client address otherwise, so the filter belongs after the identity filters.
  That is not a detail: keyed on an address, one NAT gateway's cart would satisfy
  another user's payment.

- `block` answers **409 Conflict** — the request is well formed and the caller is
  entitled to make it, but not in the state they are in. `log` is the default,
  because the relay cannot see the steps a caller took before it was in the path,
  and a flow declared slightly wrong refuses real customers.

- **A refused step is still recorded.** A refusal that did not record would be
  refused on every retry, so a caller who genuinely lost an earlier step — to a
  restart, to the other relay in a pair — could never get through at all: the flow
  would be permanently broken for them rather than broken once.

- Traffic matching no step is not judged, so the filter does not become a second,
  accidental positive security policy. Path prefixes match on whole segments, so
  `/api/cartridges` is not inside a flow that starts at `/api/cart`. `once` is the
  double-submit control and is **off** by default: a step reached twice is usually
  a customer who pressed the button again after a timeout, and the second press is
  the one that works.

- Two limits the documentation states rather than hides: the state is one
  process's, so behind two relays a caller whose cart landed on the other one
  looks like a caller who skipped it; and the state starts empty, so every caller
  mid-flow at startup has no recorded earlier step.

- `flow` is a ban reason a trigger can name, and the filter carries the usual
  counters.

### Fixed (learning reports: a data race between rendering and observing)

- **The modbus and NTP learning reports are rendered outside the learner's lock,
  from a snapshot that copied each observation by value** — and an observation
  holds slices and maps. The copy shared their backing storage, so the next frame
  was writing what the renderer was reading.

- For modbus the shared storage is the address range sets, and `addRange` merges
  *in place* (`rs[i].Lo = lo`, and `mergeRanges` writes through `rs[:0]`): a report
  could name a range half way through being merged.

- For NTP it is worse. The shared storage includes the map of NTS key identifiers,
  which the report ranges over, and a map written while it is being ranged over is
  not a race the runtime tolerates — it is a fatal "concurrent map iteration and
  map write" that ends the process. For a relay in front of a plant's clocks that
  is an outage caused by writing a report.

- Both snapshots now clone. Both have a test that renders a report while traffic
  arrives, and both fail under `-race` without the clone. The four learners on the
  shared `internal/learn` core were already safe: that is what its `Clone` is for.

- **The NTP learner also recorded a stratum per subject and rendered it nowhere.**
  That looked like a gap beside the `allow_strata` policy key, and filling it would
  have been wrong: `allow_strata` is the list of strata an *answer* may carry, and
  this learner sees the client's requests, whose stratum field is the client's own
  — usually 0, which is the kiss-o'-death value a server sends. The field is gone,
  and the struct says why, so that the next reader does not helpfully propose it.

### Fixed (sandbox: the seccomp filter stopped a hardened process creating threads)

- **`clone3` was refused with `EPERM`, and it has to be `ENOSYS`.** glibc's
  `pthread_create` calls `clone3` first and falls back to plain `clone` — which
  this filter allows — only on `ENOSYS`. Refused with `EPERM` it does not fall
  back: it fails, and a process linked against glibc **cannot create a thread at
  all** once the sandbox is on. The Go runtime calls `clone` directly, so the
  shipped `CGO_ENABLED=0` binaries never hit it; a cgo-linked build aborts with
  `runtime/cgo: pthread_create failed: Operation not permitted` the moment
  anything wants an OS thread after hardening.

- Nothing is given away by the change. `clone` is allowed either way, so refusing
  `clone3` was never what stopped a new process being made — `execve` and
  `execveat` are, and they stay `EPERM`.

- **It surfaced as a test that failed only under load.** `TestApplyLinux` runs the
  sandbox in a helper subprocess, and the race-enabled test binary is a cgo
  binary: under load the runtime wanted another thread after the sandbox went on,
  the helper aborted *after* passing every check it made, and the parent reported
  "helper failed: exit status 2". The helper now starts twenty-four locked OS
  threads deliberately and the parent asserts it got them, so the property is
  checked rather than sampled.

### Added (modbus: behavioural detection, which needs no rules)

- **`anomaly` answers a question the rules cannot**: not *is this permitted* but
  *is this what this master has been doing*, with nothing written down. Control
  traffic is repetitive in a way other traffic is not — a master's scan cycle is
  the same few function codes over the same few address ranges, every cycle, for
  years — so "this client has never done this before" is a signal here where on a
  web front end it would be noise. It watches a function code the client has not
  used (`anomaly_new_function`), a write to a register it has never driven
  (`anomaly_new_write_address`) and a burst of writes across every address
  (`anomaly_write_burst`).

- **The burst is the one that a value rule's `rate` cannot see.** A rate of "this
  setpoint may move once a minute" does not notice a master that wrote forty
  *different* registers once each, which is not a rate violation anywhere and is
  exactly the shape of somebody walking the address space.

- **It alerts, and the alerts do not reach the ban ladder.** A detector built on
  novelty fires on the first legitimate maintenance write of the year, and banning
  a plant's master for it would take the process away from the control room —
  worse than what is being guarded against. `action: deny` exists for the plants
  that want it, refuses the *first* occurrence and records it so a retry goes
  through, and is warned about at validation: it buys a hard stop and an
  operator's attention, not a block.

- **It settles before it reports.** When the relay starts everything is new, so a
  client's first `settle` (10m by default) is recorded quietly. The burst is not
  suppressed during it, because that bound is a number an operator set rather than
  something learned.

- A master that writes more distinct ranges than the detector holds has its
  novelty detection turned off and counted, rather than having its ranges
  collapsed into one span: widening what counts as seen would make the detector
  stop detecting while it went on looking like it worked.

- `settle` and `write_burst` are read as pointers, so `0s` and `0` mean *off*
  rather than *default*. The first version read them as plain values, so a
  listener configured with `write_burst: 0` silently kept the default of twenty
  and went on reporting bursts — a detector that had been turned off and was not.
  The test that found it now asserts fifty writes against a bound of zero.

### Fixed and added (modbus: the learning report proposed a bound looser than the traffic)

- **The value bound a learning report proposed was derived from every register a
  subject touched.** A master writing a 0..40 bar setpoint at register 400 and a
  0..3 mode at 401 is one subject, so the report proposed
  `values: [{min: 0, max: 40}]` — which permits setting the mode to 40. An
  engineer who pasted it got a value policy that was wrong in a way that *looked*
  derived from evidence, which is worse than having none. That proposal is gone.

- **In its place, a process baseline per address**: the envelope of the values
  written there, the largest step between consecutive writes, and the most writes
  seen in any one sliding minute. Those are what `min`, `max`, `max_delta` and
  `rate` are written from, and the report proposes them as a `values` block. This
  is what turns a learning run from an allow-list into something a value policy
  can be written from — the gap the roadmap named as "learning today produces
  allow-lists, not anomaly detection".

- Adjacent addresses whose baselines really are the same are one entry, because a
  report with a line per register of a forty-register block is a report nobody
  reads. Adjacent addresses that differ stay apart, which is the whole reason for
  recording them separately.

- **The report says, in capitals, that a baseline is where a conversation starts
  and not a control.** It is derived from traffic, and traffic is what somebody
  already inside has been shaping: a run on a plant quietly driven out of its
  envelope for a month learns the wider envelope. Nothing installs itself.

- Three narrower decisions: a **read** sets no baseline, because a bound proposed
  from what the process produced would permit a master to write anything the plant
  ever reached on its own; a **step is a distance**, so a setpoint dropped by
  fifty moved as far as one raised by fifty, and where no step was observed
  `max_delta` is left out rather than written as `0`, which would refuse every
  change; and a **coil** is observed and never proposed, because "this coil may
  only be set" from a run where nobody happened to clear it would refuse the reset
  somebody needs at three in the morning.

- **Two defects the baseline work found in the report that was already there.**
  The proposed block said to paste it under `modbus.values`, and there is no such
  key: a value policy belongs to a rule, so the block is the `values:` of the rule
  that allows those writes. And the *observation* of what a subject wrote read the
  register words of every writing function code, including three whose words are
  not values at addresses — code 5 encodes a coil's bit as `0xFF00`, code 22
  carries an AND mask and an OR mask, and code 8 a diagnostic argument. Switching
  one coil on therefore reported `values_written: {min: 65280, max: 65280}`, and
  the new per-address baseline would have proposed it as a bound. Both are fixed,
  and there is now a test that loads every block the report proposes through the
  real configuration parser, because a proposal in a vocabulary the loader does
  not read is worse than no proposal: the engineer's conclusion is that the tool
  is broken rather than that the line is wrong.

- Folding adjacent addresses into one entry now requires the write *count* to
  match as well as the envelope, the step and the peak rate. Every one of those is
  printed, so folding on anything less printed one address's number for another's:
  two registers written the same two values, one of them twice over, became a
  single line claiming two writes for an address that had four.

### Added (iec104: IEC 62351-5 recognised, counted and requirable)

- **The thirteen IEC 60870-5-7 secure-authentication types are named.** Before
  this, a listener saw type 81 as an unknown type and its policy refused it —
  which made the standard's own authentication *unusable through this relay*.
  That is the failure this mostly closes. They are the rule class `security`: its
  own class, so a rule allowing the authentication exchange does not thereby allow
  a station reset.

- **`iec104_authentications` counts the replies and aggressive-mode requests
  seen, whether or not the listener requires them.** An estate decides whether to
  turn the requirement on by finding out which of its associations already
  authenticate, and a counter that only moved once the requirement was in force
  would be no help in making that decision.

- **`authentication: {require: true}` refuses a command on an association that has
  shown no exchange inside `window`** (5m by default, because the standard's own
  session keys expire and an authentication that never did would let one exchange
  at connection time authorise every command for a week). The state is per
  association: crediting one connection's exchange to another would let a client
  that can open a socket ride on a legitimate control centre's authentication,
  which is the whole thing being defended against.

- **This relay does not verify an authentication, and says so.** Verifying means
  holding the update keys, and a relay holding them would be a second place for an
  attacker to take them from; one that failed closed on a key it had got wrong
  would stop a control centre operating a grid. No HMAC is computed, no key is
  stored, and nothing is asserted about validity — only that the exchange the
  standard defines took place, which is the most a party in the middle can
  honestly assert.

### Added (iec104: the information element, decoded and policed)

- **`ASDU.Elements` decodes the information element.** Until now this relay read
  an ASDU's header and, for a command, its qualifier and setpoint value — enough
  to decide which points a station may be commanded on and nothing about what it
  reports of them. Every layout is a table entry rather than a case in a parser,
  because a table can be checked against IEC 60870-5-101 section 7.3.1 by reading
  it, and a type absent from the table decodes to nothing rather than to a guess.

- **`quality` is what to do about the quality descriptor.** `substituted` — a
  person typed the value in rather than an instrument measuring it — is alerted on
  by default, because it is the bit no HMI in the field shows and a control centre
  acting on one is acting on somebody's opinion of the plant. `invalid` and
  `not_topical` are left to be asked for: they are ordinary on a substation with a
  device out for maintenance, and alerting on them by default would teach an
  operator to ignore the alert.

- **`timestamps` is the replay check this protocol most needs and least
  performs.** A time-tagged command replayed an hour later carries the hour-old
  timestamp with it, and nothing in IEC 60870-5-104 makes a station compare that
  against its clock — so a recorded breaker command, sent again, opens the breaker
  again. `max_command_age`, `max_command_future`, `require_on_commands` and
  `deny_invalid` are that comparison, and those refusals are **hard**: a command
  forwarded so that its age could be written down is a moved actuator. A station's
  own confirmation is never checked, because it carries the same timestamp and
  refusing it would leave a control centre waiting for the answer to a command
  this relay already let through.

- **`measurements` bounds what a station may report**, which is the arithmetic of
  `setpoints` pointed the other way. A pressure of 900 bar on a 40 bar transmitter
  is a broken instrument or a forged frame.

- **Telemetry is alerted on and carried; a command's timestamp is refused.** That
  asymmetry is the design: a relay that refused telemetry would blind a control
  room, which is its own kind of incident and a worse one than an implausible
  reading reaching a trend. So `quality` and `measurements` default to alert, their
  `deny` is soft, and an alert from either does not reach the ban ladder — a
  substation with a hand-entered reading is not an attacker, and a ban would take
  the control room's telemetry away over a data-quality problem.

- Every object of an ASDU is walked, not only the first. A report carrying forty
  measurements carries forty chances for one of them to be the substituted one.

### Added (mqtt: learning mode, and never a `#`)

- **`mqtt.learn` records what crosses the listener and writes proposed topic
  lists.** A broker in a plant carries topics nobody wrote down: the naming
  convention is in a document from 2019, the gateway that was replaced still
  publishes under the old prefix, and the historian subscribes to something wider
  than anyone remembers agreeing to. A `publish_allow` list written from the
  convention refuses what does not follow it, which on a message bus means
  telemetry *silently stops arriving* — the client keeps publishing and nothing
  changes on the screen until somebody notices a flat line.

- **No `#` is proposed, at any depth, for any subject.** This is the whole
  difficulty of learning on this protocol and the easy answer is the wrong one:
  `plant/#` covers every level under `plant`, including the ones that do not exist
  yet, so an allow list built from it allows the thing it was supposed to bound.
  What is proposed is a filter of exactly the depth observed, with `+` — which
  matches one level and no more — at the positions where the traffic varied.
  `plant/line3/press1/temperature`, `.../pressure` and `plant/line3/press2/...`
  become `plant/line3/+/+`, and the levels seen at each position are listed so a
  `+` can be narrowed by hand. A position whose values outran the bound the report
  remembers is still only a `+`.

- **The topic depth is part of a subject's identity**, because a `+` matches one
  level: topics of different depths cannot share a filter, and a report that
  folded them together would have had no choice but to widen. Two depths produce
  two filters.

- **A filter the client wrote is recorded and proposed verbatim**, under
  `depth: filter`, because a subscription is already a filter. If a historian
  asked for `plant/#` then that is what it needs; the report flags it rather than
  proposing something narrower that would break it.

- The identity is the CONNECT username, or the address when there was none — not
  the client identifier, since many clients generate a fresh one per connection
  and a subject each would be a subject per reboot. The identifiers seen are
  listed inside the subject, which is what `client_id_pattern` is written from.

- **`allow_retain: false` is never proposed**: a run that saw no retained message
  has not learned that none is wanted, so the key is left out and the listener's
  default decides. Payload sizes and the QoS span become the proposed `topics[]`
  bounds; no payload is recorded.

### Added (tftp: learning mode, with the amplification bound left alone)

- **`tftp.learn` records what crosses the listener and writes a proposed
  policy.** On this protocol there is less to go on than anywhere else: no
  authentication, no session and no account, so nothing is auditable in the
  ordinary sense. A switch fetches its firmware at three in the morning and the
  server's own log, when it has one, gives an address and a path and says nothing
  about which of them were meant to happen.

- A subject is one client, one direction and one directory, because
  `directories` is the line an engineer argues about and a subject per file would
  be a report per file. The filenames inside it are listed, bounded.

- **The amplification bounds are recorded and never proposed.** A request past
  `max_window_size` or `max_block_size` is lowered to the bound and still
  transfers, so the report sees the window of sixty-four a switch asked for — and
  a report that turned that into `max_window_size: 64` would have widened, from
  an observation, the one setting that stops a twenty-octet request yielding a
  file to a forged address. They appear as `window_asked`, `block_size_asked`,
  `declared_size` and `bytes_moved`, which no rule uses, and `enforce: false`
  suspends the path, direction and mode policy without touching a bound.

- **A `filenames` pattern is proposed only when the names generalise.** Names
  sharing a small set of extensions become `firmware/*.bin`; names that share
  nothing, or more extensions than the report remembers, get no pattern and a
  note saying why. The only pattern that always fits is `*`, and a rule
  permitting every file on the server is not what "derived from the traffic"
  should produce. The *name* bound deliberately does not make a subject
  ungeneralisable: every name's extension is recorded whether or not the name
  itself was, so four hundred images all ending `.bin` still propose one pattern
  that covers the ones the report did not list.

- `server_errors` counts what the *server* refused, and a subject with nothing
  but those is not proposed: a device asking for a file nobody uploaded is not a
  rule to write. A filename in a class this relay and the server would read
  differently is recorded under `path_class` and never proposed, and no file
  contents are recorded at all.

### Added (s7: learning mode)

- **`s7.learn` records what crosses the listener and writes a proposed policy.**
  On this protocol there is nowhere else to find out what the traffic is: the CPU
  keeps no access log, and nobody can enumerate the blocks a program touches by
  reading the program. The drawings say which blocks a controller has; the traffic
  says which of them the HMI reads every second and that the commissioning laptop
  has been reading DB1 since 2014. A run is observe-only unless `enforce` says
  otherwise.

- A subject is one client, one operation, one area and one data block — the grain
  an S7 rule is written at. Byte ranges merge as they grow, so two adjacent reads
  are one span, and **what was written is kept apart from what was read**, because
  that is the rule read most carefully and `write_addresses` is the key it becomes.

- **An access fault from the controller is attributed to the request it answers.**
  A response carries the function and the return codes and never the area or the
  block, so the request is where the subject was known; a fault is charged only to
  subjects of the operation it answers, so a password-protected CPU refusing
  writes does not cost the HMI its read. A subject the controller refuses every
  time is left out of the proposal: permitting it would permit something that
  cannot happen.

- **The proposal is written in the vocabulary `operations` uses**, so it loads. An
  operation this relay cannot name is recorded as `operation: unknown` with the
  raw function code beside it and no rule proposed for it, and an item addressed
  in a syntax this relay does not decode is recorded without an area or a block
  rather than under a fabricated `area: 0`.

- No process value is recorded, and neither is S7comm-plus: its policy is about
  opcodes rather than areas and blocks, and one report cannot propose rules in
  both vocabularies.

### Added (iec104: learning mode, and a shared core for every kind's)

- **`iec104.learn` records what crosses the listener and writes a proposed
  policy**, as `modbus.learn` does. Nobody knows what a substation's traffic
  actually is: the drawings say which points exist and which a control centre is
  supposed to command, and the traffic says what the integrator left behind. A
  policy written from the drawings refuses half of it on the first shift, which is
  how a security control gets turned off and stays off. A run is observe-only
  unless `enforce` says otherwise, because a run that refused half the traffic
  would have changed the thing it was measuring.

- A subject is one client, one **direction**, one common address and one type
  identification. The direction is part of the identity because the same type
  means different things each way — an activation going down is a command and the
  confirmation coming back is the station answering — and a report that folded
  them together would propose a rule allowing a station to command its own
  control centre.

- **A negative confirmation is attributed to the command it refuses**, not only
  to the answer it arrived as. Counted where it arrives it would tell an engineer
  that confirmations come back, which they do; counted against the command it
  says *this command is refused by the equipment*, and the proposal leaves such a
  command out rather than permitting something that cannot happen.

- The report carries `denied_by_policy` (what the current policy refused, or
  would have) and the causes of transmission actually used, which is the part of
  an IEC 104 rule most often written too loosely. The measurements travelling up
  are deliberately absent and a setpoint's span is present, because the span is
  the bound `setpoints` is written from and a learning report is a file that gets
  pasted into a ticket.

- **`internal/learn` is the machinery underneath**, extracted rather than copied
  because four more kinds need it: the bounded insertion-ordered table, the
  periodic write and the one at shutdown, the atomic replace, and the counters
  that say a run stopped learning. It takes a `Clone` for the observation, which
  the modbus original did not have — the report is rendered outside the table's
  lock, and a shallow copy of an observation with a slice field leaves the
  renderer reading an array a concurrent append is still writing to.

### Changed (the relays' tripwires reach the ban ladder)

- **`modbus_tripwire`, `iec104_tripwire`, `s7_tripwire`, `redis_tripwire`,
  `mysql_tripwire` and `postgres_tripwire` are now nameable in a ban trigger's
  `reasons`**, as `telnet_tripwire` and `ssh_tripwire` already were. They
  counted and logged but never reached the ban list, which was an accident of
  the order the kinds were built rather than a decision: a write to a coil on a
  PLC that is not there is as strong a signal as a `wget` typed into a shell
  that is not there. The ordinary fabricated exchange still does not feed the
  ladder, because banning a client for having been answered ends the collection.

- **`snmp_tripwire` deliberately stays out of that list.** A ban acts on a
  source address, and the fabricated agent never answers a version 3 message —
  so every exchange it does answer is unauthenticated v1 or v2c over UDP, where
  the address is whatever the sender wrote. Banning on it would let one forged
  packet have somebody else's address banned. The rule, now written down in
  `denyReasons` and in DECEPTION.md, is that a tripwire reaches the ladder only
  where the proxy knows who sent the frame that tripped it — which is also why
  the fabricated resolver attributes an unverified datagram to nobody.

### Added (ssh: a bastion that is not there)

- **`ssh.deception` answers a refused credential with a fabricated bastion**,
  either where a refusal would otherwise be written (`mode: answer`) or as a whole
  listener with no machine behind it (`mode: decoy`). Port 22 is scanned as
  continuously as port 23, but with a different list: the account names an estate
  actually uses -- `git`, `jenkins`, `postgres`, `deploy`, `ansible` -- tried with a
  few passwords each. The list is the intelligence, and an account name in it that
  an operator recognises is a finding on its own.

- **A public key is recorded by fingerprint and then refused**, so the client falls
  back to a password as it would against a server that trusts no keys -- and the
  password is what a trap on port 22 is for. A visitor let in on a key would have
  proved only that it holds one.

- **In `mode: answer` the section adds no authentication method the listener did
  not already offer.** It wraps the callbacks that are there, because a key-only
  bastion that started advertising password authentication when a deception section
  was added would have had its front door changed by a logging feature. Collecting
  passwords on purpose is a `mode: decoy` listener of its own.

- **A partial success is not a refusal.** RFC 4252 partial success is the protocol
  saying that credential was right and another factor comes next, so the factor
  after it is asked for as usual and the wrapping is carried into that round. Read
  as a refusal it would have handed out a shell instead of asking for the second
  factor -- the second factor removed by the feature that exists to watch people
  fail it.

- **It replaces the refusals that happen after the proxy has spoken**: a refused
  credential, a failed second factor, the estate's `authorization` policy and a
  missing access grant. The last two are asked at all only where there is a
  target to be authorised for, so a `decoy` listener is not asked and produces no
  refusal against a session that was never going anywhere. It does not replace
  `allow_clients` or a ban, and it never replaces an outage.

- **Nothing is forwarded and nothing is run.** `direct-tcpip`, `tcpip-forward` and
  `x11` are refused and are tripwires, because an open relay would put this
  estate's address on somebody else's work; a `subsystem` request (sftp, so an
  upload rather than a fetch) is refused too, because there is no fabricated file
  system to put a payload in. The credential is kept as a user name, a length and a
  correlation handle under a process-lifetime key, exactly as for telnet.

- Counters `ssh_deceived` and `ssh_tripwire`; the refusal counters still move, so
  `ssh_auth_failed` and the `auth_failed` deny events say what happened even where
  the client was told it got in. `ssh_tripwire` is nameable in a ban trigger's
  `reasons`; the ordinary fabricated exchange is not, because banning it would end
  the collection. A decoy listener needs no `upstream`, `authorized_keys`,
  `users_file`, `trusted_user_ca_keys`, `upstream_key_file` or
  `upstream_known_hosts`, and will not compile with `upstream`, `mfa` or
  `require_grant`.

### Added (telnet: a login that is not there)

- **`telnet.deception` answers as a fabricated device**, either where a refusal
  would otherwise be written on a listener that fronts real equipment
  (`mode: answer`) or as a whole listener with nothing behind it (`mode: decoy`).

  This is the protocol where the arithmetic changes most, because what arrives on
  port 23 is not a person but a dictionary: the Mirai family and everything written
  after it walk the credentials that shipped on recorders, cameras and routers, a
  handful at a time from a great many addresses. Refusing collects the address the
  firewall log already had. Answering collects the *list*, and then the four
  exchanges that follow a login -- the busybox probe, the `echo` liveness check, the
  `cat /proc/cpuinfo` that picks the payload, and the `wget` that names the payload,
  the address serving it and the architecture it was built for. That last line is an
  artefact nothing else in this proxy produces.

- **No password is recorded, in any form a guess can be tested against** -- and this
  is the section where that rule is hardest, because here the credential is the
  intelligence. What is kept per attempt is the user name, the credential's length,
  and a `credential_id` computed under a key the process makes at startup from the
  system random source and never writes down: enough to answer "how many distinct
  passwords did this client try, and have we seen this one before", and nothing at
  all to whoever reads the log afterwards. A process with no random source produces
  no handle rather than one under a constant key. The recording, where one is
  configured, holds the shell transcript and not the login, even with `input: true`.

- **The login never turns on the credential.** Every credential is accepted once
  `attempts` have been taken, and which one it was makes no difference to what
  follows: a trap that accepted the right password and refused the wrong one would be
  a credential oracle, which is the one thing a password list needs. `attempts: 2`
  or `3` is what a real device's login looks like and collects more of the list.

- **Nothing is run and nothing is fetched.** `wget`, `curl`, `tftp` and `ftpget`
  answer the connection timeout a device behind a firewall answers, after the address
  has been written down. A fabrication that fetched the payload would be doing the
  download on the attacker's behalf, from this estate's address and with its
  reputation, which turns a sensor into a participant.

- **It never replaces an outage.** In mode answer the fabrication sits where a
  policy refusal would be -- a failed or locked second factor, the `authorization`
  policy, a missing access grant -- and not where `allow_clients` or a ban refuses,
  and not where the equipment is simply unreachable: an operator working an incident
  must be told that rather than handed a device that is not there.

- **A decoy listener will not compile with `mfa` or `require_grant`**, because its
  own login prompt is the trap and accepts everybody: a factor in front of it would
  refuse the visitors it exists to collect, and a grant would be checked against a
  name nobody real typed. It also stops warning about the missing `tls` section --
  an unencrypted telnet port is what the scanning is looking for.

- **It invents no credentials and no work**: `/etc/shadow` lists the accounts with
  `*` where a hash would be, `/tmp` is empty, and so is the shell history, because a
  fabricated one would be inventing a person who used this machine.

- The tripwires need no configuring: the escalation in the order it happens, fetch
  (`wget`, `curl`, `tftp`, `nc`), make it run (`chmod`, `chattr`, `dd`), keep it
  running (`nohup`, `setsid`, `insmod`), clear what would have stopped it
  (`crontab`, `iptables`, `systemctl`), and the file names a credential lives in.
  `passwd` is deliberately absent, because `/etc/passwd` is the commonest
  reconnaissance on any machine and a tripwire matching it would make every session
  look like an escalation.

- New package `internal/fakeshell`, which is the login and the shell both this kind
  and the SSH bastion use; two profiles (`busybox`, `linux`); new counters
  `telnet_deceived` and `telnet_tripwire`; and an entry in `xproxyctl decoys` like
  the others. A session is bounded in commands as well as by the idle and session
  timeouts, so a script in a loop cannot hold a worker on a listener whose whole
  purpose is to be found.

### Added (dns: a resolver that is not there)

- **`dns.deception` answers as a fabricated resolver**, either where a refusal
  would otherwise be written on a real listener (`mode: answer`) or as a whole
  listener with nothing behind it (`mode: decoy`). In mode answer it sits in the
  four places that say the name does not exist -- the block list, an imported name
  list, a policy zone whose action is nxdomain, and the cooldown on a domain a
  client was caught tunnelling under -- and nowhere else; an RPZ rule that named
  local data, nodata or tcp_only is an answer somebody wrote and is not overruled.

  On every other protocol a refusal costs the other end a request. Here it costs
  them the conversation, because the query is all they ever send: a name on a feed
  answered NXDOMAIN tells an implant that something on this network is deciding,
  and a tunnel told NXDOMAIN moves to the channel nobody is watching. A fabricated
  answer keeps both of them talking, and every query after the first is the next
  domain in the rotation or the next chunk of what was leaving.

- **A different address for every name**, which is the difference between this and
  the `sinkhole_ipv4` this listener has always had: a sinkhole answers one address
  for everything, so a visitor who looks up two blocked names and gets one address
  has found it in one extra query. A fabricated answer is drawn from the pool by
  the name, stable for the life of the configuration.

- **A resolver is an amplifier, and this fabrication is not one.** A datagram
  proves nothing about its source, so an answer to a client whose address nothing
  has verified is bounded against the query that asked for it -- twice its size,
  which no honest answer here reaches -- and truncated past that bound: a real
  client comes back over TCP and a spoofed source cannot. A datagram whose source a
  DNS cookie proved, and any query over a stream transport, gets the full answer.
  Validation says out loud that a decoy listener wants `cookies: require`, because
  without it the address in the record is the one the packet claimed.

- **A fabricated address is somewhere a visitor then goes**, so the default pool is
  the documentation range of RFC 5737 and RFC 3849, which nothing routes and nobody
  hosts in. `loopback` and `unroutable` are the other two profiles, `addresses`
  names your own pool, and validation warns when that pool is inside the estate --
  pointing it at a honeypot of this proxy's own collects the next step too, and is
  the one configuration that has to be deliberate.

- **It answers A, AAAA, TXT and PTR and invents nothing else.** Everything else is
  NODATA: inventing an MX would mean inventing a mail host, and an NS or SOA would
  be a claim of authority a forwarding resolver is not making. The TXT answer is
  the one a tunnel is waiting for and carries no command -- the fabrication does not
  know the other end's protocol and will not guess -- but it is the shape a tunnel
  accepts, and one that accepts an answer sends the next chunk.

- **The tripwires need no configuring, and here they are mostly types**: a zone
  transfer, a signature set, ANY, the NULL record that exists to carry arbitrary
  octets, a query in a class that is not IN, a name over a hundred octets, and the
  fingerprint names (`version.bind`, `hostname.bind`, `id.server`,
  `authors.bind`). Those are never answered either, for the reason the S7
  fabrication does not answer the system status list.

- New counters `dns_deceived` and `dns_tripwire`, on the resolver's own status view
  as well, and an entry in `xproxyctl decoys` like the others. A decoy listener
  needs no `upstreams`, which is the one shape of dns listener that does not.

### Added (postgres: a database that is not there)

- **`postgres.deception` answers as a fabricated PostgreSQL**, either where a
  refusal would otherwise be written on a real listener (`mode: answer`) or as a
  whole listener with nothing behind it (`mode: decoy`). The rule is the one every
  other fabrication here follows: a statement on its way to a real database is
  never answered from here.

  The reconnaissance on this protocol is short and the escalations at the end of it
  are the worst in this set, because this server can run a shell command by design.
  A scanner asks `SELECT version()`, then `current_setting('data_directory')`, then
  whether this role is a superuser, then what databases there are -- and the third
  answer decides whether the next statement is
  `COPY t FROM PROGRAM 'sh -c ...'`, which is documented remote code execution with
  no exploit in it at all, or `COPY t TO '/var/www/html/s.php'`, or
  `pg_read_file('/etc/passwd')`, or `CREATE FUNCTION ... LANGUAGE c`. A refusal
  ends that at the startup message. Answering it says which one they were reaching
  for.

- **`superuser` is the consequential field**, and it defaults to false. A decoy
  that says yes is impersonating the account every scanner is hoping to find; one
  that says no is both safer to impersonate and the more common truth on an
  estate's application accounts, and a visitor who is told no and tries it anyway
  has said more than one who was told yes. Either way the fabrication runs nothing
  and never claims to: `COPY FROM PROGRAM` answers the permission error a plain
  role gets or the "child process exited with exit code 127" a superuser's failed
  program gets, and never a success.

- **The answers agree with each other**, which is what a fingerprinting tool
  checks. The `is_superuser` parameter in the startup sequence and the answer to
  `SELECT usesuper` are the same fact, and every `COPY` and file function is
  refused the way that fact requires. Each of the thirteen parameters the startup
  announces can be asked about again with `SHOW` and gives the same value, in the
  form that question takes: a real server answers `on` or `off` to
  `SHOW is_superuser` and `t` or `f` to the catalogue's `usesuper`. The catalogue
  tables that hold authentication material answer SQLSTATE 42501 rather than an
  empty set, because an empty set would say the table is there and has no rows,
  which `pg_shadow` never is.

- **It does not sleep and it does not invent rows.** `pg_sleep(60)` is answered
  rather than honoured, because honouring it would make this listener's resources
  something a visitor can hold a statement at a time. A `SELECT` the recognisers do
  not know returns an empty result set: the fabrication is a surface rather than a
  database, and inventing rows for an arbitrary projection would mean inventing a
  schema to match.

- **The tripwires need no configuring**: `pg_shadow`, `pg_authid`, the file
  functions, `lo_import`, `lo_export`, `pg_sleep`, `dblink`, `pg_largeobject` and
  the file roles raise `postgres_tripwire` from the start, matched per identifier
  rather than per substring so that a table named `programs` is not
  `COPY FROM PROGRAM`. A `COPY` naming a server-side path is recognised by its
  shape instead, because the path is a string literal and the statement names no
  privileged identifier at all.

- **This decoy can be behind TLS**, unlike the MySQL one: the encryption is
  negotiated before the startup packet and the relay answers the `SSLRequest`
  itself, so a `decoy` listener with a `tls` section serves a client that insists
  on `sslmode=require`.

- **The extended query protocol is declined rather than half-answered.** A `Parse`
  gets SQLSTATE 0A000 and a `ReadyForQuery`, and every driver falls back to a
  simple query -- which is what the fabrication wants, because a simple query is
  the statement text.

- **No password is recorded.** The startup packet carries no credential on this
  protocol, so there is nothing to leave out; where `require_auth` is set the
  fabrication asks for one (so the refusal looks like a checked one) and records
  its length rather than its content.

- Three profiles (`generic-postgres`, `django`, `rails`), a configurable version,
  database list and table list, new counters `postgres_deceived` and
  `postgres_tripwire`, and an entry in `xproxyctl decoys` like the others.
  `internal/pgwire` gained the server-side message builders -- the authentication
  exchange, the parameters, row descriptions, rows and the `CommandComplete` tag --
  which a relay that only ever refused had never needed.

### Added (mysql: a database that is not there)

- **`mysql.deception` answers as a fabricated MySQL**, either where a refusal
  would otherwise be written on a real listener (`mode: answer`) or as a whole
  listener with nothing behind it (`mode: decoy`). The rule is the one every other
  fabrication here follows: a statement on its way to a real database is never
  answered from here.

  The reconnaissance on this protocol is the attack's first half and it is made
  entirely of legitimate statements -- the version, `SHOW DATABASES`,
  `SELECT @@datadir`, `SELECT @@secure_file_priv`, `SHOW GRANTS`,
  `SELECT * FROM mysql.user`. Their answers decide which of four things the next
  statement is: `INTO OUTFILE` writes a web shell, `LOAD_FILE` reads a key off the
  server, `LOAD DATA LOCAL INFILE` asks the *client* for a file, and
  `CREATE FUNCTION ... SONAME` installs a shared object. A refusal at the greeting
  ends the conversation; answering it says which of the four they had in mind, and
  until then the reconnaissance is indistinguishable from a dashboard's own
  queries.

- **The answers agree with each other**, which is what a fingerprinting tool
  checks and the part that takes care on this protocol. `@@secure_file_priv` is
  NULL, so the file-writing statements get error 1290 -- the refusal a server with
  it set gives -- and `LOAD_FILE` answers NULL rather than an error, because that
  is what such a server does. `SHOW GRANTS` reports an account without `FILE`, so a
  read of `mysql.user` answers 1142 rather than an empty set: an empty set would
  say the table is there and has no rows, which `mysql.user` never is. The MariaDB
  profile does not offer `caching_sha2_password`, which MariaDB has never shipped.

- **Three things the fabrication will not do.** It never asks the client for a
  file: `LOAD DATA LOCAL INFILE` is answered with an error rather than with the
  request packet the protocol allows, because sending that would be attacking
  whoever connected -- and the clients that connect to a honeypot include the
  estate's own scanners. It does not sleep: `SELECT SLEEP(60)` answers zero
  immediately, because honouring it would make the decoy a way to hold this
  listener's resources a statement at a time. And it does not invent rows: a
  `SELECT` the recognisers do not know returns an empty result set, because the
  fabrication is a surface rather than a database.

- **The tripwires need no configuring**: `mysql.user`, `LOAD_FILE`, `INFILE`,
  `OUTFILE`, `DUMPFILE`, `SONAME`, `secure_file_priv`, `SLEEP`, `BENCHMARK`,
  `sys_exec` and `sys_eval` raise `mysql_tripwire` from the start, matched per
  identifier rather than per substring so that a column named `sleepy` is not
  `SLEEP`. `tripwire` adds object names to that rather than replacing it.

- Three profiles (`generic-mysql`, `mariadb`, `wordpress`), a configurable
  version, database list and table list, and `require_auth` for a decoy that
  refuses the login instead. `require_tls: false` is required in `decoy` mode and
  validation refuses the listener without it: the fabricated greeting does not
  offer `CLIENT_SSL`, because the negotiation is mid-handshake on this protocol
  and a server that offered it and could not complete it fails in a way a scanner
  notices.

- **A password is never recorded.** The login's user name, plugin and program name
  are kept, because they are identities; the authentication response is not, for
  the reason the SNMP relay does not log a community string.

- New counters `mysql_deceived` and `mysql_tripwire`, and the fabrication appears
  in `xproxyctl decoys` like the others. `internal/mysqlwire` gained the
  server-side packet builders -- the greeting, OK, EOF, column definitions and
  rows -- which a relay that only ever refused had never needed.

### Added (redis: a cache that is not there)

- **`redis.deception` answers as a fabricated Redis**, either where a refusal
  would otherwise be written on a real listener (`mode: answer`) or as a whole
  listener with nothing behind it (`mode: decoy`). The rule is the one every other
  fabrication in this project follows: a command on its way to a real server is
  never answered from here.

  This is the protocol where that earns the most, because the attacker on it is a
  script rather than a person, and it is always the same script. An exposed
  instance with no password is found by a scanner, and what follows is `INFO`,
  `CONFIG GET dir`, `CONFIG GET dbfilename`, `CONFIG SET` both of them somewhere
  that executes, a `SET` carrying a cron line, and `SAVE` -- remote code execution
  built entirely out of commands the protocol considers ordinary, with no exploit
  in it and nothing to patch. A refusal stops that at the first step and sends its
  author to the next address. Answering it collects the directory, the file name
  and the payload.

- **The tripwires need no configuring.** On a PLC only the operator knows which
  registers nobody legitimate reads. Here the answer is universal, so `CONFIG SET`,
  `MODULE`, `SLAVEOF`, `REPLICAOF`, `DEBUG`, `EVAL`, `EVALSHA`, `FUNCTION`,
  `SCRIPT`, `MIGRATE`, `SHUTDOWN`, `SAVE`, `BGSAVE`, `BGREWRITEAOF`, `FLUSHALL`,
  `FLUSHDB` and `ACL` raise `redis_tripwire` from the start and `tripwire` adds to
  that list rather than replacing it.

- **Two things the fabrication will not pretend.** `EVAL` and `MODULE LOAD` answer
  the error the real server answers when it cannot, because a `+OK` to either
  would be a claim that code was running and nothing said afterwards would be
  consistent with it. `SCRIPT LOAD` answers a digest and keeps nothing, and
  `EVALSHA` of it then says `NOSCRIPT` -- which is what a server that had evicted
  the script would say, so the pair stays consistent.

- **A password is never recorded.** `AUTH`'s arguments become the user name and the
  password's *length* in the event, for the reason the SNMP relay does not log a
  community string. Every other command's arguments are recorded, clipped and
  reduced to one line, because on this protocol they are the message.

- Three profiles (`generic-cache`, `session-store`, `queue`), a configurable
  `version` and keyspace, and `require_auth` for a decoy that asks for a password
  and then accepts any of them. New counters `redis_deceived` and
  `redis_tripwire`, and the fabrication appears in `xproxyctl decoys` like the
  others. `internal/respwire` gained the reply builders a server needs, which it
  had never needed as a reader.

### Fixed (redis: a key with a slash in it was hidden from the glob)

- The fabrication's `KEYS` and `SCAN` matched with `path.Match`, which is the
  obvious matcher for a glob and the wrong one here: it will not let a wildcard
  cross a slash, and a Redis key is an opaque string in which a slash means
  nothing. A configured key named `cache:img/logo.png` was not listed by the
  `cache:*` that was supposed to list it. The matcher is now Redis's own --
  `*`, `?`, `[...]` with `^` and ranges, and `\` to escape -- with no separator
  semantics, and a run of stars collapsed to one, because each star costs a scan
  of what is left of the key and thirty of them in a client-supplied pattern
  would be exponential in the length of every key compared against it.

### Added (snmp: version 3, read rather than taken on trust)

- **The rules now apply to v3 traffic.** `usm_users` gives a listener the pass
  phrases of the version 3 users whose messages it should be able to read. With
  them the keyed digest is verified and, at `authPriv`, the scoped PDU is
  decrypted -- and then `read_only`, a rule's `pdus`, `access`, `oids`,
  `deny_oids`, `write_oids` and `contexts` all decide about a v3 message exactly
  as they decide about a v2c one.

  The gap this closes was the wrong way round. Without the keys a v3 message was
  a header and an opaque payload: the user, the engine and the security level
  were checked and nothing else could be, so every rule an operator wrote about
  an operation or an object subtree applied to v1 and v2c and silently did not
  apply to the version an operator is told to insist on. A `read_only` listener
  relayed an encrypted `SetRequest`, with the honest but useless decision
  `snmp_encrypted`.

  Nothing is re-encrypted and nothing is re-signed: the octets forwarded to the
  agent are the octets that arrived. The keys are here for reading.

- **An `authPriv` exchange now works end to end on the datagram path.** An
  encrypted answer has no readable request identifier, and that identifier is
  the only thing in the protocol that pairs an answer with its question, so such
  an answer could not be matched to the manager that asked and was dropped
  (`encrypted_response`). With the user's keys it is decrypted, paired and
  forwarded.

- **Two refusals that only a listener holding keys can make.** A user with keys
  arriving at `noAuthNoPriv` is refused (`snmp_usm_downgrade`): clearing the
  flags in `msgFlags` asks the relay to stop checking rather than to produce a
  digest, and it is the cheapest forgery on this protocol. And a message whose
  clock has gone backwards -- a lower boot count, or the same boot count with a
  clock more than `replay_window` behind where the elapsed wall clock says it
  should be -- is refused (`snmp_replay`), which is RFC 3414 §2.2.3's own time
  window and the one thing a digest alone does not give. A higher boot count is
  an agent restarting and the mark follows it, so a power cut does not lock out
  an estate.

- **Key derivation is bounded.** RFC 3414 §2.6 hashes a megabyte of repeated
  pass phrase on purpose, so that guessing a pass phrase costs a megabyte per
  guess -- and the engine identifier that decides *which* key is needed arrives
  in the message. Keys are derived once per engine and cached, and
  `max_usm_engines` (default 8) bounds how many engines one user's keys are
  derived for; past the bound a message naming a new engine is refused
  (`snmp_usm_engines`) rather than paid for. Pinning a user's `engine_id`
  derives the one key at load instead.

- All of these are shadowable with `policy: {mode: shadow}` on the listener,
  which is what an operator trials the section with: a wrong pass phrase would
  otherwise stop every poll on the estate the moment it is added. Shadow mode
  cannot make a message readable, so a shadowed listener forwards it exactly as
  it arrived and decides about its header alone.

- New counters `snmp_verified`, `snmp_decrypted`, `snmp_auth_failed` and
  `snmp_replayed`; new refusal reasons `usm_downgrade`, `usm_engine`,
  `usm_engines`, `auth_failed`, `replay`, `usm_no_privacy_key` and
  `unreadable`. Validation refuses a hash too narrow for the cipher beside it
  (USM has one key derivation and the cipher truncates it, so `md5` cannot key
  `aes256`), an `authPriv` floor with a user that has no privacy key, and the
  usual shapes; it warns about `md5`, `sha1` and `des`, about one pass phrase
  keying both the digest and the cipher, and about a listener that accepts v3
  and holds no keys.

- The reader itself is `internal/snmp/usm.go`: RFC 3414's derivation and two
  digests, RFC 7860's four more, RFC 3414's DES-CBC and RFC 3826's AES-CFB in
  three widths. The derivation is tested against RFC 3414 Appendix A.3's own
  vectors rather than against ourselves.

### Fixed (iec104: a refusal took the association down with it)

- **Refusing one frame desynchronised the sequence numbering in both
  directions, and a conforming control centre or station then dropped the
  association.** This is the headline behaviour of the kind -- carry the
  telemetry, refuse the command -- and against equipment that checks the
  numbering it did not work.

  IEC 60870-5-104 numbers every I-format frame per direction, contiguously,
  and the reference implementation closes the connection on a gap rather than
  trying to recover: `cs104_connection.c`, "check the receive sequence number
  N(R) -- connection will be closed on an unexpected value", and
  `cs104_slave.c` the same. The relay forwarded the two ends' own numbers and
  answered a refusal with a copy of the frame it refused, so:

  - the refused frame consumed one of the centre's numbers and never reached
    the station, leaving every later forwarded frame one ahead of what the
    station expected;
  - the injected negative confirmation consumed one of the numbers the centre
    was counting, leaving every later station frame one behind;
  - and the negative confirmation itself carried the centre's own send
    sequence number, which is not a number any station would send.

  The probe, on a listener allowing one range of breakers -- one allowed
  command, one refused, then another allowed:

  ```
  the confirmation after a refusal: N(S) = 1, the centre was counting on 2
  telemetry after a refusal:        N(S) = 2, the centre was counting on 3
  the station's frame 2:            N(S) = 2, the station was counting on 1
  ```

  A second defect in the same bookkeeping: the acknowledgement that releases
  the sending window was only read off supervisory frames, and the standard
  lets an end piggyback N(R) on every I frame it sends -- which is what an end
  with data to send does. So the window never reopened on an ordinary
  exchange, and the thirteenth command of a session was refused with
  `iec104_window` while the station had confirmed all twelve before it. The
  S-frame path also credited the acknowledgement to the sending direction's
  state rather than the acknowledged one.

  **The relay is now an end of the association at the APCI layer.** It numbers
  the frames it writes from its own count per direction, acknowledges what it
  reads at `w` and on a timer (the standard's t1 is 15 seconds and an end that
  is not acknowledged inside it closes), and terminates the supervisory frames
  -- an acknowledgement is about the stream this relay wrote, so passing one
  on would tell the station something the centre never said. The application
  layer is untouched: the ASDU that arrives is the ASDU that leaves, and only
  the six control octets are the relay's own. What `check_sequence` and
  `max_unacknowledged` decide is unchanged -- whether a *peer's* numbering is
  checked -- and a gap is still refused and counted rather than patched over.

  The numbering check now lives in the shared test harness, so every test in
  the package makes it: the control centre in those tests closes the
  association on a frame whose N(S) is not the one it was counting on, exactly
  as a real one does. It was the absence of that check that let this ship.

### Fixed (iec104: an address policy was checked against numbers nobody sent)

- **Seven information element sizes were wrong, five of them measurements.**
  `objectSize` is how the parser steps from one information object to the next,
  so a size one octet short reads every address after the first out of the middle
  of the previous object's value. It is not a parse failure, so the addresses came
  back silently wrong -- and `ASDU.Addresses` is what an `iec104` rule's
  `addresses` list is checked against and what the OT inventory records. For any
  ASDU carrying more than one object of an affected type, both directions of error
  were available: an object outside an allowed range reading as inside it, and
  legitimate traffic refused. The affected types are the measurement family, which
  is the bulk of what a substation sends.

  Found by round-tripping a frame builder through the parser. The probe, two
  scaled measurements at IOA 1000 and 1001:

  ```
  addresses read back as [1000 256256]
  objectSize(M_ME_NB_1) = 2; the standard's element is SVA(2) + QDS(1) = 3
  ```

  | Type | was | is | composed of |
  |------|-----|----|-------------|
  | `M_ME_NA_1` | 2 | 3 | NVA + QDS |
  | `M_ME_NB_1` | 2 | 3 | SVA + QDS |
  | `M_ME_ND_1` | 1 | 2 | NVA, and no quality descriptor |
  | `M_ME_TA_1` | 5 | 6 | NVA + QDS + CP24Time2a |
  | `M_ME_TB_1` | 5 | 6 | SVA + QDS + CP24Time2a |
  | `C_CD_NA_1` | 1 | 2 | CP16Time2a, not a qualifier octet |
  | `C_TS_TA_1` | 10 | 9 | TSC + CP56Time2a |

  Every one confirmed against the encoders of `mz-automation/lib60870` by counting
  the octets each writes rather than by reading its size reservations: the
  bitstring commands reserve one octet more than they write, and taking the
  reservation as the element size would have introduced two new defects while
  fixing these. The standard's own naming settles the first three by itself --
  `M_ME_ND_1` exists *because* NA and NB carry a quality descriptor, so a table
  where NA is two octets and ND is one has them the wrong way round.

  Two existing fixtures were built to the wrong size and now fail to parse, which
  is the right answer: they were malformed ASDUs that only read because the parser
  was walking short. The size table now has a test that composes every size from
  the fields the standard names, and a second that sends three objects of every
  known type and requires the addresses that went in to come back out -- the
  property the policy depends on and the one nothing was checking.

### Added (deception past HTTP: an agent that is not there)

- **`snmp.deception`.** The most scanned management protocol there is, and the
  one where a refusal is about a *credential*: a community string that is wrong
  is answered noAccess or noSuchName and one that is right is answered with
  data, so the refusal is the oracle a password list needs. The system group is
  the other half -- every scanner reads `sysDescr`, `sysObjectID` and `sysName`
  first, and no policy can make that answer less informative because the
  estate's own monitoring reads the same objects.

  ```
  community "public"    -> noSuchName
  community "s3cret"    -> 24-port managed Ethernet switch
  a walk of 1.3.6.1.2.1 -> every port, every counter
  ```

  `mode: decoy` is a whole listener with no upstream, answering as a device
  whose counters rise and whose uptime is the uptime of nothing; `mode: answer`
  fabricates, on a listener that fronts a real agent, the answers to requests
  it was going to refuse.

  **The bound this protocol adds.** A fabricated agent is a UDP service that
  answers a small request with a larger response, which is exactly what a
  reflection amplifier is: a GETBULK of forty octets asking for a thousand
  repetitions is half a megabyte sent wherever the source address claimed to
  be. So the listener's own `max_repetitions`, `max_var_binds` and
  `max_response_bytes` bound the fabrication as they bound an agent's answer --
  the repetition count before the answer is built, the binding count while it
  is built, and an oversize answer replaced with `tooBig`. A honeypot that is
  also an amplifier is a liability rather than a sensor, and each of those three
  bounds has a test of its own.

  **What makes it answerable** is mostly that it can be walked: the system group
  and thirteen columns of the interface table, every GETNEXT strictly after the
  name asked about, and an end rather than a loop. Beyond that it is what a
  device cannot do. It does not have every object (`noSuchObject` in version 2c,
  `noSuchName` with the binding's index in version 1, which is the same
  statement in the only vocabulary a version 1 manager has). It does not answer
  version 3, because the response would carry a digest this relay cannot
  compute and an unauthenticated fabrication of an authenticated protocol is a
  worse tell than silence. It does not answer a notification. A `SetRequest` is
  answered as though it landed and nothing is written, which is the same choice
  the Modbus section makes about a refused write.

  The wire package gained what a fabrication needs and nothing there had needed
  before: an OID encoder, the unsigned value forms, a response builder, and an
  OID comparison -- with round-trip tests for each, because a name a manager
  cannot read is an answer it discards, and a comparison written on the dotted
  string puts `1.10` before `1.2` and turns a walk of an interface table into a
  walk that skips most of it.

  Twenty mutations of the new guards, nineteen killed and one equivalent: the
  version 3 refusal is enforced twice over, once here and once by the envelope
  builder, which refuses to put a v1/v2c community envelope round a v3 message.

### Added (deception past HTTP: a controller that is not there)

- **`s7.deception`.** The third OT kind, and the one where the disclosure is
  hardest to avoid by policy alone. A read of a data block the policy does not
  name is answered with an access fault and one it does name with data, so a
  sweep of block numbers reports the estate; and the system status list, which
  every scanner reads first, hands over the order number, the module type and
  the firmware:

  ```
  DB1  read  -> 4 octets
  DB2  read  -> access fault
  SZL 0x0011 -> 6ES7 315-2EH14-0AB0, firmware 3.2.7
  SZL 0x001c -> CPU 315-2 PN/DP, plant CELL4
  ```

  That list cannot be narrowed by policy without breaking the asset tools an
  estate runs itself, which is why a fabrication is the answer rather than a
  refusal.

  `mode: decoy` is a whole listener with no upstream: it answers the COTP
  connection, negotiates the PDU length its family negotiates, answers reads
  from fabricated blocks, acknowledges writes that go nowhere, and answers the
  two identification lists with an identity an operator chooses. `mode: answer`
  fabricates, on a listener that fronts a real CPU, the answers to requests it
  was going to refuse.

  **The rule that bounds it**, as on the other two kinds: a request that was
  going to reach the controller is never answered by the fabrication. Beyond
  that, only a read, a write and the identification lists are fabricated at
  all -- every other refused function keeps the access fault a protected CPU
  sends, because a fabrication that acknowledged a stop or a download would be
  telling a client a machine had stopped or a block had landed.

  **What a fabricated CPU has to get wrong to be believed** is mostly what it
  cannot do. It does not have every data block (a read of one it does not claim
  is "object does not exist"; a read past the end of one it does claim is an
  address error), it does not offer the direct peripheral area or the
  200-family areas, it negotiates 240 or 480 rather than a number no controller
  sends, and it does not speak S7comm-plus -- that is the 1200 and 1500
  families, so a decoy claiming to be a 300 answers such a request with a COTP
  disconnect, which is what a 300 does. Both built-in profiles are classic
  families for the same reason.

  Twenty-four mutations of the new guards and the new validation, all killed;
  two guards were deleted rather than tested, because `Items` already bounds the
  fabrication to a read and a write and the list switch already bounds the
  record length.

### Added (deception past HTTP: a substation that is not there)

- **`iec104.deception`.** Modbus gives up an estate one unit identifier at a
  time; IEC 104 gives up a grid one common address at a time, and it is a
  shorter walk. The common address is two octets, a control centre names it in
  every ASDU, and a relay that refuses the ones it does not carry has answered
  the question:

  ```
  common address 1  -> interrogation answered, 64 points
  common address 2  -> negative confirmation
  common address 3  -> negative confirmation
  common address 41 -> interrogation answered, 12 points
  ```

  Two answers in a sweep of 65535 is the substation list, and the interrogation
  that follows each one is the point list. The scan was refused throughout and
  the survey completed.

  Two shapes, as on the Modbus side. `mode: decoy` is a whole listener with no
  upstream, where every frame is answered by a fabricated station.
  `mode: answer` is a real relay where a refused *activation* is confirmed by
  the fabrication instead, for the clients named -- so a scanner's command
  reads as having operated a breaker and reaches nothing.

  **The rule that bounds it, and it bites harder here than on Modbus.** A
  fabricated tank level is one operator reading one number; a fabricated
  breaker confirmation is a control room that believes a circuit is open when
  it is closed. So: a frame that was going to reach a station is never answered
  by the fabrication. Deception replaces the negative confirmation a refusal
  would have sent and nothing else -- tested, not intended -- and only an
  activation is answered, because the protocol has no confirmation for a
  measurement and an ASDU no station would send is the tell rather than the
  deception. `mode: answer` will not load without `clients`; a decoy will not
  load with an `upstream`.

  **A control centre's own software checks this protocol harder than any
  Modbus master checks that one**, so the decoy speaks the association the way
  the standard describes it: nothing at all before STARTDT_act, a confirmation
  for it, then `M_EI_NA_1` -- the end of initialisation, which is how a centre
  knows a station has restarted, and whose absence would make this a station
  that has apparently been running since before the centre was born. A general
  interrogation is answered ACTCON, then the points at cause 20, then ACTTERM;
  a counter interrogation the same way with the totalisers, which only go up; a
  common address the fabrication is not is refused with cause 47, because one
  association carrying twenty substations is not a substation. Values are
  derived from a seed, the information object address and which period of the
  clock it is, so two interrogations a moment apart agree, a month of them
  never repeats, and nothing is stored. `tripwire` names the addresses nothing
  legitimate reads: those are answered too, and raised as `iec104_tripwire`.

  A confirmation is now the octets that arrived with the cause changed, rather
  than an ASDU re-encoded from the parsed fields. The tests found the reason:
  the parser keeps a *command's* qualifier and not a system command's, so a
  re-encoded confirmation of `C_IC_NA_1` -- the general interrogation, the
  commonest system command on the protocol -- came out one octet short of its
  own object count and would not parse at the control centre. Echoing the
  octets is also what a confirmation is, and it is what the relay's own
  refusals already did.

  Twenty mutations of the new guards and the new validation, all killed.

### Added (deception past HTTP: a device that is not there)

- **`modbus.deception`, and `internal/deception` for the kinds that follow.**
  Deception was an HTTP feature -- honeypot routes, decoy bodies, honeytokens,
  deceptive answers -- and every other kind either forwarded or refused. That
  asymmetry is a disclosure, and the probe is the argument:

  ```
  unit 1 read  -> 2 registers [4660 0]
  unit 2 read  -> exception 0x0a
  unit 3 read  -> exception 0x0a
  unit 17 read -> exception 0x0a
  ```

  `0x0a` is "gateway path unavailable" and the relay is right to send it. Sweep 1
  to 247 and the answers draw the map of the estate; since a refused function
  code answers `0x01` where a permitted one answers data, the same sweep also
  reports the policy. The scan is refused and the survey completes.

  Two shapes now. `mode: decoy` is a honeypot: a listener with no upstream and
  nothing behind it, where every frame is answered by a fabricated device.
  `mode: answer` is a real relay where the frames it was going to refuse are
  answered by the fabrication instead, for the clients named -- so a unit
  identifier nothing is behind reads as a device, and a refused write is echoed
  as though it landed and reaches nothing.

  **The rule that makes this usable in a plant.** On a web gateway the worst case
  of a deceptive answer is a client receiving nonsense; here it is an operator
  reading a fabricated tank level off an HMI and acting on it. So a frame that
  was going to reach a device is never answered by the fabrication: deception
  replaces a refusal and never an answer. That is a test rather than an
  intention, and it is the one mutation in this work whose survival would have
  mattered. `mode: answer` refuses to load without `clients`, and
  `deny_response: close` is warned about, since a deceived client is not closed.

  **A fabricated device has to survive a second look**, which is most of the
  design. Noise gives a decoy away, so a value is stable for a period and derived
  from the address. Stillness gives it away, so it drifts between periods.
  Impossibility gives it away, so counters are monotone by construction, `units`
  defaults to one (no gateway has 247 devices on it), and a function code the
  profile does not implement answers `0x01` -- what the real device would say. A
  decoy that implements every code in the standard is answering for a PLC nobody
  makes. Nothing is stored: a value is a function of the seed, the address and
  which period of the clock it is, so a sweep of all 65536 addresses costs no
  memory, and the seed defaults to the listener name so the device is the same
  device after a restart.

  Writing the test that a band is filled uniformly found a real defect in the
  first draft: every value is taken modulo a small range, which is the low bits of
  the hash, and FNV's low bits are its weakest -- a band a thousand wide answered
  only between 1443 and 1889 across a hundred addresses. Every register reading
  inside the middle half of its range is exactly the statistical tell that ends a
  pretence. The hash output is now avalanched before anybody takes a remainder of
  it.

  The identity is the operator's to choose. Function code 17 and 43/14 are what a
  scanner fingerprints on, and the built-in profiles (`generic-plc`,
  `generic-rtu`, `generic-meter`) say something deliberately generic: a decoy
  should claim the make the plant actually runs, because another vendor's
  controller on this site is the tell, and only the operator knows which it is.

  `tripwire` addresses are answered and raised as a `modbus_tripwire` security
  event -- the answer keeps the visitor reading, the event is what somebody acts
  on -- and it is a detection with no false-positive rate, because nothing
  legitimate reads them. `xproxyctl honeypot` lists the visitors with what each
  one touched, `xproxy_decoy_frames_total` and `xproxy_decoy_tripwire_total` are
  the series, and `modbus_deceived` / `modbus_tripwire` the counters. A decoy
  nobody reads is an ornament.

### Added (evidence: session recordings can be shown not to have been edited)

- **A hash-chained manifest beside every recording**, under
  `recording.integrity`. The access ledger was hash-chained and the recordings
  were not, which is the wrong way round for what the two are used for: the
  ledger says a session was *approved*, and the recording is the only account of
  what happened inside it. After an incident the recording is the artefact
  somebody is asked to stand behind, and a file that can be edited afterwards
  with nothing to show it had been is not evidence -- which for a NIS2 incident
  report is the difference between a record and a story.

  `<recording>.chain` holds one JSON record per line in the same shape
  `internal/access` uses: each carries the previous record's hash, and its own
  hash covers that link and the record with the hash emptied. A record describes
  a *segment* of the recording -- an offset, a length and the SHA-256 of exactly
  those bytes -- so an edit is localised to a segment rather than only known to
  have happened, and a recording cut short by a crash still has a verifiable
  prefix. `segment_bytes` decides how precisely (default 1 MiB).

  It is a sidecar rather than something inside the `.cast` because a terminal
  player reads the recording directly: hashes interleaved into it would either
  break every player or have to live in marker events, where they would appear
  in the replay as content.

  **What it is worth, stated plainly.** Both files are written by the same
  process into the same directory, so nothing here stops somebody who can write
  both from recomputing the chain. Unkeyed, it detects corruption, a shortened
  file, and any partial edit by somebody who does not rebuild every record after
  the one they changed. With `key` -- a secret reference, so the material can
  live in a vault or on an HSM rather than on the recording host -- every record
  also carries an HMAC-SHA256, and then the records cannot be forged by somebody
  who has filesystem access and not the key, which is the case that comes up: an
  intruder on the box, or an administrator editing their own session. It is a MAC
  and not a signature, so whoever can *read* the key can forge a record too; the
  key belongs somewhere the recording host cannot read at will, and verification
  belongs somewhere the recording host is not.

  A key that cannot be resolved writes no recording at all: the session takes
  the existing path for a recording that cannot be opened -- a warning and a
  `*_recording_failed` event, and the session carries on unrecorded, since a
  bastion that refuses work when a vault is unreachable is its own outage. What
  it will not do is write a recording with a manifest anybody could forge, which
  would look like evidence without being any. The resolver caches and keeps the
  previous value across a failed refresh, so a vault that goes down after the
  proxy started does not take the manifests with it.

  The chain sits between the buffer and the file rather than in front of the
  buffer, so what it digests is what reached the disk and not what the proxy
  meant to put there -- a destination that took half the bytes leaves a manifest
  for the half that landed.

- **`xproxy-replay` verifies before it plays anything back.** A recording that
  does not match its manifest is refused, with the mismatch named; `-force`
  shows it and says on stderr that it is showing a file that no longer matches.
  `-verify` answers the question on its own, and says what the manifest is worth
  -- whether it carried MACs and whether they verified under `-key` (a path or
  `env:NAME`; a vault reference is refused with what to do instead, since the
  program reads no vault). A recording with no manifest replays as before: most
  have none, and this is a viewer. The manifest is pruned with the recording it
  describes, and both appear in the `ssh_recording` line and its siblings.

- **Encryption at rest, under a key from custody.** `recording.encryption`
  writes the recording as ciphertext and names the file `....cast.enc`.
  Until now these files were `0600` in a directory an operator names, which
  is protection against another user on the same host and against nothing
  else: not a backup that leaves the building, not a stolen disk, and not
  somebody who reaches the file system with the proxy user's rights. On an
  administrative session the recording is the most valuable file on the
  machine -- keys printed, configuration read, tokens echoed, a password
  typed into a prompt that did not echo it.

  The format is in `internal/recenc`: a 32-octet header (magic, suite, a
  random 16-octet salt, the frame size), one AES-256-GCM frame per chunk,
  and an empty frame that ends the file. The file key is HKDF-SHA256 of the
  configured key with that salt, so two recordings under one configured key
  never share a key stream. Each frame's nonce is its own position and its
  additional data is the header: a frame cannot be moved within the file,
  cannot be moved between files, and the header cannot be edited. Only the
  key can produce the empty final frame, so a file that was cut short has
  no end and a reader says so rather than reporting a clean one.

  An earlier draft also bound the frame counter into the additional data and
  carried a "last frame" octet beside it. Mutation testing showed both were
  dead -- the nonce already binds the position, and the writer seals an
  empty frame only at the end -- so both are gone, and the package comment
  says why: a mechanism nobody can write a failing test for is a mechanism
  that will be believed and not checked.

  Stated plainly in the reference, because the failure here is not the
  cryptography: it is a symmetric key, so whoever can read it can read every
  recording it covers, there is no per-reviewer access and no forward
  secrecy, and **rotating the key does not re-encrypt what is already
  written** -- each recording keeps the key it was written under, so the old
  key has to be kept for as long as the recordings it wrote are kept.
  Configuring the section warns about exactly that. A key that cannot be
  resolved writes no recording rather than falling back to a plain file.

  With `integrity` as well, the manifest covers the ciphertext, which is the
  useful way round: `xproxy-replay -verify` then establishes that the file is
  the one the proxy wrote **without the content key**, so an auditor can be
  given the manifest key and not the session.

- **Every tool that reads a recording takes the key.** `xproxy-replay -key`,
  `xproxyctl session show -key`, `session play -key`, and `session list
  -key`, all with the configuration's own reference syntax (a path or
  `env:NAME`; a vault reference says what to do instead, since these
  programs hold no vault configuration). Without a key they say the file is
  encrypted and name the flag rather than failing as though the file made no
  sense, and `session list` lists both kinds and marks the ones it cannot
  look inside. What the file is comes from the magic at the start of it and
  not from its name, so a recording renamed while being archived still reads
  as what it is. `xproxy-replay`'s manifest key is now `-chain-key`, leaving
  `-key` for the recording's own contents, which is the one a reviewer needs
  every time.

### Security (1.4, the RDP channel policy could be walked around)

- **A dynamic channel could reopen a static channel the policy had just
  refused.** `channels.allow` was the whole of this gateway's channel policy,
  and `drdynvc` was one entry on it. But `drdynvc` is not a channel: it is a
  multiplexer, and inside it channels are opened by name at any point in a
  session. On a current Windows client the graphics pipeline, display control,
  geometry, camera, audio **and device and clipboard redirection** all ride
  there. So allowing `drdynvc` -- which an operator must do for a usable session
  on anything recent -- allowed every one of them, unexamined and unlogged,
  including the ones `channels.allow` had refused by name.

  Verified before it was asserted, and the probe is now a test: a desktop opened
  a dynamic channel called `cliprdr` through a gateway whose static policy
  allowed only `drdynvc`, and the client received it.

  `channels.dynamic` decides them, with an `allow` and a `deny` list matched
  whole and without regard to case. Three things about the protocol shaped the
  implementation, and two of them are the reverse of the obvious guess -- both
  came from MS-RDPEDYC rather than from expectation.

  **The desktop opens a dynamic channel, not the client.** `DYNVC_CREATE_REQ`
  travels desktop to client carrying the name; the client answers with a
  creation status. So the name a policy decides about appears in the
  desktop-to-client direction -- and this gateway did not inspect that direction
  *at all* on a TLS leg, returning the unit untouched. That inspection is new,
  and it is deliberately narrow: only `drdynvc` is looked at, because everything
  else the desktop sends is the session itself and a gateway that rewrote any of
  it would be re-implementing the protocol its client depends on.

  **Command 0x01 is two different PDUs depending on direction** -- a create
  request with a name from the server, a create response with a 32-bit status
  from the client -- and nothing in the octets distinguishes them. The parser is
  told which side sent the PDU rather than guessing; one that guessed would read
  a status as a name.

  **A refusal is written in the protocol's own words.** The gateway answers the
  desktop with the status a client that has no listener of that name would send
  (`E_NOTIMPL`), so the desktop gives up on the channel instead of waiting on a
  create nobody replied to, and the create never reaches the client. The data
  PDUs that follow on a refused identifier are dropped in both directions, and a
  close forgets the identifier, because a desktop reuses numbers and a refusal
  kept for ever would refuse a later channel given the same one.

  Absent a `dynamic` block the channels are **carried and counted**
  (`rdp_dynamic_channels_seen`), not refused, and the load warns that nothing is
  deciding about them. Refusing by default would break every session that works
  today, which is the wrong way round for a gateway people are already using.
  The warning that was already there -- that `drdynvc` carries contents "this
  gateway does not decide" -- was true when written and is now replaced, since
  it does decide once the block exists.

  Two smaller things fell out of the work. Writes to the desktop now go through
  one place under a lock, because two goroutines write there: the client's units
  on one, and a dynamic channel's refusal from the one reading the desktop, and
  two goroutines writing a TLS connection interleave records and break the
  stream. And `drdynvc` is reassembled in its own buffer per direction --
  the redirection channel's buffer was shared, and splicing the desktop's create
  onto the client's answer would have produced a message neither sent.

### Fixed (1.4, three S7comm-plus defects the dissector's own source found)

The S7comm-plus support shipped with its function table taken from two agreeing
secondary sources, because the references that would have confirmed it were
unreachable. With the primary source to hand -- the s7comm-plus Wireshark
dissector -- the table and the PDU types were confirmed exactly, and three
things were wrong. Two were defects and one was a limit that had been claimed
away rather than stated.

- **A client could carry a function code past the policy with one octet.** The
  function code was read only for the request and response opcodes this package
  first knew about (0x31, 0x32). The protocol reads it for *every* opcode but
  the notification -- including 0x02, a second response opcode the TIA Portal
  V13 HMI uses for cyclic data. So a client that set opcode 0x02 reached a
  policy that had never read a function code, and `mode: policy` with
  `classes: [read]` would have carried an `invoke`. The function is now read for
  every opcode but the notification, which is what the protocol does, and that
  is deliberately "everything except" rather than a list of the ones this
  package recognises: an opcode nobody here has seen still keeps its function
  where the others keep theirs. Opcode 0x02 is also an answer, so a client
  sending one is refused as one.

- **A keepalive with a large sequence number dropped the link.** A keepalive is
  four octets and has no length field: the two after the PDU type are a
  sequence number and a reserved octet. Reading them as a data length made any
  keepalive whose sequence number exceeded the frame look like a PDU that
  overran it -- which is refused, and the refusal is fatal. So an S7-1500 link
  that was merely idle was dropped, on a counter that said the frame was
  malformed. The earlier test passed only because it wrote a zero where a real
  keepalive carries its sequence number.

- **Firmware 1.5 PDUs were being read at the wrong offsets, and are now
  declared unreadable instead.** From firmware 1.5 the integrity block moved
  from the end of the data part to the front, and it begins with a
  variable-length integer -- so the opcode is not at a fixed offset and the
  function code cannot be located without implementing the digest framing. The
  parser had been reading an opcode and a function out of the integrity block.
  It now reports no opcode and no function for those PDUs, and they are a class
  of their own, `opaque`: refused by default, and nameable so an estate that
  needs current S7-1500 controllers working says so knowingly. Stating the
  limit is better than a policy decided on a misread digest.

  A fourth thing changed as a consequence rather than as a defect: the policy's
  "a PDU with no function carries on" shortcut covered `opaque`, because an
  opaque PDU also has no function -- for the opposite reason. The shortcut now
  covers only the PDUs that genuinely carry nothing to decide.

### Added (1.4, the protocol the newest Siemens controllers actually speak)

- **S7comm-plus, and a relay that stopped breaking S7-1200 and S7-1500
  connections.** TIA Portal talking to an S7-1200 or S7-1500 does not speak
  classic S7comm: it speaks S7comm-plus, the same TPKT and COTP stack with a
  protocol identifier of `0x72` where classic S7comm uses `0x32`. The `s7` kind
  read only `0x32`, and the effect was worse than a missing feature. The first
  S7comm-plus PDU failed the protocol-identifier check, was treated as
  `unreadable_pdu`, and **ended the connection** -- no answer in the protocol,
  nothing an operator reading the refusal counters would recognise as a policy.
  So the newest half of a Siemens estate could not be put behind this relay at
  all, and the failure presented as a network fault.

  Verified by probe before it was asserted: a client sent one S7comm-plus
  request through the relay and got `EOF`, with the controller having seen only
  the connect and the negotiation. That probe is now a test.

  `s7comm_plus` on an `s7` listener has three modes. `refuse` is the default,
  because it is what a listener written before this section existed meant -- but
  the refusal is now named (`s7comm_plus_refused`), counted, and leaves the
  session up, so an HMI on classic S7comm and TIA Portal on the same CPU no
  longer take each other down. `policy` decides each PDU by function code or by
  class (`read`, `write`, `admin`, `unknown`), which is what makes an S7-1500
  usable through the relay. `passthrough` forwards the lot, with the frame
  bounds, rate limits and rack and slot still in force, for an estate that needs
  TIA Portal working today.

  Three decisions are worth reading, because they are about the limits of what
  any relay can honestly claim on this protocol.

  **The policy is smaller than the classic one, deliberately.** Classic S7comm
  says on the wire which memory area a request names, which data block and which
  bytes. S7comm-plus does not: on the controllers that speak it the session is
  integrity-protected and the object and variable addressing is encrypted under a
  key the two ends derive, so a relay in the middle sees the outer framing and
  nothing under it. What is left is the function code, and that is what this
  decides about. `areas` and `dbs` do not apply, and the reference and the
  protocol page both say so -- a section claiming to bound data blocks here would
  be claiming to read something no relay can see, which is worse than the gap.

  **A function this relay cannot name fails closed.** Siemens publishes no
  specification for either protocol, so the function table is read from the wire
  the way the classic one is, and it is incomplete by construction. That is made
  safe by one property rather than by hoping: an unnamed function code is the
  `unknown` class, `default_action` decides it (deny unless an operator says
  otherwise), and `read_only` refuses it outright -- on a read-only listener the
  function nobody can name is exactly the one that must not be carried. `unknown`
  is nameable in a list so the decision about it is visible rather than
  inherited, and the load warns when `default_action: allow` takes that property
  away. The parser reinforces it: it reads the PDU type, the opcode and the
  function code and stops, because nothing in a policy needs the sequence number
  and reading it would be a field this relay could misread for no gain.

  **There is no way to say no in this protocol.** Classic S7comm has a refusal --
  an acknowledgement carrying an access fault, which is what a password-protected
  CPU answers -- so a refused classic request is answered and the poll loop
  carries on. S7comm-plus has no response this relay can build, and inventing one
  would put octets on the wire no controller would send. So `deny_response: error`
  degrades to `drop` for S7comm-plus, `close` is available for an estate that
  wants a refusal to end the session, and the load warns about the degradation
  rather than leaving it to be discovered in the field.

  The declared data length is checked against the octets that arrived, which is
  what makes the rest safe to rely on: it is the one header field the frame
  itself can contradict, so a header misread shows up as a frame that does not
  add up rather than as a policy decided on a bad field. A new fuzz target
  (`FuzzParsePlus`, 4.2M executions clean) holds the invariants the policy rests
  on, chiefly that "no function" and "function zero" never look the same. Fifteen
  mutations of the new guards were tried.

### Added (1.4, what a setpoint may be set to)

- **A value policy for IEC 104 setpoint commands.** A rule on this kind could
  say a control centre may send `C_SE_NB_1` to point 4711. Nothing could say
  what 4711 may be set *to* -- and on this protocol nothing else does either: a
  scaled setpoint carries any integer from -32768 to 32767, a short float most
  of the real line, and the RTU writes whatever arrives. A governor setpoint, a
  tap-changer position or a reactive-power reference driven to the end of its
  encoding is a fault that looks, frame by frame, exactly like ordinary
  operation. `setpoints` on an `iec104` listener now bounds the value (`min`,
  `max`) and the step (`max_delta`), per information object address, per station
  and per encoding.

  The value is read at the wire level for all three of the standard's
  encodings -- normalised (a signed 16-bit fraction over 2^15), scaled (a signed
  integer) and IEEE 754 short float -- and presented to the policy as one
  `float64`, because a bound is a statement about the process and an operator
  should not have to write it three times for one substation.

  Two halves, different in kind, and the difference is the honest part. `min`
  and `max` need nothing, so they are checked first and hold for every setpoint
  command including a *selection*: the station is never asked to hold a value it
  may not be given, and a refused selection is not consumed. `max_delta` needs
  to know where the point is now, and what that means here is **the last value
  this relay saw** -- a setpoint it forwarded, or a station's positive
  confirmation of one. Another control centre, a local panel or the process
  itself changes a point without passing through here, so `on_unknown` says what
  happens when there is no previous value (`allow` keeps the range in force,
  `refuse` holds the command) and `iec104_setpoint_unknown` counts how often
  that happened. A station's *negative* confirmation makes the relay forget the
  point: the command did not take effect, so a delta measured from it would be
  measured from a value the equipment refused.

  Three things were decided rather than defaulted. A **normalised** value is a
  fraction of a full scale configured in the device, which no relay can read off
  the wire -- so a bound on one is a bound on the fraction, the load *warns* when
  a bound named only for normalised types is written outside -1 to +1, and the
  reference and the protocol page both say so where a bound is written. This is
  why earlier versions of this listener had no value policy at all; a warning at
  load is better than the same mistake found at a breaker. A **non-finite**
  short float is refused as out of range, because every comparison with NaN is
  false and a bound that only asked "below `min` or above `max`" would pass a
  NaN straight through to a governor. And a **station's own report** is never
  refused by a value bound: an RTU answering with the value it actually applied,
  clamped by its own configuration and outside the bound, reaches the control
  centre -- refusing the answer would leave the centre waiting for ever for a
  command this relay already let through.

  Refusals are `setpoint_range`, `setpoint_delta` and `setpoint_unknown`, each
  with the value, the point and the bound's name in the security event and the
  shadow ledger. Both shadow switches carry the traffic and record what would
  have been refused. Counters: `iec104_setpoints`, `iec104_setpoint_points`,
  `iec104_setpoint_unknown`. Fourteen mutations of the new guards were tried and
  all fourteen were caught by the tests.

### Fixed (1.4, two bounds that could be walked past)

- **The IEC 104 select bit was read from the wrong octet on every setpoint
  command.** The select/execute bit lives in a command's *qualifier* octet, and
  the parser read octet 0 of the information element for every command type. For
  a single, double or regulating-step command that is the qualifier and the read
  was right. For a **setpoint** the value comes first -- two octets of it, or
  four for a short float -- so the parser was reading the low byte of the value
  the operator asked for. A setpoint whose low byte happened to have bit 8 set
  was read as a *selection*; one without it as an *execute*. So `require_select`
  on a listener carrying setpoints could be walked straight past by choosing a
  value, and a four-eyes rule written as `select` on one client and `execute` on
  another matched on the value rather than on the half of the two-step form.

  The offset is now a property of the type identification -- 0 for the command
  types, 2 after a normalised or scaled value, 4 after a short float -- and a
  table test holds it against `SelectSupported` and the setpoint encodings over
  all 256 type codes, so a type added later cannot be given a select bit and no
  offset.

- **A negative SNMP `max-repetitions` bypassed the amplification bound.** The
  GETBULK field is a signed integer on the wire, and the relay compared it
  against the configured bound with a `<=`: any negative value passed both the
  bound and the rule that matches on it. RFC 3416 defines the range as 0 to
  2147483647, so a negative count is malformed -- but the relay's job is to
  refuse it, not to trust the agent to. The parser still reports the field
  faithfully (a parser that clamped would hide from the relay the thing the
  relay must decide) and both the bound and the matching rule now treat a
  negative count as exceeding any limit.

### Fixed (1.4, what a release actually contains)

- **The Linux release tarball shipped four binaries for as long as there had been
  three daemons.** `make build` produces eight; the tarball copied `xproxy`,
  `xproxyctl`, `xproxy-admin` and `xproxy-fleet`, and left out `xgate`, `xrelay`,
  `xproxy-replay` and `xsigner`. So a download carried `deploy/config/xgate.yaml`
  and `deploy/config/xrelay.yaml` -- telling an operator how to configure two
  daemons whose binaries were not in it -- and an SSH bastion, or any relay
  listener, could not be run from a release at all. The RPM was corrected when the
  daemons were split out; the tarball was not, and nothing looked at it again.

  Verified by unpacking one before and after rather than by reading the rule. The
  tarball now ships everything the tree builds, and the list is a Makefile variable
  rather than a line in a copy command.

- **The macOS tarball carried two binaries its installer ignored.** It shipped five
  (the Makefile's `build-darwin` list) while `deploy/macos/install.sh` installed
  three, so `xproxy-fleet` and `xproxy-replay` reached every Mac and were installed
  on none. The installer now installs what the tarball carries. macOS still ships
  fewer than Linux, and that is deliberate rather than an omission: there is no
  launchd job for `xgate` or `xrelay`, so neither is built for it, and a test says
  so in the place where somebody would otherwise add one quietly.

- **Three tests in `test/deploy`**, in the same shape as the RPM ones beside them
  and for the same reason -- a packaging rule is written once and then drifts. One
  holds the Linux list against the build rules, one holds the macOS installer
  against the macOS tarball (and fails if that tarball starts carrying a daemon with
  no launchd job), and one fails on a stale binary count in RELEASING.md, which said
  "the three binaries" of both tarballs after the split had made them eight and
  five. All three were mutation-tested.

### Security (1.4)

A **seventh round**, sweeping the sixth's two finding classes across
the gate kinds beside the one they were found on, and one finding of
its own.

- **Four listener kinds enforced a policy they were told to shadow.**
  `policy: {mode: shadow}` on a listener is the estate's spelling of "evaluate
  and do not enforce", and the reference documents it for every listener. Four
  kinds read only their own `monitor_only` and never `config.Listener.Shadowing()`
  -- `postgres`, `mysql`, `tds` and `redis` -- so an operator who trialled one of
  those policies the documented way got a refused statement, a refused write, and
  a refusal counter telling them enforcement was happening. That is the one thing
  a trial must never do: the whole purpose of shadow mode is that nobody has to
  guess what a policy would refuse at three in the morning, and on the four
  relays that hold an estate's data it guessed wrong in the enforcing direction.

  Verified before it was asserted: a redis listener with the switch on was driven
  over a socket and answered `-NOPERM refused by xproxy: read_only`, with the
  refusal in `refusals` and nothing in `would_refusals`. All four now read both
  switches, either is enough, and a test drives it on redis and on postgres. A
  second test reads the source of every kind that has an `enforcing()` and fails
  on one that does not mention the switch, so a kind written tomorrow cannot
  leave it out quietly -- the same shape as the ban-reason test below, and for
  the same reason: the defect is not per protocol even though the behaviour is.

  The shadow-mode table in CONFIG.md was missing rows for seven kinds
  (`postgres`, `mysql`, `tds`, `redis`, `amqp`, `s7`, `bacnet`) and said of
  `tcp`, `udp` and `ntske` that nothing on them is shadowable, which stopped
  being true when they were wired to the `authorization` section. Both are fixed.

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

- **The accept-group race, swept across every listener kind.** One bug that
  four kinds shared -- found on the Redis kind and fixed there in
  `internal/acceptgroup` -- turned out to be present in twelve more. Session
  tracking written as a `sync.WaitGroup` Adds one per accepted connection in the
  accept loop and Waits in shutdown, and a WaitGroup's Add must not run
  concurrently with its Wait while the counter is at zero. The engine closes a
  listener's front socket *before* it calls that listener's Shutdown, which
  leaves the accept goroutine between a connection it has already accepted and
  the Add it has not reached yet -- and the same applies to the background
  goroutines a datagram kind starts in `serve`, which a shutdown arriving early
  enough Waits for before they are counted.

  What goes wrong is not a detector warning. The session either is or is not
  waited for depending on the scheduler, so shutdown returns while a session is
  still reading a connection the process is about to close: on a reload a session
  dropped mid-command, on a shutdown a log line written after the log file was
  closed.

  `telnet`, `vnc`, `rdp`, `ntske`, `syslog`, `snmp`, `ntp`, `udp`, `tftp`,
  `dhcp`, the QUIC relay of `kind: tcp`, the forward proxy's CONNECT and SOCKS
  paths, and the modbus and NTP learners now use `internal/acceptgroup`, which
  does the check and the Add under one lock that the close also takes. The eight
  kinds that already had the pattern -- `ftp`, `iec104`, `ldap`, `modbus`,
  `mqtt`, `smtp`, `ssh` and the TCP side of `kind: tcp` -- were audited and left
  alone, and the remaining `wg.Add(2)` calls are local to one function, where Add
  and Wait are the same goroutine.

  The sweep needed a test that shuts a listener down while clients are still
  arriving, so `test/shutdown` starts twenty-three kinds through the real engine
  and does exactly that, under the race detector. It found `ntske` on its first
  run and `snmp`, `ntp`, `syslog` and `udp` after that. It is honest in its own
  comment about what it does not do: twenty runs never hit the window from
  outside on demand, because it is a few instructions wide, so what the test
  reliably catches is the other half -- a shutdown that *hangs*, which is what an
  Enter without its Leave produces and the real risk of changing twenty
  listeners at once.

- **Two races the sweep's own test found on the way.** `proxy.New` installed the
  process-wide panic sink (`safe.Report`) as a plain package variable, and "set
  once at start-up" is not quite true: a reload builds a second Server while the
  first is still serving, so the sink is written while flow goroutines could be
  reading it. A contained panic during a reload is exactly when an operator most
  wants the stack, and a torn function pointer is the one way to turn a contained
  panic back into a process that stops. It is an atomic pointer now, set through
  `safe.SetReport`.

  And the UDP kind published a session into its table before it dialled the
  upstream -- deliberately, so that a flood of first datagrams cannot each start
  a dial -- and then wrote the socket, pool and endpoint as three plain fields,
  under everything that could already reach the session: a second datagram from
  the same client, the sweeper, a shutdown. The three are one atomic pointer now,
  so a reader either sees the upstream or sees that there is not one yet.

- **The status terminal read one key per read, and dropped everything else.**
  `xproxyctl top` handed each read from the terminal to its key handler whole, as
  if a read were a keystroke. A terminal does not work that way: a read returns
  whatever the driver had ready, so a person typing quickly, a key held down
  under autorepeat and *any paste* arrive as several keys in one read -- and the
  handler matched that group against its key table, found nothing, and discarded
  every byte of it. Pasting an address into the ban prompt, which is the ordinary
  way an address gets there, put nothing in the prompt. A read is cut into its
  keys now, with an escape sequence kept whole so that the first byte of a cursor
  key cannot arrive as the Escape that cancels a prompt, and the fetch a key asks
  for is done once per read rather than once per key, so a held `r` is one
  refresh.

  The defect was sitting behind a flaky test, which is how it was found: the
  terminal test spaced its keystrokes with a fixed pause and the pause was a
  guess at how long the program needs, so under the load of the rest of the suite
  two keystrokes landed in one read and the test failed on the ban that its
  pasted line no longer performed. It waits for the frame each key draws now --
  the program has read the key when it has drawn it, which is a fact rather than
  an estimate -- and the line the ban prompt takes is deliberately pasted in one
  write, so the case that was broken is the case the test drives. The pause that
  stood in for "nothing should happen" is gone too: the frame after the return
  key is proof the refusal was handled, so nothing has to be waited out.

- **`ntske_handshakes`, a gauge for the bound that had none.** The NTS key
  establishment relay bounds the handshakes in flight
  (`max_concurrent_handshakes`), and the only thing that reported on it was the
  counter of clients already being turned away -- which answers the question
  after the moment an operator wanted it. The gauge says how many slots are held
  now, so occupancy at the bound is visible before the refusals start; on a slow
  upstream it also separates a flood from slots held by handshakes waiting on the
  key establishment server.

  It was added for a test that was a race it usually won: the test held the only
  slot with one connection and then expected the next client to be refused, but a
  dial returns when the kernel has the connection and not when the server has
  taken the slot for it, so under load the second client took the free slot and
  the bound read as broken. It waits for the gauge now, which is the fact the
  test was assuming, and the gauge coming back down when the connection closes is
  asserted as well.

- **A listener on port `0` could fail on a port nobody asked for.** A kind that
  serves datagrams as well as connections takes its datagram socket on the port
  the accept socket was given, because the two have to be the same port -- a DNS
  resolver answers on 53 over both, and one that answered on only one of them
  works until an answer does not fit. With `address: "127.0.0.1:0"` that port is
  the kernel's choice, and the kernel chooses it from the TCP side alone: it can
  hand over a port something else already holds on the UDP side, and there is no
  way to ask for one free in both. The listener then failed to come up with a
  bind error naming a port that appears nowhere in the configuration. That pair
  is let go of and another asked for now, up to eight times.

  Three conditions guard the retry, because a retry that fires on the wrong
  failure turns one clear error into eight of them: the port has to be the
  kernel's to choose (a port the file names is the same port next time), the
  socket has to be this process's own (one handed over by the service manager is
  not ours to reopen), and the failure has to be the address being in use.
  Everything else -- a certificate that will not load, a policy that will not
  compile -- is reported as it was.

  It was found as a test flake twice, in the syslog relay and then in the DNS
  policy-zone tests, where a test that asked for a listener on port 0 got a bind
  error instead. The collision itself cannot be produced on demand -- it needs
  the kernel to hand out one particular port out of thousands while something
  holds it on the other transport -- so what is tested is the decision, every
  branch of it driven directly, and the two things that must not change: a port
  whose datagram side is taken fails with the reason it failed and nothing left
  bound behind it, and a port 0 listener comes up with both sockets.

### Fixed (1.4, shadow mode told the truth about eleven kinds)

- **A listener in shadow mode counted refusals it did not make.** Eleven relay
  kinds -- postgres, mysql, tds, redis, amqp, bacnet, dhcp, ldap, s7, snmp and
  tftp -- counted every policy decision under refusals and, when the listener was
  in monitor mode, under would-be refusals as well. So a relay being trialled
  reported enforcement that was not happening: the statement was forwarded and
  the counter said it had been refused.

  internal/proxy keeps the two tables apart on purpose -- "so a status view
  cannot add them up" is what the code says -- and this was the one way to defeat
  that, because the same decision appeared in both. The operator reading the
  refusal count of a listener under trial is exactly the person who must not be
  misled about whether the policy is ready to enforce. tftp had a second form of
  it, counting a filename "refused for its shape" that it had in fact forwarded.

  The cause was the same in every one: the counter sat above the branch rather
  than inside it, which is invisible when reading either half alone. `ntp` is the
  shape they all have now -- the refusal counted inside `if enforcing { ...
  return }`, the would-be refusal after it -- and a hard refusal is unaffected,
  because monitor mode does not carry those.

  Held for every kind at once by a test that reads the source for the shape
  rather than one shadow-mode test per kind, so a kind written that way tomorrow
  fails it.

### Added (1.4, one authorisation policy above the protocols)

- **`authorization`: which identity may reach which listener, target and
  operation -- once, for every listener kind.** Every kind here already
  decides things about a session: the SSH bastion has channel and command
  lists, the PostgreSQL relay has a statement policy, the Modbus relay has
  function codes and register ranges. Those belong where they are, because
  nothing else can say what a write to holding register 40001 means. The
  question they cannot answer is the one above them -- may this person
  reach this thing at all, from where they are, at this hour -- and asked
  inside nineteen protocol policies it has nineteen answers, in nineteen
  spellings, in nineteen places to drift apart.

  A rule names who (`users`, `principals`, `groups`), where from
  (`networks`), where to (`listeners`, `kinds`, `targets`), what
  (`connect`, `session`, `exec`, `forward`, `read`, `write`, `admin`) and
  when (`schedule`), with a negative form for every selector as its own
  key rather than a `!` prefix -- because a user or a target may begin
  with any character, and a policy language in which a name cannot be
  written literally has a hole in it. Rules are tried in order and the
  first that matches decides; the section default decides what none
  matched, and it is deny, because a policy that lets through whatever
  nobody wrote a rule for is a policy whose gaps are invisible.

  It decides nothing on its own authority: every field of a subject was
  established by the listener that asked -- a name it authenticated, a
  principal it resolved, the target the client asked for -- so nothing a
  client merely sent reaches a rule.

- **Fail-closed while it is being wired, rather than aspirational.** A
  kind that did not consult the policy would be a hole in a policy an
  operator believes covers everything, so a configuration carrying an
  `authorization` section **and** a listener of a kind that does not
  consult it is refused at load, naming the listener, its kind and the
  kinds that do. The list lives beside the listener roster and is a list
  of what *does* consult it, so a kind added tomorrow is outside the
  policy until somebody decides otherwise -- and a test holds every kind
  against both lists, failing on a kind in neither.

- **All five gate kinds ask it**, each at the point where it has an identity
  and the protocol allows. `ssh` (and SFTP inside it), `telnet` and `vnc` ask
  before the target is dialled, so a refused session never reaches a machine.
  On `rdp` and `ftp` the person appears only *after* the target is reached --
  RDP carries the credential in one packet that arrives after the desktop is
  dialled, and FTP's greeting comes from the server -- so there the refusal is
  before the credential or any command of theirs travels: the far side has seen
  a connection and nothing else. That is a fact about those protocols rather
  than a choice, it is the same constraint the access grant has, and each
  protocol page says so. All five take the upstream **pool** as the target, so
  one rule reads the same on all of them, and the per-machine question stays the
  grant's.

- **And the three database relays whose login packet names an account**:
  `postgres` at the startup packet, which is the first and only place a role
  appears -- the relay never sees the password -- and `mysql` and `tds` at their
  login packets, each before that packet is forwarded. The pool is the target;
  what may be reached inside the server stays with each kind's own policy, which
  is the thing that can say what a database or a statement means.

  `redis` and `amqp` are deliberately not wired: both confirm an identity only
  after the relay has forwarded the credential and the server has accepted it,
  so their connect-time hook has no user, and a section about people would have
  listeners where no rule about people can match. They need a second admission
  point at the server's acceptance, which is a design question rather than a
  wiring one; ROADMAP.md records it as such.

- **And the two generic layer 4 relays, `tcp` and `udp`, through one admission
  point that also closes the imported-lists gap.** A `cidr` feed had until now
  done nothing at all on any kind but `http` and `forward`: the other kinds check
  the ban list at accept and never the lists. Both questions belong at the same
  moment -- the point where a kind has a client and has not yet carried anything
  for it -- so `internal/admit` is that moment, and building it twice would have
  been the mistake. It asks the lists about the client's address, then the policy
  on the address, the listener, the pool and the hour.

  The lists go first, deliberately: a list is an import about an address and says
  nothing about this estate's intentions, so a refusal naming the feed sends an
  operator to the feed rather than to a rule they would not find. A list asking
  for a `challenge` is recorded like a log list there, because there is no request
  to serve a challenge into and turning it into a block would be a policy the
  operator did not write.

  There is no identity on a generic relay -- that is what makes it generic -- so a
  rule naming `users` matches nobody on these kinds, and the reference says so per
  kind rather than leaving it to be discovered. A rule there is `networks`,
  `targets` and `schedule`, which is a real policy: which networks may reach which
  pool, in which hours.

  On `udp` the decision is made once for a client that has no session rather than
  once per datagram. The session table is keyed by client, so that is a decision
  per client, and a policy walk for every datagram of a flood would make the flood
  cheaper to send than to refuse. A test drives five datagrams and asserts the
  policy decided once.

- **And the LDAP relay, at a bind and nothing else**, before the bind is
  forwarded. A bind is the only request that names an identity, and refusing one
  before it travels matters more here than almost anywhere: a bind that reaches a
  directory is a password guess against it. What that leaves out is documented
  rather than glossed -- an anonymous session names nobody, so no rule about
  people reaches it, and what a bound session may read or write stays with the
  `ldap` policy, which is the thing that can say what a search base means.

- **And the MQTT relay**, at the CONNECT packet and before it is forwarded, so a
  client no rule covers never reaches the broker. The CONNECT username is the
  name; the client identifier deliberately does not reach a rule, because any
  client may choose one and a pattern over it belongs in the listener's own
  `client_id_pattern` -- an identity rule written against a string the client
  picks is not an identity rule.

- **And the forward proxy**, on every request, tunnel and association --
  CONNECT, a plain proxied request, SOCKS5 and MASQUE alike -- after the
  destination policy and before the destination is dialled. Here the target is
  the destination `host:port` rather than a pool, because a forward proxy has no
  pool and the destination is exactly what a rule about egress needs to name;
  `*` does not cross the colon, so `*.vendor.example:443` is one set of hosts on
  one port rather than one pattern's worth of the whole internet. The user is
  the proxy credential's name, empty on a listener with no `auth` -- so a rule
  about users matches nobody there, and such a listener wants rules about
  networks and destinations instead.

- **And the ten kinds whose clients have no identity at all**, through the same
  admission point: `modbus`, `iec104`, `s7`, `snmp`, `tftp`, `dhcp`, `bacnet`,
  `ntske`, `syslog` and `dns`. This is the half of the estate a rule about people
  can say nothing about, and until now it was also the half a `cidr` feed did
  nothing on: an OT network is exactly where an imported list of known-bad
  addresses is worth having, and a Modbus or SNMP listener asked for none of them.
  Both questions are now asked once, in one place, for all of them, so the order
  cannot drift from kind to kind.

  On the stream kinds the question is asked on the connection, after that
  listener's own `allow_clients` and before the device, station, PLC or handshake
  slot is taken -- which matters most on `s7`, because an S7-300 has sixteen
  connection resources altogether and a client that may not reach the CPU should
  not take one while being refused, and on `ntske`, where the handshake is the
  expensive thing the port has to protect.

  On the datagram kinds it is asked per datagram, because a datagram relay has no
  session to hang the answer on. A refusal goes through each kind's own deny path,
  so a client that keeps sending earns a ban exactly as one refused by that
  listener's own address lists does -- which is what keeps the record from being
  written at packet rate, and is the answer the ban list already gave for those
  paths.

  Two of them are worth being plain about rather than counting as coverage. On
  `dhcp` a client with no lease sends from `0.0.0.0` -- that is what DHCP is for --
  so `networks` decides nothing about exactly the clients an operator most wants to
  think about, and the imported lists have nothing to match; what decides there is
  `listeners`, `targets`, `actions` and `schedule`, and the reference says so
  instead of implying a rule about networks would help. On `dns` there is no
  upstream pool at all, only a list of resolvers, so the subject carries no target
  and `targets` names nothing on that kind: a rule about where a query may point is
  a rule about a domain, which belongs to the `dns` policy.

  `dns` also needed care the others did not. A query's source address is a
  datagram's unproven claim about itself, and this listener already refused to
  attribute a blocked-name event to one -- one aggregated record rather than one
  per packet against whatever address it named. The admission point reuses that
  same path rather than writing a second one, so a refusal on an unverified
  datagram is counted and attributed to nobody, and a flood cannot have records
  written, or bans earned, against a third party.

  `syslog` asks about `write` rather than `connect`, because a sender does not open
  a session with a collector -- it delivers records -- and it asks once per
  connection on a stream and once per datagram on UDP rather than for every line a
  connection sends. The host name inside a syslog message stays out of the policy:
  it is a field the sender wrote and nothing checks it, which is why the relay
  rewrites it from the address the message came from.

  Five kinds are left outside, each for a reason rather than a queue position, and
  each recorded where a reader will find it: `http` (a gateway's unit of work is a
  request, and the per-request answer is already the `authz` filter), `smtp` (the
  SASL exchange is deliberately not parsed, so there is no name this proxy did not
  invent), `redis` and `amqp` (both authenticate at the server, so their admission
  point is its acceptance), and `ntp` (no client state at all; `ntske`, which is
  where a client is admitted before it gets cookies, does ask).

- **And the last four relays, which leaves only the HTTP gateway outside.**
  `smtp` and `ntp` join the identity-less half: `smtp` still has no name to offer,
  because the SASL lines carry the password and this relay deliberately does not
  parse them, and `ntp` has only an address, so on both a rule is `networks`,
  `targets` and `schedule`. `smtp`'s refusal is `554 5.7.1 access denied`, which a
  client library reports, rather than a dropped connection.

  **`redis` and `amqp` ask twice, and the second ask is the only place on any relay
  here where the policy sees a name that has been proven.** The earlier note said
  these two needed a *replacement* admission point at the server's acceptance. That
  was half right: what they need is a **second** one, because a connection and an
  authenticated session are two different subjects. So `connect` is asked on the
  connection, where nobody has a name and a rule is about networks; and `session` is
  asked when the server's answer to an AUTH or HELLO, or the broker's
  `connection.tune` or SASL outcome of zero, says the credential was accepted.

  The relay already read those answers -- "has this connection authenticated"
  cannot be answered from the client's side, which is what `require_auth` exists to
  prevent -- and the same answer proves the name. So an allow rule keyed on `users`
  on these two kinds is an **authenticated grant**, which is not true of
  `postgres`, `mysql` and `tds`, where the policy is asked before the server has
  spoken and an allow rule is a filter on a claim. The reference and both protocol
  pages say which kind is which, because the stronger reading is the one an
  operator will otherwise assume everywhere.

  The cost is where the refusal lands, and it is a fact about the protocols rather
  than a choice: the server has seen the credential by the time it can prove a
  name, so the refusal keeps every command or method *after* it off the server
  rather than keeping the session off entirely. The acceptance is never forwarded,
  so the client is never told it has a login it may not use.

  Two asks needed two actions, which is what `actions` is for -- and the first
  attempt got it wrong in a way a test caught immediately. With one action the
  second ask was answered by whatever rule let the connection in, so a policy
  written as `users: [bob]` refused every client, including bob: at the connection
  there is no person, and no rule about a person can match a subject that has none.
  With `connect` for the door and `session` for the person, one rule decides each:

  ```yaml
  authorization:
    rules:
      - {name: staff, allow: true, users: [bob], actions: [session]}
      - {name: floor, allow: true, networks: ["10.0.0.0/8"], actions: [connect]}
  ```

  A listener whose clients never authenticate never reaches the second question, so
  there the `connect` rule is the whole policy -- the same position every
  identity-less kind is in.

- **And the HTTP gateway, which closes the section: every listener kind asks it
  now.** This was the one kind left, and it was left because the question looked
  like it did not fit -- a gateway's unit of work is a request, and a request is
  already decided by its route and by the `authz` filter in that route's chain.
  What the gateway was actually missing is the layer above both of them, and it is
  a real one: *may this client be served by this listener at all, towards this
  pool, at this hour.* A route cannot answer that, because a route is one of the
  things being decided about. The filter cannot, because it needs a verified
  identity and this is about clients that have offered none. "Nothing from the
  vendor network reaches the internal pool outside working hours" was a sentence
  the gateway had no place to be told.

  Asked once per request, after the route is matched -- so a rule's `targets` can
  name the route's upstream pool -- and before the challenge gate, the filter chain
  and the upstream, so a refused client's request never reaches a WAF, a body
  buffer or an origin. A refusal is a **403** rather than a dropped connection,
  because on this kind there is a response to write, which is also why the question
  belongs there rather than at the accept.

  The subject carries no user, deliberately. The gateway does establish identities
  -- that is what its authenticating filters are for -- but per route, and what one
  may then do is the `authz` filter's decision; filling a user here would put the
  same question in two places with two answers. So a rule naming `users`,
  `principals` or `groups` matches nobody on this kind, exactly as on the relays
  that have no identity at all, and a policy written only about people refuses every
  request here, fail-closed. A test asserts that rather than leaving it to be
  discovered in production.

  Two asymmetries were kept on purpose. The gateway does not share
  `internal/admit`: its list handling has per-route exemptions and a `challenge`
  action that serves a real challenge page, and the shared point flattens both,
  because the kinds it serves have no request to challenge into. And the policy is
  **not** route-exemptable, unlike those lists -- a list is somebody else's import
  and a route may reasonably opt out of one, while a route that could opt out of the
  estate's own policy would not be a policy.

  With this the fail-closed load check can no longer be provoked by any
  configuration the reference describes, so the test that proved it has inverted: it
  now asserts that no kind is outside the policy, and `notYetAuthorising` in
  `internal/listener` is empty, which is the state it was built to reach. The check
  itself stays, because a kind added tomorrow starts outside and must be refused
  rather than silently uncovered.

  Cost: a policy walk per request rather than per connection, since a connection
  carries requests for many routes and the pool is not known until one is matched.
  The cheap case is the common one -- the ask returns before looking at anything
  when no section is configured -- and a test holds that too.

  One of the three mutations run against this survived at first, and it was worth
  the run: the shadow test used the section's `shadow: true` and so said nothing
  about a listener's own `policy: {mode: shadow}` -- which is exactly the switch
  four relays were found ignoring in this same release. That case now has its own
  test, and the mutation fails.

- **Two ban reasons nobody could ban on, and one refusal nobody could count.**
  Wiring `dns` turned up that the reason it hands the ban list for a name on a
  domain list, `dns_threat_intel`, was not in the table a ban trigger is validated
  against -- so a trigger naming it did not load, and the `dns_denied` the new
  admission point emits would have had the same gap. Both are nameable now. And
  `iec104` counted no refusal reason for the decisions it makes before a
  controlling station has said anything -- a client that may not connect, a
  malformed frame, a bound -- while counting every decision about an ASDU, so an
  operator reading that listener's refusals saw the protocol and not the door. It
  counts them now, before the alert switch, because a listener with alerts off is
  one that does not want the records and still wants the numbers.

- **Readable while it is being trialled.** `shadow: true` evaluates the
  whole policy and records what it would have refused without refusing
  anything -- section-wide rather than per rule, because half a policy in
  force is not a policy -- and a listener's own `policy: {mode: shadow}`
  does the same for that listener. `xproxyctl status` prints the default,
  the counts and every rule with its hit count, marking the rules that
  have never matched. The metric worth alerting on is
  `xproxy_authz_default_total`, the decisions the default made because no
  rule matched: it is the measure of how much of the estate the rules
  actually describe, and three alerts ship for it and for the two
  switches (`shadow`, `default: allow`) that change what every other
  number means.

- **How much a name is worth differs by kind, and the documentation says which
  is which.** On the kinds that authenticate the client themselves -- ssh with a
  key or certificate, telnet with a second factor, vnc with a credential it
  checks, ftp once the target's own login succeeded -- the name is proven before
  the policy is asked. On postgres, mysql, tds and rdp the far side does the
  authenticating and the policy is asked *before* the login or the credential is
  forwarded, which is the point: it keeps a refused session off the server
  entirely. But it means the name is asserted and proven afterwards, so the
  policy narrows what the far side would have allowed and never widens it -- a
  deny rule is exact, an allow rule is a filter on a claim the server still has
  to verify. That is a real property and not an authenticated grant, so the
  reference carries it in a column of the per-kind table and each protocol page
  states it, rather than leaving the stronger reading to be assumed. A rule that
  must hold whatever a client asserts belongs in `targets` and `networks`.

  Both shadow switches leave the same record, rule included. The kinds hand the
  policy their own counters, security event and ban list through one small
  interface, so the ordering that is easy to get wrong -- which switch is
  checked, whether a shadowed refusal counts as a refusal (it does not),
  whether the rule reaches the report -- is written once rather than five
  times.

  Not the `authz` filter, which decides one HTTP request by method, path,
  scopes and claims inside a route's filter chain. This decides whether a
  session happens at all. They share a vocabulary deliberately and
  nothing else, and an HTTP deployment can reasonably want both. The package
  is `internal/authorization` so the two are apart by name as well as by
  layer.

### Added (1.4, the factors that are not typed)

- **`require_hardware_key`: only a key held in a security token
  authenticates.** FIDO2 keys already worked at the bastion -- x/crypto
  parses `sk-ssh-ed25519@openssh.com` and
  `sk-ecdsa-sha2-nistp256@openssh.com` and verifies the token's signature
  envelope, presence flag included -- and what was missing is the policy.
  It is the one property of a credential this gateway can check: every
  other key it accepts is a file, and a file has copies (a backup, a
  laptop left on a train, an agent forwarded to a host that kept it) that
  nothing in the protocol can tell from the original. A token's private
  half never leaves the token.

  `require_touch`, on by default, keeps the other half. A signature says
  whether the user was present when it was made; without that the key
  cannot be copied but anything on the machine it is plugged into can use
  it. Both opt-outs are refused: a `no-touch-required` option in
  `authorized_keys` fails the load, because the credential would never
  work and finding that out at load beats finding it out at three in the
  morning, and the certificate extension of that name is refused at
  authentication -- an authority can hand out a credential that needs no
  touch, and this listener's answer to that is no. `require_touch: false`
  honours both, as OpenSSH does, for the keys that work unattended.

  What the requirement does not cover is said at load. A password beside
  it with no second factor is refused outright: it is a way in that no
  token protects. A `principals` entry may exempt itself, because an
  estate moves to tokens one person at a time and a service account has no
  hands, and the exemption draws advice. A requirement with no `sk-` key
  in the file and no authority to issue one is refused -- a listener
  nobody could log into.

  The tests implement the token's half of the protocol rather than mocking
  it, so a real handshake meets the same verification code a real token's
  signature does.

- **`mfa.push`: the second factor approved on a device instead of typed.**
  The user is shown a number, a notification goes to the device they
  already carry, and the session waits. It is the factor people actually
  use, and the one with an attack of its own: somebody who has the
  password can send notification after notification until the person taps
  approve to stop the buzzing.

  So the section is shaped by that attack rather than by the happy path.
  One request in flight per user. A bound per user per window
  (`per_window`, `window`), over which the attempt is refused and counted
  and **no notification is sent** -- the notifications are the attack. A
  number this proxy generates, shows through the protocol's own prompt and
  sends with the request, so a person who did not cause the notification
  has nothing that matches. And every way of not getting an answer is a
  refusal: a timeout, a non-200, a `result` this cannot read, an answer
  whose nonce is not the one asked about.

  The protocol is specified in CONFIG.md so a service can be written for
  it: one POST per approval, and a GET with the nonce to ask about a
  pending one, which sends no second notification. With `push` alone every
  user is pushed and the approval service decides whether they exist; with
  `file` and `push` together an enrolled user types a code and everybody
  else is pushed, which is the shape of an estate moving between the two.

  `mfa_push_sent`, `_approved`, `_denied`, `_failed` and `_throttled`
  count it, with a denial and an outage apart on purpose, and two alerts
  page: one for the fatigue bounds refusing attempts, one for an approval
  service that has stopped answering (it fails closed, so that is
  everybody with that factor locked out).

  It is wired into the ssh gate. The other kinds that ask for a factor
  still ask for a code; the enrolment, the replay rule and the lockout are
  already shared, so what is left per kind is the prompt.

- A credential written as a literal or as a reference (`env:`, `vault:`)
  is now resolved in one place, `keysource.Token`, because a threat feed
  and an approval service are written the same way and two answers to "is
  this a reference" would be two behaviours.

### Added (1.4, threat feeds)

- **A threat list may say where its entries come from: a file, a URL, a
  TAXII 2.1 collection or a MISP instance.** A list used to be a file
  somebody else's cron job dropped on the machine, which means the feed an
  estate subscribes to and the policy this proxy enforces are joined by a
  shell script nobody owns. Exactly one of `file`, `url`, `taxii` and
  `misp` is the source; two is refused rather than resolved by precedence,
  because a list whose source is ambiguous is a list nobody can say the
  contents of.

  A URL feed is fetched conditionally, so an unchanged feed costs a 304
  rather than a download. A TAXII collection is polled through its API
  root with `added_after` as a floor on age rather than incremental state:
  every fetch sends the same value, so the list stays the whole answer to
  the same question and an indicator the publisher revokes disappears from
  it. A MISP instance is searched through `/attributes/restSearch`, for the
  attribute types this proxy can match on rather than all two hundred, and
  only attributes the analyst marked `to_ids` are taken -- one that was not
  is context, not policy.

  A fetch that fails keeps the entries already read, which is deliberate:
  a publisher having an outage must not empty the policy for as long as
  that takes. It does mean the list has stopped being current while it goes
  on matching, so `xproxy_threat_feed_fetches_total` counts fetches, 304s
  and failures apart, `xproxy_threat_list_age_seconds` says how long since
  the last read, and three alerts (`XproxyThreatFeedFailing`,
  `XproxyThreatListStale`, `XproxyThreatListEmpty`) say so out loud.

  One fetch, every page of a paginated collection included, is bounded by
  `http.timeout`. Redirects are followed only to the same host: a feed
  whose publisher can redirect anywhere is a feed whose publisher can point
  this proxy's block list at a document they do not control. Verification
  may be skipped only with `insecure` **and** `allow_insecure`, and only
  for a loopback address, because a feed nobody authenticated becomes this
  proxy's block list.

- **Three indicator kinds that are about what the client asked for:
  `domain`, `url` and `hash`.** An address says who is connecting, which a
  compromised machine on a network nobody has attributed will pass. A name,
  a URL or a digest says what was asked for, and it is often the better
  question.

  A `domain` entry covers the names under it, and a `url` entry matches at
  a path boundary, so an entry for `/dl` does not match `/download`, which
  on a shared host is somebody else's. Both walks run from the shortest
  suffix down and are bounded by the deepest entry the list holds, because
  walking down from the request would let a client escape a listed name by
  padding what it sends with labels -- 65 of them still fit in a Host
  header -- or a listed path by appending segments. A query cannot be used
  for it either: `/dl?x=1` is `/dl` under the boundary rule.

  A `hash` entry is an MD5, SHA-1 or SHA-256 digest, recognised by its
  length, so a feed that writes the algorithm beside it still parses.
  `challenge` on a hash list is refused at load: the match is on a payload,
  not on a browser asking for a page, so there is nobody to challenge.

- **STIX 2.1 bundles and MISP exports are read for the parts a proxy can
  act on**, and what was not taken is counted. A bundle of ten thousand
  objects behind four entries is either the wrong feed or the wrong kind,
  and the pair of numbers -- entries and `skipped` -- is what says which. A
  STIX pattern is read as a whole or not at all: a mixed pattern used to
  contribute the half that was readable and then report nothing, which is
  an entry nobody asked for.

- **The lists are asked at three more places.** The forward proxy asks
  about the destination -- a name, and on the plain path the whole target
  -- after this estate's own allow and deny rules, because those are local
  policy and a destination an operator wrote an allow rule for must not be
  taken out by somebody else's feed. The resolver asks about the query
  name, last of three: the operator's block list wins, then a policy zone,
  whose `passthru` rule exempts a name from the lists as well. And the
  upload guard asks about a file's SHA-256, in the pass it is already
  making over the bytes and only when a hash list exists to answer.

  A hash list with no `upload_guard` filter configured anywhere draws
  advice at load, because a list nobody asks is worse than no list.

  Not covered: an address list is consulted for the client at the HTTP and
  forward listeners and nowhere else. The gate and relay kinds check the
  ban list at accept but not the imported lists.

- **`xproxyctl status` prints a line per list** -- kind, action, entries,
  hits, how long since it was read, format, skipped, fetches, 304s,
  failures and the source -- and two dashboard panels carry the same
  numbers. An imported list is only as good as its last read, and the
  status view said nothing about reads at all.

- The middleware contract gained `Env.Intel` and `Verdict.ThreatList`
  (additive; `filter.APIVersion` stays 1), so a filter that reads a payload
  can ask the hash lists about it and the data plane counts the match where
  every other match is counted. `Env.Intel` is a function rather than the
  set because the set is replaced on a reload and its entries re-read
  underneath: a filter holding the one it was built with would go on
  matching a feed nobody publishes any more.

### Added (1.4, key custody)

- **Where a private key lives is now something the configuration says:
  `key_file`, `key` or `signer`.** A TLS private key in a file is the thing
  every other control in this proxy exists to protect, and it is the one thing
  a file system hands over whole. Each entry of
  `server.listeners[].tls.certificates` names `cert_file` and then exactly one
  of three keys, and two of them being set is refused at load rather than
  resolved by a precedence nobody remembers -- a certificate with two keys
  configured is a certificate whose key nobody can name by reading the file.

  - `key_file` is a PEM file on this machine, as it has always been, and stays
    the default for every configuration written before this existed.
  - `key` is a **reference**: `file:/path`, `env:NAME` or
    `vault:secret/path#field`. A value with no scheme is a path, so nothing
    already written changes meaning, and an unknown scheme is an error rather
    than a fallback to "file" -- a typo in a scheme must not become a path
    nobody meant.
  - `signer` is a helper process on a Unix socket that holds the key -- in a
    PKCS#11 token, an HSM, a TPM, or simply under a different user with a
    tighter sandbox. The proxy sends a digest and gets a signature back, so the
    key never enters this process and anything that reads this process's memory
    gets nothing. It is a separate process rather than a linked library because
    the daemons are built with `CGO_ENABLED=0` and a PKCS#11 module is a C
    library: keeping it out is both a build fact and the point.

  At start the proxy asks the helper to sign a known value and checks it
  against the public key in `cert_file`. A helper that cannot prove it holds
  the matching key fails the load, because the alternative is a listener that
  comes up and then fails every handshake -- which looks to everyone else like
  the listener being down.

- **`secrets`: where a reference resolves from, with a vault.** A
  `secrets.vault` section names a HashiCorp Vault, its KV mount and version,
  and a token from a file or the environment (the environment is warned about:
  it is readable by anything that can read `/proc` for the same user, and every
  child process inherits it). Three rules the resolver holds to, because a
  secret resolver that breaks them is worse than a path:

  - **A value is never logged, wrapped in an error, or put in a dump.** Errors
    name the reference. The configuration holds references rather than
    material, so `xproxyctl dump`, the history and a diff show where a secret
    comes from and never what it is.
  - **A resolved value is cached and refreshed on `refresh_interval`** (default
    5m, bounded 1m to 24h), so a rotation in the vault reaches a running proxy
    with no reload and no restart. That needed more than a TTL: a certificate is
    read once at load, so there is also a refresh loop that re-resolves each
    listener's referenced keys once per interval and rebuilds the certificates
    when the material changed. It runs only where a key is a reference -- a
    listener with keys in files or behind a signer gets no goroutine -- and
    `xproxy_secret_rotations_total` counts the certificates actually replaced,
    which is what an operator compares against what the vault says it rotated.
  - **A failed refresh keeps the previous value and warns.** A vault that is
    down must not take a TLS key away from a proxy that is already serving with
    it; the whole point of the arrangement is that the estate keeps working
    while somebody fixes the vault.

  That last rule means the failure worth alerting on is not an outage but
  silence: a secret that has quietly stopped rotating. `xproxy_secrets_stale`
  counts the references whose last refresh failed, `XproxySecretStale` fires on
  it after half an hour, and `xproxyctl status` lists them.

  `http://` to a vault takes **both** `insecure` and `allow_insecure`, because
  plain HTTP puts the token and every secret it reads in clear on the wire and
  one typo must not do that. `insecure` on an `https://` address is refused
  outright: skipping verification there means anything on the path can hand
  this proxy the private keys it will then serve with, which is a worse
  position than having the keys in a file. Name `ca_file` instead.

- **`fips`: refuse to start unless the FIPS 140-3 module is active, and measure
  what it will do.** `required: true` is a refusal rather than a warning, and
  that is the whole value of the setting: a deployment that must be FIPS cannot
  quietly stop being it after a rebuild with the wrong toolchain. Build with
  `GOFIPS140=v1.0.0` and run with `GODEBUG=fips140=on`.

  `probe: true` (which follows `required` unless set) asks the module at start
  which of the configured key exchange groups and cipher suites it will
  actually do, by completing a TLS handshake over an in-process pipe for each
  one. It **probes rather than checking against a list of approved
  algorithms**, because which algorithms an active module accepts is a property
  of the toolchain and the module version rather than of this project's
  documentation, and a stale list either refuses a configuration that works or
  blesses one that does not. On the toolchain this was written against, a
  module in FIPS mode refuses `X25519` and
  `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256` while accepting
  `X25519MLKEM768` and the P-curves -- exactly the sort of detail that would be
  out of date in a list and is never out of date in a measurement.

  A refused algorithm is a warning and a counter by default, because a listener
  offering four groups with one refused still works for every client asking for
  the other three; `probe_fails: true` is the stricter reading.

- **`xsigner`(8): the helper is shipped, not just described.** The `signer`
  setting was a socket an operator had to put something behind, which made the
  strongest of the three arrangements the only one nobody could actually use.
  There is now a helper.

  It holds keys it reads as PEM -- from a file, the environment or a vault --
  and answers signature requests. It runs as its own user, its configuration
  and keys live under `/etc/xsigner` rather than `/etc/xproxy` (that directory
  is readable by the `xproxy-config` group, which is the three proxy daemons,
  and the whole point is that they cannot read what the helper reads), and the
  shipped unit gives it `PrivateNetwork=yes` -- the strongest single line in
  it, because a bug in a process that cannot send anywhere cannot exfiltrate a
  key. `-validate` loads every key before anything binds; `-print-keys` prints
  the public halves, which is the answer to the one question the protocol
  cannot answer from the proxy's side: which key is behind this name.

  **The socket's permissions are the authentication**, and there is no
  credential on the wire because whatever the proxy could present, anything
  that had taken the proxy could present too. `/run/xsigner` is 2750
  `xsigner:xsigner-clients` and the socket inside it 0660, inheriting that
  group from the setgid directory: connecting to a Unix socket needs *write*
  permission on it, so the group is the access list and the directory is the
  wall. A world-writable mode is refused outright rather than warned about --
  it would make the helper a signing oracle for every key it holds, and there
  is no deployment where it is right.

- **[SIGNER.md](SIGNER.md): the protocol, specified.** One JSON object each way
  over a Unix socket. It is written so that a helper for an HSM, a TPM, a
  smartcard or a cloud KMS can be written against it -- including what a helper
  must check (the key exists, the algorithm suits the key type, the digest is
  short enough to be a digest) and what it must never do (return a key, log a
  digest, echo an unbounded field, hang up on a bad request), plus a working
  forty-line helper.

  Two details in it are where a helper gets written wrongly, so they are stated
  twice: Ed25519 signs the *message* rather than a pre-hash, and RSA-PSS needs
  the salt length on the wire because a verifier that assumes the wrong one
  rejects a correct signature.

- **The derived sandbox knows about all three arrangements.** The signer's
  socket gets a **write** rule, not a read one: connecting to a Unix socket is
  a write under Landlock, and a read rule would give a daemon whose every
  handshake on that certificate fails with permission denied. A `file:`
  reference gets a read rule, added explicitly because a reference is not spelt
  like a path and the ordinary walk cannot classify it. A `vault:` reference
  gets no rule at all, because it is not a path.

- **The status view and the exposition say where the keys are.**
  `xproxy_private_keys{custody="file"|"reference"|"signer"}` is the count per
  arrangement -- `file` being how many private keys an attacker who reads this
  machine's file system gets, and the number an estate should be able to watch
  going down. Beside it `xproxy_secrets_vault`, `xproxy_secrets_stale`,
  `xproxy_fips_enabled`, `xproxy_fips_required` and
  `xproxy_fips_refused_algorithms`, all present at rest so they can be alerted
  on. Two Grafana panels and two alert rules
  (`XproxySecretStale`, `XproxyFIPSRefusesConfiguredAlgorithms`).

  `examples/security/key-custody.yaml` is one listener with all three
  arrangements side by side, so a migration can be read off it.

### Added (1.4, access)

- **Just-in-time access to the gate kinds: `access`, `require_grant`, and a
  ledger with a hash chain.** A bastion with standing access is a bastion whose
  accounts are worth as much as the machines behind it: the keys sit in the
  estate all the time, so whoever reaches a key, a laptop or a session reaches
  production at a moment of their choosing. The other arrangement is now
  available -- nobody opens a session unless a live grant names them, the
  listener and the target; the grant ends by itself; and a second person had to
  agree to it.

  **Four eyes.** A grant is in force only once `approvals` people have approved
  it, and neither the person who asked nor the person who gains the access may
  be one of them. Names are compared trimmed and case-insensitively, so `Alice`
  approving what `alice` asked for is one person rather than two; one approver
  cannot count twice; and the approvals a grant needs are fixed when it is
  requested, so loosening the policy later does not bring a half-approved grant
  into force. `self_approval` is an explicit, warned-about opt-in for the estate
  with one operator, where the alternative is switching the requirement off.

  **A time box.** `max_duration` bounds the window and `max_lead` how far ahead
  it may start, both checked when the request is made rather than left to an
  approver to notice. The window ends the session **that is running**, not only
  the next one somebody opens. A request nobody approved before its window
  closed is expired rather than pending.

  **A written record.** Every request, approval, denial, revocation and use is
  one line of an append-only trail carrying a hash chain, so a removed, edited,
  reordered or forged line is found when the file is read and the daemon refuses
  to serve a trail it cannot stand behind. One process holds the file
  exclusively. A record is written, flushed and synced *before* the grant it
  describes is in force, and `max_uses` is durable for the same reason: a
  one-shot grant that refills itself on restart is not one shot.

  All five gate kinds take `require_grant`, in that one spelling. Where the
  protocol names the person before the target is dialled (ssh, telnet, vnc)
  nothing is reached without a grant; where it cannot (rdp's credential and
  ftp's login both arrive after the connection is open) the grant is checked
  before the credential or any command of the person's is forwarded, and against
  the machine already reached. telnet and vnc now refuse `require_grant` at load
  when they have no way to learn a name, rather than failing closed on the first
  evening. A grant naming one machine **pins the dial to it**.

  Each gate's access log line names the grant the session was opened under,
  and the ledger's use record names the session, so an investigation holding a
  recording can find the approval and one holding an approval can find the
  recordings. Without both directions a reviewer has to guess which window
  produced the session in front of them.

  The exposition carries it: `xproxy_access_grants{state}` with every state
  present even at zero (a gauge that disappears when it reaches zero is a gauge
  an alert cannot be written against), the acts as counters, and
  `xproxy_access_refusals_total{reason}`. Three alerts come with it -- a request
  that has been pending for half an hour, sessions refused for want of a grant,
  and grants being *used* over a day with no approval recorded in the same day,
  which is four eyes switched off -- and two panels on the security dashboard.

  Eight refusal reasons, each its own counter (`no_grant`, `grant_pending`,
  `grant_not_yet`, `grant_expired`, `grant_denied`, `grant_revoked`,
  `grant_spent`, `grant_wrong_target`), because an operator answering a call
  needs to know which; a listener in `policy: {mode: shadow}` records what it
  would have refused and carries on. `xproxyctl access [ask|approve|deny|revoke]`
  and five management calls under `/v1/access` are the interface, audited with
  the caller's kernel-reported credentials beside the name each act was recorded
  under.

### Changed (1.4)

- **A discovered endpoint now earns its place with a probe.** Active health
  checking, passive outlier ejection, DNS and Consul discovery, drain and
  per-endpoint bounds were all in place, but they met each other wrongly at one
  point: an endpoint an announcement added to a **serving** pool started
  `healthy: true` and was picked immediately, before any probe had run.

  That is right at process start -- nothing has been probed then, and waiting
  would serve nothing at all for an interval -- and wrong for an announcement,
  because a registry announces an instance when its *process* starts, not when it
  is ready: the service registers, then opens its database connections, loads its
  caches and finally listens. The proxy was sending real requests into that gap
  and then ejecting the endpoint for failing them, so every deploy and every
  scale-up cost a burst of errors the proxy itself caused.

  An endpoint that arrives while the pool is serving now begins unhealthy and
  waits for `healthy_threshold` probes, and its **first probe runs at once**
  rather than after the usual start jitter -- otherwise "wait for a probe" would
  mean "sit out up to one `interval`", five minutes on a common setting.

  The three exceptions are the point of the change rather than caveats to it. An
  endpoint serves immediately when there is no `health_check` (no probe to wait
  for, so waiting would mean never), when **nothing else in the pool can carry
  the traffic** -- every other endpoint unhealthy, draining, ejected or at its
  own `max_active` -- since there is no all-unhealthy fallback and an unprobed
  endpoint beats an empty pool, and for the endpoints the pool starts with,
  discovery's own first resolution included. An address that leaves a resolution
  and comes back waits again: what is listening there now is not the process that
  was healthy before.

- **A resolution can no longer size the process: `discovery.max_endpoints`.**
  Endpoint discovery installed however many endpoints an answer carried, and
  each one is a health-check goroutine, a place in the hash ring and a slice of
  the pool. A DNS answer over TCP carries thousands of A records and the four
  megabyte registry body limit allows tens of thousands of entries, so one
  answer -- from a registry that is confused, compromised, or answering somebody
  else's question -- decided how large this process is, on every interval.

  `max_endpoints` bounds one resolution; default 4096, 1 to 65536. Beyond it the
  resolution is **truncated rather than refused**: refusing keeps the previous
  set, and for a pool whose backends have all moved that is a pool serving
  nothing, while a bounded subset still carries traffic. The specs are already
  sorted by address when the bound is applied, so the subset is the same one on
  every resolution -- an unstable subset would remove and add endpoints every
  interval, losing their statistics, restarting their ramps and rebuilding the
  ring each time. The truncation is warned about through the throttled notice
  (a registry that answers that way answers that way every interval) and
  counted as `truncations` in `xproxyctl upstreams`, so a pool serving a subset
  of what was announced is visible rather than quiet. A configuration built in
  code rather than loaded falls back to the default instead of to no bound.

- **`internal/schedule`: one time window, shared by the thirteen kinds that had
  their own.** A refactor that turned into two bug fixes, because the copies had
  drifted.

  Thirteen listener kinds have a rule list with a `schedule` section, and
  thirteen had their own hundred lines to read it -- ten of them byte-identical
  but for the package clause and a paragraph of comment. 1,404 lines out, 56 in.

  **The day names disagreed with validation.** `internal/config` accepts a day
  written either way, `mon` or `monday`, because that is what an operator writes.
  The modbus copy accepted both; the other twelve accepted only the short form
  and returned an error for the long one. So a configuration with
  `days: [monday]` on any listener but a modbus one passed
  `xrelay -config … -validate`, which said OK, and then refused to start with
  `"monday" is not a day`. Validation and the runtime disagreeing about whether a
  file is valid is the worst class of configuration bug there is: the check an
  operator runs before a change window told them the change was safe. Both
  spellings now work everywhere, and a test asserts that every day name
  validation accepts is one the runtime compiles.

  **The copies held two different answers to what a midnight-spanning window
  means**, so the same YAML was in force at different times depending on which
  listener it was written for. Twelve checked the day list against the day the
  moment falls on, which reads `{days: [fri], from: "22:00", to: "06:00"}` as
  Friday's *own* small hours -- nobody's night shift -- and refuses Saturday's,
  which is the shift that was written. The modbus copy did that *and* reached
  into Saturday morning, so it was the union of both readings and in force three
  times over.

  Neither is what `docs/CONFIG.md` describes. A window now **belongs to the day
  it started on**: Friday 22:00 to Saturday 06:00, and nothing else. This
  **changes when a midnight-spanning rule with a day list is in force** -- the
  small hours of a named day are no longer covered by that day's own evening
  window, and the small hours after it now are. Measured across every named day
  and every hour of a week, 84 of 3,528 (window, hour) pairs change, and all 84
  are midnight-spanning: a rule with no day list, or whose window sits inside one
  day, is unaffected, which is almost every rule anybody has written. An operator
  who wants a plain "these hours on these days" window is not affected at all.

  `internal/schedule` is at 98.5% coverage, and its tests pin both fixes,
  including a regression that asserts the old reading in both directions -- a fix
  that only closed the wrong window would have left the right one closed too.

- **`internal/sesslimit`: the session bound, and the race six kinds shared.**
  `max_sessions` and `max_sessions_per_client` could each be **exceeded by
  concurrent connections**, because every copy read the counter and then
  incremented it with nothing holding it in between. Driven with 512 goroutines
  against a bound of two, three sessions were admitted; the global bound failed
  the same way and by as many as the accepts in flight.

  The per-client table had a second fault: the release path deleted a client's
  entry when its count reached zero while another goroutine held the counter it
  had already fetched, so that increment landed on an orphaned counter and the
  session went uncounted for the rest of its life.

  Both are bound evasion by an attacker opening connections in parallel. It
  matters most concretely on `kind: s7`, where the bound exists because an S7-300
  has sixteen connection resources altogether and a client that takes more than
  its share denies the plant its own HMI -- and on the four database kinds, where
  the bound is what keeps one client from consuming a server's connection slots.

  The shared gate takes the count under the lock that checked it. It is a mutex
  rather than a pair of atomics on purpose: the contended operation is an
  *accept*, one per connection rather than one per frame, and a bound only
  approximately enforced is not a bound. 100% coverage, and the concurrency tests
  spin on a flag rather than parking on a WaitGroup, because a barrier that wakes
  goroutines spreads their arrival out far enough to hide the original defect.

  Six kinds migrated: amqp, mysql, postgres, redis, s7, tds. Refusal reasons are
  unchanged, so a listener's counters and alerts keep their names across this.

- **`internal/numrange`: the range list, from two copies.** `5`, `1-16`,
  `0x10-0x1F`, shared by the modbus and s7 kinds. Smaller than the schedule and
  with no behaviour question attached -- both copies were byte-identical in the
  parser and in `covers` -- but worth doing for what the s7 copy's comment
  claimed: that it used the modbus spelling deliberately, so an estate with both
  listeners does not have to remember that the two read `0-99` differently. A
  promise held by two copies is one waiting to be broken. 100% coverage, and
  `ParseNum` is exported because a policy reads bare numbers in the same two
  spellings as the ends of a range.

### Added (1.4)

- **`docs/protocols/`: one page per protocol, and a test that keeps the set
  honest.** `docs/CONFIG.md` answers "which settings are there", and a
  reflection test keeps it from falling behind the schema. Nothing answered the
  question an engineer has first: what is this protocol, what security was it
  designed with, and what did this relay decide to read?

  Twenty-eight pages, one per listener kind, each with the same five sections in
  the same order -- on the wire, what the protocol gives you, what this listener
  decides, what it does not do, and the standards -- and each handing the reader
  on to its `docs/CONFIG.md` section rather than repeating it.

  The **"what it does not do"** section is the one worth reading before relying
  on a listener, and the one that took the longest to write. A page that only
  says what a listener decides reads as a claim to cover a protocol; the honest
  version names the client list that is only an address list on UDP, the segment
  a listener is not a firewall for, the negotiation refused rather than
  rewritten, the content bounded rather than inspected, and — for the four
  database kinds — that a statement-shape policy is not a SQL firewall.

  `test/docs` ties the set to the roster in both directions and checks that no
  page is a stub: each of the five headings present, in order, with something
  under it. `TestEveryPageLinksToItsSettings` resolves the anchor rather than
  matching a string, and found twenty links that rendered as links going
  nowhere — because `docs/CONFIG.md` spells its per-kind headings two ways, the
  twenty-two older kinds as `### server.listeners[].<kind>` and the seven newest
  as `## <kind>`, so the anchor is not derivable from the kind's name.

  `docs/CONFIG.md` gained a `## http` section in the process. It is a map rather
  than a reference — HTTP is most of that document, and a reader looking for
  `## http` beside `## s7` and `## amqp` was not finding one.

- **`kind: s7`: a relay in front of a Siemens PLC.** `internal/s7` reads the
  three layers off the wire and `internal/kinds/s7` holds the policy.

  This is the protocol with the least security of any in this project. S7comm is
  TPKT (RFC 1006), COTP (X.224 class 0) and the S7 layer on TCP 102, and what
  matters about it is what it does not have. There is no transport security at
  all -- so the kind registers without a TLS section, because a certificate here
  would promise something the protocol cannot do -- and no authentication worth
  the name: the optional password protects a handful of functions on some CPU
  families and nothing on others, and an S7-300 with no password accepts a stop
  from anybody who can open a socket to it. The equipment cannot be fixed on a
  release cycle, so the boundary is the relay.

  **The controller is decided before the PLC is dialled.** Which CPU a client
  asked for is in the COTP connection request: the called TSAP's two octets hold
  a connection resource, a rack and a slot. A client that may not reach that
  controller is answered with a COTP disconnect -- what a CPU with no free
  connection resources sends -- and never reaches it, which matters because an
  S7-300 has sixteen connection resources altogether. `resources` is the cheapest
  line in the section: `pg` is the programming device connection an engineering
  station opens and `op` is an operator panel, so a listener admitting only `op`
  has refused every engineering station without naming a function.

  **One vocabulary spans two layers.** The protocol puts memory, blocks and the
  control service behind function codes, and the diagnostic buffer, the block
  list, the clock, the password and the debugger behind user-data groups and
  subfunctions. `internal/s7` maps both onto nineteen words and the policy is
  written in them -- which is what lets `read_only` mean every operation that
  changes the controller rather than just a write, one line no rule can override.
  The default allows what an HMI, a historian and an inventory do and nothing
  else; an **upload** is off with the writes although it changes nothing, because
  reading a block out of a PLC is how a plant's control logic leaves the site.

  **The memory is bounded by area, data block and byte range**, checked against
  the whole span a request covers rather than its first byte: a read of bytes 0
  to 200 against a range of 0 to 99 is refused rather than clipped, because
  clipping it would be the relay deciding which half the operator meant. The
  ranges are written in bytes and the protocol carries bit addresses, so the
  relay divides by eight rather than making an operator do it. `write_addresses`
  is separate, so one listener can allow a wide read and a narrow setpoint
  window, and `peripheral` on `deny_areas` shuts off direct access to the I/O
  hardware past the process image.

  A refused request is **answered and the session carries on**, which is the
  modbus kind's choice and for the same reason: a plant connection is a poll loop
  and dropping it turns a refusal into an outage. The answer is an
  acknowledgement with error class `0x87`, *access fault* -- what a
  password-protected CPU answers -- so the client's own library reports a
  refusal rather than a timeout; a refused user-data request is answered in its
  own layer, with the same group and subfunction and the error code for a
  function the CPU does not offer, because that is where a client that asked to
  set the clock looks. Only the frames the relay could not read at all end the
  connection. An access fault *from the controller* is logged as
  `s7_plc_refused`, because that is the case where the two policies disagree --
  usually a protected CPU and a client with no password.

  What is never logged is a value: a write's payload is a pressure, a temperature
  or a recipe parameter, and the address is what a policy is written about.

  `examples/ot/s7.yaml` has four listeners: the panels and the historian on a
  line, the engineering station on a separate address with a change window, a
  packaging cell that is `read_only`, and a cell nobody has an inventory of in
  monitor mode. Refusals are `s7_denied` for the ban triggers.

- **`kind: amqp`: a message broker relay that reads both protocols.** `internal/amqpwire`
  reads them off the wire and `internal/kinds/amqp` holds the policy.

  AMQP is two protocols sharing a name and a port, and a client picks one in its
  first eight octets. **0-9-1** is what RabbitMQ speaks and what almost every
  deployment means by AMQP: a frame protocol with a class-and-method catalogue
  where declaring an exchange, binding a queue, publishing and deleting are each
  a method frame with typed arguments. **1.0** (ISO/IEC 19464) is a different
  protocol that kept the name: nine performatives over a self-describing type
  system, where the thing being authorised is the address a link attaches to and
  everything after it carries a handle. Both are read, and **one policy decides
  both** -- the brokers that serve both versions spell an address
  `/exchange/X/key` and `/queue/Q`, so the same exchange and queue lists cover
  it and an operator writes the boundary once.

  A broker is where an estate's data is in transit, and its own permissions are a
  per-user, per-vhost matter administered inside the broker -- RabbitMQ's model is
  three regular expressions per user per vhost, which is more than most brokers
  offer and still outside the estate's own review. This listener holds that
  boundary in the configuration reviewed with everything else, and adds three
  lines the broker's model does not draw.

  **Topology is not work.** Declaring an exchange, deleting a queue, binding,
  unbinding and purging are the broker's *configuration*, and a service that
  publishes to an exchange somebody else declared needs none of them. So
  `allow_topology` is false by default, and a client library that declares its own
  queue on connect becomes a decision an operator makes rather than a default
  nobody noticed.

  **The credential is in the clear.** PLAIN -- what every deployment uses -- is
  the username and the password in one field separated by a zero octet, so
  `require_tls` defaults on and is the setting that matters most. The relay reads
  the *username* out of the SASL exchange for its rules and its logs and steps
  over the password, so no code path between the wire and a log line holds a
  broker credential. ANONYMOUS is not on the default mechanism list, because it
  is a login with no identity; a broker that *offers* it gets an
  `amqp_anonymous_offered` alert, since anything reaching that broker without
  passing this listener can use it.

  **The dangerous argument is not the obvious one.** `x-dead-letter-exchange` on
  a queue and `alternate-exchange` on an exchange each name an exchange the
  broker will route to, and `reply-to` inside a message names a queue a responder
  will deliver to. A policy that checked only the field being declared would let
  a client have the broker reach what the client may not, so all three go through
  the same lists -- as does the node address of a 1.0 attach. The name lists are
  written in the protocol's own topic language (`*` one word, `#` zero or more),
  because that is the one an operator already knows from writing bindings.

  Four more things follow from what the protocol is. A message is refused on the
  size its **content header declares**, before its body arrives, and on 1.0 by
  the sum over a run of transfers, because a message there may be split across
  them and bounding each frame would bound nothing. `require_user_id` with
  `match_user_id` turns "somebody published this" into an attributable act: it is
  the one field that ties a message to a person and nothing makes a publisher set
  it. A **refusal ends the connection**, with the protocol's own statement of why
  -- a `connection.close` carrying reply code 403, or a 1.0 `close` carrying
  `amqp:unauthorized-access` -- because AMQP is stateful in both directions and
  dropping one frame out of a conversation leaves the two sides disagreeing about
  what happened. And the **inbound direction gets the deny lists only**: an allow
  list says what a client may ask for, while a delivery names where a message came
  from, which a consumer need not be allowed to name -- a queue bound to an
  exchange by somebody else delivers messages carrying that exchange's name, and
  requiring it on the allow list would break every ordinary consumer.

  Two defects were found while writing the tests, both in the shape of the policy
  rather than in the parsing. `allow_topology: true` did not widen the method
  allow list, so a listener that permitted topology still refused
  `queue.declare` for being off a list the operator had not written -- the flag
  widens the list now, and the class is decided before the list so a refusal names
  the reason rather than the symptom. And the name patterns were being matched as
  shell globs over the whole string, in which `*` crosses a dot: `orders.*` then
  covered `orders.eu.created`, which is precisely the distinction a routing key
  policy exists to draw.

- **`kind: bacnet`: a BACnet/IP relay in front of a building.**
  `internal/bacnet` reads the three layers of ASHRAE 135 Annex J and holds the
  service, object and property tables; `internal/kinds/bacnet` holds the policy.

  The controllers behind this listener hold the setpoints for air handling,
  chillers, boilers, lighting, lifts, access control and smoke control, and the
  protocol they speak has **no identity at all**: no user, no session, no
  password that means anything, and no transport security. Clause 24's
  `authenticate` service was withdrawn from the standard and its network security
  is implemented by almost nothing in the field, so a device answers whoever asks
  it. Three properties of the protocol shape every control.

  **Writing is a service, not a mode.** `readProperty` and `writeProperty` are
  different service choices in the same request shape, so the difference between
  reading a zone temperature and setting it is one octet -- and
  `reinitializeDevice`, `deviceCommunicationControl`, `atomicWriteFile`,
  `createObject` and `youAre` are all ordinary confirmed requests. An empty
  `services` list therefore allows reading, discovery and the notifications a
  device sends of its own accord, and nothing that changes anything.

  **Writing has a priority, and the priority is the privilege.** A commandable
  object holds sixteen command slots and the plant follows the highest-priority
  one that is filled; slots 1 and 2 are manual and automatic life safety, and a
  value written there cannot be overridden by the management system, by a schedule
  or by an operator, and stands until whoever wrote it relinquishes it.
  `max_command_priority` defaults to 8 and the refusal is *hard* -- it holds in
  monitor mode, because a relay that shadowed this one would be watching somebody
  take a piece of plant.

  **It is broadcast, and it amplifies.** One `who-Is` is answered by an `i-Am`
  from every device that hears it; a BBMD's foreign-device registration lets one
  unauthenticated datagram subscribe a host to every broadcast on a network it is
  not on; `Forwarded-NPDU` carries the address a message came from inside the
  payload, where whoever sent it chose it. So `allow_broadcast`, `allow_bbmd` and
  `allow_forwarded` all default to false, `max_broadcast_replies` bounds the
  answers one broadcast brings back, a request routed to network 65535 is refused,
  and a `Forwarded-NPDU` whose claimed origin is not the address it arrived from
  is refused.

  Deciding about a request means knowing which object it is about, and the first
  object identifier in the parameters is the wrong one often enough to matter: in
  a COV notification the first is the device that sent it and the third is the
  object that changed. So the relay knows *where each service keeps its object*
  rather than searching for one, checks every object and property in a
  `readPropertyMultiple` or `writePropertyMultiple` rather than the first of
  forty, and where no fixed position describes the object -- `createObject`'s
  choice, `who-Has`'s alternative, the COV-multiple and audit services -- reports
  that it could not be located. With object rules configured, such a request is
  refused: the two ways to get that wrong are to check the wrong field and to let
  it through unchecked.

  The service list applies to the building's direction too, because it is a
  statement about which services cross this listener rather than about which a
  client may send: a device -- or something on the plant network wearing a
  device's address -- broadcasting a `timeSynchronization` at a client network
  sets the clock on every host that listens. The object and property rules are
  deliberately *not* applied backwards, since they are written about the objects a
  client may reach and applying them to the reply direction would refuse every
  `i-Am`.

  Invoke identifiers are translated per client, the way a BACnet router
  translates them. The standard makes one unique only between a client and a
  device, so two clients using identifier 1 towards the same controller through
  one relay socket would get each other's answers.

  Refusals are `bacnet_denied` deny events, so bans apply. The bounds that are
  never shadowed are `command_priority_too_high`, `whois_unbounded`,
  `whois_range_too_wide` and `rate_limited`.

  A segmented exchange is translated in both directions and a segment renews the
  exchange's deadline, because the client's acknowledgements name the identifier
  the client chose and a deadline measured from the request would expire in the
  middle of a long trend log download.

  Four defects the tests and a review found. Fuzzing the parsers for twenty million executions
  found that a four-octet property identifier decodes to a number and only some of
  those numbers are property identifiers -- a value past the twenty-two bits
  clause 21 gives one is now refused where it is read rather than reported as a
  request about a property no device could have meant. And the end-to-end test for
  shadow mode found an *ordering* defect in the policy: the command priority bound
  was hidden behind the service refusal found first, so a listener in monitor mode
  carried a write at a life safety command slot. `Decide` now matches the rule,
  then checks the bounds, then the policy choices. Reading the relay back found
  two more: a client's segment acknowledgement was forwarded with the client's own
  invoke identifier, so every segmented reply stalled after its first window, and
  an unconfirmed request arriving *from* the building was fanned out to clients
  without the service list applied to it. The listener's two goroutines use
  `internal/acceptgroup` rather than a bare `sync.WaitGroup`, so a shutdown that
  arrives at the moment it starts waits for them instead of racing the Add.

- **`kind: redis`: a Redis and Valkey relay, on the protocol where reachable means
  administrable.** `internal/respwire` reads the framing and holds the command
  table; `internal/kinds/redis` holds the policy.

  This is the protocol where a relay earns its place fastest, and the reason is
  Redis's own default: **no password**. An instance with `requirepass` unset accepts
  every command from anybody who can reach the port. And the distance from an
  administrative command to remote code execution is three of them --
  `CONFIG SET dir`, `CONFIG SET dbfilename`, `SAVE` -- which writes a file of the
  attacker's choosing wherever the server can write. Pointed at a cron directory or
  an `authorized_keys`, that is a shell, and it is how internet-exposed instances
  have been taken over for a decade.

  It is also the protocol that gives a relay the least to work with. A command is an
  array of opaque byte strings: no schema, no statement grammar, nothing to classify
  by shape the way the three SQL kinds classify a statement. So the policy is four
  decisions in order, and each one is there because the one before it is not enough.

  **Authentication first**, and taken from the *server's* reply rather than from the
  relay having seen an `AUTH`. A relay that trusted the attempt would treat a wrong
  password as a login, which is the whole of what the setting exists to prevent, so
  `fromServer` reads one bit -- the type marker of the reply that follows a
  credential -- and deliberately no more, because parsing the server's whole reply
  stream would mean a second protocol reader whose disagreements with the first are
  the interesting bugs. What a client may legitimately send before authenticating is
  named rather than guessed (`AUTH`, `HELLO`, `PING`, `QUIT`, `RESET`, `COMMAND`),
  because the alternative -- letting everything through until an `+OK` arrives -- is
  a window an attacker fills with one command.

  **Then the command name**, as an allow list defaulting to what an application does
  to a cache. The absences are the value: `MODULE LOAD`, the whole Lua family, the
  replication commands that replace the dataset from a server you choose, `MIGRATE`,
  `FLUSHALL`, `SHUTDOWN`, `MONITOR` -- which streams every command every client
  sends, arguments included, and so is every value written to the database -- and
  `KEYS`, which belongs in that list on different grounds and they are worth
  separating. `KEYS` is not an escape. It is O(n) **on the single thread that serves
  every client**, so one `KEYS *` on a large instance stops the estate for as long as
  it takes, which means a monitor-mode listener that forwarded one would cause the
  outage it was installed to prevent and the shadow report would record that it had
  noticed. That is why it is refused even in monitor mode, alongside the commands
  that write files.

  **Then the subcommand**, because `CONFIG GET` is a read and `CONFIG SET` is the
  chain above, so a policy that could only say `CONFIG` would have to refuse both or
  neither. A container command allowed with no subcommand listed allows all of them,
  which is stated rather than implied: for `CONFIG` that means `CONFIG SET`.

  **Then the key prefix**, which is the closest this protocol has to the
  database-and-table boundary the SQL kinds leave to `GRANT` -- and which is only
  safe because the wire package is honest about what it does not know. Keys sit where
  each command's signature puts them, so there are three tables rather than one: 202
  commands with fixed positions (including the interleaved ones, where `MSET` is key,
  value, key, value, and the ones whose last argument is a timeout rather than a key);
  15 that declare their key count in an argument, which is read rather than assumed
  because it is the client's number and it decides which arguments are keys; and 10
  whose positions depend on an option that may or may not be present. That third set
  is the interesting one. `SORT`'s `STORE` adds a key at the end; `XREAD`'s keys
  follow a `STREAMS` token whose position depends on four other options; `MIGRATE`'s
  key is the third argument *unless* `KEYS` is used, in which case the third is an
  empty string and the keys are at the end. Those report that their keys cannot be
  located, so the policy refuses them while a prefix policy is in force and allows
  them where one is not -- because a table entry that guessed would have the policy
  checking a `STORE` option's value or a Lua script's text, and passing exactly what
  it was meant to stop, silently. Leaving them out of the tables altogether would
  have been worse in the other direction: they would be *unknown* commands, which a
  read-only listener refuses outright and a validator would not let an operator name.

  One default on this kind is off where every sibling's is on: `upstream_tls_mode`
  is `disable`. There is nothing in the protocol to discover whether the server
  speaks TLS, so requiring it by default would refuse every upstream in the common
  deployment rather than protect anything. `require_tls` on the client's leg still
  defaults on, and matters as much as anywhere: a Redis `AUTH` sends the password as
  an argument of an ordinary command.

  A test asserts the four command tables agree with each other rather than a comment
  claiming they do -- everything the default allow list or the dangerous set names
  must be nameable in a configuration, nothing may be in both -- and it earned its
  place immediately. It caught four commands that do not exist, which I had written
  into the key table by hand (`PSETNX`, `SETGET` and two invented `_RO` variants),
  and two key positions wrong in the direction that matters: `SINTERCARD`'s fixed
  spec counted its `LIMIT` token as a key, and `ZUNIONSTORE`'s found the destination
  and none of the source keys, so a source outside the allowed prefix would have
  passed.

  Three fuzz targets, and the second is the invariant a relay rests on: what the
  reader keeps as the raw octets, read again, is the same command. It found that the
  bulk header was being recorded twice, so what the relay forwarded was not what it
  had decided about -- the exact failure a protocol relay exists to prevent. It also
  found a command name that was not text and an error reply with no readable error
  kind, both fixed.

- **A race in four kinds' shutdown, and `internal/acceptgroup` to hold the fix.**

  The redis end-to-end test surfaced it and the race detector named it: the accept
  loop's `WaitGroup.Add` against shutdown's `Wait`. `Add` must not run concurrently
  with `Wait` while the counter is at zero, and an accept loop does exactly that,
  because a connection can be accepted at the moment a shutdown begins.

  What goes wrong is worth stating, because it is not a detector warning. The
  session either is or is not waited for depending on the scheduler -- so shutdown
  can return while a session is still reading a connection the process is about to
  close. On a reload that is a session dropped mid-command; on a shutdown it is a log
  line written after the log file was closed.

  The modbus kind already did it correctly, with its own mutex and done channel. That
  pattern is now a package, with the check and the `Add` under one lock and a
  connection accepted after `Close` refused by the accept loop rather than served,
  so the four database kinds share the fix rather than four copies of the bug -- and
  so it is tested once (four goroutines Entering against Close and Wait, two hundred
  times, under `-race`) rather than four times not at all. The remaining kinds have
  the same shape and are a sweep of their own; `vnc` and `rdp` are confirmed by
  reading.

- **`kind: tds`: a SQL Server relay, on the protocol where the password is not
  encrypted and the statement is not a statement.** `internal/tdswire` reads the
  framing and the three protocols a TDS connection speaks in sequence;
  `internal/kinds/tds` holds the policy; `internal/sqlkind` with the T-SQL dialect
  classifies the statements.

  **The PRELOGIN encryption negotiation is the third cleartext downgrade in a row
  and gets the same answer.** One octet in an option table, answered by the
  server, signed by nothing -- and `off` ("I would rather not", which a great deal
  of deployed software sends) has the same wire consequence as `not_supported` ("I
  cannot", which is what something on the path rewrites the server's answer to),
  so a client that asked for the first and heard the second carries on in the
  clear without complaint. As on the postgres and mysql kinds, the relay
  negotiates with each leg itself rather than forwarding what it read: with
  `require_tls` on it answers every client `required`, so every client becomes one
  the downgrade cannot touch, and it asks the server for encryption on its own
  account regardless of what the client wanted. What matters more here than on the
  other two is why: a TDS password is XOR 0xa5 with the nibbles swapped, an
  encoding with no key, so a login that crossed in the clear has disclosed a
  reusable credential to anybody who read it. There is no `allow_weak_auth` on
  this kind because there is no stronger method to contrast one with; the one
  credential setting is `allow_cleartext_password`, named for exactly what it
  permits. `Deobfuscate` exists in the wire package so that claim is demonstrated
  by a round-trip test rather than asserted in a comment, and the relay
  deliberately never calls it: reversing the encoding would put a plaintext
  password in the relay's memory, one careless log line from disk, in exchange for
  nothing -- the only question the relay has is whether one crossed.

  Every connection whose negotiation the relay raised is logged as
  `tds_encryption_forced`, an `alert` rather than a refusal because nothing was
  denied. That list is the point: each entry is a client that would have gone in
  the clear, and one that will fail if it turns out not to speak TLS at all, so it
  is what an operator reads *before* turning the setting on rather than after.

  **The dangerous operations are procedures.** Not statements, and not one-octet
  commands as on MySQL. `xp_cmdshell` is a shell command running as the service
  account; the `sp_OA` family instantiates arbitrary COM objects, which is the
  same thing with more steps; the registry procedures are the host's
  configuration; `sp_addlinkedserver` turns one compromised database into a route
  to another; `sp_configure` is how `xp_cmdshell` gets turned back on after
  somebody disabled it. To a statement classifier every one of those is an
  `EXECUTE`, and a statement policy strict enough to catch them would refuse every
  stored procedure in the estate. So procedures get their own allow list --
  inverted the same way the statement classifier is, defaulting to what a client
  library calls rather than listing what somebody remembered to forbid -- and a
  procedure nobody thought of is refused. Refusing one of the set that leads out
  of the database is never shadowed, on the reasoning the mysql kind applies to
  replication: forwarding a shell command and writing down that it was noticed is
  not a trial of a policy. A procedure merely *off* the allow list is a soft
  refusal, because that one is most likely an application nobody has listed yet,
  and finding those is what monitor mode is for. An operator who names one of the
  hard set in `allow_procedures` has said so and is not overruled.

  **The statement an application runs is not a statement, so the policy had to
  reach into an RPC.** Every client library that uses parameters -- ADO.NET, JDBC,
  ODBC, pyodbc, go-mssqldb -- sends `sp_executesql` with the SQL as a parameter, so
  a relay that classified only `SQLBATCH` would be inspecting the `SET` statements
  a driver emits on connect and nothing an application ever runs. The wire package
  reads that one parameter and the same statement policy applies to it as to a
  batch, which the end-to-end test asserts by refusing the same `DELETE` both
  ways. The line is drawn precisely: the *other* parameters are the caller's data,
  and a relay that held them would be holding the contents of somebody's database
  and would eventually put one in a log line, so they are measured to be stepped
  over and never decoded. Which parameter carries the statement comes from the six
  documented signatures in MS-TDS rather than from "the first string-shaped
  argument" -- `sp_prepare`'s is third, behind an output handle and a parameter
  declaration, and `sp_cursorprepexec`'s is fourth. `sp_prepexecrpc` is
  deliberately absent from that table and from the default allow list: its string
  argument is an RPC call rather than a batch, so classifying it as T-SQL would
  name it `unknown` and refuse every use of the procedure, and allowing it is a
  decision worth making knowingly rather than a default that inspects nothing.

  **And the TLS handshake happens inside TDS packets, and then stops.** For the
  length of the handshake TDS wraps TLS -- the records are carried as the payload
  of PRELOGIN-type packets -- and once it finishes the encapsulation stops and TLS
  wraps TDS for the rest of the connection. The nesting inverts, once, part way
  through a connection, and where exactly is the hard part. The design assumes the
  handshake ends at a point both peers agree on, which was true when it was
  written: in TLS 1.2 everything including the session ticket precedes Finished.
  TLS 1.3 moved the ticket to *after* the handshake, so a peer whose handshake has
  completed may still have encapsulated octets coming -- and a peer that flipped to
  reading raw records there reads a TDS header as a record header, which hangs the
  connection and looks like a certificate problem. So writes flip when this side's
  handshake finishes and reads pass through a window in which either framing is
  accepted. That is not a guess about which arrived: the tag spaces are disjoint,
  an encapsulated packet beginning `0x12` and a TLS record beginning with a content
  type, 20 to 25, so the first octet says which framing it belongs to and anything
  else is refused rather than interpreted.

  Six fuzz targets found five bugs in the wire package, all fixed before the kind
  was written. A PRELOGIN option table could carry the same token twice, so the
  relay and the server could read different values depending on which one a reader
  keeps -- and on the ENCRYPTION option that is the entire negotiation. A nameless
  RPC, and a NUL inside a procedure name, were both accepted. `Procedure()` clipped
  a name before lower-casing it, and lower-casing can *lengthen* UTF-8 (U+0130
  becomes two runes), so a bounded name came back past its bound. And `Clip` cut at
  an octet boundary, so a multi-byte character could be sliced in half: the result
  is invalid UTF-8 that a JSON log writer rewrites, a terminal draws as a
  replacement character, and a comparison against a policy's spelling stops
  matching. Cutting one character short is the harmless failure; cutting into a
  character is not. That last one had been copied into four packages, so it is
  fixed in four, each with a test that a 3-octet-per-rune string clipped at a bound
  that is not a multiple of 3 comes back valid UTF-8.

  Two more the end-to-end tests found. The TLS tunnel held one mutex across its
  underlying read, so a write deadlocked behind a read that was waiting for the
  peer -- which appears only once both directions are live, so after the handshake
  and after every test of the handshake had passed; the state is atomic now and
  nothing is held across the read. And `internal/sqlkind` classified T-SQL's `EXEC`
  as `execute`, the prepared-statement kind. That is right for PostgreSQL, where
  `EXECUTE` runs a prepared statement whose text was classified at `PREPARE` time,
  and wrong here: T-SQL has no prepared-statement syntax at all -- that is
  `sp_prepare` and `sp_execute`, which are RPCs -- so `EXEC` runs a stored
  procedure, which can do anything the login can. `read_only` was decorative on the
  dialect where it matters most: `EXEC dbo.DeleteEverything` read as a read.

  One more thing the validator now says out loud: a user list and integrated
  security cannot both be in force, because an SSPI login carries no user name for
  a list to match. Naming `allow_users` or `deny_users` therefore turns integrated
  logins off unless `allow_integrated` says otherwise. The alternative was a user
  policy with a hole exactly the shape of Windows authentication, which said so
  nowhere.

  Refusals are `tds_denied` for the ban triggers.
  `examples/databases/tds.yaml` has an application front, a reporting front where
  a schedule confines the nightly extract to its window, and a shadow-mode trial;
  docs/CONFIG.md `tds`, and docs/TROUBLESHOOTING.md.

- **`kind: mysql`: a MySQL and MariaDB relay, on the protocol where the dangerous
  things are commands.** PostgreSQL's hazards are all statements, so a statement
  policy reaches them all. MySQL's are commands -- one octet each, with no SQL
  involved -- and that is the fact everything else follows from.

  `COM_SHUTDOWN` is one octet and stops the server. `COM_BINLOG_DUMP`,
  `COM_BINLOG_DUMP_GTID` and `COM_REGISTER_SLAVE` open a stream of every change
  to every database. `COM_TABLE_DUMP` is a whole table in one command.
  `COM_PROCESS_KILL` ends somebody else's query. `COM_DEBUG` writes the server's
  internals to its error log. `COM_CREATE_DB` and `COM_DROP_DB` predate the DDL
  statements and bypass a statement policy entirely. **A relay that only
  classified SQL would never see one of them**, so this kind has an
  `allow_commands` list that the postgres kind has no equivalent of, defaulting
  to the fourteen an application driver sends and nothing administrative. The
  replication commands are refused *hard*, so shadow mode does not carry them
  either.

  Two commands are subtler, and are why a capability policy on its own is not
  enough. **`COM_CHANGE_USER` re-authenticates a live connection** as somebody
  else, so a relay that did not read it would have a user and database policy
  that applied to the first message of a connection and nothing after it; the
  identity is re-checked and the refusal is hard, because the alternative is a
  connection that *is* somebody the policy refused while the relay writes down
  that it noticed. And **`COM_SET_OPTION` turns `CLIENT_MULTI_STATEMENTS` on
  after the handshake is over** -- a policy a client lifts with one command
  unless the relay reads the two-octet payload and refuses it.

  **The relay rewrites the server's greeting.** MySQL's handshake runs the
  opposite way round from PostgreSQL's: the server speaks first and advertises
  its capabilities. So the relay reads the greeting, clears the bits
  `deny_capabilities` names, and forwards the edited one -- a client that never
  sees `CLIENT_LOCAL_FILES` offered cannot negotiate it, so the server can never
  ask that client to open a path and send its contents, **and the application
  still works**. That is rewrite rather than refuse, the same choice the tftp
  kind makes with RFC 7440's window, and for the same reason: a control that
  breaks every application on a segment is a control somebody switches off. The
  default strips `local_files`, `multi_statements` and `compress`. `ssl` cannot
  be named at all, because stripping it would perform the downgrade the kind
  exists to prevent -- and validation refuses a configuration that tries. The
  strip is logged as an `alert` rather than a refusal, since nothing is denied.

  The encryption negotiation is a capability flag, which is PostgreSQL's
  SSLRequest problem with a different encoding: nothing signs the greeting, so
  anything on the path clears `CLIENT_SSL` from the advertised capabilities and
  the client never asks. `require_tls` is on by default and both legs are
  upgraded independently. `mysql_clear_password` is refused on an unencrypted
  connection even where the plugin is allowed, because that is the password on
  the wire. `mysql_native_password` is deliberately **not** counted weak: its
  challenge-response discloses no reusable secret, and treating it as weak would
  make the setting one operators turn off wholesale.

  `LOAD DATA` is classified as a bulk-data statement with `local` as a target of
  its own, and both forms are off by default -- bulk loading is a job, not
  something an application connection does by accident. The `local` refusal is
  hard, on the statement and on the server's request alike, because forwarding
  either means the client's file has already left.

  The framing has two traps, and both have tests. A payload of exactly `0xffffff`
  means "more follows", so a message whose length is an exact multiple of that
  ends with an **empty** packet: a reader that stopped on "length zero" would end
  the message one packet early. And the sequence number is checked strictly
  *within* a continuation chain, because mis-reassembling would build a message
  neither peer sent, and deliberately **not** between messages, because a relay
  originates packets of its own and so desynchronises exactly when it is doing
  its job -- while the server enforces the numbering anyway, so a relay that also
  checked would add a failure mode without adding a defence.

  Three bugs the tests found. `MaxPayload` (16 MiB) exceeded `MaxMessage`
  (1 MiB), so *any* continuation chain was refused: the protocol ceiling and the
  policy default had been conflated into one constant. The relay's own upstream
  reader enforced the cross-message sequence it had just desynchronised by
  forwarding a login. And "is the authentication exchange over" was a guess at a
  sequence number being large enough, which meant a command sent early was
  forwarded unchecked -- it is taken from the server's OK packet now, which is
  the protocol's own signal.

  Refusals are `mysql_denied` for the ban triggers.
  `examples/databases/mysql.yaml` has an application front, a replication front
  where a rule lets exactly one account from exactly one address stream the
  binary log, and a shadow-mode trial; docs/CONFIG.md `mysql`, and
  docs/TROUBLESHOOTING.md.

- **The SQL statement classifier became dialect-aware** (`internal/sqlkind`,
  where it moved from `internal/pgwire`), because MySQL and TDS need the same
  vocabulary with different lexical rules and two copies of the lexer would
  drift. The differences are not cosmetic; each decides whether a keyword is
  visible to the classifier at all. **MySQL has executable comments**:
  `/*! DROP TABLE t */` and `/*!50000 DROP TABLE t */` are *code*, which the
  server runs when the version matches, and they are the single most effective
  place to hide a keyword from a reader that skips comments -- so they are
  unwrapped and lexed as the statement they are, semicolon included. PostgreSQL
  nests block comments and MySQL does not, so `/* /* */` is a complete comment in
  one and unterminated in the other. MySQL honours backslash escapes in string
  literals and PostgreSQL has not since 9.1, so `SELECT 'a\'; DROP TABLE t'` is
  one statement in one dialect and two in the other. The keyword tables are split
  per dialect rather than merged, which is the correctness point rather than
  tidiness: `FLUSH PRIVILEGES` is a MySQL statement and a PostgreSQL syntax
  error, so one shared table would make the PostgreSQL relay classify it as an
  ordinary maintenance statement instead of `unknown`, and merging would make
  each dialect's relay less strict by exactly the other's vocabulary.

- **`kind: postgres`: a PostgreSQL relay that is deliberately not a SQL
  firewall.** Knowing which tables a statement touches means parsing SQL
  properly -- every alias, subquery, CTE, view, function body and `search_path`
  interaction -- and a relay that got that 95% right would have a policy with a
  hole in exactly the place somebody is looking. Restricting a role's tables
  stays the database's own job, done properly, with `GRANT`. What this does
  instead is the four things a relay can do that the database either cannot or
  reliably has not.

  **It refuses the encryption downgrade, which is the whole reason to put a
  relay in front of this protocol.** TLS here is negotiated *in cleartext*: the
  client sends eight octets asking, the server answers with one unsigned octet,
  and nothing signs it. libpq's default `sslmode` is `prefer`, which means "ask
  for TLS and carry on in the clear if refused, without telling anybody" -- so
  the default configuration of the most widely deployed client in the world
  downgrades silently when anything on the path rewrites one byte. The relay
  answers that request itself rather than forwarding it, because forwarding
  would mean the server's answer decided; `require_tls` is on by default, and a
  listener that sets it without a certificate is refused at load rather than at
  every handshake. The leg to the server defaults to `require` as well: a relay
  that terminated TLS from the client and then spoke plaintext onward would have
  moved the exposure rather than removed it. MySQL's `CLIENT_SSL` capability
  flag and TDS's PRELOGIN encryption option are the same shape, and will get the
  same answer.

  **It refuses the authentication methods whose credential an observer can
  reuse.** The relay reads the *server's* authentication request, because
  `pg_hba.conf` is what chooses the method, and this is where somebody notices
  that the line which matched says `md5`. `password` is the password in
  cleartext; `md5` is worse than it looks, because the stored verifier is
  `md5(password+username)` -- the hash *is* a password-equivalent, so anybody
  who reads `pg_authid` authenticates without cracking anything. PostgreSQL has
  shipped SCRAM since version 10.

  **It refuses what is not a statement at all.** `replication=true` is a startup
  *parameter*, so no statement policy would ever see it, and it turns the
  connection into a byte-for-byte copy of every database on the server including
  the role passwords. The legacy fast-path function call names a function by
  object identifier and bypasses the parser; nothing written this century sends
  it. A cancel request arrives on a connection of its own and the server acts on
  it with **no authentication whatsoever** -- the whole credential is a backend
  process identifier and a 32-bit secret -- so the relay refuses one from an
  address that is not an admitted client and counts the rest, which is what
  turns a quiet brute force of 32 bits into something somebody sees.

  **It decides by the shape of a statement, not its contents.** An allow list of
  statement *kinds*, where a statement the classifier cannot name is `unknown`
  and refused -- and `unknown` is not a kind a configuration may write. That
  inverts the deny-list problem the TFTP kind ran into: searching a statement
  for `DROP` is beaten by `DR/**/OP`, by a quoted identifier, and by an innocent
  statement that mentions the word in a string literal, whereas an allow list of
  shapes fails *closed* on a spelling nobody thought of. The classifier strips
  comments and quoting properly -- PostgreSQL's block comments nest, unlike the
  SQL standard's; dollar-quoted strings have no escaping at all; and a comment is
  whitespace rather than nothing, so `SEL/**/ECT` does not reassemble -- and it
  is conservative in the one direction that is safe, because when a classifier
  must be wrong it must be wrong towards the more restricted answer: a
  data-modifying CTE is the write it contains rather than the `SELECT` it opens
  with, `EXPLAIN ANALYZE` is the statement it runs because `ANALYZE` executes it,
  and `COPY` carries which of its three operations it is. Text that cannot be
  lexed at all is refused rather than classified, because the relay and the
  server would disagree about where the statement ends, and disagreeing about
  that is how a statement gets past a relay that read a different one.

  `COPY ... FROM PROGRAM` runs a shell command as the server's operating-system
  user. It is nameable by no rule in any mode, and validation refuses a
  configuration that tries: a setting that could switch remote code execution on
  through a relay is one somebody switches on by accident.

  `read_only` includes `call` and `do`, because a procedure and an anonymous
  block can do anything the role can, and a relay that counted them reads would
  have a `read_only` that is decorative.

  Both query protocols are read. Every driver written this century sends
  Parse/Bind/Execute and no Query at all, so a relay that inspected only Query
  would be inspecting nothing -- and a Bind is decided again for the prepared
  statement it names, which is what catches a pooled connection in transaction
  mode executing a statement another application left behind. The startup packet
  is forwarded as the octets the client sent, because re-encoding it would mean
  deciding about one message and forwarding another. A statement sent before the
  server has said AuthenticationOk is refused: there is no legitimate one.

  The log carries the statement kind and never the statement text. A `WHERE`
  clause names the row and an `INSERT` carries the value, and a security log is
  read by more people than the database is. The one exception is the leading
  keyword of a statement the classifier could not read, because "something
  unreadable was refused" with no hint of what is a line nobody can act on --
  and it goes through `textsafe`, since a verb off the network can carry an
  escape sequence.

  Refusals are `postgres_denied` for the ban triggers, with the fine-grained
  reason in the security log. Shadow mode never shadows: the client list, the
  TLS requirement, the authentication methods, a replication connection, a
  statement the classifier could not read, `COPY ... FROM PROGRAM`, the
  fast-path call, or a bound. `examples/databases/postgres.yaml`;
  docs/CONFIG.md `postgres`, docs/USAGE.md and docs/TROUBLESHOOTING.md.

- **A device inventory built from traffic rather than from scanning
  (`asset_inventory`).** An operational estate's oldest problem is that nobody
  knows what is on the network: the drawings are from commissioning, the
  spreadsheet was abandoned two engineers ago, and the one thing nobody may do
  is run a scanner -- an active scan is how a programmable controller gets
  knocked over, and on a safety network it is a thing people lose their jobs
  for. A security proxy is an unusually good place to solve that, because it
  already parses the protocols.

  **Six listener kinds contribute what they can honestly see.** `dhcp` the
  lease, which is the one message where a device states its own hardware
  address, vendor class, user class, client identifier, host name and boot file
  together; `modbus` unit identifiers and function codes, bounded at 64 of each,
  and whether the peer asked or answered; `iec104` common addresses, the same
  shape over a different protocol; `snmp` the object identifiers a manager asks
  for and an agent serves -- **not** their values, because the SNMP parser keeps
  no varbind values by design and changing a hot security parser to carry a
  string the device chose anyway would be a poor trade; `mqtt` the client
  identifier on CONNECT; `tftp` the filename and direction of a transfer, which
  on a boot segment is often the only thing that names a device at all. Every
  other kind contributes nothing, and an inventory on a daemon that runs none of
  the six is empty rather than broken.

  **Behaviour outweighs self-description.** A vendor class, a host name and an
  SNMP description are strings a device chose, and a hardware address is three
  bytes of vendor prefix anybody can set. What a device *does* -- answering
  Modbus function 3 on unit 1, carrying IEC 104 interrogations, asking for a
  firmware image -- is much harder to fake without becoming the thing it is
  pretending to be, so the rules that fire on behaviour carry more confidence
  than the rules that fire on a string. Every classification keeps a confidence
  from 0 to 100 and its evidence, strongest first: an inventory that reports
  "PLC" with no confidence and no evidence is one an engineer cannot argue with,
  and being unable to argue with it is how a wrong entry survives for years. Two
  rules of equal weight that disagree produce an ambiguous verdict with ten
  points off rather than a silent winner, and an asset no rule matches is
  `unknown` rather than the nearest thing. Each of the eighteen roles carries its
  Purdue level, so a segmentation review can ask the question it actually asks:
  what is on this wire that does not belong at this level.

  **What changes is the finding.** A steady-state inventory is a reference
  document; the security value is in the deltas, and each is a security event
  with action `alert` rather than `deny`, because the inventory refuses nothing
  and an operator filtering the log for what the proxy blocked must not find
  entries that blocked nothing: `asset_address_taken` (an address that now
  belongs to a different hardware address -- a device swapped out, or something
  standing in for one that is switched off), `asset_role_changed` (a controller
  that started behaving like an engineering station, which is the single most
  interesting line an inventory can produce), `asset_vendor_changed`,
  `asset_address_changed` and, once a baseline exists, `asset_new_asset`.

  **One record per device, split where splitting is right.** The merge is by
  hardware address first -- the identity that survives a lease -- then by
  address, and a record with no hardware address merges when one arrives. The
  case that deliberately does not merge is a hardware address nobody has seen at
  an address another record already holds *with a hardware address of its own*:
  that is two machines sharing one address over time, and one entry describing
  both would overwrite the older machine's vendor, role and history with the
  newer machine's, which is exactly the history an incident needs. The finding
  goes on the record that *lost* the address, because the new device gets a
  record of its own and the old one would otherwise simply stop appearing --
  and "stopped appearing" is not a finding anybody reads.

  **The bound evicts rather than refusing,** which is the opposite of every
  other bounded table in the proxy and is deliberate: in the relay kinds'
  pairing tables forgetting an entry makes a decision wrong, so a full table
  refuses; here forgetting loses *history*, and refusing would stop the
  inventory noticing the estate at the moment something is filling it up. The
  count of what went is exported.

  **Three stages of use.** Read it (`xproxyctl assets`, or `-long` for the
  evidence). Freeze it (`xproxyctl assets baseline`), after which everything
  that appears is a new device -- the line that turns a reference document into
  a detection, so freezing and forgetting are both audited with the caller's
  kernel-reported credentials, like a ban. Then say what belongs
  (`asset_inventory.roles`), which is the written-down form of "there are no
  engineering workstations on the process network" and is checked on every
  observation rather than once at first sighting, because a device that keeps
  behaving like something it should not be is a thing that keeps happening.

  `GET /v1/assets` with `role`, `listener`, `proto`, `vendor`, `new`, `changed`
  and `top` filters, or `id` to look a device up by identifier, address or
  hardware address -- whichever the log line in front of the operator carried. A
  role that is not a role is refused rather than matching nothing, since an empty
  list reads as "the estate is clean" and that is the wrong answer to a typo, and
  a list cut by `top` reports how many matched. `xproxy_assets`,
  `xproxy_assets_new`, `xproxy_assets_by_role{role}`,
  `xproxy_asset_unexpected_role_total` and six more, absent rather than zero
  when there is no inventory. `state_file` is what stops a restart reporting the
  whole estate as new; a state file that will not read is a warning and the proxy
  still starts, because an inventory is a record and refusing to carry traffic
  over one would make the record more important than the traffic, while a
  malformed `vendor_file` line refuses to start, because that is configuration an
  operator trusted and a list that silently dropped half its entries is worse
  than one that would not load.

  Off by default, everywhere. An inventory is a record of somebody's estate, and
  a proxy that kept one without being told to would be making a decision about
  their data for them. Nothing in it probes, scans or connects to anything.
  `examples/ot/inventory.yaml`; docs/CONFIG.md `asset_inventory`, docs/USAGE.md
  and docs/TROUBLESHOOTING.md.

- **`kind: dhcp`: a DHCP relay agent that reads what it relays, because on this
  protocol answering is the attack.** A client broadcasts "who will configure me"
  and believes whatever answers first: its address, its **default route**, its
  **resolvers**, its **proxy** (option 252) and, on a machine that boots from the
  network, the **file it boots** (options 66 and 67). Nothing in the exchange
  authenticates anybody -- a transaction identifier and a hardware address, both
  visible to everyone on the segment -- and the client has no address yet, so it
  cannot even be told apart by one. This is the one relay kind here whose
  interesting half faces *upstream*.

  **A reply from an address the listener does not admit as a server is dropped
  before it is read.** Every switch vendor sells this as DHCP snooping and
  implements it as a trusted port; here it is `allow_servers`, and it is not
  shadowable, because a listener that evaluated the list without enforcing it
  would relay a rogue server's answer and write it down. An empty list is not an
  open one: it is filled in from the `upstream` pool's endpoints at load, since
  an operator who wrote none meant "the servers I configured" -- and a pool whose
  endpoints are hostnames makes the list required rather than guessed, because
  guessing is the wrong kind of helpful on the one check this kind most depends
  on.

  **The options a server sends are checked as a configuration.** The built-in
  `deny_options` list is what carries one rather than a value: options 121 and
  Microsoft's 249 (a routing table in a broadcast reply), 33, 252 (a proxy), 66
  and 67 (what a machine boots) and 43. The default is `strip` and forward,
  because a client that still gets its address and no longer gets a route it
  should not have is a client that works. `allow_options` turns the policy inside
  out for a segment whose clients need six options.

  **The addresses in a reply are checked against the estate's own** gateways,
  resolvers and boot servers -- a check a *compromised real server* fails as
  surely as a rogue one, and the one place this kind does something no trusted
  port can. The boot server is checked in both places it lives, option 66 and the
  `siaddr` field, because a check on one has a way round it. Classless routes are
  allowed by containment, so `10.0.0.0/8` admits a route to `10.20.0.0/16` and
  refuses a default route, and the refusal names the route.

  **A client does not get to say which segment it is on.** Option 82 arriving
  from a client is stripped as RFC 3046 §2.1 requires, the relay adds its own,
  and §2.2's removal of it from the reply is enforced too.

  **The starvation bound is keyed on the hardware address**, because pool
  exhaustion is one host sending thousands of DISCOVERs with a made-up address in
  each and a limit keyed on the source address would see one sender doing nothing
  unusual. `max_clients` bounds the table doing the keying.

  A lease past `max_lease_time` is shortened rather than refused, so the client
  still boots. `default_action` is **allow** here, unlike the other relay kinds:
  DHCP is infrastructure, a listener that refused everything until somebody wrote
  a rule would stop an estate booting, and the protections above do not depend on
  a rule existing. The listener takes no `tls` section and binds no TCP port.

  Counters are `dhcp_messages`, `dhcp_discovers`, `dhcp_requests`,
  `dhcp_replies`, `dhcp_leases`, `dhcp_releases`, `dhcp_denied`,
  `dhcp_would_deny`, `dhcp_rogue`, `dhcp_stripped`, `dhcp_malformed`,
  `dhcp_rejected`, `dhcp_rate_limited`, `dhcp_timed_out`,
  `dhcp_upstream_failed`, `dhcp_unsolicited`, `dhcp_pending` and `dhcp_clients`;
  `dhcp_rogue` is the one to alert on. The wire format is `internal/dhcp` with a
  fuzz target on the reader, and `examples/addressing/dhcp.yaml` is five
  listeners: an office segment, a build segment where the PXE rule is what allows
  the boot options, a guest segment written as a positive list, a front for two
  downstream relay agents where classless routes are allowed by containment, and
  a shadow-mode trial.

  **DHCPv6 (RFC 8415) is not implemented and is not claimed to be.** It is a
  different packet format with a different relay mechanism, and reading it as if
  it were DHCPv4 would be worse than not reading it.

  Four things found while writing it. The fuzzer found a message type of **zero**
  -- option 53 present, one octet, and a value no standard defines -- accepted by
  the reader; it is the absent value wearing a length, and a relay cannot decide
  about a message whose type the two ends may read differently. A rule's positive
  lists had no effect on the listener's deny list, so "the build segment may be
  told a boot server and nothing else may" could not be written at all: naming
  what an option may contain is now how a rule allows the option, which is the
  same turn the LDAP attribute policy makes. A stripped option that was a finding
  was logged and not counted, so the number an operator would alert on did not
  exist. And the pending gauge was only republished when a message arrived, so on
  a quiet segment it sat at whatever the last busy moment said -- which is
  exactly when somebody is looking at it.

- **`kind: tftp`: a TFTP relay, so the protocol under provisioning can be put
  behind something that reads a filename as a path.** TFTP moves firmware onto
  switches, boot images to machines that have no operating system yet and
  configurations to telephones, and it has **no authentication of any kind**:
  no user, no password, no token, no transport security, and no extension that
  adds one. A request is a filename and a mode, and a server that receives one
  answers it. The clients are switches and boot ROMs, so the relay is the only
  place a policy can live -- and there are exactly four things it can be
  about.

  **The filename is read as a path and refused by class.** A deny list of
  *strings* is a list of the spellings somebody thought of: it stops
  `../../etc/shadow` and not `..\..\etc\shadow`, stops that one and not
  `/etc/shadow`, stops that one and not `secret.txt.`, which Windows opens as
  `secret.txt`. Each of those has been the bug somewhere. So the name is
  classified -- traversal, absolute, drive or UNC, backslash, trailing dot or
  space, non-ASCII, NUL, control, empty -- and the class is refused.
  `allow_path_classes` names the ones a listener accepts, a rule's own list
  widens it for that rule's traffic only, and three of them can never be
  allowed at all: a NUL, a control character and an empty name each mean this
  relay and the server are reading *different* filenames, so they are refused
  in `policy: {mode: shadow}` too. A decision about a name the server will not
  see is not a decision. The traversal check runs over **both** separators and
  before the backslash class, because an estate serving Windows hosts may well
  allow backslashes and `..\..\etc\shadow` is not made safe by that.

  **A write is a separate decision from a read, and `operations` defaults to
  `[read]`.** A write is a device putting a file onto the server, which is how
  a configuration leaves an estate and how firmware arrives in it.

  **The amplification is bounded by rewriting rather than by refusing.** A
  twenty-octet read request yields a whole file to whatever address the
  datagram claimed to come from, and RFC 7440's `windowsize` multiplies it: a
  window of sixty-four is sixty-four data packets per acknowledgement. A
  request past `max_block_size` or `max_window_size` is rewritten to the bound
  and forwarded, because a switch whose TFTP client nobody can reconfigure is
  the normal case and a bound that only refuses is a bound somebody turns off;
  `tftp_lowered` counts it. Two things cannot be lowered and are refused
  instead: a `tsize` on a write declaring more than `max_transfer_bytes`, since
  the client has said in advance how much it intends to send, and a server that
  acknowledges a *larger* block or window than it was offered, since the two
  ends would then disagree about how much is coming.

  **A transfer speaks to exactly two addresses.** The protocol moves to an
  ephemeral port pair after the first packet, so each transfer gets a socket of
  its own and only the client's transfer identifier and the first port the
  server answered from may use it. A datagram from anywhere else is dropped and
  counted rather than answered: RFC 1350 §4 says to reply with error 5, and
  replying is how a relay becomes a reflector. On a protocol with no integrity
  protection that third address is the whole attack, because a packet injected
  into a firmware transfer *is* firmware.

  The listener takes no `tls` section and binds no TCP port, and validation
  refuses both: the protocol has no transport security and no extension that
  adds one, so a listener carrying a certificate would be promising something
  it cannot do. Counters are `tftp_requests`, `tftp_transfers`,
  `tftp_transfers_open`, `tftp_reads`, `tftp_writes`, `tftp_bytes_in`,
  `tftp_bytes_out`, `tftp_denied`, `tftp_would_deny`, `tftp_path_refused`,
  `tftp_lowered`, `tftp_oversize`, `tftp_malformed`, `tftp_rejected`,
  `tftp_rate_limited`, `tftp_timed_out`, `tftp_upstream_failed` and
  `tftp_unsolicited`; refusals are `tftp_denied` for the ban triggers. The wire
  format is `internal/tftp` with fuzz targets on the reader and the classifier,
  and `examples/provisioning/tftp.yaml` is a full deployment: a read-only
  provisioning front, a write listener on its own address with a firmware
  window as a `schedule`, a UDP health check that probes with a read request
  for a file that is not there, and a shadow-mode trial.

  Two bugs the tests found while it was being written. A rule's
  `allow_path_classes` could never take effect, because the listener's list was
  consulted before any rule was read; the soft half of that check now runs
  after the rules. And a transfer ran at whatever block size the *request*
  asked for, so a server that acknowledged no options -- and therefore sent
  512-octet blocks -- had its first block read as its last, ending every such
  transfer one packet in.

- **`kind: ldap`: an LDAP and LDAPS relay, so a directory can be put behind
  something that refuses a bind with an empty password.** A directory is the
  one service in an estate that knows who everybody is, and LDAP is how
  everything asks -- which makes it two things at once: the authentication
  path for every application that has not moved to OIDC, and the most
  complete map of an organisation that exists anywhere on its network.

  Two defaults of the protocol are the reason this kind exists.

  **A simple bind with a name and an empty password is an anonymous bind**
  (RFC 4513 §5.1.2), and a great many directories answer it with *success*.
  A great many applications are written as "bind as the user, and if it
  worked the password was right" -- so that application is bypassed with an
  empty string, and the directory cannot tell that login from a correct one.
  The relay can: `methods` defaults to `[simple, sasl]`, the two that
  actually authenticate, and naming `unauthenticated` is an operator saying
  they mean it, with a validation warning that says what it means.

  **A simple bind on port 389 puts a directory password in the clear on the
  wire**, and the client library that did it does not mention it.
  `require_tls` is on by default, and it is the one refusal on this protocol
  that **holds even in shadow mode**: by the time a policy could be
  consulted the password has already travelled, so a listener that
  "evaluates and does not enforce" would be a listener that leaked a
  credential. SASL `PLAIN` counts, because it is a simple bind with extra
  steps.

  The policy is written in LDAP's own terms: who bound and how, which naming
  context and subtree a request may name, which operation and access class,
  which scope, and which attributes. Two of those are unusual enough to name.

  **Subtrees are compared one relative name at a time.** A string suffix test
  admits `dc=notexample,dc=com` under `example,dc=com` and a prefix test
  admits `ou=peoplex` under `ou=people`; distinguished names are a tree and
  are compared as one, with RFC 4514's escaping resolved, the quoted form
  understood, the attribute type folded and the insignificant space removed.
  Full normalisation would need the estate's schema, so the value is folded
  to lower case -- a deliberate choice on the safe side: a *deny* cannot be
  evaded with a capital letter, and an *allow* may admit a name the directory
  itself then says does not exist.

  **The attribute policy applies to the answer, not only to the question.** A
  search that asks for `*` never names `userPassword` and the directory sends
  it anyway, so a denied attribute is **removed from the entry on its way
  back** -- which is the half a request-side access list cannot do -- and the
  entry is re-encoded without it while its name, its other attributes and the
  search's completion survive. A request that names one *plainly* is refused
  instead, because stripping it would answer a plain question with a silence
  the client cannot distinguish from an empty directory. And a *filter* that
  tests one is refused, because `(userPassword=a*)` is a password oracle one
  character at a time. The built-in list is the password and key material of
  the directories people actually run, from OpenLDAP's `userPassword` to
  Active Directory's `unicodePwd` and LAPS's `ms-Mcs-AdmPwd`.

  **The identity is the directory's to grant.** The relay watches the bind
  *response*, not the request, and adopts the name only when the directory
  answers success -- believing the request would let anyone be anybody by
  binding with the wrong password. So `bind_dns` on a rule means what it
  says: "this service account, from this network, may read this subtree". An
  empty name in that list is the unbound connection, which is how "before you
  authenticate, you may bind and nothing else" is written. A StartTLS upgrade
  discards the identity, as RFC 4513 §5.1.7 requires and because keeping it
  would let a client bind in the clear and then hide behind TLS with what
  that bind gave it.

  **This protocol's amplification is a search.** An unbounded subtree search
  with `(objectClass=*)` is how a directory is copied, so the entries are
  counted per *search* -- not per page, because a client that pages through a
  directory has still copied it -- and the search is **cut** with the
  directory's own `sizeLimitExceeded` rather than refused: the client knows it
  got part of an answer instead of hanging. The filter is bounded too, in
  depth, in term count and in leading wildcards, because a filter is the one
  part of a request whose size the client chooses and whose cost the
  directory pays: a hundred substring terms with leading wildcards is a
  hundred full scans from two hundred octets.

  **StartTLS is terminated here** rather than forwarded, which is what makes
  it a secure upgrade: a client library that can be pointed at a host and
  nothing else gets TLS on the leg it can be made to use, and
  `upstream_tls_mode` decides the other leg separately. A listener with no
  TLS to offer says so in the protocol's own terms rather than forwarding a
  request whose answer would apply to the wrong half of the connection.

  Binds are counted apart from requests and failures apart from binds,
  because those three numbers are what say whether somebody is working
  through a password list -- and the failure counted is the *directory's* own
  `invalidCredentials`, so a ban trigger fires on what the directory decided
  rather than on what the relay guessed. A password never reaches a log, and
  neither does a filter's assertion values: the filter's shape is logged and
  what it was looking for is not, because a search for a person's name is
  that person's business and a log of every one is a surveillance record the
  estate did not ask for.

  The wire format lives in `internal/ldap`, beside the client the `ldap_auth`
  filter already authenticated with, over one BER codec -- because two
  readings of the same bytes in one binary is the class of bug a relay exists
  to remove. `examples/directory/ldap.yaml`, `docs/RFC.md` for which parts of
  the LDAP documents are read and which deliberately are not.

- **`kind: snmp`: an SNMP relay, so the estate's own equipment can be
  managed through something that refuses a write.** SNMP runs every switch,
  router, printer, uninterruptible supply and building controller there is,
  and versions 1 and 2c authenticate with a **community string**: a
  cleartext password in every datagram, `public` to read and `private` to
  write on anything nobody reconfigured, with no integrity, no replay
  protection and no confidentiality. One datagram reads a device's whole
  configuration; one changes it. Version 3 has a real security model and
  also has `noAuthNoPriv`, which is version 2c with more fields. The
  devices cannot be fixed -- printers and building controllers with
  firmware nobody ships updates for -- so the relay is the only place a
  policy can live.

  The policy is written in the protocol's own terms: the version, the
  community string or the USM user, the security level, the operation, the
  access class (`read`, `write`, `notify`, which outlives a revision that
  adds an operation) and the **object identifier subtree**. Subtrees are
  compared **per sub-identifier**, not per character, because `1.3.6.1.2.1`
  is a string prefix of `1.3.6.1.2.11` and is not its parent: a policy
  written with string prefixes allows a subtree nobody named. `deny_oids`
  is the exception inside an allowed subtree -- all of mib-2 except the ARP
  table -- and `write_oids` replaces the read list for a SetRequest, so one
  rule can allow a wide read and a narrow write. `read_only` is checked
  above every rule and **no rule can override it**, because SNMP has
  exactly one writing operation and a read-only listener a single rule
  could write through is not a read-only listener.

  **The amplification is bounded in two directions, and the interesting
  half is that one bound does not refuse.** A forty-octet GETBULK with a
  repetition count of ten thousand asks for a response of megabytes, sent
  to whatever address the datagram claimed to come from -- the classic SNMP
  reflection attack. A count past `max_repetitions` is **lowered** rather
  than the request refused: a poller asking for more than it should get
  still gets an answer, which is what makes the bound deployable in an
  estate whose pollers nobody can reconfigure, and the amplifier is gone
  either way. On the way back, `max_response_bytes` bounds the size an
  agent that ignores the first bound can still produce, and
  `max_response_ratio` is the one about *reflection* rather than size,
  because a large answer to a large question is a walk and a large answer
  to a tiny question is an amplifier. None of the three is ever shadowed: a
  relay whose amplification bounds were evaluated and not enforced would be
  a working amplifier.

  **Every answer is matched to its question**, by the request identifier,
  which is the only thing in the protocol that pairs them -- and therefore
  the only way to recognise a response nobody asked for. On UDP that is the
  shape of a response-spoofing attack on the manager: an answer to a
  question it did ask, from somewhere else, arriving first. The table that
  does the matching is bounded and **refuses the new request rather than
  forgetting an old one**, because forgetting would make the matching
  unreliable, and that matching is a check rather than a convenience.

  **The version is rewritten downwards, and the two things it will not do
  are the point.** `upgrade_version` rebuilds the envelope around the PDU
  that arrived: a manager authenticates with v3, or over RFC 6353 TLS on
  the stream side, and the relay speaks v2c to a switch whose firmware has
  neither, with an `upstream_community` the manager never learns; the answer
  is rebuilt in the version the question used. Producing v3 is refused **at
  load**, and downgrading a v3 *request* is refused **at the message** --
  both because RFC 3414 authentication needs a key this relay does not hold.
  A relay that produced an unauthenticated v3 message, or handed a v3
  manager the v2c answer its request actually got, would be telling somebody
  their traffic was authenticated when nobody had checked. A v3
  *notification* downgrades cleanly, because nothing comes back: a modern
  device sending v3 traps to a collector that understands only v2c is the
  case worth having, and it is `traps: true` with `upgrade_version: v2c`.

  A refusal is the Response PDU an agent would send -- `noAccess` on v2c
  and v3, `noSuchName` on v1, which is the only word v1 has for it -- so
  every manager already knows how to display it. Dropping the request
  instead is a timeout, and a timeout is what a dead device looks like.

  An `authPriv` payload is **decided about and not inspected, and said to
  be**: the v3 header parses, the user and the level are checked and
  enforced, and the scoped PDU is ciphertext, so there is no operation and
  no object identifier to decide about. The decision says `snmp_encrypted`
  rather than refusing traffic the listener was configured to carry or
  pretending it was inspected. The USM digest is read for its extent and
  never verified, for the same reason: a relay is not given the users'
  keys, and pretending to check would be worse than saying it cannot.

  The values are never interpreted. A binding's type tag and extent are
  read and what a `Counter64` means is not: interpreting them would need a
  MIB per estate, and a relay that mis-decoded one would corrupt a reading
  nobody could trace. Object identifiers need no MIB to compare.

  The listener takes datagrams and streams at once -- UDP 161 is what every
  poller and agent speaks, and RFC 3430's TCP mapping is what RFC 6353's
  TLS runs over on 10161 -- and a community string never appears in a log,
  because a record of guessed ones would be a list of the estate's
  passwords with a timestamp beside each. `examples/ot/snmp.yaml`,
  `docs/RFC.md` for which parts of eighteen SNMP documents are read and
  which are deliberately not.

- **`kind: iec104`: an IEC 60870-5-104 relay, so a substation gateway can be
  put behind something that refuses a breaker trip.** IEC 104 is the protocol
  that operates electricity transmission and distribution, and it is the
  grid's Modbus: plain TCP on port 2404, no authentication, no integrity, no
  session. Anyone who can reach the gateway can open a breaker on it, and the
  gateways are substation equipment with twenty-year service lives.
  IEC 62351-3 wraps it in TLS and is almost nowhere deployed.

  What the protocol *has*, and Modbus does not, is a structure that says what
  a message means -- a **type identification**, a **cause of transmission**,
  an **originator address** and a **common address** in every I frame -- so
  the policy is written about commands rather than about bytes: which stations
  may be addressed, which commands may be sent by whom to which information
  object addresses, on what schedule. `class: [monitoring]` outlives a
  standard revision that adds a type; `types: [C_RP_NA_1]` names the one that
  reboots a station and `C_CS_NA_1` the one that moves its clock, which
  changes the meaning of every timestamp in the historian and of every
  protection function keyed to one. `monitor_only` that no rule can override,
  for a historian or a neighbouring utility's data link.

  **Select-before-operate, enforced.** The standard describes the two-step
  form -- select, then execute -- and the equipment mostly accepts a bare
  execute, so a relay that remembers the selections is the only thing in the
  path that can require both steps. That turns one injected command frame from
  a breaker operation into a refusal. The state is deliberately narrow: a
  selection belongs to the connection that made it, to one common address, one
  point and one type identification; it expires; it authorises one execution;
  a deactivation withdraws it; and it dies with its connection, because one
  that outlived it would let a later client execute on an earlier one's
  intention. `select: select` on one client and `select: execute` on another
  is a four-eyes control in two lines.

  **Both directions are read, because the numbering only makes sense as a
  pair.** The sequence numbers are the only mechanism in this protocol that
  finds a lost, duplicated or replayed frame, and a relay sees both sides: a
  send number that is not the next one, a station with more than *k* frames
  outstanding, and a receive number acknowledging frames nobody sent. A gap is
  *one* refusal -- the state moves to what arrived, because a relay that
  refused for ever after one lost frame would take a substation off the air
  until somebody restarted the link.

  **Three things a policy about ASDUs would have missed.** `STOPDT_act` is a
  U-format control function with no ASDU at all, and it stops data transfer:
  a client that may send it blinds a control room without refusing a single
  command, so the control functions are a policy of their own (and naming an
  activation names its confirmation, or the station's reply would be refused
  and the centre would wait for ever). A *station* sending an activation to
  its own control centre is refused, because that is not a shape the standard
  has and it is what a compromised gateway pivoting upstream looks like. And
  commands are rate limited separately from frames, because a frame limit
  loose enough for periodic telemetry says nothing about a centre sending a
  thousand breaker commands a second.

  Refusals are the standard's own negative confirmation -- the same ASDU
  returned with the negative-confirm bit and cause `actcon` -- so the centre's
  alarm list says something true and the link carries on; a measurement gets
  no answer at all, because the protocol has no confirmation for one and
  inventing it would put an ASDU on the wire no station would ever send.

  The metric payloads are never decoded. Decoding every one of the
  hundred-odd type identifications would be a second implementation of the
  standard, and a relay that got one wrong would corrupt a reading nobody
  could trace; what is read is the ASDU header, the object addresses and a
  command's qualifier. A type the standard does not define is forwarded with
  its addresses *unread* rather than guessed at, because inventing an object
  size would misreport an address and the policy would then decide about the
  wrong point.

  There is deliberately **no per-address routing**, and the reason is the
  protocol's own shape rather than an omission: the first frame a control
  centre sends is `STARTDT_act`, which carries no common address, so a relay
  could not choose a pool from the address until the first I frame -- by which
  time the association is up and the handshake answered. One listener per
  association is the honest shape; `common_addresses` bounds which stations
  may be addressed through it. `examples/ot/iec104.yaml`, `docs/RFC.md` for
  what of the standard is read and what is not.

- **A readiness verdict a failover tool can act on, and `docs/HA.md`.**
  Making a proxy redundant is easy; making it *fail over* means answering
  one question -- what does "unfit to carry traffic" mean? -- and nothing
  in this proxy answered it. `xproxyctl ready` and `GET /v1/ready` do, with
  an exit code (0 carry, 1 do not, **2 the question could not be asked** --
  a check script that confuses the last two moves a shared address because
  a socket became unreadable) and an HTTP status for anything that speaks
  neither. `xproxyctl ready -step-down "kernel update"` takes a node out
  *before* the work starts, so the address moves while the node is still
  healthy and can finish what it has, rather than moving because the node
  died mid-upgrade; `-step-up` puts it back. The two judgement calls are
  opt-in on purpose: whether a pool with no healthy endpoint
  (`-require-upstreams`) or a hardening mechanism that did not apply
  (`-require-undegraded`) should move an address depends on the topology --
  two nodes reaching the same servers over the same network see an upstream
  outage identically, and failing over gains a flap and nothing else. Load
  is never a reason: a node that stands down under load hands its peer the
  same traffic and twice the churn. `docs/HA.md` is the rest: a keepalived
  configuration with the four details that are not obvious, and a table of
  what survives a failover and what does not -- because the three rows that
  say *no* (WAF learning, MFA lockouts, live bastion sessions) are the
  honest cost, and the relay's Modbus and Sparkplug state is the sharpest
  of them, a node promoted cold having seen nothing to compare against.

- **An expired certificate can be a refusal rather than an outage nobody
  can read.** By default this proxy serves an expired certificate, which is
  correct -- the client decides whether to trust it, so serving one is not a
  security hole -- and which means every client discovers the problem
  separately and nobody discovers it in one place. `tls.expiry` says it once:
  `refuse_expired` makes an already expired certificate a *load* error, so a
  botched renewal that wrote an expired file **cannot replace a working
  one** on a reload; `warn` is a window, reported worst first by
  `xproxyctl tls`, `GET /v1/tls/expiring` and the security log at every
  load. A certificate that expires while the proxy runs is never unloaded,
  whatever the section says: a listener that stops answering is worse than
  one answering with a certificate the client rejects for itself, and
  unloading it would turn a late renewal into an outage.

- **MQTT: the bounds belong to the topic, and Sparkplug's commands belong
  to somebody.** Three things about a publication are properties of the
  *topic* rather than of the listener -- how large a payload it may carry,
  which qualities of service it may use, and whether it may be retained --
  and a single bound for a listener has to be the loosest of them, which is
  the same as no bound. `topics[]` gives each set of filters its own:
  `max_payload_bytes`, a `min_qos`/`max_qos` window and `allow_retain`,
  with the listener's `max_payload_bytes` and `max_qos` as the fallback. Of
  those, `min_qos` is the one that is not about the transport: a command
  that may be lost is not a command.

  Then Sparkplug B, because of its message types two are not telemetry:
  `NCMD` and `DCMD` are commands to equipment, the MQTT equivalent of a
  Modbus write, and the topic says which is which -- a broker's own topic
  ACLs usually cannot tell a command from a reading. `command_clients`
  names the publishers that may send one. `allow_message_types` bounds the
  rest, `require_namespace` declares a listener to carry nothing but
  Sparkplug, and two checks enforce what the convention states and the
  broker does not: `require_birth_before_data` refuses data from an edge
  node no birth has been seen from, and `check_sequence` refuses a message
  whose sequence is not the next one -- a gap or a repeat is a lost
  message, a duplicated publisher, or somebody replaying one.

  **The metrics are not decoded.** A Sparkplug payload is protobuf and the
  metric set is the plant's own; carrying a schema per estate is not this
  proxy's business. The two top-level fields -- the timestamp and the
  sequence, two varints at a fixed place in every payload -- are read in
  place, and the rest is forwarded untouched. A payload with no sequence is
  not checked rather than refused, the edge-node table is bounded
  (`max_nodes`), and past the bound the two stateful checks are skipped for
  a node it does not hold rather than the node being refused.

- **Modbus values are changes, not only numbers.** A range says what may
  be written. The rules a plant actually asks for are about what may
  *happen*, and four of them are new: `max_delta` bounds how far one write
  may move a value from the last one this relay saw (a right value reached
  the wrong way is what a runaway or a typo in an engineering station looks
  like); `transitions` lists the changes permitted as `0->1` pairs, with
  `*` on one side, for the registers that are states rather than numbers;
  `rate` bounds how often an address may be written, per unit and address
  or per master, because a master hunting a setpoint sixty times a minute
  is either broken or not the master it claims to be; and `require_before`
  is select-before-operate -- which IEC 60870-5-104 has in the protocol and
  Modbus does not, so either every client implements the confirmation,
  where the frame that skips it looks exactly like the frame that did not,
  or the relay enforces it. Coils go through the same machinery as values
  of 0 and 1, so "the pump may be started once a minute, and only after the
  permissive is set" is a coil rule.

  Three of the four need to know what the value is, and the honest answer
  is what this relay *saw*: a write it forwarded or a read it relayed back.
  A value changed by another master, a local panel or the process itself
  was never on this path. So `on_unknown` says what to do when there is no
  value -- `allow`, counted, with the range still in force, or `refuse`,
  which waits until something reads the register -- validation warns while
  a delta or a transition list runs with `allow`, `modbus_value_unknown`
  counts the checks that ran without a value, and a masked write makes the
  relay *forget* the address rather than guess what the device now holds.
  The table is bounded by `max_value_points` (default 65536) because the
  addresses come off the network.

  A rate refusal is answered with *server busy* rather than *illegal
  value*: the same write would be accepted a minute later, and that is what
  a master's own diagnostics should say.

- **Shadow mode: a policy you can switch on.** Every policy in this proxy
  had the same adoption problem, and it is not a technical one: somebody
  writes the allow list, the command policy, the register range or the
  topic policy, and then nobody dares switch it on, because nobody knows
  what it would refuse at three in the morning. So it stays in a branch, or
  goes in at a weekend with somebody watching, or goes in allowing
  everything -- which is a policy that is not a control.

  `policy: {mode: shadow}`, for the estate or for one listener, evaluates
  the policy on real traffic, writes down every decision it would have
  made, and refuses nothing for policy. `xproxyctl policy report` is the
  list: what would have been refused, most frequent first, with the kind,
  the listener, the reason, the rule that decided, when it was first and
  last seen, and one example of what was asked for. `xproxyctl policy
  reset` empties it after the policy is fixed, so the next week's report is
  about the new one. `GET`/`DELETE /v1/policy` are the endpoints, and
  `would_refusals` sits beside `refusals` in the status view, per kind and
  reason, so a dashboard can show the two together during a rollout.

  It reaches every protocol that has a policy: Modbus's rules (function,
  unit, address, value, rate, window), NTP's request and answer rules, the
  MQTT CONNECT, publish and subscribe policies, syslog's facility, severity
  and pattern rules, the DNS client list, block list, policy zones and
  tunnel cooldowns, SSH's command, subsystem, environment and
  file-transfer rules, the client lists of the four access gateways,
  telnet's option list, FTP's and SMTP's verb lists, the forward proxy's
  destination lists, and HTTP's positive security model -- where the same
  setting also turns a blocking WAF profile into a detecting one, because
  the WAF's own rule statistics say more about what would have blocked than
  a ledger entry could.

  **What it deliberately does not stop** is the half that makes it safe to
  turn on: authentication and a second factor, a ban, a rate limit, a
  bound, a malformed message, the protocol's own negotiation, a virtual
  patch, and the forward proxy's `private` rule -- which protects the estate
  *from* the client, so shadowing it would turn a trial into a server-side
  request forgery. A bastion whose door opened because a policy was being
  trialled would be a bastion with a trial instead of a door, and
  forwarding a frame nobody could parse would mean sending a PLC bytes this
  proxy never read. The table, kind by kind, is in docs/CONFIG.md's
  `policy` section.

  The ledger is bounded (`policy.max_reasons`, default 4096) because what
  it keys on comes off the network; it keeps counts and the first and last
  time rather than every event, because a week of a plant's traffic is
  millions of frames and the question is "what would this have broken";
  what is already in it keeps counting when it is full, and the report says
  it is full rather than quietly stopping.

- **The time gateway reads the answer, then watches the source.** The NTP
  and NTS relay could already refuse an answer for the bounds a server
  states about itself. What it could not do was read an answer against
  *itself*, or notice that a server had changed into a different server --
  and for an estate where the time signs logs, orders events, bounds an
  authentication window and expires a certificate, a second either way is
  the point of the exercise.

  Three checks that need no history and no second server:
  `refuse_bogus_timestamps` (default on) refuses an answer whose four
  timestamps cannot describe an exchange -- a zero transmit or receive
  timestamp, an answer sent before the request arrived, a last
  synchronisation later than the request. It compares the packet's own
  fields and never this relay's clock, because a relay whose own time is
  wrong would otherwise refuse every correct answer, which is the failure
  that makes a check like this get switched off; an interleaved answer is
  exempt, its transmit timestamp being the server's previous one on
  purpose. `refuse_bogus_refid` (default on) refuses an identifier that
  does not match the stratum saying how to read it: a stratum 1 answer
  whose identifier is not a reference clock's name, a stratum 2-or-worse
  answer naming no upstream. Only the unset value is called wrong above
  stratum 1, because the field may be four octets of a hash of an IPv6
  address and refusing a digest for looking like a multicast address would
  refuse a correct server. And `max_root_distance` bounds half the root
  delay plus the root dispersion -- RFC 5905's own measure, and the one a
  server cannot satisfy by keeping one half small.

  Two more statements of policy: `allow_strata` is the exhaustive list
  rather than the bound (a plant whose servers are a reference clock and
  its own two followers has no stratum 5 in it), and `expect_refid` names
  the identifiers the estate's servers report, which is the cheapest
  statement of server identity the protocol allows without a key.

  A leap second gets a policy of its own, because a leap indicator is an
  instruction to every clock that hears it and the IERS only ever uses the
  end of June, December, March or September. `leap_policy: alert` (the
  default) forwards the announcement and raises a security event when it is
  out of season -- forwards, because the clients hear it from every other
  server too and suppressing it quietly would lose the estate the one event
  worth reading. `window` refuses the ones out of season, `refuse` refuses
  every announcement, `allow` says nothing and warns.

  Then `change_detection`, which asks whether the server is still the same
  server: `ntp_source_changed` (the reference identifier), and a stratum
  that jumped, an offset that stepped, a dispersion that exploded, NTS that
  stopped, a leap second announced. Every one of those passes any static
  bound an estate would write -- a GPS clock at stratum 1 now answering as
  something else at stratum 4 is inside `max_stratum: 8`, an offset that
  steps by fourteen seconds is inside `max_offset: 30s` -- which is why each
  has a signal of its own. The measurements come from both the monitor's
  own probes and the exchanges the relay forwards, so an estate polling
  once an hour still notices within a probe interval. The baseline moves to
  what was measured, so one change is one alert rather than one per poll
  for ever, and an answer with no time in it (a kiss-o'-death, an
  unsynchronised clock) never becomes the baseline. `action: refuse` drops
  the answer as well, and warns: refusing stops the corrections rather than
  reporting them.

- **Live session control: who is on, and getting them off.** A bastion
  whose only answer to "who is on the production database right now, and
  can you get them off" is "restart the daemon, which drops everybody"
  is missing the operation a bastion exists for. `GET /v1/sessions` lists
  what the daemon is serving now -- SSH and its SFTP channels, telnet,
  VNC, RDP, FTP and the Modbus device queues -- oldest first, with the
  client, the login, the target, one detail the kind chose (the desktop's
  name, the unit identifier, the subsystem) and how long it has been up.
  `DELETE /v1/sessions` closes the session named by `id`, or every
  session matching `kind`, `listener` and `user`. `xproxyctl sessions`
  and `xproxyctl sessions -kill ID` / `-kill-matching` are the commands.

  Four decisions worth writing down. A session registers *before* its
  handshake finishes, so one stuck in a handshake -- a client that
  connected and then stopped, a scanner, somebody waiting on a second
  factor -- is listed and can be closed, which a table built from
  finished logins would miss. Each session carries its own closer,
  because only the kind knows what ending its session means, and a table
  that closed sockets itself would race the kind that owns them; the
  entry is removed by the goroutine that notices the socket close, so a
  session still draining reads as still there rather than as gone. A
  request that names neither an id nor a filter is refused rather than
  taken as *everything*. And the identifiers are random rather than
  sequential, so one seen in a log line an operator pasted into a ticket
  does not let anybody guess the others.

  Every closure is audited with the session, the login, the target and
  the kernel-verified identity of the caller. `sessions_live`,
  `sessions_opened`, `sessions_closed`, `sessions_killed` and
  `sessions_refused` are in the status view, with
  `xproxy_sessions_live`, `xproxy_sessions_total` and
  `xproxy_sessions_closed_total{by="operator"}` in the Prometheus
  exposition. `xproxyctl sessions` is the live table; `xproxyctl session`
  (singular) still reads recordings back from disk.

- **xproxy-replay: the player the recordings were waiting for**, and the
  bug it found.

  The VNC and RDP gateways record the protocol stream rather than a
  video, deliberately: decoding at capture time would mean implementing
  every encoding a desktop might choose and silently losing the rest. The
  documentation said a decoder could be written against the file
  afterwards. Writing it showed that it could not: the events went through
  `json.Marshal`, which replaces every byte that is not valid UTF-8 with
  the replacement character, so a graphical recording was lossy from the
  first pixel and no player could ever have read one.

  So a recorder whose stream is binary now says so in the header
  (`XPROXY_ENCODING: base64`) and writes the data base64, and every reader
  here decodes it. The `vnc` recorder also writes the pixel format the
  desktop announced, since the handshake that carried it happens before
  the recording starts and a player cannot read the stream without it.
  `xproxyctl session show` and `play` refuse those files and name the
  program that reads them, instead of printing base64 at a terminal.

  `xproxy-replay` is that program, and it reads everything the gateways
  write. A terminal session replays with its timing through the same
  escape-sequence filter `xproxyctl session play` uses. An RFB recording
  is decoded -- Raw, CopyRect, RRE, CoRRE, Hextile, TRLE and ZRLE, which
  is what RFC 6143 specifies, with the desktop-size and cursor
  pseudo-encodings read to keep the stream in step -- into PNG frames,
  into one self-contained page that plays them with no network at all, or
  into the screen as it was at one moment. An RDP recording's framing,
  channels and marks are read and its graphics are not, which it says.

  Tight and the vendors' own encodings are not decoded, and that is the
  point of saying so: they are not in RFC 6143, Tight carries JPEG and its
  own compression streams, and a player that guessed would be inventing a
  picture inside an investigation. Such a rectangle stops the decoding, is
  counted, and is named in the output.

  Shipped as a sixth binary, in the base RPM, with `xproxy-replay`(8).

- **Both directions of a graphical session are recordable.** The `vnc`
  and `rdp` gateways recorded the picture -- the server-to-client stream
  -- and nothing else, while the ssh and telnet gateways have always been
  able to keep the other half behind `recording.input`. Now all four
  behave the same way: with `input: true` a graphical recording carries
  the viewer's or client's own stream as asciicast `i` events beside the
  `o` ones, which on RFB is every key, pointer, clipboard and negotiation
  message and on RDP is also the virtual channel traffic a redirected
  drive would carry.

  A message or unit the policy refused is written as a **mark** rather
  than as bytes. That is the useful half of the pair: the refused bytes
  are not in the file, and the fact that the viewer tried -- and which
  rule said no -- is. `view_only` dropping a key event and a channel
  nobody granted carrying a file both read the same way in a replay.

  It stays off by default, for the reason the terminal keystroke
  recording is off by default: an input stream is a keylogger, and the
  difference matters to the people recorded and to whoever holds the
  files.

- **Time: an NTP and NTS security gateway** (`kind: ntp` and
  `kind: ntske`, `internal/ntp`, `internal/kinds/ntp`,
  `internal/kinds/ntske`; RFC 5905, 4330, 7822, 8573, 8915, 9109, and
  RFC 9748 for the extension field registry).

  A time packet is forty-eight octets, has no session, carries no
  identity and is believed absolutely: the device on the other side
  steps its clock to whatever it is told. Every certificate's validity,
  every log line's order and every "what happened first" in an
  investigation rests on it.

  Three jobs live on this port and only one of them is "forward a
  packet", so they are kept apart deliberately: **forwarding** time
  packets, which this listener does with a policy; **authenticating**
  them, which belongs to whoever holds the key -- symmetric keys this
  listener can check, and NTS it deliberately cannot; and **keeping an
  accurate clock**, which is the local time daemon's job. A relay that
  tried to be a time source would be a time source nobody calibrated.

  **What a relay can do that a client cannot is compare.** A client asks
  one server and believes it. This one probes every server in the pool
  with its own transactions, measures each the same way, and refuses to
  pass on an answer from a server whose time disagrees with its peers or
  whose own dispersion says not to trust it -- because a server that is
  reachable, synchronised, authenticated and *wrong* is the case every
  other check passes. Four states are kept apart, because the operator's
  next action differs: unreachable, unsynchronised (it answers and says
  not to use its time), suspect (it answers, claims to be fine and
  disagrees) and healthy. With three or more sources the median is the
  estate's opinion and the outlier is named; with two that disagree
  neither can be called wrong, so both are marked and the event says
  that -- which is why a pool of fewer than three warns at validation.
  The transitions have hysteresis, because one slow answer on a busy
  network is not a fault and a relay that moved every client in a plant
  on one sample would be an outage generator with a health check
  attached.

  **Both directions**, as everywhere else: `reverse` fronts the estate's
  own time servers, `forward` is the controlled egress towards servers
  elsewhere, with `allow_servers` bounding the destinations whatever the
  pool's names resolve to.

  **The modes that are not time.** Mode 6 is the control protocol and
  mode 7 the vendor-private one that `monlist` belongs to -- the
  amplifier this port is famous for. Neither has the header this relay
  parses, so both are refused from the first octet, before any field of
  the body is read, and neither can be named in `modes` at all. NTPv5 is
  a different packet format again: the dispatch refuses it by name, and
  `allow_version5` forwards it as opaque bytes on a transaction socket
  of its own rather than parsing fields whose meaning is not settled.
  Versions 1 and 2 are accepted only when named, because a version 1
  packet has no mode field and reading its zero bits as a client request
  is a decision rather than a reading.

  **The packet, read whole.** Forty-eight octets is the header and not
  the packet: extension fields (RFC 7822), a MAC, both or neither.
  RFC 7822 cannot always tell the last field from a MAC -- a twenty or
  twenty-four octet tail is both -- so the relay reads it as a MAC, as
  every implementation does, *and reports that the reading was a
  choice*, which a policy then refuses by default. Before version 4
  there are no extension fields at all, so a tail there can only be a
  MAC. A field type this relay does not know is refused rather than
  forwarded, which is also how Autokey (RFC 5906, withdrawn) is handled:
  it is not implemented and its fields are not tunnelled.

  **Symmetric authentication** is AES-CMAC (RFC 8573), implemented from
  RFC 4493 and tested against its vectors with the subkeys checked
  separately. MD5 and SHA-1 verify only behind an explicit exception
  that warns, because a device from 2006 cannot be taught a new
  algorithm and refusing to speak to it at all is how an estate ends up
  with no authentication rather than weak authentication somebody knows
  about.

  **NTS** is pass-through, and that is a decision rather than a
  limitation. Protected packets are forwarded whole -- fields, order and
  bytes -- because the authentication is between the client and the
  server and every visible NTS field is readable by anybody on the path:
  "NTS is present" is a routing fact here, never an authentication one.
  What the relay does enforce is the rule that matters: an answer
  arriving without NTS fields for a request that had them is a downgrade
  to plain NTP and is refused, never passed on silently. Key
  establishment is its own listener (`kind: ntske`) on TCP 4460, where
  the ALPN `ntske/1` and the server name are read from the ClientHello,
  a connection that is not an NTS client is refused, and the handshakes
  in flight are bounded -- a TLS handshake is the expensive part of NTS
  and a flood of them is this port's denial of service. Termination is
  deliberately absent rather than approximated: doing it honestly needs
  key derivation from the TLS exporter, the cookie keys the time servers
  hold, rotation with an overlap and recovery across a restart, and an
  implementation that faked any part would be telling clients their time
  was authenticated when nobody had checked.

  **A refusal is a drop, except the one the protocol has.** A datagram
  cannot be refused -- there is no reply that means "no", and a reply to a
  forged source is traffic aimed at whoever was named -- so everything
  refused is dropped and counted with the reason in the security log.
  The exception is the kiss-o'-death: a client asking too often gets a
  stratum-0 answer whose reference identifier is `RATE`, which it
  understands and backs off from, where a drop teaches it nothing.

  Architectural decisions, documented in
  [CONFIG.md](CONFIG.md#serverlistenersntp-kind-ntp) beside the keys:

  - **Packets are forwarded as the bytes that arrived**, never
    re-encoded: an NTS-protected packet re-encoded is one the client
    rejects, and an authenticated one re-encoded is worse. So the
    client's own transmit timestamp reaches the server and the server's
    own answer reaches the client, which is what lets the client verify
    the exchange itself.
  - **Every timeout, expiry and rate limit is on the monotonic clock.**
    This is the relay for the protocol that moves the wall clock;
    wall-clock arithmetic here would be a timeout that fires when the
    time is set. The datagram relay beside it had the same bug in
    miniature -- session activity stored as Unix nanoseconds, which loses
    Go's monotonic reading -- and it is fixed, with a test that fails if
    anybody stores a wall-clock stamp there again.
  - **The association table and the outstanding-request table are
    separate.** An association is a client address *and port*, and its
    server is chosen once and kept: a client that asked a different
    server every poll would see a different offset every poll, and the
    jitter it measured would be the relay's doing. Nothing is round
    robin per packet and nothing hedges. The outstanding table is keyed
    by the server and the client's transmit timestamp, because a client
    may have several requests in flight, an answer may arrive after its
    association moved, and a server may answer something nobody asked --
    each of which is a counter rather than a confusion. An answer whose
    origin timestamp matches nothing is dropped even though it came from
    the right address; interleaved mode, where the server echoes its own
    previous transmit timestamp, is the documented exception with a
    table and a switch of its own.
  - **The relay's own cost is a number**: a packet takes one path out
    and another back, so the offset a client computes is wrong by
    `(forward − reverse delay) / 2`. Nothing removes it, so the data
    path is short and the accuracy advice is in the documentation: put a
    time server near its consumers rather than a relay in front of a
    distant one. (And a one-way data diode cannot carry NTP at all: the
    protocol needs the round trip.)

  Twenty-six counters for the time listener and seven for key
  establishment, the fine-grained refusal reasons in the per-kind
  counters, and `ntp_denied` and `ntske_denied` as ban reasons.
  `examples/ot/ntp.yaml` is three deployable listeners: the reverse
  gateway with the version and mode profile, the rate limits and the
  comparison; the forward egress with bounded destinations and a trace;
  and the key establishment relay.

- **Modbus, in both directions, in front of equipment that cannot be
  patched** (`kind: modbus`, `internal/modbus`, `internal/kinds/modbus`;
  Modbus Application Protocol v1.1b3, Modbus over Serial Line v1.02,
  Modbus/TCP Security v21).

  Modbus has no authentication, no integrity and no session. A frame says
  which device it is for, what to do and where, and the device does it.
  That is not a flaw somebody will fix: it is a protocol from 1979 running
  equipment installed a decade ago, whose vendor is gone and whose process
  does not stop for a firmware upgrade. So the only place a policy can
  exist is in the path, and it has to be written in the protocol's own
  terms -- the unit identifier, the function code, the register range, the
  value -- because those are the only terms the traffic has.

  Every frame is parsed whole, in all three framings: Modbus/TCP (MBAP)
  and the two serial framings every Modbus gateway ever sold tunnels over
  TCP. `framing` is what arrives and `upstream_framing` is what leaves,
  so one listener bridges a serial drive behind a terminal server to a
  master speaking MBAP, per route if a listener fronts both kinds of
  device at once, with `unit_override` for a device that answers only to
  slave address 1.

  **It works both ways round, because a plant has masters inside it and
  devices inside it.** `mode: reverse` fronts the equipment: masters
  connect to the listener and it dials the PLC, which is how a device that
  cannot be patched gets an allow list, a read-only historian, a value
  bound on a setpoint and an audit trail. `mode: forward` is the plant's
  controlled egress towards a device somewhere else, where the `routes`
  are the only destinations that exist -- a unit identifier no route claims
  is refused with a gateway exception rather than sent somewhere invented.
  The policy is the same either way.

  **The policy.** `read_only` refuses every function code that changes
  anything, for every client, before any rule is read, and no rule can
  override it: a read-only listener a rule could write through would not
  be one. Beyond it, ordered rules with first match winning, each naming
  any of the client network, the Modbus/TCP Security role, the unit
  identifier, the function code, the access class (`read`, `write`,
  `diagnostic`, `identify`, `vendor` -- the durable way to write "no
  writing" without listing every code that writes), the register ranges,
  the write ranges, a quantity bound, value bounds and a schedule. An
  `observe` action records and keeps looking, which is how a rule is tried
  on live traffic before it decides anything.

  Two decisions inside that are worth naming. An `addresses` rule must
  cover the **whole** range a request asks for: a read of 0 to 200 against
  a rule for 0 to 99 does not match, because splitting the request is not
  the relay's decision. And a value outside a `values` bound is refused
  *by the rule that set the bound* rather than falling through to a later
  rule that would permit it -- a bound that can be escaped by writing
  another rule underneath it is not a bound. The value bounds are the deep
  inspection a plant actually needs: a setpoint register that may hold 0
  to 100 and nothing else, `signed` for the ones encoded as signed
  integers, and a coil bound that says which way a coil may be driven, so
  "this client may stop the pump but not start it" is a rule and its
  mirror image is the same rule written the other way round.

  **A refusal is Modbus.** `deny_response: exception` answers with the
  exception a master already understands -- illegal function for a code the
  policy does not permit, illegal data address for a range it does not,
  illegal data value for a value outside a bound, gateway path unavailable
  for a unit with no route, server busy for a session whose queue is full,
  gateway target failed to respond for a device that did not answer -- and
  the session carries on, so an operator's diagnostics say something true
  at 3am. `drop` and `close` are there for the cases where a master should
  learn nothing.

  **Modbus/TCP Security**, the Modbus Organization's own answer: TLS with
  mutual authentication, conventionally on port 802 with no in-band
  upgrade to negotiate, and authorisation by the role in the client
  certificate's x.509 extension under the Modbus arc
  (`1.3.6.1.4.1.50316.802.1`). `security.mode: require` is what the
  specification describes and `allow` is the migration; `role_source: cn`
  or `ou` reads the subject instead, for an authority that cannot issue
  the extension yet, and warns, because a subject field says who a
  certificate is *for*. A role can only come from a certificate and a
  certificate only from TLS, so a listener asking for roles without TLS
  refuses every session and says `security_requires_tls` rather than
  leaving a mystery.

  **Learning mode, because nobody knows what a plant's Modbus traffic
  is.** The drawings say what it was meant to be; the traffic says what
  the integrator left behind. `learn` records every client, role, unit,
  function code, address range and value range that crosses the listener
  and writes it out as YAML: an `observed:` block describing the traffic
  and under it a `rules:` block permitting exactly what was seen, ready to
  paste. A subject whose `device_exceptions` are not zero is a request the
  device itself refuses, which is a line to write out of the policy rather
  than into it. `enforce` is false by default and validation warns while
  it is off: a learning run that decided things would not be a learning
  run, and one left on by accident should say so.

  **Traces** are the other tool and a separate file: one JSON object per
  frame, for an afternoon during a commissioning, with its own bound --
  at which it writes one line saying it stopped rather than filling the
  disk the plant's historian is also on.

  Three architectural decisions, documented in
  [CONFIG.md](CONFIG.md#serverlistenersmodbus-kind-modbus) beside the
  keys:

  - **Requests are serialised towards each device.** A Modbus slave has
    one scan. A relay that pipelined into it would be turning a policy
    engine into a load generator, so each session holds one connection
    per route and one request in flight at a time, with `max_pending`
    bounding the queue behind it -- 1 for the serial framings, which have
    no transaction identifier and where a second request in flight could
    not be told from the first.
  - **A forwarded frame keeps its bytes.** The frame the device is sent is
    the frame that arrived, byte for byte, and the answer the master gets
    is the answer that arrived; the relay re-encodes only when the
    framings differ or the unit was rewritten, because re-encoding is how
    a relay and a device come to disagree about what was said. The one
    exception runs the other way: the master's own MBAP transaction
    identifier is put back on the answer, because that is the field the
    master matches on.
  - **The device's answer is checked too.** A response the relay cannot
    parse, or one answering for a different unit identifier, is not handed
    to the master -- the two would read the same bytes differently, which
    is the whole class of bug this relay exists to prevent. The master
    gets a server failure and the event is logged.

  Fifteen counters (`modbus_requests`, `modbus_denied`,
  `modbus_would_deny`, `modbus_exceptions`, `modbus_queue_full`, …), the
  fine-grained refusal reasons in the per-kind refusal counters, and
  `modbus_denied` as a ban reason, so the ladder that answers a walk
  through function codes works here as it does everywhere else.
  `examples/ot/modbus.yaml` is three deployable listeners: the reverse
  line with a historian, bounded setpoints, a shift-scheduled pump and a
  serial drive; the same line again under Modbus/TCP Security with three
  roles; and a read-only forward egress with a trace.

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

- **The target's own host certificate** (`upstream_known_hosts`).

  The bastion read only the plain entries of its `known_hosts` file, so a
  target presenting a **host certificate** was refused -- and signing each
  new host key with a host CA is exactly how an estate that rebuilds
  machines avoids editing that file everywhere. An `@cert-authority` line
  is now honoured, with the certificate checked as OpenSSH checks it: the
  signature against that authority, that it is a host certificate and not
  a user one, the validity window, and that its principals cover the host
  being reached. An authority is trusted only for the hosts its own line
  names.

  `@revoked` also does what it says now. It was being read as "not a
  trusted entry", which is silence: a key listed as revoked *and* trusted
  elsewhere in the file was accepted on the other line. It is a refusal
  before any other line is consulted, and for a certificate it covers the
  key inside it and the authority that signed it -- one line takes back
  every certificate that CA ever issued. A file that trusts nothing at all
  fails at bind rather than refusing every session afterwards.

  Ten deliberate weakenings were each caught, three after a test was added
  for an authority scoped to another host and one duplicate check removed:
  revocation was decided in two places, so neither was covered on its own.

- **Which WAF rules are noise on this traffic, measured** (`xproxyctl waf`,
  `GET /v1/waf`).

  Beside each rule's matches the statistics now carry `alone` -- the
  matches where no other attack rule matched the same request -- and
  `agreement`, the share where at least one other did. A rule set has
  hundreds of rules and a false positive hunt has an afternoon; this says
  which few rules fire on their own, which is where that afternoon goes.

  It is a measurement of this traffic, deliberately not a verdict about
  the rule: a rule that only ever fires alone is either the one thing
  noticing something or the one thing crying wolf, and which of those it
  is takes a person. The CRS's paranoia level says how aggressive a rule
  is; this says what it did here. The scoring and reporting rules (949110
  and its kin) are excluded from the arithmetic on both sides, because the
  rule set's own bookkeeping is not a second opinion.

  The learned exclusion proposals carry the same number and are ordered by
  it, least agreement first: an exclusion for a rule nothing ever agreed
  with is the safest one to write. Twelve deliberate weakenings were each
  caught, two after the ordering test was made to discriminate -- hit count
  and agreement happened to agree in the first version of it, which proved
  nothing.

- **Imported threat intelligence** (`threat_intel`, `routes[].threat_intel`).

  Named lists of client addresses and TLS fingerprints, read from files,
  each with its own action: `log`, `challenge` or `block`. A feed of
  scanner networks, of exit nodes, of addresses seen attacking somebody
  else -- the estate has the files already, and until now the only place
  to put them was `deny_cidrs` on every route, edited by hand and reloaded
  for every change.

  **It is deliberately not the ban list.** A ban is earned here: this proxy
  watched a client do something and decided. A list is imported, and says
  nothing about what the client did *here*. So `log` is the default action,
  `block` warns at load, and the check runs **after** routing, which is what
  lets `threat_intel: false` exempt a route -- a feed with one wrong line in
  it must not take the health endpoint an operator watches the outage with.
  The ban list is still checked before routing, because a ban is this
  proxy's own finding and applies to everything.

  A list that cannot be read fails the load, and a reload that cannot read
  one is refused whole: an imported list that silently matches nothing is
  worse than no list, because the operator believes it works. A file that
  disappears or stops parsing *after* the load keeps the entries already
  read and says so in the error log, because a feed being rewritten in
  place must not empty the policy for the moment that takes. Files are
  re-read on their own (`refresh`, 5m by default, `0` for never) rather
  than needing a reload, and only a file whose size or modification time
  moved is read again.

  A `block` hands the ban list the `threat_intel` reason, so a trigger can
  escalate a client that keeps arriving from a listed network into a real
  ban. `challenge` with nothing to challenge with serves the request
  rather than blocking, since that would be a policy nobody wrote;
  validation refuses the combination at load. `xproxyctl status` lists
  every list with its entries, hits and when it was last read, and says
  whether the files are being watched at all. Twenty-eight deliberate
  weakenings were each caught, five after the tests were extended or two
  redundant guards removed -- among them a `refresh: 0` that could not be
  told from an unset field, which is now a pointer and means never.

- **A set of byte ranges is a decision, not a relay**
  (`routes[].ranges`, RFC 9110 section 14).

  A `Range` header is a small request asking for a large answer, and a set
  of ranges is a small request asking for many: each range costs the origin
  a read and the response a multipart part, so a header naming two hundred
  of them asks one machine to assemble a response dozens of times the size
  of the resource, from a packet. That is the oldest amplification bug in
  HTTP, and until now this proxy relayed the header and left it to the
  origin.

  RFC 9110 section 14.2 puts the decision exactly where a gateway can make
  it: a server **may** coalesce ranges that overlap or are separated by a
  gap smaller than the overhead of another part, "regardless of the order
  in which the corresponding byte-range-spec appeared", and one that will
  not satisfy a set may ignore the header and serve the whole
  representation. So a route with the section rewrites the set rather than
  inventing a rule -- the same bytes, fewer parts -- and what is still over
  `max_ranges` (4 by default) is either dropped, which serves the whole
  representation, or refused with 416 and `Accept-Ranges: bytes` so the
  client can ask again for fewer.

  What it does not do is guess. Another range unit is passed through, since
  an origin ignores a unit it does not implement and this proxy has nothing
  to say about one it cannot read. A value that is not a range set -- a
  spec with no dash, a descending range, more specs than are worth reading
  -- is dropped once, here, so this proxy and the origin read the request
  the same way. A suffix range (`-500`) is kept as it is, because how it
  overlaps `0-99` depends on a length the proxy does not know; the largest
  suffix covers the smaller ones and nothing else about them is assumed.

  `ranges` and `ranges_sent` appear in the access log, and
  `xproxy_ranges_total` counts what was dropped and what was refused.
  Twenty-five deliberate weakenings were each caught.

- **The attack that is a sequence of valid requests** (`api_abuse` filter).

  Every request in this sequence is correct on its own -- the right method,
  the right path, an authenticated caller, a well formed identifier -- and
  the attack is the sequence:

  ```
  GET /api/orders/1041   200
  GET /api/orders/1042   403
  GET /api/orders/1043   403
  GET /api/orders/1044   200   <- somebody else's order
  ```

  That is broken object level authorisation, the first item on the OWASP
  API Security Top 10, and nothing in this proxy could see it: the WAF
  reads one request and finds nothing wrong with any of these, because
  nothing is wrong with any of these. `account_guard` watches the
  credential endpoints, a rate limit counts requests without caring what
  they asked for, and a caller reading a hundred *different* objects at a
  perfectly ordinary rate was invisible to both.

  So the filter counts the shape of the sequence, per caller and per
  endpoint, over a window: how many **distinct** objects were touched
  (`enumeration`), whether their numeric identifiers are consecutive
  enough to be a walk rather than a busy afternoon (`sequential`), and
  what share of the answers said the object was not theirs
  (`refused` -- 401, 403 or 404, which is what probing looks like and
  little else does). A caller is the authenticated identity when the chain
  established one and the client address otherwise, so an attacker who
  spreads a walk over a hundred addresses is one caller, and the filter
  belongs after the identity filters for exactly that reason.

  **Objects, not requests**: a caller re-reading its own order fifty times
  has touched one object, which is what keeps a page refresh out of the
  `sequential` signal -- the first version of this counted requests and
  would have called forty reads of one identifier a walk of forty. An
  endpoint is the method and the path template with identifiers folded out
  (`GET /api/orders/*`), so one busy endpoint never flags a caller on
  another, and a collection endpoint with no identifier in it has no object
  to count. Identifiers are held per caller and endpoint up to 1024 and the
  excess is counted rather than forgotten silently, so a distinct count is
  never quietly wrong.

  Which request the action lands on follows from where the signal came
  from: a bound crossed on the way in refuses *that* request, while the
  `refused` share is raised by an answer already sent and applies from the
  next one. `log` is the default, `challenge` lets a person through and
  stops a script, and `block` answers 403 with the `api_abuse` reason --
  which a ban trigger can now name, so a caller that keeps walking is
  stopped before routing instead of at the filter. Per filter,
  `xproxy_api_abuse_requests_total`, `_flagged_total`, `_blocked_total`,
  `_challenged_total` and `_dropped_total` count what it did, and
  `xproxy_api_abuse_subjects`, `_objects` and `_overflowed` say how much it
  is holding. Forty deliberate weakenings were each caught, eight of them
  only after the tests were extended.

  Also fixed while the ban reasons were being read: `bans.triggers[].reasons`
  in CONFIG.md had fallen three reasons behind the table the validator
  checks against (`threat_intel`, `dns_answer_denied` and this one), which
  is the worst shape of documentation bug -- an operator reads the list,
  does not find the refusal they are watching, and concludes the proxy
  cannot ban on it. A test now compares the two.

- **The leaver, handled by the directory** (`scim`, RFC 7643 and RFC 7644).

  A SCIM 2.0 provisioning endpoint, so the directory that owns the joiner
  and leaver process provisions and deprovisions the credentials this
  proxy holds: the second-factor enrolment and the API keys. An account
  closed in the directory and not here is access that still works, and
  every estate has the story about the contractor whose key kept opening
  the door for a year -- because closing it was somebody's job to
  remember at exactly the moment nobody was thinking about it. Until now
  the only ways in were `xproxyctl mfa`, `xproxyctl apikey` and the GUI:
  all of them a person, doing it on purpose, afterwards.

  A create enrols a factor and issues a key; `active: false` and `DELETE`
  **revoke** every key of that user -- kept in the file as the record of
  what it reached and when it stopped -- and remove the enrolment. The
  resources live in a file of their own (`state_file`), because they are
  not the credentials: a deactivated user has to survive losing both, and
  a read reports what is *currently* in place rather than what was
  provisioned once, so an enrolment an operator removed by hand shows as
  removed.

  **One setting elsewhere is load-bearing, and CONFIG.md says so twice:**
  `require_enrolment` must be on wherever that enrolment file is used.
  Removing an enrolment refuses a user only where one is required; with
  it off the same removal means no factor is asked for, and a
  deprovisioning that opens the door is worse than none.

  What is implemented is the subset a provider drives -- `GET`, `POST`,
  `PUT`, `PATCH` and `DELETE` on `/Users`, the three discovery endpoints,
  the error object with its `scimType`, pagination -- and **nothing
  else**, because an endpoint that half-understands an operation is worse
  than one that refuses it: the directory believes the change landed. So
  a filter on anything but `userName` is `invalidFilter` rather than
  answered with the whole list (a provider whose filter was ignored would
  read the first user as its match and deprovision somebody else's
  account), a `userName` that would change is `mutability` (it is what
  the credentials are keyed on), an attribute this endpoint does not keep
  is refused rather than stored and never read, and the scopes of an
  issued key cannot be edited into something else.

  It is an administrative interface with the power to create and destroy
  credentials, so it carries its own locks rather than borrowing a
  route's: a bearer token of at least 16 characters compared in constant
  time, and `hosts`, `listeners` and `client_cidrs` -- validation says so
  when none of the three is set. It answers **before routing**, like the
  virtual `security.txt`, so the provider needs no route and no route can
  take the endpoint away; a request on its path that the selectors refuse
  is answered 404 and *not* routed on, because handing a proxied
  application a request meant for the control plane is how a control
  plane leaks. A refusal is a deny event with the `scim` reason, which a
  ban trigger can name, and a bad token feeds it: somebody trying tokens
  against a provisioning endpoint is not a client making a mistake twice.

  `return_secrets` is off by default. With it on, the response to a
  create or a reactivation carries the `otpauth://` URI, the recovery
  codes and the key plaintext -- which is what an automated onboarding
  needs and what puts them in the provider's logs; validation says that
  too. With it off the credentials are still made, and a reactivation
  mints fresh ones because the old secret is gone and cannot be handed
  back.

  `internal/mfa` gained `LoadProvisioning` for this: `Load` refuses an
  empty enrolment file, because a *verifying* store pointed at one is
  almost certainly pointed at the wrong file and would let everybody
  through unchallenged -- while a store that provisions starts empty by
  definition, and the same check there would mean nobody could ever be
  enrolled through it. `scim_requests` and `scim_denied` are in
  `xproxyctl stats`, `xproxy_scim_requests_total{result}` in the metrics.
  Thirty-six deliberate weakenings were each caught, five only after the
  tests were extended -- among them a compound filter, which the first
  version read as its first comparison and ignored the rest of.

- **Three things documented instead of built** (`docs/CONFIG.md`), each
  with the configuration it replaces and a test that drives it.

  *Content decoding in the WAF* is SecLang's own transformations --
  `t:urlDecodeUni`, `t:base64Decode`, `t:hexDecode`, `t:jsDecode`,
  `t:cmdLine` and the rest -- applied per rule and per target, which is
  how the Core Rule Set already reads a payload hidden inside an
  encoding. A gateway-wide list of decoders would be worse than nothing:
  a rule knows which of its targets can be encoded and a decoder applied
  to every body before any rule has decided anything is a second parser
  and a decompression bomb away from being the outage. What the rules do
  *not* see is a body wrapped in a transfer encoding -- a
  `Content-Encoding: gzip` request body is inspected as the bytes it
  arrived as -- and the reference now says so, and says where a
  compressed body is read instead: `sensitive_data`, which decodes gzip,
  deflate, br and zstd under an expansion-ratio bound, and ICAP or
  `yara` over the stream.

  *The WAF's `XML:` targets are two collections, not an XPath engine*, and
  RFC.md now names XPath 1.0 as not implemented for exactly that reason.
  The engine fills every attribute value (`XML://@*`) and every piece of
  character data (`XML:/*`), which is how the Core Rule Set reads an XML
  body; any other selector -- `XML:/invoice/total` -- is accepted by the
  parser and then evaluated against nothing, so a rule over it never
  fires. That is worth a paragraph rather than silence, because a rule an
  operator believes is running is worse than one they know they have to
  write differently: where a named element or a document's shape is the
  requirement, `xml_guard` is the filter that reads structure. A test
  drives all three selectors, so the claim stays true of the engine this
  binary links.

  *API version routing* needs no key of its own, because every way a
  version is actually spelled is already a matcher: `paths` for `/v1/`,
  a `headers` regex for `Accept: application/vnd.example.v2+json`, a
  `headers` exact for `X-API-Version`, and `when` for a query parameter
  or a pinned client network -- with the conditioned routes tried before
  the plain route on the same path, which is what makes a default work. A
  dedicated key would have covered one of those four. The reference shows
  all of them, plus where a version is stripped before the backend sees
  it and how an old one is deprecated and then held.

- **The file a DNS threat feed actually ships**
  (`server.listeners[].dns.rpz`, `draft-vixie-dns-rpz`).

  Response policy zones. `block` and `block_file` take a flat list of
  names, which is what an operator writes by hand; a feed publishes a
  zone file, where the policy is in the records -- one file saying "this
  name does not exist", "this one answers 10.0.0.1" and "this one is an
  exception" -- and it is transferred and diffed by tools that exist
  already. Until now a subscription had to be converted by an hourly
  script somebody wrote once and nobody owns, and the conversion threw
  away everything but the names.

  The QNAME trigger and the five actions are implemented -- `CNAME .` for
  NXDOMAIN, `CNAME *.` for NODATA, `rpz-passthru.` for an exception,
  `rpz-drop.` for no answer at all, `rpz-tcp-only.` for truncated over
  UDP -- plus local data (A, AAAA, TXT, and a CNAME the client resolves
  itself). Matching is what a zone lookup does: the name, then a wildcard
  on each parent, longest first, so `good.bank.example CNAME
  rpz-passthru.` is an exception for that host while `*.bank.example
  CNAME .` still denies everything else below it. Zones are ordered, and
  that is the feature: the estate's own exception zone goes in front of a
  subscription and nothing below can take an exception back. A zone's
  `action` overrides every rule in it, which is how a new feed is tried
  out (`passthru`) before it is trusted -- validation says out loud that
  such a zone blocks nothing.

  **The triggers it does not implement fail the load by name**:
  `rpz-client-ip`, `rpz-ip`, `rpz-nsdname` and `rpz-nsip` select on the
  client, on the addresses inside an answer and on the name servers of
  the delegation -- the last two needing the resolver to police a path
  this one forwards. A zone whose rules half apply is a policy the
  operator believes is working, so `ignore_unsupported: true` is what
  loads such a zone without them, counting what it skipped and saying so
  in the advice; where an answer's addresses are the concern,
  `answer_policy` screens them already and by range rather than by feed.

  A zone that cannot be read or parsed fails the load and the reload; a
  file that disappears or stops parsing *after* the load keeps the rules
  already read and says so in the error log, because a feed rewritten in
  place must not empty the policy for the moment that takes. Files are
  re-read on their own (`refresh`, 5m by default, `0` for never) and only
  one whose size or modification time moved is read again. Every decision
  writes a security event with the zone, the rule and the action, and a
  deny event under the new `dns_rpz` reason, which a ban trigger can name:
  a client walking a feed's names is one to stop at the edge rather than
  answer NXDOMAIN to a thousand times. `rpz_matched`, `rpz_passthru` and
  the per-zone rule counts are in `xproxyctl dns`
  (`xproxy_dns_rpz_total{result}`, `xproxy_dns_rpz_rules`).

  Thirty-three deliberate weakenings were each caught, five only after
  the tests were extended -- among them the one that changed the code: a
  `$ORIGIN` moved part way down a file was taking *itself* off the rules
  instead of the zone's own name, which turned a rule for `evil.sub` into
  a rule for `evil`.

- **Fixed: a DNS listener stopped the moment it started raced its own
  WaitGroup.** `Serve` registered each goroutine with `wg.Add` outside any
  lock while `Shutdown` called `wg.Wait`, and it published the DoH server
  where `Shutdown` read it unsynchronised. A listener that starts and stops
  at once -- which is what a test does, and what a reload of a
  misconfigured listener does -- then counted one thing or the other by the
  scheduler's whim. Every goroutine is now registered under the lock
  `Shutdown` takes before it waits, and `Serve` after a `Shutdown` starts
  nothing at all. Found by a new test doing exactly that, which fails under
  the race detector on the old code.

- **Encrypted DNS upstreams resume their sessions**
  (`server.listeners[].dns.upstream_resumption`, default on).

  A resolver's DoT and DoQ connections do not last: the upstream's idle
  timeout is usually shorter than the gap between queries for a quiet
  name, so the connection is dropped and the next query dials again. Each
  of those dials was a full handshake -- which on DoQ is most of what the
  transport costs. The client now keeps session tickets, so a redial
  resumes. Nothing is replayable by it: the Go client offers no early
  data, and the DoQ dialler keeps `Allow0RTT` false. Tickets are cached
  per upstream name, so two upstreams never see each other's.

  `upstream_resumed` counts the connections that resumed and
  `upstream_resumption` reports whether they may
  (`xproxy_dns_upstream_resumed_total`); DoH resumption happens inside
  the HTTP transport, which does not report it. Six deliberate weakenings
  were each caught, two after the tests were extended -- the DoQ counter
  and the listener's own switch.

- **RFC 9156 (QNAME minimisation) is documented as not applicable**, with
  the reason, and RFC.md gains that status word: minimisation is what
  keeps the root and the TLD from seeing a whole name while a *recursive*
  resolver walks the delegation chain, and this listener is a validating
  forwarder -- one upstream is asked the question and does the recursion.
  There is no chain here to walk. "We did not build it" and "it does not
  apply" are different promises, and the table now says which one this is;
  a row with either status and no reason fails the test that reads the
  document.

- **SSH command policy reads the command instead of matching it**
  (`server.listeners[].ssh.command_rules`, `internal/sshcmd`).

  `allow_commands` is a list of patterns, and for the commands that move
  files a pattern is the wrong shape of statement. `^scp -t
  /srv/incoming$` is somebody writing *"uploads into that directory,
  nothing else"*, and `scp -f /srv/incoming` (the other direction, the
  same words), `scp -rt /srv/incoming` (bundled flags), `/usr/bin/scp -t
  /srv/incoming` (a path), `scp  -t  /srv/incoming` (two spaces),
  `scp -t /srv/incoming/../../etc/ssh` (a path that resolves elsewhere)
  and `LD_PRELOAD=/tmp/x.so scp -t /srv/incoming` (an environment the
  env policy never sees, because it is a shell assignment and not an env
  request) each walk past it. Tighten the pattern against one and it is
  still wrong about the next.

  So a rule says what the operator meant: the direction (`upload` puts
  files on the target, `download` takes them off it), whether recursion
  is allowed, whether the rsync options that delete are, and which paths
  are in reach. `internal/sshcmd` splits the line the way a POSIX shell
  splits one simple command -- quoting and all, so the words the rule
  checks are the words the target will run -- and then reads scp's server
  flags, rsync's `--server`/`--sender` and short bundles, git's transport
  verbs and the sftp server's options the way each program reads its own.

  Four families, and the direction is always the file movement rather
  than the program's verb: a git fetch is `upload-pack` because that name
  is the server's point of view, and it is a `download` here. An approved
  exec of the sftp server binary is **relayed through the sftp policy**,
  which is what makes allowing it safe -- the channel carries the same
  protocol the subsystem does, so the same path, read-only and scanning
  rules apply to a transfer that used to be an opaque stream.

  Where a rule cannot be honest it refuses rather than implying a
  boundary that is not there. A line it cannot read as one simple command
  is `command_syntax`, including under `allow_shell_syntax`. A glob is
  admitted only where `paths` covers a whole subtree containing the
  directory the pattern sits in (a shell's `*` does not cross a `/`), and
  never where a `deny_paths` entry would have to be proven unmatched. A
  wrapper is not read through: `env scp -t /etc` is `env`, so no rule
  covers it and the blanket check refuses it as before. And rsync's file
  list travels inside rsync's own protocol, so an rsync rule decides the
  direction, the deletions and the transfer root and CONFIG.md says
  plainly that everything under that root is in reach -- sftp is the
  protocol that can carry a per-file rule.

  Each refusal is counted and logged under what was wrong with the
  command (`command_direction`, `command_path`, `command_recursive`,
  `command_delete`, `command_server`, `command_env`, `command_no_rule`,
  `command_syntax`), so a counter names the property rather than a rule
  number. With any rule present a family named by no rule is refused, so
  a rule for scp does not quietly leave rsync to the patterns. Forty-eight
  deliberate weakenings were each caught, two after the tests were
  extended for them.

- **Aggressive NSEC caching: a proof answers more than one question**
  (`server.listeners[].dns.dnssec.aggressive_nsec`, RFC 8198).

  A validated NXDOMAIN is not just an answer to the name that was asked:
  the NSEC record that proved it names a gap in the zone, and no name in
  that gap exists either. The resolver keeps the gap and answers the next
  name inside it from the proof it already holds. The traffic that saves
  is the traffic that produces it -- a random-subdomain flood aimed at an
  authoritative server through this resolver, or junk queries under a
  top-level name -- where every name is a sibling of the last and one
  signed proof covers them all.

  It is narrowed twice, on purpose, and CONFIG.md says why. A gap is
  reused only for a **sibling** of the name it was collected for: the same
  parent, therefore the same closest encloser, therefore the same wildcard
  denial the validator already checked -- a name deeper in the zone could
  be covered by a wildcard that the collected name was not. And only for a
  client that did **not** set DO: a synthesised NXDOMAIN carries no
  signatures, and a client that asked for the proof gets the upstream
  lookup, as does one that set CD.

  Only NSEC is used, never NSEC3: a hashed owner name says nothing about
  which names its gap holds without re-hashing every candidate, and an
  opt-out gap denies nothing at all. A gap lives for the shorter of its
  NSEC record's TTL and `cache.max_ttl`; `nsec_entries` parents are held at
  most (8192 by default), oldest dropped first. `queries_nsec` counts the
  answers served from a held proof and `denials_held` the size of the
  store. Fifteen deliberate weakenings were each caught, two only after the
  tests were extended -- among them the gap endpoints themselves, which the
  proof names as existing and which a comparison one character loose would
  have denied.

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

- **README.md is reorganised around the three questions it was being
  asked**: what does this speak, what can it do, and how is it run. It
  had grown by accretion -- every release appending bullets to one
  "Feature set" heading -- so the answer to each was spread across it.

  Now: a contents list; a protocol map of fifteen families, each naming
  the versions and the standards it speaks and the listener kind or
  filter that speaks it; the feature list split into ten named groups
  with the ones that had never reached it added (the request
  normalisation guard, refusal in the ClientHello, ICAP, graduated
  degradation, deceptive answers, the cluster in both its shapes,
  session recording and replay); a **configuration surface** table of
  all thirty-six top-level sections and all twenty-one filter kinds,
  one line each, so the whole of what can be configured is visible in
  two screens rather than inferred from CONFIG.md's eight thousand
  lines; and a **Setup** section that was previously a single quick
  start -- the four ways to install, the units and their sockets with
  the privileged ports each one opens, the flags each daemon takes, how
  a configuration is validated, reloaded, diffed and rolled back, and a
  table of the eleven **deployment shapes** the product supports, from a
  single reverse proxy to a fleet, with the example that shows each.

  Two corrections fell out of writing it. The VNC gateway's vendor
  security types were described as a configuration error; they are
  reimplemented, warned about at load, and documented for what they are
  actually worth. And RFC.md, which promises that every standard is
  listed so an absence is not mistaken for an omission, had no rows for
  the three protocols the gateways terminate: telnet (RFC 854 and 855
  with a row per option, including the two that are refused and why),
  RFB (RFC 6143), and RDP with CredSSP over NTLMv2 and the RFB vendor
  types in the non-IETF table.

- **Every list of listener kinds now says all sixteen of them.** The
  kinds arrived one release at a time and the documentation that
  enumerates them did not always follow: the `kind:` row in CONFIG.md
  stopped at `rdp`, the `proxy_protocol` row named seven kinds of the
  eleven that read a header, README's per-kind prose ran in a different
  order from its own tables, the roadmap still listed the remote access
  and operational technology kinds as candidates after they had shipped,
  and the `xgate` and `xrelay` unit files described a daemon with fewer
  listeners than it serves. All of them are the current set now, with
  the socket unit saying how a datagram listener is activated
  (`ListenDatagram`, which is what a time gateway on UDP 123 needs) and
  THREAT_MODEL.md carrying the two entries the operational technology
  kinds bring: a write to equipment that has no authentication to
  bypass, and a time service used as an amplifier.

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

- **A reload handed every rate-limited client a fresh burst.** Each
  generation built new limiters, so every bucket went back to full at every
  reload. A reload is something an operator does *because* something is
  going on, which made it the worst possible moment to lose a limit -- and
  it made repeated reloads a way to defeat one outright. A policy whose
  shape is unchanged now keeps the limiter it had, and with it every
  bucket's level. "Shape" is the bounds and the *key*: rate, burst,
  algorithm, limit, window, and `key` with its prefix lengths. Change one of
  those and the buckets do start again, because a level measured in the old
  rate's tokens says nothing about the new one, and a policy that moved from
  `client_ip` to `jwt:sub` is counting something else. Everything else about
  a policy -- what it does when it refuses, how long it tarpits, its cluster
  semantics -- is about the decision rather than the counting, and does not
  disturb a bucket.

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
