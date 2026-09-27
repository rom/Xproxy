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
