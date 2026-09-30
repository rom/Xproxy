# Modbus — the protocol under most of the world's plant

`kind: modbus`, served by **xot**, TCP port **502** (Modbus/TCP), **802**
(Modbus/TCP Security).

Published in 1979 by Modicon for a serial line, and now the most widely
deployed industrial protocol there is. Its age is the whole story: it was
designed for a two-wire link between one master and a handful of devices in a
cabinet, and it is now on Ethernet, routable, and reachable from anywhere the
network reaches.

## On the wire

A request is four things: a **unit identifier**, a **function code**, an
address and a count or a value. That is all. The reply echoes the function
code, or sets its high bit and returns an exception code.

Three framings carry the same requests:

| Framing | Where it came from | What wraps the request |
|---------|-------------------|------------------------|
| **Modbus/TCP** | The MBAP header | A transaction identifier, a protocol identifier, a length and a unit identifier |
| **RTU** | Modbus over Serial Line | An address octet, the request, and a CRC-16. Binary, and frame boundaries come from silence on the line |
| **ASCII** | The same specification | A `:` start, hex-encoded octets, an LRC and CRLF |

The address space is four tables, and which one a function code reaches is
part of the function code rather than the address:

| Table | Width | Access | Typical function codes |
|-------|-------|--------|------------------------|
| Coils | 1 bit | read/write | `0x01`, `0x05`, `0x0F` |
| Discrete inputs | 1 bit | read | `0x02` |
| Input registers | 16 bit | read | `0x04` |
| Holding registers | 16 bit | read/write | `0x03`, `0x06`, `0x10`, `0x17` |

So a register number on its own does not name a thing: register 40001 in one
vendor's documentation is holding register 0 in another's, and a policy has to
be written against the function code and the address together.

**And three function codes carry a second code that says what they actually
do.** `0x08` is "diagnostic": a sub-function word, then one data word.
Sub-function 11 returns a bus message count; sub-function 4 is Force Listen
Only Mode, which is four bytes that take the device off the bus until
something restarts it, and 10 to 21 clear the counters and the event log.
`0x2B` (43) is either a device identification request (MEI type 14) or a
CANopen tunnel (MEI type 13), which are not the same kind of thing at all.
And `0x5A` (90) is not in the specification: it is Schneider's **UMAS**, the
protocol every Unity and EcoStruxure engineering station speaks to a Modicon
PLC, carrying a session byte, a command of its own, and then the command's
data.

UMAS is where a PLC gets stopped and where a control program gets
downloaded. What is known about its commands is published research rather
than a standard, which this listener is explicit about: the commands it
recognises it names, and one it does not it reports as unknown rather than
as harmless.

The identification half of `0x2B` is worth a paragraph of its own, because it
is the only place in this protocol where a device says what it *is*: the
response to MEI type 14 carries a vendor name, a product code and a
`MajorMinorRevision` -- the firmware version -- with up to four more strings
after them (section 6.21). There is no banner, no capability exchange and no
version register everybody agrees on, so this answer is the whole of what a
relay can learn about the equipment in front of it without asking a question
of its own. This listener reads the answer as it passes and puts the three
fields into the asset inventory, where
[`asset_inventory.advisories`](../CONFIG.md#asset_inventory) matches them
against the vendors' published CSAF advisories. It never sends an
identification request of its own: a frame this relay invented would be a
frame on a process network nobody scheduled, and a firmware version is not
worth that.

## What the protocol gives you

Nothing, in the base protocol. There is **no authentication, no integrity and
no session**. A frame arrives, the device does what it says. The transaction
identifier is a correlation number, not a nonce; the unit identifier is a bus
address, not an identity.

**Modbus/TCP Security** (the 2018 protocol specification) is the one exception
and it is real: TLS with mutual authentication, and a *role* carried in an
x.509 extension of the client certificate, which the server is expected to
authorise against. It is also barely deployed, because it needs new firmware
in the device — which is the same requalification problem every OT protocol
has.

What is deployed is a device that was commissioned a decade ago, whose vendor
may no longer exist, running a process that does not stop for a firmware
upgrade. The device cannot be fixed, so the path is where a policy can live.

## What this listener decides

The vocabulary is Modbus's own, because a policy an engineer cannot check
against the device's documentation is a policy nobody maintains:

- **The unit identifier**, which on a gateway in front of a serial segment is
  the only thing that says *which device*.
- **The function code**, and therefore the table and the direction. `read_only`
  is one line that refuses every writing function code for every client.
- **The sub-function**, because the function code is not always the whole
  question. "The diagnostic counters, yes; Force Listen Only Mode, never" is
  two rules; so is "this engineering station may read variables over UMAS and
  may not stop the PLC or download a block". A rule names them by name
  (`diagnostics`, `umas_commands`) or by what they *do* (`effects`:
  `control`, `program`, `clear`, `unknown`), and the effect form is the one
  that outlives the code that carried it. By default a sub-function in those
  four groups is refused to an allow rule that never mentioned the
  sub-function at all, because a rule allowing `diagnostic` was written by
  somebody thinking of counter polls.
- **The register range**, as ranges per function code, so "the historian may
  read the process values and nothing else" is a line rather than a hope.
- **The value**, which is the part a protocol-level filter usually cannot do.
  A setpoint is bounded by what the process can physically hold; a rate of
  change is bounded so a ramp cannot be written as a step; a transition is
  bounded so a valve cannot go from closed to open without the states between;
  and a sequence is bounded so a start cannot arrive before the interlocks it
  depends on.
- **The role**, where Modbus/TCP Security is in use: the certificate's role
  extension selects the rule, so the device's own model and this listener's
  agree.
- **The schedule**, so "the pump may be stopped at any time and started only
  during the shift" is expressible.

The framings are **bridged**: a client speaking Modbus/TCP can reach a serial
drive behind a terminal server, with `framing` and `upstream_framing` naming
each side, and the relay re-frames rather than tunnelling — which means the
policy applies to the request rather than to an opaque payload.

`learn` watches a running plant and writes down what it actually does, which
is how a policy gets written for equipment nobody has documentation for. It
produces two things: the allow-list of who may reach what, and a **process
baseline** per address -- the envelope of the values written there, the largest
step between consecutive writes, and the most writes seen in any one minute,
which is what `min`, `max`, `max_delta` and `rate` are written from.

The baseline is per *address* and not per subject, because one span over every
register a master touched is looser than the traffic it came from: a master
writing a 0..40 setpoint and a 0..3 mode would get a bound permitting the mode to
be set to 40. And a baseline is where a conversation starts and not a control --
it is derived from traffic, and traffic is what somebody already inside has been
shaping, so the report says in as many words that the numbers are read against the
drawings before anything is pasted -- as the `values:` of the rule that allows
those writes, since a value policy belongs to a rule and not to the listener.

Only the function codes that really write values set an envelope: 6, 16 and the
write half of 23. Code 5 puts a coil's bit on the wire as `0xFF00`, code 22
carries an AND mask and an OR mask, and code 8 a diagnostic argument; none of
them is a value at an address, and a baseline that read them as values proposed
`min: 65280, max: 65280` for a coil somebody switched on.

## Behavioural detection

`anomaly` is the other half of it, and it needs nothing written down. The rules
answer *is this permitted*; this answers *is this what this master has been
doing*. Control traffic is repetitive in a way other traffic is not -- a master's
scan cycle is the same few function codes over the same few address ranges, every
cycle, for years -- so "this client has never done this before" is a signal here
where elsewhere it would be noise.

The models are `internal/anomaly`, shared with every other OT listener kind
because none of them is about Modbus, and [docs/CONFIG.md](../CONFIG.md) documents
the block once. What is specific to this protocol is the translation:

| The models' term | On Modbus | Used by |
|------------------|-----------|---------|
| symbol | the function code's name: `read holding registers`, `write single coil` | novelty, sequence |
| device | the unit identifier, `unit 3` | talkers |
| block | the span a request wrote, `unit 3 40100-40120` | novelty about writes |
| point | unit and address, `unit 3 40100` | telemetry, correlations |
| value | a single-register write, and every register a read was answered with | telemetry, correlations |

Novelty about writes is keyed on the **span** rather than on each address in it: a
master writes the same spans every cycle, and one recipe download would otherwise
fill a bounded set with addresses that are all the same traffic. A master that
writes more distinct spans than the detector holds has its novelty detection
turned off and the count says so, because collapsing the spans into one -- what the
learning report does -- would widen what counts as seen and make the detector stop
detecting while it went on looking like it worked.

The burst is the one thing a per-address `rate` cannot see: forty different
registers written once each is not a rate violation anywhere and is exactly the
shape of somebody walking the address space.

**The values are both directions.** This relay already decodes read replies for the
value policy's deltas and transitions, so the telemetry model sees what the *device*
answered as well as what the master wrote -- which is the half that matters. A
frozen or replayed written value says something about the master; a frozen or
replayed read value is what a control room is being shown while the process does
something else. A finding in a reply never refuses anything: by the time an answer
has arrived there is nothing left to refuse.

The `correlations` are the one model that needs an operator, and the points are
spelled the way the table above spells them (`unit 3 40100`), which is also how the
trace writes them.

It alerts, and the alerts do not reach the ban ladder: the first legitimate
maintenance write of the year is novel too, and banning the plant's master for it
would take the process away from the control room. `action: deny` refuses the
first occurrence and records it, so a retry goes through -- a hard stop and an
operator's attention, not a block. And it settles before it reports, because when
the relay starts everything is new.

A refused request is answered with a Modbus **exception** — the protocol's own
"illegal data address" or "illegal function" — so the master's own library
reports it and the poll loop carries on. Dropping the connection because one
request was refused would turn a refusal into an outage.

### The imported lists, and the estate's authorisation policy

Modbus names nobody: a master is an address and a unit identifier, and the
protocol has no authentication at all. So two questions are asked about the client
itself, after this listener's own `allow_clients` and before the device is dialled:

- **the imported address lists** (`threat_intel`), about the client's address. A
  list whose action is `block` refuses; one that asks for a `challenge` is
  recorded like a log list, because there is no request here to serve a challenge
  into and turning it into a block would be a policy the operator did not write.
- **the `authorization` section**, on the client address, the listener, the kind,
  the upstream pool and the hour. A rule naming `users` matches nobody on this
  kind, so a rule here is written with `networks`, `targets` and `schedule`.

Which unit identifiers and which registers that master may then touch stays with
this listener's own policy above, because that is the thing that can say what a
write to holding register 40001 means.

The lists are asked first: a list is an import about an address and says nothing
about this estate's intentions, so a refusal naming the feed sends an operator to
the feed rather than to a rule they would not find.

A refusal is the reason `threat_intel` or `authorization` on this listener's usual
deny event, so the counters, the security log and the ban list see it as they see
any other refusal. Either shadow switch -- `policy: {mode: shadow}` on the
listener, or `shadow: true` on the section -- records what it would have refused
and carries the traffic.

## Answering as a device that is not there

The relay is an honest gateway, and that is a disclosure: `0x0a` for a unit
identifier nothing is behind is what the specification asks for, so a sweep of 1
to 247 maps which devices exist, and a refused function code answering `0x01`
while a permitted one answers data maps the policy. The scan is refused and the
survey completes.

`deception` answers from a fabricated device instead. Two shapes:

- `mode: decoy` is a honeypot -- an address on the plant network with no upstream
  and nothing behind it. Anything speaking Modbus to it is lost or looking.
- `mode: answer` is a real relay where the frames it was going to refuse are
  answered by the fabrication instead, for the clients named in `clients`.

**The rule that makes it safe here:** a frame that was going to reach a device is
never answered by the fabrication. Deception replaces a refusal and never an
answer, because the failure mode on a plant floor is not a confused scanner but
an operator acting on a tank level that was never measured. `mode: answer`
therefore refuses to load without a client list.

The fabricated values are derived rather than invented -- stable while you read
them, drifting between periods, inside a band the profile declares, with
totalisers that only increase -- so the device survives a second look. Function
code 17 and 43/14 carry the identity a scanner fingerprints on, and it should be
the make this plant runs: a profile claiming another vendor's controller is the
tell that ends the pretence. `tripwire` addresses are answered and raised as
`modbus_tripwire`, which is a detection with no false-positive rate, because
nothing legitimate reads them.

See [docs/DECEPTION.md](../DECEPTION.md#a-device-that-is-not-there) for the
family this belongs to and
[docs/CONFIG.md](../CONFIG.md#serverlistenersmodbusdeception) for every setting.

## Engineering activity

Modbus has no word for engineering and the vendors' sub-protocols do. The
`engineering` block — [documented once in docs/CONFIG.md](../CONFIG.md#engineering),
the same on every OT kind — reads them as their own class of event, and can hold
them to an approved work order out of the [access ledger](../CONFIG.md#access).

This relay already classifies a sub-function by *effect* rather than by number,
because the number is a vendor's and the effect is a plant's, so the engineering
classes fall out of the classification that is already there:

| Effect | Class | Where it comes from |
|--------|-------|---------------------|
| `program` | `program_download` | A UMAS program transfer in function 90 on a Modicon |
| `control` | `mode_change` | Stop, start, restart, listen-only — the diagnostic sub-functions of function 8 |
| `clear` | `configuration` | The diagnostic register and the event log wiped |

**A holding-register write is not engineering.** That is a setpoint, and the
value rules and their bounds are what police it. What is engineering arrives
inside the function codes that carry a sub-protocol.

**Direction is what the sub-function says, and where this relay cannot tell it
reports a download.** "Something moved a program" is the fact; the safer reading
of an ambiguous one is the one that gets looked at.

Modbus names nobody, so the work order names the engineering station's *address*.
That is what the plant has, and inventing an identity out of a socket would be
worse than saying so. With `require_grant: true` a UMAS program write with no
open grant is refused with `engineering_no_grant`, answered as exception 01 (or
dropped, or the session closed, as `deny_response` says), and the device never
sees it.

## What it does not do

- **It does not rewrite values.** A setpoint outside the bounds is refused, not
  clamped. Clamping would mean the operator's screen and the device disagree
  about what was written, which is worse than an error.
- **It does not invent a session.** The protocol has none, so every request is
  decided on its own. There is no login to attach an identity to unless
  Modbus/TCP Security is in use.
- **It does not authenticate the base protocol.** A client list is an address
  list, and an address is not an identity. On a flat control network that is
  what there is; the improvement is Modbus/TCP Security, and this listener
  will speak it where the equipment can.
- **It does not understand your register map.** The value semantics have to be
  configured against the plant's own documentation. A bound written from a
  guess is a bound that trips during a legitimate ramp.
- **It is not a substitute for segmentation.** A master that can reach TCP 502
  on the device directly is not covered by anything here.
- **It does not claim to know UMAS.** Function code 90 is parsed as far as the
  session byte and the command, which is what a policy decides on, and no
  further: nothing here reads a UMAS payload, so there is no value bound on a
  variable written over UMAS and no bound invented for a payload whose shape
  is not published. The command table is public research, so a command absent
  from it is `unknown` -- refused by default rather than assumed harmless --
  and a read-only listener refuses every UMAS frame whatever the command,
  because a reading derived from reverse engineering is not one a relay can
  vouch for. The other vendor protocols on a Modicon estate are not parsed at
  all.
- **It does not police a CANopen tunnel.** MEI type 13 of function code 43
  carries a second protocol, and this relay reads none of it. The tunnel is
  classified `unknown`, which means a rule has to name it before it passes --
  policy about the tunnel's existence, not about its contents.
- **A decoy does not know your plant.** The fabricated values are plausible, not
  meaningful: they are inside their bands and they move, and nothing here knows
  that register 40010 is a tank level in centimetres. Somebody who knows the
  process can tell. That is the honest limit of it -- a decoy costs an
  opportunist a survey, and it will not fool the engineer who commissioned the
  line.

## Standards

| Document | What it covers |
|----------|----------------|
| Modbus Application Protocol Specification V1.1b3 | The function codes, the data model and the exception codes |
| Modbus Messaging on TCP/IP Implementation Guide V1.0b | The MBAP header and the TCP behaviour |
| Modbus over Serial Line Specification V1.02 | The RTU and ASCII framings |
| Modbus/TCP Security Protocol Specification (2018) | TLS with mutual authentication and the role extension |
| Published research on Schneider UMAS (function code 90) | The command table behind `umas_commands`. Not a standard, and treated as what it is: a command absent from it is unknown rather than harmless |
| IEC 62443 | The zone and conduit model a plant's security architecture is written against |

## See also

- The estate-wide policy above it: [docs/CONFIG.md `authorization`](../CONFIG.md#authorization)
- The settings: [docs/CONFIG.md `server.listeners[].modbus`](../CONFIG.md#serverlistenersmodbus-kind-modbus)
- A worked configuration: [`examples/ot/modbus.yaml`](../../examples/ot/modbus.yaml)
- Behaviour packs for the known tooling: [`examples/ot/packs/frostygoop-modbus.yaml`](../../examples/ot/packs/frostygoop-modbus.yaml) and [`examples/ot/packs/pipedream-modbus.yaml`](../../examples/ot/packs/pipedream-modbus.yaml), with [what a pack is and is not](../../examples/ot/packs/README.md)
- The other protocols on a plant: [s7](s7.md), [iec104](iec104.md),
  [bacnet](bacnet.md)
