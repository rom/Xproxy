# Modbus — the protocol under most of the world's plant

`kind: modbus`, served by **xrelay**, TCP port **502** (Modbus/TCP), **802**
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
where elsewhere it would be noise. A function code the client has not used, a
write to a register it has never driven, and a burst of writes across every
address, which is the one thing a per-address `rate` cannot see: forty different
registers written once each is not a rate violation anywhere and is exactly the
shape of somebody walking the address space.

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
| IEC 62443 | The zone and conduit model a plant's security architecture is written against |

## See also

- The estate-wide policy above it: [docs/CONFIG.md `authorization`](../CONFIG.md#authorization)
- The settings: [docs/CONFIG.md `server.listeners[].modbus`](../CONFIG.md#serverlistenersmodbus-kind-modbus)
- A worked configuration: [`examples/ot/modbus.yaml`](../../examples/ot/modbus.yaml)
- The other protocols on a plant: [s7](s7.md), [iec104](iec104.md),
  [bacnet](bacnet.md)
