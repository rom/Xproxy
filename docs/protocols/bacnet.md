# BACnet/IP — the building

`kind: bacnet`, served by **xot**, UDP port **47808** (0xBAC0).

ASHRAE 135, and the protocol behind the air handling, the lighting, the lifts
and the access control in most commercial buildings built in the last twenty
years. It is an object model as much as a protocol: every controller presents
*objects* with *properties*, and reading or writing a property is how a
management system does everything it does.

## On the wire

BACnet is a family with several data links — MS/TP over twisted pair, BACnet/IP
over UDP, and others. This listener reads **BACnet/IP**, Annex J.

Four layers, and each has something a policy needs:

| Layer | What it is |
|-------|-----------|
| **BVLC** | The virtual link control: a type octet, a function, a length. The function says whether this is a unicast, a broadcast, a *forwarded* message from a broadcast management device, or a foreign-device registration |
| **NPDU** | Clause 6's network layer: hop count, optional source and destination network numbers, and — when the network-layer-message bit is set — a routing or security message rather than an application one |
| **APDU** | Clause 20's application layer: confirmed request, unconfirmed request, simple ack, complex ack, segment ack, error, reject, abort. A confirmed request carries an *invoke identifier* the answer echoes |
| **Service** | `readProperty`, `writeProperty`, `readPropertyMultiple`, `writePropertyMultiple`, `subscribeCOV`, `who-is`, `i-am`, `reinitializeDevice`, `deviceCommunicationControl` and about thirty more |

The part that matters most for a policy is **command priority**. A commandable
object holds sixteen command slots; the plant follows the highest-priority slot
that is filled; and slots 1 and 2 are *manual life safety* and *automatic life
safety*. A value written at priority 1 cannot be overridden by the management
system, by the building's own program, or by anybody who does not know it is
there.

`out-of-service` is the other one. Writing it true cuts a point loose from the
physical world: the object then reports whatever was written to its present
value, and every graphic, trend and alarm above it believes the number.

## What the protocol gives you

Almost nothing. There is **no user, no session and no password that means
anything**. The only identity in the protocol is the source address of the
datagram, and it is UDP.

ASHRAE 135 clause 24 defines *network security* — the security messages the
NPDU can carry — and it is effectively undeployed; the later
BACnet/SC (secure connect) addendum puts the protocol inside TLS WebSockets and
is only now reaching equipment. What is installed is a controller with a
twenty-year service life on a flat building network.

## What this listener decides

**The services, named one at a time.** `services` defaults to the reading,
discovery and notification services and nothing that changes anything, so a
relay somebody put in front of a building without reading the manual carries
what a graphics page needs and nothing that moves plant.

**The objects and properties**, because a service on its own is too coarse:
`writeProperty` to a setpoint and `writeProperty` to `out-of-service` are the
same service.

`deny_sensitive_writes` is that distinction made a default rather than a list
somebody has to remember to write. It is **on**, and it refuses writes to the
properties that are the device's own behaviour rather than a measurement or a
setpoint: `object-name`, `out-of-service`, `program-change`, the notification
recipient lists and the MS/TP timing properties. `refuse_unlocated_objects`
covers the other half of the same idea — a request whose object this relay
cannot place is a request no object policy was applied to.

**The command priority.** `max_command_priority` defaults to 8, refusing the
seven slots above it — so nobody takes a piece of plant at a life safety slot
the management system cannot override. It is the single most useful line in the
section, and it has no equivalent in any other protocol here.

**The broadcasts.** `who-is` with no range brings back an `i-am` from every
device on the network, which is this protocol's amplification vector as well as
its discovery mechanism. So a broadcast is carried or not, the replies one
broadcast may bring back are bounded, the window they may arrive in is bounded,
and `max_whois_range`/`require_whois_range` make a sweep of the whole instance
space a decision somebody made.

**The network layer.** Routing messages, security messages, foreign-device
registration with a broadcast management device, and forwarded messages are
each carried or not. Foreign-device registration is the one worth refusing by
default: it asks the estate's BBMD to forward every broadcast to whoever
registered.

**The invoke identifiers are translated per client**, in both directions, so
two clients behind one relay cannot collide on an identifier and read each
other's answers.

### The imported lists, and the estate's authorisation policy

BACnet names nobody: a client is an address and, on a routed network, a network
number and a MAC address. So two questions are asked about the client itself,
after this listener's own `allow_clients` and before anything reaches the
building:

- **the imported address lists** (`threat_intel`), about the client's address. A
  list whose action is `block` refuses; one that asks for a `challenge` is
  recorded like a log list, because there is no request here to serve a challenge
  into and turning it into a block would be a policy the operator did not write.
- **the `authorization` section**, on the client address, the listener, the kind,
  the upstream pool and the hour. A rule naming `users` matches nobody on this
  kind, so a rule here is written with `networks`, `targets` and `schedule`.

Asked on each datagram, because BACnet/IP has no session to hang the answer on. A
refusal goes through this listener's deny path, so a client that keeps sending
earns a ban exactly as one refused by `allow_clients` does. Which services and
which objects it may touch stays with this listener's own policy above, because
that is the thing that can say what a write to analog-output 3 means in a
building.

The lists are asked first: a list is an import about an address and says nothing
about this estate's intentions, so a refusal naming the feed sends an operator to
the feed rather than to a rule they would not find.

A refusal is the reason `threat_intel` or `authorization` on this listener's usual
deny event, so the counters, the security log and the ban list see it as they see
any other refusal. Either shadow switch -- `policy: {mode: shadow}` on the
listener, or `shadow: true` on the section -- records what it would have refused
and carries the traffic.

## Behavioural detection

`anomaly` is the other half of the policy, and it needs nothing written down.
The rules answer *is this permitted*; the models answer *is this what this
client has been doing*. They are `internal/anomaly`, the same models every OT
kind runs, and [docs/CONFIG.md](../CONFIG.md) documents the block once. What is
specific to this protocol is the translation:

| The models' term | On BACnet | Used by |
|------------------|-----------|---------|
| symbol | the confirmed service (`ReadProperty`, `WriteProperty`, `ReinitializeDevice`), or the virtual link function for a message with no application layer | novelty, sequence |
| device | the object instance the request addressed, which is the nearest thing to a device identity this protocol offers | talkers |
| point | the object and property, `analog-output,3.present-value` | novelty about writes |
| value | nothing | -- |

**The talkers model earns its place here more than on most kinds.** A building's
device list is written once at commissioning and does not change for a decade, so
a new address on the segment -- `anomaly_new_talker` -- is a fact worth a line in
a log, and a known controller talking to an object it has never addressed
(`anomaly_new_pair`) is one host working along the building.

**The two value models are inert here**, and the reference says so rather than
pretending: a property value is tagged data whose type is the object's, and this relay does not decode it into a number. So `telemetry` and `correlations` have nothing to compare
on this kind, and the other four models carry it.

## Engineering activity

Four of BACnet's confirmed services are engineering rather than operation. The
`engineering` block — [documented once in docs/CONFIG.md](../CONFIG.md#engineering),
the same on every OT kind — reads them as their own class of event, and can hold
them to an approved grant out of the [access ledger](../CONFIG.md#access).

| Service | Class | Why |
|---------|-------|-----|
| `ReinitializeDevice` | `restart` | A controller restarted, warm or cold |
| `DeviceCommunicationControl` | `mode_change` | A controller told to stop talking |
| `AtomicWriteFile` | `file_transfer` | A file into the device |
| `CreateObject`, `DeleteObject` | `configuration` | The object model itself |

**A `WriteProperty` to a present-value is not engineering.** That is a setpoint
or a command, which the rules and the property policy are for.

**`ReinitializeDevice` and `DeviceCommunicationControl` are the two a
building's own tooling uses and an intruder uses for the same reason.** A
controller that has been told to stop communicating is a controller the head end
cannot see, and the head end's operator finds out from the alarm that never
arrives. Both carry a password field on the wire, which is the device's own
protection and is worth exactly what the device's default password is worth —
the grant is the term that does not depend on it.

## What it does not do

- **It does not authenticate.** The client list is an address list and this is
  UDP, so the list is worth what the network path makes it worth. There is no
  credential in the protocol to check.
- **It does not implement clause 24 security or BACnet/SC.** The security
  messages are carried or refused, not originated or verified.
- **It does not read MS/TP.** The twisted-pair data link is a different
  physical world; a router between MS/TP and BACnet/IP is where that boundary
  is.
- **It does not rewrite a priority.** A write above the bound is refused, not
  lowered. Lowering it would mean the management system believes it holds a
  slot it does not.
- **It does not reassemble segments to inspect them.** `allow_segmented`
  decides whether segmented requests are carried at all; a policy applied to
  half a reassembled request would be a policy with a hole in it.

## Standards

| Document | What it covers |
|----------|----------------|
| ANSI/ASHRAE 135 | BACnet: the object model, the services of clause 20, the network layer of clause 6 |
| ANSI/ASHRAE 135 Annex J | BACnet/IP: the BVLC functions, BBMDs and foreign-device registration |
| ANSI/ASHRAE 135 clause 24 | Network security services (largely undeployed) |
| ANSI/ASHRAE 135 Addendum BACnet/SC | Secure connect: the protocol over TLS WebSockets |
| ISO 16484-5 | The international edition of the same standard |

## See also

- The estate-wide policy above it: [docs/CONFIG.md `authorization`](../CONFIG.md#authorization)
- The settings: [docs/CONFIG.md `## bacnet`](../CONFIG.md#bacnet)
- A worked configuration: [`examples/ot/bacnet.yaml`](../../examples/ot/bacnet.yaml)
- Operating it: [docs/TROUBLESHOOTING.md `## BACnet`](../TROUBLESHOOTING.md#bacnet)
- The other protocols on a plant: [modbus](modbus.md), [s7](s7.md),
  [iec104](iec104.md)
