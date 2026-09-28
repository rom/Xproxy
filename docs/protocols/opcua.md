# OPC UA — the industrial protocol that brought its own security

`kind: opcua`, served by **xrelay**, TCP **4840**.

OPC UA (IEC 62541) is what the last fifteen years of industrial automation
standardised on. A modern PLC, a historian, a SCADA client, an MES and a cloud
gateway all speak it, and unlike the protocols it replaced it was designed with
security *in* it: certificates on both ends, a signed and encrypted channel, a
session with a user identity.

So this page is different from the others in this directory. Everywhere else the
protocol has nothing and the relay supplies everything. Here the server already
checks certificates and users, and the relay's job is to be the one place where an
estate's rules — which security policies are acceptable, whose application, which
users, which nodes — are written and enforced for *every* server behind it,
including the ones whose own configuration nobody has reviewed since they were
commissioned.

**There is no `tls` section on this listener**, and that is not an omission. The
`opc.tcp` transport has no TLS: the security is inside the protocol, negotiated
per connection in the secure channel from certificates the two ends hold. A
certificate here would promise something the transport cannot do, and terminating
the channel would make this relay a man in the middle of the one industrial
protocol designed to notice — holding the plant's private key in order to.

## On the wire

Every message starts with eight octets, and everything is little-endian.

| Field | Octets | What it says |
|-------|--------|-------------|
| MessageType | 3 | `HEL`, `ACK`, `ERR`, `RHE`, `OPN`, `CLO`, `MSG` |
| ChunkType | 1 | `F` final, `C` more to come, `A` abandon this message |
| MessageSize | 4 | The whole message **including these eight octets** |

That last word is the one mistake a UA TCP reader makes. Take the size as a body
length and every message after the first is shifted by eight octets — and most of
them still parse, so nothing fails loudly.

After the header, a secured message (`OPN`, `CLO`, `MSG`) carries a security
header and then a sequence header:

- **`OPN` carries an asymmetric security header**: the channel identifier, the
  security policy URI, the sender's certificate and the thumbprint of the
  certificate it encrypted to. It has to be in the clear — it is how each end
  learns the other's public key — which is why a relay can enforce certificate
  and policy rules without holding a private key of its own.
- **`MSG` and `CLO` carry a symmetric one**: the channel identifier and the
  *token* identifier. Two numbers rather than one, because a channel outlives its
  keys: a token has a lifetime and is renewed by a second `OPN` on the same
  channel.
- **The sequence header** is a sequence number for the channel and a **request
  identifier** for the message. The request identifier is what joins chunks into a
  message and what pairs a response with its request — the same role a token plays
  in CoAP.

## What the protocol gives you

### The three modes, and what each leaves a reader

`MessageSecurityMode` is the single most consequential field in the protocol for a
relay, and it is named in the `OpenSecureChannel` **request body** rather than in
any header — so a relay learns the policy from the header and the mode from the
service call inside.

| Mode | The body | What a relay can do |
|------|----------|--------------------|
| `none` | plaintext | everything |
| `sign` | signed, **not** encrypted | read every node identifier and method argument — and modify none of them, because the signature is over exactly the octets the client sent |
| `sign_and_encrypt` | ciphertext | see the channel, the sizes and the timing |

This is why `require_readable_bodies` exists. Confidentiality on the wire and
service-level enforcement in the middle are alternatives, not a spectrum: a
listener with rules about nodes over a `sign_and_encrypt` channel is a listener
whose rules never see a body. Validation warns about exactly that, and
`opcua_opaque_bodies` counts how often it happened.

Mode `sign` is the interesting middle. Every message is still authenticated and
modification is still detected; what is given up is confidentiality on this hop,
which matters where the wire is the threat and does not where the clients are.

### What the handshake gives away, for free

Three exchanges happen before any service call, and all three are readable:

1. **Hello / Acknowledge.** The client proposes a receive buffer, a send buffer, a
   maximum message size and a maximum chunk count, and names the endpoint URL it
   believes it reached. The server answers with the sizes in force, which are the
   **minimum** of the two proposals. That minimum is why `max_chunk_size` is worth
   setting: a relay that passed both directions through unchanged has let the ends
   agree on a chunk larger than its own buffer, and will then be refusing large
   requests in the middle of a working day rather than at the point where refusing
   costs nothing.

   Behind a relay the endpoint URL names the *relay*, because the client is saying
   where it believes it connected. A server that insists on its own hostname will
   reject it, so the relay's address belongs in the server's endpoint list. That is
   an interoperability fact to configure around, not a fault.

2. **OpenSecureChannel.** The security policy URI and both certificates in the
   header, the message security mode and the requested token lifetime in the body.

3. **CreateSession / ActivateSession.** The client's application URI, product URI,
   session name and instance certificate; then the user. The application URI must
   also appear in the certificate's subjectAltName — a server checks that, and
   `require_certificate_uri` makes this relay check it too, which is the cheapest
   identity check the protocol has.

### The security policies

| Policy | State |
|--------|-------|
| `None` | no signature, no encryption. A deliberate configuration for a segment where something else provides the security, and an accident everywhere else |
| `Basic128Rsa15` | **withdrawn** in IEC 62541 1.04: RSA-PKCS#1 v1.5 and SHA-1 |
| `Basic256` | **withdrawn**: SHA-1 again, longer key |
| `Basic256Sha256` | current |
| `Aes128_Sha256_RsaOaep` | current |
| `Aes256_Sha256_RsaPss` | current, the strongest the standard defines |

The two withdrawn ones are the two an estate most often still has switched on,
because a single old client keeps them there — and that client is the exposure.
Naming one in `security_policies` is an *error* unless
`allow_deprecated_policies` is also set, so switching SHA-1 back on has to be
written down in two places.

`None` is deliberately not classified as deprecated, which reads oddly until you
see what the two categories are for: deprecated means "broken cryptography still
switched on", `None` means "no cryptography, on purpose". They are refused for
different reasons and the log line says which.

### The identity tokens

An `ActivateSession` presents one of four, and which one it is decides how much
the session is worth:

| Token | What it proves |
|-------|---------------|
| `anonymous` | nothing. The session's rights are whatever the endpoint grants an anonymous client |
| `username` | a name and a password |
| `x509` | a user certificate |
| `issued` | a token from elsewhere: a JWT, a Kerberos ticket |

`anonymous` is off by default, which is the single most useful line in the
identity section.

A username token's password carries an encryption algorithm URI, or does not. One
that does not is a password on the wire as the operator typed it — under mode
`none` in the clear to anything on the path, and under `sign` in the clear to
**this relay**, which is the reason `refuse_plaintext_passwords` defaults on
rather than being left to the mode. This relay never keeps a password: the wire
reader retains its length and its algorithm, and the value is discarded at the
point it is read.

## What this listener decides

### The service level

Where the channel left the body readable, the rest of the policy applies.

**Which service.** The default is what an HMI does: the discovery and session
services, `read`, `history_read`, `browse`, `browse_next`, and the subscription
and monitored-item services — and nothing that changes a value, a node or the
plant. A service the table does not classify is treated as a write, because a
service whose effect is unknown is not one to carry on a read-only listener.

**`read_only` and what is not on its list.** It refuses `write`, `call`,
`add_nodes`, `add_references`, `delete_nodes`, `delete_references`,
`history_update`, `register_server` and `transfer_subscriptions`, and no rule
overrides it. `transfer_subscriptions` is on that list because it moves a
subscription from one session to another, which is how a client takes over
another client's stream of values — and on a plant, taking over the stream an
operator's screen draws from is a change to what that operator sees.

The subscription services are *not* on it. They change state the server holds
rather than anything the plant does, and a read-only listener no HMI can subscribe
through is a listener no HMI can use. The subscription bounds police those
instead.

**Which node.** Node identifiers are compared as their canonical form —
`ns=3;i=1001`, `ns=4;s=Motor/Speed` — and the four numeric encodings collapse to
one key, because a server may send `i=2253` as a FourByte on Monday and a Numeric
on Tuesday and a rule distinguishing them would be a rule that stopped working. A
Guid renders in the standard's own mixed endianness, so an identifier copied from
a server's documentation matches.

Namespaces are named by **index**, and that is the protocol's choice rather than
this relay's: a namespace URI appears only in an `ExpandedNodeId`, and the node a
Read, a Write, a Browse or a Call names is a plain `NodeId`. Translating would
mean reading and keeping the server's own `NamespaceArray` (`ns=0;i=2255`), which
is learning rather than policy. The caveat that follows is real and the reference
states it: an index means something only against the table it came from, and a
firmware update can reorder that table, so a namespace list is one to review after
one.

**Which attribute.** This is the line between moving an actuator and changing who
may move it. A write to attribute 13 (`value`) is a setpoint; a write to attribute
17 (`access_level`) is a privilege change. Both arrive as an ordinary Write, so
`write_attributes` defaults to `value` alone and a refusal of a permission
attribute is counted as `permission_write` rather than as a generic attribute
refusal — because a log line that did not say so would not tell an operator what
just happened.

**Which method.** A `Call` names two nodes: the object it is on and the method
itself. Both are checked, because allowing `Reset` on one pump is not allowing it
on every pump of that model.

**How many operations.** A Read naming ten thousand nodes is one request and ten
thousand operations. `max_operations` bounds that, and `max_write_operations`
bounds it separately for the services that change something.

### The bound that matters most

`min_publishing_interval`. The amplification on this protocol is arithmetic rather
than accidental: a `CreateSubscription` asking for a one-millisecond publishing
interval, with a thousand monitored items on it, is a server asked to send a
thousand values a millisecond — from one legitimate session, in entirely valid
protocol, with no flood and no spoofing. An interval of zero means "as fast as the
server can", which is faster than any bound, so it is refused wherever a bound
exists rather than read as unset.

`min_sampling_interval` is the same question one layer down: a sampling interval
faster than the device can answer is a device polled as fast as it will go.

### Chunks

A service call larger than the negotiated buffer arrives as several chunks joined
by their request identifier, and the body means nothing until they are joined. So
this relay assembles, with three bounds that refuse rather than trim: the chunks in
one message, the octets in it, and — the one that is easy to forget — the
part-assembled messages in flight. A peer that opens sixteen request identifiers
with one intermediate chunk each has sent very little and asked the relay to hold a
great deal.

The **abort** chunk type is honoured: the peer said it was abandoning the message,
and discarding what was accumulated is the point of the chunk type existing.

### How a refusal is expressed

A **service-level** refusal is a `ServiceFault`: a response whose TypeId is the
fault's, carrying a bad status code against the request handle the client sent. The
client's own library reports the error and the poll loop carries on, which is what
a plant needs — dropping a session because one Read was refused turns a refusal
into an outage.

A **channel-level or transport-level** refusal is an `ERR` and a close, and not by
preference. A fault answering an `OpenSecureChannel` would have to be secured with
the keys that `OpenSecureChannel` exists to establish, so the client's record layer
would discard it and the operator would read a timeout. The `ERR` carries a status
code and this relay's own reason, which is what an operator correlates against the
refusal in the log.

## What it does not do

- **Decrypt.** No key agreement, no private key of the plant's, no termination of
  the secure channel.
- **Modify a body.** Under mode `sign` the signature is over exactly what the
  client sent, so a relay that rewrote a field would break the channel — and under
  any mode, re-encoding a message would make this a second implementation of the
  encoder whose disagreements with the first are what an attacker looks for.
- **Log a value.** A Write's payload is a process value: a pressure, a
  temperature, a recipe parameter. The node, the attribute and the value's *type*
  are logged; the value is not. A method's argument count is logged; the arguments
  are not.
- **Hold a password.** Its length and whether it was protected, and nothing else.

### What is not here yet

**PubSub** (IEC 62541-14) is a different security model on a different transport —
UDP multicast or MQTT, with symmetric keys distributed by an SKS — and is not a
natural extension of a TCP reverse proxy. It is a separate phase.

## Learning mode

Nobody writes a correct `nodes` list from the address space. It says which nodes
exist, not which of them an HMI polls every second, which method a contractor's
laptop calls at three in the morning, or which namespace a historian reads that
nobody remembers commissioning. So the listener will write the list for you:
`learn.enabled` records what crosses it and `learn.file` gets a proposed rule set
on an interval and at shutdown. Run it for a week.

A **subject** is one identity — an application URI and a user — one class of
service, and one group of nodes. Not one node: a `nodes` pattern is the line an
engineer argues about, and a subject per node would be two thousand rows for one
HMI. A string identifier groups under its prefix, so `ns=4;s=Line1/Pump1/Speed`
and `ns=4;s=Line1/Pump1/Pressure` are one row proposing
`ns=4;s=Line1/Pump1/*`. A numeric identifier has no structure to group by, so
the namespace is the group and the identifiers are listed inside it — the
proposal then names them rather than inventing a pattern out of digits.

Three numbers in the report matter more than the rows:

- **`opaque_messages`** is the first thing to read. A channel in
  `sign_and_encrypt` leaves this relay nothing to read, so a run over one records
  no nodes at all — which looks exactly like a run over an idle listener. The
  report says what share it could not read, and what to change: `sign` is signed
  and unmodifiable but readable, and `require_readable_bodies` makes the
  requirement explicit.
- **`server_faults`** is the server refusing what this relay allowed, counted
  against the rows the request made. An identity whose every request was refused
  gets no rule proposed, because a rule for it would permit a thing that cannot
  happen.
- **`denied_by_policy`** is what the current policy refused, or would have on a
  run that is not enforcing. It is the number that says the policy and the
  traffic disagree, and which way.

The proposal names the services that were **called**, not the services the
subject's class covers: an identity that read a live value does not get
HistoryRead. And it proposes none of the things learning must not widen — no
security policy, no security mode, none of the amplification bounds. Those
appear as observations under names no rule uses, because a report that proposed
the fastest publishing interval it happened to see would widen the one setting
this listener exists to hold.

`learn.enforce` decides whether the policy is in force while the run measures.
Off by default, which is the only honest way to find out what a policy would
have broken; a live plant that cannot have the run be permissive turns it on.

Shadow enforcement is separate and works on its own: the listener's `policy:
shadow` setting and `monitor_only` record what would have been refused and
forward it, with the hard decisions — an unreadable message, the bounds, every
service that changes something — still enforced, because a Write forwarded so it
could be written down is a moved actuator.

## Standards

| Part | What it covers |
|------|---------------|
| IEC 62541-6 | The mappings: the UA TCP transport, the chunking, the binary encoding. This is the one a reader of this listener needs |
| IEC 62541-4 | The services: Read, Write, Call, Browse, the subscription set, and the session and channel services |
| IEC 62541-7 | The profiles, including the security policies and what each one's algorithms are |
| IEC 62541-3 | The address space: node classes, attributes, references |
| IEC 62541-2 | The security model: what the secure channel and the session are for, and what each protects against |
| IEC 62541-5 | The standard information model: namespace zero, and the node identifiers in it |
| IEC 62541-14 | PubSub — a different transport and a different security model, and not this listener |
| IEC 62443-3-3 | The plant-side requirements an estate is usually being audited against, which is what the identity and node rules here are written for |

## See also

- The estate-wide policy above it: [docs/CONFIG.md `authorization`](../CONFIG.md#authorization)
- The settings: [docs/CONFIG.md `server.listeners[].opcua`](../CONFIG.md#serverlistenersopcua-kind-opcua)
- A worked configuration: [`examples/ot/opcua.yaml`](../../examples/ot/opcua.yaml)
- The protocol it replaced on most plants: [s7](s7.md)
- The other protocol whose policy is about what a value means: [modbus](modbus.md)
- The device bus that ended up beside it: [mqtt](mqtt.md)
