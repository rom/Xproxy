# AMQP — two protocols that share a name

`kind: amqp`, served by **xrelay**, TCP port **5672** (cleartext) and **5671**
(TLS).

AMQP is not one protocol. A client picks which of two it speaks in its **first
eight octets**, and the framing of everything after that follows from the
choice. This is the only listener here that reads two protocols on one port,
and the reason is the protocol family rather than a convenience.

## On the wire

Both versions open with `AMQP` and four octets naming the revision.

**AMQP 0-9-1** — what RabbitMQ speaks, and what almost every deployment means
when it says AMQP. A frame protocol with a class-and-method catalogue:

| Frame type | What it carries |
|------------|-----------------|
| Method | A class (connection, channel, exchange, queue, basic, tx, confirm) and a method within it, with typed arguments |
| Header | A content header: the body size, and a property flags word followed by the properties that are present |
| Body | Raw bytes of a message |
| Heartbeat | Nothing |

Arguments are typed: short and long integers, short and long strings, and
**field tables** — nested maps whose entries carry a one-octet type code. The
specification and RabbitMQ disagree about what `s` means, which is why a table
that does not lay out exactly has to be treated as unreadable rather than half
read.

**AMQP 1.0** — ISO/IEC 19464, a different protocol that kept the name. Nine
*performatives* (`open`, `begin`, `attach`, `flow`, `transfer`, `disposition`,
`detach`, `end`, `close`) over a self-describing type system, plus a SASL layer
with its own four frame bodies. The unit of authorisation is the **address a
link attaches to**; every transfer after the attach carries only a *link
handle*, so the address has to be remembered.

The two meet at the brokers that serve both, which spell a 1.0 address
`/exchange/X/key` and `/queue/Q` — the same nouns the 0-9-1 methods name.

## What the protocol gives you

**SASL, and TLS if you configure it.** Both versions authenticate through SASL,
and the mechanism every deployment uses is **PLAIN**: the username and the
password in one field separated by zero octets. In the clear unless the
transport is TLS, which is why `require_tls` is the setting that matters most
here.

The broker's own authorisation is per user and per virtual host. RabbitMQ's
model is three regular expressions — configure, write, read — for each user in
each vhost, which is more than most brokers offer, and it is administered
*inside the broker*: a change to it is not a change to a file anybody reviews
with the rest of the estate's configuration.

There is no in-protocol upgrade on 0-9-1: TLS is the port. AMQP 1.0 defines a
TLS protocol identifier in the header, which asks the peer to negotiate
transport security from the first octet.

## What this listener decides

**The version, before the broker is dialled** — because the header decides the
framing of everything after it. A client asking for a version this listener
does not serve is answered with a header the listener *does* serve, which is
what both specifications say to do, and never reaches the broker. 0-8 and 0-9
are never allowed: brokers answer them for compatibility, and a policy on a
revision from 2006 is not one worth writing.

**The mechanism and the identity, separately.** ANONYMOUS is not in the default
mechanism list, because it is a login with no identity for the broker to
attribute anything to. The *username* is read out of the SASL exchange for the
rules and the logs; the password is not — no code path between the wire and a
log line holds a broker credential. Whether the credential was accepted is
taken from the **broker's** answer, not the client's claim: a 0-9-1 broker that
refuses a password closes the connection instead of sending `connection.tune`.

**The virtual host**, decided before the exchange and queue lists, because a
name means something different in each vhost.

**Topology, which is off by default.** Declaring an exchange, deleting a queue,
binding, unbinding and purging are the broker's *configuration*, and an
application that publishes to an exchange somebody else declared needs none of
them. A client library that declares its own queue on connect becomes a
decision an operator makes rather than a default nobody noticed.

**The exchanges, queues, routing keys and link addresses** — including the
three a policy written against the obvious fields would miss:

| Where | What it names |
|-------|---------------|
| `x-dead-letter-exchange` on `queue.declare` | An exchange the broker will route this queue's rejected and expired messages to |
| `alternate-exchange` on `exchange.declare` | An exchange this one sends what it could not route to |
| `reply-to` in a message's properties | A queue a request-reply service will deliver its answer to |

All three go through the same lists as the field being declared, because
otherwise a client that may not publish to an exchange can have the broker
deliver to it.

The name lists are written in **AMQP's own topic language**, since that is what
an operator already knows from writing bindings: `*` is exactly one word, `#`
is zero or more, and an ordinary glob applies inside a word. The **default
exchange is named by the empty string**, so allowing publication to a queue by
name means writing `""` deliberately.

**The bounds**: the negotiated frame size, channels, links, methods, and the
size of a message — the last taken from the 0-9-1 content header before the
body arrives, and from the sum of a 1.0 message's transfers, because bounding
each transfer frame would bound nothing.

## What it does not do

- **A refusal ends the connection**, unlike every other relay kind here. AMQP
  is stateful in both directions: dropping one frame out of a conversation
  leaves the client waiting for a reply the broker was never asked for, or the
  broker answering a method the client never learned was refused. So the
  refusal is the protocol's own — a `connection.close` with reply code 403, or
  a 1.0 `close` carrying `amqp:unauthorized-access` — and both legs close.
- **It does not negotiate TLS from inside the protocol.** A 1.0 client that
  sends the TLS protocol identifier is refused and told which header to use; it
  should be given a TLS port instead.
- **It does not apply the allow lists inbound.** What the broker hands the
  client — `basic.deliver`, `basic.get-ok`, `basic.return` — is checked against
  the *deny* lists only. An allow list says what a client may ask for; a
  delivery names where a message came from, which a consumer need not be
  allowed to name, since a queue bound by somebody else delivers messages
  carrying that exchange's name. A deny list says something else — this
  connection must never see messages from there — and that holds both ways.
- **It does not police the negotiation's channel maximum.** RabbitMQ's default
  is 2047; refusing that would break every real client. Channels are *counted*
  instead, which is one enforcement mechanism for one bound.
- **It does not re-render a peer's frame.** The only frames it writes are its
  own refusals.
- **It is not the broker's authorisation.** It holds a boundary in front of the
  broker's, in a file that is reviewed with everything else.

## Standards

| Document | What it covers |
|----------|----------------|
| AMQP 0-9-1 specification (2008) | The frame layer, the class and method catalogue, the field table encoding |
| ISO/IEC 19464:2014 / OASIS AMQP 1.0 | The performatives, the type system, the link model and the SASL layer |
| RFC 4422 | SASL, whose mechanisms both versions use |
| RFC 4616 | The PLAIN mechanism |
| RFC 8314 | Implicit TLS, the pattern 5671 follows |

## See also

- The settings: [docs/CONFIG.md `## amqp`](../CONFIG.md#amqp)
- A worked configuration: [`examples/messaging/amqp.yaml`](../../examples/messaging/amqp.yaml)
- Operating it: [docs/TROUBLESHOOTING.md `## AMQP`](../TROUBLESHOOTING.md#amqp)
- The other messaging protocol here: [mqtt](mqtt.md)
