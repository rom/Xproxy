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
is how a policy gets written for equipment nobody has documentation for.

A refused request is answered with a Modbus **exception** — the protocol's own
"illegal data address" or "illegal function" — so the master's own library
reports it and the poll loop carries on. Dropping the connection because one
request was refused would turn a refusal into an outage.

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

## Standards

| Document | What it covers |
|----------|----------------|
| Modbus Application Protocol Specification V1.1b3 | The function codes, the data model and the exception codes |
| Modbus Messaging on TCP/IP Implementation Guide V1.0b | The MBAP header and the TCP behaviour |
| Modbus over Serial Line Specification V1.02 | The RTU and ASCII framings |
| Modbus/TCP Security Protocol Specification (2018) | TLS with mutual authentication and the role extension |
| IEC 62443 | The zone and conduit model a plant's security architecture is written against |

## See also

- The settings: [docs/CONFIG.md `server.listeners[].modbus`](../CONFIG.md#serverlistenersmodbus-kind-modbus)
- A worked configuration: [`examples/ot/modbus.yaml`](../../examples/ot/modbus.yaml)
- The other protocols on a plant: [s7](s7.md), [iec104](iec104.md),
  [bacnet](bacnet.md)
