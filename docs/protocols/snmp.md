# SNMP — the protocol that manages the network

`kind: snmp`, served by **xrelay**, UDP port **161** (requests), **162**
(traps and notifications), TCP **161** and **10161** (RFC 6353 TLS).

Every switch, router, printer, UPS and access point in an estate answers SNMP,
and almost every monitoring system speaks it. It is also, in its deployed
versions, a cleartext password in every datagram and one of the internet's
better amplification vectors.

## On the wire

A BER-encoded ASN.1 message. Three versions, and the difference between them is
entirely about security:

| Version | Identity | Confidentiality |
|---------|----------|-----------------|
| **v1** (RFC 1157) | A **community string** in the clear | None |
| **v2c** (RFC 1901–1908) | The same community string | None |
| **v3** (RFC 3410–3418) | A **USM** user with authentication and privacy keys | Optional: `noAuthNoPriv`, `authNoPriv`, `authPriv` |

The operations are few:

| PDU | What it does |
|-----|-------------|
| `GetRequest` | Read named objects |
| `GetNextRequest` | Read the object after this one — how a walk works |
| `GetBulkRequest` (v2c+) | A walk in one round trip, with a **max-repetitions** count |
| `SetRequest` | Write |
| `Trap`, `Trap2`, `InformRequest` | The device speaking first |
| `Response` | The answer, with an error status |

Objects are named by **OID**: a dotted path through a registered tree, where
`1.3.6.1.2.1` is the standard MIB-2 and `1.3.6.1.4.1.<n>` is a vendor's own
space. An OID prefix is therefore a subtree, which is what makes a policy
expressible: `1.3.6.1.2.1.2` is the interfaces table, and `1.3.6.1.2.1.4.22` is
the ARP table.

## What the protocol gives you

For v1 and v2c: a password, in the clear, in every single datagram. It is
usually `public` for reading, it is usually the same on every device in the
estate, and it is usually in the monitoring system's configuration where
several teams can read it.

For v3: real cryptography — HMAC authentication and DES, AES or AES-256
privacy, with per-user keys localised to each engine. It works, and the reason
it is not everywhere is that it needs a user provisioned on every device, which
is a project rather than a setting.

The **amplification** is structural, not a bug. A twenty-octet `GetBulkRequest`
with `max-repetitions` of a few hundred produces a response of many kilobytes,
over UDP, to whatever source address the request claimed.

## What this listener decides

**The versions.** A listener that admits only v3 has said the cleartext
password is not acceptable here — and, where a device cannot do v3,
`upgrade_version` is the honest middle: the relay speaks v3 to the estate and
v2c to the device, so the password stops crossing the part of the network people
use. (On the trap side the direction reverses: a v3 notification can be
downgraded for a collector that understands only v2c, which is the one version
rewrite that works end to end, because a notification has no answer to
authenticate.)

**The credential.** `communities` names the community strings that may be
presented, `users` the USM users, and `min_security_level` refuses a v3 message
that is authenticated but not encrypted. `upstream_community` lets the string
the device expects differ from the one the estate uses.

**`read_only`.** One line, no rule can override it, and it refuses every
`SetRequest`. It is the setting most SNMP deployments should have and almost
none do.

**The object subtrees.** A monitoring system needs the interface counters, the
system group and a vendor's environmental table. It does not need the ARP table
or the TCP connection table, which are a map of the network for whoever asks.
So the subtrees are listed, and those two are excluded from them.

**The amplification, by lowering rather than refusing.** A `GetBulkRequest`
whose `max-repetitions` is above `max_repetitions` has the count *lowered* and
is forwarded, because the poller is a monitoring system nobody can reconfigure
and an error would just make it retry. What cannot be lowered is refused:
`max_var_binds`, `max_response_bytes`, and `max_response_ratio` — a response
disproportionate to its request, which is the amplification measured rather
than guessed at.

**RFC 6353 TLS** on the stream side, which is SNMP over TLS on its own port
with real transport security, for the parts of an estate that can use it.

### The imported lists, and the estate's authorisation policy

SNMP does carry something that looks like a name -- a community on v1 and v2c, a
USM user on v3 -- and neither is an identity this estate can put in a rule: a
community is a shared word travelling in clear, and a USM user is the agent's own
account rather than a person's. So two questions are asked about the client
itself, after this listener's own `allow_clients`:

- **the imported address lists** (`threat_intel`), about the client's address. A
  list whose action is `block` refuses; one that asks for a `challenge` is
  recorded like a log list, because there is no request here to serve a challenge
  into and turning it into a block would be a policy the operator did not write.
- **the `authorization` section**, on the client address, the listener, the kind,
  the upstream pool and the hour. A rule naming `users` matches nobody on this
  kind, so a rule here is written with `networks`, `targets` and `schedule`.

Asked on each datagram from a manager, and on each stream connection: a datagram
relay has no session to hang the answer on. A refusal goes through this
listener's deny path, so a client that keeps sending earns a ban exactly as one
refused by `allow_clients` does, which is what keeps the record from being written
at packet rate. Which operations and which subtrees are allowed stays with this
listener's own policy above, because that is the thing that can say what a set on
`sysName` means.

The lists are asked first: a list is an import about an address and says nothing
about this estate's intentions, so a refusal naming the feed sends an operator to
the feed rather than to a rule they would not find.

A refusal is the reason `threat_intel` or `authorization` on this listener's usual
deny event, so the counters, the security log and the ban list see it as they see
any other refusal. Either shadow switch -- `policy: {mode: shadow}` on the
listener, or `shadow: true` on the section -- records what it would have refused
and carries the traffic.

## What it does not do

- **It does not verify v3 cryptography on behalf of the device.** The
  authentication and privacy parameters are read for the user name and the
  security level; the keys belong to the agent and the manager.
- **It does not rewrite a community string into a v3 credential.** The version
  upgrade is between the relay and each side separately: the estate's v3 user is
  authenticated by the relay's upstream configuration, not derived from the
  device's community.
- **It does not resolve MIBs.** The policy is written in OIDs, because a MIB
  file is a naming convenience and a relay that depended on having the right one
  loaded would be a relay with a configuration-dependent policy.
- **It does not make UDP authenticated.** A client list on UDP is worth what the
  network path makes it worth. v3 with `authPriv` is the answer, and this
  listener will require it.
- **It does not aggregate.** A walk is still a walk; this is a relay, not a
  caching poller.

## Standards

| Document | What it covers |
|----------|----------------|
| RFC 1157 | SNMP v1 |
| RFC 1901–1908 | SNMP v2c: the community-based framework, the protocol operations, `GetBulk` |
| RFC 3410–3418 | The SNMPv3 framework, the message processing model, USM and the MIBs |
| RFC 3826 | The AES cipher in USM |
| RFC 3430 | SNMP over TCP |
| RFC 6353 | Transport Layer Security Transport Model for SNMP |
| RFC 5343 | Context engine discovery |

## See also

- The estate-wide policy above it: [docs/CONFIG.md `authorization`](../CONFIG.md#authorization)
- The settings: [docs/CONFIG.md `server.listeners[].snmp`](../CONFIG.md#serverlistenerssnmp-kind-snmp)
- A worked configuration: [`examples/ot/snmp.yaml`](../../examples/ot/snmp.yaml)
- The asset inventory built partly from what this listener sees:
  [`examples/ot/inventory.yaml`](../../examples/ot/inventory.yaml)
