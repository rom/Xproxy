# SNMP — the protocol that manages the network

`kind: snmp`, served by **xrelay** or **xot**, UDP port **161** (requests), **162**
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
| **v3 + TSM** (RFC 5591, RFC 6353) | The peer's **certificate**, from the (D)TLS session — the message itself carries no credential at all | The session's: `authPriv` by construction |

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

For v3 with the **transport security model**: nothing in the message, which is
the point. RFC 5591 takes the security parameters out entirely — no user, no
engine identifier, no clock, no digest — because RFC 6353's (D)TLS session
already authenticated and encrypted it. What identifies the sender is the
certificate its peer presented, which is an identity an estate already knows how
to issue, revoke and rotate; USM's per-user-per-engine pass phrase is a
spreadsheet nobody rotates. Two consequences fall out of the missing digest: a
refusal can be *answered*, and a request can be *rewritten*, both without a key
for the manager, because there is not one.

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

**Version 3 toward the agent, when the manager cannot speak it.**
`upgrade_version: v3` with `upstream_usm` terminates whatever security the
manager used and originates a USM session of the relay's own. That is the
deployment this protocol needs most -- the equipment was replaced, the polling
system was not -- and it means a v1 or v2c poller reaches a v3-only agent with
authentication and privacy it cannot speak, using a pass phrase it never holds.

The engine identifier is discovered rather than configured, because USM
authenticates against the authoritative engine's clock and that engine is the
agent. A first request to a cold agent draws a discovery, carries the manager's
own request identifier through it so the waiting question is the one that gets
asked, and a burst to a cold agent sends one discovery rather than one each.

The cost is not hidden: there is no end-to-end authentication between the
manager and the agent any more. The manager authenticates to the relay and the
relay authenticates to the agent, so this process is a party to the security
rather than a reader of it. Validation says so when `upstream_usm` is
configured, and an estate that wants USM end to end wants `usm_users` and no
upgrade.

**Version 3, read rather than taken on trust.** `usm_users` gives the listener
the pass phrases of the v3 users whose traffic it should be able to read. The
key derivation is RFC 3414 §2.6 -- a megabyte of repeated pass phrase hashed and
then localised to the engine identifier in the message -- so the relay derives
the same key both ends derived, verifies the digest, and at `authPriv` decrypts
the scoped PDU.

This closes a gap that was the wrong way round. Without keys, a v3 message was
a header and an opaque payload: the user, the engine and the level were checked
and nothing else could be, so `read_only` and every rule about an operation or
an object subtree applied to v1 and v2c and silently did not apply to v3 -- the
version an operator is told to insist on. With keys they apply to all three.

It also makes an `authPriv` exchange work end to end on the datagram path. An
encrypted answer has no readable request identifier, and the identifier is the
only thing that pairs an answer with its question, so before the keys existed
such an answer could not be matched to the manager that asked and was dropped.

Two refusals exist because of the keys. A user with keys arriving at
`noAuthNoPriv` is refused (`snmp_usm_downgrade`): clearing the flags asks the
relay to stop checking rather than to produce a digest, and it is the cheapest
forgery on this protocol. And a message whose clock has gone backwards past
`replay_window` is refused (`snmp_replay`), which is RFC 3414 §2.2.3's own time
window and the one thing a digest alone does not give.

Nothing is re-signed or re-encrypted. The octets forwarded to the agent are the
octets that arrived.

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

**RFC 6353**, on both transports. `tls_mode: implicit` is the stream half (TCP
10161) and `dtls_mode: implicit` the datagram half (UDP 10161), which is the one
this protocol actually runs on. Inside either, `cert_to_name` is RFC 6353 §5.3's
`snmpTlstmCertToTSNTable`: rows in order, first match wins, each saying which
certificate it is about and how to derive a name from it — `specified`,
`san_rfc822`, `san_dns`, `san_ip`, `san_any`, or `common_name`, which the
standard provides and advises against. That name is what `security_names` on a
rule names. It is the *session's* name rather than something a message carried,
so such a rule covers every message in a session whose certificate mapped —
including a v2c poller that has been given a certificate, which is the
half-migrated case worth being able to write a rule about — and covers nothing
from a session that derived no name. `users` is the other kind of credential,
the one in the message, and one message is never both.

`dtls_mode: detect` takes records and plain datagrams on the same socket,
because a DTLS content type (20–25, followed by a version whose major octet is
`0xFE`) and a BER SEQUENCE (`0x30`) cannot be read as each other. The standard
gives DTLS a port of its own, so this is not RFC 6353's arrangement; it is for
the estate whose new managers speak DTLS and whose two hundred field switches
are not going to be reconfigured to a new port. The cost is that the client
chooses which to speak, so the *policy* is what requires the certificate —
`transports` on a rule, and `default_action: deny`. Validation says so when a
`detect` listener's rules name neither.

Four checks come with the model, before the rules:

- A message whose certificate maps to **no name** is refused
  (`tsm_no_name`), because a transport model message with no derived name has no
  credential at all. `require_security_name: false` is the listener saying it
  wants the session for confidentiality and will decide on the address and the
  objects alone.
- A message on a transport that **provides no security at all** is refused
  (`tsm_transport`): the model's claim is that the transport authenticated and
  encrypted it, and on a plain datagram nothing did. That one holds whatever
  `require_security_name` says, because it is about whether the message's own
  statement is true rather than about whether a name is needed.
- A message claiming **less than the session gave** is refused (`tsm_level`).
  RFC 5591 §3.1.1 has the sender copy the flags from the transport's security
  level and RFC 6353 §3.1.2 says a (D)TLS transport provides `authPriv`, so
  `authNoPriv` inside DTLS is a sender that did not implement the model or is
  asking whether this listener reads the flags as policy.
- **Cleartext at a listener that requires DTLS** is counted and dropped
  (`cleartext_at_dtls_listener`) rather than answered: there is no session to
  answer in, and answering tells a scanner something is here.

And the rewrite the model makes possible: a v3 request under it **can** be
downgraded to v2c, because its answer needs no key either. A manager holding
nothing but a certificate reaches a switch that will never speak anything but
v2c, with an `upstream_community` it never learns, and the switch's v2c answer
comes back rebuilt in the manager's own v3 envelope — the message identifier,
the context and the level echoed, and nothing signed, because there is nothing
to sign.

### An agent that is not there

`deception` answers as a device the estate does not have: `mode: decoy` is a
whole listener with no upstream, and `mode: answer` fabricates, on a listener
that fronts a real agent, the answers to requests it was going to refuse.

Two things make it worth having on this protocol in particular. A refusal here
is about a *credential*, so it is the oracle a community-string list needs.
And the system group is the estate's own inventory, read first by every
scanner and by the monitoring the estate runs itself — which means no policy
can make that answer less informative without breaking both.

What bounds it is the usual test — a request that was going to reach the agent
is never answered from here — and one bound this protocol adds: a fabricated
agent is a UDP service answering a small request with a larger response, which
is what an amplifier is. The listener's own `max_repetitions`, `max_var_binds`
and `max_response_bytes` therefore bound the fabrication exactly as they bound
an agent's answer, and an answer past the size bound becomes `tooBig`.

The fabrication serves the system group and the interface table, and a walk of
it is a walk: strictly increasing, and it ends. It does not answer version 3 —
the response would carry a digest this relay cannot compute — and it does not
answer a notification. See
[docs/DECEPTION.md](../DECEPTION.md#an-agent-that-is-not-there).

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

## Behavioural detection

`anomaly` is the other half of the policy, and it needs nothing written down.
The rules answer *is this permitted*; the models answer *is this what this
client has been doing*. They are `internal/anomaly`, the same models every OT
kind runs, and [docs/CONFIG.md](../CONFIG.md) documents the block once. What is
specific to this protocol is the translation:

| The models' term | On SNMP | Used by |
|------------------|---------|---------|
| symbol | the PDU type: `get`, `get-next`, `get-bulk`, `set`, `trap` | novelty, sequence |
| device | the credential -- the community string for v1 and v2c, the USM user for v3, the security name for the transport model | talkers |
| point | the first binding's object identifier | novelty about writes |
| value | nothing | -- |

The device is the **credential** because on this protocol that is what a poller
*is*: one network management station polls from several addresses and every one of
them presents the same community string. A write is a SET, so
`anomaly_new_write_point` reads as "this manager has never set that object",
which is one of the more useful things a relay can say about an estate that
configures its switches over SNMP.

**The two value models are inert here**, and the reference says so rather than
pretending: a binding's tag is read and not interpreted -- a policy about SNMP values would need a MIB per estate. So `telemetry` and `correlations` have nothing to compare
on this kind, and the other four models carry it.

## What it does not do

- **It does not sign or encrypt with `usm_users`.** Those keys are for reading:
  the digest is verified and the payload decrypted, and the octets forwarded to
  the agent are the octets that arrived, so there is no way for the relay to
  hand the agent something the manager did not write. The agent still verifies
  for itself; the relay's check is in addition to that, not instead of it.
  Originating a message of the relay's own is `upstream_usm`, below, and it is a
  separate decision.
- **It does not derive one credential from another.** `upstream_usm` is an
  identity an operator configured, not a community string turned into a USM
  user. The two sides of the relay hold separate secrets, which is the point.
- **It does not resolve MIBs.** The policy is written in OIDs, because a MIB
  file is a naming convenience and a relay that depended on having the right one
  loaded would be a relay with a configuration-dependent policy.
- **It does not suppress duplicates.** The replay window refuses a datagram
  whose clock has gone backwards, which is what a capture replayed later looks
  like. A datagram replayed *within* the window is indistinguishable from the
  original to anything but the agent's own request-identifier cache.
- **It does not make UDP authenticated.** A client list on UDP is worth what the
  network path makes it worth. v3 with `authPriv` is the answer, and this
  listener will require it -- and, with `usm_users`, check it.
- **It does not aggregate.** A walk is still a walk; this is a relay, not a
  caching poller.
- **It does not speak DTLS to the agent.** `dtls_mode` is the half facing the
  management station. Towards the equipment there is plain UDP, plain TCP, or
  RFC 6353 TLS with `upstream_tls_mode` — which is the whole point of relaying
  it, because the equipment is what cannot be changed.
- **It does not turn a certificate into a USM user.** A name derived from a
  certificate is what the policy here decides on; it is not carried into a
  message towards the agent. Where the agent needs a v3 identity, that identity
  is `upstream_usm` and an operator configured it.
- **It does not accept MD5 fingerprints.** A `cert_to_name` row's fingerprint is
  an identity, so an algorithm whose collisions are a weekend's work is refused
  at load. RFC 6353's other four are accepted, and SHA-1 draws a warning.

## Standards

| Document | What it covers |
|----------|----------------|
| RFC 1157 | SNMP v1 |
| RFC 1901–1908 | SNMP v2c: the community-based framework, the protocol operations, `GetBulk` |
| RFC 3410–3418 | The SNMPv3 framework, the message processing model, USM and the MIBs |
| RFC 3826 | The AES cipher in USM |
| RFC 7860 | HMAC-SHA-2 authentication in USM |
| RFC 3430 | SNMP over TCP |
| RFC 6353 | The (D)TLS transport model: the transports, the certificate-to-name table, the ports |
| RFC 5591 | The transport security model: the SNMPv3 message that carries no security of its own |
| RFC 6347 | DTLS 1.2, which is what the datagram half runs on |
| RFC 5343 | Context engine discovery |

## See also

- The estate-wide policy above it: [docs/CONFIG.md `authorization`](../CONFIG.md#authorization)
- The settings: [docs/CONFIG.md `server.listeners[].snmp`](../CONFIG.md#serverlistenerssnmp-kind-snmp)
- A worked configuration: [`examples/ot/snmp.yaml`](../../examples/ot/snmp.yaml)
- The asset inventory built partly from what this listener sees:
  [`examples/ot/inventory.yaml`](../../examples/ot/inventory.yaml)
