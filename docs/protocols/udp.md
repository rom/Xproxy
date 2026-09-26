# UDP — the generic datagram relay

`kind: udp`, served by **xproxy**, any UDP port.

Every other listener in this project reads a protocol. This one does not: it is
the relay for a datagram protocol nobody has written a kind for, and what it
decides is therefore not about messages at all — it is about **who, how large,
how often, and how long**.

That is a smaller answer than the protocol-aware kinds give, and it is the honest
one. A relay that claimed to have a policy about a protocol it cannot parse would
be worse than one that says plainly what it bounds.

## On the wire

Nothing is assumed. A datagram arrives and a datagram is sent.

What UDP gives a relay to work with is much less than TCP:

- **There is no connection**, so there is no accept, no close, and no point at
  which a peer has proved it can receive. A *session* here is a construct: the
  relay remembers a client address for a while and sends replies back to it.
- **The source address is unverified.** A datagram's source is whatever the sender
  wrote. Every reply this relay sends is a reply to an address that may not have
  asked.
- **There is no back pressure.** A socket buffer fills and datagrams are dropped
  by the kernel, silently.
- **A datagram has a size**, and beyond the path MTU it fragments, which is its
  own class of problem.

The consequence that shapes this listener is **amplification**. If a small
request produces a large reply, and the source address is unverified, then the
relay is a device for pointing large replies at whoever the sender names. That is
how the DNS, NTP, SNMP, memcached and SSDP reflection attacks all worked, and it
is not a property of those protocols so much as of UDP.

## What the protocol gives you

Nothing at all. No authentication, no integrity, no confidentiality, no ordering,
no delivery guarantee, and a source address that is a field in a header.

Anything an estate has above UDP — DTLS, QUIC, NTS, SNMPv3, a protocol's own
MAC — is that protocol's, and this listener neither provides nor verifies it.

## What this listener decides

**Who may send.** `allow_clients` is an address list, and on UDP an address list
is worth what the network path makes it worth — but it is still the first and
cheapest control, and on a private network where the path is known it is a real
one.

**How large a datagram may be**, with `max_datagram_bytes`, in both directions.

**How many datagrams a session may carry**, with `max_datagrams`, and how many
bytes, with `max_bytes_in` and `max_bytes_out`. The *outbound* bound is the
amplification control: a session that has sent a hundred datagrams and received a
hundred megabytes is a session being used as an amplifier, whatever the protocol
inside it is.

**How often**, with `rate_limit`, per client address.

**How many sessions**, with `max_sessions` overall and `max_sessions_per_ip` —
the second mattering because a session here is a remembered address, and a
sender cycling through spoofed sources would otherwise create unbounded state.

**How long a session lives**, with `idle_timeout` and `session_timeout`. On a
protocol with no close, the timeout *is* the close, and a relay whose sessions
never expired would accumulate state until it ran out.

**Where it goes**, with `upstream` — and the pool machinery applies, including
UDP health checks, so an endpoint that has stopped answering is taken out of
rotation on a protocol that has no way to say so.

### The imported lists, and the estate's authorisation policy

A generic UDP relay knows nothing about who is connecting -- that is what makes it
generic. So two questions are asked about the client itself, once for a client that has no session, and before the endpoint is dialled:

- **the imported address lists** (`threat_intel`), about the client's address. A
  list whose action is `block` refuses; one that asks for a `challenge` is
  recorded like a log list, because there is no request here to serve a challenge
  into and turning it into a block would be a policy the operator did not write.
- **the `authorization` section**, on the client address, the listener, the kind,
  the upstream pool and the hour. A rule naming `users` matches nobody on this
  kind -- there is no identity to name -- so a rule here is written with
  `networks`, `targets` and `schedule`.

The lists are asked first: a list is an import about an address and says nothing
about this estate's intentions, so a refusal naming the feed sends an operator to
the feed rather than to a rule they would not find.

Asked once per client rather than once per datagram. The session table is keyed by
client, so a decision made where a session begins is a decision per client, and a
policy walk for every datagram of a flood would make the flood cheaper to send
than to refuse.

A refusal is the reason `threat_intel` or `authorization` on this listener's usual
deny event, so the counters, the security log and the ban list see it as they see
any other refusal. Either shadow switch -- `policy: {mode: shadow}` on the
listener, or `shadow: true` on the section -- records what it would have refused
and carries the traffic.

## What it does not do

- **It does not parse anything.** No messages, no commands, no addresses inside
  the payload. If the protocol matters, it wants a kind of its own — that is what
  the other twenty-seven are.
- **It does not verify the source address.** It cannot. What it can do is bound
  the reply so that a forged source costs an attacker more than it gains.
- **It does not do DTLS.** There is no handshake here to terminate.
- **It does not translate.** A datagram is relayed as it arrived, with no
  rewriting of anything inside it.
- **It does not guarantee delivery.** Neither does UDP. A datagram dropped
  because a bound was hit is counted; one dropped because a buffer was full is
  the kernel's.
- **It does not make a connectionless protocol into a session.** The session is a
  bookkeeping construct for routing replies and applying bounds, and it expires.

## Standards

| Document | What it covers |
|----------|----------------|
| RFC 768 | The User Datagram Protocol |
| RFC 8085 | UDP usage guidelines — the document behind most of the bounds here |
| RFC 4787 | NAT behavioural requirements for unicast UDP, which is where session-timeout practice comes from |
| RFC 5405 | The earlier UDP usage guidelines |
| RFC 4732 | Internet denial-of-service considerations, on reflection and amplification |

## See also

- The settings: [docs/CONFIG.md `server.listeners[].udp`](../CONFIG.md#serverlistenersudp-kind-udp)
- The estate-wide policy above it: [docs/CONFIG.md `authorization`](../CONFIG.md#authorization)
- A worked configuration: [`examples/layer4/udp.yaml`](../../examples/layer4/udp.yaml)
- The protocol-aware datagram kinds, which bound the same things *and* read the
  protocol: [dns](dns.md), [snmp](snmp.md), [ntp](ntp.md), [tftp](tftp.md),
  [dhcp](dhcp.md), [bacnet](bacnet.md), [syslog](syslog.md)
- The TCP sibling: [tcp](tcp.md)
