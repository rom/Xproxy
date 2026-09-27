# DNS — the name of everything

`kind: dns`, served by **xproxy**, UDP and TCP **53**, TLS **853**, QUIC **853**,
and HTTPS on whatever path is configured.

Name resolution is the first step of almost every connection an estate makes,
which makes the resolver two things at once: the place where a great deal of
policy can be applied cheaply, and the place where a compromise redirects
everything.

## On the wire

A 12-octet header — an ID, flags including the opcode and response code, and four
counts — followed by the question, answer, authority and additional sections.

Names are length-prefixed labels, and **compression pointers** let a name refer
back to an earlier offset in the message. That is the detail every DNS parser
must get right: a pointer that points forward, or at itself, or in a cycle, is a
parser loop, and a pointer into a name being parsed is how a malformed message
becomes an infinite one.

**EDNS(0)** (RFC 6891) adds an `OPT` pseudo-record carrying a larger UDP size, an
extended response code, and options:

| Option | What it carries |
|--------|----------------|
| **EDNS Client Subnet** (RFC 7871) | A prefix of the client's address, forwarded to the authoritative server so it can answer by location — and therefore a privacy leak by design |
| **DNS Cookies** (RFC 7873) | A client and server cookie, which is the protocol's own answer to off-path spoofing and reflection |
| Padding, keepalive, NSID, extended errors | |

The transports differ in what they protect:

| Transport | Protects |
|-----------|---------|
| UDP 53 | Nothing. Spoofable off-path unless cookies or 0x20 encoding are in use, and the reflection vector |
| TCP 53 | Spoofing, by requiring a handshake. Not confidentiality |
| **DoT** (RFC 7858), port 853 | Confidentiality and server authentication |
| **DoH** (RFC 8484), HTTPS | The same, and it is indistinguishable from other HTTPS traffic |
| **DoQ** (RFC 9250), QUIC 853 | The same over QUIC |

**DNSSEC** (RFC 4033–4035) signs the data rather than the channel: `RRSIG`
signatures, `DNSKEY` and `DS` records forming a chain from the root, and `NSEC`
or `NSEC3` proving that a name does *not* exist. It is what distinguishes "the
answer I got" from "the answer the zone's owner published".

## What the protocol gives you

On plain UDP, nothing: the answer is whatever arrived first with a matching ID
and port, which is why cache poisoning was a decade-long problem and why source
port randomisation, cookies and 0x20 encoding exist.

DNSSEC gives data authenticity where the zone is signed — and most zones are not.

DoT, DoH and DoQ give channel confidentiality and authenticate the *resolver*,
which is a different guarantee: you know you are talking to the resolver you
chose, and it can still tell you anything.

DNS is also the most reliable covert channel in an estate. It is allowed
everywhere, it leaves before authentication, and a name is arbitrary data: a
long label in a query to a domain an attacker controls is a byte of exfiltration,
and a `TXT` answer is a byte of command and control.

## What this listener decides

**Which names resolve at all**, with `block`, `block_file` and `block_action` —
sinkholed to a configured address, answered `NXDOMAIN`, refused or dropped — and
with `rpz`, the response policy zones an estate subscribes to, in the zone-file
format the feeds are published in.

**What the *answers* may say**, with `answer_policy`. This is the part a name
blocklist misses: a name nobody has listed can resolve to an address inside the
estate, which is DNS rebinding, and it is how a browser is made to reach an
internal service from an external page. So the answers are checked, not just the
questions.

**Whether the data is authentic**, with `dnssec`: validation with a trust anchor,
so a forged answer for a signed zone is refused rather than cached.

**What the clients get**, with `views` — split-horizon answers, so the same name
resolves differently inside and outside — and `records`, for the names this
resolver serves itself.

**Whether the client's address leaks**, with `ecs`. EDNS Client Subnet is
a privacy leak by design, and the policy is what decides whether a prefix of an
estate's internal addressing is sent to every authoritative server it queries.

**Whether this is a tunnel**, with `tunnel_detection`: the entropy and length of
the labels, the query rate to a single zone, the record types asked for, and the
proportion of answers that are `NXDOMAIN` — which together are what exfiltration
looks like and what ordinary resolution does not.

**The cache**, with `cache`, including serve-stale and prefetch, and the
aggressive NSEC use that lets a signed negative answer cover names nobody has
asked about yet.

**The amplification and the spoofing**, with `rate_limit`, `max_in_flight`, and
`cookies` with `cookie_lifetime` — the last being the protocol's own control, and
the right one: a client that has a cookie is a client that completed a round trip.

**The transports**, each on its own: `doh_path`, `doq`, DoT through the listener's
TLS, and `discovery` for the DDR and SVCB records that tell a client this
resolver has an encrypted version.

**`dns64`**, for the IPv6-only networks that need synthesised addresses.

**A resolver that is not there.** `deception` answers as a fabricated resolver: on
a real listener, in the four places a refusal would otherwise say the name does not
exist -- the block list, an imported name list, a policy zone whose action is
`nxdomain`, and the cooldown on a domain a client was caught tunnelling under -- or
as a whole listener with nothing behind it.

The refusal is the reason this earns its keep here. On every other protocol in this
set a refusal costs the other end a request; here it costs them the *conversation*,
because the query is all they ever send. A name on a feed answered NXDOMAIN tells
an implant something on this network is deciding, and it has a list of other names
to try. A tunnel told NXDOMAIN moves channel, and the channel it moves to is the
one nobody is watching. A fabricated answer keeps both of them talking.

Two things here are specific to DNS, and both are about not becoming a weapon.
A resolver is an amplifier, so a fabricated answer to a client whose address
nothing has verified is bounded against the query that asked for it and truncated
past that bound: a real client comes back over TCP, a spoofed source cannot. And a
fabricated address is somewhere a visitor then goes, so the default pool is the
documentation range of RFC 5737 and RFC 3849, which nothing routes. Pointing the
pool at your own honeypot collects the next step as well, and is the one
configuration that has to be deliberate.

It answers a different address for every name, which is the difference between
this and `sinkhole_ipv4`: a sinkhole answers one address for everything, so two
lookups find it. On a decoy listener, `cookies: require` is worth its
compatibility cost -- nothing amplifies either way, but without cookies the
address in the record is the one the datagram claimed. See
[docs/DECEPTION.md](../DECEPTION.md#a-resolver-that-is-not-there).

### The imported lists, and the estate's authorisation policy

A query names nobody: the protocol carries no identity at all, and the one field
that looks like one -- the source address -- is a datagram's unproven claim about
itself. So two questions are asked about the client itself, after this listener's
own `allow_clients`:

- **the imported address lists** (`threat_intel`), about the client's address. A
  list whose action is `block` refuses; one that asks for a `challenge` is
  recorded like a log list, because there is no request here to serve a challenge
  into and turning it into a block would be a policy the operator did not write.
- **the `authorization` section**, on the client address, the listener, the kind,
  and the hour. A `dns` listener has a list of resolvers rather than an upstream
  pool, so the subject carries no target and a rule's `targets` names nothing
  here; a rule that wants to say where a query may point is talking about a
  domain, which belongs to this listener's own policy above. A rule naming `users`
  matches nobody either, so a rule here is written with `networks`, `listeners`
  and `schedule`.

The imported lists asked here are asked about the **address**, which is separate
from the domain lists this listener already consults about a **name**. A refusal
on an unverified datagram is counted but attributed to nobody -- aggregated into
one record rather than written against the address the packet claims to come
from -- for the same reason a blocked name is: a record written against an address
anybody could have put in a datagram is a record anybody could have written
against a third party.

The lists are asked first: a list is an import about an address and says nothing
about this estate's intentions, so a refusal naming the feed sends an operator to
the feed rather than to a rule they would not find.

A refusal is the reason `threat_intel` or `authorization` on this listener's usual
deny event, so the counters, the security log and the ban list see it as they see
any other refusal. Either shadow switch -- `policy: {mode: shadow}` on the
listener, or `shadow: true` on the section -- records what it would have refused
and carries the traffic.

## What it does not do

- **It is not authoritative.** `records` serves the handful of names an estate
  wants answered locally; this is a resolver with a policy, not a zone server.
- **It does not sign.** DNSSEC is *validated* here, not produced. A relay that
  re-signed would be attesting to data it did not author, which is the opposite of
  what DNSSEC is for.
- **It does not resolve from the root itself.** It forwards to the upstreams
  configured, over the transport configured, and validates what comes back.
- **It does not rewrite an answer to make it pass.** An answer the policy refuses
  is refused; an answer that fails validation is `SERVFAIL`. Rewriting would make
  the resolver the authority on data it is checking.
- **It cannot see a client that resolves elsewhere.** A machine using DoH to a
  public resolver is not using this one, and the control for that is the network
  and the endpoint configuration, not this listener.
- **A fabrication answers four types and invents nothing else.** A, AAAA, TXT and
  PTR; everything else is NODATA. Inventing an MX would mean inventing a mail host
  to go with it, and an NS or SOA would be a claim of authority a forwarding
  resolver is not making. The TXT answer carries no command: the fabrication does
  not know the other end's protocol and will not guess at one. What it has is the
  right shape, and a tunnel that accepts an answer sends the next chunk.
- **A fabrication does not name itself.** `version.bind`, `hostname.bind` and
  `id.server` raise the tripwire and are never answered, because a resolver that
  names its own version has handed over the list of what it is vulnerable to --
  and one that names a version it is not is caught by whoever knows what that
  version really says.
- **It does not catch every tunnel.** Tunnel detection is a set of signals with
  thresholds. A slow, low-entropy tunnel inside a domain an estate legitimately
  uses is hard, and the honest statement is that the detection raises the cost
  rather than closing the channel.

## Standards

| Document | What it covers |
|----------|----------------|
| RFC 1034, 1035 | Domain names: concepts, and the implementation and specification |
| RFC 2181, 2308 | Clarifications, and negative caching |
| RFC 6891 | EDNS(0) |
| RFC 7871 | EDNS Client Subnet |
| RFC 7873, 9018 | DNS Cookies, and interoperable cookies |
| RFC 4033, 4034, 4035 | DNSSEC: introduction, resource records, protocol modifications |
| RFC 5155 | NSEC3 |
| RFC 8198 | Aggressive use of DNSSEC-validated cache |
| RFC 7858 | DNS over TLS |
| RFC 8484 | DNS Queries over HTTPS |
| RFC 9250 | DNS over Dedicated QUIC Connections |
| RFC 9460, 9461, 9462 | SVCB and HTTPS records, DoT parameters, and Discovery of Designated Resolvers |
| RFC 6147 | DNS64 |
| RFC 8482 | Refusing `ANY` queries |
| RFC 5452 | Measures against forged answers |

## See also

- The settings: [docs/CONFIG.md `server.listeners[].dns`](../CONFIG.md#serverlistenersdns-kind-dns)
- The estate-wide policy above it: [docs/CONFIG.md `authorization`](../CONFIG.md#authorization)
- Worked configurations: [`examples/blocklists/dns.yaml`](../../examples/blocklists/dns.yaml), [`dns-encrypted.yaml`](../../examples/blocklists/dns-encrypted.yaml), [`dns-rpz.yaml`](../../examples/blocklists/dns-rpz.yaml) and [`dns-tunnel.yaml`](../../examples/blocklists/dns-tunnel.yaml)
- The generic datagram relay, for a UDP protocol with no kind of its own:
  [udp](udp.md)
