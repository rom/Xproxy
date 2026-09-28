# DHCPv6 — how a machine finds out where it is, on IPv6

`kind: dhcp6`, served by **xrelay**, UDP port **547** (server and relay).

DHCPv6 is the other half of a dual-stack estate's provisioning path, and it is
not DHCPv4 with longer addresses. It is a different packet format, a different
set of messages, a client identified by a **DUID** rather than by a hardware
address, a relay mechanism that **nests** whole messages rather than filling in
a field — and a set of options with no DHCPv4 equivalent at all, of which
**prefix delegation** is the one where a wrong answer is largest.

It is also the half an estate is most likely to have left unwatched. A network
that carefully polices DHCPv4 and has never looked at UDP 547 is a network where
the IPv6 path is the way in, and everything a device is told over it — its
resolvers, its search domains, its boot image, its captive portal, and the
border relay its *IPv4* traffic goes through — is told by something that answered
first.

## On the wire

Two headers, depending on who is speaking.

A **client's or a server's** message is four octets and then options:

| Field | Octets | What it says |
|-------|--------|-------------|
| `msg-type` | 1 | `SOLICIT`, `ADVERTISE`, `REQUEST`, `REPLY`, … |
| `transaction-id` | 3 | The transaction, which is how a client matches a reply |
| options | rest | Everything else |

A **relay's** message is thirty-four, because it carries two addresses:

| Field | Octets | What it says |
|-------|--------|-------------|
| `msg-type` | 1 | `RELAY-FORW` (12) or `RELAY-REPL` (13) |
| `hop-count` | 1 | How many relays have already handled it; 32 is the limit |
| `link-address` | 16 | **Which segment** the client is on, which is what tells the server what to allocate from |
| `peer-address` | 16 | The client's own address, or the previous relay's |
| options | rest | The relay's own options, and the **Relay-Message** option holding the whole original message |

That last point is the structural difference from DHCPv4, and it is the one a
reader has to get right: a relay does not annotate a client's message, it
**encapsulates** it. Option 9 holds the entire inner message, and a chain of
relays is a message inside a message inside a message. A reader that stops at
the outer layer sees nothing a client said, and a reader that follows the chain
without bounding it is a reader an attacker can nest until something gives.

Options are `code(2) length(2) value`, with no DHCPv4-style split encoding to
reassemble and no overflow into other fields — which is the one thing DHCPv6
made simpler.

The identity is the **DUID** (RFC 8415 §11): up to 128 octets, of four kinds —
link-layer plus time (1), enterprise number (2), link-layer (3) and UUID (4).
The two link-layer forms carry a MAC address, and that is the field that lets a
DHCPv6 sighting be attached to the device an estate already knows from DHCPv4.
A DUID is meant to be stable for the life of the device and is chosen by the
device, which is to say it is an identifier, not a credential.

Addresses and prefixes arrive inside **identity associations**: `IA_NA` (3) for
non-temporary addresses, `IA_TA` (4) for temporary ones, `IA_PD` (25) for
delegated prefixes, each holding `IAADDR` (5) or `IAPREFIX` (26) options with
the preferred and valid lifetimes in them. A client sends several legitimately,
which is why "the same option twice" cannot be a blanket refusal here.

## What the protocol gives you

Nothing, in any deployment you will meet.

RFC 8415 §20 does define authentication, and §21.11 an authentication option,
and the RECONFIGURE message §18.3.11 *requires* one. Nobody deploys the key
distribution that would make it mean anything. So the trust model is the DHCPv4
trust model: a client believes what answers, and what answers can be anything
that can reach it.

Two things make the IPv6 case worse rather than better:

- **There is more in an answer.** Alongside the resolvers and the search list,
  a reply can carry a boot file URL (RFC 5970), a captive portal URL
  (RFC 8910), an SZTP bootstrap server a switch will fetch a configuration from
  and apply to itself (RFC 8572), and the S46 transition containers and AFTR
  name (RFC 7598, RFC 6334) — which put a host's **IPv4** traffic through a
  border relay of the sender's choosing. That last one is a takeover of a
  protocol the message is not even about, arriving on a port nobody is watching.
- **A reply can tell a client to stop using the relay.** The Server Unicast
  option (12) says "address the server directly from now on", and a client that
  takes it has walked around every policy this listener has.

## What this listener decides

The listener is a relay agent that **reads what it relays**, in both
directions, and the shape of the policy is the DHCPv4 one because the shape of
the threat is the same: **answering is the attack**, so the interesting half
faces upstream.

**Which servers may answer.** `allow_servers` is the single most valuable line
in the file. A reply from anything else is dropped and counted whatever it says,
and an empty list means *the endpoints of the configured pool* — never
"anybody", because an operator who wrote nothing meant the servers they
configured.

**The message types**, so `RELEASE` and `DECLINE` are a decision, and so is the
lease-query family, which the default list leaves out: it is a relay agent's own
diagnostic, and an inventory of every lease in the estate to anything else.

**The configuration a reply may carry**, option by option:

| Setting | What it bounds |
|---------|----------------|
| `allow_resolvers` | Which addresses may be handed out as the resolvers — the check that catches a compromised real server as well as a rogue one. The resolvers are not on the built-in deny list, for the same reason option 6 is not on the DHCPv4 one: this list is the better check, and handing out resolvers is what stateless DHCPv6 exists for |
| `allow_domains` | Which search domains |
| `allow_boot_urls` | Which boot file URL, which is what code runs on the next boot. The patterns take square brackets literally, because a bracket in a URL is an IPv6 literal host and reading `tftp://[2001:db8::20]/*` as a character class would match nothing while looking like a policy |
| `deny_options`, `allow_options`, `on_denied_option` | Everything else, including the captive portal, the SZTP bootstrap server, the S46 containers and the Server Unicast option. The default is to **strip** and forward, so a client still gets its address and no longer gets what the policy excluded |
| `min_lease_time`, `max_lease_time` | The valid lifetime, on an address or a delegated prefix |
| `allow_reconfigure` | Whether a RECONFIGURE reaches a client at all. Off by default |
| `refuse_repeated_options` | An option twice where the standard has no second meaning is a message two implementations read differently |

**Prefix delegation, in both directions**, which is the part with no DHCPv4
equivalent. A reply delegating `::/0` has handed a host the whole of IPv6 to
route; a client asking for a /48 where the estate delegates /56s is asking for
two hundred and fifty-six times what it should have, and a real server that
grants it has given a segment away. `prefix_delegation.prefixes`,
`min_length` and `max_length` bound both ends, and a prefix outside the estate's
is a **refusal rather than a strip**: there is no useful half of a delegation to
keep. An `IA_PREFIX` hint of `::/0` *from a client* is allowed, because RFC 8415
§21.22 lets a client send one to mean "any".

**A zero valid lifetime is never bounded up.** Zero is how a server withdraws an
address (RFC 8415 §18.2.10), and a relay that applied `min_lease_time` to it
would turn a withdrawal into a lease — which is the bug that leaves a device
holding an address the estate has given to somebody else.

**The relay chain's depth.** `max_relay_hops` bounds the nesting, and a message
arriving already wrapped several times has been somewhere.

**The relay's own options in both directions.** `interface_id`, `remote_id` and
`subscriber_id` are what this relay adds (RFC 8415 §21.18, RFC 4649, RFC 4580);
`on_client_relay_option` decides what happens when a *client* sends one, which
is the client asserting which circuit it is on — exactly the assertion the
option exists to make on its behalf.

**The rate, per DUID.** This is the key that matters here: pool exhaustion is
one host sending thousands of SOLICITs with a made-up identifier in each, and a
limit keyed on the source address would see one sender doing nothing unusual.
`max_clients` is the other half — the rate limit slows one identifier down, and
that bound stops a flood of new ones filling the table doing the limiting.

**What it writes down.** `log_leases` is on by default and produces a line for
every address and prefix handed out: which identifier got which lease, for how
long, from which server, and what else that reply told it. That last part is
what a DHCPv6 server's own log does not have, because the server is the thing
being checked. The MAC address inside a link-layer DUID goes to the asset
inventory, which is what ties this device to its DHCPv4 self.

### The imported lists, and the estate's authorisation policy

It is worth being plain about how little the address is worth here, more so than
in DHCPv4. A DHCPv6 client sends from a **link-local address it chose for
itself**. It is in nobody's threat feed and it names nothing. So both questions
are asked about the client, before anything reaches a server, and one of them has
almost nothing to work with:

- **the imported address lists** (`threat_intel`), about the client's address. A
  list whose action is `block` refuses; one asking for a `challenge` is recorded
  like a log list, because there is no request here to serve a challenge into.
- **the `authorization` section**, on the client address, the listener, the kind,
  the upstream pool and the hour. What decides on this kind is `listeners`,
  `targets`, `actions` and `schedule` — "this segment is not relayed outside
  working hours" is a real rule and it is the shape a rule here should take.

What a client may ask for once it is through stays with this listener's own
policy above, which decides on the DUID and the message type: the fields that
actually name a device. Either shadow switch — `policy: {mode: shadow}` on the
listener, or `shadow: true` on the section — records what it would have refused
and carries the traffic.

## What it does not do

- **It is not a DHCPv6 server.** There is no lease database here. It relays to a
  server and reads what comes back.
- **It does not implement RFC 8415 authentication.** Neither does anything else.
- **It cannot stop a rogue server on the same segment.** `allow_servers` stops a
  rogue answer *through this relay*. A client that can hear a multicast answer
  directly needs the switch's DHCPv6 guard, which is where that control belongs.
- **It says nothing about router advertisements.** On many IPv6 networks a host
  gets its address and its gateway from an RA and never sends a DHCPv6 message at
  all, and RA guard is a switch feature, not a relay one. This listener polices
  the DHCPv6 path; it is not the whole of IPv6 provisioning.
- **It does not rewrite an address or a prefix.** One outside the policy is
  refused, not changed: a client and a server disagreeing about what was leased
  is a fault that takes days to find. The one value it does rewrite is a
  lifetime, which both ends re-read from every reply.
- **It does not invent an identity.** A DUID is chosen by the device. This
  listener treats it as a rate-limiting key, a log field and a rule selector, not
  a credential.
- **It is not the DHCPv4 listener.** An estate running both runs both, and
  writing both down is the point.

## Standards

| Document | What it covers |
|----------|----------------|
| RFC 8415 | DHCP for IPv6: the messages, the options, the relay agent, prefix delegation — it replaced RFC 3315, 3633, 3736, 4242, 7083, 7283 and 7550 |
| RFC 5007 | The leasequery messages, which the default type list leaves out |
| RFC 5460 | Bulk leasequery, over TCP — not this listener |
| RFC 5970 | The boot file URL and parameters options (59, 60) |
| RFC 8910 | The captive portal option (103) |
| RFC 8572 | Secure zero touch provisioning: the bootstrap server option (136) |
| RFC 7598 | The S46 softwire transition containers (94 to 97) |
| RFC 6334 | The AFTR name option for DS-Lite (64) |
| RFC 4649 | The relay agent remote-ID option (37) |
| RFC 4580 | The relay agent subscriber-ID option (38) |
| RFC 3646 | The DNS recursive name server and domain search list options (23, 24) |

## See also

- The estate-wide policy above it: [docs/CONFIG.md `authorization`](../CONFIG.md#authorization)
- The settings: [docs/CONFIG.md `server.listeners[].dhcp6`](../CONFIG.md#serverlistenersdhcp6-kind-dhcp6)
- A worked configuration: [`examples/addressing/dhcp6.yaml`](../../examples/addressing/dhcp6.yaml)
- The other half of a dual-stack estate: [dhcp](dhcp.md)
- The other protocol in a provisioning path: [tftp](tftp.md)
