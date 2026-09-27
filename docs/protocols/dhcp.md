# DHCP — how a machine finds out where it is

`kind: dhcp`, served by **xrelay**, UDP ports **67** (server) and **68**
(client).

DHCP is how a machine learns its address, its gateway, its resolvers, its
domain, its boot server and — depending on the estate — its NTP servers, its
proxy configuration and its TFTP root. Everything a device knows about the
network it is on, it was told by DHCP, and it believed whatever answered first.

## On the wire

A fixed 236-octet header from the BOOTP days, and then options.

| Field | What it says |
|-------|-------------|
| `op` | Request or reply |
| `xid` | The transaction, which is how a client matches a reply |
| `ciaddr`, `yiaddr`, `siaddr`, `giaddr` | The client's current, the offered, the next-server and the **relay agent's** addresses |
| `chaddr` | The client's hardware address |
| `sname`, `file` | The boot server name and the **boot file** |
| options | Everything else, as type-length-value |

The message type is itself an option (53): `DISCOVER`, `OFFER`, `REQUEST`,
`DECLINE`, `ACK`, `NAK`, `RELEASE`, `INFORM`.

The options are where the configuration is: 1 the netmask, 3 the **routers**, 6
the **resolvers**, 15 the domain, 42 the NTP servers, 51 the lease time, 66 and
67 the **boot server and boot file**, 121 the **classless static routes**, 252
the proxy autoconfiguration URL.

Three encodings are worth knowing about because a naive reader misses options
because of them. **RFC 3396** lets a long option be split across several
instances, which have to be concatenated before the value means anything — and
lets options overflow into the `sname` and `file` fields, where a reader that
only walks the options area never sees them. **RFC 3046** adds option 82, the
relay agent information, whose sub-options a relay adds and a server keys policy
on.

A **relay agent** is the role this listener plays: it receives a broadcast from a
client, fills in `giaddr`, unicasts it to the server, and relays the answer back.

## What the protocol gives you

Nothing. There is no authentication in deployed DHCP. RFC 3118 defined it, and
it is not implemented anywhere that matters.

So the trust model is: a client believes the first answer, and the first answer
can come from anything on the segment. A rogue server that answers faster than
the real one hands out its own gateway (traffic interception), its own resolvers
(name interception), or its own boot file (code execution on the next boot).

Option 82 is the closest thing to an identity, and it is trustworthy only in one
direction: a *relay* adds it and the server can rely on it, but a **client** that
sends option 82 is claiming to be a relay.

## What this listener decides

The listener is a relay agent that **reads what it relays**, in both directions.

**Which servers may answer.** `allow_servers` is the single most useful line
here: a reply from anything else is not relayed, which is a rogue server
answering into the void.

**The message types**, so `RELEASE` and `DECLINE` — which a client can use to
release somebody else's lease — are a decision.

**The configuration a reply may carry**, option by option, and specifically:

| Setting | What it bounds |
|---------|----------------|
| `allow_gateways` | Which addresses may be handed out as the default route |
| `allow_resolvers` | Which may be handed out as the resolvers |
| `allow_boot_servers`, `boot_files` | Which next-server and which boot file — the option that decides what code runs on the next boot |
| `allow_routes` | The RFC 3442 classless static routes, which are a route table in an option |
| `min_lease_time`, `max_lease_time` | A five-second lease is a client that re-asks constantly; a year-long one is a lease nobody can revoke |
| `allow_options`, `deny_options`, `on_denied_option` | Everything else — and the denied ones can be **stripped from the reply** rather than refusing it, so a client keeps working without receiving what the policy excluded |

**`refuse_hidden_options`**, which is the RFC 3396 problem made a decision: a
reply whose options overflow into `sname` or `file` is a reply whose
configuration is somewhere a reader might not look, and a relay that cannot see
every option cannot have a policy about them.

**Option 82 in both directions.** `circuit_id` and `remote_id` are what this
relay adds; `on_client_agent_option` decides what happens when a *client* sends
option 82, which it has no business doing.

**`require_client_id_match`**, so a reply's client identifier has to match the
request it answers — a reply carrying somebody else's identifier is not an
answer to this client.

**The rate, per hardware address**, which is what a client cycling through
MAC addresses to exhaust a pool looks like.

### The imported lists, and the estate's authorisation policy

DHCP names nobody, and it is worth being plain about how little the address is
worth here: a client with no lease yet sends from `0.0.0.0`, which is what DHCP is
for. So the two questions asked about the client are asked, after this listener's
own `allow_clients` and before anything reaches a server, but one of them has
little to work with:

- **the imported address lists** (`threat_intel`), about the client's address. A
  list whose action is `block` refuses; one that asks for a `challenge` is
  recorded like a log list, because there is no request here to serve a challenge
  into and turning it into a block would be a policy the operator did not write.
- **the `authorization` section**, on the client address, the listener, the kind,
  the upstream pool and the hour. A rule naming `networks` decides nothing about
  exactly the clients an operator most wants to think about, and the imported
  lists have nothing to match against `0.0.0.0` either. What does decide here is
  `listeners`, `targets`, `actions` and `schedule`: "this segment is not relayed
  outside working hours" is a real rule, and it is the shape a rule on this kind
  should take.

What a client may ask for once it is through stays with this listener's own policy
above, which decides on the hardware address and the message type -- the fields
that actually name a device.

The lists are asked first: a list is an import about an address and says nothing
about this estate's intentions, so a refusal naming the feed sends an operator to
the feed rather than to a rule they would not find.

A refusal is the reason `threat_intel` or `authorization` on this listener's usual
deny event, so the counters, the security log and the ban list see it as they see
any other refusal. Either shadow switch -- `policy: {mode: shadow}` on the
listener, or `shadow: true` on the section -- records what it would have refused
and carries the traffic.

## What it does not do

- **It is not a DHCP server.** There is no lease database here. It relays to a
  server and reads what comes back.
- **It does not implement RFC 3118 authentication.** Nothing does.
- **It cannot stop a rogue server on the same segment.** `allow_servers` stops a
  rogue answer *through this relay*. A client that can hear a broadcast answer
  directly needs the switch's DHCP snooping, which is where that control belongs.
- **It does not do DHCPv6.** A different protocol with different messages; IPv6
  address assignment more often uses router advertisements anyway.
- **It does not rewrite addresses.** An offered address outside the policy is
  refused, not changed: a client and a server disagreeing about which address
  was leased is a fault that takes days to find.
- **It does not invent an identity.** A hardware address is a hint. It is
  trivially spoofed and this listener treats it as a rate-limiting key and a log
  field, not a credential.

## Standards

| Document | What it covers |
|----------|----------------|
| RFC 2131 | The Dynamic Host Configuration Protocol: the messages, the relay agent behaviour |
| RFC 2132 | The DHCP options and BOOTP vendor extensions |
| RFC 3046 | The relay agent information option (option 82) |
| RFC 3396 | Encoding long options: option concatenation and the `sname`/`file` overflow |
| RFC 3442 | The classless static route option (option 121) |
| RFC 3118 | Authentication for DHCP messages — defined, not deployed |
| RFC 4578 | Options for PXE clients |

## See also

- The estate-wide policy above it: [docs/CONFIG.md `authorization`](../CONFIG.md#authorization)
- The settings: [docs/CONFIG.md `server.listeners[].dhcp`](../CONFIG.md#serverlistenersdhcp-kind-dhcp)
- A worked configuration: [`examples/addressing/dhcp.yaml`](../../examples/addressing/dhcp.yaml)
- The other protocol in a provisioning path: [tftp](tftp.md)
