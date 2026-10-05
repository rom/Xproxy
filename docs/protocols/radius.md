# RADIUS — the protocol that lets people onto the network

`kind: radius`, served by **xrelay** or **xot**, UDP ports **1812**
(authentication), **1813** (accounting) and **3799** (dynamic authorization).

Every 802.1X switch port, every VPN concentrator, every wireless controller and
a good share of the administrative logins to routers go through RADIUS. It was
published in 1997, its entire cryptography is one shared secret and MD5, and it
is not going anywhere.

## On the wire

Twenty octets of header and then attributes:

| Field | Size | What it is |
|-------|------|-----------|
| Code | 1 | What the packet is: Access-Request (1), Access-Accept (2), Access-Reject (3), Accounting-Request (4), Access-Challenge (11), and RFC 5176's Disconnect and CoA (40–45) |
| Identifier | 1 | **Eight bits**, and the only thing pairing an answer to its question beyond the source address |
| Length | 2 | 20 to 4096. Octets past it are padding to be ignored; a length past the datagram means discard the packet |
| Authenticator | 16 | A nonce in a request, and a digest in a reply |

An attribute is a type octet, a length octet and a value. `Vendor-Specific`
(26) carries a vendor identifier and, by RFC 2865's *recommendation* rather
than its requirement, a vendor type and length inside that. RFC 6929's
extended attributes (241–246) put a second type octet at the front of the
value, so a rule about "attribute 241" is a rule about 256 of them.

Two values are computed rather than sent:

- The **Response Authenticator** is `MD5(code ‖ id ‖ length ‖ request
  authenticator ‖ attributes ‖ secret)`.
- The **Message-Authenticator** attribute (RFC 3579) is `HMAC-MD5` over the
  same octets with its own sixteen value octets zeroed.

`User-Password` is not encrypted. RFC 2865 §5.2 XORs it with a chain of MD5
digests over the secret and the request authenticator, so anybody holding the
secret reads it.

EAP arrives split across as many `EAP-Message` attributes as it needs, 253
octets at a time, to be concatenated in order.

## What the protocol gives you

One shared secret per client, and MD5.

There is no key agreement, no algorithm agility and no transport security.
What the secret buys is integrity on packets that carry a digest and
obfuscation on the password; what it does not buy is confidentiality on
anything else, so the user name, the realm, the NAS identifier, the VLAN and
the privilege level a reply grants are all in the clear on the wire.

Two consequences are worth stating plainly.

**Access-Accept and Access-Reject differ by one octet, and MD5 is
collidable.** An attacker on the path who can predict a request can compute a
chosen-prefix collision and turn a Reject into an Accept. That is
CVE-2024-3596, and the published mitigation is the Message-Authenticator
attribute, which the collision does not reach because it is keyed.

**The identifier is eight bits wide.** Two switches both using identifier 7 at
the same moment are indistinguishable to anything speaking to the server from
one socket, which is why a RADIUS proxy renumbers — and why renumbering needs
the secret, because changing an octet invalidates both digests.

RadSec (RFC 6614) fixes the transport by putting the whole thing inside TLS on
TCP 2083. It is a different transport with a different trust model and it is
not this listener.

## What this listener decides

**Whether the packet is authentic, before anything else is read.** Every field
a policy decides on is an attribute inside the packet, and an attribute inside
an unverified packet is whatever the last host on the path chose to put there.
So the digest is checked first, it is never shadowed, and
`require_message_authenticator` defaults on. A listener with no `secret_file`
says so in a warning at load and counts every packet it could not check.

**Which codes cross at all.** The default is the four a client sends. RFC
5176's Disconnect-Request and CoA-Request are deliberately absent: each ends or
re-authorises a live user's session from one datagram, they run from the server
towards the equipment rather than the other way, and a relay in the ordinary
position has no business carrying them.

**Which credential shapes and EAP methods are allowed.** `refuse_weak_eap`
defaults on and refuses EAP-MD5, LEAP and the bare token types: no server
authentication, no key material, and crackable offline from one observed
exchange. It is checked on the method in the packet *and* on the methods a Nak
offers instead, because a client that answers a PEAP request with a Nak naming
EAP-MD5 has asked the server to downgrade and a reader that looked only at the
packet's type would see a Nak, which is not a method.

**Which names and realms.** A realm is routing — a server proxies by it — so a
user name carrying one asks this estate to forward the credential somewhere
else. The three spellings the installed base uses (`user@realm`, `realm\user`,
`realm/user`) are split on the *first* separator, because that is how a server
reading left to right splits it, and a reader that disagreed about the realm
would be allowing a realm the credential does not go to.

**What a reply may grant.** This is the half most estates have no control over.
A client asks for access by logging in; the server's answer is what says this
login gets the enable prompt. `max_privilege_level` bounds the `priv-lvl` a
Cisco av-pair carries and `deny_administrative_replies` refuses `Service-Type =
Administrative-User`, so a compromised or spoofed server cannot hand out enable
across an estate of routers through this relay.

Both are read across the whole reply rather than from the first attribute that
parses: every av-pair, every pair inside one, and every `Service-Type`, with the
highest grant found being the one bounded. The reason is that which of two
`priv-lvl` pairs a platform acts on is the platform's business, and the av-pair
list is NUL-separated on some of them — so a reply spelling the grant the way an
attacker would was once a reply this relay read as granting nothing at all.

**That an answer belongs to a question.** The pairing is this relay's own: the
identifier it chose, the server it sent to, and a deadline. An answer with the
right identifier from the wrong host is refused as `unsolicited_reply`, which
is the shape of answer spoofing on a datagram protocol.

## What it does not do

- **It does not recover a password.** It reports that a request carried one and
  how long it was. The one exception is a listener configured with two secrets,
  where re-obfuscating under the second requires recovering the plaintext for
  the length of one packet — a listener with one secret never does.
- **It does not add a Message-Authenticator to a packet that has none.**
  Inventing one would change what the server sees a request as carrying, and on
  a protocol where the attribute's presence is itself policy it would be
  answering the question the policy asks.
- **It does not speak RadSec.** That is TLS on TCP 2083, a different transport.
- **It does not terminate EAP.** The method is policy and the exchange is
  relayed: terminating PEAP would mean holding the estate's server certificate
  and being the thing the supplicant authenticates, which is a different
  product.
- **It cannot see inside a tunnelled method.** Once EAP-TLS, PEAP or TTLS has
  its handshake, the inner identity and the inner credential are inside TLS
  this relay has no key for. `eap_types` buys which *outer* methods may be
  attempted, which is the decision that keeps EAP-MD5 off the network.
- **It does not authenticate anybody.** The server does. What this relay does
  is refuse the attempts the policy does not want made, and bound what the
  answers may grant.

## Standards

| Document | What it covers |
|----------|----------------|
| RFC 2865 | RADIUS: the packet, the attributes, the authenticators, the password obfuscation |
| RFC 2866 | RADIUS accounting, and the Accounting-Request authenticator |
| RFC 2869 | The extensions, including EAP-Message and Message-Authenticator |
| RFC 3579 | RADIUS support for EAP: the HMAC-MD5 digest and the fragmentation rules |
| RFC 3748 | EAP itself: the codes, the types, the Nak, the expanded type |
| RFC 4282 | The network access identifier, which is where `user@realm` comes from |
| RFC 5176 | Dynamic authorization: Disconnect-Request and CoA-Request |
| RFC 6929 | The extended attributes, 241 to 246 |
| RFC 6614 | RadSec, RADIUS over TLS (**not served**: a different transport) |
| RFC 7930 | Longer RADIUS packets on a stream transport (not applicable to UDP) |
| CVE-2024-3596 | The Response Authenticator collision, and why `require_message_authenticator` defaults on |

## See also

- The estate-wide policy above it: [docs/CONFIG.md `authorization`](../CONFIG.md#authorization)
- The settings: [docs/CONFIG.md `server.listeners[].radius`](../CONFIG.md#serverlistenersradius-kind-radius)
- A worked configuration: [`examples/auth/radius.yaml`](../../examples/auth/radius.yaml)
- The other protocol that authenticates network equipment, and the one with the
  commands in it: [tacacs](tacacs.md)
- What the refusals mean to an operations centre: [docs/ATTACK.md](../ATTACK.md)
