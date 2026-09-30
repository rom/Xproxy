# CoAP — REST for things too small to run TLS

`kind: coap`, served by **xot**, UDP **5683** (NoSec) and **5684** (DTLS).

CoAP is what a sensor, a valve, a street light, a smart meter or a
LwM2M-managed handset speaks. It is REST — a method, a path, a content format
and a payload — in a protocol that fits in a few hundred octets over UDP, for
devices with sixty kilobytes of flash and a coin cell.

That shape is the reason this listener can do more than bound bytes. On most
OT protocols a policy has a function code and a register number; here it has a
**path**, and the path is the device's object model. `PUT /3311/0/5850` turns a
light on. `GET /3303/0/5700` reads a temperature. An estate that can name its
equipment can name what may be done to it, which makes a positive security
model a sentence somebody can actually write rather than an aspiration.

## On the wire

Four octets of header, then a token, then options, then the payload.

| Field | Bits | What it says |
|-------|------|-------------|
| `Ver` | 2 | 1. Anything else is silently ignored |
| `T` | 2 | `CON` (acknowledged and retransmitted), `NON` (sent once), `ACK`, `RST` |
| `TKL` | 4 | The token's length, 0 to 8. **9 to 15 are reserved** |
| `Code` | 8 | Three bits of class and five of detail, written `c.dd`: `0.01 GET`, `2.05 Content`, `4.04 Not Found` |
| `Message ID` | 16 | Pairs an acknowledgement with what it acknowledges, and detects duplicates |
| Token | 0–8 octets | **Pairs a response with its request**, and is the only thing that does |
| Options | — | Delta-encoded type-length-value |
| `0xFF` + payload | — | The marker, then the body. No marker means no body |

Two of those need drawing out.

The **token, not the message identifier**, is the request/response pairing. A
response that was not ready in time arrives as a *separate* message with an
identifier of its own, so anything pairing on the identifier would lose it.

The **options are delta-encoded**: each option's number is the previous number
plus a delta, and the delta and the length are nibbles with two escape forms
(13 means one more octet, 14 means two, 15 is reserved). Nothing can be
skipped and nothing read out of order, so a length a reader does not check
puts every later option at the wrong offset — which is the one mistake in a
CoAP parser that turns a path policy into a decision about a different path
than the device will act on.

The options carry the request: `Uri-Path` (11, repeated once per segment),
`Uri-Query` (15), `Content-Format` (12), `Accept` (17), `Observe` (6),
`Block1` (27) and `Block2` (23), `Size1` (60) and `Size2` (28), `Proxy-Uri`
(35) and `Proxy-Scheme` (39), `ETag` (4), `If-Match` (1), `If-None-Match` (5),
`OSCORE` (9), `Echo` (252) and `Request-Tag` (292).

**The option number carries its own handling rules**, which is unusual and
useful. Odd numbers are **Critical**: a recipient that does not understand one
must refuse the message. Numbers with bit one set are **UnSafe to forward**: a
proxy that does not recognise one must not pass it on. So "I do not understand
this option" has a defined and safe answer — 4.02 Bad Option for a critical
one in a request, 5.02 Bad Gateway for an unsafe one — instead of a judgement
call, and the rule holds for options nobody has registered yet.

**Block-wise transfer** (RFC 7959) moves anything larger than a datagram in
numbered blocks: a block number, a more-to-come bit and a size exponent, in at
most three octets. The total is not in any one message — it is the block number
times the block size — so a bound on one datagram bounds nothing. `Size1` and
`Size2` are a *declaration* of the total, which is the one point at which
refusing a large transfer costs a single datagram.

**Observe** (RFC 7641) is a registration: a client asks once, and the device
sends notifications until somebody stops. It is how telemetry works here, and
it is the only request on this protocol whose answer has no end.

## What the protocol gives you

In the commonest deployment, nothing at all.

RFC 7252 §9 defines DTLS with pre-shared keys, raw public keys or
certificates — and it also defines **NoSec**, which is "no DTLS", and NoSec is
what most of the field runs. A vendor shipping a device with a coin cell and
sixty kilobytes of flash shipped it without a handshake. In NoSec there is no
identity whatsoever: not a weak one, none. So a policy has the source address,
the method, the path, the content format and the payload.

Where DTLS *is* deployed, it gives what TLS gives — and the session carries an
identity, which is a real name that a rule can require. That is what
`secure_only` and `security_names` are for, and it is the reason to put this
listener inside DTLS rather than beside it.

§9 has three ways for a peer to be somebody, and this listener serves all
three, because they are not a matter of taste:

| Mode | What the peer proves | What the policy names |
|------|----------------------|-----------------------|
| **PreSharedKey** (§9.1.3.1) | It holds the key for the identity it named in the clear | The identity, or a name the table maps it to |
| **RawPublicKey** (§9.1.3.2) | It holds the private key for a public key this listener pinned | The name the pinned key maps to |
| **Certificate** (§9.1.3.3) | A chain to an authority this listener trusts | `secure_only`, and a pinned key where the table has one |

The first is the one in the field. `TLS_PSK_WITH_AES_128_CCM_8` is mandatory
for it precisely because the device that needs it has sixty kilobytes of flash
and a coin cell: no chain to walk, no clock to check it against, no asymmetric
verification. A `psk` table turns DTLS on by itself — no `tls` section, no
certificate at either end — since an estate whose devices cannot hold
certificates usually has no authority of its own either.

What the identity buys is the difference between a policy about addresses and
a policy about devices. On a shared segment the source address is a guess
about which sensor sent something; `security_names: [hall-sensors]` is not.

A `tls` section on the listener is what turns it on. The certificates and the
client-certificate policy are the same configuration every other listener
uses, translated into DTLS rather than passed through, so a reload reaches a
running DTLS listener as it reaches a TLS one. `min_version: "1.3"` is an
error: §9 is DTLS 1.2 and DTLS 1.3 is not implemented here, which is better
said than ignored. What the listener adds is one session per remote address
demultiplexed from the one UDP socket, with the peers, the half-open
handshakes and the per-peer queue each bounded — because on UDP a peer that
starts a handshake has proved nothing, not even that it can receive.

**OSCORE** (RFC 8613) is the other answer: end-to-end object security, so the
request is authenticated and encrypted between the client and the device and a
relay in between can read nothing inside it. That is the right design for a
path that crosses untrusted proxies, and it is worth being plain about the
consequence here: a relay carrying an OSCORE request is carrying a request
whose method and path it cannot see, so the path policy applies to nothing.

Three properties make the insecure case worse than it looks.

- **It amplifies.** A four-octet `GET` over UDP can return a kilobyte, from a
  source address the sender chose. `/.well-known/core` exists to return a list
  of every resource on the device, which makes it the largest answer for the
  smallest question.
- **A device can be told to fetch.** `Proxy-Uri` and `Proxy-Scheme` turn the
  far end into a forward proxy. On a segmented network that is an open relay,
  an amplification stage and a route to what the segmentation was for, in one
  option — and two spellings of it, so refusing one refuses nothing.
- **A path segment is arbitrary octets.** Nothing on the wire stops a single
  `Uri-Path` segment containing a slash, so a joined path can look like two
  segments where the client sent one, and a `.` or `..` segment is a path a
  device may resolve.

## What this listener decides

**The methods.** The default is RFC 7252's four and not RFC 8132's three.
`fetch` is worth naming: it puts its selector in the *payload*, so a path
policy sees less of a `fetch` than of a `get`.

**The paths**, which is where most of the value is. `allow_paths` and the
rules' own `paths` are shell patterns over the whole path: `*` matches one
segment because it does not cross a separator, and a pattern ending `/...`
matches a subtree. The rules are the positive model — "this client may `GET`
anything under `/3303`, and `PUT` only `/3311/0/5850`" — and
`default_action: deny` means a request no rule covers is refused.

**A suspicious path is refused rather than normalised**, for the reason above:
normalising means deciding what the device would have done with the original,
and the guess is the bug.

**The option rules the standard gives.** An option this relay cannot name is
answered 5.02 if it is UnSafe and 4.02 if it is Critical, per §5.7.1 and
§5.4.1, and counted.

**Proxying is refused by default**, by either option.

**The sizes, and none of them is ever shadowed**: the payload, one block, the
whole block-wise transfer (read from `Size1` and `Size2` before the transfer
happens), the response, and — the one a per-datagram bound cannot make — the
**response as a multiple of the request**.

**Observe is bounded.** A registration has no timeout, so `max_observers`
answers "how many open-ended flows may exist" instead of leaving it to
whoever asked for the most.

**A refusal is answered.** Silence is the wrong answer to a Confirmable
request: it retransmits, so a dropped refusal becomes four or five more
requests and the device's log shows a timeout rather than a refusal.

**Which addresses may answer.** `allow_servers` defaults to the endpoints of
the upstream pool, and an answer from anywhere else is dropped and counted.

**The pairing.** The pending table is keyed on the device and the token,
because both are known on each side. `require_token` closes the degenerate
case of a client that sends no token at all.

### The imported lists, and the estate's authorisation policy

Both questions are asked about a client before anything reaches a device: the
imported address lists (`threat_intel`), and the `authorization` section on
the client address, the listener, the kind, the pool and the hour. On a
constrained network the address is often a device's only name, which makes the
lists more useful here than on DHCPv6 — where a client invents its own
link-local address — and less useful than on a protocol with a login.

Either shadow switch records what it would have refused and carries the
traffic, with the exception stated above: the size bounds and the
amplification factor are enforced regardless, because a listener that carried
an amplified answer and wrote it down would be an amplifier with logging.

## Behavioural detection

`anomaly` is the other half of the policy, and it needs nothing written down.
The rules answer *is this permitted*; the models answer *is this what this
client has been doing*. They are `internal/anomaly`, the same models every OT
kind runs, and [docs/CONFIG.md](../CONFIG.md) documents the block once. What is
specific to this protocol is the translation:

| The models' term | On CoAP | Used by |
|------------------|---------|---------|
| symbol | the method: GET, PUT, POST, DELETE | novelty, sequence |
| device | the security name the DTLS session mapped to, where there is one | talkers |
| point | the path, `/3303/0/5700`, which on an LwM2M device *is* the object model | novelty about writes |
| value | nothing | -- |

A write is PUT, POST or DELETE. The device is the security name rather than the
address because on this protocol an address is the weakest identity there is: a
constrained device behind a NAT changes address and a pre-shared key identity
does not.

**The two value models are inert here**, and the reference says so rather than
pretending: a CoAP payload is CBOR, SenML, plain text or a vendor's own encoding, and this relay does not decode it into numbers. So `telemetry` and `correlations` have nothing to compare
on this kind, and the other four models carry it.

## What it does not do

- **It is not a CoAP server.** There is no resource tree here and no cache. It
  relays to a device and reads what comes back.
- **It does not terminate the message layer.** It forwards the datagram as it
  arrived, with the client's own token and message identifier, and pairs on
  what is in it. A forward-proxy in the sense of RFC 7252 §5.7.2 would use its
  own tokens and identifiers, handle retransmission and acknowledge separate
  responses itself — a protocol engine rather than a relay that reads. The
  consequence is worth stating: two clients that choose the same token for
  concurrent requests to the same device cannot be told apart. §5.3.2 tells a
  client not to do that, and `require_token` closes the case where clients send
  no token at all.
- **It does not do CoAP over TCP, TLS or WebSockets** (RFC 8323). A different
  framing, with length prefixes instead of message identifiers and its own
  signalling codes, which almost nothing in the field speaks. A signalling code
  arriving over UDP is refused by name.
- **It does not read RFC 8974 extended tokens.** Token lengths 9 to 15 are
  reserved by RFC 7252 and RFC 8974 reuses 13 and 14 to mean "more length
  octets follow" — so the two readings disagree about where the options start,
  and a relay that guessed would be deciding about one message while the device
  acted on another.
- **It cannot see inside OSCORE.** An `OSCORE` option means the request is
  encrypted end to end, and the path policy applies to nothing. Refuse the
  option if that is not acceptable.
- **It does not rewrite a payload.** A value outside what an estate expects is
  refused, not corrected: a client and a device disagreeing about what was
  written is a fault that takes days to find.
- **It is not a substitute for DTLS.** In NoSec anything that can reach the
  segment can send a well-formed request from any address, and the only reason
  this relay helps is that it is the one place the request passes through.
- **It does not do DTLS 1.3.** RFC 7252 §9 is DTLS 1.2 and 1.3 is not
  implemented in the transport here, so `min_version: "1.3"` is a load error
  rather than a setting that quietly does nothing.
- **Raw public keys are pinned, not negotiated.** The policy is RFC 7250's —
  the key is the identity, nothing vouches for it, and `public_keys` names its
  SHA-256 — but the key travels inside a self-signed certificate rather than
  in RFC 7250's own `RawPublicKey` structure, because the DTLS library here
  does not negotiate the `client_certificate_type` and
  `server_certificate_type` extensions. A device that can only speak that
  structure cannot talk to this listener; one that can send a self-signed
  certificate around the same key can, and the handshake is a few hundred
  octets larger for it.
- **There is no forward secrecy in pre-shared key mode.** The only `ECDHE_PSK`
  suite the library implements is CBC-based, and offering the construction
  every attack on TLS record padding has been about, in order to gain a
  property, is not a trade this makes. The four AEAD PSK suites are offered;
  an estate that wants forward secrecy on this listener wants the certificate
  mode.

## Standards

| Document | What it covers |
|----------|----------------|
| RFC 7252 | The Constrained Application Protocol: the message layer, the options, the option classes, DTLS and NoSec, the three security modes, the proxy rules |
| RFC 4279 | The pre-shared key cipher suites, the identity a client sends and the hint a server offers |
| RFC 7250 | Raw public keys in TLS and DTLS: the mode whose *policy* this serves, by pinning the key a certificate carries |
| RFC 7959 | Block-wise transfers, and the Size1 and Size2 declarations |
| RFC 7641 | Observing resources: registration and notifications |
| RFC 6690 | The link format, and `/.well-known/core` resource discovery |
| RFC 8132 | The FETCH, PATCH and iPATCH methods |
| RFC 7967 | The No-Response option |
| RFC 8613 | OSCORE: object security, which a proxy cannot read inside |
| RFC 9175 | The Echo and Request-Tag options, the protocol's own freshness and amplification answer |
| RFC 8768 | The Hop-Limit option, for a chain of proxies |
| RFC 8323 | CoAP over TCP, TLS and WebSockets — not this listener |
| RFC 8974 | Extended tokens — deliberately not read; see above |

## See also

- The estate-wide policy above it: [docs/CONFIG.md `authorization`](../CONFIG.md#authorization)
- The settings: [docs/CONFIG.md `server.listeners[].coap`](../CONFIG.md#serverlistenerscoap-kind-coap)
- A worked configuration: [`examples/ot/coap.yaml`](../../examples/ot/coap.yaml)
- The other protocol whose policy is a path: [tftp](tftp.md)
- The other lightweight device bus: [mqtt](mqtt.md)
