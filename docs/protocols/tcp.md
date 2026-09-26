# TLS and QUIC passthrough — routing without terminating

`kind: tcp`, served by **xproxy**, any TCP port, and UDP for the QUIC variant.

The other listeners read a protocol so they can have a policy about it. This one
deliberately does not: it routes by the **server name in the handshake** and then
relays the bytes, so the TLS session stays end to end between the client and the
service.

That is a security property, not a limitation. A listener that terminated TLS
would hold the private key and see the plaintext, and there are services where
neither should be true of anything in the path.

## On the wire

Two handshakes, read for exactly one field each and no further.

**TLS**: a record-layer header (content type 22, a version, a length), a
`ClientHello`, and inside its extensions the **Server Name Indication** (RFC
6066) — the hostname the client is asking for, in the clear, because the
server has to know which certificate to present before it can encrypt anything.
Also visible there: the ALPN list, the supported versions, the cipher suites and
the extension ordering — which together make the **JA3/JA4 fingerprint** of the
client's TLS stack.

**QUIC**: a long-header Initial packet, whose payload is encrypted with keys
derived from the connection ID itself (RFC 9001's initial secrets), which means
anybody can decrypt an Initial packet. Inside it is a CRYPTO frame carrying the
same `ClientHello`, and therefore the same SNI — after the frames have been
reassembled, because a `ClientHello` may be split across several Initial packets.

**Encrypted Client Hello** (ECH) changes this: the real SNI is encrypted to the
server's public key and only an outer, decoy name is visible. A listener in front
of an ECH-enabled service sees the outer name.

## What the protocol gives you

TLS 1.3 gives the client a validated server identity and forward secrecy, and
this listener's whole design is to not get in the way of it. The client
validates the *service's* certificate, not the proxy's, so:

- No private key for the service lives on the proxy.
- No plaintext exists on the proxy.
- A compromise of the proxy does not yield the service's traffic.

What is visible without terminating is the SNI, the ALPN, and the handshake's
shape. That is enough to route and enough to fingerprint, and not enough to read
anything.

QUIC gives the same, with the addition that its Initial packets are readable by
design — which is what makes routing possible at all.

## What this listener decides

**The route, from the server name.** `routes` maps a name — exact, wildcard or
suffix — to an upstream pool, and `default` is what an unmatched name gets,
including nothing at all. A listener with no default has said only the names it
knows are served here, which is the difference between a proxy and an open relay.

**The destination, where the listener is transparent.** `transparent` and
`original_destination` read the kernel's original destination (`SO_ORIGINAL_DST`
or `IP_TRANSPARENT`) for a connection redirected into the proxy, and
`allow_destinations` with `destination_ports` bound where those may go — because
a transparent proxy with no destination policy is a route to anywhere for anything
that can reach it.

**The session's shape.** `idle_timeout`, `session_timeout`, `max_connections`,
and `max_bytes_in`/`max_bytes_out` — the byte bounds being the generic layer-4
control that has no protocol-specific equivalent: a session that has moved a
hundred gigabytes is not the session anybody configured this for.

**The bytes, where an estate wants that.** `yara` runs rules over the relayed
stream. It is worth being precise about what that means: the stream is encrypted,
so YARA here matches on what an encrypted stream looks like — which is useful for
a small set of things (a known plaintext protocol on an unexpected port, a
non-TLS payload) and is not content inspection.

**TLS-level refusal**, which happens before the relay: the handshake fingerprint
and the SNI are available to the ban list and the threat-intel lists, so a
client can be refused at the handshake rather than after a route is chosen.

**QUIC**, with `quic` and `quic_idle_timeout`, which is the same routing on UDP
with the Initial-packet reassembly the protocol requires.

## What it does not do

- **It does not terminate TLS.** By design and by definition. If you need to see
  the plaintext, the request belongs on an `http` listener (which terminates) or a
  `forward` listener with interception (which is explicit about it).
- **It does not see the plaintext**, and therefore no WAF, no header policy, no
  body scanning, no authentication. All of that needs termination.
- **It does not see the real name behind ECH.** An outer SNI is what a listener
  gets, and a policy written against it is a policy about the decoy. That is ECH
  working as designed, and a deployment that needs name-based routing has to
  terminate or not use ECH.
- **It does not validate certificates.** The client does that, against the
  service. The proxy has no opinion and holds no trust store for this path.
- **It does not read a client that sends no SNI.** No name means no route; `default`
  is the answer, and having no default means the connection is refused.
- **It does not multiplex.** One connection in, one connection out. HTTP/2 or
  HTTP/3 streams inside the tunnel are invisible, which is the point.

## Standards

| Document | What it covers |
|----------|----------------|
| RFC 8446 | TLS 1.3, and the `ClientHello` structure |
| RFC 6066 | Server Name Indication |
| RFC 7301 | ALPN |
| RFC 9000 | QUIC: the transport, the long header, Initial packets |
| RFC 9001 | Using TLS to secure QUIC — including the initial secrets that make an Initial packet readable |
| RFC 9114 | HTTP/3, the usual thing inside a QUIC tunnel |
| draft-ietf-tls-esni | Encrypted Client Hello |
| JA3 / JA4 (FoxIO) | The TLS client fingerprints |

## See also

- The settings: [docs/CONFIG.md `server.listeners[].tcp`](../CONFIG.md#serverlistenerstcp-kind-tcp)
- A worked configuration: [`examples/layer4/udp.yaml`](../../examples/layer4/udp.yaml) shows the sibling datagram relay
- When you need the plaintext instead: [http](http.md), [forward](forward.md)
- The generic datagram relay: [udp](udp.md)
