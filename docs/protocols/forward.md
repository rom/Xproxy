# The forward proxy — CONNECT, SOCKS5 and MASQUE

`kind: forward`, served by **xproxy**, usually TCP **3128** or **8080**.

Every other listener in this project faces inward: a client reaches a service the
estate runs. This one faces outward — the estate's own machines reach the internet
through it — which inverts what a policy is about. The question is not "who may
reach this service" but **"where may this machine go, and what may it send"**.

## On the wire

Four ways to ask for a tunnel, and this listener serves all of them on the same
port where configured.

**HTTP `CONNECT`** (RFC 9110 §9.3.6). `CONNECT example.com:443 HTTP/1.1`, a
`200` reply, and then the bytes are relayed. The request line names the
destination and nothing else about it is visible.

**HTTP/2 and HTTP/3 `CONNECT`** (RFC 9113 §8.5, RFC 9114). The same, as a stream
with an `:authority` pseudo-header and no `:path` — so a single connection to the
proxy carries many independent tunnels.

**SOCKS5** (RFC 1928). A greeting listing authentication methods, a method
selection, optionally a username/password exchange (RFC 1929), and then a request:
`CONNECT`, `BIND` or `UDP ASSOCIATE`, with the destination as an IPv4 address, an
IPv6 address or a **domain name**. The domain-name form matters: it means the
proxy resolves the name, so the client's DNS does not have to be right and the
proxy's policy applies to the name rather than to whatever the client resolved it
to.

**MASQUE**: `CONNECT-UDP` (RFC 9298) tunnels UDP over HTTP, and `CONNECT-IP`
(RFC 9484) tunnels IP packets. Both use the extended CONNECT method with a
`:protocol` pseudo-header, and both are how a modern VPN-shaped thing is built on
HTTP.

## What the protocol gives you

The tunnel protocols themselves give almost nothing. `CONNECT` has HTTP's own
authentication — `Proxy-Authorization`, usually Basic, which is a base64 password
unless the leg to the proxy is TLS. SOCKS5's username/password method (RFC 1929)
is the same in a different encoding. SOCKS5 also defines GSSAPI (RFC 1961), which
is rarely used.

What the tunnel *carries* is opaque by construction. That is the point of a
tunnel, and it is also why an unrestricted forward proxy is one of the most
useful things an attacker can find inside an estate: it is an egress path that
bypasses whatever the network's own rules were, and a way to reach services that
believe they are internal.

## What this listener decides

**The destination.** `allow` and `deny` are the core: host patterns and port
lists, evaluated deny-first. A forward proxy without a destination policy is not
a security control.

**`allow_private`**, which is the setting that stops the proxy being used against
the estate itself. A tunnel to `169.254.169.254` is the cloud metadata service; a
tunnel to `10.0.0.5:6379` is an internal Redis. Both are requests a compromised
application makes through the proxy it was given, and both are refused by default.

**The ports**, with `ports`, because a proxy that allows a hostname on any port is
a proxy to every service on that host.

**Who is asking**, with `auth`, and the identity then selects the rules — so the
build agents, the developers' laptops and the payment service can each have their
own destination list rather than sharing one.

**Whether to look inside**, with `intercept`. This is the explicit,
deliberately-named setting for TLS interception: the proxy terminates the client's
TLS with a certificate from its own CA, opens its own TLS to the destination, and
the plaintext is then available to the filters, the WAF and the scanners. It is
the one thing in this project that breaks a client's end-to-end guarantee, which
is why it is a separate section with its own exclusions rather than a flag — an
estate that intercepts still should not intercept its people's banking.

`intercept` also carries the check that a tunnel most needs: the **SNI inside the
tunnel must match the destination the CONNECT asked for**. Without it, a client
can `CONNECT allowed.example.com:443` and then handshake for `anything.else`, and
the destination policy has decided nothing.

**SOCKS5's own shapes**, with `socks5` and `socks_udp`: whether SOCKS5 is served
at all, and whether `UDP ASSOCIATE` is — the latter being a UDP relay with the
amplification and spoofing questions that come with it.

**MASQUE**, with `masque`: `CONNECT-UDP` reaches arbitrary UDP destinations and
`CONNECT-IP` reaches arbitrary *IP*, which is a much larger grant than a TCP
tunnel and belongs behind its own decision.

**The bounds**: `max_tunnels`, `max_response_bytes`, and the connect and idle
timeouts.

### The estate's own authorisation policy

Above this listener's own destination policy sits the `authorization` section,
which is not about proxying: it is the one place that says which identity may
reach what, in the same words for every protocol. This listener asks it on every
request, tunnel and association -- CONNECT, a plain proxied request, SOCKS5 and
MASQUE alike -- after the destination policy above and before the destination is
dialled.

The `target` here is the destination itself, `host:port`, not an upstream pool:
a forward proxy has no pool, and the destination is exactly what a rule about
egress needs to name. So a rule reads `targets: ["*.vendor.example:443"]`, and
`*` does not cross the colon, which is what keeps one host's ports from being
one pattern's worth of the whole internet.

The `user` is the proxy credential's name, and it is empty on a listener with no
`auth`. That is a fact the operator chose rather than a hole: a rule naming users
then matches nobody here and the default decides, so a listener with no
credentials wants rules about `networks` and `targets` instead of about people.

The order matters and is deliberate. The destination policy runs first, so this
answers only about destinations nothing else objected to, and a refusal here is
about the person rather than the place -- which is what the rule an operator
reads says. The refusal is the reason `authorization`, answered with 403 and
counted as `xproxy_refusals_total{kind="forward",reason="authorization"}`, so it
reads like every other refusal this listener makes. Either shadow switch --
`policy: {mode: shadow}` on the listener, or `shadow: true` on the section --
records what it would have refused and lets the request through.

## What it does not do

- **It does not see inside a tunnel unless `intercept` says so.** Without
  interception this is byte relaying with a destination policy, and no WAF, header
  policy or body scanning applies.
- **It does not intercept silently.** Interception needs a CA the clients trust,
  which is a deployment step somebody has to take deliberately. There is no
  configuration in which it happens without being asked for.
- **It does not intercept what its exclusions name.** The excluded destinations
  are passed through, and a deployment that does not configure exclusions is
  intercepting its people's private traffic — which the documentation says plainly
  rather than leaving to be discovered.
- **It does not resolve on the client's behalf for `CONNECT` with a literal
  address.** A client that sends an IP has already resolved, and the policy then
  applies to the address; a hostname policy cannot be applied to a request that
  contains no hostname, which is why `allow_private` and the port list matter.
- **It does not do SOCKS4 or SOCKS4a.** Neither has authentication and both are
  superseded.
- **It does not do `BIND`.** SOCKS5's `BIND` asks the proxy to listen for an
  inbound connection on the client's behalf, which is an inbound path opened by an
  outbound policy.

## Standards

| Document | What it covers |
|----------|----------------|
| RFC 9110 §9.3.6 | The `CONNECT` method |
| RFC 9112 | HTTP/1.1 message syntax, for the tunnel request |
| RFC 9113 §8.5 | The extended CONNECT method in HTTP/2 |
| RFC 9114 | HTTP/3, and CONNECT within it |
| RFC 8441 | Bootstrapping WebSockets with HTTP/2, the extended-CONNECT pattern |
| RFC 1928 | SOCKS protocol version 5 |
| RFC 1929 | Username/password authentication for SOCKS5 |
| RFC 1961 | GSS-API authentication for SOCKS5 |
| RFC 9298 | Proxying UDP in HTTP (`CONNECT-UDP`) |
| RFC 9484 | Proxying IP in HTTP (`CONNECT-IP`) |
| RFC 7617 | The Basic authentication scheme, which `Proxy-Authorization` usually carries |

## See also

- The settings: [docs/CONFIG.md `server.listeners[].forward`](../CONFIG.md#serverlistenersforward-kind-forward)
- The estate-wide policy above it: [docs/CONFIG.md `authorization`](../CONFIG.md#authorization)
- A worked configuration: [`examples/forward/socks.yaml`](../../examples/forward/socks.yaml), [`intercept.yaml`](../../examples/forward/intercept.yaml) and [`masque.yaml`](../../examples/forward/masque.yaml)
- Routing TLS without terminating it: [tcp](tcp.md)
- The inward-facing HTTP pipeline: [http](http.md)
