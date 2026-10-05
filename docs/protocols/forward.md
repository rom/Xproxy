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

**Who is asking**, with `auth` and `auth.groups`, and the identity then selects
the rules — so the build agents, the developers' laptops and the payment service
can each have their own destination list rather than sharing one.

**What may be sent, and when**, with `categories` and `rules`. `allow` and `deny`
say whether a destination exists for this listener; the rules say who may reach
it, with which method, carrying which content type, inside which hours. "Nobody
POSTs to file sharing" is one rule about one category, and "the vendor's portal
during the change window" is another with a `schedule` and the change number in
its `comment`. First match decides and an unmatched destination is refused, which
is the same shape as the OT relays' rules and refuses for the same reason.

What those rules can be decided from differs by what the proxy can see, and the
difference is large enough to be the first thing to understand: see
**[What a tunnel does not say](#what-a-tunnel-does-not-say)** below.

**Whether to read the requests inside what it decrypts**, with
`intercept.http`. A decrypted tunnel carries ordinary HTTP messages, and reading
them is what makes a rule about a method or a content type decide there as well
as on port 80. `auto` does it when the policy has such a rule, `on` always, `off`
never — and `off` with such rules written is a combination validation warns
about, because it is a policy that cannot fire.

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

**`sni` is that same check for the tunnels nothing is decrypting**, which is most
of them on most proxies. It costs a peek at bytes the client was going to send
anyway. `enforce` refuses a mismatch, `observe` (the default) records it and
relays it, `off` does not look. A handshake with no server name — which is what
Encrypted Client Hello looks like from here — is not a mismatch, and a tunnel
opened to an address rather than a name is not one either.

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

## What a tunnel does not say

This is the shape of the whole problem, and it decides what an egress policy on
this listener is worth.

A **plain request** through the proxy — an absolute `http://` URI, which is how
HTTP without TLS travels through a proxy — carries its method, its path, its
content type and usually its length. Every selector in `rules` can be decided
about it, in both directions: the request before it is sent, and the response
head before its body is relayed.

A **CONNECT tunnel** carries `host:port` and nothing else. Everything a rule
about a method or a content type would need is inside TLS. So at a tunnel's
admission point those rules are **skipped**, and what decides there is the part
of the policy that is about the destination, the identity and the hour.

An **intercepted tunnel being read as HTTP** is the plain request again. Once the
proxy has terminated the client's TLS, the messages inside are ordinary HTTP/1.1:
each request is read, decided about, relayed, and its response head decided about
before the body travels — the same rules, the same two phases, the same events
and counters as a request on port 80. `intercept.http` is the setting, `auto` is
the default, and what it means by auto is "when the policy has a rule that needs
it".

That leaves four consequences worth stating rather than discovering:

1. A rule naming `methods`, `paths`, `request_types`, `response_types`,
   `request_bytes_over` or `response_bytes_over` **decides nothing for a
   destination reached through a tunnel nothing is reading**. On an estate whose
   egress is almost entirely HTTPS, such a rule covers almost nothing unless
   `intercept` covers those destinations. Validation names the rules in that
   position — both on a listener with no `intercept` at all and on one that
   intercepts with `http: off` — and `GET /v1/listeners` carries the count, so it
   is visible rather than assumed.
2. The destination half still works everywhere, and is where most of the value
   is. "These groups, these categories, these hours" is decidable for a tunnel
   whether or not anything decrypts it, and it is the policy an egress proxy is
   bought for.
3. `sni` is what makes the destination half mean what it says. Without it a
   tunnel's destination policy decided about a name the client then need not use.
   Inside a tunnel being read, the `Host` header is held to the same check for
   the same reason, under the same setting.
4. Reading is not universal even where it is on. A tunnel that negotiated **h2**,
   a tunnel whose first bytes are **not a request line** — SSH, a database, a
   line protocol inside TLS — and **everything after a 101** are relayed as
   bytes, because a proxy that guessed at HTTP/2 framing, answered a database
   greeting with a 400, or kept reading a WebSocket as request-and-response would
   be breaking traffic rather than policing it. Each of the three is counted
   (`forward_intercept_bytes_only`), so "nothing was read" is never silent.

Within a request this listener can read — plain or inside a tunnel — two more
limits:

- A **response** rule is decided when the response head arrives — after the
  destination was contacted. The body does not have to arrive; the request did
  leave.
- A **byte bound** is decided before anything is sent when the length was
  declared. On a chunked body the bytes are counted as they travel and the
  connection is cut past the bound: what has already gone cannot be recalled,
  which is why a size rule is worth less on egress than a destination rule.

A refusal inside a tunnel is an HTTP **403 on the connection the client believes
is end to end**, naming the reason, and then the connection closes — keeping it
open would mean reading the rest of a body nobody is allowed to send. A head the
proxy cannot frame — a length and a chunked encoding both, which is the
request-smuggling shape — is answered 400 rather than passed on, and an
intercepting proxy is the only place in this project that can see one at all.

## What it does not do

- **It does not see inside a tunnel unless `intercept` says so.** Without
  interception this is byte relaying with a destination policy, and no WAF, header
  policy or body scanning applies.
- **It does not parse HTTP/2 inside an intercepted tunnel.** `alpn` offers
  `http/1.1` for that reason; a tunnel that negotiated `h2` anyway is relayed as
  bytes rather than read, because a proxy that guesses at HTTP/2 framing corrupts
  the stream it is inspecting.
- **It does not add anything to a request it relays inside a tunnel.** No `Via`,
  no forwarded headers: the destination sees what the client sent, which is the
  message the policy judged.
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
- A worked configuration: [`examples/forward/egress.yaml`](../../examples/forward/egress.yaml), [`socks.yaml`](../../examples/forward/socks.yaml), [`intercept.yaml`](../../examples/forward/intercept.yaml) and [`masque.yaml`](../../examples/forward/masque.yaml)
- Routing TLS without terminating it: [tcp](tcp.md)
- The inward-facing HTTP pipeline: [http](http.md)
