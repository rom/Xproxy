# HTTP — the pipeline

`kind: http`, served by **xproxy**, usually TCP **80** and **443**, and UDP
**443** for HTTP/3.

This is the listener the project started as, and the only one whose page cannot
list what it decides in a table — because HTTP is not one protocol with one
policy but a pipeline of them: routing, then authentication, then filters, then
the WAF, then the cache, then the upstream.

Everything the other twenty-seven listeners do for one protocol each, this one
does for the protocol that carries most of the world's traffic.

## On the wire

Three wire formats for one semantic model, which RFC 9110 finally separated
properly:

| Version | Framing | What it adds |
|---------|---------|-------------|
| **HTTP/1.1** (RFC 9112) | Text: a request line, headers, an optional body delimited by `Content-Length` or chunked encoding | Keep-alive, pipelining |
| **HTTP/2** (RFC 9113) | Binary frames on one connection, with **HPACK**-compressed headers | Multiplexed streams, flow control, server push, priorities |
| **HTTP/3** (RFC 9114) | The same over QUIC, with **QPACK** | No head-of-line blocking; the transport is UDP |

The framing is where the protocol's own security problems live. A message with
both a `Content-Length` and a `Transfer-Encoding: chunked`, or with two
`Content-Length` headers, or with a chunk size in hexadecimal with a leading
space, is a message two implementations will disagree about the length of — and
**request smuggling** is exactly that disagreement, with a proxy reading one
request where the server reads two.

The semantics are where the rest live. A path is a sequence of percent-encoded
segments that has to be decoded, normalised and re-checked; a header can appear
more than once; a cookie is a header with its own grammar; a body can be any
content type, encoded, compressed, and nested.

## What the protocol gives you

TLS, and it is genuinely good: TLS 1.3 with a certificate the client validates
against a public trust store, HSTS to stop the downgrade, and — with the
extensions this proxy supports — ECH to hide the name and post-quantum key
exchange where it is wanted.

Above the transport, HTTP itself gives you very little. `Authorization` carries
whatever scheme somebody chose; a cookie is a bearer token with a browser's
same-origin policy around it; and nothing in the protocol distinguishes a request
a person made from a request a page made on their behalf.

So essentially all of an HTTP service's security is above the protocol, which is
why this listener has a pipeline rather than a policy.

## What this listener decides

The full reference is [docs/CONFIG.md](../CONFIG.md), whose
[`## http`](../CONFIG.md#http) section is a map of where each stage is written
up. What follows is the shape.

**The framing, strictly, before anything else.** Conflicting length headers,
ambiguous chunked encodings, bare line endings, header injection through
obs-folding: each is refused rather than normalised, because normalising a
message two implementations disagree about means picking one of their readings.
The request normalisation guard then handles the path: double encoding,
overlong UTF-8, backslashes, dot segments and the rest, decoded and classified
rather than matched against a list of spellings.

**The route**, by host, path, method, header and expression — and then, per
route, everything else. That per-route granularity is the point: a login
endpoint, a static asset and an internal admin path have nothing in common in
what they should allow.

**Who is asking**, with the identity filters: OIDC login flows with session
cookies, OAuth 2.0 with introspection, JWT validation against a JWKS, DPoP and
certificate-bound tokens for sender constraint, API keys with a lifecycle, LDAP,
Basic, WebAuthn, SAML as a service provider, TOTP as a second factor, and client
certificate identity in the RFC 9440 form.

**What an upgraded connection carries**, with `websocket_guard`. Everything
above happens before the 101; after it, a request-oriented proxy stops looking,
and applications put their real API in there — chat, trading, terminals,
subscriptions. The guard parses RFC 6455 frames in both directions and applies
the protocol's own rules (opcodes, masking, fragmentation, control frames,
UTF-8), the connection's bounds (frame, message, rate), and then the
application's: `types` names the kinds of message the route carries, each with
its own size bound, its own rate and a JSON Schema it must match, and
`unknown_types` says what happens to a message the list does not name.
`compression` is where `permessage-deflate` is decided — stripped from the offer
so everything stays readable, refused so the client is told, or negotiated on
terms the proxy can inflate so the messages are both compressed and inspected.

**Whether the request is what it claims**, with the WAF: SecLang rules through
Coraza with the OWASP Core Rule Set, a learning mode, per-rule statistics and
measured confidence, gradual enforcement by block share and canary client, XML
entity and schema controls, and JSON body schema validation.

**Whether it is a person**, with the bot scoring, the device fingerprint, the
challenge and CAPTCHA machinery, and the account guard that watches for
credential stuffing and brute force across identities rather than per request.

**What the API is supposed to accept**, with OpenAPI validation against a
description, GraphQL depth and complexity limits, a positive security policy per
route, and the inventory that finds the endpoints nobody documented.

**What may leave**, with the sensitive data detection filter on responses, and
the origin lock that signs what the gateway sent so an origin can refuse
anything else.

**How much and how often**, with rate limits keyed on an address, a network
prefix, a cookie, an endpoint, a JA4 fingerprint, a JWT claim, a device or an
identity; quotas; concurrency limits; shedding; and the ban list that escalates
a pattern of refusals into a block.

**Where it goes**, with the upstream pools: health checks, outlier ejection,
circuit breakers, retries with budgets, hedging, priority and backup pools,
locality awareness, Happy Eyeballs, slow start, and HTTP/1.1, HTTP/2 or HTTP/3
to the origin.

**What is remembered**, with the cache, the compression, the static file server
and the early hints.

**And what an attacker is told**, with the deception machinery: honeypot routes,
decoys, honeytokens that trip on use, and deliberately misleading answers on real
routes — which is documented in [docs/DECEPTION.md](../DECEPTION.md).

### The estate's authorisation policy

The gateway has two layers that decide about a request already: the route, which
says what may be done with it, and the `authz` filter in that route's chain, which
says what a verified identity may do. The `authorization` section is the question
above both -- *may this client be served by this listener at all, towards this
pool, at this hour* -- and it is a question neither of them can answer. A route
cannot, because a route is one of the things being decided about. The filter
cannot, because it needs an identity, and this is about clients that have offered
none.

"Nothing from the vendor network reaches the internal pool outside working hours"
is the shape of rule this makes writable, and before it there was no place in the
gateway to be told that.

**Where it is asked.** After the route is matched -- so a rule's `targets` can name
the route's upstream pool -- and before the challenge gate, the filter chain and the
upstream. So a refused client's request never reaches a WAF, a body buffer or an
origin. A refusal is `403`, because on this kind there is a response to write, which
is also why the question belongs here rather than at the accept.

**What it does not decide.** The subject carries no user. The gateway's identities
are established per route by its authenticating filters, and what one may then do is
the `authz` filter's decision; filling a user here would be two answers to one
question. So a rule naming `users`, `principals` or `groups` matches nobody on this
kind, exactly as on the relays that have no identity at all -- and a policy written
only about people therefore refuses every request here, fail-closed. A rule on this
kind is written with `networks`, `targets`, `listeners` and `schedule`.

**Not route-exemptable**, unlike the imported lists beside it. A list is somebody
else's import and a route may reasonably opt out of one; a route that could opt out
of the estate's own policy would not be a policy.

**Cost.** Per request rather than per connection, because a connection carries
requests for many routes and the pool is not known until one is matched. The cheap
case is the common one: the question returns before it looks at anything when no
`authorization` section is configured, which is every estate that has not written
one.

Either shadow switch -- `policy: {mode: shadow}` on the listener, or `shadow: true`
on the section -- records what it would have refused, with the rule that decided,
and serves the request.

## What it does not do

- **It does not pass through what it cannot parse.** An ambiguous message is
  refused. That is a deliberate trade: a handful of genuinely broken clients are
  refused in exchange for smuggling being impossible rather than unlikely.
- **It does not terminate TLS transparently.** If a deployment needs the bytes
  relayed without termination, that is the [tcp](tcp.md) kind; if it needs the
  estate's own machines to reach outward, that is [forward](forward.md).
- **It is not a web application.** There is no application logic, no database, no
  templating. The static file server and the error pages are the extent of what it
  serves itself.
- **It does not replace the application's own authorisation.** It can establish an
  identity and pass it on; what a user may do with a given object is the
  application's, and the API abuse detection watches for enumeration rather than
  deciding per object.
- **It does not rewrite a frame.** The WebSocket guard refuses or records; it
  never edits what is travelling, because an intermediary that changes a message
  is an intermediary both endpoints then disagree with.
- **It does not serve WebSocket over HTTP/2's extended CONNECT (RFC 8441).**
  The listener does not advertise that setting, so a client that would have used
  it falls back to the HTTP/1.1 upgrade — which is the one the frame guard reads.
  A WebTransport session over HTTP/3 is relayed as streams and datagrams and is
  not message-inspected.
- **It does not see inside an end-to-end encrypted body.** A body encrypted by the
  client for the origin is opaque, and the WAF has nothing to say about it.
- **It does not guarantee the WAF catches things.** A rule set is a set of rules.
  The learning mode, the per-rule confidence and the gradual enforcement exist
  because the honest position is that a WAF's value is measurable and its coverage
  is not complete.

## Standards

| Document | What it covers |
|----------|----------------|
| RFC 9110 | HTTP semantics: methods, status codes, header fields, ranges, conditional requests |
| RFC 9111 | HTTP caching |
| RFC 9112 | HTTP/1.1 message syntax and routing |
| RFC 9113 | HTTP/2, and HPACK is RFC 7541 |
| RFC 9114 | HTTP/3, and QPACK is RFC 9204 |
| RFC 9000, 9001, 9002 | QUIC: transport, TLS, loss detection |
| RFC 8446 | TLS 1.3 |
| RFC 6265, 6265bis | Cookies |
| RFC 6797 | HSTS |
| RFC 9218 | Extensible prioritization |
| RFC 8297 | The `103 Early Hints` status code |
| RFC 7239 | Forwarded |
| RFC 9440 | Client-Cert and Client-Cert-Chain |
| RFC 7617, 6750 | Basic and Bearer authentication |
| RFC 6749, 7636, 7662, 8693, 8705, 9449 | OAuth 2.0, PKCE, introspection, token exchange, mTLS-bound tokens, DPoP |
| RFC 7515–7519 | JWS, JWE, JWK, JWA, JWT |
| RFC 9457 | Problem details for HTTP APIs |
| RFC 3507 | ICAP, for handing a body to a scanner |

The full conformance table, with what is served, what is partial and what is
refused and why, is [docs/RFC.md](../RFC.md).

## See also

- The estate-wide policy above it: [docs/CONFIG.md `authorization`](../CONFIG.md#authorization)
- The settings: [docs/CONFIG.md `## http`](../CONFIG.md#http), which is a map of
  where each stage of the pipeline is written up — and then most of the rest of
  that document
- Worked configurations: [`examples/routes/`](../../examples/routes),
  [`examples/waf/`](../../examples/waf), [`examples/filters/`](../../examples/filters),
  [`examples/security/`](../../examples/security)
- The conformance table: [docs/RFC.md](../RFC.md)
- The deception machinery: [docs/DECEPTION.md](../DECEPTION.md)
- Routing TLS without terminating it: [tcp](tcp.md)
- The outbound direction: [forward](forward.md)
