# NTS-KE — key establishment for authenticated time

`kind: ntske`, served by **xrelay** or **xot**, TCP port **4460**.

NTS key establishment is the TLS half of Network Time Security. It exists so
that the *other* half — the actual time exchange — can stay a single
unauthenticated-looking UDP round trip while being cryptographically protected.

## On the wire

A TLS 1.3 connection on TCP 4460, with **`ntske/1`** as the ALPN protocol. That
ALPN is not decoration: it is how a server distinguishes an NTS-KE client from
anything else that reached the port, and RFC 8915 requires it.

Inside the TLS session, a short exchange of **records**, each a critical bit, a
type, a length and a body:

| Record | What it says |
|--------|-------------|
| Next Protocol Negotiation | Which protocol the cookies are for (NTPv4) |
| AEAD Algorithm Negotiation | Which AEAD the time packets will use |
| New Cookie for NTPv4 | A cookie — the server sends several, and each is single-use |
| NTPv4 Server Negotiation | Which server the client should send its time queries to |
| NTPv4 Port Negotiation | On which port |
| Error, Warning | What went wrong |
| End of Message | The last record |

The client then closes the TLS connection and starts sending NTP packets to the
named server, each carrying one cookie and an authenticated extension field. It
gets a fresh cookie back with each answer, which is why the cookies are
single-use: an observer cannot link one client's queries to each other.

The keys for those extension fields come from the TLS exporter, so they are
never on the wire at all.

## What the protocol gives you

Real security, and it is the reason NTS is worth deploying: TLS 1.3 with the
server authenticated by a certificate an estate's own trust store validates, and
keys derived through the exporter rather than transmitted.

The design also gets the privacy property right. A naive design would have
authenticated each time query with a long-term identifier, which would make every
client trackable across networks. Single-use cookies handed out in bulk avoid
that.

What NTS-KE does **not** protect is the server it names. The `NTPv4 Server
Negotiation` record can point the client at a different address than the one it
connected to — which is a feature (a pool can distribute load) and a thing worth
knowing about.

## What this listener decides

It has two postures, and which one an estate wants depends on whether the time
servers behind it speak NTS themselves.

**Relaying** (no `terminate` section) is the narrower one, and it is the right
answer when they do: the TLS session belongs to the client and the NTS-KE server
whose certificate and keys it is, and the cookies are derived from that session's
exporter. A relay that terminated the TLS would be issuing cookies with keys the
time servers do not have, and nothing would work.

**Terminating** (`terminate`) is the answer when they do not — see
[Terminating](#terminating) below.

What a relaying listener reads is what is readable *before* the handshake
completes, from the ClientHello:

**The application protocol.** `require_alpn` refuses a connection that does not
offer `ntske/1`. That is the whole of this listener's first job: port 4460 is a
TLS port on a machine that is not a web server, and a client that reached it
without asking for NTS-KE is not an NTS client. Refusing at the ALPN costs
nothing and closes the port to everything else.

**The server name.** `server_names` names which SNI values may be relayed, so
one listener in front of several NTS-KE servers routes by name and refuses names
it does not serve.

**The handshakes in flight.** `max_concurrent_handshakes` is the bound that
matters here, and the reason is specific: a TLS 1.3 handshake is the expensive
part of NTS, and a key establishment server's cost is almost entirely handshakes.
Bounding connections would not bound the work; bounding the handshakes does.
`max_connections`, `handshake_timeout`, `idle_timeout` and `max_bytes` bound the
rest.

### The imported lists, and the estate's authorisation policy

NTS-KE authenticates the *server* to the client, not the other way about: the
client gets cookies out of the handshake and nothing in it names a person. An
estate can put a client certificate in front of it, and then the name is the
certificate's -- but that is checked in the handshake, and these two questions are
asked before it, because the handshake is the expensive thing this port has to
protect:

- **the imported address lists** (`threat_intel`), about the client's address. A
  list whose action is `block` refuses; one that asks for a `challenge` is
  recorded like a log list, because there is no request here to serve a challenge
  into and turning it into a block would be a policy the operator did not write.
- **the `authorization` section**, on the client address, the listener, the kind,
  the upstream pool and the hour. A rule naming `users` matches nobody on this
  kind, so a rule here is written with `networks`, `targets` and `schedule`.

Asked after this listener's own `allow_clients` and before a handshake slot is
taken, so a client that may not be here never costs one.

The lists are asked first: a list is an import about an address and says nothing
about this estate's intentions, so a refusal naming the feed sends an operator to
the feed rather than to a rule they would not find.

A refusal is the reason `threat_intel` or `authorization` on this listener's usual
deny event, so the counters, the security log and the ban list see it as they see
any other refusal. Either shadow switch -- `policy: {mode: shadow}` on the
listener, or `shadow: true` on the section -- records what it would have refused
and carries the traffic.

## Terminating

With a `terminate` section and a `tls` section, this listener *is* the NTS-KE
server. It presents the certificate, derives the two NTS keys from its own TLS
exporter, and issues cookies of its own — cookies the `kind: ntp` listener beside
it can open, because the two share the key set.

That is what makes the interesting case possible: **the time source does not have
to speak NTS at all.** It can be the plain NTPv4 server that has been in the plant
for fifteen years. The clients get authenticated time, the source gets a request
from one address it already knows, and the verification happens on the relay
where an operator can see it counted. See `ntp.nts.mode: terminate`.

The cookie is the whole of what this mode rests on, so it is worth being precise
about. A cookie is a key identifier, a nonce, and the client's two session keys
sealed with AES-SIV-CMAC-256 under a master key this relay holds. The identifier
is associated data, so a cookie moved to another identifier does not open — which
matters, because otherwise moving one would be a way to ask for it to be
decrypted under a different key. Every failure to open is one error, because a
caller that could tell them apart would be an oracle for which key identifiers
exist.

The master key is rotated (`rotate_every`, a day by default) with an overlap
(`keep_keys`, two by default). Both are deliberate: a client holds days of
cookies, so a rotation that invalidated them at once would take the estate's time
service down until every client re-established — a TLS handshake each, all in the
same second. `state` writes the set to a file, mode 0600, so a restart does not do
the same thing. That file is the secret every cookie's secrecy rests on: whoever
can read it can forge a cookie, which is to say forge an authenticated time
answer.

What a terminating listener refuses, beyond the relaying refusals: a handshake
that fails (`handshake_failed`, one reason for every TLS fault, because a port
that reported a different refusal for each would be one an attacker could
enumerate the configuration through), a client that completes the handshake and
says nothing (`no_request`, and it gets no answer — there is nothing to report a
fault in), a request that is incomplete or past its bound, an unknown *critical*
record (`unknown_critical_record`, answered with RFC 8915's code 0 rather than
"bad request", because the client sent something well formed this server cannot
honour), and terms it cannot meet (`no_terms`, answered with the two empty
negotiation records the standard defines rather than an error record — the request
was fine and the terms were not).

## What it does not do

- **It does not terminate TLS while relaying.** By design, as above: without a
  `terminate` section there is no certificate for the client to validate here,
  because the certificate the client must validate is the NTS-KE server's.
- **It does not read the records while relaying.** They are inside the TLS
  session. The relay has no visibility into the cookies, the AEAD negotiation or
  the server the client is pointed at, and it should not.
- **It does not offer an algorithm it cannot use.** Terminating, it negotiates
  AEAD_AES_SIV_CMAC_256 and NTPv4 and nothing else: a negotiation that accepted
  an algorithm this relay could not seal a cookie with would be a negotiation
  that agreed to nothing.
- **It does not carry the time exchange.** That is UDP 123 and a separate
  listener — see [ntp](ntp.md).
- **It does not validate certificates on the client's behalf while relaying.**
  The client validates the server; that is the trust model and inserting a
  relay's opinion into it would weaken it.

## Standards

| Document | What it covers |
|----------|----------------|
| RFC 8915 | Network Time Security for NTPv4: the NTS-KE protocol, the record types, the cookie model, the `ntske/1` ALPN |
| RFC 8446 | TLS 1.3, and the exporter the keys come from |
| RFC 5297 | AES-SIV, the AEAD NTS mandates and the one the cookies are sealed with |
| RFC 7301 | ALPN |
| RFC 6066 | Server Name Indication |
| RFC 7384 | The security requirements NTS was designed against |

## See also

- The estate-wide policy above it: [docs/CONFIG.md `authorization`](../CONFIG.md#authorization)
- The settings: [docs/CONFIG.md `server.listeners[].ntske`](../CONFIG.md#serverlistenersntske-kind-ntske)
- A worked configuration: [`examples/ot/ntp.yaml`](../../examples/ot/ntp.yaml), and
  the terminating one: [`examples/ot/nts-gateway.yaml`](../../examples/ot/nts-gateway.yaml)
- The time exchange itself: [ntp](ntp.md)
- TLS passthrough in general: [tcp](tcp.md)
