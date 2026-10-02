# KKDCP — Kerberos over HTTPS, and the one place it is readable

`kind: kkdcp`, served by **xproxy** or **xrelay**, HTTPS on whatever port the
listener binds (443 in the deployment it was designed for).

Kerberos is UDP and TCP on port 88, and the places people work from are not on
the network the KDC is on. So MS-KKDCP wraps a Kerberos message in a small DER
envelope, a client POSTs it to an HTTPS endpoint, and the proxy speaks TCP to
the KDC and wraps the answer back. Windows has shipped the client since 2012;
MIT and Heimdal both speak it.

It is the only listener in this project that translates one protocol into
another, and one of the few places an estate's Kerberos traffic can be read at
all.

## On the wire

An HTTPS `POST` to `/KdcProxy` with `Content-Type: application/kerberos`, whose
body is:

```
KDC-PROXY-MESSAGE ::= SEQUENCE {
    kerb-message   [0] OCTET STRING,
    target-domain  [1] KERB-REALM OPTIONAL,
    dclocator-hint [2] INTEGER OPTIONAL
}
```

`kerb-message` is not a bare Kerberos message: it is the message as it would
appear on a TCP connection to the KDC, four octets of big-endian length first.
That is what makes the envelope a transport rather than a wrapper, and it is a
second length field a reader has to agree with the KDC about.

Inside is DER Kerberos (RFC 4120). A request is `[APPLICATION 10]` (AS-REQ) or
`[APPLICATION 12]` (TGS-REQ) around a `KDC-REQ`, and what is in the clear is
everything a KDC decides on:

| Field | What it says |
|-------|-------------|
| `realm` | Which realm the request is for |
| `cname` | The client principal — present in an AS-REQ, usually absent from a TGS-REQ, where the ticket names the client and the ticket is encrypted |
| `sname` | The service the ticket is for: the realm's `krbtgt` in an AS exchange, and the service being reached in a TGS one |
| `kdc-options` | A 32-bit flag field: forwardable, proxiable, renewable, canonicalize, and bit 14, which MS-SFU uses as `cname-in-addl-tkt` |
| `etype` | The encryption types the client will accept, **in its own order of preference** |
| `padata` | The pre-authentication: an encrypted timestamp, a PKINIT request, FAST armour, a PAC request, `PA-FOR-USER` |
| `till`, `from` | The validity being asked for |

A reply is a `KDC-REP` whose ticket and `enc-part` are ciphertext — but each
`EncryptedData` names its own encryption type in the clear, which is how a
reader knows what a ticket left in. A refusal is `[APPLICATION 30]`, a
`KRB-ERROR`, with an error code and a text.

## What the protocol gives you

A great deal, and this is the one protocol in this directory that was designed
with security in it rather than beside it: mutual authentication, a key
hierarchy, replay protection, and a pre-authentication step that stops the KDC
handing out a crackable blob to anybody who asks for one.

What it does not give you is *transport* security on the HTTP leg, which is why
MS-KKDCP is HTTPS and why a listener here with no `tls` section is refused at
load: the pre-authentication blob is derived from the user's password.

And the plaintext fields are not a weakness — they are how the two ends agree
what to encrypt. They are also, usefully, exactly the fields the known attacks
on Kerberos are visible in.

## What this listener decides

**Which realms it will carry, which is what stops it being an open relay.**
`realms` is required. The envelope names a target domain and the inner message
names a realm; where both are present they have to agree, because the outer one
is what the proxy routes by and the inner one is what the KDC decides on, and a
proxy that picked one would be deciding about a different realm than the KDC.
This check is never shadowed.

**Which encryption types may be asked for.** `refuse_weak_etypes` defaults on
and refuses a request offering *nothing but* single DES, triple DES or
RC4-HMAC. "Nothing but" rather than "any", and the distinction is the whole
setting: a Windows client in a mixed estate lists aes256, aes128 and rc4 and
the KDC takes the first it can, so refusing a request that mentions RC4 would
refuse the estate. A request offering RC4 alone has asked for a ticket it can
crack offline against the service account's password — on a TGS-REQ for a
service principal, Kerberoasting with no ambiguity left in it.

**Whether an AS exchange was pre-authenticated — on the reply.** A bare AS-REQ
with no `padata` is the normal first message of every Kerberos exchange: the
KDC answers it with `KDC_ERR_PREAUTH_REQUIRED` and the client retries with a
timestamp. The interesting case is a KDC that answers one with a *ticket*,
which says the account is pre-authentication exempt and hands over an offline
password-cracking target. That is AS-REP roasting, `refuse_preauth_exempt`
defaults on, and the check has to be on the reply because the question cannot
be answered on the request. The pairing is this relay's own: nothing in the
protocol says "this reply answers a request that had no padata".

**Whether delegation crosses.** A TGS-REQ carrying `PA-FOR-USER` is S4U2Self,
which names the impersonated user in the clear; one carrying bit 14 *and* an
additional ticket is S4U2Proxy. Both default off, and S4U2Proxy needs both
halves to be recognised as one — the option alone is a client setting a
reserved bit, and an additional ticket alone is a user-to-user request.

**How many different services one client may ask for.** This is the behavioural
half of the Kerberoasting control and it catches what the encryption rules
cannot: forty distinct service principals in a minute is the realm's service
accounts being enumerated whatever encryption they were asked for in. It is
counted on TGS requests only, because an AS-REQ names the realm's `krbtgt` and
counting those would count one name over and over.

**How many pre-authentication failures.** An internet-facing KDC proxy is where
password spraying lands, and the signal is a burst of
`KDC_ERR_PREAUTH_FAILED`. The bound is per client address rather than per
account, because a sprayer tries one password against a thousand accounts: the
per-account bound is the KDC's own lockout, and locking the account is what the
sprayer wanted.

**That a refusal looks like a KDC's.** `deny_response: error` is the default and
sends a `KRB-ERROR` with `KDC_ERR_POLICY` and a text naming this proxy, wrapped
in the envelope the client expects. Silence on this protocol is a client that
falls back to port 88 — where there is no relay — and then reports a network
fault to whoever is sitting at it.

## What it does not do

- **It holds no keys and decrypts nothing.** The ticket, the reply's enc-part
  and the pre-authentication blob are opaque here and stay that way. What is
  read about them is which encryption *type* they are in, which is the field a
  policy decides on.
- **It cannot see inside FAST armour.** RFC 6113 wraps the whole request, and a
  request that arrives armoured shows this relay the armour. That is a real
  limit on `etypes` and `principals` for an estate that has deployed FAST, and
  it is the correct trade: FAST is a stronger control than this relay.
- **It does not mint, renew or validate a ticket.** The KDC does. The one
  message this relay writes itself is a `KRB-ERROR`, for a refusal.
- **It is not a KDC and does not cache.** Every request reaches a KDC, and a
  reply is forwarded or refused rather than remembered — a cached Kerberos reply
  would be a replay this relay performed.
- **It does not pool KDC connections.** One request is one TCP connection: the
  exchange is a single round trip, the connection is cheap next to the
  cryptography at both ends, and a pooled connection shared between two clients
  would be a place where one client's reply could reach the other.
- **It serves one path and one method.** Everything else gets a status and no
  body. An HTTPS endpoint whose job is to carry Kerberos has no business being
  a web server, and every feature it does not have is a feature nobody can
  reach.
- **It does not police what the ticket is later used for.** A ticket this proxy
  carried is presented to a service directly, not through here. What this
  listener bounds is which tickets may be *obtained*.

## Standards

| Document | What it covers |
|----------|----------------|
| RFC 4120 | Kerberos 5: the messages, the options, the pre-authentication, the error codes |
| RFC 3961 | The encryption and checksum framework, and the etype registry |
| RFC 3962 | The AES encryption types, 17 and 18 |
| RFC 8009 | The AES-SHA2 encryption types, 19 and 20 |
| RFC 4757 | RC4-HMAC, which is the Kerberoasting target |
| RFC 4556 | PKINIT: a certificate instead of a password |
| RFC 6113 | FAST: the armoured channel this relay cannot read inside |
| RFC 8062 | Anonymity support, which `allow_anonymous` is about |
| RFC 3244 | The Microsoft kpasswd protocol, which `allow_password_change` carries |
| MS-KKDCP | The KDC Proxy Protocol: the envelope, the path, and the HTTPS requirement |
| MS-SFU | S4U2Self and S4U2Proxy, and the use of `kdc-options` bit 14 |

## See also

- The estate-wide policy above it: [docs/CONFIG.md `authorization`](../CONFIG.md#authorization)
- The settings: [docs/CONFIG.md `server.listeners[].kkdcp`](../CONFIG.md#serverlistenerskkdcp-kind-kkdcp)
- A worked configuration: [`examples/auth/kkdcp.yaml`](../../examples/auth/kkdcp.yaml)
- The directory behind the same realm: [ldap](ldap.md)
- What the refusals mean to an operations centre: [docs/ATTACK.md](../ATTACK.md)
