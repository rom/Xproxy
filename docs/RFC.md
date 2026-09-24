# Standards this proxy implements

A proxy is a thing that sits between two implementations of a
specification and has to be right about both of them. This document is
the list of those specifications: what is implemented, what is
implemented only in part, and what is deliberately refused.

The last of those is the reason this document exists. A proxy that
quietly ignores a feature it does not understand is a proxy that reads
a message differently from the peer behind it, and every smuggling,
desync and request-splitting bug in the history of the web lives in
that gap. Where this proxy does not implement something, it says so on
the wire — a refusal, a `501`, a closed connection — rather than
passing the bytes on and hoping.

**How to read the tables.** *Full* means the parts that apply to a
proxy are implemented and tested. *Partial* means a named subset, with
the omission stated. *Refused* means the proxy recognises the thing and
declines it on purpose; the reason is given, because "not implemented"
and "refused" are different promises. *Not applicable* means the
specification describes a role this proxy does not play, so there is
nothing here for it to implement; that reason is given too, since "we
did not build it" and "it does not apply" are different promises again.

## Contents

- [HTTP](#http)
- [QUIC and HTTP/3](#quic-and-http3)
- [WebSocket, WebTransport and tunnelling](#websocket-webtransport-and-tunnelling)
- [TLS and certificates](#tls-and-certificates)
- [DNS](#dns)
- [Mail](#mail)
- [Messaging](#messaging)
- [Secure Shell and file transfer](#secure-shell-and-file-transfer)
- [Proxying and forwarding](#proxying-and-forwarding)
- [Identity, tokens and authentication](#identity-tokens-and-authentication)
- [Content, encoding and data formats](#content-encoding-and-data-formats)
- [Addressing, logging and operations](#addressing-logging-and-operations)
- [Not IETF standards](#not-ietf-standards)
- [What is deliberately not implemented](#what-is-deliberately-not-implemented)

## HTTP

| RFC | Title | Status | Notes |
|-----|-------|--------|-------|
| 9110 | HTTP Semantics | Full | Methods, status codes, conditional and range requests, `Forwarded` handling, the `CONNECT` method |
| 9111 | HTTP Caching | Partial | The response cache honours `Cache-Control`, `Vary`, `Age` and freshness; it does not implement shared-cache revalidation with `stale-while-revalidate` (RFC 5861) |
| 9112 | HTTP/1.1 | Full | Framing is decided once, in one parser; a message with both `Content-Length` and `Transfer-Encoding`, an obfuscated `chunked`, or a second framing header is refused rather than resolved |
| 9113 | HTTP/2 | Full | Through Go's `net/http2`, with the proxy's own bounds on concurrent streams and header size |
| 9218 | Extensible Prioritization Scheme for HTTP | Partial | A client's `Priority` urgency may move its own request down the load-shedding order on a route that reads it, and never up; the field is forwarded unchanged. Stream reprioritisation frames are not implemented — the proxy does not schedule the upstream's streams |
| 8297 | An HTTP Status Code for Indicating Hints (103 Early Hints) | Full | Relayed to the client, at most eight informational responses per exchange, or stripped per route |
| 8470 | Using Early Data in HTTP | Full | A request a terminating proxy marked `Early-Data: 1` is answered 425 Too Early unless the route says otherwise; a client's own marker decides nothing and is not forwarded. This proxy's own TLS server does not accept early data |
| 7541 | HPACK | Full | With HTTP/2 |
| 8441 | Bootstrapping WebSockets with HTTP/2 | Full | Extended `CONNECT`; the `:protocol` pseudo-header is claimed whole on a forward listener, and an unimplemented value is answered `501` rather than falling through to a TCP tunnel |
| 6265 | HTTP State Management (cookies) | Full | Including the `__Host-` and `__Secure-` prefixes for the cookies this proxy issues |
| 7239 | Forwarded HTTP Extension | Partial | A `Forwarded` header from an untrusted peer is removed before the request goes upstream; the client address is taken from `X-Forwarded-For` (not an RFC) when the peer is in `trusted_proxies` |
| 6797 | HTTP Strict Transport Security | Full | As a response header policy |
| 7034 | X-Frame-Options | Full | As a response header policy |
| 6454 | The Web Origin Concept | Full | Origin checking and the CORS policy |
| 7617 | The Basic HTTP Authentication Scheme | Full | `basic_auth`, and the forward proxy's own `Proxy-Authenticate` |
| 6750 | The OAuth 2.0 Authorization Framework: Bearer Token Usage | Full | The `Authorization: Bearer` form a JWT or an API key arrives in |
| 7235 | HTTP Authentication | Full | Framework, `401`/`407` and the challenge headers |
| 7578 | Returning Values from Forms: multipart/form-data | Full | Parsed by `upload_guard` and by the WAF |
| 6266 | Content-Disposition | Full | Filenames read for the upload policy |
| 9116 | A File Format to Aid in Security Vulnerability Disclosure | Full | The virtual `security.txt`, served before routing |
| 8615 | Well-Known Uniform Resource Identifiers | Full | `/.well-known/` handling, including ACME and MASQUE paths |
| 9309 | Robots Exclusion Protocol | Full | The `robots` decoy is a valid exclusion file |
| 3986 | Uniform Resource Identifier | Full | Parsing and the normalisation guard |

## QUIC and HTTP/3

| RFC | Title | Status | Notes |
|-----|-------|--------|-------|
| 9000 | QUIC: A UDP-Based Multiplexed and Secure Transport | Full | Through quic-go |
| 9001 | Using TLS to Secure QUIC | Full | Including the Initial keys a layer 4 listener derives to read a ClientHello it forwards without terminating |
| 9002 | QUIC Loss Detection and Congestion Control | Full | Through quic-go |
| 9114 | HTTP/3 | Full | Listener and upstream |
| 9204 | QPACK | Full | With HTTP/3 |
| 9221 | An Unreliable Datagram Extension to QUIC | Full | Carries WebTransport and MASQUE datagrams |
| 9250 | DNS over Dedicated QUIC Connections | Full | ALPN `doq`, two-octet length prefix, message id 0 |

## WebSocket, WebTransport and tunnelling

| RFC | Title | Status | Notes |
|-----|-------|--------|-------|
| 6455 | The WebSocket Protocol | Full | Framing parsed in both directions by `websocket_guard`: reserved bits and opcodes, masking, control frame size and fragmentation, continuation state, close codes and UTF-8 validity |
| 7692 | Compression Extensions for WebSocket | Refused | No extension is negotiated on an inspected route, and a frame arriving with a reserved bit set — which is what `permessage-deflate` uses — closes the connection with a protocol error. A compressed frame cannot be inspected, so accepting it would turn every check off silently |
| 9297 | HTTP Datagrams and the Capsule Protocol | Full | Under CONNECT-UDP and CONNECT-IP |
| 9298 | Proxying UDP in HTTP | Full | One socket per session, pinned to the target it was opened for |
| 9484 | Proxying IP in HTTP | Partial | ADDRESS_ASSIGN and ROUTE_ADVERTISEMENT with per-packet anti-spoofing; the tunnel device is created by the operator, and the proxy refuses to start a session without `ip_assign` and `ip_routes` |

## TLS and certificates

| RFC | Title | Status | Notes |
|-----|-------|--------|-------|
| 8446 | TLS 1.3 | Full | Through Go's `crypto/tls` |
| 5246 | TLS 1.2 | Full | The floor; `min_version` raises it |
| 6066 | TLS Extension Definitions | Full | Server name, maximum fragment length, certificate status request |
| 7301 | ALPN | Full | Protocol selection on every TLS listener |
| 5280 | X.509 Certificate and CRL Profile | Full | Chain building and verification |
| 6960 | Online Certificate Status Protocol | Full | Stapling, refreshed on a schedule |
| 6962 | Certificate Transparency | Full | SCT checks on upstream certificates |
| 8555 | Automatic Certificate Management Environment (ACME) | Full | `http-01` and `tls-alpn-01` |
| 8737 | ACME TLS ALPN Challenge Extension | Full | |
| 7748 | Elliptic Curves for Security | Full | X25519, and the classical half of the hybrid group |
| 8032 | Edwards-Curve Digital Signature Algorithm | Full | Ed25519 keys and host keys |
| 9180 | Hybrid Public Key Encryption | Full | Under Encrypted Client Hello |
| 5869 | HMAC-based Key Derivation Function | Full | Within the TLS stack and HPKE, not called directly |
| 2104 | HMAC | Full | Cookie signing, origin signatures, one-time passwords |
| 8018 | PKCS #5: Password-Based Cryptography v2.1 | Full | PBKDF2 for every password this proxy stores |

Two of the things this proxy does in TLS are not RFCs yet, and are
named here so nobody has to guess:

- **Encrypted Client Hello** follows `draft-ietf-tls-esni`, version
  `0xfe0d`. The wire format, the config list and the retry behaviour are
  implemented; the draft is stable enough that browsers ship it, and
  unstable enough that the version is pinned in one place.
- **X25519MLKEM768**, the post-quantum hybrid, follows
  `draft-kwiatkowski-tls-ecdhe-mlkem` over the ML-KEM of FIPS 203. It is
  the default first group, because a session recorded today is a session
  decrypted later.

## DNS

| RFC | Title | Status | Notes |
|-----|-------|--------|-------|
| 1034 / 1035 | Domain Names: concepts and implementation | Full | Message parsing and encoding, one question per query |
| 3597 | Handling of Unknown DNS Resource Record Types | Full | Which record types may carry compressed names, and which may not |
| 6891 | Extension Mechanisms for DNS (EDNS(0)) | Full | Including the advertised UDP size |
| 7766 | DNS Transport over TCP | Full | Fallback on truncation, and the TCP listener |
| 9715 | IP Fragmentation Avoidance in DNS over UDP | Full | Answers are capped at 1232 octets so a spoofed source cannot draw a large reply |
| 8482 | Providing Minimal-Sized Responses to DNS Queries with QTYPE=ANY | Full | `ANY` is answered minimally rather than expanded |
| 7858 | DNS over TLS | Full | ALPN `dot`, with session resumption to upstreams so a reconnect is not a full handshake (`upstream_resumption`) |
| 8484 | DNS Queries over HTTPS | Full | POST `application/dns-message` with id 0 |
| 9156 | DNS Query Name Minimisation | Not applicable | Minimisation is a recursive resolver's: it is what stops the root and the TLD seeing the whole name while the resolver walks the delegation chain. This listener is a validating **forwarder** -- one upstream is asked the question and does the recursion -- so there is no chain here to walk and nothing the minimisation would hide from anyone who is not already being asked. Its own DNSKEY and DS lookups are for the zone being validated, not a walk of the name |
| 9250 | DNS over Dedicated QUIC Connections | Full | |
| 9460 | Service Binding and Parameter Specification (SVCB and HTTPS RRs) | Full | Canonical parameter encoding; a record that is not in canonical form is refused |
| 9461 | Service Binding Mapping for DNS Servers | Full | `alpn`, `port`, `dohpath` |
| 9462 | Discovery of Designated Resolvers | Full | `_dns.resolver.arpa` |
| 4033 / 4034 / 4035 | DNSSEC | Full | Validation to a trust anchor before an answer is cached or served |
| 5155 | DNS Security (DNSSEC) Hashed Authenticated Denial of Existence | Full | NSEC3 closest-encloser proofs |
| 9276 | Guidance for NSEC3 Parameter Settings | Full | Iteration counts above the guidance are refused rather than computed |
| 6840 | Clarifications and Implementation Notes for DNSSEC | Full | |
| 8198 | Aggressive Use of DNSSEC-Validated Cache | Partial | `dnssec.aggressive_nsec`: a validated NSEC gap answers NXDOMAIN for a sibling of the name it was collected for, and only for a client that set neither DO nor CD. NSEC3 gaps are not used, and a validated NODATA or wildcard answer is not reused |
| 3110 | RSA/SHA-1 SIGs and RSA KEYs in the Domain Name System | Full | The DNSKEY exponent and modulus form |
| 6147 | DNS64: DNS Extensions for Network Address Translation from IPv6 Clients to IPv4 Servers | Partial | AAAA synthesis for a name with only an A record, per client network, with the IPv4 address screened by `answer_policy` before it is embedded and no AD bit on a synthesised answer. PTR synthesis for the prefix, and the prefix discovery of RFC 7050, are not implemented |
| 6052 | IPv6 Addressing of IPv4/IPv6 Translators | Full | The address placement at all six defined prefix lengths, checked against the RFC's own worked example |
| 2606 | Reserved Top Level DNS Names | Full | Used throughout the decoys and tests, so nothing in them resolves |

## Mail

| RFC | Title | Status | Notes |
|-----|-------|--------|-------|
| 5321 | Simple Mail Transfer Protocol | Full | Commands, replies and the DATA terminator, decided once by the proxy rather than twice by its peers |
| 5322 | Internet Message Format | Partial | Line structure only. The proxy does not parse headers or rewrite a message; it decides where lines and messages end |
| 6409 | Message Submission for Mail | Full | The submission listener |
| 3207 | SMTP Service Extension for Secure SMTP over TLS | Full | Including the refusal of anything pipelined behind `STARTTLS` (CVE-2011-0411) and the reset of session state afterwards |
| 8314 | Cleartext Considered Obsolete: Use of TLS for Email Submission and Access | Full | Implicit TLS on 465 |
| 1870 | SMTP Service Extension for Message Size Declaration | Full | `SIZE` advertised and enforced |
| 4954 | SMTP Service Extension for Authentication | Full | Relayed, including multi-round challenges; the credentials are never held or logged |
| 2920 | SMTP Service Extension for Command Pipelining | Full | Except behind `STARTTLS`, where it is a refusal |
| 3463 | Enhanced Mail System Status Codes | Full | On every reply the proxy writes itself |
| 3030 | SMTP Service Extensions for Transmission of Large and Binary MIME Messages | Refused | `CHUNKING` and `BDAT` are never advertised or relayed: BDAT frames a message with a length instead of a terminator, which would put the framing decision back in two places |

## Messaging

MQTT is not an IETF protocol. Both versions this proxy speaks are OASIS
standards, and 3.1.1 is also ISO/IEC 20922:2016.

| Specification | Status | Notes |
|---------------|--------|-------|
| MQTT 3.1.1 (OASIS, ISO/IEC 20922) | Full | Framing, CONNECT, PUBLISH, SUBSCRIBE and UNSUBSCRIBE parsed; everything else relayed |
| MQTT 5.0 (OASIS) | Full | Property blocks are stepped over rather than interpreted: nothing in them is a policy decision here, and parsing what it does not use is how a proxy grows bugs |

## Secure Shell and file transfer

| RFC | Title | Status | Notes |
|-----|-------|--------|-------|
| 4251 | SSH Protocol Architecture | Full | Through `golang.org/x/crypto/ssh` |
| 4252 | SSH Authentication Protocol | Full | Public key and password, with RFC 4252 partial success when a second factor is required |
| 4253 | SSH Transport Layer Protocol | Full | |
| 4254 | SSH Connection Protocol | Full | Every channel type and every session request is a policy decision, not a relay. An `exec` command line is split the way a POSIX shell splits one simple command, and the transfer families (scp, rsync, the sftp server, git's transport verbs) are read the way each program reads its own arguments, so a rule decides on what the command means |
| 4256 | Generic Message Exchange Authentication (keyboard-interactive) | Full | How the one-time code is asked for |
| 8332 | Use of RSA Keys with SHA-256 and SHA-512 | Full | |
| 8709 | Ed25519 and Ed448 Public Key Algorithms for SSH | Full | Ed25519 |
| `draft-ietf-secsh-filexfer-02` | SSH File Transfer Protocol, version 3 | Full | SFTP is a draft, not an RFC. Version 3 is what every deployed client speaks; a client negotiating higher is refused rather than guessed at |

## Proxying and forwarding

| RFC | Title | Status | Notes |
|-----|-------|--------|-------|
| 1928 | SOCKS Protocol Version 5 | Full | CONNECT and UDP ASSOCIATE |
| 1929 | Username/Password Authentication for SOCKS V5 | Full | Against the same users file as the HTTP proxy |
| 1961 | GSS-API Authentication Method for SOCKS V5 | Refused | Not implemented; a client offering only GSSAPI gets method `0xFF` |
| SOCKS4 / 4a | | Refused | No authentication and, in SOCKS4, no names. Every modern client speaks SOCKS5 |
| 9298 / 9484 | Proxying UDP and IP in HTTP | See above | |

The PROXY protocol, inbound and outbound, is not an RFC: it is
HAProxy's specification, versions 1 and 2, both implemented.

## Identity, tokens and authentication

| RFC | Title | Status | Notes |
|-----|-------|--------|-------|
| 7519 | JSON Web Token | Full | Verification, with the algorithm confusion defences of RFC 8725 |
| 7515 | JSON Web Signature | Full | |
| 7517 | JSON Web Key | Full | JWKS fetching and rotation |
| 7518 | JSON Web Algorithms | Partial | The signature algorithms a token may use; `none` is refused, and a key's type must match the algorithm |
| 7638 | JSON Web Key Thumbprint | Full | Key identification |
| 8725 | JSON Web Token Best Current Practices | Full | Issuer, audience, expiry and algorithm pinned rather than read from the token |
| 6749 | The OAuth 2.0 Authorization Framework | Partial | The authorization code flow, as a relying party, with PKCE, a nonce and a state cookie |
| 7662 | OAuth 2.0 Token Introspection | Full | |
| 7636 | Proof Key for Code Exchange | Full | The `oidc` filter sends `code_challenge` with `S256` and the verifier from its state cookie |
| 9449 | OAuth 2.0 Demonstrating Proof of Possession (DPoP) | Full | The proof, its claims, the RFC 7638 thumbprint and the `cnf.jkt` binding, with a bounded replay cache for `jti` |
| 8693 | OAuth 2.0 Token Exchange | Partial | As a client: a verified token is exchanged for one the backend can use, narrowed by audience, resource or scope. This proxy is not an exchange endpoint |
| 8707 | Resource Indicators for OAuth 2.0 | Full | The `resource` parameter of an exchange |
| 8705 | OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens | Partial | The certificate-bound access token half (section 3): `cnf["x5t#S256"]` is compared with the client certificate of the connection, or with an RFC 9440 header from a trusted peer. Mutual-TLS *client authentication* to a token endpoint (section 2) is not implemented: this proxy is not one |
| 9440 | Client-Cert HTTP Header Fields | Full | `Client-Cert` and `Client-Cert-Chain` as RFC 8941 byte sequences, sent to the upstream and stripped from an untrusted peer |
| 8941 | Structured Field Values for HTTP | Partial | The byte sequence form the client certificate headers use |
| 8949 | Concise Binary Object Representation (CBOR) | Partial | The canonical (CTAP2) subset a WebAuthn attestation and COSE key use; indefinite lengths, tags, floats and duplicate keys are refused |
| 9052 | CBOR Object Signing and Encryption (COSE) | Partial | `COSE_Key` for ES256/384/512, EdDSA, RS256 and PS256, as WebAuthn credentials carry them |
| 4051 | Additional XML Security Uniform Resource Identifiers | Partial | The signature and digest algorithm identifiers the SAML profile accepts, including ECDSA as concatenated `r` and `s` |
| 4226 | HOTP: An HMAC-Based One-Time Password Algorithm | Full | Checked against every vector in appendix D |
| 6238 | TOTP: Time-Based One-Time Password Algorithm | Full | Checked against every vector in appendix B, for all three hashes |
| 4511 | Lightweight Directory Access Protocol (LDAP): The Protocol | Full | Bind and search, as a client |
| 4513 | LDAP: Authentication Methods and Security Mechanisms | Full | Simple bind over TLS or StartTLS |
| 4514 | LDAP: String Representation of Distinguished Names | Full | |
| 4515 | LDAP: String Representation of Search Filters | Full | Filters are parsed and re-encoded, never concatenated from user input |
| 2253 | UTF-8 String Representation of Distinguished Names | Full | The certificate subject form in identity headers |
| 7642 | System for Cross-domain Identity Management: Definitions, Overview, Concepts, and Requirements | Full | The provisioning model the `scim` endpoint implements: the directory is authoritative and pushes changes |
| 7643 | System for Cross-domain Identity Management: Core Schema | Partial | The `User` resource in the attributes this proxy keeps -- `userName`, `externalId`, `displayName`, `active`, `meta` -- plus an extension for what was provisioned. Groups, `Enterprise User`, names, e-mails, phone numbers and the other multi-valued attributes are not kept: this endpoint provisions credentials, and an attribute it stored and never read would be a directory nobody maintains |
| 7644 | System for Cross-domain Identity Management: Protocol | Partial | `GET`, `POST`, `PUT`, `PATCH` and `DELETE` on `/Users`, the three discovery endpoints, the error object with its `scimType`, and pagination. The filter grammar is the `userName eq "value"` subset and anything else is refused as `invalidFilter` rather than answered with the whole list; bulk, sort, ETags and `/Groups` are not implemented and the service provider configuration says so |

OpenID Connect Core 1.0 is an OpenID Foundation specification rather
than an RFC; the discovery document, the authorization code flow, the
ID token checks and front-channel logout are implemented. SAML 2.0 and
WebAuthn are not RFCs either; both are in the table at the end of this
document, with the parts of each that are implemented.

## Content, encoding and data formats

| RFC | Title | Status | Notes |
|-----|-------|--------|-------|
| 1952 | GZIP file format | Full | Request and response compression |
| 1950 / 1951 | ZLIB and DEFLATE | Full | |
| 7932 | Brotli Compressed Data Format | Full | |
| 8878 | Zstandard Compression and the application/zstd Media Type | Full | |
| 8259 | The JavaScript Object Notation (JSON) Data Interchange Format | Full | Bodies, configuration schema, the management API |
| 3629 | UTF-8, a transformation format of ISO 10646 | Full | Validated wherever a peer's encoding decides a boundary |
| 4648 | The Base16, Base32 and Base64 Data Encodings | Full | Including the base32 of an enrolment secret |
| 9530 | Digest Fields | Full | The body digest an origin signature covers |
| 3507 | Internet Content Adaptation Protocol (ICAP) | Full | `REQMOD` and `RESPMOD` with preview and `204 No Content` |
| 2046 | MIME Part Two: Media Types | Full | Multipart parsing |
| 4918 / 3023 | XML Media Types | Partial | An XML request body is scanned before the application parses it: no document type declaration, no entity reference but the five predefines, bounded depth, elements, attributes, names and text. XSD validation is deliberately not implemented; see CONFIG.md |

## Addressing, logging and operations

| RFC | Title | Status | Notes |
|-----|-------|--------|-------|
| 4291 | IP Version 6 Addressing Architecture | Full | |
| 5952 | A Recommendation for IPv6 Address Text Representation | Full | Every address this proxy logs, through `net/netip` |
| 4632 | Classless Inter-domain Routing (CIDR) | Full | Every prefix in the configuration |
| 1918 | Address Allocation for Private Internets | Full | The private ranges a forward policy refuses by default |
| 5737 | IPv4 Address Blocks Reserved for Documentation | Full | Used throughout the examples and decoys |
| 6598 | IANA-Reserved IPv4 Prefix for Shared Address Space | Full | `100.64.0.0/10` is in the set a forward policy refuses as private |
| 1071 | Computing the Internet Checksum | Full | The capture writer's synthesised packets |
| 5424 | The Syslog Protocol | Full | Structured data, RFC 3339 timestamps |
| 3164 | The BSD syslog Protocol | Full | For receivers that want the older form |
| 6587 | Transmission of Syslog Messages over TCP | Full | Octet counting and non-transparent framing |
| 3339 | Date and Time on the Internet: Timestamps | Full | Every timestamp in every log |
| 9562 | Universally Unique IDentifiers (UUIDs) | Partial | Recognised where a positive security policy declares a parameter to be one. Request identifiers are 96 random bits in hex, not UUIDs |
| 1123 | Requirements for Internet Hosts | Full | The host name rules, including the Kubernetes object name form |

## Not IETF standards

Things this proxy implements that have no RFC, listed so the absence is
not mistaken for an omission:

| Specification | Where | Notes |
|---------------|-------|-------|
| PROXY protocol v1 and v2 | HAProxy | Inbound from trusted peers, outbound to upstreams |
| MQTT 3.1.1 and 5.0 | OASIS (3.1.1 also ISO/IEC 20922) | |
| SFTP version 3 | `draft-ietf-secsh-filexfer-02` | |
| Encrypted Client Hello | `draft-ietf-tls-esni` | Version `0xfe0d` |
| X25519MLKEM768 | `draft-kwiatkowski-tls-ecdhe-mlkem`, FIPS 203 | |
| pcapng | `draft-ietf-opsawg-pcapng` | The capture file format |
| DNS Response Policy Zones | `draft-vixie-dns-rpz` (ISC) | The QNAME trigger and the five policy actions -- NXDOMAIN, NODATA, PASSTHRU, DROP, TCP-only -- plus local data, read from zone files in the master format a feed publishes. The `rpz-client-ip`, `rpz-ip`, `rpz-nsdname` and `rpz-nsip` triggers are refused by name at load: the last two need the resolver to police a delegation path this one forwards, and where an answer's addresses are the concern `answer_policy` screens them by range. `ignore_unsupported` loads such a zone without those rules and counts them |
| WebTransport over HTTP/3 | W3C and `draft-ietf-webtrans-http3` | |
| OpenID Connect Core 1.0 | OpenID Foundation | |
| SAML 2.0 Core, Bindings and Profiles | OASIS | As a service provider: the web browser single sign-on profile with the HTTP Redirect binding for requests and HTTP POST for responses. A deliberately narrow profile -- one unencrypted assertion, exclusive canonicalization, SHA-256 and above, the signing key from the configuration -- and no single logout. [CONFIG.md](CONFIG.md) lists every refusal and the reason for it |
| XML Signature Syntax and Processing | W3C | Verification only, of one enveloped signature per element: one `Reference` naming its own parent, the enveloped-signature transform and canonicalization and no other, no `KeyInfo` trust. No signature generation |
| Exclusive XML Canonicalization 1.0 | W3C | Full, without comments, including an `InclusiveNamespaces` prefix list. The inclusive canonicalization of `REC-xml-c14n-20010315` is refused rather than approximated |
| Web Authentication (WebAuthn) level 2 | W3C | Registration and authentication as a relying party; attestation is parsed but deliberately not verified (it identifies a model, not a person) |
| Content Security Policy, CORS | W3C and WHATWG Fetch | The response header policy and the CORS policy |
| Prometheus exposition format | Prometheus project | `/metrics` |
| OpenTelemetry Protocol (OTLP) | CNCF | Traces, metrics and logs |
| YARA | VirusTotal | A documented subset; see [CONFIG.md](CONFIG.md) for exactly which |
| ModSecurity SecLang, OWASP CRS | Coraza, OWASP | The WAF rule language |
| XCLIENT | Postfix | The SMTP extension that tells a mail server the real client |
| `X-Forwarded-Client-Cert` | Envoy | One of the two forms of client certificate identity passed to the upstream; RFC 9440's `Client-Cert` is the other; `client_cert_headers` chooses, and the default is to send neither |
| OpenSSH file formats | OpenSSH | `authorized_keys`, `known_hosts`, private keys |
| WebAssembly, WASI preview 1 | W3C, Bytecode Alliance | The filter ABI |
| Gateway API, Ingress | Kubernetes SIG Network | The ingress translator |

## What is deliberately not implemented

Each of these is recognised and refused. The refusal is the feature: a
proxy that passed them on would be reading a message differently from
the peer behind it.

| Thing | Where | Why |
|-------|-------|-----|
| `Transfer-Encoding` and `Content-Length` together, or `chunked` spelled oddly | HTTP/1.1 | The two framings disagree, and which one wins is what a smuggling attack chooses. The message is refused |
| A bare LF ending an SMTP line | SMTP | It ends the line for a permissive parser and not for a strict one, which is the whole of SMTP smuggling. Refused, or repaired to CRLF and re-emitted, never passed through |
| `CHUNKING` / `BDAT` | SMTP | A length-framed message would put the end-of-message decision back in two places |
| Data pipelined behind `STARTTLS` | SMTP | Written before the client could see the `220`: plaintext for one side, ciphertext for the other |
| `permessage-deflate` | WebSocket | A compressed frame cannot be inspected; accepting the extension would disable every check silently |
| A non-shortest MQTT remaining length | MQTT | Two spellings of one length are two readings of one packet |
| An MQTT version the proxy cannot parse | MQTT | A packet it cannot check is a packet it cannot allow |
| An SFTP version above 3 | SFTP | Packets this cannot be trusted to read; the policy would be guesswork |
| An unimplemented `:protocol` on extended CONNECT | HTTP/2, HTTP/3 | Answered `501` rather than falling through to a TCP tunnel, so a request cannot be read as one thing here and another by a peer |
| SOCKS4, SOCKS4a, SOCKS `BIND` | SOCKS | No authentication, no names, and `BIND` asks the proxy to open a listening socket on a client's say-so |
| YARA modules, `at`, `for`, unbounded jumps, `@a` | YARA | Refused at load with the line number. A rule that silently matched nothing would be worse than one that will not start |
| An upstream reply the proxy cannot parse | SMTP, MQTT | Never passed on: it is exactly the reply the client would read differently |

## Keeping this honest

Every row above is something the code does, and most of them have a
test that names the RFC in its comment. The ones worth reading, if you
want to check rather than trust: `internal/smtp`, `internal/mqtt`,
`internal/sftp`, `internal/masque` and `internal/dns` each hold their
protocol's parser and its table of malformed inputs, and
[TESTS.md](TESTS.md) says what each of those tables proves.

If you find a row that overstates what is implemented, that is a bug in
this document and worth reporting as one.
