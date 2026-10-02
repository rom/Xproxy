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
- [Industrial control](#industrial-control)
- [Network management](#network-management)
- [Directory](#directory)
- [Authentication, authorisation and accounting](#authentication-authorisation-and-accounting)
- [Provisioning](#provisioning)
- [Addressing](#addressing)
- [Time](#time)
- [Secure Shell and file transfer](#secure-shell-and-file-transfer)
- [Remote desktop and terminal access](#remote-desktop-and-terminal-access)
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
| 7692 | Compression Extensions for WebSocket | Refused | On an inspected route the client's offer is **stripped from the upgrade request**, so no extension is negotiated anywhere on the path and both endpoints fall back to uncompressed frames — which is what the extension is designed to do when it is not agreed, and what keeps a browser (every one of which offers it by default) working. An origin that claims an extension regardless is refused at the 101 with `502`, and a frame arriving with a reserved bit set closes the connection with a protocol error, which now genuinely means a misbehaving peer. A compressed frame cannot be inspected, so accepting one would turn every check off silently |
| 9297 | HTTP Datagrams and the Capsule Protocol | Full | Under CONNECT-UDP and CONNECT-IP |
| 9298 | Proxying UDP in HTTP | Full | One socket per session, pinned to the target it was opened for |
| 9484 | Proxying IP in HTTP | Partial | ADDRESS_ASSIGN and ROUTE_ADVERTISEMENT with per-packet anti-spoofing; the tunnel device is created by the operator, and the proxy refuses to start a session without `ip_assign` and `ip_routes` |


**Why the extension is not decompressed instead, and what would change that.**
Inspecting a compressed frame means running DEFLATE over bytes a peer chose,
which is the one thing the rest of this guard is built to avoid: its stated
design rule is that the proxy's memory must not be a function of what a client
sends, which is why an oversize message is checked to a bound and forwarded
rather than buffered. A DEFLATE stream inverts that — a small frame expands to
an arbitrary one, `permessage-deflate` keeps its dictionary *across* messages
so the state is per connection and cannot be dropped between frames, and
`client_max_window_bits` lets the peer pick how much of that state the proxy
must hold. A bounded implementation is possible (a hard ceiling on the
decompressed size per message and on the window, the connection closed on
either) but it is a resource-exhaustion surface bought deliberately, per route,
for the bandwidth of one extension.

So the decision is: **not by default, and not implicitly.** If it is added it
is an explicit per-route opt-in with its own bounds, sitting beside the message
schemas and per-type limits rather than arriving as a side effect of a client's
offer, and the route that turns it on accepts the cost in writing. Until then
the honest arrangement is the one above: no negotiation, uncompressed frames,
every check working.

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

## Industrial control

Modbus is not an IETF protocol either. The application protocol and the
serial line specification are the Modbus Organization's, as is the
security one, and none of the three has an RFC.

| Specification | Status | Notes |
|---------------|--------|-------|
| Modbus Application Protocol v1.1b3 | Full | Every public function code -- 1 to 24 and 43 -- parsed as request and response, with the specification's own bounds enforced: the quantity limits, the byte counts, the single-coil values, the file record shapes, the MEI types, and a range that runs past the address space. Function codes 65 to 72 and 100 to 110 are recognised as user-defined and can be named in a rule; anything else is refused rather than forwarded |
| Modbus over Serial Line v1.02 | Full, as tunnelled over TCP | RTU and ASCII framing, in both directions. RTU has no delimiters, so a frame's length is computed per function code and direction and the CRC is the check that it ended where the device will think it did; the inter-frame silence of a real serial line has no equivalent on a stream, so a shape whose length cannot be computed -- a CANopen request, a response to a request that was not made -- is refused rather than guessed at |
| Modbus/TCP Security v21 (MB-TCP-Security) | Partial | TLS with mutual authentication on the listener and towards the device, and authorisation by the role in the client certificate's x.509 extension under the Modbus arc, `1.3.6.1.4.1.50316.802.1`. The role-to-object-list mapping in the specification's appendix is not read from the certificate: the rules in the configuration are richer than it (function codes, register ranges, value bounds, schedules) and are where a plant's policy actually lives |

## Telecontrol

IEC 60870-5-104 is an IEC standard, not an IETF one, and neither it nor the
companion standard it inherits its application layer from has an RFC. The
security standard that wraps it, IEC 62351-3, is a profile of TLS.

| Specification | Status | Notes |
|---------------|--------|-------|
| IEC 60870-5-104 (APCI and APDU) | Full | The framing -- start octet, length, four control octets -- and the three formats. I frames carry both sequence numbers, S frames the receive number, U frames one of the six control functions; a frame whose format says it carries nothing and whose length says otherwise is refused rather than read as empty, because that shape is how an ASDU is smuggled past a check that only looks at I frames. The sequence numbers are checked in both directions against the window (k) the two ends agreed on |
| IEC 60870-5-101 (ASDU structure and semantics) | Partial, by design | The ASDU header is read whole: the type identification, the variable structure qualifier with its sequence bit, the cause of transmission with its test and negative bits, the originator address and the common address. The information object *addresses* are read in both shapes the standard allows (per object, or implied by the first in a sequence), and a command's qualifier octets are kept so that the select bit and a value bound can be read. The information object *elements* are decoded for the types whose layout is in the table of IEC 60870-5-101 section 7.3.1 -- the value in its five encodings, the quality descriptor's five bits, and both time tags -- and are never re-encoded: every frame is forwarded as the octets that arrived, because decoding a hundred-odd types and writing them back out is how a relay and a station come to disagree about a reading nobody can trace. A type whose element layout is not in that table decodes to nothing rather than to a guess, and a type identification the standard does not define at all is forwarded with its addresses unread and can still be named in a rule by number |
| IEC 60870-5-101 quality descriptors and time tags | Read, policed, never rewritten | The five quality bits (IV, NT, SB, BL, OV) wherever they appear -- the QDS octet of a measurement, the SIQ of a single point, the DIQ of a double point, with the state bits masked out of the last two. CP56Time2a whole; CP24Time2a as minutes and milliseconds with no date, which is why nothing is concluded about its age. A field outside its range is reported as no timestamp rather than normalised into a date the station never sent |
| IEC 60870-5-7 / IEC 62351-5 (secure authentication) | Recognised and requirable, not verified | The thirteen `S_*` ASDUs are named, form the rule class `security`, and are carried: a listener that refused them as unknown types would make the standard's own authentication unusable through this relay, which is the failure that most needed avoiding. The replies and aggressive-mode requests are counted, and `authentication: {require: true}` refuses a command on an association that has shown no exchange inside a window. **No HMAC is computed and no key is held.** Verifying means holding the update keys, which would make the relay a second place to take them from, and one that failed closed on a key it had got wrong would stop a control centre operating a grid. What is asserted is that the exchange took place, per association, which is the most a party in the middle can honestly assert |
| Select-before-operate (IEC 60870-5-101 §7.3.2) | Enforced, which the standard does not require | The standard describes the two-step form; the equipment mostly accepts a bare execute. `require_select` makes it mandatory: a selection is remembered per connection, per common address, per information object address and per type identification, expires, authorises one execution, and is withdrawn by a deactivation. The bitstring commands, which have no two-step form, are exempt |
| IEC 62351-3 (TLS for the 60870-5-104 profile) | Partial | TLS from the first octet on the listener and towards the station, with the project's own hardened defaults (TLS 1.2 minimum, mutual authentication, no renegotiation) rather than the standard's own cipher list, which is older than the deployed TLS stacks. The certificate revocation and key-management requirements of the standard are the estate's, not this proxy's |
| IEC 60870-5-104 file transfer (types 120 to 127) | Recognised, not interpreted | The type identifications are named and can be allowed or refused as a class; the file segments themselves are relayed without being reassembled or scanned. A relay that reassembled them would need to hold a substation's disturbance record in memory to decide about it |

## Network management

SNMP is IETF work, and unusually complete as standards go: three versions,
a security model, a transport mapping onto TCP and a TLS profile all have
RFCs. What the table says is which parts of that a *relay* can honestly
implement without holding the keys an agent holds.

| RFC | Title | Status | Notes |
|-----|-------|--------|-------|
| 1157 | SNMP version 1 | Full, as a relay | The message, the community string, the five PDU types and the v1 trap with its own header (enterprise, agent address, generic and specific trap, timestamp). Its error statuses are the vocabulary a v1 refusal is written in: it has no `noAccess`, so a refusal is `noSuchName`, which is what a v1 agent answers for an object outside the community's view |
| 1901 | Community-based SNMPv2 (SNMPv2c) | Full, as a relay | The version field, the community string, and the framework the v2 PDU types live in |
| 1905 | Protocol Operations for SNMPv2 | Full | All eight PDU tags, including GETBULK with its non-repeaters and max-repetitions -- the field this protocol's amplification is measured in -- and the Inform and Report PDUs. A GETBULK past the configured bound is *lowered* rather than refused, because refusing breaks a poller nobody can reconfigure and lowering removes the amplifier |
| 1906 | Transport Mappings for SNMPv2 | Partial | The UDP mapping, and the maximum message size it implies (65507 octets) as the outer bound on anything this relay will read. The OSI, DDP and IPX mappings are not implemented and are not coming |
| 1907 | Management Information Base for SNMPv2 | Not applicable | This relay has no MIB of its own and answers no query about itself: its own numbers are in the Prometheus exposition and the management API. A relay that answered SNMP about itself would be one more agent to secure |
| 2578 / 2579 / 2580 | SMIv2, Textual Conventions, Conformance Statements | Not applicable, by design | The *values* in a binding are never interpreted: a binding's type tag and extent are read and what a `Counter64` means is not. Interpreting them would need a MIB per estate, and a relay that mis-decoded one would corrupt a reading nobody could trace. Object identifiers are compared structurally, per sub-identifier, which needs no MIB |
| 3411 | SNMP Management Frameworks (the architecture) | Partial | The v3 message header is read as the architecture defines it: message identifier, maximum size, the flags that carry the security level and the reportable bit, and the security model. The engine identifier bound of 32 octets is enforced. This relay is not an SNMP engine: it does not maintain engine boots and time, and it does not participate in discovery |
| 3412 | Message Processing and Dispatch | Partial | The v3 message is dispatched on its security model and level, and the scoped PDU is read when there is one. A message whose model is not USM has its security parameters left unread rather than guessed at |
| 3414 | User-based Security Model (USM) | Read, never verified | The USM parameters are parsed -- engine identifier, boots, time, user name, and the extents of the authentication and privacy parameters -- and the user name and security level are what a policy is written about. The HMAC is **not verified** and the payload is **not decrypted**, because that needs the user's keys and a relay is not given them. Pretending to check would be worse than saying it cannot: so an `authPriv` message is decided about on its header and forwarded, and is reported as `snmp_encrypted` rather than as inspected |
| 3416 | Protocol Operations for SNMPv3 | Full | The same eight PDU types inside a v3 scoped PDU, with the context engine identifier and context name, which a rule can name |
| 3417 | Transport Mappings for SNMPv3 | Partial | UDP, as above |
| 3430 | SNMP over TCP | Full | A message on a stream is a BER SEQUENCE and its own length field delimits it. The length is decided about *before* the octets it claims are read, because reading them to find out what they asked for is the work the bound exists to avoid; and there is no resynchronisation, because a stream whose framing is wrong is a stream whose next octet is unknown |
| 6353 | Transport Layer Security Transport Model (TLSTM) | Partial | TLS from the first octet on the stream side, on the standard's own port 10161, which is the half of the secure upgrade that faces a management station. The `tmSecurityName` derived from the certificate is not mapped to a USM user: the policy is written about the transport identity (the client list, the certificate the listener requires) and the credential in the message, which is what an estate can actually configure. DTLS on 10162 (RFC 5953) is **not implemented**, so a listener that is TLS throughout is a TCP one |
| 5343 | SNMP Context EngineID Discovery | Not implemented | Discovery is an engine's job, and this is not an engine |
| 5590 / 5591 | Transport Subsystem and Transport Security Model | Partial | Only as much of the model as RFC 6353 needs to make sense: a message that arrived over a secure transport is known to have done so, and that is in the access log. The security-name plumbing of the full model is not implemented |
| 3826 | AES-128 in the SNMP USM | Not implemented | Nothing here decrypts a payload, so there is no cipher to support. This is the same statement as RFC 3414 above, said where somebody would look for it |

Two rewrites are worth naming here because they are the ones a reader will
ask about. The version a message is forwarded in can be rewritten
*downwards* -- v3 or TLS facing the manager, v2c facing the switch -- and
the answer is rebuilt in the version the question used. Producing v3 is
refused at load, and downgrading a v3 **request** is refused at the
message, both for the same reason: RFC 3414 authentication needs a key this
relay does not hold, and a relay that produced an unauthenticated v3
message, or handed a v3 manager a v2c answer, would be telling somebody
their traffic was authenticated when nobody had checked. A v3
**notification** downgrades cleanly, because nothing comes back.

## Directory

LDAP is IETF work and its version 3 core is a tidy set of documents. What the
table says is which parts of them a *relay* implements, which it deliberately
does not, and where it makes a decision the standard leaves to a server.

| RFC | Title | Status | Notes |
|-----|-------|--------|-------|
| 4511 | LDAP: The Protocol | Partial, as a relay | The LDAPMessage envelope and every operation's shape: bind (simple and SASL), unbind, search, modify, add, delete, modifyDN, compare, abandon, extended, and the responses and entries that answer them, with controls read by OID and criticality. The framing is the message's own BER length, decided about before the octets it claims are read; indefinite length is refused, because it would make a message's extent depend on finding an end-of-contents pair inside a value this relay does not interpret. Message identifier 0 from a client is refused: it is reserved for the server's unsolicited notification |
| 4512 | Directory Information Models | Not applicable, by design | This relay has no schema and no subschema subentry. It reads *attribute descriptions* -- names, with the transfer option after a semicolon stripped for comparison -- and never an attribute's syntax, matching rules or values. Interpreting values would need the estate's schema, and a relay that mis-decoded one would corrupt what an application reads |
| 4513 | Authentication Methods and Security Mechanisms | Partial, and the reason for the kind | §5.1.1 anonymous bind, §5.1.2 **unauthenticated bind** and §5.1.3 name/password bind are read as three different statements, and the middle one is refused by default: a name with an empty password is an anonymous bind the directory answers with success, and the application behind it reads that success as a correct password. §5.1.3's own warning about the password travelling in the clear is `require_tls`, on by default and not shadowable. §3 StartTLS is implemented on the client's side and terminated here rather than forwarded, and §5.1.7's rule that the authentication state is discarded on an upgrade is enforced. SASL itself is **not implemented**: the mechanism name is policy and the exchange is relayed, because a relay that terminated GSSAPI would need the estate's Kerberos keys |
| 4514 | String Representation of Distinguished Names | Partial | The escaping, the quoted form RFC 1779 left behind, the hex escapes, and the insignificant space -- enough to split a name into its relative names and compare one against another from the root, which is what a subtree policy is. Full normalisation needs the schema (which attributes are case-sensitive, which are numeric or telephone strings), so the value is folded to lower case instead: a *deny* by name cannot be evaded with a capital letter, and an *allow* may admit a name the directory itself then says does not exist |
| 4515 | String Representation of Search Filters | Partial | The string form is parsed for the `ldap_auth` filter's own templates. The relay reads filters in their **BER** form and as a *shape* rather than a query: the depth, the term count, the attributes named, and whether any substring term begins with a wildcard no index can serve. The assertion values are not read -- what a client is looking for is the estate's business; what it is looking in, and how hard the looking is, is the relay's |
| 4517 | Syntaxes and Matching Rules | Not applicable | See RFC 4512: values are not interpreted. Extensible match assertions are recognised by shape and their matching rule OID is not evaluated -- which is why Active Directory's bit-and rule (`1.2.840.113556.1.4.803`) can be *named* in a filter this relay carries and is not computed here |
| 4519 | Schema for User Applications | Reference only | The names in the built-in `deny_attributes` list come from this and from the Active Directory and Samba schemas. They are strings to match, not schema this relay holds |
| 4532 | "Who am I?" extended operation | Recognised | `1.3.6.1.4.1.4203.1.11.3`, allowed or refused by OID like any extended operation, and not interpreted |
| 3062 | LDAP Password Modify extended operation | Recognised | `1.3.6.1.4.1.4203.1.11.1`, named separately in the documentation because it is the one extended operation that changes a credential, and refused unless a listener names it |
| 4533 | Content Synchronization Operation | Recognised, not interpreted | The control is carried unless a listener refuses it. A relay that decided about a replication stream would be a replica |
| 2696 | Simple Paged Results Control | Carried | `1.2.840.113556.1.4.319` is a control like any other. The relay's own `max_entries` is counted **per search**, not per page, because a client that pages through a directory has still copied it |
| 4370 | Proxied Authorization Control | Carried, and worth refusing | `2.16.840.1.113730.3.4.18` lets a bound identity act as another, which is exactly the thing a policy keyed on the bound identity is about. It is carried by default because the directory decides about it, and `deny_controls` is where a listener that keys its rules on identity should name it |
| 2849 / 2891 | LDIF, Server Side Sorting | Not applicable / carried | LDIF is a file format nothing here reads. The sort control is carried |
| 3673 | `+` for all operational attributes | Read | `*`, `+` and an empty attribute list are the three ways a search asks for attributes it did not name, which is why the attribute policy has to apply to the answer as well as to the question |
| 2830 | StartTLS (obsoleted by 4511/4513) | Historical | The OID `1.3.6.1.4.1.1466.20037` is from here, and the notice of disconnection's `1.3.6.1.4.1.1466.20036` with it |
| 1777 / 1779 | LDAPv2 | Refused by default | Version 2 is a different protocol wearing the same tags: no SASL bind, a different string syntax. `min_version` defaults to 3, and a directory that still answers version 2 is one nobody has looked at |

Two things this relay decides that the standard leaves to a server, said
plainly because they change what a client sees. A refused request is answered
with `insufficientAccessRights` (50) or `unwillingToPerform` (53) -- a
*refused bind* always with `invalidCredentials` (49), because that is the only
code a client treats as a failed login rather than a server fault. And a
search that reaches the relay's entry bound is completed with
`sizeLimitExceeded` (4), which is exactly what a directory with an
administrative limit sends: the client knows it has part of an answer, rather
than hanging on a connection that will say nothing more.

## Authentication, authorisation and accounting

The three protocols an estate's own equipment authenticates against,
rather than the ones its web applications use: RADIUS and TACACS+ for
the network gear, and Kerberos where the directory is Active Directory.
None of them is cryptographically sound by current standards and all
three carry credentials, which is the argument for a proxy in front of
them.

| RFC | Title | Status | Notes |
|-----|-------|--------|-------|
| 2865 | Remote Authentication Dial In User Service (RADIUS) | Partial | The packet, every attribute of the base dictionary, the Response Authenticator verified on the way back and recomputed for the client, and the User-Password obfuscation recognised but never undone. The relay does not authenticate anybody itself: it decides about requests and replies and carries them |
| 2866 | RADIUS Accounting | Partial | Accounting-Request and Accounting-Response are carried and counted; the Request Authenticator of an accounting packet is a digest rather than a nonce, so it is verified as one |
| 2869 | RADIUS Extensions | Partial | The attributes that matter to a policy: EAP-Message, Message-Authenticator and the tunnel attributes a reply grants with |
| 3579 | RADIUS Support For Extensible Authentication Protocol | Full | The keyed Message-Authenticator, verified on both legs and recomputed when a packet is renumbered. `require_message_authenticator` makes it mandatory, which is the protocol's own mitigation for CVE-2024-3596 |
| 3748 | Extensible Authentication Protocol (EAP) | Partial | The header, the method, an identity, and a Nak's list of methods the client would accept instead -- enough for a policy about which methods may be negotiated. No EAP method is implemented: this is not an authenticator |
| 6929 | RADIUS Protocol Extensions | Partial | The extended attribute types (241 to 246) are read as what they are, so a rule names one by its extended number rather than by the octet it shares with 245 others |
| 2548 | Microsoft Vendor-specific RADIUS Attributes | Partial | Vendor-specific attributes are unwrapped where the inner length agrees with the outer, which is how a privilege grant is found: the four vendor spaces an estate's equipment actually uses have names, and the rest are readable by number |
| 5176 | Dynamic Authorization Extensions to RADIUS | Refused | A Change-of-Authorization or Disconnect-Request is an unsolicited packet that logs a session out or rewrites its authorisation, sent to a client that may accept it from any address with the right secret. It is recognised, counted and refused rather than relayed; an estate that needs it has a path that does not run through a security proxy |
| 8907 | The TACACS+ Protocol | Partial | The header, the authentication, authorization and accounting bodies, the argument list, and the obfuscation of section 5.2 -- implemented as the keyed MD5 pad it is, which section 10.3 itself calls "not cryptographically sound". Single-connection mode is read, so several sessions on one connection are kept apart. A `FOLLOW` reply is refused rather than carried, because it redirects the device to another server with another key |
| 4120 | The Kerberos Network Authentication Service (V5) | Partial | AS-REQ, AS-REP, TGS-REQ, TGS-REP, AP-REQ and KRB-ERROR are read down to what a policy decides about: the realm, the client and server principals, the requested options, the encryption types offered, the pre-authentication types present and the ticket lifetime. No Kerberos cryptography is performed and no key is held: an encrypted part is recognised and its encryption type read, never decrypted |
| 4556 | Public Key Cryptography for Initial Authentication in Kerberos (PKINIT) | Partial | Its pre-authentication types are recognised as pre-authentication, so a certificate-based logon is not mistaken for an exemption. The certificate itself is not validated here |
| 6113 | A Generalized Framework for Kerberos Pre-Authentication | Partial | An FX-FAST armoured request is recognised as pre-authenticated; what is inside the armour is not read |
| 8009 | AES Encryption with HMAC-SHA2 for Kerberos 5 | Partial | The two encryption types, as names a policy allows or requires |
| 4757 | The RC4-HMAC Kerberos Encryption Types | Partial | Recognised and nameable, because a request offering nothing but RC4 is what Kerberoasting looks like. An estate can refuse it outright with `refuse_weak_etypes` |

## Provisioning

TFTP is four short documents and one of the oldest protocols still in daily
use. What the table says is which parts a *relay* implements, and what it does
about the fact that there is nothing in any of them to authenticate with.

| RFC | Title | Status | Notes |
|-----|-------|--------|-------|
| 1350 | The TFTP Protocol (Revision 2) | Implemented, as a relay | All five opcodes: read and write requests, data, acknowledgement and error. A request's filename and mode are read as zero-terminated netascii strings and a field with **no terminator is refused** rather than read to the end of the packet, because "to the end of the packet" is one server's reading and another's parser may take a different one -- and a filename that runs past its field is exactly where the two differ. An acknowledgement's body must be **exactly** two octets, for the same reason. The transfer identifier rules of §4 are what a transfer here is bounded to: one socket per transfer, the client's port on one side, and the first port the server answered from on the other. §4 says a packet from an unknown identifier should be answered with error 5; this relay **drops it instead**, because answering an address that has no part in the transfer is how a relay becomes a reflector. The `mail` mode is read and refused by default: the standard itself removed it, and it asked a server to deliver the file as mail to the address in the filename field |
| 2347 | TFTP Option Extension | Implemented | The option acknowledgement, and the rule that the server answers in the request's order with values no larger than it was offered. A server that acknowledges a **larger** block size or window than the request carried ends the transfer, because the two ends would then disagree about how much is coming. Error code 8 is what a request whose options are outside this relay's bounds is answered with, since that is the one a client may legitimately retry without them |
| 2348 | TFTP Blocksize Option | Implemented, and bounded | 8 to 65464 is the standard's range and `max_block_size` is the relay's, defaulting to 1468 -- a data packet inside an Ethernet frame. A larger block fragments at the IP layer, which is a lever rather than a feature. A request past the bound is **rewritten to it** and forwarded, because a device whose TFTP client nobody can reconfigure is the normal case |
| 2349 | TFTP Timeout Interval and Transfer Size Options | Implemented, and one of them is a bound | `timeout` is carried and read only far enough to refuse a value that is not a number. `tsize` is the useful one: on a **write** the client declares in advance how much it is about to send, which is the one chance to refuse an oversize transfer before an octet of it arrives rather than in the middle. On a read the *server* fills it in, and a declared size past `max_transfer_bytes` ends the transfer before the first block |
| 7440 | TFTP Windowsize Option | Implemented, and it is the amplification factor | A window of sixty-four is sixty-four data packets per acknowledgement, from a request twenty octets long, to whatever address the datagram claimed to come from. `max_window_size` defaults to 4, and a larger request is rewritten to it rather than refused |
| 906 | Bootstrap Loading using TFTP | Historical | The reason this protocol is still in every estate. Nothing here implements BOOTP or DHCP; the relay sits in front of the file server the boot ROM was pointed at |
| 1782 / 1783 / 1784 / 1785 | The original option extension drafts | Obsoleted | Superseded by 2347 to 2349. The option names are the same, which is why the names are compared case-insensitively |

Three things this relay decides that no standard mentions, said plainly
because there is nothing in the protocol to fall back on. A **filename is read
as a path and refused by class** rather than matched as a string, because TFTP
has no identity and the path is the only thing a policy has. A **write is a
separate decision from a read**, and the default is to refuse it. And what
this relay will not do is add security the protocol does not have: there is no
TLS on a `tftp` listener and no option that could carry one, so a
configuration that tried to give it a certificate is refused at load rather
than quietly accepted.

## Addressing

DHCP is two documents and a pile of option assignments. What the table says is
which parts a *relay agent* implements, and what it does about the fact that
nothing in the protocol authenticates anybody.

| RFC | Title | Status | Notes |
|-----|-------|--------|-------|
| 2131 | Dynamic Host Configuration Protocol | Implemented, as a relay agent | The BOOTP header of §2 and the message types of §3. §4.1.1's relay agent behaviour: `giaddr` filled in when it is empty, `hops` incremented and bounded, a reply sent to the address the request came from or broadcast when the client has none. An `hlen` past the sixteen-octet field is refused -- one reader takes sixteen and another reads past them, and the hardware address is what a lease is keyed on -- and the address is read as `hlen` octets rather than assumed to be six, because Infiniband's are twenty and the padding after a short one is whatever the client left there. `xid` plus the hardware address is what pairs a reply with its request, and the pairing survives the OFFER so that the ACK of the same transaction can be paired too |
| 2132 | DHCP Options and BOOTP Vendor Extensions | Implemented, and the reason for the kind | Every option is read, carried and refusable by name or number. Four are named in the policy because they carry a *configuration*: option 3 (router), 6 (DNS), 66 and 67 (boot server and file). §9.3's **option overload** is read: when option 52 says so, the `sname` and `file` fields carry options, and a reader that missed them would decide about a message the server reads differently. §9.14's client identifier is compared with the header's hardware address only in its Ethernet form, because the RFC allows any opaque value |
| 3046 | DHCP Relay Agent Information Option | Implemented, including the part that is a refusal | Option 82 with its circuit-id and remote-id suboptions. §2.1's rule that a relay **discards** the option arriving from a client is enforced: a client has no business asserting which circuit it is on, because that assertion is exactly what the option exists to make on its behalf. §2.2's rule that the relay removes what it added before forwarding the reply is enforced too -- the option is a note between the relay and the server |
| 3396 | Encoding Long Options in DHCP | Implemented in both directions | Several instances of one option are **one option** whose value is their concatenation. A reader that took the first instance and a server that joins them disagree about the value, so this joins them; the encoder splits a long option the same way, because a relay that could read the encoding and not write it could not carry what it had just allowed |
| 3442 | The Classless Static Route Option | Implemented, and decoded rather than only refused | Option 121, and Microsoft's option 249 which carries the same thing because Windows shipped before the number was assigned. Both are a routing table in a broadcast reply -- the most direct interception the protocol offers -- and both are on the default deny list. An estate that uses them names its own destinations in `allow_routes`, compared by *containment*, so `10.0.0.0/8` does not admit a default route. The refusal names the route, because an operator who sees an injection stopped is owed the route |
| 4039 | Rapid Commit | Carried | Option 80 is a zero-length option whose presence is the whole message, which is why the encoder is careful to write a valueless option rather than drop it |
| 4388 | DHCP Leasequery | Recognised, and not in the default type list | The lease-query family is a relay agent's own diagnostic and an inventory of every lease in the estate to anything else, so it is nameable in `message_types` and absent from the default |
| 4578 | DHCP Options for PXE | Read as policy input | Options 93, 94 and 97 say what kind of machine is booting. They are carried; what they are useful for here is that a rule can be written about the machines that send them |
| 4702 | The Client FQDN Option | Carried | Option 81 is a name a client asks the server to register on its behalf, and is logged with the lease |
| 3203 | DHCP reconfigure extension | Recognised | DHCPFORCERENEW is a message *to* a client that answers nothing, which is why it is worth being able to name in a policy |
| 951 / 1542 | BOOTP and its clarifications | Partial, by inheritance | The header is BOOTP's and the 300-octet minimum message is padded to, because there are relay agents and clients that drop anything shorter. A message with no option 53 is BOOTP rather than DHCP and is refused: this relay does not speak for BOOTP, and saying so is better than deciding about a message with no type |
| 8415 | DHCP for IPv6 | **Not implemented** | A different packet format, different message types, a different relay mechanism and its own options. Reading it as if it were DHCPv4 would be worse than not reading it, and a security tool that claimed one implementation covered both would be making a claim it could not keep. A segment running both needs its v6 relaying done elsewhere |
| 7513 / 7610 | SAVI for DHCP, DHCP shield | Related, not this | Both describe the switch-level countermeasure this kind implements at the relay: refusing a reply that did not come from a server. Where a switch can do it by port, it should; this is the same policy by address, plus the part a switch cannot do -- reading what the reply *says* |

Three things this relay decides that no standard mentions, said plainly because
the protocol leaves no other place to put them. A reply is checked against the
estate's **own** gateways, resolvers and boot servers, which is a check a
compromised real server fails as surely as a rogue one. A lease past the
configured bound is **shortened** rather than refused, because a client that gets
a shorter lease boots and one that gets no answer does not. And the starvation
bound is keyed on the **hardware address** from inside the message rather than on
the peer address, because the peer address of a booting client is `0.0.0.0` and a
limit keyed on it would see one sender doing nothing unusual.

## Time

Time is the one protocol whose whole job is to change something every
other protocol depends on, so the table says exactly which parts of it
this proxy reads, which it refuses, and which it deliberately does not
implement.

| RFC | Title | Status | Notes |
|-----|-------|--------|-------|
| 5905 | Network Time Protocol Version 4 | Partial | The packet, the modes and the timestamp arithmetic, as a gateway rather than as a clock: versions 1 to 4 parsed onto one header, era-safe modular subtraction for the offset and delay, stratum 0 (kiss-o'-death) and stratum 16 read as the statements they are, and the reference identifier read by stratum rather than assumed to be an IPv4 address. The clock discipline of section 10 and the mitigation algorithms of section 11 are the local time daemon's job, not a relay's |
| 4330 | Simple NTP (SNTPv4) | Full | SNTP is NTPv4's packet with a simpler client, so the same parser reads it; a device profile names the version and mode it uses |
| 7822 | NTP Extension Field Format | Full | The field format, the minimum length, and the ambiguity between a trailing extension field and a MAC -- which this reads as a MAC (as every implementation does) and reports rather than resolving silently, because the server behind it may read it the other way |
| 8573 | AES-CMAC for the NTP Authentication Extension | Full | The algorithm for symmetric keys, implemented from RFC 4493 and tested against its vectors, subkeys included. MD5 and SHA-1 are verifiable only behind an explicit exception that warns |
| 8915 | Network Time Security for NTPv4 | Partial | The visible fields (unique identifier, cookie, cookie placeholder, authenticator) are read, protected packets are passed through whole, a downgrade to plain NTP is refused, and key establishment is relayed on TCP 4460 with the ALPN `ntske/1` checked from the ClientHello. Termination -- key derivation from the TLS exporter, cookie keys shared with the servers, rotation with overlap -- is deliberately absent rather than approximated: an implementation that faked it would tell clients their time was authenticated when nobody had checked |
| 9109 | NTP Client Data Minimization | Full | A client that changes its source port and zeroes the fields it need not send is an ordinary client here: an association is an address and a port, and nothing requires port 123 on the client side |
| 9748 | NTP Extension Field Types registry | Partial | The registry is the reference for what a field type means. This build recognises the NTS types and the checksum complement of RFC 7821; anything else is counted as unknown and refused by default, because a relay cannot decide about an instruction it cannot read |
| 7821 | UDP Checksum Complement in NTP | Partial | The field type is recognised and forwarded; the complement itself is not computed, because this relay does not rewrite timestamps |
| 5906 | Autokey | Refused | Withdrawn by its own community and never implemented here. Its extension fields are refused with every other field type this relay does not know, rather than tunnelled |
| 9769 | NTP over PTP | Not applicable | This is a gateway for the NTP packet on UDP; carrying it over the PTP transport is a different transport binding, and nothing here would be more honest for pretending otherwise |
| 1119 / 1305 | NTPv2 and NTPv3 | Partial | The header is the same one, so a version 3 packet is read and forwarded where a listener's profile names version 3. Version 1 and 2 need naming too, because a version 1 packet has no mode field and reading its zero bits as a client request is a decision rather than a reading |

NTPv5 is a draft whose packet format is not version 4's. The dispatch
refuses it by name, and `allow_version5` forwards it as opaque bytes on a
transaction socket of its own rather than parsing fields whose meaning is
not settled.

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

## Remote desktop and terminal access

The three protocols a gateway terminates so that a session can be held
to a policy and recorded. Telnet's options are commands escaped into the
data, RFB settles everything worth deciding in its handshake, and RDP
settles it in the connection sequence: a relay that did not parse them
could decide none of it.

| RFC | Title | Status | Notes |
|-----|-------|--------|-------|
| 854 | Telnet Protocol Specification | Full | The NVT in both directions: `IAC` framing, `IAC IAC` as a literal 255, and a bound on one subnegotiation, so a peer that opens `IAC SB` and never closes it is cut off rather than allowed to grow a buffer |
| 855 | Telnet Option Specifications | Full | The negotiation itself. An option this proxy has no name for is refused whatever the configuration's lists say -- one whose effect it cannot name is one it cannot hold to a policy -- and every refusal is answered to the side that asked (`WILL` and `WONT` declined with `DONT`, `DO` and `DONT` with `WONT`) rather than dropped, because a refusal the asker never hears is a negotiation that repeats for ever |
| 856 | Telnet Binary Transmission | Full | In the default option set |
| 857 | Telnet Echo Option | Full | In the default option set |
| 858 | Telnet Suppress Go Ahead Option | Full | In the default option set |
| 859 | Telnet Status Option | Full | In the default option set |
| 860 | Telnet Timing Mark Option | Full | In the default option set |
| 885 | Telnet End of Record Option | Full | In the default option set |
| 1073 | Telnet Window Size Option | Full | In the default option set; the subnegotiation is read, so a recording holds the size the terminal actually had |
| 1079 | Telnet Terminal Speed Option | Full | In the default option set |
| 1091 | Telnet Terminal-Type Option | Full | In the default option set |
| 1096 | Telnet X Display Location Option | Partial | Negotiable only where a configuration names it: it tells the target an X display to reach, which is a connection back out of the estate |
| 1184 | Telnet Linemode Option | Partial | Negotiable only where a configuration names it; the default is character-at-a-time, which is what a recording wants |
| 1372 | Telnet Remote Flow Control Option | Partial | Negotiable only where a configuration names it |
| 1408 / 1572 | Telnet Environment Option, Telnet Environment Option (new) | Partial | Negotiable only where a configuration names it, and validation warns when it is: they carry variables of the client's choosing to the target, which is how a login shell is given a different `PATH` |
| 2941 | Telnet Authentication Option | Refused | Every implementation that has it negotiates it differently, so the gateway would be relaying a mechanism it does not understand between two ends that each believe it was checked |
| 2946 | Telnet Encryption Option | Refused | It would encrypt the session end to end, which is a session this gateway can no longer record, hold to a policy or ask a second factor for. Wrapping the listener in TLS is the supported way to stop a reader, and validation warns whenever it is left off |
| 6143 | The Remote Framebuffer Protocol | Partial | Versions 3.3, 3.7 and 3.8, on each leg independently and with the handshake terminated on both, so a 3.3 viewer can reach a 3.8 desktop through here; below 3.3 is refused and a version nobody defines (Apple's 3.889) is read as the highest defined version at or below it. `none` and the DES challenge of section 7.2.2 are mediated, as is VeNCrypt with its X.509 subtypes; the bare `plain` subtype is refused because it would send the credential in clear. The framebuffer messages themselves are relayed rather than decoded, with the declared picture bounded against the bytes that carry it -- nothing is decompressed to check, which is what keeps an image protocol from being the cheapest place to aim a decompression bomb |

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
| Kerberos KDC Proxy Protocol (MS-KKDCP) | Microsoft | The `kkdcp` listener kind: the KDC-PROXY-MESSAGE envelope, its length-prefixed inner message and its optional realm and flags, over HTTPS and one path. The `dclocator-hint` field is carried to the KDC and never acted on by the proxy, because a domain controller hint from a client is a client's opinion about where its credentials should go |
| MQTT 3.1.1 and 5.0 | OASIS (3.1.1 also ISO/IEC 20922) | |
| Modbus Application Protocol v1.1b3 | Modbus Organization | The `modbus` listener kind |
| Modbus over Serial Line v1.02 | Modbus Organization | RTU and ASCII framing, tunnelled over TCP the way every Modbus gateway does it |
| Modbus/TCP Security v21 | Modbus Organization | TLS with mutual authentication and the role extension under the Modbus arc; see the industrial control section for what is and is not taken from it |
| SFTP version 3 | `draft-ietf-secsh-filexfer-02` | |
| RDP (MS-RDPBCGR) | Microsoft | The connection sequence, the channel list, the device announcement and the credential packet are terminated on both legs; the session's own graphics, input and capability traffic is relayed unread, so the version of RDP does not matter. A channel that was not both announced and granted cannot be used, which is where file transfer and port redirection are switched off |
| CredSSP over NTLMv2 (MS-CSSP, MS-NLMP) | Microsoft | Towards the desktop only, with the gateway's own credential: network level authentication proves a credential before the connection sequence starts, so a client asking for it is answered with TLS -- the downgrade every remote desktop gateway performs, and the only way a gateway can check anything about a credential at all |
| RFB vendor security types | TightVNC, Apple, UltraVNC, RealVNC | Types 16, 30, 113, 129, 130 and 133 are reimplemented from the shapes their own sources and the public reimplementations agree on, each warned about at load, and interoperability against the real servers is not verified by this project's tests. They exist because the desktops exist: reaching one through a gateway that records the session, asks for a factor and holds the policy is better than reaching it directly. What each is worth cryptographically is stated in CONFIG.md rather than implied by its name |
| Encrypted Client Hello | `draft-ietf-tls-esni` | Version `0xfe0d` |
| X25519MLKEM768 | `draft-kwiatkowski-tls-ecdhe-mlkem`, FIPS 203 | |
| pcapng | `draft-ietf-opsawg-pcapng` | The capture file format |
| DNS Response Policy Zones | `draft-vixie-dns-rpz` (ISC) | The QNAME trigger and the five policy actions -- NXDOMAIN, NODATA, PASSTHRU, DROP, TCP-only -- plus local data, read from zone files in the master format a feed publishes. The `rpz-client-ip`, `rpz-ip`, `rpz-nsdname` and `rpz-nsip` triggers are refused by name at load: the last two need the resolver to police a delegation path this one forwards, and where an answer's addresses are the concern `answer_policy` screens them by range. `ignore_unsupported` loads such a zone without those rules and counts them |
| WebTransport over HTTP/3 | W3C and `draft-ietf-webtrans-http3` | |
| OpenID Connect Core 1.0 | OpenID Foundation | |
| SAML 2.0 Core, Bindings and Profiles | OASIS | As a service provider: the web browser single sign-on profile with the HTTP Redirect binding for requests and HTTP POST for responses. A deliberately narrow profile -- one unencrypted assertion, exclusive canonicalization, SHA-256 and above, the signing key from the configuration -- and no single logout. [CONFIG.md](CONFIG.md) lists every refusal and the reason for it |
| XPath 1.0 | W3C | Not implemented, and named here because SecLang's `XML:` targets look like it. The engine fills two collections -- every attribute value (`XML://@*`) and every piece of character data (`XML:/*`) -- and any other selector is parsed and then matched against nothing, so a rule over one never fires. Where a named element or a document's shape is the requirement, the `xml_guard` filter reads structure instead |
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
| `permessage-deflate` | WebSocket | A compressed frame cannot be inspected; accepting the extension would disable every check silently. The offer is stripped from an inspected upgrade rather than left to the endpoints, so a client that asks for it gets an uncompressed connection rather than a broken one |
| A non-shortest MQTT remaining length | MQTT | Two spellings of one length are two readings of one packet |
| An MQTT version the proxy cannot parse | MQTT | A packet it cannot check is a packet it cannot allow |
| An SFTP version above 3 | SFTP | Packets this cannot be trusted to read; the policy would be guesswork |
| An unimplemented `:protocol` on extended CONNECT | HTTP/2, HTTP/3 | Answered `501` rather than falling through to a TCP tunnel, so a request cannot be read as one thing here and another by a peer |
| SOCKS4, SOCKS4a, SOCKS `BIND` | SOCKS | No authentication, no names, and `BIND` asks the proxy to open a listening socket on a client's say-so |
| YARA modules, `at`, `for`, unbounded jumps, `@a` | YARA | Refused at load with the line number. A rule that silently matched nothing would be worse than one that will not start |
| An upstream reply the proxy cannot parse | SMTP, MQTT | Never passed on: it is exactly the reply the client would read differently |
| A `FOLLOW` reply | TACACS+ | It hands the device another server's address, port and key, so a server that has been taken can move every later authentication somewhere this proxy does not see. Refused, in shadow mode too |
| A Change-of-Authorization or Disconnect-Request | RADIUS | An unsolicited packet that ends somebody's session, authenticated by a shared secret and nothing else. Counted and dropped |
| A body sent with the unencrypted flag | TACACS+ | The obfuscation is weak and is still the only confidentiality the protocol has; a body in the clear is a password on the wire |
| A Kerberos message a KDC proxy does not carry | KKDCP | Only the AS and TGS exchanges and their errors belong in a KDC-PROXY-MESSAGE. Anything else is refused rather than forwarded, because a proxy that carries what it cannot name is a tunnel |

## Keeping this honest

Every row above is something the code does, and most of them have a
test that names the RFC in its comment. The ones worth reading, if you
want to check rather than trust: `internal/smtp`, `internal/mqtt`,
`internal/sftp`, `internal/masque` and `internal/dns` each hold their
protocol's parser and its table of malformed inputs, and
[TESTS.md](TESTS.md) says what each of those tables proves.

If you find a row that overstates what is implemented, that is a bug in
this document and worth reporting as one.
