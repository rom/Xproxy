# Xproxy

Xproxy is a security proxy that terminates protocols rather than
forwarding bytes. It is an HTTP/1.1, HTTP/2 and HTTP/3 reverse proxy
and load balancer with a web application firewall, a ban list, rate
limiting and load shedding at its core — and, around that core, the
other protocols an estate actually runs:

- **the edge**: DNS over UDP, TCP, TLS, HTTPS and QUIC; a forward proxy
  speaking CONNECT, SOCKS5 and MASQUE with optional TLS interception;
  layer 4 TCP and QUIC passthrough and a generic datagram relay, where
  terminating would be wrong;
- **the bastion**: an SSH jump host with SFTP inspection, and telnet,
  VNC and RDP gateways that terminate the protocol, record the session
  and can ask for a second factor;
- **the relay**: SMTP and submission, MQTT, FTP with the data channel
  mediated, a syslog relay that re-emits every record, Modbus in both
  directions for equipment that cannot be patched, and an NTP and NTS
  time gateway that compares its sources rather than believing one.

Sixteen listener kinds, thirty-six configuration sections and
twenty-one request filters, one configuration format for all of them.

It is not one binary but four, split by who is on the other end of the
socket: **xproxy** faces the internet, **xgate** faces people, **xrelay**
faces services, **xot** faces the plant. They share one repository, one configuration format and
one control plane, and each links only the protocol code it serves — so
a host with no bastion has no SSH implementation on it, rather than one
sitting unconfigured. Each is a static Go binary with no cgo, runs
unprivileged as its own user under a hardened systemd unit confined by
SELinux, and is managed over a local socket from a CLI, a terminal UI
and a web GUI.

Status: 1.4 in development on top of the **1.0.0** release
([release notes](docs/RELEASE_NOTES_1.0.md), [how a release is
cut](docs/RELEASING.md)). [docs/ROADMAP.md](docs/ROADMAP.md) lists what
each version delivered and what is planned;
[docs/CHANGELOG.md](docs/CHANGELOG.md) has the details.

## Contents

- [The idea](#the-idea) — why it terminates rather than forwards
- [How it works](#how-it-works) — listeners, the pipeline, the four daemons
- [Try it in a minute](#try-it-in-a-minute)
- [Every protocol it speaks](#every-protocol-it-speaks)
- [Every listener kind](#every-listener-kind) — what each one decides about
- [Features](#features) — transport, routing, defence, identity, deception, operations
- [The configuration surface](#the-configuration-surface) — every section and every filter
- [Setup](#setup) — install, run, configure
- [Deployment shapes](#deployment-shapes) — every supported way to run it
- [Operating it](#operating-it) — the CLI, the TUI, the GUI, metrics, logs
- [Documentation](#documentation)
- [Development](#development)

## The idea

A proxy sits between two implementations of a specification and has to
be right about both. Almost every serious proxy bug is the same bug:
the proxy read a message one way and the peer behind it read the same
bytes another way. Request smuggling is that. SMTP smuggling is that.
A `Transfer-Encoding` nobody agrees on is that.

So the rule this codebase is built around is: **decide the framing
once, and never pass on what you could not read.**

- HTTP framing is decided in one parser; a message with two framings is
  refused rather than resolved.
- An SMTP message ends where this proxy says it ends, and every line is
  re-emitted, so a bare newline cannot mean two different things to two
  servers.
- An MQTT packet whose length has a non-shortest encoding is two
  packets to somebody; it is refused.
- An upstream reply the proxy cannot parse is never relayed: it is
  exactly the reply the client would read differently.
- An unimplemented extended-CONNECT protocol is answered `501`, not
  quietly turned into a TCP tunnel.
- A Modbus RTU frame has no delimiters, so its length is computed from
  the function code and proved by the checksum; a frame that cannot be
  measured is refused rather than guessed at, because the device behind
  it will read those bytes somehow.
- An NTP packet is forty-eight octets of header and then extension
  fields, a MAC, both or neither — and RFC 7822 cannot always tell the
  last field from a MAC. The relay reads it the way every
  implementation does *and says the reading was a choice*, which a
  policy can then refuse, because that ambiguity is two peers
  disagreeing about what was said.

The same rule is why terminating is the default. A jump host that
forwards an SSH stream cannot tell a shell from a port forward, so the
only policy it can hold is "may connect". A layer 4 listener in front
of a broker cannot see a topic, so it cannot say that a device may
publish its own telemetry and nothing else. Reading the protocol is
what makes a policy possible.

[docs/RFC.md](docs/RFC.md) is the full account: every standard
implemented, every named subset, and every feature deliberately refused
with the reason.

## How it works

Every configuration is a set of listeners, upstream pools and routes.
A `kind: http` listener terminates TLS (or not), runs each request
through a fixed admission pipeline and hands it to a route's action; the
other listener kinds reuse the same accept limits, bans, logs and
management plane for other protocols.

A listener's `kind` also says which daemon serves it. Every daemon
validates the whole configuration — so one set of includes describes the
estate — and binds only the kinds of its own role:

| Daemon | Faces | Listener kinds |
|--------|-------|----------------|
| `xproxy` | the open internet | `http`, `forward`, `tcp`, `udp`, `dns` |
| `xgate` | people | `ssh`, `telnet`, `vnc`, `rdp` |
| `xrelay` | services | `smtp`, `ftp`, `ldap`, `postgres`, `mysql`, `tds`, `redis`, `amqp` |
| `xot` | the plant | `modbus`, `iec104`, `s7`, `mms`, `bacnet`, `opcua`, `coap` |
| `xrelay` **and** `xot` | what a plant and a data centre both run | `mqtt`, `syslog`, `snmp`, `tftp`, `dhcp`, `dhcp6`, `ntp`, `ntske` — linked into both, and the listener says which one binds it with `daemon: xot` (the default is `xrelay`) |
| Devices | CoAP (RFC 7252) over UDP, with block-wise transfer (RFC 7959), Observe (RFC 7641), resource discovery (RFC 6690), the RFC 8132 methods and the option classes that tell a proxy what to do with an option it cannot name; read as a relay: the method, the path, the content format, the declared transfer size, and the size of an answer relative to the question; and all three of RFC 7252 §9's security modes, so a **pre-shared key identity** or a **pinned public key** is what the policy names rather than an address | `coap` |
| Substations | IEC 61850 MMS over the ISO stack on TCP 102 — TPKT, COTP, session, presentation, ACSE, MMS — with the ACSE identity and the data model's own object names: the logical device, the logical node and the **functional constraint** that says whether a Write moves a breaker, changes a protection setting or silences a report | `mms` |
| Plants | OPC UA (IEC 62541) over `opc.tcp`, with the chunked UA TCP transport, the secure channel and its policies and modes, the session and its identity tokens, and the service layer where the mode leaves a body readable: Read, Write, Call, Browse and the subscription set, by node identifier, attribute and method | `opcua` |

A kind a binary did not link is never bound and never falls through to
the HTTP data plane: it is an error naming the daemon that serves it.

```
client ──▶ listener (accept limits, bans) ──▶ admission pipeline ──▶ route action ──▶ upstream pool
       http | tcp | udp | forward | dns         concurrency, host and       proxy, redirect,      balancer, health,
        smtp | mqtt | ftp | syslog | modbus     path checks, route match,   respond, honeypot,    ejection, retries,
        ntp | ntske | ssh | telnet | vnc | rdp  country, ACL, challenge,    static files          affinity, mirror
                                                shedding, rate limits,
                                                body limit, filters
                                                (auth, MFA, WAF, YARA,
                                                ICAP, yours), cache
```

Configuration is one YAML file (optionally with included fragments),
validated in full before it is applied, and reloaded without dropping a
connection: each reload builds a new immutable generation and swaps it
in atomically. Every deny, ban, challenge and upstream error is a
structured event in one of four log streams, and every request carries
an identifier from the access log to the upstream.

## Try it in a minute

```sh
make build
cat > x.yaml <<'EOF2'
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:8080"}]
management: {socket: /tmp/xproxy.sock, socket_mode: "0600"}
logging: {directory: /tmp/xproxy-logs}
upstreams:
  - name: app
    endpoints: [{address: 127.0.0.1:3000}]
routes:
  - name: all
    upstream: app
EOF2
mkdir -p /tmp/xproxy-logs
./bin/xproxy -config x.yaml &
curl -i http://127.0.0.1:8080/
./bin/xproxyctl -socket /tmp/xproxy.sock status
```

That is the shape of every configuration in this repository: one file,
validated in full before anything binds. The rest of this document is
what else it can be told to do, and [Setup](#setup) is how it is
installed, run and kept.

## Every protocol it speaks

Grouped by family, with the listener kind or filter that speaks it.
[docs/RFC.md](docs/RFC.md) is the authority: it names every standard
with a verdict — full, a named subset, or refused — and has a section of
its own for what is deliberately *not* implemented and why.

| Family | What is spoken here | Where |
|--------|---------------------|-------|
| HTTP | HTTP/1.1, HTTP/2 (ALPN or `h2c`), HTTP/3 over QUIC v1; extended CONNECT; WebSocket (RFC 6455), with `permessage-deflate` deliberately not negotiated on an inspected route; WebTransport over HTTP/3; gRPC and gRPC-web; Early Hints, trailers, ranges and priority signals | `http` |
| TLS | 1.2 and 1.3, SNI, ALPN, mutual TLS in both directions, SPKI pinning, session tickets with rotating keys, OCSP stapling, Certificate Transparency, ACME (HTTP-01 and TLS-ALPN-01), Encrypted Client Hello, the `X25519MLKEM768` hybrid key exchange, JA3 and JA4 fingerprints | every TLS listener |
| Layer 4 | TLS and QUIC passthrough routed by server name; any datagram protocol; PROXY protocol v1 and v2, read and written; `IP_TRANSPARENT` with the original destination read from the socket | `tcp`, `udp` |
| DNS | UDP, TCP, DoT (RFC 7858), DoH (RFC 8484) and DoQ (RFC 9250); DNSSEC validation with aggressive NSEC and NSEC3 caching (RFC 8198); response policy zones; DNS64 (RFC 6147); designated-resolver discovery (RFC 9462); SVCB and HTTPS records (RFC 9460); DNS cookies; EDNS client subnet policy | `dns` |
| Forward and tunnelling | HTTP CONNECT, SOCKS5 (RFC 1928, 1929, 1961) with UDP associations, CONNECT-UDP (RFC 9298), CONNECT-IP (RFC 9484), and TLS interception inside a tunnel | `forward` |
| Mail | SMTP (RFC 5321) and submission (RFC 6409), STARTTLS (RFC 3207), implicit TLS (RFC 8314), `SIZE`, `AUTH`, enhanced status codes, and Postfix's `XCLIENT` so the mail server still sees the real client | `smtp` |
| Messaging | MQTT 3.1.1 (also ISO/IEC 20922) and MQTT 5.0 | `mqtt` |
| File transfer | FTP and FTPS (`AUTH TLS`) with the data connection mediated at both ends; SFTP version 3 inside the SSH subsystem channel | `ftp`, `ssh` |
| Logging | Syslog RFC 5424 and RFC 3164 over UDP, TCP (RFC 6587 framing) and TLS, re-emitted in one dialect | `syslog` |
| Time | NTP v1 to v4 (RFC 5905), SNTP (RFC 4330), extension fields (RFC 7822), AES-CMAC authentication (RFC 8573), NTS (RFC 8915) either passed through whole or **terminated and re-originated** -- key establishment answered here with AES-SIV cookies (RFC 5297), every time packet's authenticator verified, and an association of the relay's own toward a source that speaks it -- on UDP 123 and TCP 4460 | `ntp`, `ntske` |
| Industrial | Modbus/TCP (MBAP), Modbus over Serial Line RTU and ASCII tunnelled over TCP, and Modbus/TCP Security with the role in the client certificate | `modbus` |
| Telecontrol | IEC 60870-5-104 (APCI/APDU, the I, S and U formats, the type identifications and causes of transmission of IEC 60870-5-101), with IEC 62351-3 TLS | `iec104` |
| Building automation | BACnet/IP (ASHRAE 135 Annex J): the BVLC functions, the network layer of clause 6 with its routing and security messages, the application layer of clause 20 with the confirmed and unconfirmed services, and the object, property and command priority each request names | `bacnet` |
| Industrial control | Siemens S7comm on TCP 102: TPKT (RFC 1006), COTP (X.224 class 0, whose connection request addresses a CPU by rack and slot), and the S7 layer -- the function codes for memory, blocks and the control service, and the user-data groups for the diagnostic buffer, the clock, the password and the debugger. **S7comm-plus** (protocol identifier `0x72`), which is what TIA Portal speaks to an S7-1200 or S7-1500, read as far as its function code -- which is as far as anything in the path can read it | `s7` |
| Messaging | AMQP 0-9-1 (the class and method catalogue RabbitMQ speaks) and AMQP 1.0 (ISO/IEC 19464: the nine performatives, its self-describing type system, and the SASL layer), read on one port because a client picks which of the two it speaks in its first eight octets | `amqp` |
| Management | SNMP v1 (RFC 1157), v2c (RFC 1901–1908) and v3 with USM (RFC 3410–3418, RFC 3826, RFC 7860) read and verified, over UDP and over TCP (RFC 3430); RFC 6353 on both transports — TLS on TCP 10161, DTLS on UDP 10161 — with RFC 5591's transport security model and RFC 6353 §5.3 certificate-to-name mapping | `snmp` |
| Directory | LDAP v3 (RFC 4511–4515, 4517, 4519) with LDAPS and the StartTLS of RFC 4513, as a relay: the bind methods, the search filter's shape, distinguished names compared per relative name, the attribute lists in both directions | `ldap`, filters |
| Addressing | DHCP (RFC 2131) with its options (RFC 2132), relay agent information (RFC 3046), long options (RFC 3396) and classless static routes (RFC 3442), as a relay agent that reads what it relays: the server a reply came from, and the configuration the reply carries | `dhcp` |
| Addressing | DHCPv6 (RFC 8415) as a relay agent that reads what it relays, with the nested relay chain, the DUID identity, the identity associations and prefix delegation, and the options that configure something other than an address: the boot file URL (RFC 5970), the captive portal (RFC 8910), the SZTP bootstrap server (RFC 8572), the S46 transition containers (RFC 7598) and the AFTR name (RFC 6334) | `dhcp6` |
| Provisioning | TFTP (RFC 1350) with the option extension (RFC 2347), block size (RFC 2348), timeout and transfer size (RFC 2349) and windowed transfer (RFC 7440), as a relay: the filename read as a path, the direction of the transfer, and the bounds on what comes back | `tftp` |
| Databases | PostgreSQL frontend/backend protocol version 3, with the SSL and GSSAPI encryption requests, the cancel request, the simple and extended query protocols, and the authentication methods of pg_hba.conf; the MySQL and MariaDB client/server protocol with handshake v10, the capability negotiation, the command set and the authentication plugins; TDS 7.x (MS-TDS) with the PRELOGIN option table, the LOGIN7 identity, the SQLBATCH and RPC message types, and the TLS handshake carried inside TDS packets; the Redis serialization protocol (RESP2 and RESP3) in both the multibulk and inline forms, with the command table's key positions | `postgres`, `mysql`, `tds`, `redis` |
| Remote access | SSH (RFC 4251–4254) with OpenSSH user and host certificates; telnet's NVT (RFC 854); RFB 3.3 to 3.8 (RFC 6143) with VeNCrypt; RDP (MS-RDPBCGR) over TLS, CredSSP over NTLMv2 towards the desktop, or the protocol's own encryption | `ssh`, `telnet`, `vnc`, `rdp` |
| Identity | OpenID Connect Core 1.0, OAuth 2.0 (RFC 6749) with introspection (RFC 7662), PKCE (RFC 7636) and token exchange (RFC 8693); JWT, JWS and JWKS (RFC 7515–7519); DPoP (RFC 9449); certificate-bound tokens (RFC 8705); SAML 2.0 as a service provider; SCIM 2.0 (RFC 7642–7644); WebAuthn level 2; LDAP (RFC 4511–4515); TOTP (RFC 6238); HTTP Basic (RFC 7617); client certificate identity as `Client-Cert` (RFC 9440) or Envoy's `X-Forwarded-Client-Cert` | filters |
| Inspection | ModSecurity SecLang with the OWASP Core Rule Set through Coraza; a documented subset of YARA; ICAP (RFC 3507); OpenAPI 3 descriptions; GraphQL; XML and XSD with exclusive canonicalization; protobuf structure without a schema; WebAssembly with WASI preview 1 | filters |
| Operations | Prometheus exposition; OpenTelemetry OTLP for traces, metrics and logs; SIEM export as NDJSON, Splunk HEC, CEF or LEEF; pcapng capture files; asciicast v2 session recordings; journald and syslog log sinks; the Consul catalogue; Kubernetes Ingress and Gateway API | the control plane |

Each protocol has a page of its own -- what it looks like on the wire, what
security it was designed with, what this proxy decided to read and what it
deliberately does not do -- indexed at
[docs/protocols/README.md](docs/protocols/README.md).

## Every listener kind

`kind: http` is the pipeline above. The others reuse its accept limits,
bans, logs, upstream pools and management plane, and each reads its own
protocol so that a policy can be written in that protocol's own terms:

| Kind | Daemon | Protocol | What it decides about |
|------|--------|----------|-----------------------|
| `http` | `xproxy` | HTTP/1.1, HTTP/2, HTTP/3 | Hosts, paths, methods, headers, bodies: routes, filters, the WAF, the cache |
| `tcp` | `xproxy` | TLS and QUIC passthrough | The server name, without terminating; YARA over the bytes |
| `udp` | `xproxy` | Any datagram protocol | Who may send, how large, how often, how long a session lives |
| `forward` | `xproxy` | CONNECT, SOCKS5, MASQUE, TLS interception | Destinations, credentials, and the plaintext inside a tunnel when asked |
| `dns` | `xproxy` | DNS over UDP, TCP, TLS, HTTPS, QUIC | Names, answers, response policy zones, tunnelling; and, with `deception`, answering a refused name as a fabricated resolver so the rest of what was leaving is collected rather than sent somewhere else |
| `ssh` | `xgate` | SSH and SFTP | Channels, commands, forwards, paths, file operations; recording, MFA; and, with `deception`, a bastion that is not there, so the account names an estate looks like it has from outside, and the passwords tried against them, are collected rather than deflected |
| `telnet` | `xgate` | Telnet (RFC 854 NVT) | Options in both directions; recording, MFA; and, with `deception`, a login and a shell that are not there, so the dictionary being walked and the payload it was for are collected rather than deflected |
| `vnc` | `xgate` | RFB 3.3–3.8, VeNCrypt, vendor security types | Security type, whose credential opens the desktop, view-only, the picture's bounds; recording, MFA |
| `rdp` | `xgate` | RDP over TLS, NLA, or the protocol's own encryption | Channels, devices, the connection sequence; recording, MFA |
| `smtp` | `xrelay` | SMTP and submission | Commands, where a message ends, TLS and authentication, bounds |
| `mqtt` | `xrelay`, `xot` | MQTT 3.1.1 and 5.0 | Topics and filters, client identifiers, retained messages, wills |
| `coap` | `xot` | CoAP (RFC 7252) over UDP, block-wise transfer, Observe, resource discovery | The methods, the **paths** -- which are the device's object model, so the policy is positive and the default is deny -- the queries, the content formats in both directions, `Proxy-Uri` and `Proxy-Scheme` refused by default, an option the relay cannot name answered the way the standard says, a path whose segments would not mean what the joined path looks like, the payload, one block, the whole declared transfer, the outstanding Observe registrations, the size of an answer as a **multiple of the question**, and the **security name** the DTLS session proved — a pre-shared key identity (RFC 7252 §9.1.3.1) or a pinned public key (§9.1.3.2), which on a shared segment is the only thing telling one sensor from another |
| `mms` | `xot` | IEC 61850 MMS on TCP 102: TPKT, COTP, ISO session and presentation, ACSE and the MMS service layer, with a learning mode that proposes the object rules | The client networks; the ACSE **AP-title** and AE-qualifier, which is the only identity this protocol has and is not a credential; whether the ACSE authentication value is a **cleartext password** (counted and reported by default, refused on request); the service and its class; the logical device; the object; and the **functional constraint** — `$CO$` operates a breaker, `$SG$` and `$SE$` change a protection relay's trip characteristic, `$BR$` and `$RP$` decide whether the control centre hears about either; then whether an operate was **selected** first, which is the one check here a relay can make that the device may not |
| `opcua` | `xot` | OPC UA (IEC 62541) over `opc.tcp`, chunked UA TCP, the secure channel, sessions and identity tokens, with a learning mode that proposes the node rules | The security policies -- with the two IEC 62541 withdrew refused unless named twice -- the message security mode, the endpoint, the client application's URI checked against its own certificate, the identity token kind, the user, and a password that crossed unprotected; then, where the mode left a body readable, the service, the node identifiers, the **attribute** (a write to `value` moves an actuator; a write to `access_level` changes who may), the method on its object, the operations in one request, and the publishing interval a subscription asked for |
| `ftp` | `xrelay` | FTP and FTPS | Commands, paths, extensions, and the data connection itself |
| `syslog` | `xrelay`, `xot` | RFC 5424 and RFC 3164 over UDP, TCP, TLS | Facility, severity, sender, the text; re-emitted in one dialect |
| `modbus` | `xot` | Modbus/TCP, RTU and ASCII, Modbus/TCP Security | Unit identifiers, function codes, diagnostic sub-functions, Schneider UMAS commands, register ranges, values, roles, schedules, behavioural detection |
| `iec104` | `xot` | IEC 60870-5-104 (with the redundancy groups of edition 2), IEC 62351-3 TLS, IEC 60870-5-7 secure authentication recognised | Type identifications, causes of transmission, common and originator addresses, information object ranges, select-before-operate that survives a failover, which connection of a redundancy group may carry data, setpoint value and step bounds, schedules; the information element too -- the quality descriptor a station attached to a reading, the value it reported, and the timestamp on a time-tagged command, which is this protocol's own replay check |
| `snmp` | `xrelay`, `xot` | SNMP v1, v2c and v3 (USM and TSM), UDP and TCP, RFC 6353 TLS and DTLS | Versions, community strings and USM users, security levels, operations, object subtrees, the amplification bounds; with the user's pass phrases, v3 digests verified and payloads decrypted so the rules apply to v3 too; USM **terminated and re-originated**, so a v1 poller reaches a v3-only agent; and, under RFC 6353, the **certificate** as the identity — mapped to a security name a rule names, with the transport itself a rule field |
| `ldap` | `xrelay` | LDAP v3, LDAPS, StartTLS | Bind methods, the bound identity, operations, naming contexts and subtrees, scopes, attributes in both directions, filter and entry bounds |
| `dhcp` | `xrelay`, `xot` | DHCPv4 with RFC 2132 options, RFC 3046 relay agent information, RFC 3442 routes | The server a reply came from, the options and addresses a reply may carry, the boot file, the lease bounds, the hardware-address rate |
| `dhcp6` | `xrelay`, `xot` | DHCPv6 (RFC 8415) with the nested relay chain, the DUID, the identity associations, prefix delegation | The server a reply came from, the options a reply may carry and the resolvers, domains and boot URLs they may name, what may be delegated and what a client may ask for, the lease bounds -- with a withdrawal never turned into a lease -- the relay chain's depth, and the starvation bound keyed on the **DUID** |
| `postgres` | `xrelay` | PostgreSQL protocol v3, both query protocols, the cleartext TLS negotiation | Whether the connection may be unencrypted at all, which role and database may be claimed, which authentication methods may cross, which *shapes* of statement are allowed, replication, the fast-path call, cancel requests; and, with `deception`, answering a refused statement as a fabricated database so the reconnaissance behind a documented shell command is collected rather than deflected |
| `mysql` | `xrelay` | MySQL and MariaDB protocol, handshake v10, the capability flags, the command set | The capability bits a client may even see offered, which of the protocol's commands may cross, whether the connection may be unencrypted, which user and database may be claimed (re-checked on COM_CHANGE_USER), which authentication plugins, which statement shapes, LOAD DATA in either form; and, with `deception`, answering a refused statement as a fabricated database so the reconnaissance is collected rather than deflected |
| `tds` | `xrelay` | TDS 7.x for SQL Server: the PRELOGIN negotiation, LOGIN7, SQLBATCH and RPC, and the TLS handshake carried inside TDS packets | Whether the connection may be unencrypted at all -- and the relay answers the negotiation itself rather than forwarding the server's octet -- whether a password may cross in the clear, which login, database and application name may be claimed, whether a login carrying no user name is admitted, which message types, which stored procedures, and which statement shapes, applied to a batch and to the SQL inside an sp_executesql alike |
| `redis` | `xrelay` | RESP2 and RESP3, multibulk and inline, with a table of where each command's keys are | Whether the connection may be unencrypted, whether a command may arrive before the connection has authenticated -- with the answer taken from the server's reply -- which ACL user may be named, which commands and subcommands may cross, which keys by prefix, which numbered databases, and whether anything may write; and, with `deception`, answering a refused command as a fabricated cache so the exploit chain is collected rather than deflected |
| `amqp` | `xrelay` | AMQP 0-9-1 and AMQP 1.0: the frame layer of each, the 0-9-1 method catalogue with its arguments and field tables, the 1.0 performatives over its type system, and the SASL exchange of both | Which of the two versions may be spoken; which SASL mechanisms and which identities; which virtual host; whether the broker's own *topology* may be changed at all, which is off by default; which exchanges, queues, routing keys and link addresses a connection may name -- including the dead-letter exchange of a queue, the alternate exchange of an exchange and the reply-to inside a message, which a policy written against the obvious fields would miss; whether every message must say who published it; and the frame, channel, link and message bounds |
| `s7` | `xot` | Siemens S7comm: the TPKT framing, the COTP connection request with the rack and slot it addresses, and the S7 layer -- function codes, user-data groups and subfunctions, and the item specifications of a read or a write | Which controller a client may reach, decided from the connection request *before the PLC is dialled*, and as what -- an operator panel, an engineering station or another PLC; which of nineteen operations it may ask for, where the default is what an HMI does and an upload is off with the writes because a block read is how control logic leaves a site; `read_only` as one line no rule can override; which memory areas, data blocks and byte ranges a request may name, checked against the whole span rather than its first byte; the block types an upload or a download may name; and the item, octet, PDU-length and connection bounds, because a CPU has sixteen connection resources altogether. For **S7comm-plus** on an S7-1200 or S7-1500, where the addressing is encrypted and only the framing is visible: the function code by name or class, with a function this relay cannot name failing closed |
| `tftp` | `xrelay`, `xot` | TFTP with RFC 2347–2349 options and RFC 7440 windows | The client list, the direction, the transfer mode, the filename read as a path and refused by class, the directories, and the block, window and transfer bounds |
| `bacnet` | `xot` | BACnet/IP: the BVLC functions, the network layer, the confirmed and unconfirmed services, and where each service keeps its object | Which addresses may speak to the building at all -- the only identity the protocol has -- which services may be sent, which objects and properties they may name, and at which *command priority*, so nobody takes a piece of plant at a life safety slot the management system cannot override; whether a broadcast is carried and how many answers it may bring back; whether foreign-device registration with the estate's broadcast management is carried at all |
| `ntp` | `xrelay`, `xot` | NTP v1–v4, SNTP, NTS-protected NTP | Versions, modes, extension fields, authentication, whether the servers agree, and -- terminating NTS -- whether each packet's authenticator verifies under the keys in the cookie this estate issued |
| `ntske` | `xrelay`, `xot` | NTS key establishment (TLS on 4460), relayed or terminated | The application protocol, the server name, the handshakes in flight; terminating, the negotiated terms and the cookies it issues |

- `kind: tcp`: layer 4 TLS and QUIC passthrough routed by server name
  without terminating TLS, with PROXY protocol v2 to TCP upstreams and
  optional YARA rules over the bytes it relays
- `kind: udp`: the datagram counterpart, for services with no parser
  here. A session table keyed by client address in place of a
  connection, bounded per source as well as in total because a
  datagram's source can be forged, a connected socket towards the
  endpoint so no third party can answer for it, and bounds on the
  datagram size, the session's length and what it may cost. It binds no
  TCP port, and what it will not relay it drops rather than answering,
  since a reply to a forged source is an attack on whoever was named
- `kind: forward`: an explicit proxy for clients with CONNECT tunnels,
  a destination policy that refuses private ranges by default, and
  proxy credentials. It also speaks **SOCKS5** on the same port (one
  peeked byte separates a greeting from an HTTP request), with UDP
  associations pinned to the client that opened them, and **MASQUE**:
  CONNECT-UDP for datagram traffic and CONNECT-IP for packets through a
  tun device the operator owns, both under the same destination policy,
  credentials, log and bans as a CONNECT tunnel. With `intercept` it
  terminates the TLS inside a tunnel and relays the plaintext, so YARA
  and everything else that reads bytes can see inside HTTPS — the
  destination is verified before any certificate is forged, the signing
  key is refused if anybody but its owner can read it, and
  `bypass_hosts` names what is never decrypted at all
- `kind: dns`: a DNS proxy over UDP, TCP, TLS, HTTPS and **QUIC** with
  DNSSEC validation, aggressive NSEC caching, a cache that can serve
  stale and prefetch what is about to expire, block lists, sinkholes,
  client allow lists, per client rate limits, DNS cookies, an
  EDNS-client-subnet policy, **split-horizon views** that answer the
  same name differently by client network, **DNS64** for IPv6-only
  clients, **response policy zones** read from the zone files a feed
  publishes (the QNAME trigger and the five actions, with the
  unsupported triggers refused by name rather than silently ignored), an
  answer policy that screens upstream answers for rebinding and
  metadata ranges, and **tunnelling detection** — query entropy,
  subdomain cardinality, TXT share, NXDOMAIN rate and encoded bytes,
  measured per client per registered domain, with several required to
  agree before anything is called exfiltration. It advertises its own
  encrypted endpoints through RFC 9462 discovery so clients upgrade
  themselves, and answers the SVCB and HTTPS records for the names it
  fronts, which is the other half of Encrypted Client Hello
- `kind: smtp`: SMTP and submission with STARTTLS or implicit TLS,
  where the proxy decides where every command and every message ends and
  writes each one out again. `CHUNKING` is never relayed, a bare newline
  is refused or repaired, and anything pipelined behind `STARTTLS` ends
  the session. Requires TLS and authentication before `MAIL` where you
  say so; bounds recipients, messages, line length and refused commands
- `kind: mqtt`: MQTT 3.1.1 and 5.0 with a topic policy. A subscription
  is a filter, not a topic, so an allow list is checked by subsumption
  and a deny list by overlap — which is what stops a device asking for
  `#`. The will goes through the publish policy at CONNECT, the only
  moment there is

- `kind: coap`: a **CoAP relay whose policy is a path**, which makes it the one
  OT-adjacent kind where a positive model is a sentence somebody can actually
  write. CoAP is REST for devices too small to run TLS comfortably, and the
  request carries a method, a **path** and a content format — so it says what is
  about to happen in fields a relay can read, and under the LwM2M object
  registry the path *is* the object model: `/3303/0/5700` is a temperature and
  `/3311/0/5850` is whether a light is on. "Read anything under `/3303`, write
  only `/3311/0/5850`" is a policy about real equipment, which is why
  `default_action` is **deny** here and `allow` on the DHCP kinds. **Proxy-Uri
  and Proxy-Scheme are refused by default**, and both, because they are two
  spellings of the same request: they tell the device to fetch a URI of the
  client's choosing, which on a constrained network is an open forward proxy
  with an amplifier attached. **A refusal is answered rather than dropped** —
  a Confirmable request retransmits, so silence turns one refused request into
  five and leaves the device's log showing a timeout where a refusal happened;
  the standard supplies the codes, including for the case it uniquely hands a
  relay: an option whose *number's own low bits* say it is Critical (4.02) or
  UnSafe to forward (5.02), a rule that holds for options nobody has registered
  yet. **A path whose segments would not mean what the joined path looks like is
  refused, not normalised**, because a single segment may contain a slash and
  then a rule about `/3303` is satisfied by a request that reaches `/3311` —
  and normalising means guessing what the device would have done. And the
  **amplification bounds are never shadowed**: a four-octet GET can return a
  kilobyte, `/.well-known/core` exists to list everything on the device, and
  the number worth bounding is the answer as a *multiple of the question*, with
  the whole block-wise transfer bounded from the client's own `Size1`
  declaration rather than one datagram at a time. In NoSec — which is what most
  of the field runs — there is no identity at all, and the validator says so.
  Where there is one, it is the identity RFC 7252 §9 defines rather than an
  address: a **pre-shared key** identity, which is what a coin-cell part ships
  with and what a `security_names` rule names, or a **public key pinned by its
  fingerprint** for an estate with no certificate authority of its own — and
  the identity reaches the policy, the access log and the refusals, because on
  a shared segment it is the only thing that tells one sensor from another

- `kind: opcua`: an **OPC UA relay in front of the one industrial protocol that
  brought its own security**. Everywhere else in this list the relay *is* the
  access control, because the protocol has none; here the server already checks
  certificates and users, and the relay is the place an estate's rules are
  written once and enforced for every server behind it — including the ones
  whose own configuration nobody has reviewed since commissioning. Most of what
  is worth enforcing is in the handshake and **all of it is in the clear by
  construction**, because the Hello, the security policy, both certificates and
  the user are how the two ends agree on what to encrypt: a listener admitting
  one current policy from two named applications with no anonymous token has
  excluded most of what goes wrong without naming a single node. The two
  policies IEC 62541 **withdrew** — SHA-1 based, and the two an estate most
  often still has on for one old client — have to be named in two places before
  they are carried. **Whether the service rules apply at all is a property of
  the channel**, and this is the trade-off the reference states rather than
  hides: with mode `sign` the body is signed and *not* encrypted, so every node
  identifier and method argument is readable and none of them may be modified;
  with `sign_and_encrypt` the body is ciphertext and the node rules are silent.
  `require_readable_bodies` is how a listener chooses, validation warns when
  rules sit alongside a mode that makes them inert, and a counter says how often
  it happened. Where the body is readable: the service, the node, the
  **attribute** — which is the line between moving an actuator and changing who
  may move it, since a write to `value` is a setpoint and a write to
  `access_level` is a privilege change and both arrive as an ordinary Write —
  the method *and* the object it is on, and `min_publishing_interval`, which is
  the bound that matters most because the amplification here is arithmetic: one
  millisecond over a thousand monitored items is a server asked to send a
  thousand values a millisecond, from one legitimate session, in valid protocol.
  It **never decrypts and never rewrites a body**: a relay that terminated the
  secure channel would be a man in the middle of the one industrial protocol
  designed to notice, holding the plant's private key to do it. And it will
  write the node list for you: **learning mode** records what crosses it — one
  row per identity, class of service and node group, with string identifiers
  grouped by their prefix and numeric ones listed under their namespace — and
  writes a `rules:` list that pastes in. It reports the share of messages whose
  body it could not read before anything else, because a run over an encrypted
  channel learns nothing about nodes and would otherwise read as an idle
  listener; it proposes the services that were *called* rather than the ones the
  class covers; and it proposes none of the bounds, because a report that
  suggested the fastest publishing interval it happened to see would widen the
  one setting this listener exists to hold

- `kind: mms`: an **IEC 61850 relay in front of a substation's IEDs**, on TCP
  102 and six layers deep — TPKT, COTP, ISO session, ISO presentation, ACSE and
  MMS. What makes it different from every other relay kind here is that the
  protocol's own **names** carry the semantics. In front of Modbus the relay has
  to be told which register is a setpoint; here `XCBR1$CO$Pos$Oper` says it
  operates a circuit breaker, `PTOC1$SG$StrVal$setMag$f` says it changes a
  protection relay's trip characteristic, and `LLN0$BR$brcbST$RptEna` says it
  decides whether the control centre hears about either. So a useful policy can
  be written for an estate whose SCL files nobody has read — which is most of
  them. Within a control object the attribute distinguishes a **select** from an
  **operate**, so a client may reserve a breaker without being able to move it.
  Two things this listener does that the devices may not. It **sees the
  password**: IEC 61850-8-1's ACSE authentication value is a cleartext
  GraphicString and on most of the installed base it is the only authentication
  an IED has, so `refuse_plaintext_passwords` defaults *off* — the opposite of
  the same knob on `opcua`, and for the opposite reason — and what the listener
  does by default is count every association carrying one and raise a finding,
  because that is the honest thing a relay can do about a credential it must not
  hold. And it can **require select before operate**: IEC 61850 leaves that to
  each object's `ctlModel`, `ctlModel` lives in the writable `$CF$`, so a client
  with configuration access can turn the interlock off — a listener that tracks
  the selection itself, and records it on the IED's *positive answer* rather than
  the client's asking, has put it somewhere the configuration cannot reach. It
  takes **no `tls:` section**: TCP 102 has none, IEC 62351-4 adds TLS beneath the
  session layer, and terminating that would terminate the only end-to-end
  protection this protocol has

- `kind: ftp`: an FTP proxy that is actually in the middle. FTP puts
  every transfer on a second connection whose address one side
  announces to the other, so a proxy that forwards that reply has told
  the client to go round it; this one rewrites the address and is one
  end of both connections. Commands, paths, extensions, a bound on a
  transfer and YARA over uploads; AUTH TLS both ways. **`PORT` is
  refused by default** — it asks the proxy to connect to an address the
  client names, which is the bounce attack
- `kind: syslog`: a syslog relay that reads what it forwards. Almost
  every field in a record is written by the sender and believed by the
  collector, and a message whose text carries a newline becomes two
  records in anything that frames on newlines. Every message is parsed
  and re-emitted as RFC 5424 in one framing; facility, severity, sender
  and pattern filters, redaction, per-sender rate limits; UDP, TCP and
  TLS on one address. The two ends are configured separately, so it is
  also a **secure upgrade**: clear UDP in from something that cannot be
  taught TLS, RFC 5425 TLS out
- `kind: modbus`: a Modbus relay that reads every frame, **in both
  directions**. Modbus has no authentication, no integrity and no
  session — a frame says which device it is for, what to do and where,
  and the device does it — so the only place a policy can exist is in the
  path, written in the protocol's own terms: unit identifier, function
  code, register range, value. `reverse` fronts equipment that cannot be
  patched; `forward` is the plant's controlled egress, where the routes
  are the only destinations that exist. MBAP and the two serial framings
  every Modbus gateway tunnels over TCP, bridged in any combination.
  `read_only` that no rule can override, ordered rules over clients,
  roles, units, function codes, access classes, address ranges and
  quantities, **value bounds** a setpoint must stay inside (and coil
  bounds that say which way a coil may be driven), and **schedules** for
  the maintenance window. Policy goes **below the function code** where
  the function code is not the whole question: function 8 covers both a
  counter poll and Force Listen Only Mode, four bytes that take a device
  off the bus, and function 90 is Schneider's UMAS, carrying a variable
  read, a PLC stop and a program download under one code. Both are named
  per sub-function, or by what the sub-function *does* — and by default a
  rule that never mentioned the sub-function does not permit the ones that
  stop a device or change what it runs. Refusals are the protocol's own exceptions, so
  the master carries on and its diagnostics say something true.
  **Modbus/TCP Security** for the devices that have it: TLS with mutual
  authentication and the role in the client certificate. And **learning
  mode**, because nobody knows what a plant's Modbus traffic is — run it
  for a week and the file it writes is the rule set to start from, with a
  **process baseline per register**: the envelope of the values written
  there, the largest step between writes and the peak write rate, which
  is what a value policy is actually written from. Plus **behavioural
  detection** that needs no rules at all — a function code this master
  has never used, a write to a register it has never driven, a burst of
  writes across the address space — because control traffic is repetitive
  in a way other traffic is not, so "this has not happened before" is a
  real signal here

- `kind: iec104`: an **IEC 60870-5-104** relay for the electricity grid,
  in both directions. IEC 104 is the protocol that operates transmission
  and distribution, and it has no authentication, no integrity and no
  session either: anyone who can reach a substation gateway on port 2404
  can trip a breaker on it, and the gateways are substation equipment
  with twenty-year service lives. What the protocol *has*, and Modbus
  does not, is a structure that says what a message means — a **type
  identification**, a **cause of transmission**, an **originator address**
  and a **common address** in every frame — so the policy is written in
  those terms: which stations may be addressed, which commands may be
  sent by whom to which points, on what schedule. The commands are a
  small numbered set, and the two that matter most are named separately:
  `C_RP_NA_1` reboots a station and `C_CS_NA_1` moves its clock, which
  changes the meaning of every timestamp in the historian and of every
  protection function keyed to one. `monitor_only` that no rule can
  override, for a historian or a neighbouring utility's data link.
  **Select-before-operate enforced**: the standard describes the two-step
  form and the equipment mostly does not check it, so a relay that
  remembers the selections is the only thing in the path that can require
  both steps — which turns one injected command frame from a breaker
  operation into a refusal. **The redundancy groups of edition 2**, which
  is where that enforcement survives contact with a control room: a
  control centre reaches a substation over several connections and
  exactly one carries data at a time, so declaring the group lets the
  relay refuse anything a standby connection sends, log a takeover as a
  failover, and carry a selection across one — because a select and an
  execute either side of a failover used to be a refusal, and a refusal
  like that at three in the morning is how select-before-operate gets
  turned off for good. **Setpoint values are bounded**, which is the
  other half of a policy about the grid: a rule says who may command a
  point, and `setpoints` says what that point may be set to (`min`, `max`)
  and how far one command may move it (`max_delta`), for all three of the
  standard's encodings. Without it a control centre that may move a
  setpoint at all may move it to anything the encoding holds — which on a
  scaled value is -32768 to 32767 and on a short float most of the real
  line. The **sequence numbering** is checked in both
  directions, because it is the only thing in the protocol that finds a
  lost, duplicated or replayed frame. `STOPDT_act` is a policy decision of
  its own: it stops data transfer, so a client that may send it blinds a
  control room without refusing a single command. A **station sending an
  activation to its own control centre** is refused, because that is not a
  shape the standard has and it is what a compromised gateway pivoting
  upstream looks like. Commands are rate limited separately from frames,
  because a control centre sending a thousand breaker commands a second is
  not a busy control centre. Refusals are the standard's own negative
  confirmation, so the centre's alarm list says something true and the
  link carries on. **IEC 62351-3** for the stations that have it: TLS from
  the first octet. The metric payloads are never decoded — a schema per
  estate is out of scope, and a relay that got one wrong would corrupt a
  reading nobody could trace

- `kind: snmp`: an **SNMP** relay in front of the equipment that
  management protocol actually manages. SNMP runs every switch, router,
  printer, uninterruptible supply and building controller in an estate,
  and v1 and v2c authenticate with a **community string**: a cleartext
  password in every datagram, `public` to read and `private` to write on
  anything nobody reconfigured, with no integrity, no replay protection
  and no confidentiality. One datagram reads a device's whole
  configuration; one changes it. v3 has a real security model and also
  has `noAuthNoPriv`, which is v2c with more fields. The devices cannot
  be fixed — they are printers and building controllers with firmware
  nobody ships updates for — so the relay is the only place a policy can
  live, written in the protocol's own terms: the version, the credential,
  the operation, and the **object identifier subtree**, compared per
  sub-identifier rather than per character, because `1.3.6.1.2.1` is a
  string prefix of `1.3.6.1.2.11` and not its parent. `read_only` is one
  line that no rule can override, because SNMP has exactly one writing
  operation. Given the v3 users' pass phrases in `usm_users`, the relay
  **reads** v3 as well: it derives the same key both ends derive, verifies
  the digest, decrypts an `authPriv` payload, and applies those same rules
  to it — which matters because without the keys every rule about an
  operation or an object subtree applied to v1 and v2c and silently did
  not apply to the version an operator is told to insist on. It never
  signs and never encrypts: the octets forwarded to the agent are the
  octets that arrived. The **amplification is bounded in two directions**: a
  forty-octet GETBULK with a repetition count of ten thousand asks for
  megabytes, aimed at whatever address the datagram claimed to come from,
  so a count past the bound is **lowered rather than refused** — a
  mis-tuned poller still gets an answer and the amplifier is gone — while
  a response disproportionate to its request is refused outright. Every
  answer is **matched to its question** by request identifier, which is
  the only thing in the protocol that pairs them and therefore the only
  way to recognise a response nobody asked for: on UDP that is the shape
  of a spoofing attack on the manager. The **version is rewritten
  downwards**: a manager authenticates with v3, or over RFC 6353 TLS, and
  the relay speaks v2c to a switch whose firmware has neither, with a
  community string the manager never learns — and the answer is rebuilt in
  the version the question used. What it will not do is forge: producing
  v3 is refused at load, and a v3 *request* is refused rather than
  downgraded, because its answer would have to be authenticated with a
  key this relay does not hold. A v3 *trap* downgrades cleanly, which is
  the modern-device, legacy-collector case. An `authPriv` payload is
  decided about and not inspected, and said to be: the header is
  readable, the ciphertext is not, and pretending otherwise would be
  worse than either refusing or forwarding. And **RFC 6353** is the way
  out of USM: `tls_mode` on the stream half, `dtls_mode` on the datagram
  half that this protocol actually runs on, with RFC 5591's transport
  security model inside either — a v3 message that carries no user, no
  engine, no clock and no digest, because the session carries all four.
  What identifies the sender is its **certificate**, which
  `cert_to_name` turns into the security name a rule names by RFC 6353
  §5.3's table, so the credential an estate has to manage becomes one it
  already issues, revokes and rotates. The missing digest is what makes
  the model worth relaying rather than merely terminating: a refusal can
  be *answered* — `noAccess` in the manager's own monitoring system where
  USM gives a timeout — and a v3 request *can* be downgraded to v2c for a
  switch that will never speak anything else, with the answer rebuilt in
  the manager's own envelope. `dtls_mode: detect` takes records and plain
  datagrams on one port for an estate part-way through that move, and says
  plainly what it costs: the client chooses which to speak, so the policy
  is what requires the certificate — which is what `transports` on a rule
  is for

- `kind: ldap`: an **LDAP and LDAPS** relay in front of a directory — the
  one service in an estate that knows who everybody is, answering the
  protocol every application that has not moved to OIDC still asks with.
  Two defaults of that protocol are why this exists. A simple bind with a
  name and an **empty password** is an anonymous bind by RFC 4513 §5.1.2,
  and most directories answer it with *success*; an application written as
  "bind as the user, and if it worked the password was right" is then
  bypassed with an empty string, and the directory cannot tell the
  difference. And a simple bind on port 389 puts a **directory password in
  the clear** on the wire, which the client library that did it does not
  mention. Both are refused by default, and the second is refused even in
  shadow mode, because by the time a policy could be consulted the password
  has already travelled. The policy is written in LDAP's terms: who bound
  and how, which naming context and subtree a request may name, which
  operation, and which attributes. Two of those are unusual. **Subtrees are
  compared one relative name at a time**, because a string suffix test
  admits `dc=notexample,dc=com` under `example,dc=com`. And the **attribute
  policy applies to the answer**: a search that asks for `*` never names
  `userPassword` and the directory sends it anyway, so a denied attribute is
  removed from the entry on its way back — which is the half a request-side
  access list cannot do — while a request that names one plainly is refused,
  and a *filter* that tests one is refused too, because `(userPassword=a*)`
  is a password oracle a character at a time. The **identity is the
  directory's to grant**: the relay watches the bind response, not the
  request, so "this service account may read this subtree" means what it
  says. An unbounded subtree search is this protocol's amplification, so the
  entries are counted and the search is cut with the directory's own
  `sizeLimitExceeded`; the filter's depth, term count and leading wildcards
  are bounded too, because a filter is the one part of a request whose size
  the client chooses and whose cost the directory pays. **StartTLS is
  terminated here** rather than forwarded, which makes it a secure upgrade
  for a client library nobody can reconfigure — and it discards the
  identity, as the standard requires

- `kind: dhcp`: a **DHCP relay agent that reads what it relays** — the one
  protocol where *answering* is the attack. A client broadcasts "who will
  configure me" and believes whatever answers first: its address, its **default
  route**, its **resolvers**, its **proxy** (option 252) and, on a machine that
  boots from the network, the **file it boots**. Nothing in the exchange
  authenticates anybody, and the client has no address yet, so it cannot even be
  told apart by one. That makes this the one relay kind whose interesting half
  faces *upstream*. A **reply from an address the listener does not admit as a
  server is dropped** before it is read — DHCP snooping by address rather than by
  switch port, never shadowed, and filled in from the upstream pool when nobody
  wrote a list, because an operator who wrote none meant "the servers I
  configured". The **options a server sends are checked as a configuration**:
  option 121 and Microsoft's 249 are a routing table in a broadcast reply,
  option 252 is a proxy, options 66 and 67 are what a machine boots, and each is
  stripped by default while the address itself goes through — a client that still
  gets its address and no longer gets a route it should not have is a client that
  works. The **addresses in a reply are checked against the estate's own**
  gateways, resolvers and boot servers, which catches a *compromised real server*
  as surely as a rogue one, and the boot server is checked in both places it
  lives because a check on one has a way round it. A **client does not get to say
  which segment it is on**: option 82 from a client is stripped as RFC 3046
  requires and the relay adds its own. And the **starvation bound is keyed on the
  hardware address**, because pool exhaustion is one host sending thousands of
  discovers with a made-up address in each and a limit keyed on the source
  address would see one sender doing nothing unusual

- `kind: dhcp6`: the same argument on the **other half of a dual-stack estate**,
  and it is a listener of its own rather than a flag on `dhcp` because DHCPv6 is
  a different protocol: a different packet format, a relay mechanism that
  **nests whole messages** rather than filling in a field, a client identified by
  a **DUID** rather than by a hardware address, and options DHCPv4 has no
  equivalent of. It is also the half an estate is most likely to have left
  unwatched, and there is *more* in an answer here. A reply can carry a **boot
  file URL** (RFC 5970), a **captive portal** a client will open (RFC 8910), an
  **SZTP bootstrap server** a switch will fetch a configuration from and apply to
  itself (RFC 8572), the **S46 containers** and **AFTR name** that put a host's
  *IPv4* traffic through a border relay of the sender's choosing — a takeover of a
  protocol the message is not even about — and the **Server Unicast option**,
  which tells a client to stop using the relay and thereby switches off every
  policy this listener has. Each is stripped by default while the address goes
  through. The **resolvers and the search list are deliberately not on that
  list**: they have a positive list of their own, which is the better check
  because it names what the estate's resolvers *are*, and handing them out is the
  whole purpose of stateless DHCPv6 on a network that addresses itself by router
  advertisement. **Prefix delegation** is the part with no DHCPv4 equivalent and
  the part where a wrong answer is largest — a reply delegating `::/0` has handed
  a host the whole of IPv6 to route — so both ends are bounded and a prefix
  outside the estate's is **refused rather than stripped**, because there is no
  useful half of a delegation to keep; a client's own `::/0` *hint* is still
  allowed, because RFC 8415 §21.22 lets it mean "any". A **valid lifetime of zero
  is never bounded up**: zero is how a server withdraws an address, and applying
  a floor to it would turn a withdrawal into a lease. And the **starvation bound
  is keyed on the DUID**, not the source address, because a DHCPv6 client sends
  from a link-local address it chose for itself and an address-keyed limit would
  see one sender doing nothing unusual

- `kind: postgres`: a **PostgreSQL relay**, which is deliberately **not a SQL
  firewall**. Knowing which tables a statement touches means parsing SQL
  properly -- every alias, subquery, CTE, view, function body and `search_path`
  interaction -- and a relay that got that 95% right would have a policy with a
  hole in exactly the place somebody is looking; restricting a role's tables
  stays the database's own job, done properly, with `GRANT`. What a relay can do
  is four things. It **refuses the encryption downgrade**, which is the whole
  reason to put one in front of this protocol: TLS is negotiated *in cleartext*
  -- eight octets ask, one unsigned octet answers -- and libpq's default
  `sslmode` is `prefer`, meaning "carry on in the clear if refused, without
  telling anybody", so the most widely deployed client in the world downgrades
  silently when something on the path rewrites one byte. The relay answers that
  request itself rather than letting the server's answer decide, and one line
  fixes for every client at once what ten thousand connection strings will not.
  It **refuses the authentication methods whose credential an observer can
  reuse**: `password` is the password in cleartext, and `md5` is worse than it
  looks, because the stored verifier is `md5(password+username)` -- the hash *is*
  a password-equivalent, so anybody who reads `pg_authid` authenticates without
  cracking anything. It **refuses what is not a statement at all**:
  `replication=true` is a startup *parameter* that turns the connection into a
  byte-for-byte copy of every database including the role passwords, so no
  statement policy would ever see it; the legacy fast-path call names a function
  by object identifier and bypasses the parser; and a cancel request arrives on
  a connection of its own which the server acts on with **no authentication
  whatsoever**, the whole credential being a process identifier and 32 bits. And
  it **decides by the shape of a statement**: an allow list of *kinds*, where a
  statement the classifier cannot name is refused. That inverts the deny-list
  problem -- searching for `DROP` is beaten by `DR/**/OP`, by a quoted
  identifier, and by an innocent statement that mentions the word in a string,
  whereas an allow list of shapes fails closed on a spelling nobody thought of.
  The classifier strips comments and quoting *properly* (PostgreSQL's block
  comments nest, dollar-quoted strings have no escaping at all, and a comment is
  whitespace rather than nothing so `SEL/**/ECT` does not become `SELECT`), and
  is conservative in the one direction that is safe: a data-modifying CTE is the
  write it contains rather than the `SELECT` it opens with, `EXPLAIN ANALYZE` is
  the statement it runs because `ANALYZE` executes it, and `COPY` carries which
  of its three operations it is -- because `COPY ... FROM PROGRAM` runs a shell
  command as the server's own user, and no rule in any mode can allow it

- `kind: mysql`: a **MySQL and MariaDB relay**, where the distinguishing fact is
  that **the dangerous operations are commands rather than statements**. After
  the handshake every client message begins with a one-octet command code, and
  several of those carry no SQL at all: `COM_SHUTDOWN` is one octet and stops the
  server, three more open a stream of every change to every database,
  `COM_TABLE_DUMP` is a whole table, `COM_PROCESS_KILL` ends somebody else's
  query, `COM_DEBUG` writes the server's internals to its error log, and
  `COM_CREATE_DB` and `COM_DROP_DB` predate the DDL statements entirely. **A
  relay that only classified SQL would never see any of them**, so this kind has
  a command allow list where the postgres one does not, defaulting to what a
  driver sends and nothing administrative. Two commands are subtler and are why a
  capability policy alone is not enough: **`COM_CHANGE_USER` re-authenticates a
  live connection** as somebody else, so a relay that did not read it would have
  a user policy that applied to the first message and nothing after it; and
  **`COM_SET_OPTION` turns `CLIENT_MULTI_STATEMENTS` on after the handshake is
  over**, so refusing the capability at the handshake is a policy a client lifts
  with one command. The move this kind makes that no other does is to **rewrite
  the server's greeting**: MySQL's handshake runs the opposite way round from
  PostgreSQL's -- the server speaks first and advertises its capabilities -- so
  the relay clears the bits the policy denies and forwards the edited one. A
  client that never sees `CLIENT_LOCAL_FILES` offered cannot negotiate it, so the
  server can never ask that client to open a path and send its contents -- which
  is how a hostile or compromised server reads the filesystem of whatever
  connected to it -- **and the application still works**. That is rewrite rather
  than refuse, the same choice the tftp kind makes with RFC 7440's window, and
  for the same reason: a control that breaks every application on a segment is a
  control somebody switches off. `CLIENT_SSL` is the one bit that cannot be
  stripped, because stripping it would perform the downgrade the kind exists to
  prevent

- `kind: tds`: a **SQL Server relay**, where three things are different again.
  **The password is an encoding, not a secret**: a `LOGIN7` carries it with the
  nibbles swapped and XORed with 0xA5, with no key, so anybody who read the
  packet has the password -- which makes `require_tls` here not hardening but the
  difference between a reusable credential on the wire and none. The negotiation
  that decides it is one unsigned octet in a `PRELOGIN` option table, where `off`
  means "I would rather not" and `not_supported` means "I cannot", and their wire
  consequence is identical -- so a client that asked for `off` and hears
  `not_supported` carries on in the clear without complaint. **The relay answers
  the negotiation itself** rather than forwarding the server's octet, making every
  client one the downgrade cannot touch, and logs each connection whose
  negotiation it raised so the clients that would have gone in the clear can be
  read off a list before the setting is turned on. **The dangerous operations are
  procedures**: `xp_cmdshell` is a shell command as the service account, the
  `sp_OA` family is arbitrary COM, the registry procedures are the host's
  configuration, `sp_addlinkedserver` turns one compromised database into a route
  to another, and `sp_configure` is how the first of those gets switched back on
  -- and to a statement classifier every one of them is an `EXECUTE`, so a
  statement policy strict enough to catch them would refuse every stored
  procedure in the estate. Hence a procedure allow list defaulting to what a
  driver calls, with that set refused even in monitor mode. And **the statement an
  application runs is not a statement**: every client library that uses parameters
  sends `sp_executesql` with the SQL in a parameter, so a relay reading only
  `SQLBATCH` would inspect the `SET` statements a driver emits on connect and
  nothing else. The relay reads that one parameter -- and only that one, because
  the rest are the caller's data -- and runs the same statement policy on it.
  The structural oddity is the **TLS handshake, which happens inside TDS packets
  and then stops**: for the length of the handshake TDS wraps TLS, afterwards TLS
  wraps TDS, and the nesting inverts once part way through a connection

- `kind: bacnet`: a **BACnet/IP relay in front of a building**. The controllers
  behind it hold the setpoints for air handling, chillers, lighting, lifts,
  access control and smoke control, and the protocol has **no identity at
  all**: no user, no session, no password that means anything, and no transport
  security. Clause 24's `authenticate` service was withdrawn from the standard
  and its network security is implemented by almost nothing in the field, so a
  device answers whoever asks it.

  Three properties of the protocol shape what the relay does. Writing is a
  *service*, not a mode, so the difference between reading a zone temperature
  and setting it is one octet -- and an unconfigured listener therefore carries
  reading, discovery and notifications and nothing that changes anything.
  Writing has a *priority*, and the priority is the privilege: a commandable
  object holds sixteen command slots, the plant follows the highest-priority one
  that is filled, and slots 1 and 2 are life safety and cannot be overridden by
  the management system, a schedule or an operator -- so a write above the bound
  is refused *hard*, in monitor mode too. And it is broadcast, and it amplifies:
  one `who-Is` is answered by an `i-Am` from every device that hears it, and a
  BBMD's foreign-device registration lets one unauthenticated datagram subscribe
  a host to every broadcast on a network it is not even on.

  Deciding about a request means knowing which object it is about, and the first
  object identifier in the parameters is the wrong one often enough to matter --
  in a COV notification the first is the device that sent it and the third is the
  object that changed. So the relay knows where each service keeps its object,
  checks every object in a multiple request rather than the first of forty, and
  where it *cannot* find one says so: with object rules configured, a request
  whose object was not found is refused rather than passed

- `kind: redis`: a **Redis and Valkey relay**, and the protocol where a relay earns
  its place fastest -- because **Redis's own default is no password**. An instance
  with `requirepass` unset accepts every command from anybody who can reach the
  port, so an instance that is *reachable* is an instance that is
  *administrable*. And the distance from an administrative command to remote code
  execution is three of them: `CONFIG SET dir`, `CONFIG SET dbfilename`, `SAVE`,
  which writes a file of the attacker's choosing wherever the server can write --
  pointed at a cron directory or an `authorized_keys`, a shell. There is also
  almost nothing for a relay to reason about, because a command is an array of
  opaque byte strings with no schema and no statement grammar. So the policy is
  four decisions in order. **Authentication first**, refusing any command that
  arrives before the connection has authenticated, with the answer taken from the
  *server's* reply rather than from the relay having seen an `AUTH` -- one that
  trusted the attempt would treat a wrong password as a login. **Then the command
  name**, as an allow list defaulting to what an application does to a cache,
  where the absences are the value: `MODULE LOAD`, the Lua interpreter, the
  replication commands that replace the dataset from a server you choose,
  `MIGRATE`, `FLUSHALL`, `MONITOR` (which streams every command every client sends,
  arguments included -- which is every value written to the database), and `KEYS`,
  which is O(n) **on the single thread that serves every client** and so is an
  outage that reads as a slow query. **Then the subcommand**, because `CONFIG GET`
  is a read and `CONFIG SET` is the paragraph above. **Then the key prefix**, which
  is the closest this protocol has to the boundary the SQL kinds leave to `GRANT`
  -- and which refuses the ten commands whose key positions depend on an option
  rather than checking the wrong argument, because a prefix policy applied to a
  `STORE` option's value or a Lua script's text is one that passes exactly what it
  was meant to stop

- `kind: amqp`: a **message broker relay**, and the only kind here that reads
  **two protocols on one port** -- because AMQP is two protocols. A client picks
  one in its first eight octets: 0-9-1, which is what RabbitMQ speaks and what
  almost every deployment means by AMQP, or 1.0 (ISO/IEC 19464), which is a
  different protocol that kept the name. On the first, every operation is a
  method frame with typed arguments; on the second there are nine performatives
  over a self-describing type system, and the thing being authorised is the
  *address a link attaches to*, with everything after it carrying a handle. Both
  are read, and one policy decides both: the brokers that serve both versions
  spell an address `/exchange/X/key` and `/queue/Q`, so the same exchange and
  queue lists cover it.

  A broker is where an estate's data is in transit -- orders, payments,
  telemetry, the events that drive every other service -- and its own
  permissions are a per-user, per-vhost matter administered inside the broker.
  This holds that boundary in the configuration that is reviewed with everything
  else, and adds three lines the broker's model does not draw.

  **Topology is not work.** Declaring an exchange, deleting a queue, binding,
  unbinding and purging are the broker's *configuration*, and a service that
  publishes to an exchange somebody else declared needs none of them -- so they
  are off until named, and a client library that declares its own queue on
  connect becomes a decision an operator makes rather than a default nobody
  noticed. **The credential is in the clear**: PLAIN, which is what every
  deployment uses, is the username and the password in one field separated by a
  zero octet, so `require_tls` is the setting that matters most -- and the relay
  reads the *username* out of the exchange for its rules and its logs and never
  the password, so no code path between the wire and a log line holds a broker
  credential. And **the dangerous argument is not the obvious one**:
  `x-dead-letter-exchange` on a queue and `alternate-exchange` on an exchange
  each name an exchange the broker will route to, and `reply-to` inside a
  message names a queue a responder will deliver to, so a policy that checked
  only the field being declared would let a client have the broker reach what
  the client may not. All three go through the same lists.

  Two smaller things fall out of the protocol being stateful in both directions.
  A refusal **ends the connection**, with the protocol's own statement of why --
  dropping one frame out of a conversation would leave the two sides disagreeing
  about what happened. And the inbound direction gets the *deny* lists only: an
  allow list says what a client may ask for, while a delivery names where a
  message came from, which a consumer need not be allowed to name

- `kind: s7`: a relay in front of a **Siemens PLC**, and the listener for the
  protocol with the least security of any here. S7comm is three layers on TCP
  102 -- TPKT, COTP, S7comm -- and what matters about it is what it does not
  have. There is **no transport security at all**, which is why this kind takes
  no TLS section: a certificate here would promise something the protocol cannot
  do. And there is **no authentication worth the name**, because the optional
  password protects a handful of functions on some CPU families and nothing on
  others, and an S7-300 with no password accepts a **stop** from anybody who can
  open a socket to it. The equipment cannot be fixed: a controller in a line is
  replaced on a capital cycle, not a release cycle, and its firmware is
  qualified against the process it runs. So the boundary has to be somewhere
  else, and this is somewhere else.

  Four things are the whole of this kind. **The controller is decided before the
  PLC is dialled**: which CPU a client asked for is in the COTP connection
  request, where the called TSAP's two octets hold a connection resource, a rack
  and a slot -- so a client that may not reach that controller is answered with
  a COTP disconnect and never takes one of its connection resources, of which an
  S7-300 has sixteen altogether. The *resource* is the cheapest useful line in
  the section, because `pg` is the programming device connection an engineering
  station opens and `op` is an operator panel: a listener admitting only `op` has
  refused every engineering station without naming a single function.

  **One vocabulary spans two layers.** The protocol puts reading and writing
  memory behind a function code, and the diagnostic buffer, the block list, the
  clock, the password and the debugger behind a user-data group and subfunction
  -- so a policy written against either alone would have nothing to say about
  half the protocol. Both are mapped onto nineteen words, the default allows what
  an HMI, a historian and an inventory do and nothing that changes anything, and
  `read_only` therefore means every operation that changes the controller rather
  than just a write -- one line no rule can override, because a read-only
  listener one rule could write through is not one. **An upload is off with the
  writes** although it changes nothing, because reading a block out of a PLC is
  how a plant's control logic leaves the site.

  **The memory is the boundary inside the CPU**: the area, the data block and the
  byte range, checked against the whole span a request covers rather than its
  first byte -- a read of bytes 0 to 200 against a range of 0 to 99 is a read of
  bytes the policy does not name, and it is refused rather than split, because
  splitting it would be the relay deciding which half the operator meant. The
  ranges are written in **bytes** and the protocol carries bits, so the relay
  divides by eight rather than making an operator do it.

  And **a refused request is answered, not dropped**: an acknowledgement carrying
  error class `0x87`, *access fault*, which is what a password-protected CPU
  answers -- so the client's own library reports a refusal rather than a timeout,
  and the poll loop a plant runs on carries on. A refused user-data request is
  answered in its own layer, with the same group and subfunction, because that is
  where a client that asked to set the clock looks. What is never written down is
  a **value**: a write's payload is a pressure, a temperature or a recipe
  parameter, and the address is what a policy is written about

  **S7comm-plus, and the limit of what any relay can see.** An S7-1200 or
  S7-1500 driven by TIA Portal does not speak classic S7comm: it speaks
  S7comm-plus, the same TPKT and COTP stack with protocol identifier `0x72`
  instead of `0x32`. A relay that read only `0x32` was not a relay in front of
  those controllers -- it ended the connection on the first PDU, with no answer
  in the protocol and nothing in the counters an operator would read as a policy.
  `s7comm_plus` decides what happens to it: `refuse` (the default, which is what
  such a listener already meant, now named and counted), `policy` or
  `passthrough`. The policy is deliberately smaller than the classic one, because
  on those controllers the session is integrity-protected and the object and
  variable addressing is **encrypted** -- so a relay sees the outer framing and
  nothing under it, and what is left to decide about is the function code: a
  read, a write, a method call or a program change. `areas` and `dbs` do not
  apply there, and a section claiming they did would be claiming to read what no
  relay can see. Siemens publishes no specification for either protocol, so the
  function names are read from the wire, and one property carries that weight: a
  function this relay **cannot name** is the `unknown` class, `default_action`
  decides it, and `read_only` refuses it -- an incomplete table costs a refusal,
  never a silent pass

- `kind: tftp`: a **TFTP** relay in front of the servers that move firmware,
  configurations and boot images. This is the protocol under provisioning: a
  switch pulls its firmware over it, a machine with no operating system yet
  pulls a boot image, a telephone pulls its configuration. It has **no
  authentication of any kind** — no user, no password, no token, no transport
  security, and no extension that adds one — and the clients are switches and
  boot ROMs, so none of that can be fixed where it lives. That leaves four
  things, and they are the whole of this kind. The **filename is read as a
  path and refused by shape**: a deny list of strings is a list of the
  spellings somebody thought of, stopping `../../etc/shadow` and not
  `..\..\etc\shadow`, stopping that and not `/etc/shadow`, stopping that and
  not `secret.txt.`, which Windows opens as `secret.txt` — so the name is
  classified and the class is refused, and three of those classes (a NUL, a
  control character, an empty name) can never be allowed at all, because they
  mean the relay and the server are reading **different names**. A **write is a
  separate decision from a read and the default is no**, because a write is how
  a configuration leaves an estate and how firmware arrives in it. The
  **amplification is bounded by rewriting rather than refusing**: a
  twenty-octet request yields a whole file and RFC 7440's window multiplies
  it, so a client asking for a window of sixty-four gets its file at the
  bound instead of an error, and nobody has to reconfigure a switch — what
  cannot be lowered is refused, including a server that acknowledges a larger
  block than it was offered. And a **transfer speaks to exactly two
  addresses**, because the protocol moves to an ephemeral port pair after the
  first packet: a datagram from anywhere else is dropped rather than answered,
  since answering is how a relay becomes a reflector and a packet injected
  into a firmware transfer *is* firmware

- `kind: ntp` and `kind: ntske`: an NTP and NTS security gateway, in
  **both directions**. A time packet is 48 octets, has no session and is
  believed absolutely — the device on the other side steps its clock to
  whatever it is told — so this reads every one: the version, the mode,
  the extension fields, and what a server's answer says about the time in
  it. Modes 6 and 7, the control protocol and the private one `monlist`
  belongs to, are refused from the first octet and never reach a server;
  NTPv5 is a different packet format and is never parsed as if it were
  this one. **What a relay can do that a client cannot is compare**: it
  probes every server with its own transactions and refuses to pass on an
  answer from one that disagrees with its peers or says not to trust its
  own clock — the case every other check passes. Pre-shared keys are
  AES-CMAC (RFC 8573; the legacy algorithms need an exception and Autokey
  is refused), NTS is passed through whole with a **downgrade to plain
  NTP refused**, and key establishment is a listener of its own on 4460
  where a connection that does not offer `ntske/1` is not an NTS client.
  Or **terminated**, which is the answer for the time server that cannot
  speak NTS and is not going to: the key establishment listener is the
  key establishment server, deriving each client's keys from the TLS
  exporter and issuing cookies sealed with AES-SIV under a master key it
  rotates with an overlap and keeps across a restart; the time listener
  opens those cookies, verifies every request's authenticator over the
  whole packet, asks the old server in plain NTP, and returns its header
  unaltered with an authenticator signed by the client's own key. There,
  "authenticated" means this relay checked. And where the source *does*
  speak NTS, the relay **re-originates** rather than downgrading: its own
  key establishment with the source, its own cookies, its own
  authenticator on every request and verification of every answer — with
  the cost written down where it is configured, because there is then no
  end-to-end authentication between a client and the source.
  Rate limits answer with the protocol's own kiss-o'-death rather than a
  drop, every expiry is on the monotonic clock because this is the relay
  for the protocol that moves the wall clock, and learning mode writes
  out the client, version and mode lists nobody could have written from
  the inventory
- `kind: ssh`: an SSH bastion. The proxy is an SSH server to the client
  and an SSH client to the target, so every channel and every request
  inside the session is a decision: `direct-tcpip` only to listed
  destinations, `exec` only for matching commands, X11 and agent
  forwarding off by default. The target never sees the client's key.
  Policy is **per principal** — by key fingerprint or by the principals
  of an OpenSSH user certificate — so the deployment robot and the
  on-call engineer are not one policy; the environment a client may set
  is an allow list from which the loader and interpreter variables are
  struck whatever it says; and `scp` and `rsync` are refused wherever
  there is an SFTP policy for them to walk past.
  **A key held in a security token** can be required (`require_hardware_key`):
  FIDO2 `sk-` keys and certificates over them, with the touch demanded
  and the opt-outs refused — the one property of a credential this
  gateway can check, because every other key it accepts is a file and a
  file has copies. The **second factor** is a one-time code or an
  approval on the device somebody already carries, whose bounds are about
  MFA fatigue rather than guessing.
  Sessions can be **recorded to a replayable file** (asciicast v2, one
  per channel) — output by default, keystrokes only if you say so.
  **SFTP is inspected inside the subsystem channel** — read-only, path
  allow and deny lists that may name the session's own user, refused
  operations, extension lists that read every suffix a name carries, a
  bound on the file a client's writes make, and YARA rules over what is
  written, per file rather than per stream — because the whole
  difference between reading a file and deleting a tree happens in
  there
- `kind: telnet`: a telnet gateway, for the equipment that speaks
  nothing else. The NVT protocol of RFC 854 is parsed in both
  directions, because telnet's options are commands escaped into the
  byte stream: an option outside `allow_options` is refused to the
  side that asked and never reaches the other, the session is recorded
  as asciicast v2, and a second factor can be asked for — a prompt the
  proxy writes and an answer it reads, with the code not echoed —
  before the target is dialled
- `kind: vnc`: a VNC gateway that terminates RFB on both legs, which is
  what lets it decide anything: **which security type** a viewer may
  use — the ones with a published specification are mediated, and the
  vendors' own (TightVNC, Apple, UltraVNC, RealVNC) are reimplemented
  from the shapes their sources agree on and warned about at load, with
  what each is actually worth written down rather than implied by its
  name — **whose credential opens the desktop** (the gateway's, never
  the viewer's), **whether the session can be driven or only watched**,
  and what the **recording** holds.
  Versions 3.3 to 3.8 on each leg independently; VeNCrypt with X.509,
  a TLS-wrapped socket, or an SSH tunnel the gateway opens itself with
  the host key pinned; MFA carried in VeNCrypt's plain credential,
  which is the only place RFB names a person
- `kind: rdp`: a Remote Desktop gateway that terminates the connection
  sequence on both legs, because everything worth deciding about an RDP
  session is settled there before a pixel moves. **Which virtual
  channels exist** is the gateway's decision, and since every
  redirection RDP has rides one, that is where file transfer and port
  redirection are switched on and off — by channel, and inside the
  redirection channel by device kind, applied to the announcement that
  nothing can be redirected without. **And inside `drdynvc`, by name**:
  that channel is not a channel but a multiplexer, and a current client
  opens the graphics pipeline, display control, the camera, audio *and
  device and clipboard redirection* by name inside it — so a gateway
  that policed only the static list could be walked around by opening
  the refused channel again in the one that was allowed, which this was
  verified doing before it was fixed. The dynamic channels are decided
  on the create request the **desktop** sends, since that is the only
  place the name appears, and a refusal is answered with the status a
  client that has no such listener would send. **Whose credential opens the
  desktop** is a separate decision from who proved themselves to the
  gateway. A second factor rides the password field, since RDP has
  nowhere to ask, and is taken off before the password travels on. A
  client asking for network level authentication is answered with TLS
  — the downgrade every remote desktop gateway performs, and the only
  way a gateway can check anything at all about a credential. Each leg
  can be TLS, network level authentication towards the desktop, or the
  protocol's own RC4 encryption for equipment too old for either, in
  which case the gateway signs its certificate with the key Microsoft
  published — which authenticates nothing, and is documented as
  authenticating nothing. Being inside that encryption is the point:
  the policy still applies, the factor is still checked and the
  recording holds the session rather than ciphertext

## Features

Everything below is configuration, not a plugin to find: one YAML file
describes it, validation refuses what cannot work, and
[docs/USAGE.md](docs/USAGE.md) has a worked example of each.

### Termination and transport

- TLS 1.2 and 1.3 with hardened defaults, SNI, hot reload of
  certificates, OCSP stapling, Certificate Transparency checks, client
  certificates (request or require), ACME issuance and renewal (HTTP-01
  and TLS-ALPN-01)
- Post-quantum key exchange as an explicit setting: `X25519MLKEM768`
  leads the default list, because a session recorded today is a session
  decrypted later — and naming any group at all used to replace the
  whole list, which is how a configuration written to prefer X25519
  silently dropped the hybrid
- Encrypted Client Hello: the server name is not on the wire, keys
  rotate with a fallback to the public name that keeps rotation safe,
  and `require` refuses the fallback where the name itself is the
  secret; `xproxyctl ech` generates the keys and the HTTPS record
- HTTP/1.1, HTTP/2 (ALPN, or `h2c` on trusted networks) and HTTP/3 over
  QUIC with address validation and Alt-Svc advertisement; HTTP/3 to
  upstreams with a TCP fallback, gRPC-web translation for browsers and
  WebTransport relays (streams and datagrams) to HTTP/3 upstreams
- Mutual TLS and public key pinning to upstreams; PROXY protocol
  towards layer 4 upstreams
- **Key custody said out loud.** Each certificate names `cert_file` and
  then exactly one of three things, so an operator reading the file can
  say where every private key is: `key_file` (a file on this machine, as
  before), `key` (a reference -- `env:`, or `vault:secret/path#field`,
  rotated into a running proxy without a reload), or `signer` (a helper
  on a Unix socket that holds the key, so it never enters this process at
  all -- `xsigner` is shipped, and an HSM, TPM or KMS helper is written
  against [docs/SIGNER.md](docs/SIGNER.md)). Two of them set is refused at
  load rather than resolved by a precedence nobody remembers
- FIPS 140-3 as a refusal rather than a hope: `fips.required` will not
  start without the module active, and the probe *measures* which of the
  configured groups and suites the module will actually do rather than
  checking them against a list that would be out of date

### Routing, load balancing and traffic management

- Routes by host (exact or wildcard), path prefix or regular
  expression, method, header and cookie conditions, priority and gRPC
  service or method; redirects, static responses, path rewriting,
  header operations, per route timeouts and body limits
- Upstream pools with round robin, weighted, least connections,
  consistent hashing, power-of-two-choices and latency-aware balancing;
  active HTTP, gRPC or datagram health checks, passive outlier ejection,
  a circuit breaker with half open probing, concurrency limits with a
  bounded queue, retries on connection errors and chosen statuses within
  a **retry budget**, **hedged requests** for the tail, signed cookie
  affinity, canary endpoints selected by header, cookie or share
- Endpoints from static addresses, hostnames re-resolved on a timer, DNS
  SRV records, or a **Consul** registry; **Unix domain sockets** as
  endpoints; priority tiers with a backup pool and locality preference
  that spills over rather than pinning; **drain** and maintenance state
  per endpoint, a connection age bound, a per-endpoint connection limit,
  slow start for a cold instance, and an explicit address-family policy
  for dual-stack endpoints (**Happy Eyeballs**, or restricted on purpose)
- **Transparent interception** where the network does the redirecting:
  `IP_TRANSPARENT` with the original destination read from the socket, so
  a layer 4 listener can front traffic that was never addressed to it
- An expression language for routes and header operations: `when`
  conditions over addresses, headers, cookies, query parameters,
  patterns, captures and the time of day, checked at load
- A **structured maintenance gate** (a window, the clients exempt from
  it, the page it serves) and **traffic shadowing** to a candidate
  upstream with the two responses diffed, so a migration is measured
  before it is switched

### Content, caching and the gateway behaviours

- Response caching with per route key policies, `Vary` and conditional
  requests; gzip, brotli and zstd compression of eligible responses,
  negotiated with the client; request mirroring
  of sampled traffic to a candidate upstream, bounded and invisible to
  clients
- Static file serving from a directory with index files, listings and a
  single page application fallback, confined to the root
- gRPC: errors answered as gRPC statuses, `grpc-timeout` honoured,
  trailers relayed, per code counters
- The gateway behaviours a modern client expects, each with a policy
  rather than a default: **Early Hints** (103) from a route's own list or
  an upstream's, **early data** accepted, refused or accepted only for
  safe methods (a 0-RTT request is replayable by definition), HTTP/2 and
  HTTP/3 **priority** signals honoured or ignored deliberately, a
  **trailers** policy per route, and a **Range** policy that bounds how
  many ranges a request may ask for and how small they may be, because a
  thousand one-byte ranges is an amplifier rather than a download
- **API version routing**: a version taken from the path, a header, a
  query parameter or a media type, so one route set can front several
  API versions and the inventory knows which is which
- Custom **error pages** by exact status, by class or as a default, read
  at load and chosen per listener or per route — a JSON document for the
  API routes and a page for the rest; a general **CORS policy** per
  route; and header operations templated from the request, the route and
  the connection

### Bounds, abuse and the ban list

- Connection limits at accept (global and per address), concurrency
  ceiling, header, body and idle timeouts, URI and body size limits
- The **request normalisation guard**, before routing, rate limits,
  filters or the WAF look at a request: control characters, invalid or
  overlong UTF-8, double encoding, encoded separators, backslashes,
  path parameters and dot segments, and HTTP/1 requests whose framing
  is ambiguous — the forms that make a proxy and an application read
  one request two ways
- Keyed rate limits (address, network, route, endpoint, country, TLS
  fingerprint, header, cookie, token claim) with reject or tarpit; CIDR
  allow and deny lists; trusted proxy handling for forwarded addresses
- Ban list: repeated denies of any category become escalating temporary
  bans dropped at accept, persisted across restarts, shared across a
  cluster and managed from the CLI; triggers aggregate by network or
  TLS fingerprint against distributed attacks
- Adaptive load shedding by priority class from upstream latency and
  in-flight load; browser proof of work challenge, always or under load,
  with a CAPTCHA tier (Turnstile, hCaptcha, reCAPTCHA) for escalation
  and device identifiers for logs and rate limits
- Account protection: credential stuffing, brute force, registration,
  reset, hoarding and scraping abuse with progressive delay, challenge
  and block, and campaign detection across many addresses
- Bot classification from JA3 and JA4 fingerprints, headers and
  behaviour, with log, challenge and deny thresholds; country policy
  from a local MaxMind or CSV database
- **Threat intelligence lists**: imported CIDR and JA4 lists with an
  action each (log, challenge, deny), refreshed on disk, with routes
  that can be exempt from them — because a feed nobody can exempt is a
  feed that eventually blocks the payment provider
- API inventory discovered from traffic, with shadow, zombie and
  superseded endpoints against OpenAPI descriptions; **API abuse
  detection** per identity over a window — distinct objects touched,
  consecutive identifiers, the share of requests refused — which is what
  enumeration looks like when every single request is allowed
- Origin lock: per request signatures the origin verifies, mutual TLS
  and network rules so an application accepts only proxied traffic
- **Refusal in the ClientHello** for a client already known to be
  unwelcome: a ban or a fingerprint answered with a failed
  negotiation rather than a key exchange spent on a refusal, which
  also gives a scanner nothing to read — no status, no page, no
  header set, no cipher list

### Message and body inspection

- WebSockets opt in per route, and where they are allowed the messages
  are inspected in both directions: RFC 6455 framing
  (reserved bits and opcodes, masking, control frame size and
  fragmentation, continuation state, close codes, UTF-8), bounds on
  frame, message and rate, and an expression list over the messages
  themselves — the upgraded connection used to be the one place this
  proxy stopped looking, which is where applications put their real API
- YARA rules over streams and bodies: a subset of the language
  implemented in Go, applied to a layer 4 connection as it passes or to
  a request or response body before it is forwarded, with a rule
  reported the first time its condition is true rather than after the
  transfer
- **gRPC message inspection**: the framing, a bound on one message
  rather than the whole stream, the protobuf structure (nesting depth,
  field count) and patterns over the strings inside — without a schema,
  because a check that is only as current as its schema is a check that
  quietly stops applying
- Sensitive data detection in both directions: cards, identity numbers,
  IBANs, e-mail, tokens, keys and query credentials, logged, masked or
  blocked per route
- Upload protection: extension chains, content sniffing against name and
  declared type, executable and web shell detection, size and count
  bounds, combinable with ICAP scanning
- Positive security model per route (methods, media types, typed query
  parameters, size bounds) and virtual patches that block a published
  vulnerability by request shape, with counters and expiry
- Web application firewall on the bundled OWASP Core Rule Set through
  Coraza: block or detect per route, custom rules, plugins and
  exclusions, bounded request and response inspection, the encodings a
  body can hide in decoded before the rules run, **learning mode** that
  proposes exclusions from real traffic, per-rule statistics with a
  **measured confidence** so a rule's own history decides whether it
  blocks, and gradual enforcement by block share or canary client
- **XML and SOAP bodies**: entity expansion, external entities and
  nesting bounded before the application's parser sees them, with schema
  validation where a schema exists; **GraphQL** depth, breadth,
  complexity and introspection bounds; **OpenAPI** descriptions used as
  an allow list, read from a file or a URL and re-read when they change
- **ICAP** scanning of uploads and downloads against an external
  service, with preview, block pages and an explicit policy for what
  a scanner being down means; the SFTP and FTP transfers a gateway
  brokers go through the same services

### Deception

- Honeypot routes with 138 built-in decoys — from
  a WordPress login to a cloud metadata document, a container registry
  catalogue, a Werkzeug debugger, an IP camera, a Postfix `main.cf`, a
  broker ACL file and an `authorized_keys` — that mark probing
  clients and feed the ban list; honeytokens that trip the moment a
  planted credential is used, wherever it was planted; hidden-field and
  timing honeypots on forms
- **Graduated degradation** instead of a refusal: a client that has
  done something wrong but not enough to ban is served correctly and
  slowly, so there is nothing to report as broken and nothing to tune
  against, and a crawl that cost nothing now costs the one thing a
  scanner has least of
- **Deceptive answers on real routes**: a wrong but plausible response
  where a refusal would tell a scanner it had found something, and a
  virtual `security.txt` per host. The whole family — what each piece
  costs an attacker, how the signals chain and the order to build them
  in — is [docs/DECEPTION.md](docs/DECEPTION.md)

### Identity and authorisation

- JWT validation at the edge with JWKS rotation, algorithm allow lists
  and claim forwarding; OAuth 2.0 token introspection (RFC 7662) for the
  opaque tokens a JWT check cannot see inside, with a bounded cache
- **Sender-constrained tokens**, so a stolen bearer token is not enough:
  DPoP proof of possession (RFC 9449) with a replay window, and
  certificate-bound access tokens (RFC 8705) checked against the
  client certificate on the connection
- OpenID Connect login (the authorization code flow) with sealed
  session cookies, required claims, identity headers for applications
  and logout through the provider, front channel included
- SAML 2.0 as a service provider: the web browser single sign-on
  profile in a deliberately narrow shape — one unencrypted assertion,
  exclusive canonicalization, SHA-256 and above, the signing key from
  the configuration — because every widened option in a SAML
  implementation is a signature-wrapping bug waiting to be found
- HTTP Basic authentication from a file of PBKDF2 hashes, LDAP bind
  against a directory, API keys with scopes and a lifecycle, and client
  certificate identity passed to applications as RFC 9440's
  `Client-Cert` or Envoy's `X-Forwarded-Client-Cert` — your choice, and
  neither by default
- **WebAuthn** as a relying party: passkeys for registration and
  authentication, with attestation parsed and deliberately not trusted
  (it identifies a model, not a person)
- **SCIM 2.0** provisioning, so an identity provider can create and
  disable the second-factor enrolments and API keys this proxy holds
  rather than somebody doing it by hand
- A second factor shared by every protocol that can ask for one: TOTP
  against one enrolment file, over keyboard-interactive on the SSH
  bastion, in a prompt the telnet gateway writes, in VeNCrypt's plain
  credential on the VNC gateway, carried in the password field on the
  RDP gateway (which has nowhere else to ask) and stripped before the
  password travels on, before an FTP session is brokered, and through a
  filter in front of a web application. One implementation on purpose —
  a second factor that means different things on different ports is not
  a second factor, because the weakest door decides. A code is spent
  when used, every failure gets the same answer, and guessing is bounded
  by a lockout
- **Authorisation as one policy**: every authenticating filter answers
  "who"; `authz` answers "what may they do", deciding on the subject,
  groups, scopes and claims those filters verified — default deny, first
  match wins, and nothing a client sent can reach a rule
- **And one policy above the protocols**: the `authorization` section
  says which identity may reach which listener, target and operation for
  every listener kind, in one place and in one vocabulary — `connect`,
  `session`, `exec`, `forward`, `read`, `write`, `admin` — rather than in
  nineteen protocol policies that can disagree. Each kind keeps its own
  policy for what only it can express (which Modbus register, which SQL
  shape, which SSH channel); this answers the question above them all.
  **Every listener kind but one asks it.** All five gate kinds — SSH and
  SFTP, Telnet, VNC, RDP and FTP — the forward proxy, where the target is
  the destination rather than a pool and a rule is an egress policy about
  people; every relay kind; and both generic layer 4 relays. On the many
  kinds whose clients have no identity at all — Modbus, S7comm, BACnet,
  SNMP, TFTP, DHCP, syslog, DNS, NTP and the generic relays — a rule is
  about networks, pools, listeners and hours, which on a plant network is
  the policy that was missing. That same admission point is where the
  imported address lists are now asked about the client, which before this
  happened only on the HTTP and forward listeners: a `cidr` feed did
  nothing at all in front of a PLC, which is exactly where one earns its
  keep. Redis and AMQP ask **twice** — once for the connection and once
  when the server's own answer proves the name — which makes them the only
  relays where an allow rule keyed on a user is an authenticated grant
  rather than a filter on a claim. The HTTP gateway asks it too, once
  per request and after the route is matched, which is the layer neither
  its routes nor its `authz` filter could supply: a route is one of the
  things being decided about, and the filter needs an identity the client
  has not offered. A refusal there is a 403 rather than a dropped
  connection. A kind added tomorrow starts outside the policy and a
  configuration naming it is refused at load, rather than left as a hole
  in a policy somebody believes is complete
- **Detections that arrive as files, not as a release.** Twenty-five
  **behaviour packs** ship with the product: ten for ATT&CK for ICS
  techniques, six for the named malware (FrostyGoop, Industroyer and
  Industroyer2, PIPEDREAM, Stuxnet, COSMICENERGY) and nine for the tooling
  an estate actually meets — Nmap's control-protocol scripts, plcscan,
  smod, Metasploit's Modbus modules, Redpoint, Snap7, the OPC UA clients,
  the hand-driven IEC 104 masters. Each is a signed, versioned file saying
  that a shape of events from one actor inside one window is one technique:
  data, with no expression language, no negation and nothing that can name
  a symbol in the binary. That matters because a plant will take a file
  this quarter and will not take a new binary — and because a pack sits on
  the *stream of events* the policies produce rather than on a frame, which
  is the only layer the named tooling is visible at: none of it exploited a
  protocol, so there is nothing in a frame to match on, and what separates
  Industroyer from a control centre is the shape of a sequence across a
  quarter of an hour. A pack may only name a technique and a refusal reason
  this build already has, checked when the file loads, so **a pack cannot
  claim a detection this proxy cannot make**. Twenty-one of the twenty-five
  may only alert and say so in the file, because a shape has false
  positives; the four that may deny rest on something named on the wire and
  still do nothing until an operator turns enforcement on, and what they
  then do is a time-boxed quarantine rather than a ban
- **Just-in-time access, and it reaches the plant.** Nobody opens a
  session on a bastion unless there is a live grant naming them, the
  listener and the target: requested by somebody, approved by somebody
  else, ending by itself, and written to a hash-chained trail. A bastion
  with standing access is a bastion whose accounts are worth as much as
  the machines behind it. On the OT kinds the same machinery answers a
  question about a *request* rather than a session, because one Modbus
  connection carries reads all day and one program write at four in the
  afternoon: **engineering activity is its own class of event** — a program
  download or upload, a controller stopped, a protection setting group
  written, a firmware image pushed, an OPC UA method called — reported with
  its class whatever the rules said about it, and refusable where there is
  no approved work order open for it. So "downloads only during an approved
  change" is a policy the relay enforces rather than a sentence in a
  procedure, and "who downloaded what, when, under which work order" comes
  out of the ledger rather than out of somebody's memory

### The estate: clusters, fleets and Kubernetes

- A **cluster** in either of two shapes. Networked: every node dials
  every peer over mutual TLS, with no leader, sharing rate limit
  consumption, bans, honeypot marks and session ticket keys — and a
  limit that must hold exactly cluster wide is decided by one owner
  per key. Local: the daemons of one host over a Unix socket,
  where the socket's permissions and the kernel's own report of the
  caller are the authentication, so there is no certificate to issue
  and none to rotate
- **Fleet operation**: `xproxy-fleet` holds the bundles and each node
  long polls for its own over mutual TLS, applies it through the
  ordinary reload — validated, checked against the sandbox, rolled back
  if it is refused — and reports its version, generation and counters
  back. The controller never connects to a node
- Kubernetes ingress controller mode: Ingress and Gateway API resources
  become routes, upstreams and certificates, reloaded within a second
  of a change through watches; manifests and a container build
  included

### Observability and control

- Four JSON log streams (access, error, security, audit) to files,
  journald or syslog, with per stream redaction of personal data and
  a request identifier end to end; SIEM export in NDJSON, Splunk HEC,
  CEF or LEEF
- `xproxyctl` over a Unix socket with kernel verified caller identity:
  status, upstreams, quotas per tenant and route, WAF rule statistics,
  learned exclusions and flagged clients, reload with dry run,
  configuration diff, history and rollback, certificates, logs, bans,
  cache, honeypots, DNS, ingress, cluster, metrics, the device
  inventory, ECH keys and the
  HTTPS record to publish, second-factor enrolment, and a full screen
  TUI; a web GUI with
  viewer and operator roles, configuration editing with validation,
  graphs and live logs
- Packet capture of the exchanges the proxy handled, written as pcapng
  that Wireshark and tshark open: the decrypted request and response
  synthesised into a TCP conversation, selected by host, route, method,
  path, client network, status, deny reason or a sample, switched on
  for a bounded window with `xproxyctl capture start` and redacted so
  the file does not carry the headers that should not be on disk
- **Session recording and replay** on every gateway that terminates an
  interactive protocol: asciicast v2 files, one per channel, the screen
  by default and the client's own stream only where a configuration says
  so, with every control sequence filtered on the way out so replaying a
  recording cannot drive the reviewer's terminal. The graphical ones hold
  the protocol stream, and `xproxy-replay` decodes it: RFB into frames or
  one self-contained page, RDP into the timeline of what the session did,
  and in both cases a plain statement of what it could not decode rather
  than a picture nobody sent. A recording can also be **hash-chained into a
  manifest beside it** and **encrypted at rest** under a key from custody:
  the chain, keyed, makes a recording unforgeable by somebody who has the
  host and not the key, and `xproxy-replay` verifies it before it plays
  anything back, because a file that can be edited afterwards with nothing
  to show it had been is not evidence. The manifest covers the ciphertext,
  so an auditor can be given the manifest key and establish that the file is
  the one the proxy wrote without being able to read the session in it
- **A device that is not there.** Deception used to stop at HTTP, and every
  other kind either forwarded or refused — which on a plant network is a
  disclosure, because an honest gateway answering "no device here" for 246 of
  247 unit identifiers has drawn the map for whoever asked. A `modbus` listener
  can now answer as a fabricated device instead: as a whole honeypot with
  nothing behind it, or, on a real relay, for the frames it was going to refuse
  anyway and only for the clients named. The values are derived rather than
  invented — stable while you read them, drifting between periods, inside their
  bands, with totalisers that only increase — because a decoy is given away by
  noise, by stillness and by impossibility. One rule holds and is tested: a
  frame that was going to reach a device is never answered by the fabrication,
  since the failure mode here is not a confused scanner but an operator acting
  on a tank level that was never measured. An `iec104` listener does the same
  for a substation, where the walk is shorter still — the common address is two
  octets and a control centre names it in every ASDU, so a relay that refuses
  the ones it does not carry has published the estate. The fabrication speaks
  the association the way the standard describes it, because a control centre's
  own software checks this protocol harder than any Modbus master checks that
  one: nothing before STARTDT_act, then the end of initialisation, an
  interrogation answered ACTCON, the points, ACTTERM, and an address it is not
  refused the way a station refuses one. And an `s7` listener does it for a
  Siemens controller, where the hardest part to hide by policy is the system
  status list: every scanner reads it first, the estate's own asset tools read
  the same list, and it hands over the order number, the module type and the
  firmware. A fabricated CPU answers it instead — and gets the things a
  controller cannot do right as well as the things it can, down to not speaking
  the protocol its family does not speak. And an `snmp` listener does it for
  the management network, where the refusal is about a *credential* -- a
  community string that is wrong is refused and one that is right is answered,
  which is the oracle a password list needs -- with the amplification bounds
  applying to the fabrication as they do to an agent, because a honeypot that
  answers a forty-octet GETBULK with half a megabyte is a liability rather than
  a sensor. And a `redis` listener does it for a cache, which is the one of
  these where the attacker is a **script** rather than a person and always the
  same script: an exposed instance is found by a scanner, and what follows is
  `INFO`, `CONFIG GET dir`, `CONFIG GET dbfilename`, `CONFIG SET` both of them
  somewhere that executes, a `SET` carrying a cron line, and `SAVE` — remote code
  execution built entirely out of commands the protocol considers ordinary, with
  no exploit in it and nothing to patch. A refusal stops that at the first step
  and sends its author to the next address; answering it collects the directory,
  the file name and the payload. The tripwires there need no configuring,
  because nothing legitimate sends any of that chain to a fabricated cache — and
  two things the fabrication will not pretend, `EVAL` and `MODULE LOAD`, answer
  the error the real server answers when it cannot, since a `+OK` to either
  would be a claim that code was running and nothing said afterwards would be
  consistent with it. A `mysql` listener does it for a database, where the
  reconnaissance is the attack's first half and is made entirely of legitimate
  statements — the version, `SHOW DATABASES`, `@@datadir`,
  `@@secure_file_priv`, `SHOW GRANTS`, `mysql.user` — whose answers decide
  which of four escalations the next statement is: a web shell through `INTO
  OUTFILE`, a key through `LOAD_FILE`, a file off the *client* through `LOAD
  DATA LOCAL INFILE`, or a shared object through `CREATE FUNCTION ... SONAME`.
  The part that takes care there is that the answers agree with each other,
  because that is what a fingerprinting tool checks: `@@secure_file_priv` NULL
  and the file statements refused the way such a server refuses them,
  `SHOW GRANTS` without `FILE` and `mysql.user` refused rather than empty, and
  no `caching_sha2_password` on a MariaDB version. It never asks the client for
  a file, never sleeps, and never invents rows. And a `postgres` listener does
  it for the database whose escalation is *documented*: `COPY t FROM PROGRAM`
  runs a shell command as the server's operating-system user by design, so the
  reconnaissance there is short and turns on one question -- is this role a
  superuser -- which is why `superuser` is the consequential field of the section
  and defaults to false. Saying no is safer to impersonate and the more common
  truth on an application account, and a visitor told no who tries it anyway has
  said more than one told yes. Either way the fabrication runs nothing and never
  says it did. The consistency that has to hold is the same fact answered in two
  forms: a real server says `on` or `off` to `SHOW is_superuser` and `t` or `f`
  to the catalogue's `usesuper`, and every `COPY` and file function is refused
  the way that fact requires. Unlike the MySQL decoy this one can sit behind
  TLS, because on this protocol the encryption is negotiated before the startup
  packet and the relay answers that itself. And a `dns` listener does it for the
  resolver, where a refusal costs the other end not a request but the whole
  conversation: the query is all they ever send. A name on a threat feed answered
  NXDOMAIN tells an implant that something here is deciding and it has a list of
  other names to try; a tunnel told NXDOMAIN moves to the channel nobody is
  watching. Answered, both keep talking, and every query after the first is the
  next domain in the rotation or the next chunk of the payload. Two things there
  are about not becoming a weapon, because a resolver is an amplifier and a
  fabricated address is somewhere a visitor then goes: an answer to a client whose
  address nothing has verified is bounded against the query that asked for it and
  truncated past that bound, so a real client comes back over TCP and a spoofed
  source cannot; and the default pool is the documentation range, which nothing
  routes, with a warning at load when an operator points it inside the estate. It
  answers a different address per name, which is the difference between it and a
  sinkhole -- a sinkhole answers one address for everything, so two lookups find
  it. And a `telnet` listener does it for a *login*, which is the one place in
  this set where the credential is the intelligence: what arrives on port 23 is
  not a person but a dictionary, and answering it collects the list, then the
  busybox probe, the liveness check, and the `wget` that names the payload, the
  address serving it and the architecture it was built for. Nothing is run and
  nothing is fetched -- a fabrication that fetched the payload would be doing the
  download from this estate's address -- and no password is kept in any form a
  guess can be tested against: the user name, the credential's length, and a
  handle under a key the process made at startup and never writes down. The one
  refusal it will not replace is an outage, because an operator working an
  incident must be told the equipment is unreachable rather than handed a device
  that is not there. An `ssh` listener does the same one port down, against a
  different list: what scans port 22 is not device defaults but the account names
  an estate uses -- `git`, `jenkins`, `postgres`, `deploy` -- so the list itself is
  the finding. A key is recorded by fingerprint and then *refused*, so the client
  falls back to a password as it would against a server that trusts no keys; on a
  real bastion the section adds no authentication method the listener did not
  already offer, because a key-only bastion that started asking for passwords would
  have had its front door changed by a logging feature; and the protocol's partial
  success is not a refusal, so a right first factor is still asked for its second
  rather than handed a shell
- **A device inventory built from traffic, not from scanning.** An
  operational estate's oldest problem is that nobody knows what is on the
  network: the drawings are from commissioning, the spreadsheet was
  abandoned, and the one thing nobody may do is run a scanner, because an
  active scan is how a programmable controller gets knocked over. A
  security proxy is an unusually good place to solve that, since it
  already parses the protocols — so the DHCP relay contributes the one
  message where a device states its own hardware address, vendor class and
  name; Modbus and IEC 104 contribute unit identifiers, common addresses
  and, above all, *which side answered*; SNMP the object identifiers asked
  for (**not** their values — the parser keeps none by design, and
  changing a hot security parser to carry a string the device chose anyway
  would be a poor trade); MQTT the client identifier; TFTP the filename,
  which on a boot segment is often the only thing that names a device at
  all. Behaviour outweighs self-description, because a vendor class is a
  string and answering function 3 on unit 1 is most of the way to being a
  controller, so every guess carries a confidence and the evidence that
  produced it — an inventory an engineer cannot argue with is one whose
  wrong entries survive for years. Each role carries its Purdue level, so
  a segmentation review can ask what is on this wire that does not belong
  at this level. Freeze it with `xproxyctl assets baseline` and everything
  that appears afterwards is a new device; list the roles the estate
  expects and a device behaving like anything else is a finding, which is
  how "there are no engineering workstations on the process network" gets
  written down. Nothing here probes, scans or connects to anything
- **The inventory matched against the vendors' own advisories.** An estate
  that cannot patch does not need to be told an advisory exists; it needs
  to know whether the version it is running is one of the affected ones,
  which today means reading a PDF per advisory against a spreadsheet
  nobody has updated. The vendors publish CSAF 2.0 now — Siemens
  ProductCERT, Schneider Electric, the CISA ICS advisories — so
  `asset_inventory.advisories` reads a directory of those documents and
  says, per device, which of them name it. The firmware comes from the
  traffic: on Modbus, the answer to a master's own Read Device
  Identification request, which is the one place in that protocol where a
  device names its vendor, product and revision, and which this relay
  reads going past and never asks for. Six answers, and five of them are
  not "affected": **an unmatched version is "not assessed", never "not
  affected"**, and it comes back with the string or the sentence that
  could not be read, because a wrong "not affected" is a device somebody
  stops looking at. Nothing fetches the documents — a relay on a process
  network dialling a vendor's website every hour is a second network
  dependency in the one place that is supposed to have none, and a
  downloader on a machine that is allowed out is where the publishers'
  signatures get verified anyway
- Shell completion for bash, zsh and fish, manual pages and a JSON
  schema of the configuration that gives editors completion and inline
  documentation
- Prometheus exposition with latency histograms and per route counters,
  Grafana dashboards and alert rules shipped with the product,
  on the socket or a hardened TCP endpoint, an in-process series buffer
  for graphs, and OpenTelemetry export of metrics, traces (W3C trace
  context propagated to upstreams) and logs
- Hot reload, graceful shutdown, systemd socket activation and notify;
  hardened unit, sysctl profile, SELinux policy, logrotate configuration,
  RPM packaging
- An in-process sandbox applied after start: Landlock rules derived from
  the configuration, a seccomp deny list, no capabilities, no new
  privileges, non dumpable; on macOS debugger denial plus the Seatbelt
  profile; its state visible in `xproxyctl sandbox`

### Extensibility and platforms

- A stable middleware interface for compiled-in filters (header
  policy, basic authentication, body rewriting, bot scoring, OpenID
  Connect), and a WebAssembly ABI that runs sandboxed modules per
  request with memory and time bounds
- Fedora is the reference platform (RPM, systemd, SELinux); macOS is
  supported with launchd jobs, a Seatbelt profile, a pf anchor and an
  installer, cross compiled by the same build

## The configuration surface

One file describes the estate; every daemon validates all of it and
binds only its own listeners. These are the top-level sections, each
with the one line that says what it is for.
[docs/CONFIG.md](docs/CONFIG.md) documents every key with its default,
and the shipped JSON schema gives an editor completion and inline
documentation for the same thing.

| Section | What it holds |
|---------|---------------|
| `version` | The schema version. `1` |
| `includes` | Globs of fragment files whose `upstreams`, `routes`, `rate_limits` and `filters` are appended in lexical order, so an estate shares what it agrees on |
| `server` | Listeners — their kind, address, TLS and per-protocol section — with the global limits, the request normalisation guard, the error pages and the session ticket policy |
| `management` | The local control socket that `xproxyctl`, the terminal UI and the web GUI speak to, with kernel-verified caller identity |
| `logging` | The four JSON streams (access, error, security, audit) and where they go: files, journald, syslog, OTLP, a SIEM, with per-stream redaction |
| `trusted_proxies` | Whose `X-Forwarded-For` is believed and whose PROXY protocol header is parsed. Empty means never |
| `rate_limits` | Named policies keyed by address, network, route, endpoint, country, fingerprint, header, cookie, token claim or device, local or cluster wide |
| `upstreams` | Endpoint pools: balancing, health checks, outlier ejection, retries and budgets, hedging, circuit breaking, affinity, discovery, TLS and origin signatures |
| `routes` | What matches and what happens: the action, the filters, caching, CORS, ranges, honeypots, deception, mirroring, WebSocket inspection and a DoH endpoint |
| `bans` | Escalating temporary bans, dropped at accept, persisted and shared, with the triggers that place them |
| `threat_intel` | Imported lists of addresses, fingerprints, names, URLs and payload digests -- from a file, a URL, a TAXII 2.1 collection or a MISP instance -- refreshed on their own, with an action each and routes that can be exempt |
| `waf` | Coraza with the bundled Core Rule Set: profiles per route, learning mode, anomaly scoring, per-rule confidence and JSON body schemas |
| `cluster` | Peers on other machines over mutual TLS, or the sibling daemons of one host over a Unix socket, sharing limits, bans, marks and ticket keys |
| `virtual_patches` | Published vulnerabilities blocked by request shape, with counters and an expiry |
| `security_txt` | A virtual `/.well-known/security.txt` per host |
| `scim` | A SCIM 2.0 provisioning endpoint for the second-factor enrolments and API keys this proxy holds |
| `honeytokens` | Planted credentials that trip the moment one is used |
| `handshake` | Refusing a client inside the ClientHello — by ban list or fingerprint — before a key exchange is spent on it |
| `degradation` | Serving a suspect client correctly but slowly, instead of handing a scanner a refusal to tune against |
| `capture` | pcapng capture of the exchanges the proxy handled, by rule, for a bounded window |
| `fleet` | The agent that long polls a controller for configuration bundles, applies them through the ordinary reload and reports status |
| `api_inventory` | The endpoints discovered from traffic, with shadow, zombie and superseded ones named against OpenAPI descriptions |
| `shedding` | Load shedding by priority class from upstream latency and in-flight load |
| `maintenance` | A window, the clients exempt from it and the page it serves |
| `challenge` | The proof-of-work page, its cookie and the CAPTCHA tier above it |
| `jwt` | Token providers: JWKS with rotation, algorithm allow lists, claims, introspection, DPoP and certificate binding |
| `metrics` | Prometheus exposition on the socket or a hardened TCP endpoint, per-route series and the in-process buffer the graphs read |
| `icap` | External scanning services and what a failure means |
| `filters` | Named request and response filters, by kind — the table below |
| `geoip` | The MaxMind or CSV database behind country policy and the `country` rate limit key |
| `ingress` | Kubernetes ingress controller mode: the class, the API server and the watches |
| `sandbox` | The in-process sandbox applied after start: Landlock rules, the seccomp deny list, capabilities |
| `cache` | The response cache: sizes, TTLs and the per-route key policy |
| `compression` | gzip, brotli and zstd of eligible responses, negotiated with the client |
| `tracing` | W3C trace context and span export, with the sampling and redaction |
| `acme` | Certificate issuance and renewal, and where the account and keys live |

Filters are the per-route extension surface. Each is named in `filters`
and referenced by routes, in the order the route lists them:

| Filter | What it does |
|--------|--------------|
| `header_guard` | Required and denied request headers, and the security headers on the way back |
| `basic_auth` | HTTP Basic against a file of PBKDF2 hashes, with the user forwarded |
| `mfa` | A second factor in front of a web application, from the same TOTP enrolment file the gateways use. The gateways can also take the factor as an approval on a device (`mfa.push`) instead of a typed code |
| `yara` | YARA rules over request and response bodies, per file rather than per stream |
| `ldap_auth` | A directory bind, in bind or search-then-bind mode, with a group requirement |
| `oidc` | OpenID Connect login with sealed session cookies, required claims and logout |
| `saml_sp` | SAML 2.0 single sign-on as a service provider, in a deliberately narrow profile |
| `xml_guard` | XML and SOAP bodies bounded — entities, expansion, nesting — with schema validation where there is a schema |
| `wasm` | A sandboxed WebAssembly module per request, with memory and time bounds |
| `bot_score` | Fingerprints, header consistency and behaviour into a score that logs, challenges or denies |
| `form_guard` | Hidden-field and timing honeypots on forms |
| `account_guard` | Credential stuffing, brute force, registration, reset, hoarding and scraping, with campaign detection |
| `api_abuse` | What one identity does with an API over a window: distinct objects, consecutive identifiers, the share refused |
| `flow` | The **order** of a business flow: a payment reached without the cart is three valid requests and one wrong sequence |
| `api_key` | API keys with scopes and a lifecycle |
| `openapi` | An OpenAPI description used as an allow list, read from a file or a URL and re-read when it changes |
| `graphql` | Depth, breadth, complexity and introspection bounds, per operation |
| `upload_guard` | Multipart uploads: extension chains, content against the declared type, executables and web shells, counts and sizes |
| `authz` | What an authenticated subject may do: default deny, first match wins, nothing a client sent reaches a rule |
| `grpc_guard` | gRPC framing, message bounds and protobuf structure, without a schema |
| `sensitive_data` | Cards, identity numbers, IBANs, tokens and keys in either direction: logged, masked or blocked |
| `body_rewrite` | Literal and regular expression rewriting of request and response bodies |

## Setup

### Install

**From source.** Go 1.26 or newer, no cgo, no C toolchain:

```sh
make build      # bin/{xproxy,xgate,xrelay,xproxyctl,xproxy-admin,xproxy-fleet,xproxy-replay,xsigner}, static and stripped
make check      # fmt, vet, race tests, lint — what CI runs
sudo make install                 # PREFIX=/usr/local: binaries, units, man pages,
                                  # completions, the JSON schema, Grafana and Prometheus assets
```

**From RPM on Fedora**, which is the reference platform. Six packages
come out of `make rpm`, one per thing you can choose to run: `xproxy`
(the edge daemon, `xproxyctl`, four units, the sysctl profile, logrotate,
sysusers and tmpfiles entries, dashboards and alert rules),
`xproxy-xgate`, `xproxy-xrelay`, `xproxy-admin` (the web GUI and its
polkit rule), `xproxy-fleet` (the controller for a fleet's management
host) and `xproxy-selinux` (the policy module, loaded and relabelled on
install). Installing only the base package gives an edge-only host,
which is the common case; a bastion host adds `xproxy-xgate`, a plant
relay adds `xproxy-xrelay`. [docs/SETUP.md](docs/SETUP.md) has the
commands, the users and directories the packages create, and the upgrade
path.

**On macOS**, cross compiled by the same build: `make install-macos`
runs the installer from `deploy/macos/`, which places the binaries,
launchd jobs, a Seatbelt profile, a pf anchor and a newsyslog
configuration. `make dist-darwin` builds the arm64 and amd64 tarballs
(the edge daemon, the control tool, the GUI and the fleet controller).
See [docs/SETUP_MACOS.md](docs/SETUP_MACOS.md) and
[docs/HARDENING_MACOS.md](docs/HARDENING_MACOS.md).

**As a container.** `deploy/kubernetes/Containerfile` builds a `scratch`
image carrying `xproxy` and `xproxyctl` and nothing else, running as an
unprivileged user id, with a manifest beside it.

### Run

Each daemon takes four flags and no more: `-config` (the file),
`-validate` (check and exit, whole file, advice included), `-version`
and `-allow-root` (which the shipped units do not need — a daemon
refuses to start as uid 0 without it).

The units run each daemon as its own unprivileged user, with socket
activation for the privileged ports, so nothing needs
`CAP_NET_BIND_SERVICE` and nothing runs as root:

| Unit | Sockets |
|------|---------|
| `xproxy.service` | `xproxy.socket` (TCP 80), `xproxy-https.socket` (TCP 443), `xproxy-h3.socket` (UDP 443) |
| `xgate.service` | `xgate.socket` (TCP 22 — read the note in the unit before enabling it) |
| `xrelay.service` | `xrelay.socket` (TCP 25); copy it per listener — `ListenStream` for Modbus on 502 or NTS key establishment on 4460, `ListenDatagram` for the time gateway on UDP 123 |
| `xproxy-admin.service` | the web GUI |
| `xproxy-fleet.service` | the fleet controller |

`Type=notify-reload` with `SIGHUP`, so `systemctl reload` waits for the
new generation to be live. The socket stays open across a restart or an
upgrade, so no connection is refused. Also shipped: a sysctl profile, a
logrotate configuration per daemon calling `xproxyctl reopen-logs`, the
sysusers and tmpfiles entries that create the users and the two shared
directories, an SELinux policy module, and a polkit rule that lets the
GUI restart the data plane. After start each daemon
sandboxes itself — Landlock rules derived from the configuration, a
seccomp deny list, no capabilities, no new privileges, not dumpable —
and `xproxyctl sandbox` says what took effect.

### Configure

One YAML file, or a file plus a directory of fragments:

```yaml
version: 1
includes: [/etc/xproxy/conf.d/*.yaml]   # upstreams, routes, rate_limits, filters
server:
  listeners:
    - {name: main, address: "0.0.0.0:80"}
```

Every daemon validates the whole file, including the listeners its
siblings will bind, and says how much of it is its own — so one set of
includes describes the estate rather than three drifting copies.
Validation is a hard gate for what cannot work and an advice channel for
what merely weakens the deployment: both are printed by `-validate` and
written to the security log at every start.

```sh
xproxy -config /etc/xproxy/xproxy.yaml -validate   # or xgate, or xrelay
xproxyctl reload -dry-run                          # build the generation without swapping it in
xproxyctl diff                                     # file against what is running
xproxyctl reload                                   # atomic swap, no connection dropped
xproxyctl history && xproxyctl rollback            # previous generations, and back to one
```

A reload builds a new immutable generation and swaps it in atomically;
listeners can be added and removed without a restart, and what does need
one is named in [docs/CONFIG.md](docs/CONFIG.md)'s reload semantics.
Editors get completion and inline documentation from the shipped JSON
schema (`xproxyctl schema`), and there are man pages for each daemon,
for `xproxyctl` and for the configuration format itself
(`xproxy.yaml(5)`).

## Deployment shapes

Every shape below is a configuration of the same three binaries, with a
complete example in [examples/](examples/).

| Shape | What it is | Where to start |
|-------|------------|----------------|
| Reverse proxy | One `xproxy` in front of applications: TLS, routes, pools, the WAF, the ban list | `examples/routing/`, `examples/waf/` |
| Three daemons on one host | The edge, the bastion and the relay side by side — a file each for what only one process can own, one include for what they agree on, and a Unix socket cluster so an address the bastion refuses is refused at the edge too | `examples/estate/` |
| A cluster of machines | Every node dials every peer over mutual TLS; no leader. Rate limit consumption, bans, honeypot marks and session ticket keys are shared, and a limit can be made exact cluster wide with one owner per key | `cluster:` in [docs/CONFIG.md](docs/CONFIG.md) |
| A fleet | `xproxy-fleet` holds the configuration bundles; each node long polls for its own, applies it through the ordinary reload (validated, sandbox checked, rolled back on refusal) and reports status. The controller never connects to a node | `examples/fleet/` |
| Kubernetes ingress | Ingress and Gateway API resources of one class become routes, upstreams and certificates, watched and applied within a second; the file's own routes are kept | `deploy/kubernetes/`, `ingress:` |
| Behind another proxy | PROXY protocol v1 and v2 from trusted peers, `trusted_proxies` for forwarded addresses, and the same limits, bans and logs keyed on the real client | `proxy_protocol`, `trusted_proxies` |
| Transparent interception | The network does the redirecting: `IP_TRANSPARENT` with the original destination read from the socket, so a layer 4 listener can front traffic that was never addressed to it | `examples/layer4/` |
| Explicit egress proxy | CONNECT, SOCKS5 and MASQUE on one port with a destination policy, credentials and optional TLS interception of the tunnel | `examples/forward/` |
| Bastion host | `xgate` with the SSH, telnet, VNC and RDP gateways, each recorded, each able to demand a second factor, none of them handing the client's credential to the target | `examples/bastion/`, `examples/mfa/` |
| Machine-to-machine relay | `xrelay` in front of what cannot be patched or reached directly: mail submission, an MQTT fleet, an FTP intake, a syslog collector, a Modbus line, a time service | `examples/mail/`, `examples/iot/`, `examples/files/`, `examples/logs/`, `examples/ot/` |
| Encrypted DNS resolver | One certificate serving DoT, DoH and DoQ, advertising itself through RFC 9462 discovery, with DNSSEC, block lists, response policy zones and tunnelling detection | `examples/blocklists/` |

[examples/](examples/) is the full set, each file validated by a test
that runs on every build: a three daemon estate with a shared ban list, a
submission proxy, an MQTT fleet, an FTP intake, a syslog relay, a Modbus
policy in front of a production line, an NTP and NTS time gateway, an SSH
bastion with RDP, VNC and telnet gateways beside it, an encrypted
resolver, an egress proxy with SOCKS5 and MASQUE, WAF rule sets, YARA
rules, honeypots, filters and rewriting.
[docs/USAGE.md](docs/USAGE.md) has a worked example of every feature;
[docs/SETUP.md](docs/SETUP.md) covers the RPM, the units, SELinux and the
web GUI.

Two things are worth saying plainly about the operational-technology
shapes. A relay in front of equipment is a policy point, not an air gap:
it reads every frame and refuses in the protocol's own terms, and that is
the whole of what it claims. And a one-way data diode cannot carry NTP or
any other request-and-response protocol at all — time needs the round
trip — so the time gateway belongs beside its consumers, not behind a
diode.

[examples/ot/packs/](examples/ot/packs/README.md) is a smaller set with a
narrower claim: six configurations written against what a named piece of
ICS tooling did -- Industroyer on IEC 104 and on MMS, FrostyGoop on
Modbus, PIPEDREAM's Modicon and OPC UA modules, and the block writes a
Stuxnet-shaped payload makes to an S7 -- so that an estate that has
nothing else can start from something. None of them is a signature: every
rule is a statement about what this plant does, the addresses in each
file have to be replaced with the plant's own, and each pack has a test
that loads the file as it ships and sends the traffic through the relay,
which is how the claim in its name is checked rather than asserted.

[packs/](packs/README.md) is the other half of that idea, and the shape an
estate can actually keep up to date: twenty-five **behaviour packs** as signed,
versioned data rather than as configurations to copy. Ten are written per ATT&CK
for ICS technique, six per named piece of malware and nine per tool, and each
says that a shape of events from one actor inside one window is one technique.
A pack notices; the configurations above refuse — and a pack is a file, so it can
arrive next quarter without a new binary and without touching a policy somebody
has already tuned. Each has a replay trace in `packs/testdata` that the test
suite runs on every build, and a pack may only name a technique and a refusal
reason this build already has, so none of them can claim a detection the binary
cannot make.

## Operating it

`xproxyctl` talks to the management socket, whose caller identity the
kernel verifies, and everything it shows is also a JSON endpoint for a
script:

| Area | Commands |
|------|----------|
| State | `status`, `stats`, `upstreams`, `quotas` (per tenant, route and policy), `cluster`, `fleet`, `sandbox`, `series`, `metrics`, `otlp`, `telemetry` |
| Configuration | `validate`, `config`, `reload` (with `-dry-run`), `diff`, `history`, `rollback`, `schema`, `completion` |
| Certificates and keys | `tls`, `reload-certs`, `acme`, `spki`, `ech`, `rotate-secret`, `origin-check` |
| Defence | `bans`, `ban`, `unban`, `waf`, `botscore`, `accounts`, `patches`, `honeypot`, `filters`, `api` |
| Traffic | `drain`, `maintenance`, `cache`, `dns`, `ingress`, `icap`, `geoip` |
| Identity | `mfa`, `apikey`, `htpasswd` |
| Policy rollout | `policy report` — what every listener in shadow mode would have refused, most frequent first, with the rule that decided and an example of what was asked for; `policy reset` empties the ledger once the policy is fixed |
| Live sessions | `sessions` — who is on now across SSH, SFTP, telnet, VNC, RDP, FTP and the Modbus device queues, with the login, the target and how long; `-kill ID` closes one and `-kill-matching` closes a set by kind, listener or person (audited, and a filter that names nothing is refused rather than taken as everything) |
| Records | `tail`, `session` (list, show, play), `capture` (start, stop, status), `reopen-logs` |
| Views | `tui` — a full screen terminal view; the web GUI is `xproxy-admin`, with viewer and operator roles, validated configuration editing, graphs and live logs |
| Recordings | `xproxy-replay` reads a session file and shows it: a terminal session replayed with its timing, a VNC one decoded into frames or one self-contained page, an RDP one as the timeline of what it did. It needs no daemon and opens no sockets |

Four JSON log streams (access, error, security, audit) go to files,
journald or syslog with per-stream redaction; a request identifier ties
a line to the upstream request and back. Prometheus exposition,
Grafana dashboards and Prometheus alert rules are shipped with the
product, and OpenTelemetry export covers metrics, traces and logs.
[docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) has a symptom index,
the stages a request can die at and every deny reason.

## Documentation

| Document | Content |
|----------|---------|
| [docs/USAGE.md](docs/USAGE.md) | Operating the proxy: an example per feature, the control tool, logging |
| [docs/CONFIG.md](docs/CONFIG.md) | Configuration reference, every key with its default |
| [docs/RFC.md](docs/RFC.md) | Every standard this proxy implements, in part or not at all: what is full, what is a named subset, and what is deliberately refused — because a proxy that quietly ignores a feature reads a message differently from the peer behind it |
| [docs/DECEPTION.md](docs/DECEPTION.md) | Honeypot routes, decoys, honeytokens, form honeypots, WAF shape rules, the slow lane, deceptive answers and handshake refusal as one family: what each costs an attacker, how the signals chain, and the order to build them in |
| [docs/ATTACK.md](docs/ATTACK.md) | What each refusal and detection means in MITRE ATT&CK terms -- ATT&CK for ICS on the plant, Enterprise ATT&CK above it, and both where one refusal is read by two teams: the techniques this proxy can observe in each matrix, which reason maps to which, where the identifiers appear (log, snapshot, metrics), and why protocol hygiene is deliberately left untagged |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Triage, a symptom index, the stages a request can die at, the timeout ladder, a section per subsystem, emergency procedures, every deny reason and what to collect for a bug report |
| [docs/SETUP.md](docs/SETUP.md) | Installation on Fedora |
| [docs/SETUP_MACOS.md](docs/SETUP_MACOS.md) | Installation on macOS |
| [packs/](packs/README.md) | The behaviour packs that ship with the product: signed, versioned detection documents, ten per ATT&CK for ICS technique, six per named piece of malware and nine per tool, with what each one is a detection for and why most of them may only alert |
| [examples/](examples/) | Complete configurations per deployment — the estate's daemons, the bastion, the mail and IoT relays, the operational-technology gateways, the encrypted resolver, the egress proxy — with WAF rules, block lists, filters, a WebAssembly module and rewriting examples beside them, all validated by tests |
| [docs/HARDENING_MACOS.md](docs/HARDENING_MACOS.md) | Host hardening on macOS |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | The split into four daemons, the kind registry and the roster, components, request path, data flows |
| [docs/SECURITY.md](docs/SECURITY.md) | Security posture, controls, secure development, reporting |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | STRIDE analysis per trust boundary |
| [docs/HARDENING.md](docs/HARDENING.md) | Host hardening checklist |
| [docs/HA.md](docs/HA.md) | Redundancy and failover: the readiness verdict a VRRP check script runs, stepping a node down before touching it, which state survives a failover and which does not, and what each daemon costs when an address moves |
| [docs/EXTENDING.md](docs/EXTENDING.md) | Compiled-in middleware and the WebAssembly ABI |
| [docs/SIGNER.md](docs/SIGNER.md) | The signer protocol: how a process that holds a private key answers a proxy that needs a signature, what a helper must check and must never do, why the socket's permissions are the authentication — and how to write a helper for an HSM, a TPM or a KMS this project does not support |
| [docs/PERFORMANCE.md](docs/PERFORMANCE.md) | Measured scale and throughput |
| [docs/TESTS.md](docs/TESTS.md) | Test harness, coverage and mutation gates |
| [docs/ASR.md](docs/ASR.md) | Architecturally significant requirements with traceability |
| [docs/AMR.md](docs/AMR.md) | Architecture decision records and the dependency list |
| [docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md) | Findings of the 1.0 security review |
| [docs/RELEASE_NOTES_1.0.md](docs/RELEASE_NOTES_1.0.md) | What 1.0.0 contains and does not claim |
| [docs/RELEASING.md](docs/RELEASING.md) | Release procedure: verify, tag, build, sign, publish |
| [docs/ROADMAP.md](docs/ROADMAP.md) | What each version delivered and what follows |
| [docs/CHANGELOG.md](docs/CHANGELOG.md) | Notable changes per version |

## Development

```sh
make check          # fmt, vet, race tests, lint
make cover-gate     # coverage under race with the 80 % gate
make mutate         # mutation testing on the admission packages
make fuzz           # all fuzz targets, 20s each
make rpm            # Fedora package with the SELinux policy
make build-darwin   # macOS binaries (arm64 and amd64), see docs/SETUP_MACOS.md
```

Go 1.26 or newer. No cgo. Dependencies are few, listed and justified in
[docs/AMR.md](docs/AMR.md) (AMR-004): the YAML parser, the Coraza WAF
engine with the Core Rule Set, bbolt for ban state, quic-go for HTTP/3,
wazero for WebAssembly, and `golang.org/x/crypto` for the SSH bastion.

Everything else is written here rather than pulled in, and the reason is
usually the same. The DNS, SMTP, MQTT, FTP, syslog, SFTP, Modbus, NTP,
RFB, RDP, NTLM, telnet and MASQUE parsers, the AES-CMAC and TOTP
implementations and the YARA engine are all first-party: a protocol this
proxy *decides* is a protocol it has to read the same way twice, and
linking libyara alone would have meant `CGO_ENABLED=1` and a C parser in
the data plane.

## Licence

Xproxy is proprietary, commercially licensed software. Copyright (c) 2026
Sysctl AB. All rights reserved. See [LICENSE](LICENSE). Third party
components keep their own licences, listed in [docs/AMR.md](docs/AMR.md).
