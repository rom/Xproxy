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

It is not one binary but three, split by who is on the other end of the
socket: **xproxy** faces the internet, **xgate** faces people, **xrelay**
faces machines. They share one repository, one configuration format and
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
- [How it works](#how-it-works) — listeners, the pipeline, the three daemons
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
| `xrelay` | machines and equipment | `smtp`, `mqtt`, `ftp`, `syslog`, `modbus`, `iec104`, `snmp`, `ldap`, `tftp`, `dhcp`, `postgres`, `mysql`, `tds`, `redis`, `bacnet`, `amqp`, `s7`, `ntp`, `ntske` |

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
| HTTP | HTTP/1.1, HTTP/2 (ALPN or `h2c`), HTTP/3 over QUIC v1; extended CONNECT; WebSocket (RFC 6455) with permessage-deflate; WebTransport over HTTP/3; gRPC and gRPC-web; Early Hints, trailers, ranges and priority signals | `http` |
| TLS | 1.2 and 1.3, SNI, ALPN, mutual TLS in both directions, SPKI pinning, session tickets with rotating keys, OCSP stapling, Certificate Transparency, ACME (HTTP-01 and TLS-ALPN-01), Encrypted Client Hello, the `X25519MLKEM768` hybrid key exchange, JA3 and JA4 fingerprints | every TLS listener |
| Layer 4 | TLS and QUIC passthrough routed by server name; any datagram protocol; PROXY protocol v1 and v2, read and written; `IP_TRANSPARENT` with the original destination read from the socket | `tcp`, `udp` |
| DNS | UDP, TCP, DoT (RFC 7858), DoH (RFC 8484) and DoQ (RFC 9250); DNSSEC validation with aggressive NSEC and NSEC3 caching (RFC 8198); response policy zones; DNS64 (RFC 6147); designated-resolver discovery (RFC 9462); SVCB and HTTPS records (RFC 9460); DNS cookies; EDNS client subnet policy | `dns` |
| Forward and tunnelling | HTTP CONNECT, SOCKS5 (RFC 1928, 1929, 1961) with UDP associations, CONNECT-UDP (RFC 9298), CONNECT-IP (RFC 9484), and TLS interception inside a tunnel | `forward` |
| Mail | SMTP (RFC 5321) and submission (RFC 6409), STARTTLS (RFC 3207), implicit TLS (RFC 8314), `SIZE`, `AUTH`, enhanced status codes, and Postfix's `XCLIENT` so the mail server still sees the real client | `smtp` |
| Messaging | MQTT 3.1.1 (also ISO/IEC 20922) and MQTT 5.0 | `mqtt` |
| File transfer | FTP and FTPS (`AUTH TLS`) with the data connection mediated at both ends; SFTP version 3 inside the SSH subsystem channel | `ftp`, `ssh` |
| Logging | Syslog RFC 5424 and RFC 3164 over UDP, TCP (RFC 6587 framing) and TLS, re-emitted in one dialect | `syslog` |
| Time | NTP v1 to v4 (RFC 5905), SNTP (RFC 4330), extension fields (RFC 7822), AES-CMAC authentication (RFC 8573), NTS (RFC 8915) passed through whole, and NTS key establishment relayed on TCP 4460 | `ntp`, `ntske` |
| Industrial | Modbus/TCP (MBAP), Modbus over Serial Line RTU and ASCII tunnelled over TCP, and Modbus/TCP Security with the role in the client certificate | `modbus` |
| Telecontrol | IEC 60870-5-104 (APCI/APDU, the I, S and U formats, the type identifications and causes of transmission of IEC 60870-5-101), with IEC 62351-3 TLS | `iec104` |
| Building automation | BACnet/IP (ASHRAE 135 Annex J): the BVLC functions, the network layer of clause 6 with its routing and security messages, the application layer of clause 20 with the confirmed and unconfirmed services, and the object, property and command priority each request names | `bacnet` |
| Industrial control | Siemens S7comm on TCP 102: TPKT (RFC 1006), COTP (X.224 class 0, whose connection request addresses a CPU by rack and slot), and the S7 layer -- the function codes for memory, blocks and the control service, and the user-data groups for the diagnostic buffer, the clock, the password and the debugger | `s7` |
| Messaging | AMQP 0-9-1 (the class and method catalogue RabbitMQ speaks) and AMQP 1.0 (ISO/IEC 19464: the nine performatives, its self-describing type system, and the SASL layer), read on one port because a client picks which of the two it speaks in its first eight octets | `amqp` |
| Management | SNMP v1 (RFC 1157), v2c (RFC 1901–1908) and v3 with USM (RFC 3410–3418), over UDP and over TCP (RFC 3430), with RFC 6353 TLS on the stream side | `snmp` |
| Directory | LDAP v3 (RFC 4511–4515, 4517, 4519) with LDAPS and the StartTLS of RFC 4513, as a relay: the bind methods, the search filter's shape, distinguished names compared per relative name, the attribute lists in both directions | `ldap`, filters |
| Addressing | DHCP (RFC 2131) with its options (RFC 2132), relay agent information (RFC 3046), long options (RFC 3396) and classless static routes (RFC 3442), as a relay agent that reads what it relays: the server a reply came from, and the configuration the reply carries | `dhcp` |
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
| `dns` | `xproxy` | DNS over UDP, TCP, TLS, HTTPS, QUIC | Names, answers, response policy zones, tunnelling |
| `ssh` | `xgate` | SSH and SFTP | Channels, commands, forwards, paths, file operations; recording, MFA |
| `telnet` | `xgate` | Telnet (RFC 854 NVT) | Options in both directions; recording, MFA |
| `vnc` | `xgate` | RFB 3.3–3.8, VeNCrypt, vendor security types | Security type, whose credential opens the desktop, view-only, the picture's bounds; recording, MFA |
| `rdp` | `xgate` | RDP over TLS, NLA, or the protocol's own encryption | Channels, devices, the connection sequence; recording, MFA |
| `smtp` | `xrelay` | SMTP and submission | Commands, where a message ends, TLS and authentication, bounds |
| `mqtt` | `xrelay` | MQTT 3.1.1 and 5.0 | Topics and filters, client identifiers, retained messages, wills |
| `ftp` | `xrelay` | FTP and FTPS | Commands, paths, extensions, and the data connection itself |
| `syslog` | `xrelay` | RFC 5424 and RFC 3164 over UDP, TCP, TLS | Facility, severity, sender, the text; re-emitted in one dialect |
| `modbus` | `xrelay` | Modbus/TCP, RTU and ASCII, Modbus/TCP Security | Unit identifiers, function codes, register ranges, values, roles, schedules |
| `iec104` | `xrelay` | IEC 60870-5-104, IEC 62351-3 TLS | Type identifications, causes of transmission, common and originator addresses, information object ranges, select-before-operate, schedules |
| `snmp` | `xrelay` | SNMP v1, v2c and v3 (USM), UDP and TCP, RFC 6353 TLS | Versions, community strings and USM users, security levels, operations, object subtrees, the amplification bounds |
| `ldap` | `xrelay` | LDAP v3, LDAPS, StartTLS | Bind methods, the bound identity, operations, naming contexts and subtrees, scopes, attributes in both directions, filter and entry bounds |
| `dhcp` | `xrelay` | DHCPv4 with RFC 2132 options, RFC 3046 relay agent information, RFC 3442 routes | The server a reply came from, the options and addresses a reply may carry, the boot file, the lease bounds, the hardware-address rate |
| `postgres` | `xrelay` | PostgreSQL protocol v3, both query protocols, the cleartext TLS negotiation | Whether the connection may be unencrypted at all, which role and database may be claimed, which authentication methods may cross, which *shapes* of statement are allowed, replication, the fast-path call, cancel requests |
| `mysql` | `xrelay` | MySQL and MariaDB protocol, handshake v10, the capability flags, the command set | The capability bits a client may even see offered, which of the protocol's commands may cross, whether the connection may be unencrypted, which user and database may be claimed (re-checked on COM_CHANGE_USER), which authentication plugins, which statement shapes, LOAD DATA in either form |
| `tds` | `xrelay` | TDS 7.x for SQL Server: the PRELOGIN negotiation, LOGIN7, SQLBATCH and RPC, and the TLS handshake carried inside TDS packets | Whether the connection may be unencrypted at all -- and the relay answers the negotiation itself rather than forwarding the server's octet -- whether a password may cross in the clear, which login, database and application name may be claimed, whether a login carrying no user name is admitted, which message types, which stored procedures, and which statement shapes, applied to a batch and to the SQL inside an sp_executesql alike |
| `redis` | `xrelay` | RESP2 and RESP3, multibulk and inline, with a table of where each command's keys are | Whether the connection may be unencrypted, whether a command may arrive before the connection has authenticated -- with the answer taken from the server's reply -- which ACL user may be named, which commands and subcommands may cross, which keys by prefix, which numbered databases, and whether anything may write |
| `amqp` | `xrelay` | AMQP 0-9-1 and AMQP 1.0: the frame layer of each, the 0-9-1 method catalogue with its arguments and field tables, the 1.0 performatives over its type system, and the SASL exchange of both | Which of the two versions may be spoken; which SASL mechanisms and which identities; which virtual host; whether the broker's own *topology* may be changed at all, which is off by default; which exchanges, queues, routing keys and link addresses a connection may name -- including the dead-letter exchange of a queue, the alternate exchange of an exchange and the reply-to inside a message, which a policy written against the obvious fields would miss; whether every message must say who published it; and the frame, channel, link and message bounds |
| `s7` | `xrelay` | Siemens S7comm: the TPKT framing, the COTP connection request with the rack and slot it addresses, and the S7 layer -- function codes, user-data groups and subfunctions, and the item specifications of a read or a write | Which controller a client may reach, decided from the connection request *before the PLC is dialled*, and as what -- an operator panel, an engineering station or another PLC; which of nineteen operations it may ask for, where the default is what an HMI does and an upload is off with the writes because a block read is how control logic leaves a site; `read_only` as one line no rule can override; which memory areas, data blocks and byte ranges a request may name, checked against the whole span rather than its first byte; the block types an upload or a download may name; and the item, octet, PDU-length and connection bounds, because a CPU has sixteen connection resources altogether |
| `tftp` | `xrelay` | TFTP with RFC 2347–2349 options and RFC 7440 windows | The client list, the direction, the transfer mode, the filename read as a path and refused by class, the directories, and the block, window and transfer bounds |
| `bacnet` | `xrelay` | BACnet/IP: the BVLC functions, the network layer, the confirmed and unconfirmed services, and where each service keeps its object | Which addresses may speak to the building at all -- the only identity the protocol has -- which services may be sent, which objects and properties they may name, and at which *command priority*, so nobody takes a piece of plant at a life safety slot the management system cannot override; whether a broadcast is carried and how many answers it may bring back; whether foreign-device registration with the estate's broadcast management is carried at all |
| `ntp` | `xrelay` | NTP v1–v4, SNTP, NTS-protected NTP | Versions, modes, extension fields, authentication, and whether the servers agree |
| `ntske` | `xrelay` | NTS key establishment (TLS on 4460) | The application protocol, the server name, the handshakes in flight |

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
  the maintenance window. Refusals are the protocol's own exceptions, so
  the master carries on and its diagnostics say something true.
  **Modbus/TCP Security** for the devices that have it: TLS with mutual
  authentication and the role in the client certificate. And **learning
  mode**, because nobody knows what a plant's Modbus traffic is — run it
  for a week and the file it writes is the rule set to start from

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
  operation into a refusal. The **sequence numbering** is checked in both
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
  operation. The **amplification is bounded in two directions**: a
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
  worse than either refusing or forwarding

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
  address would see one sender doing nothing unusual. DHCPv6 is a different
  protocol and is not pretended to be this one

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
  nothing can be redirected without. **Whose credential opens the
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

### The estate: clusters, fleets and Kubernetes

- A **cluster** in either of two shapes. Networked: every node dials
  every peer over mutual TLS, with no leader, sharing rate limit
  consumption, bans, honeypot marks and session ticket keys — and a
  limit that must hold exactly cluster wide is decided by one owner
  per key. Local: the three daemons of one host over a Unix socket,
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
  than a picture nobody sent
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

**From source.** Go 1.25 or newer, no cgo, no C toolchain:

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
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Triage, a symptom index, the stages a request can die at, the timeout ladder, a section per subsystem, emergency procedures, every deny reason and what to collect for a bug report |
| [docs/SETUP.md](docs/SETUP.md) | Installation on Fedora |
| [docs/SETUP_MACOS.md](docs/SETUP_MACOS.md) | Installation on macOS |
| [examples/](examples/) | Complete configurations per deployment — the three-daemon estate, the bastion, the mail and IoT relays, the operational-technology gateways, the encrypted resolver, the egress proxy — with WAF rules, block lists, filters, a WebAssembly module and rewriting examples beside them, all validated by tests |
| [docs/HARDENING_MACOS.md](docs/HARDENING_MACOS.md) | Host hardening on macOS |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | The split into three daemons, the kind registry and the roster, components, request path, data flows |
| [docs/SECURITY.md](docs/SECURITY.md) | Security posture, controls, secure development, reporting |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | STRIDE analysis per trust boundary |
| [docs/HARDENING.md](docs/HARDENING.md) | Host hardening checklist |
| [docs/HA.md](docs/HA.md) | Redundancy and failover: the readiness verdict a VRRP check script runs, stepping a node down before touching it, which state survives a failover and which does not, and what each of the three daemons costs when an address moves |
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

Go 1.25 or newer. No cgo. Dependencies are few, listed and justified in
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
