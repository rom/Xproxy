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
| `xrelay` | machines and equipment | `smtp`, `mqtt`, `ftp`, `syslog`, `modbus`, `ntp`, `ntske` |

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
| Remote access | SSH (RFC 4251–4254) with OpenSSH user and host certificates; telnet's NVT (RFC 854); RFB 3.3 to 3.8 (RFC 6143) with VeNCrypt; RDP (MS-RDPBCGR) over TLS, CredSSP over NTLMv2 towards the desktop, or the protocol's own encryption | `ssh`, `telnet`, `vnc`, `rdp` |
| Identity | OpenID Connect Core 1.0, OAuth 2.0 (RFC 6749) with introspection (RFC 7662), PKCE (RFC 7636) and token exchange (RFC 8693); JWT, JWS and JWKS (RFC 7515–7519); DPoP (RFC 9449); certificate-bound tokens (RFC 8705); SAML 2.0 as a service provider; SCIM 2.0 (RFC 7642–7644); WebAuthn level 2; LDAP (RFC 4511–4515); TOTP (RFC 6238); HTTP Basic (RFC 7617); client certificate identity as `Client-Cert` (RFC 9440) or Envoy's `X-Forwarded-Client-Cert` | filters |
| Inspection | ModSecurity SecLang with the OWASP Core Rule Set through Coraza; a documented subset of YARA; ICAP (RFC 3507); OpenAPI 3 descriptions; GraphQL; XML and XSD with exclusive canonicalization; protobuf structure without a schema; WebAssembly with WASI preview 1 | filters |
| Operations | Prometheus exposition; OpenTelemetry OTLP for traces, metrics and logs; SIEM export as NDJSON, Splunk HEC, CEF or LEEF; pcapng capture files; asciicast v2 session recordings; journald and syslog log sinks; the Consul catalogue; Kubernetes Ingress and Gateway API | the control plane |

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
  cache, honeypots, DNS, ingress, cluster, metrics, ECH keys and the
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
| `threat_intel` | Imported CIDR and JA4 lists, refreshed on disk, with an action each and routes that can be exempt |
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
| `mfa` | A second factor in front of a web application, from the same TOTP enrolment file the gateways use |
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
make build      # bin/{xproxy,xgate,xrelay,xproxyctl,xproxy-admin,xproxy-fleet,xproxy-replay}, static and stripped
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
| [docs/EXTENDING.md](docs/EXTENDING.md) | Compiled-in middleware and the WebAssembly ABI |
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
