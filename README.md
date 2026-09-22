# Xproxy

Xproxy is a security proxy that terminates protocols rather than
forwarding bytes. It is an HTTP/1.1, HTTP/2 and HTTP/3 reverse proxy
and load balancer with a web application firewall, a ban list, rate
limiting and load shedding at its core — and, around that core, the
other protocols an estate actually runs: SMTP and submission, MQTT, an
SSH bastion with SFTP inspection, DNS over UDP, TCP, TLS, HTTPS and
QUIC, SOCKS5 and MASQUE on a forward proxy, and layer 4 passthrough
where terminating would be wrong.

It is one static Go binary with no cgo, runs unprivileged under a
hardened systemd unit confined by SELinux, and is managed over a local
socket from a CLI, a terminal UI and a web GUI.

Status: 1.4 in development on top of the **1.0.0** release
([release notes](docs/RELEASE_NOTES_1.0.md), [how a release is
cut](docs/RELEASING.md)). [docs/ROADMAP.md](docs/ROADMAP.md) lists what
each version delivered and what is planned;
[docs/CHANGELOG.md](docs/CHANGELOG.md) has the details.

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

```
client ──▶ listener (accept limits, bans) ──▶ admission pipeline ──▶ route action ──▶ upstream pool
       http | tcp | forward | dns | smtp        concurrency, host and       proxy, redirect,      balancer, health,
                | mqtt | ssh                    path checks, route match,   respond, honeypot,    ejection, retries,
                                                country, ACL, challenge,    static files          affinity, mirror
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

## Feature set

**Termination and transport**

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

**Routing and upstreams**

- Routes by host (exact or wildcard), path prefix or regular
  expression, method, header and cookie conditions, priority and gRPC
  service or method; redirects, static responses, path rewriting,
  header operations, per route timeouts and body limits
- Upstream pools with round robin, weighted, least connections and
  consistent hashing; active HTTP or gRPC health checks, passive outlier
  ejection, a circuit breaker with half open probing, concurrency
  limits with a bounded queue, retries on connection errors and chosen
  statuses, signed cookie affinity, canary endpoints selected by header,
  cookie or share
- Response caching with per route key policies, `Vary` and conditional
  requests; gzip, brotli and zstd compression of eligible responses,
  negotiated with the client; request mirroring
  of sampled traffic to a candidate upstream, bounded and invisible to
  clients
- Static file serving from a directory with index files, listings and a
  single page application fallback, confined to the root
- gRPC: errors answered as gRPC statuses, `grpc-timeout` honoured,
  trailers relayed, per code counters

**Defence**

- Connection limits at accept (global and per address), concurrency
  ceiling, header, body and idle timeouts, URI and body size limits
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
- Keyed rate limits (address, network, route, endpoint, country, TLS
  fingerprint, header, cookie, token claim) with reject or tarpit; CIDR
  allow and deny lists; trusted proxy handling for forwarded addresses
- API inventory discovered from traffic, with shadow, zombie and
  superseded endpoints against OpenAPI descriptions
- Origin lock: per request signatures the origin verifies, mutual TLS
  and network rules so an application accepts only proxied traffic
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
  Coraza: block or detect per route, custom rules and exclusions,
  bounded request and response inspection
- Ban list: repeated denies of any category become escalating temporary
  bans dropped at accept, persisted across restarts, shared across a
  cluster and managed from the CLI; triggers aggregate by network or
  TLS fingerprint against distributed attacks
- Fleet operation: a controller pushes configuration bundles to many
  nodes over mutual TLS and collects their status; SIEM export in
  NDJSON, Splunk HEC, CEF or LEEF
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
- Honeypot routes with a hundred and forty-two built-in decoys — from
  a WordPress login to a cloud metadata document, a container registry
  catalogue, a Werkzeug debugger, an IP camera, a Postfix `main.cf`, a
  broker ACL file and an `authorized_keys` — that mark probing
  clients and feed the ban list; honeytokens that trip when a planted
  credential is used; hidden-field and timing honeypots on forms;
  graduated degradation and deceptive answers instead of a refusal a
  scanner can tune against ([docs/DECEPTION.md](docs/DECEPTION.md));
  ICAP scanning of uploads and downloads with preview, block pages and
  fail policies

**Identity**

- JWT validation at the edge with JWKS rotation, algorithm allow lists
  and claim forwarding
- OpenID Connect login (the authorization code flow) with sealed
  session cookies, required claims, identity headers for applications
  and logout through the provider
- HTTP Basic authentication from a file of PBKDF2 hashes, and LDAP
  bind against a directory
- A second factor shared by every protocol that can ask for one: TOTP
  against one enrolment file, asked for over keyboard-interactive on
  the SSH bastion and through a filter in front of a web application.
  One implementation on purpose — a second factor that means different
  things on different ports is not a second factor, because the weakest
  door decides. A code is spent when used, every failure gets the same
  answer, and guessing is bounded by a lockout

**Other listener kinds**

- `kind: tcp`: layer 4 TLS and QUIC passthrough routed by server name
  without terminating TLS, with PROXY protocol v2 to TCP upstreams and
  optional YARA rules over the bytes it relays
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
  DNSSEC validation, a cache, block lists, sinkholes, client allow lists,
  per client rate limits and **tunnelling detection** — query entropy,
  subdomain cardinality, TXT share, NXDOMAIN rate and encoded bytes,
  measured per client per registered domain, with several required to
  agree before anything is called exfiltration; it advertises its own encrypted endpoints
  through RFC 9462 discovery so clients upgrade themselves, and answers
  the SVCB and HTTPS records for the names it fronts, which is the other
  half of Encrypted Client Hello
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
- `kind: syslog`: a syslog relay that reads what it forwards. Almost
  every field in a record is written by the sender and believed by the
  collector, and a message whose text carries a newline becomes two
  records in anything that frames on newlines. Every message is parsed
  and re-emitted as RFC 5424 in one framing; facility, severity, sender
  and pattern filters, redaction, per-sender rate limits; UDP, TCP and
  TLS on one address. The two ends are configured separately, so it is
  also a **secure upgrade**: clear UDP in from something that cannot be
  taught TLS, RFC 5425 TLS out
- `kind: ftp`: an FTP proxy that is actually in the middle. FTP puts
  every transfer on a second connection whose address one side
  announces to the other, so a proxy that forwards that reply has told
  the client to go round it; this one rewrites the address and is one
  end of both connections. Commands, paths, extensions, a bound on a
  transfer and YARA over uploads; AUTH TLS both ways. **`PORT` is
  refused by default** — it asks the proxy to connect to an address the
  client names, which is the bounce attack
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

**Extensibility and platforms**

- **Authorisation as one policy**: every authenticating filter answers
  "who"; `authz` answers "what may they do", deciding on the subject,
  groups, scopes and claims those filters verified — default deny,
  first match wins, and nothing a client sent can reach a rule
- **gRPC message inspection**: the framing, a bound on one message
  rather than the whole stream, the protobuf structure (nesting depth,
  field count) and patterns over the strings inside — without a schema,
  because a check that is only as current as its schema is a check that
  quietly stops applying
- A stable middleware interface for compiled-in filters (header
  policy, basic authentication, body rewriting, bot scoring, OpenID
  Connect), and a WebAssembly ABI that runs sandboxed modules per
  request with memory and time bounds
- Kubernetes ingress controller mode: Ingress and Gateway API resources
  become routes, upstreams and certificates, reloaded within a second
  of a change through watches; manifests and a container build
  included
- Fedora is the reference platform (RPM, systemd, SELinux); macOS is
  supported with launchd jobs, a Seatbelt profile, a pf anchor and an
  installer, cross compiled by the same build

**Operations**

- Four JSON log streams (access, error, security, audit) to files,
  journald or syslog, with per stream redaction of personal data and
  a request identifier end to end
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
- An expression language for routes and header operations: `when`
  conditions over addresses, headers, cookies, query parameters,
  patterns, captures and the time of day, checked at load
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

## Quick start

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

[docs/SETUP.md](docs/SETUP.md) covers the RPM, the systemd units, SELinux
and the web GUI; [docs/USAGE.md](docs/USAGE.md) has a worked example for
every feature above, and [examples/](examples/) has complete
configurations — a submission proxy, an MQTT fleet, an SSH bastion, an
encrypted resolver, an egress proxy with SOCKS5 and MASQUE, YARA rules,
honeypots — each one validated by a test that runs on every build.

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
| [examples/](examples/) | WAF rules, block lists, filters, a WebAssembly module, rewriting and routing examples, all validated by tests |
| [docs/HARDENING_MACOS.md](docs/HARDENING_MACOS.md) | Host hardening on macOS |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Components, request path, data flows |
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
usually the same. The SMTP, MQTT, FTP, syslog, SFTP and MASQUE parsers, the TOTP
implementation and the YARA engine are all first-party: a protocol this
proxy *decides* is a protocol it has to read the same way twice, and
linking libyara alone would have meant `CGO_ENABLED=1` and a C parser in
the data plane.

## Licence

Xproxy is proprietary, commercially licensed software. Copyright (c) 2026
Sysctl AB. All rights reserved. See [LICENSE](LICENSE). Third party
components keep their own licences, listed in [docs/AMR.md](docs/AMR.md).
