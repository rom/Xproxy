# Xproxy

Xproxy is a security focused edge proxy for Fedora Linux and macOS: an HTTP/1.1,
HTTP/2 and HTTP/3 reverse proxy and load balancer with a web
application firewall, a ban list, rate limiting and load shedding at
its core, plus the listener kinds an edge needs around it (layer 4 TLS
passthrough, a forward proxy, a DNS proxy) and the integrations that
put it to work (OpenID Connect login, gRPC, Kubernetes ingress,
WebAssembly extensions). It is one static Go binary with no cgo, runs
unprivileged under a hardened systemd unit confined by SELinux, and is
managed over a local socket from a CLI, a terminal UI and a web GUI.

Status: 1.3 in development on top of the **1.0.0** release
([release notes](docs/RELEASE_NOTES_1.0.md), [how a release is
cut](docs/RELEASING.md)). [docs/ROADMAP.md](docs/ROADMAP.md) lists what
each version delivered and what is planned;
[docs/CHANGELOG.md](docs/CHANGELOG.md) has the details.

## How it works

Every configuration is a set of listeners, upstream pools and routes.
A `kind: http` listener terminates TLS (or not), runs each request
through a fixed admission pipeline and hands it to a route's action; the
other listener kinds reuse the same accept limits, bans, logs and
management plane for other protocols.

```
client ──▶ listener (accept limits, bans) ──▶ admission pipeline ──▶ route action ──▶ upstream pool
              http | tcp | forward | dns        concurrency, host and       proxy, redirect,      balancer, health,
                                                path checks, route match,   respond, honeypot,    ejection, retries,
                                                country, ACL, challenge,    static files          affinity, mirror
                                                shedding, rate limits,
                                                body limit, filters
                                                (auth, WAF, ICAP, yours),
                                                cache
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
  requests; gzip compression of eligible responses; request mirroring
  of sampled traffic to a candidate upstream, bounded and invisible to
  clients
- Static file serving from a directory with index files, listings and a
  single page application fallback, confined to the root
- gRPC: errors answered as gRPC statuses, `grpc-timeout` honoured,
  trailers relayed, per code counters

**Defence**

- Connection limits at accept (global and per address), concurrency
  ceiling, header, body and idle timeouts, URI and body size limits,
  WebSocket opt-in per route
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
- Honeypot routes with a hundred and fifteen built-in decoys — from a
  WordPress login to a cloud metadata document, a container registry
  catalogue, a Werkzeug debugger and an IP camera — that mark probing
  clients and feed the ban list; honeytokens that trip when a planted
  credential is used; hidden-field and timing honeypots on forms;
  graduated degradation and deceptive answers instead of a refusal a
  scanner can tune against ([docs/DECEPTION.md](docs/DECEPTION.md));
  ICAP scanning of uploads and downloads with preview, block pages and
  fail policies

**Identity**

- JWT validation at the edge with JWKS rotation, algorithm allow lists
  and claim forwarding
- OpenID Connect login (authorization code with PKCE) with sealed
  session cookies, required claims, identity headers for applications
  and logout through the provider
- HTTP Basic authentication from a file of PBKDF2 hashes

**Other listener kinds**

- `kind: tcp`: layer 4 TLS and QUIC passthrough routed by server name
  without terminating TLS, with PROXY protocol v2 to TCP upstreams
- `kind: forward`: an explicit proxy for clients with CONNECT tunnels,
  a destination policy that refuses private ranges by default, and
  proxy credentials
- `kind: dns`: a DNS proxy over UDP, TCP, TLS and HTTPS with DNSSEC
  validation, a cache, block lists, sinkholes, client allow lists and
  per client rate limits

**Extensibility and platforms**

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
  cache, honeypots, DNS, ingress, cluster, metrics and a full screen
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
every feature above.

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
engine with the Core Rule Set, bbolt for ban state, quic-go for HTTP/3
and wazero for WebAssembly.

## Licence

Xproxy is proprietary, commercially licensed software. Copyright (c) 2026
Sysctl AB. All rights reserved. See [LICENSE](LICENSE). Third party
components keep their own licences, listed in [docs/AMR.md](docs/AMR.md).
