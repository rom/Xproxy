# Xproxy

A security focused HTTP reverse proxy, load balancer and web application
firewall, written in Go for Fedora Linux. Single static
binary, no cgo, unprivileged under a hardened systemd unit, confined by
SELinux, managed over a local socket.

Status: **phase 3 in progress** (ICAP, ACME, the web GUI, the SELinux
policy, RPM packaging and scale validation delivered; coverage gates, the
security review and the reference hardware numbers remain). Phases 1 and 2 are complete. See
[docs/ROADMAP.md](docs/ROADMAP.md) for what is in and what follows.

## What it does today

- HTTP/1.1, HTTP/2 and HTTP/3 termination with TLS 1.2/1.3 hardened
  defaults, SNI, certificate hot reload, ACME issued certificates with
  automatic renewal, client certificates, QUIC address validation
- Host and path routing, redirects, static responses, header rewriting
- Upstream pools with round robin, weighted, least connections and
  consistent hashing; active health checks; outlier ejection; retries;
  signed cookie session affinity
- Web application firewall: bundled OWASP Core Rule Set through Coraza,
  block or detect per route, custom rules and exclusions, bounded request
  and response inspection
- Ban list: repeated denies become escalating temporary bans, dropped at
  accept, persisted across restarts, managed from the CLI
- Cluster: proxies share rate limit consumption and bans over mutual TLS,
  making limits approximately cluster wide with no external datastore
- Adaptive load shedding by priority class from upstream latency and
  in-flight load, with critical routes never shed
- Browser proof-of-work challenge, always or only under load
- JWT validation at the edge with JWKS rotation, claim forwarding and
  algorithm allow lists; mutual TLS and public key pinning to upstreams
- ICAP scanning of uploads and downloads with preview, block pages and
  fail policies
- Defences: connection limits at accept, concurrency ceiling, slowloris and
  body timeouts, size limits, keyed rate limits with reject or tarpit, CIDR
  allow and deny lists, trusted proxy handling, WebSocket opt-in
- Four JSON log streams (access, error, security, audit) with a request
  identifier end to end, delivered to files, journald or syslog, with
  per-stream redaction of personal data
- Management over a local socket from a CLI, a terminal UI and a web GUI
  with viewer and operator roles, configuration editing with validation,
  graphs and live logs
- Extensible with compiled-in middleware behind a stable interface
  (header policy and basic authentication built in)
- `xproxyctl` over a Unix socket with kernel verified caller identity:
  status, upstreams, reload, certificate reload, log reopen, tail, bans,
  cluster, metrics, sampled series, and a full-screen TUI
- Prometheus exposition with latency histograms and per-route counters,
  on the socket or a hardened TCP endpoint, plus an in-process series
  buffer for graphs
- Hot reload, graceful shutdown, systemd socket activation and notify
- Hardened unit, sysctl profile, SELinux policy, logrotate configuration

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

## Documentation

| Document | Content |
|----------|---------|
| [docs/ASR.md](docs/ASR.md) | Architecturally significant requirements with traceability |
| [docs/AMR.md](docs/AMR.md) | Architecture decision records |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Components, request path, data flows |
| [docs/SECURITY.md](docs/SECURITY.md) | Security posture, controls, secure development, reporting |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | STRIDE analysis per trust boundary |
| [docs/CONFIG.md](docs/CONFIG.md) | Configuration reference |
| [docs/USAGE.md](docs/USAGE.md) | Operating the proxy and the control tool |
| [docs/SETUP.md](docs/SETUP.md) | Installation on Fedora |
| [docs/PERFORMANCE.md](docs/PERFORMANCE.md) | Measured scale and throughput |
| [docs/EXTENDING.md](docs/EXTENDING.md) | Writing middleware against the stable interface |
| [docs/HARDENING.md](docs/HARDENING.md) | Host hardening checklist |
| [docs/TESTS.md](docs/TESTS.md) | Test harness and coverage |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Phases to 1.0 and beyond |
| [docs/CHANGELOG.md](docs/CHANGELOG.md) | Notable changes per phase |

## Development

```sh
make check          # fmt, vet, race tests, lint
make cover          # coverage under race
make fuzz           # all fuzz targets, 20s each
```

Go 1.25 or newer. No cgo. Dependencies are listed and justified in
[docs/AMR.md](docs/AMR.md) (AMR-004).

## Licence

Xproxy is proprietary, commercially licensed software. Copyright (c) 2026
Sysctl AB. All rights reserved. See [LICENSE](LICENSE). Third party
components keep their own licences, listed in [docs/AMR.md](docs/AMR.md).
