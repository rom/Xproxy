# Xproxy 1.0.0

Xproxy 1.0.0 is the first release: a security focused HTTP/1.1, HTTP/2
and HTTP/3 reverse proxy, load balancer and web application firewall for
Fedora Linux, delivered as three static binaries with a hardened systemd
unit, an SELinux policy and RPM packages.

## Highlights

- **Edge termination** for HTTP/1.1, HTTP/2 and HTTP/3 with TLS 1.2 and
  1.3 hardened defaults, SNI, certificate hot reload, client
  certificates and ACME issuance with automatic renewal.
- **Routing and load balancing**: host and path routing, redirects and
  static responses, header rewriting, round robin, weighted, least
  connections and consistent hashing pools, active health checks, outlier
  ejection, retries and signed cookie affinity. Validated at 1000 virtual
  hosts and 10 000 endpoints.
- **Defence in depth**: connection, concurrency, header, URI and body
  limits; keyed rate limits with reject or tarpit; a ban list with
  escalating temporary bans persisted across restarts; adaptive load
  shedding by priority class; a browser proof of work challenge; the
  OWASP Core Rule Set through Coraza with block or detect per route;
  external scanning over ICAP; JWT validation at the edge; a cluster mode
  that shares rate limits and bans over mutual TLS with no external
  store.
- **Operations**: four JSON log streams to files, journald or syslog
  with per stream redaction of personal data; Prometheus metrics and an
  in-process time series buffer; a command line tool, a terminal UI and a
  web GUI with viewer and operator roles over one audited management
  socket; a stable middleware interface for compiled-in extensions.
- **Platform**: unprivileged under systemd socket activation, confined
  by an SELinux policy with domains for the data plane and the GUI,
  packaged as `xproxy`, `xproxy-admin` and `xproxy-selinux`.

## Quality

- Whole suite statement coverage 82.5 % under the race detector, gated
  in CI at 80 % (60 % per package).
- Mutation testing on the admission packages: 87 %, 81 % and 98 %
  efficacy.
- Chaos tests for reload storms, flapping endpoints, upstream death mid
  response, a full log disk and certificate rotation.
- An internal security review against the threat model
  (SECURITY_REVIEW.md); its two medium findings are fixed in this
  release.
- Measured on the reference container: 10 000 requests per second at
  p99 under 10 ms with the load generator on the same four cores
  (PERFORMANCE.md).

## Installing

See [SETUP.md](SETUP.md). On Fedora: build the RPMs with `make rpm`,
install `xproxy`, `xproxy-admin` and `xproxy-selinux`, edit
`/etc/xproxy/xproxy.yaml`, enable `xproxy.socket` and `xproxy-https.socket`.

## Known limitations

These are recorded so that a reader knows what 1.0.0 does not claim:

- The SELinux policy compiles against the Fedora headers and the RPM
  loads it, but a run on a Fedora host with SELinux enforcing (AVC audit
  under traffic) has not yet been part of continuous integration. Run
  the domain permissive for a day on first deployment as SETUP.md says.
- The throughput target of 100 000 requests per second on 8 cores is
  not yet measured on dedicated hardware; the published numbers are from
  a shared 4 core container.
- No external security review has been performed yet.
- HTTP/3 has been tested with quic-go clients, not against every browser.
- Statistics are not persisted across restarts (bans are); the series
  buffer starts empty after a restart.
- WebAssembly extensions, DNS-01 ACME challenges and external account
  binding are after 1.0 (ROADMAP.md).

## Upgrading

There is no earlier release to upgrade from. The configuration schema is
versioned (`version: 1`); the loader refuses unknown keys, so a
configuration that validates today keeps validating in every 1.x
release.
