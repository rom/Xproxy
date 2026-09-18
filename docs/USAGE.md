# Usage

Day to day operation of xproxy: running the daemon, the control tool,
configuration patterns and reading the logs. Installation is covered in
[SETUP.md](SETUP.md), the full configuration reference in
[CONFIG.md](CONFIG.md).

## Binaries

| Binary | Purpose |
|--------|---------|
| `xproxy` | The data plane daemon |
| `xproxyctl` | Control tool talking to the daemon's Unix socket |
| `xproxy-admin` | Web GUI: a separate process serving a browser interface over the same socket |

### xproxy

```
xproxy -config /etc/xproxy/xproxy.yaml     # run
xproxy -config file.yaml -validate         # validate and exit 0/1
xproxy -version
```

Signals:

| Signal | Effect |
|--------|--------|
| `SIGHUP` | Re-read and apply the configuration; on error the old one stays |
| `SIGUSR1` | Reopen log files (after external rotation) |
| `SIGTERM`, `SIGINT` | Drain within `server.shutdown_timeout`, then exit |

Under systemd use `systemctl reload xproxy` and `systemctl restart xproxy`.
With socket activation a restart does not lose the listening socket, so
listener changes (which reload refuses) cost only the drain time.

### xproxyctl

```
xproxyctl [-socket /run/xproxy/mgmt.sock] [-config /etc/xproxy/xproxy.yaml] [-json] COMMAND
```

| Command | Description |
|---------|-------------|
| `status` | Version, pid, generation, listeners, counters |
| `stats` | Counters only |
| `upstreams` | Table of endpoints with health, ejection, active requests, request and error counts |
| `config` | Active configuration as YAML, defaults filled in |
| `validate` | Validate the configuration file locally |
| `reload` | Validate locally, then ask the daemon to reload |
| `reload-certs` | Re-read certificate files |
| `reopen-logs` | Reopen log files |
| `tail STREAM` | Follow `access`, `error`, `security` or `audit` |
| `bans` | List active bans with expiry, source and count |
| `ban TARGET` | Ban an address or CIDR; `-duration 1h`, `-reason text` |
| `unban TARGET` | Remove a ban |
| `cluster` | Peers, inbound connections and gossip counters |
| `spki CERT.pem` | Print the `spki_pins` value of a certificate |
| `acme` | Managed certificates with expiry, issuer, last error; `acme renew` forces renewal and waits |
| `icap` | ICAP services with reachability, preview size, ISTag and counters |
| `filters` | Middleware API version, registered kinds, configured filters with routes and deny counts |
| `geoip` | Country database kind, path, build date, lookup and unknown counters |
| `cache` | Cache entries, bytes and counters; `cache purge [HOST [PATH-PREFIX]]` removes entries |
| `honeypot` | Clients marked by honeypot routes and the decoy names; `honeypot forget IP` removes a mark |
| `dns` | DNS listener counters (queries, cache, blocked, refused, dropped, upstream failures); `dns purge` empties the caches |
| `ingress` | Kubernetes ingress controller status: syncs, watches, counts, warnings |
| `otlp` | OpenTelemetry exporter status: pushes, failures, last error |
| `htpasswd FILE NAME` | Add or replace a `basic_auth` user; the password is read from stdin |
| `tui` | Full-screen live view; `-refresh 2s`, `-no-color` (or `NO_COLOR`) |
| `metrics` | Print the Prometheus exposition |
| `series` | Print sampled series; `-since 10m`, `-last 30`, `-json` |
| `version` | Print version |

`-json` switches `status`, `stats` and `upstreams` to machine readable
output. The user running `xproxyctl` must be in the `xproxy` group (socket
mode `0660`) or be root.

Examples:

```sh
xproxyctl status
xproxyctl -json stats | jq .denied_rate_limit
xproxyctl upstreams
xproxyctl tail security | jq -c '{t:.time, ip:.client_ip, r:.reason, p:.path}'
xproxyctl reload
xproxyctl bans
xproxyctl ban -duration 24h -reason "credential stuffing" 203.0.113.0/24
xproxyctl unban 203.0.113.0/24
```

## Configuration patterns

### Minimal

```yaml
version: 1
server:
  listeners:
    - {name: http, address: ":8080"}
upstreams:
  - name: app
    endpoints: [{address: 127.0.0.1:3000}]
routes:
  - name: all
    upstream: app
```

### Pushing metrics to an OpenTelemetry collector

```yaml
metrics:
  otlp:
    endpoint: https://otel.example.internal:4318/v1/metrics
    interval: 15s
    headers: {Authorization: "Bearer replace-me"}
    ca_file: /etc/xproxy/otel-ca.pem
    service_name: edge
    attributes: {deployment.environment: production}
```

Every family in `/metrics` reaches the collector as OTLP with the same
names, so dashboards built on the Prometheus exposition carry over;
`xproxyctl otlp` shows whether pushes succeed.

### Splitting the configuration into fragments

```yaml
# /etc/xproxy/xproxy.yaml
version: 1
includes: ["/etc/xproxy/conf.d/*.yaml"]
server: {listeners: [{name: https, address: ":443", tls: {certificates: [...]}}]}
```

```yaml
# /etc/xproxy/conf.d/10-shop.yaml
upstreams:
  - name: shop
    endpoints: [{address: 10.0.1.10:8080}]
routes:
  - name: shop
    hosts: [shop.example.com]
    upstream: shop
```

Fragments hold only `upstreams`, `routes`, `rate_limits` and `filters`;
everything that controls the process (listeners, limits, logging,
management) stays in the main file, so a fragment can add a site but
never weaken a defence. Files are appended in lexical order, names must
be unique across all of them, and `xproxyctl validate` checks the whole
set. A reload re-reads every fragment. `xproxyctl config` prints the
expanded result as one self-contained document (with `includes` cleared
and the fragment paths in a leading comment), so its output can be
saved and loaded as a main file without expanding the fragments twice.
The Kubernetes ingress merge works on the expanded document the same
way.


### TLS edge with HTTP redirect

```yaml
server:
  listeners:
    - {name: public-http, address: ":80", redirect_to_https: true}
    - name: public
      address: ":443"
      tls:
        certificates:
          - {cert_file: /etc/xproxy/certs/site.pem, key_file: /etc/xproxy/certs/site-key.pem}
```

Add more certificates to the list; SNI selects the matching one.

### Automatic certificates (ACME)

```yaml
server:
  listeners:
    - {name: public-http, address: ":80", redirect_to_https: true}
    - name: public
      address: ":443"
      tls:
        acme:
          - hosts: [shop.example.com, www.shop.example.com]
          - hosts: [api.example.com]

acme:
  directory: https://acme-v02.api.letsencrypt.org/directory
  email: hostmaster@example.com
  accept_terms: true
```

Each `hosts` group becomes one certificate. With the default `http-01`
challenge the plaintext listener answers the validation requests before
the HTTPS redirect; with `challenge: tls-alpn-01` only port 443 is needed.
File certificates and ACME groups can be mixed on the same listener. The
first order runs at start; watch it with:

```sh
xproxyctl acme
xproxyctl tail error | jq -c 'select(.component=="acme")'
xproxyctl acme renew      # force, for example after changing hosts
```

Certificates and the account live under `/var/lib/xproxy/acme`; back that
directory up with the configuration. Adding or removing a group is a
listener change and needs a restart.

### HTTP/3

```yaml
    - name: public
      address: ":443"
      protocols: [h1, h2, h3]
      h3: {max_streams: 100, validate_addresses: always}
      tls: {certificates: [...]}
```

xproxy binds UDP 443 next to TCP 443 (or takes the datagram socket from
`xproxy-h3.socket`), advertises `Alt-Svc` on TLS responses, and serves the
same routes over QUIC. Open UDP 443 in the firewall. `xproxyctl status`
lists the endpoint as `public/udp`; access log lines show
`proto: HTTP/3.0`.

### Virtual hosts and path routing

```yaml
routes:
  - {name: api,  hosts: [api.example.com],        upstream: api}
  - {name: docs, hosts: [example.com], paths: [/docs], upstream: docs}
  - {name: web,  hosts: [example.com, "*.example.com"], upstream: web}
  - {name: default, priority: -100, respond: {status: 404, body: "not found\n"}}
```

Precedence: exact host over wildcard over no host; then longest path
prefix; then `priority`; then configuration order. A route with `methods`
only matches those methods; other methods fall through to the next route.

### Protecting a login endpoint

```yaml
rate_limits:
  - {name: login, key: client_ip, rate: 0.2, burst: 5, action: tarpit, tarpit_delay: 10s}
routes:
  - name: login
    hosts: [example.com]
    paths: [/login]
    methods: [POST]
    rate_limits: [login]
    max_body_bytes: 16384
    upstream: web
```

Beyond five attempts, each further attempt is held for ten seconds and then
answered 429. The hold is released early if the client disconnects.

### Rate limiting by API key with a fallback

```yaml
rate_limits:
  - {name: per-key, key: "header:X-Api-Key", rate: 100, burst: 200}
```

Requests without the header are limited by client address instead, so the
limit cannot be avoided by omitting the header.

### Restricting an admin path

```yaml
routes:
  - name: admin
    hosts: [example.com]
    paths: [/admin]
    allow_cidrs: [10.0.0.0/8]
    upstream: web
```

Deny lists are evaluated before allow lists. Client addresses come from the
peer unless it is in `trusted_proxies`.

### Behind a load balancer that sets X-Forwarded-For

```yaml
trusted_proxies: [10.0.0.0/24]
```

Only hops from this range are believed. Never list `0.0.0.0/0`.

### Behind a layer 4 balancer that speaks the PROXY protocol

```yaml
trusted_proxies: [10.0.0.0/24]
server:
  listeners:
    - {name: public, address: ":443", proxy_protocol: true, tls: {certificates: [...]}}
```

A TCP balancer that cannot add HTTP headers (HAProxy in `mode tcp`,
cloud network load balancers) prepends a PROXY protocol v1 or v2 header
to every connection instead. With `proxy_protocol: true` the listener
reads it from peers in `trusted_proxies` before TLS starts, and from
then on the client address in the header is the client: bans, connection
and rate limits, ACLs, country lookups, the access log and the
forwarding headers all see it. A trusted balancer that sends no header
is dropped, so turn the option on together with the balancer, and a
connection from any other peer is served as before, so nobody outside
the balancer range can choose an address. Layer 4 listeners (`kind:
tcp`) do the opposite: their `proxy_protocol` sends the header to the
upstream.

### Weighted and sticky pools

```yaml
upstreams:
  - name: web
    balancer: weighted
    endpoints:
      - {address: 10.0.1.10:8080, weight: 3}
      - {address: 10.0.1.11:8080, weight: 1}
    affinity: {cookie_name: XPSESS, ttl: 1h, secret_file: /var/lib/xproxy/web.key}
```

The cookie contains a signed endpoint index. If the endpoint is unhealthy
the request is rebalanced and a new cookie issued.

### Consistent hashing by tenant

```yaml
upstreams:
  - name: api
    balancer: hash
    hash_on: "header:X-Tenant"
    endpoints: [{address: 10.0.2.10:8443}, {address: 10.0.2.11:8443}]
```

Missing hash input falls back to the client address.

### WebSockets

```yaml
routes:
  - {name: ws, hosts: [example.com], paths: [/socket], websocket: true, upstream: web}
```

Without `websocket: true` an upgrade request is refused with 403 and logged.

### Health checks and ejection

```yaml
upstreams:
  - name: web
    endpoints: [...]
    health_check: {path: /healthz, interval: 5s, timeout: 2s, healthy_threshold: 2, unhealthy_threshold: 3}
    outlier_ejection: {consecutive_failures: 5, base_ejection_time: 30s, max_ejection_percent: 50}
```

Active checks mark endpoints unhealthy; passive ejection reacts to real
traffic failures with growing back-off. At most half the pool is ejected.

### Web application firewall

Enable the bundled OWASP Core Rule Set and roll it out in detect mode
first:

```yaml
waf:
  default_mode: detect
  profiles:
    - name: default
      crs: {paranoia_level: 1}
```

Watch the security log for `waf_detected` entries and the access log for
`waf_matched`. Add exclusions for legitimate traffic in a SecLang file,
then switch to block:

```yaml
waf:
  default_mode: block
  inspect_responses: true
  profiles:
    - name: default
      crs: {paranoia_level: 1}
      directive_files: [/etc/xproxy/waf/exclusions.conf]
    - name: strict
      crs: {paranoia_level: 2}
routes:
  - {name: api,    hosts: [api.example.com], upstream: api, waf: {profile: strict}}
  - {name: upload, hosts: [example.com], paths: [/upload], upstream: web, waf: {mode: off}}
  - {name: web,    hosts: [example.com], upstream: web}
```

Example exclusion file:

```
# Rich text editor posts HTML in the "body" field of /posts.
SecRule REQUEST_URI "@beginsWith /posts" \
  "id:10001,phase:1,pass,nolog,ctl:ruleRemoveTargetById=941100;ARGS:body,ctl:ruleRemoveTargetById=941160;ARGS:body"
```

Custom rules without the CRS work the same way through `directives`.

### Ban list

```yaml
bans:
  state_file: /var/lib/xproxy/bans.db
  action: drop
  exempt_cidrs: [10.0.0.0/8]
  triggers:
    - {name: waf-repeat, reasons: [waf], threshold: 5, window: 1m, duration: 15m}
    - {name: brute,      reasons: [rate_limit, acl], threshold: 20, window: 5m, duration: 1h, escalation: 2, max_duration: 24h}
```

A client that trips the WAF five times in a minute is banned for fifteen
minutes; a second ban within the escalation memory doubles it. With
`action: drop` the connection is closed at accept, which costs the proxy
nothing per attempt. Use `reject` when the proxy sits behind a load
balancer that sets `X-Forwarded-For`, because at accept only the balancer's
address is visible.

### Cluster of proxies

Issue one certificate per node from a private cluster CA, then on every
node:

```yaml
cluster:
  node_id: edge-1
  listen: 10.0.0.1:7946          # internal interface
  peers: [10.0.0.2:7946, 10.0.0.3:7946]
  tls:
    cert_file: /etc/xproxy/cluster/edge-1.pem
    key_file: /etc/xproxy/cluster/edge-1-key.pem
    ca_file: /etc/xproxy/cluster/ca.pem
    allowed_names: [edge-1, edge-2, edge-3]
```

With this in place every `rate_limits` policy is approximately cluster
wide per key and every ban (manual or triggered) reaches all nodes within
a gossip interval. So do security events: a client that touches a
honeypot on one node is marked on all of them (`xproxyctl honeypot`
shows `peer:<node>/<route>` as the route), and an OIDC logout on one
node revokes the provider session on all of them. `share_rate_limits`,
`share_bans` and `share_events` switch each channel off separately; set
`share_events: false` while nodes older than 1.3 are still in the
cluster, since they close a connection that carries events. `xproxyctl
cluster` shows connection state and the counters per channel; a peer
with `connected: false` and a `last_error` is being redialled with
back-off. Firewall the cluster port to the peers' addresses
(HARDENING.md).

### Priority classes and load shedding

```yaml
shedding:
  target_latency: 250ms
  window: 10s
routes:
  - {name: health,  hosts: [example.com], paths: [/healthz], priority_class: critical, upstream: web}
  - {name: login,   hosts: [example.com], paths: [/login],   priority_class: high,     upstream: web}
  - {name: search,  hosts: [example.com], paths: [/search],  priority_class: low,      upstream: web}
  - {name: web,     hosts: [example.com],                     upstream: web}   # normal
```

When the upstream slows past the target or the proxy nears its concurrency
ceiling, search is shed first, then normal pages, then login; health checks
are never shed. `xproxyctl status` shows `load_level`,
`upstream_latency_ms` and `shedding_classes`. Tune `target_latency` to the
site's healthy time to first byte, not to the slowest page.

### Mutual TLS to upstreams

```yaml
upstreams:
  - name: api
    scheme: https
    tls:
      server_name: api.internal
      ca_file: /etc/xproxy/certs/internal-ca.pem
      min_version: "1.3"
      client_cert_file: /etc/xproxy/certs/edge.pem
      client_key_file: /etc/xproxy/certs/edge-key.pem
      spki_pins: ["<base64 sha256>"]     # xproxyctl spki api.internal.pem
```

The upstream can now require the edge's certificate, and the edge refuses
any upstream whose public key is not pinned. Rotate the client certificate
by replacing the files and running `xproxyctl reload-certs`; a broken pair
is rejected and the old one stays in use. Keep two pins during an upstream
key rotation.

### Browser login with OpenID Connect

```yaml
filters:
  - name: sso
    kind: oidc
    options:
      issuer: https://login.example.com
      client_id: intranet
      client_secret_file: /etc/xproxy/sso.secret
      cookie_secret_file: /etc/xproxy/sso.cookie
      external_url: https://intranet.example.com
      scopes: [openid, email, profile]
      forward_headers: {X-Remote-User: sub, X-Remote-Email: email, X-Remote-Name: name}
      require_claims: {hd: example.com}
      log_claims: [email]
      session_ttl: 12h
routes:
  - name: intranet
    hosts: [intranet.example.com]
    upstream: intranet
    filters: [sso]
```

Register `https://intranet.example.com/oauth2/callback` as the redirect
URI at the provider, and
`https://intranet.example.com/oauth2/frontchannel-logout` as the front
channel logout URI so that a logout at the provider (or at another
application) ends the session here too. The first visit bounces through the provider and
comes back to the page that was asked for; after that the browser
carries an encrypted cookie and the application receives the user in
`X-Remote-User`, never a cookie it could misuse. `/oauth2/logout` ends
the session at the proxy and at the provider. Put `basic_auth` or JWT
in front of API paths instead; the OIDC filter is for people with
browsers.

### JWT validation

```yaml
jwt:
  providers:
    - name: idp
      issuer: https://idp.example.com/
      audiences: [api]
      algorithms: [RS256, ES256]
      jwks_url: https://idp.example.com/.well-known/jwks.json
      jwks_ca_file: /etc/xproxy/certs/idp-ca.pem
      forward_claims: {X-User: sub, X-Scopes: scope}
      log_claims: [sub]
routes:
  - {name: api,    hosts: [api.example.com], jwt: {provider: idp}, upstream: api}
  - {name: public, hosts: [api.example.com], paths: [/public], jwt: {provider: idp, required: false}, upstream: api}
```

Requests without a valid token get 401 with `WWW-Authenticate`; valid ones
reach the upstream with `X-User` and `X-Scopes` set from the token and the
`Authorization` header removed. A client cannot inject `X-User` itself. For
a first-party service with a shared secret use `algorithms: [HS256]` and
`hmac_secret_file`. Combine with `rate_limits` keyed by `header:X-User`
on a downstream route if you need per-user limits today; token-keyed rate
limits are planned.

### Virus and content scanning (ICAP)

```yaml
icap:
  services:
    - name: av
      url: icaps://scanner.internal:11344/avscan
      tls: {ca_file: /etc/xproxy/certs/internal-ca.pem}
      max_body: 52428800        # 50 MiB uploads
      body_limit_action: reject
      fail: closed
routes:
  - {name: upload,   hosts: [example.com], paths: [/upload],   icap: {service: av}, upstream: web}
  - {name: download, hosts: [example.com], paths: [/files],    icap: {service: av, request: false, response: true}, upstream: web}
```

Uploads are scanned before they reach the application; downloads are
scanned before they reach the client. A detection returns the scanner's
own block page, is logged with reason `icap`, and counts towards ban
triggers. `xproxyctl icap` shows whether each service answered its last
exchange, the preview size it advertised, and how many exchanges were
unmodified, modified, replaced, failed or bypassed.

### TLS passthrough by server name (layer 4)

```yaml
server:
  listeners:
    - name: passthrough
      address: ":8443"
      kind: tcp
      tcp:
        routes:
          - {sni: [mail.example.com, "*.mail.example.com"], upstream: mail}
          - {sni: [legacy.example.com], upstream: legacy}
        default: legacy           # non-TLS and unknown names
        quic: true                # also relay HTTP/3 (UDP 8443) by server name
upstreams:
  - name: mail
    health_check: {path: /healthz}     # for https upstreams checks still use HTTP
    endpoints: [{address: 10.0.3.10:443}, {address: 10.0.3.11:443}]
  - name: legacy
    endpoints: [{address: 10.0.3.20:443}]
```

The upstream keeps its own certificates and the WAF does not see the
traffic (it is encrypted end to end); use an `http` listener with TLS
termination where inspection is wanted. With `quic: true` the same
routes relay QUIC (HTTP/3) datagrams: the server name is read from the
client's Initial packet and every later datagram of that client goes
to the chosen endpoint. `proxy_protocol` applies to TCP connections
only and cannot be combined with `quic`.

### Kubernetes ingress controller

```sh
podman build -f deploy/kubernetes/Containerfile -t registry.example.com/xproxy:1.2 .
kubectl create namespace xproxy
kubectl -n xproxy create secret tls xproxy-default-tls --cert=default.pem --key=default.key
kubectl apply -f deploy/kubernetes/xproxy.yaml
```

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: shop
  namespace: shop
  annotations:
    xproxy.sysctl.se/rate-limits: "api"
    xproxy.sysctl.se/websocket: "true"
spec:
  ingressClassName: xproxy
  tls:
    - hosts: [shop.example.com]
      secretName: shop-tls
  rules:
    - host: shop.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend: {service: {name: web, port: {number: 80}}}
          - path: /api
            pathType: Prefix
            backend: {service: {name: api, port: {name: http}}}
```

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata: {name: edge, namespace: infra}
spec:
  gatewayClassName: xproxy
  listeners:
    - name: https
      hostname: "*.example.com"
      port: 443
      protocol: HTTPS
      tls: {certificateRefs: [{name: wildcard-tls}]}
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata: {name: shop, namespace: shop}
spec:
  parentRefs: [{name: edge, namespace: infra}]
  hostnames: [shop.example.com]
  rules:
    - matches: [{path: {type: PathPrefix, value: /api}}]
      filters:
        - type: RequestHeaderModifier
          requestHeaderModifier: {set: [{name: X-Tenant, value: shop}]}
      backendRefs:
        - {name: api-v1, port: 80, weight: 90}
        - {name: api-v2, port: 80, weight: 10}
```

The proxy pods read Ingress resources of class `xproxy`, and Gateway
API resources of the same class where the cluster has them, with their
service account, turn them into routes and upstreams (pod addresses
from EndpointSlices, so traffic goes to pods directly; weighted
backends become a weighted pool), install TLS secrets on the `https`
listener and reload within a second of a change through watch
streams, with a full poll every `resync` as the fallback. Everything else in the ConfigMap's `xproxy.yaml` (bans, rate
limits, filters, WAF) applies to the generated routes through the
annotations. `xproxyctl ingress` in a pod shows the controller state.

### DNS proxy with a block list

```yaml
server:
  listeners:
    - name: resolver
      address: "10.0.0.5:53"
      kind: dns
      dns:
        upstreams: ["9.9.9.9:53", "149.112.112.112:53"]
        allow_clients: [10.0.0.0/8]
        block: [tracker.example, "*.ads.example"]
        block_file: /etc/xproxy/blocklist.txt      # hosts file format accepted
        block_action: sinkhole
        sinkhole_ipv4: 10.0.0.5                     # a local page explaining the block
        cache: {max_entries: 100000, max_ttl: 6h}
        rate_limit: {qps: 20, burst: 200}
bans:
  triggers:
    - {name: dns-abuse, reasons: [dns_blocked], threshold: 500, window: 10m, duration: 1h}
```

```yaml
# Encrypted upstreams and DNS over HTTPS for clients
server:
  listeners:
    - name: resolver
      address: "127.0.0.1:53"
      kind: dns
      dns:
        upstreams: ["tls://dns.quad9.net:853", "https://dns.quad9.net/dns-query"]
        upstream_ca_file: /etc/pki/tls/certs/ca-bundle.crt
    - name: https
      address: ":443"
      tls: {certificates: [{cert_file: /etc/xproxy/dns.pem, key_file: /etc/xproxy/dns.key}]}
routes:
  - name: doh
    hosts: [dns.example.com]
    paths: [/dns-query]
    doh: {listener: resolver}
    rate_limits: [doh-clients]
```

Clients on the internal network resolve through the proxy, which
answers repeated questions from its cache, replaces blocked names with
the sinkhole address, refuses everyone else, drops floods per client
and forwards the rest to the upstream resolvers with a fresh
transaction id and source port per query, or over TLS or HTTPS with
reused connections when the upstream string says so. Browsers and
phones can use the `doh` route as their DNS over HTTPS resolver, with
the same block list and cache. `xproxyctl dns` shows the
counters; `log_queries: true` writes every question to the access log
when an investigation needs it.

### Forward proxy for outbound clients (CONNECT)

```yaml
server:
  listeners:
    - name: egress
      address: "10.0.0.5:3128"
      kind: forward
      forward:
        ports: [80, 443]
        allow: ["*.example.com", "api.partner.test", "203.0.113.0/24"]
        deny: ["admin.example.com"]
        auth: {users_file: /etc/xproxy/egress.htpasswd, realm: egress}
        max_tunnels: 2000
bans:
  triggers:
    - {name: egress-abuse, reasons: [forward_denied, forward_auth], threshold: 20, window: 1m, duration: 10m}
```

```sh
xproxyctl htpasswd /etc/xproxy/egress.htpasswd build-agent   # prompts for the passphrase
HTTPS_PROXY=http://build-agent:passphrase@10.0.0.5:3128 curl https://api.example.com/
```

Clients send `CONNECT api.example.com:443` and the proxy tunnels the
bytes after the destination passed the policy: the port is listed, the
resolved address is public (private ranges are refused unless
`allow_private: true`), it is not denied and it matches the allow list.
Plain `http://` URLs are relayed as requests with hop-by-hop headers
removed. Every request is one `forward` line in the access log with the
user and destination; refusals are security events and, with the
trigger above, ban a client that keeps probing. Keep the listener on an
internal address or in front of `tls` with client certificates; a
forward proxy reachable from the Internet without `auth` is an open
relay.

### Honeypot routes and decoys

```yaml
routes:
  - name: wp-probe
    paths: [/wp-login.php, /xmlrpc.php]
    honeypot: {decoy: wp-login, delay: 2s}
    response_headers: {set: {Server: "Apache/2.4.41 (Ubuntu)"}}
  - name: env-probe
    paths: [/.env, /.git/config]
    honeypot: {decoy: env}
  - name: admin-probe
    paths: [/admin]
    honeypot: {body_file: /etc/xproxy/decoys/admin.html, status: 200}
bans:
  triggers:
    - {name: probes, reasons: [honeypot], threshold: 1, window: 10m, duration: 24h}
```

A scanner that asks for `/.env` receives a plausible file and is banned
on the spot; the security log records the request with reason
`honeypot`. Clients that touched a honeypot stay marked for an hour by
default: their later requests on every route carry
`honeypot_marked: true` in the access log, and a `bot_score` filter can
weigh the mark. `xproxyctl honeypot` lists the marks.

### gRPC services

```yaml
server:
  listeners:
    - name: rpc
      address: "10.0.0.5:8443"
      tls: {certificates: [{cert_file: /etc/xproxy/rpc.pem, key_file: /etc/xproxy/rpc.key}]}
    - name: rpc-internal
      address: "10.0.0.5:8080"
      h2c: true                     # plaintext HTTP/2 for in-cluster clients
upstreams:
  - name: orders
    h2c: true                       # the gRPC servers listen without TLS
    endpoints: [{address: 10.0.5.10:9000}, {address: 10.0.5.11:9000}]
    health_check: {type: grpc, grpc_service: orders.v1.Orders, interval: 5s}
  - name: catalog
    scheme: https
    endpoints: [{address: catalog.svc.internal:443}]
    health_check: {type: grpc}
routes:
  - name: orders
    grpc: {services: [orders.v1.Orders]}
    upstream: orders
    rate_limits: [api]
  - name: catalog-read
    grpc: {methods: [catalog.v1.Catalog/Get, catalog.v1.Catalog/List]}
    upstream: catalog
  - name: rpc-other
    grpc: {}
    respond: {status: 404}          # invalid: gRPC routes need an upstream
```

(Drop the last route: a request for an unlisted service gets
`grpc-status: 12 UNIMPLEMENTED` from the proxy on its own.) Health
checks use the standard health service, so an endpoint that reports
`NOT_SERVING` is taken out of rotation before clients see errors, and
a rate limited call is refused with `RESOURCE_EXHAUSTED` rather than a
text page a gRPC client cannot read.

### Routing by pattern, header and cookie

```yaml
routes:
  - name: canary
    hosts: [app.example.com]
    headers: [{name: X-Canary, exact: "1"}]
    upstream: app-v2
  - name: beta-testers
    hosts: [app.example.com]
    cookies: [{name: beta, present: true}]
    upstream: app-v2
  - name: item-api
    hosts: [app.example.com]
    path_regex: ['/api/v[0-9]+/items/[0-9]+']
    upstream: items
  - name: app
    hosts: [app.example.com]
    upstream: app-v1
```

A request with `X-Canary: 1` or a `beta` cookie reaches the new
version whatever its path; `/api/v3/items/42` reaches the item service
while `/api/v3/items/list` does not (patterns match the whole path);
everything else goes to the current version. Conditioned routes are
tried before the plain route on the same path, so the order above does
not matter. For a canary by share of traffic rather than by header,
use a `weighted` upstream; for one by header on the same route, see
`canary` on the upstream pool (traffic management).

### Response compression

```yaml
compression: {level: 5, min_bytes: 1024}
routes:
  - name: api
    hosts: [api.example.com]
    upstream: api                      # JSON compressed on the way out
  - name: account
    hosts: [www.example.com]
    paths: [/account]
    compress: false                    # pages with tokens: leave as they are
    upstream: web
```

One section turns gzip on for every route; a route opts out with
`compress: false`. Bodies the upstream already compressed, images,
ranges and `no-transform` responses pass through, small bodies are left
alone, and `Vary: Accept-Encoding` is set on everything that could be
compressed so shared caches stay correct. The access log shows
`encoding: gzip` on compressed answers and `xproxyctl status` counts
them.

### Static files and single page applications

```yaml
routes:
  - name: assets
    hosts: [app.example.com]
    paths: [/static]
    strip_prefix: /static
    static: {root: /srv/app/static, cache_control: "public, max-age=86400, immutable"}
  - name: spa
    hosts: [app.example.com]
    paths: [/]
    static: {root: /srv/app/dist, fallback: /index.html}
  - name: api
    hosts: [app.example.com]
    paths: [/api]
    upstream: api
```

Requests for `/static/app.js` serve `/srv/app/static/app.js` with an
`ETag`, ranges and conditional requests; anything under `/` that is not
a file in `/srv/app/dist` serves `index.html`, so client side routes
deep link; the API is proxied. Files are opened inside the root only,
dot files are never served, and a root that disappears fails the reload
rather than the site. Give the `xproxy` user read access to the tree
and, under SELinux, label it `httpd_sys_content_t` or the policy's
equivalent (SETUP.md). `static_served` and `static_not_found` count the
answers.

### Request mirroring

```yaml
upstreams:
  - name: api-v2
    endpoints: [{address: 10.0.4.10:8080}]
  - name: api-v3-candidate
    endpoints: [{address: 10.0.4.50:8080}]
routes:
  - name: api
    hosts: [api.example.com]
    upstream: api-v2
    mirror: {upstream: api-v3-candidate, percent: 10, methods: [GET], max_in_flight: 32}
```

One request in ten is copied to the candidate with `X-Xproxy-Mirror: 1`
and the same `X-Request-Id` as the live request, so the two backends'
logs can be joined. The client only ever sees the live response;
copies are bounded in body size, time and number in flight, and
dropped rather than queued when the candidate falls behind.

### Response caching

```yaml
cache: {max_bytes: 268435456, max_object_bytes: 2097152}
routes:
  - name: assets
    hosts: [www.example.com]
    paths: [/static/]
    cache: {ttl: 1h, headers: [Accept-Encoding]}
    upstream: web
  - name: api-public
    hosts: [api.example.com]
    paths: [/v1/public/]
    cache: {ttl: 10s, query: listed, query_params: [page, lang]}
    upstream: api
```

The upstream stays in control through `Cache-Control`; `xproxyctl cache
purge www.example.com /static/` drops entries after a deploy.

### Country policy (GeoIP)

```yaml
geoip: {database: /var/lib/xproxy/GeoLite2-Country.mmdb}   # or csv: /etc/xproxy/geo.csv
rate_limits:
  - {name: per-country, key: country, rate: 500, burst: 1000}
routes:
  - name: shop
    hosts: [shop.example.com]
    geo: {allow: [SE, NO, DK, FI], unknown: deny}
    rate_limits: [per-country]
    upstream: shop
  - name: api
    hosts: [api.example.com]
    geo: {deny: [KP]}
    upstream: api
```

`xproxyctl geoip` shows the database, its build date and lookup
counters. The database file is owned by root, group `xproxy`, mode
`0640`, and replaced atomically before `xproxyctl reload`.

### Bot classification

```yaml
challenge: {secret_file: /var/lib/xproxy/challenge.key}
filters:
  - name: bots
    kind: bot_score
    options:
      challenge_at: 50          # scripted clients solve the proof of work first
      deny_at: 85               # scanners and denied fingerprints are refused
      header: X-Bot-Score       # let the application decide on the rest
      ja4_allow: [t13d1516h2_8daaf6152771_b0da82dd1658]   # the monitoring probe
routes:
  - name: web
    hosts: [www.example.com]
    filters: [bots]
    upstream: web
```

Start with `deny_at` and `challenge_at` at 0 and `log_at: 1` for a day:
the access log then carries `bot_score`, `bot_signals` and `ja4` for
every request, which gives the fingerprints of your own tools for
`ja4_allow` and the score distribution for the thresholds.

### WebAssembly filters

```yaml
filters:
  - name: tenant-policy
    kind: wasm
    options:
      module: /etc/xproxy/filters/tenant-policy.wasm
      config: "allowed=acme,globex"
      timeout: 20ms
routes:
  - name: api
    hosts: [api.example.com]
    upstream: api
    filters: [tenant-policy]
```

The module decides per request from what it reads through the host
functions (method, path, headers, client address, country, JA4, its
own `config`), may add or remove headers in both directions, deny with
a status and reason of its own, and annotate the access log. It runs
with a memory bound and a deadline; a module that traps or overruns
fails closed unless `on_error: allow`. Build it with any toolchain that
targets WebAssembly; EXTENDING.md has the ABI and a minimal guest.

### Header policy and basic authentication (filters)

Filters are middleware instances attached to routes; the built-in kinds
are `header_guard` and `basic_auth` (`xproxyctl filters` lists what the
binary has; [EXTENDING.md](EXTENDING.md) shows how to add one).

```yaml
filters:
  - name: scanners
    kind: header_guard
    options:
      deny: [{header: User-Agent, pattern: "(?i)sqlmap|nikto|masscan|zgrab"}]
  - name: partner-key
    kind: header_guard
    options:
      require: [{header: X-API-Key, pattern: "^pk_[A-Za-z0-9]{32}$"}]
      status: 401
  - name: staff
    kind: basic_auth
    stage: before_auth
    options: {users_file: /etc/xproxy/staff.htpasswd, realm: staff, forward_user_header: X-Remote-User}

routes:
  - name: partner-api
    hosts: [api.example.com]
    paths: [/partner/]
    filters: [scanners, partner-key]
    upstream: api
  - name: intranet
    hosts: [intranet.example.com]
    filters: [staff]
    upstream: intranet
```

```sh
echo 'correct horse battery staple' | xproxyctl htpasswd /etc/xproxy/staff.htpasswd alice
chown root:xproxy /etc/xproxy/staff.htpasswd && chmod 0640 /etc/xproxy/staff.htpasswd
xproxyctl reload
xproxyctl filters
```

Denies are logged on the security stream with the filter name as reason
and can drive ban triggers (`categories: [scanners]`).

### Browser challenge

```yaml
challenge:
  secret_file: /var/lib/xproxy/challenge.key
  difficulty: 16
  ttl: 1h
routes:
  - {name: signup, hosts: [example.com], paths: [/signup], challenge: {mode: always}, upstream: web}
  - {name: web,    hosts: [example.com], challenge: {mode: load, level: 0.5}, upstream: web}
```

The signup page always requires a solved challenge. The rest of the site
requires one only while the load level is at or above 0.5, so a flood of
plain HTTP clients is turned away with a static page while browsers carry
on after a short delay. Do not gate API routes: clients without JavaScript
cannot pass. Give monitoring systems `exempt_cidrs`.

## Web GUI

`xproxy-admin` serves the browser interface. It is a separate process from
the data plane, holds no secrets of its own beyond its users file, and
forwards every action to the management socket, so everything it does is
in the audit log like a `xproxyctl` call.

```
xproxy-admin serve [-listen 127.0.0.1:8443] [-socket /run/xproxy/mgmt.sock]
                   [-config /etc/xproxy/xproxy.yaml] [-users /etc/xproxy/admin-users]
                   [-tls-cert PATH -tls-key PATH [-client-ca PATH]]
                   [-restart-cmd "systemctl restart xproxy.service"]
                   [-session-idle 30m] [-session-max 12h]
xproxy-admin user add NAME -role viewer|operator [-cert-only]
xproxy-admin user del NAME
xproxy-admin user list
xproxy-admin passwd NAME
```

Roles:

| Role | May |
|------|-----|
| `viewer` | See every screen: overview, upstreams, bans, graphs, cluster, certificates, ICAP, the configuration file and the logs |
| `operator` | Everything a viewer may, plus ban and unban, reload, reload certificates, reopen logs, renew certificates, edit and save the configuration file, restart the data plane |

Screens:

- **Overview**: version, uptime, generation, request and response counters,
  denials by reason, load level, listeners; the action buttons for
  operators.
- **Upstreams**: every endpoint with health, ejection, active requests and
  error counts, refreshed every five seconds.
- **Bans**: the active list with expiry, source and count; add a ban with a
  duration and reason (recorded as `admin:<user>: <reason>`), unban.
- **Graphs**: requests, denials, bytes, connections, load level, upstream
  latency, bans and cluster peers from the sampled series buffer, with a
  selectable window.
- **Cluster**, **Certificates** (ACME status with days left and a renew
  button), **ICAP** (service reachability and counters).
- **Config**: the active configuration as the data plane loaded it, and an
  editor for the file. *Validate* runs the full validation without
  touching the file and lists every problem; *Validate and save* writes
  the file atomically, keeps the previous version in `xproxy.yaml.bak`,
  and refuses to overwrite a file that changed since it was loaded;
  *Reload data plane* applies it.
- **Logs**: the last lines of a stream and a live follow with a substring
  filter and pause.

Access: the default listener is `127.0.0.1:8443` in plain HTTP, reached
through an SSH tunnel (`ssh -L 8443:127.0.0.1:8443 edge`). Binding to any
other address requires `-tls-cert`, `-tls-key` and `-client-ca`: the
browser must present a client certificate from that CA, and a certificate
whose common name matches a user logs that user in without a password
(`-cert-only` users have no password at all). Five failed logins from one
address lock it out for five minutes. Sessions end after thirty minutes
idle or twelve hours in total.

The first user:

```sh
xproxy-admin user add admin -role operator     # prompts for the password twice
xproxy-admin user add oncall -role viewer
```

## Live terminal view

`xproxyctl tui` opens a full-screen view that refreshes from the
management socket:

| Screen | Content |
|--------|---------|
| 1 Overview | Version, listeners, counters, shedding state, request and denied sparklines |
| 2 Upstreams | Endpoint health, ejection, in-flight, requests and errors |
| 3 Bans | Active bans; `j`/`k` select, `u` unban (confirm with `y`), `b` ban with `address [duration] [reason]` |
| 4 Cluster | Peers, inbound connections, message counters |
| 5 Graphs | Sparklines of the sampled series over the retention window |
| 6 Security log | Last events from the security log file (needs `-config` to locate it) |

Keys: `1` to `6` or `tab` and `shift-tab` switch screens, `r` refreshes,
`p` pauses, `+` and `-` change the interval, `q` quits. Bans and unbans
from the TUI go through the same audited API as the CLI.

## Metrics and graphs

Scrape through the socket with a local exporter, or enable the TCP
endpoint for Prometheus:

```yaml
metrics:
  listen: 10.0.0.1:9100
  allow_cidrs: [10.0.5.0/24]          # the Prometheus servers
  tls:
    cert_file: /etc/xproxy/certs/metrics.pem
    key_file: /etc/xproxy/certs/metrics-key.pem
    client_ca_file: /etc/xproxy/certs/monitoring-ca.pem
```

```sh
xproxyctl metrics | grep -E '^xproxy_(requests_total|load_level|denied_total)'
xproxyctl series -since 30m -last 12
```

Useful expressions: `rate(xproxy_denied_total[5m])` by `reason` for attack
activity, `histogram_quantile(0.99, rate(xproxy_upstream_ttfb_seconds_bucket[5m]))`
for backend health, `xproxy_shedding` to alert on load shedding,
`xproxy_upstream_endpoint_healthy == 0` for dead endpoints,
`xproxy_log_dropped_total` for a collector problem. The `series` command
shows the same numbers the TUI and GUI graph, sampled in process for the
configured retention, so a graph is available on a host with no
monitoring stack at all.

## Logs

All streams are JSON lines with `time`, `level`, `msg` and `stream`.

### Sinks

Each stream lists where it goes. A typical production setup keeps access
logs in files, sends security and audit events to journald and to a remote
collector, and lets journald handle operational messages:

```yaml
logging:
  directory: /var/log/xproxy
  access:   {file: access.log, max_size_mb: 512, max_files: 10, sinks: [file]}
  error:    {sinks: [journald]}
  security: {file: security.log, sinks: [file, journald, syslog]}
  audit:    {file: audit.log, sinks: [file, syslog]}
  journald: {identifier: xproxy}
  syslog:
    network: tcp+tls
    address: logs.example.internal:6514
    ca_file: /etc/xproxy/certs/logs-ca.pem
    server_name: logs.example.internal
    facility: local3
```

`journalctl -t xproxy XPROXY_STREAM=security` and
`journalctl XPROXY_CLIENT_IP=203.0.113.9` filter on the indexed fields.
`xproxyctl status` shows `log_syslog_sent`, `log_syslog_dropped` and
`log_journald_dropped`; drops mean the collector is slow or unreachable,
never that the proxy waited.

### Redaction

```yaml
logging:
  redaction:
    client_ip: hash
    hash_secret_file: /var/lib/xproxy/redaction.key
    user_agent: drop
    referer: origin
    claims: hash
    drop_fields: [sni]
```

With this in place the access, security and error streams carry a stable
pseudonym instead of the client address (the same client keeps the same
`h:` value across restarts and across nodes sharing the key file), no user
agent, referers cut to their origin and hashed token subjects, while the
audit stream keeps full detail. Set `enabled: false` to switch the rules
off temporarily during an incident without deleting them, and remember
that `xproxyctl bans` and the ban list itself still hold real addresses.

### access

One line per request:

```json
{"time":"...","level":"INFO","msg":"request","stream":"access","request_id":"6e74c0...","client_ip":"203.0.113.9","method":"GET","host":"example.com","path":"/","query_len":0,"proto":"HTTP/2.0","status":200,"bytes_in":0,"bytes_out":1234,"duration_ms":3.2,"route":"web","upstream":"web","endpoint":"10.0.1.10:8080","attempts":1,"user_agent":"...","referer":"","tls":"1.3","sni":"example.com"}
```

`denied` appears when the proxy rejected the request; `upstream_error` when
the upstream failed. Status 499 means the client left before a response.

### security

One line per deny, tarpit or dropped connection:

```json
{"time":"...","level":"WARN","msg":"security","stream":"security","action":"deny","reason":"rate_limit","request_id":"...","client_ip":"203.0.113.9","method":"POST","host":"example.com","path":"/login","route":"login","status":429,"user_agent":"..."}
```

Reasons: `concurrency`, `uri_length`, `bad_host`, `no_route`, `acl_deny`,
`acl_allow`, `rate_limit`, `rate_limit:<name>` (tarpit), `body_size`,
`websocket`, `waf`, `banned`, `max_connections`, `max_connections_per_ip`.

WAF entries add `waf_profile`, `waf_mode`, `waf_matched` (rule ids),
`waf_message`, `waf_score`, `waf_rule` (the interrupting rule), `waf_phase`.
Detections in `detect` mode appear on the access line with
`waf_detected: true`. Bans and unbans are logged with `msg: "client banned"`
and `"client unbanned"`, including trigger name, duration and count.

### error

Operational events: start, stop, listeners, reloads, upstream errors,
endpoint health transitions and ejections.

### audit

Management actions with the caller's uid, gid and pid, and every reload.

## Counters

`xproxyctl status` shows the counters used for graphs (1.0 adds a
Prometheus endpoint). Names match the JSON fields: `requests`,
`responses_2xx` to `responses_5xx`, `bytes_in`, `bytes_out`, `denied_*`,
`tarpitted`, `upstream_errors`, `upstream_timeouts`, `upstream_no_healthy`,
`client_aborts`, `denied_ban`, `denied_waf`, `waf_detected`, `bans_active`,
`bans_total`, `cluster_peers`, `cluster_connected`, `shed`, `load_level`,
`upstream_latency_ms`, `shedding_classes`, `challenges_issued`,
`challenges_passed`, `challenges_failed`, `reloads`, `reload_failures`,
`open_connections`, `rejected_connections`, `in_flight`.

## Troubleshooting

| Symptom | Check |
|---------|-------|
| `config: ... no such file or directory` | Certificate or CA paths; `xproxy -validate` lists all problems at once |
| 404 for a host you configured | Host matching is exact or single label wildcard; check the `host` field in the access log |
| 403 with `reason: acl_allow` | The client address is not in `allow_cidrs`; if behind a proxy, set `trusted_proxies` |
| 401 with `WWW-Authenticate: Bearer` | JWT missing or invalid; the security log names the category (expired, signature, issuer, audience, algorithm, unknown_key) |
| 503 on a JWT route with `detail: keys_unavailable` | The provider's key set never loaded; check `jwks_url` and `jwks_ca_file` in the error log |
| 502 to an https upstream after enabling pins or mTLS | `xproxyctl spki` on the upstream certificate; check the client certificate is issued by the CA the upstream trusts |
| Scanner block page (status from the scanner, `reason: icap`) | The ICAP service replaced the request or response; `icap_verdict: replaced` in the access line |
| 502 with `detail: reqmod_unavailable` | The ICAP service failed or timed out and `fail: closed`; `xproxyctl icap` |
| 403 with `reason: waf` | A rule blocked the request; `waf_matched` names the rules. Add an exclusion or lower the paranoia level for that route |
| 403 with `reason: banned` or connections closed immediately | `xproxyctl bans`; unban or add the range to `exempt_cidrs` |
| Reload fails with a WAF compile error | The error names the file and line of the bad directive; the old rules stay active |
| 413 immediately | `Content-Length` above `max_body_bytes` |
| 429 with `Retry-After` | Rate limit; `denied` names the policy |
| 502 | Upstream connection failed; see `upstream_error` in access and the error log |
| 503 with `Retry-After: 5` | No healthy endpoint; `xproxyctl upstreams` |
| 503 with `Retry-After: 1` | Concurrency ceiling reached |
| 503 with `Retry-After: 2` and `denied: shed:<class>` in the access log | Load shedding; check `load_level` and upstream latency |
| 503 HTML page titled "Checking your browser" | Challenge gate; a browser solves it, an API client cannot |
| Reload says listener changed | Restart instead; sockets may be systemd owned |
| `management socket ... already in use` | Another xproxy is running |
