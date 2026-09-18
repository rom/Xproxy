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

## Logs

All streams are JSON lines with `time`, `level`, `msg` and `stream`.

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
`websocket`, `max_connections`, `max_connections_per_ip`.

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
`client_aborts`, `reloads`, `reload_failures`, `open_connections`,
`rejected_connections`, `in_flight`.

## Troubleshooting

| Symptom | Check |
|---------|-------|
| `config: ... no such file or directory` | Certificate or CA paths; `xproxy -validate` lists all problems at once |
| 404 for a host you configured | Host matching is exact or single label wildcard; check the `host` field in the access log |
| 403 with `reason: acl_allow` | The client address is not in `allow_cidrs`; if behind a proxy, set `trusted_proxies` |
| 413 immediately | `Content-Length` above `max_body_bytes` |
| 429 with `Retry-After` | Rate limit; `denied` names the policy |
| 502 | Upstream connection failed; see `upstream_error` in access and the error log |
| 503 with `Retry-After: 5` | No healthy endpoint; `xproxyctl upstreams` |
| 503 with `Retry-After: 1` | Concurrency ceiling reached |
| Reload says listener changed | Restart instead; sockets may be systemd owned |
| `management socket ... already in use` | Another xproxy is running |
