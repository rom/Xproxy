# Configuration reference

xproxy reads one YAML document. Unknown keys are errors. Every omitted value
takes the default listed here; a zero duration or count means "default",
never "disabled". Paths must be absolute. Durations use Go syntax: `500ms`,
`10s`, `5m`, `1h`. Names match `[A-Za-z0-9][A-Za-z0-9_.-]{0,63}`.

Validate with `xproxy -config FILE -validate`; all problems are reported at
once. The example in `deploy/config/xproxy.yaml` exercises most keys.

## Top level

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `version` | int | required | Schema version. Must be `1`. |
| `server` | object | | Listeners and global limits |
| `management` | object | | Control socket |
| `logging` | object | | Log streams |
| `trusted_proxies` | list of CIDR | `[]` | Peers whose `X-Forwarded-For` is believed. Empty means never. |
| `rate_limits` | list | `[]` | Named rate limit policies |
| `upstreams` | list | `[]` | Named endpoint pools |
| `routes` | list | `[]` | Request matching and actions |

## server

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `listeners` | list | required, at least one | See below |
| `limits` | object | | Global protections |
| `server_header` | string | `""` | Value of the `Server` response header. Empty removes it. |
| `shutdown_timeout` | duration | `30s` | Drain time on stop and for old generations after reload |

### server.listeners[]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | name | required, unique | Also used to match systemd socket names |
| `address` | host:port | required | `":443"`, `"0.0.0.0:80"`, `"[::1]:8080"`. Port `0` picks a free port (tests). |
| `protocols` | list | `[h1, h2]` with TLS, `[h1]` without | `h2` and `h3` require `tls`. `h3` adds a QUIC endpoint on UDP at the same port and requires `h1` or `h2` alongside it (clients discover HTTP/3 through `Alt-Svc`). |
| `h3` | object | defaults when `h3` is listed | QUIC tuning; see below |
| `tls` | object | none | TLS termination; see below |
| `proxy_protocol` | bool | `false` | Reserved (PROXY protocol parsing arrives in 1.0) |
| `redirect_to_https` | bool | `false` | Answer every request with 308 to `https://host/path?query`. Plaintext listeners only. |

### server.listeners[].h3

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `max_streams` | int | `100` | Concurrent request streams per QUIC connection; 1 to 10000 |
| `validate_addresses` | `always`, `under_load` | `always` | `always` makes every unvalidated client address complete a Retry round trip before the server allocates connection state; `under_load` does so only when open connections exceed a quarter of `max_connections` |
| `alt_svc_max_age` | duration | `24h` | Reserved for the `Alt-Svc` `ma` value (currently the library default) |

QUIC connections share the listener's `max_connections`,
`max_connections_per_ip`, ban list, header size and idle timeout;
`read_header_timeout` bounds the handshake. `read_timeout` and
`write_timeout` do not apply to HTTP/3 streams; use route `timeout` and
upstream `total` for those. 0-RTT is never enabled.

### server.listeners[].tls

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `certificates` | list | one of `certificates` or `acme` | `{cert_file, key_file}` PEM pairs; selected by SNI, first is the fallback |
| `acme` | list | | `{hosts: [...]}` groups issued and renewed through the top-level `acme` section; one certificate per group, named after its first host. Hosts are fully qualified names without wildcards and unique across the listener. Selected by SNI after the file certificates |
| `min_version` | `"1.2"` or `"1.3"` | `"1.2"` | TLS 1.0 and 1.1 cannot be configured |
| `client_auth` | `none`, `request`, `require` | `none` | Client certificates; `request` verifies if presented |
| `client_ca_file` | path | | Required for `request` and `require` |
| `cipher_suites` | list of names | ECDHE AEAD suites | TLS 1.2 suites, crypto/tls names. Insecure suites are rejected. TLS 1.3 suites are not configurable. |

### server.limits

| Key | Type | Default | Range | Description |
|-----|------|---------|-------|-------------|
| `max_header_bytes` | int | `65536` | 1024 to 1 MiB | Request header block, including HTTP/2 header list |
| `max_body_bytes` | int | `10485760` | 0 or more | Request body; `0` disables the global cap (routes can still set one) |
| `max_uri_length` | int | `8192` | 256 to 65536 | Request line target length; 414 above |
| `read_header_timeout` | duration | `10s` | positive | Slowloris defence |
| `read_timeout` | duration | `60s` | positive | Whole request including body |
| `write_timeout` | duration | `60s` | positive | Whole response |
| `idle_timeout` | duration | `120s` | positive | Keep-alive idle |
| `max_connections` | int | `65536` | positive | Open connections across all listeners |
| `max_connections_per_ip` | int | `256` | positive, at most `max_connections` | Per source address |
| `max_concurrent_requests` | int | `16384` | positive | In-flight requests; 503 above |

## management

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `socket` | path | `""` (disabled) | Unix socket for `xproxyctl` |
| `socket_mode` | octal string | `"0660"` | Any `other` permission is rejected |

## logging

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `directory` | path | `/var/log/xproxy` | Must exist and be writable |
| `level` | `debug`, `info`, `warn`, `error` | `info` | Minimum level for the error stream |
| `stdout` | bool | `false` | Mirror all streams to stdout (journald, containers) |
| `access`, `error`, `security`, `audit` | stream | | Per stream settings |
| `journald` | object | none | journald sink, used by streams listing `journald` |
| `syslog` | object | none | syslog sink, used by streams listing `syslog` |
| `redaction` | object | none | Personal data rules applied before every sink |

### logging.<stream>

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | |
| `file` | file name | `access.log` etc. | Bare name inside `directory` |
| `max_size_mb` | int | `0` (no internal rotation) | Rotate to `.1`, `.2`, ... when exceeded |
| `max_files` | int | `5` | Archives kept |
| `sinks` | list | `[file]` | Any of `file`, `journald`, `syslog`; a stream can go to several |

### logging.journald

Native journald protocol over the journal's datagram socket, no cgo. The
JSON line is `MESSAGE`; the level maps to `PRIORITY`; the stream and every
top-level attribute become `XPROXY_*` fields, so
`journalctl XPROXY_CLIENT_IP=203.0.113.9` works without parsing.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `socket` | path | `/run/systemd/journal/socket` | |
| `identifier` | name | `xproxy` | `SYSLOG_IDENTIFIER` |

### logging.syslog

Messages are queued and sent by a background writer; the request path
never waits for a collector. A full queue drops and counts. Stream
transports use RFC 6587 octet counting and reconnect with back-off.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `network` | `unix`, `udp`, `tcp`, `tcp+tls` | `unix` | |
| `address` | path or host:port | `/dev/log` for unix | |
| `format` | `rfc5424`, `rfc3164` | `rfc3164` for unix, else `rfc5424` | The JSON line is the message; the stream is the RFC 5424 MSGID |
| `facility` | name | `local0` | `kern`, `user`, `mail`, `daemon`, `auth`, `syslog`, `lpr`, `news`, `uucp`, `cron`, `authpriv`, `ftp`, `local0` to `local7` |
| `app_name` | name | `xproxy` | APP-NAME or tag |
| `hostname` | string | OS host name | |
| `ca_file`, `cert_file`, `key_file`, `server_name` | | | `tcp+tls`: pinned CA, optional client certificate, verified name |
| `queue_size` | int | `8192` | Messages held for a slow collector; 64 to 1000000 |

Datagram transports truncate messages at 8 KiB.

### logging.redaction

Presence enables the rules; `enabled: false` switches them off while
keeping the configuration. Rules run before every sink, so files, journald
and syslog all receive the same redacted record.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | |
| `streams` | list | `[access, security, error]` | The audit stream keeps full detail unless listed |
| `client_ip` | `keep`, `truncate`, `hash` | `truncate` | `truncate` masks to /24 (IPv4) or /48 (IPv6); `hash` writes a keyed pseudonym (`h:` + 16 hex) that is stable per key and lets you correlate one client across lines without storing the address |
| `hash_secret_file` | path | ephemeral | Key for `hash`; set it so pseudonyms survive restarts and match across nodes |
| `user_agent` | `keep`, `drop` | `keep` | |
| `referer` | `keep`, `origin`, `drop` | `origin` | `origin` keeps scheme and host only |
| `claims` | `keep`, `hash`, `drop` | `hash` | Applies to `jwt_*` (except `jwt_provider`) and `client_cn` |
| `drop_fields` | list | `[]` | Further attribute names removed from lines; `time`, `level`, `msg` and `stream` cannot be dropped |

## rate_limits[]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | name | required, unique | Referenced by routes |
| `key` | `client_ip`, `route`, `header:<Name>` | `client_ip` | Bucket identity. A missing header falls back to the client address. |
| `rate` | float | required, positive | Tokens per second |
| `burst` | int | `rate` rounded, at least 1 | Bucket capacity |
| `action` | `reject`, `tarpit` | `reject` | `reject` answers 429 at once |
| `tarpit_delay` | duration | `10s` | Hold before answering 429 (released on client disconnect) |

Memory: at most 64 x 8192 buckets per policy.

## upstreams[]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | name | required, unique | |
| `balancer` | `round_robin`, `weighted`, `least_conn`, `hash` | `round_robin` | |
| `hash_on` | `client_ip`, `header:<Name>`, `cookie:<Name>` | `client_ip` | For `hash`; missing input falls back to the client address |
| `endpoints` | list | required, at least one | `{address: host:port, weight: 1..1000}` |
| `scheme` | `http`, `https` | `http` | |
| `tls` | object | | Only with `https`; see below |
| `health_check` | object | none | Active probing; see below |
| `outlier_ejection` | object | none | Passive ejection; see below |
| `affinity` | object | none | Cookie stickiness; see below |
| `timeouts.connect` | duration | `5s` | Dial and TLS handshake |
| `timeouts.response_header` | duration | `30s` | Time to first response byte |
| `timeouts.idle` | duration | `90s` | Pooled connection idle |
| `timeouts.total` | duration | `5m` | Whole exchange |
| `max_idle_conns_per_host` | int | `64` | Pooled connections per endpoint |
| `retries` | int | `1` | 0 to 5; only replayable requests, only on connection errors |

### upstreams[].tls

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `server_name` | string | endpoint host | SNI and verification name |
| `ca_file` | path | system pool | PEM bundle to verify against |
| `min_version` | `"1.2"`, `"1.3"` | `"1.2"` | Minimum TLS version towards the upstream |
| `client_cert_file`, `client_key_file` | path | | Mutual TLS to the upstream; set both. Re-read by `xproxyctl reload-certs` and by configuration reload; idle connections are dropped so new ones present the new certificate |
| `spki_pins` | list of base64 SHA-256 | `[]` | Pins of the upstream leaf public key; the connection is refused unless the presented leaf matches one, in addition to chain verification. `xproxyctl spki CERT.pem` prints a pin. Cannot be combined with `insecure_skip_verify` |
| `insecure_skip_verify` | bool | `false` | Requires `allow_insecure: true` as well |
| `allow_insecure` | bool | `false` | Second opt-in |

### upstreams[].health_check

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `path` | path | `/` | GET target |
| `interval` | duration | `5s` | At least 500ms; start is jittered |
| `timeout` | duration | `2s` | Must be shorter than `interval` |
| `healthy_threshold` | int | `2` | Consecutive successes to mark healthy |
| `unhealthy_threshold` | int | `3` | Consecutive failures to mark unhealthy |
| `expected_status` | list of int | `[200]` | |
| `max_concurrent` | int | `32` | Probes in flight per pool; 1 to 4096. Bounds the burst when a pool has thousands of endpoints |
| `keep_alive` | bool | `false` | Reuse pooled connections for probes. Off opens a fresh connection per probe (verifies the whole connect path, no descriptor held between probes); on saves the handshake at the cost of one idle connection per endpoint |

### upstreams[].outlier_ejection

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `consecutive_failures` | int | `5` | Connection errors or 503 responses in a row |
| `base_ejection_time` | duration | `30s` | Multiplied by the ejection count, capped at 10x |
| `max_ejection_percent` | int | `50` | Never eject more than this share of the pool |

### upstreams[].affinity

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `cookie_name` | token | `XPSESS` | |
| `ttl` | duration | `1h` | Cookie and signature lifetime |
| `secret_file` | path | ephemeral | HMAC key, created `0600` on first use if absent |

## routes[]

Matching: exact host, then wildcard host, then hostless routes; within a
host the longest path prefix; then `methods`; then `priority` (higher
wins); then configuration order.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | name | required, unique | Appears in logs |
| `hosts` | list | `[]` (any) | `example.com` or `*.example.com` (one label) |
| `paths` | list | `["/"]` | Prefixes on segment boundaries |
| `methods` | list | `[]` (any) | Upper-case tokens |
| `priority` | int | `0` | Tie breaker |
| `upstream` | name | | Exactly one of `upstream`, `redirect`, `respond` |
| `redirect` | `{to, status}` | status `308` | `to` is a URL or path; status 301, 302, 303, 307 or 308 |
| `respond` | `{status, body}` | status `200` | Static response, body up to 64 KiB |
| `strip_prefix` | path | | Remove this prefix before forwarding |
| `rewrite_path` | path | | Replace the path entirely; exclusive with `strip_prefix` |
| `host_header` | string | client `Host` | Host sent upstream |
| `request_headers` | `{set, add, remove}` | | Applied before forwarding; values may not contain CR, LF or NUL |
| `response_headers` | `{set, add, remove}` | | Applied to responses, including redirect and respond actions |
| `rate_limits` | list of names | `[]` | Evaluated in order; first exhausted policy acts |
| `allow_cidrs` | list | `[]` (all) | Client must be inside one |
| `deny_cidrs` | list | `[]` | Evaluated first |
| `max_body_bytes` | int | global | May only lower the global limit |
| `timeout` | duration | none | Whole request deadline for this route |
| `websocket` | bool | `false` | Allow `Upgrade` requests |

## metrics

The management socket always serves `/metrics` in Prometheus text format
and `/v1/series` with sampled series. This section adds an optional TCP
endpoint for scrapers and sizes the series buffer.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `listen` | host:port | `""` (disabled) | Serves only `/metrics`. Binding all interfaces requires `tls` with `client_ca_file` |
| `allow_cidrs` | list | `[]` (any) | Scraper source addresses; others get 403 and a security event |
| `tls.cert_file`, `tls.key_file` | path | | Make the endpoint HTTPS |
| `tls.client_ca_file` | path | | Require client certificates from this CA (mutual TLS) |
| `per_route` | bool | `true` | Expose `xproxy_route_requests_total{route,outcome}` (one series per route and outcome) |
| `endpoint_series` | bool | `true` | Expose five series per upstream endpoint (`xproxy_upstream_endpoint_*`). About 1 KiB per endpoint per scrape; turn off above a few thousand endpoints and rely on the per-pool `xproxy_upstream_endpoints_healthy` |
| `sample_interval` | duration | `10s` | Series sampling period; 1s to 5m |
| `retention` | duration | `1h` | Series kept in memory; at most 100000 points |

Exposed families: `xproxy_requests_total`, `xproxy_responses_total{class}`,
`xproxy_denied_total{reason}`, `xproxy_bytes_in_total`,
`xproxy_bytes_out_total`, `xproxy_waf_detected_total`,
`xproxy_upstream_errors_total`, `xproxy_upstream_timeouts_total`,
`xproxy_upstream_no_healthy_total`, `xproxy_client_aborts_total`,
`xproxy_connections_rejected_total`, `xproxy_reloads_total{result}`,
`xproxy_bans_total`, `xproxy_challenges_total{result}`,
`xproxy_log_sent_total{sink}`, `xproxy_log_dropped_total{sink}`,
`xproxy_connections_open`, `xproxy_requests_in_flight`,
`xproxy_bans_active`, `xproxy_load_level`,
`xproxy_upstream_latency_seconds`, `xproxy_shedding{class}`,
`xproxy_cluster_peers`, `xproxy_cluster_peers_connected`,
`xproxy_cluster_messages_total{direction,type}`,
`xproxy_cluster_rejected_total`, `xproxy_request_duration_seconds`
(histogram), `xproxy_upstream_ttfb_seconds` (histogram),
`xproxy_upstream_endpoint_{healthy,ejected,active}{upstream,endpoint}`,
`xproxy_upstream_endpoint_{requests,errors}_total{upstream,endpoint}`,
`xproxy_route_requests_total{route,outcome}`, `xproxy_build_info`,
`xproxy_uptime_seconds`, `xproxy_config_generation`.

Series (per-second rates for counters, current values for gauges):
`requests`, `responses_2xx`, `responses_4xx`, `responses_5xx`, `denied`,
`shed`, `bytes_in`, `bytes_out`, `upstream_errors`, `open_connections`,
`in_flight`, `load_level`, `upstream_latency_ms`, `bans_active`,
`cluster_connected`.

## bans

Present means enabled. Bans apply before routing; banned peers are closed
at accept when `action` is `drop`, and answered 403 when the client address
comes from a trusted proxy chain or `action` is `reject`.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `state_file` | path | `""` (memory only) | bbolt file that persists bans across restarts |
| `max_entries` | int | `100000` | Bound on banned addresses; the soonest expiring are evicted when full |
| `exempt_cidrs` | list | `[]` | Never banned, by trigger or by operator |
| `action` | `drop`, `reject` | `drop` | Close at accept, or answer 403 only |
| `triggers` | list | `[]` | Automatic bans; see below |

### bans.triggers[]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | name | required, unique | Appears in the ban entry as `trigger:<name>` |
| `reasons` | list | `[]` (all) | Deny categories that count: `acl`, `rate_limit`, `waf`, `body_size`, `uri_length`, `bad_host`, `no_route`, `websocket`, `concurrency` |
| `threshold` | int | required | Denies within `window` that trigger the ban |
| `window` | duration | required | At most 24h |
| `duration` | duration | required | First ban length |
| `escalation` | float | `2` | Multiplier applied for each repeat ban of the same address |
| `max_duration` | duration | `24h` | Cap on escalated duration; at least `duration` |

Manual bans (`xproxyctl ban`) accept addresses and CIDRs no wider than /8
(IPv4) or /32 (IPv6); loopback and unspecified addresses are refused.

## waf

Present means enabled. Routes without a `waf` block use `default_mode` and
`default_profile`. Profiles compile at load and at reload; a broken rule
set fails the reload.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `profiles` | list | required, at least one | Rule sets; see below |
| `default_mode` | `off`, `detect`, `block` | `block` | `detect` logs what `block` would have done |
| `default_profile` | name | `default` | |
| `request_body_limit` | int | `1048576` | Bytes of request body inspected; 1024 to 1 GiB |
| `request_body_limit_action` | `reject`, `partial` | `reject` | 413 above the limit, or inspect the first bytes and pass the rest |
| `inspect_responses` | bool | `false` | Enable response header and body rules (data leakage) |
| `response_body_limit` | int | `524288` | Larger response bodies pass uninspected |
| `response_mime_types` | list | text and JSON/XML types | Bodies with other content types are not inspected |

### waf.profiles[]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | name | required, unique | |
| `crs` | object | none | Enable the bundled OWASP Core Rule Set |
| `crs.paranoia_level` | int | `1` | 1 to 4 |
| `crs.inbound_threshold` | int | `5` | Anomaly score that blocks a request |
| `crs.outbound_threshold` | int | `4` | Anomaly score that blocks a response |
| `directive_files` | list of paths | `[]` | SecLang files loaded after CRS setup and before CRS rules (exclusions go here) |
| `directives` | string | `""` | Inline SecLang loaded in the same position, at most 1 MiB |

A profile needs at least one of `crs`, `directive_files` or `directives`.

### routes[].waf

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `mode` | `off`, `detect`, `block` | `waf.default_mode` | |
| `profile` | name | `waf.default_profile` | |

## cluster

Present means enabled. Nodes exchange rate limit consumption and ban
changes over mutual TLS (AMR-009, AMR-021). Every node listens and dials
every peer; there is no leader. Enabling or disabling the section, and
changing `listen`, `node_id` or `tls`, require a restart. Peers, intervals
and sharing flags reload.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `node_id` | name | host name | Identity announced to peers and used as the ban source (`peer:<node_id>`) |
| `listen` | host:port | required | Cluster listener. Must be a specific internal address, not all interfaces |
| `peers` | list of host:port | `[]` | Cluster addresses of the other nodes |
| `tls.cert_file`, `tls.key_file` | path | required | This node's certificate, used for both directions |
| `tls.ca_file` | path | required | Cluster CA; every peer must present a certificate from it |
| `tls.allowed_names` | list | `[]` (any name from the CA) | Restrict peers to these certificate common names or DNS SANs |
| `gossip_interval` | duration | `1s` | How often consumption and ban batches are sent; 100ms to 60s |
| `peer_stale` | duration | 3 x `gossip_interval` | How long a peer report keeps reducing local refill after its last update; at least 2 x the interval |
| `share_rate_limits` | bool | `true` | Exchange consumption reports |
| `share_bans` | bool | `true` | Exchange bans and unbans, and send a snapshot to a newly connected peer |
| `max_keys_per_report` | int | `4096` | Largest consumers kept per report |

Semantics: with sharing on, a rate limit policy's `rate` becomes an
approximate cluster wide rate per key. Each node refills a key's bucket at
`rate` minus the sum of fresh peer consumption for that key; `burst` stays
per node. Accuracy is bounded by one gossip interval of delay and reports
expire after `peer_stale`, so losing a peer degrades to local limiting.

The cluster listener can be socket activated with `FileDescriptorName=cluster`.

## jwt

Present means providers are available; routes opt in with a `jwt` block.
Tokens are validated on the standard library: RSA (PKCS#1 v1.5 and PSS),
ECDSA, Ed25519 and HMAC signatures, JSON Web Key Sets from a file or an
HTTPS URL, and the standard time and audience claims. `none` is never
accepted.

### jwt.providers[]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | name | required, unique | Referenced by routes |
| `issuer` | string | required | Must equal the token's `iss` |
| `audiences` | list | `[]` (any) | The token's `aud` must contain one; set it |
| `algorithms` | list | `[RS256, ES256, EdDSA]` | Allow list from RS256/384/512, PS256/384/512, ES256/384/512, EdDSA, HS256/384/512 |
| `jwks_file` | path | | Key set on disk, re-read on reload |
| `jwks_url` | https URL | | Key set fetched at start, every `jwks_refresh`, and on an unknown key id (at most once a minute) |
| `jwks_ca_file` | path | system pool | CA pinned for the fetch |
| `jwks_refresh` | duration | `1h` | At least 1m |
| `hmac_secret_file` | path | | Shared secret (at least 32 bytes) for HS algorithms; symmetric keys are never taken from a key set |
| `clock_skew` | duration | `30s` | Tolerance on `exp`, `nbf` and `iat`; 0 to 10m |
| `required_claims` | list | `[]` | Claims that must be present; `exp` always is |
| `source` | `bearer`, `header:<Name>`, `cookie:<Name>` | `bearer` | Where the token is read from |
| `forward_claims` | map header -> claim | `{}` | Set upstream headers from claims; client supplied copies of these headers are always removed, token or not. `Authorization`, `Cookie` and `Host` cannot be targets |
| `strip_token` | bool | `true` | Remove the token before forwarding |
| `log_claims` | list | `[]` | Claims copied to the access log as `jwt_<claim>` |

A provider whose key set has never loaded (for example the JWKS URL is
unreachable at start) rejects tokens with 503 and `Retry-After` until a
fetch succeeds; a fetch that returns no keys keeps the previous set.

### routes[].jwt

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `provider` | name | required | |
| `required` | bool | `true` | `false` lets requests without a token through (spoofed claim headers still removed) and rejects invalid ones |

Rejections answer 401 with `WWW-Authenticate: Bearer` (`error="invalid_token"`
for a present but invalid token), are logged with the failure category
(expired, signature, issuer, audience, algorithm, unknown_key, claim,
malformed) and feed ban triggers under the `jwt` category. The JWT filter
runs before the WAF on the same route.

## icap

Present means scanning services are available; routes opt in with an
`icap` block. Requests (REQMOD) and responses (RESPMOD) are handed to the
service per RFC 3507 with preview and `204 No Content` support. A
`200` answer with an encapsulated response is sent to the client as is
(a block page); one with an encapsulated request replaces the method, path,
headers and body sent upstream, except the protected headers (`Host`, the
forwarding headers, `Authorization`, `Cookie`).

### icap.services[]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | name | required, unique | Referenced by routes |
| `url` | `icap://host[:port]/service` or `icaps://...` | required | Default ports 1344 and 11344 |
| `tls.ca_file`, `tls.server_name` | | | Pinned CA and verified name for `icaps` |
| `connect_timeout` | duration | `2s` | |
| `timeout` | duration | `5s` | Whole exchange; at most 2m |
| `max_conns` | int | `8` | Pooled idle connections |
| `max_body` | int | `10485760` | Largest body sent for scanning; 1024 to 1 GiB |
| `body_limit_action` | `reject`, `bypass` | `reject` | 413, or pass unscanned and count as bypassed |
| `fail` | `closed`, `open` | `closed` | On a service error or timeout: 502 with `Retry-After`, or pass unscanned and count as bypassed |
| `preview` | `auto`, `off`, bytes | `auto` | Preview size from OPTIONS, none, or a fixed count |

The service is probed with OPTIONS at load and reload; an unreachable
service is logged, not fatal, and behaves according to `fail` until it
answers.

### routes[].icap

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `service` | name | required | |
| `request` | bool | `true` | Send requests (REQMOD) |
| `response` | bool | `false` | Send responses (RESPMOD); the response body is buffered up to `max_body` |

Blocks are logged with reason `icap` and feed ban triggers under the
`icap` category. The ICAP filter runs after JWT and WAF on the same route.

## filters[]

Middleware instances of registered kinds, attached to routes by name
(`routes[].filters`). `xproxyctl filters` lists the kinds compiled into
the binary; [EXTENDING.md](EXTENDING.md) describes how to add one.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | name | required, unique | Referenced by routes; the default deny reason |
| `kind` | name | required | A registered kind: `header_guard`, `basic_auth`, or one added to `internal/filters` |
| `stage` | `before_auth`, `after_auth`, `after_waf`, `after_scan` | `after_auth` | Position relative to the built-in JWT, WAF and ICAP filters |
| `options` | mapping | | Kind specific; unknown keys are rejected |

### Kind `header_guard`

Requires or denies requests by header patterns (RE2 syntax).

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `require` | list of `{header, pattern}` | | Every rule must match the header's value (a missing header is the empty string) |
| `deny` | list of `{header, pattern}` | | Any match denies; evaluated before `require` |
| `status` | int | `403` | 4xx status on deny |
| `reason` | string | the filter name | Deny reason in logs, counters and ban triggers |

### Kind `basic_auth`

HTTP Basic authentication against a file of `name:hash` lines written by
`xproxyctl htpasswd FILE NAME` (PBKDF2-HMAC-SHA256, 600 000 iterations;
the file must not be world readable). Verified credentials are cached by
digest so the hash cost is paid once per client session.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `users_file` | path | required | Users file |
| `realm` | string | `restricted` | `WWW-Authenticate` realm |
| `cache_ttl` | duration | `5m` | Credential cache; `0` disables |
| `forward_user_header` | header | none | Set to the user name on the upstream request |
| `strip` | bool | `true` | Remove `Authorization` before forwarding |

Denies answer 401 with `WWW-Authenticate` and reason `<filter name>`;
the user name is added to the access log line as `auth_user`.

### routes[].filters

A list of filter names, run in the listed order within each stage. A
route may combine them with `jwt`, `waf` and `icap`.

## acme

Required when any listener has `tls.acme` groups. One account per proxy;
the account key, account URL and issued certificates live under
`state_dir` (mode `0700`, files `0600`), so a restart serves the existing
certificates immediately and only renews what is due.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `directory` | `https://` URL | required | The CA's directory (RFC 8555) |
| `email` | address | required | Account contact |
| `accept_terms` | bool | must be `true` | Agree to the CA's terms on registration |
| `ca_file` | path | system pool | Pins the CA of the directory server (private CAs, tests) |
| `state_dir` | absolute path | `/var/lib/xproxy/acme` | Account and certificates; must be writable by the service (it is under `StateDirectory` in the shipped unit) |
| `challenge` | `http-01`, `tls-alpn-01` | `http-01` | `http-01` answers `/.well-known/acme-challenge/` on every plaintext listener before the HTTPS redirect and routing; `tls-alpn-01` answers the `acme-tls/1` ALPN on the TLS listener |
| `renew_before` | duration | `720h` | Renew when less than this remains; 24h to 89 days |
| `check_interval` | duration | `12h` | How often expiry is checked; 1m to 7d. A failed order backs off one hour |

Orders use a fresh P-256 key per certificate and an ES256 account key.
A certificate is installed only after the returned chain is verified to
cover every host in the group. Status is at `GET /v1/acme` and
`xproxyctl acme`; `xproxyctl acme renew` forces renewal of every group
and waits for the outcome (a renewal already running is joined, not
duplicated).

## shedding

Present means enabled. The load level is the larger of the in-flight
ratio (`in_flight / max_concurrent_requests`) and the latency level
(`(latency - target) / target`, capped at 1, where latency is the average
upstream time to first byte over `window`). A class is shed with 503 while
the level is at or above its threshold and admitted again once the level
falls below the threshold minus `hysteresis`. Critical routes are never
shed. A window without samples drains the latency signal, so shedding
never locks in.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `target_latency` | duration | `250ms` | Upstream time to first byte the site is designed for |
| `window` | duration | `10s` | Averaging window; 1s to 10m |
| `low`, `normal`, `high` | float | `0.6`, `0.8`, `0.95` | Shed thresholds per class; must be non-decreasing |
| `hysteresis` | float | `0.1` | Readmission margin below the threshold |
| `retry_after` | duration | `2s` | `Retry-After` on shed responses |

### routes[].priority_class

`low`, `normal` (default), `high` or `critical`. Put health checks, login
and payment on `critical` or `high`; search, feeds and exports on `low`.

## challenge

Present means the challenge engine is available; routes opt in with a
`challenge` block. Unverified clients receive a 503 page with a signed
nonce and a script that finds a SHA-256 proof of work, posts it to
`/.xproxy/challenge`, and receives a signed cookie. Both reserved paths
(`/.xproxy/challenge` and `/.xproxy/challenge.js`) are served on every
host before routing.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `secret_file` | path | ephemeral | HMAC key for nonces and cookies; set it so cookies survive restarts and are valid across a cluster |
| `difficulty` | int | `16` | Leading zero bits required; 8 to 24. 16 is roughly 65 000 hashes, under a second in a browser |
| `ttl` | duration | `1h` | Validity of a passed challenge; at least 1m |
| `bind_ip` | bool | `true` | Cookie and nonce are bound to the client address |
| `cookie_name` | token | `XPCHAL` | |
| `exempt_cidrs` | list | `[]` | Never challenged (monitoring, partners) |
| `title` | string | `Checking your browser` | Heading on the page; no HTML characters |

### routes[].challenge

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `mode` | `off`, `always`, `load` | `always` | `load` challenges only while the shedding load level is at or above `level` and requires a `shedding` section |
| `level` | float | `0.5` | Activation level for `load` mode |

The challenge is for browser-facing routes: API clients cannot solve it.

## Headers set on forwarded requests

| Header | Value |
|--------|-------|
| `X-Forwarded-For` | client chain (trusted hops preserved) plus peer |
| `X-Forwarded-Host` | original `Host` |
| `X-Forwarded-Proto` | `http` or `https` |
| `X-Real-Ip` | derived client address |
| `X-Request-Id` | per request identifier, also returned to the client |

`Forwarded` and hop-by-hop headers are removed.

## Reload semantics

Changed by `SIGHUP` or `xproxyctl reload` without restart: routes,
upstreams, rate limits, trusted proxies, logging levels, limits other than
listeners, certificate files, WAF profiles and modes, ban triggers and
exemptions (active bans are kept; changing `bans.state_file` opens a new
list), cluster peers, intervals and sharing flags, shedding thresholds,
challenge settings (the key is kept), priority classes. Requires restart: any
change under `server.listeners` other than certificate file contents
(including the `tls.acme` groups), `management.socket`, cluster `listen`,
`node_id` or `tls`, and the `acme` section.
