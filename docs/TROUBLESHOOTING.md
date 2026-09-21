# Troubleshooting

This is the document you open when something is wrong and you want it to
stop being wrong. It is organised by what you can see — a status code, a
log line, a graph — rather than by subsystem, because that is what you
have when the page is on fire.

Three things are true of almost every problem here:

1. **The proxy already told you.** Every refusal carries a `reason` and
   usually a `detail`, and both are in the access log line for that
   request. Find the line before you change anything.
2. **`xproxy -validate` is cheaper than a restart.** It loads the whole
   file, checks every path, certificate and reference, and prints
   *every* problem at once instead of the first.
3. **A reload never replaces a working configuration with a broken
   one.** If a reload fails, the old generation is still serving. You
   have time.
4. **Most refusals happen before the thing you are looking at.** The
   proxy refuses at the earliest stage that can decide, so a counter
   that has not moved usually means the request died above it.
   [Where a request can die](#where-a-request-can-die) is the order.

If you know the symptom, start at the [symptom
index](#symptom-index). If you know the subsystem, use the list below.
If you know neither, run the [sixty-second
triage](#the-sixty-second-triage) and let the access line tell you which
of the two you have.

**Orientation**

- [The sixty-second triage](#the-sixty-second-triage)
- [Reading an access log line](#reading-an-access-log-line)
- [Symptom index](#symptom-index)
- [What each command is for](#what-each-command-is-for)
- [Where a request can die](#where-a-request-can-die)
- [The timeout ladder](#the-timeout-ladder)
- [Proving it is not the proxy](#proving-it-is-not-the-proxy)
- [Reproducing safely](#reproducing-safely)

**The proxy itself**

- [Start-up and configuration](#start-up-and-configuration)
- [Reload](#reload)
- [Routing](#routing)
- [TLS](#tls)
- [Upstreams](#upstreams)
- [Protocols: HTTP/1, HTTP/2, HTTP/3](#protocols-http1-http2-http3)
- [WebSockets, streaming and long-lived requests](#websockets-streaming-and-long-lived-requests)
- [gRPC and gRPC-web](#grpc-and-grpc-web)
- [Static files and single page applications](#static-files-and-single-page-applications)
- [Cache and compression](#cache-and-compression)

**Protection**

- [Rate limits, bans, shedding and tarpits](#rate-limits-bans-shedding-and-tarpits)
- [WAF](#waf)
- [Virtual patches and the positive policy](#virtual-patches-and-the-positive-policy)
- [Authentication](#authentication)
- [The challenge and CAPTCHA](#the-challenge-and-captcha)
- [Filters](#filters)
- [Bot score](#bot-score)
- [Origin lock](#origin-lock)
- [Virtual security.txt](#virtual-securitytxt)

**Beyond one proxy**

- [Cluster](#cluster)
- [DNS listener](#dns-listener)
- [Forward proxy, layer 4 and QUIC](#forward-proxy-layer-4-and-quic)
- [Mirroring and shadowing](#mirroring-and-shadowing)
- [The API inventory](#the-api-inventory)
- [Kubernetes ingress mode](#kubernetes-ingress-mode)
- [Fleet](#fleet)

**Operations**

- [Management socket and GUI](#management-socket-and-gui)
- [Logs, metrics, traces and SIEM](#logs-metrics-traces-and-siem)
- [Sandbox, systemd and SELinux](#sandbox-systemd-and-selinux)
- [Performance: latency, memory, CPU, descriptors](#performance-latency-memory-cpu-descriptors)
- [Capacity and sizing](#capacity-and-sizing)
- [Clocks and expiry](#clocks-and-expiry)
- [Clients that misbehave](#clients-that-misbehave)
- [Emergencies](#emergencies)
- [Upgrades and rollback](#upgrades-and-rollback)

**Reference**

- [Bounded tables and what "full" means](#bounded-tables-and-what-full-means)
- [Deny reasons and details](#deny-reasons-and-details)
- [When to escalate, and with what](#when-to-escalate-and-with-what)
- [Glossary](#glossary)
- [Collecting a bug report](#collecting-a-bug-report)

## The sixty-second triage

```sh
xproxyctl status          # generation, uptime, listeners, counters, sandbox
xproxyctl upstreams       # which endpoints are healthy, and since when
xproxyctl stats           # the denial counters, by reason
journalctl -u xproxy -n 50 --no-pager     # what the process last said
```

Then one request through the thing that is failing, with the id it
returns:

```sh
curl -sv -o /dev/null -H 'Host: app.example.com' http://127.0.0.1:8080/the/path 2>&1 | grep -i 'x-request-id\|< HTTP'
grep '"request_id":"<that id>"' /var/log/xproxy/access.log | jq .
```

The access line for that id names the route, the upstream, the endpoint,
the deny reason and the detail. Nine problems in ten are over at this
point; the rest of this document is the tenth.

If the proxy is not answering at all, check in this order: the process
is running (`systemctl status xproxy`), the socket is bound
(`ss -lntp | grep xproxy`), nothing else owns the port, and the
management socket exists (`xproxyctl status` fails with
`dial unix ...: connect: no such file or directory` when it does not).

## Reading an access log line

An access line is one JSON object. The fields that matter when
something is wrong:

| Field | Means |
|-------|-------|
| `request_id` | The id echoed to the client in `X-Request-Id`. Ask for it in a bug report |
| `route` | The route that matched. `_challenge` and `_security_txt` are internal, not configured routes |
| `host`, `path` | The **normalised** host and the cleaned routing path, not the raw ones. A mismatch with what the client sent is itself the finding |
| `status` | What the client got |
| `denied` | Why the proxy refused, as `reason` or `reason:detail`. Absent when the proxy did not refuse |
| `upstream`, `endpoint` | Which pool and which address the request went to. Empty on a refusal |
| `attempts` | 1 unless a retry happened |
| `duration_ms` | The whole request, in the proxy. There is no per-upstream time in the access line — the upstream's share comes from the trace's client span, or from the `LATENCY-MS` column of `xproxyctl upstreams` |
| `client_ip` | After `trusted_proxies` and `X-Forwarded-For`. If this is your load balancer, `trusted_proxies` is wrong |
| `waf_matched` | Rule ids, when the WAF acted |
| `honeypot_marked` | This client touched a honeypot earlier |
| `device`, `automation` | From the challenge cookie, when the challenge is configured. The tier itself is not logged; `device` being present at all means the client holds a cookie |
| `country`, `ja4` | Present when geo or TLS fingerprinting are on |
| `cache` | `hit`, `miss` or `bypass`. A miss that was then stored is still logged as `miss`: the line is written before the body finishes streaming |

Fields are dropped by `logging.access.fields` and by sampling, so if one
you expect is missing, check both before concluding the proxy did not
compute it.

## Symptom index

| Symptom | Check |
|---------|-------|
| `config: ... no such file or directory` at start | A certificate, CA, rule or body path. `xproxy -validate` lists **all** of them at once |
| The process exits immediately with `refusing to run as root` | Intended: use socket activation and `User=xproxy`, or pass `-allow-root` if there is genuinely no other way |
| 404 for a host you configured | Host matching is exact, or a single-label wildcard. Compare the `host` field in the access log with what you configured — the log shows the normalised form |
| 400 with `reason: bad_host` | The `Host` header has an empty label (`a..b`), a stray bracket or a port that is not a number. It is refused rather than guessed at |
| 400 with `reason: normalization` | See [Routing](#routing); `detail` names the exact check |
| 403 with `denied: allow_cidrs` (security log `reason: acl_allow`) | The client address is not in the allow list. If the proxy is behind a load balancer and this is the balancer's address, `trusted_proxies` is not set |
| 403 with `reason: geo` | The country is not allowed, or is unknown and `unknown: deny`. `xproxyctl status` shows whether a geo database is loaded at all |
| 403 with `reason: banned` | `xproxyctl bans`. Unban, or add the range to `bans.exempt_cidrs` |
| 403 with `reason: waf` | A rule matched. `waf_matched` names it; see [WAF](#waf) |
| 403 with `reason: honeypot` | The client asked for a honeypot path. That is the honeypot working |
| 403 with `reason: honeytoken` | The client presented a planted credential. `detail` names the plant; see [Honeytokens](#honeytokens) |
| 403 on a form submission with `form_guard` in the line | `form_guard` fired. `detail` says which half: `field:<name>` is the hidden field, `too_fast`/`too_old`/`no_form_fetch` is the clock; see [Form honeypots](#form-honeypots) |
| An endpoint returns empty or wrong data for one client only | A `deceive` block on that route admitted it; see [Deceptive answers](#deceptive-answers) |
| A client reports the site is slow and is not banned | A `degradation` level admitted it; the access line says `degraded: <level>`. See [The slow lane](#the-slow-lane-degradation) |
| A TLS error at the client and no access log line | `handshake` refused the connection before it became a request; see [Refusal at the TLS handshake](#refusal-at-the-tls-handshake) |
| 403 with `reason: cors` | The `Origin` is not allowed by the route's `cors` block |
| 401 with `WWW-Authenticate: Bearer` | JWT missing or invalid. The security log names the category |
| 405 on `/.well-known/security.txt` | Only `GET` and `HEAD` are answered there |
| 413 immediately, no upstream in the log | `Content-Length` above `max_body_bytes` (global or per route) |
| 413 with `detail: larger than a signed body digest covers` | `origin_signature.body_digest` is on and the body is over 8 MiB |
| 429 with `Retry-After` | A rate limit. `denied` names the policy |
| 429 with `reason: account_abuse` | `account_guard` acted. `xproxyctl accounts` |
| 502 | The upstream connection failed. `upstream_error` in the access line, more in the error log |
| 502 with `detail: reqmod_unavailable` | The ICAP service failed or timed out with `fail: closed` |
| 503 with `Retry-After: 1` | The concurrency ceiling. `in_flight` against `max_concurrent_requests` |
| 503 with `Retry-After: 2` and `denied: shed:<class>` | Load shedding. Check `load_level` and upstream latency |
| 503 with `Retry-After: 5` | No healthy endpoint. `xproxyctl upstreams` |
| 503 with `reason: body_budget` | The process-wide buffered-body budget is spent; see [Performance](#performance-latency-memory-cpu-descriptors) |
| 503 with `reason: maintenance` | The maintenance gate is on |
| 504 | The upstream did not answer inside `timeouts.response_header` or `timeouts.total` |
| 415 with `detail: request:unscannable` | `sensitive_data` could not read the body: an unimplemented content coding, a corrupt compressed body, or a `Content-Range` |
| An HTML page titled "Checking your browser" | The challenge gate. A browser solves it; an API client cannot — exempt the client or the route |
| A page that is not yours, with a scanner's branding | An ICAP service replaced the response. `icap_verdict: replaced` in the access line |
| `... table full` in the error log | A bounded table hit its cap; see [Bounded tables](#bounded-tables-and-what-full-means) |
| `xproxyctl capture status` says `off` and no file appears | The runtime switch is off; the section alone only makes a capture possible. See [Packet capture](#packet-capture) |
| `management socket ... already in use` | Another xproxy is running, or a stale socket after a kill -9 |
| A reload says a listener needs a restart | Only a listener with a UDP socket (`h3`, `tcp.quic`, plain `dns`) changed on the same address |
| `configuration advice` warnings at start | Not errors: configurations that load but are a bad idea. Read them |
| `/v1/health` reports `degraded` | A hardening mechanism did not take effect and `sandbox.strict` is off |
| 403 with `reason: websocket` | The route does not set `websocket: true`; an `Upgrade` is refused rather than proxied |
| 403 with `reason: webtransport` | The route does not set `webtransport: true` |
| 415 with `reason: grpc_web` | The route's `grpc` block does not set `web: true` |
| 405 with an `Allow` header and `reason: policy` | The route's positive policy lists methods and this is not one |
| The patch's own status with `reason: virtual_patch` | `detail` is the patch id; `xproxyctl patches` shows its hits |
| A gRPC client sees a status instead of an HTTP error | Intended: refusals are answered as trailers-only with a `grpc-status` |
| 499 in the access log | The client disconnected mid-request. Not an upstream failure |
| 404 from a `static` route for a file that is there | A dot in the name, a non-regular file, or a path rewritten before the handler saw it. Every open failure answers 404 on purpose |
| A stream or WebSocket dies at exactly 60s or 120s | `read_timeout`/`write_timeout`, or `idle_timeout`. See [The timeout ladder](#the-timeout-ladder) |
| HTTP/3 works nowhere | The UDP port, which is a separate socket and a separate firewall rule from TCP |
| `mirror: dropped` or `mirror: body_too_large` in the access line | The mirror's in-flight bound or its body bound; the live request was not affected |
| `origin-check` says `not_enforced` | The origin is serving requests that did not come through the proxy |
| An Ingress rule is dropped with a warning | The host is not a DNS name or the path is not a plain prefix; see [Kubernetes ingress mode](#kubernetes-ingress-mode) |
| Tokens, staples or tickets all expire at once | A clock. See [Clocks and expiry](#clocks-and-expiry) |

## What each command is for

Almost every answer in this document comes out of one of these. When you
do not know where to look, start at the top.

| You want to know | Run |
|------------------|-----|
| Whether the process is healthy at all | `xproxyctl status` |
| What it refused and why, in bulk | `xproxyctl stats`, `xproxyctl -json stats \| jq` |
| Which endpoints are up, ejected, ramping, circuit-broken or queueing | `xproxyctl upstreams` |
| What configuration is actually running | `xproxyctl config` (expanded, defaults filled in, header values redacted) |
| Whether the file on disk differs from it | `xproxyctl diff`, exit status 1 when it does |
| What a reload would change | `xproxyctl reload -dry-run` |
| What changed last time, and how to undo it | `xproxyctl history`, `xproxyctl rollback ID` |
| Which certificate is served for a name | `xproxyctl tls` |
| Whether a managed certificate is stuck | `xproxyctl acme` |
| Who is banned | `xproxyctl bans` |
| Which keys are consuming a rate limit | `xproxyctl quotas -top 20` |
| Which WAF rules fire | `xproxyctl waf -top 20` |
| Which filters are configured and what they deny | `xproxyctl filters` |
| Whether the cluster is actually a cluster | `xproxyctl cluster` |
| Whether hardening took effect | `xproxyctl sandbox` |
| What the exporters are doing with your telemetry | `xproxyctl telemetry` |
| The live picture, refreshing | `xproxyctl tui` |
| One stream as it happens | `xproxyctl tail access\|error\|security\|audit` |
| Exactly what a client sent and what we answered, byte for byte | `xproxyctl capture start -duration 10m`, then the pcapng in Wireshark |

Two of these deserve a habit rather than a lookup. `xproxyctl config` is
the answer to almost every "but I configured that" — it prints what the
process resolved, not what you wrote. And `xproxyctl tail security | jq
-c` on a second terminal, while you reproduce the problem, turns a
guessing game into reading.

## Where a request can die

The proxy refuses at the earliest point that can decide, which is why a
counter you expect to move sometimes does not: the request never reached
that stage. This is the order, with what each stage can answer.

| # | Stage | Refuses with | Notes |
|---|-------|--------------|-------|
| 1 | Connection admission | (no HTTP response) | `max_connections`, `max_connections_per_ip`. The connection is closed, so there is no access line |
| 2 | Client address | — | `trusted_proxies` decides whether `X-Forwarded-For` is believed. Everything below keys on the result |
| 3 | Concurrency slot | 503 `concurrency`, `Retry-After: 1` | `max_concurrent_requests` |
| 4 | Ban list | 403 `banned` | Address and JA4. Before any routing, so a banned client costs nothing |
| 5 | ACME `http-01` | 200 or 404 | `/.well-known/acme-challenge/` is answered before routing |
| 6 | `redirect_to_https` | 308 | Listener-level, before the URI and normalisation checks |
| 7 | URI length | 414 `uri_length` | `max_uri_length` |
| 8 | Normalisation | 400 `normalization:<check>` | Every check in the table under [Routing](#routing) |
| 9 | Host | 400 `bad_host` | An empty label, a stray bracket, a non-numeric port |
| 10 | Unicode folding | 400 `normalization:unicode_fold` | Folding introduced a separator the raw path did not have |
| 11 | Challenge endpoints | 200 / 403 | `/.xproxy/…` is served on every host, before routing |
| 12 | `security.txt` | 200 | Matched entry answers; no match falls through to routing |
| 13 | **Route match** | 404 `no_route` | Exact host, then wildcard, then hostless; longest path prefix wins |
| 14 | gRPC-web gate | 415 `grpc_web` | The route has no `grpc.web` |
| 15 | WebTransport gate | 403 `webtransport` | The route has no `webtransport` |
| 16 | CORS preflight | 204 | Answered *before* authentication, limits and filters: it carries no credentials |
| 17 | Maintenance | 503 `maintenance` | Unless the client, header or route is exempt |
| 18 | Virtual patches | the patch's status, `virtual_patch:<id>` | Before anything spends work on the request |
| 19 | Positive policy | 405/415/400 `policy:<detail>` | 405 carries an `Allow` header |
| 20 | Compression | — | The writer is installed here; nothing is refused |
| 21 | Geo | 403 `geo` | After the cheaper checks, before the ACLs it might duplicate |
| 22 | `deny_cidrs` | 403 `acl_deny` | |
| 23 | `allow_cidrs` | 403 `acl_allow` | |
| 24 | Challenge cookie | — | Read once; its tier and device feed everything below |
| 25 | Challenge gate | the challenge page | `mode: always`, or `load` while the shedder reports pressure |
| 26 | Load shedding | 503 `shed:<class>` | By priority class, with `Retry-After` |
| 27 | Rate limits (request-keyed) | 429 `rate_limit:<policy>` | Or a tarpit, which holds first |
| 28 | Body limit | 413 `body_size` | `Content-Length` first, then the reader enforces it |
| 29 | Buffered-body budget | 503 `body_budget` | Only on routes that materialise a body |
| 30 | **Filter chain** | the filter's status, `filter`/`waf`/`jwt`/… | Instances live for the whole exchange |
| 31 | Identity rate limits | 429 | Keyed on what the filter chain verified, so they run after it |
| 32 | Route timeout | — | Armed here, tightened by a gRPC client's own `Grpc-Timeout` |
| 33 | **Action** | — | Redirect, honeypot, DoH, static, respond, cache lookup, or the upstream |

Three consequences worth remembering:

- **A rate limit that "does not apply"** is usually a request refused
  above line 27 — by an ACL, a patch, the policy check or maintenance.
  Its counter never moves because the limiter never saw it.
- **A filter that never runs** is a route whose requests die above line
  30. `xproxyctl filters` shows the deny count per filter: a flat zero
  with traffic on the route means the request is dying earlier.
- **A honeypot mark is read at line 24**, so it is available to the
  filters and to the log for a request that is refused later.

Responses come back through a shorter path: the filter chain's response
phase, the error-page interception, the cache store, and the compression
writer's close. A response-phase filter denial arrives as
`filter denied:` in the error log and, to the client, as the filter's
own status.

## The timeout ladder

Eight timeouts can end a request and they are configured in three
different places. In the order they can fire:

| Timeout | Where | Default | Ends |
|---------|-------|---------|------|
| `server.limits.read_header_timeout` | Server | 10s | A client that opens a connection and dawdles over the request line and headers (slowloris) |
| `server.limits.read_timeout` | Server | 60s | The whole request including its body |
| `upstreams[].timeouts.connect` | Pool | 5s | Dial and TLS handshake to the endpoint |
| `upstreams[].timeouts.response_header` | Pool | 30s | Time to the upstream's first response byte → 504 |
| `routes[].timeouts.idle` | Route | none | A response that produces no bytes for this long, for streaming and long-poll routes |
| `routes[].timeout` / `routes[].timeouts.total` | Route | none | The whole exchange, accept to last byte |
| `upstreams[].timeouts.total` | Pool | 5m | The whole upstream exchange |
| `server.limits.write_timeout` | Server | 60s | The whole response to the client |
| `server.limits.idle_timeout` | Server | 120s | A keep-alive connection with nothing on it |

The one that bites first wins, and the one that bites is usually not the
one you changed. Three rules:

- **A streaming route needs `timeouts.idle`, not a larger `total`.** A
  server-sent-events endpoint with `total: 5m` is cut at five minutes
  however healthy it is. Set `total: 0` and an idle timeout instead.
- **`write_timeout` is server-wide and bounds the response to the
  client**, so a slow client downloading a large file hits it before any
  route timeout does. Raise it for a download host, or serve downloads
  from a listener of their own.
- **A gRPC client's `Grpc-Timeout` tightens the route deadline** but
  never loosens it. A client asking for an hour on a route with a
  thirty-second total gets thirty seconds.

To see which one fired, read `duration_ms` in the access line against
the defaults: a 504 at about 5s is `connect`, at about 30s is
`response_header`. A cut response with a 200 already sent is `total`,
`idle` or `write_timeout` — the error log names it, and
`upstream_error` in the access line carries the transport error where
there was one. With tracing on, the client span is the upstream's share
of the server span, which is the exact answer rather than the
inferred one.

## Proving it is not the proxy

Before changing anything, establish which side is wrong. Run these from
the proxy host, in this order.

```sh
# 1. The origin, directly, bypassing the proxy entirely.
curl -sv -H 'Host: app.example.com' http://10.0.3.11:8080/the/path

# 2. The proxy, from the proxy host, bypassing the network in front of it.
curl -sv -H 'Host: app.example.com' http://127.0.0.1:8080/the/path

# 3. The proxy, from where the client is.
curl -sv https://app.example.com/the/path
```

- **1 fails**: it is the origin. Nothing in this document will help.
- **1 works, 2 fails**: it is the proxy, and the access line for step 2
  says why.
- **2 works, 3 fails**: it is in front of the proxy — DNS, a load
  balancer, a firewall, TLS termination somewhere else — or it is
  something about the real client that curl does not reproduce (a
  cookie, a client certificate, HTTP/2, a user agent a filter judges).

For the third case, make curl look more like the client one attribute at
a time: `--http2`, `-H 'User-Agent: …'`, `-b 'cookie=…'`, `--cert`. The
attribute that reproduces the failure is the cause.

**A request that never reaches an access line** did not get past
connection admission (line 1 of the table above) or failed the TLS
handshake. Neither produces a request, so neither produces an access
line; look at the error log and at the client's own error text.

## Reproducing safely

Everything below observes without changing what clients see.

| Question | Safe way to answer it |
|----------|----------------------|
| Would this configuration load? | `xproxy -config … -validate` |
| What would a reload change? | `xproxyctl reload -dry-run` |
| Would the WAF block this? | `mode: detect` on the route, or `mode: learn` to collect exclusions |
| Would this new backend answer the same? | `routes[].mirror` with `diff`: the copy runs in the background and never touches the client's response |
| Would this filter block real traffic? | `sensitive_data` and `bot_score` both have a recording mode (`action: log`, `learn: true`) |
| Does this origin refuse unsigned requests? | `xproxyctl origin-check`, which probes each origin with a signed and an unsigned request |
| Is this endpoint healthy from *here*? | `curl` from the proxy host to the endpoint address, with the `Host` the proxy sends |
| What exactly did the client send, and what did we answer? | `xproxyctl capture start -duration 10m` with a rule for that client or route, then read the pcapng in Wireshark. It records, it does not change what clients see — but the file holds decrypted traffic, so delete it afterwards |

Two more that change behaviour but are reversible in one command:
`xproxyctl maintenance on` (and `off`), and a `canary` endpoint in a
pool, which takes a named share of traffic and is removed by a reload.

## Start-up and configuration

**Validate first, always.**

```sh
xproxy -config /etc/xproxy/xproxy.yaml -validate
```

It parses, expands includes, applies defaults, checks every referenced
file exists and is readable, resolves every cross-reference (a route's
upstream, a filter name, a rate limit, an ICAP service) and prints
every problem it found — not the first one. Exit status 0 or 1.

**The error says a line and a key.** Configuration errors name the path
in the document (`routes[3].filters[1]`, `upstreams[0].tls.ca_file`),
not just a line, because includes make line numbers ambiguous.

**Includes.** `xproxyctl config` prints the *expanded* document the
process is actually running, with a leading comment naming every file
that was read. If a setting is not what you expect, look there before
looking at your source files: a later include wins, and a directory
include reads in lexical order.

**Two processes, one file.** A configuration is not a lock. If you run a
second xproxy against the same `management.socket` or the same ban
`state_file`, the second one fails to start; if you point it at the same
listener address, one of them fails to bind. Both are the right
behaviour and both look like "it will not start".

**`-validate` passes but the process exits at start.** The things
validation cannot check are: binding a privileged port without the
capability or socket activation; a certificate whose key does not match
it; a DNS name that does not resolve; a secret file with wrong
permissions (mode `0644` on a keyring is refused deliberately). All four
print a specific message to stderr and to the error log before exiting.

**Advice, not errors.** Some configurations load but are a bad idea, and
validation says so without refusing: an empty `cluster.tls.allowed_names`
(any certificate the CA ever issued becomes a cluster peer), an open
`kind: dns` listener with no `allow_clients` and no `rate_limit`,
`bind_node_id` turned off. They are printed by `-validate` and logged as
`configuration advice` on every start and reload. If you do not want
them, fix them; there is no flag to silence them.

**The file is a directory.** `-config` pointing at a directory reads
every `*.yaml` in it in lexical order, which is why `10-` and `90-`
prefixes are worth using. A fragment that appears not to apply is
usually being overridden by one later in the order; `xproxyctl config`
names every file that was read in a comment at the top.

**A fragment adds a section twice.** Sections merge by appending, not by
replacing, so two fragments each defining `routes` give you both lists.
Two routes with the same name is an error; two routes with the same
host and path is not, and the first wins. That is why the expanded
document is the thing to read.

**Secrets with the wrong mode.** A keyring, a challenge secret or an
affinity secret at mode `0644` is refused rather than used. The message
names the file and the mode it found. The proxy creates these files at
`0600` on first start; a mode that changed afterwards is a deployment
step that copied them.

**The process starts and then exits within a second.** Look at the
error log rather than stdout: the message that matters is almost always
the last one before the exit, and systemd's own "failed with result" is
never it.

## Reload

```sh
xproxyctl reload -dry-run     # what would change, per section, with a text diff
xproxyctl reload              # apply
systemctl reload xproxy       # the same thing through systemd
```

**A failed reload changes nothing.** The new configuration is loaded and
validated in full before anything is swapped. On failure the error names
the problem and the old generation keeps serving; `reload_failures` is
incremented.

**What a reload cannot do.** Four things need a restart and the dry run
says so: the cluster's `listen` address, `node_id` or TLS material; the
`management.socket` path; `acme`; and a listener with a UDP socket
changing on the same address. Everything else — routes, upstreams,
filters, WAF rules, certificates, listeners added or removed — applies
on reload.

**Why the old generation lingers.** After a reload the previous
generation keeps its in-flight requests until the last one ends, then is
torn down (with a hard cap for one that never ends). A long upload or a
gRPC stream is not cut. During that window two generations are alive and
memory is higher; that is expected and resolves itself.

**A reload that "does nothing".** `xproxyctl reload -dry-run` reporting
`same: true` means the file on disk and the running configuration are
identical after includes and defaults — usually because the file you
edited is not the file the process reads. `xproxyctl status` names the
configuration path.

**Landlock refuses a reload.** If the sandbox applied Landlock rules at
start, a reload naming a file outside the directories admitted then is
refused with a message saying to restart. Landlock rules cannot be
widened in place. Put new material inside an already-admitted directory,
or restart.

**What a reload does to live state.** Bans, honeypot marks, rate limit
buckets, the API inventory and the WAF's statistics live in the server
and survive a reload; they are not part of a generation. What is rebuilt
is everything derived from the configuration: routes, pools, filters,
compiled rules, certificates. A counter that resets on reload is a bug;
a bucket that does not is the design.

**A reload while an attack is running.** It is safe, and the ban list is
not disturbed. The one thing to know is that a rate limit whose key or
window changed starts from an empty table for the new shape, so an
attacker gets one window's worth of fresh allowance. Prefer a ban to a
limit change mid-incident.

**Reload loops.** If something reloads the proxy repeatedly — a
configuration management run on a timer, a fleet agent fetching a bundle
that never validates — you will see `reloads` and `reload_failures`
climbing together in `xproxyctl status`, and two generations will be
alive more often than not. The error log names the failing key every
time; it is the same key every time.

## Routing

**The matching order** is: exact host, then wildcard host, then hostless
routes; within a host, the longest path prefix wins, and a `path_regex`
entry counts as the length of its pattern. Method, header and expression
conditions narrow a route; they do not change its rank.

**A request lands on the catch-all.** Nine times in ten the host is
spelled differently from the configuration. The `host` field in the
access log is the normalised form; compare it with `routes[].hosts`.
Empty labels (`api..example.com`) are refused with `bad_host` rather
than normalised, because two spellings of one name would otherwise be
two routing keys.

**400 with `reason: normalization`.** The `detail` names the check:

| Detail | Means |
|--------|-------|
| `path_control_char`, `query_control_char` | A byte below 0x20 or DEL in the decoded path or query |
| `path_invalid_utf8` | An overlong or truncated UTF-8 sequence |
| `path_double_encoding` | A percent escape survived one decoding (`%252e`) |
| `path_encoded_slash` | `%2F` or `%5C` in the raw path |
| `path_backslash` | A backslash anywhere in the decoded path. On by default: IIS, Apache on Windows and .NET read it as a separator |
| `path_parameter` | A `;` in the decoded path. On by default: servlet containers strip it before mapping, so `/admin;x` is `/admin` to them |
| `path_dot_segment` | A `.` or `..` segment, including the `..;` and backslash spellings |
| `framing_content_length`, `framing_te_cl`, `framing_transfer_encoding` | Ambiguous HTTP/1 framing |
| `unicode_fold` | Unicode folding introduced a separator that was not in the original path |

If a legitimate application genuinely uses matrix parameters or
backslashes in paths, turn the specific check off for the whole server
(`server.normalization.reject_path_params: false`) and understand what
you are re-opening.

**`strip_prefix` and `rewrite_path` surprises.** The upstream receives
the rewritten path; the access log shows the routing path. To see what
the upstream got, look at the upstream's own log, or set a request
header from `${path}` temporarily.

**Expressions never match.** `xproxy -validate` compiles every
expression and names the route on a syntax error, so a silently
non-matching expression is a semantic problem: most often comparing a
header the client does not send, which is `""` and not an error.

**Two routes both look right.** Rank is decided before any condition is
evaluated: exact host beats wildcard host beats hostless, and within a
host the longest path prefix wins, with a `path_regex` entry ranked by
the length of its pattern. Methods, headers and `when` expressions
narrow a route that already ranked highest — they do not promote a
lower-ranked one. A route that "should have matched" because its
condition is more specific will not.

**A route with `grpc` and a route without, on the same path.** The gRPC
one wins for gRPC requests, and one naming services beats one with an
empty `grpc` block. This is the exception to "length decides", and it
is what lets a gRPC catch-all and an HTTP catch-all share `/`.

**The upstream sees a different path from the log.** The access log
records the routing path, which is what matching used. The upstream
receives that path after `strip_prefix`, then `rewrite_path` or
`rewrite_regex`. To see what the upstream actually got without changing
the upstream, add a request header from `${path}` on the route and read
it there, or look at the upstream's own log.

**A capture group is empty in a template.** `${1}`..`${9}` and
`${name}` come from the route's `path_regex` match. A route that matched
on a plain prefix has no captures at all, and a placeholder without a
value expands to the empty string rather than failing — which is why a
header that should carry a tenant id silently carries nothing.

**Trailing slashes.** The routing path is cleaned, so `/a/` and `/a`
are different paths but `/a//b` and `/a/./b` are both `/a/b`. A prefix
of `/a` matches `/ab` as well as `/a/b`; write `/a/` when that is what
you mean.

## TLS

**A handshake fails before any request.** Nothing appears in the access
log, because there is no request. Look in the error log, and at the
client's own error:

| Client says | Usually |
|-------------|---------|
| `unknown certificate authority` | The client does not trust your chain; serve the intermediate, not just the leaf |
| `handshake failure` with no shared cipher | `min_version` or a cipher list too narrow for the client |
| `no application protocol` | ALPN mismatch: the client offered only h2 to a listener that does not enable it |
| `certificate required` | The listener has `client_auth` and the client sent none |
| `bad certificate` | Client certificate present but not issued by `client_ca_file`, or expired |
| `unrecognized name` | SNI names a host with no certificate and there is no default |

**Which certificate is being served.** `xproxyctl tls` lists every
loaded certificate with its names, issuer, expiry and whether it is
stapled. A certificate is selected by SNI; a client that sends none gets
the first configured one.

**`xproxyctl reload-certs`** re-reads certificate files only, without a
configuration reload. Use it after renewal. If the files changed but the
served certificate did not, the paths in the configuration are not the
paths your renewal wrote to.

**OCSP stapling stops.** A staple that is still valid survives a failed
fetch, so "no staple" means either the responder has been unreachable
past the staple's own lifetime, or the certificate has no OCSP URL.
`xproxyctl tls` shows the staple's expiry. For a must-staple
certificate, a responder outage is a handshake outage — that is the
certificate's design, not the proxy's.

**Certificate Transparency refuses a certificate.** With `ct` on, a
certificate without enough SCTs from distinct logs is refused at load.
The error names how many were found and how many are required.

**A client certificate is not being asked for.** `client_auth` has
levels: `none` asks for nothing, `request` asks and accepts a client
that sends none, `require` refuses a connection without one. The
`${cert:...}` variables and `cert()` in expressions are empty for any
connection the listener did not ask, which is most of them.

**The chain is right and the client still refuses it.** Serve the
intermediate. A certificate file holding only the leaf validates fine on
the proxy — which has the intermediate in its own store — and fails on
a client that does not. Concatenate leaf then intermediate(s), never the
root.

**Session resumption stops working after a deploy.** Without
`server.session_tickets`, each process derives its own keys and a
restart invalidates every ticket. With it, keys derive from a shared
secret and the clock, so every node resumes every other node's sessions
— and two nodes whose clocks disagree do not. `xproxyctl tls tickets`
reports the epoch, the fingerprint and which peers derive the same set.

**SPKI pinning breaks after a renewal.** `spki_pins` pins the public
key, not the certificate. A renewal that reuses the key keeps working; a
renewal with a new key does not. Pin two keys (current and next) before
rotating. `xproxyctl spki CERT.pem` prints the pin of a certificate
*file*, so to pin a live origin, fetch its certificate first:

```sh
openssl s_client -connect origin.example.com:443 -servername origin.example.com </dev/null 2>/dev/null \
  | openssl x509 > /tmp/origin.pem
xproxyctl spki /tmp/origin.pem
```

**ACME never issues.** `xproxyctl acme` shows the account, each domain's
state and the last error. The usual causes: `http-01` with the challenge
path not reachable from the internet (a route or a WAF rule in front of
`/.well-known/acme-challenge/`), or `tls-alpn-01` on a listener that is
not the one port 443 traffic reaches.

## Upstreams

```sh
xproxyctl upstreams     # endpoints, discovery, slow start, circuits, queues
```

There is one upstream view, not two. It prints a row per endpoint
(weight, canary, healthy, ejected, active, requests, errors, ramp,
latency, and whether the endpoint is static or discovered), then a line
per pool that has discovery or slow start, then a second table for the
pools that have a circuit breaker or a queue.

**502.** The connection to the endpoint failed. The access line's
`upstream_error` and the error log name it: `connection refused`
(nothing listening), `i/o timeout` (filtered, or the endpoint is
wedged), `no such host` (DNS), `x509: ...` (TLS to the upstream).

**503 with `Retry-After: 5`.** No endpoint is healthy. If health checks
are configured, `xproxyctl upstreams` shows which check failed and when;
if they are not, the pool marks an endpoint unhealthy from failed
requests and recovers it after the interval.

**504.** The upstream accepted the connection and then did not answer
inside `timeouts.response_header`, or the whole exchange passed
`timeouts.total`. These are per route; a slow endpoint needs a longer
timeout or a faster endpoint, and a streaming route needs `total`
raised or set to 0.

**Retries that make it worse.** `retry_on` with `5xx` and a
non-idempotent method duplicates writes. Retries only replay a request
with a rewindable body; a streaming upload is never retried. The retry
budget stops a failing pool from being retried into the ground: a retry
is sent only while the retries in flight stay under `percent` of the
requests in flight, with `min_concurrency` always allowed, so the
allowance falls with the traffic. Nothing names it in a view — you see
it as retries that quietly stop happening while the pool is busy, which
looks like "retries stopped working" and is the feature.

**The circuit breaker is open.** Requests are refused without a dial
until the probe interval passes. The second table of `xproxyctl
upstreams` shows the state, the failure count against the threshold, how
many times it has opened, how many requests it refused, and the time it
next probes.

**Sticky sessions land on the wrong backend.** Check that the affinity
cookie is actually reaching the proxy (a browser will not send it
cross-site without `SameSite` allowing it) and that the endpoint list
has not changed: affinity survives a reload, but an endpoint that left
the pool cannot be honoured and the request is rebalanced.

**Slow start.** A newly healthy endpoint takes a fraction of the traffic
for `slow_start`, ramping up. A pool that looks unbalanced right after a
deploy is usually this.

**Discovery finds nothing, or too much.** `xproxyctl upstreams` prints a
discovery line per pool with the type, the name, the interval, the
endpoint count, the resolutions, the changes, the errors and the last
error. A pool with both static and discovered endpoints serves both. A
failed resolution keeps the previous set rather than emptying the pool,
which is why a DNS outage does not take the site down and also why a
stale set can persist.

**An endpoint is ejected and never comes back.** Outlier ejection
removes an endpoint after `consecutive_failures` and returns it after
`base_ejection_time` multiplied by how many times it has been ejected,
capped at ten times; `max_ejection_percent` stops the pool from ejecting
itself into nothing. An endpoint that is genuinely down stays ejected,
and an endpoint that flaps ejects for longer each time, up to that
ceiling. The `EJECTED` column
shows it, and a health check is what returns it deliberately.

**Every endpoint is unhealthy but curl works.** The health check goes to
`path` with the pool's own scheme and a `Host` you may not be setting;
an origin that requires a `Host` header answers the check differently
from your curl. `expected_status` and `body_contains` narrow it
further. Reproduce with exactly what the check sends.

**The Host the upstream sees.** By default it is the client's. A pool
whose origins are virtual-hosted needs `host_header` on the route, and
a health check needs its own. A 404 from the origin for a path that
exists is very often this.

**Hedging sends two requests.** `hedge` issues a second copy to another
endpoint after a delay and takes whichever answers first, cancelling the
loser. It is bounded by the retry budget like a retry. Only use it where
a duplicate request is harmless: it is not for anything that writes.

## Protocols: HTTP/1, HTTP/2, HTTP/3

**A client negotiates the wrong protocol.** ALPN decides, and ALPN
offers only what the listener enables. `protocols: [h1, h2]` on a TLS
listener offers both; `h2c: true` on a plaintext listener accepts
prior-knowledge HTTP/2 without TLS. A browser will not speak h2c, ever,
so an `h2c` listener is for service traffic and health checkers.

**HTTP/3 is never used.** In order: the listener lists `h3` in
`protocols`; the UDP port is reachable (it is a separate socket from
TCP and a separate firewall rule); `Alt-Svc` is being served, which the
proxy only does once the endpoint is actually serving; and the client
has not blocked QUIC. `curl --http3` against the proxy, from a host
with UDP egress, is the shortest test.

**HTTP/3 is slower than HTTP/2.** `validate_addresses: always` costs
every new client address one extra round trip before the server
allocates state. That is the default and it is deliberate — a spoofed
Initial is otherwise free for the sender. `under_load` moves the cost to
the moment open connections pass a quarter of `max_connections`.

**HTTP/3 streams ignore the server timeouts.** `read_timeout` and
`write_timeout` do not apply to HTTP/3 at all. A route timeout and the
upstream `total` are what bound an HTTP/3 request; `read_header_timeout`
still bounds the handshake. A route that behaves over HTTP/2 and hangs
over HTTP/3 is usually this.

**`max_streams` refuses concurrency, not requests.** A client that
opens more than `max_streams` concurrent streams on one QUIC connection
has them refused at the QUIC layer, which a client library may report as
a connection error rather than a per-request one.

**0-RTT never happens.** It is not enabled and cannot be. A replayable
early-data request in front of an arbitrary application is not a
trade-off this proxy offers.

## WebSockets, streaming and long-lived requests

**403 with `reason: websocket`.** The route does not have
`websocket: true`. An `Upgrade` request on a route that has not asked
for one is refused rather than proxied, because a route's whole
admission chain is written for request/response traffic.

**The upgrade succeeds and then the connection dies at a fixed
interval.** Something on the ladder is cutting it. Check, in this
order: the route `timeout`/`timeouts.total` (an upgraded connection is
still one request), `server.limits.write_timeout`, and any idle timeout
between the client and the proxy that is not the proxy's. A connection
that always dies at exactly 60s is `read_timeout` or `write_timeout`;
at exactly 120s it is `idle_timeout`.

**A streaming response is buffered.** Compression buffers up to
`min_bytes` before deciding, which delays the first bytes of a small
stream. A `Flush` from the upstream decides immediately, so an upstream
that never flushes streams badly through any compressing proxy. Turn
compression off for the route, or make the upstream flush.

**Server-sent events stop after a few minutes.** Set `timeouts.total: 0`
and `timeouts.idle` to something above the heartbeat interval. Without a
heartbeat there is nothing to distinguish a healthy idle stream from a
dead one, and the proxy will not guess.

**A long upload is cut.** `read_timeout` bounds the whole request
including the body, so a slow upload of a large file hits it regardless
of the body limit. It is server-wide; raise it, or give uploads their
own listener.

**A reload during a long request.** The old generation keeps its
in-flight requests until the last one ends, so the upload or the stream
is not cut. Two generations are alive meanwhile; that is the design.

## gRPC and gRPC-web

**A gRPC request gets an HTTP error instead of a status.** It should
not: when the proxy refuses a gRPC request it answers a trailers-only
response with HTTP 200 and a `grpc-status`, so a gRPC client sees a
status rather than a transport failure. The mapping:

| Proxy answer | `grpc-status` |
|--------------|---------------|
| 403 | 7 PERMISSION_DENIED |
| 401 | 16 UNAUTHENTICATED |
| No route | 12 UNIMPLEMENTED |
| Rate or size limit | 8 RESOURCE_EXHAUSTED |
| No healthy endpoint, connection error | 14 UNAVAILABLE |
| Timeout | 4 DEADLINE_EXCEEDED |
| Anything else | 13 INTERNAL |

The proxy's own status is in `grpc-message`. If a client is seeing a raw
HTTP status instead, the request was not recognised as gRPC — check the
content type.

**A gRPC route never matches.** A `grpc` route matches only requests
whose content type is `application/grpc` or `application/grpc+…`.
Among routes of equal path length, one naming services beats one with an
empty `grpc` block, which beats a plain route — so a gRPC catch-all and
an HTTP catch-all can share `/`. A route with a `grpc` block and no
`upstream` cannot match at all.

**gRPC fails end to end with no useful error.** gRPC needs HTTP/2 on
both sides. The listener needs `h2` (with TLS) or `h2c: true` (without),
*and* the upstream needs `scheme: https` or `h2c`. Half of that is the
usual cause: a TLS listener with h2 in front of an `http` upstream
downgrades to HTTP/1.1 to the origin, and gRPC does not survive it.

**415 with `reason: grpc_web`.** A gRPC-web request arrived on a route
whose `grpc` block does not set `web: true`. Binary and text variants
both need it.

**gRPC-web works in curl and not in the browser.** The browser needs
the CORS preflight answered, and gRPC-web preflights ask for headers a
default policy does not allow. The route's `cors` block must allow the
origin; the preflight is answered before authentication, so a 403 on the
preflight is the CORS policy and nothing else.

**A deadline is shorter than configured.** The client's `Grpc-Timeout`
tightens the route deadline. An overflowing or unparseable value counts
as absent rather than as infinity.

## Static files and single page applications

**404 for a file that exists.** In order: the path after `strip_prefix`
or `rewrite_path` is what selects the file, not the request path; a name
beginning with a dot is refused unless `dot_files` is set; anything that
is not a regular file or a directory answers 404; and every failure to
open answers 404 rather than 403, deliberately, so the shape of the tree
leaks nothing. The error log has the real reason.

**A symlink out of the root does not work.** It cannot. The tree is
opened through a root handle, so a link pointing outside it is refused
however it is spelled. Put the target inside the root, or serve it from
a second static route.

**A single page application 404s on deep links.** Set `fallback:
/index.html`. Assets that exist are still served as themselves; only
misses fall back, which is what makes it safe.

**The wrong content type.** Types for the common web formats come from
a fixed table rather than the host's MIME database, so they cannot
change under you when the base image does. Everything else falls through
to the host, and nothing unknown is ever served as HTML.
`X-Content-Type-Options: nosniff` is always set.

**A directory redirect loses the query string or goes somewhere odd.**
A directory without a trailing slash is a 301 to the cleaned path with
one added. If the result is not what you expect, the path was already
being rewritten before the static handler saw it.

**A reload fails with a missing static root.** The root must exist at
load. That is deliberate: an absent root would otherwise turn every
request on the route into a 404 after a reload nobody noticed. The
previous generation keeps serving.

## Cache and compression

**Nothing is cached.** A response is cacheable only when the request's
wire path equals the routing path, the method and status are in the
lists, and the response allows it. `Authorization`, `Range` and (without
`cookies: true`) `Cookie` bypass the cache by design.
`xproxyctl status` has hits, misses and stores.

**A stale response.** `xproxyctl cache purge HOST PATH-PREFIX` removes
entries (both arguments are positional and optional; with neither, the
whole cache goes). The TTL is the response's own `max-age` unless
`ignore_cache_control` is set, clamped to `cache.ttl`.

**A response is not compressed.** In order: the media type is not in
`compression.types`; the body is below `min_bytes`; the response already
has a `Content-Encoding` or a `Content-Range`; `Cache-Control:
no-transform`; the client did not offer the encoding; or — the one that
surprises people — the request carried `Authorization` or a `Cookie`.
Compressing a response to an authenticated request is the BREACH
condition, so it is off unless `compress_authenticated` says otherwise.

## Rate limits, bans, shedding and tarpits

**429 for traffic that should pass.** `denied` names the policy. Check
the key: `client_ip` behind a NAT is one bucket for a whole office, and
`client_net` is deliberately coarser. `xproxyctl quotas` shows the
heaviest keys of each policy, which usually identifies the sharer.

**A limit that seems not to apply.** Rate limits keyed on request data
run *after* ACLs, the maintenance gate, virtual patches and the policy
check — a request refused earlier never reaches the limiter, so its
counter does not move.

**`rate limit key table full`.** The per-shard key table is full of live
keys. The decision falls back to a coarser key — the client address,
then its /24 or /48 — and refuses when there is nothing coarser left.
This is a deliberate direction: admitting an untracked request would
make the bound itself the way past the limit. If it happens in normal
traffic, the key is too fine (a header value that never repeats).

**Bans.** `xproxyctl bans` lists them with source, reason and expiry.
`xproxyctl unban <target>` removes one. A ban placed by an operator
cannot be removed by a cluster peer; a peer's own ban can. Exempt ranges
go in `bans.exempt_cidrs`, and they are checked before triggers, so an
exempt client never accumulates a ban window at all.

**A ban you did not expect.** The security log line for the ban names
the trigger and the reason that tripped it. The common surprise is a
trigger on `challenge`: only reasons that describe something the client
did wrong feed the ladder, so a CAPTCHA provider outage does not ban
everyone — but a genuinely wrong proof does.

**Load shedding.** `denied: shed:<class>` means the load level passed
the class's threshold. `xproxyctl status` shows `load_level` and
`upstream_latency_ms`. Shedding is driven by upstream latency and
in-flight count, so a slow upstream sheds *this* proxy's traffic; fix
the upstream, or raise `target_latency` if the latency is normal for
that service.

**Tarpits.** A tarpitted request gives up its concurrency slot and holds
a tarpit slot instead. If `tarpit_overflow` is rising, `max_tarpits` is
reached and requests that would have been held are refused at once —
which is the safe direction.

**Choosing a key, and what each one costs.** The key decides who shares
a bucket, and most complaints about a rate limit are really complaints
about its key:

| Key | One bucket per | Watch out for |
|-----|----------------|---------------|
| `client_ip` | Address | A NAT or a CDN is one bucket for everyone behind it |
| `client_net` | `/24` or `/48` | Deliberately coarser; an office shares with its neighbours |
| `route`, `endpoint` | Route, or method plus path template | A global ceiling, not a per-client one |
| `country` | Country | Only with a geo database; falls back to the address |
| `identity`, `identity:<kind>` | Verified identity | Runs *after* the filter chain, so an unauthenticated request never reaches it |
| `device` | Challenge cookie device id | Needs the challenge with `device` on |
| `ja4` | TLS fingerprint | Only for TLS connections |
| `header:`, `cookie:`, `jwt:` | That value | A value that never repeats fills the key table |

Every key that cannot be answered falls back to the client address
rather than to one shared bucket, which is why a policy keyed on a
header can still refuse a client that never sends it.

**A sliding window and a token bucket behave differently under a
burst.** A token bucket allows `burst` immediately and then refills at
`rate`; a sliding window counts `limit` in `window` with no burst
allowance at all. A limit that "suddenly got stricter" is often a change
from one algorithm to the other.

**`distributed: approximate` is not a cluster-wide limit.** Peers report
consumption and each node reduces its own refill accordingly, so the
cluster total drifts above the configured rate under burst. `exact`
makes one node the owner of each key and asks it, at the cost of a round
trip inside the `exact_timeout`; on timeout the asking node decides
locally. Neither is free and the choice is deliberate.

**A ban that never expires.** Escalation doubles the duration for a
repeat offender up to `max_duration`; a client that keeps tripping the
trigger keeps extending. `xproxyctl bans` shows the current expiry, and
the escalation history is bounded so it cannot grow without limit.

## WAF

**A false positive.**

```sh
xproxyctl waf                 # profiles, routes, counters, rules by hits
xproxyctl waf proposals       # learned exclusion candidates
xproxyctl waf exclusions      # the same, printed as SecLang to review
xproxyctl waf reset           # clear the statistics (audited)
```

The access line's `waf_matched` names the rule ids. Then, in order of
preference:

1. An exclusion for that rule on that route and that argument — the
   narrowest thing that works.
2. A lower paranoia level for that route.
3. `mode: detect` for that route while you work it out, which records
   without blocking.

Do not turn the WAF off globally for one route's problem.

**Learning mode.** `mode: learn` records what *would* have blocked,
per route and rule, without acting. `xproxyctl waf proposals` then lists the
candidates and `xproxyctl waf exclusions` prints them as SecLang you can
review and paste. This is the intended way to introduce the WAF to an existing
application.

**Gradual enforcement.** `block_share` blocks a percentage of matching
requests and `canary_clients` blocks only for chosen clients. A rule
that "sometimes blocks" is usually this, working as configured.

**A reload with a WAF error.** The error names the file and the line of
the bad directive and the old rules stay active. Rule files are read at
load and on reload; a rule set updated on disk needs a reload to take
effect.

**The WAF does not see the body.** Bodies over `request_body_limit` are
not inspected. The limit exists because inspection buffers; raise it for
a route that needs it, and watch the buffered-body budget.

## Virtual patches and the positive policy

Both refuse before the WAF and before the filters, which is why a
request they refuse never appears in the WAF counters.

**A virtual patch never fires.** Every condition in it must hold: hosts,
routes, methods, path prefixes, path patterns, query, headers, cookies
and the body pattern are ANDed. `xproxyctl patches` shows each patch
with its hit count and the time it last matched — a patch with zero hits
and traffic that should match it has a condition that does not.

**A patch fires on traffic it should not.** A patch with no selectors
matches everything; validation requires at least one condition, but
"one condition" can be a path prefix of `/`. Narrow it and watch the hit
count.

**A patch expired.** `expires` disables it after the date, which is the
point: a temporary measure should not outlive the fix. `xproxyctl
patches` shows the expiry. An expired patch is not an error and is not
removed from the configuration.

**A patch with a body pattern on a large body.** The body is buffered up
to `max_bytes`; past that the patch treats the body as matching unless
`over_limit: skip` says otherwise. Failing closed is the default because
a patch exists to block something specific.

**405 with `reason: policy` and an `Allow` header.** The route's policy
lists methods and the request's is not one. Unlike `routes[].methods`,
which selects the route, the policy refuses — so a method that is not in
the policy gets a 405 from this route rather than falling through to
another.

**The policy refuses a parameter the application accepts.** The policy
is the contract: `deny_unknown_query` refuses parameters not in the
list, a repeated parameter is judged for *every* value, and
`max_repeat` defaults to 1. `detail` names which rule refused.

## Authentication

**JWT.** The security log names the category, which is the fastest way
to the cause:

| Category | Means |
|----------|-------|
| `missing` | No `Authorization: Bearer` and none of the configured alternatives |
| `malformed` | Not three base64url segments |
| `signature` | The signature does not verify against any current key |
| `unknown_key` | The `kid` is not in the key set; a rotation the proxy has not fetched yet |
| `expired`, `not_yet_valid` | `exp` / `nbf` against the clock, with the configured leeway |
| `issuer`, `audience` | The claim does not match the configuration. Absence also fails — deliberately |
| `algorithm` | The token's algorithm is not in the allowed list (`none` never is) |
| `keys_unavailable` | The key set never loaded. 503, not 401, because it is the proxy's problem |

`keys_unavailable` is the one to escalate: check `jwks_url`,
`jwks_ca_file` and egress from the proxy to the provider.

**Introspection accepts nothing.** A missing `iss` or `aud` in the
introspection response fails, the same as on the JWT path. If your
authorization server answers with a bare `{"active": true}`, it must be
configured to return the claims, or the route must not use `audiences`.

**OIDC loops between the provider and the proxy.** Almost always the
redirect URI. Set `external_url` explicitly: without it the URL is
derived from the request, and `X-Forwarded-Proto` is honoured only from
a peer inside `trusted_proxies`. A provider that redirects to `http://`
when you serve `https://` is this, every time.

**OIDC session lost on every request.** The cookie is not coming back:
check `cookie_domain`, and that the browser is not blocking a
`SameSite=Lax` cookie on a cross-site POST.

**Basic auth or LDAP is slow under load.** Password verification is
deliberately expensive and runs under a bounded semaphore; a queue that
is full refuses rather than growing. If this is the bottleneck, the
answer is a token-based scheme in front, not a cheaper hash.

**Client certificate identity headers are empty.** `cert:` template
variables are empty without `client_auth` on the listener. A client
certificate the listener did not request is not present at all.

**A client supplied the identity header itself.** It cannot: a header
whose template reads a `${cert:...}` field is removed from the incoming
request before the operations run, whether or not the `when` condition
admits them. That is the one case where a header is stripped even when
the block does not apply, and it is why a forged `X-Client-Cn` never
reaches the origin.

**The JWT is valid and the route still refuses.** Check the order: the
route's `jwt` block names a provider, and a provider with `audiences`
requires the claim to be present *and* to match. Absence fails
deliberately — a token minted for something else should not be accepted
by omission.

**Key rotation at the provider.** `unknown_key` means the `kid` is not
in the cached set. The set is refetched on a schedule and on an unknown
key, with a back-off; a provider that rotates faster than the back-off,
or one that is unreachable from the proxy, produces a window of
`unknown_key`. `keys_unavailable` is the harder failure: the set never
loaded at all, and the route answers 503 rather than 401 so that it
reads as an outage.

**LDAP binds succeed for one user and not another.** DNs are compared
case-insensitively, so case is not it. Check the `user_filter` template
against the account that fails — a filter that assumes an attribute
every account has is the usual cause — and remember that the filter is
parsed per attempt, so a deeply nested one costs on every login.

## The challenge and CAPTCHA

**An API client gets an HTML page.** The challenge is for browsers.
Exempt the client's network (`challenge.exempt_cidrs`), or scope the
challenge to the routes that browsers use.

**Everyone is challenged repeatedly.** The cookie is not surviving.
Check: `bind_ip` with a client whose address changes mid-session (mobile
networks), `bind_ja4` with a client that renegotiates differently, and
`cookie_scope: host` with a site that spans several hosts — a pass
earned on one host is then deliberately not valid on another.

**`verification table full` or `verification quota spent`.** The replay
table is partitioned per client address; one client's quota does not
affect anybody else. A single client seeing this is solving far more
challenges than a browser would.

**429 on `/.xproxy/challenge`.** Verification is rate limited per client
address. A browser posts one per page; a script posts more.

**CAPTCHA always fails with `captcha hostname`.** The hostname the
provider reports is compared against `challenge.captcha.hostnames`, or
the host names your routes configure. If your CAPTCHA site key is
registered for a different hostname than the proxy serves, they will
never agree.

**CAPTCHA fails with `captcha provider error`.** Egress from the proxy
to the provider, or the secret file. Note that provider failures do
*not* count against the client, so this will not ban your users.

## Filters

**`xproxyctl filters`** lists every registered kind and every configured
instance with its stage.

**ICAP.** `xproxyctl icap` shows each service's state and last error.
`fail: closed` turns a service outage into 502s (`reqmod_unavailable`);
`fail: open` passes traffic unscanned. Choose deliberately. A response
replaced by the scanner shows `icap_verdict: replaced`.

**WASM.** A module that panics or exceeds its fuel is contained and the
request continues or is refused according to the filter's configuration;
the error log names the module. A module rebuilt on disk needs a reload.

**`sensitive_data` blocks legitimate traffic.** `action: log` first,
always: it records findings without acting, and the counters tell you
what a `block` would have done. Then narrow `types` and `detectors`.

**`sensitive_data` refuses with `unscannable`.** The body could not be
read: an unimplemented content coding, a corrupt compressed body,
several `Content-Encoding` headers, or a `Content-Range`. The default
for requests is to refuse, because an origin reads those bytes whatever
the header claimed. `unscannable: skip` restores the old behaviour for a
route that genuinely needs it.

**`upload_guard` refuses with `multipart_disposition`.** The part's
`Content-Disposition` names a file in a spelling this proxy cannot parse
but a framework can (a duplicate `filename`, a trailing bare parameter).
It is refused rather than ignored. A client library producing that is
worth fixing.

**`openapi` rejects a request the application accepts.** The description
is the contract here. `strict_query` refuses undeclared parameters; a
repeated parameter is validated for *every* value, not just the first.
Update the description or relax the filter.

**`graphql` refuses with `expansion`.** The query's fragments expand
past the visit budget. A legitimate query does not; a generated one
might, and should be simplified.

**`account_guard` blocks a real user.** `xproxyctl accounts` shows the
ladder state per key. Counts keyed on the account belong to the person
being attacked, not the attacker, which is why no built-in class blocks
on the account alone. If you added such a rung, that is the cause.

**Filter order.** Filters run in the order `routes[].filters` lists
them, and the first deny wins. Put the cheap, decisive ones first — an
API key check before a body-inspecting scanner — or you pay for the
expensive one on requests the cheap one would have refused.

**A filter that buffers the body changes what else can happen.** Every
body-materialising filter (`upload_guard`, `sensitive_data`,
`account_guard`, `openapi`, `graphql`, `body_rewrite`, `wasm`, the WAF's
body inspection, a virtual patch body pattern, a mirror) charges the
process-wide budget for the life of the request. Adding one to a route
with large bodies is how a working configuration starts answering 503
`body_budget` under load.

**`api_key` refuses a key that is in the file.** Check its state:
`xproxyctl apikey list` shows each key with its scopes, expiry and
whether it is revoked. A rotated key keeps the old secret only for the
grace period. The key itself is removed from the forwarded request
(`strip`, on by default), and a client-supplied copy of the forwarded id
header is always removed — so an origin that reads `X-Api-Key-Id` reads
the proxy's word for it, never the client's.

**A filter's deny count is zero and you expected otherwise.**
`xproxyctl filters` counts denials per instance. Zero with traffic on
the route means either the filter admits everything, or the requests die
before the filter chain — see [Where a request can
die](#where-a-request-can-die).

## Form honeypots

[DECEPTION.md](DECEPTION.md) is the chapter behind this section and the
five that follow it: what each deception control is for, how its
signals chain into the others, and the order to deploy them in.


**Real people are refused with `field:<name>`.** Something is filling
the hidden field for them, which means it is not hidden enough. A
password manager will fill an input it can see in the DOM: give it
`tabindex="-1"` and `autocomplete="off"`. An accessibility tool will
read a field that is only visually hidden: `aria-hidden="true"` and a
label that says to leave it empty. And a field positioned off screen
survives a stylesheet that failed to load, where `display:none` set in
CSS does not — a person on a page with no styles sees the field and
fills it in.

**Real people are refused with `too_fast`.** `min_seconds` is set to
what an average fill takes rather than the shortest honest one. A
password manager submits a login form in well under a second, a
one-field newsletter box almost as fast, and a returning user with a
browser-autofilled address form faster than you would guess. Read
`form_seconds` in the access log for the denied requests: the
distribution tells you where the floor belongs. Fields are the half
with no false positives; timing is the half to tune.

**Real people are refused with `too_old`.** A form left open in a tab
over lunch is ordinary. `max_seconds` guards against a page harvested
once and replayed for weeks, so hours, not minutes — and remember a
reload of the form page refreshes the record.

**Real people are refused with `no_form_fetch`.** `require_fetch` is
set on a page that can reach the client without a fetch this node saw:
a CDN or browser cache, a prerender, a form posted from another host,
or a second proxy node that served the page (the table is per process
and not shared). Turn it off unless all of those are impossible.

**Nothing is ever refused.** Check the obvious first: the hidden field
has to be in the served HTML, and its `name` has to match `fields`
exactly. Then check the filter runs at all — `xproxyctl filters` counts
denials per instance, and a route that does not list the filter never
calls it. A submission whose `Content-Type` is not
`application/x-www-form-urlencoded` is not parsed (by design), and a
body larger than `max_body_bytes` passes uninspected.

**Denies ban nobody.** A ban trigger names a built-in reason, and the
filter's default reason is its own name. Set `reason: honeypot` on the
filter to put its denies in a category a trigger can name.

**Timing stopped working after a traffic increase.** The fetch table
holds `max_clients` entries and sweeps its older half when full, so a
busy node forgets the oldest fetches. That is deliberately permissive —
a forgotten fetch is "no record", which is allowed — but it means the
timing check quietly covers less. Raise `max_clients`, or rely on
`fields`, which needs no table.

## Bot score

**A real browser is scored as automation.** `xproxyctl botscore -top N`
with `learn: true` shows the score distribution per route, which is the
honest way to pick a threshold. The signals that most often misfire on
real traffic are `fingerprint_mismatch` (a browser behind a TLS-
inspecting middlebox presents a hello the proxy does not recognise as a
browser's) and `browser_headers_missing` (a fetch from a page that sets
its own headers). Lower those weights rather than the threshold.

**Nothing is ever scored.** `log_at` defaults to 30, so lower scores
never reach the access log; `deny_at` and `challenge_at` default to 0,
which is off. A filter that is configured and does nothing is usually
configured to do nothing.

**Two of the signals never fire.** `automation_markers` and
`device_shared` both need a `challenge` section with `device` on, and
only apply once the client holds a cookie. Without the challenge they
are permanently zero.

**A client is denied and then denied for ever.** `honeypot_marked` is
worth 40 on its own and the mark lasts as long as the honeypot route's
`mark`. `xproxyctl honeypot forget IP` clears it.

## Deceptive answers

**An endpoint "works" but returns nothing useful — for one client.**
That is `deceive`, and it is meant to look exactly like this. The
access line for that client carries `deceived: <route>` and a `deceive`
security event names the route, the path and the method; `xproxyctl
honeypot` says whether the client is marked and why. `GET /v1/deceive`
lists the routes that deceive and how often each has.

**A real client was deceived.** Clear the mark (`xproxyctl honeypot
forget IP`), then fix what marked it: a decoy on a path something real
reaches, a `bot_score_at` too low for the traffic, or a
`client_cidrs` range wider than meant. Remember that a deceived write
never reached the origin, so anything that client sent while deceived
is gone — check what it was doing before deciding it is only a
configuration issue.

**Nothing is deceived although the block is there.** The conditions are
AND-ed with the method narrowing and OR-ed among themselves: `marked`,
`bot_score_at` and `client_cidrs` each admit on their own, but
`methods` must also match. A `bot_score_at` needs a `bot_score` filter
on the route to produce a score at all.

**Is it safe to turn on?** The honest answer is that it is the one
control here whose failure mode is silent. Run it first with
`client_cidrs` on a range you have watched in the access log, or with
`marked: true` and honeypots you trust, and watch `deceived` against
the request count for a week before widening it.

## The slow lane (degradation)

**A client says the site is slow, and it is not banned.** Look for
`degraded: <level>` in its access log lines. A level admits a client
for one of three reasons — a honeypot or honeytoken mark, a bot score
at or above `bot_score_at`, or a `client_cidrs` range — and the first
level that admits the request decides, so a wide level above a narrow
one takes traffic the narrow one was written for. `xproxyctl honeypot`
shows whether the client is marked and why; `xproxyctl honeypot forget
IP` clears it, and the next request is served at full speed.

**Everything is degraded.** A level with no condition and no selector
is refused by validation, so this is a level whose selectors are wider
than intended: a `client_cidrs` prefix that is shorter than meant, or
`marked: true` with a honeypot on a path ordinary clients reach. The
`degraded` counter against the request count is the quickest check.

**A degraded response is not slower.** Three reasons. `bytes_per_second`
shapes the body, so a small response finishes inside the first
second's allowance and arrives at full speed — that is deliberate.
`delay` needs a free tarpit slot (`max_tarpits`); when none is free the
response is served without it, and `tarpit_overflow` counts that.
And a shaped response only slows what the proxy writes: a hijacked
connection (WebSocket, CONNECT) is not shaped.

**Legitimate clients are marked.** That is a honeypot problem rather
than a degradation one: a decoy on a path something real reaches, or a
crawler reading a file served honestly. See [Honeypot marks](#honeytokens)
and give a decoy served honestly `mark: 0s`.

**How much is it costing us?** A held response occupies a tarpit slot
and a shaped one occupies a connection for longer, which is the trade.
`in_flight`, `open_connections` and `tarpit_overflow` are the numbers
to watch; if the tarpit is overflowing, either the delay is too long
or the level is too wide.

## Refusal at the TLS handshake

**A client reports a TLS error and nothing appears in the access log.**
That is `handshake` doing its job, and the missing line is the trade it
makes. Look in the security log for `reason: handshake`: it carries the
client address, both fingerprints and the detail (`banned` or
`fingerprint`). `xproxyctl tls` prints the policy and the refusal count
above the certificates, and `xproxy_tls_handshakes_refused_total` is
the series to graph.

**Legitimate clients are being refused.** Almost always a
`deny_fingerprints` prefix that is wider than intended: a JA4 prefix
names a TLS stack, and browsers share stacks with the tools built on
them. Take the prefix out, put back the full fingerprints you have
actually seen in your own logs, and check the `ja4` field in the access
log for what else matches.

**A banned client still gets a handshake.** `refuse_banned` needs a
`bans` section (validation refuses it otherwise), and it only refuses
what the ban list already holds — an address ban, or a fingerprint ban.
A client banned *during* its connection keeps that connection: the
refusal is per handshake, and existing connections are not torn down.

**Nothing is refused although the policy is set.** The policy is per
TLS listener; a plain HTTP listener has no handshake to refuse in, and
validation warns when no listener has a `tls` section. An HTTP/3
listener is covered, because QUIC carries the same ClientHello.

**How to test one.** `openssl s_client -connect host:443 -servername
name` shows the failed negotiation; the proxy's security log line for
the same moment names the reason. There is deliberately nothing in the
alert for a client to read.

## Honeytokens

**A token never fires, although the decoy holding it was read.** Three
things in order. The value must be the one actually served — compare it
against the decoy body, character for character, since a trailing
newline or a shortened key is a different string. The field must be one
the token looks in: `in` defaults to all four, but a token narrowed to
`cookies` will not see the same value in a header. And the match mode
has to suit the plant: `exact` compares the whole field value once a
`Bearer `/`Basic `/`Token `/`ApiKey ` scheme is stripped, so a token
sent as `key=<token>&x=1` inside one parameter value matches, while one
embedded in a longer string needs `match: contains`.

**A token fires on traffic that never saw the plant.** It was planted
somewhere real traffic reaches, or the value is not distinctive enough
— validation refuses values under 8 characters (16 for `contains`), but
a longer value that happens to be a common identifier will still
collide. Switch it to `action: log`, watch what arrives, and re-plant.

**The value appears in a log.** It should not: a hit logs the token
name, the field and the description. If the *value* is in an access log
line, it arrived somewhere the access log records — the path. Move that
plant to a header, a cookie or a query parameter, none of which the
access log writes (`query_len` is a length, not the query).

**Where did the hit come from?** The security event carries
`client_ip`, `field` and `token`; the access line for the same
`request_id` carries the rest. The client is also marked, so its later
requests are labelled `honeypot_marked` and `xproxyctl honeypot` shows
the address with the token name as its route.

**Nothing is banned after a hit.** The ban needs a trigger on reason
`honeytoken`; threshold 1 is the right value, because nobody sends one
by accident. Without `bans`, a hit is refused and recorded but the next
request is treated on its own merits.

**A plant has to be retired.** Set `enabled: false` to keep the entry
and stop watching, or remove it. The counters survive a reload but not
a restart, so record the hit count before a restart if it matters.

## Origin lock

**The origin refuses everything.** Run `xproxyctl origin-check`: it
sends an unsigned and a signed request to each endpoint of every
upstream that has an `origin_signature` and reports the verdict per
endpoint. A non-zero exit means at least one origin is not enforcing.

| Verdict | Means |
|---------|-------|
| `enforced` | The origin refused the unsigned request and accepted the signed one. This is the goal |
| `not_enforced` | The origin served the unsigned request. The lock is not being checked at all |
| `inconclusive` | The origin refused both. The key, the header name or the clock disagree |
| `unreachable` | Neither probe got an answer. Network or TLS, before any of this |

**`inconclusive` on a freshly rotated key.** `xproxyctl rotate-secret` adds a
new primary and keeps the previous one, so the proxy signs with the new
key while the origin still verifies with either. If the origin has only
the old key it still verifies; if the origin has only the *new* key and
the proxy has not reloaded, it does not. Rotate, then reload, then
update the origin.

**`closed` with the clocks minutes apart.** The signature carries a
timestamp and the origin should refuse one older than the TTL — and one
more than a minute in the future. Two hosts whose clocks differ by more
than the TTL will never agree. This is the same class of problem as JWT
`exp`; see [Clocks and expiry](#clocks-and-expiry).

**413 with `larger than a signed body digest covers`.** `body_digest`
is on and the body is over 8 MiB. The request is refused rather than
forwarded with a signature that covers only the headers, because a
signature that stops at the headers is one a replay can attach any body
to.

## Virtual security.txt

**The file is not served.** Entries are tried in order and the first
whose selectors *all* match answers. An entry with hosts, a host
pattern, client CIDRs or listeners listed answers only for those; an
entry with no selectors answers for everything, so it belongs last. A
request that matches no entry is routed normally, which is how an origin
that serves its own file keeps doing so.

**405 on the path.** Only `GET` and `HEAD` are answered.

**An expiry warning at start.** RFC 9116 asks for an `Expires` less than
a year out. More than three years produces advice, not an error.

**The document is stale.** It is rendered once and cached for
`cache_for`; a reload rebuilds it. A `body_file` is read at load, so a
file edited on disk needs a reload like any other.

## Cluster

```sh
xproxyctl cluster     # peers, connected state, messages sent and received
```

**A peer never connects.** In order: the address and port, mutual TLS
(each node needs a certificate the other's CA signs), and
`bind_node_id` — on by default, it requires the announced `node_id` to
be a name the peer's certificate carries. A cluster whose certificate
names and node ids differ will not connect until they agree, which is
the point.

**`allowed_names` is empty.** Then any certificate the CA ever issued is
a cluster peer, and a cluster certificate is full trust inside the
cluster. Validation says this out loud. Use a CA that issues nothing
else, and list the names.

**Rate limits are not shared.** Sharing reduces refill from peer
reports; it does not make a distributed exact limit unless
`distributed: exact` is set, and that has its own trade-off (the key's
owner decides for every node).

**Bans propagate but marks do not, or vice versa.** Both travel as
events. A peer event's lifetime is clamped to what *this* node would
have chosen for that kind, peer-sourced marks have their own quarter of
the table, and an unmark only concerns a mark from the same peer. A mark
that "did not arrive" may have been clamped to nothing by a local
configuration with no honeypot routes.

**A peer connects and then disconnects repeatedly.** Every node dials
the peers it is configured with and accepts from the ones that dial it,
so a one-way firewall rule gives you a link that exists in one direction
only. `xproxyctl cluster` on *both* nodes is the check: a peer that
appears connected on one side and not on the other is this.

**Everything is shared and you wanted less.** `share_rate_limits`,
`share_bans` and `share_events` are separate switches, all on by
default. Events are honeypot marks and revoked sessions; a node older
than 1.3 closes a connection that carries them.

**Two nodes, one state file.** They must not share the ban `state_file`
or the management socket over a network filesystem. Bans propagate as
events; the file is each node's own.

## DNS listener

**Queries time out.** `allow_clients` refuses silently by design (a
refusal to a spoofed source is an amplifier). Check it first.

**SERVFAIL for a name that resolves elsewhere.** DNSSEC validation
failed. `dns_bogus` in the security log names the query. A client that
sets CD gets the data anyway — and that answer is deliberately not
cached for anyone else.

**Answers are truncated over UDP.** `ANY` over UDP is always answered
with TC=1 (RFC 8482). Large answers are truncated to the advertised EDNS
size; a client that wants them retries over TCP.

**`xproxyctl dns`** shows queries, cache entries, blocked counts and the
DNSSEC result tally.

**A blocked name still resolves.** `block_action` decides what a blocked
query answers: `nxdomain` (the default) or `sinkhole`, which answers the
configured address. A client that caches a previous answer keeps using
it until its own TTL expires; `xproxyctl dns purge` empties this proxy's
caches, not theirs.

**The block file does not take effect.** It is read at load and on
reload, like every other file. A file edited in place needs a reload.
Comments (`#`, `;`) and blank lines are skipped, and a name that is not
a name is refused when the file is read.

**Upstream failures with no obvious cause.** A `tls://` or `https://`
upstream needs the CA to be right (`upstream_ca_file`) and the name in
the URL to match the certificate. `xproxyctl dns` counts upstream
failures separately from refusals and drops, which is the fastest way to
tell a policy refusal from a broken upstream.

## Forward proxy, layer 4 and QUIC

**`CONNECT` refused with `forward_denied`.** The destination is not in
the allow list or the port is not in `ports`.

**A layer 4 route picks the default.** The server name was not readable:
a client that does not send SNI, or one that fragments its ClientHello
across TLS records in a way that never completes inside the peek
timeout. The access line has `sni: ""`.

**QUIC flows are rejected.** `quic_rejected` counts them. A datagram
that is not a QUIC v1 Initial, or one whose ClientHello never completes
within the pending-datagram bound, is dropped.

**HTTP/3 clients fall back to HTTP/2.** Check that the UDP port is
actually reachable (it is a different socket from TCP), and that
`Alt-Svc` is being served.

## Mirroring and shadowing

**The mirror receives nothing.** The access line says which: `sent`,
`dropped` (the in-flight bound for the route is reached) or
`body_too_large` (the body is past `max_body_bytes` for the mirror, so
the live request proceeds unmirrored). A route with no `upstream`
cannot mirror at all, and upgrade requests are never mirrored.

**The mirror is affecting clients.** It should not be able to: the copy
runs in the background, its response is read and discarded, and the live
request never waits for it. What *can* affect clients is the buffering
— a mirrored route holds the body so both requests can read it, which
charges the buffered-body budget. A route that starts returning 503
`body_budget` after a mirror was added is this.

**The shadow diff reports differences that are not real.** Pick stable
headers. `Date`, `ETag`, `Set-Cookie` and anything with a timestamp
differ legitimately between two backends and will report a `header`
result on every request. Cookie, authorization and token header values
are never written to the log, only the fact that they differ.

**The diff reports nothing at all.** Comparison is skipped when the live
response does not finish inside the mirror `timeout`, and the detail log
is sampled by `sample_percent` even though the metric counts every
comparison. Look at `xproxy_mirror_diff_total{result}` before concluding
nothing was compared.

## Packet capture

**Nothing is written.** Both switches have to be on. `xproxyctl capture
status` answers in one line: `capture: no capture section configured`
means the configuration has none (or `enabled: false`), `capture: off`
means the section is there and nobody turned it on — `xproxyctl capture
start -duration 10m`. A capture that *was* on and stopped by itself hit
`max_duration`; that is the design, not a fault.

**The switch is on and the file stays empty.** Look at the counters in
`xproxyctl capture status`.

| Counter climbing | What it means |
|------------------|---------------|
| `skipped` only | No rule matched the traffic, a rule that waits for the answer did not want it, sampling dropped it, or a rule is at its `max_flows`. The per-rule lines below the counters say which rule is taking anything at all |
| `failed` | The file could not be written: the directory is gone, full, or not writable by the proxy user. The sandbox allows the configured `directory` because the rules are derived from the configuration, but a reload that moves it somewhere Landlock was not given is refused with a message to restart |
| nothing at all | No exchange reached the capture. Connections refused below HTTP — a TLS handshake that failed, a listener bound that closed the connection, a layer 4 listener — are not exchanges and are not recorded; a request refused above it, including one refused before routing, is |

**A rule matches nothing.** Every selector a rule names has to hold, and
the first matching rule decides, so a broad rule above a narrow one
takes the traffic the narrow one was written for — put the catch-all
last. `routes` needs the route *name*, `hosts` matches the request
authority (a `*.example.com` pattern is not the apex), `paths` are
prefixes of the cleaned path, and `client_cidrs` compares the derived
client address, which is the `X-Forwarded-For` one only when the peer is
in `trusted_proxies`.

**A rule on `statuses`, `reasons` or `denied` seems not to fire.** It
fires at the end: none of them can be decided when the request arrives,
so the exchange is held and written once the proxy has answered. That
includes the refusals that happen before routing — a ban, the
maintenance gate, a malformed `Host`, the concurrency ceiling — which
the request-side selectors cannot describe (there is no route yet) but
which a `denied` or `reasons` rule still captures, without bodies,
because nothing read them. What it
cannot do is match a request that never got a status — a client that
disappeared mid-request is written as `HTTP/1.1 000 No Response`.
`reasons` matches the reason and the reason with its detail, so `waf`
also selects `waf:942100`; the deny reasons are listed under "Deny
reasons and details" below.

**Wireshark shows the conversation but no HTTP.** Check the port. The
synthesised conversation uses the real client and listener ports, and a
listener on a port Wireshark does not associate with HTTP needs `Decode
As… HTTP`. An HTTP/2 or HTTP/3 exchange is written with an `HTTP/1.1`
start line for exactly this reason, because those have no status line on
the wire.

**The bodies are missing or cut short.** `bodies: false` is the default:
only the heads are captured. With bodies on, each one is bounded by
`max_body_bytes`, and a body that hit the bound is marked `truncated` in
the frame comment and counted in `truncated` — the stream is short
because the bound cut it, not because the client stopped. A body the
handler never read is a body the upstream never saw, and is not in the
file either.

**The file disappeared.** Rotation. A file past `max_file_bytes` is
closed and a new one opened, and only `max_files` are kept — the oldest
is removed. Copy a capture out of the directory before it is worth
keeping.

**A header value reads `REDACTED`.** That is `redact` doing its job. It
is a fixed string rather than a blanked-out value, so the file carries
neither the value nor its length. Remove the header name from `redact`
to capture it — and then treat the file accordingly.

**Somebody left a capture running.** `xproxy_capture_active` is 1 while
one is recording; alert on it. The audit log has the answer to who:
every `capture` action is written there with the caller's uid, gid and
pid. The window ends by itself after `max_duration`, so the worst case
is bounded by that value, not by the operator's memory.

## The API inventory

**An endpoint is reported as shadow when it is documented.** The
inventory compares what it observed against the route's `openapi`
description. A path that is documented under a template the proxy does
not derive from the observed path — a numeric id it read as a literal
segment rather than a parameter — reads as undocumented. The `top` view
shows the template it derived.

**Everything is a zombie after a restart.** The inventory keeps its
state in `api_inventory.state_file`, written every `save_interval` and
at shutdown, and restores it at start. Without that key it begins empty,
and every documented operation that has not been called since the
restart looks unused.

**The table is full.** The endpoint table is bounded like every other
one; past the bound, new endpoints are dropped and counted rather than
growing. An application that puts an id in the path without the proxy
deriving a template is the usual cause, and the fix is the description,
not the bound.

## Kubernetes ingress mode

**No routes appear.** In order: the ingress class on the resource must
equal the configured class (the field wins over the deprecated
annotation, and an Ingress with neither is nobody's); the service and
its EndpointSlices must exist and have ready endpoints; and the
namespace must be one the controller watches. `xproxyctl ingress` shows
syncs, watch state, counts and the warnings the last translation
produced — the warnings are where a dropped rule says why.

**A rule is dropped with a warning about a host or a path.** Hosts and
paths from an Ingress go into the proxy's own routing keys, metric
labels and log fields, so a host must be a DNS name and a path a plain
prefix. A space, a control character or a NUL in either is dropped
rather than routed, because a tenant who can create an Ingress could
otherwise write into another tenant's telemetry.

**A TLS secret is ignored.** It must be of type `kubernetes.io/tls`. An
Opaque secret that happens to carry `tls.crt` and `tls.key` is refused,
because a reference to one is a way to publish any key in the namespace.

**A Gateway certificate reference is refused.** A reference into another
namespace needs a ReferenceGrant, which is not implemented, so it is
refused rather than honoured. Without that check anyone able to create a
Gateway could mount any TLS private key in the cluster under a host name
of their choosing.

**The Gateway API is not picked up.** The CRDs are optional: a cluster
that answers 404 for them is not an error and the controller records
that the API is absent. `xproxyctl ingress` says whether it found them.

**A sync fails and the routes vanish.** They do not. A failed fetch
leaves the previous generation in place; the controller logs the
resource that failed and retries. What *can* remove routes is a
successful sync of a cluster that genuinely no longer has them.

## Fleet

**A node never fetches its bundle.** The controller authorises by
certificate name: it must equal the node id, unless the controller's
`-name-map` names that exception. `xproxy-fleet nodes` shows what the
controller thinks it knows about each node.

**A bundle applies and then rolls back.** The node applied it, the proxy
refused the configuration, and the node restored the previous files —
which is the design. The node's status carries the error; so does its
own error log.

**`-any-name` warnings on every authorisation.** Intended: with it, one
stolen node certificate can fetch every node's bundle and report as any
node. Use `-name-map` instead.

## Management socket and GUI

**`xproxyctl` cannot connect.** The socket path (`xproxyctl -socket`),
the process running, and the socket's mode and group. `xproxyctl` needs
read *and* write on the socket.

**The GUI refuses a login with 429.** Five failures lock that address
and account pair for five minutes; a hundred failures from anywhere in
the same window close the login page for everyone. Over a Unix socket or
an SSH tunnel every client shares one address, which is why the account
is part of the key.

**A user removed from the users file can still log in.** They cannot:
the file is re-read when it changes and the account behind a session is
resolved on every request. If it looks otherwise, the file the GUI reads
is not the file you edited — `xproxy-admin` names it at start.

**`xproxy-admin` will not start: a user has an empty hash.** A line of
the users file is `name:role:` with nothing after the last colon, which is a truncated line or an edit that lost the hash. Such a
user would appear in the list and never be able to log in, so it is
refused at the file rather than at the login page. Set a password with
`xproxy-admin user add`, or write the literal `x509` as the hash for a
user who only logs in with a client certificate.

**The log view is empty.** A stream that is configured but whose file
does not exist yet reads as an empty view, which is the state right
after an install and after a rotation nothing has written into. Check
`logging.directory` and the stream's `file`, and that the GUI's
`-config` is the data plane's own configuration file: the log view
resolves the file through it, not through its own options. A stream
that is not configured at all is refused with 400, not shown empty.

**Saving the configuration from the GUI answers 413.** The editor
accepts 8 MiB of text. A document larger than that belongs in a
configuration directory with includes (`-config` pointing at a
directory), not in one file.

**Saving the configuration answers 409.** Somebody else (or another tab)
saved since this one was opened; the entity tag no longer matches.
Reload the editor, which re-reads the file, and reapply the change. The
file is never overwritten on a stale tag.

**A viewer can see too much.** `viewer` is a trusted operator without
write access: it reads the whole configuration file, the logs and the
bans. It is not a low-privilege role. Do not give it to anyone who may
not see the configuration.

**The socket exists and `xproxyctl` still cannot use it.** The mode is
`0660` and the group is the service's, so the caller must be in that
group or be root. A read-only bind mount, or a socket on a filesystem
mounted `noexec`/`nosuid` in a container, produces the same symptom with
a different cause.

**`xproxyctl` talks to the wrong proxy.** `-socket` defaults to the
compiled-in path. Two proxies on one host need two socket paths and
`-socket` on every command; `xproxyctl status` prints the configuration
path the daemon is running, which is how you tell them apart.

## Logs, metrics, traces and SIEM

**An access line is missing fields.** `logging.access.fields` selects
them, and sampling drops whole lines. Both are configuration, not
failure.

**Security events are missing.** `logging.security.enabled`, and the
sinks for that stream. Aggregated events (a banned client looping
connections, blocked DNS queries) are deliberately summarised: one
warning per interval with an occurrence count, not one line per packet.

**Redaction did not cover something.** Redaction covers the log streams
and the SIEM export, and a span's `client.address`. The rest of a trace
— the host and the path — is outside it, and the access log carries the
trace id, so treat the trace collector as holding those values in the
clear.

**The SIEM queue drops.** It is bounded on purpose; drops are counted
and visible in `xproxyctl telemetry`. A collector that cannot keep up
must not be able to stall the data plane.

**Traces do not appear.** Sampling (`sample_percent`), and
`trust_incoming` — by default an incoming `traceparent`'s sampled flag
is *not* honoured, so a client cannot force every request into your
exporter.

**Prometheus scrape is refused.** The metrics listener has its own
access list; refusals are aggregated into one warning rather than one
per attempt.

**A counter and a metric disagree.** They are the same numbers with
different lifetimes: counters in `xproxyctl status` are since start, the
Prometheus families are the same counters, and the sampled series behind
`xproxyctl series` are windowed by `retention`. A rate computed over a
window will not equal a total.

**Per-route metrics are missing.** `metrics.per_route` is on by default
but produces one series per route, bucket and outcome; a deployment that
turned it off to control cardinality is the usual reason a route
dashboard is empty.

**The access log grows faster than expected.** Sampling
(`sample_percent`) and `always_log` interact. `always_log` is on by
default and keeps every line whose response was 4xx or 5xx, or whose
request was denied, whatever the sampling says. A route that errors
constantly therefore logs every error even at one percent sampling,
which is the intent and also the surprise.

**Log rotation loses lines.** The proxy writes to the path it opened.
After an external rotation, `xproxyctl reopen-logs` (or
`systemctl reload`) makes it open the new file; until then it writes to
the rotated one, which still exists under its new name.

## Sandbox, systemd and SELinux

**`/v1/health` says `degraded`.** A hardening mechanism did not take
effect: an old kernel without Landlock, a container without the seccomp
syscall, a missing capability. The `degraded_reasons` name it.
`sandbox.strict: true` makes it fatal at start instead.

**A file is unreadable only under systemd.** `ProtectSystem`,
`ReadWritePaths` and `ProtectHome` in the unit, and SELinux labels.
`journalctl -u xproxy` shows the permission error; `ausearch -m AVC -ts
recent` shows the denial if SELinux is the cause.

**Socket activation does not hand over the socket.** `LISTEN_FDS` must
match the sockets in the unit, and the listener addresses in the
configuration must match the sockets systemd created. A mismatch makes
the proxy bind its own socket, which fails for a privileged port.

**The process cannot write its state files.** `state_dir`, the ban
`state_file` and the API inventory file all need a writable directory
owned by the service user. These are the paths that survive a restart;
losing them is not fatal but you lose history.

## Performance: latency, memory, CPU, descriptors

**Latency added by the proxy.** The access line has `duration_ms` for
the whole request and nothing for the upstream's share, so take the
share from one of two places: the per-endpoint `LATENCY-MS` column of
`xproxyctl upstreams` (a smoothed time to first byte, which is the
upstream's own speed) or, with tracing on, the client span inside the
server span for one request. A consistent gap between the two is the
proxy's own work: WAF inspection, body-buffering filters, compression.
`xproxyctl waf` shows the rules by hits, which is usually where it
goes.

**Memory grows and does not come back.** In order of likelihood: two
generations alive after a reload (resolves itself), a body-buffering
filter on a route with large bodies (check
`buffered_body` in `xproxyctl stats`), the response cache
(`cache.max_bytes`), and bounded tables that are genuinely full under
attack. The buffered-body budget is the one to raise or lower
deliberately: `server.limits.max_buffered_body_bytes`, 512 MiB by
default, refuses with 503 and `reason: body_budget` rather than growing.

**CPU is high with little traffic.** Usually a regular expression: a
`path_regex` route, a WAF rule, a `sensitive_data` custom detector or a
virtual patch body pattern. `xproxyctl waf` and the route list narrow
it.

**Too many open files.** `LimitNOFILE` in the unit. Each client
connection, each upstream connection and each log file costs one. The
connection limiter (`max_connections`, `max_connections_per_ip`) is the
bound that keeps this from being unbounded.

**Connections pile up in `CLOSE_WAIT`.** Almost always an upstream that
does not close; `timeouts.idle` and the layer 4 `idle_timeout` reclaim
them.

**Latency is fine at the median and terrible at p99.** Look for work
that only some requests do: a body-inspecting filter that triggers on
one content type, a WAF rule with a body pattern, a route whose upstream
pool has one slow endpoint (`xproxyctl upstreams` has the per-endpoint
latency), or a cache that misses for one path shape. The per-route
latency histogram in the Prometheus exposition separates them.

**Throughput drops when TLS is added.** Handshakes, not records. A
client population that does not resume — no session tickets, or tickets
invalidated by a restart — pays a full handshake per connection.
`server.session_tickets` and a longer `idle_timeout` both help more than
any cipher choice.

**Memory is flat and the machine still swaps.** The response cache is
bounded by `cache.max_bytes` and the body budget by
`max_buffered_body_bytes`, but neither bounds the Go heap's own
fragmentation. The number to watch is RSS against those two bounds plus
the connection count; if RSS is far above their sum, it is worth a
report.

## Capacity and sizing

The bounds interact, and the defaults are chosen for a machine, not for
your machine. The ones that matter, and what to look at:

| Bound | Default | Raise it when |
|-------|---------|---------------|
| `max_connections` | 65536 | `rejected_connections` is rising and the machine has descriptors to spare |
| `max_connections_per_ip` | 256 | Real clients share an address (a NAT, a CDN, a corporate proxy) and are being refused |
| `max_concurrent_requests` | 16384 | 503 with `Retry-After: 1` under load the upstreams can actually serve |
| `max_buffered_body_bytes` | 512 MiB | 503 `body_budget` with memory to spare and body-inspecting filters you need |
| `max_tarpits` | 1024 | `tarpit_overflow` is rising and you want the holds rather than the refusals |
| `LimitNOFILE` | the unit's | Any of the above is raised; each connection costs a descriptor on each side |

Two multiplications worth doing before raising anything:
`max_connections_per_ip` times `max_body_bytes` is what one address can
ask the proxy to hold, and that product is why the buffered-body budget
exists. `max_concurrent_requests` times the largest per-request
allocation in your filter chain is the other.

## Clocks and expiry

A surprising share of "it worked yesterday" is a clock. Everything in
this list compares a timestamp against `time.Now()`:

| Thing | What a wrong clock does |
|-------|------------------------|
| JWT `exp` / `nbf` | `expired` or `not_yet_valid` for valid tokens, with the configured leeway as the only slack |
| Origin signature `t` | The origin refuses everything as too old, or as more than a minute in the future |
| TLS certificates | A handshake fails for a certificate that is valid everywhere else |
| OCSP staples | A staple looks expired and is not served |
| Session ticket keys | Two nodes derive different keys from the same secret and stop resuming each other's sessions |
| Ban expiry | Bans outlive or under-live their duration |
| Cache TTL | Entries expire instantly or never |
| Challenge cookies | Every client is challenged again on every request |
| Virtual patch `expires` | A patch disables itself early, or refuses to |

Check `timedatectl` on every node before looking anywhere else, and in a
cluster check that they agree with each other, not just with an upstream
server. `xproxyctl tls tickets` reports which peers derive the same key
set, which is the fastest clock check in a cluster.

## Clients that misbehave

**A client disconnects mid-request.** The access line records status
499 and `client_aborts` moves. This is not an error and not an upstream
failure; a rising 499 rate usually means a timeout *in front of* the
proxy that is shorter than the one behind it.

**A client that never reads the response.** The response fills the
socket buffer and then blocks until `write_timeout`. This is what
`write_timeout` is for; a client doing it deliberately is a slow-read
attack and the connection limiter is the bound that keeps it from
mattering.

**A client that opens connections and sends nothing.** Bounded by
`read_header_timeout` (10s by default) and by `max_connections_per_ip`.
Neither produces an access line, because neither produces a request.

**A client that retries aggressively on 429.** Its own retry storm can
keep it permanently limited. `Retry-After` is set on every rate-limit
refusal; a client that ignores it will stay refused.

**A client that sends two `Content-Length` headers.** Refused with
`framing_content_length` before routing. This is request smuggling and
is not a compatibility setting.

## Emergencies

Short, reversible things, in the order you would reach for them.

**Stop serving, without stopping the proxy.**

```sh
xproxyctl maintenance on      # 503 for everything but the allowlist
xproxyctl maintenance off
```

The allowlist (`maintenance.allow_cidrs`, `allow_header`) and any route
with `maintenance: false` keep working, so you can still reach a health
endpoint and your own tooling.

**Stop an attack from one place.**

```sh
xproxyctl ban -duration 24h -reason "credential stuffing" 203.0.113.0/24
xproxyctl ban -duration 1h  ja4:t13d1516h2_8daaf6152771_b186095e22b6
```

A JA4 ban catches a tool across addresses. Both propagate to cluster
peers.

**Take a bad configuration back.**

```sh
xproxyctl history                 # generation, time, note, size
xproxyctl rollback <id>           # audited; becomes a new history entry
```

Rollback needs `management.history_dir`. Without it, the previous file
is whatever your own change control kept.

**Get a struggling upstream out of the path.** Remove the endpoint from
the pool and reload; the reload is atomic and the drain is graceful. A
circuit breaker will do it for you if one is configured, which is the
reason to configure one before you need it.

**Turn one noisy protection off for one route.** A route's `waf.mode:
detect`, its `policy` removed, or a filter dropped from
`routes[].filters` — then reload. Prefer the narrowest scope that works;
a global `waf.default_mode: detect` turns the WAF off for everything,
including the route that is not the problem.

**What not to do in a hurry.** Do not widen `trusted_proxies` to make an
ACL pass: that tells the proxy to believe `X-Forwarded-For` from whoever
is asking. Do not set `unknown: allow` on a geo policy to fix one
client. Do not raise `max_body_bytes` globally to fix one upload route.
All three are the sort of change that is still there in a year.

## Upgrades and rollback

**Before.** Record what is running, so you can compare afterwards:

```sh
xproxy -version
xproxyctl config > /var/tmp/config.before.yaml
xproxyctl status -json > /var/tmp/status.before.json
```

**The new binary refuses the old configuration.** Validation is stricter
than it was, on purpose: a setting that used to load and do something
surprising becomes an error rather than staying surprising. The message
names the key. `xproxy -config … -validate` with the new binary, before
you restart anything, turns this from an outage into a ticket.

**A setting that used to be advice is now an error** (or the other way
round). Advice and errors are both printed by `-validate`; the
CHANGELOG says which moved.

**The configuration loads and behaviour changed.** Compare the expanded
documents, not the files: defaults change more often than keys do.

```sh
diff -u /var/tmp/config.before.yaml <(xproxyctl config)
```

**Going back.** A recorded configuration is the fastest route:
`xproxyctl history`, then `xproxyctl rollback <id>`. Rolling the
*binary* back needs the package manager; the state files (bans, the API
inventory, the ACME account, secret keyrings) are forward compatible
within a major version, so an older binary reads them.

**A cluster mid-upgrade.** Nodes of different versions peer as long as
the protocol has not changed; the CHANGELOG says when it has. Session
ticket keys derive from the shared secret and the clock, so resumption
across versions keeps working. Upgrade one node, check `xproxyctl
cluster` from both sides, then continue.

## Bounded tables and what "full" means

Every table that grows with attacker-controlled input is capped, and
what happens at the cap is a security decision. None of it is silent:
each site warns at most once per minute with the occurrences since the
last warning, and the totals are in the status views.

| Table | At the cap |
|-------|-----------|
| `rate_limit_keys` | Falls back to a coarser key — the address, then its /24 or /48 — and refuses when nothing coarser is left |
| `ban_windows` | Stops tracking new addresses |
| `honeypot_marks` | Refuses new marks; peer-sourced marks have their own quarter |
| `challenge_nonces` | Refuses, per client address rather than globally |
| `bot_score_clients` | Evicts the oldest |
| `waf_rules`, `waf_learning` | Stops recording new rules |
| Export queues | Drop, counted |

Under attack, a full table is the design working. In ordinary traffic it
means a key that never repeats — a header value with a timestamp in it,
a path with an id — and the fix is the key, not the bound.

## Deny reasons and details

**One refusal has three spellings, and they are not interchangeable.**
This trips people up more than anything else in the logs:

| Where you see it | Field | Example for one refusal |
|------------------|-------|------------------------|
| The access log | `denied` | `allow_cidrs`, `rate_limit:per-ip`, `virtual_patch:cve-2026-1` |
| The security log | `reason`, plus `detail` | `reason: acl_allow`; `reason: virtual_patch`, `detail: cve-2026-1` |
| `bans.triggers[].reasons` | the ban category | `acl`, `rate_limit` |

The access log's `denied` is the narrow form, joined with a colon. The
security log splits it into `reason` and `detail`. The ban category
folds a family together — `acl_deny` and `acl_allow` both count as
`acl`, and anything beginning `rate_limit` counts as `rate_limit` — so
a trigger is written against the category, and `reasons: [acl_allow]`
matches nothing.

`detail` is free text that narrows a reason and is never matched on.

**Not every reason can feed a ban.** A trigger may only name a category
from the *Ban* column below; validation refuses the others. That is
deliberate: a ban ladder should be fed by things a client chose to do,
not by the proxy protecting itself. Shedding, maintenance, the
buffered-body budget and a full table are the proxy's own state, and
banning a client for arriving during one of them would punish the
innocent.

| Reason | Raised by | Ban |
|--------|-----------|-----|
| `acl` | `allow_cidrs` / `deny_cidrs` (logged as `acl_deny` / `acl_allow`) | yes |
| `geo` | Country policy | yes |
| `banned` | The ban list | no (it is already banned) |
| `rate_limit` | A rate limit policy (`detail` names it) | yes |
| `concurrency` | `max_concurrent_requests` | yes |
| `body_size` | `max_body_bytes`, or a signed body digest bound | yes |
| `body_budget` | The process-wide buffered-body budget | no |
| `uri_length` | `max_uri_length` | yes |
| `bad_host` | An unusable `Host` | yes |
| `normalization` | A normalisation check (`detail` names it) | no |
| `no_route` | Nothing matched | yes |
| `websocket` | An upgrade on a route that does not allow it | yes |
| `grpc_web` | A gRPC-web request on a route without `grpc.web` | no |
| `webtransport` | A WebTransport session on a route without `webtransport` | no |
| `cors` | The route's CORS policy | no |
| `maintenance` | The maintenance gate | no |
| `policy` | The route's positive-security policy | no |
| `virtual_patch` | A virtual patch (`detail` is the patch id) | no |
| `waf` | A WAF rule | yes |
| `jwt` | JWT verification | yes |
| `icap` | An ICAP service | yes |
| `honeypot` | A honeypot route | yes |
| `honeytoken` | A request presenting a planted credential; `detail` is the token name | yes |
| `handshake` | The `handshake` section, before the connection became a request; `detail` is `banned` or `fingerprint` | no (it is already a refusal of what the ban list holds) |
| `challenge` | The challenge gate | yes (only the client's own mistakes) |
| `sensitive_data` | The DLP filter | no |
| `account_abuse` | `account_guard` | yes |
| `shed` | Load shedding (`detail` is the class) | no |
| `filter` | Any other filter (`detail` is the filter name) | no |
| `forward_denied`, `forward_auth` | The forward proxy | yes |
| `tcp_no_route` | A layer 4 listener with no route and no default | yes |
| `dns_blocked`, `dns_bogus` | The DNS listener | yes |

A trigger naming a reason that is not in the Ban column fails
validation with the list of the ones that are, so this is not something
you can get wrong silently.

## When to escalate, and with what

Not everything here is yours to fix. These are the ones to hand on, and
what to hand on with them:

| Signal | Why it is not a tuning problem |
|--------|-------------------------------|
| `keys_unavailable` on JWT | The key set never loaded. The proxy is answering 503 rather than 401 precisely so this is visible as an outage, not as a client error |
| `/v1/health` `degraded` with a hardening reason | A security mechanism did not take effect. It is a deployment change, not a configuration one |
| A `panic` in the error log | Bring the whole line, the request id and the configuration. A panic is a bug even when it is contained |
| A bounded table full in ordinary traffic | The key is wrong, and the key is usually somebody's design decision |
| `not_enforced` from `origin-check` | The origin is not verifying. That is the origin team's change |
| A failing reload on a node that a fleet controller manages | The node restored the previous bundle by design; the fix is in the bundle, upstream of this node |

With any of them: the version, the expanded configuration, the access
line for one affected request, and the error log for the minute around
it. See [Collecting a bug report](#collecting-a-bug-report).

## Glossary

The words this document uses in a particular way.

| Term | Means here |
|------|-----------|
| **Generation** | One loaded configuration and everything built from it. A reload creates a new one; the old one keeps its in-flight requests until they end |
| **Route** | One entry in `routes`. `_challenge` and `_security_txt` appear in the log as routes but are internal |
| **Pool** | One entry in `upstreams`, with its endpoints, balancer, retries, circuit breaker and queue |
| **Endpoint** | One address inside a pool, static or discovered |
| **Reason** | The coarse denial category. What `bans.triggers[].reasons` matches on |
| **Detail** | Free text that narrows a reason. Not matchable |
| **Mark** | A honeypot's record of a client, which follows it across every route for `mark` |
| **Tier** | How far a client got through the challenge: none, proof of work, or CAPTCHA |
| **Class** | A route's priority class, which load shedding refuses in order |
| **Advice** | A configuration that loads but weakens the deployment. Printed at every start and reload; never fatal |
| **Bounded table** | A table that grows with attacker-controlled input and therefore has a cap and a defined behaviour at the cap |
| **Shed** | Refused because the proxy is protecting itself, not because the client did anything |
| **Tarpit** | Held rather than refused, in a slot of its own so it does not hold a request slot |
| **Decoy** | The body a honeypot route answers with |
| **Enforced** (origin lock) | The origin refuses what did not come through the proxy |

## Collecting a bug report

If you are going to ask somebody else, bring:

```sh
xproxy -version
xproxyctl status                      # generation, listeners, sandbox, counters
xproxyctl config > config.expanded.yaml   # header values are redacted
xproxyctl upstreams
xproxyctl stats
journalctl -u xproxy --since '-1h' --no-pager > error.log
```

plus the **access log line for one failing request** (by `request_id`)
and the client's own view of it (`curl -sv`). Redact what you must, but
say what you redacted: "the Host header" is useful, a line with a field
missing is not.

`xproxyctl config` already redacts header operation values, so an
expanded configuration is safe to share in a way the file on disk is
not — but it still names every path, host and upstream address you run.
