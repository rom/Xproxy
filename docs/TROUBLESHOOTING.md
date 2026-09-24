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
| A VNC session looks slower, or the viewer says it is using ZRLE rather than Tight | Intended on a framed listener: the encodings a gateway cannot measure are removed from the viewer's list, `tight` among them, which is what makes `bounds` possible. `xproxy_refusals_total{kind="vnc",reason="encoding_tight"}` counts it. `pixel_stream: opaque` gets Tight back and gives the bounds up; see [CONFIG.md](CONFIG.md#reading-the-picture-pixel_stream-and-bounds) |
| A VNC session ends as soon as it starts, with `vnc_denied` and `pixel_format_changed` | The viewer re-negotiated colour depth mid-stream (TigerVNC's automatic mode). RFB has no point where that takes effect, so a framing gateway cannot follow it: fix the viewer's depth, or set `pixel_stream: opaque` |
| An SSH session is refused with `ssh_denied` and `shell_syntax` | The `exec` command carried a shell operator (`;`, `&&`, a pipe, a backquote, a `$(`, a redirection). `allow_commands` is a list of patterns, and a pattern cannot hold a shell: the line is refused before the patterns are tried. `allow_shell_syntax: true` turns the check off; `force-command` on the certificate is the strong form |
| An SSH session with a valid certificate cannot open a port forward or get a terminal | The certificate does not carry the extension that permits it. `ssh-keygen -L -f cert.pub` lists them; a certificate made with `-O clear` grants only what was named after it. The refusal is `cert_no_port_forwarding` or `cert_pty_refused`, and the listener's own `allow_channels` is not the reason |
| A certificate is refused although its signature is good and its window covers now | One of: `source-address` does not cover this client, the window is longer than `max_certificate_lifetime`, the key or its CA is in `revoked_keys`, or it carries a critical option this gateway does not implement (which refuses rather than being ignored). The security log's `detail` says which |
| An FTP client's resumed upload is answered `451 a resumed transfer cannot be inspected here` | Intended on a listener with `yara` or `icap`: the bytes a resumed transfer carries are a fragment of the file, so a rule set that would match the whole never sees it. The client has to upload from the start. `xproxy_refusals_total{kind="ftp",reason="rest_unscannable"}` counts it |
| An FTP path is answered `550` although it is inside `allow_paths` | The argument's *shape* was refused before the lists were consulted: a backslash, a control character, or bytes that are not valid UTF-8. The security log's `what` says which (`path_separator`, `path_control`, `path_encoding`); see [CONFIG.md](CONFIG.md#path-shapes-the-proxy-will-not-guess-about) |
| A VNC session ends with `vnc_denied` and `unframable` | The desktop or the viewer used a message type this gateway does not know the length of, which is where the vendors put file transfer. `detail` names it |
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

**ECH is configured and `accepted` stays at zero.** In order: is the
record published for the name clients actually connect to (not just for
the public name); does the published `ech=` value match the
`publish:` line in `xproxyctl tls`; and is the client's resolver
returning the HTTPS record at all — a resolver that strips unknown
parameters, or a client not using DoH/DoT, is the usual answer. ECH is
a DNS feature as much as a TLS one.

**Clients see a certificate error since ECH was enabled.** They are
falling back to the public name and this listener cannot serve it. Add
the public name to the certificate. Validation warns about exactly this
at load, so check `xproxyctl reload --dry-run` too.

**ECH accepted counts are healthy but one client fails every time.**
That client holds a stale config. It is handed the current one during
the failed handshake when the key has `retry: true` — if no key does,
nothing tells it, and it keeps failing. `xproxyctl tls` shows the retry
flag per key.

**A site stopped being reachable after `require: true`.** That is what
it does: every client without the key is refused, including one whose
DNS answer was filtered en route. Turn it off unless the listener
exists only for ECH clients.

**The layer 4 listener in front stopped routing correctly.** ECH hides
the inner name, and SNI routing sees only the public one, so every ECH
client lands wherever the public name points. Terminate TLS at the ECH
listener instead of passing it through.

**Which key exchange is in use, and is it post-quantum.** `xproxyctl
tls` prints the accepted groups per listener and the negotiated
counts with the post-quantum share; `tls_group` in the access log says
what one request agreed. A share lower than expected is a client fleet
that cannot do the hybrid, not a proxy fault — look at which groups are
being negotiated instead, and by which user agents.

**The post-quantum share dropped to zero after a change.** Almost
always `key_exchange` naming groups and leaving `X25519MLKEM768` out:
the list replaces the default rather than adding to it. Validation
prints an advice line about exactly this at load
(`xproxyctl reload --dry-run` shows it).

**A client cannot connect after narrowing `key_exchange`.** A single
configured group means every client that guessed differently pays a
HelloRetryRequest, and a client that supports none of the listed groups
fails outright with a handshake failure. Widen the list; the cost of an
extra accepted group is nothing until it is negotiated.

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
| `exchange_refused` | The authorization server refused to exchange the token for this audience. 403: the token is valid and this backend is not somewhere it reaches |
| `exchange_unavailable` | The token endpoint could not be asked. 503 with `Retry-After`, because it is the proxy's problem |
| `dpop_missing` | The token says it is bound to a key (`cnf.jkt`) and no `DPoP` header came with it |
| `dpop_unbound` | `dpop.mode: require` and the token carries no `cnf.jkt` at all |
| `dpop_binding` | The proof is valid and signed by a *different* key than the token names |
| `dpop_replay` | That proof's `jti` has been used inside its window |
| `dpop_proof` | The proof itself: the type, the algorithm, the signature, `htm`, `htu`, `iat`, `ath`, or its shape |
| `cert_missing` | The token is bound to a certificate (`cnf["x5t#S256"]`) and the request presented none |
| `cert_binding` | The token is bound to a *different* certificate than the one presented |
| `cert_unbound` | `certificate_binding.mode: require` and the token carries no `cnf["x5t#S256"]` |

`keys_unavailable` is the one to escalate: check `jwks_url`,
`jwks_ca_file` and egress from the proxy to the provider.

**Everything gets 403 `exchange_refused` after `token_exchange` went on.**
The authorization server considered the request and said no, so its own
logs name the reason; the usual causes are a `client_id` that is not
registered for the token-exchange grant, an `audience` or `resource` that
is not a client it knows, or `scopes` the subject is not entitled to at
that audience. Start by removing `scopes` and letting the server decide
what the audience gets. A refusal is cached for `cache_ttl`, so a fix at
the authorization server takes up to that long to show — or a reload,
which builds a fresh cache.

**403 `exchange_refused` for one client only.** That client's token cannot
be exchanged for this audience: the subject is not entitled to the backend,
which is the control working. The alternative reading — that the client's
token is fine and the audience is wrong — shows up as *every* client
failing, not one.

**The backend says it got no credential at all.** Three possibilities.
`token_exchange.required: false` is set and the exchange failed, which is
exactly what that setting does and what validation warns about. The
`header` names something the backend does not read — note that any header
other than `Authorization` carries the bare token with no `Bearer ` in
front. Or `strip_token` removed the client's token and the exchange is not
configured on the provider the route names.

**The authorization server is being hammered.** Calls in flight are bounded
at 32 per provider and answers are cached for `cache_ttl`, so a steady
stream of *distinct* tokens is the only shape that produces load —
short-lived tokens with `cache_ttl` longer than their life do not help,
because the cache never outlives what was issued. Raise the token lifetime
at the authorization server, not `cache_ttl`.

**Every request fails with `dpop_proof` after `dpop` went on.** Four
causes, in the order worth checking. The client's proof signs the URI *it*
used and this process compares it with the URI *it* saw: behind another
TLS-terminating proxy those differ, and `dpop.external_url` is the answer
— the scheme is deliberately never taken from `X-Forwarded-Proto`, because
a client that can set that header could otherwise choose which URI its
proof has to match. The client's clock may be outside `max_age` plus
`clock_skew` in either direction. The proof's algorithm may not be in
`dpop.algorithms` (the default list has no RS256 in it). Or the client is
not sending `ath`, which RFC 9449 requires beside an access token.

**`dpop_binding` for one client only.** That client's proof verifies and
names a key the token was not issued for. Either it is using a different
key than the one it registered at the token endpoint — a key rotation on
its side that the authorization server has not seen — or the token is not
that client's. The security log's `dpop_jkt` is absent on a refusal and
present on success, so comparing a working client's value with the token's
`cnf.jkt` settles which.

**`dpop_missing` where the client does send a proof.** The proof travels in
the `DPoP` header and the token in `Authorization`. A load balancer or
service mesh in front that strips unknown headers takes the proof with it.
Check what reaches this proxy, not what the client sent.

**A client's requests stop working under load with `dpop_replay`.** Either
it is reusing one `jti`, which is a client bug (the identifier is meant to
be fresh per request), or a retry is re-sending the same proof after a
timeout — which is the same thing from the proxy's side, and correct to
refuse. `replay_entries` does not cause this: over its bound the table
drops entries, which loses protection rather than adding refusals.

**Everything fails with `cert_missing` after `certificate_binding` went
on.** The proxy sees no client certificate. Either the listener does not
ask for one — `server.listeners[].tls.client_auth` must be `request` or
`require`, and validation warns at every load when nothing does — or TLS is
terminated in front of this proxy, in which case the certificate is not on
this connection at all: set `trust_forwarded_header` and have the
terminating proxy send RFC 9440's `Client-Cert`, and name that proxy in
`trusted_proxies`. Without `trusted_proxies` the header is never read, and
validation warns about that too.

**`cert_binding` for one client only.** That client's token names another
certificate than the one it is presenting. The usual cause is a renewal:
the client rotated its certificate and is still holding tokens issued
against the old one, which expire on their own. If it persists, the client
is presenting a certificate the authorization server never saw — check
which certificate it authenticates to the token endpoint with, since that
is the one the binding names. The access log's `cert_thumbprint` is
present on success and absent on a refusal, so comparing a working
client's value with the token's `cnf["x5t#S256"]` settles it.

**`cert_unbound` on tokens that used to work.** That is `require` doing its
job: the authorization server is issuing tokens without a confirmation
claim for this client. Either the client is not authenticating to the token
endpoint with mutual TLS (the server only binds a token when it is), or the
server is not configured to bind for it. `mode: allow` is the setting for a
route where some clients are there yet and some are not: it refuses a bound
token on the wrong connection and leaves the rest alone.

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

**The backend stopped seeing `X-SSL-Client-DN` (or another certificate
identity header) it used to read.** Those headers are now removed from
every request that did not arrive from a peer inside `trusted_proxies`,
because a client that can send one chooses its own identity and the
backend cannot tell the two apart. Two fixes, depending on who was
setting it. If this proxy terminates the TLS, set
`routes[].client_cert_headers: rfc9440` (or `xfcc`), or set the backend's
own header name from `${cert:...}` in `request_headers.set`. If another
proxy in front terminates it and sets the header, add that proxy's network
to `trusted_proxies` — which is the same switch that decides whether its
`X-Forwarded-For` is believed, and for the same reason.

**A backend reads `Client-Cert` and gets nothing on a plaintext
listener.** Correct: there is no certificate, so there is nothing to
state, and an empty header would mean whatever the backend's parser makes
of emptiness. The absence is the answer.

**`Client-Cert` does not parse at the backend.** It is a Structured Fields
Byte Sequence (RFC 8941): standard base64, padded, between colons. A
parser expecting URL-safe base64, or one that forgets to strip the colons,
fails on a correct value. `openssl x509 -in <(printf %s "$v" | tr -d : |
base64 -d) -inform DER -noout -subject` is the shell check.

**`openapi` refuses an array or object parameter the client spells
correctly.** Check the parameter's `style` in the description against what
the client sends. A `pipeDelimited` array (`?ids=1|2`) sent to a parameter
with no `style` is one value that is not a number, because the default is
comma-separated — the description is the thing to fix, not the client. An
object parameter must be declared `style: deepObject` for
`?filter[from]=x` to be read as that object; without it the filter looks
for a parameter called `filter`, finds nothing, and calls a required
parameter missing. `label` and `matrix` path parameters are read by their
own separators; other exotic styles are not, and a parameter that needs
one is better declared with `content` instead.

**`openapi` answers 401 with detail `security` for requests that used to
work.** `require_security` is enforcing the description's own `security`
section. Three causes worth checking in order. The credential is going to
a different place than the description says — compare
`components.securitySchemes` against what the client actually sends. An
authentication filter earlier in the same chain *consumed* the header, so
by the time this filter looks there is nothing there; put this filter
before that one. Or the description is wrong: an operation inherited the
global requirement when it should have declared `security: []`. The
security log line carries `security_schemes` with the names of the
alternative that was expected.

**A warning at every load: "openapi description asks for a credential
that is not being enforced".** The description declares `security` on
that many operations and `require_security` is off, so the section is
being read as documentation. Either turn it on, or — if authentication is
terminated somewhere else entirely — the warning is the reminder that
this filter is not the thing enforcing it.

**`openapi` answers 400 with detail `read_only:body.<field>`.** The body
carries a property the description marks `readOnly`, which OpenAPI says
must not be sent. The usual innocent cause is a client that GETs an
object and PUTs the whole thing back, server-owned fields included. Use
`read_only: log` for a while: the request goes through and the access log
carries `openapi_read_only` with the properties, which is how to see
whether `deny` would break the clients before it does.

**A form body started being refused.** `application/x-www-form-urlencoded`
bodies are validated against their declared schema now, where they used
to be forwarded unchecked. The detail is `schema:body.<field>` as it is
for JSON. Fields are coerced by what the schema says they are, so
`remember=perhaps` against `type: boolean` is a type error — which is
what the application would have made of it too, less predictably.
`validate_body: false` turns the whole body check off if the schema and
the clients disagree and the schema is the one that is wrong.

**`graphql` refuses with `expansion`.** The query's fragments expand
past the visit budget. A legitimate query does not; a generated one
might, and should be simplified.

**`graphql` refuses with `get_mutation`.** A mutation or subscription
arrived by GET, which the GraphQL over HTTP specification does not allow
and no option here permits: a GET is what a link, an image tag, a
prefetch and a crawler all produce, so a mutation reachable that way is
one anybody can fire from another origin with the browser attaching the
cookies. Send it by POST. A client that uses GET for everything is a
client to fix, not a bound to relax.

**`graphql` refuses with `unnamed` or `operation`.**
`require_operation_name` is on (possibly because `allow_operations` is
set, which implies it) and the client sent an anonymous operation; or the
operation's name is not on the list. `xproxyctl` does not enumerate the
names — the security log line carries the detail, and the client's own
query is the other half. Adding a name to the list is a deliberate act;
that is the point of the list.

**`graphql` refuses with `persisted`.** The request carried no query
text, only a hash the origin would look up, and `persisted: deny` says an
unreadable query is not an allowed one. If persisted queries are how the
clients work, this is the wrong setting for that route: nothing here can
bound a document it cannot see, and the bound has to live at the origin
instead.

**A `graphql` complexity refusal disagrees with the query's own
arithmetic.** Variables are read now, so `friends(first: $n)` costs what
the request says `n` is — but only when the request carries it as a whole
non-negative number. A variable with a schema default the filter never
sees, or one the client omits, is scored as `max_list`, which is usually
the surprise. The other half is that a larger literal beside a smaller
variable still wins.

**A security key is refused and the page just says it was not accepted.**
By design: which step refused a key is what an attacker probes for, so the
page says one thing and the error log says which. Look for
`webauthn ceremony refused` with its `step` field. The common causes in
order: `origin` — `webauthn.origins` does not list the origin the browser
is actually on, which includes the port (`https://app.example.test:8443`
is not `https://app.example.test`); `challenge` — the page was open longer
than three minutes, or was reloaded and posted an old one; `assertion`
with an rp-id complaint — `webauthn.rp_id` is not the page's domain or a
parent of it, and the browser refuses before the request is even made.

**Registration answers 401 `verify_first`.** Registering a key needs a
factor already verified, which is the point: an endpoint that trusted only
the password would let somebody who has just stolen one add their own
second factor. Enter a code first, then register. For a user with no code
either, bootstrap with `xproxyctl mfa enrol` (or the GUI) and have them
register the key afterwards.

**A key that worked stops working, with a clone complaint in the log.**
The authenticator's sign count did not move forward. Two real causes: the
credential was copied (which is what the check is for), or the credential
file was restored from a backup taken after some logins, so the stored
count is ahead of the authenticator. In the second case remove that
credential line and register the key again. Note that many authenticators
do not count at all and report zero forever; that is permitted and is not
this.

**The credential file is not being written.** The proxy writes it on every
registration *and* on every login, to record the sign count, so the
directory must be writable by the proxy user — the file is replaced by a
rename, so the directory matters and not only the file. A login whose count
cannot be stored is refused with a 503 rather than allowed, because a
forgotten count is a clone check that passes.

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

## WebSockets

**Upgrades answer 403 with `reason: websocket`.** The route does not
have `websocket: true`. That is the default: an upgrade is a tunnel,
and a route says so explicitly.

**Upgrades answer 502.** The origin did not answer 101, or answered it
without `Upgrade: websocket` and `Connection: Upgrade` — a 101 that
does not say what it switched to is not an upgrade, and the transport
will not hand back a connection for it.

**Connections close with code 1002 (protocol error).** The guard found
something the RFC forbids, and the security log says which: an unmasked
client frame, a reserved bit (usually a client that negotiated
`permessage-deflate` — see below), a reserved opcode, a fragmented
control frame, a continuation with nothing to continue, a close code
that must not be sent, or text that is not UTF-8.

**Connections close with 1009 (too big).** `max_frame_bytes` or
`max_message_bytes`. Read `xproxy_websocket_messages_total` and the
application's own limits before raising them; a bound that is higher
than anything legitimate sends is still worth having.

**Connections close with 1008 (policy).** A denied pattern, an opcode
the route does not allow, or the message rate. The security event names
which.

**A compression extension stopped working.** It is refused on purpose.
A `permessage-deflate` frame cannot be inspected, so accepting the
negotiation would turn every check off without saying so. Either drop
the extension at the application or accept that the route cannot be
inspected and remove the guard.

**The violation count is double what you expect.** Both directions are
inspected, so a denied message and the origin's echo of it are two.

**Nothing is ever counted.** `xproxyctl` and `GET /v1/websocket` list
only routes that have a guard; a route with `websocket: true` and no
`websocket_guard` is an uninspected tunnel by design.

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

**A local peer never connects.** On a Unix socket cluster the questions
are different, because the socket is the authentication:

- `xproxyctl cluster` on the listening side shows `rejected_connections`
  climbing and the error log says why. `uid not in allow_uids` means
  `cluster.local.allow_uids` does not list the user the dialling daemon
  runs as: check with `id -u xgate`, not with what the peer announces.
- Nothing at all in the log, and the dialling side shows a `last_error`
  of `permission denied`: the dialling daemon cannot open the socket.
  Either the directory is not `0770 root:xproxy-cluster`, or the daemon
  is not in that group (`id -nG xgate`), or its unit does not list
  `/run/xproxy-cluster` in `ReadWritePaths`, or the in-process Landlock
  rules do not cover it — `xproxyctl sandbox` lists them, and the rules
  are derived from `cluster.listen` and `cluster.peers`, so a peer
  added without a restart is a peer the sandbox has not heard of.
- `is already in use` at start: another process is listening on that
  path. Two daemons configured with one `listen` is the usual cause.
- `exists and is not a socket`: `listen` points at a real file. The
  daemon refuses rather than deleting it.

**A local cluster is refused at validation.** `listen` and every `peers`
entry must both be Unix paths or both be `host:port`; `cluster.tls` is
refused on a local cluster and required on a networked one; a
`socket_mode` granting anything to others is refused, because on this
socket the permissions are the authentication.

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

**DoQ clients cannot connect.** Three things, in order: `doq: true` on
an encrypted listener (it needs `tls`), UDP reachable on that port (DoT
and DoH use TCP on the same number, so a firewall that allows 853/tcp
may not allow 853/udp), and the client actually speaking DoQ — the ALPN
is the only thing separating it from HTTP/3, and a client offering `h3`
is refused rather than served.

**Discovery records are published but clients stay on plaintext.** A
client verifies the certificate of the endpoint the record names before
using it, and falls back silently when that fails. Check that the
listener really serves the `name` in the record, that the certificate
covers it, and that the port is right. `kdig -t SVCB _dns.resolver.arpa`
against the plaintext listener shows what clients are being told.

**A name in `records` returns nothing.** That is what an owned name
with no record of the asked type does: NOERROR and no answers, never a
forwarded lookup. If the name should also have A or AAAA records from
upstream, it does not belong in `records` — the local set is
authoritative for the whole name, not for one type of it.

**The ECH parameter in a record does not match the listener.**
`xproxyctl tls` prints the config list the TLS listener actually
serves; compare it with the `ech` value here. A mismatch means clients
fall back to the public name on every attempt, which looks healthy and
encrypts nothing.

## DNS64

**Nothing is synthesised.** Four things to check, in order. `clients` may
not contain the client (it is empty by default, meaning every client;
narrow it deliberately). The name may have a real AAAA record, which is
answered with, never over. The name may not exist at all, which stays
NXDOMAIN — synthesising over either would be this resolver inventing an
answer. Or the A address is one `answer_policy` denies, which is the check
working: see below.

**A private address is not synthesised.** That is deliberate and it is the
reason DNS64 is safe to have here. `64:ff9b::7f00:1` is not inside
`127.0.0.0/8` and no prefix list would catch it, but it is `127.0.0.1` to
everything past the translator — so the IPv4 address is screened before it
is embedded. If the estate really does translate to private space, exempt
the name with `answer_policy.allow_names` or carve the range out with
`answer_policy.allow`.

**Dual-stack clients are reaching services through the translator.** They
are in `clients`. A client that has IPv4 does not need DNS64, and a
synthesised address sends it the long way round for nothing. Name only the
IPv6-only networks — an IPv4 network in that list is refused at load for
the same reason.

**A validating client rejects the answer.** It should: a synthesised answer
is not signed and does not carry AD (RFC 6147 section 5.5). A client that
validates for itself has to ask for A and do its own synthesis, which is
what RFC 6147 expects of it.

**`queries_synthesised` is far below the AAAA query count.** Most names
have AAAA records of their own, which is the healthy case. Compare with the
access log: a synthesised answer's `source` ends in `:dns64`.

## DNS views (split horizon)

**A client gets the wrong view's answer.** The first view whose networks
contain the client wins, so a narrow network listed after a wide one that
contains it never matches. Put `10.9.0.0/16` before `10.0.0.0/8`. The
access log line carries `view`, which says which one answered.

**A client in a view still gets the public answer.** The view has no
record for that name, so the listener's own set answers and, failing that,
the upstream does. A view replaces the record set rather than adding to it:
a name that both sets should answer has to be in both.

**One client's answer reached another.** It cannot come from the cache: a
local answer is never cached and a block is decided before the cache is
read. What looks like it usually is not a view at all — check whether the
name is in the listener's `records` as well, and whether the client's
address is what you think it is (`client_ip` in the access log is the
address the query came from, which behind a forwarder is the forwarder).

**A view with an upstream of its own is refused.** It is not a supported
shape, for the reason in CONFIG.md: two views with different upstreams
answering out of one cache would answer the same question differently. Use
a second listener.

**`queries_viewed` is zero.** No query matched a view. Either the networks
do not contain the clients, or the clients reach this resolver through a
forwarder whose address is what the view sees.

## Byte ranges

**A client's `Range` header does not reach the upstream.** A route with a
`ranges` section decides it. Three things it can do, and the access log
says which: `ranges_sent` carries the value forwarded, or `none` when the
header was dropped. A dropped header means the set was still over
`max_ranges` after coalescing and `action` is `ignore` (the default), so
the whole representation is served — which is what RFC 9110 permits a
server that will not satisfy a set to do. `ranges_dropped` counts them.

**A download manager gets the whole file instead of the part it asked
for.** The same thing: it asked for more ranges than the route allows.
Raise `max_ranges` for that route, or set `action: refuse` so the client
is told (416) rather than handed a body it did not want. Refusing is the
better answer for a route whose clients can adapt; ignoring is the better
answer for a route whose clients cannot.

**416 where the resource exists.** `action: refuse` with a set over the
bound answers 416 with `Accept-Ranges: bytes`, which tells the client
ranges are supported and this set was not. It is not the origin's 416
about an unsatisfiable range; `ranges_refused` counts the proxy's.

**The upstream receives a different set from the one the client sent.**
That is the coalescing, and it is deliberate: overlapping and adjacent
ranges are merged and the set is sorted, which RFC 9110 section 14.2
allows explicitly and which is what turns most oversized sets into one
range rather than a refusal. The bytes asked for are the same. `coalesce:
false` turns it off, and then a client that overlaps its ranges is
counted as asking for each of them.

**A `Range` header with another unit is passed through.** `items=0-9`
is not this proxy's to interpret: an origin ignores a unit it does not
implement. Only `bytes=` is read.

## DNS upstream resumption

**`upstream_resumed` stays at zero with `tls://` or `quic://`
upstreams.** Either the connection is never dropped (resumption only
shows when a redial happens) or the upstream issues no session tickets,
which some resolvers do not. Neither is a fault: a connection that stays
up costs nothing to resume. `upstream_resumption` in `xproxyctl dns`
says whether tickets are kept at all — `false` there means
`upstream_resumption: false` is set on the listener.

**A DoH upstream never reports a resumption.** It happens inside the
HTTP transport, which does not tell the caller, so nothing is counted for
`https://` upstreams. The resumption still happens.

**Turning resumption off changes nothing immediately.** The idle
connections already open keep their sessions until they are dropped; the
setting applies to the next dial. A reload that changes it closes the
idle HTTP connections, so a DoH upstream picks it up at once.

## DNS aggressive NSEC caching

**`queries_nsec` is zero although `aggressive_nsec` is on.** Nothing has
been learned, or nothing asked was covered. Check in this order:

1. `denials_held` in `xproxyctl dns`. Zero means no proof was stored. Only
   a **validated** NXDOMAIN is learned, so the zone has to be signed and
   the answer has to come back secure — `bogus` and `insecure` counts
   rising instead is the answer. A zone signed with NSEC3 stores nothing
   either: NSEC3 gaps are not used, on purpose (a hashed owner name says
   nothing about which names it holds, and an opt-out gap denies nothing).
2. The client's flags. A query with DO or CD set always goes upstream,
   because a synthesised NXDOMAIN carries no signatures. A validating
   resolver or a `dig +dnssec` behind this one sets DO on everything, so
   the feature does nothing for it — which is correct, not broken.
3. What was asked. A gap answers only a **sibling** of the name it was
   collected for. `a.b.example.net` does not reuse a proof collected for
   `x.example.net`, and neither does `example.net` itself.

**A name that exists is answered NXDOMAIN.** A gap is held for the shorter
of its NSEC record's TTL and `cache.max_ttl`, so a name added to the zone
inside that window is denied until the gap expires, exactly as a cached
NXDOMAIN would be. `xproxyctl dns purge` empties the store with the
caches. If it outlives the TTL, or a name outside the gap is denied, that
is a bug: the gap's own owner and next name exist by construction and must
never be denied.

**Memory.** `nsec_entries` bounds the number of **parent names** held, not
the number of names denied — one entry can deny an unbounded number of
siblings, which is the point. Each entry holds at most eight gaps. The
oldest entry is dropped when the bound is reached, so a flood across many
parents costs bounded memory and loses the older proofs rather than
growing.

## DNS tunnel detection

**Nothing is ever detected.** Check `tracked` in `xproxyctl status`: if
it is zero the detector is seeing nothing, which usually means the
clients resolve somewhere else. If it is climbing but `detections` stays
at zero, the traffic is not agreeing on enough signals — lower
`min_signals` to 1 *temporarily* to see which one fires on its own, then
put it back. A real tunnel trips three or four.

**Everything is detected.** Almost always `min_signals: 1`, or a
threshold pulled down far enough that ordinary traffic clears it. The
detection names the signals that fired; if the same one name keeps
appearing and it is a reputation service, an antivirus lookup or a
telemetry endpoint, that is what `allow_domains` is for. Those services
genuinely do encode a hash into a name and answer TXT — they are DNS
tunnels by design, just consensual ones.

**A whole domain stopped resolving for one machine.** That is
`action: block` doing what it says: a detection refuses every name under
the registered domain, for the client it was detected for, until
`cooldown` ends. Look for the `dns_tunnel` security event with that
client and domain. If it was wrong, add the domain to `allow_domains`
and go back to `action: log` while the thresholds are retuned.

**`tracked` sits at `max_tracked` and `evicted` climbs fast.** The table
is keyed on a client and a domain, both chosen by whoever sends the
queries, so a client walking through random domains fills it on purpose.
The bound is holding, which is the intended behaviour, but queries past
it go unmeasured: raise `max_tracked` if the resolver has the memory, and
look at which client is generating the cardinality — it is the one worth
investigating.

**Detections name a domain that is not the tunnel.** Queries are grouped
by the registered name: the last two labels, or three under a known
registry suffix. The suffix list is a safety net rather than the full
public suffix list, so under an unusual registry the grouping can be one
label too coarse. The client and the signals are still right even when
the name is grouped high.

**A tunnel over DoT, DoH or DoQ is not caught.** It is — every answered
query on the listener is measured whatever transport carried it. But a
client that resolves through a *different* encrypted resolver is not
using this listener at all, which is a network policy question rather
than a detector one: block outbound 853 and the known DoH endpoints, or
serve the discovery records so clients upgrade to this resolver instead.

## DNS serve-stale and prefetch

**`xproxyctl dns` shows `stale` climbing.** The listener is answering
from expired entries because the upstream resolvers are not answering.
That is `serve_stale` doing its job and it is also an outage: the
answers are out of date and getting older. Check `upstream_failures` in
the same view and the upstreams themselves. `source=stale` in the access
log names the queries affected.

**A name that changed address keeps resolving to the old one for up to
30 seconds after the upstream came back.** That is `stale_ttl`: a stale
answer is served with a short TTL so the client comes back soon, and
until it does the client's own cache holds what it was given. Nothing is
wrong; lower `stale_ttl` if 30 seconds is too long for a failover, at
the cost of more queries during an outage.

**A stale answer was not served even though the entry should still be in
the window.** Three reasons, in order of likelihood. The entry was
evicted: the cache is an LRU and a stale entry occupies a slot like any
other, so a busy resolver with a small `max_entries` loses the least
recently used ones first. The window had passed — `serve_stale` is
measured from expiry, not from the last query. Or the upstream *did*
answer, with SERVFAIL, on a listener with `dnssec` on: that is not
treated as an outage, because with validation on a SERVFAIL is the code
for an answer that was *rejected*, and standing in for it with an
expired answer of our own would hand the client exactly what validation
refused.

**Prefetch does not seem to do anything.** It only fires on a query for
an entry that is already in the cache and already past
`prefetch_threshold` of its TTL — a name queried once per hour with a
five minute TTL is never in that state and is not what the setting is
for. `xproxy_dns_prefetch_total` counts the refreshes started; if it is
zero on a busy resolver, raise `prefetch_threshold` (0.1 is the default,
0.5 the maximum) or check that the names in question are actually being
re-queried before they expire.

**Upstream traffic went up after turning prefetch on.** Some increase is
the point: a refreshed entry is an upstream query that used to happen on
a client's clock instead. A large increase means `prefetch_threshold` is
too high for the TTLs in play — refreshing an entry with half its life
left does twice the upstream traffic for the same coverage.

## DNS cookies

**A client stopped resolving after `cookies: require` went on.** That is
the setting doing what it says. Two shapes, and the refusal reason tells
them apart. `cookie_missing` (REFUSED) is a client that sends no COOKIE
option at all — most stub resolvers — and there is nothing to invite it
back with. `cookie_required` (BADCOOKIE) is a client that sent one and
should be retrying with what it was handed; a client stuck in a loop of
those is one that is not storing the server cookie, which is a bug at its
end. Either way, `require` belongs on a listener whose clients are known;
`respond` gets the verification benefit without refusing anybody.

**Rcode 7 in a capture where BADCOOKIE was expected.** That is
BADCOOKIE. Rcode 23 does not fit in the four bits the header has, so RFC
6891 keeps the low four there (7) and the high eight in the OPT record's
TTL. `dig` and `kdig` reassemble it; a tool that reads only the header
says YXRRSET. The access log says 23.

**`cookies_verified` stays at zero on a busy listener.** Either the
clients do not implement cookies, or they are not sending back what they
were given. Check `cookies_issued` in the same view: issued climbing with
verified flat is clients that ignore the cookie; both flat means no
client is asking for one.

**Bans still do not fire for UDP clients.** A security event from a bare
UDP datagram is attributed to nobody on purpose — counting it towards a
ban would let anybody have a third party banned by spoofing them — so it
is aggregated into one `dns security events from unverified sources are
aggregated` warning instead. Cookies are what change that: a UDP query
carrying one this listener issued has completed a round trip, so its
events are attributed and drive bans like a TCP client's. If bans matter
for UDP clients, `cookies: respond` is the prerequisite.

**Every client had to redo the exchange after a restart or a failover.**
The cookie secret is per listener and per process and is never written
anywhere, so a restart invalidates the cookies it issued and two nodes
do not accept each other's. The cost is one BADCOOKIE round trip per
client, once. It is not worth engineering around.

**Answers got bigger, or a name that used to fit in a datagram now
truncates.** Putting a cookie into a response means rebuilding the
message, which loses the upstream's name compression. The cookie's own
space is reserved before the truncation decision, so the datagram is
never oversize — the answer is a little smaller than it could have been
instead. On a listener where this matters, `cookies: off`.

## DNS answer policy and the client subnet

**A name that works everywhere else returns NXDOMAIN here.** Look for
`dns_answer_denied` in the security log: it names the address that
tripped the screen. If the address is one this network really uses, the
fix is `answer_policy.allow` (a range) or `answer_policy.allow_names` (a
name), not turning the screen off. The common honest cases are an
internal zone served from private space, a name that points at a host on
the carrier NAT range `100.64.0.0/10`, and a split-horizon name whose
public half is what this client needed — that last one is what
`action: strip` is for.

**The screen never fires, on a network where it should.** Two causes.
The section may deny nothing that the answers actually contain: check
what the name resolves to with `kdig` against the upstream directly
rather than through the proxy. Or the answers are coming out of the
cache from before the policy was added — the screen does run on cache
hits, and drops the entry when it fires, so this only looks like a miss
for names whose entries predate the reload *and* are not being queried.
`xproxyctl dns purge` settles it either way.

**The whole answer went away and the client needed one address of it.**
That is `nxdomain` or `refuse` on a name with both a public and a
private address. `action: strip` keeps the public one. The stripped form
is what the cache stores, so the removed address does not reappear on
the next query.

**A validating client calls a stripped answer bogus.** It is not bogus,
it is unsigned: a signature over a record set one member short does not
verify, so the RRSIGs of a set that lost records are removed with them.
A client that must validate every answer and a listener that rewrites
answers are two incompatible requirements; use `nxdomain` there, or
exempt the name.

**Sinkhole answers are not screened, and 0.0.0.0 is a denied range.**
Deliberately: `records`, `discovery` and `sinkhole_ipv4` are this
proxy's own answers, and screening them would have a sinkhole refuse
itself.

**Geolocated names resolve to the wrong region after an upgrade.**
`ecs: strip` is the default now: the client's EDNS Client Subnet option
is not forwarded, because the cache here is keyed by the question alone
and a per-subnet answer would be served to every client. The upstream
resolver still adds its own option describing this proxy, so the answers
are the ones nearest the *proxy*. That is correct for a resolver serving
one site and wrong for one serving many; `ecs: forward` restores the old
behaviour and accepts that a client can then choose what the cache
holds. `xproxy_dns_ecs_stripped_total` counts the queries affected.

## Forward proxy, layer 4 and QUIC

**`CONNECT` refused with `forward_denied`.** The destination is not in
the allow list or the port is not in `ports`.

**A MASQUE request answers 501.** Either the protocol is not enabled
(`masque.udp` or `masque.ip`), or it is one this proxy does not
implement — every extended CONNECT is answered here rather than falling
through to the ordinary CONNECT path, because a request with a path and
no authority is not a TCP tunnel request. For `connect-ip`, 501 with
`masque_no_device` means the tunnel device could not be opened; the
error log says why, and the usual causes are that it has not been
created (`ip tuntap add mode tun xproxy0`) or that the process may not
open `/dev/net/tun`.

**A MASQUE client cannot even send the request.** Extended CONNECT
needs HTTP/2 or HTTP/3; a listener without `h2` in `protocols` has no
way to carry `:protocol`. Check the negotiated protocol, not just that
TLS works.

**Datagrams disappear.** `xproxy_masque_dropped_total` counts them. For
`connect-udp` the causes are a capsule with a context other than 0 (an
extension nothing here registers) and an answer from an address other
than the target. For `connect-ip` it is the anti-spoofing rule: the
source must be inside `ip_assign` and the destination inside
`ip_routes`.

**A SOCKS client gets "general SOCKS server failure".** Look for the
`forward` access line with `protocol: socks5`: the `reason` field says
which check refused it. Policy refusals come back as "connection not
allowed" and an unresolvable name as "host unreachable", so a general
failure is usually the tunnel bound (`tunnel_limit`) or a shutdown in
progress.

**A SOCKS client is refused before it sends a destination.** Two
causes. The listener has `auth` and the client offered only "no
authentication" — it gets method `0xFF` and a close; configure the
credentials in the client (`socks5h://user:pass@host:port`). Or the
client is speaking SOCKS4, which is refused outright: it has no
authentication and no names, and every modern client can do SOCKS5.

**SOCKS works but DNS does not.** The client is resolving names itself
and sending an address. Use the form that asks the proxy to resolve —
`socks5h://` in curl and git, `-o ProxyUseFdpass` style options
elsewhere — or the destination policy sees an address where you wrote a
name in `allow`.

**UDP through SOCKS does nothing.** `socks_udp` must be on (validation
refuses `socks_udp` without `socks5`), and the association only relays
for the client address that opened it: a client behind a NAT that
changes its source port between the control connection and the
datagrams is not the same client as far as the relay is concerned.
`forward_udp_dropped` counts each refusal; a rising count with no
traffic getting through is that mismatch, a refused destination, or a
fragmented datagram (never reassembled, always dropped).

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

## TLS interception

**Every intercepted site fails with a certificate error in the
browser.** The client does not trust the interception CA. Install
`ca_cert_file` — the certificate, never the key — in the trust store of
the machine, and remember that Firefox, Java and Node each keep their
own store separate from the system one. `forward_intercept_refused`
climbs and the tunnel closes right after the CONNECT succeeds.

**The proxy refuses to start: "readable by more than its owner".** The
signing key can impersonate every site to every client that trusts the
CA, so `ca_key_file` must be mode 0600 and owned by the user the proxy
runs as. `xproxy check` says the same thing before a restart does.

**One site fails while the rest work.** Look at the security log for
`forward_upstream_tls`: the destination's own certificate did not
verify against `ca_file` (or the system store), and the proxy refuses
to forge a certificate for a server it could not check. That is the
intended behaviour — it is the same failure the client would have had
without the proxy. If the destination legitimately uses a private CA,
add it to `ca_file`; do not reach for `verify_upstream: false`, which
turns the check off for every destination at once.

**A site works through the proxy but not when intercepted, and the
error is about the protocol rather than the certificate.** `alpn`
defaults to `http/1.1` alone on purpose. If you added `h2`, the
decrypted stream is relayed as bytes and not parsed as HTTP/2, which
some sites survive and some do not; validation warns about it.

**Something that is not a browser stops working through the tunnel.**
If it is not speaking TLS at all it is passed through untouched
(`forward_intercept_passed` climbs) and interception is not the cause.
If it is speaking TLS and pinning a key — mobile apps, some agents —
then it is working exactly as designed and the destination belongs in
`bypass_hosts`.

**`forward_sni_mismatch` in the security log.** The handshake inside
the tunnel named a different host from the `CONNECT`. Ordinary clients
never do this; treat it as somebody trying to reach a destination the
policy checked against another name. A `CONNECT` to a bare address is
not subject to the check — the address is what the policy checked and
where the bytes go, and the name only picks a virtual host there.

**Nothing is intercepted at all.** Check `hosts` — a name there matches
the host in the CONNECT, not the address behind it — and check that the
destination is not also in `bypass_hosts`, which is consulted first and
wins. `forward_intercepted` staying at zero while `forward_tunnels`
climbs is that.

**YARA rules do not fire on HTTPS.** They only see what is decrypted,
so the destination has to be intercepted, and `directions` has to
include the side the bytes are on: `client` for what leaves,
`upstream` for what arrives.

## SMTP listener

**Every session ends with `421 4.4.1 upstream unavailable`.** The proxy
could not open its own session to the mail server. The error log says
which step failed: no reachable endpoint, a greeting that was not
`220`, an EHLO the upstream refused, or — with
`upstream_tls_mode: starttls` — an upstream that does not advertise
`STARTTLS`. That last one fails on purpose rather than continuing in
clear.

**`421 4.3.0 upstream failure` in the middle of a session.** The
upstream sent a reply this proxy would not parse: a code that changed
mid-continuation, a line without CRLF, or more continuation lines than
any registered extension uses. It is never passed through, because a
reply the proxy did not understand is the one the client would read
differently. `smtp_protocol_errors` counts it and the error log has the
reason.

**A client says the server does not support STARTTLS.** Check
`tls_mode` (it must be `starttls`), that the listener has a `tls`
section, and that `STARTTLS` is still in `commands`. The proxy
advertises it from its own capability, never from the upstream's: the
upstream's offer is about a different hop.

**`554 5.7.0 data pipelined across STARTTLS`.** The client wrote
another command before reading the `220`. That is CVE-2011-0411, and it
is refused whether it was an attack or a client that pipelines without
checking for the `PIPELINING` capability. The session ends and the
event is a `smtp_denied` deny.

**`500 5.5.2 line must end with CRLF`.** A bare LF, which is the SMTP
smuggling vector. If the sender is a real client that cannot be fixed,
`bare_newlines: convert` repairs the line instead of refusing the
session — the proxy re-emits every line itself, so both ends still
agree. A bare CR inside a line is always refused; there is no safe
repair for it.

**`552` on a message the sender says is small enough.** Two different
checks. A `SIZE=` on MAIL over `max_message_size` is refused before the
body is sent. A body that runs past it is refused while it is being
read, and the upstream connection is then dropped **without** its
terminator, so the mail server discards the partial message rather than
queueing a truncated one; the client's session ends too.

**Recipients are refused with `452` well below the mail server's
limit.** `max_recipients` is the proxy's own bound, per message, and it
counts only the RCPT commands the upstream accepted.

**A session ends with `421 4.7.0 too many errors`.** `max_errors`
counts every refusal the proxy itself answers — an unknown verb, an
out-of-order command, a recipient over the bound, a declared size over
the limit — not just bad syntax. A client that legitimately trips it is
usually one probing capabilities it was never offered.

**A client is answered `554 5.7.1 access denied` before the banner.**
It is outside `allow_clients`. `smtp_rejected` counts it, and the
upstream is never contacted.

**The mail server logs the proxy as the client.** Turn on `xclient`.
It only takes effect when the upstream advertises `XCLIENT`, which
Postfix does after `smtpd_authorized_xclient_hosts` names the proxy.
`proxy_protocol` is the other way to do it, and the two are
independent.

**A message was delivered but the headers look different.** They are
not rewritten. What changes is framing: lines are re-emitted with CRLF,
and a message that used bare newlines is either refused or repaired
depending on `bare_newlines`.

## MQTT listener

**A device connects and is immediately dropped with no CONNACK.** Three
causes, in this order: it is outside `allow_clients`, the listener is
over `max_connections`, or its first packet was not a CONNECT. MQTT has
no reply before CONNACK, so a close is the only answer the protocol
allows; the access log line says which (`client_not_allowed`,
`not_connect`), and `mqtt_rejected` counts the first two.

**CONNACK carries a refusal code.** The code says which check: `0x01`
or `0x84` is the protocol version, `0x02` or `0x85` the client id
(empty, too long, or not matching `client_id_pattern`), `0x05` or
`0x87` the policy — no username with `require_auth`, a keep alive
outside `keep_alive_max`, or a will topic the publish policy refuses.
3.1.1 and 5.0 spell the same refusal differently, which is why there
are two codes for each.

**A subscription that looks allowed is refused.** A filter is not a
topic. `subscribe_allow: ["devices/+/commands"]` allows
`devices/1/commands` and `devices/+/commands`, and refuses
`devices/#` and `#`, because those could deliver topics the entry never
covered. Widen the allow list to the shape you actually want to permit
rather than relying on the device asking narrowly.

**A subscription to a name that is not denied is still refused.**
`subscribe_deny` is checked by overlap: `secret/+/key` refuses
`secret/#` and `+/1/key` too, since either could reach a denied topic.

**Publications vanish with `action: drop`.** They are refused, not
lost: `mqtt_refused` counts them, the security log says which topic, and
a QoS 1 or 2 publisher is answered with not-authorized rather than left
retrying. At QoS 0 there is nothing to answer with, so the drop is
silent to the client by design.

**The session ends on a packet the device thinks is fine.** Check
`mqtt_protocol_errors`. The parser refuses what the specification
forbids and some brokers tolerate: a remaining length with a
non-shortest encoding, QoS 3, DUP on a QoS 0 publication, a packet id of
zero, a string that is not UTF-8 or carries NUL or a surrogate, reserved
flag bits. Nothing is forwarded after one, because the length field is
what the next read depends on.

**`max_packet_size` ends sessions on a firmware update topic.** The
bound covers the whole packet and applies in both directions; raise it,
or move bulk transfers off MQTT. 5.0 clients are not told the proxy's
maximum in CONNACK — the broker's own value is passed through — so a
client may believe a larger packet is acceptable and be disconnected by
this bound.

**A broker packet ends the session with `upstream_protocol`.** The
broker sent something this proxy would not parse. It is not passed
through: its framing is what the client's next read depends on.

## Authorisation

**Everything is refused with `rule:unauthenticated`.** The policy ran
before anything verified an identity. `authz` decides on what an
authenticating filter recorded, so it has to be last in the route's
`filters` list — before them there is nothing to decide about, and
deciding on values a client supplied is exactly what this avoids. For a
route that is meant to be open, `require_authenticated: false`.

**Everything is refused with `rule:default`.** No rule matched and the
default is deny, which is the point. The access line carries
`authz_rule`, so the refusals say `default` rather than naming a rule.
Check the path patterns first: a pattern is a path exactly, or one
ending `/**` for a tree, and a prefix that is not a path boundary does
not match — `/v1/orders` does not cover `/v1/orders-internal`.

**A rule with scopes never matches.** Scopes are all-of: a credential
carrying two of the three a rule names does not satisfy it. Groups are
any-of. If that is the wrong way round for what you meant, split the
rule.

**Groups are empty although the directory has them.** `ldap_auth`
records the attribute named by `group_attr`, which defaults to
`memberOf` only when `require_group` is set; set `group_attr`
explicitly to record groups without requiring one. For `oidc`, the
claim is `groups_claim` (default `groups`) and it is read from the
verified session, so a provider that only puts groups in the userinfo
response will not have them there.

**A policy allows more than it reads.** Look for a rule with no
selectors. As a deny that is a backstop; as an allow it fails the load
for this reason. Also check rule order: the first match decides, so an
allow above a deny wins.

**The backend sees no groups.** `forward_groups_header` has to be set,
and the header is written only when the policy allowed. Any value a
client sent under that name is removed before the decision, not after.

## gRPC message inspection

**Calls are refused with `INVALID_ARGUMENT` and the reason
`grpc_guard:malformed`.** The message did not walk as protobuf. The
usual cause is a body that is not gRPC framing at all — a client
sending `application/grpc` with something else inside it — or a proxy
in front that re-framed the stream. `action: log` lets the calls
through while the records accumulate.

**`grpc_guard:short_frame`.** The body ended in the middle of a length
the frame declared. A client that finished sends whole frames; one that
stopped part way is a client whose message nobody has. If it happens
under load rather than from one client, look for something cutting the
stream between the client and this proxy.

**`grpc_guard:too_deep` or `too_many_fields` on calls that work
elsewhere.** The bounds are lower than the service's real messages.
Turn on `action: log`, look at `grpc_depth` and `grpc_fields` in the
access lines for a while, and set the bounds above what the service
actually sends. Guessing and finding out in production is the thing to
avoid here.

**`deny_patterns` never match.** Two reasons. They run over the strings
found in a message, so a value that is not valid UTF-8 is not offered
to them; and `allow_compressed: true` with patterns fails the load for
exactly this reason, so if the load succeeded compression is already
off. Also check `max_scan_bytes`: past it the rest of the request is
forwarded unread and the access line says `grpc_partial`.

**A field is refused that should not be.** A length-delimited protobuf
field is a nested message or a string, and without a schema there is no
way to be certain which. It is tried as a message first, because a
nested message read as a string is a subtree the depth and field bounds
never see. A string that happens to parse as a message is walked as
one, which costs a walk and can add to the field count.

**gRPC-web calls are not inspected.** This filter reads the wire
framing, and gRPC-web is translated to it earlier on a route that
accepts it. Put the filter on the route and it sees the translated
call.

## Syslog relay

**Nothing reaches the collector.** Look at `syslog_received` first: if
it is zero, the messages are not arriving, and on UDP that usually means
`allow_senders`. If it is climbing while `syslog_forwarded` is not,
check `syslog_refused` (unparseable, oversize or a refused sender),
`syslog_dropped` (a facility, severity or deny pattern filtered it),
`syslog_rate_limited`, `syslog_queue_dropped` (the collector is slower
than the senders) and `syslog_send_failed` (the collector is not
reachable at all).

**Records are refused as malformed.** The relay will not forward what it
could not read, because a message's facility, severity and host are
exactly the fields every rule here decides on. The usual causes are a
priority above 191 (there is no facility to name above it), a NUL or a
line ending inside a header field, text that is not UTF-8, and
structured data whose values are not quoted the way RFC 5424 requires.
The security event carries the reason.

**The host name in the collector is not what the sender set.**
`hostname` decides that. `annotate` (the default) keeps the sender's
name and adds `xproxyOrigin@0` with the observed address; `observed`
replaces the field; `keep` takes the sender's word, which nothing
checks and which is why it warns.

**Records arrive in a different format from the one that was sent.**
Deliberately. Everything is re-emitted as RFC 5424 whatever arrived, so
that the record the collector stores is the record the relay decided
about. A newline in the text becomes a visible symbol rather than a
second record; a line ending inside a structured data value is escaped;
a field that cannot appear in a header is replaced.

**A stream connection drops after one bad message.** On a counted frame
(`octet_counting`), refusing to read the octets the frame declared
leaves the reader at an offset nobody knows, so the connection ends.
On a delimited one the reader skips to the next line ending and carries
on. `framing: auto` decides per message by whether it starts with a
digit.

**Messages stop under load.** `rate_limit` is per sender, and
`max_senders` bounds the table it keeps; when the table is full a new
sender is refused rather than evicting the entries doing the limiting.
`queue` is what waits for the collector, and a full queue drops and
counts rather than holding every sender behind one slow collector.

## FTP proxy

**Transfers hang, or the client reports "cannot open data connection".**
The data connection is separate, and the proxy is one end of it. Three
things to check: the client is using passive mode (`PASV` or `EPSV`),
since active is off by default; `data_ports` is open on any firewall in
front of the proxy, and wide enough for the transfers that run at once;
and `data_address` names an address the client can reach, which matters
only when the proxy is itself behind a NAT. A transfer arranged and not
used within `data_timeout` is dropped.

**`PORT` or `EPRT` is answered 502.** Active mode is off by default. It
asks the proxy to connect back to an address the client names, which is
the bounce attack: a client that names somebody else's address has made
the proxy open a connection on its behalf. `allow_active: true` turns it
on, and then the address must be the client's own and the port
unprivileged, or the answer is 501.

**A transfer ends with 426 and the file is short.** Either
`max_file_bytes` or a `yara` match. Both act by cutting the data
connection, because a transfer cannot be un-sent, and the client is told
426 rather than the target's 226 — telling it the transfer completed
would be a lie. The security log says which, with the path.

**A command is answered 502 although the server supports it.** Two
different lists. `commands` is what this listener allows; the default is
every verb the proxy can read the effect of, which is smaller than what
a server implements — a verb whose effect it cannot name is a verb it
cannot hold to a policy, so `SITE EXEC` and the rest are not relayable
at all. Adding an unknown verb to `commands` fails the load rather than
widening the proxy.

**A path is refused although it looks right.** Paths are resolved
against the working directory the proxy has been following from the
`CWD` replies, then cleaned, then matched. A path that still climbs
above its root is refused outright. If the session did something the
proxy could not follow — a `CWD` it never saw the reply to — the
directories can drift; `PWD` on the client shows the target's view and
the refusal in the log shows the proxy's.

**Everything is answered 534 before login.** `require_tls` is on, which
is the default wherever TLS is reachable, and the control connection is
still in clear. The client has to send `AUTH TLS` first. Only `AUTH`,
`QUIT`, `FEAT`, `NOOP`, `PBSZ`, `PROT` and `HELP` are allowed before it.

**`CCC` is refused.** Deliberately. It clears the control channel after
`AUTH TLS`, which puts every path, every file name and every reply that
follows back in clear on the wire; the transfer protection it is usually
paired with does not cover any of that.

**A session ends after a few refusals.** `max_errors`, default 10. A
client walking a policy to find its edges is a client to stop talking
to, and the refusals are `ftp_denied` for the ban triggers.

## SSH bastion

**Every client is refused at authentication.** `ssh_auth_failed` counts
the attempts and the security log names the method and the user. The
usual causes are a key that is not in `authorized_keys` (the file is read
at load, so a key added since needs a reload) and a client offering only
a method the listener has not configured — without `users_file` there is
no password authentication at all.

**Authentication succeeds and then the connection drops.** The target
leg failed. The error log says which: no reachable endpoint, or a host
key that is not in `upstream_known_hosts`. That second one is the check
working: the bastion is the one place that can notice a machine in the
middle, so it refuses rather than connecting anyway. Add the target's
key to known_hosts with `ssh-keyscan`, having checked it.

**A command is refused but a shell works.** `exec` is in
`allow_requests` but the command did not match `allow_commands`, which
are RE2 patterns anchored as written — `uptime` matches anywhere in the
line unless you write `^uptime$`. The refusal is an `ssh_denied` event
with the command.

**A key in `authorized_keys` is refused once `principals` exists.** That
is the list being the policy. With one entry present, a key no entry
covers is refused at authentication rather than falling back to the
listener's own settings — falling back would be the opposite of what the
list says. Add the key's `SHA256:` fingerprint (`ssh-keygen -lf`) to an
entry, or end the list with an entry that names neither a fingerprint
nor a certificate principal, which matches everything. Such an entry
must be last; validation refuses one with entries after it, because they
could never be reached.

**A certificate is refused although the CA is right.** Three things are
checked, and the error log says which failed: the signature against
`trusted_user_ca_keys`, the validity window against now, and the
certificate's principal list against the login being used. `ssh -v`
shows which certificate was offered; `ssh-keygen -Lf` prints its
principals and window. Without `trusted_user_ca_keys` a certificate is
refused outright rather than treated as the plain key inside it.

**A principal is refused at authentication with no other explanation.**
`deny: true` is exactly that: the entry exists so the key can stay in
`authorized_keys` while the person it belongs to is off. The refusal
names the principal, so the security log says who rather than which
fingerprint.

**A principal's policy seems to ignore a listener setting.** It does not
— unset fields inherit, set ones replace. A `policy` that lists
`allow_requests: [exec]` replaces the listener's whole list rather than
adding to it, so `pty-req` and `shell` are gone with it. Write out every
value an entry needs.

**`Setenv` fails, or a variable never reaches the target.** `allow_env`
defaults to `TERM`, `LANG` and `LC_*`; anything else is refused with the
request and logged as `env_refused`. The loader and interpreter
variables (`LD_*`, `BASH_ENV`, `PERL5OPT`, `PYTHONPATH`, `PATH`, …) are
refused whatever `allow_env` says, and naming one fails the load: each
is a way to run code before the command the policy approved, which would
make `allow_commands` decoration. Note that `env` must also be in
`allow_requests`, and that most clients send nothing unless asked to
(`ssh -o SendEnv=…`).

**`scp` or `rsync` is refused although `exec` is allowed.** Neither ever
opens the `sftp` subsystem, so every path and operation rule there is
off their path: `allow_file_transfer_commands` therefore defaults to
`false` exactly where there is an `sftp` section to bypass. Set it to
`true` if the transfer is what you want (it warns beside an `sftp`
policy, because that is the bypass the section exists to close), or move
the transfer onto sftp. The refusal is `file_transfer_refused` with the
command. Every word is read, not only the first, each with any directory part
removed and `VAR=value` prefixes skipped, so `env scp -t` and
`sh -c 'scp …'` are refused too. A command whose argument merely says
`scp` is refused with them; that is the direction to be wrong in on a
bastion.

With `command_rules` the answer is narrower than that switch: a rule says
the direction, the paths and whether recursion is allowed, and it decides
for the family it names instead of the blanket refusal. See the
`command_*` labels below.

**A command is refused with `command_direction`, `command_path` or
another `command_*` label.** That is a `command_rules` entry deciding,
and the label says which property of the command was wrong rather than
which rule said so. `xproxyctl status` counts them per listener:

| Label | What the command asked for |
|-------|----------------------------|
| `command_direction` | A movement the rule does not allow: `scp -f` under `directions: [upload]`, a `git-receive-pack` push under `[download]`, an `rsync --server` without `--sender` under a download-only rule |
| `command_path` | A path outside `paths`, inside `deny_paths`, one that climbs above its own root, or a glob whose expansion cannot be proven to stay inside an allowed subtree. The path is judged **after** resolving it, so `/srv/incoming/../../etc/ssh` is refused as `/etc/ssh` |
| `command_recursive` | `scp -r` without `recursive: true` |
| `command_delete` | `--delete`, `--delete-during`, `--remove-source-files` or `--force` without `delete: true` |
| `command_server` | An scp with neither `-t` nor `-f`, or an rsync with no `--server`: not the far side of a client's transfer, so it is doing something else on the target — an rsync client would dial out of it |
| `command_env` | A `VAR=value` assignment in front of the command. The `allow_env` policy covers `env` requests; an assignment is a shell's, and it is refused rather than read |
| `command_no_rule` | A family this gateway reads (`scp`, `rsync`, the sftp server binary, git's transport verbs) with no rule of its own. Once there is one rule, a family named by none is refused — otherwise a rule for scp would quietly leave rsync to the patterns |
| `command_syntax` | The line could not be read as one simple command: a substitution, an unbalanced quote, an option no version of the program takes. It applies to the transfer families even under `allow_shell_syntax` |

**A command a rule should allow is refused as `command_syntax`.** Look at
the detail in the security event: it names what could not be read. The
usual causes are a substitution (`scp -t $(cat /etc/x)` — the gateway
cannot know what path that becomes), a glob without
`allow_shell_syntax` (refused earlier, as `shell_syntax`), and an option
the program's server mode does not take.

**A glob is refused although the directory is in `paths`.** A glob is
expanded by the target's shell, so the only honest check is whether every
name it could produce is inside an allowed subtree: `paths` must contain
a pattern ending in `/**` (or `/`) that covers the directory the glob
sits in, and a single-level pattern is not enough. With any `deny_paths`
entry a glob is refused outright — a pattern cannot be proven not to
match one. Name the file, or widen `paths` to the subtree deliberately.

**`env scp -t /srv/incoming` is refused although a scp rule allows that
path.** A wrapper is not read through: the command is `env`, so no rule
covers it, and the blanket `file_transfer_refused` check — which reads
every word — refuses it. That is deliberate. A rule is never a way to
reach a transfer command through something else, because this gateway
cannot know what a wrapper will do with the words after it.

**rsync copies a file the rule's `paths` does not name.** In server mode
rsync's file list travels inside rsync's own protocol, negotiated after
the command line: the rule decides the direction, the deletions and the
transfer root, and everything under that root is in reach of the
transfer. Where the requirement is a rule per file, sftp is the protocol
that can carry one — and an `sftp_server` rule with
`enforce_sftp_policy: true` is how an exec of the sftp server binary is
held to it.

**Port forwarding is refused.** Two separate gates: `direct-tcpip` must
be in `allow_channels`, and the destination must be in `forward`.
Validation refuses one without the other, so a listener that allows the
channel type always has a destination list — an empty one would refuse
every forward while looking permissive.

**Agent forwarding or X11 does not work.** Both are left out of
`allow_requests` on purpose. Adding them warns, because each gives
whatever runs on the target a channel back into the client, and agent
forwarding lets it sign with the client's keys for as long as the
session lasts.

**An SFTP client connects and then fails immediately.** Only version 3
is parsed. A client that negotiates higher is refused at the version
exchange rather than having its packets guessed at; most clients fall
back when the server answers 3, but one that insists cannot be
inspected.

**SFTP refuses a path that looks allowed.** Paths are matched after
cleaning, and a path that still climbs above its own root
(`../../etc/x`) is refused outright: its meaning depends on the
session's working directory, which the proxy cannot see. Use absolute
paths. `allow_paths` patterns ending in `/**` or `/` cover a tree;
plain globs do not cross a slash, so `/srv/data/*` does not match
`/srv/data/a/b`.

**SFTP writes fail with permission denied and the server's own
permissions are fine.** `read_only` refuses more than `write`: setstat,
remove, mkdir, rmdir, rename, symlink, and any `open` carrying a
writing, creating or truncating flag. `sftp_refused` counts them and the
security log names the operation and the reason.

**An sftp session is refused at the subsystem request, before any
packet.** A path pattern names `{user}` or `{principal}` and this
session's name cannot stand in one: anything outside letters, digits,
`-`, `_` and `.`, anything over 64 characters, or a name that is only
dots. It is refused rather than escaped, because a login of `../..`
substituted into an allow list is an allow list for another directory.
The event is `ssh_sftp_identity_refused` and it names the variable.
`{principal}` also needs a `principals` list; without one the load
fails rather than every session.

**A file is refused for its name.** `allow_extensions` and
`deny_extensions` decide `open`, `rename` and `symlink` — not `stat` or
`remove`, since refusing to delete a file for what it is called leaves
it there. Every extension in a name is read, so `invoice.pdf.exe` is an
exe however the allow list ends. Extensions are written without a dot
and without a glob, and compared without case. The refusal is
`sftp_refused` with `extension`.

**A write is refused with `unknown_handle`.** The proxy is holding this
session to `max_file_bytes` or to a rule set, and both need to know
which file a handle is. It learns that from the `open` it decided on
and the handle the server answered with, so a write on a handle it never
saw that pair for cannot be judged. Either the client is writing to
something it did not open through here, or `max_open_files` filled —
raise it if a real client legitimately holds more handles at once.

**Uploads fail part way with permission denied.** Check
`max_file_bytes`: it bounds the file the writes make, counted from the
end of the furthest write, so a sparse write far out trips it
immediately even though little has been sent. If a `yara` section is
set, look for a `yara_match` event with the path — a rule read what was
being written. With `action: close` the transfer ends there; with
`action: log` the write is still refused and the session goes on.
`read_only` beside a `yara` section warns, because nothing then reaches
the rules.

**The recording directory stays empty.** Three things to check, in
order: the section is on the listener the session actually used; the
requests it records are allowed (`shell`, or `exec` with `commands`
left on — validation refuses a `recording` where neither can happen);
and the principal covering that key has not turned it off with
`recording: {enabled: false}`. A file appears when the channel opens
and is closed when it ends, so a session still running has a file that
is short by design.

**A recording cannot be opened and the session runs anyway.** That is
deliberate: a bastion that refuses work because a disk filled is its own
outage. The error log says why and an `ssh_recording_failed` event is
written, so the gap is visible rather than silent. Check that the
directory exists — the proxy does not create it — and that the proxy
user can write to it.

**A recording stops before the session did.** `max_file_bytes`, almost
always: the file carries a marker saying so, and the `ssh_recording`
line has `truncated: true`. The bound is on the session's bytes, so the
file is a little larger than the number set. Raise it, or accept that a
command which prints for an hour is not worth keeping in full.

**A replay wraps every line in the wrong place.** The recording was
made without a `pty-req` to take the size from, so it says 80x24. A
client that runs a command without asking for a terminal does not tell
anyone how wide its terminal is.

**Nothing shows what was typed.** `input` is off by default. Turning it
on records the keystrokes, including passwords typed into prompts that
never echoed them; whether that is lawful where you are is not a
question this configuration can answer.

**A session ends when a command finishes but the exit status is
missing, or `ssh host command` fails with EOF although the command
ran.** That would be a bug here rather than a policy: the bastion relays
the target's requests, and waits for any request that is mid-answer,
before closing the client's channel — a lost exit status or a lost
reply to the `exec` itself looks to the client like a crash. One such
race was fixed in 1.4; if you see it again, collect the access line and
the target's own log.

## Second factor (MFA)

**The SSH client says "permission denied" after the key was accepted.**
That is the second factor doing its job: the key is a partial success
and the session does not exist until a code verifies. A client that
cannot do keyboard-interactive (`-o PreferredAuthentications=publickey`,
or a batch job) will never get past it; give that account its own
listener without `mfa`, or use a recovery code interactively.

**Every code is refused.** Almost always the clock. TOTP steps are
thirty seconds, and `skew` accepts one step either side by default;
beyond a minute of drift nothing will verify. Check the clock on the
proxy and on the phone. `xproxyctl mfa verify -file … -user … -code …`
answers the same question without a session in the way.

**A code works once and then never again in the same minute.** It is
spent: a one-time password used twice is not one-time. Wait for the next
step. This is also why `skew` above 1 warns — each extra step is a
window in which an observed code can be replayed.

**A code that failed on one node works on another.** The spent-code
memory is per process. In a cluster a code can be replayed once per
node; put the listener behind a single node where that matters, or set
`skew: 0` so the window is one step.

**The user is refused even with the right code.** They may be locked
out: `max_failures` within `window` locks for `lockout`, and while
locked even a correct code is refused. The security log has
`mfa_failed` with the reason.

**The HTTP filter refuses with "no identity to challenge".** The `mfa`
filter runs before the one that authenticates. Put it after
`basic_auth`, `ldap_auth` or `oidc` in the route's `filters` list —
it challenges an identity, and a request with none has nothing to
challenge.

**The challenge form appears on every request.** The cookie is not
coming back. It is `Secure` and defaults to the `__Host-` prefix, so it
needs HTTPS and a path of `/`; on a plaintext listener no browser will
return it. It is also bound to the user, so a session that changes
identity is challenged again.

**Everyone was signed out after a secret rotation.** They should not
have been: the cookie is checked against every key in the ring. If it
happened, the `cookie_secret_file` was replaced rather than rotated —
use `xproxyctl rotate` so the old key stays in the ring.

**A user lost their phone.** A recovery code from the enrolment works
once in place of a code, at which point it is spent for good; re-enrol
the user afterwards with `xproxyctl mfa enrol` and replace their line.

## SAML single sign-on

**Every login ends at the consumer service with `signature`.** The
response did not verify against `idp_cert_file`. Three causes, in order
of likelihood. The provider rotated its signing certificate — export it
again, or point `idp_metadata_file` at the file the provider publishes
and let the proxy read it. The certificate configured is the encryption
certificate rather than the signing one: providers publish both, and
only a `KeyDescriptor` with `use="signing"` (or none) is read from
metadata. Or the provider signs the response and `signed_element` asks
for the assertion — set `signed_element: response`, or `either` if the
provider is inconsistent. `KeyInfo` in the document is never consulted,
so "the response carries its own certificate" is not a reason it should
have worked.

**`profile` on every login.** The response is outside the accepted
profile, and the proxy's log line says which part. The three that come
up in practice: the provider encrypts assertions (turn that off for this
service provider — TLS already covers the hop, and this profile does not
decrypt); it signs with SHA-1 (raise it to SHA-256); or it emits a
transform this profile does not take, which for a provider that offers a
choice means selecting exclusive canonicalization with the
enveloped-signature transform. A document type declaration in the
response is also `profile`, and there is nothing to configure: no
identity provider needs one.

**`refused`, with a good signature.** A check that is not about the
signature failed, and the warning in the error log names it: another
audience (`entity_id` here must be exactly what the provider has as the
service provider's entity ID), another `Destination` or `Recipient`
(`external_url` + `acs_path` must be exactly the consumer URL registered
at the provider — a trailing slash or a port is a different URL), an
expired window (check the clocks; `clock_skew` is 30 seconds by default),
or a name identifier format outside `name_id_formats`.

**`state_missing` on a login that looked fine.** The browser did not send
the state cookie back to the consumer service. It is `SameSite=Lax`,
which a top-level POST from the provider does carry, so the usual cause
is a different host: the login started on `app.example.com` and the
provider posts to `www.app.example.com`, or `cookie_domain` is set to
something the consumer path is not under. It is also what a response
nobody asked for looks like — a provider configured for
provider-initiated single sign-on will always land here, because this
profile has no state to bind such a response to.

**`replay` on a second attempt.** The same assertion was presented twice:
a reloaded consumer page, a browser retry, or an actual replay. The
assertion identifier is remembered until the assertion would have expired
anyway. Start the login again rather than reloading; a reload of a POST
cannot succeed by design.

**Logins loop: the provider sends the browser back and it starts
again.** The session cookie is not coming back, or it is expiring
immediately. It is `Secure`, so on a plaintext listener no browser
returns it; and the session is capped by the assertion, so a provider
issuing assertions valid for one minute gives one-minute sessions
whatever `session_ttl` says. `xproxyctl filters` shows `accepted` rising
with `logins` if the responses are being accepted, which separates "the
login fails" from "the session does not stick".

**The provider rejects the authentication request.** Compare what it
expects with `/saml/metadata` from this proxy, which is generated from the
running configuration: the entity ID, the consumer URL and the binding.
The request is unsigned — it carries no secret, and the response is
checked against this proxy's own state whatever the request looked like —
so a provider configured to require signed requests must have that
turned off for this service provider.

**Signing out here does not sign out at the provider.** It cannot:
single logout is not implemented (see CONFIG.md for why). `logout_path`
forgets the session at this proxy; the provider's own sign-out page ends
the session there. Keep `session_ttl` short if that gap matters, and note
that the provider's `SessionNotOnOrAfter` already caps it.

**The log says the identity provider certificate has expired.** It is a
warning, not a refusal: a pinned key is its own trust anchor, so
signatures still verify. It is there because nothing else would mention
it and because the provider is about to rotate.

## YARA scanning

**The listener will not start and names a line in the rule file.** The
engine is a subset of YARA (see `docs/CONFIG.md`), and anything outside
it is refused rather than ignored. The usual causes are `import "pe"` or
a module reference, `$a at 0`, a `for` loop, an unbounded jump `[2-]`,
alternation inside a hex string, `@a` or `!a`, and the `xor` or
`base64` modifiers. Rewrite the rule or drop it; a rule that loaded but
matched nothing would be worse.

**A rule that matches in `yara` on the command line does not match
here.** Three likely reasons. The pattern needs something the subset
does not have — check the rule against the list above. Or it straddles
two reads and is wider than the overlap: `max_window` bounds the
overlap, and a pattern wider than 4096 bytes cannot be matched reliably
across reads (the scanner reports this internally as truncated). Or the
match is past `max_bytes`, after which the stream carries on unscanned.

**Nothing matches at all on a `kind: tcp` listener.** If the listener
also has `quic: true`, remember that QUIC flows are not scanned:
they are encrypted, and a rule over ciphertext matches nothing.
Validation warns about this. The same applies to any TLS connection the
listener passes through — a layer 4 listener does not terminate TLS, so
what it sees is ciphertext. Put the rules where the bytes are plain:
the `yara` filter, behind TLS termination.

**A match closed a connection that was legitimate.** Switch to
`action: log`, watch `xproxy_yara_matches_total` and the `yara_match`
events for a while, then narrow the rule. The event carries the rule
names, their tags and the offset the rule became true at.

**The access log says `yara_partial`.** The body was larger than the
filter's `max_bytes`; it was scanned to the bound and forwarded whole.
Raise `max_bytes` if the traffic warrants the memory, and remember it is
buffered.

**`filesize` behaves oddly.** In a stream it means the bytes seen so
far, not the size of the object; there is no end to measure against
until there is one. A condition on it becomes true partway through.

**Scanning is expensive.** `max_bytes` bounds the work per direction and
`directions` halves it where only one side carries what the rules are
about. The other lever is the rules themselves: a regular expression is
scanned over every window and also widens the overlap to its cap, while
a literal or hex pattern narrows both.

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

**A view is empty, or says a subsystem is not enabled, on a daemon that
serves it nowhere.** `xproxyctl waf`, `filters`, `cache`, `quotas`,
`inventory`, `accounts` and the rest report on the HTTP data plane, and
only `xproxy` links one. Against `xgate` or `xrelay` they answer an
empty result rather than an error, because "this daemon runs no WAF" is
true and is the answer you want when a script asks all three. Point
`xproxyctl -socket` at the edge daemon's socket for those views.
`origin-check` is the exception: it is an action rather than a view, so
it says `this daemon serves no http listeners` instead of pretending to
have probed.

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

## XML and SOAP bodies

**Everything is refused with `xml_doctype`.** The client is sending a
document type declaration. That is refused whole and on purpose: it is
where an external entity, an external DTD and entity expansion live, and
this proxy cannot know what the application's parser would do with one.
Most XML libraries emit a `<!DOCTYPE>` only when asked to; the fix is on
the client side. There is no option to allow it.

**`xml_entity` on documents that look fine.** The body references an entity
that is not one of the five XML predefines (`&lt;` `&gt;` `&amp;` `&quot;`
`&apos;`). Anything else is a reference to something the document did not
carry, which is the external entity attack. A client that means a literal
character should send a character reference (`&#233;`) or the character
itself.

**`xml_size` where the body is not that large.** `max_bytes` bounds the
document, and an oversize body is refused rather than passed uninspected —
otherwise a large document would be the way past the filter. Raise
`max_bytes` for an API that genuinely sends them; do not turn the filter
off for that route.

**`xml_root` after a deployment.** The service moved namespace or the
client is posting to the wrong endpoint. `require_root_namespace` compares
the root's own declarations, so a client that dropped the `xmlns` on the
envelope fails here even though the local name is right.

**`xml_malformed` on documents the application used to accept.** Some
parsers accept mismatched tags, duplicate attributes and unquoted values;
this does not, because two parsers disagreeing about a malformed document
is where the interesting bugs are. The detail says which rule and at which
byte.

**Turning the filter on without breaking anybody.** `report: true` logs
`xml_would_refuse` with the rule and refuses nothing. Leave it on for a
day, read the access log, then turn it off.

## Early hints, early data and trailers

**Clients get a 425 on POSTs and nothing else changed.** A terminating
proxy in front started sending `Early-Data: 1`, which means those requests
arrived in the TLS handshake and can be replayed by whoever captured them.
That is `early_data: safe_methods` -- the default -- doing what RFC 8470
asks of a proxy, and the client is expected to send the request again on the
finished connection. If the route can genuinely take a replay, set
`early_data: allow` on it; if even a repeated read matters, `reject`. Note
that the marker counts only from a peer inside `trusted_proxies`.

**The access log shows status 103.** It should not any more: a 1xx is
recorded as informational and the final status is what the line carries. A
103 in that field means an older build.

**Early hints do not reach the browser.** Three places to look. The route
may have `early_hints: strip`. There may be more than eight of them from
the upstream, and the ninth onwards are dropped on purpose. Or the client
is not HTTP/1.1 or later -- `net/http` does not relay informational
responses to an HTTP/1.0 client.

**A client waits forever for a trailer.** Something announced one and sent
nothing: either an upstream bug, or a proxy in the chain that removed the
fields and left the announcement. This proxy removes both together, and
`trailers: strip` is refused on a gRPC route because the status lives
there.

**Requests are shed that used to be served.** Check whether the route has
`client_priority: lower` and the client sends `Priority: u=6` or `u=7`. The
client is asking to be shed first, and on that route the answer is yes. The
access log carries `priority_urgency`, and `priority_class` when it changed
the class.

## Deny reasons and details

**One refusal has three spellings, and they are not interchangeable.**
This trips people up more than anything else in the logs:

| Where you see it | Field | Example for one refusal |
|------------------|-------|------------------------|
| The access log | `denied` | `allow_cidrs`, `rate_limit:per-ip`, `virtual_patch:cve-2026-1` |
| The security log | `reason`, plus `detail` | `reason: acl_allow`; `reason: virtual_patch`, `detail: cve-2026-1` |
| `bans.triggers[].reasons` | the ban category | `acl`, `rate_limit` |
| The metrics endpoint | `reason` on a counter | `xproxy_denied_total{reason="acl"}`, `xproxy_refusals_total{kind="ftp",reason="path_refused"}` |

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
| `early_data` | A request that arrived as unconfirmed TLS early data on a route that will not take one (425 Too Early, RFC 8470) | no (the client did nothing wrong; it retries on the finished connection) |
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
| `forward_sni_mismatch` | TLS interception: the handshake inside a tunnel named a host the `CONNECT` did not | yes |
| `forward_upstream_tls` | TLS interception: the destination's own certificate did not verify, so nothing was forged for it | no (it is the destination's fault, not the client's) |
| `tcp_no_route` | A layer 4 listener with no route and no default | yes |
| `udp_denied` | The datagram relay: a client outside `allow_clients`, a datagram over `max_datagram_bytes`, the rate limit, or a session table that is full (`detail` says which). A datagram is dropped rather than answered, because a reply to a forged source is traffic aimed at whoever was named | yes |
| `dns_blocked`, `dns_bogus` | The DNS listener | yes |
| `dns_answer_denied` | An upstream answer pointed into a range `answer_policy` denies (rebinding, a metadata endpoint), or had such records stripped | yes |
| `dns_tunnel` | A client's queries under one domain agreed on enough tunnelling signals, or a query was refused during the cooldown after that | yes |
| `smtp_denied` | The SMTP listener: a client outside `allow_clients`, an overlong line, a bare newline, or data pipelined across STARTTLS (`detail` says which) | yes |
| `yara` | A YARA rule fired on a layer 4 stream with `action: close` | yes |
| `syslog_denied` | The syslog relay: a refused sender, a message it could not parse, one over the bound, or a stream whose framing could not be read | yes |
| `ftp_denied` | The FTP proxy: a refused command, path, extension or address, a failed login, a malformed control line, a bounce attempt, or a transfer cut by a bound or a rule (`detail` says which) | yes |
| `ssh_denied` | The SSH bastion: a failed authentication, a refused channel, request, subsystem, command, environment variable, file transfer helper or forward, or a refused SFTP request (`detail` says which) | yes |
| `mqtt_denied` | The MQTT listener: a refused CONNECT, a topic or filter outside the policy, a malformed packet, or a client outside `allow_clients` (`detail` says which) | yes |
| `telnet_denied` | The telnet gateway: a client outside `allow_clients`, a refused option, a failed factor, or a session it could not open (`detail` says which) | yes |
| `vnc_denied` | The VNC gateway: a security type outside the policy, a failed VNC authentication or factor, a target that offered nothing mediable, a client outside `allow_clients`, or a bound on the picture -- a framebuffer, a rectangle or a clipboard transfer past what `bounds` allows (`what` says which, and `detail` carries the numbers) | yes |
| `rdp_denied` | The RDP gateway: a refused channel or device, a failed factor, a connection sequence it could not read, or a client outside `allow_clients` (`detail` says which) | yes |
| `sftp_icap` | The SFTP scanner refused a file. The security event beside it is `sftp_icap_blocked`; the ban trigger names the observation | yes |

A trigger naming a reason that is not in the Ban column fails
validation with the list of the ones that are, so this is not something
you can get wrong silently.

### Counting refusals, by protocol and reason

The Ban column's reasons are deliberately coarse: `ftp_denied` is one
category so that one trigger can ban a client walking the policy,
whatever part of it they are walking. That is the wrong grain for an
operator asking *what should I change*, and the per-protocol counters
are no better on their own — `xproxy_ftp_refused_total` says the proxy
answered commands the server never heard, not whether that was the
command list, the path list or a login.

`xproxy_refusals_total{kind, reason}` is the breakdown, and it is what
`xproxy_denied_total{reason}` is for HTTP:

```sh
xproxyctl metrics | grep xproxy_refusals_total
xproxyctl stats | jq .refusals            # the same numbers, per kind
```

`kind` is the listener kind that refused — the same word a `kind:` in
the configuration says. `reason` is the security log's own `reason` or
`what` for that refusal with the kind's own prefix taken off, because
the label already carries it: a `reason: vnc_version` event is
`xproxy_refusals_total{kind="vnc",reason="version"}`. So the series
name the log line to go and read, and the vocabulary is whatever the
protocol has rather than a second list to keep in step with the first.

A series appears when that refusal first happens, so a quiet process
exports few of them; `grep` on a busy one is the list of what is
actually being refused. What each kind can say:

| Kind | The refusals it counts |
|------|------------------------|
| `tcp` | `max_connections`, `no_route`, `banned`, and for an intercepting listener `destination_not_allowed` and `no_original_destination`; QUIC flows add `quic_max_flows` |
| `udp` | `client_not_allowed`, `datagram_too_large`, `rate_limit`, `max_sessions`, `max_sessions_per_ip`, `banned`, `upstream_datagram_too_large` |
| `forward` | the destination policy (`not_allowed`, `deny`, `private`, `host`, `port`, `resolve`), the request shape (`not_absolute`, `scheme`, `authority`), `auth`, `tunnel_limit`, interception (`sni_mismatch`, `upstream_tls`, `client_tls`), SOCKS UDP (`udp_malformed`, `udp_unsolicited`, `udp_wrong_source`, `udp_peer_table_full`, `udp_disabled`) and MASQUE (`masque_target`, `masque_session_limit`, `masque_context`, `masque_spoofed`, `masque_unsolicited`) |
| `dns` | `workers_busy` (`max_in_flight`), `rate_limit`, `banned`, `malformed`, `client_not_allowed`, `blocked`, `tunnel`, `any_over_udp`, `formerr`, `opcode`, `answer_denied`, `answer_stripped`, `cookie_required`, `cookie_missing`, `cookie_malformed` |
| `ssh` | `client_not_allowed`, `max_sessions`, `max_sessions_per_principal`, `max_forwards`, `auth_failed`, `mfa_failed`, `mfa_not_enrolled`, the channel and request policy (`channel_refused`, `request_refused`, `subsystem_refused`, `env_refused`, `command_refused`, `shell_syntax`, `file_transfer_refused`, `forward_refused`, `remote_forward_refused`), the structured command rules (`command_direction`, `command_path`, `command_recursive`, `command_delete`, `command_server`, `command_env`, `command_no_rule`, `command_syntax`), what the certificate did not grant (`cert_no_port_forwarding`, `cert_pty_refused`, `cert_X11_forwarding_refused`, `cert_agent_forwarding_refused`), and SFTP (`sftp_refused`, `sftp_malformed`, `sftp_identity_refused`, `sftp_icap`) |
| `telnet` | `client_refused`, `banned`, `option_refused`, `subnegotiation_refused`, `malformed`, `mfa_failed`, `prompt` |
| `vnc` | `client_refused`, `banned`, `version`, `auth_failed`, `mfa_failed`, `view_only`, the security negotiation (`security_not_offered`, `security_not_usable`, `security_not_mediated`, `subtype_not_offered`, `vencrypt_subtype_not_mediated`, `tight_auth_not_offered`), the variants' own parameters (`tls`, `mslogon_parameters`, `ard_parameters`, `rsaaes_key`, `rsaaes_random`, `rsaaes_transcript`), and the picture (`framebuffer_too_large`, `rectangle_too_large`, `rectangle_outside_framebuffer`, `too_many_rectangles`, `encoded_rectangle_too_large`, `decode_ratio`, `cut_text_too_large`, `unframable`, `pixel_format`, `pixel_format_changed`, `resize_refused`, `resize_too_large`, `clipboard_to_client`, `clipboard_to_target`, and `encoding_<name>` for each encoding taken out of a client's list) |
| `rdp` | `client_refused`, `banned`, `mfa_failed`, `negotiate`, `no_protocol`, `tls`, `channels`, `channel_inert`, `channel_message`, `channel_chunk`, `channel_compressed`, `device_announce`, `client_info`, `info_encrypted`, `client_security`, `client_encryption`, `no_encryption_method`, `security_exchange`, `conference`, `no_io_channel`, `fast_path`, `data_unit` |
| `smtp` | `client_not_allowed`, `max_connections`, the command policy (`unknown_command`, `command_refused`, `ehlo_required`, `mail_required`, `mail_and_rcpt_required`, `transaction_open`, `already_authenticated`), TLS and authentication (`encryption_required`, `encryption_required_for_auth`, `authentication_required`, `tls_unavailable`, `tls_already_active`), the bounds (`message_too_large`, `too_many_recipients`, `line_too_long`) and the protocol abuse (`bare_newline`, `smuggling`, `starttls_injection`) |
| `mqtt` | `client_not_allowed`, `max_connections`, `not_connect`, `second_connect`, `version_refused`, the client id policy (`empty_client_id`, `client_id_too_long`, `client_id_refused`), `no_username`, `keep_alive_refused`, the topic policy (`publish_topic_refused`, `subscribe_refused`, `retain_refused`, `will_topic_refused`, `will_retain_refused`), `packet_too_large`, `malformed` |
| `ftp` | `client_refused`, `banned`, `max_connections`, `auth_failed`, `identity_refused`, `mfa_required`, `mfa_failed`, the command and path policy (`unknown_command`, `command_refused`, `path_refused`, `read_only`, `active_refused`, `no_data_connection`), the path shapes it will not guess about (`path_separator`, `path_control`, `path_encoding`), the commands that are half a decision (`rest_invalid`, `rest_unscannable`, `rename_out_of_order`), TLS (`tls_required`, `auth_refused`, `ccc_refused`, `tls_pipelined`), the data channel (`bounce_refused`, `malformed_address`, `data_stranger`, `upstream_address`, `transfer_cut`) and the line discipline (`line_too_long`, `malformed_line`, `malformed_command`) |
| `syslog` | `sender_refused`, `max_connections`, `rate_limit`, `too_large`, `framing`, `malformed`, the message policy (`facility`, `severity`, `pattern`) and `queue_full` when the collector is behind |

Two things are deliberately *not* in this family. Refusals by the
server-wide accept path — `server.limits.max_connections`,
`max_connections_per_ip`, `connection_rate` — happen before any kind
sees the connection and stay in `xproxy_connections_rejected_total` and
`xproxy_connections_rate_refused_total`. And failures that are not
refusals — an upstream that would not answer, a read that died — stay in
each kind's error counter, because an operator hunting a policy should
not have to read past a broken backend to find it.

`xproxy_refusals_untracked_total` must be zero. Anything else is a bug
in a listener kind (a refusal named under an unknown kind, or past the
bound on one kind's reason set): the refusals still happened and the
security log still has them, but they are missing from the breakdown.
Worth a report.

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
