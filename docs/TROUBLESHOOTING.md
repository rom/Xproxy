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

- [The sixty-second triage](#the-sixty-second-triage)
- [Reading an access log line](#reading-an-access-log-line)
- [Symptom index](#symptom-index)
- [Start-up and configuration](#start-up-and-configuration)
- [Reload](#reload)
- [Routing](#routing)
- [TLS](#tls)
- [Upstreams](#upstreams)
- [Rate limits, bans, shedding and tarpits](#rate-limits-bans-shedding-and-tarpits)
- [WAF](#waf)
- [Authentication](#authentication)
- [The challenge and CAPTCHA](#the-challenge-and-captcha)
- [Filters](#filters)
- [Cache and compression](#cache-and-compression)
- [Cluster](#cluster)
- [DNS listener](#dns-listener)
- [Forward proxy, layer 4 and QUIC](#forward-proxy-layer-4-and-quic)
- [Fleet](#fleet)
- [Management socket and GUI](#management-socket-and-gui)
- [Logs, metrics, traces and SIEM](#logs-metrics-traces-and-siem)
- [Sandbox, systemd and SELinux](#sandbox-systemd-and-selinux)
- [Performance: latency, memory, CPU, descriptors](#performance-latency-memory-cpu-descriptors)
- [Bounded tables and what "full" means](#bounded-tables-and-what-full-means)
- [Deny reasons and details](#deny-reasons-and-details)
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
| `duration_ms`, `upstream_ms` | Total, and the part the upstream owns. A large gap is the proxy's own work or a slow client |
| `client_ip` | After `trusted_proxies` and `X-Forwarded-For`. If this is your load balancer, `trusted_proxies` is wrong |
| `waf_matched` | Rule ids, when the WAF acted |
| `honeypot_marked` | This client touched a honeypot earlier |
| `challenge_tier` | `none`, `proof` or `captcha` |
| `country`, `ja4`, `device` | Present when geo, TLS fingerprinting or the challenge are on |
| `cache` | `hit`, `miss`, `bypass` or `store` |

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
| 403 with `reason: acl` and `detail: allow_cidrs` | The client address is not in the allow list. If the proxy is behind a load balancer and this is the balancer's address, `trusted_proxies` is not set |
| 403 with `reason: geo` | The country is not allowed, or is unknown and `unknown: deny`. `xproxyctl status` shows whether a geo database is loaded at all |
| 403 with `reason: banned` | `xproxyctl bans`. Unban, or add the range to `bans.exempt_cidrs` |
| 403 with `reason: waf` | A rule matched. `waf_matched` names it; see [WAF](#waf) |
| 403 with `reason: honeypot` | The client asked for a honeypot path. That is the honeypot working |
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
| `management socket ... already in use` | Another xproxy is running, or a stale socket after a kill -9 |
| A reload says a listener needs a restart | Only a listener with a UDP socket (`h3`, `tcp.quic`, plain `dns`) changed on the same address |
| `configuration advice` warnings at start | Not errors: configurations that load but are a bad idea. Read them |
| `/v1/health` reports `degraded` | A hardening mechanism did not take effect and `sandbox.strict` is off |

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

**SPKI pinning breaks after a renewal.** `spki_pins` pins the public
key, not the certificate. A renewal that reuses the key keeps working; a
renewal with a new key does not. Pin two keys (current and next) before
rotating. `xproxyctl spki <host:port>` prints the pin for a running
upstream.

**ACME never issues.** `xproxyctl acme` shows the account, each domain's
state and the last error. The usual causes: `http-01` with the challenge
path not reachable from the internet (a route or a WAF rule in front of
`/.well-known/acme-challenge/`), or `tls-alpn-01` on a listener that is
not the one port 443 traffic reaches.

## Upstreams

```sh
xproxyctl upstreams     # per endpoint: healthy, active, latency, last error
xproxyctl pools         # per pool: algorithm, retries, circuit state
```

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
budget stops a failing pool from being retried into the ground —
`xproxyctl pools` shows when the budget is exhausted, which looks like
"retries stopped working" and is the feature.

**The circuit breaker is open.** Requests are refused without a dial
until the probe interval passes. `xproxyctl pools` shows the state and
the time of the next probe.

**Sticky sessions land on the wrong backend.** Check that the affinity
cookie is actually reaching the proxy (a browser will not send it
cross-site without `SameSite` allowing it) and that the endpoint list
has not changed: affinity survives a reload, but an endpoint that left
the pool cannot be honoured and the request is rebalanced.

**Slow start.** A newly healthy endpoint takes a fraction of the traffic
for `slow_start`, ramping up. A pool that looks unbalanced right after a
deploy is usually this.

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

## WAF

**A false positive.**

```sh
xproxyctl waf                 # rules by hits, with routes and last seen
xproxyctl waf-exclusions      # generated exclusions for what it has seen
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
per route and rule, without acting. `xproxyctl waf` then shows the
candidates and `xproxyctl waf-exclusions` prints exclusions you can
paste. This is the intended way to introduce the WAF to an existing
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

## Cache and compression

**Nothing is cached.** A response is cacheable only when the request's
wire path equals the routing path, the method and status are in the
lists, and the response allows it. `Authorization`, `Range` and (without
`cookies: true`) `Cookie` bypass the cache by design.
`xproxyctl status` has hits, misses and stores.

**A stale response.** `xproxyctl purge -host h -prefix /p` removes
entries. The TTL is the response's own `max-age` unless
`ignore_cache_control` is set, clamped to `cache.ttl`.

**A response is not compressed.** In order: the media type is not in
`compression.types`; the body is below `min_bytes`; the response already
has a `Content-Encoding` or a `Content-Range`; `Cache-Control:
no-transform`; the client did not offer the encoding; or — the one that
surprises people — the request carried `Authorization` or a `Cookie`.
Compressing a response to an authenticated request is the BREACH
condition, so it is off unless `compress_authenticated` says otherwise.

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

**A viewer can see too much.** `viewer` is a trusted operator without
write access: it reads the whole configuration file, the logs and the
bans. It is not a low-privilege role. Do not give it to anyone who may
not see the configuration.

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

**Latency added by the proxy.** Compare `duration_ms` and
`upstream_ms` in the access line. A consistent gap is the proxy's work:
WAF inspection, body-buffering filters, compression. `xproxyctl waf`
shows the rules by hits, which is usually where the time goes.

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

`reason` is the coarse category and is what `bans.triggers[].reasons`
matches on. `detail` is free text that narrows it.

| Reason | Raised by |
|--------|-----------|
| `acl` | `allow_cidrs` / `deny_cidrs` |
| `geo` | Country policy |
| `banned` | The ban list |
| `rate_limit` | A rate limit policy (`detail` names it) |
| `concurrency` | `max_concurrent_requests` |
| `body_size` | `max_body_bytes`, or a signed body digest bound |
| `body_budget` | The process-wide buffered-body budget |
| `uri_length` | `max_uri_length` |
| `bad_host` | An unusable `Host` |
| `normalization` | A normalisation check (`detail` names it) |
| `no_route` | Nothing matched |
| `websocket` | An upgrade on a route that does not allow it |
| `cors` | The route's CORS policy |
| `maintenance` | The maintenance gate |
| `policy` | The route's positive-security policy |
| `virtual_patch` | A virtual patch (`detail` is the patch id) |
| `waf` | A WAF rule |
| `jwt` | JWT verification |
| `icap` | An ICAP service |
| `honeypot` | A honeypot route |
| `challenge` | The challenge gate |
| `sensitive_data` | The DLP filter |
| `account_abuse` | `account_guard` |
| `shed` | Load shedding (`detail` is the class) |
| `filter` | Any other filter (`detail` is the filter name) |
| `forward_denied`, `forward_auth` | The forward proxy |
| `tcp_no_route` | A layer 4 listener with no route and no default |
| `dns_blocked`, `dns_bogus` | The DNS listener |

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
