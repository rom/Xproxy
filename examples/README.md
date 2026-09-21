# Examples

Ready to adapt configuration fragments and rule files. Every file here
is validated by `go test ./test/examples/`: the YAML documents pass the
configuration parser, the SecLang files compile with the Core Rule Set
and block what they say, the block list loads, the WebAssembly module
runs through the filter, and the rewriting rules apply to sample bodies.
Paths inside the files follow the Fedora layout (`/etc/xproxy`); on
macOS replace the prefix with `/usr/local/etc/xproxy`.

| Directory | Files | What they show |
|-----------|-------|----------------|
| `waf/` | `exclusions.conf`, `custom-rules.conf`, `hardening-rules.conf`, `attack-surface-rules.conf`, `waf.yaml` | Path scoped and profile wide CRS exclusions, custom rules (debug header, virtual patch, IP host header, JSON content type, scoring only, response leak), a second themed set (backup and source leftovers, template and JNDI expressions, class loader binding, `..;` path parameters, diagnostic methods, executable uploads, parameter, cookie and range bounds, GraphQL introspection, keys and database errors in responses), a third themed set (cloud metadata and scheme SSRF, local file inclusion and stream wrappers, Java, PHP and YAML deserialisation, external entities, NoSQL operators, shell commands, SpEL and Shellshock, smuggling shapes, routing headers and cache deception, prototype pollution, header injection and open redirects, debugger parameters, browser-executing uploads, scanner agents, interpreter error pages and directory listings), two profiles in detect and block mode, learning, a directory rule set |
| `forward/` | `socks.yaml`, `masque.yaml` | An egress proxy speaking HTTP CONNECT and SOCKS5 on one port with UDP associations, an allow list of the destinations a build estate needs, shared credentials and ban triggers for probing and credential guessing; UDP and IP proxying over extended CONNECT with the tunnel device, assigned source and advertised routes a CONNECT-IP endpoint needs |
| `mail/` | `submission.yaml` | Submission on 587 with STARTTLS required before AUTH or MAIL, implicit TLS on 465 with no STARTTLS to downgrade to, a replaced banner, recipient, message and error bounds, verified TLS to the mail server, XCLIENT so it still sees the real client, and a ban trigger on protocol abuse |
| `iot/` | `mqtt.yaml` | An MQTT broker fronted by a topic policy: devices publish their own telemetry and subscribe to their own commands, the broker's `$SYS` tree is refused both ways, retained messages are off, client ids must match a pattern, and a ban trigger catches anything walking the topic tree |
| `bastion/` | `ssh.yaml` | An SSH bastion that terminates the session: operators get a shell, commands and port forwards to two database ranges, X11 and agent forwarding are left out, and a delivery account gets nothing but read-only sftp into one directory with symbolic links refused |
| `mfa/` | `second-factor.yaml` | One TOTP enrolment file behind two protocols: the SSH bastion asks for a code after the key, and the same file backs the `mfa` filter in front of a web application, with the filter order that makes it work |
| `blocklists/` | `dns-blocklist.txt`, `dns.yaml`, `dns-encrypted.yaml`, `scanner-cidrs.yaml`, `bad-bots.yaml` | A DNS block list in every accepted line form with a sinkhole listener and DNSSEC; an encrypted resolver serving DoT, DoH and DoQ on one certificate, advertising itself through RFC 9462 discovery so clients upgrade themselves, and publishing the HTTPS records (with ECH) for the names it fronts; an include fragment with CIDR deny and allow lists; a `header_guard` fragment refusing scanner user agents |
| `filters/` | `header-policy.yaml`, `basic-auth.yaml`, `bot-score.yaml`, `form-guard.yaml`, `api-security.yaml`, `orders-openapi.yaml`, `wasm/policy.wat`, `wasm/policy.wasm`, `wasm/wasm.yaml` | Header requirements and denials with security response headers, basic authentication with a forwarded user, behavioural bot scoring with challenge and deny thresholds, hidden-field and timing form honeypots on a sign-up, a contact form and a password reset, a WebAssembly policy module with its text source and the filter that loads it; API keys with scopes, an OpenAPI description as an allow list with a sample description, GraphQL bounds and a per key sliding window |
| `rewrites/` | `paths.yaml`, `body.yaml`, `error-pages.yaml`, `error-pages/*.html`, `error-pages/api-error.json` | Regular expression path rewriting with captures, templated headers, mounting under a sub path, redirects that keep path and query, header rewriting; literal and regular expression body rewriting on both sides; custom error pages by status and class with a JSON document for API routes |
| `security/` | `honeypots.yaml`, `honeytokens.yaml`, `ech.yaml`, `captcha.yaml`, `distributed-bans.yaml`, `positive-model.yaml`, `security-txt.yaml`, `capture.yaml` | Honeypot routes and decoys, honeytokens planted in decoys and beyond them with a threshold-of-one ban, Encrypted Client Hello with a key rotation and the public name's own route, CAPTCHA providers, prefix and JA4 bans, a positive security policy with virtual patches, a virtual `security.txt`, and pcapng capture with rules for one client, every refusal, one WAF reason, a status class and a sampled route |
| `routes/` | `cors.yaml`, `maintenance.yaml`, `websocket.yaml` | A general CORS policy per route; a structured maintenance gate; WebSocket frame inspection on a chat route with tight bounds, a subprotocol and denied patterns beside a market-data feed with wide bounds and no inspection |
| `routing/` | `expressions.yaml`, `routing.yaml` | Regular expression paths, header and cookie conditions, a canary by header or cookie, retry policy, circuit breaker, concurrency gate and queue; `when` expressions selecting routes by address range, header or cookie, time window and body size, and gating header operations |

Use a file with `xproxy -config FILE -validate`, or copy the section you
need into `/etc/xproxy/xproxy.yaml` (fragments with only `routes`,
`upstreams`, `rate_limits` or `filters` can go to `/etc/xproxy/conf.d/`
with `includes: [/etc/xproxy/conf.d/*.yaml]` in the main file). The
reference for every key is [docs/CONFIG.md](../docs/CONFIG.md); the
operating patterns behind the examples are in
[docs/USAGE.md](../docs/USAGE.md).
