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
| `waf/` | `exclusions.conf`, `custom-rules.conf`, `waf.yaml` | Path scoped and profile wide CRS exclusions, custom rules (debug header, virtual patch, IP host header, JSON content type, scoring only, response leak), two profiles in detect and block mode, learning, a directory rule set |
| `blocklists/` | `dns-blocklist.txt`, `dns.yaml`, `scanner-cidrs.yaml`, `bad-bots.yaml` | A DNS block list in every accepted line form with a sinkhole listener and DNSSEC; an include fragment with CIDR deny and allow lists; a `header_guard` fragment refusing scanner user agents |
| `filters/` | `header-policy.yaml`, `basic-auth.yaml`, `bot-score.yaml`, `wasm/policy.wat`, `wasm/policy.wasm`, `wasm/wasm.yaml` | Header requirements and denials with security response headers, basic authentication with a forwarded user, behavioural bot scoring with challenge and deny thresholds, a WebAssembly policy module with its text source and the filter that loads it |
| `rewrites/` | `paths.yaml`, `body.yaml` | Prefix stripping, mounting under a sub path, permanent redirects, request and response header rewriting; literal and regular expression body rewriting on both sides |
| `routing/` | `routing.yaml` | Regular expression paths, header and cookie conditions, a canary by header or cookie, retry policy, circuit breaker, concurrency gate and queue |

Use a file with `xproxy -config FILE -validate`, or copy the section you
need into `/etc/xproxy/xproxy.yaml` (fragments with only `routes`,
`upstreams`, `rate_limits` or `filters` can go to `/etc/xproxy/conf.d/`
with `includes: [/etc/xproxy/conf.d/*.yaml]` in the main file). The
reference for every key is [docs/CONFIG.md](../docs/CONFIG.md); the
operating patterns behind the examples are in
[docs/USAGE.md](../docs/USAGE.md).
