# Extending Xproxy: the middleware interface

Xproxy is extended with compiled-in middleware ("filters"): Go packages
that implement the interface in `internal/filter`, register a *kind* at
start, and are configured per instance under `filters:` and attached to
routes by name. This document is the contract: what a filter may rely on,
what it must do, and how the interface evolves. The current API version
is 1 (`filter.APIVersion`; `xproxyctl filters` prints it).

Go plugins are never used. Since 1.2 there are two ways to extend the
proxy: compiled-in kinds (this document's first part) and WebAssembly
modules run by the built-in `wasm` kind in a sandbox (the ABI in the
second part, AMR-013 and AMR-042). A compiled-in kind sees everything
and runs at native speed; a module runs with a memory and time bound,
sees the request through a small set of host functions, and can be
shipped and replaced without a build of the proxy.

## The interface

```go
package filter

type Filter interface {
    Name() string
    Begin(ctx context.Context, info *Info) Instance
}

type Instance interface {
    Request(r *http.Request) Verdict
    Response(resp *http.Response) Verdict
    End() []any
}

type Info struct {
    RequestID string      // the request identifier in every log line
    ClientIP  netip.Addr  // after trusted proxy evaluation
    Route     string      // route name
    Host      string      // normalised host
    Path      string      // cleaned path
    Method    string
    TLS       bool
    Country   string   // from the geoip database, "" when unknown or not configured
    JA3, JA4  string   // TLS client fingerprints, "" on plaintext listeners
    ALPN      []string // protocols the client offered
    ChallengeVerified bool // the client carries a valid browser challenge cookie
    CaptchaVerified   bool // that cookie was earned through the CAPTCHA tier
    DeviceID          string // device identifier from the challenge cookie, "" without one
    Automation        []string // automation markers the challenge script saw (webdriver, ...), nil without
}

type Verdict struct {
    Deny     bool              // stop the chain and answer the client
    Status   int               // 4xx or 5xx; 403 when unset
    Reason   string            // short token for logs, bans and counters; the filter name when unset
    Detail   string            // free text for the security log
    Attrs    []any             // extra slog attributes for the security event
    Headers  map[string]string // response headers on a deny (WWW-Authenticate, Retry-After)
    Response *http.Response    // full response to send instead of a status page (block pages)
    Challenge bool             // serve the browser challenge instead of the status page (when configured and the client is unverified)
    Captcha   bool             // with Challenge: ask for the CAPTCHA tier (the proof of work when none is configured)
    ThreatList string          // the imported threat list this verdict came from, on a deny and on a pass alike
}
```

A filter is built once per configuration generation and shared by every
request on every route that lists it. `Begin` runs once per request and
returns an `Instance` that lives for that exchange; returning `nil` opts
the request out of both phases. Instances are not shared between
requests, so per-request state lives in the instance and shared state
(compiled patterns, users, caches) in the filter with its own locking.

## Lifecycle of one request

1. The data plane has admitted the request: connection limits, bans,
   host and path normalisation, route match, ACL, challenge, shedding,
   rate limits and the body size limit have all passed. A filter never
   sees a request that the edge would have refused anyway.
2. `Begin` for every filter in the route's chain, in chain order.
3. `Request` for every instance in chain order. The first deny wins; the
   remaining instances' `Request` is not called. The request may be
   modified: headers added or removed, the body wrapped (replace
   `r.Body` with a reader that yields the same bytes when a filter needs
   to inspect it; the WAF does this). `r.URL` and `r.Host` are the
   values that will be sent upstream after the route's rewrites.
4. The route action runs: proxy, redirect or static response. For the
   proxy action the upstream response passes through `Response` for
   every instance in chain order, inside the reverse proxy's
   `ModifyResponse`, before any byte reaches the client. A deny there
   replaces the response (status page, or `Verdict.Response`). The
   response body may be wrapped the same way as the request body.
5. `End` for every instance, always, after the exchange (including a
   deny in either phase and a client abort). Its attributes are appended
   to the access log line, so a filter can record what it decided
   (`"auth_user", "alice"`) without writing its own log.

`Response` and `End` may run on a different goroutine from `Request`;
the data plane never calls two methods of one instance concurrently.

## Stages

Built-in filters run in a fixed order: JWT validation, then the WAF, then
ICAP scanning. A configured filter picks where it goes with `stage`:

| Stage | Runs |
|-------|------|
| `before_auth` | before JWT: authentication schemes of your own, request normalisation |
| `after_auth` (default) | after JWT, before the WAF: authorisation on validated claims, header policy |
| `after_waf` | after the WAF, before ICAP: only on requests the rules accepted |
| `after_scan` | last, after ICAP |

Within a stage, filters run in the order the route lists them. The JWT
filter forwards validated claims as headers; a filter after it can read
them from the request.

## Registering a kind

```go
package myfilter

import "github.com/rom/xproxy/internal/filter"

type Config struct {
    Header string `json:"header"`
    Values []string `json:"values"`
}

func parse(opts filter.Options) (*Config, error) {
    var c Config
    if err := opts.Decode(&c); err != nil { // rejects unknown keys
        return nil, err
    }
    if c.Header == "" {
        return nil, errors.New("header is required")
    }
    return &c, nil
}

func init() {
    filter.Register(filter.Kind{
        Name:        "my_filter",
        Description: "One line for xproxyctl filters.",
        Validate:    func(o filter.Options) error { _, err := parse(o); return err },
        New: func(name string, o filter.Options, env filter.Env) (filter.Filter, error) {
            c, err := parse(o)
            if err != nil {
                return nil, err
            }
            return &myFilter{name: name, cfg: c, log: env.Log}, nil
        },
    })
}

`Env.Events` is the node's event bus. A filter that keeps state other
nodes of a cluster should share (a revoked session, a client it has
decided about) publishes a `filter.Event{Kind, Key, Until}` and
subscribes to the same kind to learn the peers' facts:

```go
env.Events.Subscribe("my_filter/"+name, func(e filter.Event) { f.apply(e.Key, e.Until) })
...
env.Events.Publish(filter.Event{Kind: "my_filter/" + name, Key: key, Until: exp})
```

Put the filter name in the kind so that two instances stay apart. Publish
never blocks and never echoes locally; subscriptions end with the
generation. Kinds are bounded to 128 bytes and keys to 512; a lifetime
over a year is clamped. `Env.Events` is nil in `filtertest`, so check it.
Without a `cluster` section the bus is inert.
```

Then add `_ "github.com/rom/xproxy/internal/filters/myfilter"` to
`internal/filters/all.go`. Every binary that loads configuration imports
that package, so `xproxyctl validate` knows the kind too.

Rules for `Validate` and `New`:

- `Validate` runs at configuration load (also on `xproxyctl validate`
  and in the GUI editor) and must report every problem it can find in
  one error; `errors.Join` is the idiom. It may read files the options
  name (a users file) but must not open network connections.
- `New` runs once per generation, on reload as well as start. What
  `Validate` accepted, `New` must accept; a failure in `New` aborts the
  reload and the previous generation keeps serving.
- A filter that holds resources implements `filter.Closer`; `Close` runs
  when the generation is torn down, after its in-flight requests.
- Kind names are `[a-z][a-z0-9_]*`, at most 32 characters, unique;
  `Register` panics otherwise, which stops the process at start rather
  than at the first request.

## What the data plane does around a filter

- A deny is answered with the verdict's status and headers, logged on
  the security stream with the reason, detail and attributes, counted
  in `denied_filter` and in `xproxy_filter_denied_total{filter,kind}`,
  and fed to the ban list under the reason as category, so ban triggers
  can act on it (`bans.triggers[].categories: [my_filter]`).
- The reason defaults to the instance name and the status to 403 when
  the verdict leaves them empty.
- `Verdict.Silent` marks a deny that is a step of a normal flow (a
  login redirect, a logout): the response is sent, the access log gets
  `flow: <reason>:<detail>`, and no security event, ban observation or
  deny counter results. Use it for redirects, never for refusals.
- `Verdict.Response` is sent as is (status, headers, body) with the
  proxy's own security headers added.
- Request body limits apply before the chain; a filter that reads the
  body reads at most the route's limit.
- `Env.Intel` returns the imported threat-intelligence lists, or nil
  when the configuration has none. It is a function, not the set: the
  set is replaced on a reload and its entries are re-read under the
  filter, so a filter that captured one would go on matching a feed
  nobody publishes any more. A filter that reads a payload asks the hash
  lists about its digest and names the list in `Verdict.ThreatList`; the
  data plane counts that in `threat_intel_matched` and, on a deny, in
  `threat_intel_blocked`, so a match at a filter is counted like a match
  anywhere else. Set it whatever the list's action: a list whose action
  is `log` matched just as truly as one that blocks.

## Testing a filter

`internal/filter/filtertest` runs a filter the way the data plane does:

```go
f, err := filtertest.Build("my_filter", "instance", filter.Options{"header": "X-Tenant", "values": []any{"a"}})
res := filtertest.Run(f, req, nil)     // res.Request, res.Response, res.Attrs
```

`filtertest.BuildWithEnv` is the same for a filter that uses what the
data plane hands it -- the event bus, or the threat lists:

```go
f, err := filtertest.BuildWithEnv("upload_guard", "uploads", opts,
    filter.Env{Intel: func() *intel.Set { return set }})
```

`internal/filters/headerguard` (stateless, patterns) and
`internal/filters/basicauth` (a users file, a cache, deny headers) are
the reference implementations with tests.

## WebAssembly ABI (version 1)

A `wasm` filter loads one module from disk and runs it per request in a
wazero sandbox (pure Go, no cgo). The module is any WebAssembly binary
whose exports and imports follow this contract; it can be written in
Rust, C, Zig, TinyGo or Go (`GOOS=wasip1 GOARCH=wasm`, reactor mode with
`//go:wasmexport`). WASI preview 1 imports are available (clock,
random, no file system or sockets).

```yaml
filters:
  - name: policy
    kind: wasm
    options:
      module: /etc/xproxy/filters/policy.wasm
      config: "tenant=acme"     # free text the module reads with get(config)
      timeout: 50ms             # per call; a trap or timeout fails closed
      memory_limit_pages: 256   # 64 KiB pages per instance (16 MiB)
      instances: 16             # pooled instances
      on_error: deny            # or allow
      engine: auto              # compiler where executable memory is allowed, else interpreter
```

### Guest exports

| Export | Signature | Meaning |
|--------|-----------|---------|
| `memory` | memory | Linear memory the host reads strings from and writes strings into |
| `xproxy_abi_version` | `() -> i32` | Must return `1`; checked at load |
| `xproxy_alloc` | `(size: i32) -> i32` | Returns a pointer to `size` writable bytes; the host calls it before writing a string. A bump allocator is enough: instances are pooled and the host never frees |
| `xproxy_on_request` | `() -> i32` | Runs in the request phase; `0` continues, any other value denies (details from `deny`) |
| `xproxy_on_response` | `(status: i32) -> i32` | Optional; runs in the response phase with the upstream status |
| `_initialize` | `()` | Optional (WASI reactor); called once per instance |

### Host imports (module `xproxy`)

Strings are `(ptr, len)` pairs in guest memory, at most 64 KiB. A
returned string is packed in an `i64`: pointer in the high 32 bits,
length in the low 32 bits, `0` when absent.

| Import | Signature | Meaning |
|--------|-----------|---------|
| `get` | `(kind: i32, name_ptr: i32, name_len: i32) -> i64` | Read a request value; `name` only for header kinds |
| `set_header` | `(target: i32, name_ptr, name_len, value_ptr, value_len)` | `target` 0 request, 1 response (or the deny response during a request deny) |
| `remove_header` | `(target: i32, name_ptr, name_len)` | |
| `deny` | `(status: i32, reason_ptr, reason_len, detail_ptr, detail_len)` | Sets the verdict; `status` 400 to 599 (403 otherwise), `reason` a token (the filter name otherwise) |
| `log` | `(level: i32, ptr, len)` | Error log at debug 0, info 1, warn 2, error 3, tagged with the request id and route |
| `log_attr` | `(key_ptr, key_len, value_ptr, value_len)` | Adds `wasm_<key>` to the access log line (at most 32) |
| `set_body` | `(target: i32, ptr, len)` | Replaces the request (0) or response (1) body with guest bytes up to `body_limit`; sets the length and drops `Content-Encoding` on a response |

`get` kinds: 0 method, 1 path, 2 host, 3 query, 4 request header by
name, 5 client address, 6 route, 7 request id, 8 the `config` option,
9 country, 10 JA4, 11 response header by name, 12 response status
(response phase only), 13 request body, 14 response body (response
phase only), 15 body state: `ok`, `too_large` or `disabled`.

Bodies (added in 1.3): the first `get` of a body reads it into memory up
to `body_limit` (default 64 KiB) and hands the guest a copy; the
upstream or client then reads the buffered bytes, or what `set_body`
replaced them with. A body over the limit is never exposed (`get`
returns 0, the state says `too_large`) and streams through untouched,
so a module can only inspect what fits its bound; `body_limit: 0`
turns body access off. Reading a body costs a copy and, for requests,
delays forwarding until it has arrived; keep the limit to what the
policy needs.

### Rules

- Every call runs with the configured `timeout`; a trap, an
  out-of-bounds access or a timeout is a guest error. With `on_error:
  deny` (the default) the request is refused with 500 and reason the
  filter name; with `allow` it continues and the access log carries
  `wasm_error: allowed`. The instance that failed is discarded.
- Memory is bounded per instance by `memory_limit_pages`; strings that
  cross the boundary are bounded at 64 KiB; header operations at 64 per
  call; header names and values are checked for control characters.
- Instances are pooled up to `instances`; a request that finds the
  pool empty gets a fresh instance, so state kept in guest memory is
  per instance and must not be relied on between requests.
- The module is read and compiled at configuration load (`xproxyctl
  validate` compiles it too) and on every reload; a broken module or
  a wrong ABI version is a load error.
- The ABI version changes only for incompatible changes to the tables
  above; new `get` kinds and new imports are added compatibly.

A guest that blocks requests carrying `X-Block`, written as
WebAssembly text:

```wat
(module
  (import "xproxy" "get"  (func $get  (param i32 i32 i32) (result i64)))
  (import "xproxy" "deny" (func $deny (param i32 i32 i32 i32 i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "x-blockblocked")
  (global $heap (mut i32) (i32.const 4096))
  (func (export "xproxy_abi_version") (result i32) (i32.const 1))
  (func (export "xproxy_alloc") (param $n i32) (result i32)
    global.get $heap
    global.get $heap local.get $n i32.add global.set $heap)
  (func (export "xproxy_on_request") (result i32)
    (i64.and (call $get (i32.const 4) (i32.const 0) (i32.const 7)) (i64.const 0xffffffff))
    i32.wrap_i64
    (if (then
      (call $deny (i32.const 403) (i32.const 7) (i32.const 7) (i32.const 0) (i32.const 0))
      (return (i32.const 1))))
    (i32.const 0)))
```

The test guest in `internal/filters/wasm/module_test.go` is the same
program assembled by hand and exercises every import.

## Stability

Version 1 guarantees:

- The method sets of `Filter`, `Instance` and `Kind`, the fields of
  `Info` and `Verdict`, the call order above, and the stage names.
- Additions are compatible: new optional fields in `Info`, `Verdict` or
  `Env`, new optional interfaces a filter may implement (as `Closer`),
  new stages. Version 1 gained `Info.Country`, `Info.JA3`, `Info.JA4`,
  `Info.ALPN`, `Info.ChallengeVerified` and `Verdict.Challenge` in 1.1
  this way, `Info.HoneypotMarked` and `Verdict.Silent` in 1.2,
  `Env.Events`, `Info.CaptchaVerified`, `Info.DeviceID`, `Info.Automation`
  and `Verdict.Captcha` in 1.3, and `Env.Intel` and `Verdict.ThreatList`
  in 1.4. The
  WebAssembly ABI gained body `get` kinds and `set_body` in 1.3 at
  version 1.
- Incompatible changes bump `APIVersion`, are recorded in CHANGELOG.md
  and AMR.md, and keep the previous version's semantics for one release.

Not covered by the contract: the internals of the built-in filters, the
`proxy` package types, and the wire format of `/v1/filters`.
