# Extending Xproxy: the middleware interface

Xproxy is extended with compiled-in middleware ("filters"): Go packages
that implement the interface in `internal/filter`, register a *kind* at
start, and are configured per instance under `filters:` and attached to
routes by name. This document is the contract: what a filter may rely on,
what it must do, and how the interface evolves. The current API version
is 1 (`filter.APIVersion`; `xproxyctl filters` prints it).

Go plugins are never used, and a WebAssembly ABI is planned after 1.0
(AMR-013). Until then an extension is source in the tree, built into the
binary, and reviewed like any other code.

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

## Testing a filter

`internal/filter/filtertest` runs a filter the way the data plane does:

```go
f, err := filtertest.Build("my_filter", "instance", filter.Options{"header": "X-Tenant", "values": []any{"a"}})
res := filtertest.Run(f, req, nil)     // res.Request, res.Response, res.Attrs
```

`internal/filters/headerguard` (stateless, patterns) and
`internal/filters/basicauth` (a users file, a cache, deny headers) are
the reference implementations with tests.

## Stability

Version 1 guarantees:

- The method sets of `Filter`, `Instance` and `Kind`, the fields of
  `Info` and `Verdict`, the call order above, and the stage names.
- Additions are compatible: new optional fields in `Info`, `Verdict` or
  `Env`, new optional interfaces a filter may implement (as `Closer`),
  new stages. Version 1 gained `Info.Country`, `Info.JA3`, `Info.JA4`,
  `Info.ALPN`, `Info.ChallengeVerified` and `Verdict.Challenge` in 1.1
  this way, and `Info.HoneypotMarked` and `Verdict.Silent` in 1.2.
- Incompatible changes bump `APIVersion`, are recorded in CHANGELOG.md
  and AMR.md, and keep the previous version's semantics for one release.

Not covered by the contract: the internals of the built-in filters, the
`proxy` package types, and the wire format of `/v1/filters`.
