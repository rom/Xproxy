# Tests

The test harness covers unit, integration, end-to-end, fuzz, race, lint
and vulnerability checks. This document describes what exists, how to run
it, what each layer is responsible for and what is added in later phases.

## Running

| Command | What it does |
|---------|--------------|
| `make test` | Unit and integration tests |
| `make test-race` | Same under the race detector (the CI default) |
| `make cover` | Coverage profile under race with cross-package instrumentation; prints total |
| `make cover-gate` | `make cover` then the gate: core packages at least 80 % together, none below 60 % (`COVER_MIN`, `COVER_FLOOR`) |
| `make mutate` | Mutation testing with gremlins on `limits`, `router` and `netutil` (`.gremlins.yaml` sets the thresholds) |
| `make fuzz FUZZTIME=30s` | Runs every `Fuzz*` target for the given budget |
| `make lint` | `golangci-lint` with the configuration in `.golangci.yml` |
| `make vet`, `make fmt` | `go vet`, formatting check |
| `make vuln` | `govulncheck` |
| `make check` | fmt, vet, race tests, lint |
| `go test -run TestProxyBasics -v ./internal/proxy/` | One test with output |
| `go test -bench . -benchmem ./internal/router/` | Router benchmark |

Tests need no network access beyond loopback and no root. They pick free
ports by listening on port 0 and reading the bound address back from the
server.

## Layers

### Unit tests

| Package | Tests | Focus |
|---------|-------|-------|
| `internal/config` | `TestConfigReferenceComplete` (every YAML key of the schema is mentioned in CONFIG.md), `TestMinimalDefaults`, `TestRejects` (25 rejection cases), `TestListenerKinds` (tcp and forward listener defaults and 26 rejections), `TestGRPCConfig`, `TestRouteActions`, `TestIngressConfig` (including `debounce`), `TestIncludes` (fragments appended in order with defaults, scalar sections, duplicates, unknown upstreams and multi document fragments refused, empty and relative globs, world writable fragments), `TestMultipleErrorsReported`, `TestZeroTimeoutMeansDefault`, `TestDuration`, `TestRateLimitDefaults`, `TestHostPattern`, `TestExampleConfig` | Defaults, every validation rule, error aggregation, the shipped example |
| `internal/router` | `TestMatch`, `TestNoMatch`, `TestMatchGRPC`, `BenchmarkMatch` | Exact versus wildcard host precedence, longest prefix, segment boundaries, methods, priority |
| `internal/netutil` | `TestClientIP`, `TestCleanPath`, `TestHost` | Trusted proxy algorithm including malformed hops and IPv4 mapped addresses; traversal normalisation; host normalisation |
| `internal/limits` | `TestAllowFallback` (full shard decides on the fallback key, no fallback bounded by burst, fallback equal to key), `TestKeyedLimiter`, `TestKeyedLimiterBound`, `TestPeerRates`, `TestConcurrency`, `TestConnLimiter`, `TestConnLimiterBanned` | Refill arithmetic with a fake clock, memory bound and eviction, peer reports reduce refill and expire, flush and its cap, release idempotency, real sockets dropped at accept, banned peers closed at accept |
| `internal/tlsconf` | `TestServer`, `TestClient` | SNI selection, hardening flags, insecure suite rejection, double opt-in |
| `internal/upstream` | `TestGRPCHealthEncoding`, `TestRoundRobin`, `TestWeighted`, `TestLeastConn`, `TestHashRing`, `TestAffinity`, `TestOutlierEjection`, `TestActiveHealthCheck` | Balancer semantics including smooth weighting and minimal key movement on the ring; cookie tamper and expiry; ejection percentage; health state transitions against a real HTTP server |
| `internal/logging` | `TestOpenAndWrite`, `TestRotate`, `TestRedactor`, `TestRedactionInStreams`, `TestJournaldSink`, `TestSyslogUDP`, `TestSyslogTCPFramingAndTLS`, `TestSyslogUnixAndDrops`, `TestMultiSink` | JSON single line, level filter, file mode, injection safety, rotation chain; every redaction rule including stable keyed pseudonyms across instances and IPv4/IPv6 truncation; redaction applied per stream with audit untouched; native journald datagrams parsed back (priority, identifier, indexed fields, binary multi-line values, key sanitising); RFC 5424 over UDP, RFC 3164 with octet counting over TCP and TLS with a pinned CA, Unix datagram; an unreachable collector never blocks and drops are counted; one stream to file and syslog with redaction on both |
| `internal/mgmt` | `TestManagementAPI`, `TestBanAPI`, `TestMetricsEndpoints`, `TestMetricsListener` | Socket mode, status, actions, error propagation, 501 for missing actions, in-use socket refusal; ban list, add, refuse loopback and bad durations, remove, counters; `/metrics` and `/v1/series` on the socket with bad parameters rejected; TCP metrics listener with an allow list refusing the caller, mutual TLS refusing clients without a certificate and serving one with, no management paths exposed, disabled listener as a no-op |
| `internal/ban` | `TestTriggerAndEscalation`, `TestWindowReset`, `TestExemptAndManual`, `TestBound`, `TestPersistence`, `TestReconfigure` | Trigger thresholds and reason filters, escalation and cap with a fake clock, window reset, exemptions, refusal of loopback and wide prefixes, CIDR bans, IPv4 mapped lookups, table bound, bbolt round trip including expiry and unban, reconfiguration keeps state |
| `internal/cluster` | `TestTwoNodes`, `TestRejectsUnauthenticated`, `TestProtocolErrors` | Bans and unbans propagate, sources are rewritten, rates arrive as rates, late joiner gets a snapshot, peer removal on reconfigure, status; connections without a certificate, with a foreign CA or outside `allowed_names` are rejected and counted; bad JSON, messages before hello, wrong version, unknown type and oversized lines close the connection while a valid session is applied |
| `internal/jwt` | `TestVerifyAlgorithms`, `TestVerifyRejections`, `TestHMAC`, `TestJWKSURLAndRotation`, `TestJWKSParsing`, `TestFilter`, `TestClaimString` | RS256, PS256, ES256 and EdDSA accepted with and without key ids; expiry, skew, `nbf`, issuer, audience (string and list), missing and required claims, `alg: none`, disallowed algorithms, HMAC against an asymmetric provider, unknown key, wrong key, algorithm and key type mismatch, tampered payload, malformed and oversized tokens; HMAC secret handling; JWKS over HTTPS with a pinned CA, rotation through on-demand refresh, rate limiting of refreshes, unpinned CA fails closed; malformed and symmetric keys skipped when parsing; filter behaviour for missing, optional, valid, invalid tokens, header spoof removal, cookie and header sources with stripping |
| `internal/tui` | `TestRenderAllViewsFit`, `TestRenderContent`, `TestHelpers`, `TestKeys`, `TestRunRequiresTerminal` | Every screen renders to exactly the terminal height and within its width at three sizes with and without colour; expected content per screen including selection, errors and prompts; ANSI-aware width and clipping; key handling for navigation, interval, pause, ban prompt with editing, unban confirmation and API errors, escape; refusal to run without a terminal |
| `internal/admin` | `TestPasswordHashing`, `TestUsersFile`, `TestOptionsPolicy`, `TestAuthAndRoles`, `TestLoginLockout`, `TestLogs`, `TestSplitProblems` | Hash format and verification including malformed hashes; users file round trip, mode, bad roles and names; listener policy (loopback and Unix allowed, non-loopback needs mutual TLS); against a fake management socket: anonymous 401, security headers, login without the CSRF header refused, wrong password, unknown and certificate-only users, viewer can read but not act, cookie attributes, logout, operator actions forwarded (reload, ban with the audit prefix, unban, restart command), cross-origin and cross-site fetch metadata refused, series parameter validation, configuration file read, validate with problems, invalid save refused without touching the file, stale entity tag 409, atomic save with backup and preserved mode, idle expiry; five failures lock the source out; log tail and server-sent event follow |
| `internal/netutil` (SNI) | `TestClientHelloSNI` | A real client hello parsed for its name (case folded), every truncation rejected without panic, non-TLS bytes and corrupt lengths refused, a hello without SNI |
| `internal/cache` | `TestStoreAndBounds`, `TestVary`, `TestHelpers` | Store and hit, expiry, per object and total bounds with LRU eviction order, purge by host and prefix, resize; Vary variants; Cache-Control parsing, Vary names, storable headers |
| `internal/tlsconf` (fingerprints) | `TestFingerprint` | JA3 and JA4 from a ClientHello: format, GREASE ignored, cipher order changes JA3 but not JA4, QUIC marker, minimal hello, bounded table with eviction and delete |
| `internal/filters/botscore` | `TestSignals`, `TestBehaviour`, `TestValidateOptions` | Each signal and its weight, header forwarding, challenge versus deny thresholds, verified clients not challenged, JA4 allow and deny lists; behaviour window with error rate, regular timing, rate and path spread, reset after the window, bursts not regular; option validation |
| `internal/geoip` | `TestMMDB`, `TestCSVAndDB`, `TestCacheBound` | The MMDB reader against files built by a writer of the real format: exact and longest prefix matches, IPv4 under the IPv6 tree, mapped addresses, record decoding, truncated and garbage files rejected; CSV parsing with header, quotes and comments, bad codes and empty tables refused; the cache bound |
| `internal/filter`, `internal/filters/*` | `TestRegistry`, `TestOptionsDecode`, `TestGuard`, `TestValidate`, `TestBasicAuth`, `TestBasicAuthValidate` | Kind registration and rejection of bad names and duplicates; options decoding with nested maps, unknown keys refused; header guard require and deny rules with status and detail, invalid patterns, header names, statuses and keys refused; basic authentication challenge headers, wrong password, unknown user, header stripping and forwarding, access log attribute, credential cache, users file validation (missing, world readable, malformed hash) |
| `internal/icap` | `TestOptionsAndReqmod`, `TestRespmodAndErrors`, `TestUnreachable`, `TestHeaderBlocks` | Against a fake ICAP server (`icaptest`): OPTIONS parsing, preview then `100 Continue` then `204`, block on preview with the encapsulated page, small and empty bodies, modified request, connection reuse, RESPMOD clean, blocked and rewritten, server error and timeout counted with recovery, unreachable service, header block rendering without hop-by-hop or injected headers |
| `internal/metrics` | `TestOTLPExporter`, `TestEncoder`, `TestHistogram`, `TestSeriesAndSampler` | OTLP/JSON push against a fake collector: gzip, headers, resource attributes, sums with attributes and start time, gauges, histogram bucket counts with the overflow bucket, status, the interval loop, a failing collector counted, a final push on stop, a missing CA refused; Text format with escaping and sorted labels, histogram buckets, sum and count; atomic histogram bucketing; ring buffer order, retention, since and limit, per-second rates from counters, counter reset handling, start and stop |
| `internal/shed` | `TestInflightLevel`, `TestLatencyLevelAndDrain`, `TestReconfigureKeepsSamples` | Class thresholds against the in-flight ratio, hysteresis, latency level from windowed samples, drain after an idle window, reconfiguration |
| `internal/challenge` | `TestFlow`, `TestVerifyInputs`, `TestPersistentKey`, `TestProofDefinition`, `TestScriptSHA256MatchesGo` | Page and headers, proof verification, wrong proof and wrong address refused, replay refused, cookie bound to address, expiry and tampering, exemptions, method and input validation, expired nonces, open redirect neutralised, key persistence, proof definition shared with the script |
| `internal/waf` | `TestBlockSQLi`, `TestDetectMode`, `TestCleanRequestPasses`, `TestBodyInspectionAndReplay`, `TestBodyLimitReject`, `TestResponseInspection`, `TestCustomDirectivesAndBadRules`, `TestOnlyNeededModesCompiled` | CRS blocks injection in query and body, detect mode logs without denying, clean traffic produces no attributes, inspected bodies are replayed intact, 413 above the body limit, response leakage blocked and clean or oversize responses pass intact, custom SecLang rules, compile errors surface, lazy compilation per mode |

### Integration tests (in `internal/proxy`)

These start a full `Server` on loopback with real `httptest` backends and
drive it with `net/http` and raw TCP.

| Test | Covers |
|------|--------|
| `TestProxyBasics` | Routing, strip prefix, header operations, forwarding headers with trusted and untrusted peers, traversal, no route, method filter, round robin distribution, dead upstream 502, rate limit 429 with `Retry-After`, tarpit delay, ACL 403, WebSocket refusal, redirect and respond actions, body limit 413, sticky cookie attributes and stickiness, URI length 414, counters and upstream statistics |
| `TestRetryOnDeadEndpoint` | Retry to a second endpoint, outlier ejection of the dead one, no replay of POST |
| `TestReload` | Generation swap changes routing, listener change refused, reload counters |
| `TestTLSAndRedirect` | HTTP to HTTPS 308 preserving path and query, TLS 1.3 with HTTP/2 negotiated, `X-Forwarded-Proto`, TLS 1.2 refused when the minimum is 1.3 |
| `TestTCPPassthrough` | Two HTTPS origins with their own certificates behind a `kind: tcp` listener: routed by server name end to end (the client verifies the origin's certificate; a wildcard route to the wrong origin fails the client's check, proving no termination), non-TLS bytes to the default echo upstream, unknown name closed on a listener without default, counters and pool accounting, idle timeout |
| `TestTCPProxyProtocol` | The upstream receives a PROXY v2 header (signature, command, family, client port) followed by the client's bytes |
| `TestForwardProxy` | A `kind: forward` listener as the proxy of an `http.Client`: CONNECT tunnel to an HTTPS origin verified end to end, plain relay with hop-by-hop headers removed and `Via` both ways, refusals for an unlisted port, a denied name, a denied CIDR, an unresolvable name, an origin-form request and (on the default policy) a private address; 407 with `Proxy-Authenticate`, wrong password refused, the right one tunnels, a destination outside the allow list refused with credentials, a rotated users file takes effect on reload and a broken one fails the reload; the tunnel bound answers 503, bytes sent before the 200 reach the origin, idle tunnels close; counters and no tunnel left after shutdown |
| `TestHoneypot` | Built-in decoy with a spoofed `Server` header, HEAD without body, a body file with a delay, the third hit trips a `honeypot` ban trigger, marks listed with hits and route, unmark, a vanished body file fails the reload |
| `TestHoneypotMarks` | The mark table: repeat hits, expiry, invalid addresses ignored, the 65536 bound with a sweep, decoy lists in config and proxy agree |
| `TestDoHRoute` | RFC 8484 GET and POST through a dns listener: answer, content type, `max-age` from the TTL, the second query a cache hit, a blocked name NXDOMAIN with `max-age=0`, bad base64, empty query, wrong content type and method refused, listener counters |
| `TestDNSListener` | A `kind: dns` listener with a fake upstream: Go's resolver over UDP and TCP resolves through it, blocked names (inline and file) are NXDOMAIN, a reload with an emptied block list takes effect while the cache survives, counters reach the stats and the management view, purge, a vanished block file fails the reload |
| `TestOIDC` | Against a fake provider (discovery, authorization, token endpoint checking PKCE and client credentials, JWKS, end session): login lands on the page first asked for with claims forwarded as headers and the cookie stripped upstream, a client supplied identity header is replaced, the session is reused, logout goes through the provider and clears the cookie, a tampered cookie is a fresh login, a forged `state` is 400, a provider error 401, a wrong nonce 401, a required claim mismatch 403, cookie key created `0600`; front channel logout with an unknown id, a wrong issuer, a missing id and the live id, after which the browser logs in again |
| `TestGRPC` | A hand rolled gRPC backend over h2c behind an `h2c: true` listener: echo with trailers relayed, a trailers-only backend error passed through, an unknown service answered `UNIMPLEMENTED` by the proxy, a plain request on a gRPC path not matching the gRPC route, ordinary routes over h2c, `grpc-timeout` shorter than the route timeout answered `DEADLINE_EXCEEDED`, status counters, a backend reporting `NOT_SERVING` ejected by the grpc health check and restored |
| `TestGRPCHelpers` | `grpc-timeout` parsing, status mapping, content type detection |
| `TestMirror` | Copies carry the rewritten path, `host_header`, marker and request id; bodies reach both; a body over the bound is proxied and not mirrored; unlisted methods are not mirrored; a stalled mirror drops the copy beyond `max_in_flight` without delaying the client; a dead mirror counts as failed and is invisible |
| `TestForwardConnectH2` | CONNECT over an HTTP/2 stream on a TLS forward listener carries a request to a plain origin and its response; tunnel counters; a refused destination is a 403 on the stream |
| `TestForwardPolicy` | Destination matcher (exact, `*.suffix`, CIDR, single address), every private range, hop-by-hop stripping including names listed in `Connection` |
| `TestResponseCache` | Miss then hit with `X-Cache` and `Age`, HEAD from GET's entry, `If-None-Match` 304, `Cache-Control: no-store` and `Set-Cookie` responses not stored, cookie requests bypass, `Vary: Accept-Encoding` gives one entry per encoding, a body above the object bound streams uncached, purge by host and prefix, counters through the management view |
| `TestBotScoreOverTLS` | Over a TLS listener: the fingerprint of the connection reaches the filter, the score is forwarded in a header, a scanner user agent above `deny_at` is refused and counted, a low `challenge_at` serves the challenge page and counts it, full browser headers score zero |
| `TestGeoPolicy` | Country allow and deny per route from a CSV table through trusted proxy forwarding, unknown addresses per the route's choice, a rate limit keyed on country sharing one bucket per country, `denied_geo` and the geoip status |
| `TestTarpitDoesNotHoldConcurrency` | With `max_concurrent_requests: 4` and `max_tarpits: 2`, six tarpitted requests: two are held, four rejected at once, the open route stays served meanwhile, counters and the hold time match (SR-1) |
| `TestHeaderRateLimitRotation` | 400 requests each with a new header key value against a limit keyed on that header with a shrunken table: far fewer than 400 pass, denials recorded (SR-2) |
| `TestChaosReloadStorm` | 200 concurrent reloads across four configurations while eight clients hammer the proxy: every request 200, generation advanced, old generations drained (goroutines back to baseline) |
| `TestChaosUpstreamFlap` | One of two endpoints behind a relay that drops connections in 300 ms on/off cycles, with retries, active checks and outlier ejection: every request 200, endpoint errors and an ejection recorded, the endpoint healthy again after the flapping stops |
| `TestChaosUpstreamDiesMidResponse` | The upstream sends headers and part of a 100 KB body then closes: the client never receives a complete body, the request returns within five seconds, the next request on another pool succeeds |
| `TestChaosLogDiskFull` | Every log file is `/dev/full` (ENOSPC on each write): requests are served, `log_write_errors` counts the drops, `xproxy_log_write_errors_total` is exposed, stderr carries one warning per minute |
| `TestChaosCertificateRotation` | Certificate files replaced in place then `reload-certs`: new handshakes see the new certificate, the expiry gauge is exposed, a broken file fails the reload and the previous certificate keeps serving |
| `TestFilters` | A `basic_auth` filter at `before_auth` and a `header_guard` at `after_auth` on two routes: open route passes and denies a scanner with the configured status, protected route challenges with 401, passes with credentials and forwards the user header without `Authorization`, denies a scanner after authentication; `denied_filter`, `Filters()` status per instance and the `xproxy_filter_denied_total` metric |
| `TestFiltersConfig` (config) | Default stage; unknown kind (error lists the registered kinds), invalid and unknown options, bad stage, unknown filter on a route, bad and duplicate names |
| `TestScale` | A generated table of 100 hosts and 1000 endpoints (1000 hosts and 10 000 endpoints with `XPROXY_SCALE=full`, `make scale`) with active health checks against a backend in a child process: parse, build and start timings, heap, goroutine and descriptor growth bounds, routing across the table, unknown host 404, management views and both metrics expositions, reload timing and old generation drain, traffic over random hosts with latency percentiles, no unhealthy endpoints |
| `TestACMEEndToEnd` | A listener with only ACME groups against the in-process fake CA (`internal/acme/acmetest`): no certificate before issuance, unknown challenge token 404, forced renewal through the manager joins the start-up order, both hosts served with a chain that verifies against the CA, `acme-tls/1` refused without a pending challenge; run for `http-01` and `tls-alpn-01` |
| `TestConnectionLimits` | Concurrency 503 on a live connection, third connection dropped at accept, counters |
| `TestSlowHeaderTimeout` | Slowloris connection closed by the header timeout |
| `TestWAFIntegration` | Block, detect and off modes per route, custom profile status, body inspected and forwarded, injection in body blocked, counters |
| `TestBanIntegration` | WAF denies trigger a ban that applies before routing, other clients unaffected, exempt range never banned, rate limit denies feed the catch-all trigger, manual CIDR ban and unban |
| `TestBanDropsConnectionAtAccept` | Accept hook sees bans; loopback refusal |
| `TestBansSurviveReload` | Reload keeps active bans; removing the section drops the list |
| `TestAdaptiveShedding` | A slow backend raises the level to 1; low, normal and high get 503 with `Retry-After` while critical is served; classes return once the window drains |
| `TestChallengeGate` | Script served on any host, unverified client challenged, exempt client passes, solved proof yields a cookie that works from the same address only, failed proof counted, `load` mode opens when calm and gates under load |
| `TestWriteMetrics` | Exposition after mixed traffic: request and response counters, denied reasons, endpoint gauges and counters, per-route outcomes, histograms, shedding gauges, build info; every family declared once; sampler produces points at the configured interval |
| `TestICAPIntegration` | Clean upload reaches the backend intact, infected upload gets the scanner's block page and headers, modified request rewrites path and headers with forwarding headers and host protected, over-limit body rejected, response scanning passes clean and blocks infected, unreachable service fails closed, repeated blocks trigger a ban, status and preview counters |
| `TestICAPFailOpen` | Unreachable service with `fail: open` passes traffic |
| `TestRedactedAccessLog` | A request through the full pipeline with redaction on: stable pseudonym, no address, user agent or referer path in the access file, status flag |
| `TestUpstreamMutualTLS` | Backend requiring a client certificate refuses the proxy without one; with the pair the backend sees the edge identity; certificate rotation through `ReloadCertificates` takes effect; a broken key fails the reload and keeps the old certificate |
| `TestUpstreamSPKIPin` | Wrong pin gives 502; a pin list containing the right pin passes |
| `TestJWTRoutes` | 401 challenge without a token, forwarded claims and stripped token with a valid one, spoofed header removed, expired token rejected with `invalid_token`, optional route semantics, open route unaffected, repeated failures trigger a ban |
| `TestJWTFromJWKSURL` | Provider fed by an HTTPS key set with a pinned CA |
| `TestHTTP3` | `Alt-Svc` on the TLS listener, a request over QUIC with `HTTP/3.0`, forwarding headers and response hygiene, body limit over QUIC, QUIC connection counted |
| `TestHTTP3ConnectionLimit` | A second QUIC connection from the same address is refused in the handshake while the first keeps working; rejection counted |
| `TestClusterSharesLimitsAndBans` | Two full servers peer over mTLS; a client's consumption on one node holds its bucket at zero on the other, other clients unaffected, recovery after reports go stale, ban propagation, listen change refused on reload |

### Fuzz targets

| Target | Input | Property |
|--------|-------|----------|
| `config.FuzzParse` | arbitrary bytes | never panics; nil config implies error |
| `router.FuzzMatch` | host, path, method | never panics on any strings |
| `netutil.FuzzCleanPath` | path | output always starts with `/` |
| `netutil.FuzzHost` | host header | never panics |

Fuzz corpora that find failures are committed under `testdata/fuzz`.

### Scale and load

`make scale` runs `TestScale` at the 1.0 target size and prints the
measurements; `make bench` runs the routing, limiter and metrics
benchmarks; `make load` starts the load backend and a proxy on loopback
and drives vegeta at `RATE` for `DURATION`. `test/load/README.md` has the
procedure and the rules for a comparable number; `docs/PERFORMANCE.md`
records the results.

### Packaging and policy (CI `package` job)

Runs in a Fedora container: `make selinux` compiles the module against the
Fedora policy headers (which catches interface names that only exist in
upstream reference policy), `make rpm` builds the three packages offline
from the vendored tarball, `make rpmlint` checks them against
`deploy/rpm/xproxy.rpmlintrc`, the packages are installed with `dnf` and
the three binaries print their version. What the container cannot do is
load the module or run with SELinux enforcing; that is the Fedora VM item
under planned additions and the release checklist.

### Static and supply chain

`golangci-lint` (errcheck, gosec, staticcheck, govet, bodyclose, noctx,
errorlint, gocritic and more), `go vet`, `gofmt`, `govulncheck`. All run in
CI (`.github/workflows/ci.yml`) on every push and pull request.

## Coverage

`make cover` instruments every package under `internal/` for every test
binary (`-coverpkg=./internal/...`), so an integration test in
`internal/proxy` counts towards the packages it exercises, and runs under
the race detector. `make cover-gate` then applies two rules through
`test/covergate`: the core packages together must reach 80 %, and no
single package may fall below 60 %. Both numbers are Makefile variables.
Excluded from the gate: the binaries (`cmd/`, covered by the smoke
procedures), the test fakes (`acmetest`, `icaptest`, `filtertest`,
`testutil`), `version` and the `filters` registration list. CI fails on
either rule (ASR-Q2).

Current numbers from `make cover-gate` (whole suite, race enabled):

| Package | Coverage |
|---------|----------|
| `internal/limits` | 99 % |
| `internal/shed` | 99 % |
| `internal/router` | 97 % |
| `internal/filter` | 96 % |
| `internal/metrics` | 95 % |
| `internal/netutil` | 95 % |
| `internal/ingress` | `TestTranslate`, `TestGatewayAPI`, `TestWatches`, `TestControllerAndProxy` | Translation of rules, annotations, default backends, class filtering, port resolution by number and name, ready endpoints only, placeholders for empty services, TLS secrets, every warning, long names; against a fake API server: sync and change detection, certificate files `0600`, merge into a base configuration served by the proxy, a cluster change requesting a reload, stale certificate removal, name collisions refused, an unauthorised token kept as an error with the last snapshot; Gateway API: class filtering, hostnames from the route and from listeners, prefix, exact, method, header and regular expression matches, header modifier, URL rewrite, redirect, weighted backends with a zero weight excluded, listener certificates, warnings, the merged result validating; watches: streams open per collection, a burst of events becomes one debounced sync and reload, counters |
| `internal/dns` | `TestMessages`, `TestBlockList`, `TestCache`, `TestServer`, `TestResolverNoUpstream`, `TestEncryptedUpstreams` | Header and question parsing, TTL walk and adjustment, EDNS size, truncation, sinkhole answers, pointer loops and truncations refused; block list forms and hosts file loading; LRU bound, TTL ageing, expiry, resize, purge; DNS over TLS and HTTPS upstreams round robin with a pinned CA, connection reuse, close, the wrong CA refused, upstream string forms; a full server against a fake upstream: forwarding, cache hits, negative caching, block actions swapped by policy, TC retry over TCP and truncation for UDP clients, SERVFAIL on a silent upstream, FORMERR, dropped garbage and responses, NOTIMP, client ACL, rate limit drops, status and access lines; a dead upstream |
| `internal/filters/wasm` | `TestGuest`, `TestBodies`, `TestLoadErrors` | A guest assembled by hand in the test (`module_test.go`): request headers set from the guest and from `config`, response header removed, access log attribute, deny from the request phase with status, reason and detail, deny from the response phase, an infinite loop hits the timeout and fails closed while the filter keeps serving with a fresh instance, `on_error: allow`, a module without the response export; load errors for a missing or relative module, ABI version 2, bad options, garbage bytes; bodies: read and echo within the limit with the state header, a body over the limit untouched and reported, request and response replacement with lengths fixed and `Content-Encoding` dropped, body access disabled, the limit bound |
| `internal/filters/oidc` | `TestParse`, `TestSealOpen`, `TestRevocation` | Every option rule and default, no key file created by validation; seal and open with purpose binding, tampering and garbage refused, expired sessions refused, cookie stripping keeps other cookies, claim formatting |
| `internal/filters/headerguard` | 92 % |
| `internal/challenge` | 90 % |
| `internal/config` | 89 % |
| `internal/cluster` | 88 % |
| `internal/upstream` | 88 % |
| `internal/filters/basicauth` | 88 % |
| `internal/waf` | 85 % |
| `internal/jwt` | 85 % |
| `internal/tlsconf` | 82 % |
| `internal/acme/jose` | 82 % |
| `internal/logging` | 82 % |
| `internal/acme` | 81 % |
| `internal/ban` | 80 % |
| `internal/admin` | 80 % |
| `internal/h3` | 79 % |
| `internal/mgmt` | 78 % |
| `internal/proxy` | 77 % |
| `internal/icap` | 77 % |
| `internal/passwd` | 77 % |
| `internal/tui` | 62 % (the terminal loop itself is covered by the pseudo terminal check) |
| **core packages together** | **82.5 % of 7704 statements** |

Not covered: the raw terminal loop of the TUI (pseudo terminal check),
socket activation (needs systemd), the QUIC transport internals beyond the
handshake and admission tests, and file system failures other than a full
disk.

## Mutation testing

`make mutate` runs [gremlins](https://github.com/go-gremlins/gremlins) on
the packages whose comparisons and arithmetic decide admission:
`internal/limits` (token buckets, peer rates, connection and concurrency
limits), `internal/router` (host and path precedence) and
`internal/netutil` (client address and host normalisation). Gremlins
applies one mutation at a time (flip a comparison, move a boundary, change
an operator, invert a sign) and runs the package tests; a mutant that
survives marks a behaviour no test observes. `.gremlins.yaml` sets the
gate at 75 % efficacy (killed over killed plus lived) and 90 % mutant
coverage. Timed out mutants are excluded from efficacy; run it on an
otherwise idle machine, the timeouts derive from a baseline run.

| Package | Mutants | Killed | Lived | Efficacy |
|---------|---------|--------|-------|----------|
| `internal/limits` | 68 | 59 | 9 | 86.8 % |
| `internal/router` | 31 | 25 | 6 | 80.6 % |
| `internal/netutil` | 46 | 45 | 1 | 97.8 % |

The first run scored 61.8 %, 79.3 % and 87.0 %; the survivors led to
`limits/mutation_test.go` (exact token, eviction, peer staleness, peer
count and shard bound boundaries, the hash function, per address
connection counts), `TestTieBreaks` and `TestWildcardHostEdges` in the
router, and `TestHostEdges` in netutil. What still lives are boundary
mutants on the sort comparator for equal length prefixes (equivalent
under stable sort with the index tie break) and on comparisons whose
boundary case is unreachable by construction (an IPv6 literal without a
closing bracket at position zero, `len(host)+1`). They are accepted and
listed here so a future change to those lines is looked at.

## Chaos tests

`internal/proxy/chaos_test.go` injects the failures an operator sees in
production and asserts continuity, bounded recovery and no leak: a reload
storm, a flapping endpoint, an upstream dying mid response, a full log
disk and certificate rotation with a broken file. The table above lists
what each one checks. Two of them changed the product: a full disk now
counts dropped events (`log_write_errors`, `xproxy_log_write_errors_total`)
and warns on stderr at most once a minute instead of failing silently,
and the earliest certificate expiry per listener is exposed as
`xproxy_certificate_expiry_seconds` so a forgotten renewal is an alert,
not an outage.

## Manual smoke procedure

Used before every merge to `main` until binary level tests exist:

```sh
make build
python3 -m http.server 18080 --bind 127.0.0.1 &
cat > /tmp/x.yaml <<'EOF2'
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:18081"}]
management: {socket: /tmp/xproxy-mgmt.sock, socket_mode: "0600"}
logging: {directory: /tmp/xproxy-logs}
rate_limits: [{name: rl, rate: 5, burst: 3}]
upstreams: [{name: py, endpoints: [{address: 127.0.0.1:18080}], health_check: {path: /, interval: 1s, timeout: 500ms}}]
routes: [{name: all, upstream: py, rate_limits: [rl]}]
EOF2
mkdir -p /tmp/xproxy-logs
./bin/xproxy -config /tmp/x.yaml &
curl -i http://127.0.0.1:18081/                          # 200, X-Request-Id, no Server header
for i in 1 2 3 4 5; do curl -s -o /dev/null -w "%{http_code} " http://127.0.0.1:18081/; done   # 200 200 429 429 429
./bin/xproxyctl -socket /tmp/xproxy-mgmt.sock status
./bin/xproxyctl -socket /tmp/xproxy-mgmt.sock upstreams
./bin/xproxyctl -socket /tmp/xproxy-mgmt.sock -config /tmp/x.yaml reload
tail -1 /tmp/xproxy-logs/security.log; cat /tmp/xproxy-logs/audit.log
kill %2; kill %1
```

### Pseudo terminal check of the TUI

Before release the TUI is driven in a pseudo terminal against a running
proxy (a Python `pty.fork` of `xproxyctl tui`, sending `2`, `3`, `5`,
`6`, `1`, `q`), asserting that the alternate screen is entered and left,
that each screen shows live data (upstream address, a ban, sparklines,
security events) and that the process exits with status 0.

### Browser check of the GUI

Run the smoke set-up above, create users and start the GUI:

```sh
echo 'operator-password-1' | ./bin/xproxy-admin user add op -role operator -users /tmp/admin-users
./bin/xproxy-admin serve -listen 127.0.0.1:18203 -socket /tmp/xproxy-smoke/mgmt.sock -config /tmp/xproxy-smoke/xproxy.yaml -users /tmp/admin-users
```

Then drive headless Chromium over the DevTools protocol (a Node script
with the built-in `WebSocket`, no packages): navigate to the page, submit
the login form, switch `location.hash` through every screen, run
*Validate* on a broken edit and *Validate and save* on a good one, unban,
switch the log view to `access` and request a page through the proxy. The
expected result is every screen rendered with data, the problems list
naming the bad key, the saved file with `.bak` next to it, the new access
line arriving through the event stream, and no Content Security Policy
violation or script error in the browser log (the only console errors are
the deliberate 401 before login and the 502 for a feature the smoke
configuration does not enable). This procedure was run on the reference
build; it becomes an automated job once the Fedora runner exists.

### Browser check of the challenge

The challenge script is verified in a real browser before release, using
the headless Chromium that CI images carry:

```sh
# xproxy running with challenge: {difficulty: 14} and a route with
# challenge: {mode: always}, upstream serving "hello from backend"
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:18121/        # 503: the page
chromium --headless --no-sandbox --virtual-time-budget=60000 --dump-dom http://127.0.0.1:18121/
# prints the backend document; the access log shows 503, 200 (script),
# 303 (verification) and 200 (return), and challenges_passed is 1
```

## Planned additions

Phase 2:

- WAF corpus tests: the CRS regression suite run through the proxy in
  detect mode, asserting scores per rule family; a false positive suite from
  sample applications. (The engine level tests above cover the integration;
  the corpus run is still open.)
- Cluster convergence bounds under load and a three node partition test
  (the two node functional tests exist; see above).
- HTTP/3 interoperability with `quic-go` clients and a curl build.
- Load tests on the reference hardware (8 cores, remote generator); the
  `test/load` suite, the container baseline and the soak script exist,
  the 24 hour soak and the 8 core numbers are still to be run.
- Fuzz targets for ICAP framing, WAF transaction building, redaction rules
  and the cluster wire format.
- ACME against Pebble in a container in CI (the fake CA in
  `acmetest` covers the protocol; Pebble adds its deliberate failures and
  nonce rejection).

Phase 3:

- Binary level end-to-end suite in `test/e2e` that runs `bin/xproxy` with
  socket activation emulated via `LISTEN_FDS`, exercises `xproxyctl` and
  checks logs.
- Chaos: certificate expiry while serving (the certificate itself expiring,
  as opposed to rotation, which is covered), a SIGKILLed upstream process
  (the mid-response death is covered at the connection level).
- Fedora VM runner: install the RPMs, enable units, run traffic, assert no
  AVC denials and a passing `systemd-analyze security` band (the container
  job covers build, lint and install).
- Automated browser job for the GUI (the DevTools procedure above) on the
  same runner.
