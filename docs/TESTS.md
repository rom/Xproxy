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
| `make vet-all` | `go vet` for Linux amd64 and arm64 and macOS arm64 and amd64, so the macOS port cannot rot |
| `make vuln` | `govulncheck` |
| `make check` | fmt, vet-all, race tests, lint |
| `go test -run TestProxyBasics -v ./internal/proxy/` | One test with output |
| `go test -bench . -benchmem ./internal/router/ ./internal/waf/ ./internal/dns/ ./internal/netutil/` | Benchmarks: routing, a clean request through the CRS with and without statistics, DNS message parsing, PROXY header parsing |
| `go test ./internal/config -run TestExampleDumpGolden -update` | Regenerate the golden dump of the example configuration after an intended default change |

Tests need no network access beyond loopback and no root. They pick free
ports by listening on port 0 and reading the bound address back from the
server.

## Layers

### Unit tests

| Package | Tests | Focus |
|---------|-------|-------|
| `internal/config` | `TestConfigReferenceComplete` (every YAML key of the schema is mentioned in CONFIG.md), `TestMinimalDefaults`, `TestRejects` (25 rejection cases), `TestListenerKinds` (tcp and forward listener defaults and 26 rejections), `TestGRPCConfig`, `TestRouteActions`, `TestIngressConfig` (including `debounce`), `TestIncludes` (fragments appended in order with defaults, scalar sections, duplicates, unknown upstreams and multi document fragments refused, empty and relative globs, world writable fragments), `TestMultipleErrorsReported`, `TestZeroTimeoutMeansDefault`, `TestDuration`, `TestRateLimitDefaults`, `TestHostPattern`, `TestExampleConfig` | Defaults, every validation rule, error aggregation, the shipped example |
| `internal/router` | `TestMatch`, `TestNoMatch`, `TestMatchGRPC`, `TestRegexAndConditions`, `BenchmarkMatch` | Exact versus wildcard host precedence, longest prefix, segment boundaries, methods, priority; anchored patterns ranked by literal prefix and beating a plain prefix of the same length, header exact, prefix, regex, presence and absence, cookie presence, conditioned routes before plain ones, configuration order at equal conditions |
| `internal/netutil` | `TestClientIP`, `TestCleanPath`, `TestHost`, `TestProxyHeader` | Trusted proxy algorithm including malformed hops and IPv4 mapped addresses; traversal normalisation; host normalisation; PROXY protocol v1 and v2 headers (IPv4, IPv6, UNKNOWN and LOCAL, TLVs skipped, every truncation and malformed field refused, nothing consumed without a signature) |
| `internal/limits` | `TestAllowFallback` (full shard decides on the fallback key, no fallback bounded by burst, fallback equal to key), `TestKeyedLimiter`, `TestKeyedLimiterBound`, `TestPeerRates`, `TestConcurrency`, `TestConnLimiter`, `TestConnLimiterBanned`, `TestTop` | Refill arithmetic with a fake clock, memory bound and eviction, peer reports reduce refill and expire, flush and its cap, release idempotency, real sockets dropped at accept, banned peers closed at accept; lifetime totals and top consumers surviving a flush |
| `internal/tlsconf` | `TestServer`, `TestClient` | SNI selection, hardening flags, insecure suite rejection, double opt-in |
| `internal/tlsconf` (session tickets) | `TestTicketsResumeAcrossNodes` | Two nodes built from the same secret file: a ticket from node A resumes on node B, still resumes after one rotation on B, is refused two epochs later, peer fingerprint agreement and mismatch, the rotation callback, idempotent start and stop, nil receiver; `internal/config` `TestSessionTicketsConfig` covers defaults, the relative path, missing file and rotate bounds, and the restart requirement in the diff |
| `internal/proxy` (listener reload) | `TestReloadListeners` | Reload adds a listener and serves it, rebuilds one on the same address keeping the socket (address unchanged, old idle keep-alive connection closed by the drain, new behaviour served), renames one keeping its socket, removes one (socket closed after the drain), fails as a whole on an address in use with the set unchanged, refuses an `h3` listener changed on the same address while its certificate files still reload in place |
| `internal/config/schema` | `TestSchemaCurrent`, `TestSchemaRefs`, `TestSchemaCoversDump` | The committed schema matches the configuration types (regenerate with `-update` or `go generate`); every `$ref` resolves and every object forbids unknown keys; every key of the golden example dump exists in the schema with a compatible type and enumerated values |
| `internal/manpage` | `TestRender`, `TestPagesCurrent` | Markdown to troff: headings, inline code, bold, emphasis, links, lists, code blocks, tables with break points and escaped pipes; the committed pages match the sources, name every command and, when groff is installed, format without a warning |
| `internal/filters/apikey` | `TestLifecycle`, `TestSourcesAndValidation` | Issue, duplicate id refused, file mode and no plaintext on disk, valid key with forwarded id and scopes and a spoofed header removed, missing, unknown, expired, wildcard scope, missing scope (403), rotation with and without grace, revocation, removal, a broken file keeping the previous table; bearer, query and header sources with stripping; rejected options and a world readable file |
| `internal/filters/openapi` | `TestValidation`, `TestSpecErrors`, `TestFileReload`, `TestURLSpec` | Against a YAML description: valid list, create, non JSON body, concrete over templated path, uuid path parameter, HEAD; unknown path (404), outside the base path, undefined method with `Allow`, query maximum, type, array enum, strict query, required header, path format, required body, undeclared media type (415), malformed JSON, format and list bounds, nested item rules, enum, oneOf, bounded details, body too large (413), body restored, `unknown_paths: allow`; rejected descriptions and options, a JSON description with `base_path`; a changed file picked up after the interval and dated change time, a broken rewrite kept out with a failure counted, identical bytes not a reload; URL options refused, the initial fetch with ETag and cache written, 304 leaving the description, a background refresh installing a new version and updating the cache, a broken fetch kept out, a start from the cache with the registry down and a refusal without one |
| `internal/filters/graphql` | `TestBounds`, `TestValidate` | Depth, complexity with literal and variable list arguments, aliases, introspection, syntax errors, fragment cycles, inline fragments, directives and nested argument values, size, batches, GET and `application/graphql`, non GraphQL traffic passing, body restored; rejected options and defaults |
| `cmd/xproxyctl` (apikey) | `TestApikeyCommand` | add with scopes, expiry and note (plaintext printed once, hash on disk), duplicate and bad ids, bad expiry, rotate, list, revoke, remove, usage errors |
| `internal/proxy` (HTTP/3 upstream) | `TestHTTP3Upstream`, `TestHTTP3UpstreamFallback` | A pool with `h3` reaches an HTTP/3 backend (the backend sees `HTTP/3.0`, the pool reports protocol h3); a TCP-only endpoint makes QUIC time out and the request is served over TCP with one counted fallback, and fails with 502 when `h3_fallback` is off |
| `internal/proxy` (gRPC-web) | `TestGRPCWeb` | Binary and text variants over HTTP/1.1 against an h2c gRPC backend: the echo frame followed by a trailer frame with `grpc-status: 0`, CORS headers for an allowed origin only, upstream headers kept, base64 decoding of concatenated padded chunks, a trailers-only failure as a trailer frame, the preflight answered for the allowed origin and refused for another, and refusal in gRPC-web form on a gRPC route without `web` |
| `internal/proxy` (WebTransport) | `TestWebTransportRelay` | A webtransport-go client through an h3 listener with `webtransport` to an HTTP/3 echo backend: the CONNECT carries the header operations, forwarding headers and origin; a bidirectional stream, a unidirectional stream in each direction and a datagram are echoed; the session counter; a route without `webtransport` refuses the session |
| `internal/jwt` (introspection) | `TestIntrospection` | Against a TLS endpoint with basic credentials: an opaque token yields claims, the second check is served from the cache, an inactive token is refused with reason `inactive` and cached, an endpoint failure is `ErrIntrospection` and not cached, counters, audience rules on introspected claims, selection of introspection with and without keys and with `always`; `internal/config` `TestIntrospectionConfig` covers defaults and rejected settings |
| `internal/proxy` (client certificates) | `TestClientCertificateIdentity` | A listener requiring client certificates: `cert("cn")` in `when` routes one identity to its pool, `${cert:cn}`, `${cert:fingerprint}`, `${cert:xfcc}`, `${cert:subject}` and `${cert:serial}` reach the upstream and a client supplied header is overwritten |
| `internal/admin` (OIDC) | `TestOIDCLogin` | Against a fake provider: the auth methods document, the redirect with PKCE, nonce and scopes and a state cookie, the callback refused without the cookie and with a tampered state, an operator session from a mapped group with an action allowed, a viewer group, an unmapped group refused, and start-up refusal of an http issuer and of options without a role mapping |
| `internal/limits` (window) | `TestSlidingWindow` | Limit per window, independence of keys, the weighted estimate at a window edge admitting exactly the remainder, reset after two idle windows, peer reports counting as rate times window and expiring, eviction of idle window keys, flush and top |
| `internal/cluster` (exact) | `TestExactTake` | Two nodes learn each other's ids from the hello answer and agree on key owners; a Take for a key owned by the peer is decided by the peer's rate source and counted on both sides; a key owned locally is not asked; an unknown policy and a stopped owner fall back to a local decision within the timeout; `internal/config` `TestRateLimitAlgorithms` covers defaults and every rejected combination; `internal/proxy` `TestSlidingWindowRoute` refuses the fourth request of a three-per-minute window on a live server and reports the policy |
| `internal/upstream` (latency) | `TestLatencyEjection`, `TestHealthCheckBody` | Fast responses never eject; a slow endpoint is ejected once `latency_min_samples` is reached with its average reset and the ejection counted; `max_ejection_percent` holds for latency ejections; the relative rule ejects an endpoint three times slower than its pool and spares one at the average; failures and zero latencies record no sample. Probes against a live server flip health with `body_contains` and `body_regex` as the body changes; `internal/proxy` `TestRouteLatencyHistogram` checks the per route histogram in the exposition (with the tenant label) and the p50/p99 estimates in the quota report |
| `internal/expr` | `TestEval`, `TestParseErrors`, `TestNilEnv`, `TestEscapes` | Operators and precedence, string and numeric comparison, lists, `cidr` sets with prefixes and single addresses, `matches`, every function, captures, time variables, truthiness of strings and booleans; every syntax and static error with its message; a nil environment; string escapes |
| `internal/router` (when) | `TestWhen` | An expression selects among routes on the same path, two conditions beat one, a false expression falls through to a shorter path, a nil environment fails expressions; `internal/config` `TestWhenConfig` accepts valid expressions on routes and header blocks and reports unknown variables, functions, patterns and capture groups with the key path; `internal/proxy` `TestWhenRoutingAndHeaders` routes by header, address and method through a live server and gates request and response header operations by query, path and cookie |
| `cmd/xproxyctl` (table) | `TestCommandTable` | The command table (usage, help, completion) and the dispatch agree, summaries carry no colon, and the bash and zsh scripts parse when the shells are installed |
| `internal/upstream` | `TestGRPCHealthEncoding`, `TestRoundRobin`, `TestWeighted`, `TestLeastConn`, `TestHashRing`, `TestAffinity`, `TestOutlierEjection`, `TestActiveHealthCheck`, `TestBreaker`, `TestGate`, `TestCanary` | Balancer semantics including smooth weighting and minimal key movement on the ring; cookie tamper and expiry; ejection percentage; health state transitions against a real HTTP server; the breaker's state machine with a fake clock (reset on success, open at the threshold, refusal with the remaining time, one trial at a time, reopen with a doubled back-off, close and reset on a good trial, stale outcomes ignored); the gate's slot, bounded queue, timeout, immediate refusal, cancellation and release; canary classification by header, cookie and values, exclusive selection per side, fallback both ways and off, a percentage split, inert flags without a policy |
| `internal/logging` | `TestAccessTextFormats`, `TestOpenAndWrite`, `TestRotate`, `TestRedactor`, `TestRedactionInStreams`, `TestJournaldSink`, `TestSyslogUDP`, `TestSyslogTCPFramingAndTLS`, `TestSyslogUnixAndDrops`, `TestMultiSink` | A combined line matched against the NCSA shape with an identity from `oidc_sub`, quotes and newlines escaped, `-` for zero bytes and missing fields, a custom template with derived fields, template validation; JSON single line, level filter, file mode, injection safety, rotation chain; every redaction rule including stable keyed pseudonyms across instances and IPv4/IPv6 truncation; redaction applied per stream with audit untouched; native journald datagrams parsed back (priority, identifier, indexed fields, binary multi-line values, key sanitising); RFC 5424 over UDP, RFC 3164 with octet counting over TCP and TLS with a pinned CA, Unix datagram; an unreachable collector never blocks and drops are counted; one stream to file and syslog with redaction on both |
| `internal/mgmt` | `TestManagementAPI`, `TestBanAPI`, `TestMetricsEndpoints`, `TestMetricsListener` | Socket mode, status, actions, error propagation, 501 for missing actions, in-use socket refusal, `/v1/waf`, `/v1/waf/exclusions` and `/v1/waf/reset` without a WAF, `/v1/sandbox` 404 without the action; ban list, add, refuse loopback and bad durations, remove, counters; `/metrics` and `/v1/series` on the socket with bad parameters rejected; TCP metrics listener with an allow list refusing the caller, mutual TLS refusing clients without a certificate and serving one with, no management paths exposed, disabled listener as a no-op |
| `internal/ban` | `TestTriggerAndEscalation`, `TestWindowReset`, `TestExemptAndManual`, `TestBound`, `TestPersistence`, `TestReconfigure`, `TestAggregates`, `TestFingerprintPersistence` | Network aggregates needing several sources, IPv4 and IPv6 network bans, exempt networks spared, fingerprint aggregates ignoring plaintext clients, fingerprint lookups sparing exempt addresses, entries and statistics across kinds, manual and malformed fingerprint targets, expiry, peer fingerprint bans and unbans, fingerprint bans persisted; trigger thresholds and reason filters, escalation and cap with a fake clock, window reset, exemptions, refusal of loopback and wide prefixes, CIDR bans, IPv4 mapped lookups, table bound, bbolt round trip including expiry and unban, reconfiguration keeps state |
| `internal/cluster` | `TestTwoNodes`, `TestEvents`, `TestRejectsUnauthenticated`, `TestProtocolErrors` | Bans and unbans propagate, sources are rewritten, rates arrive as rates, late joiner gets a snapshot, peer removal on reconfigure, status; events reach the peer with their sender, invalid events (no kind, no key, expired) are dropped, lifetimes are clamped, counters, `share_events: false` silences the channel; connections without a certificate, with a foreign CA or outside `allowed_names` are rejected and counted; bad JSON, messages before hello, wrong version and oversized lines close the connection, an unknown type is skipped and counted, a valid session is applied |
| `internal/jwt` | `TestVerifyAlgorithms`, `TestVerifyRejections`, `TestHMAC`, `TestJWKSURLAndRotation`, `TestJWKSParsing`, `TestFilter`, `TestClaimString` | RS256, PS256, ES256 and EdDSA accepted with and without key ids; expiry, skew, `nbf`, issuer, audience (string and list), missing and required claims, `alg: none`, disallowed algorithms, HMAC against an asymmetric provider, unknown key, wrong key, algorithm and key type mismatch, tampered payload, malformed and oversized tokens; HMAC secret handling; JWKS over HTTPS with a pinned CA, rotation through on-demand refresh, rate limiting of refreshes, unpinned CA fails closed; malformed and symmetric keys skipped when parsing; filter behaviour for missing, optional, valid, invalid tokens, header spoof removal, cookie and header sources with stripping |
| `internal/tui` | `TestRenderAllViewsFit`, `TestRenderContent`, `TestHelpers`, `TestKeys`, `TestRunRequiresTerminal` | Every screen renders to exactly the terminal height and within its width at three sizes with and without colour; expected content per screen including selection, errors and prompts; ANSI-aware width and clipping; key handling for navigation, interval, pause, ban prompt with editing, unban confirmation and API errors, escape; refusal to run without a terminal; the routes, WAF and TLS screens, pool lines under upstreams, the sandbox, telemetry and dns overview lines, every screen with empty data |
| `internal/admin` | `TestPasswordHashing`, `TestUsersFile`, `TestOptionsPolicy`, `TestAuthAndRoles`, `TestLoginLockout`, `TestExtendedViews`, `TestLogs`, `TestSplitProblems` | Hash format and verification including malformed hashes; users file round trip, mode, bad roles and names; listener policy (loopback and Unix allowed, non-loopback needs mutual TLS); against a fake management socket: anonymous 401, security headers, login without the CSRF header refused, wrong password, unknown and certificate-only users, viewer can read but not act, cookie attributes, logout, operator actions forwarded (reload, ban with the audit prefix, unban, restart command), cross-origin and cross-site fetch metadata refused, series parameter validation, configuration file read, validate with problems, invalid save refused without touching the file, stale entity tag 409, atomic save with backup and preserved mode, idle expiry; five failures lock the source out; log tail and server-sent event follow; the 1.3 pass-throughs reach a viewer unchanged, the SecLang download is text, WAF reset and rollback need the operator role, the rollback carries its id, the dry run returns the change set without reloading |
| `internal/netutil` (SNI, QUIC) | `TestClientHelloSNI`, `TestQUICInitial` | A real client hello parsed for its name (case folded), every truncation rejected without panic, non-TLS bytes and corrupt lengths refused, a hello without SNI; a real quic-go first flight decrypted and its ClientHello reassembled across two datagrams, a tampered packet refused, non-QUIC bytes and another version refused, truncations, gaps and out of order frames, the reassembly bound, varints |
| `internal/cache` | `TestStoreAndBounds`, `TestVary`, `TestHelpers` | Store and hit, expiry, per object and total bounds with LRU eviction order, purge by host and prefix, resize; Vary variants; Cache-Control parsing, Vary names, storable headers |
| `internal/tlsconf` (fingerprints) | `TestFingerprint` | JA3 and JA4 from a ClientHello: format, GREASE ignored, cipher order changes JA3 but not JA4, QUIC marker, minimal hello, bounded table with eviction and delete |
| `internal/filters/botscore` | `TestSignals`, `TestBehaviour`, `TestDeviceSignals`, `TestValidateOptions` | Each signal and its weight, header forwarding, challenge versus deny thresholds, verified clients not challenged, JA4 allow and deny lists; behaviour window with error rate, regular timing, rate and path spread, reset after the window, bursts not regular; a device seen from three addresses scoring device_shared, automation markers weighing 45 and denying together with a bot user agent, device windows resetting, empty devices untracked, the device in the attributes; option validation |
| `internal/geoip` | `TestMMDB`, `TestCSVAndDB`, `TestCacheBound` | The MMDB reader against files built by a writer of the real format: exact and longest prefix matches, IPv4 under the IPv6 tree, mapped addresses, record decoding, truncated and garbage files rejected; CSV parsing with header, quotes and comments, bad codes and empty tables refused; the cache bound |
| `internal/filter`, `internal/filters/*` | `TestRegistry`, `TestOptionsDecode`, `TestGuard`, `TestValidate`, `TestBasicAuth`, `TestBasicAuthValidate` | Kind registration and rejection of bad names and duplicates; options decoding with nested maps, unknown keys refused; header guard require and deny rules with status and detail, invalid patterns, header names, statuses and keys refused; basic authentication challenge headers, wrong password, unknown user, header stripping and forwarding, access log attribute, credential cache, users file validation (missing, world readable, malformed hash) |
| `internal/icap` | `TestOptionsAndReqmod`, `TestRespmodAndErrors`, `TestUnreachable`, `TestHeaderBlocks` | Against a fake ICAP server (`icaptest`): OPTIONS parsing, preview then `100 Continue` then `204`, block on preview with the encapsulated page, small and empty bodies, modified request, connection reuse, RESPMOD clean, blocked and rewritten, server error and timeout counted with recovery, unreachable service, header block rendering without hop-by-hop or injected headers |
| `internal/metrics` | `TestOTLPExporter`, `TestEncoder`, `TestHistogram`, `TestSeriesAndSampler` | OTLP/JSON push against a fake collector: gzip, headers, resource attributes, sums with attributes and start time, gauges, histogram bucket counts with the overflow bucket, status, the interval loop, a failing collector counted, a final push on stop, a missing CA refused; Text format with escaping and sorted labels, histogram buckets, sum and count; atomic histogram bucketing; ring buffer order, retention, since and limit, per-second rates from counters, counter reset handling, start and stop |
| `internal/shed` | `TestInflightLevel`, `TestLatencyLevelAndDrain`, `TestReconfigureKeepsSamples` | Class thresholds against the in-flight ratio, hysteresis, latency level from windowed samples, drain after an idle window, reconfiguration |
| `internal/challenge` | `TestFlow`, `TestVerifyInputs`, `TestPersistentKey`, `TestKeyRotation`, `TestProofDefinition`, `TestScriptSHA256MatchesGo`, `TestTiersAndDevice`, `TestCaptcha` | Page and headers, proof verification, wrong proof and wrong address refused, replay refused, cookie bound to address, expiry and tampering, exemptions, method and input validation, expired nonces, open redirect neutralised, key persistence and rotation, proof definition and form fields shared with the script; proof, captcha, legacy and device-less cookies read back with their tier and device, a forged tier refused, device parsing, the posted device landing in the cookie, devices off; against a fake provider: escalation and always modes, widget, script and policy origins per provider, rejected token, low score, unreachable provider, a pass with the secret, token and address sent, nonce single use, proofs alongside, statistics, missing and empty secrets, hostname binding refusing a token solved for another host, an allowlist overriding the request host and the check turned off |
| `internal/waf` | `TestBlockSQLi`, `TestDetectMode`, `TestCleanRequestPasses`, `TestBodyInspectionAndReplay`, `TestBodyLimitReject`, `TestResponseInspection`, `TestCustomDirectivesAndBadRules`, `TestOnlyNeededModesCompiled`, `TestRuleStatistics`, `TestLearningProposals`, `TestLearningTableBound`, `TestQuoteTarget`, `TestCRSDirectory`, `TestCRSDirectoryErrors`, `TestProfilesWithoutCRS`, `TestCRSPlugins`, `TestJSONSchemaBlock`, `TestJSONSchemaRequired`, `TestAnomalyDetection`, `TestAnomalyTrackerBound` | CRS blocks injection in query and body, detect mode logs without denying, clean traffic produces no attributes, inspected bodies are replayed intact, 413 above the body limit, response leakage blocked and clean or oversize responses pass intact, custom SecLang rules, compile errors surface, lazy compilation per mode; per rule counters with severity, tags, ordering, top bound and reset; learning proposals below and at `min_hits` with clients, path scoping, unique ids and a global form, the rendered file, and the proposed directives compiled into a new engine stop the same request without leaking outside the path; the entry bound and dropped count; target quoting; a copy of the embedded CRS loaded from a directory blocks injection, reports its source and version, picks up an added rule file and a preferred `crs-setup.conf`, fails on a broken file; missing, file, no setup and no rules directories refused; profiles without the CRS report and learn from custom rules; plugins as loose files and as a checked out repository with a before rule reading a data file and an after rule, selection by name, a missing name and an empty directory refused; JSON body schemas: a valid body replayed, a violation denied with a problem body and attributes, malformed JSON, 413 over the limit, other paths, methods and media types untouched, detect mode logging, the violation counter, `required` refusing a missing body and a wrong media type, a missing schema file; anomaly detection over synthetic windows: baseline built from normal clients, a scanner flagged with its feature and score, block, challenge and log actions, flag expiry, reset and the disabled report; the tracker bound with dropped clients counted |

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
| `TestQUICPassthrough` | A quic-go echo server behind a `kind: tcp` listener with `quic: true`: streams echo end to end with the origin's certificate verified by the client, flow counters, an unknown name never reaches an endpoint and is counted, the flow ends after the idle timeout with bytes accounted |
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
| `cmd/xproxyctl` `TestCommands`, `TestOptionalSubsystems`, `TestUnreachableSocket`, `TestHtpasswd`, `TestSandboxSummary` | Every command run against a live management server on a temporary socket: version, validate, status (text, JSON, sandbox summary), stats, upstreams, quotas, waf and its sub commands, sandbox (table, rules, JSON), tls, telemetry, config, reload and dry run, diff (exit 0 when equal), history and rollback without a history, certificate reload, log reopen, ban list, add, refuse loopback, remove, cluster and ACME unconfigured, metrics, series, filters, spki of a generated certificate, usage errors, tui without a terminal, unknown command; optional subsystems fail cleanly; an unreachable socket; the users file helper appends, replaces and refuses short passwords |
| `internal/config` `TestExampleDumpGolden` | The dump of the shipped example with every default filled in matches `testdata/example.dump.yaml` and is a fixed point (dumping the loaded dump gives the same text), so a changed default shows up in review |
| `internal/config` `TestDocsYAMLSyntax` | Every fenced `yaml` block of README, USAGE, CONFIG, EXTENDING, SETUP, SETUP_MACOS and HARDENING is decoded strictly against the configuration schema (unknown keys at any depth fail), complete documents are validated without file checks, list fragments and non configuration blocks are skipped and counted; a documentation example that drifts from the schema fails the build |
| `test/bypass` `TestWAFEvasions`, `TestProtocolAndLimits`, `TestAccessControls`, `TestPositiveModelAndPatches`, `TestRateLimitAndBans`, `TestHoneypotMarks`, `TestUploadDisguises`, `TestSensitiveExfil`, `TestAccountBruteForce`, `TestOpenAPIPositiveModel` | The adversarial harness: injection payloads (SQLi, XSS, traversal, command, inclusion, NUL, fullwidth Unicode) through query, path, form, JSON, multipart, cookie, user agent, referer, chunked and content-type-disguised channels, each refused before the backend, with the path-injection gap at paranoia level 1 asserted as documented; request smuggling and framing (CL+TE resolved to chunked, bare LF canonicalised, two content lengths, space before colon, missing and duplicate host, bare LF, NUL and CR in the target, over-limit URI, headers and body); deny and allow CIDR routes with spoofed forwarded addresses, the header guard's case folding, the API key filter with no, wrong, empty and misplaced keys and the stripped forwarded id, the challenge gate against a forged cookie; the positive route policy (undeclared, mistyped, over-long, repeated and too many parameters, disallowed method) and a virtual patch; rate limit enforcement, a network aggregate ban over a spread source, a WAF repeat ban and a honeypot probe ban; upload disguises (executables and server code behind names, double extensions and declared types); a card number blocked leaving in a response and in request bodies; credential stuffing on one pair and across accounts; and the OpenAPI positive model (undocumented path and method, out-of-range and undeclared parameters, missing body, wrong content type), each with a clean control request served |
| `test/examples` `TestYAMLDocuments`, `TestWAFExclusions`, `TestWAFCustomRules`, `TestWAFPluginAndSchema`, `TestDNSBlockList`, `TestHeaderPolicy`, `TestBadBots`, `TestBodyRewrite`, `TestWasmPolicy` | Every document under `examples/` parses (fragments through a main file that includes them); the exclusion file compiles with the CRS and lets the excluded field through while the same payload elsewhere is blocked and uploads skip body inspection; the custom rules deny the debug header, the virtual patched path, an IP host header, a secret path probe and a non JSON API write while clean traffic passes; the example plugin denies its listed agents and the order schema refuses an invalid order while a valid one passes; the block list loads every line form and matches names, wildcards and exact entries only as documented; the header policy, bad bot and body rewriting filters behave on sample requests and bodies; the WebAssembly policy module denies with its reason, adds its response header and its log attribute |
| `internal/proxy` `TestCompressionEncodings` | Brotli and zstd bodies decode to the origin's, quality values and the configured order decide between encodings, a wildcard accepts the preferred one, an offer restricted to gzip leaves a Brotli-only client uncompressed, `Vary` and `Content-Encoding` set, validation of encodings and levels |
| `internal/tmpl` `TestParseAndExpand`, `TestParseErrors`, `TestLenient` | Placeholders, arguments, numbered and named captures, escaped dollars, missing values, static detection, strict rejection of unknown names, lenient parsing that keeps unknown sequences |
| `internal/proxy` `TestRegexRewriteAndTemplates`, `TestRewriteConfigRejects` | A regex rewrite with numbered and named groups reaching the backend, non matching paths unchanged, templated request headers (client address, capture, header lookup, escaped dollar, removal) and response headers (route, scheme, query parameter), a redirect built from variables, server level 404 page in HTML and JSON with the request id and a literal script placeholder, HEAD without a body, a route level 403 page with the denial reason and JSON off, an upstream 503 body replaced with corrected length and type; validation of bad patterns, replacements, unknown variables, exclusive rewrites, page keys, relative names without a directory, empty sections and intercept ranges |
| `internal/upstream` `TestDiscoveryDNS`, `TestDiscoverySRV`, `TestSlowStart` | A and AAAA discovery adds endpoints next to static ones, a change keeps the surviving endpoint object and counters and removes the gone one, failures keep the set and are counted, picks reach discovered endpoints; SRV uses the lowest priority group with record weights and the hash ring is rebuilt on change; the slow start ramp from 10 % to full over its window, round robin admission with a deterministic coin, a lone ramping endpoint never refused, effective weights, ramp scheduled from the end of an ejection, status and stats fields |
| `internal/bound` `TestNoticeThrottles`, `TestNoticeDefaults` | A notice warns once per interval with the occurrences since the previous warning and the total, and counts correctly under concurrency |
| `internal/apiinv` `TestInventory`, `TestSkeleton`; `internal/proxy` `TestAPIInventoryIntegration` | An OpenAPI skeleton from a report: named parameters from variable segments, methods merged across hosts with summed evidence, response classes and media types, request bodies, security schemes and servers, YAML round trip, empty reports, parameter naming; observations folded into endpoints with status classes, credentials and versions, a shadow endpoint, a documented operation never called reported as a zombie, an undescribed route neither, a superseded v1 next to v2, the shadow, zombie, versions, undocumented and top views, stale documented endpoints becoming zombies, save and load with the start time, the endpoint bound with drops, a disabled table; through the proxy with an `openapi` route: documented endpoints with the description's template and two credential kinds, an undocumented path and a v2 as shadow, a plain route neither, a respond route excluded, two zombies, the state file written at shutdown and restored |
| `internal/originsig` `TestSignAndVerify`; `internal/proxy` `TestOriginSignature` | Sign and verify with an included header, the previous key of a ring verifying its signatures, expiry, tampered path, client, header and method, an unknown key, a missing and a malformed header, a short key refused, key ids; through the proxy: the key file created, a forged client header replaced and the origin verifying, a direct request to the origin refused, a rotated key verified with the ring |
| `internal/proxy` `TestWAFGradualEnforcement` | A test mode route enforcing only the canary prefix, full enforcement, a 50 % route blocking a stable share of 200 clients with each client seeing one behaviour, the report's share and prefixes per route, block and detect counters both advancing, the split function at 30, 0 and 100 %, invalid share and prefix settings refused |
| `internal/filters/accountguard` `TestLoginLadder`, `TestCredentialStuffing`, `TestDistributedCampaign`, `TestRegisterResetScrape`, `TestIdentityAndBodies`, `TestDelaySlots`, `TestCaptchaAction`, `TestValidateOptions`, `TestStatusAndCounters`, `TestDeviceAndAutomation`; `test/examples` `TestAccountGuard` | The login ladder from delay through challenge to a published pair block, verified clients passing the challenge step, blocked requests, other accounts unaffected, expiry, hashed and case folded identities absent from the log, body failures and success resets; many accounts from one address and one account from many addresses; a campaign under per address thresholds challenging fresh addresses, expiring, and peer block and campaign events applied while foreign ones are ignored; disposable domains including subdomains and operator additions, repeat registrations, query identities, path spread scraping on a prefix, method mismatch, header identities on a cart with log then block; JSON, form, oversize, foreign type, numeric and malformed bodies with the body replayed; delay slot exhaustion and cancelled contexts; rejected options, class defaults and matching; challenge and captcha steps against proof and captcha cookies with a campaign outranking a step; the status view with tracked keys, blocks, window totals and top bounds, process counters per class and action, a closed guard leaving the view; one device across rotating addresses and accounts reaching the device account threshold, clients without a device judged on other keys, a device block travelling to peers and holding from any address, automation markers forcing the CAPTCHA tier and counted, devices in the status; the example filters against a stuffing run |
| `internal/filters/sensitive` `TestDetectors`, `TestSensitiveFilter`, `TestCounters`, `TestEncodedBodies`, `TestOversizeStreams`; `test/examples` `TestSensitiveData` | Every built-in detector on valid and invalid samples (Luhn, personnummer dates, coordination numbers and checksums, IBAN mod 97, SSN ranges, JWT headers, key formats); the filter in log, mask and block mode on query strings, credential parameter names, headers with the ignore list, request and response bodies, unlisted and encoded bodies passing unscanned, masking with content length updated, minimum findings, custom detectors and rejected options; findings per kind and message outcomes per direction counted; gzip, deflate, brotli and zstd bodies masked (forwarded decoded), logged (forwarded as they were) and blocked, `encoded: skip`, unknown encodings, ranges and corrupt data untouched, a body decoding past the bound streamed decoded; oversize bodies streamed in log mode with the finding recorded, masked across a one byte reader, cut with ErrBlocked in block mode, skipped on request, unknown lengths buffered then streamed, rejected options; the example filters log a request, mask a response and block a card export |
| `internal/filters/uploadguard` `TestUploadGuard`, `TestUploadGuardModes`, `TestHelpers`; `test/examples` `TestUploadGuard` | Multipart uploads: images and documents pass with plain fields, too many files, an unlisted field, denied, unlisted and missing extensions, a hidden and an odd double extension, version dots passing, traversal and control characters in names, a PE, a shell script and PHP code behind image names, magic and declared type mismatches, Office containers as zip, a file over its limit, the body replayed with attributes, a request over the total limit, non multipart bodies untouched; defaults with the built-in deny list, an explicit allow overriding it, last-extension mode, strict and disabled sniffing, raw uploads named from the path and from the disposition, rejected options; extension chains, detection, declared type matching, executable detection; the example filters against uploads |
| `internal/proxy` `TestMaintenanceMode` | Config-enabled maintenance holding an ordinary client with 503 and Retry-After, serving the allowlisted network, the bypass header and an exempt route, and the runtime toggle off and on |
| `internal/proxy` `TestRouteTimeouts` | A route idle timeout cutting a stalled streaming response early, and a total timeout bounding a slow exchange |
| `internal/proxy` `TestCORS`, `TestCORSPatternUnit` | Preflight answered 204 with the headers and no backend hit for exact and wildcard origins, a disallowed origin left without the allow header, an actual request carrying the headers and reaching the backend, the any-origin route echoing `*`, a no-origin request untouched; the wildcard host matcher across labels, scheme and suffix tricks |
| `internal/proxy` `TestIdentityRateLimit`, `TestIdentityRateLimitJWT`; `internal/filter` `TestIdentitySet` | Two API keys and two JWT subjects each get their own bucket while the raw header cannot be rotated to escape it, an unauthenticated request refused by the filter before the limiter; the identity set records, overwrites and prefers kinds and is safe on a nil receiver |
| `internal/proxy` `TestNormalizationGuard`, `TestNormalizationDefaults`, `TestCheckNormalizationUnit` | Raw requests through a listener: encoded UTF-8 passes, double encoding, encoded slash and backslash, literal backslash, NUL, CR LF, a control character in the query, overlong and invalid UTF-8 refused with 400 and counted, two content lengths and an odd transfer coding refused, Unicode folding off leaving fullwidth and decomposed spellings unrouted, `nfc` folding decomposed but not compatibility forms, `nfkc` folding fullwidth with the upstream receiving the original path; the defaults refusing NUL and invalid UTF-8 while admitting double encoding and encoded slashes; every check and the relaxed settings against crafted requests |
| `internal/proxy` `TestRateLimitKeys`, `TestBearerClaim`; `internal/netutil` `TestPathTemplate` | Buckets per cookie with the address fallback, per /16 and /48 network, per endpoint template across identifiers with other endpoints and methods separate, per bearer claim without verification with garbage falling back, JA4 on plaintext falling back; claim extraction from string, number and boolean claims and refusals; path templates for numbers, UUIDs, hashes, opaque tokens, file names and version segments |
| `internal/proxy` `TestRoutePolicy`, `TestVirtualPatches`, `TestPolicyHelpers`; `internal/config` `TestPolicyAndPatchValidation` | A route policy admitting a documented request and refusing method (405 with `Allow`), media type, missing content type, missing required, unknown, mistyped, out of enum, overlong, pattern, repeated, non uuid, bool and number parameters, query bytes, URI length, header count and header bytes, with a policy free route untouched and the counter advanced; virtual patches by path plus parameter plus method, header pattern on wildcard hosts, body pattern on a route and media type with the body replayed, log, expired and disabled patches passing, status flags, hits kept across a reload; host, media type and uuid helpers; defaults and every validation branch of policies and patches |
| `internal/fleet` `TestBundleReadValidateWrite`, `TestAgentAppliesAndReports`, `TestAgentApplyOffAndUnassigned`, `TestControllerAuthorisation`, `TestAdminHandlerAndValidateDir`, `TestAgentConstruction` | Bundles read from common and node directories with overrides and hidden files skipped, order independent content digests, validation of configuration, traversal, missing configuration and digest mismatch, path rules, writes with modes and a restore that removes new files and leaves unrelated ones, a symlink escape refused; against a mutual TLS controller: first apply with files and marker, status report with tags and certificate name persisted, a directory change applied through the long poll, an invalid bundle kept out of service with the error visible, a refused reload rolled back and reported, a restarted agent reading its marker; apply off reporting a pending digest, an unassigned node; another node's certificate refused for fetch and report, ETag and 304 long poll, bad ids, mismatching reports, anonymous clients, `-any-name`; the operator handler, `ValidateDir` and restored reports; agent construction errors |
| `cmd/xproxy-fleet` `TestValidateAndUsage` | `validate` over a directory with a good and a broken node, exit codes, usage errors, `version`, `serve` without certificates, a query without a controller |
| `test/observability` `TestDashboards`, `TestAlertRules` | The shipped Grafana dashboards parse, declare the Prometheus data source input and the instance variable, have unique panel ids inside the grid, and every query names only metric families the exporter source defines and filters on the instance variable; the alert rules have three groups, unique `Xproxy*` names, a page or warn severity, summary and description, balanced expressions, known metric families and the expected core rules |
| `internal/logging` `TestCEFAndLEEF`, `TestSIEMSinkFormats`, `TestSIEMSinkFailuresAndStatus`, `TestSyslogCEF` | CEF and LEEF renderings of access, security, audit and error records: headers, severities, event ids, standard and labelled custom keys, user and endpoint extraction, escaping of pipes, equals signs and line breaks; the HTTPS sink against a collector in every format with the content type, the authorization header from a file, extra headers, gzip on and off, the two exported streams and the counters; a 503 counted as failed and dropped with the last error in the status, a missing auth or CA file refused; CEF behind an RFC 5424 syslog header |
| `internal/waf` `TestStatsConcurrent`, `internal/limits` `TestOverflowCounted` | Eight goroutines through the WAF statistics under the race detector with exact totals and no drops; a full rate limit shard counts its fallback decisions |
| `internal/sandbox` `TestDerive`, `TestGlobBase`, `TestCheck`, `TestBeneathAny`, `TestSeccompProgram`, `TestItoa`, `TestApplyLinux`, `TestApplyDisabledAndStrict` | Landlock rules derived from a configuration (certificates, includes, rule sets, static roots, filter modules, databases read; socket, logs, state, history, ACME, extra paths write; directories only, sorted, no overlap, relative values ignored); glob bases; a candidate configuration checked against the rules (new file under an admitted directory passes, outside read and write under a read directory refused, nil status passes); the seccomp program interpreted in the test: every denied number returns EPERM, the runtime's calls are allowed, a foreign architecture and the x32 ABI are killed, the list is sorted and unique; a confined child process reports each mechanism's state and probes it (reads inside and outside the rules, writes to read-only paths, unshare and ptrace under the filter, dumpable, core limit, capability sets, no_new_privs, bind after start), with assertions conditional on what the kernel offers; disabled sandbox |
| `TestWAFReport` | `/v1/waf` view through the server: embedded profiles with version, route assignments, counters across block and detect routes, a learned proposal scoped to the route path from two clients, the exclusions text, statistics kept across a reload, reset, learning switched off at reload |
| `TestBanIntegration` | WAF denies trigger a ban that applies before routing, other clients unaffected, exempt range never banned, rate limit denies feed the catch-all trigger, manual CIDR ban and unban |
| `TestBanDropsConnectionAtAccept` | Accept hook sees bans; loopback refusal |
| `TestBansSurviveReload` | Reload keeps active bans; removing the section drops the list |
| `TestAdaptiveShedding` | A slow backend raises the level to 1; low, normal and high get 503 with `Retry-After` while critical is served; classes return once the window drains |
| `TestNetworkAggregateBan` | WAF denies spread over one /24: no ban from a single source, the network banned once a second address contributes, a fresh address in it refused, the neighbouring network served, the exempt network never banned, a fingerprint ban placed and lifted by hand |
| `TestCaptchaTier` | An account guard captcha step: the widget page with the provider's policy, a proof of work cookie refused for it, the provider token verified and the tiered cookie admitted, statistics, the `device` rate limit key from the cookie and its address fallback |
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
| `TestClusterSharesLimitsAndBans` | Two full servers peer over mTLS; a client's consumption on one node holds its bucket at zero on the other, other clients unaffected, recovery after reports go stale, ban propagation, a honeypot mark and its removal propagate with the peer route label, listen change refused on reload |
| `TestStaticFiles` | Index and typed assets with `ETag`, 304 on `If-None-Match`, ranges, directory redirect, 404 without index, dot files, `.git` directories, symbolic links to files and directories outside the root, encoded and plain traversal all 404, `dot_files` opt-in, 405 with `Allow`, HEAD, single page fallback with real assets still served, listings with hidden dot files and a parent link, `max_file_bytes`, counters, a vanished root failing the reload while the old generation serves |
| `TestCompression`, `TestWantsGzip` | A proxied JSON body compressed with its length dropped, ETag weakened and `Vary` added; a small body passed through with its length; a streamed body compressed whole; pre-encoded, `no-transform`, image, range and 204 responses untouched; every `Accept-Encoding` form (absent, other codings, `q=0`, wildcard refusal and acceptance); HEAD; per route opt-out; static and respond bodies through the same writer; counters; the parser on ten header forms |
| `internal/filters/bodyrewrite` `TestRewrite`, `TestValidateOptions` | Both directions rewritten with a literal rule, a bounded regex rule with groups and a key rename; lengths and validators updated; unlisted types, encoded bodies, oversize bodies of unknown length and bodiless requests untouched; no attributes when nothing changed; nine invalid option sets refused |
| `internal/dns` `TestDNSSECValidation`, `TestDNSSECHelpers` | A signed hierarchy generated in the test (root anchor, a zone with NSEC, an insecure delegation, an NSEC3 child): secure A, tampered signature and unsigned data in a signed zone bogus, NXDOMAIN and NODATA proofs by NSEC and NSEC3, an insecure delegation's data insecure, a wildcard answer with and without its proof, AD and SERVFAIL shaping, CD passthrough, counters and key cache, expired signatures; canonical ordering per RFC 4034, NSEC coverage, trust anchor formats, key tags, DO handling and record stripping, no chain and non answers |
| `internal/dns` `TestEncryptedListener`, `TestEncryptedDNSListener` (proxy) | One TLS port answers DoT with and without the `dot` ALPN, DoH over HTTP/2 POST and HTTP/1.1 GET on the configured path with cache headers, 404 elsewhere, 405 with `Allow`, 415 for a wrong content type, per transport counters; a full proxy with a plain and an encrypted dns listener answering a sinkhole over DoT and DoH, status and certificate listing |
| `internal/tracing` `TestTraceparent`, `TestExport` | Continuing an incoming context with a fresh span id and the tracestate, malformed and all-zero contexts starting new traces, sampling at 0, 50 and 100 percent, the incoming flag honoured only with trust, nil safety; an export to a fake collector with headers, resource attributes, parent links, kinds, statuses and typed attributes, idempotent finish, failure counting and flush on stop |
| `internal/logging` `TestOTLPSink` | Access and security streams reach a fake collector as log records with severity, body, typed attributes, the stream and the trace and span ids; a stream without the sink is not exported |
| `TestTracingPropagation` (proxy) | A new trace reaches the upstream as `traceparent`, an incoming one is continued with our span as parent and its tracestate, the client's sampled flag is not trusted, propagation off strips the header, removing the section on reload stops tracing |
| `internal/tlsconf` `TestOCSPStapling`, `TestCertificateTransparency` | Against a fake responder signed by the test CA: no staple before start, a good response stapled on a copy of the certificate, parsed back, kept through a responder failure with the error recorded, a revoked answer stapled, a certificate without a responder reported; SCTs signed by a test log over the rebuilt precertificate TBS verify, an unknown log, a missing issuer and a tampered signature do not, the require policy with and without a log list, enforce failing the load and warnings otherwise, malformed extensions and empty log lists |
| `internal/secret` `TestKeyring` | Create with mode `0600`, stable reload, rotation prepending a key and keeping the bound, raw key files loading and converting, short keys, malformed lines, empty rings, missing files, the keep bound, ephemeral rings |
| `TestKeyRotation` (challenge), `TestAffinityRotation` (upstream), `TestSealAcrossRotation` (oidc) | Cookies and sessions issued before a rotation verify or open after it, a later rotation that drops the key refuses them, the primary changes, purpose binding holds |
| `internal/config` `TestDiff`, `TestUnifiedDiff`, `TestHistory` | Item level changes across listeners, upstreams, routes, rate limits and whole sections with their kinds, summaries and the restart list, the text diff shape, a dump that clears includes and loads; the line differ's hunks and truncation; history recording with modes, pruning to the keep count, foreign files ignored, loading by id with path traversal refused, nil and unconfigured behaviour |
| `TestQuotas` | Routes with tenant labels: per route status classes, bytes, rate limit denials, tenant aggregation, the policy's decisions and top consumer with tokens left, upstream share, and the tenant label and byte counters in the metrics exposition |
| `TestCanaryRouting` | Plain requests stay on the stable endpoint, a header or cookie selects the canary, a different value does not, pool and endpoint counters, fallback to the stable endpoint when the canary is down |
| `TestCircuitBreaker`, `TestUpstreamQueue` | Two upstream 503s open the circuit, the third request is refused locally with `Retry-After`, status and counters, a trial after `open_for` closes it and traffic flows; a pool with one slot and a one deep queue: the second request waits and times out, the third is refused at once, the first completes, queue status and counters |
| `TestRetryOnStatus` | A round robin pool with one endpoint answering 503: every GET succeeds through the retry, the failing endpoint is tried, counters; POSTs are not replayed; without `retry_on` the 503 reaches the client; an exhausted budget returns the last response with its body and headers |
| `TestRoutingByRegexAndHeaders` | Header exact match, cookie presence, an anchored path pattern with `strip_prefix`, a failing pattern falling back to the prefix route, cleaned paths |
| `TestProxyProtocolInbound`, `TestProxyProtocolUntrustedPeer` | An `http` listener with `proxy_protocol` behind a trusted peer: v2 and v1 headers set the client address seen by the upstream and by `deny_cidrs`, `LOCAL` keeps the balancer, a trusted peer without a header is dropped without reaching the upstream and counted; from an untrusted peer the header is not parsed and a plain request works |

### Fuzz targets

| Target | Input | Property |
|--------|-------|----------|
| `config.FuzzParse` | arbitrary bytes | never panics; nil config implies error |
| `router.FuzzMatch` | host, path, method | never panics on any strings |
| `netutil.FuzzCleanPath` | path | output always starts with `/` |
| `netutil.FuzzHost` | host header | never panics |
| `netutil.FuzzReadProxyHeader` | bytes | never panics; a parsed header is version 1 or 2 and, unless LOCAL, carries two addresses of one family |
| `logging.FuzzParseTemplate` | access log template | `ParseTemplate` and `ValidTemplate` agree; a non empty valid template yields tokens |
| `dns.FuzzParseMessage` | wire message | never panics (compression loops included); record counts equal the header counts; the question end lies inside the message; names at most 253 bytes |
| `dns.FuzzParseTrustAnchor` | DS or DNSKEY line | never panics; a parsed anchor names a zone |
| `config.FuzzUnifiedDiff` | two texts | never panics; changed exactly when the line sequences differ; every hunk line comes from an input |

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
procedures and, for `xproxyctl`, by its own end to end tests), the test
fakes (`acmetest`, `icaptest`, `filtertest`, `testutil`), `version`, the
`filters` registration list, `paths` (constants only) and `sandbox`,
whose Landlock, seccomp and capability code runs in a confined child
process that the parent's profile cannot observe (the child's probes
assert the effects instead). CI fails on either rule (ASR-Q2).

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
| `internal/tui` | 65 % (the terminal loop itself is covered by the pseudo terminal check) |
| `internal/sandbox` | 41 % in the parent process; the mechanisms run in the confined child (excluded from the gate) |
| `cmd/xproxyctl` | 59 % from its own tests (not part of the gate) |
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
