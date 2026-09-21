package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/rom/xproxy/internal/apiinv"
	"io"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/acme"
	"github.com/rom/xproxy/internal/cache"
	"github.com/rom/xproxy/internal/challenge"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/filters/accountguard"
	"github.com/rom/xproxy/internal/h3"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/originsig"
	"github.com/rom/xproxy/internal/otlp"
	"github.com/rom/xproxy/internal/securitytxt"
	"github.com/rom/xproxy/internal/tlsconf"
	"github.com/rom/xproxy/internal/tracing"
	"github.com/rom/xproxy/internal/upstream"
)

// listenerHandler is the http.Handler installed on one listener (and on
// its HTTP/3 endpoint when enabled).
type listenerHandler struct {
	srv *Server
	ln  *config.Listener
	h3  *h3.Server
}

// reqState is the per-request bookkeeping used for logging.
type reqState struct {
	id         string
	start      time.Time
	clientIP   netip.Addr
	host       string
	path       string
	route      string
	upstream   string
	endpoint   string
	attempts   int
	denied     string
	upErr      string
	extra      []any // filter attributes for the access log
	country    string
	ja4        string
	chalTier   int                // challenge cookie tier (challenge.TierNone without one)
	device     string             // device identifier from the challenge cookie
	identity   *filter.Identity   // verified identities from the filter chain
	cancel     context.CancelFunc // cancels the request (idle timeout)
	automation []string           // automation markers from the challenge cookie
	span       *tracing.Span      // server span, nil without tracing
	upSpan     *tracing.Span      // client span of the upstream exchange
	propagate  bool
	cache      string // hit, miss or bypass on a cached route
	encoding   string // gzip when the proxy compressed the response
	canary     bool   // the response came from a canary endpoint
	cacheKey   string
	marked     bool         // client previously hit a honeypot
	degraded   string       // the degradation level serving this request, if any
	pcapAsked  bool         // the capture hook ran for this request
	mirror     string       // sent, dropped or body_too_large on a mirrored route
	bodyDigest string       // set when the origin signature covers the body
	shadow     *shadowState // live response capture for mirror diffing, nil otherwise
	grpc       bool         // request is gRPC: errors are answered as gRPC statuses
	grpcWeb    bool         // request is gRPC-web: translated to gRPC for the upstream
	h3srv      *h3.Server   // the HTTP/3 endpoint the request arrived on, for WebTransport
	grpcCode   string       // grpc-status of the upstream response
	release    func()       // concurrency slot; idempotent
	// cr is the matched route; captures and captureNames hold the
	// route's regular expression match for templates.
	cr           *compiledRoute
	captures     []string
	captureNames []string
	// pcap is the packet capture bookkeeping, set only when a capture
	// rule wants this exchange.
	pcap *captureState
	// reason is the denial category for error pages.
	reason string
}

// filterDenied carries a response phase verdict through ReverseProxy's
// error path.
type filterDenied struct{ v filter.Verdict }

func (e *filterDenied) Error() string { return "filter denied: " + e.v.Reason }

func newRequestID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (h *listenerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s := h.srv
	rt := s.rt.Load()
	// The generation serving this request is torn down when its last
	// request ends, so it must know this one is running.
	rt.inFlight.Add(1)
	defer rt.inFlight.Add(-1)
	rw := &responseWriter{ResponseWriter: w}
	st := &reqState{id: newRequestID(), start: time.Now()}
	rw.st = st
	st.h3srv = h.h3
	st.clientIP = netutil.ClientIP(r, rt.trusted)
	if tr := s.tracer.Load(); tr != nil {
		st.span = tr.StartServer(r, r.Method)
		st.propagate = tr.Propagate()
	}
	s.stats.Requests.Add(1)
	var route *compiledRoute
	defer func() {
		if route != nil {
			route.observe(rw.Status(), st.denied != "", r.ContentLength, rw.bytes)
		}
	}()
	if r.ContentLength > 0 {
		s.stats.BytesIn.Add(uint64(r.ContentLength)) //nolint:gosec // guarded by > 0 above
	}
	defer s.logAccess(rw, r, st)
	defer func() { s.finishCapture(rw, r, st) }()

	// Never advertise ourselves.
	if s.cfg().Server.ServerHeader != "" {
		rw.Header().Set("Server", s.cfg().Server.ServerHeader)
	}
	rw.Header().Set("X-Request-Id", st.id)
	if h.h3 != nil && r.ProtoMajor < 3 && r.TLS != nil {
		h.h3.SetAltSvc(rw.Header())
	}

	release, ok := s.concurrency.Acquire()
	st.release = release
	if !ok {
		s.stats.DeniedConcurrency.Add(1)
		st.denied = "max_concurrent_requests"
		rw.Header().Set("Retry-After", "1")
		s.deny(rw, r, st, http.StatusServiceUnavailable, "concurrency")
		return
	}
	defer release()

	// The TLS fingerprint of the connection, for fingerprint bans, ban
	// triggers, filters and the access log.
	if r.TLS != nil {
		if fp, ok := s.fingerprints.Get(r.RemoteAddr); ok {
			st.ja4 = fp.JA4
		}
	}
	// Carry the fingerprint so a bind_ja4 challenge cookie's signature can
	// cover it (token binding).
	if st.ja4 != "" {
		r = r.WithContext(challenge.WithJA4(r.Context(), st.ja4))
	}
	if bl := s.bans.Load(); bl != nil && bl.BannedClient(st.clientIP, st.ja4) {
		s.stats.DeniedBan.Add(1)
		st.denied = "banned"
		s.deny(rw, r, st, http.StatusForbidden, "banned")
		return
	}

	// http-01 challenge responses come before any redirect or routing.
	if s.acme != nil && strings.HasPrefix(r.URL.Path, acme.HTTP01Path) {
		st.route = "_acme"
		if ka, ok := s.acme.HTTP01(strings.TrimPrefix(r.URL.Path, acme.HTTP01Path)); ok && r.Method == http.MethodGet {
			rw.Header().Set("Content-Type", "text/plain")
			rw.Header().Set("Cache-Control", "no-store")
			rw.WriteHeader(http.StatusOK)
			_, _ = rw.Write([]byte(ka))
			return
		}
		s.plainStatus(rw, r, http.StatusNotFound)
		return
	}

	if h.ln.RedirectToHTTPS {
		host := netutil.Host(r.Host)
		if host == "" {
			s.stats.DeniedBadHost.Add(1)
			s.deny(rw, r, st, http.StatusBadRequest, "bad_host")
			return
		}
		target := "https://" + strings.TrimSuffix(host, ":80") + r.URL.RequestURI()
		http.Redirect(rw, r, target, http.StatusPermanentRedirect)
		return
	}

	if len(r.RequestURI) > s.cfg().Server.Limits.MaxURILength {
		s.stats.DeniedURILength.Add(1)
		st.denied = "uri_too_long"
		s.deny(rw, r, st, http.StatusRequestURITooLong, "uri_length")
		return
	}

	norm := &rt.cfg.Server.Normalization
	if detail := checkNormalization(norm, r); detail != "" {
		s.stats.DeniedNormalization.Add(1)
		st.denied = "normalization:" + detail
		s.denyDetail(rw, r, st, http.StatusBadRequest, "normalization", detail)
		return
	}

	st.host = netutil.Host(r.Host)
	if st.host == "" && r.Host != "" {
		s.stats.DeniedBadHost.Add(1)
		st.denied = "bad_host"
		s.deny(rw, r, st, http.StatusBadRequest, "bad_host")
		return
	}
	folded := routingPath(norm, r.URL.Path)
	if foldIntroducesSyntax(r.URL.Path, folded) {
		s.stats.DeniedNormalization.Add(1)
		st.denied = "normalization:unicode_fold"
		s.denyDetail(rw, r, st, http.StatusBadRequest, "normalization", "unicode_fold")
		return
	}
	st.path = netutil.CleanPath(folded)
	st.grpcWeb = isGRPCWeb(r)
	st.grpc = isGRPC(r) || st.grpcWeb || isGRPCWebPreflight(r)

	// A planted credential, presented back to us. Checked before
	// routing, because a token read from a decoy can be sent anywhere,
	// and before the challenge and security.txt paths, because a
	// scanner replaying one is not a browser to be challenged.
	if rt.honeytokens != nil {
		if h, where := rt.honeytokens.check(r, st.path); h != nil {
			if s.honeytokenHit(rw, r, st, h, where) {
				return
			}
		}
	}

	// Reserved challenge paths, served on every host.
	if ch := s.challenger.Load(); ch != nil && strings.HasPrefix(st.path, "/.xproxy/") {
		switch st.path {
		case challenge.ScriptPath:
			st.route = "_challenge"
			ch.ServeScript(rw, r)
			return
		case challenge.VerifyPath:
			st.route = "_challenge"
			ok, reason := ch.Verify(rw, r, st.clientIP, r.TLS != nil)
			if !ok {
				st.denied = "challenge:" + reason
				s.logs.SecurityEvent(r.Context(), "challenge_failed", reason,
					"request_id", st.id, "client_ip", st.clientIP.String(), "user_agent", r.UserAgent(),
					"client_fault", challenge.ClientFault(reason))
				// Only the client's own mistakes feed the ban triggers; a
				// refusal the proxy caused (a full replay table) would
				// otherwise ban every client whose correct solve it just
				// refused.
				if bl := s.bans.Load(); bl != nil && challenge.ClientFault(reason) {
					bl.ObserveClient(st.clientIP, st.ja4, "challenge")
				}
			}
			return
		}
	}

	// A virtual security.txt, answered before routing so that a host
	// with no route of its own still has one. A request that matches no
	// entry falls through and is routed as usual, so an origin that
	// serves its own file keeps doing so.
	if st.path == securitytxt.Path || st.path == securitytxt.LegacyPath {
		if doc := rt.securityTxt.Match(st.host, st.clientIP, h.ln.Name); doc != nil {
			st.route = "_security_txt"
			st.extra = append(st.extra, "security_txt", doc.Name())
			s.stats.SecurityTxt.Add(1)
			doc.Serve(rw, r)
			return
		}
	}

	match := rt.router.MatchRequest(st.host, st.path, r.Method, st.grpc, r.Header, &tvars{r: r, st: st, rt: rt})
	if match == nil {
		s.stats.DeniedNoRoute.Add(1)
		st.denied = "no_route"
		s.deny(rw, r, st, http.StatusNotFound, "no_route")
		return
	}
	cr := rt.routes[match.Index]
	st.route = cr.cfg.Name
	st.cr = cr
	cr.captureFrom(st)
	route = cr
	if st.grpcWeb || isGRPCWebPreflight(r) {
		if cr.cfg.GRPC == nil || !cr.cfg.GRPC.Web {
			st.denied = "grpc_web"
			s.deny(rw, r, st, http.StatusUnsupportedMediaType, "grpc_web")
			return
		}
		if isGRPCWebPreflight(r) {
			s.grpcWebPreflight(rw, r, st, cr)
			return
		}
	}
	if isWebTransport(r) && !cr.cfg.WebTransport {
		st.denied = "webtransport"
		s.deny(rw, r, st, http.StatusForbidden, "webtransport")
		return
	}
	// A CORS preflight is answered before authentication, rate limits and
	// filters: it carries no credentials and must not be blocked by them.
	if cr.cors != nil && cr.cors.preflight(rw, r) {
		st.route = cr.cfg.Name
		return
	}
	// Maintenance mode: hold everything but the allowlist and exempt
	// routes while it is on.
	if m := rt.maintenance; m != nil && s.maintenance.Load() {
		on := true
		if cr.cfg.Maintenance != nil {
			on = *cr.cfg.Maintenance
		}
		if on && !m.exempt(st.clientIP, r) {
			s.stats.DeniedMaintenance.Add(1)
			st.denied = "maintenance"
			m.serve(rw, r)
			return
		}
	}

	// Virtual patches: known vulnerabilities blocked by request shape,
	// before anything else spends work on the request.
	for _, vp := range rt.patches {
		if !vp.active(st.start) || !vp.selects(r, st.host, st.path, cr.cfg.Name) {
			continue
		}
		if vp.bodyRE != nil && !vp.bodyMatches(r) {
			continue
		}
		vp.hits.Add(1)
		vp.lastHit.Store(st.start.UnixNano())
		if vp.cfg.Action == "log" {
			st.extra = append(st.extra, "virtual_patch", vp.cfg.ID)
			s.logs.SecurityEvent(r.Context(), "virtual_patch", vp.cfg.ID,
				"request_id", st.id, "client_ip", st.clientIP.String(), "method", r.Method,
				"host", r.Host, "path", r.URL.Path, "route", st.route, "action", "log", "user_agent", r.UserAgent())
			continue
		}
		s.stats.DeniedVirtualPatch.Add(1)
		st.denied = "virtual_patch:" + vp.cfg.ID
		st.extra = append(st.extra, "virtual_patch", vp.cfg.ID)
		s.denyDetail(rw, r, st, vp.cfg.Status, "virtual_patch", vp.cfg.ID)
		return
	}

	// Positive security model of the route.
	if cr.policy != nil {
		if res := cr.policy.check(r); res != nil {
			s.stats.DeniedPolicy.Add(1)
			cr.policyDenied.Add(1)
			st.denied = "policy:" + res.detail
			if res.status == http.StatusMethodNotAllowed {
				rw.Header().Set("Allow", cr.policy.allow)
			}
			s.denyDetail(rw, r, st, res.status, "policy", res.detail)
			return
		}
	}
	if cr.compress != nil && r.Method != http.MethodHead && !isUpgrade(r) && !isGRPC(r) &&
		(cr.compressAuth || !carriesCredentials(r)) {
		if enc := cr.compress.negotiate(r); enc != "" {
			cw := newCompressWriter(rw.ResponseWriter, cr.compress, enc)
			rw.ResponseWriter = cw
			defer func() {
				cw.Close()
				if cw.compress {
					st.encoding = enc
					s.stats.Compressed.Add(1)
					s.stats.CompressedRawBytes.Add(uint64(max(cw.raw, 0))) //nolint:gosec // non-negative
				}
			}()
		}
	}
	st.marked = s.marks.marked(st.clientIP, st.start)
	// A packet capture, when one is recording and a rule wants this
	// exchange. Asked here because the route is now known, and before
	// the body is read by anything that would consume it.
	s.beginCapture(r, st)

	// Country lookup and policy (after the address ACL, which is cheaper).
	if rt.geo != nil && rt.geoNeeded {
		if st.country == "" {
			st.country = rt.geo.Country(st.clientIP)
		}
	}
	if !cr.geoAllowed(st.country) {
		s.stats.DeniedGeo.Add(1)
		st.denied = "geo:" + st.country
		s.deny(rw, r, st, http.StatusForbidden, "geo")
		return
	}

	// Access control.
	if len(cr.deny) > 0 && netutil.Contains(cr.deny, st.clientIP) {
		s.stats.DeniedACL.Add(1)
		st.denied = "deny_cidrs"
		s.deny(rw, r, st, http.StatusForbidden, "acl_deny")
		return
	}
	if len(cr.allow) > 0 && !netutil.Contains(cr.allow, st.clientIP) {
		s.stats.DeniedACL.Add(1)
		st.denied = "allow_cidrs"
		s.deny(rw, r, st, http.StatusForbidden, "acl_allow")
		return
	}

	// The challenge cookie, read once: its tier gates routes and filter
	// verdicts, its device identifier feeds the log and rate limit keys.
	if ch := s.challenger.Load(); ch != nil {
		ck := ch.Inspect(r, st.clientIP)
		st.chalTier, st.device, st.automation = ck.Tier, ck.Device, ck.Automation
	}

	// Browser challenge gate: unverified clients get the page instead of
	// the route. In load mode only while the shedder reports pressure.
	if cr.challenge != nil {
		if ch := s.challenger.Load(); ch != nil && !ch.Exempt(st.clientIP) {
			active := cr.challenge.Mode == "always"
			if !active {
				if sh := s.shedder.Load(); sh != nil && sh.Level() >= cr.challenge.Level {
					active = true
				}
			}
			if active && st.chalTier < challenge.TierProof {
				s.stats.Challenged.Add(1)
				st.denied = "challenge"
				ch.Serve(rw, r, st.clientIP)
				return
			}
		}
	}

	// Adaptive load shedding by priority class.
	if sh := s.shedder.Load(); sh != nil {
		if ok, level := sh.Admit(cr.class); !ok {
			s.stats.Shed.Add(1)
			st.denied = "shed:" + cr.class.String()
			rw.Header().Set("Retry-After", strconv.Itoa(int(sh.RetryAfter().Seconds())))
			s.logs.Error.Debug("request shed", "request_id", st.id, "route", st.route, "class", cr.class.String(), "level", level)
			s.plainStatus(rw, r, http.StatusServiceUnavailable)
			return
		}
	}

	// Rate limits keyed on request data run before the filter chain.
	if s.applyRateLimits(rw, r, st, cr, cr.rateLimits, release) {
		return
	}

	// Body limit. The route may lower the global bound.
	limit := s.cfg().Server.Limits.MaxBodyBytes
	if cr.cfg.MaxBodyBytes != nil && *cr.cfg.MaxBodyBytes < limit {
		limit = *cr.cfg.MaxBodyBytes
	}
	if limit > 0 {
		if r.ContentLength > limit {
			s.stats.DeniedBodySize.Add(1)
			st.denied = "body_too_large"
			s.deny(rw, r, st, http.StatusRequestEntityTooLarge, "body_size")
			return
		}
		if r.Body != nil && r.Body != http.NoBody {
			r.Body = http.MaxBytesReader(rw, r.Body, limit)
		}
	}

	// Anything on this route that materialises the body charges the
	// process-wide budget for the life of the request. Each such feature
	// is bounded per request; the product was the real ceiling, and
	// max_connections_per_ip times max_body_bytes is gigabytes of heap
	// from one address at the defaults.
	if cr.buffersBody || rt.patchBuffersBody {
		want := r.ContentLength
		if want < 0 {
			want = limit // chunked: the worst case this route admits
		}
		if r.Body == nil || r.Body == http.NoBody {
			want = 0
		}
		rel, ok := s.bodyBudget.Reserve(want)
		if !ok {
			s.stats.DeniedBodyBudget.Add(1)
			st.denied = "body_budget"
			s.deny(rw, r, st, http.StatusServiceUnavailable, "body_budget")
			return
		}
		defer rel()
	}

	// Per-route filters. Instances live for the whole exchange.
	var instances filter.Instances
	if len(cr.filters) > 0 {
		info := &filter.Info{
			RequestID: st.id, ClientIP: st.clientIP, Route: cr.cfg.Name,
			Host: st.host, Path: st.path, Method: r.Method, TLS: r.TLS != nil, Country: st.country,
			HoneypotMarked: st.marked,
			TrustedPeer:    netutil.Contains(rt.trusted, netutil.RemoteAddr(r)),
		}
		if fp, ok := s.fingerprints.Get(r.RemoteAddr); ok && r.TLS != nil {
			info.JA3, info.JA4, info.ALPN = fp.JA3, fp.JA4, fp.ALPN
			st.ja4 = fp.JA4
		}
		if s.challenger.Load() != nil {
			info.ChallengeVerified = st.chalTier >= challenge.TierProof
			info.CaptchaVerified = st.chalTier >= challenge.TierCaptcha
			info.DeviceID = st.device
			info.Automation = st.automation
		}
		ctx, idSet := filter.WithIdentity(r.Context())
		r = r.WithContext(ctx)
		st.identity = idSet
		instances = cr.filters.Begin(r.Context(), info)
		defer func() { st.extra = append(st.extra, instances.End()...) }()
		if v := instances.Request(r); v.Deny {
			if v.Challenge {
				if ch := s.challenger.Load(); ch != nil && !ch.Exempt(st.clientIP) {
					// A CAPTCHA verdict needs the CAPTCHA tier when one is
					// configured; a proof of work cookie is not enough.
					required := challenge.TierProof
					if v.Captcha && ch.HasCaptcha() {
						required = challenge.TierCaptcha
					}
					if st.chalTier >= required {
						goto admitted
					}
					s.stats.Challenged.Add(1)
					st.denied = "challenge:" + v.Reason
					s.logs.SecurityEvent(r.Context(), "challenge", v.Reason, append([]any{
						"request_id", st.id, "client_ip", st.clientIP.String(), "route", st.route, "detail", v.Detail, "captcha", required == challenge.TierCaptcha}, v.Attrs...)...)
					ch.ServeTier(rw, r, st.clientIP, v.Captcha)
					return
				}
			}
			s.filterDeny(rw, r, st, v)
			return
		}
	}
admitted:

	if cr.cors != nil {
		cr.cors.apply(rw.Header(), r)
	}

	// Rate limits keyed on the verified identity run after the filter
	// chain that established it.
	if len(cr.identityLimits) > 0 {
		if s.applyRateLimits(rw, r, st, cr, cr.identityLimits, release) {
			return
		}
	}

	// A WebTransport session is relayed only now: the CONNECT has passed
	// maintenance, patches, policy, ACLs, geo, the challenge, shedding,
	// the rate limits and the filter chain like any other request.
	if isWebTransport(r) {
		s.relayWebTransport(rw, r, st, cr)
		return
	}

	// Per-route timeout, tightened by a gRPC client's own deadline.
	ctx := r.Context()
	deadline := cr.cfg.TotalTimeout().D()
	if st.grpc {
		if d := parseGRPCTimeout(r.Header.Get("Grpc-Timeout")); d > 0 && (deadline == 0 || d < deadline) {
			deadline = d
		}
	}
	if deadline > 0 || cr.idleTimeout > 0 {
		var cancel context.CancelFunc
		if deadline > 0 {
			ctx, cancel = context.WithTimeout(ctx, deadline)
		} else {
			ctx, cancel = context.WithCancel(ctx)
		}
		defer cancel()
		// The idle reader (set in ModifyResponse) cancels the request when
		// the upstream stalls; keep the canceller reachable through st.
		st.cancel = cancel
		r = r.WithContext(ctx)
	}

	// The slow lane. Applied once the route is matched and the filters
	// have run, so a level can read the mark and the bot score, and
	// before the answer is produced, so it shapes whatever the action
	// below writes.
	if hold := s.applyDegradation(rw, r, st); hold > 0 {
		if !s.holdDegraded(r, hold) {
			// The client gave up while it was held. Nothing to serve.
			s.stats.ClientAborts.Add(1)
			rw.status, rw.wrote = 499, true
			return
		}
	}

	// Actions.
	switch {
	case cr.deceive != nil && cr.deceive.admits(st, r):
		// Before every other action: a client this route no longer
		// trusts gets a plausible answer rather than the origin's, and
		// its writes never reach the origin at all.
		s.deceive(rw, r, st, cr)
	case cr.cfg.Redirect != nil:
		cr.respOps.apply(rw.Header(), &tvars{r: r, st: st})
		http.Redirect(rw, r, cr.redirectTo.Expand(&tvars{r: r, st: st}), cr.cfg.Redirect.Status)
	case cr.cfg.Honeypot != nil:
		s.honeypot(rw, r, st, cr, release)
	case cr.cfg.DoH != nil:
		s.doh(rw, r, st, cr)
	case cr.cfg.Static != nil:
		s.static(rw, r, st, cr)
	case cr.cfg.Respond != nil:
		cr.respOps.apply(rw.Header(), &tvars{r: r, st: st})
		if rw.Header().Get("Content-Type") == "" {
			rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
		}
		rw.Header().Set("X-Content-Type-Options", "nosniff")
		rw.WriteHeader(cr.cfg.Respond.Status)
		if r.Method != http.MethodHead {
			_, _ = rw.Write([]byte(cr.cfg.Respond.Body))
		}
	default:
		if rc := cr.cfg.Cache; rc != nil {
			if c := s.cache.Load(); c != nil {
				if key := cacheKey(rc, r, st.host, st.path); key != "" {
					if e, ok := c.Get(key, r.Header); ok {
						s.serveCached(rw, r, st, cr, e)
						return
					}
					st.cacheKey = key
					st.cache = "miss"
				} else {
					st.cache = "bypass"
				}
			}
		}
		s.proxyTo(rw, r, st, cr, instances)
	}
}

// filterDeny handles a deny verdict from the filter chain.
func (s *Server) filterDeny(rw *responseWriter, r *http.Request, st *reqState, v filter.Verdict) {
	if v.Silent {
		// A flow step, not a refusal: answer without the security bookkeeping.
		st.extra = append(st.extra, "flow", v.Reason+":"+v.Detail)
		if !rw.wrote {
			for k, val := range v.Headers {
				rw.Header().Set(k, val)
			}
			if v.Response != nil {
				s.writeResponse(rw, r, v.Response)
			} else {
				s.plainStatus(rw, r, v.Status)
			}
		}
		return
	}
	st.denied = v.Reason
	if v.Detail != "" {
		st.denied += ":" + v.Detail
	}
	switch v.Reason {
	case "waf":
		s.stats.DeniedWAF.Add(1)
	case "jwt":
		s.stats.DeniedJWT.Add(1)
	case "icap":
		s.stats.DeniedICAP.Add(1)
	case "body_size":
		s.stats.DeniedBodySize.Add(1)
	case "sensitive_data":
		s.stats.DeniedSensitive.Add(1)
	case accountguard.Reason:
		s.stats.DeniedAccount.Add(1)
	default:
		s.stats.DeniedFilter.Add(1)
	}
	s.logs.SecurityEvent(r.Context(), "deny", v.Reason, append([]any{
		"request_id", st.id, "client_ip", st.clientIP.String(), "method", r.Method,
		"host", r.Host, "path", r.URL.Path, "route", st.route, "status", v.Status,
		"detail", v.Detail, "user_agent", r.UserAgent()}, v.Attrs...)...)
	if bl := s.bans.Load(); bl != nil {
		bl.ObserveClient(st.clientIP, st.ja4, banCategory(v.Reason))
	}
	if rw.wrote {
		return
	}
	for k, val := range v.Headers {
		rw.Header().Set(k, val)
	}
	if v.Response != nil {
		s.writeResponse(rw, r, v.Response)
		return
	}
	s.plainStatus(rw, r, v.Status)
}

// writeResponse sends a filter supplied response verbatim, keeping the
// proxy's own hygiene headers.
func (s *Server) writeResponse(rw *responseWriter, r *http.Request, resp *http.Response) {
	h := rw.Header()
	for k, vs := range resp.Header {
		if k == "Server" || k == "Connection" || k == "Transfer-Encoding" {
			continue
		}
		h[k] = vs
	}
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	rw.WriteHeader(resp.StatusCode)
	if r.Method != http.MethodHead && resp.Body != nil {
		_, _ = io.Copy(rw, io.LimitReader(resp.Body, 4<<20))
		_ = resp.Body.Close()
	}
}

// banCategory maps a deny reason to the trigger category in the
// configuration.
func banCategory(reason string) string {
	switch {
	case reason == "acl_deny", reason == "acl_allow":
		return "acl"
	case strings.HasPrefix(reason, "rate_limit"):
		return "rate_limit"
	default:
		return reason
	}
}

func (s *Server) proxyTo(rw *responseWriter, r *http.Request, st *reqState, cr *compiledRoute, instances filter.Instances) {
	pool := cr.pool
	st.upstream = pool.Name

	if isUpgrade(r) && !cr.cfg.WebSocket {
		s.stats.DeniedWebSocket.Add(1)
		st.denied = "websocket_not_allowed"
		s.deny(rw, r, st, http.StatusForbidden, "websocket")
		return
	}

	if g := pool.Gate(); g != nil {
		release, err := g.Acquire(r.Context())
		if err != nil {
			s.queueRefused(rw, r, st, err)
			return
		}
		defer release()
	}
	// A signature that covers the body needs the body, so it is read
	// here, before the reverse proxy runs: the same buffer serves the
	// retry path, and a bodied request too large to digest is refused
	// rather than forwarded with a signature that stops at the headers.
	if signer := s.rt.Load().signers[pool.Name]; signer != nil && signer.Digest {
		if !s.digestBody(rw, r, st) {
			return
		}
	}
	var mirrored *http.Request
	if cr.mirror != nil {
		mirrored = s.prepareMirror(r, st, cr)
		if mirrored != nil && cr.mirror.diff != nil {
			st.shadow = newShadowState(cr.mirror.diff)
		}
	}
	pi := &pickInfo{hashKey: hashKey(pool.Cfg, r, st), canary: pool.CanaryMode(r)}
	if name := pool.AffinityCookie(); name != "" {
		if c, err := r.Cookie(name); err == nil {
			pi.cookie = c.Value
		}
	}
	ctx := withPick(r.Context(), pi)
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(ctx, pool.Cfg.Timeouts.Total.D())
	defer cancel()
	r = r.WithContext(ctx)

	start := time.Now()
	if st.span != nil {
		st.upSpan = st.span.Child("upstream " + pool.Name)
		st.upSpan.Set(otlp.String("xproxy.upstream", pool.Name))
	}
	rp := &httputil.ReverseProxy{
		Transport:     newPoolTransport(pool),
		FlushInterval: -1,
		ErrorLog:      nil,
		Rewrite: func(pr *httputil.ProxyRequest) {
			s.rewrite(pr, st, cr)
		},
		ModifyResponse: func(resp *http.Response) error {
			ttfb := time.Since(start)
			s.stats.UpstreamTTFB.Observe(ttfb.Seconds())
			if sh := s.shedder.Load(); sh != nil {
				sh.Observe(ttfb)
			}
			pi.mu.Lock()
			if pi.endpoint != nil {
				st.endpoint = pi.endpoint.Address
				st.canary = pi.endpoint.Canary
			}
			st.attempts = pi.attempts
			if st.upSpan != nil {
				st.upSpan.Set(otlp.String("server.address", st.endpoint), otlp.Int("http.response.status_code", int64(resp.StatusCode)), otlp.Int("xproxy.attempts", int64(pi.attempts)))
				st.upSpan.Finish(resp.StatusCode >= 500)
			}
			cookie := pi.setCookie
			retried := pi.attempts - 1
			statusRetries := pi.statusRetries
			pi.mu.Unlock()
			if retried > 0 {
				s.stats.UpstreamRetries.Add(uint64(retried))             //nolint:gosec // positive
				s.stats.UpstreamStatusRetries.Add(uint64(statusRetries)) //nolint:gosec // bounded by retried
			}
			if cookie != "" {
				http.SetCookie(rw, &http.Cookie{
					Name: pool.AffinityCookie(), Value: cookie, Path: "/",
					MaxAge:   int(pool.Cfg.Affinity.TTL.D().Seconds()),
					HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode,
				})
			}
			if v := instances.Response(resp); v.Deny {
				return &filterDenied{v: v}
			}
			// The cache snapshot is taken before the route's response header
			// operations run: their templates may expand request data of
			// this client (a cookie, a header, the address), which must not
			// be replayed to everyone else; a hit applies them afresh.
			if st.cacheKey != "" && r.Method == http.MethodGet {
				if c := s.cache.Load(); c != nil {
					if ttl, ok := storable(cr.cfg.Cache, r, resp, c.MaxObject()); ok {
						hdr := cache.StorableHeader(resp.Header)
						vary, _ := cache.VaryNames(resp.Header.Values("Vary"))
						status, key, host, path, reqHdr := resp.StatusCode, st.cacheKey, st.host, st.path, r.Header.Clone()
						resp.Body = &cachingBody{ReadCloser: resp.Body, limit: c.MaxObject(), store: func(body []byte) {
							now := time.Now()
							e := &cache.Entry{Status: status, Header: hdr, Body: append([]byte(nil), body...), Stored: now, Expires: now.Add(ttl), Host: host, Path: path}
							e.SetVary(vary)
							c.Put(key, reqHdr, e)
						}}
					}
				}
			}
			cr.respOps.apply(resp.Header, &tvars{r: r, st: st})
			// The capture's copy is taken here, after the route's own
			// header operations, so the file holds what the client got
			// rather than what the upstream sent.
			if cs := st.pcap; cs != nil && cs.respBody != nil && resp.Body != nil && resp.Body != http.NoBody {
				resp.Body = &captureBody{ReadCloser: resp.Body, tee: cs.respBody}
			}
			if cr.idleTimeout > 0 && st.cancel != nil && resp.Body != nil && resp.Body != http.NoBody {
				resp.Body = newIdleReader(resp.Body, cr.idleTimeout, st.cancel)
			}
			if cr.cors != nil {
				// The route's policy is authoritative; drop any copy the
				// upstream set so the header the proxy wrote to rw stands.
				stripUpstreamCORS(resp.Header)
			}
			if ep := cr.errPages; ep != nil {
				ep.interceptBody(resp, r, st)
			} else if ep := s.rt.Load().errorPages; ep != nil {
				ep.interceptBody(resp, r, st)
			}
			if st.grpcWeb {
				grpcWebResponse(resp, r.Header.Get("Content-Type"))
				if o, ok := grpcWebOriginAllowed(cr.cfg.GRPC.WebOrigins, r.Header.Get("Origin")); ok {
					grpcWebCORS(resp.Header, o)
				}
			}
			if st.grpc {
				if code := grpcStatusOf(resp); code != "" {
					st.grpcCode = code
				} else {
					resp.Body = &grpcStatusBody{ReadCloser: resp.Body, resp: resp, set: func(code string) { st.grpcCode = code }}
				}
			}
			if st.cache != "" {
				resp.Header.Set("X-Cache", strings.ToUpper(st.cache))
			}
			if s.cfg().Server.ServerHeader == "" {
				resp.Header.Del("Server")
			} else {
				resp.Header.Set("Server", s.cfg().Server.ServerHeader)
			}
			if st.shadow != nil {
				// Outermost body wrap: summarise exactly what the client
				// receives, after every other transformation above.
				st.shadow.captureLive(resp)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			s.upstreamError(rw, req, st, pi, err)
		},
	}
	if mirrored != nil {
		s.sendMirror(mirrored, st, cr)
	}
	rp.ServeHTTP(rw, r)
	pi.mu.Lock()
	if pi.endpoint != nil {
		st.endpoint = pi.endpoint.Address
	}
	if st.attempts == 0 {
		st.attempts = pi.attempts
	}
	pi.mu.Unlock()
}

func (s *Server) rewrite(pr *httputil.ProxyRequest, st *reqState, cr *compiledRoute) {
	in, out := pr.In, pr.Out
	rt := s.rt.Load()
	out.URL.Scheme = cr.pool.Scheme
	out.URL.Host = "pool" // replaced by poolTransport per attempt
	out.URL.Path, out.URL.RawPath = cr.outboundPath(in.URL.Path, in.URL.RawPath, in, st)
	if cr.cfg.HostHeader != "" {
		out.Host = cr.cfg.HostHeader
	} else {
		out.Host = in.Host
	}
	if st.grpcWeb {
		grpcWebRequest(out, in.Header.Get("Content-Type"))
	}
	// Forwarding headers: only a trusted peer's chain is preserved.
	if netutil.Contains(rt.trusted, netutil.RemoteAddr(in)) {
		out.Header["X-Forwarded-For"] = in.Header["X-Forwarded-For"]
	}
	pr.SetXForwarded()
	out.Header.Set("X-Real-Ip", st.clientIP.String())
	out.Header.Set("X-Request-Id", st.id)
	out.Header.Del("Forwarded")
	// The mirror marker is the proxy's own statement; a client must not be
	// able to make live traffic look like a shadow copy.
	out.Header.Del(mirrorHeader)
	// Trace context: the upstream's spans hang under our client span; an
	// incoming header from an untrusted client is replaced, never forwarded
	// as is, when propagation is off.
	out.Header.Del("Traceparent")
	out.Header.Del("Tracestate")
	if st.propagate {
		parent := st.upSpan
		if parent == nil {
			parent = st.span
		}
		if parent != nil {
			out.Header.Set("Traceparent", parent.Traceparent())
			if parent.TraceState != "" {
				out.Header.Set("Tracestate", parent.TraceState)
			}
		}
	}
	cr.reqOps.apply(out.Header, &tvars{r: in, st: st})
	if signer := rt.signers[cr.pool.Name]; signer != nil {
		signer.Sign(out, time.Now(), st.clientIP.String(), st.id, st.bodyDigest)
	}
}

// outboundPath applies strip_prefix, rewrite_path or rewrite_regex and
// records regular expression captures for templates.
func (cr *compiledRoute) outboundPath(path, rawPath string, r *http.Request, st *reqState) (string, string) {
	if cr.rewriteRE == nil {
		return rewritePath(path, rawPath, cr.cfg)
	}
	clean := netutil.CleanPath(path)
	if cr.cfg.StripPrefix != "" {
		clean, _ = rewritePath(clean, "", cr.cfg)
	}
	m := cr.rewriteRE.FindStringSubmatch(clean)
	if m == nil {
		return clean, ""
	}
	st.captures, st.captureNames = m, cr.rewriteRE.SubexpNames()
	return cr.rewriteTo.Expand(&tvars{r: r, st: st}), ""
}

// rewritePath applies strip_prefix / rewrite_path to the outbound path.
func rewritePath(path, rawPath string, rc *config.Route) (string, string) {
	if rc.RewritePath != "" {
		return rc.RewritePath, ""
	}
	if rc.StripPrefix != "" {
		clean := netutil.CleanPath(path)
		if strings.HasPrefix(clean, rc.StripPrefix) {
			rest := strings.TrimPrefix(clean, rc.StripPrefix)
			if rest == "" || rest[0] != '/' {
				rest = "/" + rest
			}
			return rest, ""
		}
	}
	return path, rawPath
}

func (s *Server) upstreamError(rw *responseWriter, r *http.Request, st *reqState, pi *pickInfo, err error) {
	pi.mu.Lock()
	if pi.endpoint != nil {
		st.endpoint = pi.endpoint.Address
	}
	st.attempts = pi.attempts
	retried, statusRetries := pi.attempts-1, pi.statusRetries
	pi.mu.Unlock()
	if retried > 0 {
		s.stats.UpstreamRetries.Add(uint64(retried))             //nolint:gosec // positive
		s.stats.UpstreamStatusRetries.Add(uint64(statusRetries)) //nolint:gosec // bounded by retried
	}
	var fd *filterDenied
	if errors.As(err, &fd) {
		s.filterDeny(rw, r, st, fd.v)
		return
	}
	if sh := s.shedder.Load(); sh != nil && errors.Is(err, context.DeadlineExceeded) {
		// A timeout is the strongest latency signal there is.
		sh.Observe(time.Since(st.start))
	}
	st.upErr = err.Error()
	if st.upSpan != nil {
		st.upSpan.Set(otlp.String("error.type", err.Error()))
		st.upSpan.Finish(true)
	}
	status := http.StatusBadGateway
	switch {
	case errors.Is(err, context.Canceled) && r.Context().Err() == context.Canceled:
		// Client went away; nothing to send.
		s.stats.ClientAborts.Add(1)
		rw.status = 499
		rw.wrote = true
		return
	case errors.Is(err, context.DeadlineExceeded):
		s.stats.UpstreamTimeouts.Add(1)
		status = http.StatusGatewayTimeout
	case errors.Is(err, errNoEndpoint):
		s.stats.UpstreamNoHealthy.Add(1)
		status = http.StatusServiceUnavailable
		rw.Header().Set("Retry-After", "5")
	case errors.Is(err, upstream.ErrCircuitOpen):
		s.stats.UpstreamCircuitOpen.Add(1)
		status = http.StatusServiceUnavailable
		var coe *circuitOpenError
		secs := 1
		if errors.As(err, &coe) {
			secs = max(int(coe.retryAfter.Seconds()+0.999), 1)
		}
		rw.Header().Set("Retry-After", strconv.Itoa(secs))
		st.upErr = "circuit_open"
		if rw.wrote {
			return
		}
		s.plainStatus(rw, r, status)
		return
	default:
		s.stats.UpstreamErrors.Add(1)
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			s.stats.DeniedBodySize.Add(1)
			st.denied = "body_too_large"
			status = http.StatusRequestEntityTooLarge
		}
	}
	s.logs.Error.Warn("upstream error", "request_id", st.id, "route", st.route, "upstream", st.upstream, "endpoint", st.endpoint, "attempts", st.attempts, "err", err.Error())
	if rw.wrote {
		return
	}
	s.plainStatus(rw, r, status)
}

// queueRefused answers a request the pool's gate could not seat: the
// queue was full or the wait ran out. A client cancel gets nothing.
func (s *Server) queueRefused(rw *responseWriter, r *http.Request, st *reqState, err error) {
	switch {
	case errors.Is(err, upstream.ErrQueueFull):
		s.stats.UpstreamQueueFull.Add(1)
		st.upErr = "queue_full"
	case errors.Is(err, upstream.ErrQueueTimeout):
		s.stats.UpstreamQueueTimeouts.Add(1)
		st.upErr = "queue_timeout"
	default:
		s.stats.ClientAborts.Add(1)
		rw.status = 499
		rw.wrote = true
		return
	}
	rw.Header().Set("Retry-After", "1")
	s.plainStatus(rw, r, http.StatusServiceUnavailable)
}

// observeEndpoint feeds the API inventory with a finished request.
func (s *Server) observeEndpoint(rw *responseWriter, r *http.Request, st *reqState, status int) {
	o := apiinv.Observation{Host: st.host, Method: r.Method, Path: netutil.PathTemplate(st.path), Route: st.cr.cfg.Name, Status: status,
		Auth: authKind(r), RequestType: mediaType(r.Header.Get("Content-Type")), ResponseType: mediaType(rw.Header().Get("Content-Type"))}
	if len(st.cr.describers) > 0 {
		o.Documented = apiinv.No
		for _, d := range st.cr.describers {
			if tmpl, ok := d.Documented(r.Method, st.path); ok {
				o.Documented, o.Path = apiinv.Yes, tmpl
				break
			}
		}
	}
	s.inventory.Observe(o, st.start)
}

// authKind names the credential a request carries.
func authKind(r *http.Request) string {
	if a := r.Header.Get("Authorization"); a != "" {
		scheme, _, _ := strings.Cut(a, " ")
		switch strings.ToLower(scheme) {
		case "bearer":
			return "bearer"
		case "basic":
			return "basic"
		}
		return "other"
	}
	if r.Header.Get("X-Api-Key") != "" || r.Header.Get("Api-Key") != "" {
		return "api_key"
	}
	if r.Header.Get("Cookie") != "" {
		return "cookie"
	}
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return "client_cert"
	}
	return "none"
}

func mediaType(ct string) string {
	if ct == "" {
		return ""
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.ToLower(strings.TrimSpace(ct))
}

// deny writes a minimal error response and a security log entry.
func (s *Server) deny(rw *responseWriter, r *http.Request, st *reqState, status int, reason string) {
	s.denyDetail(rw, r, st, status, reason, "")
}

// denyDetail is deny with a detail attribute in the security event.
func (s *Server) denyDetail(rw *responseWriter, r *http.Request, st *reqState, status int, reason, detail string) {
	st.reason = reason
	attrs := []any{"request_id", st.id, "client_ip", st.clientIP.String(), "method", r.Method,
		"host", r.Host, "path", r.URL.Path, "route", st.route, "status", status,
		"user_agent", r.UserAgent()}
	if detail != "" {
		attrs = append(attrs, "detail", detail)
	}
	s.logs.SecurityEvent(r.Context(), "deny", reason, attrs...)
	if bl := s.bans.Load(); bl != nil && reason != "banned" {
		bl.ObserveClient(st.clientIP, st.ja4, banCategory(reason))
	}
	s.plainStatus(rw, r, status)
}

// tarpit holds the connection for the configured delay, then denies. The
// hold is bounded by the client context so a disconnected attacker does not
// pin a goroutine.
func (s *Server) tarpit(rw *responseWriter, r *http.Request, st *reqState, rl *config.RateLimit) {
	s.logs.SecurityEvent(r.Context(), "tarpit", "rate_limit:"+rl.Name,
		"request_id", st.id, "client_ip", st.clientIP.String(), "method", r.Method,
		"host", r.Host, "path", r.URL.Path, "route", st.route, "delay", rl.TarpitDelay.D().String())
	if bl := s.bans.Load(); bl != nil {
		bl.ObserveClient(st.clientIP, st.ja4, "rate_limit")
	}
	select {
	case <-time.After(rl.TarpitDelay.D()):
	case <-r.Context().Done():
		s.stats.ClientAborts.Add(1)
		rw.status = 499
		rw.wrote = true
		return
	}
	rw.Header().Set("Retry-After", strconv.Itoa(int(retryAfter(rl))))
	s.plainStatus(rw, r, http.StatusTooManyRequests)
}

// plainStatus writes a terse status page. No body details are leaked: the
// text is the standard reason phrase only.
func (s *Server) plainStatus(rw *responseWriter, r *http.Request, status int) {
	if isGRPC(r) && r.ProtoMajor == 2 {
		writeGRPCStatus(rw, status)
		return
	}
	if isGRPCWeb(r) {
		writeGRPCWebStatus(rw, r, status)
		return
	}
	h := rw.Header()
	body := []byte(strconv.Itoa(status) + " " + http.StatusText(status) + "\n")
	ctype := "text/plain; charset=utf-8"
	if ep := s.errorPagesFor(rw); ep != nil {
		var reason string
		if rw.st != nil {
			reason = rw.st.reason
		}
		if b, ct, ok := ep.render(r, rw.st, status, reason); ok {
			body, ctype = b, ct
		}
	}
	h.Set("Content-Type", ctype)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	if status >= 500 || status == http.StatusTooManyRequests {
		h.Set("Connection", "close")
	}
	rw.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = rw.Write(body)
	}
}

func (s *Server) logAccess(rw *responseWriter, r *http.Request, st *reqState) {
	status := rw.Status()
	s.stats.countStatus(status)
	s.stats.BytesOut.Add(uint64(max(rw.bytes, 0))) //nolint:gosec // non-negative
	dur := time.Since(st.start)
	s.stats.RequestDuration.Observe(dur.Seconds())
	if st.cr != nil {
		st.cr.hist.Observe(dur.Seconds())
	}
	attrs := []any{
		"request_id", st.id,
		"client_ip", st.clientIP.String(),
		"method", r.Method,
		"host", r.Host,
		"path", r.URL.Path,
		"query_len", len(r.URL.RawQuery),
		"proto", r.Proto,
		"status", status,
		"bytes_in", r.ContentLength,
		"bytes_out", rw.bytes,
		"duration_ms", float64(dur.Microseconds()) / 1000,
		"route", st.route,
		"upstream", st.upstream,
		"endpoint", st.endpoint,
		"attempts", st.attempts,
		"user_agent", r.UserAgent(),
		"referer", r.Referer(),
	}
	if r.TLS != nil {
		attrs = append(attrs, "tls", tlsconf.VersionName(r.TLS.Version), "sni", r.TLS.ServerName)
		// The negotiated group, so a post-quantum rollout can be read
		// off real traffic rather than assumed from the configuration.
		if g := config.GroupName(r.TLS.CurveID); g != "" {
			attrs = append(attrs, "tls_group", g)
			s.stats.KeyExchange(g, config.IsPostQuantum(r.TLS.CurveID))
		}
		if len(r.TLS.PeerCertificates) > 0 {
			attrs = append(attrs, "client_cn", r.TLS.PeerCertificates[0].Subject.CommonName)
		}
	}
	if st.country != "" {
		attrs = append(attrs, "country", st.country)
	}
	if st.ja4 != "" {
		attrs = append(attrs, "ja4", st.ja4)
	}
	if st.device != "" {
		attrs = append(attrs, "device", st.device)
	}
	if len(st.automation) > 0 {
		attrs = append(attrs, "automation", strings.Join(st.automation, ","))
	}
	if st.cr != nil && st.cr.inventory && s.inventory.Enabled() {
		s.observeEndpoint(rw, r, st, status)
	}
	if st.cache != "" {
		attrs = append(attrs, "cache", st.cache)
	}
	if st.canary {
		attrs = append(attrs, "canary", true)
	}
	if st.span != nil {
		attrs = append(attrs, "trace_id", st.span.TraceIDString(), "span_id", st.span.SpanIDString())
		if st.span.Sampled {
			attrs = append(attrs, "trace_sampled", true)
		}
		// A span is not a log line, so the redactor never saw it: the
		// client address goes through the same client_ip rule here, or
		// a deployment that turned redaction on still shipped the full
		// address to its trace collector beside a trace id the access
		// log also carries.
		clientAddr := st.clientIP.String()
		if s.traceRedactIP.Load() {
			clientAddr = s.logs.Redactor().ClientAddress(clientAddr)
		}
		st.span.Set(otlp.String("http.request.method", r.Method), otlp.String("url.path", r.URL.Path), otlp.String("server.address", r.Host),
			otlp.String("network.protocol.version", r.Proto), otlp.Int("http.response.status_code", int64(status)), otlp.String("client.address", clientAddr),
			otlp.String("xproxy.request_id", st.id), otlp.String("xproxy.route", st.route))
		if st.upstream != "" {
			st.span.Set(otlp.String("xproxy.upstream", st.upstream))
		}
		if st.denied != "" {
			st.span.Set(otlp.String("xproxy.denied", st.denied))
		}
		st.span.Name = r.Method + " " + st.route
		defer st.span.Finish(status >= 500 || st.denied != "")
	}
	if st.encoding != "" {
		attrs = append(attrs, "encoding", st.encoding)
	}
	if st.marked {
		attrs = append(attrs, "honeypot_marked", true)
	}
	if st.mirror != "" {
		attrs = append(attrs, "mirror", st.mirror)
	}
	if st.grpc {
		attrs = append(attrs, "grpc", true)
		if st.grpcCode != "" {
			attrs = append(attrs, "grpc_status", st.grpcCode)
			if c, err := strconv.Atoi(st.grpcCode); err == nil && c >= 0 && c <= 16 {
				s.stats.GRPCStatus[c].Add(1)
			}
		}
	}
	if st.denied != "" {
		attrs = append(attrs, "denied", st.denied)
	}
	if st.upErr != "" {
		attrs = append(attrs, "upstream_error", st.upErr)
	}
	if len(st.extra) > 0 {
		attrs = append(attrs, st.extra...)
		for i := 0; i+1 < len(st.extra); i += 2 {
			if st.extra[i] == "waf_detected" {
				s.stats.WAFDetected.Add(1)
			}
		}
	}
	// Sampling and field selection affect only the written line; every
	// request is already counted above.
	pol := s.rt.Load().accessLog
	if !pol.keep(status, st.denied) {
		return
	}
	s.logs.Access.Info("request", pol.selectFields(attrs)...)
}

func isUpgrade(r *http.Request) bool {
	if r.Header.Get("Upgrade") == "" {
		return false
	}
	for _, v := range r.Header.Values("Connection") {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "upgrade") {
				return true
			}
		}
	}
	return false
}

// applyRateLimits evaluates a set of rate limit policies; it returns
// true when a policy denied the request and a response was written, so
// the caller returns. release is the concurrency slot, released before a
// tarpit holds its own slot.
func (s *Server) applyRateLimits(rw *responseWriter, r *http.Request, st *reqState, cr *compiledRoute, limits []*rateLimit, release func()) bool {
	for _, rl := range limits {
		key := s.rateKey(rl.cfg, r, st)
		allowed, decided := false, false
		if rl.cfg.Distributed == "exact" {
			if node := s.cluster.Load(); node != nil {
				// The key's owner decides; without an answer in time the
				// local limiter does.
				allowed, decided = node.Take(rl.cfg.Name, key, 1)
			}
		}
		if !decided {
			// When the key table is full the decision falls back to
			// the client address and then to its network, rather than
			// admitting an untracked request.
			allowed = rl.lim.AllowFallback(key, []string{"ip:" + st.clientIP.String(), coarseKey(st.clientIP)}, 1)
		}
		if allowed {
			rl.allowed.Add(1)
			continue
		}
		rl.denied.Add(1)
		cr.rateLimited.Add(1)
		st.denied = "rate_limit:" + rl.cfg.Name
		if rl.cfg.Action == "tarpit" {
			// A tarpit does no work, so it must not hold a concurrency slot
			// (an attacker could otherwise fill max_concurrent_requests with
			// idle held requests); it holds a tarpit slot instead, and above
			// that bound the request is rejected immediately.
			if tpRelease, ok := s.tarpits.Acquire(); ok {
				release()
				s.stats.Tarpitted.Add(1)
				s.tarpit(rw, r, st, rl.cfg)
				tpRelease()
				return true
			}
			s.stats.TarpitOverflow.Add(1)
		}
		s.stats.DeniedRateLimit.Add(1)
		rw.Header().Set("Retry-After", strconv.Itoa(int(retryAfter(rl.cfg))))
		s.deny(rw, r, st, http.StatusTooManyRequests, "rate_limit")
		return true
	}
	return false
}

// rateKey derives the bucket identity of a request for a policy. Keys a
// request may lack (a header, a cookie, a claim, a fingerprint, a
// country) fall back to the client address, so a limit cannot be
// avoided by omitting the identifier; rotating the identifier still
// buys fresh buckets, which is why such keys are paired with a
// client_ip or client_net policy.
func (s *Server) rateKey(rl *config.RateLimit, r *http.Request, st *reqState) string {
	ip := "ip:" + st.clientIP.String()
	switch {
	case rl.Key == "client_ip":
		return st.clientIP.String()
	case rl.Key == "client_net":
		bits := rl.NetV4
		if st.clientIP.Is6() && !st.clientIP.Is4In6() {
			bits = rl.NetV6
		}
		if p, err := st.clientIP.Unmap().Prefix(bits); err == nil {
			return "net:" + p.String()
		}
		return ip
	case rl.Key == "route":
		return st.route
	case rl.Key == "endpoint":
		return trim("ep:"+r.Method+" "+st.route+" "+netutil.PathTemplate(st.path), 256)
	case rl.Key == "country":
		if st.country == "" {
			return ip
		}
		return "c:" + st.country
	case rl.Key == "identity":
		if v := st.identity.Any("oidc", "jwt", "api_key", "basic", "ldap"); v != "" {
			return "id:" + trim(v, 256)
		}
		return ip
	case strings.HasPrefix(rl.Key, "identity:"):
		if v := st.identity.Get(rl.Key[len("identity:"):]); v != "" {
			return "id:" + rl.Key[len("identity:"):] + ":" + trim(v, 256)
		}
		return ip
	case rl.Key == "device":
		if st.device != "" {
			return "dev:" + st.device
		}
		return ip
	case rl.Key == "ja4":
		if r.TLS != nil {
			if fp, ok := s.fingerprints.Get(r.RemoteAddr); ok && fp.JA4 != "" {
				return "ja4:" + fp.JA4
			}
		}
		return ip
	case strings.HasPrefix(rl.Key, "header:"):
		v := r.Header.Get(rl.Key[len("header:"):])
		if v == "" {
			return ip
		}
		return "h:" + trim(v, 256)
	case strings.HasPrefix(rl.Key, "cookie:"):
		if c, err := r.Cookie(rl.Key[len("cookie:"):]); err == nil && c.Value != "" {
			return "ck:" + trim(c.Value, 256)
		}
		return ip
	case strings.HasPrefix(rl.Key, "jwt:"):
		if v := bearerClaim(r.Header.Get("Authorization"), rl.Key[len("jwt:"):]); v != "" {
			return "jwt:" + trim(v, 256)
		}
		return ip
	}
	return st.clientIP.String()
}

// bearerClaim reads a claim from the payload of a bearer token without
// verifying it: the value only names a bucket, and a forged token buys
// its bearer nothing beyond a bucket of its own (the JWT filter still
// rejects it). Only string, number and boolean claims are used.
func bearerClaim(authorization, claim string) string {
	tok, ok := strings.CutPrefix(authorization, "Bearer ")
	if !ok {
		tok, ok = strings.CutPrefix(authorization, "bearer ")
		if !ok {
			return ""
		}
	}
	parts := strings.Split(strings.TrimSpace(tok), ".")
	if len(parts) != 3 || len(parts[1]) > 16<<10 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims map[string]any
	if json.Unmarshal(payload, &claims) != nil {
		return ""
	}
	switch v := claims[claim].(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	}
	return ""
}

func hashKey(u *config.Upstream, r *http.Request, st *reqState) string {
	if u.Balancer != "hash" {
		return ""
	}
	switch {
	case strings.HasPrefix(u.HashOn, "header:"):
		if v := r.Header.Get(u.HashOn[7:]); v != "" {
			return v
		}
	case strings.HasPrefix(u.HashOn, "cookie:"):
		if c, err := r.Cookie(u.HashOn[7:]); err == nil && c.Value != "" {
			return c.Value
		}
	}
	return st.clientIP.String()
}

func retryAfter(rl *config.RateLimit) float64 {
	if rl.Rate <= 0 {
		return 1
	}
	s := 1 / rl.Rate
	if s < 1 {
		return 1
	}
	return s
}

// digestBody buffers the request body, records its digest on st and
// makes the buffer replayable for retries. It answers 413 and returns
// false when the body is larger than a digest may cover.
func (s *Server) digestBody(rw *responseWriter, r *http.Request, st *reqState) bool {
	if r.Body == nil || r.Body == http.NoBody {
		return true
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, originsig.MaxDigestBody+1))
	if err != nil {
		s.denyDetail(rw, r, st, http.StatusBadRequest, "body_size", "body unreadable")
		return false
	}
	if int64(len(body)) > originsig.MaxDigestBody {
		s.denyDetail(rw, r, st, http.StatusRequestEntityTooLarge, "body_size", "larger than a signed body digest covers")
		return false
	}
	st.bodyDigest = originsig.BodyDigest(body)
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	return true
}

// coarseKey is the last resort of a full rate-limit key table: the
// client's /24 or /48, which one client cannot rotate out of the way
// the address itself can be rotated.
func coarseKey(ip netip.Addr) string {
	// The zero address has no prefix: netip answers it with the zero
	// Prefix and no error, whose String is the word "invalid", so
	// without this guard every client the listener could not parse an
	// address for would share one bucket named after that word.
	if !ip.IsValid() {
		return ""
	}
	bits := 24
	if ip.Is6() && !ip.Is4In6() {
		bits = 48
	}
	p, err := ip.Unmap().Prefix(bits)
	if err != nil {
		return ""
	}
	return "net:" + p.String()
}
