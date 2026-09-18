package proxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/acme"
	"github.com/rom/xproxy/internal/challenge"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/h3"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/tlsconf"
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
	id       string
	start    time.Time
	clientIP netip.Addr
	host     string
	path     string
	route    string
	upstream string
	endpoint string
	attempts int
	denied   string
	upErr    string
	extra    []any // filter attributes for the access log
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
	rw := &responseWriter{ResponseWriter: w}
	st := &reqState{id: newRequestID(), start: time.Now()}
	st.clientIP = netutil.ClientIP(r, rt.trusted)
	s.stats.Requests.Add(1)
	var route *compiledRoute
	defer func() {
		if route != nil {
			route.observe(rw.Status(), st.denied != "")
		}
	}()
	if r.ContentLength > 0 {
		s.stats.BytesIn.Add(uint64(r.ContentLength)) //nolint:gosec // guarded by > 0 above
	}
	defer s.logAccess(rw, r, st)

	// Never advertise ourselves.
	if s.cfg().Server.ServerHeader != "" {
		rw.Header().Set("Server", s.cfg().Server.ServerHeader)
	}
	rw.Header().Set("X-Request-Id", st.id)
	if h.h3 != nil && r.ProtoMajor < 3 && r.TLS != nil {
		h.h3.SetAltSvc(rw.Header())
	}

	release, ok := s.concurrency.Acquire()
	if !ok {
		s.stats.DeniedConcurrency.Add(1)
		st.denied = "max_concurrent_requests"
		rw.Header().Set("Retry-After", "1")
		s.deny(rw, r, st, http.StatusServiceUnavailable, "concurrency")
		return
	}
	defer release()

	if bl := s.bans.Load(); bl != nil && bl.Banned(st.clientIP) {
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

	st.host = netutil.Host(r.Host)
	if st.host == "" && r.Host != "" {
		s.stats.DeniedBadHost.Add(1)
		st.denied = "bad_host"
		s.deny(rw, r, st, http.StatusBadRequest, "bad_host")
		return
	}
	st.path = netutil.CleanPath(r.URL.Path)

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
					"request_id", st.id, "client_ip", st.clientIP.String(), "user_agent", r.UserAgent())
				if bl := s.bans.Load(); bl != nil {
					bl.Observe(st.clientIP, "challenge")
				}
			}
			return
		}
	}

	match := rt.router.Match(st.host, st.path, r.Method)
	if match == nil {
		s.stats.DeniedNoRoute.Add(1)
		st.denied = "no_route"
		s.deny(rw, r, st, http.StatusNotFound, "no_route")
		return
	}
	cr := rt.routes[match.Index]
	st.route = cr.cfg.Name
	route = cr

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
			if active && !ch.Verified(r, st.clientIP) {
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

	// Rate limits.
	for _, rl := range cr.rateLimits {
		key := rateKey(rl.cfg, r, st)
		if rl.lim.Allow(key) {
			continue
		}
		st.denied = "rate_limit:" + rl.cfg.Name
		if rl.cfg.Action == "tarpit" {
			s.stats.Tarpitted.Add(1)
			s.tarpit(rw, r, st, rl.cfg)
			return
		}
		s.stats.DeniedRateLimit.Add(1)
		rw.Header().Set("Retry-After", strconv.Itoa(int(retryAfter(rl.cfg))))
		s.deny(rw, r, st, http.StatusTooManyRequests, "rate_limit")
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

	// Per-route filters (WAF). Instances live for the whole exchange.
	var instances filter.Instances
	if len(cr.filters) > 0 {
		instances = cr.filters.Begin(r.Context(), &filter.Info{
			RequestID: st.id, ClientIP: st.clientIP, Route: cr.cfg.Name,
			Host: st.host, Path: st.path, Method: r.Method, TLS: r.TLS != nil,
		})
		defer func() { st.extra = append(st.extra, instances.End()...) }()
		if v := instances.Request(r); v.Deny {
			s.filterDeny(rw, r, st, v)
			return
		}
	}

	// Per-route timeout.
	ctx := r.Context()
	if cr.cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cr.cfg.Timeout.D())
		defer cancel()
		r = r.WithContext(ctx)
	}

	// Actions.
	switch {
	case cr.cfg.Redirect != nil:
		applyHeaderOps(rw.Header(), cr.cfg.ResponseHeaders)
		http.Redirect(rw, r, cr.cfg.Redirect.To, cr.cfg.Redirect.Status)
	case cr.cfg.Respond != nil:
		applyHeaderOps(rw.Header(), cr.cfg.ResponseHeaders)
		if rw.Header().Get("Content-Type") == "" {
			rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
		}
		rw.Header().Set("X-Content-Type-Options", "nosniff")
		rw.WriteHeader(cr.cfg.Respond.Status)
		if r.Method != http.MethodHead {
			_, _ = rw.Write([]byte(cr.cfg.Respond.Body))
		}
	default:
		s.proxyTo(rw, r, st, cr, instances)
	}
}

// filterDeny handles a deny verdict from the filter chain.
func (s *Server) filterDeny(rw *responseWriter, r *http.Request, st *reqState, v filter.Verdict) {
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
	default:
		s.stats.DeniedFilter.Add(1)
	}
	s.logs.SecurityEvent(r.Context(), "deny", v.Reason, append([]any{
		"request_id", st.id, "client_ip", st.clientIP.String(), "method", r.Method,
		"host", r.Host, "path", r.URL.Path, "route", st.route, "status", v.Status,
		"detail", v.Detail, "user_agent", r.UserAgent()}, v.Attrs...)...)
	if bl := s.bans.Load(); bl != nil {
		bl.Observe(st.clientIP, banCategory(v.Reason))
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

	pi := &pickInfo{hashKey: hashKey(pool.Cfg, r, st)}
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
	rp := &httputil.ReverseProxy{
		Transport:     &poolTransport{pool: pool, retries: *pool.Cfg.Retries},
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
			}
			st.attempts = pi.attempts
			cookie := pi.setCookie
			pi.mu.Unlock()
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
			applyHeaderOps(resp.Header, cr.cfg.ResponseHeaders)
			if s.cfg().Server.ServerHeader == "" {
				resp.Header.Del("Server")
			} else {
				resp.Header.Set("Server", s.cfg().Server.ServerHeader)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			s.upstreamError(rw, req, st, pi, err)
		},
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
	out.URL.Path, out.URL.RawPath = rewritePath(in.URL.Path, in.URL.RawPath, cr.cfg)
	if cr.cfg.HostHeader != "" {
		out.Host = cr.cfg.HostHeader
	} else {
		out.Host = in.Host
	}
	// Forwarding headers: only a trusted peer's chain is preserved.
	if netutil.Contains(rt.trusted, netutil.RemoteAddr(in)) {
		out.Header["X-Forwarded-For"] = in.Header["X-Forwarded-For"]
	}
	pr.SetXForwarded()
	out.Header.Set("X-Real-Ip", st.clientIP.String())
	out.Header.Set("X-Request-Id", st.id)
	out.Header.Del("Forwarded")
	applyHeaderOps(out.Header, cr.cfg.RequestHeaders)
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
	pi.mu.Unlock()
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

// deny writes a minimal error response and a security log entry.
func (s *Server) deny(rw *responseWriter, r *http.Request, st *reqState, status int, reason string) {
	s.logs.SecurityEvent(r.Context(), "deny", reason,
		"request_id", st.id, "client_ip", st.clientIP.String(), "method", r.Method,
		"host", r.Host, "path", r.URL.Path, "route", st.route, "status", status,
		"user_agent", r.UserAgent())
	if bl := s.bans.Load(); bl != nil && reason != "banned" {
		bl.Observe(st.clientIP, banCategory(reason))
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
		bl.Observe(st.clientIP, "rate_limit")
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
	h := rw.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	if status >= 500 || status == http.StatusTooManyRequests {
		h.Set("Connection", "close")
	}
	rw.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = rw.Write([]byte(strconv.Itoa(status) + " " + http.StatusText(status) + "\n"))
	}
}

func (s *Server) logAccess(rw *responseWriter, r *http.Request, st *reqState) {
	status := rw.Status()
	s.stats.countStatus(status)
	s.stats.BytesOut.Add(uint64(max(rw.bytes, 0))) //nolint:gosec // non-negative
	dur := time.Since(st.start)
	s.stats.RequestDuration.Observe(dur.Seconds())
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
		if len(r.TLS.PeerCertificates) > 0 {
			attrs = append(attrs, "client_cn", r.TLS.PeerCertificates[0].Subject.CommonName)
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
	s.logs.Access.Info("request", attrs...)
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

func applyHeaderOps(h http.Header, ops config.HeaderOps) {
	for _, k := range ops.Remove {
		h.Del(k)
	}
	for k, v := range ops.Set {
		h.Set(k, v)
	}
	for k, v := range ops.Add {
		h.Add(k, v)
	}
}

func rateKey(rl *config.RateLimit, r *http.Request, st *reqState) string {
	switch {
	case rl.Key == "client_ip":
		return st.clientIP.String()
	case rl.Key == "route":
		return st.route
	case strings.HasPrefix(rl.Key, "header:"):
		v := r.Header.Get(rl.Key[len("header:"):])
		if v == "" {
			// Missing header falls back to the client IP so the limit can
			// not be bypassed by omitting it.
			return "ip:" + st.clientIP.String()
		}
		if len(v) > 256 {
			v = v[:256]
		}
		return "h:" + v
	}
	return st.clientIP.String()
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
