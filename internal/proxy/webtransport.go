package proxy

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/rom/xproxy/internal/h3"
	"github.com/rom/xproxy/internal/upstream"
)

// isWebTransport reports an extended CONNECT for WebTransport (the
// :protocol is webtransport, or webtransport-h3 in current drafts).
func isWebTransport(r *http.Request) bool {
	return r.Method == http.MethodConnect && (r.Proto == "webtransport" || r.Proto == "webtransport-h3")
}

// relayWebTransport serves an extended CONNECT for WebTransport on a
// route with webtransport: true. The upstream session is opened first
// (a failure is an ordinary 502), then the client's is accepted and the
// two are relayed until one ends.
func (s *Server) relayWebTransport(rw *responseWriter, r *http.Request, st *reqState, cr *compiledRoute) {
	if st.h3srv == nil || !st.h3srv.WebTransport() || r.ProtoMajor != 3 {
		st.denied = "webtransport_listener"
		s.deny(rw, r, st, http.StatusBadRequest, "webtransport")
		return
	}
	pool := cr.pool
	if pool == nil || !pool.H3() {
		st.denied = "webtransport_upstream"
		s.deny(rw, r, st, http.StatusBadGateway, "webtransport")
		return
	}
	e, _ := pool.Pick("", "", nil, upstream.CanaryAny)
	if e == nil {
		s.stats.UpstreamErrors.Add(1)
		st.upErr = "no endpoint available"
		s.plainStatus(rw, r, http.StatusServiceUnavailable)
		return
	}
	st.upstream, st.endpoint = pool.Name, e.Address
	pool.Begin(e)
	failed := true
	defer func() { pool.End(e, failed, 0) }()

	hdr := r.Header.Clone()
	for _, k := range []string{"Connection", "Keep-Alive", "Proxy-Connection", "Transfer-Encoding", "Upgrade", "Te", "Trailer", "Forwarded", "Traceparent", "Tracestate"} {
		hdr.Del(k)
	}
	if s.rt.Load() != nil {
		hdr.Set("X-Forwarded-For", st.clientIP.String())
	}
	hdr.Set("X-Forwarded-Proto", "https")
	hdr.Set("X-Forwarded-Host", r.Host)
	hdr.Set("X-Real-Ip", st.clientIP.String())
	hdr.Set("X-Request-Id", st.id)
	cr.reqOps.apply(hdr, &tvars{r: r, st: st})

	tc := pool.H3TLS()
	if tc == nil {
		st.denied = "webtransport_upstream"
		s.deny(rw, r, st, http.StatusBadGateway, "webtransport")
		return
	}
	tc = tc.Clone()
	if tc.ServerName == "" {
		if host, _, err := net.SplitHostPort(e.Address); err == nil {
			tc.ServerName = host
		}
	}
	host := r.Host
	if cr.cfg.HostHeader != "" {
		host = cr.cfg.HostHeader
	}
	path, _ := cr.outboundPath(r.URL.Path, r.URL.RawPath, r, st)
	target := "https://" + host + path
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	dialCtx, cancel := context.WithTimeout(r.Context(), max(pool.Cfg.Timeouts.Connect.D(), time.Second))
	resp, us, err := h3.DialWebTransport(dialCtx, tc, e.Address, target, hdr, max(pool.Cfg.Timeouts.Connect.D(), time.Second)) //nolint:bodyclose // the CONNECT stream is the session; closing it ends the session
	cancel()
	if err != nil {
		s.stats.UpstreamErrors.Add(1)
		st.upErr = err.Error()
		s.logs.Error.Warn("webtransport upstream dial failed", "request_id", st.id, "route", cr.cfg.Name, "endpoint", e.Address, "err", err.Error())
		s.plainStatus(rw, r, http.StatusBadGateway)
		return
	}
	if resp != nil {
		for k, v := range resp.Header {
			if k == "Content-Type" || len(k) > 2 && k[:2] == "X-" {
				rw.Header()[k] = v
			}
		}
	}
	cs, err := st.h3srv.Upgrade(rw.ResponseWriter, r)
	if err != nil {
		_ = us.CloseWithError(0, "")
		st.upErr = err.Error()
		s.plainStatus(rw, r, http.StatusBadRequest)
		return
	}
	failed = false
	rw.status, rw.wrote = http.StatusOK, true
	s.stats.WebTransportSessions.Add(1)
	var stats h3.RelayStats
	h3.RelayWebTransport(r.Context(), cs, us, &stats)
	st.extra = append(st.extra, "webtransport", true, "wt_streams", strconv.FormatUint(stats.Streams.Load()+stats.UniStreams.Load(), 10), "wt_datagrams", strconv.FormatUint(stats.Datagrams.Load(), 10))
}
