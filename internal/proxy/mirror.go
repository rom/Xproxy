package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/httpx"
	"github.com/rom/xproxy/internal/upstream"
	"math/rand/v2"
)

// mirror is the compiled routes[].mirror: the pool that receives copies
// and a bound on copies in flight.
type mirror struct {
	cfg     *config.RouteMirror
	pool    *upstream.Pool
	methods map[string]bool
	sem     chan struct{}
	// diff is the compiled shadow-diff policy, nil when not configured.
	diff *shadowDiff
}

// shadowDiff is the compiled routes[].mirror.diff policy.
type shadowDiff struct {
	sample  int
	maxBody int64
	headers []string // canonicalised header names to compare
}

func newMirror(mc *config.RouteMirror, pool *upstream.Pool) *mirror {
	m := &mirror{cfg: mc, pool: pool, sem: make(chan struct{}, mc.MaxInFlight)}
	if len(mc.Methods) > 0 {
		m.methods = make(map[string]bool, len(mc.Methods))
		for _, x := range mc.Methods {
			m.methods[x] = true
		}
	}
	if d := mc.Diff; d != nil {
		sd := &shadowDiff{sample: d.SamplePercent, maxBody: d.MaxBodyBytes}
		for _, h := range d.Headers {
			sd.headers = append(sd.headers, http.CanonicalHeaderKey(h))
		}
		m.diff = sd
	}
	return m
}

// mirrorHeader marks a copy so the receiving application can tell it from
// live traffic.
const mirrorHeader = "X-Xproxy-Mirror"

// prepareMirror decides whether this request is mirrored and, when it is,
// buffers the body (bounded) so that both the live request and the copy
// can read it. It returns the copy to send, or nil.
func (s *Server) prepareMirror(r *http.Request, st *reqState, cr *compiledRoute) *http.Request {
	m := cr.mirror
	if m.methods != nil && !m.methods[r.Method] {
		return nil
	}
	if m.cfg.Percent < 100 && rand.IntN(100) >= m.cfg.Percent { //nolint:gosec // sampling, not security
		return nil
	}
	if isUpgrade(r) {
		return nil
	}
	var body []byte
	if r.Body != nil && r.Body != http.NoBody {
		if r.ContentLength > m.cfg.MaxBodyBytes {
			st.mirror = "body_too_large"
			s.stats.MirrorSkipped.Add(1)
			return nil
		}
		buf, err := io.ReadAll(io.LimitReader(r.Body, m.cfg.MaxBodyBytes+1))
		if err != nil {
			// Let the live request surface the error; nothing to mirror.
			r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf), &errReader{err}))
			return nil
		}
		if int64(len(buf)) > m.cfg.MaxBodyBytes {
			// Over the bound: hand what was read back to the live request
			// followed by the rest, and do not mirror.
			r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf), r.Body))
			st.mirror = "body_too_large"
			s.stats.MirrorSkipped.Add(1)
			return nil
		}
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(buf))
		body = buf
	}
	// The copy is built like the live outbound request: same path rules,
	// host and header operations, plus the mirror marker.
	pr := &httputil.ProxyRequest{In: r, Out: r.Clone(context.Background())}
	pr.Out.Body = io.NopCloser(bytes.NewReader(body))
	pr.Out.ContentLength = int64(len(body))
	pr.Out.RequestURI = ""
	// The live copy goes through ReverseProxy, which drops hop-by-hop
	// headers; the mirror is sent directly, so drop them here.
	httpx.StripHopByHop(pr.Out.Header)
	s.rewrite(pr, st, cr)
	pr.Out.URL.Scheme = m.pool.Scheme
	pr.Out.Header.Set(mirrorHeader, "1")
	return pr.Out
}

// sendMirror delivers a copy in the background, bounded by the route's
// in-flight count and timeout. The response is discarded; only its
// status reaches the debug log.
func (s *Server) sendMirror(out *http.Request, st *reqState, cr *compiledRoute) {
	m := cr.mirror
	select {
	case m.sem <- struct{}{}:
	default:
		st.mirror = "dropped"
		s.stats.MirrorDropped.Add(1)
		return
	}
	st.mirror = "sent"
	s.stats.MirrorSent.Add(1)
	id, route := st.id, st.route
	go func() {
		defer func() { <-m.sem }()
		ctx, cancel := context.WithTimeout(context.Background(), m.cfg.Timeout.D())
		defer cancel()
		req := out.WithContext(withPick(ctx, &pickInfo{hashKey: out.Header.Get("X-Real-Ip")}))
		tr := &poolTransport{pool: m.pool, retries: 0}
		start := time.Now()
		resp, err := tr.RoundTrip(req)
		if err != nil {
			s.stats.MirrorFailed.Add(1)
			s.logs.Error.Debug("mirror failed", "request_id", id, "route", route, "upstream", m.pool.Name, "err", err.Error())
			return
		}
		if m.diff != nil && st.shadow != nil {
			// Traffic shadowing: summarise the shadow response and compare
			// it with the live one once the client has finished reading.
			sum := summarise(resp.Body, m.diff.maxBody)
			sum.status = resp.StatusCode
			sum.headers = selectHeaders(resp.Header, m.diff.headers)
			select {
			case <-st.shadow.done:
				s.reportDiff(m.diff, st, sum)
			case <-time.After(m.cfg.Timeout.D()):
				// The live response did not finish within the budget; the
				// comparison is skipped rather than reported against a
				// partial capture.
			}
			return
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
		s.logs.Error.Debug("mirror sent", "request_id", id, "route", route, "upstream", m.pool.Name, "status", resp.StatusCode,
			"duration_ms", float64(time.Since(start).Microseconds())/1000)
	}()
}

type errReader struct{ err error }

func (e *errReader) Read([]byte) (int, error) { return 0, e.err }
