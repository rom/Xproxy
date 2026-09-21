package proxy

import (
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/netutil"
)

// Deceptive answers on real routes.
//
// A refusal is information. A scanner that gets 403 has learned that
// the request it sent was the interesting one, and it will vary that
// request until something is not refused — the refusal is the oracle
// that tells it when it has found the way through.
//
// An answer that looks ordinary gives it nothing to steer by. The
// crawl completes, the data is wrong, and the request that would have
// worked looks exactly like the one that did not.
//
// This is the sharpest tool in the file, because the failure mode is a
// real client quietly receiving nonsense. Everything here is built so
// that cannot happen by accident: a route must name a condition, the
// conditions are ones the proxy already has a reason to trust, and
// every deceived request is loud in the logs and separate in the
// counters.

// deceivePolicy is the compiled route setting.
type deceivePolicy struct {
	cfg      *config.Deceive
	clients  []netip.Prefix
	methods  map[string]bool
	body     []byte
	ctype    string
	mark     time.Duration
	scoreAt  float64
	onScore  bool
	onMarked bool
	served   atomic.Uint64
}

func newDeceivePolicy(c *config.Deceive) (*deceivePolicy, error) {
	p := &deceivePolicy{
		cfg: c, ctype: c.ContentType, mark: c.Mark.D(),
		onMarked: c.Marked, onScore: c.BotScoreAt > 0, scoreAt: float64(c.BotScoreAt),
	}
	p.clients = netutil.ParsePrefixes(c.ClientCIDRs)
	if len(c.Methods) > 0 {
		p.methods = map[string]bool{}
		for _, m := range c.Methods {
			p.methods[strings.ToUpper(m)] = true
		}
	}
	switch {
	case c.Decoy != "":
		d := decoys[c.Decoy]
		p.body, p.ctype = []byte(d.body), d.contentType
	case c.BodyFile != "":
		b, err := readBounded(c.BodyFile, 1<<20)
		if err != nil {
			return nil, err
		}
		p.body = b
	default:
		p.body = []byte(c.Body)
	}
	return p, nil
}

// admits reports whether this request gets the lie. It is asked only
// for routes that configured one.
func (p *deceivePolicy) admits(st *reqState, r *http.Request) bool {
	if p.methods != nil && !p.methods[strings.ToUpper(r.Method)] {
		return false
	}
	if p.onMarked && st.marked {
		return true
	}
	if p.onScore {
		if score, ok := botScoreOf(st); ok && score >= p.scoreAt {
			return true
		}
	}
	return len(p.clients) > 0 && netutil.Contains(p.clients, st.clientIP)
}

// deceive answers the request with the configured body. The origin is
// never asked: for a write that is the point, and it is why the
// conditions are worth being sure of.
func (s *Server) deceive(rw *responseWriter, r *http.Request, st *reqState, cr *compiledRoute) {
	p := cr.deceive
	p.served.Add(1)
	s.stats.Deceived.Add(1)
	st.extra = append(st.extra, "deceived", cr.cfg.Name)
	// Loud on the inside, so nobody debugs a "working" endpoint for a
	// week: this is a security event like any other refusal, and the
	// only one whose answer looks like success.
	s.logs.SecurityEvent(r.Context(), "deceive", "deceive",
		"request_id", st.id, "client_ip", st.clientIP.String(), "method", r.Method,
		"host", r.Host, "path", st.path, "route", cr.cfg.Name, "user_agent", r.UserAgent(),
		"status", p.cfg.Status, "marked", st.marked)
	if p.mark > 0 {
		// Keep the client on the same answer for as long as the mark
		// lasts, so a scanner does not see the endpoint change its mind
		// between requests.
		s.marks.add(st.clientIP, "deceive:"+cr.cfg.Name, p.mark, time.Now())
	}
	h := rw.Header()
	h.Set("Content-Type", p.ctype)
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	cr.respOps.apply(h, &tvars{r: r, st: st})
	rw.WriteHeader(p.cfg.Status)
	if r.Method != http.MethodHead {
		_, _ = rw.Write(p.body)
	}
}

// DeceiveStatus is one row of the management view.
type DeceiveStatus struct {
	Route  string `json:"route"`
	Status int    `json:"status"`
	Served uint64 `json:"served"`
	Marked bool   `json:"marked,omitempty"`
	Score  int    `json:"bot_score_at,omitempty"`
	Bytes  int    `json:"body_bytes"`
}

// Deceptions reports the routes that answer some clients with a lie.
func (s *Server) Deceptions() []DeceiveStatus {
	rt := s.rt.Load()
	if rt == nil {
		return nil
	}
	out := make([]DeceiveStatus, 0, len(rt.routes))
	for _, cr := range rt.routes {
		if cr.deceive == nil {
			continue
		}
		p := cr.deceive
		out = append(out, DeceiveStatus{
			Route: cr.cfg.Name, Status: p.cfg.Status, Served: p.served.Load(),
			Marked: p.onMarked, Score: p.cfg.BotScoreAt, Bytes: len(p.body),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
