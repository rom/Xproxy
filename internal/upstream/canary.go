package upstream

import (
	"math/rand/v2"
	"net/http"
	"sync/atomic"
)

// CanaryMode says which endpoints a request may use.
type CanaryMode int

// Canary modes.
const (
	CanaryAny   CanaryMode = iota // no canary policy: every endpoint
	CanaryOnly                    // canary endpoints, the rest as fallback
	CanaryAvoid                   // ordinary endpoints, canaries as fallback
)

// CanaryStatus is the management view of a pool's canary policy.
type CanaryStatus struct {
	Header    string  `json:"header,omitempty"`
	Cookie    string  `json:"cookie,omitempty"`
	Percent   float64 `json:"percent"`
	Endpoints int     `json:"endpoints"`
	Requests  uint64  `json:"requests"`
	Fallbacks uint64  `json:"fallbacks"`
}

// canaryState is the pool's compiled policy.
type canaryState struct {
	header, cookie string
	values         map[string]bool
	percent        float64
	fallback       bool
	count          int
	requests       atomic.Uint64
	fallbacks      atomic.Uint64
}

// CanaryMode classifies a request under the pool's canary policy:
// CanaryOnly when the header or cookie selects it (with one of `values`
// when listed) or when it falls in the `percent` share, CanaryAvoid
// otherwise, CanaryAny when the pool has no policy.
func (p *Pool) CanaryMode(r *http.Request) CanaryMode {
	c := p.canary
	if c == nil {
		return CanaryAny
	}
	if c.header != "" {
		if v := r.Header.Get(c.header); v != "" && (len(c.values) == 0 || c.values[v]) {
			return CanaryOnly
		}
	}
	if c.cookie != "" {
		if ck, err := r.Cookie(c.cookie); err == nil && (len(c.values) == 0 || c.values[ck.Value]) {
			return CanaryOnly
		}
	}
	if c.percent > 0 && rand.Float64()*100 < c.percent { //nolint:gosec // traffic split, not security
		return CanaryOnly
	}
	return CanaryAvoid
}

// canaryExclude adds the endpoints the mode rules out to exclude and
// returns the merged set (exclude itself when nothing changes).
func (p *Pool) canaryExclude(mode CanaryMode, exclude map[*Endpoint]bool) map[*Endpoint]bool {
	if mode == CanaryAny || p.canary == nil {
		return exclude
	}
	want := mode == CanaryOnly
	out := make(map[*Endpoint]bool, len(exclude)+len(p.endpoints))
	for e, v := range exclude {
		out[e] = v
	}
	for _, e := range p.endpoints {
		if e.Canary != want {
			out[e] = true
		}
	}
	return out
}
