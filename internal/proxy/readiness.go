package proxy

import (
	"sort"
	"sync"
	"time"
)

// Readiness answers one question: should this node be carrying traffic
// right now?
//
// It exists because a pair of nodes sharing an address -- keepalived, VRRP,
// a load balancer's own health check -- needs an answer with an *exit
// code*, and the answer has to be about more than whether the process is
// alive. A process that is alive, bound, and cannot reach a single upstream
// endpoint is the worst state to hold an address in: it accepts every
// connection and fails every request, where a node that stood down would
// have let its peer take them.
//
// Three things can make a node say no, and they are deliberately separate
// because an operator has to choose which ones matter for their estate
// (docs/HA.md):
//
//   - It was told to. An operator steps a node down before maintenance, and
//     the check script reports it, so the address moves *before* anything
//     is restarted rather than during. This is the one an operator uses.
//   - It has no healthy endpoint for a pool that has endpoints configured.
//     Whether this should move an address is a judgement: with two nodes on
//     the same network it usually means the upstream is down for both, and
//     failing over gains nothing. It is therefore opt-in.
//   - Something it needs is unavailable -- a sandbox mechanism that failed
//     to apply. Also a judgement, because a proxy without a seccomp filter
//     is still a proxy, so this too is opt-in.
//
// What is never a reason is a busy node. Load is what a load balancer is
// for; a node that stands down under load hands its peer the same load and
// twice the connections.
type Readiness struct {
	// Serving is the verdict under the options asked for.
	Serving bool `json:"serving"`
	// Reasons say why not, or why a node is short of ideal while still
	// serving. Each is one sentence, worst first.
	Reasons []string `json:"reasons,omitempty"`
	// SteppedDown is set when an operator took this node out.
	SteppedDown bool `json:"stepped_down,omitempty"`
	// StepReason and StepAt record who said so and when, as given.
	StepReason string    `json:"step_reason,omitempty"`
	StepAt     time.Time `json:"step_at,omitempty"`
	// Listeners is how many are bound.
	Listeners int `json:"listeners"`
	// PoolsWithoutEndpoints names the upstream pools that have endpoints
	// configured and none healthy.
	PoolsWithoutEndpoints []string `json:"pools_without_endpoints,omitempty"`
	// Degraded names the mechanisms that are not doing their job.
	Degraded []string `json:"degraded,omitempty"`
}

// ReadinessOptions say which of the reasons count against serving. The
// zero value is the narrow question -- is this node up and has nobody
// stood it down -- which is what a VRRP check script wants by default.
type ReadinessOptions struct {
	// RequireUpstreams makes a pool with no healthy endpoint a refusal.
	RequireUpstreams bool
	// RequireUndegraded makes an unavailable hardening mechanism a
	// refusal. It is applied by WithDegraded, because the sandbox status
	// belongs to the process that applied it.
	RequireUndegraded bool
}

// stepDown is the operator's switch. It is deliberately not persisted:
// a node that has restarted is a node whose state an operator has not
// seen, and the safe default for a proxy is to serve. An estate that
// needs a step-down to survive a restart writes it into the
// configuration instead (docs/HA.md).
type stepDown struct {
	mu     sync.Mutex
	down   bool
	reason string
	at     time.Time
}

// SetServing steps this node down or back up. The reason is recorded and
// reported; an empty one is fine.
func (s *Server) SetServing(serving bool, reason string) Readiness {
	s.step.mu.Lock()
	s.step.down = !serving
	s.step.reason = reason
	s.step.at = time.Now()
	s.step.mu.Unlock()
	s.logs.Security.Warn("node serving state changed", "serving", serving, "reason", reason)
	return s.Readiness(ReadinessOptions{})
}

// Readiness answers whether this node should be carrying traffic.
func (s *Server) Readiness(opt ReadinessOptions) Readiness {
	r := Readiness{Serving: true}

	s.step.mu.Lock()
	r.SteppedDown, r.StepReason = s.step.down, s.step.reason
	if !s.step.at.IsZero() {
		r.StepAt = s.step.at
	}
	s.step.mu.Unlock()
	if r.SteppedDown {
		r.Serving = false
		what := "an operator stepped this node down"
		if r.StepReason != "" {
			what += ": " + r.StepReason
		}
		r.Reasons = append(r.Reasons, what)
	}

	s.mu.Lock()
	r.Listeners = len(s.listeners)
	s.mu.Unlock()
	if r.Listeners == 0 {
		// Nothing is bound, so there is nothing to carry traffic with,
		// whatever the options say.
		r.Serving = false
		r.Reasons = append(r.Reasons, "no listener is bound")
	}

	for name, eps := range s.Upstreams() {
		if len(eps) == 0 {
			// A pool configured without endpoints is a configuration the
			// operator chose; discovery may fill it later.
			continue
		}
		healthy := 0
		for _, ep := range eps {
			if ep.Healthy && !ep.Ejected && !ep.Draining {
				healthy++
			}
		}
		if healthy == 0 {
			r.PoolsWithoutEndpoints = append(r.PoolsWithoutEndpoints, name)
		}
	}
	sort.Strings(r.PoolsWithoutEndpoints)
	if len(r.PoolsWithoutEndpoints) > 0 {
		what := "no healthy endpoint in " + joinNames(r.PoolsWithoutEndpoints)
		if opt.RequireUpstreams {
			r.Serving = false
		}
		r.Reasons = append(r.Reasons, what)
	}

	return r
}

// WithDegraded folds the hardening mechanisms that are not doing their job
// into a verdict. The sandbox status is held by the process that applied
// it rather than by the proxy, which is why it arrives here instead of
// being read above.
func (r Readiness) WithDegraded(degraded []string, required bool) Readiness {
	if len(degraded) == 0 {
		return r
	}
	r.Degraded = append([]string(nil), degraded...)
	sort.Strings(r.Degraded)
	if required {
		r.Serving = false
	}
	r.Reasons = append(r.Reasons, "hardening degraded: "+joinNames(r.Degraded))
	return r
}

// joinNames reads a short list the way a sentence would.
func joinNames(in []string) string {
	switch len(in) {
	case 0:
		return ""
	case 1:
		return in[0]
	}
	out := ""
	for i, s := range in {
		switch {
		case i == 0:
			out = s
		case i == len(in)-1:
			out += " and " + s
		default:
			out += ", " + s
		}
	}
	return out
}
