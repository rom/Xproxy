package http

import (
	"net/http"

	"github.com/rom/xproxy/internal/authorization"
)

// The estate's authorisation policy on an HTTP listener.
//
// This was the last listener kind outside the `authorization` section, and it was
// outside for a reason rather than by oversight: every other kind has a session,
// and a session is what that section decides about. A gateway's unit of work is a
// request, and what a request may do is already decided by its route and by the
// `authz` filter in that route's chain.
//
// What was missing is the question above both of them, and it is a real one: *may
// this client be served by this listener at all, towards this pool, at this hour.*
// A route cannot answer it, because a route is one of the things being decided
// about, and the `authz` filter cannot, because it needs a verified identity and
// this question is about clients that have not offered one. An estate that says
// "nothing from the vendor network reaches the internal pool outside working
// hours" is saying something no part of the gateway could previously be told.
//
// # Where it is asked, and why there
//
// After routing and before the challenge gate and the filter chain -- the same
// point the imported lists are asked, for the same reason. After routing, so a
// rule's `targets` can name the route's upstream pool, which is what makes a rule
// about where traffic may go writable at all. Before the filters, so a refused
// client's request never reaches a WAF, a body buffer or an upstream.
//
// Unlike the lists it is **not** route-exemptable. A list is an import and a route
// may reasonably opt out of somebody else's feed; the estate's own policy is above
// a route, and a route that could opt out of it would not be a policy.
//
// # What it does not decide
//
// The subject carries no user. The gateway does establish identities -- that is
// what its authenticating filters are for -- but per route, and what a verified
// identity may then do is the `authz` filter's decision. Filling `User` here would
// put the same question in two places with two answers. So a rule naming `users`,
// `principals` or `groups` matches nobody on this kind, exactly as on the relays
// that have no identity at all, and a rule here is written with `networks`,
// `targets`, `listeners` and `schedule`.
//
// # Cost
//
// This is per request rather than per connection, because a connection carries
// requests for many routes and the pool is not known until one is matched. A
// policy walk on the request path is worth being careful about, so the cheap case
// is the common one: Policy.Ask returns on a nil policy before it does anything,
// which is every estate that has not written the section.
//
// It also does not go through internal/admit, and that is deliberate rather than
// an inconsistency. That package asks the lists and then the policy, in one order,
// for the kinds whose list handling is a simple block. This kind's list handling is
// not simple: it has per-route exemptions and a `challenge` action that serves a
// real challenge page, both of which admit flattens because the kinds it serves
// have no request to challenge into. Routing this kind through it would trade a
// working challenge for a uniform call site.
func (s *engine) authorization(rw *responseWriter, r *http.Request, st *reqState, cr *compiledRoute) bool {
	p := s.host.Authorization()
	if p == nil {
		return false
	}
	target := ""
	if cr != nil {
		if cr.pool != nil {
			target = cr.pool.Name
		} else if cr.cfg != nil {
			target = cr.cfg.Upstream
		}
	}
	listener := ""
	shadowing := func() bool { return false }
	if st.ln != nil {
		listener = st.ln.Name
		shadowing = st.ln.Shadowing
	}
	// Deny records rather than acts: on the other kinds it counts and logs,
	// because they refuse by closing a socket. Here only the caller has the
	// writer, so it takes the rule and the detail and answers the request itself.
	var rule, detail string
	reason := p.Ask(authorization.Subject{
		Listener: listener,
		Kind:     "http",
		Client:   st.clientIP,
		Target:   target,
		Action:   authorization.ActionConnect,
	}, st.clientIP.String(), authorization.Gate{
		Shadowing: shadowing,
		Record: func(reason, rule, detail string) {
			s.stats.WouldRefuse("http", reason)
			s.host.Shadow().Record("http", listener, reason, rule, detail)
		},
		Deny: func(_, rl, dt string) { rule, detail = rl, dt },
	})
	if reason == "" {
		return false
	}
	st.denied = reason
	if rule != "" {
		st.denied = reason + ":" + rule
		st.extra = append(st.extra, "authz_rule", rule)
	}
	s.stats.Refuse("http", reason)
	// A 403 rather than a dropped connection, so a client library reports a
	// refusal instead of hanging on a socket that went away.
	s.denyDetail(rw, r, st, http.StatusForbidden, reason, detail)
	return true
}
