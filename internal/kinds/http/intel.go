package http

import (
	"net/http"

	"github.com/rom/xproxy/internal/challenge"
	"github.com/rom/xproxy/internal/intel"
)

// Imported threat intelligence: lists of client addresses and TLS
// fingerprints somebody else attributed, and what the operator asked for
// about a match.
//
// The check sits after routing, so a route can be exempt from it, and
// before the challenge gate, so a list that asks for a challenge gets
// one. It is deliberately not where the ban check is. A ban is this
// proxy's own finding about this client and applies to everything,
// including the health endpoint; a list is an import, and an import with
// one wrong line in it must not take the endpoint an operator watches the
// outage with.

// threatIntel applies the lists to one request. It reports true when the
// request has been answered and the handler must stop.
func (s *engine) threatIntel(rw *responseWriter, r *http.Request, st *reqState, exempt bool) bool {
	set := s.host.ThreatIntel()
	if set == nil || exempt {
		return false
	}
	hit, ok := set.Match(st.clientIP, st.ja4)
	if !ok {
		return false
	}
	st.extra = append(st.extra, "threat_list", hit.List)
	s.stats.ThreatIntelMatched.Add(1)
	if s.cfg().ThreatIntel.Logs() && hit.Action == intel.ActionLog {
		// A list that only logs still says so, once per matching
		// request: a list nobody can see matching is a list nobody can
		// tune. The other two actions write their own event.
		s.logs.SecurityEvent(r.Context(), "allow", "threat_intel",
			"request_id", st.id, "client_ip", st.clientIP.String(), "route", st.route,
			"list", hit.List, "kind", hit.Kind, "action", hit.Action)
	}
	switch hit.Action {
	case intel.ActionBlock:
		s.stats.ThreatIntelBlocked.Add(1)
		st.denied = "threat_intel:" + hit.List
		// deny writes the security event and hands the ban list the
		// reason, so a trigger can escalate on an imported list exactly
		// as it does on this proxy's own refusals.
		s.denyDetail(rw, r, st, http.StatusForbidden, "threat_intel", hit.List)
		return true
	case intel.ActionChallenge:
		ch := s.challenger.Load()
		if ch == nil || ch.Exempt(st.clientIP) || st.chalTier >= challenge.TierProof {
			// Nothing to challenge with, or the client has already
			// proved itself. A list that asks for a challenge where
			// there is none does not become a block: that would be a
			// policy the operator did not write.
			return false
		}
		s.stats.ThreatIntelChallenged.Add(1)
		st.denied = "threat_intel:" + hit.List
		s.logs.SecurityEvent(r.Context(), "challenge", "threat_intel",
			"request_id", st.id, "client_ip", st.clientIP.String(), "route", st.route,
			"list", hit.List, "kind", hit.Kind)
		ch.Serve(rw, r, st.clientIP)
		return true
	}
	return false
}
