package proxy

import (
	"errors"
	"net/netip"
	"sort"

	"github.com/rom/xproxy/internal/apiinv"
	"github.com/rom/xproxy/internal/cache"
	"github.com/rom/xproxy/internal/filters/accountguard"
	"github.com/rom/xproxy/internal/filters/botscore"
	"github.com/rom/xproxy/internal/geoip"
	"github.com/rom/xproxy/internal/icap"
	"github.com/rom/xproxy/internal/waf/wafstatus"
)

// The management views of the data plane, delegated.
//
// A daemon that linked no plane answers each of these with its zero
// value rather than an error: `xproxyctl waf` against the bastion
// reports a WAF that is not enabled, which is true, instead of failing
// in a way an operator has to look up.

// errNoPlane is the one case where a zero value would be a lie: an
// action was asked for and nothing can perform it.
var errNoPlane = errors.New("this daemon serves no http listeners")

// WAF reports the web application firewall.
func (s *Server) WAF(top int) WAFReport {
	if pl := s.planeOrNil(); pl != nil {
		return pl.WAF(top)
	}
	return WAFReport{Profiles: []wafstatus.ProfileStatus{}, Routes: []WAFRoute{}}
}

// WAFExclusions renders the learned proposals as SecLang.
func (s *Server) WAFExclusions() string {
	if pl := s.planeOrNil(); pl != nil {
		return pl.WAFExclusions()
	}
	return ""
}

// WAFReset clears the rule statistics.
func (s *Server) WAFReset() {
	if pl := s.planeOrNil(); pl != nil {
		pl.WAFReset()
	}
}

// Filters lists the configured middleware instances.
func (s *Server) Filters() []FilterStatus {
	if pl := s.planeOrNil(); pl != nil {
		return pl.Filters()
	}
	return []FilterStatus{}
}

// ICAP lists the configured scanning services. They belong to the
// engine rather than to a data plane, so every daemon reports its own
// -- a bastion that scans sftp writes has services to report and no
// plane to ask.
func (s *Server) ICAP() []icap.Status {
	rt := s.rt.Load()
	out := make([]icap.Status, 0, len(rt.icap))
	for _, svc := range rt.icap {
		out = append(out, svc.Status())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ICAPService implements Host: a scanning service by name, from the
// generation serving now.
func (s *Server) ICAPService(name string) *icap.Service {
	if name == "" {
		return nil
	}
	return s.rt.Load().icap[name]
}

// GeoIP reports the country database, and whether one is configured.
func (s *Server) GeoIP() (geoip.Status, bool) {
	if pl := s.planeOrNil(); pl != nil {
		return pl.GeoIP()
	}
	return geoip.Status{}, false
}

// CacheStats reports the response cache, and whether one is configured.
func (s *Server) CacheStats() (cache.Stats, bool) {
	if pl := s.planeOrNil(); pl != nil {
		return pl.CacheStats()
	}
	return cache.Stats{}, false
}

// PurgeCache drops the entries of a host and path prefix and returns how
// many went, and whether there was a cache to purge.
func (s *Server) PurgeCache(host, prefix string) (int, bool) {
	if pl := s.planeOrNil(); pl != nil {
		return pl.PurgeCache(host, prefix)
	}
	return 0, false
}

// Quotas reports usage per tenant, route and rate limit policy.
func (s *Server) Quotas(top int) QuotaReport {
	if pl := s.planeOrNil(); pl != nil {
		return pl.Quotas(top)
	}
	return QuotaReport{Tenants: []TenantQuota{}, Routes: []RouteQuota{}, RateLimits: []PolicyQuota{}, Upstreams: []UpstreamLoad{}}
}

// VirtualPatches lists the structured patches and their hits.
func (s *Server) VirtualPatches() []PatchStatus {
	if pl := s.planeOrNil(); pl != nil {
		return pl.VirtualPatches()
	}
	return []PatchStatus{}
}

// Honeytokens lists the planted credentials and their hits.
func (s *Server) Honeytokens() []HoneytokenStatus {
	if pl := s.planeOrNil(); pl != nil {
		return pl.Honeytokens()
	}
	return []HoneytokenStatus{}
}

// Deceptions lists the routes answering deceptively.
func (s *Server) Deceptions() []DeceiveStatus {
	if pl := s.planeOrNil(); pl != nil {
		return pl.Deceptions()
	}
	return []DeceiveStatus{}
}

// Degradation lists the graduated degradation levels.
func (s *Server) Degradation() []DegradeStatus {
	if pl := s.planeOrNil(); pl != nil {
		return pl.Degradation()
	}
	return []DegradeStatus{}
}

// WebSocketGuards lists the per route frame inspectors.
func (s *Server) WebSocketGuards() []WSGuardStatus {
	if pl := s.planeOrNil(); pl != nil {
		return pl.WebSocketGuards()
	}
	return []WSGuardStatus{}
}

// Decoys names the built-in honeypot decoys this binary carries.
func (s *Server) Decoys() []string {
	if pl := s.planeOrNil(); pl != nil {
		return pl.Decoys()
	}
	return []string{}
}

// HoneypotMarks lists the clients a honeypot marked.
func (s *Server) HoneypotMarks() []Mark {
	if pl := s.planeOrNil(); pl != nil {
		return pl.HoneypotMarks()
	}
	return []Mark{}
}

// HoneypotMarksDropped counts marks the bounded table refused.
func (s *Server) HoneypotMarksDropped() uint64 {
	if pl := s.planeOrNil(); pl != nil {
		return pl.HoneypotMarksDropped()
	}
	return 0
}

// UnmarkHoneypot withdraws a mark this node made.
func (s *Server) UnmarkHoneypot(ip netip.Addr) bool {
	if pl := s.planeOrNil(); pl != nil {
		return pl.UnmarkHoneypot(ip)
	}
	return false
}

// Maintenance reads or sets the maintenance toggle. configured is false
// without a maintenance section, and also in a daemon with no data
// plane, where there is nothing to hold open or closed.
func (s *Server) Maintenance(on *bool) (state, configured bool) {
	if pl := s.planeOrNil(); pl != nil {
		return pl.Maintenance(on)
	}
	return false, false
}

// OriginCheck asks an upstream whether it enforces the signed origin
// header. It is an action rather than a view, so with no data plane it
// says so instead of answering an empty result.
func (s *Server) OriginCheck(upstreamName, host, path string) ([]OriginCheckResult, error) {
	if pl := s.planeOrNil(); pl != nil {
		return pl.OriginCheck(upstreamName, host, path)
	}
	return nil, errNoPlane
}

// Accounts reports the account guard.
func (s *Server) Accounts(top int) accountguard.Report {
	if pl := s.planeOrNil(); pl != nil {
		return pl.Accounts(top)
	}
	return accountguard.Report{Guards: []accountguard.GuardStatus{}}
}

// BotScore reports the behavioural bot scorer.
func (s *Server) BotScore(top int) botscore.Report {
	if pl := s.planeOrNil(); pl != nil {
		return pl.BotScore(top)
	}
	return botscore.Report{}
}

// APIInventory reports the endpoints discovered from traffic.
func (s *Server) APIInventory(view string, top int) apiinv.Report {
	if pl := s.planeOrNil(); pl != nil {
		return pl.APIInventory(view, top)
	}
	return apiinv.Report{Items: []apiinv.Endpoint{}}
}
