package http

import (
	"sort"
	"time"

	"github.com/rom/xproxy/internal/apiinv"
	"github.com/rom/xproxy/internal/cache"
	"github.com/rom/xproxy/internal/filters/accountguard"
	"github.com/rom/xproxy/internal/filters/botscore"
	"github.com/rom/xproxy/internal/filters/sensitive"
	"github.com/rom/xproxy/internal/geoip"
	"github.com/rom/xproxy/internal/icap"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/tracing"
	"github.com/rom/xproxy/internal/waf"
)

// The management view of the data plane. Every method here answers for
// the live generation; the engine's method of the same name delegates
// to it and answers a zero value in a daemon that linked no plane.

// Snapshot adds the plane's counters to the engine's snapshot. What is
// here is what only the data plane knows: requests in flight on its
// generations, the gates it holds and the filters it alone links.
func (s *engine) Snapshot(snap *proxy.Snapshot) {
	snap.InFlight = s.concurrency.InFlight()
	snap.TarpitActive = s.tarpits.InFlight()
	snap.HoneypotMarked = len(s.marks.list(time.Now()))
	snap.BufferedBody = s.bodyBudget.Stats()
	if sh := s.shedder.Load(); sh != nil {
		ss := sh.Snapshot()
		snap.LoadLevel = ss.Level
		snap.UpstreamLatencyMS = ss.LatencyMS
		snap.SheddingClasses = []string{}
		if ss.SheddingLow {
			snap.SheddingClasses = append(snap.SheddingClasses, "low")
		}
		if ss.SheddingNorm {
			snap.SheddingClasses = append(snap.SheddingClasses, "normal")
		}
		if ss.SheddingHigh {
			snap.SheddingClasses = append(snap.SheddingClasses, "high")
		}
	}
	if ch := s.challenger.Load(); ch != nil {
		snap.ChallengesIssued, snap.ChallengesPassed, snap.ChallengesFailed, snap.CaptchasPassed = ch.Stats()
	}
	for _, f := range sensitive.Snapshot().Findings {
		snap.SensitiveFindings += f.Count
	}
	ac := accountguard.Status(0)
	snap.AccountBlocks, snap.AccountCampaigns = ac.Counters.Blocks, ac.Counters.Campaigns
	for _, g := range ac.Guards {
		for _, ep := range g.Endpoints {
			snap.AccountBlocksActive += ep.ActiveBlocks
		}
	}
}

// WAF builds the WAF report with at most top rules.
func (s *engine) WAF(top int) proxy.WAFReport {
	rt := s.rt.Load()
	rep := proxy.WAFReport{Profiles: []waf.ProfileStatus{}, Routes: []proxy.WAFRoute{}}
	if rt.waf != nil {
		rep.Enabled = true
		rep.Profiles = rt.waf.Profiles()
	}
	for _, cr := range rt.routes {
		if cr.wafMode == "" || cr.wafMode == string(waf.ModeOff) {
			continue
		}
		p, _ := wafSelection(rt.cfg, cr.cfg)
		wr := proxy.WAFRoute{Route: cr.cfg.Name, Profile: p, Mode: cr.wafMode, BlockPercent: 100}
		if cr.wafMode == string(waf.ModeBlock) {
			wr.BlockPercent = cr.cfg.WAF.Percent()
			if cr.cfg.WAF != nil {
				wr.BlockCIDRs = cr.cfg.WAF.BlockCIDRs
			}
		} else {
			wr.BlockPercent = 0
		}
		rep.Routes = append(rep.Routes, wr)
	}
	rep.Report = s.wafStats.Report(top, rt.routePaths())
	return rep
}

// WAFExclusions renders the learning proposals as SecLang.
func (s *engine) WAFExclusions() string { return s.wafStats.Exclusions(s.rt.Load().routePaths()) }

// WAFReset clears the WAF statistics and learning table.
func (s *engine) WAFReset() { s.wafStats.Reset() }

// routePaths maps every route to its first path prefix, "" for regex
// routes, for scoping exclusion proposals.
func (rt *runtime) routePaths() map[string]string {
	out := make(map[string]string, len(rt.routes))
	for _, cr := range rt.routes {
		if len(cr.cfg.PathRegex) == 0 && len(cr.cfg.Paths) > 0 {
			out[cr.cfg.Name] = cr.cfg.Paths[0]
		} else {
			out[cr.cfg.Name] = ""
		}
	}
	return out
}

// Filters lists the configured middleware instances.
func (s *engine) Filters() []proxy.FilterStatus { return s.rt.Load().filterStatus() }

// ICAP lists the configured ICAP services, by name.
func (s *engine) ICAP() []icap.Status {
	rt := s.rt.Load()
	out := make([]icap.Status, 0, len(rt.icap))
	for _, svc := range rt.icap {
		out = append(out, svc.Status())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// GeoIP reports the country database, and whether one is configured.
func (s *engine) GeoIP() (geoip.Status, bool) {
	rt := s.rt.Load()
	if rt.geo == nil {
		return geoip.Status{}, false
	}
	return rt.geo.Status(), true
}

// CacheStats reports the response cache, and whether one is configured.
func (s *engine) CacheStats() (cache.Stats, bool) {
	c := s.cache.Load()
	if c == nil {
		return cache.Stats{}, false
	}
	return c.Stats(), true
}

// PurgeCache drops the entries of a host and path prefix.
func (s *engine) PurgeCache(host, prefix string) (int, bool) {
	c := s.cache.Load()
	if c == nil {
		return 0, false
	}
	return c.Purge(host, prefix), true
}

// Accounts returns the live state of the account_guard filters with up
// to top active blocks per endpoint.
func (s *engine) Accounts(top int) accountguard.Report { return accountguard.Status(top) }

// BotScore returns the learning-mode baselines and threshold suggestions
// of every bot_score filter running with learn: true, up to top routes
// each.
func (s *engine) BotScore(top int) botscore.Report { return botscore.Status(top) }

// APIInventory builds the inventory view: all, shadow, zombie,
// versions, documented or undocumented, at most top items.
func (s *engine) APIInventory(view string, top int) apiinv.Report {
	rt := s.rt.Load()
	docs := map[string][]apiinv.Operation{}
	for _, cr := range rt.routes {
		if !cr.inventory {
			continue
		}
		for _, d := range cr.describers {
			docs[cr.cfg.Name] = append(docs[cr.cfg.Name], d.Operations()...)
		}
	}
	return s.inventory.Report(view, top, docs, time.Now())
}

// Tracing returns the tracer status, or nil when tracing is off.
func (s *engine) Tracing() *tracing.Status {
	tr := s.tracer.Load()
	if tr == nil {
		return nil
	}
	st := tr.Status()
	return &st
}
