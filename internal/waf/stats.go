package waf

import (
	"fmt"
	"hash/fnv"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/corazawaf/coraza/v3/types"

	"github.com/rom/xproxy/internal/bound"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/waf/wafstatus"
)

// Stats collects per rule statistics and, when learning is enabled, the
// matched variables that feed exclusion proposals. One Stats lives for the
// life of the process and is shared by every configuration generation, so
// counts survive reloads while an operator tunes a rule set (reset it with
// POST /v1/waf/reset).
//
// The request path touches no shared lock: the per rule counters are
// atomics in a concurrent map keyed by rule id (a new rule takes one
// insertion), and the learning table is sharded by key hash so that
// concurrent requests only meet when they match the same rule on the same
// target and route.
type Stats struct {
	started atomic.Int64 // unix nanoseconds
	now     func() time.Time

	requests atomic.Uint64
	blocked  atomic.Uint64
	detected atomic.Uint64

	rules        sync.Map // int -> *ruleCounter
	ruleCount    atomic.Int64
	rulesDropped bound.Notice

	learning atomic.Pointer[learnConfig]
	shards   [learnShards]learnShard
	entries  atomic.Int64
	dropped  bound.Notice

	// schemaViolations counts JSON body schema violations (blocked or
	// detected); anomaly is the behavioural detector.
	schemaViolations atomic.Uint64
	anomaly          anomaly
}

// maxRules bounds the rule table; the CRS has a few hundred rules and
// custom sets rarely exceed a thousand.
const maxRules = 8192

// maxLearnEntries bounds the learning table when the configuration sets
// no max_entries.
const maxLearnEntries = 10000

// learnShards is the number of independently locked learning tables.
const learnShards = 16

// NewStats creates an empty statistics table.
func NewStats() *Stats {
	s := &Stats{now: time.Now}
	s.started.Store(s.now().UnixNano())
	for i := range s.shards {
		s.shards[i].entries = map[learnKey]*learnEntry{}
	}
	s.anomaly.init(func() time.Time { return s.now() })
	return s
}

// ruleCounter is one rule's live counters.
type ruleCounter struct {
	id       int
	message  string
	severity string
	tags     []string
	matches  atomic.Uint64
	blocks   atomic.Uint64
	detects  atomic.Uint64
	lastSeen atomic.Int64
	lastURI  atomic.Pointer[string]
}

// learnConfig is the learning setting of the active generation.
type learnConfig struct {
	enabled    bool
	minHits    int
	maxEntries int
}

// learnShard is one lock's worth of the learning table.
type learnShard struct {
	mu      sync.Mutex
	entries map[learnKey]*learnEntry
}

// learnKey identifies a (rule, target, route) triple.
type learnKey struct {
	rule   int
	target string
	route  string
}

func (k learnKey) shard() int {
	h := fnv.New32a()
	_, _ = h.Write([]byte(k.target))
	_, _ = h.Write([]byte(k.route))
	return int(h.Sum32()^uint32(k.rule)) % learnShards //nolint:gosec // rule ids are small positive
}

type learnEntry struct {
	hits     uint64
	clients  map[string]struct{}
	lastSeen time.Time
	lastURI  string
	message  string
	sample   string
}

// maxClientsPerEntry bounds the distinct client set kept per entry.
const maxClientsPerEntry = 64

// Configure applies the learning and anomaly settings of a configuration
// generation.
func (s *Stats) Configure(l *config.WAFLearning, a *config.WAFAnomaly) {
	s.anomaly.configure(a)
	if l == nil || !l.Enabled {
		s.learning.Store(&learnConfig{})
		return
	}
	c := &learnConfig{enabled: true, minHits: l.MinHits, maxEntries: l.MaxEntries}
	if c.maxEntries <= 0 {
		c.maxEntries = maxLearnEntries
	}
	s.learning.Store(c)
}

func (s *Stats) config() *learnConfig {
	if c := s.learning.Load(); c != nil {
		return c
	}
	return &learnConfig{}
}

// Reset clears every counter and the learning table.
func (s *Stats) Reset() {
	s.requests.Store(0)
	s.blocked.Store(0)
	s.detected.Store(0)
	s.rules.Range(func(k, _ any) bool { s.rules.Delete(k); return true })
	s.ruleCount.Store(0)
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.Lock()
		sh.entries = map[learnKey]*learnEntry{}
		sh.mu.Unlock()
	}
	s.entries.Store(0)
	s.schemaViolations.Store(0)
	s.anomaly.reset()
	s.started.Store(s.now().UnixNano())
}

// record accounts one finished transaction.
func (s *Stats) record(in *instance) {
	s.requests.Add(1)
	blocked := in.verdict != nil
	detected := !blocked && in.f.mode == ModeDetect && in.detected()
	if blocked {
		s.blocked.Add(1)
	}
	if detected {
		s.detected.Add(1)
	}
	if in.schema != nil {
		s.schemaViolations.Add(1)
	}
	if in.flag != nil {
		s.anomaly.acted.Add(1)
	}
	now := s.now()
	rules := in.tx.MatchedRules()
	matched := false
	for _, m := range rules {
		if relevant(m) {
			matched = true
			break
		}
	}
	errored := blocked || in.schema != nil || in.status >= 400
	s.anomaly.observe(in.info.ClientIP.String(), in.info.Path, matched || in.schema != nil, errored, now)
	if len(rules) == 0 {
		return
	}
	cfg := s.config()
	for _, m := range rules {
		if !relevant(m) {
			continue
		}
		r := m.Rule()
		rc := s.counter(r, m)
		if rc == nil {
			continue
		}
		rc.matches.Add(1)
		if blocked {
			rc.blocks.Add(1)
		}
		if detected {
			rc.detects.Add(1)
		}
		rc.lastSeen.Store(now.UnixNano())
		uri := trimURI(m.URI())
		rc.lastURI.Store(&uri)
		if cfg.enabled && isAttackRule(r) {
			s.learn(cfg, m, in, now)
		}
	}
}

// counter returns the live counters of a rule, creating them on first
// sight; nil when the table is full (counted and warned).
func (s *Stats) counter(r types.RuleMetadata, m types.MatchedRule) *ruleCounter {
	if v, ok := s.rules.Load(r.ID()); ok {
		return v.(*ruleCounter)
	}
	if s.ruleCount.Load() >= maxRules {
		s.rulesDropped.Hit(nil, "waf rule statistics table full; further rules are not counted", "table", "waf_rules", "max", maxRules, "rule", r.ID())
		return nil
	}
	rc := &ruleCounter{id: r.ID(), message: m.Message(), severity: r.Severity().String(), tags: keepTags(r.Tags())}
	if v, loaded := s.rules.LoadOrStore(r.ID(), rc); loaded {
		return v.(*ruleCounter)
	}
	s.ruleCount.Add(1)
	return rc
}

// isAttackRule reports whether r is a detection rule whose targets can be
// excluded, as opposed to a scoring or reporting rule.
func isAttackRule(r types.RuleMetadata) bool {
	if r.ID() == 949110 || r.ID() == 959100 {
		return false
	}
	for _, t := range r.Tags() {
		if strings.HasPrefix(t, "attack-") {
			return true
		}
	}
	return len(r.Tags()) == 0 || !hasTag(r.Tags(), "OWASP_CRS")
}

func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}

// keepTags keeps the informative tags: attack class and paranoia level.
func keepTags(tags []string) []string {
	var out []string
	for _, t := range tags {
		if strings.HasPrefix(t, "attack-") || strings.HasPrefix(t, "paranoia-level/") || strings.HasPrefix(t, "platform-") || strings.HasPrefix(t, "language-") {
			out = append(out, t)
		}
	}
	return out
}

func trimURI(u string) string {
	if len(u) > 256 {
		return u[:256]
	}
	return u
}

// learn records the matched variables of a detection rule.
func (s *Stats) learn(cfg *learnConfig, m types.MatchedRule, in *instance, now time.Time) {
	for _, md := range m.MatchedDatas() {
		target := md.Variable().Name()
		if k := md.Key(); k != "" {
			target += ":" + k
		}
		key := learnKey{rule: m.Rule().ID(), target: target, route: in.info.Route}
		sh := &s.shards[key.shard()]
		sh.mu.Lock()
		e := sh.entries[key]
		if e == nil {
			if s.entries.Load() >= int64(cfg.maxEntries) {
				sh.mu.Unlock()
				s.dropped.Hit(nil, "waf learning table full; new (rule, target, route) entries are dropped", "table", "waf_learning", "max", cfg.maxEntries)
				continue
			}
			e = &learnEntry{clients: map[string]struct{}{}, message: m.Message()}
			sh.entries[key] = e
			s.entries.Add(1)
		}
		e.hits++
		if len(e.clients) < maxClientsPerEntry {
			e.clients[in.info.ClientIP.String()] = struct{}{}
		}
		e.lastSeen = now
		e.lastURI = trimURI(m.URI())
		if e.sample == "" {
			e.sample = trimURI(md.Value())
		}
		sh.mu.Unlock()
	}
}

// Report builds the management view with at most top rules. paths maps
// route names to path prefixes for scoping proposals.
func (s *Stats) Report(top int, paths map[string]string) Report {
	rep := Report{Since: time.Unix(0, s.started.Load()), Requests: s.requests.Load(), Blocked: s.blocked.Load(), Detected: s.detected.Load(),
		Rules: []RuleStat{}, RulesDropped: s.rulesDropped.Total(), SchemaViolations: s.schemaViolations.Load(), Anomaly: s.anomaly.report()}
	s.rules.Range(func(_, v any) bool {
		rc := v.(*ruleCounter)
		st := RuleStat{ID: rc.id, Message: rc.message, Severity: rc.severity, Tags: append([]string(nil), rc.tags...),
			Matches: rc.matches.Load(), Blocks: rc.blocks.Load(), Detects: rc.detects.Load()}
		if ns := rc.lastSeen.Load(); ns != 0 {
			st.LastSeen = time.Unix(0, ns)
		}
		if u := rc.lastURI.Load(); u != nil {
			st.LastURI = *u
		}
		rep.Rules = append(rep.Rules, st)
		return true
	})
	rep.TotalRules = len(rep.Rules)
	sort.Slice(rep.Rules, func(i, j int) bool {
		if rep.Rules[i].Matches != rep.Rules[j].Matches {
			return rep.Rules[i].Matches > rep.Rules[j].Matches
		}
		return rep.Rules[i].ID < rep.Rules[j].ID
	})
	if top >= 0 && len(rep.Rules) > top {
		rep.Rules = rep.Rules[:top]
	}
	cfg := s.config()
	rep.Learning = &LearningReport{Enabled: cfg.enabled, MinHits: cfg.minHits, Entries: int(s.entries.Load()),
		MaxEntries: cfg.maxEntries, Dropped: s.dropped.Total(), Proposals: s.Proposals(paths)}
	return rep
}

// Proposals returns the current exclusion proposals.
func (s *Stats) Proposals(paths map[string]string) []Proposal {
	cfg := s.config()
	minHits := uint64(max(cfg.minHits, 1)) //nolint:gosec // validated positive
	out := []Proposal{}
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.Lock()
		for k, e := range sh.entries {
			if e.hits < minHits {
				continue
			}
			out = append(out, Proposal{Rule: k.rule, Message: e.message, Target: k.target, Route: k.route, Path: paths[k.route],
				Hits: e.hits, Clients: len(e.clients), LastSeen: e.lastSeen, LastURI: e.lastURI, Sample: e.sample})
		}
		sh.mu.Unlock()
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Hits != out[j].Hits {
			return out[i].Hits > out[j].Hits
		}
		if out[i].Rule != out[j].Rule {
			return out[i].Rule < out[j].Rule
		}
		if out[i].Route != out[j].Route {
			return out[i].Route < out[j].Route
		}
		return out[i].Target < out[j].Target
	})
	for i := range out {
		out[i].Directive = directive(&out[i], proposalBaseID+i)
	}
	return out
}

// proposalBaseID is the first rule ID given to generated exclusions. CRS
// reserves 1 to 99,999 for local rules.
const proposalBaseID = 10000

// directive renders one proposal as SecLang. A proposal with a path is
// scoped to requests under that prefix through a phase 1 ctl action; one
// without applies to every request of the profile through an
// unconditional SecAction. Both forms are ctl actions, evaluated per
// request, because directive files load before the CRS rules where a
// SecRuleUpdateTargetById would not find its rule yet.
func directive(p *Proposal, id int) string {
	target := quoteTarget(p.Target)
	if p.Path == "" {
		return fmt.Sprintf("SecAction \"id:%d,phase:1,pass,t:none,nolog,ctl:ruleRemoveTargetById=%d;%s\"", id, p.Rule, target)
	}
	return fmt.Sprintf("SecRule REQUEST_URI \"@beginsWith %s\" \"id:%d,phase:1,pass,t:none,nolog,ctl:ruleRemoveTargetById=%d;%s\"",
		strings.ReplaceAll(p.Path, "\"", ""), id, p.Rule, target)
}

// quoteTarget escapes a VARIABLE:key for use inside a quoted directive.
func quoteTarget(t string) string {
	t = strings.ReplaceAll(t, "\\", "\\\\")
	t = strings.ReplaceAll(t, "\"", "\\\"")
	return strings.ReplaceAll(t, ",", "\\,")
}

// Exclusions renders the proposals as a SecLang file ready to be reviewed
// and placed in a profile's directive_files.
func (s *Stats) Exclusions(paths map[string]string) string {
	props := s.Proposals(paths)
	var b strings.Builder
	fmt.Fprintf(&b, "# xproxy WAF exclusion proposals generated %s\n", s.now().UTC().Format(time.RFC3339))
	b.WriteString("# Review every line before use: a proposal means the rule matched the target\n")
	b.WriteString("# repeatedly, not that the traffic was legitimate.\n")
	if len(props) == 0 {
		b.WriteString("# (no proposals)\n")
		return b.String()
	}
	for _, p := range props {
		fmt.Fprintf(&b, "\n# rule %d: %s\n# route %s, %d hits from %d clients, last %s\n", p.Rule, p.Message,
			orDash(p.Route), p.Hits, p.Clients, p.LastSeen.UTC().Format(time.RFC3339))
		if p.Sample != "" {
			fmt.Fprintf(&b, "# sample: %s\n", strings.ReplaceAll(p.Sample, "\n", " "))
		}
		b.WriteString(p.Directive)
		b.WriteString("\n")
	}
	return b.String()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// The management view of the WAF is a leaf package, so a daemon can
// serve it without linking the engine; these names stay here because
// this is where the code that fills them in lives.
type (
	RuleStat       = wafstatus.RuleStat
	Report         = wafstatus.Report
	LearningReport = wafstatus.LearningReport
	Proposal       = wafstatus.Proposal
)
