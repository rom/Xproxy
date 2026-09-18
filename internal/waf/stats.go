package waf

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/corazawaf/coraza/v3/types"

	"github.com/rom/xproxy/internal/config"
)

// Stats collects per rule statistics and, when learning is enabled, the
// matched variables that feed exclusion proposals. One Stats lives for the
// life of the process and is shared by every configuration generation, so
// counts survive reloads while an operator tunes a rule set (reset it with
// POST /v1/waf/reset).
type Stats struct {
	started time.Time
	now     func() time.Time

	requests atomic.Uint64
	blocked  atomic.Uint64
	detected atomic.Uint64

	mu       sync.Mutex
	rules    map[int]*RuleStat
	learning learning
}

// maxRules bounds the rule table; the CRS has a few hundred rules and
// custom sets rarely exceed a thousand.
const maxRules = 8192

// maxLearnEntries bounds the learning table when the configuration sets
// no max_entries.
const maxLearnEntries = 10000

// NewStats creates an empty statistics table.
func NewStats() *Stats {
	now := time.Now
	return &Stats{started: now(), now: now, rules: map[int]*RuleStat{}, learning: learning{entries: map[learnKey]*learnEntry{}}}
}

// RuleStat is one rule's counters.
type RuleStat struct {
	ID       int    `json:"id"`
	Message  string `json:"message,omitempty"`
	Severity string `json:"severity,omitempty"`
	// Tags keeps the attack- and paranoia-level tags of the rule.
	Tags []string `json:"tags,omitempty"`
	// Matches counts transactions in which the rule matched. Blocks counts
	// those the WAF denied (block mode); Detects counts those detect mode
	// would have denied.
	Matches  uint64    `json:"matches"`
	Blocks   uint64    `json:"blocks"`
	Detects  uint64    `json:"detects"`
	LastSeen time.Time `json:"last_seen"`
	LastURI  string    `json:"last_uri,omitempty"`
}

// learning is the exclusion learning state.
type learning struct {
	enabled    bool
	minHits    int
	maxEntries int
	entries    map[learnKey]*learnEntry
	dropped    uint64
}

// learnKey identifies a (rule, target, route) triple.
type learnKey struct {
	rule   int
	target string
	route  string
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

// Configure applies the learning settings of a configuration generation.
func (s *Stats) Configure(l *config.WAFLearning) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if l == nil || !l.Enabled {
		s.learning.enabled = false
		return
	}
	s.learning.enabled = true
	s.learning.minHits = l.MinHits
	s.learning.maxEntries = l.MaxEntries
	if s.learning.maxEntries <= 0 {
		s.learning.maxEntries = maxLearnEntries
	}
}

// Reset clears every counter and the learning table.
func (s *Stats) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests.Store(0)
	s.blocked.Store(0)
	s.detected.Store(0)
	s.rules = map[int]*RuleStat{}
	s.learning.entries = map[learnKey]*learnEntry{}
	s.learning.dropped = 0
	s.started = s.now()
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
	rules := in.tx.MatchedRules()
	if len(rules) == 0 {
		return
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, m := range rules {
		if !relevant(m) {
			continue
		}
		r := m.Rule()
		st := s.rules[r.ID()]
		if st == nil {
			if len(s.rules) >= maxRules {
				continue
			}
			st = &RuleStat{ID: r.ID(), Message: m.Message(), Severity: r.Severity().String(), Tags: keepTags(r.Tags())}
			s.rules[r.ID()] = st
		}
		st.Matches++
		if blocked {
			st.Blocks++
		}
		if detected {
			st.Detects++
		}
		st.LastSeen = now
		st.LastURI = trimURI(m.URI())
		if s.learning.enabled && isAttackRule(r) {
			s.learn(m, in, now)
		}
	}
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
func (s *Stats) learn(m types.MatchedRule, in *instance, now time.Time) {
	l := &s.learning
	for _, md := range m.MatchedDatas() {
		target := md.Variable().Name()
		if k := md.Key(); k != "" {
			target += ":" + k
		}
		key := learnKey{rule: m.Rule().ID(), target: target, route: in.info.Route}
		e := l.entries[key]
		if e == nil {
			if len(l.entries) >= l.maxEntries {
				l.dropped++
				continue
			}
			e = &learnEntry{clients: map[string]struct{}{}, message: m.Message()}
			l.entries[key] = e
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
	}
}

// Report is the management view (GET /v1/waf).
type Report struct {
	Since    time.Time `json:"since"`
	Requests uint64    `json:"requests"`
	Blocked  uint64    `json:"blocked"`
	Detected uint64    `json:"detected"`
	// Rules lists the matched rules, most matched first, at most top
	// entries; TotalRules is the number of distinct rules seen.
	Rules      []RuleStat      `json:"rules"`
	TotalRules int             `json:"total_rules"`
	Learning   *LearningReport `json:"learning"`
}

// LearningReport describes the learning table and its proposals.
type LearningReport struct {
	Enabled    bool       `json:"enabled"`
	MinHits    int        `json:"min_hits"`
	Entries    int        `json:"entries"`
	MaxEntries int        `json:"max_entries"`
	Dropped    uint64     `json:"dropped"`
	Proposals  []Proposal `json:"proposals"`
}

// Proposal is one suggested exclusion: rule ID and target seen together at
// least min_hits times on a route.
type Proposal struct {
	Rule    int    `json:"rule"`
	Message string `json:"message,omitempty"`
	Target  string `json:"target"`
	Route   string `json:"route,omitempty"`
	// Path is the route's path prefix when known, used to scope the
	// generated exclusion; "" scopes it to the whole profile.
	Path      string    `json:"path,omitempty"`
	Hits      uint64    `json:"hits"`
	Clients   int       `json:"clients"`
	LastSeen  time.Time `json:"last_seen"`
	LastURI   string    `json:"last_uri,omitempty"`
	Sample    string    `json:"sample,omitempty"`
	Directive string    `json:"directive"`
}

// Report builds the management view with at most top rules. paths maps
// route names to path prefixes for scoping proposals.
func (s *Stats) Report(top int, paths map[string]string) Report {
	s.mu.Lock()
	defer s.mu.Unlock()
	rep := Report{Since: s.started, Requests: s.requests.Load(), Blocked: s.blocked.Load(), Detected: s.detected.Load(),
		Rules: make([]RuleStat, 0, len(s.rules)), TotalRules: len(s.rules)}
	for _, r := range s.rules {
		c := *r
		c.Tags = append([]string(nil), r.Tags...)
		rep.Rules = append(rep.Rules, c)
	}
	sort.Slice(rep.Rules, func(i, j int) bool {
		if rep.Rules[i].Matches != rep.Rules[j].Matches {
			return rep.Rules[i].Matches > rep.Rules[j].Matches
		}
		return rep.Rules[i].ID < rep.Rules[j].ID
	})
	if top >= 0 && len(rep.Rules) > top {
		rep.Rules = rep.Rules[:top]
	}
	l := &s.learning
	rep.Learning = &LearningReport{Enabled: l.enabled, MinHits: l.minHits, Entries: len(l.entries),
		MaxEntries: l.maxEntries, Dropped: l.dropped, Proposals: s.proposalsLocked(paths)}
	return rep
}

// Proposals returns the current exclusion proposals.
func (s *Stats) Proposals(paths map[string]string) []Proposal {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.proposalsLocked(paths)
}

func (s *Stats) proposalsLocked(paths map[string]string) []Proposal {
	l := &s.learning
	out := []Proposal{}
	for k, e := range l.entries {
		if e.hits < uint64(max(l.minHits, 1)) { //nolint:gosec // minHits is validated positive
			continue
		}
		p := Proposal{Rule: k.rule, Message: e.message, Target: k.target, Route: k.route, Path: paths[k.route],
			Hits: e.hits, Clients: len(e.clients), LastSeen: e.lastSeen, LastURI: e.lastURI, Sample: e.sample}
		out = append(out, p)
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
