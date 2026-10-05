package forward

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/schedule"
)

// The egress policy: who may send what, where, and when.
//
// `allow` and `deny` answer whether a destination exists for this listener at
// all. This answers the question after that, which is the one an estate running
// a forward proxy actually has: the build agents may reach the package mirrors
// and nothing else, nobody may POST to file sharing, the vendor's support portal
// is reachable during the change window, and an upload of a hundred megabytes to
// a destination in no category is a finding whoever made it.
//
// # Where a rule can be decided
//
// A forward proxy sees two different things, and the difference is the whole
// shape of this file.
//
// A plain request through the proxy -- an absolute URI, which is how HTTP
// without TLS travels through a proxy -- carries its method, its path, its
// content type and usually its length. Every selector can be decided about it.
//
// A CONNECT tunnel carries a destination and nothing else. Everything else is
// inside TLS, so a rule naming a method decides nothing there. It is not
// silently ignored: the rule is skipped at the tunnel's admission point,
// validation says which rules those are, and the management API marks them, so
// an operator can see that a rule covers the plain path only. Making those rules
// decide inside a tunnel means reading the requests in it, which is what
// `intercept` is for and is its own piece of work.
//
// That asymmetry is honest rather than convenient. A policy that claimed to
// stop uploads and did not would be worse than no policy, because somebody
// would stop looking.

// egressPolicy is a listener's compiled rules.
type egressPolicy struct {
	// rules are pointers because a rule counts its own decisions, and a
	// counter is not a thing to copy.
	rules []*egressRule
	// cats maps a category name, folded, to its destination patterns.
	cats map[string][]destRule
	// groups maps a user name to the groups it is in, both folded.
	groups map[string][]string
	// requestOnly counts the rules that can only be decided about a visible
	// request, for the report.
	requestOnly int
}

// egressRule is one compiled rule.
type egressRule struct {
	name    string
	action  string
	comment string

	users, notUsers   map[string]bool
	groups, notGroups map[string]bool
	nets, notNets     []netip.Prefix
	cats, notCats     []string
	hosts, notHosts   []destRule
	ports             map[int]bool

	methods            map[string]bool
	paths              []*regexp.Regexp
	reqTypes, respType []string
	reqOver, respOver  int64

	window *schedule.Window

	// request is true when the rule names something only a visible request
	// can answer, so a tunnel's admission point skips it. response is true
	// when it names something only the response head can answer, so the
	// request point skips it too and the response point is where it decides.
	request, response bool
	// hits counts the decisions this rule made, for the report. It lives in
	// the compiled rule, so a reload starts the count again -- which is the
	// right answer, because the rule after a reload may not be the same rule.
	hits atomic.Uint64
}

// egressSubject is what one decision is about. The request fields are set only
// where a request is visible.
type egressSubject struct {
	client netip.Addr
	user   string
	host   string
	ips    []netip.Addr
	port   int

	// phase says which of the fields below mean anything.
	phase     egressPhase
	method    string
	path      string
	reqType   string
	respType  string
	reqBytes  int64
	respBytes int64
	// ignoreSize asks the rules as though every body were small enough, which
	// is how the size a rule would refuse at is found before a body is sent.
	ignoreSize bool

	at time.Time
}

// The three points at which this policy is asked, which differ in what is
// known rather than in what the rules say.
type egressPhase int

const (
	// phaseSession is a tunnel being opened: a destination, an identity and an
	// hour, and nothing else. Rules that name a request are skipped.
	phaseSession egressPhase = iota
	// phaseRequest is a visible request before its response: everything except
	// what the response will say.
	phaseRequest
	// phaseResponse is the response head having arrived. Only the rules that
	// name something about the response are asked here, so no rule is asked
	// twice about one request -- and nothing matching is not a refusal, because
	// the request was already allowed through phaseRequest.
	phaseResponse
)

// requestFacts are what a visible request says about itself: everything the
// egress rules can ask that a tunnel cannot answer.
type requestFacts struct {
	method      string
	path        string
	contentType string
	// bytes is the declared body length, or -1 when there is none to declare.
	bytes int64
}

// An egress decision.
type egressDecision struct {
	// Allowed is false when the policy refuses.
	Allowed bool
	// Reason is the refusal's reason, in the spelling the counters use:
	// rule_deny for a rule that refused, no_rule for nothing matching.
	Reason string
	// Rule and Comment name the rule that decided, where one did.
	Rule, Comment string
	// Observed are the names of the observe rules that matched on the way,
	// which is how a rule is tried before it decides anything.
	Observed []string
}

// compileEgress builds the policy from a listener's configuration. An empty
// rules list is no policy at all and returns nil, which is how a listener that
// does not want one pays nothing for it.
func compileEgress(fc *config.ForwardListener) (*egressPolicy, error) {
	if len(fc.Rules) == 0 && len(fc.Categories) == 0 {
		return nil, nil
	}
	p := &egressPolicy{cats: map[string][]destRule{}, groups: map[string][]string{}}
	for i := range fc.Categories {
		c := &fc.Categories[i]
		patterns := append([]string{}, c.Hosts...)
		if c.File != "" {
			more, err := readPatternFile(c.File)
			if err != nil {
				return nil, fmt.Errorf("category %s: %w", c.Name, err)
			}
			patterns = append(patterns, more...)
		}
		rules, err := compileDestRules(patterns)
		if err != nil {
			return nil, fmt.Errorf("category %s: %w", c.Name, err)
		}
		p.cats[strings.ToLower(c.Name)] = rules
	}
	if fc.Auth != nil {
		for name, members := range fc.Auth.Groups {
			g := strings.ToLower(name)
			for _, m := range members {
				u := strings.ToLower(m)
				p.groups[u] = append(p.groups[u], g)
			}
		}
	}
	p.rules = make([]*egressRule, 0, len(fc.Rules))
	for i := range fc.Rules {
		r, err := compileEgressRule(&fc.Rules[i])
		if err != nil {
			return nil, err
		}
		if r.request {
			p.requestOnly++
		}
		p.rules = append(p.rules, r)
	}
	return p, nil
}

func compileEgressRule(c *config.ForwardRule) (*egressRule, error) {
	r := &egressRule{name: c.Name, action: c.Action, comment: c.Comment}
	if r.action == "" {
		r.action = "deny"
	}
	r.users, r.notUsers = foldSet(c.Users), foldSet(c.NotUsers)
	r.groups, r.notGroups = foldSet(c.Groups), foldSet(c.NotGroups)
	var err error
	if r.nets, err = parsePrefixes(c.Networks); err != nil {
		return nil, fmt.Errorf("rule %s: networks: %w", c.Name, err)
	}
	if r.notNets, err = parsePrefixes(c.NotNetworks); err != nil {
		return nil, fmt.Errorf("rule %s: not_networks: %w", c.Name, err)
	}
	r.cats, r.notCats = lowerAll(c.Categories), lowerAll(c.NotCategories)
	if r.hosts, err = compileDestRules(c.Hosts); err != nil {
		return nil, fmt.Errorf("rule %s: hosts: %w", c.Name, err)
	}
	if r.notHosts, err = compileDestRules(c.NotHosts); err != nil {
		return nil, fmt.Errorf("rule %s: not_hosts: %w", c.Name, err)
	}
	if len(c.Ports) > 0 {
		r.ports = map[int]bool{}
		for _, port := range c.Ports {
			r.ports[port] = true
		}
	}
	if len(c.Methods) > 0 {
		r.methods = map[string]bool{}
		for _, m := range c.Methods {
			r.methods[strings.ToUpper(m)] = true
		}
	}
	if r.paths, err = compilePaths(c.Paths); err != nil {
		return nil, fmt.Errorf("rule %s: paths: %w", c.Name, err)
	}
	r.reqTypes, r.respType = lowerAll(c.RequestTypes), lowerAll(c.ResponseTypes)
	r.reqOver, r.respOver = c.RequestBytesOver, c.ResponseBytesOver
	if c.Schedule != nil {
		if r.window, err = schedule.Compile(c.Schedule); err != nil {
			return nil, fmt.Errorf("rule %s: schedule: %w", c.Name, err)
		}
	}
	r.response = len(r.respType) > 0 || r.respOver > 0
	r.request = r.response || len(r.methods) > 0 || len(r.paths) > 0 ||
		len(r.reqTypes) > 0 || r.reqOver > 0
	return r, nil
}

// Decide runs the policy. A rule that needs a visible request is skipped when
// there is none, so the answer for a tunnel is the answer the destination,
// the identity and the hour give.
func (p *egressPolicy) Decide(sub egressSubject) egressDecision {
	if p == nil || len(p.rules) == 0 {
		return egressDecision{Allowed: true}
	}
	d := egressDecision{}
	for _, r := range p.rules {
		if !r.asks(sub.phase) {
			continue
		}
		if !r.matches(p, sub) {
			continue
		}
		if r.action == "observe" {
			// An observe rule records and keeps looking, which is how a rule is
			// tried on live traffic before it is allowed to decide anything.
			r.hits.Add(1)
			d.Observed = append(d.Observed, r.name)
			continue
		}
		r.hits.Add(1)
		d.Rule, d.Comment = r.name, r.comment
		d.Allowed = r.action == "allow"
		if !d.Allowed {
			d.Reason = "rule_deny"
		}
		return d
	}
	if sub.phase == phaseResponse {
		// Nothing had anything to say about the response, which is not a
		// refusal: the request got here by being allowed.
		d.Allowed = true
		return d
	}
	// Nothing matched. The destination is refused, for the reason every other
	// policy in this project gives: what nobody wrote a rule for is not
	// permitted by default, because a gap that permits is a gap nobody sees.
	d.Reason = "no_rule"
	return d
}

// asks reports whether this rule is one of the rules asked at this phase. Each
// rule is asked at exactly one of them, which is what keeps a rule from
// deciding twice about one request.
func (r *egressRule) asks(phase egressPhase) bool {
	switch phase {
	case phaseSession:
		return !r.request
	case phaseRequest:
		return !r.response
	default:
		return r.response
	}
}

// matches is every selector the rule names, all of which have to hold.
func (r *egressRule) matches(p *egressPolicy, sub egressSubject) bool {
	user := strings.ToLower(sub.user)
	if len(r.users) > 0 && !r.users[user] {
		return false
	}
	if len(r.notUsers) > 0 && r.notUsers[user] {
		return false
	}
	if len(r.groups) > 0 || len(r.notGroups) > 0 {
		in := p.groups[user]
		if len(r.groups) > 0 && !anyIn(r.groups, in) {
			return false
		}
		if len(r.notGroups) > 0 && anyIn(r.notGroups, in) {
			return false
		}
	}
	if len(r.nets) > 0 && !inAnyPrefix(r.nets, sub.client) {
		return false
	}
	if len(r.notNets) > 0 && inAnyPrefix(r.notNets, sub.client) {
		return false
	}
	if len(r.cats) > 0 && !r.inAnyCategory(p, r.cats, sub) {
		return false
	}
	if len(r.notCats) > 0 && r.inAnyCategory(p, r.notCats, sub) {
		return false
	}
	if len(r.hosts) > 0 && !anyRule(r.hosts, sub.host, sub.ips) {
		return false
	}
	if len(r.notHosts) > 0 && anyRule(r.notHosts, sub.host, sub.ips) {
		return false
	}
	if len(r.ports) > 0 && !r.ports[sub.port] {
		return false
	}
	if r.window != nil && !r.window.InForce(sub.at) {
		return false
	}
	if sub.phase == phaseSession {
		return true
	}
	return r.matchesRequest(sub)
}

// matchesRequest is the half a tunnel cannot answer. The response selectors are
// compared only at the response phase, where there is a response to compare
// them with.
func (r *egressRule) matchesRequest(sub egressSubject) bool {
	if len(r.methods) > 0 && !r.methods[strings.ToUpper(sub.method)] {
		return false
	}
	if len(r.paths) > 0 && !anyPath(r.paths, sub.path) {
		return false
	}
	if len(r.reqTypes) > 0 && !anyMedia(r.reqTypes, sub.reqType) {
		return false
	}
	if sub.phase == phaseResponse && len(r.respType) > 0 && !anyMedia(r.respType, sub.respType) {
		return false
	}
	// A bound matches a body larger than it. An unknown length is not larger
	// than anything: a chunked body is counted while it travels and the rule is
	// asked again with what was counted, rather than guessed about here.
	if !sub.ignoreSize && r.reqOver > 0 && sub.reqBytes <= r.reqOver {
		return false
	}
	if !sub.ignoreSize && sub.phase == phaseResponse && r.respOver > 0 && sub.respBytes <= r.respOver {
		return false
	}
	return true
}

// inAnyCategory reports whether the destination is in any of the named
// categories. A name no category defines cannot get here: validation refuses
// a rule that names one.
func (r *egressRule) inAnyCategory(p *egressPolicy, names []string, sub egressSubject) bool {
	for _, n := range names {
		if anyRule(p.cats[n], sub.host, sub.ips) {
			return true
		}
	}
	return false
}

// BodyBound is the size at which a body stops being allowed, for a body whose
// length was not declared.
//
// A declared length is decided before anything is sent, which is the whole value
// of a size rule. A chunked body has no declared length, and a rule about one
// then has two choices: ignore it, or count what goes past and cut the
// connection when the count passes the bound. Ignoring it would make
// request_bytes_over a rule an upload avoids by not declaring its size, which is
// one header's worth of bypass.
//
// So this answers "at what size would a rule refuse this", and the caller counts.
// What has already gone cannot be recalled -- the first ten megabytes of an
// exfiltration are gone whatever happens next -- and that is the honest limit of
// a size rule on egress, said here and in the protocol page rather than left for
// somebody to assume otherwise.
func (p *egressPolicy) BodyBound(sub egressSubject) (bound int64, rule, comment string) {
	if p == nil {
		return 0, "", ""
	}
	sub.ignoreSize = true
	for _, r := range p.rules {
		var over int64
		switch sub.phase {
		case phaseResponse:
			over = r.respOver
		default:
			over = r.reqOver
		}
		if over <= 0 || r.action != "deny" || !r.asks(sub.phase) {
			continue
		}
		if !r.matches(p, sub) {
			continue
		}
		if bound == 0 || over < bound {
			bound, rule, comment = over, r.name, r.comment
		}
	}
	return bound, rule, comment
}

// Report is what the management API says about the policy.
type Report struct {
	// Rules are the rules in order, with what each one has decided.
	Rules []RuleStatus `json:"rules,omitempty"`
	// Categories are the category names with how many patterns each holds.
	Categories map[string]int `json:"categories,omitempty"`
	// RequestOnly counts the rules that can only be decided about a visible
	// request, which inside a tunnel this listener does not intercept is
	// none of them. It is here so an operator reading the report sees the
	// limit rather than discovering it.
	RequestOnly int `json:"request_only,omitempty"`
}

// RuleStatus is one rule, as the report gives it.
type RuleStatus struct {
	Name    string `json:"name"`
	Action  string `json:"action"`
	Hits    uint64 `json:"hits"`
	Comment string `json:"comment,omitempty"`
	// Request is true when this rule needs a visible request, so it decides
	// nothing inside a tunnel.
	Request bool `json:"request,omitempty"`
}

// Report builds the status of the compiled policy.
func (p *egressPolicy) Report() Report {
	if p == nil {
		return Report{}
	}
	rep := Report{Categories: map[string]int{}, RequestOnly: p.requestOnly}
	for name, rules := range p.cats {
		rep.Categories[name] = len(rules)
	}
	rep.Rules = make([]RuleStatus, 0, len(p.rules))
	for _, r := range p.rules {
		rep.Rules = append(rep.Rules, RuleStatus{Name: r.name, Action: r.action,
			Hits: r.hits.Load(), Comment: r.comment, Request: r.request})
	}
	return rep
}

// EgressStatus is what GET /v1/listeners says about this listener's rules.
//
// nil where there are none, so the field is absent for every listener that is
// not policing egress. The one number it exists for is RequestOnly beside
// Reading: rules that need a visible request, on a listener that is not reading
// inside its tunnels, are a policy about the plain path alone.
func (f *forwardServer) EgressStatus() *proxy.EgressStatus {
	p := f.policy.Load()
	if p == nil || p.egress == nil {
		return nil
	}
	rep := p.egress.Report()
	if len(rep.Rules) == 0 {
		return nil
	}
	return &proxy.EgressStatus{Rules: len(rep.Rules), RequestOnly: rep.RequestOnly,
		Reading: f.wantsHTTP(p, "")}
}

// maxPatternFileBytes bounds a category file. A list of domains is a text file
// somebody maintains, and sixteen megabytes of it is a mistake.
const maxPatternFileBytes = 16 << 20

// maxPatternFileLines bounds how many patterns one file may hold.
const maxPatternFileLines = 200000

// readPatternFile reads destination patterns, one per line, # for a comment.
//
// A file that cannot be read is an error rather than an empty category: a
// category silently smaller than the policy says is a policy that permits what
// it was written to refuse.
func readPatternFile(path string) ([]string, error) {
	f, err := os.Open(path) //nolint:gosec // a category file named in the configuration
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() > maxPatternFileBytes {
		return nil, fmt.Errorf("%s: %d bytes is more than the %d a category file may hold",
			path, st.Size(), maxPatternFileBytes)
	}
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 4<<10), 64<<10)
	line := 0
	for sc.Scan() {
		line++
		if len(out) >= maxPatternFileLines {
			return nil, fmt.Errorf("%s: more than %d patterns", path, maxPatternFileLines)
		}
		t := strings.TrimSpace(sc.Text())
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		out = append(out, t)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return out, nil
}

// foldSet is a set of names compared without case.
func foldSet(list []string) map[string]bool {
	if len(list) == 0 {
		return nil
	}
	out := make(map[string]bool, len(list))
	for _, s := range list {
		out[strings.ToLower(s)] = true
	}
	return out
}

func lowerAll(list []string) []string {
	if len(list) == 0 {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, s := range list {
		out = append(out, strings.ToLower(s))
	}
	return out
}

func anyIn(want map[string]bool, have []string) bool {
	for _, h := range have {
		if want[h] {
			return true
		}
	}
	return false
}

func parsePrefixes(list []string) ([]netip.Prefix, error) {
	if len(list) == 0 {
		return nil, nil
	}
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p)
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("%q is not an address or CIDR", s)
		}
		out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
	}
	return out, nil
}

func inAnyPrefix(nets []netip.Prefix, ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Path patterns.
//
// A pattern is translated to a regular expression once, at load: * matches
// anything within one path segment and ** matches across segments, which is the
// convention an operator has met before and -- more to the point -- the one that
// does not have a trap in it. With only *, "any .zip anywhere" cannot be
// written, and somebody would write "*.zip", read it as that, and have a rule
// that matched a .zip at the root and nowhere else.
//
// The translation quotes everything else, so a pattern is a pattern and never a
// regular expression somebody wrote by accident. The result has no nested
// quantifier and cannot backtrack badly.
func compilePaths(patterns []string) ([]*regexp.Regexp, error) {
	if len(patterns) == 0 {
		return nil, nil
	}
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, pat := range patterns {
		if len(pat) > maxPathPattern {
			return nil, fmt.Errorf("%q is longer than the %d characters a path pattern may have",
				pat, maxPathPattern)
		}
		var b strings.Builder
		b.WriteString("^")
		for i := 0; i < len(pat); {
			switch {
			case strings.HasPrefix(pat[i:], "**"):
				b.WriteString(".*")
				i += 2
			case pat[i] == '*':
				b.WriteString("[^/]*")
				i++
			default:
				b.WriteString(regexp.QuoteMeta(pat[i : i+1]))
				i++
			}
		}
		b.WriteString("$")
		re, err := regexp.Compile(b.String())
		if err != nil {
			return nil, fmt.Errorf("%q: %w", pat, err)
		}
		out = append(out, re)
	}
	return out, nil
}

// maxPathPattern bounds one pattern. A path pattern is a line somebody wrote.
const maxPathPattern = 1024

func anyPath(patterns []*regexp.Regexp, path string) bool {
	if path == "" {
		path = "/"
	}
	for _, re := range patterns {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

// anyMedia matches a Content-Type against patterns, comparing the media type
// without its parameters so that "text/html; charset=utf-8" is text/html. A
// header with no type at all matches nothing: a rule about a content type must
// not fire on a request that declared none.
func anyMedia(patterns []string, header string) bool {
	t := mediaType(header)
	if t == "" {
		return false
	}
	for _, pat := range patterns {
		if pat == t {
			return true
		}
		if tree, ok := strings.CutSuffix(pat, "/*"); ok {
			if top, _, found := strings.Cut(t, "/"); found && top == tree {
				return true
			}
		}
	}
	return false
}

// mediaType is the type and subtype, folded, with the parameters dropped. A
// header this cannot parse is treated as no type rather than as its raw text,
// so a malformed Content-Type cannot be written to dodge a rule by matching
// nothing it was compared against.
func mediaType(header string) string {
	if header == "" {
		return ""
	}
	t, _, err := mime.ParseMediaType(header)
	if err != nil {
		// Take what is before the first ';' and check it has the one slash a
		// media type has. Anything else is not a type.
		t = strings.TrimSpace(strings.ToLower(strings.Split(header, ";")[0]))
		if a, b, ok := strings.Cut(t, "/"); !ok || a == "" || b == "" || strings.ContainsAny(t, " \t") {
			return ""
		}
	}
	return strings.ToLower(t)
}

// groupsOf is the groups a name is in, for the estate's own authorisation
// section: it has had a groups selector since it was written, and this listener
// had nothing to put in it until the auth section grew a groups map.
func (p *egressPolicy) groupsOf(user string) []string {
	if p == nil || user == "" {
		return nil
	}
	return p.groups[strings.ToLower(user)]
}

// errBodyTooLarge is what a bounded body returns past its bound. It travels out
// through the round trip, which is what stops the upload.
var errBodyTooLarge = errors.New("forward: request body over the size a rule refuses at")

// boundedBody is a request body that stops at a size.
//
// It is the counting half of a rule about a body nobody declared the length of.
// The bytes already read have already gone to the destination -- a proxy cannot
// recall them -- so what this buys is that the rest does not follow.
type boundedBody struct {
	io.ReadCloser
	left int64
}

func (b *boundedBody) Read(p []byte) (int, error) {
	if b.left <= 0 {
		return 0, errBodyTooLarge
	}
	if int64(len(p)) > b.left+1 {
		p = p[:b.left+1]
	}
	n, err := b.ReadCloser.Read(p)
	b.left -= int64(n)
	if b.left < 0 {
		// One byte past the bound is what makes it "over" rather than "at".
		return n, errBodyTooLarge
	}
	return n, err
}
