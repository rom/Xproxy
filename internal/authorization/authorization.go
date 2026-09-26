// Package authorization is the estate's authorisation policy: one place that
// says which identity may reach which listener, target and operation, for every
// listener kind rather than per kind.
//
// It is not internal/filters/authz, which is the HTTP filter kind that decides
// what a verified identity may do with one request -- its method, its path, its
// scopes. That one runs inside a route's filter chain and answers a question
// about a request; this one runs at a listener's admission point and answers a
// question about a session, in words every protocol can be asked in. They
// deliberately share a vocabulary (default deny, first match wins, the negative
// selectors as their own keys) and nothing else.
//
// Every kind here already decides things about a session. An ssh listener has
// principals with channel and command lists, a postgres relay has a statement
// policy, a modbus relay has function codes and register ranges. Those are
// protocol policy and they belong where they are: nothing else can say what a
// Modbus write to holding register 40001 means.
//
// What was missing is the question above them. "May Alice reach the production
// database at all, from where she is, at this hour" is one question about one
// person, and answering it in nineteen places means nineteen files to read
// before anybody can say what Alice may do -- and nineteen places for the
// answer to differ. This package is that question, asked once.
//
// It decides nothing on its own authority. Every field of a Subject is
// something a listener kind established: a name it authenticated, a principal
// it resolved, groups a directory or a certificate gave it, the target the
// client asked for. A value a client simply sent never reaches a rule here.
//
// # What a decision is
//
// Rules are tried in order and the first one that matches decides, which is how
// every other list in this project works. A rule that names no selector matches
// everything, so a catch-all is written by leaving it empty. When no rule
// matches, the section's own default decides -- and the default is deny,
// because a policy that lets through what nobody wrote a rule for is a policy
// whose gaps are invisible.
//
// # Fail closed while it is being wired
//
// A kind that does not ask this package would be a hole in a policy an operator
// believes covers everything, so a configuration with an authorization section
// and a listener of a kind that does not consult it is refused at load. The
// list of kinds that do consult it is listener.Authorises, which grows as they
// are wired, and a test holds it against the listener roster so a kind added
// later is outside the policy until somebody decides that it is not.
package authorization

import (
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/schedule"
)

// Subject is what a listener kind knows when it asks. Everything in it was
// established by the kind: a name it authenticated, a principal it resolved,
// groups something signed for, the target the client asked for.
type Subject struct {
	// Listener is the listener's configured name and Kind its kind, so a rule
	// can name either -- one listener, or every listener of a kind.
	Listener, Kind string
	// Client is the address the session came from, as the kind decided it
	// (behind a trusted proxy chain, the forwarded one).
	Client netip.Addr
	// User is the authenticated name, empty when the kind has none. Principal
	// is the policy identity the kind resolved for it, which on an ssh
	// listener is the principals entry that covered the key.
	User, Principal string
	// Groups are the groups something the kind trusts said this identity is
	// in: a directory bind, a certificate's principals, a token's claim.
	Groups []string
	// Target is what was asked for, in the form the protocol uses: a host and
	// port for a tunnel, an upstream endpoint for a relay, a share or a topic
	// where that is what a session names. Empty where the kind has nothing to
	// say yet.
	Target string
	// Action is what is being asked, in this package's own vocabulary rather
	// than each protocol's: see the Action constants.
	Action string
	// At is when, for the schedule a rule may carry. Zero means now.
	At time.Time
}

// The actions, which are this package's vocabulary rather than any one
// protocol's. A kind maps its own operations onto them, and the mapping is in
// the kind's own documentation: what matters here is that a rule written for
// "write" means the same thing on SFTP as on Modbus.
const (
	// ActionConnect is a session being opened at all. Every kind can ask
	// this one, and a policy that names nothing else is a policy about who
	// may reach what.
	ActionConnect = "connect"
	// ActionSession is an interactive session inside a connection: a shell,
	// a desktop, a terminal.
	ActionSession = "session"
	// ActionExec is one command run without an interactive session.
	ActionExec = "exec"
	// ActionForward is a tunnel through the session, in either direction.
	ActionForward = "forward"
	// ActionRead and ActionWrite are a payload moving: a file read or
	// written, a register read or written, a row selected or changed.
	ActionRead  = "read"
	ActionWrite = "write"
	// ActionAdmin is an operation that changes the far side's own
	// configuration rather than its data.
	ActionAdmin = "admin"
)

// The constants above are the vocabulary; config.AuthzActions is the list a
// configuration is validated against. One list, in the package that validates,
// and a test here holds the constants against it -- two lists of action names
// would be a rule that loads and never matches.

// Rule is one compiled decision.
type Rule struct {
	Name  string
	Allow bool
	// The exact-match sets, nil when the rule names none of that kind.
	users, principals, groups          map[string]bool
	notUsers, notPrincipals, notGroups map[string]bool
	listeners, kinds, actions          map[string]bool
	nets, notNets                      []netip.Prefix
	targets, notTargets                []string
	window                             *schedule.Window
	// Hits counts the decisions this rule made, so an operator can see which
	// rules are load-bearing and which never fire. A rule that never fires is
	// either dead or the thing somebody believed was protecting them.
	Hits atomic.Uint64
}

// Policy is a compiled authorisation policy.
type Policy struct {
	rules   []*Rule
	allowBy bool
	// shadow evaluates without enforcing, so a policy can be read against real
	// traffic before it decides anything.
	shadow bool
	// Allowed and Denied count decisions, and NoRule the ones the default
	// decided because nothing matched -- which is the number that says
	// whether the rules describe the estate or only part of it.
	Allowed, Denied, NoRule atomic.Uint64
}

// Decision is what a policy answered, and which rule answered it.
type Decision struct {
	Allow bool
	// Rule is the rule that decided, or "" when the default did.
	Rule string
}

// Reason is the deny reason a kind logs and counts, so a refusal here reads
// the same whichever listener made it.
const Reason = "authorization"

// New compiles the configured policy. A nil section compiles to a nil *Policy,
// which allows everything -- "no policy" is not "deny everything", and a
// listener with no authorization section keeps the policy it had before there
// was one.
//
// Everything here has already been validated by internal/config. What this
// still returns errors for is the shapes a compiler cannot assume: the rest is
// belt and braces for a caller that built a section in Go rather than YAML.
func New(c *config.Authorization) (*Policy, error) {
	if c == nil {
		return nil, nil
	}
	p := &Policy{allowBy: c.Allows(), shadow: c.Shadow}
	seen := map[string]bool{}
	for i := range c.Rules {
		r := &c.Rules[i]
		if r.Name == "" {
			return nil, fmt.Errorf("authorization.rules[%d]: name is required; a decision nobody can name is a decision nobody can find in a log", i)
		}
		if seen[r.Name] {
			return nil, fmt.Errorf("authorization.rules[%d]: duplicate name %q", i, r.Name)
		}
		seen[r.Name] = true
		c := &Rule{
			Name: r.Name, Allow: r.Allow,
			users: set(r.Users), principals: set(r.Principals), groups: foldSet(r.Groups),
			notUsers: set(r.NotUsers), notPrincipals: set(r.NotPrincipals), notGroups: foldSet(r.NotGroups),
			listeners: set(r.Listeners), kinds: set(r.Kinds), actions: set(r.Actions),
			targets: lowerAll(r.Targets), notTargets: lowerAll(r.NotTargets),
		}
		for _, a := range r.Actions {
			if !config.AuthzActions[a] {
				return nil, fmt.Errorf("authorization.rules[%d] (%s): %q is not an action", i, r.Name, a)
			}
		}
		var err error
		if c.nets, err = prefixes(r.Networks); err != nil {
			return nil, fmt.Errorf("authorization.rules[%d] (%s): networks: %w", i, r.Name, err)
		}
		if c.notNets, err = prefixes(r.NotNetworks); err != nil {
			return nil, fmt.Errorf("authorization.rules[%d] (%s): not_networks: %w", i, r.Name, err)
		}
		if c.window, err = schedule.Compile(r.Schedule); err != nil {
			return nil, fmt.Errorf("authorization.rules[%d] (%s): %w", i, r.Name, err)
		}
		p.rules = append(p.rules, c)
	}
	return p, nil
}

// Decide answers one question. A nil policy allows, because "no policy" is not
// "deny everything": a listener that is not covered by an authorization section
// keeps the policy it had before there was one.
func (p *Policy) Decide(sub Subject) Decision {
	if p == nil {
		return Decision{Allow: true}
	}
	if sub.At.IsZero() {
		sub.At = time.Now()
	}
	for _, r := range p.rules {
		if !r.matches(sub) {
			continue
		}
		r.Hits.Add(1)
		if r.Allow {
			p.Allowed.Add(1)
		} else {
			p.Denied.Add(1)
		}
		return Decision{Allow: r.Allow, Rule: r.Name}
	}
	p.NoRule.Add(1)
	if p.allowBy {
		p.Allowed.Add(1)
	} else {
		p.Denied.Add(1)
	}
	return Decision{Allow: p.allowBy}
}

// matches reports whether every selector a rule names holds for the subject.
func (r *Rule) matches(sub Subject) bool {
	switch {
	case len(r.users) > 0 && !r.users[sub.User],
		len(r.principals) > 0 && !r.principals[sub.Principal],
		len(r.listeners) > 0 && !r.listeners[sub.Listener],
		len(r.kinds) > 0 && !r.kinds[sub.Kind],
		len(r.actions) > 0 && !r.actions[sub.Action]:
		return false
	case r.notUsers[sub.User] && sub.User != "",
		r.notPrincipals[sub.Principal] && sub.Principal != "":
		return false
	}
	if len(r.groups) > 0 && !anyGroup(r.groups, sub.Groups) {
		return false
	}
	if len(r.notGroups) > 0 && anyGroup(r.notGroups, sub.Groups) {
		return false
	}
	// A rule that names networks needs an address to compare: a subject with
	// none does not match it, rather than matching every network.
	if len(r.nets) > 0 && (!sub.Client.IsValid() || !inAny(r.nets, sub.Client)) {
		return false
	}
	if len(r.notNets) > 0 && sub.Client.IsValid() && inAny(r.notNets, sub.Client) {
		return false
	}
	if len(r.targets) > 0 && !matchTarget(r.targets, sub.Target) {
		return false
	}
	if len(r.notTargets) > 0 && matchTarget(r.notTargets, sub.Target) {
		return false
	}
	return r.window.InForce(sub.At)
}

// Status is one rule in the status view: what it is and how much it has
// decided.
type Status struct {
	Name  string `json:"name"`
	Allow bool   `json:"allow"`
	Hits  uint64 `json:"hits"`
}

// Rules reports every rule with its hit count, in order.
func (p *Policy) Rules() []Status {
	if p == nil {
		return nil
	}
	out := make([]Status, 0, len(p.rules))
	for _, r := range p.rules {
		out = append(out, Status{Name: r.Name, Allow: r.Allow, Hits: r.Hits.Load()})
	}
	return out
}

// DefaultAllows reports which way an unmatched subject goes, for the status
// view: an operator reading hit counts has to know what the gaps do.
func (p *Policy) DefaultAllows() bool { return p != nil && p.allowBy }

// set is a lookup table for exact matches.
func set(list []string) map[string]bool {
	if len(list) == 0 {
		return nil
	}
	out := make(map[string]bool, len(list))
	for _, v := range list {
		out[v] = true
	}
	return out
}

// foldSet is a lookup table for the names that are compared without case: a
// directory hands back a distinguished name in whatever case it likes.
func foldSet(list []string) map[string]bool {
	if len(list) == 0 {
		return nil
	}
	out := make(map[string]bool, len(list))
	for _, v := range list {
		out[strings.ToLower(v)] = true
	}
	return out
}

func lowerAll(list []string) []string {
	if len(list) == 0 {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, v := range list {
		out = append(out, strings.ToLower(v))
	}
	return out
}

// anyGroup reports whether the subject is in any of the rule's groups.
func anyGroup(want map[string]bool, have []string) bool {
	for _, g := range have {
		if want[strings.ToLower(g)] {
			return true
		}
	}
	return false
}

// prefixes parses a network list, taking a bare address as a single host: an
// operator writing one address means that address, not a syntax error.
func prefixes(list []string) ([]netip.Prefix, error) {
	if len(list) == 0 {
		return nil, nil
	}
	out := make([]netip.Prefix, 0, len(list))
	for _, v := range list {
		if p, err := netip.ParsePrefix(v); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(v)
		if err != nil {
			return nil, fmt.Errorf("%q is not an address or a CIDR", v)
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

func inAny(nets []netip.Prefix, ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// matchTarget matches a target against patterns in which * does not cross a
// colon or a slash. A rule for "10.0.0.5:*" is about one host's ports, and one
// for "/srv/*" is about one directory's entries -- a wildcard that crossed
// those would quietly widen the rule past what it looks like.
func matchTarget(patterns []string, target string) bool {
	t := strings.ToLower(target)
	for _, p := range patterns {
		if globMatch(p, t) {
			return true
		}
	}
	return false
}

// globMatch is the pattern rule above, iteratively: * matches any run of
// characters that are not ':' or '/'.
func globMatch(pattern, s string) bool {
	if pattern == "*" {
		// The one pattern that means everything, including the empty target.
		return true
	}
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s
	}
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	pos := len(parts[0])
	for i := 1; i < len(parts); i++ {
		part := parts[i]
		last := i == len(parts)-1
		switch {
		case part == "" && last:
			// A trailing *: whatever is left must not cross a separator.
			return !strings.ContainsAny(s[pos:], ":/")
		case last:
			if !strings.HasSuffix(s, part) || len(s) < pos+len(part) {
				return false
			}
			return !strings.ContainsAny(s[pos:len(s)-len(part)], ":/")
		}
		at := strings.Index(s[pos:], part)
		if at < 0 || strings.ContainsAny(s[pos:pos+at], ":/") {
			return false
		}
		pos += at + len(part)
	}
	return true
}

// Shadows reports whether the policy is being read rather than enforced. A
// caller that shadows still logs and counts the decision, and then does what it
// would have done without a policy at all.
func (p *Policy) Shadows() bool { return p != nil && p.shadow }
