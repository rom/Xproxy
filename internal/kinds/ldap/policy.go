package ldap

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/ldap"
	"github.com/rom/xproxy/internal/netutil"
)

// The policy is written in LDAP's own terms, because those terms are what a
// directory administrator's documentation is written in: who binds and how,
// which subtree a request may name, which operation it is, which attributes
// it may see, and how hard the filter is.
//
// Rules are ordered and the first match decides, with three exceptions that
// are deliberate and cannot be overridden by a rule:
//
//   - require_tls, because a simple bind on an unprotected connection has
//     already put a password on the wire by the time a rule could be
//     consulted;
//   - read_only, because "nobody changes the directory through this relay"
//     is a statement about the whole listener and one a single rule should
//     not be able to contradict;
//   - base_dns, because the naming contexts a listener fronts are what makes
//     it *this* listener rather than a way into the whole directory.

// Decision is what the policy decided about one request.
type Decision struct {
	// Allow says the request may go on.
	Allow bool
	// Rule is the rule that decided, or "" for a default.
	Rule string
	// Reason is why, as a stable label the counters and the security log
	// both use.
	Reason string
	// Detail names the thing the decision was about -- the object, the
	// attribute, the mechanism -- because a refusal that says which is an
	// audit trail and one that says "denied" is not.
	Detail string
	// Strip are the attributes to remove from this search's answers. It is
	// the other half of the attribute policy: a request that asked for "*"
	// never named a password hash, and the directory will send one anyway.
	Strip *attrSet
	// Entries is the bound on entries this search may return.
	Entries int
	// allowOnly is the inverse of Strip: when a rule names an attribute
	// list, anything outside it is removed from the answer. The two are
	// never both set.
	allowOnly *attrSet
	// Hard says this refusal is not policy and is therefore not shadowed.
	// There is one on this protocol: a bind carrying a password on an
	// unprotected connection. By the time a policy could be consulted the
	// password has already travelled, so a listener in shadow mode that
	// forwarded it would be a listener whose "evaluate, do not enforce"
	// setting leaked a credential.
	Hard bool
}

// attrSet is a set of attribute descriptions, compared without their
// transfer options: a policy about userCertificate covers
// userCertificate;binary, because the option is how the value is encoded and
// not what it is.
type attrSet struct {
	names map[string]bool
}

func newAttrSet(in []string) *attrSet {
	if len(in) == 0 {
		return nil
	}
	s := &attrSet{names: make(map[string]bool, len(in))}
	for _, n := range in {
		if name := baseAttr(n); name != "" {
			s.names[name] = true
		}
	}
	if len(s.names) == 0 {
		return nil
	}
	return s
}

// baseAttr folds an attribute description to the name a policy is written
// about.
func baseAttr(s string) string {
	name := strings.ToLower(strings.TrimSpace(s))
	if i := strings.IndexByte(name, ';'); i >= 0 {
		name = name[:i]
	}
	return name
}

// Has says whether the set contains an attribute.
func (s *attrSet) Has(attr string) bool {
	if s == nil {
		return false
	}
	return s.names[baseAttr(attr)]
}

// Empty says whether there is nothing in the set, so a caller can skip the
// work of walking an answer.
func (s *attrSet) Empty() bool { return s == nil || len(s.names) == 0 }

// merge returns the union of two sets, which is how a rule's own deny list
// adds to the listener's rather than replacing it.
func merge(a, b *attrSet) *attrSet {
	switch {
	case a.Empty():
		return b
	case b.Empty():
		return a
	}
	out := &attrSet{names: make(map[string]bool, len(a.names)+len(b.names))}
	for n := range a.names {
		out.names[n] = true
	}
	for n := range b.names {
		out.names[n] = true
	}
	return out
}

// suffixes is a set of distinguished names, each covering itself and
// everything below it.
type suffixes []wire.DN

func compileSuffixes(what string, in []string) (suffixes, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make(suffixes, 0, len(in))
	for _, s := range in {
		dn, err := wire.ParseDN(s)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", what, err)
		}
		out = append(out, dn)
	}
	return out, nil
}

// covers says whether a name is at or below any of the suffixes.
func (s suffixes) covers(dn wire.DN) bool {
	for _, suffix := range s {
		if dn.Under(suffix) {
			return true
		}
	}
	return false
}

// rule is one compiled rule.
type rule struct {
	name        string
	action      string
	clients     []netip.Prefix
	bindDNs     suffixes
	bindAny     bool // a rule naming the empty DN covers an unbound connection
	bindUnbound bool
	methods     map[wire.Method]bool
	ops         map[wire.Op]bool
	access      map[string]bool
	baseDNs     suffixes
	denyDNs     suffixes
	scopes      map[int]bool
	attributes  *attrSet
	denyAttrs   *attrSet
	maxEntries  int
	maxTerms    int
	maxDepth    int
	wildcard    *bool
	sched       *schedule
}

// Policy is the compiled listener policy.
type Policy struct {
	readOnly     bool
	requireTLS   bool
	minVersion   int
	methods      map[wire.Method]bool
	mechanisms   map[string]bool
	baseDNs      suffixes
	denyAttrs    *attrSet
	stripDenied  bool
	maxEntries   int
	maxTerms     int
	maxDepth     int
	wildcard     bool
	extended     map[string]bool
	denyControls map[string]bool
	rules        []*rule
	defaultAllow bool
	allow, deny  []netip.Prefix
	now          func() time.Time
}

// request is what the policy decides about: a parsed message, who sent it,
// and what the connection has become.
type request struct {
	client netip.Addr
	msg    *wire.Message
	// bound is the identity this connection authenticated as, and method
	// how. An unbound connection has an empty name and MethodAnonymous.
	bound     wire.DN
	boundName string
	method    wire.Method
	// secure says the connection is protected, by implicit TLS or by a
	// StartTLS this relay completed.
	secure bool
}

// target is the distinguished name this request is about, and whether it has
// one at all.
func (r request) target() (wire.DN, string, bool) {
	m := r.msg
	switch {
	case m.Search != nil:
		return m.Search.BaseDN, m.Search.Base, true
	case m.Modify != nil:
		return m.Modify.ObjectDN, m.Modify.Object, true
	case m.Bind != nil:
		return m.Bind.DN, m.Bind.Name, true
	case m.Op == wire.OpAddRequest || m.Op == wire.OpDelRequest ||
		m.Op == wire.OpModifyDNRequest || m.Op == wire.OpCompareRequest:
		return m.TargetDN, m.Target, true
	}
	return nil, "", false
}

// accessOf names what an operation does, in the words a rule is written in.
func accessOf(op wire.Op) string {
	switch {
	case op == wire.OpBindRequest:
		return "bind"
	case op.Writes():
		return "write"
	case op.Reads():
		return "read"
	}
	return ""
}

// compile builds the policy. Everything that can be wrong about a rule is
// wrong here, at load, rather than at the first request that matches it.
func compile(l *config.LDAPListener, now func() time.Time) (*Policy, error) {
	p := &Policy{readOnly: l.ReadOnly,
		requireTLS:   l.RequireTLS == nil || *l.RequireTLS,
		minVersion:   l.MinVersion,
		stripDenied:  l.OnDeniedAttribute != "deny",
		maxEntries:   l.MaxEntries,
		maxTerms:     l.MaxFilterTerms,
		maxDepth:     l.MaxFilterDepth,
		wildcard:     l.AllowLeadingWildcard == nil || *l.AllowLeadingWildcard,
		defaultAllow: l.DefaultAction == "allow",
		now:          now}
	if p.now == nil {
		p.now = time.Now
	}
	if p.minVersion == 0 {
		p.minVersion = 3
	}
	if p.maxEntries == 0 {
		p.maxEntries = 500
	}
	if p.maxTerms == 0 {
		p.maxTerms = 64
	}
	if p.maxDepth == 0 {
		p.maxDepth = 12
	}
	var err error
	if p.allow, err = prefixes("allow_clients", l.AllowClients); err != nil {
		return nil, err
	}
	if p.deny, err = prefixes("deny_clients", l.DenyClients); err != nil {
		return nil, err
	}
	if p.methods, err = methodSet("methods", l.Methods); err != nil {
		return nil, err
	}
	if p.methods == nil {
		// The default: the two methods that actually authenticate. Leaving
		// anonymous and unauthenticated out of the default is the whole
		// point -- both are anonymous binds, and one of them is wearing a
		// user's name.
		p.methods = map[wire.Method]bool{wire.MethodSimple: true, wire.MethodSASL: true}
	}
	if len(l.SASLMechanisms) > 0 {
		p.mechanisms = map[string]bool{}
		for _, m := range l.SASLMechanisms {
			p.mechanisms[strings.ToUpper(strings.TrimSpace(m))] = true
		}
	}
	if p.baseDNs, err = compileSuffixes("base_dns", l.BaseDNs); err != nil {
		return nil, err
	}
	if len(l.DenyAttributes) > 0 {
		p.denyAttrs = newAttrSet(l.DenyAttributes)
	} else {
		p.denyAttrs = newAttrSet(config.DefaultLDAPDenyAttributes)
	}
	p.extended = map[string]bool{wire.OIDStartTLS: true}
	for _, oid := range l.ExtendedOperations {
		p.extended[strings.TrimSpace(oid)] = true
	}
	if len(l.DenyControls) > 0 {
		p.denyControls = map[string]bool{}
		for _, oid := range l.DenyControls {
			p.denyControls[strings.TrimSpace(oid)] = true
		}
	}
	for i := range l.Rules {
		r, err := compileRule(&l.Rules[i])
		if err != nil {
			return nil, err
		}
		p.rules = append(p.rules, r)
	}
	return p, nil
}

func prefixes(what string, in []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		pfx, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("%s: %q: %w", what, s, err)
		}
		out = append(out, pfx.Masked())
	}
	return out, nil
}

func methodSet(what string, in []string) (map[wire.Method]bool, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := map[wire.Method]bool{}
	for _, s := range in {
		m, ok := wire.MethodOf(s)
		if !ok {
			return nil, fmt.Errorf("%s: %q is not a bind method", what, s)
		}
		out[m] = true
	}
	return out, nil
}

func compileRule(c *config.LDAPRule) (*rule, error) {
	r := &rule{name: c.Name, action: c.Action, maxEntries: c.MaxEntries,
		maxTerms: c.MaxFilterTerms, maxDepth: c.MaxFilterDepth, wildcard: c.AllowLeadingWildcard}
	if r.action == "" {
		r.action = "allow"
	}
	where := "rules." + c.Name
	var err error
	if r.clients, err = prefixes(where+".clients", c.Clients); err != nil {
		return nil, err
	}
	for _, dn := range c.BindDNs {
		if dn == "" {
			// The unbound connection: how "before you authenticate, you may
			// do this and no more" is written.
			r.bindUnbound = true
			continue
		}
		parsed, err := wire.ParseDN(dn)
		if err != nil {
			return nil, fmt.Errorf("%s.bind_dns: %w", where, err)
		}
		r.bindDNs = append(r.bindDNs, parsed)
	}
	r.bindAny = len(c.BindDNs) == 0
	if r.methods, err = methodSet(where+".methods", c.Methods); err != nil {
		return nil, err
	}
	if len(c.Operations) > 0 {
		r.ops = map[wire.Op]bool{}
		for _, name := range c.Operations {
			op, ok := wire.OpOf(name)
			if !ok {
				return nil, fmt.Errorf("%s.operations: %q is not an operation", where, name)
			}
			r.ops[op] = true
		}
	}
	if len(c.Access) > 0 {
		r.access = map[string]bool{}
		for _, a := range c.Access {
			switch a {
			case "read", "write", "bind":
				r.access[a] = true
			default:
				return nil, fmt.Errorf("%s.access: %q", where, a)
			}
		}
	}
	if r.baseDNs, err = compileSuffixes(where+".base_dns", c.BaseDNs); err != nil {
		return nil, err
	}
	if r.denyDNs, err = compileSuffixes(where+".deny_dns", c.DenyDNs); err != nil {
		return nil, err
	}
	if len(c.Scopes) > 0 {
		r.scopes = map[int]bool{}
		for _, s := range c.Scopes {
			switch s {
			case "base":
				r.scopes[wire.ScopeBase] = true
			case "one":
				r.scopes[wire.ScopeOne] = true
			case "sub":
				r.scopes[wire.ScopeSub] = true
			default:
				return nil, fmt.Errorf("%s.scopes: %q", where, s)
			}
		}
	}
	r.attributes = newAttrSet(c.Attributes)
	r.denyAttrs = newAttrSet(c.DenyAttributes)
	if r.sched, err = compileSchedule(c.Schedule); err != nil {
		return nil, fmt.Errorf("%s: %w", where, err)
	}
	return r, nil
}

// Client decides whether an address may connect at all. It is separate from
// Decide because it happens before anything is read, and because it is not
// policy in the shadow sense: an address that may not reach the directory is
// refused whether or not the rest is enforced.
func (p *Policy) Client(a netip.Addr) bool {
	if netutil.Contains(p.deny, a) {
		return false
	}
	if len(p.allow) > 0 {
		return netutil.Contains(p.allow, a)
	}
	return true
}

// BindsInClear says whether this listener would let a password-carrying bind
// travel unprotected. It is asked at load, so a misconfiguration is a
// warning rather than a discovery.
func (p *Policy) BindsInClear() bool { return !p.requireTLS }

// Decide applies the policy to one request.
func (p *Policy) Decide(req request) Decision {
	m := req.msg
	// The operations that carry no decision. An unbind is the client saying
	// goodbye and an abandon is it withdrawing its own request; refusing
	// either would leave a connection in a state neither end agrees about.
	if m.Op == wire.OpUnbindRequest || m.Op == wire.OpAbandonRequest {
		return Decision{Allow: true}
	}
	if d, decided := p.decideBind(req); decided {
		return d
	}
	// read_only next, and not overridable: a read-only listener that one
	// rule could write through is not a read-only listener.
	if p.readOnly && m.Op.Writes() {
		_, name, _ := req.target()
		return Decision{Reason: "ldap_read_only", Detail: m.Op.String() + " " + name}
	}
	// The naming contexts this listener fronts, before the rules and before
	// default_action: allow. A listener for one tree that could be asked
	// about another is not a listener for one tree.
	if dn, name, ok := req.target(); ok && len(p.baseDNs) > 0 && !p.baseDNs.covers(dn) {
		return Decision{Reason: "ldap_base_dn", Detail: name}
	}
	if d, decided := p.decideExtended(req); decided {
		return d
	}
	for _, c := range m.Controls {
		if p.denyControls[c.OID] {
			return Decision{Reason: "ldap_control", Detail: c.OID}
		}
	}
	now := p.now()
	// The rules, and then the default. A search's own bounds are resolved
	// against whichever rule matched, because a rule may raise or lower
	// them for the traffic it covers.
	for _, r := range p.rules {
		matched, why := r.matches(req, now)
		if !matched {
			continue
		}
		switch r.action {
		case "deny":
			return Decision{Rule: r.name, Reason: "ldap_rule", Detail: why}
		case "observe":
			continue
		default:
			return p.allowed(req, r)
		}
	}
	if p.defaultAllow {
		return p.allowed(req, nil)
	}
	_, name, _ := req.target()
	return Decision{Reason: "ldap_default_deny", Detail: m.Op.String() + " " + name}
}

// decideBind decides about a bind, which is the operation this relay exists
// for on this protocol.
func (p *Policy) decideBind(req request) (Decision, bool) {
	b := req.msg.Bind
	if b == nil {
		return Decision{}, false
	}
	if b.Version < p.minVersion {
		// LDAPv2 is a different protocol wearing the same tags.
		return Decision{Reason: "ldap_version", Detail: fmt.Sprintf("v%d", b.Version)}, true
	}
	if !p.methods[b.Method] {
		switch b.Method {
		case wire.MethodAnonymous:
			return Decision{Reason: "ldap_anonymous_bind"}, true
		case wire.MethodUnauthenticated:
			// The refusal worth having. A name with an empty password is an
			// anonymous bind the directory answers with success, and the
			// application reads that success as authentication.
			return Decision{Reason: "ldap_unauthenticated_bind", Detail: b.DN.String()}, true
		default:
			return Decision{Reason: "ldap_bind_method", Detail: b.Method.String()}, true
		}
	}
	if b.Method == wire.MethodSASL && p.mechanisms != nil &&
		!p.mechanisms[strings.ToUpper(b.Mechanism)] {
		return Decision{Reason: "ldap_sasl_mechanism", Detail: b.Mechanism}, true
	}
	// The credential in the clear. This is a confidentiality bound rather
	// than a policy statement: by the time a rule could be consulted the
	// password is already on the wire, so it is refused whether or not this
	// listener enforces its policy.
	if p.requireTLS && !req.secure && carriesPassword(b) {
		return Decision{Reason: "ldap_bind_in_clear", Detail: b.DN.String(), Hard: true}, true
	}
	return Decision{}, false
}

// carriesPassword says whether this bind puts a credential on the wire in a
// form reading it recovers. SASL PLAIN does exactly what a simple bind does,
// which is why it is named here and not only in the mechanism list.
func carriesPassword(b *wire.Bind) bool {
	switch b.Method {
	case wire.MethodSimple:
		return true
	case wire.MethodSASL:
		switch strings.ToUpper(b.Mechanism) {
		case "PLAIN", "LOGIN":
			return true
		}
	}
	return false
}

// decideExtended decides about an extended operation, which is named by OID
// because that is the only thing about one a relay can read.
func (p *Policy) decideExtended(req request) (Decision, bool) {
	e := req.msg.Extended
	if e == nil || req.msg.Op != wire.OpExtendedRequest {
		return Decision{}, false
	}
	if !p.extended[e.OID] {
		return Decision{Reason: "ldap_extended", Detail: e.OID}, true
	}
	return Decision{}, false
}

// allowed builds the decision for a request a rule -- or the default --
// allows, resolving the bounds and the attribute policy that go with it.
func (p *Policy) allowed(req request, r *rule) Decision {
	d := Decision{Allow: true}
	if r != nil {
		d.Rule = r.name
	}
	s := req.msg.Search
	if s == nil {
		return d
	}
	d.Entries = p.effectiveEntries(r)
	// The filter bounds. They are resolved here rather than in matches()
	// because a rule that named no bound of its own still gets the
	// listener's, and a filter past *that* is refused rather than falling
	// through to a default that would allow it.
	terms, depth, wildcard := p.effectiveFilter(r)
	switch {
	case s.Filter.Terms > terms:
		return Decision{Rule: d.Rule, Reason: "ldap_filter_terms",
			Detail: fmt.Sprintf("%d terms", s.Filter.Terms)}
	case s.Filter.Depth > depth:
		return Decision{Rule: d.Rule, Reason: "ldap_filter_depth",
			Detail: fmt.Sprintf("%d deep", s.Filter.Depth)}
	case s.Filter.LeadingWildcard > 0 && !wildcard:
		return Decision{Rule: d.Rule, Reason: "ldap_leading_wildcard",
			Detail: strings.Join(s.Filter.Attributes, ",")}
	}
	deny := p.denyAttrs
	if r != nil {
		deny = merge(deny, r.denyAttrs)
	}
	// An attribute the policy refuses, named in the filter, is refused
	// whatever on_denied_attribute says: a filter that tests userPassword is
	// a password oracle, and with substrings it is one character at a time.
	for _, attr := range s.Filter.Attributes {
		if deny.Has(attr) {
			return Decision{Rule: d.Rule, Reason: "ldap_filter_attribute", Detail: attr}
		}
	}
	// An attribute the policy refuses, asked for *by name*, is refused too:
	// stripping it would be answering a question the client asked plainly
	// with a silence it cannot distinguish from an empty directory.
	for _, attr := range s.Attributes {
		if attr == "*" || attr == "+" {
			continue
		}
		switch {
		case deny.Has(attr):
			return Decision{Rule: d.Rule, Reason: "ldap_attribute", Detail: attr}
		case r != nil && !r.attributes.Empty() && !r.attributes.Has(attr):
			return Decision{Rule: d.Rule, Reason: "ldap_attribute_not_allowed", Detail: attr}
		}
	}
	if !p.stripDenied {
		// on_denied_attribute: deny. The request named none of them, so
		// there is nothing to refuse and nothing to strip: what the
		// directory sends goes on. Saying so here is better than leaving a
		// reader to infer it.
		return d
	}
	d.Strip = deny
	if r != nil && !r.attributes.Empty() {
		// A rule with an attribute list turns the answer policy inside out:
		// anything not named is removed. The set is carried as the answer
		// filter rather than as a deny list, which is what allowOnly is.
		d.Strip = nil
		d.allowOnly = r.attributes
	}
	return d
}

func (p *Policy) effectiveEntries(r *rule) int {
	if r != nil && r.maxEntries > 0 {
		return r.maxEntries
	}
	return p.maxEntries
}

func (p *Policy) effectiveFilter(r *rule) (terms, depth int, wildcard bool) {
	terms, depth, wildcard = p.maxTerms, p.maxDepth, p.wildcard
	if r == nil {
		return
	}
	if r.maxTerms > 0 {
		terms = r.maxTerms
	}
	if r.maxDepth > 0 {
		depth = r.maxDepth
	}
	if r.wildcard != nil {
		wildcard = *r.wildcard
	}
	return
}

// matches says whether a rule covers this request, and which thing made it
// not match when one thing is the reason.
func (r *rule) matches(req request, now time.Time) (bool, string) {
	m := req.msg
	if !r.sched.inForce(now) {
		return false, ""
	}
	if len(r.clients) > 0 && !netutil.Contains(r.clients, req.client) {
		return false, ""
	}
	if !r.bindAny {
		// The identity this connection has. An unbound connection matches
		// only a rule that names the empty DN, which is how a policy says
		// what may happen before anyone authenticates.
		unbound := req.boundName == ""
		switch {
		case unbound && !r.bindUnbound:
			return false, ""
		case !unbound && !r.bindDNs.covers(req.bound):
			return false, ""
		}
	}
	if r.methods != nil && !r.methods[req.method] {
		return false, ""
	}
	if r.ops != nil && !r.ops[m.Op] {
		return false, ""
	}
	if r.access != nil && !r.access[accessOf(m.Op)] {
		return false, ""
	}
	if m.Search != nil && r.scopes != nil && !r.scopes[m.Search.Scope] {
		return false, ""
	}
	// The object last, because it is the expensive test and because a rule
	// that named no subtree is about the operation rather than the objects.
	dn, name, ok := req.target()
	if !ok {
		return true, ""
	}
	if len(r.denyDNs) > 0 && r.denyDNs.covers(dn) {
		// An exception inside an allowed subtree. The rule does not cover
		// this request, so the search carries on rather than allowing it.
		return false, name
	}
	if len(r.baseDNs) > 0 && !r.baseDNs.covers(dn) {
		return false, name
	}
	return true, ""
}
