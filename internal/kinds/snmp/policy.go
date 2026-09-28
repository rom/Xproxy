package snmp

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/schedule"
	wire "github.com/rom/xproxy/internal/snmp"
)

// The policy is written in SNMP's own terms, because those terms are what a
// network engineer's runbook and a vendor's configuration guide are written
// in: the version, the community string or the USM user, the operation, and
// the object identifier subtree.
//
// Rules are ordered and the first match decides, with one exception that is
// deliberate: read_only on the listener is checked before any rule and
// cannot be overridden by one. SNMP has exactly one writing operation, so
// read_only is a one-line policy that covers the whole of "nobody
// reconfigures anything through this relay" -- and a read-only listener that
// a single rule could write through is not a read-only listener.

// Decision is what the policy decided about one message.
type Decision struct {
	// Allow says the message may go on.
	Allow bool
	// Rule is the rule that decided, or "" for a default.
	Rule string
	// Reason is why, as a stable label the counters and the security log
	// both use.
	Reason string
	// Observed says a rule matched with action observe: the message was
	// recorded and the search carried on, so this is not the decision.
	Observed bool
	// Detail names the object the decision was about, where one object was
	// the reason. A refusal that says which OID it was about is an audit
	// trail; one that says "denied" is not.
	Detail string
}

// subtrees is a set of object identifier subtrees.
//
// The test is per sub-identifier rather than per character, which is the
// whole point of keeping an OID as numbers: the *string* "1.3.6.1.2.1" is a
// prefix of the string "1.3.6.1.2.11", and the object is not under the
// subtree. A policy written with string prefixes allows a subtree nobody
// named.
type subtrees []wire.OID

func compileSubtrees(what string, in []string) (subtrees, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make(subtrees, 0, len(in))
	for _, s := range in {
		o, err := wire.ParseOID(s)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", what, err)
		}
		out = append(out, o)
	}
	return out, nil
}

// covers says whether an object is at or below any of the subtrees.
func (t subtrees) covers(o wire.OID) bool {
	for _, p := range t {
		if o.Under(p) {
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
	versions    map[wire.Version]bool
	communities map[string]bool
	users       map[string]bool
	names       map[string]bool
	transports  map[Transport]bool
	minLevel    wire.SecurityLevel
	hasLevel    bool
	pdus        map[wire.PDUType]bool
	access      map[string]bool
	oids        subtrees
	denyOIDs    subtrees
	writeOIDs   subtrees
	contexts    map[string]bool
	maxReps     int
	sched       *schedule.Window
}

// Policy is the compiled listener policy.
type Policy struct {
	readOnly     bool
	traps        bool
	versions     map[wire.Version]bool
	communities  map[string]bool
	users        map[string]bool
	minLevel     wire.SecurityLevel
	hasMinLevel  bool
	rules        []*rule
	defaultAllow bool
	allow, deny  []netip.Prefix
	maxReps      int
	maxVarBinds  int
	now          func() time.Time
}

// request is what the policy decides about: a parsed message and who sent
// it.
type request struct {
	client netip.Addr
	msg    *wire.Message
	// transport is what the message arrived on, which a rule may name: on
	// this protocol the transport is half the credential, because a community
	// string in a plain datagram and the same request inside DTLS are not the
	// same statement about who is asking.
	transport Transport
	// name is the transport security model's security name, derived from the
	// peer's certificate by RFC 6353 s5.3's mapping. Empty on every other
	// transport and on a message that is not under that model.
	name string
}

// credential is the identity a message carries, whichever version it is.
// For v1 and v2c that is the community string; for v3 the USM user name.
// Naming them together is what lets one rule cover both without a policy
// having to know which version a device happens to speak this year.
func (r request) credential() string {
	if r.msg.Version == wire.V3 && r.msg.V3 != nil {
		return r.msg.V3.User
	}
	return r.msg.Community
}

// level is the security level a message was sent at. A v1 or v2c message is
// noAuthNoPriv by construction: its credential is in the clear and there is
// nothing to verify it with.
func (r request) level() wire.SecurityLevel {
	if r.msg.Version == wire.V3 && r.msg.V3 != nil {
		return r.msg.V3.Level
	}
	return wire.NoAuthNoPriv
}

// compile builds the policy. Everything that can be wrong about a rule is
// wrong here, at load, rather than at the first message that matches it.
func compile(l *config.SNMPListener, now func() time.Time) (*Policy, error) {
	p := &Policy{readOnly: l.ReadOnly, traps: l.Traps,
		defaultAllow: l.DefaultAction == "allow",
		maxReps:      l.MaxRepetitions, maxVarBinds: l.MaxVarBinds, now: now}
	if p.now == nil {
		p.now = time.Now
	}
	if p.maxReps == 0 {
		p.maxReps = 100
	}
	if p.maxVarBinds == 0 {
		p.maxVarBinds = 128
	}
	var err error
	if p.allow, err = prefixes("allow_clients", l.AllowClients); err != nil {
		return nil, err
	}
	if p.deny, err = prefixes("deny_clients", l.DenyClients); err != nil {
		return nil, err
	}
	if p.versions, err = versionSet("versions", l.Versions); err != nil {
		return nil, err
	}
	p.communities = stringSet(l.Communities)
	p.users = stringSet(l.Users)
	if l.MinSecurityLevel != "" {
		lvl, ok := wire.LevelOf(l.MinSecurityLevel)
		if !ok {
			return nil, fmt.Errorf("min_security_level: %q", l.MinSecurityLevel)
		}
		p.minLevel, p.hasMinLevel = lvl, true
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
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("%s: %q: %w", what, s, err)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

func versionSet(what string, in []string) (map[wire.Version]bool, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := map[wire.Version]bool{}
	for _, s := range in {
		v, ok := wire.VersionOf(strings.TrimSpace(s))
		if !ok {
			return nil, fmt.Errorf("%s: %q is not a version", what, s)
		}
		out[v] = true
	}
	return out, nil
}

func stringSet(in []string) map[string]bool {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]bool, len(in))
	for _, s := range in {
		out[s] = true
	}
	return out
}

func compileRule(c *config.SNMPRule) (*rule, error) {
	r := &rule{name: c.Name, action: c.Action, maxReps: c.MaxRepetitions}
	if r.action == "" {
		r.action = "allow"
	}
	where := "rules." + c.Name
	var err error
	if r.clients, err = prefixes(where+".clients", c.Clients); err != nil {
		return nil, err
	}
	if r.versions, err = versionSet(where+".versions", c.Versions); err != nil {
		return nil, err
	}
	r.communities = stringSet(c.Communities)
	r.users = stringSet(c.Users)
	r.names = stringSet(c.SecurityNames)
	r.contexts = stringSet(c.Contexts)
	if len(c.Transports) > 0 {
		r.transports = map[Transport]bool{}
		for _, name := range c.Transports {
			tr, ok := TransportOf(name)
			if !ok {
				return nil, fmt.Errorf("%s.transports: %q is not one of %s", where, name,
					strings.Join(Transports(), ", "))
			}
			r.transports[tr] = true
		}
	}
	if c.MinSecurityLevel != "" {
		lvl, ok := wire.LevelOf(c.MinSecurityLevel)
		if !ok {
			return nil, fmt.Errorf("%s.min_security_level: %q", where, c.MinSecurityLevel)
		}
		r.minLevel, r.hasLevel = lvl, true
	}
	if len(c.PDUs) > 0 {
		r.pdus = map[wire.PDUType]bool{}
		for _, name := range c.PDUs {
			t, ok := wire.PDUTypeOf(strings.TrimSpace(name))
			if !ok {
				return nil, fmt.Errorf("%s.pdus: %q is not an operation", where, name)
			}
			r.pdus[t] = true
		}
	}
	if len(c.Access) > 0 {
		r.access = map[string]bool{}
		for _, a := range c.Access {
			switch a {
			case "read", "write", "notify":
				r.access[a] = true
			default:
				return nil, fmt.Errorf("%s.access: %q", where, a)
			}
		}
	}
	if r.oids, err = compileSubtrees(where+".oids", c.OIDs); err != nil {
		return nil, err
	}
	if r.denyOIDs, err = compileSubtrees(where+".deny_oids", c.DenyOIDs); err != nil {
		return nil, err
	}
	if r.writeOIDs, err = compileSubtrees(where+".write_oids", c.WriteOIDs); err != nil {
		return nil, err
	}
	if r.sched, err = schedule.Compile(c.Schedule); err != nil {
		return nil, fmt.Errorf("%s: %w", where, err)
	}
	return r, nil
}

// accessOf names what an operation does, in the words a rule is written in.
func accessOf(t wire.PDUType) string {
	switch {
	case t.Writes():
		return "write"
	case t.Reads():
		return "read"
	case t.Notification():
		return "notify"
	}
	return ""
}

// Client decides whether a manager may send at all. It is separate from
// Decide because it happens before a message is parsed, and because it is
// not policy in the shadow sense: an address that may not reach the
// equipment is refused whether or not the rest is enforced.
func (p *Policy) Client(a netip.Addr) bool {
	if netutil.Contains(p.deny, a) {
		return false
	}
	if len(p.allow) > 0 {
		return netutil.Contains(p.allow, a)
	}
	return true
}

// MaxRepetitions is the GETBULK bound in force for a message, which a rule
// may raise or lower for the traffic it covers.
func (p *Policy) MaxRepetitions(req request, ruleName string) int {
	for _, r := range p.rules {
		if r.name == ruleName && r.maxReps > 0 {
			return r.maxReps
		}
	}
	return p.maxReps
}

// Decide applies the policy to one message.
func (p *Policy) Decide(req request) Decision {
	m := req.msg
	// The version first, because every later field is in a different place
	// per version and because "v3 only" is the most useful line an operator
	// can write on this protocol.
	if p.versions != nil && !p.versions[m.Version] {
		return Decision{Reason: "snmp_version", Detail: m.Version.String()}
	}
	// Then the credential, which is the community string or the USM user.
	if m.Version == wire.V3 {
		if p.users != nil && !p.users[req.credential()] {
			return Decision{Reason: "snmp_user", Detail: req.credential()}
		}
		if p.hasMinLevel && req.level() < p.minLevel {
			// noAuthNoPriv is version 2c with more fields, and a listener
			// that went to the trouble of requiring v3 usually wants more.
			return Decision{Reason: "snmp_security_level", Detail: req.level().String()}
		}
	} else if p.communities != nil && !p.communities[m.Community] {
		// The community string is not reported in the detail: it is a
		// credential, and a security log that printed every guessed one
		// would be a list of credentials to try.
		return Decision{Reason: "snmp_community"}
	}
	if m.PDU == nil {
		// A v3 message whose scoped PDU is encrypted. The header passed, and
		// there is nothing further to decide: no operation, no object
		// identifiers. Saying so plainly is better than refusing traffic the
		// listener was configured to carry or pretending it was inspected.
		return Decision{Allow: true, Reason: "snmp_encrypted"}
	}
	pdu := m.PDU
	// read_only next, and not overridable: one writing operation, one line.
	if p.readOnly && pdu.Type.Writes() {
		return Decision{Reason: "snmp_read_only", Detail: firstOID(pdu)}
	}
	// A message whose direction is wrong for this listener. A trap listener
	// carries notifications from agents; an agent front carries requests to
	// them. A request arriving at a trap port, or a trap at an agent front,
	// is a datagram sent to the wrong place at best.
	if p.traps != pdu.Type.Notification() && pdu.Type != wire.Response && pdu.Type != wire.ReportPDU {
		return Decision{Reason: "snmp_direction", Detail: pdu.Type.String()}
	}
	if p.maxVarBinds > 0 && len(pdu.VarBinds) > p.maxVarBinds {
		return Decision{Reason: "snmp_var_binds", Detail: fmt.Sprintf("%d bindings", len(pdu.VarBinds))}
	}
	now := p.now()
	for _, r := range p.rules {
		matched, why := r.matches(req, now)
		if !matched {
			continue
		}
		switch r.action {
		case "deny":
			return Decision{Rule: r.name, Reason: "snmp_rule", Detail: why}
		case "observe":
			// Recorded, and the search carries on: how a rule is tried on
			// live traffic before it decides anything.
			continue
		default:
			return Decision{Allow: true, Rule: r.name}
		}
	}
	if p.defaultAllow {
		return Decision{Allow: true}
	}
	return Decision{Reason: "snmp_default_deny", Detail: firstOID(pdu)}
}

// firstOID names the object a decision was about, which is what makes a
// refusal an audit trail rather than a count.
func firstOID(p *wire.PDU) string {
	if p == nil || len(p.VarBinds) == 0 {
		return ""
	}
	return p.VarBinds[0].OID.String()
}

// matches says whether a rule covers this message, and which object made it
// not match when an object is the reason.
func (r *rule) matches(req request, now time.Time) (bool, string) {
	m := req.msg
	if !r.sched.InForce(now) {
		return false, ""
	}
	if len(r.clients) > 0 && !netutil.Contains(r.clients, req.client) {
		return false, ""
	}
	if r.versions != nil && !r.versions[m.Version] {
		return false, ""
	}
	// The credential sets are per version: a rule naming communities cannot
	// match a v3 message, and one naming users cannot match a v2c message.
	// Letting either cross over would make a rule written about one
	// authentication scheme apply to another.
	if r.communities != nil {
		if m.Version == wire.V3 || !r.communities[m.Community] {
			return false, ""
		}
	}
	if r.users != nil {
		// A rule naming USM users cannot cover a message under the transport
		// security model either, and it does not need a clause of its own to
		// say so: that model carries no user, so the credential is empty, and
		// a rule naming an empty user name is refused at load.
		if m.Version != wire.V3 || !r.users[req.credential()] {
			return false, ""
		}
	}
	if r.names != nil {
		// The name is the *session's*, derived from the peer's certificate,
		// rather than something the message carried. So a rule naming it
		// covers every message in a session whose certificate mapped -- a v2c
		// poller that has been given a certificate included, which is the
		// half-migrated case worth being able to write a rule about.
		//
		// A session that derived no name matches nothing here, and needs no
		// clause of its own to say so: the name is empty, and a rule naming an
		// empty security name is refused at load.
		if !r.names[req.name] {
			return false, ""
		}
	}
	if r.transports != nil {
		// A rule that names no transport covers all of them, which keeps every
		// policy written before this field meant what it meant. A request whose
		// transport was never set matches none of them, for the reason the
		// names above need no clause either: the set cannot hold the empty
		// transport, because TransportOf refuses it.
		if !r.transports[req.transport] {
			return false, ""
		}
	}
	if r.hasLevel && req.level() < r.minLevel {
		return false, ""
	}
	if r.contexts != nil {
		if m.V3 == nil || !r.contexts[m.V3.ContextName] {
			return false, ""
		}
	}
	pdu := m.PDU
	if pdu == nil {
		// An encrypted payload cannot be matched on anything below here, so
		// a rule that names an operation or an object does not match it.
		return r.pdus == nil && r.access == nil && r.oids == nil && r.writeOIDs == nil, ""
	}
	if r.pdus != nil && !r.pdus[pdu.Type] {
		return false, ""
	}
	if r.access != nil && !r.access[accessOf(pdu.Type)] {
		return false, ""
	}
	if r.maxReps > 0 && pdu.Type == wire.GetBulkRequest &&
		(pdu.MaxRepetitions < 0 || pdu.MaxRepetitions > int64(r.maxReps)) {
		// A rule that raises or lowers the repetition bound does not match
		// traffic past its own bound, so the next rule -- or the default --
		// decides. Matching and then allowing would make the bound a
		// suggestion.
		//
		// A negative count is past the bound rather than under it, for the
		// reason lowerRepetitions gives: signed it compares small, and an agent
		// that reads it unsigned sees an enormous one.
		return false, ""
	}
	// The object identifiers last, because they are the expensive test and
	// because a rule that named none is about the operation rather than
	// about the objects.
	want := r.oids
	if pdu.Type.Writes() && len(r.writeOIDs) > 0 {
		// One rule can allow a wide read and a narrow write: the write list
		// replaces the read list rather than adding to it.
		want = r.writeOIDs
	}
	for _, b := range pdu.VarBinds {
		if len(r.denyOIDs) > 0 && r.denyOIDs.covers(b.OID) {
			// An exception inside an allowed subtree: all of mib-2 except
			// the ARP table. The rule does not cover this message, so the
			// search carries on rather than allowing it.
			return false, b.OID.String()
		}
		if len(want) > 0 && !want.covers(b.OID) {
			return false, b.OID.String()
		}
	}
	return true, ""
}
