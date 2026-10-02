package kkdcp

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/kerberos"
	"github.com/rom/xproxy/internal/schedule"
)

// The policy, compiled once at load.
//
// The thing to understand about its shape is which leg each check is on,
// because on this protocol that is not a matter of taste.
//
// **The realm is decided first, on the way in, and is never shadowed.** A
// proxy that forwarded a message for a realm it does not serve is an open
// relay, and carrying one to find out what the policy would have said is the
// thing the realm list exists to prevent.
//
// **The encryption types are decided on the request.** What a client offers
// is what it will accept, and refusing the request is the only point at
// which refusing costs nothing: by the time the reply exists, the KDC has
// minted a ticket.
//
// **Pre-authentication exemption is decided on the reply, and it has to
// be.** A bare AS-REQ with no pre-authentication is the normal first message
// of every Kerberos exchange -- the KDC answers it with
// KDC_ERR_PREAUTH_REQUIRED and the client retries with a timestamp. The
// interesting case is a KDC that answers one with a *ticket*, which says the
// account is exempt and hands out an offline password-cracking target. So
// the check pairs the reply with its request, and the pairing is this
// relay's own: nothing in the protocol says "this reply answers a request
// that had no padata".

// Decision is one policy answer.
type Decision struct {
	Allow  bool
	Reason string
	Detail string
	Rule   string
	// Hard marks a refusal that stands even in shadow mode.
	Hard bool
}

// Request is what the policy decides about on the way in.
type Request struct {
	Client netip.Addr
	// TargetDomain is the realm the envelope named, and Realm the one the
	// message named. They are separate because a disagreement between them
	// is itself a finding.
	TargetDomain string
	Realm        string
	Type         wire.MsgType
	Principal    string
	Service      string
	ServiceClass string
	ETypes       []wire.EType
	OnlyWeak     bool
	Options      wire.Options
	Preauth      bool
	S4U2Self     bool
	S4U2Proxy    bool
	Anonymous    bool
	Lifetime     time.Duration
	HasLifetime  bool
	At           time.Time
}

// Answer is what the policy decides about on the way back.
type Answer struct {
	Client netip.Addr
	Type   wire.MsgType
	// TicketEType is the type the KDC encrypted the ticket in, which on a
	// service ticket is the service account's key and is what Kerberoasting
	// is about.
	TicketEType    wire.EType
	HasTicketEType bool
	// PreauthExempt says this is a successful AS exchange whose request
	// carried no pre-authentication.
	PreauthExempt bool
	// ErrorCode is a KRB-ERROR's, zero for a reply.
	ErrorCode int32
	IsError   bool
	Rule      string
	At        time.Time
}

type rule struct {
	name     string
	action   string
	observe  bool
	nets     []netip.Prefix
	realms   map[string]bool
	types    map[wire.MsgType]bool
	princs   map[string]bool
	services map[string]bool
	denySvcs map[string]bool
	etypes   map[wire.EType]bool
	lifetime time.Duration
	sched    *schedule.Window
}

type policy struct {
	allowByDef       bool
	realms           map[string]bool
	needTarget       bool
	types            map[wire.MsgType]bool
	etypes           map[wire.EType]bool
	denyETypes       map[wire.EType]bool
	refuseWeak       bool
	refuseWeakTicket bool
	refuseExempt     bool
	allowS4U2Self    bool
	allowS4U2Proxy   bool
	allowAnonymous   bool
	allowPassword    bool
	allowForwarded   bool
	denyOptions      []wire.Options
	princs           map[string]bool
	denyPrincs       map[string]bool
	services         map[string]bool
	denyServices     map[string]bool
	lifetime         time.Duration
	rules            []*rule
}

func compile(k *config.KKDCPListener) (*policy, error) {
	p := &policy{
		allowByDef:       k.DefaultAction == "allow",
		realms:           lower(k.Realms),
		needTarget:       boolOr(k.RequireTargetDomain, false),
		refuseWeak:       boolOr(k.RefuseWeakETypes, true),
		refuseWeakTicket: boolOr(k.RefuseWeakTicketETypes, false),
		refuseExempt:     boolOr(k.RefusePreauthExempt, true),
		allowS4U2Self:    boolOr(k.AllowS4U2Self, false),
		allowS4U2Proxy:   boolOr(k.AllowS4U2Proxy, false),
		allowAnonymous:   boolOr(k.AllowAnonymous, false),
		allowPassword:    boolOr(k.AllowPasswordChange, false),
		allowForwarded:   boolOr(k.AllowForwardedTickets, true),
		princs:           lower(k.Principals),
		denyPrincs:       lower(k.DenyPrincipals),
		services:         lower(k.Services),
		denyServices:     lower(k.DenyServices),
		lifetime:         k.MaxTicketLifetime.D(),
	}
	if len(p.realms) == 0 {
		// Validation refuses this, and the kind refuses it again: a KDC proxy
		// with no realm list is an open relay, and the one place that must
		// not depend on a validator having run is the code that forwards.
		return nil, fmt.Errorf("realms: required")
	}
	var err error
	if p.types, err = typeSet(k.MessageTypes); err != nil {
		return nil, fmt.Errorf("message_types: %w", err)
	}
	if len(p.types) == 0 {
		p.types = map[wire.MsgType]bool{wire.MsgASReq: true, wire.MsgTGSReq: true}
		if p.allowPassword {
			p.types[wire.MsgAPReq] = true
		}
	}
	if p.etypes, err = etypeSet(k.ETypes); err != nil {
		return nil, fmt.Errorf("etypes: %w", err)
	}
	if p.denyETypes, err = etypeSet(k.DenyETypes); err != nil {
		return nil, fmt.Errorf("deny_etypes: %w", err)
	}
	for _, n := range k.DenyOptions {
		o, ok := wire.OptionOf(n)
		if !ok {
			return nil, fmt.Errorf("deny_options: %q is not a KDC option", n)
		}
		p.denyOptions = append(p.denyOptions, o)
	}
	for i := range k.Rules {
		r := &k.Rules[i]
		ru := &rule{name: r.Name, action: r.Action, observe: r.Action == "observe",
			realms: lower(r.Realms), princs: lower(r.Principals),
			services: lower(r.Services), denySvcs: lower(r.DenyServices),
			lifetime: r.MaxTicketLifetime.D()}
		if ru.nets, err = prefixes(r.Clients); err != nil {
			return nil, fmt.Errorf("rules[%d].clients: %w", i, err)
		}
		if ru.types, err = typeSet(r.MessageTypes); err != nil {
			return nil, fmt.Errorf("rules[%d].message_types: %w", i, err)
		}
		if ru.etypes, err = etypeSet(r.ETypes); err != nil {
			return nil, fmt.Errorf("rules[%d].etypes: %w", i, err)
		}
		if r.Schedule != nil {
			if ru.sched, err = schedule.Compile(r.Schedule); err != nil {
				return nil, fmt.Errorf("rules[%d].schedule: %w", i, err)
			}
		}
		p.rules = append(p.rules, ru)
	}
	return p, nil
}

func typeSet(names []string) (map[wire.MsgType]bool, error) {
	if len(names) == 0 {
		return nil, nil
	}
	out := make(map[wire.MsgType]bool, len(names))
	for _, n := range names {
		m, ok := wire.MsgTypeOf(n)
		if !ok {
			return nil, fmt.Errorf("%q is not a request type", n)
		}
		out[m] = true
	}
	return out, nil
}

func etypeSet(names []string) (map[wire.EType]bool, error) {
	if len(names) == 0 {
		return nil, nil
	}
	out := make(map[wire.EType]bool, len(names))
	for _, n := range names {
		e, ok := wire.ETypeOf(n)
		if !ok {
			return nil, fmt.Errorf("%q is not an encryption type", n)
		}
		out[e] = true
	}
	return out, nil
}

// Realm answers the realm question, which is asked before anything else and
// is never shadowed.
//
// The two realms have to agree where both are present. The outer one is what
// the proxy routes by and the inner one is what the KDC decides on, so a
// proxy that picked one would be deciding about a different realm than the
// KDC -- and a client that sends two is either confused or trying exactly
// that.
func (p *policy) Realm(req Request) Decision {
	if req.TargetDomain == "" && p.needTarget {
		return Decision{Reason: "target_domain_required", Hard: true}
	}
	if req.TargetDomain != "" && req.Realm != "" &&
		!strings.EqualFold(req.TargetDomain, req.Realm) {
		return Decision{Reason: "realm_mismatch",
			Detail: req.TargetDomain + " != " + req.Realm, Hard: true}
	}
	for _, r := range []string{req.TargetDomain, req.Realm} {
		if r == "" {
			continue
		}
		if !p.realms[strings.ToLower(r)] {
			return Decision{Reason: "realm_not_allowed", Detail: r, Hard: true}
		}
	}
	return Decision{Allow: true}
}

// Decide answers one request.
func (p *policy) Decide(req Request) Decision {
	if !p.types[req.Type] {
		return Decision{Reason: "message_type_not_allowed", Detail: req.Type.String()}
	}
	if req.Type == wire.MsgAPReq && !p.allowPassword {
		return Decision{Reason: "password_change_not_allowed", Detail: req.Service}
	}
	if req.Anonymous && !p.allowAnonymous {
		return Decision{Reason: "anonymous_not_allowed"}
	}
	if req.S4U2Self && !p.allowS4U2Self {
		return Decision{Reason: "s4u2self_not_allowed", Detail: req.Principal}
	}
	if req.S4U2Proxy && !p.allowS4U2Proxy {
		return Decision{Reason: "s4u2proxy_not_allowed", Detail: req.Service}
	}
	if !p.allowForwarded && (req.Options.Has(wire.OptForwarded) || req.Options.Has(wire.OptProxy)) {
		return Decision{Reason: "forwarded_ticket_not_allowed", Detail: req.Options.String()}
	}
	for _, o := range p.denyOptions {
		if req.Options.Has(o) {
			return Decision{Reason: "option_not_allowed", Detail: o.String()}
		}
	}
	if d := p.names(req); !d.Allow {
		return d
	}
	r := p.match(req)
	if d := p.etypeCheck(req, r); !d.Allow {
		return d
	}
	if d := p.lifetimeCheck(req, r); !d.Allow {
		return d
	}
	if r == nil {
		d := Decision{Allow: p.allowByDef}
		if !d.Allow {
			d.Reason = "no_rule_matched"
		}
		return d
	}
	if r.observe {
		return Decision{Allow: true, Rule: r.name}
	}
	if r.action == "deny" {
		return Decision{Reason: "rule_denied", Rule: r.name}
	}
	if r.sched != nil && !r.sched.InForce(req.At) {
		return Decision{Reason: "outside_schedule", Rule: r.name}
	}
	if len(r.denySvcs) > 0 && req.Service != "" && p.serviceNamed(r.denySvcs, req) {
		return Decision{Reason: "service_not_allowed", Detail: req.Service, Rule: r.name}
	}
	return Decision{Allow: true, Rule: r.name}
}

// names applies the principal and service lists.
//
// A service is matched on the whole name and on the service class alone, so
// `MSSQLSvc` covers every SQL Server instance in the realm and
// `host/dc1.corp.example` covers one host. That is the shape a real policy
// has: an estate knows which *kinds* of service it wants reachable from
// outside long before it knows every instance's name.
func (p *policy) names(req Request) Decision {
	if req.Principal != "" {
		pr := strings.ToLower(req.Principal)
		if p.denyPrincs[pr] {
			return Decision{Reason: "principal_not_allowed", Detail: req.Principal}
		}
		if p.princs != nil && !p.princs[pr] {
			return Decision{Reason: "principal_not_allowed", Detail: req.Principal}
		}
	}
	if req.Service == "" {
		return Decision{Allow: true}
	}
	if p.serviceNamed(p.denyServices, req) {
		return Decision{Reason: "service_not_allowed", Detail: req.Service}
	}
	if p.services != nil && !p.serviceNamed(p.services, req) {
		return Decision{Reason: "service_not_allowed", Detail: req.Service}
	}
	return Decision{Allow: true}
}

// serviceNamed reports whether a set names this request's service, by the
// whole name or by its class.
func (p *policy) serviceNamed(set map[string]bool, req Request) bool {
	if len(set) == 0 {
		return false
	}
	return set[strings.ToLower(req.Service)] || set[strings.ToLower(req.ServiceClass)]
}

// etypeCheck applies the encryption type policy.
func (p *policy) etypeCheck(req Request, r *rule) Decision {
	set := p.etypes
	if r != nil && r.etypes != nil {
		set = r.etypes
	}
	for _, e := range req.ETypes {
		if p.denyETypes[e] {
			return Decision{Reason: "etype_not_allowed", Detail: e.String(), Rule: ruleName(r)}
		}
		if set != nil && !set[e] {
			return Decision{Reason: "etype_not_allowed", Detail: e.String(), Rule: ruleName(r)}
		}
	}
	if p.refuseWeak && req.OnlyWeak {
		// Only-weak rather than any-weak, and the distinction is the whole
		// setting: a Windows client lists aes256, aes128 and rc4 and the KDC
		// takes the first it can, so refusing a request that mentions RC4
		// would refuse the estate.
		return Decision{Reason: "weak_etype_only", Detail: etypeList(req.ETypes),
			Rule: ruleName(r)}
	}
	return Decision{Allow: true}
}

// lifetimeCheck applies the ticket lifetime bound.
func (p *policy) lifetimeCheck(req Request, r *rule) Decision {
	bound := p.lifetime
	if r != nil && r.lifetime > 0 {
		bound = r.lifetime
	}
	if bound <= 0 || !req.HasLifetime || req.Lifetime <= bound {
		return Decision{Allow: true}
	}
	return Decision{Reason: "lifetime_too_long",
		Detail: req.Lifetime.String() + " above " + bound.String(), Rule: ruleName(r)}
}

// Answer decides about one reply.
func (p *policy) Answer(a Answer) Decision {
	if a.PreauthExempt && p.refuseExempt {
		// Hard: the point of the check is that the reply is the crackable
		// thing, so carrying it to see what the policy would have said hands
		// it over.
		return Decision{Reason: "preauth_not_required", Rule: a.Rule, Hard: true}
	}
	if a.HasTicketEType && p.refuseWeakTicket && a.TicketEType.Weak() {
		return Decision{Reason: "weak_ticket_etype", Detail: a.TicketEType.String(), Rule: a.Rule}
	}
	return Decision{Allow: true}
}

// match finds the first rule a request matches, in order.
func (p *policy) match(req Request) *rule {
	for _, r := range p.rules {
		if r.covers(req) {
			return r
		}
	}
	return nil
}

func (r *rule) covers(req Request) bool {
	if len(r.nets) > 0 && !contains(r.nets, req.Client) {
		return false
	}
	if r.realms != nil && !r.realms[strings.ToLower(req.Realm)] &&
		!r.realms[strings.ToLower(req.TargetDomain)] {
		return false
	}
	if r.types != nil && !r.types[req.Type] {
		return false
	}
	if r.princs != nil && !r.princs[strings.ToLower(req.Principal)] {
		return false
	}
	if r.services != nil && req.Service != "" &&
		!r.services[strings.ToLower(req.Service)] &&
		!r.services[strings.ToLower(req.ServiceClass)] {
		return false
	}
	return true
}

func ruleName(r *rule) string {
	if r == nil {
		return ""
	}
	return r.name
}

// etypeList renders the offered types for a log line and a refusal detail.
func etypeList(list []wire.EType) string {
	parts := make([]string, 0, len(list))
	for _, e := range list {
		parts = append(parts, e.String())
	}
	return strings.Join(parts, ",")
}

// prefixes parses a list of CIDR networks, accepting a bare address as a
// host route.
func prefixes(list []string) ([]netip.Prefix, error) {
	if len(list) == 0 {
		return nil, nil
	}
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		s = strings.TrimSpace(s)
		if pfx, err := netip.ParsePrefix(s); err == nil {
			out = append(out, pfx)
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("%q is not an address or a network", s)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

func contains(ps []netip.Prefix, ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, pfx := range ps {
		if pfx.Contains(ip) {
			return true
		}
	}
	return false
}
