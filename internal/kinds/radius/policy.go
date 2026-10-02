package radius

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/radius"
	"github.com/rom/xproxy/internal/schedule"
)

// The policy, compiled once at load so a configuration that is wrong is
// wrong here rather than at the first login it refuses.
//
// Two things about its shape are worth saying out loud.
//
// **The request leg and the reply leg are different policies.** A request
// is a claim -- this user, from this NAS, with this credential -- and what
// a policy can do with it is refuse the claims it does not want made. A
// reply is a *grant*, and what a policy can do with one is bound what it
// grants. So Decide and Reply are separate methods with separate rule
// fields, and the privilege settings live only on the second, because
// privilege exists only there.
//
// **The integrity checks are not policy.** Whether a packet's digest
// verifies is decided before any of this and is never shadowed: a relay
// that forwarded a packet it could not authenticate because its policy was
// in shadow mode would be a relay with no authentication at all.

// Decision is one policy answer.
type Decision struct {
	Allow  bool
	Reason string
	Detail string
	Rule   string
	// Hard marks a refusal that stands even in shadow mode, which on this
	// kind is the dynamic authorization codes: carrying a Disconnect-Request
	// to find out what it would have done ends somebody's session.
	Hard bool
}

// Request is what the policy decides about on the way in.
type Request struct {
	Client   netip.Addr
	Code     wire.Code
	ID       uint8
	User     string
	Local    string
	Realm    string
	NASID    string
	AuthType wire.AuthType
	EAPType  wire.EAPType
	HasEAP   bool
	// EAPOffers are the methods a Nak offered, which is where a downgrade
	// is visible.
	EAPOffers []wire.EAPType
	Password  bool
	Attrs     []wire.AttrType
	At        time.Time
}

// Reply is what the policy decides about on the way back.
type Reply struct {
	Client netip.Addr
	Code   wire.Code
	// Privilege is the administrative level the reply grants, where it
	// grants one in a form the wire package recognises.
	Privilege    int
	HasPrivilege bool
	// Administrative is Service-Type = Administrative-User, the standard
	// attribute's spelling of the same grant.
	Administrative bool
	Attrs          []wire.AttrType
	// Rule is the rule that allowed the request this answers, so a
	// per-rule privilege bound applies to the answer as well as the
	// question.
	Rule string
	At   time.Time
}

type rule struct {
	name    string
	action  string
	observe bool
	nets    []netip.Prefix
	codes   map[wire.Code]bool
	auth    map[wire.AuthType]bool
	eap     map[wire.EAPType]bool
	users   map[string]bool
	realms  map[string]bool
	nasIDs  map[string]bool
	maxPriv *int
	needMAC *bool
	sched   *schedule.Window
}

type policy struct {
	allowByDef bool
	allowIPs   []netip.Prefix
	denyIPs    []netip.Prefix

	codes     map[wire.Code]bool
	denyCodes map[wire.Code]bool
	dynamic   bool

	needMAC    bool
	verifyResp bool

	auth        map[wire.AuthType]bool
	refusePAP   bool
	eap         map[wire.EAPType]bool
	denyEAP     map[wire.EAPType]bool
	refuseWeak  bool
	users       map[string]bool
	denyUsers   map[string]bool
	realms      map[string]bool
	denyRealms  map[string]bool
	needRealm   bool
	nasIDs      map[string]bool
	maxPriv     int
	denyAdmin   bool
	denyAttrs   map[wire.AttrType]bool
	denyReply   map[wire.AttrType]bool
	refuseProxy bool
	maxAttrs    int
	maxMessage  int
	rules       []*rule
	now         func() time.Time
}

// defaultCodes are the four a client sends: authentication, accounting and
// the two status queries. The dynamic authorization codes are deliberately
// absent, and allow_dynamic_authorization is what adds them.
var defaultCodes = map[wire.Code]bool{
	wire.CodeAccessRequest:     true,
	wire.CodeAccountingRequest: true,
	wire.CodeStatusServer:      true,
	wire.CodeStatusClient:      true,
}

func compile(r *config.RADIUSListener) (*policy, error) {
	p := &policy{
		allowByDef:  r.DefaultAction == "allow",
		needMAC:     boolOr(r.RequireMessageAuthenticator, true),
		verifyResp:  boolOr(r.VerifyResponseAuthenticator, true),
		dynamic:     boolOr(r.AllowDynamicAuthorization, false),
		refusePAP:   boolOr(r.RefusePlaintextPasswords, false),
		refuseWeak:  boolOr(r.RefuseWeakEAP, true),
		needRealm:   boolOr(r.RequireRealm, false),
		denyAdmin:   boolOr(r.DenyAdministrativeReplies, false),
		refuseProxy: boolOr(r.RefuseProxyState, false),
		maxAttrs:    or(r.MaxAttributes, 255),
		maxMessage:  or(r.MaxMessageBytes, wire.MaxMessage),
		maxPriv:     15,
		now:         time.Now,
	}
	if r.MaxPrivilegeLevel != nil {
		p.maxPriv = *r.MaxPrivilegeLevel
	}
	var err error
	if p.allowIPs, err = prefixes(r.AllowClients); err != nil {
		return nil, fmt.Errorf("allow_clients: %w", err)
	}
	if p.denyIPs, err = prefixes(r.DenyClients); err != nil {
		return nil, fmt.Errorf("deny_clients: %w", err)
	}
	if p.codes, err = codeSet(r.Codes); err != nil {
		return nil, fmt.Errorf("codes: %w", err)
	}
	if len(p.codes) == 0 {
		p.codes = defaultCodes
	}
	if p.denyCodes, err = codeSet(r.DenyCodes); err != nil {
		return nil, fmt.Errorf("deny_codes: %w", err)
	}
	if p.auth, err = authSet(r.AuthTypes); err != nil {
		return nil, fmt.Errorf("auth_types: %w", err)
	}
	if p.eap, err = eapSet(r.EAPTypes); err != nil {
		return nil, fmt.Errorf("eap_types: %w", err)
	}
	if p.denyEAP, err = eapSet(r.DenyEAPTypes); err != nil {
		return nil, fmt.Errorf("deny_eap_types: %w", err)
	}
	if p.denyAttrs, err = attrSet(r.DenyAttributes); err != nil {
		return nil, fmt.Errorf("deny_attributes: %w", err)
	}
	if p.denyReply, err = attrSet(r.DenyReplyAttributes); err != nil {
		return nil, fmt.Errorf("deny_reply_attributes: %w", err)
	}
	p.users, p.denyUsers = lower(r.Users), lower(r.DenyUsers)
	p.realms, p.denyRealms = lower(r.Realms), lower(r.DenyRealms)
	p.nasIDs = lower(r.NASIdentifiers)
	for i := range r.Rules {
		c := &r.Rules[i]
		ru := &rule{name: c.Name, action: c.Action, observe: c.Action == "observe",
			maxPriv: c.MaxPrivilegeLevel, needMAC: c.RequireMessageAuthenticator,
			users: lower(c.Users), realms: lower(c.Realms), nasIDs: lower(c.NASIdentifiers)}
		if ru.nets, err = prefixes(c.Clients); err != nil {
			return nil, fmt.Errorf("rules[%d].clients: %w", i, err)
		}
		if ru.codes, err = codeSet(c.Codes); err != nil {
			return nil, fmt.Errorf("rules[%d].codes: %w", i, err)
		}
		if ru.auth, err = authSet(c.AuthTypes); err != nil {
			return nil, fmt.Errorf("rules[%d].auth_types: %w", i, err)
		}
		if ru.eap, err = eapSet(c.EAPTypes); err != nil {
			return nil, fmt.Errorf("rules[%d].eap_types: %w", i, err)
		}
		if c.Schedule != nil {
			if ru.sched, err = schedule.Compile(c.Schedule); err != nil {
				return nil, fmt.Errorf("rules[%d].schedule: %w", i, err)
			}
		}
		p.rules = append(p.rules, ru)
	}
	return p, nil
}

func codeSet(names []string) (map[wire.Code]bool, error) {
	if len(names) == 0 {
		return nil, nil
	}
	out := make(map[wire.Code]bool, len(names))
	for _, n := range names {
		c, ok := wire.CodeOf(n)
		if !ok {
			return nil, fmt.Errorf("%q is not a code", n)
		}
		out[c] = true
	}
	return out, nil
}

func authSet(names []string) (map[wire.AuthType]bool, error) {
	if len(names) == 0 {
		return nil, nil
	}
	out := make(map[wire.AuthType]bool, len(names))
	for _, n := range names {
		a, ok := wire.AuthTypeOf(n)
		if !ok {
			return nil, fmt.Errorf("%q is not an authentication method", n)
		}
		out[a] = true
	}
	return out, nil
}

func eapSet(names []string) (map[wire.EAPType]bool, error) {
	if len(names) == 0 {
		return nil, nil
	}
	out := make(map[wire.EAPType]bool, len(names))
	for _, n := range names {
		e, ok := wire.EAPTypeOf(n)
		if !ok {
			return nil, fmt.Errorf("%q is not an EAP method", n)
		}
		out[e] = true
	}
	return out, nil
}

func attrSet(names []string) (map[wire.AttrType]bool, error) {
	if len(names) == 0 {
		return nil, nil
	}
	out := make(map[wire.AttrType]bool, len(names))
	for _, n := range names {
		a, ok := wire.AttrOf(n)
		if !ok {
			return nil, fmt.Errorf("%q is not an attribute", n)
		}
		out[a] = true
	}
	return out, nil
}

// Client answers the address lists, which are asked before anything is
// parsed.
func (p *policy) Client(ip netip.Addr) bool {
	if contains(p.denyIPs, ip) {
		return false
	}
	if len(p.allowIPs) == 0 {
		return true
	}
	return contains(p.allowIPs, ip)
}

// NeedMAC reports whether a request from this client must carry a valid
// Message-Authenticator.
//
// It is answered before the rules decide anything, because it is an
// integrity question rather than a policy one -- and it is answered *by*
// the rules, because the one piece of equipment too old to send one is
// written down as a rule rather than by turning the check off for the
// estate. The rule lookup here matches on the address alone, which is all
// that is known before a packet has been verified: a rule that also named
// users would be deciding on a claim inside a packet whose integrity is
// exactly what is in question.
func (p *policy) NeedMAC(ip netip.Addr) bool {
	for _, r := range p.rules {
		if r.observe || len(r.nets) == 0 || !contains(r.nets, ip) {
			continue
		}
		if r.needMAC != nil {
			return *r.needMAC
		}
	}
	return p.needMAC
}

// Decide answers one request.
func (p *policy) Decide(req Request) Decision {
	if p.denyCodes[req.Code] {
		return Decision{Reason: "code_not_allowed", Detail: req.Code.String()}
	}
	if req.Code.Dynamic() && !p.dynamic {
		// Hard: carrying one of these to see what the policy would have
		// done ends or re-authorises a live user's session.
		return Decision{Reason: "dynamic_authorization_not_allowed",
			Detail: req.Code.String(), Hard: true}
	}
	if !p.codes[req.Code] {
		return Decision{Reason: "code_not_allowed", Detail: req.Code.String()}
	}
	if p.refuseProxy && hasAttr(req.Attrs, wire.AttrProxyState) {
		return Decision{Reason: "proxy_state_not_allowed"}
	}
	for _, a := range req.Attrs {
		if p.denyAttrs[a] {
			return Decision{Reason: "attribute_not_allowed", Detail: a.String()}
		}
	}
	if p.refusePAP && req.AuthType == wire.AuthPAP {
		return Decision{Reason: "plaintext_password"}
	}
	if d := p.authCheck(req); !d.Allow {
		return d
	}
	if d := p.eapCheck(req); !d.Allow {
		return d
	}
	if d := p.names(req); !d.Allow {
		return d
	}
	return p.rulesFor(req)
}

// authCheck applies the credential allow list, listener-wide and then by
// whichever rule names this request.
func (p *policy) authCheck(req Request) Decision {
	set := p.auth
	if r := p.match(req); r != nil && r.auth != nil {
		set = r.auth
	}
	if set != nil && !set[req.AuthType] {
		return Decision{Reason: "auth_type_not_allowed", Detail: string(req.AuthType)}
	}
	return Decision{Allow: true}
}

// eapCheck applies the EAP method policy, to the method asked for and to
// the methods a Nak offers instead.
//
// The offers matter as much as the method. A client that answers a PEAP
// request with a Nak naming EAP-MD5 has asked the server to downgrade, and
// a relay that checked only the type in the packet would see a Nak -- which
// is not a method -- and carry it.
func (p *policy) eapCheck(req Request) Decision {
	if !req.HasEAP {
		return Decision{Allow: true}
	}
	set := p.eap
	if r := p.match(req); r != nil && r.eap != nil {
		set = r.eap
	}
	check := func(e wire.EAPType, what string) Decision {
		if p.denyEAP[e] {
			return Decision{Reason: "eap_type_not_allowed", Detail: what + e.String()}
		}
		if p.refuseWeak && e.Weak() {
			return Decision{Reason: "weak_eap_type", Detail: what + e.String()}
		}
		if set != nil && !set[e] {
			return Decision{Reason: "eap_type_not_allowed", Detail: what + e.String()}
		}
		return Decision{Allow: true}
	}
	// The negotiation's own types are not methods: Identity, Notification
	// and Nak carry no credential and refusing them would refuse the first
	// round of every exchange.
	switch req.EAPType {
	case wire.EAPTypeIdentity, wire.EAPTypeNotification, wire.EAPTypeNak:
	default:
		if d := check(req.EAPType, ""); !d.Allow {
			return d
		}
	}
	for _, e := range req.EAPOffers {
		if e == 0 {
			// RFC 3748 §5.3.1's "no acceptable method", which is a client
			// giving up rather than asking for something.
			continue
		}
		if d := check(e, "offered "); !d.Allow {
			return d
		}
	}
	return Decision{Allow: true}
}

// names applies the user, realm and NAS lists.
func (p *policy) names(req Request) Decision {
	if req.Code != wire.CodeAccessRequest && req.Code != wire.CodeAccountingRequest {
		// A status query carries no name, and refusing one for not having
		// a name on a list would refuse every health check.
		return Decision{Allow: true}
	}
	u := strings.ToLower(req.User)
	if p.denyUsers[u] {
		return Decision{Reason: "user_not_allowed", Detail: req.User}
	}
	if p.users != nil && !p.users[u] {
		return Decision{Reason: "user_not_allowed", Detail: req.User}
	}
	rl := strings.ToLower(req.Realm)
	if req.Realm == "" {
		if p.needRealm {
			return Decision{Reason: "realm_required", Detail: req.User}
		}
	} else {
		if p.denyRealms[rl] {
			return Decision{Reason: "realm_not_allowed", Detail: req.Realm}
		}
		if p.realms != nil && !p.realms[rl] {
			return Decision{Reason: "realm_not_allowed", Detail: req.Realm}
		}
	}
	if p.nasIDs != nil && !p.nasIDs[strings.ToLower(req.NASID)] {
		return Decision{Reason: "nas_not_allowed", Detail: req.NASID}
	}
	return Decision{Allow: true}
}

// rulesFor finds the rule that decides this request and applies it.
func (p *policy) rulesFor(req Request) Decision {
	r := p.match(req)
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
	return Decision{Allow: true, Rule: r.name}
}

// match finds the first rule a request matches, in order.
func (p *policy) match(req Request) *rule {
	for _, r := range p.rules {
		if !r.covers(req) {
			continue
		}
		return r
	}
	return nil
}

func (r *rule) covers(req Request) bool {
	if len(r.nets) > 0 && !contains(r.nets, req.Client) {
		return false
	}
	if r.codes != nil && !r.codes[req.Code] {
		return false
	}
	if r.auth != nil && !r.auth[req.AuthType] {
		return false
	}
	if r.users != nil && !r.users[strings.ToLower(req.User)] {
		return false
	}
	if r.realms != nil && !r.realms[strings.ToLower(req.Realm)] {
		return false
	}
	if r.nasIDs != nil && !r.nasIDs[strings.ToLower(req.NASID)] {
		return false
	}
	if r.eap != nil && req.HasEAP && !r.eap[req.EAPType] {
		return false
	}
	return true
}

// Reply answers one reply, which is where privilege is decided.
func (p *policy) Reply(rep Reply) Decision {
	for _, a := range rep.Attrs {
		if p.denyReply[a] {
			return Decision{Reason: "reply_attribute_not_allowed", Detail: a.String()}
		}
	}
	if p.denyAdmin && rep.Administrative {
		return Decision{Reason: "administrative_reply_not_allowed", Rule: rep.Rule}
	}
	bound := p.maxPriv
	for _, r := range p.rules {
		if r.name == rep.Rule && r.maxPriv != nil {
			bound = *r.maxPriv
			break
		}
	}
	if rep.HasPrivilege && rep.Privilege > bound {
		return Decision{Reason: "privilege_too_high",
			Detail: fmt.Sprintf("priv-lvl=%d above %d", rep.Privilege, bound), Rule: rep.Rule}
	}
	return Decision{Allow: true}
}

// hasAttr reports whether a type is in a request's attribute list.
func hasAttr(list []wire.AttrType, t wire.AttrType) bool {
	for _, a := range list {
		if a == t {
			return true
		}
	}
	return false
}

// prefixes parses a list of CIDR networks, accepting a bare address as a
// host route -- which is what most of these lists are: one switch.
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
