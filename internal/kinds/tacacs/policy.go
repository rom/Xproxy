package tacacs

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/schedule"
	wire "github.com/rom/xproxy/internal/tacacs"
)

// The policy, compiled once at load.
//
// Three things about its shape.
//
// **The command is the unit.** Everything else here -- the exchange, the
// service, the authentication type -- narrows which commands a rule is
// about. A listener with no command lists is still useful: it bounds, it
// audits, it refuses by address, it refuses a FOLLOW. A listener *with* them
// is the only thing in an estate that can say "no router behind this relay
// accepts `write erase`, whatever the TACACS+ server's profiles say".
//
// **A pattern has a wildcard only at the end.** `show ...` covers every
// show command; `show running-config` covers exactly that. A hole in the
// middle is refused at load, because a pattern whose author and whose
// reader disagree about what it covers is worse than no pattern on a
// protocol that authorises each command separately.
//
// **The deny list is checked first and nothing overrides it.** That is how
// an exception inside an allowed set is written, and it is the shape every
// real device-administration policy has: allow `show ...`, deny `show
// running-config`.

// Decision is one policy answer.
type Decision struct {
	Allow  bool
	Reason string
	Detail string
	Rule   string
	// Hard marks a refusal that stands even in shadow mode: the ones about
	// what the *server* sent, where carrying it to see what would have
	// happened is the thing being prevented.
	Hard bool
}

// Request is what the policy decides about on the way in.
type Request struct {
	Client netip.Addr
	// Exchange is the packet type, and Seq its sequence number.
	Exchange wire.Type
	Seq      uint8
	Session  uint32
	// Action, AuthenType and Service come from an authentication start, or
	// from the session this packet belongs to.
	Action     wire.AuthenAction
	AuthenType wire.AuthenType
	Service    wire.AuthenService
	Method     wire.AuthenMethod
	PrivLvl    uint8
	User       string
	Port       string
	RemAddr    string
	// Command is the reassembled command line of an authorization or
	// accounting request, empty where the request is not about one.
	Command string
	// ServiceArg is the `service` argument's value: shell, ppp, junos-exec.
	ServiceArg string
	Args       wire.Args
	// Unencrypted says the body arrived in the clear.
	Unencrypted bool
	At          time.Time
}

// Answer is what the policy decides about on the way back: the privilege a
// server granted, and whether it tried to redirect the client.
type Answer struct {
	Client netip.Addr
	// Exchange is the packet type the answer belongs to.
	Exchange wire.Type
	// Status is rendered rather than typed, because the three exchanges
	// have three status enumerations and what the policy needs is the two
	// facts below plus a name for the log.
	Status string
	// Follow is a FOLLOW status in any of the three exchanges.
	Follow bool
	// Privilege is a `priv-lvl` argument in an authorization response,
	// which is the grant a device must apply.
	Privilege    int
	HasPrivilege bool
	// Pass says the server allowed what was asked.
	Pass bool
	// Rule is the rule that allowed the request this answers.
	Rule string
	At   time.Time
}

type rule struct {
	name     string
	action   string
	observe  bool
	nets     []netip.Prefix
	exchange map[wire.Type]bool
	users    map[string]bool
	cmds     []pattern
	denyCmds []pattern
	services map[string]bool
	authSvcs map[wire.AuthenService]bool
	authType map[wire.AuthenType]bool
	maxPriv  *int
	sched    *schedule.Window
}

type policy struct {
	allowByDef bool
	allowIPs   []netip.Prefix
	denyIPs    []netip.Prefix

	exchanges map[wire.Type]bool

	refuseClear bool
	allowFollow bool
	allowChpass bool
	allowSend   bool
	allowUnauth bool
	refusePlain bool

	authTypes map[wire.AuthenType]bool
	services  map[string]bool
	authSvcs  map[wire.AuthenService]bool
	users     map[string]bool
	denyUsers map[string]bool
	cmds      []pattern
	denyCmds  []pattern
	maxPriv   int
	maxArgs   int
	rules     []*rule
}

func compile(c *config.TACACSListener) (*policy, error) {
	p := &policy{
		allowByDef:  c.DefaultAction == "allow",
		refuseClear: boolOr(c.RefuseUnencrypted, true),
		allowFollow: boolOr(c.AllowFollow, false),
		allowChpass: boolOr(c.AllowChangePassword, false),
		allowSend:   boolOr(c.AllowSendAuth, false),
		allowUnauth: boolOr(c.AllowUnauthenticatedAuthorization, false),
		refusePlain: boolOr(c.RefusePlaintextPasswords, false),
		maxArgs:     or(c.MaxArgs, 64),
		maxPriv:     15,
	}
	if c.MaxPrivilegeLevel != nil {
		p.maxPriv = *c.MaxPrivilegeLevel
	}
	var err error
	if p.allowIPs, err = prefixes(c.AllowClients); err != nil {
		return nil, fmt.Errorf("allow_clients: %w", err)
	}
	if p.denyIPs, err = prefixes(c.DenyClients); err != nil {
		return nil, fmt.Errorf("deny_clients: %w", err)
	}
	if p.exchanges, err = typeSet(c.Exchanges); err != nil {
		return nil, fmt.Errorf("exchanges: %w", err)
	}
	if p.authTypes, err = authenTypeSet(c.AuthenTypes); err != nil {
		return nil, fmt.Errorf("authen_types: %w", err)
	}
	if p.authSvcs, err = serviceSet(c.AuthenServices); err != nil {
		return nil, fmt.Errorf("authen_services: %w", err)
	}
	if p.cmds, err = patterns(c.Commands); err != nil {
		return nil, fmt.Errorf("commands: %w", err)
	}
	if p.denyCmds, err = patterns(c.DenyCommands); err != nil {
		return nil, fmt.Errorf("deny_commands: %w", err)
	}
	p.services = lower(c.Services)
	p.users, p.denyUsers = lower(c.Users), lower(c.DenyUsers)
	for i := range c.Rules {
		r := &c.Rules[i]
		ru := &rule{name: r.Name, action: r.Action, observe: r.Action == "observe",
			users: lower(r.Users), services: lower(r.Services), maxPriv: r.MaxPrivilegeLevel}
		if ru.nets, err = prefixes(r.Clients); err != nil {
			return nil, fmt.Errorf("rules[%d].clients: %w", i, err)
		}
		if ru.exchange, err = typeSet(r.Exchanges); err != nil {
			return nil, fmt.Errorf("rules[%d].exchanges: %w", i, err)
		}
		if ru.authType, err = authenTypeSet(r.AuthenTypes); err != nil {
			return nil, fmt.Errorf("rules[%d].authen_types: %w", i, err)
		}
		if ru.authSvcs, err = serviceSet(r.AuthenServices); err != nil {
			return nil, fmt.Errorf("rules[%d].authen_services: %w", i, err)
		}
		if ru.cmds, err = patterns(r.Commands); err != nil {
			return nil, fmt.Errorf("rules[%d].commands: %w", i, err)
		}
		if ru.denyCmds, err = patterns(r.DenyCommands); err != nil {
			return nil, fmt.Errorf("rules[%d].deny_commands: %w", i, err)
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

func typeSet(names []string) (map[wire.Type]bool, error) {
	if len(names) == 0 {
		return nil, nil
	}
	out := make(map[wire.Type]bool, len(names))
	for _, n := range names {
		t, ok := wire.TypeOf(n)
		if !ok {
			return nil, fmt.Errorf("%q is not an exchange", n)
		}
		out[t] = true
	}
	return out, nil
}

func authenTypeSet(names []string) (map[wire.AuthenType]bool, error) {
	if len(names) == 0 {
		return nil, nil
	}
	out := make(map[wire.AuthenType]bool, len(names))
	for _, n := range names {
		a, ok := wire.AuthenTypeOf(n)
		if !ok {
			return nil, fmt.Errorf("%q is not an authentication type", n)
		}
		out[a] = true
	}
	return out, nil
}

func serviceSet(names []string) (map[wire.AuthenService]bool, error) {
	if len(names) == 0 {
		return nil, nil
	}
	out := make(map[wire.AuthenService]bool, len(names))
	for _, n := range names {
		s, ok := wire.ServiceOf(n)
		if !ok {
			return nil, fmt.Errorf("%q is not a service", n)
		}
		out[s] = true
	}
	return out, nil
}

// Client answers the address lists, asked before anything is read.
func (p *policy) Client(ip netip.Addr) bool {
	if contains(p.denyIPs, ip) {
		return false
	}
	return len(p.allowIPs) == 0 || contains(p.allowIPs, ip)
}

// Header decides what can be decided from the twelve octets in front of a
// body, which on a listener with no key is everything it will ever know.
func (p *policy) Header(ip netip.Addr, h wire.Header) Decision {
	if !h.Type.Known() {
		return Decision{Reason: "unknown_exchange", Detail: h.Type.String()}
	}
	if p.exchanges != nil && !p.exchanges[h.Type] {
		return Decision{Reason: "exchange_not_allowed", Detail: h.Type.String()}
	}
	if h.Unencrypted() && p.refuseClear {
		// Hard: the body of an administrative login is in the clear, and
		// carrying it to find out what the policy would have said puts a
		// password on the wire.
		return Decision{Reason: "unencrypted_body", Detail: h.Type.String(), Hard: true}
	}
	return Decision{Allow: true}
}

// Decide answers one request whose body this listener read.
func (p *policy) Decide(req Request) Decision {
	if len(req.Args) > p.maxArgs {
		return Decision{Reason: "too_many_arguments", Detail: itoa(len(req.Args))}
	}
	if d := p.authen(req); !d.Allow {
		return d
	}
	if req.Exchange == wire.TypeAuthor && req.Method.Unauthenticated() && !p.allowUnauth {
		return Decision{Reason: "unauthenticated_authorization", Detail: req.Method.String()}
	}
	if req.PrivLvl > uint8(p.maxPriv) { //nolint:gosec // maxPriv is validated to 0..15
		return Decision{Reason: "privilege_too_high",
			Detail: fmt.Sprintf("priv-lvl=%d above %d", req.PrivLvl, p.maxPriv)}
	}
	u := strings.ToLower(req.User)
	if req.User != "" {
		if p.denyUsers[u] {
			return Decision{Reason: "user_not_allowed", Detail: req.User}
		}
		if p.users != nil && !p.users[u] {
			return Decision{Reason: "user_not_allowed", Detail: req.User}
		}
	}
	if req.ServiceArg != "" && p.services != nil && !p.services[strings.ToLower(req.ServiceArg)] {
		return Decision{Reason: "service_not_allowed", Detail: req.ServiceArg}
	}
	r := p.match(req)
	if d := p.commands(req, r); !d.Allow {
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
	if r.maxPriv != nil && req.PrivLvl > uint8(*r.maxPriv) { //nolint:gosec // validated to 0..15
		return Decision{Reason: "privilege_too_high",
			Detail: fmt.Sprintf("priv-lvl=%d above %d", req.PrivLvl, *r.maxPriv), Rule: r.name}
	}
	return Decision{Allow: true, Rule: r.name}
}

// authen applies the settings about what kind of authentication a session
// is.
func (p *policy) authen(req Request) Decision {
	if req.Exchange != wire.TypeAuthen {
		// The action and the authentication type on an authorization or
		// accounting request describe how the user was authenticated
		// earlier, which the method field already covers. Refusing one here
		// would refuse a command because of how its session started, which
		// is a decision the session itself already took.
		if req.AuthenType != 0 && p.authTypes != nil && !p.authTypes[req.AuthenType] {
			return Decision{Reason: "authen_type_not_allowed", Detail: req.AuthenType.String()}
		}
		return Decision{Allow: true}
	}
	switch req.Action {
	case wire.ActionChangePass:
		if !p.allowChpass {
			return Decision{Reason: "change_password_not_allowed"}
		}
	case wire.ActionSendAuth:
		if !p.allowSend {
			// Hard: a SENDAUTH session asks the server to hand out a
			// credential for a peer, and carrying one to see what the
			// policy would have said hands it out.
			return Decision{Reason: "sendauth_not_allowed", Hard: true}
		}
	case wire.ActionLogin:
	default:
		return Decision{Reason: "unknown_action", Detail: req.Action.String()}
	}
	if !req.AuthenType.Known() {
		return Decision{Reason: "unknown_authen_type", Detail: req.AuthenType.String()}
	}
	if p.authTypes != nil && !p.authTypes[req.AuthenType] {
		return Decision{Reason: "authen_type_not_allowed", Detail: req.AuthenType.String()}
	}
	if p.refusePlain && req.AuthenType.Plaintext() {
		return Decision{Reason: "plaintext_password", Detail: req.AuthenType.String()}
	}
	if p.authSvcs != nil && !p.authSvcs[req.Service] {
		return Decision{Reason: "authen_service_not_allowed", Detail: req.Service.String()}
	}
	return Decision{Allow: true}
}

// commands applies the command lists: the rule's where it has them, the
// listener's otherwise, and the deny list first in both cases.
func (p *policy) commands(req Request, r *rule) Decision {
	if req.Command == "" {
		return Decision{Allow: true}
	}
	deny, allow := p.denyCmds, p.cmds
	if r != nil {
		if len(r.denyCmds) > 0 {
			deny = r.denyCmds
		}
		if len(r.cmds) > 0 {
			allow = r.cmds
		}
	}
	name := ruleName(r)
	if matchAny(deny, req.Command) {
		return Decision{Reason: "command_not_allowed", Detail: req.Command, Rule: name}
	}
	if len(allow) > 0 && !matchAny(allow, req.Command) {
		return Decision{Reason: "command_not_allowed", Detail: req.Command, Rule: name}
	}
	return Decision{Allow: true}
}

// Answer decides about one reply.
func (p *policy) Answer(a Answer) Decision {
	if a.Follow && !p.allowFollow {
		// Hard in every mode: a FOLLOW carries another server's address,
		// port and key, and a client that follows one sends its next
		// credential there. Carrying it to see what the policy would have
		// said is the thing being prevented.
		return Decision{Reason: "follow_not_allowed", Detail: a.Status, Hard: true}
	}
	bound := p.maxPriv
	for _, r := range p.rules {
		if r.name == a.Rule && r.maxPriv != nil {
			bound = *r.maxPriv
			break
		}
	}
	if a.HasPrivilege && a.Privilege > bound {
		return Decision{Reason: "privilege_grant_too_high",
			Detail: fmt.Sprintf("priv-lvl=%d above %d", a.Privilege, bound), Rule: a.Rule}
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
	if r.exchange != nil && !r.exchange[req.Exchange] {
		return false
	}
	if r.users != nil && !r.users[strings.ToLower(req.User)] {
		return false
	}
	if r.services != nil && !r.services[strings.ToLower(req.ServiceArg)] {
		return false
	}
	if r.authSvcs != nil && !r.authSvcs[req.Service] {
		return false
	}
	if r.authType != nil && !r.authType[req.AuthenType] {
		return false
	}
	// A rule whose command list does not cover this command does not
	// decide it. Without this a rule written to allow `show ...` would also
	// be the rule that decided `reload`, and `reload` would be allowed by
	// it -- which is the opposite of what its author wrote.
	if len(r.cmds) > 0 && req.Command != "" && !matchAny(r.cmds, req.Command) {
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

func itoa(n int) string { return fmt.Sprintf("%d", n) }

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
