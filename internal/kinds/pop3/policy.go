package pop3

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/pop3"
	"github.com/rom/xproxy/internal/schedule"
)

// The policy.
//
// The same five questions the imap kind asks, in the same order, with two
// differences that come from the protocol rather than from a choice.
//
// There is no mailbox: POP3 has exactly one, so a mailbox list would be a
// list with one entry. What takes its place is the retrieval bound, which is
// about volume rather than access and is the only thing here that
// distinguishes a client collecting its mail from a client collecting
// somebody's mail.
//
// And the credential question is simpler and harsher. There is no mechanism
// negotiation to inspect on the USER and PASS pair: the password is on the
// next line, so either the transport protects it or it is published.

// Decision is what the policy decided about one command.
type Decision struct {
	Allow  bool
	Reason string
	Detail string
	Rule   string
	Hard   bool
}

func allow(rule string) Decision { return Decision{Allow: true, Rule: rule} }

// Request is one command with what the session knows about it.
type Request struct {
	Client    netip.Addr
	User      string
	State     wire.State
	Encrypted bool
	Command   *wire.Command
	// Retrieved and Messages are the running totals this connection has
	// taken, which is what the bounds are measured against.
	Retrieved int64
	Messages  int
}

type rule struct {
	name     string
	users    map[string]bool
	clients  []netip.Prefix
	allow    map[string]bool
	deny     map[string]bool
	readOnly bool
	maxMsgs  int
	maxBytes int64
	deniedBy bool
	window   *schedule.Window
}

type policy struct {
	allowClients []netip.Prefix
	denyClients  []netip.Prefix
	mechanisms   map[string]bool
	users        map[string]bool
	allow        map[string]bool
	deny         map[string]bool
	readOnly     bool
	maxMsgs      int
	maxBytes     int64
	requireTLS   bool
	rules        []rule
	defaultAllow bool
	now          func() time.Time
}

func compile(c *config.POP3Listener) (*policy, error) {
	p := &policy{
		mechanisms:   lower(c.Mechanisms),
		users:        lower(c.Users),
		readOnly:     c.ReadOnly,
		maxMsgs:      c.MaxMessages,
		maxBytes:     c.MaxRetrBytes,
		requireTLS:   boolOn(c.RequireTLS),
		defaultAllow: c.DefaultAction != "deny",
		now:          time.Now,
	}
	var err error
	if p.allowClients, err = prefixes(c.AllowClients); err != nil {
		return nil, fmt.Errorf("allow_clients: %w", err)
	}
	if p.denyClients, err = prefixes(c.DenyClients); err != nil {
		return nil, fmt.Errorf("deny_clients: %w", err)
	}
	if p.allow, err = commands(c.Commands); err != nil {
		return nil, fmt.Errorf("commands: %w", err)
	}
	if p.deny, err = commands(c.DenyCommands); err != nil {
		return nil, fmt.Errorf("deny_commands: %w", err)
	}
	for i := range c.Rules {
		r, err := compileRule(&c.Rules[i])
		if err != nil {
			return nil, fmt.Errorf("rules[%d]: %w", i, err)
		}
		p.rules = append(p.rules, r)
	}
	return p, nil
}

func compileRule(rc *config.POP3Rule) (rule, error) {
	r := rule{
		name:     rc.Name,
		users:    lower(rc.Users),
		readOnly: rc.ReadOnly,
		maxMsgs:  rc.MaxMessages,
		maxBytes: rc.MaxRetrBytes,
		deniedBy: rc.Action == "deny",
	}
	var err error
	if r.clients, err = prefixes(rc.Clients); err != nil {
		return r, fmt.Errorf("clients: %w", err)
	}
	if r.allow, err = commands(rc.Commands); err != nil {
		return r, fmt.Errorf("commands: %w", err)
	}
	if r.deny, err = commands(rc.DenyCommands); err != nil {
		return r, fmt.Errorf("deny_commands: %w", err)
	}
	if r.window, err = schedule.Compile(rc.Schedule); err != nil {
		return r, fmt.Errorf("schedule: %w", err)
	}
	return r, nil
}

// commands folds a command list and refuses a name this relay has no
// meaning for: a rule naming one would never match, and an operator would
// believe something was allowed that nothing decides about.
func commands(in []string) (map[string]bool, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make(map[string]bool, len(in))
	for _, s := range in {
		name := strings.ToUpper(strings.TrimSpace(s))
		if name == "" {
			continue
		}
		if !wire.Known(name) {
			return nil, fmt.Errorf("%q is not a POP3 command this relay knows; the commands are %s",
				s, strings.Join(wire.Names(), ", "))
		}
		out[name] = true
	}
	return out, nil
}

func prefixes(in []string) ([]netip.Prefix, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
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

// Client reports whether an address may connect at all.
func (p *policy) Client(ip netip.Addr) bool {
	for _, n := range p.denyClients {
		if n.Contains(ip) {
			return false
		}
	}
	if len(p.allowClients) == 0 {
		return true
	}
	for _, n := range p.allowClients {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Mechanism decides about an authentication attempt before the credential
// travels. `user` is the USER and PASS pair, `apop` the digest, and anything
// else a SASL mechanism name.
func (p *policy) Mechanism(name string, encrypted bool) Decision {
	folded := strings.ToLower(name)
	// APOP is a digest rather than a password, so the transport question is
	// about the other two and about the SASL mechanisms that carry one.
	plaintext := folded == "user" || wire.Plaintext(folded)
	if p.requireTLS && !encrypted && plaintext {
		return Decision{Reason: "tls_required", Detail: folded, Hard: true}
	}
	if len(p.mechanisms) > 0 && !p.mechanisms[folded] {
		return Decision{Reason: "mechanism_not_allowed", Detail: folded}
	}
	return allow("")
}

// User decides about a claimed identity.
func (p *policy) User(name string) Decision {
	if len(p.users) == 0 {
		return allow("")
	}
	if !p.users[strings.ToLower(name)] {
		return Decision{Reason: "user_not_allowed", Detail: clipName(name)}
	}
	return allow("")
}

// Decide decides about one command.
func (p *policy) Decide(req Request) Decision {
	cmd := req.Command
	if !wire.Known(cmd.Name) {
		return Decision{Reason: "unknown_command", Detail: cmd.Name, Hard: true}
	}
	if !wire.AllowedIn(cmd.Name, req.State) {
		return Decision{Reason: "wrong_state",
			Detail: cmd.Name + " in " + req.State.String(), Hard: true}
	}
	if _, _, err := cmd.Message(); err != nil {
		return Decision{Reason: "malformed_message_number", Detail: err.Error(), Hard: true}
	}
	if _, _, err := cmd.Lines(); err != nil {
		return Decision{Reason: "malformed_line_count", Detail: err.Error(), Hard: true}
	}
	r, found := p.ruleFor(req)
	if found && r.deniedBy {
		return Decision{Reason: "rule_denied", Rule: r.name}
	}
	if cmd.Writes() {
		if p.readOnly {
			return Decision{Reason: "read_only", Detail: cmd.Name}
		}
		if found && r.readOnly {
			return Decision{Reason: "read_only", Detail: cmd.Name, Rule: r.name}
		}
	}
	if p.deny[cmd.Name] {
		return Decision{Reason: "command_denied", Detail: cmd.Name}
	}
	if len(p.allow) > 0 && !p.allow[cmd.Name] {
		return Decision{Reason: "command_not_allowed", Detail: cmd.Name}
	}
	if found {
		if r.deny[cmd.Name] {
			return Decision{Reason: "command_denied", Detail: cmd.Name, Rule: r.name}
		}
		if len(r.allow) > 0 && !r.allow[cmd.Name] {
			return Decision{Reason: "command_not_allowed", Detail: cmd.Name, Rule: r.name}
		}
	}
	if d := p.boundsCheck(req, r, found); !d.Allow {
		return d
	}
	if found {
		return allow(r.name)
	}
	if !p.defaultAllow {
		return Decision{Reason: "default_deny"}
	}
	return allow("")
}

// boundsCheck is the copying bound, measured against what this connection
// has already taken.
//
// It is checked before the command rather than only during it, so a client
// that has reached the bound is told no rather than cut off mid-message --
// and it is checked during the transfer as well, in the relay, because a
// single RETR of a 2 GB message would otherwise pass a check made before
// anybody knew the size.
func (p *policy) boundsCheck(req Request, r rule, found bool) Decision {
	if !req.Command.Collects() {
		return allow("")
	}
	maxMsgs, maxBytes, ruleName := p.maxMsgs, p.maxBytes, ""
	if found {
		if r.maxMsgs > 0 {
			maxMsgs, ruleName = r.maxMsgs, r.name
		}
		if r.maxBytes > 0 {
			maxBytes, ruleName = r.maxBytes, r.name
		}
	}
	if maxMsgs > 0 && req.Messages >= maxMsgs {
		return Decision{Reason: "too_many_messages",
			Detail: fmt.Sprintf("%d retrieved, the bound is %d", req.Messages, maxMsgs),
			Rule:   ruleName}
	}
	if maxBytes > 0 && req.Retrieved >= maxBytes {
		return Decision{Reason: "retrieval_too_large",
			Detail: fmt.Sprintf("%d octets retrieved, the bound is %d", req.Retrieved, maxBytes),
			Rule:   ruleName}
	}
	return allow(ruleName)
}

// Bounds are the two running limits in force for a request, which the relay
// needs while a transfer is in flight rather than before it.
func (p *policy) Bounds(req Request) (maxMsgs int, maxBytes int64) {
	maxMsgs, maxBytes = p.maxMsgs, p.maxBytes
	if r, found := p.ruleFor(req); found {
		if r.maxMsgs > 0 {
			maxMsgs = r.maxMsgs
		}
		if r.maxBytes > 0 {
			maxBytes = r.maxBytes
		}
	}
	return maxMsgs, maxBytes
}

func (p *policy) ruleFor(req Request) (rule, bool) {
	for _, r := range p.rules {
		if len(r.users) > 0 && !r.users[strings.ToLower(req.User)] {
			continue
		}
		if len(r.clients) > 0 && !contains(r.clients, req.Client) {
			continue
		}
		if r.window != nil && !r.window.InForce(p.now()) {
			continue
		}
		return r, true
	}
	return rule{}, false
}

func contains(ns []netip.Prefix, ip netip.Addr) bool {
	for _, n := range ns {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func clipName(s string) string {
	const max = 64
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

func lower(in []string) map[string]bool {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]bool, len(in))
	for _, s := range in {
		if v := strings.ToLower(strings.TrimSpace(s)); v != "" {
			out[v] = true
		}
	}
	return out
}

// boolOn reads an optional boolean that defaults on, which is every one of
// them on this kind: the transport check, the logs and the alerts.
func boolOn(p *bool) bool { return p == nil || *p }

func or[T comparable](v, def T) T {
	var zero T
	if v == zero {
		return def
	}
	return v
}
