package imap

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/imap"
	"github.com/rom/xproxy/internal/schedule"
)

// The policy.
//
// Five questions, asked in this order, because the cheapest and least
// revocable come first:
//
//  1. Is the command one this relay knows? An unknown command is refused
//     rather than forwarded, because a relay that carries what it cannot
//     name is a tunnel.
//  2. Is it legal in the state the connection is in? RFC 9051 says which
//     commands belong where, and a FETCH before a SELECT is answered here
//     rather than by the mailbox.
//  3. Does the credential need a transport it has not got? LOGIN and the
//     plaintext mechanisms are refused on a connection in the clear, and
//     that refusal is not shadowable: the password travels before any
//     policy could run.
//  4. Do the lists admit it -- the command, the mailbox, the mechanism,
//     the claimed identity?
//  5. Are the bounds satisfied -- the sequence set, the literal?
//
// A rule narrows all of that for a named set of users, clients and
// mailboxes, which is how "this account may read its own mail and nothing
// else" is written down.

// Decision is what the policy decided about one command.
type Decision struct {
	// Allow is whether the command may cross.
	Allow bool
	// Reason is the refusal reason, which is the counter name and the
	// security event's, and is what the client is told.
	Reason string
	// Detail is the one safe fact about why, for the log line.
	Detail string
	// Rule is the name of the rule that decided, where one did.
	Rule string
	// Hard marks a refusal shadow mode does not defer: the password has
	// already travelled, or the request is one no configuration admits.
	Hard bool
}

func allow(rule string) Decision { return Decision{Allow: true, Rule: rule} }

// Request is one command, with what the session knows about it.
type Request struct {
	// Client is the address the command came from.
	Client netip.Addr
	// User is the identity this connection claimed, where it has.
	User string
	// State is where the connection stood when the command arrived.
	State wire.State
	// Encrypted is whether the client's leg is TLS.
	Encrypted bool
	// Command is the parsed command.
	Command *wire.Command
	// Mailboxes are the mailbox names it refers to, decoded.
	Mailboxes []string
	// Messages is how many messages its sequence set names, Open where
	// the set runs to the end of the mailbox.
	Messages uint64
	Open     bool
	// Literal is the declared size of the literal the line ends with.
	Literal int
}

// rule is one compiled rule.
type rule struct {
	name      string
	users     map[string]bool
	clients   []netip.Prefix
	mailboxes []pattern
	allow     map[string]bool
	deny      map[string]bool
	readOnly  bool
	maxFetch  int
	maxAppend int
	deniedBy  bool
	window    *schedule.Window
}

// policy is the compiled listener policy.
type policy struct {
	allowClients []netip.Prefix
	denyClients  []netip.Prefix
	mechanisms   map[string]bool
	users        map[string]bool
	allow        map[string]bool
	deny         map[string]bool
	mailboxes    []pattern
	denyMailbox  []pattern
	readOnly     bool
	maxFetch     int
	maxAppend    int
	maxLiteral   int
	openSets     bool
	requireTLS   bool
	allowIdle    bool
	noCompress   bool
	rules        []rule
	defaultAllow bool
	now          func() time.Time
}

// compile turns the configuration into the policy, refusing at load what
// cannot be a policy: a command this relay has no name for, a mechanism
// that is not a mechanism, a mailbox pattern with a wildcard in the middle.
func compile(c *config.IMAPListener) (*policy, error) {
	p := &policy{
		mechanisms:   lower(c.Mechanisms),
		users:        lower(c.Users),
		readOnly:     c.ReadOnly,
		maxFetch:     c.MaxFetchMessages,
		maxAppend:    or(c.MaxAppendBytes, 32<<20),
		maxLiteral:   or(c.MaxLiteralBytes, 64<<10),
		openSets:     boolOr(c.AllowOpenSets, false),
		requireTLS:   boolOr(c.RequireTLS, true),
		allowIdle:    boolOr(c.AllowIdle, true),
		noCompress:   boolOr(c.RefuseCompression, true),
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
	if p.mailboxes, err = patterns(c.Mailboxes); err != nil {
		return nil, fmt.Errorf("mailboxes: %w", err)
	}
	if p.denyMailbox, err = patterns(c.DenyMailboxes); err != nil {
		return nil, fmt.Errorf("deny_mailboxes: %w", err)
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

func compileRule(rc *config.IMAPRule) (rule, error) {
	r := rule{
		name:      rc.Name,
		users:     lower(rc.Users),
		readOnly:  rc.ReadOnly,
		maxFetch:  rc.MaxFetchMessages,
		maxAppend: rc.MaxAppendBytes,
		deniedBy:  rc.Action == "deny",
	}
	var err error
	if r.clients, err = prefixes(rc.Clients); err != nil {
		return r, fmt.Errorf("clients: %w", err)
	}
	if r.mailboxes, err = patterns(rc.Mailboxes); err != nil {
		return r, fmt.Errorf("mailboxes: %w", err)
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
// meaning for, because a rule naming one would be a rule that never
// matches and an operator who thinks something is allowed.
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
			return nil, fmt.Errorf("%q is not an IMAP command this relay knows; the commands are %s",
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

// Mechanism decides about an authentication attempt, before the credential
// travels.
//
// The transport question is answered first and its refusal is Hard: a
// LOGIN on a connection in the clear has published the password by the
// time any list is consulted, so there is nothing for shadow mode to
// defer.
func (p *policy) Mechanism(name string, encrypted bool) Decision {
	folded := strings.ToLower(name)
	if p.requireTLS && !encrypted && (folded == "login" || wire.Plaintext(name)) {
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
	name := cmd.Effective()
	if !wire.Known(cmd.Name) {
		return Decision{Reason: "unknown_command", Detail: cmd.Name, Hard: true}
	}
	if cmd.Name == "UID" && cmd.Sub == "" {
		return Decision{Reason: "malformed_command", Detail: "UID with no command", Hard: true}
	}
	if !wire.AllowedIn(cmd.Name, req.State) {
		return Decision{Reason: "wrong_state",
			Detail: cmd.Name + " in " + req.State.String(), Hard: true}
	}
	if name == "IDLE" && !p.allowIdle {
		return Decision{Reason: "idle_not_allowed"}
	}
	if name == "COMPRESS" || (p.noCompress && strings.HasPrefix(name, "COMPRESS")) {
		return Decision{Reason: "compression_not_allowed", Detail: name, Hard: true}
	}
	r, found := p.ruleFor(req)
	if found && r.deniedBy {
		return Decision{Reason: "rule_denied", Rule: r.name}
	}
	if d := p.mailboxCheck(req, r, found); !d.Allow {
		return d
	}
	if d := p.commandCheck(name, cmd, r, found); !d.Allow {
		return d
	}
	if d := p.boundsCheck(req, name, r, found); !d.Allow {
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

// ruleFor is the first rule whose users, clients, mailboxes and schedule
// all match.
func (p *policy) ruleFor(req Request) (rule, bool) {
	for _, r := range p.rules {
		if len(r.users) > 0 && !r.users[strings.ToLower(req.User)] {
			continue
		}
		if len(r.clients) > 0 && !contains(r.clients, req.Client) {
			continue
		}
		if len(r.mailboxes) > 0 && !matchAll(r.mailboxes, req.Mailboxes) {
			continue
		}
		if r.window != nil && !r.window.InForce(p.now()) {
			continue
		}
		return r, true
	}
	return rule{}, false
}

// mailboxCheck applies the listener's lists and the rule's, on the decoded
// name. A command that names no mailbox is not a mailbox decision.
func (p *policy) mailboxCheck(req Request, r rule, found bool) Decision {
	for _, m := range req.Mailboxes {
		if matchAny(p.denyMailbox, m) {
			return Decision{Reason: "mailbox_denied", Detail: clipName(m)}
		}
		if len(p.mailboxes) > 0 && !matchAny(p.mailboxes, m) {
			return Decision{Reason: "mailbox_not_allowed", Detail: clipName(m)}
		}
		if found && len(r.mailboxes) > 0 && !matchAny(r.mailboxes, m) {
			return Decision{Reason: "mailbox_not_allowed", Detail: clipName(m), Rule: r.name}
		}
	}
	return allow("")
}

// commandCheck applies the command lists and the read-only switches.
func (p *policy) commandCheck(name string, cmd *wire.Command, r rule, found bool) Decision {
	writes := wire.Writes(cmd)
	if p.readOnly && writes {
		return Decision{Reason: "read_only", Detail: name}
	}
	if found && r.readOnly && writes {
		return Decision{Reason: "read_only", Detail: name, Rule: r.name}
	}
	if p.deny[name] {
		return Decision{Reason: "command_denied", Detail: name}
	}
	if len(p.allow) > 0 && !p.allow[name] {
		return Decision{Reason: "command_not_allowed", Detail: name}
	}
	if found {
		if r.deny[name] {
			return Decision{Reason: "command_denied", Detail: name, Rule: r.name}
		}
		if len(r.allow) > 0 && !r.allow[name] {
			return Decision{Reason: "command_not_allowed", Detail: name, Rule: r.name}
		}
	}
	return allow("")
}

// boundsCheck applies the two bounds that are about volume rather than
// access: how much of a mailbox one request may name, and how large a
// message written into one may be.
//
// The literal bound is the one that has to be decided here rather than
// while reading: LITERAL+ sends the octets without waiting, so a bound
// checked against what arrived is a bound checked after the fact.
func (p *policy) boundsCheck(req Request, name string, r rule, found bool) Decision {
	maxFetch, maxAppend := p.maxFetch, p.maxAppend
	ruleName := ""
	if found {
		if r.maxFetch > 0 {
			maxFetch, ruleName = r.maxFetch, r.name
		}
		if r.maxAppend > 0 {
			maxAppend, ruleName = r.maxAppend, r.name
		}
	}
	if maxFetch > 0 && wire.Collects(req.Command) {
		if req.Open && !p.openSets {
			return Decision{Reason: "open_sequence_set",
				Detail: name + " to the end of the mailbox", Rule: ruleName}
		}
		if maxFetch > 0 && req.Messages > uint64(maxFetch) { //nolint:gosec // validation refuses a negative bound
			return Decision{Reason: "fetch_too_large",
				Detail: fmt.Sprintf("%s names %d messages, the bound is %d", name, req.Messages, maxFetch),
				Rule:   ruleName}
		}
	}
	if req.Literal > 0 {
		bound := p.maxLiteral
		reason := "literal_too_large"
		if name == "APPEND" {
			bound, reason = maxAppend, "append_too_large"
		}
		if bound > 0 && req.Literal > bound {
			return Decision{Reason: reason,
				Detail: fmt.Sprintf("%d octets, the bound is %d", req.Literal, bound),
				Rule:   ruleName}
		}
	}
	return allow(ruleName)
}

// Answer decides about a response, which on this protocol is a decision of
// its own rather than a formality.
//
// A PREAUTH greeting says the connection is authenticated before anybody
// claimed an identity: carrying it would make every later decision about a
// name this relay never saw, so it is refused rather than forwarded.
func (p *policy) Answer(r *wire.Response, preauthRefused bool) Decision {
	if r.Preauth() && preauthRefused {
		return Decision{Reason: "preauth_greeting", Detail: "the server authenticated the transport", Hard: true}
	}
	return allow("")
}

// pattern is a compiled mailbox pattern: the literal words before a
// wildcard, and which wildcard ended it.
//
// IMAP has two, and they mean different things: `*` matches the rest of
// the name including the hierarchy separator, `%` matches within one
// level. A policy that treated them the same would admit
// `Shared/Everyone/HR` under a rule written `Shared/%`.
type pattern struct {
	raw   string
	lit   string
	star  bool
	level bool
}

// patterns compiles a mailbox list, refusing a wildcard that is not at the
// end: `Sent*box` reads as a pattern and is not one, and a comparison that
// quietly treated it as a literal would be a rule nobody wrote.
func patterns(in []string) ([]pattern, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make([]pattern, 0, len(in))
	for _, s := range in {
		raw := strings.TrimSpace(s)
		if raw == "" {
			continue
		}
		p := pattern{raw: raw, lit: raw}
		switch {
		case strings.HasSuffix(raw, "*"):
			p.star, p.lit = true, raw[:len(raw)-1]
		case strings.HasSuffix(raw, "%"):
			p.level, p.lit = true, raw[:len(raw)-1]
		}
		if i := strings.IndexAny(p.lit, "*%"); i >= 0 {
			return nil, fmt.Errorf("%q: a wildcard is only ever the last character", s)
		}
		out = append(out, p)
	}
	return out, nil
}

// match reports whether a decoded mailbox name matches.
//
// The comparison folds case for INBOX alone, which is the one name RFC
// 9051 §5.1 makes case-insensitive; every other name is the server's and
// is compared as it stands, because a mailbox called `Archive` and one
// called `archive` are two mailboxes.
func (p pattern) match(name string) bool {
	lit, n := p.lit, name
	if strings.EqualFold(lit, "inbox") && strings.EqualFold(name, "inbox") {
		return true
	}
	switch {
	case p.star:
		return strings.HasPrefix(n, lit)
	case p.level:
		if !strings.HasPrefix(n, lit) {
			return false
		}
		rest := n[len(lit):]
		return !strings.ContainsAny(rest, "/.")
	default:
		return n == lit
	}
}

func matchAny(ps []pattern, name string) bool {
	for _, p := range ps {
		if p.match(name) {
			return true
		}
	}
	return false
}

// matchAll is for a rule's selector: every mailbox the command names has
// to match, because a COPY names two and a rule that matched on one of
// them would decide about the other without having been written for it.
func matchAll(ps []pattern, names []string) bool {
	if len(names) == 0 {
		return false
	}
	for _, n := range names {
		if !matchAny(ps, n) {
			return false
		}
	}
	return true
}

func contains(ns []netip.Prefix, ip netip.Addr) bool {
	for _, n := range ns {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// clipName bounds a name on its way into a log line. The textsafe package
// handles the control characters; this is the length.
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

func boolOr(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

func or[T comparable](v, def T) T {
	var zero T
	if v == zero {
		return def
	}
	return v
}
