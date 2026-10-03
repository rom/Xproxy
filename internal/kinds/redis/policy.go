package redis

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/respwire"
	"github.com/rom/xproxy/internal/schedule"
)

// The policy, in Redis's own terms.
//
// This protocol has the least structure in the project and the most dangerous
// default posture. There is no schema, no statement grammar and nothing to
// classify by shape: a command is an array of opaque byte strings. And Redis's own
// default is no password at all, so an instance that is reachable is an instance
// that is administrable.
//
// So the policy is built on four things, in the order they are decided.
//
// **Authentication before anything else.** A command that arrives before the
// connection has authenticated is refused, hard. This is the one that turns
// "reachable" back into "authorised" in front of a server whose `requirepass` is
// unset -- which is most of them -- and it is why the refusal cannot be shadowed:
// forwarding an unauthenticated command and writing down that it was noticed means
// the command ran.
//
// **The command name, as an allow list.** Defaulting to what an application does
// to a cache. The absences are the whole of the value, because on Redis the
// distance between an administrative command and remote code execution is one
// command: `CONFIG SET dir` plus `CONFIG SET dbfilename` plus `SAVE` writes a file
// wherever the server can write, which pointed at a cron directory is a shell.
//
// **The subcommand, where it is the whole of what matters.** `CONFIG GET` is a
// read and `CONFIG SET` is the above, so a policy that could only say CONFIG would
// have to refuse both or neither.
//
// **The key prefix**, which is the closest this protocol has to the
// database-and-table boundary the SQL kinds leave to GRANT. It works only because
// the wire package knows where each command's keys are -- and, crucially, says so
// when it does not: a command whose key positions depend on an option is refused
// while a prefix policy is in force rather than checked against the wrong
// argument, which would be a policy that passes exactly what it was meant to stop.

// Decision is what the policy says about one thing a client did.
type Decision struct {
	Allow          bool
	Reason, Detail string
	// Hard says the refusal stands even in shadow mode.
	Hard bool
	Rule string
	// Observed names the observe rules this session matched. They are recorded
	// in the log line and decide nothing, which is what lets a rule be tried on
	// live traffic before it decides anything.
	Observed []string
}

func deny(reason string) Decision { return Decision{Reason: reason} }
func hardDeny(reason, detail string) Decision {
	return Decision{Reason: reason, Detail: detail, Hard: true}
}

type policy struct {
	allowIPs, denyIPs []netip.Prefix

	allowUsers, denyUsers []string

	requireTLS  bool
	requireAuth bool
	allowInline bool

	allowCmds, denyCmds map[string]bool
	allowSubs, denySubs map[string]bool
	allowPrefix         []string
	denyPrefix          []string
	allowDBs            map[int]bool

	readOnly bool

	maxMessage, maxBulk, maxElements int
	maxCommands                      int

	rules []*rule

	allowByDef bool
	nak        bool
	monitor    bool
}

type rule struct {
	name    string
	clients []netip.Prefix
	users   []string
	sched   *schedule.Window
	observe bool
	action  string

	allowCmds, denyCmds map[string]bool
	allowSubs, denySubs map[string]bool
	allowPrefix         []string
	denyPrefix          []string
	readOnly            *bool
	maxCommands         int
}

func compile(c *config.RedisListener) (*policy, error) {
	p := &policy{
		requireTLS:  c.RequireTLS == nil || *c.RequireTLS,
		requireAuth: c.RequireAuth == nil || *c.RequireAuth,
		allowInline: c.AllowInline,
		readOnly:    c.ReadOnly,
		maxMessage:  or(c.MaxMessageBytes, wire.DefaultMaxMessage),
		maxBulk:     or(c.MaxBulkBytes, wire.DefaultMaxBulk),
		maxElements: or(c.MaxElements, wire.DefaultMaxElements),
		maxCommands: c.MaxCommands,
		monitor:     c.MonitorOnly,
		nak:         c.DenyResponse != "drop",
		allowUsers:  lower(c.AllowUsers),
		denyUsers:   lower(c.DenyUsers),
		allowPrefix: c.AllowKeyPrefixes,
		denyPrefix:  c.DenyKeyPrefixes,
	}
	switch c.DefaultAction {
	case "", "deny":
	case "allow":
		p.allowByDef = true
	default:
		return nil, fmt.Errorf("default_action: %q is not allow or deny", c.DefaultAction)
	}
	var err error
	if p.allowIPs, err = prefixes(c.AllowClients); err != nil {
		return nil, fmt.Errorf("redis allow_clients: %w", err)
	}
	if p.denyIPs, err = prefixes(c.DenyClients); err != nil {
		return nil, fmt.Errorf("redis deny_clients: %w", err)
	}
	p.allowCmds = cmdSet(c.AllowCommands)
	if p.allowCmds == nil {
		p.allowCmds = cmdSet(wire.DefaultCommands())
	}
	p.denyCmds = cmdSet(c.DenyCommands)
	if p.allowSubs, err = subSet(c.AllowSubcommands, "allow_subcommands"); err != nil {
		return nil, err
	}
	if p.denySubs, err = subSet(c.DenySubcommands, "deny_subcommands"); err != nil {
		return nil, err
	}
	if len(c.AllowDatabases) > 0 {
		p.allowDBs = make(map[int]bool, len(c.AllowDatabases))
		for _, db := range c.AllowDatabases {
			if db < 0 {
				return nil, fmt.Errorf("allow_databases: %d is not a database number", db)
			}
			p.allowDBs[db] = true
		}
	}
	for i := range c.Rules {
		r, err := compileRule(&c.Rules[i], i)
		if err != nil {
			return nil, err
		}
		p.rules = append(p.rules, r)
	}
	return p, nil
}

func compileRule(rc *config.RedisRule, i int) (*rule, error) {
	r := &rule{name: rc.Name, users: lower(rc.Users), action: rc.Action,
		allowPrefix: rc.AllowKeyPrefixes, denyPrefix: rc.DenyKeyPrefixes,
		maxCommands: rc.MaxCommands}
	if r.name == "" {
		r.name = fmt.Sprintf("rules[%d]", i)
	}
	switch rc.Action {
	case "", "allow":
		r.action = "allow"
	case "deny":
	case "observe":
		r.observe = true
	default:
		return nil, fmt.Errorf("rules[%d].action: %q is not allow, deny or observe", i, rc.Action)
	}
	var err error
	if r.clients, err = prefixes(rc.Clients); err != nil {
		return nil, fmt.Errorf("rules[%d].clients: %w", i, err)
	}
	r.allowCmds = cmdSet(rc.AllowCommands)
	r.denyCmds = cmdSet(rc.DenyCommands)
	if r.allowSubs, err = subSet(rc.AllowSubcommands,
		fmt.Sprintf("rules[%d].allow_subcommands", i)); err != nil {
		return nil, err
	}
	if r.denySubs, err = subSet(rc.DenySubcommands,
		fmt.Sprintf("rules[%d].deny_subcommands", i)); err != nil {
		return nil, err
	}
	if rc.ReadOnly != nil {
		v := *rc.ReadOnly
		r.readOnly = &v
	}
	if rc.Schedule != nil {
		if r.sched, err = schedule.Compile(rc.Schedule); err != nil {
			return nil, fmt.Errorf("rules[%d].schedule: %w", i, err)
		}
	}
	return r, nil
}

// cmdSet folds the names, because that is the spelling the reader produces and a
// policy holding two would match neither reliably.
func cmdSet(names []string) map[string]bool {
	if len(names) == 0 {
		return nil
	}
	out := make(map[string]bool, len(names))
	for _, n := range names {
		out[strings.ToUpper(strings.TrimSpace(n))] = true
	}
	return out
}

// subSet reads the "CONTAINER SUB" spellings into "CONTAINER SUB" keys.
func subSet(names []string, field string) (map[string]bool, error) {
	if len(names) == 0 {
		return nil, nil
	}
	out := make(map[string]bool, len(names))
	for i, n := range names {
		fields := strings.Fields(strings.ToUpper(n))
		if len(fields) != 2 {
			return nil, fmt.Errorf("%s[%d]: %q is not a container command and a subcommand",
				field, i, n)
		}
		out[fields[0]+" "+fields[1]] = true
	}
	return out, nil
}

// Session is what the policy knows about a connection when it decides.
type Session struct {
	IP       netip.Addr
	User     string
	Secure   bool
	Authed   bool
	Database int
	At       time.Time
}

// Bounds the reader needs.
func (p *policy) MaxMessage() int  { return p.maxMessage }
func (p *policy) MaxBulk() int     { return p.maxBulk }
func (p *policy) MaxElements() int { return p.maxElements }

// Connect decides about a connection before a single command is read.
func (p *policy) Connect(se *Session) Decision {
	if !p.admits(se.IP) {
		return hardDeny("client_not_allowed", "")
	}
	if p.requireTLS && !se.Secure {
		// Hard: an AUTH on this connection would put the password on the wire as
		// an ordinary command argument, and so would every value after it.
		return hardDeny("tls_required", "")
	}
	return Decision{Allow: true}
}

// Auth decides about an AUTH or a HELLO carrying credentials.
//
// The user list applies to the name the client asked to be, not to a name the
// server confirmed -- the server decides whether the password is right, and this
// decides which attempts may even be made. That is the same distinction the
// postgres and mysql kinds draw, and worth keeping because on Redis the
// one-argument AUTH form names no user at all: it authenticates as `default`, so
// that is the name it is judged under.
func (p *policy) Auth(se *Session, user string) Decision {
	if user == "" {
		user = "default"
	}
	if !permitted(strings.ToLower(user), p.allowUsers, p.denyUsers) {
		return deny("user_not_allowed")
	}
	return Decision{Allow: true}
}

// Command decides about one command.
//
// The order is: the deny lists, then the things that cannot be read, then
// authentication, then the allow lists, then read-only, then the keys. Each step
// is before the next for a reason, and the first two are before authentication
// because a command the relay could not read is not made safe by a password.
func (p *policy) Command(se *Session, c *wire.Command) (d Decision) {
	// The observe rules this session matched go on whatever is decided: they
	// are the record of a rule being tried, and a deferred assignment is how
	// every return below carries it without the decisions themselves having to
	// know about it.
	defer func() { d.Observed = p.observed(se) }()
	r := p.match(se)

	if c.Inline && !p.allowInline {
		// Not hard: it is a form, not an escalation, and an operator running a
		// trial wants to see whether anything of theirs uses it.
		return Decision{Reason: "inline_not_allowed", Detail: c.Name, Rule: ruleName(r)}
	}

	// The deny lists win over everything below, including a rule's allow list.
	if p.denyCmds[c.Name] {
		return p.harden(c.Name, Decision{Reason: "command_denied", Detail: c.String()})
	}
	if r != nil && r.denyCmds[c.Name] {
		return p.harden(c.Name, Decision{Reason: "command_denied", Detail: c.String(), Rule: r.name})
	}
	if c.Sub != "" {
		full := c.Name + " " + c.Sub
		if p.denySubs[full] || (r != nil && r.denySubs[full]) {
			return p.harden(c.Name, Decision{Reason: "subcommand_denied",
				Detail: c.String(), Rule: ruleName(r)})
		}
	}

	// Authentication. Everything a client may legitimately send before it has
	// authenticated is here by name, because the alternative -- letting anything
	// through until an OK arrives -- is the hole this setting exists to close.
	if p.requireAuth && !se.Authed && !preAuth(c.Name) {
		return hardDeny("not_authenticated", c.String())
	}

	// The allow lists. A rule that names commands widens the listener for its own
	// traffic; one that names none inherits the listener's list.
	allowed := p.allowCmds
	if r != nil && r.allowCmds != nil {
		allowed = r.allowCmds
	}
	if !allowed[c.Name] {
		return p.harden(c.Name, Decision{Reason: "command_not_allowed",
			Detail: c.String(), Rule: ruleName(r)})
	}
	// A subcommand allow list narrows a container command that is otherwise
	// allowed. Naming none allows all of them, which for CONFIG means CONFIG SET
	// -- so this is how an operator allows the read and not the write.
	if c.Sub != "" {
		subs := p.allowSubs
		if r != nil && r.allowSubs != nil {
			subs = r.allowSubs
		}
		if subs != nil && hasContainer(subs, c.Name) && !subs[c.Name+" "+c.Sub] {
			return p.harden(c.Name, Decision{Reason: "subcommand_not_allowed",
				Detail: c.String(), Rule: ruleName(r)})
		}
	}

	ro := p.readOnly
	if r != nil && r.readOnly != nil {
		ro = *r.readOnly
	}
	if ro && wire.Writes(c.Name) {
		return Decision{Reason: "read_only", Detail: c.String(), Rule: ruleName(r)}
	}

	if d := p.keys(r, c); !d.Allow {
		return d
	}

	if r == nil {
		d := Decision{Allow: p.allowByDef}
		if !d.Allow {
			d.Reason = "no_rule_matched"
		}
		return d
	}
	if r.action == "deny" {
		return Decision{Reason: "rule_denied", Rule: r.name}
	}
	if r.sched != nil && !r.sched.InForce(se.At) {
		return Decision{Reason: "outside_schedule", Rule: r.name}
	}
	return Decision{Allow: true, Rule: r.name}
}

// keys applies the key prefix policy.
//
// The `known` value from the wire package is the whole of why this is safe. A
// command whose key positions depend on an option -- SORT with STORE, XREAD's
// STREAMS token, MIGRATE with KEYS -- cannot be checked, and checking some other
// argument instead would be a prefix policy that passes exactly what it was meant
// to stop. So it is refused while a prefix policy is in force, and the refusal
// names the command so an operator can decide to allow it on a rule with no
// prefix policy of its own.
func (p *policy) keys(r *rule, c *wire.Command) Decision {
	allow, deniedPrefixes := p.allowPrefix, p.denyPrefix
	if r != nil && (len(r.allowPrefix) > 0 || len(r.denyPrefix) > 0) {
		allow, deniedPrefixes = r.allowPrefix, r.denyPrefix
	}
	if len(allow) == 0 && len(deniedPrefixes) == 0 {
		return Decision{Allow: true}
	}
	keys, known := wire.Keys(c)
	if !known {
		return hardDeny("key_position_unknown", c.String())
	}
	for _, k := range keys {
		if hasPrefixAny(k, deniedPrefixes) {
			return Decision{Reason: "key_denied", Detail: k, Rule: ruleName(r)}
		}
		if len(allow) > 0 && !hasPrefixAny(k, allow) {
			return Decision{Reason: "key_not_allowed", Detail: k, Rule: ruleName(r)}
		}
	}
	return Decision{Allow: true}
}

// SelectDB decides about a SELECT.
//
// A Redis database is not an access boundary -- the password is the same for all of
// them -- but it is how an estate separates one application's keys from another's,
// and a relay can hold that line where the server will not.
func (p *policy) SelectDB(se *Session, db int) Decision {
	if p.allowDBs == nil {
		return Decision{Allow: true}
	}
	if !p.allowDBs[db] {
		return Decision{Reason: "database_not_allowed", Detail: fmt.Sprint(db)}
	}
	return Decision{Allow: true}
}

// MaxCommands is the per-connection command bound in force for a session.
func (p *policy) MaxCommands(se *Session) int {
	if r := p.match(se); r != nil && r.maxCommands > 0 {
		return r.maxCommands
	}
	return p.maxCommands
}

// harden marks a refusal that monitor mode must not shadow.
//
// An explicit allow list still wins: an operator who writes FLUSHALL into
// allow_commands has said so, and this is never reached for it. What it stops is a
// listener in monitor mode forwarding a CONFIG SET, an EVAL or a KEYS because
// nothing is being enforced yet.
func (p *policy) harden(name string, d Decision) Decision {
	if wire.Dangerous(name) {
		d.Hard = true
	}
	return d
}

// preAuth is what a client may legitimately send before authenticating.
//
// Naming them is the point: the alternative is to let everything through until the
// server answers +OK, which is a window an attacker fills with one command. AUTH
// and HELLO carry the credential; PING is how a pool checks a connection it has
// not used yet; QUIT and RESET end one. COMMAND DOCS is what several client
// libraries send on connect before they authenticate, and refusing it would break
// them for no gain -- it discloses the command table, which an attacker can read
// from the release notes.
func preAuth(name string) bool {
	switch name {
	case "AUTH", "HELLO", "PING", "QUIT", "RESET", "COMMAND":
		return true
	}
	return false
}

// hasContainer says whether a subcommand set mentions this container command at
// all. A set that does not is not a policy about it, so naming CONFIG GET must not
// silently narrow CLIENT.
func hasContainer(subs map[string]bool, name string) bool {
	for k := range subs {
		if strings.HasPrefix(k, name+" ") {
			return true
		}
	}
	return false
}

func hasPrefixAny(k string, prefixes []string) bool {
	for _, p := range prefixes {
		if p != "" && strings.HasPrefix(k, p) {
			return true
		}
	}
	return false
}

func (p *policy) match(se *Session) *rule {
	for _, r := range p.rules {
		if !p.covers(r, se) {
			continue
		}
		if r.observe {
			// An observe rule records and the search carries on, which is what
			// lets a rule be tried on live traffic before it decides anything.
			// A rule that stopped the search here would *allow* everything it
			// covered -- so trying out a rule would have been a way to turn
			// off every deny rule below it, which is the opposite of trying
			// something out.
			continue
		}
		return r
	}
	return nil
}

// covers says whether every selector this rule sets holds for the session.
// It is shared by match above and observed below, so the rule that decides and
// the rules that are only recorded are chosen by one piece of code.
func (p *policy) covers(r *rule, se *Session) bool {
	if len(r.clients) > 0 && !contains(r.clients, se.IP) {
		return false
	}
	if len(r.users) > 0 && !hasFold(r.users, se.User) {
		return false
	}
	return true
}

// observed names the observe rules this session matches, for the log line:
// they are recorded and they decide nothing.
func (p *policy) observed(se *Session) []string {
	var out []string
	for _, r := range p.rules {
		if r.observe && p.covers(r, se) {
			out = append(out, r.name)
		}
	}
	return out
}

func (p *policy) admits(ip netip.Addr) bool {
	if contains(p.denyIPs, ip) {
		return false
	}
	return len(p.allowIPs) == 0 || contains(p.allowIPs, ip)
}

func ruleName(r *rule) string {
	if r == nil {
		return ""
	}
	return r.name
}

func permitted(v string, allow, denyList []string) bool {
	if hasFold(denyList, v) {
		return false
	}
	return len(allow) == 0 || hasFold(allow, v)
}

func hasFold(list []string, v string) bool {
	for _, s := range list {
		if strings.EqualFold(s, v) {
			return true
		}
	}
	return false
}

func lower(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, strings.ToLower(strings.TrimSpace(s)))
	}
	return out
}

func or(v, def int) int {
	if v > 0 {
		return v
	}
	return def
}

func prefixes(in []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(in))
	for _, s := range in {
		n, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

func contains(ns []netip.Prefix, ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	for _, n := range ns {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
