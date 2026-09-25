package mysql

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/mysqlwire"
	"github.com/rom/xproxy/internal/sqlkind"
)

// The policy, in MySQL's own terms.
//
// It has the same four jobs as the postgres one -- refuse the encryption
// downgrade, refuse the weak credentials, refuse what is not a statement, decide
// by the shape of what is -- and one more that is MySQL's alone, because on this
// protocol the dangerous operations are *commands* rather than statements.
//
// A relay that only classified SQL would never see COM_SHUTDOWN, which is one
// octet and stops the server; or the three replication commands, which are a copy
// of every change to every database; or COM_CREATE_DB and COM_DROP_DB, which
// predate the DDL statements and bypass a statement policy entirely; or
// COM_CHANGE_USER, which re-authenticates a live connection as somebody else and
// without which a user policy applies to the first message and nothing after it.
//
// And there is one thing this policy does that no other kind does: it **rewrites
// the server's greeting**. A capability a client never sees offered is one it
// cannot negotiate, so stripping CLIENT_LOCAL_FILES means the server can never
// ask that client for a file -- and the application still works. That is the TFTP
// window bound again: rewrite rather than refuse, because a control that breaks
// every application on the segment is a control somebody switches off.

// Decision is what the policy says about one thing a client did.
type Decision struct {
	Allow          bool
	Reason, Detail string
	// Hard says the refusal stands even in shadow mode.
	Hard bool
	Rule string
}

func deny(reason string) Decision { return Decision{Reason: reason} }
func hardDeny(reason, detail string) Decision {
	return Decision{Reason: reason, Detail: detail, Hard: true}
}

type policy struct {
	allowIPs, denyIPs []netip.Prefix

	allowUsers, denyUsers []string
	allowDBs, denyDBs     []string
	allowPrograms         []string

	requireTLS    bool
	allowWeakAuth bool
	allowAuth     map[string]bool

	allowCmds map[byte]bool
	denyCmds  map[byte]bool
	// denyCaps is the mask stripped from the server's greeting.
	denyCaps uint32

	readOnly   bool
	allowKinds map[sqlkind.Kind]bool
	denyKinds  map[sqlkind.Kind]bool
	allowLoad  map[sqlkind.CopyTarget]bool

	maxStatements    int
	maxStatementByte int
	maxMessage       int

	rules []*rule

	allowByDef bool
	nak        bool
	monitor    bool
}

type rule struct {
	name     string
	clients  []netip.Prefix
	users    []string
	dbs      []string
	programs []string
	sched    *schedule
	observe  bool
	action   string

	allowCmds  map[byte]bool
	denyCmds   map[byte]bool
	allowKinds map[sqlkind.Kind]bool
	denyKinds  map[sqlkind.Kind]bool
	allowLoad  map[sqlkind.CopyTarget]bool
	readOnly   *bool
	maxStmt    int
}

// defaultDenyCaps is what a listener strips when the configuration names
// nothing. Each of the three is a capability whose presence changes what the
// rest of the connection can do.
func defaultDenyCaps() uint32 {
	return wire.CapLocalFiles | wire.CapMultiStatements |
		wire.CapCompress | wire.CapZstdCompression
}

func compile(c *config.MySQLListener) (*policy, error) {
	p := &policy{
		requireTLS:       c.RequireTLS == nil || *c.RequireTLS,
		allowWeakAuth:    c.AllowWeakAuth,
		readOnly:         c.ReadOnly,
		maxStatements:    or(c.MaxStatements, 1),
		maxStatementByte: or(c.MaxStatementBytes, 64<<10),
		maxMessage:       or(c.MaxMessageBytes, wire.DefaultMaxMessage),
		monitor:          c.MonitorOnly,
		nak:              c.DenyResponse != "drop",
		allowUsers:       lower(c.AllowUsers),
		denyUsers:        lower(c.DenyUsers),
		allowDBs:         lower(c.AllowDatabases),
		denyDBs:          lower(c.DenyDatabases),
		allowPrograms:    c.AllowPrograms,
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
		return nil, fmt.Errorf("mysql allow_clients: %w", err)
	}
	if p.denyIPs, err = prefixes(c.DenyClients); err != nil {
		return nil, fmt.Errorf("mysql deny_clients: %w", err)
	}
	if p.allowCmds, err = cmdSet(c.AllowCommands, "allow_commands"); err != nil {
		return nil, err
	}
	if p.allowCmds == nil {
		p.allowCmds = map[byte]bool{}
		for _, cmd := range wire.DefaultCommands() {
			p.allowCmds[cmd] = true
		}
	}
	if p.denyCmds, err = cmdSet(c.DenyCommands, "deny_commands"); err != nil {
		return nil, err
	}
	if p.allowKinds, err = kindSet(c.AllowStatements, "allow_statements"); err != nil {
		return nil, err
	}
	if p.denyKinds, err = kindSet(c.DenyStatements, "deny_statements"); err != nil {
		return nil, err
	}
	if p.allowLoad, err = loadSet(c.AllowLoad); err != nil {
		return nil, err
	}
	if p.denyCaps, err = capMask(c.DenyCapabilities); err != nil {
		return nil, err
	}
	if len(c.DenyCapabilities) == 0 {
		p.denyCaps = defaultDenyCaps()
	}
	if len(c.AllowAuth) > 0 {
		p.allowAuth = map[string]bool{}
		for i, name := range c.AllowAuth {
			n := strings.TrimSpace(name)
			if !knownPlugin(n) {
				return nil, fmt.Errorf("allow_auth[%d]: %q is not an authentication plugin (%s)",
					i, name, strings.Join(wire.AuthPlugins(), ", "))
			}
			p.allowAuth[n] = true
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

func knownPlugin(n string) bool {
	for _, p := range wire.AuthPlugins() {
		if p == n {
			return true
		}
	}
	return false
}

func compileRule(rc *config.MySQLRule, i int) (*rule, error) {
	r := &rule{name: rc.Name, users: lower(rc.Users), dbs: lower(rc.Databases),
		programs: rc.Programs, action: rc.Action, maxStmt: rc.MaxStatements}
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
	if r.allowCmds, err = cmdSet(rc.AllowCommands, fmt.Sprintf("rules[%d].allow_commands", i)); err != nil {
		return nil, err
	}
	if r.denyCmds, err = cmdSet(rc.DenyCommands, fmt.Sprintf("rules[%d].deny_commands", i)); err != nil {
		return nil, err
	}
	if r.allowKinds, err = kindSet(rc.AllowStatements, fmt.Sprintf("rules[%d].allow_statements", i)); err != nil {
		return nil, err
	}
	if r.denyKinds, err = kindSet(rc.DenyStatements, fmt.Sprintf("rules[%d].deny_statements", i)); err != nil {
		return nil, err
	}
	if r.allowLoad, err = loadSet(rc.AllowLoad); err != nil {
		return nil, fmt.Errorf("rules[%d]: %w", i, err)
	}
	if rc.ReadOnly != nil {
		v := *rc.ReadOnly
		r.readOnly = &v
	}
	if rc.Schedule != nil {
		if r.sched, err = compileSchedule(rc.Schedule); err != nil {
			return nil, fmt.Errorf("rules[%d].schedule: %w", i, err)
		}
	}
	return r, nil
}

func cmdSet(names []string, field string) (map[byte]bool, error) {
	if len(names) == 0 {
		return nil, nil
	}
	out := make(map[byte]bool, len(names))
	for i, n := range names {
		c, ok := wire.CommandOf(n)
		if !ok {
			return nil, fmt.Errorf("%s[%d]: %q is not a command (%s)",
				field, i, n, strings.Join(wire.CommandNames(), ", "))
		}
		out[c] = true
	}
	return out, nil
}

func kindSet(names []string, field string) (map[sqlkind.Kind]bool, error) {
	if len(names) == 0 {
		return nil, nil
	}
	out := make(map[sqlkind.Kind]bool, len(names))
	for i, n := range names {
		k, ok := sqlkind.KindOf(n)
		if !ok {
			return nil, fmt.Errorf("%s[%d]: %q is not a statement kind (%s)",
				field, i, n, strings.Join(sqlkind.KindNames(), ", "))
		}
		out[k] = true
	}
	return out, nil
}

// loadSet reads which LOAD DATA forms may cross.
func loadSet(names []string) (map[sqlkind.CopyTarget]bool, error) {
	if len(names) == 0 {
		return nil, nil
	}
	out := make(map[sqlkind.CopyTarget]bool, len(names))
	for i, n := range names {
		switch t := sqlkind.CopyTarget(strings.ToLower(strings.TrimSpace(n))); t {
		case sqlkind.CopyFile, sqlkind.CopyLocal:
			out[t] = true
		default:
			return nil, fmt.Errorf("allow_load[%d]: %q is not file or local", i, n)
		}
	}
	return out, nil
}

// capMask reads the capabilities to strip.
func capMask(names []string) (uint32, error) {
	var mask uint32
	for i, n := range names {
		bit, ok := wire.CapOf(n)
		if !ok {
			return 0, fmt.Errorf("deny_capabilities[%d]: %q is not a capability (%s)",
				i, n, strings.Join(wire.CapNames(), ", "))
		}
		if bit == wire.CapSSL {
			// Stripping this would perform the downgrade the whole kind exists
			// to prevent: a client that never sees CLIENT_SSL offered never
			// asks for TLS, and then the credential crosses in the clear.
			return 0, fmt.Errorf("deny_capabilities[%d]: ssl cannot be stripped; "+
				"a client that never sees it offered never asks for TLS", i)
		}
		mask |= bit
	}
	return mask, nil
}

// Session is what the policy knows about a connection when it decides.
type Session struct {
	IP       netip.Addr
	User     string
	Database string
	Program  string
	Secure   bool
	At       time.Time
}

// DenyCaps is the mask to strip from the server's greeting.
func (p *policy) DenyCaps() uint32 { return p.denyCaps }

// Login decides about a connection from its handshake response.
func (p *policy) Login(se *Session, l *wire.Login) Decision {
	if !p.admits(se.IP) {
		return hardDeny("client_not_allowed", "")
	}
	// The confidentiality of the connection is decided before the identity in
	// it: a handshake response that crossed in the clear has already disclosed
	// the user name and the database.
	if p.requireTLS && !se.Secure {
		return hardDeny("tls_required", "")
	}
	return p.identity(se, l.User, l.Database)
}

// ChangeUser decides about a COM_CHANGE_USER, which re-authenticates a live
// connection as somebody else.
func (p *policy) ChangeUser(se *Session, cu *wire.ChangeUser) Decision {
	d := p.identity(se, cu.User, cu.Database)
	if !d.Allow {
		// Hard, because the alternative is a connection that is now somebody
		// the policy refused while the relay writes down that it noticed.
		d.Hard = true
	}
	return d
}

// identity applies the user, database and program lists.
func (p *policy) identity(se *Session, user, db string) Decision {
	u := strings.ToLower(user)
	if u == "" {
		return hardDeny("no_user", "")
	}
	if !permitted(u, p.allowUsers, p.denyUsers) {
		return deny("user_not_allowed")
	}
	if db != "" && !permitted(strings.ToLower(db), p.allowDBs, p.denyDBs) {
		return deny("database_not_allowed")
	}
	if len(p.allowPrograms) > 0 && !matchAny(se.Program, p.allowPrograms) {
		return deny("program_not_allowed")
	}
	r := p.match(se)
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
	if r.sched != nil && !r.sched.inForce(se.At) {
		return Decision{Reason: "outside_schedule", Rule: r.name}
	}
	return Decision{Allow: true, Rule: r.name}
}

// Auth decides about the authentication plugin the exchange settled on.
func (p *policy) Auth(se *Session, plugin string) Decision {
	if plugin == "" {
		return Decision{Allow: true}
	}
	if p.allowAuth != nil && !p.allowAuth[plugin] {
		return hardDeny("auth_not_allowed", plugin)
	}
	if wire.WeakAuth(plugin) && !p.allowWeakAuth {
		return hardDeny("weak_auth", plugin)
	}
	// mysql_clear_password on an unencrypted connection is the password in the
	// clear on the wire, which is worse than the plugin being weak in general
	// -- so it is refused even where the plugin is allowed.
	if plugin == wire.AuthClearText && !se.Secure {
		return hardDeny("cleartext_password_unencrypted", plugin)
	}
	return Decision{Allow: true}
}

// Command decides about one protocol command.
//
// This is the half of the policy the postgres kind does not have, and it is
// where MySQL's real hazards live: a command carries no SQL, so no statement
// policy would ever see it.
func (p *policy) Command(se *Session, cmd byte) Decision {
	name := wire.CommandName(cmd)
	r := p.match(se)
	if p.denyCmds[cmd] {
		return Decision{Reason: "command_denied", Detail: name}
	}
	if r != nil && r.denyCmds[cmd] {
		return Decision{Reason: "command_denied", Detail: name, Rule: r.name}
	}
	// The replication commands are hard: each opens a stream of every change to
	// every database, and forwarding one while writing down that it was noticed
	// is not a trial of anything.
	if replication(cmd) && !p.allowCmds[cmd] && (r == nil || !r.allowCmds[cmd]) {
		return hardDeny("replication_command", name)
	}
	if r != nil && r.allowCmds != nil {
		if r.allowCmds[cmd] {
			return Decision{Allow: true, Rule: r.name}
		}
		return Decision{Reason: "command_not_allowed", Detail: name, Rule: r.name}
	}
	if !p.allowCmds[cmd] {
		return Decision{Reason: "command_not_allowed", Detail: name, Rule: ruleName(r)}
	}
	return Decision{Allow: true, Rule: ruleName(r)}
}

func replication(cmd byte) bool {
	switch cmd {
	case wire.ComBinlogDump, wire.ComBinlogDumpGTID, wire.ComRegisterSlave:
		return true
	}
	return false
}

// SetOption decides about a COM_SET_OPTION that turns multi-statement support
// on.
//
// This is the command that makes a capability policy real rather than
// decorative: stripping CLIENT_MULTI_STATEMENTS from the greeting is not enough,
// because this lifts it afterwards.
func (p *policy) SetOption(se *Session, on, readable bool) Decision {
	if !readable {
		return hardDeny("set_option_unreadable", "")
	}
	if on && p.denyCaps&wire.CapMultiStatements != 0 {
		return deny("multi_statements_denied")
	}
	return Decision{Allow: true}
}

// LocalInfile decides about a server asking the client for a file.
//
// The relay sees the request and the client's own setting is exactly what the
// attack relies on being wrong, so this is the only place it can be refused on
// the client's behalf.
func (p *policy) LocalInfile(se *Session, path string) Decision {
	if p.allowLoad[sqlkind.CopyLocal] {
		return Decision{Allow: true}
	}
	return hardDeny("local_infile", path)
}

// Statement decides about one statement out of a query.
func (p *policy) Statement(se *Session, st sqlkind.Statement, text string) Decision {
	r := p.match(se)
	if len(text) > p.maxStatementByte {
		return hardDeny("statement_too_long", fmt.Sprintf("%d octets", len(text)))
	}
	if p.denyKinds[st.Kind] {
		return Decision{Reason: "statement_denied", Detail: string(st.Kind)}
	}
	if r != nil && r.denyKinds[st.Kind] {
		return Decision{Reason: "statement_denied", Detail: string(st.Kind), Rule: r.name}
	}
	if st.Kind == sqlkind.KindUnknown {
		return hardDeny("statement_unreadable", st.Verb)
	}
	if st.Kind == sqlkind.KindCopy {
		if d := p.loadDecision(r, st); !d.Allow {
			return d
		}
	}
	ro := p.readOnly
	if r != nil && r.readOnly != nil {
		ro = *r.readOnly
	}
	if ro && st.Writes {
		return Decision{Reason: "read_only", Detail: string(st.Kind), Rule: ruleName(r)}
	}
	if r != nil && r.allowKinds != nil {
		if r.allowKinds[st.Kind] {
			return Decision{Allow: true, Rule: r.name}
		}
		return Decision{Reason: "statement_not_allowed", Detail: string(st.Kind), Rule: r.name}
	}
	if p.allowKinds != nil {
		if !p.allowKinds[st.Kind] {
			return Decision{Reason: "statement_not_allowed", Detail: string(st.Kind), Rule: ruleName(r)}
		}
		return Decision{Allow: true, Rule: ruleName(r)}
	}
	if r != nil {
		if r.observe {
			return Decision{Allow: true, Rule: r.name}
		}
		if r.action == "deny" {
			return Decision{Reason: "rule_denied", Rule: r.name}
		}
		if r.sched != nil && !r.sched.inForce(se.At) {
			return Decision{Reason: "outside_schedule", Rule: r.name}
		}
		return Decision{Allow: true, Rule: r.name}
	}
	d := Decision{Allow: p.allowByDef}
	if !d.Allow {
		d.Reason = "no_rule_matched"
	}
	return d
}

// loadDecision decides about a LOAD DATA, whose LOCAL form points at the client.
func (p *policy) loadDecision(r *rule, st sqlkind.Statement) Decision {
	allowed := p.allowLoad
	if r != nil && r.allowLoad != nil {
		allowed = r.allowLoad
	}
	if allowed[st.Copy] {
		return Decision{Allow: true}
	}
	if st.Copy == sqlkind.CopyLocal {
		// Hard: the statement makes the *client* read a path and send it, so
		// forwarding it and writing down that it was noticed means the file has
		// already left.
		return hardDeny("load_local", "")
	}
	return Decision{Reason: "load_not_allowed", Detail: string(st.Copy), Rule: ruleName(r)}
}

// MaxStatements is the statements-per-message bound in force for a session.
func (p *policy) MaxStatements(se *Session) int {
	if r := p.match(se); r != nil && r.maxStmt > 0 {
		return r.maxStmt
	}
	return p.maxStatements
}

// MaxMessage is the reassembly bound.
func (p *policy) MaxMessage() int { return p.maxMessage }

func (p *policy) match(se *Session) *rule {
	for _, r := range p.rules {
		if len(r.clients) > 0 && !contains(r.clients, se.IP) {
			continue
		}
		if len(r.users) > 0 && !hasFold(r.users, se.User) {
			continue
		}
		if len(r.dbs) > 0 && !hasFold(r.dbs, se.Database) {
			continue
		}
		if len(r.programs) > 0 && !matchAny(se.Program, r.programs) {
			continue
		}
		return r
	}
	return nil
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

func matchAny(v string, pats []string) bool {
	for _, pat := range pats {
		if pat == "*" {
			return true
		}
		if strings.HasSuffix(pat, "*") {
			if strings.HasPrefix(strings.ToLower(v), strings.ToLower(pat[:len(pat)-1])) {
				return true
			}
			continue
		}
		if strings.EqualFold(v, pat) {
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
