package postgres

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/pgwire"
)

// The policy, in PostgreSQL's own terms.
//
// A database proxy has a temptation to resist: it can see every statement, so it
// is tempting to make it a firewall for SQL. It cannot be one. Knowing which
// tables a statement touches means parsing SQL properly -- every alias,
// subquery, CTE, view, function body and search_path interaction -- and a relay
// that got that 95% right would have a policy with a hole in exactly the place
// somebody is looking. Restricting a role's tables is the database's own job,
// done properly, with GRANT.
//
// What a relay can do that the database cannot is everything that happens
// *before* the database has an opinion, and the two things it can do better:
//
//   - **Refuse the encryption downgrade.** The client asks for TLS in cleartext
//     and the server may answer no; libpq's default sslmode is `prefer`, which
//     carries on in the clear without telling anybody. The relay is configured
//     once, where ten thousand connection strings are not.
//   - **Refuse the authentication methods that put a reusable credential on the
//     wire**, which the server's own pg_hba.conf can also do -- and which, on
//     every estate that has ever been audited, it does not.
//   - **Decide by the shape of the statement, not its contents.** An allow list
//     of statement kinds, where a statement this relay cannot classify is
//     refused. That is a much smaller claim than a SQL firewall and it is one
//     that holds: it stops `COPY ... FROM PROGRAM`, DDL on a production
//     database, and the `; DROP TABLE` half of an injection, without pretending
//     to know which rows a SELECT will return.
//   - **Refuse what is not a statement at all**: a replication connection, a
//     legacy function call, a cancel request from an address that has no
//     business sending one.

// Decision is what the policy says about one thing a client did.
type Decision struct {
	Allow bool
	// Reason and Detail name the refusal for the log, the counters and the
	// ban list. Detail never repeats a peer-chosen string raw.
	Reason, Detail string
	// Hard says the refusal stands even in shadow mode. The line is the same
	// one every other kind draws: a decision about identity, about the
	// confidentiality of the connection, or about a message this relay could
	// not read is never merely observed, because forwarding it and writing it
	// down is not a trial of anything.
	Hard bool
	// Rule is the name of the rule that decided, for the log line.
	Rule string
}

func deny(reason string) Decision {
	return Decision{Reason: reason}
}

func hardDeny(reason, detail string) Decision {
	return Decision{Reason: reason, Detail: detail, Hard: true}
}

// policy is the compiled listener policy.
type policy struct {
	// The client networks. Deny is evaluated first.
	allowIPs, denyIPs []netip.Prefix

	// Identity, from the startup packet. This is the only identity the
	// protocol offers before authentication, and it is a claim rather than a
	// credential: the client says who it wants to be and the server decides.
	// So these lists are about which claims may even be *attempted*, which is
	// a smaller and still useful thing -- an estate where nothing should ever
	// connect as `postgres` can say so here and have it hold before a single
	// password is guessed at.
	allowUsers, denyUsers []string
	allowDBs, denyDBs     []string
	allowApps             []string

	// requireTLS refuses a client that will not encrypt. See the comment on
	// the field in the configuration: this is the single most valuable line in
	// a postgres listener's configuration.
	requireTLS bool
	// allowWeakAuth permits an authentication method whose credential an
	// observer can reuse.
	allowWeakAuth bool
	// allowAuth, when set, is the allow list of methods by name.
	allowAuth map[string]bool

	// What may be done.
	readOnly   bool
	allowKinds map[wire.Kind]bool
	denyKinds  map[wire.Kind]bool
	allowCopy  map[wire.CopyTarget]bool

	allowReplication  bool
	allowFunctionCall bool
	allowCancel       bool

	// Bounds. Every one of these is a number a peer chose.
	maxStatements    int
	maxStatementByte int
	maxMessage       int

	rules []*rule

	allowByDef bool
	nak        bool
	monitor    bool
}

// rule is one compiled rule.
type rule struct {
	name    string
	clients []netip.Prefix
	users   []string
	dbs     []string
	apps    []string
	sched   *schedule
	observe bool
	action  string

	// A rule's own narrowing. A rule may permit a kind the listener does not,
	// and may refuse one the listener allows; the deny lists always win, on
	// the listener and on the rule both.
	allowKinds map[wire.Kind]bool
	denyKinds  map[wire.Kind]bool
	allowCopy  map[wire.CopyTarget]bool
	readOnly   *bool
	maxStmt    int
}

// compile turns the configuration into the policy.
func compile(c *config.PostgresListener) (*policy, error) {
	p := &policy{
		requireTLS:        c.RequireTLS == nil || *c.RequireTLS,
		allowWeakAuth:     c.AllowWeakAuth,
		readOnly:          c.ReadOnly,
		allowReplication:  c.AllowReplication,
		allowFunctionCall: c.AllowFunctionCall,
		allowCancel:       c.AllowCancel == nil || *c.AllowCancel,
		maxStatements:     or(c.MaxStatements, 8),
		maxStatementByte:  or(c.MaxStatementBytes, 64<<10),
		maxMessage:        or(c.MaxMessageBytes, wire.MaxMessage),
		monitor:           c.MonitorOnly,
		nak:               c.DenyResponse != "drop",
		allowUsers:        lower(c.AllowUsers),
		denyUsers:         lower(c.DenyUsers),
		allowDBs:          lower(c.AllowDatabases),
		denyDBs:           lower(c.DenyDatabases),
		allowApps:         c.AllowApplications,
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
		return nil, fmt.Errorf("postgres allow_clients: %w", err)
	}
	if p.denyIPs, err = prefixes(c.DenyClients); err != nil {
		return nil, fmt.Errorf("postgres deny_clients: %w", err)
	}
	if p.allowKinds, err = kindSet(c.AllowStatements, "allow_statements"); err != nil {
		return nil, err
	}
	if p.denyKinds, err = kindSet(c.DenyStatements, "deny_statements"); err != nil {
		return nil, err
	}
	if p.allowCopy, err = copySet(c.AllowCopy); err != nil {
		return nil, err
	}
	if len(c.AllowAuth) > 0 {
		p.allowAuth = map[string]bool{}
		for i, name := range c.AllowAuth {
			n := strings.ToLower(strings.TrimSpace(name))
			if !knownAuth[n] {
				return nil, fmt.Errorf("allow_auth[%d]: %q is not an authentication method (%s)",
					i, name, strings.Join(authNames(), ", "))
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

// knownAuth is the set of method names a configuration may write. They are the
// names the PostgreSQL manual and pg_hba.conf use, so an operator writes what
// they already know.
var knownAuth = map[string]bool{
	"password": true, "md5": true, "scram": true, "gss": true,
	"sspi": true, "kerberos": true, "scm": true, "ok": true,
}

func authNames() []string {
	return []string{"password", "md5", "scram", "gss", "sspi", "kerberos", "scm"}
}

func compileRule(rc *config.PostgresRule, i int) (*rule, error) {
	r := &rule{
		name:    rc.Name,
		users:   lower(rc.Users),
		dbs:     lower(rc.Databases),
		apps:    rc.Applications,
		action:  rc.Action,
		maxStmt: rc.MaxStatements,
	}
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
	if r.allowKinds, err = kindSet(rc.AllowStatements, fmt.Sprintf("rules[%d].allow_statements", i)); err != nil {
		return nil, err
	}
	if r.denyKinds, err = kindSet(rc.DenyStatements, fmt.Sprintf("rules[%d].deny_statements", i)); err != nil {
		return nil, err
	}
	if r.allowCopy, err = copySet(rc.AllowCopy); err != nil {
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

func kindSet(names []string, field string) (map[wire.Kind]bool, error) {
	if len(names) == 0 {
		return nil, nil
	}
	out := make(map[wire.Kind]bool, len(names))
	for i, n := range names {
		k, ok := wire.KindOf(n)
		if !ok {
			return nil, fmt.Errorf("%s[%d]: %q is not a statement kind (%s)",
				field, i, n, strings.Join(wire.KindNames(), ", "))
		}
		out[k] = true
	}
	return out, nil
}

func copySet(names []string) (map[wire.CopyTarget]bool, error) {
	if len(names) == 0 {
		return nil, nil
	}
	out := make(map[wire.CopyTarget]bool, len(names))
	for i, n := range names {
		switch t := wire.CopyTarget(strings.ToLower(strings.TrimSpace(n))); t {
		case wire.CopyIn, wire.CopyOut, wire.CopyFile:
			out[t] = true
		case wire.CopyProgram:
			// Deliberately not nameable. COPY ... FROM PROGRAM runs a shell
			// command as the server's operating-system user: it is remote code
			// execution with a SQL keyword in front of it, and a configuration
			// that could switch it on through a relay would be a configuration
			// somebody switches on by accident. An estate that genuinely wants
			// it wants it on a connection that does not go through here.
			return nil, fmt.Errorf("allow_copy[%d]: program cannot be allowed through this relay; "+
				"COPY ... FROM PROGRAM runs a command as the server's user", i)
		default:
			return nil, fmt.Errorf("allow_copy[%d]: %q is not in, out or file", i, n)
		}
	}
	return out, nil
}

// Session is what the policy knows about a connection when it decides.
type Session struct {
	IP       netip.Addr
	User     string
	Database string
	App      string
	Secure   bool
	At       time.Time
}

// Startup decides about a connection from its startup packet, which is
// everything the protocol offers before anybody authenticates.
func (p *policy) Startup(se *Session, s *wire.Startup) Decision {
	if !p.admits(se.IP) {
		return hardDeny("client_not_allowed", "")
	}
	// The confidentiality of the connection is decided before the identity in
	// it is read, because the identity is *in* the packet: a user name and a
	// database name that arrived in the clear have already been disclosed, and
	// refusing afterwards refuses a secret that is already out.
	if p.requireTLS && !se.Secure {
		return hardDeny("tls_required", "")
	}
	if mode, on := s.Replication(); on && !p.allowReplication {
		// A physical replication stream is a byte-for-byte copy of every
		// database on the server, including the role passwords. It is a
		// startup *parameter*, so no statement policy would ever see it.
		return hardDeny("replication_not_allowed", mode)
	}
	if u := strings.ToLower(s.User()); u == "" {
		return hardDeny("no_user", "")
	} else if !permitted(u, p.allowUsers, p.denyUsers) {
		return deny("user_not_allowed")
	}
	if db := strings.ToLower(s.Database()); !permitted(db, p.allowDBs, p.denyDBs) {
		return deny("database_not_allowed")
	}
	if len(p.allowApps) > 0 && !matchAny(s.Get("application_name"), p.allowApps) {
		return deny("application_not_allowed")
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

// Auth decides about the authentication method the server asked for.
//
// The relay reads the *server's* request rather than the client's answer,
// because the server is the one that chooses: pg_hba.conf decides, and this is
// where a relay can notice that the line which matched says `md5` on a network
// where it should say `scram`.
func (p *policy) Auth(se *Session, code int32) Decision {
	name := wire.AuthName(code)
	if p.allowAuth != nil && !p.allowAuth[name] && code != wire.AuthOK {
		return hardDeny("auth_not_allowed", name)
	}
	if wire.Weak(code) && !p.allowWeakAuth {
		// `password` is the password itself in cleartext. `md5` is worse than
		// it looks: the stored verifier is md5(password+username), so the hash
		// *is* a password-equivalent and anybody who reads the server's
		// pg_authid can authenticate without cracking anything. PostgreSQL has
		// shipped SCRAM since version 10.
		return hardDeny("weak_auth", name)
	}
	return Decision{Allow: true}
}

// Statement decides about one statement.
func (p *policy) Statement(se *Session, st wire.Statement, text string) Decision {
	r := p.match(se)
	if len(text) > p.maxStatementByte {
		return hardDeny("statement_too_long", fmt.Sprintf("%d octets", len(text)))
	}
	// The deny lists first, on the rule and on the listener, because a deny
	// list nothing can override is how an exception inside an allowed set is
	// written.
	if p.denyKinds[st.Kind] {
		return Decision{Reason: "statement_denied", Detail: string(st.Kind)}
	}
	if r != nil && r.denyKinds[st.Kind] {
		return Decision{Reason: "statement_denied", Detail: string(st.Kind), Rule: r.name}
	}
	// A statement this relay could not classify is refused whatever else says,
	// and it is hard: the whole design is an allow list of shapes, and a shape
	// nobody could read is not one of them. Observing it would mean forwarding
	// a statement the relay has no opinion about while writing down that it
	// had one.
	if st.Kind == wire.KindUnknown {
		return hardDeny("statement_unreadable", st.Verb)
	}
	if st.Kind == wire.KindCopy {
		if d := p.copyDecision(r, st); !d.Allow {
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
	// A rule's positive list, then the listener's. A rule that names a kind
	// widens the listener for its own traffic, which is the turn that makes
	// the kind usable: one rule for the reporting account that may only
	// select, another for the migration account that may also change the
	// schema, without two listeners.
	if r != nil && r.allowKinds != nil {
		if r.allowKinds[st.Kind] {
			return Decision{Allow: true, Rule: r.name}
		}
		return Decision{Reason: "statement_not_allowed", Detail: string(st.Kind), Rule: r.name}
	}
	if p.allowKinds != nil && !p.allowKinds[st.Kind] {
		return Decision{Reason: "statement_not_allowed", Detail: string(st.Kind), Rule: ruleName(r)}
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
	if p.allowKinds != nil {
		// The listener's positive list matched, which is an allow in its own
		// right: an estate that listed the statements it permits has said what
		// it permits, and making that depend on default_action as well would
		// mean writing the same thing twice.
		return Decision{Allow: true}
	}
	d := Decision{Allow: p.allowByDef}
	if !d.Allow {
		d.Reason = "no_rule_matched"
	}
	return d
}

// copyDecision decides about a COPY, which is three operations wearing one
// keyword.
func (p *policy) copyDecision(r *rule, st wire.Statement) Decision {
	if st.Copy == wire.CopyProgram {
		// Never allowed, by any rule, in any mode, and hard so that shadow
		// mode does not forward it. This is the one statement in the protocol
		// that is unambiguously remote code execution.
		return hardDeny("copy_program", "")
	}
	allowed := p.allowCopy
	if r != nil && r.allowCopy != nil {
		allowed = r.allowCopy
	}
	if allowed == nil {
		// The default is the two that move data over the protocol itself.
		// `file` touches the server's own filesystem and needs a privileged
		// role, so an estate that wants it says so.
		allowed = map[wire.CopyTarget]bool{wire.CopyIn: true, wire.CopyOut: true}
	}
	if !allowed[st.Copy] {
		return Decision{Reason: "copy_not_allowed", Detail: string(st.Copy), Rule: ruleName(r)}
	}
	return Decision{Allow: true}
}

// FunctionCall decides about the legacy fast-path interface, which names a
// function by object identifier and bypasses the parser completely. Nothing
// written this century sends it.
func (p *policy) FunctionCall(se *Session) Decision {
	if p.allowFunctionCall {
		return Decision{Allow: true}
	}
	return hardDeny("function_call", "")
}

// Cancel decides about a CancelRequest, which arrives on a connection of its
// own and which the server acts on with no authentication at all: the whole
// credential is a process identifier and a 32-bit secret.
//
// The relay cannot check the secret -- only the server knows it -- so what it
// can do is refuse one from an address that is not an admitted client, and
// count them, which is what turns a quiet brute force of 32 bits into something
// somebody sees.
func (p *policy) Cancel(se *Session) Decision {
	if !p.admits(se.IP) {
		return hardDeny("client_not_allowed", "")
	}
	if !p.allowCancel {
		return deny("cancel_not_allowed")
	}
	return Decision{Allow: true}
}

// match finds the first rule whose selectors all match.
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
		if len(r.apps) > 0 && !matchAny(se.App, r.apps) {
			continue
		}
		return r
	}
	return nil
}

func ruleName(r *rule) string {
	if r == nil {
		return ""
	}
	return r.name
}

// permitted applies a deny list then an allow list, deny first.
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

// matchAny matches a value against patterns, where a pattern may end in * .
// Application names are chosen by the client and are not a credential; they are
// useful for telling a migration tool from a reporting dashboard when both
// connect as the same role, which is the ordinary state of affairs.
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

// admits applies the listener's client lists, deny first.
func (p *policy) admits(ip netip.Addr) bool {
	if contains(p.denyIPs, ip) {
		return false
	}
	return len(p.allowIPs) == 0 || contains(p.allowIPs, ip)
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
