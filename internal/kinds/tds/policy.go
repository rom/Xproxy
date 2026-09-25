package tds

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/sqlkind"
	wire "github.com/rom/xproxy/internal/tdswire"
)

// The policy, in TDS's own terms.
//
// It has the postgres kind's four jobs -- refuse the encryption downgrade,
// refuse the credential that crosses in the clear, refuse what is not a
// statement, decide by the shape of what is -- and two that belong to SQL Server.
//
// The first is the procedure policy. This protocol's dangerous operations are not
// statements and not one-octet commands: they are stored procedures, and to a
// statement classifier `xp_cmdshell 'whoami'` is an EXECUTE like any other. A
// statement policy strict enough to catch it would refuse every stored procedure
// in the estate. So procedures get their own allow list, with a set whose refusal
// monitor mode may not shadow: a shell command, a COM object, the host registry,
// a linked server, and the switch that turns those back on.
//
// The second is that the statement policy has to reach into an RPC to work at
// all. Every client library that uses parameters sends `sp_executesql` with the
// SQL in a parameter, so a policy that classified only SQLBATCH would be
// inspecting the SET statements a driver emits on connect and nothing an
// application ever runs. The wire package reads that one parameter, and the same
// statement policy runs on it.
//
// One thing this kind does *not* do, and the reason is worth stating: it does not
// try to be a SQL firewall, any more than the other two database kinds do.
// Knowing which tables a statement touches means parsing T-SQL properly, and a
// relay that got that 95% right would have a hole exactly where somebody is
// looking. Restricting a login's tables is SQL Server's own job, with GRANT.

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
	allowApps             []string

	requireTLS      bool
	allowCleartext  bool
	allowIntegrated bool

	allowTypes, denyTypes map[byte]bool
	allowProcs, denyProcs map[string]bool

	readOnly   bool
	allowKinds map[sqlkind.Kind]bool
	denyKinds  map[sqlkind.Kind]bool

	maxStatements    int
	maxStatementByte int
	maxMessage       int

	rules []*rule

	allowByDef bool
	nak        bool
	monitor    bool
}

type rule struct {
	name    string
	clients []netip.Prefix
	users   []string
	dbs     []string
	apps    []string
	sched   *schedule
	observe bool
	action  string

	allowTypes, denyTypes map[byte]bool
	allowProcs, denyProcs map[string]bool
	allowKinds            map[sqlkind.Kind]bool
	denyKinds             map[sqlkind.Kind]bool
	readOnly              *bool
	maxStmt               int
}

func compile(c *config.TDSListener) (*policy, error) {
	p := &policy{
		requireTLS:       c.RequireTLS == nil || *c.RequireTLS,
		allowCleartext:   c.AllowCleartextPassword,
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
		allowApps:        c.AllowApps,
	}
	// Integrated security carries no user name, so a user list and an integrated
	// login cannot both be in force. Naming a user list therefore turns
	// integrated logins off unless the configuration says otherwise: a relay
	// that let one through would have a user policy with a hole exactly the
	// shape of Windows authentication, and would not say so anywhere.
	switch {
	case c.AllowIntegrated != nil:
		p.allowIntegrated = *c.AllowIntegrated
	default:
		p.allowIntegrated = len(c.AllowUsers) == 0 && len(c.DenyUsers) == 0
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
		return nil, fmt.Errorf("tds allow_clients: %w", err)
	}
	if p.denyIPs, err = prefixes(c.DenyClients); err != nil {
		return nil, fmt.Errorf("tds deny_clients: %w", err)
	}
	if p.allowTypes, err = typeSet(c.AllowTypes, "allow_types"); err != nil {
		return nil, err
	}
	if p.allowTypes == nil {
		p.allowTypes = map[byte]bool{}
		for _, t := range wire.DefaultTypes() {
			p.allowTypes[t] = true
		}
	}
	if p.denyTypes, err = typeSet(c.DenyTypes, "deny_types"); err != nil {
		return nil, err
	}
	p.allowProcs = procSet(c.AllowProcedures)
	if p.allowProcs == nil {
		p.allowProcs = procSet(wire.DefaultProcedures())
	}
	p.denyProcs = procSet(c.DenyProcedures)
	if p.allowKinds, err = kindSet(c.AllowStatements, "allow_statements"); err != nil {
		return nil, err
	}
	if p.denyKinds, err = kindSet(c.DenyStatements, "deny_statements"); err != nil {
		return nil, err
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

func compileRule(rc *config.TDSRule, i int) (*rule, error) {
	r := &rule{name: rc.Name, users: lower(rc.Users), dbs: lower(rc.Databases),
		apps: rc.Apps, action: rc.Action, maxStmt: rc.MaxStatements}
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
	if r.allowTypes, err = typeSet(rc.AllowTypes, fmt.Sprintf("rules[%d].allow_types", i)); err != nil {
		return nil, err
	}
	if r.denyTypes, err = typeSet(rc.DenyTypes, fmt.Sprintf("rules[%d].deny_types", i)); err != nil {
		return nil, err
	}
	r.allowProcs = procSet(rc.AllowProcedures)
	r.denyProcs = procSet(rc.DenyProcedures)
	if r.allowKinds, err = kindSet(rc.AllowStatements, fmt.Sprintf("rules[%d].allow_statements", i)); err != nil {
		return nil, err
	}
	if r.denyKinds, err = kindSet(rc.DenyStatements, fmt.Sprintf("rules[%d].deny_statements", i)); err != nil {
		return nil, err
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

func typeSet(names []string, field string) (map[byte]bool, error) {
	if len(names) == 0 {
		return nil, nil
	}
	out := make(map[byte]bool, len(names))
	for i, n := range names {
		t, ok := wire.TypeOf(n)
		if !ok {
			return nil, fmt.Errorf("%s[%d]: %q is not a message type (%s)",
				field, i, n, strings.Join(wire.TypeNames(), ", "))
		}
		out[t] = true
	}
	return out, nil
}

// procSet lower-cases the names, because that is the spelling Procedure returns
// and a policy that held two spellings would match neither reliably.
func procSet(names []string) map[string]bool {
	if len(names) == 0 {
		return nil
	}
	out := make(map[string]bool, len(names))
	for _, n := range names {
		out[strings.ToLower(strings.TrimSpace(n))] = true
	}
	return out
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

// Session is what the policy knows about a connection when it decides.
type Session struct {
	IP         netip.Addr
	User       string
	Database   string
	App        string
	Integrated bool
	Secure     bool
	At         time.Time
}

// Encryption decides what the relay answers a client's PRELOGIN with.
//
// This is the whole of the downgrade defence, and it is a *decision* rather than
// a forward: the client's request and the server's answer are one octet each,
// unsigned, and anything on the path can rewrite either. A relay that forwarded
// the server's answer would be forwarding whatever the path last said.
//
// hasCert is whether the listener can actually terminate TLS. A listener that
// requires encryption without a certificate has nothing to serve, which the
// validator refuses -- but the check is here too, because a decision that
// depended on configuration validation having run is a decision with a way to be
// wrong.
func (p *policy) Encryption(asked byte, hasCert bool) (answer byte, forced bool, d Decision) {
	if p.requireTLS {
		if !hasCert {
			return 0, false, hardDeny("tls_required", "the listener has no certificate")
		}
		// ENCRYPT_REQ, not ENCRYPT_ON: `on` leaves a client that asked for off
		// free to read the answer as a preference, and `required` does not.
		return wire.EncryptReq, !wire.Encrypted(asked), Decision{Allow: true}
	}
	// With the requirement off, the client's own wish is honoured -- including
	// when the wish is to encrypt, which is the case a relay must not quietly
	// break.
	switch asked {
	case wire.EncryptReq, wire.EncryptClientCertReq, wire.EncryptOn, wire.EncryptClientCertOn:
		if !hasCert {
			return 0, false, hardDeny("tls_required",
				"the client requires encryption and the listener has no certificate")
		}
		return wire.EncryptReq, false, Decision{Allow: true}
	}
	return wire.EncryptOff, false, Decision{Allow: true}
}

// UpstreamEncryption is what the relay asks the *server* for, which is not what
// the client asked for.
//
// The two legs are negotiated independently on purpose. A relay that terminated
// the client's TLS and then spoke cleartext to the server would have moved the
// exposure rather than removed it -- and the password it forwards is recoverable
// with a nibble swap.
func (p *policy) UpstreamEncryption(mode string) byte {
	if mode == "disable" {
		return wire.EncryptOff
	}
	return wire.EncryptReq
}

// UpstreamAnswer decides whether the server's answer is good enough.
func (p *policy) UpstreamAnswer(mode string, got byte) Decision {
	if mode == "disable" || wire.Encrypted(got) {
		return Decision{Allow: true}
	}
	if mode == "prefer" {
		// Asked for, refused, carried on -- which is exactly the behaviour this
		// kind refuses on the client's leg, so it is only ever reached because
		// an operator asked for it by name.
		return Decision{Allow: true}
	}
	return hardDeny("upstream_no_tls", wire.EncryptName(got))
}

// Login decides about a connection from its LOGIN7.
func (p *policy) Login(se *Session, l *wire.Login7) Decision {
	if !p.admits(se.IP) {
		return hardDeny("client_not_allowed", "")
	}
	// Confidentiality before identity: a LOGIN7 that crossed in the clear has
	// already disclosed the login name, the database, the host name and a
	// password recoverable by anybody who read it.
	if l.HasPassword && !se.Secure && !p.allowCleartext {
		return hardDeny("cleartext_password", "")
	}
	if l.Integrated {
		if !p.allowIntegrated {
			// Hard: the alternative is a login the user policy cannot be
			// applied to, admitted while the relay writes down that it noticed.
			return hardDeny("integrated_not_allowed",
				"the login carries no user name for a user list to match")
		}
	} else if se.User == "" {
		return hardDeny("no_user", "")
	}
	return p.identity(se)
}

// identity applies the user, database and app lists and finds the rule.
func (p *policy) identity(se *Session) Decision {
	if se.User != "" && !permitted(strings.ToLower(se.User), p.allowUsers, p.denyUsers) {
		return deny("user_not_allowed")
	}
	if se.Database != "" && !permitted(strings.ToLower(se.Database), p.allowDBs, p.denyDBs) {
		return deny("database_not_allowed")
	}
	if len(p.allowApps) > 0 && !matchAny(se.App, p.allowApps) {
		return deny("app_not_allowed")
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

// Message decides about one message by its type.
func (p *policy) Message(se *Session, typ byte) Decision {
	name := wire.TypeName(typ)
	r := p.match(se)
	if p.denyTypes[typ] {
		return Decision{Reason: "type_denied", Detail: name}
	}
	if r != nil && r.denyTypes[typ] {
		return Decision{Reason: "type_denied", Detail: name, Rule: r.name}
	}
	// The pre-TDS7 login is hard: the relay does not read that message shape, so
	// forwarding one means forwarding octets it has not understood, and doing so
	// while writing down that it noticed is not a trial of anything.
	if typ == wire.TypeLogin && !p.allowTypes[typ] && (r == nil || !r.allowTypes[typ]) {
		return hardDeny("legacy_login", name)
	}
	if r != nil && r.allowTypes != nil {
		if r.allowTypes[typ] {
			return Decision{Allow: true, Rule: r.name}
		}
		return Decision{Reason: "type_not_allowed", Detail: name, Rule: r.name}
	}
	if !p.allowTypes[typ] {
		return Decision{Reason: "type_not_allowed", Detail: name, Rule: ruleName(r)}
	}
	return Decision{Allow: true, Rule: ruleName(r)}
}

// Procedure decides about one RPC.
//
// The deny lists win, then the dangerous set, then the rule's own allow list,
// then the listener's. A name here is the one Procedure returns, so a client that
// called sp_executesql by its numeric identifier is decided about under the same
// name as one that spelled it out.
func (p *policy) Procedure(se *Session, proc string) Decision {
	r := p.match(se)
	if p.denyProcs[proc] {
		return p.harden(proc, Decision{Reason: "procedure_denied", Detail: proc})
	}
	if r != nil && r.denyProcs[proc] {
		return p.harden(proc, Decision{Reason: "procedure_denied", Detail: proc, Rule: r.name})
	}
	if r != nil && r.allowProcs != nil {
		if r.allowProcs[proc] {
			return Decision{Allow: true, Rule: r.name}
		}
		return p.harden(proc, Decision{Reason: "procedure_not_allowed", Detail: proc, Rule: r.name})
	}
	if !p.allowProcs[proc] {
		return p.harden(proc, Decision{Reason: "procedure_not_allowed", Detail: proc, Rule: ruleName(r)})
	}
	return Decision{Allow: true, Rule: ruleName(r)}
}

// harden marks a refusal that monitor mode must not shadow.
//
// An explicit allow list still wins: an operator who writes xp_cmdshell into
// allow_procedures has said so, and this never reaches them. What it stops is a
// listener in monitor mode forwarding a shell command because nothing is being
// enforced yet.
func (p *policy) harden(proc string, d Decision) Decision {
	if wire.Dangerous(proc) {
		d.Hard = true
	}
	return d
}

// Statement decides about one statement, whether it came from a SQLBATCH or out
// of an sp_executesql parameter.
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

// MaxStatements is the statements-per-batch bound in force for a session.
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
		if len(r.apps) > 0 && !matchAny(se.App, r.apps) {
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
