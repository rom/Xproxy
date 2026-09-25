package postgres

import (
	"net/netip"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/pgwire"
)

func must(t *testing.T, c *config.PostgresListener) *policy {
	t.Helper()
	p, err := compile(c)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func no(b bool) *bool { return &b }

var at = time.Date(2026, 3, 4, 10, 0, 0, 0, time.UTC)

func sess(user, db string) *Session {
	return &Session{IP: netip.MustParseAddr("10.0.0.5"), User: user, Database: db,
		Secure: true, At: at}
}

// startupOf builds the parsed startup packet a policy decides about.
func startupOf(kv ...string) *wire.Startup {
	s := &wire.Startup{Code: wire.Version3}
	for i := 0; i+1 < len(kv); i += 2 {
		s.Params = append(s.Params, wire.Param{Key: kv[i], Value: kv[i+1]})
	}
	return s
}

// The defaults are what an operator gets by writing `postgres: {upstream: pg}`,
// and on this protocol they are most of the security.
func TestTheDefaultsAreTheOnesThatMatter(t *testing.T) {
	p := must(t, &config.PostgresListener{Upstream: "pg", DefaultAction: "allow"})

	if !p.requireTLS {
		t.Error("tls is not required by default")
	}
	if p.allowReplication {
		t.Error("replication is allowed by default")
	}
	if p.allowFunctionCall {
		t.Error("the fast-path function call is allowed by default")
	}
	if !p.allowCancel {
		t.Error("cancel is refused by default, which breaks a thing operators legitimately do")
	}
	if p.allowWeakAuth {
		t.Error("weak authentication is allowed by default")
	}

	// A connection in the clear is refused, and it is hard: the user and
	// database are inside the packet, so one that crossed unencrypted has
	// already disclosed them.
	se := sess("alice", "sales")
	se.Secure = false
	d := p.Startup(se, startupOf("user", "alice"))
	if d.Allow || d.Reason != "tls_required" || !d.Hard {
		t.Fatalf("plaintext: %+v", d)
	}

	// Cleartext and md5 are refused, SCRAM is not.
	for code, want := range map[int32]bool{
		wire.AuthCleartextPassword: false,
		wire.AuthMD5Password:       false,
		wire.AuthSCMCredential:     false,
		wire.AuthSASL:              true,
		wire.AuthGSS:               true,
		wire.AuthOK:                true,
	} {
		d = p.Auth(sess("alice", "sales"), code)
		if d.Allow != want {
			t.Errorf("%s: allow=%v, want %v", wire.AuthName(code), d.Allow, want)
		}
		if !want && !d.Hard {
			t.Errorf("%s: a disclosed credential is shadowable", wire.AuthName(code))
		}
	}

	// COPY defaults to the two that move data over the protocol itself.
	for target, want := range map[wire.CopyTarget]bool{
		wire.CopyIn: true, wire.CopyOut: true, wire.CopyFile: false, wire.CopyProgram: false,
	} {
		st := wire.Statement{Kind: wire.KindCopy, Copy: target, Writes: true}
		d = p.Statement(sess("alice", "sales"), st, "COPY t ...")
		if d.Allow != want {
			t.Errorf("copy %s: allow=%v, want %v", target, d.Allow, want)
		}
	}
}

// replication is a startup parameter, so no statement policy would ever see it,
// and it is a copy of the whole server.
func TestAReplicationConnectionIsRefusedAndNeverShadowed(t *testing.T) {
	p := must(t, &config.PostgresListener{Upstream: "pg", DefaultAction: "allow"})
	d := p.Startup(sess("repl", "repl"), startupOf("user", "repl", "replication", "true"))
	if d.Allow || d.Reason != "replication_not_allowed" || !d.Hard {
		t.Fatalf("%+v", d)
	}
	// And the same connection without the parameter goes through, so the test
	// is about the parameter rather than the role.
	if d = p.Startup(sess("repl", "repl"), startupOf("user", "repl")); !d.Allow {
		t.Fatalf("an ordinary connection was refused: %+v", d)
	}
	// Explicitly allowed, it crosses.
	p = must(t, &config.PostgresListener{Upstream: "pg", DefaultAction: "allow", AllowReplication: true})
	if d = p.Startup(sess("repl", "repl"), startupOf("user", "repl", "replication", "database")); !d.Allow {
		t.Fatalf("allow_replication did not take effect: %+v", d)
	}
}

// The identity in a startup packet is a claim, and the lists are about which
// claims may be attempted.
func TestTheRoleAndDatabaseListsDecideWhichClaimsMayBeMade(t *testing.T) {
	p := must(t, &config.PostgresListener{Upstream: "pg", DefaultAction: "allow",
		DenyUsers: []string{"postgres"}, AllowDatabases: []string{"sales"}})

	if d := p.Startup(sess("postgres", "sales"), startupOf("user", "postgres")); d.Allow {
		t.Error("a denied role was admitted")
	}
	// Case does not matter: PostgreSQL folds unquoted identifiers to lower
	// case, so a policy that was case-sensitive would be bypassed by shouting.
	if d := p.Startup(sess("POSTGRES", "sales"), startupOf("user", "POSTGRES")); d.Allow {
		t.Error("a denied role in upper case was admitted")
	}
	if d := p.Startup(sess("alice", "sales"), startupOf("user", "alice", "database", "sales")); !d.Allow {
		t.Error("an allowed role and database were refused")
	}
	if d := p.Startup(sess("alice", "hr"), startupOf("user", "alice", "database", "hr")); d.Allow {
		t.Error("a database outside the list was admitted")
	}
	// The database defaults to the user name, so a connection string with no
	// database in it is still decided rather than skipped.
	if d := p.Startup(sess("alice", "alice"), startupOf("user", "alice")); d.Allow {
		t.Error("the defaulted database was not checked against the list")
	}
	// A packet with no user at all is refused hard: there is no identity to
	// decide about.
	if d := p.Startup(sess("", ""), startupOf("application_name", "psql")); d.Allow || !d.Hard {
		t.Errorf("a packet with no user: %+v", d)
	}
}

// read_only has to include CALL and DO, or it is decorative: a procedure and an
// anonymous block can do anything the role can.
func TestReadOnlyIncludesTheStatementsThatRunCode(t *testing.T) {
	p := must(t, &config.PostgresListener{Upstream: "pg", DefaultAction: "allow", ReadOnly: true})
	for _, k := range []wire.Kind{wire.KindInsert, wire.KindUpdate, wire.KindDelete,
		wire.KindMerge, wire.KindDDL, wire.KindGrant, wire.KindCall, wire.KindDo,
		wire.KindMaintenance, wire.KindCopy} {
		st := wire.Statement{Kind: k, Writes: true}
		if k == wire.KindCopy {
			st.Copy = wire.CopyIn
		}
		if d := p.Statement(sess("alice", "sales"), st, "x"); d.Allow {
			t.Errorf("%s crossed a read_only listener", k)
		}
	}
	for _, k := range []wire.Kind{wire.KindSelect, wire.KindShow, wire.KindExplain,
		wire.KindSet, wire.KindBegin, wire.KindCommit, wire.KindFetch} {
		if d := p.Statement(sess("alice", "sales"), wire.Statement{Kind: k}, "x"); !d.Allow {
			t.Errorf("%s was refused by a read_only listener: %+v", k, d)
		}
	}
}

// A statement the classifier could not name is refused whatever the
// configuration says, because the whole design is an allow list of shapes.
func TestAnUnreadableStatementIsRefusedEvenWhenEverythingIsAllowed(t *testing.T) {
	p := must(t, &config.PostgresListener{Upstream: "pg", DefaultAction: "allow"})
	st := wire.Statement{Kind: wire.KindUnknown, Verb: "FLUSH", Writes: true}
	d := p.Statement(sess("alice", "sales"), st, "FLUSH PRIVILEGES")
	if d.Allow || d.Reason != "statement_unreadable" || !d.Hard {
		t.Fatalf("%+v", d)
	}
	// The verb is in the detail, because "something unreadable was refused"
	// with no hint of what is a line nobody can act on.
	if d.Detail != "FLUSH" {
		t.Errorf("detail %q does not name the verb", d.Detail)
	}
	// And it cannot be allowed by naming it, because `unknown` is not a kind a
	// configuration may write.
	if _, err := compile(&config.PostgresListener{Upstream: "pg",
		AllowStatements: []string{"unknown"}}); err == nil {
		t.Error("unknown was accepted as an allowable kind")
	}
}

// COPY ... FROM PROGRAM is remote code execution with a SQL keyword in front of
// it, and nothing may allow it.
func TestCopyProgramCannotBeAllowedByAnything(t *testing.T) {
	// Not by the listener.
	if _, err := compile(&config.PostgresListener{Upstream: "pg",
		AllowCopy: []string{"program"}}); err == nil {
		t.Error("allow_copy accepted program")
	}
	// Not by a rule.
	if _, err := compile(&config.PostgresListener{Upstream: "pg",
		Rules: []config.PostgresRule{{Name: "r", AllowCopy: []string{"program"}}}}); err == nil {
		t.Error("a rule accepted program")
	}
	// And a listener that allows everything else still refuses it, hard.
	p := must(t, &config.PostgresListener{Upstream: "pg", DefaultAction: "allow",
		AllowCopy: []string{"in", "out", "file"}})
	st := wire.Statement{Kind: wire.KindCopy, Copy: wire.CopyProgram, Writes: true}
	d := p.Statement(sess("alice", "sales"), st, "COPY t FROM PROGRAM 'id'")
	if d.Allow || d.Reason != "copy_program" || !d.Hard {
		t.Fatalf("%+v", d)
	}
}

// A rule that names a kind widens the listener for its own traffic. This is the
// turn that makes one listener serve a reporting account and a migration
// account without two listeners, and it is the same turn the LDAP attribute
// policy and the DHCP option policy make.
func TestARuleWidensTheListenerForItsOwnTraffic(t *testing.T) {
	p := must(t, &config.PostgresListener{
		Upstream: "pg", DefaultAction: "deny", ReadOnly: true,
		AllowStatements: []string{"select", "show"},
		Rules: []config.PostgresRule{
			{Name: "migrations", Users: []string{"migrator"},
				AllowStatements: []string{"ddl", "select"}, ReadOnly: no(false)},
		},
	})
	// The reporting account gets the listener's list.
	if d := p.Statement(sess("reporting", "sales"), wire.Statement{Kind: wire.KindSelect}, "x"); !d.Allow {
		t.Fatalf("select for reporting: %+v", d)
	}
	if d := p.Statement(sess("reporting", "sales"),
		wire.Statement{Kind: wire.KindDDL, Writes: true}, "x"); d.Allow {
		t.Error("reporting was allowed ddl")
	}
	// The migration account gets its rule's, including a read_only of its own.
	d := p.Statement(sess("migrator", "sales"), wire.Statement{Kind: wire.KindDDL, Writes: true}, "x")
	if !d.Allow || d.Rule != "migrations" {
		t.Fatalf("ddl for migrator: %+v", d)
	}
	// And a kind neither list names is still refused for the rule's traffic.
	if d = p.Statement(sess("migrator", "sales"),
		wire.Statement{Kind: wire.KindGrant, Writes: true}, "x"); d.Allow {
		t.Error("migrator was allowed grant, which no list names")
	}
}

// A deny list is not overridable, on the listener or on a rule. That is how an
// exception inside an allowed set is written.
func TestADenyListIsNotOverridableByARule(t *testing.T) {
	p := must(t, &config.PostgresListener{
		Upstream: "pg", DefaultAction: "allow",
		DenyStatements: []string{"grant"},
		Rules: []config.PostgresRule{
			{Name: "admin", Users: []string{"root"}, AllowStatements: []string{"grant", "ddl"}},
		},
	})
	d := p.Statement(sess("root", "sales"), wire.Statement{Kind: wire.KindGrant, Writes: true}, "x")
	if d.Allow {
		t.Fatalf("a rule overrode the listener's deny list: %+v", d)
	}
	// The rule's other permission still works, so the test is about the deny
	// list rather than the rule never matching.
	if d = p.Statement(sess("root", "sales"),
		wire.Statement{Kind: wire.KindDDL, Writes: true}, "x"); !d.Allow {
		t.Fatalf("the rule did not match at all: %+v", d)
	}
	// And a rule's own deny beats its own permission.
	p = must(t, &config.PostgresListener{Upstream: "pg", DefaultAction: "allow",
		Rules: []config.PostgresRule{{Name: "r", AllowStatements: []string{"ddl"},
			DenyStatements: []string{"ddl"}}}})
	if d = p.Statement(sess("alice", "sales"),
		wire.Statement{Kind: wire.KindDDL, Writes: true}, "x"); d.Allow {
		t.Error("a rule's permission beat its own deny")
	}
}

// The client list is checked before anything is read, and it is hard.
func TestTheClientListIsCheckedBeforeTheIdentity(t *testing.T) {
	p := must(t, &config.PostgresListener{Upstream: "pg", DefaultAction: "allow",
		AllowClients: []string{"10.0.0.0/24"}})
	se := sess("alice", "sales")
	se.IP = netip.MustParseAddr("192.0.2.1")
	d := p.Startup(se, startupOf("user", "alice"))
	if d.Allow || d.Reason != "client_not_allowed" || !d.Hard {
		t.Fatalf("%+v", d)
	}
	// A cancel request from the same address is refused for the same reason,
	// because it arrives on a connection of its own with no identity at all.
	if d = p.Cancel(se); d.Allow || d.Reason != "client_not_allowed" {
		t.Fatalf("cancel: %+v", d)
	}
	if d = p.Cancel(sess("", "")); !d.Allow {
		t.Fatalf("a cancel from an admitted client was refused: %+v", d)
	}
}

// A schedule decides when a rule allows what it allows.
func TestTheScheduleDecidesWhenARuleApplies(t *testing.T) {
	p := must(t, &config.PostgresListener{
		Upstream: "pg", DefaultAction: "deny",
		Rules: []config.PostgresRule{{Name: "window", Users: []string{"migrator"},
			Schedule: &config.ModbusSchedule{From: "01:00", To: "03:00"}}},
	})
	inside := sess("migrator", "sales")
	inside.At = time.Date(2026, 3, 4, 2, 0, 0, 0, time.UTC)
	if d := p.Statement(inside, wire.Statement{Kind: wire.KindSelect}, "x"); !d.Allow {
		t.Fatalf("inside the window: %+v", d)
	}
	outside := sess("migrator", "sales")
	outside.At = time.Date(2026, 3, 4, 10, 0, 0, 0, time.UTC)
	d := p.Statement(outside, wire.Statement{Kind: wire.KindSelect}, "x")
	if d.Allow || d.Reason != "outside_schedule" {
		t.Fatalf("outside the window: %+v", d)
	}
}

// An observing rule decides nothing: it is how an operator sees what a rule
// would match before giving it an action.
func TestAnObservingRuleDecidesNothing(t *testing.T) {
	p := must(t, &config.PostgresListener{
		Upstream: "pg", DefaultAction: "deny",
		Rules: []config.PostgresRule{{Name: "watch", Users: []string{"alice"}, Action: "observe"}},
	})
	if d := p.Statement(sess("alice", "sales"),
		wire.Statement{Kind: wire.KindDDL, Writes: true}, "x"); !d.Allow {
		t.Fatalf("an observing rule refused: %+v", d)
	}
	// And a user it does not match still falls to the default.
	if d := p.Statement(sess("bob", "sales"), wire.Statement{Kind: wire.KindSelect}, "x"); d.Allow {
		t.Error("the default action was not applied to unmatched traffic")
	}
}

// The authentication allow list is by name, and refuses a method the estate did
// not list even when it is not weak.
func TestTheAuthListRefusesAMethodTheEstateDidNotName(t *testing.T) {
	p := must(t, &config.PostgresListener{Upstream: "pg", DefaultAction: "allow",
		AllowAuth: []string{"scram"}})
	if d := p.Auth(sess("alice", "sales"), wire.AuthSASL); !d.Allow {
		t.Error("scram was refused by a list naming it")
	}
	d := p.Auth(sess("alice", "sales"), wire.AuthGSS)
	if d.Allow || d.Reason != "auth_not_allowed" || !d.Hard {
		t.Fatalf("gss against a scram-only list: %+v", d)
	}
	// AuthenticationOk is not a method and must never be refused, or every
	// connection fails at the moment it succeeds.
	if d = p.Auth(sess("alice", "sales"), wire.AuthOK); !d.Allow {
		t.Fatalf("AuthenticationOk was refused: %+v", d)
	}
	if _, err := compile(&config.PostgresListener{Upstream: "pg",
		AllowAuth: []string{"nonsense"}}); err == nil {
		t.Error("a method that is not a method was accepted")
	}
}

// A statement past its bound is refused before anything decides about its
// contents, and the bound is hard.
func TestAStatementPastItsBoundIsRefused(t *testing.T) {
	p := must(t, &config.PostgresListener{Upstream: "pg", DefaultAction: "allow",
		MaxStatementBytes: 16})
	long := "SELECT 'aaaaaaaaaaaaaaaaaaaaaaaaaaaa'"
	d := p.Statement(sess("alice", "sales"), wire.Statement{Kind: wire.KindSelect}, long)
	if d.Allow || d.Reason != "statement_too_long" || !d.Hard {
		t.Fatalf("%+v", d)
	}
}

// The fast-path function call bypasses the parser entirely, so it bypasses
// every statement rule too.
func TestTheFastPathFunctionCallIsRefusedByDefault(t *testing.T) {
	p := must(t, &config.PostgresListener{Upstream: "pg", DefaultAction: "allow"})
	d := p.FunctionCall(sess("alice", "sales"))
	if d.Allow || d.Reason != "function_call" || !d.Hard {
		t.Fatalf("%+v", d)
	}
	p = must(t, &config.PostgresListener{Upstream: "pg", DefaultAction: "allow",
		AllowFunctionCall: true})
	if d = p.FunctionCall(sess("alice", "sales")); !d.Allow {
		t.Fatalf("allow_function_call did not take effect: %+v", d)
	}
}

// What compile refuses to understand, so that a typo is a startup error rather
// than a policy that quietly matches nothing.
func TestCompileRefusesWhatItCannotUnderstand(t *testing.T) {
	for name, c := range map[string]*config.PostgresListener{
		"a kind that is not a kind":   {Upstream: "pg", AllowStatements: []string{"selekt"}},
		"a deny kind that is not one": {Upstream: "pg", DenyStatements: []string{"selekt"}},
		"a copy target":               {Upstream: "pg", AllowCopy: []string{"sideways"}},
		"a default action":            {Upstream: "pg", DefaultAction: "maybe"},
		"a client network":            {Upstream: "pg", AllowClients: []string{"10.0.0.1"}},
		"a rule action":               {Upstream: "pg", Rules: []config.PostgresRule{{Action: "perhaps"}}},
		"a rule's network":            {Upstream: "pg", Rules: []config.PostgresRule{{Clients: []string{"nope"}}}},
		"a rule's kind":               {Upstream: "pg", Rules: []config.PostgresRule{{AllowStatements: []string{"x"}}}},
	} {
		if _, err := compile(c); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	// A rule with no name gets one, so a log line can say which rule decided.
	p := must(t, &config.PostgresListener{Upstream: "pg", Rules: []config.PostgresRule{{}}})
	if p.rules[0].name != "rules[0]" {
		t.Errorf("an unnamed rule is called %q", p.rules[0].name)
	}
}

// Application names are matched with a trailing wildcard, because a driver
// appends a version to its own name.
func TestAnApplicationNameMatchesWithATrailingWildcard(t *testing.T) {
	p := must(t, &config.PostgresListener{Upstream: "pg", DefaultAction: "allow",
		AllowApplications: []string{"grafana*", "psql"}})
	for app, want := range map[string]bool{
		"grafana":       true,
		"grafana-9.2.1": true,
		"psql":          true,
		"PSQL":          true,
		"pgadmin":       false,
		"":              false,
	} {
		se := sess("alice", "sales")
		se.App = app
		d := p.Startup(se, startupOf("user", "alice", "application_name", app))
		if d.Allow != want {
			t.Errorf("application %q: allow=%v, want %v", app, d.Allow, want)
		}
	}
}
