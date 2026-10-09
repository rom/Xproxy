package mysql

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/mysqlwire"
	"github.com/rom/xproxy/internal/sqlkind"
)

// The rest of the decision: which rule a session matches, what the lists
// around the identity refuse, and what a rule can say about the traffic it
// covers that the listener does not say about everything else.
//
// All of it is decided before anything is relayed, from the connection's own
// attributes, so all of it is testable without a server. That is the point of
// keeping the policy a pure function of the session: the alternative is a
// policy whose only test is an end-to-end one, and then the cases nobody
// writes an end-to-end test for are the ones an attacker finds.

// with is a listener with one rule, which is the shape most of what follows
// needs.
func with(t *testing.T, rules ...config.MySQLRule) *policy {
	t.Helper()
	return must(t, &config.MySQLListener{Upstream: "my", DefaultAction: "allow", Rules: rules})
}

// What compile refuses inside a rule. A typo in a rule is worse than one at
// the top level: the rule quietly covers nothing, so the traffic it was
// written for is decided by the default and nobody is told.
func TestCompileRefusesWhatARuleCannotMean(t *testing.T) {
	for name, c := range map[string]*config.MySQLListener{
		"a denied client that is not a prefix": {Upstream: "my", DenyClients: []string{"10.0.0.1"}},
		"a denied statement kind":              {Upstream: "my", DenyStatements: []string{"selekt"}},
		"a rule client that is not a prefix": {Upstream: "my",
			Rules: []config.MySQLRule{{Name: "r", Clients: []string{"10.0.0.1"}}}},
		"a rule denying a command that is not one": {Upstream: "my",
			Rules: []config.MySQLRule{{Name: "r", DenyCommands: []string{"sudo"}}}},
		"a rule allowing a statement kind that is not one": {Upstream: "my",
			Rules: []config.MySQLRule{{Name: "r", AllowStatements: []string{"selekt"}}}},
		"a rule denying a statement kind that is not one": {Upstream: "my",
			Rules: []config.MySQLRule{{Name: "r", DenyStatements: []string{"selekt"}}}},
		"a rule allowing a load target that is not one": {Upstream: "my",
			Rules: []config.MySQLRule{{Name: "r", AllowLoad: []string{"sideways"}}}},
		"a rule schedule that is not a time": {Upstream: "my",
			Rules: []config.MySQLRule{{Name: "r", Schedule: &config.ModbusSchedule{From: "midnight", To: "03:00"}}}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := compile(c); err == nil {
				t.Fatalf("%s was accepted", name)
			}
		})
	}
}

// The lists around the identity, in the order they are asked. A database and
// a program are part of who is connecting on this protocol: the database is
// in the handshake response, and program_name is a connection attribute every
// client library sends.
func TestTheIdentityListsRefuseInOrder(t *testing.T) {
	p := must(t, &config.MySQLListener{Upstream: "my", DefaultAction: "allow",
		AllowDatabases: []string{"sales"}, AllowPrograms: []string{"app-server", "report*"}})

	se := sess("app", "payroll")
	if d := p.Login(se, loginOf("app", "payroll")); d.Allow || d.Reason != "database_not_allowed" {
		t.Errorf("a database off the list: %+v", d)
	}
	// The program list is asked after the database, and an empty program
	// cannot satisfy a list: a client that sent no attribute is not one of
	// the named programs.
	se = sess("app", "sales")
	if d := p.Login(se, loginOf("app", "sales")); d.Allow || d.Reason != "program_not_allowed" {
		t.Errorf("a session with no program: %+v", d)
	}
	for _, program := range []string{"app-server", "APP-SERVER", "reporting-nightly"} {
		se = sess("app", "sales")
		se.Program = program
		if d := p.Login(se, loginOf("app", "sales")); !d.Allow {
			t.Errorf("program %q: %+v", program, d)
		}
	}
	se = sess("app", "sales")
	se.Program = "mysqldump"
	if d := p.Login(se, loginOf("app", "sales")); d.Allow {
		t.Errorf("program mysqldump was admitted by a list that does not name it: %+v", d)
	}
	// A list of just "*" is a list that admits anything, including a client
	// that sent no attribute at all.
	open := must(t, &config.MySQLListener{Upstream: "my", DefaultAction: "allow",
		AllowPrograms: []string{"*"}})
	if d := open.Login(sess("app", "sales"), loginOf("app", "sales")); !d.Allow {
		t.Errorf("a wildcard program list refused a session: %+v", d)
	}
}

// A denied client is refused whether or not an allow list also names it: the
// deny list is the one an operator writes after something has happened, and a
// rule that could overrule it would make it advice.
func TestADeniedClientIsRefusedAndAnUnknownAddressCannotBeOnAList(t *testing.T) {
	p := must(t, &config.MySQLListener{Upstream: "my", DefaultAction: "allow",
		AllowClients: []string{"10.0.0.0/8"}, DenyClients: []string{"10.0.0.5/32"}})
	se := sess("app", "sales")
	if d := p.Login(se, loginOf("app", "sales")); d.Allow || d.Reason != "client_not_allowed" {
		t.Errorf("a denied address inside the allowed network: %+v", d)
	}
	se.IP = netip.MustParseAddr("10.0.0.6")
	if d := p.Login(se, loginOf("app", "sales")); !d.Allow {
		t.Errorf("an allowed address was refused: %+v", d)
	}
	// An address the relay never learned is in no network, so a list refuses
	// it: a list is a control, and a connection whose address is unknown
	// cannot be shown to be on it.
	se.IP = netip.Addr{}
	if d := p.Login(se, loginOf("app", "sales")); d.Allow {
		t.Errorf("an address with no value was admitted against a list: %+v", d)
	}
	// And a denied user is refused the same way, whatever the allow list says.
	named := must(t, &config.MySQLListener{Upstream: "my", DefaultAction: "allow",
		AllowUsers: []string{"app", "root"}, DenyUsers: []string{"root"}})
	if d := named.Login(sess("root", "sales"), loginOf("root", "sales")); d.Allow || d.Reason != "user_not_allowed" {
		t.Errorf("a denied user: %+v", d)
	}
}

// What a rule covers, and what each of its selectors turns away. A rule that
// matched a session it was not written for would widen the policy for traffic
// nobody meant to widen it for, which is the way a rule goes wrong.
func TestARuleCoversOnlyTheSessionsItNames(t *testing.T) {
	p := with(t, config.MySQLRule{Name: "reports", Clients: []string{"10.0.0.0/24"},
		Users: []string{"app"}, Databases: []string{"sales"}, Programs: []string{"report*"},
		MaxStatements: 5})
	match := func() *Session {
		se := sess("app", "sales")
		se.Program = "reporting-nightly"
		return se
	}
	if got := p.MaxStatements(match()); got != 5 {
		t.Errorf("the rule's statement bound is %d, want its own 5", got)
	}
	for _, c := range []struct {
		name string
		edit func(*Session)
	}{
		{"another address", func(se *Session) { se.IP = netip.MustParseAddr("192.0.2.1") }},
		{"another user", func(se *Session) { se.User = "migrator" }},
		{"another database", func(se *Session) { se.Database = "payroll" }},
		{"another program", func(se *Session) { se.Program = "mysqldump" }},
	} {
		t.Run(c.name, func(t *testing.T) {
			se := match()
			c.edit(se)
			if got := p.MaxStatements(se); got == 5 {
				t.Errorf("the rule covered a session with %s", c.name)
			}
		})
	}
}

// What a rule says about the traffic it covers. Each of these is the rule's
// own answer rather than the listener's, which is the whole reason to write
// one: a bulk loader that may do what the application connections may not.
func TestARuleDecidesForTheTrafficItCovers(t *testing.T) {
	t.Run("a command it denies", func(t *testing.T) {
		p := with(t, config.MySQLRule{Name: "apps", Users: []string{"app"},
			DenyCommands: []string{"statistics"}})
		d := p.Command(sess("app", "sales"), wire.ComStatistics)
		if d.Allow || d.Reason != "command_denied" || d.Rule != "apps" {
			t.Fatalf("%+v", d)
		}
	})

	t.Run("a command list of its own", func(t *testing.T) {
		p := with(t, config.MySQLRule{Name: "apps", Users: []string{"app"},
			AllowCommands: []string{"query"}})
		if d := p.Command(sess("app", "sales"), wire.ComQuery); !d.Allow || d.Rule != "apps" {
			t.Fatalf("query: %+v", d)
		}
		// The rule's list replaces the listener's rather than adding to it:
		// a rule written to narrow a connection must narrow it.
		d := p.Command(sess("app", "sales"), wire.ComPing)
		if d.Allow || d.Reason != "command_not_allowed" || d.Rule != "apps" {
			t.Fatalf("ping: %+v", d)
		}
	})

	t.Run("a statement kind it denies", func(t *testing.T) {
		p := with(t, config.MySQLRule{Name: "apps", Users: []string{"app"},
			DenyStatements: []string{"ddl"}})
		d := p.Statement(sess("app", "sales"), sqlkind.Statement{Kind: sqlkind.KindDDL, Writes: true}, "x")
		if d.Allow || d.Reason != "statement_denied" || d.Rule != "apps" {
			t.Fatalf("%+v", d)
		}
	})

	t.Run("a statement list of its own", func(t *testing.T) {
		p := with(t, config.MySQLRule{Name: "apps", Users: []string{"app"},
			AllowStatements: []string{"select"}})
		if d := p.Statement(sess("app", "sales"), sqlkind.Statement{Kind: sqlkind.KindSelect}, "x"); !d.Allow {
			t.Fatalf("select: %+v", d)
		}
		d := p.Statement(sess("app", "sales"), sqlkind.Statement{Kind: sqlkind.KindInsert, Writes: true}, "x")
		if d.Allow || d.Reason != "statement_not_allowed" || d.Rule != "apps" {
			t.Fatalf("insert: %+v", d)
		}
	})

	t.Run("a load form of its own", func(t *testing.T) {
		// The loader may read a path on the server; nothing else may, and
		// nobody may make the client read one.
		p := with(t, config.MySQLRule{Name: "loader", Users: []string{"bulk"},
			AllowLoad: []string{"file"}})
		file := sqlkind.Statement{Kind: sqlkind.KindCopy, Copy: sqlkind.CopyFile, Writes: true}
		if d := p.Statement(sess("bulk", "sales"), file, "LOAD DATA INFILE ..."); !d.Allow {
			t.Fatalf("the loader's own form: %+v", d)
		}
		if d := p.Statement(sess("app", "sales"), file, "LOAD DATA INFILE ..."); d.Allow {
			t.Fatalf("an ordinary session loaded a file: %+v", d)
		}
		local := sqlkind.Statement{Kind: sqlkind.KindCopy, Copy: sqlkind.CopyLocal, Writes: true}
		d := p.Statement(sess("bulk", "sales"), local, "LOAD DATA LOCAL INFILE ...")
		if d.Allow || !d.Hard {
			t.Fatalf("the local form reaches the client's own disk: %+v", d)
		}
	})
}

// A statement longer than the bound is refused without being classified, and
// hard: the classifier is a parser, and a megabyte of text that is not SQL is
// the input a parser is least safe reading.
func TestAStatementOverTheByteBoundIsRefusedBeforeItIsRead(t *testing.T) {
	p := must(t, &config.MySQLListener{Upstream: "my", DefaultAction: "allow", MaxStatementBytes: 64})
	d := p.Statement(sess("app", "sales"), sqlkind.Statement{Kind: sqlkind.KindSelect},
		"SELECT "+strings.Repeat("x", 200))
	if d.Allow || d.Reason != "statement_too_long" || !d.Hard {
		t.Fatalf("%+v", d)
	}
	if !strings.Contains(d.Detail, "octets") {
		t.Errorf("the refusal does not say how long it was: %q", d.Detail)
	}
}

// The identity decisions a rule makes about the connection rather than about
// one statement, on a listener that denies by default.
func TestWhatTheConnectionItselfIsRefusedFor(t *testing.T) {
	deny := must(t, &config.MySQLListener{Upstream: "my", DefaultAction: "deny",
		Rules: []config.MySQLRule{{Name: "apps", Users: []string{"app"}}}})
	if d := deny.Login(sess("app", "sales"), loginOf("app", "sales")); !d.Allow || d.Rule != "apps" {
		t.Errorf("the covered user: %+v", d)
	}
	// Nothing covers this one, and the listener denies by default: the reason
	// says so rather than naming a list the session was not on.
	d := deny.Login(sess("migrator", "sales"), loginOf("migrator", "sales"))
	if d.Allow || d.Reason != "no_rule_matched" {
		t.Errorf("an uncovered user: %+v", d)
	}

	refuse := with(t, config.MySQLRule{Name: "lockdown", Users: []string{"app"}, Action: "deny"})
	if d := refuse.Login(sess("app", "sales"), loginOf("app", "sales")); d.Allow || d.Reason != "rule_denied" || d.Rule != "lockdown" {
		t.Errorf("a deny rule: %+v", d)
	}

	// A connection outside its rule's window is refused at login, not at its
	// first statement: the session itself is what the window is about.
	window := with(t, config.MySQLRule{Name: "nightly", Users: []string{"app"},
		Schedule: &config.ModbusSchedule{From: "01:00", To: "03:00"}})
	if d := window.Login(sess("app", "sales"), loginOf("app", "sales")); d.Allow || d.Reason != "outside_schedule" {
		t.Errorf("outside the window: %+v", d)
	}
	inside := sess("app", "sales")
	inside.At = time.Date(2026, 3, 4, 2, 0, 0, 0, time.UTC)
	if d := window.Login(inside, loginOf("app", "sales")); !d.Allow {
		t.Errorf("inside the window: %+v", d)
	}
}

// An exchange that settled on no plugin at all is not a plugin decision: the
// server asked for nothing, which happens when it recognises the client's
// first guess, and a policy that refused it would refuse every ordinary
// connection.
func TestNoPluginIsNotAPluginRefusal(t *testing.T) {
	p := must(t, &config.MySQLListener{Upstream: "my", DefaultAction: "allow",
		AllowAuth: []string{"caching_sha2_password"}})
	if d := p.Auth(sess("app", "sales"), ""); !d.Allow {
		t.Fatalf("%+v", d)
	}
	if d := p.Auth(sess("app", "sales"), "mysql_native_password"); d.Allow || !d.Hard {
		t.Fatalf("a plugin off the list: %+v", d)
	}
}
