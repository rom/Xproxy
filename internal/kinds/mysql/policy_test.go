package mysql

import (
	"net/netip"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/mysqlwire"
	"github.com/rom/xproxy/internal/sqlkind"
)

func must(t *testing.T, c *config.MySQLListener) *policy {
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

func loginOf(user, db string) *wire.Login {
	return &wire.Login{Caps: wire.CapProtocol41, User: user, Database: db}
}

// The defaults are what an operator gets by writing `mysql: {upstream: my}`, and
// on this protocol most of the security is in the command list and the strip.
func TestTheDefaultsAreTheOnesThatMatter(t *testing.T) {
	p := must(t, &config.MySQLListener{Upstream: "my", DefaultAction: "allow"})

	if !p.requireTLS {
		t.Error("tls is not required by default")
	}
	if p.allowWeakAuth {
		t.Error("weak authentication is allowed by default")
	}
	// The three capabilities stripped by default, and the one that must never
	// be: stripping ssl would perform the downgrade the kind exists to prevent.
	for _, c := range []uint32{wire.CapLocalFiles, wire.CapMultiStatements, wire.CapCompress} {
		if p.DenyCaps()&c == 0 {
			t.Errorf("%s is not stripped by default", wire.CapName(c))
		}
	}
	if p.DenyCaps()&wire.CapSSL != 0 {
		t.Fatal("the ssl capability is stripped by default, which is the downgrade")
	}
	// The administrative commands are off, and the driver ones are on.
	for _, c := range []byte{wire.ComShutdown, wire.ComDebug, wire.ComProcessKill,
		wire.ComBinlogDump, wire.ComBinlogDumpGTID, wire.ComRegisterSlave,
		wire.ComTableDump, wire.ComCreateDB, wire.ComDropDB, wire.ComRefresh,
		wire.ComProcessInfo, wire.ComFieldList, wire.ComClone} {
		if d := p.Command(sess("app", "sales"), c); d.Allow {
			t.Errorf("%s is allowed by default", wire.CommandName(c))
		}
	}
	for _, c := range []byte{wire.ComQuery, wire.ComStmtPrepare, wire.ComStmtExecute,
		wire.ComPing, wire.ComQuit, wire.ComInitDB, wire.ComChangeUser} {
		if d := p.Command(sess("app", "sales"), c); !d.Allow {
			t.Errorf("%s is refused by default, which breaks a driver: %+v", wire.CommandName(c), d)
		}
	}
	// LOAD DATA is off in both forms: bulk loading is a job, not something an
	// application connection does by accident.
	for _, target := range []sqlkind.CopyTarget{sqlkind.CopyFile, sqlkind.CopyLocal} {
		st := sqlkind.Statement{Kind: sqlkind.KindCopy, Copy: target, Writes: true}
		if d := p.Statement(sess("app", "sales"), st, "LOAD DATA ..."); d.Allow {
			t.Errorf("load %s is allowed by default", target)
		}
	}
	// One statement per message by default, because multi_statements is
	// stripped and a message carrying more is a client working around it.
	if n := p.MaxStatements(sess("app", "sales")); n != 1 {
		t.Errorf("max_statements defaults to %d", n)
	}
}

// The replication commands are hard: each opens a stream of every change to every
// database, so forwarding one and writing down that it was noticed is not a trial.
func TestTheReplicationCommandsAreRefusedHard(t *testing.T) {
	p := must(t, &config.MySQLListener{Upstream: "my", DefaultAction: "allow"})
	for _, c := range []byte{wire.ComBinlogDump, wire.ComBinlogDumpGTID, wire.ComRegisterSlave} {
		d := p.Command(sess("app", "sales"), c)
		if d.Allow || d.Reason != "replication_command" || !d.Hard {
			t.Errorf("%s: %+v", wire.CommandName(c), d)
		}
	}
	// Named explicitly, they cross -- because a replica genuinely needs them,
	// and a listener in front of one says so.
	p = must(t, &config.MySQLListener{Upstream: "my", DefaultAction: "allow",
		AllowCommands: []string{"binlog_dump", "register_slave", "query", "ping", "quit"}})
	for _, c := range []byte{wire.ComBinlogDump, wire.ComRegisterSlave} {
		if d := p.Command(sess("repl", ""), c); !d.Allow {
			t.Errorf("%s was refused by a list naming it: %+v", wire.CommandName(c), d)
		}
	}
	// And one still not named is still hard.
	if d := p.Command(sess("repl", ""), wire.ComBinlogDumpGTID); !d.Hard {
		t.Errorf("an unnamed replication command is shadowable: %+v", d)
	}
}

// COM_SET_OPTION is what makes a handshake-only capability policy decorative.
func TestSetOptionCannotLiftTheStrippedCapability(t *testing.T) {
	p := must(t, &config.MySQLListener{Upstream: "my", DefaultAction: "allow"})
	// multi_statements is stripped by default, so turning it on is refused.
	d := p.SetOption(sess("app", "sales"), true, true)
	if d.Allow || d.Reason != "multi_statements_denied" {
		t.Fatalf("%+v", d)
	}
	// Turning it *off* is always fine.
	if d = p.SetOption(sess("app", "sales"), false, true); !d.Allow {
		t.Fatalf("switching multi-statements off was refused: %+v", d)
	}
	// A payload the relay could not read is hard, because it cannot tell which
	// way the option went.
	if d = p.SetOption(sess("app", "sales"), false, false); d.Allow || !d.Hard {
		t.Fatalf("an unreadable set_option: %+v", d)
	}
	// And an estate that deliberately allows multi-statements can.
	p = must(t, &config.MySQLListener{Upstream: "my", DefaultAction: "allow",
		DenyCapabilities: []string{"local_files"}})
	if d = p.SetOption(sess("app", "sales"), true, true); !d.Allow {
		t.Fatalf("multi_statements refused where it was not stripped: %+v", d)
	}
}

// COM_CHANGE_USER re-authenticates a live connection, so the identity policy has
// to apply to the new user and the refusal has to be hard.
func TestChangeUserIsDecidedAndItsRefusalIsHard(t *testing.T) {
	p := must(t, &config.MySQLListener{Upstream: "my", DefaultAction: "allow",
		AllowUsers: []string{"app"}})
	if d := p.ChangeUser(sess("app", "sales"), &wire.ChangeUser{User: "app", Database: "sales"}); !d.Allow {
		t.Fatalf("a permitted change-user: %+v", d)
	}
	d := p.ChangeUser(sess("app", "sales"), &wire.ChangeUser{User: "root", Database: "sales"})
	if d.Allow || d.Reason != "user_not_allowed" || !d.Hard {
		t.Fatalf("%+v", d)
	}
	// A change-user with no user at all has no identity to decide about.
	if d = p.ChangeUser(sess("app", "sales"), &wire.ChangeUser{}); d.Allow || !d.Hard {
		t.Fatalf("an empty change-user: %+v", d)
	}
}

// The capability strip is configurable, and ssl is not.
func TestSSLCannotBeStripped(t *testing.T) {
	if _, err := compile(&config.MySQLListener{Upstream: "my",
		DenyCapabilities: []string{"ssl"}}); err == nil {
		t.Fatal("deny_capabilities accepted ssl")
	}
	// A named list replaces the default entirely, so an estate that wants
	// compression can have it.
	p := must(t, &config.MySQLListener{Upstream: "my",
		DenyCapabilities: []string{"local_files", "multi_statements"}})
	if p.DenyCaps()&wire.CapCompress != 0 {
		t.Error("compress was stripped by a list that did not name it")
	}
	if p.DenyCaps()&wire.CapLocalFiles == 0 {
		t.Error("local_files was not stripped by a list naming it")
	}
	if _, err := compile(&config.MySQLListener{Upstream: "my",
		DenyCapabilities: []string{"nonsense"}}); err == nil {
		t.Fatal("a capability that is not one was accepted")
	}
}

// The server asking the client for a file is the attack the local_files strip
// prevents, and the refusal is hard: forwarding the request means the file has
// already left.
func TestALocalInfileRequestIsRefusedHard(t *testing.T) {
	p := must(t, &config.MySQLListener{Upstream: "my", DefaultAction: "allow"})
	d := p.LocalInfile(sess("app", "sales"), "/etc/passwd")
	if d.Allow || d.Reason != "local_infile" || !d.Hard {
		t.Fatalf("%+v", d)
	}
	if d.Detail != "/etc/passwd" {
		t.Errorf("the refusal does not name the path: %q", d.Detail)
	}
	// An estate that genuinely loads from clients says so.
	p = must(t, &config.MySQLListener{Upstream: "my", DefaultAction: "allow",
		AllowLoad: []string{"local"}})
	if d = p.LocalInfile(sess("app", "sales"), "/data/x.csv"); !d.Allow {
		t.Fatalf("allow_load local did not take effect: %+v", d)
	}
}

// A LOAD DATA LOCAL statement is refused hard for the same reason.
func TestLoadDataLocalIsRefusedHardAndFileIsNot(t *testing.T) {
	p := must(t, &config.MySQLListener{Upstream: "my", DefaultAction: "allow"})
	local := sqlkind.Statement{Kind: sqlkind.KindCopy, Copy: sqlkind.CopyLocal, Writes: true}
	d := p.Statement(sess("app", "sales"), local, "LOAD DATA LOCAL INFILE ...")
	if d.Allow || d.Reason != "load_local" || !d.Hard {
		t.Fatalf("local: %+v", d)
	}
	// The server-side form is refused too, but softly: it needs the FILE
	// privilege, so the database is also deciding.
	file := sqlkind.Statement{Kind: sqlkind.KindCopy, Copy: sqlkind.CopyFile, Writes: true}
	if d = p.Statement(sess("app", "sales"), file, "LOAD DATA INFILE ..."); d.Allow || d.Hard {
		t.Fatalf("file: %+v", d)
	}
}

// mysql_clear_password is refused on an unencrypted connection even when the
// plugin itself is allowed, because that is the password on the wire.
func TestCleartextPasswordIsRefusedWithoutEncryption(t *testing.T) {
	p := must(t, &config.MySQLListener{Upstream: "my", DefaultAction: "allow",
		AllowWeakAuth: true})
	insecure := sess("app", "sales")
	insecure.Secure = false
	d := p.Auth(insecure, wire.AuthClearText)
	if d.Allow || d.Reason != "cleartext_password_unencrypted" || !d.Hard {
		t.Fatalf("%+v", d)
	}
	// Inside TLS, with the plugin allowed, it crosses -- which is what it is
	// for: a PAM or LDAP back end needs the password itself.
	if d = p.Auth(sess("app", "sales"), wire.AuthClearText); !d.Allow {
		t.Fatalf("cleartext inside tls with allow_weak_auth: %+v", d)
	}
	// Without allow_weak_auth it is refused either way.
	p = must(t, &config.MySQLListener{Upstream: "my", DefaultAction: "allow"})
	if d = p.Auth(sess("app", "sales"), wire.AuthClearText); d.Allow || !d.Hard {
		t.Fatalf("cleartext without allow_weak_auth: %+v", d)
	}
	// mysql_native_password is deliberately not weak.
	if d = p.Auth(sess("app", "sales"), wire.AuthNative); !d.Allow {
		t.Fatalf("mysql_native_password was refused as weak: %+v", d)
	}
	// And the allow list refuses a plugin the estate did not name even when it
	// is strong.
	p = must(t, &config.MySQLListener{Upstream: "my", DefaultAction: "allow",
		AllowAuth: []string{wire.AuthCachingSHA2}})
	if d = p.Auth(sess("app", "sales"), wire.AuthNative); d.Allow || d.Reason != "auth_not_allowed" {
		t.Fatalf("%+v", d)
	}
}

// A rule widens the listener for its own traffic, on commands as well as
// statements.
func TestARuleWidensTheCommandListForItsOwnTraffic(t *testing.T) {
	p := must(t, &config.MySQLListener{
		Upstream: "my", DefaultAction: "deny", ReadOnly: true,
		AllowStatements: []string{"select", "show"},
		Rules: []config.MySQLRule{
			{Name: "replica", Users: []string{"repl"},
				AllowCommands: []string{"binlog_dump", "register_slave", "ping", "quit"}},
			{Name: "migrations", Users: []string{"migrator"},
				AllowStatements: []string{"ddl", "select"}, ReadOnly: no(false)},
		},
	})
	// The replica account may stream, and nobody else may.
	if d := p.Command(sess("repl", ""), wire.ComBinlogDump); !d.Allow || d.Rule != "replica" {
		t.Fatalf("replica: %+v", d)
	}
	if d := p.Command(sess("app", "sales"), wire.ComBinlogDump); d.Allow {
		t.Error("the application account was allowed to stream the binlog")
	}
	// The replica's rule names no statements, so the listener's list applies to
	// it -- and a query it does send is still read-only.
	if d := p.Statement(sess("repl", ""), sqlkind.Statement{Kind: sqlkind.KindDDL, Writes: true}, "x"); d.Allow {
		t.Error("the replica account was allowed ddl")
	}
	// The migration account gets its own statements and its own read_only.
	if d := p.Statement(sess("migrator", "sales"),
		sqlkind.Statement{Kind: sqlkind.KindDDL, Writes: true}, "x"); !d.Allow {
		t.Errorf("migrator ddl: %+v", d)
	}
}

// A deny list is not overridable by a rule, on commands as on statements.
func TestADenyListIsNotOverridableByARule(t *testing.T) {
	p := must(t, &config.MySQLListener{
		Upstream: "my", DefaultAction: "allow",
		AllowCommands: []string{"query", "ping", "shutdown"},
		DenyCommands:  []string{"shutdown"},
		Rules: []config.MySQLRule{{Name: "admin", Users: []string{"root"},
			AllowCommands: []string{"shutdown", "query"}}},
	})
	if d := p.Command(sess("root", ""), wire.ComShutdown); d.Allow {
		t.Fatal("a rule overrode the listener's deny list")
	}
	// The rule's other permission still works, so the test is about the deny
	// list rather than the rule never matching.
	if d := p.Command(sess("root", ""), wire.ComQuery); !d.Allow {
		t.Fatalf("the rule did not match at all: %+v", d)
	}
}

// read_only and the statement lists behave as on the postgres kind, including
// call and do counting as writes.
func TestReadOnlyIncludesTheStatementsThatRunCode(t *testing.T) {
	p := must(t, &config.MySQLListener{Upstream: "my", DefaultAction: "allow", ReadOnly: true})
	for _, k := range []sqlkind.Kind{sqlkind.KindInsert, sqlkind.KindUpdate,
		sqlkind.KindDelete, sqlkind.KindDDL, sqlkind.KindGrant, sqlkind.KindCall,
		sqlkind.KindDo, sqlkind.KindMaintenance} {
		if d := p.Statement(sess("app", "sales"), sqlkind.Statement{Kind: k, Writes: true}, "x"); d.Allow {
			t.Errorf("%s crossed a read_only listener", k)
		}
	}
	for _, k := range []sqlkind.Kind{sqlkind.KindSelect, sqlkind.KindShow, sqlkind.KindSet} {
		if d := p.Statement(sess("app", "sales"), sqlkind.Statement{Kind: k}, "x"); !d.Allow {
			t.Errorf("%s was refused by a read_only listener", k)
		}
	}
}

// A statement the classifier cannot read is refused whatever the configuration
// says, and the MySQL dialect is the one used.
func TestAnUnreadableStatementIsRefusedHard(t *testing.T) {
	p := must(t, &config.MySQLListener{Upstream: "my", DefaultAction: "allow"})
	st := sqlkind.Statement{Kind: sqlkind.KindUnknown, Verb: "VACUUM", Writes: true}
	d := p.Statement(sess("app", "sales"), st, "VACUUM FULL")
	if d.Allow || d.Reason != "statement_unreadable" || !d.Hard {
		t.Fatalf("%+v", d)
	}
	if d.Detail != "VACUUM" {
		t.Errorf("the refusal does not name the verb: %q", d.Detail)
	}
}

// The client list is checked before the identity, and it is hard.
func TestTheClientListIsCheckedFirst(t *testing.T) {
	p := must(t, &config.MySQLListener{Upstream: "my", DefaultAction: "allow",
		AllowClients: []string{"10.0.0.0/24"}})
	se := sess("app", "sales")
	se.IP = netip.MustParseAddr("192.0.2.1")
	d := p.Login(se, loginOf("app", "sales"))
	if d.Allow || d.Reason != "client_not_allowed" || !d.Hard {
		t.Fatalf("%+v", d)
	}
	// And a connection in the clear is refused before its identity is read.
	se = sess("app", "sales")
	se.Secure = false
	if d = p.Login(se, loginOf("app", "sales")); d.Allow || d.Reason != "tls_required" || !d.Hard {
		t.Fatalf("plaintext: %+v", d)
	}
}

// A schedule and an observing rule behave as on every other kind.
func TestTheScheduleAndTheObservingRule(t *testing.T) {
	p := must(t, &config.MySQLListener{
		Upstream: "my", DefaultAction: "deny",
		Rules: []config.MySQLRule{{Name: "window", Users: []string{"migrator"},
			Schedule: &config.ModbusSchedule{From: "01:00", To: "03:00"}}},
	})
	inside := sess("migrator", "sales")
	inside.At = time.Date(2026, 3, 4, 2, 0, 0, 0, time.UTC)
	if d := p.Statement(inside, sqlkind.Statement{Kind: sqlkind.KindSelect}, "x"); !d.Allow {
		t.Fatalf("inside: %+v", d)
	}
	if d := p.Statement(sess("migrator", "sales"),
		sqlkind.Statement{Kind: sqlkind.KindSelect}, "x"); d.Allow {
		t.Fatal("outside the window was allowed")
	}
	// An observe rule decides nothing, which means the rest of the policy
	// decides: on a listener that denies by default, the default does. A rule
	// that allowed what it covered would make a trial the most dangerous edit
	// in a configuration.
	p = must(t, &config.MySQLListener{Upstream: "my", DefaultAction: "deny",
		Rules: []config.MySQLRule{{Name: "watch", Users: []string{"app"}, Action: "observe"}}})
	d := p.Statement(sess("app", "sales"),
		sqlkind.Statement{Kind: sqlkind.KindDDL, Writes: true}, "x")
	if d.Allow {
		t.Fatalf("an observing rule decided, by allowing: %+v", d)
	}
	if len(d.Observed) != 1 || d.Observed[0] != "watch" {
		t.Errorf("the rule being tried was not recorded: %+v", d.Observed)
	}
	// And a deny rule under it still decides.
	p = must(t, &config.MySQLListener{Upstream: "my", DefaultAction: "allow",
		Rules: []config.MySQLRule{
			{Name: "watch", Users: []string{"app"}, Action: "observe"},
			{Name: "lockdown", Users: []string{"app"}, Action: "deny"},
		}})
	if d := p.Statement(sess("app", "sales"),
		sqlkind.Statement{Kind: sqlkind.KindSelect}, "x"); d.Allow || d.Rule != "lockdown" {
		t.Errorf("a trial rule above the deny rule decided: %+v", d)
	}
}

// What compile refuses to understand, so that a typo is a startup error rather
// than a policy that quietly matches nothing.
func TestCompileRefusesWhatItCannotUnderstand(t *testing.T) {
	for name, c := range map[string]*config.MySQLListener{
		"a command that is not one":      {Upstream: "my", AllowCommands: []string{"sudo"}},
		"a deny command that is not one": {Upstream: "my", DenyCommands: []string{"sudo"}},
		"a statement kind":               {Upstream: "my", AllowStatements: []string{"selekt"}},
		"a load target":                  {Upstream: "my", AllowLoad: []string{"sideways"}},
		"a capability":                   {Upstream: "my", DenyCapabilities: []string{"nope"}},
		"stripping ssl":                  {Upstream: "my", DenyCapabilities: []string{"ssl"}},
		"a plugin":                       {Upstream: "my", AllowAuth: []string{"magic"}},
		"a default action":               {Upstream: "my", DefaultAction: "maybe"},
		"a client network":               {Upstream: "my", AllowClients: []string{"10.0.0.1"}},
		"a rule action":                  {Upstream: "my", Rules: []config.MySQLRule{{Action: "perhaps"}}},
		"a rule's command":               {Upstream: "my", Rules: []config.MySQLRule{{AllowCommands: []string{"x"}}}},
	} {
		if _, err := compile(c); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	p := must(t, &config.MySQLListener{Upstream: "my", Rules: []config.MySQLRule{{}}})
	if p.rules[0].name != "rules[0]" {
		t.Errorf("an unnamed rule is called %q", p.rules[0].name)
	}
}
