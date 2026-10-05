package tds

import (
	"net/netip"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/sqlkind"
	wire "github.com/rom/xproxy/internal/tdswire"
)

func mustCompile(t *testing.T, c *config.TDSListener) *policy {
	t.Helper()
	p, err := compile(c)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func sess(user, db, app string) *Session {
	return &Session{IP: netip.MustParseAddr("10.0.0.5"), User: user, Database: db,
		App: app, Secure: true, At: time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)}
}

// The downgrade defence, which is the reason this kind exists. A client that
// asked for `off` -- which is a great deal of deployed software -- is answered
// `required`, so it upgrades; and the relay never repeats the answer it read from
// the server, because that octet is unsigned and whatever is on the path may
// have written it.
func TestTheEncryptionAnswerIsDecidedAndNotForwarded(t *testing.T) {
	p := mustCompile(t, &config.TDSListener{Upstream: "u"})
	for _, asked := range []byte{wire.EncryptOff, wire.EncryptNotSup, wire.EncryptOn,
		wire.EncryptReq, wire.EncryptClientCertOn, 0x42} {
		answer, forced, d := p.Encryption(asked, true)
		if !d.Allow {
			t.Fatalf("asked %s: refused: %+v", wire.EncryptName(asked), d)
		}
		if answer != wire.EncryptReq {
			t.Fatalf("asked %s: answered %s, want required",
				wire.EncryptName(asked), wire.EncryptName(answer))
		}
		// The alert fires exactly when the relay raised the negotiation, so the
		// log names the clients that would have gone in the clear and not the
		// ones that were already encrypting.
		if want := !wire.Encrypted(asked); forced != want {
			t.Fatalf("asked %s: forced=%v, want %v", wire.EncryptName(asked), forced, want)
		}
	}
	// Requiring encryption without a certificate is refused rather than silently
	// downgraded, and hard, so monitor mode cannot shadow it.
	_, _, d := p.Encryption(wire.EncryptOff, false)
	if d.Allow || !d.Hard || d.Reason != "tls_required" {
		t.Fatalf("no certificate: %+v", d)
	}
}

// With the requirement off, a client that wants encryption still gets it. A
// relay that answered `off` to everybody because the listener did not insist
// would be performing the downgrade itself.
// An observe rule records and decides nothing, so the rules below it still
// decide -- and on a listener that denies by default, the default does.
func TestAnObserveRuleIsRecordedAndDecidesNothing(t *testing.T) {
	p := mustCompile(t, &config.TDSListener{Upstream: "sql", DefaultAction: "deny",
		Rules: []config.TDSRule{{Name: "trial", Users: []string{"app"}, Action: "observe"}}})
	s := sess("app", "sales", "report.exe")
	sts, lexed := sqlkind.Statements(sqlkind.TSQL, "SELECT 1", 4)
	if !lexed || len(sts) == 0 {
		t.Fatal("the statement did not lex")
	}
	d := p.Statement(s, sts[0], "SELECT 1")
	if d.Allow {
		t.Fatalf("a trial rule decided, by allowing: %+v", d)
	}
	if len(d.Observed) != 1 || d.Observed[0] != "trial" {
		t.Errorf("the rule being tried was not recorded: %+v", d.Observed)
	}
	// And the deny rule under it decides.
	p = mustCompile(t, &config.TDSListener{Upstream: "sql", DefaultAction: "allow",
		Rules: []config.TDSRule{
			{Name: "trial", Users: []string{"app"}, Action: "observe"},
			{Name: "lockdown", Users: []string{"app"}, Action: "deny"},
		}})
	if d := p.Statement(s, sts[0], "SELECT 1"); d.Allow || d.Rule != "lockdown" {
		t.Errorf("the trial rule shadowed the deny rule: %+v", d)
	}
}

func TestAClientThatWantsEncryptionIsNotTalkedOutOfIt(t *testing.T) {
	no := false
	p := mustCompile(t, &config.TDSListener{Upstream: "u", RequireTLS: &no})
	for _, asked := range []byte{wire.EncryptOn, wire.EncryptReq, wire.EncryptClientCertReq} {
		answer, _, d := p.Encryption(asked, true)
		if !d.Allow || !wire.Encrypted(answer) {
			t.Fatalf("asked %s: answered %s (%+v)",
				wire.EncryptName(asked), wire.EncryptName(answer), d)
		}
	}
	// And a client that asked for it when the listener cannot provide it is
	// refused rather than answered "not supported", which is the lie that makes
	// the downgrade work.
	if _, _, d := p.Encryption(wire.EncryptReq, false); d.Allow || !d.Hard {
		t.Fatalf("%+v", d)
	}
	// Only a client that asked for nothing gets nothing.
	if answer, forced, _ := p.Encryption(wire.EncryptOff, true); answer != wire.EncryptOff || forced {
		t.Fatalf("answered %s, forced=%v", wire.EncryptName(answer), forced)
	}
}

// The server's leg is negotiated separately, and `require` means it. A relay that
// terminated the client's TLS and spoke cleartext onwards would have moved the
// exposure rather than removed it -- and what it forwards is a password
// recoverable with a nibble swap.
func TestTheUpstreamLegIsItsOwnNegotiation(t *testing.T) {
	p := mustCompile(t, &config.TDSListener{Upstream: "u"})
	if got := p.UpstreamEncryption("require"); got != wire.EncryptReq {
		t.Fatalf("asked the server for %s", wire.EncryptName(got))
	}
	if got := p.UpstreamEncryption("disable"); got != wire.EncryptOff {
		t.Fatalf("disable asked for %s", wire.EncryptName(got))
	}
	for _, tc := range []struct {
		mode string
		got  byte
		ok   bool
	}{
		{"require", wire.EncryptOn, true},
		{"require", wire.EncryptReq, true},
		{"require", wire.EncryptOff, false},
		{"require", wire.EncryptNotSup, false},
		{"prefer", wire.EncryptNotSup, true},
		{"disable", wire.EncryptOff, true},
	} {
		d := p.UpstreamAnswer(tc.mode, tc.got)
		if d.Allow != tc.ok {
			t.Fatalf("%s + %s: allow=%v", tc.mode, wire.EncryptName(tc.got), d.Allow)
		}
		if !tc.ok && !d.Hard {
			t.Fatalf("%s + %s: a soft refusal", tc.mode, wire.EncryptName(tc.got))
		}
	}
}

// A TDS password is XOR 0xa5 with the nibbles swapped. There is no stronger
// authentication method to prefer, so the only decision is whether the
// connection is encrypted -- and a login that crossed in the clear has already
// disclosed a reusable credential, which is why the refusal is hard.
func TestALoginWithAPasswordNeedsAnEncryptedConnection(t *testing.T) {
	p := mustCompile(t, &config.TDSListener{Upstream: "u", DefaultAction: "allow"})
	s := sess("sa", "sales", "MyApp")
	s.Secure = false
	d := p.Login(s, &wire.Login7{User: "sa", HasPassword: true})
	if d.Allow || !d.Hard || d.Reason != "cleartext_password" {
		t.Fatalf("%+v", d)
	}
	// Encrypted, and it is an ordinary login.
	s.Secure = true
	if d = p.Login(s, &wire.Login7{User: "sa", HasPassword: true}); !d.Allow {
		t.Fatalf("%+v", d)
	}
	// Named explicitly, it is allowed -- the setting says what it permits.
	p = mustCompile(t, &config.TDSListener{Upstream: "u", DefaultAction: "allow",
		AllowCleartextPassword: true})
	s.Secure = false
	if d = p.Login(s, &wire.Login7{User: "sa", HasPassword: true}); !d.Allow {
		t.Fatalf("named: %+v", d)
	}
}

// A user list and integrated security cannot both be in force: an SSPI login
// carries no user name for a list to match. Rather than have the list quietly
// not apply -- a user policy with a hole exactly the shape of Windows
// authentication -- naming a list refuses the login that cannot be checked
// against it.
func TestAUserListTurnsIntegratedLoginsOff(t *testing.T) {
	integrated := &wire.Login7{Integrated: true}
	s := sess("", "sales", "MyApp")

	// No user list: integrated is ordinary.
	p := mustCompile(t, &config.TDSListener{Upstream: "u", DefaultAction: "allow"})
	if d := p.Login(s, integrated); !d.Allow {
		t.Fatalf("no list: %+v", d)
	}
	// A user list, and the login that cannot be checked against it is refused,
	// hard.
	p = mustCompile(t, &config.TDSListener{Upstream: "u", DefaultAction: "allow",
		AllowUsers: []string{"reporting"}})
	d := p.Login(s, integrated)
	if d.Allow || !d.Hard || d.Reason != "integrated_not_allowed" {
		t.Fatalf("with a list: %+v", d)
	}
	// A deny list has the same problem and the same answer.
	p = mustCompile(t, &config.TDSListener{Upstream: "u", DefaultAction: "allow",
		DenyUsers: []string{"sa"}})
	if d = p.Login(s, integrated); d.Allow {
		t.Fatalf("with a deny list: %+v", d)
	}
	// Said explicitly, it is allowed and the operator has been told in the
	// validator what they gave up.
	yes := true
	p = mustCompile(t, &config.TDSListener{Upstream: "u", DefaultAction: "allow",
		AllowUsers: []string{"reporting"}, AllowIntegrated: &yes})
	if d = p.Login(s, integrated); !d.Allow {
		t.Fatalf("named: %+v", d)
	}
	// A login that is neither integrated nor named is nobody.
	p = mustCompile(t, &config.TDSListener{Upstream: "u", DefaultAction: "allow"})
	if d = p.Login(sess("", "", ""), &wire.Login7{}); d.Allow || d.Reason != "no_user" {
		t.Fatalf("%+v", d)
	}
}

// The procedure allow list is the half of the policy the other database kinds do
// not have, and the default is what a driver calls rather than what an operator
// remembered to forbid.
func TestTheDefaultProcedureListIsWhatADriverCalls(t *testing.T) {
	p := mustCompile(t, &config.TDSListener{Upstream: "u", DefaultAction: "allow"})
	s := sess("app", "sales", "MyApp")
	for _, proc := range []string{"sp_executesql", "sp_prepexec", "sp_cursorfetch",
		"sp_reset_connection", "sp_describe_first_result_set", "sp_columns"} {
		if d := p.Procedure(s, proc); !d.Allow {
			t.Fatalf("%s: %+v", proc, d)
		}
	}
	// And everything else is off, including things whose names nobody thought to
	// put on a deny list.
	for _, proc := range []string{"xp_cmdshell", "sp_oacreate", "xp_regwrite",
		"sp_addlinkedserver", "sp_configure", "sp_send_dbmail", "xp_dirtree",
		"sp_prepexecrpc", "sp_some_procedure_nobody_has_heard_of"} {
		d := p.Procedure(s, proc)
		if d.Allow {
			t.Fatalf("%s was allowed by default", proc)
		}
	}
}

// A refusal of one of the ways out of the database is not shadowed. Forwarding a
// shell command and writing down that it was noticed is not a trial of a policy;
// it is a shell command.
func TestRefusingAWayOutOfTheDatabaseIsNeverShadowed(t *testing.T) {
	p := mustCompile(t, &config.TDSListener{Upstream: "u", DefaultAction: "allow"})
	s := sess("app", "sales", "MyApp")
	for _, proc := range wire.DangerousProcedures() {
		d := p.Procedure(s, proc)
		if d.Allow {
			t.Fatalf("%s was allowed", proc)
		}
		if !d.Hard {
			t.Fatalf("%s: a refusal monitor mode would shadow", proc)
		}
	}
	// A procedure that is merely not on the allow list is a soft refusal: it is
	// probably an application the operator has not listed yet, and the whole
	// point of monitor mode is finding those.
	if d := p.Procedure(s, "sp_helpdb"); d.Allow || d.Hard {
		t.Fatalf("%+v", d)
	}
	// An operator who names one has said so, and is not overruled.
	p = mustCompile(t, &config.TDSListener{Upstream: "u", DefaultAction: "allow",
		AllowProcedures: []string{"sp_executesql", "XP_CmdShell"}})
	if d := p.Procedure(s, "xp_cmdshell"); !d.Allow {
		t.Fatalf("named explicitly: %+v", d)
	}
	// The name is folded on both sides, so the configuration's spelling does not
	// decide whether the policy applies.
	if d := p.Procedure(s, "sp_executesql"); !d.Allow {
		t.Fatalf("%+v", d)
	}
}

// The message-type allow list, and the one type whose refusal is hard: the
// pre-TDS7 login, which the relay does not read at all.
func TestTheMessageTypeList(t *testing.T) {
	p := mustCompile(t, &config.TDSListener{Upstream: "u", DefaultAction: "allow"})
	s := sess("app", "sales", "MyApp")
	for _, typ := range wire.DefaultTypes() {
		if d := p.Message(s, typ); !d.Allow {
			t.Fatalf("%s: %+v", wire.TypeName(typ), d)
		}
	}
	// bulk_load is off by default: its stream is not SQL and carries no policy.
	if d := p.Message(s, wire.TypeBulkLoad); d.Allow {
		t.Fatalf("bulk_load was allowed by default")
	}
	// The pre-TDS7 login is refused hard, because forwarding a message shape the
	// relay has not read is the thing this kind exists not to do.
	d := p.Message(s, wire.TypeLogin)
	if d.Allow || !d.Hard || d.Reason != "legacy_login" {
		t.Fatalf("%+v", d)
	}
	// Named, it is allowed -- and then it is the operator's decision.
	p = mustCompile(t, &config.TDSListener{Upstream: "u", DefaultAction: "allow",
		AllowTypes: []string{"sql_batch", "login"}})
	if d = p.Message(s, wire.TypeLogin); !d.Allow {
		t.Fatalf("named: %+v", d)
	}
	// And the deny list wins over the allow list.
	p = mustCompile(t, &config.TDSListener{Upstream: "u", DefaultAction: "allow",
		AllowTypes: []string{"sql_batch", "rpc"}, DenyTypes: []string{"rpc"}})
	if d = p.Message(s, wire.TypeRPC); d.Allow {
		t.Fatalf("deny_types lost to allow_types: %+v", d)
	}
}

// The statement policy, which is the same one the postgres and mysql kinds run,
// reaching T-SQL by two routes: a batch and an sp_executesql parameter.
func TestTheStatementPolicy(t *testing.T) {
	p := mustCompile(t, &config.TDSListener{Upstream: "u", DefaultAction: "allow",
		ReadOnly: true})
	s := sess("reporting", "sales", "Excel")
	for _, tc := range []struct {
		sql string
		ok  bool
	}{
		{"SELECT 1", true},
		{"UPDATE t SET x = 1", false},
		{"EXEC dbo.something", false}, // a procedure can do anything the login can
		{"BACKUP DATABASE d TO disk", false},
		{"DBCC CHECKDB", false},
		{"SHUTDOWN", false},
	} {
		sts, lexed := sqlkind.Statements(sqlkind.TSQL, tc.sql, 4)
		if !lexed || len(sts) == 0 {
			t.Fatalf("%q did not lex", tc.sql)
		}
		d := p.Statement(s, sts[0], tc.sql)
		if d.Allow != tc.ok {
			t.Fatalf("%q: allow=%v (%+v)", tc.sql, d.Allow, d)
		}
	}
	// A statement the classifier cannot name is refused hard, which is the whole
	// inversion: a spelling nobody thought of fails closed.
	unknown := sqlkind.Statement{Kind: sqlkind.KindUnknown, Verb: "FLOOB"}
	if d := p.Statement(s, unknown, "FLOOB x"); d.Allow || !d.Hard {
		t.Fatalf("%+v", d)
	}
	// And a statement past the byte bound, before anything tries to classify it.
	long := make([]byte, 70<<10)
	for i := range long {
		long[i] = 'a'
	}
	if d := p.Statement(s, sqlkind.Statement{Kind: sqlkind.KindSelect}, string(long)); d.Allow || !d.Hard {
		t.Fatalf("%+v", d)
	}
}

// Rules select on the client, the login, the database and the application name,
// and a schedule bounds when what a rule allows is allowed.
func TestRulesAndSchedules(t *testing.T) {
	p := mustCompile(t, &config.TDSListener{
		Upstream: "u",
		Rules: []config.TDSRule{
			{Name: "etl", Users: []string{"etl"},
				Schedule:        &config.ModbusSchedule{From: "02:00", To: "05:00"},
				AllowProcedures: []string{"sp_executesql", "bulk_insert"},
				AllowTypes:      []string{"sql_batch", "rpc", "bulk_load"}},
			{Name: "readers", Apps: []string{"Excel*"}, ReadOnly: boolp(true)},
		},
	})
	night := time.Date(2026, 3, 4, 3, 0, 0, 0, time.UTC)
	noon := time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)

	etl := sess("etl", "sales", "loader")
	etl.At = night
	if d := p.Login(etl, &wire.Login7{User: "etl"}); !d.Allow || d.Rule != "etl" {
		t.Fatalf("at night: %+v", d)
	}
	etl.At = noon
	d := p.Login(etl, &wire.Login7{User: "etl"})
	if d.Allow || d.Reason != "outside_schedule" {
		t.Fatalf("at noon: %+v", d)
	}
	// The rule widens its own traffic: bulk_load is off on the listener and on
	// for this login.
	if d = p.Message(etl, wire.TypeBulkLoad); !d.Allow || d.Rule != "etl" {
		t.Fatalf("bulk_load for etl: %+v", d)
	}
	// And a login no rule matches gets the default, which is deny.
	other := sess("someone", "sales", "psql")
	if d = p.Login(other, &wire.Login7{User: "someone"}); d.Allow || d.Reason != "no_rule_matched" {
		t.Fatalf("%+v", d)
	}
	// The app pattern matches with a trailing star, and its rule makes the
	// session read-only without the listener being.
	reader := sess("analyst", "sales", "Excel 16.0")
	if d = p.Login(reader, &wire.Login7{User: "analyst"}); !d.Allow || d.Rule != "readers" {
		t.Fatalf("%+v", d)
	}
	sts, _ := sqlkind.Statements(sqlkind.TSQL, "DELETE FROM t", 4)
	if d = p.Statement(reader, sts[0], "DELETE FROM t"); d.Allow || d.Reason != "read_only" {
		t.Fatalf("%+v", d)
	}
}

func boolp(v bool) *bool { return &v }

// The identity lists, and the client list that is checked before them -- because
// a connection from a network that may not reach the database is refused without
// the relay caring who it claims to be.
func TestTheIdentityLists(t *testing.T) {
	p := mustCompile(t, &config.TDSListener{Upstream: "u", DefaultAction: "allow",
		AllowClients:    []string{"10.0.0.0/24"},
		DenyClients:     []string{"10.0.0.9/32"},
		AllowUsers:      []string{"app", "reporting"},
		DenyUsers:       []string{"sa"},
		AllowDatabases:  []string{"sales"},
		AllowApps:       []string{"MyApp", "Excel*"},
		AllowIntegrated: boolp(false),
	})
	for _, tc := range []struct {
		name         string
		ip           string
		user, db, ap string
		want         string
	}{
		{"an ordinary login", "10.0.0.5", "app", "sales", "MyApp", ""},
		{"a network that may not reach it", "192.168.1.5", "app", "sales", "MyApp", "client_not_allowed"},
		{"a denied host inside an allowed network", "10.0.0.9", "app", "sales", "MyApp", "client_not_allowed"},
		{"a login not on the list", "10.0.0.5", "webapp", "sales", "MyApp", "user_not_allowed"},
		{"a login on the deny list", "10.0.0.5", "sa", "sales", "MyApp", "user_not_allowed"},
		{"a database not on the list", "10.0.0.5", "app", "master", "MyApp", "database_not_allowed"},
		{"an application not on the list", "10.0.0.5", "app", "sales", "sqlcmd", "app_not_allowed"},
		{"an application matched by prefix", "10.0.0.5", "app", "sales", "Excel 16.0", ""},
	} {
		s := &Session{IP: netip.MustParseAddr(tc.ip), User: tc.user, Database: tc.db,
			App: tc.ap, Secure: true, At: time.Now()}
		d := p.Login(s, &wire.Login7{User: tc.user, Database: tc.db})
		if tc.want == "" {
			if !d.Allow {
				t.Fatalf("%s: %+v", tc.name, d)
			}
			continue
		}
		if d.Allow || d.Reason != tc.want {
			t.Fatalf("%s: %+v, want %s", tc.name, d, tc.want)
		}
	}
	// The client list is the one refusal that is hard, because it is not about
	// anything the connection claimed: the network either may reach the database
	// or it may not.
	s := &Session{IP: netip.MustParseAddr("192.168.1.5"), User: "app", Secure: true, At: time.Now()}
	if d := p.Login(s, &wire.Login7{User: "app"}); !d.Hard {
		t.Fatalf("%+v", d)
	}
}

// A configuration the relay cannot make sense of is refused at compile rather
// than at the first connection that trips over it.
func TestABadConfigurationIsRefusedAtCompile(t *testing.T) {
	for _, tc := range []struct {
		name string
		c    *config.TDSListener
	}{
		{"an unknown message type", &config.TDSListener{Upstream: "u", AllowTypes: []string{"nonsense"}}},
		{"an unknown statement kind", &config.TDSListener{Upstream: "u", DenyStatements: []string{"nonsense"}}},
		{"an unparseable client network", &config.TDSListener{Upstream: "u", AllowClients: []string{"10.0.0.1"}}},
		{"an unparseable deny network", &config.TDSListener{Upstream: "u", DenyClients: []string{"not-an-address"}}},
		{"a default action that is neither", &config.TDSListener{Upstream: "u", DefaultAction: "maybe"}},
		{"a rule action that is none of the three",
			&config.TDSListener{Upstream: "u", Rules: []config.TDSRule{{Action: "perhaps"}}}},
		{"a rule with an unparseable network",
			&config.TDSListener{Upstream: "u", Rules: []config.TDSRule{{Clients: []string{"x"}}}}},
		{"a rule with an unknown type",
			&config.TDSListener{Upstream: "u", Rules: []config.TDSRule{{AllowTypes: []string{"x"}}}}},
		{"a rule with an unknown statement kind",
			&config.TDSListener{Upstream: "u", Rules: []config.TDSRule{{DenyStatements: []string{"x"}}}}},
		{"a rule with a day that is not a day",
			&config.TDSListener{Upstream: "u", Rules: []config.TDSRule{
				{Schedule: &config.ModbusSchedule{Days: []string{"someday"}}}}}},
		{"a rule with a time that is not a time",
			&config.TDSListener{Upstream: "u", Rules: []config.TDSRule{
				{Schedule: &config.ModbusSchedule{From: "25:00"}}}}},
	} {
		if _, err := compile(tc.c); err == nil {
			t.Fatalf("%s was accepted", tc.name)
		}
	}
	// An unnamed rule still has a name, so a log line and a counter can refer to
	// it.
	p := mustCompile(t, &config.TDSListener{Upstream: "u",
		Rules: []config.TDSRule{{Users: []string{"app"}}}})
	if d := p.Login(sess("app", "sales", "x"), &wire.Login7{User: "app"}); d.Rule != "rules[0]" {
		t.Fatalf("%+v", d)
	}
}
