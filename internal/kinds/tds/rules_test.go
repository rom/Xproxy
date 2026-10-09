package tds

import (
	"crypto/tls"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/proxytest"
	"github.com/rom/xproxy/internal/sqlkind"
	wire "github.com/rom/xproxy/internal/tdswire"
)

// A rule's own lists, which replace the listener's for the traffic the rule
// covers.
//
// Replacing rather than narrowing is the whole point of a rule here: the
// listener says what the estate's ordinary traffic may do and a rule says what
// one login, one application or one network may do instead. Every list exists
// in both places, so each one is asked twice -- once where the listener
// decides and once where the rule does -- and the deny side has to win in both
// directions, because a deny list a rule could be talked out of is not a deny
// list.

// stmt classifies one piece of T-SQL the way the relay does.
func stmt(t *testing.T, sql string) sqlkind.Statement {
	t.Helper()
	sts, lexed := sqlkind.Statements(sqlkind.TSQL, sql, 4)
	if !lexed || len(sts) == 0 {
		t.Fatalf("%q did not lex", sql)
	}
	return sts[0]
}

func TestARulesListsReplaceTheListenersForTheTrafficItCovers(t *testing.T) {
	p := mustCompile(t, &config.TDSListener{
		Upstream: "u", DefaultAction: "allow",
		AllowTypes:      []string{"sql_batch", "rpc"},
		AllowStatements: []string{"select", "insert"},
		AllowProcedures: []string{"sp_executesql"},
		Rules: []config.TDSRule{{
			Name: "etl", Users: []string{"etl"}, Action: "allow",
			// Narrower on every axis than the listener, and a different set
			// rather than a subset: a rule's list is the list in force.
			AllowTypes:      []string{"sql_batch"},
			AllowStatements: []string{"insert", "update"},
			AllowProcedures: []string{"bulk_insert"},
		}, {
			Name: "reporting", Users: []string{"reporting"}, Action: "allow",
			DenyTypes:      []string{"rpc"},
			DenyStatements: []string{"insert"},
			DenyProcedures: []string{"sp_executesql"},
		}},
	})

	etl, rep := sess("etl", "sales", "loader"), sess("reporting", "sales", "Excel")

	// The rule's allow list is the one in force, in both directions: what it
	// names is carried although the listener does not name it, and what the
	// listener names is refused because the rule does not.
	if d := p.Procedure(etl, "bulk_insert"); !d.Allow || d.Rule != "etl" {
		t.Errorf("a procedure the rule names: %+v", d)
	}
	if d := p.Procedure(etl, "sp_executesql"); d.Allow ||
		d.Reason != "procedure_not_allowed" || d.Rule != "etl" {
		t.Errorf("a procedure only the listener names: %+v", d)
	}
	if d := p.Statement(etl, stmt(t, "UPDATE t SET x = 1"), "UPDATE t SET x = 1"); !d.Allow ||
		d.Rule != "etl" {
		t.Errorf("a statement kind the rule names: %+v", d)
	}
	if d := p.Statement(etl, stmt(t, "SELECT 1"), "SELECT 1"); d.Allow ||
		d.Reason != "statement_not_allowed" || d.Rule != "etl" {
		t.Errorf("a statement kind only the listener names: %+v", d)
	}
	if d := p.Message(etl, wire.TypeRPC); d.Allow ||
		d.Reason != "type_not_allowed" || d.Rule != "etl" {
		t.Errorf("a message type only the listener names: %+v", d)
	}

	// And the rule's deny lists win over the listener's allow lists, naming
	// the rule so the refusal can be argued with.
	if d := p.Procedure(rep, "sp_executesql"); d.Allow ||
		d.Reason != "procedure_denied" || d.Rule != "reporting" {
		t.Errorf("the rule's procedure deny list: %+v", d)
	}
	if d := p.Statement(rep, stmt(t, "INSERT INTO t VALUES (1)"),
		"INSERT INTO t VALUES (1)"); d.Allow ||
		d.Reason != "statement_denied" || d.Rule != "reporting" {
		t.Errorf("the rule's statement deny list: %+v", d)
	}
	if d := p.Message(rep, wire.TypeRPC); d.Allow ||
		d.Reason != "type_denied" || d.Rule != "reporting" {
		t.Errorf("the rule's type deny list: %+v", d)
	}
	// What neither list touches is still decided by the listener's.
	if d := p.Statement(rep, stmt(t, "SELECT 1"), "SELECT 1"); !d.Allow ||
		d.Rule != "reporting" {
		t.Errorf("a statement the rule says nothing about: %+v", d)
	}
}

// The listener's own deny lists, which no rule reaches: a deny written at the
// top of the section is the estate's line and a rule is an exception inside it,
// not a way around it.
func TestTheListenersDenyListsAreNotReachableFromARule(t *testing.T) {
	p := mustCompile(t, &config.TDSListener{
		Upstream: "u", DefaultAction: "allow",
		DenyStatements: []string{"ddl"},
		Rules: []config.TDSRule{{Name: "etl", Users: []string{"etl"}, Action: "allow",
			AllowStatements: []string{"ddl", "select"}}},
	})
	etl := sess("etl", "sales", "loader")
	if d := p.Statement(etl, stmt(t, "DROP TABLE t"), "DROP TABLE t"); d.Allow ||
		d.Reason != "statement_denied" || d.Rule != "" {
		t.Errorf("a rule allowed what the listener denies: %+v", d)
	}
	if d := p.Statement(etl, stmt(t, "SELECT 1"), "SELECT 1"); !d.Allow {
		t.Errorf("the rest of the rule's list stopped working: %+v", d)
	}
}

// A rule that refuses, and a rule whose window has closed, decided on a
// statement rather than at login. Both are reached again there because a
// session outlives the login: a schedule that ended at five in the morning has
// to stop the batch sent at five past, not only the connection opened after it.
func TestARuleThatRefusesIsReachedOnEveryStatementAndNotOnlyAtLogin(t *testing.T) {
	p := mustCompile(t, &config.TDSListener{
		Upstream: "u", DefaultAction: "allow",
		Rules: []config.TDSRule{
			{Name: "quarantine", Users: []string{"temp"}, Action: "deny"},
			{Name: "window", Users: []string{"etl"}, Action: "allow",
				Schedule: &config.ModbusSchedule{From: "02:00", To: "05:00"}},
		},
	})
	temp := sess("temp", "sales", "psql")
	if d := p.Login(temp, &wire.Login7{User: "temp"}); d.Allow ||
		d.Reason != "rule_denied" || d.Rule != "quarantine" {
		t.Errorf("at login: %+v", d)
	}
	if d := p.Statement(temp, stmt(t, "SELECT 1"), "SELECT 1"); d.Allow ||
		d.Reason != "rule_denied" || d.Rule != "quarantine" {
		t.Errorf("on a statement: %+v", d)
	}

	etl := sess("etl", "sales", "loader")
	etl.At = time.Date(2026, 3, 4, 3, 0, 0, 0, time.UTC)
	if d := p.Statement(etl, stmt(t, "SELECT 1"), "SELECT 1"); !d.Allow || d.Rule != "window" {
		t.Errorf("inside the window: %+v", d)
	}
	etl.At = time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)
	if d := p.Statement(etl, stmt(t, "SELECT 1"), "SELECT 1"); d.Allow ||
		d.Reason != "outside_schedule" || d.Rule != "window" {
		t.Errorf("outside it: %+v", d)
	}
}

// Which rule covers a session: every selector it sets has to hold, and a
// selector it leaves empty holds for anything. The client network and the
// database are the two the login name does not imply -- the same login from a
// jump host and from a workstation is two different situations.
func TestEverySelectorARuleSetsHasToHold(t *testing.T) {
	p := mustCompile(t, &config.TDSListener{
		Upstream: "u", DefaultAction: "allow",
		Rules: []config.TDSRule{{Name: "jump-host", Action: "allow",
			Clients:   []string{"10.9.0.0/24"},
			Databases: []string{"sales"},
			Apps:      []string{"*"},
			ReadOnly:  boolp(true)}},
	})
	// Inside every selector: the rule decides, and it is the one that makes
	// the session read-only.
	inside := sess("analyst", "sales", "whatever")
	inside.IP = netip.MustParseAddr("10.9.0.7")
	if d := p.Statement(inside, stmt(t, "DELETE FROM t"), "DELETE FROM t"); d.Allow ||
		d.Reason != "read_only" || d.Rule != "jump-host" {
		t.Errorf("inside the rule: %+v", d)
	}
	// The right database from the wrong network, and the right network with
	// the wrong database: neither is covered, so the listener decides and the
	// write is carried.
	for what, se := range map[string]*Session{
		"the wrong network":  inside,
		"the wrong database": inside,
	} {
		se2 := *se
		if what == "the wrong network" {
			se2.IP = netip.MustParseAddr("192.0.2.7")
		} else {
			se2.Database = "payroll"
		}
		if d := p.Statement(&se2, stmt(t, "DELETE FROM t"), "DELETE FROM t"); !d.Allow ||
			d.Rule != "" {
			t.Errorf("%s was covered anyway: %+v", what, d)
		}
	}
	// A session with no address at all is not in any network: a rule written
	// about a network must not cover a connection whose address this relay
	// could not read.
	none := *inside
	none.IP = netip.Addr{}
	if d := p.Statement(&none, stmt(t, "DELETE FROM t"), "DELETE FROM t"); !d.Allow {
		t.Errorf("a rule about a network covered a session with no address: %+v", d)
	}
}

// The statements-per-batch bound, which a rule can raise for the one login
// that really does send a hundred statements in a batch without raising it for
// everybody. Default 1: a batch is one statement unless an estate says
// otherwise, because several statements in one batch is what turns a working
// injection into a working injection that also covers its tracks.
func TestTheBatchBoundIsOneUnlessARuleRaisesIt(t *testing.T) {
	p := mustCompile(t, &config.TDSListener{
		Upstream: "u", DefaultAction: "allow",
		Rules: []config.TDSRule{{Name: "etl", Users: []string{"etl"},
			Action: "allow", MaxStatements: 50}},
	})
	if got := p.MaxStatements(sess("app", "sales", "MyApp")); got != 1 {
		t.Errorf("the default batch bound is %d, want 1", got)
	}
	if got := p.MaxStatements(sess("etl", "sales", "loader")); got != 50 {
		t.Errorf("the rule's batch bound is %d, want 50", got)
	}
}

// And the lists are compiled when the listener is built, in a rule as well as
// at the top of the section. A statement kind or a message type no edition
// knows is a rule that matches nothing: the rule an operator wrote to refuse
// something would refuse nothing, and the traffic it was written about would
// be decided by whatever is underneath.
func TestARulesListsAreCompiledTheSameAsTheListeners(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		l          config.TDSListener
	}{
		{"the listener's deny types", "deny_types",
			config.TDSListener{Upstream: "u", DenyTypes: []string{"sql-batch"}}},
		{"the listener's statement list", "allow_statements",
			config.TDSListener{Upstream: "u", AllowStatements: []string{"selekt"}}},
		{"a rule's deny types", "rules[0].deny_types",
			config.TDSListener{Upstream: "u", Rules: []config.TDSRule{
				{Name: "r", DenyTypes: []string{"not-a-type"}}}}},
		{"a rule's statement list", "rules[0].allow_statements",
			config.TDSListener{Upstream: "u", Rules: []config.TDSRule{
				{Name: "r", AllowStatements: []string{"selekt"}}}}},
	} {
		_, err := compile(&tc.l)
		if err == nil {
			t.Errorf("%s compiled", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v does not say which list", tc.name, err)
		}
	}
}

// The listener's own lists where no rule is in play at all, which is the
// configuration most estates actually run: one set of lines at the top of the
// section and no exceptions.
func TestTheListenersOwnListsDecideWhereNoRuleDoes(t *testing.T) {
	p := mustCompile(t, &config.TDSListener{
		Upstream: "u", DefaultAction: "allow",
		DenyProcedures:  []string{"sp_executesql"},
		AllowStatements: []string{"select"},
		MaxStatements:   50,
	})
	s := sess("app", "sales", "MyApp")
	if d := p.Procedure(s, "sp_executesql"); d.Allow ||
		d.Reason != "procedure_denied" || d.Rule != "" {
		t.Errorf("the listener's procedure deny list: %+v", d)
	}
	if d := p.Statement(s, stmt(t, "DELETE FROM t"), "DELETE FROM t"); d.Allow ||
		d.Reason != "statement_not_allowed" {
		t.Errorf("the listener's statement allow list: %+v", d)
	}
	if d := p.Statement(s, stmt(t, "SELECT 1"), "SELECT 1"); !d.Allow {
		t.Errorf("a statement kind the listener names: %+v", d)
	}
	// And the batch bound set at the top of the section, where no rule raises
	// or lowers it.
	if got := p.MaxStatements(s); got != 50 {
		t.Errorf("the listener's batch bound is %d, want 50", got)
	}
}

// What stops the listener being built, as opposed to what stops a message.
//
// Each of these is a configuration an operator would otherwise find out about
// from traffic: a policy that will not compile, a trust store for the server
// that is not one, and require_tls on a listener with no certificate of its
// own -- which would refuse every client at the first PRELOGIN, having
// promised in the file that it would require encryption.
func TestASectionThatCannotBeServedIsRefusedWhenTheListenerIsBuilt(t *testing.T) {
	dir := t.TempDir()
	notACert := filepath.Join(dir, "not-a-certificate.pem")
	if err := os.WriteFile(notACert, []byte("this is not PEM\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, want string
		tc         config.TDSListener
		tlsCfg     *tls.Config
	}{
		{"a policy that will not compile", "allow_statements",
			config.TDSListener{Upstream: "u", AllowStatements: []string{"selekt"}}, nil},
		{"a trust store that is not one", "upstream_tls",
			config.TDSListener{Upstream: "u", UpstreamTLSMode: "require",
				UpstreamTLS: &config.UpstreamTLS{CAFile: notACert}}, nil},
		{"require_tls with no certificate", "require_tls",
			config.TDSListener{Upstream: "u", RequireTLS: boolp(true)}, nil},
	} {
		_, err := newServer(nil, config.Listener{Name: "sql", TDS: &tc.tc}, nil, tc.tlsCfg)
		if err == nil {
			t.Errorf("%s: built", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v does not say what was wrong", tc.name, err)
		}
		if !strings.Contains(err.Error(), "sql") {
			t.Errorf("%s: %v does not name the listener", tc.name, err)
		}
	}
	// And the same section with a certificate is built.
	if _, err := newServer(nil, config.Listener{Name: "sql",
		TDS: &config.TDSListener{Upstream: "u", RequireTLS: boolp(true)}},
		nil, &tls.Config{MinVersion: tls.VersionTLS12}); err != nil {
		t.Errorf("require_tls with a certificate: %v", err)
	}
}

// What a refusal is recorded as, driven through the relay so the record is the
// one an operator reads rather than one a test built.
//
// Three things are in it that nothing else reaches: the ban observation, which
// happens before alert_on_deny can silence the record because turning the log
// down is not a decision to stop responding; the rule that decided, so the
// refusal can be argued with; and the observe rules that matched, which is
// where an operator reads what a rule being tried would have covered.
func TestARefusalIsRecordedWithItsRuleAndTheRulesBeingTried(t *testing.T) {
	up := startFake(t, &fakeServer{encryption: wire.EncryptOff})
	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: db
      address: "127.0.0.1:0"
      kind: tds
      tds:
`+base+`        allow_integrated: false
        rules:
          - {name: being-tried, action: observe, apps: ["sqlcmd*"]}
          - {name: no-sqlcmd, action: deny, apps: ["sqlcmd*"]}
bans:
  action: reject
  state_file: %s
logging: {access: {enabled: false}}
upstreams:
  - {name: sql, endpoints: [{address: %q}]}
`, filepath.Join(t.TempDir(), "bans.state"), up.addr()))
	addr := proxytest.Addr(t, s, "db")

	// An integrated login from the application the rules are about: refused,
	// and the record carries the integrated flag, the rule that decided and
	// the rule that was only being tried.
	cl := dial(t, addr, wire.EncryptOff)
	p := cl.login(t, "", "master", "sqlcmd", false, true)
	if n, ok := refusedWith(p); !ok || n != wire.LoginFailed {
		t.Fatalf("answer was %v %d", ok, n)
	}
	if types, _, _ := up.saw(); len(types) != 0 {
		t.Fatalf("the login reached the server: %v", types)
	}
	if got := s.Stats().Refusals["tds"]["integrated_not_allowed"]; got == 0 {
		t.Errorf("the refusal was not counted: %v", s.Stats().Refusals["tds"])
	}
}

// With the alerts off the counters and the ban observation still happen and
// the security event does not. An estate that has turned the record down has
// said it reads the counters; it has not said to stop refusing.
func TestWithTheAlertsOffTheRefusalIsStillCounted(t *testing.T) {
	up := startFake(t, &fakeServer{encryption: wire.EncryptOff})
	s, addr := relayFor(t, base+"        alert_on_deny: false\n        deny_users: [sa]\n", up.addr())
	cl := dial(t, addr, wire.EncryptOff)
	p := cl.login(t, "sa", "master", "sqlcmd", true, false)
	if n, ok := refusedWith(p); !ok || n != wire.LoginFailed {
		t.Fatalf("answer was %v %d", ok, n)
	}
	if got := s.Stats().Refusals["tds"]["user_not_allowed"]; got == 0 {
		t.Errorf("the refusal was not counted: %v", s.Stats().Refusals["tds"])
	}
}
