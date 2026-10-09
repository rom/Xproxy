package postgres

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/pgwire"
)

// Which rule covers a session, and what a rule's own lists do once one does.
//
// A rule is how this kind is usable at all: one rule for the reporting account
// that may only select, another for the migration account that may also change
// the schema, without two listeners. So the question that has to be settled is
// which rule a session gets -- every selector a rule sets has to hold, and the
// client network and the database are the two the login name does not imply.

func TestEverySelectorARuleSetsHasToHoldForTheSession(t *testing.T) {
	p := must(t, &config.PostgresListener{Upstream: "pg", DefaultAction: "allow",
		Rules: []config.PostgresRule{{Name: "jump-host", Action: "allow",
			Clients:      []string{"10.9.0.0/24"},
			Users:        []string{"analyst"},
			Databases:    []string{"sales"},
			Applications: []string{"psql*"},
			ReadOnly:     no(true)}}})
	write := wire.Statement{Kind: wire.KindDelete, Writes: true}

	inside := &Session{IP: netip.MustParseAddr("10.9.0.7"), User: "analyst",
		Database: "sales", App: "psql 16", Secure: true, At: at}
	if d := p.Statement(inside, write, "DELETE FROM t"); d.Allow ||
		d.Reason != "read_only" || d.Rule != "jump-host" {
		t.Errorf("inside every selector: %+v", d)
	}

	// One selector at a time taken away: each one on its own is enough for the
	// rule not to cover the session, and then the listener decides.
	for what, change := range map[string]func(*Session){
		"the wrong network":     func(s *Session) { s.IP = netip.MustParseAddr("192.0.2.7") },
		"no network at all":     func(s *Session) { s.IP = netip.Addr{} },
		"the wrong login":       func(s *Session) { s.User = "someone" },
		"the wrong database":    func(s *Session) { s.Database = "payroll" },
		"the wrong application": func(s *Session) { s.App = "pgAdmin" },
	} {
		se := *inside
		change(&se)
		if d := p.Statement(&se, write, "DELETE FROM t"); !d.Allow || d.Rule != "" {
			t.Errorf("%s was covered anyway: %+v", what, d)
		}
	}
}

// A rule that refuses and a rule whose window has closed are both reached on
// every statement rather than only at the connection: a session outlives its
// own login, so a change window that ended at five has to stop the statement
// sent at five past.
func TestARuleThatRefusesIsReachedOnEveryStatement(t *testing.T) {
	p := must(t, &config.PostgresListener{Upstream: "pg", DefaultAction: "allow",
		Rules: []config.PostgresRule{
			{Name: "quarantine", Users: []string{"temp"}, Action: "deny"},
			{Name: "window", Users: []string{"migrate"}, Action: "allow",
				Schedule: &config.ModbusSchedule{From: "02:00", To: "05:00"}},
		}})
	read := wire.Statement{Kind: wire.KindSelect}

	if d := p.Statement(sess("temp", "sales"), read, "SELECT 1"); d.Allow ||
		d.Reason != "rule_denied" || d.Rule != "quarantine" {
		t.Errorf("a rule that refuses: %+v", d)
	}

	night := &Session{IP: netip.MustParseAddr("10.0.0.5"), User: "migrate",
		Database: "sales", Secure: true,
		At: time.Date(2026, 3, 4, 3, 0, 0, 0, time.UTC)}
	if d := p.Statement(night, read, "SELECT 1"); !d.Allow || d.Rule != "window" {
		t.Errorf("inside the window: %+v", d)
	}
	noon := *night
	noon.At = time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)
	if d := p.Statement(&noon, read, "SELECT 1"); d.Allow ||
		d.Reason != "outside_schedule" || d.Rule != "window" {
		t.Errorf("outside it: %+v", d)
	}
}

// The listener's own positive list is an allow in its own right: an estate
// that listed the statements it permits has said what it permits, and making
// that depend on default_action as well would mean writing the same thing
// twice. What the list does not name is refused whatever the default is.
func TestTheListenersPositiveListDecidesOnItsOwn(t *testing.T) {
	p := must(t, &config.PostgresListener{Upstream: "pg",
		AllowStatements: []string{"select", "insert"}})
	se := sess("app", "sales")
	if d := p.Statement(se, wire.Statement{Kind: wire.KindSelect}, "SELECT 1"); !d.Allow {
		t.Errorf("a statement the list names, with no default_action: %+v", d)
	}
	if d := p.Statement(se, wire.Statement{Kind: wire.KindDelete, Writes: true},
		"DELETE FROM t"); d.Allow || d.Reason != "statement_not_allowed" {
		t.Errorf("a statement the list does not name: %+v", d)
	}
}

// COPY is three operations wearing one keyword, and a rule's allow_copy
// replaces the listener's for the traffic it covers. `program` is never
// allowed by any of them: it is the one statement in this protocol that is
// unambiguously remote code execution.
func TestARulesCopyListReplacesTheListenersAndProgramIsNeverInIt(t *testing.T) {
	p := must(t, &config.PostgresListener{Upstream: "pg", DefaultAction: "allow",
		AllowCopy: []string{"in"},
		Rules: []config.PostgresRule{{Name: "loader", Users: []string{"etl"},
			Action: "allow", AllowCopy: []string{"in", "out", "file"}}}})

	etl, app := sess("etl", "sales"), sess("app", "sales")
	for _, tc := range []struct {
		se     *Session
		target wire.CopyTarget
		allow  bool
	}{
		{etl, wire.CopyIn, true},
		{etl, wire.CopyOut, true},
		{etl, wire.CopyFile, true},
		{app, wire.CopyIn, true},
		{app, wire.CopyOut, false},
		{app, wire.CopyFile, false},
	} {
		st := wire.Statement{Kind: wire.KindCopy, Copy: tc.target, Writes: true}
		d := p.Statement(tc.se, st, "COPY t ...")
		if d.Allow != tc.allow {
			t.Errorf("%s copy %s: allow=%v (%+v)", tc.se.User, tc.target, d.Allow, d)
		}
	}
	for _, se := range []*Session{etl, app} {
		st := wire.Statement{Kind: wire.KindCopy, Copy: wire.CopyProgram, Writes: true}
		if d := p.Statement(se, st, "COPY t FROM PROGRAM 'sh'"); d.Allow || !d.Hard {
			t.Errorf("%s: COPY FROM PROGRAM: %+v", se.User, d)
		}
	}
}

// A cancel request carries no identity at all -- a process identifier and a
// 32-bit secret the relay cannot check -- so the only questions are whether
// the address is an admitted client and whether this estate lets one session
// cancel another's query.
func TestACancelIsDecidedByTheAddressAndTheSwitch(t *testing.T) {
	open := must(t, &config.PostgresListener{Upstream: "pg", DefaultAction: "allow",
		AllowClients: []string{"10.0.0.0/8"}})
	from := func(s string) *Session {
		return &Session{IP: netip.MustParseAddr(s), At: at}
	}
	if d := open.Cancel(from("10.0.0.5")); !d.Allow {
		t.Errorf("a cancel from an admitted client: %+v", d)
	}
	if d := open.Cancel(from("192.0.2.5")); d.Allow || !d.Hard ||
		d.Reason != "client_not_allowed" {
		t.Errorf("a cancel from elsewhere: %+v", d)
	}
	shut := must(t, &config.PostgresListener{Upstream: "pg", DefaultAction: "allow",
		AllowCancel: no(false)})
	if d := shut.Cancel(from("10.0.0.5")); d.Allow || d.Reason != "cancel_not_allowed" {
		t.Errorf("a cancel on a listener that refuses them: %+v", d)
	}
	// And a session with no address is in no network, so a listener with a
	// client list does not admit one.
	if d := open.Cancel(&Session{At: at}); d.Allow {
		t.Errorf("a cancel with no address: %+v", d)
	}
}

// The lists are compiled when the listener is built, in a rule as well as at
// the top of the section: a statement kind no edition knows is a rule that
// matches nothing, so the traffic it was written about would be decided by
// whatever is underneath it.
func TestARulesListsAreCompiledTheSameAsTheListeners(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		l          config.PostgresListener
	}{
		{"the listener's client deny list", "deny_clients",
			config.PostgresListener{Upstream: "pg", DenyClients: []string{"10.0.0.1"}}},
		{"a rule's statement deny list", "rules[0].deny_statements",
			config.PostgresListener{Upstream: "pg", Rules: []config.PostgresRule{
				{Name: "r", DenyStatements: []string{"selekt"}}}}},
		{"a rule's schedule", "rules[0].schedule",
			config.PostgresListener{Upstream: "pg", Rules: []config.PostgresRule{
				{Name: "r", Schedule: &config.ModbusSchedule{Days: []string{"someday"}}}}}},
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

// A listener with no deception section has no fabrication, and every call a
// session makes on it has to answer that way rather than reaching into one
// that is not there. The methods are called on the ordinary path of every
// connection, so the nil case is the common case on a real listener.
func TestAListenerWithNoFabricationAnswersSoEverywhere(t *testing.T) {
	var none *decoy
	if none.admits(netip.MustParseAddr("10.0.0.5")) {
		t.Error("a listener with no fabrication admitted a client to it")
	}
	if none.tripped("COPY t FROM '/etc/passwd'") {
		t.Error("a listener with no fabrication tripped a wire it does not have")
	}
	if st, ok := (&server{}).DecoyStatus(); ok {
		t.Errorf("a listener with no fabrication reported a status: %+v", st)
	}
}
