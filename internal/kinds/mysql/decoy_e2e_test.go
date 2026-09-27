package mysql

import (
	"strings"
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/mysqlwire"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// A fabricated database, through the whole relay.
//
// These are the tests that say the wiring is right rather than that the replies
// are: a honeypot listener that greets and answers with no server behind it, a
// refusal on a real listener answered by the fabrication instead, and the
// reconnaissance chain collected while the real server saw none of it.

// decoyYAML is a listener that is nothing but a fabricated server: no upstream,
// because there is nothing behind it, and no TLS requirement, because the
// fabricated greeting does not offer CLIENT_SSL.
const decoyYAML = `
version: 1
server:
  listeners:
    - name: db
      address: "127.0.0.1:0"
      kind: mysql
      mysql:
        require_tls: false
        default_action: allow
        deception:
          mode: decoy
          profile: wordpress
          version: "5.7.44-0ubuntu0.20.04.1"
logging: {access: {enabled: false}}
`

// query sends a COM_QUERY and reads the whole reply back.
func (cl *client) query(t *testing.T, text string) *reply {
	t.Helper()
	if _, err := cl.c.Write(wire.Frame(0, append([]byte{wire.ComQuery}, text...))); err != nil {
		t.Fatalf("%q: %v", text, err)
	}
	var raw []byte
	for i := 0; i < 64; i++ {
		p, err := cl.rd.Next()
		if err != nil {
			t.Fatalf("%q: %v", text, err)
		}
		raw = append(raw, wire.Frame(p.Seq, p.Payload)...)
		if done(p.Payload) {
			break
		}
	}
	// The reply was reassembled from sequence numbers the relay chose, so the
	// harness reads it from the start of its own framing.
	return readReply(t, renumber(raw, raw[3]))
}

// done says a packet ends a reply: an error, or the OK or EOF that terminates a
// result set. A column-count packet is neither, which is why the length matters.
func done(p []byte) bool {
	if len(p) == 0 {
		return false
	}
	switch p[0] {
	case wire.RespErr:
		return true
	case wire.RespOK:
		return true
	case wire.RespEOF:
		return len(p) < 9
	}
	return false
}

// A honeypot listener: it greets, it accepts the login, and there is nothing
// behind it.
func TestADecoyListenerGreetsWithNoServerBehindIt(t *testing.T) {
	s := proxytest.Start(t, decoyYAML)
	addr := proxytest.Addr(t, s, "db")

	g := offered(t, addr)
	if g.Version != "5.7.44-0ubuntu0.20.04.1" {
		t.Errorf("the greeting reports %q", g.Version)
	}
	if g.Offers(wire.CapSSL) {
		t.Error("the fabricated greeting offered TLS")
	}
	cl := dial(t, addr, "root", "", wire.CapDeprecateEOF)
	if msg := cl.ready(t); msg != "" {
		t.Fatalf("the login was refused: %s", msg)
	}
	if got := one(t, cl.query(t, "select version()")); got != "5.7.44-0ubuntu0.20.04.1" {
		t.Errorf("version() answered %q", got)
	}
	if got := one(t, cl.query(t, "select database()")); got != "wordpress" {
		t.Errorf("database() answered %q", got)
	}
	tables := cl.query(t, "show tables")
	if len(tables.rows) == 0 || tables.columns[0] != "Tables_in_wordpress" {
		t.Errorf("SHOW TABLES answered %v with %d rows", tables.columns, len(tables.rows))
	}
	names := make([]string, 0, len(tables.rows))
	for _, row := range tables.rows {
		names = append(names, *row[0])
	}
	if !hasName(names, "wp_users") {
		t.Errorf("the wordpress profile's tables are %v", names)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool { return sn.MySQLDeceived >= 4 },
		"the deception counter did not move")
	// The status view knows about it, which is where an operator looks.
	st, ok := decoyStatus(s)
	if !ok {
		t.Fatal("the listener reported no decoy")
	}
	if st.Mode != "decoy" || st.Kind != "mysql" || st.Profile != "wordpress" {
		t.Errorf("status %+v", st)
	}
	if st.Served == 0 || !st.Anyone || len(st.Visitors) != 1 {
		t.Errorf("status %+v", st)
	}
}

// The reconnaissance chain, answered, and then the escalation it was for --
// which is the message worth having.
func TestTheReconnaissanceChainIsAnsweredAndTheEscalationRecorded(t *testing.T) {
	s := proxytest.Start(t, decoyYAML)
	cl := dial(t, proxytest.Addr(t, s, "db"), "root", "", wire.CapDeprecateEOF)
	if msg := cl.ready(t); msg != "" {
		t.Fatalf("the login was refused: %s", msg)
	}
	// The questions whose answers decide what is possible.
	for _, step := range []string{
		"select @@version",
		"show databases",
		"select @@datadir",
		"select @@secure_file_priv",
		"show grants",
	} {
		if r := cl.query(t, step); r.err != nil {
			t.Errorf("%s was refused: %d %s", step, r.err.Code, r.err.Text)
		}
	}
	// And the four things they were for, each refused the way a real server
	// refuses it -- which is itself an answer, and a true one.
	for _, step := range []string{
		"select user, authentication_string from mysql.user",
		"select '<?php system($_GET[0]);' into outfile '/var/www/html/s.php'",
		"load data local infile '/etc/passwd' into table t",
		"create function sys_exec returns int soname 'udf.so'",
	} {
		if r := cl.query(t, step); r.err == nil {
			t.Errorf("%s was answered rather than refused", step)
		}
	}
	// LOAD_FILE is the one of the four that is answered rather than refused,
	// because a server whose secure_file_priv is NULL answers NULL: it is the
	// truthful answer and it agrees with what @@secure_file_priv said above. It
	// still trips the wire.
	if r := cl.query(t, "select load_file('/etc/shadow')"); r.err != nil {
		t.Errorf("LOAD_FILE was refused rather than answered NULL: %d %s", r.err.Code, r.err.Text)
	} else if len(r.rows) != 1 || r.rows[0][0] != nil {
		t.Errorf("LOAD_FILE answered %v", r.rows)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool { return sn.MySQLTripwire >= 5 },
		"the escalation chain did not trip the wire")
}

// The same fabrication on a listener that fronts a real server: it answers where
// a refusal would be written, and nowhere else.
//
// That is the invariant the whole feature rests on -- a statement on its way to a
// real database is never answered from here -- and this is the test of it.
func TestOnARealMySQLListenerOnlyRefusalsAreFabricated(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	section := base +
		"        allow_statements: [select]\n" +
		"        deception:\n" +
		"          mode: answer\n" +
		"          clients: [\"127.0.0.0/8\"]\n" +
		"          version: \"8.0.36\"\n"
	s, addr := relayFor(t, section, fake.addr())
	cl := dial(t, addr, "app", "appdb", wire.CapDeprecateEOF)
	if msg := cl.ready(t); msg != "" {
		t.Fatalf("the login was refused: %s", msg)
	}
	// An allowed statement reaches the server.
	if got := cl.send(t, wire.ComQuery, "select 1"); got != "" {
		t.Errorf("an allowed SELECT was refused: %s", got)
	}
	// A refused one is answered by the fabrication rather than refused, and does
	// not reach the server.
	r := cl.query(t, "drop table users")
	if r.err != nil {
		t.Errorf("a refused statement was refused rather than fabricated: %d %s", r.err.Code, r.err.Text)
	} else if !r.ok {
		t.Errorf("a refused statement answered a result set")
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool { return sn.MySQLDeceived >= 1 },
		"the fabrication did not answer a refused statement")
	for _, q := range fake.sawStmts() {
		if strings.Contains(strings.ToLower(q), "drop") {
			t.Errorf("a fabricated statement reached the server: %q", q)
		}
	}
	// The refusal counters still moved: the fabrication replaces what the client
	// is told, not what the operator is told.
	if n := s.Stats().Refusals["mysql"]["statement_not_allowed"]; n < 1 {
		t.Errorf("the refusal was not counted: %+v", s.Stats().Refusals["mysql"])
	}
}

// A client outside the section's list is refused rather than lied to.
func TestAMySQLClientOutsideTheListIsStillRefused(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	section := base +
		"        allow_statements: [select]\n" +
		"        deception:\n" +
		"          mode: answer\n" +
		"          clients: [\"10.9.0.0/24\"]\n" +
		"          version: \"8.0.36\"\n"
	s, addr := relayFor(t, section, fake.addr())
	cl := dial(t, addr, "app", "appdb", wire.CapDeprecateEOF)
	if msg := cl.ready(t); msg != "" {
		t.Fatalf("the login was refused: %s", msg)
	}
	if got := cl.send(t, wire.ComQuery, "drop table users"); got == "" {
		t.Error("a client outside the list was fabricated to")
	}
	if n := s.Stats().MySQLDeceived; n != 0 {
		t.Errorf("the fabrication answered %d statements for a client outside its list", n)
	}
}

// decoyStatus finds this listener's decoy in the status view.
func decoyStatus(s *proxy.Server) (proxy.DecoyStatus, bool) {
	for _, st := range s.DeviceDecoys() {
		if st.Kind == "mysql" {
			return st, true
		}
	}
	return proxy.DecoyStatus{}, false
}

// awaitCounter polls for a condition, because the relay decides on its own
// goroutines.
func awaitCounter(t *testing.T, s *proxy.Server, ok func(proxy.Snapshot) bool, what string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if ok(s.Stats()) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s: %+v", what, s.Stats().Refusals["mysql"])
}
