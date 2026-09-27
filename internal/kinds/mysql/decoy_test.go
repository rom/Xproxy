package mysql

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/mysqlwire"
)

// A database that is not there.
//
// What is worth asserting about a fabrication is not that it answers but that it
// answers what a real server answers, because the shape of a reply is what a
// client library reads and what a fingerprinting tool checks. So most of what
// follows reads the reply back apart: the column headings, the values, the error
// numbers.

func decoyFor(t *testing.T, c *config.MySQLDeception) *decoy {
	t.Helper()
	d, err := newDecoy(c, "db")
	if err != nil {
		t.Fatalf("newDecoy: %v", err)
	}
	if d == nil {
		t.Fatal("newDecoy built nothing")
	}
	at := time.Date(2025, 3, 5, 14, 0, 0, 0, time.UTC)
	d.now = func() time.Time { return at }
	d.started = at.Add(-72 * time.Hour)
	d.values.SetClockForTest(func() time.Time { return at })
	return d
}

// ask runs one query against the fabrication and reads the reply back.
func ask(t *testing.T, d *decoy, text string) *reply {
	t.Helper()
	raw, ok := d.answer(wire.ComQuery, []byte(text), &decoySession{deprecateEOF: true})
	if !ok {
		t.Fatalf("%q: the fabrication had no answer", text)
	}
	return readReply(t, raw)
}

// reply is a parsed server reply: an error, an OK, or a result set.
type reply struct {
	err     *wire.ErrorPacket
	ok      bool
	columns []string
	rows    [][]*string
}

// readReply parses a whole reply out of a stream of wire packets, which is a
// second implementation of the framing rather than a reuse of the one under test.
func readReply(t *testing.T, raw []byte) *reply {
	t.Helper()
	packets := split(t, raw)
	if len(packets) == 0 {
		t.Fatal("no packets")
	}
	first := packets[0]
	switch {
	case first[0] == wire.RespErr:
		e, err := wire.ReadError(first, wire.CapProtocol41)
		if err != nil {
			t.Fatalf("an error packet does not parse: %v", err)
		}
		return &reply{err: e}
	case first[0] == wire.RespOK:
		return &reply{ok: true}
	case first[0] == wire.RespEOF && len(first) < 9:
		return &reply{ok: true}
	}
	n, _, err := lenEnc(first)
	if err != nil {
		t.Fatalf("the column count does not parse: %v", err)
	}
	r := &reply{}
	if int(n) >= len(packets) {
		t.Fatalf("a result set declares %d columns and has %d packets", n, len(packets))
	}
	for i := 1; i <= int(n); i++ {
		p := packets[i]
		// The fifth length-encoded string of a column definition is its name.
		for j := 0; j < 4; j++ {
			_, p = lenEncStr(t, p)
		}
		name, _ := lenEncStr(t, p)
		r.columns = append(r.columns, name)
	}
	rest := packets[1+int(n):]
	// Without CLIENT_DEPRECATE_EOF an EOF packet closes the column block before
	// the rows begin. Treating it as the end of the set is how a reader that had
	// not negotiated the shape it asked for would read no rows at all -- which is
	// exactly the failure the shape test is about, so the harness has to get it
	// right to be able to test for it.
	if len(rest) > 0 && len(rest[0]) > 0 && rest[0][0] == wire.RespEOF && len(rest[0]) < 9 {
		rest = rest[1:]
	}
	for _, p := range rest {
		if len(p) > 0 && (p[0] == wire.RespOK || p[0] == wire.RespEOF && len(p) < 9) {
			break
		}
		var row []*string
		rest := p
		for i := 0; i < int(n); i++ {
			if len(rest) > 0 && rest[0] == 0xFB {
				row = append(row, nil)
				rest = rest[1:]
				continue
			}
			v, next := lenEncStr(t, rest)
			row = append(row, wire.Str(v))
			rest = next
		}
		r.rows = append(r.rows, row)
	}
	return r
}

// split reads a stream of wire packets and returns their payloads.
func split(t *testing.T, raw []byte) [][]byte {
	t.Helper()
	var out [][]byte
	seq := -1
	for len(raw) > 0 {
		if len(raw) < 4 {
			t.Fatalf("%d octets left, which is less than a header", len(raw))
		}
		n := int(raw[0]) | int(raw[1])<<8 | int(raw[2])<<16
		if len(raw) < 4+n {
			t.Fatalf("a packet declares %d octets and %d are left", n, len(raw)-4)
		}
		// The numbering is contiguous, because a client library checks it and a
		// gap makes it report a protocol error rather than the rows. It is one
		// octet and wraps, which a long result set does: 255 is followed by 0.
		if seq >= 0 && int(raw[3]) != (seq+1)%256 {
			t.Fatalf("a packet is numbered %d after %d", raw[3], seq)
		}
		seq = int(raw[3])
		out = append(out, raw[4:4+n])
		raw = raw[4+n:]
	}
	return out
}

func lenEnc(b []byte) (uint64, []byte, error) {
	if len(b) == 0 {
		return 0, nil, errShort
	}
	switch c := b[0]; {
	case c < 251:
		return uint64(c), b[1:], nil
	case c == 0xFC && len(b) >= 3:
		return uint64(b[1]) | uint64(b[2])<<8, b[3:], nil
	case c == 0xFD && len(b) >= 4:
		return uint64(b[1]) | uint64(b[2])<<8 | uint64(b[3])<<16, b[4:], nil
	case c == 0xFE && len(b) >= 9:
		var v uint64
		for i := 8; i >= 1; i-- {
			v = v<<8 | uint64(b[i])
		}
		return v, b[9:], nil
	}
	return 0, nil, errShort
}

type shortErr string

func (e shortErr) Error() string { return string(e) }

const errShort = shortErr("a length-encoded field runs off the end")

func lenEncStr(t *testing.T, b []byte) (string, []byte) {
	t.Helper()
	n, rest, err := lenEnc(b)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if uint64(len(rest)) < n {
		t.Fatalf("a string declares %d octets and %d are left", n, len(rest))
	}
	return string(rest[:n]), rest[n:]
}

// one reads the single value of a one-column, one-row reply.
func one(t *testing.T, r *reply) string {
	t.Helper()
	if r.err != nil {
		t.Fatalf("an error reply: %d %s", r.err.Code, r.err.Text)
	}
	if len(r.rows) != 1 || len(r.rows[0]) != 1 {
		t.Fatalf("%d rows", len(r.rows))
	}
	if r.rows[0][0] == nil {
		t.Fatal("the value is NULL")
	}
	return *r.rows[0][0]
}

// The greeting, which is the only packet a server sends unprompted and the one
// every scanner reads.
func TestTheGreetingIsOneAClientCanNegotiateWith(t *testing.T) {
	d := decoyFor(t, &config.MySQLDeception{Mode: "decoy", Version: "8.0.35"})
	packets := split(t, d.greeting(4242))
	if len(packets) != 1 {
		t.Fatalf("%d packets", len(packets))
	}
	g, err := wire.ParseGreeting(packets[0])
	if err != nil {
		t.Fatalf("the greeting does not parse: %v", err)
	}
	if g.Version != "8.0.35" {
		t.Errorf("version %q", g.Version)
	}
	if !g.Offers(wire.CapProtocol41) || !g.Offers(wire.CapSecureConnection) {
		t.Errorf("caps %08x: every client library written this century needs both", g.Caps)
	}
	// CLIENT_SSL is deliberately not offered: the negotiation is mid-handshake on
	// this protocol, and a server that offered it and could not complete it fails
	// in a way a scanner notices.
	if g.Offers(wire.CapSSL) {
		t.Error("the greeting offered TLS, which the fabrication cannot complete")
	}
	// The challenge is twenty printable octets with no NUL, because a NUL would
	// truncate the field it sits in and a control character is a tell.
	salt := d.salt(4242)
	if len(salt) != 20 {
		t.Fatalf("the challenge is %d octets", len(salt))
	}
	for i, c := range salt {
		if c < 33 || c > 126 {
			t.Errorf("octet %d of the challenge is %02x", i, c)
		}
	}
	// Two connections get different challenges, because a server that reused one
	// would be one whose scramble is a constant.
	if string(d.salt(4242)) == string(d.salt(4243)) {
		t.Error("two connections were given the same challenge")
	}
	// MariaDB has never shipped caching_sha2_password, so a MariaDB version
	// offering it is a contradiction a fingerprinting tool checks.
	maria := decoyFor(t, &config.MySQLDeception{Mode: "decoy", Profile: "mariadb"})
	mg, err := wire.ParseGreeting(split(t, maria.greeting(1))[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(mg.Version, "MariaDB") {
		t.Errorf("the mariadb profile reports %q", mg.Version)
	}
	if mg.Plugin == "caching_sha2_password" {
		t.Error("a MariaDB greeting offered a plugin MariaDB has never shipped")
	}
}

// The reconnaissance: the statements whose answers decide what a visitor tries
// next.
func TestTheReconnaissanceStatementsAreAnswered(t *testing.T) {
	d := decoyFor(t, &config.MySQLDeception{Mode: "decoy", Version: "8.0.36", Profile: "generic-mysql"})
	for _, tc := range []struct{ query, want string }{
		{"select 1", "1"},
		{"SELECT VERSION()", "8.0.36"},
		{"select @@version", "8.0.36"},
		{"SELECT @@global.version", "8.0.36"},
		{"select @@datadir", "/var/lib/mysql/"},
		{"SELECT @@basedir", "/usr/"},
		{"select database()", "appdb"},
		{"SELECT USER()", "app@localhost"},
		{"select current_user()", "app@localhost"},
		{"SELECT @@hostname", "db01"},
		{"select @@port", "3306"},
	} {
		if got := one(t, ask(t, d, tc.query)); got != tc.want {
			t.Errorf("%s -> %q, want %q", tc.query, got, tc.want)
		}
	}
	// secure_file_priv is NULL rather than empty, which is the value that says
	// "no file statements at all" -- and is consistent with the refusals the
	// file statements get below. An empty string would say the opposite.
	r := ask(t, d, "select @@secure_file_priv")
	if r.err != nil {
		t.Fatalf("%d %s", r.err.Code, r.err.Text)
	}
	if len(r.rows) != 1 || r.rows[0][0] != nil {
		t.Errorf("secure_file_priv answered %v", r.rows)
	}
	// SHOW DATABASES is the first thing asked after the version.
	dbs := ask(t, d, "show databases")
	if len(dbs.columns) != 1 || dbs.columns[0] != "Database" {
		t.Errorf("SHOW DATABASES columns %v", dbs.columns)
	}
	names := make([]string, 0, len(dbs.rows))
	for _, row := range dbs.rows {
		names = append(names, *row[0])
	}
	for _, want := range []string{"appdb", "information_schema", "mysql", "performance_schema"} {
		if !hasName(names, want) {
			t.Errorf("SHOW DATABASES has no %q: %v", want, names)
		}
	}
	// Sorted, so two reads list them in the same order: a catalogue that changed
	// between two statements would be a server that had been reconfigured.
	for i := 1; i < len(names); i++ {
		if names[i-1] >= names[i] {
			t.Errorf("SHOW DATABASES is not sorted: %v", names)
			break
		}
	}
	// SHOW TABLES answers per database, and the column heading carries the name
	// -- which is a detail a tool reads.
	tables := ask(t, d, "show tables")
	if len(tables.columns) != 1 || tables.columns[0] != "Tables_in_appdb" {
		t.Errorf("SHOW TABLES columns %v", tables.columns)
	}
	if len(tables.rows) == 0 {
		t.Error("SHOW TABLES answered no rows")
	}
	// And from another database, which is how a visitor walks the catalogue.
	if got := ask(t, d, "show tables from mysql"); len(got.rows) != 0 {
		t.Errorf("SHOW TABLES FROM mysql answered %d rows", len(got.rows))
	}
	// SHOW GRANTS says what this account may do, which is the question before
	// every file statement.
	grants := one(t, ask(t, d, "show grants"))
	if !strings.Contains(grants, "GRANT SELECT") || strings.Contains(grants, "FILE") {
		t.Errorf("SHOW GRANTS answered %q", grants)
	}
}

// SHOW VARIABLES, with and without a pattern. The pattern is SQL LIKE and not a
// glob: * and ? are literals here, and a matcher that treated them as wildcards
// would list variables the pattern did not ask for.
func TestShowVariablesUsesSQLLikeAndNotAGlob(t *testing.T) {
	d := decoyFor(t, &config.MySQLDeception{Mode: "decoy", Version: "8.0.36"})
	all := ask(t, d, "show variables")
	if len(all.columns) != 2 || all.columns[0] != "Variable_name" || all.columns[1] != "Value" {
		t.Fatalf("columns %v", all.columns)
	}
	if len(all.rows) < 15 {
		t.Errorf("SHOW VARIABLES answered %d rows", len(all.rows))
	}
	// Every value is a string, never NULL: this statement's result set has no
	// NULLs in it, which is a difference from the @@ select and one a tool
	// notices.
	for _, row := range all.rows {
		if row[1] == nil {
			t.Errorf("%s answered NULL", *row[0])
		}
	}
	filtered := ask(t, d, "show variables like 'version%'")
	if len(filtered.rows) == 0 {
		t.Fatal("a LIKE pattern matched nothing")
	}
	for _, row := range filtered.rows {
		if !strings.HasPrefix(*row[0], "version") {
			t.Errorf("version%% matched %q", *row[0])
		}
	}
	// A pattern with no wildcard at all matches the whole name and nothing else:
	// LIKE 'version' is not LIKE 'version%', so it must not also return
	// version_comment and its neighbours.
	exact := ask(t, d, "show variables like 'version'")
	if len(exact.rows) != 1 || *exact.rows[0][0] != "version" {
		t.Errorf("LIKE 'version' matched %d rows: %v", len(exact.rows), rowNames(exact))
	}
	if one := ask(t, d, "show variables like 'datadir'"); len(one.rows) != 1 {
		t.Errorf("LIKE 'datadir' matched %d rows: %v", len(one.rows), rowNames(one))
	}
	// A single-character wildcard, and a literal star.
	for _, tc := range []struct {
		pattern string
		want    bool
	}{
		{"datadi_", true},
		{"datadi?", false},
		{"*", false},
		{"%dir", true},
	} {
		got := ask(t, d, "show variables like '"+tc.pattern+"'")
		if (len(got.rows) > 0) != tc.want {
			t.Errorf("LIKE %q matched %d rows, want any=%v", tc.pattern, len(got.rows), tc.want)
		}
	}
}

// The four things the reconnaissance is *for*, and what each gets.
func TestTheEscalationStatementsAreRefusedTheWayARealServerRefusesThem(t *testing.T) {
	d := decoyFor(t, &config.MySQLDeception{Mode: "decoy", Version: "8.0.36"})
	for _, tc := range []struct {
		what  string
		query string
		code  uint16
	}{
		// The one that asks the *client* for a file. It is never answered with
		// the request packet the protocol allows: that would be attacking
		// whoever connected, and the clients that connect to a honeypot include
		// the estate's own scanners.
		{"LOAD DATA LOCAL INFILE", "load data local infile '/etc/passwd' into table t", 1148},
		{"INTO OUTFILE", "select 1 into outfile '/var/www/html/s.php'", 1290},
		{"INTO DUMPFILE", "select 1 into dumpfile '/tmp/x'", 1290},
		{"CREATE FUNCTION ... SONAME", "create function sys_exec returns int soname 'udf.so'", 1126},
		// The credential dump, which a real server answers 1142 rather than with
		// an empty set: an empty set would say the table is there and has no
		// rows, which mysql.user never is.
		{"a read of mysql.user", "select user, authentication_string from mysql.user", wire.StatementDenied},
		{"a read of the privilege views", "select * from information_schema.user_privileges", wire.StatementDenied},
	} {
		r := ask(t, d, tc.query)
		if r.err == nil {
			t.Errorf("%s was answered rather than refused", tc.what)
			continue
		}
		if r.err.Code != tc.code {
			t.Errorf("%s answered %d, want %d (%s)", tc.what, r.err.Code, tc.code, r.err.Text)
		}
	}
	// And every one of them trips the wire without being configured.
	for _, q := range []string{
		"load data local infile '/etc/passwd' into table t",
		"select 1 into outfile '/var/www/html/s.php'",
		"create function sys_exec returns int soname 'udf.so'",
		"select * from mysql.user",
		"select load_file('/etc/shadow')",
		"select @@secure_file_priv",
		"select sleep(60)",
		"select benchmark(1000000, md5('a'))",
	} {
		if !d.tripped(q) {
			t.Errorf("%q did not trip", q)
		}
	}
	// The ordinary traffic does not, or every visitor would look like an attack.
	for _, q := range []string{
		"select 1", "select id, name from users where id = 7", "show databases",
		"select @@version", "insert into orders (total) values (12)", "commit",
		// The words that contain a tripwire and are not one: the test is per
		// identifier, so a column named "sleepy" is not SLEEP.
		"select sleepy from patients", "select outfiles from jobs",
	} {
		if d.tripped(q) {
			t.Errorf("%q tripped", q)
		}
	}
}

// SLEEP and BENCHMARK are answered rather than honoured. Waiting would make this
// listener's resources something a visitor can hold, a statement at a time, for
// as long as they like -- which is a denial of service the honeypot performs on
// itself.
func TestTheFabricationDoesNotSleep(t *testing.T) {
	d := decoyFor(t, &config.MySQLDeception{Mode: "decoy"})
	start := time.Now()
	if got := one(t, ask(t, d, "select sleep(60)")); got != "0" {
		t.Errorf("SLEEP(60) answered %q", got)
	}
	if got := one(t, ask(t, d, "SELECT BENCHMARK(100000000, MD5('a'))")); got != "0" {
		t.Errorf("BENCHMARK answered %q", got)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("the two statements took %s", elapsed)
	}
}

// What an unrecognised statement gets, by shape.
func TestAnUnrecognisedStatementIsAnsweredByItsShape(t *testing.T) {
	d := decoyFor(t, &config.MySQLDeception{Mode: "decoy"})
	// A SELECT the recognisers do not know: an empty result set, which is the
	// honest answer. The fabrication is a surface rather than a database, and
	// inventing rows for an arbitrary projection would mean inventing a schema
	// to match.
	sel := ask(t, d, "select total, created_at from orders where id = 91")
	if sel.err != nil {
		t.Errorf("a SELECT was refused: %d %s", sel.err.Code, sel.err.Text)
	}
	if len(sel.columns) != 1 || len(sel.rows) != 0 {
		t.Errorf("a SELECT answered %d columns and %d rows", len(sel.columns), len(sel.rows))
	}
	// A write, DDL or transaction statement: accepted, and nothing happens. The
	// reply is what makes the visitor go on to the statement that says what they
	// were doing.
	for _, q := range []string{
		"insert into users (name) values ('x')",
		"update users set name = 'x' where id = 1",
		"delete from users where id = 1",
		"create table t (a int)",
		"drop table users",
		"grant all on *.* to 'x'@'%'",
		"begin", "commit", "set names utf8mb4",
	} {
		if r := ask(t, d, q); !r.ok {
			if r.err != nil {
				t.Errorf("%q was refused: %d %s", q, r.err.Code, r.err.Text)
			} else {
				t.Errorf("%q answered a result set", q)
			}
		}
	}
	// A statement that cannot be lexed -- an unterminated quote -- is the syntax
	// error a real server gives, and not an empty set.
	if r := ask(t, d, "select * from t where a = 'unterminated"); r.err == nil || r.err.Code != 1064 {
		t.Errorf("an unterminated quote answered %+v", r)
	}
}

// The commands beside COM_QUERY.
func TestTheOtherCommandsAnswerAsAServerDoes(t *testing.T) {
	d := decoyFor(t, &config.MySQLDeception{Mode: "decoy"})
	ds := &decoySession{deprecateEOF: true}
	// COM_PING, which a connection pool sends constantly.
	if raw, ok := d.answer(wire.ComPing, nil, ds); !ok || !readReply(t, raw).ok {
		t.Error("COM_PING was not answered with an OK")
	}
	// COM_INIT_DB selects a database that exists and refuses one that does not,
	// which is the answer that tells a visitor the catalogue is real.
	if raw, _ := d.answer(wire.ComInitDB, []byte("appdb"), ds); !readReply(t, raw).ok {
		t.Error("COM_INIT_DB of an existing database was refused")
	}
	if ds.database != "appdb" {
		t.Errorf("COM_INIT_DB left the session in %q", ds.database)
	}
	raw, _ := d.answer(wire.ComInitDB, []byte("nosuchdb"), ds)
	if r := readReply(t, raw); r.err == nil || r.err.Code != 1049 {
		t.Errorf("COM_INIT_DB of a database nobody has answered %+v", r)
	}
	// COM_STATISTICS is the one reply in the protocol that is neither a result
	// set nor an OK: a single line of text.
	raw, _ = d.answer(wire.ComStatistics, nil, ds)
	line := string(split(t, raw)[0])
	for _, want := range []string{"Uptime:", "Threads:", "Questions:", "Queries per second avg:"} {
		if !strings.Contains(line, want) {
			t.Errorf("COM_STATISTICS has no %q: %q", want, line)
		}
	}
	// COM_QUIT has no reply: the real server closes.
	if raw, ok := d.answer(wire.ComQuit, nil, ds); !ok || len(raw) != 0 {
		t.Errorf("COM_QUIT answered %d octets", len(raw))
	}
	// A prepared statement is not pretended: answering the prepare would mean
	// keeping the handle and answering the execute.
	raw, _ = d.answer(wire.ComStmtPrepare, []byte("select 1"), ds)
	if r := readReply(t, raw); r.err == nil {
		t.Error("COM_STMT_PREPARE was answered")
	}
}

// The counters that must only rise. A questions counter that went backwards
// between two COM_STATISTICS is the tell that ends the pretence, so it is derived
// from the elapsed time rather than sampled.
func TestTheStatisticsOnlyRise(t *testing.T) {
	d := decoyFor(t, &config.MySQLDeception{Mode: "decoy"})
	at := time.Date(2025, 3, 5, 14, 0, 0, 0, time.UTC)
	d.started = at
	prev := -1
	for i := 0; i < 30; i++ {
		now := at.Add(time.Duration(i) * 41 * time.Second)
		d.now = func() time.Time { return now }
		d.values.SetClockForTest(func() time.Time { return now })
		line := d.statistics()
		q := fieldOf(t, line, "Questions:")
		if q < prev {
			t.Fatalf("the questions count went from %d to %d", prev, q)
		}
		prev = q
	}
	if prev <= 1000 {
		t.Errorf("the questions count never moved: %d", prev)
	}
	// A clock that goes backwards -- a virtual machine resumed from a snapshot,
	// an NTP step -- must not show through as a negative uptime.
	d.now = func() time.Time { return at.Add(-time.Hour) }
	if got := d.statistics(); strings.Contains(got, "-") {
		t.Errorf("a clock that went backwards produced %q", got)
	}
}

// fieldOf reads a number out of the COM_STATISTICS line.
func fieldOf(t *testing.T, line, label string) int {
	t.Helper()
	at := strings.Index(line, label)
	if at < 0 {
		t.Fatalf("%q has no %q", line, label)
	}
	fields := strings.Fields(line[at+len(label):])
	if len(fields) == 0 {
		t.Fatalf("%q has no value after %q", line, label)
	}
	n := 0
	for i := 0; i < len(fields[0]); i++ {
		c := fields[0][i]
		if c < '0' || c > '9' {
			t.Fatalf("%q is not a number", fields[0])
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// The result set's shape follows what the client negotiated.
// CLIENT_DEPRECATE_EOF replaces both EOF packets, and a client that asked for the
// new shape and received the old one stops reading where it expected more.
func TestTheResultSetShapeFollowsTheNegotiation(t *testing.T) {
	d := decoyFor(t, &config.MySQLDeception{Mode: "decoy"})
	for _, eof := range []bool{false, true} {
		raw, ok := d.answer(wire.ComQuery, []byte("select 1"), &decoySession{deprecateEOF: eof})
		if !ok {
			t.Fatal("no answer")
		}
		packets := split(t, raw)
		last := packets[len(packets)-1]
		if eof && last[0] != wire.RespOK {
			t.Errorf("with CLIENT_DEPRECATE_EOF the set ends %02x, want OK", last[0])
		}
		if !eof && last[0] != wire.RespEOF {
			t.Errorf("without CLIENT_DEPRECATE_EOF the set ends %02x, want EOF", last[0])
		}
		// Either way the value is the same, because the shape is the framing and
		// not the answer.
		if got := one(t, readReply(t, raw)); got != "1" {
			t.Errorf("deprecate=%v: %q", eof, got)
		}
	}
}

// The catalogue an operator configures, which is the part a visitor reads most
// closely.
func TestTheConfiguredCatalogueReplacesTheProfiles(t *testing.T) {
	d := decoyFor(t, &config.MySQLDeception{
		Mode: "decoy", Version: "8.0.36",
		Databases: []string{"information_schema", "mysql", "crm"},
		Tables:    []string{"crm.contacts", "crm.deals", "crm.notes"},
	})
	rows := ask(t, d, "show databases").rows
	names := make([]string, 0, len(rows))
	for _, row := range rows {
		names = append(names, *row[0])
	}
	if len(names) != 3 || !hasName(names, "crm") {
		t.Errorf("SHOW DATABASES answered %v", names)
	}
	// The application database is the first that is not a system schema, which is
	// what database() reports and what SHOW TABLES defaults to.
	if got := one(t, ask(t, d, "select database()")); got != "crm" {
		t.Errorf("database() answered %q", got)
	}
	tables := ask(t, d, "show tables")
	if tables.columns[0] != "Tables_in_crm" || len(tables.rows) != 3 {
		t.Errorf("SHOW TABLES answered %v with %d rows", tables.columns, len(tables.rows))
	}
}

// What the section refuses to compile.
func TestTheMySQLDeceptionSectionRefusesWhatCannotWork(t *testing.T) {
	for _, tc := range []struct {
		what  string
		c     *config.MySQLDeception
		wants string
	}{
		{"a profile that does not exist",
			&config.MySQLDeception{Mode: "decoy", Profile: "oracle"}, "is not a profile"},
		{"a tripwire with a space in it",
			&config.MySQLDeception{Mode: "decoy", Tripwire: []string{"mysql user"}}, "not an object name"},
		{"an empty tripwire",
			&config.MySQLDeception{Mode: "decoy", Tripwire: []string{""}}, "not an object name"},
		{"a client list that is not one",
			&config.MySQLDeception{Mode: "decoy", Clients: []string{"10.0.0.1"}}, "clients"},
	} {
		if _, err := newDecoy(tc.c, "db"); err == nil {
			t.Errorf("%s: compiled", tc.what)
		} else if !strings.Contains(err.Error(), tc.wants) {
			t.Errorf("%s: %v, want %q", tc.what, err, tc.wants)
		}
	}
	if d, err := newDecoy(nil, "db"); d != nil || err != nil {
		t.Errorf("an absent section built %v, %v", d, err)
	}
	off := false
	if d, err := newDecoy(&config.MySQLDeception{Mode: "decoy", Enabled: &off}, "db"); d != nil || err != nil {
		t.Errorf("a disabled section built %v, %v", d, err)
	}
	// A configured tripwire adds to the built-in set rather than replacing it.
	more, err := newDecoy(&config.MySQLDeception{Mode: "decoy", Tripwire: []string{"appdb.salaries"}}, "db")
	if err != nil {
		t.Fatal(err)
	}
	if !more.tripped("select * from appdb.salaries") {
		t.Error("a configured tripwire did not trip")
	}
	if !more.tripped("select * from mysql.user") {
		t.Error("configuring one tripwire removed the built-in ones")
	}
}

// The client list, which is what keeps a fabrication off the traffic it was not
// meant for.
func TestOnlyTheNamedClientsAreLiedToByTheDatabase(t *testing.T) {
	d := decoyFor(t, &config.MySQLDeception{Mode: "answer", Clients: []string{"10.9.0.0/24"}})
	if !d.admits(netip.MustParseAddr("10.9.0.5")) {
		t.Error("a client inside the list was not admitted")
	}
	if d.admits(netip.MustParseAddr("10.8.0.5")) {
		t.Error("a client outside the list was admitted")
	}
	var none *decoy
	if none.admits(netip.MustParseAddr("10.9.0.5")) {
		t.Error("a listener with no section admitted a client")
	}
	if none.tripped("select * from mysql.user") {
		t.Error("a listener with no section tripped")
	}
	if _, ok := none.answer(wire.ComPing, nil, &decoySession{}); ok {
		t.Error("a listener with no section answered")
	}
}

// The renumbering, which is what lets a reply built at sequence 1 continue a
// client's own count. A client library checks the numbering, and a gap makes it
// report a protocol error rather than the rows.
func TestARenumberedReplyContinuesTheClientsCount(t *testing.T) {
	d := decoyFor(t, &config.MySQLDeception{Mode: "decoy"})
	raw, _ := d.answer(wire.ComQuery, []byte("show variables"), &decoySession{})
	for _, first := range []byte{1, 4, 250, 255} {
		moved := renumber(raw, first)
		if len(moved) != len(raw) {
			t.Fatalf("renumbering changed the length from %d to %d", len(raw), len(moved))
		}
		at, want := 0, first
		for at+4 <= len(moved) {
			if moved[at+3] != want {
				t.Fatalf("from %d: a packet is numbered %d, want %d", first, moved[at+3], want)
			}
			n := int(moved[at]) | int(moved[at+1])<<8 | int(moved[at+2])<<16
			at += 4 + n
			want++
		}
		// The sequence is one octet and wraps, which is what the protocol does:
		// a long result set passes 255 and carries on at zero.
		if first == 255 && len(split(t, moved)) == 0 {
			t.Error("a reply renumbered from 255 did not read back")
		}
	}
	// And the payloads are untouched: only the fourth octet of each header moves.
	before, after := readReply(t, raw), readReply(t, renumber(raw, 9))
	if len(before.rows) == 0 || len(before.rows) != len(after.rows) {
		t.Fatalf("renumbering changed %d rows to %d", len(before.rows), len(after.rows))
	}
	for i := range before.rows {
		for j := range before.rows[i] {
			a, b := before.rows[i][j], after.rows[i][j]
			if (a == nil) != (b == nil) || (a != nil && *a != *b) {
				t.Fatalf("renumbering changed row %d column %d", i, j)
			}
		}
	}
}

// hasName says whether a list holds a name, which is what several of the
// catalogue assertions above need.
func hasName(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// rowNames is the first column of every row, for an error message about a match.
func rowNames(r *reply) []string {
	var out []string
	for _, row := range r.rows {
		if len(row) > 0 && row[0] != nil {
			out = append(out, *row[0])
		}
	}
	return out
}
