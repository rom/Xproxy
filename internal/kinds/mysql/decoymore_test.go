package mysql

import (
	"errors"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/mysqlwire"
)

// The rest of the fabrication: the statements a visitor asks after the
// version, the commands that are not queries, and the flavour.
//
// What is worth asserting is not that it answers but that it answers what a
// real server answers, because the shape of a reply is what a tool reads. An
// empty result set where a server gives 1142, or a result set where a server
// gives a status line, is the tell that ends the pretence -- and a
// fabrication that has been seen through is worse than none, because the
// visitor now knows the estate is watching.

// errUnreadable is the error a handshake response that did not parse gives.
var errUnreadable = errors.New("short packet")

// The catalogue walk, which is what a visitor does between the version and
// the credentials: the engines, the processes, the warnings from the
// statement before.
func TestTheCatalogueStatementsAreAnswered(t *testing.T) {
	d := decoyFor(t, &config.MySQLDeception{Mode: "decoy", Version: "8.0.36", Profile: "generic-mysql"})

	engines := ask(t, d, "show engines")
	if len(engines.columns) != 2 || engines.columns[0] != "Engine" {
		t.Errorf("SHOW ENGINES columns %v", engines.columns)
	}
	var defaulted int
	for _, row := range engines.rows {
		if row[1] != nil && *row[1] == "DEFAULT" {
			defaulted++
		}
	}
	if defaulted != 1 {
		t.Errorf("%d engines are the default: %v", defaulted, engines.rows)
	}

	// A server with one connection on it is a server nobody uses, which is
	// the tell this answer exists to avoid.
	ps := ask(t, d, "show processlist")
	if len(ps.columns) != 8 || ps.columns[0] != "Id" || ps.columns[1] != "User" {
		t.Errorf("SHOW PROCESSLIST columns %v", ps.columns)
	}
	if len(ps.rows) < 2 {
		t.Errorf("SHOW PROCESSLIST answered %d rows", len(ps.rows))
	}
	for _, row := range ps.rows {
		if row[0] == nil || row[1] == nil || *row[1] == "" {
			t.Errorf("a process row has no id or user: %v", row)
		}
	}

	// Warnings and errors are empty rather than refused: a client library
	// reads them after every statement, and an error there would be reported
	// instead of whatever the client was actually doing.
	for _, q := range []string{"show warnings", "SHOW ERRORS"} {
		r := ask(t, d, q)
		if r.err != nil || len(r.rows) != 0 {
			t.Errorf("%s answered %+v", q, r)
		}
	}

	// SHOW TABLES IN <db> is the other spelling of FROM, and a visitor uses
	// whichever their client puts in front of them.
	if got := ask(t, d, "show tables in mysql"); len(got.rows) != 0 {
		t.Errorf("SHOW TABLES IN mysql answered %d rows", len(got.rows))
	}
	in := ask(t, d, "show tables in appdb")
	from := ask(t, d, "show tables from appdb")
	if len(in.rows) == 0 || len(in.rows) != len(from.rows) {
		t.Errorf("IN answered %d rows and FROM %d", len(in.rows), len(from.rows))
	}

	// An empty statement is what a client sends when its own string building
	// went wrong, and a server answers OK rather than a syntax error.
	if r := ask(t, d, ";"); r.err != nil {
		t.Errorf("an empty statement was refused: %d %s", r.err.Code, r.err.Text)
	}
}

// The tables holding authentication material are refused with the error a
// real server gives, which is also the answer that keeps the pretence
// consistent with the grants it reported.
func TestThePerformanceSchemaAccountTablesAreRefusedLikeTheOthers(t *testing.T) {
	d := decoyFor(t, &config.MySQLDeception{Mode: "decoy", Version: "8.0.36"})
	for _, q := range []string{
		"select * from performance_schema.accounts",
		"SELECT USER, HOST FROM performance_schema.users",
		"select * from performance_schema.hosts limit 10",
	} {
		r := ask(t, d, q)
		if r.err == nil {
			t.Errorf("%s was answered rather than refused: %+v", q, r)
			continue
		}
		if r.err.Code != wire.StatementDenied {
			t.Errorf("%s answered %d, want the denied error", q, r.err.Code)
		}
		if !strings.Contains(r.err.Text, "performance_schema.") {
			t.Errorf("the refusal does not name the table: %q", r.err.Text)
		}
	}
}

// The commands that are not queries. Each has one right answer and it is not
// a result set: a client library that got the wrong shape here reports a
// protocol error, which is a tell.
func TestTheRemainingCommandsAnswerInTheRightShape(t *testing.T) {
	d := decoyFor(t, &config.MySQLDeception{Mode: "decoy", Version: "8.0.36"})
	for _, c := range []struct {
		name    string
		cmd     byte
		payload string
		first   byte
	}{
		{"a field list", wire.ComFieldList, "orders", wire.RespEOF},
		{"a change of user", wire.ComChangeUser, "app", wire.RespOK},
		{"a reset", wire.ComResetConnection, "", wire.RespOK},
		{"a set option", wire.ComSetOption, "\x00\x00", wire.RespEOF},
	} {
		t.Run(c.name, func(t *testing.T) {
			se := &decoySession{deprecateEOF: true, database: "appdb"}
			raw, ok := d.answer(c.cmd, []byte(c.payload), se)
			if !ok || len(raw) < 5 {
				t.Fatalf("answered %q, %v", raw, ok)
			}
			if raw[4] != c.first {
				t.Errorf("the reply starts with %#x, want %#x", raw[4], c.first)
			}
			// A reset takes the session back to no database, which is what
			// the command means: the connection is as it was at login.
			if c.cmd == wire.ComResetConnection && se.database != "" {
				t.Errorf("the session still holds database %q", se.database)
			}
		})
	}
}

// The flavour decides details a fingerprinting tool reads: MariaDB's basedir
// has no trailing slash and its version comment names the distribution rather
// than Ubuntu's build. A decoy whose details do not agree with the version it
// reports is one that has been seen through.
func TestTheFlavourIsConsistentWithTheVersion(t *testing.T) {
	maria := decoyFor(t, &config.MySQLDeception{Mode: "decoy", Profile: "mariadb"})
	if got := one(t, ask(t, maria, "select @@basedir")); got != "/usr" {
		t.Errorf("mariadb basedir %q", got)
	}
	if got := one(t, ask(t, maria, "select @@version_comment")); got != "Debian 12" {
		t.Errorf("mariadb version_comment %q", got)
	}
	mysql := decoyFor(t, &config.MySQLDeception{Mode: "decoy", Profile: "generic-mysql"})
	if got := one(t, ask(t, mysql, "select @@basedir")); got != "/usr/" {
		t.Errorf("mysql basedir %q", got)
	}
	if got := one(t, ask(t, mysql, "select @@version_comment")); got != "(Ubuntu)" {
		t.Errorf("mysql version_comment %q", got)
	}
}

// A catalogue of nothing but system schemas has no application database in
// it, and the fabrication says information_schema rather than an empty name:
// DATABASE() returning nothing is a connection with no default schema, which
// is not what a client that connected with one sees.
func TestACatalogueOfSystemSchemasStillNamesOne(t *testing.T) {
	d := decoyFor(t, &config.MySQLDeception{Mode: "decoy", Version: "8.0.36",
		Databases: []string{"information_schema", "mysql", "performance_schema"}})
	if got := one(t, ask(t, d, "select database()")); got != "information_schema" {
		t.Errorf("database() answered %q", got)
	}
}

// The profile list is what the configuration reference and the shell
// completion are written from, so it has to be sorted and complete.
func TestTheProfileListIsSortedAndNamesEveryProfile(t *testing.T) {
	got := Profiles()
	if len(got) == 0 {
		t.Fatal("no profiles")
	}
	for i := 1; i < len(got); i++ {
		if got[i-1] >= got[i] {
			t.Fatalf("the list is not sorted: %v", got)
		}
	}
	for _, want := range []string{"generic-mysql", "mariadb"} {
		if !hasName(got, want) {
			t.Errorf("%q is not in %v", want, got)
		}
	}
	// And every name in it builds, which is what the completion promises.
	for _, name := range got {
		if _, err := newDecoy(&config.MySQLDeception{Mode: "decoy", Profile: name}, "db"); err != nil {
			t.Errorf("profile %q does not build: %v", name, err)
		}
	}
}

// A listener with no deception section reports no decoy rather than an empty
// one: the status view is read to find out whether anything is fabricating,
// and a zero entry would read as "yes, and nothing has happened".
func TestAListenerWithoutADecoyReportsNone(t *testing.T) {
	var t0 server
	st, on := t0.DecoyStatus()
	if on {
		t.Errorf("a listener with no decoy reported %+v", st)
	}
	if st.Listener != "" || st.Served != 0 || len(st.Visitors) != 0 {
		t.Errorf("the empty status is not empty: %+v", st)
	}
}

// What is written down about a login the fabrication accepted, and about one
// it could not read. The password is never in it; the fields that identify
// the client are, because those are what distinguish a scanner from a
// misconfigured application.
func TestTheLoginSummaryNamesTheClientAndNeverThePassword(t *testing.T) {
	got := loginSummary(&wire.Login{
		User: "root", Database: "wordpress", Plugin: "mysql_native_password",
		Attrs: map[string]string{"_client_name": "libmysql"},
	}, nil)
	for _, want := range []string{"user root", "database wordpress", "plugin mysql_native_password", "client libmysql"} {
		if !strings.Contains(got, want) {
			t.Errorf("the summary lacks %q: %q", want, got)
		}
	}
	// The fields that were not sent are left out rather than written as
	// empty, so a line with a database in it means a database was asked for.
	short := loginSummary(&wire.Login{User: "app"}, nil)
	if strings.Contains(short, "database") || strings.Contains(short, "plugin") || strings.Contains(short, "client") {
		t.Errorf("the summary invented fields: %q", short)
	}
	// And a handshake response that did not parse is still worth a line: the
	// attempt happened, and that is the record.
	if got := loginSummary(nil, errUnreadable); !strings.Contains(got, "unreadable login") ||
		!strings.Contains(got, errUnreadable.Error()) {
		t.Errorf("an unreadable login was summarised as %q", got)
	}
}

// Whatever reaches a log line is one line: a user name with a newline in it
// would otherwise write a second record of the visitor's choosing.
func TestAControlCharacterCannotSplitALogLine(t *testing.T) {
	if got := oneLine("app\r\nuser=root\x00"); strings.ContainsAny(got, "\r\n\x00") {
		t.Errorf("oneLine left a control character in %q", got)
	}
	if got := oneLine("ordinary"); got != "ordinary" {
		t.Errorf("oneLine rewrote %q", got)
	}
}

// Renumbering walks the packets of a reply and stops at the end of what it
// was given: a truncated last packet claims more octets than are there, and
// walking past it would read whatever is next in memory.
func TestRenumberingStopsAtATruncatedPacket(t *testing.T) {
	// One whole packet, then a header claiming ten octets with two behind it.
	raw := append(wire.Frame(0, []byte("ok")), 10, 0, 0, 0, 'x', 'y')
	out := renumber(raw, 7)
	if len(out) != len(raw) {
		t.Fatalf("renumber returned %d octets for %d", len(out), len(raw))
	}
	if out[3] != 7 {
		t.Errorf("the first packet is numbered %d, want 7", out[3])
	}
	if out[3+len(wire.Frame(0, []byte("ok")))] != 8 {
		t.Errorf("the truncated packet is numbered %d, want 8", out[3+len(wire.Frame(0, []byte("ok")))])
	}
}

// SHOW VARIABLES LIKE takes a SQL pattern, where a run of wildcards is one
// wildcard and an empty name matches only an empty pattern.
func TestTheLikePatternHandlesRunsAndEmptyNames(t *testing.T) {
	for _, c := range []struct {
		pattern, s string
		want       bool
	}{
		{"%%version%%", "version_comment", true},
		{"%%%", "anything", true},
		{"%", "", true},
		{"a%", "", false},
		{"", "", true},
		{"", "x", false},
	} {
		if got := likeMatch(c.pattern, c.s); got != c.want {
			t.Errorf("likeMatch(%q, %q) = %v, want %v", c.pattern, c.s, got, c.want)
		}
	}
}
