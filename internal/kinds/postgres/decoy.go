package postgres

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/deception"
	wire "github.com/rom/xproxy/internal/pgwire"
	"github.com/rom/xproxy/internal/proxy"
)

// A database that is not there.
//
// See internal/deception for why. What is specific to PostgreSQL is that the
// reconnaissance is short and the escalations are worse than anywhere else,
// because this server can run a shell command *by design*:
//
//	SELECT version()                        what is this
//	SELECT current_setting('data_directory') where does it keep its files
//	SELECT usesuper FROM pg_user WHERE ...   is this role a superuser
//	SELECT datname FROM pg_database          what is here
//
// The third answer decides everything that follows. A superuser can
// `COPY tbl FROM PROGRAM 'sh -c …'`, which is documented remote code execution
// with no exploit in it at all; can `COPY tbl TO '/var/www/html/s.php'`; can read
// any file with `pg_read_file`; and can load a shared object with
// `CREATE FUNCTION ... LANGUAGE c`. A non-superuser can do none of it, which is
// why `superuser` is the most consequential field of the section.
//
// A refusal at the startup message ends the conversation. Answering it says which
// of those four they were reaching for.
//
// Three things are deliberate, and they are the same three as the MySQL
// fabrication beside this one. It never runs anything and never claims to: COPY
// FROM PROGRAM is refused with the wording a non-superuser gets, or with the
// wording a server whose `COPY` failed gets, and never with a success. It does not
// sleep, because `pg_sleep(60)` honoured is this listener's resources held a
// statement at a time. And it does not invent rows for a projection it does not
// recognise, because that would mean inventing a schema to match.

// pgProfile is a fabricated server's identity and shape.
type pgProfile struct {
	version   string
	databases []string
	// tables are `schema.table` names.
	tables []string
}

// The built-in profiles. The versions are ones in wide use rather than the
// newest, because a decoy claiming last week's release is one nobody believes on
// an estate that patches quarterly.
var pgProfiles = map[string]pgProfile{
	"generic-postgres": {
		version:   "15.6 (Debian 15.6-0+deb12u1)",
		databases: []string{"postgres", "template0", "template1", "appdb"},
		tables: []string{
			"public.users", "public.sessions", "public.orders", "public.order_items",
			"public.audit_log", "public.schema_migrations",
		},
	},
	"django": {
		version:   "14.11 (Ubuntu 14.11-0ubuntu0.22.04.1)",
		databases: []string{"postgres", "template0", "template1", "django"},
		tables: []string{
			"public.auth_user", "public.auth_group", "public.auth_permission",
			"public.django_session", "public.django_migrations", "public.django_admin_log",
		},
	},
	"rails": {
		version:   "13.14 (Debian 13.14-1.pgdg120+2)",
		databases: []string{"postgres", "template0", "template1", "app_production"},
		tables: []string{
			"public.users", "public.accounts", "public.active_storage_blobs",
			"public.ar_internal_metadata", "public.schema_migrations",
		},
	},
}

// DefaultProfile is the profile a section that names none gets.
const DefaultProfile = "generic-postgres"

// Profiles are the shapes a fabricated server can have, for validation.
func Profiles() []string {
	out := make([]string, 0, len(pgProfiles))
	for name := range pgProfiles {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

// The tripwires that need no configuring: the escalation chain and nothing else.
// Each is matched as a whole identifier, so a column named "sleepy" is not
// pg_sleep and a table named "programs" is not COPY FROM PROGRAM.
var builtInTripwires = []string{
	"pg_read_file", "pg_read_binary_file", "pg_ls_dir", "pg_stat_file",
	"lo_import", "lo_export", "pg_sleep", "dblink", "dblink_connect",
	"program", "pg_execute_server_program", "pg_write_server_files",
	"pg_read_server_files",
}

// privilegedTables are the catalogue tables an ordinary role cannot read: the
// places PostgreSQL keeps authentication material, and the ones that hold the
// contents of other people's rows.
//
// They are one list rather than two because every one of them is also a tripwire.
// Reading pg_authid is not something an application does, and a second list that
// had to be kept in step with this one is a list that would not be.
var privilegedTables = []string{
	"pg_shadow", "pg_authid", "pg_user_mappings", "pg_statistic",
	"pg_subscription", "pg_largeobject",
}

// The synthetic address the one fabricated number lives at. There is one because
// there is one number a visitor can see: how many backends are connected, which
// pg_stat_activity is built out of and pg_backend_pid is derived from. A gauge
// nothing answers from would be a number nobody ever reads.
const addrBackends = 1

// decoy is the fabricated server.
type decoy struct {
	// whole says the listener is a honeypot: every statement is answered here
	// and there is no server behind it.
	whole       bool
	profile     string
	version     string
	databases   []string
	tables      []string
	trip        map[string]bool
	superuser   bool
	requireAuth bool
	started     time.Time
	period      time.Duration
	values      *deception.Values
	policy      *deception.Policy
}

// newDecoy builds the fabrication, or nil where the section is absent or off.
func newDecoy(c *config.PostgresDeception, name string) (*decoy, error) {
	if c == nil || (c.Enabled != nil && !*c.Enabled) {
		return nil, nil
	}
	p, ok := pgProfiles[c.Profile]
	if !ok {
		if c.Profile != "" {
			return nil, fmt.Errorf("deception.profile: %q is not a profile", c.Profile)
		}
		p = pgProfiles[DefaultProfile]
	}
	d := &decoy{
		whole:       c.Mode == "decoy",
		profile:     c.Profile,
		version:     orString(c.Version, p.version),
		databases:   append([]string(nil), p.databases...),
		tables:      append([]string(nil), p.tables...),
		superuser:   c.Superuser,
		requireAuth: c.RequireAuth,
		started:     time.Now(),
		trip:        map[string]bool{},
	}
	if d.profile == "" {
		d.profile = DefaultProfile
	}
	if len(c.Databases) > 0 {
		d.databases = append([]string(nil), c.Databases...)
	}
	if len(c.Tables) > 0 {
		d.tables = append([]string(nil), c.Tables...)
	}
	// Sorted, because a catalogue query answers in order and a second read that
	// came back differently would be a server reconfigured between two
	// statements.
	slices.Sort(d.databases)
	d.databases = slices.Compact(d.databases)
	slices.Sort(d.tables)
	d.tables = slices.Compact(d.tables)
	for _, t := range builtInTripwires {
		d.trip[t] = true
	}
	for _, t := range privilegedTables {
		d.trip[t] = true
	}
	for i, t := range c.Tripwire {
		norm := strings.ToLower(strings.TrimSpace(t))
		if norm == "" || strings.ContainsAny(norm, " \t\r\n") {
			return nil, fmt.Errorf("deception.tripwire[%d]: %q is not an object name", i, t)
		}
		d.trip[norm] = true
	}
	seed := c.Seed
	if seed == 0 {
		seed = deception.SeedFor(name)
	}
	d.period = c.Period.D()
	if d.period <= 0 {
		d.period = deception.DefaultPeriod
	}
	d.values = deception.NewValues(seed, d.period, []deception.Band{
		{Lo: addrBackends, Hi: addrBackends, Shape: deception.ShapeAnalogue, Min: 3, Max: 40},
	})
	d.policy = deception.NewPolicy(nil, c.MaxClients)
	if len(c.Clients) > 0 {
		prefixes := make([]netip.Prefix, 0, len(c.Clients))
		for _, s := range c.Clients {
			pfx, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, fmt.Errorf("deception.clients: %q: %w", s, err)
			}
			prefixes = append(prefixes, pfx.Masked())
		}
		d.policy = deception.NewPolicy(prefixes, c.MaxClients)
	}
	return d, nil
}

func orString(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// admits says whether this client gets the fabrication.
func (d *decoy) admits(ip netip.Addr) bool { return d != nil && d.policy.Admits(ip) }

// tripped says whether a statement names something nothing legitimate asks a
// fabricated database for.
func (d *decoy) tripped(text string) bool {
	if d == nil {
		return false
	}
	// COPY to or from a server-side path, which is how a web shell gets written
	// and how a file gets read without any of the file functions. The path is a
	// string literal, so the statement names no privileged identifier at all and
	// the list below cannot see it: it has to be recognised by its shape.
	lower := strings.ToLower(strings.TrimSpace(text))
	if strings.HasPrefix(lower, "copy") && !copyOfQuery(lower) &&
		!strings.Contains(lower, "stdin") && !strings.Contains(lower, "stdout") {
		return true
	}
	for _, w := range identifiers(text) {
		if d.trip[w] {
			return true
		}
	}
	return false
}

// identifiers is the words of a statement, lower-cased, with a qualified name
// kept whole as well as split into its parts.
func identifiers(text string) []string {
	var out []string
	var b strings.Builder
	flush := func() {
		if b.Len() == 0 {
			return
		}
		w := strings.ToLower(b.String())
		out = append(out, w)
		if a, c, ok := strings.Cut(w, "."); ok {
			out = append(out, a, c)
		}
		b.Reset()
	}
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '_', c == '$', c == '.':
			b.WriteByte(c)
		default:
			flush()
		}
	}
	flush()
	return out
}

func modeName(whole bool) string {
	if whole {
		return "decoy"
	}
	return "answer"
}

// DecoyStatus is what this listener's decoy has seen, for the status view.
func (t *server) DecoyStatus() (proxy.DecoyStatus, bool) {
	d := t.decoy
	if d == nil {
		return proxy.DecoyStatus{}, false
	}
	st := proxy.DecoyStatus{
		Listener: t.name, Kind: "postgres", Mode: modeName(d.whole),
		Profile: d.profile, Served: d.policy.Served(),
		Tripped: d.policy.Tripped(), Anyone: d.policy.Anyone(),
	}
	for _, c := range d.policy.Clients(32) {
		st.Visitors = append(st.Visitors, proxy.DecoyVisitor{
			ClientIP: c.Addr.String(), FirstSeen: c.FirstSeen, LastSeen: c.LastSeen,
			Frames: c.Frames, Tripped: c.Tripped,
		})
	}
	return st, true
}

// appDatabase is the database a visitor is told they are connected to: the first
// that is not a template or the bootstrap one.
func (d *decoy) appDatabase() string {
	for _, db := range d.databases {
		switch db {
		case "postgres", "template0", "template1":
			continue
		}
		return db
	}
	return "postgres"
}

// gauge is the fabricated number at an address, bounded by its band -- which is
// where the floor comes from: the band's minimum is 3, so there is no second
// bound to apply here and a guard for one would be a guard nothing reaches.
func (d *decoy) gauge(addr int) int {
	return int(d.values.Register(0, addr))
}

// startup is the sequence a client waits for before it will send a statement:
// AuthenticationOk, the parameters, the backend key, and ReadyForQuery.
//
// It is all of it or none: a client that received AuthenticationOk and no
// ReadyForQuery waits for ever, and one that received no BackendKeyData cannot
// cancel a query afterwards. The parameters are the ones libpq and every driver
// after it read -- server_version above all, which is the answer to the first
// question a scanner asks.
//
// The database is not among them, and not by omission: this protocol has no
// database parameter. A client knows which one it asked for, and asks again with
// current_database() if it wants the server's word for it.
func (d *decoy) startup(role string, pid uint32) []byte {
	out := wire.AuthenticationOk()
	for _, kv := range [][2]string{
		{"application_name", ""},
		{"client_encoding", "UTF8"},
		{"DateStyle", "ISO, MDY"},
		{"default_transaction_read_only", "off"},
		{"in_hot_standby", "off"},
		{"integer_datetimes", "on"},
		{"IntervalStyle", "postgres"},
		{"is_superuser", onOff(d.superuser)},
		{"server_encoding", "UTF8"},
		{"server_version", d.version},
		{"session_authorization", role},
		{"standard_conforming_strings", "on"},
		{"TimeZone", "Etc/UTC"},
	} {
		out = append(out, wire.ParameterStatus(kv[0], kv[1])...)
	}
	out = append(out, wire.BackendKeyData(pid, pid^0x5a5a5a5a)...)
	return append(out, wire.ReadyForQuery('I')...)
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// The fabricated answers.
//
// Each is what a real server sends for that statement, because the shape of a
// reply is what a driver reads and what a fingerprinting tool checks. The
// statements recognised by name are the reconnaissance ones, because those are
// the ones whose answers decide what the visitor tries next -- and getting one of
// them wrong, or inconsistent with another, is what ends the pretence.

// query answers one simple-query message, ending with the ReadyForQuery a client
// waits for before it will send anything else.
//
// A client in the simple query protocol that received an answer and no
// ReadyForQuery waits for ever, so the terminator is added here rather than by
// each branch.
func (d *decoy) query(text string, se *decoySession) []byte {
	return append(d.answer(text, se), wire.ReadyForQuery('I')...)
}

// answer is the reply to one statement, without the terminator.
func (d *decoy) answer(text string, se *decoySession) []byte {
	lower := strings.ToLower(strings.TrimSpace(text))
	// COPY's three dangerous forms, first, because the classifier names them and
	// because what a real server says depends on whether the role is a
	// superuser. Saying so truthfully is what makes the rest of the fabrication
	// consistent: a role reported as not a superuser must be refused these.
	if reply, ok := d.copyStatement(lower); ok {
		return reply
	}
	// The file functions. A non-superuser is refused by permission; a superuser
	// gets the error a server gives for a path outside its data directory, which
	// is what a hardened one answers and is still an answer the visitor learns
	// from.
	if fn, ok := d.fileFunction(lower); ok {
		if !d.superuser {
			return wire.ErrorResponse("ERROR", "42501",
				"permission denied for function "+fn)
		}
		return wire.ErrorResponse("ERROR", "58P01",
			"could not open file: No such file or directory")
	}
	// pg_sleep, answered rather than honoured: waiting would make this
	// listener's resources something a visitor can hold, a statement at a time,
	// for as long as they like.
	if mentions(lower, "pg_sleep") {
		return wire.ResultSet([]wire.Field{{Name: "pg_sleep", OID: 2278, Size: 4, Modifier: -1}},
			[][]*string{{wire.Str("")}})
	}
	// The catalogue tables that hold authentication material. A real server
	// answers 42501 rather than an empty set: an empty set would say the table is
	// there and has no rows, which pg_shadow never is.
	if table, ok := privileged(lower); ok {
		return wire.ErrorResponse("ERROR", "42501", "permission denied for table "+table)
	}
	if reply, ok := d.recognise(lower, se); ok {
		return reply
	}
	stmts, ok := wire.Statements(text, 8)
	if !ok || len(stmts) == 0 {
		return wire.ErrorResponse("ERROR", "42601", "syntax error at or near the end of input")
	}
	switch stmts[0].Kind {
	case wire.KindSelect, wire.KindShow, wire.KindExplain, wire.KindFetch:
		// A SELECT the recognisers do not know. An empty result set is the honest
		// answer: the fabrication is a surface rather than a database, and
		// inventing rows for an arbitrary projection would mean inventing a
		// schema to match.
		return wire.ResultSet([]wire.Field{wire.Text("?column?")}, nil)
	case wire.KindBegin:
		return wire.CommandComplete("BEGIN")
	case wire.KindCommit:
		return wire.CommandComplete("COMMIT")
	case wire.KindRollback:
		return wire.CommandComplete("ROLLBACK")
	case wire.KindSet:
		return wire.CommandComplete("SET")
	case wire.KindInsert:
		// The tag carries the object identifier and the count, and a driver reads
		// the count out of it to answer "how many rows did that affect".
		return wire.CommandComplete("INSERT 0 1")
	case wire.KindUpdate:
		return wire.CommandComplete("UPDATE 1")
	case wire.KindDelete:
		return wire.CommandComplete("DELETE 1")
	case wire.KindDo:
		// A DO block is plpgsql, which this fabrication does not run and does not
		// pretend to. Saying the language is not installed is both a refusal and
		// a true-sounding one on a minimal install.
		return wire.ErrorResponse("ERROR", "42704",
			`language "plpgsql" does not exist`)
	case wire.KindDDL:
		return wire.CommandComplete(ddlTag(lower))
	case wire.KindEmpty:
		return wire.EmptyQueryResponse()
	default:
		return wire.CommandComplete(strings.ToUpper(firstWord(lower)))
	}
}

// copyStatement answers COPY, whose three forms are the worst statements on this
// protocol and whose answers must agree with what the role was said to be.
func (d *decoy) copyStatement(lower string) ([]byte, bool) {
	if !strings.HasPrefix(lower, "copy") {
		return nil, false
	}
	switch {
	case mentions(lower, "program"):
		// Remote code execution, by design and documented. A non-superuser is
		// refused by permission, which is the answer that agrees with an
		// is_superuser of off; a superuser gets the error a COPY whose program
		// failed gives, because the fabrication runs nothing and will not say it
		// did.
		if !d.superuser {
			return wire.ErrorResponse("ERROR", "42501",
				"must be superuser or a member of the pg_execute_server_program role to COPY to or from an external program"), true
		}
		return wire.ErrorResponse("ERROR", "XX000",
			"program \"sh\" failed: child process exited with exit code 127"), true
	case copyOfQuery(lower):
		// COPY (SELECT ...) TO STDOUT, which a real server runs and this one
		// cannot: there is no relation to name back and no rows to send. Saying
		// the form is unsupported is the one refusal here that does not pretend
		// to be about privileges.
		return wire.ErrorResponse("ERROR", "0A000",
			"COPY of a query is not supported on this connection"), true
	case strings.Contains(lower, "stdin"):
		// COPY FROM STDIN is bulk ingest over the protocol. Answering
		// CopyInResponse would put the connection into copy mode and the
		// fabrication would have to read an unbounded stream, so it is refused as
		// a table nobody has -- which is also true.
		return wire.ErrorResponse("ERROR", "42P01",
			"relation \""+copyRelation(lower)+"\" does not exist"), true
	case strings.Contains(lower, "stdout"):
		return wire.ErrorResponse("ERROR", "42P01",
			"relation \""+copyRelation(lower)+"\" does not exist"), true
	}
	// COPY to or from a server-side path, which needs the file roles.
	if !d.superuser {
		return wire.ErrorResponse("ERROR", "42501",
			"must be superuser or a member of the pg_write_server_files role to COPY to a file"), true
	}
	return wire.ErrorResponse("ERROR", "42501",
		"could not open file for writing: Permission denied"), true
}

// copyOfQuery says a COPY reads a parenthesised query rather than a relation.
func copyOfQuery(lower string) bool {
	fields := strings.Fields(lower)
	return len(fields) >= 2 && strings.HasPrefix(fields[1], "(")
}

// copyRelation is the table a COPY names, for an error message that quotes it
// back the way a real server does.
func copyRelation(lower string) string {
	fields := strings.Fields(lower)
	if len(fields) < 2 {
		return "unknown"
	}
	return strings.Trim(fields[1], `"();`)
}

// fileFunction is the file-reading function a statement calls, if any.
func (d *decoy) fileFunction(lower string) (string, bool) {
	for _, fn := range []string{
		"pg_read_file", "pg_read_binary_file", "pg_ls_dir", "pg_stat_file",
		"lo_import", "lo_export",
	} {
		if strings.Contains(lower, fn+"(") {
			return fn, true
		}
	}
	return "", false
}

// privileged names the catalogue table a statement is reaching for when it is one
// an ordinary role cannot read.
func privileged(lower string) (string, bool) {
	for _, w := range identifiers(lower) {
		_, name, ok := strings.Cut(w, ".")
		if !ok {
			name = w
		}
		if slices.Contains(privilegedTables, name) {
			return name, true
		}
	}
	return "", false
}

// recognise answers the statements whose answers decide what a visitor tries
// next.
func (d *decoy) recognise(lower string, se *decoySession) ([]byte, bool) {
	db := se.database
	if db == "" {
		db = d.appDatabase()
	}
	switch {
	case lower == "select 1", lower == "select 1;":
		return d.oneValue("?column?", "1"), true
	case mentions(lower, "version") && !mentions(lower, "pg_database"):
		return d.oneValue("version", "PostgreSQL "+d.version+" on x86_64-pc-linux-gnu, "+
			"compiled by gcc (Debian 12.2.0-14) 12.2.0, 64-bit"), true
	case mentions(lower, "pg_database"):
		return d.databaseList(), true
	case mentions(lower, "current_database"):
		return d.oneValue("current_database", db), true
	case strings.HasPrefix(lower, "show "):
		// Before the privilege question below, because the privilege has two
		// spellings and they do not have the same answer: a real server answers
		// "on" or "off" to SHOW is_superuser and "t" or "f" to the catalogue's
		// usesuper column. Answering either in the other's form is the kind of
		// disagreement a fingerprinting tool is looking for, so the setting is
		// answered as a setting.
		return d.showSetting(showTarget(lower[5:]), se.role), true
	case mentions(lower, "current_setting"):
		return d.currentSetting(lower, se.role), true
	case mentions(lower, "usesuper"), mentions(lower, "rolsuper"):
		// The answer that decides everything else, and it comes before the
		// identity questions below for a reason: the statement that asks it is
		// "SELECT usesuper FROM pg_user WHERE usename = current_user", which
		// mentions both. A fabrication that answered the identity there would
		// answer the wrong question -- and this is the question the visitor's
		// next statement depends on.
		return d.oneValue("usesuper", boolText(d.superuser)), true
	case mentions(lower, "current_user"), mentions(lower, "session_user"),
		mentions(lower, "user"), mentions(lower, "pg_user"):
		return d.oneValue("current_user", se.role), true
	case mentions(lower, "current_schema"):
		return d.oneValue("current_schema", "public"), true
	case mentions(lower, "pg_tables"), mentions(lower, "information_schema"),
		mentions(lower, "pg_class"):
		return d.tableList(), true
	case mentions(lower, "inet_server_addr"):
		return d.oneValue("inet_server_addr", "10.0.16.30/32"), true
	case mentions(lower, "inet_server_port"):
		return d.oneValue("inet_server_port", "5432"), true
	case mentions(lower, "pg_backend_pid"):
		return d.oneValue("pg_backend_pid", strconv.Itoa(1000+d.gauge(addrBackends))), true
	case mentions(lower, "pg_postmaster_start_time"):
		return d.oneValue("pg_postmaster_start_time",
			d.started.UTC().Format("2006-01-02 15:04:05.000000-07")), true
	case mentions(lower, "pg_stat_activity"):
		return d.activity(db), true
	}
	return nil, false
}

// settings is what SHOW and current_setting answer. The values are a default
// package install's, because that is what a server nobody has hardened looks
// like -- which is the server being impersonated.
//
// Every parameter the startup sequence announces is in here, and with the same
// value. A client is told thirteen of them before it sends a statement, and one
// that asked about one of those and was told "unrecognized configuration
// parameter" would be talking to a server that forgot what it had just said.
func (d *decoy) settings(role string) [][2]string {
	return [][2]string{
		{"server_version", d.version},
		{"data_directory", "/var/lib/postgresql/15/main"},
		{"config_file", "/etc/postgresql/15/main/postgresql.conf"},
		{"hba_file", "/etc/postgresql/15/main/pg_hba.conf"},
		{"log_directory", "log"},
		{"listen_addresses", "*"},
		{"port", "5432"},
		{"max_connections", "100"},
		{"shared_buffers", "128MB"},
		{"ssl", "off"},
		{"password_encryption", "scram-sha-256"},
		{"is_superuser", onOff(d.superuser)},
		{"search_path", `"$user", public`},
		{"TimeZone", "Etc/UTC"},
		{"client_encoding", "UTF8"},
		{"server_encoding", "UTF8"},
		{"transaction_read_only", "off"},
		{"log_statement", "none"},
		{"shared_preload_libraries", ""},
		// The rest of what the startup sequence announced.
		{"application_name", ""},
		{"DateStyle", "ISO, MDY"},
		{"default_transaction_read_only", "off"},
		{"in_hot_standby", "off"},
		{"integer_datetimes", "on"},
		{"IntervalStyle", "postgres"},
		{"standard_conforming_strings", "on"},
		{"session_authorization", role},
	}
}

// showTarget is the parameter a SHOW names: the terminator a client library
// leaves on is not part of it, and neither is the space in front of that
// terminator -- psql sends "SHOW data_directory ;" and a name with a space on the
// end matches no setting at all.
func showTarget(rest string) string {
	return strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(rest), ";"))
}

func (d *decoy) showSetting(name, role string) []byte {
	if name == "all" {
		rows := make([][]*string, 0, len(d.settings(role)))
		for _, kv := range d.settings(role) {
			rows = append(rows, []*string{wire.Str(kv[0]), wire.Str(kv[1]), wire.Str("")})
		}
		return wire.ResultSet([]wire.Field{
			wire.Text("name"), wire.Text("setting"), wire.Text("description"),
		}, rows)
	}
	for _, kv := range d.settings(role) {
		if strings.EqualFold(kv[0], name) {
			return d.oneValue(kv[0], kv[1])
		}
	}
	return wire.ErrorResponse("ERROR", "42704",
		`unrecognized configuration parameter "`+wire.Clip(name)+`"`)
}

func (d *decoy) currentSetting(lower, role string) []byte {
	at := strings.Index(lower, "current_setting(")
	if at < 0 {
		// The name without its call, which a real server reads as a column
		// reference rather than a function. Slicing from a -1 here would have
		// parsed a parameter name out of the middle of the statement.
		return wire.ErrorResponse("ERROR", "42703",
			`column "current_setting" does not exist`)
	}
	rest := lower[at+len("current_setting("):]
	name := rest
	if end := strings.IndexAny(rest, ")"); end >= 0 {
		name = rest[:end]
	}
	name = strings.Trim(strings.TrimSpace(name), "'\"")
	for _, kv := range d.settings(role) {
		if strings.EqualFold(kv[0], name) {
			return d.oneValue("current_setting", kv[1])
		}
	}
	return wire.ErrorResponse("ERROR", "42704",
		`unrecognized configuration parameter "`+wire.Clip(name)+`"`)
}

// databaseList is what a client's \l answers, and the first question after the
// version.
func (d *decoy) databaseList() []byte {
	rows := make([][]*string, 0, len(d.databases))
	for _, db := range d.databases {
		rows = append(rows, []*string{
			wire.Str(db), wire.Str("postgres"), wire.Str("UTF8"),
		})
	}
	return wire.ResultSet([]wire.Field{
		{Name: "datname", OID: wire.OIDName, Size: 64, Modifier: -1},
		wire.Text("owner"),
		wire.Text("encoding"),
	}, rows)
}

// tableList is what a catalogue query answers: the schema and the table, which
// is the part of the fabrication a visitor reads most closely.
func (d *decoy) tableList() []byte {
	rows := make([][]*string, 0, len(d.tables))
	for _, t := range d.tables {
		schema, name, ok := strings.Cut(t, ".")
		if !ok {
			schema, name = "public", t
		}
		rows = append(rows, []*string{wire.Str(schema), wire.Str(name), wire.Str("postgres")})
	}
	return wire.ResultSet([]wire.Field{
		{Name: "schemaname", OID: wire.OIDName, Size: 64, Modifier: -1},
		{Name: "tablename", OID: wire.OIDName, Size: 64, Modifier: -1},
		{Name: "tableowner", OID: wire.OIDName, Size: 64, Modifier: -1},
	}, rows)
}

// activity is pg_stat_activity: this connection and the application's. A server
// with exactly one connection on it is a server nobody uses, which is a tell.
func (d *decoy) activity(db string) []byte {
	n := d.gauge(addrBackends)
	rows := make([][]*string, 0, n)
	for i := 0; i < n; i++ {
		rows = append(rows, []*string{
			wire.Str(strconv.Itoa(1000 + i*3)), wire.Str(db), wire.Str("app"),
			wire.Str("10.0.16." + strconv.Itoa(20+i%8)), wire.Str("idle"), nil,
		})
	}
	return wire.ResultSet([]wire.Field{
		{Name: "pid", OID: wire.OIDInt4, Size: 4, Modifier: -1},
		{Name: "datname", OID: wire.OIDName, Size: 64, Modifier: -1},
		{Name: "usename", OID: wire.OIDName, Size: 64, Modifier: -1},
		wire.Text("client_addr"),
		wire.Text("state"),
		wire.Text("query"),
	}, rows)
}

// oneValue is the commonest result set on this protocol: one column, one row.
func (d *decoy) oneValue(name, value string) []byte {
	return wire.ResultSet([]wire.Field{wire.Text(name)}, [][]*string{{wire.Str(value)}})
}

// mentions says whether a statement names an identifier, as a whole word.
func mentions(lower, name string) bool {
	for _, w := range identifiers(lower) {
		if w == name {
			return true
		}
	}
	return false
}

func boolText(b bool) string {
	if b {
		return "t"
	}
	return "f"
}

func firstWord(lower string) string {
	if f := strings.Fields(lower); len(f) > 0 {
		return f[0]
	}
	return ""
}

// ddlTag is the CommandComplete tag of a schema change, which a driver reads back
// as the name of what it did.
func ddlTag(lower string) string {
	fields := strings.Fields(strings.ToUpper(lower))
	switch {
	case len(fields) >= 2:
		return fields[0] + " " + strings.TrimSuffix(fields[1], ";")
	case len(fields) == 1:
		return strings.TrimSuffix(fields[0], ";")
	}
	return "OK"
}

// decoySession is the state a fabricated server keeps about one connection: the
// role and database the startup packet named, and nothing else, because nothing
// else would be noticed.
type decoySession struct {
	role     string
	database string
}

// serveDecoy runs a connection on a listener that is nothing but a fabricated
// server.
//
// The encryption negotiation has already happened in negotiate, so this begins
// where a real server begins: with the startup packet already read. The bounds
// still apply -- the handshake timeout, the session duration, the reader's own
// message bound -- because a honeypot is still a service on a port.
func (t *server) serveDecoy(se *session) {
	d := t.decoy
	ds := &decoySession{role: se.user, database: se.database}
	if ds.role == "" {
		ds.role = "postgres"
	}
	//nolint:gosec // the identifier is cosmetic and masked to the positive range
	pid := uint32(time.Now().UnixNano()&0x7FFFFFFF) | 1
	rd := wire.NewReader(se.client, wire.FromClient, t.policy.maxMessage)
	if d.requireAuth {
		// The refusal a server whose pg_hba line says md5 gives to a wrong
		// password -- which means asking for one first. A server that refused
		// before asking is one that never wanted a credential, and the request
		// is also what makes the attempt worth recording: the client answers it
		// with what it would have logged in with.
		//
		// It is off by default, because the reconnaissance happens after the
		// login and a decoy that refuses the login collects nothing else.
		salt := []byte{byte(pid >> 24), byte(pid >> 16), byte(pid >> 8), byte(pid)}
		if err := se.writeClient(wire.AuthenticationRequest(wire.AuthMD5Password, salt)); err != nil {
			return
		}
		detail := startupSummary(se)
		if m, err := rd.Next(); err == nil && m.Type == wire.MsgPasswordMessage {
			// The length, never the credential. A record that carried the
			// password would be a password store, and this one is read by more
			// people and kept in more places than a database's own log.
			detail += ", credential " + strconv.Itoa(credentialLen(m.Body)) + " octets"
		}
		t.recordDeception(se, ds, "auth_failed", detail, false)
		_ = se.writeClient(wire.ErrorResponse("FATAL", "28P01",
			`password authentication failed for user "`+wire.Clip(ds.role)+`"`))
		return
	}
	t.recordDeception(se, ds, "startup", startupSummary(se), false)
	if err := se.writeClient(d.startup(ds.role, pid)); err != nil {
		return
	}
	if dur := t.pc.SessionDuration.D(); dur > 0 {
		_ = se.client.SetDeadline(time.Now().Add(dur))
	}
	for {
		m, err := rd.Next()
		if err != nil {
			return
		}
		switch m.Type {
		case wire.MsgTerminate:
			return
		case wire.MsgQuery:
			text := queryText(m.Body)
			t.recordDeception(se, ds, "decoy", text, d.tripped(text))
			if err := se.writeClient(d.query(text, ds)); err != nil {
				return
			}
		case wire.MsgSync, wire.MsgFlush:
			if err := se.writeClient(wire.ReadyForQuery('I')); err != nil {
				return
			}
		default:
			// The extended protocol -- Parse, Bind, Execute, Describe -- and the
			// function-call and copy messages. Answering any of them would mean
			// keeping a prepared statement and a portal and answering the
			// Execute that follows, so the fabrication says what a server says
			// about a message it will not handle and lets the client fall back
			// to a simple query, which every driver does.
			t.recordDeception(se, ds, "decoy", "message "+string(m.Type), false)
			out := wire.ErrorResponse("ERROR", "0A000",
				"the extended query protocol is not supported on this connection")
			if err := se.writeClient(append(out, wire.ReadyForQuery('I')...)); err != nil {
				return
			}
		}
	}
}

// credentialLen is the length of the credential in a PasswordMessage, which is a
// C string: the terminating zero is not part of it.
func credentialLen(body []byte) int {
	if i := bytes.IndexByte(body, 0); i >= 0 {
		return i
	}
	return len(body)
}

// queryText is the statement in a Query message: a C string, so the terminating
// zero is not part of it.
func queryText(body []byte) string {
	if i := bytes.IndexByte(body, 0); i >= 0 {
		return string(body[:i])
	}
	return string(body)
}

// startupSummary is what of a startup packet goes into the record.
//
// The role, the database and the application name, because all three are
// identities a client chose to announce. There is no password to leave out: on
// this protocol the relay never sees one, because the credential exchange comes
// after the startup packet and the fabrication accepts before asking.
func startupSummary(se *session) string {
	var b strings.Builder
	b.WriteString("role ")
	b.WriteString(wire.Clip(se.user))
	if se.database != "" {
		b.WriteString(", database ")
		b.WriteString(wire.Clip(se.database))
	}
	if se.app != "" {
		b.WriteString(", application ")
		b.WriteString(wire.Clip(se.app))
	}
	return b.String()
}

// recordDeception notes one fabricated answer where an operator looks.
func (t *server) recordDeception(se *session, ds *decoySession, why, detail string, tripped bool) {
	d := t.decoy
	d.policy.Record(se.ip, tripped, time.Now())
	t.host.Counters().PostgresDeceived.Add(1)
	event := "postgres_deceived"
	if tripped {
		t.host.Counters().PostgresTripwire.Add(1)
		event = "postgres_tripwire"
	}
	attrs := []any{
		"listener", t.name, "client_ip", se.ip.String(), "reason", why,
		"mode", modeName(d.whole),
	}
	if ds != nil && ds.role != "" {
		attrs = append(attrs, "db_user", ds.role)
	}
	if ds != nil && ds.database != "" {
		attrs = append(attrs, "database", ds.database)
	}
	if detail != "" {
		attrs = append(attrs, "statement", oneLine(detail))
	}
	t.host.Logs().SecurityEvent(context.Background(), "deceive", event, attrs...)
}

// oneLine reduces a statement to one log field. A statement carrying a payload
// carries newlines, and a record built out of them would be several records.
func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == 0 {
			return ' '
		}
		return r
	}, s)
}

// deceive answers one statement as the fabricated server on a listener that
// fronts a real one, and reports whether it did.
//
// It is called only where the statement was not going to reach the server: a
// refusal. That is the invariant the whole feature rests on -- a statement on its
// way to a real database is never answered from here -- and it is a test rather
// than a comment.
func (se *session) deceive(text, why string) bool {
	t := se.t
	d := t.decoy
	if d == nil || !d.admits(se.ip) {
		return false
	}
	ds := &decoySession{role: se.user, database: se.database}
	t.recordDeception(se, ds, why, text, d.tripped(text))
	return se.writeClient(d.query(text, ds)) == nil
}
