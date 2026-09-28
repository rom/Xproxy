package mysql

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/deception"
	wire "github.com/rom/xproxy/internal/mysqlwire"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/sqlkind"
)

// A database that is not there.
//
// See internal/deception for why. What is specific to MySQL is that the
// reconnaissance is the attack's first half and it is made entirely of
// legitimate statements. A scanner finds the port, reads the greeting for a
// version, and then asks the questions that decide what is possible:
//
//	SHOW DATABASES                  what is here
//	SELECT @@datadir                where does it keep its files
//	SELECT @@secure_file_priv       may a statement write one
//	SHOW GRANTS                     does this account have FILE
//	SELECT * FROM mysql.user        the password hashes
//
// The answers decide which of four things the next statement is. INTO OUTFILE
// writes a web shell into a document root. LOAD_FILE reads a key off the server.
// LOAD DATA LOCAL INFILE asks the *client* for a file, which is the one that
// works through a firewall. CREATE FUNCTION ... SONAME installs a shared object.
//
// A refusal ends that at the greeting. Answering it says which of the four they
// were reaching for, and that is the whole value here: the reconnaissance is
// indistinguishable from an application's own queries until you see what follows
// it.
//
// Three things are deliberate.
//
// **It never asks the client for a file.** LOAD DATA LOCAL INFILE is answered
// with an error, not with the request packet the protocol allows. A fabrication
// that sent that request would be attacking the client that connected to it --
// and the clients that connect to a honeypot include the estate's own scanners.
//
// **It does not sleep.** SELECT SLEEP(60) is answered immediately with a zero.
// Honouring it would make the fabrication a way to hold this listener's
// resources, a request at a time, for as long as the visitor liked.
//
// **A password is never recorded.** The login packet's user name is an identity
// and is kept; the authentication response is measured and discarded.

// dbProfile is a fabricated server's identity and shape.
type dbProfile struct {
	version   string
	flavour   string
	databases []string
	// tables are `database.table` names.
	tables []string
}

// The built-in profiles. The versions are ones in wide use rather than the
// newest: a decoy claiming a release from last week is one nobody believes on an
// estate that patches quarterly.
var dbProfiles = map[string]dbProfile{
	"generic-mysql": {
		version: "8.0.36-0ubuntu0.22.04.1", flavour: "mysql",
		databases: []string{"information_schema", "mysql", "performance_schema", "sys", "appdb"},
		tables: []string{
			"appdb.users", "appdb.sessions", "appdb.orders", "appdb.order_items",
			"appdb.audit_log", "appdb.settings",
		},
	},
	"mariadb": {
		version: "10.11.6-MariaDB-0+deb12u1", flavour: "mariadb",
		databases: []string{"information_schema", "mysql", "performance_schema", "billing"},
		tables: []string{
			"billing.customers", "billing.invoices", "billing.invoice_lines",
			"billing.payments", "billing.ledger",
		},
	},
	"wordpress": {
		version: "5.7.44-0ubuntu0.20.04.1", flavour: "mysql",
		databases: []string{"information_schema", "mysql", "performance_schema", "wordpress"},
		tables: []string{
			"wordpress.wp_users", "wordpress.wp_usermeta", "wordpress.wp_posts",
			"wordpress.wp_postmeta", "wordpress.wp_options", "wordpress.wp_comments",
		},
	},
}

// DefaultProfile is the profile a section that names none gets.
const DefaultProfile = "generic-mysql"

// Profiles are the shapes a fabricated server can have, for validation.
func Profiles() []string {
	out := make([]string, 0, len(dbProfiles))
	for name := range dbProfiles {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

// The tripwires that need no configuring: the escalation chain, and nothing
// else. Each is matched as a whole word against the statement text, so a column
// named "sleepy" does not trip SLEEP.
var builtInTripwires = []string{
	"mysql.user", "load_file", "infile", "outfile", "dumpfile", "soname",
	"secure_file_priv", "sleep", "benchmark", "sys_exec", "sys_eval",
	"user_privileges", "master.info",
}

// The synthetic addresses the gauges live at, one per fabricated number.
// deception.Values answers by address, and the bands below give each its range.
const (
	addrThreads   = 1
	addrQueryRate = 2
)

// decoy is the fabricated server.
type decoy struct {
	// whole says the listener is a honeypot: every statement is answered here
	// and there is no server behind it.
	whole       bool
	profile     string
	version     string
	flavour     string
	databases   []string
	tables      []string
	trip        map[string]bool
	requireAuth bool
	started     time.Time
	period      time.Duration
	values      *deception.Values
	policy      *deception.Policy
	now         func() time.Time
}

// newDecoy builds the fabrication, or nil where the section is absent or off.
func newDecoy(c *config.MySQLDeception, name string) (*decoy, error) {
	if c == nil || (c.Enabled != nil && !*c.Enabled) {
		return nil, nil
	}
	p, ok := dbProfiles[c.Profile]
	if !ok {
		if c.Profile != "" {
			return nil, fmt.Errorf("deception.profile: %q is not a profile", c.Profile)
		}
		p = dbProfiles[DefaultProfile]
	}
	d := &decoy{
		whole:       c.Mode == "decoy",
		profile:     c.Profile,
		version:     orString(c.Version, p.version),
		flavour:     p.flavour,
		databases:   append([]string(nil), p.databases...),
		tables:      append([]string(nil), p.tables...),
		requireAuth: c.RequireAuth,
		started:     time.Now(),
		trip:        map[string]bool{},
		now:         time.Now,
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
	// Sorted, because SHOW DATABASES and SHOW TABLES answer in order and a
	// second read that came back differently would be a server whose catalogue
	// had changed between two statements.
	slices.Sort(d.databases)
	d.databases = slices.Compact(d.databases)
	slices.Sort(d.tables)
	d.tables = slices.Compact(d.tables)
	for _, t := range builtInTripwires {
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
		{Lo: addrThreads, Hi: addrThreads, Shape: deception.ShapeAnalogue, Min: 2, Max: 24},
		{Lo: addrQueryRate, Hi: addrQueryRate, Shape: deception.ShapeAnalogue, Min: 150, Max: 400},
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

// tripped says whether a statement mentions something nothing legitimate asks a
// fabricated database for.
//
// The test is per word rather than per substring, because a column named
// "sleepy" is not SLEEP and a table named "outfiles" is not INTO OUTFILE. The
// one exception is a qualified name like mysql.user, which is two words joined
// by a dot and is matched as written.
func (d *decoy) tripped(text string) bool {
	if d == nil {
		return false
	}
	for _, w := range identifiers(text) {
		if d.trip[w] {
			return true
		}
	}
	return false
}

// identifiers is the words of a statement, lower-cased, with a qualified name
// kept whole as well as split.
func identifiers(text string) []string {
	var out []string
	var b strings.Builder
	flush := func() {
		if b.Len() == 0 {
			return
		}
		w := strings.ToLower(b.String())
		out = append(out, w)
		// A qualified name is also its parts, so a tripwire naming just "user"
		// matches mysql.user -- and one naming mysql.user does not match a
		// column called user.
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
		Listener: t.name, Kind: "mysql", Mode: modeName(d.whole),
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

// greeting is the packet a fabricated server sends before anything is asked of
// it, and the one every scanner reads.
//
// CLIENT_SSL is deliberately not offered. The negotiation is mid-handshake on
// this protocol -- the client answers the greeting with a short packet and then
// the connection becomes TLS -- and a fabrication that offered it and could not
// complete it would fail in a way a scanner notices. An unencrypted server on
// 3306 is also what the scanning is looking for.
func (d *decoy) greeting(threadID uint32) []byte {
	caps := wire.CapLongPassword | wire.CapFoundRows | wire.CapLongFlag |
		wire.CapConnectWithDB | wire.CapProtocol41 | wire.CapTransactions |
		wire.CapSecureConnection | wire.CapPluginAuth | wire.CapConnectAttrs |
		wire.CapPluginAuthLenEnc | wire.CapDeprecateEOF
	plugin := "caching_sha2_password"
	charset := byte(255)
	if d.flavour == "mariadb" {
		// MariaDB has never shipped caching_sha2_password, and a MariaDB version
		// string offering it is a contradiction a fingerprinting tool checks.
		plugin = "mysql_native_password"
		charset = 33
	}
	return wire.Greet(wire.GreetingOptions{
		Version: d.version, ThreadID: threadID, Salt: d.salt(threadID),
		Caps: caps, Charset: charset, AuthPlugin: plugin,
	})
}

// salt is the twenty-octet challenge. It is a nonce rather than a secret -- the
// fabrication does not check the answer -- but it has to look like one and it
// must not contain a NUL, which would truncate the field it sits in.
func (d *decoy) salt(threadID uint32) []byte {
	out := make([]byte, 20)
	h := deception.SeedFor(strconv.FormatUint(uint64(threadID), 10)+d.version) | 1
	for i := range out {
		h ^= h << 13
		h ^= h >> 7
		h ^= h << 17
		// The printable range, which is what a real server's challenge is: the
		// protocol allows any octet but every implementation uses these, and a
		// challenge full of control characters is a tell.
		out[i] = byte(33 + h%94)
	}
	return out
}

// The fabricated answers.
//
// Each is what a real server sends for that statement, because the *shape* of a
// reply is what a client library reads and what a fingerprinting tool checks. The
// statements recognised by name are the reconnaissance ones -- the version, the
// data directory, the catalogue, the grants -- because those are the ones whose
// answers decide what the visitor tries next, and getting one of them wrong is
// what ends the pretence.

// answer builds the reply to one command, starting at sequence 1 (the command was
// packet 0), or reports that the fabrication has none.
func (d *decoy) answer(cmd byte, payload []byte, se *decoySession) ([]byte, bool) {
	if d == nil {
		return nil, false
	}
	switch cmd {
	case wire.ComQuit:
		return nil, true
	case wire.ComPing:
		return wire.OKPacket(1, 0, 0, 0, ""), true
	case wire.ComInitDB:
		db := string(payload)
		if !slices.Contains(d.databases, db) {
			return wire.ErrPacket(1, 1049, "42000", "Unknown database '"+wire.Clip(db)+"'"), true
		}
		se.database = db
		return wire.OKPacket(1, 0, 0, 0, ""), true
	case wire.ComQuery:
		return d.query(string(payload), se), true
	case wire.ComFieldList:
		return wire.EOFPacket(1, 0), true
	case wire.ComStatistics:
		// A one-line status string rather than a result set, which is what this
		// command answers -- the one place in the protocol where it does.
		return wire.Frame(1, []byte(d.statistics())), true
	case wire.ComChangeUser:
		return wire.OKPacket(1, 0, 0, 0, ""), true
	case wire.ComResetConnection:
		se.database = ""
		return wire.OKPacket(1, 0, 0, 0, ""), true
	case wire.ComSetOption:
		return wire.EOFPacket(1, 0), true
	}
	// The prepared-statement and replication commands, and anything else. A
	// fabrication that answered a prepared statement would have to keep the
	// handle and answer the execute, so it says so instead -- with the real
	// wording, which is what a library reports.
	return wire.ErrPacket(1, 1047, "08S01",
		"Unknown command"), true
}

// query answers one COM_QUERY.
//
// The recognisers come before the classifier, because the reconnaissance
// statements are all SELECTs and SHOWs and a policy about kinds cannot tell
// `SELECT @@datadir` from `SELECT id FROM users`. What the classifier is for is
// everything else: whether the statement writes, and whether it is a shape this
// fabrication should answer at all.
func (d *decoy) query(text string, se *decoySession) []byte {
	lower := strings.ToLower(strings.TrimSpace(text))
	eof := se.deprecateEOF

	// LOAD DATA LOCAL INFILE, first and refused. The protocol lets a server
	// answer it with a request for the file, and the client obeys: a
	// fabrication that did that would be attacking whoever connected to it,
	// which on a honeypot includes the estate's own scanners.
	if strings.HasPrefix(lower, "load data") && strings.Contains(lower, " local ") {
		return wire.ErrPacket(1, 1148, "42000",
			"The used command is not allowed with this MySQL version")
	}
	// The file-writing and file-reading statements. secure_file_priv is reported
	// as NULL below, so the refusal these get is the one a server with it set
	// would give -- which is consistent, and is also the answer that says the
	// visitor has learned something true.
	if strings.Contains(lower, "outfile") || strings.Contains(lower, "dumpfile") {
		return wire.ErrPacket(1, 1290, "HY000",
			"The MySQL server is running with the --secure-file-priv option so it cannot execute this statement")
	}
	if strings.Contains(lower, "create function") && strings.Contains(lower, "soname") {
		return wire.ErrPacket(1, 1126, "HY000",
			"Can't open shared library")
	}
	// SLEEP and BENCHMARK, answered rather than honoured: waiting would make
	// this listener's resources something a visitor can hold, a statement at a
	// time, for as long as they like.
	// LOAD_FILE, which reads a file on the server. A server whose
	// secure_file_priv is NULL -- which is what this fabrication reports --
	// answers NULL rather than an error, so that is what it answers: the
	// visitor learns something true, and the two answers agree with each other.
	if calls(lower, "load_file(") {
		return d.oneNull("load_file()", eof)
	}
	if calls(lower, "sleep(") {
		return d.oneValue("SLEEP(0)", "0", eof)
	}
	if calls(lower, "benchmark(") {
		return d.oneValue("BENCHMARK(0,0)", "0", eof)
	}
	// The tables an unprivileged account cannot read, and the one everybody asks
	// for first. A real server answers 1142 here rather than an empty set, and
	// the difference matters: an empty set says the table is there and has no
	// rows, which is not a thing mysql.user ever is. The refusal is also the
	// answer that keeps the pretence consistent with the grants reported above.
	if table, ok := privileged(lower); ok {
		return wire.ErrPacket(1, wire.StatementDenied, "42000",
			"SELECT command denied to user 'app'@'localhost' for table '"+wire.Clip(table)+"'")
	}
	if reply, ok := d.recognise(lower, eof); ok {
		return reply
	}
	stmts, ok := sqlkind.Statements(sqlkind.MySQL, text, 8)
	if !ok || len(stmts) == 0 {
		return wire.ErrPacket(1, 1064, "42000",
			"You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version")
	}
	switch stmts[0].Kind {
	case sqlkind.KindSelect, sqlkind.KindShow, sqlkind.KindExplain:
		// A SELECT the recognisers did not know. An empty result set is the
		// honest answer: the fabrication is a surface rather than a database, and
		// inventing rows for an arbitrary projection would mean inventing a
		// schema to match it.
		return d.emptySet(eof)
	case sqlkind.KindEmpty:
		return wire.OKPacket(1, 0, 0, 0, "")
	default:
		// Writes, DDL, GRANT, transaction control: accepted, and nothing
		// happens. The reply is what makes the visitor go on to the statement
		// that says what they were doing.
		return wire.OKPacket(1, 0, 0, 0, "")
	}
}

// recognise answers the statements whose answers decide what a visitor tries
// next.
func (d *decoy) recognise(lower string, eof bool) ([]byte, bool) {
	switch {
	case lower == "select 1", lower == "select 1;", lower == "/* ping */ select 1":
		return d.oneValue("1", "1", eof), true
	case strings.HasPrefix(lower, "show databases"), strings.HasPrefix(lower, "show schemas"):
		rows := make([][]*string, 0, len(d.databases))
		for _, db := range d.databases {
			rows = append(rows, []*string{wire.Str(db)})
		}
		return d.set([]wire.Column{{Name: "Database", Table: "SCHEMATA", Type: wire.TypeVarString, Length: 64}},
			rows, eof), true
	case strings.HasPrefix(lower, "show tables"):
		return d.showTables(lower, eof), true
	case strings.HasPrefix(lower, "show variables"):
		return d.showVariables(lower, eof), true
	case strings.HasPrefix(lower, "show grants"):
		return d.oneValue("Grants for app@localhost",
			"GRANT SELECT, INSERT, UPDATE, DELETE ON `"+d.appDatabase()+"`.* TO `app`@`localhost`", eof), true
	case strings.HasPrefix(lower, "show engines"):
		return d.set([]wire.Column{
			{Name: "Engine", Type: wire.TypeVarString, Length: 64},
			{Name: "Support", Type: wire.TypeVarString, Length: 8},
		}, [][]*string{
			{wire.Str("InnoDB"), wire.Str("DEFAULT")},
			{wire.Str("MEMORY"), wire.Str("YES")},
			{wire.Str("MyISAM"), wire.Str("YES")},
		}, eof), true
	case strings.HasPrefix(lower, "show processlist"):
		return d.processList(eof), true
	case strings.HasPrefix(lower, "show warnings"), strings.HasPrefix(lower, "show errors"):
		return d.emptySet(eof), true
	}
	// The expression selects, which is how every scanner asks. They arrive in
	// every spelling -- SELECT VERSION(), SELECT @@version, SELECT
	// @@global.version -- so they are matched by what they mention rather than by
	// their exact text.
	for _, v := range d.variables() {
		if mentions(lower, v.name) {
			label := v.name
			if strings.Contains(lower, "@@") {
				label = "@@" + v.name
			}
			if v.value == nil {
				return d.oneNull(label, eof), true
			}
			return d.oneValue(label, *v.value, eof), true
		}
	}
	switch {
	case mentions(lower, "version"):
		return d.oneValue("version()", d.version, eof), true
	case mentions(lower, "database"), mentions(lower, "schema"):
		return d.oneValue("database()", d.appDatabase(), eof), true
	case mentions(lower, "user"), mentions(lower, "current_user"), mentions(lower, "system_user"):
		return d.oneValue("user()", "app@localhost", eof), true
	case mentions(lower, "connection_id"):
		return d.oneValue("connection_id()", strconv.Itoa(d.gauge(addrThreads)), eof), true
	}
	return nil, false
}

// mentions says whether a statement names an identifier, as a whole word.
func mentions(lower, name string) bool {
	// The qualified forms -- @@global.version, @@session.sql_mode -- need no case
	// of their own: identifiers already yields a qualified name's parts beside
	// the whole, so "version" is among the words of "@@global.version".
	for _, w := range identifiers(lower) {
		if w == name {
			return true
		}
	}
	return false
}

// calls says whether a statement calls a function, by name and open bracket.
//
// The bracket is part of the test: a column named "sleep" is not a call to
// SLEEP, and a fabrication that answered zero to "SELECT sleep FROM naps" would
// be answering something nobody asked.
func calls(lower, fn string) bool {
	return strings.Contains(lower, fn)
}

// variable is one fabricated system variable.
type variable struct {
	name  string
	value *string
}

// variables is what SHOW VARIABLES answers and what every @@ select reads.
//
// The values are the ones a default package install has, because that is what a
// server nobody has hardened looks like -- which is the server being
// impersonated. secure_file_priv is NULL rather than empty, which is the value
// that says "no file statements at all": it is consistent with the refusals the
// file statements get above, and it is a true thing for the visitor to learn.
func (d *decoy) variables() []variable {
	datadir := "/var/lib/mysql/"
	basedir := "/usr/"
	if d.flavour == "mariadb" {
		basedir = "/usr"
	}
	return []variable{
		{"version", wire.Str(d.version)},
		{"version_comment", wire.Str(d.versionComment())},
		{"version_compile_os", wire.Str("Linux")},
		{"version_compile_machine", wire.Str("x86_64")},
		{"datadir", wire.Str(datadir)},
		{"basedir", wire.Str(basedir)},
		{"secure_file_priv", nil},
		{"hostname", wire.Str("db01")},
		{"port", wire.Str("3306")},
		{"socket", wire.Str("/var/run/mysqld/mysqld.sock")},
		{"sql_mode", wire.Str("ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE," +
			"NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION")},
		{"character_set_server", wire.Str("utf8mb4")},
		{"collation_server", wire.Str("utf8mb4_0900_ai_ci")},
		{"max_allowed_packet", wire.Str("67108864")},
		{"local_infile", wire.Str("OFF")},
		{"general_log", wire.Str("OFF")},
		{"log_bin", wire.Str("OFF")},
		{"have_ssl", wire.Str("DISABLED")},
		{"transaction_isolation", wire.Str("REPEATABLE-READ")},
		{"time_zone", wire.Str("SYSTEM")},
		{"innodb_version", wire.Str(strings.SplitN(d.version, "-", 2)[0])},
	}
}

func (d *decoy) versionComment() string {
	if d.flavour == "mariadb" {
		return "Debian 12"
	}
	return "(Ubuntu)"
}

// appDatabase is the schema a visitor is told they are in: the first one that is
// not a system schema, which is what an application connects to.
func (d *decoy) appDatabase() string {
	for _, db := range d.databases {
		switch db {
		case "information_schema", "mysql", "performance_schema", "sys":
			continue
		}
		return db
	}
	return "information_schema"
}

func (d *decoy) showVariables(lower string, eof bool) []byte {
	pattern := ""
	if at := strings.Index(lower, " like "); at >= 0 {
		pattern = strings.Trim(strings.TrimSpace(lower[at+6:]), "'\";")
	}
	cols := []wire.Column{
		{Name: "Variable_name", Table: "session_variables", Type: wire.TypeVarString, Length: 64},
		{Name: "Value", Table: "session_variables", Type: wire.TypeVarString, Length: 1024},
	}
	vars := d.variables()
	rows := make([][]*string, 0, len(vars))
	for _, v := range vars {
		if pattern != "" && !likeMatch(pattern, v.name) {
			continue
		}
		value := v.value
		if value == nil {
			// SHOW VARIABLES reports an unset variable as an empty string, not
			// as NULL: the statement's result set has no NULLs in it, which is a
			// difference from the @@ select above and one a tool would notice.
			value = wire.Str("")
		}
		rows = append(rows, []*string{wire.Str(v.name), value})
	}
	return d.set(cols, rows, eof)
}

func (d *decoy) showTables(lower string, eof bool) []byte {
	db := d.appDatabase()
	if at := strings.Index(lower, " from "); at >= 0 {
		db = strings.Trim(strings.Fields(lower[at+6:])[0], "`;")
	} else if at := strings.Index(lower, " in "); at >= 0 {
		db = strings.Trim(strings.Fields(lower[at+4:])[0], "`;")
	}
	rows := make([][]*string, 0, len(d.tables))
	for _, t := range d.tables {
		schema, name, ok := strings.Cut(t, ".")
		if !ok {
			schema, name = d.appDatabase(), t
		}
		if !strings.EqualFold(schema, db) {
			continue
		}
		rows = append(rows, []*string{wire.Str(name)})
	}
	return d.set([]wire.Column{
		{Name: "Tables_in_" + db, Table: "TABLE_NAMES", Type: wire.TypeVarString, Length: 64},
	}, rows, eof)
}

// processList is what SHOW PROCESSLIST answers: this connection, and a handful of
// the application's. A server with exactly one connection on it is a server
// nobody uses, which is a tell.
func (d *decoy) processList(eof bool) []byte {
	cols := []wire.Column{
		{Name: "Id", Type: wire.TypeLongLong, Length: 21},
		{Name: "User", Type: wire.TypeVarString, Length: 32},
		{Name: "Host", Type: wire.TypeVarString, Length: 64},
		{Name: "db", Type: wire.TypeVarString, Length: 64},
		{Name: "Command", Type: wire.TypeVarString, Length: 16},
		{Name: "Time", Type: wire.TypeLong, Length: 7},
		{Name: "State", Type: wire.TypeVarString, Length: 64},
		{Name: "Info", Type: wire.TypeVarString, Length: 255},
	}
	n := d.gauge(addrThreads)
	rows := make([][]*string, 0, n)
	for i := 0; i < n; i++ {
		db := d.appDatabase()
		rows = append(rows, []*string{
			wire.Str(strconv.Itoa(100 + i*3)), wire.Str("app"),
			wire.Str("10.0.16." + strconv.Itoa(20+i%8) + ":" + strconv.Itoa(40000+i*17)),
			wire.Str(db), wire.Str("Sleep"), wire.Str(strconv.Itoa(1 + i*7%300)),
			wire.Str(""), nil,
		})
	}
	return d.set(cols, rows, eof)
}

// statistics is COM_STATISTICS's one-line answer, which is the only reply in the
// protocol that is neither a result set nor an OK.
func (d *decoy) statistics() string {
	up := int(d.now().Sub(d.started) / time.Second)
	if up < 0 {
		up = 0
	}
	periods := int64(d.now().Sub(d.started) / d.period)
	if periods < 0 {
		periods = 0
	}
	queries := 1000 + periods*int64(d.gauge(addrQueryRate))
	perSecond := 0.0
	if up > 0 {
		perSecond = float64(queries) / float64(up)
	}
	return fmt.Sprintf("Uptime: %d  Threads: %d  Questions: %d  Slow queries: 0  Opens: %d  "+
		"Flush tables: 3  Open tables: %d  Queries per second avg: %.3f",
		up, d.gauge(addrThreads), queries, 40+len(d.tables), len(d.tables), perSecond)
}

// gauge is one of the fabricated numbers, bounded by its band.
func (d *decoy) gauge(addr int) int {
	v := int(d.values.Register(0, addr))
	if v < 1 {
		return 1
	}
	return v
}

// set builds a result set at sequence 1.
func (d *decoy) set(cols []wire.Column, rows [][]*string, eof bool) []byte {
	out, _ := wire.ResultSet(1, cols, rows, eof)
	return out
}

// oneValue is the commonest result set on this protocol: one column, one row.
func (d *decoy) oneValue(name, value string, eof bool) []byte {
	return d.set([]wire.Column{{Name: name, Type: wire.TypeVarString, Length: 255}},
		[][]*string{{wire.Str(value)}}, eof)
}

// oneNull is the same with a NULL in it, which is not the same reply as an empty
// string and which a client library distinguishes.
func (d *decoy) oneNull(name string, eof bool) []byte {
	return d.set([]wire.Column{{Name: name, Type: wire.TypeVarString, Length: 255}},
		[][]*string{{nil}}, eof)
}

// emptySet is a result set with one column and no rows, which is what a SELECT
// that matched nothing returns -- and is not the same thing as an error.
func (d *decoy) emptySet(eof bool) []byte {
	return d.set([]wire.Column{{Name: "?", Type: wire.TypeVarString, Length: 255}}, nil, eof)
}

// likeMatch is SQL LIKE: % for any run, _ for one character, and no other
// metacharacters. It is written out because a SQL LIKE is not a glob -- * and ?
// are literals here, and a matcher that treated them as wildcards would list
// variables a pattern did not ask for.
func likeMatch(pattern, s string) bool {
	pattern, s = strings.ToLower(pattern), strings.ToLower(s)
	for len(pattern) > 0 {
		switch pattern[0] {
		case '%':
			for len(pattern) > 1 && pattern[1] == '%' {
				pattern = pattern[1:]
			}
			for i := 0; i <= len(s); i++ {
				if likeMatch(pattern[1:], s[i:]) {
					return true
				}
			}
			return false
		case '_':
			if len(s) == 0 {
				return false
			}
			pattern, s = pattern[1:], s[1:]
		default:
			if len(s) == 0 || s[0] != pattern[0] {
				return false
			}
			pattern, s = pattern[1:], s[1:]
		}
	}
	return len(s) == 0
}

// decoySession is the state a fabricated server keeps about one connection.
//
// There are only three things, and each is one a client would notice the absence
// of: which database it selected, whether it negotiated CLIENT_DEPRECATE_EOF
// (which changes the shape of every result set), and the thread identifier the
// greeting gave it.
type decoySession struct {
	database     string
	deprecateEOF bool
	threadID     uint32
	user         string
}

// serveDecoy runs a connection on a listener that is nothing but a fabricated
// server.
//
// The bounds still apply -- the handshake timeout, the idle timeout, the reader's
// own message bound, the session limit -- because a honeypot is still a service
// on a port and a visitor who sends a million statements is still holding
// resources.
func (t *server) serveDecoy(se *session) {
	d := t.decoy
	ds := &decoySession{threadID: uint32(time.Now().UnixNano() & 0x7FFFFFFF)} //nolint:gosec // masked to the positive range
	if err := se.writeClient(d.greeting(ds.threadID)); err != nil {
		return
	}
	rd := wire.NewReader(se.client, t.policy.MaxMessage())
	rd.Lax()
	// The login packet, which carries the user name and the capabilities. The
	// user name is an identity and is recorded; the authentication response is
	// measured and discarded.
	if hs := t.mc.HandshakeTimeout.D(); hs > 0 {
		_ = se.client.SetReadDeadline(time.Now().Add(hs))
	}
	p, err := rd.Next()
	if err != nil {
		return
	}
	login, err := wire.ParseLogin(p.Payload)
	if err == nil {
		ds.user = login.User
		ds.database = login.Database
		ds.deprecateEOF = login.Wants(wire.CapDeprecateEOF)
	}
	t.recordDeception(se, ds, "login", loginSummary(login, err), false)
	if d.requireAuth {
		// The refusal a server with no matching account gives. It is off by
		// default: accepting is what lets the reconnaissance happen at all, and
		// an account that works is what the scanning is looking for.
		_ = se.writeClient(wire.ErrPacket(p.Seq+1, wire.AccessDenied, "28000",
			"Access denied for user '"+wire.Clip(ds.user)+"'@'"+se.ip.String()+"' (using password: YES)"))
		return
	}
	if err := se.writeClient(wire.OKPacket(p.Seq+1, 0, 0, 0, "")); err != nil {
		return
	}
	for {
		if idle := t.mc.IdleTimeout.D(); idle > 0 {
			_ = se.client.SetReadDeadline(time.Now().Add(idle))
		}
		rd.Reset()
		p, err := rd.Next()
		if err != nil {
			return
		}
		cmd, payload, ok := p.Command()
		if !ok {
			return
		}
		reply, answered := d.answer(cmd, payload, ds)
		detail := wire.CommandName(cmd)
		if cmd == wire.ComQuery {
			detail = wire.Clip(string(payload))
		}
		t.recordDeception(se, ds, "decoy", detail, cmd == wire.ComQuery && d.tripped(string(payload)))
		if !answered || len(reply) == 0 {
			// COM_QUIT, which the real server answers by closing.
			return
		}
		if err := se.writeClient(reply); err != nil {
			return
		}
	}
}

// loginSummary is what of a login packet goes into the record.
//
// The password is never among it. A log holding every credential sprayed at the
// estate is a list of the estate's own credentials as often as not, so the
// authentication response is measured and discarded -- which is still useful,
// because its length says which plugin the client used and an empty one says
// there was no password at all.
func loginSummary(l *wire.Login, err error) string {
	if l == nil {
		return "unreadable login: " + err.Error()
	}
	var b strings.Builder
	b.WriteString("user ")
	b.WriteString(wire.Clip(l.User))
	if l.Database != "" {
		b.WriteString(", database ")
		b.WriteString(wire.Clip(l.Database))
	}
	if l.Plugin != "" {
		b.WriteString(", plugin ")
		b.WriteString(wire.Clip(l.Plugin))
	}
	if p := l.Attrs["_client_name"]; p != "" {
		b.WriteString(", client ")
		b.WriteString(wire.Clip(p))
	}
	return b.String()
}

// recordDeception notes one fabricated answer where an operator looks.
func (t *server) recordDeception(se *session, ds *decoySession, why, detail string, tripped bool) {
	d := t.decoy
	d.policy.Record(se.ip, tripped, time.Now())
	t.host.Counters().MySQLDeceived.Add(1)
	event := "mysql_deceived"
	if tripped {
		t.host.Counters().MySQLTripwire.Add(1)
		event = "mysql_tripwire"
		// The tripwire feeds the ban ladder and the ordinary fabricated
		// exchange does not: a statement reaching for a file or a credential
		// is something every other listener would want to act on, while
		// banning the exchange itself would end the collection that was about
		// to tell you more.
		if bl := t.host.Bans(); bl != nil && se.ip.IsValid() {
			bl.Observe(se.ip, "mysql_tripwire")
		}
	}
	attrs := []any{
		"listener", t.name, "client_ip", se.ip.String(), "reason", why,
		"mode", modeName(d.whole),
	}
	if ds != nil && ds.user != "" {
		attrs = append(attrs, "db_user", ds.user)
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
func (se *session) deceive(cmd byte, payload []byte, seq byte, why string) bool {
	t := se.t
	d := t.decoy
	if d == nil || !d.admits(se.ip) {
		return false
	}
	se.mu.Lock()
	ds := &decoySession{database: se.database, user: se.user}
	se.mu.Unlock()
	ds.deprecateEOF = se.clientCaps&wire.CapDeprecateEOF != 0
	reply, ok := d.answer(cmd, payload, ds)
	if !ok || len(reply) == 0 {
		return false
	}
	detail := wire.CommandName(cmd)
	if cmd == wire.ComQuery {
		detail = wire.Clip(string(payload))
	}
	t.recordDeception(se, ds, why, detail, cmd == wire.ComQuery && d.tripped(string(payload)))
	// The reply is built at sequence 1 and the client is waiting for the packet
	// after the one it sent, so it is renumbered: a client library checks the
	// numbering and a gap makes it report a protocol error rather than the rows.
	if err := se.writeClient(renumber(reply, seq+1)); err != nil {
		return false
	}
	return true
}

// renumber rewrites the sequence numbers of a built reply so that it continues
// the client's own count.
func renumber(reply []byte, first byte) []byte {
	out := append([]byte(nil), reply...)
	at, seq := 0, first
	for at+4 <= len(out) {
		n := int(out[at]) | int(out[at+1])<<8 | int(out[at+2])<<16
		out[at+3] = seq
		seq++
		at += 4 + n
		if at > len(out) {
			break
		}
	}
	return out
}

// privileged names the table a statement is reaching for when it is one an
// ordinary application account cannot read.
//
// These are the objects a credential dump goes to, and the list is short because
// it is the list of places MySQL keeps authentication material. Everything else
// under mysql. is covered by the schema test.
func privileged(lower string) (string, bool) {
	for _, w := range identifiers(lower) {
		schema, name, ok := strings.Cut(w, ".")
		if !ok {
			continue
		}
		switch schema {
		case "mysql":
			return "mysql." + name, true
		case "information_schema":
			switch name {
			case "user_privileges", "schema_privileges", "table_privileges",
				"column_privileges", "processlist", "innodb_sys_tables", "files":
				return "information_schema." + name, true
			}
		case "performance_schema":
			if strings.HasPrefix(name, "accounts") || strings.HasPrefix(name, "users") ||
				strings.HasPrefix(name, "hosts") {
				return "performance_schema." + name, true
			}
		}
	}
	return "", false
}
