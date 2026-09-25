package respwire

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

// multibulk builds a command the way a client library sends one.
func multibulk(parts ...string) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "*%d\r\n", len(parts))
	for _, p := range parts {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(p), p)
	}
	return b.Bytes()
}

func read(t *testing.T, wire []byte) (*Command, error) {
	t.Helper()
	return NewReader(bytes.NewReader(wire), 0, 0, 0).Next()
}

// The ordinary path, and the folding the whole policy rests on: Redis compares a
// command name without regard to case, so a relay that held two spellings would
// match neither reliably.
func TestACommandIsReadAndItsNameFolded(t *testing.T) {
	for _, spelling := range []string{"GET", "get", "Get", "gEt"} {
		c, err := read(t, multibulk(spelling, "session:abc"))
		if err != nil {
			t.Fatalf("%q: %v", spelling, err)
		}
		if c.Name != "GET" {
			t.Fatalf("%q read as %q", spelling, c.Name)
		}
		if len(c.Args) != 1 || string(c.Args[0]) != "session:abc" {
			t.Fatalf("%q: args %q", spelling, c.Args)
		}
		if c.Inline {
			t.Fatalf("%q: read as inline", spelling)
		}
	}
	// The *argument* is not folded, because it is a key and Redis keys are
	// case-sensitive. A relay that folded one would apply a prefix policy to a
	// key the server does not have.
	c, err := read(t, multibulk("GET", "Session:ABC"))
	if err != nil {
		t.Fatal(err)
	}
	if string(c.Args[0]) != "Session:ABC" {
		t.Fatalf("the key was folded to %q", c.Args[0])
	}
}

// A subcommand is the whole of what matters on the container commands: CONFIG SET
// writes a file wherever the server can write and CONFIG GET is a read, so a
// policy that could only say CONFIG would have to refuse both or neither.
func TestASubcommandIsReadOnTheCommandsWhereItDecides(t *testing.T) {
	c, err := read(t, multibulk("config", "set", "dir", "/var/spool/cron"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Name != "CONFIG" || c.Sub != "SET" {
		t.Fatalf("%q / %q", c.Name, c.Sub)
	}
	if c.String() != "CONFIG SET" {
		t.Fatalf("names itself %q", c.String())
	}
	// And is not invented where there is none: GET's first argument is a key,
	// and reporting it as a subcommand would put a key in a log line labelled as
	// a command.
	if c, err = read(t, multibulk("GET", "SET")); err != nil {
		t.Fatal(err)
	}
	if c.Sub != "" {
		t.Fatalf("GET grew a subcommand %q", c.Sub)
	}
	if c.String() != "GET" {
		t.Fatalf("names itself %q", c.String())
	}
}

// The inline form is what a human types into netcat and what most exploitation
// scripts send, because it needs no length arithmetic. A relay that read only the
// array form would be blind to exactly the traffic it exists to refuse.
func TestTheInlineFormIsRead(t *testing.T) {
	for _, tc := range []struct {
		wire string
		name string
		args []string
	}{
		{"PING\r\n", "PING", nil},
		{"config set dir /tmp\r\n", "CONFIG", []string{"set", "dir", "/tmp"}},
		{"  GET   a  \r\n", "GET", []string{"a"}},
		// A bare LF, which Redis accepts in an inline command.
		{"FLUSHALL\n", "FLUSHALL", nil},
	} {
		c, err := read(t, []byte(tc.wire))
		if err != nil {
			t.Fatalf("%q: %v", tc.wire, err)
		}
		if !c.Inline {
			t.Fatalf("%q: not marked inline", tc.wire)
		}
		if c.Name != tc.name {
			t.Fatalf("%q: name %q", tc.wire, c.Name)
		}
		if len(c.Args) != len(tc.args) {
			t.Fatalf("%q: args %q, want %q", tc.wire, c.Args, tc.args)
		}
		for i := range tc.args {
			if string(c.Args[i]) != tc.args[i] {
				t.Fatalf("%q: arg %d is %q", tc.wire, i, c.Args[i])
			}
		}
	}
	// The subcommand is folded in the inline form too, or a policy would apply
	// to one form and not the other -- which is the form an attacker picks.
	c, err := read(t, []byte("config set dir /tmp\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Sub != "SET" {
		t.Fatalf("inline subcommand read as %q", c.Sub)
	}
}

// The two counts a client chooses, each checked before anything is sized by it.
// A reader that trusted either would allocate what one small message asked for.
func TestTheCountsAreCheckedBeforeAnythingIsAllocated(t *testing.T) {
	for _, tc := range []struct {
		name string
		wire string
		want error
	}{
		{"an element count past the bound", "*99999999\r\n", ErrTooMany},
		{"a bulk length past the bound", "*1\r\n$99999999\r\n", ErrTooMany},
		{"an element count that is not a number", "*fourteen\r\n", ErrProtocol},
		{"a bulk length that is not a number", "*1\r\n$lots\r\n", ErrProtocol},
		{"a count below the protocol's null", "*-7\r\n", ErrProtocol},
		{"a bulk length below the null", "*1\r\n$-7\r\n", ErrProtocol},
	} {
		_, err := read(t, []byte(tc.wire))
		if !errors.Is(err, tc.want) {
			t.Fatalf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
	// And the bound that actually matters: a permitted element count of
	// permitted-length strings multiplies past both.
	var b bytes.Buffer
	fmt.Fprintf(&b, "*%d\r\n", 65)
	b.WriteString("$4\r\nMSET\r\n")
	chunk := strings.Repeat("x", 200_000)
	for i := 0; i < 64; i++ {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(chunk), chunk)
	}
	// Each string is under the default bulk bound and the count is under the
	// default element bound, but together they are over the message bound.
	rd := NewReader(bytes.NewReader(b.Bytes()), 1<<20, 1<<20, 1024)
	if _, err := rd.Next(); !errors.Is(err, ErrTooLong) {
		t.Fatalf("%v, want ErrTooLong -- a count of permitted strings is not a permitted message", err)
	}
}

// A bulk bound above the message bound is not a bound at all: the message check
// would fire first and the configured value would never apply, which reads in a
// log as the wrong limit refusing the request.
func TestABulkBoundAboveTheMessageBoundIsBroughtDown(t *testing.T) {
	rd := NewReader(bytes.NewReader(multibulk("SET", "k", strings.Repeat("v", 5000))),
		1024, 1<<20, 16)
	_, err := rd.Next()
	if !errors.Is(err, ErrTooMany) && !errors.Is(err, ErrTooLong) {
		t.Fatalf("%v", err)
	}
	if rd.maxBulk > rd.max {
		t.Fatalf("maxBulk %d is above max %d", rd.maxBulk, rd.max)
	}
}

// The messages that are not commands. Each would, if accepted, hand the policy
// something it has no opinion about while the server acted on it.
func TestTheMessagesThatAreNotCommands(t *testing.T) {
	for _, tc := range []struct {
		name string
		wire string
	}{
		{"an empty array", "*0\r\n"},
		{"a null array", "*-1\r\n"},
		{"an empty inline command", "\r\n"},
		{"whitespace alone", "   \r\n"},
		{"a header with no CRLF", "*1\r$3\r\nGET\r\n"},
		{"a bulk string not ended by CRLF", "*1\r\n$3\r\nGETX\n"},
		{"an element that is not a bulk string", "*2\r\n$3\r\nGET\r\n:1\r\n"},
		{"a null element inside a command", "*2\r\n$3\r\nGET\r\n$-1\r\n"},
		{"an array header where a bulk string belongs", "*2\r\n$3\r\nGET\r\n*1\r\n"},
	} {
		if _, err := read(t, []byte(tc.wire)); err == nil {
			t.Fatalf("%s was accepted", tc.name)
		}
	}
}

// The raw octets are kept as they arrived, because a relay forwards them
// unchanged. One that re-encoded would be forwarding a message it had built
// rather than the one the client sent -- and any difference between the two is a
// difference between what the relay decided about and what the server runs.
func TestTheRawOctetsAreKeptExactly(t *testing.T) {
	wire := multibulk("SET", "k", "a value with \r\n inside it")
	c, err := read(t, wire)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.Raw, wire) {
		t.Fatalf("raw is %q, want %q", c.Raw, wire)
	}
	// Including an inline command, whose form the relay must not normalise into
	// an array: the server treats the two differently and a policy decided about
	// one of them.
	if c, err = read(t, []byte("PING\r\n")); err != nil {
		t.Fatal(err)
	}
	if string(c.Raw) != "PING\r\n" {
		t.Fatalf("raw is %q", c.Raw)
	}
}

// A pipeline is several commands on one connection, read one at a time, because
// the policy decides about each. A reader that took a pipeline as one message
// would have one decision covering commands it never looked at.
func TestAPipelineIsReadOneCommandAtATime(t *testing.T) {
	var b bytes.Buffer
	b.Write(multibulk("GET", "a"))
	b.Write(multibulk("SET", "b", "1"))
	b.WriteString("PING\r\n")
	b.Write(multibulk("FLUSHALL"))
	rd := NewReader(bytes.NewReader(b.Bytes()), 0, 0, 0)
	var got []string
	for {
		c, err := rd.Next()
		if err != nil {
			break
		}
		got = append(got, c.Name)
	}
	want := []string{"GET", "SET", "PING", "FLUSHALL"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("read %v, want %v", got, want)
	}
}

// Where the keys are, which is the closest this protocol has to the
// database-and-table boundary the SQL kinds leave to GRANT.
func TestTheKeysAreFoundWhereTheSignatureSaysTheyAre(t *testing.T) {
	for _, tc := range []struct {
		parts []string
		keys  []string
	}{
		{[]string{"GET", "a"}, []string{"a"}},
		{[]string{"MGET", "a", "b", "c"}, []string{"a", "b", "c"}},
		// Interleaved: MSET is key, value, key, value, and a reader that took
		// every argument would apply a prefix policy to the values.
		{[]string{"MSET", "a", "1", "b", "2"}, []string{"a", "b"}},
		{[]string{"RENAME", "a", "b"}, []string{"a", "b"}},
		{[]string{"SMOVE", "src", "dst", "member"}, []string{"src", "dst"}},
		// The final argument is a timeout rather than a key.
		{[]string{"BLPOP", "a", "b", "0"}, []string{"a", "b"}},
		// A container command's key is behind its subcommand.
		{[]string{"OBJECT", "ENCODING", "a"}, []string{"a"}},
		{[]string{"XGROUP", "CREATE", "s", "g", "$"}, []string{"s"}},
		// The key count is an argument, and it decides which arguments are keys:
		// a reader that assumed a position would check the script's text.
		{[]string{"EVAL", "return 1", "2", "a", "b", "arg"}, []string{"a", "b"}},
		{[]string{"EVAL", "return 1", "0", "arg1", "arg2"}, nil},
		{[]string{"LMPOP", "2", "a", "b", "LEFT"}, []string{"a", "b"}},
		{[]string{"SINTERCARD", "2", "a", "b", "LIMIT", "3"}, []string{"a", "b"}},
		// And the commands that take none.
		{[]string{"PING"}, nil},
		{[]string{"MULTI"}, nil},
		{[]string{"FLUSHALL"}, nil},
	} {
		c, err := read(t, multibulk(tc.parts...))
		if err != nil {
			t.Fatalf("%v: %v", tc.parts, err)
		}
		keys, known := Keys(c)
		if !known {
			t.Fatalf("%v: the keys were reported unknown", tc.parts)
		}
		if strings.Join(keys, ",") != strings.Join(tc.keys, ",") {
			t.Fatalf("%v: keys %v, want %v", tc.parts, keys, tc.keys)
		}
	}
}

// The commands whose key positions depend on an option are reported unknown
// rather than guessed at.
//
// This is the assertion that keeps the prefix policy honest. A made-up position
// would have the policy checking a STORE option's value, a Lua script's text or a
// timeout -- and passing whatever it was meant to stop, silently.
func TestAnOptionDependentKeyPositionIsReportedUnknown(t *testing.T) {
	for _, parts := range [][]string{
		{"SORT", "mylist", "STORE", "somewhere:else"},
		{"XREAD", "COUNT", "2", "STREAMS", "s1", "s2", "0", "0"},
		{"XREADGROUP", "GROUP", "g", "c", "STREAMS", "s", ">"},
		{"GEORADIUS", "k", "0", "0", "1", "km", "STORE", "elsewhere"},
		{"ZUNIONSTORE", "dest", "2", "a", "b"},
		{"MIGRATE", "h", "6379", "", "0", "100", "KEYS", "a", "b"},
	} {
		c, err := read(t, multibulk(parts...))
		if err != nil {
			t.Fatalf("%v: %v", parts, err)
		}
		if _, known := Keys(c); known {
			t.Fatalf("%v: claimed to know where the keys are", parts)
		}
		// But the command is *known*, which is the distinction: a validator lets
		// an operator name it and a read-only listener judges it on its own
		// terms, rather than it being an unheard-of command.
		if !Known(c.Name) {
			t.Fatalf("%s is not known at all", c.Name)
		}
	}
}

// A key count that disagrees with the arguments is not resolved in either
// direction: one of the two numbers is wrong and there is no way to tell which.
func TestAKeyCountThatDisagreesWithTheArgumentsIsRefused(t *testing.T) {
	for _, parts := range [][]string{
		{"EVAL", "return 1", "5", "a", "b"}, // says five, has two
		{"EVAL", "return 1", "-1", "a"},     // a negative count
		{"EVAL", "return 1", "many", "a"},   // not a number
		{"LMPOP", "9", "a"},                 // says nine, has one
		{"EVAL", "return 1"},                // no count argument at all
	} {
		c, err := read(t, multibulk(parts...))
		if err != nil {
			t.Fatalf("%v: %v", parts, err)
		}
		if keys, known := Keys(c); known {
			t.Fatalf("%v: reported keys %v", parts, keys)
		}
	}
}

// A command this package has never heard of counts as a write.
//
// That is the direction a classifier has to be wrong in: Redis gains commands
// every release and a module adds its own, and one nobody has written down must
// not pass a read-only listener because of it.
func TestAnUnknownCommandCountsAsAWrite(t *testing.T) {
	if Known("JSON.SET") {
		t.Fatal("a module command is in the table")
	}
	if !Writes("JSON.SET") {
		t.Fatal("an unknown command was classified as a read")
	}
	// And the reads that are known stay reads, or read_only would refuse
	// everything and be turned off.
	for _, r := range []string{"GET", "MGET", "EXISTS", "TTL", "HGETALL",
		"LRANGE", "SMEMBERS", "ZRANGE", "PING", "SCAN", "KEYS", "EVAL_RO"} {
		if Writes(r) {
			t.Fatalf("%s was classified as a write", r)
		}
	}
	for _, w := range []string{"SET", "DEL", "EXPIRE", "HSET", "LPUSH", "SADD",
		"ZADD", "FLUSHALL", "CONFIG", "EVAL", "PUBLISH", "XADD"} {
		if !Writes(w) {
			t.Fatalf("%s was classified as a read", w)
		}
	}
}

// The four tables are one statement about each command, and a command in the
// wrong one of them is a hole rather than a typo.
//
// Every name the default allow list or the dangerous set mentions has to be
// nameable in a configuration, or the default would be a list an operator cannot
// reproduce. Nothing may be in both, because that would be a command the
// listener allows by default and refuses even in monitor mode.
func TestTheCommandTablesAgreeWithEachOther(t *testing.T) {
	for _, c := range DefaultCommands() {
		if !Known(c) {
			t.Errorf("the default allow list names %s, which is in no table", c)
		}
		if Dangerous(c) {
			t.Errorf("%s is allowed by default and refused even in monitor mode", c)
		}
	}
	for _, c := range DangerousCommands() {
		if !Known(c) {
			t.Errorf("the dangerous set names %s, which is in no table", c)
		}
	}
	// And the names a configuration may use are exactly the known ones, so a
	// validation error can list them.
	all := CommandNames()
	for _, c := range append(DefaultCommands(), DangerousCommands()...) {
		found := false
		for _, n := range all {
			if n == c {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s cannot be named in a configuration", c)
		}
	}
	// Every name in the table is upper-case, because that is the spelling the
	// reader produces and a lower-case entry would never be matched.
	for _, c := range all {
		if c != upper(c) {
			t.Errorf("%q in the table is not folded", c)
		}
	}
}

// An error reply is a single line and its terminator is the framing, so a CR or
// LF in the text would end the reply early and the rest would be read as another
// one -- a reply the relay never meant to send, built out of a string the client
// chose. That is response splitting with a Redis client library on the receiving
// end.
func TestAnErrorReplyCannotBeSplit(t *testing.T) {
	for _, msg := range []string{
		"key not allowed: a\r\n+OK\r\n",
		"key not allowed: a\nsomething else",
		"key\rnot\nallowed",
		"a\x00b",
	} {
		out := Error("NOPERM", msg)
		if n := bytes.Count(out, []byte("\r\n")); n != 1 {
			t.Fatalf("%q produced %d line endings: %q", msg, n, out)
		}
		if !bytes.HasSuffix(out, []byte("\r\n")) {
			t.Fatalf("%q: %q does not end the reply", msg, out)
		}
		if bytes.ContainsAny(out[:len(out)-2], "\r\n\x00") {
			t.Fatalf("%q left a terminator in the text: %q", msg, out)
		}
	}
	// The kind is sanitised too, and defaults rather than producing "- msg".
	if out := Error("", "no"); !bytes.HasPrefix(out, []byte("-ERR no")) {
		t.Fatalf("%q", out)
	}
	if out := Error("BAD\r\nKIND", "no"); bytes.Count(out, []byte("\r\n")) != 1 {
		t.Fatalf("%q", out)
	}
}

// A clipped string still has to be a string. The bound is in octets and a key can
// be any octets at all, so a naive slice cuts a multi-byte character in half --
// and the result is invalid UTF-8 that a JSON log writer rewrites, a terminal
// draws as a replacement character, and a comparison against a policy's spelling
// no longer matches.
func TestClipCutsOnARuneBoundary(t *testing.T) {
	got := Clip(strings.Repeat("字", MaxString)) // 3 octets per rune
	if !utf8.ValidString(got) {
		t.Fatalf("Clip produced invalid UTF-8: %q", got)
	}
	if len(got) > MaxString+3 {
		t.Fatalf("Clip returned %d octets", len(got))
	}
	if strings.ContainsRune(got, utf8.RuneError) {
		t.Fatalf("Clip produced a replacement character: %q", got)
	}
	if Clip("short") != "short" {
		t.Fatal("a short string was clipped")
	}
}

// A command name is a fixed alphabet, so anything that is not one is refused
// rather than carried.
//
// The name reaches a log line, a counter label and a shadow-mode report, and
// octets that are not text have no business in any of the three. Refusing at the
// reader means every later stage can assume it has a name -- which it could not if
// the reader merely clipped and folded whatever arrived.
func TestSomethingThatCannotBeACommandNameIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  string
	}{
		{"an octet that is not text", "\xcd"},
		{"a name longer than any command", strings.Repeat("k", MaxString*4)},
		{"a name with a space in it", "GET KEY"},
		{"a name with a newline in it", "GET\nSET"},
		{"a name with a NUL in it", "GET\x00"},
		{"a name that is punctuation", "*"},
		{"an empty name", ""},
	} {
		if _, err := read(t, multibulk(tc.got, "a")); err == nil {
			t.Errorf("%s was accepted as a command", tc.name)
		}
		// And in the inline form too, which is the form that is easier to send.
		if _, err := read(t, []byte(tc.got+"\r\n")); err == nil &&
			!strings.ContainsAny(tc.got, " \r\n") {
			t.Errorf("%s was accepted inline", tc.name)
		}
	}
	// A module's command name is not punctuation to be refused: dots and
	// underscores are how every module names its commands.
	for _, ok := range []string{"JSON.SET", "bf.add", "ft.search", "GET",
		"BITFIELD_RO", "EVAL_RO"} {
		if _, err := read(t, multibulk(ok, "a")); err != nil {
			t.Errorf("%s was refused: %v", ok, err)
		}
	}
}

// A key long enough to be clipped is clipped when it reaches a policy or a log
// line, and *not* before it is forwarded.
//
// Those are two different needs and conflating them would break one of them: a
// clipped key on the wire is a different key, so the relay would decide about one
// and the server would act on another.
func TestAKeyIsClippedForTheLogAndNotForTheWire(t *testing.T) {
	long := strings.Repeat("k", MaxString*4)
	c, err := read(t, multibulk("GET", long))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Args[0]) != len(long) {
		t.Fatalf("the key was clipped to %d octets before forwarding", len(c.Args[0]))
	}
	keys, known := Keys(c)
	if !known || len(keys) != 1 {
		t.Fatalf("keys %v known=%v", keys, known)
	}
	if len(keys[0]) > MaxString+3 {
		t.Fatalf("the key reaching a policy is %d octets", len(keys[0]))
	}
}
