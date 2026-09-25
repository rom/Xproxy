package respwire

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"
)

func FuzzNext(f *testing.F) {
	f.Add(multibulk("GET", "a"))
	f.Add(multibulk("CONFIG", "SET", "dir", "/tmp"))
	f.Add(multibulk("EVAL", "return 1", "2", "a", "b"))
	f.Add([]byte("PING\r\n"))
	f.Add([]byte("*1\r\n$4\r\nPING\r\n"))
	f.Add([]byte("*-1\r\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		rd := NewReader(bytes.NewReader(b), 4096, 512, 32)
		c, err := rd.Next()
		if err != nil {
			return
		}
		// A command always has a name a policy can compare, and it is always
		// folded -- a policy that compared two spellings would be bypassed by
		// the other one.
		if c.Name == "" {
			t.Fatalf("a command with no name: %+v", c)
		}
		if c.Name != upper(c.Name) {
			t.Fatalf("an unfolded name: %q", c.Name)
		}
		if len(c.Name) > MaxString+3 {
			t.Fatalf("an unclipped name: %d octets", len(c.Name))
		}
		if !utf8.ValidString(c.Name) && !utf8.ValidString(Clip(c.Name)) {
			t.Fatalf("a name that is not text: %q", c.Name)
		}
		// A subcommand appears exactly where the table says one can, and never
		// anywhere else: a key reported as a subcommand would put a key into a
		// log line labelled as a command.
		if c.Sub != "" && !takesSub(c.Name) {
			t.Fatalf("%s grew a subcommand %q", c.Name, c.Sub)
		}
		if c.Sub != "" && c.Sub != upper(c.Sub) {
			t.Fatalf("an unfolded subcommand: %q", c.Sub)
		}
		// Raw is what the relay forwards. Whatever it holds must be no longer
		// than the bound the reader was given, or the bound is not one.
		if len(c.Raw) > 4096 {
			t.Fatalf("raw is %d octets past a 4096 bound", len(c.Raw))
		}
		// The keys, when the package claims to know where they are, are clipped
		// and are text: they reach a policy comparison and a log line.
		keys, known := Keys(c)
		if !known {
			return
		}
		for _, k := range keys {
			if len(k) > MaxString+3 {
				t.Fatalf("%s: an unclipped key of %d octets", c.Name, len(k))
			}
			if !utf8.ValidString(k) && utf8.ValidString(string(c.Args[0])) {
				t.Fatalf("%s: a valid argument became invalid text: %q", c.Name, k)
			}
		}
		// A keyless command never reports keys, and a command with keys never
		// reports more than it has arguments.
		if len(keys) > len(c.Args) {
			t.Fatalf("%s: %d keys out of %d arguments", c.Name, len(keys), len(c.Args))
		}
	})
}

// FuzzReadThenForward is the invariant a relay depends on: what the reader hands
// back as Raw, read again, is the same command.
//
// The relay forwards Raw. If reading it produced a *different* command from the
// one the policy decided about, the policy would be deciding about one message
// and the server running another -- which is the whole failure mode a protocol
// relay exists to avoid.
func FuzzReadThenForward(f *testing.F) {
	f.Add(multibulk("SET", "k", "v"))
	f.Add(multibulk("CONFIG", "GET", "*"))
	f.Add([]byte("DEL a b c\r\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		one, err := NewReader(bytes.NewReader(b), 8192, 2048, 64).Next()
		if err != nil {
			return
		}
		two, err := NewReader(bytes.NewReader(one.Raw), 8192, 2048, 64).Next()
		if err != nil {
			t.Fatalf("%s: what the reader kept does not parse: %v (%q)",
				one.Name, err, one.Raw)
		}
		if two.Name != one.Name || two.Sub != one.Sub {
			t.Fatalf("re-read as %s/%s, was %s/%s", two.Name, two.Sub, one.Name, one.Sub)
		}
		if len(two.Args) != len(one.Args) {
			t.Fatalf("%s: re-read with %d arguments, was %d",
				one.Name, len(two.Args), len(one.Args))
		}
		for i := range one.Args {
			if !bytes.Equal(one.Args[i], two.Args[i]) {
				t.Fatalf("%s: argument %d changed", one.Name, i)
			}
		}
	})
}

func FuzzError(f *testing.F) {
	f.Add("NOPERM", "key not allowed")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, kind, msg string) {
		out := Error(kind, msg)
		// One line, ending the reply, with no terminator inside it. Anything
		// else is a second reply the relay did not mean to send, built out of a
		// string a client chose.
		if n := bytes.Count(out, []byte("\r\n")); n != 1 {
			t.Fatalf("%q/%q produced %d line endings", kind, msg, n)
		}
		if !bytes.HasSuffix(out, []byte("\r\n")) {
			t.Fatalf("%q/%q does not end the reply: %q", kind, msg, out)
		}
		body := out[:len(out)-2]
		if bytes.ContainsAny(body, "\r\n\x00") {
			t.Fatalf("%q/%q left a terminator in the text: %q", kind, msg, out)
		}
		if len(body) == 0 || body[0] != TypeError {
			t.Fatalf("%q/%q is not an error reply: %q", kind, msg, out)
		}
		// And a client library has to be able to read a kind out of it, so
		// there is always a non-empty one.
		if fields := strings.Fields(string(body[1:])); len(fields) == 0 {
			t.Fatalf("%q/%q has no error kind: %q", kind, msg, out)
		}
	})
}
