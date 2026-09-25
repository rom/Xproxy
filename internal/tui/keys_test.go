package tui

import (
	"strings"
	"testing"
)

// A read from a terminal is not a key. These are the groupings a real one
// produces: a line pasted into a prompt, a key held down, a cursor key,
// and the Escape that cancels.
func TestSplitKeysCutsAReadIntoKeys(t *testing.T) {
	for _, c := range []struct {
		name string
		read string
		want []string
	}{
		{"one key", "j", []string{"j"}},
		{"a pasted address", "203.0.113.9", strings.Split("203.0.113.9", "")},
		{"a held key", "jjj", []string{"j", "j", "j"}},
		{"a cursor key stays whole", "\x1b[B", []string{"\x1b[B"}},
		{"shift tab stays whole", "\x1b[Z", []string{"\x1b[Z"}},
		{"a cursor key with parameters", "\x1b[1;5A", []string{"\x1b[1;5A"}},
		{"escape on its own", "\x1b", []string{"\x1b"}},
		{"application mode cursor key", "\x1bOA", []string{"\x1bOA"}},
		{"a key after a cursor key", "\x1b[Bj", []string{"\x1b[B", "j"}},
		{"a cursor key after typing", "ab\x1b[A", []string{"a", "b", "\x1b[A"}},
		{"escape then typing", "\x1bab", []string{"\x1b", "a", "b"}},
		{"backspace and return", "a\x7f\r", []string{"a", "\x7f", "\r"}},
		{"a multi-byte rune is one key", "é", []string{"é"}},
		{"an invalid byte is one key", "\xff", []string{"\xff"}},
		// A read can end in the middle of an escape sequence. What is
		// there is one key rather than several, because the alternative
		// is an Escape that cancels a prompt the person was filling in.
		{"a truncated sequence", "\x1b[", []string{"\x1b["}},
		{"a truncated sequence with parameters", "\x1b[1;", []string{"\x1b[1;"}},
		{"a truncated application sequence", "\x1bO", []string{"\x1bO"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := splitKeys([]byte(c.read))
			if len(got) != len(c.want) {
				t.Fatalf("%q split into %d keys (%q), want %d (%q)", c.read, len(got), got, len(c.want), c.want)
			}
			for i := range got {
				if string(got[i]) != c.want[i] {
					t.Errorf("key %d of %q is %q, want %q", i, c.read, got[i], c.want[i])
				}
			}
		})
	}
}

// Whatever the cut, no byte is invented and none is lost.
func TestSplitKeysKeepsEveryByte(t *testing.T) {
	for _, read := range []string{"", "j", "\x1b[Bqp", "b203.0.113.9 1h reason\r", "\x1b\x1b[A\x1bOB\xff\xc3", "é\x7f"} {
		var b strings.Builder
		for _, k := range splitKeys([]byte(read)) {
			if len(k) == 0 {
				t.Fatalf("%q produced an empty key", read)
			}
			b.Write(k)
		}
		if b.String() != read {
			t.Errorf("%q reassembled as %q", read, b.String())
		}
	}
}
