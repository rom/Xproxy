package yara_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/yara"
)

// Every comparison a condition can make, against both of the things it
// can count: how often a pattern occurred and how many bytes have gone
// past.
//
// Worth going through one at a time because a rule written with the
// wrong operator does not fail -- it fires on the wrong streams, or on
// none at all, and a rule that cannot fire looks exactly like a rule
// that decided the traffic was clean.
func TestEveryComparison(t *testing.T) {
	src := `
rule compared {
  strings:
    $a = "ab"
  condition:
    %s
}`
	for _, c := range []struct {
		cond  string
		input string
		want  bool
	}{
		{"#a < 2", "ab", true},
		{"#a < 2", "abab", false},
		{"#a <= 2", "abab", true},
		{"#a <= 2", "ababab", false},
		{"#a > 2", "ababab", true},
		{"#a > 2", "abab", false},
		{"#a >= 3", "ababab", true},
		{"#a >= 3", "abab", false},
		{"#a == 2", "abab", true},
		{"#a == 2", "ababab", false},
		{"#a != 2", "ab", true},
		{"#a != 2", "abab", false},
		{"filesize < 5 and $a", "abab", true},
		{"filesize < 5 and $a", "ababab", false},
		{"filesize <= 4 and $a", "abab", true},
		{"filesize > 4 and $a", "ababab", true},
		{"filesize > 4 and $a", "abab", false},
		{"filesize >= 6 and $a", "ababab", true},
		{"filesize == 4 and $a", "abab", true},
		{"filesize != 4 and $a", "abab", false},
		{"filesize != 4 and $a", "ababab", true},
		// The number forms, which decide what the bound actually is.
		{"filesize >= 0x10 and $a", strings.Repeat("ab", 8), true},
		{"filesize >= 0x10 and $a", strings.Repeat("ab", 7), false},
		{"filesize < 0X10 and $a", "abab", true},
		{"#a == 0x0", "no pattern here", true},
		{"filesize < 1KB and $a", "abab", true},
		{"filesize < 1kb and $a", "abab", true},
		{"filesize < 1MB and $a", "abab", true},
		{"filesize < 1GB and $a", "abab", true},
		// Nothing between "not" and its operand, twice over.
		{"not not $a", "ab", true},
		{"not not $a", "cd", false},
		{"$a or $a or $a", "ab", true},
		{"$a and $a and $a", "ab", true},
	} {
		rs := compile(t, strings.Replace(src, "%s", c.cond, 1))
		if got := len(rs.Scan([]byte(c.input))) == 1; got != c.want {
			t.Errorf("%q against %q = %v, want %v", c.cond, c.input, got, c.want)
		}
	}
}

// A number a rule cannot mean is refused at load.
//
// Both of these used to pass. "0x" with no digits after it read as
// zero, and a literal past the top of int64 wrapped round to a
// negative, so "filesize < 0x" and "filesize < 0xffffffffffffffff"
// both compiled into bounds no stream is ever under: rules that can
// never fire, on a scanner whose whole job is to fire. A rule file
// with a typo in it should not start.
func TestANumberARuleCannotMeanIsRefused(t *testing.T) {
	for _, c := range []struct{ name, src, want string }{
		{
			"a hex prefix with no digits",
			`rule r { strings: $a = "x" condition: filesize < 0x and $a }`,
			"has no digits",
		},
		{
			"a hex literal past the top of int64",
			`rule r { strings: $a = "x" condition: filesize < 0xffffffffffffffff and $a }`,
			"does not fit",
		},
		{
			"a decimal literal past the top of int64",
			`rule r { strings: $a = "x" condition: filesize < 99999999999999999999 and $a }`,
			"does not fit",
		},
		{
			// The digits fit; the kilobytes do not.
			"a size suffix that overflows",
			`rule r { strings: $a = "x" condition: filesize < 9223372036854775807KB and $a }`,
			"does not fit",
		},
		{
			"a count past the top of int64",
			`rule r { strings: $a = "x" condition: #a > 0x8000000000000000 }`,
			"does not fit",
		},
		// The same numbers, read in a hex pattern's jump.
		{"a jump that is not a number", `rule r { strings: $a = { 4D [x] 5A } condition: $a }`, "bad digit"},
		{"a jump written in hex", `rule r { strings: $a = { 4D [b] 5A } condition: $a }`, "bad digit"},
		{"a jump's low bound", `rule r { strings: $a = { 4D [x-2] 5A } condition: $a }`, "bad digit"},
		{"a jump's high bound", `rule r { strings: $a = { 4D [2-y] 5A } condition: $a }`, "bad digit"},
		{"a jump with no digits", `rule r { strings: $a = { 4D [0x] 5A } condition: $a }`, "has no digits"},
		{"jump bounds in the wrong order", `rule r { strings: $a = { 4D [5-2] 5A } condition: $a }`, "out of order"},
		{"a jump wider than the overlap", `rule r { strings: $a = { 4D [1-5000] 5A } condition: $a }`, "4096"},
		{"three numbers in a jump", `rule r { strings: $a = { 4D [1-2-3] 5A } condition: $a }`, "a jump is"},
		{"an unterminated jump", `rule r { strings: $a = { 4D [1-2 } condition: $a }`, "unterminated jump"},
	} {
		_, err := yara.Compile(c.src)
		if err == nil {
			t.Errorf("%s: compiled", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want it to mention %q", c.name, err, c.want)
		}
	}
}

// A jump of a fixed width, which is the one jump form the other tests
// do not use.
func TestFixedWidthJump(t *testing.T) {
	rs := compile(t, `rule j { strings: $a = { 4D 5A [2] 50 45 } condition: $a }`)
	if len(rs.Scan([]byte{0x4d, 0x5a, 0x00, 0x00, 0x50, 0x45})) != 1 {
		t.Fatal("two bytes between should match [2]")
	}
	if len(rs.Scan([]byte{0x4d, 0x5a, 0x00, 0x50, 0x45})) != 0 {
		t.Fatal("one byte between should not match [2]")
	}
}

// Everything a condition is refused for, with the reason it gives.
//
// The reasons are the point. A rule set is written by hand, often under
// time pressure during an incident, and the difference between "$b is
// not defined in this rule" and "unexpected" is whether the author
// fixes the rule in a minute or gives up and ships the file with the
// rule commented out.
func TestEveryReasonAConditionIsRefused(t *testing.T) {
	for _, c := range []struct{ name, src, want string }{
		{
			`"them" on its own`,
			`rule r { strings: $a = "x" condition: them }`,
			`"them" must follow "of"`,
		},
		{
			"a YARA feature a stream cannot have",
			`rule r { strings: $a = "x" condition: entrypoint }`,
			"not supported",
		},
		{
			"a word that means nothing here",
			`rule r { strings: $a = "x" condition: perhaps }`,
			"not supported in a condition",
		},
		{
			"a wildcard outside a set",
			`rule r { strings: $a = "x" condition: $a* }`,
			"a wildcard belongs in a set",
		},
		{
			// Still refused, and the reason is still the right one:
			// "!" is only not a sigil when it is the start of "!=".
			"a string length",
			`rule r { strings: $a = "x" condition: !a > 0 }`,
			"lengths have no meaning in a stream",
		},
		{
			"a count of a string that is not there",
			`rule r { strings: $a = "x" condition: #z > 1 }`,
			"$z is not defined in this rule",
		},
		{
			"a string literal where a condition goes",
			`rule r { strings: $a = "x" condition: "x" }`,
			"unexpected",
		},
		{
			"a count with no comparison",
			`rule r { strings: $a = "x" condition: #a }`,
			"not a comparison",
		},
		{
			"a count compared with a word",
			`rule r { strings: $a = "x" condition: #a and $a }`,
			"expected a comparison",
		},
		{
			"a count compared with a string",
			`rule r { strings: $a = "x" condition: #a > $a }`,
			"expected a number",
		},
		{
			"filesize with no comparison",
			`rule r { strings: $a = "x" condition: filesize }`,
			"not a comparison",
		},
		{
			`a count with "of" left out`,
			`rule r { strings: $a = "x" condition: 1 them }`,
			`expected "of"`,
		},
		{
			"a set that is neither them nor parenthesised",
			`rule r { strings: $a = "x" condition: 1 of $a }`,
			`expected "them" or a set`,
		},
		{
			"a set holding something that is not a string name",
			`rule r { strings: $a = "x" condition: any of (x) }`,
			"expected a string name in the set",
		},
		{
			"a set with no comma between its names",
			`rule r { strings: $a = "x" $b = "y" condition: any of ($a $b) }`,
			`expected ")"`,
		},
		{
			"a set with a trailing comma",
			`rule r { strings: $a = "x" condition: any of ($a,) }`,
			"expected a string name in the set",
		},
		{
			// Every pattern in the rule is private, so "them" names
			// nothing: the condition can never be true.
			"a set of nothing but private strings",
			`rule r { strings: $a = "x" private condition: all of them }`,
			"the set is empty",
		},
		{
			`"not" with nothing after it`,
			`rule r { strings: $a = "x" condition: not }`,
			"unexpected",
		},
		{
			"an unclosed group",
			`rule r { strings: $a = "x" condition: ( $a }`,
			`expected ")"`,
		},
		{
			"an empty group",
			`rule r { strings: $a = "x" condition: ( ) }`,
			"unexpected",
		},
		{
			`"and" with nothing after it`,
			`rule r { strings: $a = "x" condition: $a and }`,
			"unexpected",
		},
		{
			`"or" with nothing after it`,
			`rule r { strings: $a = "x" condition: $a or }`,
			"unexpected",
		},
	} {
		_, err := yara.Compile(c.src)
		if err == nil {
			t.Errorf("%s: compiled", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want it to mention %q", c.name, err, c.want)
		}
	}
}

// What the lexer refuses, and where it says it happened.
//
// The line number matters as much as the reason: a rule set is one
// concatenated file by the time Compile sees it, so "line 7" is how an
// author finds the rule that broke the load.
func TestEveryReasonTheLexerRefuses(t *testing.T) {
	for _, c := range []struct{ name, src, want string }{
		{"an unterminated escape", `rule r { strings: $a = "x\`, "unterminated"},
		{"an unknown escape", `rule r { strings: $a = "x\q" condition: $a }`, `unknown escape \q`},
		{"a truncated hex escape", `rule r { strings: $a = "x\x4`, "truncated"},
		{"a bad hex escape", `rule r { strings: $a = "x\xZZ" condition: $a }`, `bad \x escape`},
		{"a string running to the end of a line", "rule r { strings: $a = \"x\ncondition: $a }", "unterminated string"},
		{"a regular expression running to the end of a line", "rule r { strings: $a = /x\n/ condition: $a }", "unterminated regular expression"},
		{"an unterminated regular expression", `rule r { strings: $a = /x`, "unterminated regular expression"},
		{"an unterminated comment", "rule r { /* open\ncondition: true }", "unterminated comment"},
		{"an unterminated hex string", `rule r { strings: $a = { 4D 5A`, "unterminated hex string"},
		{"a character the grammar has no use for", `rule r { strings: $a = "x" condition: $a & $a }`, `unexpected character "&"`},
	} {
		_, err := yara.Compile(c.src)
		if err == nil {
			t.Errorf("%s: compiled", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want it to mention %q", c.name, err, c.want)
		}
	}
}

// The escapes and comment forms a rule file actually uses.
func TestEscapesAndComments(t *testing.T) {
	rs := compile(t, `
// a line comment
rule esc /* and a block one
   over two lines */ {
  strings:
    $a = "a\r\n\\\"b"
    $b = /a[/]b/is
  condition:
    any of them
}`)
	if len(rs.Scan([]byte("a\r\n\\\"b"))) != 1 {
		t.Fatal("the escaped string should match")
	}
	if len(rs.Scan([]byte("A/B"))) != 1 {
		t.Fatal("a slash inside a character class should stay in the pattern, and i should fold case")
	}
	// A nested brace in a hex string, and the line count that survives
	// it: the refusal below has to name line 4, not line 1.
	_, err := yara.Compile("rule a {\n  strings:\n    $a = { 4D 5A }\n  condition:\n    $z\n}")
	if err == nil || !strings.Contains(err.Error(), "line 5") {
		t.Fatalf("want the line of the undefined string: %v", err)
	}
}

// Len, Width and Names describe a rule set to a status view, which is
// the only place an operator can see that the file they shipped is the
// file that loaded.
func TestRuleSetDescribesItself(t *testing.T) {
	rs := compile(t, `
rule second { strings: $a = "short" condition: $a }
rule first { strings: $b = "a much longer pattern" condition: $b }`)
	if rs.Len() != 2 {
		t.Errorf("Len = %d, want 2", rs.Len())
	}
	if got := rs.Names(); len(got) != 2 || got[0] != "first" || got[1] != "second" {
		t.Errorf("Names = %v, want them sorted", got)
	}
	if want := len("a much longer pattern"); rs.Width() != want {
		t.Errorf("Width = %d, want the longest pattern, %d", rs.Width(), want)
	}
}

// Loading from disk, which is how every rule set in production arrives.
func TestLoadFileAndDir(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	one := write("one.yar", `rule one { strings: $a = "aaa" condition: $a }`)
	write("two.yara", `rule two { strings: $b = "bbb" condition: $b }`)
	// Neither of these is a rule file, and neither may break the load.
	write("notes.txt", "this is not a rule file at all {")
	if err := os.Mkdir(filepath.Join(dir, "nested.yar"), 0o700); err != nil {
		t.Fatal(err)
	}

	rs, err := yara.LoadFile(one)
	if err != nil {
		t.Fatal(err)
	}
	if rs.Len() != 1 || rs.Names()[0] != "one" {
		t.Errorf("LoadFile gave %v", rs.Names())
	}

	rs, err = yara.LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := rs.Names(); len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Errorf("LoadDir gave %v, want both rule files and nothing else", got)
	}

	if _, err := yara.LoadFile(filepath.Join(dir, "absent.yar")); err == nil {
		t.Error("a file that is not there should be an error")
	}
	bad := write("bad.yar", `rule bad { condition: pe.sections > 1 }`)
	if _, err := yara.LoadFile(bad); err == nil || !strings.Contains(err.Error(), bad) {
		t.Errorf("a file that does not compile should name itself: %v", err)
	}
	// One bad file fails the whole directory: a rule set that quietly
	// lost a rule is the failure this scanner cannot afford.
	if _, err := yara.LoadDir(dir); err == nil || !strings.Contains(err.Error(), dir) {
		t.Errorf("LoadDir should refuse the directory and name it: %v", err)
	}

	empty := t.TempDir()
	if _, err := yara.LoadDir(empty); err == nil || !strings.Contains(err.Error(), "no .yar") {
		t.Errorf("an empty directory should say so: %v", err)
	}
	if _, err := yara.LoadDir(filepath.Join(empty, "absent")); err == nil {
		t.Error("a directory that is not there should be an error")
	}
}

// Flush is what makes a rule fire where the stream actually paused.
//
// A proxy reads a socket and gets fewer bytes than a window; without
// Flush the scanner would sit on them until enough had accumulated,
// which for a slow trickle means the decision arrives after the bytes
// it was about.
func TestFlushScansWhatHasArrived(t *testing.T) {
	rs := compile(t, `rule f { strings: $a = "trigger" condition: $a }`)
	s := rs.NewScanner(4096)
	if _, err := s.Write([]byte("a trigger, and nothing like enough bytes to fill a window")); err != nil {
		t.Fatal(err)
	}
	if s.Fired() {
		t.Fatal("a short write should not have been scanned yet")
	}
	s.Flush()
	if !s.Fired() {
		t.Fatal("Flush should have scanned what arrived")
	}
	// Flushing again with nothing new is a no-op, not a second match.
	s.Flush()
	if got := s.Matches(); len(got) != 1 {
		t.Fatalf("matches %v", got)
	}
}

// Truncated is the scanner admitting what it cannot promise.
//
// A pattern wider than the overlap can be missed when it straddles two
// reads. The honest answer is to say so: a proxy that knows the scan
// was partial can refuse the transfer, where one told nothing would
// pass it as clean.
func TestTruncatedSaysTheOverlapWasNotEnough(t *testing.T) {
	wide := compile(t, `rule w { strings: $a = "`+strings.Repeat("A", 5000)+`" condition: $a }`)
	if s := wide.NewScanner(64 << 10); !s.Truncated() {
		t.Error("a pattern wider than the overlap should report Truncated")
	}
	// A regular expression has no fixed width, so it takes the whole
	// overlap -- more than half of a small window, which is the other
	// way the scan goes partial.
	re := compile(t, `rule r { strings: $a = /needle[0-9]+/ condition: $a }`)
	if s := re.NewScanner(4096); !s.Truncated() {
		t.Error("an overlap past half the window should report Truncated")
	}
	narrow := compile(t, `rule n { strings: $a = "needle" condition: $a }`)
	if s := narrow.NewScanner(64 << 10); s.Truncated() {
		t.Error("a pattern that fits should not report Truncated")
	}
}
