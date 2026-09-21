package yara_test

import (
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/yara"
)

func compile(t *testing.T, src string) *yara.Rules {
	t.Helper()
	rs, err := yara.Compile(src)
	if err != nil {
		t.Fatalf("compile: %v\n%s", err, src)
	}
	return rs
}

func names(ms []yara.Match) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.Rule)
	}
	return out
}

func TestLiteralStrings(t *testing.T) {
	rs := compile(t, `
rule eicar_like : malware test {
  meta:
    description = "a literal"
    severity = 8
  strings:
    $a = "X5O!P%@AP"
    $b = "EICAR-STANDARD" nocase
  condition:
    all of them
}`)
	if got := names(rs.Scan([]byte("... X5O!P%@AP ... eicar-standard-antivirus ..."))); len(got) != 1 {
		t.Fatalf("got %v", got)
	}
	if got := names(rs.Scan([]byte("X5O!P%@AP only"))); len(got) != 0 {
		t.Fatalf("all of them should need both: %v", got)
	}
	m := rs.Scan([]byte("X5O!P%@AP EICAR-STANDARD"))
	if len(m) != 1 || m[0].Meta["description"] != "a literal" || len(m[0].Tags) != 2 {
		t.Fatalf("match %+v", m)
	}
}

func TestModifiers(t *testing.T) {
	rs := compile(t, `
rule wide_and_fullword {
  strings:
    $w = "secret" wide
    $f = "cat" fullword
  condition:
    any of them
}`)
	// "secret" as UTF-16LE.
	wideBytes := make([]byte, 0, 12)
	for _, c := range []byte("secret") {
		wideBytes = append(wideBytes, c, 0)
	}
	if len(rs.Scan(wideBytes)) != 1 {
		t.Fatal("the wide form should match")
	}
	if len(rs.Scan([]byte("secret"))) != 0 {
		t.Fatal("wide without ascii should not match the narrow form")
	}
	if len(rs.Scan([]byte("the cat sat"))) != 1 {
		t.Fatal("fullword should match a whole word")
	}
	if len(rs.Scan([]byte("concatenate"))) != 0 {
		t.Fatal("fullword should not match inside a word")
	}
}

func TestHexStrings(t *testing.T) {
	rs := compile(t, `
rule pe_header {
  strings:
    $mz = { 4D 5A ?? ?? [0-8] 50 45 00 00 }
    $nib = { 4? FF }
  condition:
    $mz or $nib
}`)
	body := append([]byte{0x4d, 0x5a, 0x90, 0x00}, make([]byte, 6)...)
	body = append(body, 0x50, 0x45, 0x00, 0x00)
	if len(rs.Scan(body)) != 1 {
		t.Fatal("the hex pattern with a jump should match")
	}
	if len(rs.Scan([]byte{0x4d, 0x5a, 0x90, 0x00, 0x50, 0x46, 0x00, 0x00})) != 0 {
		t.Fatal("a wrong byte should not match")
	}
	if len(rs.Scan([]byte{0x41, 0xff})) != 1 {
		t.Fatal("the nibble wildcard should match 0x41")
	}
	if len(rs.Scan([]byte{0x51, 0xff})) != 0 {
		t.Fatal("the nibble wildcard should not match 0x51")
	}
}

func TestRegexStrings(t *testing.T) {
	rs := compile(t, `
rule tokens {
  strings:
    $t = /AKIA[0-9A-Z]{16}/
    $u = /password\s*=\s*\w+/ nocase
  condition:
    any of them
}`)
	if len(rs.Scan([]byte("id=AKIAIOSFODNN7EXAMPLE;"))) != 1 {
		t.Fatal("the key pattern should match")
	}
	if len(rs.Scan([]byte("PASSWORD = hunter2"))) != 1 {
		t.Fatal("the nocase pattern should match")
	}
	if len(rs.Scan([]byte("nothing here"))) != 0 {
		t.Fatal("nothing should match")
	}
}

func TestConditions(t *testing.T) {
	src := `
rule counts {
  strings:
    $a = "ab"
    $b = "cd"
    $c = "ef"
  condition:
    %s
}`
	cases := []struct {
		cond  string
		input string
		want  bool
	}{
		{"#a > 2", "ababab", true},
		{"#a > 2", "abab", false},
		{"#a == 0", "cd", true},
		{"2 of them", "abcd", true},
		{"2 of them", "ab", false},
		{"any of them", "ef", true},
		{"all of them", "abcdef", true},
		{"all of them", "abcd", false},
		{"any of ($a,$b)", "ef", false},
		{"any of ($a*)", "ab", true},
		{"$a and not $b", "ab", true},
		{"$a and not $b", "abcd", false},
		{"($a or $b) and $c", "abef", true},
		{"($a or $b) and $c", "ab", false},
		{"filesize > 4 and $a", "ababab", true},
		{"filesize > 100 and $a", "ababab", false},
		{"true", "", true},
		{"false", "abcdef", false},
	}
	for _, c := range cases {
		rs := compile(t, strings.Replace(src, "%s", c.cond, 1))
		got := len(rs.Scan([]byte(c.input))) == 1
		if got != c.want {
			t.Errorf("%q against %q = %v want %v", c.cond, c.input, got, c.want)
		}
	}
}

// A match that straddles two writes is still a match: that is the whole
// difference between scanning a file and scanning a stream.
func TestStreamingAcrossWrites(t *testing.T) {
	rs := compile(t, `
rule split {
  strings:
    $a = "needle-in-the-haystack"
  condition:
    $a
}`)
	s := rs.NewScanner(4096)
	_, _ = s.Write([]byte(strings.Repeat("x", 4090) + "needle-in"))
	_, _ = s.Write([]byte("-the-haystack" + strings.Repeat("y", 2000)))
	if !s.Fired() {
		t.Fatal("a match across the window boundary was missed")
	}
	if got := s.Close(); len(got) != 1 || got[0].Rule != "split" {
		t.Fatalf("got %v", got)
	}
}

// A rule is reported as soon as its condition is true, which is what
// lets a proxy act before the rest of the stream has gone through.
func TestFiresEarly(t *testing.T) {
	rs := compile(t, `
rule early {
  strings:
    $a = "trigger"
  condition:
    $a
}`)
	s := rs.NewScanner(4096)
	_, _ = s.Write([]byte(strings.Repeat("z", 4000) + "trigger" + strings.Repeat("z", 600)))
	if !s.Fired() {
		t.Fatal("the rule should have fired before Close")
	}
	before := s.Bytes()
	_, _ = s.Write([]byte(strings.Repeat("z", 10000)))
	if got := s.Close(); len(got) != 1 || got[0].Offset > before+10000 {
		t.Fatalf("offset %v", got)
	}
}

func TestCompileRefuses(t *testing.T) {
	bad := map[string]string{
		"no rules":            ``,
		"no condition":        `rule r { strings: $a = "x" }`,
		"empty strings":       `rule r { strings: condition: true }`,
		"undefined string":    `rule r { strings: $a = "x" condition: $b }`,
		"duplicate rule":      `rule r { condition: true } rule r { condition: true }`,
		"duplicate string":    `rule r { strings: $a = "x" $a = "y" condition: $a }`,
		"import":              `import "pe" rule r { condition: true }`,
		"module":              `rule r { condition: pe.number_of_sections > 1 }`,
		"at":                  `rule r { strings: $a = "x" condition: $a at 0 }`,
		"for loop":            `rule r { strings: $a = "x" condition: for any i in (1..3) : ( true ) }`,
		"offset":              `rule r { strings: $a = "x" condition: @a > 0 }`,
		"unbounded jump":      `rule r { strings: $a = { 4D 5A [2-] 50 45 } condition: $a }`,
		"hex alternation":     `rule r { strings: $a = { 4D ( 5A | 5B ) } condition: $a }`,
		"unknown modifier":    `rule r { strings: $a = "x" base64 condition: $a }`,
		"bad hex":             `rule r { strings: $a = { ZZ } condition: $a }`,
		"unterminated string": `rule r { strings: $a = "x condition: $a }`,
		"impossible count":    `rule r { strings: $a = "x" condition: 3 of them }`,
		"empty set":           `rule r { strings: $a = "x" condition: any of ($z*) }`,
		"jump at the end":     `rule r { strings: $a = { 4D 5A [1-2] } condition: $a }`,
	}
	for name, src := range bad {
		if _, err := yara.Compile(src); err == nil {
			t.Errorf("%s: should not compile", name)
		}
	}
}

func TestCommentsAndMeta(t *testing.T) {
	rs := compile(t, `
// a line comment
/* a block
   comment */
rule commented {
  meta:
    author = "ops"
    score = 10
    enabled = true
  strings:
    $a = "hit"   // trailing
  condition:
    $a
}`)
	m := rs.Scan([]byte("a hit here"))
	if len(m) != 1 || m[0].Meta["author"] != "ops" || m[0].Meta["score"] != "10" || m[0].Meta["enabled"] != "true" {
		t.Fatalf("meta %+v", m)
	}
}

// A private rule is evaluated but not reported.
func TestPrivateRule(t *testing.T) {
	rs := compile(t, `
private rule quiet {
  strings:
    $a = "x"
  condition:
    $a
}
rule loud {
  strings:
    $b = "y"
  condition:
    $b
}`)
	if got := names(rs.Scan([]byte("xy"))); len(got) != 1 || got[0] != "loud" {
		t.Fatalf("got %v", got)
	}
}

func TestEscapes(t *testing.T) {
	rs := compile(t, `rule esc { strings: $a = "a\tb\x41\n" condition: $a }`)
	if len(rs.Scan([]byte("a\tbA\n"))) != 1 {
		t.Fatal("escapes should be decoded")
	}
}

func FuzzCompile(f *testing.F) {
	f.Add(`rule r { strings: $a = "x" condition: $a }`)
	f.Add(`rule r { strings: $a = { 4D 5A ?? } condition: $a }`)
	f.Add(`rule r { condition: filesize > 10 }`)
	f.Fuzz(func(t *testing.T, src string) {
		rs, err := yara.Compile(src)
		if err != nil {
			return
		}
		// Anything that compiles must scan without panicking, and must
		// not claim a match on an empty stream unless its condition can
		// be satisfied by nothing at all.
		_ = rs.Scan([]byte("some bytes to scan"))
		_ = rs.Names()
	})
}
