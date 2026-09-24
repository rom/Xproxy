package textsafe_test

import (
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/textsafe"
)

// Clip's job is that a value a peer chose cannot change what a line
// means. The C0 controls are the obvious half; the other two groups are
// the ones a filter written once and not revisited tends to miss.
func TestClipReplacesWhatChangesALinesMeaning(t *testing.T) {
	for name, s := range map[string]string{
		"a newline":                "alice\nadmin",
		"a carriage return":        "alice\rdeny",
		"an escape":                "alice\x1b[2J",
		"delete":                   "alice\x7f",
		"a C1 control (CSI)":       "alice\u009b2J",
		"a bidirectional override": "alice\u202eecived",
		"a bidirectional isolate":  "alice\u2066x\u2069",
		"a zero width space":       "al\u200bice",
		"a zero width joiner":      "al\u200dice",
		"a left to right mark":     "alice\u200e",
		"an arabic letter mark":    "alice\u061c",
		"a byte order mark":        "al" + string(rune(0xfeff)) + "ice",
		"a line separator":         "alice\u2028admin",
		"a paragraph separator":    "alice\u2029admin",
	} {
		got := textsafe.Clip(s, 0)
		if strings.ContainsAny(got, "\n\r\x1b\x7f") {
			t.Errorf("%s: %q still carries a control byte", name, got)
		}
		for _, r := range got {
			if r != '?' && (r < 0x20 || r >= 0x80 && r <= 0x9f) {
				t.Errorf("%s: %q still carries %U", name, got, r)
			}
			for _, bad := range []rune{0x202e, 0x2066, 0x2069, 0x200b, 0x200d, 0x200e, 0x061c, 0xfeff, 0x2028, 0x2029} {
				if r == bad {
					t.Errorf("%s: %q still carries %U", name, got, r)
				}
			}
		}
		if !strings.Contains(got, "al") {
			t.Errorf("%s: %q lost the text around it", name, got)
		}
	}
}

// Ordinary text in other scripts is untouched, which is the half that
// proves this is not a filter on everything above ASCII.
func TestClipKeepsOrdinaryText(t *testing.T) {
	for _, s := range []string{"naïve", "日本語", "Привет", "🙂", "a-b_c.d", "user@example.com"} {
		if got := textsafe.Clip(s, 0); got != s {
			t.Errorf("%q became %q", s, got)
		}
	}
}

// The bound is in bytes and says it cut, so a reader can tell a long
// value from a truncated one.
func TestClipBounds(t *testing.T) {
	if got := textsafe.Clip64(strings.Repeat("a", 100)); got != strings.Repeat("a", 64)+"..." {
		t.Errorf("Clip64 gave %q", got)
	}
	if got := textsafe.Clip256("short"); got != "short" {
		t.Errorf("a short value was changed: %q", got)
	}
}

// Component is narrower than a file system on purpose: the strings it
// guards go into a path template, so anything that could be read as a
// separator or a parent directory is refused rather than escaped.
func TestComponent(t *testing.T) {
	for _, ok := range []string{"alice", "deploy-bot", "a_b.c", "0"} {
		if !textsafe.Component(ok) {
			t.Errorf("%q was refused", ok)
		}
	}
	for _, bad := range []string{"", ".", "..", "...", "a/b", "a\\b", "a b", "a;b", "a\x00b", "a$b", "../etc", strings.Repeat("a", 65)} {
		if textsafe.Component(bad) {
			t.Errorf("%q was accepted", bad)
		}
	}
}
