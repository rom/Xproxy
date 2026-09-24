package termsafe_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/termsafe"
)

func filter(t *testing.T, in string, m termsafe.Mode) string {
	t.Helper()
	var out bytes.Buffer
	f := termsafe.New(&out, m)
	if _, err := f.Write([]byte(in)); err != nil {
		t.Fatal(err)
	}
	if err := f.Flush(); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

// The sequences that reach outside the replay window are the point of
// this package, so each one gets a case. None of them may survive in a
// form a terminal acts on, in either mode: what a reviewer's terminal
// must never see is an ESC introducing one.
func TestTheSequencesThatReachOutsideAreNeverForwarded(t *testing.T) {
	cases := map[string]string{
		"clipboard (OSC 52)":          "\x1b]52;c;aGVsbG8=\x07",
		"clipboard, ST terminated":    "\x1b]52;c;aGVsbG8=\x1b\\",
		"window title (OSC 0)":        "\x1b]0;a title\x07",
		"window title (OSC 2)":        "\x1b]2;a title\x07",
		"working directory (OSC 7)":   "\x1b]7;file://host/tmp\x07",
		"hyperlink (OSC 8)":           "\x1b]8;;http://evil.test\x07click\x1b]8;;\x07",
		"notification (OSC 9)":        "\x1b]9;you have mail\x07",
		"device attributes (CSI c)":   "\x1b[c",
		"secondary attributes":        "\x1b[>c",
		"device status (CSI n)":       "\x1b[6n",
		"window manipulation (CSI t)": "\x1b[8;50;200t",
		"DECRQSS":                     "\x1bP$qm\x1b\\",
		"request mode (CSI p)":        "\x1b[?1049$p",
		"mouse reporting":             "\x1b[?1000h",
		"any-event mouse":             "\x1b[?1003h",
		"SGR mouse":                   "\x1b[?1006h",
		"focus reporting":             "\x1b[?1004h",
		"bracketed paste":             "\x1b[?2004h",
		"application program command": "\x1b_anything\x1b\\",
		"privacy message":             "\x1b^anything\x1b\\",
		"start of string":             "\x1bXanything\x1b\\",
		"device control string":       "\x1bPanything\x1b\\",
		"an 8 bit CSI":                "\u009b6n",
		"an 8 bit OSC":                "\u009d52;c;aGk=\x07",
	}
	for name, seq := range cases {
		for _, m := range []termsafe.Mode{termsafe.Plain, termsafe.Safe} {
			got := filter(t, "before"+seq+"after", m)
			if strings.ContainsRune(got, 0x1b) {
				t.Errorf("%s in mode %d survived as an escape: %q", name, m, got)
			}
			// Whatever happened to the sequence, the text around it is
			// still there: this is a filter and not a refusal.
			if !strings.Contains(got, "before") || !strings.Contains(got, "after") {
				t.Errorf("%s in mode %d lost the text around it: %q", name, m, got)
			}
		}
	}
}

// The encoded form is what a reviewer reads to see that something was
// there. It has to name the sequence and contain no escape of its own.
func TestTheEncodedFormIsReadableAndInert(t *testing.T) {
	got := filter(t, "\x1b]52;c;aGVsbG8=\x07", termsafe.Safe)
	for _, want := range []string{`\e`, "]52;c;aGVsbG8=", `\x07`} {
		if !strings.Contains(got, want) {
			t.Errorf("the encoded clipboard write %q does not carry %q", got, want)
		}
	}
	if strings.ContainsAny(got, "\x1b\x07") {
		t.Errorf("the encoded form still carries a control byte: %q", got)
	}
	// In Plain there is nothing at all, because a transcript of escape
	// sequences is not what somebody reading a session wants.
	if got := filter(t, "a\x1b]52;c;aGk=\x07b", termsafe.Plain); got != "ab" {
		t.Errorf("Plain kept %q, want the text alone", got)
	}
}

// Safe keeps what draws inside the window, because a replay that lost
// its colours and cursor movement would not be a replay. Each of these
// must survive byte for byte.
func TestSafeKeepsWhatDrawsInsideTheWindow(t *testing.T) {
	for _, seq := range []string{
		"\x1b[31m", "\x1b[0m", "\x1b[1;32;40m", "\x1b[38;5;208m", "\x1b[38;2;10;20;30m",
		"\x1b[H", "\x1b[10;20H", "\x1b[2J", "\x1b[K", "\x1b[3A", "\x1b[2K",
		"\x1b[1L", "\x1b[1M", "\x1b[4P", "\x1b[2S", "\x1b[s", "\x1b[u", "\x1b[1;24r",
		"\x1b[?25l", "\x1b[?25h", "\x1b[?1049h", "\x1b[?7h", "\x1b[4h",
		"\x1b7", "\x1b8", "\x1bM", "\x1bD", "\x1b(B", "\x1b)0",
	} {
		if got := filter(t, seq, termsafe.Safe); got != seq {
			t.Errorf("Safe rewrote %q as %q", seq, got)
		}
		// Plain drops all of them, keeping only text.
		if got := filter(t, "x"+seq+"y", termsafe.Plain); got != "xy" {
			t.Errorf("Plain kept %q from %q", got, seq)
		}
	}
}

// A sequence split across writes is the one a filter that matched on
// whole strings would forward intact, so it is the case that matters
// most: the state machine has to survive the split.
func TestASequenceSplitAcrossWritesIsStillCaught(t *testing.T) {
	full := "before\x1b]52;c;aGVsbG8=\x07after"
	for cut := 1; cut < len(full); cut++ {
		var out bytes.Buffer
		f := termsafe.New(&out, termsafe.Safe)
		if _, err := f.Write([]byte(full[:cut])); err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(full[cut:])); err != nil {
			t.Fatal(err)
		}
		if err := f.Flush(); err != nil {
			t.Fatal(err)
		}
		if strings.ContainsRune(out.String(), 0x1b) {
			t.Fatalf("split at %d let an escape through: %q", cut, out.String())
		}
	}
}

// A stream that ends in the middle of a sequence must not leave the
// filter holding it: a truncated recording is ordinary, and a peer that
// left one there deliberately must not get it forwarded by the flush.
func TestAnUnterminatedSequenceIsFlushedEncoded(t *testing.T) {
	var out bytes.Buffer
	f := termsafe.New(&out, termsafe.Safe)
	if _, err := f.Write([]byte("text\x1b]52;c;aGVsbG")); err != nil {
		t.Fatal(err)
	}
	if err := f.Flush(); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.HasPrefix(got, "text") {
		t.Errorf("the text before the sequence was lost: %q", got)
	}
	if strings.ContainsRune(got, 0x1b) {
		t.Errorf("the flush forwarded the escape: %q", got)
	}
	if !strings.Contains(got, `\e]52`) {
		t.Errorf("the flush did not say a sequence was there: %q", got)
	}
}

// A sequence that never ends must not make the filter hold an unbounded
// amount of somebody else's session.
func TestASequenceThatNeverEndsIsBounded(t *testing.T) {
	var out bytes.Buffer
	f := termsafe.New(&out, termsafe.Safe)
	// A megabyte of OSC payload with no terminator.
	if _, err := f.Write([]byte("\x1b]52;c;" + strings.Repeat("A", 1<<20))); err != nil {
		t.Fatal(err)
	}
	if err := f.Flush(); err != nil {
		t.Fatal(err)
	}
	if out.Len() == 0 {
		t.Fatal("nothing came out of an endless sequence")
	}
	if strings.ContainsRune(out.String(), 0x1b) {
		t.Error("an endless sequence let an escape through")
	}
}

// What makes the screen disagree with the file: a bidirectional override
// reorders a line, a zero width character hides in one. Neither is
// visible, which is the whole of the Trojan Source class, so both are
// named rather than passed on.
func TestTheCharactersThatMakeTheScreenLieAreNamed(t *testing.T) {
	for name, r := range map[string]rune{
		"right to left override": 0x202e,
		"left to right override": 0x202d,
		"first strong isolate":   0x2068,
		"pop directional":        0x2069,
		"zero width space":       0x200b,
		"zero width joiner":      0x200d,
		"left to right mark":     0x200e,
		"arabic letter mark":     0x061c,
		"byte order mark":        0xfeff,
		"line separator":         0x2028,
	} {
		in := "rm -rf " + string(r) + "safe"
		got := filter(t, in, termsafe.Safe)
		if strings.ContainsRune(got, r) {
			t.Errorf("%s survived: %q", name, got)
		}
		if !strings.Contains(got, `\u`) {
			t.Errorf("%s was dropped without a word: %q", name, got)
		}
		if got := filter(t, in, termsafe.Plain); strings.ContainsRune(got, r) {
			t.Errorf("%s survived Plain: %q", name, got)
		}
	}
	// Ordinary text in other scripts is not touched, which is the half
	// that proves this is not a filter on everything above ASCII.
	for _, s := range []string{"naïve", "日本語", "Привет", "🙂"} {
		if got := filter(t, s, termsafe.Safe); got != s {
			t.Errorf("%q became %q", s, got)
		}
	}
}

// The bytes that overwrite what is already on the screen are how text is
// hidden from a reader rather than from a terminal, so Plain -- which is
// for reading -- does not keep them.
func TestPlainDoesNotLetTextBeOverwritten(t *testing.T) {
	if got := filter(t, "password: hunter2\rpassword: ******", termsafe.Plain); !strings.Contains(got, "hunter2") {
		t.Errorf("a carriage return hid text from a reader: %q", got)
	}
	if got := filter(t, "secret\x08\x08\x08\x08\x08\x08public", termsafe.Plain); !strings.Contains(got, "secret") {
		t.Errorf("a backspace hid text from a reader: %q", got)
	}
	// Safe keeps both, because they are how a terminal draws.
	if got := filter(t, "a\rb", termsafe.Safe); got != "a\rb" {
		t.Errorf("Safe rewrote a carriage return: %q", got)
	}
}

// Newlines and tabs are the layout; a bell and a form feed are not text.
func TestTheControlBytesThatAreLayoutSurvive(t *testing.T) {
	for _, m := range []termsafe.Mode{termsafe.Plain, termsafe.Safe} {
		if got := filter(t, "a\nb\tc", m); got != "a\nb\tc" {
			t.Errorf("mode %d rewrote the layout: %q", m, got)
		}
		if got := filter(t, "a\x07b", m); strings.ContainsRune(got, 0x07) {
			t.Errorf("mode %d kept a bell: %q", m, got)
		}
	}
}

// Filtered is the same policy over a string, for the places that hold
// one rather than a stream.
func TestFilteredAppliesToAString(t *testing.T) {
	if got := termsafe.Filtered("a\x1b]0;title\x07b", termsafe.Plain); got != "ab" {
		t.Errorf("Filtered gave %q", got)
	}
	if got := termsafe.Filtered("\x1b[31mred\x1b[0m", termsafe.Safe); got != "\x1b[31mred\x1b[0m" {
		t.Errorf("Filtered dropped the colour: %q", got)
	}
}
