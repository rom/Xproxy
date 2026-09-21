package syslog_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/syslog"
)

func TestParse5424(t *testing.T) {
	in := `<34>1 2026-09-21T14:30:22.123456Z mymachine.example.com su 1234 ID47 [exampleSDID@32473 iut="3" eventSource="Application"][b@1 x="y"] 'su root' failed`
	m, err := syslog.Parse([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if m.Facility != 4 || m.Severity != 2 {
		t.Errorf("facility %d severity %d", m.Facility, m.Severity)
	}
	if syslog.FacilityName(m.Facility) != "auth" || syslog.SeverityName(m.Severity) != "crit" {
		t.Errorf("names: %s.%s", syslog.FacilityName(m.Facility), syslog.SeverityName(m.Severity))
	}
	if !m.HasTimestamp || m.Timestamp.UTC().Format(time.RFC3339) != "2026-09-21T14:30:22Z" {
		t.Errorf("timestamp %v", m.Timestamp)
	}
	if m.Hostname != "mymachine.example.com" || m.AppName != "su" || m.ProcID != "1234" || m.MsgID != "ID47" {
		t.Errorf("header %+v", m)
	}
	if len(m.Structured) != 2 || m.Structured[0].ID != "exampleSDID@32473" || len(m.Structured[0].Params) != 2 {
		t.Fatalf("structured data %+v", m.Structured)
	}
	if m.Structured[0].Params[1].Value != "Application" {
		t.Errorf("param %+v", m.Structured[0].Params[1])
	}
	if m.Message != "'su root' failed" {
		t.Errorf("message %q", m.Message)
	}
}

// The nil value is a field the sender had nothing to put in, not a
// field whose value is a dash.
func TestParse5424Nil(t *testing.T) {
	m, err := syslog.Parse([]byte(`<13>1 - - - - - - hello`))
	if err != nil {
		t.Fatal(err)
	}
	if m.HasTimestamp || m.Hostname != "" || m.AppName != "" || m.ProcID != "" || m.MsgID != "" {
		t.Fatalf("%+v", m)
	}
	if len(m.Structured) != 0 || m.Message != "hello" {
		t.Fatalf("%+v", m)
	}
}

// The escaping inside a structured data value is the one place the
// format has any, and getting it wrong is how a value ends an element
// early.
func TestParseStructuredEscapes(t *testing.T) {
	m, err := syslog.Parse([]byte(`<13>1 - - - - - [a@1 v="he said \"hi\" ] \\ done"] text`))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Structured) != 1 || len(m.Structured[0].Params) != 1 {
		t.Fatalf("%+v", m.Structured)
	}
	if got := m.Structured[0].Params[0].Value; got != `he said "hi" ] \ done` {
		t.Errorf("value %q", got)
	}
	if m.Message != "text" {
		t.Errorf("message %q", m.Message)
	}
}

func TestParse3164(t *testing.T) {
	m, err := syslog.Parse([]byte("<34>Oct 11 22:14:15 mymachine su[1234]: 'su root' failed for lonvick"))
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != 0 {
		t.Errorf("version %d, want 0 for the older format", m.Version)
	}
	if m.Hostname != "mymachine" || m.AppName != "su" || m.ProcID != "1234" {
		t.Errorf("%+v", m)
	}
	if m.Message != "'su root' failed for lonvick" {
		t.Errorf("message %q", m.Message)
	}
	// No timestamp, no host: everything after the priority is the text.
	m, err = syslog.Parse([]byte("<13>just a line"))
	if err != nil {
		t.Fatal(err)
	}
	if m.Message != "just a line" || m.Hostname != "" {
		t.Errorf("%+v", m)
	}
}

func TestParseRefuses(t *testing.T) {
	for name, in := range map[string]string{
		"no priority":       "hello",
		"unterminated pri":  "<34 hello",
		"priority too big":  "<999>1 - - - - - - x",
		"priority negative": "<-1>1 - - - - - - x",
		"empty priority":    "<>x",
		"short 5424 header": "<13>1 - - -",
		"bad timestamp":     "<13>1 not-a-time - - - - x",
		"unquoted sd value": `<13>1 - - - - - [a@1 v=unquoted] x`,
		"unterminated sd":   `<13>1 - - - - - [a@1 v="x] text`,
		"nul in message":    "<13>1 - - - - - - a\x00b",
		"newline in host":   "<13>1 - my\nhost - - - - x",
		"not utf-8":         "<13>1 - - - - - - \xff\xfe",
	} {
		if m, err := syslog.Parse([]byte(in)); err == nil {
			t.Errorf("%s: %q parsed as %+v", name, in, m)
		} else if !errors.Is(err, syslog.ErrMalformed) {
			t.Errorf("%s: err = %v, want ErrMalformed", name, err)
		}
	}
}

// Everything the relay sends goes out as RFC 5424, whatever came in.
// One dialect out is what makes the record a collector stores the
// record the relay decided about.
func TestFormatIsCanonical(t *testing.T) {
	m, err := syslog.Parse([]byte("<34>Oct 11 22:14:15 mymachine su[1234]: failed"))
	if err != nil {
		t.Fatal(err)
	}
	out := string(m.Format())
	if !strings.HasPrefix(out, "<34>1 ") {
		t.Fatalf("an old format message was not re-emitted as 5424: %q", out)
	}
	if !strings.Contains(out, " mymachine su 1234 - - failed") {
		t.Errorf("re-emitted as %q", out)
	}
	// Re-reading what was written gives the same message back.
	again, err := syslog.Parse(m.Format())
	if err != nil {
		t.Fatalf("the output does not parse: %v", err)
	}
	if again.Hostname != m.Hostname || again.AppName != m.AppName || again.Message != m.Message {
		t.Errorf("round trip: %+v vs %+v", again, m)
	}
}

// A newline in the text is the injection this format invites: a
// collector that frames on newlines would read one message as two, and
// the second one says whatever the sender wanted a record to say.
func TestFormatCannotInjectARecord(t *testing.T) {
	m := syslog.Message{Facility: 1, Severity: 5, Version: 1,
		Hostname: "host", AppName: "app",
		Message: "ok\n<0>1 - evil - - - - the admin did it"}
	out := string(m.Format())
	if strings.Contains(out, "\n") {
		t.Fatalf("the output carries a newline: %q", out)
	}
	framed := string(syslog.Frame([]byte(out), syslog.NonTransparent))
	if strings.Count(framed, "\n") != 1 {
		t.Fatalf("framed as %d records: %q", strings.Count(framed, "\n"), framed)
	}
	// The same for a structured data value and a header field.
	m2 := syslog.Message{Facility: 1, Severity: 5, Hostname: "a b\nc",
		Structured: []syslog.SDElement{{ID: "x@1", Params: []syslog.SDParam{{Name: "k", Value: "v\"]\n<0>1"}}}}}
	out2 := string(m2.Format())
	if strings.ContainsAny(out2, "\n\r") {
		t.Fatalf("output carries a line ending: %q", out2)
	}
	if _, err := syslog.Parse([]byte(out2)); err != nil {
		t.Fatalf("the escaped output does not parse: %v (%q)", err, out2)
	}
}

func TestFramingOctetCounting(t *testing.T) {
	// The lengths are exact: a counted frame says how many octets
	// follow, so the next message begins immediately after them.
	in := "9 <13>1 - x5 <13>1"
	r := syslog.NewReader(strings.NewReader(in), 4096, syslog.OctetCounting)
	first, err := r.ReadMessage()
	if err != nil || string(first) != "<13>1 - x" {
		t.Fatalf("first = %q %v", first, err)
	}
	second, err := r.ReadMessage()
	if err != nil || string(second) != "<13>1" {
		t.Fatalf("second = %q %v", second, err)
	}
}

func TestFramingRefuses(t *testing.T) {
	for name, in := range map[string]string{
		"length is not a number": "1x2 hello",
		"empty length":           " hello",
		"too many digits":        "12345678901 hello",
		"zero length":            "0 ",
	} {
		r := syslog.NewReader(strings.NewReader(in), 4096, syslog.OctetCounting)
		if _, err := r.ReadMessage(); err == nil {
			t.Errorf("%s: %q was framed", name, in)
		}
	}
	// A length over the bound is refused without allocating for it.
	r := syslog.NewReader(strings.NewReader("1000000 x"), 4096, syslog.OctetCounting)
	if _, err := r.ReadMessage(); !errors.Is(err, syslog.ErrTooLarge) {
		t.Errorf("a huge length: %v", err)
	}
}

func TestFramingNonTransparent(t *testing.T) {
	r := syslog.NewReader(strings.NewReader("<13>one\n<13>two\r\n<13>three"), 4096, syslog.NonTransparent)
	for _, want := range []string{"<13>one", "<13>two", "<13>three"} {
		got, err := r.ReadMessage()
		if err != nil {
			t.Fatalf("%s: %v", want, err)
		}
		if string(got) != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
}

// A message over the bound does not swallow the one behind it.
func TestFramingResyncs(t *testing.T) {
	long := strings.Repeat("x", 600)
	r := syslog.NewReader(strings.NewReader("<13>"+long+"\n<13>next\n"), 480, syslog.NonTransparent)
	if _, err := r.ReadMessage(); !errors.Is(err, syslog.ErrOversizeSkipped) {
		t.Fatalf("the long message was accepted: %v", err)
	}
	got, err := r.ReadMessage()
	if err != nil || string(got) != "<13>next" {
		t.Fatalf("after the long message: %q %v", got, err)
	}
}

// Auto framing decides per message, which is what a listener taking
// both dialects needs.
func TestFramingAuto(t *testing.T) {
	r := syslog.NewReader(strings.NewReader("9 <13>plain<13>line\n"), 4096, syslog.Auto)
	first, err := r.ReadMessage()
	if err != nil || string(first) != "<13>plain" {
		t.Fatalf("first = %q %v", first, err)
	}
	second, err := r.ReadMessage()
	if err != nil || string(second) != "<13>line" {
		t.Fatalf("second = %q %v", second, err)
	}
}

func TestNames(t *testing.T) {
	if n, ok := syslog.FacilityNumber("authpriv"); !ok || n != 10 {
		t.Errorf("authpriv = %d %v", n, ok)
	}
	if n, ok := syslog.SeverityNumber("WARNING"); !ok || n != 4 {
		t.Errorf("warning = %d %v", n, ok)
	}
	if _, ok := syslog.FacilityNumber("nonsense"); ok {
		t.Error("an unknown facility was accepted")
	}
}
