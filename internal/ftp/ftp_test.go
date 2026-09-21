package ftp_test

import (
	"bufio"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/ftp"
)

func reader(s string, max int) *ftp.Reader {
	return ftp.NewReader(bufio.NewReaderSize(strings.NewReader(s), 4096), max)
}

// A line that is not exactly CRLF-terminated, or that carries a telnet
// command, is refused rather than repaired: every one of them is a way
// for the proxy and the target to disagree about where a command ends.
func TestReadLineRefusesAmbiguity(t *testing.T) {
	for name, c := range map[string]struct {
		in   string
		want error
	}{
		"bare newline":   {"USER alice\n", ftp.ErrBareNewline},
		"bare cr":        {"USER a\rlice\r\n", ftp.ErrBareCR},
		"telnet iac":     {"USER a\xfflice\r\n", ftp.ErrTelnet},
		"over the bound": {"USER " + strings.Repeat("a", 200) + "\r\n", ftp.ErrLineTooLong},
	} {
		if _, err := reader(c.in, 64).ReadLine(); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", name, err, c.want)
		}
	}
	line, err := reader("USER alice\r\n", 64).ReadLine()
	if err != nil || string(line) != "USER alice" {
		t.Fatalf("a good line: %q %v", line, err)
	}
}

// After a line over the bound the reader is back at a line boundary, so
// the rest of the long line is never read as a command of its own.
func TestReadLineResyncs(t *testing.T) {
	r := reader("USER "+strings.Repeat("a", 200)+"\r\nNOOP\r\n", 64)
	if _, err := r.ReadLine(); !errors.Is(err, ftp.ErrLineTooLong) {
		t.Fatal("the long line was accepted")
	}
	line, err := r.ReadLine()
	if err != nil || string(line) != "NOOP" {
		t.Fatalf("after the long line: %q %v", line, err)
	}
}

func TestParseCommand(t *testing.T) {
	for _, c := range []struct {
		in         string
		verb, arg  string
		shouldFail bool
	}{
		{in: "NOOP", verb: "NOOP"},
		{in: "user alice", verb: "USER", arg: "alice"},
		{in: "RETR /srv/a b.txt", verb: "RETR", arg: "/srv/a b.txt"},
		// The argument keeps its own spaces, and only the first is the
		// separator: a file called "a  b" is one file.
		{in: "RETR  leading", verb: "RETR", arg: " leading"},
		{in: "", shouldFail: true},
		{in: "RETR\x00 x", shouldFail: true},
		{in: "TOOLONGVERB x", shouldFail: true},
		{in: "RE7R x", shouldFail: true},
	} {
		got, err := ftp.ParseCommand([]byte(c.in))
		if c.shouldFail {
			if err == nil {
				t.Errorf("%q parsed as %+v", c.in, got)
			}
			continue
		}
		if err != nil || got.Verb != c.verb || got.Arg != c.arg {
			t.Errorf("%q = %+v %v, want %s %q", c.in, got, err, c.verb, c.arg)
		}
	}
}

func TestReadReply(t *testing.T) {
	r := reader("220 ready\r\n", 4096)
	rep, err := ftp.ReadReply(r)
	if err != nil || rep.Code != 220 || rep.Text() != "ready" {
		t.Fatalf("single line: %+v %v", rep, err)
	}

	// A continuation ends only on the same code with a space, so a line
	// inside the group that looks like a reply does not end it early.
	r = reader("211-Features:\r\n MLST\r\n211-999 not the end\r\n211 End\r\n", 4096)
	rep, err = ftp.ReadReply(r)
	if err != nil || rep.Code != 211 || len(rep.Lines) != 4 {
		t.Fatalf("multi line: %+v %v", rep, err)
	}
	if rep.Lines[3] != "End" {
		t.Errorf("last line = %q", rep.Lines[3])
	}

	for name, in := range map[string]string{
		"not digits":   "2x0 no\r\n",
		"no separator": "220x no\r\n",
		"too short":    "220\r\n",
		"out of range": "099 no\r\n",
	} {
		if _, err := ftp.ReadReply(reader(in, 4096)); err == nil {
			t.Errorf("%s: %q parsed", name, in)
		}
	}

	// A server that never closes a group does not get to grow the
	// proxy's memory.
	var b strings.Builder
	for i := 0; i < ftp.MaxReplyLines+10; i++ {
		b.WriteString("211-line\r\n")
	}
	if _, err := ftp.ReadReply(reader(b.String(), 4096)); !errors.Is(err, ftp.ErrTooManyReplyLines) {
		t.Errorf("an unterminated group: %v", err)
	}
}

// A reply the proxy writes cannot carry a line ending of its own, or
// text that came from elsewhere could end the reply early and have the
// rest read as another one.
func TestReplyFormatSanitises(t *testing.T) {
	out := string(ftp.Reply{Code: 550, Lines: []string{"denied: /a\r\n230 Logged in"}}.Format())
	if strings.Count(out, "\r\n") != 1 {
		t.Fatalf("a reply carried its own line ending: %q", out)
	}
	if !strings.HasPrefix(out, "550 ") {
		t.Fatalf("reply = %q", out)
	}
	multi := string(ftp.Reply{Code: 211, Lines: []string{"a", "b", "c"}}.Format())
	if multi != "211-a\r\n211-b\r\n211 c\r\n" {
		t.Fatalf("multi line = %q", multi)
	}
}

func TestPASV(t *testing.T) {
	for _, c := range []struct {
		in   string
		want string
	}{
		{"Entering Passive Mode (192,168,1,2,19,136)", "192.168.1.2:5000"},
		{"Entering Passive Mode (10,0,0,1,0,21).", "10.0.0.1:21"},
		{"=10,0,0,1,4,1", "10.0.0.1:1025"},
	} {
		got, err := ftp.ParsePASV(c.in)
		if err != nil || got.String() != c.want {
			t.Errorf("%q = %v %v, want %s", c.in, got, err, c.want)
		}
	}
	for _, bad := range []string{
		"Entering Passive Mode (192,168,1,2,19)",
		"Entering Passive Mode (192,168,1,2,19,999)",
		"Entering Passive Mode (192,168,1,2,0,0)", // port 0 goes nowhere
		"no numbers here",
	} {
		if got, err := ftp.ParsePASV(bad); err == nil {
			t.Errorf("%q parsed as %v", bad, got)
		}
	}
	s, ok := ftp.FormatPASV(netip.MustParseAddrPort("192.168.1.2:5000"))
	if !ok || s != "192,168,1,2,19,136" {
		t.Errorf("format = %q %v", s, ok)
	}
	if _, ok := ftp.FormatPASV(netip.MustParseAddrPort("[2001:db8::1]:21")); ok {
		t.Error("an IPv6 address cannot be spelled as six octets")
	}
}

func TestEPSV(t *testing.T) {
	port, err := ftp.ParseEPSV("Entering Extended Passive Mode (|||49152|)")
	if err != nil || port != 49152 {
		t.Fatalf("epsv = %d %v", port, err)
	}
	if _, err := ftp.ParseEPSV("Entering Extended Passive Mode (|||0|)"); err == nil {
		t.Error("port 0 parsed")
	}
	if _, err := ftp.ParseEPSV("nothing"); err == nil {
		t.Error("a reply with no group parsed")
	}
	if got := ftp.FormatEPSV(49152); got != "(|||49152|)" {
		t.Errorf("format = %q", got)
	}
}

func TestEPRT(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"|1|192.168.1.2|5000|", "192.168.1.2:5000"},
		{"|2|2001:db8::1|5000|", "[2001:db8::1]:5000"},
		{"#2#2001:db8::1#5000#", "[2001:db8::1]:5000"},
	} {
		got, err := ftp.ParseEPRT(c.in)
		if err != nil || got.String() != c.want {
			t.Errorf("%q = %v %v, want %s", c.in, got, err, c.want)
		}
	}
	for _, bad := range []string{
		"|1|2001:db8::1|5000|", // the family and the address disagree
		"|2|192.168.1.2|5000|",
		"|3|192.168.1.2|5000|",
		"|1|192.168.1.2|0|",
		"|1|192.168.1.2|",
		"",
	} {
		if got, err := ftp.ParseEPRT(bad); err == nil {
			t.Errorf("%q parsed as %v", bad, got)
		}
	}
	if got := ftp.FormatEPRT(netip.MustParseAddrPort("192.168.1.2:5000")); got != "|1|192.168.1.2|5000|" {
		t.Errorf("format = %q", got)
	}
	if got := ftp.FormatEPRT(netip.MustParseAddrPort("[2001:db8::1]:5000")); got != "|2|2001:db8::1|5000|" {
		t.Errorf("format = %q", got)
	}
}
