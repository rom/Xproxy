package smtp_test

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/smtp"
)

func reader(s string, max int) *smtp.Reader {
	return smtp.NewReader(strings.NewReader(s), max)
}

func TestReadLineCRLF(t *testing.T) {
	r := reader("EHLO host\r\nQUIT\r\n", 512)
	for _, want := range []string{"EHLO host", "QUIT"} {
		line, err := r.ReadLine()
		if err != nil {
			t.Fatalf("ReadLine: %v", err)
		}
		if string(line) != want {
			t.Fatalf("got %q want %q", line, want)
		}
	}
	if _, err := r.ReadLine(); !errors.Is(err, io.EOF) {
		t.Fatalf("want EOF, got %v", err)
	}
}

// A line ended by LF alone is the whole of SMTP smuggling: the proxy and
// the next hop disagree about where it ended.
func TestReadLineBareNewline(t *testing.T) {
	r := reader("NOOP\n", 512)
	if _, err := r.ReadLine(); !errors.Is(err, smtp.ErrBareNewline) {
		t.Fatalf("want ErrBareNewline, got %v", err)
	}
	lenient := reader("NOOP\n", 512)
	lenient.AllowBareLF = true
	line, err := lenient.ReadLine()
	if err != nil || string(line) != "NOOP" {
		t.Fatalf("lenient: %q %v", line, err)
	}
}

func TestReadLineBareCR(t *testing.T) {
	r := reader("MAIL FROM:<a\rRCPT TO:<b>>\r\n", 512)
	if _, err := r.ReadLine(); !errors.Is(err, smtp.ErrBareCR) {
		t.Fatalf("want ErrBareCR, got %v", err)
	}
}

func TestReadLineTooLong(t *testing.T) {
	r := reader("NOOP "+strings.Repeat("x", 600)+"\r\nQUIT\r\n", 128)
	if _, err := r.ReadLine(); !errors.Is(err, smtp.ErrLineTooLong) {
		t.Fatalf("want ErrLineTooLong, got %v", err)
	}
	// The rest of the overlong line is consumed, so the next read is the
	// next command and not the tail of the last one.
	line, err := r.ReadLine()
	if err != nil || string(line) != "QUIT" {
		t.Fatalf("after overlong line: %q %v", line, err)
	}
}

func TestBuffered(t *testing.T) {
	r := reader("STARTTLS\r\nMAIL FROM:<x@y>\r\n", 512)
	if _, err := r.ReadLine(); err != nil {
		t.Fatal(err)
	}
	if r.Buffered() == 0 {
		t.Fatal("pipelined octets should be visible as buffered")
	}
}

func TestParseCommand(t *testing.T) {
	c, err := smtp.ParseCommand([]byte("mail FROM:<a@b> SIZE=10"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Verb != "MAIL" || c.Arg != "FROM:<a@b> SIZE=10" {
		t.Fatalf("got %+v", c)
	}
	for _, bad := range []string{"", "MA1L x", "-HELO", strings.Repeat("A", 20)} {
		if _, err := smtp.ParseCommand([]byte(bad)); err == nil {
			t.Fatalf("%q should not parse", bad)
		}
	}
}

func TestReadReply(t *testing.T) {
	r := reader("250-host\r\n250-SIZE 100\r\n250 STARTTLS\r\n", 512)
	rep, err := smtp.ReadReply(r)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Code != 250 || len(rep.Lines) != 3 || rep.Lines[1] != "SIZE 100" {
		t.Fatalf("got %+v", rep)
	}
	if got := string(rep.Format()); got != "250-host\r\n250-SIZE 100\r\n250 STARTTLS\r\n" {
		t.Fatalf("round trip: %q", got)
	}
}

// A reply whose code changes mid-way is two replies to somebody.
func TestReadReplyCodeChange(t *testing.T) {
	r := reader("250-host\r\n220 ready\r\n", 512)
	if _, err := smtp.ReadReply(r); !errors.Is(err, smtp.ErrBadReply) {
		t.Fatalf("want ErrBadReply, got %v", err)
	}
}

func TestReadReplyMalformed(t *testing.T) {
	for _, bad := range []string{"2 ok\r\n", "abc ok\r\n", "250xok\r\n", "999 ok\r\n"} {
		if _, err := smtp.ReadReply(reader(bad, 512)); err == nil {
			t.Fatalf("%q should not parse", bad)
		}
	}
}

func TestReadReplyTooManyLines(t *testing.T) {
	var b strings.Builder
	for i := 0; i < smtp.MaxReplyLines+5; i++ {
		b.WriteString("250-x\r\n")
	}
	b.WriteString("250 done\r\n")
	if _, err := smtp.ReadReply(reader(b.String(), 512)); !errors.Is(err, smtp.ErrTooManyReplyLines) {
		t.Fatalf("want ErrTooManyReplyLines, got %v", err)
	}
}

func TestFilterEHLO(t *testing.T) {
	rep := smtp.Reply{Code: 250, Lines: []string{"host", "PIPELINING", "STARTTLS", "CHUNKING", "SIZE 100"}}
	hidden := map[string]bool{"STARTTLS": true, "CHUNKING": true}
	out := smtp.FilterEHLO(rep, func(kw string) bool { return !hidden[kw] }, []string{"STARTTLS", "SIZE 50"})
	want := []string{"host", "PIPELINING", "SIZE 100", "STARTTLS"}
	if len(out.Lines) != len(want) {
		t.Fatalf("got %v", out.Lines)
	}
	for i := range want {
		if out.Lines[i] != want[i] {
			t.Fatalf("line %d: %q want %q", i, out.Lines[i], want[i])
		}
	}
	// SIZE 50 was not added: the keyword is already present, and an
	// EHLO list with the same keyword twice is a list two parsers read
	// differently.
	if _, ok := smtp.Capability(out, "SIZE"); !ok {
		t.Fatal("SIZE should survive")
	}
	if _, ok := smtp.Capability(out, "CHUNKING"); ok {
		t.Fatal("CHUNKING should be gone")
	}
}

func TestCopyData(t *testing.T) {
	var out bytes.Buffer
	r := reader("line one\r\n..stuffed\r\n.\r\nNOOP\r\n", 512)
	n, err := smtp.CopyData(&out, r, 1000, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := out.String(); got != "line one\r\n..stuffed\r\n.\r\n" {
		t.Fatalf("got %q", got)
	}
	if n != int64(len("line one\r\n..stuffed\r\n.\r\n")) {
		t.Fatalf("n = %d", n)
	}
	// The command after the message is still there to be read.
	line, err := r.ReadLine()
	if err != nil || string(line) != "NOOP" {
		t.Fatalf("after data: %q %v", line, err)
	}
}

// The terminator the proxy acts on is the terminator it writes, so a
// bare-LF dot cannot end the message for one side only.
func TestCopyDataBareDot(t *testing.T) {
	var out bytes.Buffer
	r := reader("body\r\n\n.\nMAIL FROM:<evil@example.com>\r\n.\r\n", 512)
	if _, err := smtp.CopyData(&out, r, 1000, 0); !errors.Is(err, smtp.ErrBareNewline) {
		t.Fatalf("want ErrBareNewline, got %v", err)
	}
	if strings.Contains(out.String(), "evil") {
		t.Fatal("the injected message reached the upstream")
	}
}

func TestCopyDataTooLarge(t *testing.T) {
	var out bytes.Buffer
	r := reader(strings.Repeat("x", 100)+"\r\n"+strings.Repeat("y", 100)+"\r\n.\r\n", 512)
	if _, err := smtp.CopyData(&out, r, 1000, 150); !errors.Is(err, smtp.ErrMessageTooLarge) {
		t.Fatalf("want ErrMessageTooLarge, got %v", err)
	}
	if err := smtp.Discard(r, 1000, 1<<20); err != nil {
		t.Fatalf("Discard: %v", err)
	}
}

func TestCopyDataUnterminated(t *testing.T) {
	var out bytes.Buffer
	r := reader("body\r\n", 512)
	if _, err := smtp.CopyData(&out, r, 1000, 0); !errors.Is(err, smtp.ErrDataUnterminated) {
		t.Fatalf("want ErrDataUnterminated, got %v", err)
	}
}

func FuzzReadReply(f *testing.F) {
	f.Add("250 ok\r\n")
	f.Add("250-a\r\n250 b\r\n")
	f.Add("5")
	f.Fuzz(func(t *testing.T, s string) {
		rep, err := smtp.ReadReply(reader(s, 512))
		if err == nil && (rep.Code < 100 || rep.Code > 599) {
			t.Fatalf("accepted code %d", rep.Code)
		}
	})
}

func FuzzParseCommand(f *testing.F) {
	f.Add("EHLO host")
	f.Add("MAIL FROM:<a@b>")
	f.Fuzz(func(t *testing.T, s string) {
		c, err := smtp.ParseCommand([]byte(s))
		if err == nil && strings.ContainsAny(c.Verb, " \r\n") {
			t.Fatalf("verb %q has whitespace", c.Verb)
		}
	})
}
