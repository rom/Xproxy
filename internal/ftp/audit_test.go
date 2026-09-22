package ftp

import (
	"bufio"
	"net/netip"
	"strings"
	"testing"
)

// FuzzParseAddresses: every one of these turns a peer's text into an
// address the proxy will dial or expect a connection from. A panic here
// is a crash from one reply, and a wrong answer is a data connection
// somewhere the policy never looked at.
func FuzzParseAddresses(f *testing.F) {
	f.Add("227 Entering Passive Mode (192,168,0,1,4,1)")
	f.Add("=10,0,0,1,4,1")
	f.Add("229 Entering Extended Passive Mode (|||60000|)")
	f.Add("|1|192.0.2.7|21|")
	f.Add("|2|2001:db8::1|21|")
	f.Add("192,168,0,1,4,1")
	f.Fuzz(func(t *testing.T, s string) {
		if ap, err := ParsePASV(s); err == nil && ap.Port() == 0 {
			t.Fatalf("PASV %q returned port 0 with no error", s)
		}
		if port, err := ParseEPSV(s); err == nil && (port < 1 || port > 65535) {
			t.Fatalf("EPSV %q gave port %d", s, port)
		}
		if ap, err := ParsePORT(s); err == nil {
			mustBeDialable(t, "PORT", s, ap)
		}
		if ap, err := ParseEPRT(s); err == nil {
			mustBeDialable(t, "EPRT", s, ap)
		}
	})
}

// mustBeDialable holds the property the data-connection policy rests
// on: what a parser returns is a real address with a real port, and
// carries no zone. A zone would make the address compare unequal to the
// client's own and, worse, name an interface on the proxy's host.
func mustBeDialable(t *testing.T, what, in string, ap netip.AddrPort) {
	t.Helper()
	if !ap.IsValid() {
		t.Fatalf("%s %q returned an invalid address with no error", what, in)
	}
	if ap.Port() == 0 {
		t.Fatalf("%s %q returned port 0", what, in)
	}
	if ap.Addr().Zone() != "" {
		t.Fatalf("%s %q returned a zoned address %v", what, in, ap)
	}
	if ap.Addr().IsUnspecified() {
		t.Fatalf("%s %q returned the unspecified address", what, in)
	}
}

// TestActedOnAddressesMustBePeers. A passive reply's address is
// advisory -- the proxy dials the server it is already connected to,
// because a server behind NAT advertises whatever it likes, including
// 0.0.0.0 -- so ParsePASV stays lenient on purpose. PORT and EPRT are
// different: they name where the proxy will open a connection, so
// anything that cannot be the other end of one is refused here as well
// as by the session's check against the client's own address. Either
// check alone is one caller away from being forgotten.
func TestActedOnAddressesMustBePeers(t *testing.T) {
	for _, in := range []string{
		"1,2,3,4,5,6", "0,0,0,0,4,1", "224,0,0,1,4,1", "255,255,255,255,4,1",
	} {
		if _, err := ParsePASV(in); err != nil {
			t.Errorf("PASV %q was refused, but its address is advisory: %v", in, err)
		}
	}
	for _, in := range []string{
		"0,0,0,0,4,1", "224,0,0,1,4,1", "255,255,255,255,4,1", "127,0,0,1,0,0",
	} {
		if ap, err := ParsePORT(in); err == nil {
			t.Errorf("PORT %q accepted as %v", in, ap)
		}
	}
	for _, in := range []string{
		"|1|0.0.0.0|21|", "|2|::|21|", "|1|224.0.0.1|21|",
		"|2|ff02::1|21|", "|2|fe80::1%eth0|21|", "|1|192.0.2.7|0|",
	} {
		if ap, err := ParseEPRT(in); err == nil {
			t.Errorf("EPRT %q accepted as %v", in, ap)
		}
	}
	// The ordinary forms still work.
	if _, err := ParsePORT("192,0,2,7,4,1"); err != nil {
		t.Errorf("an ordinary PORT was refused: %v", err)
	}
	if _, err := ParseEPRT("|1|192.0.2.7|21|"); err != nil {
		t.Errorf("an ordinary EPRT was refused: %v", err)
	}
	if _, err := ParseEPRT("|2|2001:db8::1|21|"); err != nil {
		t.Errorf("an ordinary IPv6 EPRT was refused: %v", err)
	}
}

// FuzzReadReply drives the reply reader, which decides where one reply
// ends and the next begins. A reader that can be made to run past a
// reply's end reads the next one as part of it, and a proxy that gets
// that wrong is answering commands with somebody else's answers.
func FuzzReadReply(f *testing.F) {
	f.Add("220 hello\r\n")
	f.Add("230-first\r\n230 last\r\n")
	f.Add("230-first\r\n more\r\n230 last\r\n")
	f.Add("999999999999999999999 overflow\r\n")
	f.Fuzz(func(t *testing.T, s string) {
		r := NewReader(bufio.NewReader(strings.NewReader(s)), 512)
		for i := 0; i < 8; i++ {
			rep, err := ReadReply(r)
			if err != nil {
				return
			}
			if rep.Code < 100 || rep.Code > 599 {
				t.Fatalf("reply code %d from %q", rep.Code, s)
			}
			// What a reply carries is about to be relayed to a client,
			// and a line ending in it would be a reply of the peer's
			// own devising.
			if strings.ContainsAny(string(rep.Format()), "\x00") {
				t.Fatalf("formatted reply carries a NUL: %q", rep.Format())
			}
			out := rep.Format()
			if n := strings.Count(string(out), "\r\n"); n != 1 && !strings.Contains(string(out), "-") {
				t.Fatalf("a single reply formatted to %d lines: %q", n, out)
			}
		}
	})
}

// FuzzParseCommand: the command line is the first thing a client sends
// and the thing every policy decision is made on.
func FuzzParseCommand(f *testing.F) {
	f.Add("USER alice\r\n")
	f.Add("RETR ../../etc/passwd\r\n")
	f.Add("PORT 1,2,3,4,5,6\r\n")
	f.Fuzz(func(t *testing.T, s string) {
		c, err := ParseCommand([]byte(s))
		if err != nil {
			return
		}
		if c.Verb == "" {
			t.Fatalf("%q parsed to an empty command", s)
		}
		if strings.ContainsAny(c.Verb, "\r\n\x00 ") {
			t.Fatalf("%q gave a command name with a delimiter in it: %q", s, c.Verb)
		}
		if strings.ToUpper(c.Verb) != c.Verb {
			t.Fatalf("%q gave a name that is not folded: %q", s, c.Verb)
		}
		if strings.ContainsAny(string(c.Format()), "\x00") {
			t.Fatalf("%q formatted with a NUL: %q", s, c.Format())
		}
	})
}
