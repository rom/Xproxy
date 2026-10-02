package pop3

import "testing"

// FuzzParseCommand drives the command parser with whatever the corpus
// mutates into. The invariants are the ones the session rests on: the
// keyword is letters and nothing else, the arguments are bounded, and
// nothing that parsed carries a control character -- the keyword and the
// identity beside it both reach a log line.
func FuzzParseCommand(f *testing.F) {
	for _, seed := range []string{
		"CAPA",
		"USER bob",
		"PASS secret",
		"APOP bob c4c9334bac560ecc979e58001b3e22fb",
		"AUTH PLAIN aGk=",
		"RETR 3",
		"TOP 3 10",
		"LIST",
		"UIDL 7",
		"QUIT",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in string) {
		c, err := ParseCommand([]byte(in))
		if err != nil {
			return
		}
		if c.Name == "" || len(c.Name) > 16 {
			t.Fatalf("keyword %q from %q", c.Name, in)
		}
		for _, r := range c.Name {
			if !(r >= 'A' && r <= 'Z') {
				t.Fatalf("keyword %q from %q is not folded letters", c.Name, in)
			}
		}
		if len(c.Args) >= MaxArgs {
			t.Fatalf("%d arguments from %q", len(c.Args), in)
		}
		for _, a := range c.Args {
			for _, b := range []byte(a) {
				if b < 0x20 || b == 0x7f {
					t.Fatalf("control character %#x in %q from %q", b, a, in)
				}
			}
		}
		// A number that comes back is a message number, which is never
		// zero: the protocol numbers from one and a zero would be a
		// different message on either side of the relay.
		if n, ok, err := c.Message(); err == nil && ok && n == 0 {
			t.Fatalf("%q gave message number 0", in)
		}
		// Multiline has to be a function of the command and its argument
		// count alone, because a session that asked twice could get two
		// answers and then read the reply the wrong way.
		if c.Multiline() != c.Multiline() {
			t.Fatalf("%q answers Multiline inconsistently", in)
		}
	})
}

// FuzzParseReply does the same from the server's side: a reply's text is
// the server's, and an estate's POP3 server is not always one the estate
// administers.
func FuzzParseReply(f *testing.F) {
	for _, seed := range []string{
		"+OK",
		"+OK 2 messages (320 octets)",
		"-ERR invalid command",
		"-ERR [AUTH] authentication failed",
		"+OK [LOGIN-DELAY 60] try later",
		"+ Y2hhbGxlbmdl",
		"+OK POP3 server ready <1896.697170952@dbc.mtview.ca.us>",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in string) {
		r, err := ParseReply([]byte(in))
		if err != nil {
			return
		}
		for _, s := range []string{r.Code, r.Text} {
			for _, b := range []byte(s) {
				if b < 0x20 || b == 0x7f {
					t.Fatalf("control character %#x in %q from %q", b, s, in)
				}
			}
		}
		// A continuation is an OK with the one code this package assigns
		// itself, and nothing else may carry that code -- a session that
		// mistook a code for a challenge would wait for a credential the
		// client is not going to send.
		if r.Continuation() && !r.OK {
			t.Fatalf("%q is a continuation and not OK", in)
		}
		// The timestamp, where there is one, is a bracketed run inside the
		// text that this package hands to an APOP decision.
		if ts, ok := Timestamp(r.Text); ok {
			if len(ts) < 2 || ts[0] != '<' || ts[len(ts)-1] != '>' {
				t.Fatalf("%q gave timestamp %q", in, ts)
			}
		}
	})
}

// FuzzUnstuff asserts the inverse property the message body rests on: a
// line that is stuffed and then unstuffed is the line that went in, and a
// line that unstuffs is never longer than it was. Getting this wrong ends
// a message where the sender did not.
func FuzzUnstuff(f *testing.F) {
	for _, seed := range []string{".", "..", "...", ".hidden", "ordinary", ""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in string) {
		if got := string(Unstuff(Stuff([]byte(in)))); got != in {
			t.Fatalf("Stuff then Unstuff of %q gave %q", in, got)
		}
		if got := Unstuff([]byte(in)); len(got) > len(in) {
			t.Fatalf("Unstuff(%q) grew to %d octets", in, len(got))
		}
		// The terminator is exactly one dot, and a stuffed body line is
		// never it -- which is the whole of the byte-stuffing's purpose.
		if Terminator(Stuff([]byte(in))) && in != "." {
			t.Fatalf("%q stuffed to the terminator", in)
		}
	})
}
