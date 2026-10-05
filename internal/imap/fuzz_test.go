package imap

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzParseCommand drives the command parser with whatever the corpus
// mutates into, and asserts the invariants the session relies on: a
// literal's declared size is never negative, the argument count is
// bounded, and nothing that parsed carries a control character -- because
// the tag and the arguments reach a log line and a policy comparison.
func FuzzParseCommand(f *testing.F) {
	for _, seed := range []string{
		"A001 CAPABILITY",
		"a1 LOGIN bob secret",
		"t SELECT INBOX",
		"t APPEND INBOX {310}",
		"t APPEND INBOX (\\Seen) {99+}",
		`t LIST "" *`,
		"t UID FETCH 1:* (UID FLAGS BODY[HEADER])",
		`t SELECT "a\"b"`,
		"t STATUS &U,BTFw- (MESSAGES)",
		"t FETCH 1 (BODY.PEEK[HEADER.FIELDS (FROM TO)])",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in string) {
		c, err := ParseCommand([]byte(in))
		if err != nil {
			return
		}
		if c.Tag == "" || len(c.Tag) > MaxTag {
			t.Fatalf("tag %q from %q", c.Tag, in)
		}
		if len(c.Args) > MaxArgs {
			t.Fatalf("%d arguments from %q", len(c.Args), in)
		}
		if c.Literal != nil && c.Literal.Size < 0 {
			t.Fatalf("literal size %d from %q", c.Literal.Size, in)
		}
		for _, s := range append([]string{c.Tag, c.Name, c.Sub}, c.Args...) {
			for _, r := range s {
				if r < 0x20 || r == 0x7f {
					t.Fatalf("control character %#x in %q from %q", r, s, in)
				}
			}
		}
		// Effective is the name a policy decides about, so it is always one
		// of the two names the command carries.
		if e := c.Effective(); e != c.Name && e != c.Sub {
			t.Fatalf("effective %q is neither %q nor %q", e, c.Name, c.Sub)
		}
		// A mailbox that decodes is a name a rule can be compared against,
		// which means valid UTF-8 and no control characters.
		names, err := Mailboxes(c)
		if err != nil {
			return
		}
		for _, n := range names {
			if !utf8.ValidString(n) {
				t.Fatalf("mailbox %q from %q is not UTF-8", n, in)
			}
		}
	})
}

// FuzzParseResponse does the same from the server's side. A response's
// text is the server's and lands in an alert a mail client shows to a
// person, so a response that parsed carries nothing a terminal acts on.
func FuzzParseResponse(f *testing.F) {
	for _, seed := range []string{
		"A001 OK LOGIN completed",
		"A001 NO [AUTHENTICATIONFAILED] bad",
		"* OK [CAPABILITY IMAP4rev2 STARTTLS] ready",
		"* CAPABILITY IMAP4rev2 IDLE LITERAL+",
		"* 12 FETCH (UID 99 FLAGS (\\Seen))",
		"* 23 EXISTS",
		"+ go ahead",
		"* BYE closing",
		"* PREAUTH already authenticated",
		`* LIST (\HasNoChildren) "/" "INBOX"`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in string) {
		r, err := ParseResponse([]byte(in))
		if err != nil {
			return
		}
		for _, s := range []string{r.Tag, r.Status, r.Item, r.Code, r.CodeArgs, r.Text} {
			for _, b := range []byte(s) {
				if b < 0x20 || b == 0x7f {
					t.Fatalf("control character %#x in %q from %q", b, s, in)
				}
			}
		}
		// A continuation request is not also a status response: a session
		// that read it as both would answer a literal prompt with a
		// decision about a status it never received.
		if r.Continuation && (r.Status != "" || r.Item != "" || r.Tag != "") {
			t.Fatalf("continuation and more from %q: %+v", in, r)
		}
		if r.Status != "" && !isStatus(r.Status) {
			t.Fatalf("status %q from %q", r.Status, in)
		}
	})
}

// FuzzDecodeMailbox is the one that matters most for the policy: a name
// that decodes is compared against a rule, so a decode that produced
// invalid UTF-8, a control character or an unbounded string would be a
// comparison against something nobody wrote.
func FuzzDecodeMailbox(f *testing.F) {
	for _, seed := range []string{
		"INBOX",
		"Sent Items",
		"~peter/mail/&U,BTFw-/&ZeVnLIqe-",
		"&-",
		"&AOQ-",
		"Отправленные",
		"&!!!!-",
		"&",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in string) {
		out, err := DecodeMailbox(in)
		if err != nil {
			return
		}
		if !utf8.ValidString(out) {
			t.Fatalf("%q decoded to invalid UTF-8 %q", in, out)
		}
		for _, r := range out {
			if r < 0x20 || r == 0x7f {
				t.Fatalf("%q decoded to %q, which carries %#x", in, out, r)
			}
		}
		if len(in) <= MaxMailbox && len(out) > 4*MaxMailbox {
			t.Fatalf("%d octets decoded to %d", len(in), len(out))
		}
		// A name with no escape is returned as it came, which is what makes
		// a UTF8=ACCEPT name and a modified UTF-7 one reach the same rule.
		if !strings.Contains(in, "&") && out != in {
			t.Fatalf("%q with no escape became %q", in, out)
		}
	})
}

// FuzzParseSeqSet asserts the counting invariant a bound rests on: an
// open set reports no count, and a closed one counts at least its terms.
func FuzzParseSeqSet(f *testing.F) {
	for _, seed := range []string{"1", "1:5", "1,3,5", "1:*", "*", "1:3,10:*", "0", "1:0"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in string) {
		s, err := ParseSeqSet(in, MaxSeqTerms)
		if err != nil {
			return
		}
		if s.Terms < 1 || s.Terms > MaxSeqTerms {
			t.Fatalf("%q gave %d terms", in, s.Terms)
		}
		if s.Open && s.Count != 0 {
			t.Fatalf("%q is open and counts %d", in, s.Count)
		}
		if !s.Open && s.Count < uint64(s.Terms) {
			t.Fatalf("%q counts %d over %d terms", in, s.Count, s.Terms)
		}
	})
}
