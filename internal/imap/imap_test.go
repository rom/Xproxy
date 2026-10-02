package imap

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// A command line is a tag, a name and arguments, and every one of the
// three is something a policy decides with: the tag matches the answer,
// the name is the operation, and the arguments carry the mailbox and the
// credential.
func TestACommandLineIsReadAsATagANameAndItsArguments(t *testing.T) {
	for _, tc := range []struct {
		line string
		tag  string
		name string
		args []string
	}{
		{"A001 CAPABILITY", "A001", "CAPABILITY", nil},
		{"a1 LOGIN bob secret", "a1", "LOGIN", []string{"bob", "secret"}},
		{"2 select INBOX", "2", "SELECT", []string{"INBOX"}},
		{`x LOGIN "bob smith" "pass word"`, "x", "LOGIN", []string{"bob smith", "pass word"}},
		{"t FETCH 1:* (UID FLAGS BODY[HEADER])", "t", "FETCH", []string{"1:*", "(UID FLAGS BODY[HEADER])"}},
		{"t UID FETCH 1 (RFC822)", "t", "UID", []string{"FETCH", "1", "(RFC822)"}},
		{"t LIST \"\" *", "t", "LIST", []string{"", "*"}},
	} {
		c, err := ParseCommand([]byte(tc.line))
		if err != nil {
			t.Errorf("%q: %v", tc.line, err)
			continue
		}
		if c.Tag != tc.tag || c.Name != tc.name {
			t.Errorf("%q: tag %q name %q, want %q %q", tc.line, c.Tag, c.Name, tc.tag, tc.name)
		}
		if len(c.Args) != len(tc.args) {
			t.Errorf("%q: args %q, want %q", tc.line, c.Args, tc.args)
			continue
		}
		for i := range tc.args {
			if c.Args[i] != tc.args[i] {
				t.Errorf("%q: arg %d is %q, want %q", tc.line, i, c.Args[i], tc.args[i])
			}
		}
	}
}

// A tag is echoed in the answer and is how the relay pairs the two, so
// what a tag may not be matters: a `+` makes the line look like a
// continuation request, and a long one is memory the client chose.
func TestATagAClientMayNotSendIsRefused(t *testing.T) {
	for _, line := range []string{
		"",
		" CAPABILITY",
		"+ CAPABILITY",
		"a+1 CAPABILITY",
		`a"1 CAPABILITY`,
		"a(1 CAPABILITY",
		"a%1 CAPABILITY",
		"a*1 CAPABILITY",
		strings.Repeat("t", MaxTag+1) + " NOOP",
	} {
		if c, err := ParseCommand([]byte(line)); err == nil {
			t.Errorf("%q became tag %q command %q", line, c.Tag, c.Name)
		}
	}
}

// The literal is the reason this parser exists: `{310}` says the next 310
// octets are an argument, and the relay has to decide about the command
// before they arrive. RFC 7888's `{310+}` sends them without waiting,
// which is exactly why the declared size is what a bound is checked
// against.
func TestALiteralIsReadFromTheCommandLineBeforeItsOctetsArrive(t *testing.T) {
	c, err := ParseCommand([]byte("A1 APPEND INBOX {310}"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Literal == nil || c.Literal.Size != 310 || c.Literal.NonSync {
		t.Fatalf("literal %+v, want size 310 synchronising", c.Literal)
	}
	if len(c.Args) != 1 || c.Args[0] != "INBOX" {
		t.Fatalf("args %q, want the mailbox before the literal", c.Args)
	}
	plus, err := ParseCommand([]byte("A1 APPEND INBOX (\\Seen) {99+}"))
	if err != nil {
		t.Fatal(err)
	}
	if plus.Literal == nil || plus.Literal.Size != 99 || !plus.Literal.NonSync {
		t.Fatalf("literal %+v, want size 99 non-synchronising", plus.Literal)
	}
	// A literal has to be the last thing on the line. Anything after the
	// closing brace means the server is waiting for octets where this
	// reader is waiting for text, and the two have desynchronised.
	for _, line := range []string{
		"A1 APPEND INBOX {10} trailing",
		"A1 APPEND {10}x",
		"A1 APPEND INBOX {}",
		"A1 APPEND INBOX {-1}",
		"A1 APPEND INBOX {12a}",
		"A1 APPEND INBOX {10",
		"A1 APPEND INBOX {999999999999999}",
	} {
		if c, err := ParseCommand([]byte(line)); err == nil {
			t.Errorf("%q parsed with literal %+v", line, c.Literal)
		}
	}
}

// A quoted string has exactly two escapes. A parser that invented a third
// would read a different mailbox name from the same octets than the
// server does, which is how a policy is bypassed with a backslash.
func TestAQuotedStringKeepsOnlyTheTwoEscapesTheGrammarHas(t *testing.T) {
	c, err := ParseCommand([]byte(`t SELECT "a\"b\\c"`))
	if err != nil {
		t.Fatal(err)
	}
	if want := `a"b\c`; c.Args[0] != want {
		t.Fatalf("argument %q, want %q", c.Args[0], want)
	}
	for _, line := range []string{
		`t SELECT "unterminated`,
		`t SELECT "bad\nescape"`,
		`t SELECT "trailing\`,
	} {
		if _, err := ParseCommand([]byte(line)); err == nil {
			t.Errorf("%q was accepted", line)
		}
	}
}

// A parenthesised list is kept whole rather than decoded, because a relay
// that re-encoded a FETCH item list would decide about one request and
// forward another.
func TestAParenthesisedListIsKeptWhole(t *testing.T) {
	c, err := ParseCommand([]byte(`t FETCH 1 (BODY.PEEK[HEADER.FIELDS (FROM TO)] UID)`))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Args) != 2 {
		t.Fatalf("args %q, want the set and the list", c.Args)
	}
	if want := `(BODY.PEEK[HEADER.FIELDS (FROM TO)] UID)`; c.Args[1] != want {
		t.Fatalf("list %q, want %q", c.Args[1], want)
	}
	if _, err := ParseCommand([]byte("t FETCH 1 (UID")); err == nil {
		t.Error("an unterminated list was accepted")
	}
	if _, err := ParseCommand([]byte("t FETCH 1 " + strings.Repeat("(", 40))); err == nil {
		t.Error("a list nested past the bound was accepted")
	}
}

// The command set is stateful, and the state table is the relay's own
// answer rather than the server's: a FETCH before a SELECT is refused
// here, so the mailbox never sees it.
func TestTheStateTableIsWhatTheRFCSays(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state State
		want  bool
	}{
		{"CAPABILITY", StateNone, true},
		{"CAPABILITY", StateSelected, true},
		{"LOGIN", StateNone, true},
		{"LOGIN", StateAuth, false},
		{"STARTTLS", StateAuth, false},
		{"SELECT", StateNone, false},
		{"SELECT", StateAuth, true},
		{"FETCH", StateAuth, false},
		{"FETCH", StateSelected, true},
		{"APPEND", StateAuth, true},
		{"IDLE", StateAuth, true},
		{"EXPUNGE", StateAuth, false},
		{"NOOP", StateLogout, false},
		{"NONSENSE", StateSelected, false},
	} {
		if got := AllowedIn(tc.name, tc.state); got != tc.want {
			t.Errorf("%s in %s: %v, want %v", tc.name, tc.state, got, tc.want)
		}
	}
	if !Known("fetch") || Known("FETCHX") {
		t.Error("Known does not fold case or admits what it should not")
	}
	if names := Names(); len(names) < 30 || names[0] > names[1] {
		t.Errorf("Names returned %d names, sorted %v", len(names), names[0] <= names[1])
	}
}

// Every client written this century uses UIDs, so a policy that
// distinguished FETCH from UID FETCH would be a policy about nothing.
func TestUIDIsTheCommandItQualifies(t *testing.T) {
	for _, tc := range []struct{ line, want string }{
		{"t UID FETCH 1 (RFC822)", "FETCH"},
		{"t UID STORE 1 +FLAGS (\\Deleted)", "STORE"},
		{"t UID COPY 1:5 Archive", "COPY"},
		{"t FETCH 1 (RFC822)", "FETCH"},
		{"t UID", "UID"},
	} {
		c, err := ParseCommand([]byte(tc.line))
		if err != nil {
			t.Errorf("%q: %v", tc.line, err)
			continue
		}
		if got := c.Effective(); got != tc.want {
			t.Errorf("%q: effective %q, want %q", tc.line, got, tc.want)
		}
	}
}

// A mailbox policy is worth nothing if it reads the wrong argument, and
// the position moves: COPY names its mailbox after the sequence set, and
// a UID COPY moves everything along by one.
func TestTheMailboxArgumentIsFoundWhereEachCommandPutsIt(t *testing.T) {
	for _, tc := range []struct {
		line string
		want []string
	}{
		{"t SELECT INBOX", []string{"INBOX"}},
		{"t EXAMINE Archive", []string{"Archive"}},
		{`t STATUS "Sent Items" (MESSAGES)`, []string{"Sent Items"}},
		{"t APPEND Drafts {10}", []string{"Drafts"}},
		{"t COPY 1:5 Archive", []string{"Archive"}},
		{"t UID COPY 1:5 Archive", []string{"Archive"}},
		{"t MOVE 1 Trash", []string{"Trash"}},
		{"t UID MOVE 1 Trash", []string{"Trash"}},
		{`t LIST "" *`, []string{"*"}},
		{"t RENAME Old New", []string{"Old", "New"}},
		{"t NOOP", nil},
		{"t FETCH 1 (UID)", nil},
	} {
		c, err := ParseCommand([]byte(tc.line))
		if err != nil {
			t.Errorf("%q: %v", tc.line, err)
			continue
		}
		got, err := Mailboxes(c)
		if err != nil {
			t.Errorf("%q: %v", tc.line, err)
			continue
		}
		if len(got) != len(tc.want) {
			t.Errorf("%q: mailboxes %q, want %q", tc.line, got, tc.want)
			continue
		}
		for i := range tc.want {
			if got[i] != tc.want[i] {
				t.Errorf("%q: mailbox %d is %q, want %q", tc.line, i, got[i], tc.want[i])
			}
		}
	}
}

// A mailbox name, a tag and a server's text all end up in a log line, a
// security event and an operator's terminal. None of them may carry what
// a terminal acts on.
func TestAControlCharacterIsRefusedInBothDirections(t *testing.T) {
	for _, line := range []string{
		"t SELECT IN\x1b[2JBOX",
		"t SELECT IN\x00BOX",
		"t\x07 NOOP",
	} {
		if _, err := ParseCommand([]byte(line)); !errors.Is(err, ErrControl) {
			t.Errorf("%q: %v, want ErrControl", line, err)
		}
	}
	for _, line := range []string{
		"* OK \x1b]0;title\x07",
		"A1 NO \x00",
	} {
		if _, err := ParseResponse([]byte(line)); !errors.Is(err, ErrControl) {
			t.Errorf("%q: %v, want ErrControl", line, err)
		}
	}
}

// A line over the bound is refused, and the next command still reads --
// because the alternative is parsing the tail of the refused line as a
// command of its own, which is how one line becomes two.
func TestALineTooLongIsRefusedAndTheNextCommandStillReads(t *testing.T) {
	long := "t SELECT " + strings.Repeat("x", 200)
	r := NewReader(strings.NewReader(long+"\r\nA2 NOOP\r\n"), 64)
	if _, err := r.ReadLine(); !errors.Is(err, ErrLineTooLong) {
		t.Fatalf("first line: %v, want ErrLineTooLong", err)
	}
	line, err := r.ReadLine()
	if err != nil {
		t.Fatalf("second line: %v", err)
	}
	if string(line) != "A2 NOOP" {
		t.Fatalf("second line is %q, want the command after the long one", line)
	}
	// A line that overshoots the bound by one or two arrives whole,
	// because the buffer is two octets larger; the reader must not
	// discard then, or it swallows the next command.
	exact := strings.Repeat("y", 65)
	r2 := NewReader(strings.NewReader(exact+"\r\nA3 NOOP\r\n"), 64)
	if _, err := r2.ReadLine(); !errors.Is(err, ErrLineTooLong) {
		t.Fatalf("overshooting line: %v, want ErrLineTooLong", err)
	}
	if line, err := r2.ReadLine(); err != nil || string(line) != "A3 NOOP" {
		t.Fatalf("after an overshooting line: %q %v", line, err)
	}
}

// CRLF is the terminator. A bare LF ends the line for a permissive peer
// and not for a strict one, which is the oldest ambiguity in every text
// protocol.
func TestABareNewlineAndABareCRAreRefused(t *testing.T) {
	if _, err := NewReader(strings.NewReader("A1 NOOP\n"), 64).ReadLine(); !errors.Is(err, ErrBareNewline) {
		t.Errorf("bare LF: %v, want ErrBareNewline", err)
	}
	if _, err := NewReader(strings.NewReader("A1 \rNOOP\r\n"), 64).ReadLine(); !errors.Is(err, ErrBareCR) {
		t.Errorf("bare CR: %v, want ErrBareCR", err)
	}
}

// A literal is read as octets rather than as text, and a relay that
// refuses the command still has to get past the octets the client
// announced -- or close a connection that did nothing wrong.
func TestALiteralIsReadOrSkippedExactly(t *testing.T) {
	r := NewReader(strings.NewReader("hello worldA2 NOOP\r\n"), 64)
	body, err := r.ReadLiteral(11)
	if err != nil || string(body) != "hello world" {
		t.Fatalf("literal %q %v", body, err)
	}
	if line, err := r.ReadLine(); err != nil || string(line) != "A2 NOOP" {
		t.Fatalf("after the literal: %q %v", line, err)
	}
	skip := NewReader(strings.NewReader("0123456789A3 NOOP\r\n"), 64)
	if err := skip.Discard(10); err != nil {
		t.Fatal(err)
	}
	if line, err := skip.ReadLine(); err != nil || string(line) != "A3 NOOP" {
		t.Fatalf("after a discarded literal: %q %v", line, err)
	}
	var out bytes.Buffer
	cp := NewReader(strings.NewReader("abcdeA4 NOOP\r\n"), 64)
	if err := cp.CopyLiteral(&out, 5); err != nil || out.String() != "abcde" {
		t.Fatalf("copied %q %v", out.String(), err)
	}
	if line, err := cp.ReadLine(); err != nil || string(line) != "A4 NOOP" {
		t.Fatalf("after a copied literal: %q %v", line, err)
	}
}

// A response is read for the three things a relay decides with: whether
// it is this command's answer, what it says, and which data item it
// carries.
func TestAResponseIsReadForItsStatusCodeAndItem(t *testing.T) {
	for _, tc := range []struct {
		line   string
		tag    string
		status string
		item   string
		number uint32
		code   string
		text   string
	}{
		{"A001 OK LOGIN completed", "A001", "OK", "", 0, "", "LOGIN completed"},
		{"A001 OK [READ-WRITE] SELECT done", "A001", "OK", "", 0, "READ-WRITE", "SELECT done"},
		{"A001 NO [AUTHENTICATIONFAILED] bad password", "A001", "NO", "", 0, "AUTHENTICATIONFAILED", "bad password"},
		{"* OK [CAPABILITY IMAP4rev2 STARTTLS] ready", "", "OK", "", 0, "CAPABILITY", "ready"},
		{"* CAPABILITY IMAP4rev2 IDLE", "", "", "CAPABILITY", 0, "", "IMAP4rev2 IDLE"},
		{"* 12 FETCH (UID 99)", "", "", "FETCH", 12, "", "(UID 99)"},
		{"* 23 EXISTS", "", "", "EXISTS", 23, "", ""},
		{"* BYE closing", "", "BYE", "", 0, "", "closing"},
		{"* PREAUTH already in", "", "PREAUTH", "", 0, "", "already in"},
	} {
		r, err := ParseResponse([]byte(tc.line))
		if err != nil {
			t.Errorf("%q: %v", tc.line, err)
			continue
		}
		if r.Tag != tc.tag || r.Status != tc.status || r.Item != tc.item ||
			r.Number != tc.number || r.Code != tc.code || r.Text != tc.text {
			t.Errorf("%q: %+v", tc.line, r)
		}
	}
	cont, err := ParseResponse([]byte("+ go ahead"))
	if err != nil || !cont.Continuation || cont.Text != "go ahead" {
		t.Errorf("continuation: %+v %v", cont, err)
	}
	for _, line := range []string{"", "rubbish", "* ", "* 1", "A1 MAYBE text"} {
		if r, err := ParseResponse([]byte(line)); err == nil {
			t.Errorf("%q became %+v", line, r)
		}
	}
}

// PREAUTH says the connection is authenticated before anybody claimed an
// identity. A relay that carried it would make every later decision about
// a name it never saw.
func TestPreauthAndTheOtherStatusHelpersNameWhatTheyAre(t *testing.T) {
	for _, tc := range []struct {
		line                        string
		ok, failed, preauth, byeVal bool
	}{
		{"A1 OK done", true, false, false, false},
		{"A1 NO refused", false, true, false, false},
		{"A1 BAD nonsense", false, true, false, false},
		{"* PREAUTH in", false, false, true, false},
		{"* BYE out", false, false, false, true},
	} {
		r, err := ParseResponse([]byte(tc.line))
		if err != nil {
			t.Fatalf("%q: %v", tc.line, err)
		}
		if r.OK() != tc.ok || r.Failed() != tc.failed ||
			r.Preauth() != tc.preauth || r.Bye() != tc.byeVal {
			t.Errorf("%q: ok %v failed %v preauth %v bye %v",
				tc.line, r.OK(), r.Failed(), r.Preauth(), r.Bye())
		}
	}
}

// A capability list is narrowed rather than rewritten: a client that
// parses it positionally should see the server's order, minus what this
// relay will not carry.
func TestACapabilityListIsNarrowedWithoutReordering(t *testing.T) {
	caps := ParseCaps("IMAP4rev2 STARTTLS auth=plain AUTH=GSSAPI LITERAL+ COMPRESS=DEFLATE IDLE")
	if !caps.Has("literal+") || caps.Has("MOVE") {
		t.Fatalf("Has is wrong on %v", caps)
	}
	if got := caps.Mechanisms(); len(got) != 2 || got[0] != "PLAIN" || got[1] != "GSSAPI" {
		t.Fatalf("mechanisms %q", got)
	}
	narrowed := caps.Without(func(c string) bool {
		return Compressed(c) || c == "AUTH=PLAIN"
	})
	want := "IMAP4REV2 STARTTLS AUTH=GSSAPI LITERAL+ IDLE"
	if narrowed.String() != want {
		t.Fatalf("narrowed to %q, want %q", narrowed, want)
	}
	with := narrowed.With("loginDisabled").With("LOGINDISABLED")
	if n := strings.Count(with.String(), "LOGINDISABLED"); n != 1 {
		t.Fatalf("LOGINDISABLED appears %d times in %q", n, with)
	}
	if !Plaintext("plain") || !Plaintext("LOGIN") || Plaintext("GSSAPI") {
		t.Error("Plaintext names the wrong mechanisms")
	}
}

// A policy written about "Sent" has to compare the name the server
// stores, and RFC 3501 spells a non-ASCII name in a modified UTF-7 that
// no amount of string comparison will see through.
func TestAModifiedUTF7MailboxNameIsDecoded(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"INBOX", "INBOX"},
		{"Sent Items", "Sent Items"},
		{"~peter/mail/&U,BTFw-/&ZeVnLIqe-", "~peter/mail/台北/日本語"},
		{"&-", "&"},
		{"a&-b", "a&b"},
		{"&AOQ-", "ä"},
		{"Отправленные", "Отправленные"},
	} {
		got, err := DecodeMailbox(tc.in)
		if err != nil {
			t.Errorf("%q: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%q decoded to %q, want %q", tc.in, got, tc.want)
		}
	}
	for _, in := range []string{
		"&",
		"&AOQ",
		"&!!!!-",
		"&AO-",
		"IN\x01BOX",
		strings.Repeat("x", MaxMailbox+1),
		"\xff\xfe",
	} {
		if got, err := DecodeMailbox(in); err == nil {
			t.Errorf("%q decoded to %q, want a refusal", in, got)
		}
	}
}

// A sequence set is counted rather than expanded: `1:*` is three
// characters and every message in the mailbox, which is what copying one
// looks like and what a bound is for.
func TestASequenceSetIsCountedWithoutBeingExpanded(t *testing.T) {
	for _, tc := range []struct {
		in    string
		terms int
		open  bool
		count uint64
	}{
		{"1", 1, false, 1},
		{"1:5", 1, false, 5},
		{"5:1", 1, false, 5},
		{"1,3,5", 3, false, 3},
		{"1:*", 1, true, 0},
		{"*", 1, true, 0},
		{"1:3,10:*", 2, true, 0},
		{"4294967295", 1, false, 1},
	} {
		got, err := ParseSeqSet(tc.in, 0)
		if err != nil {
			t.Errorf("%q: %v", tc.in, err)
			continue
		}
		if got.Terms != tc.terms || got.Open != tc.open || got.Count != tc.count {
			t.Errorf("%q: %+v, want terms %d open %v count %d",
				tc.in, got, tc.terms, tc.open, tc.count)
		}
	}
	for _, in := range []string{"", "0", "1:0", "a", "1:b", "1,,2", "4294967296"} {
		if got, err := ParseSeqSet(in, 0); err == nil {
			t.Errorf("%q became %+v", in, got)
		}
	}
	if _, err := ParseSeqSet("1,2,3,4", 3); !errors.Is(err, ErrBadSeqSet) {
		t.Error("a set past the term bound was accepted")
	}
}

// The three questions a policy asks of a command, each of which the
// relay answers for itself rather than by reading the server's mind.
func TestWhatACommandIsForPolicyPurposes(t *testing.T) {
	for _, tc := range []struct {
		line                  string
		writes, collects      bool
		mech, user            string
		mechInitial, hasLogin bool
	}{
		{line: "t FETCH 1 (RFC822)", collects: true},
		{line: "t UID FETCH 1 (RFC822)", collects: true},
		{line: "t SEARCH ALL", collects: true},
		{line: "t COPY 1 Archive", writes: true, collects: true},
		{line: "t APPEND INBOX {3}", writes: true},
		{line: "t EXPUNGE", writes: true},
		{line: "t SELECT INBOX"},
		{line: "t LOGIN bob secret", user: "bob", hasLogin: true},
		{line: "t AUTHENTICATE PLAIN", mech: "PLAIN"},
		{line: "t AUTHENTICATE PLAIN aGk=", mech: "PLAIN", mechInitial: true},
	} {
		c, err := ParseCommand([]byte(tc.line))
		if err != nil {
			t.Errorf("%q: %v", tc.line, err)
			continue
		}
		if Writes(c) != tc.writes || Collects(c) != tc.collects {
			t.Errorf("%q: writes %v collects %v", tc.line, Writes(c), Collects(c))
		}
		mech, initial := Mechanism(c)
		if mech != tc.mech || initial != tc.mechInitial {
			t.Errorf("%q: mechanism %q initial %v", tc.line, mech, initial)
		}
		user, ok := Login(c)
		if user != tc.user || ok != tc.hasLogin {
			t.Errorf("%q: login %q %v", tc.line, user, ok)
		}
	}
}

// The state names are what the configuration reference and the log lines
// print, so a number that escaped would be an operator reading "state(7)".
func TestTheStateNamesAreTheOnesWritten(t *testing.T) {
	for s, want := range map[State]string{
		StateNone:     "not-authenticated",
		StateAuth:     "authenticated",
		StateSelected: "selected",
		StateLogout:   "logout",
		State(9):      "state(9)",
	} {
		if got := s.String(); got != want {
			t.Errorf("state %d is %q, want %q", int(s), got, want)
		}
	}
}
