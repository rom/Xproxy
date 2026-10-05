package pop3

import (
	"errors"
	"strings"
	"testing"
)

// A command is a keyword and at most two arguments, and the keyword is
// what a policy is written about.
func TestACommandIsReadAsAKeywordAndItsArguments(t *testing.T) {
	for _, tc := range []struct {
		line string
		name string
		args []string
	}{
		{"CAPA", "CAPA", nil},
		{"user bob", "USER", []string{"bob"}},
		{"PASS secret", "PASS", []string{"secret"}},
		{"RETR 3", "RETR", []string{"3"}},
		{"TOP 3 10", "TOP", []string{"3", "10"}},
		{"  LIST   3  ", "LIST", []string{"3"}},
		{"AUTH PLAIN aGk=", "AUTH", []string{"PLAIN", "aGk="}},
	} {
		c, err := ParseCommand([]byte(tc.line))
		if err != nil {
			t.Errorf("%q: %v", tc.line, err)
			continue
		}
		if c.Name != tc.name || len(c.Args) != len(tc.args) {
			t.Errorf("%q: %+v, want %q %q", tc.line, c, tc.name, tc.args)
			continue
		}
		for i := range tc.args {
			if c.Args[i] != tc.args[i] {
				t.Errorf("%q: arg %d is %q, want %q", tc.line, i, c.Args[i], tc.args[i])
			}
		}
	}
	for _, line := range []string{
		"",
		"   ",
		"RETR\x003",
		"RE\x1b[2JTR 1",
		"RETR1234567890123456 1",
		"4RETR 1",
		"LIST 1 2 3 4 5 6 7 8 9",
	} {
		if c, err := ParseCommand([]byte(line)); err == nil {
			t.Errorf("%q became %+v", line, c)
		}
	}
}

// Whether a reply is one line or many is the thing a POP3 relay cannot
// get wrong: guess it and the two ends have desynchronised, which means
// the client is shown somebody else's mail or none of its own. LIST and
// UIDL are the two whose answer depends on their argument.
func TestWhetherAReplyIsMultiLineDependsOnTheCommandAndItsArgument(t *testing.T) {
	for _, tc := range []struct {
		line string
		want bool
	}{
		{"RETR 1", true},
		{"TOP 1 5", true},
		{"CAPA", true},
		{"LIST", true},
		{"LIST 3", false},
		{"UIDL", true},
		{"UIDL 3", false},
		{"STAT", false},
		{"DELE 1", false},
		{"USER bob", false},
		{"QUIT", false},
	} {
		c, err := ParseCommand([]byte(tc.line))
		if err != nil {
			t.Fatalf("%q: %v", tc.line, err)
		}
		if got := c.Multiline(); got != tc.want {
			t.Errorf("%q: multiline %v, want %v", tc.line, got, tc.want)
		}
	}
}

// The terminator is a line with one dot and a body line that starts with
// one arrives with two. A reader that does not unstuff sees a message end
// where the sender did not put one.
func TestTheTerminatorAndTheStuffedDotAreTheSameAmbiguityAsSMTPs(t *testing.T) {
	if !Terminator([]byte(".")) {
		t.Error("a single dot is the terminator")
	}
	for _, line := range []string{"..", ". ", "", "x"} {
		if Terminator([]byte(line)) {
			t.Errorf("%q was read as the terminator", line)
		}
	}
	for _, tc := range []struct{ in, want string }{
		{"..hidden", ".hidden"},
		{"...", ".."},
		{"ordinary", "ordinary"},
		{".", "."},
		{"", ""},
	} {
		if got := string(Unstuff([]byte(tc.in))); got != tc.want {
			t.Errorf("Unstuff(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// Stuffing is the inverse on every line a relay re-emits, which is
	// what keeps a rewritten line from ending the message early.
	for _, line := range []string{".hidden", "..", "ordinary", ""} {
		stuffed := Stuff([]byte(line))
		if got := string(Unstuff(stuffed)); got != line {
			t.Errorf("Stuff then Unstuff of %q gave %q", line, got)
		}
	}
}

// The state table is the relay's own answer. STLS belongs to the
// authorization state only: an upgrade offered after the password has
// gone past is no upgrade.
func TestTheStateTableIsWhatTheRFCsSay(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state State
		want  bool
	}{
		{"USER", StateAuthorization, true},
		{"USER", StateTransaction, false},
		{"PASS", StateAuthorization, true},
		{"STLS", StateAuthorization, true},
		{"STLS", StateTransaction, false},
		{"AUTH", StateAuthorization, true},
		{"CAPA", StateAuthorization, true},
		{"CAPA", StateTransaction, true},
		{"RETR", StateAuthorization, false},
		{"RETR", StateTransaction, true},
		{"DELE", StateTransaction, true},
		{"QUIT", StateTransaction, true},
		{"RETR", StateUpdate, false},
		{"NONSENSE", StateTransaction, false},
	} {
		if got := AllowedIn(tc.name, tc.state); got != tc.want {
			t.Errorf("%s in %s: %v, want %v", tc.name, tc.state, got, tc.want)
		}
	}
	if !Known("retr") || Known("RETRX") {
		t.Error("Known does not fold case or admits what it should not")
	}
	if names := Names(); len(names) != 15 || names[0] != "APOP" {
		t.Errorf("Names returned %v", names)
	}
	for s, want := range map[State]string{
		StateAuthorization: "authorization",
		StateTransaction:   "transaction",
		StateUpdate:        "update",
		State(7):           "state(7)",
	} {
		if got := s.String(); got != want {
			t.Errorf("state %d is %q, want %q", int(s), got, want)
		}
	}
}

// A reply is read for its status, its extended response code and nothing
// else: the text is the server's and goes into a log line, so it is
// checked for what a terminal would act on.
func TestAReplyIsReadForItsStatusAndCode(t *testing.T) {
	for _, tc := range []struct {
		line string
		ok   bool
		code string
		text string
	}{
		{"+OK", true, "", ""},
		{"+OK 2 messages", true, "", "2 messages"},
		{"-ERR", false, "", ""},
		{"-ERR invalid command", false, "", "invalid command"},
		{"-ERR [AUTH] authentication failed", false, "AUTH", "authentication failed"},
		{"-ERR [IN-USE] mailbox is locked", false, "IN-USE", "mailbox is locked"},
		{"+OK [LOGIN-DELAY 60] wait", true, "LOGIN-DELAY", "wait"},
		{"+ aGVsbG8=", true, "CONTINUE", "aGVsbG8="},
	} {
		r, err := ParseReply([]byte(tc.line))
		if err != nil {
			t.Errorf("%q: %v", tc.line, err)
			continue
		}
		if r.OK != tc.ok || r.Code != tc.code || r.Text != tc.text {
			t.Errorf("%q: %+v, want ok %v code %q text %q", tc.line, r, tc.ok, tc.code, tc.text)
		}
	}
	if r, _ := ParseReply([]byte("+ Y2hhbGxlbmdl")); !r.Continuation() {
		t.Error("a SASL challenge is a continuation")
	}
	if r, _ := ParseReply([]byte("+OK done")); r.Continuation() {
		t.Error("+OK is not a continuation")
	}
	for _, line := range []string{"", "OK", "+OKAY fine", "-ERROR bad", "rubbish", "+OK \x07"} {
		if r, err := ParseReply([]byte(line)); err == nil {
			t.Errorf("%q became %+v", line, r)
		}
	}
}

// A line over the bound is refused and the next command still reads, and
// CRLF is the terminator in both directions.
func TestTheReaderBoundsALineAndRefusesTheAmbiguousEndings(t *testing.T) {
	long := "RETR " + strings.Repeat("9", 200)
	r := NewReader(strings.NewReader(long+"\r\nSTAT\r\n"), 64)
	if _, err := r.ReadLine(); !errors.Is(err, ErrLineTooLong) {
		t.Fatalf("long line: %v, want ErrLineTooLong", err)
	}
	if line, err := r.ReadLine(); err != nil || string(line) != "STAT" {
		t.Fatalf("after the long line: %q %v", line, err)
	}
	if _, err := NewReader(strings.NewReader("STAT\n"), 64).ReadLine(); !errors.Is(err, ErrBareNewline) {
		t.Error("a bare LF was accepted")
	}
	if _, err := NewReader(strings.NewReader("ST\rAT\r\n"), 64).ReadLine(); !errors.Is(err, ErrBareCR) {
		t.Error("a bare CR was accepted")
	}
	// The AUTH exchange needs a longer line than a command does, so a
	// session makes its reader with the longer bound and lowers it for the
	// command loop. Raising it past the buffer is clamped rather than
	// granted, because the buffer would refuse the line anyway.
	big := NewReader(strings.NewReader(strings.Repeat("A", 600)+"\r\nSTAT\r\n"), MaxAuthLine)
	big.SetMax(64)
	if _, err := big.ReadLine(); !errors.Is(err, ErrLineTooLong) {
		t.Fatalf("under the command bound: %v, want ErrLineTooLong", err)
	}
	big.SetMax(MaxAuthLine)
	if line, err := big.ReadLine(); err != nil || string(line) != "STAT" {
		t.Fatalf("after SetMax: %q %v", line, err)
	}
	clamped := NewReader(strings.NewReader("x\r\n"), 64)
	clamped.SetMax(1 << 20)
	if _, err := clamped.ReadLine(); err != nil {
		t.Fatalf("a clamped bound refused an ordinary line: %v", err)
	}
}

// The numbers a command carries are read where it carries them, and a
// message number that is not one is refused rather than guessed at.
func TestTheNumbersACommandCarriesAreRead(t *testing.T) {
	for _, tc := range []struct {
		line    string
		msg     uint32
		hasMsg  bool
		lines   uint32
		hasLine bool
	}{
		{line: "RETR 3", msg: 3, hasMsg: true},
		{line: "DELE 12", msg: 12, hasMsg: true},
		{line: "TOP 4 10", msg: 4, hasMsg: true, lines: 10, hasLine: true},
		{line: "TOP 4 0", msg: 4, hasMsg: true, lines: 0, hasLine: true},
		{line: "LIST"},
		{line: "UIDL"},
		{line: "STAT"},
	} {
		c, err := ParseCommand([]byte(tc.line))
		if err != nil {
			t.Fatalf("%q: %v", tc.line, err)
		}
		msg, ok, err := c.Message()
		if err != nil || msg != tc.msg || ok != tc.hasMsg {
			t.Errorf("%q: message %d %v %v", tc.line, msg, ok, err)
		}
		lines, ok, err := c.Lines()
		if err != nil || lines != tc.lines || ok != tc.hasLine {
			t.Errorf("%q: lines %d %v %v", tc.line, lines, ok, err)
		}
	}
	for _, line := range []string{"RETR 0", "RETR x", "DELE -1", "TOP 1 x"} {
		c, err := ParseCommand([]byte(line))
		if err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		_, _, msgErr := c.Message()
		_, _, lineErr := c.Lines()
		if msgErr == nil && lineErr == nil {
			t.Errorf("%q: neither number was refused", line)
		}
	}
}

// The identity arrives in the clear and the credential beside it is
// deliberately not returned: a value nothing reads cannot be logged by
// accident.
func TestTheIdentityIsReadAndTheCredentialIsNot(t *testing.T) {
	c, _ := ParseCommand([]byte("USER bob"))
	if u, ok := c.User(); !ok || u != "bob" {
		t.Errorf("USER gave %q %v", u, ok)
	}
	a, _ := ParseCommand([]byte("APOP bob c4c9334bac560ecc979e58001b3e22fb"))
	if u, ok := a.APOPUser(); !ok || u != "bob" {
		t.Errorf("APOP gave %q %v", u, ok)
	}
	// Two arguments are required, because one is a name with no digest and
	// three is not this command.
	for _, line := range []string{"APOP bob", "APOP", "USER", "USER bob extra"} {
		c, err := ParseCommand([]byte(line))
		if err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		if _, ok := c.User(); ok && c.Name == "USER" && len(c.Args) != 1 {
			t.Errorf("%q was read as a user name", line)
		}
		if _, ok := c.APOPUser(); ok && len(c.Args) != 2 {
			t.Errorf("%q was read as an APOP", line)
		}
	}
	m, _ := ParseCommand([]byte("AUTH PLAIN aGk="))
	mech, initial, ok := m.Mechanism()
	if !ok || mech != "PLAIN" || !initial {
		t.Errorf("AUTH gave %q initial %v ok %v", mech, initial, ok)
	}
	bare, _ := ParseCommand([]byte("auth gssapi"))
	mech, initial, ok = bare.Mechanism()
	if !ok || mech != "GSSAPI" || initial {
		t.Errorf("AUTH GSSAPI gave %q initial %v ok %v", mech, initial, ok)
	}
}

// What a command does to the mailbox, and what it takes out of it: the
// two questions a read-only listener and a copying bound ask.
func TestWritesAndCollectsNameWhatTheyAre(t *testing.T) {
	for _, tc := range []struct {
		line             string
		writes, collects bool
	}{
		{"DELE 1", true, false},
		{"RSET", true, false},
		{"RETR 1", false, true},
		{"TOP 1 10", false, true},
		{"LIST", false, false},
		{"UIDL", false, false},
		{"STAT", false, false},
	} {
		c, err := ParseCommand([]byte(tc.line))
		if err != nil {
			t.Fatalf("%q: %v", tc.line, err)
		}
		if c.Writes() != tc.writes || c.Collects() != tc.collects {
			t.Errorf("%q: writes %v collects %v", tc.line, c.Writes(), c.Collects())
		}
	}
}

// A CAPA list is read one line at a time, and the SASL line is where the
// mechanisms are. A capability carries parameters, so the comparison is
// on the first word.
func TestTheCapabilityListIsReadLineByLine(t *testing.T) {
	var caps Caps
	for _, line := range []string{"TOP", "USER", "SASL plain login", "STLS", "UIDL", "  ", ""} {
		caps = caps.ParseCaps(line)
	}
	if len(caps) != 5 {
		t.Fatalf("caps %v", caps)
	}
	for _, want := range []string{"top", "STLS", "sasl", "UIDL"} {
		if !caps.Has(want) {
			t.Errorf("Has(%q) is false on %v", want, caps)
		}
	}
	if caps.Has("PIPELINING") {
		t.Error("Has invented a capability")
	}
	// The names are folded upper, because a mechanism name is
	// case-insensitive and a policy comparing two spellings compares
	// nothing.
	mechs := caps.Mechanisms()
	if len(mechs) != 2 || mechs[0] != "PLAIN" || mechs[1] != "LOGIN" {
		t.Errorf("mechanisms %q", mechs)
	}
	if !Plaintext("plain") || !Plaintext("LOGIN") || Plaintext("CRAM-MD5") {
		t.Error("Plaintext names the wrong mechanisms")
	}
	if got := (Caps{"TOP"}).Mechanisms(); got != nil {
		t.Errorf("a list with no SASL line gave %q", got)
	}
}

// The greeting's timestamp is the challenge an APOP digest is computed
// over, and a relay that terminates both legs has two of them -- which is
// why it is recognised rather than assumed.
func TestTheGreetingTimestampIsFoundOrAbsent(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
		ok   bool
	}{
		{"+OK POP3 server ready <1896.697170952@dbc.mtview.ca.us>", "<1896.697170952@dbc.mtview.ca.us>", true},
		{"+OK ready", "", false},
		{"+OK <unterminated", "", false},
		{"+OK <>", "<>", true},
	} {
		got, ok := Timestamp(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("Timestamp(%q) = %q %v, want %q %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}
