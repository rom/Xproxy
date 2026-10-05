// Package pop3 holds the protocol pieces a POP3-aware proxy needs:
// reading commands and replies with hard bounds, knowing which commands
// belong to which state, knowing which replies are multi-line, and
// reading the CAPA list so a relay can narrow it.
//
// POP3 is a small protocol and the smallness is the trap. Three things
// here exist because of it.
//
// **Whether a reply is one line or many depends on the command, and for
// two commands on whether it had an argument.** `LIST` lists every
// message and ends with a dot; `LIST 3` answers one line. `UIDL` is the
// same. A relay that guessed wrong would read the next client command as
// part of the previous reply, or wait for a terminator that is never
// coming, and either way the two ends have desynchronised -- which on
// this protocol means the client is shown somebody else's mail or none
// of its own.
//
// **The terminator is a line with one dot, and a body line that starts
// with a dot is sent with two.** That is RFC 1939 §3's byte-stuffing,
// and it is the same class of ambiguity as SMTP's: a reader that does not
// unstuff sees a message end where the sender did not put one.
//
// **The credential is in the second command.** `USER` names an identity
// and `PASS` sends the password in the clear, one line later, with
// nothing in between. There is no negotiation to inspect and no
// mechanism to refuse: either the connection is encrypted by the time
// PASS arrives or the password has been published. The relay's
// require_tls is that line, and it cannot be a shadow-mode decision for
// the same reason.
package pop3

import (
	"bufio"
	"errors"
	"io"
	"strconv"
	"strings"
)

// The bounds RFC 1939 sets, which are the defaults the configuration
// starts from.
const (
	// MaxCommandLine is the bound on a command line including CRLF. RFC
	// 1939 §3 bounds a keyword to four characters and an argument to
	// forty; 512 is the conventional line limit and leaves room for the
	// base64 of an AUTH exchange, which RFC 5034 puts on a line of its
	// own.
	MaxCommandLine = 512
	// MaxAuthLine is the bound on one line of a SASL exchange, whose
	// base64 can be longer than a command: a GSSAPI token does not fit
	// in 512 octets.
	MaxAuthLine = 8192
	// MaxReplyLine is the bound on one line of a reply, including a line
	// of a retrieved message. RFC 5322 §2.1.1 bounds a message line to
	// 1000 octets including CRLF; servers send longer ones, so this is
	// the conventional 4096 rather than the standard's number.
	MaxReplyLine = 4096
	// MaxMultiLines bounds the lines of a multi-line reply that is not
	// message content: a CAPA list, a LIST, a UIDL. A mailbox with a
	// hundred thousand messages makes a UIDL of a hundred thousand
	// lines, which is a bound to count rather than refuse, so this is
	// generous and finite.
	MaxMultiLines = 1 << 20
	// MaxArgs bounds a command's arguments. No POP3 command takes more
	// than two.
	MaxArgs = 8
)

var (
	// ErrLineTooLong is a line over the configured bound.
	ErrLineTooLong = errors.New("pop3: line too long")
	// ErrBareNewline is a line ended by LF without the CR, which is the
	// terminator ambiguity this protocol shares with SMTP.
	ErrBareNewline = errors.New("pop3: bare newline")
	// ErrBareCR is a CR that is not followed by LF.
	ErrBareCR = errors.New("pop3: bare carriage return")
	// ErrControl is a control character in a command or a reply's text.
	ErrControl = errors.New("pop3: control character")
	// ErrEmptyLine is a line with nothing on it where a command was
	// expected.
	ErrEmptyLine = errors.New("pop3: empty line")
	// ErrBadCommand is a line whose keyword is not one.
	ErrBadCommand = errors.New("pop3: malformed command")
	// ErrTooManyArgs is a command line with more arguments than any POP3
	// command takes.
	ErrTooManyArgs = errors.New("pop3: too many arguments")
	// ErrBadReply is a reply that begins with neither +OK nor -ERR.
	ErrBadReply = errors.New("pop3: malformed reply")
	// ErrBadNumber is a message number that is not a positive integer.
	ErrBadNumber = errors.New("pop3: malformed message number")
	// ErrTooManyLines is a multi-line reply past MaxMultiLines.
	ErrTooManyLines = errors.New("pop3: reply has too many lines")
)

// Reader reads CRLF-terminated lines with a hard bound and no bare
// newlines, and unstuffs the leading dot of a multi-line body.
type Reader struct {
	br *bufio.Reader
	// max is the bound in force, and ceiling is the buffer's, which is
	// fixed when the reader is made. SetMax cannot raise the bound past
	// the buffer, because a line longer than the buffer is refused by the
	// buffer whatever the bound says -- so a reader is made with the
	// longest line its session will ever read (the AUTH exchange's) and
	// lowered to the command bound, rather than the other way round.
	max, ceiling int
}

// NewReader returns a Reader over r bounded to max octets per line
// including the CRLF. The buffer is sized to max, which is therefore the
// highest bound SetMax can restore.
func NewReader(r io.Reader, max int) *Reader {
	if max < 64 {
		max = 64
	}
	return &Reader{br: bufio.NewReaderSize(r, max+2), max: max, ceiling: max}
}

// Buffered is the number of octets read from the connection and not yet
// consumed. After STLS, anything buffered was sent before the client
// could have seen the answer, which is the injection this protocol has
// in common with SMTP's STARTTLS.
func (r *Reader) Buffered() int { return r.br.Buffered() }

// SetMax changes the line bound: the AUTH exchange raises it and the
// command loop lowers it again. It is clamped to the bound the reader was
// made with, which is the buffer's size.
func (r *Reader) SetMax(max int) {
	switch {
	case max < 64:
		max = 64
	case max > r.ceiling:
		max = r.ceiling
	}
	r.max = max
}

// ReadLine reads one line and returns it without the CRLF.
func (r *Reader) ReadLine() ([]byte, error) {
	line, err := r.br.ReadSlice('\n')
	switch {
	case errors.Is(err, bufio.ErrBufferFull):
		r.discardLine()
		return nil, ErrLineTooLong
	case err == nil && len(line) > r.max:
		return nil, ErrLineTooLong
	case err != nil:
		return nil, err
	}
	body := line[:len(line)-1]
	if n := len(body); n > 0 && body[n-1] == '\r' {
		body = body[:n-1]
	} else {
		return nil, ErrBareNewline
	}
	for _, b := range body {
		if b == '\r' {
			return nil, ErrBareCR
		}
	}
	out := make([]byte, len(body))
	copy(out, body)
	return out, nil
}

func (r *Reader) discardLine() {
	for {
		_, err := r.br.ReadSlice('\n')
		if err == nil || !errors.Is(err, bufio.ErrBufferFull) {
			return
		}
	}
}

// Terminator reports whether a line is the single dot that ends a
// multi-line reply.
func Terminator(line []byte) bool { return len(line) == 1 && line[0] == '.' }

// Unstuff removes the extra dot RFC 1939 §3 requires on a body line that
// starts with one. The line that comes back is what the sender wrote,
// which is what an inspection has to see and what a re-emitted line has
// to be stuffed again from.
func Unstuff(line []byte) []byte {
	if len(line) > 1 && line[0] == '.' {
		return line[1:]
	}
	return line
}

// Stuff adds the dot back, for a line this relay re-emits rather than
// forwards verbatim.
func Stuff(line []byte) []byte {
	if len(line) > 0 && line[0] == '.' {
		out := make([]byte, 0, len(line)+1)
		return append(append(out, '.'), line...)
	}
	return line
}

// State is where a connection stands in RFC 1939 §3: before a credential
// is accepted, after it, or in the update that happens at QUIT.
type State int

// The three states.
const (
	// StateAuthorization is before a credential has been accepted.
	StateAuthorization State = iota
	// StateTransaction is after it: the mailbox is open.
	StateTransaction
	// StateUpdate is the state a QUIT enters, where the deletions of the
	// session are applied. No command is legal in it.
	StateUpdate
)

// String names a state the way the configuration reference spells it.
func (s State) String() string {
	switch s {
	case StateAuthorization:
		return "authorization"
	case StateTransaction:
		return "transaction"
	case StateUpdate:
		return "update"
	}
	return "state(" + strconv.Itoa(int(s)) + ")"
}

// states is the command table: which states each command may be sent in.
// RFC 1939 §5 and §6 give the base set, RFC 2449 adds CAPA in both
// states, RFC 2595 adds STLS in the authorization state only -- an
// upgrade after the password is no upgrade -- and RFC 5034 adds AUTH
// there too.
var states = map[string][]State{
	"USER": {StateAuthorization},
	"PASS": {StateAuthorization},
	"APOP": {StateAuthorization},
	"AUTH": {StateAuthorization},
	"STLS": {StateAuthorization},
	"CAPA": {StateAuthorization, StateTransaction},
	"QUIT": {StateAuthorization, StateTransaction},
	"NOOP": {StateTransaction},
	"STAT": {StateTransaction},
	"LIST": {StateTransaction},
	"UIDL": {StateTransaction},
	"RETR": {StateTransaction},
	"TOP":  {StateTransaction},
	"DELE": {StateTransaction},
	"RSET": {StateTransaction},
}

// Known reports whether this package recognises a command name.
func Known(name string) bool {
	_, ok := states[strings.ToUpper(name)]
	return ok
}

// Names is every command name this package knows, which is what a
// validation error lists when a rule names something else.
func Names() []string {
	out := make([]string, 0, len(states))
	for n := range states {
		out = append(out, n)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// AllowedIn reports whether a command may be sent in a state.
func AllowedIn(name string, s State) bool {
	for _, want := range states[strings.ToUpper(name)] {
		if want == s {
			return true
		}
	}
	return false
}

// Command is one client command line.
type Command struct {
	// Name is the keyword, upper cased.
	Name string
	// Args are the arguments as they were written.
	Args []string
	// Raw is the line as it arrived, without the CRLF.
	Raw []byte
}

// ParseCommand reads a command line.
func ParseCommand(line []byte) (*Command, error) {
	if len(line) == 0 {
		return nil, ErrEmptyLine
	}
	for _, b := range line {
		if b < 0x20 || b == 0x7f {
			return nil, ErrControl
		}
	}
	fields := strings.Fields(string(line))
	if len(fields) == 0 {
		return nil, ErrEmptyLine
	}
	name := fields[0]
	if len(name) > 16 {
		return nil, ErrBadCommand
	}
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
			return nil, ErrBadCommand
		}
	}
	if len(fields) > MaxArgs {
		return nil, ErrTooManyArgs
	}
	return &Command{Name: strings.ToUpper(name), Args: fields[1:], Raw: line}, nil
}

// Multiline reports whether the successful reply to a command is a
// multi-line one terminated by a dot.
//
// LIST and UIDL are the two whose answer depends on their argument: with
// a message number the answer is one line, without one it is the whole
// mailbox. Getting this wrong desynchronises the two ends of the relay,
// which is why it is a function with a test rather than a set of names.
func (c *Command) Multiline() bool {
	switch c.Name {
	case "RETR", "TOP", "CAPA":
		return true
	case "LIST", "UIDL":
		return len(c.Args) == 0
	}
	return false
}

// Message is the message number a command names, where it names one.
func (c *Command) Message() (uint32, bool, error) {
	switch c.Name {
	case "RETR", "DELE", "TOP", "LIST", "UIDL":
	default:
		return 0, false, nil
	}
	if len(c.Args) == 0 {
		return 0, false, nil
	}
	n, err := strconv.ParseUint(c.Args[0], 10, 32)
	if err != nil || n == 0 {
		return 0, false, ErrBadNumber
	}
	return uint32(n), true, nil
}

// Lines is the line count a TOP command asks for, which is this
// protocol's one bounded read of a message body.
func (c *Command) Lines() (uint32, bool, error) {
	if c.Name != "TOP" || len(c.Args) < 2 {
		return 0, false, nil
	}
	n, err := strconv.ParseUint(c.Args[1], 10, 32)
	if err != nil {
		return 0, false, ErrBadNumber
	}
	return uint32(n), true, nil
}

// User is the identity a USER command claims.
func (c *Command) User() (string, bool) {
	if c.Name != "USER" || len(c.Args) != 1 {
		return "", false
	}
	return c.Args[0], true
}

// APOPUser is the identity an APOP command claims. The digest beside it
// is a credential and is deliberately not returned: nothing in the relay
// needs it, and a value that is never read cannot be logged by accident.
func (c *Command) APOPUser() (string, bool) {
	if c.Name != "APOP" || len(c.Args) != 2 {
		return "", false
	}
	return c.Args[0], true
}

// Mechanism is the SASL mechanism of an AUTH command, upper cased, with
// whether an initial response was sent beside it. RFC 5034 allows the
// initial response on the command line, where it is a credential.
func (c *Command) Mechanism() (string, bool, bool) {
	if c.Name != "AUTH" || len(c.Args) == 0 {
		return "", false, false
	}
	return strings.ToUpper(c.Args[0]), len(c.Args) > 1, true
}

// Writes reports whether a command changes the mailbox. DELE marks a
// message for deletion and RSET unmarks every one of them; both are
// changes to what the mailbox will hold after the update state, which is
// what a read-only listener refuses.
func (c *Command) Writes() bool {
	switch c.Name {
	case "DELE", "RSET":
		return true
	}
	return false
}

// Collects reports whether a command reads message content, which is
// what a mailbox-copying bound counts: RETR takes a whole message and
// TOP takes the beginning of one.
func (c *Command) Collects() bool {
	switch c.Name {
	case "RETR", "TOP":
		return true
	}
	return false
}

// Reply is one server reply line: the status and its text.
type Reply struct {
	// OK is true for +OK and false for -ERR.
	OK bool
	// Code is the bracketed extended response code of RFC 2449 §8 --
	// IN-USE, LOGIN-DELAY, SYS/PERM, AUTH -- upper cased, or empty.
	Code string
	// Text is the human-readable remainder.
	Text string
	// Raw is the line as it arrived, without the CRLF.
	Raw []byte
}

// ParseReply reads a server reply line.
func ParseReply(line []byte) (*Reply, error) {
	if len(line) == 0 {
		return nil, ErrEmptyLine
	}
	for _, b := range line {
		if b < 0x20 || b == 0x7f {
			return nil, ErrControl
		}
	}
	s := string(line)
	r := &Reply{Raw: line}
	switch {
	case s == "+OK" || strings.HasPrefix(s, "+OK "):
		r.OK, r.Text = true, strings.TrimPrefix(strings.TrimPrefix(s, "+OK"), " ")
	case s == "-ERR" || strings.HasPrefix(s, "-ERR "):
		r.Text = strings.TrimPrefix(strings.TrimPrefix(s, "-ERR"), " ")
	case s == "+" || strings.HasPrefix(s, "+ "):
		// The continuation of a SASL exchange: a challenge, in base64.
		r.OK, r.Text = true, strings.TrimPrefix(strings.TrimPrefix(s, "+"), " ")
		r.Code = "CONTINUE"
		return r, nil
	default:
		return nil, ErrBadReply
	}
	if strings.HasPrefix(r.Text, "[") {
		if end := strings.IndexByte(r.Text, ']'); end > 0 {
			inside := r.Text[1:end]
			name, _, _ := strings.Cut(inside, " ")
			r.Code = strings.ToUpper(name)
			r.Text = strings.TrimPrefix(r.Text[end+1:], " ")
		}
	}
	return r, nil
}

// Continuation reports whether a reply is the `+ ` challenge of a SASL
// exchange rather than the end of one.
func (r *Reply) Continuation() bool { return r.Code == "CONTINUE" }

// Timestamp is the `<...>` of a greeting, which is the challenge an APOP
// digest is computed over. A relay that terminates the client's leg and
// opens its own has two greetings and therefore two timestamps, so an
// APOP digest computed against one cannot be verified against the other
// -- which is why a listener either forwards the server's greeting
// unchanged or refuses APOP, and never both.
func Timestamp(greeting string) (string, bool) {
	i := strings.IndexByte(greeting, '<')
	if i < 0 {
		return "", false
	}
	j := strings.IndexByte(greeting[i:], '>')
	if j < 0 {
		return "", false
	}
	return greeting[i : i+j+1], true
}

// Caps is a CAPA list, upper cased, one capability per line of the
// reply.
type Caps []string

// ParseCaps reads a capability from one line of a CAPA reply and adds it
// to the list.
func (c Caps) ParseCaps(line string) Caps {
	line = strings.TrimSpace(line)
	if line == "" {
		return c
	}
	return append(c, strings.ToUpper(line))
}

// Has reports whether a capability is advertised. The comparison is on
// the first word, because a capability line carries parameters: `SASL
// PLAIN LOGIN` is the SASL capability.
func (c Caps) Has(name string) bool {
	want := strings.ToUpper(name)
	for _, v := range c {
		first, _, _ := strings.Cut(v, " ")
		if first == want {
			return true
		}
	}
	return false
}

// Mechanisms are the SASL mechanism names of the SASL capability line.
func (c Caps) Mechanisms() []string {
	for _, v := range c {
		if first, rest, _ := strings.Cut(v, " "); first == "SASL" {
			return strings.Fields(rest)
		}
	}
	return nil
}

// Plaintext reports whether a SASL mechanism puts the password on the
// wire where anybody on the path can read it.
func Plaintext(mech string) bool {
	switch strings.ToUpper(mech) {
	case "PLAIN", "LOGIN":
		return true
	}
	return false
}
