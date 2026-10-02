// Package imap holds the protocol pieces an IMAP-aware proxy needs:
// reading commands and responses with hard bounds, recognising the
// literal a command ends with before its octets arrive, knowing which
// state each command belongs to, and reading the capability list a
// server advertises so a relay can narrow it.
//
// Nothing here talks to a network by itself. The session that does lives
// in the proxy; keeping the parsing separate is what makes the awkward
// cases testable without a mail server -- and IMAP has more of them than
// any other protocol in this project.
//
// Four of those cases are the reason this package exists.
//
// **A command can end in a literal, and the octets have not arrived
// yet.** `A1 APPEND INBOX {310}` says the next 310 octets are the
// argument, and a server that wants them answers with a continuation
// request first. A relay that decides about the command only after
// reading the literal has already accepted a message of whatever size
// the client chose; one that decides on the command line can refuse
// before the first octet. RFC 7888's LITERAL+ removes the continuation
// -- `{310+}` sends immediately -- which is exactly why a bound on it
// has to be checked against the declared size rather than against what
// was read.
//
// **A tag is chosen by the client.** It is echoed in the tagged response
// and is how a relay matches an answer to its question, so it is read
// with a length bound and refused if it carries anything a tag may not
// (RFC 9051's tag is an astring without `+`).
//
// **The command set is stateful.** SELECT belongs to the authenticated
// state, FETCH to the selected state, LOGIN to neither of those; a
// client that sends FETCH before SELECT is either broken or probing.
// The table here says which state each command belongs to, so the relay
// can refuse rather than forward and let the server decide.
//
// **A mailbox name is not a string.** RFC 3501 §5.1.3 encodes non-ASCII
// mailbox names in a modified UTF-7, so a policy written about a name
// has to compare the decoded form or it compares nothing. RFC 9051
// allows UTF-8 directly where the client has said UTF8=ACCEPT, so both
// spellings reach the same decision.
package imap

import (
	"bufio"
	"errors"
	"io"
	"strconv"
	"strings"
)

// The bounds a relay chooses. IMAP itself bounds almost nothing: RFC
// 9051 §4 says a line may be arbitrarily long and leaves the limit to
// the implementation, which means the limit is whatever the first peer
// to run out of memory decides.
const (
	// MaxCommandLine is the default bound on one command line including
	// CRLF. Eight kilobytes is far past any client's longest FETCH and
	// far short of a memory attack.
	MaxCommandLine = 8192
	// MaxResponseLine is the default bound on one response line. Servers
	// send longer lines than clients: a FETCH of a header, a LIST of a
	// thousand mailboxes in one untagged response, an envelope with
	// forty recipients.
	MaxResponseLine = 1 << 16
	// MaxTag is the longest tag accepted. Clients use four or five
	// octets; a tag is echoed in every answer, so a long one is a way to
	// make the server spend memory on the relay's behalf.
	MaxTag = 64
	// MaxArgs bounds the arguments read from one command line. A FETCH
	// macro expands to a handful and a SEARCH to dozens; a thousand is
	// a client that is not a mail client.
	MaxArgs = 1024
	// MaxMailbox is the longest mailbox name read. RFC 9051 does not
	// bound it; no server stores one this long.
	MaxMailbox = 1024
	// MaxLiteral is the default ceiling on a literal's declared size,
	// which is also the bound on an APPEND. 32 MiB is larger than every
	// attachment limit an estate configures and small enough that a
	// client cannot ask the server to hold a gigabyte.
	MaxLiteral = 32 << 20
	// MaxSeqTerms bounds the comma-separated terms of a sequence set.
	// `1:*` is one term; ten thousand of them is a request whose cost is
	// the client's to choose and the server's to pay.
	MaxSeqTerms = 1024
)

var (
	// ErrLineTooLong is a line over the configured bound. The session
	// answers BAD and counts it rather than reading on, because the rest
	// of that line would be read as a command of its own.
	ErrLineTooLong = errors.New("imap: line too long")
	// ErrBareNewline is a line ended by LF without the CR. RFC 9051
	// §2.2 makes CRLF the terminator, and accepting a bare LF is how two
	// peers come to disagree about where a command ends.
	ErrBareNewline = errors.New("imap: bare newline")
	// ErrBareCR is a CR that is not followed by LF, the same
	// disagreement from the other side.
	ErrBareCR = errors.New("imap: bare carriage return")
	// ErrControl is a control character in a place the grammar does not
	// allow one. A tag or a mailbox name carrying a CR, a NUL or a
	// terminal escape is never legitimate and is how a log line or a
	// second command gets forged.
	ErrControl = errors.New("imap: control character")
	// ErrEmptyLine is a line with nothing on it where a command was
	// expected.
	ErrEmptyLine = errors.New("imap: empty line")
	// ErrBadTag is a tag that is missing, too long, or carries a
	// character a tag may not.
	ErrBadTag = errors.New("imap: malformed tag")
	// ErrBadCommand is a line with a tag and no command name.
	ErrBadCommand = errors.New("imap: malformed command")
	// ErrBadLiteral is a literal whose braces do not parse, whose size
	// is not a number, or which is not at the end of the line. A literal
	// anywhere but the end is a line the relay and the server would read
	// differently: the server waits for octets, the relay for a CRLF.
	ErrBadLiteral = errors.New("imap: malformed literal")
	// ErrLiteralTooLarge is a literal declaring more octets than the
	// bound allows.
	ErrLiteralTooLarge = errors.New("imap: literal too large")
	// ErrTooManyArgs is a command line with more arguments than the
	// bound allows.
	ErrTooManyArgs = errors.New("imap: too many arguments")
	// ErrUnterminated is a quoted string with no closing quote, or a
	// parenthesised list that does not close.
	ErrUnterminated = errors.New("imap: unterminated argument")
	// ErrBadResponse is a response line that is neither tagged nor
	// untagged nor a continuation request.
	ErrBadResponse = errors.New("imap: malformed response")
	// ErrBadSeqSet is a sequence set that does not parse, or one with
	// more terms than the bound allows.
	ErrBadSeqSet = errors.New("imap: malformed sequence set")
	// ErrBadMailbox is a mailbox name over the bound or carrying a
	// modified UTF-7 escape that does not decode.
	ErrBadMailbox = errors.New("imap: malformed mailbox name")
)

// Reader reads CRLF-terminated lines with a hard bound, and the octets
// of a literal when the caller has decided to allow one. It wraps a
// bufio.Reader so the session can ask what is still buffered, which is
// how the STARTTLS injection check works: anything buffered after the
// command was read was sent before the client could see the answer.
type Reader struct {
	br *bufio.Reader
	// max is the bound in force and ceiling is the buffer's, fixed when
	// the reader is made. A bound raised past the buffer would be a bound
	// that did not apply: the buffer refuses the line first and says
	// nothing about why.
	max, ceiling int
}

// NewReader returns a Reader over r bounded to max octets per line
// including the CRLF. The buffer is sized to that bound, so a line that
// does not fit is refused rather than grown into -- and that bound is the
// highest SetMax can restore.
func NewReader(r io.Reader, max int) *Reader {
	if max < 64 {
		max = 64
	}
	return &Reader{br: bufio.NewReaderSize(r, max+2), max: max, ceiling: max}
}

// Buffered is the number of octets already read from the connection and
// not yet consumed.
func (r *Reader) Buffered() int { return r.br.Buffered() }

// SetMax changes the line bound, clamped to the bound the reader was made
// with.
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
//
// A line over the bound returns ErrLineTooLong with the rest of that
// line consumed where the reader is mid-line, so a caller that answers
// BAD and carries on is reading the next command rather than the tail of
// this one.
func (r *Reader) ReadLine() ([]byte, error) {
	line, err := r.br.ReadSlice('\n')
	switch {
	case errors.Is(err, bufio.ErrBufferFull):
		r.discardLine()
		return nil, ErrLineTooLong
	case err == nil && len(line) > r.max:
		// A whole line, longer than the bound. The buffer is two octets
		// larger than the bound, so a line that overshoots by one or two
		// arrives complete and the reader already stands at the next
		// line: discarding here would swallow the command after it.
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

// discardLine reads to the end of the current line and throws it away.
func (r *Reader) discardLine() {
	for {
		_, err := r.br.ReadSlice('\n')
		if err == nil || !errors.Is(err, bufio.ErrBufferFull) {
			return
		}
	}
}

// ReadLiteral reads exactly n octets, which is what a literal is. The
// caller has already decided the size is allowed; this is the read, not
// the decision.
func (r *Reader) ReadLiteral(n int) ([]byte, error) {
	if n < 0 {
		return nil, ErrBadLiteral
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r.br, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// CopyLiteral copies exactly n octets to w without holding them, which
// is how a literal larger than anything worth buffering is forwarded
// once the policy has allowed it.
func (r *Reader) CopyLiteral(w io.Writer, n int64) error {
	if n < 0 {
		return ErrBadLiteral
	}
	_, err := io.CopyN(w, r.br, n)
	return err
}

// Discard throws away n octets, which is what happens to the literal of
// a command the relay refused: the client has been told no and is still
// going to send the octets it announced, and the alternative to reading
// them is closing a connection that did nothing wrong.
func (r *Reader) Discard(n int) error {
	_, err := r.br.Discard(n)
	return err
}

// State is where a connection stands in RFC 9051 §3: before
// authentication, after it, with a mailbox selected, or on its way out.
type State int

// The four states, in the order a connection passes through them.
const (
	// StateNone is the not-authenticated state: a greeting has been
	// sent and no credential accepted.
	StateNone State = iota
	// StateAuth is the authenticated state: an identity is established
	// and no mailbox is selected.
	StateAuth
	// StateSelected is the selected state: a mailbox is open and the
	// message commands are legal.
	StateSelected
	// StateLogout is the logout state, which exists so that a command
	// arriving after LOGOUT has somewhere to be refused.
	StateLogout
)

// String names a state the way the configuration reference and the log
// lines spell it.
func (s State) String() string {
	switch s {
	case StateNone:
		return "not-authenticated"
	case StateAuth:
		return "authenticated"
	case StateSelected:
		return "selected"
	case StateLogout:
		return "logout"
	}
	return "state(" + strconv.Itoa(int(s)) + ")"
}

// states is the command table: which states each command may be sent
// in. A command absent from the table is unknown to this relay, which
// is a decision of its own rather than a reason to forward blindly.
//
// The grouping follows RFC 9051 §6: the any-state commands, the
// not-authenticated ones, the authenticated ones and the selected ones.
// Where an extension added a command (IDLE in RFC 2177, MOVE in RFC
// 6851, UNSELECT in RFC 3691, the quota and ACL commands) it is listed
// in the state its own document gives it.
var states = map[string][]State{
	// Any state.
	"CAPABILITY": {StateNone, StateAuth, StateSelected},
	"NOOP":       {StateNone, StateAuth, StateSelected},
	"LOGOUT":     {StateNone, StateAuth, StateSelected},
	"ID":         {StateNone, StateAuth, StateSelected}, // RFC 2971
	"ENABLE":     {StateAuth, StateSelected},            // RFC 9051 §6.3.1

	// Not authenticated.
	"STARTTLS":     {StateNone},
	"AUTHENTICATE": {StateNone},
	"LOGIN":        {StateNone},

	// Authenticated.
	"SELECT":       {StateAuth, StateSelected},
	"EXAMINE":      {StateAuth, StateSelected},
	"CREATE":       {StateAuth, StateSelected},
	"DELETE":       {StateAuth, StateSelected},
	"RENAME":       {StateAuth, StateSelected},
	"SUBSCRIBE":    {StateAuth, StateSelected},
	"UNSUBSCRIBE":  {StateAuth, StateSelected},
	"LIST":         {StateAuth, StateSelected},
	"LSUB":         {StateAuth, StateSelected},
	"NAMESPACE":    {StateAuth, StateSelected}, // RFC 2342
	"STATUS":       {StateAuth, StateSelected},
	"APPEND":       {StateAuth, StateSelected},
	"IDLE":         {StateAuth, StateSelected}, // RFC 2177
	"GETQUOTA":     {StateAuth, StateSelected}, // RFC 9208
	"GETQUOTAROOT": {StateAuth, StateSelected},
	"SETQUOTA":     {StateAuth, StateSelected},
	"GETACL":       {StateAuth, StateSelected}, // RFC 4314
	"SETACL":       {StateAuth, StateSelected},
	"DELETEACL":    {StateAuth, StateSelected},
	"LISTRIGHTS":   {StateAuth, StateSelected},
	"MYRIGHTS":     {StateAuth, StateSelected},

	// Selected.
	"CHECK":    {StateSelected},
	"CLOSE":    {StateSelected},
	"UNSELECT": {StateSelected}, // RFC 3691
	"EXPUNGE":  {StateSelected},
	"SEARCH":   {StateSelected},
	"FETCH":    {StateSelected},
	"STORE":    {StateSelected},
	"COPY":     {StateSelected},
	"MOVE":     {StateSelected}, // RFC 6851
	"UID":      {StateSelected},
	"SORT":     {StateSelected}, // RFC 5256
	"THREAD":   {StateSelected},
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
	return sorted(out)
}

// AllowedIn reports whether a command may be sent in a state. An
// unknown command is allowed in no state, so the caller refuses it with
// a reason of its own rather than this one.
func AllowedIn(name string, s State) bool {
	for _, want := range states[strings.ToUpper(name)] {
		if want == s {
			return true
		}
	}
	return false
}

// Literal is the `{n}` or `{n+}` a command line can end with: the
// declaration that the next n octets are an argument.
type Literal struct {
	// Size is the number of octets declared.
	Size int
	// NonSync is RFC 7888's LITERAL+ form, `{n+}`: the client will send
	// the octets without waiting for a continuation request. It is the
	// form a bound has to be checked against before the octets arrive,
	// because there is no continuation to withhold.
	NonSync bool
}

// Command is one client command line, read as far as a policy needs it.
type Command struct {
	// Tag is the client's tag, echoed in the tagged response.
	Tag string
	// Name is the command name, upper cased. For a UID command it is
	// "UID" and Sub holds the command it qualifies.
	Name string
	// Sub is the command a UID command qualifies -- FETCH, STORE, COPY,
	// MOVE, SEARCH, EXPUNGE -- upper cased, or empty.
	Sub string
	// Args are the arguments as they were written, with quoted strings
	// unquoted and parenthesised lists kept whole.
	Args []string
	// Literal is the literal this line ends with, or nil.
	Literal *Literal
	// Raw is the line as it arrived, without the CRLF.
	Raw []byte
}

// ParseCommand reads a command line as far as a policy decides about:
// the tag, the name, the arguments and any trailing literal.
//
// What it does not do is interpret an argument the policy has no
// business in. A FETCH item list is kept as one argument rather than
// decoded into a tree, because a relay that re-encoded it would be
// deciding about one request and forwarding another.
func ParseCommand(line []byte) (*Command, error) {
	if len(line) == 0 {
		return nil, ErrEmptyLine
	}
	for _, b := range line {
		if b < 0x20 || b == 0x7f {
			return nil, ErrControl
		}
	}
	s := string(line)
	tag, rest, ok := cut(s)
	if !ok || !validTag(tag) {
		return nil, ErrBadTag
	}
	c := &Command{Tag: tag, Raw: line}
	name, rest, ok := cut(rest)
	if !ok && name == "" {
		return nil, ErrBadCommand
	}
	if !validName(name) {
		return nil, ErrBadCommand
	}
	c.Name = strings.ToUpper(name)
	args, lit, err := parseArgs(rest)
	if err != nil {
		return nil, err
	}
	c.Args, c.Literal = args, lit
	if c.Name == "UID" && len(c.Args) > 0 && validName(c.Args[0]) {
		c.Sub = strings.ToUpper(c.Args[0])
	}
	return c, nil
}

// Effective is the command a policy decides about: for `UID FETCH` it is
// FETCH, because a rule naming FETCH means the operation rather than the
// spelling, and a policy that distinguished them would be bypassed by
// every client that uses UIDs -- which is every client written this
// century.
func (c *Command) Effective() string {
	if c.Name == "UID" && c.Sub != "" {
		return c.Sub
	}
	return c.Name
}

// validTag reports whether a tag is one RFC 9051 allows: at least one
// octet, no more than MaxTag, and none of the characters the grammar
// excludes from a tag -- which `+` is, because a line starting with it
// is a continuation request.
func validTag(tag string) bool {
	if tag == "" || len(tag) > MaxTag {
		return false
	}
	for _, r := range tag {
		switch {
		case r <= 0x20 || r >= 0x7f:
			return false
		case strings.ContainsRune(`(){%*"\]+`, r):
			return false
		}
	}
	return true
}

// validName reports whether a command name is plausible: letters, and
// the one command name with a dash in it that extensions have produced.
func validName(name string) bool {
	if name == "" || len(name) > 32 {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		case r == '-':
		default:
			return false
		}
	}
	return true
}

// parseArgs splits the rest of a command line into arguments, keeping a
// quoted string's contents and a parenthesised list whole, and reads a
// trailing literal if there is one.
func parseArgs(s string) ([]string, *Literal, error) {
	var (
		args []string
		lit  *Literal
	)
	for {
		s = strings.TrimLeft(s, " ")
		if s == "" {
			return args, lit, nil
		}
		if len(args) >= MaxArgs {
			return nil, nil, ErrTooManyArgs
		}
		switch s[0] {
		case '"':
			val, rest, err := quoted(s)
			if err != nil {
				return nil, nil, err
			}
			args, s = append(args, val), rest
		case '(':
			val, rest, err := list(s)
			if err != nil {
				return nil, nil, err
			}
			args, s = append(args, val), rest
		case '{':
			l, rest, err := literal(s)
			if err != nil {
				return nil, nil, err
			}
			// A literal is the last thing on a line: what follows is
			// octets, not text. Anything after the closing brace means
			// the relay and the server would read the line differently.
			if strings.TrimLeft(rest, " ") != "" {
				return nil, nil, ErrBadLiteral
			}
			return args, l, nil
		default:
			atom, rest, _ := cut(s)
			args, s = append(args, atom), rest
		}
	}
}

// quoted reads a quoted string, honouring the two escapes RFC 9051
// defines -- a backslash before a quote or a backslash -- and nothing
// else, because a parser that invented more escapes than the server has
// would read a different name from the same octets.
func quoted(s string) (string, string, error) {
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if i+1 >= len(s) {
				return "", "", ErrUnterminated
			}
			i++
			if s[i] != '"' && s[i] != '\\' {
				return "", "", ErrUnterminated
			}
			b.WriteByte(s[i])
		case '"':
			return b.String(), s[i+1:], nil
		default:
			b.WriteByte(s[i])
		}
	}
	return "", "", ErrUnterminated
}

// list reads a parenthesised list and returns it with its parentheses,
// because it is kept rather than interpreted.
func list(s string) (string, string, error) {
	depth, inQuote := 0, false
	for i := 0; i < len(s); i++ {
		switch {
		case inQuote && s[i] == '\\':
			i++
		case s[i] == '"':
			inQuote = !inQuote
		case inQuote:
		case s[i] == '(':
			depth++
			if depth > 32 {
				return "", "", ErrUnterminated
			}
		case s[i] == ')':
			depth--
			if depth == 0 {
				return s[:i+1], s[i+1:], nil
			}
		}
	}
	return "", "", ErrUnterminated
}

// literal reads a `{n}` or `{n+}` declaration.
func literal(s string) (*Literal, string, error) {
	end := strings.IndexByte(s, '}')
	if end < 0 {
		return nil, "", ErrBadLiteral
	}
	body := s[1:end]
	l := &Literal{}
	if strings.HasSuffix(body, "+") {
		l.NonSync, body = true, body[:len(body)-1]
	}
	if body == "" || len(body) > 12 {
		return nil, "", ErrBadLiteral
	}
	n, err := strconv.Atoi(body)
	if err != nil || n < 0 {
		return nil, "", ErrBadLiteral
	}
	l.Size = n
	return l, s[end+1:], nil
}

// cut splits off the first space-separated word.
func cut(s string) (string, string, bool) {
	if i := strings.IndexByte(s, ' '); i >= 0 {
		return s[:i], s[i+1:], true
	}
	return s, "", false
}

// sorted returns the strings in order, without pulling in sort for one
// call in a package this small.
func sorted(in []string) []string {
	for i := 1; i < len(in); i++ {
		for j := i; j > 0 && in[j] < in[j-1]; j-- {
			in[j], in[j-1] = in[j-1], in[j]
		}
	}
	return in
}
