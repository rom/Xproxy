package imap

import (
	"encoding/base64"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Response is one line from the server, read as far as a relay decides
// about it: whether it is tagged, which status it carries, which
// bracketed response code, and -- for an untagged data response -- which
// data item it is.
type Response struct {
	// Tag is the tag of a tagged response, empty for an untagged one.
	Tag string
	// Continuation is a `+` line: the server asking for the literal it
	// was told to expect, or for the next step of a SASL exchange.
	Continuation bool
	// Status is OK, NO, BAD, PREAUTH or BYE where the line carries one,
	// and empty on a data response.
	Status string
	// Item is the data item of an untagged response -- CAPABILITY,
	// LIST, FETCH, EXISTS, SEARCH -- upper cased, and empty otherwise.
	// A numbered response (`* 12 FETCH (...)`) carries the number in
	// Number and the name here, because the name is what a policy is
	// about.
	Item string
	// Number is the message number of a numbered untagged response.
	Number uint32
	// Code is the bracketed response code -- CAPABILITY, ALERT,
	// READ-ONLY, TRYCREATE, AUTHENTICATIONFAILED -- upper cased, without
	// its arguments, and empty where there is none.
	Code string
	// CodeArgs is what followed the code inside the brackets.
	CodeArgs string
	// Text is the human-readable remainder of the line.
	Text string
	// Raw is the line as it arrived, without the CRLF.
	Raw []byte
}

// ParseResponse reads a server line.
//
// Control characters are refused here as they are in a command: a
// server's text ends up in a log line, an alert a mail client shows to a
// person, and a security event, and none of those should carry a
// terminal escape because a mailbox name did.
func ParseResponse(line []byte) (*Response, error) {
	if len(line) == 0 {
		return nil, ErrEmptyLine
	}
	for _, b := range line {
		if b < 0x20 || b == 0x7f {
			return nil, ErrControl
		}
	}
	s := string(line)
	r := &Response{Raw: line}
	switch {
	case s == "+" || strings.HasPrefix(s, "+ "):
		r.Continuation = true
		r.Text = strings.TrimPrefix(strings.TrimPrefix(s, "+"), " ")
		return r, nil
	case strings.HasPrefix(s, "* "):
		return untagged(r, s[2:])
	}
	tag, rest, ok := cut(s)
	if !ok || !validTag(tag) {
		return nil, ErrBadResponse
	}
	r.Tag = tag
	status, rest, _ := cut(rest)
	if !isStatus(status) {
		return nil, ErrBadResponse
	}
	r.Status = strings.ToUpper(status)
	readCode(r, rest)
	return r, nil
}

// untagged reads what follows `* `, which is either a status response or
// a data response, and the data response may be numbered.
func untagged(r *Response, rest string) (*Response, error) {
	first, after, _ := cut(rest)
	if isStatus(first) {
		r.Status = strings.ToUpper(first)
		readCode(r, after)
		return r, nil
	}
	if n, err := strconv.ParseUint(first, 10, 32); err == nil {
		r.Number = uint32(n)
		name, tail, _ := cut(after)
		if !validName(name) {
			return nil, ErrBadResponse
		}
		r.Item, r.Text = strings.ToUpper(name), tail
		return r, nil
	}
	if !validName(first) {
		return nil, ErrBadResponse
	}
	r.Item, r.Text = strings.ToUpper(first), after
	return r, nil
}

// readCode splits a status response's text into its bracketed response
// code and the human-readable remainder.
func readCode(r *Response, s string) {
	r.Text = s
	if !strings.HasPrefix(s, "[") {
		return
	}
	end := strings.IndexByte(s, ']')
	if end < 0 {
		return
	}
	inside := s[1:end]
	name, args, _ := cut(inside)
	r.Code, r.CodeArgs = strings.ToUpper(name), args
	r.Text = strings.TrimPrefix(s[end+1:], " ")
}

// isStatus reports whether a word is one of the five status words.
func isStatus(w string) bool {
	switch strings.ToUpper(w) {
	case "OK", "NO", "BAD", "PREAUTH", "BYE":
		return true
	}
	return false
}

// OK reports a success status.
func (r *Response) OK() bool { return r.Status == "OK" }

// Failed reports a NO or BAD status, which is how an authentication
// failure arrives and therefore how a relay counts one.
func (r *Response) Failed() bool { return r.Status == "NO" || r.Status == "BAD" }

// Preauth reports the greeting that says the connection is already
// authenticated. RFC 9051 §7.1.4 allows it -- a server may decide from
// the transport, a Unix socket or a client certificate, that no
// credential is needed -- and a relay in front of a mailbox should not
// carry it: the identity every later decision is made about would be one
// nobody claimed and this relay never saw.
func (r *Response) Preauth() bool { return r.Status == "PREAUTH" }

// Bye reports the untagged BYE a server sends before closing.
func (r *Response) Bye() bool { return r.Status == "BYE" }

// Caps is a capability list, upper cased, in the order the server sent
// it -- which is kept because a client that parses positionally should
// see what the server meant rather than what this relay sorted.
type Caps []string

// ParseCaps reads a capability list from the text of a CAPABILITY
// response or from the arguments of a CAPABILITY response code.
func ParseCaps(text string) Caps {
	out := Caps{}
	for _, f := range strings.Fields(text) {
		if f == "" {
			continue
		}
		out = append(out, strings.ToUpper(f))
	}
	return out
}

// Has reports whether a capability is advertised.
func (c Caps) Has(name string) bool {
	want := strings.ToUpper(name)
	for _, v := range c {
		if v == want {
			return true
		}
	}
	return false
}

// Mechanisms are the SASL mechanism names of the AUTH= capabilities.
func (c Caps) Mechanisms() []string {
	var out []string
	for _, v := range c {
		if m, ok := strings.CutPrefix(v, "AUTH="); ok && m != "" {
			out = append(out, m)
		}
	}
	return out
}

// Without returns the list with every capability drop reports true for
// removed. It is how a relay narrows what a client is told the server
// can do: a mechanism the policy will refuse is better not advertised,
// because a client that never offers it never has its password refused
// halfway through an exchange.
func (c Caps) Without(drop func(string) bool) Caps {
	out := make(Caps, 0, len(c))
	for _, v := range c {
		if !drop(v) {
			out = append(out, v)
		}
	}
	return out
}

// With returns the list with name added if it is not already there,
// which is how LOGINDISABLED is advertised on a connection where the
// relay will refuse LOGIN: RFC 3501 §6.2.3 makes it the way a server
// says so, and a client that reads it asks for something else instead of
// sending a password into a refusal.
func (c Caps) With(name string) Caps {
	up := strings.ToUpper(name)
	if c.Has(up) {
		return c
	}
	return append(append(Caps{}, c...), up)
}

// String renders the list the way it travels on the wire.
func (c Caps) String() string { return strings.Join(c, " ") }

// Compressed reports whether a capability turns the connection into one
// this relay cannot read. COMPRESS=DEFLATE (RFC 4978) deflates
// everything after it is negotiated, so a relay that advertised it would
// be offering to stop inspecting -- the same decision this project makes
// about permessage-deflate on a WebSocket.
func Compressed(cap string) bool {
	return strings.HasPrefix(strings.ToUpper(cap), "COMPRESS=")
}

// Plaintext reports whether a SASL mechanism puts a password on the wire
// in a form anybody on the path can read. PLAIN and LOGIN send it
// outright; the digest mechanisms do not, whatever else is wrong with
// them.
func Plaintext(mech string) bool {
	switch strings.ToUpper(mech) {
	case "PLAIN", "LOGIN":
		return true
	}
	return false
}

// DecodeMailbox reads a mailbox name as the server stores it.
//
// RFC 3501 §5.1.3 encodes a non-ASCII name in a modified UTF-7: `&`
// starts a base64 run of UTF-16BE code units using `,` for `/`, `-`
// ends it, and `&-` is a literal ampersand. A policy written about
// "Sent" or "Отправленные" has to compare the decoded form, because the
// client and the server both speak the encoded one and neither will tell
// the relay which it meant.
//
// RFC 9051 allows the name as UTF-8 directly once UTF8=ACCEPT is
// enabled, so a name with no `&` is returned as it came -- after being
// checked for the control characters and the invalid UTF-8 that a name
// in a log line, an event and a policy comparison must not carry.
func DecodeMailbox(name string) (string, error) {
	if len(name) > MaxMailbox {
		return "", ErrBadMailbox
	}
	for i := 0; i < len(name); i++ {
		if name[i] < 0x20 || name[i] == 0x7f {
			return "", ErrBadMailbox
		}
	}
	if !strings.Contains(name, "&") {
		if !utf8.ValidString(name) {
			return "", ErrBadMailbox
		}
		return name, nil
	}
	var b strings.Builder
	for i := 0; i < len(name); {
		if name[i] != '&' {
			b.WriteByte(name[i])
			i++
			continue
		}
		end := strings.IndexByte(name[i+1:], '-')
		if end < 0 {
			return "", ErrBadMailbox
		}
		run := name[i+1 : i+1+end]
		i += end + 2
		if run == "" {
			b.WriteByte('&')
			continue
		}
		s, err := decodeRun(run)
		if err != nil {
			return "", err
		}
		b.WriteString(s)
	}
	out := b.String()
	if !utf8.ValidString(out) {
		return "", ErrBadMailbox
	}
	return out, nil
}

// decodeRun decodes one modified-base64 run into UTF-8.
func decodeRun(run string) (string, error) {
	// The modified alphabet is base64 with ',' for '/' and no padding.
	fixed := strings.ReplaceAll(run, ",", "/")
	raw, err := base64.RawStdEncoding.DecodeString(fixed)
	if err != nil || len(raw)%2 != 0 || len(raw) == 0 {
		return "", ErrBadMailbox
	}
	units := make([]uint16, 0, len(raw)/2)
	for i := 0; i < len(raw); i += 2 {
		units = append(units, uint16(raw[i])<<8|uint16(raw[i+1]))
	}
	decoded := string(utf16.Decode(units))
	if strings.ContainsRune(decoded, utf8.RuneError) {
		return "", ErrBadMailbox
	}
	for _, r := range decoded {
		if r < 0x20 || r == 0x7f {
			return "", ErrBadMailbox
		}
	}
	return decoded, nil
}

// SeqSet is a sequence set: the messages a FETCH, STORE, COPY, MOVE or
// SEARCH names. `1:*` is every message in the mailbox, which is what
// copying one looks like.
type SeqSet struct {
	// Terms is the number of comma-separated terms, which is the cost
	// the server pays for the request.
	Terms int
	// Open is true where a term ends in `*`: the set runs to the last
	// message, so its size is the mailbox's rather than the client's.
	Open bool
	// Count is the number of messages named where the set is closed, and
	// 0 where Open is true.
	Count uint64
}

// ParseSeqSet reads a sequence set, bounded to maxTerms.
//
// It is read rather than expanded: a set of a million messages is three
// characters, and a relay that built the list would be spending the
// memory the bound exists to protect.
func ParseSeqSet(s string, maxTerms int) (*SeqSet, error) {
	if s == "" {
		return nil, ErrBadSeqSet
	}
	if maxTerms <= 0 {
		maxTerms = MaxSeqTerms
	}
	out := &SeqSet{}
	for _, term := range strings.Split(s, ",") {
		out.Terms++
		if out.Terms > maxTerms {
			return nil, ErrBadSeqSet
		}
		lo, hi, ranged := strings.Cut(term, ":")
		switch {
		case !ranged:
			n, err := seqNum(term)
			if err != nil {
				return nil, err
			}
			if n == 0 {
				out.Open = true
				continue
			}
			out.Count++
		default:
			a, err := seqNum(lo)
			if err != nil {
				return nil, err
			}
			b, err := seqNum(hi)
			if err != nil {
				return nil, err
			}
			if a == 0 || b == 0 {
				out.Open = true
				continue
			}
			if b < a {
				a, b = b, a
			}
			out.Count += uint64(b-a) + 1
		}
	}
	if out.Open {
		out.Count = 0
	}
	return out, nil
}

// seqNum reads one number of a sequence set. `*` is returned as 0, which
// is not a valid message number, so it cannot be confused with one.
func seqNum(s string) (uint32, error) {
	if s == "*" {
		return 0, nil
	}
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil || n == 0 {
		return 0, ErrBadSeqSet
	}
	return uint32(n), nil
}

// Mechanism is the SASL mechanism of an AUTHENTICATE command, upper
// cased, with the initial response of RFC 4959 separated from it. The
// initial response carries the credential, so it is recognised in order
// to be kept out of a log line rather than to be read.
func Mechanism(c *Command) (name string, initial bool) {
	if c.Name != "AUTHENTICATE" || len(c.Args) == 0 {
		return "", false
	}
	return strings.ToUpper(c.Args[0]), len(c.Args) > 1
}

// Login is the user name of a LOGIN command, which is the one place in
// this protocol where an identity arrives beside its password in the
// clear.
func Login(c *Command) (string, bool) {
	if c.Name != "LOGIN" || len(c.Args) < 1 {
		return "", false
	}
	return c.Args[0], true
}

// mailboxArg says which argument of a command is a mailbox name, for the
// commands where one is. The position matters: RENAME has two and COPY
// and MOVE name theirs after the sequence set.
var mailboxArg = map[string]int{
	"SELECT": 0, "EXAMINE": 0, "CREATE": 0, "DELETE": 0,
	"RENAME": 0, "SUBSCRIBE": 0, "UNSUBSCRIBE": 0, "STATUS": 0,
	"APPEND": 0, "LIST": 1, "LSUB": 1, "COPY": 1, "MOVE": 1,
	"GETQUOTAROOT": 0, "GETACL": 0, "SETACL": 0, "DELETEACL": 0,
	"LISTRIGHTS": 0, "MYRIGHTS": 0,
}

// LiteralArgument reports whether the literal this command's line ends with
// stands where an argument the policy reads should be.
//
// It exists because of what a literal does to the parse. A literal is the last
// token on the line, so its octets arrive afterwards and the argument list ends
// where it begins: `SELECT {25+}` parses as SELECT with *no* arguments, and
// every reader below -- Mailboxes, Login, Mechanism, the sequence set -- then
// answers "this command names none", which is indistinguishable from a command
// that really does name none. The mailbox lists, the user list, the rule
// selectors and the estate's authorization question are all keyed on those
// answers, so a client could put the name it wanted in a literal and have every
// one of them decide about nothing while the server received the name intact.
//
// The relay refuses such a command rather than guessing. Reading the literal
// first would mean this proxy answering the client's continuation request
// instead of the server, which makes it a participant in an exchange it is
// meant to be relaying; and a mailbox name does not need a literal -- a
// conformant client may use one, but the ones in use spell names as atoms or
// quoted strings, and a refusal an operator can see beats a policy that
// silently decided nothing.
func LiteralArgument(c *Command) bool {
	if c.Literal == nil {
		return false
	}
	hi, ok := policyArg(c)
	return ok && len(c.Args) <= hi
}

// policyArg is the highest argument position a command has that the policy
// reads, and whether it has one at all.
func policyArg(c *Command) (int, bool) {
	name := c.Effective()
	shift := 0
	if c.Name == "UID" {
		// A UID form puts the sub-command first, so every argument after it
		// has moved along by one.
		shift = 1
	}
	hi, ok := -1, false
	if i, isMailbox := mailboxArg[name]; isMailbox {
		hi, ok = i+shift, true
		if name == "RENAME" {
			// Both names are decided about, so the second one counts.
			hi = 1
		}
	}
	switch name {
	case "FETCH", "STORE", "COPY", "MOVE":
		// The sequence set, which is what the collection bounds are read from.
		if shift > hi {
			hi = shift
		}
		ok = true
	case "LOGIN", "AUTHENTICATE":
		// The identity, and the mechanism: the two credential questions.
		if hi < 0 {
			hi = 0
		}
		ok = true
	}
	return hi, ok
}

// Mailboxes are the mailbox names a command refers to, decoded. RENAME
// refers to two and both are decided about: a rename is a read of one
// name and a write of another.
func Mailboxes(c *Command) ([]string, error) {
	name := c.Effective()
	i, ok := mailboxArg[name]
	// A UID COPY or UID MOVE puts the sub-command first, so every
	// argument after it has moved along by one.
	if c.Name == "UID" && ok {
		i++
	}
	if !ok || i >= len(c.Args) {
		return nil, nil
	}
	out := make([]string, 0, 2)
	m, err := DecodeMailbox(c.Args[i])
	if err != nil {
		return nil, err
	}
	out = append(out, m)
	if name == "RENAME" && len(c.Args) > 1 {
		to, err := DecodeMailbox(c.Args[1])
		if err != nil {
			return nil, err
		}
		out = append(out, to)
	}
	return out, nil
}

// Writes reports whether a command changes the mailbox rather than
// reading it: the set a read-only listener refuses, and the set worth
// logging on a listener that allows them.
func Writes(c *Command) bool {
	switch c.Effective() {
	case "CREATE", "DELETE", "RENAME", "APPEND", "STORE", "COPY", "MOVE",
		"EXPUNGE", "SETACL", "DELETEACL", "SETQUOTA", "SUBSCRIBE", "UNSUBSCRIBE":
		return true
	}
	return false
}

// Collects reports whether a command reads message content, which is the
// operation a mailbox-copying bound is about: FETCH and its UID form
// carry the messages, SEARCH finds them, and COPY and MOVE move them
// somewhere the client can fetch them from more comfortably.
func Collects(c *Command) bool {
	switch c.Effective() {
	case "FETCH", "SEARCH", "SORT", "THREAD", "COPY", "MOVE":
		return true
	}
	return false
}
