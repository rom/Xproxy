// Package smtp holds the protocol pieces an SMTP-aware proxy needs:
// reading commands and replies with hard bounds, rewriting the EHLO
// capability list, and reading DATA without letting the two ends
// disagree about where the message ends.
//
// Nothing here talks to a network by itself. The session that does live
// in the proxy; keeping the parsing separate is what makes the awkward
// cases (a bare LF before a dot, a reply continued over 40 lines, a
// pipelined STARTTLS) testable without a mail server.
package smtp

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// The bounds RFC 5321 section 4.5.3.1 sets, which are the defaults the
// configuration starts from.
const (
	// MaxCommandLine is the command line limit including CRLF.
	MaxCommandLine = 512
	// MaxTextLine is the message line limit including CRLF.
	MaxTextLine = 1000
	// MaxPath is the limit on a forward or reverse path.
	MaxPath = 256
	// MaxReplyLines bounds a multi-line reply. No registered extension
	// comes close; a server that sends more is either broken or trying
	// to spend the proxy's memory.
	MaxReplyLines = 100
)

var (
	// ErrLineTooLong is a line over the configured bound. The session
	// answers 500 and counts an error rather than reading on: the rest
	// of that line would be parsed as a command of its own.
	ErrLineTooLong = errors.New("smtp: line too long")
	// ErrBareNewline is a line ending in LF without the CR. RFC 5321
	// section 2.3.8 forbids it, and accepting it is how a message ends
	// in one place for the proxy and another for the next hop.
	ErrBareNewline = errors.New("smtp: bare newline")
	// ErrBareCR is a CR that is not followed by LF, the other half of
	// the same disagreement.
	ErrBareCR = errors.New("smtp: bare carriage return")
	// ErrBadReply is a reply that is not three digits and a separator.
	ErrBadReply = errors.New("smtp: malformed reply")
	// ErrTooManyReplyLines is a reply continued past MaxReplyLines.
	ErrTooManyReplyLines = errors.New("smtp: reply has too many lines")
)

// Reader reads CRLF-terminated lines with a hard bound and no bare
// newlines. It wraps a bufio.Reader so the session can ask what is still
// buffered, which is how the STARTTLS injection check works.
type Reader struct {
	br  *bufio.Reader
	max int
	// AllowBareLF accepts a line ended by LF alone. The line is still
	// re-emitted with CRLF, so the two ends never see a different line
	// structure; what it changes is whether a sloppy client is refused
	// or repaired.
	AllowBareLF bool
}

// NewReader returns a Reader over r bounded to max octets per line
// including the CRLF. The buffer is sized to that bound so a line that
// does not fit is refused rather than grown into.
func NewReader(r io.Reader, max int) *Reader {
	if max < 64 {
		max = 64
	}
	return &Reader{br: bufio.NewReaderSize(r, max+2), max: max}
}

// Buffered is the number of octets already read from the connection and
// not yet consumed. After a command whose reply changes how the stream
// is read — STARTTLS above all — anything buffered was sent before the
// client could have seen the answer.
func (r *Reader) Buffered() int { return r.br.Buffered() }

// SetMax changes the line bound. DATA raises it from the command limit
// to the text limit and lowers it again at the end of the message.
func (r *Reader) SetMax(max int) { r.max = max }

// ReadLine reads one line and returns it without the CRLF. A line over
// the bound returns ErrLineTooLong with what was read so far consumed to
// the end of the line, so the caller can answer and carry on if it
// chooses to.
func (r *Reader) ReadLine() ([]byte, error) {
	line, err := r.br.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) || (err == nil && len(line) > r.max) {
		r.discardLine()
		return nil, ErrLineTooLong
	}
	if err != nil {
		return nil, err
	}
	body := line[:len(line)-1]
	if n := len(body); n > 0 && body[n-1] == '\r' {
		body = body[:n-1]
	} else if !r.AllowBareLF {
		return nil, ErrBareNewline
	}
	// A CR anywhere else is the same ambiguity in the other direction:
	// a peer that splits on CR sees a line boundary the proxy does not.
	for _, b := range body {
		if b == '\r' {
			return nil, ErrBareCR
		}
	}
	out := make([]byte, len(body))
	copy(out, body)
	return out, nil
}

// discardLine drops octets up to and including the next LF, bounded so a
// peer that never sends one cannot hold the reader.
func (r *Reader) discardLine() {
	for n := 0; n < 1<<20; n++ {
		b, err := r.br.ReadByte()
		if err != nil || b == '\n' {
			return
		}
	}
}

// Command is one parsed client command: the verb uppercased, and the
// argument with the single separating space removed.
type Command struct {
	Verb string
	Arg  string
	Raw  string
}

// ParseCommand splits a command line. The verb is letters only, which is
// every verb SMTP has ever registered, and rejecting the rest here means
// the allow list never sees something that only looks like a verb.
func ParseCommand(line []byte) (Command, error) {
	s := string(line)
	if s == "" {
		return Command{}, errors.New("smtp: empty command")
	}
	verb, arg, _ := strings.Cut(s, " ")
	for _, r := range verb {
		if (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') {
			return Command{}, fmt.Errorf("smtp: %q is not a command", clip(verb, 16))
		}
	}
	if len(verb) > 16 {
		return Command{}, errors.New("smtp: command verb too long")
	}
	return Command{Verb: strings.ToUpper(verb), Arg: arg, Raw: s}, nil
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// Reply is a server reply: the code, its enhanced status code where one
// is present, and the text of each line.
type Reply struct {
	Code  int
	Lines []string
}

// ReadReply reads a reply, following "250-" continuations to the final
// "250 " line. Every line must carry the same code: a reply whose code
// changes mid-way is two replies to somebody, which is the desync this
// proxy exists to prevent.
func ReadReply(r *Reader) (Reply, error) {
	var rep Reply
	for {
		line, err := r.ReadLine()
		if err != nil {
			return rep, err
		}
		if len(line) < 3 {
			return rep, ErrBadReply
		}
		code, err := strconv.Atoi(string(line[:3]))
		if err != nil || code < 100 || code > 599 {
			return rep, ErrBadReply
		}
		if rep.Code == 0 {
			rep.Code = code
		} else if code != rep.Code {
			return rep, ErrBadReply
		}
		text := ""
		last := true
		if len(line) > 3 {
			switch line[3] {
			case ' ':
				text = string(line[4:])
			case '-':
				text, last = string(line[4:]), false
			default:
				return rep, ErrBadReply
			}
		}
		rep.Lines = append(rep.Lines, text)
		if last {
			return rep, nil
		}
		if len(rep.Lines) >= MaxReplyLines {
			return rep, ErrTooManyReplyLines
		}
	}
}

// Format renders a reply on the wire, as a continuation for every line
// but the last.
func (rep Reply) Format() []byte {
	if len(rep.Lines) == 0 {
		return []byte(fmt.Sprintf("%d \r\n", rep.Code))
	}
	var b strings.Builder
	for i, l := range rep.Lines {
		sep := "-"
		if i == len(rep.Lines)-1 {
			sep = " "
		}
		fmt.Fprintf(&b, "%d%s%s\r\n", rep.Code, sep, l)
	}
	return []byte(b.String())
}

// Keyword is the EHLO keyword of a capability line: "SIZE 1024" is SIZE.
func Keyword(line string) string {
	kw, _, _ := strings.Cut(strings.TrimSpace(line), " ")
	return strings.ToUpper(kw)
}

// FilterEHLO rewrites a 250 reply to EHLO. The greeting line is kept as
// it is; every capability line is offered to keep, and the ones it
// refuses are dropped. Lines in add are appended, which is how the proxy
// advertises what it implements itself rather than what the upstream
// does.
func FilterEHLO(rep Reply, keep func(keyword string) bool, add []string) Reply {
	out := Reply{Code: rep.Code}
	if len(rep.Lines) == 0 {
		return rep
	}
	out.Lines = append(out.Lines, rep.Lines[0])
	for _, l := range rep.Lines[1:] {
		if keep(Keyword(l)) {
			out.Lines = append(out.Lines, l)
		}
	}
	seen := map[string]bool{}
	for _, l := range out.Lines[1:] {
		seen[Keyword(l)] = true
	}
	for _, l := range add {
		if !seen[Keyword(l)] {
			out.Lines = append(out.Lines, l)
		}
	}
	return out
}

// Capability reports whether a reply to EHLO advertises a keyword, and
// returns the rest of that line.
func Capability(rep Reply, keyword string) (string, bool) {
	if len(rep.Lines) == 0 {
		return "", false
	}
	for _, l := range rep.Lines[1:] {
		if Keyword(l) == strings.ToUpper(keyword) {
			_, rest, _ := strings.Cut(strings.TrimSpace(l), " ")
			return rest, true
		}
	}
	return "", false
}
