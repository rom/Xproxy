package syslog

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// Format renders a message as RFC 5424. Everything the relay sends is
// written by this function, whatever format it arrived in: one dialect
// out means the record a collector stores is the record the relay
// decided about, and a message that arrived with a newline in a field
// cannot become two records downstream.
func (m Message) Format() []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "<%d>1 ", m.Priority())
	if m.HasTimestamp && !m.Timestamp.IsZero() {
		b.WriteString(m.Timestamp.UTC().Format(time.RFC3339Nano))
	} else {
		b.WriteString(Nil)
	}
	for _, f := range []string{m.Hostname, m.AppName, m.ProcID, m.MsgID} {
		b.WriteByte(' ')
		b.WriteString(printable(f))
	}
	b.WriteByte(' ')
	if len(m.Structured) == 0 {
		b.WriteString(Nil)
	} else {
		for _, el := range m.Structured {
			b.WriteByte('[')
			b.WriteString(sdName(el.ID))
			for _, p := range el.Params {
				b.WriteByte(' ')
				b.WriteString(sdName(p.Name))
				b.WriteString(`="`)
				b.WriteString(sdValue(p.Value))
				b.WriteByte('"')
			}
			b.WriteByte(']')
		}
	}
	if m.Message != "" {
		b.WriteByte(' ')
		b.WriteString(messageText(m.Message))
	}
	return []byte(b.String())
}

// printable renders a header field, replacing what cannot appear in
// one. A field that is empty is the nil value, because RFC 5424 has no
// empty field and a collector reading one would lose count.
func printable(s string) string {
	if s == "" {
		return Nil
	}
	out := strings.Map(func(r rune) rune {
		if r < 33 || r > 126 {
			return '_'
		}
		return r
	}, s)
	if len(out) > 255 {
		out = out[:255]
	}
	return out
}

// sdName renders a structured data name, which RFC 5424 restricts to
// printable ASCII without space, =, ] or ".
func sdName(s string) string {
	if s == "" {
		return "x"
	}
	out := strings.Map(func(r rune) rune {
		switch {
		case r < 33 || r > 126:
			return '_'
		case r == '=' || r == ']' || r == '"':
			return '_'
		}
		return r
	}, s)
	if len(out) > 32 {
		out = out[:32]
	}
	return out
}

// sdValue escapes a structured data value the way RFC 5424 section
// 6.3.3 requires, and takes line endings out: a value carrying one
// would end the record early wherever the next hop frames on newlines.
func sdValue(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '"', ']', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\n', '\r', 0:
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// messageText is the free text, with the line endings and the NUL taken
// out. This is the injection the format invites: a collector that frames
// on newlines reads one message as two, and the second one says
// whatever the sender wanted a record to say — including a priority of
// its own.
func messageText(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '\n':
			return '␤' // a visible symbol for newline, so nothing is lost silently
		case '\r', 0:
			return ' '
		}
		return r
	}, s)
}

// Framing is how a message is delimited on a stream.
type Framing int

const (
	// OctetCounting is RFC 6587 section 3.4.1: a decimal length, a
	// space, and exactly that many octets. It is the only framing that
	// cannot be confused by what a message contains, and the only one
	// RFC 5425 allows over TLS.
	OctetCounting Framing = iota
	// NonTransparent is RFC 6587 section 3.4.2: messages separated by a
	// line ending. It is what most senders do and what makes the
	// injection above worth taking seriously.
	NonTransparent
	// Auto reads either, decided per message by whether it starts with
	// a digit.
	Auto
)

// Reader reads framed messages from a stream.
type Reader struct {
	br      *bufio.Reader
	max     int
	framing Framing
}

// NewReader returns a reader bounded to max octets per message.
func NewReader(r io.Reader, max int, f Framing) *Reader {
	if max < 480 {
		// RFC 5426 section 3.2: every receiver must take 480 octets.
		max = 480
	}
	return &Reader{br: bufio.NewReaderSize(r, min(max+16, 1<<20)), max: max, framing: f}
}

// ReadMessage reads one framed message and returns its bytes.
func (r *Reader) ReadMessage() ([]byte, error) {
	framing := r.framing
	if framing == Auto {
		c, err := r.br.Peek(1)
		if err != nil {
			return nil, err
		}
		if c[0] >= '0' && c[0] <= '9' {
			framing = OctetCounting
		} else {
			framing = NonTransparent
		}
	}
	if framing == OctetCounting {
		return r.readCounted()
	}
	return r.readDelimited()
}

func (r *Reader) readCounted() ([]byte, error) {
	var digits []byte
	for {
		c, err := r.br.ReadByte()
		if err != nil {
			return nil, err
		}
		if c == ' ' {
			break
		}
		if c < '0' || c > '9' {
			return nil, fmt.Errorf("%w: length is not a number", ErrMalformed)
		}
		digits = append(digits, c)
		if len(digits) > 10 {
			return nil, fmt.Errorf("%w: length has too many digits", ErrMalformed)
		}
	}
	if len(digits) == 0 {
		return nil, fmt.Errorf("%w: empty length", ErrMalformed)
	}
	n, err := strconv.Atoi(string(digits))
	if err != nil || n <= 0 {
		return nil, fmt.Errorf("%w: length", ErrMalformed)
	}
	if n > r.max {
		// The length is believed enough to refuse it, and not enough to
		// allocate for it: a sender that says a gigabyte does not get a
		// gigabyte of the relay's memory. The stream cannot be resynced
		// after this, so the caller ends the connection.
		return nil, ErrTooLarge
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r.br, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func (r *Reader) readDelimited() ([]byte, error) {
	line, err := r.br.ReadSlice('\n')
	switch {
	case errors.Is(err, bufio.ErrBufferFull):
		// The message is longer than the bound and the reader is in the
		// middle of it; skip to the end so the next one is read as a
		// message rather than as the tail of this one.
		r.discard()
		return nil, ErrOversizeSkipped
	case err == nil && len(line) > r.max:
		// A whole message, over the bound. The reader is already at the
		// next one, so nothing is skipped: discarding here would eat it.
		return nil, ErrOversizeSkipped
	case err != nil && !errors.Is(err, io.EOF):
		return nil, err
	case errors.Is(err, io.EOF) && len(line) == 0:
		return nil, io.EOF
	}
	out := strings.TrimRight(string(line), "\r\n")
	return []byte(out), nil
}

func (r *Reader) discard() {
	for n := 0; n < 1<<22; n++ {
		b, err := r.br.ReadByte()
		if err != nil || b == '\n' {
			return
		}
	}
}

// Frame writes a message with the given framing.
func Frame(b []byte, f Framing) []byte {
	if f == NonTransparent {
		return append(append([]byte(nil), b...), '\n')
	}
	out := strconv.AppendInt(nil, int64(len(b)), 10)
	out = append(out, ' ')
	return append(out, b...)
}
