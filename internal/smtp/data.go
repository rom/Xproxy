package smtp

import (
	"errors"
	"io"
)

var (
	// ErrMessageTooLarge is a message past the configured size.
	ErrMessageTooLarge = errors.New("smtp: message too large")
	// ErrDataUnterminated is a connection that ended inside DATA.
	ErrDataUnterminated = errors.New("smtp: connection ended inside DATA")
)

// CopyData relays a DATA message from r to w, up to and including the
// terminating CRLF.CRLF, and returns the octets written.
//
// The end of the message is decided here and nowhere else, and what w
// receives is written by this function rather than passed through, so
// the proxy and the next hop cannot disagree about where the message
// ended. That disagreement is SMTP smuggling: a peer that also accepts
// a bare LF before a dot sees a second message where this one sees a
// line of text. Reader refuses a bare newline outright unless the
// configuration asked for repair, in which case the line is re-emitted
// with CRLF and the two ends still agree.
//
// Dot stuffing is left exactly as the sender wrote it: a body line that
// begins with a dot arrives stuffed and is forwarded stuffed, so only
// the terminator is interpreted.
func CopyData(w io.Writer, r *Reader, maxLine int, maxSize int64) (int64, error) {
	prev := r.max
	r.SetMax(maxLine)
	defer r.SetMax(prev)
	var n int64
	for {
		line, err := r.ReadLine()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return n, ErrDataUnterminated
			}
			return n, err
		}
		if len(line) == 1 && line[0] == '.' {
			end, err := w.Write([]byte(".\r\n"))
			return n + int64(end), err
		}
		if maxSize > 0 && n+int64(len(line))+2 > maxSize {
			// The message is refused, but the rest of it still has to
			// be read off the wire before a reply means anything, so
			// the caller drains with Discard.
			return n, ErrMessageTooLarge
		}
		wrote, err := w.Write(append(line, '\r', '\n'))
		n += int64(wrote)
		if err != nil {
			return n, err
		}
	}
}

// Discard reads to the end of a DATA message and throws it away, so a
// refusal can still be answered on a connection that stays usable.
// It stops at the terminator, at limit octets, or at the first error.
func Discard(r *Reader, maxLine int, limit int64) error {
	prev := r.max
	r.SetMax(maxLine)
	defer r.SetMax(prev)
	var n int64
	for {
		line, err := r.ReadLine()
		if err != nil {
			if errors.Is(err, ErrLineTooLong) {
				continue
			}
			return err
		}
		if len(line) == 1 && line[0] == '.' {
			return nil
		}
		n += int64(len(line)) + 2
		if limit > 0 && n > limit {
			return ErrMessageTooLarge
		}
	}
}
