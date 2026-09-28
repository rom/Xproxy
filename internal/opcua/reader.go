package opcua

import (
	"fmt"
	"io"
)

// A Reader reads UA TCP messages off a stream, one chunk at a time.
//
// The framing is the reason this exists rather than a bufio.Scanner: the length is
// in the header and it *includes* the header, so a reader that took it as a body
// length would read eight octets too few and then find the next message's header
// where a body should be. Getting that wrong does not fail loudly — it produces a
// stream of messages that are each shifted by eight octets and mostly still parse.
type Reader struct {
	r   io.Reader
	max int
	hdr [HeaderLen]byte
	// buf is reused between messages, because a plant connection reads a message
	// every poll interval for months.
	buf []byte
}

// NewReader makes a reader bounded at max octets per chunk. A max of zero or more
// than MaxMessageSize is clamped to MaxMessageSize: the bound exists to stop a peer
// naming a length nobody will allocate, and a caller that asked for no bound has
// asked for the package's.
func NewReader(r io.Reader, max int) *Reader {
	if max <= 0 || max > MaxMessageSize {
		max = MaxMessageSize
	}
	return &Reader{r: r, max: max}
}

// Next reads one chunk.
//
// It returns the chunk's own error for a message that arrived whole and did not
// parse, and an I/O error for one that did not arrive. A caller has to tell those
// apart: the first is a peer to refuse and the second is a connection that ended.
func (rd *Reader) Next() (*Chunk, error) {
	if _, err := io.ReadFull(rd.r, rd.hdr[:]); err != nil {
		return nil, err
	}
	n, err := PeekSize(rd.hdr[:])
	if err != nil {
		return nil, err
	}
	if n > rd.max {
		return nil, fmt.Errorf("%w: a message of %d octets, past the %d bound",
			ErrTooLong, n, rd.max)
	}
	if cap(rd.buf) < n {
		rd.buf = make([]byte, n)
	}
	raw := rd.buf[:n]
	copy(raw, rd.hdr[:])
	if _, err := io.ReadFull(rd.r, raw[HeaderLen:]); err != nil {
		// A header that named more than arrived. It is an I/O error rather than a
		// parse error because the octets are gone: there is nothing to decide
		// about and nothing to answer on.
		return nil, err
	}
	return ParseChunk(raw)
}

// Max is the bound in force, which a caller needs when it has to tell a peer what
// it exceeded.
func (rd *Reader) Max() int { return rd.max }
