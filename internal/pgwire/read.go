package pgwire

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Reading the framed stream.
//
// After the startup exchange every message is type(1) + length(4) + body, and
// the length *includes itself* but not the type octet. That off-by-four is the
// single most common mistake in a reader of this protocol, and getting it wrong
// by one either loses framing on the next message or reads one octet of the
// next message's type as this one's body. The arithmetic is done once, here.

// Reader reads framed messages from one side of a connection.
type Reader struct {
	r   io.Reader
	dir Direction
	buf []byte
	// max bounds one message body.
	max int
}

// NewReader makes a reader for one direction.
func NewReader(r io.Reader, dir Direction, max int) *Reader {
	if max <= 0 || max > MaxMessage {
		max = MaxMessage
	}
	return &Reader{r: r, dir: dir, max: max, buf: make([]byte, 0, 4096)}
}

// ReadStartup reads the first message on the connection.
//
// It is separate from Next because the first message has no type octet: the
// length comes first. A reader that used one path for both would have to guess,
// and on this protocol guessing means reading the high octet of a length as a
// message type.
func (rd *Reader) ReadStartup() (*Startup, []byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(rd.r, hdr[:]); err != nil {
		return nil, nil, err
	}
	n := int(binary.BigEndian.Uint32(hdr[:]))
	if n < 8 {
		return nil, nil, ErrShort
	}
	if n > rd.max {
		return nil, nil, fmt.Errorf("%w: startup is %d octets", ErrTooLong, n)
	}
	raw := make([]byte, n)
	copy(raw, hdr[:])
	if _, err := io.ReadFull(rd.r, raw[4:]); err != nil {
		return nil, nil, err
	}
	s, err := ParseStartup(raw)
	if err != nil {
		return nil, nil, err
	}
	// The raw octets go back to the caller so a forwarded startup packet is
	// the one the client sent rather than one this relay rebuilt. A relay that
	// re-encoded it would be deciding about a message and forwarding a
	// different one.
	return s, raw, nil
}

// Next reads one message. The returned Body is only valid until the next call:
// a caller that keeps it must copy it, and every caller here that keeps
// anything keeps a string built from it rather than the slice.
func (rd *Reader) Next() (Message, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(rd.r, hdr[:]); err != nil {
		return Message{}, err
	}
	n := int(binary.BigEndian.Uint32(hdr[1:5]))
	// The length counts itself. Anything less than four cannot be a length,
	// and exactly four is an empty body, which several messages legitimately
	// have -- Sync, Flush, Terminate, CopyDone.
	if n < 4 {
		return Message{}, ErrShort
	}
	body := n - 4
	if body > rd.max {
		return Message{}, fmt.Errorf("%w: %d octets in a %s", ErrTooLong, body, Message{Type: hdr[0], Dir: rd.dir}.Name())
	}
	if cap(rd.buf) < body {
		rd.buf = make([]byte, body)
	}
	rd.buf = rd.buf[:body]
	if body > 0 {
		if _, err := io.ReadFull(rd.r, rd.buf); err != nil {
			return Message{}, err
		}
	}
	return Message{Type: hdr[0], Dir: rd.dir, Body: rd.buf}, nil
}

// Raw rebuilds the octets of a message as they were on the wire, for
// forwarding. The relay forwards what it read rather than what it understood:
// a message this code has no opinion about must cross unchanged, or a server
// newer than this relay would see a request the client did not make.
func (m Message) Raw() []byte {
	out := make([]byte, 5+len(m.Body))
	out[0] = m.Type
	binary.BigEndian.PutUint32(out[1:5], uint32(len(m.Body)+4)) //nolint:gosec // bounded by MaxMessage
	copy(out[5:], m.Body)
	return out
}
