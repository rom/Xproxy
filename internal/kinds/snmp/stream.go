package snmp

import (
	"bufio"
	"errors"
	"io"

	wire "github.com/rom/xproxy/internal/snmp"
)

// The framing on a stream.
//
// RFC 3430 puts SNMP on TCP with no framing of its own: a message is a BER
// SEQUENCE and its own length field delimits it. That is workable and it is
// also the whole attack surface of the transport, because the length is
// chosen by whoever sent it. So this reader decides about the length before
// it reads anything the length claims to cover: a message past the bound is
// refused unread, because reading it to find out what it asked for is
// exactly the work the bound exists to avoid.
//
// There is no resynchronisation. A stream whose framing is wrong is a
// stream whose next octet is unknown, and guessing would be inventing a
// message boundary nobody sent. The session ends instead.

var (
	// errTooLong is a message whose declared length is past the bound.
	errTooLong = errors.New("snmp: message past the bound")
	// errFraming is a stream that does not begin a BER SEQUENCE where one
	// was due.
	errFraming = errors.New("snmp: not a message")
)

// streamReader reads length-delimited SNMP messages from a stream.
type streamReader struct {
	r   *bufio.Reader
	max int
}

func newStreamReader(r io.Reader, max int) *streamReader {
	if max <= 0 {
		max = 8192
	}
	// The buffer is the bound, not a guess: a reader that buffered more
	// than one message may hold would be holding what it already decided
	// not to read.
	size := max + 8
	if size < 512 {
		size = 512
	}
	return &streamReader{r: bufio.NewReaderSize(r, size), max: max}
}

// next reads one message and returns it whole, tag and length included,
// which is what a relay forwards when it forwards something unchanged.
func (s *streamReader) next() ([]byte, error) {
	tag, err := s.r.ReadByte()
	if err != nil {
		return nil, err
	}
	if wire.Tag(tag) != wire.TagSequence {
		return nil, errFraming
	}
	first, err := s.r.ReadByte()
	if err != nil {
		return nil, err
	}
	header := []byte{tag, first}
	n := int(first)
	switch {
	case first == 0x80:
		// The indefinite length: legal in BER and not in the DER-like
		// subset every SNMP implementation writes. It would make the
		// message's extent depend on finding an end-of-contents octet pair
		// somewhere in a payload this relay does not interpret.
		return nil, errFraming
	case first > 0x80:
		count := int(first & 0x7f)
		if count > 4 {
			return nil, errTooLong
		}
		lenOctets := make([]byte, count)
		if _, err := io.ReadFull(s.r, lenOctets); err != nil {
			return nil, err
		}
		header = append(header, lenOctets...)
		n = 0
		for _, c := range lenOctets {
			n = n<<8 | int(c)
		}
		if n < 0 {
			return nil, errTooLong
		}
	}
	if len(header)+n > s.max {
		return nil, errTooLong
	}
	out := make([]byte, len(header)+n)
	copy(out, header)
	if _, err := io.ReadFull(s.r, out[len(header):]); err != nil {
		return nil, err
	}
	return out, nil
}
