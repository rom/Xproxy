package mysqlwire

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Reading the packet stream.
//
// A packet is three octets of little-endian length, one octet of sequence
// number, then that many octets of payload. Two things about that framing are
// traps.
//
// **A payload of exactly 0xffffff means "more follows".** A larger message is
// sent as a chain of full packets ending in one that is shorter -- and a message
// whose length is an exact multiple of 0xffffff ends with an *empty* packet,
// which a reader that stopped on "length zero" would treat as the end of the
// connection. The protocol has no bound on how long a chain may be, so a relay
// that reassembled without one would let a sender chain 16 MiB packets until
// memory ran out.
//
// **The sequence number matters.** It resets to zero for each new command and
// increments per packet, and the server checks it. A relay that ignored it could
// be fed a message assembled from two senders' packets, or could forward a chain
// with a gap in it that the server reads as a different message from the one the
// relay decided about.

// Packet is one reassembled message from one side.
type Packet struct {
	// Seq is the sequence number of the first packet of the message.
	Seq byte
	// Payload is the reassembled payload. It is only valid until the next read.
	Payload []byte
	// Packets is how many wire packets it took, which is 1 for almost
	// everything and more for a large statement or a bulk insert.
	Packets int
}

// Reader reads reassembled messages from one side of a connection.
type Reader struct {
	r   io.Reader
	buf []byte
	max int
	// seq is the sequence number expected next.
	seq byte
	// strict says an out-of-sequence packet is an error rather than something
	// to resynchronise on. It is on, because the alternative is a relay that
	// decides about a message the server will read differently.
	strict bool
}

// NewReader makes a reader bounded at max reassembled octets.
func NewReader(r io.Reader, max int) *Reader {
	if max <= 0 || max > MaxMessage {
		max = MaxMessage
	}
	return &Reader{r: r, max: max, strict: true, buf: make([]byte, 0, 4096)}
}

// Reset puts the sequence back to zero, which is what happens at the start of
// each command and after a TLS upgrade.
func (rd *Reader) Reset() { rd.seq = 0 }

// SetSeq sets the next expected sequence number, for the caller that has just
// forwarded a packet it read elsewhere.
func (rd *Reader) SetSeq(seq byte) { rd.seq = seq }

// Next reads one message, following a continuation chain to its end.
func (rd *Reader) Next() (Packet, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(rd.r, hdr[:]); err != nil {
		return Packet{}, err
	}
	n := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	first := hdr[3]
	if rd.strict && first != rd.seq {
		return Packet{}, fmt.Errorf("%w: got %d, expected %d", ErrSequence, first, rd.seq)
	}
	rd.seq = first + 1

	rd.buf = rd.buf[:0]
	count := 0
	for {
		if len(rd.buf)+n > rd.max {
			return Packet{}, fmt.Errorf("%w: %d octets", ErrTooLong, len(rd.buf)+n)
		}
		start := len(rd.buf)
		if cap(rd.buf) < start+n {
			grown := make([]byte, start, start+n)
			copy(grown, rd.buf)
			rd.buf = grown
		}
		rd.buf = rd.buf[:start+n]
		if n > 0 {
			if _, err := io.ReadFull(rd.r, rd.buf[start:]); err != nil {
				return Packet{}, err
			}
		}
		count++
		if n != MaxPayload {
			// Not a full packet, so the message ends here. Note that this is
			// the *only* end condition: a zero-length packet after a full one
			// is the legitimate terminator of a message whose length is an
			// exact multiple of 0xffffff, and a reader that stopped on zero
			// alone would end the message one packet early.
			return Packet{Seq: first, Payload: rd.buf, Packets: count}, nil
		}
		if _, err := io.ReadFull(rd.r, hdr[:]); err != nil {
			return Packet{}, err
		}
		n = int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
		if rd.strict && hdr[3] != rd.seq {
			return Packet{}, fmt.Errorf("%w: continuation got %d, expected %d", ErrSequence, hdr[3], rd.seq)
		}
		rd.seq = hdr[3] + 1
	}
}

// Command is the command octet of a client message, and the rest.
//
// A message with an empty payload has no command in it. The protocol does not
// define one, and a relay that read the next octet of whatever followed would be
// deciding about a command the client did not send.
func (p Packet) Command() (byte, []byte, bool) {
	if len(p.Payload) == 0 {
		return 0, nil, false
	}
	return p.Payload[0], p.Payload[1:], true
}

// Frame writes a payload as wire packets, splitting it the way the protocol
// requires.
//
// A payload of exactly MaxPayload has to be followed by an empty packet, or the
// receiver waits for a continuation that never comes. Getting that wrong is a
// hang rather than an error, which is why the encoder does it rather than each
// caller.
func Frame(seq byte, payload []byte) []byte {
	out := make([]byte, 0, len(payload)+8)
	for {
		n := len(payload)
		if n > MaxPayload {
			n = MaxPayload
		}
		out = append(out, byte(n), byte(n>>8), byte(n>>16), seq)
		out = append(out, payload[:n]...)
		seq++
		payload = payload[n:]
		if n != MaxPayload {
			return out
		}
		if len(payload) == 0 {
			// The terminating empty packet.
			return append(out, 0, 0, 0, seq)
		}
	}
}

// ErrPacket builds a server error packet, which is how a relay refuses in the
// protocol the client is speaking.
//
// 1045 is ER_ACCESS_DENIED_ERROR with SQLSTATE 28000, which is what the server
// itself answers for "you may not": a client library reports it the way it
// reports the server's own refusals, so an application's existing error handling
// works. 1142 is ER_TABLEACCESS_DENIED_ERROR with 42000, the closer fit for a
// refused statement on a connection that is otherwise fine.
func ErrPacket(seq byte, code uint16, state, text string) []byte {
	payload := make([]byte, 0, 9+len(text))
	payload = append(payload, RespErr)
	payload = binary.LittleEndian.AppendUint16(payload, code)
	payload = append(payload, '#')
	if len(state) != 5 {
		state = "HY000"
	}
	payload = append(payload, state...)
	payload = append(payload, safeText(text)...)
	return Frame(seq, payload)
}

// safeText makes a message fit to put in a protocol field: no NUL to truncate
// it, no control characters to break a log line at the other end.
func safeText(s string) string {
	s = Clip(s)
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			out = append(out, ' ')
			continue
		}
		out = append(out, s[i])
	}
	return string(out)
}

// AccessDenied and StatementDenied are the two refusals this relay sends.
const (
	AccessDenied    = 1045
	StatementDenied = 1142
)
