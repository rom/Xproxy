package tdswire

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Reading the packet stream.
//
// A packet is eight octets of header -- type, status, length, SPID, PacketID,
// Window -- and then the payload. Three things about that are traps.
//
// **The length is big-endian, and it includes the header.** TDS is a Microsoft
// protocol that is little-endian nearly everywhere else, including inside every
// message body this package reads, so the one big-endian field in the header is
// exactly the field a reader gets backwards. A length read the wrong way round
// is 0x0001 read as 0x0100, which is a plausible-looking 256 -- so it does not
// fail loudly, it just loses framing.
//
// **A message ends when a packet has the EOM status bit, not when it is short.**
// Unlike MySQL there is no "full means more follows" rule: a sender may end a
// message with a full packet, or continue with a short one. A reader that
// guessed from the length would split one message into two or join two into one.
//
// **The length includes the header, so the payload is length minus eight.** A
// length below eight is a packet shorter than its own header, and subtracting
// eight from it underflows -- which is the same class of bug as PostgreSQL's
// self-referential length.

// Packet is one reassembled message.
type Packet struct {
	// Type is the message type, from the first packet's header.
	Type byte
	// SPID is the server process identifier the header carried.
	SPID uint16
	// Payload is the reassembled body, valid until the next read.
	Payload []byte
	// Packets is how many wire packets it took.
	Packets int
	// Reset says the message asked for the session to be reset first, which is
	// what a connection pool sends when it hands a connection to a different
	// caller -- and which a relay should notice, because the identity policy it
	// applied may no longer describe who is using the connection.
	Reset bool
}

// Reader reads reassembled messages from one side.
type Reader struct {
	r   io.Reader
	buf []byte
	max int
}

// NewReader makes a reader bounded at max reassembled octets.
func NewReader(r io.Reader, max int) *Reader {
	if max <= 0 || max > MaxMessage {
		max = MaxMessage
	}
	return &Reader{r: r, max: max, buf: make([]byte, 0, 8192)}
}

// Next reads one message, following the packet chain to the one marked EOM.
func (rd *Reader) Next() (Packet, error) {
	var hdr [HeaderLen]byte
	if _, err := io.ReadFull(rd.r, hdr[:]); err != nil {
		return Packet{}, err
	}
	p := Packet{Type: hdr[0], SPID: binary.BigEndian.Uint16(hdr[4:6])}
	rd.buf = rd.buf[:0]
	for {
		// The one big-endian field in a protocol that is little-endian
		// everywhere else.
		total := int(binary.BigEndian.Uint16(hdr[2:4]))
		if total < MinPacketLen {
			return Packet{}, fmt.Errorf("%w: length %d", ErrShort, total)
		}
		body := total - HeaderLen
		if len(rd.buf)+body > rd.max {
			return Packet{}, fmt.Errorf("%w: %d octets", ErrTooLong, len(rd.buf)+body)
		}
		if hdr[1]&StatusResetConnection != 0 || hdr[1]&StatusResetConnectionSkipTran != 0 {
			p.Reset = true
		}
		start := len(rd.buf)
		if cap(rd.buf) < start+body {
			grown := make([]byte, start, start+body)
			copy(grown, rd.buf)
			rd.buf = grown
		}
		rd.buf = rd.buf[:start+body]
		if body > 0 {
			if _, err := io.ReadFull(rd.r, rd.buf[start:]); err != nil {
				return Packet{}, err
			}
		}
		p.Packets++
		// EOM, and only EOM, ends a message. A short packet does not.
		if hdr[1]&StatusEOM != 0 {
			p.Payload = rd.buf
			return p, nil
		}
		if _, err := io.ReadFull(rd.r, hdr[:]); err != nil {
			return Packet{}, err
		}
		// A continuation packet of a different type is a message assembled from
		// two, which neither peer sent.
		if hdr[0] != p.Type {
			return Packet{}, fmt.Errorf("%w: continuation is type %s in a %s message",
				ErrTruncated, TypeName(hdr[0]), TypeName(p.Type))
		}
	}
}

// Frame writes a payload as packets of at most size octets each, marking the
// last one EOM.
//
// size is the negotiated packet size, which the login exchange settles; 4096 is
// the protocol's default and what a client uses before it knows better.
func Frame(typ byte, spid uint16, payload []byte, size int) []byte {
	if size < HeaderLen+1 || size > MaxPacketLen {
		size = 4096
	}
	room := size - HeaderLen
	out := make([]byte, 0, len(payload)+HeaderLen*2)
	id := byte(1)
	for {
		n := len(payload)
		if n > room {
			n = room
		}
		status := StatusEOM
		if n < len(payload) {
			status = StatusNormal
		}
		out = append(out, typ, status)
		out = binary.BigEndian.AppendUint16(out, uint16(n+HeaderLen)) //nolint:gosec // bounded by size
		out = binary.BigEndian.AppendUint16(out, spid)
		out = append(out, id, 0)
		out = append(out, payload[:n]...)
		payload = payload[n:]
		if status == StatusEOM {
			return out
		}
		id++
	}
}

// The token types in a server's tabular result, of which this relay needs two.
const (
	// TokenError is a server error, which is the shape the relay borrows to
	// refuse in the protocol the client is speaking.
	TokenError byte = 0xaa
	// TokenDone ends a request's results.
	TokenDone byte = 0xfd
	// TokenLoginAck says the login succeeded, which is how the relay knows the
	// authentication exchange is over -- the protocol's own signal, rather than
	// a guess.
	TokenLoginAck byte = 0xad
	// TokenEnvChange reports a session change, including the database and the
	// packet size.
	TokenEnvChange byte = 0xe3
)

// ErrorToken builds an ERROR token stream, which is how the relay says no.
//
// The number matters: a client library switches on it. 229 is "the %ls
// permission was denied", which is what SQL Server itself answers when a
// principal may not do something -- so an application's existing error handling
// works, and the message says the proxy refused it so nobody goes looking for a
// GRANT that would not have helped.
//
// The token is followed by a DONE so the client stops waiting for results.
func ErrorToken(number int32, message, server string) []byte {
	msg := ToUCS2(safeText(message))
	srv := ToUCS2(Clip(server))
	// Length (2), Number (4), State (1), Class (1), MsgText (2+n),
	// ServerName (1+n), ProcName (1+n), LineNumber (4).
	body := make([]byte, 0, 16+len(msg)+len(srv))
	body = binary.LittleEndian.AppendUint32(body, uint32(number))     //nolint:gosec // a protocol field
	body = append(body, 1)                                            // state
	body = append(body, 14)                                           // class: 11-16 is "an error the user can correct"
	body = binary.LittleEndian.AppendUint16(body, uint16(len(msg)/2)) //nolint:gosec // bounded
	body = append(body, msg...)
	body = append(body, byte(len(srv)/2)) //nolint:gosec // bounded by Clip
	body = append(body, srv...)
	body = append(body, 0) // no procedure name
	body = binary.LittleEndian.AppendUint32(body, 0)

	out := make([]byte, 0, 3+len(body)+13)
	out = append(out, TokenError)
	out = binary.LittleEndian.AppendUint16(out, uint16(len(body))) //nolint:gosec // bounded
	out = append(out, body...)

	// DONE: status (2), current command (2), row count (8).
	out = append(out, TokenDone)
	out = binary.LittleEndian.AppendUint16(out, 0)
	out = binary.LittleEndian.AppendUint16(out, 0)
	out = binary.LittleEndian.AppendUint64(out, 0)
	return out
}

// PermissionDenied is the error number the relay refuses with.
const PermissionDenied = 229

// LoginFailed is the number for a refused connection, which is what a client
// expects when it may not connect at all.
const LoginFailed = 18456

// safeText makes a message fit to put in a protocol field: no control characters
// to break a log line at the other end.
func safeText(s string) string {
	s = Clip(s)
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			r = ' '
		}
		out = append(out, r)
	}
	return string(out)
}

// LoginAck says whether a server's token stream contains a LOGINACK, which is the
// protocol's own statement that the authentication exchange succeeded.
//
// The relay reads this rather than guessing from a packet count, for the reason
// the MySQL kind learned the hard way: a guess is not a security boundary.
func LoginAck(payload []byte) bool {
	// The token stream is a sequence of tokens whose lengths vary by type, so
	// walking it properly means a table of every token. The relay does not need
	// that: it needs to know whether a LOGINACK is in here, and a LOGINACK is
	// the first token of the response to a successful login. Checking the first
	// token is exact for the case that matters and never produces a false
	// positive from data further in, which walking badly would.
	return len(payload) > 0 && payload[0] == TokenLoginAck
}

// ErrorNumber reads the number from a server's ERROR token, when the stream
// begins with one, so the relay can recognise an authentication failure without
// matching on message text.
func ErrorNumber(payload []byte) (int32, bool) {
	if len(payload) < 7 || payload[0] != TokenError {
		return 0, false
	}
	return int32(binary.LittleEndian.Uint32(payload[3:7])), true //nolint:gosec // a protocol field
}
