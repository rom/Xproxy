package tds

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync/atomic"

	wire "github.com/rom/xproxy/internal/tdswire"
)

// The TLS handshake on this protocol happens *inside* TDS packets, and then
// stops.
//
// This is the oddest thing about TDS and the reason a relay needs a wrapper here
// that the postgres and mysql kinds do not. On those two, upgrading means "stop
// speaking the protocol, speak TLS, then speak the protocol again inside it". On
// TDS the handshake records are carried as the payload of TDS packets of type
// PRELOGIN -- so for the length of the handshake, TDS wraps TLS -- and once the
// handshake finishes the encapsulation stops and TLS wraps TDS for the rest of
// the connection. The nesting inverts, once, part way through a connection.
//
// **Where exactly it inverts is the hard part, and TLS 1.3 made it harder.** The
// design assumes the handshake ends at a point both peers agree on, which was
// true when it was written: in TLS 1.2 everything including the session ticket is
// sent before Finished, so when a peer's handshake completes the encapsulated
// stream is exhausted. TLS 1.3 moved the session ticket to *after* the handshake,
// so a client whose handshake has completed may still have encapsulated octets
// coming -- and a client that flipped to reading raw records would read a TDS
// header as a record header, which is a connection that hangs and looks like a
// certificate problem.
//
// So the flip is asymmetric, and reading goes through a short window where either
// framing is accepted. This is not a guess about which one arrived: the two tag
// spaces are disjoint. An encapsulated packet begins with the PRELOGIN type,
// 0x12, and a TLS record begins with a content type, 20 to 25 -- so the first
// octet after the handshake says which framing it belongs to, and anything else
// is refused rather than interpreted. Writing needs no window: a peer's own
// handshake output is finished when its handshake is, and the other side stops
// expecting encapsulation at the same point.

// The tunnel's three states.
const (
	// wrapping: the handshake is in progress, and both directions are
	// encapsulated.
	wrapping int32 = iota
	// either: this peer's handshake is done, so it writes raw, but the other
	// peer may still be sending encapsulated post-handshake messages.
	either
	// raw: the other peer has sent a TLS record, so the encapsulation is over
	// in both directions for good.
	raw
)

// TLS content types, which is the tag space an unencapsulated record can use.
// They do not overlap TypePreLogin (0x12), which is what makes the window above
// unambiguous rather than a guess.
const (
	minContentType = 20 // change_cipher_spec
	maxContentType = 25 // tls12_cid
)

// tunnel encapsulates a TLS handshake in TDS packets and then stops.
//
// The state is atomic and nothing is held across the underlying read, which
// matters more than it looks: a relay reads one direction while writing the
// other, so a tunnel that held a mutex while blocked waiting for its peer would
// stall every write behind a read that had not arrived yet. That is a deadlock
// which only appears once both directions are live -- so after the handshake, and
// after every test of the handshake itself has passed.
//
// buf belongs to the reader alone. crypto/tls serialises its own reads and its
// own writes, and one tunnel serves one tls.Conn, so there is one reader.
type tunnel struct {
	net.Conn
	spid uint16
	size int

	buf   []byte
	state atomic.Int32
	// max bounds one encapsulated packet's payload, so a peer cannot make the
	// relay hold an arbitrary amount of memory before a single certificate has
	// been verified.
	max int
}

func newTunnel(c net.Conn, spid uint16, size, max int) *tunnel {
	if size < wire.HeaderLen+1 || size > wire.MaxPacketLen {
		size = 4096
	}
	if max <= 0 {
		max = wire.DefaultMaxMessage
	}
	t := &tunnel{Conn: c, spid: spid, size: size, max: max}
	t.state.Store(wrapping)
	return t
}

// HandshakeDone is called once crypto/tls reports the handshake complete.
//
// It stops encapsulating what this peer writes and opens the window in which
// either framing is accepted on the way in. It does not end the encapsulation
// outright, because the peer may still owe post-handshake messages it sent before
// its own handshake completed.
func (t *tunnel) HandshakeDone() {
	t.state.CompareAndSwap(wrapping, either)
}

func (t *tunnel) Read(p []byte) (int, error) {
	for len(t.buf) == 0 {
		if t.state.Load() == raw {
			// Nothing owed and the encapsulation is over: the TLS record layer
			// reads the connection directly from here on.
			return t.Conn.Read(p)
		}
		if err := t.fill(); err != nil {
			return 0, err
		}
	}
	n := copy(p, t.buf)
	t.buf = t.buf[n:]
	return n, nil
}

// fill reads one encapsulated packet's payload into the buffer, or notices that
// the peer has stopped encapsulating.
//
// It reads a packet at a time rather than following the EOM chain: what the TLS
// record layer wants is a stream of octets, and which packet each one arrived in
// carries no meaning during a handshake. Following the chain would mean holding a
// whole flight before handing over the first record of it.
func (t *tunnel) fill() error {
	var hdr [wire.HeaderLen]byte
	// One octet first, because in the `either` state it decides which framing
	// the rest belongs to and there is no putting it back.
	if _, err := io.ReadFull(t.Conn, hdr[:1]); err != nil {
		return err
	}
	if hdr[0] != wire.TypePreLogin {
		if t.state.Load() == either && hdr[0] >= minContentType && hdr[0] <= maxContentType {
			// A TLS record, unencapsulated: the peer's post-handshake traffic
			// has begun and the nesting has inverted. The octet is owed to the
			// record layer, so it goes in the buffer rather than being dropped.
			t.state.Store(raw)
			t.buf = append(t.buf, hdr[0])
			return nil
		}
		// Neither framing. During the handshake this is a peer that stopped
		// encapsulating early, and reading its payload as TLS records would mean
		// feeding the record layer whatever that message happened to contain.
		return fmt.Errorf("tds: %#02x begins neither an encapsulated packet nor a tls record "+
			"during the handshake", hdr[0])
	}
	if _, err := io.ReadFull(t.Conn, hdr[1:]); err != nil {
		return err
	}
	total := int(binary.BigEndian.Uint16(hdr[2:4]))
	if total < wire.MinPacketLen {
		return fmt.Errorf("%w: length %d", wire.ErrShort, total)
	}
	body := total - wire.HeaderLen
	if body > t.max {
		return fmt.Errorf("%w: %d octets in a handshake packet", wire.ErrTooLong, body)
	}
	if body == 0 {
		return nil
	}
	b := make([]byte, body)
	if _, err := io.ReadFull(t.Conn, b); err != nil {
		return err
	}
	t.buf = append(t.buf, b...)
	return nil
}

func (t *tunnel) Write(p []byte) (int, error) {
	if t.state.Load() != wrapping {
		return t.Conn.Write(p)
	}
	if _, err := t.Conn.Write(wire.Frame(wire.TypePreLogin, t.spid, p, t.size)); err != nil {
		return 0, err
	}
	// The whole buffer went out or none of it did. Reporting a short write with
	// no error would have crypto/tls resend the tail as a second handshake
	// flight, which the peer would read as a protocol violation.
	return len(p), nil
}
