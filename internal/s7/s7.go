// Package s7 reads the protocol a Siemens PLC speaks on TCP 102: three
// layers, each of which has to be read to get at the next.
//
// **TPKT** (RFC 1006) gives the stream its frames: a version octet, a
// reserved octet and a two-octet length that counts its own header.
//
// **COTP** (ISO 8073 class 0, X.224) gives it a connection. The
// interesting part is the connection request, because that is where the
// *address* is: a called TSAP of two octets holds the connection
// resource and the rack and slot of the CPU being addressed. A relay that
// read nothing else could still say which rack and slot a client may
// reach, which on a plant network is most of the boundary.
//
// **S7comm** is Siemens' own protocol on top, and it has no public
// specification: what is here is read from the protocol as deployed
// equipment speaks it, the way Wireshark's dissector and the open
// libraries do, and the parts this relay does not recognise it says it
// does not recognise rather than guessing.
//
// That last point is the whole design. This is a protocol with **no
// authentication worth the name**: the optional password protects a
// handful of functions on some CPU families and nothing on others, and an
// unprotected S7-300 accepts a stop from anybody who can open a socket to
// it. So the relay's job is to know what an operation *is* -- reading a
// data block, writing one, stopping the CPU, downloading a program,
// setting the clock -- and every one of those is a function code or a
// user-data subfunction this package names.
//
// Nothing here writes a frame except the refusal the caller sends in the
// protocol's own form, and nothing re-renders one: the relay forwards the
// octets it read.
package s7

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// The TPKT header: a version, a reserved octet and a length that includes
// the four octets of the header itself (RFC 1006 §6).
const (
	TPKTVersion = 3
	TPKTHeader  = 4
	// MinFrame is the shortest TPKT frame that can hold a COTP header.
	MinFrame = TPKTHeader + 2
	// DefaultMaxFrame bounds one frame when a caller names no bound. A
	// negotiated S7 PDU is 240, 480 or 960 octets on the families in the
	// field, and 2048 on an S7-1500; the TPKT frame that carries one is a
	// little larger.
	DefaultMaxFrame = 8192
)

// Frame is one TPKT frame, with the octets it arrived as.
type Frame struct {
	// Raw is the whole frame, header included. It is what the relay
	// forwards: this package never renders a frame back.
	Raw []byte
	// Payload is the COTP part, after the TPKT header.
	Payload []byte
}

// Reader reads TPKT frames off a connection.
type Reader struct {
	br  *bufio.Reader
	max int
}

// NewReader wraps a connection. max bounds one frame including its
// header.
func NewReader(r io.Reader, max int) *Reader {
	if max <= 0 {
		max = DefaultMaxFrame
	}
	if max < MinFrame {
		max = MinFrame
	}
	return &Reader{br: bufio.NewReaderSize(r, 8<<10), max: max}
}

// Max is the frame bound in force.
func (r *Reader) Max() int { return r.max }

// Next reads one frame.
//
// The length is two octets from the network, so it is checked against the
// bound before anything is allocated for it -- and against the minimum,
// because a length of three describes a frame that cannot hold the header
// it just arrived in.
func (r *Reader) Next() (*Frame, error) {
	var h [TPKTHeader]byte
	if _, err := io.ReadFull(r.br, h[:]); err != nil {
		return nil, err
	}
	if h[0] != TPKTVersion {
		return nil, fmt.Errorf("not an ISO-on-TCP stream: TPKT version %d", h[0])
	}
	n := int(binary.BigEndian.Uint16(h[2:4]))
	if n < MinFrame {
		return nil, fmt.Errorf("a TPKT frame of %d octets is shorter than its own header", n)
	}
	if n > r.max {
		return nil, fmt.Errorf("a TPKT frame of %d octets is over the %d this listener allows", n, r.max)
	}
	raw := make([]byte, n)
	copy(raw, h[:])
	if _, err := io.ReadFull(r.br, raw[TPKTHeader:]); err != nil {
		return nil, err
	}
	return &Frame{Raw: raw, Payload: raw[TPKTHeader:]}, nil
}

var errShort = errors.New("the field runs past the end of the frame")
