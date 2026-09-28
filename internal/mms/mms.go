// Package mms reads the protocol a substation IED speaks on TCP 102, which is
// six layers deep before anything worth a policy appears.
//
// **TPKT** (RFC 1006) frames the stream: a version octet, a reserved octet and a
// two-octet length that counts its own header.
//
// **COTP** (ISO 8073 class 0, X.224) gives it a connection, and its connection
// request carries the transport selectors. On IEC 61850 those are a convention
// rather than an address — 0x0001 at both ends on most of the estate — so unlike
// S7comm, where the called TSAP holds the rack and slot, there is nothing here to
// write a policy about. The addressing that matters is two layers up.
//
// **ISO 8327 session** and **ISO 8823 presentation** are carried because they have
// to be traversed, not because they say much: the session layer is a four-octet
// TLV and the presentation layer a BER wrapper naming which abstract syntax the
// user data is in.
//
// **ACSE** (ISO 8650) is the first layer with an identity in it. The association
// request carries the calling and called **AP-title** — an object identifier, which
// is as close as this protocol comes to naming who is calling — the AE-qualifier,
// and, where the estate configured one, an **authentication value that is a
// cleartext password**. IEC 62351-4 exists because of that. A relay in front of
// this protocol can see the password crossing and refuse the association that
// carries one in the clear, which is the first thing worth doing here.
//
// **MMS** (ISO 9506) is the service layer, and IEC 61850 maps its object names onto
// a substation's data model: a domain identifier that is a logical device, and an
// item identifier of the form LN$FC$DO$DA. The **functional constraint** — the FC
// between the dollar signs — is the whole of the security semantics, and it is why
// this package parses names rather than passing them through:
//
//   - `ST` and `MX` are status and measurands. Reading them is what a control
//     centre does every second.
//   - `CO` is control. A Write to `LN$CO$Pos$Oper` operates a switch: that is a
//     breaker, and it is one MMS Write from anybody who can open a socket.
//   - `SP` is a setpoint, `CF` configuration.
//   - `SG` and `SE` are setting groups, which hold a protection relay's trip
//     characteristics. Changing those is the most consequential write in a
//     substation and the least likely to be noticed, because nothing moves until
//     the fault it was meant to clear.
//   - `BR` and `RP` are report control blocks. Disabling one does not change the
//     plant; it stops the control centre hearing about it.
//
// Nothing here renders a frame except the refusal a caller sends in the protocol's
// own form. The relay forwards the octets it read.
package mms

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// The TPKT header (RFC 1006 §6): a version, a reserved octet, and a length that
// includes the four octets of the header itself.
const (
	TPKTVersion = 3
	TPKTHeader  = 4
	// MinFrame is the shortest frame that can hold a COTP header.
	MinFrame = TPKTHeader + 2
	// DefaultMaxFrame bounds one frame when a caller names no bound. An MMS
	// association negotiates a PDU size, and 32 KiB is what the field uses; the
	// bound here is generous enough for a GetNameList response over a large
	// logical device and nothing like enough to be a memory bound.
	DefaultMaxFrame = 64 << 10
)

// The errors this package returns. A caller distinguishes them because "this is
// not an ISO-on-TCP stream at all" and "this is one and the frame is too long"
// are different refusals.
var (
	ErrShort    = errors.New("mms: truncated")
	ErrVersion  = errors.New("mms: not an ISO-on-TCP stream")
	ErrTooLong  = errors.New("mms: frame longer than the bound")
	ErrSize     = errors.New("mms: impossible length")
	ErrEncoding = errors.New("mms: malformed encoding")
	// ErrOpaque says a layer was read but what it carries was not MMS: a
	// presentation context this relay does not know, which is not an error in the
	// traffic and is not something a service rule may decide about either.
	ErrOpaque = errors.New("mms: not an MMS payload")
)

// Frame is one TPKT frame with the octets it arrived as.
type Frame struct {
	// Raw is the whole frame, header included: what the relay forwards, since
	// this package never renders one back.
	Raw []byte
	// Body is the frame past the TPKT header, which is where COTP starts.
	Body []byte
}

// Reader reads TPKT frames off a stream, bounded.
type Reader struct {
	br  *bufio.Reader
	max int
}

// NewReader bounds a stream. A max of zero or less means DefaultMaxFrame, and one
// below MinFrame is raised to it: a bound that cannot admit a header would refuse
// every frame, which is a configuration error reported as a protocol error.
func NewReader(r io.Reader, max int) *Reader {
	if max <= 0 {
		max = DefaultMaxFrame
	}
	if max < MinFrame {
		max = MinFrame
	}
	return &Reader{br: bufio.NewReaderSize(r, 4096), max: max}
}

// Max is the bound in force.
func (r *Reader) Max() int { return r.max }

// Next reads one frame.
//
// The length is two octets from the network, so it is checked against the bound
// before anything is allocated for it, and against the minimum, because a length
// of three describes a frame that cannot hold what must follow.
func (r *Reader) Next() (*Frame, error) {
	var h [TPKTHeader]byte
	if _, err := io.ReadFull(r.br, h[:]); err != nil {
		return nil, err
	}
	if h[0] != TPKTVersion {
		return nil, fmt.Errorf("%w: TPKT version %d", ErrVersion, h[0])
	}
	n := int(binary.BigEndian.Uint16(h[2:]))
	if n < MinFrame {
		return nil, fmt.Errorf("%w: TPKT length %d", ErrSize, n)
	}
	if n > r.max {
		return nil, fmt.Errorf("%w: %d octets, bound %d", ErrTooLong, n, r.max)
	}
	raw := make([]byte, n)
	copy(raw, h[:])
	if _, err := io.ReadFull(r.br, raw[TPKTHeader:]); err != nil {
		return nil, err
	}
	return &Frame{Raw: raw, Body: raw[TPKTHeader:]}, nil
}
