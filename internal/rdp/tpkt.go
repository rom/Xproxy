// Package rdp is the Remote Desktop Protocol wire format the rdp
// listener kind reads and writes.
//
// Unlike the vendors' VNC types, none of this is reverse engineering:
// RDP is written down. The connection sequence is MS-RDPBCGR, the
// conference layer underneath it is T.125 and T.124, the credential
// exchange for network level authentication is MS-CSSP over MS-NLMP,
// and the device redirection this gateway filters is MS-RDPEFS. What
// is implemented here is the part a proxy needs in order to decide
// things: the negotiation, the channel list, the credential, and
// enough framing to tell one PDU from the next. The rest is relayed
// without being decoded, which is why this package is a few thousand
// lines and not a few hundred thousand.
package rdp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// MaxPDU bounds one protocol data unit. TPKT's own length field is
// sixteen bits, so this is the protocol's ceiling rather than a
// policy: a peer cannot ask for more than it.
const MaxPDU = 0xFFFF

// ErrFraming is a stream that is not RDP framing at all.
var ErrFraming = errors.New("rdp: framing")

// The two ways a PDU is framed. Everything in the connection sequence
// is slow path -- TPKT, then an X.224 data unit, then the conference
// layer. Once the session is running, input and screen updates move to
// fast path, which drops all of that for a one or two byte header.
//
// The first byte tells them apart: slow path begins with TPKT's
// version 3, and no fast path header can, because the low two bits of
// a fast path header are its action and neither action is 3.
const tpktVersion = 3

// PDU is one unit as it arrived: Raw is the whole thing, to be
// forwarded when nothing needs changing, and Body is the payload
// inside the framing.
type PDU struct {
	FastPath bool
	Raw      []byte
	Body     []byte
}

// ReadPDU reads one PDU of either framing.
func ReadPDU(r io.Reader) (PDU, error) {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:1]); err != nil {
		return PDU{}, err
	}
	if head[0] == tpktVersion {
		if _, err := io.ReadFull(r, head[1:4]); err != nil {
			return PDU{}, err
		}
		n := int(binary.BigEndian.Uint16(head[2:4]))
		if n < 4 {
			return PDU{}, fmt.Errorf("%w: tpkt of %d bytes", ErrFraming, n)
		}
		raw := make([]byte, n)
		copy(raw, head[:4])
		if _, err := io.ReadFull(r, raw[4:]); err != nil {
			return PDU{}, err
		}
		return PDU{Raw: raw, Body: raw[4:]}, nil
	}
	// Fast path: the action byte, then a length of one or two bytes.
	// The top bit of the first length byte says which.
	if _, err := io.ReadFull(r, head[1:2]); err != nil {
		return PDU{}, err
	}
	size, headLen := int(head[1]), 2
	if head[1]&0x80 != 0 {
		if _, err := io.ReadFull(r, head[2:3]); err != nil {
			return PDU{}, err
		}
		size = int(head[1]&0x7F)<<8 | int(head[2])
		headLen = 3
	}
	if size < headLen {
		return PDU{}, fmt.Errorf("%w: fast path pdu of %d bytes", ErrFraming, size)
	}
	raw := make([]byte, size)
	copy(raw, head[:headLen])
	if _, err := io.ReadFull(r, raw[headLen:]); err != nil {
		return PDU{}, err
	}
	return PDU{FastPath: true, Raw: raw, Body: raw[headLen:]}, nil
}

// TPKT wraps a payload in a TPKT header.
func TPKT(body []byte) ([]byte, error) {
	if len(body)+4 > MaxPDU {
		return nil, fmt.Errorf("%w: pdu of %d bytes, over the %d the header can carry", ErrFraming, len(body)+4, MaxPDU)
	}
	out := []byte{tpktVersion, 0, 0, 0}
	binary.BigEndian.PutUint16(out[2:4], uint16(len(body)+4)) //nolint:gosec // bounded above
	return append(out, body...), nil
}

// The X.224 unit types this gateway names.
const (
	x224CR = 0xE0 // connection request
	x224CC = 0xD0 // connection confirm
	x224DT = 0xF0 // data
)

// x224Data is the fixed header every slow path PDU carries between
// TPKT and the conference layer: a length indicator, the data type,
// and the end-of-transmission mark.
var x224Data = []byte{0x02, x224DT, 0x80}

// DataPDU wraps a conference layer payload as a slow path PDU.
func DataPDU(body []byte) ([]byte, error) {
	return TPKT(append(append([]byte(nil), x224Data...), body...))
}

// X224Payload returns what a slow path PDU carries past the X.224
// header, or an error if it is not a data unit.
func X224Payload(body []byte) ([]byte, error) {
	if len(body) < 3 {
		return nil, fmt.Errorf("%w: x.224 unit of %d bytes", ErrFraming, len(body))
	}
	li := int(body[0])
	if body[1] != x224DT {
		return nil, fmt.Errorf("%w: x.224 type %#02x is not a data unit", ErrFraming, body[1])
	}
	if li+1 > len(body) {
		return nil, fmt.Errorf("%w: x.224 length indicator %d past the unit", ErrFraming, li)
	}
	return body[li+1:], nil
}
