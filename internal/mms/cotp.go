package mms

import (
	"encoding/binary"
	"fmt"
)

// COTP (ISO 8073 class 0, X.224), which is the connection this protocol runs on.
//
// Unlike S7comm, where the called TSAP holds the rack and slot of the CPU and is
// therefore an address worth a policy, IEC 61850's transport selectors are a
// convention: a single octet 0x01 at both ends on most of the estate, and whatever
// the SCL file said on the rest. So this layer is read to be traversed and to be
// bounded, and the addressing that matters is the AP-title two layers up.
//
// What is still worth reading here is the PDU type, because a relay has to know a
// connection request from a data transfer to know which layer comes next, and
// because a disconnect request is how an association ends without an MMS conclude.

// The COTP PDU types (X.224 §13).
const (
	CR uint8 = 0xE0 // connection request
	CC uint8 = 0xD0 // connection confirm
	DR uint8 = 0x80 // disconnect request
	DC uint8 = 0xC0 // disconnect confirm
	DT uint8 = 0xF0 // data
	ED uint8 = 0x10 // expedited data
	AK uint8 = 0x60 // data acknowledgement
	EA uint8 = 0x20 // expedited acknowledgement
	RJ uint8 = 0x50 // reject
	ER uint8 = 0x70 // error
)

// The connection parameters of a CR or CC (X.224 §13.3.4).
const (
	paramTPDUSize uint8 = 0xC0
	paramCalling  uint8 = 0xC1
	paramCalled   uint8 = 0xC2
)

// MaxSelector bounds a transport selector. X.224 allows 32 octets; 61850 uses one
// or two.
const MaxSelector = 32

// COTP is one COTP PDU.
type COTP struct {
	Type uint8
	// DstRef and SrcRef are the connection references of a CR, CC, DR or DC.
	DstRef, SrcRef uint16
	// Class is the transport class and options octet of a CR or CC.
	Class uint8
	// TPDUSize is the size parameter as it arrives: a power-of-two exponent, so
	// 0x0a is 1024 octets.
	TPDUSize uint8
	// Calling and Called are the transport selectors, as they arrived.
	Calling, Called []byte
	// EOT says a data PDU is the last of its sequence, and Number its sequence
	// number.
	EOT    bool
	Number uint8
	// Data is the user data of a DT, which is where the session layer starts.
	Data []byte
}

// TypeName names a PDU type for a log line, and says which number it was when it is
// one this package does not name.
func TypeName(t uint8) string {
	switch t {
	case CR:
		return "connection_request"
	case CC:
		return "connection_confirm"
	case DR:
		return "disconnect_request"
	case DC:
		return "disconnect_confirm"
	case DT:
		return "data"
	case ED:
		return "expedited_data"
	case AK:
		return "data_ack"
	case EA:
		return "expedited_ack"
	case RJ:
		return "reject"
	case ER:
		return "error"
	}
	return fmt.Sprintf("cotp(0x%02x)", t)
}

// ParseCOTP reads one PDU out of a TPKT frame's body.
//
// The first octet is a length that counts the header past itself, and it is a peer's
// number: a length longer than the frame is refused rather than used to slice, and a
// length of zero would describe a header with no type octet in it.
func ParseCOTP(b []byte) (*COTP, error) {
	if len(b) < 2 {
		return nil, fmt.Errorf("%w: %d octets where a COTP header must be", ErrShort, len(b))
	}
	li := int(b[0])
	if li == 0 {
		return nil, fmt.Errorf("%w: COTP header length 0", ErrSize)
	}
	if 1+li > len(b) {
		return nil, fmt.Errorf("%w: COTP header says %d octets, %d are in the frame",
			ErrShort, li, len(b)-1)
	}
	h := b[1 : 1+li]
	c := &COTP{Type: h[0] & 0xF0}
	// A data PDU's type octet is 0xF0 with no low bits; the others carry their
	// low nibble as part of the type, so an expedited data PDU (0x10) and a
	// credit-bearing variant have to be distinguished before the mask.
	if h[0] == ED {
		c.Type = ED
	}
	rest := h[1:]
	switch c.Type {
	case CR, CC:
		if len(rest) < 5 {
			return nil, fmt.Errorf("%w: a %s in %d octets", ErrShort, TypeName(c.Type), len(rest))
		}
		c.DstRef = binary.BigEndian.Uint16(rest[0:])
		c.SrcRef = binary.BigEndian.Uint16(rest[2:])
		c.Class = rest[4]
		if err := c.params(rest[5:]); err != nil {
			return nil, err
		}
	case DR, DC:
		if len(rest) < 4 {
			return nil, fmt.Errorf("%w: a %s in %d octets", ErrShort, TypeName(c.Type), len(rest))
		}
		c.DstRef = binary.BigEndian.Uint16(rest[0:])
		c.SrcRef = binary.BigEndian.Uint16(rest[2:])
	case DT:
		if len(rest) < 1 {
			return nil, fmt.Errorf("%w: a data PDU with no sequence octet", ErrShort)
		}
		c.EOT = rest[0]&0x80 != 0
		c.Number = rest[0] & 0x7F
		c.Data = b[1+li:]
	}
	return c, nil
}

// params reads the variable part of a CR or CC: a sequence of code, length, value.
func (c *COTP) params(b []byte) error {
	for len(b) > 0 {
		if len(b) < 2 {
			return fmt.Errorf("%w: a COTP parameter header in %d octets", ErrShort, len(b))
		}
		code, n := b[0], int(b[1])
		if 2+n > len(b) {
			return fmt.Errorf("%w: COTP parameter 0x%02x says %d octets, %d are left",
				ErrShort, code, n, len(b)-2)
		}
		v := b[2 : 2+n]
		switch code {
		case paramTPDUSize:
			if n == 1 {
				c.TPDUSize = v[0]
			}
		case paramCalling:
			if n > MaxSelector {
				return fmt.Errorf("%w: a calling selector of %d octets", ErrSize, n)
			}
			c.Calling = v
		case paramCalled:
			if n > MaxSelector {
				return fmt.Errorf("%w: a called selector of %d octets", ErrSize, n)
			}
			c.Called = v
		}
		b = b[2+n:]
	}
	return nil
}

// TPDUBytes is what a size exponent means in octets, or zero for one outside the
// range X.224 defines (§13.3.4 allows 7 through 13, that is 128 to 8192).
func TPDUBytes(exp uint8) int {
	if exp < 7 || exp > 13 {
		return 0
	}
	return 1 << exp
}
