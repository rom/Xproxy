package s7

import (
	"encoding/binary"
	"fmt"
)

// COTP, which is where the address is.
//
// The connection request carries a *called TSAP*, and on this protocol
// those two octets are the whole of the addressing: the first says what
// kind of connection is being asked for and the second holds the rack and
// the slot of the CPU. A relay that read nothing else could still say
// which rack and slot a client may reach -- and on a plant network, where
// one engineering station can reach every controller on the segment, that
// is most of the boundary an operator wants.
//
// The connection type matters as much as the rack. `PG` is the programming
// device connection: it is what an engineering station opens, and it is the
// one that may download a program. `OP` is an operator panel. Anything
// else is a basic communication connection, which is what one PLC opens to
// another. A listener that admits only OP connections has said something
// useful without naming a single function code.

// The COTP PDU types (X.224 §13). Only the ones that appear on an
// ISO-on-TCP connection are named; anything else is reported as the number
// it is.
const (
	COTPConnectionRequest uint8 = 0xE0
	COTPConnectionConfirm uint8 = 0xD0
	COTPDisconnectRequest uint8 = 0x80
	COTPDisconnectConfirm uint8 = 0xC0
	COTPData              uint8 = 0xF0
	COTPExpeditedData     uint8 = 0x10
	COTPDataAck           uint8 = 0x60
	COTPExpeditedAck      uint8 = 0x20
	COTPReject            uint8 = 0x50
	COTPError             uint8 = 0x70
)

// The connection parameters of a CR or CC (X.224 §13.3.4).
const (
	paramTPDUSize uint8 = 0xC0
	paramCalling  uint8 = 0xC1
	paramCalled   uint8 = 0xC2
)

// The connection resources a called TSAP's first octet names, as Siemens
// uses them.
const (
	ResourcePG    uint8 = 0x01
	ResourceOP    uint8 = 0x02
	ResourceBasic uint8 = 0x03
)

// COTP is one COTP PDU.
type COTP struct {
	Type uint8
	// DstRef and SrcRef are the connection references of a CR, CC, DR or
	// DC.
	DstRef, SrcRef uint16
	// Class is the transport class and options octet of a CR or CC.
	Class uint8
	// TPDUSize is the size parameter as it arrives: a power of two
	// exponent, so 0x0a is 1024 octets.
	TPDUSize uint8
	// Calling and Called are the TSAPs, as they arrived.
	Calling, Called []byte
	// EOT says a data PDU is the last of its sequence, and Number is its
	// sequence number.
	EOT    bool
	Number uint8
	// Data is the user data: on a data PDU, the S7 PDU.
	Data []byte
}

// ParseCOTP reads a COTP PDU out of a TPKT payload.
func ParseCOTP(b []byte) (*COTP, error) {
	if len(b) < 2 {
		return nil, fmt.Errorf("a COTP header of %d octets has no length and type", len(b))
	}
	li := int(b[0])
	// The length indicator counts the header after itself, so the header
	// is li+1 octets and the user data begins there. A length indicator
	// past the frame is the classic way to make two readers disagree.
	if li+1 > len(b) {
		return nil, fmt.Errorf("a COTP length indicator of %d is past the end of a %d octet payload", li, len(b))
	}
	c := &COTP{Type: b[1]}
	switch c.Type {
	case COTPData, COTPExpeditedData:
		if li < 2 {
			return nil, fmt.Errorf("a COTP data header of %d octets has no sequence octet", li)
		}
		c.EOT = b[2]&0x80 != 0
		c.Number = b[2] & 0x7f
		c.Data = b[li+1:]
		return c, nil
	case COTPConnectionRequest, COTPConnectionConfirm:
		if li < 6 {
			return nil, fmt.Errorf("a COTP connection header of %d octets is too short", li)
		}
		c.DstRef = binary.BigEndian.Uint16(b[2:4])
		c.SrcRef = binary.BigEndian.Uint16(b[4:6])
		c.Class = b[6]
		if err := c.readParams(b[7 : li+1]); err != nil {
			return nil, err
		}
		return c, nil
	case COTPDisconnectRequest, COTPDisconnectConfirm:
		if li >= 5 {
			c.DstRef = binary.BigEndian.Uint16(b[2:4])
			c.SrcRef = binary.BigEndian.Uint16(b[4:6])
		}
		return c, nil
	}
	// A type this package does not read is returned as itself, with no
	// claims about its contents: the policy refuses it, which is the only
	// honest thing to do with a transport PDU nobody here understands.
	return c, nil
}

// readParams reads the variable part of a CR or CC.
func (c *COTP) readParams(b []byte) error {
	for len(b) > 0 {
		if len(b) < 2 {
			return errShort
		}
		code, n := b[0], int(b[1])
		rest := b[2:]
		if n > len(rest) {
			return errShort
		}
		v := rest[:n]
		switch code {
		case paramTPDUSize:
			if len(v) == 1 {
				c.TPDUSize = v[0]
			}
		case paramCalling:
			c.Calling = v
		case paramCalled:
			c.Called = v
		}
		b = rest[n:]
	}
	return nil
}

// TypeName names a PDU type, or gives its number when this package does
// not know it.
func (c *COTP) TypeName() string {
	switch c.Type {
	case COTPConnectionRequest:
		return "connection_request"
	case COTPConnectionConfirm:
		return "connection_confirm"
	case COTPDisconnectRequest:
		return "disconnect_request"
	case COTPDisconnectConfirm:
		return "disconnect_confirm"
	case COTPData:
		return "data"
	case COTPExpeditedData:
		return "expedited_data"
	case COTPDataAck:
		return "data_ack"
	case COTPExpeditedAck:
		return "expedited_ack"
	case COTPReject:
		return "reject"
	case COTPError:
		return "error"
	}
	return fmt.Sprintf("%#x", c.Type)
}

// Known says whether the PDU type is one this package reads.
func (c *COTP) Known() bool {
	switch c.Type {
	case COTPConnectionRequest, COTPConnectionConfirm, COTPDisconnectRequest,
		COTPDisconnectConfirm, COTPData, COTPExpeditedData, COTPDataAck,
		COTPExpeditedAck, COTPReject, COTPError:
		return true
	}
	return false
}

// Destination reads the rack, the slot and the connection resource out of
// a called TSAP, and says whether it was the two octets Siemens puts them
// in.
//
// A TSAP of another length is a legal COTP address and not a Siemens one,
// so it reports `ok` false rather than a rack of zero: a listener that
// read "rack 0, slot 0" from an address it did not understand would be
// checking its allow list against a number nobody sent.
func (c *COTP) Destination() (resource uint8, rack, slot int, ok bool) {
	if len(c.Called) != 2 {
		return 0, 0, 0, false
	}
	return c.Called[0], int(c.Called[1] >> 5), int(c.Called[1] & 0x1f), true
}

// ResourceName names a connection resource.
func ResourceName(r uint8) string {
	switch r {
	case ResourcePG:
		return "pg"
	case ResourceOP:
		return "op"
	case ResourceBasic:
		return "basic"
	}
	return fmt.Sprintf("%#x", r)
}

// ResourceOf reads a resource name as the configuration spells it.
func ResourceOf(s string) (uint8, bool) {
	switch s {
	case "pg":
		return ResourcePG, true
	case "op":
		return ResourceOP, true
	case "basic":
		return ResourceBasic, true
	}
	return 0, false
}

// TPDUBytes is the TPDU size a size parameter names: the parameter is a
// power of two exponent (X.224 §13.3.4), and 0 means the parameter was not
// there.
func TPDUBytes(exp uint8) int {
	if exp < 7 || exp > 14 {
		// Outside the range the standard defines. Reported as zero, which
		// the caller reads as "no bound stated" rather than as a size.
		return 0
	}
	return 1 << exp
}
