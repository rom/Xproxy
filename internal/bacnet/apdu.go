package bacnet

import "fmt"

// PDUType is the application layer PDU type: the high nibble of the
// first octet of an APDU.
type PDUType uint8

// The eight PDU types of clause 20.
const (
	PDUConfirmedRequest   PDUType = 0
	PDUUnconfirmedRequest PDUType = 1
	PDUSimpleACK          PDUType = 2
	PDUComplexACK         PDUType = 3
	PDUSegmentACK         PDUType = 4
	PDUError              PDUType = 5
	PDUReject             PDUType = 6
	PDUAbort              PDUType = 7
)

var pduNames = [8]string{
	"confirmed-request", "unconfirmed-request", "simple-ack", "complex-ack",
	"segment-ack", "error", "reject", "abort",
}

// String names the PDU type.
func (t PDUType) String() string {
	if t < 8 {
		return pduNames[t]
	}
	return fmt.Sprintf("pdu-type-%d", uint8(t))
}

// Request reports whether the PDU is a client asking for something, as
// against a device answering.
func (t PDUType) Request() bool {
	return t == PDUConfirmedRequest || t == PDUUnconfirmedRequest
}

// maxAPDULengths is the encoding of clause 20.1.2.5: five sizes and a
// reserved range. A device says how much it can take, and a client says
// how much it will accept back.
var maxAPDULengths = [16]int{50, 128, 206, 480, 1024, 1476}

// maxSegments is clause 20.1.2.4: a count, "unspecified", or "more than
// sixty-four", which is the one a relay should not take at face value.
var maxSegments = [8]int{0, 2, 4, 8, 16, 32, 64, 65}

// APDU is a parsed application layer message.
type APDU struct {
	Type PDUType
	// Service is the service choice, which every PDU type except
	// SegmentACK, Reject and Abort carries. HasService says whether it
	// is there.
	Service    Service
	HasService bool
	// InvokeID ties a reply to its request. Every type but an
	// unconfirmed request has one.
	InvokeID    uint8
	HasInvokeID bool
	// InvokeOffset is where the identifier sits in the octets this APDU
	// was read from, so a relay can rewrite it without re-deriving the
	// header's length.
	//
	// A relay has to rewrite it. The standard makes an invoke identifier
	// unique only between one client and one device, so two clients
	// speaking to the same controller through one relay socket would be
	// indistinguishable on the way back, and one client's answer would be
	// delivered to the other. Translating it is what a BACnet router does
	// for the same reason.
	InvokeOffset int
	// Segmented, MoreFollows, Sequence and Window are the segmentation
	// fields. A segmented message is a message a relay sees a piece of,
	// which is the reason they are surfaced rather than skipped.
	Segmented   bool
	MoreFollows bool
	Sequence    uint8
	Window      uint8
	// SegmentedAccepted is the client's claim that it can receive a
	// segmented reply; MaxSegments and MaxAPDU are how much it will take.
	// MaxSegments is 0 for "unspecified" and 65 for "more than 64".
	SegmentedAccepted bool
	MaxSegments       int
	MaxAPDU           int
	// Reason is a Reject's or an Abort's reason code.
	Reason    uint8
	HasReason bool
	// Server, on an Abort or a SegmentACK, says the sending peer is the
	// server of the exchange rather than the client.
	Server bool
	// Params is what is left: the service's own encoded parameters.
	Params []byte
}

// ParseAPDU reads the application layer.
//
// The reserved bits in the first two octets are checked for the same
// reason the network layer's are: a field the standard says is zero, sent
// as one, is a sender arranging for two readers to disagree.
func ParseAPDU(b []byte) (APDU, error) {
	if len(b) == 0 {
		return APDU{}, fmt.Errorf("%w: an empty application message", ErrTruncated)
	}
	a := APDU{Type: PDUType(b[0] >> 4)}
	flags := b[0] & 0x0F
	at := 1
	take := func(what string) (byte, error) {
		if at >= len(b) {
			return 0, fmt.Errorf("%w: %s is past the end of a %d octet message", ErrTruncated, what, len(b))
		}
		v := b[at]
		at++
		return v, nil
	}
	var err error
	switch a.Type {
	case PDUConfirmedRequest:
		if flags&0x01 != 0 {
			return a, fmt.Errorf("%w: a reserved bit set in a confirmed request (0x%02x)", ErrMalformed, b[0])
		}
		a.Segmented, a.MoreFollows, a.SegmentedAccepted = flags&0x08 != 0, flags&0x04 != 0, flags&0x02 != 0
		if !a.Segmented && a.MoreFollows {
			return a, fmt.Errorf("%w: more-follows on a request that is not segmented", ErrMalformed)
		}
		var sz byte
		if sz, err = take("the size octet"); err != nil {
			return a, err
		}
		if sz&0x80 != 0 {
			return a, fmt.Errorf("%w: a reserved bit set in the size octet (0x%02x)", ErrMalformed, sz)
		}
		a.MaxSegments = maxSegments[(sz>>4)&0x07]
		if a.MaxAPDU = maxAPDULengths[sz&0x0F]; a.MaxAPDU == 0 {
			return a, fmt.Errorf("%w: a reserved maximum APDU length (%d)", ErrMalformed, sz&0x0F)
		}
		a.InvokeOffset = at
		if a.InvokeID, err = take("the invoke identifier"); err != nil {
			return a, err
		}
		a.HasInvokeID = true
		if a.Segmented {
			if a.Sequence, err = take("the sequence number"); err != nil {
				return a, err
			}
			if a.Window, err = take("the window size"); err != nil {
				return a, err
			}
			if a.Window == 0 {
				return a, fmt.Errorf("%w: a proposed window size of zero", ErrMalformed)
			}
		}
		var ch byte
		if ch, err = take("the service choice"); err != nil {
			return a, err
		}
		a.Service, a.HasService = Service{Confirmed: true, Choice: ch}, true
	case PDUUnconfirmedRequest:
		if flags != 0 {
			return a, fmt.Errorf("%w: a reserved bit set in an unconfirmed request (0x%02x)", ErrMalformed, b[0])
		}
		var ch byte
		if ch, err = take("the service choice"); err != nil {
			return a, err
		}
		a.Service, a.HasService = Service{Choice: ch}, true
	case PDUSimpleACK:
		if flags != 0 {
			return a, fmt.Errorf("%w: a reserved bit set in a simple ack (0x%02x)", ErrMalformed, b[0])
		}
		a.InvokeOffset = at
		if a.InvokeID, err = take("the invoke identifier"); err != nil {
			return a, err
		}
		a.HasInvokeID = true
		var ch byte
		if ch, err = take("the service choice"); err != nil {
			return a, err
		}
		a.Service, a.HasService = Service{Confirmed: true, Choice: ch}, true
	case PDUComplexACK:
		if flags&0x03 != 0 {
			return a, fmt.Errorf("%w: a reserved bit set in a complex ack (0x%02x)", ErrMalformed, b[0])
		}
		a.Segmented, a.MoreFollows = flags&0x08 != 0, flags&0x04 != 0
		if !a.Segmented && a.MoreFollows {
			return a, fmt.Errorf("%w: more-follows on a reply that is not segmented", ErrMalformed)
		}
		a.InvokeOffset = at
		if a.InvokeID, err = take("the invoke identifier"); err != nil {
			return a, err
		}
		a.HasInvokeID = true
		if a.Segmented {
			if a.Sequence, err = take("the sequence number"); err != nil {
				return a, err
			}
			if a.Window, err = take("the window size"); err != nil {
				return a, err
			}
		}
		var ch byte
		if ch, err = take("the service choice"); err != nil {
			return a, err
		}
		a.Service, a.HasService = Service{Confirmed: true, Choice: ch}, true
	case PDUSegmentACK:
		if flags&0x0C != 0 {
			return a, fmt.Errorf("%w: a reserved bit set in a segment ack (0x%02x)", ErrMalformed, b[0])
		}
		a.Server = flags&0x01 != 0
		a.InvokeOffset = at
		if a.InvokeID, err = take("the invoke identifier"); err != nil {
			return a, err
		}
		a.HasInvokeID = true
		if a.Sequence, err = take("the sequence number"); err != nil {
			return a, err
		}
		if a.Window, err = take("the window size"); err != nil {
			return a, err
		}
	case PDUError:
		if flags != 0 {
			return a, fmt.Errorf("%w: a reserved bit set in an error (0x%02x)", ErrMalformed, b[0])
		}
		a.InvokeOffset = at
		if a.InvokeID, err = take("the invoke identifier"); err != nil {
			return a, err
		}
		a.HasInvokeID = true
		var ch byte
		if ch, err = take("the service choice"); err != nil {
			return a, err
		}
		a.Service, a.HasService = Service{Confirmed: true, Choice: ch}, true
	case PDUReject, PDUAbort:
		if a.Type == PDUReject && flags != 0 {
			return a, fmt.Errorf("%w: a reserved bit set in a reject (0x%02x)", ErrMalformed, b[0])
		}
		if a.Type == PDUAbort {
			if flags&0x0E != 0 {
				return a, fmt.Errorf("%w: a reserved bit set in an abort (0x%02x)", ErrMalformed, b[0])
			}
			a.Server = flags&0x01 != 0
		}
		a.InvokeOffset = at
		if a.InvokeID, err = take("the invoke identifier"); err != nil {
			return a, err
		}
		a.HasInvokeID = true
		if a.Reason, err = take("the reason"); err != nil {
			return a, err
		}
		a.HasReason = true
	default:
		return a, fmt.Errorf("%w: %s", ErrMalformed, a.Type)
	}
	a.Params = b[at:]
	return a, nil
}
