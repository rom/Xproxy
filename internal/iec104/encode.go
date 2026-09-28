package iec104

import (
	"encoding/binary"
	"math"
	"time"
)

// Building APDUs.
//
// The relay forwards the octets that arrived rather than re-encoding them,
// for the reason the package comment gives: re-encoding is how a relay and
// a station come to disagree about what was said. Nothing here changes
// that. What is here is for the one case where there is no station -- a
// decoy answering as a substation that is not on the network -- and for
// the tests, which have to be able to write a frame a real client would.
//
// Every function appends and returns, so a caller building several ASDUs
// into one buffer does not pay for a copy each time.

// EncodeU is a U-format APDU: one control function and nothing else.
func EncodeU(c Control) []byte {
	return []byte{Start, 4, byte(c), 0, 0, 0}
}

// EncodeS is an S-format APDU: an acknowledgement carrying the receive
// sequence number and no data.
func EncodeS(recv uint16) []byte {
	out := []byte{Start, 4, 0x01, 0, 0, 0}
	binary.LittleEndian.PutUint16(out[4:6], recv<<1)
	return out
}

// EncodeI wraps an ASDU in an I-format APDU with the two sequence numbers.
//
// The numbers are the sender's own count of what it has sent and what it
// has received, shifted up one bit -- the low bit of the send field is what
// says the frame is an I frame at all.
func EncodeI(send, recv uint16, asdu []byte) []byte {
	out := make([]byte, 0, APCILen+len(asdu))
	out = append(out, Start, byte(4+len(asdu)))
	out = binary.LittleEndian.AppendUint16(out, send<<1)
	out = binary.LittleEndian.AppendUint16(out, recv<<1)
	return append(out, asdu...)
}

// Head is the six octets every ASDU begins with.
type Head struct {
	Type Type
	// Objects is the number of information objects, or of elements in a
	// sequence. One is the commonest and zero is not a legal ASDU.
	Objects int
	// Sequence says the addresses run on from the first rather than being
	// carried per object, which is how a station reports a block of
	// consecutive points.
	Sequence bool
	Cause    Cause
	// Negative marks a command that will not be carried out, and Test a
	// frame that is not about the process.
	Negative, Test bool
	Originator     byte
	Common         uint16
}

// AppendHead appends an ASDU header.
func AppendHead(dst []byte, h Head) []byte {
	n := h.Objects
	if n < 0 {
		n = 0
	}
	if n > 127 {
		n = 127
	}
	vsq := byte(n) //nolint:gosec // bounded to 0..127 above
	if h.Sequence {
		vsq |= 0x80
	}
	cot := byte(h.Cause) & 0x3F
	if h.Negative {
		cot |= 0x40
	}
	if h.Test {
		cot |= 0x80
	}
	dst = append(dst, byte(h.Type), vsq, cot, h.Originator)
	return binary.LittleEndian.AppendUint16(dst, h.Common)
}

// AppendIOA appends an information object address: three octets, little
// endian, which is the one field of this protocol everybody gets wrong
// once.
func AppendIOA(dst []byte, ioa uint32) []byte {
	return append(dst, byte(ioa), byte(ioa>>8), byte(ioa>>16))
}

// QualityGood is a value the device stands behind: no bit set. The bits that
// say what is wrong with one are Quality's own, in element.go, so that the
// encoder and the decoder name the same five things the same way -- a decoy that
// set any of them would be reporting a fault nobody is going to find.
const QualityGood Quality = 0

// AppendSinglePoint appends an M_SP_NA_1 object: an address and one bit
// with its quality.
func AppendSinglePoint(dst []byte, ioa uint32, on bool, quality Quality) []byte {
	dst = AppendIOA(dst, ioa)
	siq := byte(quality) & 0xF0
	if on {
		siq |= 0x01
	}
	return append(dst, siq)
}

// AppendScaled appends an M_ME_NB_1 object: a scaled measurement, which is
// what most of a substation's analogue traffic is.
func AppendScaled(dst []byte, ioa uint32, value int16, quality Quality) []byte {
	dst = AppendIOA(dst, ioa)
	dst = binary.LittleEndian.AppendUint16(dst, uint16(value)) //nolint:gosec // the standard's own signed encoding
	return append(dst, byte(quality))
}

// AppendFloat appends an M_ME_NC_1 object: a short floating point
// measurement, which is what newer equipment reports.
func AppendFloat(dst []byte, ioa uint32, value float32, quality Quality) []byte {
	dst = AppendIOA(dst, ioa)
	dst = binary.LittleEndian.AppendUint32(dst, math.Float32bits(value))
	return append(dst, byte(quality))
}

// AppendTotal appends an M_IT_NA_1 object: an integrated total with its
// sequence number. The sequence octet's low five bits count the reads, so
// a counter answering the same sequence every time is a counter nobody is
// integrating.
func AppendTotal(dst []byte, ioa uint32, value int32, sequence byte) []byte {
	dst = AppendIOA(dst, ioa)
	dst = binary.LittleEndian.AppendUint32(dst, uint32(value)) //nolint:gosec // the standard's own signed encoding
	return append(dst, sequence&0x1F)
}

// AppendCP56Time2a appends the seven-octet timestamp: milliseconds within
// the minute, then the minute, hour, day with day of week, month and year.
func AppendCP56Time2a(dst []byte, at time.Time) []byte {
	at = at.UTC()
	ms := uint16(at.Second()*1000 + at.Nanosecond()/1e6) //nolint:gosec // under 60000
	dst = binary.LittleEndian.AppendUint16(dst, ms)
	dst = append(dst, byte(at.Minute()), byte(at.Hour()))
	dst = append(dst, byte(at.Day())|byte(dayOfWeek(at))<<5)
	return append(dst, byte(at.Month()), byte(at.Year()%100))
}

// dayOfWeek is Monday 1 to Sunday 7, which is how the standard counts and
// not how Go does.
func dayOfWeek(at time.Time) int {
	if d := int(at.Weekday()); d != 0 {
		return d
	}
	return 7
}
