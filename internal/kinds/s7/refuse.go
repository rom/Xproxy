package s7

import (
	"encoding/binary"

	wire "github.com/rom/xproxy/internal/s7"
)

// How this relay says no, in the protocol's own words.
//
// A PLC that refuses something answers with an acknowledgement carrying an
// error class, and a client library reports that as an error rather than as a
// timeout. So a refused request gets one: class 0x87, **access fault**, which
// is what a protected CPU answers a client that has not supplied its
// password. The client sees the refusal it would have seen from the
// controller itself, and the relay's own log line says which listener and
// which rule refused it.
//
// A refused *connection* is answered with a COTP disconnect request, which is
// what a CPU with no free connection resources sends. The alternative -- a
// silent close -- reads to an engineering station as a network fault, and an
// engineer chasing a network fault that is a policy is an afternoon wasted.
//
// This file is the only place in the kind that builds a frame. It builds the
// relay's *own* messages and never re-renders a peer's, because a proxy that
// re-encoded a frame would be a second implementation of the encoder whose
// disagreements with the first are what an attacker is looking for.

// accessFault is the error class a protected CPU answers with.
const accessFault = 0x87

// notImplemented is the user-data error code for a function the CPU does not
// offer, which is the honest thing to tell a client about a subfunction this
// listener will not carry.
const notImplemented = 0x8104

// errorAck builds an acknowledgement refusing a job.
//
// The parameter echoes the function code with an item count of zero, which is
// the shape a client's reader expects: the library matches the function, sees
// the error class and reports it.
func errorAck(pdu *wire.PDU) []byte {
	param := []byte{pdu.Function, 0x00}
	if !pdu.HasFunction {
		param = nil
	}
	body := make([]byte, 0, 12+len(param))
	body = append(body, wire.ProtocolID, byte(wire.AckData), 0, 0)
	body = binary.BigEndian.AppendUint16(body, pdu.PDURef)
	body = binary.BigEndian.AppendUint16(body, uint16(len(param))) //nolint:gosec // two octets
	body = binary.BigEndian.AppendUint16(body, 0)
	body = append(body, accessFault, 0x00)
	body = append(body, param...)
	return tpktData(body)
}

// errorUserData builds a user-data response refusing a user-data request.
//
// It answers in the layer the request arrived in: the same group and
// subfunction, the response type, and an error code saying the function is not
// available. A client that asked to set the clock is told the CPU will not,
// which is the truth as far as that client is concerned.
func errorUserData(pdu *wire.PDU, u *wire.UserData) []byte {
	param := []byte{
		0x00, 0x01, 0x12, // the user-data marker
		0x08, // a response parameter is eight octets
		0x12, // the response method
		wire.UserResponse<<4 | u.Group,
		u.Sub,
		u.Sequence,
		0x00, // the data unit reference
		0x00, // no more data follows
	}
	param = binary.BigEndian.AppendUint16(param, notImplemented)
	// The message type is *userdata* on the way back as well as on the way
	// out: this layer answers in itself rather than in an acknowledgement,
	// and a client's reader looks for the group and the subfunction it asked
	// about. So there is no error class here either -- the error is the code
	// in the parameter, which is where a client that asked to set the clock
	// looks to find out that the CPU will not.
	body := make([]byte, 0, 10+len(param))
	body = append(body, wire.ProtocolID, byte(wire.Userdata), 0, 0)
	body = binary.BigEndian.AppendUint16(body, pdu.PDURef)
	body = binary.BigEndian.AppendUint16(body, uint16(len(param))) //nolint:gosec // twelve octets
	body = binary.BigEndian.AppendUint16(body, 0)
	body = append(body, param...)
	return tpktData(body)
}

// disconnect builds a COTP disconnect request, which is how a connection is
// refused.
func disconnect(dstRef, srcRef uint16) []byte {
	body := make([]byte, 0, 7)
	body = append(body, 0x06, wire.COTPDisconnectRequest)
	body = binary.BigEndian.AppendUint16(body, dstRef)
	body = binary.BigEndian.AppendUint16(body, srcRef)
	body = append(body, 0x00) // the reason: not specified
	return tpkt(body)
}

// tpktData wraps an S7 PDU in a COTP data PDU and a TPKT frame.
func tpktData(s7 []byte) []byte {
	cotp := make([]byte, 0, 3+len(s7))
	cotp = append(cotp, 0x02, wire.COTPData, 0x80)
	cotp = append(cotp, s7...)
	return tpkt(cotp)
}

// tpkt wraps a payload in a TPKT header.
func tpkt(payload []byte) []byte {
	out := make([]byte, 0, wire.TPKTHeader+len(payload))
	out = append(out, wire.TPKTVersion, 0)
	out = binary.BigEndian.AppendUint16(out, uint16(wire.TPKTHeader+len(payload))) //nolint:gosec // the frames here are a few dozen octets
	return append(out, payload...)
}
