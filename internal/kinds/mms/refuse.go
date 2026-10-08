package mms

import (
	"encoding/binary"
	"math"

	wire "github.com/rom/xproxy/internal/mms"
)

// Refusing, in the protocol's own form.
//
// A client's library has a table of MMS error classes and codes, and it turns them
// into something an operator reads: "object access denied" rather than "the
// connection closed". So a refusal this relay composes is a confirmed-error PDU
// echoing the invoke identifier of the request it refuses, wrapped back down through
// the presentation, session and transport layers.
//
// This is the one place the package encodes rather than reads, and it encodes the
// smallest thing that will do: there is no general BER writer here, because a relay
// that could re-render a request could also be asked to rewrite one.

// The refusal responses a listener may be configured with.
const (
	denyError  = "error"
	denyReject = "reject"
	denyDrop   = "drop"
	denyClose  = "close"
)

func (t *server) denyResponse() string {
	if t.mc.DenyResponse == "" {
		return denyError
	}
	return t.mc.DenyResponse
}

// refused answers one refused request and says whether to forward it and whether the
// association is over.
//
// A soft refusal on a listener that is not enforcing is recorded and forwarded, which
// is what shadow mode is. A hard one is refused whatever the mode.
func (t *server) refused(c *conn, m *wire.Message, d Decision, detail string) (forward, fatal bool) {
	if !t.enforcing() && !d.Hard {
		t.refusalOnly(c, d, detail)
		return true, false
	}
	c.refusal()
	t.deny(c, d.Reason, detail)
	t.alertDeny(c, d, detail)
	return t.respond(c, m, d)
}

// respond is what the client is told about a request that was kept from the
// IED. It is separate from refused because the behavioural models do their own
// recording -- and deliberately do not reach the ban ladder -- so they need the
// answer without the refusal's bookkeeping.
func (t *server) respond(c *conn, m *wire.Message, d Decision) (forward, fatal bool) {
	switch t.denyResponse() {
	case denyDrop:
		return false, false
	case denyClose:
		return false, true
	case denyReject:
		_ = c.writeClient(rejectFrame(invokeOf(m)))
		return false, false
	}
	if !m.HasInvokeID {
		// No identifier to echo, so no error a client's library can match to the
		// call it made. Closing is the honest answer.
		return false, true
	}
	_ = c.writeClient(errorFrame(invokeOf(m), d.ErrorClass, d.ErrorCode))
	return false, false
}

// refuseConn refuses at a layer below the service, where there is no invoke
// identifier to answer and closing is the only thing a peer will understand.
func (t *server) refuseConn(c *conn, d Decision, detail string) {
	if !t.enforcing() && !d.Hard {
		t.refusalOnly(c, d, detail)
		return
	}
	c.refusal()
	t.deny(c, d.Reason, detail)
	t.alertDeny(c, d, detail)
	_ = c.client.Close()
}

// refusalOnly records what would have been refused and lets it through, which is what
// a shadow or learning listener does.
func (t *server) refusalOnly(c *conn, d Decision, detail string) {
	h := t.host
	h.Counters().WouldRefuse("mms", d.Reason)
	h.Shadow().Record("mms", t.name, d.Reason, d.Rule, detail)
	t.logWouldRefuse(c, d, detail)
}

// errorFrame builds a confirmed-error PDU inside the layers that carry it.
//
// The shape is:
//
//	confirmed-ErrorPDU [2] { invokeID, serviceError [0] { errorClass [0] { <class> } } }
//
// The error class is itself a choice whose tag is the class, and whose value is the
// code -- which is how one INTEGER carries both halves of what a client's table is
// keyed on.
func errorFrame(invoke uint32, class, code int) []byte {
	pdu := ctxTag(2, true,
		berInt(int64(invoke)),
		ctxTag(0, true,
			ctxTag(0, true,
				ctxTag(byte(class), false, berContent(int64(code))))))
	return dataFrame(pdu)
}

// rejectFrame builds a reject PDU, which says the request was not one the device will
// perform at all rather than that the object was denied.
//
//	rejectPDU [4] { originalInvokeID [0], pduError [2] { <reason> } }
func rejectFrame(invoke uint32) []byte {
	const rejectUnrecognisedService = 1
	pdu := ctxTag(4, true,
		ctxTag(0, false, berContent(int64(invoke))),
		ctxTag(2, false, berContent(rejectUnrecognisedService)))
	return dataFrame(pdu)
}

// dataFrame wraps an MMS PDU in a presentation data value, a session data transfer, a
// COTP data PDU and a TPKT header.
//
// The presentation context identifier is 3, which is what every IEC 61850 stack binds
// MMS to. This is the one place a number is assumed rather than read, and the reason
// it is safe here is that the frame is this relay's own answer to a client it is
// about to stop talking to: if the client bound MMS to some other identifier it will
// discard the frame, which leaves it with a refusal it could not read rather than a
// request that was carried.
func dataFrame(pdu []byte) []byte {
	const mmsContext = 3
	pdv := appTag(1, berSeq(berInt(mmsContext), ctxTag(0, true, pdu)))
	session := append([]byte{wire.SPDUGiveTokens, 0, wire.SPDUDataTransfer, 0}, pdv...)
	cotp := append([]byte{0x02, wire.DT, 0x80}, session...)
	n := len(cotp) + wire.TPKTHeader
	if n > math.MaxUint16 {
		// Unreachable for the two refusals this file builds -- both are tens of
		// octets -- and checked anyway, because a truncated length would put a
		// frame on the wire that says it is shorter than it is, which is the one
		// thing a framing layer must never do.
		return nil
	}
	out := []byte{wire.TPKTVersion, 0, 0, 0}
	binary.BigEndian.PutUint16(out[2:], uint16(n)) //nolint:gosec // bounded above
	return append(out, cotp...)
}

// invokeOf narrows a request's invoke identifier to the Unsigned32 the standard types
// it as. The wire package has already refused anything larger, so this is the
// narrowing that says so rather than a check that can fail.
func invokeOf(m *wire.Message) uint32 {
	if m.InvokeID > wire.MaxInvokeID {
		return 0
	}
	return uint32(m.InvokeID)
}

// The smallest BER writer that will do.

func tlv(id byte, body ...[]byte) []byte {
	var b []byte
	for _, p := range body {
		b = append(b, p...)
	}
	out := []byte{id}
	out = append(out, berLen(len(b))...)
	return append(out, b...)
}

func berLen(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n < 0x100:
		return []byte{0x81, byte(n)}
	}
	return []byte{0x82, byte(n >> 8), byte(n)}
}

func ctxTag(tag byte, cons bool, body ...[]byte) []byte {
	id := wire.ClassContext | tag
	if cons {
		id |= wire.Constructed
	}
	return tlv(id, body...)
}

func appTag(tag byte, body ...[]byte) []byte {
	return tlv(wire.ClassApplication|wire.Constructed|tag, body...)
}

func berSeq(body ...[]byte) []byte {
	return tlv(byte(wire.TagSequence)|wire.Constructed, body...)
}

func berInt(v int64) []byte { return tlv(byte(wire.TagInteger), berContent(v)) }

// berContent renders an integer's content octets: shortest two's complement.
func berContent(v int64) []byte {
	if v == 0 {
		return []byte{0}
	}
	var b []byte
	neg := v < 0
	for v != 0 && v != -1 {
		b = append([]byte{byte(v)}, b...)
		v >>= 8
	}
	if len(b) == 0 {
		// The loop stops when what is left is all sign bits, so an empty b
		// means v was -1: zero already returned above. The content octets of
		// -1 are one 0xFF, and returning 0 here would encode it as zero --
		// a different integer, and in an error code a different refusal.
		return []byte{0xFF}
	}
	if !neg && b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	if neg && b[0]&0x80 == 0 {
		b = append([]byte{0xFF}, b...)
	}
	return b
}
