package opcua

import (
	"encoding/binary"

	wire "github.com/rom/xproxy/internal/opcua"
)

// How this relay says no, in the protocol's own words.
//
// A server that refuses a service answers with a **ServiceFault**: a response whose
// TypeId is the fault's rather than the service's, carrying a bad status code in its
// response header. A client's library reports that as the error it is, against the
// request handle it came from, and the poll loop carries on — which is what a plant
// needs, because dropping a session because one Read was refused turns a refusal
// into an outage.
//
// A refusal that cannot be a fault is an **ERR** and a close. There are two kinds:
// a decision made before any session exists, where there is no request identifier
// to answer on, and a decision about the transport itself. Closing without an ERR
// would leave the client's log saying "connection reset" and the operator with
// nothing to correlate against this relay's refusal.
//
// This file builds the relay's own messages and never re-renders a peer's. A proxy
// that re-encoded a chunk would be a second implementation of the encoder, and the
// two implementations' disagreements are what an attacker looks for — and on this
// protocol it would be worse than that: under mode sign the body is signed, so a
// re-rendered message is a message whose signature no longer matches.

// serviceFault builds a ServiceFault answering one request.
//
// The response header is the whole message: a fault carries no body of its own
// beyond it. The request handle is echoed so the client's library can match the
// fault to the call it made, and the status code is the one the policy chose.
func serviceFault(channel, token, sequence, request, handle, status uint32) []byte {
	body := make([]byte, 0, 64)
	// The TypeId: a four-byte numeric node id in namespace zero.
	body = append(body, 0x01, 0x00)
	body = binary.LittleEndian.AppendUint16(body, uint16(wire.SvcFault))
	// The response header: the timestamp, the handle, the result, no diagnostic
	// info, an empty string table and an empty additional header.
	body = binary.LittleEndian.AppendUint64(body, uint64(wire.ToFileTime(now()))) //nolint:gosec // a timestamp after 1601 is positive
	body = binary.LittleEndian.AppendUint32(body, handle)
	body = binary.LittleEndian.AppendUint32(body, status)
	body = append(body, 0x00) // no diagnostic info
	body = binary.LittleEndian.AppendUint32(body, 0)
	body = append(body, 0x00, 0x00, 0x00) // a null node id and no extension body

	// The symmetric security header and the sequence header, then the chunk.
	out := make([]byte, 0, wire.HeaderLen+16+len(body))
	out = append(out, wire.Message[:]...)
	out = append(out, byte(wire.Final))
	out = binary.LittleEndian.AppendUint32(out, uint32(wire.HeaderLen+16+len(body))) //nolint:gosec // bounded by the body above
	out = binary.LittleEndian.AppendUint32(out, channel)
	out = binary.LittleEndian.AppendUint32(out, token)
	out = binary.LittleEndian.AppendUint32(out, sequence)
	out = binary.LittleEndian.AppendUint32(out, request)
	return append(out, body...)
}

// refuseConn refuses in a way that ends the connection: an ERR with the reason, and
// then the caller closes.
func (t *server) refuseConn(c *conn, d Decision, what string) {
	c.refusal()
	t.refused2(c, d, what)
	if !t.enforcing() && !d.Hard {
		return
	}
	if t.policy.respondWith() == "drop" {
		return
	}
	status := d.Status
	if status == 0 {
		status = wire.StatusBadSecurityChecksFailed
	}
	// The reason carries the refusal's own words, which is what an operator
	// correlates against this relay's log. It does not carry the rule's comment:
	// that is the estate's own note and belongs in the log rather than on the
	// wire to a client that may not be trusted with it.
	_ = c.writeClient(wire.EncodeError(status, "xproxy: "+d.Reason))
}

// refusalOnly records a refusal and does nothing about it, which is what a shadow
// listener does with a decision it is not enforcing.
func (t *server) refusalOnly(c *conn, d Decision, what string) {
	c.refusal()
	t.refused2(c, d, what)
}

// refuseMessage refuses one message and keeps the session.
//
// It is used where there is no assembled message to answer against — a rate limit,
// for instance, which is decided before the chunk is read. There is nothing to
// answer, so the message is swallowed; the client's own retry is what it sees.
func (t *server) refuseMessage(c *conn, d Decision, what string) {
	c.refusal()
	t.refused2(c, d, what)
}

// refused turns a refused service call into what the relay does about it.
//
// The session carries on. A fault is sent where the policy asks for one and where
// there is a request identifier to answer on, which there always is here: the
// message assembled, so it had a sequence header.
func (t *server) refused(c *conn, m *wire.Assembled, d Decision, what string) (forward, fatal bool) {
	c.refusal()
	t.refused2(c, d, what)
	if !t.enforcing() && !d.Hard {
		// Shadow or monitor mode: the refusal is recorded and the message goes
		// through, except for the hard decisions.
		return true, false
	}
	return t.respond(c, m, d)
}

// respond is what the client is told about a call that was kept from the
// server. It is separate from refused because the behavioural models do their
// own recording -- and deliberately do not reach the ban ladder -- so they need
// the answer without the refusal's bookkeeping.
func (t *server) respond(c *conn, m *wire.Assembled, d Decision) (forward, fatal bool) {
	switch t.policy.respondWith() {
	case "drop":
		return false, false
	case "close":
		return false, true
	case "error":
		status := d.Status
		if status == 0 {
			status = wire.StatusBadSecurityChecksFailed
		}
		_ = c.writeClient(wire.EncodeError(status, "xproxy: "+d.Reason))
		return false, true
	default:
		status := d.Status
		if status == 0 {
			status = wire.StatusBadServiceUnsupported
		}
		// The sequence number is this relay's own and starts where the message's
		// did: a client checks that the numbers increase within a channel, and a
		// fault answering request N sits where the server's own answer would
		// have.
		_ = c.writeClient(serviceFault(m.Channel, m.Token, m.RequestID, m.RequestID,
			c.handleFor(m.RequestID), status))
		return false, false
	}
}

// handleFor is the request handle a fault echoes.
//
// The handle is in the request header, which this relay read, so it is remembered
// alongside the service. Where it was not — the table was full, or the message was
// opaque — zero is sent, which is what a server sends when it has no handle to
// echo.
func (c *conn) handleFor(request uint32) uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.handles[request]
}

func (c *conn) rememberHandle(request, handle uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.handles == nil {
		c.handles = make(map[uint32]uint32, 8)
	}
	if len(c.handles) >= MaxPendingRequests {
		return
	}
	c.handles[request] = handle
}

func (c *conn) forgetHandle(request uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.handles, request)
}
