package rdp

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// The negotiation that opens every connection: the client says which
// security protocols it can speak, and the server picks one. It is the
// first decision a gateway makes and the one that decides what it can
// see afterwards, so it is not relayed -- it is answered.

// The security protocols of MS-RDPBCGR 2.2.1.1.1.
const (
	ProtocolRDP      = 0x00000000 // legacy: RC4 inside the protocol itself
	ProtocolSSL      = 0x00000001 // TLS around the whole connection
	ProtocolHybrid   = 0x00000002 // TLS, then CredSSP: network level authentication
	ProtocolRDSTLS   = 0x00000004
	ProtocolHybridEx = 0x00000008
	ProtocolRDSAAD   = 0x00000010
)

// ProtocolName names one for a log line.
func ProtocolName(p uint32) string {
	switch p {
	case ProtocolRDP:
		return "rdp"
	case ProtocolSSL:
		return "tls"
	case ProtocolHybrid:
		return "nla"
	case ProtocolRDSTLS:
		return "rdstls"
	case ProtocolHybridEx:
		return "nla-ex"
	case ProtocolRDSAAD:
		return "rdsaad"
	}
	return fmt.Sprintf("protocol-%#x", p)
}

// ProtocolByName is the reverse, for configuration.
func ProtocolByName(s string) (uint32, bool) {
	switch s {
	case "rdp":
		return ProtocolRDP, true
	case "tls":
		return ProtocolSSL, true
	case "nla":
		return ProtocolHybrid, true
	}
	return 0, false
}

// The negotiation message types.
const (
	negTypeRequest = 0x01
	negTypeResonse = 0x02
	negTypeFailure = 0x03
)

// The failure codes of MS-RDPBCGR 2.2.1.2.2, which is how a server
// tells a client to come back speaking something else.
const (
	FailSSLRequiredByServer    = 0x00000001
	FailSSLNotAllowedByServer  = 0x00000002
	FailHybridRequiredByServer = 0x00000005
)

// ConnectionRequest is what a client opens with.
type ConnectionRequest struct {
	// Cookie is the routing token a load balancer or a client puts in
	// front of the negotiation, usually "mstshash=" and a user name.
	// It is carried across unchanged where it is a name, and named in
	// the log, because it is the only identity available this early.
	Cookie string
	// Protocols is what the client says it can speak, and Flags what
	// it asks for beyond that.
	Protocols uint32
	Flags     uint8
	// HasNegotiation is false for a client old enough to send none, in
	// which case the connection is the legacy protocol by definition.
	HasNegotiation bool
}

// maxCookie bounds the routing token. The X.224 length indicator is
// one byte, so a unit cannot carry more than 249 bytes of options
// anyway; this is lower than that because the token ends up in a log
// line and in the access record, and a real one -- "Cookie:
// mstshash=" and a user name -- is a fraction of it.
const maxCookie = 128

// ParseConnectionRequest reads the X.224 connection request inside a
// slow path PDU's payload.
func ParseConnectionRequest(body []byte) (ConnectionRequest, error) {
	var cr ConnectionRequest
	if len(body) < 7 {
		return cr, fmt.Errorf("%w: connection request of %d bytes", ErrFraming, len(body))
	}
	if body[1] != x224CR {
		return cr, fmt.Errorf("%w: x.224 type %#02x is not a connection request", ErrFraming, body[1])
	}
	// Past the fixed header: destination and source references, the
	// class, then whatever the client added.
	rest, err := x224Options(body)
	if err != nil {
		return cr, err
	}
	if i := bytes.Index(rest, []byte("\r\n")); i >= 0 {
		if i > maxCookie {
			return cr, fmt.Errorf("%w: routing token of %d bytes", ErrFraming, i)
		}
		cr.Cookie = string(rest[:i])
		rest = rest[i+2:]
	}
	if len(rest) == 0 {
		return cr, nil
	}
	if len(rest) < 8 || rest[0] != negTypeRequest {
		// Anything else here is not a negotiation, and a connection
		// with no negotiation is the legacy protocol.
		return cr, nil
	}
	if n := binary.LittleEndian.Uint16(rest[2:4]); n != 8 {
		return cr, fmt.Errorf("%w: negotiation request says %d bytes, not 8", ErrFraming, n)
	}
	cr.HasNegotiation = true
	cr.Flags = rest[1]
	cr.Protocols = binary.LittleEndian.Uint32(rest[4:8])
	return cr, nil
}

// Encode renders a connection request, which is what the gateway sends
// towards a target.
func (cr ConnectionRequest) Encode() ([]byte, error) {
	var opt []byte
	if cr.Cookie != "" {
		if len(cr.Cookie) > maxCookie {
			return nil, fmt.Errorf("%w: routing token of %d bytes", ErrFraming, len(cr.Cookie))
		}
		opt = append(append([]byte(cr.Cookie), '\r'), '\n')
	}
	if cr.HasNegotiation {
		neg := []byte{negTypeRequest, cr.Flags, 0x08, 0x00, 0, 0, 0, 0}
		binary.LittleEndian.PutUint32(neg[4:8], cr.Protocols)
		opt = append(opt, neg...)
	}
	// Length indicator, type, destination, source, class, then the
	// options.
	head := []byte{byte(6 + len(opt)), x224CR, 0, 0, 0, 0, 0}
	if 6+len(opt) > 0xFF {
		return nil, fmt.Errorf("%w: connection request of %d bytes", ErrFraming, 6+len(opt))
	}
	return TPKT(append(head, opt...))
}

// ConnectionConfirm is the server's answer: the protocol it picked, or
// why it refused.
type ConnectionConfirm struct {
	Protocol uint32
	Flags    uint8
	// Failure is non-zero when the server refused, and then Protocol
	// means nothing.
	Failure uint32
	// HasNegotiation is false for a server that answered without one,
	// which means the legacy protocol.
	HasNegotiation bool
}

// ParseConnectionConfirm reads the answer.
func ParseConnectionConfirm(body []byte) (ConnectionConfirm, error) {
	var cc ConnectionConfirm
	if len(body) < 7 {
		return cc, fmt.Errorf("%w: connection confirm of %d bytes", ErrFraming, len(body))
	}
	if body[1] != x224CC {
		return cc, fmt.Errorf("%w: x.224 type %#02x is not a connection confirm", ErrFraming, body[1])
	}
	rest, err := x224Options(body)
	if err != nil {
		return cc, err
	}
	if len(rest) < 8 {
		return cc, nil
	}
	switch rest[0] {
	case negTypeResonse:
		cc.HasNegotiation = true
		cc.Flags = rest[1]
		cc.Protocol = binary.LittleEndian.Uint32(rest[4:8])
	case negTypeFailure:
		cc.HasNegotiation = true
		cc.Failure = binary.LittleEndian.Uint32(rest[4:8])
	}
	return cc, nil
}

// Encode renders the answer, which is what the gateway sends a client.
func (cc ConnectionConfirm) Encode() ([]byte, error) {
	var opt []byte
	if cc.HasNegotiation {
		typ, value := byte(negTypeResonse), cc.Protocol
		if cc.Failure != 0 {
			typ, value = negTypeFailure, cc.Failure
		}
		opt = []byte{typ, cc.Flags, 0x08, 0x00, 0, 0, 0, 0}
		binary.LittleEndian.PutUint32(opt[4:8], value)
	}
	head := []byte{byte(6 + len(opt)), x224CC, 0, 0, 0x12, 0x34, 0}
	return TPKT(append(head, opt...))
}
