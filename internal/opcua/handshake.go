package opcua

import "fmt"

// The bounds on what a Hello may propose. They are not the standard's — the
// standard sets only a floor — they are what this relay will carry.
const (
	// MinBuffer is IEC 62541-6 s7.1.2.3's floor: a peer that proposes a receive
	// buffer under 8192 has proposed something no conforming implementation has
	// to work with.
	MinBuffer = 8192
	// MaxEndpointURL bounds the endpoint URL a Hello names. The standard's own
	// limit is 4096 octets and a URL longer than that must be refused, because
	// it is the field a server echoes.
	MaxEndpointURL = 4096
)

// A Hello is the first thing a client sends: the version it speaks and the four
// sizes it proposes, then the endpoint it means to reach.
//
// The sizes matter to a relay for a reason that is easy to miss. They are a
// negotiation, and the answer is the *minimum* of the two ends' proposals, so a
// relay that passes both directions through unchanged has let the two ends agree
// on a chunk size larger than the relay's own buffer — after which every large
// request is a message the relay has to refuse in the middle. Reading them is what
// lets a listener either lower its own answer or refuse the connection at the point
// where refusing is still cheap.
type HelloBody struct {
	// ProtocolVersion is zero in every version of the standard so far. A peer
	// naming something else is naming a transport this relay has not read.
	ProtocolVersion uint32
	// ReceiveBufferSize and SendBufferSize are the largest chunk this peer will
	// accept and the largest it will send.
	ReceiveBufferSize uint32
	SendBufferSize    uint32
	// MaxMessageSize is the largest assembled message, and zero means the peer
	// sets no limit of its own. Zero is not "nothing": it is the peer declining
	// to bound what it will accept, which is precisely when the relay's bound is
	// the only one there is.
	MaxMessageSize uint32
	// MaxChunkCount bounds the chunks in one message, and zero again means no
	// limit from this peer.
	MaxChunkCount uint32
	// EndpointURL is the opc.tcp:// URL the client believes it is reaching. It
	// is the client's own idea of the address, so behind a relay it names the
	// relay rather than the server, and a server that insists on its own
	// hostname will reject it — which is an interoperability fact a listener
	// documents rather than a fault.
	EndpointURL string
}

// ParseHello reads a Hello body.
func ParseHello(body []byte) (*HelloBody, error) {
	r := &reader{b: body}
	h := &HelloBody{
		ProtocolVersion:   r.uint32(),
		ReceiveBufferSize: r.uint32(),
		SendBufferSize:    r.uint32(),
		MaxMessageSize:    r.uint32(),
		MaxChunkCount:     r.uint32(),
	}
	n, ok := r.length("endpoint url", MaxEndpointURL)
	if ok {
		h.EndpointURL = string(r.bytes(n))
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	return h, nil
}

// Acceptable says whether the sizes a Hello proposes are ones this relay can hold
// to, and names the first that is not.
//
// The receive and send buffers are checked against the floor and the ceiling; the
// message size and chunk count are not, because zero is legal there and a peer's
// own limit being larger than the relay's costs nothing — the relay refuses at its
// own bound, which is what MaxAssembled and MaxChunks are.
func (h *HelloBody) Acceptable() error {
	switch {
	case h.ProtocolVersion != 0:
		return fmt.Errorf("%w: protocol version %d", ErrEncoding, h.ProtocolVersion)
	case h.ReceiveBufferSize < MinBuffer:
		return fmt.Errorf("%w: a receive buffer of %d, under the %d floor",
			ErrEncoding, h.ReceiveBufferSize, MinBuffer)
	case h.SendBufferSize < MinBuffer:
		return fmt.Errorf("%w: a send buffer of %d, under the %d floor",
			ErrEncoding, h.SendBufferSize, MinBuffer)
	case h.ReceiveBufferSize > MaxMessageSize:
		return fmt.Errorf("%w: a receive buffer of %d", ErrTooLong, h.ReceiveBufferSize)
	case h.SendBufferSize > MaxMessageSize:
		return fmt.Errorf("%w: a send buffer of %d", ErrTooLong, h.SendBufferSize)
	}
	return nil
}

// An Acknowledge is the server's answer: the same five numbers, with no endpoint.
// Whatever the client proposed, these are the sizes that hold for the connection.
type AcknowledgeBody struct {
	ProtocolVersion   uint32
	ReceiveBufferSize uint32
	SendBufferSize    uint32
	MaxMessageSize    uint32
	MaxChunkCount     uint32
}

// ParseAcknowledge reads an Acknowledge body.
//
// Trailing octets are refused rather than ignored. An Acknowledge is a fixed twenty
// octets and nothing may follow them, so anything that does is either a peer this
// package has not understood or an attempt to hide a second message inside the
// first — and both are worth a refusal at the point where the connection has not
// yet carried anything.
func ParseAcknowledge(body []byte) (*AcknowledgeBody, error) {
	r := &reader{b: body}
	a := &AcknowledgeBody{
		ProtocolVersion:   r.uint32(),
		ReceiveBufferSize: r.uint32(),
		SendBufferSize:    r.uint32(),
		MaxMessageSize:    r.uint32(),
		MaxChunkCount:     r.uint32(),
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	if r.left() != 0 {
		return nil, fmt.Errorf("%w: %d octets after an acknowledge", ErrSize, r.left())
	}
	return a, nil
}

// An Error ends the connection: a status code and a human-readable reason.
//
// It is the one message where the *reason* is the interesting field, because it is
// free text a server chose and a relay logs. Which is exactly why it is bounded and
// why a listener that logs it should treat it as what it is: a remote peer's
// unvalidated string.
type ErrorBody struct {
	// Code is an OPC UA StatusCode. The high sixteen bits are the severity and
	// the identifier; the low sixteen carry flags that are rarely set here.
	Code uint32
	// Reason is the server's explanation, and may be empty.
	Reason string
}

// ParseError reads an Error body.
func ParseError(body []byte) (*ErrorBody, error) {
	r := &reader{b: body}
	e := &ErrorBody{Code: r.uint32()}
	n, ok := r.length("reason", MaxString)
	if ok {
		e.Reason = string(r.bytes(n))
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	return e, nil
}

// Bad says the status code carries the error severity, which is the top two bits
// set. A code with them clear is a success or an uncertainty, and an ERR message
// carrying one is a peer contradicting itself.
func (e *ErrorBody) Bad() bool { return e.Code&0xC0000000 == 0x80000000 }

// A ReverseHello is the server making the connection: it names itself and the
// endpoint the client should then ask for.
//
// It exists for the case where the server is the one behind a firewall that allows
// no inbound connections — a plant network dialling out to a cloud client. That
// inverts the direction a relay expects, and a listener that does not mean to
// support it should refuse the message rather than pass it: the alternative is a
// connection where the peer that dialled is the one that will be trusted as a
// server.
type ReverseHelloBody struct {
	// ServerURI is the server's application URI, which is also the URI its
	// certificate must carry.
	ServerURI string
	// EndpointURL is where the client should connect back to.
	EndpointURL string
}

// ParseReverseHello reads a ReverseHello body.
func ParseReverseHello(body []byte) (*ReverseHelloBody, error) {
	r := &reader{b: body}
	h := &ReverseHelloBody{}
	if n, ok := r.length("server uri", MaxEndpointURL); ok {
		h.ServerURI = string(r.bytes(n))
	}
	if n, ok := r.length("endpoint url", MaxEndpointURL); ok {
		h.EndpointURL = string(r.bytes(n))
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	return h, nil
}
