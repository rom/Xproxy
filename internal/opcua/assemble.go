package opcua

import (
	"encoding/binary"
	"fmt"
)

// An Assembler joins the chunks of one direction of one secure channel into
// messages.
//
// It is per-direction and per-connection, not per-channel, because the chunks of a
// connection arrive in one order on one socket and a channel is renewed within it.
// Several request identifiers may be in flight at once — a Publish sits open while
// Reads come and go — so this keeps a partial message per identifier rather than one
// at a time.
//
// What it will not do is grow without limit. Three bounds apply and each refuses
// rather than trims: the chunks in one message, the octets in one message, and the
// partial messages in flight. The last is the one that is easy to forget, and it is
// the one an attacker reaches for: a peer that opens a thousand request identifiers
// with one intermediate chunk each has sent very little and asked the relay to hold
// a great deal.
type Assembler struct {
	// parts holds the body octets accumulated per request identifier.
	parts map[uint32]*partial
	// max is the number of partial messages in flight, bounded by MaxPartial.
	max int
}

// MaxPartial bounds the part-assembled messages one direction may have open. A
// client with more than this many services in flight is not a client any plant has.
const MaxPartial = 16

type partial struct {
	// body holds the octets joined so far, and is empty when the channel
	// encrypted them.
	body []byte
	// size is the octets accounted for, which is not len(body): under
	// SignAndEncrypt the bound still applies to a body nothing kept.
	size   int
	chunks int
}

// NewAssembler makes an assembler for one direction.
func NewAssembler() *Assembler {
	return &Assembler{parts: make(map[uint32]*partial), max: MaxPartial}
}

// Assembled is a joined message: the chunks' bodies concatenated, with the channel
// it arrived on.
//
// It is not called Message because Message is already the MSG message type, and a
// package where those two names were one letter apart would be a package where the
// wrong one gets used.
type Assembled struct {
	// Type is the message type every chunk carried.
	Type MessageType
	// Channel and Token are from the security header.
	Channel uint32
	Token   uint32
	// RequestID is what the chunks were joined by, and what pairs a response with
	// its request.
	RequestID uint32
	// Chunks is how many chunks it took.
	Chunks int
	// Body is the joined service body: the TypeId and everything after it. It is
	// nil when the channel encrypted it.
	Body []byte
	// Encrypted says the body is ciphertext, which is not an error.
	Encrypted bool
}

// Add offers one chunk to the assembler.
//
// It returns a message when the chunk completed one, nil when more are expected, and
// an error when a bound or a rule was broken. mode says what the channel is doing to
// the body, and is what decides whether the body is joined at all: under
// SignAndEncrypt there is nothing to join, so the chunk's length is accounted for
// and its octets are not kept.
//
// An Abort chunk discards the partial message and returns no message and no error:
// the peer said it was abandoning the request, and honouring that is the point.
func (a *Assembler) Add(c *Chunk, mode MessageSecurityMode) (*Assembled, error) {
	if !c.Type.Secured() {
		return nil, fmt.Errorf("%w: %s is not a secured message", ErrMessageType, c.Type)
	}
	// An OPN chunk carries the asymmetric header and is never chunked in
	// practice; a MSG or CLO carries the symmetric one. Either way the sequence
	// header follows and that is where the request identifier is.
	var channel, token uint32
	var off int
	if c.Type == OpenSecureChannel {
		h, o, err := ParseAsymmetric(c.Body)
		if err != nil {
			return nil, err
		}
		channel, off = h.SecureChannelID, o
	} else {
		h, o, err := ParseSymmetric(c.Body)
		if err != nil {
			return nil, err
		}
		channel, token, off = h.SecureChannelID, h.TokenID, o
	}
	seq, off, err := ParseSequence(c.Raw, off)
	if err != nil {
		return nil, err
	}
	body := c.Raw[off:]

	if c.Chunk == Abort {
		delete(a.parts, seq.RequestID)
		return nil, nil
	}

	p := a.parts[seq.RequestID]
	if p == nil {
		if len(a.parts) >= a.max {
			return nil, fmt.Errorf("%w: %d part-assembled messages", ErrTooLong, len(a.parts))
		}
		p = &partial{}
		// A single final chunk is the common case and needs no table entry: it is
		// only recorded when more are coming, so the ordinary message costs no
		// allocation in the map at all.
		if c.Chunk == Intermediate {
			a.parts[seq.RequestID] = p
		}
	}
	p.chunks++
	if p.chunks > MaxChunks {
		delete(a.parts, seq.RequestID)
		return nil, fmt.Errorf("%w: %d chunks in one message", ErrTooLong, p.chunks)
	}
	if p.size+len(body) > MaxAssembled {
		delete(a.parts, seq.RequestID)
		return nil, fmt.Errorf("%w: %d octets assembled", ErrTooLong, p.size+len(body))
	}
	p.size += len(body)
	// The octets are kept only when there is something to read in them. Under
	// SignAndEncrypt the bound above still applied, because the cost of holding a
	// chunk is the same whether or not a relay can read it.
	if mode.Readable() {
		p.body = append(p.body, body...)
	}

	if c.Chunk == Intermediate {
		return nil, nil
	}
	delete(a.parts, seq.RequestID)
	m := &Assembled{
		Type:      c.Type,
		Channel:   channel,
		Token:     token,
		RequestID: seq.RequestID,
		Chunks:    p.chunks,
		Encrypted: !mode.Readable(),
	}
	if mode.Readable() {
		m.Body = p.body
	}
	return m, nil
}

// Open says how many part-assembled messages are held, which is what a counter
// reports and what a test asserts on.
func (a *Assembler) Open() int { return len(a.parts) }

// Reset drops every partial message, for a connection that closed.
func (a *Assembler) Reset() { a.parts = make(map[uint32]*partial) }

// EncodeError builds an ERR message: the one message this relay composes itself.
//
// A refusal on a UA TCP connection is an ERR and then a close, and composing it is
// worth the few lines because the alternative is closing a connection with no reason
// on the wire — after which the client's own log says "connection reset" and the
// operator has nothing to correlate against this relay's refusal.
func EncodeError(code uint32, reason string) []byte {
	if len(reason) > MaxString {
		reason = reason[:MaxString]
	}
	b := make([]byte, HeaderLen+8+len(reason))
	copy(b, Error[:])
	b[3] = byte(Final)
	putUint32(b[4:], uint32(len(b))) //nolint:gosec // bounded by MaxString above
	putUint32(b[8:], code)
	// A String's length is an Int32, and an empty reason is written as zero
	// rather than as the null -1: the field is present and empty, which is what a
	// server with no explanation sends.
	binary.LittleEndian.PutUint32(b[12:], uint32(len(reason))) //nolint:gosec // bounded above
	copy(b[16:], reason)
	return b
}

// The status codes this relay sends in an ERR, from IEC 62541-6 table 5.
const (
	// StatusBadTCPMessageTypeInvalid is a message type the relay does not read.
	StatusBadTCPMessageTypeInvalid uint32 = 0x807E0000
	// StatusBadTCPMessageTooLarge is a message past a bound.
	StatusBadTCPMessageTooLarge uint32 = 0x80800000
	// StatusBadTCPNotEnoughResources is the relay declining to hold more.
	StatusBadTCPNotEnoughResources uint32 = 0x80810000
	// StatusBadTCPInternalError is a fault in the relay itself.
	StatusBadTCPInternalError uint32 = 0x80820000
	// StatusBadTCPEndpointURLInvalid is an endpoint URL the relay refuses.
	StatusBadTCPEndpointURLInvalid uint32 = 0x80830000
	// StatusBadSecurityChecksFailed is a security rule the peer broke.
	StatusBadSecurityChecksFailed uint32 = 0x80130000
	// StatusBadSecurityPolicyRejected is a policy the relay will not carry.
	StatusBadSecurityPolicyRejected uint32 = 0x80220000
	// StatusBadSecurityModeRejected is a message security mode it will not carry.
	StatusBadSecurityModeRejected uint32 = 0x80210000
	// StatusBadCertificateUseNotAllowed is a certificate used for something it
	// does not permit.
	StatusBadCertificateUseNotAllowed uint32 = 0x80180000
	// StatusBadUserAccessDenied is an identity the relay refuses.
	StatusBadUserAccessDenied uint32 = 0x801F0000
	// StatusBadServiceUnsupported is a service the relay will not carry.
	StatusBadServiceUnsupported uint32 = 0x800B0000
	// StatusBadNotWritable is a write to something this listener holds read-only.
	StatusBadNotWritable uint32 = 0x803B0000
	// StatusBadNodeIdUnknown is a node the relay will not name.
	StatusBadNodeIDUnknown uint32 = 0x80340000
	// StatusBadRequestTooLarge is a request past a bound.
	StatusBadRequestTooLarge uint32 = 0x80B80000
	// StatusBadTooManyOperations is a request naming more operations than the
	// relay will carry.
	StatusBadTooManyOperations uint32 = 0x80100000
)
