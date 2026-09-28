// Package ntske implements NTS key establishment: the record layer of RFC 8915
// section 4, the key derivation of section 5.1, and a cookie format for the
// keys it produces.
//
// NTS has two halves on two ports and they are different things. The time
// exchanges are UDP 123, with authentication in extension fields. The key
// establishment is TLS on TCP 4460 with the ALPN "ntske/1": the client
// authenticates the server, both derive the NTS keys from the TLS exporter, and
// the server hands back cookies that the time exchanges then spend. It happens
// rarely -- once, and again when the cookies run low -- and it is where all the
// cryptography is.
//
// This package is the part that can be stated without reference to a listener:
// the records, the derivation, and the cookie. Terminating NTS needs all three
// to be right at once, and getting any of them wrong would mean telling clients
// their time was authenticated when nobody had checked -- so each is separately
// testable, and the derivation is tested against the vector RFC 8915 does not
// give by deriving both directions and requiring them to differ, to be the
// right length, and to depend on every input the standard says they depend on.
package ntske

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Record types, from RFC 8915 s4.1.
const (
	RecEndOfMessage  uint16 = 0
	RecNextProtocol  uint16 = 1
	RecError         uint16 = 2
	RecWarning       uint16 = 3
	RecAEADAlgorithm uint16 = 4
	RecNewCookie     uint16 = 5
	RecServer        uint16 = 6
	RecPort          uint16 = 7
)

// NextProtoNTPv4 is the only next protocol this understands, and the only one
// the standard defines.
const NextProtoNTPv4 uint16 = 0

// AEADAESSIVCMAC256 is AEAD_AES_SIV_CMAC_256, number 15 in the IANA AEAD
// registry. RFC 8915 s5.1 requires every implementation to support it, and it
// is the only one this offers: a negotiation that accepted an algorithm this
// relay could not actually seal a cookie with would be a negotiation that
// agreed to nothing.
const AEADAESSIVCMAC256 uint16 = 15

// Error codes, RFC 8915 s4.1.3.
const (
	ErrUnrecognisedCritical uint16 = 0
	ErrBadRequest           uint16 = 1
	ErrInternalServer       uint16 = 2
)

// Bounds. A key establishment message is small and arrives before anything is
// known about the sender, so both are bounded.
const (
	// MaxMessage bounds one whole key establishment message.
	MaxMessage = 16 << 10
	// MaxRecordBody bounds one record's body.
	MaxRecordBody = 4 << 10
	// MaxRecords bounds how many records one message may carry, because a
	// message of ten thousand empty records is a message that costs more to
	// read than to send.
	MaxRecords = 64
	// MaxCookies bounds how many cookies this will take from one answer,
	// because a server that sent ten thousand would be spending this relay's
	// memory rather than answering it.
	MaxCookies = 32
)

// Errors this package returns.
var (
	// ErrTruncated is a message that ends inside a record.
	ErrTruncated = errors.New("ntske: message ends inside a record")
	// ErrTooLong is a record or a message past its bound.
	ErrTooLong = errors.New("ntske: past the bound")
	// ErrNoEnd is a message with no End of Message record, which is a message
	// that may not be finished: acting on it would be acting on half a request.
	ErrNoEnd = errors.New("ntske: no end of message record")
	// ErrCritical is a critical record this implementation does not know. The
	// standard requires it to be refused rather than ignored, which is the
	// whole point of the bit.
	ErrCritical = errors.New("ntske: unrecognised critical record")
	// ErrRequest is a request that is well formed as records and wrong as a
	// request, which is the distinction the error record makes: code 1 rather
	// than code 0.
	ErrRequest = errors.New("ntske: bad request")
)

// Record is one record of the key establishment message.
type Record struct {
	// Critical is the high bit of the type field. A receiver that does not
	// understand the type must refuse the message rather than skip the record.
	Critical bool
	Type     uint16
	Body     []byte
}

// AppendTo encodes the record.
func (r Record) AppendTo(dst []byte) []byte {
	t := r.Type & 0x7fff
	if r.Critical {
		t |= 0x8000
	}
	dst = binary.BigEndian.AppendUint16(dst, t)
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(r.Body))) //nolint:gosec // bounded by the caller
	return append(dst, r.Body...)
}

// ParseRecords reads a whole key establishment message.
//
// It requires the End of Message record. A message without one is not a short
// message to be acted on as far as it goes: the sender may still be writing, and
// a server that answered half a negotiation would be agreeing to terms nobody
// finished proposing.
func ParseRecords(b []byte) ([]Record, error) {
	if len(b) > MaxMessage {
		return nil, ErrTooLong
	}
	var out []Record
	for len(b) > 0 {
		if len(out) >= MaxRecords {
			return nil, ErrTooLong
		}
		if len(b) < 4 {
			return nil, ErrTruncated
		}
		t := binary.BigEndian.Uint16(b)
		n := int(binary.BigEndian.Uint16(b[2:]))
		if n > MaxRecordBody {
			return nil, ErrTooLong
		}
		if len(b) < 4+n {
			return nil, ErrTruncated
		}
		r := Record{Critical: t&0x8000 != 0, Type: t & 0x7fff, Body: b[4 : 4+n]}
		out = append(out, r)
		b = b[4+n:]
		if r.Type == RecEndOfMessage {
			if len(b) != 0 {
				// Octets after the end are not a second message on this
				// connection: the record says the message ended, so anything
				// following it is something a reader and a writer would
				// disagree about.
				return nil, ErrTooLong
			}
			return out, nil
		}
	}
	return nil, ErrNoEnd
}

// uint16s reads a body that is a sequence of 16-bit numbers, which is what the
// two negotiation records carry.
func uint16s(body []byte) ([]uint16, error) {
	if len(body)%2 != 0 {
		return nil, fmt.Errorf("%w: a list of 16-bit numbers is %d octets", ErrTruncated, len(body))
	}
	out := make([]uint16, 0, len(body)/2)
	for i := 0; i < len(body); i += 2 {
		out = append(out, binary.BigEndian.Uint16(body[i:]))
	}
	return out, nil
}

// uint16List encodes such a list.
func uint16List(vs ...uint16) []byte {
	var out []byte
	for _, v := range vs {
		out = binary.BigEndian.AppendUint16(out, v)
	}
	return out
}

// Request is what a client asks for.
type Request struct {
	// NextProtocols and AEADs are what the client offers, in its order of
	// preference.
	NextProtocols []uint16
	AEADs         []uint16
	// Server and Port are the time server the client asks to be told about.
	// Both are optional and neither obliges the server.
	Server  string
	Port    uint16
	HasPort bool
}

// ParseRequest reads a client's key establishment request.
//
// A record this does not know is refused when it is critical and ignored when
// it is not, which is the standard's own rule and the reason the bit exists: an
// extension a server does not understand must not be silently dropped when the
// client said it mattered.
func ParseRequest(b []byte) (*Request, error) {
	recs, err := ParseRecords(b)
	if err != nil {
		return nil, err
	}
	q := &Request{}
	for _, r := range recs {
		switch r.Type {
		case RecEndOfMessage:
		case RecNextProtocol:
			if q.NextProtocols, err = uint16s(r.Body); err != nil {
				return nil, err
			}
		case RecAEADAlgorithm:
			if q.AEADs, err = uint16s(r.Body); err != nil {
				return nil, err
			}
		case RecServer:
			q.Server = string(r.Body)
		case RecPort:
			if len(r.Body) != 2 {
				return nil, fmt.Errorf("%w: a port is two octets", ErrTruncated)
			}
			q.Port, q.HasPort = binary.BigEndian.Uint16(r.Body), true
		case RecError, RecWarning, RecNewCookie:
			// A client does not send these. Not refused, because the standard
			// does not say to, and a server that refused a stray warning would
			// be refusing the whole exchange over nothing.
		default:
			if r.Critical {
				return nil, fmt.Errorf("%w: type %d", ErrCritical, r.Type)
			}
		}
	}
	if len(q.NextProtocols) == 0 {
		return nil, fmt.Errorf("%w: no next protocol offered", ErrRequest)
	}
	if len(q.AEADs) == 0 {
		return nil, fmt.Errorf("%w: no AEAD algorithm offered", ErrRequest)
	}
	return q, nil
}

// Response is what a server answers.
type Response struct {
	NextProtocol uint16
	AEAD         uint16
	Cookies      [][]byte
	// Server and Port tell the client where to spend the cookies, when they
	// are not where it asked.
	Server  string
	Port    uint16
	HasPort bool
}

// AppendTo encodes the response, ending with End of Message.
//
// The order is the standard's: the negotiated protocol and algorithm first, so
// that a client reading in order knows how to interpret the cookies before it
// reaches them.
func (r *Response) AppendTo(dst []byte) []byte {
	dst = Record{Critical: true, Type: RecNextProtocol, Body: uint16List(r.NextProtocol)}.AppendTo(dst)
	dst = Record{Critical: true, Type: RecAEADAlgorithm, Body: uint16List(r.AEAD)}.AppendTo(dst)
	if r.Server != "" {
		dst = Record{Critical: true, Type: RecServer, Body: []byte(r.Server)}.AppendTo(dst)
	}
	if r.HasPort {
		dst = Record{Critical: true, Type: RecPort,
			Body: binary.BigEndian.AppendUint16(nil, r.Port)}.AppendTo(dst)
	}
	for _, c := range r.Cookies {
		dst = Record{Type: RecNewCookie, Body: c}.AppendTo(dst)
	}
	return Record{Critical: true, Type: RecEndOfMessage}.AppendTo(dst)
}

// ErrorMessage is the whole message a server sends instead of a response.
//
// It is critical, because a client that ignored it would wait for cookies that
// are not coming.
func ErrorMessage(code uint16) []byte {
	out := Record{Critical: true, Type: RecError,
		Body: binary.BigEndian.AppendUint16(nil, code)}.AppendTo(nil)
	return Record{Critical: true, Type: RecEndOfMessage}.AppendTo(out)
}

// Negotiate picks the protocol and algorithm from what the client offered.
//
// The client's order is its preference and is honoured, which costs nothing
// here because only one of each is supported: a server that imposed its own
// order would be a server whose behaviour changed when its list grew.
func Negotiate(q *Request) (nextProto, aead uint16, ok bool) {
	found := false
	for _, p := range q.NextProtocols {
		if p == NextProtoNTPv4 {
			nextProto, found = p, true
			break
		}
	}
	if !found {
		return 0, 0, false
	}
	for _, a := range q.AEADs {
		if a == AEADAESSIVCMAC256 {
			return nextProto, a, true
		}
	}
	return 0, 0, false
}

// AppendTo encodes a client's request.
//
// The client half exists because this relay is a client too: terminating a
// client's NTS means holding keys with the time source as well, and getting
// those means asking for them the same way anybody else does.
func (q *Request) AppendTo(dst []byte) []byte {
	dst = Record{Critical: true, Type: RecNextProtocol, Body: uint16List(q.NextProtocols...)}.AppendTo(dst)
	dst = Record{Critical: true, Type: RecAEADAlgorithm, Body: uint16List(q.AEADs...)}.AppendTo(dst)
	if q.Server != "" {
		dst = Record{Type: RecServer, Body: []byte(q.Server)}.AppendTo(dst)
	}
	if q.HasPort {
		dst = Record{Type: RecPort, Body: uint16List(q.Port)}.AppendTo(dst)
	}
	return Record{Critical: true, Type: RecEndOfMessage}.AppendTo(dst)
}

// ClientRequest is what this relay asks a key establishment server for: the one
// protocol and the one algorithm it can actually use.
//
// Offering more than it can do would be dishonest in the direction that
// matters: the server would pick something, and the relay would have agreed to
// an algorithm it cannot seal a cookie with.
func ClientRequest() *Request {
	return &Request{NextProtocols: []uint16{NextProtoNTPv4}, AEADs: []uint16{AEADAESSIVCMAC256}}
}

// KEError is a server that answered with an error record rather than terms.
type KEError struct{ Code uint16 }

func (e *KEError) Error() string {
	switch e.Code {
	case ErrUnrecognisedCritical:
		return "ntske: the server did not recognise a critical record"
	case ErrBadRequest:
		return "ntske: the server called the request bad"
	case ErrInternalServer:
		return "ntske: the server reported an internal error"
	}
	return fmt.Sprintf("ntske: the server answered with error code %d", e.Code)
}

// ParseResponse reads a server's answer to a request.
//
// A response with no cookies is refused even though it is well formed. The
// cookies are the entire point of the exchange: a relay that accepted an empty
// answer would hold keys it could never spend, and would discover that one
// time exchange at a time.
func ParseResponse(b []byte) (*Response, error) {
	recs, err := ParseRecords(b)
	if err != nil {
		return nil, err
	}
	r := &Response{}
	protos, aeads := 0, 0
	for _, rec := range recs {
		switch rec.Type {
		case RecEndOfMessage:
		case RecError:
			if len(rec.Body) != 2 {
				return nil, fmt.Errorf("%w: an error code is two octets", ErrTruncated)
			}
			return nil, &KEError{Code: binary.BigEndian.Uint16(rec.Body)}
		case RecWarning:
			// A warning this implementation does not know is not a refusal, and
			// the standard says to carry on. There are none defined.
		case RecNextProtocol:
			vs, err := uint16s(rec.Body)
			if err != nil {
				return nil, err
			}
			if len(vs) != 1 {
				return nil, fmt.Errorf("%w: the server chose %d protocols", ErrRequest, len(vs))
			}
			r.NextProtocol, protos = vs[0], protos+1
		case RecAEADAlgorithm:
			vs, err := uint16s(rec.Body)
			if err != nil {
				return nil, err
			}
			if len(vs) != 1 {
				return nil, fmt.Errorf("%w: the server chose %d algorithms", ErrRequest, len(vs))
			}
			r.AEAD, aeads = vs[0], aeads+1
		case RecNewCookie:
			if len(rec.Body) == 0 || len(rec.Body) > MaxCookie {
				return nil, fmt.Errorf("%w: a cookie of %d octets", ErrRequest, len(rec.Body))
			}
			if len(r.Cookies) >= MaxCookies {
				return nil, fmt.Errorf("%w: more than %d cookies", ErrRequest, MaxCookies)
			}
			r.Cookies = append(r.Cookies, rec.Body)
		case RecServer:
			r.Server = string(rec.Body)
		case RecPort:
			if len(rec.Body) != 2 {
				return nil, fmt.Errorf("%w: a port is two octets", ErrTruncated)
			}
			r.Port, r.HasPort = binary.BigEndian.Uint16(rec.Body), true
		default:
			if rec.Critical {
				return nil, fmt.Errorf("%w: type %d", ErrCritical, rec.Type)
			}
		}
	}
	switch {
	case protos != 1 || aeads != 1:
		return nil, fmt.Errorf("%w: %d protocol and %d algorithm records", ErrRequest, protos, aeads)
	case r.NextProtocol != NextProtoNTPv4:
		return nil, fmt.Errorf("%w: the server chose protocol %d", ErrRequest, r.NextProtocol)
	case r.AEAD != AEADAESSIVCMAC256:
		return nil, fmt.Errorf("%w: the server chose algorithm %d", ErrRequest, r.AEAD)
	case len(r.Cookies) == 0:
		return nil, fmt.Errorf("%w: no cookies", ErrRequest)
	}
	return r, nil
}
