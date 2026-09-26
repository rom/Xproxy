package amqp

import (
	"encoding/binary"

	wire "github.com/rom/xproxy/internal/amqpwire"
)

// How this relay says no, in the protocol the client is speaking.
//
// It matters more here than on most kinds, because AMQP is stateful in both
// directions. A refusal that answered one frame and let the connection
// continue would leave the two sides disagreeing about what happened: the
// client would see a channel closed that the broker still has open, or the
// broker would answer a method the client never learned was refused. So a
// refusal ends the connection, with the protocol's own statement of why --
// the same choice the SQL kinds make for a refusal during a handshake, for
// the same reason.
//
// This is the one place in the kind that writes a frame rather than
// forwarding one. That is deliberate and it is bounded: the relay renders
// *its own* messages, never a re-rendering of something a peer sent, because
// a proxy that re-encoded a peer's frame would be a second implementation of
// the encoder whose disagreements with the first are what an attacker is
// looking for.

// maxRefusalText bounds the text a refusal carries.
//
// It is short on purpose. The text is a reason and a detail this relay wrote,
// it goes into a frame whose own length fields are one octet wide in the forms
// used here, and a client library prints it -- so a hundred octets is both
// enough to say what happened and small enough that every length below is
// provably in range.
const maxRefusalText = 100

// accessRefused is AMQP 0-9-1's own reply code for "you may not do that"
// (§4.2.2), and the condition AMQP 1.0 gives the same answer under (§2.8.1).
const (
	accessRefused    = 403
	unauthorizedName = "amqp:unauthorized-access"
)

// closeFrame091 builds a connection.close on channel 0.
//
// The text says xproxy refused it, so nobody spends an afternoon on a broker
// permission that would not have helped, and the class and method fields are
// zero: they name the method that caused a broker's own error, and this is
// not the broker's error.
func closeFrame091(text string) []byte {
	text = clip(text)
	args := make([]byte, 0, 6+len(text))
	args = binary.BigEndian.AppendUint16(args, accessRefused)
	args = appendShortstr(args, text)
	args = binary.BigEndian.AppendUint16(args, 0) // class-id
	args = binary.BigEndian.AppendUint16(args, 0) // method-id
	payload := make([]byte, 0, 4+len(args))
	payload = binary.BigEndian.AppendUint16(payload, wire.ClassConnection)
	payload = binary.BigEndian.AppendUint16(payload, 50) // connection.close
	payload = append(payload, args...)
	return frame091(wire.FrameMethod, 0, payload)
}

// closeFrame10 builds a 1.0 close carrying an error, which is how that
// version says the same thing.
func closeFrame10(description string) []byte {
	description = clip(description)
	// error{condition: symbol, description: string}
	inner := appendSymbol(nil, unauthorizedName)
	inner = appendString(inner, description)
	errBody := described(0x1d, list8(inner, 2))
	body := described(0x18, list8(errBody, 1))
	return frame10(wire.FrameAMQP, 0, body)
}

// saslOutcome10 builds a SASL outcome refusing the exchange, which is how a
// 1.0 connection is turned away before it exists: there is no connection to
// close yet, so a close performative would be a frame about nothing.
func saslOutcome10() []byte {
	// sasl-outcome{code: 1}, which is "auth", the refusal of a credential.
	body := described(0x44, list8([]byte{0x50, 1}, 1))
	return frame10(wire.FrameSASL, 0, body)
}

// preferredHeader is the protocol header this listener answers a refused one
// with.
//
// Both versions say the same thing about this: a peer that does not accept
// the header it was sent replies with a header it does support and closes the
// socket (0-9-1 §4.2.2, 1.0 §2.2). That is more useful than silence -- a
// client library reports "the server speaks 0-9-1" rather than "the
// connection dropped" -- and it discloses nothing an operator has not chosen
// to serve.
func (p *policy) preferredHeader() []byte {
	if p.versions[wire.V091] {
		return []byte{'A', 'M', 'Q', 'P', 0, 0, 9, 1}
	}
	if p.versions[wire.V10] {
		return []byte{'A', 'M', 'Q', 'P', 0, 1, 0, 0}
	}
	return nil
}

// The encoders, kept small and local. Each one appends, so a caller builds a
// frame with no intermediate allocation per field.

// clip bounds a string this file is about to put a one-octet length in front
// of. Every encoder below then has its length in range by construction.
func clip(s string) string {
	if len(s) > maxRefusalText {
		return s[:maxRefusalText]
	}
	return s
}

func appendShortstr(b []byte, s string) []byte {
	s = clip(s)
	b = append(b, uint8(len(s))) //nolint:gosec // clip bounds it to 100
	return append(b, s...)
}

func frame091(typ uint8, channel uint16, payload []byte) []byte {
	out := make([]byte, 0, 8+len(payload))
	out = append(out, typ)
	out = binary.BigEndian.AppendUint16(out, channel)
	out = binary.BigEndian.AppendUint32(out, uint32(len(payload))) //nolint:gosec // the payloads here are a few dozen octets
	out = append(out, payload...)
	return append(out, wire.FrameEnd)
}

func frame10(typ uint8, channel uint16, body []byte) []byte {
	out := make([]byte, 0, 8+len(body))
	out = binary.BigEndian.AppendUint32(out, uint32(8+len(body))) //nolint:gosec // the bodies here are a few dozen octets
	out = append(out, 2, typ)                                     // a data offset of two words: no extended header
	out = binary.BigEndian.AppendUint16(out, channel)
	return append(out, body...)
}

// described wraps a body in a descriptor written as a small unsigned long,
// which is the form every implementation sends.
func described(code uint8, body []byte) []byte {
	out := make([]byte, 0, 3+len(body))
	out = append(out, 0x00, 0x53, code)
	return append(out, body...)
}

// list8 is a list whose size and count fit in an octet each, which every
// frame this file builds does.
func list8(items []byte, count int) []byte {
	if len(items)+1 > 0xff || count > 0xff {
		// Unreachable: every list this file builds holds two clipped
		// strings at most. Saying so beats rendering a length that wrapped.
		return nil
	}
	out := make([]byte, 0, 3+len(items))
	out = append(out, 0xc0, uint8(len(items)+1), uint8(count)) //nolint:gosec // bounded just above
	return append(out, items...)
}

func appendSymbol(b []byte, s string) []byte {
	s = clip(s)
	b = append(b, 0xa3, uint8(len(s))) //nolint:gosec // clip bounds it to 100
	return append(b, s...)
}

func appendString(b []byte, s string) []byte {
	s = clip(s)
	b = append(b, 0xa1, uint8(len(s))) //nolint:gosec // clip bounds it to 100
	return append(b, s...)
}
