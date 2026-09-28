package mms

import "fmt"

// ISO 8327-1 session and ISO 8823 presentation, both of which are here to be
// traversed.
//
// The session layer of the basic combined subset that IEC 61850 uses is four octets
// on a data frame: a GIVE TOKENS SPDU and a DATA TRANSFER SPDU, each with an
// identifier of 1 and a length of 0. Both carry the same identifier and are told
// apart by their order, which is the standard's own arrangement and not something
// this reader can improve on.
//
// The association's own SPDUs — CONNECT, ACCEPT, REFUSE, FINISH, DISCONNECT, ABORT
// — carry parameters in a code/length/value list, and the one that matters is the
// user data, because that is where the presentation layer and then ACSE are.

// The SPDU identifiers (ISO 8327-1 §8).
const (
	SPDUGiveTokens   uint8 = 1
	SPDUDataTransfer uint8 = 1
	SPDUConnect      uint8 = 13
	SPDUAccept       uint8 = 14
	SPDURefuse       uint8 = 12
	SPDUFinish       uint8 = 9
	SPDUDisconnect   uint8 = 10
	SPDUAbort        uint8 = 25
	SPDUNotFinished  uint8 = 8
)

// The session parameter groups and parameters this reader looks for.
const (
	pgiUserData         uint8 = 193
	pgiExtendedUserData uint8 = 194
)

// SPDUName names an identifier for a log line.
func SPDUName(si uint8) string {
	switch si {
	case SPDUDataTransfer:
		return "data_transfer"
	case SPDUConnect:
		return "connect"
	case SPDUAccept:
		return "accept"
	case SPDURefuse:
		return "refuse"
	case SPDUFinish:
		return "finish"
	case SPDUDisconnect:
		return "disconnect"
	case SPDUAbort:
		return "abort"
	case SPDUNotFinished:
		return "not_finished"
	}
	return fmt.Sprintf("spdu(%d)", si)
}

// Session is what one COTP data PDU's payload turned out to be.
type Session struct {
	// Kind is the identifier of the SPDU that decided it: DataTransfer for
	// ordinary traffic, Connect for the association request, and so on.
	Kind uint8
	// UserData is the presentation-layer octets, which is what the next layer
	// reads. It is empty for an SPDU that carries none, such as a bare
	// disconnect.
	UserData []byte
}

// MaxSPDUs bounds how many SPDUs one payload may concatenate. Two is the shape the
// standard uses; the bound is loose enough for an implementation that sends a token
// SPDU of its own and tight enough that a peer cannot make a loop out of it.
const MaxSPDUs = 8

// ParseSession reads one COTP data payload.
//
// A payload is one or more SPDUs, and the concatenation the standard defines for
// data transfer — GIVE TOKENS then DATA TRANSFER, both with a length of zero — is
// what makes a loop necessary here rather than a single read.
func ParseSession(b []byte) (*Session, error) {
	s := &Session{}
	for n := 0; len(b) > 0; n++ {
		if n >= MaxSPDUs {
			return nil, fmt.Errorf("%w: more than %d session units in one payload",
				ErrEncoding, MaxSPDUs)
		}
		if len(b) < 2 {
			return nil, fmt.Errorf("%w: %d octets where an SPDU header must be",
				ErrShort, len(b))
		}
		si, li := b[0], int(b[1])
		if 2+li > len(b) {
			return nil, fmt.Errorf("%w: SPDU %d says %d octets, %d are left",
				ErrShort, si, li, len(b)-2)
		}
		body := b[2 : 2+li]
		b = b[2+li:]
		switch si {
		case SPDUDataTransfer:
			// A zero-length unit with identifier 1 is GIVE TOKENS or DATA
			// TRANSFER; either way what follows it is the next unit or the user
			// data. A non-empty one is a DATA TRANSFER carrying its own payload,
			// which some stacks send.
			s.Kind = SPDUDataTransfer
			if li > 0 {
				s.UserData = body
				return s, nil
			}
			if len(b) >= 2 && b[0] == SPDUDataTransfer && b[1] == 0 {
				// The second half of the canonical pair.
				continue
			}
			s.UserData = b
			return s, nil
		case SPDUConnect, SPDUAccept, SPDURefuse, SPDUFinish, SPDUDisconnect,
			SPDUAbort, SPDUNotFinished:
			s.Kind = si
			ud, err := sessionUserData(body)
			if err != nil {
				return nil, err
			}
			s.UserData = ud
			return s, nil
		default:
			return nil, fmt.Errorf("%w: session unit %d", ErrEncoding, si)
		}
	}
	if s.Kind == 0 {
		return nil, fmt.Errorf("%w: an empty session payload", ErrShort)
	}
	return s, nil
}

// sessionUserData pulls the user data out of a CONNECT or ACCEPT's parameter list.
//
// The list is code, length, value, and a parameter group holds a nested list. Only
// the two user-data groups are looked into, because everything else here — the
// selectors, the version, the token settings — is agreement between the two stacks
// and nothing a relay decides about.
func sessionUserData(b []byte) ([]byte, error) {
	for n := 0; len(b) > 0; n++ {
		if n >= MaxElements {
			return nil, fmt.Errorf("%w: more than %d session parameters",
				ErrEncoding, MaxElements)
		}
		if len(b) < 2 {
			return nil, fmt.Errorf("%w: a session parameter header in %d octets",
				ErrShort, len(b))
		}
		code, li := b[0], int(b[1])
		if 2+li > len(b) {
			return nil, fmt.Errorf("%w: session parameter %d says %d octets, %d are left",
				ErrShort, code, li, len(b)-2)
		}
		if code == pgiUserData || code == pgiExtendedUserData {
			return b[2 : 2+li], nil
		}
		b = b[2+li:]
	}
	// No user data. An association request without it is one this relay has
	// nothing to read, which the caller decides about rather than this reader.
	return nil, nil
}
