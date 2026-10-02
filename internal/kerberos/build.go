package kerberos

import "time"

// Minting a KRB-ERROR, which is the one message a relay has to be able to
// write itself.
//
// A refused request needs an answer in the protocol's own terms. The
// alternative is silence, and silence on this protocol is a client that
// retries, falls back to UDP or TCP on port 88 -- where there is no relay
// -- and then reports a network fault to whoever is sitting at it. A
// KRB-ERROR says no in the only language the client reads, and the error
// text says which proxy refused it, so nobody spends an afternoon on a KDC
// that was never asked.
//
// The code is the relay's choice and KDC_ERR_POLICY is the honest one:
// the request was well formed and the policy refused it. Using
// KDC_ERR_C_PRINCIPAL_UNKNOWN would be a lie the client's own logs would
// then repeat.

// MarshalError builds a KRB-ERROR for a refusal.
//
// stime and susec are required fields, so they are written from the clock
// the caller passes -- which a test pins. realm and sname are required
// too; a refusal that has not read far enough to know the service names
// the realm's ticket-granting service, because that is what the client
// asked for in the only case where the parse failed that early.
func MarshalError(now time.Time, code int32, realm string, sname Principal, text string) []byte {
	var body []byte
	body = append(body, ctxInt(0, pvno)...)
	body = append(body, ctxInt(1, int64(MsgError))...)
	body = append(body, ctxTime(4, now)...)
	body = append(body, ctxInt(5, int64(now.Nanosecond()/1000))...)
	body = append(body, ctxInt(6, int64(code))...)
	body = append(body, ctxString(9, realm)...)
	body = append(body, ctxPrincipal(10, sname)...)
	if text != "" {
		body = append(body, ctxString(11, text)...)
	}
	seq := derTLV(classUniversal|constructed, tagSequence, body)
	return derTLV(classApplication|constructed, uint32(MsgError), seq)
}

// KrbtgtFor is the realm's own ticket-granting service principal, which is
// the service a refusal names when the relay has not read far enough to
// know a better answer.
func KrbtgtFor(realm string) Principal {
	return Principal{Type: NTSrvInst, Parts: []string{"krbtgt", realm}}
}

// ctxInt writes [tag] EXPLICIT INTEGER.
func ctxInt(tag uint32, v int64) []byte {
	return derTLV(classContext|constructed, tag, derInt(v))
}

// ctxString writes [tag] EXPLICIT GeneralString, which is how the
// installed base encodes a KerberosString.
func ctxString(tag uint32, s string) []byte {
	return derTLV(classContext|constructed, tag,
		derTLV(classUniversal, tagGeneralStr, []byte(s)))
}

// ctxTime writes [tag] EXPLICIT GeneralizedTime in the one form RFC 4120
// §5.2.3 allows: UTC, to the second, with no fraction.
func ctxTime(tag uint32, t time.Time) []byte {
	return derTLV(classContext|constructed, tag,
		derTLV(classUniversal, tagGeneralTime, []byte(t.UTC().Format("20060102150405Z"))))
}

// ctxPrincipal writes [tag] EXPLICIT PrincipalName.
func ctxPrincipal(tag uint32, p Principal) []byte {
	var parts []byte
	for _, s := range p.Parts {
		parts = append(parts, derTLV(classUniversal, tagGeneralStr, []byte(s))...)
	}
	body := append(ctxInt(0, int64(p.Type)),
		derTLV(classContext|constructed, 1,
			derTLV(classUniversal|constructed, tagSequence, parts))...)
	return derTLV(classContext|constructed, tag,
		derTLV(classUniversal|constructed, tagSequence, body))
}

// derInt renders an INTEGER in the two's-complement minimal form DER
// requires.
func derInt(v int64) []byte {
	var b []byte
	n := v
	for {
		b = append([]byte{byte(n & 0xff)}, b...)
		n >>= 8
		if n == 0 && b[0]&0x80 == 0 {
			break
		}
		if n == -1 && b[0]&0x80 != 0 {
			break
		}
	}
	return derTLV(classUniversal, tagInteger, b)
}

// ErrorText renders the message a refusal carries, which is read by a
// person at a keyboard: it says which proxy refused, and why, and nothing
// about the estate's internals.
func ErrorText(listener, reason string) string {
	s := "refused by xproxy"
	if listener != "" {
		s += " (" + listener + ")"
	}
	if reason != "" {
		s += ": " + reason
	}
	return s
}
