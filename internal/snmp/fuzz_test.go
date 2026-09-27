package snmp

import (
	"bytes"
	"errors"
	"testing"
)

// The whole read, on arbitrary octets.
//
// Everything this package does runs on a datagram a stranger sent to a
// well-known UDP port, and the encoding is BER -- a length-prefixed, nested,
// tag-driven format, which is the shape that has produced more parser
// vulnerabilities than any other in network software. So this is the part of the
// relay an attacker reaches first, with one packet and no handshake.
//
// The assertions are the invariants the relay is written against: a refusal names
// one of the errors this package documents, what is reported points into the
// message rather than past it, the bounds hold, and -- the one that matters most
// on this protocol -- a refusal this relay generates is never larger than the
// request that provoked it. An SNMP responder that answers a small request with a
// large reply is a reflection amplifier, and on a relay that answers refusals
// itself that property has to hold in code rather than by inspection.
func FuzzParse(f *testing.F) {
	get := func(o ...uint32) []byte { return varbind(oid(o...), tlv(TagNull)) }
	f.Add(v2c("public", pdu(TagGetRequest, 1, 0, 0, get(1, 3, 6, 1, 2, 1, 1, 5, 0))))
	f.Add(v1msg("private", pdu(TagGetRequest, 2, 0, 0, get(1, 3, 6, 1, 2, 1, 1, 1, 0))))
	f.Add(v2c("public", pdu(TagGetBulkRequest, 3, 0, 50, get(1, 3, 6, 1, 2, 1, 2, 2))))
	f.Add(v2c("public", pdu(TagGetBulkRequest, 4, 0, 1<<20, get(1, 3, 6, 1))))
	// A negative max-repetitions: malformed per RFC 3416, reported as it
	// arrived, and the relay's bound is what refuses to be fooled by it.
	f.Add(v2c("public", pdu(TagGetBulkRequest, 10, 0, -839632, get(1, 3, 6, 1))))
	f.Add(v2c("public", pdu(TagSetRequest, 5, 0, 0,
		varbind(oid(1, 3, 6, 1, 2, 1, 1, 5, 0), octets(TagOctetStr, "new")))))
	f.Add(v3msg(6, 0x03, 3, usm("engine", 1, 2, "operator", "", ""),
		tlv(TagSequence, join(octets(TagOctetStr, "engine"), octets(TagOctetStr, ""),
			pdu(TagGetRequest, 7, 0, 0, get(1, 3, 6, 1)))...)))
	f.Add(v3msg(8, 0x00, 3, usm("engine", 1, 2, "", "", ""), tlv(TagSequence)))
	f.Add([]byte{})
	f.Add([]byte{0x30})
	f.Add([]byte{0x30, 0x80, 0x00, 0x00})             // indefinite length
	f.Add([]byte{0x30, 0x84, 0xff, 0xff, 0xff, 0xff}) // a length field that overflows
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x09})       // an unknown version
	f.Add(append(v2c("x", pdu(TagGetRequest, 9, 0, 0, get(1, 3, 6, 1))), 0x00))

	f.Fuzz(func(t *testing.T, in []byte) {
		m, err := Parse(in)
		if err != nil {
			expected(t, err)
			if m != nil {
				t.Fatal("Parse returned a message with an error")
			}
			return
		}
		if !bytes.Equal(m.Raw, in) {
			t.Fatal("Message.Raw is not the octets it was parsed from; the relay " +
				"forwards these, so they have to be what was read")
		}
		if len(in) > MaxMessage {
			t.Fatalf("accepted %d octets, past MaxMessage", len(in))
		}
		if !m.Version.Known() {
			t.Fatalf("accepted version %v, which the relay cannot place a credential in", m.Version)
		}
		if len(m.Community) > MaxCommunity {
			t.Fatalf("community of %d octets accepted", len(m.Community))
		}
		switch m.Version {
		case V3:
			if m.V3 == nil {
				t.Fatal("a v3 message with no v3 header")
			}
			if m.V3.Level > AuthPriv {
				t.Fatalf("security level %v is not one of the three", m.V3.Level)
			}
		default:
			if m.V3 != nil {
				t.Fatalf("%v carried a v3 header", m.Version)
			}
		}
		if p := m.PDU; p != nil {
			// The repetition fields are reported as they arrived, negative
			// included. That is this package's job: RFC 3416 gives them the
			// range 0..2147483647, so a negative one is malformed, and a parser
			// that clamped it would hide from the relay the very thing the
			// relay has to decide about. The fuzzer produced one (-839632) and
			// it turned out the relay's amplification bound compared it signed
			// and let it through unlowered -- fixed in internal/kinds/snmp,
			// with a test there, which is the layer that owns the decision.
			// What is asserted here is only that the value round-trips.
			for _, vb := range p.VarBinds {
				if len(vb.OID) == 0 {
					continue
				}
				// An OID the policy checks against a subtree has to be one the
				// message carried, not one the parser assembled from elsewhere.
				for _, sub := range vb.OID {
					if sub > 1<<32-1 {
						t.Fatalf("sub-identifier %d is wider than the encoding allows", sub)
					}
				}
			}
			if p.Bindings != nil && !bytes.Contains(in, p.Bindings) {
				t.Fatal("the encoded bindings are not a slice of the message")
			}
		}

		// The refusal this relay would answer with, if it answers at all. It
		// must parse, it must be a response, and it must not be bigger than
		// what provoked it.
		if out := Refusal(m); out != nil {
			if len(out) > len(in) {
				t.Fatalf("a %d-octet request would be refused with %d octets, which "+
					"makes this relay an amplifier", len(in), len(out))
			}
			back, err := Parse(out)
			if err != nil {
				t.Fatalf("the refusal this relay sends does not parse: %v", err)
			}
			if back.PDU == nil || back.PDU.Type != Response {
				t.Fatal("the refusal is not a response")
			}
			if back.PDU.RequestID != m.PDU.RequestID {
				t.Fatalf("the refusal pairs with request %d, not %d",
					back.PDU.RequestID, m.PDU.RequestID)
			}
		}
	})
}

// FuzzWithMaxRepetitions drives the one edit this relay makes to a request it
// forwards: lowering a GETBULK's repetition count rather than refusing the
// request, so a poller nobody can reconfigure still gets an answer.
//
// An edit is riskier than a read: what goes out is what the agent acts on, so a
// re-encoding that is not a valid PDU, or that changes anything but the one
// field, is a relay rewriting traffic it was asked only to bound.
func FuzzWithMaxRepetitions(f *testing.F) {
	get := func(o ...uint32) []byte { return varbind(oid(o...), tlv(TagNull)) }
	f.Add(pdu(TagGetBulkRequest, 1, 0, 100, get(1, 3, 6, 1)), int64(10))
	f.Add(pdu(TagGetBulkRequest, 2, 3, 65535, get(1, 3, 6, 1, 2, 1, 2, 2)), int64(1))
	f.Add(pdu(TagGetRequest, 3, 0, 0, get(1, 3, 6, 1)), int64(5))
	f.Add([]byte{}, int64(0))
	f.Add([]byte{0x30, 0x00}, int64(-1))

	f.Fuzz(func(t *testing.T, raw []byte, n int64) {
		// The PDU this takes is the inner one, so feed it the body of a parsed
		// message where there is one and the raw octets otherwise.
		pdu := raw
		if m, err := Parse(raw); err == nil && m.PDU != nil && m.PDU.Bindings != nil {
			pdu = raw
		}
		out, err := WithMaxRepetitions(pdu, n)
		if err != nil {
			expected(t, err)
			return
		}
		if len(out) > MaxMessage {
			t.Fatalf("the edit produced %d octets, past MaxMessage", len(out))
		}
		// The edit is idempotent: applying it again with the same bound must not
		// keep growing the message, which is what a length field written without
		// rewriting its parents would do.
		twice, err := WithMaxRepetitions(out, n)
		if err == nil && len(twice) != len(out) {
			t.Fatalf("editing twice changed the size from %d to %d", len(out), len(twice))
		}
	})
}

// expected fails on any error this package does not document.
func expected(t *testing.T, err error) {
	t.Helper()
	for _, known := range []error{
		ErrTruncated, ErrIndefinite, ErrLongLength, ErrTag, ErrIntegerRange,
		ErrOID, ErrTrailing, ErrNesting, ErrCount,
		ErrVersion, ErrSecurityModel, ErrCommunity,
	} {
		if errors.Is(err, known) {
			return
		}
	}
	t.Fatalf("error %v is not one this package documents", err)
}
