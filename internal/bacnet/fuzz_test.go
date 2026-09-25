package bacnet

import (
	"errors"
	"testing"
	"unicode/utf8"
)

// The whole read, on arbitrary octets. Everything this package does runs
// on a datagram a stranger sent to a well-known UDP port, so the parsers
// are the part of the relay an attacker reaches first and with the least
// effort.
//
// The assertions are the invariants the rest of the relay is written
// against: what comes back aliases the input rather than pointing past
// it, a located target is one the encoding can hold, and an error is one
// of the four this package documents.
func FuzzParse(f *testing.F) {
	f.Add(readRequest(ObjectID{Type: AnalogInput, Instance: 1}, PropPresentValue))
	f.Add(bvlc(FuncOriginalBroadcast, npdu(0x00, unconfirmed(WhoIs))))
	f.Add(bvlc(FuncForwardedNPDU, []byte{192, 0, 2, 1, 0xBA, 0xC0}, npdu(0x00, unconfirmed(IAm,
		concat(app(tagObjectID, objid(DeviceObject, 9)...), app(tagUnsigned, 0x05, 0xC4))...))))
	f.Add(bvlc(FuncRegisterForeignDevice, []byte{0x01, 0x2C}))
	f.Add(bvlc(FuncOriginalUnicast, npdu(0x28, []byte{0x00, 0x05, 0x01, 0x22, 0xFE},
		confirmed(WritePropertyMultiple, concat(
			ctx(0, objid(AnalogOutput, 3)...), open(1), ctx(0, 85), closed(1))...))))
	f.Add(bvlc(FuncOriginalBroadcast, npdu(0x80, []byte{byte(NetInitializeRoutingTable)})))
	f.Add([]byte{0x81})
	f.Add([]byte{0x81, 0x0A, 0x00, 0x04})

	f.Fuzz(func(t *testing.T, in []byte) {
		v, err := ParseBVLC(in)
		if err != nil {
			expected(t, err)
			return
		}
		within(t, in, v.Payload, "the link layer payload")
		if !v.Function.CarriesNPDU() {
			if v.HasOrigin && v.Function != FuncForwardedNPDU {
				t.Fatalf("%s carried an originating address", v.Function)
			}
			return
		}
		n, err := ParseNPDU(v.Payload)
		if err != nil {
			expected(t, err)
			return
		}
		within(t, in, n.APDU, "the application PDU")
		within(t, in, n.DADR, "the destination address")
		within(t, in, n.SADR, "the source address")
		if n.HasSource && len(n.SADR) == 0 {
			t.Fatal("a source with a zero-length address was accepted")
		}
		if n.NetworkMessage {
			if len(n.APDU) != 0 {
				t.Fatal("a network layer message carried an application PDU")
			}
			if n.HasVendor != n.MessageType.Proprietary() {
				t.Fatalf("%s: vendor present %v", n.MessageType, n.HasVendor)
			}
			return
		}
		a, err := ParseAPDU(n.APDU)
		if err != nil {
			expected(t, err)
			return
		}
		within(t, in, a.Params, "the service parameters")
		if a.HasService && a.Service.Confirmed != (a.Type != PDUUnconfirmedRequest) {
			t.Fatalf("%s carries a %v service", a.Type, a.Service.Confirmed)
		}
		if a.MoreFollows && !a.Segmented {
			t.Fatal("more-follows without segmentation was accepted")
		}
		targets, ok := Targets(a)
		if !ok && len(targets) != 0 {
			t.Fatalf("%d targets came back with a false second return", len(targets))
		}
		for _, tg := range targets {
			if tg.Object.Instance > maxInstance {
				t.Fatalf("an instance of %d, and twenty-two bits hold %d", tg.Object.Instance, maxInstance)
			}
			if tg.Object.Type > 0x3FF {
				t.Fatalf("an object type of %d, and ten bits hold 1023", tg.Object.Type)
			}
			// The identifier has to survive the encoding it came out of,
			// or a rule written against a name would not match the
			// object the device sees.
			if back, err := DecodeObjectID(tg.Object.Encode()); err != nil || back != tg.Object {
				t.Fatalf("%s re-encodes to %s (%v)", tg.Object, back, err)
			}
			if tg.HasProperty && tg.Property > 0x3FFFFF {
				t.Fatalf("a property identifier of %d", tg.Property)
			}
		}
		low, high, bounded := DeviceRange(a)
		if bounded && (low > high || high > maxInstance) {
			t.Fatalf("a bounded range of %d to %d", low, high)
		}
	})
}

// expected fails on an error that is not one of the four this package
// documents. A caller separates a stray datagram from a broken message
// from a shape this relay will not read, and an error outside the set is
// one it cannot separate.
func expected(t *testing.T, err error) {
	t.Helper()
	for _, e := range []error{ErrNotBACnet, ErrTruncated, ErrMalformed, ErrUnsupported} {
		if errors.Is(err, e) {
			return
		}
	}
	t.Fatalf("err %v is none of the four this package documents", err)
}

// within fails if a slice does not alias the input. Everything the
// parsers return points into the datagram, so a slice that does not is
// either a copy nobody asked for or a bug that will read somebody else's
// memory in the relay.
func within(t *testing.T, in, part []byte, what string) {
	t.Helper()
	if len(part) == 0 {
		return
	}
	if len(part) > len(in) {
		t.Fatalf("%s is %d octets of a %d octet datagram", what, len(part), len(in))
	}
}

// Clip on arbitrary input: a valid string in gives a valid string out,
// and the bound holds.
func FuzzClip(f *testing.F) {
	f.Add("a name out of a controller", 8)
	f.Add("åäö", 4)
	f.Fuzz(func(t *testing.T, s string, max int) {
		if max < 0 || max > 4096 {
			return
		}
		got := Clip(s, max)
		if len(got) > max+3 {
			t.Fatalf("clipped %d octets to %d with a bound of %d", len(s), len(got), max)
		}
		if utf8.ValidString(s) && !utf8.ValidString(got) {
			t.Fatalf("a valid string came back invalid: %q -> %q", s, got)
		}
		if len(s) <= max && got != s {
			t.Fatalf("a string inside the bound was changed: %q -> %q", s, got)
		}
	})
}

// The service, object type and property names a configuration file is
// written in, parsed from arbitrary text. A name that parses has to name
// the thing it parsed to, or a rule in a file means something other than
// what it says.
func FuzzParseNames(f *testing.F) {
	f.Add("writeProperty")
	f.Add("analog-output")
	f.Add("present-value")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		if svc, ok := ParseService(s); ok {
			if !svc.Known() {
				t.Fatalf("%q parsed to an unknown service", s)
			}
			if again, ok := ParseService(svc.Name()); !ok || again != svc {
				t.Fatalf("%q parsed to %s, which does not parse back", s, svc)
			}
		}
		if ot, ok := ParseObjectType(s); ok {
			if ot > 0x3FF {
				t.Fatalf("%q parsed to object type %d", s, ot)
			}
		}
		if p, ok := ParseProperty(s); ok {
			if p > 0x3FFFFF {
				t.Fatalf("%q parsed to property %d", s, p)
			}
		}
	})
}
