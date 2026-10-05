package radius

import (
	"errors"
	"testing"
)

// eapPacket renders an EAP packet with its length field filled in.
func eapPacket(code EAPCode, id uint8, typ EAPType, data ...byte) []byte {
	b := []byte{byte(code), id, 0, 0, byte(typ)}
	b = append(b, data...)
	b[2], b[3] = byte(len(b)>>8), byte(len(b))
	return b
}

// eapAttrs splits an EAP packet across EAP-Message attributes of at most
// n octets each, which is what a NAS does with anything longer than 253.
func eapAttrs(eap []byte, n int) [][]byte {
	var out [][]byte
	for len(eap) > 0 {
		k := min(n, len(eap))
		out = append(out, attr(AttrEAPMessage, eap[:k]...))
		eap = eap[k:]
	}
	return out
}

func TestEAPIsReassembledAcrossItsAttributes(t *testing.T) {
	t.Parallel()
	// A PEAP exchange's TLS flight is routinely longer than one
	// attribute. A reader that read only the first would be reading 253
	// octets of a handshake and calling that the method.
	eap := eapPacket(EAPResponse, 5, EAPTypePEAP, make([]byte, 600)...)
	attrs := eapAttrs(eap, 253)
	if len(attrs) != 3 {
		t.Fatalf("the test's own split made %d attributes, want 3", len(attrs))
	}
	p := mustParse(t, packet(CodeAccessRequest, 1, auth16(1), attrs...))
	e, err := p.EAP()
	if err != nil {
		t.Fatalf("EAP: %v", err)
	}
	if e.Type != EAPTypePEAP {
		t.Errorf("type = %v, want peap", e.Type)
	}
	if e.Fragments != 3 {
		t.Errorf("fragments = %d, want 3", e.Fragments)
	}
	if e.Length != len(eap) || e.Bytes != len(eap) {
		t.Errorf("length = %d, bytes = %d, want %d for both", e.Length, e.Bytes, len(eap))
	}
	if !e.Type.Tunnelled() {
		t.Error("peap is not reported as tunnelled")
	}
}

func TestTheEAPLengthFieldDecidesWhereThePacketEnds(t *testing.T) {
	t.Parallel()
	t.Run("octets past the length field are padding", func(t *testing.T) {
		t.Parallel()
		eap := eapPacket(EAPResponse, 1, EAPTypeIdentity, []byte("bob")...)
		// A second identity appended after the length says it ended. A
		// reader that went to the end of the reassembly would report the
		// wrong identity.
		eap = append(eap, []byte("@evil.example")...)
		p := mustParse(t, packet(CodeAccessRequest, 1, auth16(1), eapAttrs(eap, 253)...))
		e, err := p.EAP()
		if err != nil {
			t.Fatalf("EAP: %v", err)
		}
		if e.Identity != "bob" {
			t.Fatalf("identity = %q, want bob: the padding was read", e.Identity)
		}
		if e.Bytes == e.Length {
			t.Error("the test did not actually pad the packet")
		}
	})
	t.Run("a length past what arrived is refused", func(t *testing.T) {
		t.Parallel()
		eap := eapPacket(EAPResponse, 1, EAPTypeIdentity, 'b')
		eap[3] += 4
		p := mustParse(t, packet(CodeAccessRequest, 1, auth16(1), eapAttrs(eap, 253)...))
		if _, err := p.EAP(); !errors.Is(err, ErrEAPLength) {
			t.Fatalf("err = %v, want ErrEAPLength", err)
		}
	})
	t.Run("a length below a header is refused", func(t *testing.T) {
		t.Parallel()
		p := mustParse(t, packet(CodeAccessRequest, 1, auth16(1),
			attr(AttrEAPMessage, 2, 1, 0, 3, 1)))
		if _, err := p.EAP(); !errors.Is(err, ErrEAPLength) {
			t.Fatalf("err = %v, want ErrEAPLength", err)
		}
	})
	t.Run("shorter than a header is refused", func(t *testing.T) {
		t.Parallel()
		p := mustParse(t, packet(CodeAccessRequest, 1, auth16(1), attr(AttrEAPMessage, 2, 1, 0)))
		if _, err := p.EAP(); !errors.Is(err, ErrEAPShort) {
			t.Fatalf("err = %v, want ErrEAPShort", err)
		}
	})
	t.Run("no attribute at all is told apart from a bad one", func(t *testing.T) {
		t.Parallel()
		p := mustParse(t, packet(CodeAccessRequest, 1, auth16(1)))
		if _, err := p.EAP(); !errors.Is(err, ErrEAPNone) {
			t.Fatalf("err = %v, want ErrEAPNone", err)
		}
	})
}

func TestASuccessCarriesNoType(t *testing.T) {
	t.Parallel()
	p := mustParse(t, packet(CodeAccessAccept, 1, auth16(1),
		attr(AttrEAPMessage, byte(EAPSuccess), 7, 0, 4)))
	e, err := p.EAP()
	if err != nil {
		t.Fatalf("EAP: %v", err)
	}
	if e.HasType {
		t.Error("a four-octet Success was given a type")
	}
	if e.Method() != "success" {
		t.Errorf("method = %q, want success", e.Method())
	}
}

func TestANakSaysWhichMethodsTheClientWill(t *testing.T) {
	t.Parallel()
	t.Run("the offered methods are read in order", func(t *testing.T) {
		t.Parallel()
		p := mustParse(t, packet(CodeAccessRequest, 1, auth16(1),
			eapAttrs(eapPacket(EAPResponse, 2, EAPTypeNak,
				byte(EAPTypePEAP), byte(EAPTypeMD5Challenge)), 253)...))
		e, err := p.EAP()
		if err != nil {
			t.Fatalf("EAP: %v", err)
		}
		if len(e.NakTypes) != 2 || e.NakTypes[0] != EAPTypePEAP ||
			e.NakTypes[1] != EAPTypeMD5Challenge {
			t.Fatalf("nak types = %v", e.NakTypes)
		}
	})
	t.Run("a nak with no octets at all is refused", func(t *testing.T) {
		t.Parallel()
		// RFC 3748 §5.3.1 requires at least one desired type, where 0
		// means "none acceptable". An empty list is neither, and it is
		// the shape of a client getting a reader to conclude that no weak
		// method was offered.
		p := mustParse(t, packet(CodeAccessRequest, 1, auth16(1),
			eapAttrs(eapPacket(EAPResponse, 2, EAPTypeNak), 253)...))
		if _, err := p.EAP(); !errors.Is(err, ErrEAPEmptyNak) {
			t.Fatalf("err = %v, want ErrEAPEmptyNak", err)
		}
	})
}

func TestAnIdentityWithAControlCharacterIsRefused(t *testing.T) {
	t.Parallel()
	p := mustParse(t, packet(CodeAccessRequest, 1, auth16(1),
		eapAttrs(eapPacket(EAPResponse, 1, EAPTypeIdentity, 'b', '\n', 'o'), 253)...))
	if _, err := p.EAP(); !errors.Is(err, ErrEAPBadText) {
		t.Fatalf("err = %v, want ErrEAPBadText", err)
	}
}

func TestAnExpandedTypeIsReadOrRefused(t *testing.T) {
	t.Parallel()
	t.Run("the vendor and number are read", func(t *testing.T) {
		t.Parallel()
		p := mustParse(t, packet(CodeAccessRequest, 1, auth16(1),
			eapAttrs(eapPacket(EAPResponse, 1, EAPTypeExpanded,
				0x00, 0x37, 0x2a, 0x00, 0x00, 0x00, 0x01), 253)...))
		e, err := p.EAP()
		if err != nil {
			t.Fatalf("EAP: %v", err)
		}
		if e.Vendor != 0x372a || e.VendorType != 1 {
			t.Fatalf("vendor = %#x, type = %d", e.Vendor, e.VendorType)
		}
		if e.Method() == "" {
			t.Error("an expanded type rendered as nothing")
		}
	})
	t.Run("one shorter than its vendor fields is refused", func(t *testing.T) {
		t.Parallel()
		p := mustParse(t, packet(CodeAccessRequest, 1, auth16(1),
			eapAttrs(eapPacket(EAPResponse, 1, EAPTypeExpanded, 0, 0, 1), 253)...))
		if _, err := p.EAP(); !errors.Is(err, ErrEAPExpanded) {
			t.Fatalf("err = %v, want ErrEAPExpanded", err)
		}
	})
}

func TestTheWeakMethodsAreTheOnesNamed(t *testing.T) {
	t.Parallel()
	for _, n := range WeakEAPTypes() {
		tp, ok := EAPTypeOf(n)
		if !ok {
			t.Fatalf("EAPTypeOf(%q) did not read it", n)
		}
		if !tp.Weak() {
			t.Errorf("%q is listed as weak and does not report weak", n)
		}
	}
	for _, strong := range []EAPType{EAPTypeTLS, EAPTypePEAP, EAPTypeTTLS,
		EAPTypeMSCHAPv2, EAPTypeTEAP} {
		if strong.Weak() {
			t.Errorf("%v reports weak", strong)
		}
	}
	for _, n := range EAPTypeNames() {
		if _, ok := EAPTypeOf(n); !ok {
			t.Errorf("EAPTypeOf(%q) did not read it back", n)
		}
	}
	// The spellings an operator writes, and a number for a method this
	// package has no name for.
	for _, spelling := range []string{"md5", "eap-tls", "MSCHAPv2", "ms-chapv2"} {
		if _, ok := EAPTypeOf(spelling); !ok {
			t.Errorf("EAPTypeOf(%q) was not accepted", spelling)
		}
	}
	if tp, ok := EAPTypeOf("99"); !ok || tp != 99 {
		t.Errorf(`EAPTypeOf("99") = (%v, %v)`, tp, ok)
	}
	if _, ok := EAPTypeOf("nonsense"); ok {
		t.Error("a nonsense method name was accepted")
	}
}

func TestAReassemblyLargerThanAPacketIsRefused(t *testing.T) {
	t.Parallel()
	// The bound is not reachable through Parse -- a 4096-octet packet
	// cannot hold more EAP than that -- so it is exercised by building the
	// attribute list directly, which is what proves the check is there
	// rather than implied by the packet length.
	p := &Packet{Code: CodeAccessRequest}
	for i := 0; i < 16; i++ {
		p.Attrs = append(p.Attrs, Attr{Type: AttrEAPMessage, Value: make([]byte, 253)})
	}
	if _, err := p.EAP(); errors.Is(err, ErrEAPTooLarge) {
		t.Fatalf("4048 octets are within the bound, and were refused by it")
	}
	p.Attrs = append(p.Attrs, Attr{Type: AttrEAPMessage, Value: make([]byte, 253)})
	if _, err := p.EAP(); !errors.Is(err, ErrEAPTooLarge) {
		t.Fatalf("err = %v, want ErrEAPTooLarge", err)
	}
}
