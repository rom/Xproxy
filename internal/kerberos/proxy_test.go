package kerberos

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestTheEnvelopeRoundTrips(t *testing.T) {
	t.Parallel()
	cname := user("alice")
	inner := req{typ: MsgASReq, realm: "CORP.EXAMPLE", cname: &cname,
		etypes: []EType{ETypeAES256SHA1}}.build()
	b := MarshalProxyMessage(inner, "CORP.EXAMPLE")
	m, err := ParseProxyMessage(b, 1<<20)
	if err != nil {
		t.Fatalf("ParseProxyMessage: %v", err)
	}
	if !bytes.Equal(m.Inner, inner) {
		t.Fatal("the inner message did not survive the envelope")
	}
	if m.TargetDomain != "CORP.EXAMPLE" {
		t.Errorf("target domain = %q", m.TargetDomain)
	}
	if m.HasHint {
		t.Error("a hint appeared in an envelope that carries none")
	}
	// A reply envelope carries no target domain, which is what MS-KKDCP's
	// own clients send back.
	reply := MarshalProxyMessage(inner, "")
	m, err = ParseProxyMessage(reply, 1<<20)
	if err != nil {
		t.Fatalf("ParseProxyMessage: %v", err)
	}
	if m.TargetDomain != "" {
		t.Errorf("target domain = %q, want none", m.TargetDomain)
	}
	// And the inner message is still readable as Kerberos.
	if _, err := Parse(m.Inner); err != nil {
		t.Fatalf("the unwrapped message did not parse: %v", err)
	}
}

func TestTheLocatorHintIsCarriedAndNotActedOn(t *testing.T) {
	t.Parallel()
	// Built by hand, because this package never writes a hint: a relay
	// that echoed one into a reply would be adding a field the standard
	// does not define one for.
	inner := Frame([]byte{0x6a, 0x00})
	body := derTLV(classContext|constructed, 0, derTLV(classUniversal, tagOctetString, inner))
	body = append(body, ctxString(1, "CORP.EXAMPLE")...)
	body = append(body, ctxInt(2, 0x40000000)...)
	b := derTLV(classUniversal|constructed, tagSequence, body)
	m, err := ParseProxyMessage(b, 1<<20)
	if err != nil {
		t.Fatalf("ParseProxyMessage: %v", err)
	}
	if !m.HasHint || m.Hint != 0x40000000 {
		t.Fatalf("hint = (%d, %v)", m.Hint, m.HasHint)
	}
	// It is not echoed back.
	out := MarshalProxyMessage(m.Inner, m.TargetDomain)
	again, err := ParseProxyMessage(out, 1<<20)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if again.HasHint {
		t.Error("the hint was echoed into the reply")
	}
}

func TestTheInnerLengthPrefixMustSayExactlyWhatIsThere(t *testing.T) {
	t.Parallel()
	msg := []byte{0x6a, 0x03, 0x30, 0x01, 0x00}
	t.Run("a correct prefix", func(t *testing.T) {
		t.Parallel()
		got, err := Unframe(Frame(msg), 1<<20)
		if err != nil {
			t.Fatalf("Unframe: %v", err)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("got %x", got)
		}
	})
	t.Run("a prefix shorter than what follows", func(t *testing.T) {
		t.Parallel()
		// The octets past the prefix are a second message this reader
		// would not have seen and the KDC would. Refused rather than
		// ignored.
		b := Frame(msg)
		binary.BigEndian.PutUint32(b[:4], uint32(len(msg)-1))
		if _, err := Unframe(b, 1<<20); !errors.Is(err, ErrInnerLength) {
			t.Fatalf("err = %v, want ErrInnerLength", err)
		}
	})
	t.Run("a prefix longer than what follows", func(t *testing.T) {
		t.Parallel()
		b := Frame(msg)
		binary.BigEndian.PutUint32(b[:4], uint32(len(msg)+1))
		if _, err := Unframe(b, 1<<20); !errors.Is(err, ErrInnerLength) {
			t.Fatalf("err = %v, want ErrInnerLength", err)
		}
	})
	t.Run("a zero prefix", func(t *testing.T) {
		t.Parallel()
		if _, err := Unframe([]byte{0, 0, 0, 0}, 1<<20); !errors.Is(err, ErrInnerEmpty) {
			t.Fatalf("err = %v, want ErrInnerEmpty", err)
		}
	})
	t.Run("no prefix at all", func(t *testing.T) {
		t.Parallel()
		if _, err := Unframe([]byte{0, 0}, 1<<20); !errors.Is(err, ErrInnerLength) {
			t.Fatalf("err = %v, want ErrInnerLength", err)
		}
	})
	t.Run("a prefix past the listener's bound is refused before the rest is read", func(t *testing.T) {
		t.Parallel()
		// The bound is checked against the prefix, not against what
		// arrived, so a four-gigabyte claim is refused without the reader
		// having to hold four gigabytes.
		b := []byte{0xff, 0xff, 0xff, 0xff, 1, 2, 3}
		if _, err := Unframe(b, 64<<10); !errors.Is(err, ErrInnerTooBig) {
			t.Fatalf("err = %v, want ErrInnerTooBig", err)
		}
		// And a bound of zero means no bound, which is what a caller with
		// no configured limit relies on.
		if _, err := Unframe(Frame([]byte{1, 2}), 0); err != nil {
			t.Fatalf("an unbounded Unframe failed: %v", err)
		}
	})
}

func TestAnEnvelopeWithoutAKerbMessageIsRefused(t *testing.T) {
	t.Parallel()
	only := derTLV(classUniversal|constructed, tagSequence, ctxString(1, "CORP.EXAMPLE"))
	if _, err := ParseProxyMessage(only, 1<<20); !errors.Is(err, ErrNoInner) {
		t.Fatalf("err = %v, want ErrNoInner", err)
	}
	// Not a SEQUENCE at all.
	if _, err := ParseProxyMessage([]byte{0x04, 0x01, 0x00}, 1<<20); !errors.Is(err, ErrNotEnvelope) {
		t.Fatal("an OCTET STRING was accepted as an envelope")
	}
	// kerb-message that is not an OCTET STRING.
	wrong := derTLV(classUniversal|constructed, tagSequence,
		derTLV(classContext|constructed, 0, derInt(5)))
	if _, err := ParseProxyMessage(wrong, 1<<20); !errors.Is(err, ErrTag) {
		t.Fatal("a kerb-message that is not an OCTET STRING was accepted")
	}
	// Octets after the envelope.
	good := MarshalProxyMessage([]byte{0x6a, 0x00}, "")
	if _, err := ParseProxyMessage(append(good, 0x30, 0x00), 1<<20); !errors.Is(err, ErrTrailing) {
		t.Fatal("trailing octets were accepted")
	}
}

func TestAnUnknownEnvelopeFieldIsSkipped(t *testing.T) {
	t.Parallel()
	// The envelope is small and stable, and a reader that refused an
	// extension would refuse traffic from the next client that adds one.
	inner := Frame([]byte{0x6a, 0x00})
	body := derTLV(classContext|constructed, 0, derTLV(classUniversal, tagOctetString, inner))
	body = append(body, derTLV(classContext|constructed, 7, derInt(1))...)
	b := derTLV(classUniversal|constructed, tagSequence, body)
	m, err := ParseProxyMessage(b, 1<<20)
	if err != nil {
		t.Fatalf("ParseProxyMessage: %v", err)
	}
	if len(m.Inner) != 2 {
		t.Fatalf("inner = %x", m.Inner)
	}
}

func TestALongEnvelopeIsLengthedCorrectly(t *testing.T) {
	t.Parallel()
	// The writer's length encoding has four branches and a Windows PAC
	// reaches the third. A wrong branch would produce an envelope the
	// client cannot read, which is a bug no short test would find.
	for _, n := range []int{10, 200, 5000, 70000} {
		msg := make([]byte, n)
		msg[0] = 0x6a
		m, err := ParseProxyMessage(MarshalProxyMessage(msg, "R"), 1<<20)
		if err != nil {
			t.Fatalf("%d octets: %v", n, err)
		}
		if len(m.Inner) != n {
			t.Fatalf("%d octets: got %d back", n, len(m.Inner))
		}
	}
}
