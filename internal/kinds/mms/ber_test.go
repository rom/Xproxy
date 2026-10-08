package mms

import (
	"bytes"
	"strings"
	"testing"

	wire "github.com/rom/xproxy/internal/mms"
)

// The BER writer this relay refuses with.
//
// A refusal is an MMS message, so it has to be encoded correctly or the IED's
// own library will not read it -- and a refusal nobody can read is a session
// that hangs instead of one that is told no. These are the three pieces that
// decide that: the length form, the integer content, and the narrowing of an
// invoke identifier back onto the wire's own type.

// BER has three length forms under 64 KiB, and the writer has to use the
// shortest one that fits: a decoder is entitled to refuse a length encoded
// longer than it needs, and an IED that refused this relay's refusal would
// leave the client waiting.
func TestTheLengthFormIsTheShortestThatFits(t *testing.T) {
	for _, c := range []struct {
		n    int
		want []byte
	}{
		{0, []byte{0x00}},
		{1, []byte{0x01}},
		{0x7f, []byte{0x7f}},              // the last short form
		{0x80, []byte{0x81, 0x80}},        // one octet of length
		{0xff, []byte{0x81, 0xff}},        // the last of that form
		{0x100, []byte{0x82, 0x01, 0x00}}, // two octets
		{0xffff, []byte{0x82, 0xff, 0xff}},
	} {
		if got := berLen(c.n); !bytes.Equal(got, c.want) {
			t.Errorf("berLen(%d) = % x, want % x", c.n, got, c.want)
		}
	}
}

// An integer's content octets are the shortest two's complement that keeps the
// sign.
//
// The sign is the part worth testing: dropping a leading 0x00 from a positive
// number whose top bit is set would make it negative, and dropping a leading
// 0xff from a negative one would make it positive. An MMS error code read with
// the wrong sign is a refusal that says something else.
func TestAnIntegersContentKeepsItsSign(t *testing.T) {
	for _, c := range []struct {
		v    int64
		want []byte
	}{
		{0, []byte{0x00}},
		{1, []byte{0x01}},
		{127, []byte{0x7f}},
		{128, []byte{0x00, 0x80}}, // the pad that keeps it positive
		{255, []byte{0x00, 0xff}},
		{256, []byte{0x01, 0x00}},
		{-1, []byte{0xff}},
		{-128, []byte{0x80}},
		{-129, []byte{0xff, 0x7f}}, // the pad that keeps it negative
		{-256, []byte{0xff, 0x00}},
	} {
		got := berContent(c.v)
		if !bytes.Equal(got, c.want) {
			t.Errorf("berContent(%d) = % x, want % x", c.v, got, c.want)
		}
		// And the sign survives a round trip through the wire's reader,
		// which is the property the octets are for.
		if len(got) > 0 {
			var v int64
			if got[0]&0x80 != 0 {
				v = -1
			}
			for _, b := range got {
				v = v<<8 | int64(b)
			}
			if v != c.v {
				t.Errorf("berContent(%d) reads back as %d", c.v, v)
			}
		}
	}
}

// A tag-length-value with a body past the short form still frames correctly,
// which is the case the length form above exists for.
func TestABodyPastTheShortFormIsStillFramed(t *testing.T) {
	body := bytes.Repeat([]byte{0xAA}, 300)
	out := tlv(0x30, body)
	if out[0] != 0x30 {
		t.Fatalf("identifier = %#x", out[0])
	}
	if !bytes.Equal(out[1:4], []byte{0x82, 0x01, 0x2c}) {
		t.Errorf("length octets = % x, want 82 01 2c", out[1:4])
	}
	if !bytes.Equal(out[4:], body) {
		t.Error("the body did not survive the framing")
	}
}

// The invoke identifier is narrowed to the Unsigned32 the standard types it
// as, and the wire package has already refused anything larger -- so this is
// the narrowing that says so rather than a check that can fail.
//
// What matters is that an identifier past the bound becomes zero rather than
// wrapping: a refusal answering invoke 0 is one the client can see does not
// match its request, where a wrapped identifier would match somebody else's.
func TestAnInvokeIdentifierPastTheBoundBecomesZero(t *testing.T) {
	for _, c := range []struct {
		in   uint64
		want uint32
	}{
		{0, 0},
		{1, 1},
		{wire.MaxInvokeID, uint32(wire.MaxInvokeID)},
		{wire.MaxInvokeID + 1, 0},
		{1 << 40, 0},
	} {
		if got := invokeOf(&wire.Message{InvokeID: c.in}); got != c.want {
			t.Errorf("invokeOf(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

// The sort is an insertion sort over a handful of short strings, and what it
// has to be is stable in the sense that matters here: the same set always
// comes out in the same order, so a log line naming what a session used does
// not change between two identical sessions.
func TestTheServiceListComesOutInOneOrder(t *testing.T) {
	for _, c := range []struct{ in, want []string }{
		{nil, nil},
		{[]string{"a"}, []string{"a"}},
		{[]string{"b", "a"}, []string{"a", "b"}},
		{[]string{"read", "write", "define", "read"}, []string{"define", "read", "read", "write"}},
		{[]string{"c", "b", "a"}, []string{"a", "b", "c"}},
	} {
		got := append([]string(nil), c.in...)
		sortStrings(got)
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("sortStrings(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}
