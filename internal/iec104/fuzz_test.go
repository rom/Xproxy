package iec104

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// The whole read, on arbitrary octets.
//
// This is the thinnest parser in the tree against a port that faces grid
// control: an APDU arrives from whatever can route to TCP 2404, and everything
// the relay decides about a command is decided from the structure read here. So
// the assertions are the invariants the policy above is written against -- an
// address it reports must be an address the encoding can hold, a qualifier it
// hands out must point into the frame that carried it, and a refusal must name
// one of the four errors this package documents, because the relay switches on
// them and an unnamed one reaches a default written for something else.

// FuzzParse drives the in-memory parser.
func FuzzParse(f *testing.F) {
	// Real frames, from this package's own builders.
	f.Add(apdu(0x07, 0x00, 0x00, 0x00)) // STARTDT_act
	f.Add(apdu(0x0b, 0x00, 0x00, 0x00)) // STARTDT_con
	f.Add(apdu(0x43, 0x00, 0x00, 0x00)) // TESTFR_act
	f.Add(apdu(0x01, 0x00, 0x04, 0x00)) // an S frame
	f.Add(iframe(1, 1, asdu(MSpNA1, 1, false, CauseSpontaneous, 1, 0x01, 0x00, 0x00, 0x01)...))
	f.Add(iframe(2, 1, asdu(CSeNC1, 1, false, CauseActivation, 1,
		0x0a, 0x00, 0x00, 0x00, 0x00, 0x20, 0x41, 0x80)...))
	f.Add(iframe(3, 1, asdu(CScNA1, 1, false, CauseActivation, 1, 0x05, 0x00, 0x00, 0x81)...))
	f.Add(iframe(4, 1, asdu(MMeNA1, 8, true, CauseSpontaneous, 1,
		0x01, 0x00, 0x00, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16)...))
	f.Add(iframe(5, 1, asdu(CIcNA1, 0, false, CauseActivation, 1)...)) // the zero-object case
	f.Add(iframe(6, 1, asdu(Type(0xff), 3, false, CauseActivation, 1, 1, 2, 3)...))
	// And the shapes that must be refused.
	f.Add([]byte{})
	f.Add([]byte{Start})
	f.Add([]byte{Start, 0x04})
	f.Add([]byte{0x00, 0x04, 0, 0, 0, 0})
	f.Add([]byte{Start, 0xff, 0, 0, 0, 0})
	f.Add(append(apdu(0x01, 0x00, 0x00, 0x00), 0xde, 0xad)) // an S frame with a body

	f.Fuzz(func(t *testing.T, in []byte) {
		fr, err := Parse(in)
		if err != nil {
			expected(t, err)
			if fr != nil {
				t.Fatal("Parse returned a frame with an error")
			}
			return
		}
		// The length octet and the buffer agree, or the frame the relay
		// forwards is not the frame it checked.
		if int(in[1]) != len(in)-2 {
			t.Fatalf("accepted a frame whose length octet says %d in %d octets", in[1], len(in))
		}
		if !bytes.Equal(fr.Raw, in) {
			t.Fatal("Frame.Raw is not the octets it was parsed from")
		}
		switch fr.Format {
		case FormatI:
			if fr.ASDU == nil {
				t.Fatal("an I frame with no ASDU")
			}
			if fr.Send >= MaxSeq || fr.Recv >= MaxSeq {
				t.Fatalf("sequence numbers %d/%d are outside the number space", fr.Send, fr.Recv)
			}
			a := fr.ASDU
			if a.Objects < 0 || a.Objects > 0x7f {
				t.Fatalf("object count %d cannot be carried by the qualifier", a.Objects)
			}
			if len(a.Addresses) > a.Objects {
				t.Fatalf("%d addresses reported for %d objects", len(a.Addresses), a.Objects)
			}
			if a.Sequence && len(a.Addresses) > 1 {
				t.Fatalf("a sequence carries one address; %d reported", len(a.Addresses))
			}
			for _, ad := range a.Addresses {
				if ad > 0xffffff {
					t.Fatalf("address %d is wider than the three octets that carry it", ad)
				}
			}
			if a.Cause > 0x3f {
				t.Fatalf("cause %d has the flag bits in it", a.Cause)
			}
			// The qualifier is handed to the policy, so it has to point into
			// the frame rather than past it.
			if a.Qualifier != nil {
				within(t, in, a.Qualifier)
			}
			// Select is read from the qualifier, so one without the other is a
			// decision made from nothing: select-before-execute is the rule
			// this kind enforces that the equipment mostly does not.
			if a.Select && len(a.Qualifier) == 0 {
				t.Fatal("Select is set with no qualifier to have read it from")
			}
		case FormatS, FormatU:
			if fr.ASDU != nil {
				t.Fatalf("%v frame carried an ASDU, which is how a station slips "+
					"one past a check that only looks at I frames", fr.Format)
			}
			if len(in) != APCILen {
				t.Fatalf("%v frame of %d octets was accepted", fr.Format, len(in))
			}
		default:
			t.Fatalf("format %v is not one the relay handles", fr.Format)
		}
	})
}

// FuzzReadFrame drives the streaming reader over arbitrary octets, which is how
// frames actually arrive.
//
// The invariant that matters here is that the reader and the in-memory parser
// agree. A reader that consumed a different number of octets than the frame it
// returned would leave the stream at an offset nobody knows -- and on a protocol
// framed by a start octet and a length, a desync is not recoverable: the next
// 0x68 is as likely to be inside a measurement as at a boundary, which is why
// this package refuses to hunt for one.
func FuzzReadFrame(f *testing.F) {
	f.Add(append(apdu(0x07, 0, 0, 0), apdu(0x0b, 0, 0, 0)...))
	f.Add(append(apdu(0x01, 0x00, 0x04, 0x00),
		iframe(1, 1, asdu(MSpNA1, 1, false, CauseSpontaneous, 1, 1, 0, 0, 1)...)...))
	f.Add([]byte{Start, 0x03, 0, 0, 0})    // a length below the minimum
	f.Add([]byte{Start, 0xfe, 0, 0, 0, 0}) // a length above what the reader takes
	f.Add([]byte{Start, 0x04, 0, 0, 0})    // truncated body
	f.Add([]byte{0x68, 0x68, 0x68, 0x68})  // start octets all the way down

	f.Fuzz(func(t *testing.T, in []byte) {
		br := bytes.NewReader(in)
		rd := NewReader(br)
		for n := 0; n < 64; n++ {
			before := br.Len()
			fr, err := rd.ReadFrame()
			if err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
					return
				}
				expected(t, err)
				return
			}
			consumed := before - br.Len()
			if consumed != len(fr.Raw) {
				t.Fatalf("the reader consumed %d octets and returned a frame of %d; "+
					"the stream is now at an offset nobody knows", consumed, len(fr.Raw))
			}
			if int(fr.Raw[1]) != len(fr.Raw)-2 {
				t.Fatalf("returned a frame whose length octet says %d in %d octets",
					fr.Raw[1], len(fr.Raw))
			}
			// Everything the reader accepts, the in-memory parser accepts the
			// same way: two readings of one frame is two policies.
			again, err := Parse(fr.Raw)
			if err != nil {
				t.Fatalf("the reader accepted a frame Parse refuses: %v", err)
			}
			if again.Format != fr.Format || (again.ASDU == nil) != (fr.ASDU == nil) {
				t.Fatalf("the reader and Parse read one frame differently: %v/%v",
					fr.Format, again.Format)
			}
			if fr.ASDU != nil && again.ASDU.Type != fr.ASDU.Type {
				t.Fatalf("the reader read type %v and Parse read %v", fr.ASDU.Type, again.ASDU.Type)
			}
		}
	})
}

// expected fails on any error that is not one this package documents.
func expected(t *testing.T, err error) {
	t.Helper()
	switch {
	case errors.Is(err, ErrStart), errors.Is(err, ErrLength),
		errors.Is(err, ErrShortASDU), errors.Is(err, ErrObjects):
		return
	}
	t.Fatalf("error %v is none of the four this package documents", err)
}

// within fails when b does not point into the frame it came from.
func within(t *testing.T, frame, b []byte) {
	t.Helper()
	if len(b) == 0 {
		return
	}
	if !bytes.Contains(frame, b) {
		t.Fatalf("a slice of %d octets handed to the policy is not in the frame", len(b))
	}
}
