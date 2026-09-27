package iec104

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"
	"time"
)

// The property worth having: what this package builds, this package reads
// back. A builder and a parser that disagree would put a decoy on the
// network answering frames no client can read, which is a decoy that
// announces itself.
func TestWhatIsBuiltParsesBack(t *testing.T) {
	asdu := AppendHead(nil, Head{
		Type: MMeNB1, Objects: 3, Cause: CauseIntroGeneral, Common: 0x1234, Originator: 7,
	})
	for i := range 3 {
		asdu = AppendScaled(asdu, uint32(1000+i), int16(100*i), QualityGood)
	}
	f, err := Parse(EncodeI(5, 9, asdu))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if f.Format != FormatI || f.Send != 5 || f.Recv != 9 {
		t.Fatalf("APCI: %v send %d recv %d", f.Format, f.Send, f.Recv)
	}
	a := f.ASDU
	if a == nil {
		t.Fatal("no ASDU")
	}
	if a.Type != MMeNB1 || a.Objects != 3 || a.Cause != CauseIntroGeneral {
		t.Errorf("header: type %v objects %d cause %v", a.Type, a.Objects, a.Cause)
	}
	if a.Common != 0x1234 || a.Originator != 7 {
		t.Errorf("addresses: common %d originator %d", a.Common, a.Originator)
	}
	if len(a.Addresses) != 3 || a.Addresses[0] != 1000 || a.Addresses[2] != 1002 {
		t.Errorf("object addresses: %v", a.Addresses)
	}
	if a.Sequence || a.Negative || a.Test {
		t.Errorf("flags: sequence %v negative %v test %v", a.Sequence, a.Negative, a.Test)
	}
}

// The flags share octets with other fields, which is where an encoder goes
// wrong: a negative confirmation that also reads as a test frame is a
// frame a control centre files under the wrong heading.
func TestTheFlagsDoNotCollideWithTheFields(t *testing.T) {
	for _, tc := range []struct {
		name          string
		head          Head
		neg, test, sq bool
	}{
		{name: "plain", head: Head{Type: CScNA1, Objects: 1, Cause: CauseActCon, Common: 1}},
		{
			name: "negative", neg: true,
			head: Head{Type: CScNA1, Objects: 1, Cause: CauseActCon, Common: 1, Negative: true},
		},
		{
			name: "test", test: true,
			head: Head{Type: CScNA1, Objects: 1, Cause: CauseActCon, Common: 1, Test: true},
		},
		{
			name: "both", neg: true, test: true,
			head: Head{Type: CScNA1, Objects: 1, Cause: CauseActCon, Common: 1, Negative: true, Test: true},
		},
		{
			name: "a sequence of measurements", sq: true,
			head: Head{Type: MMeNB1, Objects: 4, Cause: CauseSpontaneous, Common: 1, Sequence: true},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			asdu := AppendHead(nil, tc.head)
			asdu = AppendIOA(asdu, 4711)
			// Enough element octets for the widest case here: a sequence
			// of four scaled measurements is four three-octet elements.
			asdu = append(asdu, make([]byte, 12)...)
			f, err := Parse(EncodeI(1, 1, asdu))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			a := f.ASDU
			if a.Cause != tc.head.Cause {
				t.Errorf("cause %v, want %v", a.Cause, tc.head.Cause)
			}
			if a.Negative != tc.neg || a.Test != tc.test || a.Sequence != tc.sq {
				t.Errorf("negative %v test %v sequence %v", a.Negative, a.Test, a.Sequence)
			}
			if a.Addresses[0] != 4711 {
				t.Errorf("the address came back as %d", a.Addresses[0])
			}
		})
	}
}

// The U and S frames, which carry no data and are most of what a
// connection's first second is made of.
func TestTheControlFramesAreWhatTheyClaim(t *testing.T) {
	for _, c := range []Control{StartDTAct, StartDTCon, StopDTAct, StopDTCon, TestFRAct, TestFRCon} {
		f, err := Parse(EncodeU(c))
		if err != nil {
			t.Fatalf("%v: %v", c, err)
		}
		if f.Format != FormatU || f.Control != c {
			t.Errorf("%v came back as %v %v", c, f.Format, f.Control)
		}
	}
	f, err := Parse(EncodeS(1234))
	if err != nil {
		t.Fatal(err)
	}
	if f.Format != FormatS || f.Recv != 1234 {
		t.Errorf("S frame: %v recv %d", f.Format, f.Recv)
	}
}

// The object encodings, read back by hand: the parser deliberately does
// not decode a measurement's value, so this is where the values are
// checked at all.
func TestTheObjectsCarryTheirValues(t *testing.T) {
	// A single point: the bit is the low bit of the quality octet.
	b := AppendSinglePoint(nil, 1, true, QualityGood)
	if len(b) != 4 || b[3] != 0x01 {
		t.Errorf("single point on: % x", b)
	}
	if b := AppendSinglePoint(nil, 1, false, QualityInvalid); b[3] != 0x80 {
		t.Errorf("single point off and invalid: % x", b)
	}
	// A scaled value is signed, little endian, and negative values are
	// the ones an encoder gets wrong.
	for _, v := range []int16{0, 1, -1, 32767, -32768, 1234} {
		b := AppendScaled(nil, 7, v, QualityGood)
		if len(b) != 6 {
			t.Fatalf("scaled: % x", b)
		}
		if got := int16(binary.LittleEndian.Uint16(b[3:5])); got != v { //nolint:gosec // the standard's own signed encoding
			t.Errorf("scaled %d came back %d", v, got)
		}
	}
	// A short float is IEEE 754, little endian.
	b = AppendFloat(nil, 7, 21.5, QualityGood)
	if got := math.Float32frombits(binary.LittleEndian.Uint32(b[3:7])); got != 21.5 {
		t.Errorf("float came back %v", got)
	}
	// A total is a signed 32-bit count and a five-bit sequence number.
	b = AppendTotal(nil, 7, -5, 0xFF)
	if got := int32(binary.LittleEndian.Uint32(b[3:7])); got != -5 { //nolint:gosec // the standard's own signed encoding
		t.Errorf("total came back %d", got)
	}
	if b[7] != 0x1F {
		t.Errorf("the sequence octet is % x, want the low five bits only", b[7])
	}
}

// A timestamp a control centre will not file under 1970 or under the wrong
// minute. The fields overlap -- the day carries the day of week in its top
// three bits -- which is the other thing an encoder gets wrong.
func TestTheTimestampIsTheStandardsShape(t *testing.T) {
	at := time.Date(2026, 3, 9, 14, 45, 30, 500e6, time.UTC) // a Monday
	b := AppendCP56Time2a(nil, at)
	if len(b) != 7 {
		t.Fatalf("%d octets", len(b))
	}
	if ms := binary.LittleEndian.Uint16(b[0:2]); ms != 30500 {
		t.Errorf("milliseconds in the minute: %d", ms)
	}
	if b[2] != 45 || b[3] != 14 {
		t.Errorf("minute %d hour %d", b[2], b[3])
	}
	if day := b[4] & 0x1F; day != 9 {
		t.Errorf("day %d", day)
	}
	if dow := b[4] >> 5; dow != 1 {
		t.Errorf("day of week %d, want Monday as 1", dow)
	}
	if b[5] != 3 || b[6] != 26 {
		t.Errorf("month %d year %d", b[5], b[6])
	}
	// Sunday is 7 rather than 0, which is the standard's counting and not
	// Go's.
	sunday := AppendCP56Time2a(nil, time.Date(2026, 3, 8, 1, 0, 0, 0, time.UTC))
	if dow := sunday[4] >> 5; dow != 7 {
		t.Errorf("Sunday came back as %d", dow)
	}
}

// An object count outside what the field can hold is clamped rather than
// written into the flag bit beside it: a count of 200 that set the
// sequence bit would be an ASDU claiming something nobody meant.
func TestTheObjectCountCannotReachTheSequenceBit(t *testing.T) {
	for _, n := range []int{-1, 0, 1, 127, 128, 1000} {
		b := AppendHead(nil, Head{Type: MSpNA1, Objects: n, Cause: CauseSpontaneous, Common: 1})
		if b[1]&0x80 != 0 {
			t.Errorf("objects %d set the sequence bit: % x", n, b)
		}
		if got := int(b[1] & 0x7F); n > 0 && n <= 127 && got != n {
			t.Errorf("objects %d came back %d", n, got)
		}
	}
	// And the sequence bit is still available to whoever asks for it.
	b := AppendHead(nil, Head{Type: MSpNA1, Objects: 4, Sequence: true, Cause: CauseSpontaneous, Common: 1})
	if b[1] != 0x84 {
		t.Errorf("a sequence of four is % x", b[1])
	}
}

// The length octet counts what follows it, which is what a reader trusts.
func TestTheLengthOctetCountsTheRest(t *testing.T) {
	asdu := AppendHead(nil, Head{Type: MSpNA1, Objects: 1, Cause: CauseSpontaneous, Common: 1})
	asdu = AppendSinglePoint(asdu, 1, true, QualityGood)
	apdu := EncodeI(0, 0, asdu)
	if int(apdu[1]) != len(apdu)-2 {
		t.Errorf("length %d for %d octets", apdu[1], len(apdu))
	}
	if !bytes.Equal(apdu[APCILen:], asdu) {
		t.Error("the ASDU is not where the APCI says it is")
	}
}

// Every information element's size, against what the standard composes it
// from. This table is the one that matters most in the package: the size
// is how the parser steps from one object to the next, so a size one octet
// short reads every address after the first out of the middle of a value.
// That is not a parse failure -- it is a policy about addresses being
// checked against numbers nobody sent.
//
// Before this test five of the measurement sizes were wrong, and a probe
// of two scaled measurements at 1000 and 1001 read back as 1000 and
// 256256. The sizes here were confirmed against the encoders of
// mz-automation/lib60870 by counting the octets each one writes, and the
// composition in each name below is why the number is what it is.
func TestEveryElementSizeMatchesItsComposition(t *testing.T) {
	const (
		siq  = 1 // single point information with quality
		diq  = 1 // double point information with quality
		vti  = 1 // value with transient state
		qds  = 1 // quality descriptor
		nva  = 2 // normalised value
		sva  = 2 // scaled value
		r32  = 4 // short floating point
		bsi  = 4 // binary state information
		bcr  = 5 // binary counter reading, sequence octet included
		cp24 = 3
		cp56 = 7
		cp16 = 2
		sco  = 1 // single command
		dco  = 1 // double command
		rco  = 1 // regulating step command
		qos  = 1 // qualifier of setpoint command
		qoi  = 1 // qualifier of interrogation
		qcc  = 1 // qualifier of counter interrogation
		qrp  = 1 // qualifier of reset process
		fbp  = 2 // fixed test bit pattern
		tsc  = 2 // test sequence counter
	)
	for _, tc := range []struct {
		typ  Type
		want int
		of   string
	}{
		{MSpNA1, siq, "SIQ"},
		{MSpTA1, siq + cp24, "SIQ + CP24Time2a"},
		{MDpNA1, diq, "DIQ"},
		{MDpTA1, diq + cp24, "DIQ + CP24Time2a"},
		{MStNA1, vti + qds, "VTI + QDS"},
		{MStTA1, vti + qds + cp24, "VTI + QDS + CP24Time2a"},
		{MBoNA1, bsi + qds, "BSI + QDS"},
		{MBoTA1, bsi + qds + cp24, "BSI + QDS + CP24Time2a"},
		{MMeNA1, nva + qds, "NVA + QDS"},
		{MMeTA1, nva + qds + cp24, "NVA + QDS + CP24Time2a"},
		{MMeNB1, sva + qds, "SVA + QDS"},
		{MMeTB1, sva + qds + cp24, "SVA + QDS + CP24Time2a"},
		{MMeNC1, r32 + qds, "R32 + QDS"},
		{MMeTC1, r32 + qds + cp24, "R32 + QDS + CP24Time2a"},
		{MItNA1, bcr, "BCR"},
		{MItTA1, bcr + cp24, "BCR + CP24Time2a"},
		{MMeND1, nva, "NVA, and no quality descriptor -- which is what the D is for"},
		{MSpTB1, siq + cp56, "SIQ + CP56Time2a"},
		{MDpTB1, diq + cp56, "DIQ + CP56Time2a"},
		{MStTB1, vti + qds + cp56, "VTI + QDS + CP56Time2a"},
		{MBoTB1, bsi + qds + cp56, "BSI + QDS + CP56Time2a"},
		{MMeTD1, nva + qds + cp56, "NVA + QDS + CP56Time2a"},
		{MMeTE1, sva + qds + cp56, "SVA + QDS + CP56Time2a"},
		{MMeTF1, r32 + qds + cp56, "R32 + QDS + CP56Time2a"},
		{MItTB1, bcr + cp56, "BCR + CP56Time2a"},
		{CScNA1, sco, "SCO"},
		{CDcNA1, dco, "DCO"},
		{CRcNA1, rco, "RCO"},
		{CSeNA1, nva + qos, "NVA + QOS"},
		{CSeNB1, sva + qos, "SVA + QOS"},
		{CSeNC1, r32 + qos, "R32 + QOS"},
		{CBoNA1, bsi, "BSI, and no qualifier"},
		{CScTA1, sco + cp56, "SCO + CP56Time2a"},
		{CDcTA1, dco + cp56, "DCO + CP56Time2a"},
		{CRcTA1, rco + cp56, "RCO + CP56Time2a"},
		{CSeTA1, nva + qos + cp56, "NVA + QOS + CP56Time2a"},
		{CSeTB1, sva + qos + cp56, "SVA + QOS + CP56Time2a"},
		{CSeTC1, r32 + qos + cp56, "R32 + QOS + CP56Time2a"},
		{CBoTA1, bsi + cp56, "BSI + CP56Time2a"},
		{CIcNA1, qoi, "QOI"},
		{CCiNA1, qcc, "QCC"},
		{CRdNA1, 0, "nothing at all"},
		{CRpNA1, qrp, "QRP"},
		{CCdNA1, cp16, "CP16Time2a"},
		{CCsNA1, cp56, "CP56Time2a"},
		{CTsNA1, fbp, "FBP"},
		{CTsTA1, tsc + cp56, "TSC + CP56Time2a"},
	} {
		t.Run(tc.typ.String(), func(t *testing.T) {
			got, known := objectSize(tc.typ)
			if !known {
				t.Fatalf("%v is not in the size table", tc.typ)
			}
			if got != tc.want {
				t.Errorf("%v: size %d, want %d (%s)", tc.typ, got, tc.want, tc.of)
			}
		})
	}
}

// And the consequence, as a test rather than as an argument: a frame
// carrying several objects of one type reads back with the addresses that
// were sent, for every type the table knows.
func TestEveryTypeReadsBackItsAddresses(t *testing.T) {
	for _, typ := range []Type{
		MSpNA1, MDpNA1, MStNA1, MBoNA1, MMeNA1, MMeNB1, MMeNC1, MItNA1, MMeND1,
		MSpTA1, MDpTA1, MStTA1, MBoTA1, MMeTA1, MMeTB1, MMeTC1, MItTA1,
		MSpTB1, MDpTB1, MStTB1, MBoTB1, MMeTD1, MMeTE1, MMeTF1, MItTB1,
		CScNA1, CDcNA1, CRcNA1, CSeNA1, CSeNB1, CSeNC1, CBoNA1,
		CScTA1, CDcTA1, CRcTA1, CSeTA1, CSeTB1, CSeTC1, CBoTA1,
		CIcNA1, CCiNA1, CRpNA1, CCdNA1, CCsNA1, CTsNA1, CTsTA1,
	} {
		t.Run(typ.String(), func(t *testing.T) {
			size, _ := objectSize(typ)
			want := []uint32{100, 1000, 0x010203}
			asdu := AppendHead(nil, Head{Type: typ, Objects: len(want), Cause: CausePeriodic, Common: 1})
			for _, ioa := range want {
				asdu = AppendIOA(asdu, ioa)
				// The element itself is not decoded here; what is under
				// test is that the parser steps over exactly as much of it
				// as the type says.
				asdu = append(asdu, make([]byte, size)...)
			}
			f, err := Parse(EncodeI(0, 0, asdu))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			got := f.ASDU.Addresses
			if len(got) != len(want) {
				t.Fatalf("%d addresses, want %d", len(got), len(want))
			}
			for i := range want {
				if got[i] != want[i] {
					t.Errorf("address %d came back %d, want %d", i, got[i], want[i])
				}
			}
		})
	}
}
