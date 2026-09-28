package iec104

import (
	"encoding/binary"
	"math"
	"testing"
	"time"
)

// The information element, decoded.
//
// Every case here is an element built octet by octet from the layouts of
// IEC 60870-5-101 section 7.3.1, rather than from this package's own encoder:
// a test that built its input with the same table it is checking would agree
// with itself about a layout that is wrong.

func decodeOne(t *testing.T, ty Type, objects byte, sequence bool, body ...byte) []Element {
	t.Helper()
	raw := asdu(ty, objects, sequence, CauseSpontaneous, 1, body...)
	a, err := ParseASDU(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return a.Elements(raw)
}

// A single point keeps its value and its quality in one octet, and reading the
// whole octet as quality would report a working point as blocked.
func TestASinglePointSharesItsOctetWithItsQuality(t *testing.T) {
	// SIQ: bit 1 is the state, bits 5..8 are BL, SB, NT, IV.
	for _, tc := range []struct {
		name  string
		siq   byte
		value float64
		qual  Quality
	}{
		{"off and good", 0x00, 0, 0},
		{"on and good", 0x01, 1, 0},
		{"on and substituted", 0x21, 1, QualitySubstituted},
		{"off and invalid", 0x80, 0, QualityInvalid},
		{"on, blocked and not topical", 0x51, 1, QualityBlocked | QualityNotTopical},
	} {
		t.Run(tc.name, func(t *testing.T) {
			els := decodeOne(t, MSpNA1, 1, false, obj(100, tc.siq)...)
			if len(els) != 1 {
				t.Fatalf("got %d elements", len(els))
			}
			e := els[0]
			if e.Address != 100 {
				t.Errorf("address %d, want 100", e.Address)
			}
			if !e.HasValue || e.Value != tc.value {
				t.Errorf("value %v (have=%v), want %v", e.Value, e.HasValue, tc.value)
			}
			if !e.HasQuality || e.Quality != tc.qual {
				t.Errorf("quality %q, want %q", e.Quality, tc.qual)
			}
		})
	}
}

// A double point is two bits, so all four states have to come back distinct:
// reading it as one bit makes indeterminate look like off.
func TestADoublePointHasFourStates(t *testing.T) {
	for diq, want := range map[byte]float64{0x00: 0, 0x01: 1, 0x02: 2, 0x03: 3} {
		els := decodeOne(t, MDpNA1, 1, false, obj(7, diq)...)
		if len(els) != 1 || els[0].Value != want {
			t.Errorf("DIQ %#x decoded to %v, want %v", diq, els[0].Value, want)
		}
		// And the state bits are not quality bits. A double point reporting
		// "indeterminate" -- both bits set -- is not one reporting an overflow,
		// and a quality carrying either of those bits would compare unequal to
		// the good quality it is.
		if q := els[0].Quality; q != 0 {
			t.Errorf("DIQ %#x reported quality %#x (%q), want good", diq, byte(q), q)
		}
	}
	// A double point that really does carry a quality bit still reports it.
	els := decodeOne(t, MDpNA1, 1, false, obj(7, 0x83)...)
	if len(els) != 1 || els[0].Quality != QualityInvalid || els[0].Value != 3 {
		t.Errorf("an invalid indeterminate point decoded to value %v quality %#x",
			els[0].Value, byte(els[0].Quality))
	}
}

// A step position is seven bits of two's complement. Reading it unsigned reports
// tap 127 on a transformer whose tap is -1.
func TestAStepPositionIsSigned(t *testing.T) {
	for _, tc := range []struct {
		vti       byte
		want      float64
		transient bool
	}{
		{0x00, 0, false},
		{0x01, 1, false},
		{0x3f, 63, false},
		{0x40, -64, false},
		{0x7f, -1, false},
		{0xff, -1, true}, // the same position, in transit
	} {
		els := decodeOne(t, MStNA1, 1, false, obj(7, tc.vti, 0x00)...)
		if len(els) != 1 {
			t.Fatalf("VTI %#x gave %d elements", tc.vti, len(els))
		}
		if els[0].Value != tc.want {
			t.Errorf("VTI %#x decoded to %v, want %v", tc.vti, els[0].Value, tc.want)
		}
		if els[0].Transient != tc.transient {
			t.Errorf("VTI %#x transient=%v, want %v", tc.vti, els[0].Transient, tc.transient)
		}
	}
}

// A normalised measurement is a fraction of full scale, and the quality octet
// comes after its two value octets.
func TestANormalisedMeasurementAndItsQuality(t *testing.T) {
	// 0x7fff is one step short of +1; the quality octet says substituted.
	els := decodeOne(t, MMeNA1, 1, false, obj(300, 0xff, 0x7f, 0x20)...)
	if len(els) != 1 {
		t.Fatalf("got %d elements", len(els))
	}
	e := els[0]
	if e.Kind != Normalised {
		t.Errorf("kind %v, want normalised", e.Kind)
	}
	if want := float64(32767) / 32768; e.Value != want {
		t.Errorf("value %v, want %v", e.Value, want)
	}
	if !e.Quality.Substituted() {
		t.Errorf("quality %q does not say substituted", e.Quality)
	}
	// And the negative half of the range is negative.
	els = decodeOne(t, MMeNA1, 1, false, obj(300, 0x00, 0x80, 0x00)...)
	if els[0].Value != -1 {
		t.Errorf("0x8000 decoded to %v, want -1", els[0].Value)
	}
}

// A bit the standard reserves is not a quality bit. A station that sets one has
// said nothing about quality, and a Quality carrying it would compare unequal to
// the good quality it is -- which is how a report ends up listing a healthy point
// as having something wrong with it.
func TestAReservedQualityBitIsNotKept(t *testing.T) {
	// QDS bits 2, 3 and 4 are reserved; bits 1 and 5..8 are OV, BL, SB, NT, IV.
	els := decodeOne(t, MMeNB1, 1, false, obj(300, 0x05, 0x00, 0x0e)...)
	if len(els) != 1 {
		t.Fatalf("got %d elements", len(els))
	}
	if q := els[0].Quality; q != 0 {
		t.Errorf("reserved bits were kept as quality %#x (%q)", byte(q), q)
	}
	// And a real bit beside them still arrives.
	els = decodeOne(t, MMeNB1, 1, false, obj(300, 0x05, 0x00, 0x0e|byte(QualitySubstituted))...)
	if len(els) != 1 || els[0].Quality != QualitySubstituted {
		t.Errorf("quality %#x, want substituted alone", byte(els[0].Quality))
	}
}

// A short float is in engineering units, which is the only encoding here that
// needs no scale factor kept somewhere else.
func TestAShortFloatMeasurement(t *testing.T) {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], math.Float32bits(21.5))
	els := decodeOne(t, MMeNC1, 1, false, obj(42, b[0], b[1], b[2], b[3], 0x00)...)
	if len(els) != 1 || els[0].Value != 21.5 {
		t.Fatalf("decoded %v, want 21.5", els[0].Value)
	}
	if !els[0].HasQuality || els[0].Quality != 0 {
		t.Errorf("quality %q, want good", els[0].Quality)
	}
}

// M_ME_ND_1 is the measurement without a quality descriptor -- that is what the
// D is for -- so the report must say the quality is absent rather than good.
// Treating absent as good would assert something the wire never said.
func TestAMeasurementWithoutQualitySaysSo(t *testing.T) {
	els := decodeOne(t, MMeND1, 1, false, obj(9, 0x00, 0x40)...)
	if len(els) != 1 {
		t.Fatalf("got %d elements", len(els))
	}
	if els[0].HasQuality {
		t.Error("M_ME_ND_1 reported a quality descriptor it does not carry")
	}
	if !els[0].HasValue {
		t.Error("M_ME_ND_1 carries a value and none was read")
	}
}

// An integrated total carries its flags in the octet after the accumulator, and
// the carry bit is what makes a difference between two readings wrong.
func TestACounterCarriesItsSequenceAndFlags(t *testing.T) {
	var b [4]byte
	var neg int32 = -5
	binary.LittleEndian.PutUint32(b[:], uint32(neg))
	// Sequence 3, carry set, adjusted clear, invalid set.
	els := decodeOne(t, MItNA1, 1, false, obj(500, b[0], b[1], b[2], b[3], 0x03|0x20|0x80)...)
	if len(els) != 1 {
		t.Fatalf("got %d elements", len(els))
	}
	e := els[0]
	if e.Value != -5 {
		t.Errorf("counter %v, want -5", e.Value)
	}
	if e.CounterSequence != 3 {
		t.Errorf("sequence %d, want 3", e.CounterSequence)
	}
	if !e.CounterCarry || e.CounterAdjusted || !e.CounterInvalid {
		t.Errorf("flags carry=%v adjusted=%v invalid=%v", e.CounterCarry, e.CounterAdjusted, e.CounterInvalid)
	}
	// A counter has no quality descriptor; its three flags are in its own octet.
	if e.HasQuality {
		t.Error("an integrated total reported a quality descriptor")
	}
}

// The seven-octet timestamp, read as the standard lays it out.
func TestACP56TimestampIsReadWhole(t *testing.T) {
	want := time.Date(2026, time.September, 28, 14, 35, 12, 250*int(time.Millisecond), time.UTC)
	var tag []byte
	tag = AppendCP56Time2a(tag, want)
	els := decodeOne(t, MSpTB1, 1, false, obj(11, append([]byte{0x01}, tag...)...)...)
	if len(els) != 1 {
		t.Fatalf("got %d elements", len(els))
	}
	e := els[0]
	if !e.HasTime || !e.HasDate {
		t.Fatalf("no dated timestamp was read (time=%v date=%v)", e.HasTime, e.HasDate)
	}
	if !e.Time.Equal(want) {
		t.Errorf("timestamp %v, want %v", e.Time, want)
	}
	if e.TimeInvalid {
		t.Error("a valid timestamp was read as invalid")
	}
}

// The timestamp's own IV bit says the station's clock is not to be trusted. A
// command carrying it has told the relay its timestamp means nothing.
func TestATimestampsInvalidBitIsCarried(t *testing.T) {
	tag := AppendCP56Time2a(nil, time.Date(2026, time.March, 1, 3, 4, 5, 0, time.UTC))
	tag[2] |= 0x80 // IV, in the minute octet
	els := decodeOne(t, MSpTB1, 1, false, obj(11, append([]byte{0x01}, tag...)...)...)
	if len(els) != 1 || !els[0].TimeInvalid {
		t.Error("the invalid bit was not carried")
	}
	// And the summer-time bit, which lives in the hour octet.
	tag = AppendCP56Time2a(nil, time.Date(2026, time.July, 1, 3, 4, 5, 0, time.UTC))
	tag[3] |= 0x80
	els = decodeOne(t, MSpTB1, 1, false, obj(11, append([]byte{0x01}, tag...)...)...)
	if len(els) != 1 || !els[0].TimeSummer {
		t.Error("the summer-time bit was not carried")
	}
}

// A timestamp whose fields are outside their ranges is no timestamp. time.Date
// would normalise month 13 into January of the next year, which is a date the
// station never sent -- so it is reported as absent, and a policy requiring one
// then refuses.
func TestATimestampOutsideItsRangesIsNoTimestamp(t *testing.T) {
	for _, tc := range []struct {
		name string
		at   int
		val  byte
	}{
		{"month 13", 5, 13},
		{"day 0", 4, 0},
		{"hour 24", 3, 24},
		{"minute 60", 2, 60},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tag := AppendCP56Time2a(nil, time.Date(2026, time.March, 1, 3, 4, 5, 0, time.UTC))
			tag[tc.at] = tc.val
			els := decodeOne(t, MSpTB1, 1, false, obj(11, append([]byte{0x01}, tag...)...)...)
			if len(els) != 1 {
				t.Fatalf("got %d elements", len(els))
			}
			if els[0].HasTime {
				t.Errorf("an out-of-range timestamp was read as %v", els[0].Time)
			}
		})
	}
}

// A three-octet tag has no date, so nothing can be said about its age. Saying it
// has one would let an age policy compare against year zero and refuse
// everything.
func TestACP24TimestampHasNoDate(t *testing.T) {
	// 1250 ms into minute 35.
	els := decodeOne(t, MSpTA1, 1, false, obj(11, 0x01, 0xe2, 0x04, 35)...)
	if len(els) != 1 {
		t.Fatalf("got %d elements", len(els))
	}
	e := els[0]
	if !e.HasTime {
		t.Fatal("no timestamp was read")
	}
	if e.HasDate {
		t.Error("a CP24Time2a was reported as carrying a date")
	}
	if e.Time.Minute() != 35 || e.Time.Second() != 1 {
		t.Errorf("timestamp %v, want minute 35 second 1", e.Time)
	}
}

// A sequence carries one address and the addresses of the rest are that one
// counted up, which is the whole point of the bit. A decoder that reported them
// all at the first address would report one point reporting six values.
func TestASequenceCountsItsAddressesUp(t *testing.T) {
	body := []byte{100, 0, 0} // the first address
	for i := 0; i < 3; i++ {
		body = append(body, byte(i+1), 0x00, 0x00) // scaled value, good quality
	}
	els := decodeOne(t, MMeNB1, 3, true, body...)
	if len(els) != 3 {
		t.Fatalf("got %d elements, want 3", len(els))
	}
	for i, e := range els {
		if want := uint32(100 + i); e.Address != want {
			t.Errorf("element %d is at address %d, want %d", i, e.Address, want)
		}
		if e.Value != float64(i+1) {
			t.Errorf("element %d has value %v, want %d", i, e.Value, i+1)
		}
	}
}

// A type whose layout this package does not have decodes to nothing rather than
// to a guess. A layout guessed at would report a quality bit from the middle of
// a value.
func TestAnUndecodedTypeYieldsNoElements(t *testing.T) {
	if Decodes(CIcNA1) {
		t.Fatal("this test needs a type with no element layout")
	}
	els := decodeOne(t, CIcNA1, 1, false, obj(0, 0x14)...)
	if len(els) != 0 {
		t.Errorf("an interrogation command decoded to %d elements", len(els))
	}
}

// A truncated element yields nothing rather than a value read past the end. The
// parser refuses a short ASDU, so this is the belt on the braces: the element
// decoder is called with whatever the parser accepted.
func TestATruncatedElementYieldsNothing(t *testing.T) {
	// A short-float measurement needs five octets and gets two.
	raw := asdu(MMeNC1, 1, false, CauseSpontaneous, 1, 42, 0, 0, 0x01, 0x02)
	a, err := ParseASDU(raw)
	if err == nil {
		if els := a.Elements(raw); len(els) != 0 {
			t.Errorf("a truncated element decoded to %d elements", len(els))
		}
		return
	}
	// The parser refusing it outright is the better answer, and is what
	// happens: there is nothing left for the element decoder to be wrong about.
}

// The quality bits are named the way a policy names them, both ways round.
func TestQualityNamesRoundTrip(t *testing.T) {
	for _, name := range QualityNames {
		bit, ok := QualityBitOf(name)
		if !ok {
			t.Errorf("%q is in QualityNames and QualityBitOf does not know it", name)
			continue
		}
		if got := bit.String(); got != name {
			t.Errorf("%q round-tripped to %q", name, got)
		}
	}
	if _, ok := QualityBitOf("nonsense"); ok {
		t.Error("QualityBitOf accepted a name that is not a quality bit")
	}
	// The order is the one an operator reads, worst first.
	if got := (QualityInvalid | QualityOverflow | QualitySubstituted).String(); got != "invalid,substituted,overflow" {
		t.Errorf("the bits are named %q", got)
	}
	// Overflow is a process event rather than a data-quality one, so it is not
	// what Bad means.
	if QualityOverflow.Bad() {
		t.Error("an overflowed reading was reported as bad data")
	}
	if !QualityInvalid.Bad() || !QualitySubstituted.Bad() {
		t.Error("invalid or substituted was not reported as bad data")
	}
	if Quality(0).Bad() || Quality(0).String() != "" {
		t.Error("a good value was reported as having something wrong with it")
	}
}
