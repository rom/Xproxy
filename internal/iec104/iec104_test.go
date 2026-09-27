package iec104

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

// apdu builds an APDU from its four control octets and its body, setting
// the length the way a station would.
func apdu(c1, c2, c3, c4 byte, body ...byte) []byte {
	out := []byte{Start, byte(4 + len(body)), c1, c2, c3, c4}
	return append(out, body...)
}

// iframe builds an I-format APDU carrying an ASDU.
func iframe(send, recv uint16, asdu ...byte) []byte {
	var c [4]byte
	binary.LittleEndian.PutUint16(c[0:2], send<<1)
	binary.LittleEndian.PutUint16(c[2:4], recv<<1)
	return apdu(c[0], c[1], c[2], c[3], asdu...)
}

// asdu builds an ASDU header and its body.
func asdu(t Type, objects byte, sequence bool, cause Cause, common uint16, body ...byte) []byte {
	vsq := objects
	if sequence {
		vsq |= 0x80
	}
	out := []byte{byte(t), vsq, byte(cause), 0}
	out = binary.LittleEndian.AppendUint16(out, common)
	return append(out, body...)
}

// obj is one information object: a three-octet address and its element.
func obj(addr uint32, elem ...byte) []byte {
	out := []byte{byte(addr), byte(addr >> 8), byte(addr >> 16)}
	return append(out, elem...)
}

// The three formats, read from the control octets rather than guessed at
// from the length: this is the first decision a relay makes about a frame
// and everything else depends on it.
func TestTheThreeFormatsAreReadFromTheControlOctets(t *testing.T) {
	// A start/stop handshake and a keepalive: U format, no body.
	for _, want := range []Control{StartDTAct, StartDTCon, StopDTAct, StopDTCon, TestFRAct, TestFRCon} {
		f, err := Parse(apdu(byte(want), 0, 0, 0))
		if err != nil {
			t.Fatalf("%s: %v", want, err)
		}
		if f.Format != FormatU || f.Control != want {
			t.Errorf("%s read as %s %s", want, f.Format, f.Control)
		}
	}
	// A supervisory acknowledgement carries a receive sequence number
	// and nothing else.
	f, err := Parse(apdu(0x01, 0, 0x14, 0x00))
	if err != nil {
		t.Fatal(err)
	}
	if f.Format != FormatS || f.Recv != 10 {
		t.Errorf("S frame: %s recv %d", f.Format, f.Recv)
	}
	// An I frame carries both sequence numbers, shifted out of the
	// control octets, and its ASDU.
	f, err = Parse(iframe(3, 7, asdu(MSpNA1, 1, false, CauseSpontaneous, 1, obj(100, 0x01)...)...))
	if err != nil {
		t.Fatal(err)
	}
	if f.Format != FormatI || f.Send != 3 || f.Recv != 7 {
		t.Errorf("I frame: %s send %d recv %d", f.Format, f.Send, f.Recv)
	}
	if f.ASDU == nil || f.ASDU.Type != MSpNA1 || f.ASDU.Cause != CauseSpontaneous {
		t.Errorf("asdu %+v", f.ASDU)
	}
	// The sequence numbers wrap at 15 bits, and the top of the range has
	// to survive the shift: a relay that truncated here would reject a
	// station's frames once a connection had been up long enough.
	f, err = Parse(iframe(MaxSeq-1, MaxSeq-1, asdu(MSpNA1, 1, false, CauseSpontaneous, 1, obj(1, 0)...)...))
	if err != nil {
		t.Fatal(err)
	}
	if f.Send != MaxSeq-1 || f.Recv != MaxSeq-1 {
		t.Errorf("the top of the sequence space: send %d recv %d", f.Send, f.Recv)
	}
}

// What is not a frame. Every one of these would otherwise be forwarded to
// a substation gateway that will read the octets somehow.
func TestFramesThatAreNotFrames(t *testing.T) {
	good := iframe(0, 0, asdu(MSpNA1, 1, false, CauseSpontaneous, 1, obj(1, 0)...)...)
	for what, tc := range map[string]struct {
		raw  []byte
		want error
	}{
		"no start octet":       {append([]byte{0x67}, good[1:]...), ErrStart},
		"nothing at all":       {nil, ErrStart},
		"an apci and no more":  {[]byte{Start, 4}, ErrStart},
		"a length that lies":   {append([]byte{Start, 99}, good[2:]...), ErrLength},
		"a length of zero":     {[]byte{Start, 0, 0, 0, 0, 0}, ErrLength},
		"an asdu without one":  {iframe(0, 0, 1, 1, 3), ErrShortASDU},
		"more objects than to": {iframe(0, 0, asdu(MSpNA1, 4, false, CauseSpontaneous, 1, obj(1, 0)...)...), ErrObjects},
		"a sequence too short": {iframe(0, 0, asdu(MMeNB1, 8, true, CausePeriodic, 1, obj(1, 0, 0)...)...), ErrObjects},
	} {
		_, err := Parse(tc.raw)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", what, err, tc.want)
		}
	}
	// The length octet's own bounds, which the shapes above do not reach:
	// below the four control octets there is no frame, and above 253 the
	// APDU would be longer than the octet can describe. A reader that
	// took either would hand the next frame's octets to a station as the
	// tail of this one.
	for _, length := range []byte{0, 1, 2, 3, 254, 255} {
		raw := append([]byte{Start, length}, make([]byte, 4)...)
		if _, err := Parse(raw); err == nil {
			t.Errorf("length %d was accepted", length)
		}
		if _, err := NewReader(bytes.NewReader(raw)).ReadFrame(); !errors.Is(err, ErrLength) && !errors.Is(err, ErrStart) {
			t.Errorf("length %d read as %v", length, err)
		}
	}
	// And the smallest frame there is -- four control octets and nothing
	// else -- is a frame.
	if _, err := Parse(apdu(byte(StartDTAct), 0, 0, 0)); err != nil {
		t.Errorf("the shortest frame: %v", err)
	}
	// An S or U frame whose length says it carries a body is refused
	// rather than read as an empty one: that is the shape of an ASDU
	// smuggled past a check that only looks at I frames.
	if _, err := Parse(apdu(byte(StartDTAct), 0, 0, 0, 0x2d, 0x01)); !errors.Is(err, ErrLength) {
		t.Errorf("a U frame with a body: %v", err)
	}
	if _, err := Parse(apdu(0x01, 0, 0, 0, 0x2d, 0x01)); !errors.Is(err, ErrLength) {
		t.Errorf("an S frame with a body: %v", err)
	}
}

// The ASDU header, field by field, because every one of them is something
// a policy is written about.
func TestTheASDUHeaderIsReadFieldByField(t *testing.T) {
	// A negative confirmation of a test command from a station: the two
	// flags share the cause octet, and a relay that read the whole octet
	// as the cause would see COT 199 and refuse a station's own answer.
	body := asdu(CTsNA1, 1, false, CauseActCon, 0x0102, obj(0, 0xaa, 0x55)...)
	body[2] |= 0x40 | 0x80 // negative, test
	body[3] = 9            // originator address
	f, err := Parse(iframe(1, 1, body...))
	if err != nil {
		t.Fatal(err)
	}
	a := f.ASDU
	if a.Type != CTsNA1 || a.Cause != CauseActCon || !a.Negative || !a.Test {
		t.Fatalf("header %+v", a)
	}
	if a.Originator != 9 || a.Common != 0x0102 {
		t.Errorf("originator %d common %d", a.Originator, a.Common)
	}
	if a.Objects != 1 || a.Sequence {
		t.Errorf("objects %d sequence %v", a.Objects, a.Sequence)
	}
}

// Addresses, in both the shapes the standard allows: carried per object,
// or implied by the first one in a sequence. A policy about addresses
// depends on getting this right, and a sequence is how a station sends a
// hundred measurements in one frame.
func TestAddressesAreReadInBothShapes(t *testing.T) {
	// Three separate objects, each with its own address. A scaled
	// measurement is two value octets and a quality descriptor, so each
	// object is six octets -- an element one short is how every address
	// after the first comes out wrong.
	var body []byte
	for _, a := range []uint32{100, 1000, 0x010203} {
		body = append(body, obj(a, 0x11, 0x22, 0x00)...)
	}
	f, err := Parse(iframe(0, 0, asdu(MMeNB1, 3, false, CausePeriodic, 1, body...)...))
	if err != nil {
		t.Fatal(err)
	}
	if got := f.ASDU.Addresses; len(got) != 3 || got[0] != 100 || got[1] != 1000 || got[2] != 0x010203 {
		t.Errorf("addresses %v", got)
	}
	// A sequence: one address then the elements. Only the first address
	// is on the wire, so only the first is reported -- reporting three
	// would be inventing two.
	seq := append(obj(500), 0x11, 0x22, 0x00, 0x33, 0x44, 0x00, 0x55, 0x66, 0x00)
	f, err = Parse(iframe(0, 0, asdu(MMeNB1, 3, true, CausePeriodic, 1, seq...)...))
	if err != nil {
		t.Fatal(err)
	}
	if got := f.ASDU.Addresses; len(got) != 1 || got[0] != 500 {
		t.Errorf("sequence addresses %v", got)
	}
	if !f.ASDU.Sequence {
		t.Error("the sequence flag was lost")
	}
	// A *sequence* of commands, which is the other place the select bit
	// lives: one address and then the elements, so the qualifier of the
	// first element is where the bit is. A relay that read the bit only
	// in the per-object shape would let a sequence of selects through as
	// executes.
	f, err = Parse(iframe(0, 0, asdu(CScNA1, 2, true, CauseActivation, 1, append(obj(4321), 0x81, 0x81)...)...))
	if err != nil {
		t.Fatal(err)
	}
	if !f.ASDU.Select || len(f.ASDU.Qualifier) != 1 || f.ASDU.Qualifier[0] != 0x81 {
		t.Errorf("a sequence of selects: %+v", f.ASDU)
	}
	f, err = Parse(iframe(0, 0, asdu(CScNA1, 2, true, CauseActivation, 1, append(obj(4321), 0x01, 0x01)...)...))
	if err != nil {
		t.Fatal(err)
	}
	if f.ASDU.Select {
		t.Errorf("a sequence of executes read as selects: %+v", f.ASDU)
	}
	// A qualifier of zero objects is not a frame to reject: some
	// implementations send one, and there is simply nothing to read.
	f, err = Parse(iframe(0, 0, asdu(MMeNB1, 0, false, CausePeriodic, 1)...))
	if err != nil || len(f.ASDU.Addresses) != 0 {
		t.Errorf("zero objects: %v %v", err, f)
	}
	// A type this does not know is forwarded with its addresses unread
	// rather than guessed at: inventing an object size would misreport
	// an address, and a policy would then refuse or allow the wrong one.
	f, err = Parse(iframe(0, 0, asdu(Type(200), 1, false, CauseSpontaneous, 1, 1, 2, 3, 4)...))
	if err != nil {
		t.Fatal(err)
	}
	if f.ASDU.Type.Known() || len(f.ASDU.Addresses) != 0 {
		t.Errorf("an unknown type: %+v", f.ASDU)
	}
}

// The select bit, which is what select-before-operate is built on.
func TestTheSelectBitIsReadFromTheCommandQualifier(t *testing.T) {
	// A select: single command, activation, S/E set.
	f, err := Parse(iframe(0, 0, asdu(CScNA1, 1, false, CauseActivation, 1, obj(4321, 0x81)...)...))
	if err != nil {
		t.Fatal(err)
	}
	if !f.ASDU.Select || len(f.ASDU.Qualifier) != 1 {
		t.Fatalf("select: %+v", f.ASDU)
	}
	// And the execute that follows it: the same command without the bit.
	f, err = Parse(iframe(1, 0, asdu(CScNA1, 1, false, CauseActivation, 1, obj(4321, 0x01)...)...))
	if err != nil {
		t.Fatal(err)
	}
	if f.ASDU.Select {
		t.Errorf("execute read as select: %+v", f.ASDU)
	}
	// A setpoint's qualifier is its value and the qualifier octet, and
	// the select bit is in the last one, not the first.
	f, err = Parse(iframe(2, 0, asdu(CSeNB1, 1, false, CauseActivation, 1, obj(7, 0x34, 0x12, 0x80)...)...))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.ASDU.Qualifier) != 3 || f.ASDU.Qualifier[0] != 0x34 {
		t.Errorf("setpoint qualifier %v", f.ASDU.Qualifier)
	}
	// A monitoring type carries no command qualifier at all, and must
	// not appear to carry a selection.
	f, err = Parse(iframe(3, 0, asdu(MSpNA1, 1, false, CauseSpontaneous, 1, obj(7, 0x81)...)...))
	if err != nil {
		t.Fatal(err)
	}
	if f.ASDU.Select || f.ASDU.Qualifier != nil {
		t.Errorf("a measurement looked like a selection: %+v", f.ASDU)
	}
}

// The reader over a stream, including the two things a stream does that a
// buffer does not: end in the middle, and carry several frames back to
// back.
func TestTheReaderReadsFrameAfterFrame(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(apdu(byte(StartDTAct), 0, 0, 0))
	buf.Write(iframe(0, 0, asdu(MSpNA1, 1, false, CauseSpontaneous, 1, obj(1, 0)...)...))
	buf.Write(apdu(0x01, 0, 0x02, 0x00))
	rd := NewReader(&buf)
	for i, want := range []Format{FormatU, FormatI, FormatS} {
		f, err := rd.ReadFrame()
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if f.Format != want {
			t.Errorf("frame %d: %s, want %s", i, f.Format, want)
		}
		// The raw octets are kept, because a relay forwards what it read
		// rather than re-encoding: re-encoding is how a relay and a
		// station come to disagree about what was said.
		if f.Raw[0] != Start || int(f.Raw[1]) != len(f.Raw)-2 {
			t.Errorf("frame %d raw %x", i, f.Raw)
		}
	}
	if _, err := rd.ReadFrame(); !errors.Is(err, io.EOF) {
		t.Errorf("at the end: %v", err)
	}
	// A frame cut short is an unexpected end, not a frame.
	short := iframe(0, 0, asdu(MSpNA1, 1, false, CauseSpontaneous, 1, obj(1, 0)...)...)
	rd = NewReader(bytes.NewReader(short[:len(short)-2]))
	if _, err := rd.ReadFrame(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("a frame cut short: %v", err)
	}
	// And a stream that is not this protocol stops rather than hunting
	// for the next start octet, which it would find inside a
	// measurement as often as at a frame boundary.
	rd = NewReader(bytes.NewReader([]byte{0x16, 0x10, 0x68, 0x04, 0x07, 0, 0, 0}))
	if _, err := rd.ReadFrame(); !errors.Is(err, ErrStart) {
		t.Errorf("a stream that is not iec 104: %v", err)
	}
}

// The names an operator writes, against the numbers on the wire. The
// names are the standard's own because that is what the substation
// documentation says, and a translation an operator has to do in their
// head is a misconfiguration waiting to happen.
func TestTheNamesAreTheStandardsOwn(t *testing.T) {
	for name, want := range map[string]Type{
		"C_SC_NA_1": 45, "C_DC_NA_1": 46, "C_RC_NA_1": 47, "C_SE_NC_1": 50,
		"C_IC_NA_1": 100, "C_CS_NA_1": 103, "C_RP_NA_1": 105,
		"M_SP_NA_1": 1, "M_ME_TF_1": 36, "F_SG_NA_1": 125,
		"c_sc_na_1": 45, // case does not matter, because documentation varies
	} {
		got, ok := TypeOf(name)
		if !ok || got != want {
			t.Errorf("%s: %d %v, want %d", name, got, ok, want)
		}
	}
	if _, ok := TypeOf("C_SC_NA_2"); ok {
		t.Error("a type that does not exist was accepted")
	}
	if got := CScNA1.String(); got != "C_SC_NA_1" {
		t.Errorf("name %q", got)
	}
	if got := Type(200).String(); got != "TYPE_200" {
		t.Errorf("an undefined type reads as %q", got)
	}
	for name, want := range map[string]Cause{
		"act": 6, "actcon": 7, "deact": 8, "spont": 3, "introgen": 20,
		"introgroup1": 21, "introgroup16": 36, "ACT": 6,
	} {
		got, ok := CauseOf(name)
		if !ok || got != want {
			t.Errorf("cause %s: %d %v, want %d", name, got, ok, want)
		}
	}
	if _, ok := CauseOf("whenever"); ok {
		t.Error("a cause that does not exist was accepted")
	}
	if got := CauseActivation.String(); got != "act" {
		t.Errorf("cause name %q", got)
	}
	if got := Cause(60).String(); got != "COT_60" {
		t.Errorf("an undefined cause reads as %q", got)
	}
	for name, want := range map[string]Control{
		"STARTDT_act": StartDTAct, "stopdt_act": StopDTAct, "TESTFR_con": TestFRCon,
	} {
		got, ok := ControlOf(name)
		if !ok || got != want {
			t.Errorf("control %s: %v %v", name, got, ok)
		}
	}
	if _, ok := ControlOf("RESETDT_act"); ok {
		t.Error("a control function that does not exist was accepted")
	}
}

// The classification a policy is written in terms of. Getting the
// boundaries wrong is how "allow only monitoring" comes to allow a breaker
// trip.
func TestTypesAreClassifiedByWhatTheyDo(t *testing.T) {
	for _, tc := range []struct {
		t                         Type
		monitoring, command, syst bool
		selectable                bool
	}{
		{MSpNA1, true, false, false, false},
		{MMeTF1, true, false, false, false},
		{CScNA1, false, true, false, true},
		{CDcTA1, false, true, false, true},
		{CBoNA1, false, true, false, false}, // a 32-bit output has no two-step form
		{CBoTA1, false, true, false, false},
		{CIcNA1, false, false, true, false},
		{CCsNA1, false, false, true, false}, // the clock, which moves every timestamp
		{CRpNA1, false, false, true, false}, // the reset, which reboots a station
		{PMeNA1, false, false, false, false},
		{FSgNA1, false, false, false, false},
	} {
		if got := tc.t.Monitoring(); got != tc.monitoring {
			t.Errorf("%s monitoring %v", tc.t, got)
		}
		if got := tc.t.Command(); got != tc.command {
			t.Errorf("%s command %v", tc.t, got)
		}
		if got := tc.t.System(); got != tc.syst {
			t.Errorf("%s system %v", tc.t, got)
		}
		if got := tc.t.SelectSupported(); got != tc.selectable {
			t.Errorf("%s selectable %v", tc.t, got)
		}
	}
	// Only activation and deactivation ask a station to do something. A
	// confirmation carries the same type identification and is the
	// station answering, which a relay must not refuse.
	for c, want := range map[Cause]bool{
		CauseActivation: true, CauseDeactivation: true,
		CauseActCon: false, CauseDeactCon: false, CauseActTerm: false,
		CauseSpontaneous: false, CausePeriodic: false,
	} {
		if got := c.Commanding(); got != want {
			t.Errorf("%s commanding %v", c, got)
		}
	}
}
