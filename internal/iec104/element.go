package iec104

import (
	"encoding/binary"
	"math"
	"strings"
	"time"
)

// The information element: what an information object actually says.
//
// The header of an ASDU says what kind of thing is being reported and about
// which addresses; the element says the thing itself. A relay that read only the
// header could decide about *which* points a station reports and never about
// what it reports of them -- and three of the questions an operator most wants
// asked are in the element rather than the header:
//
//   - **Is this value real?** Every monitored type but one carries a quality
//     descriptor. `SB`, substituted, means a human typed the value in rather than
//     an instrument measuring it. `IV`, invalid, means the device itself says not
//     to trust it. A control centre acting on a substituted value is acting on
//     somebody's opinion, and neither bit reaches the screen of most HMIs.
//
//   - **When did this happen?** A time-tagged command carries a CP56Time2a, and
//     a command replayed an hour later carries the hour-old timestamp with it.
//     That is the cheapest application-layer replay check this protocol offers,
//     and IEC 62351-5 exists in part because nothing in 60870-5-104 itself makes
//     anybody perform it.
//
//   - **What is the value?** `setpoints` already bounds what a control centre may
//     command. The same arithmetic applied to what a station *reports* is how a
//     measurement outside the instrument's own range -- a pressure of 900 bar on a
//     40 bar transmitter -- becomes something an operator is told about rather
//     than something that sits on a trend.
//
// The decoding here is per the element layouts of IEC 60870-5-101 section 7.3.1,
// which IEC 60870-5-104 carries unchanged. Every layout is a table entry rather
// than a special case in a parser, because the table is what can be checked
// against the standard by reading it.

// Quality is the quality descriptor's bits, as they arrive.
//
// The same five bits appear in the QDS octet of a measurement, in the SIQ octet
// of a single point and in the DIQ octet of a double point, which is why one type
// covers all three: an operator's question ("is anything reporting a substituted
// value?") is the same question whatever the point is.
type Quality byte

// The bits, at the positions the standard puts them. OV is only defined for the
// types that can overflow; the other four are in every quality octet.
const (
	// QualityOverflow is OV: the value is outside the range the type can
	// carry, so the number that arrived is not the number that was measured.
	QualityOverflow Quality = 0x01
	// QualityBlocked is BL: the point is blocked for transmission at the
	// station, so what arrives is held rather than current.
	QualityBlocked Quality = 0x10
	// QualitySubstituted is SB: the value was entered by a person rather than
	// measured. It is the bit worth an alert -- a control centre acting on a
	// substituted value is acting on somebody's opinion of the plant.
	QualitySubstituted Quality = 0x20
	// QualityNotTopical is NT: the value has not been refreshed within the
	// time it should have been, so it is stale.
	QualityNotTopical Quality = 0x40
	// QualityInvalid is IV: the station itself says the value is not to be
	// trusted.
	QualityInvalid Quality = 0x80
)

func (q Quality) Overflow() bool    { return q&QualityOverflow != 0 }
func (q Quality) Blocked() bool     { return q&QualityBlocked != 0 }
func (q Quality) Substituted() bool { return q&QualitySubstituted != 0 }
func (q Quality) NotTopical() bool  { return q&QualityNotTopical != 0 }
func (q Quality) Invalid() bool     { return q&QualityInvalid != 0 }

// Bad says whether any of the four bits that mean "do not act on this" is set.
// Overflow is left out: an overflowed value is a real reading of a real
// instrument that has gone past its scale, which is a process event rather than
// a data-quality one.
func (q Quality) Bad() bool {
	return q&(QualityBlocked|QualitySubstituted|QualityNotTopical|QualityInvalid) != 0
}

// String names the bits that are set, in the order an operator reads them, and
// is empty for a value with nothing wrong with it.
func (q Quality) String() string {
	var out []string
	if q.Invalid() {
		out = append(out, "invalid")
	}
	if q.NotTopical() {
		out = append(out, "not_topical")
	}
	if q.Substituted() {
		out = append(out, "substituted")
	}
	if q.Blocked() {
		out = append(out, "blocked")
	}
	if q.Overflow() {
		out = append(out, "overflow")
	}
	return strings.Join(out, ",")
}

// QualityBitOf maps a configured name onto its bit.
func QualityBitOf(name string) (Quality, bool) {
	switch name {
	case "invalid":
		return QualityInvalid, true
	case "not_topical":
		return QualityNotTopical, true
	case "substituted":
		return QualitySubstituted, true
	case "blocked":
		return QualityBlocked, true
	case "overflow":
		return QualityOverflow, true
	}
	return 0, false
}

// QualityNames is every name a policy may use, for the reference and for
// validation.
var QualityNames = []string{"invalid", "not_topical", "substituted", "blocked", "overflow"}

// ValueKind says what an element's number is, because the number alone does not
// say. A policy bound of "between 0 and 40" means something different against a
// normalised value (a fraction of a full scale this relay cannot see) than
// against a short float in engineering units, and the reference says so.
type ValueKind int

// The kinds, in the order the standard introduces them.
const (
	// NoValue is an element this package does not read a number out of.
	NoValue ValueKind = iota
	// SinglePoint is one bit: off or on.
	SinglePoint
	// DoublePoint is two bits: intermediate, off, on, indeterminate.
	DoublePoint
	// StepPosition is a transformer tap or similar, -64 to 63, with a
	// transient flag beside it.
	StepPosition
	// BitString is 32 bits with no arithmetic meaning, reported as the
	// unsigned number they spell so that a policy can compare it at all.
	BitString
	// Normalised is a fraction of a full scale configured in the device: the
	// signed 16-bit value over 2^15.
	Normalised
	// Scaled is a signed 16-bit integer in whatever unit the device was
	// configured with.
	Scaled
	// ShortFloat is an IEEE 754 single, which is the only encoding here that
	// is in engineering units without a scale factor kept elsewhere.
	ShortFloat
	// Counter is an integrated total: a signed 32-bit accumulator with a
	// sequence number and three flags beside it.
	Counter
)

// String names the kind for a log line and the report.
func (k ValueKind) String() string {
	switch k {
	case SinglePoint:
		return "single_point"
	case DoublePoint:
		return "double_point"
	case StepPosition:
		return "step_position"
	case BitString:
		return "bitstring"
	case Normalised:
		return "normalised"
	case Scaled:
		return "scaled"
	case ShortFloat:
		return "short_float"
	case Counter:
		return "counter"
	}
	return "none"
}

// timeKind says which of the protocol's two time tags an element carries.
type timeKind int

const (
	noTime timeKind = iota
	// cp24 is three octets: milliseconds and minutes, and no date at all.
	// Nothing can be said about its age, because the date it belongs to is
	// whatever the reader assumes.
	cp24
	// cp56 is seven octets: milliseconds through year. This is the one an age
	// check can be made against.
	cp56
)

// layout is where the parts of one information element are.
//
// Offsets are from the start of the element, which is after the three-octet
// information object address. A negative offset means the part is not there.
type layout struct {
	kind    ValueKind
	valueAt int
	// qualityAt is the octet carrying the quality bits. For a single or double
	// point that is the same octet as the value, which is why the two are
	// separate fields rather than one.
	qualityAt int
	timeAt    int
	timeKind  timeKind
}

// layouts is the element layout of every type this package decodes, per
// IEC 60870-5-101 section 7.3.1.
//
// A type absent from this table is one whose elements are not decoded: its
// addresses are still read, its header is still policed, and no claim is made
// about what its objects say. That is the honest failure -- a layout guessed at
// would report a quality bit from the middle of a value.
var layouts = map[Type]layout{
	// Process information, monitored, without a time tag.
	MSpNA1: {kind: SinglePoint, valueAt: 0, qualityAt: 0, timeAt: -1},
	MDpNA1: {kind: DoublePoint, valueAt: 0, qualityAt: 0, timeAt: -1},
	MStNA1: {kind: StepPosition, valueAt: 0, qualityAt: 1, timeAt: -1},
	MBoNA1: {kind: BitString, valueAt: 0, qualityAt: 4, timeAt: -1},
	MMeNA1: {kind: Normalised, valueAt: 0, qualityAt: 2, timeAt: -1},
	MMeNB1: {kind: Scaled, valueAt: 0, qualityAt: 2, timeAt: -1},
	MMeNC1: {kind: ShortFloat, valueAt: 0, qualityAt: 4, timeAt: -1},
	MItNA1: {kind: Counter, valueAt: 0, qualityAt: -1, timeAt: -1},
	// M_ME_ND_1 is the measurement without a quality descriptor, which is what
	// the D in its name is for. A policy about quality has nothing to ask of
	// it, and saying so is the point of the separate type.
	MMeND1: {kind: Normalised, valueAt: 0, qualityAt: -1, timeAt: -1},

	// The same, with a three-octet time tag that carries no date.
	MSpTA1: {kind: SinglePoint, valueAt: 0, qualityAt: 0, timeAt: 1, timeKind: cp24},
	MDpTA1: {kind: DoublePoint, valueAt: 0, qualityAt: 0, timeAt: 1, timeKind: cp24},
	MStTA1: {kind: StepPosition, valueAt: 0, qualityAt: 1, timeAt: 2, timeKind: cp24},
	MBoTA1: {kind: BitString, valueAt: 0, qualityAt: 4, timeAt: 5, timeKind: cp24},
	MMeTA1: {kind: Normalised, valueAt: 0, qualityAt: 2, timeAt: 3, timeKind: cp24},
	MMeTB1: {kind: Scaled, valueAt: 0, qualityAt: 2, timeAt: 3, timeKind: cp24},
	MMeTC1: {kind: ShortFloat, valueAt: 0, qualityAt: 4, timeAt: 5, timeKind: cp24},
	MItTA1: {kind: Counter, valueAt: 0, qualityAt: -1, timeAt: 5, timeKind: cp24},

	// And with the seven-octet tag that carries a date, which is the one an age
	// can be measured against.
	MSpTB1: {kind: SinglePoint, valueAt: 0, qualityAt: 0, timeAt: 1, timeKind: cp56},
	MDpTB1: {kind: DoublePoint, valueAt: 0, qualityAt: 0, timeAt: 1, timeKind: cp56},
	MStTB1: {kind: StepPosition, valueAt: 0, qualityAt: 1, timeAt: 2, timeKind: cp56},
	MBoTB1: {kind: BitString, valueAt: 0, qualityAt: 4, timeAt: 5, timeKind: cp56},
	MMeTD1: {kind: Normalised, valueAt: 0, qualityAt: 2, timeAt: 3, timeKind: cp56},
	MMeTE1: {kind: Scaled, valueAt: 0, qualityAt: 2, timeAt: 3, timeKind: cp56},
	MMeTF1: {kind: ShortFloat, valueAt: 0, qualityAt: 4, timeAt: 5, timeKind: cp56},
	MItTB1: {kind: Counter, valueAt: 0, qualityAt: -1, timeAt: 5, timeKind: cp56},

	// Commands. The value of a setpoint command is already read by Setpoint;
	// what matters here is the time tag, because a time-tagged command is the
	// one whose replay this relay can notice.
	CScNA1: {kind: SinglePoint, valueAt: 0, qualityAt: -1, timeAt: -1},
	CDcNA1: {kind: DoublePoint, valueAt: 0, qualityAt: -1, timeAt: -1},
	CRcNA1: {kind: DoublePoint, valueAt: 0, qualityAt: -1, timeAt: -1},
	CBoNA1: {kind: BitString, valueAt: 0, qualityAt: -1, timeAt: -1},
	CSeNA1: {kind: Normalised, valueAt: 0, qualityAt: -1, timeAt: -1},
	CSeNB1: {kind: Scaled, valueAt: 0, qualityAt: -1, timeAt: -1},
	CSeNC1: {kind: ShortFloat, valueAt: 0, qualityAt: -1, timeAt: -1},

	CScTA1: {kind: SinglePoint, valueAt: 0, qualityAt: -1, timeAt: 1, timeKind: cp56},
	CDcTA1: {kind: DoublePoint, valueAt: 0, qualityAt: -1, timeAt: 1, timeKind: cp56},
	CRcTA1: {kind: DoublePoint, valueAt: 0, qualityAt: -1, timeAt: 1, timeKind: cp56},
	CBoTA1: {kind: BitString, valueAt: 0, qualityAt: -1, timeAt: 4, timeKind: cp56},
	CSeTA1: {kind: Normalised, valueAt: 0, qualityAt: -1, timeAt: 3, timeKind: cp56},
	CSeTB1: {kind: Scaled, valueAt: 0, qualityAt: -1, timeAt: 3, timeKind: cp56},
	CSeTC1: {kind: ShortFloat, valueAt: 0, qualityAt: -1, timeAt: 5, timeKind: cp56},
}

// Decodes says whether this package reads the elements of a type.
func Decodes(t Type) bool {
	_, ok := layouts[t]
	return ok
}

// Element is one decoded information object.
type Element struct {
	// Address is the information object address this element belongs to.
	Address uint32
	// Kind says what Value is, and Value is the number whatever the encoding
	// on the wire was. A policy bound is written against the number; the kind
	// is what says what the number means.
	Kind     ValueKind
	Value    float64
	HasValue bool
	// Quality is the quality descriptor, and HasQuality whether the type
	// carries one at all: absent is not the same as good, and a policy that
	// treated M_ME_ND_1 as quality-good would be asserting something the wire
	// never said.
	Quality    Quality
	HasQuality bool
	// Transient is a step position's own flag: the tap is moving, so the
	// position is somewhere between two.
	Transient bool
	// Time is the element's time tag as an instant, and HasTime whether one
	// was carried. A CP24Time2a has no date, so HasDate is false for it and
	// nothing can be concluded about its age -- the instant is minutes and
	// milliseconds inside an unknown hour.
	Time    time.Time
	HasTime bool
	HasDate bool
	// TimeInvalid is the time tag's own IV bit: the station says its clock is
	// not to be trusted. A command carrying it has told the relay that its
	// timestamp means nothing, which is a thing a policy may refuse rather
	// than a thing to silently accept.
	TimeInvalid bool
	// TimeSummer is the SU bit of a CP56Time2a: the time is summer time. It is
	// carried because a station that sets it and a control centre that ignores
	// it disagree about an hour, twice a year.
	TimeSummer bool
	// CounterSequence is an integrated total's sequence number, and
	// CounterCarry, CounterAdjusted and CounterInvalid its three flags. A
	// counter whose carry bit is set has wrapped since the last read, which is
	// what makes a difference between two readings wrong.
	CounterSequence byte
	CounterCarry    bool
	CounterAdjusted bool
	CounterInvalid  bool
}

// Elements decodes the information objects of an ASDU.
//
// raw is the ASDU exactly as it arrived, the same octets Parse was given, because
// the elements are not retained: the reader's buffer is reused between frames, so
// an ASDU that kept a slice of it would report the next frame's octets.
//
// It returns nothing for a type whose layout this package does not have, and for
// a type it does have it returns one element per object -- or, for a sequence,
// one per element with the addresses counted up from the first, which is what a
// sequence means.
func (a *ASDU) Elements(raw []byte) []Element {
	if a == nil || a.Objects == 0 {
		return nil
	}
	lay, ok := layouts[a.Type]
	if !ok {
		return nil
	}
	size, known := objectSize(a.Type)
	if !known || size == 0 || len(raw) < ASDUHeaderLen {
		return nil
	}
	body := raw[ASDUHeaderLen:]
	out := make([]Element, 0, a.Objects)
	if a.Sequence {
		// One address, then the elements. The addresses of the rest are that
		// one counted up, which is the whole point of the sequence bit.
		if len(body) < 3+size*a.Objects {
			return nil
		}
		base := addr3(body)
		for i := 0; i < a.Objects; i++ {
			at := body[3+i*size:]
			out = append(out, decodeElement(base+uint32(i), at[:size], lay)) //nolint:gosec // Objects is at most 127
		}
		return out
	}
	if len(body) < (3+size)*a.Objects {
		return nil
	}
	for i := 0; i < a.Objects; i++ {
		at := body[i*(3+size):]
		out = append(out, decodeElement(addr3(at), at[3:3+size], lay))
	}
	return out
}

// decodeElement reads one element against its layout.
func decodeElement(addr uint32, e []byte, lay layout) Element {
	el := Element{Address: addr, Kind: lay.kind}
	if lay.qualityAt >= 0 && lay.qualityAt < len(e) {
		// Only the bits this package defines are kept. A station that sets one
		// of the reserved bits has not said anything about quality, and a
		// Quality carrying it would compare unequal to the same quality from a
		// station that left it clear.
		el.Quality = Quality(e[lay.qualityAt]) & (QualityOverflow | QualityBlocked |
			QualitySubstituted | QualityNotTopical | QualityInvalid)
		// A single or double point keeps its quality bits in the same octet as
		// its state, so the state bits are cleared: SIQ's one bit sits where OV
		// does, and DIQ's two sit across OV and a reserved bit. A double point
		// reporting "indeterminate" is not a point reporting an overflow.
		switch lay.kind {
		case SinglePoint:
			el.Quality &^= 0x01
		case DoublePoint:
			el.Quality &^= 0x03
		default:
		}
		el.HasQuality = true
	}
	el.Value, el.HasValue, el.Transient = decodeValue(e, lay)
	if lay.kind == Counter && len(e) >= lay.valueAt+5 {
		f := e[lay.valueAt+4]
		el.CounterSequence = f & 0x1f
		el.CounterCarry = f&0x20 != 0
		el.CounterAdjusted = f&0x40 != 0
		el.CounterInvalid = f&0x80 != 0
	}
	if lay.timeAt >= 0 {
		switch lay.timeKind {
		case cp56:
			if t, iv, su, ok := decodeCP56(e, lay.timeAt); ok {
				el.Time, el.TimeInvalid, el.TimeSummer = t, iv, su
				el.HasTime, el.HasDate = true, true
			}
		case cp24:
			if t, iv, ok := decodeCP24(e, lay.timeAt); ok {
				el.Time, el.TimeInvalid = t, iv
				el.HasTime = true
			}
		case noTime:
		}
	}
	return el
}

// decodeValue reads the number out of an element.
func decodeValue(e []byte, lay layout) (val float64, ok bool, transient bool) {
	at := lay.valueAt
	switch lay.kind {
	case SinglePoint:
		if at >= len(e) {
			return 0, false, false
		}
		return float64(e[at] & 0x01), true, false
	case DoublePoint:
		if at >= len(e) {
			return 0, false, false
		}
		return float64(e[at] & 0x03), true, false
	case StepPosition:
		if at >= len(e) {
			return 0, false, false
		}
		// Seven bits of two's complement, -64 to 63, and bit 8 says the tap is
		// in transit. Sign-extending is the decoding: a position of -1 arrives
		// as 0x7f, and reading it unsigned would report tap 127 on a
		// transformer that has nineteen.
		v := int8(e[at]&0x7f) << 1 / 2 //nolint:gosec // seven-bit two's complement, sign-extended
		return float64(v), true, e[at]&0x80 != 0
	case BitString:
		if at+4 > len(e) {
			return 0, false, false
		}
		// Thirty-two bits with no arithmetic meaning, reported as the unsigned
		// number they spell. Every value up to 2^32 is exact in a float64, so
		// nothing is lost by carrying it as one.
		return float64(binary.LittleEndian.Uint32(e[at:])), true, false
	case Normalised:
		if at+2 > len(e) {
			return 0, false, false
		}
		return float64(signed16(e[at:])) / 32768, true, false
	case Scaled:
		if at+2 > len(e) {
			return 0, false, false
		}
		return float64(signed16(e[at:])), true, false
	case ShortFloat:
		if at+4 > len(e) {
			return 0, false, false
		}
		return float64(math.Float32frombits(binary.LittleEndian.Uint32(e[at:]))), true, false
	case Counter:
		if at+4 > len(e) {
			return 0, false, false
		}
		return float64(int32(binary.LittleEndian.Uint32(e[at:]))), true, false //nolint:gosec // the standard's own signed accumulator
	case NoValue:
		return 0, false, false
	}
	return 0, false, false
}

// decodeCP56 reads a seven-octet CP56Time2a.
//
// The layout, low octet first: two octets of milliseconds within the minute,
// then minutes with IV in bit 8, then hours with SU in bit 8, then the day of
// the month in bits 1..5 (the day of the week is bits 6..8 and is not read --
// two sources for one fact, and the date is the one that counts), then the month
// in bits 1..4, then the year in bits 1..7 as an offset from 2000.
//
// The instant is built in UTC. The standard leaves the zone to the estate, and a
// relay that applied its own local zone would put a substation's timestamps an
// hour out wherever the two disagree; an age check compares two instants read the
// same way, which is what makes it meaningful without knowing the zone.
func decodeCP56(e []byte, at int) (t time.Time, invalid, summer bool, ok bool) {
	if at+7 > len(e) {
		return time.Time{}, false, false, false
	}
	b := e[at : at+7]
	ms := int(binary.LittleEndian.Uint16(b[0:2]))
	minute := int(b[2] & 0x3f)
	invalid = b[2]&0x80 != 0
	hour := int(b[3] & 0x1f)
	summer = b[3]&0x80 != 0
	day := int(b[4] & 0x1f)
	month := int(b[5] & 0x0f)
	year := 2000 + int(b[6]&0x7f)
	// A field outside its range is a timestamp that means nothing, and
	// time.Date would normalise it into a different date rather than say so --
	// month 13 becomes January of the next year. So it is reported as no
	// timestamp, which a policy requiring one then refuses.
	if minute > 59 || hour > 23 || day < 1 || day > 31 || month < 1 || month > 12 || ms > 59999 {
		return time.Time{}, invalid, summer, false
	}
	return time.Date(year, time.Month(month), day, hour, minute, ms/1000,
		(ms%1000)*int(time.Millisecond), time.UTC), invalid, summer, true
}

// decodeCP24 reads a three-octet CP24Time2a: milliseconds and minutes, and no
// date at all.
//
// The instant returned is inside the zero year, because there is no date to put
// it in. It is enough to compare two elements of the same minute and not enough
// to say anything about age, which is why HasDate stays false and the age policy
// says it applies to CP56Time2a only.
func decodeCP24(e []byte, at int) (t time.Time, invalid, ok bool) {
	if at+3 > len(e) {
		return time.Time{}, false, false
	}
	b := e[at : at+3]
	ms := int(binary.LittleEndian.Uint16(b[0:2]))
	minute := int(b[2] & 0x3f)
	invalid = b[2]&0x80 != 0
	if minute > 59 || ms > 59999 {
		return time.Time{}, invalid, false
	}
	return time.Date(0, time.January, 1, 0, minute, ms/1000,
		(ms%1000)*int(time.Millisecond), time.UTC), invalid, true
}
