package opcua

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"time"
)

// BuiltinType is the type identifier in a Variant's encoding mask: which of the
// twenty-five built-in types the value is.
type BuiltinType byte

// The built-in types of IEC 62541-6 table 1, in their encoding-mask order.
const (
	TypeNull BuiltinType = iota
	TypeBoolean
	TypeSByte
	TypeByte
	TypeInt16
	TypeUInt16
	TypeInt32
	TypeUInt32
	TypeInt64
	TypeUInt64
	TypeFloat
	TypeDouble
	TypeString
	TypeDateTime
	TypeGuid
	TypeByteString
	TypeXMLElement
	TypeNodeId
	TypeExpandedNodeId
	TypeStatusCode
	TypeQualifiedName
	TypeLocalizedText
	TypeExtensionObject
	TypeDataValue
	TypeVariant
	TypeDiagnosticInfo
)

var typeNames = [...]string{
	"null", "boolean", "sbyte", "byte", "int16", "uint16", "int32", "uint32",
	"int64", "uint64", "float", "double", "string", "datetime", "guid",
	"bytestring", "xmlelement", "nodeid", "expandednodeid", "statuscode",
	"qualifiedname", "localizedtext", "extensionobject", "datavalue", "variant",
	"diagnosticinfo",
}

func (t BuiltinType) String() string {
	if int(t) < len(typeNames) {
		return typeNames[t]
	}
	return fmt.Sprintf("type(%d)", byte(t))
}

// Known says the type is one of the twenty-five the standard defines. Numbers above
// them are reserved and a Variant naming one is a value this package cannot read —
// and, because a Variant has no length prefix, a value nothing after it can be read
// past either.
func (t BuiltinType) Known() bool { return t <= TypeDiagnosticInfo }

// Numeric says the type is one whose value a range or rate-of-change rule can be
// written against. It is the question an OT policy asks, and the answer excludes
// Boolean deliberately: a boolean is a state, and a rule about it is a transition
// rule rather than a range.
func (t BuiltinType) Numeric() bool {
	return t >= TypeSByte && t <= TypeDouble
}

// The Variant encoding-mask bits above the type.
const (
	variantType   = 0x3F
	variantDims   = 0x40
	variantArray  = 0x80
	maxVariantDim = 8
)

// A Variant is one value of any built-in type, which is what every Read returns and
// every Write carries.
//
// The type is kept alongside the value rather than collapsed into an `any`, because
// a policy written about a value has to know what it is comparing: a setpoint
// arriving as a Double where the server holds an Int16 is a different event from a
// setpoint out of range, and a rule that silently converted would report the wrong
// one.
type Variant struct {
	// Type is the built-in type of the value, or of the array's elements.
	Type BuiltinType
	// Array says the value is an array rather than a scalar.
	Array bool
	// Dimensions is the multidimensional shape, when one was given.
	Dimensions []int32
	// Num holds the value for the numeric types, converted to a float64 so one
	// comparison serves all of them. It is exact for every integer type up to
	// 2^53 and for Float; beyond that an Int64 loses precision, which is stated
	// here rather than hidden because a rule about a 64-bit counter's exact value
	// is a rule that needs Ints.
	Num float64
	// Ints holds the exact value for the integer types, which is what an equality
	// rule and a counter need.
	Ints int64
	// Bool holds the value for Boolean.
	Bool bool
	// Text holds it for the string-like types and the rendered form for Guid,
	// ByteString and XmlElement.
	Text string
	// Node holds it for NodeId and ExpandedNodeId.
	Node NodeId
	// Status holds it for StatusCode.
	Status uint32
	// Time holds it for DateTime.
	Time time.Time
	// Count is the element count for an array, whose elements this type does not
	// keep: a rule about an array's elements is a rule about a thousand values,
	// and the bound that matters is the count. Scalars report zero.
	Count int
	// Elems holds the elements of a numeric array up to MaxArrayValues, which is
	// what a range rule over an array of setpoints needs.
	Elems []float64
}

// MaxArrayValues bounds the array elements this package keeps. An array longer than
// this is still counted and still bounded by MaxArray; its elements are simply not
// retained, because a policy that examined ten thousand of them per message would
// be the amplifier.
const MaxArrayValues = 64

// maxVariantDepth bounds the recursion through the three types that nest: a
// Variant inside a Variant, a DataValue inside one, an ExtensionObject's body.
const maxVariantDepth = 8

// variant reads a Variant at the cursor.
func (r *reader) variant(depth int) Variant {
	if depth > maxVariantDepth {
		r.fail("%w: a variant nested %d deep", ErrTooLong, depth)
		return Variant{}
	}
	mask := r.byte()
	if r.err != nil {
		return Variant{}
	}
	v := Variant{Type: BuiltinType(mask & variantType)}
	if !v.Type.Known() {
		r.fail("%w: a variant of built-in type %d", ErrEncoding, byte(v.Type))
		return Variant{}
	}
	if v.Type == TypeNull {
		if mask&variantArray != 0 {
			// An array of nothing is not a shape the encoding defines: there is
			// no element to count the length of.
			r.fail("%w: an array variant of the null type", ErrEncoding)
		}
		return v
	}
	if mask&variantArray == 0 {
		r.value(&v, depth)
		return v
	}
	v.Array = true
	n := r.arrayLen("variant array")
	if r.err != nil {
		return Variant{}
	}
	v.Count = n
	for i := 0; i < n; i++ {
		var e Variant
		e.Type = v.Type
		r.value(&e, depth)
		if r.err != nil {
			return Variant{}
		}
		if v.Type.Numeric() && len(v.Elems) < MaxArrayValues {
			v.Elems = append(v.Elems, e.Num)
		}
	}
	if mask&variantDims != 0 {
		d := r.arrayLen("variant dimensions")
		if d > maxVariantDim {
			r.fail("%w: %d array dimensions", ErrTooLong, d)
			return Variant{}
		}
		for i := 0; i < d; i++ {
			v.Dimensions = append(v.Dimensions, r.int32())
		}
	}
	return v
}

// value reads one value of v.Type into v. It is where every built-in type's wire
// form lives, and it is exhaustive on purpose: a Variant carries no length, so a
// type this function could not read would be a type nothing after it could be read
// past either.
func (r *reader) value(v *Variant, depth int) {
	switch v.Type {
	case TypeNull:
		// Nothing on the wire.
	case TypeBoolean:
		// Any non-zero octet is true. The standard says a server shall send 0 or
		// 1, and a reader that only accepted those would refuse a message every
		// stack in the field accepts.
		v.Bool = r.byte() != 0
		if v.Bool {
			v.Num, v.Ints = 1, 1
		}
	case TypeSByte:
		v.Ints = int64(int8(r.byte())) //nolint:gosec // two's complement on the wire
		v.Num = float64(v.Ints)
	case TypeByte:
		v.Ints = int64(r.byte())
		v.Num = float64(v.Ints)
	case TypeInt16:
		v.Ints = int64(int16(r.uint16())) //nolint:gosec // two's complement
		v.Num = float64(v.Ints)
	case TypeUInt16:
		v.Ints = int64(r.uint16())
		v.Num = float64(v.Ints)
	case TypeInt32:
		v.Ints = int64(r.int32())
		v.Num = float64(v.Ints)
	case TypeUInt32:
		v.Ints = int64(r.uint32())
		v.Num = float64(v.Ints)
	case TypeInt64:
		v.Ints = r.int64()
		v.Num = float64(v.Ints)
	case TypeUInt64:
		u := r.uint64()
		v.Ints = int64(u) //nolint:gosec // kept for the exact bits; Num is the comparable form
		v.Num = float64(u)
	case TypeFloat:
		v.Num = float64(math.Float32frombits(r.uint32()))
	case TypeDouble:
		v.Num = math.Float64frombits(r.uint64())
	case TypeString, TypeXMLElement:
		v.Text = r.str()
	case TypeDateTime:
		v.Time = FileTime(r.int64())
	case TypeGuid:
		if g := r.bytes(16); g != nil {
			v.Text = guid(g)
		}
	case TypeByteString:
		v.Text = hex.EncodeToString(r.byteString())
	case TypeNodeId:
		v.Node = r.nodeID(false)
	case TypeExpandedNodeId:
		v.Node = r.nodeID(true)
	case TypeStatusCode:
		v.Status = r.uint32()
	case TypeQualifiedName:
		ns := r.uint16()
		v.Text = fmt.Sprintf("%d:%s", ns, r.str())
	case TypeLocalizedText:
		v.Text = r.localizedText()
	case TypeExtensionObject:
		v.Node = r.extensionObject(depth + 1)
	case TypeDataValue:
		dv := r.dataValue(depth + 1)
		*v = dv.Value
		v.Status = dv.Status
	case TypeVariant:
		*v = r.variant(depth + 1)
	case TypeDiagnosticInfo:
		r.diagnosticInfo(depth + 1)
	default:
		r.fail("%w: a value of built-in type %d", ErrEncoding, byte(v.Type))
	}
}

// The LocalizedText mask bits.
const (
	textLocale = 0x01
	textText   = 0x02
)

// localizedText reads a LocalizedText and returns its text, dropping the locale.
// The locale is what language the text is in; a policy is about the text.
func (r *reader) localizedText() string {
	mask := r.byte()
	if mask&textLocale != 0 {
		r.str()
	}
	if mask&textText != 0 {
		return r.str()
	}
	return ""
}

// The ExtensionObject body encodings.
const (
	extNone       = 0x00
	extByteString = 0x01
	extXML        = 0x02
)

// extensionObject reads an ExtensionObject and returns its type identifier.
//
// The body is not decoded. An ExtensionObject is the encoding's escape hatch — a
// structure the standard did not define, identified by a node id and carried as a
// byte string — and a relay that tried to interpret every vendor's structures would
// be a relay with a vendor's parser in it. The *identifier* is the interesting part
// and is what a rule is written about: a user identity token is an ExtensionObject,
// and which kind it is decides whether a password crossed the wire.
func (r *reader) extensionObject(depth int) NodeId {
	if depth > maxVariantDepth {
		r.fail("%w: an extension object nested %d deep", ErrTooLong, depth)
		return NodeId{}
	}
	id := r.nodeID(true)
	switch r.byte() {
	case extNone:
	case extByteString, extXML:
		r.byteString()
	default:
		// The encoding octet has three defined values. Anything else means the
		// body's length is unknown, so there is no reading past it.
		r.fail("%w: an extension object body encoding", ErrEncoding)
	}
	return id
}

// A DataValue is a value with the server's opinion of it: a status code and two
// timestamps.
//
// The status is not decoration. A Read that returns a good value and a Read that
// returns Bad_NodeIdUnknown are the same message shape, and the difference is this
// field — which is what lets a relay tell a client browsing an address space from a
// client enumerating one that is not there.
type DataValue struct {
	Value       Variant
	Status      uint32
	Source      time.Time
	Server      time.Time
	SourcePico  uint16
	ServerPico  uint16
	HasValue    bool
	HasStatus   bool
	HasSourceTS bool
	HasServerTS bool
}

// The DataValue encoding mask bits.
const (
	dvValue      = 0x01
	dvStatus     = 0x02
	dvSourceTS   = 0x04
	dvServerTS   = 0x08
	dvSourcePico = 0x10
	dvServerPico = 0x20
)

func (r *reader) dataValue(depth int) DataValue {
	if depth > maxVariantDepth {
		r.fail("%w: a data value nested %d deep", ErrTooLong, depth)
		return DataValue{}
	}
	mask := r.byte()
	var d DataValue
	if mask&dvValue != 0 {
		d.Value, d.HasValue = r.variant(depth), true
	}
	if mask&dvStatus != 0 {
		d.Status, d.HasStatus = r.uint32(), true
	}
	if mask&dvSourceTS != 0 {
		d.Source, d.HasSourceTS = FileTime(r.int64()), true
	}
	if mask&dvSourcePico != 0 {
		d.SourcePico = r.uint16()
	}
	if mask&dvServerTS != 0 {
		d.Server, d.HasServerTS = FileTime(r.int64()), true
	}
	if mask&dvServerPico != 0 {
		d.ServerPico = r.uint16()
	}
	return d
}

// The DiagnosticInfo mask bits.
const (
	diSymbolicID     = 0x01
	diNamespaceURI   = 0x02
	diLocalizedText  = 0x04
	diLocale         = 0x08
	diAdditionalInfo = 0x10
	diInnerStatus    = 0x20
	diInnerDiag      = 0x40
)

// diagnosticInfo reads a DiagnosticInfo and keeps nothing.
//
// It is read rather than skipped because it has no length prefix and it nests: the
// only way past one is through it. What it carries is indices into a string table
// elsewhere in the response, which is a debugging aid and not something a policy is
// written about — and a server that returns it is usually a server someone asked to,
// through ReturnDiagnostics in the request header.
func (r *reader) diagnosticInfo(depth int) {
	if depth > maxVariantDepth {
		r.fail("%w: diagnostic info nested %d deep", ErrTooLong, depth)
		return
	}
	mask := r.byte()
	if mask&diSymbolicID != 0 {
		r.int32()
	}
	if mask&diNamespaceURI != 0 {
		r.int32()
	}
	if mask&diLocale != 0 {
		r.int32()
	}
	if mask&diLocalizedText != 0 {
		r.int32()
	}
	if mask&diAdditionalInfo != 0 {
		r.str()
	}
	if mask&diInnerStatus != 0 {
		r.uint32()
	}
	if mask&diInnerDiag != 0 {
		r.diagnosticInfo(depth + 1)
	}
}

// fileTimeEpoch is 1601-01-01 UTC, which is where a Windows FILETIME counts from
// and therefore where an OPC UA DateTime does. It is held as a Unix second count
// rather than as a time.Time difference for a reason worth stating: the gap from
// 1601 to now is about 1.3e19 nanoseconds and a time.Duration holds 9.2e18, so
// every arithmetic that goes through a Duration saturates silently and produces a
// timestamp in the wrong century.
const fileTimeEpochUnix = -11644473600

// ticksPerSecond is how many hundred-nanosecond ticks make a second.
const ticksPerSecond = 10_000_000

// FileTime converts an OPC UA DateTime — hundreds of nanoseconds since 1601 — to a
// Go time.
//
// Zero and the maximum are the two values the standard gives meanings to: zero is
// "no time given" and Int64's maximum is "infinity", and both map to the zero time
// here rather than to a date four hundred years out. A relay that rendered
// 1601-01-01 in a log line for a timestamp the server declined to set would be
// reporting a fact nobody stated.
func FileTime(t int64) time.Time {
	if t <= 0 || t == math.MaxInt64 {
		return time.Time{}
	}
	return time.Unix(t/ticksPerSecond+fileTimeEpochUnix, (t%ticksPerSecond)*100).UTC()
}

// ToFileTime is the inverse, for a value this relay writes.
func ToFileTime(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return (t.Unix()-fileTimeEpochUnix)*ticksPerSecond + int64(t.Nanosecond())/100
}

// statusSeverity is the top two bits of a StatusCode.
const (
	severityGood        = 0x00000000
	severityUncertain   = 0x40000000
	severityBad         = 0x80000000
	statusSeverityMask  = 0xC0000000
	statusSubCodeShift  = 16
	statusSubCodeMask   = 0x0FFF
	statusStructureBits = 0x0000FFFF
)

// Good, Uncertain and Bad classify a StatusCode by its severity bits.
func Good(code uint32) bool      { return code&statusSeverityMask == severityGood }
func Uncertain(code uint32) bool { return code&statusSeverityMask == severityUncertain }
func Bad(code uint32) bool       { return code&statusSeverityMask == severityBad }

// StatusName renders a status code in the form a log line wants: the severity and
// the sub-code, in hex.
//
// It does not name the four hundred codes the standard defines. A table of them
// would be four hundred lines that go stale with each edition, and what a reader
// needs from a refusal is the code as the server's own documentation writes it.
func StatusName(code uint32) string {
	sev := "good"
	switch {
	case Bad(code):
		sev = "bad"
	case Uncertain(code):
		sev = "uncertain"
	}
	if code&statusStructureBits != 0 {
		return fmt.Sprintf("%s:0x%08X", sev, code)
	}
	return fmt.Sprintf("%s:0x%04X", sev, (code>>statusSubCodeShift)&statusSubCodeMask)
}

// putUint32 writes a little-endian uint32, for the few messages this relay emits
// itself rather than forwards.
func putUint32(b []byte, v uint32) { binary.LittleEndian.PutUint32(b, v) }

// double reads a Double, which the service bodies use for intervals and ages.
func (r *reader) double() float64 { return math.Float64frombits(r.uint64()) }

// boolean reads a Boolean, where any non-zero octet is true.
func (r *reader) boolean() bool { return r.byte() != 0 }
