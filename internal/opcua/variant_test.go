package opcua

import (
	"bytes"
	"errors"
	"math"
	"testing"
)

func TestEveryBuiltinTypeIsRead(t *testing.T) {
	// A Variant has no length prefix, so a type this package could not read would
	// be a type nothing after it could be read past either. That makes the
	// exhaustiveness a correctness property rather than a completeness nicety.
	for _, tc := range []struct {
		name  string
		build func(*builder)
		typ   BuiltinType
		check func(*testing.T, Variant)
	}{
		{"boolean", func(w *builder) { w.byte(byte(TypeBoolean)).bool(true) }, TypeBoolean,
			func(t *testing.T, v Variant) {
				if !v.Bool || v.Ints != 1 {
					t.Errorf("%+v", v)
				}
			}},
		{"sbyte", func(w *builder) { w.byte(byte(TypeSByte)).byte(0xFF) }, TypeSByte,
			func(t *testing.T, v Variant) {
				if v.Ints != -1 {
					t.Errorf("Ints %d, want -1", v.Ints)
				}
			}},
		{"byte", func(w *builder) { w.byte(byte(TypeByte)).byte(0xFF) }, TypeByte,
			func(t *testing.T, v Variant) {
				if v.Ints != 255 {
					t.Errorf("Ints %d, want 255", v.Ints)
				}
			}},
		{"int16", func(w *builder) { w.byte(byte(TypeInt16)).u16(0xFFFF) }, TypeInt16,
			func(t *testing.T, v Variant) {
				if v.Ints != -1 {
					t.Errorf("Ints %d, want -1", v.Ints)
				}
			}},
		{"uint16", func(w *builder) { w.byte(byte(TypeUInt16)).u16(0xFFFF) }, TypeUInt16,
			func(t *testing.T, v Variant) {
				if v.Ints != 65535 {
					t.Errorf("Ints %d", v.Ints)
				}
			}},
		{"int32", func(w *builder) { w.byte(byte(TypeInt32)).i32(-2000000000) }, TypeInt32,
			func(t *testing.T, v Variant) {
				if v.Ints != -2000000000 {
					t.Errorf("Ints %d", v.Ints)
				}
			}},
		{"uint32", func(w *builder) { w.byte(byte(TypeUInt32)).u32(4000000000) }, TypeUInt32,
			func(t *testing.T, v Variant) {
				if v.Ints != 4000000000 {
					t.Errorf("Ints %d", v.Ints)
				}
			}},
		{"int64", func(w *builder) { w.byte(byte(TypeInt64)).i64(-9000000000000000000) }, TypeInt64,
			func(t *testing.T, v Variant) {
				if v.Ints != -9000000000000000000 {
					t.Errorf("Ints %d", v.Ints)
				}
			}},
		{"uint64", func(w *builder) { w.byte(byte(TypeUInt64)).u64(math.MaxUint64) }, TypeUInt64,
			func(t *testing.T, v Variant) {
				// The exact bits are kept in Ints and the comparable form in
				// Num: a 64-bit counter's exact value needs the first and a
				// range rule needs the second.
				if uint64(v.Ints) != math.MaxUint64 {
					t.Errorf("Ints %d", v.Ints)
				}
				if v.Num != float64(uint64(math.MaxUint64)) {
					t.Errorf("Num %v", v.Num)
				}
			}},
		{"float", func(w *builder) { w.byte(byte(TypeFloat)).f32(1.5) }, TypeFloat,
			func(t *testing.T, v Variant) {
				if v.Num != 1.5 {
					t.Errorf("Num %v", v.Num)
				}
			}},
		{"double", func(w *builder) { w.byte(byte(TypeDouble)).f64(-273.15) }, TypeDouble,
			func(t *testing.T, v Variant) {
				if v.Num != -273.15 {
					t.Errorf("Num %v", v.Num)
				}
			}},
		{"string", func(w *builder) { w.byte(byte(TypeString)).str("running") }, TypeString,
			func(t *testing.T, v Variant) {
				if v.Text != "running" {
					t.Errorf("Text %q", v.Text)
				}
			}},
		{"datetime", func(w *builder) { w.byte(byte(TypeDateTime)).i64(ToFileTime(testTime())) },
			TypeDateTime, func(t *testing.T, v Variant) {
				if !v.Time.Equal(testTime()) {
					t.Errorf("Time %v", v.Time)
				}
			}},
		{"guid", func(w *builder) {
			w.byte(byte(TypeGuid)).bytes(bytes.Repeat([]byte{0xAB}, 16))
		}, TypeGuid, func(t *testing.T, v Variant) {
			if v.Text != "ABABABAB-ABAB-ABAB-ABAB-ABABABABABAB" {
				t.Errorf("Text %q", v.Text)
			}
		}},
		{"bytestring", func(w *builder) {
			w.byte(byte(TypeByteString)).bstr([]byte{0x01, 0x02})
		}, TypeByteString, func(t *testing.T, v Variant) {
			if v.Text != "0102" {
				t.Errorf("Text %q", v.Text)
			}
		}},
		{"xmlelement", func(w *builder) {
			w.byte(byte(TypeXMLElement)).str("<x/>")
		}, TypeXMLElement, func(t *testing.T, v Variant) {
			if v.Text != "<x/>" {
				t.Errorf("Text %q", v.Text)
			}
		}},
		{"nodeid", func(w *builder) { w.byte(byte(TypeNodeId)).numeric(3, 7) }, TypeNodeId,
			func(t *testing.T, v Variant) {
				if v.Node.Key() != "ns=3;i=7" {
					t.Errorf("Node %s", v.Node)
				}
			}},
		{"expandednodeid", func(w *builder) {
			w.byte(byte(TypeExpandedNodeId)).byte(byte(Numeric) | flagNamespaceURI).
				u16(0).u32(7).str("urn:x")
		}, TypeExpandedNodeId, func(t *testing.T, v Variant) {
			if v.Node.NamespaceURI != "urn:x" {
				t.Errorf("Node %s", v.Node)
			}
		}},
		{"statuscode", func(w *builder) {
			w.byte(byte(TypeStatusCode)).u32(StatusBadNodeIDUnknown)
		}, TypeStatusCode, func(t *testing.T, v Variant) {
			if v.Status != StatusBadNodeIDUnknown {
				t.Errorf("Status %#x", v.Status)
			}
		}},
		{"qualifiedname", func(w *builder) {
			w.byte(byte(TypeQualifiedName)).u16(4).str("Speed")
		}, TypeQualifiedName, func(t *testing.T, v Variant) {
			if v.Text != "4:Speed" {
				t.Errorf("Text %q", v.Text)
			}
		}},
		{"localizedtext", func(w *builder) {
			w.byte(byte(TypeLocalizedText)).byte(textLocale | textText).str("en").str("Running")
		}, TypeLocalizedText, func(t *testing.T, v Variant) {
			if v.Text != "Running" {
				t.Errorf("Text %q", v.Text)
			}
		}},
		{"extensionobject", func(w *builder) {
			w.byte(byte(TypeExtensionObject)).numeric(0, 884).byte(extByteString).
				bstr([]byte{1, 2, 3})
		}, TypeExtensionObject, func(t *testing.T, v Variant) {
			if v.Node.Key() != "ns=0;i=884" {
				t.Errorf("Node %s", v.Node)
			}
		}},
		{"datavalue", func(w *builder) {
			w.byte(byte(TypeDataValue)).byte(dvValue | dvStatus).
				byte(byte(TypeDouble)).f64(42).u32(0)
		}, TypeDouble, func(t *testing.T, v Variant) {
			if v.Num != 42 {
				t.Errorf("Num %v", v.Num)
			}
		}},
		{"variant", func(w *builder) {
			w.byte(byte(TypeVariant)).byte(byte(TypeInt32)).i32(9)
		}, TypeInt32, func(t *testing.T, v Variant) {
			if v.Ints != 9 {
				t.Errorf("Ints %d", v.Ints)
			}
		}},
		{"diagnosticinfo", func(w *builder) {
			w.byte(byte(TypeDiagnosticInfo)).byte(diSymbolicID | diAdditionalInfo).
				i32(1).str("because")
		}, TypeDiagnosticInfo, func(t *testing.T, v Variant) {}},
		{"null", func(w *builder) { w.byte(byte(TypeNull)) }, TypeNull,
			func(t *testing.T, v Variant) {}},
	} {
		w := build()
		tc.build(w)
		r := &reader{b: w.b}
		v := r.variant(0)
		if err := r.done(); err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if r.left() != 0 {
			t.Errorf("%s: %d octets left unread", tc.name, r.left())
		}
		if v.Type != tc.typ {
			t.Errorf("%s: type %s, want %s", tc.name, v.Type, tc.typ)
		}
		tc.check(t, v)
	}
}

func TestABuiltinTypeNobodyDefinedIsRefused(t *testing.T) {
	for _, b := range []byte{26, 30, 0x3F} {
		r := &reader{b: []byte{b, 0, 0, 0, 0}}
		r.variant(0)
		if err := r.done(); !errors.Is(err, ErrEncoding) {
			t.Errorf("type %d: err %v, want ErrEncoding", b, err)
		}
	}
}

func TestAnArrayVariantIsCountedAndItsNumericElementsKept(t *testing.T) {
	w := build().byte(byte(TypeDouble) | variantArray).array(3).f64(1).f64(2).f64(3)
	r := &reader{b: w.b}
	v := r.variant(0)
	if err := r.done(); err != nil {
		t.Fatal(err)
	}
	if !v.Array || v.Count != 3 {
		t.Errorf("%+v", v)
	}
	if len(v.Elems) != 3 || v.Elems[2] != 3 {
		t.Errorf("Elems %v", v.Elems)
	}
}

func TestAnArrayLongerThanTheBoundIsKeptAsACountAndNotAsValues(t *testing.T) {
	// A policy that examined every element of a long array would be the
	// amplifier, so the elements stop at MaxArrayValues and the count does not.
	n := MaxArrayValues + 10
	w := build().byte(byte(TypeDouble) | variantArray).array(n)
	for i := 0; i < n; i++ {
		w.f64(float64(i))
	}
	r := &reader{b: w.b}
	v := r.variant(0)
	if err := r.done(); err != nil {
		t.Fatal(err)
	}
	if v.Count != n {
		t.Errorf("Count %d, want %d", v.Count, n)
	}
	if len(v.Elems) != MaxArrayValues {
		t.Errorf("Elems %d, want %d", len(v.Elems), MaxArrayValues)
	}
}

func TestAnArrayPastMaxArrayIsRefusedRatherThanTrimmed(t *testing.T) {
	w := build().byte(byte(TypeDouble) | variantArray).i32(MaxArray + 1)
	r := &reader{b: w.b}
	r.variant(0)
	if err := r.done(); !errors.Is(err, ErrTooLong) {
		t.Errorf("err %v, want ErrTooLong", err)
	}
}

func TestAnArrayOfTheNullTypeIsRefused(t *testing.T) {
	// There is no element whose length the array's own length could be counted
	// in, so the shape is one the encoding does not define.
	r := &reader{b: []byte{byte(TypeNull) | variantArray, 1, 0, 0, 0}}
	r.variant(0)
	if err := r.done(); !errors.Is(err, ErrEncoding) {
		t.Errorf("err %v, want ErrEncoding", err)
	}
}

func TestAMultidimensionalArrayCarriesItsShape(t *testing.T) {
	w := build().byte(byte(TypeInt32) | variantArray | variantDims).
		array(4).i32(1).i32(2).i32(3).i32(4).
		array(2).i32(2).i32(2)
	r := &reader{b: w.b}
	v := r.variant(0)
	if err := r.done(); err != nil {
		t.Fatal(err)
	}
	if len(v.Dimensions) != 2 || v.Dimensions[0] != 2 {
		t.Errorf("Dimensions %v", v.Dimensions)
	}
}

func TestTooManyDimensionsAreRefused(t *testing.T) {
	w := build().byte(byte(TypeInt32) | variantArray | variantDims).array(0).array(maxVariantDim + 1)
	r := &reader{b: w.b}
	r.variant(0)
	if err := r.done(); !errors.Is(err, ErrTooLong) {
		t.Errorf("err %v, want ErrTooLong", err)
	}
}

func TestAVariantNestedPastTheDepthBoundIsRefused(t *testing.T) {
	// A Variant may hold a Variant, so nesting is unbounded on the wire and has
	// to be bounded here: a few octets per level is all it costs a peer.
	w := build()
	for i := 0; i <= maxVariantDepth+1; i++ {
		w.byte(byte(TypeVariant))
	}
	w.byte(byte(TypeInt32)).i32(1)
	r := &reader{b: w.b}
	r.variant(0)
	if err := r.done(); !errors.Is(err, ErrTooLong) {
		t.Errorf("err %v, want ErrTooLong", err)
	}
}

func TestADiagnosticInfoNestedPastTheBoundIsRefused(t *testing.T) {
	w := build()
	for i := 0; i <= maxVariantDepth+1; i++ {
		w.byte(diInnerDiag)
	}
	w.byte(0)
	r := &reader{b: w.b}
	r.diagnosticInfo(0)
	if err := r.done(); !errors.Is(err, ErrTooLong) {
		t.Errorf("err %v, want ErrTooLong", err)
	}
}

func TestAnExtensionObjectBodyEncodingNobodyDefinedIsRefused(t *testing.T) {
	// There are three defined values, and anything else means the body's length is
	// unknown — so there is no reading past it and no point pretending otherwise.
	w := build().nullNode().byte(0x03)
	r := &reader{b: w.b}
	r.extensionObject(0)
	if err := r.done(); !errors.Is(err, ErrEncoding) {
		t.Errorf("err %v, want ErrEncoding", err)
	}
}

func TestAnExtensionObjectWithAnXMLBodyIsReadPast(t *testing.T) {
	w := build().numeric(0, 300).byte(extXML).bstr([]byte("<x/>")).u32(0xAABBCCDD)
	r := &reader{b: w.b}
	id := r.extensionObject(0)
	if err := r.done(); err != nil {
		t.Fatal(err)
	}
	if id.Key() != "ns=0;i=300" {
		t.Errorf("id %s", id)
	}
	if got := r.uint32(); got != 0xAABBCCDD {
		t.Errorf("the field after the body read as %#x", got)
	}
}

func TestADataValueCarriesTheServersOpinionOfTheValue(t *testing.T) {
	// A Read that returns a good value and one that returns Bad_NodeIdUnknown are
	// the same message shape; this field is the difference.
	w := build().byte(dvValue | dvStatus | dvSourceTS | dvServerTS | dvSourcePico | dvServerPico).
		byte(byte(TypeDouble)).f64(3.5).
		u32(StatusBadNodeIDUnknown).
		i64(ToFileTime(testTime())).u16(7).
		i64(ToFileTime(testTime())).u16(9)
	r := &reader{b: w.b}
	d := r.dataValue(0)
	if err := r.done(); err != nil {
		t.Fatal(err)
	}
	if !d.HasValue || d.Value.Num != 3.5 {
		t.Errorf("value %+v", d.Value)
	}
	if !d.HasStatus || d.Status != StatusBadNodeIDUnknown {
		t.Errorf("status %#x", d.Status)
	}
	if !d.HasSourceTS || !d.Source.Equal(testTime()) {
		t.Errorf("source %v", d.Source)
	}
	if !d.HasServerTS || !d.Server.Equal(testTime()) {
		t.Errorf("server %v", d.Server)
	}
	if d.SourcePico != 7 || d.ServerPico != 9 {
		t.Errorf("picoseconds %d/%d", d.SourcePico, d.ServerPico)
	}
	// An empty mask is a DataValue with nothing in it, which is legal and is what
	// a Write of "no opinion" looks like.
	r = &reader{b: []byte{0}}
	d = r.dataValue(0)
	if err := r.done(); err != nil {
		t.Fatal(err)
	}
	if d.HasValue || d.HasStatus {
		t.Errorf("%+v", d)
	}
}

func TestTheBuiltinTypesClassifyForAPolicy(t *testing.T) {
	// Numeric is the question a range or rate-of-change rule asks, and Boolean is
	// deliberately outside it: a boolean is a state and a rule about it is a
	// transition rule.
	for _, tc := range []struct {
		t       BuiltinType
		numeric bool
	}{
		{TypeNull, false}, {TypeBoolean, false},
		{TypeSByte, true}, {TypeByte, true},
		{TypeInt16, true}, {TypeUInt16, true},
		{TypeInt32, true}, {TypeUInt32, true},
		{TypeInt64, true}, {TypeUInt64, true},
		{TypeFloat, true}, {TypeDouble, true},
		{TypeString, false}, {TypeDateTime, false},
		{TypeNodeId, false}, {TypeVariant, false},
	} {
		if got := tc.t.Numeric(); got != tc.numeric {
			t.Errorf("%s Numeric %v, want %v", tc.t, got, tc.numeric)
		}
	}
	for b := 0; b < 256; b++ {
		want := b <= int(TypeDiagnosticInfo)
		if got := BuiltinType(b).Known(); got != want {
			t.Errorf("type %d Known %v, want %v", b, got, want)
		}
	}
	if got := BuiltinType(99).String(); got != "type(99)" {
		t.Errorf("String %q", got)
	}
}

func TestATruncatedVariantIsReportedRatherThanReadAsZero(t *testing.T) {
	for _, w := range [][]byte{
		{},
		{byte(TypeDouble)},
		{byte(TypeDouble), 1, 2, 3},
		{byte(TypeString)},
		{byte(TypeString), 5, 0, 0, 0, 'a'},
		{byte(TypeDouble) | variantArray, 2, 0, 0, 0},
	} {
		r := &reader{b: w}
		r.variant(0)
		if err := r.done(); !errors.Is(err, ErrShort) {
			t.Errorf("%x: err %v, want ErrShort", w, err)
		}
	}
}

func TestALengthNobodyDefinedIsRefusedRatherThanClampedToEmpty(t *testing.T) {
	// Minus one is the null value; every other negative number is a length that
	// agrees with nothing else about where the next field starts.
	for _, n := range []int32{-2, -100, math.MinInt32} {
		w := build().i32(n)
		r := &reader{b: w.b}
		r.str()
		if err := r.done(); !errors.Is(err, ErrEncoding) {
			t.Errorf("length %d: err %v, want ErrEncoding", n, err)
		}
	}
	// Minus one is null and not an error.
	r := &reader{b: build().null().b}
	if got := r.str(); got != "" {
		t.Errorf("a null string read as %q", got)
	}
	if err := r.done(); err != nil {
		t.Errorf("a null string is reported as an error: %v", err)
	}
}

func TestAStringPastTheBoundIsRefused(t *testing.T) {
	w := build().i32(MaxString + 1)
	r := &reader{b: w.b}
	r.str()
	if err := r.done(); !errors.Is(err, ErrTooLong) {
		t.Errorf("err %v, want ErrTooLong", err)
	}
}

func TestTheFirstFailureSticksSoALaterReadDoesNotLookLikeData(t *testing.T) {
	// A caller that ignored one error must not then act on a zero value as though
	// it were a field the peer sent.
	r := &reader{b: []byte{1}}
	r.uint32() // fails: one octet where four were wanted
	first := r.done()
	if !errors.Is(first, ErrShort) {
		t.Fatalf("err %v", first)
	}
	if got := r.uint32(); got != 0 {
		t.Errorf("a read after a failure returned %d", got)
	}
	if !errors.Is(r.done(), first) {
		t.Error("a later failure replaced the first")
	}
	if got := r.str(); got != "" {
		t.Errorf("a string read after a failure returned %q", got)
	}
}

func TestABooleanIsTrueForAnyNonZeroOctet(t *testing.T) {
	// The standard says a server shall send 0 or 1; a reader that only accepted
	// those would refuse messages every stack in the field accepts.
	for _, b := range []byte{1, 2, 0xFF} {
		r := &reader{b: []byte{b}}
		if !r.boolean() {
			t.Errorf("%#x read as false", b)
		}
	}
	r := &reader{b: []byte{0}}
	if r.boolean() {
		t.Error("zero read as true")
	}
}
