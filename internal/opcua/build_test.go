package opcua

import (
	"encoding/binary"
	"math"
	"testing"
	"time"
)

// builder writes the wire forms the tests need. It exists because the package reads
// and does not write: a test that hand-wrote octets would be a test nobody could
// change, and a test that used a third-party encoder would be a test of that
// encoder's agreement with this parser rather than of the parser.
type builder struct{ b []byte }

func (w *builder) byte(v byte) *builder    { w.b = append(w.b, v); return w }
func (w *builder) bool(v bool) *builder    { return w.byte(map[bool]byte{true: 1, false: 0}[v]) }
func (w *builder) raw(v ...byte) *builder  { w.b = append(w.b, v...); return w }
func (w *builder) bytes(v []byte) *builder { w.b = append(w.b, v...); return w }

func (w *builder) u16(v uint16) *builder {
	w.b = binary.LittleEndian.AppendUint16(w.b, v)
	return w
}

func (w *builder) u32(v uint32) *builder {
	w.b = binary.LittleEndian.AppendUint32(w.b, v)
	return w
}

func (w *builder) i32(v int32) *builder { return w.u32(uint32(v)) }

func (w *builder) u64(v uint64) *builder {
	w.b = binary.LittleEndian.AppendUint64(w.b, v)
	return w
}

func (w *builder) i64(v int64) *builder   { return w.u64(uint64(v)) }
func (w *builder) f64(v float64) *builder { return w.u64(math.Float64bits(v)) }
func (w *builder) f32(v float32) *builder { return w.u32(math.Float32bits(v)) }
func (w *builder) str(v string) *builder  { return w.i32(int32(len(v))).bytes([]byte(v)) }
func (w *builder) null() *builder         { return w.i32(-1) }
func (w *builder) bstr(v []byte) *builder { return w.i32(int32(len(v))).bytes(v) }
func (w *builder) array(n int) *builder   { return w.i32(int32(n)) }
func (w *builder) localized(v string) *builder {
	if v == "" {
		return w.byte(0)
	}
	return w.byte(textText).str(v)
}

// numeric writes a NodeId in the Numeric encoding, which every test uses because it
// is the one encoding that can express any namespace and any identifier.
func (w *builder) numeric(ns uint16, id uint32) *builder {
	return w.byte(byte(Numeric)).u16(ns).u32(id)
}

func (w *builder) nullNode() *builder { return w.byte(byte(TwoByte)).byte(0) }

// extNone writes an ExtensionObject with no body, which is what every request
// header's AdditionalHeader is.
func (w *builder) emptyExt() *builder { return w.nullNode().byte(extNone) }

// noDiag writes a DiagnosticInfo with nothing set.
func (w *builder) noDiag() *builder { return w.byte(0) }

// chunk frames the accumulated octets as one UA TCP message of type t.
func (w *builder) chunk(t MessageType, ct ChunkType) []byte {
	out := make([]byte, HeaderLen+len(w.b))
	copy(out, t[:])
	out[3] = byte(ct)
	binary.LittleEndian.PutUint32(out[4:], uint32(len(out)))
	copy(out[HeaderLen:], w.b)
	return out
}

func build() *builder { return &builder{} }

// requestHeader writes the header every service request starts with, with a session
// token of the given identifier.
func (w *builder) requestHeader(token uint32) *builder {
	return w.numeric(0, token).
		i64(ToFileTime(testTime())).
		u32(1). // request handle
		u32(0). // return diagnostics
		null(). // audit entry id
		u32(0). // timeout hint
		emptyExt()
}

// secured writes a symmetric security header and a sequence header, which is what
// every MSG chunk carries before its body.
func (w *builder) secured(channel, token, seq, request uint32) *builder {
	return w.u32(channel).u32(token).u32(seq).u32(request)
}

// testTime is the one timestamp every test message carries, so a golden comparison
// never depends on when it ran.
func testTime() time.Time {
	return time.Date(2026, time.March, 4, 9, 30, 0, 0, time.UTC)
}

func mustParse(t *testing.T, raw []byte) *Chunk {
	t.Helper()
	c, err := ParseChunk(raw)
	if err != nil {
		t.Fatalf("ParseChunk: %v", err)
	}
	return c
}
