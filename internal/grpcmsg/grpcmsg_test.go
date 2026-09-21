package grpcmsg_test

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/grpcmsg"
)

// field builds one protobuf field.
func field(num int32, typ uint64, body []byte) []byte {
	out := binary.AppendUvarint(nil, uint64(num)<<3|typ)
	switch typ {
	case 2:
		out = binary.AppendUvarint(out, uint64(len(body)))
		out = append(out, body...)
	default:
		out = append(out, body...)
	}
	return out
}

func str(num int32, s string) []byte    { return field(num, 2, []byte(s)) }
func nested(num int32, b []byte) []byte { return field(num, 2, b) }
func varint(num int32, v uint64) []byte {
	return field(num, 0, binary.AppendUvarint(nil, v))
}

// frame wraps a payload in the gRPC message header.
func frame(compressed bool, payload []byte) []byte {
	out := make([]byte, 5, 5+len(payload))
	if compressed {
		out[0] = 1
	}
	binary.BigEndian.PutUint32(out[1:], uint32(len(payload)))
	return append(out, payload...)
}

func TestSplitFrames(t *testing.T) {
	a, b := []byte("one"), []byte("two")
	buf := append(frame(false, a), frame(true, b)...)
	frames, rest, err := grpcmsg.SplitFrames(buf, 0)
	if err != nil || len(frames) != 2 || len(rest) != 0 {
		t.Fatalf("frames %d rest %d err %v", len(frames), len(rest), err)
	}
	if string(frames[0].Payload) != "one" || frames[0].Compressed {
		t.Errorf("first %+v", frames[0])
	}
	if string(frames[1].Payload) != "two" || !frames[1].Compressed {
		t.Errorf("second %+v", frames[1])
	}

	// A partial frame is carried, not guessed at: the rest of it is in
	// the next read.
	partial := append(frame(false, a), frame(false, b)[:4]...)
	frames, rest, err = grpcmsg.SplitFrames(partial, 0)
	if err != nil || len(frames) != 1 || len(rest) != 4 {
		t.Fatalf("partial: frames %d rest %d err %v", len(frames), len(rest), err)
	}
}

// A header claiming four gigabytes is refused on the header alone,
// before anything is allocated for it.
func TestSplitFramesBound(t *testing.T) {
	hdr := make([]byte, 5)
	binary.BigEndian.PutUint32(hdr[1:], 1<<30)
	if _, _, err := grpcmsg.SplitFrames(hdr, 1<<20); !errors.Is(err, grpcmsg.ErrFrameTooLarge) {
		t.Fatalf("err = %v, want ErrFrameTooLarge", err)
	}
	// Without a bound the same header is simply incomplete, because
	// the octets have not arrived.
	frames, rest, err := grpcmsg.SplitFrames(hdr, 0)
	if err != nil || len(frames) != 0 || len(rest) != 5 {
		t.Fatalf("frames %d rest %d err %v", len(frames), len(rest), err)
	}
}

func TestWalkFindsStrings(t *testing.T) {
	msg := append(str(1, "alice@example.com"), varint(2, 42)...)
	msg = append(msg, nested(3, append(str(1, "inner text"), varint(2, 7)...))...)

	var got []string
	rep, err := grpcmsg.Walk(msg, grpcmsg.Limits{}, func(_ []int32, s string) bool {
		got = append(got, s)
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "alice@example.com" || got[1] != "inner text" {
		t.Fatalf("strings %q", got)
	}
	if rep.Depth != 1 {
		t.Errorf("depth %d, want 1", rep.Depth)
	}
	if rep.Fields != 5 {
		t.Errorf("fields %d, want 5", rep.Fields)
	}
}

// The path says where a string was found, which is what a rule about
// one field rather than the whole message needs.
func TestWalkReportsPath(t *testing.T) {
	msg := nested(3, nested(4, str(5, "deep")))
	var path []int32
	if _, err := grpcmsg.Walk(msg, grpcmsg.Limits{}, func(p []int32, s string) bool {
		if s == "deep" {
			path = append([]int32(nil), p...)
		}
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if len(path) != 3 || path[0] != 3 || path[1] != 4 || path[2] != 5 {
		t.Fatalf("path %v, want [3 4 5]", path)
	}
}

// A message nested a thousand deep costs the backend's parser far more
// than it costs the sender to write.
func TestWalkDepthBound(t *testing.T) {
	msg := str(1, "bottom")
	for i := 0; i < 64; i++ {
		msg = nested(1, msg)
	}
	if _, err := grpcmsg.Walk(msg, grpcmsg.Limits{MaxDepth: 8}, nil); !errors.Is(err, grpcmsg.ErrTooDeep) {
		t.Fatalf("err = %v, want ErrTooDeep", err)
	}
	if _, err := grpcmsg.Walk(msg, grpcmsg.Limits{MaxDepth: 200}, nil); err != nil {
		t.Fatalf("a message inside the bound was refused: %v", err)
	}
}

func TestWalkFieldBound(t *testing.T) {
	var msg []byte
	for i := 0; i < 100; i++ {
		msg = append(msg, varint(1, uint64(i))...)
	}
	if _, err := grpcmsg.Walk(msg, grpcmsg.Limits{MaxFields: 10}, nil); !errors.Is(err, grpcmsg.ErrTooManyFields) {
		t.Fatalf("err = %v, want ErrTooManyFields", err)
	}
	// The count is across every level, not per message.
	deep := nested(1, nested(2, msg))
	if _, err := grpcmsg.Walk(deep, grpcmsg.Limits{MaxFields: 10}, nil); !errors.Is(err, grpcmsg.ErrTooManyFields) {
		t.Fatalf("nested: err = %v", err)
	}
}

func TestWalkRefusesMalformed(t *testing.T) {
	for name, b := range map[string][]byte{
		"field number zero": field(0, 0, []byte{1}),
		"truncated varint":  {0x08, 0xff},
		"length past end":   {0x0a, 0x10, 'a'},
		"short 64-bit":      {0x09, 1, 2, 3},
		"short 32-bit":      {0x0d, 1, 2},
		"group wire type":   {0x0b},
		"unknown wire type": {0x0f},
		"truncated key":     {0xff},
	} {
		if _, err := grpcmsg.Walk(b, grpcmsg.Limits{}, nil); !errors.Is(err, grpcmsg.ErrMalformed) {
			t.Errorf("%s: err = %v, want ErrMalformed", name, err)
		}
	}
}

// Bytes that are not text are not handed to a rule that expects text.
func TestWalkSkipsBinary(t *testing.T) {
	msg := field(1, 2, []byte{0xff, 0xfe, 0xfd, 0xfc})
	var got []string
	rep, err := grpcmsg.Walk(msg, grpcmsg.Limits{}, func(_ []int32, s string) bool {
		got = append(got, s)
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 || rep.Strings != 0 {
		t.Fatalf("binary was handed over as text: %q", got)
	}
}

// A long string is truncated on a character boundary rather than
// dropped: a rule about the start of a string still works on the start
// of it.
func TestWalkTruncatesStrings(t *testing.T) {
	long := strings.Repeat("é", 100) // two octets each
	msg := str(1, long)
	var got string
	if _, err := grpcmsg.Walk(msg, grpcmsg.Limits{MaxStringBytes: 9}, func(_ []int32, s string) bool {
		got = s
		return true
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) > 9 || len(got) == 0 {
		t.Fatalf("truncated to %d octets", len(got))
	}
	if !strings.HasPrefix(long, got) {
		t.Fatalf("truncation changed the text: %q", got)
	}
}

// The callback can stop the walk, which is how a rule that has already
// decided avoids paying for the rest of a large message.
func TestWalkStops(t *testing.T) {
	msg := append(str(1, "first"), str(2, "second")...)
	n := 0
	if _, err := grpcmsg.Walk(msg, grpcmsg.Limits{}, func(_ []int32, s string) bool {
		n++
		return false
	}); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("the walk continued after being stopped: %d strings", n)
	}
}

func TestMethod(t *testing.T) {
	for _, c := range []struct {
		in, svc, m string
		ok         bool
	}{
		{"/pkg.Service/Method", "pkg.Service", "Method", true},
		{"/S/M", "S", "M", true},
		{"/pkg.Service/", "", "", false},
		{"//Method", "", "", false},
		{"/nomethod", "", "", false},
		{"nopath", "", "", false},
		{"", "", "", false},
	} {
		svc, m, ok := grpcmsg.Method(c.in)
		if ok != c.ok || svc != c.svc || m != c.m {
			t.Errorf("%q = %q %q %v, want %q %q %v", c.in, svc, m, ok, c.svc, c.m, c.ok)
		}
	}
}

// A length varint larger than a signed integer holds must not become a
// negative number in a bound check and then a slice that panics. Every
// length in a message is a client's.
func TestWalkHugeLength(t *testing.T) {
	for name, b := range map[string][]byte{
		// Field 1, wire type 2, length 2^63.
		"length past max int64": append([]byte{0x0a}, binary.AppendUvarint(nil, 1<<63)...),
		"length max uint64":     append([]byte{0x0a}, binary.AppendUvarint(nil, 1<<64-1)...),
	} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: panicked: %v", name, r)
				}
			}()
			if _, err := grpcmsg.Walk(b, grpcmsg.Limits{}, nil); err == nil {
				t.Errorf("%s: parsed", name)
			}
		}()
	}
	// The same length one level in, where the outer message is well
	// formed and the inner blob is simply bytes. Nothing is refused
	// here and nothing may panic either.
	nested := append([]byte{0x0a, 0x0b, 0x0a}, binary.AppendUvarint(nil, 1<<63)...)
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("a nested huge length panicked: %v", r)
		}
	}()
	if _, err := grpcmsg.Walk(nested, grpcmsg.Limits{}, nil); err != nil {
		t.Errorf("a well formed outer message was refused: %v", err)
	}
}
