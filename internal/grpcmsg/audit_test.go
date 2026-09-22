package grpcmsg

import (
	"testing"
	"unicode/utf8"
)

// FuzzSplitFrames: the framing decides where one message ends and the
// next begins. Every length in it is the peer's, and a length trusted
// without a bound is a slice of whatever number they sent.
func FuzzSplitFrames(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0, 3, 1, 2, 3})
	f.Add([]byte{1, 0, 0, 0, 1, 9})
	f.Add([]byte{0, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0, 0x7f, 0xff, 0xff, 0xff, 1})
	f.Fuzz(func(t *testing.T, b []byte) {
		const maxMsg = 1 << 16
		frames, rest, err := SplitFrames(b, maxMsg)
		if err != nil {
			return
		}
		total := len(rest)
		for _, fr := range frames {
			if len(fr.Payload) > maxMsg {
				t.Fatalf("a frame of %d bytes came back past a bound of %d", len(fr.Payload), maxMsg)
			}
			total += len(fr.Payload) + 5
		}
		if total != len(b) {
			t.Fatalf("framing lost or invented bytes: %d in, %d accounted for", len(b), total)
		}
	})
}

// FuzzWalk: a schema-less walk over bytes a peer chose. The bounds are
// the whole safety argument, and every length inside is theirs.
func FuzzWalk(f *testing.F) {
	f.Add([]byte{0x0a, 0x03, 'a', 'b', 'c'})
	f.Add([]byte{0x12, 0x02, 0x08, 0x01})
	f.Add([]byte{0x0a, 0xff, 0xff, 0xff, 0xff, 0x7f})
	f.Fuzz(func(t *testing.T, b []byte) {
		limits := Limits{MaxDepth: 8, MaxFields: 100, MaxStringBytes: 256}
		n := 0
		_, _ = Walk(b, limits, func(path []int32, value string) bool {
			n++
			if n > limits.MaxFields {
				t.Fatalf("the field bound was passed: %d", n)
			}
			if len(value) > limits.MaxStringBytes {
				t.Fatalf("a string of %d bytes came back past a bound of %d", len(value), limits.MaxStringBytes)
			}
			if !utf8.ValidString(value) {
				t.Fatalf("a value that is not UTF-8 reached a rule: %q", value)
			}
			if len(path) > limits.MaxDepth {
				t.Fatalf("a path deeper than the bound: %v", path)
			}
			return true
		})
	})
}
