package recenc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

// key is one test's key. The material is not interesting; what is tested
// is what the format does with it.
var key = []byte("a key from custody, thirty-two++")

// sealed writes a recording and returns the file.
func sealed(t *testing.T, chunk int, parts ...string) []byte {
	t.Helper()
	var b bytes.Buffer
	w, err := NewWriter(&b, key, chunk)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range parts {
		if n, err := w.Write([]byte(p)); n != len(p) || err != nil {
			t.Fatalf("write: %d of %d, %v", n, len(p), err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// opened reads one back.
func opened(t *testing.T, file, k []byte) ([]byte, error) {
	t.Helper()
	r, err := NewReader(bytes.NewReader(file), k)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

// What goes in comes out, whatever the writes were split into: a
// recording is written a terminal write at a time, not a chunk at a time.
func TestWhatIsSealedComesBack(t *testing.T) {
	for _, tc := range []struct {
		name  string
		chunk int
		parts []string
	}{
		{"one small write", MinChunk, []string{"hello\r\n"}},
		{"nothing at all", MinChunk, nil},
		{"exactly one chunk", MinChunk, []string{strings.Repeat("x", MinChunk)}},
		{"exactly two chunks", MinChunk, []string{strings.Repeat("x", 2*MinChunk)}},
		{"a chunk and one octet", MinChunk, []string{strings.Repeat("x", MinChunk+1)}},
		{"many small writes across chunks", MinChunk, func() []string {
			out := make([]string, 0, 300)
			for i := range 300 {
				out = append(out, strings.Repeat(string(rune('a'+i%26)), 40))
			}
			return out
		}()},
		{"one write larger than the chunk", MinChunk, []string{strings.Repeat("y", 5*MinChunk+7)}},
		{"the default chunk", 0, []string{strings.Repeat("z", 3*DefaultChunk)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := strings.Join(tc.parts, "")
			file := sealed(t, tc.chunk, tc.parts...)
			if !Looks(file) {
				t.Error("the file does not begin with the magic")
			}
			if bytes.Contains(file, []byte("hello")) && want != "" {
				t.Error("the plaintext is in the file")
			}
			got, err := opened(t, file, key)
			if err != nil {
				t.Fatalf("read back: %v", err)
			}
			if string(got) != want {
				t.Errorf("read back %d octets, wrote %d", len(got), len(want))
			}
		})
	}
}

// The key is the whole point: another key does not open the file, and
// neither does no key.
func TestOnlyTheKeyOpensIt(t *testing.T) {
	file := sealed(t, MinChunk, "sudo -i\r\n")
	other := append([]byte(nil), key...)
	other[0]++
	if _, err := opened(t, file, other); !errors.Is(err, ErrKey) {
		t.Errorf("another key: %v, want ErrKey", err)
	}
	if _, err := opened(t, file, nil); err == nil {
		t.Error("no key opened the recording")
	}
}

// Every shape of a change to the ciphertext: which error it is, and what
// a reader is allowed to have produced before it.
//
// A frame that does not open produces nothing, ever -- the plaintext of a
// tampered frame must not reach a reviewer. A file that stops early is
// different: the frames before the cut opened honestly, and a recording
// cut off by a crash is still an account of what happened before it. So
// those return their verified prefix *and* ErrTruncated, which is why
// every caller here treats the error as fatal rather than as an end.
func TestAChangedFileDoesNotOpen(t *testing.T) {
	for _, tc := range []struct {
		name   string
		edit   func([]byte) []byte
		want   error
		prefix bool // a verified prefix may come out
	}{
		{"an octet of the ciphertext flipped", func(b []byte) []byte {
			b[HeaderLen+8] ^= 1
			return b
		}, ErrKey, false},
		{"an octet of the salt flipped", func(b []byte) []byte {
			b[len(Magic)+3] ^= 1
			return b
		}, ErrKey, false},
		{"the tail cut off", func(b []byte) []byte { return b[:len(b)-1] }, ErrTruncated, true},
		{"the end marker removed", func(b []byte) []byte {
			// The marker is a length and a bare tag: the last 4+16 octets.
			return b[:len(b)-(4+tagLen)]
		}, ErrTruncated, true},
		{"the header alone", func(b []byte) []byte { return b[:HeaderLen] }, ErrTruncated, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := opened(t, tc.edit(sealed(t, MinChunk, "one\r\n", "two\r\n")), key)
			if !errors.Is(err, tc.want) {
				t.Fatalf("%v, want %v", err, tc.want)
			}
			if !tc.prefix && len(got) > 0 {
				t.Errorf("%d octets of plaintext came out of a file that did not open", len(got))
			}
		})
	}
}

// One write, one chunk, one frame: a recording written in a single frame
// and then cut anywhere inside it yields nothing at all, because there is
// no verified prefix to yield.
func TestACutInsideTheOnlyFrameYieldsNothing(t *testing.T) {
	file := sealed(t, MinChunk, "sudo -i\r\n")
	for _, cut := range []int{HeaderLen, HeaderLen + 4, len(file) - (4 + tagLen) - 1} {
		got, err := opened(t, file[:cut], key)
		if !errors.Is(err, ErrTruncated) {
			t.Errorf("cut at %d: %v, want ErrTruncated", cut, err)
		}
		if len(got) > 0 {
			t.Errorf("cut at %d: %q came out", cut, got)
		}
	}
}

// A frame cannot be moved inside the file, which is what binds the
// counter into the additional data.
func TestFramesCannotBeReordered(t *testing.T) {
	file := sealed(t, MinChunk, strings.Repeat("a", MinChunk), strings.Repeat("b", MinChunk))
	// Two frames of exactly one chunk each, then the marker. Swap them.
	size := 4 + MinChunk + tagLen
	first := append([]byte(nil), file[HeaderLen:HeaderLen+size]...)
	second := append([]byte(nil), file[HeaderLen+size:HeaderLen+2*size]...)
	swapped := append([]byte(nil), file[:HeaderLen]...)
	swapped = append(swapped, second...)
	swapped = append(swapped, first...)
	swapped = append(swapped, file[HeaderLen+2*size:]...)
	if _, err := opened(t, swapped, key); !errors.Is(err, ErrKey) {
		t.Errorf("reordered frames: %v, want ErrKey", err)
	}
}

// And a frame cannot be moved between files, which is what binds the
// header. Two recordings under one configured key have different salts,
// so a frame taken from one is not a frame of the other.
func TestFramesCannotBeSplicedBetweenFiles(t *testing.T) {
	a := sealed(t, MinChunk, strings.Repeat("a", MinChunk), "tail\r\n")
	b := sealed(t, MinChunk, strings.Repeat("b", MinChunk), "tail\r\n")
	if bytes.Equal(a[:HeaderLen], b[:HeaderLen]) {
		t.Fatal("two recordings share a header, so they share a key stream")
	}
	size := 4 + MinChunk + tagLen
	spliced := append([]byte(nil), a[:HeaderLen]...)
	spliced = append(spliced, b[HeaderLen:HeaderLen+size]...)
	spliced = append(spliced, a[HeaderLen+size:]...)
	if _, err := opened(t, spliced, key); !errors.Is(err, ErrKey) {
		t.Errorf("a frame from another recording: %v, want ErrKey", err)
	}
}

// A file that grew after it was written is a fact about the file, and it
// stays one: a caller that reads again after the complaint is told the
// same thing rather than given the clean end of file that would let the
// answer be missed.
func TestBytesAfterTheEndAreReported(t *testing.T) {
	file := append(sealed(t, MinChunk, "one\r\n"), 0, 1, 2, 3)
	if _, err := opened(t, file, key); err == nil || !strings.Contains(err.Error(), "after the end") {
		t.Errorf("%v, want a complaint about bytes after the end", err)
	}
	r, err := NewReader(bytes.NewReader(file), key)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	for i := range 3 {
		n, err := r.Read(buf)
		if i == 0 {
			if n == 0 || err != nil {
				t.Fatalf("the first read: %d, %v", n, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), "after the end") {
			t.Errorf("read %d after the complaint: %d octets, %v", i, n, err)
		}
	}
}

// A file that is not one of these says so, rather than failing as a
// wrong key: a tool has to be able to tell an unencrypted recording from
// one it cannot read.
func TestAnUnencryptedFileIsNamedAsSuch(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"an asciicast header", `{"version":2,"width":80,"height":24}` + "\n"},
		{"empty", ""},
		{"shorter than a header", "XPROXY"},
		{"the magic of something else", strings.Repeat("Z", HeaderLen)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := opened(t, []byte(tc.body), key); !errors.Is(err, ErrNotEncrypted) {
				t.Errorf("%v, want ErrNotEncrypted", err)
			}
		})
	}
}

// The header describes the file, so a header that describes something
// this reader will not do is refused before any frame is opened.
func TestARefusedHeaderIsRefusedBeforeTheFrames(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func([]byte) []byte
		want string
	}{
		{"a suite that does not exist", func(b []byte) []byte {
			b[len(Magic)] = 9
			return b
		}, "unknown suite"},
		{"a chunk below the bound", func(b []byte) []byte {
			b[HeaderLen-1] = 1
			b[HeaderLen-2] = 0
			return b
		}, "outside"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := opened(t, tc.edit(sealed(t, MinChunk, "one\r\n")), key)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("%v, want %q", err, tc.want)
			}
		})
	}
}

// The chunk comes from configuration, so a value outside the bounds is
// an error rather than a silent clamp -- an operator who asked for one
// frame per megabyte and got one per 64 KiB was not told.
func TestTheChunkBoundsAreErrors(t *testing.T) {
	for _, chunk := range []int{1, MinChunk - 1, MaxChunk + 1, -1} {
		if _, err := NewWriter(io.Discard, key, chunk); err == nil {
			t.Errorf("chunk %d was accepted", chunk)
		}
	}
	if _, err := NewWriter(io.Discard, nil, MinChunk); err == nil {
		t.Error("a writer with no key was accepted")
	}
}

// Close is what writes the end marker, so a caller that forgets leaves a
// file that reads as truncated -- and a second Close is not a second
// marker.
func TestCloseIsWhatEndsTheFile(t *testing.T) {
	var b bytes.Buffer
	w, err := NewWriter(&b, key, MinChunk)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("one\r\n")); err != nil {
		t.Fatal(err)
	}
	unclosed := append([]byte(nil), b.Bytes()...)
	if _, err := opened(t, unclosed, key); !errors.Is(err, ErrTruncated) {
		t.Errorf("a recording still being written: %v, want ErrTruncated", err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("a second close: %v", err)
	}
	closed := b.Bytes()
	if _, err := w.Write([]byte("more")); err == nil {
		t.Error("a write after close was accepted")
	}
	got, err := opened(t, closed, key)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "one\r\n" {
		t.Errorf("read back %q", got)
	}
}

// A destination that fails partway is reported rather than swallowed: the
// recording is short, and the caller has to be able to say so.
func TestAFailingDestinationIsReported(t *testing.T) {
	w, err := NewWriter(&failAfter{n: HeaderLen}, key, MinChunk)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(strings.Repeat("x", MinChunk))); err == nil {
		t.Fatal("a write to a failed destination succeeded")
	}
	if _, err := w.Write([]byte("more")); err == nil {
		t.Error("a second write after a failure succeeded")
	}
	if err := w.Close(); err == nil {
		t.Error("close after a failure reported nothing")
	}
	// And a destination that fails while the header is being written is an
	// error from the constructor, not a writer that looks usable.
	if _, err := NewWriter(&failAfter{n: 2}, key, MinChunk); err == nil {
		t.Error("a writer was returned over a destination that could not take the header")
	}
}

// failAfter takes n octets and then refuses. It is a pointer so that the
// count is spent across writes; as a value it would forgive every write,
// which is a test that proves nothing.
type failAfter struct{ n int }

func (f *failAfter) Write(p []byte) (int, error) {
	if f.n <= 0 {
		return 0, io.ErrClosedPipe
	}
	if len(p) <= f.n {
		f.n -= len(p)
		return len(p), nil
	}
	n := f.n
	f.n = 0
	return n, io.ErrShortWrite
}

// failOnce refuses the nth write and takes everything after it, which is
// what a disk that filled and was then cleared looks like.
type failOnce struct {
	at, n int
}

func (f *failOnce) Write(p []byte) (int, error) {
	f.n++
	if f.n == f.at {
		return 0, io.ErrShortWrite
	}
	return len(p), nil
}

// A reader that stops returning data keeps returning the same error
// rather than resuming, so a caller that ignores one error does not get
// half a recording.
func TestAFailedReaderStaysFailed(t *testing.T) {
	file := sealed(t, MinChunk, "one\r\n")
	file[HeaderLen+8] ^= 1
	r, err := NewReader(bytes.NewReader(file), key)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	if _, err := r.Read(buf); !errors.Is(err, ErrKey) {
		t.Fatalf("first read: %v", err)
	}
	if _, err := r.Read(buf); !errors.Is(err, ErrKey) {
		t.Errorf("second read: %v, want the same error", err)
	}
}

// A file whose frames are all sealed under one key and one nonce sequence
// would leak the plaintext of one recording to anybody holding another:
// the same key stream twice is the classic way to lose a stream cipher. So
// the file key is derived per recording from a random salt, and the same
// session written twice does not produce the same file.
func TestTwoRecordingsDoNotShareAKeyStream(t *testing.T) {
	const body = "the same session, twice\r\n"
	a := sealed(t, MinChunk, body)
	b := sealed(t, MinChunk, body)
	if bytes.Equal(a[:HeaderLen], b[:HeaderLen]) {
		t.Fatal("two recordings share a header, so they share a salt")
	}
	// The comparison is the ciphertext itself and not the whole frame. A
	// GCM tag covers the additional data, which carries the salt, so the
	// tags differ even when the key stream does not -- comparing frames
	// would pass a file whose key stream was reused, which is the failure
	// this test exists for.
	n := len(body)
	ct := func(file []byte) []byte { return file[HeaderLen+4 : HeaderLen+4+n] }
	if bytes.Equal(ct(a), ct(b)) {
		t.Error("the same plaintext under the same configured key produced the same key stream")
	}
	// And both still read back, which is what says the salt in the file is
	// the salt the key was derived from.
	for i, file := range [][]byte{a, b} {
		got, err := opened(t, file, key)
		if err != nil || string(got) != body {
			t.Errorf("recording %d: %q, %v", i, got, err)
		}
	}
}

// The header says which suite and which frame size, and it is the
// additional data of every frame, so editing it does not produce a file
// that reads differently -- it produces a file that does not read.
func TestTheHeaderCannotBeEdited(t *testing.T) {
	// A frame size the reader would otherwise accept: the edit is not
	// refused by the bounds check, so what catches it is the seal.
	file := sealed(t, MinChunk, strings.Repeat("x", MinChunk), "tail\r\n")
	edited := append([]byte(nil), file...)
	binary.BigEndian.PutUint32(edited[HeaderLen-4:], 2*MinChunk)
	if _, err := opened(t, edited, key); !errors.Is(err, ErrKey) {
		t.Errorf("a re-written frame size: %v, want ErrKey", err)
	}
	// The reserved octet is in the additional data too, so a future field
	// cannot be set on an old file without the key.
	edited = append([]byte(nil), file...)
	edited[len(Magic)+1] = 1
	if _, err := opened(t, edited, key); !errors.Is(err, ErrKey) {
		t.Errorf("a set reserved octet: %v, want ErrKey", err)
	}
}

// A frame length is read before the frame is, so it decides an
// allocation: it is bounded by what the header says a chunk is, and a
// length outside that is named rather than attempted.
func TestAFrameLengthIsBoundedByTheHeader(t *testing.T) {
	for _, tc := range []struct {
		name   string
		length uint32
	}{
		{"four gigabytes", 0xFFFFFFFF},
		{"one more than a chunk and a tag", MinChunk + tagLen + 1},
		{"shorter than a tag", tagLen - 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := append([]byte(nil), sealed(t, MinChunk, "one\r\n")...)
			binary.BigEndian.PutUint32(file[HeaderLen:], tc.length)
			_, err := opened(t, file, key)
			if err == nil || !strings.Contains(err.Error(), "which is not") {
				t.Errorf("%v, want the frame length to be named as out of bounds", err)
			}
		})
	}
}

// No key at all is its own answer rather than a key of length zero that
// happens not to open anything: a caller who forgot has to be told.
func TestNoKeyIsItsOwnAnswer(t *testing.T) {
	file := sealed(t, MinChunk, "one\r\n")
	_, err := NewReader(bytes.NewReader(file), nil)
	if err == nil || !strings.Contains(err.Error(), "no key") {
		t.Errorf("%v, want a complaint about the missing key", err)
	}
}

// A writer that failed stays failed. Without that a destination which
// refused one frame and took the next would leave a file with a hole in
// the middle and an end marker at the end of it -- a recording that reads
// as whole and is not.
func TestAWriterThatFailedStaysFailed(t *testing.T) {
	// The second write to the destination is the first frame: the first is
	// the header.
	w, err := NewWriter(&failOnce{at: 2}, key, MinChunk)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(strings.Repeat("a", MinChunk))); err == nil {
		t.Fatal("the frame that was refused reported no error")
	}
	if _, err := w.Write([]byte(strings.Repeat("b", MinChunk))); err == nil {
		t.Error("a later write succeeded, so the file would have a hole in it")
	}
	if err := w.Close(); err == nil {
		t.Error("close reported nothing, so the file would end as though it were whole")
	}
}

// And a reader that failed stays failed, for the same reason from the
// other side: the frame after a tampered one may be perfectly good, and
// handing it over would show a reviewer a session with its middle
// replaced by nothing.
func TestAReaderThatFailedStaysFailedAcrossGoodFrames(t *testing.T) {
	file := sealed(t, MinChunk, strings.Repeat("a", MinChunk), strings.Repeat("b", MinChunk))
	file[HeaderLen+8] ^= 1
	r, err := NewReader(bytes.NewReader(file), key)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, MinChunk)
	if _, err := r.Read(buf); !errors.Is(err, ErrKey) {
		t.Fatalf("first read: %v", err)
	}
	n, err := r.Read(buf)
	if !errors.Is(err, ErrKey) {
		t.Errorf("second read: %v, want the same error", err)
	}
	if n > 0 {
		t.Errorf("%d octets of the frame after the tampered one were handed over", n)
	}
}
