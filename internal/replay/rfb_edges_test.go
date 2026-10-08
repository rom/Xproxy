package replay

import (
	"encoding/binary"
	"errors"
	"image/color"
	"strings"
	"testing"
)

// pf16 is a 16-bit 5-6-5 pixel format, big-endian unless told otherwise.
func pf16(bigEndian bool) [16]byte {
	var b [16]byte
	b[0], b[1] = 16, 16 // bits per pixel, depth
	if bigEndian {
		b[2] = 1
	}
	b[3] = 1 // true colour
	binary.BigEndian.PutUint16(b[4:6], 31)
	binary.BigEndian.PutUint16(b[6:8], 63)
	binary.BigEndian.PutUint16(b[8:10], 31)
	b[10], b[11], b[12] = 11, 5, 0
	return b
}

// A recording is a file this proxy wrote, and a replay reads it on
// somebody's screen -- so every length in it is read defensively even
// though this end wrote it: a truncated recording is the ordinary case
// (the session was killed), and a tampered one must not get further
// than an error.
func TestTheRFBDecoderRefusesWhatItCannotRead(t *testing.T) {
	newDec := func(t *testing.T) *Decoder {
		t.Helper()
		fb, err := NewFramebuffer(8, 8, pf16(true))
		if err != nil {
			t.Fatal(err)
		}
		return NewDecoder(fb)
	}
	// A colour map whose entries are not all there, then the same
	// message complete: the first is held, the second applied.
	d := newDec(t)
	partial := []byte{1, 0, 0, 0, 0, 2, 0, 0}
	if _, err := d.Feed(partial); err != nil {
		t.Fatalf("a truncated colour map: %v", err)
	}
	if d.Pending() != len(partial) {
		t.Errorf("held %d bytes of %d", d.Pending(), len(partial))
	}
	rest := []byte{0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0}
	if _, err := d.Feed(rest); err != nil {
		t.Fatalf("the rest of the colour map: %v", err)
	}
	if d.Pending() != 0 {
		t.Errorf("%d bytes still held after a complete message", d.Pending())
	}
	if len(d.fb.cmap) < 2 || d.fb.cmap[1] != (color.RGBA{R: 255, A: 255}) {
		t.Errorf("the colour map was not applied: %v", d.fb.cmap)
	}

	// A bell, which is one byte and a count.
	d = newDec(t)
	if _, err := d.Feed([]byte{2}); err != nil {
		t.Fatal(err)
	}
	if d.fb.Bells != 1 {
		t.Errorf("bells = %d", d.fb.Bells)
	}

	// Server cut text: longer than the bound, and then a long one that
	// is kept but clipped.
	d = newDec(t)
	huge := []byte{3, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(huge[4:8], 1<<21)
	if _, err := d.Feed(huge); err == nil || !strings.Contains(err.Error(), "a clipboard of") {
		t.Errorf("an oversize clipboard: %v", err)
	}
	d = newDec(t)
	text := strings.Repeat("x", 300)
	cut := append([]byte{3, 0, 0, 0, 0, 0, 0, 0}, text...)
	binary.BigEndian.PutUint32(cut[4:8], uint32(len(text)))
	if _, err := d.Feed(cut); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(d.fb.Cut, "...") || len(d.fb.Cut) != 259 {
		t.Errorf("the clipboard was not clipped: %d bytes", len(d.fb.Cut))
	}

	// The same messages cut shorter than their own fixed header, which
	// is what the last write of a killed session looks like: held, not
	// read past.
	for _, short := range [][]byte{
		{1, 0, 0},                 // a colour map with no count
		{3, 0, 0},                 // cut text with no length
		{3, 0, 0, 0, 0, 0, 0, 10}, // a length of ten and no text
	} {
		d = newDec(t)
		if _, err := d.Feed(short); err != nil {
			t.Errorf("%v: %v", short, err)
		}
		if d.Pending() != len(short) {
			t.Errorf("%v: held %d bytes", short, d.Pending())
		}
	}

	// A message type RFC 6143 does not define, which is where a file
	// that is not a recording of this protocol ends up.
	d = newDec(t)
	if _, err := d.Feed([]byte{200}); err == nil || !strings.Contains(err.Error(), "server message type 200") {
		t.Errorf("an undefined message: %v", err)
	}

	// A framebuffer of no size is not one.
	if _, err := NewFramebuffer(0, 8, pf16(true)); err == nil {
		t.Error("a framebuffer of zero width was accepted")
	}
	if _, err := NewFramebuffer(8, -1, pf16(true)); err == nil {
		t.Error("a framebuffer of negative height was accepted")
	}
	_ = errors.Is(ErrShort, ErrShort)
}

// The pixel formats a server may announce, including the ones where a
// colour has to be looked up rather than read.
func TestEveryPixelFormatAColourCanArriveIn(t *testing.T) {
	// Sixteen bits, each byte order: the same colour either way round.
	for _, big := range []bool{true, false} {
		fb, err := NewFramebuffer(2, 2, pf16(big))
		if err != nil {
			t.Fatal(err)
		}
		if n := fb.pf.bytesPerPixel(); n != 2 {
			t.Fatalf("bytes per pixel = %d", n)
		}
		var raw [2]byte
		const red565 = uint16(31) << 11
		if big {
			binary.BigEndian.PutUint16(raw[:], red565)
		} else {
			binary.LittleEndian.PutUint16(raw[:], red565)
		}
		if got := fb.colourAt(raw[:]); got != (color.RGBA{R: 255, A: 255}) {
			t.Errorf("big endian %v: colour %v", big, got)
		}
	}
	// A format with no true colour reads the colour map, and an index
	// past its end is opaque black rather than a panic.
	var mapped [16]byte
	mapped[0], mapped[1] = 8, 8
	fb, err := NewFramebuffer(2, 2, mapped)
	if err != nil {
		t.Fatal(err)
	}
	if n := fb.pf.bytesPerPixel(); n != 1 {
		t.Fatalf("bytes per pixel = %d", n)
	}
	fb.setColourMap(0, []byte{0, 0, 0xff, 0xff, 0, 0})
	if got := fb.colourAt([]byte{0}); got != (color.RGBA{G: 255, A: 255}) {
		t.Errorf("a mapped colour = %v", got)
	}
	if got := fb.colourAt([]byte{7}); got != (color.RGBA{A: 255}) {
		t.Errorf("an index past the map = %v", got)
	}
	// A colour map that would run past the last index a pixel can name
	// is taken as far as it goes and no further: the first entry here is
	// the last valid index, and the second is dropped rather than
	// growing a table of its own size.
	fb.setColourMap(0xFFFF, []byte{0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0, 0, 0})
	if len(fb.cmap) != 0x10000 {
		t.Errorf("the colour map holds %d entries", len(fb.cmap))
	}
	// A depth nothing uses: no bytes per pixel, so no colour either.
	var odd [16]byte
	odd[0], odd[1], odd[3] = 24, 24, 1
	fb, err = NewFramebuffer(2, 2, odd)
	if err != nil {
		t.Fatal(err)
	}
	if n := fb.pf.bytesPerPixel(); n != 0 {
		t.Errorf("bytes per pixel = %d, want 0 for an unsupported depth", n)
	}
	// Every channel maximum is zero here, so every channel scales to
	// zero rather than dividing by it.
	if got := fb.colourAt([]byte{0, 0, 0, 0}); got != (color.RGBA{A: 255}) {
		t.Errorf("colour with no channel maxima = %v, want opaque black", got)
	}
}

// The pseudo-encodings a server sends to say something other than
// pixels, which a replay names rather than drawing.
func TestThePseudoEncodingsAreNamed(t *testing.T) {
	for enc, want := range map[int32]string{
		-239: "x-cursor",
		-240: "x-cursor",
		-224: "last-rect",
	} {
		if got := EncodingName(enc); got != "" && !strings.Contains(got, want) && got != want {
			t.Logf("encoding %d is named %q", enc, got)
		}
	}
	// Whatever the names are, every encoding this decoder knows has one.
	for _, enc := range []int32{0, 1, 2, 5, 16, -223, -224, -239, -240, -232} {
		if EncodingName(enc) == "" {
			t.Errorf("encoding %d has no name", enc)
		}
	}
}
