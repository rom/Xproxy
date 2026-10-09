package replay

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"image/color"
	"strings"
	"testing"
)

// Every encoding, complete and then cut at every length.
//
// A recording is a file this proxy wrote and a replay draws it on
// somebody's screen, so the lengths in it are read defensively although this
// end wrote them: a session killed mid-rectangle leaves a truncated file,
// which is the ordinary case, and a file somebody edited must not get
// further than an error. The encodings are where that matters most -- they
// are the part of RFB whose length is computed from the content rather than
// stated, so a wrong length is a read past the end of a slice rather than a
// short message.
//
// Cutting at *every* prefix rather than at the offsets a reviewer picked is
// the point: it walks each length check in each encoding without anybody
// having to work out where they are.

// red, green and blue in the 5-6-5 format pf16 describes, and the colours
// they decode to.
var (
	red   = []byte{0xF8, 0x00}
	green = []byte{0x07, 0xE0}
	blue  = []byte{0x00, 0x1F}

	redRGBA   = color.RGBA{R: 255, A: 255}
	greenRGBA = color.RGBA{G: 255, A: 255}
	blueRGBA  = color.RGBA{B: 255, A: 255}
)

// decoder is a decoder over a framebuffer of this size in pf16.
func decoder(t *testing.T, w, h int) *Decoder {
	t.Helper()
	fb, err := NewFramebuffer(w, h, pf16(true))
	if err != nil {
		t.Fatal(err)
	}
	return NewDecoder(fb)
}

// u32 and cat keep the payload builders to one line each.
func u32(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b[:]
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func rep(b []byte, n int) []byte {
	var out []byte
	for i := 0; i < n; i++ {
		out = append(out, b...)
	}
	return out
}

// zrleOf wraps tile bytes in the length-prefixed zlib stream a ZRLE
// rectangle carries.
func zrleOf(t *testing.T, tiles []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(tiles); err != nil {
		t.Fatal(err)
	}
	// Flush rather than Close: a server flushes per rectangle and keeps the
	// stream open for the session, which is the shape this decoder reads.
	if err := zw.Flush(); err != nil {
		t.Fatal(err)
	}
	return cat(u32(uint32(buf.Len())), buf.Bytes())
}

func TestEveryEncodingCompleteAndThenCutShort(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enc     int32
		w, h    int
		payload func(*testing.T) []byte
		// check is run against the framebuffer after the complete payload.
		check func(*testing.T, *Decoder)
	}{
		{name: "raw", enc: encRaw, w: 2, h: 2,
			payload: func(*testing.T) []byte { return rep(red, 4) },
			check: func(t *testing.T, d *Decoder) {
				at(t, d, 0, 0, redRGBA)
				at(t, d, 1, 1, redRGBA)
			}},
		{name: "rre: a background and one subrectangle", enc: encRRE, w: 4, h: 4,
			payload: func(*testing.T) []byte {
				return cat(u32(1), green, red,
					[]byte{0, 1, 0, 1, 0, 2, 0, 2}) // x=1 y=1 w=2 h=2
			},
			check: func(t *testing.T, d *Decoder) {
				at(t, d, 0, 0, greenRGBA)
				at(t, d, 1, 1, redRGBA)
				at(t, d, 2, 2, redRGBA)
				at(t, d, 3, 3, greenRGBA)
			}},
		{name: "coRRE: the same with one-byte coordinates", enc: encCoRRE, w: 4, h: 4,
			payload: func(*testing.T) []byte {
				return cat(u32(1), green, blue, []byte{1, 1, 2, 2})
			},
			check: func(t *testing.T, d *Decoder) {
				at(t, d, 0, 0, greenRGBA)
				at(t, d, 2, 2, blueRGBA)
			}},
		{name: "hextile: a raw tile", enc: encHextile, w: 4, h: 4,
			payload: func(*testing.T) []byte {
				return cat([]byte{hexRaw}, rep(blue, 16))
			},
			check: func(t *testing.T, d *Decoder) { at(t, d, 2, 2, blueRGBA) }},
		{name: "hextile: a background, a foreground and a subrectangle",
			enc: encHextile, w: 4, h: 4,
			payload: func(*testing.T) []byte {
				return cat([]byte{hexBackground | hexForeground | hexAnySubrects},
					green, red, []byte{1}, []byte{0x11, 0x11}) // x=1 y=1 w=2 h=2
			},
			check: func(t *testing.T, d *Decoder) {
				at(t, d, 0, 0, greenRGBA)
				at(t, d, 1, 1, redRGBA)
				at(t, d, 2, 2, redRGBA)
			}},
		{name: "hextile: a coloured subrectangle", enc: encHextile, w: 4, h: 4,
			payload: func(*testing.T) []byte {
				return cat([]byte{hexBackground | hexAnySubrects | hexSubrectsColoured},
					green, []byte{1}, blue, []byte{0x00, 0x00}) // x=0 y=0 w=1 h=1
			},
			check: func(t *testing.T, d *Decoder) {
				at(t, d, 0, 0, blueRGBA)
				at(t, d, 1, 0, greenRGBA)
			}},
		// The inheritance is the property worth pinning: a tile that names no
		// colours takes the previous tile's, so a decoder that reset them
		// between tiles would paint the second half of every screen black.
		{name: "hextile: a second tile inherits the first's colours",
			enc: encHextile, w: 32, h: 16,
			payload: func(*testing.T) []byte {
				return cat(
					[]byte{hexBackground | hexForeground | hexAnySubrects},
					green, red, []byte{1}, []byte{0x00, 0xFF}, // the whole first tile red
					[]byte{0}) // and a tile that says nothing
			},
			check: func(t *testing.T, d *Decoder) {
				at(t, d, 0, 0, redRGBA)
				at(t, d, 16, 0, greenRGBA) // the inherited background
			}},
		{name: "trle: a raw tile", enc: encTRLE, w: 4, h: 4,
			payload: func(*testing.T) []byte { return cat([]byte{0}, rep(red, 16)) },
			check:   func(t *testing.T, d *Decoder) { at(t, d, 3, 3, redRGBA) }},
		{name: "trle: one colour", enc: encTRLE, w: 4, h: 4,
			payload: func(*testing.T) []byte { return cat([]byte{1}, green) },
			check:   func(t *testing.T, d *Decoder) { at(t, d, 2, 1, greenRGBA) }},
		{name: "trle: a packed palette", enc: encTRLE, w: 4, h: 4,
			payload: func(*testing.T) []byte {
				// Two colours, one bit an index, one byte a row: the left half
				// of each row is index 0 and the right half index 1.
				return cat([]byte{2}, green, blue, rep([]byte{0x30}, 4))
			},
			check: func(t *testing.T, d *Decoder) {
				at(t, d, 0, 0, greenRGBA)
				at(t, d, 1, 0, greenRGBA)
				at(t, d, 2, 0, blueRGBA)
				at(t, d, 3, 3, blueRGBA)
			}},
		{name: "trle: plain run length", enc: encTRLE, w: 4, h: 4,
			payload: func(*testing.T) []byte {
				// One run of sixteen: the colour, then the length less one.
				return cat([]byte{128}, blue, []byte{15})
			},
			check: func(t *testing.T, d *Decoder) { at(t, d, 1, 2, blueRGBA) }},
		{name: "trle: a run length of more than 255", enc: encTRLE, w: 64, h: 8,
			payload: func(*testing.T) []byte {
				// 512 pixels in one run: 255, 255 and then the remainder, which
				// is how a length past one byte is written.
				return cat([]byte{128}, red, []byte{255, 255, 1})
			},
			check: func(t *testing.T, d *Decoder) { at(t, d, 63, 7, redRGBA) }},
		{name: "trle: a palette run length", enc: encTRLE, w: 4, h: 4,
			payload: func(*testing.T) []byte {
				// Two palette entries, then index 0 with a run of sixteen and
				// nothing after it.
				return cat([]byte{130}, green, blue, []byte{0x80, 15})
			},
			check: func(t *testing.T, d *Decoder) { at(t, d, 3, 0, greenRGBA) }},
		{name: "trle: a palette index with no run", enc: encTRLE, w: 2, h: 1,
			payload: func(*testing.T) []byte {
				// Two single pixels rather than runs: the high bit clear.
				return cat([]byte{130}, green, blue, []byte{0x01, 0x00})
			},
			check: func(t *testing.T, d *Decoder) {
				at(t, d, 0, 0, blueRGBA)
				at(t, d, 1, 0, greenRGBA)
			}},
		{name: "zrle: tiles through the session's zlib stream", enc: encZRLE, w: 4, h: 4,
			payload: func(t *testing.T) []byte { return zrleOf(t, cat([]byte{1}, red)) },
			check:   func(t *testing.T, d *Decoder) { at(t, d, 1, 1, redRGBA) }},
		// The cursor rectangles are read to keep the stream in step and not
		// drawn: what was on the screen is the framebuffer, and a cursor
		// image is not part of it.
		{name: "a cursor is measured and not drawn", enc: pseudoCursor, w: 2, h: 2,
			payload: func(*testing.T) []byte { return make([]byte, 2*2*2+1*2) },
			check: func(t *testing.T, d *Decoder) {
				at(t, d, 0, 0, color.RGBA{}) // nothing was painted
			}},
		{name: "an X cursor as well", enc: pseudoXCursor, w: 2, h: 2,
			payload: func(*testing.T) []byte { return make([]byte, 6+2*1*2) },
			check:   func(t *testing.T, d *Decoder) { at(t, d, 0, 0, color.RGBA{}) }},
		{name: "an X cursor with no image is its six bytes of colours",
			enc: pseudoXCursor, w: 0, h: 0,
			payload: func(*testing.T) []byte { return make([]byte, 6) },
			check:   func(*testing.T, *Decoder) {}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := tc.payload(t)

			// Complete: it consumes the whole payload and paints.
			d := decoder(t, 64, 16)
			n, err := d.rect(payload, 0, 0, tc.w, tc.h, tc.enc)
			if err != nil {
				t.Fatalf("the complete rectangle: %v", err)
			}
			if n != len(payload) {
				t.Errorf("consumed %d of %d bytes", n, len(payload))
			}
			tc.check(t, d)

			// Then cut at every length before that one.
			for cut := 0; cut < len(payload); cut++ {
				d := decoder(t, 64, 16)
				n, err := d.rect(payload[:cut], 0, 0, tc.w, tc.h, tc.enc)
				if err == nil {
					t.Errorf("cut to %d of %d bytes: accepted, consuming %d",
						cut, len(payload), n)
					continue
				}
				if n != 0 {
					t.Errorf("cut to %d: refused and still reported %d bytes consumed",
						cut, n)
				}
				// And the same bytes complete still work on that decoder,
				// which is what a recording read event by event depends on.
				if _, err := d.rect(payload, 0, 0, tc.w, tc.h, tc.enc); err != nil {
					t.Errorf("cut to %d, then the whole rectangle: %v", cut, err)
				}
			}
		})
	}
}

// at asserts one pixel.
func at(t *testing.T, d *Decoder, x, y int, want color.RGBA) {
	t.Helper()
	if got := d.fb.img.RGBAAt(x, y); got != want {
		t.Errorf("pixel %d,%d is %v, want %v", x, y, got, want)
	}
}

// The counts and modes a rectangle can claim that no rectangle can mean.
// Each is a definite error rather than a short read: there is no amount of
// further bytes that would make it right, so holding the stream open for
// them would be waiting for a message that is not coming.
func TestTheEncodingsRefuseWhatNoServerCanMean(t *testing.T) {
	for _, tc := range []struct {
		name string
		enc  int32
		w, h int
		b    []byte
		want string
	}{
		{name: "more subrectangles than a rectangle can hold", enc: encRRE, w: 4, h: 4,
			b: cat(u32(1<<20+1), red), want: "subrectangles in one rectangle"},
		{name: "a zrle rectangle longer than the bound", enc: encZRLE, w: 4, h: 4,
			b: u32(1<<26 + 1), want: "a zrle rectangle of"},
		{name: "a tile mode between the palette and the run lengths",
			enc: encTRLE, w: 4, h: 4, b: []byte{17},
			want: "which the specification does not define"},
		{name: "the gap below the palette run lengths", enc: encTRLE, w: 4, h: 4,
			b: []byte{129}, want: "which the specification does not define"},
		{name: "an encoding this player does not read", enc: 0x574d5669, w: 4, h: 4,
			b: nil, want: "which this player does not decode"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := decoder(t, 8, 8)
			_, err := d.rect(tc.b, 0, 0, tc.w, tc.h, tc.enc)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want one about %q", err, tc.want)
			}
			if errors.Is(err, ErrShort) {
				t.Error("reported as a short read, so the stream would wait for bytes that cannot help")
			}
		})
	}
}

// A zrle stream that does not start with a zlib header is not a short read
// either: every later rectangle in the session goes through the same stream,
// so there is nothing to wait for.
func TestAZRLEStreamThatDoesNotStart(t *testing.T) {
	d := decoder(t, 8, 8)
	body := []byte{0xFF, 0xFF, 0xFF, 0xFF}
	_, err := d.rect(cat(u32(uint32(len(body))), body), 0, 0, 4, 4, encZRLE)
	if err == nil || !strings.Contains(err.Error(), "the zrle stream does not start") {
		t.Fatalf("error %v", err)
	}
}

// A desktop-size pseudo-rectangle resizes the framebuffer, keeping what was
// drawn where it still fits -- and is ignored for a size no framebuffer can
// have, rather than allocating for it.
func TestADesktopResizeKeepsWhatFitsAndRefusesWhatCannot(t *testing.T) {
	d := decoder(t, 4, 4)
	if _, err := d.rect(rep(red, 16), 0, 0, 4, 4, encRaw); err != nil {
		t.Fatal(err)
	}

	if _, err := d.rect(nil, 0, 0, 2, 8, pseudoDesktopSize); err != nil {
		t.Fatal(err)
	}
	if w, h := d.fb.Size(); w != 2 || h != 8 {
		t.Fatalf("the framebuffer is %dx%d, want 2x8", w, h)
	}
	at(t, d, 1, 3, redRGBA)      // inside the old picture
	at(t, d, 1, 7, color.RGBA{}) // past it

	for _, tc := range []struct {
		name string
		w, h int
	}{
		{"no width", 0, 8},
		{"no height", 8, 0},
		{"a negative width", -1, 8},
		{"more pixels than the bound", 1 << 16, 1 << 16},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := d.rect(nil, 0, 0, tc.w, tc.h, pseudoDesktopSize); err != nil {
				t.Fatal(err)
			}
			if w, h := d.fb.Size(); w != 2 || h != 8 {
				t.Errorf("the framebuffer became %dx%d", w, h)
			}
		})
	}
}

// A pixel format whose bits per pixel is not 8, 16 or 32 has no pixel size
// to read, so a raw rectangle in it is refused rather than read as zero-byte
// pixels for ever.
func TestAFormatWithNoPixelSize(t *testing.T) {
	pf := pf16(true)
	pf[0] = 24 // bits per pixel
	fb, err := NewFramebuffer(4, 4, pf)
	if err != nil {
		t.Fatal(err)
	}
	d := NewDecoder(fb)
	if _, err := d.rect(rep(red, 16), 0, 0, 4, 4, encRaw); err == nil ||
		!strings.Contains(err.Error(), "bits per pixel") {
		t.Fatalf("error %v", err)
	}
}

// copyRect moves a rectangle that is already on the screen, and it reads its
// source into a copy first: a move that overlaps itself would otherwise read
// pixels it had just written.
func TestACopyRectThatOverlapsItself(t *testing.T) {
	d := decoder(t, 4, 1)
	if _, err := d.rect(cat(red, green, blue, red), 0, 0, 4, 1, encRaw); err != nil {
		t.Fatal(err)
	}
	// Copy the leftmost three pixels one to the right, which overlaps.
	src := []byte{0, 0, 0, 0}
	if _, err := d.rect(src, 1, 0, 3, 1, encCopyRect); err != nil {
		t.Fatal(err)
	}
	for x, want := range []color.RGBA{redRGBA, redRGBA, greenRGBA, blueRGBA} {
		at(t, d, x, 0, want)
	}
}
