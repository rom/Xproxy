package rfb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// be appends big endian values, which is every number in RFB.
func be(out []byte, vals ...any) []byte {
	for _, v := range vals {
		switch n := v.(type) {
		case byte:
			out = append(out, n)
		case uint16:
			out = binary.BigEndian.AppendUint16(out, n)
		case uint32:
			out = binary.BigEndian.AppendUint32(out, n)
		case int32:
			out = binary.BigEndian.AppendUint32(out, uint32(n)) //nolint:gosec // encodings are signed
		case []byte:
			out = append(out, n...)
		default:
			panic("be: unsupported type")
		}
	}
	return out
}

// rect builds one rectangle header.
func rect(x, y, w, h uint16, enc int32) []byte {
	return be(nil, x, y, w, h, enc)
}

// update wraps rectangles in a framebuffer update with a count.
func update(count uint16, rects ...[]byte) []byte {
	out := be(nil, SrvFramebufferUpdate, byte(0), count)
	for _, r := range rects {
		out = append(out, r...)
	}
	return out
}

// bell is one byte, and it is the test's ruler: a reader that framed the
// message before it returns the bell next, and one that did not returns
// something else or an error. Asserting on the message after is the only
// way to prove a length was computed rather than guessed.
var bell = []byte{SrvBell}

// serverReader reads body, writing what it accepts into out so a test
// can prove the gateway forwards exactly what it read.
func serverReader(t *testing.T, body []byte, w, h uint16, bpp byte, lim UpdateLimits) (*ServerReader, *bytes.Buffer) {
	t.Helper()
	si := ServerInit{Width: w, Height: h}
	si.PixelFormat[0] = bpp
	var out bytes.Buffer
	r, err := NewServerReader(bytes.NewReader(body), &out, si, lim)
	if err != nil {
		t.Fatal(err)
	}
	return r, &out
}

// Every encoding the gateway frames is framed to the byte. Each case is
// a rectangle followed by a Bell: the Bell coming back proves the
// rectangle's payload length was computed exactly, and this is the test
// that a mistake in any of them would fail rather than corrupt.
func TestEveryFramableEncodingIsFramedExactly(t *testing.T) {
	const bpp = 4 // 32 bits per pixel
	cases := []struct {
		name string
		body []byte
	}{
		{"raw", append(rect(0, 0, 4, 2, EncRaw), make([]byte, 4*2*bpp)...)},
		{"copyrect", append(rect(0, 0, 8, 8, EncCopyRect), be(nil, uint16(1), uint16(2))...)},
		// RRE: a count, a background pixel, then count subrectangles of
		// a pixel and four 16 bit coordinates.
		{"rre", append(rect(0, 0, 8, 8, EncRRE), be(nil, uint32(2), make([]byte, bpp), make([]byte, 2*(bpp+8)))...)},
		// CoRRE is the same with 8 bit coordinates.
		{"corre", append(rect(0, 0, 8, 8, EncCoRRE), be(nil, uint32(3), make([]byte, bpp), make([]byte, 3*(bpp+4)))...)},
		{"zlib", append(rect(0, 0, 8, 8, EncZlib), be(nil, uint32(9), make([]byte, 9))...)},
		{"zrle", append(rect(0, 0, 8, 8, EncZRLE), be(nil, uint32(17), make([]byte, 17))...)},
		// A cursor is its pixels and then a one bit mask, padded to
		// whole bytes per row.
		{"cursor", append(rect(3, 4, 9, 5, PseudoCursor), make([]byte, 9*5*bpp+2*5)...)},
		{"xcursor", append(rect(0, 0, 9, 5, PseudoXCursor), make([]byte, 6+2*2*5)...)},
		{"xcursor-empty", rect(0, 0, 0, 0, PseudoXCursor)},
		{"desktop-size", rect(0, 0, 640, 480, PseudoDesktopSize)},
		{"extended-desktop-size", append(rect(0, 0, 640, 480, PseudoExtendedDesktop), be(nil, byte(2), byte(0), byte(0), byte(0), make([]byte, 32))...)},
		{"desktop-name", append(rect(0, 0, 0, 0, PseudoDesktopName), be(nil, uint32(4), []byte("lath"))...)},
		{"cursor-pos", rect(5, 6, 0, 0, PseudoCursorPos)},
		{"compress-level", rect(0, 0, 0, 0, PseudoCompressLevel0+5)},
		{"quality-level", rect(0, 0, 0, 0, PseudoQualityLevel0+3)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body := append(update(1, c.body), bell...)
			r, out := serverReader(t, body, 1024, 768, 32, UpdateLimits{})
			m, err := r.Next()
			if err != nil {
				t.Fatalf("the update did not frame: %v", err)
			}
			if m.Type != SrvFramebufferUpdate || m.Rectangles != 1 {
				t.Fatalf("message %d with %d rectangles", m.Type, m.Rectangles)
			}
			if got := out.Bytes(); !bytes.Equal(got, body[:len(body)-1]) {
				t.Errorf("forwarded %d bytes of a %d byte update", len(got), len(body)-1)
			}
			next, err := r.Next()
			if err != nil || next.Type != SrvBell {
				t.Fatalf("the message after the rectangle was %v (%v), so the rectangle was mis-framed", next.Type, err)
			}
		})
	}
}

// Hextile is the one framable encoding whose length can only be found by
// reading it, tile by tile, so each shape of tile gets its own case.
func TestHextileIsFramedTileByTile(t *testing.T) {
	const bpp = 4
	// A 17x17 rectangle is four tiles: 16x16, 1x16, 16x1 and 1x1, which
	// is what exercises the partial tiles at the edges.
	tiles := []byte{}
	// Tile one: raw.
	tiles = append(tiles, hextileRaw)
	tiles = append(tiles, make([]byte, 16*16*bpp)...)
	// Tile two: a background and a foreground, no subrectangles.
	tiles = append(tiles, hextileBackground|hextileForeground)
	tiles = append(tiles, make([]byte, 2*bpp)...)
	// Tile three: two plain subrectangles.
	tiles = append(tiles, hextileAnySubrects, 2)
	tiles = append(tiles, make([]byte, 2*2)...)
	// Tile four: two coloured subrectangles, which carry a pixel each.
	tiles = append(tiles, hextileAnySubrects|hextileSubrectsColoured, 2)
	tiles = append(tiles, make([]byte, 2*(bpp+2))...)

	body := append(update(1, append(rect(0, 0, 17, 17, EncHextile), tiles...)), bell...)
	r, _ := serverReader(t, body, 1024, 768, 32, UpdateLimits{})
	if _, err := r.Next(); err != nil {
		t.Fatalf("the hextile update did not frame: %v", err)
	}
	next, err := r.Next()
	if err != nil || next.Type != SrvBell {
		t.Fatalf("the message after the hextile was %v (%v)", next.Type, err)
	}
}

// An encoding the gateway cannot frame ends the stream rather than being
// guessed at: a gateway that guessed would read the next rectangle's
// header out of the middle of a picture.
func TestAnUnframableEncodingEndsTheStream(t *testing.T) {
	for _, enc := range []int32{EncTight, EncTRLE, EncZlibHex, EncJPEG, PseudoCursorWithAlpha, 12345} {
		body := update(1, append(rect(0, 0, 8, 8, enc), make([]byte, 64)...))
		r, _ := serverReader(t, body, 1024, 768, 32, UpdateLimits{})
		_, err := r.Next()
		if !errors.Is(err, ErrUnframable) {
			t.Errorf("%s: %v, want an unframable error", EncodingName(enc), err)
		}
	}
}

// The framebuffer bound is the first one that matters: it is the number
// the viewer allocates from before a single pixel arrives.
func TestTheFramebufferBoundRefusesAGiantDesktop(t *testing.T) {
	lim := UpdateLimits{MaxPixels: 1920 * 1080}
	if err := lim.CheckFramebuffer(1920, 1080); err != nil {
		t.Errorf("an ordinary desktop was refused: %v", err)
	}
	if err := lim.CheckFramebuffer(65535, 65535); !errors.Is(err, ErrFramebufferTooLarge) {
		t.Errorf("65535x65535 gave %v", err)
	}
	// No bound is no bound.
	if err := (UpdateLimits{}).CheckFramebuffer(65535, 65535); err != nil {
		t.Errorf("an unbounded listener refused a desktop: %v", err)
	}
}

// A rectangle that reaches outside the framebuffer is a write past the
// end of the buffer the viewer allocated for it.
func TestARectangleOutsideTheFramebufferIsRefused(t *testing.T) {
	for _, c := range []struct{ x, y, w, h uint16 }{
		{0, 0, 641, 1}, {0, 0, 1, 481}, {640, 0, 1, 1}, {0, 480, 1, 1}, {600, 400, 100, 100},
	} {
		body := update(1, append(rect(c.x, c.y, c.w, c.h, EncRaw), make([]byte, int(c.w)*int(c.h)*4)...))
		r, _ := serverReader(t, body, 640, 480, 32, UpdateLimits{})
		if _, err := r.Next(); !errors.Is(err, ErrRectangleOutside) {
			t.Errorf("a %dx%d rectangle at %d,%d in a 640x480 framebuffer gave %v", c.w, c.h, c.x, c.y, err)
		}
	}
	// One that fits exactly is not refused.
	body := append(update(1, append(rect(0, 0, 640, 480, EncRaw), make([]byte, 640*480*4)...)), bell...)
	r, _ := serverReader(t, body, 640, 480, 32, UpdateLimits{})
	if _, err := r.Next(); err != nil {
		t.Errorf("a full screen rectangle was refused: %v", err)
	}
}

// A thousand one pixel rectangles cost the viewer a thousand decode
// calls for one screen.
func TestTooManyRectangles(t *testing.T) {
	var rects [][]byte
	for i := 0; i < 8; i++ {
		rects = append(rects, append(rect(uint16(i), 0, 1, 1, EncRaw), make([]byte, 4)...))
	}
	body := update(8, rects...)
	r, _ := serverReader(t, body, 640, 480, 32, UpdateLimits{MaxRectangles: 4})
	if _, err := r.Next(); !errors.Is(err, ErrTooManyRectangles) {
		t.Errorf("eight rectangles under a bound of four gave %v", err)
	}
	// Exactly the bound is allowed.
	body = append(update(4, rects[:4]...), bell...)
	r, _ = serverReader(t, body, 640, 480, 32, UpdateLimits{MaxRectangles: 4})
	if m, err := r.Next(); err != nil || m.Rectangles != 4 {
		t.Errorf("four rectangles under a bound of four gave %d, %v", m.Rectangles, err)
	}
}

// The encoded payload bound is checked against the length the rectangle
// declares, before the bytes are read: an oversize rectangle is refused
// rather than read into memory and then refused.
func TestAnOversizeEncodedRectangleIsRefusedBeforeItIsRead(t *testing.T) {
	// A zlib rectangle declaring a megabyte, with none of it present.
	body := update(1, append(rect(0, 0, 8, 8, EncZlib), be(nil, uint32(1<<20))...))
	r, _ := serverReader(t, body, 640, 480, 32, UpdateLimits{MaxRectBytes: 4096})
	if _, err := r.Next(); !errors.Is(err, ErrRectangleTooLarge) {
		t.Errorf("a megabyte under a 4096 bound gave %v", err)
	}
}

// The decode ratio is the decompression bomb check, and it is made
// without decompressing anything: the picture a rectangle declares
// against the bytes that carry it.
func TestTheDecodeRatioRefusesABomb(t *testing.T) {
	lim := UpdateLimits{MaxRatio: 100}
	// 512x512 at four bytes a pixel is a megabyte, declared in sixteen
	// bytes of zlib: a ratio of over sixty thousand.
	bomb := update(1, append(rect(0, 0, 512, 512, EncZRLE), be(nil, uint32(16), make([]byte, 16))...))
	r, _ := serverReader(t, bomb, 1024, 1024, 32, lim)
	if _, err := r.Next(); !errors.Is(err, ErrDecodeRatio) {
		t.Errorf("a 65000-fold expansion gave %v", err)
	}
	// Ordinary compression passes, which is the half that proves the
	// bound is not simply refusing compression: the same rectangle in
	// 64 kilobytes is a sixteenfold saving and a real screen.
	ok := append(update(1, append(rect(0, 0, 512, 512, EncZRLE), be(nil, uint32(64<<10), make([]byte, 64<<10))...)), bell...)
	r, _ = serverReader(t, ok, 1024, 1024, 32, lim)
	if _, err := r.Next(); err != nil {
		t.Errorf("a sixteenfold saving was refused: %v", err)
	}
	// A raw rectangle is never a bomb: it carries every pixel it
	// declares, so the ratio does not apply to it.
	raw := append(update(1, append(rect(0, 0, 512, 512, EncRaw), make([]byte, 512*512*4)...)), bell...)
	r, _ = serverReader(t, raw, 1024, 1024, 32, lim)
	if _, err := r.Next(); err != nil {
		t.Errorf("a raw rectangle was measured against the decode ratio: %v", err)
	}
}

// LastRect ends an update whatever the count said, which is how a server
// that does not know the count in advance sends one.
func TestLastRectEndsAnUpdateWhateverTheCountSaid(t *testing.T) {
	body := append(update(0xffff,
		append(rect(0, 0, 2, 2, EncRaw), make([]byte, 2*2*4)...),
		rect(0, 0, 0, 0, PseudoLastRect),
	), bell...)
	r, _ := serverReader(t, body, 640, 480, 32, UpdateLimits{MaxRectangles: 8})
	m, err := r.Next()
	if err != nil {
		t.Fatalf("the update did not frame: %v", err)
	}
	if m.Rectangles != 2 {
		t.Errorf("%d rectangles, want the picture and the LastRect", m.Rectangles)
	}
	if next, err := r.Next(); err != nil || next.Type != SrvBell {
		t.Fatalf("the message after a LastRect update was %v (%v)", next.Type, err)
	}
}

// A resize changes what the following rectangles are measured against,
// and is bounded itself: a desktop cannot get past the framebuffer bound
// by announcing a small screen and then growing it.
func TestAResizeMovesTheFramebufferAndIsBounded(t *testing.T) {
	lim := UpdateLimits{MaxPixels: 1920 * 1080}
	// Grow to 1024x1024, then draw a rectangle that only fits after the
	// resize.
	body := append(update(2,
		rect(0, 0, 1024, 1024, PseudoDesktopSize),
		append(rect(0, 0, 1024, 1024, EncRaw), make([]byte, 1024*1024*4)...),
	), bell...)
	r, _ := serverReader(t, body, 640, 480, 32, lim)
	m, err := r.Next()
	if err != nil {
		t.Fatalf("a resize followed by a full screen rectangle: %v", err)
	}
	if !m.Resized || m.Width != 1024 || m.Height != 1024 {
		t.Errorf("resize %v to %dx%d", m.Resized, m.Width, m.Height)
	}
	// A resize past the bound is refused.
	body = update(1, rect(0, 0, 32000, 32000, PseudoDesktopSize))
	r, _ = serverReader(t, body, 640, 480, 32, lim)
	if _, err := r.Next(); !errors.Is(err, ErrFramebufferTooLarge) {
		t.Errorf("a resize to 32000x32000 gave %v", err)
	}
}

// A clipboard transfer is bounded in both directions, and the extended
// format -- whose length arrives negated -- is bounded the same way.
func TestCutTextIsBounded(t *testing.T) {
	lim := UpdateLimits{MaxCutText: 16}
	body := be(nil, SrvCutText, byte(0), byte(0), byte(0), uint32(64), make([]byte, 64))
	r, _ := serverReader(t, body, 640, 480, 32, lim)
	if _, err := r.Next(); !errors.Is(err, ErrCutTextTooLarge) {
		t.Errorf("64 bytes under a bound of 16 gave %v", err)
	}
	// The extended format: the same length, negated.
	body = be(nil, SrvCutText, byte(0), byte(0), byte(0), int32(-64), make([]byte, 64))
	r, _ = serverReader(t, body, 640, 480, 32, lim)
	if _, err := r.Next(); !errors.Is(err, ErrCutTextTooLarge) {
		t.Errorf("an extended transfer of 64 bytes gave %v", err)
	}
	// One inside the bound is read whole, and the message after it
	// proves the length was honoured.
	body = append(be(nil, SrvCutText, byte(0), byte(0), byte(0), int32(-8), make([]byte, 8)), bell...)
	r, _ = serverReader(t, body, 640, 480, 32, lim)
	m, err := r.Next()
	if err != nil || !m.Extended || m.CutText != 8 {
		t.Fatalf("extended %v of %d bytes: %v", m.Extended, m.CutText, err)
	}
	if next, err := r.Next(); err != nil || next.Type != SrvBell {
		t.Fatalf("the message after an extended transfer was %v (%v)", next.Type, err)
	}
}

// A pixel format the gateway cannot measure lengths in is refused where
// it arrives rather than producing lengths that are wrong.
func TestAnImpossiblePixelFormatIsRefused(t *testing.T) {
	for _, bits := range []byte{0, 1, 24, 64} {
		var pf [16]byte
		pf[0] = bits
		if _, err := BytesPerPixel(pf); err == nil {
			t.Errorf("%d bits per pixel was accepted", bits)
		}
	}
	for _, bits := range []byte{8, 16, 32} {
		var pf [16]byte
		pf[0] = bits
		if n, err := BytesPerPixel(pf); err != nil || n != int(bits)/8 {
			t.Errorf("%d bits per pixel gave %d, %v", bits, n, err)
		}
	}
}

// A server message the gateway cannot frame ends the stream, which is
// what keeps a file transfer out: the vendors put theirs in message
// types whose length nothing else knows.
func TestAnUnframableServerMessageEndsTheStream(t *testing.T) {
	for _, typ := range []byte{SrvTightFileTransfer, SrvProprietary, SrvXvp, SrvGII, SrvVMware, 42} {
		r, _ := serverReader(t, []byte{typ, 0, 0, 0, 0, 0, 0, 0}, 640, 480, 32, UpdateLimits{})
		if _, err := r.Next(); !errors.Is(err, ErrUnframable) {
			t.Errorf("%s gave %v", ServerMessageName(typ), err)
		}
	}
	// The ones it does know are framed, each followed by a Bell.
	cases := map[string][]byte{
		"set-colour-map":            be(nil, SrvSetColourMapEntries, byte(0), uint16(0), uint16(3), make([]byte, 18)),
		"bell":                      {SrvBell},
		"end-of-continuous-updates": {SrvEndOfContinuous},
		"fence":                     be(nil, SrvFence, byte(0), byte(0), byte(0), uint32(0), byte(4), make([]byte, 4)),
	}
	for name, body := range cases {
		r, _ := serverReader(t, append(body, bell...), 640, 480, 32, UpdateLimits{})
		if _, err := r.Next(); err != nil {
			t.Errorf("%s did not frame: %v", name, err)
		}
		if next, err := r.Next(); err != nil || next.Type != SrvBell {
			t.Errorf("the message after a %s was %v (%v)", name, next.Type, err)
		}
	}
}

// Every client message the gateway frames is framed to the byte, and the
// ones it does not know end the stream. The vendors' file transfer lives
// in the second group, which is why a file cannot cross this gateway:
// not because a rule forbids it, but because forwarding a message whose
// length is unknown would lose every message after it.
func TestClientMessagesAreFramedExactly(t *testing.T) {
	var pf [16]byte
	pf[0] = 32
	known := map[string][]byte{
		"set-pixel-format":          be(nil, CliSetPixelFormat, byte(0), byte(0), byte(0), pf[:]),
		"set-encodings":             be(nil, CliSetEncodings, byte(0), uint16(2), EncRaw, EncZRLE),
		"update-request":            be(nil, CliUpdateRequest, byte(1), uint16(0), uint16(0), uint16(64), uint16(64)),
		"key-event":                 be(nil, CliKeyEvent, byte(1), uint16(0), uint32(65)),
		"pointer-event":             be(nil, CliPointerEvent, byte(0), uint16(10), uint16(20)),
		"client-cut-text":           be(nil, CliCutText, byte(0), byte(0), byte(0), uint32(3), []byte("abc")),
		"enable-continuous-updates": be(nil, CliEnableContinuous, byte(1), uint16(0), uint16(0), uint16(64), uint16(64)),
		"fence":                     be(nil, CliFence, byte(0), byte(0), byte(0), uint32(0), byte(2), []byte("hi")),
		"set-desktop-size":          be(nil, CliSetDesktopSize, byte(0), uint16(1280), uint16(720), byte(1), byte(0), make([]byte, 16)),
	}
	for name, body := range known {
		// A key event after it is the ruler: it comes back only if the
		// first message's length was computed exactly.
		ruler := be(nil, CliKeyEvent, byte(1), uint16(0), uint32(66))
		r := NewClientReader(bytes.NewReader(append(body, ruler...)), UpdateLimits{})
		m, err := r.Next()
		if err != nil {
			t.Errorf("%s did not frame: %v", name, err)
			continue
		}
		if !bytes.Equal(m.Bytes, body) {
			t.Errorf("%s: framed %d bytes of %d", name, len(m.Bytes), len(body))
		}
		if next, err := r.Next(); err != nil || next.Type != CliKeyEvent {
			t.Errorf("the message after a %s was %v (%v)", name, next.Type, err)
		}
	}
	for _, typ := range []byte{CliTightFileTransfer, CliQEMU, CliGII, CliXvp, CliFixColourMap, 99} {
		r := NewClientReader(bytes.NewReader([]byte{typ, 0, 0, 0, 0, 0, 0, 0}), UpdateLimits{})
		if _, err := r.Next(); !errors.Is(err, ErrUnframable) {
			t.Errorf("%s gave %v", ClientMessageName(typ), err)
		}
	}
}

// What a SetEncodings carried is read out, because the gateway decides
// what the desktop is allowed to draw with.
func TestSetEncodingsIsReadAndBounded(t *testing.T) {
	body := be(nil, CliSetEncodings, byte(0), uint16(3), EncTight, EncZRLE, PseudoCursor)
	r := NewClientReader(bytes.NewReader(body), UpdateLimits{})
	m, err := r.Next()
	if err != nil {
		t.Fatal(err)
	}
	want := []int32{EncTight, EncZRLE, PseudoCursor}
	if len(m.Encodings) != len(want) {
		t.Fatalf("%v, want %v", m.Encodings, want)
	}
	for i := range want {
		if m.Encodings[i] != want[i] {
			t.Errorf("encoding %d is %d, want %d", i, m.Encodings[i], want[i])
		}
	}
	// A count past the bound is refused before the list is allocated.
	body = be(nil, CliSetEncodings, byte(0), uint16(65535))
	r = NewClientReader(bytes.NewReader(body), UpdateLimits{})
	if _, err := r.Next(); err == nil || !strings.Contains(err.Error(), "bound") {
		t.Errorf("65535 encodings gave %v", err)
	}
}

// The filter keeps what the gateway can frame, in the order the client
// asked for it, and never leaves a list with nothing to draw with.
func TestFilterEncodingsKeepsOrderAndAlwaysLeavesAPicture(t *testing.T) {
	asked := []int32{EncTight, EncZRLE, EncTRLE, EncHextile, PseudoCursor, PseudoCursorWithAlpha,
		EncCopyRect, PseudoLEDState, PseudoFence, PseudoExtendedClipboard}
	kept, removed := FilterEncodings(asked)
	wantKept := []int32{EncZRLE, EncHextile, PseudoCursor, EncCopyRect, PseudoFence, PseudoExtendedClipboard}
	if len(kept) != len(wantKept) {
		t.Fatalf("kept %v, want %v", kept, wantKept)
	}
	for i := range wantKept {
		if kept[i] != wantKept[i] {
			t.Fatalf("kept %v, want %v", kept, wantKept)
		}
	}
	wantGone := map[int32]bool{EncTight: true, EncTRLE: true, PseudoCursorWithAlpha: true, PseudoLEDState: true}
	for _, e := range removed {
		if !wantGone[e] {
			t.Errorf("%s was removed", EncodingName(e))
		}
		delete(wantGone, e)
	}
	if len(wantGone) != 0 {
		t.Errorf("these survived the filter: %v", wantGone)
	}
	// A client that asked only for encodings the gateway cannot frame
	// still gets a session that can draw: raw is mandatory in RFB, so it
	// is what is left.
	kept, removed = FilterEncodings([]int32{EncTight, EncTRLE})
	if len(kept) != 1 || kept[0] != EncRaw || len(removed) != 2 {
		t.Errorf("a tight-only client was left with %v (removed %v)", kept, removed)
	}
	// A list that already has a picture is not given raw as well.
	kept, _ = FilterEncodings([]int32{EncZRLE, EncTight})
	if len(kept) != 1 || kept[0] != EncZRLE {
		t.Errorf("raw was added to a list that could already draw: %v", kept)
	}
}

// The encoded form round-trips, because the gateway forwards a list it
// has filtered rather than the one it was given.
func TestEncodeSetEncodingsRoundTrips(t *testing.T) {
	list := []int32{EncRaw, EncZRLE, PseudoCursor, PseudoCompressLevel0 + 2}
	r := NewClientReader(bytes.NewReader(EncodeSetEncodings(list)), UpdateLimits{})
	m, err := r.Next()
	if err != nil || m.Type != CliSetEncodings {
		t.Fatalf("message %d: %v", m.Type, err)
	}
	if len(m.Encodings) != len(list) {
		t.Fatalf("%v, want %v", m.Encodings, list)
	}
	for i := range list {
		if m.Encodings[i] != list[i] {
			t.Fatalf("%v, want %v", m.Encodings, list)
		}
	}
}

// A client's clipboard is bounded the same way the desktop's is, in both
// the ordinary and the extended format.
func TestClientCutTextIsBounded(t *testing.T) {
	lim := UpdateLimits{MaxCutText: 4}
	for _, n := range []int32{16, -16} {
		body := be(nil, CliCutText, byte(0), byte(0), byte(0), n, make([]byte, 16))
		r := NewClientReader(bytes.NewReader(body), lim)
		if _, err := r.Next(); !errors.Is(err, ErrCutTextTooLarge) {
			t.Errorf("a transfer of length %d gave %v", n, err)
		}
	}
}

// The picture is written onward as it is read, not assembled and then
// forwarded. A gateway that assembled a full screen update per session
// would hold tens of megabytes times max_connections, which is a way of
// running a proxy out of memory by connecting to it.
//
// The proof is a megabyte rectangle cut short: most of it is already on
// its way out when the read fails, in pieces, rather than waiting for a
// last byte that never comes.
func TestThePictureIsWrittenOnwardAsItIsRead(t *testing.T) {
	const declared = 512 * 512 * 4 // a megabyte at 32 bits per pixel
	body := update(1, append(rect(0, 0, 512, 512, EncRaw), make([]byte, declared-100)...))
	r, out := serverReader(t, body, 1024, 1024, 32, UpdateLimits{})
	if _, err := r.Next(); err == nil {
		t.Fatal("a truncated rectangle was accepted")
	}
	// Everything but the piece the read died in has been forwarded, so
	// the gateway was holding one piece and not a picture.
	forwarded := out.Len()
	if forwarded < declared-chunk*2 {
		t.Errorf("only %d of %d bytes had been forwarded, so the message was being assembled", forwarded, declared)
	}
	if forwarded >= len(body) {
		t.Errorf("%d bytes forwarded out of a %d byte message that never finished", forwarded, len(body))
	}
}

// A hextile rectangle's length is only known once it has been read, so
// the bound on it is applied as the tiles arrive rather than after the
// whole rectangle: the session ends where the bound is crossed.
func TestAHextileRectangleIsStoppedWhereTheBoundIsCrossed(t *testing.T) {
	const bpp = 4
	tiles := []byte{}
	for i := 0; i < 16; i++ { // sixteen raw tiles of 16x16
		tiles = append(tiles, hextileRaw)
		tiles = append(tiles, make([]byte, 16*16*bpp)...)
	}
	body := update(1, append(rect(0, 0, 256, 16, EncHextile), tiles...))
	// Two tiles' worth: the third crosses it.
	r, out := serverReader(t, body, 640, 480, 32, UpdateLimits{MaxRectBytes: 2 * 16 * 16 * bpp})
	if _, err := r.Next(); !errors.Is(err, ErrRectangleTooLarge) {
		t.Fatalf("a hextile rectangle over the bound gave %v", err)
	}
	if out.Len() >= len(body) {
		t.Error("the whole rectangle was forwarded before the bound fired")
	}
}

// A pixel format change that arrives while the reader is waiting for bytes
// takes effect on the rectangle that follows it, not the one after that.
//
// This is the ordering the stream actually has. A client's SetPixelFormat
// reaches the server as soon as whoever is forwarding it writes it, so the very
// next rectangle is in the new format -- while the reader is blocked on the
// socket and cannot be told anything. Taking the change between messages sized
// that rectangle with the old bytes per pixel: at 32 bits announced and 8 asked
// for, a 64x1 raw rectangle carrying 64 bytes was read as 256, and the 192 bytes
// of over-read swallowed whatever the server sent next -- a ServerCutText the
// policy would have dropped, or a message type the gateway refuses to frame --
// and passed it through unread.
//
// The Bell is the ruler, as everywhere else here: it comes back as its own
// message only if the rectangle's length was computed from the format in force.
func TestAPendingPixelFormatAppliesToTheNextRectangle(t *testing.T) {
	// 64x1 raw at 8 bits per pixel is 64 bytes; at the announced 32 it would be
	// 256, so a reader on the old format over-reads by 192 and eats the Bell.
	body := append(update(1, append(rect(0, 0, 64, 1, EncRaw), make([]byte, 64)...)), bell...)
	r, out := serverReader(t, body, 1024, 768, 32, UpdateLimits{})

	var eight [16]byte
	eight[0] = 8
	handed := false
	r.SetPendingFormat(func() ([16]byte, bool) {
		if handed {
			return [16]byte{}, false
		}
		handed = true
		return eight, true
	})

	m, err := r.Next()
	if err != nil {
		t.Fatalf("the update did not frame: %v", err)
	}
	if m.Type != SrvFramebufferUpdate || m.Rectangles != 1 {
		t.Fatalf("message %d with %d rectangles", m.Type, m.Rectangles)
	}
	if got, want := out.Len(), len(body)-len(bell); got != want {
		t.Errorf("forwarded %d bytes, want the %d of the update alone", got, want)
	}
	next, err := r.Next()
	if err != nil {
		t.Fatalf("the bell did not frame, so the rectangle over-read: %v", err)
	}
	if next.Type != SrvBell {
		t.Errorf("the message after the rectangle was %d, want a bell", next.Type)
	}
}

// And a format the reader cannot measure lengths in is an error rather than a
// silently kept old one.
func TestAPendingPixelFormatThatCannotBeMeasuredIsRefused(t *testing.T) {
	body := append(update(1, append(rect(0, 0, 4, 2, EncRaw), make([]byte, 4*2*4)...)), bell...)
	r, _ := serverReader(t, body, 1024, 768, 32, UpdateLimits{})
	var odd [16]byte
	odd[0] = 7 // not 8, 16 or 32
	r.SetPendingFormat(func() ([16]byte, bool) { return odd, true })
	if _, err := r.Next(); err == nil {
		t.Error("a format with no whole number of bytes per pixel was accepted")
	}
}
