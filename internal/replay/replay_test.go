package replay

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image/color"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/recenc"
)

// A recording is written by the proxy and read here, so the tests build
// the file the way the proxy does: a header line and one JSON array per
// event.

// pf32 is 32 bits, little endian, true colour, eight bits each: what a
// viewer asks for unless it says otherwise.
var pf32 = [16]byte{32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0}

func write(t *testing.T, dir, name string, env map[string]string, w, h int, events ...[2]any) string {
	t.Helper()
	var b bytes.Buffer
	head := map[string]any{"version": 2, "width": w, "height": h, "env": env}
	line, err := json.Marshal(head)
	if err != nil {
		t.Fatal(err)
	}
	b.Write(line)
	b.WriteByte('\n')
	binary := env["XPROXY_ENCODING"] == "base64"
	for _, ev := range events {
		data := string(ev[1].([]byte))
		if binary {
			data = base64.StdEncoding.EncodeToString(ev[1].([]byte))
		}
		out, err := json.Marshal([]any{ev[0], "o", data})
		if err != nil {
			t.Fatal(err)
		}
		b.Write(out)
		b.WriteByte('\n')
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// rfbEnv is the header a vnc recording carries.
func rfbEnv() map[string]string {
	return map[string]string{
		"XPROXY_PROTOCOL":     "rfb",
		"XPROXY_STREAM":       "rfb-server-to-client",
		"XPROXY_PIXEL_FORMAT": hex.EncodeToString(pf32[:]),
		"XPROXY_ENCODING":     "base64",
	}
}

// update builds a framebuffer update out of already-encoded rectangles.
func update(rects ...[]byte) []byte {
	out := []byte{0, 0, 0, 0}
	binary.BigEndian.PutUint16(out[2:4], uint16(len(rects)))
	for _, r := range rects {
		out = append(out, r...)
	}
	return out
}

func rect(x, y, w, h int, enc int32, payload []byte) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[0:2], uint16(x))
	binary.BigEndian.PutUint16(b[2:4], uint16(y))
	binary.BigEndian.PutUint16(b[4:6], uint16(w))
	binary.BigEndian.PutUint16(b[6:8], uint16(h))
	binary.BigEndian.PutUint32(b[8:12], uint32(enc)) //nolint:gosec // the field is signed on the wire
	return append(b, payload...)
}

// px is one pixel in the format above.
func px(r, g, bl uint8) []byte { return []byte{bl, g, r, 0} }

// The floor: a recording is opened, its kind comes from the header the
// proxy wrote rather than from the bytes, and a raw rectangle lands where
// it says it does.
func TestARawRectangleLandsWhereItSays(t *testing.T) {
	dir := t.TempDir()
	body := update(rect(1, 1, 2, 1, 0, append(px(255, 0, 0), px(0, 255, 0)...)))
	path := write(t, dir, "s.rfb.cast", rfbEnv(), 4, 4, [2]any{0.1, body})
	rec, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rec.Close() }()
	if rec.Kind != KindRFB {
		t.Fatalf("kind %q", rec.Kind)
	}
	pf, ok := rec.PixelFormat()
	if !ok {
		t.Fatal("the recorded pixel format was not read")
	}
	fb, err := NewFramebuffer(4, 4, pf)
	if err != nil {
		t.Fatal(err)
	}
	d := NewDecoder(fb)
	var ups []Update
	if err := rec.Each(func(ev Event) error {
		u, err := d.Feed(ev.Data)
		ups = append(ups, u...)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(ups) != 1 || len(ups[0].Rects) != 1 {
		t.Fatalf("updates %+v", ups)
	}
	if got := fb.Image().RGBAAt(1, 1); got != (color.RGBA{R: 255, A: 255}) {
		t.Errorf("pixel at 1,1 is %+v", got)
	}
	if got := fb.Image().RGBAAt(2, 1); got != (color.RGBA{G: 255, A: 255}) {
		t.Errorf("pixel at 2,1 is %+v", got)
	}
	if got := fb.Image().RGBAAt(0, 0); got != (color.RGBA{}) {
		t.Errorf("a pixel nobody wrote is %+v", got)
	}
}

// Every encoding RFC 6143 specifies is decoded, and each one is checked
// by the pixels it puts on the screen rather than by parsing without
// error: a decoder that consumed the bytes and drew nothing would pass
// the second test and fail the person reading the recording.
func TestTheSpecifiedEncodingsAreDecoded(t *testing.T) {
	red := color.RGBA{R: 255, A: 255}
	green := color.RGBA{G: 255, A: 255}
	for _, tc := range []struct {
		name  string
		body  []byte
		check func(t *testing.T, fb *Framebuffer)
	}{
		{
			name: "raw",
			body: update(rect(0, 0, 1, 1, 0, px(255, 0, 0))),
			check: func(t *testing.T, fb *Framebuffer) {
				if got := fb.Image().RGBAAt(0, 0); got != red {
					t.Errorf("0,0 is %+v", got)
				}
			},
		},
		{
			name: "copy-rect moves what is already there",
			body: append(update(rect(0, 0, 1, 1, 0, px(255, 0, 0))),
				update(rect(3, 3, 1, 1, 1, []byte{0, 0, 0, 0}))...),
			check: func(t *testing.T, fb *Framebuffer) {
				if got := fb.Image().RGBAAt(3, 3); got != red {
					t.Errorf("3,3 is %+v", got)
				}
			},
		},
		{
			name: "rre fills and then paints over",
			body: update(rect(0, 0, 4, 4, 2, func() []byte {
				b := []byte{0, 0, 0, 1}
				b = append(b, px(255, 0, 0)...) // background
				b = append(b, px(0, 255, 0)...) // one subrectangle
				b = append(b, 0, 1, 0, 1, 0, 2, 0, 2)
				return b
			}())),
			check: func(t *testing.T, fb *Framebuffer) {
				if got := fb.Image().RGBAAt(0, 0); got != red {
					t.Errorf("the background at 0,0 is %+v", got)
				}
				if got := fb.Image().RGBAAt(2, 2); got != green {
					t.Errorf("the subrectangle at 2,2 is %+v", got)
				}
			},
		},
		{
			name: "corre, the same with one-byte coordinates",
			body: update(rect(0, 0, 4, 4, 4, func() []byte {
				b := []byte{0, 0, 0, 1}
				b = append(b, px(255, 0, 0)...)
				b = append(b, px(0, 255, 0)...)
				b = append(b, 1, 1, 1, 1)
				return b
			}())),
			check: func(t *testing.T, fb *Framebuffer) {
				if got := fb.Image().RGBAAt(1, 1); got != green {
					t.Errorf("1,1 is %+v", got)
				}
				if got := fb.Image().RGBAAt(3, 3); got != red {
					t.Errorf("3,3 is %+v", got)
				}
			},
		},
		{
			name: "hextile with a background and a coloured subrectangle",
			body: update(rect(0, 0, 4, 4, 5, func() []byte {
				// One tile: background set, subrects present and coloured.
				b := []byte{hexBackground | hexAnySubrects | hexSubrectsColoured}
				b = append(b, px(255, 0, 0)...)
				b = append(b, 1) // one subrectangle
				b = append(b, px(0, 255, 0)...)
				b = append(b, 0x11, 0x00) // x=1,y=1, w=1,h=1
				return b
			}())),
			check: func(t *testing.T, fb *Framebuffer) {
				if got := fb.Image().RGBAAt(0, 0); got != red {
					t.Errorf("the tile background at 0,0 is %+v", got)
				}
				if got := fb.Image().RGBAAt(1, 1); got != green {
					t.Errorf("the subrectangle at 1,1 is %+v", got)
				}
			},
		},
		{
			name: "trle, one solid tile",
			body: update(rect(0, 0, 2, 2, 15, append([]byte{1}, 0, 0, 255))),
			check: func(t *testing.T, fb *Framebuffer) {
				for _, p := range [][2]int{{0, 0}, {1, 1}} {
					if got := fb.Image().RGBAAt(p[0], p[1]); got != red {
						t.Errorf("%d,%d is %+v", p[0], p[1], got)
					}
				}
			},
		},
		{
			name: "zrle, the same tile through the session's zlib stream",
			body: update(rect(0, 0, 2, 2, 16, zrlePayload(t, append([]byte{1}, 0, 0, 255)))),
			check: func(t *testing.T, fb *Framebuffer) {
				if got := fb.Image().RGBAAt(1, 0); got != red {
					t.Errorf("1,0 is %+v", got)
				}
			},
		},
		{
			name: "desktop-size resizes the framebuffer",
			body: update(rect(0, 0, 8, 8, -223, nil)),
			check: func(t *testing.T, fb *Framebuffer) {
				if w, h := fb.Size(); w != 8 || h != 8 {
					t.Errorf("the framebuffer is %dx%d", w, h)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fb, err := NewFramebuffer(4, 4, pf32)
			if err != nil {
				t.Fatal(err)
			}
			d := NewDecoder(fb)
			if _, err := d.Feed(tc.body); err != nil {
				t.Fatalf("feed: %v", err)
			}
			if d.Pending() != 0 {
				t.Errorf("%d bytes were left over", d.Pending())
			}
			tc.check(t, fb)
		})
	}
}

// zrlePayload is a TRLE tile through a zlib stream, with the four byte
// length ZRLE puts in front of it.
func zrlePayload(t *testing.T, tile []byte) []byte {
	t.Helper()
	var z bytes.Buffer
	w := zlib.NewWriter(&z)
	if _, err := w.Write(tile); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, uint32(z.Len()))
	return append(out, z.Bytes()...)
}

// A message split across events is one message: the recorder writes what
// a read returned, so a rectangle routinely spans several lines.
func TestAMessageSplitAcrossEventsIsOneMessage(t *testing.T) {
	body := update(rect(0, 0, 2, 1, 0, append(px(255, 0, 0), px(255, 0, 0)...)))
	fb, err := NewFramebuffer(2, 1, pf32)
	if err != nil {
		t.Fatal(err)
	}
	d := NewDecoder(fb)
	for i := range body {
		ups, err := d.Feed(body[i : i+1])
		if err != nil {
			t.Fatalf("at byte %d: %v", i, err)
		}
		if i < len(body)-1 && len(ups) != 0 {
			t.Fatalf("an update completed at byte %d of %d", i, len(body))
		}
	}
	if fb.Updates != 1 {
		t.Fatalf("%d updates", fb.Updates)
	}
	if got := fb.Image().RGBAAt(1, 0); got != (color.RGBA{R: 255, A: 255}) {
		t.Errorf("1,0 is %+v", got)
	}
}

// An encoding this player does not decode is said out loud. Tight is the
// case that matters: it is what the popular servers negotiate, it is not
// in RFC 6143, and a player that drew something anyway would be inventing
// a picture in an investigation.
func TestAnEncodingThisPlayerDoesNotDecodeIsNamed(t *testing.T) {
	fb, err := NewFramebuffer(4, 4, pf32)
	if err != nil {
		t.Fatal(err)
	}
	d := NewDecoder(fb)
	_, err = d.Feed(update(rect(0, 0, 4, 4, 7, []byte{0, 0, 0, 0})))
	if err == nil {
		t.Fatal("a tight rectangle was read as if it were understood")
	}
	if !strings.Contains(err.Error(), "tight") || !strings.Contains(err.Error(), "does not decode") {
		t.Errorf("the error does not name the encoding: %v", err)
	}
}

// The bounds hold: a framebuffer past the gateway's own pixel bound is
// refused, a rectangle that runs past the edge writes nothing outside it,
// and a server message type nobody defines stops the reading.
func TestTheBoundsHold(t *testing.T) {
	if _, err := NewFramebuffer(20000, 20000, pf32); err == nil {
		t.Error("a framebuffer of 400 million pixels was allocated")
	}
	fb, err := NewFramebuffer(2, 2, pf32)
	if err != nil {
		t.Fatal(err)
	}
	d := NewDecoder(fb)
	// A rectangle claiming to start outside the framebuffer.
	if _, err := d.Feed(update(rect(1, 1, 2, 2, 0, bytes.Repeat(px(255, 0, 0), 4)))); err != nil {
		t.Fatalf("feed: %v", err)
	}
	if got := fb.Image().RGBAAt(1, 1); got != (color.RGBA{R: 255, A: 255}) {
		t.Errorf("the pixel inside the framebuffer is %+v", got)
	}
	if _, err := d.Feed([]byte{99}); err == nil {
		t.Error("an undefined server message type was accepted")
	}
}

// The frames a page and a directory are made of are bounded and sampled,
// because a session of ten thousand updates is not a page anything opens.
func TestFramesAreBoundedAndSampled(t *testing.T) {
	fb, err := NewFramebuffer(2, 2, pf32)
	if err != nil {
		t.Fatal(err)
	}
	fs := &FrameSet{Max: 2}
	for i := 0; i < 5; i++ {
		if err := fs.Add(time.Duration(i)*time.Second, fb, ""); err != nil {
			t.Fatal(err)
		}
	}
	if len(fs.Frames) != 2 {
		t.Fatalf("%d frames, want the bound's 2", len(fs.Frames))
	}
	every := &FrameSet{Every: 3}
	for i := 0; i < 9; i++ {
		if err := every.Add(time.Duration(i)*time.Second, fb, ""); err != nil {
			t.Fatal(err)
		}
	}
	if len(every.Frames) != 3 {
		t.Fatalf("%d frames with -every 3 over nine updates", len(every.Frames))
	}
	dir := t.TempDir()
	names, err := fs.WritePNGs(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 {
		t.Fatalf("%d files", len(names))
	}
	for _, n := range names {
		b, err := os.ReadFile(n)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.HasPrefix(b, []byte("\x89PNG\r\n\x1a\n")) {
			t.Errorf("%s is not a PNG", n)
		}
	}
	var page bytes.Buffer
	if err := fs.WritePage(&page, "a <session>", []string{"a mark with \"quotes\""}); err != nil {
		t.Fatal(err)
	}
	text := page.String()
	for _, want := range []string{"<!doctype html>", "data:image/png;base64", "a &lt;session&gt;", `a mark with \"quotes\"`} {
		if !strings.Contains(text, want) {
			t.Errorf("the page does not carry %q", want)
		}
	}
	// The page is self-contained: no network, no script host, no fetch.
	for _, forbidden := range []string{"http://", "https://", "fetch(", "XMLHttpRequest"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("the page reaches outside itself: %q", forbidden)
		}
	}
}

// A terminal recording is still a terminal recording: the header names no
// protocol, and the kind says so.
func TestATerminalRecordingIsRecognised(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "s.cast", map[string]string{"SHELL": "/bin/sh"}, 80, 24, [2]any{0.0, []byte("hello")})
	rec, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rec.Close() }()
	if rec.Kind != KindTerminal {
		t.Fatalf("kind %q", rec.Kind)
	}
	if _, ok := rec.PixelFormat(); ok {
		t.Error("a terminal recording carries a pixel format")
	}
	if got := rec.Describe(1, time.Second); !strings.Contains(got, "terminal") {
		t.Errorf("describe: %s", got)
	}
}

// A file that is not a recording is refused where it is opened, not
// halfway through.
func TestAFileThatIsNotARecordingIsRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(path, []byte("this is not a recording\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("a text file was opened as a recording")
	}
	if _, err := Open(filepath.Join(dir, "absent")); err == nil {
		t.Fatal("a file that does not exist was opened")
	}
}

// The encoding names are what a timeline prints, so an unknown one is
// still legible rather than blank.
func TestEncodingNames(t *testing.T) {
	for enc, want := range map[int32]string{0: "raw", 1: "copy-rect", 5: "hextile", 16: "zrle", 7: "tight", -223: "desktop-size", 4242: "encoding-4242"} {
		if got := EncodingName(enc); got != want {
			t.Errorf("encoding %d is %q, want %q", enc, got, want)
		}
	}
	if got := fmt.Sprint(KindRFB); got != "rfb" {
		t.Errorf("kind prints as %q", got)
	}
}

// The timeline and the page are what an operator sees, so the pieces
// they are made of are exercised here rather than only through the
// command: a colour map, a clipboard, a bell, a resize mid-session and a
// cursor rectangle all keep the stream in step, and each one is a way a
// real desktop's stream stops being readable if it is wrong.
func TestTheStreamStaysInStepThroughEveryMessage(t *testing.T) {
	fb, err := NewFramebuffer(4, 4, [16]byte{8, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	if err != nil {
		t.Fatal(err)
	}
	d := NewDecoder(fb)
	// A colour map of two entries, then a raw rectangle naming index 1.
	cmap := []byte{1, 0, 0, 0, 0, 2}
	cmap = append(cmap, 0, 0, 0, 0, 0, 0) // index 0: black
	cmap = append(cmap, 0xFF, 0, 0, 0, 0, 0)
	if _, err := d.Feed(cmap); err != nil {
		t.Fatalf("colour map: %v", err)
	}
	if _, err := d.Feed(update(rect(0, 0, 1, 1, 0, []byte{1}))); err != nil {
		t.Fatalf("raw through the colour map: %v", err)
	}
	if got := fb.Image().RGBAAt(0, 0); got.R != 255 {
		t.Errorf("the colour map was not used: %+v", got)
	}
	// A bell and a clipboard.
	if _, err := d.Feed([]byte{2}); err != nil {
		t.Fatalf("bell: %v", err)
	}
	cut := []byte{3, 0, 0, 0, 0, 0, 0, 5}
	cut = append(cut, []byte("hello")...)
	if _, err := d.Feed(cut); err != nil {
		t.Fatalf("clipboard: %v", err)
	}
	if fb.Bells != 1 || fb.Cut != "hello" {
		t.Errorf("bells %d cut %q", fb.Bells, fb.Cut)
	}
	// A cursor rectangle is read and not drawn, and the stream carries on.
	cursor := update(rect(0, 0, 2, 2, -239, make([]byte, 2*2*1+2)))
	if _, err := d.Feed(cursor); err != nil {
		t.Fatalf("cursor: %v", err)
	}
	if _, err := d.Feed(update(rect(3, 3, 1, 1, 0, []byte{1}))); err != nil {
		t.Fatalf("after the cursor: %v", err)
	}
	if got := fb.Image().RGBAAt(3, 3); got.R != 255 {
		t.Errorf("the rectangle after a cursor is %+v", got)
	}
	if d.Pending() != 0 {
		t.Errorf("%d bytes left over", d.Pending())
	}
}

// A truncated recording -- the file the gateway wrote when a session was
// cut off at max_file_bytes -- is readable up to the cut, and says what
// it could not finish rather than failing.
func TestATruncatedStreamSaysSo(t *testing.T) {
	fb, err := NewFramebuffer(4, 4, pf32)
	if err != nil {
		t.Fatal(err)
	}
	d := NewDecoder(fb)
	body := update(rect(0, 0, 4, 4, 0, bytes.Repeat(px(1, 2, 3), 16)))
	if _, err := d.Feed(body[:20]); err != nil {
		t.Fatalf("feed: %v", err)
	}
	if fb.Updates != 0 {
		t.Errorf("%d updates from half a rectangle", fb.Updates)
	}
	if d.Pending() != 20 {
		t.Errorf("%d bytes pending, want the 20 fed", d.Pending())
	}
	// And the bound on what is held while waiting holds.
	d.MaxBuffered = 32
	if _, err := d.Feed(make([]byte, 64)); err == nil {
		t.Error("an unbounded amount was buffered waiting for a message")
	}
}

// The zrle stream is one stream for the session, so a second rectangle
// continues it rather than starting a new one -- which is the bug every
// naive ZRLE decoder has.
func TestTheZRLEStreamIsOneStreamForTheSession(t *testing.T) {
	fb, err := NewFramebuffer(2, 2, pf32)
	if err != nil {
		t.Fatal(err)
	}
	d := NewDecoder(fb)
	var z bytes.Buffer
	w := zlib.NewWriter(&z)
	// Two tiles, one per rectangle, through one stream.
	if _, err := w.Write(append([]byte{1}, 0, 0, 255)); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	first := z.Len()
	if _, err := w.Write(append([]byte{1}, 255, 0, 0)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	all := z.Bytes()
	head := make([]byte, 4)
	binary.BigEndian.PutUint32(head, uint32(first))
	if _, err := d.Feed(update(rect(0, 0, 2, 2, 16, append(head, all[:first]...)))); err != nil {
		t.Fatalf("the first zrle rectangle: %v", err)
	}
	if got := fb.Image().RGBAAt(0, 0); got != (color.RGBA{R: 255, A: 255}) {
		t.Fatalf("after the first rectangle 0,0 is %+v", got)
	}
	head2 := make([]byte, 4)
	binary.BigEndian.PutUint32(head2, uint32(len(all)-first))
	if _, err := d.Feed(update(rect(0, 0, 2, 2, 16, append(head2, all[first:]...)))); err != nil {
		t.Fatalf("the second zrle rectangle: %v", err)
	}
	if got := fb.Image().RGBAAt(1, 1); got != (color.RGBA{B: 255, A: 255}) {
		t.Errorf("after the second rectangle 1,1 is %+v", got)
	}
}

// The palette and run-length tiles TRLE defines, which is where most of
// a real session's bytes go.
func TestThePaletteAndRunLengthTiles(t *testing.T) {
	for _, tc := range []struct {
		name string
		tile []byte
		want map[[2]int]color.RGBA
	}{
		{
			name: "a two-colour packed palette",
			tile: func() []byte {
				b := []byte{2}                           // two palette entries
				b = append(b, 0, 0, 255)                 // red
				b = append(b, 255, 0, 0)                 // blue
				return append(b, 0b01000000, 0b10000000) // row 0: 0,1  row 1: 1,0
			}(),
			want: map[[2]int]color.RGBA{
				{0, 0}: {R: 255, A: 255}, {1, 0}: {B: 255, A: 255},
				{0, 1}: {B: 255, A: 255}, {1, 1}: {R: 255, A: 255},
			},
		},
		{
			name: "a plain run length tile",
			tile: append([]byte{128}, 0, 0, 255, 3), // one colour, run of 1+3
			want: map[[2]int]color.RGBA{{0, 0}: {R: 255, A: 255}, {1, 1}: {R: 255, A: 255}},
		},
		{
			name: "a palette run length tile",
			tile: func() []byte {
				b := []byte{130}         // 128 + two palette entries
				b = append(b, 0, 0, 255) // red
				b = append(b, 255, 0, 0) // blue
				b = append(b, 0x80, 1)   // index 0, run of 1+1
				b = append(b, 0x81, 1)   // index 1, run of 1+1
				return b
			}(),
			want: map[[2]int]color.RGBA{{0, 0}: {R: 255, A: 255}, {0, 1}: {B: 255, A: 255}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fb, err := NewFramebuffer(2, 2, pf32)
			if err != nil {
				t.Fatal(err)
			}
			d := NewDecoder(fb)
			if _, err := d.Feed(update(rect(0, 0, 2, 2, 15, tc.tile))); err != nil {
				t.Fatalf("feed: %v", err)
			}
			for at, want := range tc.want {
				if got := fb.Image().RGBAAt(at[0], at[1]); got != want {
					t.Errorf("%d,%d is %+v, want %+v", at[0], at[1], got, want)
				}
			}
		})
	}
}

// A recording encrypted at rest is the same recording behind a key. What
// decides is the magic at the start of the file rather than its name, so a
// file renamed while it was archived still reads as what it is; and a
// caller with no key is told that, rather than being handed a parse error
// about a file it has correctly identified.
func TestAnEncryptedRecordingOpensWithItsKey(t *testing.T) {
	dir := t.TempDir()
	plain := write(t, dir, "s.cast", map[string]string{"SHELL": "/bin/sh"}, 80, 24,
		[2]any{0.0, []byte("hello")})
	body, err := os.ReadFile(plain)
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately not named .enc: the decision is the content.
	sealed := filepath.Join(dir, "archived-copy")
	f, err := os.Create(sealed) //nolint:gosec // a temporary directory this test made
	if err != nil {
		t.Fatal(err)
	}
	w, err := recenc.NewWriter(f, []byte("a content key"), recenc.MinChunk)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := Open(sealed); !errors.Is(err, ErrEncrypted) {
		t.Errorf("no key: %v, want ErrEncrypted", err)
	}
	if _, err := OpenKeyed(sealed, []byte("not the key")); errors.Is(err, ErrEncrypted) || err == nil {
		t.Errorf("the wrong key: %v, want a failure that is not ErrEncrypted", err)
	}
	rec, err := OpenKeyed(sealed, []byte("a content key"))
	if err != nil {
		t.Fatalf("with the key: %v", err)
	}
	defer func() { _ = rec.Close() }()
	if rec.Kind != KindTerminal || rec.Header.Width != 80 {
		t.Errorf("kind %q, %dx%d", rec.Kind, rec.Header.Width, rec.Header.Height)
	}
	ev, err := rec.Next()
	if err != nil {
		t.Fatal(err)
	}
	if string(ev.Data) != "hello" {
		t.Errorf("the first event is %q", ev.Data)
	}

	// A key passed for a recording that is not encrypted is simply not
	// used, so one command line reads a directory holding both kinds.
	if _, err := OpenKeyed(plain, []byte("a content key")); err != nil {
		t.Errorf("a plain recording with a key given: %v", err)
	}
}

// The pixel reader, at every width a server may use.
//
// A recording is replayed long after the session, and the pixel format is
// whatever that viewer and that desktop agreed on at the time -- 8, 16 or 32
// bits, either byte order. A reader that only handled the common one would
// render an old recording as noise, and noise is indistinguishable from a
// session that really did show noise.
func TestEveryPixelWidthAndBothByteOrdersAreRead(t *testing.T) {
	for _, c := range []struct {
		name string
		pf   [16]byte
		px   []byte
		want color.RGBA
	}{
		{
			// 32 bits little endian, eight bits each: the usual.
			name: "32 bits little endian",
			pf:   [16]byte{32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0},
			px:   []byte{0x30, 0x20, 0x10, 0x00},
			want: color.RGBA{R: 0x10, G: 0x20, B: 0x30, A: 255},
		},
		{
			name: "32 bits big endian",
			pf:   [16]byte{32, 24, 1, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0},
			px:   []byte{0x00, 0x10, 0x20, 0x30},
			want: color.RGBA{R: 0x10, G: 0x20, B: 0x30, A: 255},
		},
		{
			// 16 bits, 5-6-5: the format a slow link asks for.
			name: "16 bits little endian 565",
			pf:   [16]byte{16, 16, 0, 1, 0, 31, 0, 63, 0, 31, 11, 5, 0, 0, 0, 0},
			px:   []byte{0x00, 0xf8}, // red at full in 565
			want: color.RGBA{R: 255, G: 0, B: 0, A: 255},
		},
		{
			name: "16 bits big endian 565",
			pf:   [16]byte{16, 16, 1, 1, 0, 31, 0, 63, 0, 31, 11, 5, 0, 0, 0, 0},
			px:   []byte{0xf8, 0x00},
			want: color.RGBA{R: 255, G: 0, B: 0, A: 255},
		},
		{
			// 8 bits, 3-3-2.
			name: "8 bits",
			pf:   [16]byte{8, 8, 0, 1, 0, 7, 0, 7, 0, 3, 5, 2, 0, 0, 0, 0},
			px:   []byte{0xe0}, // red at full in 332
			want: color.RGBA{R: 255, G: 0, B: 0, A: 255},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			fb, err := NewFramebuffer(1, 1, c.pf)
			if err != nil {
				t.Fatal(err)
			}
			if got := fb.colourAt(c.px); got != c.want {
				t.Errorf("colourAt = %+v, want %+v", got, c.want)
			}
		})
	}
	// A width this reader has no name for yields no pixel rather than
	// reading past the bytes it was given.
	odd, err := NewFramebuffer(1, 1, [16]byte{24, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0})
	if err != nil {
		t.Fatal(err)
	}
	if n := odd.pf.bytesPerPixel(); n != 0 {
		t.Errorf("bytesPerPixel for 24 bits = %d, want 0", n)
	}
}

// A framebuffer that cannot exist is refused rather than allocated.
//
// The numbers come out of the recording, which came off the wire, so they are
// a desktop's claim about itself. MaxPixels is why a recording naming 65535 by
// 65535 does not ask the machine replaying it for sixteen gigabytes.
func TestAFramebufferSizeIsNotTrusted(t *testing.T) {
	for _, c := range []struct{ w, h int }{{0, 24}, {80, 0}, {-1, 10}, {10, -1}} {
		if _, err := NewFramebuffer(c.w, c.h, pf32); err == nil {
			t.Errorf("a framebuffer of %dx%d was allocated", c.w, c.h)
		}
	}
	if _, err := NewFramebuffer(65535, 65535, pf32); err == nil {
		t.Error("a framebuffer past MaxPixels was allocated")
	} else if !strings.Contains(err.Error(), "bound") {
		t.Errorf("err = %v, want it to name the bound", err)
	}
}

// The palette index reader, at each width a tile may pack to.
//
// A palette of n colours packs its indices at 1, 2, 4 or 8 bits, and the
// packing is per row with each row starting on a byte. Reading one bit width
// as another is how a tile comes out as diagonal stripes, and a row that is
// shorter than the tile claims must read as index zero rather than past its
// end.
func TestThePackedPaletteIndexIsReadAtEveryWidth(t *testing.T) {
	for _, c := range []struct {
		n    int
		bits int
	}{{1, 1}, {2, 1}, {3, 2}, {4, 2}, {5, 4}, {16, 4}, {17, 8}, {128, 8}} {
		if got := paletteBits(c.n); got != c.bits {
			t.Errorf("paletteBits(%d) = %d, want %d", c.n, got, c.bits)
		}
	}
	// One bit: the high bit of the byte is index 0 of the row.
	row1 := []byte{0b10110000}
	for xx, want := range []int{1, 0, 1, 1, 0, 0, 0, 0} {
		if got := packedIndex(row1, xx, 1); got != want {
			t.Errorf("packedIndex(1 bit, %d) = %d, want %d", xx, got, want)
		}
	}
	// Two bits, four to the byte, most significant first.
	row2 := []byte{0b11100100}
	for xx, want := range []int{3, 2, 1, 0} {
		if got := packedIndex(row2, xx, 2); got != want {
			t.Errorf("packedIndex(2 bits, %d) = %d, want %d", xx, got, want)
		}
	}
	// Four bits, two to the byte, high nibble first.
	row4 := []byte{0xA5}
	for xx, want := range []int{0xA, 0x5} {
		if got := packedIndex(row4, xx, 4); got != want {
			t.Errorf("packedIndex(4 bits, %d) = %d, want %d", xx, got, want)
		}
	}
	// Eight bits, one to the byte.
	row8 := []byte{7, 200}
	for xx, want := range []int{7, 200} {
		if got := packedIndex(row8, xx, 8); got != want {
			t.Errorf("packedIndex(8 bits, %d) = %d, want %d", xx, got, want)
		}
	}
	// Past the row's end at every width: index zero, not a read past it.
	for _, bits := range []int{1, 2, 4, 8} {
		if got := packedIndex(nil, 0, bits); got != 0 {
			t.Errorf("packedIndex(%d bits) past the end = %d, want 0", bits, got)
		}
		if got := packedIndex([]byte{0xff}, 64, bits); got != 0 {
			t.Errorf("packedIndex(%d bits) far past the end = %d, want 0", bits, got)
		}
	}
}
