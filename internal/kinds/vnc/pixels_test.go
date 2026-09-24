package vnc_test

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/rfb"
)

// gone reports whether the session ended, which is how a bound that
// fired shows at the client: RFB has no error message after the
// handshake, so there is nothing to say and the session stops.
func gone(t *testing.T, cl *client) bool {
	t.Helper()
	_ = cl.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := io.ReadAll(cl.c)
	if err != nil && !strings.Contains(err.Error(), "reset") {
		return false
	}
	_, err = cl.c.Read(make([]byte, 1))
	return err != nil
}

// A desktop that announces a framebuffer past the bound is refused
// before the client is told about it: the announced size is the first
// number a viewer allocates from, and the point of the bound is that
// the viewer never sees it.
func TestAGiantFramebufferIsRefusedBeforeTheClientSeesIt(t *testing.T) {
	tg := startTarget(t, &target{width: 30000, height: 30000})
	s, addr := gateway(t, tg, "        security_types: [none]\n        bounds: {max_framebuffer_pixels: 2073600}")
	cl := dial(t, addr)
	cl.version(rfb.V38)
	cl.offered()
	cl.write([]byte{rfb.SecNone})
	if ok, _ := cl.result(); !ok {
		t.Fatal("the security result was a failure")
	}
	cl.write(rfb.ClientInit{Shared: true}.Encode())
	// The ServerInit never arrives: the gateway read it, refused it and
	// closed both legs.
	_ = cl.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := cl.c.Read(make([]byte, 1)); err == nil {
		t.Fatalf("a 30000x30000 desktop was forwarded (%d bytes)", n)
	}
	waitFor(t, "the refusal to be counted by reason", func() bool {
		return s.Stats().Refusals["vnc"]["framebuffer_too_large"] == 1
	})
}

// The same listener passes an ordinary desktop, which is the half that
// proves the bound is a bound and not a closed door.
func TestAnOrdinaryFramebufferIsNotRefused(t *testing.T) {
	tg := startTarget(t, &target{width: 1920, height: 1080})
	_, addr := gateway(t, tg, "        security_types: [none]\n        bounds: {max_framebuffer_pixels: 2073600}")
	cl := dial(t, addr)
	si := cl.open(true)
	if si.Width != 1920 || si.Height != 1080 {
		t.Fatalf("desktop %dx%d", si.Width, si.Height)
	}
	if got := cl.read(len(tg.shown)); !bytes.Equal(got, tg.shown) {
		t.Errorf("the picture did not arrive: %q", got)
	}
}

// A rectangle that declares far more picture than it carries is a
// decompression bomb, and it is refused without anything being
// decompressed: the geometry against the bytes is the whole check.
func TestADecompressionBombIsRefused(t *testing.T) {
	// 512x512 at 32 bits per pixel is a megabyte, declared in sixteen
	// bytes of ZRLE.
	bomb := []byte{0, 0, 0, 1}
	bomb = binary.BigEndian.AppendUint16(bomb, 0)
	bomb = binary.BigEndian.AppendUint16(bomb, 0)
	bomb = binary.BigEndian.AppendUint16(bomb, 512)
	bomb = binary.BigEndian.AppendUint16(bomb, 512)
	bomb = binary.BigEndian.AppendUint32(bomb, uint32(rfb.EncZRLE))
	bomb = binary.BigEndian.AppendUint32(bomb, 16)
	bomb = append(bomb, make([]byte, 16)...)

	tg := startTarget(t, &target{shown: bomb})
	s, addr := gateway(t, tg, "        security_types: [none]\n        bounds: {max_decode_ratio: 100}")
	cl := dial(t, addr)
	cl.open(true)
	if !gone(t, cl) {
		t.Error("the session outlived a rectangle claiming a megabyte in sixteen bytes")
	}
	waitFor(t, "the ratio refusal to be counted", func() bool {
		return s.Stats().Refusals["vnc"]["decode_ratio"] == 1
	})
}

// A rectangle reaching outside the framebuffer is a write past the end
// of the buffer the viewer made for it.
func TestARectangleOutsideTheDesktopIsRefused(t *testing.T) {
	out := []byte{0, 0, 0, 1}
	out = binary.BigEndian.AppendUint16(out, 1000)
	out = binary.BigEndian.AppendUint16(out, 700)
	out = binary.BigEndian.AppendUint16(out, 200)
	out = binary.BigEndian.AppendUint16(out, 200)
	out = binary.BigEndian.AppendUint32(out, 0) // raw
	out = append(out, make([]byte, 200*200*4)...)

	tg := startTarget(t, &target{shown: out})
	s, addr := gateway(t, tg, "        security_types: [none]")
	cl := dial(t, addr)
	cl.open(true)
	if !gone(t, cl) {
		t.Error("the session outlived a rectangle outside the 1024x768 desktop")
	}
	waitFor(t, "the geometry refusal to be counted", func() bool {
		return s.Stats().Refusals["vnc"]["rectangle_outside_framebuffer"] == 1
	})
}

// A client asks for every encoding it has. The gateway forwards only the
// ones it can frame, so the desktop never uses one that would leave the
// gateway unable to find the next rectangle -- and the client still gets
// a session, because a list is filtered rather than refused.
func TestTheEncodingListIsFilteredToWhatTheGatewayCanFrame(t *testing.T) {
	tg := startTarget(t, &target{})
	s, addr := gateway(t, tg, "        security_types: [none]")
	cl := dial(t, addr)
	cl.open(true)
	cl.read(len(tg.shown))

	asked := []int32{rfb.EncTight, rfb.EncZRLE, rfb.EncTRLE, rfb.EncHextile, rfb.EncCopyRect, rfb.EncRaw}
	cl.write(rfb.EncodeSetEncodings(asked))
	want := rfb.EncodeSetEncodings([]int32{rfb.EncZRLE, rfb.EncHextile, rfb.EncCopyRect, rfb.EncRaw})
	if !tg.waitSeen(want) {
		t.Fatalf("the target was given %x, want the filtered list %x", tg.seen(), want)
	}
	if bytes.Contains(tg.seen(), rfb.EncodeSetEncodings(asked)) {
		t.Error("the unfiltered list reached the desktop")
	}
	waitFor(t, "the removed encodings to be counted", func() bool {
		r := s.Stats().Refusals["vnc"]
		return r["encoding_tight"] == 1 && r["encoding_trle"] == 1
	})
}

// A file transfer cannot cross this gateway, and not because a rule says
// so: the vendors put it in a message type whose length nothing else
// knows, and a gateway that forwarded one could not find the message
// after it. So the session ends, framed or opaque.
func TestAFileTransferMessageEndsTheSession(t *testing.T) {
	for _, mode := range []string{"framed", "opaque"} {
		t.Run(mode, func(t *testing.T) {
			tg := startTarget(t, &target{})
			s, addr := gateway(t, tg, "        security_types: [none]\n        pixel_stream: "+mode)
			cl := dial(t, addr)
			cl.open(true)
			// TightVNC's file transfer, client message 252.
			cl.write([]byte{252, 6, 0, 0, 0, 0, 0, 0})
			if !gone(t, cl) {
				t.Error("the session outlived a file transfer message")
			}
			waitFor(t, "the refusal to be counted", func() bool {
				return s.Stats().Refusals["vnc"]["unframable"] >= 1
			})
			if bytes.Contains(tg.seen(), []byte{252, 6}) {
				t.Error("a file transfer message reached the desktop")
			}
		})
	}
}

// The clipboard has a direction, and each direction is a decision of its
// own: a clipboard into the desktop is an upload with no name and no
// size in the log.
func TestTheClipboardPolicyHasADirection(t *testing.T) {
	cut := append([]byte{6, 0, 0, 0, 0, 0, 0, 3}, []byte("abc")...)
	for _, c := range []struct {
		policy  string
		reaches bool
	}{{"both", true}, {"to_client", false}, {"to_target", true}, {"none", false}} {
		t.Run(c.policy, func(t *testing.T) {
			tg := startTarget(t, &target{})
			s, addr := gateway(t, tg, "        security_types: [none]\n        clipboard: "+c.policy)
			cl := dial(t, addr)
			cl.open(true)
			cl.read(len(tg.shown))
			cl.write(cut)
			// A key event after it, as the thing that must arrive
			// whatever happened to the clipboard.
			key := []byte{4, 1, 0, 0, 0, 0, 0, 'A'}
			cl.write(key)
			if !tg.waitSeen(key) {
				t.Fatalf("the key event did not arrive: %x", tg.seen())
			}
			if got := bytes.Contains(tg.seen(), cut); got != c.reaches {
				t.Errorf("clipboard reached the desktop: %v, want %v", got, c.reaches)
			}
			if !c.reaches {
				waitFor(t, "the drop to be counted", func() bool {
					return s.Stats().Refusals["vnc"]["clipboard_to_target"] == 1
				})
			}
		})
	}
}

// The desktop's own clipboard is the other direction, and it is dropped
// without ending the session: a cut text is a whole message, so the one
// after it still arrives.
func TestTheDesktopsClipboardIsDroppedOnItsOwn(t *testing.T) {
	shown := append([]byte{3, 0, 0, 0, 0, 0, 0, 5}, []byte("hello")...)
	shown = append(shown, 2) // a bell, which must still arrive
	tg := startTarget(t, &target{shown: shown})
	s, addr := gateway(t, tg, "        security_types: [none]\n        clipboard: to_target")
	cl := dial(t, addr)
	cl.open(true)
	if got := cl.read(1); got[0] != 2 {
		t.Fatalf("the message after the dropped clipboard was %d, want a bell", got[0])
	}
	waitFor(t, "the drop to be counted", func() bool {
		return s.Stats().Refusals["vnc"]["clipboard_to_client"] == 1
	})
}

// A resize is a client asking the desktop to allocate a framebuffer,
// which is the same request as the desktop announcing one, so it takes
// the same bound -- and the whole message can be refused by policy.
func TestAResizeIsBoundedAndCanBeRefused(t *testing.T) {
	resize := func(w, h uint16) []byte {
		out := []byte{251, 0}
		out = binary.BigEndian.AppendUint16(out, w)
		out = binary.BigEndian.AppendUint16(out, h)
		return append(out, 0, 0)
	}
	t.Run("refused by policy", func(t *testing.T) {
		tg := startTarget(t, &target{})
		s, addr := gateway(t, tg, "        security_types: [none]\n        allow_resize: false")
		cl := dial(t, addr)
		cl.open(true)
		cl.read(len(tg.shown))
		cl.write(resize(1280, 720))
		key := []byte{4, 1, 0, 0, 0, 0, 0, 'A'}
		cl.write(key)
		if !tg.waitSeen(key) {
			t.Fatalf("the key event did not arrive: %x", tg.seen())
		}
		if bytes.Contains(tg.seen(), resize(1280, 720)) {
			t.Error("a resize reached a desktop that does not allow one")
		}
		waitFor(t, "the refusal to be counted", func() bool {
			return s.Stats().Refusals["vnc"]["resize_refused"] == 1
		})
	})
	t.Run("bounded when allowed", func(t *testing.T) {
		tg := startTarget(t, &target{})
		s, addr := gateway(t, tg, "        security_types: [none]\n        bounds: {max_framebuffer_pixels: 2073600}")
		cl := dial(t, addr)
		cl.open(true)
		cl.read(len(tg.shown))
		// Inside the bound: forwarded.
		cl.write(resize(1280, 720))
		if !tg.waitSeen(resize(1280, 720)) {
			t.Fatalf("an ordinary resize did not arrive: %x", tg.seen())
		}
		// Past it: the session ends rather than the desktop being asked
		// for a gigabyte of framebuffer.
		cl.write(resize(30000, 30000))
		if !gone(t, cl) {
			t.Error("the session outlived a resize to 30000x30000")
		}
		waitFor(t, "the refusal to be counted", func() bool {
			return s.Stats().Refusals["vnc"]["resize_too_large"] == 1
		})
	})
}

// An opaque listener is the escape hatch for a desktop that must use the
// tight encoding: the picture is forwarded unread, which is what makes
// tight possible and what makes the bounds impossible.
func TestAnOpaqueListenerForwardsWhatItCannotFrame(t *testing.T) {
	// A tight rectangle, which a framed listener would refuse.
	tight := []byte{0, 0, 0, 1}
	tight = binary.BigEndian.AppendUint16(tight, 0)
	tight = binary.BigEndian.AppendUint16(tight, 0)
	tight = binary.BigEndian.AppendUint16(tight, 16)
	tight = binary.BigEndian.AppendUint16(tight, 16)
	tight = binary.BigEndian.AppendUint32(tight, uint32(rfb.EncTight))
	tight = append(tight, 0x80, 4, 1, 2, 3, 4)

	tg := startTarget(t, &target{shown: tight})
	_, addr := gateway(t, tg, "        security_types: [none]\n        pixel_stream: opaque")
	cl := dial(t, addr)
	cl.open(true)
	if got := cl.read(len(tight)); !bytes.Equal(got, tight) {
		t.Errorf("an opaque listener did not forward the tight rectangle: %x", got)
	}
	// The same rectangle on a framed listener ends the session.
	tg2 := startTarget(t, &target{shown: tight})
	s, addr2 := gateway(t, tg2, "        security_types: [none]")
	cl2 := dial(t, addr2)
	cl2.open(true)
	if !gone(t, cl2) {
		t.Error("a framed listener forwarded a tight rectangle")
	}
	waitFor(t, "the unframable refusal to be counted", func() bool {
		return s.Stats().Refusals["vnc"]["unframable"] >= 1
	})
}

// A pixel format the gateway cannot measure lengths in ends the session
// rather than the bounds quietly becoming wrong: every length in the
// picture is a multiple of the pixel width.
func TestAPixelFormatChangeAfterTheFirstUpdateEndsTheSession(t *testing.T) {
	var pf [16]byte
	pf[0] = 16
	setFormat := append([]byte{0, 0, 0, 0}, pf[:]...)
	tg := startTarget(t, &target{})
	s, addr := gateway(t, tg, "        security_types: [none]")
	cl := dial(t, addr)
	cl.open(true)
	cl.read(len(tg.shown))
	// Before any update is asked for, a format change is allowed.
	cl.write(setFormat)
	if !tg.waitSeen(setFormat) {
		t.Fatalf("an early pixel format did not reach the desktop: %x", tg.seen())
	}
	// After the first request there is no point in the stream where a
	// new format takes effect, so the session ends instead.
	req := []byte{3, 0, 0, 0, 0, 0, 0, 4, 0, 3}
	cl.write(req)
	if !tg.waitSeen(req) {
		t.Fatalf("the update request did not arrive: %x", tg.seen())
	}
	cl.write(setFormat)
	if !gone(t, cl) {
		t.Error("the session outlived a pixel format change mid-stream")
	}
	waitFor(t, "the refusal to be counted", func() bool {
		return s.Stats().Refusals["vnc"]["pixel_format_changed"] == 1
	})
}
