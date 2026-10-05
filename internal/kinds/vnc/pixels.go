package vnc

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/rfb"
)

// The pixel stream, and the policy over it.
//
// A gateway that forwarded the desktop's bytes unread could hold a
// policy about who connects and nothing about what arrives. What
// arrives, in an image protocol, is a series of numbers that are the
// viewer's allocations: a framebuffer of so many pixels, a rectangle of
// so many more, a compressed payload that claims to expand to so much.
// Those numbers are twelve bytes each to send and megabytes each to
// honour, which is what makes an image protocol the cheapest place to
// aim a decompression bomb.
//
// So this reads both directions. The desktop's, to bound what it
// declares; the client's, because framing is what lets a gateway drop
// one message and forward the next -- which is how view_only works, how
// the clipboard policy works, and why a file transfer cannot pass.

// pixelPolicy is the listener's policy over the stream, built once.
type pixelPolicy struct {
	// framed says whether the desktop's messages are read. Without it
	// only the announced framebuffer is bounded.
	framed bool
	limits rfb.UpdateLimits
	// clipToClient and clipToTarget are the directions a clipboard
	// transfer may travel.
	clipToClient, clipToTarget bool
	// allowResize lets a client ask the desktop to change size.
	allowResize bool
	// viewOnly drops what drives the desktop.
	viewOnly bool
}

func newPixelPolicy(c *config.VNCListener) pixelPolicy {
	p := pixelPolicy{
		framed:      c.PixelStream != config.VNCPixelsOpaque,
		viewOnly:    c.ViewOnly,
		allowResize: c.AllowResize == nil || *c.AllowResize,
	}
	switch c.Clipboard {
	case config.VNCClipboardToClient:
		p.clipToClient = true
	case config.VNCClipboardToTarget:
		p.clipToTarget = true
	case config.VNCClipboardNone:
	default:
		p.clipToClient, p.clipToTarget = true, true
	}
	if b := c.Bounds; b != nil {
		p.limits = rfb.UpdateLimits{
			MaxPixels:     b.MaxFramebufferPixels,
			MaxRectangles: b.MaxRectanglesPerUpdate,
			MaxRectBytes:  b.MaxEncodedRectangle,
			MaxRatio:      b.MaxDecodeRatio,
			MaxCutText:    b.MaxCutText,
		}
	}
	return p
}

// pixels is a session's state shared by the two pump goroutines: the
// pixel format the desktop's leg is being read in, and whether the
// client has asked for a picture yet.
type pixels struct {
	// mu guards pf and pfSet, which carry a client's SetPixelFormat across to
	// the goroutine reading the desktop.
	//
	// The ordering is what matters, and it is the reason this is a guarded value
	// rather than a channel: the format is stored, then the message is
	// forwarded, and the reader takes the stored value at the point it derives a
	// length from it. A channel drained between messages took the change one
	// message too late -- the reader was already blocked on the socket when it
	// arrived, because a VNC server says nothing after ServerInit until a
	// picture is asked for -- so the first rectangle of the new format was sized
	// with the bytes per pixel of the old one and the over-read swallowed
	// whatever the desktop sent next.
	mu    sync.Mutex
	pf    [16]byte
	pfSet bool
	// changed marks a format change already made. A second one is refused
	// rather than dropped: one reader cannot be in two formats, and a silent
	// drop leaves this gateway framing in one while the desktop answers in
	// another.
	changed atomic.Bool
	// requested marks the first framebuffer update request. After it, a
	// pixel format change has no synchronisation point in RFB -- there
	// is no message that says "the next rectangle is in the new
	// format" -- so a gateway that kept framing would be guessing where
	// the rectangles are.
	requested atomic.Bool
}

func newPixels() *pixels { return &pixels{} }

// store records a format change for the desktop's reader to take.
func (p *pixels) store(pf [16]byte) {
	p.mu.Lock()
	p.pf, p.pfSet = pf, true
	p.mu.Unlock()
}

// take is the reader's side: the format if one is waiting, and false otherwise.
func (p *pixels) take() ([16]byte, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.pfSet {
		return [16]byte{}, false
	}
	p.pfSet = false
	return p.pf, true
}

// deadline puts the idle timeout on a leg before each message.
func (se *session) deadline(c net.Conn) {
	if se.t.v.IdleTimeout > 0 {
		_ = c.SetReadDeadline(time.Now().Add(se.t.v.IdleTimeout.D()))
	}
}

// shown is where the desktop's picture goes: the recording and the
// client, in that order, so what was recorded is what was shown.
//
// The reader writes through it as it reads rather than assembling each
// message first: a full screen update is tens of megabytes, and a
// gateway that held one per session would be a proxy an operator could
// run out of memory by connecting to it.
type shown struct{ se *session }

func (w shown) Write(b []byte) (int, error) {
	w.se.rec.Out(b)
	return w.se.client.Write(b)
}

// framedToClient reads the desktop's messages, bounds them, records
// them and forwards them.
func (se *session) framedToClient() string {
	r, err := rfb.NewServerReader(se.up, shown{se}, se.si, se.t.px.limits)
	if err != nil {
		// A pixel format this gateway cannot measure lengths in. The
		// session ends rather than the bounds quietly not applying.
		se.pixelDeny("pixel_format", err)
		return "pixel_format"
	}
	// The reader takes a format change where it uses one, so nothing here has
	// to wait for the client and the desktop is never held up.
	r.SetPendingFormat(se.px.take)
	for {
		se.deadline(se.up)
		m, err := r.Next()
		if err != nil {
			return se.pixelEnd(err, "target")
		}
		// A clipboard transfer is the one message the reader holds
		// rather than passing on, because it is the one this policy may
		// drop.
		if m.Held == nil {
			continue
		}
		if !se.t.px.clipToClient {
			se.dropped("clipboard_to_client")
			continue
		}
		if _, werr := (shown{se}).Write(m.Held); werr != nil {
			return "write"
		}
	}
}

// framedToTarget reads the client's messages and applies the policy:
// what drives the desktop, what reaches its clipboard, what it may be
// asked to draw with, and whether it may be resized.
func (se *session) framedToTarget() string {
	r := rfb.NewClientReader(se.client, se.t.px.limits)
	for {
		se.deadline(se.client)
		m, err := r.Next()
		if err != nil {
			return se.pixelEnd(err, "client")
		}
		out, drop, end := se.decideClient(m)
		if end != "" {
			return end
		}
		se.recordInput(m, drop)
		if drop != "" {
			se.dropped(drop)
			continue
		}
		if _, err := se.up.Write(out); err != nil {
			return "write"
		}
	}
}

// decideClient applies the policy to one client message. It returns the
// bytes to forward, or the reason the message is dropped, or the reason
// the session ends.
func (se *session) decideClient(m rfb.ClientMessage) (out []byte, drop, end string) {
	p := se.t.px
	switch m.Type {
	case rfb.CliKeyEvent, rfb.CliPointerEvent:
		if p.viewOnly {
			// This session is watched, not driven.
			return nil, "view_only", ""
		}
	case rfb.CliCutText:
		// Pasting into the desktop is driving it, so view_only covers
		// the clipboard as well as the pointer.
		if p.viewOnly || !p.clipToTarget {
			return nil, "clipboard_to_target", ""
		}
	case rfb.CliSetEncodings:
		if !p.framed {
			break
		}
		kept, removed := rfb.FilterEncodings(m.Encodings)
		if len(removed) == 0 {
			break
		}
		// An encoding this gateway cannot frame is taken out of the
		// list rather than refused with the session: the client asked
		// for every encoding it has, and the desktop will use one of
		// the ones that are left.
		for _, e := range removed {
			se.dropped("encoding_" + rfb.EncodingName(e))
		}
		return rfb.EncodeSetEncodings(kept), "", ""
	case rfb.CliSetPixelFormat:
		if !p.framed {
			break
		}
		if se.px.requested.Load() {
			se.pixelDeny("pixel_format_changed", errors.New("a pixel format change after the first update request has no point in the stream where it takes effect"))
			return nil, "", "pixel_format_changed"
		}
		if se.px.changed.Swap(true) {
			// A second change before the first update. One reader cannot be in
			// two formats, and dropping the second quietly -- which is what a
			// one-slot handover did -- leaves this gateway framing in one format
			// while the desktop answers in another.
			se.pixelDeny("pixel_format_changed", errors.New("a second pixel format change has no point in the stream where it takes effect"))
			return nil, "", "pixel_format_changed"
		}
		// Stored before the message is forwarded, so the desktop cannot answer
		// in the new format before the reader can see it. The reader takes it
		// when it next derives a length from the format, which is necessarily
		// after this.
		se.px.store(m.PixelFormat)
	case rfb.CliUpdateRequest, rfb.CliEnableContinuous:
		se.px.requested.Store(true)
	case rfb.CliSetDesktopSize:
		if !p.allowResize {
			return nil, "resize_refused", ""
		}
		// A client asking a desktop to allocate a framebuffer is the
		// same request in the other direction, so it takes the same
		// bound.
		if err := p.limits.CheckFramebuffer(m.Width, m.Height); err != nil {
			se.pixelDeny("resize_too_large", err)
			return nil, "", "resize_too_large"
		}
	}
	return m.Bytes, "", ""
}

// dropped counts a message or an encoding the policy did not pass on.
func (se *session) dropped(reason string) {
	se.t.engine.Counters().VNCRefused.Add(1)
	se.t.engine.Counters().Refuse("vnc", reason)
}

// pixelEnd names why a framed copy stopped. A bound that fired is a
// deny with a reason of its own; a peer hanging up or an idle deadline
// is neither.
func (se *session) pixelEnd(err error, leg string) string {
	reason := pixelReason(err)
	if reason == "" {
		return endReason(err)
	}
	se.pixelDeny(reason, fmt.Errorf("%s: %w", leg, err))
	return reason
}

// pixelReason maps a bound to the word an operator queries by. An empty
// reason is not a refusal: the stream simply ended.
func pixelReason(err error) string {
	switch {
	case errors.Is(err, rfb.ErrFramebufferTooLarge):
		return "framebuffer_too_large"
	case errors.Is(err, rfb.ErrRectanglePixels):
		return "rectangle_too_large"
	case errors.Is(err, rfb.ErrRectangleOutside):
		return "rectangle_outside_framebuffer"
	case errors.Is(err, rfb.ErrTooManyRectangles):
		return "too_many_rectangles"
	case errors.Is(err, rfb.ErrRectangleTooLarge):
		return "encoded_rectangle_too_large"
	case errors.Is(err, rfb.ErrDecodeRatio):
		return "decode_ratio"
	case errors.Is(err, rfb.ErrCutTextTooLarge):
		return "cut_text_too_large"
	case errors.Is(err, rfb.ErrUnframable):
		return "unframable"
	}
	return ""
}

// pixelDeny records a refusal on the pixel path, with the numbers that
// caused it: a bound that fires without saying which one and by how
// much is a bound an operator cannot tune.
func (se *session) pixelDeny(reason string, err error) {
	se.t.deny(se.ip, "vnc_"+reason, err.Error())
}
