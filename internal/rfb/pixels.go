package rfb

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// The pixel stream, which is the part of RFB a gateway has until now
// forwarded without reading.
//
// Reading it is what makes a bound possible. An image protocol's
// numbers are the client's allocations: a framebuffer is width times
// height times bytes per pixel, and a rectangle's declared geometry is
// what a viewer sizes its decode buffer from. A desktop that says
// 4096x4096 in twelve bytes of zlib is not sending a picture, it is
// asking the machine on somebody's desk to allocate sixty-four
// megabytes, and it can ask again immediately.
//
// So the gateway frames the stream: every message read whole, every
// rectangle's payload length computed from what the encoding says
// rather than searched for. Framing is also the limit of what this can
// do — an encoding whose payload length this cannot compute leaves the
// gateway unable to find the next rectangle, and a gateway that
// guessed would corrupt the screen. Those encodings are removed from
// what the client asks for instead, so the desktop never uses one.

// Encodings, RFC 6143 section 7.7 and the registered additions. The
// negative ones are pseudo-encodings: a rectangle that carries a
// capability or a cursor rather than a picture.
const (
	EncRaw      int32 = 0
	EncCopyRect int32 = 1
	EncRRE      int32 = 2
	EncCoRRE    int32 = 4
	EncHextile  int32 = 5
	EncZlib     int32 = 6
	EncTight    int32 = 7
	EncZlibHex  int32 = 8
	EncTRLE     int32 = 15
	EncZRLE     int32 = 16
	EncJPEG     int32 = 21

	PseudoCursorPos          int32 = -232
	PseudoDesktopSize        int32 = -223
	PseudoLastRect           int32 = -224
	PseudoCursor             int32 = -239
	PseudoXCursor            int32 = -240
	PseudoDesktopName        int32 = -307
	PseudoExtendedDesktop    int32 = -308
	PseudoContinuousUpdates  int32 = -313
	PseudoCursorWithAlpha    int32 = -314
	PseudoExtendedClipboard  int32 = -1063131698 // 0xc0a1e5ce
	PseudoQEMUPointerMotion  int32 = -257
	PseudoQEMUExtendedKey    int32 = -258
	PseudoLEDState           int32 = -261
	PseudoFence              int32 = -312
	PseudoVMwareCursor       int32 = 0x574d5664
	PseudoTightPNG           int32 = -260
	PseudoCompressLevel0     int32 = -256
	PseudoQualityLevel0      int32 = -32
	PseudoCompressLevelLast  int32 = -247
	PseudoQualityLevelLast   int32 = -23
	PseudoDesktopSizeRequest int32 = -223
)

var encodingNames = map[int32]string{
	EncRaw: "raw", EncCopyRect: "copyrect", EncRRE: "rre", EncCoRRE: "corre",
	EncHextile: "hextile", EncZlib: "zlib", EncTight: "tight", EncZlibHex: "zlibhex",
	EncTRLE: "trle", EncZRLE: "zrle", EncJPEG: "jpeg",
	PseudoCursorPos: "cursor-pos", PseudoDesktopSize: "desktop-size",
	PseudoLastRect: "last-rect", PseudoCursor: "cursor", PseudoXCursor: "xcursor",
	PseudoDesktopName: "desktop-name", PseudoExtendedDesktop: "extended-desktop-size",
	PseudoContinuousUpdates: "continuous-updates", PseudoCursorWithAlpha: "cursor-with-alpha",
	PseudoExtendedClipboard: "extended-clipboard", PseudoQEMUPointerMotion: "qemu-pointer-motion",
	PseudoQEMUExtendedKey: "qemu-extended-key", PseudoLEDState: "led-state",
	PseudoFence: "fence", PseudoVMwareCursor: "vmware-cursor", PseudoTightPNG: "tight-png",
}

// EncodingName names an encoding for a log line or a counter. The
// compression and quality levels are ranges rather than single values,
// so they are named as ranges.
func EncodingName(e int32) string {
	if n, ok := encodingNames[e]; ok {
		return n
	}
	switch {
	case e >= PseudoCompressLevel0 && e <= PseudoCompressLevelLast:
		return "compress-level"
	case e >= PseudoQualityLevel0 && e <= PseudoQualityLevelLast:
		return "quality-level"
	}
	return fmt.Sprintf("encoding-%d", e)
}

// Framable reports whether this gateway can compute an encoding's
// payload length, which is what it needs to find the next rectangle.
//
// Tight and TRLE are the notable absences. Both are framable in
// principle and neither is framable safely here: Tight's length
// depends on a filter, a palette size and a "tight pixel" whose width
// is not the pixel format's, and TRLE's on a per-tile palette. A
// mistake in either does not fail, it desynchronises — the gateway
// reads the next rectangle's header out of the middle of a picture —
// and this repository has no TightVNC or TurboVNC server to verify an
// implementation against. So they are not framed and not offered.
func Framable(e int32) bool {
	switch e {
	case EncRaw, EncCopyRect, EncRRE, EncCoRRE, EncHextile, EncZlib, EncZRLE:
		return true
	case PseudoDesktopSize, PseudoLastRect, PseudoCursor, PseudoXCursor, PseudoCursorPos,
		PseudoDesktopName, PseudoExtendedDesktop:
		return true
	}
	// The compression and quality hints are rectangles with no data.
	return levelHint(e)
}

// levelHint is one of the two ranges that ask for a compression or
// quality level. They arrive as rectangles carrying nothing.
func levelHint(e int32) bool {
	return (e >= PseudoCompressLevel0 && e <= PseudoCompressLevelLast) ||
		(e >= PseudoQualityLevel0 && e <= PseudoQualityLevelLast)
}

// Offerable reports whether a client may ask for an encoding through a
// framing gateway. It is Framable plus the capabilities that are
// answered with a message rather than a rectangle: a fence, continuous
// updates, and the extended clipboard, all three of which this gateway
// reads.
//
// Everything else is removed from the client's list rather than
// refused, because a client asks for every encoding it has and a
// desktop uses one of them: taking one away costs a little bandwidth,
// refusing the session costs the operator their session.
func Offerable(e int32) bool {
	switch e {
	case PseudoFence, PseudoContinuousUpdates, PseudoExtendedClipboard:
		return true
	}
	return Framable(e)
}

// Compressed reports whether an encoding's payload is a compressed
// stream the client inflates into a buffer of its own. Those are the
// ones a declared geometry far larger than the bytes that carry it is a
// bomb rather than a saving: a fill or a copy writes into the
// framebuffer the client already has, and the framebuffer is bounded
// separately.
func Compressed(e int32) bool {
	return e == EncZlib || e == EncZRLE || e == EncTight || e == EncZlibHex || e == EncTRLE
}

// BytesPerPixel is the pixel format's width in bytes. RFC 6143 section
// 7.4 allows 8, 16 and 32 bits; anything else is a format this gateway
// cannot compute a length from.
func BytesPerPixel(pf [16]byte) (int, error) {
	switch pf[0] {
	case 8, 16, 32:
		return int(pf[0]) / 8, nil
	}
	return 0, fmt.Errorf("rfb: %d bits per pixel is not 8, 16 or 32", pf[0])
}

// UpdateLimits bound the pixel stream. A zero field is no bound.
type UpdateLimits struct {
	// MaxPixels bounds the framebuffer the desktop announces and any
	// single rectangle inside it, in pixels.
	MaxPixels int
	// MaxRectangles bounds one update's rectangle count.
	MaxRectangles int
	// MaxRectBytes bounds one rectangle's encoded payload.
	MaxRectBytes int
	// MaxRatio bounds declared pixel bytes over encoded bytes for a
	// compressed rectangle: the expansion the client is being asked to
	// make room for.
	MaxRatio int
	// MaxCutText bounds a clipboard transfer in either direction.
	MaxCutText int
}

// The errors a bound produces, so a caller can name the one that fired
// without matching on a message.
var (
	ErrFramebufferTooLarge = errors.New("rfb: the framebuffer is over max_framebuffer_pixels")
	ErrTooManyRectangles   = errors.New("rfb: more rectangles in one update than max_rectangles_per_update")
	ErrRectangleTooLarge   = errors.New("rfb: a rectangle's encoded payload is over max_encoded_rectangle")
	ErrRectanglePixels     = errors.New("rfb: a rectangle is larger than max_framebuffer_pixels")
	ErrRectangleOutside    = errors.New("rfb: a rectangle reaches outside the framebuffer")
	ErrDecodeRatio         = errors.New("rfb: a rectangle would expand by more than max_decode_ratio")
	ErrCutTextTooLarge     = errors.New("rfb: a clipboard transfer is over max_cut_text")
	ErrUnframable          = errors.New("rfb: the peer used an encoding this gateway cannot frame")
)

// CheckFramebuffer applies MaxPixels to an announced desktop size.
func (l UpdateLimits) CheckFramebuffer(w, h uint16) error {
	if l.MaxPixels > 0 && int(w)*int(h) > l.MaxPixels {
		return fmt.Errorf("%w: %dx%d", ErrFramebufferTooLarge, w, h)
	}
	return nil
}

// Server to client message types, RFC 6143 section 7.6 and the
// registered additions.
const (
	SrvFramebufferUpdate   byte = 0
	SrvSetColourMapEntries byte = 1
	SrvBell                byte = 2
	SrvCutText             byte = 3
	SrvEndOfContinuous     byte = 150
	SrvFence               byte = 248
	SrvVMware              byte = 249
	SrvXvp                 byte = 250
	SrvTightFileTransfer   byte = 252
	SrvGII                 byte = 253
	SrvProprietary         byte = 255
)

// Client to server message types.
const (
	CliSetPixelFormat    byte = 0
	CliFixColourMap      byte = 1
	CliSetEncodings      byte = 2
	CliUpdateRequest     byte = 3
	CliKeyEvent          byte = 4
	CliPointerEvent      byte = 5
	CliCutText           byte = 6
	CliEnableContinuous  byte = 150
	CliFence             byte = 248
	CliXvp               byte = 250
	CliSetDesktopSize    byte = 251
	CliTightFileTransfer byte = 252
	CliGII               byte = 253
	CliQEMU              byte = 255
)

var serverMessageNames = map[byte]string{
	SrvFramebufferUpdate: "framebuffer-update", SrvSetColourMapEntries: "set-colour-map",
	SrvBell: "bell", SrvCutText: "server-cut-text", SrvEndOfContinuous: "end-of-continuous-updates",
	SrvFence: "fence", SrvVMware: "vmware", SrvXvp: "xvp",
	SrvTightFileTransfer: "file-transfer", SrvGII: "gii", SrvProprietary: "proprietary",
}

var clientMessageNames = map[byte]string{
	CliSetPixelFormat: "set-pixel-format", CliFixColourMap: "fix-colour-map",
	CliSetEncodings: "set-encodings", CliUpdateRequest: "update-request",
	CliKeyEvent: "key-event", CliPointerEvent: "pointer-event", CliCutText: "client-cut-text",
	CliEnableContinuous: "enable-continuous-updates", CliFence: "fence", CliXvp: "xvp",
	CliSetDesktopSize: "set-desktop-size", CliTightFileTransfer: "file-transfer",
	CliGII: "gii", CliQEMU: "qemu",
}

// ServerMessageName and ClientMessageName name a message type for a log
// line, a counter or a policy list.
func ServerMessageName(t byte) string {
	if n, ok := serverMessageNames[t]; ok {
		return n
	}
	return fmt.Sprintf("message-%d", t)
}

func ClientMessageName(t byte) string {
	if n, ok := clientMessageNames[t]; ok {
		return n
	}
	return fmt.Sprintf("message-%d", t)
}

// maxHeldBytes bounds a message the reader has to hold rather than
// stream: a clipboard transfer, which the caller may drop. Everything
// else is written through as it is read, so a session's memory is a
// scratch buffer and not a picture.
const maxHeldBytes = 16 << 20

// chunk is how much of a picture moves at a time. A full screen raw
// update is tens of megabytes and a viewer wants to start drawing it
// before the last byte arrives, so it is passed through in pieces
// rather than assembled and then forwarded.
const chunk = 64 << 10

// reader reads a message, checking the parts that are lengths and
// passing the parts that are pixels straight through.
//
// The write-through is the point. A gateway that assembled each message
// before forwarding it would hold a full screen update per session --
// tens of megabytes, times max_connections -- which is a way of running
// a proxy out of memory by connecting to it.
type reader struct {
	r io.Reader
	w io.Writer
	// scratch holds the fields the framer looks at, which are never
	// more than a few dozen bytes.
	scratch []byte
	// hold, when not nil, collects what is read instead of writing it
	// out: a message the caller may decide to drop.
	hold []byte
	// held says whether hold is collecting, since an empty message is
	// different from no message.
	held bool
}

// begin starts a message. holding says whether its bytes are collected
// for the caller to decide about rather than written through.
func (x *reader) begin(holding bool) {
	x.held = holding
	x.hold = x.hold[:0]
}

// release writes what has been held so far and stops holding, which is
// what a reader does once it knows the message is not one the caller may
// drop: the type byte is read before the type is known.
func (x *reader) release() error {
	if !x.held {
		return nil
	}
	x.held = false
	if len(x.hold) == 0 || x.w == nil {
		return nil
	}
	_, err := x.w.Write(x.hold)
	return err
}

// emit writes bytes onward, or collects them when the message is held.
func (x *reader) emit(b []byte) error {
	if x.held {
		if len(x.hold)+len(b) > maxHeldBytes {
			return fmt.Errorf("rfb: a held message of over %d bytes", maxHeldBytes)
		}
		x.hold = append(x.hold, b...)
		return nil
	}
	if x.w == nil {
		return nil
	}
	_, err := x.w.Write(b)
	return err
}

// take reads n bytes the framer needs to look at, and passes them on.
// The slice is valid until the next take.
func (x *reader) take(n int) ([]byte, error) {
	if n < 0 || n > chunk {
		return nil, fmt.Errorf("rfb: a header of %d bytes", n)
	}
	if cap(x.scratch) < n {
		x.scratch = make([]byte, n, max(n, 64))
	}
	b := x.scratch[:n]
	if _, err := io.ReadFull(x.r, b); err != nil {
		return nil, err
	}
	return b, x.emit(b)
}

// pass moves n bytes from the peer onward without looking at them,
// which is what a picture is.
func (x *reader) pass(n int) error {
	if n < 0 {
		return fmt.Errorf("rfb: a payload of %d bytes", n)
	}
	for n > 0 {
		step := min(n, chunk)
		if cap(x.scratch) < step {
			x.scratch = make([]byte, step)
		}
		b := x.scratch[:step]
		if _, err := io.ReadFull(x.r, b); err != nil {
			return err
		}
		if err := x.emit(b); err != nil {
			return err
		}
		n -= step
	}
	return nil
}

// ServerReader reads the desktop's messages, bounds them, and writes
// them onward as it goes.
type ServerReader struct {
	x   reader
	bpp int
	// pending is where a pixel format change is taken from, when one is
	// installed. See SetPendingFormat.
	pending func() ([16]byte, bool)
	lim     UpdateLimits
	// w and h are the framebuffer as last announced, which a resize
	// pseudo-rectangle changes.
	w, h uint16
	// rect counts a rectangle's payload as it streams, for the bound on
	// the encodings whose length is only known once it is read.
	rect int
}

// NewServerReader reads the desktop's leg and writes what it accepts to
// out, which is the client and the recording. si is the ServerInit the
// session settled on: its pixel format is what every length in the
// picture is measured in.
func NewServerReader(r io.Reader, out io.Writer, si ServerInit, lim UpdateLimits) (*ServerReader, error) {
	bpp, err := BytesPerPixel(si.PixelFormat)
	if err != nil {
		return nil, err
	}
	return &ServerReader{x: reader{r: r, w: out}, bpp: bpp, lim: lim, w: si.Width, h: si.Height}, nil
}

// SetPixelFormat changes the width every subsequent length is measured
// in. A gateway calls it when it lets a client's SetPixelFormat
// through, and only where it can be sure no update is in flight.
func (s *ServerReader) SetPixelFormat(pf [16]byte) error {
	bpp, err := BytesPerPixel(pf)
	if err != nil {
		return err
	}
	s.bpp = bpp
	return nil
}

// SetPendingFormat installs a source of pixel format changes, read at the point
// the format is used rather than between messages.
//
// A client's SetPixelFormat takes effect on the server the moment the server
// reads it, and the server is told by whoever is forwarding the message. There
// is no point in the stream that says "the next rectangle is in the new format",
// so the only ordering that holds is: store the format, then forward the
// message, and read the stored value when a length is computed from it. A reader
// that took the format between messages took it one message too late -- it was
// already blocked on the socket when the change arrived -- and sized the first
// rectangle of the new format with the bytes per pixel of the old one, which
// over-read into whatever the server sent next.
//
// fn returns false when there is nothing new. It is called from the read
// goroutine, so an implementation shares its state with the writer's goroutine
// under a lock of its own.
func (s *ServerReader) SetPendingFormat(fn func() ([16]byte, bool)) { s.pending = fn }

// applyPending takes a format change that arrived while this reader was waiting
// for bytes. It is called where a length is derived from the format.
func (s *ServerReader) applyPending() error {
	if s.pending == nil {
		return nil
	}
	pf, ok := s.pending()
	if !ok {
		return nil
	}
	return s.SetPixelFormat(pf)
}

// ServerMessage is what one message was. Its bytes have already been
// written onward, except for a clipboard transfer, which is held so the
// caller can decide about it.
type ServerMessage struct {
	Type byte
	// Held is a clipboard message the caller must forward itself, or
	// drop. Nil for every other type.
	Held []byte
	// Rectangles is how many a framebuffer update carried.
	Rectangles int
	// Encodings are the distinct encodings it used, for the log.
	Encodings []int32
	// Resized is set when the update carried a new desktop size.
	Resized bool
	// Width and Height are the desktop after this message.
	Width, Height uint16
	// CutText is the clipboard payload's length.
	CutText int
	// Extended marks a clipboard message in the extended format, whose
	// length arrives negated.
	Extended bool
}

// Next reads one message, writing it onward as it reads.
func (s *ServerReader) Next() (ServerMessage, error) {
	// The type byte is held, because the type is what says whether the
	// message is one the caller may drop -- a clipboard transfer -- and
	// the byte has been read by the time that is known. Every other type
	// releases it and streams the rest.
	s.x.begin(true)
	head, err := s.x.take(1)
	if err != nil {
		return ServerMessage{}, err
	}
	m := ServerMessage{Type: head[0], Width: s.w, Height: s.h}
	if m.Type != SrvCutText {
		if err := s.x.release(); err != nil {
			return m, err
		}
	}
	switch m.Type {
	case SrvFramebufferUpdate:
		if err := s.update(&m); err != nil {
			return m, err
		}
	case SrvSetColourMapEntries:
		b, err := s.x.take(5)
		if err != nil {
			return m, err
		}
		// Three 16 bit values per entry.
		if err := s.x.pass(int(binary.BigEndian.Uint16(b[3:5])) * 6); err != nil {
			return m, err
		}
	case SrvBell, SrvEndOfContinuous:
		// No body.
	case SrvCutText:
		if err := s.cutText(&m); err != nil {
			return m, err
		}
		m.Held = s.x.hold
	case SrvFence:
		b, err := s.x.take(8) // 3 padding, 4 flags, 1 length
		if err != nil {
			return m, err
		}
		if err := s.x.pass(int(b[7])); err != nil {
			return m, err
		}
	default:
		// A message whose length this gateway does not know cannot be
		// read past, so the rest of the stream cannot be framed either.
		// The vendor extensions live here, which is the point: a
		// desktop cannot open a file transfer through a gateway that
		// does not know how long one is.
		return m, fmt.Errorf("%w: server message %s", ErrUnframable, ServerMessageName(m.Type))
	}
	m.Width, m.Height = s.w, s.h
	return m, nil
}

// cutText reads a clipboard message's length and payload. An extended
// clipboard message (the 0xc0a1e5ce pseudo-encoding) carries its length
// negated, which is how a peer that has it says so.
func (s *ServerReader) cutText(m *ServerMessage) error {
	// Still held from the type byte on, so the caller has a whole
	// message to forward or to drop.
	b, err := s.x.take(7) // 3 padding, 4 length
	if err != nil {
		return err
	}
	n := int32(binary.BigEndian.Uint32(b[3:7])) //nolint:gosec // the sign is the format flag
	if n < 0 {
		m.Extended = true
		n = -n
	}
	m.CutText = int(n)
	if s.lim.MaxCutText > 0 && m.CutText > s.lim.MaxCutText {
		return fmt.Errorf("%w: %d bytes", ErrCutTextTooLarge, m.CutText)
	}
	return s.x.pass(m.CutText)
}

// update reads a framebuffer update: a rectangle count, then that many
// rectangles, each of whose payload length comes from its encoding.
func (s *ServerReader) update(m *ServerMessage) error {
	b, err := s.x.take(3) // 1 padding, 2 rectangle count
	if err != nil {
		return err
	}
	count := int(binary.BigEndian.Uint16(b[1:3]))
	// A count of 0xffff with a LastRect at the end is how a server that
	// does not know the count in advance sends one, so the bound is
	// applied to the rectangles actually read rather than to the
	// announced count.
	seen := map[int32]bool{}
	for i := 0; i < count; i++ {
		if s.lim.MaxRectangles > 0 && i >= s.lim.MaxRectangles {
			return fmt.Errorf("%w: %d", ErrTooManyRectangles, count)
		}
		last, enc, err := s.rectangle()
		if err != nil {
			return err
		}
		if !seen[enc] {
			seen[enc] = true
			m.Encodings = append(m.Encodings, enc)
		}
		if enc == PseudoDesktopSize || enc == PseudoExtendedDesktop {
			m.Resized = true
		}
		m.Rectangles++
		if last {
			return nil
		}
	}
	return nil
}

// rectangle reads one rectangle: the twelve byte header, the bounds
// that apply to it, and its payload. It reports whether the rectangle
// was a LastRect, which ends the update whatever the count said.
func (s *ServerReader) rectangle() (bool, int32, error) {
	h, err := s.x.take(12)
	if err != nil {
		return false, 0, err
	}
	x := binary.BigEndian.Uint16(h[0:2])
	y := binary.BigEndian.Uint16(h[2:4])
	w := binary.BigEndian.Uint16(h[4:6])
	ht := binary.BigEndian.Uint16(h[6:8])
	enc := int32(binary.BigEndian.Uint32(h[8:12])) //nolint:gosec // encodings are signed
	if !Framable(enc) {
		return false, enc, fmt.Errorf("%w: %s", ErrUnframable, EncodingName(enc))
	}
	if enc == PseudoLastRect {
		return true, enc, nil
	}
	if picture(enc) {
		if err := s.checkGeometry(x, y, w, ht); err != nil {
			return false, enc, err
		}
	}
	s.rect = 0
	if err := s.payload(enc, w, ht); err != nil {
		return false, enc, err
	}
	if err := s.checkPayload(enc, w, ht); err != nil {
		return false, enc, err
	}
	if enc == PseudoDesktopSize || enc == PseudoExtendedDesktop {
		// A resize is the desktop telling the client to reallocate, so
		// the new size is bounded exactly as the first one was.
		if err := s.lim.CheckFramebuffer(w, ht); err != nil {
			return false, enc, err
		}
		s.w, s.h = w, ht
	}
	return false, enc, nil
}

// picture reports whether a rectangle carries part of the screen, which
// is when its x, y, width and height are geometry rather than a
// cursor's hotspot or a capability's parameters.
func picture(enc int32) bool {
	switch enc {
	case EncRaw, EncCopyRect, EncRRE, EncCoRRE, EncHextile, EncZlib, EncZRLE:
		return true
	}
	return false
}

// checkGeometry keeps a rectangle inside the framebuffer it belongs to.
// A viewer writes a rectangle's pixels at the offset the rectangle
// gives, and one that reaches past the framebuffer is a write past the
// end of the buffer the viewer allocated for it -- which is a memory
// bug in the viewer and a refusal here.
func (s *ServerReader) checkGeometry(x, y, w, h uint16) error {
	if int(x)+int(w) > int(s.w) || int(y)+int(h) > int(s.h) {
		return fmt.Errorf("%w: %dx%d at %d,%d in a %dx%d framebuffer",
			ErrRectangleOutside, w, h, x, y, s.w, s.h)
	}
	if s.lim.MaxPixels > 0 && int(w)*int(h) > s.lim.MaxPixels {
		return fmt.Errorf("%w: %dx%d", ErrRectanglePixels, w, h)
	}
	return nil
}

// checkPayload applies the two bounds that are about the payload: its
// size, and how far a compressed one claims to expand. The length is
// what actually arrived, which for the length-prefixed encodings was
// also checked before any of it was read.
func (s *ServerReader) checkPayload(enc int32, w, h uint16) error {
	if err := s.applyPending(); err != nil {
		return err
	}
	if !picture(enc) {
		return nil
	}
	if s.lim.MaxRectBytes > 0 && s.rect > s.lim.MaxRectBytes {
		return fmt.Errorf("%w: %d bytes in a %s rectangle", ErrRectangleTooLarge, s.rect, EncodingName(enc))
	}
	if s.lim.MaxRatio <= 0 || !Compressed(enc) {
		return nil
	}
	// The declared picture against the bytes that carry it. A payload
	// of nothing is not a saving, it is a rectangle that expands
	// without bound, so it is measured against one byte.
	declared := int(w) * int(h) * s.bpp
	carried := max(s.rect, 1)
	if declared/carried > s.lim.MaxRatio {
		return fmt.Errorf("%w: %d bytes declaring %d (%dx%d at %d bytes per pixel)",
			ErrDecodeRatio, s.rect, declared, w, h, s.bpp)
	}
	return nil
}

// grew records payload bytes as they stream and stops a rectangle that
// outgrows the bound part way through: with the picture passed on as it
// arrives there is nothing held to refuse, so the session ends where the
// bound is crossed rather than after the whole rectangle.
func (s *ServerReader) grew(n int) error {
	s.rect += n
	if s.lim.MaxRectBytes > 0 && s.rect > s.lim.MaxRectBytes {
		return fmt.Errorf("%w: %d bytes", ErrRectangleTooLarge, s.rect)
	}
	return nil
}

// payload reads a rectangle's data. Every branch either computes the
// length from the encoding or reads a length the encoding carries; none
// of them searches for the end.
func (s *ServerReader) payload(enc int32, w, h uint16) error {
	if err := s.applyPending(); err != nil {
		return err
	}
	pixels := int(w) * int(h)
	switch enc {
	case EncRaw:
		return s.body(pixels * s.bpp)
	case EncCopyRect:
		return s.body(4)
	case EncRRE:
		return s.subrects(8)
	case EncCoRRE:
		return s.subrects(4)
	case EncHextile:
		return s.hextile(w, h)
	case EncZlib, EncZRLE:
		return s.lengthPrefixed()
	case PseudoCursor:
		// The cursor's pixels and then its one bit mask, padded to
		// whole bytes per row.
		return s.x.pass(pixels*s.bpp + ((int(w)+7)/8)*int(h))
	case PseudoXCursor:
		if pixels == 0 {
			return nil
		}
		// Two RGB colours, then two one bit planes.
		return s.x.pass(6 + 2*((int(w)+7)/8)*int(h))
	case PseudoDesktopName:
		b, err := s.x.take(4)
		if err != nil {
			return err
		}
		n := int(binary.BigEndian.Uint32(b))
		if n < 0 || n > MaxName {
			return fmt.Errorf("rfb: a desktop name of %d bytes", n)
		}
		return s.x.pass(n)
	case PseudoExtendedDesktop:
		b, err := s.x.take(4) // screen count and three padding
		if err != nil {
			return err
		}
		return s.x.pass(int(b[0]) * 16)
	case PseudoDesktopSize, PseudoCursorPos:
		return nil
	}
	if levelHint(enc) {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrUnframable, EncodingName(enc))
}

// body streams a payload of a known length, counting it towards the
// rectangle bound.
func (s *ServerReader) body(n int) error {
	if err := s.grew(n); err != nil {
		return err
	}
	return s.x.pass(n)
}

// subrects reads an RRE or CoRRE payload: a count, a background pixel,
// and that many subrectangles, each a pixel and geom bytes of geometry
// (eight for RRE's 16 bit coordinates, four for CoRRE's 8 bit ones).
func (s *ServerReader) subrects(geom int) error {
	b, err := s.x.take(4)
	if err != nil {
		return err
	}
	n := int(binary.BigEndian.Uint32(b))
	// The count is a peer's number, so it is bounded before it becomes
	// a read: a count of four billion subrectangles is not a picture.
	total := s.bpp + n*(s.bpp+geom)
	if n < 0 || total < 0 {
		return fmt.Errorf("rfb: %d subrectangles is not a rectangle", n)
	}
	s.rect += 4
	return s.body(total)
}

// lengthPrefixed reads the four byte length the zlib based encodings
// carry, and then that many bytes. The bound is applied to the length
// before any of the payload is read, which is the one place a rectangle
// can be refused before it costs anything at all.
func (s *ServerReader) lengthPrefixed() error {
	b, err := s.x.take(4)
	if err != nil {
		return err
	}
	n := int(binary.BigEndian.Uint32(b))
	if n < 0 {
		return fmt.Errorf("rfb: a payload of %d bytes", n)
	}
	if s.lim.MaxRectBytes > 0 && n > s.lim.MaxRectBytes {
		return fmt.Errorf("%w: %d bytes", ErrRectangleTooLarge, n)
	}
	s.rect += 4
	return s.body(n)
}

// The bits of a hextile tile's subencoding byte, RFC 6143 section
// 7.7.4.
const (
	hextileRaw              = 1
	hextileBackground       = 2
	hextileForeground       = 4
	hextileAnySubrects      = 8
	hextileSubrectsColoured = 16
)

// hextile reads a hextile payload, which is the one framable encoding
// whose length can only be found by reading it: the rectangle is a grid
// of sixteen pixel tiles and each tile says what it contains.
func (s *ServerReader) hextile(w, h uint16) error {
	for ty := 0; ty < int(h); ty += 16 {
		th := min(16, int(h)-ty)
		for tx := 0; tx < int(w); tx += 16 {
			tw := min(16, int(w)-tx)
			b, err := s.x.take(1)
			if err != nil {
				return err
			}
			sub := b[0]
			if err := s.grew(1); err != nil {
				return err
			}
			if sub&hextileRaw != 0 {
				if err := s.body(tw * th * s.bpp); err != nil {
					return err
				}
				continue
			}
			n := 0
			if sub&hextileBackground != 0 {
				n += s.bpp
			}
			if sub&hextileForeground != 0 {
				n += s.bpp
			}
			if err := s.body(n); err != nil {
				return err
			}
			if sub&hextileAnySubrects == 0 {
				continue
			}
			c, err := s.x.take(1)
			if err != nil {
				return err
			}
			each := 2
			if sub&hextileSubrectsColoured != 0 {
				each += s.bpp
			}
			if err := s.grew(1); err != nil {
				return err
			}
			if err := s.body(int(c[0]) * each); err != nil {
				return err
			}
		}
	}
	return nil
}

// ClientReader reads whole client to server messages. Framing this
// direction is what lets a gateway drop one message and forward the
// next: a message is only as long as its type says, and the vendor
// extensions -- file transfer among them -- have no length a gateway
// that does not implement them can know.
//
// These are held rather than streamed. A client's messages are a key
// press, a pointer move, a request for pixels and a clipboard transfer:
// small, and each one a decision.
type ClientReader struct {
	x   reader
	lim UpdateLimits
}

// NewClientReader reads the client's leg.
func NewClientReader(r io.Reader, lim UpdateLimits) *ClientReader {
	return &ClientReader{x: reader{r: r}, lim: lim}
}

// ClientMessage is one message read whole.
type ClientMessage struct {
	Type byte
	// Bytes is the message as it arrived, for forwarding.
	Bytes []byte
	// Encodings are what a SetEncodings asked for, in order.
	Encodings []int32
	// PixelFormat is what a SetPixelFormat asked for.
	PixelFormat [16]byte
	// CutText is a clipboard payload's length.
	CutText int
	// Extended marks a clipboard message in the extended format.
	Extended bool
	// Width and Height are what a SetDesktopSize asked for.
	Width, Height uint16
}

// MaxEncodings bounds a SetEncodings list. A client asks for every
// encoding it has, which is tens; the point of the bound is that the
// list is read into memory before it is filtered.
const MaxEncodings = 4096

// Next reads one message.
func (c *ClientReader) Next() (ClientMessage, error) {
	c.x.begin(true)
	head, err := c.x.take(1)
	if err != nil {
		return ClientMessage{}, err
	}
	m := ClientMessage{Type: head[0]}
	switch m.Type {
	case CliSetPixelFormat:
		b, err := c.x.take(19) // 3 padding, 16 pixel format
		if err != nil {
			return m, err
		}
		copy(m.PixelFormat[:], b[3:19])
	case CliSetEncodings:
		if err := c.setEncodings(&m); err != nil {
			return m, err
		}
	case CliUpdateRequest:
		err = c.x.pass(9)
	case CliKeyEvent:
		err = c.x.pass(7)
	case CliPointerEvent:
		err = c.x.pass(5)
	case CliCutText:
		err = c.cutText(&m)
	case CliEnableContinuous:
		err = c.x.pass(9)
	case CliFence:
		b, ferr := c.x.take(8) // 3 padding, 4 flags, 1 length
		if ferr != nil {
			return m, ferr
		}
		err = c.x.pass(int(b[7]))
	case CliSetDesktopSize:
		b, serr := c.x.take(7) // 1 padding, 2 width, 2 height, 1 screens, 1 padding
		if serr != nil {
			return m, serr
		}
		m.Width = binary.BigEndian.Uint16(b[1:3])
		m.Height = binary.BigEndian.Uint16(b[3:5])
		err = c.x.pass(int(b[5]) * 16)
	default:
		return m, fmt.Errorf("%w: client message %s", ErrUnframable, ClientMessageName(m.Type))
	}
	if err != nil {
		return m, err
	}
	m.Bytes = c.x.hold
	return m, nil
}

func (c *ClientReader) setEncodings(m *ClientMessage) error {
	b, err := c.x.take(3) // 1 padding, 2 count
	if err != nil {
		return err
	}
	n := int(binary.BigEndian.Uint16(b[1:3]))
	if n > MaxEncodings {
		return fmt.Errorf("rfb: %d encodings asked for, over the %d bound", n, MaxEncodings)
	}
	m.Encodings = make([]int32, 0, n)
	for i := 0; i < n; i++ {
		e, err := c.x.take(4)
		if err != nil {
			return err
		}
		m.Encodings = append(m.Encodings, int32(binary.BigEndian.Uint32(e))) //nolint:gosec // encodings are signed
	}
	return nil
}

func (c *ClientReader) cutText(m *ClientMessage) error {
	b, err := c.x.take(7) // 3 padding, 4 length
	if err != nil {
		return err
	}
	n := int32(binary.BigEndian.Uint32(b[3:7])) //nolint:gosec // the sign is the format flag
	if n < 0 {
		m.Extended = true
		n = -n
	}
	m.CutText = int(n)
	if c.lim.MaxCutText > 0 && m.CutText > c.lim.MaxCutText {
		return fmt.Errorf("%w: %d bytes", ErrCutTextTooLarge, m.CutText)
	}
	return c.x.pass(m.CutText)
}

// EncodeSetEncodings renders a SetEncodings message, which is how a
// gateway forwards a list it has filtered rather than the one it was
// given.
func EncodeSetEncodings(list []int32) []byte {
	out := make([]byte, 0, 4+len(list)*4)
	out = append(out, CliSetEncodings, 0)
	out = binary.BigEndian.AppendUint16(out, uint16(len(list))) //nolint:gosec // callers filter a 16 bit count
	for _, e := range list {
		out = binary.BigEndian.AppendUint32(out, uint32(e)) //nolint:gosec // encodings are signed
	}
	return out
}

// FilterEncodings keeps the encodings a framing gateway can live with,
// in the order the client asked for them, and reports the ones it
// removed. Raw is added when nothing that draws survived: every RFB
// client and server must support it, so a list that would otherwise
// leave the desktop unable to send a picture still works.
func FilterEncodings(list []int32) (kept, removed []int32) {
	kept = make([]int32, 0, len(list))
	for _, e := range list {
		if Offerable(e) {
			kept = append(kept, e)
			continue
		}
		removed = append(removed, e)
	}
	hasPicture := false
	for _, e := range kept {
		if picture(e) {
			hasPicture = true
			break
		}
	}
	if !hasPicture {
		kept = append(kept, EncRaw)
	}
	return kept, removed
}
