package replay

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/color"
	"io"
)

// The RFB side of a replay: a framebuffer, the server messages that
// change it, and the encodings this package can read.
//
// What is decoded: Raw, CopyRect, RRE, CoRRE, Hextile, TRLE and ZRLE,
// which is the set RFC 6143 specifies, plus the DesktopSize and LastRect
// pseudo-encodings and the two cursor ones (read to keep the stream in
// step, and not drawn -- a cursor is not what was on the screen).
//
// What is not: Tight and the vendors' own. They are not in RFC 6143,
// Tight carries JPEG and its own zlib streams, and a player that guessed
// would be showing a picture nobody sent. Such a rectangle is counted and
// named, and the framebuffer keeps whatever was there.

// Server message types of RFC 6143 section 7.6.
const (
	msgFramebufferUpdate   = 0
	msgSetColourMapEntries = 1
	msgBell                = 2
	msgServerCutText       = 3
)

// The encodings this decoder knows, by their wire numbers.
const (
	encRaw      int32 = 0
	encCopyRect int32 = 1
	encRRE      int32 = 2
	encCoRRE    int32 = 4
	encHextile  int32 = 5
	encTRLE     int32 = 15
	encZRLE     int32 = 16
	encTight    int32 = 7

	pseudoCursor      int32 = -239
	pseudoXCursor     int32 = -240
	pseudoDesktopSize int32 = -223
	pseudoLastRect    int32 = -224
)

// EncodingName names an encoding for a timeline or a warning.
func EncodingName(e int32) string {
	switch e {
	case encRaw:
		return "raw"
	case encCopyRect:
		return "copy-rect"
	case encRRE:
		return "rre"
	case encCoRRE:
		return "corre"
	case encHextile:
		return "hextile"
	case encTRLE:
		return "trle"
	case encZRLE:
		return "zrle"
	case encTight:
		return "tight"
	case pseudoCursor:
		return "cursor"
	case pseudoXCursor:
		return "x-cursor"
	case pseudoDesktopSize:
		return "desktop-size"
	case pseudoLastRect:
		return "last-rect"
	}
	return fmt.Sprintf("encoding-%d", e)
}

// MaxPixels bounds a framebuffer this decoder will allocate: the same
// 7680x4320 the gateway bounds a session to.
const MaxPixels = 33_177_600

// Framebuffer is the picture as the decoder has it, and the record of
// what it could not read.
type Framebuffer struct {
	img *image.RGBA
	pf  pixelFormat
	// cmap is the colour map for a format that is not true colour.
	cmap []color.RGBA

	// Updates is how many framebuffer updates have been applied.
	Updates int
	// Rects counts rectangles by encoding name.
	Rects map[string]int
	// Undecoded counts the rectangles left alone because this package
	// does not read their encoding.
	Undecoded int
	// Cut is the last clipboard text the server sent, clipped.
	Cut string
	// Bells is how many times the session rang.
	Bells int
}

// NewFramebuffer prepares a framebuffer of the recorded size.
func NewFramebuffer(w, h int, pf [16]byte) (*Framebuffer, error) {
	if w <= 0 || h <= 0 {
		return nil, fmt.Errorf("replay: a framebuffer of %dx%d", w, h)
	}
	if w*h > MaxPixels {
		return nil, fmt.Errorf("replay: a framebuffer of %dx%d is past the bound of %d pixels", w, h, MaxPixels)
	}
	f := &Framebuffer{img: image.NewRGBA(image.Rect(0, 0, w, h)), pf: readPixelFormat(pf), Rects: map[string]int{}}
	return f, nil
}

// Image is the picture now. The caller may encode it; it must not write
// to it.
func (f *Framebuffer) Image() *image.RGBA { return f.img }

// Size is the framebuffer's current size, which a desktop-size
// pseudo-rectangle can change mid-session.
func (f *Framebuffer) Size() (int, int) {
	b := f.img.Bounds()
	return b.Dx(), b.Dy()
}

// pixelFormat is the sixteen octets, read.
type pixelFormat struct {
	bpp, depth             int
	bigEndian, trueColor   bool
	rMax, gMax, bMax       uint32
	rShift, gShift, bShift uint
}

func readPixelFormat(b [16]byte) pixelFormat {
	return pixelFormat{
		bpp:       int(b[0]),
		depth:     int(b[1]),
		bigEndian: b[2] != 0,
		trueColor: b[3] != 0,
		rMax:      uint32(binary.BigEndian.Uint16(b[4:6])),
		gMax:      uint32(binary.BigEndian.Uint16(b[6:8])),
		bMax:      uint32(binary.BigEndian.Uint16(b[8:10])),
		rShift:    uint(b[10]),
		gShift:    uint(b[11]),
		bShift:    uint(b[12]),
	}
}

// bytesPerPixel is what one pixel occupies on the wire.
func (p pixelFormat) bytesPerPixel() int {
	switch p.bpp {
	case 8:
		return 1
	case 16:
		return 2
	case 32:
		return 4
	}
	return 0
}

// colourAt reads one pixel.
func (f *Framebuffer) colourAt(b []byte) color.RGBA {
	p := f.pf
	n := p.bytesPerPixel()
	var v uint32
	switch n {
	case 1:
		v = uint32(b[0])
	case 2:
		if p.bigEndian {
			v = uint32(binary.BigEndian.Uint16(b))
		} else {
			v = uint32(binary.LittleEndian.Uint16(b))
		}
	case 4:
		if p.bigEndian {
			v = binary.BigEndian.Uint32(b)
		} else {
			v = binary.LittleEndian.Uint32(b)
		}
	}
	if !p.trueColor {
		if int(v) < len(f.cmap) {
			return f.cmap[v]
		}
		return color.RGBA{A: 255}
	}
	scale := func(raw, max uint32) uint8 {
		if max == 0 {
			return 0
		}
		return uint8(raw * 255 / max) //nolint:gosec // bounded by the division
	}
	return color.RGBA{
		R: scale((v>>p.rShift)&p.rMax, p.rMax),
		G: scale((v>>p.gShift)&p.gMax, p.gMax),
		B: scale((v>>p.bShift)&p.bMax, p.bMax),
		A: 255,
	}
}

// Rect is one rectangle of an update, for the timeline.
type Rect struct {
	X, Y, W, H int
	Encoding   int32
	Bytes      int
	Decoded    bool
}

// Update is what one framebuffer update did.
type Update struct {
	Rects []Rect
	// Resized is set when a desktop-size pseudo-rectangle changed the
	// framebuffer.
	Resized bool
}

// stream is a cursor over the recorded server bytes. The decoder is fed
// one event at a time and a message can span events, so the bytes are
// buffered and consumed only when a whole message is there.
type stream struct {
	buf []byte
	// zin is the ZRLE zlib stream, which is one stream for the whole
	// session rather than one per rectangle.
	zr   io.ReadCloser
	zbuf bytes.Buffer
	// zplain is the decompressed tail: a rectangle's tiles may need more
	// bytes than the stream has produced yet, and the leftovers belong to
	// the next one.
	zplain []byte
}

// Decoder applies a recorded RFB server stream to a framebuffer.
type Decoder struct {
	fb *Framebuffer
	st stream
	// MaxBuffered bounds what is held while waiting for the rest of a
	// message. A server that announced a rectangle and stopped must not
	// grow this without limit.
	MaxBuffered int
}

// NewDecoder returns a decoder writing into fb.
func NewDecoder(fb *Framebuffer) *Decoder {
	return &Decoder{fb: fb, MaxBuffered: 64 << 20}
}

// ErrShort says the buffered bytes do not hold a whole message yet. It
// is not a failure: the next event may complete it.
var ErrShort = fmt.Errorf("replay: incomplete message")

// Feed adds recorded bytes and applies every complete message in them.
// It returns the updates that completed, in order.
func (d *Decoder) Feed(b []byte) ([]Update, error) {
	if len(d.st.buf)+len(b) > d.MaxBuffered {
		return nil, fmt.Errorf("replay: %d bytes buffered without a complete message", len(d.st.buf)+len(b))
	}
	d.st.buf = append(d.st.buf, b...)
	var out []Update
	for len(d.st.buf) > 0 {
		u, n, err := d.message(d.st.buf)
		if errors.Is(err, ErrShort) {
			break
		}
		if err != nil {
			return out, err
		}
		d.st.buf = d.st.buf[n:]
		if u != nil {
			out = append(out, *u)
		}
	}
	return out, nil
}

// Pending is how many bytes are held waiting for the rest of a message,
// which at the end of a recording is a truncated one.
func (d *Decoder) Pending() int { return len(d.st.buf) }

// message reads one server message. It returns the number of bytes it
// consumed, and an update when the message was one.
func (d *Decoder) message(b []byte) (*Update, int, error) {
	switch b[0] {
	case msgFramebufferUpdate:
		return d.update(b)
	case msgSetColourMapEntries:
		if len(b) < 6 {
			return nil, 0, ErrShort
		}
		first := int(binary.BigEndian.Uint16(b[2:4]))
		n := int(binary.BigEndian.Uint16(b[4:6]))
		need := 6 + n*6
		if len(b) < need {
			return nil, 0, ErrShort
		}
		d.fb.setColourMap(first, b[6:need])
		return nil, need, nil
	case msgBell:
		d.fb.Bells++
		return nil, 1, nil
	case msgServerCutText:
		if len(b) < 8 {
			return nil, 0, ErrShort
		}
		n := int(binary.BigEndian.Uint32(b[4:8]))
		if n < 0 || n > 1<<20 {
			return nil, 0, fmt.Errorf("replay: a clipboard of %d bytes", n)
		}
		if len(b) < 8+n {
			return nil, 0, ErrShort
		}
		d.fb.Cut = clip(string(b[8 : 8+n]))
		return nil, 8 + n, nil
	}
	return nil, 0, fmt.Errorf("replay: server message type %d, which RFC 6143 does not define", b[0])
}

func clip(s string) string {
	const max = 256
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

func (f *Framebuffer) setColourMap(first int, b []byte) {
	for i := 0; i+6 <= len(b); i += 6 {
		idx := first + i/6
		if idx < 0 || idx > 0xFFFF {
			continue
		}
		for len(f.cmap) <= idx {
			f.cmap = append(f.cmap, color.RGBA{A: 255})
		}
		f.cmap[idx] = color.RGBA{
			R: uint8(binary.BigEndian.Uint16(b[i:i+2]) >> 8),   //nolint:gosec // the high half
			G: uint8(binary.BigEndian.Uint16(b[i+2:i+4]) >> 8), //nolint:gosec // the same
			B: uint8(binary.BigEndian.Uint16(b[i+4:i+6]) >> 8), //nolint:gosec // the same
			A: 255,
		}
	}
}

// update reads a framebuffer update: a count of rectangles and then each
// one, in the encoding it names.
func (d *Decoder) update(b []byte) (*Update, int, error) {
	if len(b) < 4 {
		return nil, 0, ErrShort
	}
	nRects := int(binary.BigEndian.Uint16(b[2:4]))
	off := 4
	u := &Update{}
	for i := 0; i < nRects; i++ {
		if len(b) < off+12 {
			return nil, 0, ErrShort
		}
		x := int(binary.BigEndian.Uint16(b[off : off+2]))
		y := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		w := int(binary.BigEndian.Uint16(b[off+4 : off+6]))
		h := int(binary.BigEndian.Uint16(b[off+6 : off+8]))
		enc := int32(binary.BigEndian.Uint32(b[off+8 : off+12])) //nolint:gosec // the field is signed
		off += 12
		if enc == pseudoLastRect {
			break
		}
		n, err := d.rect(b[off:], x, y, w, h, enc)
		if err != nil {
			return nil, 0, err
		}
		r := Rect{X: x, Y: y, W: w, H: h, Encoding: enc, Bytes: n, Decoded: enc != encTight && !unknown(enc)}
		if enc == pseudoDesktopSize {
			u.Resized = true
		}
		u.Rects = append(u.Rects, r)
		d.fb.Rects[EncodingName(enc)]++
		if !r.Decoded {
			d.fb.Undecoded++
		}
		off += n
	}
	d.fb.Updates++
	return u, off, nil
}

// unknown says whether an encoding is one this package cannot even
// measure, which is where a stream stops being readable.
func unknown(enc int32) bool {
	switch enc {
	case encRaw, encCopyRect, encRRE, encCoRRE, encHextile, encTRLE, encZRLE,
		pseudoCursor, pseudoXCursor, pseudoDesktopSize, pseudoLastRect:
		return false
	}
	return true
}
