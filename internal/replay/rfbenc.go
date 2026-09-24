package replay

import (
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/color"
)

// One function per encoding. Each returns how many bytes of the
// rectangle's payload it consumed, or ErrShort when the payload is not
// all here yet -- which is the normal case while a recording is read
// event by event.

func (d *Decoder) rect(b []byte, x, y, w, h int, enc int32) (int, error) {
	switch enc {
	case encRaw:
		return d.raw(b, x, y, w, h)
	case encCopyRect:
		return d.copyRect(b, x, y, w, h)
	case encRRE:
		return d.rre(b, x, y, w, h, false)
	case encCoRRE:
		return d.rre(b, x, y, w, h, true)
	case encHextile:
		return d.hextile(b, x, y, w, h)
	case encTRLE:
		return d.trle(b, x, y, w, h, nil)
	case encZRLE:
		return d.zrle(b, x, y, w, h)
	case pseudoDesktopSize:
		d.fb.resize(w, h)
		return 0, nil
	case pseudoCursor:
		// The cursor is read to keep the stream in step and not drawn:
		// what was on the screen is the framebuffer, and a cursor image
		// is not part of it.
		bpp := d.fb.pf.bytesPerPixel()
		need := w*h*bpp + ((w+7)/8)*h
		if len(b) < need {
			return 0, ErrShort
		}
		return need, nil
	case pseudoXCursor:
		need := 6
		if w > 0 && h > 0 {
			need += 2 * ((w + 7) / 8) * h
		}
		if len(b) < need {
			return 0, ErrShort
		}
		return need, nil
	}
	// An encoding this package does not read. The stream cannot be
	// followed past a rectangle whose length is not computable, so this
	// is where a replay of it stops -- said plainly rather than by
	// showing a picture that was never sent.
	return 0, fmt.Errorf("replay: rectangle in %s, which this player does not decode", EncodingName(enc))
}

// resize changes the framebuffer, keeping what was already drawn where
// it still fits.
func (f *Framebuffer) resize(w, h int) {
	if w <= 0 || h <= 0 || w*h > MaxPixels {
		return
	}
	next := image.NewRGBA(image.Rect(0, 0, w, h))
	old := f.img.Bounds()
	for yy := 0; yy < h && yy < old.Dy(); yy++ {
		for xx := 0; xx < w && xx < old.Dx(); xx++ {
			next.SetRGBA(xx, yy, f.img.RGBAAt(xx, yy))
		}
	}
	f.img = next
}

// set paints one pixel, ignoring anything outside the framebuffer: a
// rectangle that runs past the edge is a server's claim, not a reason to
// write outside an array.
func (f *Framebuffer) set(x, y int, c color.RGBA) {
	b := f.img.Bounds()
	if x < 0 || y < 0 || x >= b.Dx() || y >= b.Dy() {
		return
	}
	f.img.SetRGBA(x, y, c)
}

func (f *Framebuffer) fill(x, y, w, h int, c color.RGBA) {
	for yy := 0; yy < h; yy++ {
		for xx := 0; xx < w; xx++ {
			f.set(x+xx, y+yy, c)
		}
	}
}

// raw is one pixel after another, left to right and top to bottom.
func (d *Decoder) raw(b []byte, x, y, w, h int) (int, error) {
	bpp := d.fb.pf.bytesPerPixel()
	if bpp == 0 {
		return 0, fmt.Errorf("replay: %d bits per pixel", d.fb.pf.bpp)
	}
	need := w * h * bpp
	if len(b) < need {
		return 0, ErrShort
	}
	off := 0
	for yy := 0; yy < h; yy++ {
		for xx := 0; xx < w; xx++ {
			d.fb.set(x+xx, y+yy, d.fb.colourAt(b[off:off+bpp]))
			off += bpp
		}
	}
	return need, nil
}

// copyRect moves a rectangle that is already on the screen.
func (d *Decoder) copyRect(b []byte, x, y, w, h int) (int, error) {
	if len(b) < 4 {
		return 0, ErrShort
	}
	sx := int(binary.BigEndian.Uint16(b[0:2]))
	sy := int(binary.BigEndian.Uint16(b[2:4]))
	// The source is read into a copy first: a move that overlaps itself
	// would otherwise read pixels it had just written.
	src := make([]color.RGBA, 0, w*h)
	for yy := 0; yy < h; yy++ {
		for xx := 0; xx < w; xx++ {
			src = append(src, d.fb.img.RGBAAt(sx+xx, sy+yy))
		}
	}
	i := 0
	for yy := 0; yy < h; yy++ {
		for xx := 0; xx < w; xx++ {
			d.fb.set(x+xx, y+yy, src[i])
			i++
		}
	}
	return 4, nil
}

// rre is a background colour and then a list of subrectangles. CoRRE is
// the same with one-byte coordinates.
func (d *Decoder) rre(b []byte, x, y, w, h int, compact bool) (int, error) {
	bpp := d.fb.pf.bytesPerPixel()
	if len(b) < 4+bpp {
		return 0, ErrShort
	}
	n := int(binary.BigEndian.Uint32(b[0:4]))
	if n < 0 || n > 1<<20 {
		return 0, fmt.Errorf("replay: %d subrectangles in one rectangle", n)
	}
	sub := 8
	if compact {
		sub = 4
	}
	need := 4 + bpp + n*(bpp+sub)
	if len(b) < need {
		return 0, ErrShort
	}
	d.fb.fill(x, y, w, h, d.fb.colourAt(b[4:4+bpp]))
	off := 4 + bpp
	for i := 0; i < n; i++ {
		c := d.fb.colourAt(b[off : off+bpp])
		off += bpp
		var sx, sy, sw, sh int
		if compact {
			sx, sy, sw, sh = int(b[off]), int(b[off+1]), int(b[off+2]), int(b[off+3])
		} else {
			sx = int(binary.BigEndian.Uint16(b[off : off+2]))
			sy = int(binary.BigEndian.Uint16(b[off+2 : off+4]))
			sw = int(binary.BigEndian.Uint16(b[off+4 : off+6]))
			sh = int(binary.BigEndian.Uint16(b[off+6 : off+8]))
		}
		off += sub
		d.fb.fill(x+sx, y+sy, sw, sh, c)
	}
	return need, nil
}

// Hextile subencoding bits (RFC 6143 section 7.7.4).
const (
	hexRaw = 1 << iota
	hexBackground
	hexForeground
	hexAnySubrects
	hexSubrectsColoured
)

// hextile divides the rectangle into 16x16 tiles, each of which is raw
// or a background with subrectangles, and each of which may inherit the
// previous tile's colours.
func (d *Decoder) hextile(b []byte, x, y, w, h int) (int, error) {
	bpp := d.fb.pf.bytesPerPixel()
	off := 0
	var bg, fg color.RGBA
	for ty := 0; ty < h; ty += 16 {
		for tx := 0; tx < w; tx += 16 {
			tw, th := min(16, w-tx), min(16, h-ty)
			if len(b) < off+1 {
				return 0, ErrShort
			}
			mask := b[off]
			off++
			if mask&hexRaw != 0 {
				need := tw * th * bpp
				if len(b) < off+need {
					return 0, ErrShort
				}
				i := off
				for yy := 0; yy < th; yy++ {
					for xx := 0; xx < tw; xx++ {
						d.fb.set(x+tx+xx, y+ty+yy, d.fb.colourAt(b[i:i+bpp]))
						i += bpp
					}
				}
				off += need
				continue
			}
			if mask&hexBackground != 0 {
				if len(b) < off+bpp {
					return 0, ErrShort
				}
				bg = d.fb.colourAt(b[off : off+bpp])
				off += bpp
			}
			if mask&hexForeground != 0 {
				if len(b) < off+bpp {
					return 0, ErrShort
				}
				fg = d.fb.colourAt(b[off : off+bpp])
				off += bpp
			}
			d.fb.fill(x+tx, y+ty, tw, th, bg)
			if mask&hexAnySubrects == 0 {
				continue
			}
			if len(b) < off+1 {
				return 0, ErrShort
			}
			n := int(b[off])
			off++
			for i := 0; i < n; i++ {
				c := fg
				if mask&hexSubrectsColoured != 0 {
					if len(b) < off+bpp {
						return 0, ErrShort
					}
					c = d.fb.colourAt(b[off : off+bpp])
					off += bpp
				}
				if len(b) < off+2 {
					return 0, ErrShort
				}
				sx, sy := int(b[off]>>4), int(b[off]&0x0F)
				sw, sh := int(b[off+1]>>4)+1, int(b[off+1]&0x0F)+1
				off += 2
				d.fb.fill(x+tx+sx, y+ty+sy, sw, sh, c)
			}
		}
	}
	return off, nil
}

// zrle is TRLE tiles through one zlib stream shared by the whole
// session, which is why the stream lives on the decoder rather than on
// the rectangle -- and why a decoder that opened a new stream per
// rectangle would read the first one and fail on every one after it.
//
// The plaintext is grown until the tiles parse rather than read to a
// worst-case bound: a server flushes the stream per rectangle, so asking
// for more than it sent would block on bytes that are not coming.
func (d *Decoder) zrle(b []byte, x, y, w, h int) (int, error) {
	if len(b) < 4 {
		return 0, ErrShort
	}
	n := int(binary.BigEndian.Uint32(b[0:4]))
	if n < 0 || n > 1<<26 {
		return 0, fmt.Errorf("replay: a zrle rectangle of %d bytes", n)
	}
	if len(b) < 4+n {
		return 0, ErrShort
	}
	d.st.zbuf.Write(b[4 : 4+n])
	if d.st.zr == nil {
		zr, err := zlib.NewReader(&d.st.zbuf)
		if err != nil {
			return 0, fmt.Errorf("replay: the zrle stream does not start: %w", err)
		}
		d.st.zr = zr
	}
	bound := zrleTileBytes(w, h, d.fb.pf)
	for {
		used, err := d.trle(d.st.zplain, x, y, w, h, nil)
		if err == nil {
			d.st.zplain = d.st.zplain[used:]
			return 4 + n, nil
		}
		if !errors.Is(err, ErrShort) {
			return 0, err
		}
		if len(d.st.zplain) > bound {
			return 0, fmt.Errorf("replay: a zrle rectangle decompressed past %d bytes", bound)
		}
		chunk := make([]byte, 16<<10)
		rn, rerr := d.st.zr.Read(chunk)
		if rn > 0 {
			d.st.zplain = append(d.st.zplain, chunk[:rn]...)
			continue
		}
		if rerr != nil {
			// The stream gave everything it has and the tiles are still
			// short: the rectangle is cut off, which at the end of a
			// truncated recording is the normal case.
			return 0, ErrShort
		}
	}
}

// zrleTileBytes is the most one rectangle of tiles can decompress to,
// which is what the reader is bounded by: a zlib stream that claimed to
// hold more would otherwise be an unbounded read.
func zrleTileBytes(w, h int, pf pixelFormat) int {
	tiles := ((w + 63) / 64) * ((h + 63) / 64)
	if tiles < 1 {
		tiles = 1
	}
	per := 1 + 64*64*(pf.bytesPerPixel()+1) + 128*(pf.bytesPerPixel()+1)
	return tiles * per
}

// trle is the tile encoding ZRLE carries and an encoding of its own:
// 64x64 tiles, each raw, a solid colour, a palette or run-length coded.
func (d *Decoder) trle(b []byte, x, y, w, h int, _ []color.RGBA) (int, error) {
	cpix := d.fb.cpixelBytes()
	off := 0
	for ty := 0; ty < h; ty += 64 {
		for tx := 0; tx < w; tx += 64 {
			tw, th := min(64, w-tx), min(64, h-ty)
			if len(b) < off+1 {
				return 0, ErrShort
			}
			mode := b[off]
			off++
			switch {
			case mode == 0: // raw
				need := tw * th * cpix
				if len(b) < off+need {
					return 0, ErrShort
				}
				i := off
				for yy := 0; yy < th; yy++ {
					for xx := 0; xx < tw; xx++ {
						d.fb.set(x+tx+xx, y+ty+yy, d.fb.cpixel(b[i:i+cpix]))
						i += cpix
					}
				}
				off += need
			case mode == 1: // one colour
				if len(b) < off+cpix {
					return 0, ErrShort
				}
				d.fb.fill(x+tx, y+ty, tw, th, d.fb.cpixel(b[off:off+cpix]))
				off += cpix
			case mode >= 2 && mode <= 16: // packed palette
				n := int(mode)
				if len(b) < off+n*cpix {
					return 0, ErrShort
				}
				pal := make([]color.RGBA, n)
				for i := 0; i < n; i++ {
					pal[i] = d.fb.cpixel(b[off+i*cpix : off+(i+1)*cpix])
				}
				off += n * cpix
				bits := paletteBits(n)
				rowBytes := (tw*bits + 7) / 8
				if len(b) < off+rowBytes*th {
					return 0, ErrShort
				}
				for yy := 0; yy < th; yy++ {
					row := b[off+yy*rowBytes : off+(yy+1)*rowBytes]
					for xx := 0; xx < tw; xx++ {
						idx := packedIndex(row, xx, bits)
						if idx < len(pal) {
							d.fb.set(x+tx+xx, y+ty+yy, pal[idx])
						}
					}
				}
				off += rowBytes * th
			case mode == 128: // plain run length
				n, err := d.rleTile(b[off:], x+tx, y+ty, tw, th, nil, cpix)
				if err != nil {
					return 0, err
				}
				off += n
			case mode >= 130: // palette run length
				n := int(mode - 128)
				if len(b) < off+n*cpix {
					return 0, ErrShort
				}
				pal := make([]color.RGBA, n)
				for i := 0; i < n; i++ {
					pal[i] = d.fb.cpixel(b[off+i*cpix : off+(i+1)*cpix])
				}
				off += n * cpix
				used, err := d.rleTile(b[off:], x+tx, y+ty, tw, th, pal, cpix)
				if err != nil {
					return 0, err
				}
				off += used
			default:
				return 0, fmt.Errorf("replay: tile mode %d, which the specification does not define", mode)
			}
		}
	}
	return off, nil
}

// rleTile reads a run-length coded tile, either of plain pixels or of
// palette indices.
func (d *Decoder) rleTile(b []byte, x, y, w, h int, pal []color.RGBA, cpix int) (int, error) {
	off, painted, total := 0, 0, w*h
	for painted < total {
		var c color.RGBA
		if pal == nil {
			if len(b) < off+cpix {
				return 0, ErrShort
			}
			c = d.fb.cpixel(b[off : off+cpix])
			off += cpix
		} else {
			if len(b) < off+1 {
				return 0, ErrShort
			}
			idx := int(b[off] & 0x7F)
			runFollows := b[off]&0x80 != 0
			off++
			if idx < len(pal) {
				c = pal[idx]
			}
			if !runFollows {
				d.paint(x, y, w, painted, 1, c)
				painted++
				continue
			}
		}
		run := 1
		for {
			if len(b) < off+1 {
				return 0, ErrShort
			}
			v := b[off]
			off++
			run += int(v)
			if v != 255 {
				break
			}
		}
		if run > total-painted {
			run = total - painted
		}
		d.paint(x, y, w, painted, run, c)
		painted += run
	}
	return off, nil
}

// paint fills run pixels starting at the painted-th pixel of a tile.
func (d *Decoder) paint(x, y, w, painted, run int, c color.RGBA) {
	for i := 0; i < run; i++ {
		p := painted + i
		d.fb.set(x+p%w, y+p/w, c)
	}
}

// cpixelBytes is the compressed pixel size TRLE uses: three bytes where
// the format is 32 bits with an unused byte, and the pixel size
// otherwise.
func (f *Framebuffer) cpixelBytes() int {
	p := f.pf
	if p.bpp == 32 && p.depth <= 24 && p.rMax <= 255 && p.gMax <= 255 && p.bMax <= 255 {
		return 3
	}
	return p.bytesPerPixel()
}

// cpixel reads a compressed pixel.
func (f *Framebuffer) cpixel(b []byte) color.RGBA {
	if len(b) != 3 {
		return f.colourAt(b)
	}
	// The three significant bytes, in the order the format's shifts say.
	var v uint32
	if f.pf.bigEndian {
		v = uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
	} else {
		v = uint32(b[2])<<16 | uint32(b[1])<<8 | uint32(b[0])
	}
	var four [4]byte
	if f.pf.bigEndian {
		binary.BigEndian.PutUint32(four[:], v)
	} else {
		binary.LittleEndian.PutUint32(four[:], v)
	}
	return f.colourAt(four[:])
}

// paletteBits is how many bits one index takes for a palette of n.
func paletteBits(n int) int {
	switch {
	case n <= 2:
		return 1
	case n <= 4:
		return 2
	case n <= 16:
		return 4
	}
	return 8
}

// packedIndex reads the xx-th index of a packed row.
func packedIndex(row []byte, xx, bits int) int {
	switch bits {
	case 1:
		i := xx / 8
		if i >= len(row) {
			return 0
		}
		shift := 7 - xx%8
		return int(row[i]>>uint(shift)) & 1 //nolint:gosec // 0..7 by construction
	case 2:
		i := xx / 4
		if i >= len(row) {
			return 0
		}
		shift := 6 - 2*(xx%4)
		return int(row[i]>>uint(shift)) & 3 //nolint:gosec // 0, 2, 4 or 6 by construction
	case 4:
		i := xx / 2
		if i >= len(row) {
			return 0
		}
		if xx%2 == 0 {
			return int(row[i] >> 4)
		}
		return int(row[i] & 0x0F)
	}
	if xx >= len(row) {
		return 0
	}
	return int(row[xx])
}
