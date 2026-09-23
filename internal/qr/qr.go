// Package qr renders a short string as a QR Code symbol (ISO/IEC 18004)
// in byte mode at error correction level M.
//
// It is here for one job: the enrolment code an authenticator reads,
// where the payload is a short ASCII `otpauth://` URI and the symbol is
// looked at once. So it does that job and says so — one mode, one
// error correction level, no kanji, no structured append, no micro QR.
// Everything it does support it does completely: every version from 1
// to 40, the full mask selection by the standard's penalty rules, and
// the encoding verified symbol for symbol against an independent
// implementation at every version (see the tests).
//
// Level M corrects about fifteen per cent of the symbol, which is what
// authenticator applications have read off screens for years: high
// enough to survive a photograph of a monitor, low enough that the
// symbol stays small.
package qr

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
)

// ErrTooLong says the text does not fit in any symbol. At level M the
// largest holds 2331 bytes, which nothing this is for comes close to.
var ErrTooLong = errors.New("qr: too long for a symbol")

// ErrEmpty says there is nothing to encode. A symbol of nothing scans
// as an empty string, which is worse than no symbol: it looks like it
// worked.
var ErrEmpty = errors.New("qr: nothing to encode")

const maxVersion = 40

// The two published numbers per version at level M (ISO/IEC 18004
// tables 13 to 22): how many error correction codewords each block
// carries, and how many blocks the symbol is split into. Everything
// else — the total capacity, how long each block is, which blocks are
// one codeword longer — follows from these and from the layout, so
// they are the only table here.
var (
	ecPerBlock = [maxVersion + 1]int{0,
		10, 16, 26, 18, 24, 16, 18, 22, 22, 26,
		30, 22, 22, 24, 24, 28, 28, 26, 26, 26,
		26, 28, 28, 28, 28, 28, 28, 28, 28, 28,
		28, 28, 28, 28, 28, 28, 28, 28, 28, 28}
	blockCount = [maxVersion + 1]int{0,
		1, 1, 1, 2, 2, 4, 4, 4, 5, 5,
		5, 8, 9, 9, 10, 10, 11, 13, 14, 16,
		17, 17, 18, 20, 21, 23, 25, 26, 28, 29,
		31, 33, 35, 37, 38, 40, 43, 45, 47, 49}
)

// Code is one symbol: a square of modules, dark or light.
type Code struct {
	// Version is 1 to 40 and Size is the side in modules, 4*V+17.
	Version int
	Size    int
	dark    []bool
}

// Dark says whether the module at x, y is dark. Anything outside the
// symbol is light, which is what the quiet zone is.
func (c *Code) Dark(x, y int) bool {
	if x < 0 || y < 0 || x >= c.Size || y >= c.Size {
		return false
	}
	return c.dark[y*c.Size+x]
}

// Encode renders text as the smallest symbol that holds it.
func Encode(text string) (*Code, error) {
	data := []byte(text)
	if len(data) == 0 {
		return nil, ErrEmpty
	}
	version := pickVersion(len(data))
	if version == 0 {
		return nil, fmt.Errorf("%w: %d bytes", ErrTooLong, len(data))
	}
	return encodeWith(data, version, -1), nil
}

// encodeWith builds the symbol. A mask below zero means choose one by
// the standard's penalty rules, which is what Encode does; the tests
// pass a mask so that each of the eight can be checked on its own.
func encodeWith(data []byte, version, mask int) *Code {
	m := newMatrix(version)
	m.place(codewords(data, version))
	if mask < 0 {
		mask = m.bestMask()
	}
	m.applyMask(mask)
	m.drawFormat(mask)
	return &Code{Version: version, Size: m.size, dark: m.dark}
}

// pickVersion is the smallest symbol the text fits in.
func pickVersion(n int) int {
	for v := 1; v <= maxVersion; v++ {
		if bitsNeeded(n, v) <= dataCodewords(v)*8 {
			return v
		}
	}
	return 0
}

// bitsNeeded is what the text costs in a symbol of this version: the
// mode indicator, the character count whose width changes at version
// 10, and the text itself.
func bitsNeeded(n, version int) int {
	return 4 + countBits(version) + 8*n
}

func countBits(version int) int {
	if version < 10 {
		return 8
	}
	return 16
}

// totalCodewords counts what the symbol has room for by looking at the
// layout rather than at a second table: every module that is not part
// of a function pattern carries data, eight to the codeword, and what
// is left over is the remainder bits the standard leaves at zero.
func totalCodewords(version int) int {
	m := newMatrix(version)
	free := 0
	for _, fn := range m.fn {
		if !fn {
			free++
		}
	}
	return free / 8
}

func dataCodewords(version int) int {
	return totalCodewords(version) - ecPerBlock[version]*blockCount[version]
}

// codewords turns the text into the symbol's codewords: the encoded
// data, padded, split into blocks, each block's error correction
// computed, and the lot interleaved the way the standard reads it back.
func codewords(data []byte, version int) []byte {
	total, blocks, ec := totalCodewords(version), blockCount[version], ecPerBlock[version]
	want := total - ec*blocks

	var b bitWriter
	b.write(4, 4) // byte mode
	b.write(len(data), countBits(version))
	for _, c := range data {
		b.write(int(c), 8)
	}
	// The terminator is up to four zero bits, or fewer at the very end
	// of the capacity.
	for i := 0; i < 4 && len(b.bits) < want*8; i++ {
		b.write(0, 1)
	}
	for len(b.bits)%8 != 0 {
		b.write(0, 1)
	}
	pad := []byte{0xEC, 0x11}
	out := b.bytes()
	for i := 0; len(out) < want; i++ {
		out = append(out, pad[i%2])
	}

	// The blocks are as equal as they can be: the remainder goes one
	// codeword at a time to the blocks at the end.
	short := want / blocks
	long := want % blocks
	dataBlocks := make([][]byte, blocks)
	ecBlocks := make([][]byte, blocks)
	gen := generator(ec)
	at := 0
	for i := range dataBlocks {
		n := short
		if i >= blocks-long {
			n++
		}
		dataBlocks[i] = out[at : at+n]
		at += n
		ecBlocks[i] = remainder(dataBlocks[i], gen)
	}

	res := make([]byte, 0, total)
	for i := 0; i < short+1; i++ {
		for _, blk := range dataBlocks {
			if i < len(blk) {
				res = append(res, blk[i])
			}
		}
	}
	for i := 0; i < ec; i++ {
		for _, blk := range ecBlocks {
			res = append(res, blk[i])
		}
	}
	return res
}

// bitWriter collects bits most significant first. The values it takes
// are small and never negative -- a mode indicator, a length, a byte --
// so they are ints rather than a width that has to be converted at
// every call.
type bitWriter struct{ bits []bool }

func (w *bitWriter) write(v, n int) {
	for i := n - 1; i >= 0; i-- {
		w.bits = append(w.bits, v>>i&1 == 1)
	}
}

func (w *bitWriter) bytes() []byte {
	out := make([]byte, (len(w.bits)+7)/8)
	for i, b := range w.bits {
		if b {
			out[i/8] |= 1 << (7 - i%8)
		}
	}
	return out
}

// ---- PNG and data URI ----

// PNG draws the symbol with each module scale pixels square and a
// quiet zone of quiet modules on every side. The standard asks for a
// quiet zone of four; without one a reader that finds the symbol at
// all is doing it by luck.
func (c *Code) PNG(scale, quiet int) ([]byte, error) {
	if scale < 1 {
		scale = 1
	}
	if quiet < 0 {
		quiet = 0
	}
	side := (c.Size + 2*quiet) * scale
	img := image.NewPaletted(image.Rect(0, 0, side, side), color.Palette{
		color.RGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF},
		color.RGBA{A: 0xFF},
	})
	for y := 0; y < side; y++ {
		for x := 0; x < side; x++ {
			if c.Dark(x/scale-quiet, y/scale-quiet) {
				img.SetColorIndex(x, y, 1)
			}
		}
	}
	var buf bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.BestCompression}
	if err := enc.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DataURI is the PNG as a `data:` URI, which is how a page shows a
// symbol without fetching anything.
func (c *Code) DataURI(scale, quiet int) (string, error) {
	b, err := c.PNG(scale, quiet)
	if err != nil {
		return "", err
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(b), nil
}
