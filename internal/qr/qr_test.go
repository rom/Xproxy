package qr

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"image/png"
	"os"
	"strconv"
	"strings"
	"testing"
)

// alphabet is the payload the reference file's symbols were made from.
const alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-._~:/?#@!$&*+,;=%"

func payload(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteByte(alphabet[i%len(alphabet)])
	}
	return b.String()
}

func grid(c *Code) string {
	var b strings.Builder
	for y := 0; y < c.Size; y++ {
		for x := 0; x < c.Size; x++ {
			if c.Dark(x, y) {
				b.WriteByte('1')
			} else {
				b.WriteByte('0')
			}
		}
	}
	return b.String()
}

// TestAgainstTheReferenceSymbols is the test that matters: every
// version from 1 to 40 and every one of the eight masks, at two
// payload sizes each, against symbols made by an implementation that
// has nothing to do with this one. A wrong block count, a misplaced
// alignment pattern, a version information word off by a bit, an error
// correction polynomial that is nearly right -- each changes the grid
// and none of them would change whether the code runs.
func TestAgainstTheReferenceSymbols(t *testing.T) {
	f, err := os.Open("testdata/reference.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	checked := 0
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 4 {
			t.Fatalf("reference line %q", line)
		}
		version, _ := strconv.Atoi(fields[0])
		mask, _ := strconv.Atoi(fields[1])
		n, _ := strconv.Atoi(fields[2])
		sum := sha256.Sum256([]byte(grid(encodeWith([]byte(payload(n)), version, mask))))
		if got := hex.EncodeToString(sum[:]); got != fields[3] {
			t.Errorf("version %d mask %d, %d bytes: %s, want %s", version, mask, n, got, fields[3])
		}
		checked++
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if checked < 600 {
		t.Fatalf("only %d reference symbols were checked", checked)
	}
}

// TestErrorCorrectionMatchesTheStandardsExample uses the worked example
// of ISO/IEC 18004 annex I: the data codewords of "01234567" in a
// version 1-M symbol, and the ten error correction codewords they
// produce. It pins the field, the generator polynomial and the
// division independently of any other implementation.
func TestErrorCorrectionMatchesTheStandardsExample(t *testing.T) {
	data, err := hex.DecodeString("10200c566180ec11ec11ec11ec11ec11")
	if err != nil {
		t.Fatal(err)
	}
	const want = "a524d4c1ed36c7872c55"
	if got := hex.EncodeToString(remainder(data, generator(10))); got != want {
		t.Fatalf("error correction codewords %s, want %s", got, want)
	}
}

// TestCapacities checks the numbers the whole encoding rests on against
// the published ones: the total codewords of a symbol, which this
// package counts from its own layout rather than from a table, and the
// data codewords left at level M once the error correction is taken
// out.
func TestCapacities(t *testing.T) {
	for _, c := range []struct{ version, total, data int }{
		{1, 26, 16}, {2, 44, 28}, {3, 70, 44}, {4, 100, 64}, {5, 134, 86},
		{6, 172, 108}, {7, 196, 124}, {10, 346, 216}, {14, 581, 365},
		{20, 1085, 669}, {32, 2465, 1541}, {40, 3706, 2334},
	} {
		if got := totalCodewords(c.version); got != c.total {
			t.Errorf("version %d: %d codewords, want %d", c.version, got, c.total)
		}
		if got := dataCodewords(c.version); got != c.data {
			t.Errorf("version %d: %d data codewords, want %d", c.version, got, c.data)
		}
	}
}

// TestVersionIsTheSmallestThatFits: a symbol one byte past a version's
// capacity is the next version up, and one byte inside it is not.
func TestVersionIsTheSmallestThatFits(t *testing.T) {
	for version := 1; version <= 39; version++ {
		fits := (dataCodewords(version)*8 - 4 - countBits(version)) / 8
		c, err := Encode(payload(fits))
		if err != nil || c.Version != version {
			t.Fatalf("%d bytes gave version %d (%v), want %d", fits, c.Version, err, version)
		}
		if c.Size != 4*version+17 {
			t.Fatalf("version %d is %d modules across", version, c.Size)
		}
		c, err = Encode(payload(fits + 1))
		if err != nil || c.Version <= version {
			t.Fatalf("%d bytes gave version %d (%v), want more than %d", fits+1, c.Version, err, version)
		}
	}
}

func TestRefusals(t *testing.T) {
	if _, err := Encode(""); !errors.Is(err, ErrEmpty) {
		t.Fatalf("empty text: %v", err)
	}
	// One byte past the largest symbol at level M.
	if _, err := Encode(payload(2332)); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Fatalf("oversize text: %v", err)
	}
	if _, err := Encode(payload(2331)); err != nil {
		t.Fatalf("the largest symbol was refused: %v", err)
	}
}

// TestFunctionPatterns checks the three things a reader looks for
// first, because a symbol that is wrong here is not found at all.
func TestFunctionPatterns(t *testing.T) {
	c, err := Encode("otpauth://totp/xproxy:alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEH&issuer=xproxy")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range [][2]int{{0, 0}, {c.Size - 7, 0}, {0, c.Size - 7}} {
		for dy := 0; dy < 7; dy++ {
			for dx := 0; dx < 7; dx++ {
				d := max(abs(dx-3), abs(dy-3))
				if want := d != 2 && d <= 3; c.Dark(p[0]+dx, p[1]+dy) != want {
					t.Fatalf("finder at %v is wrong at %d,%d", p, dx, dy)
				}
			}
		}
	}
	for i := 8; i < c.Size-8; i++ {
		if c.Dark(i, 6) != (i%2 == 0) || c.Dark(6, i) != (i%2 == 0) {
			t.Fatalf("timing pattern is wrong at %d", i)
		}
	}
	if !c.Dark(8, c.Size-8) {
		t.Fatal("the module that is always dark is not")
	}
	// Outside the symbol is light, which is what a quiet zone is made
	// of; a reader that finds a dark module there finds nothing.
	if c.Dark(-1, 0) || c.Dark(0, -1) || c.Dark(c.Size, 0) || c.Dark(0, c.Size) {
		t.Fatal("something is dark outside the symbol")
	}
}

func TestPNG(t *testing.T) {
	c, err := Encode("otpauth://totp/xproxy:alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEH")
	if err != nil {
		t.Fatal(err)
	}
	const scale, quiet = 4, 4
	raw, err := c.PNG(scale, quiet)
	if err != nil {
		t.Fatal(err)
	}
	img, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("the PNG does not decode: %v", err)
	}
	side := (c.Size + 2*quiet) * scale
	if b := img.Bounds(); b.Dx() != side || b.Dy() != side {
		t.Fatalf("image is %v, want %d square", b, side)
	}
	// Every pixel is the module under it, and the quiet zone is light.
	for _, p := range [][2]int{{0, 0}, {side - 1, side - 1}, {quiet*scale - 1, quiet * scale}} {
		if r, _, _, _ := img.At(p[0], p[1]).RGBA(); r != 0xFFFF {
			t.Fatalf("quiet zone pixel %v is not white", p)
		}
	}
	for y := 0; y < c.Size; y++ {
		for x := 0; x < c.Size; x++ {
			r, _, _, _ := img.At((x+quiet)*scale+scale/2, (y+quiet)*scale+scale/2).RGBA()
			if (r == 0) != c.Dark(x, y) {
				t.Fatalf("pixel for module %d,%d does not match", x, y)
			}
		}
	}
	// A scale and quiet zone below one and zero are nonsense a caller
	// should not have to guard against.
	if b, err := c.PNG(0, -1); err != nil || len(b) == 0 {
		t.Fatalf("degenerate scale: %v", err)
	}
	uri, err := c.DataURI(3, 4)
	if err != nil || !strings.HasPrefix(uri, "data:image/png;base64,") {
		t.Fatalf("data uri %q %v", uri[:min(40, len(uri))], err)
	}
	// It has to be small enough to sit in a page without bloating it.
	if len(uri) > 8<<10 {
		t.Fatalf("data uri is %d bytes", len(uri))
	}
}

// TestEveryMaskIsSelectable makes sure the penalty rules do not always
// answer the same thing, which would mean they are not being applied.
func TestEveryMaskIsSelectable(t *testing.T) {
	seen := map[int]bool{}
	for n := 1; n < 200; n++ {
		data := []byte(payload(n))
		version := pickVersion(len(data))
		m := newMatrix(version)
		m.place(codewords(data, version))
		seen[m.bestMask()] = true
	}
	if len(seen) < 5 {
		t.Fatalf("only masks %v were ever chosen", seen)
	}
}
