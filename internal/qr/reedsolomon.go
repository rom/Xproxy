package qr

// Reed-Solomon over GF(256) with the primitive polynomial x^8 + x^4 +
// x^3 + x^2 + 1 (0x11D), which is the field ISO/IEC 18004 specifies.
// This is the encoder only: a symbol is written here and read by
// something else, so nothing in this repository needs to correct one.

var (
	expTable [256]byte
	logTable [256]byte
)

func init() {
	x := byte(1)
	for i := 0; i < 256; i++ {
		expTable[i] = x
		if i < 255 {
			logTable[x] = byte(i)
		}
		// x *= 2 in the field: a carry out of bit seven folds back
		// through the polynomial.
		hi := x&0x80 != 0
		x <<= 1
		if hi {
			x ^= 0x1D
		}
	}
}

// mul multiplies in the field. Zero has no logarithm, so it is answered
// before the tables are touched.
func mul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return expTable[(int(logTable[a])+int(logTable[b]))%255]
}

// generator is the divisor polynomial for n error correction
// codewords: the product of (x - 2^i) for i below n, coefficients from
// the highest power down, with the leading one left implicit -- which
// is what makes the division below a loop over n bytes rather than
// n + 1.
func generator(n int) []byte {
	g := make([]byte, n)
	g[n-1] = 1
	root := byte(1)
	for i := 0; i < n; i++ {
		// Multiply by (x - root); subtraction is exclusive or here.
		for j := 0; j < n; j++ {
			g[j] = mul(g[j], root)
			if j+1 < n {
				g[j] ^= g[j+1]
			}
		}
		root = mul(root, 2)
	}
	return g
}

// remainder divides the data by the generator and returns what is left,
// which is the block's error correction codewords.
func remainder(data, gen []byte) []byte {
	out := make([]byte, len(gen))
	for _, d := range data {
		factor := d ^ out[0]
		copy(out, out[1:])
		out[len(out)-1] = 0
		for i, g := range gen {
			out[i] ^= mul(g, factor)
		}
	}
	return out
}
