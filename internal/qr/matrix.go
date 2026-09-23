package qr

// The symbol's layout: the patterns a reader finds the symbol by, where
// the data goes between them, and the mask that keeps the data from
// looking like those patterns.

type matrix struct {
	size int
	dark []bool
	// fn marks a module that belongs to a function pattern or to the
	// format and version areas. Data goes everywhere else, and the mask
	// applies to nothing else.
	fn []bool
}

// newMatrix draws every function pattern of a version and reserves the
// format and version areas, leaving the data modules free.
func newMatrix(version int) *matrix {
	size := 4*version + 17
	m := &matrix{size: size, dark: make([]bool, size*size), fn: make([]bool, size*size)}
	for _, p := range [][2]int{{0, 0}, {size - 7, 0}, {0, size - 7}} {
		m.finder(p[0], p[1])
	}
	for i := 8; i < size-8; i++ {
		m.function(i, 6, i%2 == 0)
		m.function(6, i, i%2 == 0)
	}
	centres := alignCentres(version)
	for _, ax := range centres {
		for _, ay := range centres {
			// The three corners hold finders instead.
			if (ax == 6 && ay == 6) || (ax == 6 && ay == size-7) || (ax == size-7 && ay == 6) {
				continue
			}
			m.alignment(ax, ay)
		}
	}
	m.reserveFormat(version)
	return m
}

func (m *matrix) at(x, y int) int { return y*m.size + x }

// function draws a module of a function pattern: it is set and it is
// out of the data's way.
func (m *matrix) function(x, y int, dark bool) {
	if x < 0 || y < 0 || x >= m.size || y >= m.size {
		return
	}
	m.dark[m.at(x, y)] = dark
	m.fn[m.at(x, y)] = true
}

// finder draws one of the three squares a reader locks onto, with the
// light separator around it.
func (m *matrix) finder(x, y int) {
	for dy := -1; dy <= 7; dy++ {
		for dx := -1; dx <= 7; dx++ {
			d := max(abs(dx-3), abs(dy-3))
			m.function(x+dx, y+dy, d != 2 && d <= 3)
		}
	}
}

// alignment draws one of the smaller squares that hold a large symbol
// straight.
func (m *matrix) alignment(x, y int) {
	for dy := -2; dy <= 2; dy++ {
		for dx := -2; dx <= 2; dx++ {
			m.function(x+dx, y+dy, max(abs(dx), abs(dy)) != 1)
		}
	}
}

// alignCentres is where the alignment patterns sit: the first at 6, the
// last seven from the edge, the rest evenly spaced between them. The
// spacing is even in the standard's table for every version but 32,
// which is the one exception rather than a rule with a formula.
func alignCentres(version int) []int {
	if version == 1 {
		return nil
	}
	n := version/7 + 2
	step := 26
	if version != 32 {
		step = (version*4 + n*2 + 1) / (n*2 - 2) * 2
	}
	out := make([]int, n)
	out[0] = 6
	for i, pos := n-1, 4*version+10; i >= 1; i, pos = i-1, pos-step {
		out[i] = pos
	}
	return out
}

// reserveFormat keeps the format and version areas out of the data's
// way. What goes in them is written after the mask is chosen, because
// the format says which mask it was.
func (m *matrix) reserveFormat(version int) {
	for i := 0; i <= 8; i++ {
		if i == 6 {
			continue // the timing patterns run through here
		}
		m.function(8, i, false)
		m.function(i, 8, false)
	}
	for i := 0; i < 8; i++ {
		m.function(m.size-1-i, 8, false)
		m.function(8, m.size-1-i, false)
	}
	if version >= 7 {
		for i := 0; i < 18; i++ {
			m.function(m.size-11+i%3, i/3, false)
			m.function(i/3, m.size-11+i%3, false)
		}
	}
}

// place writes the codewords into the data modules, two columns at a
// time from the right, alternating up and down, skipping the timing
// column. Bits past the end of the data are the remainder bits, which
// stay light.
func (m *matrix) place(data []byte) {
	i := 0
	for right := m.size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5 // the timing column is not a data column
		}
		up := (m.size-1-right)%4 < 2
		for v := 0; v < m.size; v++ {
			for j := 0; j < 2; j++ {
				x := right - j
				y := v
				if up {
					y = m.size - 1 - v
				}
				if m.fn[m.at(x, y)] {
					continue
				}
				if i < len(data)*8 {
					m.dark[m.at(x, y)] = data[i/8]>>(7-i%8)&1 == 1
				}
				i++
			}
		}
	}
}

// maskAt is the eight patterns of the standard, which are chosen
// between rather than configured: one of them always breaks up whatever
// the data happened to look like.
func maskAt(mask, x, y int) bool {
	switch mask {
	case 0:
		return (x+y)%2 == 0
	case 1:
		return y%2 == 0
	case 2:
		return x%3 == 0
	case 3:
		return (x+y)%3 == 0
	case 4:
		return (y/2+x/3)%2 == 0
	case 5:
		return x*y%2+x*y%3 == 0
	case 6:
		return (x*y%2+x*y%3)%2 == 0
	default:
		return ((x+y)%2+x*y%3)%2 == 0
	}
}

// applyMask flips the data modules the mask names. It is its own
// inverse, so the same call undoes it.
func (m *matrix) applyMask(mask int) {
	for y := 0; y < m.size; y++ {
		for x := 0; x < m.size; x++ {
			if !m.fn[m.at(x, y)] && maskAt(mask, x, y) {
				m.dark[m.at(x, y)] = !m.dark[m.at(x, y)]
			}
		}
	}
}

// bestMask tries all eight and keeps the one the standard's penalty
// rules like most. The format bits are written each time because rule
// three counts patterns that run through them.
func (m *matrix) bestMask() int {
	best, bestScore := 0, -1
	for mask := 0; mask < 8; mask++ {
		m.applyMask(mask)
		m.drawFormat(mask)
		if s := m.penalty(); bestScore < 0 || s < bestScore {
			best, bestScore = mask, s
		}
		m.applyMask(mask)
	}
	return best
}

// penalty is the four rules of ISO/IEC 18004 section 8.8.2: runs of one
// colour, blocks of one colour, anything that looks like a finder, and
// an imbalance between dark and light.
func (m *matrix) penalty() int {
	const (
		n1 = 3
		n2 = 3
		n3 = 40
		n4 = 10
	)
	score := 0
	dark := 0

	// Rules one and three, over every row and every column.
	for i := 0; i < m.size; i++ {
		for _, byRow := range []bool{true, false} {
			run, runDark := 0, false
			var window int
			for j := 0; j < m.size; j++ {
				x, y := j, i
				if !byRow {
					x, y = i, j
				}
				d := m.dark[m.at(x, y)]
				if byRow && d {
					dark++
				}
				if d == runDark {
					run++
					if run == 5 {
						score += n1
					} else if run > 5 {
						score++
					}
				} else {
					runDark, run = d, 1
				}
				window = window << 1 & 0x7FF
				if d {
					window |= 1
				}
				if j >= 10 && (window == 0x05D || window == 0x5D0) {
					score += n3
				}
			}
		}
	}

	// Rule two: every two by two square of one colour.
	for y := 0; y < m.size-1; y++ {
		for x := 0; x < m.size-1; x++ {
			a, b := m.dark[m.at(x, y)], m.dark[m.at(x+1, y)]
			c, d := m.dark[m.at(x, y+1)], m.dark[m.at(x+1, y+1)]
			if a == b && b == c && c == d {
				score += n2
			}
		}
	}

	// Rule four: how far the proportion of dark modules is from half,
	// in steps of five per cent.
	total := m.size * m.size
	k := abs(dark*20-total*10) / total
	return score + k*n4
}

// drawFormat writes the format information — the error correction level
// and the mask — in the two places it appears, and the one module that
// is always dark.
func (m *matrix) drawFormat(mask int) {
	// Level M is 0b00. The fifteen bits are a BCH(15, 5) code, then
	// masked so that a symbol of all light modules is not a valid
	// format.
	data := mask // 0<<3 | mask
	rem := data
	for i := 0; i < 10; i++ {
		rem = rem<<1 ^ rem>>9*0x537
	}
	bits := (data<<10 | rem&0x3FF) ^ 0x5412

	for i := 0; i <= 5; i++ {
		m.function(8, i, bit(bits, i))
	}
	m.function(8, 7, bit(bits, 6))
	m.function(8, 8, bit(bits, 7))
	m.function(7, 8, bit(bits, 8))
	for i := 9; i < 15; i++ {
		m.function(14-i, 8, bit(bits, i))
	}
	for i := 0; i < 8; i++ {
		m.function(m.size-1-i, 8, bit(bits, i))
	}
	for i := 8; i < 15; i++ {
		m.function(8, m.size-15+i, bit(bits, i))
	}
	m.function(8, m.size-8, true)

	version := (m.size - 17) / 4
	if version < 7 {
		return
	}
	// The version is a BCH(18, 6) code, in two copies beside the
	// other two finders.
	rem = version
	for i := 0; i < 12; i++ {
		rem = rem<<1 ^ rem>>11*0x1F25
	}
	vbits := version<<12 | rem&0xFFF
	for i := 0; i < 18; i++ {
		b := bit(vbits, i)
		m.function(m.size-11+i%3, i/3, b)
		m.function(i/3, m.size-11+i%3, b)
	}
}

func bit(v, i int) bool { return v>>i&1 == 1 }

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
