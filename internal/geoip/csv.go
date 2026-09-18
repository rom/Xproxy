package geoip

import (
	"bufio"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
)

// Table is a prefix to country table loaded from CSV lines of the form
// "network,country" (an IPv4 or IPv6 CIDR and an ISO 3166-1 alpha-2
// code). Longest prefix wins.
type Table struct {
	byLen [129][]entry // prefixes grouped by length, each sorted by address
	count int
}

type entry struct {
	addr    netip.Addr
	country string
}

// OpenCSV loads a table from a file.
func OpenCSV(path string) (*Table, error) {
	f, err := os.Open(path) //nolint:gosec // operator supplied path
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	t := &Table{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 64<<10)
	line := 0
	for sc.Scan() {
		line++
		s := strings.TrimSpace(sc.Text())
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		net, country, ok := strings.Cut(s, ",")
		if !ok {
			return nil, fmt.Errorf("%s:%d: expected network,country", path, line)
		}
		p, err := netip.ParsePrefix(strings.TrimSpace(net))
		if err != nil {
			if line == 1 { // header row
				continue
			}
			return nil, fmt.Errorf("%s:%d: %w", path, line, err)
		}
		country = strings.ToUpper(strings.TrimSpace(strings.Trim(country, "\"")))
		if len(country) != 2 {
			return nil, fmt.Errorf("%s:%d: country %q is not a two letter code", path, line, country)
		}
		p = p.Masked()
		bits := p.Bits()
		if p.Addr().Is4() {
			bits += 96 // IPv4 lives at ::ffff:0:0/96 after Unmap-style normalisation below
		}
		t.byLen[bits] = append(t.byLen[bits], entry{addr: to16(p.Addr()), country: country})
		t.count++
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if t.count == 0 {
		return nil, errors.New("geoip csv: no entries")
	}
	for i := range t.byLen {
		sort.Slice(t.byLen[i], func(a, b int) bool { return t.byLen[i][a].addr.Less(t.byLen[i][b].addr) })
	}
	return t, nil
}

func to16(a netip.Addr) netip.Addr {
	if a.Is4() {
		return netip.AddrFrom16(a.As16())
	}
	return a
}

// Len returns the number of prefixes.
func (t *Table) Len() int { return t.count }

// Country returns the country of the longest matching prefix, or "".
func (t *Table) Country(addr netip.Addr) string {
	a := to16(addr.Unmap())
	for bits := 128; bits >= 0; bits-- {
		es := t.byLen[bits]
		if len(es) == 0 {
			continue
		}
		p := netip.PrefixFrom(a, bits).Masked()
		i := sort.Search(len(es), func(i int) bool { return !es[i].addr.Less(p.Addr()) })
		if i < len(es) && es[i].addr == p.Addr() {
			return es[i].country
		}
	}
	return ""
}
