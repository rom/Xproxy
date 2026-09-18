package geoip

import (
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/rom/xproxy/internal/config"
)

// mmdbWriter builds a small MaxMind DB file (record size 24, IPv6 tree
// with IPv4 under ::/96) for tests, so the reader is checked against the
// real format rather than against itself.
type mmdbWriter struct {
	nodes [][2]uint32 // records: 0 = unset (filled as "no data" at the end)
	data  []byte
	dataO map[string]int
}

type mmdbEntry struct {
	prefix  string
	country string
}

func buildMMDB(t *testing.T, entries []mmdbEntry) []byte {
	t.Helper()
	w := &mmdbWriter{dataO: map[string]int{}}
	w.nodes = append(w.nodes, [2]uint32{})
	const dataFlag = 1 << 31 // marks a record as a data offset during construction
	for _, e := range entries {
		p := netip.MustParsePrefix(e.prefix)
		bits := p.Bits()
		addr := p.Addr()
		var key [16]byte
		if addr.Is4() {
			a := addr.As4()
			copy(key[12:], a[:])
			bits += 96
		} else {
			key = addr.As16()
		}
		node := uint32(0)
		for i := 0; i < bits; i++ {
			bit := (key[i/8] >> (7 - uint(i%8))) & 1
			if i == bits-1 {
				w.nodes[node][bit] = dataFlag | uint32(w.dataOffset(e.country)) //nolint:gosec // test
				break
			}
			next := w.nodes[node][bit]
			if next == 0 || next&dataFlag != 0 {
				// New node; when a shorter prefix already answered here,
				// both children inherit its data (a longer prefix then
				// overrides one side), as real databases are built.
				w.nodes = append(w.nodes, [2]uint32{next, next})
				next = uint32(len(w.nodes) - 1) //nolint:gosec // test
				w.nodes[node][bit] = next
			}
			node = next
		}
	}
	nodeCount := uint32(len(w.nodes)) //nolint:gosec // test
	var out []byte
	put24 := func(v uint32) { out = append(out, byte(v>>16), byte(v>>8), byte(v)) }
	for _, n := range w.nodes {
		for _, rec := range n {
			switch {
			case rec == 0:
				put24(nodeCount)
			case rec&dataFlag != 0:
				put24(nodeCount + 16 + (rec &^ dataFlag))
			default:
				put24(rec)
			}
		}
	}
	out = append(out, make([]byte, 16)...)
	out = append(out, w.data...)
	out = append(out, []byte(metadataMarker)...)
	meta := encMap(map[string][]byte{
		"node_count":                  encUint(6, uint64(nodeCount)),
		"record_size":                 encUint(5, 24),
		"ip_version":                  encUint(5, 6),
		"database_type":               encString("Test-Country"),
		"binary_format_major_version": encUint(5, 2),
		"binary_format_minor_version": encUint(5, 0),
		"build_epoch":                 encUint(9, 1700000000),
		"languages":                   encArray([][]byte{encString("en")}),
		"description":                 encMap(map[string][]byte{"en": encString("test")}),
	})
	return append(out, meta...)
}

func (w *mmdbWriter) dataOffset(country string) int {
	if o, ok := w.dataO[country]; ok {
		return o
	}
	o := len(w.data)
	w.data = append(w.data, encMap(map[string][]byte{
		"country": encMap(map[string][]byte{"iso_code": encString(country), "geoname_id": encUint(6, 12345)}),
	})...)
	w.dataO[country] = o
	return o
}

func ctrl(typ, size int) []byte {
	var b []byte
	if typ >= 8 {
		b = append(b, byte(0)) // extended
	} else {
		b = append(b, byte(typ<<5))
	}
	switch {
	case size < 29:
		b[0] |= byte(size)
	case size < 285:
		b[0] |= 29
		b = append(b, byte(size-29))
	default:
		b[0] |= 30
		b = append(b, byte((size-285)>>8), byte(size-285))
	}
	if typ >= 8 {
		b = append(b[:1], append([]byte{byte(typ - 7)}, b[1:]...)...)
	}
	return b
}

func encString(s string) []byte { return append(ctrl(2, len(s)), []byte(s)...) }

func encUint(typ int, v uint64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	i := 0
	for i < 8 && buf[i] == 0 {
		i++
	}
	return append(ctrl(typ, 8-i), buf[i:]...)
}

func encMap(m map[string][]byte) []byte {
	b := ctrl(7, len(m))
	for k, v := range m {
		b = append(b, encString(k)...)
		b = append(b, v...)
	}
	return b
}

func encArray(items [][]byte) []byte {
	b := ctrl(11, len(items))
	for _, it := range items {
		b = append(b, it...)
	}
	return b
}

func TestMMDB(t *testing.T) {
	b := buildMMDB(t, []mmdbEntry{{"192.0.2.0/24", "SE"}, {"198.51.100.0/24", "NO"}, {"198.51.100.128/25", "FI"}, {"2001:db8::/32", "DE"}})
	m, err := ParseMMDB(b)
	if err != nil {
		t.Fatal(err)
	}
	if m.Type() != "Test-Country" || m.BuildEpoch() != 1700000000 {
		t.Fatalf("metadata: %s %d", m.Type(), m.BuildEpoch())
	}
	cases := map[string]string{
		"192.0.2.7":        "SE",
		"192.0.3.1":        "",
		"198.51.100.5":     "NO",
		"198.51.100.200":   "FI", // longest prefix
		"2001:db8::1":      "DE",
		"2001:db9::1":      "",
		"::ffff:192.0.2.9": "SE", // mapped IPv4
		"10.0.0.1":         "",
	}
	for in, want := range cases {
		if got := m.Country(netip.MustParseAddr(in)); got != want {
			t.Errorf("Country(%s) = %q, want %q", in, got, want)
		}
	}
	rec, err := m.Lookup(netip.MustParseAddr("192.0.2.1"))
	if err != nil || rec["country"].(map[string]any)["geoname_id"] != uint64(12345) {
		t.Fatalf("record %v %v", rec, err)
	}
	// Corruption is an error, not a panic.
	for _, cut := range []int{len(b) - 5, len(b) / 2, 10} {
		if _, err := ParseMMDB(b[:cut]); err == nil {
			t.Errorf("truncated at %d accepted", cut)
		}
	}
	if _, err := ParseMMDB([]byte("nonsense")); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestCSVAndDB(t *testing.T) {
	dir := t.TempDir()
	csv := filepath.Join(dir, "geo.csv")
	if err := os.WriteFile(csv, []byte("network,country\n192.0.2.0/24,se\n192.0.2.128/25,\"NO\"\n2001:db8::/32,DE\n# comment\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := Open(&config.GeoIP{CSV: csv})
	if err != nil {
		t.Fatal(err)
	}
	if db.Country(netip.MustParseAddr("192.0.2.5")) != "SE" || db.Country(netip.MustParseAddr("192.0.2.200")) != "NO" || db.Country(netip.MustParseAddr("2001:db8::5")) != "DE" || db.Country(netip.MustParseAddr("9.9.9.9")) != "" {
		t.Fatal("csv lookups")
	}
	db.Country(netip.MustParseAddr("192.0.2.5")) // cached
	st := db.Status()
	if st.Kind != "csv" || st.Prefixes != 3 || st.Lookups != 5 || st.Unknown != 1 || st.Cached != 4 {
		t.Fatalf("status %+v", st)
	}
	bad := filepath.Join(dir, "bad.csv")
	_ = os.WriteFile(bad, []byte("192.0.2.0/24,SWE\n"), 0o600)
	if _, err := Open(&config.GeoIP{CSV: bad}); err == nil {
		t.Fatal("bad country code accepted")
	}
	_ = os.WriteFile(bad, []byte("network,country\n"), 0o600)
	if _, err := Open(&config.GeoIP{CSV: bad}); err == nil {
		t.Fatal("empty table accepted")
	}
	mm := filepath.Join(dir, "geo.mmdb")
	_ = os.WriteFile(mm, buildMMDB(t, []mmdbEntry{{"192.0.2.0/24", "SE"}}), 0o600)
	db, err = Open(&config.GeoIP{Database: mm})
	if err != nil {
		t.Fatal(err)
	}
	if db.Country(netip.MustParseAddr("192.0.2.1")) != "SE" || db.Status().Kind != "mmdb:Test-Country" {
		t.Fatal("mmdb through Open")
	}
	if _, err := Open(&config.GeoIP{}); err == nil {
		t.Fatal("empty config accepted")
	}
}

func TestCacheBound(t *testing.T) {
	dir := t.TempDir()
	csv := filepath.Join(dir, "geo.csv")
	_ = os.WriteFile(csv, []byte("10.0.0.0/8,SE\n"), 0o600)
	db, err := Open(&config.GeoIP{CSV: csv})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < cacheSize+1000; i++ {
		db.Country(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}))
	}
	if n := db.Status().Cached; n > cacheSize {
		t.Fatalf("cache grew to %d", n)
	}
}
