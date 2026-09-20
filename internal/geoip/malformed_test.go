package geoip

import (
	"bytes"
	"encoding/binary"
	"math"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A GeoIP database is a binary format most deployments fetch from a
// third party and refresh on a schedule, and this reader parses all of
// it — the search tree, the metadata and the records — at start-up and
// again on every reload. A file that is truncated, corrupted in
// transit, or built by somebody who would like the proxy to stop must
// produce an error, not a panic and not an hour of work.

// TestTruncationAtEveryLength feeds ParseMMDB every prefix of a valid
// database. A prefix is what a partial download and a full disk look
// like.
func TestTruncationAtEveryLength(t *testing.T) {
	full := buildMMDB(t, []mmdbEntry{{"192.0.2.0/24", "SE"}, {"2001:db8::/32", "DE"}})
	if _, err := ParseMMDB(full); err != nil {
		t.Fatalf("the whole database: %v", err)
	}
	for i := 0; i < len(full); i++ {
		i := i
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on a %d byte prefix: %v", i, r)
				}
			}()
			db, err := ParseMMDB(full[:i])
			if err != nil {
				return
			}
			// A prefix that parses must still answer safely.
			_ = db.Country(netip.MustParseAddr("192.0.2.1"))
			_ = db.Country(netip.MustParseAddr("2001:db8::1"))
		}()
	}
}

// TestSingleByteCorruption changes one byte at a time anywhere in the
// file and then looks an address up. The tree walk indexes into the
// file from values the file itself carries, which is exactly the shape
// that reads out of bounds when one of them is wrong.
func TestSingleByteCorruption(t *testing.T) {
	full := buildMMDB(t, []mmdbEntry{
		{"192.0.2.0/24", "SE"}, {"198.51.100.0/24", "NO"}, {"2001:db8::/32", "DE"},
	})
	addrs := []netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("198.51.100.7"),
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("::1"),
	}
	r := rand.New(rand.NewPCG(7, 11))
	for n := 0; n < 4000; n++ {
		b := append([]byte(nil), full...)
		i := r.IntN(len(b))
		b[i] ^= byte(1 << r.IntN(8))
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					t.Fatalf("panic with byte %d flipped: %v", i, rec)
				}
			}()
			db, err := ParseMMDB(b)
			if err != nil {
				return
			}
			for _, a := range addrs {
				if c := db.Country(a); len(c) > 64 {
					t.Fatalf("byte %d flipped produced a %d character country", i, len(c))
				}
			}
		}()
	}
}

// TestMetadataRejections covers the metadata fields the reader must not
// believe. Each of these is a number the file supplies and the reader
// then uses to index into the file.
func TestMetadataRejections(t *testing.T) {
	full := buildMMDB(t, []mmdbEntry{{"192.0.2.0/24", "SE"}})
	marker := bytes.LastIndex(full, []byte(metadataMarker))
	if marker < 0 {
		t.Fatal("the test database has no metadata marker")
	}

	// setUint rewrites a uint field in the metadata map by finding its
	// key and replacing the value that follows.
	setUint := func(b []byte, key string, size int, value uint64) []byte {
		out := append([]byte(nil), b...)
		needle := append([]byte{byte(0x40 | len(key))}, key...) // short string
		at := bytes.Index(out[marker:], needle)
		if at < 0 {
			t.Fatalf("key %q not found in the metadata", key)
		}
		at += marker + len(needle)
		// The value is a uint16 (type 5) or uint32 (type 6).
		ctrl := out[at]
		typ := ctrl >> 5
		if typ != 5 && typ != 6 {
			t.Fatalf("key %q has type %d, not an integer", key, typ)
		}
		n := int(ctrl & 0x1f)
		enc := make([]byte, 8)
		binary.BigEndian.PutUint64(enc, value)
		enc = enc[8-size:]
		replacement := append([]byte{typ<<5 | byte(len(enc))}, enc...)
		rest := append([]byte(nil), out[at+1+n:]...)
		return append(append(out[:at], replacement...), rest...)
	}

	cases := []struct {
		name  string
		build func() []byte
	}{
		{"record size 0", func() []byte { return setUint(full, "record_size", 1, 0) }},
		{"record size 7", func() []byte { return setUint(full, "record_size", 1, 7) }},
		{"record size 64", func() []byte { return setUint(full, "record_size", 1, 64) }},
		{"ip version 0", func() []byte { return setUint(full, "ip_version", 1, 0) }},
		{"ip version 5", func() []byte { return setUint(full, "ip_version", 1, 5) }},
		{"node count 0", func() []byte { return setUint(full, "node_count", 1, 0) }},
		{"node count enormous", func() []byte { return setUint(full, "node_count", 4, 0xffffffff) }},
		{"node count past the file", func() []byte { return setUint(full, "node_count", 4, uint64(len(full))) }},
		{"no marker", func() []byte { return full[:marker] }},
		{"marker only", func() []byte { return []byte(metadataMarker) }},
		{"metadata is a string", func() []byte {
			return append(append([]byte(nil), full[:marker]...), append([]byte(metadataMarker), 0x43, 'a', 'b', 'c')...)
		}},
		{"empty file", func() []byte { return nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic: %v", r)
				}
			}()
			b := tc.build()
			db, err := ParseMMDB(b)
			if err != nil {
				return
			}
			// If it parsed, it must at least not walk out of the file.
			_ = db.Country(netip.MustParseAddr("192.0.2.1"))
			t.Logf("%s parsed; the lookup was safe", tc.name)
		})
	}
}

// TestLookupsOnEveryAddressShape covers the addresses a lookup can be
// asked about, including the ones that are not really addresses.
func TestLookupsOnEveryAddressShape(t *testing.T) {
	v6 := mustParse(t, buildMMDB(t, []mmdbEntry{{"192.0.2.0/24", "SE"}, {"2001:db8::/32", "DE"}}))
	addrs := []string{
		"192.0.2.1", "192.0.2.255", "192.0.2.0", "192.0.1.255", "192.0.3.0",
		"0.0.0.0", "255.255.255.255", "127.0.0.1",
		"::", "::1", "2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", "2001:db9::",
		"::ffff:192.0.2.1", "::ffff:10.0.0.1", "fe80::1", "ff02::1",
	}
	for _, s := range addrs {
		a := netip.MustParseAddr(s)
		if _, err := v6.Lookup(a); err != nil {
			t.Logf("%s: %v", s, err)
		}
		c := v6.Country(a)
		if len(c) > 8 {
			t.Fatalf("%s produced the country %q", s, c)
		}
	}
	// An IPv4-mapped IPv6 address is the same client as the IPv4 one:
	// a database that answered differently would put one client in two
	// countries.
	if a, b := v6.Country(netip.MustParseAddr("192.0.2.1")), v6.Country(netip.MustParseAddr("::ffff:192.0.2.1")); a != b {
		t.Fatalf("192.0.2.1 is %q and ::ffff:192.0.2.1 is %q", a, b)
	}
	// The zero address is not a crash.
	if c := v6.Country(netip.Addr{}); c != "" {
		t.Fatalf("the zero address is in %q", c)
	}
}

// mustParse parses a database the test built.
func mustParse(t *testing.T, b []byte) *MMDB {
	t.Helper()
	db, err := ParseMMDB(b)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

// TestDecoderTypes walks every type the data format defines, with the
// values at the edges of each. The decoder is reached from a record
// lookup, so everything here is under the control of whoever built the
// file.
func TestDecoderTypes(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want any
	}{
		{"empty string", []byte{0x40}, ""},
		{"short string", []byte{0x43, 'a', 'b', 'c'}, "abc"},
		{"empty bytes", []byte{0x80}, nil},
		{"uint16 zero", []byte{0xa0}, uint64(0)},
		{"uint16", []byte{0xa2, 0x01, 0x02}, uint64(0x0102)},
		{"uint32", []byte{0xc4, 0, 0, 1, 0}, uint64(256)},
		{"int32 negative", []byte{0x04, 0x01, 0xff, 0xff, 0xff, 0xff}, int32(-1)},
		{"boolean false", []byte{0x00, 0x07}, false},
		{"boolean true", []byte{0x01, 0x07}, true},
		{"empty array", []byte{0x00, 0x04}, nil},
		{"empty map", []byte{0xe0}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := newDecoder(tc.in)
			v, _, err := d.decode(0, 0)
			if err != nil {
				t.Fatalf("%v: %v", tc.in, err)
			}
			if tc.want != nil && v != tc.want {
				t.Fatalf("decoded %#v, want %#v", v, tc.want)
			}
		})
	}

	// A double and a float come back as float64.
	double := append([]byte{0x68}, make([]byte, 8)...)
	binary.BigEndian.PutUint64(double[1:], math.Float64bits(1.5))
	if v, _, err := newDecoder(double).decode(0, 0); err != nil || v != 1.5 {
		t.Fatalf("double: %v %v", v, err)
	}
	f := append([]byte{0x04, 0x08}, make([]byte, 4)...)
	binary.BigEndian.PutUint32(f[2:], math.Float32bits(2.5))
	if v, _, err := newDecoder(f).decode(0, 0); err != nil || v != 2.5 {
		t.Fatalf("float: %v %v", v, err)
	}
}

// TestDecoderRejections covers the values a decoder must refuse. Each
// is a handful of bytes that asks for something the file cannot back.
func TestDecoderRejections(t *testing.T) {
	cases := map[string][]byte{
		"empty input":             {},
		"truncated string":        {0x45, 'a', 'b'},
		"truncated bytes":         {0x85, 'a'},
		"bad double":              {0x64, 0, 0, 0, 0},
		"bad float":               {0x03, 0x08, 0, 0},
		"integer too wide":        {0xa9, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		"uint128 too wide":        {0x02, 0x0a, 1},
		"int32 too wide":          {0x05, 0x01, 1, 2, 3, 4, 5},
		"truncated size 29":       {0x5d},
		"truncated size 30":       {0x5e, 0x01},
		"truncated size 31":       {0x5f, 0x01, 0x02},
		"truncated extended":      {0x00},
		"truncated pointer":       {0x28},
		"pointer past the end":    {0x27, 0xff},
		"unknown type":            {0x03, 0x40},
		"map key is not string":   {0xe1, 0xa1, 0x01, 0x43, 'a', 'b', 'c'},
		"map larger than input":   {0xe5, 0x41, 'a'},
		"array larger than input": {0x05, 0x04, 0x41, 'a'},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic: %v", r)
				}
			}()
			d := newDecoder(in)
			if v, _, err := d.decode(0, 0); err == nil {
				t.Fatalf("decoded to %#v", v)
			}
		})
	}
}

// TestPointerLoop covers a record that points at itself, and two that
// point at each other. The depth limit is what ends them.
func TestPointerLoop(t *testing.T) {
	// A one-byte pointer to offset 0, at offset 0.
	self := []byte{0x20, 0x00}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, _, err := newDecoder(self).decode(0, 0); err == nil {
			t.Error("a self-referencing pointer decoded cleanly")
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("a self-referencing pointer did not come back")
	}

	// Two pointers, each naming the other's offset.
	pair := []byte{0x20, 0x02, 0x20, 0x00}
	done = make(chan struct{})
	go func() {
		defer close(done)
		if _, _, err := newDecoder(pair).decode(0, 0); err == nil {
			t.Error("a pointer cycle decoded cleanly")
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("a pointer cycle did not come back")
	}
}

// TestToUint covers the metadata number conversion, which has to take
// every integer type the format can carry and refuse the ones that
// cannot be a count.
func TestToUint(t *testing.T) {
	cases := []struct {
		in   any
		want uint64
	}{
		{uint64(7), 7},
		{uint32(7), 7},
		{uint16(7), 7},
		{int32(7), 7},
		{int32(-1), 0},
		{float64(7), 7},
		{float64(-1), 0},
		{float64(math.MaxUint32 + 1), 0},
		{math.NaN(), 0},
		{math.Inf(1), 0},
		{math.Inf(-1), 0},
		{"7", 0},
		{nil, 0},
		{true, 0},
		{[]any{7}, 0},
	}
	for _, tc := range cases {
		if got := toUint(tc.in); got != tc.want {
			t.Errorf("toUint(%#v) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// TestOpenMMDB covers the file-reading half: a path that is not there,
// one that is a directory, and one whose contents are not a database.
func TestOpenMMDB(t *testing.T) {
	dir := t.TempDir()
	if _, err := OpenMMDB(filepath.Join(dir, "absent.mmdb")); err == nil {
		t.Fatal("a missing database was opened")
	}
	if _, err := OpenMMDB(dir); err == nil {
		t.Fatal("a directory was opened as a database")
	}
	notADB := filepath.Join(dir, "not.mmdb")
	if err := os.WriteFile(notADB, []byte(strings.Repeat("not a database\n", 100)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenMMDB(notADB); err == nil {
		t.Fatal("a text file was opened as a database")
	}
	good := filepath.Join(dir, "good.mmdb")
	if err := os.WriteFile(good, buildMMDB(t, []mmdbEntry{{"192.0.2.0/24", "SE"}}), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := OpenMMDB(good)
	if err != nil {
		t.Fatal(err)
	}
	if db.Country(netip.MustParseAddr("192.0.2.1")) != "SE" {
		t.Fatal("the control database does not answer")
	}
	if db.Type() == "" || db.BuildEpoch() == 0 {
		t.Fatalf("metadata: type %q epoch %d", db.Type(), db.BuildEpoch())
	}
}

// TestConcurrentLookups reads one database from many goroutines. It is
// opened once per generation and every request on every listener asks
// it for a country.
func TestConcurrentLookups(t *testing.T) {
	db := mustParse(t, buildMMDB(t, []mmdbEntry{
		{"192.0.2.0/24", "SE"}, {"198.51.100.0/24", "NO"}, {"2001:db8::/32", "DE"},
	}))
	addrs := []netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("198.51.100.1"),
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("10.0.0.1"),
	}
	want := make([]string, len(addrs))
	for i, a := range addrs {
		want[i] = db.Country(a)
	}
	done := make(chan string, 64)
	for i := 0; i < 64; i++ {
		go func(i int) {
			for j := range addrs {
				if got := db.Country(addrs[j]); got != want[j] {
					done <- "mismatch"
					return
				}
			}
			done <- ""
		}(i)
	}
	for i := 0; i < 64; i++ {
		if msg := <-done; msg != "" {
			t.Fatalf("goroutine %d: %s", i, msg)
		}
	}
}
