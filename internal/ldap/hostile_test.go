package ldap

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"math/rand"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- the BER decoder, which reads whatever the directory sends ----

// validReply is a well-formed bind response, the shape every test below
// deforms.
func validReply() []byte {
	return node(classUniversal, tagSequence,
		integer(1),
		node(classApplication, appBindResponse, enumerated(0), str("cn=admin"), str("")),
	).encode(nil)
}

// TestParseTruncation cuts a valid message at every length. Each prefix
// must be refused without a panic; none may parse as something else.
func TestParseTruncation(t *testing.T) {
	full := validReply()
	for n := 0; n < len(full); n++ {
		p, used, err := parse(full[:n])
		if err == nil {
			t.Errorf("the first %d of %d bytes parsed as %d bytes: %+v", n, len(full), used, p)
		}
		if p != nil {
			t.Errorf("an error at %d bytes came with a packet", n)
		}
	}
	p, used, err := parse(full)
	if err != nil || used != len(full) {
		t.Fatalf("the whole message: %v %d", err, used)
	}
	if len(p.kids) != 2 {
		t.Fatalf("%d children", len(p.kids))
	}
	// Trailing bytes are not consumed and not an error at this level: the
	// caller knows the message ends where the length says it does.
	p, used, err = parse(append(full, 0xff, 0xff))
	if err != nil || used != len(full) || len(p.kids) != 2 {
		t.Fatalf("trailing bytes: %v %d", err, used)
	}
}

// TestParseBitFlips flips every bit of a valid message. The decoder may
// accept, refuse or return something different; it may not panic, hang
// or claim to have read more bytes than it was given.
func TestParseBitFlips(t *testing.T) {
	full := validReply()
	for i := range full {
		for bit := 0; bit < 8; bit++ {
			bad := make([]byte, len(full))
			copy(bad, full)
			bad[i] ^= 1 << bit
			p, used, err := parse(bad)
			if err != nil {
				continue
			}
			if used > len(bad) {
				t.Fatalf("byte %d bit %d: consumed %d of %d", i, bit, used, len(bad))
			}
			if p == nil {
				t.Fatalf("byte %d bit %d: no error and no packet", i, bit)
			}
		}
	}
}

// TestParseLengthForms covers the length header, where a decoder that
// trusts the sender reads past its buffer or allocates what it is told.
func TestParseLengthForms(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		ok   bool
	}{
		{"empty", nil, false},
		{"identifier only", []byte{0x04}, false},
		{"short form, empty value", []byte{0x04, 0x00}, true},
		{"short form at the boundary", append([]byte{0x04, 0x7f}, bytes.Repeat([]byte{'a'}, 0x7f)...), true},
		{"long form, one byte", append([]byte{0x04, 0x81, 0x80}, bytes.Repeat([]byte{'a'}, 0x80)...), true},
		{"indefinite length", []byte{0x30, 0x80, 0x00, 0x00}, false},
		{"five length bytes", []byte{0x04, 0x85, 1, 2, 3, 4, 5}, false},
		{"length bytes past the buffer", []byte{0x04, 0x84, 0x00}, false},
		{"length past the buffer", []byte{0x04, 0x7f, 'a'}, false},
		{"a length of two gigabytes", []byte{0x04, 0x84, 0x7f, 0xff, 0xff, 0xff}, false},
		{"the largest four-byte length", []byte{0x04, 0x84, 0xff, 0xff, 0xff, 0xff}, false},
		{"high tag number form", []byte{0x1f, 0x81, 0x00, 0x00}, false},
		{"a constructed value with a short child", []byte{0x30, 0x02, 0x04, 0x05}, false},
		{"a constructed value whose children overrun", []byte{0x30, 0x03, 0x04, 0x05, 'a'}, false},
	}
	for _, tc := range cases {
		p, _, err := parse(tc.in)
		if tc.ok && err != nil {
			t.Errorf("%s was refused: %v", tc.name, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("%s was accepted as %+v", tc.name, p)
		}
	}
	// readLength directly, including the header count it reports.
	if n, hdr, err := readLength([]byte{0x00}); n != 0 || hdr != 1 || err != nil {
		t.Errorf("readLength(0): %d %d %v", n, hdr, err)
	}
	if n, hdr, err := readLength([]byte{0x83, 0x01, 0x00, 0x00}); n != 65536 || hdr != 4 || err != nil {
		t.Errorf("readLength(3 bytes): %d %d %v", n, hdr, err)
	}
	if _, _, err := readLength(nil); err == nil {
		t.Error("an empty length was read")
	}
}

// TestParseDepthBoundary pins the nesting bound: one level inside it
// parses, one level past it is refused. A bound that is off by one is a
// bound nobody tested.
func TestParseDepthBoundary(t *testing.T) {
	wrap := func(n int) []byte {
		b := str("x").encode(nil)
		for i := 0; i < n; i++ {
			b = leaf(classUniversal|constructed, tagSequence, b).encode(nil)
		}
		return b
	}
	if _, _, err := parse(wrap(maxDepth)); err != nil {
		t.Errorf("a message nested %d deep was refused: %v", maxDepth, err)
	}
	if _, _, err := parse(wrap(maxDepth + 1)); err == nil {
		t.Errorf("a message nested %d deep was accepted", maxDepth+1)
	}
	// The refusal costs no more than the acceptance: the bound is checked
	// on the way down, not after building the tree, so the depth of the
	// bomb does not change how long the refusal takes.
	at := func(depth int) time.Duration {
		b := wrap(depth)
		started := time.Now()
		if _, _, err := parse(b); err == nil {
			t.Fatalf("a message nested %d deep was accepted", depth)
		}
		return time.Since(started)
	}
	shallow, deep := at(maxDepth+1), at(10000)
	if deep > 2*time.Second || deep > 100*shallow+time.Millisecond {
		t.Errorf("refusing a bomb took %v where the boundary took %v", deep, shallow)
	}
}

// TestEncodeRoundTrip covers the encoder against its own decoder over
// the values the client actually writes, and pins the encoding: two runs
// of the same message are byte identical, because a directory's audit
// log should not see the proxy change its mind.
func TestEncodeRoundTrip(t *testing.T) {
	for _, v := range []int{0, 1, 2, 3, 127, 128, 255, 256, 257, 65535, 65536, 1 << 20, 1<<31 - 1} {
		b := integer(v).encode(nil)
		p, n, err := parse(b)
		if err != nil || n != len(b) {
			t.Fatalf("integer %d: %v", v, err)
		}
		got, err := p.intValue()
		if err != nil || got != v {
			t.Fatalf("integer %d came back as %d (%v)", v, got, err)
		}
		// A value whose top bit is set carries a leading zero, so it can
		// never be read as negative.
		if p.data[0]&0x80 != 0 {
			t.Fatalf("integer %d encodes as negative: %x", v, p.data)
		}
		if e := enumerated(v); e.tag != tagEnum {
			t.Fatalf("enumerated %d has tag %d", v, e.tag)
		}
	}
	for _, b := range []bool{true, false} {
		p, _, err := parse(boolean(b).encode(nil))
		if err != nil || len(p.data) != 1 {
			t.Fatalf("boolean %v: %v", b, err)
		}
		if (p.data[0] != 0) != b {
			t.Fatalf("boolean %v came back as %x", b, p.data)
		}
	}
	// Lengths across both forms.
	for _, n := range []int{0, 1, 0x7f, 0x80, 0xff, 0x100, 0xffff, 0x10000, 1 << 20} {
		b := str(strings.Repeat("a", n)).encode(nil)
		p, used, err := parse(b)
		if err != nil || used != len(b) || len(p.data) != n {
			t.Fatalf("a %d byte string: %v %d %d", n, err, used, len(p.data))
		}
	}
	// Two encodings of one message are the same bytes.
	a, b := validReply(), validReply()
	if !bytes.Equal(a, b) {
		t.Fatal("the encoder is not deterministic")
	}
	// Every value the decoder accepts re-encodes to the same bytes.
	p, _, err := parse(a)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p.encode(nil), a) {
		t.Fatalf("re-encoding changed the message:\n%x\n%x", p.encode(nil), a)
	}
}

// TestIntValueRejections covers the one place a length is turned into a
// number the caller acts on.
func TestIntValueRejections(t *testing.T) {
	for _, data := range [][]byte{nil, {}, {1, 2, 3, 4, 5}, bytes.Repeat([]byte{0xff}, 16)} {
		if _, err := (&packet{data: data}).intValue(); err == nil {
			t.Errorf("an integer of %d bytes was accepted", len(data))
		}
	}
	// Four 0xff bytes is the largest value the reader takes, and it does
	// not come back negative.
	v, err := (&packet{data: []byte{0xff, 0xff, 0xff, 0xff}}).intValue()
	if err != nil || v < 0 {
		t.Fatalf("four 0xff bytes: %d %v", v, err)
	}
}

// TestParseIsPure runs the decoder from many goroutines over one buffer:
// it must not write into what it was given, and two runs must agree.
func TestParseIsPure(t *testing.T) {
	in := validReply()
	before := append([]byte(nil), in...)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				p, _, err := parse(in)
				if err != nil || len(p.kids) != 2 {
					t.Errorf("concurrent parse: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
	if !bytes.Equal(in, before) {
		t.Fatal("the decoder wrote into its input")
	}
}

// TestParseRandomBytes throws structured rubbish at the decoder: it must
// always return, never panic, and never claim more bytes than it read.
func TestParseRandomBytes(t *testing.T) {
	r := rand.New(rand.NewSource(20260920))
	for i := 0; i < 20000; i++ {
		b := make([]byte, r.Intn(64))
		for j := range b {
			// Weighted towards identifiers and lengths, so the decoder is
			// actually driven into its branches rather than rejected at
			// the first byte.
			switch r.Intn(4) {
			case 0:
				b[j] = byte(0x30)
			case 1:
				b[j] = byte(r.Intn(6))
			case 2:
				b[j] = byte(0x80 | r.Intn(8))
			default:
				b[j] = byte(r.Intn(256))
			}
		}
		p, used, err := parse(b)
		if err != nil {
			continue
		}
		if used > len(b) || p == nil {
			t.Fatalf("%x: used %d of %d, packet %v", b, used, len(b), p != nil)
		}
	}
}

// ---- the filter parser, which reads a configured template ----

// TestFilterParsing covers the RFC 4515 shapes the parser accepts and
// the many it must not.
func TestFilterParsing(t *testing.T) {
	good := []string{
		"(uid=alice)",
		"(uid=*)",
		"(&(objectClass=person)(uid=alice))",
		"(|(uid=a)(uid=b))",
		"(!(uid=alice))",
		"(&(|(a=1)(b=2))(!(c=3)))",
		"(uid=)",                  // an empty assertion value is legal
		"(uid=\\2a)",              // an escaped star is a value, not a wildcard
		"(uid=a\\28b\\29c)",       // escaped parentheses
		"(uid=\\00)",              // an escaped NUL
		"(objectClass;lang-en=x)", // an attribute option
		"(a-b.c=1)",               // the punctuation an attribute may carry
		"(uid=" + strings.Repeat("a", 1000) + ")",
	}
	for _, s := range good {
		if _, err := ParseFilter(s); err != nil {
			t.Errorf("%q was refused: %v", s, err)
		}
	}
	bad := []string{
		"",
		"uid=alice",
		"(uid=alice",
		"uid=alice)",
		"(uid=alice))",
		"((uid=alice)",
		"()",
		"(&)",
		"(|)",
		"(!)",
		"(!(a=1)(b=2))", // not takes one filter
		"(=alice)",      // no attribute
		"(uid)",         // no assertion
		"(uid=a*b)",     // substring, deliberately unsupported
		"(uid=*a)",
		"(uid=a*)",
		"(uid=\\)",   // truncated escape
		"(uid=\\2)",  // truncated escape
		"(uid=\\zz)", // not hex
		"(uid=\\2g)",
		"(ui d=alice)", // a space is not an attribute character
		"(uid\x00=alice)",
		"(ui(d=alice)",
		"(" + strings.Repeat("a", 129) + "=x)", // an attribute past the bound
		"(&(uid=alice)) trailing",
		" (uid=alice)",
		"(uid=alice) ",
		"(&(uid=alice)(uid=bob)",
	}
	for _, s := range bad {
		if p, err := ParseFilter(s); err == nil {
			t.Errorf("%q was accepted as %+v", s, p)
		}
	}
}

// TestFilterDepthBound pins the nesting bound of the filter parser. The
// filter is parsed once per login attempt, so an unbounded parser would
// be a way to take the proxy down with a configuration typo.
func TestFilterDepthBound(t *testing.T) {
	nest := func(n int) string {
		return strings.Repeat("(&", n) + "(uid=alice)" + strings.Repeat(")", n)
	}
	// One level inside the bound parses; the filter itself is one level,
	// so the deepest accepted nesting is one less than the bound.
	if _, err := ParseFilter(nest(maxFilterDepth - 1)); err != nil {
		t.Errorf("a filter nested %d deep was refused: %v", maxFilterDepth-1, err)
	}
	if _, err := ParseFilter(nest(maxFilterDepth)); err == nil {
		t.Errorf("a filter nested %d deep was accepted", maxFilterDepth)
	}
	// The one that would have taken the stack out.
	done := make(chan error, 1)
	go func() { _, err := ParseFilter(nest(5_000_000)); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a filter nested five million deep was accepted")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("parsing a deeply nested filter did not return")
	}
	// A filter the bound accepts still encodes to a packet the BER
	// decoder reads back, which is what the bound is derived from.
	f, err := ParseFilter(nest(maxFilterDepth - 2))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := parse(f.encode(nil)); err != nil {
		t.Fatalf("a filter at the bound does not survive its own encoding: %v", err)
	}
}

// TestEscapingIsALosslessBoundary is the property the whole filter
// injection defence rests on: whatever a login form carries, escaping it
// and parsing the result gives back exactly those bytes, and the filter
// keeps the shape the template gave it.
func TestEscapingIsALosslessBoundary(t *testing.T) {
	values := []string{
		"alice",
		"",
		"*",
		"*)(uid=*",
		"a)(|(uid=admin",
		")(cn=*))(|(cn=*",
		"\\",
		"\\2a",
		"(((((",
		"a\x00b",
		"\x00",
		"admin\x00.png",
		"o'brien",
		"a=b",
		"a,b+c",
		"é你好",      // multi-byte UTF-8
		"\xff\xfe", // not UTF-8 at all
		"\r\n",
		"\t ",
		strings.Repeat("*", 100),
		strings.Repeat("\x00", 10),
	}
	for _, v := range values {
		f, err := ParseFilter("(&(objectClass=person)(uid=" + EscapeFilter(v) + "))")
		if err != nil {
			t.Errorf("escaping %q produced an unparsable filter: %v", v, err)
			continue
		}
		// The template's shape is intact: an AND of exactly two items.
		if f.class != classContext || f.tag != filterAnd || len(f.kids) != 2 {
			t.Errorf("%q changed the filter's shape: class %x tag %d, %d children", v, f.class, f.tag, len(f.kids))
			continue
		}
		item := f.kids[1]
		if item.tag != filterEqual || len(item.kids) != 2 {
			t.Errorf("%q changed the item: tag %d, %d children", v, item.tag, len(item.kids))
			continue
		}
		if got := string(item.kids[1].data); got != v {
			t.Errorf("%q came back as %q", v, got)
		}
	}
	// Escaping is idempotent in the sense that matters: escaping an
	// already escaped value yields the escaped text, not the original.
	if got := EscapeFilter(EscapeFilter("*")); got == "*" {
		t.Error("escaping twice cancelled out")
	}
	// Every byte survives a round trip.
	var all []byte
	for i := 0; i < 256; i++ {
		all = append(all, byte(i))
	}
	got, err := unescapeValue(EscapeFilter(string(all)))
	if err != nil {
		t.Fatal(err)
	}
	if got != string(all) {
		t.Fatalf("a round trip of every byte returned %d bytes", len(got))
	}
	// Escaping never leaves a character that could end an item.
	esc := EscapeFilter(string(all))
	if strings.ContainsAny(esc, "()*\x00") {
		t.Fatal("an escaped value still carries a filter metacharacter")
	}
}

// TestEscapeDN covers the other injection boundary: a value substituted
// into a distinguished name.
func TestEscapeDN(t *testing.T) {
	cases := map[string]string{
		"alice":            "alice",
		"":                 "",
		"a,b":              "a\\,b",
		"a+b":              "a\\+b",
		`a"b`:              `a\"b`,
		"a\\b":             "a\\\\b",
		"a<b>c":            "a\\<b\\>c",
		"a;b":              "a\\;b",
		" leading":         "\\ leading",
		"trailing ":        "trailing\\ ",
		"#hash":            "\\#hash",
		"mid#hash":         "mid#hash",
		"a\x00b":           "a\\00b",
		"cn=admin,dc=corp": "cn=admin\\,dc=corp",
		" ":                "\\ ",
	}
	for in, want := range cases {
		if got := EscapeDN(in); got != want {
			t.Errorf("EscapeDN(%q) = %q want %q", in, got, want)
		}
	}
	// The characters that separate one RDN from the next never survive
	// unescaped, whatever else is in the value.
	for i := 0; i < 256; i++ {
		v := "x" + string(rune(i)) + "y"
		got := EscapeDN(v)
		for _, c := range []string{",", "+", "\"", "<", ">", ";"} {
			if strings.Contains(strings.ReplaceAll(got, "\\"+c, ""), c) {
				t.Errorf("EscapeDN(%q) = %q leaves a bare %s", v, got, c)
			}
		}
	}
}

// TestHexVal covers the escape decoder's digit table.
func TestHexVal(t *testing.T) {
	for i := 0; i < 256; i++ {
		c := byte(i)
		v, ok := hexVal(c)
		want := -1
		switch {
		case c >= '0' && c <= '9':
			want = int(c - '0')
		case c >= 'a' && c <= 'f':
			want = int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			want = int(c-'A') + 10
		}
		if ok != (want >= 0) || (ok && int(v) != want) {
			t.Errorf("hexVal(%q) = %d,%v want %d", c, v, ok, want)
		}
	}
}

// ---- the client, against directories that misbehave ----

// rawDirectory answers every request with bytes a test chose, so the
// client meets a directory that is broken, hostile or simply not LDAP.
type rawDirectory struct {
	t     *testing.T
	ln    net.Listener
	reply func(req []byte) []byte
	mu    sync.Mutex
	reqs  int
}

func newRawDirectory(t *testing.T, reply func([]byte) []byte) *rawDirectory {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	d := &rawDirectory{t: t, ln: ln, reply: reply}
	go d.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return d
}

func (d *rawDirectory) serve() {
	for {
		conn, err := d.ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = conn.Close() }()
			buf := make([]byte, 64<<10)
			for {
				_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
				n, err := conn.Read(buf)
				if n > 0 {
					d.mu.Lock()
					d.reqs++
					d.mu.Unlock()
					out := d.reply(buf[:n])
					if out == nil {
						return
					}
					if _, err := conn.Write(out); err != nil {
						return
					}
				}
				if err != nil {
					return
				}
			}
		}()
	}
}

func (d *rawDirectory) url() string { return "ldap://" + d.ln.Addr().String() }

func (d *rawDirectory) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.reqs
}

func (d *rawDirectory) dial(t *testing.T) *Conn {
	t.Helper()
	c, err := Dial(Options{URL: d.url(), Timeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestBindAgainstABrokenDirectory covers the answers a directory must
// not be able to turn into a successful authentication.
func TestBindAgainstABrokenDirectory(t *testing.T) {
	replies := map[string][]byte{
		"nothing at all":           {},
		"one byte":                 {0x30},
		"a truncated message":      {0x30, 0x20, 0x02, 0x01, 0x01},
		"not LDAP":                 []byte("HTTP/1.1 200 OK\r\n\r\n"),
		"a message with one child": node(classUniversal, tagSequence, integer(1)).encode(nil),
		"a result with no code": node(classUniversal, tagSequence, integer(1),
			node(classApplication, appBindResponse)).encode(nil),
		"a search result instead": node(classUniversal, tagSequence, integer(1),
			node(classApplication, appSearchResultEntry, str("cn=x"), node(classUniversal, tagSequence))).encode(nil),
		"an unknown result code": node(classUniversal, tagSequence, integer(1),
			node(classApplication, appBindResponse, enumerated(80), str(""), str(""))).encode(nil),
		"a code that is not an integer": node(classUniversal, tagSequence, integer(1),
			node(classApplication, appBindResponse, str("zero"), str(""), str(""))).encode(nil),
		"an oversize code": node(classUniversal, tagSequence, integer(1),
			node(classApplication, appBindResponse, leaf(classUniversal, tagEnum, bytes.Repeat([]byte{0xff}, 8)), str(""))).encode(nil),
		"a nesting bomb": nestedMessage(200),
	}
	for name, reply := range replies {
		d := newRawDirectory(t, func([]byte) []byte { return reply })
		c, err := Dial(Options{URL: d.url(), Timeout: 300 * time.Millisecond})
		if err != nil {
			t.Fatalf("%s: dial: %v", name, err)
		}
		err = c.Bind("cn=admin", "password")
		_ = c.Close()
		if err == nil {
			t.Errorf("%s was accepted as a successful bind", name)
		}
		if errors.Is(err, ErrInvalidCredentials) && name != "invalid credentials" {
			t.Errorf("%s was reported as invalid credentials", name)
		}
	}
	// A directory that hangs up mid-message, and one that never answers.
	d := newRawDirectory(t, func([]byte) []byte { return nil })
	c := d.dial(t)
	if err := c.Bind("cn=admin", "password"); err == nil {
		t.Error("a directory that hung up produced a successful bind")
	}
	silent := newRawDirectory(t, func([]byte) []byte { time.Sleep(30 * time.Second); return nil })
	c2, err := Dial(Options{URL: silent.url(), Timeout: 300 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c2.Close() }()
	started := time.Now()
	if err := c2.Bind("cn=admin", "password"); err == nil {
		t.Error("a silent directory produced a successful bind")
	}
	if d := time.Since(started); d > 5*time.Second {
		t.Errorf("the bind waited %v past its timeout", d)
	}
}

// nestedMessage builds a reply nested far past the decoder's bound.
func nestedMessage(depth int) []byte {
	b := str("x").encode(nil)
	for i := 0; i < depth; i++ {
		b = leaf(classUniversal|constructed, tagSequence, b).encode(nil)
	}
	return b
}

// TestEmptyPasswordNeverReachesTheDirectory is RFC 4513 §5.1.2: a simple
// bind with an empty password is an anonymous bind, which a directory
// answers with success. The client must refuse it itself, so an empty
// form field can never authenticate.
func TestEmptyPasswordNeverReachesTheDirectory(t *testing.T) {
	d := newRawDirectory(t, func([]byte) []byte {
		return node(classUniversal, tagSequence, integer(1),
			node(classApplication, appBindResponse, enumerated(0), str(""), str(""))).encode(nil)
	})
	c := d.dial(t)
	if err := c.Bind("cn=admin", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("an empty password gave %v", err)
	}
	if n := d.count(); n != 0 {
		t.Fatalf("the empty password reached the directory %d times", n)
	}
	// A password that is only whitespace is a password, not an empty one:
	// the directory decides.
	if err := c.Bind("cn=admin", " "); err != nil {
		t.Fatalf("a whitespace password: %v", err)
	}
}

// TestReadTLVBounds covers the framing reader directly, including the
// ceiling that keeps a directory from naming a gigabyte.
func TestReadTLVBounds(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		ok   bool
	}{
		{"empty", nil, false},
		{"one byte", []byte{0x30}, false},
		{"an empty value", []byte{0x30, 0x00}, true},
		{"short form", []byte{0x04, 0x02, 'h', 'i'}, true},
		{"short form, body missing", []byte{0x04, 0x02, 'h'}, false},
		{"long form", append([]byte{0x04, 0x81, 0x80}, bytes.Repeat([]byte{'a'}, 0x80)...), true},
		{"long form, body short", []byte{0x04, 0x81, 0x80, 'a'}, false},
		{"indefinite length", []byte{0x30, 0x80}, false},
		{"five length bytes", []byte{0x30, 0x85, 1, 2, 3, 4, 5}, false},
		{"length bytes missing", []byte{0x30, 0x84, 0x00}, false},
		{"eight megabytes and one", []byte{0x30, 0x84, 0x00, 0x80, 0x00, 0x01}, false},
		{"two gigabytes", []byte{0x30, 0x84, 0x7f, 0xff, 0xff, 0xff}, false},
		{"four gigabytes", []byte{0x30, 0x84, 0xff, 0xff, 0xff, 0xff}, false},
	}
	for _, tc := range cases {
		out, err := readTLV(bytes.NewReader(tc.in))
		if tc.ok && err != nil {
			t.Errorf("%s was refused: %v", tc.name, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("%s was accepted as %d bytes", tc.name, len(out))
		}
		if err == nil && len(out) > len(tc.in) {
			t.Errorf("%s returned %d bytes from %d", tc.name, len(out), len(tc.in))
		}
	}
	// The ceiling is not reached by allocating what the sender named: a
	// message that claims eight megabytes and sends nothing fails on the
	// read, not on the allocation.
	if _, err := readTLV(bytes.NewReader([]byte{0x30, 0x84, 0x00, 0x7f, 0xff, 0xff})); err == nil {
		t.Error("a message that claimed eight megabytes and sent none was accepted")
	}
	// A reader that fails part way through is reported, not padded.
	if _, err := readTLV(io.MultiReader(bytes.NewReader([]byte{0x04, 0x04, 'a'}), errReader{})); err == nil {
		t.Error("a failing reader produced a message")
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

// TestSearchAgainstABrokenDirectory covers the streaming half of the
// client: many messages arrive per request, and the loop must end.
func TestSearchAgainstABrokenDirectory(t *testing.T) {
	filter, err := ParseFilter("(uid=alice)")
	if err != nil {
		t.Fatal(err)
	}
	entry := func(id int, dn string) []byte {
		attrs := node(classUniversal, tagSequence,
			node(classUniversal, tagSequence, str("cn"), node(classUniversal, tagSet, str("Alice"))))
		return node(classUniversal, tagSequence, integer(id),
			node(classApplication, appSearchResultEntry, str(dn), attrs)).encode(nil)
	}
	done := func(id, code int) []byte {
		return node(classUniversal, tagSequence, integer(id),
			node(classApplication, appSearchResultDone, enumerated(code), str(""), str(""))).encode(nil)
	}

	// The ordinary case, with a reference message in the middle that the
	// client must skip rather than take for an entry.
	ref := node(classUniversal, tagSequence, integer(1),
		node(classApplication, 19, str("ldap://other/dc=x"))).encode(nil)
	d := newRawDirectory(t, func([]byte) []byte {
		out := append([]byte{}, entry(1, "uid=alice,dc=corp")...)
		out = append(out, ref...)
		return append(out, done(1, 0)...)
	})
	entries, err := d.dial(t).Search("dc=corp", ScopeSub, filter, []string{"cn"}, 10)
	if err != nil || len(entries) != 1 || entries[0].DN != "uid=alice,dc=corp" {
		t.Fatalf("a normal search: %v %+v", err, entries)
	}
	if got := entries[0].Attrs["cn"]; len(got) != 1 || got[0] != "Alice" {
		t.Fatalf("attributes: %+v", entries[0].Attrs)
	}

	// sizeLimitExceeded is not a failure: the entries before it stand.
	d = newRawDirectory(t, func([]byte) []byte {
		return append(entry(1, "uid=alice,dc=corp"), done(1, 4)...)
	})
	if got, err := d.dial(t).Search("dc=corp", ScopeSub, filter, nil, 10); err != nil || len(got) != 1 {
		t.Fatalf("sizeLimitExceeded: %v %+v", err, got)
	}

	// A directory that ignores the size limit is cut off, and the
	// connection is closed rather than left mid-stream.
	d = newRawDirectory(t, func([]byte) []byte {
		var out []byte
		for i := 0; i < 50; i++ {
			out = append(out, entry(1, fmt.Sprintf("uid=u%d,dc=corp", i))...)
		}
		return append(out, done(1, 0)...)
	})
	c := d.dial(t)
	if _, err := c.Search("dc=corp", ScopeSub, filter, nil, 2); err == nil {
		t.Error("a directory past the size limit was accepted")
	}
	if _, err := c.Search("dc=corp", ScopeSub, filter, nil, 2); err == nil {
		t.Error("the connection was usable after the size limit was exceeded")
	}

	// A directory that never sends a done message is bounded by the read
	// deadline, not by the entries it sends.
	d = newRawDirectory(t, func([]byte) []byte { return entry(1, "uid=alice,dc=corp") })
	slow, err := Dial(Options{URL: d.url(), Timeout: 500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = slow.Close() }()
	started := time.Now()
	if _, err := slow.Search("dc=corp", ScopeSub, filter, nil, 0); err == nil {
		t.Error("a search with no done message returned successfully")
	}
	if el := time.Since(started); el > 10*time.Second {
		t.Errorf("the search waited %v", el)
	}

	// Malformed replies of every shape.
	for name, reply := range map[string][]byte{
		"rubbish":                  []byte("not ldap at all\n"),
		"a message with one child": node(classUniversal, tagSequence, integer(1)).encode(nil),
		"an entry with no attributes": node(classUniversal, tagSequence, integer(1),
			node(classApplication, appSearchResultEntry, str("uid=x"))).encode(nil),
		"a done with no code": node(classUniversal, tagSequence, integer(1),
			node(classApplication, appSearchResultDone)).encode(nil),
		"a failed search": node(classUniversal, tagSequence, integer(1),
			node(classApplication, appSearchResultDone, enumerated(32), str(""), str(""))).encode(nil),
	} {
		d := newRawDirectory(t, func([]byte) []byte { return reply })
		if got, err := d.dial(t).Search("dc=corp", ScopeSub, filter, nil, 10); err == nil {
			t.Errorf("%s was accepted, returning %d entries", name, len(got))
		}
	}

	// An entry whose attribute list is half built is read for what it
	// has, because a directory that returns one odd attribute should not
	// fail a login.
	partial := node(classApplication, appSearchResultEntry, str("uid=x"),
		node(classUniversal, tagSequence,
			node(classUniversal, tagSequence, str("cn")), // no values
			node(classUniversal, tagSequence, str("mail"), node(classUniversal, tagSet, str("a@b.c"))),
		))
	e, err := parseEntry(partial)
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Attrs) != 1 || e.Attrs["mail"][0] != "a@b.c" {
		t.Fatalf("a half built entry: %+v", e.Attrs)
	}
	if _, err := parseEntry(node(classApplication, appSearchResultEntry, str("uid=x"))); err == nil {
		t.Error("an entry with no attribute list was accepted")
	}
}

// TestDialRejections covers the URLs an operator can write.
func TestDialRejections(t *testing.T) {
	bad := []string{
		"",
		"http://dir.example",
		"ldapi:///",
		"://dir.example",
		"ldap",
		"LDAP://dir.example", // the scheme is matched exactly
		"ldap://dir.example:notaport",
		"ldap://" + strings.Repeat("a", 300) + ":389",
		"ldap://127.0.0.1:0",
	}
	for _, u := range bad {
		c, err := Dial(Options{URL: u, Timeout: 500 * time.Millisecond})
		if err == nil {
			_ = c.Close()
			t.Errorf("%q was dialled", u)
		}
	}
	// A port nobody listens on fails fast rather than hanging.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	started := time.Now()
	if _, err := Dial(Options{URL: "ldap://" + addr, Timeout: 2 * time.Second}); err == nil {
		t.Error("a closed port was dialled")
	}
	if d := time.Since(started); d > 5*time.Second {
		t.Errorf("the dial took %v", d)
	}
	// ldaps against a directory speaking plain LDAP fails in the
	// handshake, not in the bind.
	plain := newRawDirectory(t, func([]byte) []byte { return []byte{0x30, 0x00} })
	if _, err := Dial(Options{URL: "ldaps://" + plain.ln.Addr().String(), Timeout: 2 * time.Second,
		TLS: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}}); err == nil { //nolint:gosec // the point is that even this fails
		t.Error("ldaps against a plaintext directory succeeded")
	}
}

// TestStartTLS covers the upgrade in the middle of a plaintext
// connection, which is the one moment the client is exposed to a
// directory that lies about supporting it.
func TestStartTLS(t *testing.T) {
	extResp := func(code int) []byte {
		return node(classUniversal, tagSequence, integer(1),
			node(classApplication, appExtendedResponse, enumerated(code), str(""), str(""))).encode(nil)
	}
	// A directory that refuses the upgrade: the dial fails rather than
	// continuing in the clear.
	for name, reply := range map[string][]byte{
		"refused":         extResp(2),
		"unavailable":     extResp(52),
		"a bind response": {0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00},
		"rubbish":         []byte("no\n"),
		"a response with no code": node(classUniversal, tagSequence, integer(1),
			node(classApplication, appExtendedResponse)).encode(nil),
	} {
		d := newRawDirectory(t, func([]byte) []byte { return reply })
		if c, err := Dial(Options{URL: d.url(), StartTLS: true, Timeout: 2 * time.Second}); err == nil {
			_ = c.Close()
			t.Errorf("StartTLS continued after %s", name)
		}
	}
	// A directory that answers success and then does not speak TLS: the
	// handshake fails and the connection is not used.
	d := newRawDirectory(t, func([]byte) []byte { return extResp(0) })
	if c, err := Dial(Options{URL: d.url(), StartTLS: true, Timeout: 2 * time.Second,
		TLS: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}}); err == nil { //nolint:gosec // a hostile directory is the case under test
		_ = c.Close()
		t.Error("the TLS handshake succeeded against a plaintext directory")
	}
	// A directory whose certificate is not trusted is refused: the
	// upgrade must verify, or it is theatre.
	real := newTLSDirectory(t)
	if c, err := Dial(Options{URL: "ldap://" + real.addr, StartTLS: true, Timeout: 2 * time.Second}); err == nil {
		_ = c.Close()
		t.Error("StartTLS accepted an untrusted certificate")
	}
	// With the certificate pinned, the upgrade completes and a bind runs
	// over it.
	c, err := Dial(Options{URL: "ldap://" + real.addr, StartTLS: true, Timeout: 5 * time.Second, TLS: real.clientConfig()})
	if err != nil {
		t.Fatalf("StartTLS against a real server: %v", err)
	}
	defer func() { _ = c.Close() }()
	if err := c.Bind("cn=admin", "password"); err != nil {
		t.Fatalf("bind after StartTLS: %v", err)
	}
	if !real.sawTLS() {
		t.Error("the bind did not travel over TLS")
	}
}

// tlsDirectory answers StartTLS, completes a handshake with its own
// certificate and then answers binds.
type tlsDirectory struct {
	addr string
	cfg  *tls.Config
	mu   sync.Mutex
	tls  bool
}

func newTLSDirectory(t *testing.T) *tlsDirectory {
	t.Helper()
	cert := selfSigned(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	d := &tlsDirectory{addr: ln.Addr().String(), cfg: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go d.handle(conn)
		}
	}()
	return d
}

func (d *tlsDirectory) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	// The StartTLS request, answered in the clear.
	if _, err := readTLV(conn); err != nil {
		return
	}
	resp := node(classUniversal, tagSequence, integer(1),
		node(classApplication, appExtendedResponse, enumerated(0), str(""), str(""))).encode(nil)
	if _, err := conn.Write(resp); err != nil {
		return
	}
	tc := tls.Server(conn, d.cfg)
	if err := tc.Handshake(); err != nil {
		return
	}
	d.mu.Lock()
	d.tls = true
	d.mu.Unlock()
	for {
		_ = tc.SetDeadline(time.Now().Add(20 * time.Second))
		if _, err := readTLV(tc); err != nil {
			return
		}
		bind := node(classUniversal, tagSequence, integer(2),
			node(classApplication, appBindResponse, enumerated(0), str(""), str(""))).encode(nil)
		if _, err := tc.Write(bind); err != nil {
			return
		}
	}
}

func (d *tlsDirectory) sawTLS() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.tls
}

func (d *tlsDirectory) clientConfig() *tls.Config {
	pool := certPoolOf(d.cfg.Certificates[0])
	return &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}
}

// TestMessageIDsAdvance pins the one piece of connection state: each
// request carries a new message id, so a reply cannot be matched to the
// wrong request.
func TestMessageIDsAdvance(t *testing.T) {
	var ids []int
	d := newRawDirectory(t, func(req []byte) []byte {
		p, _, err := parse(req)
		if err != nil || len(p.kids) < 1 {
			return nil
		}
		id, err := p.kids[0].intValue()
		if err != nil {
			return nil
		}
		ids = append(ids, id)
		return node(classUniversal, tagSequence, integer(id),
			node(classApplication, appBindResponse, enumerated(0), str(""), str(""))).encode(nil)
	})
	c := d.dial(t)
	for i := 0; i < 5; i++ {
		if err := c.Bind("cn=admin", "password"); err != nil {
			t.Fatalf("bind %d: %v", i, err)
		}
	}
	if len(ids) != 5 {
		t.Fatalf("%d requests reached the directory", len(ids))
	}
	for i, id := range ids {
		if id != i+1 {
			t.Fatalf("request %d carried message id %d", i, id)
		}
	}
}

// selfSigned builds a certificate for 127.0.0.1, so a test can pin one.
func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test directory"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// certPoolOf trusts exactly one certificate.
func certPoolOf(c tls.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(c.Leaf)
	return pool
}
