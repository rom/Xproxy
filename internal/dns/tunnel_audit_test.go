package dns

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/netutil"
)

// FuzzTunnelObserve: every name the detector measures came off the
// wire, and the table it keeps is keyed on one. A panic here is a crash
// from one query; a table that grows on a name is a resolver a client
// can spend.
func FuzzTunnelObserve(f *testing.F) {
	f.Add("www.example.com", uint16(1), 0)
	f.Add("mfzwizltoq2gk3tf.evil.test", uint16(16), 3)
	f.Add("", uint16(1), 0)
	f.Add(".", uint16(1), 0)
	f.Add(strings.Repeat(".", 300), uint16(1), 0)
	f.Add(strings.Repeat("a", 300), uint16(1), 0)
	f.Fuzz(func(t *testing.T, name string, qtype uint16, rcode int) {
		p := TunnelPolicy{
			Window: time.Minute, MinQueries: 2, MinSignals: 1,
			Entropy: 3.0, EntropyShare: 0.5, MinLabelLength: 4,
			Distinct: 4, TXTShare: 0.5, NXShare: 0.5, PayloadBytes: 16,
			Action: "block", Cooldown: time.Minute, MaxTracked: 8,
		}
		d := NewDetector(p)
		now := time.Now()
		for i := 0; i < 4; i++ {
			det, ok := d.Observe(testAuditClient, Question{Name: name, Type: qtype}, rcode, now)
			if !ok {
				continue
			}
			// A DNS label may hold any byte, so the domain is not
			// required to be text. What it is required to be is a
			// suffix of what was asked for, folded only in ASCII:
			// anything else means the key a client is grouped and
			// blocked under is not the name they sent, and two
			// different names could share one.
			if !strings.HasSuffix(netutil.ASCIILower(name), det.Domain) {
				t.Fatalf("detection domain %q is not a suffix of the name %q", det.Domain, name)
			}
			if len(det.Domain) > len(name) {
				t.Fatalf("detection domain %q is longer than the name %q", det.Domain, name)
			}
			if det.Payload < 0 || det.Queries < 0 {
				t.Fatalf("detection carries negative counts: %+v", det)
			}
		}
		if n := d.Tracked(); n > p.MaxTracked {
			t.Fatalf("the table holds %d past a bound of %d", n, p.MaxTracked)
		}
		d.Blocks(testAuditClient, name, now)
	})
}

var testAuditClient = netip.MustParseAddr("198.51.100.4")

// TestEntropyOnEveryByte: the entropy figure is computed over bytes, so
// a name carrying anything at all must produce a finite number rather
// than a NaN that compares false against every threshold and silently
// switches the signal off. That is the NaN bug this audit round already
// found once, in another parser.
func TestEntropyOnEveryByte(t *testing.T) {
	for _, s := range []string{
		"", "a", "\x00", "\x00\x00", strings.Repeat("\xff", 64),
		"mfzwizltoq2gk3tf", strings.Repeat("ab", 500),
	} {
		e := Entropy(s)
		if e != e { // NaN
			t.Fatalf("Entropy(%q) is NaN", clipAudit(s))
		}
		if e < 0 || e > 8 {
			t.Fatalf("Entropy(%q) = %v, outside 0..8 bits per character", clipAudit(s), e)
		}
	}
}

// TestTunnelNeverGrowsOnDistinctNames is the bound that keeps the
// detector from being the denial of service it exists to catch: the key
// is a client and a domain and an attacker chooses both.
func TestTunnelNeverGrowsOnDistinctNames(t *testing.T) {
	p := TunnelPolicy{
		Window: time.Hour, MinQueries: 2, MinSignals: 1, Entropy: 3,
		EntropyShare: 0.5, MinLabelLength: 4, Distinct: 2, TXTShare: 0.5,
		NXShare: 0.5, PayloadBytes: 8, Action: "block",
		Cooldown: time.Hour, MaxTracked: 16,
	}
	d := NewDetector(p)
	now := time.Now()
	// Every query from a new client under a new domain, all inside one
	// window so nothing can be evicted for age, and all of them
	// detections so nothing can be evicted for being uninteresting.
	for i := 0; i < 20000; i++ {
		c := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		for j := 0; j < 3; j++ {
			d.Observe(c, Question{
				Name: "mfzwizltoq2gk3tfor4h" + string(rune('a'+j%26)) + ".d" + string(rune('a'+i%26)) + ".test",
				Type: TypeTXT,
			}, RcodeNXDomain, now)
		}
		if n := d.Tracked(); n > p.MaxTracked {
			t.Fatalf("after %d clients the table holds %d, past a bound of %d", i, n, p.MaxTracked)
		}
	}
	if d.Evicted == 0 {
		t.Fatal("the bound held silently; nothing was recorded as dropped")
	}
}

func clipAudit(s string) string {
	if len(s) > 32 {
		return s[:32] + "..."
	}
	return s
}

// TestNamesFoldInASCIIOnly. DNS case insensitivity is ASCII only (RFC
// 4343) and a label may hold any byte (RFC 1035 section 3.1), so
// strings.ToLower is the wrong tool for a name twice over: it folds by
// Unicode rules, mapping characters DNS treats as distinct onto one
// another, and on a byte that is not valid UTF-8 it yields the
// replacement character -- every such byte becoming the same three
// bytes, so two different names fold to one string that is longer than
// either.
//
// That string is the cache key, the block list comparison, the
// canonical name a signature is verified over and the name an NSEC3
// denial is hashed from. Nothing reaches it today, because labelOK
// refuses a label byte outside printable ASCII before any of them see
// it (TestLabelBytesAreGatedBeforeFolding below), so this is the hole
// the gate is covering rather than a hole. It is closed here anyway:
// the gate is in a different function from every one of those uses,
// and netutil.Registrable is exported with no gate in front of it at
// all.
func TestNamesFoldInASCIIOnly(t *testing.T) {
	a := "\xf2.example.com"
	b := "\xf3.example.com"
	if netutil.ASCIILower(a) == netutil.ASCIILower(b) {
		t.Fatal("two different names still fold to one")
	}
	for _, n := range []string{a, b, "\xff", "\x00", "ABC.Example.COM"} {
		if got := netutil.ASCIILower(n); len(got) != len(n) {
			t.Errorf("folding %q changed its length: %q", n, got)
		}
	}
	if netutil.ASCIILower("ABC.Example.COM") != "abc.example.com" {
		t.Error("ASCII folding stopped working")
	}
	// The Kelvin sign is the Unicode fold that bites in practice: it
	// lowers to "k", so a name carrying one compared equal to a name
	// with an ordinary k that DNS treats as a different name.
	if netutil.ASCIILower("\u212A") != "\u212A" {
		t.Error("a character DNS treats as distinct was folded")
	}
	if netutil.ASCIIEqualFold("\u212A", "k") {
		t.Error("the Kelvin sign compared equal to k")
	}
	if !netutil.ASCIIEqualFold("EXAMPLE", "example") {
		t.Error("ASCII comparison stopped working")
	}
	// And the grouping key a client is blocked under folds the same
	// way, since it is the one of these with no gate in front of it.
	if netutil.Registrable("EXAMPLE.COM") != "example.com" {
		t.Error("the grouping key stopped folding ASCII")
	}
	// Two names that differ inside the registered part must not group
	// together; two that differ only below it are meant to.
	if netutil.Registrable("\xf2.test") == netutil.Registrable("\xf3.test") {
		t.Error("two different registered names group under one key")
	}
	if netutil.Registrable(a) != netutil.Registrable(b) {
		t.Error("two subdomains of one registered name stopped grouping together")
	}
}

// TestLabelBytesAreGatedBeforeFolding pins the check the rest of this
// depends on: a name off the wire carrying a byte outside printable
// ASCII is refused at the parser, before it can become a cache key or
// the input to a hash. If this ever loosens, the folding above is what
// stops it becoming a collision.
func TestLabelBytesAreGatedBeforeFolding(t *testing.T) {
	wire := func(b byte) []byte {
		q := make([]byte, 12)
		q[1] = 1
		q[2] = 0x01
		q[5] = 1
		q = append(q, 1, b)
		q = append(q, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e')
		q = append(q, 4, 't', 'e', 's', 't', 0)
		return append(q, 0, 1, 0, 1)
	}
	for _, b := range []byte{0x00, 0x09, 0x20, 0x7f, 0x80, 0xf2, 0xff, '.', '\\'} {
		if q, _, err := ParseQuestion(wire(b)); err == nil {
			t.Errorf("a label byte %#x was accepted as part of %q", b, q.Name)
		}
	}
	// An ordinary label still parses, folded in ASCII.
	q, _, err := ParseQuestion(wire('A'))
	if err != nil {
		t.Fatalf("an ordinary name was refused: %v", err)
	}
	if q.Name != "a.example.test" {
		t.Fatalf("name %q", q.Name)
	}
}
