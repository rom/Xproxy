package dns

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func testTunnelPolicy() TunnelPolicy {
	return TunnelPolicy{
		Window: 5 * time.Minute, MinQueries: 20, MinSignals: 2,
		Entropy: 3.6, EntropyShare: 0.5, MinLabelLength: 12,
		Distinct: 50, TXTShare: 0.5, NXShare: 0.5,
		PayloadBytes: 4096, Action: "log", Cooldown: 10 * time.Minute,
		MaxTracked: 1000,
	}
}

var testClient = netip.MustParseAddr("10.0.0.7")

// tunnelTraffic sends n queries that look like a tunnel and returns the
// first detection.
func runTunnel(t *testing.T, d *Detector, n int, qtype uint16, rcode int, domain string) (Detection, bool) {
	t.Helper()
	return runTunnelAt(t, d, n, qtype, rcode, domain, tunnelNow)
}

// tunnelNow is a fixed instant, so a test can say what the cooldown
// after a detection is measured from.
var tunnelNow = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func runTunnelAt(t *testing.T, d *Detector, n int, qtype uint16, rcode int, domain string, now time.Time) (Detection, bool) {
	t.Helper()
	var first Detection
	found := false
	for i := 0; i < n; i++ {
		// A base32-looking payload label, as a tunnel writes it: a new
		// one every time, because each carries a different chunk.
		sub := fmt.Sprintf("mfzwizltoq2gk3tfor4hi7dbnzsw4y3pnu%04x", i)
		q := Question{Name: sub + "." + domain, Type: qtype, Class: ClassIN}
		if det, ok := d.Observe(testClient, q, rcode, now); ok && !found {
			first, found = det, true
		}
	}
	return first, found
}

// TestTunnelDetected: encoded names, a new subdomain each time, TXT and
// NXDOMAIN together under one domain is a tunnel, and the detection
// names every signal that fired rather than a score.
func TestTunnelDetected(t *testing.T) {
	p := testTunnelPolicy()
	d := NewDetector(p)
	det, ok := runTunnel(t, d, 200, TypeTXT, RcodeNXDomain, "evil.test")
	if !ok {
		t.Fatal("a textbook tunnel was not detected")
	}
	if det.Domain != "evil.test" {
		t.Fatalf("domain %q", det.Domain)
	}
	// The detection fires as soon as enough signals agree, which is
	// before the slower ones (cardinality, volume) have had time to,
	// so what it carries is a subset and every member of it is real.
	known := map[string]bool{"entropy": true, "distinct_subdomains": true, "txt_heavy": true, "nxdomain_rate": true, "payload_volume": true}
	for _, r := range det.Reasons {
		if !known[r] {
			t.Errorf("unexpected signal %q", r)
		}
	}
	if len(det.Reasons) < p.MinSignals {
		t.Fatalf("fired on %d signals, min_signals is %d", len(det.Reasons), p.MinSignals)
	}
	if det.Payload == 0 || det.Queries == 0 {
		t.Fatalf("detection carries no weight: %+v", det)
	}
	// By the end of the run every signal has fired.
	d.mu.Lock()
	got := d.w[key(testClient, "evil.test")].signals(p, d.subsCap)
	d.mu.Unlock()
	for _, r := range got {
		delete(known, r)
	}
	if len(known) != 0 {
		t.Errorf("signals that should have fired did not: %v", known)
	}
}

// TestOneSignalIsNotEnough is the whole reason min_signals exists. Each
// of these is honest traffic that trips exactly one test, and none of
// them may be called a tunnel on its own.
func TestOneSignalIsNotEnough(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name string
		send func(d *Detector)
	}{
		{
			// A content delivery network: random-looking names, but few
			// of them, all A records, all resolving.
			"random cdn names",
			func(d *Detector) {
				for i := 0; i < 200; i++ {
					sub := fmt.Sprintf("mfzwizltoq2gk3tfor4hi7dbnzsw4y3pnu%02x", i%8)
					d.Observe(testClient, Question{Name: sub + ".cdn.test", Type: TypeA}, RcodeNoError, now)
				}
			},
		},
		{
			// A mail server: TXT queries all day (SPF, DKIM, DMARC),
			// ordinary names, resolving.
			"txt only",
			func(d *Detector) {
				for i := 0; i < 200; i++ {
					d.Observe(testClient, Question{Name: "_dmarc.mail.test", Type: TypeTXT}, RcodeNoError, now)
				}
			},
		},
		{
			// A laptop waking up on a network with a search domain:
			// NXDOMAIN after NXDOMAIN for short, ordinary names.
			"nxdomain only",
			func(d *Detector) {
				for i := 0; i < 200; i++ {
					d.Observe(testClient, Question{Name: "wpad.corp.test", Type: TypeA}, RcodeNXDomain, now)
				}
			},
		},
		{
			// A service with a host per customer: many subdomains, but
			// readable ones, A records, resolving.
			"many readable subdomains",
			func(d *Detector) {
				for i := 0; i < 200; i++ {
					d.Observe(testClient, Question{Name: fmt.Sprintf("shop%d.hosting.test", i), Type: TypeA}, RcodeNoError, now)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := NewDetector(testTunnelPolicy())
			tc.send(d)
			if d.Detections != 0 {
				t.Fatalf("one signal produced a detection: %d", d.Detections)
			}
		})
	}
}

// TestBelowMinQueriesIsNotJudged: a handful of queries is not a sample.
func TestBelowMinQueriesIsNotJudged(t *testing.T) {
	d := NewDetector(testTunnelPolicy())
	if _, ok := runTunnel(t, d, 19, TypeTXT, RcodeNXDomain, "evil.test"); ok {
		t.Fatal("judged on fewer queries than the minimum")
	}
	if _, ok := runTunnel(t, d, 2, TypeTXT, RcodeNXDomain, "evil.test"); !ok {
		t.Fatal("the twenty-first query did not complete the window")
	}
}

// TestAllowedDomainIsNeverJudged: the reputation services and telemetry
// that legitimately look exactly like this are named, not scored.
func TestAllowedDomainIsNeverJudged(t *testing.T) {
	p := testTunnelPolicy()
	allow, err := NewBlockList([]string{"evil.test"})
	if err != nil {
		t.Fatal(err)
	}
	p.Allow = allow
	d := NewDetector(p)
	if _, ok := runTunnel(t, d, 200, TypeTXT, RcodeNXDomain, "evil.test"); ok {
		t.Fatal("an allowed domain was judged")
	}
	// A different domain is still judged.
	if _, ok := runTunnel(t, d, 200, TypeTXT, RcodeNXDomain, "other.test"); !ok {
		t.Fatal("the allow list silenced a domain it does not name")
	}
}

// TestBlocksOnlyAfterDetectionAndOnlyForTheCooldown.
func TestBlocksDuringCooldown(t *testing.T) {
	p := testTunnelPolicy()
	p.Action = "block"
	p.Cooldown = time.Minute
	d := NewDetector(p)
	now := tunnelNow
	if _, blocked := d.Blocks(testClient, "x.evil.test", now); blocked {
		t.Fatal("blocked before any detection")
	}
	if _, ok := runTunnel(t, d, 200, TypeTXT, RcodeNXDomain, "evil.test"); !ok {
		t.Fatal("no detection")
	}
	at := now.Add(time.Second)
	if dom, blocked := d.Blocks(testClient, "another.evil.test", at); !blocked || dom != "evil.test" {
		t.Fatalf("not blocked after a detection: %q %v", dom, blocked)
	}
	// Another client under the same domain is not blocked: the
	// detection was about this client's traffic, not the name.
	other := netip.MustParseAddr("10.0.0.8")
	if _, blocked := d.Blocks(other, "another.evil.test", at); blocked {
		t.Fatal("a different client was blocked by somebody else's detection")
	}
	// A different domain is not blocked either.
	if _, blocked := d.Blocks(testClient, "www.good.test", at); blocked {
		t.Fatal("an unrelated domain was blocked")
	}
	// And the block expires.
	if _, blocked := d.Blocks(testClient, "another.evil.test", at.Add(2*time.Minute)); blocked {
		t.Fatal("the cooldown never ended")
	}
}

// TestLogActionNeverBlocks: the default action watches and says so.
func TestLogActionNeverBlocks(t *testing.T) {
	d := NewDetector(testTunnelPolicy())
	if _, ok := runTunnel(t, d, 200, TypeTXT, RcodeNXDomain, "evil.test"); !ok {
		t.Fatal("no detection")
	}
	if _, blocked := d.Blocks(testClient, "x.evil.test", tunnelNow); blocked {
		t.Fatal("action: log blocked a query")
	}
}

// TestTableIsBounded: the key is a client and a domain, and both are
// chosen by whoever sends the queries. A detector that grew without
// bound would be the denial of service it is meant to catch.
func TestTableIsBounded(t *testing.T) {
	p := testTunnelPolicy()
	p.MaxTracked = 64
	d := NewDetector(p)
	now := time.Now()
	for i := 0; i < 5000; i++ {
		c := netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1})
		d.Observe(c, Question{Name: fmt.Sprintf("a.d%d.test", i), Type: TypeA}, RcodeNoError, now)
	}
	if n := d.Tracked(); n > 64 {
		t.Fatalf("table holds %d, want at most 64", n)
	}
	if d.Evicted == 0 {
		t.Fatal("nothing was recorded as dropped, so the bound is silent")
	}
}

// TestDistinctSetIsBoundedPerWindow: the set a tunnel inflates is also
// the set an attacker would use to inflate this table, so it stops
// growing at a multiple of the threshold — and stopping is itself the
// signal, not a reason to forget.
func TestDistinctSetIsBounded(t *testing.T) {
	p := testTunnelPolicy()
	p.Distinct = 10
	p.MinSignals = 1
	d := NewDetector(p)
	now := time.Now()
	for i := 0; i < 10000; i++ {
		d.Observe(testClient, Question{Name: fmt.Sprintf("s%d.big.test", i), Type: TypeA}, RcodeNoError, now)
	}
	d.mu.Lock()
	n := len(d.w[key(testClient, "big.test")].subs)
	limit := d.subsCap
	d.mu.Unlock()
	if n > limit {
		t.Fatalf("the distinct set holds %d, want at most %d", n, limit)
	}
	if d.Detections == 0 {
		t.Fatal("cardinality past the bound stopped being a signal")
	}
}

// TestWindowResets: an old window does not count towards a new one, or
// a slow trickle would eventually add up to a detection.
func TestWindowResets(t *testing.T) {
	p := testTunnelPolicy()
	p.Window = time.Minute
	d := NewDetector(p)
	now := time.Now()
	for i := 0; i < 100; i++ {
		// One query every two minutes: never more than one per window.
		sub := fmt.Sprintf("mfzwizltoq2gk3tfor4hi7dbnzsw4y3pnu%04x", i)
		d.Observe(testClient, Question{Name: sub + ".evil.test", Type: TypeTXT}, RcodeNXDomain,
			now.Add(time.Duration(i)*2*time.Minute))
	}
	if d.Detections != 0 {
		t.Fatalf("a trickle across windows accumulated into %d detections", d.Detections)
	}
}

// TestQueryForTheDomainItselfIsNotMeasured: there is nothing below it
// to carry a payload.
func TestApexIsNotMeasured(t *testing.T) {
	d := NewDetector(testTunnelPolicy())
	now := time.Now()
	for i := 0; i < 500; i++ {
		d.Observe(testClient, Question{Name: "evil.test", Type: TypeTXT}, RcodeNXDomain, now)
	}
	if d.Tracked() != 0 || d.Detections != 0 {
		t.Fatalf("the apex was measured: tracked %d detections %d", d.Tracked(), d.Detections)
	}
}

// TestPayloadCountsEachNameOnce: asking for the same long name again
// carries no second copy of anything. Counting it would turn any client
// that polls a long name into an exfiltration of megabytes, and would
// make this signal a second reading of the entropy one rather than an
// independent check — which is what min_signals depends on. It has to
// hold whether or not the cardinality signal is switched on, because
// the set that tells a repeat from a new name is the same set.
func TestPayloadCountsEachNameOnce(t *testing.T) {
	for _, distinct := range []int{50, 0} {
		p := testTunnelPolicy()
		p.Distinct = distinct
		d := NewDetector(p)
		now := time.Now()
		const sub = "mfzwizltoq2gk3tfor4hi7dbnzsw4y3pnu"
		for i := 0; i < 500; i++ {
			d.Observe(testClient, Question{Name: sub + ".poll.test", Type: TypeA}, RcodeNoError, now)
		}
		d.mu.Lock()
		payload := d.w[key(testClient, "poll.test")].payload
		d.mu.Unlock()
		if payload != int64(len(sub)) {
			t.Errorf("distinct=%d: one name polled 500 times counted %d bytes, want %d",
				distinct, payload, len(sub))
		}
	}
}

// TestEntropy pins the number an operator has to be able to check a
// name against by hand before choosing a threshold.
func TestEntropy(t *testing.T) {
	if e := Entropy(""); e != 0 {
		t.Fatalf("empty: %v", e)
	}
	if e := Entropy("aaaaaaaa"); e != 0 {
		t.Fatalf("one repeated character carries no information: %v", e)
	}
	words := Entropy("mail")
	encoded := Entropy("mfzwizltoq2gk3tfor4hi7dbnzsw4y3pnu")
	if encoded <= words {
		t.Fatalf("an encoded label (%v) did not beat a word (%v)", encoded, words)
	}
	if encoded < 4 {
		t.Fatalf("a base32 payload should be near five bits, got %v", encoded)
	}
}

// TestLongestLabelDecides: a tunnel that hides its payload behind an
// ordinary looking prefix is still a tunnel, and averaging over the
// whole name would let the prefix hide it.
func TestLongestLabelDecides(t *testing.T) {
	p := testTunnelPolicy()
	if !encodedLooking("www.api.mfzwizltoq2gk3tfor4hi7dbnzsw4y3pnu", p.Entropy, p.MinLabelLength) {
		t.Fatal("a payload behind an ordinary prefix was missed")
	}
	if encodedLooking("www.api.mail", p.Entropy, p.MinLabelLength) {
		t.Fatal("ordinary labels were read as a payload")
	}
}
