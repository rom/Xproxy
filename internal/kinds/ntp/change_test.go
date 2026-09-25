package ntp

import (
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/ntp"
)

// The watcher answers "is this still the same server", which is the
// question every static bound leaves open: each change below is inside
// any threshold an estate would set and each is what a replaced,
// re-pointed or impersonated time source looks like.

// sample builds one measurement of a server.
func sample(edit func(*wire.Packet)) *wire.Packet {
	p := &wire.Packet{Version: 4, Mode: wire.ModeServer, Stratum: 2,
		ReferenceID: [4]byte{10, 30, 10, 1},
		Receive:     wire.TimestampOf(time.Now()), Transmit: wire.TimestampOf(time.Now())}
	if edit != nil {
		edit(p)
	}
	return p
}

// testWatcher is a watcher over a listener with no sockets: the
// detections are arithmetic over what a server said, so they are tested
// without one.
func testWatcher(t *testing.T, d *config.NTPChangeDetection) *watcher {
	t.Helper()
	n := &config.NTPListener{Upstream: "clocks", ChangeDetection: d}
	return newWatcher(&server{n: n, cfg: config.Listener{Name: "time"}, start: time.Now()})
}

func reasons(changes []Change) []string {
	out := make([]string, 0, len(changes))
	for _, c := range changes {
		out = append(out, c.Reason)
	}
	return out
}

func has(changes []Change, reason string) bool {
	for _, c := range changes {
		if c.Reason == reason {
			return true
		}
	}
	return false
}

func TestTheFirstMeasurementIsTheBaselineAndNotAChange(t *testing.T) {
	w := testWatcher(t, nil)
	if got := w.Check("10.30.10.1:123", sample(nil), 5*time.Millisecond); len(got) != 0 {
		t.Fatalf("the first measurement reported %v", reasons(got))
	}
	// And the same server saying the same things again is not a change
	// either, which is what stops this being an alert per poll.
	if got := w.Check("10.30.10.1:123", sample(nil), 6*time.Millisecond); len(got) != 0 {
		t.Fatalf("an unchanged server reported %v", reasons(got))
	}
}

func TestEachChangeIsNamed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		edit   func(*wire.Packet)
		offset time.Duration
		want   string
	}{
		{"the time source changed", func(p *wire.Packet) { p.ReferenceID = [4]byte{192, 0, 2, 9} },
			5 * time.Millisecond, "source_changed"},
		{"the stratum jumped", func(p *wire.Packet) { p.Stratum = 9 },
			5 * time.Millisecond, "stratum_jumped"},
		{"the offset stepped by fourteen seconds", nil, 14 * time.Second, "offset_stepped"},
		{"the dispersion exploded",
			func(p *wire.Packet) { p.RootDispersion = wire.ShortOf(2 * time.Second) },
			5 * time.Millisecond, "dispersion_grew"},
		{"a leap second is announced", func(p *wire.Packet) { p.Leap = wire.LeapAddSecond },
			5 * time.Millisecond, "leap_announced"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := testWatcher(t, nil)
			first := sample(func(p *wire.Packet) { p.RootDispersion = wire.ShortOf(time.Millisecond) })
			w.Check("10.30.10.1:123", first, 5*time.Millisecond)
			got := w.Check("10.30.10.1:123", sample(tc.edit), tc.offset)
			if !has(got, tc.want) {
				t.Fatalf("changes %v, want %s", reasons(got), tc.want)
			}
			// The baseline moves to what was measured, so the same
			// change is not reported for ever after.
			again := w.Check("10.30.10.1:123", sample(tc.edit), tc.offset)
			if has(again, tc.want) {
				t.Errorf("the change was reported twice: %v", reasons(again))
			}
		})
	}
}

// A stratum that falls is a jump too. A server that was four hops from a
// reference clock and now claims to be one is the more alarming
// direction: better numbers arriving from nowhere is what a clock somebody
// stood in front of looks like.
func TestAStratumThatFallsIsAJump(t *testing.T) {
	w := testWatcher(t, nil)
	w.Check("10.30.10.1:123", sample(func(p *wire.Packet) { p.Stratum = 9 }), 5*time.Millisecond)
	got := w.Check("10.30.10.1:123", sample(func(p *wire.Packet) { p.Stratum = 1 }), 5*time.Millisecond)
	if !has(got, "stratum_jumped") {
		t.Fatalf("changes %v, want stratum_jumped", reasons(got))
	}
	// And a move inside the threshold is not a jump in either direction:
	// a server whose own upstream failed over moves by one or two.
	w2 := testWatcher(t, nil)
	w2.Check("10.30.10.1:123", sample(func(p *wire.Packet) { p.Stratum = 3 }), time.Millisecond)
	if got := w2.Check("10.30.10.1:123", sample(func(p *wire.Packet) { p.Stratum = 2 }), time.Millisecond); has(got, "stratum_jumped") {
		t.Errorf("a failover of one hop: %v", reasons(got))
	}
}

// NTS stopping is the change that matters most and is hardest to see from
// a client: the answers stay valid NTP.
func TestASourceThatStopsCarryingNTSSaysSo(t *testing.T) {
	w := testWatcher(t, nil)
	protected := sample(func(p *wire.Packet) {
		p.Extensions = []wire.Extension{{Type: wire.EFNTSAuthenticator, Body: make([]byte, 28)}}
	})
	parsed, err := wire.Parse(protected.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.NTS().Present {
		t.Fatal("the first measurement is not NTS-protected, so this test proves nothing")
	}
	w.Check("10.30.10.1:123", parsed, time.Millisecond)
	got := w.Check("10.30.10.1:123", sample(nil), time.Millisecond)
	if !has(got, "nts_lost") {
		t.Fatalf("changes %v, want nts_lost", reasons(got))
	}
	// And the other way about is not an alarm: a server that starts
	// carrying NTS is an estate getting better.
	if got := w.Check("10.30.10.1:123", parsed, time.Millisecond); has(got, "nts_lost") {
		t.Errorf("a server that started carrying NTS: %v", reasons(got))
	}
}

// An answer that carries no measurement of the server's own time must not
// become the baseline: folding a kiss-o'-death or an unsynchronised
// answer in would make the next real answer look like a change.
func TestAnAnswerWithNoTimeInItIsNotABaseline(t *testing.T) {
	w := testWatcher(t, nil)
	w.Check("10.30.10.1:123", sample(nil), 5*time.Millisecond)
	kiss := sample(func(p *wire.Packet) {
		p.Stratum = 0
		copy(p.ReferenceID[:], "RATE")
	})
	if got := w.Check("10.30.10.1:123", kiss, 0); len(got) != 0 {
		t.Errorf("a kiss-o'-death reported %v", reasons(got))
	}
	unsync := sample(func(p *wire.Packet) { p.Leap = wire.LeapUnsynchronised })
	if got := w.Check("10.30.10.1:123", unsync, 0); len(got) != 0 {
		t.Errorf("an unsynchronised answer reported %v", reasons(got))
	}
	// The baseline is still the good answer, so the good answer is still
	// not a change.
	if got := w.Check("10.30.10.1:123", sample(nil), 5*time.Millisecond); len(got) != 0 {
		t.Errorf("after the two, a good answer reported %v", reasons(got))
	}
}

func TestTheThresholdsAreTheOperatorsAndTheTableIsBounded(t *testing.T) {
	// A tighter step and a tighter stratum jump catch what the defaults
	// let pass, which is what makes them settings rather than constants.
	w := testWatcher(t, &config.NTPChangeDetection{
		MaxStep: config.Duration(10 * time.Millisecond), MaxStratumJump: 1, DispersionGrowth: 2})
	w.Check("10.30.10.1:123", sample(nil), 5*time.Millisecond)
	got := w.Check("10.30.10.1:123", sample(func(p *wire.Packet) { p.Stratum = 4 }), 30*time.Millisecond)
	if !has(got, "offset_stepped") || !has(got, "stratum_jumped") {
		t.Fatalf("changes %v", reasons(got))
	}
	// Off means off, everywhere.
	off := testWatcher(t, &config.NTPChangeDetection{Enabled: ptr(false)})
	off.Check("10.30.10.1:123", sample(nil), 0)
	if got := off.Check("10.30.10.1:123", sample(func(p *wire.Packet) { p.Stratum = 12 }), time.Hour); len(got) != 0 {
		t.Errorf("a listener with the watching off reported %v", reasons(got))
	}
	if off.Enabled() {
		t.Error("the watcher says it is enabled")
	}
	if !w.Enabled() || w.Refusing() {
		t.Error("the default watcher alerts and does not refuse")
	}
	if !testWatcher(t, &config.NTPChangeDetection{Action: "refuse"}).Refusing() {
		t.Error("a listener that says refuse does not")
	}
	// The table is bounded: a listener has a handful of servers, and a
	// detector that grew without limit would be the leak.
	big := testWatcher(t, nil)
	for i := 0; i < 2000; i++ {
		big.Check(netipString(i), sample(nil), time.Millisecond)
	}
	big.mu.Lock()
	n := len(big.base)
	big.mu.Unlock()
	if n > 1024 {
		t.Fatalf("the table holds %d sources", n)
	}
	// A nil watcher is safe, which is what a listener holds when the
	// section is not there at all.
	var none *watcher
	if got := none.Check("x", sample(nil), 0); got != nil {
		t.Error("a nil watcher reported a change")
	}
	none.Report("x", []Change{{Reason: "source_changed"}})
	if none.Enabled() || none.Refusing() {
		t.Error("a nil watcher answers as if it were one")
	}
}

// netipString is a distinct server address per index.
func netipString(i int) string {
	return "10.30." + itoa(i/256) + "." + itoa(i%256) + ":123"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
