package modbus

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/anomaly"
	"github.com/rom/xproxy/internal/config"
)

// anomalyFor compiles a detector from the YAML an operator would write, so that
// every default in the test is the default an operator gets.
func anomalyFor(t *testing.T, section string) *detector {
	t.Helper()
	cfg, err := config.Parse([]byte(fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: plant
      address: "127.0.0.1:0"
      kind: modbus
      modbus:
        upstream: plc
        anomaly:
          enabled: true
%s
upstreams: [{name: plc, endpoints: [{address: "127.0.0.1:502"}]}]
`, section)))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	d, err := anomaly.FromConfig(cfg.Server.Listeners[0].Modbus.Anomaly, anomalyDay)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return &detector{d}
}

// detector is the test's own view of the shared models: the kind's own
// translation of a request, and the models' answer, with none of the logging
// and refusing that decideAnomaly does around them.
type detector struct{ *anomaly.Detector }

func (d *detector) check(req request, now time.Time) []anomaly.Finding {
	return d.Observe(anomalyEvent(req, now))
}

func (d *detector) clients() int    { return d.Status().Actors }
func (d *detector) dropped() uint64 { return d.Status().Dropped }
func (d *detector) blinded() uint64 { return d.Status().Blinded }

// reasons is what one check reported, for comparing against a list.
func reasons(fs []anomaly.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Reason)
	}
	return out
}

var anomalyDay = time.Date(2026, 4, 1, 6, 0, 0, 0, time.UTC)

// Nothing is reported while the client is settling, and the traffic is still
// recorded: that is the difference between settling and ignoring.
func TestNovelIsNotReportedWhileSettling(t *testing.T) {
	a := anomalyFor(t, "          settle: 10m")
	first := req(t, "10.0.0.8", "", 3, readRegs)
	if got := reasons(a.check(first, anomalyDay)); len(got) != 0 {
		t.Errorf("the first request of a settling client reported %v", got)
	}
	// A write, still settling: novel in two ways and reported as neither.
	w := req(t, "10.0.0.8", "", 3, writeReg)
	if got := reasons(a.check(w, anomalyDay.Add(time.Minute))); len(got) != 0 {
		t.Errorf("a novel write while settling reported %v", got)
	}
	// Past the window, the same two are no longer novel, because they were
	// recorded while nothing was being reported.
	if got := reasons(a.check(first, anomalyDay.Add(11*time.Minute))); len(got) != 0 {
		t.Errorf("a read learned while settling was reported later: %v", got)
	}
	if got := reasons(a.check(w, anomalyDay.Add(11*time.Minute))); len(got) != 0 {
		t.Errorf("a write learned while settling was reported later: %v", got)
	}
}

// A master that has only ever read, writing.
func TestAFunctionThisMasterHasNotUsed(t *testing.T) {
	a := anomalyFor(t, "          settle: 1m")
	settled := anomalyDay.Add(2 * time.Minute)
	a.check(req(t, "10.0.0.8", "", 3, readRegs), anomalyDay)
	got := reasons(a.check(req(t, "10.0.0.8", "", 3, writeReg), settled))
	// A first write is novel twice over: the function code and the address.
	want := []string{"anomaly_new_symbol", "anomaly_new_write_point"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("a first write reported %v, wanted %v", got, want)
	}
	// And only once. The second is this master's normal traffic now.
	if got := reasons(a.check(req(t, "10.0.0.8", "", 3, writeReg), settled.Add(time.Second))); len(got) != 0 {
		t.Errorf("the same write was reported twice: %v", got)
	}
}

// A write to a register this master has not written, with the function code
// already known, so only the address can be what was novel.
func TestAnAddressThisMasterHasNotWritten(t *testing.T) {
	a := anomalyFor(t, "          settle: 1m")
	settled := anomalyDay.Add(2 * time.Minute)
	a.check(req(t, "10.0.0.8", "", 3, writeReg), anomalyDay) // register 400
	other := []byte{6, 0x01, 0xF4, 0x00, 0x0A}               // write 10 to register 500
	got := reasons(a.check(req(t, "10.0.0.8", "", 3, other), settled))
	if strings.Join(got, ",") != "anomaly_new_write_point" {
		t.Errorf("a write to an unwritten register reported %v", got)
	}
	// A read of a register nobody has written is not a new write address. The
	// signal is about what a master drives, and reading is not driving. (It is a
	// new function code here, because this master has only written so far, and
	// that finding is correct.)
	far := []byte{3, 0x0F, 0xA0, 0x00, 0x02} // read 2 registers at 4000
	got = reasons(a.check(req(t, "10.0.0.8", "", 3, far), settled.Add(time.Second)))
	if contains(got, "anomaly_new_write_point") {
		t.Errorf("a read was reported as a new write address: %v", got)
	}
}

// One master's record is not another's. Two masters doing the same thing for the
// first time are two findings, and neither teaches the other.
func TestTheRecordIsPerMaster(t *testing.T) {
	a := anomalyFor(t, "          settle: 1m")
	settled := anomalyDay.Add(2 * time.Minute)
	a.check(req(t, "10.0.0.8", "", 3, readRegs), anomalyDay)
	a.check(req(t, "10.0.0.9", "", 3, readRegs), anomalyDay)
	for _, ip := range []string{"10.0.0.8", "10.0.0.9"} {
		got := reasons(a.check(req(t, ip, "", 3, writeReg), settled))
		if len(got) != 2 {
			t.Errorf("%s reported %v for its first write", ip, got)
		}
	}
}

// The burst is about a client across every address, which is what the
// per-address rate of a value rule cannot see.
func TestABurstOfWritesAcrossAddresses(t *testing.T) {
	a := anomalyFor(t, "          settle: 1m\n          novelty: {burst: 5, burst_period: 10s}")
	settled := anomalyDay.Add(2 * time.Minute)
	// Five writes, each to a different register, inside the window. Five is the
	// bound and not past it, so nothing is a burst yet -- and every one of them
	// is a new address, which is a different finding.
	burst := false
	for i := 0; i < 5; i++ {
		w := []byte{6, 0x02, byte(i), 0x00, 0x01}
		for _, r := range reasons(a.check(req(t, "10.0.0.8", "", 3, w), settled)) {
			if r == "anomaly_write_burst" {
				burst = true
			}
		}
	}
	if burst {
		t.Fatal("five writes against a bound of five was called a burst")
	}
	sixth := []byte{6, 0x02, 0x10, 0x00, 0x01}
	got := reasons(a.check(req(t, "10.0.0.8", "", 3, sixth), settled.Add(time.Second)))
	if !contains(got, "anomaly_write_burst") {
		t.Errorf("a sixth write in the window reported %v", got)
	}
}

// The window slides, so the same six writes spread out are not a burst.
func TestWritesOutsideTheWindowAreNotABurst(t *testing.T) {
	a := anomalyFor(t, "          settle: 1m\n          novelty: {burst: 5, burst_period: 10s}")
	at := anomalyDay.Add(2 * time.Minute)
	for i := 0; i < 6; i++ {
		w := []byte{6, 0x02, byte(i), 0x00, 0x01}
		got := reasons(a.check(req(t, "10.0.0.8", "", 3, w), at))
		if contains(got, "anomaly_write_burst") {
			t.Fatalf("write %d a minute after the last was called a burst", i)
		}
		at = at.Add(time.Minute)
	}
}

// A burst is reported while the client is still settling, unlike novelty. The
// bound is a number an operator set rather than something learned, so there is
// nothing for the settling window to be about.
func TestABurstIsReportedWhileSettling(t *testing.T) {
	a := anomalyFor(t, "          settle: 1h\n          novelty: {burst: 2, burst_period: 10s}")
	var last []string
	for i := 0; i < 3; i++ {
		w := []byte{6, 0x02, byte(i), 0x00, 0x01}
		last = reasons(a.check(req(t, "10.0.0.8", "", 3, w), anomalyDay.Add(time.Duration(i)*time.Second)))
	}
	if !contains(last, "anomaly_write_burst") {
		t.Errorf("a burst during the settling window reported %v", last)
	}
	// And novelty still is not, which is the whole point of the difference.
	if contains(last, "anomaly_new_write_point") {
		t.Error("novelty was reported during the settling window")
	}
}

// Turning a detector off turns that one off and leaves the others alone.
func TestEachDetectorCanBeTurnedOff(t *testing.T) {
	for _, c := range []struct {
		name    string
		section string
		// want is what a first write reports with that detector off, in order.
		want string
	}{
		{"symbols off", "          novelty: {symbols: false, burst: 0}", "anomaly_new_write_point"},
		{"write_points off", "          novelty: {write_points: false, burst: 0}", "anomaly_new_symbol"},
	} {
		t.Run(c.name, func(t *testing.T) {
			// The burst is off throughout: it is exercised on its own below,
			// and two writes would not reach the default bound anyway.
			a := anomalyFor(t, "          settle: 1m\n"+c.section)
			settled := anomalyDay.Add(2 * time.Minute)
			a.check(req(t, "10.0.0.8", "", 3, readRegs), anomalyDay)
			got := reasons(a.check(req(t, "10.0.0.8", "", 3, writeReg), settled))
			if strings.Join(got, ",") != c.want {
				t.Errorf("a first write reported %v, wanted just %s", got, c.want)
			}
		})
	}
}

// And write_burst: 0 is off, not "bound of nought".
func TestABurstOfZeroIsOff(t *testing.T) {
	a := anomalyFor(t, "          settle: 1m\n          novelty: {burst: 0, write_points: false}")
	settled := anomalyDay.Add(2 * time.Minute)
	for i := 0; i < 50; i++ {
		w := []byte{6, 0x02, byte(i), 0x00, 0x01}
		if got := reasons(a.check(req(t, "10.0.0.8", "", 3, w), settled)); contains(got, "anomaly_write_burst") {
			t.Fatalf("write %d was called a burst with the bound turned off: %v", i, got)
		}
	}
}

// A detector enabled with nothing to detect is a configuration mistake somebody
// would spend an afternoon on, so it is refused rather than accepted quietly.
func TestADetectorWithNothingToDetectIsRefused(t *testing.T) {
	_, err := config.Parse([]byte(`
version: 1
server:
  listeners:
    - name: plant
      address: "127.0.0.1:0"
      kind: modbus
      modbus:
        upstream: plc
        anomaly:
          enabled: true
          novelty: {symbols: false, write_points: false, burst: 0}
upstreams: [{name: plc, endpoints: [{address: "127.0.0.1:502"}]}]
`))
	if err == nil {
		t.Fatal("a detector with every signal off was accepted")
	}
	if !strings.Contains(err.Error(), "nothing to detect") {
		t.Errorf("the refusal does not say why: %v", err)
	}
}

// The client bound is a bound, and reaching it is counted rather than silent.
func TestTheClientBoundIsCounted(t *testing.T) {
	a := anomalyFor(t, "          settle: 1m\n          max_clients: 8")
	for i := 0; i < 12; i++ {
		ip := fmt.Sprintf("10.0.1.%d", i)
		a.check(req(t, ip, "", 3, readRegs), anomalyDay)
	}
	if a.clients() != 8 {
		t.Errorf("the table holds %d clients against a bound of 8", a.clients())
	}
	if a.dropped() != 4 {
		t.Errorf("four clients were turned away and %d were counted", a.dropped())
	}
}

// When a client's own address bound is reached the detector stops claiming
// novelty for it, and says so.
//
// The alternative -- collapsing the ranges into one span, which is what the
// learning report does -- widens what counts as seen and would make the detector
// stop detecting while it went on looking like it worked.
func TestAMasterThatOutrunsItsAddressBoundBlindsTheDetector(t *testing.T) {
	a := anomalyFor(t, "          settle: 1m")
	settled := anomalyDay.Add(2 * time.Minute)
	// Every other register, so no two spans coalesce.
	for i := 0; i <= anomaly.DefaultPoints; i++ {
		w := []byte{6, byte(i * 2 >> 8), byte(i * 2), 0x00, 0x01}
		a.check(req(t, "10.0.0.8", "", 3, w), settled)
	}
	if a.blinded() != 1 {
		t.Fatalf("one client was blinded and %d were counted", a.blinded())
	}
	// A further new address is no longer reported, because the detector can no
	// longer tell.
	far := []byte{6, 0x7F, 0x00, 0x00, 0x01}
	if got := reasons(a.check(req(t, "10.0.0.8", "", 3, far), settled)); contains(got, "anomaly_new_write_point") {
		t.Errorf("a blinded detector still claimed novelty: %v", got)
	}
	// And the count stays at one. It counts clients, not frames: a number that
	// climbed with every write from a blinded master would say nothing about how
	// many masters the detector had stopped watching.
	if a.blinded() != 1 {
		t.Errorf("the blinded count climbed to %d on later writes", a.blinded())
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
