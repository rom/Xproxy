package iec104

import (
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/iec104"
)

// The authentication an association has shown, and how long it counts for.
//
// The expiry lives here rather than in an end-to-end test because waiting out a
// window is not something a test should do: the arithmetic is the thing worth
// asserting, and it is one function.

func TestAnAssociationWithNoExchangeIsNeverFresh(t *testing.T) {
	var a authState
	if ok, at := a.fresh(time.Now().Add(-time.Hour)); ok || !at.IsZero() {
		t.Errorf("an association that never authenticated reads fresh=%v at=%v", ok, at)
	}
}

// "Never" has to be distinguishable from "long ago", which is why the state
// carries a flag beside the instant: the zero time is a valid instant, and an
// association that authenticated at it is not one that never did.
func TestAnAuthenticationExpiresWithItsWindow(t *testing.T) {
	var a authState
	now := time.Date(2026, time.September, 28, 12, 0, 0, 0, time.UTC)
	a.observe(&wire.ASDU{Type: wire.SChNA1, Common: 1}, false, now)
	a.observe(&wire.ASDU{Type: wire.SRpNA1, Common: 1}, true, now)
	a.observe(&wire.ASDU{Type: wire.SRpNA1, Common: 1, Cause: wire.CauseActCon}, false, now)

	for _, tc := range []struct {
		name  string
		at    time.Time
		since time.Duration
		want  bool
	}{
		{"straight away", now, time.Minute, true},
		{"inside the window", now.Add(30 * time.Second), time.Minute, true},
		{"exactly at the window", now.Add(time.Minute), time.Minute, true},
		{"just past it", now.Add(time.Minute + time.Nanosecond), time.Minute, false},
		{"long past it", now.Add(time.Hour), time.Minute, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ok, at := a.fresh(tc.at.Add(-tc.since))
			if ok != tc.want {
				t.Errorf("fresh=%v, want %v", ok, tc.want)
			}
			if at != now {
				t.Errorf("the instant is %v, want %v", at, now)
			}
		})
	}
}

// A reply counts only after a challenge from, and a positive confirmation by,
// the station. In particular, a client cannot authenticate itself by naming the
// reply type.
func TestOnlyACompletedExchangeCounts(t *testing.T) {
	now := time.Now()
	var a authState
	a.observe(&wire.ASDU{Type: wire.SRpNA1, Common: 1}, true, now)
	a.observe(&wire.ASDU{Type: wire.SRpNA1, Common: 1, Cause: wire.CauseActCon}, false, now)
	if ok, _ := a.fresh(now.Add(-time.Minute)); ok {
		t.Fatal("an unsolicited reply counted as authentication")
	}
	a.observe(&wire.ASDU{Type: wire.SChNA1, Common: 1}, false, now)
	a.observe(&wire.ASDU{Type: wire.SRpNA1, Common: 1}, true, now)
	a.observe(&wire.ASDU{Type: wire.SRpNA1, Common: 1, Cause: wire.CauseActCon, Negative: true}, false, now)
	if ok, _ := a.fresh(now.Add(-time.Minute)); ok {
		t.Fatal("a rejected reply counted as authentication")
	}
	a.observe(&wire.ASDU{Type: wire.SChNA1, Common: 1}, false, now)
	a.observe(&wire.ASDU{Type: wire.SRpNA1, Common: 1}, true, now)
	if !a.observe(&wire.ASDU{Type: wire.SRpNA1, Common: 1, Cause: wire.CauseActCon}, false, now) {
		t.Fatal("a completed exchange was not observed")
	}
	if ok, _ := a.fresh(now.Add(-time.Minute)); !ok {
		t.Fatal("a completed exchange did not count as authentication")
	}
}

// A later authentication moves the instant forward, so an association that keeps
// authenticating keeps its commands.
func TestALaterAuthenticationRefreshesTheAssociation(t *testing.T) {
	var a authState
	first := time.Date(2026, time.September, 28, 12, 0, 0, 0, time.UTC)
	a.observe(&wire.ASDU{Type: wire.SAsNA1, Common: 1}, true, first)
	a.observe(&wire.ASDU{Type: wire.SAsNA1, Common: 1, Cause: wire.CauseActCon}, false, first)
	second := first.Add(time.Hour)
	a.observe(&wire.ASDU{Type: wire.SAsNA1, Common: 1}, true, second)
	a.observe(&wire.ASDU{Type: wire.SAsNA1, Common: 1, Cause: wire.CauseActCon}, false, second)
	ok, at := a.fresh(second.Add(-time.Minute))
	if !ok || at != second {
		t.Errorf("fresh=%v at=%v, want true and %v", ok, at, second)
	}
}

func TestTheAuthenticationWindowDefault(t *testing.T) {
	p, err := compileAuthentication(&config.IEC104Authentication{Require: true})
	if err != nil {
		t.Fatal(err)
	}
	if p.window != defaultAuthWindow {
		t.Errorf("the default window is %v, want %v", p.window, defaultAuthWindow)
	}
	if !p.on() {
		t.Error("a listener that requires authentication says the policy is off")
	}
	// And an unconfigured listener requires nothing, so a substation estate that
	// does not implement 60870-5-7 -- which is most of them -- is not refused
	// every command on the first day.
	if p, err = compileAuthentication(nil); err != nil {
		t.Fatal(err)
	} else if p.on() {
		t.Error("an unconfigured listener requires authentication")
	}
	if _, err := compileAuthentication(&config.IEC104Authentication{
		Require: true, Window: config.Duration(-time.Second),
	}); err == nil {
		t.Error("a negative window loaded")
	}
}
