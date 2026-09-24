package udp

import (
	"testing"
	"time"
)

// A session's activity is an elapsed time, not a wall-clock one.
//
// This is a regression test for arithmetic rather than for behaviour. A
// session stamped with time.Now().UnixNano() and compared against
// time.Now() reads the wall clock twice, and Go's monotonic reading is
// lost in the conversion -- so on the one host that is guaranteed to have
// its clock set (this proxy also relays NTP) every session would expire
// at once when the clock jumped forward, and none of them ever when it
// jumped back.
func TestSessionActivityIsMeasuredOnTheMonotonicClock(t *testing.T) {
	se := &session{start: time.Now()}
	se.touch()
	if v := se.last.Load(); v < 0 || v > int64(time.Minute) {
		t.Fatalf("the activity stamp is %d, which is a wall-clock time rather than an elapsed one", v)
	}
	if d := se.idleFor(time.Now()); d < 0 || d > time.Second {
		t.Fatalf("idle %v just after a datagram", d)
	}
	// A session that has not been touched since it started is idle for
	// as long as it has existed, and not for fifty-five years.
	old := &session{start: time.Now().Add(-90 * time.Second)}
	if d := old.idleFor(time.Now()); d < 89*time.Second || d > 91*time.Second {
		t.Fatalf("idle %v for a session started ninety seconds ago", d)
	}
}
