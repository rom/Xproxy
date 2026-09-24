package ntp

import (
	"testing"
	"time"
)

// Every duration this listener measures -- an association's idleness, a
// request's age, a rate limit's window, a server's holdover -- is measured
// from the listener's own start on the monotonic clock, not from the wall
// clock.
//
// The difference matters here more than almost anywhere else in this
// proxy: a time gateway sits next to a daemon whose whole job is to step
// the wall clock, and a step of an hour would otherwise expire every
// association at once or hold every outstanding request open for an hour.
// So the stamp is an elapsed duration, which is what this asserts: a
// wall-clock stamp would be some 1.7e18 nanoseconds, not a few
// microseconds since the test started.
func TestTheListenersStampsAreElapsedNotEpoch(t *testing.T) {
	s := &server{start: time.Now()}
	first := s.nanos()
	if first < 0 || first > int64(time.Minute) {
		t.Fatalf("nanos() is %d, which is not an elapsed measure from the listener's start (a wall-clock stamp is about %d)",
			first, time.Now().UnixNano())
	}
	time.Sleep(2 * time.Millisecond)
	second := s.nanos()
	if second <= first {
		t.Fatalf("the clock did not advance: %d then %d", first, second)
	}
	if got := time.Duration(second - first); got < time.Millisecond || got > 30*time.Second {
		t.Fatalf("two milliseconds of sleep measured as %v", got)
	}
}
