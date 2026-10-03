package dns

import (
	"testing"
	"time"
)

// The prefetch claim, which is what keeps one popular name from being refreshed
// by every goroutine that notices it is about to expire.
//
// The claim matters more here than a single-flight usually does: the entries
// worth prefetching are by definition the ones being asked for constantly, so
// without it the moment an entry nears expiry is the moment every in-flight
// query for it goes upstream at once -- a thundering herd this resolver would
// have caused rather than absorbed.
func TestThePrefetchClaimIsHeldByOneRefresherAtATime(t *testing.T) {
	c := NewCache(10)
	q := Question{Name: "a.test", Type: TypeA, Class: ClassIN}
	query := mustQuery(t, 1, "a.test", TypeA)
	h, _ := ParseHeader(query)
	_, qEnd, _ := ParseQuestion(query)
	resp := AnswerA(query, qEnd, h, q, []byte{93, 184, 216, 34}, 60)
	rh, _ := ParseHeader(resp)
	now := time.Now()

	// An entry nobody has is not claimable: there is nothing to refresh, and a
	// claim granted here would be a refresh of something this resolver was
	// never asked for.
	if c.Refreshing(q) {
		t.Fatal("a claim was granted on an entry that is not in the cache")
	}
	c.Put(q, resp, qEnd, rh, time.Second, now)

	// The first caller takes the claim and the second does not.
	if !c.Refreshing(q) {
		t.Fatal("the first caller did not get the claim")
	}
	if c.Refreshing(q) {
		t.Fatal("a second caller got the claim while the first held it")
	}
	// A refresh that came back with nothing releases it, so the next attempt
	// can try again rather than the entry being stuck until it expires.
	c.Refreshed(q)
	if !c.Refreshing(q) {
		t.Fatal("the claim was not released by a refresh that produced nothing")
	}
	// And the Put that replaces the entry releases it too, which is the path a
	// successful refresh takes: it does not call Refreshed at all.
	c.Put(q, resp, qEnd, rh, time.Second, now.Add(time.Millisecond))
	if !c.Refreshing(q) {
		t.Fatal("the claim was not released by the Put that replaced the entry")
	}

	// Releasing a claim on something that is not there is not an error: the
	// entry can have been dropped by the policy, or evicted, while the refresh
	// was in flight.
	c.Refreshed(Question{Name: "absent.test", Type: TypeA, Class: ClassIN})

	// The claim is per question, so one name's refresh does not block
	// another's.
	other := Question{Name: "b.test", Type: TypeA, Class: ClassIN}
	oq := mustQuery(t, 2, "b.test", TypeA)
	oh, _ := ParseHeader(oq)
	_, oEnd, _ := ParseQuestion(oq)
	ores := AnswerA(oq, oEnd, oh, other, []byte{93, 184, 216, 35}, 60)
	orh, _ := ParseHeader(ores)
	c.Put(other, ores, oEnd, orh, time.Second, now)
	if !c.Refreshing(other) {
		t.Fatal("one name's claim blocked another's")
	}
	// Dropping the entry drops the claim with it, because the claim is a field
	// of the entry rather than a table of its own: a claim that outlived its
	// entry would stop the name ever being prefetched again.
	c.Drop(other)
	if c.Refreshing(other) {
		t.Fatal("a dropped entry was still claimable")
	}
	c.Put(other, ores, oEnd, orh, time.Second, now)
	if !c.Refreshing(other) {
		t.Fatal("a re-cached entry was not claimable")
	}
}

// How much of an entry's life is left, which is what decides when a prefetch is
// worth starting.
func TestWhatIsLeftOfAnEntrysLifeIsReportedAsAFraction(t *testing.T) {
	c := NewCache(10)
	q := Question{Name: "a.test", Type: TypeA, Class: ClassIN}
	query := mustQuery(t, 1, "a.test", TypeA)
	h, _ := ParseHeader(query)
	_, qEnd, _ := ParseQuestion(query)
	resp := AnswerA(query, qEnd, h, q, []byte{93, 184, 216, 34}, 60)
	rh, _ := ParseHeader(resp)
	now := time.Now()

	// Nothing cached: no fraction, rather than a zero that would read as "about
	// to expire" and start a prefetch for a name nobody asked for.
	if _, ok := c.Remaining(q, now); ok {
		t.Fatal("a fraction was reported for an entry that is not cached")
	}
	c.Put(q, resp, qEnd, rh, 10*time.Second, now)
	for _, c2 := range []struct {
		after time.Duration
		want  float64
	}{
		{0, 1},
		{5 * time.Second, 0.5},
		{9 * time.Second, 0.1},
	} {
		got, ok := c.Remaining(q, now.Add(c2.after))
		if !ok {
			t.Errorf("after %v no fraction was reported", c2.after)
			continue
		}
		if diff := got - c2.want; diff > 0.001 || diff < -0.001 {
			t.Errorf("after %v the fraction is %v, want %v", c2.after, got, c2.want)
		}
	}
	// At or past the TTL there is no fraction: the entry is expired, which is a
	// different question from how much of it is left.
	if _, ok := c.Remaining(q, now.Add(10*time.Second)); ok {
		t.Error("a fraction was reported for an expired entry")
	}
	if _, ok := c.Remaining(q, now.Add(time.Minute)); ok {
		t.Error("a fraction was reported long after the entry expired")
	}
}
