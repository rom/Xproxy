package mqtt

import (
	"strings"
	"testing"
)

// The bounded sets and the depth bound a learning run works within, and what a
// bound does to the filter it proposes.
//
// The thing every case here is about: a bound may cost the report detail, and it
// may never cost the proposal its narrowness. A position whose values outran
// their bound becomes `+`, which matches one level; it never becomes `#`.

func TestALevelSetStopsAtItsBound(t *testing.T) {
	m := map[string]bool{}
	full := false
	for i := 0; i < maxLearnedLevels*3; i++ {
		addBoundedStr(m, "press"+itoaMQTT(i), maxLearnedLevels, &full)
	}
	if len(m) != maxLearnedLevels {
		t.Errorf("the set holds %d values, want the bound of %d", len(m), maxLearnedLevels)
	}
	if !full {
		t.Error("the set filled up and did not say so")
	}
}

func TestARepeatedLevelDoesNotFillTheBound(t *testing.T) {
	m := map[string]bool{}
	full := false
	for i := 0; i < maxLearnedLevels; i++ {
		addBoundedStr(m, "press"+itoaMQTT(i), maxLearnedLevels, &full)
	}
	if len(m) != maxLearnedLevels || full {
		t.Fatalf("the bound's worth of values did not fit: %d, full=%v", len(m), full)
	}
	for i := 0; i < maxLearnedLevels*3; i++ {
		addBoundedStr(m, "press0", maxLearnedLevels, &full)
	}
	if len(m) != maxLearnedLevels {
		t.Errorf("a repeated value changed the set to %d", len(m))
	}
	if full {
		t.Error("a value already in the set was reported as filling the bound")
	}
}

// A position that outran its bound is proposed as `+`, and never as anything
// wider. This is the case where the report knows it has not seen everything, and
// it is exactly where reaching for `#` would be tempting.
func TestAPositionPastItsBoundIsStillOnlyAPlus(t *testing.T) {
	o := learnObs{}
	for i := 0; i < maxLearnedLevels*3; i++ {
		addLevels(&o, []string{"plant", "line3", "press" + itoaMQTT(i)})
	}
	if !o.levelsFull[2] {
		t.Fatal("the third position did not outrun its bound")
	}
	f, ok := proposeFilter(&o)
	if !ok {
		t.Fatal("no filter was proposed")
	}
	if f != "plant/line3/+" {
		t.Errorf("the filter is %q, want plant/line3/+", f)
	}
	if strings.Contains(f, "#") {
		t.Errorf("a position past its bound was widened to a multi-level wildcard: %q", f)
	}
}

// A topic deeper than the bound has its tail folded into the last level rather
// than being dropped: it is still traffic, and a report that left it out would
// say the traffic is narrower than it is.
func TestATopicPastTheDepthBoundIsFoldedNotDropped(t *testing.T) {
	deep := make([]string, maxLearnedDepth+5)
	for i := range deep {
		deep[i] = "l" + itoaMQTT(i)
	}
	levels, folded := topicLevels(strings.Join(deep, "/"))
	if !folded {
		t.Fatal("a topic past the bound was not reported as folded")
	}
	if len(levels) != maxLearnedDepth {
		t.Errorf("the folded topic has %d levels, want %d", len(levels), maxLearnedDepth)
	}
	// Nothing is lost: the tail is in the last level.
	if !strings.Contains(levels[len(levels)-1], deep[len(deep)-1]) {
		t.Errorf("the tail was dropped rather than folded: %q", levels[len(levels)-1])
	}
}

func TestATopicWithinTheDepthBoundIsNotFolded(t *testing.T) {
	levels, folded := topicLevels("plant/line3/press1/temperature")
	if folded {
		t.Error("an ordinary topic was reported as folded")
	}
	if len(levels) != 4 {
		t.Errorf("the topic has %d levels, want 4", len(levels))
	}
}

// An observation is copied before it is rendered, because the report is written
// outside the table's lock. A copy that shared the level sets would let a
// publication arriving mid-report change the report, and race on a map the
// renderer is walking.
func TestAnMQTTObservationIsCopiedDeeply(t *testing.T) {
	o := learnObs{filters: map[string]bool{"a/#": true}, ids: map[string]bool{"id-1": true}}
	addLevels(&o, []string{"plant", "line3"})
	c := cloneMQTTObs(o)
	o.levels[0]["factory"] = true
	o.levelsFull[0] = true
	o.filters["b/#"] = true
	o.ids["id-2"] = true

	if c.levels[0]["factory"] {
		t.Error("the copied level set follows the original")
	}
	if c.levelsFull[0] {
		t.Error("the copied fullness flags follow the original")
	}
	if c.filters["b/#"] {
		t.Error("the copied filter set follows the original")
	}
	if c.ids["id-2"] {
		t.Error("the copied identifier set follows the original")
	}
}

func itoaMQTT(n int) string {
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
