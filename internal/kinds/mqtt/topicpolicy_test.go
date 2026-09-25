package mqtt

import (
	"encoding/binary"
	"net/netip"
	"strconv"
	"testing"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/mqtt"
)

// The two properties of the Sparkplug state that an end-to-end test
// cannot see: what happens after a gap, and what happens when the table
// of edge nodes is full. Both are about the policy staying usable when
// something has already gone wrong.

func sparkplug(t *testing.T, c *config.MQTTSparkplug) *sparkplugPolicy {
	t.Helper()
	p, err := compileSparkplug(c)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if p == nil {
		t.Fatal("no policy compiled")
	}
	return p
}

// payload carries a timestamp, a metric set that is never decoded, and a
// sequence number. The sequence is a varint, so 128 and above take two
// octets -- writing it as one would make the payload malformed and the
// check skip it, which is exactly the wrong thing for a test to do
// silently.
func payload(seq uint64) []byte {
	b := []byte{0x08, 0x80, 0x01, 0x12, 0x03, 'a', 'b', 'c', 0x18}
	return binary.AppendUvarint(b, seq)
}

func pub(topic string) wire.Publish { return wire.Publish{Topic: topic} }

func TestOneSequenceGapIsOneRefusal(t *testing.T) {
	p := sparkplug(t, &config.MQTTSparkplug{Enabled: true, CheckSequence: true})
	client := netip.MustParseAddr("10.0.0.9")
	topic := "spBv1.0/plant/NDATA/edge-1"
	if got := p.check(client, pub("spBv1.0/plant/NBIRTH/edge-1"), payload(0)); got != "" {
		t.Fatalf("the birth: %s", got)
	}
	if got := p.check(client, pub(topic), payload(1)); got != "" {
		t.Fatalf("the first data: %s", got)
	}
	// A gap: one message was lost, or somebody replayed one.
	if got := p.check(client, pub(topic), payload(5)); got != "sparkplug_sequence" {
		t.Fatalf("a gap: %q", got)
	}
	// And the next message in step with what arrived is allowed: the
	// state moves to what was seen, so a single lost packet does not
	// refuse the whole fleet for ever.
	if got := p.check(client, pub(topic), payload(6)); got != "" {
		t.Fatalf("after the gap: %q", got)
	}
	if got := p.check(client, pub(topic), payload(7)); got != "" {
		t.Fatalf("the message after that: %q", got)
	}
	// The wrap at 255 is the convention's, and a birth resets to zero.
	for seq := 8; seq <= 255; seq++ {
		if got := p.check(client, pub(topic), payload(uint64(seq))); got != "" {
			t.Fatalf("seq %d: %q", seq, got)
		}
	}
	if got := p.check(client, pub(topic), payload(0)); got != "" {
		t.Fatalf("the wrap to 0: %q", got)
	}
}

func TestTheEdgeNodeTableIsBoundedAndForwardsRatherThanRefuses(t *testing.T) {
	p := sparkplug(t, &config.MQTTSparkplug{Enabled: true, CheckSequence: true,
		RequireBirthBeforeData: true, MaxNodes: 4})
	client := netip.MustParseAddr("10.0.0.9")
	// Four nodes fill the table, each born.
	for i := 0; i < 4; i++ {
		node := "edge-" + strconv.Itoa(i)
		if got := p.check(client, pub("spBv1.0/plant/NBIRTH/"+node), payload(0)); got != "" {
			t.Fatalf("%s: %q", node, got)
		}
	}
	// A fifth node is not remembered, so the two checks that need the
	// table cannot be made for it -- and the message is forwarded rather
	// than refused, because refusing every message from a node because a
	// table is full would be an outage caused by a bound.
	if got := p.check(client, pub("spBv1.0/plant/NDATA/edge-99"), payload(7)); got != "" {
		t.Fatalf("a node past the bound: %q", got)
	}
	n, dropped := p.Edges()
	if n != 4 || dropped == 0 {
		t.Fatalf("edges %d dropped %d", n, dropped)
	}
	// The nodes it does hold are still checked, which is what makes the
	// bound a bound rather than a switch.
	if got := p.check(client, pub("spBv1.0/plant/NDATA/edge-0"), payload(9)); got != "sparkplug_sequence" {
		t.Fatalf("a node inside the bound: %q", got)
	}
	// A nil policy is safe: it is what a listener holds without the
	// section.
	var none *sparkplugPolicy
	if got := none.check(client, pub("spBv1.0/plant/NDATA/edge-1"), payload(1)); got != "" {
		t.Errorf("a nil policy refused: %q", got)
	}
	if n, _ := none.Edges(); n != 0 {
		t.Error("a nil policy holds edges")
	}
}

// A death ends a node: its sequence is not checked, because a death is
// published as the will of a session that is already gone, and the next
// birth is what starts the sequence again.
func TestADeathEndsTheNode(t *testing.T) {
	p := sparkplug(t, &config.MQTTSparkplug{Enabled: true, CheckSequence: true,
		RequireBirthBeforeData: true})
	client := netip.MustParseAddr("10.0.0.9")
	if got := p.check(client, pub("spBv1.0/plant/NBIRTH/edge-1"), payload(0)); got != "" {
		t.Fatalf("the birth: %s", got)
	}
	// A death with any sequence at all.
	if got := p.check(client, pub("spBv1.0/plant/NDEATH/edge-1"), payload(200)); got != "" {
		t.Fatalf("the death: %q", got)
	}
	// Data after the death, before a new birth: out of order.
	if got := p.check(client, pub("spBv1.0/plant/NDATA/edge-1"), payload(1)); got != "sparkplug_no_birth" {
		t.Fatalf("data after a death: %q", got)
	}
	// The new birth starts it again.
	if got := p.check(client, pub("spBv1.0/plant/NBIRTH/edge-1"), payload(0)); got != "" {
		t.Fatalf("the second birth: %q", got)
	}
	if got := p.check(client, pub("spBv1.0/plant/NDATA/edge-1"), payload(1)); got != "" {
		t.Fatalf("data after the second birth: %q", got)
	}
}

// A rule that refuses retain on a listener whose own policy allows it:
// the end-to-end test exercises the listener's refusal, and this is the
// other direction -- the topic being the narrower of the two. A firmware
// topic wants a retained message; an alarm topic must never have one,
// because a retained alarm is an alarm that fires again at every
// reconnection.
func TestARuleRefusesRetainTheListenerWouldAllow(t *testing.T) {
	yes := true
	no := false
	rules, err := compileTopicRules([]config.MQTTTopicRule{
		{Name: "alarms", Filters: []string{"plant/+/alarm"}, AllowRetain: &no},
		{Name: "firmware", Filters: []string{"plant/+/firmware"}, AllowRetain: &yes},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	// The listener allows retain and every quality of service: whatever is
	// refused below is the rule's doing.
	s := &server{m: &config.MQTTListener{AllowRetain: &yes}, topics: rules, maxQoS: 2}

	retained := wire.Publish{Topic: "plant/line2/alarm", Retain: true}
	reason, rule := s.checkPublish(retained)
	if reason != "retain_refused" || rule != "alarms" {
		t.Errorf("a retained alarm: %q by %q", reason, rule)
	}
	// The same topic without the retain flag is ordinary traffic.
	if reason, _ := s.checkPublish(wire.Publish{Topic: "plant/line2/alarm"}); reason != "" {
		t.Errorf("an alarm that is not retained: %q", reason)
	}
	// And the topic that wants one gets one.
	if reason, rule := s.checkPublish(wire.Publish{Topic: "plant/line2/firmware", Retain: true}); reason != "" {
		t.Errorf("a retained firmware image: %q by %q", reason, rule)
	}
	// A topic no rule names falls back to the listener, which allows it.
	if reason, _ := s.checkPublish(wire.Publish{Topic: "plant/line2/telemetry", Retain: true}); reason != "" {
		t.Errorf("a topic no rule names: %q", reason)
	}
}
