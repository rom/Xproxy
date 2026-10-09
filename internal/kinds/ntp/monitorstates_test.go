package ntp_test

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/proxy"
)

// The states the monitor can put a time source into, each driven by a server
// that behaves that way.
//
// Folding these together would lose the distinction an operator needs. "The
// source is unusable" is not actionable; "the source says it is not
// synchronised", "the source is refusing us" and "two sources disagree and
// neither can be called wrong" are three different telephone calls. The
// event names the state and carries the reason, so this asserts both rather
// than the unhealthy counter alone.

// monQuality probes often and decides on one sample, so a state is reached in
// a second rather than in a minute.
const monQuality = `        upstream: clocks
        rate_limit: 100
        quality:
          compare_sources: true
          probe_interval: 1s
          max_disagreement: 250ms
          healthy_after: 1
          unhealthy_after: 1`

func TestTheStatesTheMonitorPutsASourceInto(t *testing.T) {
	for _, tc := range []struct {
		name string
		// server is the shape the one source answers with.
		server *timeServer
		// reason is the event this state carries.
		event, detail string
	}{
		// A server at stratum 16 is saying, in the protocol's own terms,
		// that it does not know the time. Taking its answer anyway is how a
		// fleet follows a clock that is not synchronised to anything.
		{name: "a source that says it is not synchronised",
			server: &timeServer{stratum: 16},
			event:  "ntp_source_unsynchronised", detail: "stratum 16"},
		// A kiss-o'-death is the server telling us to go away. It is not a
		// bad measurement, it is a refusal, and a monitor that recorded it
		// as a wrong clock would have an operator looking at the wrong
		// thing.
		// A kiss carries leap indicator 3 as well (RFC 5905 section 7.4),
		// so this is also the case that pins the order of the two checks:
		// read the other way round, a source that is refusing us is
		// reported as a source whose clock is wrong.
		{name: "a source refusing us with a kiss-o'-death",
			server: &timeServer{kiss: "RATE"},
			event:  "ntp_source_unreachable", detail: "kiss-o'-death: RATE"},
		{name: "a denial rather than a rate limit",
			server: &timeServer{kiss: "DENY"},
			event:  "ntp_source_unreachable", detail: "kiss-o'-death: DENY"},
		// And a source that says only that its clock is not synchronised,
		// with a stratum that is otherwise fine: that one is about the
		// clock, and it keeps its own state.
		{name: "a source whose clock is not synchronised",
			server: &timeServer{stratum: 2, leap: 3},
			event:  "ntp_source_unsynchronised",
			detail: "the server says its clock is not synchronised"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := startTimeServer(t, tc.server)
			s, _ := ntpServer(t, monQuality, src)
			cap := &monEvents{}
			s.Logs().Watch(cap)

			ev := cap.find(t, tc.event)
			if got := fmt.Sprint(ev.attrs["detail"]); got != tc.detail {
				t.Errorf("detail %q, want %q", got, tc.detail)
			}
			if got := fmt.Sprint(ev.attrs["server"]); got != src.addr() {
				t.Errorf("server %q, want %q", got, src.addr())
			}
			awaitNTPCounter(t, s, "the unhealthy source", func(sn proxy.Snapshot) bool {
				return sn.NTPSourceUnhealthy >= 1
			})
		})
	}
}

// Two sources that disagree, and nothing to break the tie.
//
// With three sources the odd one out is the wrong one. With two there is no
// majority, and the honest answer is that both are suspect: a monitor that
// picked one would be picking by its position in the configuration.
func TestTwoSourcesThatDisagreeAreBothSuspect(t *testing.T) {
	here := startTimeServer(t, &timeServer{})
	ahead := startTimeServer(t, &timeServer{offset: 5 * time.Second})
	s, _ := ntpServer(t, monQuality, here, ahead)
	cap := &monEvents{}
	s.Logs().Watch(cap)

	ev := cap.find(t, "ntp_clock_disagreement")
	if got := fmt.Sprint(ev.attrs["detail"]); got != "two sources disagree" {
		t.Errorf("detail %q", got)
	}
	// The event names both sides and both offsets, which is what makes it
	// readable without opening the configuration.
	for _, key := range []string{"source", "against", "source_offset_ms", "against_offset_ms"} {
		if _, ok := ev.attrs[key]; !ok {
			t.Errorf("the event does not carry %s: %+v", key, ev.attrs)
		}
	}
	awaitNTPCounter(t, s, "the disagreement", func(sn proxy.Snapshot) bool {
		return sn.NTPDisagreements >= 1 && sn.NTPSourceUnhealthy >= 1
	})

	// Both were marked, not one: the suspect state applies to the pair.
	suspect := cap.count("ntp_source_suspect")
	if suspect < 2 {
		t.Errorf("%d sources were marked suspect, want both", suspect)
	}
}

// awaitNTPCounter waits for a counter condition.
func awaitNTPCounter(t *testing.T, s *proxy.Server, what string, ok func(proxy.Snapshot) bool) {
	t.Helper()
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); {
		if ok(s.Stats()) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	sn := s.Stats()
	t.Fatalf("%s never happened; probes %d, failed %d, unhealthy %d, disagreements %d",
		what, sn.NTPProbes, sn.NTPProbeFailed, sn.NTPSourceUnhealthy, sn.NTPDisagreements)
}

// monEvents collects the security log.
type monEvents struct {
	mu     sync.Mutex
	events []monEvent
}

type monEvent struct {
	action, reason string
	attrs          map[string]any
}

func (c *monEvents) SecurityEvent(action, reason string, attrs []any) {
	m := map[string]any{}
	for i := 0; i+1 < len(attrs); i += 2 {
		k, _ := attrs[i].(string)
		m[k] = attrs[i+1]
	}
	c.mu.Lock()
	c.events = append(c.events, monEvent{action: action, reason: reason, attrs: m})
	c.mu.Unlock()
}

func (c *monEvents) find(t *testing.T, reason string) monEvent {
	t.Helper()
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); {
		c.mu.Lock()
		for _, e := range c.events {
			if e.reason == reason {
				c.mu.Unlock()
				return e
			}
		}
		c.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	seen := map[string]int{}
	for _, e := range c.events {
		seen[e.reason]++
	}
	t.Fatalf("no %s event; saw %v", reason, seen)
	return monEvent{}
}

func (c *monEvents) count(reason string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, e := range c.events {
		if e.reason == reason {
			n++
		}
	}
	return n
}
