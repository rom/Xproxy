package config

import (
	"strings"
	"testing"
	"time"
)

// sseRouteConfig wraps an sse_guard in the smallest configuration that carries
// a route.
func sseRouteConfig(guard string) string {
	return `
version: 1
server:
  listeners:
    - {name: main, address: ":8080"}
upstreams:
  - name: app
    endpoints: [{address: 127.0.0.1:9000}]
routes:
  - name: events
    paths: [/events]
    upstream: app
    sse_guard:
` + guard
}

func sseGuardOf(t *testing.T, guard string) *SSEGuard {
	t.Helper()
	cfg, err := ParseWith([]byte(sseRouteConfig(guard)), false)
	if err != nil {
		t.Fatal(err)
	}
	g := cfg.Routes[0].SSEGuard
	if g == nil {
		t.Fatal("no sse_guard section")
	}
	return g
}

// Writing `sse_guard: {}` is enough to get the policy, so the defaults are
// what most routes run with and are worth pinning: an event bound, a line
// bound, a field count, the cursor's length, the inspect bound, and the three
// settings whose default is the safe reading rather than the permissive one.
func TestTheSSEGuardDefaultsAreTheOnesARouteRunsWith(t *testing.T) {
	g := sseGuardOf(t, "      max_events: 0\n")

	for _, c := range []struct {
		name      string
		got, want int64
	}{
		{"max_event_bytes", g.MaxEventBytes, 1 << 20},
		{"max_line_bytes", g.MaxLineBytes, 64 << 10},
		{"max_inspect_bytes", g.MaxInspectBytes, 64 << 10},
		{"max_fields", int64(g.MaxFields), 256},
		{"max_id_bytes", int64(g.MaxIDBytes), 256},
		{"max_inflate_ratio", int64(g.MaxInflateRatio), 100},
	} {
		if c.got != c.want {
			t.Errorf("%s defaulted to %d, want %d", c.name, c.got, c.want)
		}
	}
	// The data of an event is read and its comments are not, compression is
	// stripped rather than carried, and the answer to a refusal is to end the
	// stream -- because on this protocol the response has already begun.
	if g.Inspect != "data" {
		t.Errorf("inspect defaulted to %q, want data", g.Inspect)
	}
	if g.Compression != "strip" {
		t.Errorf("compression defaulted to %q, want strip", g.Compression)
	}
	if g.Action != "close" {
		t.Errorf("action defaulted to %q, want close", g.Action)
	}
}

// Every bound is checked against its own range, because a bound outside it is
// either a typo or a policy that cannot be reached.
func TestTheSSEBoundsAreCheckedAgainstTheirOwnRanges(t *testing.T) {
	for _, c := range []struct {
		name, guard, want string
	}{
		{"an event bound under the smallest event", "      max_event_bytes: 32\n",
			"max_event_bytes: must be between 64 B and 64 MiB"},
		{"an event bound past the largest", "      max_event_bytes: 134217728\n",
			"max_event_bytes: must be between 64 B and 64 MiB"},
		{"a line bound under the smallest line", "      max_line_bytes: 32\n",
			"max_line_bytes: must be between 64 B and 1 MiB"},
		{"a line bound past the largest", "      max_line_bytes: 2097152\n",
			"max_line_bytes: must be between 64 B and 1 MiB"},
		{"no fields at all", "      max_fields: -1\n", "max_fields: must be between 1 and 4096"},
		{"more fields than an event has", "      max_fields: 5000\n",
			"max_fields: must be between 1 and 4096"},
		{"a negative rate", "      events_per_second: -1\n",
			"events_per_second: must be between 0 and 1000000"},
		{"a rate nothing could send", "      events_per_second: 2000000\n",
			"events_per_second: must be between 0 and 1000000"},
		{"a negative event count", "      max_events: -1\n", "max_events: must not be negative"},
		{"a negative stream bound", "      max_stream_bytes: -1\n",
			"max_stream_bytes: must not be negative"},
		{"a duration under a second", "      max_duration: 100ms\n",
			"max_duration: must be 0 or between 1s and 168h"},
		{"a duration past a week", "      max_duration: 200h\n",
			"max_duration: must be 0 or between 1s and 168h"},
		{"an idle timeout under a second", "      idle_timeout: 100ms\n",
			"idle_timeout: must be 0 or between 1s and 24h"},
		{"an idle timeout past a day", "      idle_timeout: 48h\n",
			"idle_timeout: must be 0 or between 1s and 24h"},
		{"a cursor of no octets", "      max_id_bytes: -1\n",
			"max_id_bytes: must be between 1 and 8192"},
		{"a cursor longer than any", "      max_id_bytes: 9000\n",
			"max_id_bytes: must be between 1 and 8192"},
		{"a retry floor under a millisecond", "      min_retry: 100us\n",
			"min_retry: must be 0 or between 1ms and 1h"},
		{"a retry floor past an hour", "      min_retry: 2h\n",
			"min_retry: must be 0 or between 1ms and 1h"},
		{"an inspect bound under the smallest event", "      max_inspect_bytes: 32\n",
			"max_inspect_bytes: must be between 64 B and 16 MiB"},
		{"an inspect bound past the largest", "      max_inspect_bytes: 33554432\n",
			"max_inspect_bytes: must be between 64 B and 16 MiB"},
		{"an inflate ratio of one", "      compression: inspect\n      max_inflate_ratio: 1\n",
			"max_inflate_ratio: must be between 2 and 10000"},
		{"an inflate ratio nothing bounds", "      compression: inspect\n      max_inflate_ratio: 20000\n",
			"max_inflate_ratio: must be between 2 and 10000"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseWith([]byte(sseRouteConfig(c.guard)), false)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error is %v, which does not contain %q", err, c.want)
			}
		})
	}
	// And the bounds a route may legitimately write, including the zero that
	// means "no bound" on the three that have one.
	g := sseGuardOf(t, `      max_event_bytes: 65536
      max_line_bytes: 8192
      max_fields: 64
      events_per_second: 10
      max_events: 1000
      max_stream_bytes: 1048576
      max_duration: 1h
      idle_timeout: 30s
      max_id_bytes: 128
      min_retry: 1s
      max_inspect_bytes: 32768
`)
	if g.MaxEventBytes != 65536 || g.MaxFields != 64 || g.MaxDuration.D() != time.Hour ||
		g.MinRetry.D() != time.Second {
		t.Errorf("a configuration inside every range compiled to %+v", g)
	}
}

// The words each setting takes, and nothing else: a value nobody implements
// is a refusal at load rather than a policy that silently does something
// else.
func TestEverySSEEnumerationRefusesWhatItDoesNotMean(t *testing.T) {
	for _, c := range []struct {
		name, guard, want string
	}{
		{"an inspect mode that is not one", "      inspect: some\n",
			"inspect: must be none, data or all"},
		{"a compression policy that is not one", "      compression: maybe\n",
			"compression: must be strip, refuse or inspect"},
		// There is no third answer on this protocol: the response has begun,
		// so an event cannot be refused on its own.
		{"refusing a single event", "      action: refuse\n", "action: must be close or log"},
		{"an unknown-event policy that is not one", "      unknown_events: refuse\n",
			"unknown_events: must be allow, observe or deny"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseWith([]byte(sseRouteConfig(c.guard)), false)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error is %v, which does not contain %q", err, c.want)
			}
		})
	}
}

// The pairs that have to agree, which are the ones a reader of the
// configuration would assume agree.
func TestTheSSESettingsThatHaveToAgreeAreChecked(t *testing.T) {
	for _, c := range []struct {
		name, guard, want string
	}{
		{"patterns with nothing to match against", "      inspect: none\n      deny_patterns: [secret]\n",
			"deny_patterns needs inspect: data or all"},
		{"a pattern that is not one", "      deny_patterns: [\"(\"]\n",
			"deny_patterns[0]:"},
		{"a cursor pattern that is not one", "      last_event_id_pattern: \"[\"\n",
			"last_event_id_pattern:"},
		{"refusing every event this route carries", "      unknown_events: deny\n",
			"refuses every event this route carries"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseWith([]byte(sseRouteConfig(c.guard)), false)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error is %v, which does not contain %q", err, c.want)
			}
		})
	}
	// unknown_events: deny is a policy as soon as something is allowed, by
	// either of the two lists that allow something.
	for _, guard := range []string{
		"      unknown_events: deny\n      allow_events: [tick]\n",
		"      unknown_events: deny\n      events: [{name: tick}]\n",
	} {
		if _, err := ParseWith([]byte(sseRouteConfig(guard)), false); err != nil {
			t.Errorf("%s: %v", strings.TrimSpace(guard), err)
		}
	}
}

// The per-name policy, where a name that cannot be an `event:` field value is
// a rule that would never match anything.
func TestTheSSEEventListIsCheckedNameByName(t *testing.T) {
	for _, c := range []struct {
		name, guard, want string
	}{
		{"a type with no name", "      events: [{max_bytes: 1024}]\n", "name is required"},
		{"a name with a colon in it", "      events: [{name: \"a:b\"}]\n",
			"cannot be an event name"},
		{"a name with a newline in it", "      events: [{name: \"a\\nb\"}]\n",
			"cannot be an event name"},
		{"a name twice", "      events: [{name: tick}, {name: tick}]\n", "is named twice"},
		{"a bound above the route's", "      max_event_bytes: 4096\n      events: [{name: tick, max_bytes: 8192}]\n",
			"max_bytes: must be between 0 and the route's max_event_bytes (4096)"},
		{"a negative bound", "      events: [{name: tick, max_bytes: -1}]\n",
			"max_bytes: must be between 0 and the route's max_event_bytes"},
		{"a negative rate", "      events: [{name: tick, events_per_second: -1}]\n",
			"events_per_second: must be between 0 and 1000000"},
		{"a rate nothing could send", "      events: [{name: tick, events_per_second: 2000000}]\n",
			"events_per_second: must be between 0 and 1000000"},
		{"an allowed name that is not a name", "      allow_events: [\"a:b\"]\n",
			"allow_events[0]:"},
		{"a denied name that is not a name", "      deny_events: [\"a\\nb\"]\n",
			"deny_events[0]:"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseWith([]byte(sseRouteConfig(c.guard)), false)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error is %v, which does not contain %q", err, c.want)
			}
		})
	}
	// A per-name policy that is inside every bound compiles, and keeps what
	// was written.
	g := sseGuardOf(t, `      max_event_bytes: 65536
      events:
        - {name: tick, max_bytes: 1024, events_per_second: 1}
        - {name: measurement, max_bytes: 32768}
`)
	if len(g.Events) != 2 || g.Events[0].Name != "tick" || g.Events[0].MaxBytes != 1024 ||
		g.Events[1].MaxBytes != 32768 {
		t.Errorf("the event list compiled to %+v", g.Events)
	}
}

// The four warnings, which are about a configuration that is legal and reads
// as a mistake. A warning that fires on a correct configuration teaches
// people to ignore them all, so each of these is checked both ways.
func TestTheSSEWarningsFireOnlyWhereTheyShould(t *testing.T) {
	for _, c := range []struct {
		name, guard, want string
	}{
		{"a cursor pattern with no cursor",
			"      allow_last_event_id: false\n      last_event_id_pattern: \"^[0-9]+$\"\n",
			"no cursor reaches the application"},
		{"a ratio nothing reads",
			"      compression: strip\n      max_inflate_ratio: 200\n",
			"only read with compression: inspect"},
		{"a policy outside the allow list",
			"      allow_events: [tick]\n      events: [{name: measurement}]\n",
			"is not in allow_events"},
		{"a name on both lists",
			"      allow_events: [tick]\n      deny_events: [tick]\n",
			"deny wins"},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := ParseWith([]byte(sseRouteConfig(c.guard)), false)
			if err != nil {
				t.Fatal(err)
			}
			if !hasAdvice(cfg, c.want) {
				t.Errorf("no warning containing %q: %v", c.want, cfg.Advice())
			}
		})
	}
	// And the configuration each of them is about, written correctly: a
	// cursor pattern with the cursor on, a ratio where it is read, a policy
	// inside the allow list, and a name on one list.
	cfg, err := ParseWith([]byte(sseRouteConfig(`      last_event_id_pattern: "^[0-9]+$"
      compression: inspect
      max_inflate_ratio: 200
      allow_events: [tick, measurement]
      deny_events: [internal]
      events: [{name: tick, max_bytes: 1024}]
`)), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, unwanted := range []string{"no cursor reaches the application",
		"only read with compression: inspect", "is not in allow_events", "deny wins"} {
		if hasAdvice(cfg, unwanted) {
			t.Errorf("a correct configuration was warned about %q: %v", unwanted, cfg.Advice())
		}
	}
}
