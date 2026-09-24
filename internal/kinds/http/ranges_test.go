package http

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/rom/xproxy/internal/config"
)

func boolp(b bool) *bool { return &b }

// What a set of ranges means, which is the only thing a policy can be
// written against: the bytes asked for, not the spelling.
func TestARangeSetIsReadAsTheBytesItAsksFor(t *testing.T) {
	p := compileRangePolicy(&config.RouteRanges{MaxRanges: 2})
	for _, tc := range []struct {
		name, in string
		want     rangeOutcome
		value    string
	}{
		// Nothing to do: one range, already canonical.
		{"one range", "bytes=0-99", rangeKeep, ""},
		{"a suffix range", "bytes=-500", rangeKeep, ""},
		{"an open range", "bytes=100-", rangeKeep, ""},
		// Overlapping and adjacent ranges are the same bytes with fewer
		// parts, which RFC 9110 section 14.2 lets a server say.
		{"overlapping", "bytes=0-99,50-199", rangeRewrite, "bytes=0-199"},
		{"adjacent", "bytes=0-99,100-199", rangeRewrite, "bytes=0-199"},
		{"contained", "bytes=0-999,100-199", rangeRewrite, "bytes=0-999"},
		{"out of order", "bytes=200-299,0-99", rangeRewrite, "bytes=0-99,200-299"},
		{"swallowed by an open range", "bytes=500-599,100-", rangeRewrite, "bytes=100-"},
		{"running into an open range", "bytes=0-99,50-", rangeRewrite, "bytes=0-"},
		{"two open ranges", "bytes=500-,100-", rangeRewrite, "bytes=100-"},
		{"two suffix ranges", "bytes=-100,-500", rangeRewrite, "bytes=-500"},
		// Whitespace is not a different set.
		{"spaces", "bytes=0-99, 100-199", rangeRewrite, "bytes=0-199"},
		// Past the bound after coalescing: the header goes, so the whole
		// representation is served.
		{"three separate ranges", "bytes=0-9,100-109,200-209", rangeDrop, ""},
		// A unit this proxy cannot read is left for the origin to
		// ignore, and something that is not a range set at all is
		// dropped so that both ends read this request the same way.
		{"another unit", "items=0-9", rangeKeep, ""},
		{"not a range set", "0-99", rangeDrop, ""},
		{"no specs", "bytes=", rangeDrop, ""},
		{"a spec with no dash", "bytes=99", rangeDrop, ""},
		{"a descending range", "bytes=99-0", rangeDrop, ""},
		{"a negative offset", "bytes=-0", rangeDrop, ""},
		{"not a number", "bytes=a-b", rangeDrop, ""},
		{"nothing at all", "bytes=-", rangeDrop, ""},
		// A set whose second spec cannot be read is dropped whole, not
		// trimmed to the part that could: a request built from the
		// readable half is a request the client never sent.
		{"one good spec and one bad", "bytes=0-99,junk", rangeDrop, ""},
		{"a good spec after a bad one", "bytes=junk,0-99", rangeDrop, ""},
		{"empty", "", rangeKeep, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, value, _ := p.apply(tc.in)
			if got != tc.want || value != tc.value {
				t.Errorf("apply(%q) = %v %q, want %v %q", tc.in, got, value, tc.want, tc.value)
			}
		})
	}
	// No policy decides nothing.
	var none *rangePolicy
	if got, _, _ := none.apply("bytes=0-9,20-29,40-49,60-69,80-89"); got != rangeKeep {
		t.Errorf("a route with no policy rewrote a header: %v", got)
	}
}

// The amplification the bound exists for: one small header asking an
// origin to assemble hundreds of parts.
func TestAHundredRangesIsOneDecision(t *testing.T) {
	value := "bytes=0-0"
	for i := 1; i < 200; i++ {
		value += fmt.Sprintf(",%d-%d", i*10, i*10+1)
	}
	drop := compileRangePolicy(&config.RouteRanges{})
	if got, _, asked := drop.apply(value); got != rangeDrop || asked != 200 {
		t.Errorf("ignore: %v after %d ranges, want the header dropped", got, asked)
	}
	refuse := compileRangePolicy(&config.RouteRanges{Action: "refuse"})
	if got, _, _ := refuse.apply(value); got != rangeDeny {
		t.Errorf("refuse: %v, want 416", got)
	}
	// More specs than are worth reading is refused as malformed rather
	// than sorted: the reading is the work the bound is there to avoid.
	huge := "bytes=0-0"
	for i := 1; i < maxRangeSpecs+10; i++ {
		huge += fmt.Sprintf(",%d-%d", i*10, i*10+1)
	}
	if got, _, _ := refuse.apply(huge); got != rangeDrop {
		t.Errorf("a set past maxRangeSpecs: %v, want it dropped unparsed", got)
	}
}

// Coalescing off means the set is counted as it arrived, which is a
// choice an operator can make and a reason to warn them.
func TestWithoutCoalescingTheSetIsCountedAsItArrived(t *testing.T) {
	p := compileRangePolicy(&config.RouteRanges{MaxRanges: 2, Coalesce: boolp(false)})
	// Three ranges that are one run of bytes: merged they would pass.
	if got, _, _ := p.apply("bytes=0-99,100-199,200-299"); got != rangeDrop {
		t.Errorf("apply = %v, want the header dropped", got)
	}
	on := compileRangePolicy(&config.RouteRanges{MaxRanges: 2})
	if got, value, _ := on.apply("bytes=0-99,100-199,200-299"); got != rangeRewrite || value != "bytes=0-299" {
		t.Errorf("with coalescing: %v %q", got, value)
	}
}

const rangesYAML = `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
upstreams:
  - {name: app, endpoints: [{address: %s}]}
routes:
  - {name: plain, hosts: [plain.test], upstream: app}
  - {name: bounded, hosts: [bounded.test], upstream: app, ranges: {max_ranges: 2}}
  - {name: strict, hosts: [strict.test], upstream: app, ranges: {max_ranges: 1, action: refuse}}
`

// End to end: what the backend is asked for, and what a client that asks
// for too much is told.
func TestTheRangePolicyDecidesWhatTheBackendIsAsked(t *testing.T) {
	b := newBackend(t, "app")
	srv, url := startServer(t, fmt.Sprintf(rangesYAML, b.addr()))
	ask := func(host, value string) (int, string) {
		t.Helper()
		r, _ := http.NewRequest(http.MethodGet, url+"/file", nil)
		r.Host = host
		if value != "" {
			r.Header.Set("Range", value)
		}
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		got := ""
		if last := b.last.Load(); last != nil {
			got = last.Header.Get("Range")
		}
		return resp.StatusCode, got
	}
	// A route with no policy relays the set as it arrived, however silly.
	if code, got := ask("plain.test", "bytes=0-9,20-29,40-49,60-69"); code != http.StatusOK || got != "bytes=0-9,20-29,40-49,60-69" {
		t.Errorf("no policy: %d %q", code, got)
	}
	// A bounded route merges what it can.
	if code, got := ask("bounded.test", "bytes=0-99,100-199"); code != http.StatusOK || got != "bytes=0-199" {
		t.Errorf("coalesced: %d %q", code, got)
	}
	// And drops what it cannot bring under the bound, so the backend is
	// asked for the whole representation rather than for many parts.
	if code, got := ask("bounded.test", "bytes=0-9,100-109,200-209"); code != http.StatusOK || got != "" {
		t.Errorf("over the bound: %d %q", code, got)
	}
	if srv.Stats().RangesDropped == 0 {
		t.Error("the dropped header was not counted")
	}
	// A strict route says so instead, and says ranges are still
	// available, so a client can ask again for fewer.
	r, _ := http.NewRequest(http.MethodGet, url+"/file", nil)
	r.Host = "strict.test"
	r.Header.Set("Range", "bytes=0-9,100-109")
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusRequestedRangeNotSatisfiable {
		t.Errorf("strict route answered %d, want 416", resp.StatusCode)
	}
	if resp.Header.Get("Accept-Ranges") != "bytes" {
		t.Errorf("the refusal does not say ranges are still available: %q", resp.Header.Get("Accept-Ranges"))
	}
	if srv.Stats().RangesRefused == 0 {
		t.Error("the refusal was not counted")
	}
	// One range still reaches the backend on the strict route.
	if code, got := ask("strict.test", "bytes=0-9"); code != http.StatusOK || got != "bytes=0-9" {
		t.Errorf("one range on the strict route: %d %q", code, got)
	}
}
