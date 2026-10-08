package observability

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// alertGate is a kind's "write a security event for this refusal" switch, as the
// kinds spell it: a guard that returns early when alert_on_deny is off. The
// receiver differs by kind -- t.alerts(), s.alerts(), t.m.Alerts(), s.k.Alerts() --
// so the pattern names the call rather than the receiver.
var alertGate = regexp.MustCompile(`if !(?:\w+\.)*[aA]lerts\(\) \{\n\s*return\b`)

// banObserve is a refusal reaching the automatic-ban ladder.
var banObserve = regexp.MustCompile(`bl\.Observe\(`)

// endOfFunc is the closing brace of a top-level function, which in gofmt'd Go is
// the only `}` in the first column.
var endOfFunc = regexp.MustCompile(`(?m)^\}`)

// TestNoKindLetsTheAlertSwitchStopTheBan holds the one ordering that matters in
// every kind's refusal path at once.
//
// `alert_on_deny` is documented as turning the *record* off: "it keeps the
// counters and loses the record, which is a decision to make deliberately on a
// listener whose refusals are routine". On ten kinds it did more than that. The
// ban observation sat after the security event, inside the same early return, so
// an operator who turned the log volume down on a noisy listener also stopped
// every refusal on it from counting towards an automatic ban -- and nothing said
// so. A modbus listener in a plant, where refusals *are* routine and the knob is
// exactly the one an operator reaches for, silently lost its ban response.
//
// The two are not the same decision. The record is for a human reading it later;
// the ban is the response, and a refusal too routine to write down is still a
// refusal that counts. So the observation goes above the gate, and this holds it
// there: after any gate on the alert switch, no Observe may follow before the
// function ends.
//
// Source-reading rather than behavioural because it is an ordering within a
// function and there are twenty-one kinds with the switch: a test per kind would
// be twenty-one harnesses for one invariant, and the twenty-second kind would not
// have one at all.
func TestNoKindLetsTheAlertSwitchStopTheBan(t *testing.T) {
	var bad []string
	gates := 0
	for _, f := range kindSources(t) {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		for _, g := range alertGate.FindAllStringIndex(src, -1) {
			gates++
			rest := src[g[1]:]
			if e := endOfFunc.FindStringIndex(rest); e != nil {
				rest = rest[:e[0]]
			}
			if banObserve.MatchString(rest) {
				bad = append(bad, f+" at offset "+itoa(g[0]))
			}
		}
	}
	if gates < 30 {
		t.Fatalf("only %d gates on the alert switch were found; the spelling this test matches has changed", gates)
	}
	if len(bad) > 0 {
		t.Errorf("the ban observation is behind the alert_on_deny gate in:\n  %s\n"+
			"Move it above the gate. alert_on_deny turns the record off; it must not "+
			"turn the response off with it.", strings.Join(bad, "\n  "))
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

// kindSources is every non-test Go file under the kinds.
func kindSources(t *testing.T) []string {
	t.Helper()
	dirs, err := os.ReadDir("../../internal/kinds")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		files, err := os.ReadDir(filepath.Join("../../internal/kinds", d.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range files {
			n := e.Name()
			if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
				continue
			}
			out = append(out, filepath.Join("../../internal/kinds", d.Name(), n))
		}
	}
	if len(out) < 100 {
		t.Fatalf("only %d kind sources found; the tree has moved", len(out))
	}
	return out
}
