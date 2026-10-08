package observability

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// denyEvent is a refusal being written to the security log. The action argument may
// wrap onto the next line, so the pattern spans one.
var denyEvent = regexp.MustCompile(`SecurityEvent\([^,]+,\s*"deny"`)

// alertSwitch is a condition that reads the kind's alert switch, in each of the
// four spellings the kinds use for it: the early-return accessor bangate_test.go
// matches (`if !t.alerts() { return`), the positive wrapper (`if t.alerts() {`),
// the bool a closure captures (`if !alerts {`, which is dns), and the field read
// straight off the server (`if !t.alertOnDeny {`, which is bacnet).
//
// This is a necessary condition the source can be read for, not a proof: it says
// the function consults the switch before it writes the record, not that every
// path to the record passes through the branch. The behavioural tests in the kind
// packages are what establish that; this is the sweep that finds the site nobody
// remembered to wire at all.
var alertSwitch = regexp.MustCompile(`if !?(?:\w+\.)*(?:[aA]lerts\(\)|[aA]lerts\b|[aA]lertOnDeny\b)`)

// TestEveryRefusalRecordIsBehindTheAlertSwitch holds the promise the setting makes.
//
// `alert_on_deny: false` is documented as losing the security event for every
// refusal on the listener. A kind that has the setting and writes a refusal from
// somewhere the gate does not cover keeps writing that one -- so an operator who
// turned the setting off still gets events, from a path nobody wrote down, and the
// setting is a lie about part of the listener rather than a control.
//
// This is where the per-kind wiring is actually checked: a kind has one or two
// funnels and then the odd site that grew its own event -- an ICAP verdict, an MFA
// failure, a channel policy, a dynamic-channel refusal. The funnels are easy to
// remember and those are not.
//
// Source-reading because it is a reachability question across a package and there
// are twenty-six kinds with the setting: a behavioural test per site would be one
// harness per refusal reason, and the reason added tomorrow would have none.
func TestEveryRefusalRecordIsBehindTheAlertSwitch(t *testing.T) {
	cfg, err := os.ReadFile("../../internal/config/config.go")
	if err != nil {
		t.Fatal(err)
	}
	listener, ok := structBody(string(cfg), "Listener")
	if !ok {
		t.Fatal("the Listener struct has moved")
	}
	var ungated []string
	kinds, events := 0, 0
	for _, m := range kindSection.FindAllStringSubmatch(listener, -1) {
		field, kind := m[2], m[3]
		if notKinds[kind] {
			continue
		}
		body, ok := structBody(string(cfg), field)
		if !ok || !strings.Contains(body, `yaml:"alert_on_deny"`) {
			continue
		}
		kinds++
		for _, f := range kindFiles(t, kind) {
			src, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			for _, fn := range topLevelFuncs(string(src)) {
				for _, e := range denyEvent.FindAllStringIndex(fn.body, -1) {
					events++
					gate := alertSwitch.FindStringIndex(fn.body)
					if gate == nil || gate[1] > e[0] {
						ungated = append(ungated, f+" "+fn.name)
						break
					}
				}
			}
		}
	}
	if kinds < 20 || events < 30 {
		t.Fatalf("examined %d kinds and %d refusal records; the shapes this test matches have changed", kinds, events)
	}
	sort.Strings(ungated)
	if len(ungated) > 0 {
		t.Errorf("these write a refusal record that alert_on_deny cannot silence:\n  %s\n"+
			"Either gate the event on the kind's alerts(), or route it through the "+
			"kind's deny funnel, which is gated.", strings.Join(unique(ungated), "\n  "))
	}
}

func unique(in []string) []string {
	var out []string
	for i, s := range in {
		if i == 0 || s != in[i-1] {
			out = append(out, s)
		}
	}
	return out
}

type topFunc struct {
	name string
	body string
}

// topLevelFuncs splits gofmt'd Go into its top-level functions: each runs from a
// line beginning "func " to the closing brace in the first column.
func topLevelFuncs(src string) []topFunc {
	var out []topFunc
	for i := 0; ; {
		k := strings.Index(src[i:], "\nfunc ")
		if k < 0 {
			return out
		}
		start := i + k + 1
		nl := strings.IndexByte(src[start:], '\n')
		if nl < 0 {
			return out
		}
		rest := src[start:]
		end := len(rest)
		switch first := rest[:nl]; {
		case strings.Contains(first, "{") && strings.HasSuffix(first, "}"):
			// A one-line body. Without this the function runs on to the
			// next closing brace in the first column, swallowing the
			// function after it -- and the gate of the swallowed one
			// then covers both.
			end = nl
		default:
			if e := endOfFunc.FindStringIndex(rest); e != nil {
				end = e[1]
			}
		}
		out = append(out, topFunc{name: strings.TrimSuffix(rest[:nl], " {"), body: rest[:end]})
		i = start + end
	}
}

// kindFiles is the non-test Go files of one kind.
func kindFiles(t *testing.T, kind string) []string {
	t.Helper()
	dir := filepath.Join("../../internal/kinds", kind)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		out = append(out, filepath.Join(dir, n))
	}
	return out
}
