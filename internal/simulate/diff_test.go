package simulate

import (
	"strings"
	"testing"
)

const noWAFYAML = `version: 1
server:
  listeners: [{name: edge, address: "0.0.0.0:443"}]
upstreams:
  - {name: app, endpoints: [{address: "10.0.0.1:8080"}]}
routes:
  - {name: all, paths: ["/"], upstream: app}
`

const corpus = `# what the scanner flagged, and one request that has to keep working
>>> name="the injection"
GET /?id=1%27+OR+1%3D1-- HTTP/1.1
Host: shop.example.com
Connection: close

>>> name="the shift supervisor's report"
GET /reports/daily HTTP/1.1
Host: shop.example.com
Connection: close
`

// The feature, end to end: the same corpus through the configuration an estate
// has and the one it is proposing, and the short list of what moved.
func TestTheDifferentialReportNamesWhatWouldChange(t *testing.T) {
	inputs, err := ParseRequests(strings.NewReader(corpus))
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 2 {
		t.Fatalf("inputs %+v", inputs)
	}

	before := ask(t, noWAFYAML, inputs)
	after := ask(t, wafYAML, inputs)
	d := Compare(before, after)

	if !d.Differs() {
		t.Fatalf("adding a WAF changed nothing: %+v", after)
	}
	if d.Items != 2 || d.Same != 1 {
		t.Errorf("items %d same %d: one request moved and one did not", d.Items, d.Same)
	}
	if len(d.Changes) != 1 {
		t.Fatalf("changes %+v", d.Changes)
	}
	c := d.Changes[0]
	if c.How != NewlyRefused {
		t.Errorf("how %q: the injection was allowed and is now refused", c.How)
	}
	if c.Input != "the injection" {
		t.Errorf("input %q: the report names the item, so somebody can find it", c.Input)
	}
	if !strings.Contains(c.After, "waf") {
		t.Errorf("after %q: the report says which rule", c.After)
	}
	if !strings.Contains(d.Summary(), "1 newly refused") {
		t.Errorf("summary %q", d.Summary())
	}

	// And the other direction, which is the one a security reviewer reads:
	// taking the WAF away is a newly allowed request.
	back := Compare(after, before)
	if len(back.Changes) != 1 || back.Changes[0].How != NewlyAllowed {
		t.Errorf("removing the WAF: %+v", back.Changes)
	}
	// Newly allowed sorts first, because a hole is worse than an outage.
	mixed := Compare(
		[]Outcome{{Input: "a", Decision: Allowed}, {Input: "b", Decision: Refused, Reason: "waf"}},
		[]Outcome{{Input: "a", Decision: Refused, Reason: "waf"}, {Input: "b", Decision: Allowed}})
	if len(mixed.Changes) != 2 || mixed.Changes[0].How != NewlyAllowed {
		t.Errorf("order %+v", mixed.Changes)
	}
}

// An input only one side was asked about is its own kind of change, not an
// agreement.
func TestAnInputOnlyOneSideSawIsNotAnAgreement(t *testing.T) {
	d := Compare(
		[]Outcome{{Input: "a", Decision: Allowed}, {Input: "gone", Decision: Allowed}},
		[]Outcome{{Input: "a", Decision: Allowed}, {Input: "new", Decision: Refused, Reason: "waf"}})
	if d.Same != 1 || len(d.Changes) != 2 {
		t.Fatalf("%+v", d)
	}
	for _, c := range d.Changes {
		if c.How != Unanswerable {
			t.Errorf("%+v", c)
		}
	}
	if d.Items != 3 {
		t.Errorf("items %d: two on one side, two on the other, one shared", d.Items)
	}
}

// A refusal for a different reason, and an allowed request with a different
// answer, are both worth reporting and neither is a newly refused request.
func TestAChangedReasonIsNotANewRefusal(t *testing.T) {
	d := Compare(
		[]Outcome{{Input: "a", Decision: Refused, Reason: "patch:cve-2024-1234"},
			{Input: "b", Decision: Allowed, Status: 200}},
		[]Outcome{{Input: "a", Decision: Refused, Reason: "waf:942100"},
			{Input: "b", Decision: Allowed, Status: 301}})
	if d.Counts[ReasonChanged] != 1 || d.Counts[StatusChanged] != 1 {
		t.Errorf("counts %v", d.Counts)
	}
	if d.Counts[NewlyRefused] != 0 {
		t.Error("a reason change was reported as a new refusal")
	}
}

// ask runs one configuration over the inputs.
func ask(t *testing.T, yaml string, inputs []Input) []Outcome {
	t.Helper()
	r, err := Start(parse(t, yaml), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	}()
	out := make([]Outcome, 0, len(inputs))
	for _, in := range inputs {
		out = append(out, r.Ask(in))
	}
	return out
}
