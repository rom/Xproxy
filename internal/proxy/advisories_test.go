package proxy

import (
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/assets"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/csaf"
	"github.com/rom/xproxy/internal/logging"
)

// logsTo is a log set whose security stream a test can read. Everything else
// goes nowhere, because what is being checked here is what an operator would
// see in the security log.
func logsTo(w io.Writer) *logging.Logs {
	drop := slog.New(slog.NewJSONHandler(io.Discard, nil))
	return &logging.Logs{Access: drop, Error: drop, Audit: drop,
		Security: slog.New(slog.NewJSONHandler(w, nil))}
}

// tryInventoryProxy builds a server and returns nil when the configuration is
// refused, which is what an unreadable advisory source has to do.
func tryInventoryProxy(t *testing.T, section string) *Server {
	t.Helper()
	cfg, err := config.Parse([]byte(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
upstreams:
  - name: u
    endpoints: [{address: "127.0.0.1:1"}]
routes:
  - {name: r, upstream: u}
` + section))
	if err != nil {
		t.Fatalf("the configuration did not parse: %v", err)
	}
	s, err := New(cfg, logging.Discard())
	if err != nil {
		return nil
	}
	return s
}

// One advisory, shaped like a Siemens one, for the estate below.
const oneAdvisory = `{
  "document": {
    "category": "csaf_security_advisory",
    "csaf_version": "2.0",
    "title": "Denial of service in SIMATIC S7-1200 CPUs",
    "publisher": {"category": "vendor", "name": "Siemens ProductCERT"},
    "tracking": {"id": "SSA-TESTONE", "status": "final", "version": "1",
      "current_release_date": "2024-02-13T00:00:00Z"},
    "aggregate_severity": {"text": "critical"}
  },
  "product_tree": {"branches": [{"category": "vendor", "name": "Siemens AG", "branches": [
    {"category": "product_name", "name": "SIMATIC S7-1200 CPU family", "branches": [
      {"category": "product_version_range", "name": "vers:all/<V4.5",
       "product": {"product_id": "P1", "name": "SIMATIC S7-1200 < V4.5"}},
      {"category": "product_version", "name": "V4.5",
       "product": {"product_id": "P2", "name": "SIMATIC S7-1200 V4.5"}}]}]}]},
  "vulnerabilities": [{
    "cve": "CVE-2024-11111",
    "product_status": {"known_affected": ["P1"], "fixed": ["P2"]},
    "scores": [{"products": ["P1"],
      "cvss_v3": {"baseScore": 7.5, "baseSeverity": "HIGH"}}],
    "remediations": [{"category": "vendor_fix", "details": "Update to V4.5 or later",
      "product_ids": ["P1"]}]
  }]
}`

// advisoryProxy is a server with an inventory and a directory of advisories.
func advisoryProxy(t *testing.T, extra string) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ssa-testone.json"), []byte(oneAdvisory), 0o600); err != nil {
		t.Fatal(err)
	}
	section := "\nasset_inventory:\n  enabled: true\n  advisories:\n    enabled: true\n" +
		"    sources:\n      - name: test\n        directory: " + dir + "\n" + extra
	return inventoryProxy(t, section), dir
}

// A controller reports its firmware through a Modbus identification response,
// and the advisory that names it turns up in the report and in the log.
func TestADeviceBelowTheAdvisoryBoundIsAffected(t *testing.T) {
	var log strings.Builder
	s, _ := advisoryProxy(t, "")
	s.logs = logsTo(&log)

	s.ObserveAsset(assets.Observation{Proto: "modbus", Listener: "line1",
		Addr: netip.MustParseAddr("10.30.1.5"), Hardware: []byte{0x00, 0x1b, 0x1b, 1, 2, 3},
		Server: true, Units: []int{1}, Funcs: []int{3},
		Maker: "Siemens", Model: "SIMATIC S7-1200 CPU 1212C DC/DC/DC", Firmware: "V4.2.1"})

	rep := s.AdvisoryReport("", false)
	if rep == nil {
		t.Fatal("no advisory report")
	}
	if rep.Counts.Documents != 1 {
		t.Fatalf("%d documents loaded", rep.Counts.Documents)
	}
	if len(rep.Assessments) != 1 {
		t.Fatalf("%d assessments: %+v", len(rep.Assessments), rep.Assessments)
	}
	got := rep.Assessments[0]
	if got.State != csaf.StateAffected {
		t.Fatalf("state %s (%s)", got.State, got.Reason)
	}
	if got.Worst != "high" {
		t.Errorf("worst severity %q", got.Worst)
	}
	if len(got.Hits) == 0 || got.Hits[0].Advisory != "SSA-TESTONE" {
		t.Errorf("hits %+v", got.Hits)
	}
	if got.Hits[0].Fixed != "V4.5" {
		t.Errorf("the version to move to was not reported: %+v", got.Hits[0])
	}
	if n := s.stats.AdvisoryAffected.Load(); n != 1 {
		t.Errorf("affected gauge %d", n)
	}
	if n := s.stats.AdvisoryFindings.Load(); n != 1 {
		t.Errorf("findings %d", n)
	}
	if !strings.Contains(log.String(), "asset_advisory_affected") {
		t.Errorf("no security event was written:\n%s", log.String())
	}
	if !strings.Contains(log.String(), "CVE-2024-11111") {
		t.Errorf("the event does not name the vulnerability:\n%s", log.String())
	}

	// The same device again, and again, is not a second event: a controller
	// that is affected stays affected until somebody updates it, and an event
	// per frame would bury the estate.
	before := log.Len()
	for i := 0; i < 3; i++ {
		s.ObserveAsset(assets.Observation{Proto: "modbus", Listener: "line1",
			Addr: netip.MustParseAddr("10.30.1.5"), Hardware: []byte{0x00, 0x1b, 0x1b, 1, 2, 3},
			Server: true, Units: []int{1}, Funcs: []int{3},
			Maker: "Siemens", Model: "SIMATIC S7-1200 CPU 1212C DC/DC/DC", Firmware: "V4.2.1"})
	}
	if log.Len() != before {
		t.Errorf("the same assessment was reported again:\n%s", log.String()[before:])
	}

	// And the updated firmware moves it, which is the half that says the
	// matching is reading the version rather than the name.
	s.ObserveAsset(assets.Observation{Proto: "modbus", Listener: "line1",
		Addr: netip.MustParseAddr("10.30.1.5"), Hardware: []byte{0x00, 0x1b, 0x1b, 1, 2, 3},
		Server: true, Maker: "Siemens", Model: "SIMATIC S7-1200 CPU 1212C DC/DC/DC",
		Firmware: "V4.5"})
	if rep := s.AdvisoryReport(csaf.StateFixed, false); len(rep.Assessments) != 1 {
		t.Errorf("the updated controller is not reported as fixed: %+v", rep.Assessments)
	}
	if n := s.stats.AdvisoryAffected.Load(); n != 0 {
		t.Errorf("the affected gauge did not come down: %d", n)
	}
}

// The refusal, end to end: a device whose firmware string is not a version
// anything can compare is not assessed, with the string in the reason -- and it
// is never reported as not affected.
func TestADeviceWhoseVersionCannotBeReadIsNotAssessed(t *testing.T) {
	var log strings.Builder
	s, _ := advisoryProxy(t, "    alert_on_not_assessed: true\n")
	s.logs = logsTo(&log)

	s.ObserveAsset(assets.Observation{Proto: "modbus", Listener: "line1",
		Addr: netip.MustParseAddr("10.30.1.6"), Hardware: []byte{0x00, 0x1b, 0x1b, 4, 5, 6},
		Server: true, Maker: "Siemens", Model: "SIMATIC S7-1200 CPU 1214C",
		Firmware: "Rel. 04.03"})

	rep := s.AdvisoryReport("", false)
	if len(rep.Assessments) != 1 {
		t.Fatalf("%d assessments", len(rep.Assessments))
	}
	got := rep.Assessments[0]
	if got.State != csaf.StateNotAssessed {
		t.Fatalf("state %s, want not_assessed", got.State)
	}
	if !strings.Contains(got.Reason, "Rel. 04.03") {
		t.Errorf("the reason does not carry the string that could not be read: %q", got.Reason)
	}
	if n := s.stats.AdvisoryNotAssessed.Load(); n != 1 {
		t.Errorf("not-assessed gauge %d", n)
	}
	if !strings.Contains(log.String(), "asset_advisory_not_assessed") {
		t.Errorf("no event for a device nobody has assessed:\n%s", log.String())
	}
	// A state filter that is not a state is the control plane's problem; here
	// the point is that the device is in neither of the two states that would
	// let somebody stop looking at it.
	for _, clean := range []string{csaf.StateNotAffected, csaf.StateFixed} {
		if got := s.AdvisoryReport(clean, false); len(got.Assessments) != 0 {
			t.Errorf("a device nobody assessed was reported as %s", clean)
		}
	}
}

// A severity floor decides which findings become events, and not which devices
// are assessed: the report still has everything.
func TestTheSeverityFloorFiltersEventsAndNotTheReport(t *testing.T) {
	var log strings.Builder
	s, _ := advisoryProxy(t, "    min_severity: critical\n")
	s.logs = logsTo(&log)

	s.ObserveAsset(assets.Observation{Proto: "modbus", Listener: "line1",
		Addr: netip.MustParseAddr("10.30.1.7"), Hardware: []byte{0x00, 0x1b, 0x1b, 7, 8, 9},
		Server: true, Maker: "Siemens", Model: "SIMATIC S7-1200 CPU 1215C",
		Firmware: "V4.2.1"})

	if strings.Contains(log.String(), "asset_advisory_affected") {
		t.Errorf("a high finding was logged under a critical floor:\n%s", log.String())
	}
	if n := s.stats.AdvisoryFindings.Load(); n != 1 {
		t.Errorf("the finding was not counted: %d", n)
	}
	rep := s.AdvisoryReport(csaf.StateAffected, false)
	if len(rep.Assessments) != 1 {
		t.Errorf("the floor hid the device from the report: %+v", rep.Assessments)
	}
}

// A device the advisories say nothing about, and the states that are not a
// verdict: "no loaded advisory names this product" is not "nothing affects it".
func TestADeviceNoAdvisoryNames(t *testing.T) {
	s, _ := advisoryProxy(t, "")
	s.ObserveAsset(assets.Observation{Proto: "modbus", Listener: "line1",
		Addr: netip.MustParseAddr("10.30.1.8"), Hardware: []byte{0x00, 0x1b, 0x1b, 9, 9, 9},
		Server: true, Maker: "Advantech", Model: "WebAccess Panel", Firmware: "V1.2"})
	rep := s.AdvisoryReport("", false)
	if len(rep.Assessments) != 1 || rep.Assessments[0].State != csaf.StateUnknownProduct {
		t.Fatalf("assessments %+v", rep.Assessments)
	}
	// A device that has never said what it is cannot be tied to a product at
	// all. It is still in the report -- "this many devices have not named
	// themselves" is a fact about the estate -- and it says so in the reason
	// rather than being counted as something nobody assessed.
	s.ObserveAsset(assets.Observation{Proto: "modbus", Listener: "line1",
		Addr: netip.MustParseAddr("10.30.1.9"), Server: true, Units: []int{1}})
	var found bool
	for _, one := range s.AdvisoryReport("", false).Assessments {
		if one.Product != "" {
			continue
		}
		found = true
		if one.State != csaf.StateUnknownProduct {
			t.Errorf("a device with no product name came back as %s", one.State)
		}
		if !strings.Contains(one.Reason, "has not said what it is") {
			t.Errorf("the reason does not say why: %q", one.Reason)
		}
	}
	if !found {
		t.Error("a device that never named itself is missing from the report")
	}
}

// A source that cannot be read is a startup error rather than an empty set: a
// proxy reporting no advisories because a path was misspelled would be claiming
// an estate has nothing against it.
func TestAnUnreadableSourceRefusesToStart(t *testing.T) {
	cfg := "\nasset_inventory:\n  enabled: true\n  advisories:\n    enabled: true\n" +
		"    sources:\n      - name: missing\n        directory: /nonexistent/csaf\n"
	if s := tryInventoryProxy(t, cfg); s == nil {
		return
	}
	t.Fatal("a proxy started with an advisory directory it could not read")
}

// Without the section there is no matcher, and every reader of it says so
// rather than answering for an estate nobody asked about.
func TestNoAdvisoriesConfigured(t *testing.T) {
	s := inventoryProxy(t, "\nasset_inventory:\n  enabled: true\n")
	if s.Advisories() != nil {
		t.Error("an advisory set nobody asked for")
	}
	if s.AdvisoryReport("", false) != nil {
		t.Error("an advisory report without advisories")
	}
	if s.Stats().AdvisoryAffected != 0 {
		t.Error("the status view reports an assessment that never ran")
	}
}
