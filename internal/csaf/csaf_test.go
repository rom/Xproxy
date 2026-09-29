package csaf

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The documents in testdata are shaped like the real ones: a Siemens
// ProductCERT advisory with a version range and a fixed version, a CISA ICS
// advisory whose affected product is a relationship between a firmware and the
// controller it is installed on, a Siemens advisory whose range carries a
// condition this package will not evaluate, and a file that is not an advisory
// at all.

func TestADocumentIsReadAsProductsAndVersions(t *testing.T) {
	a := mustParse(t, "ssa-482757.json")
	if a.ID != "SSA-482757" {
		t.Errorf("tracking id %q", a.ID)
	}
	if a.Publisher != "Siemens ProductCERT" {
		t.Errorf("publisher %q", a.Publisher)
	}
	if a.TLP != "WHITE" {
		t.Errorf("TLP %q: an advisory's distribution label decides whether a finding may be forwarded", a.TLP)
	}
	if want := time.Date(2024, 2, 13, 0, 0, 0, 0, time.UTC); !a.Released.Equal(want) {
		t.Errorf("released %v, want %v", a.Released, want)
	}
	if a.URL == "" {
		t.Error("the self reference was not kept, so a finding cannot link to the advisory")
	}
	// Three products in the tree, two vulnerable and one fixed, each with the
	// vendor and product name the tree gave it.
	if len(a.Records) != 3 {
		t.Fatalf("%d records, want three: two affected and one fixed\n%+v", len(a.Records), a.Records)
	}
	var affected, fixed int
	for _, r := range a.Records {
		if r.Vendor != "Siemens AG" {
			t.Errorf("record %s has vendor %q", r.CVE, r.Vendor)
		}
		switch r.Status {
		case StatusAffected:
			affected++
			if r.Severity != "high" || r.Score != 7.5 {
				t.Errorf("%s scored %q %v", r.Product, r.Severity, r.Score)
			}
		case StatusFixed:
			fixed++
		}
	}
	if affected != 2 || fixed != 1 {
		t.Errorf("%d affected and %d fixed, want two and one", affected, fixed)
	}
	// The remediation and the fixed version travel with the record, because
	// "which version do I move to" is the next question after "am I affected".
	for _, r := range a.Records {
		if r.Status != StatusAffected || r.Product != "SIMATIC S7-1200 CPU family" {
			continue
		}
		if r.Fix == "" {
			t.Error("the vendor fix was dropped")
		}
		if r.Fixed != "V4.5" {
			t.Errorf("fixed in %q, want the version from the document's own fixed list", r.Fixed)
		}
	}
}

// A relationship is how an advisory says "this firmware, on that controller".
// The version lives on the firmware and the name a device reports lives on the
// controller, so both have to be matchable.
func TestARelationshipCarriesBothNames(t *testing.T) {
	a := mustParse(t, "icsa-24-012-03.json")
	var rel *Record
	for i := range a.Records {
		if a.Records[i].Status == StatusAffected {
			rel = &a.Records[i]
		}
	}
	if rel == nil {
		t.Fatal("the relationship's affected product was not read")
	}
	if rel.Product != "Modicon M340 firmware" {
		t.Errorf("product %q, want the component's name", rel.Product)
	}
	if rel.Platform != "Modicon M340 BMXP342020" {
		t.Errorf("platform %q, want the name the relationship says it is installed on", rel.Platform)
	}
	if rel.Versions.String() != "All versions < V3.60" {
		t.Errorf("versions %q, want the component's own range", rel.Versions.String())
	}
}

// A file that is not an advisory is not an error: a publisher's directory holds
// an index, a provider metadata file and a signature beside the documents.
func TestSomethingThatIsNotAnAdvisory(t *testing.T) {
	if _, err := parseFile(t, "index.txt.json"); !errors.Is(err, ErrNotCSAF) {
		t.Errorf("an index file gave %v, want a not-CSAF error", err)
	}
	for _, body := range []string{"", "{}", "not json at all", `{"document":{"csaf_version":"1.2","category":"x"}}`} {
		if _, err := Parse([]byte(body)); err == nil {
			t.Errorf("%q was read as an advisory", body)
		}
	}
	// A document that says it is a version this does not know is refused
	// rather than read optimistically, because reading half a schema is how a
	// matcher decides a device is unaffected because a field moved.
	_, err := Parse([]byte(`{"document":{"csaf_version":"3.0","category":"csaf_security_advisory",` +
		`"tracking":{"id":"X"}}}`))
	if err == nil {
		t.Error("a CSAF 3.0 document was read as 2.0")
	}
}

func mustParse(t *testing.T, name string) *Advisory {
	t.Helper()
	a, err := parseFile(t, name)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return a
}

func parseFile(t *testing.T, name string) (*Advisory, error) {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return Parse(body)
}
