// Package csaf reads CSAF 2.0 security advisories and matches them against the
// devices the asset inventory has seen.
//
// The estate this is for is the one that cannot patch. An industrial site knows
// -- eventually, from a newsletter, a regulator or a vendor's portal -- that
// there is an advisory for a controller it runs; what it does not know is
// whether *its* controller, on the firmware version it is actually running, is
// one of the affected ones. Answering that by hand means reading a PDF per
// advisory against a spreadsheet nobody has updated, which is why it does not
// get done.
//
// Two things make it answerable here. The inventory beside this package already
// knows what is on the network and, for the protocols that say so, what
// firmware each device reports -- built from traffic the proxy was carrying
// anyway, on a network where a scanner is not allowed. And the vendors now
// publish machine-readable advisories: CSAF 2.0 (OASIS) is JSON, Siemens
// ProductCERT, Schneider Electric and the CISA ICS advisories all publish it,
// and a CSAF document says which products and which version ranges each CVE
// affects.
//
// So this package does one thing: it reads those documents and says, per
// device, which of them name it.
//
// # What it refuses to do
//
// The whole value of this is in the refusals, so they come first.
//
// **An unmatched version is not assessed, never "not affected".** If a device
// reports "Rel. 04.03" and an advisory says "all versions < V4.2", this package
// does not decide. It reports the device as not assessed, with the string it
// could not read, and that device appears in the list of things somebody has to
// check by hand. A tool that guessed would produce a shorter list and a wrong
// one, and the wrong entries would be the ones nobody looks at again.
//
// **A product this cannot match is unknown, not clean.** An advisory names
// products in the vendor's own words ("SIMATIC S7-1200 CPU family"); a device
// reports what it reports. Where those cannot be tied together conservatively,
// the answer is that the device's product is not in the loaded advisories --
// which is not the same sentence as "no advisory affects this device", and the
// status view says so in those words.
//
// **Nothing here is a vulnerability scan.** No probe, no version query the
// proxy invents, no request this package causes. The firmware strings come from
// exchanges that were already happening, and the advisories come from files
// somebody else downloaded.
//
// **It does not fetch.** The documents are read from a directory, which is what
// a site's own downloader (the CSAF standard has one; so does every vendor's
// portal) writes into. A process-network relay dialling out to a vendor's
// website on a schedule is the sort of thing an OT change board refuses, and
// correctly: the advisory feed would be a second network dependency in the one
// place that is supposed to have none.
//
// # What it produces
//
// One assessment per device: a state, the advisories that named it, the worst
// severity among them, and the fixed version where the document says one. The
// states are deliberately six rather than two, and five of them are not
// "affected": the useful output of a first run is the *shape* of the estate's
// exposure, including how much of it nobody can assess yet.
package csaf

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/textsafe"
)

// Bounds on one document, and on a set of them.
const (
	// MaxDocumentBytes bounds one advisory file. A CSAF document is tens of
	// kilobytes; the largest ICS advisories with a hundred products are a few
	// hundred. A file past this is not an advisory, and the bound is applied
	// before the read rather than after.
	MaxDocumentBytes = 8 << 20
	// MaxProducts bounds the products one document may name. A Siemens
	// advisory for a product family names a few dozen.
	MaxProducts = 4096
	// MaxRecords bounds the (vulnerability, product) pairs one document
	// yields, which is the product of its vulnerabilities and its products
	// and so the number worth bounding.
	MaxRecords = 65536
	// MaxNameLength bounds a vendor or product name taken from a document.
	MaxNameLength = 160
	// MaxTextLength bounds a title or a remediation's text.
	MaxTextLength = 512
)

// The product statuses a CSAF vulnerability carries, as this package keeps
// them. The document has more lists than these; the mapping is below at
// statusOf, and a list this cannot place is counted rather than assumed.
const (
	// StatusAffected is known_affected, first_affected or last_affected: the
	// vendor says this version of this product has the vulnerability.
	StatusAffected = "affected"
	// StatusNotAffected is known_not_affected: the vendor says it does not.
	// It is kept, rather than discarded as uninteresting, because it is the
	// only thing in the whole pipeline that can clear a device -- and it can
	// only do so when the version comparison succeeds.
	StatusNotAffected = "not_affected"
	// StatusFixed is fixed or first_fixed: the version carries the fix.
	StatusFixed = "fixed"
	// StatusInvestigating is under_investigation: the vendor has not said
	// yet, which is a real answer and worth reporting as itself.
	StatusInvestigating = "under_investigation"
)

// Advisory is one CSAF document, reduced to what an inventory can use.
type Advisory struct {
	// ID is document.tracking.id: SSA-482757, ICSA-24-012-03, and so on. It
	// is what an operator looks up.
	ID string `json:"id"`
	// Title is the document's title.
	Title string `json:"title,omitempty"`
	// Publisher is document.publisher.name, which is how "Siemens
	// ProductCERT" and "CISA" are told apart in a mixed directory.
	Publisher string `json:"publisher,omitempty"`
	// Category is document.category: csaf_security_advisory, csaf_vex and the
	// rest. A VEX document is read the same way and says less.
	Category string `json:"category,omitempty"`
	// Released is tracking.current_release_date.
	Released time.Time `json:"released,omitempty"`
	// Revision is tracking.version, so that a reader can tell which issue of
	// an advisory a finding came from.
	Revision string `json:"revision,omitempty"`
	// TLP is the distribution label, when the document carries one. It
	// matters because an advisory under TLP:AMBER must not be forwarded, and
	// a finding that quotes one is a forwarding.
	TLP string `json:"tlp,omitempty"`
	// URL is the document's self reference.
	URL string `json:"url,omitempty"`
	// Severity is document.aggregate_severity.text, which is the vendor's own
	// one-word summary and is not a CVSS score.
	Severity string `json:"severity,omitempty"`
	// File is where this document was read from.
	File string `json:"file,omitempty"`
	// Records are the (vulnerability, product) pairs.
	Records []Record `json:"-"`
	// Skipped counts what this could not place: a product branch with no
	// version, a product status list it does not map, a score with no
	// products. Reported rather than hidden, because a document that yields
	// nothing is either the wrong document or one this cannot read, and an
	// operator should see which.
	Skipped int `json:"skipped,omitempty"`
}

// Record is one product of one vulnerability: the unit a device is matched
// against.
type Record struct {
	// CVE is the vulnerability's identifier. A CSAF vulnerability need not
	// have one -- the standard allows a title alone -- so this may be empty
	// and Title carries the name instead.
	CVE   string
	Title string
	CWE   string
	// Status is what the document says about this product at this version.
	Status string
	// Vendor and Product are the names the product tree gave, in the vendor's
	// own words.
	Vendor, Product string
	// Platform is the product a relationship says this one is installed on:
	// "firmware V4.2 installed on CPU 1212C" gives Product "firmware" and
	// Platform "CPU 1212C", and a device reporting either name is matched.
	Platform string
	// Versions is the version or range this record is about.
	Versions Range
	// Severity, Score and ScoreKind are the CVSS figures for this product,
	// when the document scored it.
	Severity  string
	Score     float64
	ScoreKind string
	// Fix is the remediation's own words, and Fixed the versions the
	// document's own fixed list names -- taken from the product tree rather
	// than from the remediation's prose, because "update to the latest
	// version" is not a version.
	Fix    string
	FixURL string
	Fixed  string
	// ID is the document's product_id for this product, which is what ties a
	// finding back to a line in the file it came from.
	ID string
}

// ErrNotCSAF is returned for a document that is not a CSAF 2.0 advisory. It is
// separate from a parse failure because a directory of mixed files is ordinary
// -- a README, a signature, an index -- and a file that is not an advisory at
// all is skipped with a count, while an advisory this cannot read is an error.
var ErrNotCSAF = errors.New("not a CSAF 2.0 document")

// wire is the subset of the CSAF schema this reads. Everything omitted is
// omitted because a proxy cannot act on it: the notes, the acknowledgements,
// the threats, the tracking history, the revision notes.
type wire struct {
	Document struct {
		Category    string `json:"category"`
		CSAFVersion string `json:"csaf_version"`
		Title       string `json:"title"`
		Publisher   struct {
			Name     string `json:"name"`
			Category string `json:"category"`
		} `json:"publisher"`
		Tracking struct {
			ID                 string `json:"id"`
			Version            string `json:"version"`
			Status             string `json:"status"`
			CurrentReleaseDate string `json:"current_release_date"`
		} `json:"tracking"`
		Distribution struct {
			TLP struct {
				Label string `json:"label"`
			} `json:"tlp"`
		} `json:"distribution"`
		AggregateSeverity struct {
			Text string `json:"text"`
		} `json:"aggregate_severity"`
		References []struct {
			Category string `json:"category"`
			URL      string `json:"url"`
		} `json:"references"`
	} `json:"document"`
	ProductTree struct {
		Branches         []branch `json:"branches"`
		FullProductNames []struct {
			ProductID string `json:"product_id"`
			Name      string `json:"name"`
		} `json:"full_product_names"`
		Relationships []struct {
			Category                  string `json:"category"`
			ProductReference          string `json:"product_reference"`
			RelatesToProductReference string `json:"relates_to_product_reference"`
			FullProductName           struct {
				ProductID string `json:"product_id"`
				Name      string `json:"name"`
			} `json:"full_product_name"`
		} `json:"relationships"`
	} `json:"product_tree"`
	Vulnerabilities []struct {
		CVE   string `json:"cve"`
		Title string `json:"title"`
		CWE   struct {
			ID string `json:"id"`
		} `json:"cwe"`
		ProductStatus map[string][]string `json:"product_status"`
		Scores        []struct {
			Products []string `json:"products"`
			CVSSv2   *cvss    `json:"cvss_v2"`
			CVSSv3   *cvss    `json:"cvss_v3"`
			CVSSv4   *cvss    `json:"cvss_v4"`
		} `json:"scores"`
		Remediations []struct {
			Category   string   `json:"category"`
			Details    string   `json:"details"`
			URL        string   `json:"url"`
			ProductIDs []string `json:"product_ids"`
		} `json:"remediations"`
	} `json:"vulnerabilities"`
}

type cvss struct {
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

// branch is one node of the product tree. The tree nests: a vendor branch holds
// product_name branches, which hold product_version or product_version_range
// branches, which carry the product. Other categories appear in between
// (product_family, architecture, service_pack) and are walked through.
type branch struct {
	Category string   `json:"category"`
	Name     string   `json:"name"`
	Branches []branch `json:"branches"`
	Product  *struct {
		ProductID string `json:"product_id"`
		Name      string `json:"name"`
	} `json:"product"`
}

// product is one leaf of the tree: which vendor, which product, which versions.
type product struct {
	vendor, name string
	// platform is the product a relationship says this one is installed on.
	platform string
	versions Range
	// hasVersion says a version branch named this product's versions. A leaf
	// with none is a product with no version at all, which the CSAF standard
	// allows and which this treats as every version -- the same thing the
	// vendor means by naming a product and no version.
	hasVersion bool
}

// Parse reads one CSAF document.
func Parse(data []byte) (*Advisory, error) {
	if len(data) == 0 {
		return nil, ErrNotCSAF
	}
	if len(data) > MaxDocumentBytes {
		return nil, fmt.Errorf("csaf: %d bytes, past the %d-byte bound", len(data), MaxDocumentBytes)
	}
	var w wire
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotCSAF, err)
	}
	// The two fields that say this is the format. A document without them is
	// something else in the directory -- an index, a provider metadata file, a
	// signature -- and is skipped rather than reported as a broken advisory.
	if w.Document.CSAFVersion == "" || w.Document.Category == "" {
		return nil, ErrNotCSAF
	}
	if w.Document.CSAFVersion != "2.0" {
		// A version this does not know is refused rather than read
		// optimistically: reading half of a schema is how a matcher decides a
		// device is unaffected because the field moved.
		return nil, fmt.Errorf("csaf: version %q is not 2.0", clip(w.Document.CSAFVersion, 32))
	}
	if w.Document.Tracking.ID == "" {
		return nil, errors.New("csaf: document.tracking.id is required")
	}
	a := &Advisory{
		ID:        clip(w.Document.Tracking.ID, MaxNameLength),
		Title:     clip(w.Document.Title, MaxTextLength),
		Publisher: clip(w.Document.Publisher.Name, MaxNameLength),
		Category:  clip(w.Document.Category, MaxNameLength),
		Revision:  clip(w.Document.Tracking.Version, 32),
		TLP:       clip(w.Document.Distribution.TLP.Label, 32),
		Severity:  strings.ToLower(clip(w.Document.AggregateSeverity.Text, 32)),
	}
	if t, err := time.Parse(time.RFC3339, w.Document.Tracking.CurrentReleaseDate); err == nil {
		a.Released = t
	}
	for _, ref := range w.Document.References {
		if ref.Category == "self" {
			a.URL = clip(ref.URL, MaxTextLength)
			break
		}
	}
	products, skipped := w.products()
	a.Skipped += skipped
	a.records(&w, products)
	return a, nil
}

// products flattens the product tree: product_id to what it is.
func (w *wire) products() (map[string]product, int) {
	out := make(map[string]product)
	var skipped int
	for i := range w.ProductTree.Branches {
		walk(&w.ProductTree.Branches[i], product{}, out, &skipped)
	}
	// full_product_names names a product with no tree around it, so there is
	// no vendor and no version branch: the name is all there is. It is kept
	// because relationships reference these, and matched on the name alone.
	//
	// With no version named, the product is every version of itself -- the
	// same reading a tree leaf with no version branch gets, and the same thing
	// a vendor means by naming a product and no version. It errs towards
	// reporting: a device of that product is a finding to check rather than one
	// cleared by a comparison nobody made, which is the direction this package
	// errs in everywhere.
	for _, f := range w.ProductTree.FullProductNames {
		if f.ProductID == "" || len(out) >= MaxProducts {
			continue
		}
		if _, ok := out[f.ProductID]; ok {
			continue
		}
		out[f.ProductID] = product{name: clip(f.Name, MaxNameLength), versions: AllVersions()}
	}
	// A relationship is how a document says "this firmware, on that device".
	// The version lives on the component and the recognisable name usually on
	// the platform, so the relationship's own product_id inherits both: the
	// component's versions, and both names to match against.
	for _, rel := range w.ProductTree.Relationships {
		id := rel.FullProductName.ProductID
		if id == "" || len(out) >= MaxProducts {
			continue
		}
		part, ok := out[rel.ProductReference]
		if !ok {
			skipped++
			continue
		}
		joined := part
		if on, ok := out[rel.RelatesToProductReference]; ok {
			joined.platform = on.name
			if joined.vendor == "" {
				joined.vendor = on.vendor
			}
		}
		out[id] = joined
	}
	return out, skipped
}

// walk descends one branch, carrying down what the ancestors said.
func walk(b *branch, in product, out map[string]product, skipped *int) {
	cur := in
	switch b.Category {
	case "vendor":
		cur.vendor = clip(b.Name, MaxNameLength)
	case "product_name", "product_family":
		// A family and a name both contribute: "SIMATIC S7-1200" as the
		// family and "CPU 1212C" as the name is one product with a two-part
		// name, and joining them is how a device reporting either is matched.
		cur.name = joinName(cur.name, clip(b.Name, MaxNameLength))
	case "product_version":
		if v, err := ParseVersion(b.Name); err == nil {
			cur.versions = ExactVersion(v)
		} else {
			// A version branch whose value is not a version this can compare.
			// The product is still recorded -- it is a product the advisory
			// names -- with an unreadable range, so a device that matches it
			// is reported as not assessed rather than as clean.
			cur.versions = ParseRange(b.Name)
			if cur.versions.Readable() {
				cur.versions = Range{raw: b.Name, why: "a version this cannot compare"}
			}
		}
		cur.hasVersion = true
	case "product_version_range":
		cur.versions = ParseRange(b.Name)
		cur.hasVersion = true
	}
	if b.Product != nil && b.Product.ProductID != "" {
		if len(out) < MaxProducts {
			leaf := cur
			if !leaf.hasVersion {
				// A product named with no version at all. The vendor means
				// every version of it, which is also what a range of "all
				// versions" means, and saying so is better than treating the
				// product as unreadable.
				leaf.versions = AllVersions()
			}
			if leaf.name == "" {
				leaf.name = clip(b.Product.Name, MaxNameLength)
			}
			out[b.Product.ProductID] = leaf
		} else {
			*skipped++
		}
	}
	for i := range b.Branches {
		walk(&b.Branches[i], cur, out, skipped)
	}
}

func joinName(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	default:
		return clip(a+" "+b, MaxNameLength)
	}
}

// records turns the vulnerabilities into one record per product.
func (a *Advisory) records(w *wire, products map[string]product) {
	for i := range w.Vulnerabilities {
		v := &w.Vulnerabilities[i]
		// The scores and the remediations are per product, so they are
		// indexed before the statuses are walked.
		scores := map[string]*cvss{}
		kinds := map[string]string{}
		for _, s := range v.Scores {
			c, kind := pick(s.CVSSv4, s.CVSSv3, s.CVSSv2)
			if c == nil {
				a.Skipped++
				continue
			}
			for _, id := range s.Products {
				scores[id], kinds[id] = c, kind
			}
		}
		fixes := map[string][2]string{}
		for _, r := range v.Remediations {
			if r.Category != "vendor_fix" && r.Category != "mitigation" &&
				r.Category != "workaround" && r.Category != "none_available" {
				continue
			}
			for _, id := range r.ProductIDs {
				if _, seen := fixes[id]; seen {
					continue
				}
				fixes[id] = [2]string{clip(r.Details, MaxTextLength), clip(r.URL, MaxTextLength)}
			}
		}
		// The versions a fix is in, taken from the document's own fixed list
		// rather than from the remediation's prose: "update to the latest
		// version" is not a version.
		fixedIn := fixedVersions(v.ProductStatus, products)
		for list, ids := range v.ProductStatus {
			status, ok := statusOf(list)
			if !ok {
				a.Skipped += len(ids)
				continue
			}
			for _, id := range ids {
				p, ok := products[id]
				if !ok {
					a.Skipped++
					continue
				}
				if len(a.Records) >= MaxRecords {
					a.Skipped++
					continue
				}
				r := Record{CVE: clip(v.CVE, 64), Title: clip(v.Title, MaxTextLength),
					CWE: clip(v.CWE.ID, 32), Status: status,
					Vendor: p.vendor, Product: p.name, Platform: p.platform,
					Versions: p.versions, Fixed: fixedIn, ID: id}
				if c := scores[id]; c != nil {
					r.Score = c.BaseScore
					r.Severity = strings.ToLower(clip(c.BaseSeverity, 16))
					r.ScoreKind = kinds[id]
				}
				if r.Severity == "" {
					// The document's own one-word summary, when it scored
					// nothing. It is the vendor's assessment of the advisory
					// rather than of this product, and is used only as a
					// fallback so that a finding is never severity-less.
					r.Severity = a.Severity
				}
				if f, ok := fixes[id]; ok {
					r.Fix, r.FixURL = f[0], f[1]
				}
				a.Records = append(a.Records, r)
			}
		}
	}
}

// fixedVersions is the versions this vulnerability's fixed products name, as
// one string. It is what an operator needs next -- "go to V4.2.3" -- and it
// comes from the product tree rather than from prose.
func fixedVersions(status map[string][]string, products map[string]product) string {
	var out []string
	seen := map[string]bool{}
	for _, list := range []string{"fixed", "first_fixed", "recommended"} {
		for _, id := range status[list] {
			p, ok := products[id]
			if !ok || p.versions.String() == "" || seen[p.versions.String()] {
				continue
			}
			seen[p.versions.String()] = true
			out = append(out, p.versions.String())
			if len(out) == 4 {
				return strings.Join(out, ", ")
			}
		}
	}
	return strings.Join(out, ", ")
}

// statusOf maps a CSAF product status list onto what this package keeps.
//
// The lists this does not map are not errors: "recommended" names the version
// to move to rather than a state of a device, and a future schema may add
// more. They are counted as skipped so that a document yielding nothing is
// visible.
func statusOf(list string) (string, bool) {
	switch list {
	case "known_affected", "first_affected", "last_affected":
		return StatusAffected, true
	case "known_not_affected":
		return StatusNotAffected, true
	case "fixed", "first_fixed":
		return StatusFixed, true
	case "under_investigation":
		return StatusInvestigating, true
	}
	return "", false
}

// pick takes the newest CVSS version the document scored with. A document that
// carries both v3 and v4 is scoring the same vulnerability twice, and the newer
// metric is the one the vendor means.
func pick(v4, v3, v2 *cvss) (*cvss, string) {
	switch {
	case v4 != nil && v4.BaseScore > 0:
		return v4, "cvss_v4"
	case v3 != nil && v3.BaseScore > 0:
		return v3, "cvss_v3"
	case v2 != nil && v2.BaseScore > 0:
		return v2, "cvss_v2"
	}
	return nil, ""
}

// clip bounds a string a document chose and takes the control characters out.
//
// An advisory file is not traffic, but it is not this estate's writing either:
// it comes from a vendor's publishing pipeline, it is read into a status view
// and a security event, and a product name with a CSI sequence in it would be a
// log injection with an OASIS schema in front of it.
func clip(s string, n int) string {
	return textsafe.Clip(strings.TrimSpace(s), n)
}
