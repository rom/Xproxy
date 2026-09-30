package docs

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/attack"
)

// docs/ATTACK.md is what somebody answering "which ATT&CK techniques does
// this see" reads, so it has to be the same table the code tags with.
// Both directions matter: a technique or a mapping the page does not name
// is a detection nobody knows about, and a technique the page names that
// the code does not have is a claim.

func attackDoc(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../docs/ATTACK.md")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestTheAttackPageNamesEveryTechnique(t *testing.T) {
	doc := attackDoc(t)
	for _, tech := range attack.All() {
		if !strings.Contains(doc, tech.ID) {
			t.Errorf("docs/ATTACK.md does not name %s (%s)", tech.ID, tech.Name)
			continue
		}
		if !strings.Contains(doc, tech.Name) {
			t.Errorf("docs/ATTACK.md names %s without MITRE's name for it, %q",
				tech.ID, tech.Name)
		}
	}
}

func TestTheAttackPageNamesNoTechniqueTheCodeDoesNotHave(t *testing.T) {
	// The link targets are stripped first: a sub-technique's identifier is
	// written with a dot and its URL with a slash, so a page naming
	// T1071.004 has "T1071/004" in the href, and scanning that would read
	// as a claim about the parent technique.
	doc := regexp.MustCompile(`\(https://attack\.mitre\.org/[^)]*\)`).
		ReplaceAllString(attackDoc(t), "")
	// Both identifier spaces, and an Enterprise sub-technique written
	// with its dot, because the page names those too.
	for _, m := range regexp.MustCompile(`T[01]\d{3}(\.\d{3})?`).FindAllString(doc, -1) {
		if !attack.Known(m) {
			t.Errorf("docs/ATTACK.md names %s, which internal/attack cannot observe: "+
				"a page that claims a detection is worse than a page that admits a gap", m)
		}
	}
}

// Both catalogues are on the page, under headings of their own, because
// an operations centre reads one of them and an assessor the other.
func TestTheAttackPageCarriesBothMatrices(t *testing.T) {
	doc := attackDoc(t)
	for _, want := range []string{
		"## The ATT&CK for ICS techniques this proxy can observe",
		"## The Enterprise ATT&CK techniques this proxy can observe",
		"`matrix`",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("docs/ATTACK.md is missing %q", want)
		}
	}
	for _, m := range []attack.Matrix{attack.MatrixICS, attack.MatrixEnterprise} {
		if len(attack.InMatrix(m)) == 0 {
			t.Errorf("the %s catalogue is empty", m)
		}
	}
}

func TestTheAttackPageNamesEveryMapping(t *testing.T) {
	doc := attackDoc(t)
	for _, m := range attack.Mappings() {
		// The row is "`reason` | T0855, T0835 |" under the kind's own
		// heading, so the reason in backticks is what to look for.
		if !strings.Contains(doc, "`"+m.Reason+"`") {
			t.Errorf("docs/ATTACK.md does not carry %s/%s", m.Kind, m.Reason)
		}
	}
	for _, kind := range attack.Kinds() {
		if !strings.Contains(doc, "#### "+kind) {
			t.Errorf("docs/ATTACK.md has no section for kind %s", kind)
		}
	}
}

// The page is findable. A document nothing links to is one nobody reads,
// which is the same rule the protocol pages are held to.
func TestTheAttackPageIsLinked(t *testing.T) {
	for _, from := range []string{"../../README.md", "../../docs/CONFIG.md"} {
		b, err := os.ReadFile(from)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), "ATTACK.md") {
			t.Errorf("%s does not link to docs/ATTACK.md", from)
		}
	}
}
