package docs

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/attack"
)

// docs/ATTACK.md is what somebody answering "which ATT&CK for ICS
// techniques does this see" reads, so it has to be the same table the
// code tags with. Both directions matter: a technique or a mapping the
// page does not name is a detection nobody knows about, and a technique
// the page names that the code does not have is a claim.

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
	doc := attackDoc(t)
	for _, m := range regexp.MustCompile(`T0\d{3}`).FindAllString(doc, -1) {
		if !attack.Known(m) {
			t.Errorf("docs/ATTACK.md names %s, which internal/attack cannot observe: "+
				"a page that claims a detection is worse than a page that admits a gap", m)
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
