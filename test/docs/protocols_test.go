// Package docs holds the tests that keep the documentation and the code
// from drifting apart where neither can be derived from the other.
//
// The per-protocol pages are the case this package was written for.
// docs/CONFIG.md is checked against the schema by reflection, so a new
// setting cannot go undocumented. Nothing does that for a *protocol*: a
// new listener kind can be registered, rostered, configured and shipped
// without anybody writing down what the protocol is, what security it was
// designed with, or what this relay decided to read -- and that is the
// page an engineer reads first, before they have any opinion about which
// settings to write.
package docs

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/listener"
)

// dir is where the pages live, relative to this package.
const dir = "../../docs/protocols"

// required are the headings every page carries, in this order.
//
// The order is part of the contract rather than a style preference: a
// reader arriving at one of these pages wants the protocol before the
// policy and the policy before the reference, and a page that answered
// "which settings are there" before "what is this protocol" would be a
// second copy of docs/CONFIG.md.
var required = []string{
	"## On the wire",
	"## What the protocol gives you",
	"## What this listener decides",
	"## What it does not do",
	"## Standards",
}

func TestEveryKindHasAProtocolPage(t *testing.T) {
	for _, kind := range listener.Kinds() {
		if _, err := os.Stat(filepath.Join(dir, kind+".md")); err != nil {
			t.Errorf("the roster names the kind %q, and docs/protocols/%s.md does not exist", kind, kind)
		}
	}
}

func TestNoPageNamesAKindThatDoesNotExist(t *testing.T) {
	for _, name := range pages(t) {
		if _, ok := listener.RoleOf(name); !ok {
			t.Errorf("docs/protocols/%s.md describes a kind the roster does not name", name)
		}
	}
}

// TestEveryPageIsComplete is the part that stops a page from being a
// stub. Each heading has to be there, and each has to have something
// under it: a page whose sections are all empty passes a test that only
// looks for the headings, and is worse than no page at all, because a
// reader has already spent their trust by the time they find out.
func TestEveryPageIsComplete(t *testing.T) {
	for _, name := range pages(t) {
		text := read(t, name)
		if !strings.HasPrefix(text, "# ") {
			t.Errorf("docs/protocols/%s.md does not begin with a title", name)
		}
		at := 0
		for _, h := range required {
			i := strings.Index(text, "\n"+h+"\n")
			if i < 0 {
				t.Errorf("docs/protocols/%s.md has no %q section", name, h)
				continue
			}
			if i < at {
				t.Errorf("docs/protocols/%s.md has %q out of order", name, h)
			}
			at = i
			if n := len(strings.TrimSpace(section(text, h))); n < 200 {
				t.Errorf("docs/protocols/%s.md: %q holds %d characters, which is a stub", name, h, n)
			}
		}
	}
}

// TestEveryPageLinksToItsSettings is the other half of a page being an
// introduction rather than a replacement: it has to hand the reader on to
// the reference, at a heading that exists.
//
// The anchor is checked rather than assumed because docs/CONFIG.md spells
// its per-kind headings two ways -- the twenty-two older kinds as
// `### server.listeners[].<kind>` and the newest as `## <kind>` -- so the
// anchor a page needs is not derivable from the kind's name, and a link
// written from the wrong guess renders as a link that silently goes
// nowhere.
func TestEveryPageLinksToItsSettings(t *testing.T) {
	anchors := headings(t, "../../docs/CONFIG.md")
	for _, name := range pages(t) {
		text := read(t, name)
		m := regexp.MustCompile(`\(\.\./CONFIG\.md#([a-z0-9._-]+)\)`).FindAllStringSubmatch(text, -1)
		if len(m) == 0 {
			t.Errorf("docs/protocols/%s.md does not link into ../CONFIG.md", name)
			continue
		}
		for _, one := range m {
			if !anchors[one[1]] {
				t.Errorf("docs/protocols/%s.md links to ../CONFIG.md#%s, which is not a heading",
					name, one[1])
			}
		}
	}
}

// headings are the anchors a Markdown file's headings produce, by the rule
// the forges use: lower case, punctuation but for hyphens dropped, spaces
// to hyphens.
func headings(t *testing.T, path string) map[string]bool {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Periods go too, which is what the forges do and what the links
	// already in docs/CHANGELOG.md were written against.
	drop := regexp.MustCompile(`[^\w\s-]`)
	space := regexp.MustCompile(`\s+`)
	out := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "#") {
			continue
		}
		title := strings.TrimSpace(strings.TrimLeft(line, "#"))
		if title == "" {
			continue
		}
		s := drop.ReplaceAllString(strings.ToLower(title), "")
		out[space.ReplaceAllString(strings.TrimSpace(s), "-")] = true
	}
	if len(out) == 0 {
		t.Fatalf("%s has no headings", path)
	}
	return out
}

// TestTheIndexNamesEveryPage keeps docs/protocols/README.md from being
// the one file nobody updates.
func TestTheIndexNamesEveryPage(t *testing.T) {
	index, err := os.ReadFile(filepath.Join(dir, "README.md"))
	if err != nil {
		t.Fatalf("docs/protocols/README.md: %v", err)
	}
	text := string(index)
	for _, name := range pages(t) {
		if !strings.Contains(text, "]("+name+".md)") {
			t.Errorf("docs/protocols/README.md does not link to %s.md", name)
		}
	}
	// And every daemon is named, so a reader can tell which of the three
	// programs serves a protocol without opening its page.
	for _, r := range listener.Roles() {
		if !strings.Contains(text, r.Daemon()) {
			t.Errorf("docs/protocols/README.md does not name %s", r.Daemon())
		}
	}
}

// TestTheIndexIsLinkedFromTheDocsAPersonStartsAt makes the set findable.
// A directory of pages nobody links to is a directory nobody reads.
func TestTheIndexIsLinkedFromTheDocsAPersonStartsAt(t *testing.T) {
	for _, from := range []string{"../../README.md", "../../docs/CONFIG.md", "../../docs/ARCHITECTURE.md"} {
		b, err := os.ReadFile(from)
		if err != nil {
			t.Fatalf("%s: %v", from, err)
		}
		if !strings.Contains(string(b), "protocols/README.md") {
			t.Errorf("%s does not link to the protocol pages", from)
		}
	}
}

// pages are the kind names the directory holds, sorted.
func pages(t *testing.T) []string {
	t.Helper()
	found, err := filepath.Glob(filepath.Join(dir, "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(found))
	for _, p := range found {
		name := strings.TrimSuffix(filepath.Base(p), ".md")
		if name == "README" {
			continue
		}
		out = append(out, name)
	}
	if len(out) == 0 {
		t.Fatal("docs/protocols holds no pages")
	}
	sort.Strings(out)
	return out
}

func read(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name+".md"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// section is the text under a heading, up to the next heading of the same
// level or above.
func section(text, heading string) string {
	i := strings.Index(text, "\n"+heading+"\n")
	if i < 0 {
		return ""
	}
	rest := text[i+len(heading)+2:]
	for _, marker := range []string{"\n## ", "\n# "} {
		if j := strings.Index(rest, marker); j >= 0 {
			rest = rest[:j]
		}
	}
	return rest
}
