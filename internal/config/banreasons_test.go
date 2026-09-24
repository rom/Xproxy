package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// observeRE finds the reason a listener hands the ban list:
// bl.Observe(ip, "ftp_denied").
var observeRE = regexp.MustCompile(`Observe\([^,)]+,\s*"([a-z0-9_]+)"`)

// TestEveryReasonAKindEmitsCanBeBannedOn is the seventh round's sweep
// of a gap four listener kinds shared: each of them hands the ban list
// a reason of its own, and each says so in docs/CONFIG.md ("Refusals
// are rdp_denied deny events, so bans apply") -- but the reason was
// not in the table a ban trigger is validated against, so the
// configuration the documentation describes would not load.
//
// It is the kind of gap that only shows up when somebody writes the
// trigger, which is why the check is here rather than in a reviewer's
// memory: a kind added tomorrow fails this test until its reason can
// be named. It reads the source rather than a list, because a list is
// the thing that was already wrong.
func TestEveryReasonAKindEmitsCanBeBannedOn(t *testing.T) {
	root := ".."
	seen := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, m := range observeRE.FindAllStringSubmatch(string(b), -1) {
			seen[m[1]] = p
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) == 0 {
		t.Fatal("no deny reasons found; the pattern no longer matches how a kind reports one")
	}
	for reason, file := range seen {
		if !denyReasons[reason] {
			t.Errorf("%s reports %q to the ban list, but no trigger can name it", file, reason)
		}
	}
}
