package deploy

import (
	"regexp"
	"sort"
	"strings"
	"testing"
)

// What a release tarball contains drifts behind what the tree builds, for the same
// reason the RPM spec did: the rule is written once and then nobody looks at it
// again. The Linux tarball shipped four binaries for as long as there had been three
// daemons, so a download carried deploy/config/xgate.yaml and xrelay.yaml -- telling
// an operator how to configure two daemons whose binaries were not in it. An SSH
// bastion or any relay listener could not be run from a release at all.
//
// These hold the release rules against the build rules. Not that the lists are
// identical -- macOS deliberately ships fewer, because it has no launchd job for
// xgate or xrelay -- but that nothing the tree builds is silently left out of the
// platform that is supposed to carry it.

// built is every binary the Makefile's `build` target produces.
func built(t *testing.T) []string {
	t.Helper()
	mk := read(t, "Makefile")
	re := regexp.MustCompile(`-o \$\(BIN\)/([a-z-]+) \./cmd/`)
	ms := re.FindAllStringSubmatch(mk, -1)
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m[1])
	}
	if len(out) < 5 {
		t.Fatalf("found %d build rules in the Makefile, which cannot be right: %v", len(out), out)
	}
	sort.Strings(out)
	return out
}

// list reads a `NAME = a b c` or `NAME="a b c"` assignment.
func list(t *testing.T, body, name string) []string {
	t.Helper()
	re := regexp.MustCompile(`(?m)^` + name + `\s*=\s*"?([a-z0-9 _-]+)"?\s*$`)
	m := re.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("%s is not defined; this test's parsing is stale", name)
	}
	out := strings.Fields(m[1])
	sort.Strings(out)
	return out
}

// The Linux tarball carries everything the tree builds. This is the one that was
// wrong: it is the download an operator who does not use the RPM gets.
func TestTheLinuxTarballShipsEveryBinaryTheTreeBuilds(t *testing.T) {
	want, got := built(t), list(t, read(t, "Makefile"), "LINUX_BINARIES")
	if strings.Join(want, " ") != strings.Join(got, " ") {
		t.Errorf("the Linux release tarball ships %v but the tree builds %v; a binary "+
			"missing here is a daemon an operator cannot run from a release", got, want)
	}
	// And the rule actually copies the list rather than naming it and ignoring it.
	if !strings.Contains(read(t, "Makefile"), "for b in $(LINUX_BINARIES); do cp $(BIN)/$$b") {
		t.Error("the release target no longer copies LINUX_BINARIES")
	}
}

// The macOS tarball and the macOS installer carry the same list. They disagreed:
// the tarball carried five and the installer installed three, so two binaries were
// shipped to every Mac and installed on none.
func TestTheMacInstallerInstallsWhatItsTarballCarries(t *testing.T) {
	tarball := list(t, read(t, "Makefile"), "DARWIN_BINARIES")
	installer := list(t, read(t, "deploy", "macos", "install.sh"), "BINARIES")
	if strings.Join(tarball, " ") != strings.Join(installer, " ") {
		t.Errorf("the darwin tarball carries %v and install.sh installs %v", tarball, installer)
	}
	// macOS ships fewer on purpose, and the reason is that it has no launchd job
	// for these three. If one is ever added, this is where the decision surfaces.
	for _, absent := range []string{"xgate", "xrelay", "xot"} {
		for _, b := range tarball {
			if b == absent {
				t.Errorf("the darwin tarball carries %s; macOS has no launchd job for "+
					"it, so either add deploy/macos/com.sysctl.%s.plist or drop it",
					absent, absent)
			}
		}
	}
	// Every binary it does carry is one the tree builds for some platform.
	build := strings.Join(built(t), " ")
	for _, b := range tarball {
		if !strings.Contains(build, b) {
			t.Errorf("the darwin tarball carries %s, which the tree does not build", b)
		}
	}
}

// The release procedure describes what the tarballs contain, and a count in prose
// is the first thing to go stale: it said "the three binaries" of both after the
// split made it eight and five.
func TestTheReleaseProcedureDoesNotMiscountTheBinaries(t *testing.T) {
	doc := read(t, "docs", "RELEASING.md")
	for _, stale := range []string{"the three binaries", "the four binaries"} {
		if strings.Contains(doc, stale) {
			t.Errorf("RELEASING.md still says %q; the Linux tarball carries %d and the "+
				"macOS one %d", stale, len(list(t, read(t, "Makefile"), "LINUX_BINARIES")),
				len(list(t, read(t, "Makefile"), "DARWIN_BINARIES")))
		}
	}
	// And it names the two daemons that were missing, so a reader can tell what a
	// download contains without unpacking one.
	for _, want := range []string{"xgate", "xrelay", "xot"} {
		if !strings.Contains(doc, want) {
			t.Errorf("RELEASING.md does not mention %s anywhere", want)
		}
	}
}
