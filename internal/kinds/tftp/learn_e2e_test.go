package tftp

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/proxy"
	wire "github.com/rom/xproxy/internal/tftp"
)

// Learning mode, through the whole relay.
//
// Nobody knows what an estate's TFTP traffic is: the protocol has no
// authentication and no session, so there is nothing to audit. A policy written
// from the deployment guide refuses the half nobody documented, which on this
// protocol means a switch that does not boot.

func learnRelay(t *testing.T, rules string, srv *fileServer, enforce bool) (*proxy.Server, string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "learned.yaml")
	s, addr := tftpRelay(t, fmt.Sprintf(`        upstream: servers
        learn:
          enabled: true
          file: %s
          enforce: %t
%s`, path, enforce, rules), srv.addr())
	return s, addr, path
}

// learnedReport shuts the listener down, which is what writes the report, and
// reads it.
func learnedReport(t *testing.T, s *proxy.Server, path string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the learning report was not written: %v", err)
	}
	return string(body)
}

// What a learning run produces: where the traffic went, and a rule set that
// permits exactly that.
func TestATFTPLearningRunWritesWhatItSaw(t *testing.T) {
	srv := startFileServer(t, &fileServer{file: []byte("an image")})
	s, addr, path := learnRelay(t, "        default_action: allow", srv, true)

	// Two files in one directory, so the report shows one subject with two
	// names rather than two subjects. A socket each, because a client's source
	// port *is* its transfer identifier: two transfers from one port are one
	// transfer and a retransmission as far as this relay is concerned.
	if got, _ := dial(t, addr).read("firmware/switch-a.bin"); string(got) != "an image" {
		t.Fatalf("the transfer did not complete: %q", got)
	}
	if got, _ := dial(t, addr).read("firmware/switch-b.bin"); string(got) != "an image" {
		t.Fatalf("the second transfer did not complete: %q", got)
	}
	got := learnedReport(t, s, path)

	obs, rules, ok := strings.Cut(got, "\nrules:")
	if !ok {
		t.Fatalf("the report proposes no rules:\n%s", got)
	}
	for _, want := range []string{
		"TFTP traffic",
		`listener "boot"`,
		"operation: read",
		"directory: firmware",
		"requests: 2",
		`filenames_seen: ["switch-a.bin", "switch-b.bin"]`,
		`extensions_seen: [".bin"]`,
		"modes: [octet]",
	} {
		if !strings.Contains(obs, want) {
			t.Errorf("the report has no %q:\n%s", want, obs)
		}
	}
	// And the proposal is in the vocabulary tftp.rules actually uses, with the
	// pattern derived from the extension rather than widened to everything.
	for _, want := range []string{"action: allow", "operations: [read]",
		`directories: ["firmware"]`, `filenames: ["firmware/*.bin"]`, "modes: [octet]"} {
		if !strings.Contains(rules, want) {
			t.Errorf("the proposal has no %q:\n%s", want, rules)
		}
	}
}

// A learning run is observe-only by default, which is the point: a run that
// refused half the traffic would have changed the thing it was measuring.
func TestATFTPLearningRunDoesNotEnforceByDefault(t *testing.T) {
	srv := startFileServer(t, &fileServer{file: []byte("an image")})
	s, addr, path := learnRelay(t, "        default_action: deny", srv, false)

	cl := dial(t, addr)
	// No rule allows this and the default is deny. The listener is learning, so
	// it goes through and the report says the policy disagreed.
	if got, _ := cl.read("firmware/switch-a.bin"); string(got) != "an image" {
		t.Fatalf("a learning run refused the transfer it was meant to be measuring: %q", got)
	}
	got := learnedReport(t, s, path)
	if !strings.Contains(got, "denied_by_policy: 1") {
		t.Errorf("the report does not say the policy disagreed:\n%s", got)
	}
}

// Learning with enforcement on is a listener that still refuses. The two are
// separate knobs on purpose: a run on a network that cannot be left unprotected
// keeps the policy in force and writes down what it refused.
func TestATFTPLearningRunWithEnforcementStillRefuses(t *testing.T) {
	srv := startFileServer(t, &fileServer{file: []byte("an image")})
	s, addr, path := learnRelay(t, "        default_action: deny", srv, true)

	cl := dial(t, addr)
	if _, e := cl.read("firmware/switch-a.bin"); e == nil {
		t.Fatal("the transfer was not refused")
	}
	if n := len(srv.seen()); n != 0 {
		t.Errorf("the request reached the server anyway (%d)", n)
	}
	got := learnedReport(t, s, path)
	if !strings.Contains(got, "denied_by_policy: 1") {
		t.Errorf("the refusal is not in the report:\n%s", got)
	}
}

// A file the server does not have belongs out of the policy rather than in it.
// A device asking for a firmware image nobody uploaded answers exactly this.
func TestAFileTheServerRefusesIsNotProposed(t *testing.T) {
	srv := startFileServer(t, &fileServer{errorCode: int(wire.ErrFileNotFound)})
	s, addr, path := learnRelay(t, "        default_action: allow", srv, true)

	cl := dial(t, addr)
	if _, e := cl.read("firmware/missing.bin"); e == nil {
		t.Fatal("the server's refusal did not reach the client")
	}
	got := learnedReport(t, s, path)

	obs, rules, ok := strings.Cut(got, "\nrules:")
	if !ok {
		t.Fatalf("the report has no rule set:\n%s", got)
	}
	if !strings.Contains(obs, "server_errors: 1") {
		t.Errorf("the server's refusal was not recorded:\n%s", obs)
	}
	if strings.Contains(rules, "operations: [read]") {
		t.Errorf("the proposal writes a rule for a file the server does not have:\n%s", rules)
	}
}

// The amplification bound is never proposed.
//
// A request asking for a window of sixty-four is lowered to the bound and still
// transfers, so the report sees the sixty-four. A proposal that turned that into
// `max_window_size: 64` would have widened, from an observation, the one setting
// that stops a twenty-octet request yielding a file to a forged address.
func TestTheAmplificationBoundIsNeverProposed(t *testing.T) {
	srv := startFileServer(t, &fileServer{file: []byte("an image")})
	s, addr, path := learnRelay(t, "        default_action: allow", srv, true)

	cl := dial(t, addr)
	cl.read("firmware/switch-a.bin",
		wire.Option{Name: wire.OptWindowSize, Value: "64"},
		wire.Option{Name: wire.OptBlockSize, Value: "8192"})
	got := learnedReport(t, s, path)

	obs, rules, ok := strings.Cut(got, "\nrules:")
	if !ok {
		t.Fatalf("the report has no rule set:\n%s", got)
	}
	// What was asked for is recorded, under names no rule uses.
	if !strings.Contains(obs, "window_asked: 64") {
		t.Errorf("the window that was asked for is not recorded:\n%s", obs)
	}
	if !strings.Contains(obs, "block_size_asked: 8192") {
		t.Errorf("the block size that was asked for is not recorded:\n%s", obs)
	}
	// And no rule sets any of the three.
	for _, never := range []string{"max_window_size", "max_block_size", "max_transfer_bytes"} {
		if strings.Contains(rules, never) {
			t.Errorf("the proposal sets %s, which is a bound rather than policy:\n%s", never, rules)
		}
	}
}

// A filename this relay and the server would read differently is recorded and
// never proposed. There is nothing to clean about a name whose end two parsers
// disagree on, so a rule about it would be a rule about a name the server never
// sees.
func TestAPathNobodyCanAgreeOnIsRecordedAndNotProposed(t *testing.T) {
	srv := startFileServer(t, &fileServer{file: []byte("an image")})
	s, addr, path := learnRelay(t, "        default_action: allow", srv, false)

	cl := dial(t, addr)
	cl.read("firmware/../../etc/shadow")
	got := learnedReport(t, s, path)

	obs, rules, ok := strings.Cut(got, "\nrules:")
	if !ok {
		t.Fatalf("the report has no rule set:\n%s", got)
	}
	if !strings.Contains(obs, "path_class: traversal") {
		t.Errorf("the traversal is not in the report:\n%s", obs)
	}
	if strings.Contains(obs, "directory:") {
		t.Errorf("the report invented a directory for a name nobody resolved:\n%s", obs)
	}
	if !strings.Contains(rules, "[]") {
		t.Errorf("a rule was proposed for a path class:\n%s", rules)
	}
}

// Names that share no small set of extensions do not get a pattern.
//
// The only pattern that always fits is `*`, and a proposal that fell back to it
// would permit every file on the server while looking derived from the traffic.
func TestNamesThatDoNotGeneraliseGetNoPattern(t *testing.T) {
	srv := startFileServer(t, &fileServer{file: []byte("an image")})
	s, addr, path := learnRelay(t, "        default_action: allow", srv, true)

	// Two names in the same directory with no extension between them, on a
	// socket each.
	dial(t, addr).read("configs/switch-a")
	dial(t, addr).read("configs/switch-b")
	got := learnedReport(t, s, path)

	_, rules, ok := strings.Cut(got, "\nrules:")
	if !ok {
		t.Fatalf("the report has no rule set:\n%s", got)
	}
	if strings.Contains(rules, "filenames:") {
		t.Errorf("a pattern was proposed from names that share nothing:\n%s", rules)
	}
	if !strings.Contains(rules, "No `filenames` pattern is proposed") {
		t.Errorf("the proposal does not say why there is no pattern:\n%s", rules)
	}
	// The directory rule is still proposed: that much was observed.
	if !strings.Contains(rules, `directories: ["configs"]`) {
		t.Errorf("the directory was not proposed:\n%s", rules)
	}
}

// What the section refuses to load.
func TestWhatATFTPLearningSectionRefusesToLoad(t *testing.T) {
	srv := startFileServer(t, &fileServer{})
	for _, tc := range []struct{ name, section, wants string }{
		{
			name:    "learning with no file",
			section: "        learn: {enabled: true}",
			wants:   "learn.file: required",
		},
		{
			name:    "a relative path",
			section: "        learn: {enabled: true, file: learned.yaml}",
			wants:   "must be an absolute path",
		},
		{
			name:    "an interval nobody meant",
			section: "        learn: {enabled: true, file: /tmp/l.yaml, interval: 1s}",
			wants:   "learn.interval: must be between 10s and 24h",
		},
		{
			name:    "a bound nobody meant",
			section: "        learn: {enabled: true, file: /tmp/l.yaml, max_subjects: 2}",
			wants:   "learn.max_subjects: must be between 16 and 1000000",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			yaml := fmt.Sprintf(tftpYAML, "        upstream: servers\n"+tc.section, "", srv.addr())
			if _, err := config.Parse([]byte(yaml)); err == nil {
				t.Fatal("the section loaded")
			} else if !strings.Contains(err.Error(), tc.wants) {
				t.Errorf("the error is %v, want it to mention %q", err, tc.wants)
			}
		})
	}
}

// A file at the top of the server's own directory has no directory, and the
// proposal says so rather than writing `directories: [""]`, which matches
// nothing and would refuse the transfer it was derived from.
func TestAFileAtTheTopOfTheTreeIsNotProposedAsADirectory(t *testing.T) {
	srv := startFileServer(t, &fileServer{file: []byte("a config")})
	s, addr, path := learnRelay(t, "        default_action: allow", srv, true)

	if got, _ := dial(t, addr).read("switch.cfg"); string(got) != "a config" {
		t.Fatalf("the transfer did not complete: %q", got)
	}
	got := learnedReport(t, s, path)

	obs, rules, ok := strings.Cut(got, "\nrules:")
	if !ok {
		t.Fatalf("the report has no rule set:\n%s", got)
	}
	if !strings.Contains(obs, `directory: ""`) {
		t.Errorf("the report does not say the file was at the top:\n%s", obs)
	}
	if strings.Contains(rules, `directories: [""]`) {
		t.Errorf("the proposal writes a directory that matches nothing:\n%s", rules)
	}
	if !strings.Contains(rules, "at the top of the server's own directory were asked for too") {
		t.Errorf("the proposal does not say what to do about it:\n%s", rules)
	}
	// The pattern is still proposed, rooted rather than under a directory.
	if !strings.Contains(rules, `filenames: ["*.cfg"]`) {
		t.Errorf("no rooted pattern was proposed:\n%s", rules)
	}
}

// A directory holding more kinds of file than the report remembers does not
// generalise into a pattern.
//
// What was recorded is then a sample of the extensions rather than all of them,
// and a pattern derived from a sample permits the files the sample did not
// contain -- which on a TFTP server is every other file in that directory.
func TestADirectoryOfManyKindsGetsNoPattern(t *testing.T) {
	srv := startFileServer(t, &fileServer{file: []byte("a file")})
	s, addr, path := learnRelay(t, "        default_action: allow", srv, true)

	exts := []string{".bin", ".cfg", ".txt", ".img", ".tar", ".xml", ".json", ".ini", ".dat"}
	if len(exts) <= maxLearnedExts {
		t.Fatalf("this test needs more than %d extensions", maxLearnedExts)
	}
	for i, e := range exts {
		dial(t, addr).read("mixed/file" + itoa(i) + e)
	}
	got := learnedReport(t, s, path)

	obs, rules, ok := strings.Cut(got, "\nrules:")
	if !ok {
		t.Fatalf("the report has no rule set:\n%s", got)
	}
	// The extensions recorded stop at the bound, so what is in the report is a
	// sample and the report has to be read rather than pasted.
	if n := strings.Count(obs, "."); n == 0 {
		t.Fatalf("no extensions were recorded at all:\n%s", obs)
	}
	if strings.Contains(rules, "filenames:") {
		t.Errorf("a pattern was proposed from a sample of the extensions:\n%s", rules)
	}
	if !strings.Contains(rules, "No `filenames` pattern is proposed") {
		t.Errorf("the proposal does not say why there is no pattern:\n%s", rules)
	}
	// The directory is still proposed: that much was observed in full.
	if !strings.Contains(rules, `directories: ["mixed"]`) {
		t.Errorf("the directory was not proposed:\n%s", rules)
	}
}
