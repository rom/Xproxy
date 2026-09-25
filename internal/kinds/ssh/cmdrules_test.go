package ssh

import (
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/sshcmd"
)

// rules builds the compiled rules of a policy, failing the test on a
// rule the loader would have refused.
func rules(t *testing.T, list ...config.SSHCommandRule) *cmdRules {
	t.Helper()
	rs, err := compileCmdRules(list)
	if err != nil {
		t.Fatalf("compileCmdRules: %v", err)
	}
	return rs
}

// decide parses a line and applies the rules, which is the pair the
// gateway uses.
func decide(t *testing.T, rs *cmdRules, line string) cmdDecision {
	t.Helper()
	c, err := sshcmd.Parse(line)
	if err != nil {
		t.Fatalf("Parse(%q): %v", line, err)
	}
	return rs.decide(c)
}

// The rule an operator means to write -- "uploads into that directory,
// nothing else" -- and every line a pattern for it would have let
// through.
func TestTheLinesAPatternWouldHaveAdmitted(t *testing.T) {
	rs := rules(t, config.SSHCommandRule{
		Command: "scp", Directions: []string{"upload"}, Paths: []string{"/srv/incoming/**"},
	})
	for _, line := range []string{
		"scp -t /srv/incoming",
		"scp -t /srv/incoming/",
		"scp -t /srv/incoming/sub/dir",
		"scp -dt /srv/incoming",
		"/usr/bin/scp -t /srv/incoming",
		"scp -t '/srv/incoming/two words'",
		"scp  -t   /srv/incoming",
	} {
		if d := decide(t, rs, line); !d.allow {
			t.Errorf("%q was refused (%s: %s)", line, d.reason, d.detail)
		}
	}
	for _, tc := range []struct{ line, reason string }{
		// The other direction, spelled with the same words.
		{"scp -f /srv/incoming", refuseDirection},
		{"scp -f /srv/incoming/secret", refuseDirection},
		// Recursion, which is a different permission from a file.
		{"scp -rt /srv/incoming", refuseRecursive},
		{"scp -t -r /srv/incoming", refuseRecursive},
		// A path that resolves somewhere else entirely.
		{"scp -t /srv/incoming/../../etc/ssh", refusePath},
		{"scp -t /etc/ssh", refusePath},
		{"scp -t /srv/incoming/../outgoing", refusePath},
		// A path whose meaning depends on a working directory this
		// gateway cannot see.
		{"scp -t ../../etc", refusePath},
		// Not the far side of a copy at all.
		{"scp /srv/incoming/a /srv/incoming/b", refuseServer},
		// An assignment in front of it, which is how a command is given
		// an environment the env policy never saw.
		{"LD_PRELOAD=/tmp/x.so scp -t /srv/incoming", refuseEnv},
	} {
		d := decide(t, rs, tc.line)
		if d.allow || d.reason != tc.reason {
			t.Errorf("%q: allow %v reason %q, want refused with %q", tc.line, d.allow, d.reason, tc.reason)
		}
		if d.detail == "" {
			t.Errorf("%q was refused with no detail", tc.line)
		}
	}
}

// A family with no rule of its own is refused rather than falling back
// to the patterns: a rule for scp must not quietly leave rsync open.
func TestAFamilyWithNoRuleIsRefused(t *testing.T) {
	rs := rules(t, config.SSHCommandRule{Command: "scp", Directions: []string{"upload"}})
	for _, line := range []string{
		"rsync --server . /srv", "git-upload-pack /srv/git/x.git", "/usr/lib/openssh/sftp-server",
	} {
		d := decide(t, rs, line)
		if d.allow || d.reason != refuseNoRule {
			t.Errorf("%q: allow %v reason %q, want %q", line, d.allow, d.reason, refuseNoRule)
		}
	}
	// And a command of no family at all is not this layer's to decide.
	if d := decide(t, rs, "journalctl -u xproxy"); d.matched {
		t.Error("an ordinary command was decided by the transfer rules")
	}
}

// A wrapper is not a transfer family the gateway knows how to inspect, but
// neither may it carry one past the structured rules into the legacy gates.
// The check uses the words produced by the shell-aware splitter, rather than
// the original spelling, so quoting cannot conceal the helper's name.
func TestAWrappedFamilyIsRefused(t *testing.T) {
	rs := rules(t, config.SSHCommandRule{Command: "scp", Directions: []string{"upload"}})
	for _, line := range []string{
		"env scp -f /etc/passwd",
		"env s''cp -f /etc/passwd",
		"sudo rsync --server --sender . /etc",
		"sh -c 'git-upload-pack /srv/private.git'",
	} {
		d := decide(t, rs, line)
		if d.allow || !d.matched || d.reason != refuseNoRule {
			t.Errorf("%q: %+v, want refusal with %q", line, d, refuseNoRule)
		}
	}
	if d := decide(t, rs, "journalctl -u xproxy"); d.matched {
		t.Errorf("an ordinary wrapped command was decided: %+v", d)
	}
}

func TestRsyncRules(t *testing.T) {
	rs := rules(t, config.SSHCommandRule{
		Command: "rsync", Directions: []string{"upload"}, Paths: []string{"/srv/incoming/**"},
	})
	if d := decide(t, rs, "rsync --server -vlogDtpre.iLsfxC . /srv/incoming"); !d.allow {
		t.Errorf("an upload was refused (%s: %s)", d.reason, d.detail)
	}
	for _, tc := range []struct{ line, reason string }{
		{"rsync --server --sender -vlogDtpre.iLsfxC . /srv/incoming", refuseDirection},
		{"rsync --server --delete . /srv/incoming", refuseDelete},
		{"rsync --server --remove-source-files . /srv/incoming", refuseDelete},
		{"rsync --server . /srv/other", refusePath},
		{"rsync -av /srv/incoming other.example:/tmp", refuseServer},
	} {
		if d := decide(t, rs, tc.line); d.allow || d.reason != tc.reason {
			t.Errorf("%q: allow %v reason %q, want %q", tc.line, d.allow, d.reason, tc.reason)
		}
	}
	// delete: true admits the option it names, and nothing else.
	del := rules(t, config.SSHCommandRule{Command: "rsync", Directions: []string{"upload"}, Delete: true})
	if d := decide(t, del, "rsync --server --delete . /srv/incoming"); !d.allow {
		t.Errorf("--delete was refused where the rule allows it (%s)", d.reason)
	}
}

// git's verbs are the server's point of view, so a rule that means
// "clones, no pushes" has to be read that way round.
func TestGitDirectionsAreTheFileMovement(t *testing.T) {
	rs := rules(t, config.SSHCommandRule{
		Command: "git", Directions: []string{"download"}, Paths: []string{"/srv/git/**"},
	})
	if d := decide(t, rs, "git-upload-pack '/srv/git/x.git'"); !d.allow {
		t.Errorf("a fetch was refused (%s: %s)", d.reason, d.detail)
	}
	if d := decide(t, rs, "git-receive-pack '/srv/git/x.git'"); d.allow || d.reason != refuseDirection {
		t.Errorf("a push was allowed by a download-only rule: %+v", d)
	}
	if d := decide(t, rs, "git-upload-pack '/srv/other/x.git'"); d.allow || d.reason != refusePath {
		t.Errorf("a repository outside the paths was allowed: %+v", d)
	}
}

// A glob is admitted only where every name it can expand to is inside a
// subtree the rule allows, and never where a deny list would have to be
// proven clear.
func TestAGlobIsOnlyAdmittedInsideASubtree(t *testing.T) {
	sub := rules(t, config.SSHCommandRule{
		Command: "scp", Directions: []string{"download"}, Paths: []string{"/srv/data/**"},
	})
	if d := decide(t, sub, "scp -f /srv/data/*.csv"); !d.allow {
		t.Errorf("a glob inside the allowed subtree was refused (%s: %s)", d.reason, d.detail)
	}
	for _, line := range []string{"scp -f /srv/*", "scp -f /etc/*", "scp -f /srv/data/../*"} {
		if d := decide(t, sub, line); d.allow {
			t.Errorf("%q was allowed", line)
		}
	}
	// A single-level pattern cannot cover names nobody has seen, even
	// when it matches the directory the glob sits in: "/srv/*" allows
	// "/srv/data" and says nothing about what is inside it.
	one := rules(t, config.SSHCommandRule{
		Command: "scp", Directions: []string{"download"}, Paths: []string{"/srv/data/*", "/srv/*"},
	})
	if d := decide(t, one, "scp -f /srv/data/*"); d.allow {
		t.Error("a glob was admitted by a pattern that covers one level")
	}
	// And the same pattern still allows a literal path it names.
	if d := decide(t, one, "scp -f /srv/data/report.csv"); !d.allow {
		t.Errorf("a literal path the pattern names was refused (%s: %s)", d.reason, d.detail)
	}
	// With a deny list the question cannot be answered at all.
	deny := rules(t, config.SSHCommandRule{
		Command: "scp", Directions: []string{"download"},
		Paths: []string{"/srv/data/**"}, DenyPaths: []string{"/srv/data/keys/**"},
	})
	if d := decide(t, deny, "scp -f /srv/data/*"); d.allow || !strings.Contains(d.detail, "deny_paths") {
		t.Errorf("a glob was judged against a deny list: %+v", d)
	}
	if d := decide(t, deny, "scp -f /srv/data/keys/id_rsa"); d.allow || d.reason != refusePath {
		t.Errorf("a denied path was allowed: %+v", d)
	}
}

// The sftp server binary is the subsystem under another name, so the
// rule's answer is "yes, inspected" and never "yes".
func TestAnSFTPServerRuleAsksForInspection(t *testing.T) {
	rs := rules(t, config.SSHCommandRule{Command: "sftp_server", EnforceSFTPPolicy: true})
	d := decide(t, rs, "/usr/lib/openssh/sftp-server -e")
	if !d.allow || !d.sftp {
		t.Errorf("an sftp server exec was not sent through the sftp policy: %+v", d)
	}
}

// Nothing decides anything without rules, and a rule this loader cannot
// read is a load error rather than a rule that quietly allows.
func TestTheRulesAreRefusedRatherThanGuessed(t *testing.T) {
	var none *cmdRules
	if d := none.decide(&sshcmd.Command{Kind: sshcmd.KindSCP}); d.matched {
		t.Error("a nil rule set decided a command")
	}
	if rs, err := compileCmdRules(nil); rs != nil || err != nil {
		t.Errorf("an empty list built %v, %v", rs, err)
	}
	for _, list := range [][]config.SSHCommandRule{
		{{Command: "ftp", Directions: []string{"upload"}}},
		{{Command: "scp", Directions: []string{"sideways"}}},
		{{Command: "scp", Directions: []string{"upload"}}, {Command: "scp", Directions: []string{"download"}}},
	} {
		if _, err := compileCmdRules(list); err == nil {
			t.Errorf("%+v was accepted", list)
		}
	}
}

// A path that climbs above its own root is refused even by a rule with
// no path list: what it means depends on the directory the command will
// run in, which this gateway cannot see, so there is nothing to check it
// against.
func TestARelativePathIsRefusedWithNoPathListAtAll(t *testing.T) {
	rs := rules(t, config.SSHCommandRule{Command: "scp", Directions: []string{"upload", "download"}})
	for _, line := range []string{"scp -t ../../etc", "scp -f ../secrets"} {
		d := decide(t, rs, line)
		if d.allow || d.reason != refusePath {
			t.Errorf("%q: allow %v reason %q, want %q", line, d.allow, d.reason, refusePath)
		}
	}
	// A path inside the target's own tree is fine: an empty list means
	// every path, not no path.
	if d := decide(t, rs, "scp -t /srv/incoming"); !d.allow {
		t.Errorf("an absolute path was refused by a rule with no list (%s)", d.reason)
	}
}
