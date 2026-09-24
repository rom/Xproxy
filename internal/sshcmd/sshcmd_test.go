package sshcmd

import (
	"errors"
	"strings"
	"testing"
)

// reasonOf is the refusal reason of an error, or "" for none.
func reasonOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ""
}

func words(t *testing.T, line string) []string {
	t.Helper()
	ws, err := Split(line)
	if err != nil {
		t.Fatalf("Split(%q): %v", line, err)
	}
	out := make([]string, 0, len(ws))
	for _, w := range ws {
		out = append(out, w.Text)
	}
	return out
}

// The splitting a shell does, which is the only splitting whose words
// are the words the target will run.
func TestTheLineIsSplitAsAShellSplitsIt(t *testing.T) {
	for _, tc := range []struct {
		line string
		want []string
	}{
		{`scp -t /srv/incoming`, []string{"scp", "-t", "/srv/incoming"}},
		{`  scp   -t    /srv/in  `, []string{"scp", "-t", "/srv/in"}},
		{"scp\t-t\t/srv/in", []string{"scp", "-t", "/srv/in"}},
		{`scp -t '/srv/in coming'`, []string{"scp", "-t", "/srv/in coming"}},
		{`scp -t "/srv/in coming"`, []string{"scp", "-t", "/srv/in coming"}},
		{`scp -t /srv/in\ coming`, []string{"scp", "-t", "/srv/in coming"}},
		{`scp -t ''`, []string{"scp", "-t", ""}},
		{`a'b'c"d"e`, []string{"abcde"}},
		// A quoted operator is data, and the shell will hand it to the
		// program as one word rather than reading it as syntax.
		{`grep -e 'a;b' /var/log/x`, []string{"grep", "-e", "a;b", "/var/log/x"}},
		{`echo "a|b"`, []string{"echo", "a|b"}},
		// Inside double quotes a backslash escapes only four
		// characters; anywhere else it is a literal backslash, and
		// reading it otherwise would give a word the shell will not.
		{`echo "a\"b"`, []string{"echo", `a"b`}},
		{`echo "a\nb"`, []string{"echo", `a\nb`}},
		{`echo "a\\b"`, []string{"echo", `a\b`}},
	} {
		if got := words(t, tc.line); strings.Join(got, "\x00") != strings.Join(tc.want, "\x00") {
			t.Errorf("Split(%q) = %q, want %q", tc.line, got, tc.want)
		}
	}
}

// And everything that is not one simple command.
func TestALineThatIsNotOneCommandIsRefused(t *testing.T) {
	for _, tc := range []struct{ line, reason string }{
		{"", ReasonEmpty},
		{"   ", ReasonEmpty},
		{"scp -t /srv; rm -rf /", ReasonOperator},
		{"scp -t /srv && id", ReasonOperator},
		{"scp -t /srv | tee /tmp/x", ReasonOperator},
		{"scp -t /srv > /etc/passwd", ReasonOperator},
		{"scp -t /srv\nid", ReasonOperator},
		{"(id)", ReasonOperator},
		{"scp -t $(id)", ReasonSubstitution},
		{"scp -t `id`", ReasonSubstitution},
		{"scp -t ${HOME}", ReasonSubstitution},
		{`scp -t "$(id)"`, ReasonSubstitution},
		{"scp -t \"`id`\"", ReasonSubstitution},
		{`scp -t "/srv`, ReasonQuote},
		{`scp -t '/srv`, ReasonQuote},
		{`scp -t /srv\`, ReasonEscape},
		{"scp -t /srv\x00", ReasonControl},
		{"scp -t '/srv\x1b[2J'", ReasonControl},
		{"scp -t \"/srv\x07\"", ReasonControl},
		{"scp -t /srv" + strings.Repeat("x", MaxLine), ReasonTooLong},
		{"scp -t" + strings.Repeat(" x", MaxWords+1), ReasonTooManyWords},
		{"A=1 B=2", ReasonEmpty},
	} {
		_, err := Parse(tc.line)
		if got := reasonOf(err); got != tc.reason {
			t.Errorf("Parse(%q) refused with %q, want %q (err %v)", tc.line, got, tc.reason, err)
		}
	}
}

// A substitution inside single quotes is not one: the shell hands it
// over literally, so the word this checks is the word that will run.
func TestSingleQuotesHoldASubstitutionLiterally(t *testing.T) {
	if got := words(t, `grep -F '$(id)' /var/log/x`); got[1] != "-F" || got[2] != "$(id)" {
		t.Errorf("single-quoted substitution read as %q", got)
	}
}

// A glob is kept rather than refused, and marked: what it expands to is
// the target shell's decision, and only the caller knows whether a word
// it cannot resolve is admissible.
func TestAGlobIsMarkedNotResolved(t *testing.T) {
	ws, err := Split(`scp -f /srv/data/* '/srv/lit*eral' "/srv/q?"`)
	if err != nil {
		t.Fatal(err)
	}
	if !ws[2].Glob {
		t.Error("an unquoted glob was not marked")
	}
	if ws[3].Glob {
		t.Error("a single-quoted glob was marked, though the shell will not expand it")
	}
	if ws[4].Glob {
		t.Error("a double-quoted glob was marked, though the shell will not expand it")
	}
}

// The command word is read the way a shell finds the program, so a path
// or a wrapper name cannot hide a family behind a pattern.
func TestTheFamilyIsFoundWhateverTheCommandIsCalled(t *testing.T) {
	for _, tc := range []struct {
		line string
		kind Kind
		name string
	}{
		{"scp -t /srv/in", KindSCP, "scp"},
		{"/usr/bin/scp -t /srv/in", KindSCP, "scp"},
		{"/usr/local/libexec/scp.exe -t /srv/in", KindSCP, "scp"},
		{"rsync --server . /srv/in", KindRsync, "rsync"},
		{"/usr/lib/openssh/sftp-server", KindSFTPServer, "sftp-server"},
		{"internal-sftp", KindSFTPServer, "internal-sftp"},
		{"git-upload-pack '/srv/git/x.git'", KindGit, "git-upload-pack"},
		{"git upload-pack /srv/git/x.git", KindGit, "git"},
		{"journalctl -u xproxy", KindOther, "journalctl"},
		// Only the three transport verbs are read as git: git-annex-shell
		// and the rest are programs this has no parser for, and saying so
		// leaves them to the rules every other command is held to.
		{"git-annex-shell configlist /srv/x", KindOther, "git-annex-shell"},
		{"env", KindOther, "env"},
	} {
		c, err := Parse(tc.line)
		if err != nil {
			t.Fatalf("Parse(%q): %v", tc.line, err)
		}
		if c.Kind != tc.kind || c.Name != tc.name {
			t.Errorf("Parse(%q) = kind %q name %q, want %q and %q", tc.line, c.Kind, c.Name, tc.kind, tc.name)
		}
	}
}

// A wrapper is not read through: "env scp -t /etc" is env, and a policy
// that means to allow scp must not see one here. The caller refuses it
// for having no rule, which is the safe direction.
func TestAWrapperIsNotReadAsTheFamilyItCarries(t *testing.T) {
	for _, line := range []string{"env scp -t /etc", "sudo rsync --server . /", "sh -c scp"} {
		c, err := Parse(line)
		if err != nil {
			t.Fatalf("Parse(%q): %v", line, err)
		}
		if c.Kind != KindOther {
			t.Errorf("Parse(%q) read the wrapper as %q", line, c.Kind)
		}
	}
}

// Leading assignments are reported, not skipped over: each is a way to
// change what the command does, so the policy has to see them.
func TestAssignmentsAreReportedSeparately(t *testing.T) {
	c, err := Parse("LD_PRELOAD=/tmp/x.so PATH=/tmp scp -t /srv/in")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Env) != 2 || c.Env[0] != "LD_PRELOAD=/tmp/x.so" {
		t.Errorf("assignments read as %q", c.Env)
	}
	if c.Kind != KindSCP {
		t.Errorf("the command behind the assignments read as %q", c.Kind)
	}
	// And a word that only looks like one is a command, not an
	// assignment: "./x=y" is a program with an odd name.
	c, err = Parse("./x=y -t /srv")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Env) != 0 || c.Name != "x=y" {
		t.Errorf("%q was read as an assignment", c.Line)
	}
}

// scp's direction is a flag, not a word order, and it is the whole
// question a transfer policy asks.
func TestSCPDirectionAndFlags(t *testing.T) {
	for _, tc := range []struct {
		line      string
		dir       Direction
		recursive bool
		paths     []string
	}{
		{"scp -t /srv/in", Upload, false, []string{"/srv/in"}},
		{"scp -f /srv/in", Download, false, []string{"/srv/in"}},
		{"scp -rt /srv/in", Upload, true, []string{"/srv/in"}},
		{"scp -t -r -d -p -v /srv/in", Upload, true, []string{"/srv/in"}},
		{"scp -dtr /srv/in", Upload, true, []string{"/srv/in"}},
		{"scp -f -- -weird-name", Download, false, []string{"-weird-name"}},
		{"scp -f /srv/a /srv/b", Download, false, []string{"/srv/a", "/srv/b"}},
		// No -t and no -f: not the far side of a copy at all, which the
		// caller refuses for naming no direction.
		{"scp /srv/a /srv/b", Neither, false, []string{"/srv/a", "/srv/b"}},
	} {
		c, err := Parse(tc.line)
		if err != nil {
			t.Fatalf("Parse(%q): %v", tc.line, err)
		}
		if c.SCP.Direction != tc.dir || c.SCP.Recursive != tc.recursive {
			t.Errorf("Parse(%q) = %q recursive %v, want %q and %v",
				tc.line, c.SCP.Direction, c.SCP.Recursive, tc.dir, tc.recursive)
		}
		if len(c.SCP.Paths) != len(tc.paths) {
			t.Fatalf("Parse(%q) found %d paths, want %d", tc.line, len(c.SCP.Paths), len(tc.paths))
		}
		for i, p := range tc.paths {
			if c.SCP.Paths[i].Text != p {
				t.Errorf("Parse(%q) path %d = %q, want %q", tc.line, i, c.SCP.Paths[i].Text, p)
			}
		}
	}
}

func TestAnUnreadableInvocationIsRefused(t *testing.T) {
	for _, tc := range []struct{ line, reason string }{
		{"scp -t -f /srv/in", ReasonOption},      // both directions at once
		{"scp -X /srv/in", ReasonOption},         // a flag no scp server takes
		{"scp -S /bin/sh -t /srv", ReasonOption}, // the client-side flag that names a program
		{"scp -t", ReasonArguments},              // no path
		{"rsync --server --daemon . /srv", ReasonOption},
		{"rsync --server --rsh=/bin/sh . /srv", ReasonOption},
		{"rsync --server --remote-option=--x . /srv", ReasonOption},
		{"rsync --server -M--x . /srv", ReasonOption},
		{"rsync --server", ReasonArguments},
		{"sftp-server -d /etc", ReasonOption}, // a start directory the policy cannot see
		{"sftp-server -p open", ReasonOption},
		{"sftp-server -l", ReasonArguments},
		{"git-upload-pack", ReasonArguments},
		{"git-upload-pack /a /b", ReasonArguments},
		{"git shell", ReasonOption},
		{"git-upload-pack --strange /a", ReasonOption},
	} {
		_, err := Parse(tc.line)
		if got := reasonOf(err); got != tc.reason {
			t.Errorf("Parse(%q) refused with %q, want %q (err %v)", tc.line, got, tc.reason, err)
		}
	}
}

// rsync as a client actually invokes it, which is the only form a
// gateway should see, plus the forms that mean something else.
func TestRsyncServerInvocations(t *testing.T) {
	for _, tc := range []struct {
		line    string
		server  bool
		dir     Direction
		deletes bool
		path    string
	}{
		{"rsync --server -vlogDtpre.iLsfxC . /srv/in", true, Upload, false, "/srv/in"},
		{"rsync --server --sender -vlogDtpre.iLsfxC . /srv/out", true, Download, false, "/srv/out"},
		{"rsync --server --delete -vlogDtpre.iLsfxC . /srv/in", true, Upload, true, "/srv/in"},
		{"rsync --server --delete-during . /srv/in", true, Upload, true, "/srv/in"},
		{"rsync --server --remove-source-files . /srv/in", true, Upload, true, "/srv/in"},
		// Without --server it is a client: an rsync that dials out of
		// the target to somewhere the gateway never sees.
		{"rsync -av /srv/in other.example:/tmp", false, Upload, false, "other.example:/tmp"},
	} {
		c, err := Parse(tc.line)
		if err != nil {
			t.Fatalf("Parse(%q): %v", tc.line, err)
		}
		r := c.Rsync
		if r.Server != tc.server || r.Direction != tc.dir || r.Deletes != tc.deletes {
			t.Errorf("Parse(%q) = server %v %q deletes %v, want %v %q %v",
				tc.line, r.Server, r.Direction, r.Deletes, tc.server, tc.dir, tc.deletes)
		}
		last := r.Paths[len(r.Paths)-1].Text
		if last != tc.path {
			t.Errorf("Parse(%q) transfer root = %q, want %q", tc.line, last, tc.path)
		}
	}
}

// The letters after an "e" in a short bundle are rsync's compatibility
// string, not options: reading them as flags would refuse every real
// client.
func TestTheRsyncCompatibilityStringIsNotReadAsFlags(t *testing.T) {
	if _, err := Parse("rsync --server -vlogDtpre.iLsfxCM . /srv/in"); err != nil {
		t.Errorf("a compatibility string was read as flags: %v", err)
	}
	if _, err := Parse("rsync --server -vMe.iLsfxC . /srv/in"); reasonOf(err) != ReasonOption {
		t.Errorf("-M before the compatibility string was admitted: %v", err)
	}
}

func TestGitDirectionIsTheFileMovementNotTheVerb(t *testing.T) {
	for _, tc := range []struct {
		line, verb string
		dir        Direction
		path       string
	}{
		{"git-upload-pack '/srv/git/x.git'", "upload-pack", Download, "/srv/git/x.git"},
		{"git-upload-archive /srv/git/x.git", "upload-archive", Download, "/srv/git/x.git"},
		{"git-receive-pack /srv/git/x.git", "receive-pack", Upload, "/srv/git/x.git"},
		{"git receive-pack --strict /srv/git/x.git", "receive-pack", Upload, "/srv/git/x.git"},
		{"git-upload-pack --timeout=30 /srv/git/x.git", "upload-pack", Download, "/srv/git/x.git"},
	} {
		c, err := Parse(tc.line)
		if err != nil {
			t.Fatalf("Parse(%q): %v", tc.line, err)
		}
		if c.Git.Verb != tc.verb || c.Git.Direction != tc.dir || c.Git.Path.Text != tc.path {
			t.Errorf("Parse(%q) = %q %q %q, want %q %q %q", tc.line,
				c.Git.Verb, c.Git.Direction, c.Git.Path.Text, tc.verb, tc.dir, tc.path)
		}
	}
}

func TestSFTPServerOptions(t *testing.T) {
	c, err := Parse("sftp-server -e -l INFO -R -u 0022")
	if err != nil {
		t.Fatal(err)
	}
	if !c.SFTPServer.ReadOnly {
		t.Error("-R was not read as read-only")
	}
	if len(c.SFTPServer.Options) != 6 {
		t.Errorf("options read as %q", c.SFTPServer.Options)
	}
	if _, err := Parse("sftp-server -lINFO"); err != nil {
		t.Errorf("a joined value was refused: %v", err)
	}
}

func TestAnErrorSaysWhatItCouldNotRead(t *testing.T) {
	_, err := Parse("scp -X /srv")
	var e *Error
	if !errors.As(err, &e) || e.Detail == "" || !strings.Contains(err.Error(), e.Reason) {
		t.Errorf("the refusal does not say what it could not read: %v", err)
	}
	if (&Error{Reason: ReasonEmpty}).Error() != ReasonEmpty {
		t.Error("a reason with no detail should render as the reason")
	}
}
