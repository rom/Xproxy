package ssh_test

// The structured command rules end to end: the rule an operator writes,
// the commands a client sends, and what reaches the target. The refusal
// labels are spelled out rather than imported, because they are what
// docs/TROUBLESHOOTING.md tells an operator to look for in the counters.

import (
	"encoding/binary"
	"strings"
	"testing"

	cssh "golang.org/x/crypto/ssh"
)

// End to end, through a real listener: the rule an operator writes, the
// commands a client sends, and what reaches the target.
func TestARuleDecidesTheSessionNotAPattern(t *testing.T) {
	extra := `        sftp: {allow_paths: ["/srv/data/**"]}
        command_rules:
          - command: scp
            directions: [upload]
            paths: ["/srv/incoming/**"]
          - command: rsync
            directions: [download]
            paths: ["/srv/data/**"]`
	s, addr, key, tg := bastion(t, extra)
	c := dialBastion(t, addr, key)

	// What the rule allows reaches the target, although the blanket
	// refusal an sftp policy brings would have stopped it.
	for _, cmd := range []string{
		"scp -t /srv/incoming",
		"rsync --server --sender -vlogDtpre.iLsfxC . /srv/data",
	} {
		sess, err := c.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sess.Output(cmd); err != nil {
			t.Errorf("%q was refused: %v", cmd, err)
		}
		_ = sess.Close()
	}
	ran := strings.Join(tg.seen(), "\n")
	if !strings.Contains(ran, "exec:scp -t /srv/incoming") {
		t.Errorf("the allowed upload did not reach the target: %s", ran)
	}
	// And every spelling a pattern would have admitted is refused,
	// counted under what was wrong with it.
	for _, cmd := range []string{
		"scp -f /srv/incoming",                      // the other direction
		"scp -rt /srv/incoming",                     // recursion
		"scp -t /srv/incoming/../../etc/ssh",        // resolves elsewhere
		"/usr/bin/scp -t /etc",                      // a path, and outside
		"LD_PRELOAD=/tmp/x.so scp -t /srv/incoming", // an assignment in front
		"rsync --server . /srv/data",                // upload where only downloads are allowed
		"rsync --server --sender . /srv/other",      // outside the paths
		"git-upload-pack /srv/git/x.git",            // a family with no rule
		"/usr/lib/openssh/sftp-server",              // likewise
	} {
		sess, err := c.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := sess.Output(cmd); err == nil {
			t.Errorf("%q was allowed", cmd)
		}
		_ = sess.Close()
	}
	for _, r := range tg.seen() {
		for _, bad := range []string{"-f /srv", "-rt", "/etc", "sftp-server", "git-upload-pack", "LD_PRELOAD"} {
			if strings.HasPrefix(r, "exec:") && strings.Contains(r, bad) {
				t.Errorf("a refused command reached the target: %s", r)
			}
		}
	}
	refusals := s.Stats().Refusals["ssh"]
	for _, want := range []string{"command_direction", "command_recursive", "command_path", "command_env", "command_no_rule"} {
		if refusals[want] == 0 {
			t.Errorf("no refusal counted under %q: %v", want, refusals)
		}
	}
	// An ordinary command is still the patterns' business, not the
	// rules': with no allow_commands it runs.
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if out, err := sess.Output("uptime"); err != nil || string(out) != "ran uptime" {
		t.Fatalf("an ordinary command: %q %v", out, err)
	}
}

// A line the parser cannot read is refused when it names a family the
// rules cover, and left to the patterns when it does not.
func TestAnUnreadableTransferLineIsRefusedNotPatterned(t *testing.T) {
	extra := `        allow_shell_syntax: true
        allow_commands: ["^echo .*$"]
        command_rules:
          - command: scp
            directions: [upload]
            paths: ["/srv/incoming/**"]`
	s, addr, key, tg := bastion(t, extra)
	c := dialBastion(t, addr, key)
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	// Shell syntax is allowed on this listener, so the gate before the
	// rules lets it through; the rules refuse it for being a transfer
	// command whose words cannot be trusted.
	if _, err := sess.Output("scp -t $(cat /etc/hostname)"); err == nil {
		t.Error("an unreadable scp line was allowed")
	}
	_ = sess.Close()
	if s.Stats().Refusals["ssh"]["command_syntax"] == 0 {
		t.Errorf("the refusal was not counted as syntax: %v", s.Stats().Refusals["ssh"])
	}
	// A command of no family keeps the behaviour it had before rules
	// existed: the patterns decide, operators and all.
	sess, err = c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sess.Output("echo $(id)"); err != nil {
		t.Errorf("a pattern-allowed command was refused: %v", err)
	}
	for _, r := range tg.seen() {
		if strings.Contains(r, "scp") {
			t.Errorf("the unreadable line reached the target: %s", r)
		}
	}
}

// An approved exec of the sftp server binary is relayed through the
// sftp policy, which is what makes approving it safe: the same read-only
// and path rules the subsystem is held to apply to the exec.
func TestAnApprovedSFTPServerExecIsInspected(t *testing.T) {
	extra := `        sftp: {read_only: true, allow_paths: ["/srv/data/**"]}
        command_rules:
          - command: sftp_server
            enforce_sftp_policy: true`
	s, addr, key, tg := bastion(t, extra)
	c := dialBastion(t, addr, key)
	ch, reqs, err := c.OpenChannel("session", nil)
	if err != nil {
		t.Fatal(err)
	}
	go cssh.DiscardRequests(reqs)
	ok, err := ch.SendRequest("exec", true, sshStringBytes("/usr/lib/openssh/sftp-server -e"))
	if err != nil || !ok {
		t.Fatalf("the approved exec was refused: %v %v", ok, err)
	}
	if _, err := ch.Write(sftpPacket(1, binary.BigEndian.AppendUint32(nil, 3))); err != nil {
		t.Fatal(err)
	}
	if typ, _ := readSFTP(t, ch); typ != 2 {
		t.Fatalf("version reply was type %d", typ)
	}
	// A write through the exec is refused by the same read-only rule
	// the subsystem is held to.
	write := binary.BigEndian.AppendUint32(nil, 2)
	write = append(write, sftpStr("/srv/data/report.csv")...)
	write = binary.BigEndian.AppendUint32(write, 0x2|0x8)
	write = binary.BigEndian.AppendUint32(write, 0)
	if _, err := ch.Write(sftpPacket(3, write)); err != nil {
		t.Fatal(err)
	}
	if typ, payload := readSFTP(t, ch); typ != 101 || binary.BigEndian.Uint32(payload[4:]) != 3 {
		t.Fatalf("the write should have been refused: type %d", typ)
	}
	// And a path outside the tree, which the exec has no way around.
	outside := binary.BigEndian.AppendUint32(nil, 3)
	outside = append(outside, sftpStr("/etc/shadow")...)
	outside = binary.BigEndian.AppendUint32(outside, 0x1)
	outside = binary.BigEndian.AppendUint32(outside, 0)
	if _, err := ch.Write(sftpPacket(3, outside)); err != nil {
		t.Fatal(err)
	}
	if typ, _ := readSFTP(t, ch); typ != 101 {
		t.Fatalf("the path outside the tree should have been refused: type %d", typ)
	}
	for _, r := range tg.seen() {
		if r == "sftp:3" {
			t.Error("a refused open reached the target")
		}
	}
	if s.Stats().SFTPRefused < 2 {
		t.Errorf("the sftp refusals were not counted: %d", s.Stats().SFTPRefused)
	}
}

// A principal with a policy of its own but no rules inherits the
// listener's, as every other field does: otherwise adding a principal
// entry silently drops the transfer rules.
func TestAPrincipalInheritsTheListenersRules(t *testing.T) {
	extra := `        command_rules:
          - command: scp
            directions: [upload]
            paths: ["/srv/incoming/**"]
        principals:
          - name: everyone
            policy:
              allow_env: [TERM]`
	_, addr, key, tg := bastion(t, extra)
	c := dialBastion(t, addr, key)
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sess.Output("scp -f /srv/incoming"); err == nil {
		t.Error("a download was allowed although the listener's rule says uploads only")
	}
	_ = sess.Close()
	sess, err = c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sess.Output("scp -t /srv/incoming"); err != nil {
		t.Errorf("the inherited rule refused what it allows: %v", err)
	}
	for _, r := range tg.seen() {
		if strings.Contains(r, "-f /srv") {
			t.Errorf("the refused download reached the target: %s", r)
		}
	}
}
