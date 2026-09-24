package ftp_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/icap/icaptest"
	"github.com/rom/xproxy/internal/mfa"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// ftpBastionWith is ftpBastion with lines outside the ftp section too,
// for the icap services a listener refers to.
func ftpBastionWith(t *testing.T, ftpExtra, top string) (*proxy.Server, string, *targetFTP) {
	t.Helper()
	tg := startTargetFTP(t)
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: files
      address: "127.0.0.1:0"
      kind: ftp
      ftp:
        upstream: servers
%s
logging: {access: {enabled: false}}
upstreams:
  - name: servers
    endpoints: [{address: %s}]
%s
`, ftpExtra, tg.addr(), top)
	s := proxytest.Start(t, yaml)
	return s, s.Addrs()["files"], tg
}

// mods is the scanning requests the fake server saw, leaving out the
// OPTIONS probe every service answers when it is built.
func mods(f *icaptest.Server) []string {
	f.Mu.Lock()
	defer f.Mu.Unlock()
	out := make([]string, 0, len(f.Requests))
	for _, m := range f.Requests {
		if m == "REQMOD" || m == "RESPMOD" {
			out = append(out, m)
		}
	}
	return out
}

func castFiles(t *testing.T, dir string) []string {
	t.Helper()
	got, err := filepath.Glob(filepath.Join(dir, "*.cast"))
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// A recording is what the session did: the commands as the person sent
// them, the replies as the target gave them, and a mark for each
// transfer. What it must not hold is the password, and what it must
// not hold is the file.
func TestRecordingHoldsTheDialogueAndNotTheSecrets(t *testing.T) {
	dir := t.TempDir()
	s, addr, tg := ftpBastion(t, "        recording: {directory: "+dir+"}")
	c := dialFTP(t, addr)
	c.login("alice", "hunter2")
	if code, _ := c.cmd("CWD /pub"); code != 250 {
		t.Fatalf("CWD was %d", code)
	}
	// A download, so there is a transfer to mark.
	data := c.passive()
	if code, _ := c.cmd("RETR file.txt"); code != 150 {
		t.Fatalf("RETR was %d", code)
	}
	conn, err := net.Dial("tcp", data)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(conn)
	_ = conn.Close()
	if code, _ := c.reply(); code != 226 {
		t.Fatalf("transfer end was %d", code)
	}
	if !strings.Contains(string(body), "hello from the server") {
		t.Fatalf("the file did not arrive: %q", body)
	}
	_, _ = c.cmd("QUIT")
	// The file is created at login and flushed when the session ends,
	// so its existence is not the signal to read it: ftp_recorded is
	// incremented after the flush, which is.
	deadline := time.Now().Add(10 * time.Second)
	for s.Stats().FTPRecorded == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the session ended without a finished recording")
		}
		time.Sleep(10 * time.Millisecond)
	}
	files := castFiles(t, dir)
	if len(files) != 1 {
		t.Fatalf("%d recordings, want 1", len(files))
	}
	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, want := range []string{"USER alice", "CWD /pub", "RETR file.txt", "226", "RETR /pub/file.txt"} {
		if !strings.Contains(text, want) {
			t.Errorf("the recording does not carry %q:\n%s", want, text)
		}
	}
	// The password is the one thing a recording must never hold: a file
	// an operator cannot safely keep is one that gets turned off.
	if strings.Contains(text, "hunter2") {
		t.Error("the password reached the recording")
	}
	if !strings.Contains(text, "redacted") {
		t.Error("the recording does not say the password was left out")
	}
	// Nor the file: a mark says what moved, the bytes stay out.
	if strings.Contains(text, "hello from the server") {
		t.Error("the transferred file reached the recording")
	}
	_ = tg
	// The header names the session, so a file found alone says whose it is.
	var head struct {
		Title string            `json:"title"`
		Env   map[string]string `json:"env"`
	}
	if err := json.Unmarshal([]byte(strings.SplitN(text, "\n", 2)[0]), &head); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(head.Title, "alice@") || head.Env["XPROXY_PROTOCOL"] != "ftp" {
		t.Errorf("header %+v does not name the session", head)
	}
}

// A connection that never logs in writes no file: it is in the access
// log already, and a directory of empty recordings hides the real ones.
func TestNoLoginNoRecording(t *testing.T) {
	dir := t.TempDir()
	_, addr, _ := ftpBastion(t, "        recording: {directory: "+dir+"}")
	c := dialFTP(t, addr)
	if code, _ := c.cmd("USER alice"); code != 331 {
		t.Fatalf("USER was %d", code)
	}
	_, _ = c.cmd("QUIT")
	time.Sleep(200 * time.Millisecond)
	if got := castFiles(t, dir); len(got) != 0 {
		t.Errorf("%d recordings for a session that never logged in", len(got))
	}
}

// An upload goes to the scanner before it goes to the server, and a
// file the scanner refuses never reaches it at all.
func TestICAPBlocksAnUploadBeforeItLands(t *testing.T) {
	fake := icaptest.New(t, 0)
	top := fmt.Sprintf("icap:\n  services:\n    - {name: av, url: %q, fail: closed}\n", fake.URL())
	s, addr, tg := ftpBastionWith(t, "        icap: {service: av}", top)

	c := dialFTP(t, addr)
	c.login("alice", "secret")
	data := c.passive()
	if code, _ := c.cmd("STOR bad.txt"); code != 150 {
		t.Fatalf("STOR was %d", code)
	}
	conn, err := net.Dial("tcp", data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "EICAR-test-body"); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	code, text := c.reply()
	if code != 426 {
		t.Fatalf("a refused upload ended %d %q, want 426", code, text)
	}
	if !strings.Contains(text, "scanner") {
		t.Errorf("the client was not told why: %q", text)
	}
	if got := tg.lastStored(); strings.Contains(got, "EICAR") {
		t.Errorf("the refused file reached the server: %q", got)
	}
	if st := s.Stats(); st.FTPScanBlocked != 1 {
		t.Errorf("ftp_scan_blocked %d, want 1", st.FTPScanBlocked)
	}
}

// A clean upload is scanned and still arrives whole: scanning holds the
// file, it does not eat it.
func TestICAPPassesACleanUploadThrough(t *testing.T) {
	fake := icaptest.New(t, 0)
	top := fmt.Sprintf("icap:\n  services:\n    - {name: av, url: %q, fail: closed}\n", fake.URL())
	s, addr, tg := ftpBastionWith(t, "        icap: {service: av}", top)

	c := dialFTP(t, addr)
	c.login("alice", "secret")
	data := c.passive()
	if code, _ := c.cmd("STOR good.txt"); code != 150 {
		t.Fatalf("STOR was %d", code)
	}
	conn, err := net.Dial("tcp", data)
	if err != nil {
		t.Fatal(err)
	}
	const payload = "a perfectly ordinary file"
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if code, _ := c.reply(); code != 226 {
		t.Fatalf("a clean upload ended %d", code)
	}
	if got := tg.lastStored(); got != payload {
		t.Errorf("the server got %q, want %q", got, payload)
	}
	if st := s.Stats(); st.FTPScanned != 1 || st.FTPScanBlocked != 0 {
		t.Errorf("scanned %d blocked %d, want 1 and 0", st.FTPScanned, st.FTPScanBlocked)
	}
	// The scanner was given the file, and told where it came from.
	bodies, mods := fake.Bodies, mods(fake)
	if len(bodies) != 1 || bodies[0] != payload {
		t.Errorf("the scanner saw %q", bodies)
	}
	if len(mods) != 1 || mods[0] != "REQMOD" {
		t.Errorf("an upload was sent as %v, want one REQMOD", mods)
	}
}

// A directory listing is not a file, and is not worth a scanner's time.
func TestICAPDoesNotScanListings(t *testing.T) {
	fake := icaptest.New(t, 0)
	top := fmt.Sprintf("icap:\n  services:\n    - {name: av, url: %q, fail: closed}\n", fake.URL())
	_, addr, _ := ftpBastionWith(t, "        icap: {service: av, downloads: true}", top)

	c := dialFTP(t, addr)
	c.login("alice", "secret")
	data := c.passive()
	if code, _ := c.cmd("LIST"); code != 150 {
		t.Fatalf("LIST was %d", code)
	}
	conn, err := net.Dial("tcp", data)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(conn)
	_ = conn.Close()
	if code, _ := c.reply(); code != 226 {
		t.Fatalf("LIST ended %d", code)
	}
	if n := len(mods(fake)); n != 0 {
		t.Errorf("a listing was sent to the scanner %d times", n)
	}
}

// enrol writes an enrolment file and returns its path and the secret.
func enrol(t *testing.T, user string) (string, string) {
	t.Helper()
	secret, err := mfa.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "mfa")
	line := fmt.Sprintf("%s:%s\n", user, secret)
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, secret
}

func code(t *testing.T, secret string) string {
	t.Helper()
	raw, err := mfa.ParseSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	p := mfa.Params{}
	c, err := mfa.Code(raw, mfa.Counter(time.Now(), 30*time.Second), p)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The password alone is not a login when a second factor is required:
// the proxy asks with 332 and holds every other command until the code
// arrives.
func TestMFAIsAskedForWithACCT(t *testing.T) {
	file, secret := enrol(t, "alice")
	s, addr, _ := ftpBastion(t, "        mfa: {file: "+file+"}")
	c := dialFTP(t, addr)
	if code, _ := c.cmd("USER alice"); code != 331 {
		t.Fatalf("USER was %d", code)
	}
	rc, text := c.cmd("PASS secret")
	if rc != 332 {
		t.Fatalf("PASS was %d %q, want 332", rc, text)
	}
	// Nothing else works until the factor is in.
	if rc, _ := c.cmd("PWD"); rc != 530 {
		t.Errorf("PWD before the factor was %d, want 530", rc)
	}
	if rc, _ := c.cmd("ACCT 000000"); rc != 530 {
		t.Errorf("a wrong code was %d, want 530", rc)
	}
	if rc, _ := c.cmd("ACCT %s", code(t, secret)); rc != 230 {
		t.Errorf("the right code was %d, want 230", rc)
	}
	if rc, _ := c.cmd("PWD"); rc != 257 {
		t.Errorf("PWD after the factor was %d", rc)
	}
	st := s.Stats()
	if st.FTPMFAOK != 1 || st.FTPMFAFailed != 1 {
		t.Errorf("mfa ok %d failed %d, want 1 and 1", st.FTPMFAOK, st.FTPMFAFailed)
	}
}

// A client with no ACCT of its own appends the code to the password.
// The target must never see it.
func TestMFACodeAppendedToThePassword(t *testing.T) {
	file, secret := enrol(t, "bob")
	_, addr, tg := ftpBastion(t, "        mfa: {file: "+file+"}")
	c := dialFTP(t, addr)
	if rc, _ := c.cmd("USER bob"); rc != 331 {
		t.Fatalf("USER was %d", rc)
	}
	if rc, text := c.cmd("PASS secret,%s", code(t, secret)); rc != 230 {
		t.Fatalf("PASS with the code was %d %q, want 230", rc, text)
	}
	if rc, _ := c.cmd("PWD"); rc != 257 {
		t.Errorf("PWD after the factor was %d", rc)
	}
	for _, line := range tg.commands() {
		if strings.HasPrefix(line, "PASS ") && strings.Contains(line, ",") {
			t.Errorf("the target was given the code: %q", line)
		}
	}
}

// An unenrolled user is refused where the policy requires enrolment:
// an optional second factor is one an attacker declines by using an
// account that never enrolled.
func TestUnenrolledUserIsRefused(t *testing.T) {
	file, _ := enrol(t, "alice")
	_, addr, _ := ftpBastion(t, "        mfa: {file: "+file+"}")
	c := dialFTP(t, addr)
	if rc, _ := c.cmd("USER mallory"); rc != 331 {
		t.Fatalf("USER was %d", rc)
	}
	if rc, _ := c.cmd("PASS secret"); rc != 332 {
		t.Fatalf("PASS was %d, want 332 even for a user with no enrolment", rc)
	}
	if rc, _ := c.cmd("ACCT 123456"); rc != 530 {
		t.Errorf("an unenrolled user got %d, want 530", rc)
	}
	if rc, _ := c.cmd("PWD"); rc != 530 {
		t.Errorf("an unenrolled user reached PWD: %d", rc)
	}
}

// TestARecoveryCodeOpensTheSession is the seventh round's sweep of the
// finding the sixth round made on RDP: the bound on what could be
// split off a password was sixteen characters and a recovery code is
// seventeen, so the recovery path did not work on either of the two
// protocols that carry a code that way. Fixed in both; this is the
// half that holds it here.
//
// It is driven through a real enrolment written by the control plane,
// so the code under test is the one an operator would be handed.
func TestARecoveryCodeOpensTheSession(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "mfa")
	if err := os.WriteFile(file, []byte("# empty\nplaceholder:JBSWY3DPEHPK3PXPJBSWY3DPEH\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := mfa.Load(file)
	if err != nil {
		t.Fatal(err)
	}
	_, codes, err := store.Enrol("alice", mfa.Params{})
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) == 0 {
		t.Fatal("no recovery codes")
	}

	s, addr, tg := ftpBastion(t, "        mfa: {file: "+file+"}")
	c := dialFTP(t, addr)
	if rc, _ := c.cmd("USER alice"); rc != 331 {
		t.Fatalf("USER was %d", rc)
	}
	// The recovery code rides the password, which is the arrangement
	// that was refusing it for being one character too long.
	if rc, text := c.cmd("PASS her-password,%s", codes[0]); rc != 230 {
		t.Fatalf("a recovery code was refused: %d %q", rc, text)
	}
	if rc, _ := c.cmd("PWD"); rc != 257 {
		t.Errorf("PWD after the recovery code was %d", rc)
	}
	for _, line := range tg.commands() {
		if strings.HasPrefix(line, "PASS ") && strings.Contains(line, ",") {
			t.Errorf("the target was given the recovery code: %q", line)
		}
	}
	if n := s.Stats().FTPMFAOK; n != 1 {
		t.Errorf("ftp_mfa_ok %d, want 1", n)
	}

	// And it is single use: the same code again is refused.
	c2 := dialFTP(t, addr)
	if rc, _ := c2.cmd("USER alice"); rc != 331 {
		t.Fatalf("USER was %d", rc)
	}
	// A code that came in on the password is verified there, so a
	// spent one is refused outright rather than asked for again.
	if rc, _ := c2.cmd("PASS her-password,%s", codes[0]); rc != 530 {
		t.Errorf("a replayed recovery code was %d, want 530", rc)
	}
	if rc, _ := c2.cmd("PWD"); rc != 530 {
		t.Errorf("a replayed recovery code reached PWD: %d", rc)
	}
}
