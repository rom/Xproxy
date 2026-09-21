package admin

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/passwd"
)

// Revocation must take effect while the GUI runs. Before this, the users
// file was read once at start-up and a session carried its role for its
// whole life, so a removed operator kept logging in and a demoted one
// kept write access until somebody restarted the process.

// rewrite replaces the users file and makes sure the change is visible to
// the change detector (the test writes twice within one clock tick).
func rewrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
}

func TestUsersFileIsRereadWhenItChanges(t *testing.T) {
	dir := t.TempDir()
	p := writeUsers(t, dir)
	u, err := LoadUsers(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := u.Lookup("op"); !ok {
		t.Fatal("the operator is missing from the file as written")
	}
	// A second process (the user command, configuration management, an
	// operator with an editor) removes the account.
	rewrite(t, p, "view:viewer:x509\n")
	u.now = func() time.Time { return time.Now().Add(time.Hour) } // past the recheck interval
	if _, ok := u.Lookup("op"); ok {
		t.Fatal("a user removed from the file still resolves")
	}
	if _, ok := u.Lookup("view"); !ok {
		t.Fatal("a user added to the file does not resolve")
	}
	// A role lowered in the file is the role that applies.
	rewrite(t, p, "view:viewer:x509\nop:viewer:x509\n")
	u.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if x, ok := u.Lookup("op"); !ok || x.Role != RoleViewer {
		t.Fatalf("role after the rewrite: %v %v", x.Role, ok)
	}
}

// A file that cannot be parsed must not empty the set: a half-written
// file would otherwise lock every operator out of the GUI.
func TestUnreadableUsersFileKeepsTheCurrentSet(t *testing.T) {
	dir := t.TempDir()
	p := writeUsers(t, dir)
	u, err := LoadUsers(p)
	if err != nil {
		t.Fatal(err)
	}
	var warned error
	u.Warn = func(err error) { warned = err }
	rewrite(t, p, "this is not a users file\n")
	u.now = func() time.Time { return time.Now().Add(time.Hour) }
	if _, ok := u.Lookup("op"); !ok {
		t.Fatal("a malformed file locked the operator out")
	}
	if warned == nil {
		t.Fatal("the failed re-read was not reported")
	}
}

// An empty file, on the other hand, is a deliberate revocation of
// everyone and must be honoured.
func TestEmptiedUsersFileRevokesEveryone(t *testing.T) {
	dir := t.TempDir()
	p := writeUsers(t, dir)
	u, err := LoadUsers(p)
	if err != nil {
		t.Fatal(err)
	}
	rewrite(t, p, "# everyone removed\n")
	u.now = func() time.Time { return time.Now().Add(time.Hour) }
	if got := len(u.List()); got != 0 {
		t.Fatalf("users after the file was emptied: %d", got)
	}
}

func TestSessionEndsWhenTheUserIsRemoved(t *testing.T) {
	dir := t.TempDir()
	fm := startFakeMgmt(t)
	p := writeUsers(t, dir)
	s, c := newTestServer(t, Options{Listen: "127.0.0.1:0", Socket: fm.path, UsersFile: p})
	if st := c.login("op", "operator-password-1"); st != 200 {
		t.Fatalf("login: %d", st)
	}
	if st, _ := c.do("GET", "/api/status", nil, false); st != 200 {
		t.Fatalf("status while logged in: %d", st)
	}
	rewrite(t, p, "view:viewer:x509\n")
	s.users.now = func() time.Time { return time.Now().Add(time.Hour) }
	if st, _ := c.do("GET", "/api/status", nil, false); st != 401 {
		t.Fatalf("a removed user still had a live session: %d", st)
	}
}

func TestSessionLosesOperatorRightsWhenTheRoleIsLowered(t *testing.T) {
	dir := t.TempDir()
	fm := startFakeMgmt(t)
	p := writeUsers(t, dir)
	s, c := newTestServer(t, Options{Listen: "127.0.0.1:0", Socket: fm.path, UsersFile: p})
	if st := c.login("op", "operator-password-1"); st != 200 {
		t.Fatalf("login: %d", st)
	}
	vw, err := passwd.HashWithIterations("operator-password-1", 1000)
	if err != nil {
		t.Fatal(err)
	}
	rewrite(t, filepath.Join(dir, "users"), "op:viewer:"+vw+"\n")
	s.users.now = func() time.Time { return time.Now().Add(time.Hour) }
	// Reads still work; a write is refused with the viewer's rights.
	if st, _ := c.do("GET", "/api/status", nil, false); st != 200 {
		t.Fatalf("status as a viewer: %d", st)
	}
	st, _ := c.do("POST", "/api/reload", nil, true)
	if st != 403 {
		t.Fatalf("a demoted operator still had write access: %d", st)
	}
}

// Keying the login limiter on the source alone locked every operator
// out for the window after five bad logins from one place — and a
// client over the Unix socket or an SSH tunnel is one place, "local",
// for everybody. Keying on the account alone would allow unlimited
// spraying across names, so the key is both, with a global ceiling that
// still stops a spray.
func TestLoginLimiterKeysSourceAndUser(t *testing.T) {
	dir := t.TempDir()
	fm := startFakeMgmt(t)
	p := writeUsers(t, dir)
	_, c := newTestServer(t, Options{Listen: "127.0.0.1:0", Socket: fm.path, UsersFile: p})
	for i := 0; i < 5; i++ {
		if st := c.login("op", "wrong"); st != 401 {
			t.Fatalf("failure %d: %d", i, st)
		}
	}
	if st := c.login("op", "operator-password-1"); st != 429 {
		t.Fatalf("the account was not locked after five failures: %d", st)
	}
	// Another operator from the same tunnel still gets in.
	if st := c.login("view", "viewer-password-01"); st != 200 {
		t.Fatalf("one account's failures locked out another operator: %d", st)
	}
}

// A spray across many names from one place does reach the global
// ceiling, at which point the GUI is closed for the window.
func TestLoginLimiterGlobalCeiling(t *testing.T) {
	l := newLoginLimiter(5, time.Minute)
	for i := 0; i < 5*globalFactor; i++ {
		l.fail("local", "user"+strconv.Itoa(i))
	}
	if blocked, wait := l.blocked("local", "someone-else"); !blocked || wait <= 0 {
		t.Fatalf("a spray across names was not stopped: %v %v", blocked, wait)
	}
	// It lifts with the window.
	l.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	if blocked, _ := l.blocked("local", "someone-else"); blocked {
		t.Fatal("the ceiling did not lift with the window")
	}
}
