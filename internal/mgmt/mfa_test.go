package mgmt

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	_ "github.com/rom/xproxy/internal/kinds/telnet" // a listener kind with a second factor
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/mfa"
	"github.com/rom/xproxy/internal/proxy"
)

// mfaServer starts a proxy with one telnet listener that asks for a
// second factor, and the management socket in front of it.
func mfaServer(t *testing.T) (*proxy.Server, string, string) {
	t.Helper()
	dir := t.TempDir()
	file := filepath.Join(dir, "mfa")
	if err := os.WriteFile(file, []byte("seed:JBSWY3DPEHPK3PXPJBSWY3DPEH\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]byte(`
version: 1
server:
  listeners:
    - name: kit
      address: "127.0.0.1:0"
      kind: telnet
      telnet: {upstream: u, mfa: {file: ` + file + `}}
logging: {access: {enabled: false}}
upstreams:
  - name: u
    endpoints: [{address: "127.0.0.1:1"}]
`))
	if err != nil {
		t.Fatal(err)
	}
	p, err := proxy.New(cfg, logging.Discard())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = p.Shutdown(ctx)
	})
	sock := filepath.Join(dir, "m.sock")
	m := New(config.Management{Socket: sock, SocketMode: "0600"}, p, logging.Discard(), Actions{})
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Shutdown(context.Background()) })
	return p, sock, file
}

// call makes one management request over the socket.
func call(t *testing.T, sock, method, path string, body any) (int, []byte) {
	t.Helper()
	c := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, "http://unix"+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, out
}

// A person enrolled through the socket can use the factor at once, and
// what comes back is what an operator has to show them once.
func TestEnrolThroughTheSocketWorksImmediately(t *testing.T) {
	p, sock, file := mfaServer(t)

	code, body := call(t, sock, "POST", "/v1/mfa/enrol",
		map[string]any{"listener": "kit", "user": "alice", "issuer": "Lab"})
	if code != 200 {
		t.Fatalf("enrol: %d %s", code, body)
	}
	var out struct {
		Secret   string   `json:"secret"`
		URI      string   `json:"uri"`
		Recovery []string `json:"recovery"`
		ShowOnce bool     `json:"show_once"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if out.Secret == "" || len(out.Recovery) != mfa.RecoveryCodes || !out.ShowOnce {
		t.Fatalf("enrolment: %+v", out)
	}
	if !strings.HasPrefix(out.URI, "otpauth://totp/") || !strings.Contains(out.URI, "Lab") {
		t.Errorf("uri %q", out.URI)
	}

	// The listener verifies a code made with it, with no reload.
	list := p.MFA()
	if len(list) != 1 || list[0].Listener != "kit" || list[0].File != file {
		t.Fatalf("status %+v", list)
	}
	var found bool
	for _, u := range list[0].Users {
		if u.User == "alice" {
			found = true
		}
	}
	if !found {
		t.Errorf("alice is not in the status: %+v", list[0].Users)
	}

	// And the file on disk holds the secret rather than the codes.
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "alice:") {
		t.Errorf("the file has no line for alice:\n%s", raw)
	}
	for _, c := range out.Recovery {
		if strings.Contains(string(raw), c) {
			t.Fatal("a recovery code is in the file in clear")
		}
	}
}

// Removing a person takes them out of the status and the file at once.
func TestRemoveThroughTheSocket(t *testing.T) {
	p, sock, file := mfaServer(t)
	if code, body := call(t, sock, "POST", "/v1/mfa/enrol",
		map[string]any{"listener": "kit", "user": "alice"}); code != 200 {
		t.Fatalf("enrol: %d %s", code, body)
	}
	if code, body := call(t, sock, "POST", "/v1/mfa/remove",
		map[string]any{"listener": "kit", "user": "alice"}); code != 200 {
		t.Fatalf("remove: %d %s", code, body)
	}
	for _, u := range p.MFA()[0].Users {
		if u.User == "alice" {
			t.Error("a removed user is still in the status")
		}
	}
	raw, _ := os.ReadFile(file)
	if strings.Contains(string(raw), "alice:") {
		t.Errorf("a removed user is still in the file:\n%s", raw)
	}
	// Removing them again says so rather than pretending.
	if code, _ := call(t, sock, "POST", "/v1/mfa/remove",
		map[string]any{"listener": "kit", "user": "alice"}); code != 409 {
		t.Errorf("removing twice answered %d", code)
	}
}

// Replacing the recovery codes gives new ones and says they are shown
// once.
func TestRecoveryThroughTheSocket(t *testing.T) {
	_, sock, _ := mfaServer(t)
	call(t, sock, "POST", "/v1/mfa/enrol", map[string]any{"listener": "kit", "user": "alice"})
	code, body := call(t, sock, "POST", "/v1/mfa/recovery",
		map[string]any{"listener": "kit", "user": "alice"})
	if code != 200 {
		t.Fatalf("recovery: %d %s", code, body)
	}
	var out struct {
		Recovery []string `json:"recovery"`
		ShowOnce bool     `json:"show_once"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Recovery) != mfa.RecoveryCodes || !out.ShowOnce {
		t.Errorf("recovery: %+v", out)
	}
}

// The status view shows a lockout and unlocking clears it, which is
// what an operator does for somebody whose authenticator drifted.
func TestUnlockThroughTheSocket(t *testing.T) {
	p, sock, _ := mfaServer(t)
	call(t, sock, "POST", "/v1/mfa/enrol", map[string]any{"listener": "kit", "user": "alice"})

	// Wrong codes until the guard gives up, driven through the
	// listener rather than reached into: what the status shows has to
	// be what a session would actually have caused.
	addr := p.Addrs()["kit"]
	for i := 0; i < 6; i++ {
		wrongCode(t, addr, "alice")
	}
	waitFor(t, "the lockout to show", func() bool { return lockedIn(t, sock, "kit", "alice") })
	if code, body := call(t, sock, "POST", "/v1/mfa/unlock",
		map[string]any{"listener": "kit", "user": "alice"}); code != 200 {
		t.Fatalf("unlock: %d %s", code, body)
	}
	if lockedIn(t, sock, "kit", "alice") {
		t.Error("the user is still locked out")
	}
}

// The status and the actions refuse a listener that has no factor,
// rather than answering as if they had done something.
func TestAListenerWithoutAFactorIsRefused(t *testing.T) {
	_, sock, _ := mfaServer(t)
	for _, path := range []string{"/v1/mfa/enrol", "/v1/mfa/remove", "/v1/mfa/unlock", "/v1/mfa/recovery"} {
		code, body := call(t, sock, "POST", path,
			map[string]any{"listener": "nowhere", "user": "alice"})
		if code != 409 {
			t.Errorf("%s answered %d: %s", path, code, body)
		}
		if !strings.Contains(string(body), "second factor") {
			t.Errorf("%s said %q", path, body)
		}
	}
	// And a request with nothing in it is a bad request, not a 500.
	for _, path := range []string{"/v1/mfa/enrol", "/v1/mfa/remove"} {
		if code, _ := call(t, sock, "POST", path, map[string]any{}); code != 400 {
			t.Errorf("%s with no fields answered %d", path, code)
		}
	}
}

// lockedIn asks the status view whether a user is locked out. The
// answer is decoded rather than matched as text: the view is rendered
// for a person to read, and a check that depended on its spacing would
// pass or fail for the wrong reason.
func lockedIn(t *testing.T, sock, listener, user string) bool {
	t.Helper()
	code, body := call(t, sock, "GET", "/v1/mfa", nil)
	if code != 200 {
		t.Fatalf("status: %d %s", code, body)
	}
	var view []struct {
		Listener string `json:"listener"`
		Users    []struct {
			User   string `json:"user"`
			Locked bool   `json:"locked"`
		} `json:"users"`
	}
	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatalf("status: %v\n%s", err, body)
	}
	for _, l := range view {
		if l.Listener != listener {
			continue
		}
		for _, u := range l.Users {
			if u.User == user {
				return u.Locked
			}
		}
	}
	t.Fatalf("%s is not in the status for %s:\n%s", user, listener, body)
	return false
}

// wrongCode opens one telnet session and gives a code that is not the
// right one.
func wrongCode(t *testing.T, addr, user string) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	readUntil(t, c, "login: ")
	if _, err := c.Write([]byte(user + "\r\n")); err != nil {
		return
	}
	readUntil(t, c, "code: ")
	if _, err := c.Write([]byte("000000\r\n")); err != nil {
		return
	}
	readUntil(t, c, "not accepted")
}

// readUntil reads until want appears or the deadline passes.
func readUntil(t *testing.T, c net.Conn, want string) {
	t.Helper()
	var got []byte
	buf := make([]byte, 512)
	for {
		n, err := c.Read(buf)
		got = append(got, buf[:n]...)
		if strings.Contains(string(got), want) || err != nil {
			return
		}
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A name that cannot go in the file is refused before anything is
// written.
func TestABadNameIsRefused(t *testing.T) {
	_, sock, file := mfaServer(t)
	before, _ := os.ReadFile(file)
	code, body := call(t, sock, "POST", "/v1/mfa/enrol",
		map[string]any{"listener": "kit", "user": "a:b"})
	if code != 409 {
		t.Fatalf("a name with a separator answered %d: %s", code, body)
	}
	after, _ := os.ReadFile(file)
	if string(before) != string(after) {
		t.Error("the file changed for a refused name")
	}
}
