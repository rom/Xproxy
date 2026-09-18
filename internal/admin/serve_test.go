package admin

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/testutil"
)

func TestStartUnixSocket(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "admin.sock")
	s, err := New(Options{Listen: "unix:" + sock, Socket: "/nonexistent", UsersFile: writeUsers(t, dir), Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	if s.Addr() == "" {
		t.Fatal("no address")
	}
	st, err := os.Stat(sock)
	if err != nil || st.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode: %v %v", st, err)
	}
	c := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}}}
	resp, err := c.Get("http://admin/api/health")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("health: %d", resp.StatusCode)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Fatal("socket left behind")
	}
}

func TestStartMutualTLSAndCertificateLogin(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	srvCert, srvKey := ca.Issue(t, dir, "admin.test")
	users := writeUsers(t, dir) // "cert" is an operator without a password
	s, err := New(Options{Listen: "127.0.0.1:0", Socket: "/nonexistent", UsersFile: users,
		TLS:            TLSOptions{CertFile: srvCert, KeyFile: srvKey, ClientCAFile: ca.Path},
		RestartCommand: []string{"/bin/true"}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = s.Shutdown(ctx)
	})
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	client := func(name string) *http.Client {
		tc := &tls.Config{RootCAs: pool, ServerName: "admin.test", MinVersion: tls.VersionTLS12}
		if name != "" {
			c, k := ca.Issue(t, dir, name)
			pair, err := tls.LoadX509KeyPair(c, k)
			if err != nil {
				t.Fatal(err)
			}
			tc.Certificates = []tls.Certificate{pair}
		}
		return &http.Client{Transport: &http.Transport{TLSClientConfig: tc}}
	}
	base := "https://" + s.Addr()

	// No client certificate: the handshake is refused.
	if _, err := client("").Get(base + "/api/health"); err == nil {
		t.Fatal("connection without a client certificate accepted")
	}
	// A certificate for an unknown user: connected but not logged in.
	resp, err := client("stranger").Get(base + "/api/me")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("unknown certificate user: %d", resp.StatusCode)
	}
	// A certificate whose common name is a user logs in as that user and
	// receives a session cookie with the __Host- prefix and Secure.
	c := client("cert")
	resp, err = c.Get(base + "/api/me")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"via":"certificate"`) || !strings.Contains(string(body), `"role":"operator"`) {
		t.Fatalf("certificate login: %d %s", resp.StatusCode, body)
	}
	var cookie *http.Cookie
	for _, ck := range resp.Cookies() {
		if ck.Name == "__Host-xproxy_admin" {
			cookie = ck
		}
	}
	if cookie == nil || !cookie.Secure || !cookie.HttpOnly {
		t.Fatalf("cookie: %+v", cookie)
	}
	if resp.Header.Get("Strict-Transport-Security") == "" {
		t.Fatal("HSTS missing over TLS")
	}
	// The session cookie alone (same TLS client) now authenticates, and
	// the operator may act.
	req, _ := http.NewRequest("POST", base+"/api/restart", nil)
	req.Header.Set("X-Xproxy-Admin", "1")
	req.AddCookie(cookie)
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("restart as certificate operator: %d", resp.StatusCode)
	}
	resp, err = c.Get(base + "/api/users")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"cert_only":true`) {
		t.Fatalf("users: %d %s", resp.StatusCode, body)
	}
}

func TestStartErrors(t *testing.T) {
	dir := t.TempDir()
	users := writeUsers(t, dir)
	// Unreadable certificate.
	s, err := New(Options{Listen: "127.0.0.1:0", Socket: "/x", UsersFile: users, TLS: TLSOptions{CertFile: "/nonexistent.pem", KeyFile: "/nonexistent.key"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err == nil {
		t.Fatal("start with a missing certificate succeeded")
	}
	// Client CA without certificates in it.
	ca := testutil.WriteCA(t, dir)
	c, k := ca.Issue(t, dir, "a")
	empty := filepath.Join(dir, "empty.pem")
	_ = os.WriteFile(empty, []byte("nothing"), 0o600)
	s, err = New(Options{Listen: "127.0.0.1:0", Socket: "/x", UsersFile: users, TLS: TLSOptions{CertFile: c, KeyFile: k, ClientCAFile: empty}})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err == nil {
		t.Fatal("start with an empty client CA succeeded")
	}
	// Address in use.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	s, err = New(Options{Listen: ln.Addr().String(), Socket: "/x", UsersFile: users})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(); err == nil {
		t.Fatal("start on a used port succeeded")
	}
	if err := (&Server{}).Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}
