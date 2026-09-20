package admin

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/passwd"
)

// ssoServer is a GUI wired to a fake provider, with the helpers every
// test below needs: a client that does not follow redirects, the state
// cookie handed out by /api/oidc/login, and the callback URL the
// provider would send the browser to.
type ssoServer struct {
	t    *testing.T
	idp  *fakeIDP
	srv  *Server
	c    *client
	raw  *http.Client
	toP  *http.Client // follows nothing, but trusts the provider's CA
	dir  string
	base string
}

func startSSO(t *testing.T, tweak func(*OIDCOptions)) *ssoServer {
	t.Helper()
	fm := startFakeMgmt(t)
	dir := t.TempDir()
	idp := startIDP(t)
	secret := filepath.Join(dir, "gui-secret")
	if err := os.WriteFile(secret, []byte("gui-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	o := OIDCOptions{Issuer: idp.srv.URL, ClientID: "gui", ClientSecretFile: secret, CAFile: idp.caFile(t, dir),
		Operators: []string{"proxy-admins"}, Viewers: []string{"proxy-viewers"}}
	if tweak != nil {
		tweak(&o)
	}
	srv, c := newTestServer(t, Options{Listen: "127.0.0.1:0", Socket: fm.path, UsersFile: writeUsers(t, dir), OIDC: &o})
	stop := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	toP := idp.srv.Client()
	toP.CheckRedirect = stop
	return &ssoServer{t: t, idp: idp, srv: srv, c: c, raw: &http.Client{CheckRedirect: stop}, toP: toP, dir: dir, base: c.base}
}

// start returns the state cookie and the callback URL the provider would
// redirect the browser to.
func (s *ssoServer) start() (*http.Cookie, string) {
	s.t.Helper()
	resp, err := s.raw.Get(s.base + oidcLoginPath)
	if err != nil {
		s.t.Fatal(err)
	}
	_ = resp.Body.Close()
	var ck *http.Cookie
	for _, x := range resp.Cookies() {
		if x.Name == oidcStateCookie {
			ck = x
		}
	}
	if ck == nil {
		s.t.Fatalf("no state cookie: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	back, err := s.toP.Get(resp.Header.Get("Location"))
	if err != nil {
		s.t.Fatal(err)
	}
	_ = back.Body.Close()
	return ck, back.Header.Get("Location")
}

// callback plays the browser's return trip and reports where the GUI
// sent it.
func (s *ssoServer) callback(target string, ck *http.Cookie) *http.Response {
	s.t.Helper()
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		s.t.Fatal(err)
	}
	if ck != nil {
		req.AddCookie(ck)
	}
	resp, err := s.raw.Do(req)
	if err != nil {
		s.t.Fatal(err)
	}
	_ = resp.Body.Close()
	return resp
}

func (s *ssoServer) where(resp *http.Response) string { return resp.Header.Get("Location") }

// TestSSOCallbackRejections walks the callback with every part of the
// flow broken in turn. Each one must land on the login page with a
// reason, never on a session.
func TestSSOCallbackRejections(t *testing.T) {
	s := startSSO(t, nil)

	// A cookie from one login does not authorise another login's code.
	ck1, _ := s.start()
	_, back2 := s.start()
	if got := s.where(s.callback(back2, ck1)); got != "/?sso_error=state_mismatch" {
		t.Errorf("a cookie from another login gave %q", got)
	}

	// The provider reporting an error, with a hostile reason: the reason
	// reaches the page sanitised, so it cannot smuggle markup or a
	// redirect into the GUI.
	hostile := url.QueryEscape("access_denied<script>alert(1)</script>\r\nLocation: http://evil")
	got := s.where(s.callback(s.base+oidcCallback+"?error="+hostile, nil))
	if strings.ContainsAny(got, "<>\r\n\"") || !strings.HasPrefix(got, "/?sso_error=provider%3Aaccess_denied") {
		t.Errorf("the provider's error reached the page as %q", got)
	}

	// No code, no state, an oversize cookie.
	for _, target := range []string{
		s.base + oidcCallback,
		s.base + oidcCallback + "?code=c0de",
		s.base + oidcCallback + "?state=x",
	} {
		ck, _ := s.start()
		if got := s.where(s.callback(target, ck)); got != "/?sso_error=state_missing" {
			t.Errorf("%s gave %q", target, got)
		}
	}
	ck, back := s.start()
	big := &http.Cookie{Name: oidcStateCookie, Value: strings.Repeat("A", 4097)}
	if got := s.where(s.callback(back, big)); got != "/?sso_error=state_missing" {
		t.Errorf("an oversize state cookie gave %q", got)
	}

	// A cookie that is not the sealed state at all, and one whose
	// ciphertext has been flipped: the state parameter is derived from
	// the cookie, so both have to carry a matching parameter to get past
	// the binding check and reach the seal.
	for _, name := range []string{"not base64 at all !!", base64.RawURLEncoding.EncodeToString([]byte("short")), flipState(ck.Value)} {
		bad := &http.Cookie{Name: oidcStateCookie, Value: name}
		target := s.base + oidcCallback + "?code=c0de&state=" + url.QueryEscape(stateParam(name))
		if got := s.where(s.callback(target, bad)); got != "/?sso_error=state_invalid" {
			t.Errorf("the cookie %.20q gave %q", name, got)
		}
	}

	// A state that has expired: the cookie is still authentic, so only
	// the timestamp inside it refuses the login.
	l := s.srv.oidc
	stale, err := l.seal(oidcState{Nonce: "n", Verifier: "v", Exp: time.Now().Add(-time.Second).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	target := s.base + oidcCallback + "?code=c0de&state=" + url.QueryEscape(stateParam(stale))
	if got := s.where(s.callback(target, &http.Cookie{Name: oidcStateCookie, Value: stale})); got != "/?sso_error=state_invalid" {
		t.Errorf("an expired state gave %q", got)
	}

	// A nonce the login did not ask for: the verifier is this login's,
	// so the code exchange succeeds and only the nonce refuses it.
	ck, back = s.start()
	s.idp.mu.Lock()
	s.idp.seen.Set("nonce", "somebody-elses-nonce")
	s.idp.mu.Unlock()
	if got := s.where(s.callback(back, ck)); got != "/?sso_error=nonce" {
		t.Errorf("a replayed nonce gave %q", got)
	}

	// No claim that names the user.
	s.idp.mu.Lock()
	s.idp.user = map[string]any{"sub": "", "groups": []string{"proxy-admins"}}
	s.idp.mu.Unlock()
	ck, back = s.start()
	if got := s.where(s.callback(back, ck)); got != "/?sso_error=no_user" {
		t.Errorf("a token with no user gave %q", got)
	}

	// A user name longer than the field allows.
	s.idp.mu.Lock()
	s.idp.user = map[string]any{"sub": "u", "email": strings.Repeat("n", 257) + "@example.com", "groups": []string{"proxy-admins"}}
	s.idp.mu.Unlock()
	ck, back = s.start()
	if got := s.where(s.callback(back, ck)); got != "/?sso_error=no_user" {
		t.Errorf("an oversize user name gave %q", got)
	}

	// An authorized party that is not us.
	s.idp.mu.Lock()
	s.idp.user = map[string]any{"sub": "u", "email": "a@b.c", "groups": []string{"proxy-admins"}, "azp": "another-client"}
	s.idp.mu.Unlock()
	ck, back = s.start()
	if got := s.where(s.callback(back, ck)); got != "/?sso_error=azp" {
		t.Errorf("a token issued to another party gave %q", got)
	}

	// None of it left a session behind.
	if st, body := s.c.do("GET", "/api/me", nil, false); st == 200 {
		t.Fatalf("a refused login still produced a session: %s", body)
	}
}

// flipState corrupts the middle of a sealed state, leaving its shape.
func flipState(s string) string {
	b := []byte(s)
	i := len(b) / 2
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	return string(b)
}

// pemCert wraps a certificate for a CA file.
func pemCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// TestSSOTokenEndpointFailures covers the half of the flow that runs
// server to server, where a broken or hostile provider must not become
// a session.
func TestSSOTokenEndpointFailures(t *testing.T) {
	s := startSSO(t, nil)
	l := s.srv.oidc

	for _, tc := range []struct {
		name string
		body string
		code int
	}{
		{"http error", `{"error":"invalid_grant"}`, 400},
		{"error in a 200", `{"error":"invalid_grant<script>"}`, 200},
		{"no id token", `{"access_token":"a","token_type":"Bearer"}`, 200},
		{"not json", "<html>login page</html>", 200},
		{"truncated json", `{"id_token":"a.b.`, 200},
		{"empty body", "", 200},
		{"oversize token", `{"id_token":"` + strings.Repeat("a", 1<<20) + `"}`, 200},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.code)
			_, _ = io.WriteString(w, tc.body)
		}))
		d := &oidcDiscovery{TokenEndpoint: srv.URL}
		tok, err := l.exchange(t.Context(), d, "c0de", "verifier", "https://gui/callback")
		srv.Close()
		if err == nil {
			t.Errorf("%s produced a token of %d bytes", tc.name, len(tok))
			continue
		}
		// The provider's body is not reflected into the operator's log:
		// a decoder complaining about one character is fine, a page of
		// somebody else's markup is not.
		if strings.Contains(err.Error(), "<html>") || strings.Contains(err.Error(), "<script>") || len(err.Error()) > 200 {
			t.Errorf("%s put provider text in the error: %.200v", tc.name, err)
		}
	}

	// A token endpoint that redirects is not followed: an open redirect
	// there would post the client secret to wherever it points.
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer target.Close()
	red := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer red.Close()
	if _, err := l.exchange(t.Context(), &oidcDiscovery{TokenEndpoint: red.URL}, "c", "v", "https://gui/cb"); err == nil {
		t.Error("the token endpoint's redirect was followed")
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("the credentials were posted to the redirect target %d times", n)
	}

	// An endpoint that never answers is bounded by the context, not by
	// the client's own ten seconds. A listener that accepts and then
	// says nothing is the honest shape of a provider that has hung.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = conn.Close() })
		}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := l.exchange(ctx, &oidcDiscovery{TokenEndpoint: "http://" + ln.Addr().String() + "/token"}, "c", "v", "https://gui/cb"); err == nil {
		t.Error("a hanging token endpoint produced a token")
	}
	if d := time.Since(started); d > 5*time.Second {
		t.Errorf("the exchange waited %v past its context", d)
	}

	// A URL that cannot be a request at all.
	if _, err := l.exchange(t.Context(), &oidcDiscovery{TokenEndpoint: "://not a url"}, "c", "v", "x"); err == nil {
		t.Error("a malformed token endpoint was posted to")
	}
}

// TestSSODiscoveryFailures covers the metadata document, which decides
// where the credentials go and which keys sign the identity.
func TestSSODiscoveryFailures(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "s")
	if err := os.WriteFile(secret, []byte("gui-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	var doc atomic.Value
	doc.Store("")
	var code atomic.Int32
	code.Store(200)
	idp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(int(code.Load()))
		_, _ = io.WriteString(w, doc.Load().(string))
	}))
	defer idp.Close()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pemCert(idp.Certificate().Raw), 0o600); err != nil {
		t.Fatal(err)
	}

	newLogin := func() *oidcLogin {
		t.Helper()
		l, err := newOIDCLogin(OIDCOptions{Issuer: idp.URL, ClientID: "gui", ClientSecretFile: secret, CAFile: ca,
			Operators: []string{"admins"}}, log)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(l.stop)
		return l
	}

	full := func(m map[string]string) string {
		b, _ := json.Marshal(m)
		return string(b)
	}
	for _, tc := range []struct {
		name string
		body string
		code int32
	}{
		{"http error", "", 500},
		{"not json", "<html>", 200},
		{"truncated", `{"issuer":"`, 200},
		{"no endpoints", `{"issuer":"x"}`, 200},
		{"no jwks", full(map[string]string{"issuer": idp.URL, "authorization_endpoint": idp.URL + "/a", "token_endpoint": idp.URL + "/t"}), 200},
		{"issuer mismatch", full(map[string]string{"issuer": "https://evil.example", "authorization_endpoint": idp.URL + "/a", "token_endpoint": idp.URL + "/t", "jwks_uri": idp.URL + "/j"}), 200},
	} {
		doc.Store(tc.body)
		code.Store(tc.code)
		l := newLogin()
		if _, err := l.discover(t.Context()); err == nil {
			t.Errorf("%s was accepted as provider metadata", tc.name)
		}
		// The retry is backed off, so a provider that is down cannot be
		// turned into a request amplifier by reloading the login page.
		if _, err := l.discover(t.Context()); err == nil || !strings.Contains(err.Error(), "unavailable") {
			t.Errorf("%s was retried at once: %v", tc.name, err)
		}
	}

	// A metadata document larger than the reader's ceiling.
	doc.Store(`{"issuer":"` + idp.URL + `","pad":"` + strings.Repeat("p", 300<<10) + `"}`)
	code.Store(200)
	if _, err := newLogin().discover(t.Context()); err == nil {
		t.Error("an oversize metadata document was accepted")
	}

	// A provider that is simply not there.
	down := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	downURL := down.URL
	downCA := filepath.Join(dir, "down.pem")
	if err := os.WriteFile(downCA, pemCert(down.Certificate().Raw), 0o600); err != nil {
		t.Fatal(err)
	}
	down.Close()
	l, err := newOIDCLogin(OIDCOptions{Issuer: downURL, ClientID: "gui", ClientSecretFile: secret, CAFile: downCA, Viewers: []string{"*"}}, log)
	if err != nil {
		t.Fatalf("a provider that is down must not stop the GUI from starting: %v", err)
	}
	t.Cleanup(l.stop)
	if _, err := l.discover(t.Context()); err == nil {
		t.Error("discovery against a closed provider succeeded")
	}
}

// TestSSOLoginPageWithoutAProvider covers the operator's view when the
// provider is unreachable: the login page says so instead of hanging or
// crashing, and the password login still works.
func TestSSOLoginPageWithoutAProvider(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "s")
	if err := os.WriteFile(secret, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	down := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, pemCert(down.Certificate().Raw), 0o600); err != nil {
		t.Fatal(err)
	}
	issuer := down.URL
	down.Close()

	fm := startFakeMgmt(t)
	_, c := newTestServer(t, Options{Listen: "127.0.0.1:0", Socket: fm.path, UsersFile: writeUsers(t, dir),
		OIDC: &OIDCOptions{Issuer: issuer, ClientID: "gui", ClientSecretFile: secret, CAFile: caPath, Viewers: []string{"*"}}})
	raw := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := raw.Get(c.base + oidcLoginPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 302 || resp.Header.Get("Location") != "/?sso_error=provider_unavailable" {
		t.Fatalf("login start with no provider: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	for _, ck := range resp.Cookies() {
		if ck.Name == oidcStateCookie && ck.Value != "" {
			t.Error("a state cookie was set although no login started")
		}
	}
	// The callback is equally unimpressed.
	req, _ := http.NewRequest("GET", c.base+oidcCallback+"?code=c&state="+url.QueryEscape(stateParam("x")), nil)
	req.AddCookie(&http.Cookie{Name: oidcStateCookie, Value: "x"})
	resp, err = raw.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.Header.Get("Location") != "/?sso_error=state_invalid" {
		t.Fatalf("callback with no provider: %q", resp.Header.Get("Location"))
	}
	// Passwords still work.
	if st := c.login("op", "operator-password-1"); st != 200 {
		t.Fatalf("password login with a broken provider: %d", st)
	}
	// And the login page advertises both methods.
	if st, body := c.do("GET", "/api/auth", nil, false); st != 200 || !strings.Contains(string(body), `"oidc":true`) || !strings.Contains(string(body), `"password":true`) {
		t.Fatalf("auth methods: %d %s", st, body)
	}
}

// TestSSOOptions covers the option checks and the redirect URI, which
// is what the provider is told to send the identity back to.
func TestSSOOptions(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "s")
	if err := os.WriteFile(secret, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	bad := []struct {
		name string
		o    OIDCOptions
	}{
		{"no issuer", OIDCOptions{ClientID: "c", ClientSecretFile: secret, Viewers: []string{"*"}}},
		{"unparsable issuer", OIDCOptions{Issuer: "https://%zz", ClientID: "c", ClientSecretFile: secret, Viewers: []string{"*"}}},
		{"plain http issuer", OIDCOptions{Issuer: "http://idp.example", ClientID: "c", ClientSecretFile: secret, Viewers: []string{"*"}}},
		{"no host", OIDCOptions{Issuer: "https://", ClientID: "c", ClientSecretFile: secret, Viewers: []string{"*"}}},
		{"no client id", OIDCOptions{Issuer: "https://idp.example", ClientSecretFile: secret, Viewers: []string{"*"}}},
		{"no secret file", OIDCOptions{Issuer: "https://idp.example", ClientID: "c", Viewers: []string{"*"}}},
		{"secret file missing", OIDCOptions{Issuer: "https://idp.example", ClientID: "c", ClientSecretFile: filepath.Join(dir, "nope"), Viewers: []string{"*"}}},
		{"no role mapping", OIDCOptions{Issuer: "https://idp.example", ClientID: "c", ClientSecretFile: secret}},
		{"ca file missing", OIDCOptions{Issuer: "https://idp.example", ClientID: "c", ClientSecretFile: secret, Viewers: []string{"*"}, CAFile: filepath.Join(dir, "nope.pem")}},
		{"ca file with no certificates", OIDCOptions{Issuer: "https://idp.example", ClientID: "c", ClientSecretFile: secret, Viewers: []string{"*"}, CAFile: secret}},
	}
	for _, tc := range bad {
		if l, err := newOIDCLogin(tc.o, log); err == nil {
			l.stop()
			t.Errorf("%s was accepted", tc.name)
		}
	}
	// Enabled is nil-safe: the GUI asks it before the options exist.
	var nilOpts *OIDCOptions
	if nilOpts.Enabled() || (&OIDCOptions{}).Enabled() {
		t.Error("an empty OIDC configuration reports itself enabled")
	}

	// The redirect URI follows the request unless an external URL is
	// configured, and a configured one wins over anything a client sends
	// in the Host header.
	s := &Server{oidc: &oidcLogin{o: OIDCOptions{}}}
	req := httptest.NewRequest("GET", "http://gui.example/api/oidc/login", nil)
	req.Host = "gui.example"
	if got := s.oidcRedirectURI(req); got != "http://gui.example"+oidcCallback {
		t.Errorf("derived redirect URI: %q", got)
	}
	s.tlsOn = true
	if got := s.oidcRedirectURI(req); got != "https://gui.example"+oidcCallback {
		t.Errorf("derived redirect URI over TLS: %q", got)
	}
	s.oidc.o.ExternalURL = "https://admin.example.com/"
	req.Host = "attacker.example"
	if got := s.oidcRedirectURI(req); got != "https://admin.example.com"+oidcCallback {
		t.Errorf("the Host header moved the redirect URI to %q", got)
	}
}

// TestSSORoleMapping covers the claim that decides what an authenticated
// user may do. A wrong answer here is a privilege escalation, so every
// shape the claim can arrive in is checked.
func TestSSORoleMapping(t *testing.T) {
	l := &oidcLogin{o: OIDCOptions{RoleClaim: "groups", Operators: []string{"admins"}, Viewers: []string{"readers"}}}
	cases := []struct {
		name   string
		claims map[string]any
		want   Role
		ok     bool
	}{
		{"a string claim", map[string]any{"groups": "admins"}, RoleOperator, true},
		{"a list claim", map[string]any{"groups": []any{"x", "readers"}}, RoleViewer, true},
		{"operator wins over viewer", map[string]any{"groups": []any{"readers", "admins"}}, RoleOperator, true},
		{"no claim", map[string]any{}, "", false},
		{"an unrelated value", map[string]any{"groups": "nobody"}, "", false},
		{"a space separated string is one value", map[string]any{"groups": "nobody admins"}, "", false},
		{"a comma separated string is one value", map[string]any{"groups": "nobody,admins"}, "", false},
		{"a prefix is not a match", map[string]any{"groups": "administrators"}, "", false},
		{"a different case is not a match", map[string]any{"groups": "Admins"}, "", false},
		{"a number claim", map[string]any{"groups": 42.0}, "", false},
		{"a boolean claim", map[string]any{"groups": true}, "", false},
		{"a null claim", map[string]any{"groups": nil}, "", false},
		{"a nested list", map[string]any{"groups": []any{[]any{"admins"}}}, "", false},
		{"non strings in the list are skipped", map[string]any{"groups": []any{1.0, nil, "admins"}}, RoleOperator, true},
		{"an empty list", map[string]any{"groups": []any{}}, "", false},
		{"an object claim", map[string]any{"groups": map[string]any{"admins": true}}, "", false},
	}
	for _, tc := range cases {
		got, ok := l.role(tc.claims)
		if got != tc.want || ok != tc.ok {
			t.Errorf("%s: got %q,%v want %q,%v", tc.name, got, ok, tc.want, tc.ok)
		}
	}
	// A wildcard viewer accepts anyone the provider authenticated, and
	// still never hands out the operator role.
	anyone := &oidcLogin{o: OIDCOptions{RoleClaim: "groups", Operators: []string{"admins"}, Viewers: []string{"*"}}}
	for _, claims := range []map[string]any{{}, {"groups": "whatever"}, {"groups": []any{"x"}}} {
		if got, ok := anyone.role(claims); got != RoleViewer || !ok {
			t.Errorf("wildcard viewer on %v gave %q,%v", claims, got, ok)
		}
	}
	if got, _ := anyone.role(map[string]any{"groups": "admins"}); got != RoleOperator {
		t.Error("the operator claim lost to the wildcard")
	}
	// A wildcard among the operators is a literal value, not a wildcard:
	// "everyone is an operator" is not something a typo should express.
	ops := &oidcLogin{o: OIDCOptions{RoleClaim: "groups", Operators: []string{"*"}}}
	if _, ok := ops.role(map[string]any{"groups": "anything"}); ok {
		t.Error("a star in operators granted the operator role to everyone")
	}
}

// TestSSOStateSeal covers the sealed cookie the flow's security rests
// on: it must not be readable, malleable, or interchangeable with
// another process's.
func TestSSOStateSeal(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	dir := t.TempDir()
	secret := filepath.Join(dir, "s")
	if err := os.WriteFile(secret, []byte("s3cret"), 0o600); err != nil {
		t.Fatal(err)
	}
	mk := func() *oidcLogin {
		l, err := newOIDCLogin(OIDCOptions{Issuer: "https://idp.invalid", ClientID: "c", ClientSecretFile: secret, Viewers: []string{"*"}}, log)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(l.stop)
		return l
	}
	a, b := mk(), mk()
	st := oidcState{Nonce: "nonce-value", Verifier: "verifier-value", Exp: time.Now().Add(time.Minute).Unix()}
	sealed, err := a.seal(st)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sealed, "nonce-value") || strings.Contains(sealed, "verifier-value") {
		t.Error("the sealed state carries its contents in the clear")
	}
	var got oidcState
	if err := a.open(sealed, &got); err != nil || got != st {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	// Another process cannot open it: the key is per process, so a
	// cookie does not survive a restart or move between nodes.
	if err := b.open(sealed, &got); err == nil {
		t.Error("another instance opened the sealed state")
	}
	// Every byte matters.
	raw, err := base64.RawURLEncoding.DecodeString(sealed)
	if err != nil {
		t.Fatal(err)
	}
	for i := range raw {
		bad := make([]byte, len(raw))
		copy(bad, raw)
		bad[i] ^= 0x01
		if err := a.open(base64.RawURLEncoding.EncodeToString(bad), &got); err == nil {
			t.Fatalf("a flip at byte %d of %d was accepted", i, len(raw))
		}
	}
	// Truncation, extension and rubbish.
	for _, s := range []string{"", "!!!!", sealed[:len(sealed)-1], sealed + "A", base64.RawURLEncoding.EncodeToString(raw[:a.aead.NonceSize()-1])} {
		if err := a.open(s, &got); err == nil {
			t.Errorf("%.16q was opened", s)
		}
	}
	// Something that seals but is not JSON on the way back.
	if _, err := a.seal(func() {}); err == nil {
		t.Error("an unmarshalable state was sealed")
	}
	// The state parameter is derived from the cookie and is not the
	// cookie: it must not leak the whole sealed value.
	p := stateParam(sealed)
	if p == sealed || !strings.Contains(p, ".") {
		t.Errorf("state parameter %q", p)
	}
	other, err := a.seal(st)
	if err != nil {
		t.Fatal(err)
	}
	if p2 := stateParam(sealed); p2 != p {
		t.Error("the state parameter is not stable")
	}
	if stateParam(other) == p {
		t.Error("two sealed states share a parameter")
	}
	if stateParam("a") == stateParam("b") {
		t.Error("the state parameter collides")
	}
	// A short sealed value must not panic the prefix.
	_ = stateParam("")
	_ = stateParam("ab")
}

// TestSanitizeParam covers the one function that puts provider text on
// the login page.
func TestSanitizeParam(t *testing.T) {
	cases := map[string]string{
		"":                             "",
		"access_denied":                "access_denied",
		"a b c":                        "abc",
		"<script>alert(1)</script>":    "scriptalert1script",
		"x\r\nLocation: http://evil":   "xLocationhttpevil",
		"../../etc/passwd":             "etcpasswd",
		"%3Cscript%3E":                 "3Cscript3E",
		"\x00\x01\x02":                 "",
		"é你好":                          "",
		strings.Repeat("a", 200):       strings.Repeat("a", 40),
		strings.Repeat("é", 200):       "",
		"a" + strings.Repeat("!", 100): "a",
	}
	for in, want := range cases {
		if got := sanitizeParam(in); got != want {
			t.Errorf("sanitizeParam(%.20q) = %q want %q", in, got, want)
		}
		if got := sanitizeParam(in); len(got) > 40 {
			t.Errorf("sanitizeParam(%.20q) returned %d bytes", in, len(got))
		}
	}
	// Whatever comes out is safe in a query string unchanged.
	for in := range cases {
		got := sanitizeParam(in)
		if url.QueryEscape(got) != got {
			t.Errorf("sanitizeParam(%.20q) = %q needs escaping", in, got)
		}
	}
}

// TestLogFollowStream covers the server-sent event stream behind the
// live log view, including the rotation it has to follow.
func TestLogFollowStream(t *testing.T) {
	fm := startFakeMgmt(t)
	dir := t.TempDir()
	logDir := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logDir, 0o750); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "xproxy.yaml")
	cfg := "version: 1\nserver:\n  listeners: [{name: http, address: \"127.0.0.1:0\"}]\n" +
		"logging:\n  directory: " + logDir + "\n  access: {enabled: true}\n" +
		"upstreams:\n  - {name: app, endpoints: [{address: 127.0.0.1:9}]}\n" +
		"routes:\n  - {name: all, paths: [\"/\"], upstream: app}\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o640); err != nil {
		t.Fatal(err)
	}
	logFile := filepath.Join(logDir, "access.log")
	if err := os.WriteFile(logFile, []byte("old line\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	_, c := newTestServer(t, Options{Listen: "127.0.0.1:0", Socket: fm.path, UsersFile: writeUsers(t, dir), ConfigFile: cfgPath})
	if st := c.login("op", "operator-password-1"); st != 200 {
		t.Fatal("login")
	}

	// A stream with no file behind it is refused before anything opens.
	req, _ := http.NewRequest("GET", c.base+"/api/logs/bogus/follow", nil)
	req.AddCookie(c.cookie)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("following an unknown stream gave %d", resp.StatusCode)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	req, _ = http.NewRequestWithContext(ctx, "GET", c.base+"/api/logs/access/follow", nil)
	req.AddCookie(c.cookie)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("follow: %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	lines := make(chan string, 64)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			select {
			case lines <- sc.Text():
			case <-ctx.Done():
				return
			}
		}
		close(lines)
	}()
	wait := func(want string) {
		t.Helper()
		deadline := time.After(20 * time.Second)
		for {
			select {
			case l, ok := <-lines:
				if !ok {
					t.Fatalf("the stream ended before %q", want)
				}
				if strings.Contains(l, want) {
					return
				}
			case <-deadline:
				t.Fatalf("%q never arrived", want)
			}
		}
	}
	wait(": follow")

	// A line appended after the stream opened arrives; the line that was
	// there before it does not, because following starts at the end.
	appendLine := func(path, s string) {
		t.Helper()
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o640)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(f, s+"\n"); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	appendLine(logFile, `{"msg":"first"}`)
	wait(`data: {"msg":"first"}`)

	// A line arriving in two writes is not split across two events.
	f, err := os.OpenFile(logFile, os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(f, `{"msg":"halves`); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if _, err := io.WriteString(f, "-together\"}\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	wait(`data: {"msg":"halves-together"}`)

	// Rotation: the file is renamed away and a new one takes its place.
	// The stream follows the name, so lines written to the new file
	// arrive without the client reconnecting.
	if err := os.Rename(logFile, logFile+".1"); err != nil {
		t.Fatal(err)
	}
	appendLine(logFile, `{"msg":"after-rotation"}`)
	wait(`data: {"msg":"after-rotation"}`)
	cancel()
}

// TestWriteFileAtomic covers the write behind the configuration editor,
// which must never leave a half written file and never follow a link.
func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "xproxy.yaml")
	if err := os.WriteFile(path, []byte("one\n"), 0o604); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(path, []byte("two\n"), []byte("one\n")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != "two\n" {
		t.Fatalf("content %q", b)
	}
	if b, _ := os.ReadFile(path + ".bak"); string(b) != "one\n" {
		t.Fatalf("backup %q", b)
	}
	// The mode of the target is preserved, oddities included, and the
	// backup does not become more permissive than it.
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o604 {
		t.Errorf("mode %v", st.Mode().Perm())
	}
	bst, err := os.Stat(path + ".bak")
	if err != nil {
		t.Fatal(err)
	}
	if bst.Mode().Perm()&^st.Mode().Perm() != 0 {
		t.Errorf("the backup is %v where the file is %v", bst.Mode().Perm(), st.Mode().Perm())
	}

	// A new file gets the default mode, and no backup is written when
	// there is no previous content.
	fresh := filepath.Join(dir, "fresh.yaml")
	if err := writeFileAtomic(fresh, []byte("x\n"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(fresh + ".bak"); !errors.Is(err, os.ErrNotExist) {
		t.Error("a backup was written for a file that had no previous content")
	}
	if st, _ := os.Stat(fresh); st.Mode().Perm() != 0o640 {
		t.Errorf("a new file got mode %v", st.Mode().Perm())
	}

	// The backup name is a symbolic link pointing somewhere else: the
	// write must refuse rather than follow it. Another member of the
	// group can plant such a link in the configuration directory.
	linked := filepath.Join(dir, "linked.yaml")
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(linked, []byte("a\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(victim, []byte("do not touch\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, linked+".bak"); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := writeFileAtomic(linked, []byte("b\n"), []byte("a\n")); err == nil {
		t.Error("the backup followed a symbolic link")
	}
	if b, _ := os.ReadFile(victim); string(b) != "do not touch\n" {
		t.Fatalf("the link target was overwritten: %q", b)
	}
	if b, _ := os.ReadFile(linked); string(b) != "a\n" {
		t.Errorf("the target changed although the write failed: %q", b)
	}

	// A directory that cannot be written to fails before anything is
	// renamed over the target. Running as root defeats the mode, so the
	// case is skipped there.
	if os.Geteuid() != 0 {
		ro := filepath.Join(dir, "ro")
		if err := os.Mkdir(ro, 0o500); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(ro, "c.yaml")
		if err := writeFileAtomic(target, []byte("x\n"), nil); err == nil {
			t.Error("a write into an unwritable directory succeeded")
		}
		if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
			t.Error("a failed write left a file behind")
		}
		// No temporary file is left lying around either.
		ents, err := os.ReadDir(ro)
		if err == nil && len(ents) != 0 {
			t.Errorf("the failed write left %d entries", len(ents))
		}
	}

	// A path whose directory does not exist at all.
	if err := writeFileAtomic(filepath.Join(dir, "nope", "c.yaml"), []byte("x"), nil); err == nil {
		t.Error("a write into a missing directory succeeded")
	}

	// The directory is left with no temporary files after a successful
	// run either.
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temporary file %q left behind", e.Name())
		}
	}
}

// TestUserFileEdges covers the user file, which is edited by hand as
// often as through the tool.
func TestUserFileEdges(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users")

	// A file that is not there is an empty set, not an error: the GUI
	// then refuses every login rather than failing to start.
	u, err := LoadUsers(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(u.List()) != 0 {
		t.Fatalf("a missing file yielded %d users", len(u.List()))
	}
	if _, ok := u.Lookup("op"); ok {
		t.Error("a user came out of a missing file")
	}

	hash, err := passwd.HashWithIterations("a-long-enough-password", 1000)
	if err != nil {
		t.Fatal(err)
	}
	// Names the file format cannot hold, and roles that do not exist.
	for _, name := range []string{"", strings.Repeat("n", 65), "a:b", "a b", "a\nb", "a/b", "../etc/passwd", "a\x00b", "é", "a#b"} {
		if err := u.Set(User{Name: name, Role: RoleViewer, Hash: hash}); err == nil {
			t.Errorf("the name %q was accepted", name)
		}
	}
	for _, role := range []string{"", "root", "Operator", "operator "} {
		if err := u.Set(User{Name: "x", Role: Role(role), Hash: hash}); err == nil {
			t.Errorf("the role %q was accepted", role)
		}
	}
	if err := u.Set(User{Name: "x", Role: RoleViewer}); err == nil {
		t.Error("a user with no hash was accepted")
	}
	// Names at the edge of what is allowed.
	for _, name := range []string{"a", strings.Repeat("n", 64), "a.b-c_d@example.com", "0"} {
		if err := u.Set(User{Name: name, Role: RoleViewer, Hash: hash}); err != nil {
			t.Errorf("the name %q was refused: %v", name, err)
		}
	}
	if len(u.List()) != 4 {
		t.Fatalf("%d users", len(u.List()))
	}
	// The file the tool wrote is readable by nobody else.
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		t.Errorf("the user file is mode %v", st.Mode().Perm())
	}
	// And it reads back to the same set.
	again, err := LoadUsers(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(again.List()) != 4 {
		t.Fatalf("re-read gave %d users", len(again.List()))
	}
	// List never carries the hashes.
	for _, x := range again.List() {
		if x.Hash != "" {
			t.Errorf("List leaked the hash of %q", x.Name)
		}
	}
	// Deleting a user who is not there says so; deleting one twice does
	// not remove somebody else.
	if err := u.Delete("nobody"); err == nil {
		t.Error("deleting an absent user succeeded")
	}
	if err := u.Delete("a"); err != nil {
		t.Fatal(err)
	}
	if err := u.Delete("a"); err == nil {
		t.Error("deleting the same user twice succeeded")
	}
	if len(u.List()) != 3 {
		t.Fatalf("%d users after the deletes", len(u.List()))
	}

	// A hand edited file is picked up, and a file replaced with rubbish
	// is reported rather than silently emptied.
	if err := os.WriteFile(path, []byte("# comment\n\nhand:viewer:"+hash+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond) // the file is re-stated at most once a second
	if _, ok := u.Lookup("hand"); !ok {
		t.Error("a hand edited user was not picked up")
	}
	if _, ok := u.Lookup("0"); ok {
		t.Error("a user removed by hand is still there")
	}
	for _, bad := range []string{"nocolons\n", "a:viewer\n", "a:nosuchrole:" + hash + "\n", ":viewer:" + hash + "\n", "a:viewer:\n", "a b:viewer:" + hash + "\n"} {
		p := filepath.Join(dir, "bad")
		if err := os.WriteFile(p, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadUsers(p); err == nil {
			t.Errorf("the line %q was accepted", strings.TrimSpace(bad))
		}
	}
	// A line longer than the scanner's buffer is an error, not a
	// truncated user name.
	long := filepath.Join(dir, "long")
	if err := os.WriteFile(long, []byte("a:viewer:"+strings.Repeat("x", 8192)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadUsers(long); err == nil {
		t.Error("an 8 KiB line was accepted")
	}
	// A directory where the file should be.
	if _, err := LoadUsers(dir); err == nil {
		t.Error("a directory was read as a user file")
	}
	// A write that cannot happen is reported to the caller.
	if os.Geteuid() != 0 {
		ro := filepath.Join(dir, "ro")
		if err := os.Mkdir(ro, 0o500); err != nil {
			t.Fatal(err)
		}
		u2, err := LoadUsers(filepath.Join(ro, "users"))
		if err != nil {
			t.Fatal(err)
		}
		if err := u2.Set(User{Name: "x", Role: RoleViewer, Hash: hash}); err == nil {
			t.Error("a user was written into an unwritable directory")
		}
	}
	_ = fmt.Sprint()
}
