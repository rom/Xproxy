package jwt

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/filter"
)

// authServer is a token endpoint that records what it was asked and
// answers what a case wants.
type authServer struct {
	srv      *httptest.Server
	calls    atomic.Int64
	lastForm atomic.Value // url.Values
	lastAuth atomic.Value // string
	// answer decides the response; nil answers a plain access token.
	answer func(form url.Values) (int, map[string]any)
}

func newAuthServer(t *testing.T) *authServer {
	t.Helper()
	a := &authServer{}
	a.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.calls.Add(1)
		_ = r.ParseForm()
		a.lastForm.Store(r.PostForm)
		a.lastAuth.Store(r.Header.Get("Authorization"))
		status, body := http.StatusOK, map[string]any{
			"access_token":      "downstream-token",
			"issued_token_type": typeAccessToken,
			"token_type":        "Bearer",
			"expires_in":        300,
		}
		if a.answer != nil {
			status, body = a.answer(r.PostForm)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(a.srv.Close)
	return a
}

// caFile writes the test server's certificate where the config can pin it.
func (a *authServer) caFile(t *testing.T, dir string) string {
	t.Helper()
	cert := a.srv.Certificate()
	pem := "-----BEGIN CERTIFICATE-----\n"
	enc := encodePEM(cert.Raw)
	pem += enc + "-----END CERTIFICATE-----\n"
	p := filepath.Join(dir, "as-ca.pem")
	if err := os.WriteFile(p, []byte(pem), 0o600); err != nil {
		t.Fatal(err)
	}
	// Prove the file is usable as a pool, so a failure here is this
	// helper's and not the feature's.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(pem)) {
		t.Fatal("the written CA file has no certificate in it")
	}
	return p
}

func encodePEM(der []byte) string {
	const line = 64
	b := b64std(der)
	var out strings.Builder
	for len(b) > line {
		out.WriteString(b[:line] + "\n")
		b = b[line:]
	}
	if b != "" {
		out.WriteString(b + "\n")
	}
	return out.String()
}

// exchangeProvider is a provider whose tokens are ES256 and which
// exchanges them at a.
func exchangeProvider(t *testing.T, a *authServer, over func(*config.TokenExchange)) (*Provider, signer) {
	t.Helper()
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, es, _ := keys(t)
	tx := &config.TokenExchange{
		URL: a.srv.URL, ClientID: "gateway", ClientSecretFile: secret,
		CAFile: a.caFile(t, dir), Audience: "orders-api",
		CacheTTL: config.Duration(time.Minute), Timeout: config.Duration(3 * time.Second),
	}
	if over != nil {
		over(tx)
	}
	p := provider(t, config.JWTProvider{
		Audiences: []string{"api"}, Algorithms: []string{"ES256"},
		JWKSFile: writeJWKS(t, dir, es), TokenExchange: tx,
	})
	return p, es
}

func sendToken(t *testing.T, p *Provider, token string) (filter.Verdict, *http.Request) {
	t.Helper()
	r, _ := http.NewRequest("GET", "http://api.test/orders", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	v := p.Filter(true).Begin(t.Context(), nil).Request(r)
	return v, r
}

// The backend must not receive a credential that works at the front door.
// That is the whole feature: the client's token is replaced by one issued
// for this backend, and the client's token is gone from the request.
func TestTheBackendGetsATokenThatOnlyWorksThere(t *testing.T) {
	a := newAuthServer(t)
	p, es := exchangeProvider(t, a, nil)
	token := es.sign(t, base(nil))
	v, r := sendToken(t, p, token)
	if v.Deny {
		t.Fatalf("denied: %+v", v)
	}
	if got := r.Header.Get("Authorization"); got != "Bearer downstream-token" {
		t.Fatalf("Authorization forwarded as %q, want the exchanged token", got)
	}
	if strings.Contains(r.Header.Get("Authorization"), token) {
		t.Fatal("the client's token reached the backend")
	}
	// What the authorization server was asked is as much the feature as
	// what came back: the grant type, the subject token and its type, and
	// the audience that makes the new token narrower than the old one.
	form := a.lastForm.Load().(url.Values)
	if form.Get("grant_type") != grantTokenExchange {
		t.Errorf("grant_type %q", form.Get("grant_type"))
	}
	if form.Get("subject_token") != token {
		t.Error("the client's token was not the subject token")
	}
	if form.Get("subject_token_type") != typeAccessToken {
		t.Errorf("subject_token_type %q", form.Get("subject_token_type"))
	}
	if form.Get("audience") != "orders-api" {
		t.Errorf("audience %q", form.Get("audience"))
	}
	// And the proxy authenticated itself, or the authorization server has
	// no idea who is asking.
	if auth, _ := a.lastAuth.Load().(string); !strings.HasPrefix(auth, "Basic ") {
		t.Errorf("the proxy did not authenticate: %q", auth)
	}
}

// One exchange per token, not per request: the authorization server is a
// shared service and the login flow is behind the same endpoint.
func TestTheExchangeIsCached(t *testing.T) {
	a := newAuthServer(t)
	p, es := exchangeProvider(t, a, nil)
	token := es.sign(t, base(nil))
	for i := 0; i < 5; i++ {
		if v, _ := sendToken(t, p, token); v.Deny {
			t.Fatalf("request %d denied: %+v", i, v)
		}
	}
	if n := a.calls.Load(); n != 1 {
		t.Fatalf("%d exchanges for five requests, want 1", n)
	}
	// A different token is a different exchange.
	if v, _ := sendToken(t, p, es.sign(t, base(map[string]any{"sub": "bob"}))); v.Deny {
		t.Fatalf("the second client was denied: %+v", v)
	}
	if n := a.calls.Load(); n != 2 {
		t.Fatalf("%d exchanges for two tokens, want 2", n)
	}
	// Cached with no TTL at all means every request asks.
	b := newAuthServer(t)
	q, es2 := exchangeProvider(t, b, func(tx *config.TokenExchange) { tx.CacheTTL = 0 })
	t2 := es2.sign(t, base(nil))
	for i := 0; i < 3; i++ {
		_, _ = sendToken(t, q, t2)
	}
	if n := b.calls.Load(); n != 3 {
		t.Fatalf("%d exchanges with cache_ttl 0, want 3", n)
	}
}

// A refusal from the authorization server is an answer about this client
// and this backend, so it is the client's 403 rather than the proxy's 503.
func TestARefusedExchangeIsTheClientsProblem(t *testing.T) {
	a := newAuthServer(t)
	a.answer = func(url.Values) (int, map[string]any) {
		return http.StatusBadRequest, map[string]any{"error": "invalid_target"}
	}
	p, es := exchangeProvider(t, a, nil)
	// One token, signed once: an ECDSA signature is randomised, so
	// re-signing the same claims would be a different token and a
	// different cache entry.
	token := es.sign(t, base(nil))
	v, r := sendToken(t, p, token)
	if !v.Deny || v.Status != http.StatusForbidden || v.Detail != "exchange_refused" {
		t.Fatalf("got %+v, want 403 exchange_refused", v)
	}
	if r.Header.Get("Authorization") != "" {
		t.Error("a token was forwarded after a refused exchange")
	}
	// The refusal is cached: asking again per request would turn one
	// client's misconfiguration into load the login flow shares.
	for i := 0; i < 4; i++ {
		_, _ = sendToken(t, p, token)
	}
	if n := a.calls.Load(); n != 1 {
		t.Fatalf("%d calls, want the refusal cached after one", n)
	}
}

// An endpoint that cannot be asked is the proxy's problem, and is never
// cached: the next request should try again rather than inherit an outage
// that may be over.
func TestAnUnreachableEndpointIsA503AndIsNotCached(t *testing.T) {
	a := newAuthServer(t)
	p, es := exchangeProvider(t, a, nil)
	a.srv.Close() // the endpoint goes away
	token := es.sign(t, base(nil))
	v, _ := sendToken(t, p, token)
	if !v.Deny || v.Status != http.StatusServiceUnavailable || v.Detail != "exchange_unavailable" {
		t.Fatalf("got %+v, want 503 exchange_unavailable", v)
	}
	if v.Headers["Retry-After"] == "" {
		t.Error("no Retry-After on a 503")
	}
	_, _, _, _, cached := p.ExchangeStats()
	if cached != 0 {
		t.Fatalf("%d cached entries after an outage, want none", cached)
	}
}

// The answer is checked rather than assumed. A server that hands back a
// refresh token would otherwise have it forwarded as an access token,
// which is a long-lived credential given to a backend.
func TestTheAnswerIsCheckedBeforeItIsForwarded(t *testing.T) {
	for _, tc := range []struct {
		name string
		body map[string]any
	}{
		{"no access_token", map[string]any{"issued_token_type": typeAccessToken}},
		{"an empty access_token", map[string]any{"access_token": "", "issued_token_type": typeAccessToken}},
		{"a refresh token", map[string]any{"access_token": "r", "issued_token_type": "urn:ietf:params:oauth:token-type:refresh_token"}},
		{"an id token", map[string]any{"access_token": "i", "issued_token_type": "urn:ietf:params:oauth:token-type:id_token"}},
		{"not json", nil},
	} {
		a := newAuthServer(t)
		a.answer = func(url.Values) (int, map[string]any) { return http.StatusOK, tc.body }
		p, es := exchangeProvider(t, a, nil)
		v, r := sendToken(t, p, es.sign(t, base(nil)))
		if !v.Deny || v.Status != http.StatusServiceUnavailable {
			t.Errorf("%s: got %+v, want a 503", tc.name, v)
		}
		if r.Header.Get("Authorization") != "" {
			t.Errorf("%s: a token was forwarded", tc.name)
		}
	}
	// And an issued_token_type of jwt is accepted, since that is the
	// other type RFC 8693 names for an access token.
	a := newAuthServer(t)
	a.answer = func(url.Values) (int, map[string]any) {
		return http.StatusOK, map[string]any{"access_token": "jwt-token", "issued_token_type": typeJWT, "expires_in": 60}
	}
	p, es := exchangeProvider(t, a, nil)
	if v, r := sendToken(t, p, es.sign(t, base(nil))); v.Deny || r.Header.Get("Authorization") != "Bearer jwt-token" {
		t.Fatalf("a jwt token type was refused: %+v %q", v, r.Header.Get("Authorization"))
	}
}

// A cached token must not outlive what was issued, or a backend receives
// something already dead.
func TestTheCacheDoesNotOutliveTheNewToken(t *testing.T) {
	a := newAuthServer(t)
	a.answer = func(url.Values) (int, map[string]any) {
		return http.StatusOK, map[string]any{"access_token": "short", "issued_token_type": typeAccessToken, "expires_in": 1}
	}
	p, es := exchangeProvider(t, a, func(tx *config.TokenExchange) {
		tx.CacheTTL = config.Duration(time.Hour) // far longer than the token lives
	})
	token := es.sign(t, base(nil))
	if v, _ := sendToken(t, p, token); v.Deny {
		t.Fatalf("denied: %+v", v)
	}
	if n := a.calls.Load(); n != 1 {
		t.Fatalf("%d calls", n)
	}
	time.Sleep(1200 * time.Millisecond)
	if v, _ := sendToken(t, p, token); v.Deny {
		t.Fatalf("denied after the token expired: %+v", v)
	}
	if n := a.calls.Load(); n != 2 {
		t.Fatalf("%d calls, want a second exchange once the first token expired", n)
	}
}

// required: false lets the request through, and it goes through with no
// token at all -- putting the client's back would forward the credential
// this exists to withhold.
func TestRequiredFalseSendsNothingRatherThanTheClientsToken(t *testing.T) {
	a := newAuthServer(t)
	a.answer = func(url.Values) (int, map[string]any) {
		return http.StatusBadRequest, map[string]any{"error": "invalid_target"}
	}
	no := false
	p, es := exchangeProvider(t, a, func(tx *config.TokenExchange) { tx.Required = &no })
	token := es.sign(t, base(nil))
	v, r := sendToken(t, p, token)
	if v.Deny {
		t.Fatalf("required: false denied the request: %+v", v)
	}
	if got := r.Header.Get("Authorization"); got != "" {
		t.Fatalf("Authorization forwarded as %q, want nothing", got)
	}
}

// The scopes and the resource reach the authorization server as RFC 8693
// and RFC 8707 spell them.
func TestWhatIsAskedForReachesTheServer(t *testing.T) {
	a := newAuthServer(t)
	p, es := exchangeProvider(t, a, func(tx *config.TokenExchange) {
		tx.Audience = ""
		tx.Resource = "https://orders.internal/api"
		tx.Scopes = []string{"orders:read", "orders:write"}
		tx.RequestedTokenType = typeJWT
	})
	if v, _ := sendToken(t, p, es.sign(t, base(nil))); v.Deny {
		t.Fatalf("denied: %+v", v)
	}
	form := a.lastForm.Load().(url.Values)
	if form.Get("resource") != "https://orders.internal/api" {
		t.Errorf("resource %q", form.Get("resource"))
	}
	if form.Get("scope") != "orders:read orders:write" {
		t.Errorf("scope %q, want a space separated list", form.Get("scope"))
	}
	if form.Get("requested_token_type") != typeJWT {
		t.Errorf("requested_token_type %q", form.Get("requested_token_type"))
	}
	if form.Get("audience") != "" {
		t.Errorf("an audience was sent that was not configured: %q", form.Get("audience"))
	}
}

// A named header carries the token alone: a backend reading
// X-Service-Token does not want "Bearer " in front of it.
func TestANamedHeaderCarriesTheTokenAlone(t *testing.T) {
	a := newAuthServer(t)
	p, es := exchangeProvider(t, a, func(tx *config.TokenExchange) { tx.Header = "X-Service-Token" })
	v, r := sendToken(t, p, es.sign(t, base(nil)))
	if v.Deny {
		t.Fatalf("denied: %+v", v)
	}
	if got := r.Header.Get("X-Service-Token"); got != "downstream-token" {
		t.Fatalf("X-Service-Token %q, want the bare token", got)
	}
	if r.Header.Get("Authorization") != "" {
		t.Error("Authorization was set as well as the named header")
	}
}

// An unverified token never reaches the authorization server: asking it
// about whatever a client posted spends its capacity on this proxy's
// behalf, and caching the answer by digest would let one client's garbage
// occupy the table.
func TestAnInvalidTokenIsNeverExchanged(t *testing.T) {
	a := newAuthServer(t)
	p, _ := exchangeProvider(t, a, nil)
	for _, token := range []string{"not-a-token", "a.b.c", strings.Repeat("x", 200)} {
		if v, _ := sendToken(t, p, token); !v.Deny {
			t.Errorf("%q was accepted", token)
		}
	}
	if n := a.calls.Load(); n != 0 {
		t.Fatalf("%d exchanges for tokens that never verified", n)
	}
	_, _, _, _, cached := p.ExchangeStats()
	if cached != 0 {
		t.Fatalf("%d cached entries, want none", cached)
	}
}

// b64std is standard base64, for writing a PEM.
func b64std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
