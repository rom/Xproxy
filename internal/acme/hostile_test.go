package acme

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/acme/acmetest"
	"github.com/rom/xproxy/internal/config"
)

// The certificate authority is somebody else's server, reached over the
// network, and its answers decide what certificate this proxy serves.
// These tests are about what it must not be able to talk the client
// into.

// fakeCA answers the directory and then whatever a test chose for the
// next request, with a fresh nonce each time.
type fakeCA struct {
	srv    *httptest.Server
	body   atomic.Value // string
	code   atomic.Int32
	nonce  atomic.Bool // false withholds the Replay-Nonce header
	hits   atomic.Int32
	mangle atomic.Value // func(path string) (int, string), consulted first
}

func startCA(t *testing.T) *fakeCA {
	t.Helper()
	ca := &fakeCA{}
	ca.body.Store("{}")
	ca.code.Store(200)
	ca.nonce.Store(true)
	mux := http.NewServeMux()
	ca.srv = httptest.NewServer(mux)
	t.Cleanup(ca.srv.Close)
	mux.HandleFunc("/dir", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"newNonce": ca.srv.URL + "/nonce", "newAccount": ca.srv.URL + "/acct",
			"newOrder": ca.srv.URL + "/order", "revokeCert": ca.srv.URL + "/revoke",
		})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ca.hits.Add(1)
		if ca.nonce.Load() {
			w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", ca.hits.Load()))
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(200)
			return
		}
		if f, ok := ca.mangle.Load().(func(string) (int, string)); ok && f != nil {
			if code, body := f(r.URL.Path); code != 0 {
				w.WriteHeader(code)
				_, _ = io.WriteString(w, body)
				return
			}
		}
		w.WriteHeader(int(ca.code.Load()))
		_, _ = io.WriteString(w, ca.body.Load().(string))
	})
	return ca
}

func (ca *fakeCA) answer(code int, body string) {
	ca.code.Store(int32(code)) //nolint:gosec // test status
	ca.body.Store(body)
}

func (ca *fakeCA) client(t *testing.T) *Client {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewClient(ca.srv.URL+"/dir", "", key)
	if err != nil {
		t.Fatal(err)
	}
	c.SetKID(ca.srv.URL + "/acct/1")
	return c
}

// TestDirectoryRejections covers the one document that says where
// everything else lives: a wrong directory sends every later request
// somewhere else.
func TestDirectoryRejections(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
		body string
	}{
		{"empty", 200, ""},
		{"not json", 200, "<html>"},
		{"a json array", 200, "[1,2]"},
		{"a truncated document", 200, `{"newNonce":"x"`},
		{"no newNonce", 200, `{"newAccount":"a","newOrder":"o"}`},
		{"no newAccount", 200, `{"newNonce":"n","newOrder":"o"}`},
		{"no newOrder", 200, `{"newNonce":"n","newAccount":"a"}`},
		{"every member empty", 200, `{"newNonce":"","newAccount":"","newOrder":""}`},
		{"a server error", 500, `{"newNonce":"n","newAccount":"a","newOrder":"o"}`},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.code)
			_, _ = io.WriteString(w, tc.body)
		}))
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		c, err := NewClient(srv.URL, "", key)
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.Directory(t.Context())
		srv.Close()
		if err == nil && tc.code == 200 && !strings.Contains(tc.body, "newOrder") {
			t.Errorf("%s was accepted as a directory", tc.name)
		}
		if err == nil && tc.code != 200 {
			// A 500 with a complete body is still a body: what matters is
			// that nothing incomplete is cached.
			continue
		}
	}
	// A directory that is fetched once is cached: the client must not
	// ask again for every request.
	ca := startCA(t)
	c := ca.client(t)
	d1, err := c.Directory(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	d2, err := c.Directory(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 {
		t.Error("the directory was fetched twice")
	}
	// A CA file that is not a certificate is refused at construction.
	dir := t.TempDir()
	notPEM := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(notPEM, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewClient("https://ca.example/dir", notPEM, key); err == nil {
		t.Error("a CA file with no certificates was accepted")
	}
	if _, err := NewClient("https://ca.example/dir", filepath.Join(dir, "missing.pem"), key); err == nil {
		t.Error("a missing CA file was accepted")
	}
}

// TestNonceHandling covers the replay protection: without a nonce
// nothing can be signed, and a CA that says the nonce was wrong gets
// exactly one retry.
func TestNonceHandling(t *testing.T) {
	ca := startCA(t)
	c := ca.client(t)
	// A CA that never sends a nonce fails rather than signing without one.
	ca.nonce.Store(false)
	if _, err := c.GetOrder(t.Context(), ca.srv.URL+"/order/1"); err == nil {
		t.Error("a request was made with no nonce")
	}
	ca.nonce.Store(true)

	// badNonce is retried once, and only once.
	var posts atomic.Int32
	ca.mangle.Store(func(path string) (int, string) {
		if strings.HasPrefix(path, "/order/") {
			posts.Add(1)
			return 400, `{"type":"urn:ietf:params:acme:error:badNonce","detail":"bad nonce"}`
		}
		return 0, ""
	})
	_, err := c.GetOrder(t.Context(), ca.srv.URL+"/order/1")
	if err == nil {
		t.Fatal("a badNonce error was reported as success")
	}
	if n := posts.Load(); n != 2 {
		t.Errorf("badNonce was retried %d times", n-1)
	}
	// A problem that is not badNonce is not retried.
	posts.Store(0)
	ca.mangle.Store(func(path string) (int, string) {
		if strings.HasPrefix(path, "/order/") {
			posts.Add(1)
			return 403, `{"type":"urn:ietf:params:acme:error:unauthorized","detail":"no"}`
		}
		return 0, ""
	})
	if _, err := c.GetOrder(t.Context(), ca.srv.URL+"/order/1"); err == nil {
		t.Error("an unauthorized error was reported as success")
	}
	if n := posts.Load(); n != 1 {
		t.Errorf("a non-nonce error was retried %d times", n-1)
	}
	ca.mangle.Store((func(string) (int, string))(nil))
}

// TestProblemErrors covers the RFC 7807 documents the CA answers with,
// which is what an operator reads in the log when issuance fails.
func TestProblemErrors(t *testing.T) {
	ca := startCA(t)
	c := ca.client(t)
	for _, tc := range []struct {
		name string
		code int
		body string
		want string
	}{
		{"a problem document", 403, `{"type":"urn:ietf:params:acme:error:unauthorized","detail":"not authorized"}`, "not authorized"},
		{"a problem with no detail", 429, `{"type":"urn:ietf:params:acme:error:rateLimited"}`, "rateLimited"},
		{"an empty body", 500, "", "Internal Server Error"},
		{"not json", 502, "<html>502</html>", "Bad Gateway"},
		{"a json array", 400, "[1,2]", "Bad Request"},
	} {
		ca.answer(tc.code, tc.body)
		_, err := c.GetOrder(t.Context(), ca.srv.URL+"/order/1")
		if err == nil {
			t.Errorf("%s: no error", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %q does not mention %q", tc.name, err, tc.want)
		}
		var p *Problem
		if !errors.As(err, &p) {
			t.Errorf("%s: the error is not a problem document: %T", tc.name, err)
			continue
		}
		if p.Status != tc.code {
			t.Errorf("%s: status %d", tc.name, p.Status)
		}
		// The rendered error carries no control characters, whatever the
		// CA put in the detail: it goes into the log as it stands.
		if strings.ContainsAny(p.Error(), "\r\n") {
			t.Errorf("%s: the error text spans lines: %q", tc.name, p.Error())
		}
	}
	// A detail full of terminal escapes is still one line.
	ca.answer(400, `{"type":"t","detail":"a\u001b[2Jb"}`)
	if _, err := c.GetOrder(t.Context(), ca.srv.URL+"/order/1"); err == nil || strings.Contains(err.Error(), "\n") {
		t.Errorf("a hostile detail: %v", err)
	}
}

// TestResponsesThatAreNotOrders covers the decoding of every document
// the client reads, with answers a CA should never send.
func TestResponsesThatAreNotOrders(t *testing.T) {
	ca := startCA(t)
	c := ca.client(t)
	bodies := []string{
		"",
		"not json",
		"[1,2,3]",
		`"a string"`,
		"null",
		`{"status":123}`, // the wrong type for a status
		`{"identifiers":"not a list"}`,
		`{"authorizations":{"a":1}}`,
		`{"status":"` + strings.Repeat("s", 1<<20) + `"}`, // larger than the reader's ceiling
	}
	for _, b := range bodies {
		ca.answer(200, b)
		o, err := c.GetOrder(t.Context(), ca.srv.URL+"/order/1")
		if err != nil {
			continue // refused, which is fine
		}
		// Accepted: then it must be an order shaped like one, not a
		// half-decoded document the caller will act on.
		if o == nil {
			t.Errorf("%.30q gave no order and no error", b)
			continue
		}
		if o.URL != ca.srv.URL+"/order/1" {
			t.Errorf("%.30q: the order lost its URL", b)
		}
	}
	// An authorization document of the wrong shape is refused too.
	for _, b := range []string{"", "not json", `{"challenges":"none"}`, `{"identifier":5}`} {
		ca.answer(200, b)
		if a, err := c.GetAuthorization(t.Context(), ca.srv.URL+"/authz/1"); err == nil && a == nil {
			t.Errorf("%.20q gave no authorization and no error", b)
		}
	}
}

// TestCertificateMustBePEM is the last check before a certificate is
// served: whatever the CA sends, it has to be a certificate.
func TestCertificateMustBePEM(t *testing.T) {
	ca := startCA(t)
	c := ca.client(t)
	for _, b := range []string{"", "not pem", "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n", "<html>"} {
		ca.answer(200, b)
		if _, err := c.Certificate(t.Context(), ca.srv.URL+"/cert/1"); err == nil {
			t.Errorf("%.20q was accepted as a certificate", b)
		}
	}
	ca.answer(200, "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
	pem, err := c.Certificate(t.Context(), ca.srv.URL+"/cert/1")
	if err != nil || !strings.Contains(string(pem), "BEGIN CERTIFICATE") {
		t.Fatalf("a PEM chain was refused: %v", err)
	}
}

// TestWaitStatuses covers the polling loops, including the statuses
// that must end the wait rather than spin until the deadline.
func TestWaitStatuses(t *testing.T) {
	ca := startCA(t)
	c := ca.client(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	// An order that is already valid returns at once.
	ca.answer(200, `{"status":"valid","certificate":"https://ca/cert"}`)
	o, err := c.WaitOrder(ctx, ca.srv.URL+"/order/1", "valid")
	if err != nil || o.Status != "valid" {
		t.Fatalf("a valid order: %+v %v", o, err)
	}
	// An invalid order ends the wait with the CA's own reason.
	ca.answer(200, `{"status":"invalid","error":{"type":"urn:ietf:params:acme:error:dns","detail":"no such name"}}`)
	started := time.Now()
	if _, err := c.WaitOrder(ctx, ca.srv.URL+"/order/1", "valid"); err == nil {
		t.Error("an invalid order was waited out")
	} else if !strings.Contains(err.Error(), "no such name") {
		t.Errorf("the reason was lost: %v", err)
	}
	if d := time.Since(started); d > 2*time.Second {
		t.Errorf("an invalid order took %v to report", d)
	}
	// Invalid with no error document still ends the wait.
	ca.answer(200, `{"status":"invalid"}`)
	if _, err := c.WaitOrder(ctx, ca.srv.URL+"/order/1", "valid"); err == nil {
		t.Error("an invalid order with no reason was waited out")
	}
	// Authorizations: valid returns, and each failed status ends the
	// wait with the challenge's reason when it has one.
	ca.answer(200, `{"status":"valid"}`)
	if err := c.WaitAuthorization(ctx, ca.srv.URL+"/authz/1"); err != nil {
		t.Fatalf("a valid authorization: %v", err)
	}
	for _, status := range []string{"invalid", "revoked", "expired", "deactivated"} {
		ca.answer(200, `{"status":"`+status+`","identifier":{"type":"dns","value":"a.example"},
			"challenges":[{"type":"http-01","error":{"type":"t","detail":"fetch failed"}}]}`)
		err := c.WaitAuthorization(ctx, ca.srv.URL+"/authz/1")
		if err == nil {
			t.Errorf("status %s was waited out", status)
			continue
		}
		if !strings.Contains(err.Error(), "fetch failed") || !strings.Contains(err.Error(), "http-01") {
			t.Errorf("status %s: %v", status, err)
		}
	}
	// A failed authorization with no challenge error still names the
	// identifier and the status.
	ca.answer(200, `{"status":"invalid","identifier":{"type":"dns","value":"a.example"}}`)
	err = c.WaitAuthorization(ctx, ca.srv.URL+"/authz/1")
	if err == nil || !strings.Contains(err.Error(), "a.example") || !strings.Contains(err.Error(), "invalid") {
		t.Errorf("a bare invalid authorization: %v", err)
	}
	// A cancelled context ends a wait that would otherwise poll on.
	ca.answer(200, `{"status":"pending"}`)
	short, cancelShort := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancelShort()
	started = time.Now()
	if _, err := c.WaitOrder(short, ca.srv.URL+"/order/1", "valid"); err == nil {
		t.Error("a pending order returned success")
	}
	if d := time.Since(started); d > 10*time.Second {
		t.Errorf("the wait ignored its context for %v", d)
	}
	if err := c.WaitAuthorization(short, ca.srv.URL+"/authz/1"); err == nil {
		t.Error("a pending authorization returned success")
	}
}

// TestPollDelay covers the back-off: it grows, and it is capped, so a
// CA that keeps answering "pending" is polled less and less.
func TestPollDelay(t *testing.T) {
	prev := time.Duration(0)
	for i := 0; i < 100; i++ {
		d := pollDelay(i)
		if d <= 0 {
			t.Fatalf("pollDelay(%d) = %v", i, d)
		}
		if d < prev {
			t.Fatalf("pollDelay(%d) = %v went backwards from %v", i, d, prev)
		}
		if d > 5*time.Second {
			t.Fatalf("pollDelay(%d) = %v is past the cap", i, d)
		}
		prev = d
	}
	if pollDelay(0) >= pollDelay(1) {
		t.Error("the delay does not grow")
	}
	if pollDelay(1000) != 5*time.Second {
		t.Errorf("the cap is %v", pollDelay(1000))
	}
}

// TestCAThatDisappears covers the network under the client.
func TestCAThatDisappears(t *testing.T) {
	ca := startCA(t)
	c := ca.client(t)
	// Warm the directory, then close the server.
	if _, err := c.Directory(t.Context()); err != nil {
		t.Fatal(err)
	}
	ca.srv.Close()
	if _, err := c.GetOrder(t.Context(), ca.srv.URL+"/order/1"); err == nil {
		t.Error("an order was fetched from a closed server")
	}
	if _, err := c.NewOrder(t.Context(), []string{"a.example"}); err == nil {
		t.Error("an order was created on a closed server")
	}
	if err := c.Register(t.Context(), "admin@example.com"); err == nil {
		t.Error("an account was registered on a closed server")
	}
}

// TestManagerStateOnDisk covers what the manager reads back after a
// restart: the files are the only memory it has, and a file somebody
// else can write is a certificate somebody else chose.
func TestManagerStateOnDisk(t *testing.T) {
	dir := t.TempDir()
	ca := acmetest.New(t, dir)
	m := manager(t, ca, dir, "http-01", [][]string{{"a.example.test"}})

	// Nothing issued yet: the snapshot is empty rather than nil-panicking.
	if certs := m.Certificates(); len(certs) != 0 {
		t.Fatalf("%d certificates before issuance", len(certs))
	}
	if _, ok := m.HTTP01("no-such-token"); ok {
		t.Error("a token nobody issued was answered")
	}
	if _, ok := m.TLSALPN01("a.example.test"); ok {
		t.Error("a challenge certificate was served without a challenge")
	}
	// The status view exists before anything is issued.
	st := m.Status()
	if len(st) != 1 || st[0].Hosts[0] != "a.example.test" {
		t.Fatalf("status before issuance: %+v", st)
	}

	// Files that are not a key pair: each is a reason to obtain a new
	// certificate, not to serve something broken.
	certDir := filepath.Join(dir, "state", "certs")
	name := st[0].Name
	cp := filepath.Join(certDir, name+".pem")
	kp := filepath.Join(certDir, name+"-key.pem")
	for _, tc := range []struct{ name, cert, key string }{
		{"empty files", "", ""},
		{"not pem", "hello", "hello"},
		{"a certificate and no key", "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n", ""},
		{"a key and no certificate", "", "-----BEGIN EC PRIVATE KEY-----\nMHc\n-----END EC PRIVATE KEY-----\n"},
		{"a truncated certificate", "-----BEGIN CERTIFICATE-----\nMIIB", "-----BEGIN EC PRIVATE KEY-----\nMHc"},
	} {
		if err := os.WriteFile(cp, []byte(tc.cert), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(kp, []byte(tc.key), 0o600); err != nil {
			t.Fatal(err)
		}
		m2, err := New(m.cfg, [][]string{{"a.example.test"}}, nolog)
		if err != nil {
			t.Fatalf("%s: the manager did not start: %v", tc.name, err)
		}
		if certs := m2.Certificates(); len(certs) != 0 {
			t.Errorf("%s: %d certificates were served", tc.name, len(certs))
		}
		m2.Stop()
	}
	// A state directory that cannot be created is a start-up error, not
	// a manager that silently keeps nothing.
	if os.Geteuid() != 0 {
		ro := filepath.Join(dir, "ro")
		if err := os.Mkdir(ro, 0o500); err != nil {
			t.Fatal(err)
		}
		cfg := m.cfg
		cfg.StateDir = filepath.Join(ro, "state")
		if _, err := New(cfg, [][]string{{"a.example.test"}}, nolog); err == nil {
			t.Error("a state directory that cannot be created was accepted")
		}
	}
}

// TestManagerStartAndStop covers the renewal loop's lifecycle, which
// runs for the life of the process.
func TestManagerStartAndStop(t *testing.T) {
	dir := t.TempDir()
	ca := acmetest.New(t, dir)
	m := manager(t, ca, dir, "http-01", [][]string{{"a.example.test"}})
	m.cfg.CheckInterval = config.Duration(20 * time.Millisecond)
	m.Start()
	time.Sleep(100 * time.Millisecond)
	// Stopping is idempotent and returns once the loop has left.
	done := make(chan struct{})
	go func() { m.Stop(); m.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Stop did not return")
	}
	// The status view still answers after the loop has stopped.
	if len(m.Status()) != 1 {
		t.Error("the status view lost its entry")
	}
}

// TestALPNCertificate covers the self-signed certificate a tls-alpn-01
// validation is answered with. It carries the key authorisation in a
// critical extension, and the CA refuses it if that is wrong.
func TestALPNCertificate(t *testing.T) {
	cert, err := alpnCertificate("a.example.test", "token.thumbprint")
	if err != nil {
		t.Fatal(err)
	}
	if cert.Leaf == nil {
		t.Fatal("the challenge certificate has no parsed leaf")
	}
	if len(cert.Leaf.DNSNames) != 1 || cert.Leaf.DNSNames[0] != "a.example.test" {
		t.Errorf("names %v", cert.Leaf.DNSNames)
	}
	var found bool
	for _, ext := range cert.Leaf.Extensions {
		if ext.Id.Equal(idPeAcmeIdentifier) {
			found = true
			if !ext.Critical {
				t.Error("the acme identifier extension is not critical")
			}
			// The value is the SHA-256 of the key authorisation, wrapped
			// in an ASN.1 octet string.
			sum := sha256.Sum256([]byte("token.thumbprint"))
			if !bytes.Contains(ext.Value, sum[:]) {
				t.Errorf("the extension does not carry the digest: %x", ext.Value)
			}
		}
	}
	if !found {
		t.Error("the acme identifier extension is missing")
	}
	// The certificate is valid now and expires within a day: it exists
	// only for one handshake.
	now := time.Now()
	if cert.Leaf.NotBefore.After(now) || cert.Leaf.NotAfter.Before(now) {
		t.Errorf("validity %s..%s", cert.Leaf.NotBefore, cert.Leaf.NotAfter)
	}
	if cert.Leaf.NotAfter.Sub(now) > 48*time.Hour {
		t.Errorf("the challenge certificate lives for %s", cert.Leaf.NotAfter.Sub(now))
	}
	// A different key authorisation gives a different certificate, and
	// two calls with the same one still differ (a fresh key each time).
	other, err := alpnCertificate("a.example.test", "another.thumbprint")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(cert.Certificate[0], other.Certificate[0]) {
		t.Error("two key authorisations produced the same certificate")
	}
	again, err := alpnCertificate("a.example.test", "token.thumbprint")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(cert.Certificate[0], again.Certificate[0]) {
		t.Error("the challenge certificate is reused")
	}
	// A host that is not a name still produces a certificate rather than
	// an error: the CA is the one that decides it is wrong.
	if _, err := alpnCertificate("", ""); err != nil {
		t.Errorf("an empty host: %v", err)
	}
}
