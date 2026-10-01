package forward

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/passwd"
	"github.com/rom/xproxy/internal/proxytest"
	"github.com/rom/xproxy/internal/testutil"
)

// The egress policy against real traffic through a real proxy.
//
// The unit tests decide what each selector means; this one is here because the
// thing that goes wrong with a policy like this is never the matching. It is the
// wiring: a decision taken at the wrong point, a response relayed before it was
// decided about, a refusal that reaches the client as a 200.
func TestTheEgressPolicyRefusesRealTraffic(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	origin := tlsOrigin(t, "origin.test", ca, dir)
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/binary" {
			w.Header().Set("Content-Type", "application/octet-stream")
		}
		_, _ = fmt.Fprintf(w, "plain:%s:%s", r.Method, r.URL.Path)
	}))
	t.Cleanup(plain.Close)
	_, originPort, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "https://"))
	_, plainPort, _ := net.SplitHostPort(strings.TrimPrefix(plain.URL, "http://"))

	hash, err := passwd.HashWithIterations("correct horse battery", 1000)
	if err != nil {
		t.Fatal(err)
	}
	users := filepath.Join(dir, "proxy.htpasswd")
	if err := os.WriteFile(users, []byte("alice:"+hash+"\nbuild1:"+hash+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// localhost stands in for the categories: one category the policy allows
	// reads from, and the rules then decide on the method, the content type and
	// the person.
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: egress
      address: "127.0.0.1:0"
      kind: forward
      forward:
        ports: [%s, %s]
        allow_private: true
        auth: {users_file: %s, realm: lab, groups: {agents: [build1], staff: [alice]}}
        categories:
          - name: local
            hosts: ["localhost", "127.0.0.1"]
        rules:
          - name: no-executables-back
            action: deny
            response_types: ["application/octet-stream"]
            comment: "change 2026-7"
          - name: no-uploads
            action: deny
            categories: [local]
            methods: [POST, PUT]
          - name: staff-read
            action: allow
            groups: [staff]
            categories: [local]
            methods: [GET, HEAD, CONNECT]
          - name: agents-anywhere
            action: allow
            groups: [agents]
logging:
  access: {enabled: false}
upstreams:
  - name: unused
    endpoints: [{address: 127.0.0.1:1}]
routes: []
`, originPort, plainPort, users)
	s := proxytest.Start(t, yaml)
	addr := s.Addrs()["egress"]
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)

	get := func(t *testing.T, user, method, url string, body io.Reader) *http.Response {
		t.Helper()
		c := forwardClient(t, addr, pool, user, "correct horse battery")
		req, err := http.NewRequestWithContext(t.Context(), method, url, body)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, url, err)
		}
		t.Cleanup(func() { _ = resp.Body.Close() })
		return resp
	}

	t.Run("a read the policy allows", func(t *testing.T) {
		resp := get(t, "alice", "GET", "http://localhost:"+plainPort+"/page", nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d", resp.StatusCode)
		}
		b, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(b), "plain:GET:/page") {
			t.Errorf("body %q", b)
		}
	})

	t.Run("an upload the policy refuses", func(t *testing.T) {
		resp := get(t, "alice", "POST", "http://localhost:"+plainPort+"/page",
			strings.NewReader("payload"))
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status %d, want 403", resp.StatusCode)
		}
		b, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(b), "rule_deny") {
			t.Errorf("the refusal does not name the reason: %q", b)
		}
	})

	t.Run("a response the policy refuses on the way back", func(t *testing.T) {
		// The request is allowed -- it is a GET from staff to an allowed
		// category -- and the response is what is refused, which is the one
		// decision that cannot be taken before the destination is contacted.
		resp := get(t, "alice", "GET", "http://localhost:"+plainPort+"/binary", nil)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status %d, want 403", resp.StatusCode)
		}
		b, _ := io.ReadAll(resp.Body)
		if strings.Contains(string(b), "plain:GET:/binary") {
			t.Error("the body was relayed to the client before the policy refused it")
		}
	})

	t.Run("a person no rule covers", func(t *testing.T) {
		// build1 is in agents, which is allowed anywhere; alice is in staff,
		// which is allowed reads. The difference is the whole point of groups.
		if resp := get(t, "build1", "GET", "http://localhost:"+plainPort+"/page", nil); resp.StatusCode != http.StatusOK {
			t.Errorf("an agent was refused: %d", resp.StatusCode)
		}
	})

	t.Run("a tunnel the destination rules allow", func(t *testing.T) {
		// Inside a tunnel there is no method, so staff-read's method list cannot
		// decide -- but CONNECT to an allowed category by an agent can, because
		// agents-anywhere names no request-level selector.
		c := forwardClient(t, addr, pool, "build1", "correct horse battery")
		resp, err := c.Get("https://localhost:" + originPort + "/tunnel")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status %d", resp.StatusCode)
		}
	})

	t.Run("a tunnel no rule can decide about", func(t *testing.T) {
		// alice's only allow rule names methods, which a tunnel does not carry,
		// so nothing allows her tunnel and it is refused for no_rule rather
		// than quietly permitted.
		c := forwardClient(t, addr, pool, "alice", "correct horse battery")
		_, err := c.Get("https://localhost:" + originPort + "/tunnel")
		if err == nil {
			t.Error("the tunnel was established")
		} else if !strings.Contains(err.Error(), "403") && !strings.Contains(err.Error(), "Forbidden") {
			t.Errorf("the tunnel failed with %v, want a 403", err)
		}
	})

	t.Run("the counters say what refused", func(t *testing.T) {
		if got := s.Counters().RefusalCounts()["forward"]["rule_deny"]; got < 2 {
			t.Errorf("rule_deny counted %d times, want at least 2", got)
		}
		if got := s.Counters().RefusalCounts()["forward"]["no_rule"]; got < 1 {
			t.Errorf("no_rule counted %d times, want at least 1", got)
		}
	})
}

// The check a tunnel needs when nothing is decrypting it.
//
// `intercept` has carried a CONNECT-versus-SNI check since it was written, and
// it only ever ran where the proxy was already terminating TLS. That left the
// ordinary case -- a proxy with a destination allow list and no interception at
// all -- deciding about a name the client then did not use, which is how domain
// fronting gets through a name-based policy.
func TestTheSNICheckOnATunnelNobodyIsDecrypting(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	origin := tlsOrigin(t, "origin.test", ca, dir)
	_, originPort, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "https://"))

	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: enforced
      address: "127.0.0.1:0"
      kind: forward
      forward:
        ports: [%s]
        allow_private: true
        sni: enforce
    - name: observed
      address: "127.0.0.1:0"
      kind: forward
      forward:
        ports: [%s]
        allow_private: true
logging:
  access: {enabled: false}
upstreams:
  - name: unused
    endpoints: [{address: 127.0.0.1:1}]
routes: []
`, originPort, originPort)
	s := proxytest.Start(t, yaml)
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)

	t.Run("a handshake for another name is refused", func(t *testing.T) {
		before := s.Counters().RefusalCounts()["forward"]["sni_mismatch"]
		c := connectTunnel(t, s.Addrs()["enforced"], "localhost:"+originPort)
		tc := tlsClientNamed(c, "elsewhere.test", pool)
		if err := tc.Handshake(); err == nil {
			t.Error("a handshake naming a host the tunnel did not name went through")
		}
		if got := s.Counters().RefusalCounts()["forward"]["sni_mismatch"]; got == before {
			t.Errorf("sni_mismatch counted %d, was %d", got, before)
		}
	})

	t.Run("the name the tunnel named is relayed", func(t *testing.T) {
		before := s.Counters().RefusalCounts()["forward"]["sni_mismatch"]
		c := connectTunnel(t, s.Addrs()["enforced"], "localhost:"+originPort)
		tc := tlsClientNamed(c, "localhost", pool)
		// The handshake still fails, on the origin's certificate: it is issued
		// for origin.test and this asked for localhost. That is the origin
		// refusing, which is the point -- the proxy relayed the handshake and
		// the two ends decided, which is what a tunnel is for.
		err := tc.Handshake()
		if err == nil || !strings.Contains(err.Error(), "certificate is valid for") {
			t.Errorf("handshake failed with %v, want the origin's certificate error", err)
		}
		_ = tc.Close()
		if got := s.Counters().RefusalCounts()["forward"]["sni_mismatch"]; got != before {
			t.Errorf("the proxy refused a matching name: %d refusals, was %d", got, before)
		}
	})

	t.Run("observe records it and relays it anyway", func(t *testing.T) {
		// The default, so that an estate reads its own traffic before this
		// refuses any of it.
		before := s.Counters().WouldRefusalCounts()["forward"]["sni_mismatch"]
		c := connectTunnel(t, s.Addrs()["observed"], "localhost:"+originPort)
		tc := tlsClientNamed(c, "elsewhere.test", pool)
		// The handshake fails on the origin's certificate rather than on the
		// proxy: the point is that the proxy let it through and wrote it down.
		_ = tc.Handshake()
		_ = tc.Close()
		if got := s.Counters().WouldRefusalCounts()["forward"]["sni_mismatch"]; got == before {
			t.Errorf("the mismatch was not recorded: %d", got)
		}
		if got := s.Counters().RefusalCounts()["forward"]["sni_mismatch"]; got != 1 {
			t.Errorf("observe refused something: %d refusals", got)
		}
	})
}

// tlsClientNamed is a TLS client that asks for one name, with a deadline so a
// refused handshake fails rather than waits.
func tlsClientNamed(c net.Conn, name string, pool *x509.CertPool) *tls.Conn {
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	return tls.Client(c, &tls.Config{ServerName: name, RootCAs: pool, MinVersion: tls.VersionTLS12})
}
