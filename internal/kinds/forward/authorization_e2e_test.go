package forward

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/passwd"
	"github.com/rom/xproxy/internal/proxytest"
)

// The decision itself, driven directly: who is asking, from where, and where
// they are going. It is a unit test of the decision rather than a request
// through the listener because a destination is resolved before the policy
// runs, and this machine's resolver knows nothing about the names a rule here
// lists; the end-to-end path is the test below.
func TestTheForwardPolicyDecidesOnUserAndDestination(t *testing.T) {
	yaml := `
version: 1
server:
  listeners:
    - {name: fwd, address: "127.0.0.1:0", kind: forward, forward: {}}
logging:
  access: {enabled: false}
upstreams:
  - {name: u, endpoints: [{address: "127.0.0.1:1"}]}
routes: []
authorization:
  rules:
    # A person may reach the vendor's API and nothing else.
    - {name: integrations, allow: true, users: [integration], targets: ["api.vendor.example:443"]}
    # Staff may reach anything on the web, from the office only.
    - {name: staff, allow: true, users: [alice], networks: ["192.0.2.0/24"], targets: ["*:443", "*:80"]}
`
	s := proxytest.Start(t, yaml)
	f := &forwardServer{host: s, name: "fwd"}
	office := netip.MustParseAddr("192.0.2.9")
	home := netip.MustParseAddr("198.51.100.9")
	for _, tc := range []struct {
		name        string
		client      netip.Addr
		user, host  string
		port        int
		wantRefusal bool
	}{
		{"the integration account at its one destination", office, "integration", "api.vendor.example", 443, false},
		{"the same account anywhere else", office, "integration", "api.other.example", 443, true},
		{"staff from the office", office, "alice", "www.example.com", 443, false},
		{"staff from home", home, "alice", "www.example.com", 443, true},
		// The glob does not cross the colon, so "*:443" is every host's 443
		// and not every host's everything -- which is what keeps one pattern
		// from being worth the whole internet.
		{"staff on a port no rule names", office, "alice", "www.example.com", 8443, true},
		{"somebody no rule covers", office, "mallory", "www.example.com", 443, true},
		// No name at all: a listener with no proxy credentials has nobody for
		// a rule about users to match, so the default decides. Deny.
		{"an anonymous client", office, "", "www.example.com", 443, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := f.admitByPolicy(f.policy.Load(), tc.client, tc.user, tc.host, tc.port)
			if (got != "") != tc.wantRefusal {
				t.Errorf("admitByPolicy(%v, %q, %q, %d) = %q, want refusal=%v",
					tc.client, tc.user, tc.host, tc.port, got, tc.wantRefusal)
			}
		})
	}
	// And with no section at all nothing is refused: a listener with no policy
	// over it keeps the policy it had before there was one.
	plain := proxytest.Start(t, `
version: 1
server:
  listeners:
    - {name: fwd, address: "127.0.0.1:0", kind: forward, forward: {}}
logging: {access: {enabled: false}}
upstreams:
  - {name: u, endpoints: [{address: "127.0.0.1:1"}]}
routes: []
`)
	open := &forwardServer{host: plain, name: "fwd"}
	if got := open.admitByPolicy(open.policy.Load(), office, "", "www.example.com", 443); got != "" {
		t.Errorf("a listener with no policy refused: %q", got)
	}
}

// The end-to-end path: an authenticated client the policy does not cover is
// refused with the reason in the answer, and the destination is never dialled.
// This is the plumbing -- ServeHTTP, check, deny -- rather than the matching.
func TestAForwardRequestThePolicyRefuses(t *testing.T) {
	var reached int
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached++
		fmt.Fprint(w, "origin")
	}))
	t.Cleanup(origin.Close)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))

	// bob may go there; alice is the one connecting.
	hash, err := passwd.HashWithIterations("correct horse battery", 1000)
	if err != nil {
		t.Fatal(err)
	}
	users := filepath.Join(t.TempDir(), "users")
	if err := os.WriteFile(users, []byte("alice:"+hash+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: fwd
      address: "127.0.0.1:0"
      kind: forward
      forward:
        ports: [%s]
        allow_private: true
        auth: {users_file: %s, realm: lab}
logging: {access: {enabled: false}}
upstreams:
  - {name: u, endpoints: [{address: "127.0.0.1:1"}]}
routes: []
authorization:
  rules:
    - {name: only-bob, allow: true, users: [bob]}
`, port, users))
	fwd := proxytest.Addr(t, s, "fwd")

	// Spoken by hand so the refusal is read as the proxy wrote it.
	conn, err := net.Dial("tcp", fwd)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	cred := base64.StdEncoding.EncodeToString([]byte("alice:correct horse battery"))
	req := fmt.Sprintf("GET http://localhost:%s/x HTTP/1.1\r\nHost: localhost:%s\r\n"+
		"Proxy-Authorization: Basic %s\r\n\r\n", port, port, cred)
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	got := string(buf[:n])
	if !strings.Contains(got, "403") || !strings.Contains(got, "authorization") {
		t.Fatalf("answer %q, want a 403 naming authorization", got)
	}
	if reached != 0 {
		t.Errorf("the destination was reached %d times", reached)
	}
	if n := s.Stats().Refusals["forward"]["authorization"]; n != 1 {
		t.Errorf("authorization refusals %d, want 1: %v", n, s.Stats().Refusals["forward"])
	}
}
