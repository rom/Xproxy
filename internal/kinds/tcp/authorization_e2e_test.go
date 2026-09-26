package tcp_test

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/rom/xproxy/internal/kinds/tcp"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// countingSink accepts and counts, so a test can say whether the endpoint was
// reached at all -- which is the assertion that matters. A test that checked only
// the client's side would pass against a relay that refused the client and
// dialled the endpoint anyway.
func countingSink(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var n atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			_ = c.Close()
		}
	}()
	return ln.Addr().String(), &n
}

// authzRelay starts a kind: tcp listener with a top-level section appended.
func authzRelay(t *testing.T, backend, top string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: l4
      address: "127.0.0.1:0"
      kind: tcp
      tcp:
        default: backend
logging: {access: {enabled: false}}
upstreams:
  - name: backend
    endpoints: [{address: %s}]
%s
`, backend, top))
	return s, s.Addrs()["l4"]
}

func writeList(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "nets.txt")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// speak opens a connection, says something -- the relay waits for a ClientHello
// or a timeout before routing, so silence would take the settle path -- and
// reports whether the endpoint was reached.
func speak(t *testing.T, addr string, reached *atomic.Int64) bool {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte("hello\n")); err != nil {
		return false
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if reached.Load() > 0 {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// A client on a blocking list never reaches the endpoint. Until now a cidr feed
// did nothing at all on this kind, which is the gap this closes.
func TestAListedClientNeverReachesTheEndpointOnTCP(t *testing.T) {
	backend, reached := countingSink(t)
	list := writeList(t, "127.0.0.1/32\n")
	s, addr := authzRelay(t, backend, fmt.Sprintf(`threat_intel:
  lists:
    - {name: listed-clients, file: %s, action: block}`, list))

	if speak(t, addr, reached) {
		t.Error("a listed client reached the endpoint")
	}
	if n := s.Stats().Refusals["tcp"]["threat_intel"]; n != 1 {
		t.Errorf("threat_intel refusals %d, want 1: %v", n, s.Stats().Refusals["tcp"])
	}
}

// And a client the policy does not cover. A generic relay has no identity to
// decide about, so the rule is about the address, the pool and the hour.
func TestAPolicyRefusesAClientOnTCP(t *testing.T) {
	backend, reached := countingSink(t)
	s, addr := authzRelay(t, backend, `authorization:
  rules:
    - {name: plant-floor, allow: true, networks: ["10.0.0.0/8"]}`)

	if speak(t, addr, reached) {
		t.Error("a client no rule covers reached the endpoint")
	}
	if n := s.Stats().Refusals["tcp"]["authorization"]; n != 1 {
		t.Errorf("authorization refusals %d, want 1: %v", n, s.Stats().Refusals["tcp"])
	}
}

// A rule naming the pool carries the connection, which is what makes the rule
// worth writing: the target on this kind is the upstream the route chose.
func TestAPolicyNamingThePoolCarriesTheConnection(t *testing.T) {
	backend, reached := countingSink(t)
	_, addr := authzRelay(t, backend, `authorization:
  rules:
    - {name: loopback, allow: true, networks: ["127.0.0.0/8"], targets: [backend]}`)

	if !speak(t, addr, reached) {
		t.Error("a connection the policy allows did not reach the endpoint")
	}
}

// A shadowed listener records and carries on.
func TestAShadowedListenerRecordsOnTCP(t *testing.T) {
	backend, reached := countingSink(t)
	s, addr := authzRelay(t, backend, `policy: {mode: shadow}
authorization:
  rules:
    - {name: not-loopback, networks: ["127.0.0.0/8"]}`)

	if !speak(t, addr, reached) {
		t.Error("a shadowed listener refused a connection")
	}
	found := false
	for _, e := range s.Shadow().Report() {
		if e.Kind == "tcp" && e.Reason == "authorization" && e.Rule == "not-loopback" {
			found = true
		}
	}
	if !found {
		t.Errorf("no shadow entry naming the rule: %+v", s.Shadow().Report())
	}
	if n := s.Stats().Refusals["tcp"]["authorization"]; n != 0 {
		t.Errorf("a shadowed refusal was counted as a refusal: %d", n)
	}
}
