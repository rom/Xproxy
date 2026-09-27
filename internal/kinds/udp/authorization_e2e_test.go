package udp_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/rom/xproxy/internal/kinds/udp"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// authzRelay starts a relay with a top-level section appended -- the imported
// lists, the authorisation policy, or both.
func authzRelay(t *testing.T, e *echoUDP, top string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: games
      address: "127.0.0.1:0"
      kind: udp
      udp:
        upstream: backends
logging: {access: {enabled: false}}
upstreams:
  - name: backends
    endpoints: [{address: %s}]
%s
`, e.addr(), top))
	return s, s.Addrs()["games"]
}

// writeList puts one cidr list on disk.
func writeList(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "nets.txt")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// silent reports whether nothing came back within the window, which is what a
// dropped datagram looks like from the client's side: a datagram relay has
// nothing to refuse a datagram with.
func silent(t *testing.T, c interface {
	SetReadDeadline(time.Time) error
	Read([]byte) (int, error)
}) bool {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(400 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, err := c.Read(make([]byte, 2048))
	return err != nil
}

// A client on a blocking list never reaches the endpoint. Until now a cidr feed
// did nothing at all on this kind, which is the gap this closes.
func TestAListedClientNeverReachesTheEndpointOnUDP(t *testing.T) {
	e := startEchoUDP(t, "echo:")
	// The client of a loopback test is 127.0.0.1, so that is what the list holds.
	list := writeList(t, "127.0.0.1/32\n")
	s, addr := authzRelay(t, e, fmt.Sprintf(`threat_intel:
  lists:
    - {name: listed-clients, file: %s, action: block}`, list))

	c := dialUDP(t, addr)
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if !silent(t, c) {
		t.Error("a listed client got an answer")
	}
	select {
	case src := <-e.sources:
		t.Errorf("the endpoint saw a datagram from %s", src)
	default:
	}
	if n := s.Stats().Refusals["udp"]["threat_intel"]; n != 1 {
		t.Errorf("threat_intel refusals %d, want 1: %v", n, s.Stats().Refusals["udp"])
	}
}

// And a client the policy does not cover. A generic relay has no identity to
// decide about, so the rule is about the address, the pool and the hour -- which
// is the only policy available here, and a real one.
func TestAPolicyRefusesAClientOnUDP(t *testing.T) {
	e := startEchoUDP(t, "echo:")
	s, addr := authzRelay(t, e, `authorization:
  rules:
    - {name: plant-floor, allow: true, networks: ["10.0.0.0/8"]}`)

	c := dialUDP(t, addr)
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if !silent(t, c) {
		t.Error("a client no rule covers got an answer")
	}
	if n := s.Stats().Refusals["udp"]["authorization"]; n != 1 {
		t.Errorf("authorization refusals %d, want 1: %v", n, s.Stats().Refusals["udp"])
	}
}

// A rule that does cover the client carries the datagram, and the policy is asked
// once for the session rather than once per datagram: a policy walk per datagram
// would make a flood cheaper to send than to refuse.
func TestThePolicyIsAskedOncePerSessionOnUDP(t *testing.T) {
	e := startEchoUDP(t, "echo:")
	s, addr := authzRelay(t, e, `authorization:
  rules:
    - {name: loopback, allow: true, networks: ["127.0.0.0/8"], targets: [backends]}`)

	c := dialUDP(t, addr)
	for i := 0; i < 5; i++ {
		if _, err := c.Write([]byte("hello")); err != nil {
			t.Fatal(err)
		}
		if err := c.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 2048)
		if _, err := c.Read(buf); err != nil {
			t.Fatalf("datagram %d was not carried: %v", i, err)
		}
	}
	// Five datagrams, one session, and the policy decided once: allowed counts
	// decisions, so more than one would mean a decision per datagram.
	az := s.Stats().Authz
	if az == nil {
		t.Fatal("no authorisation summary")
	}
	if az.Allowed != 1 {
		t.Errorf("the policy decided %d times for one session, want once", az.Allowed)
	}
}
