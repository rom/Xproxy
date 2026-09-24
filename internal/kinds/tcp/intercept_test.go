package tcp_test

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	_ "github.com/rom/xproxy/internal/kinds/tcp" // the kind under test
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// An intercepting listener takes its destination from the socket. On a
// connection nobody intercepted, that destination is the listener's own
// address -- which is exactly the shape a wrong firewall rule produces,
// and the loop check is what stands between it and a process that
// consumes descriptors until it dies from one client packet.
//
// So this test drives the dangerous case rather than the happy one: it is
// the case that can be produced without root, and the one whose failure
// is catastrophic rather than inconvenient.
func interceptor(t *testing.T, extra string) (*proxy.Server, string) {
	t.Helper()
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: l4
      address: "127.0.0.1:0"
      kind: tcp
      tcp:
        original_destination: true
        allow_destinations: ["127.0.0.0/8"]
%s
logging: {access: {enabled: false}}
upstreams:
  - name: unused
    endpoints: [{address: "127.0.0.1:1"}]
routes: []
`, extra)
	s := proxytest.Start(t, yaml)
	return s, s.Addrs()["l4"]
}

func TestInterceptRefusesToDialItself(t *testing.T) {
	s, addr := interceptor(t, "")
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	// Enough bytes to settle the ClientHello peek, then the connection
	// must end rather than being relayed anywhere.
	if _, err := c.Write([]byte("hello there")); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := io.Copy(io.Discard, c); err == nil && n > 0 {
		t.Fatalf("the connection relayed %d bytes to the proxy's own address", n)
	}
	waitFor(t, 5*time.Second, "the loop to be counted", func() bool {
		return s.Stats().TCPErrors >= 1
	})
	// And exactly one connection was made: the loop was refused before a
	// second one existed.
	if n := s.Stats().TCPConnections; n != 1 {
		t.Fatalf("%d connections for one client: the loop was not stopped", n)
	}
}

// A destination outside allow_destinations cannot be produced here: the
// only destination a test without real interception can make is the
// listener's own address, and that is a loop, which is checked first
// (deliberately -- it is both cheaper and the more dangerous case). The
// policy itself is covered by internal/transparent's own tests, and the
// whole path against a real TPROXY rule is in the manual procedure in
// docs/TESTS.md, because it needs CAP_NET_ADMIN and a firewall.

// The settings that cannot work are refused at load rather than on the
// first connection: routes beside an original destination would be
// ignored, and a missing destination policy makes an open relay. The
// configuration package tests the messages; what matters here is that a
// listener with them cannot be started.
func TestInterceptValidation(t *testing.T) {
	for _, c := range []struct{ name, tcp string }{
		{"a default upstream would be ignored", "        original_destination: true\n        allow_destinations: [\"10.0.0.0/8\"]\n        default: unused\n"},
		{"no destination policy is an open relay", "        original_destination: true\n"},
	} {
		yaml := `
version: 1
server:
  listeners:
    - name: l4
      address: "127.0.0.1:0"
      kind: tcp
      tcp:
` + c.tcp + `
logging: {access: {enabled: false}}
upstreams:
  - name: unused
    endpoints: [{address: "127.0.0.1:1"}]
routes: []
`
		if _, err := config.Parse([]byte(yaml)); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
}
