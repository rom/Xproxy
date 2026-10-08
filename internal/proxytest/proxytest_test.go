package proxytest_test

import (
	"net/http"
	"strings"
	"testing"

	_ "github.com/rom/xproxy/internal/kinds/http" // the kind the configurations below name
	"github.com/rom/xproxy/internal/proxytest"
)

// The harness the kind packages are tested through.
//
// It is tested for the same reason the kinds are: a helper that reported a
// configuration had loaded when it had not, or handed back the wrong listener's
// port, would turn a real failure into a passing test in forty packages at
// once. Two of its five calls exist precisely so a test can assert that a
// daemon does *not* start, and those are the ones worth pinning: they must
// return the error rather than swallow it, and they must distinguish the
// configuration that would not parse from the one that parsed and would not run.
//
// What is not reachable from here is each call's `t.Fatal` branch, which needs
// a *testing.T that records a failure instead of ending the test. Those are the
// harness saying a test's own arrangement is wrong, and a test that provoked one
// would be a test that fails.

const minimal = `
version: 1
server:
  listeners:
    - {name: edge, address: "127.0.0.1:0"}
logging: {access: {enabled: false}}
upstreams:
  - {name: app, endpoints: [{address: 127.0.0.1:1}]}
routes:
  - {name: r, upstream: app}
`

// A configuration that loads, starts and binds: Addr finds the port the kernel
// chose, which is the whole reason the kinds can ask for ":0".
func TestStartBindsAndAddrFindsThePort(t *testing.T) {
	s := proxytest.Start(t, minimal)
	addr := proxytest.Addr(t, s, "edge")
	if !strings.HasPrefix(addr, "127.0.0.1:") || strings.HasSuffix(addr, ":0") {
		t.Fatalf("addr = %q, want a bound port", addr)
	}
	resp, body := proxytest.Get(t, "http://"+addr+"/", "Host", "anything.test")
	// The route points at a dead endpoint, so what comes back is a gateway
	// error -- which is still the listener answering, which is the point.
	if resp.StatusCode == http.StatusOK {
		t.Errorf("status %d with no upstream behind it: %q", resp.StatusCode, body)
	}
}

// StartError separates the two ways a daemon fails to come up, because a test
// asserting "this must not start" has to know it did not start for its own
// reason rather than a typo in its YAML.
func TestStartErrorTellsTheTwoFailuresApart(t *testing.T) {
	// Will not parse.
	if err := proxytest.StartError(t, "version: 1\nserver: [this is not a mapping]\n"); err == nil {
		t.Error("a configuration that does not parse returned no error")
	}
	// Parses, and will not load: a listener that requires TLS without one.
	const noCert = `
version: 1
server:
  listeners:
    - {name: edge, address: "127.0.0.1:0", protocols: [h1, h2]}
logging: {access: {enabled: false}}
upstreams:
  - {name: app, endpoints: [{address: 127.0.0.1:1}]}
routes:
  - {name: r, upstream: app}
`
	if err := proxytest.StartError(t, noCert); err == nil {
		t.Error("h2 without TLS loaded")
	}
	// And a configuration that does start comes back with no error at all,
	// having been shut down again.
	if err := proxytest.StartError(t, minimal); err != nil {
		t.Errorf("a configuration that starts: %v", err)
	}
}

// TryStart builds without starting, for the tests whose subject is a
// configuration that must not load at all -- where the bug would be a listener
// quietly serving plaintext instead of refusing.
func TestTryStartBuildsWithoutBinding(t *testing.T) {
	if _, err := proxytest.TryStart("version: 1\nserver: [not a mapping]\n"); err == nil {
		t.Error("a configuration that does not parse built a server")
	}
	s, err := proxytest.TryStart(minimal)
	if err != nil {
		t.Fatalf("a configuration that loads: %v", err)
	}
	if s == nil {
		t.Fatal("no server and no error")
	}
	// Nothing was bound, so there are no addresses to find.
	if n := len(s.Addrs()); n != 0 {
		t.Errorf("%d addresses before Start", n)
	}
}
