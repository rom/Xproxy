package forward

import (
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

	"github.com/rom/xproxy/internal/proxytest"
)

// writeList puts one list on disk and returns its path.
func writeList(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A forward proxy asks the imported lists two questions: who is connecting,
// and where they are going. This is the second one, which is the one worth
// having at an egress proxy -- and the destination is a name or an address,
// which decides which lists may answer.
//
// It is a unit test of the decision rather than a request through the
// listener, because a destination is resolved before the policy runs and this
// machine's resolver knows nothing about the names a feed lists. The end to
// end path is the client-address case below.
func TestAForwardDestinationIsAskedAbout(t *testing.T) {
	// The second entry is what an address destination would match if it were
	// offered to a domain list: the walk takes suffixes, and the tail of a
	// dotted quad is a two-label "name" as far as a feed's syntax goes.
	domains := writeList(t, "domains.txt", "evil.example\n0.113.4\n")
	urls := writeList(t, "urls.txt", "shared.example/bad\n")
	hashes := writeList(t, "hashes.txt",
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n")
	nets := writeList(t, "nets.txt", "203.0.113.0/24\n")
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - {name: fwd, address: "127.0.0.1:0", kind: forward, forward: {}}
logging:
  access: {enabled: false}
threat_intel:
  lists:
    - {name: bad-names, kind: domain, file: %s, action: block}
    - {name: bad-urls, kind: url, file: %s, action: block}
    - {name: bad-files, kind: hash, file: %s, action: block}
    - {name: bad-nets, file: %s, action: block}
upstreams:
  - {name: u, endpoints: [{address: "127.0.0.1:1"}]}
routes: []
`, domains, urls, hashes, nets)
	s := proxytest.Start(t, yaml)
	f := &forwardServer{host: s, name: "fwd"}
	client := netip.MustParseAddr("192.0.2.9")
	for _, tc := range []struct {
		name, host, url, want string
	}{
		{"the name itself", "evil.example", "", "bad-names"},
		{"a name under it", "cdn.evil.example", "", "bad-names"},
		{"a name beside it", "notevil.example", "", ""},
		{"a listed url through the plain path", "shared.example", "shared.example/bad/x", "bad-urls"},
		{"another resource on the same host", "shared.example", "shared.example/good", ""},
		// A destination written as an address is not a name. A domain list
		// holds names, and asking it about an address would be answering a
		// question it has no entries for.
		{"an address destination", "203.0.113.4", "", ""},
		{"an address destination in brackets", "[2001:db8::1]", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := f.intel(client, tc.host, tc.url); got != tc.want {
				t.Errorf("intel(%q, %q) = %q, want %q", tc.host, tc.url, got, tc.want)
			}
		})
	}
	// An address feed is about the client, and the client is what it is asked
	// about: a destination in 203.0.113.0/24 above was allowed, and the same
	// address connecting is refused.
	if got := f.intel(netip.MustParseAddr("203.0.113.7"), "good.example", ""); got != "bad-nets" {
		t.Errorf("a listed client was not matched: %q", got)
	}
	// And a hash list cannot match a forward request at all: nothing in a
	// CONNECT or a proxied GET names a payload.
	digest := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got := f.intel(client, digest, ""); got != "" {
		t.Errorf("a digest as a host name matched a hash list: %q", got)
	}
}

// The end to end path: a client in a listed network is refused by the forward
// listener, with the refusal counted and the reason in the answer. This is the
// plumbing -- ServeHTTP, check, deny -- rather than the matching, which is
// above.
func TestAListedForwardClientIsRefused(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "origin")
	}))
	t.Cleanup(origin.Close)
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(origin.URL, "http://"))
	// The client of a test through a loopback listener is 127.0.0.1, so that
	// is what the list holds. An intel list takes a loopback entry where the
	// ban list refuses one: a ban is earned and a loopback client is this
	// machine, while a list is imported and a test estate is entitled to
	// import one about itself.
	nets := writeList(t, "clients.txt", "127.0.0.1/32\n")
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: fwd
      address: "127.0.0.1:0"
      kind: forward
      forward: {ports: [%s], allow_private: true}
logging:
  access: {enabled: false}
threat_intel:
  lists:
    - {name: listed-clients, file: %s, action: block}
upstreams:
  - {name: u, endpoints: [{address: "127.0.0.1:1"}]}
routes: []
`, port, nets)
	s := proxytest.Start(t, yaml)
	before := s.Counters().ThreatIntelBlocked.Load()
	fwd := proxytest.Addr(t, s, "fwd")
	// Spoken by hand rather than with a proxy-aware client, so the refusal is
	// read as the proxy wrote it.
	conn, err := net.Dial("tcp", fwd)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := fmt.Fprintf(conn, "GET http://localhost:%s/x HTTP/1.1\r\nHost: localhost:%s\r\n\r\n", port, port); err != nil {
		t.Fatal(err)
	}
	// One read with a deadline: the refusal is one small write, and the
	// connection stays open afterwards, so reading to EOF would wait for the
	// idle timeout.
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	got := string(buf[:n])
	if !strings.Contains(got, "403") || !strings.Contains(got, "threat_intel") {
		t.Fatalf("answer %q, want a 403 naming threat_intel", got)
	}
	if after := s.Counters().ThreatIntelBlocked.Load(); after != before+1 {
		t.Errorf("threat_intel_blocked %d, want %d", after, before+1)
	}
}
