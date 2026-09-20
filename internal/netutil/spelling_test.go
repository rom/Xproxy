package netutil

import "testing"

// A host arrives from the client as text and becomes a routing key. DNS
// knows one name where text knows many spellings, and every spelling
// that survives normalisation as a distinct string is a second key for
// the same host: it misses the exact route table and falls through to
// the catch-all, skipping that route's access lists, authentication
// filters, WAF profile, rate limits and policy.
func TestHostHasOneSpellingPerName(t *testing.T) {
	// Spellings of one name that must all normalise to the same key.
	for _, spelling := range []string{
		"api.example.test",
		"api.example.test.",
		"API.Example.TEST",
		"api.example.test:443",
		"API.Example.TEST.:8443",
	} {
		if got := Host(spelling); got != "api.example.test" {
			t.Errorf("Host(%q) = %q", spelling, got)
		}
	}
	// Text that is not a host name at all: an empty label anywhere. Each
	// of these used to come back as its own routing key.
	for _, bad := range []string{
		"api.example.test..",
		"api.example.test...",
		".api.example.test",
		"api..example.test",
		"..",
	} {
		if got := Host(bad); got != "" {
			t.Errorf("Host(%q) = %q, want a refusal", bad, got)
		}
	}
}

// The same rule on the layer 4 and QUIC path, where the name comes from
// a ClientHello and selects the upstream or falls to tcp.default.
func TestClientHelloSNIHasOneSpellingPerName(t *testing.T) {
	for _, spelling := range []string{"api.example.test", "api.example.test.", "API.Example.TEST"} {
		name, err := ClientHelloSNI(seedHello(spelling))
		if err != nil || name != "api.example.test" {
			t.Errorf("%q: %q %v", spelling, name, err)
		}
	}
	for _, bad := range []string{"api.example.test..", ".api.example.test", "api..example.test"} {
		if name, err := ClientHelloSNI(seedHello(bad)); err == nil {
			t.Errorf("%q was accepted as %q", bad, name)
		}
	}
}
