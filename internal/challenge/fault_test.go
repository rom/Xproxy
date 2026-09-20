package challenge

import "testing"

// ClientFault is an allow list, not a deny list. The third round
// enumerated two proxy-side reasons and missed the CAPTCHA provider
// ones, so a provider outage counted every visitor who solved the
// widget as a failure and, with a challenge ban trigger configured,
// banned them all. A reason added later must be harmless by default.
func TestClientFaultCoversProviderOutages(t *testing.T) {
	// Nothing the proxy or the provider can fail at is the client's.
	for _, reason := range []string{
		"verification table full", "nonce already used",
		"captcha unreachable", "captcha provider error", "captcha request",
		"some reason nobody has written yet", "",
	} {
		if ClientFault(reason) {
			t.Errorf("%q counted against the client", reason)
		}
	}
	// What the client actually did wrong still counts.
	for _, reason := range []string{
		"method", "form", "counter", "proof",
		"malformed nonce", "bad nonce signature", "nonce expired", "nonce too long",
		"captcha token", "captcha rejected", "captcha score", "captcha hostname",
	} {
		if !ClientFault(reason) {
			t.Errorf("%q did not count against the client", reason)
		}
	}
}
