package challenge

import "testing"

// A failed verification is only the client's fault when the client made
// it fail. The proxy's own verification table filling up under load, and
// a nonce spent by a double-submitted form or a reloaded page, are not
// grounds for a ban: counting them turns a flood into a self-inflicted
// outage in which every legitimate visitor who solves the challenge is
// banned for solving it.
func TestClientFaultExcludesTheProxysOwnLimits(t *testing.T) {
	for _, reason := range []string{"verification table full", "nonce already used"} {
		if ClientFault(reason) {
			t.Errorf("%q counted against the client", reason)
		}
	}
	for _, reason := range []string{"bad nonce", "wrong answer", "expired", "captcha failed", ""} {
		if !ClientFault(reason) {
			t.Errorf("%q did not count against the client", reason)
		}
	}
}
