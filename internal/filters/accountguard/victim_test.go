package accountguard

import "testing"

// A count keyed on the account belongs to the person being attacked:
// anybody can type somebody else's name. Before this, a handful of failed
// logins against a chosen account blocked its owner from their own
// addresses, which turns the anti-abuse feature into a targeted denial of
// service. Account-keyed counts may raise the ladder as far as a
// challenge, which the real owner can pass; they must never reach a
// block.
func TestDefaultBlocksAreNotAccountKeyed(t *testing.T) {
	classes := []string{"login", "register", "reset", "cart", "scrape", "checkout", "api", "generic"}
	seen := 0
	for _, class := range classes {
		steps := defaultSteps(class)
		if len(steps) == 0 {
			continue // not a built-in class
		}
		seen++
		blocks := 0
		for i, s := range steps {
			if s.Action != "block" {
				continue
			}
			blocks++
			if s.Account > 0 {
				t.Errorf("%s step %d: block keyed on account (%d)", class, i, s.Account)
			}
			if s.AccountIPs > 0 {
				t.Errorf("%s step %d: block keyed on account_ips (%d)", class, i, s.AccountIPs)
			}
		}
		if blocks == 0 {
			t.Errorf("%s has no block step, so the test proves nothing about it", class)
		}
	}
	if seen < 4 {
		t.Fatalf("only %d built-in classes were exercised", seen)
	}
}

// The ladder must still stop an attacker: every class keeps a rung keyed
// on the address.
func TestDefaultStepsStillCountTheSource(t *testing.T) {
	for _, class := range []string{"login", "register", "reset", "cart"} {
		found := false
		for _, s := range defaultSteps(class) {
			if s.Action == "block" && (s.IP > 0 || s.Pair > 0 || s.Device > 0) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s has no block keyed on the address, the pair or the device", class)
		}
	}
}
