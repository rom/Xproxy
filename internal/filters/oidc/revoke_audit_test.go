package oidc

import (
	"testing"
	"time"
)

// TestUnauthenticatedRevocationCannotEvict: when the revocation index is
// full of live entries, a front-channel or peer revocation is dropped, so a
// flood of made-up session ids cannot undo a real logout. The owner's own
// logout may still evict the soonest to expire.
func TestUnauthenticatedRevocationCannotEvict(t *testing.T) {
	f := &oidcFilter{name: "login", cfg: &Config{RevokedMax: 2, ttl: time.Hour}, revoked: map[string]time.Time{}}
	now := time.Now()
	// Two genuine logouts, expiring soon.
	f.revoke("real-1", now.Add(10*time.Minute), true)
	f.revoke("real-2", now.Add(20*time.Minute), true)
	// An attacker floods fresh, far-expiring sids through the unauthenticated
	// path: none of them may displace the real ones.
	for i := 0; i < 50; i++ {
		f.revoke("fake", now.Add(time.Hour), false)
	}
	if !f.isRevoked("real-1") || !f.isRevoked("real-2") || f.isRevoked("fake") {
		t.Fatalf("index after flood: %v", f.revoked)
	}
	// The owner's logout still finds room by evicting the soonest to expire.
	f.revoke("real-3", now.Add(30*time.Minute), true)
	if f.isRevoked("real-1") || !f.isRevoked("real-2") || !f.isRevoked("real-3") {
		t.Fatalf("owner logout did not evict the oldest: %v", f.revoked)
	}
}
