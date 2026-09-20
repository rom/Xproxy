package oidc

import (
	"testing"
	"time"
)

func newRevokeFilter(limit int) *oidcFilter {
	return &oidcFilter{name: "login", cfg: &Config{RevokedMax: limit, ttl: time.Hour}, revoked: map[string]time.Time{}, revokedFC: map[string]time.Time{}, issued: map[string]time.Time{}}
}

// TestUnauthenticatedRevocationCannotEvict: front-channel or peer
// revocations for unknown session ids live in their own bounded table, so
// a flood of made-up ids can neither displace a real logout nor keep one
// from being recorded. The owner's own logout may still evict the soonest
// to expire of the owner table.
func TestUnauthenticatedRevocationCannotEvict(t *testing.T) {
	f := newRevokeFilter(2)
	now := time.Now()
	// Two genuine logouts, expiring soon.
	f.revoke("real-1", now.Add(10*time.Minute), true)
	f.revoke("real-2", now.Add(20*time.Minute), true)
	// An attacker floods fresh, far-expiring sids through the unauthenticated
	// path: none of them may displace the real ones.
	for i := 0; i < 50; i++ {
		f.revoke("fake", now.Add(time.Hour), false)
		f.revoke("fake2", now.Add(time.Hour), false)
		f.revoke("fake3", now.Add(time.Hour), false)
	}
	if !f.isRevoked("real-1") || !f.isRevoked("real-2") {
		t.Fatalf("index after flood: %v", f.revoked)
	}
	if len(f.revokedFC) > 2 {
		t.Fatalf("unauthenticated table unbounded: %d", len(f.revokedFC))
	}
	// The owner's logout still finds room by evicting the soonest to expire.
	f.revoke("real-3", now.Add(30*time.Minute), true)
	if f.isRevoked("real-1") || !f.isRevoked("real-2") || !f.isRevoked("real-3") {
		t.Fatalf("owner logout did not evict the oldest: %v", f.revoked)
	}
	// A genuine front-channel logout, for a sid this node issued a session
	// for, is recorded although the unauthenticated table is full: the
	// provider can only name that sid because the login happened here.
	f.noteIssued("issued-sid", now.Add(time.Hour))
	f.revoke("issued-sid", now.Add(time.Hour), false)
	if !f.isRevoked("issued-sid") {
		t.Fatal("front-channel logout for an issued session dropped")
	}
	if _, inFC := f.revokedFC["issued-sid"]; inFC {
		t.Fatal("issued sid landed in the unauthenticated table")
	}
	// The drop is counted, not logged per call.
	if f.fcFull.Total() == 0 {
		t.Fatal("dropped revocations not counted")
	}
}

// TestOwnerLogoutCannotDrainFrontChannel: an authenticated caller who
// logs out repeatedly evicts from the owner table only; entries the
// provider revoked for other users are untouched.
func TestOwnerLogoutCannotDrainFrontChannel(t *testing.T) {
	f := newRevokeFilter(2)
	now := time.Now()
	f.revoke("victim-1", now.Add(time.Hour), false)
	f.revoke("victim-2", now.Add(time.Hour), false)
	for i := 0; i < 10; i++ {
		f.revoke("attacker", now.Add(2*time.Hour), true)
	}
	if !f.isRevoked("victim-1") || !f.isRevoked("victim-2") {
		t.Fatal("owner logouts drained the provider's revocations")
	}
}
