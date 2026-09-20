package cluster

import "testing"

// A peer's actions are recorded under the name its certificate carries,
// never under the node id it announces. mTLS authenticates the
// certificate; the id is a field in a message the peer wrote, so a node
// free to choose it could place bans and honeypot marks under another
// node's name and the audit trail would say whatever the attacker
// wanted.
func TestPeerIdentityIsTheCertificateName(t *testing.T) {
	in := &inbound{certName: "node-a"}
	announced := "node-b"
	in.nodeID.Store(&announced)
	if got := in.identity(); got != "node-a" {
		t.Fatalf("identity %q, want the certificate name", got)
	}
	// Without a certificate there is nothing better than the announced
	// id, and the transport requires one, so this is only a fallback.
	bare := &inbound{}
	bare.nodeID.Store(&announced)
	if got := bare.identity(); got != "node-b" {
		t.Fatalf("fallback identity %q", got)
	}
}

// With bind_node_id on, the announced id must be a name the certificate
// carries.
func TestCertNameMatches(t *testing.T) {
	names := []string{"edge1.example.test", "node-a"}
	for _, ok := range []string{"node-a", "NODE-A", "edge1.example.test"} {
		if !certNameMatches(names, ok) {
			t.Errorf("%q should match", ok)
		}
	}
	for _, bad := range []string{"node-b", "", "edge1", "node-a.example.test"} {
		if certNameMatches(names, bad) {
			t.Errorf("%q should not match", bad)
		}
	}
	if certNameMatches(nil, "node-a") {
		t.Error("a peer with no certificate must not match a name")
	}
}
