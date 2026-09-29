package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	cssh "golang.org/x/crypto/ssh"
)

// The critical-option gate, driven directly, because the end-to-end tests
// cannot see which reason refused a certificate.
//
// CheckCert refuses any critical option this gateway did not name: an option it
// might not implement must not be quietly ignored. source-address has to be in
// that list even though CheckCert does not evaluate it, and the reason is a
// change in the library rather than anything about this gateway. x/crypto/ssh
// up to v0.54.0 skipped this one option inside CheckCert, on the grounds that
// its own serverAuthenticate would enforce it later, and a caller calling
// CheckCert directly inherited the skip. v0.55.0 removed the special case, so a
// direct caller that does not name the option refuses every certificate
// carrying it -- whatever the value, and before certSourceAddress ever reads
// it.
//
// That failure is fail-closed and exactly backwards: it refuses the
// certificates an estate hardened and leaves the check that reads them
// unreached. It is also nearly invisible end to end, because the test for a
// restricted certificate asserts a refusal and would get one for the wrong
// reason. So the list is asserted here, against the gateway's own value.
func TestTheCertificateOptionsThisGatewayAccepts(t *testing.T) {
	ca := mustSigner(t)
	client := mustSigner(t)
	checker := &cssh.CertChecker{
		IsUserAuthority: func(auth cssh.PublicKey) bool {
			return string(auth.Marshal()) == string(ca.PublicKey().Marshal())
		},
		// The gateway's own list, so dropping an option from it fails here.
		SupportedCriticalOptions: certOptionsImplemented,
	}
	for what, opts := range map[string]map[string]string{
		"source-address alone":             {"source-address": "127.0.0.0/8"},
		"source-address and force-command": {"source-address": "10.0.0.0/8", "force-command": "/bin/true"},
		"force-command alone":              {"force-command": "/bin/true"},
		// A value CheckCert cannot be expected to judge: naming the option
		// says somebody reads it, not that this one parses. certSourceAddress
		// is where an unreadable list is refused, and it has its own test.
		"a source-address that is not a network": {"source-address": "not-a-cidr/99"},
	} {
		if err := checker.CheckCert("alice", signedCert(t, ca, client, opts)); err != nil {
			t.Errorf("%s: %v", what, err)
		}
	}
	// And the gate still closes on an option this gateway does not implement,
	// which is the reason it exists at all.
	for _, opt := range []string{"verify-required", "no-touch-required", "something-invented"} {
		cert := signedCert(t, ca, client, map[string]string{opt: ""})
		if err := checker.CheckCert("alice", cert); err == nil {
			t.Errorf("the critical option %q was accepted and nothing implements it", opt)
		}
	}
}

// mustSigner is an ed25519 signer, which is what an authority and a client key
// both are here.
func mustSigner(t *testing.T) cssh.Signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := cssh.NewSignerFromSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// signedCert is a user certificate carrying the given critical options, signed
// so that CheckCert reaches every check rather than stopping at the signature.
func signedCert(t *testing.T, ca, key cssh.Signer, critical map[string]string) *cssh.Certificate {
	t.Helper()
	cert := &cssh.Certificate{
		Key:             key.PublicKey(),
		CertType:        cssh.UserCert,
		KeyId:           "test",
		ValidPrincipals: []string{"alice"},
		ValidAfter:      uint64(time.Now().Add(-time.Minute).Unix()), //nolint:gosec // a recent time fits
		ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),    //nolint:gosec // a future time fits
		Permissions:     cssh.Permissions{CriticalOptions: critical},
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	return cert
}
