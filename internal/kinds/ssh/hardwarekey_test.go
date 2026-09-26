package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	cssh "golang.org/x/crypto/ssh"

	"github.com/rom/xproxy/internal/config"
)

// The token policy, driven directly: the listener's requirement, a principal's
// own answer to it, and a certificate that asks for the touch to be waived.
func TestTheHardwareKeyDecision(t *testing.T) {
	_, signer := SKTestKey(t)
	skPub := signer.PublicKey()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	filePub, err := cssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	yes, no := true, false
	for _, tc := range []struct {
		name     string
		required bool
		touch    *bool
		pr       *sshPrincipal
		key      cssh.PublicKey
		wantErr  string
	}{
		{name: "a token where one is required", required: true, key: skPub},
		{name: "a file where one is required", required: true, key: filePub,
			wantErr: "only a key held in a security token"},
		{name: "a file where none is required", key: filePub},
		// The exemption an estate needs while it is moving to tokens, and the
		// opposite: a principal held to a standard the listener does not set.
		{name: "a principal exempted from the requirement", required: true, key: filePub,
			pr: &sshPrincipal{name: "robot", hardware: &no}},
		{name: "a principal that asks for one the listener does not", key: filePub,
			pr:      &sshPrincipal{name: "admin", hardware: &yes},
			wantErr: "only a key held in a security token"},
		// An authority can hand out a credential that needs no touch. This
		// listener's answer to that is no, unless it has said otherwise.
		{name: "a certificate waiving the touch", required: true, key: certWaivingTouch(t, skPub),
			wantErr: "requires user presence"},
		{name: "the same certificate where the touch is not required", required: true,
			touch: &no, key: certWaivingTouch(t, skPub)},
		// A certificate over a key in a file is still a key in a file.
		{name: "a certificate over a file key", required: true, key: certOver(t, filePub),
			wantErr: "only a key held in a security token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := &server{h: &config.SSHListener{RequireHardwareKey: tc.required, RequireTouch: tc.touch}}
			err := srv.checkHardwareKey(tc.key, tc.pr)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Errorf("refused: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Errorf("error %v, want one about %q", err, tc.wantErr)
			}
		})
	}
}

// certWaivingTouch is a certificate carrying the no-touch-required extension,
// which is how an authority hands out a credential that needs no touch.
func certWaivingTouch(t *testing.T, key cssh.PublicKey) cssh.PublicKey {
	t.Helper()
	cert := certOver(t, key).(*cssh.Certificate)
	cert.Extensions = map[string]string{noTouchRequired: ""}
	return cert
}

func certOver(t *testing.T, key cssh.PublicKey) cssh.PublicKey {
	t.Helper()
	return &cssh.Certificate{Key: key, CertType: cssh.UserCert, KeyId: "test"}
}

// The classification itself, which is what every rule above rests on.
func TestWhatCountsAsHardwareBacked(t *testing.T) {
	_, signer := SKTestKey(t)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	filePub, err := cssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		key  cssh.PublicKey
		want bool
	}{
		{"a security key", signer.PublicKey(), true},
		{"a key in a file", filePub, false},
		// For a certificate it is the certificate's own key that decides: the
		// authority signed a statement about a key, and where that key lives
		// is the question here.
		{"a certificate over a security key", certOver(t, signer.PublicKey()), true},
		{"a certificate over a file key", certOver(t, filePub), false},
		{"a certificate over nothing", &cssh.Certificate{}, false},
	} {
		if got := hardwareBacked(tc.key); got != tc.want {
			t.Errorf("%s: hardwareBacked = %v, want %v", tc.name, got, tc.want)
		}
	}
}
