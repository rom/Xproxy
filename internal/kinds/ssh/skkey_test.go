package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"testing"

	cssh "golang.org/x/crypto/ssh"
)

// A FIDO2 key, without a FIDO2 token.
//
// There is no way to plug a security key into a test, so the token's half of
// the protocol is implemented here: an sk-ssh-ed25519@openssh.com public key
// (the ed25519 public key with the application string beside it) and a signer
// that builds the envelope a token builds -- the application digest, the flags
// saying whether the user was present, a counter, and the digest of what is
// being signed -- and signs that.
//
// It is the real wire format, verified by the same code that verifies a real
// token's signature, so what the tests exercise is this gateway's policy
// rather than a stand-in for it. Exported because the end-to-end tests live in
// the external test package and there is no second copy of this worth having.

// SKSigner signs as a security key does. Presence clear signs as a token whose
// user never touched it.
type SKSigner struct {
	pub      cssh.PublicKey
	priv     ed25519.PrivateKey
	app      string
	Presence bool
}

// PublicKey is the sk- key this signer presents.
func (s *SKSigner) PublicKey() cssh.PublicKey { return s.pub }

// Sign builds the signature a token would, over the envelope a token signs.
func (s *SKSigner) Sign(_ io.Reader, data []byte) (*cssh.Signature, error) {
	appDigest := sha256.Sum256([]byte(s.app))
	dataDigest := sha256.Sum256(data)
	var flags byte
	if s.Presence {
		flags = 0x01 // the user-presence bit, as in openssh/PROTOCOL.u2f
	}
	const counter = 7
	envelope := cssh.Marshal(struct {
		ApplicationDigest []byte `ssh:"rest"`
		Flags             byte
		Counter           uint32
		MessageDigest     []byte `ssh:"rest"`
	}{appDigest[:], flags, counter, dataDigest[:]})
	return &cssh.Signature{
		Format: cssh.KeyAlgoSKED25519,
		Blob:   ed25519.Sign(s.priv, envelope),
		Rest: cssh.Marshal(struct {
			Flags   byte
			Counter uint32
		}{flags, counter}),
	}, nil
}

// SKTestKey returns a hardware-backed key: the authorized_keys line for it and
// a signer that presents it, with presence asserted.
func SKTestKey(t *testing.T) (string, *SKSigner) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const app = "ssh:"
	blob := cssh.Marshal(struct {
		Type        string
		KeyBytes    []byte
		Application string
	}{cssh.KeyAlgoSKED25519, pub, app})
	parsed, err := cssh.ParsePublicKey(blob)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Type() != cssh.KeyAlgoSKED25519 {
		t.Fatalf("built a %s, not a security key", parsed.Type())
	}
	return string(cssh.MarshalAuthorizedKey(parsed)), &SKSigner{pub: parsed, priv: priv, app: app, Presence: true}
}
