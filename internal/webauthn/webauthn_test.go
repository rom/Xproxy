package webauthn

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// authenticator is the other half of the ceremony: a key, a credential
// identifier and a counter. Tests need it because there is no other way to
// produce an assertion, and writing it is also the only way to be sure the
// verifier is checking the bytes the specification says rather than the
// bytes this package happens to produce.
type authenticator struct {
	key   *ecdsa.PrivateKey
	id    []byte
	count uint32
	// rpID is what the authenticator hashes into its data.
	rpID string
}

func newAuthenticator(t *testing.T, rpID string) *authenticator {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	return &authenticator{key: k, id: id, count: 1, rpID: rpID}
}

// coseKey is the public key as an authenticator reports it.
func (a *authenticator) coseKey() []byte {
	size := 32
	x := a.key.X.FillBytes(make([]byte, size))
	y := a.key.Y.FillBytes(make([]byte, size))
	var b []byte
	b = append(b, 0xa5) // map of 5
	b = append(b, encInt(coseKty)...)
	b = append(b, encInt(ktyEC2)...)
	b = append(b, encInt(coseAlg)...)
	b = append(b, encInt(algES256)...)
	b = append(b, encInt(coseCrv)...)
	b = append(b, encInt(1)...) // P-256
	b = append(b, encInt(coseXE)...)
	b = append(b, encBytes(x)...)
	b = append(b, encInt(coseY)...)
	b = append(b, encBytes(y)...)
	return b
}

// encInt encodes a CBOR integer of either sign.
func encInt(n int64) []byte {
	if n >= 0 {
		return encUint(0, uint64(n))
	}
	return encUint(1, uint64(-1-n)) //nolint:gosec // n is negative here
}

// encUint encodes a head with a major type.
func encUint(major byte, v uint64) []byte {
	switch {
	case v < 24:
		return []byte{major<<5 | byte(v)}
	case v < 1<<8:
		return []byte{major<<5 | 24, byte(v)}
	case v < 1<<16:
		return append([]byte{major<<5 | 25}, byte(v>>8), byte(v))
	case v < 1<<32:
		b := []byte{major<<5 | 26}
		return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
	b := []byte{major<<5 | 27}
	var x [8]byte
	binary.BigEndian.PutUint64(x[:], v)
	return append(b, x[:]...)
}

func encBytes(b []byte) []byte { return append(encUint(2, uint64(len(b))), b...) }
func encText(s string) []byte  { return append(encUint(3, uint64(len(s))), s...) }

// authData builds authenticator data. attested adds the credential.
func (a *authenticator) authData(flags byte, attested bool) []byte {
	h := sha256.Sum256([]byte(a.rpID))
	out := append([]byte{}, h[:]...)
	if attested {
		flags |= flagAttested
	}
	out = append(out, flags)
	var c [4]byte
	binary.BigEndian.PutUint32(c[:], a.count)
	out = append(out, c[:]...)
	if attested {
		out = append(out, make([]byte, 16)...) // aaguid
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(a.id)))
		out = append(out, l[:]...)
		out = append(out, a.id...)
		out = append(out, a.coseKey()...)
	}
	return out
}

// clientData builds a clientDataJSON.
func clientDataJSON(t *testing.T, typ, origin string, challenge []byte, crossOrigin bool) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"type":        typ,
		"challenge":   base64.RawURLEncoding.EncodeToString(challenge),
		"origin":      origin,
		"crossOrigin": crossOrigin,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// attestationObject wraps authenticator data the way a registration does.
func (a *authenticator) attestationObject(flags byte) []byte {
	ad := a.authData(flags, true)
	var b []byte
	b = append(b, 0xa3) // map of 3
	b = append(b, encText("fmt")...)
	b = append(b, encText("none")...)
	b = append(b, encText("attStmt")...)
	b = append(b, 0xa0) // empty map
	b = append(b, encText("authData")...)
	b = append(b, encBytes(ad)...)
	return b
}

// assert signs an assertion over the given client data.
func (a *authenticator) assert(t *testing.T, flags byte, cd []byte) (ad, sig []byte) {
	t.Helper()
	ad = a.authData(flags, false)
	sum := sha256.Sum256(cd)
	signed := append(append([]byte{}, ad...), sum[:]...)
	digest := sha256.Sum256(signed)
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return ad, sig
}

func policy() *Policy {
	return &Policy{RPID: "example.test", Origins: []string{"https://example.test"}}
}

// A registration produces a credential, and an assertion with the key it
// produced verifies. Both halves are needed: a verifier that accepts
// nothing passes every negative test.
func TestARegisteredKeyAuthenticates(t *testing.T) {
	p := policy()
	a := newAuthenticator(t, p.RPID)
	challenge := []byte("0123456789abcdef0123456789abcdef")
	reg, err := p.Register(a.attestationObject(flagUserPresent|flagUserVerified),
		clientDataJSON(t, "webauthn.create", "https://example.test", challenge, false), challenge)
	if err != nil {
		t.Fatalf("registration: %v", err)
	}
	if string(reg.CredentialID) != string(a.id) {
		t.Fatal("the credential identifier is not the authenticator's")
	}
	if !reg.UserVerified {
		t.Error("user verification was not recorded")
	}
	cred := Credential{User: "alice", ID: reg.CredentialID, PublicKey: reg.PublicKey, SignCount: reg.SignCount}

	a.count = 2
	cd := clientDataJSON(t, "webauthn.get", "https://example.test", challenge, false)
	ad, sig := a.assert(t, flagUserPresent, cd)
	count, err := p.Assertion(cred, ad, cd, sig, challenge)
	if err != nil {
		t.Fatalf("assertion: %v", err)
	}
	if count != 2 {
		t.Fatalf("sign count %d, want 2", count)
	}
}

// Each of these is a property the signature alone does not give. A verifier
// that skips any of them accepts an assertion made for something else.
func TestTheSignedContentsAreCheckedAndNotOnlyTheSignature(t *testing.T) {
	p := policy()
	a := newAuthenticator(t, p.RPID)
	challenge := []byte("0123456789abcdef0123456789abcdef")
	reg, err := p.Register(a.attestationObject(flagUserPresent),
		clientDataJSON(t, "webauthn.create", "https://example.test", challenge, false), challenge)
	if err != nil {
		t.Fatal(err)
	}
	cred := Credential{User: "alice", ID: reg.CredentialID, PublicKey: reg.PublicKey, SignCount: reg.SignCount}

	cases := []struct {
		name      string
		typ       string
		origin    string
		challenge []byte
		cross     bool
		flags     byte
		rpID      string
		wantErr   error
	}{
		{name: "a registration signature replayed as an authentication", typ: "webauthn.create", origin: "https://example.test", challenge: challenge, flags: flagUserPresent, wantErr: ErrCeremony},
		{name: "another challenge", typ: "webauthn.get", origin: "https://example.test", challenge: []byte("ffffffffffffffffffffffffffffffff"), flags: flagUserPresent, wantErr: ErrCeremony},
		{name: "a look-alike origin", typ: "webauthn.get", origin: "https://example.test.evil.test", challenge: challenge, flags: flagUserPresent, wantErr: ErrCeremony},
		{name: "the origin with a path on it", typ: "webauthn.get", origin: "https://example.test/login", challenge: challenge, flags: flagUserPresent, wantErr: ErrCeremony},
		{name: "plain http", typ: "webauthn.get", origin: "http://example.test", challenge: challenge, flags: flagUserPresent, wantErr: ErrCeremony},
		{name: "a cross-origin ceremony", typ: "webauthn.get", origin: "https://example.test", challenge: challenge, cross: true, flags: flagUserPresent, wantErr: ErrCeremony},
		{name: "nobody touched the key", typ: "webauthn.get", origin: "https://example.test", challenge: challenge, flags: 0, wantErr: ErrCeremony},
		{name: "another relying party", typ: "webauthn.get", origin: "https://example.test", challenge: challenge, flags: flagUserPresent, rpID: "other.test", wantErr: ErrCeremony},
	}
	for _, tc := range cases {
		b := a
		if tc.rpID != "" {
			// The same key, telling the truth about talking to somebody
			// else. The signature verifies and the ceremony does not.
			b = &authenticator{key: a.key, id: a.id, count: a.count, rpID: tc.rpID}
		}
		b.count++
		cd := clientDataJSON(t, tc.typ, tc.origin, tc.challenge, tc.cross)
		ad, sig := b.assert(t, tc.flags, cd)
		if _, err := p.Assertion(cred, ad, cd, sig, challenge); !errors.Is(err, tc.wantErr) {
			t.Errorf("%s: err %v, want %v", tc.name, err, tc.wantErr)
		}
	}
	// A signature over the right contents made by another key.
	other := newAuthenticator(t, p.RPID)
	other.id, other.count = a.id, a.count+10
	cd := clientDataJSON(t, "webauthn.get", "https://example.test", challenge, false)
	ad, sig := other.assert(t, flagUserPresent, cd)
	if _, err := p.Assertion(cred, ad, cd, sig, challenge); !errors.Is(err, ErrSignature) {
		t.Errorf("another key's signature: %v, want ErrSignature", err)
	}
	// And the right signature over tampered authenticator data.
	a.count++
	ad, sig = a.assert(t, flagUserPresent, cd)
	bad := append([]byte{}, ad...)
	bad[35] ^= 0xff // a byte of the sign count
	if _, err := p.Assertion(cred, bad, cd, sig, challenge); !errors.Is(err, ErrSignature) {
		t.Errorf("tampered authenticator data: %v, want ErrSignature", err)
	}
}

// User verification is the difference between "somebody touched the key"
// and "the person unlocked it". A policy that asks for it must not accept
// the weaker one.
func TestUserVerificationIsRequiredWhenAsked(t *testing.T) {
	p := policy()
	p.UserVerification = true
	a := newAuthenticator(t, p.RPID)
	challenge := []byte("0123456789abcdef0123456789abcdef")
	reg, err := p.Register(a.attestationObject(flagUserPresent|flagUserVerified),
		clientDataJSON(t, "webauthn.create", "https://example.test", challenge, false), challenge)
	if err != nil {
		t.Fatal(err)
	}
	cred := Credential{User: "alice", ID: reg.CredentialID, PublicKey: reg.PublicKey, SignCount: reg.SignCount}
	cd := clientDataJSON(t, "webauthn.get", "https://example.test", challenge, false)
	a.count++
	ad, sig := a.assert(t, flagUserPresent, cd)
	if _, err := p.Assertion(cred, ad, cd, sig, challenge); !errors.Is(err, ErrCeremony) {
		t.Fatalf("presence alone was accepted where verification was required: %v", err)
	}
	a.count++
	ad, sig = a.assert(t, flagUserPresent|flagUserVerified, cd)
	if _, err := p.Assertion(cred, ad, cd, sig, challenge); err != nil {
		t.Fatalf("a verified user was refused: %v", err)
	}
	// And a registration that was not verified is refused under the same
	// policy, so a key cannot be enrolled under the weaker rule and used
	// under the stronger one.
	b := newAuthenticator(t, p.RPID)
	if _, err := p.Register(b.attestationObject(flagUserPresent),
		clientDataJSON(t, "webauthn.create", "https://example.test", challenge, false), challenge); !errors.Is(err, ErrCeremony) {
		t.Fatalf("an unverified registration was accepted: %v", err)
	}
}

// A counting authenticator that counts backwards is what a cloned
// credential looks like. One that does not count at all reports zero
// forever, which the specification permits and must keep working.
func TestACountThatGoesBackwardsIsAClone(t *testing.T) {
	p := policy()
	a := newAuthenticator(t, p.RPID)
	challenge := []byte("0123456789abcdef0123456789abcdef")
	reg, _ := p.Register(a.attestationObject(flagUserPresent),
		clientDataJSON(t, "webauthn.create", "https://example.test", challenge, false), challenge)
	cred := Credential{User: "alice", ID: reg.CredentialID, PublicKey: reg.PublicKey, SignCount: 10}
	cd := clientDataJSON(t, "webauthn.get", "https://example.test", challenge, false)
	for _, count := range []uint32{5, 10} {
		a.count = count
		ad, sig := a.assert(t, flagUserPresent, cd)
		if _, err := p.Assertion(cred, ad, cd, sig, challenge); !errors.Is(err, ErrClone) {
			t.Errorf("count %d after 10: %v, want ErrClone", count, err)
		}
	}
	a.count = 11
	ad, sig := a.assert(t, flagUserPresent, cd)
	if got, err := p.Assertion(cred, ad, cd, sig, challenge); err != nil || got != 11 {
		t.Fatalf("a count that moved forward: %d %v", got, err)
	}
	// An authenticator that does not count: zero on both sides passes,
	// every time.
	zero := newAuthenticator(t, p.RPID)
	zero.count = 0
	zreg, err := p.Register(zero.attestationObject(flagUserPresent),
		clientDataJSON(t, "webauthn.create", "https://example.test", challenge, false), challenge)
	if err != nil {
		t.Fatal(err)
	}
	zcred := Credential{User: "alice", ID: zreg.CredentialID, PublicKey: zreg.PublicKey, SignCount: 0}
	for i := 0; i < 3; i++ {
		ad, sig := zero.assert(t, flagUserPresent, cd)
		if _, err := p.Assertion(zcred, ad, cd, sig, challenge); err != nil {
			t.Fatalf("a non-counting authenticator was refused: %v", err)
		}
	}
}

// The challenge is the replay protection, so it is spent once whether the
// ceremony worked or not, belongs to one account, and expires.
func TestAChallengeIsSpentOnceAndBelongsToOneAccount(t *testing.T) {
	c := NewChallenges(100, time.Minute)
	id, value, err := c.Issue("alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(value) != 32 {
		t.Fatalf("challenge is %d bytes, want 32", len(value))
	}
	if _, err := c.Spend(id, "bob"); !errors.Is(err, ErrChallenge) {
		t.Error("another account spent alice's challenge")
	}
	// The failed attempt still spent it, which is the point: a challenge
	// that survives a failure is a retry budget.
	if _, err := c.Spend(id, "alice"); !errors.Is(err, ErrChallenge) {
		t.Error("a challenge survived being spent by the wrong account")
	}
	id, value, _ = c.Issue("alice")
	got, err := c.Spend(id, "alice")
	if err != nil || string(got) != string(value) {
		t.Fatalf("spend: %v", err)
	}
	if _, err := c.Spend(id, "alice"); !errors.Is(err, ErrChallenge) {
		t.Error("a challenge was spent twice")
	}
	// Expiry, and an identifier nobody issued.
	now := time.Now()
	c.now = func() time.Time { return now }
	id, _, _ = c.Issue("alice")
	now = now.Add(2 * time.Minute)
	if _, err := c.Spend(id, "alice"); !errors.Is(err, ErrChallenge) {
		t.Error("an expired challenge was spent")
	}
	if _, err := c.Spend("deadbeef", "alice"); !errors.Is(err, ErrChallenge) {
		t.Error("an identifier nobody issued was spent")
	}
	// The table is bounded.
	small := NewChallenges(10, time.Minute)
	for i := 0; i < 50; i++ {
		if _, _, err := small.Issue("alice"); err != nil {
			t.Fatal(err)
		}
		if small.Len() > 10 {
			t.Fatalf("table grew to %d, want at most 10", small.Len())
		}
	}
}

// The CBOR reader runs on bytes from a browser and an authenticator. Every
// shape it refuses is one it would otherwise have to guess about.
func TestTheCBORReaderRefusesWhatItWillNotGuessAbout(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"a truncated head", []byte{0x18}},
		{"a truncated byte string", []byte{0x43, 0x01}},
		{"an indefinite length map", []byte{0xbf, 0x01, 0x01, 0xff}},
		{"an indefinite length array", []byte{0x9f, 0x01, 0xff}},
		{"a reserved additional information", []byte{0x1c}},
		{"a tag", []byte{0xc0, 0x01}},
		{"a float", []byte{0xfa, 0x00, 0x00, 0x00, 0x00}},
		{"a map key that is not a number or a string", []byte{0xa1, 0x81, 0x01, 0x01}},
		{"a duplicate map key", []byte{0xa2, 0x01, 0x01, 0x01, 0x02}},
		{"a map claiming more pairs than there are", []byte{0xa9, 0x01, 0x01}},
		{"an array claiming more items than there are", []byte{0x99, 0xff, 0xff, 0x01}},
		{"a byte string claiming two megabytes", []byte{0x5a, 0x00, 0x20, 0x00, 0x00}},
	} {
		if _, _, err := decodeCBOR(tc.in); err == nil {
			t.Errorf("%s was accepted", tc.name)
		}
	}
	// Nesting past the bound, built as a chain of one-item arrays.
	deep := make([]byte, 0, 64)
	for i := 0; i < 40; i++ {
		deep = append(deep, 0x81)
	}
	deep = append(deep, 0x01)
	if _, _, err := decodeCBOR(deep); err == nil {
		t.Error("a deeply nested document was accepted")
	}
	// And the shapes it must read: a small map, an array, both signs of
	// integer, a byte string and a text string.
	v, n, err := decodeCBOR([]byte{0xa2, 0x01, 0x20, 0x63, 0x61, 0x62, 0x63, 0x42, 0x01, 0x02})
	if err != nil || n != 10 {
		t.Fatalf("a valid map: %v (%d bytes)", err, n)
	}
	m, ok := cborMap(v)
	if !ok || len(m) != 2 {
		t.Fatalf("decoded %#v", v)
	}
	if got, _ := cborInt(m[numKey(1)]); got != -1 {
		t.Errorf("negative integer decoded as %d", got)
	}
	if got, _ := cborBytes(m[textKey("abc")]); string(got) != "\x01\x02" {
		t.Errorf("byte string decoded as %x", got)
	}
}

// A credential key this proxy cannot verify with is refused where somebody
// is watching, not at a login weeks later.
func TestACOSEKeyIsCheckedBeforeItIsStored(t *testing.T) {
	a := newAuthenticator(t, "example.test")
	if _, err := parseCOSEKey(a.coseKey()); err != nil {
		t.Fatalf("a valid key was refused: %v", err)
	}
	// An Ed25519 key, which is the other shape a browser may produce.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var okp []byte
	okp = append(okp, 0xa4)
	okp = append(okp, encInt(coseKty)...)
	okp = append(okp, encInt(ktyOKP)...)
	okp = append(okp, encInt(coseAlg)...)
	okp = append(okp, encInt(algEdDSA)...)
	okp = append(okp, encInt(coseCrv)...)
	okp = append(okp, encInt(6)...)
	okp = append(okp, encInt(coseXE)...)
	okp = append(okp, encBytes(pub)...)
	if _, err := parseCOSEKey(okp); err != nil {
		t.Fatalf("an Ed25519 key was refused: %v", err)
	}
	// The shapes that must not be stored.
	short := func(x, y []byte) []byte {
		var b []byte
		b = append(b, 0xa5)
		b = append(b, encInt(coseKty)...)
		b = append(b, encInt(ktyEC2)...)
		b = append(b, encInt(coseAlg)...)
		b = append(b, encInt(algES256)...)
		b = append(b, encInt(coseCrv)...)
		b = append(b, encInt(1)...)
		b = append(b, encInt(coseXE)...)
		b = append(b, encBytes(x)...)
		b = append(b, encInt(coseY)...)
		b = append(b, encBytes(y)...)
		return b
	}
	x := a.key.X.FillBytes(make([]byte, 32))
	y := a.key.Y.FillBytes(make([]byte, 32))
	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"not CBOR", []byte{0xff}},
		{"trailing bytes", append(a.coseKey(), 0x01)},
		{"a short x coordinate", short(x[1:], y)},
		{"a point off the curve", short(x, big.NewInt(1).FillBytes(make([]byte, 32)))},
		{"a symmetric key", []byte{0xa2, 0x01, 0x04, 0x03, 0x04}},
	} {
		if _, err := parseCOSEKey(tc.in); err == nil {
			t.Errorf("%s was accepted as a key", tc.name)
		}
	}
	// A P-256 key claiming ES512, which disagrees with itself about how
	// long a signature is.
	mismatched := short(x, y)
	mismatched[4] = 0x38 // rewrite alg to a one-byte negative
	mismatched[5] = 0x23 // -36, ES512
	if _, err := parseCOSEKey(mismatched); err == nil {
		t.Error("a P-256 key was accepted with ES512")
	}
}

// The store is the record. It round-trips, refuses what it cannot verify
// with, bounds a user's keys, and remembers a sign count across a reload,
// because a count a restart forgets is a clone check that passes.
func TestTheCredentialFileIsTheRecord(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "webauthn")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	a := newAuthenticator(t, "example.test")
	cred := Credential{User: "alice", ID: a.id, PublicKey: a.coseKey(), SignCount: 3, Label: "yubikey"}
	if err := s.Add(cred); err != nil {
		t.Fatal(err)
	}
	if !s.Enrolled("alice") || s.Enrolled("bob") {
		t.Fatal("enrolment")
	}
	// A credential identifier is public, so it must not be usable for
	// whatever account the request claims.
	if _, ok := s.ByID("bob", a.id); ok {
		t.Fatal("another account used alice's credential")
	}
	got, ok := s.ByID("alice", a.id)
	if !ok || got.SignCount != 3 || got.Label != "yubikey" {
		t.Fatalf("lookup: %+v %v", got, ok)
	}
	// The same authenticator twice would reset the count, which is the
	// clone check thrown away.
	if err := s.Add(cred); err == nil {
		t.Error("the same credential was registered twice")
	}
	// The count survives a reload.
	if err := s.Touch(a.id, 9); err != nil {
		t.Fatal(err)
	}
	again, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := again.ByID("alice", a.id); got.SignCount != 9 {
		t.Fatalf("sign count after a reload: %d, want 9", got.SignCount)
	}
	// The file is readable and the mode is not world readable: it is not a
	// secret, but it is an account list.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", info.Mode().Perm())
	}
	// Removal, of one key and of a user.
	b := newAuthenticator(t, "example.test")
	if err := s.Add(Credential{User: "alice", ID: b.id, PublicKey: b.coseKey()}); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove("bob", b.id); err == nil {
		t.Error("another account removed alice's key")
	}
	if err := s.Remove("alice", b.id); err != nil {
		t.Fatal(err)
	}
	if len(s.Credentials("alice")) != 1 {
		t.Fatalf("%d credentials after removing one", len(s.Credentials("alice")))
	}
	if err := s.RemoveUser("alice"); err != nil {
		t.Fatal(err)
	}
	if s.Enrolled("alice") {
		t.Error("the user is still enrolled")
	}
	// A user cannot register more keys than the bound.
	for i := 0; i < maxCredentialsPerUser; i++ {
		k := newAuthenticator(t, "example.test")
		if err := s.Add(Credential{User: "carol", ID: k.id, PublicKey: k.coseKey()}); err != nil {
			t.Fatalf("credential %d: %v", i, err)
		}
	}
	k := newAuthenticator(t, "example.test")
	if err := s.Add(Credential{User: "carol", ID: k.id, PublicKey: k.coseKey()}); !errors.Is(err, errTooMany) {
		t.Errorf("past the bound: %v", err)
	}
}

// A line that does not parse fails the read: a credential meant to be
// there and silently not locks somebody out, and one meant to be removed
// and still there is worse.
func TestABadCredentialLineFailsTheRead(t *testing.T) {
	a := newAuthenticator(t, "example.test")
	id := base64.RawURLEncoding.EncodeToString(a.id)
	key := base64.RawURLEncoding.EncodeToString(a.coseKey())
	good := "alice:" + id + ":" + key + ":3"
	for _, tc := range []struct{ name, line string }{
		{"too few fields", "alice:" + id + ":" + key},
		{"too many fields", good + ":label:extra"},
		{"no user", ":" + id + ":" + key + ":3"},
		{"a credential id that is not base64url", "alice:!!!:" + key + ":3"},
		{"an empty credential id", "alice::" + key + ":3"},
		{"a key that is not a COSE key", "alice:" + id + ":" + base64.RawURLEncoding.EncodeToString([]byte{0xff}) + ":3"},
		{"a sign count that is not a number", "alice:" + id + ":" + key + ":many"},
		{"a sign count past 32 bits", "alice:" + id + ":" + key + ":4294967296"},
		{"a label with a colon in it", good + ":a:b"},
	} {
		dir := t.TempDir()
		path := filepath.Join(dir, "webauthn")
		if err := os.WriteFile(path, []byte(tc.line+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Errorf("%s was accepted", tc.name)
		}
	}
	// And the good line loads, with comments and blank lines around it.
	dir := t.TempDir()
	path := filepath.Join(dir, "webauthn")
	if err := os.WriteFile(path, []byte("# a comment\n\n"+good+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Load(path)
	if err != nil {
		t.Fatalf("a valid file was refused: %v", err)
	}
	if !s.Enrolled("alice") {
		t.Error("the credential did not load")
	}
	// A duplicate credential in the file is two accounts able to use one
	// key, or one account's count being read from two places.
	if err := os.WriteFile(path, []byte(good+"\n"+strings.Replace(good, "alice", "bob", 1)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("a duplicate credential was accepted")
	}
}

// Authenticator data is attacker-controlled in the shape that matters: the
// lengths inside it.
func TestAuthenticatorDataLengthsAreNotTrusted(t *testing.T) {
	a := newAuthenticator(t, "example.test")
	full := a.authData(flagUserPresent, true)
	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"shorter than the fixed part", full[:30]},
		{"attested with nothing after the flag", full[:37]},
		{"attested with a truncated identifier", full[:40]},
		{"a credential id length past the buffer", withIDLen(full, 4000)},
		{"a credential id length of zero", withIDLen(full, 0)},
		{"trailing bytes with no extensions flag", append(append([]byte{}, full...), 0x00)},
	} {
		if _, err := parseAuthData(tc.in); err == nil {
			t.Errorf("%s was accepted", tc.name)
		}
	}
	if _, err := parseAuthData(full); err != nil {
		t.Fatalf("valid authenticator data was refused: %v", err)
	}
}

// withIDLen rewrites the credential identifier length field.
func withIDLen(ad []byte, n uint16) []byte {
	out := append([]byte{}, ad...)
	binary.BigEndian.PutUint16(out[53:55], n)
	return out
}

// A registration that carries no credential, or an attestation object of
// the wrong shape, is refused rather than stored as something empty.
func TestARegistrationMustCarryACredential(t *testing.T) {
	p := policy()
	a := newAuthenticator(t, p.RPID)
	challenge := []byte("0123456789abcdef0123456789abcdef")
	cd := clientDataJSON(t, "webauthn.create", "https://example.test", challenge, false)
	// Authenticator data with no attested credential in it.
	bare := a.authData(flagUserPresent, false)
	var obj []byte
	obj = append(obj, 0xa3)
	obj = append(obj, encText("fmt")...)
	obj = append(obj, encText("none")...)
	obj = append(obj, encText("attStmt")...)
	obj = append(obj, 0xa0)
	obj = append(obj, encText("authData")...)
	obj = append(obj, encBytes(bare)...)
	if _, err := p.Register(obj, cd, challenge); !errors.Is(err, ErrCeremony) {
		t.Errorf("a registration with no credential: %v", err)
	}
	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"not CBOR", []byte{0xff}},
		{"not a map", []byte{0x01}},
		{"no fmt", mapOf(encText("authData"), encBytes(a.authData(flagUserPresent, true)))},
		{"no authData", mapOf(encText("fmt"), encText("none"))},
		{"trailing bytes", append(a.attestationObject(flagUserPresent), 0x00)},
	} {
		if _, err := p.Register(tc.in, cd, challenge); err == nil {
			t.Errorf("%s was accepted", tc.name)
		}
	}
}

// mapOf builds a one-pair CBOR map.
func mapOf(k, v []byte) []byte {
	out := []byte{0xa1}
	out = append(out, k...)
	return append(out, v...)
}
