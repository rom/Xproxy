package rfb

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// Both ends of the exchange arrive at the same secret, and the
// credential one seals is the credential the other opens.
func TestMSLogonExchangeAndCredential(t *testing.T) {
	params, serverPriv, err := NewMSLogonParams()
	if err != nil {
		t.Fatal(err)
	}
	clientPub, clientPriv, err := MSLogonPublic(params)
	if err != nil {
		t.Fatal(err)
	}
	clientShared, err := MSLogonShared(params.Pub, clientPriv, params.Mod)
	if err != nil {
		t.Fatal(err)
	}
	serverShared, err := MSLogonShared(clientPub, serverPriv, params.Mod)
	if err != nil {
		t.Fatal(err)
	}
	if clientShared != serverShared {
		t.Fatalf("the two ends derived %d and %d", clientShared, serverShared)
	}

	sealed, err := MSLogonSeal(clientShared, "LAB\\alice", "hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if len(sealed) != MSLogonCredentialSize {
		t.Fatalf("%d bytes, want %d", len(sealed), MSLogonCredentialSize)
	}
	// The credential is not on the wire in clear, weak as the key is.
	if bytes.Contains(sealed, []byte("alice")) || bytes.Contains(sealed, []byte("hunter2")) {
		t.Error("the credential went out unencrypted")
	}
	user, pass, err := MSLogonOpen(serverShared, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if user != "LAB\\alice" || pass != "hunter2" {
		t.Errorf("opened %q and %q", user, pass)
	}
}

// The two fields are chained separately, so the password does not
// depend on what the username happened to be.
func TestMSLogonFieldsAreChainedSeparately(t *testing.T) {
	const shared = 0x0123456789abcdef
	a, err := MSLogonSeal(shared, "alice", "same-password")
	if err != nil {
		t.Fatal(err)
	}
	b, err := MSLogonSeal(shared, "a-much-longer-name", "same-password")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a[MSLogonUserSize:], b[MSLogonUserSize:]) {
		t.Error("the password field changed with the username")
	}
	if bytes.Equal(a[:MSLogonUserSize], b[:MSLogonUserSize]) {
		t.Error("two different usernames sealed the same")
	}
}

// A credential that does not fit its field is refused rather than
// quietly cut in half.
func TestMSLogonRefusesAnOversizeCredential(t *testing.T) {
	if _, err := MSLogonSeal(42, strings.Repeat("a", MSLogonUserSize), "x"); err == nil {
		t.Error("an oversize username was accepted")
	}
	if _, err := MSLogonSeal(42, "alice", strings.Repeat("p", MSLogonPassSize)); err == nil {
		t.Error("an oversize password was accepted")
	}
	// One byte short of the field is fine: the field is NUL-padded.
	if _, err := MSLogonSeal(42, strings.Repeat("a", MSLogonUserSize-1), ""); err != nil {
		t.Errorf("a username that fits was refused: %v", err)
	}
}

// Parameters that fix the shared secret are refused. The type is weak
// by construction, but these make it no exchange at all.
func TestMSLogonRefusesDegenerateParameters(t *testing.T) {
	cases := []MSLogonParams{
		{Gen: 5, Mod: 0, Pub: 3},
		{Gen: 5, Mod: 1, Pub: 0},
		{Gen: 0, Mod: 97, Pub: 5},
		{Gen: 1, Mod: 97, Pub: 5},
		{Gen: 5, Mod: 97, Pub: 0},
		{Gen: 5, Mod: 97, Pub: 1},
		// A value at or above the modulus is not a residue.
		{Gen: 97, Mod: 97, Pub: 5},
		{Gen: 5, Mod: 97, Pub: 97},
	}
	for _, p := range cases {
		if _, err := ReadMSLogonParams(bytes.NewReader(p.Encode())); !errors.Is(err, ErrMSLogonParams) {
			t.Errorf("gen %d mod %d pub %d was accepted (%v)", p.Gen, p.Mod, p.Pub, err)
		}
	}
	// And a shared secret that comes out fixed is refused too.
	if _, err := MSLogonShared(1, 7, 97); !errors.Is(err, ErrMSLogonParams) {
		t.Errorf("a public value of 1 was accepted (%v)", err)
	}
}

func TestMSLogonParamsRoundTrip(t *testing.T) {
	want := MSLogonParams{Gen: 5, Mod: 0x7fffffffffffffc3, Pub: 0x1234567890abcdef}
	got, err := ReadMSLogonParams(bytes.NewReader(want.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("read %+v, want %+v", got, want)
	}
	if _, err := ReadMSLogonParams(bytes.NewReader(want.Encode()[:20])); err == nil {
		t.Error("a truncated parameter block was accepted")
	}
}
