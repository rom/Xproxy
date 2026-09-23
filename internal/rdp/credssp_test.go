package rdp

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/ntlm"
)

// A message round-trips through the encoding the protocol uses, with
// the optional fields that are absent staying absent.
func TestTSRequestRoundTrip(t *testing.T) {
	want := tsRequest{
		Version:     6,
		NegoTokens:  []negoToken{{Token: []byte("NTLMSSP\x00token")}},
		PubKeyAuth:  bytes.Repeat([]byte{0xAB}, 48),
		ClientNonce: bytes.Repeat([]byte{0xCD}, credSSPNonceBytes),
	}
	var buf bytes.Buffer
	if err := writeTSRequest(&buf, want); err != nil {
		t.Fatal(err)
	}
	got, err := readTSRequest(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 6 || len(got.NegoTokens) != 1 ||
		string(got.NegoTokens[0].Token) != string(want.NegoTokens[0].Token) {
		t.Fatalf("read %+v", got)
	}
	if !bytes.Equal(got.PubKeyAuth, want.PubKeyAuth) || !bytes.Equal(got.ClientNonce, want.ClientNonce) {
		t.Error("the sealed fields did not survive")
	}
	if got.AuthInfo != nil || got.ErrorCode != 0 {
		t.Errorf("fields that were not sent came back: %+v", got)
	}
}

// A long message still round-trips, which is what exercises the
// multi-byte length the reader has to handle.
func TestALongTSRequestRoundTrips(t *testing.T) {
	want := tsRequest{Version: 6, AuthInfo: bytes.Repeat([]byte{0x5A}, 4000)}
	var buf bytes.Buffer
	if err := writeTSRequest(&buf, want); err != nil {
		t.Fatal(err)
	}
	got, err := readTSRequest(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.AuthInfo, want.AuthInfo) {
		t.Errorf("read %d bytes of credential, want %d", len(got.AuthInfo), len(want.AuthInfo))
	}
}

// A length a peer chose is checked before anything is allocated for
// it, and a message that stops early is a short read rather than a
// parse of whatever arrived.
func TestTSRequestLengthsAreChecked(t *testing.T) {
	// A length of a length that cannot be right.
	if _, err := readTSRequest(bytes.NewReader([]byte{0x30, 0x88, 1, 2, 3})); !errors.Is(err, ErrCredSSP) {
		t.Error("a silly length of a length was accepted")
	}
	// An indefinite length, which DER does not have.
	if _, err := readTSRequest(bytes.NewReader([]byte{0x30, 0x80, 1, 2})); !errors.Is(err, ErrCredSSP) {
		t.Error("an indefinite length was accepted")
	}
	// A message over the bound, refused before the body is read.
	if _, err := readTSRequest(bytes.NewReader([]byte{0x30, 0x83, 0xFF, 0xFF, 0xFF})); !errors.Is(err, ErrCredSSP) {
		t.Error("an oversize message was accepted")
	}
	// A body that never arrives.
	if _, err := readTSRequest(bytes.NewReader([]byte{0x30, 0x20, 1, 2})); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("a truncated message: %v", err)
	}
	// Something that is not a message at all.
	if _, err := readTSRequest(bytes.NewReader([]byte{0x30, 0x02, 0xFF, 0xFF})); !errors.Is(err, ErrCredSSP) {
		t.Error("bytes that are not a message were accepted")
	}
}

// The credential is rendered the way the protocol carries it, with its
// text in the encoding Windows expects.
func TestCredentialsAreEncodedForWindows(t *testing.T) {
	b, err := encodeCredentials(credential("LAB", "svc", "s3cret"))
	if err != nil {
		t.Fatal(err)
	}
	var outer tsCredentials
	if _, err := asn1.Unmarshal(b, &outer); err != nil {
		t.Fatal(err)
	}
	if outer.CredType != 1 {
		t.Errorf("credential type %d, want 1", outer.CredType)
	}
	var inner tsPasswordCreds
	if _, err := asn1.Unmarshal(outer.Credentials, &inner); err != nil {
		t.Fatal(err)
	}
	if string(inner.Domain) != string(utf16Bytes("LAB")) ||
		string(inner.User) != string(utf16Bytes("svc")) ||
		string(inner.Password) != string(utf16Bytes("s3cret")) {
		t.Errorf("read %q %q %q", inner.Domain, inner.User, inner.Password)
	}
	// The password is not in the message in a form a grep would find.
	if bytes.Contains(b, []byte("s3cret")) {
		t.Error("the password is in the message as plain bytes")
	}
}

// The binding ties the exchange to one tunnel: from version five it is
// a hash over a nonce and the key, and the two directions differ.
func TestTheBindingIsPerConnectionAndPerDirection(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 270)
	nonce := bytes.Repeat([]byte{2}, credSSPNonceBytes)
	client := bindingValue(6, clientToServerBinding, nonce, key)
	server := bindingValue(6, serverToClientBinding, nonce, key)
	if bytes.Equal(client, server) {
		t.Error("the two directions bind to the same value")
	}
	if len(client) != sha256.Size {
		t.Errorf("the binding is %d bytes", len(client))
	}
	// Another nonce is another binding, which is what stops the tokens
	// being replayed into a different tunnel.
	other := bindingValue(6, clientToServerBinding, bytes.Repeat([]byte{3}, credSSPNonceBytes), key)
	if bytes.Equal(client, other) {
		t.Error("two connections bind to the same value")
	}
	// And another key is another binding, which is what stops them
	// being relayed into someone else's.
	elsewhere := bindingValue(6, clientToServerBinding, nonce, bytes.Repeat([]byte{9}, 270))
	if bytes.Equal(client, elsewhere) {
		t.Error("two servers bind to the same value")
	}
	// Before version five the key itself is the value, which is the
	// arrangement that allowed the relay.
	if old := bindingValue(4, clientToServerBinding, nonce, key); !bytes.Equal(old, key) {
		t.Error("the older binding is not the key itself")
	}
}

// A desktop that answers with the wrong binding is one the credential
// does not go to.
func TestAWrongBindingStopsTheExchange(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 270)
	nonce := bytes.Repeat([]byte{2}, credSSPNonceBytes)
	s, peer := sessionPair(t)

	// What a correct desktop would send.
	sealed, sig := peer.Seal(bindingValue(6, serverToClientBinding, nonce, key))
	if err := checkBinding(s, append(append([]byte(nil), sig...), sealed...), 6, nonce, key); err != nil {
		t.Fatalf("a correct binding was refused: %v", err)
	}

	// One over another key.
	s2, peer2 := sessionPair(t)
	sealed, sig = peer2.Seal(bindingValue(6, serverToClientBinding, nonce, bytes.Repeat([]byte{9}, 270)))
	if err := checkBinding(s2, append(append([]byte(nil), sig...), sealed...), 6, nonce, key); !errors.Is(err, ErrCredSSP) {
		t.Errorf("a binding over another key was accepted (%v)", err)
	}

	// And nothing at all.
	s3, _ := sessionPair(t)
	if err := checkBinding(s3, nil, 6, nonce, key); !errors.Is(err, ErrCredSSP) {
		t.Error("a missing binding was accepted")
	}
	if err := checkBinding(s3, bytes.Repeat([]byte{0}, 8), 6, nonce, key); !errors.Is(err, ErrCredSSP) {
		t.Error("a binding shorter than a signature was accepted")
	}
}

// sessionPair builds the two ends' views of one session, so a test
// can seal at one and open at the other.
func sessionPair(t *testing.T) (client, server *ntlm.Session) {
	t.Helper()
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	c, err := ntlm.NewSession(key, ntlm.RoleClient)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ntlm.NewSession(key, ntlm.RoleServer)
	if err != nil {
		t.Fatal(err)
	}
	return c, s
}

func credential(domain, user, password string) ntlm.Credential {
	return ntlm.Credential{Domain: domain, User: user, Password: password}
}

func TestUTF16Fields(t *testing.T) {
	if got := utf16Bytes("AB"); !bytes.Equal(got, []byte{'A', 0, 'B', 0}) {
		t.Errorf("AB rendered as %x", got)
	}
	if got := utf16Bytes(""); len(got) != 0 {
		t.Errorf("an empty field is %d bytes", len(got))
	}
	if got := utf16Bytes(strings.Repeat("é", 2)); len(got) != 4 {
		t.Errorf("two non-ASCII characters are %d bytes", len(got))
	}
}
