package ech

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"strings"
	"testing"
)

// TestRoundTrip proves the encoder and the decoder agree, which is the
// least a wire format owes.
func TestRoundTrip(t *testing.T) {
	c, priv, err := Generate("ech.example.com", 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(priv) != 32 || len(c.PublicKey) != 32 {
		t.Fatalf("key sizes: priv %d pub %d", len(priv), len(c.PublicKey))
	}
	pub, err := PrivateKeyPublic(priv)
	if err != nil || !bytes.Equal(pub, c.PublicKey) {
		t.Fatalf("the private key does not match the config: %v", err)
	}
	enc, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(enc)
	if err != nil {
		t.Fatal(err)
	}
	if back.ID != 7 || back.PublicName != "ech.example.com" ||
		!bytes.Equal(back.PublicKey, c.PublicKey) || len(back.Ciphers) != 3 ||
		back.MaxNameLength != DefaultMaxNameLength {
		t.Fatalf("round trip = %+v", back)
	}
}

// TestGoAcceptsOurConfig is the test that matters: crypto/tls has its
// own parser, and a config it refuses is a config no client can use.
func TestGoAcceptsOurConfig(t *testing.T) {
	c, priv, err := Generate("ech.example.com", 1)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	// Server side: the key is accepted and a handshake can be built.
	sc := &tls.Config{
		MinVersion:               tls.VersionTLS13,
		EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{{Config: enc, PrivateKey: priv, SendAsRetry: true}},
	}
	if len(sc.EncryptedClientHelloKeys) != 1 {
		t.Fatal("key not set")
	}
	// Client side: crypto/tls parses the list we would publish, and
	// reports a malformed one. This is Go's own parser, not ours.
	list, err := MarshalList([]Config{c})
	if err != nil {
		t.Fatal(err)
	}
	cc := &tls.Config{MinVersion: tls.VersionTLS13, EncryptedClientHelloConfigList: list, ServerName: "a.example.com"}
	if _, err := tls.Dial("tcp", "127.0.0.1:1", cc); err == nil {
		t.Fatal("dial to a closed port succeeded")
	} else if strings.Contains(err.Error(), "ECHConfig") || strings.Contains(err.Error(), "ech") {
		// A parse failure surfaces before the dial does.
		t.Fatalf("crypto/tls rejected our config list: %v", err)
	}
}

func TestListRoundTrip(t *testing.T) {
	a, _, err := Generate("ech.example.com", 1)
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := Generate("ech.example.com", 2)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := MarshalList([]Config{a, b})
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseList(enc)
	if err != nil {
		t.Fatal(err)
	}
	if len(back) != 2 || back[0].ID != 1 || back[1].ID != 2 {
		t.Fatalf("list round trip = %+v", back)
	}
	// The DNS form.
	s, err := ListBase64([]Config{a, b})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || !bytes.Equal(raw, enc) {
		t.Fatalf("base64 form does not match: %v", err)
	}
}

// TestMalformed: every truncation and every field a hostile record can
// lie about. A parser that reads DNS answers is reachable by anyone.
func TestMalformed(t *testing.T) {
	c, _, err := Generate("ech.example.com", 1)
	if err != nil {
		t.Fatal(err)
	}
	good, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	for i := range good {
		if _, err := Parse(good[:i]); err == nil {
			t.Errorf("a config truncated to %d bytes was accepted", i)
		}
	}
	if _, err := Parse(append(append([]byte(nil), good...), 0)); err == nil {
		t.Error("trailing bytes accepted")
	}
	// A version this build does not speak is named, not guessed at.
	other := append([]byte(nil), good...)
	other[0], other[1] = 0xfe, 0x0a
	if _, err := Parse(other); err == nil || !strings.Contains(err.Error(), "version") {
		t.Errorf("other version: %v", err)
	}
	// A length that does not describe the body.
	bad := append([]byte(nil), good...)
	bad[3]++
	if _, err := Parse(bad); err == nil {
		t.Error("wrong length accepted")
	}
	// A KEM nobody implements.
	kem := append([]byte(nil), good...)
	kem[5], kem[6] = 0x00, 0x10
	if _, err := Parse(kem); err == nil || !strings.Contains(err.Error(), "KEM") {
		t.Errorf("unsupported KEM: %v", err)
	}
	if _, err := Parse(nil); err == nil {
		t.Error("empty config accepted")
	}
	if _, err := ParseList(nil); err == nil {
		t.Error("empty list accepted")
	}
	if _, err := ParseList([]byte{0x00, 0x00}); err == nil {
		t.Error("a list of nothing accepted")
	}
	if _, err := Parse(make([]byte, maxConfigBytes+1)); err == nil {
		t.Error("an oversize config was parsed")
	}
}

// TestMandatoryExtension: a config carrying an extension a client must
// understand cannot be served by a build that does not implement it.
func TestMandatoryExtension(t *testing.T) {
	c, _, err := Generate("ech.example.com", 1)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	// Append a mandatory extension (high bit set) and fix the lengths.
	ext := []byte{0x80, 0x01, 0x00, 0x00}
	body := enc[4:]
	body = body[:len(body)-2]
	body = append(body, 0x00, byte(len(ext)))
	body = append(body, ext...)
	out := []byte{enc[0], enc[1], byte(len(body) >> 8), byte(len(body))}
	out = append(out, body...)
	if _, err := Parse(out); err == nil || !strings.Contains(err.Error(), "mandatory") {
		t.Errorf("mandatory extension: %v", err)
	}
}

func TestPublicNameRules(t *testing.T) {
	for _, bad := range []string{"", "localhost", ".example.com", "example.com.", "a..b.com",
		"*.example.com", "ech example.com", "ürl.example.com", strings.Repeat("a", 250) + ".example.com"} {
		if err := ValidPublicName(bad); err == nil {
			t.Errorf("public name %q accepted", bad)
		}
	}
	if err := ValidPublicName("ech.example.com"); err != nil {
		t.Errorf("a good name refused: %v", err)
	}
	if _, _, err := Generate("localhost", 1); err == nil {
		t.Error("Generate accepted a name with no dot")
	}
}
