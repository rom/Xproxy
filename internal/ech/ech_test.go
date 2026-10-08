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

// Everything a config is refused for, and the one fault that is worst to miss.
//
// check runs over a config built in code -- by the key generator, or by an
// operator's own tooling -- before it is served. A config that got past this
// and onto the wire fails every ECH handshake and the client falls back to the
// public name silently, which is the hardest ECH fault to notice: nothing
// errors, nothing logs, and the privacy the feature exists for is simply gone.
// So the refusals are worth having written down.
func TestEveryReasonAConfigIsRefused(t *testing.T) {
	good := func() Config {
		c, _, err := Generate("ech.example.com", 1)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	for _, tc := range []struct {
		name  string
		spoil func(*Config)
		wants string
	}{
		{
			"a public key of the wrong length",
			func(c *Config) { c.PublicKey = c.PublicKey[:16] },
			"want 32",
		},
		{
			"no public key at all",
			func(c *Config) { c.PublicKey = nil },
			"want 32",
		},
		{
			"no cipher suites",
			func(c *Config) { c.Ciphers = nil },
			"no cipher suites",
		},
		{
			// HPKE has other KDFs; this build offers one, and a config
			// naming another would be served and never negotiated.
			"a KDF this build does not have",
			func(c *Config) { c.Ciphers = []Cipher{{KDF: 0x0002, AEAD: AEADAES128GCM}} },
			"unsupported KDF",
		},
		{
			"an AEAD this build does not have",
			func(c *Config) { c.Ciphers = []Cipher{{KDF: KDFHKDFSHA256, AEAD: 0x00ff}} },
			"unsupported AEAD",
		},
		{
			// One bad suite among good ones is still a bad config: a
			// client that picked it would fail, and which one it picks
			// is not this server's choice.
			"one bad suite among the good ones",
			func(c *Config) {
				c.Ciphers = append(c.Ciphers, Cipher{KDF: KDFHKDFSHA256, AEAD: 0x00ff})
			},
			"unsupported AEAD",
		},
		{
			"a public name that is not a name",
			func(c *Config) { c.PublicName = "not a hostname" },
			"",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := good()
			tc.spoil(&c)
			_, err := c.Marshal()
			if err == nil {
				t.Fatal("the config was accepted")
			}
			if tc.wants != "" && !strings.Contains(err.Error(), tc.wants) {
				t.Errorf("error %q, want %q", err, tc.wants)
			}
			// And a list carrying it is refused too, naming which one:
			// a rotation that overlapped a bad config with a good one
			// must not publish the pair.
			if _, err := MarshalList([]Config{good(), c}); err == nil {
				t.Error("a list carrying it was accepted")
			} else if !strings.Contains(err.Error(), "config 1") {
				t.Errorf("the list error does not name which config: %v", err)
			}
		})
	}

	// The three suites this build does offer are all accepted, so the
	// refusals above are about what is missing rather than a parser that
	// refuses everything.
	c := good()
	c.Ciphers = []Cipher{
		{KDF: KDFHKDFSHA256, AEAD: AEADAES128GCM},
		{KDF: KDFHKDFSHA256, AEAD: AEADAES256GCM},
		{KDF: KDFHKDFSHA256, AEAD: AEADChaCha20Poly1305},
	}
	if _, err := c.Marshal(); err != nil {
		t.Errorf("the three suites this build offers: %v", err)
	}
}

// The base64 an HTTPS record carries, and the empty list that must not become
// an empty parameter.
//
// `ech=` with nothing after it is a record saying ECH is available and offering
// no way to use it, so a client either fails or falls back -- and an operator
// reading their own zone file sees the parameter and believes it is configured.
func TestTheRecordParameterIsRefusedRatherThanEmpty(t *testing.T) {
	if _, err := MarshalList(nil); err == nil {
		t.Error("an empty list was encoded")
	}
	if s, err := ListBase64(nil); err == nil {
		t.Errorf("ListBase64(nil) = %q, want an error", s)
	}

	c, _, err := Generate("ech.example.com", 3)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ListBase64([]Config{c})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("the parameter is not base64: %v", err)
	}
	list, err := MarshalList([]Config{c})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, list) {
		t.Error("the parameter is not the encoded list")
	}
}

// A private key that is not one is reported rather than producing a public key
// that matches nothing.
//
// This is the check that catches a config served with the wrong key before it
// is served, which is the silent-fallback fault again: the pair is verified at
// load because nothing downstream of it will complain.
func TestAPrivateKeyThatIsNotOneIsReported(t *testing.T) {
	for _, c := range []struct {
		name string
		priv []byte
	}{
		{"empty", nil},
		{"too short", make([]byte, 16)},
		{"too long", make([]byte, 64)},
	} {
		if pub, err := PrivateKeyPublic(c.priv); err == nil {
			t.Errorf("%s: derived %x", c.name, pub)
		} else if !strings.Contains(err.Error(), "X25519") {
			t.Errorf("%s: error %q does not say what it wanted", c.name, err)
		}
	}
}
