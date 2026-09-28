package snmp

import (
	"bytes"
	"testing"
)

// buildOne originates a message at a level, with keys derived the way a real
// originator derives them.
func buildOne(t *testing.T, level SecurityLevel, a AuthAlgo, p PrivAlgo, engine []byte) ([]byte, []byte, []byte) {
	t.Helper()
	scoped, err := ScopedPDU(engine, "", requestPDU(t, GetRequest, 42, "1.3.6.1.2.1.1.1.0"))
	if err != nil {
		t.Fatal(err)
	}
	authKey := PasswordToKey(a, "the authentication pass phrase", engine)
	privKey := PasswordToKey(a, "the privacy pass phrase", engine)
	out, err := BuildV3(V3Build{
		MessageID: 7, MaxSize: 65507, Reportable: true, Level: level,
		EngineID: engine, User: "relay", EngineBoots: 11, EngineTime: 2222,
		Scoped: scoped, Auth: a, AuthKey: authKey, Priv: p, PrivKey: privKey,
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return out, authKey, privKey
}

// What is built parses, verifies and decrypts.
//
// This is the assertion worth having: Verify and Decrypt were written for
// messages other implementations send, so a message that satisfies them is a
// message a real agent accepts -- and the two halves cannot agree by sharing a
// mistake, because they do not share any code.
func TestABuiltMessageVerifiesAndDecrypts(t *testing.T) {
	engine := []byte{0x80, 0x00, 0x1f, 0x88, 0x80, 0x01, 0x02, 0x03, 0x04}
	for _, a := range AuthAlgos {
		for _, p := range PrivAlgos {
			// Only the pairs a configuration can hold. A privacy key is
			// localised with the *authentication* hash, so MD5 cannot fill an
			// AES-256 key and validation refuses that pair; a build refusing it
			// too is the same rule in the same words rather than a silent
			// downgrade to a key padded with something.
			if a.KeyLen() < p.KeyLen() {
				continue
			}
			t.Run(string(a)+"/"+string(p), func(t *testing.T) {
				raw, authKey, privKey := buildOne(t, AuthPriv, a, p, engine)
				m, err := Parse(raw)
				if err != nil {
					t.Fatalf("parse: %v", err)
				}
				if m.Version != V3 || m.V3 == nil {
					t.Fatalf("version %v header %v", m.Version, m.V3)
				}
				if m.V3.Level != AuthPriv || !m.V3.ScopedPDUEncrypted {
					t.Fatalf("level %v encrypted %t", m.V3.Level, m.V3.ScopedPDUEncrypted)
				}
				if m.V3.User != "relay" || !bytes.Equal(m.V3.EngineID, engine) {
					t.Fatalf("user %q engine %x", m.V3.User, m.V3.EngineID)
				}
				if m.V3.EngineBoots != 11 || m.V3.EngineTime != 2222 {
					t.Fatalf("clock %d/%d", m.V3.EngineBoots, m.V3.EngineTime)
				}
				if err := Verify(m, authKey, a); err != nil {
					t.Fatalf("verify: %v", err)
				}
				plain, err := Decrypt(m, privKey, p)
				if err != nil {
					t.Fatalf("decrypt: %v", err)
				}
				s, err := ParseScoped(plain)
				if err != nil {
					t.Fatalf("scoped: %v", err)
				}
				if s.PDU == nil || s.PDU.Type != GetRequest || s.PDU.RequestID != 42 {
					t.Fatalf("the PDU did not survive: %+v", s.PDU)
				}
			})
		}
	}
}

// authNoPriv signs and leaves the scoped PDU readable, so the ordinary parse
// reaches the PDU with no key at all.
func TestAnAuthNoPrivMessageIsSignedAndReadable(t *testing.T) {
	engine := []byte{0x80, 0x00, 0x1f, 0x88, 0x09}
	raw, authKey, _ := buildOne(t, AuthNoPriv, AuthSHA256, PrivAES128, engine)
	m, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if m.V3.Level != AuthNoPriv || m.V3.ScopedPDUEncrypted {
		t.Fatalf("level %v encrypted %t", m.V3.Level, m.V3.ScopedPDUEncrypted)
	}
	if m.PDU == nil || m.PDU.RequestID != 42 {
		t.Fatalf("the PDU is not readable: %+v", m.PDU)
	}
	if err := Verify(m, authKey, AuthSHA256); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// noAuthNoPriv carries no digest and no salt.
func TestANoAuthNoPrivMessageCarriesNoDigest(t *testing.T) {
	engine := []byte{0x80, 0x00, 0x1f, 0x88, 0x09}
	scoped, err := ScopedPDU(engine, "", requestPDU(t, GetRequest, 3, "1.3.6.1.2.1.1.5.0"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := BuildV3(V3Build{MessageID: 1, MaxSize: 65507, Level: NoAuthNoPriv,
		EngineID: engine, User: "discover", Scoped: scoped})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	m, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if m.V3.Level != NoAuthNoPriv {
		t.Fatalf("level %v", m.V3.Level)
	}
	if len(m.V3.AuthParams) != 0 || len(m.V3.PrivParams) != 0 {
		t.Fatalf("digest %x salt %x", m.V3.AuthParams, m.V3.PrivParams)
	}
	if m.PDU == nil || m.PDU.RequestID != 3 {
		t.Fatalf("the PDU is not readable: %+v", m.PDU)
	}
}

// The digest covers the whole message, so any octet changed in flight breaks it.
// That is the assertion that the offset arithmetic is right: a digest computed
// over the wrong span would still verify against itself and would not notice a
// change outside that span.
func TestTheDigestCoversEveryOctet(t *testing.T) {
	engine := []byte{0x80, 0x00, 0x1f, 0x88, 0x77}
	raw, authKey, _ := buildOne(t, AuthNoPriv, AuthSHA1, PrivAES128, engine)
	m, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(m, authKey, AuthSHA1); err != nil {
		t.Fatalf("the message does not verify to begin with: %v", err)
	}
	for i := range raw {
		// The digest field itself is excluded: it is zeroed before the
		// computation, so changing it is what Verify compares rather than
		// what it covers.
		if i >= m.V3.AuthParamsAt && i < m.V3.AuthParamsAt+len(m.V3.AuthParams) {
			continue
		}
		tampered := make([]byte, len(raw))
		copy(tampered, raw)
		tampered[i] ^= 0x01
		tm, err := Parse(tampered)
		if err != nil {
			continue // a length or a tag: refused before the digest is reached
		}
		if tm.V3 == nil {
			continue
		}
		if err := Verify(tm, authKey, AuthSHA1); err == nil {
			t.Fatalf("octet %d changed and the digest still verified", i)
		}
	}
}

// A fresh salt every time, so two identical requests are two different
// ciphertexts. A fixed salt with a fixed key and a fixed clock is a keystream
// reused, which on a stream cipher gives away the exclusive-or of two
// plaintexts.
func TestTheSaltIsFreshEachTime(t *testing.T) {
	engine := []byte{0x80, 0x00, 0x1f, 0x88, 0x55}
	first, _, _ := buildOne(t, AuthPriv, AuthSHA256, PrivAES128, engine)
	second, _, _ := buildOne(t, AuthPriv, AuthSHA256, PrivAES128, engine)
	if bytes.Equal(first, second) {
		t.Fatal("two builds of the same request produced the same octets")
	}
	a, err := Parse(first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse(second)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.V3.PrivParams, b.V3.PrivParams) {
		t.Fatalf("the salt was reused: %x", a.V3.PrivParams)
	}
	if bytes.Equal(a.V3.Ciphertext, b.V3.Ciphertext) {
		t.Fatal("the same plaintext encrypted to the same ciphertext")
	}
}

// A build whose level asks for more than its keys can give is refused rather
// than quietly downgraded. A message sent at a lower level than the operator
// configured is the failure nobody notices.
func TestABuildIsRefusedRatherThanDowngraded(t *testing.T) {
	engine := []byte{0x80, 0x00, 0x1f, 0x88, 0x01}
	scoped, err := ScopedPDU(engine, "", requestPDU(t, GetRequest, 1, "1.3.6.1.2.1.1.1.0"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		b    V3Build
	}{
		{"authNoPriv with no algorithm", V3Build{Level: AuthNoPriv, Scoped: scoped, EngineID: engine}},
		{"authNoPriv with a short key", V3Build{Level: AuthNoPriv, Scoped: scoped, EngineID: engine,
			Auth: AuthSHA256, AuthKey: []byte("short")}},
		{"authPriv with no privacy key", V3Build{Level: AuthPriv, Scoped: scoped, EngineID: engine,
			Auth: AuthSHA256, AuthKey: PasswordToKey(AuthSHA256, "phrase", engine), Priv: PrivAES128}},
		{"no scoped PDU", V3Build{Level: NoAuthNoPriv, EngineID: engine}},
		{"a salt of the wrong length", V3Build{Level: AuthPriv, Scoped: scoped, EngineID: engine,
			Auth: AuthSHA256, AuthKey: PasswordToKey(AuthSHA256, "phrase", engine),
			Priv: PrivAES128, PrivKey: PasswordToKey(AuthSHA256, "phrase", engine), Salt: []byte{1, 2, 3}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := BuildV3(c.b); err == nil {
				t.Fatal("the build was accepted")
			}
		})
	}
}

// A DES message is padded to the block size and decrypts to a scoped PDU whose
// BER length says where it ends, whatever follows it.
func TestADESMessagePadsToTheBlock(t *testing.T) {
	engine := []byte{0x80, 0x00, 0x1f, 0x88, 0x0d}
	raw, _, privKey := buildOne(t, AuthPriv, AuthSHA1, PrivDES, engine)
	m, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.V3.Ciphertext)%8 != 0 {
		t.Fatalf("the ciphertext is %d octets, not a whole number of blocks", len(m.V3.Ciphertext))
	}
	plain, err := Decrypt(m, privKey, PrivDES)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	s, err := ParseScoped(plain)
	if err != nil {
		t.Fatalf("scoped: %v", err)
	}
	if s.PDU == nil || s.PDU.RequestID != 42 {
		t.Fatalf("the PDU did not survive the padding: %+v", s.PDU)
	}
}
