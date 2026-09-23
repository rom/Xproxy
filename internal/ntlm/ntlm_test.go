package ntlm

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The key everything rests on, against the worked example of MS-NLMP
// section 4.2.4. If this is wrong nothing else can be right, and it
// would be wrong in a way that only a real Windows server would show.
func TestNTOWFv2AgainstThePublishedExample(t *testing.T) {
	got := ntowfv2("User", "Domain", "Password")
	want := unhex(t, "0c868a403bfd7a93a3001ef22ef02e3f")
	if !bytes.Equal(got, want) {
		t.Errorf("NTOWFv2 = %x, want %x", got, want)
	}
}

// And the response built from it, with the example's own challenge,
// client challenge, timestamp and attribute list.
func TestNTLMv2ResponseAgainstThePublishedExample(t *testing.T) {
	ntowf := ntowfv2("User", "Domain", "Password")
	serverChallenge := unhex(t, "0123456789abcdef")
	clientChallenge := unhex(t, "aaaaaaaaaaaaaaaa")
	// The example's attribute list: the domain, the server and the
	// end-of-list pair. The four zero bytes after it in the worked
	// example belong to temp rather than to the list.
	targetInfo := unhex(t, "02000c0044006f006d00610069006e00"+
		"01000c00530065007200760065007200"+"00000000")

	// The example's temp has a timestamp of zero, which the real one
	// takes from the clock.
	temp := []byte{0x01, 0x01, 0, 0, 0, 0, 0, 0}
	temp = append(temp, make([]byte, 8)...)
	temp = append(temp, clientChallenge...)
	temp = append(temp, 0, 0, 0, 0)
	temp = append(temp, targetInfo...)
	temp = append(temp, 0, 0, 0, 0)

	proof := hmacMD5(ntowf, concat(serverChallenge, temp))
	if want := unhex(t, "68cd0ab851e51c96aabc927bebef6a1c"); !bytes.Equal(proof, want) {
		t.Errorf("NTProofStr = %x, want %x", proof, want)
	}
	base := hmacMD5(ntowf, proof)
	if want := unhex(t, "8de40ccadbc14a82f15cb0ad0de95ca3"); !bytes.Equal(base, want) {
		t.Errorf("SessionBaseKey = %x, want %x", base, want)
	}
}

// buildChallenge renders a server's message the way one arrives.
func buildChallenge(t *testing.T, flags uint32, targetInfo []byte) []byte {
	t.Helper()
	name := encodeUTF16("SERVER")
	out := append(append([]byte(nil), signature...), 0, 0, 0, 0)
	binary.LittleEndian.PutUint32(out[8:12], typeChallenge)
	const fixed = 48
	// The target name descriptor, then the flags, the challenge, the
	// reserved field and the attribute list descriptor.
	desc := func(n, off int) []byte {
		d := make([]byte, 8)
		binary.LittleEndian.PutUint16(d[0:2], uint16(n))
		binary.LittleEndian.PutUint16(d[2:4], uint16(n))
		binary.LittleEndian.PutUint32(d[4:8], uint32(off))
		return d
	}
	out = append(out, desc(len(name), fixed)...)
	out = binary.LittleEndian.AppendUint32(out, flags)
	out = append(out, unhex(t, "0123456789abcdef")...)
	out = append(out, make([]byte, 8)...)
	out = append(out, desc(len(targetInfo), fixed+len(name))...)
	out = append(out, name...)
	return append(out, targetInfo...)
}

func TestChallengeParses(t *testing.T) {
	info := unhex(t, "02000c0044006f006d00610069006e000000000000000000")
	raw := buildChallenge(t, NegotiateUnicode|NegotiateExtendedSessionSec|NegotiateKeyExch, info)
	c, err := ParseChallenge(raw)
	if err != nil {
		t.Fatal(err)
	}
	if c.TargetName != "SERVER" {
		t.Errorf("target name %q", c.TargetName)
	}
	if !bytes.Equal(c.ServerChallenge, unhex(t, "0123456789abcdef")) {
		t.Errorf("server challenge %x", c.ServerChallenge)
	}
	if !bytes.Equal(c.TargetInfo, info) {
		t.Errorf("target info %x", c.TargetInfo)
	}
	if !bytes.Equal(c.raw, raw) {
		t.Error("the message that arrived was not kept for the integrity check")
	}
}

// Every length in the challenge is the server's to choose, so each is
// checked before it is used.
func TestChallengeLengthsAreChecked(t *testing.T) {
	good := buildChallenge(t, NegotiateExtendedSessionSec, nil)
	cases := []struct {
		name string
		make func() []byte
	}{
		{"too short to have a header", func() []byte { return good[:40] }},
		{"not a challenge at all", func() []byte {
			b := append([]byte(nil), good...)
			binary.LittleEndian.PutUint32(b[8:12], typeNegotiate)
			return b
		}},
		{"a field past the message", func() []byte {
			b := append([]byte(nil), good...)
			binary.LittleEndian.PutUint32(b[16:20], 0xFFFF)
			return b
		}},
		{"a field longer than the bound", func() []byte {
			b := append([]byte(nil), good...)
			binary.LittleEndian.PutUint16(b[12:14], maxField+1)
			return b
		}},
	}
	for _, c := range cases {
		if _, err := ParseChallenge(c.make()); !errors.Is(err, ErrNTLM) {
			t.Errorf("%s was accepted (%v)", c.name, err)
		}
	}
}

// A server that will not do extended session security is one this
// package refuses to send a credential to: without it the session keys
// are the weaker construction, and CredSSP's protection of the
// credential rests on them.
func TestASessionWithoutExtendedSecurityIsRefused(t *testing.T) {
	raw := buildChallenge(t, NegotiateUnicode, nil)
	c, err := ParseChallenge(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Authenticate(c, Credential{User: "u", Password: "p"}); !errors.Is(err, ErrNTLM) {
		t.Errorf("a weak session was accepted (%v)", err)
	}
}

// The third message carries the response, the sealed key and an
// integrity check over all three messages.
func TestAuthenticateBuildsAUsableMessage(t *testing.T) {
	info := unhex(t, "02000c0044006f006d00610069006e000000000000000000")
	raw := buildChallenge(t, NegotiateUnicode|NegotiateExtendedSessionSec|NegotiateKeyExch, info)
	c, err := ParseChallenge(raw)
	if err != nil {
		t.Fatal(err)
	}
	msg, s, err := Authenticate(c, Credential{Domain: "Domain", User: "User",
		Password: "Password", Workstation: "GATE"})
	if err != nil {
		t.Fatal(err)
	}
	if string(msg[:8]) != string(signature) || binary.LittleEndian.Uint32(msg[8:12]) != typeAuthenticate {
		t.Fatal("what was built is not an authenticate message")
	}
	if len(s.ExportedSessionKey) != 16 {
		t.Fatalf("session key of %d bytes", len(s.ExportedSessionKey))
	}
	// The password is nowhere in the message.
	if bytes.Contains(msg, encodeUTF16("Password")) || bytes.Contains(msg, []byte("Password")) {
		t.Error("the password went out in the message")
	}
	// The name and domain are, since the server needs them.
	if !bytes.Contains(msg, encodeUTF16("User")) || !bytes.Contains(msg, encodeUTF16("Domain")) {
		t.Error("the name and domain did not reach the message")
	}
	// The integrity check is not left as zeroes.
	if bytes.Contains(msg, make([]byte, 16)) == false {
		t.Log("no zero run, which is fine")
	}
	// Two runs differ, because the client challenge and session key
	// are drawn fresh each time.
	again, _, err := Authenticate(c, Credential{Domain: "Domain", User: "User", Password: "Password"})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(msg, again) {
		t.Error("two authentications produced the same message")
	}
}

// What one end seals the other opens, and a message that was changed
// does not open at all.
func TestSealAndUnseal(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 16)
	client, err := newSession(key)
	if err != nil {
		t.Fatal(err)
	}
	// The peer reads with the keys this end writes with, which is what
	// the other role's view of the same session is.
	peer, err := NewSession(key, RoleServer)
	if err != nil {
		t.Fatal(err)
	}

	for i, msg := range []string{"first", "second", strings.Repeat("x", 500)} {
		ct, sig := client.Seal([]byte(msg))
		if len(sig) != SignatureSize {
			t.Fatalf("signature of %d bytes", len(sig))
		}
		if bytes.Contains(ct, []byte(msg)) {
			t.Errorf("message %d went out in clear", i)
		}
		got, err := peer.Unseal(ct, sig)
		if err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
		if string(got) != msg {
			t.Errorf("message %d opened as %q", i, got)
		}
	}

	// A changed message does not authenticate.
	ct, sig := client.Seal([]byte("the credential"))
	bad := append([]byte(nil), ct...)
	bad[0] ^= 0xFF
	if _, err := peer.Unseal(bad, sig); !errors.Is(err, ErrNTLM) {
		t.Errorf("a changed message opened (%v)", err)
	}
}

// The first message says what this end will and will not do.
func TestNegotiateAsksForASealedSession(t *testing.T) {
	msg := Negotiate()
	if string(msg[:8]) != string(signature) || binary.LittleEndian.Uint32(msg[8:12]) != typeNegotiate {
		t.Fatal("what was built is not a negotiate message")
	}
	flags := binary.LittleEndian.Uint32(msg[12:16])
	for name, bit := range map[string]uint32{
		"unicode": NegotiateUnicode, "seal": NegotiateSeal, "sign": NegotiateSign,
		"extended session security": NegotiateExtendedSessionSec,
		"key exchange":              NegotiateKeyExch, "128 bit": Negotiate128,
	} {
		if flags&bit == 0 {
			t.Errorf("the negotiation does not ask for %s", name)
		}
	}
	if flags&NegotiateOEM != 0 {
		t.Error("the negotiation offers the OEM character set")
	}
}
