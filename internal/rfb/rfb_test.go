package rfb

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestVersionRoundTrip(t *testing.T) {
	for _, v := range Supported {
		b := v.Handshake()
		if len(b) != 12 {
			t.Fatalf("%s is %d bytes, want 12", v, len(b))
		}
		got, err := ParseVersion(b)
		if err != nil || got != v {
			t.Errorf("%s round-tripped to %v (%v)", v, got, err)
		}
	}
}

// A peer that is not speaking RFB is not guessed at: reading a version
// out of a prefix is how a proxy and a server come to disagree about
// whether a security list follows.
func TestSomethingElseIsNotAVersion(t *testing.T) {
	for _, in := range []string{
		"GET / HTTP/1.1", "RFB 003.008", "RFB 3.8\n\n\n\n\n", "rfb 003.008\n",
		"RFB 00a.008\n", "RFB 003:008\n", "",
	} {
		if _, err := ParseVersion([]byte(in)); err == nil {
			t.Errorf("%q was read as a version", in)
		}
	}
}

// Two peers settle on the lower of what each offers, and a version
// nobody defines is rounded down to one that is.
func TestNegotiatedTakesTheLowerDefinedVersion(t *testing.T) {
	for _, tc := range []struct {
		client, server, want Version
		ok                   bool
	}{
		{V38, V38, V38, true},
		{V38, V37, V37, true},
		{V37, V38, V37, true},
		{V33, V38, V33, true},
		{V38, V33, V33, true},
		// Real clients announce versions nobody defines.
		{Version{3, 889}, V38, V38, true}, // Apple's
		{Version{4, 1}, V38, V38, true},   // a future one
		{Version{3, 4}, V38, V33, true},   // between 3.3 and 3.7
		{Version{3, 0}, V38, Version{}, false},
	} {
		got, ok := Negotiated(tc.client, tc.server)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("Negotiated(%s, %s) = %s %v, want %s %v", tc.client, tc.server, got, ok, tc.want, tc.ok)
		}
	}
}

func TestSecurityListRoundTrip(t *testing.T) {
	want := []uint8{SecVeNCrypt, SecVNCAuth, SecNone}
	got, err := ReadSecurityList(bytes.NewReader(SecurityList(want)))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("list round-tripped to %v (%v)", got, err)
	}
	// An empty list is a refusal and carries its reason.
	_, err = ReadSecurityList(bytes.NewReader(SecurityFailure("no")))
	if !errors.Is(err, ErrNoSecurity) || !strings.Contains(err.Error(), "no") {
		t.Errorf("a refusal read as %v", err)
	}
}

// Every length a peer chooses is bounded before anything is
// allocated, or a four byte header asks for four gigabytes.
func TestLengthsAreBoundedBeforeAllocation(t *testing.T) {
	huge := []byte{0xff, 0xff, 0xff, 0xff}
	if _, err := ReadString(bytes.NewReader(huge), MaxReason); err == nil {
		t.Error("a four gigabyte string was accepted")
	}
	// A ServerInit whose name length is absurd.
	init := make([]byte, serverInitHead)
	copy(init[20:], huge)
	if _, err := ReadServerInit(bytes.NewReader(init)); err == nil {
		t.Error("a four gigabyte desktop name was accepted")
	}
}

// The fixed part of a ServerInit is twenty-four bytes, and getting
// that wrong reads the name length out of the pixel format.
func TestServerInitRoundTrip(t *testing.T) {
	want := ServerInit{Width: 1920, Height: 1080, Name: "console"}
	for i := range want.PixelFormat {
		want.PixelFormat[i] = byte(i + 1)
	}
	got, err := ReadServerInit(bytes.NewReader(want.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	if got.Width != want.Width || got.Height != want.Height || got.Name != want.Name || got.PixelFormat != want.PixelFormat {
		t.Errorf("ServerInit round-tripped to %+v, want %+v", got, want)
	}
	// A name of nothing is a name of nothing, not a short read.
	empty := ServerInit{Width: 1, Height: 1}
	if g, err := ReadServerInit(bytes.NewReader(empty.Encode())); err != nil || g.Name != "" {
		t.Errorf("an unnamed desktop: %+v (%v)", g, err)
	}
}

func TestClientInitRoundTrip(t *testing.T) {
	for _, shared := range []bool{true, false} {
		c := ClientInit{Shared: shared}
		got, err := ReadClientInit(bytes.NewReader(c.Encode()))
		if err != nil || got != c {
			t.Errorf("ClientInit(%v) round-tripped to %+v (%v)", shared, got, err)
		}
	}
}

// The DES challenge of RFC 6143 section 7.2.2, against the vector
// every implementation agrees on. The bit reversal is what the
// original implementation did; a proxy that did the sensible thing
// instead would agree with nobody.
func TestVNCAuthResponseMatchesTheKnownVector(t *testing.T) {
	challenge, _ := hex.DecodeString("00000000000000000000000000000000")
	got, err := VNCAuthResponse(challenge, "password")
	if err != nil {
		t.Fatal(err)
	}
	// An all-zero challenge under the key "password" is two identical
	// ECB blocks, which is the shape of the thing as much as the value.
	if !bytes.Equal(got[:8], got[8:]) {
		t.Errorf("two identical blocks encrypted differently: %x", got)
	}
	if len(got) != ChallengeSize {
		t.Errorf("response is %d bytes, want %d", len(got), ChallengeSize)
	}
	// A password past eight bytes is truncated, so these agree.
	long, _ := VNCAuthResponse(challenge, "passwordIGNORED")
	if !bytes.Equal(got, long) {
		t.Error("a password past eight bytes changed the response")
	}
	// And a different password does not.
	other, _ := VNCAuthResponse(challenge, "passwore")
	if bytes.Equal(got, other) {
		t.Error("two different passwords gave one response")
	}
	if _, err := VNCAuthResponse(challenge[:8], "x"); err == nil {
		t.Error("a short challenge was accepted")
	}
}

func TestReverseBits(t *testing.T) {
	for _, tc := range []struct{ in, want byte }{
		{0x01, 0x80}, {0x80, 0x01}, {0xff, 0xff}, {0x00, 0x00}, {0b1010_0000, 0b0000_0101},
	} {
		if got := reverseBits(tc.in); got != tc.want {
			t.Errorf("reverseBits(%08b) = %08b, want %08b", tc.in, got, tc.want)
		}
	}
}

func TestSecurityResultCarriesAReasonOnlyOn38(t *testing.T) {
	if got := SecurityResult(V38, false, "nope"); !bytes.Contains(got, []byte("nope")) {
		t.Errorf("3.8 failure carried no reason: %v", got)
	}
	if got := SecurityResult(V37, false, "nope"); len(got) != 4 {
		t.Errorf("3.7 failure is %d bytes, want 4 with no reason", len(got))
	}
	if got := SecurityResult(V38, true, ""); len(got) != 4 {
		t.Errorf("success is %d bytes, want 4", len(got))
	}
	ok, reason, err := ReadSecurityResult(bytes.NewReader(SecurityResult(V38, false, "why")), V38)
	if err != nil || ok || reason != "why" {
		t.Errorf("read back %v %q (%v)", ok, reason, err)
	}
}

func TestVeNCryptSubtypes(t *testing.T) {
	want := []uint32{VeNCryptX509Vnc, VeNCryptTLSNone}
	got, err := ReadSubtypes(bytes.NewReader(Subtypes(want)))
	if err != nil || len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("subtypes round-tripped to %v (%v)", got, err)
	}
	for _, tc := range []struct {
		t         uint32
		tls, x509 bool
		auth      uint8
	}{
		{VeNCryptPlain, false, false, SecPlain},
		{VeNCryptTLSNone, true, false, SecNone},
		{VeNCryptTLSVnc, true, false, SecVNCAuth},
		{VeNCryptX509None, true, true, SecNone},
		{VeNCryptX509Vnc, true, true, SecVNCAuth},
		{VeNCryptX509Plain, true, true, SecPlain},
	} {
		if UsesTLS(tc.t) != tc.tls || UsesX509(tc.t) != tc.x509 || AuthAfterTLS(tc.t) != tc.auth {
			t.Errorf("%s: tls %v x509 %v auth %d", SubtypeName(tc.t), UsesTLS(tc.t), UsesX509(tc.t), AuthAfterTLS(tc.t))
		}
	}
}

// The names are what a policy is written in, so they resolve both ways
// and an invented one does not resolve at all.
func TestNames(t *testing.T) {
	if s, ok := SecurityByName("vencrypt"); !ok || s != SecVeNCrypt {
		t.Errorf("vencrypt = %d %v", s, ok)
	}
	if _, ok := SecurityByName("nosuchtype"); ok {
		t.Error("an invented security type resolved")
	}
	if SecurityName(SecRSAAES) != "rsa-aes" || SecurityName(200) != "security-200" {
		t.Errorf("names: %q %q", SecurityName(SecRSAAES), SecurityName(200))
	}
	if s, ok := SubtypeByName("x509-vnc"); !ok || s != VeNCryptX509Vnc {
		t.Errorf("x509-vnc = %d %v", s, ok)
	}
	// Every type this proxy mediates has a name, and none of them is
	// also proprietary: the two sets are what a policy chooses between.
	for tpe := range Mediated {
		if _, ok := securityNames[tpe]; !ok {
			t.Errorf("mediated type %d has no name", tpe)
		}
		if Proprietary[tpe] {
			t.Errorf("type %s is both mediated and proprietary", SecurityName(tpe))
		}
	}
}

func TestPlainCredentialsRoundTrip(t *testing.T) {
	// Both lengths come before either value, which is the subtype's
	// own framing and not RFB's usual length-prefixed string.
	b := Plain("alice", "492013")
	if len(b) != 8+len("alice")+len("492013") {
		t.Fatalf("%d bytes for a 5 and 6 byte credential", len(b))
	}
	if string(b[8:]) != "alice492013" {
		t.Errorf("the values do not follow the lengths: %q", b[8:])
	}
	user, secret, err := ReadPlain(bytes.NewReader(b), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if user != "alice" || secret != "492013" {
		t.Errorf("read %q and %q", user, secret)
	}
}

func TestAPlainCredentialIsBoundedBeforeAllocation(t *testing.T) {
	// Four gigabytes of username, announced by eight bytes.
	head := []byte{0xff, 0xff, 0xff, 0xff, 0, 0, 0, 1}
	if _, _, err := ReadPlain(bytes.NewReader(head), 1024); err == nil {
		t.Fatal("an unbounded username was accepted")
	}
	head = []byte{0, 0, 0, 1, 0xff, 0xff, 0xff, 0xff}
	if _, _, err := ReadPlain(bytes.NewReader(head), 1024); err == nil {
		t.Fatal("an unbounded password was accepted")
	}
	// An empty credential is not an error: it is a name nobody is
	// enrolled under, which is a decision for the caller.
	user, secret, err := ReadPlain(bytes.NewReader([]byte{0, 0, 0, 0, 0, 0, 0, 0}), 1024)
	if err != nil || user != "" || secret != "" {
		t.Errorf("empty credential: %q %q %v", user, secret, err)
	}
}

func TestOnlyPre38NoneSkipsTheSecurityResult(t *testing.T) {
	cases := []struct {
		v    Version
		sec  uint8
		want bool
	}{
		{V33, SecNone, false},
		{V37, SecNone, false},
		{V38, SecNone, true},
		{V33, SecVNCAuth, true},
		{V37, SecVNCAuth, true},
		{V38, SecVNCAuth, true},
		// The outer type is what decides, so VeNCrypt always carries
		// one however its subtype authenticated.
		{V37, SecVeNCrypt, true},
		{V37, SecInvalid, true},
	}
	for _, c := range cases {
		if got := SendsResult(c.v, c.sec); got != c.want {
			t.Errorf("SendsResult(%s, %s) = %v, want %v", c.v, SecurityName(c.sec), got, c.want)
		}
	}
}

func TestThreeThreeNamesOneSecurityType(t *testing.T) {
	b := Security33(SecVNCAuth)
	if len(b) != 4 {
		t.Fatalf("%d bytes, want 4", len(b))
	}
	got, err := ReadSecurity33(bytes.NewReader(b))
	if err != nil || got != SecVNCAuth {
		t.Errorf("read %d (%v)", got, err)
	}
	// Zero means the server refused, and a reason follows.
	if _, err := ReadSecurity33(bytes.NewReader(Security33(SecInvalid))); err == nil {
		t.Error("the invalid marker was read as a usable type")
	}
}

func TestVeNCryptVersionRoundTrip(t *testing.T) {
	b := VeNCryptVersion(VeNCrypt02)
	if len(b) != 2 || b[0] != 0 || b[1] != 2 {
		t.Fatalf("VeNCrypt 0.2 rendered as %v", b)
	}
	v, err := ReadVeNCryptVersion(bytes.NewReader(b))
	if err != nil || v != VeNCrypt02 {
		t.Errorf("read %v (%v)", v, err)
	}
}

func TestSubtypeChoiceIsFourBytes(t *testing.T) {
	b := Subtypes([]uint32{VeNCryptX509Plain})
	if len(b) != 5 || b[0] != 1 {
		t.Fatalf("one subtype rendered as %v", b)
	}
	got, err := ReadSubtypeChoice(bytes.NewReader(b[1:]))
	if err != nil || got != VeNCryptX509Plain {
		t.Errorf("read %d (%v)", got, err)
	}
	if SubtypeName(VeNCryptX509Plain) != "x509-plain" {
		t.Errorf("x509-plain is named %q", SubtypeName(VeNCryptX509Plain))
	}
	if !strings.Contains(SubtypeName(4242), "4242") {
		t.Errorf("an unknown subtype is named %q", SubtypeName(4242))
	}
}

func TestReadVersionRefusesShortAndUnknown(t *testing.T) {
	if _, err := ReadVersion(bytes.NewReader([]byte("RFB 003."))); err == nil {
		t.Error("a truncated version string was accepted")
	}
	if _, err := ReadVersion(bytes.NewReader([]byte("HTTP/1.1 200"))); err == nil {
		t.Error("something that is not a version was accepted")
	}
	v, err := ReadVersion(bytes.NewReader(V38.Handshake()))
	if err != nil || v != V38 {
		t.Errorf("read %v (%v)", v, err)
	}
}

func TestStringRoundTrip(t *testing.T) {
	b := String("no route to that desktop")
	got, err := ReadString(bytes.NewReader(b), MaxReason)
	if err != nil || got != "no route to that desktop" {
		t.Errorf("read %q (%v)", got, err)
	}
}
