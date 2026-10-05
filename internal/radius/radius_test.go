package radius

import (
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // the tests verify the digests the standard specifies
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// A builder, so the tests read as RADIUS rather than as hexadecimal.

// attr renders one attribute.
func attr(t AttrType, value ...byte) []byte {
	return append([]byte{byte(t), byte(len(value) + 2)}, value...)
}

// vsa renders a Vendor-Specific attribute in RFC 2865 §5.26's recommended
// encoding.
func vsa(vendor uint32, vendorType uint8, value ...byte) []byte {
	inner := append([]byte{vendorType, byte(len(value) + 2)}, value...)
	v := make([]byte, 4, 4+len(inner))
	binary.BigEndian.PutUint32(v, vendor)
	return attr(AttrVendorSpecific, append(v, inner...)...)
}

// packet renders a whole packet with the length field filled in.
func packet(code Code, id uint8, auth [16]byte, attrs ...[]byte) []byte {
	var body []byte
	for _, a := range attrs {
		body = append(body, a...)
	}
	b := make([]byte, HeaderBytes, HeaderBytes+len(body))
	b[0], b[1] = byte(code), id
	copy(b[4:], auth[:])
	b = append(b, body...)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	return b
}

func auth16(fill byte) [16]byte {
	var a [16]byte
	for i := range a {
		a[i] = fill
	}
	return a
}

func mustParse(t *testing.T, b []byte) *Packet {
	t.Helper()
	p, err := Parse(b)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return p
}

func TestTheLengthFieldDecidesWhereAPacketEnds(t *testing.T) {
	t.Parallel()
	// RFC 2865 §3: octets outside Length are padding to be ignored, and a
	// Length longer than what arrived means the packet is discarded. Both
	// directions matter, and getting either wrong is a reader that
	// disagrees with a server about which attributes are in a packet.
	t.Run("padding past the length field is not read", func(t *testing.T) {
		t.Parallel()
		b := packet(CodeAccessRequest, 7, auth16(1), attr(AttrUserName, 'b', 'o', 'b'))
		// A whole second attribute, appended after the length says the
		// packet ended. A reader that walked to the end of the datagram
		// would find a User-Password here and decide this was a PAP
		// request.
		b = append(b, attr(AttrUserPassword, make([]byte, 16)...)...)
		p := mustParse(t, b)
		if got := len(p.Attrs); got != 1 {
			t.Fatalf("attributes = %d, want 1 (the padded one must not be read)", got)
		}
		if p.AuthType() != AuthNone {
			t.Errorf("auth type = %q, want none: the padding was read", p.AuthType())
		}
	})
	t.Run("a length past the datagram is refused", func(t *testing.T) {
		t.Parallel()
		b := packet(CodeAccessRequest, 7, auth16(1), attr(AttrUserName, 'b'))
		binary.BigEndian.PutUint16(b[2:4], uint16(len(b)+8))
		if _, err := Parse(b); !errors.Is(err, ErrTruncated) {
			t.Fatalf("err = %v, want ErrTruncated", err)
		}
	})
	t.Run("a length below a header is refused", func(t *testing.T) {
		t.Parallel()
		b := packet(CodeAccessRequest, 7, auth16(1))
		binary.BigEndian.PutUint16(b[2:4], 19)
		if _, err := Parse(b); !errors.Is(err, ErrLength) {
			t.Fatalf("err = %v, want ErrLength", err)
		}
	})
	t.Run("a length past the standard's maximum is refused", func(t *testing.T) {
		t.Parallel()
		b := make([]byte, MaxMessage+8)
		b[0] = byte(CodeAccessRequest)
		binary.BigEndian.PutUint16(b[2:4], MaxMessage+1)
		if _, err := Parse(b); !errors.Is(err, ErrLength) {
			t.Fatalf("err = %v, want ErrLength", err)
		}
	})
	t.Run("shorter than a header is refused", func(t *testing.T) {
		t.Parallel()
		if _, err := Parse(make([]byte, 19)); !errors.Is(err, ErrShort) {
			t.Fatalf("err = %v, want ErrShort", err)
		}
	})
}

func TestAnImpossibleAttributeLengthIsRefusedRatherThanSkipped(t *testing.T) {
	t.Parallel()
	// A length of 0 or 1 does not advance the walk. A reader that skipped
	// it would loop for ever on one datagram, which is the whole reason
	// this is a refusal and not a continue.
	for _, l := range []byte{0, 1} {
		b := packet(CodeAccessRequest, 1, auth16(2), []byte{byte(AttrUserName), l, 'x'})
		if _, err := Parse(b); !errors.Is(err, ErrAttrLength) {
			t.Fatalf("length %d: err = %v, want ErrAttrLength", l, err)
		}
	}
	// And an attribute whose length runs past the packet.
	b := packet(CodeAccessRequest, 1, auth16(2), []byte{byte(AttrUserName), 8, 'x'})
	if _, err := Parse(b); !errors.Is(err, ErrAttrOverruns) {
		t.Fatalf("err = %v, want ErrAttrOverruns", err)
	}
}

func TestAVendorAttributeIsOnlyUnwrappedWhenItsOwnLengthAgrees(t *testing.T) {
	t.Parallel()
	t.Run("the recommended encoding is read", func(t *testing.T) {
		t.Parallel()
		p := mustParse(t, packet(CodeAccessAccept, 3, auth16(4),
			vsa(VendorCisco, 1, []byte("shell:priv-lvl=15")...)))
		a, ok := p.Vendor(VendorCisco, 1)
		if !ok {
			t.Fatal("the cisco attribute was not found")
		}
		if s, _ := a.Text(); s != "shell:priv-lvl=15" {
			t.Fatalf("value = %q", s)
		}
		if a.Name() != "cisco.1" {
			t.Errorf("name = %q, want cisco.1", a.Name())
		}
	})
	t.Run("a vendor that did not follow it keeps its value whole", func(t *testing.T) {
		t.Parallel()
		// Four octets of vendor and then five octets whose second is not a
		// length that accounts for them. Reading the first two as a type
		// and a length would hand a rule a value that is not one.
		raw := append([]byte{0, 0, 0, 42}, 'a', 'b', 'c', 'd', 'e')
		p := mustParse(t, packet(CodeAccessRequest, 1, auth16(1), attr(AttrVendorSpecific, raw...)))
		a := p.Attrs[0]
		if a.Vendor != 42 {
			t.Fatalf("vendor = %d, want 42", a.Vendor)
		}
		if a.VendorType != 0 {
			t.Errorf("vendor type = %d, want 0 (unread)", a.VendorType)
		}
		if got := string(a.Value); got != "abcde" {
			t.Errorf("value = %q, want the whole of it", got)
		}
	})
}

func TestAnExtendedAttributeKeepsItsExtendedType(t *testing.T) {
	t.Parallel()
	p := mustParse(t, packet(CodeAccessRequest, 1, auth16(1), attr(241, 7, 'x', 'y')))
	a := p.Attrs[0]
	if !a.Type.Extended() {
		t.Fatal("type 241 is not reported as extended")
	}
	if a.ExtType != 7 {
		t.Fatalf("extended type = %d, want 7", a.ExtType)
	}
	if got := string(a.Value); got != "xy" {
		t.Errorf("value = %q, want xy: the extended type was read as data", got)
	}
	if a.Name() != "attr(241).7" {
		t.Errorf("name = %q", a.Name())
	}
}

// digest computes RFC 3579 §3.2's HMAC-MD5 over a packet whose
// Message-Authenticator is already present and zeroed, which is what a
// correct sender does.
func digest(secret, b []byte, requestAuth [16]byte, at int) []byte {
	buf := make([]byte, len(b))
	copy(buf, b)
	copy(buf[4:HeaderBytes], requestAuth[:])
	for i := 0; i < 16; i++ {
		buf[at+i] = 0
	}
	h := hmac.New(md5.New, secret) //nolint:gosec // the standard specifies HMAC-MD5
	h.Write(buf)
	return h.Sum(nil)
}

// signed builds a packet carrying a correct Message-Authenticator.
func signed(secret []byte, code Code, id uint8, auth [16]byte,
	requestAuth [16]byte, attrs ...[]byte) []byte {
	// A copy rather than an append onto the caller's slice: appending into
	// the spare capacity of a slice somebody else still holds is how one
	// test's packet quietly changes another's.
	all := make([][]byte, 0, len(attrs)+1)
	all = append(all, attrs...)
	all = append(all, attr(AttrMessageAuthenticator, make([]byte, 16)...))
	b := packet(code, id, auth, all...)
	at := len(b) - 16
	copy(b[at:], digest(secret, b, requestAuth, at))
	return b
}

func TestTheMessageAuthenticatorVerifies(t *testing.T) {
	t.Parallel()
	secret := []byte("s3cret")
	t.Run("a request signs over its own authenticator", func(t *testing.T) {
		t.Parallel()
		ra := auth16(0x11)
		b := signed(secret, CodeAccessRequest, 9, ra, ra, attr(AttrUserName, 'b', 'o', 'b'))
		p := mustParse(t, b)
		if err := p.VerifyMessageAuthenticator(secret, ra); err != nil {
			t.Fatalf("verify: %v", err)
		}
	})
	t.Run("a response signs over the request's authenticator", func(t *testing.T) {
		t.Parallel()
		// This is the substitution the standard requires, and the test
		// that proves it is needed: the response's own authenticator field
		// is different, and a verifier that used it fails.
		ra, own := auth16(0x11), auth16(0x22)
		b := signed(secret, CodeAccessAccept, 9, own, ra)
		p := mustParse(t, b)
		if err := p.VerifyMessageAuthenticator(secret, ra); err != nil {
			t.Fatalf("verify with the request's authenticator: %v", err)
		}
		if err := p.VerifyMessageAuthenticator(secret, own); !errors.Is(err, ErrBadDigest) {
			t.Fatalf("verify with its own authenticator: err = %v, want ErrBadDigest", err)
		}
	})
	t.Run("a wrong secret fails", func(t *testing.T) {
		t.Parallel()
		ra := auth16(3)
		p := mustParse(t, signed(secret, CodeAccessRequest, 1, ra, ra))
		if err := p.VerifyMessageAuthenticator([]byte("other"), ra); !errors.Is(err, ErrBadDigest) {
			t.Fatalf("err = %v, want ErrBadDigest", err)
		}
	})
	t.Run("a flipped attribute octet fails", func(t *testing.T) {
		t.Parallel()
		ra := auth16(3)
		b := signed(secret, CodeAccessRequest, 1, ra, ra, attr(AttrUserName, 'b', 'o', 'b'))
		b[HeaderBytes+2] ^= 0x20 // bob -> bOb
		p := mustParse(t, b)
		if err := p.VerifyMessageAuthenticator(secret, ra); !errors.Is(err, ErrBadDigest) {
			t.Fatalf("err = %v, want ErrBadDigest", err)
		}
	})
	t.Run("a digest of the wrong length fails rather than being truncated", func(t *testing.T) {
		t.Parallel()
		ra := auth16(3)
		b := packet(CodeAccessRequest, 1, ra, attr(AttrMessageAuthenticator, make([]byte, 8)...))
		p := mustParse(t, b)
		if err := p.VerifyMessageAuthenticator(secret, ra); !errors.Is(err, ErrBadDigest) {
			t.Fatalf("err = %v, want ErrBadDigest", err)
		}
	})
	t.Run("no attribute and no secret are told apart", func(t *testing.T) {
		t.Parallel()
		ra := auth16(3)
		p := mustParse(t, packet(CodeAccessRequest, 1, ra))
		if err := p.VerifyMessageAuthenticator(secret, ra); !errors.Is(err, ErrNoDigest) {
			t.Fatalf("err = %v, want ErrNoDigest", err)
		}
		if err := p.VerifyMessageAuthenticator(nil, ra); !errors.Is(err, ErrNoSecret) {
			t.Fatalf("err = %v, want ErrNoSecret", err)
		}
	})
}

func TestTheResponseAuthenticatorVerifies(t *testing.T) {
	t.Parallel()
	secret := []byte("s3cret")
	ra := auth16(0x55)
	// Build a reply and fill in the authenticator the way a server does.
	b := packet(CodeAccessAccept, 11, ra, attr(AttrReplyMessage, 'o', 'k'))
	p := mustParse(t, b)
	want := p.ResponseAuthenticator(secret, ra)
	copy(b[4:HeaderBytes], want[:])
	p = mustParse(t, b)
	if !p.VerifyResponseAuthenticator(secret, ra) {
		t.Fatal("a correctly signed reply did not verify")
	}
	if p.VerifyResponseAuthenticator([]byte("other"), ra) {
		t.Error("a wrong secret verified")
	}
	if p.VerifyResponseAuthenticator(secret, auth16(0x56)) {
		t.Error("a wrong request authenticator verified")
	}
	if p.VerifyResponseAuthenticator(nil, ra) {
		t.Error("no secret verified")
	}
}

func TestARealmIsSplitTheWayAServerSplitsIt(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, local, realm string }{
		{"bob", "bob", ""},
		{"bob@corp.example", "bob", "corp.example"},
		{`CORP\bob`, "bob", "CORP"},
		{"CORP/bob", "bob", "CORP"},
		// A name with both. The first separator decides, because that is
		// how a server reading left to right splits it -- and a reader
		// that disagreed would be allowing a realm the credential does
		// not go to.
		{`CORP\bob@other.example`, "bob@other.example", "CORP"},
		{"bob@corp.example\\x", "bob", "corp.example\\x"},
	}
	for _, c := range cases {
		local, realm := Realm(c.in)
		if local != c.local || realm != c.realm {
			t.Errorf("Realm(%q) = (%q, %q), want (%q, %q)", c.in, local, realm, c.local, c.realm)
		}
	}
}

func TestTheAuthenticationMethodIsReadTheWayAServerWouldChooseIt(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		attrs [][]byte
		want  AuthType
	}{
		{"nothing", nil, AuthNone},
		{"a password", [][]byte{attr(AttrUserPassword, make([]byte, 16)...)}, AuthPAP},
		{"chap", [][]byte{attr(AttrCHAPPassword, make([]byte, 17)...)}, AuthCHAP},
		{"ms-chap v2", [][]byte{vsa(VendorMicrosoft, 25, 1, 2, 3)}, AuthMSCHAP},
		{"eap", [][]byte{attr(AttrEAPMessage, 2, 1, 0, 5, 1)}, AuthEAP},
		{
			// RFC 3579 §2.6.2 lets a server do either; every real one
			// prefers EAP, so reporting PAP here would be deciding about
			// a method the server will not use.
			"both eap and a password",
			[][]byte{attr(AttrUserPassword, make([]byte, 16)...), attr(AttrEAPMessage, 2, 1, 0, 5, 1)},
			AuthEAP,
		},
	}
	for _, c := range cases {
		p := mustParse(t, packet(CodeAccessRequest, 1, auth16(1), c.attrs...))
		if got := p.AuthType(); got != c.want {
			t.Errorf("%s: auth type = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestAPasswordLengthTheObfuscationCannotHaveProducedIsRejected(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		n  int
		ok bool
	}{{16, true}, {128, true}, {17, false}, {0, false}, {144, false}} {
		p := mustParse(t, packet(CodeAccessRequest, 1, auth16(1),
			attr(AttrUserPassword, make([]byte, c.n)...)))
		got, ok := p.PasswordBytes()
		if c.n == 0 {
			// A zero-length attribute is two octets and parses; the
			// length is not a multiple of 16 that is non-zero.
			if ok {
				t.Errorf("a zero-length password was accepted")
			}
			continue
		}
		if got != c.n || ok != c.ok {
			t.Errorf("%d octets: (%d, %v), want (%d, %v)", c.n, got, ok, c.n, c.ok)
		}
	}
}

func TestAPrivilegeGrantIsFoundInTheFormsEquipmentUses(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		av   string
		want int
		ok   bool
	}{
		{"the cisco shell form", "shell:priv-lvl=15", 15, true},
		{"the bare form", "priv-lvl=7", 7, true},
		{"an optional pair", "shell:priv-lvl*15", 15, true},
		{"one pair among several", "shell:roles=admin,shell:priv-lvl=15", 15, true},
		// Past the ladder is still a grant, and read as one: the policy's
		// bound is what refuses it. A reader that answered "this grants
		// nothing" about `priv-lvl=16` would be deciding, in the parser, that
		// a value it does not recognise is safe.
		{"a level past the ladder", "shell:priv-lvl=16", 16, true},
		{"something else entirely", "shell:roles=operator", 0, false},
		// The NUL-separated pair list, which is how several platforms write
		// it. This is the spelling that used to read as no grant at all,
		// because the value was rendered through a text-safe accessor that
		// refuses control characters -- one octet, and the bound never applied.
		{"the NUL-separated form", "shell:roles=admin\x00shell:priv-lvl=15", 15, true},
		{"a NUL-separated pair alone", "shell:priv-lvl=15\x00", 15, true},
	}
	for _, c := range cases {
		p := mustParse(t, packet(CodeAccessAccept, 1, auth16(1),
			vsa(VendorCisco, 1, []byte(c.av)...)))
		got, ok := p.PrivilegeLevel()
		if got != c.want || ok != c.ok {
			t.Errorf("%s (%q): (%d, %v), want (%d, %v)", c.name, c.av, got, ok, c.want, c.ok)
		}
	}
	// Every attribute is read and the highest wins, because a bound applied to
	// a grant the equipment is not the one to act on is not a bound: which of
	// two priv-lvl pairs a platform takes is the platform's business, so both
	// are the proxy's.
	two := mustParse(t, packet(CodeAccessAccept, 1, auth16(1),
		vsa(VendorCisco, 1, []byte("shell:priv-lvl=1")...),
		vsa(VendorCisco, 1, []byte("shell:priv-lvl=15")...)))
	if n, ok := two.PrivilegeLevel(); !ok || n != 15 {
		t.Errorf("two priv-lvl pairs read as (%d, %v), want (15, true)", n, ok)
	}
	// And an unreadable one does not hide the one after it.
	hidden := mustParse(t, packet(CodeAccessAccept, 1, auth16(1),
		vsa(VendorCisco, 1, []byte("shell:roles=\x01\x02")...),
		vsa(VendorCisco, 1, []byte("shell:priv-lvl=15")...)))
	if n, ok := hidden.PrivilegeLevel(); !ok || n != 15 {
		t.Errorf("a grant behind an unreadable attribute read as (%d, %v), want (15, true)", n, ok)
	}

	// And the standard attribute that means the same thing.
	admin := mustParse(t, packet(CodeAccessAccept, 1, auth16(1),
		attr(AttrServiceType, 0, 0, 0, 6)))
	if !admin.Administrative() {
		t.Error("Service-Type = Administrative-User was not recognised")
	}
	// Including when it is not the first Service-Type on the reply.
	second := mustParse(t, packet(CodeAccessAccept, 1, auth16(1),
		attr(AttrServiceType, 0, 0, 0, 1), attr(AttrServiceType, 0, 0, 0, 6)))
	if !second.Administrative() {
		t.Error("a second Service-Type granting Administrative-User was not read")
	}
	login := mustParse(t, packet(CodeAccessAccept, 1, auth16(1),
		attr(AttrServiceType, 0, 0, 0, 1)))
	if login.Administrative() {
		t.Error("Service-Type = Login was read as administrative")
	}
}

func TestATextAttributeWithAControlCharacterIsRefused(t *testing.T) {
	t.Parallel()
	// A NAS-Identifier with a newline in it is a second line in a log
	// file. The attribute parses; reading it as text does not.
	p := mustParse(t, packet(CodeAccessRequest, 1, auth16(1),
		attr(AttrNASIdentifier, 'a', '\n', 'b')))
	if _, ok := p.Attrs[0].Text(); ok {
		t.Fatal("a newline was accepted in a text attribute")
	}
	if p.UserName() != "" {
		t.Error("UserName returned something for a packet with none")
	}
	bad := mustParse(t, packet(CodeAccessRequest, 1, auth16(1),
		attr(AttrUserName, 'b', 0x1b, '[')))
	if bad.UserName() != "" {
		t.Error("an escape sequence was accepted as a user name")
	}
}

func TestCodeAndAttributeNamesRoundTrip(t *testing.T) {
	t.Parallel()
	for _, n := range CodeNames() {
		c, ok := CodeOf(n)
		if !ok || c.String() != n {
			t.Errorf("CodeOf(%q) = (%v, %v)", n, c, ok)
		}
	}
	for _, n := range AttrNames() {
		a, ok := AttrOf(n)
		if !ok || a.String() != n {
			t.Errorf("AttrOf(%q) = (%v, %v)", n, a, ok)
		}
	}
	for _, n := range AuthTypeNames() {
		if _, ok := AuthTypeOf(n); !ok {
			t.Errorf("AuthTypeOf(%q) did not read it back", n)
		}
	}
	// A number is a legitimate way to name an attribute the registry has
	// and this package does not.
	if a, ok := AttrOf("200"); !ok || a != 200 {
		t.Errorf(`AttrOf("200") = (%v, %v)`, a, ok)
	}
	if _, ok := AttrOf("0"); ok {
		t.Error(`AttrOf("0") was accepted; 0 is not an attribute type`)
	}
	if _, ok := CodeOf("not-a-code"); ok {
		t.Error("a nonsense code name was accepted")
	}
}

func TestDirectionIsAPropertyOfTheCode(t *testing.T) {
	t.Parallel()
	if !CodeAccessRequest.Request() || CodeAccessRequest.Response() {
		t.Error("Access-Request")
	}
	if !CodeAccessAccept.Response() || CodeAccessAccept.Request() {
		t.Error("Access-Accept")
	}
	// A Disconnect-Request is a request that is not a client's: it runs
	// from a server towards the equipment, which is why Request() is
	// false for it and Dynamic() is true.
	if CodeDisconnectRequest.Request() {
		t.Error("Disconnect-Request read as a client request")
	}
	for _, c := range []Code{CodeDisconnectRequest, CodeDisconnectACK, CodeDisconnectNAK,
		CodeCoARequest, CodeCoAACK, CodeCoANAK} {
		if !c.Dynamic() {
			t.Errorf("%s is not reported as dynamic authorization", c)
		}
	}
	if CodeAccessRequest.Dynamic() {
		t.Error("Access-Request read as dynamic authorization")
	}
}

func TestSummaryNamesWhatAPacketIsWithoutTheCredential(t *testing.T) {
	t.Parallel()
	p := mustParse(t, packet(CodeAccessRequest, 42, auth16(1),
		attr(AttrUserName, 'b', 'o', 'b'),
		attr(AttrUserPassword, make([]byte, 16)...)))
	s := p.Summary()
	for _, want := range []string{"access-request", "id=42", "user=bob", "attrs=2"} {
		if !strings.Contains(s, want) {
			t.Errorf("summary %q does not contain %q", s, want)
		}
	}
	if strings.Contains(p.String(), "password") {
		t.Error("String() mentions a password")
	}
}
