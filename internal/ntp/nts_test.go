package ntp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/rom/xproxy/internal/siv"
)

func ntsKey(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b ^ byte(i)
	}
	return k
}

// aCookie is a stand-in for a real one: opaque octets of a length that is a
// multiple of four, which is what a cookie has to be to survive the extension
// field it travels in.
func aCookie(n int) []byte {
	c := make([]byte, n)
	for i := range c {
		c[i] = byte(i + 1)
	}
	return c
}

// ntsRequest builds what an NTS client sends: a header, a unique identifier, a
// cookie, any placeholders, and the authenticator over all of it.
func ntsRequest(t *testing.T, c2s, cookie []byte, placeholders int) []byte {
	t.Helper()
	p := &Packet{Version: 4, Mode: ModeClient, Poll: 6, Precision: -20, Transmit: Timestamp(1) << 32}
	uid, err := NTSUniqueIDField()
	if err != nil {
		t.Fatal(err)
	}
	p.Extensions = []Extension{uid, NTSCookieField(cookie)}
	for i := 0; i < placeholders; i++ {
		p.Extensions = append(p.Extensions, NTSPlaceholderField(len(cookie)))
	}
	out, err := SealNTS(p.Bytes(), c2s, nil)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestAnNTSRequestVerifiesUnderItsKey(t *testing.T) {
	c2s := ntsKey(0x11)
	cookie := aCookie(104)
	raw := ntsRequest(t, c2s, cookie, 2)
	p, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := p.OpenNTS(c2s)
	if err != nil {
		t.Fatal(err)
	}
	if len(fields) != 0 {
		t.Errorf("a request encrypted %d fields", len(fields))
	}
	// The cookie and the placeholders are in the clear, which is what lets a
	// server know which keys to use before it can verify anything.
	n := p.NTS()
	if !n.Present || n.Cookies != 1 || n.Placeholders != 2 || !n.Authenticator {
		t.Fatalf("visible fields %+v", n)
	}
	if got := NTSCookies(p.Extensions); len(got) != 1 || !bytes.Equal(got[0], cookie) {
		t.Fatalf("the cookie came back as %d octets of %d", len(got), len(cookie))
	}
}

func TestAnNTSResponseCarriesItsCookiesEncrypted(t *testing.T) {
	s2c := ntsKey(0x22)
	cookies := [][]byte{aCookie(104), aCookie(108)}
	p := &Packet{Version: 4, Mode: ModeServer, Stratum: 2, Transmit: Timestamp(2) << 32}
	p.Extensions = []Extension{{Type: EFUniqueIdentifier, Body: make([]byte, UniqueIDLen)}}
	inner := make([]Extension, 0, len(cookies))
	for _, c := range cookies {
		inner = append(inner, NTSCookieField(c))
	}
	raw, err := SealNTS(p.Bytes(), s2c, inner)
	if err != nil {
		t.Fatal(err)
	}
	// Nothing about the cookies is visible on the wire: an observer who could
	// read them could follow this client to its next exchange.
	for _, c := range cookies {
		if bytes.Contains(raw, c) {
			t.Fatal("a replacement cookie is on the wire in the clear")
		}
	}
	got, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if n := got.NTS(); n.Cookies != 0 {
		t.Errorf("%d cookie fields are visible", n.Cookies)
	}
	fields, err := got.OpenNTS(s2c)
	if err != nil {
		t.Fatal(err)
	}
	back := NTSCookies(fields)
	if len(back) != len(cookies) {
		t.Fatalf("%d cookies inside, want %d", len(back), len(cookies))
	}
	for i := range cookies {
		if !bytes.Equal(back[i], cookies[i]) {
			t.Errorf("cookie %d came back changed", i)
		}
	}
}

// A cookie's length is not carried anywhere: the extension field pads to a
// multiple of four and says nothing about how much of it is padding. So a
// cookie that is not a multiple of four comes back longer than it left, and the
// server that issued it cannot open it. This is why the cookie format is sized
// to fit.
func TestACookieIsPaddedByTheFieldItTravelsIn(t *testing.T) {
	for _, n := range []int{101, 102, 103, 104} {
		cookie := aCookie(n)
		p := &Packet{Version: 4, Mode: ModeClient, Extensions: []Extension{NTSCookieField(cookie)}}
		got, err := Parse(p.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		back := NTSCookies(got.Extensions)
		if len(back) != 1 {
			t.Fatalf("%d cookies", len(back))
		}
		if len(back[0]) != pad4(n) {
			t.Fatalf("a cookie of %d octets came back as %d, want %d", n, len(back[0]), pad4(n))
		}
		if n%4 == 0 && !bytes.Equal(back[0], cookie) {
			t.Fatalf("a cookie of %d octets did not survive", n)
		}
	}
}

// Every octet of the packet is authenticated, which is the whole claim NTS
// makes: an attacker who changed a timestamp, a stratum, the cookie or the
// unique identifier must not be able to make the change stick.
func TestChangingAnythingBreaksTheAuthenticator(t *testing.T) {
	c2s := ntsKey(0x33)
	raw := ntsRequest(t, c2s, aCookie(104), 1)
	p, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	a, err := p.NTSAuth()
	if err != nil {
		t.Fatal(err)
	}
	// Every octet before the authenticator: the header and the plain fields.
	for i := 0; i < a.Offset; i++ {
		edited := append([]byte(nil), raw...)
		edited[i] ^= 0x01
		q, err := Parse(edited)
		if err != nil {
			continue // a length field made it unparseable, which is also a refusal
		}
		if _, err := q.OpenNTS(c2s); err == nil {
			t.Fatalf("octet %d of the authenticated region changed and the packet still verified", i)
		}
	}
	// And every octet of the authenticator itself.
	for i := a.Offset; i < len(raw); i++ {
		edited := append([]byte(nil), raw...)
		edited[i] ^= 0x01
		q, err := Parse(edited)
		if err != nil {
			continue
		}
		if _, err := q.OpenNTS(c2s); err == nil {
			t.Fatalf("octet %d of the authenticator changed and the packet still verified", i)
		}
	}
}

func TestTheWrongKeyDoesNotVerify(t *testing.T) {
	raw := ntsRequest(t, ntsKey(0x44), aCookie(104), 0)
	p, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.OpenNTS(ntsKey(0x45)); !errors.Is(err, ErrNTSVerify) {
		t.Fatalf("got %v, want %v", err, ErrNTSVerify)
	}
	// The other direction's key is a wrong key too, which is what stops a
	// packet the server sent being replayed to the server.
	if _, err := p.OpenNTS(ntsKey(0x44)); err != nil {
		t.Fatalf("the right key did not verify: %v", err)
	}
}

// A packet this relay assembled rather than parsed has no Raw, and the
// authenticated region is defined in terms of Raw. Verifying one would index
// past the end of a slice that is not there.
func TestVerifyingAPacketThatWasNeverParsedIsRefused(t *testing.T) {
	key := ntsKey(0xaa)
	raw, err := SealNTS((&Packet{Version: 4, Mode: ModeClient}).Bytes(), key, nil)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	unparsed := &Packet{Version: 4, Mode: ModeClient, Extensions: parsed.Extensions}
	if _, err := unparsed.OpenNTS(key); !errors.Is(err, ErrNTSAuth) {
		t.Fatalf("got %v, want %v", err, ErrNTSAuth)
	}
}

func TestAPacketWithNoAuthenticator(t *testing.T) {
	p := &Packet{Version: 4, Mode: ModeClient, Extensions: []Extension{NTSCookieField(aCookie(104))}}
	got, err := Parse(p.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := got.NTSAuth(); !errors.Is(err, ErrNoNTSAuth) {
		t.Fatalf("got %v, want %v", err, ErrNoNTSAuth)
	}
	if _, err := got.OpenNTS(ntsKey(1)); !errors.Is(err, ErrNoNTSAuth) {
		t.Fatalf("got %v, want %v", err, ErrNoNTSAuth)
	}
}

// Anything after the authenticator is unauthenticated, so a packet with
// anything after it is refused rather than verified and then acted on as far as
// the authenticator reached.
func TestNothingMayFollowTheAuthenticator(t *testing.T) {
	c2s := ntsKey(0x55)
	raw := ntsRequest(t, c2s, aCookie(104), 0)

	t.Run("an extension field", func(t *testing.T) {
		with := append(append([]byte(nil), raw...),
			Extension{Type: EFUniqueIdentifier, Body: make([]byte, 32)}.Bytes()...)
		p, err := Parse(with)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.OpenNTS(c2s); !errors.Is(err, ErrNTSAuth) {
			t.Fatalf("got %v, want %v", err, ErrNTSAuth)
		}
	})
	t.Run("a MAC", func(t *testing.T) {
		with := append(append([]byte(nil), raw...), make([]byte, 24)...)
		p, err := Parse(with)
		if err != nil {
			t.Fatal(err)
		}
		if !p.HasMAC {
			t.Skip("the tail did not read as a MAC")
		}
		if _, err := p.OpenNTS(c2s); !errors.Is(err, ErrNTSAuth) {
			t.Fatalf("got %v, want %v", err, ErrNTSAuth)
		}
	})
	t.Run("a crypto-NAK", func(t *testing.T) {
		with := append(append([]byte(nil), raw...), make([]byte, 4)...)
		p, err := Parse(with)
		if err != nil {
			t.Fatal(err)
		}
		if !p.CryptoNAK {
			t.Skip("the tail did not read as a crypto-NAK")
		}
		if _, err := p.OpenNTS(c2s); !errors.Is(err, ErrNTSAuth) {
			t.Fatalf("got %v, want %v", err, ErrNTSAuth)
		}
	})
}

// The two lengths inside the authenticator are a sender's claim about a field
// that also has a length, and a reader that trusted them would read past the
// end of one of them.
func TestAMalformedAuthenticatorIsRefused(t *testing.T) {
	body := func(nl, cl int, fill int) []byte {
		b := binary.BigEndian.AppendUint16(nil, uint16(nl)) //nolint:gosec // a test
		b = binary.BigEndian.AppendUint16(b, uint16(cl))    //nolint:gosec // a test
		return append(b, make([]byte, fill)...)
	}
	// The fills are chosen so the field is not four, twenty or twenty-four
	// octets long: a tail of one of those lengths is read as a MAC, which is
	// RFC 7822's own ambiguity and not what these cases are about.
	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"no body", nil},
		{"lengths and nothing else", body(16, 16, 0)},
		{"a nonce shorter than the standard allows", body(8, 16, 8+16)},
		{"no nonce at all", body(0, 16, 24)},
		{"a nonce past the bound", body(MaxNTSNonce+4, 16, MaxNTSNonce+4+16)},
		{"a ciphertext shorter than a tag", body(16, siv.TagSize-1, 16+16)},
		{"no ciphertext at all", body(16, 0, 24)},
		{"lengths past the body", body(16, 64, 16+16)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &Packet{Version: 4, Mode: ModeClient,
				Extensions: []Extension{{Type: EFNTSAuthenticator, Body: tc.body}}}
			got, err := Parse(p.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := got.NTSAuth(); !errors.Is(err, ErrNTSAuth) {
				t.Fatalf("got %v, want %v", err, ErrNTSAuth)
			}
		})
	}
}

// A nonce that is not a multiple of four is padded inside the field, and the
// explicit length is what says how much of it is nonce.
func TestANonceIsPaddedAndStillVerifies(t *testing.T) {
	key := ntsKey(0x66)
	for _, n := range []int{16, 17, 20, MaxNTSNonce} {
		nonce := make([]byte, n)
		for i := range nonce {
			nonce[i] = byte(i)
		}
		p := &Packet{Version: 4, Mode: ModeClient, Transmit: Timestamp(3) << 32}
		raw, err := sealNTSWith(p.Bytes(), key, nonce, nil)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Parse(raw)
		if err != nil {
			t.Fatalf("nonce of %d: %v", n, err)
		}
		a, err := got.NTSAuth()
		if err != nil {
			t.Fatalf("nonce of %d: %v", n, err)
		}
		if len(a.Nonce) != n {
			t.Errorf("nonce of %d came back as %d", n, len(a.Nonce))
		}
		if _, err := got.OpenNTS(key); err != nil {
			t.Errorf("nonce of %d did not verify: %v", n, err)
		}
	}
}

// Two seals of the same packet differ, because the nonce is fresh. AES-SIV
// survives a repeated nonce, but a repeated one would make a client's requests
// linkable to each other, which is what NTS is for.
func TestTwoSealsOfOnePacketDiffer(t *testing.T) {
	key := ntsKey(0x77)
	p := (&Packet{Version: 4, Mode: ModeClient}).Bytes()
	a, err := SealNTS(p, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := SealNTS(p, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two authenticators over one packet are identical")
	}
}

// The placeholder exists so that a request is as large as the response it asks
// for. If it were not, a server answering a small request with a handful of
// cookies would be an amplifier.
func TestAResponseIsNoLargerThanTheRequestThatAskedForIt(t *testing.T) {
	c2s, s2c := ntsKey(0x88), ntsKey(0x99)
	cookie := aCookie(104)
	const asked = MaxNTSCookies - 1
	req := ntsRequest(t, c2s, cookie, asked)

	p := &Packet{Version: 4, Mode: ModeServer, Stratum: 2}
	p.Extensions = []Extension{{Type: EFUniqueIdentifier, Body: make([]byte, UniqueIDLen)}}
	var inner []Extension
	for i := 0; i < asked+1; i++ {
		inner = append(inner, NTSCookieField(cookie))
	}
	resp, err := SealNTS(p.Bytes(), s2c, inner)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp) > len(req) {
		t.Fatalf("a response of %d octets to a request of %d is an amplifier", len(resp), len(req))
	}
}

func TestParseExtensionsRefusesWhatItCannotRead(t *testing.T) {
	good := append(Extension{Type: EFNTSCookie, Body: aCookie(20)}.Bytes(),
		Extension{Type: EFUniqueIdentifier, Body: make([]byte, 32)}.Bytes()...)
	got, err := ParseExtensions(good)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("%d fields", len(got))
	}
	if n, err := ParseExtensions(nil); err != nil || n != nil {
		t.Errorf("empty: %v %v", n, err)
	}
	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"a header cut in half", []byte{0, 1, 0}},
		{"a length below the minimum", []byte{0, 1, 0, 8, 0, 0, 0, 0}},
		{"a length past what is there", []byte{0, 1, 0, 32, 0, 0, 0, 0}},
		{"trailing octets after a whole field",
			append(Extension{Type: EFNTSCookie, Body: aCookie(20)}.Bytes(), 1, 2, 3)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseExtensions(tc.in); err == nil {
				t.Fatal("parsed")
			}
		})
	}
}

// More encrypted fields than one packet may carry: the plaintext is
// authenticated, so this is a peer with a bug rather than an attacker, and it is
// still bounded because it is still a loop over a length a peer chose.
func TestTooManyEncryptedFieldsAreRefused(t *testing.T) {
	var b []byte
	for i := 0; i <= MaxExtensions; i++ {
		b = append(b, Extension{Type: EFNTSCookie, Body: make([]byte, 12)}.Bytes()...)
	}
	if _, err := ParseExtensions(b); !errors.Is(err, ErrExtension) {
		t.Fatalf("got %v, want %v", err, ErrExtension)
	}
}

func TestSealingRefusesAKeyItCannotUse(t *testing.T) {
	if _, err := SealNTS((&Packet{Version: 4, Mode: ModeClient}).Bytes(), make([]byte, 17), nil); err == nil {
		t.Fatal("sealed under a 17-octet key")
	}
}

func TestNTSCookiesIgnoresWhatIsNotACookie(t *testing.T) {
	fields := []Extension{
		{Type: EFUniqueIdentifier, Body: make([]byte, 32)},
		NTSCookieField(aCookie(104)),
		{Type: EFNTSCookie, Body: nil},
		{Type: EFNTSCookie, Body: make([]byte, MaxNTSCookie+4)},
		NTSPlaceholderField(104),
	}
	got := NTSCookies(fields)
	if len(got) != 1 || len(got[0]) != 104 {
		t.Fatalf("%d cookies through the filter", len(got))
	}
}

func TestAUniqueIdentifierIsRandomAndLongEnough(t *testing.T) {
	a, err := NTSUniqueIDField()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NTSUniqueIDField()
	if err != nil {
		t.Fatal(err)
	}
	// RFC 8915 s5.3 requires at least 32 octets, because it is what ties an
	// answer to the request that asked for it.
	if a.Type != EFUniqueIdentifier || len(a.Body) < 32 {
		t.Fatalf("a unique identifier of %d octets, type %d", len(a.Body), a.Type)
	}
	if bytes.Equal(a.Body, b.Body) {
		t.Fatal("two unique identifiers are the same, so an answer to one would answer the other")
	}
}
