package ntp

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

// hexBytes is a test's way of writing a packet the way a capture shows
// it.
func hexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// serverPacket is a plain NTPv4 server answer: leap none, version 4,
// mode 4, stratum 2, poll 6, precision -20, a root delay and dispersion,
// a reference identifier, and four timestamps.
func serverPacket() []byte {
	p := &Packet{
		Leap: LeapNone, Version: 4, Mode: ModeServer, Stratum: 2,
		Poll: 6, Precision: -20,
		RootDelay:      ShortOf(12 * time.Millisecond),
		RootDispersion: ShortOf(3 * time.Millisecond),
		Reference:      TimestampOf(time.Date(2026, 3, 2, 8, 0, 0, 0, time.UTC)),
		Origin:         TimestampOf(time.Date(2026, 3, 2, 8, 1, 0, 0, time.UTC)),
		Receive:        TimestampOf(time.Date(2026, 3, 2, 8, 1, 0, 10_000_000, time.UTC)),
		Transmit:       TimestampOf(time.Date(2026, 3, 2, 8, 1, 0, 11_000_000, time.UTC)),
	}
	copy(p.ReferenceID[:], []byte{10, 0, 0, 1})
	return p.Bytes()
}

// A packet renders and parses back to itself, field for field. This is
// the floor: a relay that could not read what it writes could not read
// what a server writes either.
func TestAPacketRoundTrips(t *testing.T) {
	raw := serverPacket()
	if len(raw) != HeaderLen {
		t.Fatalf("a header is %d octets, got %d", HeaderLen, len(raw))
	}
	p, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.Leap != LeapNone || p.Version != 4 || p.Mode != ModeServer {
		t.Errorf("first octet: %+v", p)
	}
	if p.Stratum != 2 || p.Poll != 6 || p.Precision != -20 {
		t.Errorf("stratum %d poll %d precision %d", p.Stratum, p.Poll, p.Precision)
	}
	if got := p.RootDelay.Duration(); got < 11*time.Millisecond || got > 13*time.Millisecond {
		t.Errorf("root delay %v", got)
	}
	if !bytes.Equal(p.Raw, raw) {
		t.Error("Raw is not the bytes that arrived")
	}
	if !bytes.Equal(p.Bytes(), raw) {
		t.Error("a parsed packet does not render back to itself")
	}
	// A signed precision survives: the field is a power of two and it is
	// negative on every clock anybody would use.
	if p.Precision >= 0 {
		t.Error("precision read as unsigned")
	}
}

// The dispatch reads the first octet and nothing else, because a version
// or a mode this parser does not read is a different layout rather than
// this one with another number in it.
func TestTheDispatchReadsTheFirstOctetOnly(t *testing.T) {
	for _, tc := range []struct {
		name     string
		first    byte
		version  uint8
		mode     Mode
		parsable bool
	}{
		{"a version 4 client", 0x23, 4, ModeClient, true},
		{"a version 4 server", 0x24, 4, ModeServer, true},
		{"a version 3 client", 0x1B, 3, ModeClient, true},
		{"a version 2 client", 0x13, 2, ModeClient, true},
		// Version 1 has no mode field: the bits are zero, and the
		// packet is still this layout. What it means is decided by
		// EffectiveMode below rather than by refusing to read it.
		{"a version 1 packet", 0x08, 1, ModeReserved, true},
		{"version 5, which is not this layout", 0x2B, 5, ModeClient, false},
		{"version 0", 0x03, 0, ModeClient, false},
		{"mode 6, the control protocol", 0x26, 4, ModeControl, false},
		{"mode 7, the private one monlist belongs to", 0x27, 4, ModePrivate, false},
		{"a symmetric active peer", 0x21, 4, ModeSymActive, true},
		{"a broadcast", 0x25, 4, ModeBroadcast, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k, err := Classify([]byte{tc.first})
			if err != nil {
				t.Fatal(err)
			}
			if k.Version != tc.version || k.Mode != tc.mode {
				t.Fatalf("version %d mode %s", k.Version, k.Mode)
			}
			if k.Parsable() != tc.parsable {
				t.Fatalf("parsable %v, want %v", k.Parsable(), tc.parsable)
			}
			// And the parser itself refuses what the dispatch refuses,
			// rather than trusting the caller to have asked.
			full := append([]byte{tc.first}, make([]byte, HeaderLen-1)...)
			_, err = Parse(full)
			if tc.parsable && err != nil {
				t.Fatalf("parse: %v", err)
			}
			if !tc.parsable && err == nil {
				t.Fatal("parsed a layout this parser does not read")
			}
		})
	}
	if _, err := Classify(nil); err == nil {
		t.Error("an empty packet classified")
	}
}

// What the parser refuses, and why each one matters.
func TestParseRefuses(t *testing.T) {
	short := make([]byte, HeaderLen-1)
	short[0] = 0x23
	if _, err := Parse(short); !errors.Is(err, ErrShort) {
		t.Errorf("a packet shorter than the header: %v", err)
	}
	long := make([]byte, MaxPacket+1)
	long[0] = 0x23
	if _, err := Parse(long); !errors.Is(err, ErrBounds) {
		t.Errorf("a packet past the bound: %v", err)
	}
	// A version this parser does not read, with a body that would parse
	// perfectly as a version 4 packet: the refusal is the version, not
	// the body.
	v5 := serverPacket()
	v5[0] = byte(LeapNone)<<6 | 5<<3 | byte(ModeServer)
	if _, err := Parse(v5); !errors.Is(err, ErrVersion) {
		t.Errorf("version 5: %v", err)
	}
	ctrl := serverPacket()
	ctrl[0] = byte(LeapNone)<<6 | 4<<3 | byte(ModeControl)
	if _, err := Parse(ctrl); !errors.Is(err, ErrMode) {
		t.Errorf("mode 6: %v", err)
	}
}

// The tail after the header is extension fields, a MAC, or both, and the
// rules for telling them apart are the ones RFC 7822 documents.
func TestTheTailIsExtensionFieldsOrAMAC(t *testing.T) {
	base := serverPacket()
	ef := func(typ uint16, n int) []byte {
		e := Extension{Type: typ, Body: make([]byte, n-4)}
		return e.Bytes()
	}
	for _, tc := range []struct {
		name      string
		tail      []byte
		exts      int
		hasMAC    bool
		nak       bool
		ambiguous bool
		bad       bool
	}{
		{name: "nothing at all"},
		{name: "a key identifier alone is a crypto-NAK", tail: make([]byte, 4), nak: true},
		{name: "twenty octets is a key identifier and a 128-bit digest",
			tail: make([]byte, 20), hasMAC: true},
		{name: "twenty-four is a 160-bit digest", tail: make([]byte, 24), hasMAC: true},
		{name: "one extension field", tail: ef(EFUniqueIdentifier, 36), exts: 1},
		{name: "two extension fields",
			tail: append(ef(EFUniqueIdentifier, 36), ef(EFNTSCookie, 104)...), exts: 2},
		{name: "an extension field and a MAC",
			tail: append(ef(EFUniqueIdentifier, 36), make([]byte, 20)...), exts: 1, hasMAC: true},
		{name: "a field of the minimum length", tail: ef(EFChecksumComplement, MinExtensionLen), exts: 1},
		// A length field below the minimum: written by hand, because
		// the encoder pads up to the minimum and could not produce it.
		{name: "a field below the minimum length",
			tail: append([]byte{0x01, 0x04, 0x00, 0x0C}, make([]byte, 8)...), bad: true},
		{name: "a tail of two octets", tail: make([]byte, 2), bad: true},
		{name: "a tail of eight octets that is neither", tail: make([]byte, 8), bad: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Parse(append(append([]byte{}, base...), tc.tail...))
			if tc.bad {
				if err == nil {
					t.Fatalf("parsed as %+v", p)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(p.Extensions) != tc.exts {
				t.Errorf("%d extension fields, want %d", len(p.Extensions), tc.exts)
			}
			if p.HasMAC != tc.hasMAC || p.CryptoNAK != tc.nak {
				t.Errorf("mac %v nak %v", p.HasMAC, p.CryptoNAK)
			}
			// The authenticated bytes end where the MAC starts, and the
			// MAC covers the header and every field before it.
			want := HeaderLen
			for _, e := range p.Extensions {
				want += e.Length
			}
			if p.MACStart != want {
				t.Errorf("MACStart %d, want %d", p.MACStart, want)
			}
		})
	}
	// A field whose length field lies about how much is there.
	lying := append(append([]byte{}, base...), 0x01, 0x04, 0x00, 0x40)
	lying = append(lying, make([]byte, 28)...)
	if _, err := Parse(lying); err == nil {
		t.Error("a length field past the end of the packet was believed")
	}
	// A length that is not a multiple of four.
	odd := append(append([]byte{}, base...), 0x01, 0x04, 0x00, 0x1E)
	odd = append(odd, make([]byte, 26)...)
	if _, err := Parse(odd); err == nil {
		t.Error("a length that is not a multiple of four was believed")
	}
}

// The ambiguity of RFC 7822 is reported rather than resolved silently: a
// tail that is both a MAC and a well-formed extension field is read as a
// MAC, and the packet says the reading was a choice.
func TestTheMACAmbiguityIsReported(t *testing.T) {
	base := serverPacket()
	// A 24-octet tail whose first four octets are a valid field header
	// of length 24: both readings parse.
	tail := make([]byte, 24)
	tail[0], tail[1] = 0x01, 0x04
	tail[2], tail[3] = 0x00, 0x18
	p, err := Parse(append(append([]byte{}, base...), tail...))
	if err != nil {
		t.Fatal(err)
	}
	if !p.HasMAC {
		t.Error("the tail was not read as a MAC")
	}
	if !p.MACAmbiguous {
		t.Error("the ambiguity was not reported")
	}
	// A tail that can only be a MAC is not ambiguous.
	plain := make([]byte, 20)
	p2, err := Parse(append(append([]byte{}, base...), plain...))
	if err != nil {
		t.Fatal(err)
	}
	if p2.MACAmbiguous {
		t.Error("a tail with no other reading was called ambiguous")
	}
}

// Versions before 4 have no extension fields, so a tail there can only
// be a MAC. A relay that read one as an extension field would be
// inventing a meaning the sender's protocol does not have.
func TestBeforeVersion4TheTailIsOnlyAMAC(t *testing.T) {
	base := serverPacket()
	base[0] = byte(LeapNone)<<6 | 3<<3 | byte(ModeServer)
	mac := append(append([]byte{}, base...), make([]byte, 20)...)
	p, err := Parse(mac)
	if err != nil {
		t.Fatalf("a version 3 packet with a MAC: %v", err)
	}
	if !p.HasMAC || len(p.Extensions) != 0 {
		t.Errorf("mac %v extensions %d", p.HasMAC, len(p.Extensions))
	}
	ext := Extension{Type: EFUniqueIdentifier, Body: make([]byte, 32)}
	if _, err := Parse(append(append([]byte{}, base...), ext.Bytes()...)); err == nil {
		t.Error("a version 3 packet carrying an extension field was accepted")
	}
}

// The visible NTS fields say what is present. They do not say anything
// is authentic, and the type is named so that nothing reads them as if
// they did.
func TestTheNTSFieldsSayWhatIsPresentAndNoMore(t *testing.T) {
	base := serverPacket()
	tail := Extension{Type: EFUniqueIdentifier, Body: make([]byte, 32)}.Bytes()
	tail = append(tail, Extension{Type: EFNTSCookie, Body: make([]byte, 100)}.Bytes()...)
	tail = append(tail, Extension{Type: EFNTSCookiePlaceholder, Body: make([]byte, 100)}.Bytes()...)
	tail = append(tail, Extension{Type: EFNTSAuthenticator, Body: make([]byte, 64)}.Bytes()...)
	p, err := Parse(append(append([]byte{}, base...), tail...))
	if err != nil {
		t.Fatal(err)
	}
	n := p.NTS()
	if !n.Present || len(n.UniqueID) != 32 || n.Cookies != 1 || n.Placeholders != 1 || !n.Authenticator {
		t.Fatalf("nts fields: %+v", n)
	}
	if n.AuthenticatorLen != 68 {
		t.Errorf("authenticator length %d", n.AuthenticatorLen)
	}
	// A packet with none of them says so, which is what makes "this
	// association is NTS" a fact a policy can hold.
	plain, err := Parse(serverPacket())
	if err != nil {
		t.Fatal(err)
	}
	if plain.NTS().Present {
		t.Error("a plain packet reported NTS fields")
	}
}

// A field type this relay does not know is counted, because a relay
// cannot decide about an instruction it cannot read -- and that includes
// every extension field Autokey ever defined.
func TestUnknownExtensionFieldsAreCounted(t *testing.T) {
	base := serverPacket()
	tail := Extension{Type: 0x0002, Body: make([]byte, 32)}.Bytes()
	tail = append(tail, Extension{Type: EFUniqueIdentifier, Body: make([]byte, 32)}.Bytes()...)
	p, err := Parse(append(append([]byte{}, base...), tail...))
	if err != nil {
		t.Fatal(err)
	}
	if p.UnknownExtensions() != 1 {
		t.Errorf("unknown fields: %d", p.UnknownExtensions())
	}
	if got := ExtensionName(0x0002); got != "unknown_0x0002" {
		t.Errorf("name %q", got)
	}
	if !KnownExtension(EFNTSAuthenticator) || KnownExtension(0x0002) {
		t.Error("the registry table does not say what it knows")
	}
}

// Stratum 0 is a message rather than a time, and the four reference
// identifier octets are its code. Reading it as a very good clock is the
// mistake; reading the identifier as an address is the other one.
func TestStratumZeroIsAMessageAndTheReferenceIDIsNotAlwaysAnAddress(t *testing.T) {
	kod := &Packet{Version: 4, Mode: ModeServer, Stratum: 0}
	copy(kod.ReferenceID[:], "RATE")
	p, err := Parse(kod.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !p.KissOfDeath() || p.KissCode() != "RATE" {
		t.Errorf("kiss: %v %q", p.KissOfDeath(), p.KissCode())
	}
	if got := p.RefID(); got != "kiss:RATE" {
		t.Errorf("refid %q", got)
	}
	// A stratum 1 server's identifier is its reference clock's name.
	one := &Packet{Version: 4, Mode: ModeServer, Stratum: 1}
	copy(one.ReferenceID[:], "GPS")
	p1, _ := Parse(one.Bytes())
	if got := p1.RefID(); got != "refclock:GPS" {
		t.Errorf("refid %q", got)
	}
	if p1.KissOfDeath() || p1.KissCode() != "" {
		t.Error("stratum 1 read as a kiss")
	}
	// At stratum 2 and above it may be an address and may be four octets
	// of a hash, and the field does not say which -- so neither does the
	// rendering.
	two := &Packet{Version: 4, Mode: ModeServer, Stratum: 2}
	copy(two.ReferenceID[:], []byte{192, 0, 2, 1})
	p2, _ := Parse(two.Bytes())
	if got := p2.RefID(); got == "192.0.2.1" {
		t.Error("a stratum 2 identifier was rendered as if it could only be an address")
	}
	// An unsynchronised server says so in the leap indicator, which is a
	// different statement from stratum 16 and worth both checks.
	un := &Packet{Version: 4, Mode: ModeServer, Stratum: 16, Leap: LeapUnsynchronised}
	p3, _ := Parse(un.Bytes())
	if !p3.Unsynchronised() {
		t.Error("the leap indicator did not report an unsynchronised server")
	}
	q := p3.Quality(time.Now())
	if !q.Unsynchronised || q.Stratum != 16 {
		t.Errorf("quality: %+v", q)
	}
}

// The offset and delay arithmetic, including across the end of an era:
// the subtraction is modular and the result is signed, so an exchange
// that straddles 2036 gives milliseconds rather than a century.
func TestOffsetAndDelayAcrossAnEra(t *testing.T) {
	// A clean exchange: the request left at t1, the server saw it 20ms
	// later, answered 1ms after that, and the answer arrived 20ms on.
	t1 := TimestampOf(time.Date(2026, 3, 2, 8, 0, 0, 0, time.UTC))
	p := &Packet{
		Receive:  TimestampOf(time.Date(2026, 3, 2, 8, 0, 0, 20_000_000, time.UTC)),
		Transmit: TimestampOf(time.Date(2026, 3, 2, 8, 0, 0, 21_000_000, time.UTC)),
	}
	t4 := TimestampOf(time.Date(2026, 3, 2, 8, 0, 0, 41_000_000, time.UTC))
	if off := Offset(t1, p, t4); off < -time.Millisecond || off > time.Millisecond {
		t.Errorf("offset %v, want about zero", off)
	}
	if d := Delay(t1, p, t4); d < 39*time.Millisecond || d > 41*time.Millisecond {
		t.Errorf("delay %v, want about 40ms", d)
	}
	// The same exchange with the era rolling over in the middle of it.
	// The request leaves in the last hundredth of a second of the era and
	// everything after it lands in the next one, so the seconds field
	// wraps between T1 and T2: the subtraction has to be the modular one
	// the protocol specifies, or a forty-millisecond round trip reads as
	// a hundred and thirty-six years.
	const ms = Timestamp(1<<32) / 1000 // one millisecond of the fraction
	e1 := Timestamp(0xFFFFFFFF)<<32 | 990*ms
	ep := &Packet{Receive: e1 + 20*ms, Transmit: e1 + 21*ms}
	e4 := e1 + 41*ms
	if e1>>32 != 0xFFFFFFFF || e4>>32 != 0 {
		t.Fatalf("the exchange does not cross the era: %016x to %016x", uint64(e1), uint64(e4))
	}
	if off := Offset(e1, ep, e4); off < -2*time.Millisecond || off > 2*time.Millisecond {
		t.Errorf("offset across the era %v, want about zero", off)
	}
	if d := Delay(e1, ep, e4); d < 39*time.Millisecond || d > 41*time.Millisecond {
		t.Errorf("delay across the era %v, want about 40ms", d)
	}
	// A delay that comes out negative is not a measurement.
	if d := Delay(t4, p, t1); d != 0 {
		t.Errorf("a negative delay was reported as %v", d)
	}
	// A timestamp places itself in the era nearest the receiving clock.
	now := time.Date(2036, 3, 2, 8, 0, 0, 0, time.UTC)
	ts := TimestampOf(now)
	if got := ts.Time(now); got.Sub(now).Abs() > time.Millisecond {
		t.Errorf("a timestamp in the second era came back as %v", got)
	}
	if !Timestamp(0).Time(now).IsZero() {
		t.Error("an unset timestamp came back as a time")
	}
	// The fixed point saturates rather than wrapping: a wrapped root
	// dispersion reads as an excellent clock.
	if got := ShortOf(100 * time.Hour); got != 0xFFFFFFFF {
		t.Errorf("a duration the format cannot hold: %08x", uint32(got))
	}
	if ShortOf(-time.Second) != 0 {
		t.Error("a negative duration should be zero")
	}
}

// An answer is tied to its question by the origin timestamp and nothing
// else, which is why the check is here and not optional.
func TestAnAnswerIsTiedToItsQuestion(t *testing.T) {
	sent := TimestampOf(time.Now())
	p := &Packet{Origin: sent}
	if !p.AnswersRequest(sent) {
		t.Error("the answer to the question was not recognised")
	}
	if p.AnswersRequest(sent + 1) {
		t.Error("an answer to another question was accepted")
	}
	if (&Packet{}).AnswersRequest(0) {
		t.Error("an empty origin matched an unsent request")
	}
}

// AES-CMAC against the vectors of RFC 4493, subkeys included so a
// failure says which half is wrong.
func TestAESCMACAgainstRFC4493(t *testing.T) {
	key := hexBytes(t, "2b7e151628aed2a6abf7158809cf4f3c")
	// The subkey derivation.
	var l [16]byte
	block := aesBlock(t, key)
	block.Encrypt(l[:], l[:])
	if got := hex.EncodeToString(l[:]); got != "7df76b0c1ab899b33e42f047b91b546f" {
		t.Fatalf("L = %s", got)
	}
	k1 := shiftAndXor(l[:])
	if got := hex.EncodeToString(k1); got != "fbeed618357133667c85e08f7236a8de" {
		t.Fatalf("K1 = %s", got)
	}
	k2 := shiftAndXor(k1)
	if got := hex.EncodeToString(k2); got != "f7ddac306ae266ccf90bc11ee46d513b" {
		t.Fatalf("K2 = %s", got)
	}
	msg := hexBytes(t, "6bc1bee22e409f96e93d7e117393172a"+
		"ae2d8a571e03ac9c9eb76fac45af8e51"+
		"30c81c46a35ce411e5fbc1191a0a52ef"+
		"f69f2445df4f9b17ad2b417be66c3710")
	for _, tc := range []struct {
		n    int
		want string
	}{
		{0, "bb1d6929e95937287fa37d129b756746"},
		{16, "070a16b46b4d4144f79bdd9dd04a287c"},
		{40, "dfa66747de9ae63030ca32611497c827"},
		{64, "51f0bebf7e3b9d92fc49741779363cfe"},
	} {
		got, err := cmacAES(key, msg[:tc.n])
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(got) != tc.want {
			t.Errorf("CMAC of %d octets = %s, want %s", tc.n, hex.EncodeToString(got), tc.want)
		}
	}
}

// A packet's MAC verifies against the key it names, and every way of
// getting that wrong is a refusal rather than a pass.
func TestMACVerification(t *testing.T) {
	key := Key{ID: 7, Algorithm: AlgAESCMAC, Secret: hexBytes(t, "2b7e151628aed2a6abf7158809cf4f3c")}
	keys := Keys{7: key}
	signed, err := key.Sign(serverPacket())
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(signed)
	if err != nil {
		t.Fatal(err)
	}
	if !p.HasMAC || p.KeyID != 7 {
		t.Fatalf("mac %v key %d", p.HasMAC, p.KeyID)
	}
	if err := p.Verify(keys); err != nil {
		t.Fatalf("a packet this key signed: %v", err)
	}
	// One bit of the digest.
	bad := append([]byte{}, signed...)
	bad[len(bad)-1] ^= 1
	pb, _ := Parse(bad)
	if err := pb.Verify(keys); err == nil {
		t.Error("a digest with a bit flipped verified")
	}
	// One bit of the packet the digest covers.
	body := append([]byte{}, signed...)
	body[2] ^= 1
	pc, _ := Parse(body)
	if err := pc.Verify(keys); err == nil {
		t.Error("a packet edited under its own MAC verified")
	}
	// A key identifier nobody holds.
	other := append([]byte{}, signed...)
	other[HeaderLen+3] = 9
	po, _ := Parse(other)
	if err := po.Verify(keys); err == nil {
		t.Error("a key nobody holds verified")
	}
	// A packet with no MAC at all is not a packet that failed: it is a
	// different statement, and a policy that requires authentication
	// has to be able to tell them apart.
	plain, _ := Parse(serverPacket())
	if err := plain.Verify(keys); !errors.Is(err, ErrNoMAC) {
		t.Errorf("a packet with no MAC: %v", err)
	}
	// A digest of the wrong length for the key's algorithm: twenty
	// octets of digest where AES-CMAC produces sixteen. The length is
	// taken from the algorithm rather than from the packet, so this is a
	// refusal rather than a comparison of the first sixteen.
	sha := Key{ID: 7, Algorithm: AlgSHA1, Secret: key.Secret}
	wrongLen, err := sha.Sign(serverPacket())
	if err != nil {
		t.Fatal(err)
	}
	pw, err := Parse(wrongLen)
	if err != nil {
		t.Fatal(err)
	}
	err = pw.Verify(keys)
	if err == nil {
		t.Error("a digest of the wrong length for the algorithm verified")
	} else if !strings.Contains(err.Error(), "20 octets of digest where aes-cmac produces 16") {
		// The length comes from the key's algorithm, so this is a
		// refusal that names the mistake rather than a comparison of the
		// first sixteen octets that happens to fail.
		t.Errorf("a digest of the wrong length reads as an ordinary failure: %v", err)
	}
	// The legacy algorithms verify only where a configuration names
	// them, and they are different keys.
	legacy := Key{ID: 1, Algorithm: AlgMD5, Secret: []byte("secret")}
	ls, err := legacy.Sign(serverPacket())
	if err != nil {
		t.Fatal(err)
	}
	pl, _ := Parse(ls)
	if err := pl.Verify(Keys{1: legacy}); err != nil {
		t.Errorf("a legacy MD5 MAC: %v", err)
	}
	if err := pl.Verify(Keys{1: {ID: 1, Algorithm: AlgAESCMAC, Secret: key.Secret}}); err == nil {
		t.Error("an MD5 digest verified as AES-CMAC")
	}
	// An algorithm this build does not compute, and a key the algorithm
	// cannot take, are configuration mistakes and say so.
	if _, err := (Key{Algorithm: "sha3"}).Compute(nil); err == nil {
		t.Error("an algorithm nobody implements was accepted")
	}
	if _, err := (Key{Algorithm: AlgAESCMAC, Secret: []byte("short")}).Compute(nil); err == nil {
		t.Error("a key AES cannot take was accepted")
	}
	// SHA-1 is the other legacy shape, at 24 octets of tail.
	legacySHA := Key{ID: 2, Algorithm: AlgSHA1, Secret: []byte("secret")}
	ss, _ := legacySHA.Sign(serverPacket())
	pss, err := Parse(ss)
	if err != nil {
		t.Fatal(err)
	}
	if len(pss.MAC) != 20 {
		t.Fatalf("a sha1 digest is %d octets", len(pss.MAC))
	}
	if err := pss.Verify(Keys{2: legacySHA}); err != nil {
		t.Errorf("a legacy SHA-1 MAC: %v", err)
	}
}

// A crypto-NAK is a key identifier with no digest: a server saying it
// will not authenticate this exchange. It is not a MAC that failed.
func TestACryptoNAKIsNotAFailedMAC(t *testing.T) {
	raw := append(serverPacket(), 0, 0, 0, 7)
	p, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !p.CryptoNAK || p.HasMAC {
		t.Fatalf("nak %v mac %v", p.CryptoNAK, p.HasMAC)
	}
	if err := p.Verify(Keys{7: {ID: 7, Algorithm: AlgAESCMAC, Secret: make([]byte, 16)}}); !errors.Is(err, ErrNoMAC) {
		t.Errorf("verifying a crypto-NAK: %v", err)
	}
}

// The modes and their names, in both directions, because a configuration
// says "client" and a log says "client" and the two have to be the same
// table.
func TestModeNames(t *testing.T) {
	for _, name := range []string{"symmetric_active", "symmetric_passive", "client", "server", "broadcast", "control", "private"} {
		m, ok := ModeOf(name)
		if !ok {
			t.Fatalf("%q is not a mode", name)
		}
		if m.String() != name {
			t.Errorf("%s round tripped as %s", name, m)
		}
	}
	if _, ok := ModeOf("gossip"); ok {
		t.Error("a mode nobody defined was accepted")
	}
	if Mode(9).String() != "mode_9" {
		t.Errorf("an out-of-range mode: %s", Mode(9))
	}
	if !ModeClient.TimeService() || ModeControl.TimeService() || !ModePrivate.Management() {
		t.Error("the time-service and management classification is wrong")
	}
	if LeapUnsynchronised.String() != "unsynchronised" || LeapNone.String() != "none" ||
		LeapAddSecond.String() != "add_second" || LeapDeleteSecond.String() != "delete_second" {
		t.Error("the leap indicator names")
	}
}

// The mode a policy decides about, for the one version whose mode field
// does not exist.
func TestTheEffectiveMode(t *testing.T) {
	for _, tc := range []struct {
		name string
		kind Kind
		want Mode
	}{
		{"a version 1 packet with the bits zero is a client", Kind{Version: 1, Mode: ModeReserved}, ModeClient},
		{"a version 1 packet that does name a mode keeps it", Kind{Version: 1, Mode: ModeServer}, ModeServer},
		{"a version 4 packet with the bits zero is reserved and nothing else",
			Kind{Version: 4, Mode: ModeReserved}, ModeReserved},
		{"every other mode is itself", Kind{Version: 4, Mode: ModeSymActive}, ModeSymActive},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.kind.EffectiveMode(); got != tc.want {
				t.Fatalf("effective mode %s, want %s", got, tc.want)
			}
		})
	}
}

// FuzzParse drives the parser with whatever arrives. The properties are
// the ones the relay rests on: nothing panics, a parsed packet's
// authenticated region is inside the packet, and the extension fields
// account for exactly the bytes between the header and the MAC.
func FuzzParse(f *testing.F) {
	f.Add(serverPacket())
	f.Add(append(serverPacket(), make([]byte, 20)...))
	f.Add(append(serverPacket(), Extension{Type: EFNTSCookie, Body: make([]byte, 100)}.Bytes()...))
	f.Fuzz(func(t *testing.T, data []byte) {
		k, err := Classify(data)
		if err != nil {
			return
		}
		p, err := Parse(data)
		if err != nil {
			return
		}
		if !k.Parsable() {
			t.Fatalf("a layout the dispatch refuses was parsed: version %d mode %s", k.Version, k.Mode)
		}
		if p.MACStart < HeaderLen || p.MACStart > len(data) {
			t.Fatalf("authenticated region ends at %d of %d", p.MACStart, len(data))
		}
		sum := HeaderLen
		for _, e := range p.Extensions {
			if e.Length < MinExtensionLen || e.Length%4 != 0 {
				t.Fatalf("a field of length %d", e.Length)
			}
			sum += e.Length
		}
		if sum != p.MACStart {
			t.Fatalf("the fields account for %d octets, the MAC starts at %d", sum, p.MACStart)
		}
		if p.HasMAC && len(p.MAC) != 16 && len(p.MAC) != 20 {
			t.Fatalf("a digest of %d octets", len(p.MAC))
		}
		if p.CryptoNAK && len(p.MAC) != 0 {
			t.Fatal("a crypto-NAK with a digest")
		}
		// The NTS reading never panics and never claims more than the
		// fields present.
		n := p.NTS()
		if n.Authenticator && !n.Present {
			t.Fatal("an authenticator without NTS present")
		}
	})
}

// Every packet the parser accepts renders back to the octets it came
// from.
//
// This is the invariant behind the relay's rule that a forwarded packet
// is the bytes that arrived: the two readings can only agree for as long
// as nothing the parser takes in is dropped when it is written out. A
// field this package stops modelling -- padding inside an extension
// field, a digest of a length it does not expect, a tail it reads one way
// and writes another -- shows up here, on the packet shape that lost it,
// rather than in a plant whose devices are authenticating different bytes
// from the ones the relay checked.
func TestEveryAcceptedPacketRendersBackToItself(t *testing.T) {
	key := Key{ID: 7, Algorithm: AlgAESCMAC, Secret: hexBytes(t, "2b7e151628aed2a6abf7158809cf4f3c")}
	sha := Key{ID: 8, Algorithm: AlgSHA1, Secret: key.Secret}
	sign := func(t *testing.T, k Key, b []byte) []byte {
		t.Helper()
		out, err := k.Sign(b)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	withFields := func(fields ...Extension) []byte {
		p := &Packet{Leap: LeapNone, Version: 4, Mode: ModeClient, Stratum: 0, Poll: 6,
			Precision: -20, Transmit: TimestampOf(time.Date(2026, 3, 2, 8, 0, 0, 0, time.UTC))}
		p.Extensions = fields
		return p.Bytes()
	}
	// A 24-octet tail that is both a valid extension field and a MAC
	// shape: the parser reads it as a MAC and says the reading was a
	// choice, and it still has to write back what it read.
	ambiguous := append(withFields(), 0x01, 0x04, 0x00, 0x18)
	ambiguous = append(ambiguous, make([]byte, 20)...)
	// A version 3 packet, where the tail can only ever be a MAC.
	legacy := &Packet{Leap: LeapNone, Version: 3, Mode: ModeClient, Poll: 6, Precision: -20,
		Transmit: TimestampOf(time.Date(2026, 3, 2, 8, 0, 0, 0, time.UTC))}
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"a server's answer", serverPacket()},
		{"a client's request", withFields()},
		{"a 128-bit digest", sign(t, key, serverPacket())},
		{"a 160-bit digest", sign(t, sha, serverPacket())},
		{"a crypto-NAK", append(withFields(), 0, 0, 0, 7)},
		{"a known extension field", withFields(Extension{Type: EFUniqueIdentifier, Body: make([]byte, 32)})},
		{"a field this relay does not know", withFields(Extension{Type: 0x0002, Body: make([]byte, 28)})},
		{"the shortest field there is", withFields(Extension{Type: EFNTSCookie, Body: make([]byte, 12)})},
		{"three fields and a digest",
			sign(t, key, withFields(
				Extension{Type: EFUniqueIdentifier, Body: make([]byte, 32)},
				Extension{Type: EFNTSCookie, Body: make([]byte, 100)},
				Extension{Type: EFNTSAuthenticator, Body: make([]byte, 48)}))},
		{"an ambiguous tail", ambiguous},
		{"a version 3 packet with a digest", sign(t, key, legacy.Bytes())},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Parse(tc.raw)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got := p.Bytes(); !bytes.Equal(got, tc.raw) {
				t.Fatalf("rendered %d octets from %d:\n got %x\nwant %x", len(got), len(tc.raw), got, tc.raw)
			}
			if !bytes.Equal(p.Raw, tc.raw) {
				t.Errorf("Raw is not the datagram: %d octets of %d", len(p.Raw), len(tc.raw))
			}
		})
	}
}

// The three readings a relay makes of a server's own statement about
// itself: the synchronisation distance, when a leap second could really
// be announced, and whether the identifier matches the stratum that says
// how to read it.
func TestTheSynchronisationDistanceIsBothHalves(t *testing.T) {
	p := &Packet{RootDelay: ShortOf(400 * time.Millisecond),
		RootDispersion: ShortOf(100 * time.Millisecond)}
	// Half the delay plus the dispersion: 200ms + 100ms.
	if got := p.RootDistance(); got < 295*time.Millisecond || got > 305*time.Millisecond {
		t.Fatalf("distance %v, want about 300ms", got)
	}
	// Each half can sit inside its own bound while the sum does not,
	// which is why the sum is the number a bound is written about: a
	// delay of 900ms and a dispersion of 200ms are both under a second
	// and the distance is 650ms.
	both := &Packet{RootDelay: ShortOf(900 * time.Millisecond),
		RootDispersion: ShortOf(200 * time.Millisecond)}
	if both.RootDelay.Duration() > time.Second || both.RootDispersion.Duration() > time.Second {
		t.Fatal("a half is past a second, so this test proves nothing")
	}
	if got := both.RootDistance(); got < 645*time.Millisecond || got > 655*time.Millisecond {
		t.Errorf("distance %v, want about 650ms", got)
	}
	if (&Packet{}).RootDistance() != 0 {
		t.Error("an answer claiming no error at all")
	}
}

func TestALeapSecondOnlyHappensAtTheEndOfFourMonths(t *testing.T) {
	window := 24 * time.Hour
	for _, tc := range []struct {
		when string
		want bool
	}{
		{"2026-06-30T12:00:00Z", true}, // the end of June, where they happen
		{"2026-12-31T23:59:00Z", true}, // and the end of December
		{"2026-03-31T06:00:00Z", true}, // the two the IERS uses only if it must
		{"2026-09-30T00:30:00Z", true},
		{"2026-06-15T12:00:00Z", false}, // the middle of a month that has one
		{"2026-08-31T23:00:00Z", false}, // the end of one that never does
		{"2026-01-31T23:59:00Z", false},
	} {
		when, err := time.Parse(time.RFC3339, tc.when)
		if err != nil {
			t.Fatal(err)
		}
		if got := LeapPlausible(when, window); got != tc.want {
			t.Errorf("%s: %v", tc.when, got)
		}
	}
	// The window is the caller's, because implementations differ about
	// how early they announce. A month out is plausible with a month's
	// window and not with a day's.
	early, _ := time.Parse(time.RFC3339, "2026-06-05T12:00:00Z")
	if LeapPlausible(early, window) {
		t.Error("five days into June with a day's window")
	}
	if !LeapPlausible(early, 31*24*time.Hour) {
		t.Error("five days into June with a month's window")
	}
	// A window of zero is a day, not everything.
	if !LeapPlausible(mustTime(t, "2026-12-31T12:00:00Z"), 0) ||
		LeapPlausible(mustTime(t, "2026-12-01T12:00:00Z"), 0) {
		t.Error("a zero window is not a day")
	}
	// And only the two announcing values are announcements: an
	// unsynchronised clock is a different statement.
	if !LeapAddSecond.Announcing() || !LeapDeleteSecond.Announcing() {
		t.Error("an announcement is not one")
	}
	if LeapNone.Announcing() || LeapUnsynchronised.Announcing() {
		t.Error("not an announcement is one")
	}
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestTheTimestampsAreReadAgainstEachOther(t *testing.T) {
	now := time.Now()
	sound := func(edit func(*Packet)) *Packet {
		p := &Packet{Mode: ModeServer, Stratum: 2,
			Reference: TimestampOf(now.Add(-time.Minute)),
			Receive:   TimestampOf(now), Transmit: TimestampOf(now.Add(time.Millisecond))}
		if edit != nil {
			edit(p)
		}
		return p
	}
	if why := sound(nil).TimestampsConsistent(); why != "" {
		t.Fatalf("a sound answer: %s", why)
	}
	for _, tc := range []struct {
		name string
		edit func(*Packet)
	}{
		{"no transmit timestamp", func(p *Packet) { p.Transmit = 0 }},
		{"no receive timestamp", func(p *Packet) { p.Receive = 0 }},
		{"transmitted before received", func(p *Packet) { p.Transmit = TimestampOf(now.Add(-time.Second)) }},
		{"synchronised after the request arrived", func(p *Packet) { p.Reference = TimestampOf(now.Add(time.Hour)) }},
	} {
		if why := sound(tc.edit).TimestampsConsistent(); why == "" {
			t.Errorf("%s was called sound", tc.name)
		}
	}
	// A request is not an answer: the fields mean different things and a
	// client does not fill most of them in, so the check says nothing
	// about one.
	req := &Packet{Mode: ModeClient, Transmit: TimestampOf(now)}
	if why := req.TimestampsConsistent(); why != "" {
		t.Errorf("a client's request was judged as an answer: %s", why)
	}
	// An exchange across the end of an era is the small number it really
	// is rather than a hundred and thirty-six years: the seconds field
	// wraps between the receive and the transmit timestamp, and the
	// modular subtraction has to see a millisecond.
	era := time.Date(2036, time.February, 7, 6, 28, 15, 990_000_000, time.UTC)
	across := &Packet{Mode: ModeServer, Stratum: 2,
		Receive: TimestampOf(era), Transmit: TimestampOf(era.Add(20 * time.Millisecond))}
	if across.Receive.Seconds() == across.Transmit.Seconds() {
		t.Fatal("the seconds field did not wrap, so this test proves nothing")
	}
	if why := across.TimestampsConsistent(); why != "" {
		t.Errorf("an exchange across the end of an era: %s", why)
	}
}

func TestTheReferenceIdentifierIsReadByItsStratum(t *testing.T) {
	gps := &Packet{Stratum: 1}
	copy(gps.ReferenceID[:], "GPS")
	if why := gps.RefIDSane(); why != "" {
		t.Errorf("a reference clock's name: %s", why)
	}
	if got := gps.RefIDText(); got != "GPS" {
		t.Errorf("text %q", got)
	}
	binary := &Packet{Stratum: 1, ReferenceID: [4]byte{0xde, 0xad, 0xbe, 0xef}}
	if binary.RefIDSane() == "" {
		t.Error("a stratum 1 answer whose identifier is not a name was called sound")
	}
	up := &Packet{Stratum: 3, ReferenceID: [4]byte{10, 30, 10, 1}}
	if why := up.RefIDSane(); why != "" {
		t.Errorf("an upstream address: %s", why)
	}
	if got := up.RefIDText(); got != "10.30.10.1" {
		t.Errorf("text %q", got)
	}
	none := &Packet{Stratum: 3}
	if none.RefIDSane() == "" {
		t.Error("a stratum 3 answer that names no upstream was called sound")
	}
	// At stratum 0 the field is a kiss code, which is not the identity of
	// a server and is not judged here.
	kiss := &Packet{Mode: ModeServer, Stratum: 0}
	copy(kiss.ReferenceID[:], "RATE")
	if why := kiss.RefIDSane(); why != "" {
		t.Errorf("a kiss code: %s", why)
	}
	// Four octets that could be a hash of an IPv6 address are not called
	// wrong for looking like a multicast address, because refusing a
	// digest would refuse a correct server.
	hash := &Packet{Stratum: 2, ReferenceID: [4]byte{239, 255, 0, 1}}
	if why := hash.RefIDSane(); why != "" {
		t.Errorf("four octets of a digest: %s", why)
	}
}
