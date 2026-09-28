package opcua

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

func TestAHeaderNamesTheTypeTheChunkAndTheSize(t *testing.T) {
	raw := build().u32(0).u32(65536).u32(65536).u32(0).u32(0).str("opc.tcp://plant:4840").
		chunk(Hello, Final)
	c := mustParse(t, raw)
	if c.Type != Hello {
		t.Errorf("type %s, want HEL", c.Type)
	}
	if c.Chunk != Final {
		t.Errorf("chunk %s, want final", c.Chunk)
	}
	if len(c.Body) != len(raw)-HeaderLen {
		t.Errorf("body %d octets, want %d", len(c.Body), len(raw)-HeaderLen)
	}
	if !bytes.Equal(c.Raw, raw) {
		t.Error("Raw is not the octets that arrived")
	}
}

func TestASizeThatDisagreesWithTheOctetsIsRefused(t *testing.T) {
	// Either reading is a choice, and the two readers on either side of a relay
	// would not make the same one. A relay that took the declared size would
	// leave the surplus to be read as the head of the next message; one that
	// took the actual size would forward a message the peer framed differently.
	raw := build().u32(0).chunk(Message, Final)
	binary.LittleEndian.PutUint32(raw[4:], uint32(len(raw)+4))
	if _, err := ParseChunk(raw); !errors.Is(err, ErrSize) {
		t.Errorf("err %v, want ErrSize", err)
	}
	raw = build().u32(0).chunk(Message, Final)
	binary.LittleEndian.PutUint32(raw[4:], uint32(len(raw)-1))
	if _, err := ParseChunk(raw); !errors.Is(err, ErrSize) {
		t.Errorf("shorter: err %v, want ErrSize", err)
	}
}

func TestPeekSizeBoundsWhatAReaderWillAllocate(t *testing.T) {
	for _, tc := range []struct {
		name string
		size uint32
		want error
	}{
		{"a header alone", HeaderLen, nil},
		{"the largest allowed", MaxMessageSize, nil},
		{"one past it", MaxMessageSize + 1, ErrTooLong},
		{"less than a header", HeaderLen - 1, ErrSize},
		{"zero", 0, ErrSize},
		{"the whole address space", math.MaxUint32, ErrTooLong},
	} {
		h := make([]byte, HeaderLen)
		copy(h, Message[:])
		h[3] = byte(Final)
		binary.LittleEndian.PutUint32(h[4:], tc.size)
		n, err := PeekSize(h)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: err %v, want %v", tc.name, err, tc.want)
			continue
		}
		if err == nil && n != int(tc.size) {
			t.Errorf("%s: %d, want %d", tc.name, n, tc.size)
		}
	}
	if _, err := PeekSize(make([]byte, HeaderLen-1)); !errors.Is(err, ErrShort) {
		t.Error("a short header is not reported as truncated")
	}
}

func TestAnUnknownMessageTypeIsRefused(t *testing.T) {
	raw := build().u32(0).chunk(MessageType{'X', 'Y', 'Z'}, Final)
	if _, err := ParseChunk(raw); !errors.Is(err, ErrMessageType) {
		t.Errorf("err %v, want ErrMessageType", err)
	}
}

func TestAnUnknownChunkTypeIsRefused(t *testing.T) {
	raw := build().u32(0).chunk(Message, ChunkType('X'))
	if _, err := ParseChunk(raw); !errors.Is(err, ErrChunkType) {
		t.Errorf("err %v, want ErrChunkType", err)
	}
}

func TestAChunkedHandshakeMessageIsRefused(t *testing.T) {
	// There is no request identifier in a handshake message, so a non-final one
	// is a fragment nothing could join to the next.
	for _, ct := range []ChunkType{Intermediate, Abort} {
		raw := build().u32(0).chunk(Hello, ct)
		if _, err := ParseChunk(raw); !errors.Is(err, ErrChunkType) {
			t.Errorf("%s: err %v, want ErrChunkType", ct, err)
		}
	}
	// A secured message may be chunked, and is.
	raw := build().secured(1, 2, 3, 4).chunk(Message, Intermediate)
	if _, err := ParseChunk(raw); err != nil {
		t.Errorf("an intermediate MSG: %v", err)
	}
}

func TestTheMessageTypesClassifyAsTheTransportDoes(t *testing.T) {
	for _, tc := range []struct {
		t                         MessageType
		known, handshake, secured bool
	}{
		{Hello, true, true, false},
		{Acknowledge, true, true, false},
		{Error, true, true, false},
		{ReverseHello, true, true, false},
		{OpenSecureChannel, true, false, true},
		{CloseSecureChannel, true, false, true},
		{Message, true, false, true},
		{MessageType{'F', 'O', 'O'}, false, false, false},
	} {
		if got := tc.t.Known(); got != tc.known {
			t.Errorf("%s Known %v, want %v", tc.t, got, tc.known)
		}
		if got := tc.t.Handshake(); got != tc.handshake {
			t.Errorf("%s Handshake %v, want %v", tc.t, got, tc.handshake)
		}
		if got := tc.t.Secured(); got != tc.secured {
			t.Errorf("%s Secured %v, want %v", tc.t, got, tc.secured)
		}
	}
	// Every known type is one or the other and never both: the two categories
	// partition the transport, and a type in neither would be one no code path
	// handles.
	for _, m := range []MessageType{Hello, Acknowledge, Error, ReverseHello,
		OpenSecureChannel, CloseSecureChannel, Message} {
		if m.Handshake() == m.Secured() {
			t.Errorf("%s is in both categories or neither", m)
		}
	}
}

func TestTypeOfReadsEveryTypeBackByNameAndByTag(t *testing.T) {
	for _, tc := range []struct {
		name string
		want MessageType
	}{
		{"hello", Hello}, {"HEL", Hello},
		{"acknowledge", Acknowledge}, {"ACK", Acknowledge},
		{"error", Error}, {"ERR", Error},
		{"reverse_hello", ReverseHello}, {"RHE", ReverseHello},
		{"open_secure_channel", OpenSecureChannel}, {"OPN", OpenSecureChannel},
		{"close_secure_channel", CloseSecureChannel}, {"CLO", CloseSecureChannel},
		{"message", Message}, {"MSG", Message},
	} {
		got, ok := TypeOf(tc.name)
		if !ok || got != tc.want {
			t.Errorf("TypeOf(%q) = %s, %v; want %s", tc.name, got, ok, tc.want)
		}
	}
	if _, ok := TypeOf("nonsense"); ok {
		t.Error("TypeOf accepted a name that is not a type")
	}
}

func TestChunkTypeRendersAndClassifies(t *testing.T) {
	for _, tc := range []struct {
		c     ChunkType
		s     string
		known bool
	}{
		{Final, "final", true},
		{Intermediate, "intermediate", true},
		{Abort, "abort", true},
		{ChunkType('Z'), `chunk('Z')`, false},
	} {
		if got := tc.c.String(); got != tc.s {
			t.Errorf("String %q, want %q", got, tc.s)
		}
		if got := tc.c.Known(); got != tc.known {
			t.Errorf("%s Known %v, want %v", tc.s, got, tc.known)
		}
	}
}

func TestAHelloCarriesTheSizesAndTheEndpoint(t *testing.T) {
	raw := build().u32(0).u32(65536).u32(65535).u32(16777216).u32(5).
		str("opc.tcp://plant.example:4840/UA/Server").chunk(Hello, Final)
	c := mustParse(t, raw)
	h, err := ParseHello(c.Body)
	if err != nil {
		t.Fatal(err)
	}
	if h.ReceiveBufferSize != 65536 || h.SendBufferSize != 65535 {
		t.Errorf("buffers %d/%d", h.ReceiveBufferSize, h.SendBufferSize)
	}
	if h.MaxMessageSize != 16777216 || h.MaxChunkCount != 5 {
		t.Errorf("limits %d/%d", h.MaxMessageSize, h.MaxChunkCount)
	}
	if h.EndpointURL != "opc.tcp://plant.example:4840/UA/Server" {
		t.Errorf("endpoint %q", h.EndpointURL)
	}
	if err := h.Acceptable(); err != nil {
		t.Errorf("Acceptable: %v", err)
	}
}

func TestAHelloIsRefusedForTheSizesItProposes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		hello HelloBody
		want  error
	}{
		{"the floor exactly", HelloBody{ReceiveBufferSize: MinBuffer, SendBufferSize: MinBuffer}, nil},
		{"a receive buffer under the floor",
			HelloBody{ReceiveBufferSize: MinBuffer - 1, SendBufferSize: MinBuffer}, ErrEncoding},
		{"a send buffer under the floor",
			HelloBody{ReceiveBufferSize: MinBuffer, SendBufferSize: MinBuffer - 1}, ErrEncoding},
		{"a receive buffer past the ceiling",
			HelloBody{ReceiveBufferSize: MaxMessageSize + 1, SendBufferSize: MinBuffer}, ErrTooLong},
		{"a send buffer past the ceiling",
			HelloBody{ReceiveBufferSize: MinBuffer, SendBufferSize: MaxMessageSize + 1}, ErrTooLong},
		{"a protocol version nobody defined",
			HelloBody{ProtocolVersion: 1, ReceiveBufferSize: MinBuffer, SendBufferSize: MinBuffer}, ErrEncoding},
	} {
		if err := tc.hello.Acceptable(); !errors.Is(err, tc.want) {
			t.Errorf("%s: err %v, want %v", tc.name, err, tc.want)
		}
	}
}

func TestAnEndpointURLPastTheStandardsOwnLimitIsRefused(t *testing.T) {
	long := strings.Repeat("a", MaxEndpointURL+1)
	raw := build().u32(0).u32(65536).u32(65536).u32(0).u32(0).str(long).chunk(Hello, Final)
	c := mustParse(t, raw)
	if _, err := ParseHello(c.Body); !errors.Is(err, ErrTooLong) {
		t.Errorf("err %v, want ErrTooLong", err)
	}
}

func TestANullEndpointURLIsEmptyAndNotAnError(t *testing.T) {
	raw := build().u32(0).u32(65536).u32(65536).u32(0).u32(0).null().chunk(Hello, Final)
	c := mustParse(t, raw)
	h, err := ParseHello(c.Body)
	if err != nil {
		t.Fatal(err)
	}
	if h.EndpointURL != "" {
		t.Errorf("endpoint %q, want empty", h.EndpointURL)
	}
}

func TestAnAcknowledgeIsTwentyOctetsAndNothingMore(t *testing.T) {
	raw := build().u32(0).u32(65536).u32(65536).u32(0).u32(0).chunk(Acknowledge, Final)
	c := mustParse(t, raw)
	a, err := ParseAcknowledge(c.Body)
	if err != nil {
		t.Fatal(err)
	}
	if a.ReceiveBufferSize != 65536 {
		t.Errorf("receive buffer %d", a.ReceiveBufferSize)
	}
	// A message hiding a second message behind a fixed-length body is worth
	// refusing while the connection has carried nothing.
	raw = build().u32(0).u32(65536).u32(65536).u32(0).u32(0).raw(0xFF).chunk(Acknowledge, Final)
	c = mustParse(t, raw)
	if _, err := ParseAcknowledge(c.Body); !errors.Is(err, ErrSize) {
		t.Errorf("trailing octet: err %v, want ErrSize", err)
	}
	if _, err := ParseAcknowledge(make([]byte, 19)); !errors.Is(err, ErrShort) {
		t.Error("a short acknowledge is not reported as truncated")
	}
}

func TestAnErrorCarriesACodeAndTheServersOwnWords(t *testing.T) {
	raw := build().u32(StatusBadTCPEndpointURLInvalid).str("no such endpoint").
		chunk(Error, Final)
	c := mustParse(t, raw)
	e, err := ParseError(c.Body)
	if err != nil {
		t.Fatal(err)
	}
	if e.Code != StatusBadTCPEndpointURLInvalid {
		t.Errorf("code %#x", e.Code)
	}
	if e.Reason != "no such endpoint" {
		t.Errorf("reason %q", e.Reason)
	}
	if !e.Bad() {
		t.Error("a bad status is not reported as bad")
	}
	// A good code in an ERR is a peer contradicting itself, which is worth being
	// able to say rather than reporting as an error of its own.
	raw = build().u32(0).null().chunk(Error, Final)
	e, err = ParseError(mustParse(t, raw).Body)
	if err != nil {
		t.Fatal(err)
	}
	if e.Bad() {
		t.Error("a good status is reported as bad")
	}
	if e.Reason != "" {
		t.Errorf("reason %q, want empty", e.Reason)
	}
}

func TestAReverseHelloNamesTheServerAndWhereToReachIt(t *testing.T) {
	raw := build().str("urn:plant:server").str("opc.tcp://plant:4840").
		chunk(ReverseHello, Final)
	c := mustParse(t, raw)
	h, err := ParseReverseHello(c.Body)
	if err != nil {
		t.Fatal(err)
	}
	if h.ServerURI != "urn:plant:server" || h.EndpointURL != "opc.tcp://plant:4840" {
		t.Errorf("%+v", h)
	}
	if _, err := ParseReverseHello(nil); !errors.Is(err, ErrShort) {
		t.Error("an empty reverse hello is not reported as truncated")
	}
}

func TestEncodeErrorFramesAMessageThisPackageThenReads(t *testing.T) {
	raw := EncodeError(StatusBadSecurityPolicyRejected, "Basic256 is not carried here")
	c := mustParse(t, raw)
	if c.Type != Error || c.Chunk != Final {
		t.Fatalf("type %s chunk %s", c.Type, c.Chunk)
	}
	e, err := ParseError(c.Body)
	if err != nil {
		t.Fatal(err)
	}
	if e.Code != StatusBadSecurityPolicyRejected {
		t.Errorf("code %#x", e.Code)
	}
	if e.Reason != "Basic256 is not carried here" {
		t.Errorf("reason %q", e.Reason)
	}
	// An empty reason is a present, empty String rather than the null form, so a
	// peer reads a reason of zero length rather than no field at all.
	raw = EncodeError(StatusBadTCPInternalError, "")
	e, err = ParseError(mustParse(t, raw).Body)
	if err != nil {
		t.Fatal(err)
	}
	if e.Reason != "" {
		t.Errorf("reason %q", e.Reason)
	}
	if len(raw) != HeaderLen+8 {
		t.Errorf("an empty reason framed %d octets, want %d", len(raw), HeaderLen+8)
	}
}

func TestEncodeErrorTruncatesAReasonRatherThanFramingAMessageNobodyCanRead(t *testing.T) {
	raw := EncodeError(StatusBadTCPInternalError, strings.Repeat("x", MaxString+100))
	c := mustParse(t, raw)
	e, err := ParseError(c.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Reason) != MaxString {
		t.Errorf("reason %d octets, want %d", len(e.Reason), MaxString)
	}
}

func TestTheSecurityPoliciesAreNamedAndClassified(t *testing.T) {
	for _, tc := range []struct {
		p                 SecurityPolicy
		known, deprecated bool
		short             string
	}{
		{PolicyNone, true, false, "None"},
		{PolicyBasic128Rsa15, true, true, "Basic128Rsa15"},
		{PolicyBasic256, true, true, "Basic256"},
		{PolicyBasic256Sha256, true, false, "Basic256Sha256"},
		{PolicyAes128Sha256RsaOaep, true, false, "Aes128_Sha256_RsaOaep"},
		{PolicyAes256Sha256RsaPss, true, false, "Aes256_Sha256_RsaPss"},
		{SecurityPolicy("http://example.invalid/Policy#Mine"), false, false,
			"http://example.invalid/Policy#Mine"},
	} {
		if got := tc.p.Known(); got != tc.known {
			t.Errorf("%s Known %v, want %v", tc.p.Short(), got, tc.known)
		}
		if got := tc.p.Deprecated(); got != tc.deprecated {
			t.Errorf("%s Deprecated %v, want %v", tc.p.Short(), got, tc.deprecated)
		}
		if got := tc.p.Short(); got != tc.short {
			t.Errorf("Short %q, want %q", got, tc.short)
		}
	}
	// None is deliberately not deprecated: it is a configuration, not broken
	// cryptography, and the two are refused for different reasons.
	if PolicyNone.Deprecated() {
		t.Error("None is classified as deprecated")
	}
}

func TestPolicyOfAcceptsTheShortNameTheURIAndAnyCase(t *testing.T) {
	for _, name := range []string{
		"Basic256Sha256", "basic256sha256", "BASIC256SHA256",
		string(PolicyBasic256Sha256),
	} {
		got, ok := PolicyOf(name)
		if !ok || got != PolicyBasic256Sha256 {
			t.Errorf("PolicyOf(%q) = %q, %v", name, got, ok)
		}
	}
	if _, ok := PolicyOf("Basic512"); ok {
		t.Error("PolicyOf accepted a policy that does not exist")
	}
}

func TestTheSecurityModesSayWhetherABodyCanBeRead(t *testing.T) {
	for _, tc := range []struct {
		m               MessageSecurityMode
		known, readable bool
		name            string
	}{
		{ModeInvalid, false, false, "invalid"},
		{ModeNone, true, true, "none"},
		{ModeSign, true, true, "sign"},
		{ModeSignAndEncrypt, true, false, "sign_and_encrypt"},
		{MessageSecurityMode(4), false, false, "mode(4)"},
	} {
		if got := tc.m.Known(); got != tc.known {
			t.Errorf("%s Known %v, want %v", tc.name, got, tc.known)
		}
		if got := tc.m.Readable(); got != tc.readable {
			t.Errorf("%s Readable %v, want %v", tc.name, got, tc.readable)
		}
		if got := tc.m.String(); got != tc.name {
			t.Errorf("String %q, want %q", got, tc.name)
		}
	}
	// Sign is the case worth pinning: the body is secured and it is also
	// readable, and a relay that treated "secured" as "opaque" would enforce
	// nothing on the one mode where it can enforce everything.
	if !ModeSign.Readable() {
		t.Error("a signed body is reported as unreadable")
	}
}

func TestModeOfReadsTheModesBackByName(t *testing.T) {
	for name, want := range map[string]MessageSecurityMode{
		"none": ModeNone, "None": ModeNone,
		"sign": ModeSign, "SIGN": ModeSign,
		"sign_and_encrypt": ModeSignAndEncrypt, "signandencrypt": ModeSignAndEncrypt,
	} {
		got, ok := ModeOf(name)
		if !ok || got != want {
			t.Errorf("ModeOf(%q) = %s, %v; want %s", name, got, ok, want)
		}
	}
	if _, ok := ModeOf("encrypt"); ok {
		t.Error("ModeOf accepted a mode that does not exist: encryption without a signature")
	}
}

func TestAnAsymmetricHeaderCarriesThePolicyAndBothCertificates(t *testing.T) {
	cert := bytes.Repeat([]byte{0x30}, 400)
	thumb := bytes.Repeat([]byte{0xAB}, 20)
	body := build().u32(0).str(string(PolicyBasic256Sha256)).bstr(cert).bstr(thumb).
		u32(1).u32(1)
	raw := body.chunk(OpenSecureChannel, Final)
	c := mustParse(t, raw)
	h, off, err := ParseAsymmetric(c.Body)
	if err != nil {
		t.Fatal(err)
	}
	if h.Policy != PolicyBasic256Sha256 {
		t.Errorf("policy %q", h.Policy)
	}
	if !bytes.Equal(h.SenderCertificate, cert) {
		t.Error("the sender certificate is not the octets that arrived")
	}
	if !bytes.Equal(h.ReceiverThumbprint, thumb) {
		t.Error("the receiver thumbprint is not the octets that arrived")
	}
	// The offset is into the whole chunk, because that is what a signature is
	// computed over.
	s, end, err := ParseSequence(c.Raw, off)
	if err != nil {
		t.Fatal(err)
	}
	if s.SequenceNumber != 1 || s.RequestID != 1 {
		t.Errorf("sequence %+v", s)
	}
	if end != len(raw) {
		t.Errorf("the body ends at %d of %d", end, len(raw))
	}
}

func TestACertificatePastTheBoundIsRefused(t *testing.T) {
	body := build().u32(0).str(string(PolicyNone)).
		i32(MaxCertificate + 1).bytes(bytes.Repeat([]byte{0}, 10))
	if _, _, err := ParseAsymmetric(body.b); !errors.Is(err, ErrTooLong) {
		t.Errorf("err %v, want ErrTooLong", err)
	}
}

func TestASymmetricHeaderIsTheChannelAndTheToken(t *testing.T) {
	raw := build().secured(0x1234, 0x5678, 9, 10).chunk(Message, Final)
	c := mustParse(t, raw)
	h, off, err := ParseSymmetric(c.Body)
	if err != nil {
		t.Fatal(err)
	}
	if h.SecureChannelID != 0x1234 || h.TokenID != 0x5678 {
		t.Errorf("%+v", h)
	}
	s, _, err := ParseSequence(c.Raw, off)
	if err != nil {
		t.Fatal(err)
	}
	if s.SequenceNumber != 9 || s.RequestID != 10 {
		t.Errorf("%+v", s)
	}
	if _, _, err := ParseSymmetric(make([]byte, 7)); !errors.Is(err, ErrShort) {
		t.Error("a short symmetric header is not reported as truncated")
	}
}

func TestASequenceHeaderOutsideTheChunkIsRefusedRatherThanPanicking(t *testing.T) {
	chunk := make([]byte, 20)
	for _, off := range []int{-1, 21, 100} {
		if _, _, err := ParseSequence(chunk, off); !errors.Is(err, ErrShort) {
			t.Errorf("offset %d: err %v, want ErrShort", off, err)
		}
	}
	if _, _, err := ParseSequence(chunk, 16); !errors.Is(err, ErrShort) {
		t.Error("an offset that leaves too few octets is not reported as truncated")
	}
}

func TestAnOpenChannelRequestNamesTheModeThatDecidesEverythingAfterIt(t *testing.T) {
	body := build().u32(0).u32(uint32(ChannelIssue)).u32(uint32(ModeSignAndEncrypt)).
		bstr(bytes.Repeat([]byte{7}, 32)).u32(3600000)
	o, err := ParseOpenChannel(body.b)
	if err != nil {
		t.Fatal(err)
	}
	if o.Type != ChannelIssue {
		t.Errorf("type %s", o.Type)
	}
	if o.Mode != ModeSignAndEncrypt {
		t.Errorf("mode %s", o.Mode)
	}
	if len(o.Nonce) != 32 {
		t.Errorf("nonce %d octets", len(o.Nonce))
	}
	if o.Lifetime != 3600000 {
		t.Errorf("lifetime %d", o.Lifetime)
	}
	// A mode outside the three is refused: leaving it would let a listener's
	// "is this mode allowed" test pass a value with no meaning.
	body = build().u32(0).u32(0).u32(99).null().u32(0)
	if _, err := ParseOpenChannel(body.b); !errors.Is(err, ErrEncoding) {
		t.Errorf("err %v, want ErrEncoding", err)
	}
	// And a renewal is distinguished from an issue, because a renewal on an
	// unknown channel is a different event.
	body = build().u32(0).u32(uint32(ChannelRenew)).u32(uint32(ModeSign)).null().u32(600000)
	o, err = ParseOpenChannel(body.b)
	if err != nil {
		t.Fatal(err)
	}
	if o.Type != ChannelRenew || o.Type.String() != "renew" {
		t.Errorf("type %s", o.Type)
	}
	if got := ChannelRequestType(7).String(); got != "request(7)" {
		t.Errorf("String %q", got)
	}
}

func TestFileTimeIsTheEpochTheStandardNamesAndZeroIsNoTime(t *testing.T) {
	want := time.Date(2026, time.March, 4, 9, 30, 0, 0, time.UTC)
	ft := ToFileTime(want)
	if got := FileTime(ft); !got.Equal(want) {
		t.Errorf("round trip %v, want %v", got, want)
	}
	// Zero and infinity both mean "no time given", and rendering either as a
	// date in 1601 would report a fact nobody stated.
	for _, v := range []int64{0, -1, math.MaxInt64} {
		if got := FileTime(v); !got.IsZero() {
			t.Errorf("FileTime(%d) = %v, want the zero time", v, got)
		}
	}
	if got := ToFileTime(time.Time{}); got != 0 {
		t.Errorf("ToFileTime(zero) = %d, want 0", got)
	}
	// One tick is a hundred nanoseconds, from 1601-01-01.
	if got := FileTime(1); !got.Equal(time.Date(1601, time.January, 1, 0, 0, 0, 100, time.UTC)) {
		t.Errorf("FileTime(1) = %v", got)
	}
}

func TestStatusCodesClassifyBySeverity(t *testing.T) {
	for _, tc := range []struct {
		code                 uint32
		good, uncertain, bad bool
	}{
		{0x00000000, true, false, false},
		{0x40000000, false, true, false},
		{0x80000000, false, false, true},
		{StatusBadUserAccessDenied, false, false, true},
	} {
		if Good(tc.code) != tc.good || Uncertain(tc.code) != tc.uncertain || Bad(tc.code) != tc.bad {
			t.Errorf("%#x: good %v uncertain %v bad %v", tc.code,
				Good(tc.code), Uncertain(tc.code), Bad(tc.code))
		}
	}
	if got := StatusName(StatusBadUserAccessDenied); got != "bad:0x001F" {
		t.Errorf("StatusName %q", got)
	}
	if got := StatusName(0); got != "good:0x0000" {
		t.Errorf("StatusName %q", got)
	}
	if got := StatusName(0x40930000); got != "uncertain:0x0093" {
		t.Errorf("StatusName %q", got)
	}
	// A code with the structure bits set is rendered whole, because those bits
	// say the response carries diagnostic structure and dropping them would make
	// two different codes print the same.
	if got := StatusName(0x8034000A); got != "bad:0x8034000A" {
		t.Errorf("StatusName %q", got)
	}
}
