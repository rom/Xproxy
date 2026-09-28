package opcua

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// msg frames one MSG chunk on a channel, with the given request identifier and body.
func msg(ct ChunkType, channel, token, seq, request uint32, body []byte) []byte {
	return build().secured(channel, token, seq, request).bytes(body).chunk(Message, ct)
}

func TestASingleFinalChunkIsAMessage(t *testing.T) {
	a := NewAssembler()
	body := call(SvcRead, build().f64(0).u32(0).array(0))
	m, err := a.Add(mustParse(t, msg(Final, 1, 2, 1, 5, body)), ModeSign)
	if err != nil {
		t.Fatal(err)
	}
	if m == nil {
		t.Fatal("a final chunk produced no message")
	}
	if m.Channel != 1 || m.Token != 2 || m.RequestID != 5 {
		t.Errorf("%+v", m)
	}
	if m.Chunks != 1 {
		t.Errorf("chunks %d", m.Chunks)
	}
	if !bytes.Equal(m.Body, body) {
		t.Error("the body is not the octets that arrived")
	}
	// The common case leaves nothing in the table at all: a single final chunk
	// never needs an entry, so the ordinary message costs no bookkeeping.
	if a.Open() != 0 {
		t.Errorf("%d partial messages after a complete one", a.Open())
	}
}

func TestChunksAreJoinedByTheirRequestIdentifier(t *testing.T) {
	a := NewAssembler()
	// Two messages interleaved on one channel: a Publish sitting open while a
	// Read comes and goes is the ordinary case, so the identifier and not the
	// arrival order is what joins them.
	if m, err := a.Add(mustParse(t, msg(Intermediate, 1, 2, 1, 10, []byte("aaa"))), ModeSign); err != nil || m != nil {
		t.Fatalf("m %v err %v", m, err)
	}
	if m, err := a.Add(mustParse(t, msg(Intermediate, 1, 2, 2, 11, []byte("xxx"))), ModeSign); err != nil || m != nil {
		t.Fatalf("m %v err %v", m, err)
	}
	if a.Open() != 2 {
		t.Errorf("%d partial messages", a.Open())
	}
	m, err := a.Add(mustParse(t, msg(Final, 1, 2, 3, 11, []byte("yyy"))), ModeSign)
	if err != nil {
		t.Fatal(err)
	}
	if m == nil || string(m.Body) != "xxxyyy" {
		t.Fatalf("m %+v", m)
	}
	if m.Chunks != 2 {
		t.Errorf("chunks %d", m.Chunks)
	}
	if a.Open() != 1 {
		t.Errorf("%d partial messages left", a.Open())
	}
	m, err = a.Add(mustParse(t, msg(Final, 1, 2, 4, 10, []byte("bbb"))), ModeSign)
	if err != nil {
		t.Fatal(err)
	}
	if m == nil || string(m.Body) != "aaabbb" {
		t.Fatalf("m %+v", m)
	}
	if a.Open() != 0 {
		t.Errorf("%d partial messages left", a.Open())
	}
}

func TestAnAbortChunkDiscardsThePartialMessageAndIsNotAnError(t *testing.T) {
	// The peer said it was giving up. Honouring that is the whole point of the
	// chunk type, and a reader that treated it as an error would refuse a
	// connection for something the standard defines.
	a := NewAssembler()
	if _, err := a.Add(mustParse(t, msg(Intermediate, 1, 2, 1, 7, bytes.Repeat([]byte("a"), 100))), ModeSign); err != nil {
		t.Fatal(err)
	}
	m, err := a.Add(mustParse(t, msg(Abort, 1, 2, 2, 7, build().u32(StatusBadRequestTooLarge).str("gave up").b)), ModeSign)
	if err != nil {
		t.Errorf("an abort is reported as an error: %v", err)
	}
	if m != nil {
		t.Error("an abort produced a message")
	}
	if a.Open() != 0 {
		t.Errorf("%d partial messages after an abort", a.Open())
	}
	// And the next message on the same identifier starts clean rather than
	// carrying the abandoned octets.
	m, err = a.Add(mustParse(t, msg(Final, 1, 2, 3, 7, []byte("fresh"))), ModeSign)
	if err != nil {
		t.Fatal(err)
	}
	if string(m.Body) != "fresh" {
		t.Errorf("body %q", m.Body)
	}
}

func TestAnAbortOnAnIdentifierWithNothingOpenIsHarmless(t *testing.T) {
	a := NewAssembler()
	m, err := a.Add(mustParse(t, msg(Abort, 1, 2, 1, 99, nil)), ModeSign)
	if err != nil || m != nil {
		t.Errorf("m %v err %v", m, err)
	}
}

func TestTooManyChunksInOneMessageIsRefused(t *testing.T) {
	a := NewAssembler()
	for i := 0; i < MaxChunks; i++ {
		if _, err := a.Add(mustParse(t, msg(Intermediate, 1, 2, uint32(i), 1, []byte("a"))), ModeSign); err != nil {
			t.Fatalf("chunk %d: %v", i, err)
		}
	}
	_, err := a.Add(mustParse(t, msg(Intermediate, 1, 2, 99, 1, []byte("a"))), ModeSign)
	if !errors.Is(err, ErrTooLong) {
		t.Errorf("err %v, want ErrTooLong", err)
	}
	// The refusal also drops the partial message, so a peer cannot hold the
	// memory by sending one chunk past the bound and then stopping.
	if a.Open() != 0 {
		t.Errorf("%d partial messages after the refusal", a.Open())
	}
}

func TestTooManyPartialMessagesIsRefused(t *testing.T) {
	// This is the bound that is easy to forget and the one an attacker reaches
	// for: a thousand request identifiers with one chunk each is very little sent
	// and a great deal asked of the relay.
	a := NewAssembler()
	for i := 0; i < MaxPartial; i++ {
		if _, err := a.Add(mustParse(t, msg(Intermediate, 1, 2, 1, uint32(i), []byte("a"))), ModeSign); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	_, err := a.Add(mustParse(t, msg(Intermediate, 1, 2, 1, 9999, []byte("a"))), ModeSign)
	if !errors.Is(err, ErrTooLong) {
		t.Errorf("err %v, want ErrTooLong", err)
	}
	if a.Open() != MaxPartial {
		t.Errorf("%d partial messages", a.Open())
	}
	// A final chunk on an identifier already open still completes, so the bound
	// refuses new work rather than stranding what is in flight.
	if _, err := a.Add(mustParse(t, msg(Final, 1, 2, 2, 0, []byte("b"))), ModeSign); err != nil {
		t.Errorf("a final chunk on an open identifier: %v", err)
	}
	if a.Open() != MaxPartial-1 {
		t.Errorf("%d partial messages after one completed", a.Open())
	}
}

func TestAnEncryptedBodyIsAccountedForAndNotKept(t *testing.T) {
	// The cost of holding a chunk is the same whether or not a relay can read it,
	// so the bound applies either way and the octets do not.
	a := NewAssembler()
	body := bytes.Repeat([]byte{0xAA}, 1000)
	m, err := a.Add(mustParse(t, msg(Final, 1, 2, 1, 3, body)), ModeSignAndEncrypt)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Encrypted {
		t.Error("the message is not reported as encrypted")
	}
	if m.Body != nil {
		t.Errorf("%d octets of ciphertext were kept", len(m.Body))
	}
	if m.Channel != 1 || m.RequestID != 3 {
		t.Errorf("%+v", m)
	}
}

func TestAnEncryptedMessagePastTheAssembledBoundIsStillRefused(t *testing.T) {
	a := NewAssembler()
	// Each chunk is under the per-chunk bound; together they pass the assembled
	// one, and nothing was kept, so only the accounting can catch it.
	chunk := bytes.Repeat([]byte{0xAA}, MaxMessageSize-HeaderLen-16)
	var err error
	for i := 0; i < MaxChunks && err == nil; i++ {
		_, err = a.Add(mustParse(t, msg(Intermediate, 1, 2, uint32(i), 1, chunk)), ModeSignAndEncrypt)
	}
	if !errors.Is(err, ErrTooLong) {
		t.Errorf("err %v, want ErrTooLong", err)
	}
	if a.Open() != 0 {
		t.Errorf("%d partial messages after the refusal", a.Open())
	}
}

func TestAnOpenSecureChannelChunkIsAssembledFromItsAsymmetricHeader(t *testing.T) {
	a := NewAssembler()
	body := build().u32(0).str(string(PolicyNone)).null().null().
		u32(1).u32(1).
		bytes(call(SvcOpenChannel, build().u32(0).u32(0).u32(uint32(ModeNone)).null().u32(3600000)))
	m, err := a.Add(mustParse(t, body.chunk(OpenSecureChannel, Final)), ModeNone)
	if err != nil {
		t.Fatal(err)
	}
	if m.Type != OpenSecureChannel {
		t.Errorf("type %s", m.Type)
	}
	if m.RequestID != 1 {
		t.Errorf("request %d", m.RequestID)
	}
	// The token is zero on an OPN: there is no token yet, which is why the message
	// carries certificates instead of one.
	if m.Token != 0 {
		t.Errorf("token %d", m.Token)
	}
	c, err := ParseCall(m.Body, true)
	if err != nil {
		t.Fatal(err)
	}
	if c.Service != SvcOpenChannel {
		t.Errorf("service %s", c.Service)
	}
}

func TestAHandshakeMessageIsNotSomethingToAssemble(t *testing.T) {
	a := NewAssembler()
	raw := build().u32(0).u32(65536).u32(65536).u32(0).u32(0).null().chunk(Hello, Final)
	if _, err := a.Add(mustParse(t, raw), ModeNone); !errors.Is(err, ErrMessageType) {
		t.Errorf("err %v, want ErrMessageType", err)
	}
}

func TestAChunkWithATruncatedSecurityHeaderIsRefused(t *testing.T) {
	a := NewAssembler()
	for _, raw := range [][]byte{
		build().u32(1).chunk(Message, Final),               // half a symmetric header
		build().u32(1).u32(2).u32(3).chunk(Message, Final), // half a sequence header
		build().u32(0).chunk(OpenSecureChannel, Final),     // half an asymmetric header
	} {
		if _, err := a.Add(mustParse(t, raw), ModeNone); !errors.Is(err, ErrShort) {
			t.Errorf("%x: err %v, want ErrShort", raw, err)
		}
	}
}

func TestResetDropsEveryPartialMessage(t *testing.T) {
	a := NewAssembler()
	for i := 0; i < 3; i++ {
		if _, err := a.Add(mustParse(t, msg(Intermediate, 1, 2, 1, uint32(i), []byte("a"))), ModeSign); err != nil {
			t.Fatal(err)
		}
	}
	a.Reset()
	if a.Open() != 0 {
		t.Errorf("%d partial messages after a reset", a.Open())
	}
	// And the assembler is usable again rather than left with a nil map.
	if _, err := a.Add(mustParse(t, msg(Intermediate, 1, 2, 1, 1, []byte("a"))), ModeSign); err != nil {
		t.Errorf("after a reset: %v", err)
	}
}

func TestACloseSecureChannelIsAssembledLikeAMessage(t *testing.T) {
	a := NewAssembler()
	raw := build().secured(1, 2, 9, 4).
		bytes(call(SvcCloseChannel, build())).chunk(CloseSecureChannel, Final)
	m, err := a.Add(mustParse(t, raw), ModeSign)
	if err != nil {
		t.Fatal(err)
	}
	if m.Type != CloseSecureChannel {
		t.Errorf("type %s", m.Type)
	}
	c, err := ParseCall(m.Body, true)
	if err != nil {
		t.Fatal(err)
	}
	if c.Service != SvcCloseChannel {
		t.Errorf("service %s", c.Service)
	}
}

func TestTheStatusCodesThisRelaySendsAreAllBad(t *testing.T) {
	// A refusal carrying a good status code would be a refusal a client reads as
	// a success, which is worse than no message at all.
	for name, code := range map[string]uint32{
		"message type invalid":     StatusBadTCPMessageTypeInvalid,
		"message too large":        StatusBadTCPMessageTooLarge,
		"not enough resources":     StatusBadTCPNotEnoughResources,
		"internal error":           StatusBadTCPInternalError,
		"endpoint url invalid":     StatusBadTCPEndpointURLInvalid,
		"security checks failed":   StatusBadSecurityChecksFailed,
		"security policy rejected": StatusBadSecurityPolicyRejected,
		"security mode rejected":   StatusBadSecurityModeRejected,
		"certificate use":          StatusBadCertificateUseNotAllowed,
		"user access denied":       StatusBadUserAccessDenied,
		"service unsupported":      StatusBadServiceUnsupported,
		"not writable":             StatusBadNotWritable,
		"node id unknown":          StatusBadNodeIDUnknown,
		"request too large":        StatusBadRequestTooLarge,
		"too many operations":      StatusBadTooManyOperations,
	} {
		if !Bad(code) {
			t.Errorf("%s (%#x) is not a bad status", name, code)
		}
		if !strings.HasPrefix(StatusName(code), "bad:") {
			t.Errorf("%s renders as %q", name, StatusName(code))
		}
	}
}
