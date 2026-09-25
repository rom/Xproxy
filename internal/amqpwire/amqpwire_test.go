package amqpwire

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// The header is how a connection says which of the two protocols it is,
// and a relay that read it wrong would apply the wrong framing to
// everything after it.
func TestTheHeaderSaysWhichProtocol(t *testing.T) {
	for _, c := range []struct {
		name  string
		bytes []byte
		want  Version
		layer uint8
		text  string
	}{
		{"0-9-1", header091(), V091, 0, "0-9-1"},
		{"1.0", header10(ProtoAMQP), V10, ProtoAMQP, "1.0"},
		{"1.0 over the SASL layer", header10(ProtoSASL), V10, ProtoSASL, "1.0 sasl"},
		{"1.0 asking for TLS", header10(ProtoTLS), V10, ProtoTLS, "1.0 tls"},
		{"0-8", []byte{'A', 'M', 'Q', 'P', 1, 1, 8, 0}, Legacy, 1, "0-8"},
		{"0-9", []byte{'A', 'M', 'Q', 'P', 1, 1, 0, 9}, Legacy, 1, "0-8"},
		{"a version nobody defines", []byte{'A', 'M', 'Q', 'P', 0, 7, 3, 2}, Unknown, 0, "unknown (0.7.3.2)"},
	} {
		h, err := ParseHeader(c.bytes)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := h.Version(); got != c.want {
			t.Errorf("%s: version = %v, want %v", c.name, got, c.want)
		}
		if got := h.Layer(); got != c.layer {
			t.Errorf("%s: layer = %d, want %d", c.name, got, c.layer)
		}
		if got := h.String(); got != c.text {
			t.Errorf("%s: %q, want %q", c.name, got, c.text)
		}
		// The header is forwarded as it arrived, octet for octet.
		if !bytes.Equal(h.Bytes(), c.bytes) {
			t.Errorf("%s: the header was not kept as it arrived", c.name)
		}
	}
}

func TestSomethingThatIsNotAMQPIsRefusedAsSuch(t *testing.T) {
	for _, c := range []struct {
		name string
		b    []byte
	}{
		{"an HTTP request", []byte("GET / HT")},
		{"TLS", []byte{0x16, 0x03, 0x01, 0x02, 0x00, 1, 0, 0}},
		{"too short", []byte{'A', 'M', 'Q', 'P'}},
		{"too long", []byte{'A', 'M', 'Q', 'P', 0, 0, 9, 1, 0}},
		{"empty", nil},
	} {
		if _, err := ParseHeader(c.b); err == nil {
			t.Errorf("%s: was read as a protocol header", c.name)
		}
	}
}

// The frame reader, on both framings, and on the malformed frames that are
// the reason it exists.
func TestFramesAreReadAndBounded(t *testing.T) {
	payload := method(ClassChannel, 10, shortstr(""))
	stream := join(header091(),
		frame091(FrameMethod, 1, payload),
		frame091(FrameHeartbeat, 0, nil))
	r := NewReader(bytes.NewReader(stream), 0)
	h, err := r.Header()
	if err != nil {
		t.Fatal(err)
	}
	if h.Version() != V091 {
		t.Fatalf("version %v", h.Version())
	}
	f, err := r.Next()
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != FrameMethod || f.Channel != 1 || !bytes.Equal(f.Payload, payload) {
		t.Errorf("frame = %+v", f)
	}
	if !bytes.Equal(f.Raw, frame091(FrameMethod, 1, payload)) {
		t.Error("the frame's own octets were not kept")
	}
	if f.Heartbeat() {
		t.Error("a method frame was read as a heartbeat")
	}
	f, err = r.Next()
	if err != nil {
		t.Fatal(err)
	}
	if !f.Heartbeat() || !f.KnownType() {
		t.Errorf("the heartbeat was read as %+v", f)
	}
	if _, err := r.Next(); !errors.Is(err, io.EOF) {
		t.Errorf("the end of the stream was reported as %v", err)
	}
}

func TestAFrameThatDoesNotEndWhereItSaidIsRefused(t *testing.T) {
	bad := frame091(FrameMethod, 1, method(ClassChannel, 10))
	bad[len(bad)-1] = 0x00 // the frame-end octet, wrong
	r := NewReader(bytes.NewReader(join(header091(), bad)), 0)
	if _, err := r.Header(); err != nil {
		t.Fatal(err)
	}
	_, err := r.Next()
	if err == nil || !strings.Contains(err.Error(), "did not end with") {
		t.Errorf("a frame whose end octet was wrong was read: %v", err)
	}
}

func TestAFrameOverTheBoundIsRefusedBeforeItIsRead(t *testing.T) {
	// A frame that claims four gigabytes. Nothing is allocated for it: the
	// bound is checked against the declared size, which is the whole point
	// of checking it before the read.
	claim := join([]byte{FrameMethod}, be16b(1), be32b(0xffffffff))
	r := NewReader(bytes.NewReader(join(header091(), claim)), MinFrameMax091)
	if _, err := r.Header(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Next(); err == nil || !strings.Contains(err.Error(), "over the") {
		t.Errorf("a frame of four gigabytes was accepted: %v", err)
	}
	// And the bound is never below the protocol's own minimum, so a peer
	// obeying the specification is never refused for it.
	if got := NewReader(bytes.NewReader(nil), 16).Max(); got != MinFrameMax091 {
		t.Errorf("a bound of 16 octets was kept as %d", got)
	}
}

func TestATruncatedFrameIsAnError(t *testing.T) {
	full := frame091(FrameMethod, 1, method(ClassQueue, 10, short(0), shortstr("q")))
	for n := 1; n < len(full); n++ {
		r := NewReader(bytes.NewReader(join(header091(), full[:n])), 0)
		if _, err := r.Header(); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Next(); err == nil {
			t.Fatalf("%d octets of a %d octet frame were read as a frame", n, len(full))
		}
	}
}

func TestTheTenFramingIsReadWithItsDataOffset(t *testing.T) {
	body := perf10(uint8(PerfOpen), str10("client-1"), str10("/"))
	// A frame with an extended header: the data offset moves the body
	// along, and a reader that assumed eight octets would read the
	// extension as the performative.
	size := uint32(8 + 4 + len(body))
	extended := join(be32b(size), []byte{3, FrameAMQP}, be16b(0), []byte{0, 0, 0, 0}, body)
	stream := join(header10(ProtoAMQP), frame10(FrameAMQP, 0, body), extended,
		frame10(FrameAMQP, 0, nil))
	r := NewReader(bytes.NewReader(stream), 0)
	if _, err := r.Header(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"open", "open"} {
		f, err := r.Next()
		if err != nil {
			t.Fatal(err)
		}
		p, err := ParsePerformative(f.Payload)
		if err != nil {
			t.Fatal(err)
		}
		if p.Name() != want {
			t.Errorf("performative = %q, want %q", p.Name(), want)
		}
	}
	// An empty body is this version's heartbeat.
	f, err := r.Next()
	if err != nil {
		t.Fatal(err)
	}
	if !f.Heartbeat() {
		t.Error("an empty 1.0 frame was not read as a heartbeat")
	}
}

func TestTheTenFramingRefusesAnImpossibleHeader(t *testing.T) {
	for _, c := range []struct {
		name string
		b    []byte
		want string
	}{
		{"a size inside the header", join(be32b(4), []byte{2, 0}, be16b(0)), "smaller than its own header"},
		{"a data offset inside the header", join(be32b(16), []byte{1, 0}, be16b(0), make([]byte, 8)), "inside the frame header"},
		{"a data offset past the frame", join(be32b(12), []byte{4, 0}, be16b(0), make([]byte, 4)), "past the end"},
		{"a size over the bound", join(be32b(1<<30), []byte{2, 0}, be16b(0)), "over the"},
	} {
		r := NewReader(bytes.NewReader(join(header10(ProtoAMQP), c.b)), MinFrameMax091)
		if _, err := r.Header(); err != nil {
			t.Fatal(err)
		}
		_, err := r.Next()
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
}

func TestAFrameBeforeTheVersionIsKnownIsRefused(t *testing.T) {
	r := NewReader(bytes.NewReader(frame091(FrameHeartbeat, 0, nil)), 0)
	if _, err := r.Next(); err == nil {
		t.Error("a frame was read before the protocol version was")
	}
}

func TestAnUnknownFrameTypeIsReportedRatherThanGuessedAt(t *testing.T) {
	r := NewReader(bytes.NewReader(join(header091(), frame091(7, 0, []byte{1, 2}))), 0)
	if _, err := r.Header(); err != nil {
		t.Fatal(err)
	}
	f, err := r.Next()
	if err != nil {
		t.Fatal(err)
	}
	if f.KnownType() {
		t.Error("frame type 7 was read as one of the four")
	}
	// The octets are still there, so a listener can log what it refused.
	if !bytes.Equal(f.Payload, []byte{1, 2}) {
		t.Error("the payload of an unknown frame type was lost")
	}
}
