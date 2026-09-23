package rdp

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// The two framings are told apart by their first byte, and each one
// round-trips through what this package writes.
func TestPDUFramings(t *testing.T) {
	slow, err := DataPDU([]byte("conference layer"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ReadPDU(bytes.NewReader(slow))
	if err != nil {
		t.Fatal(err)
	}
	if got.FastPath {
		t.Error("a tpkt pdu was read as fast path")
	}
	payload, err := X224Payload(got.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "conference layer" {
		t.Errorf("payload %q", payload)
	}

	// Fast path with a one byte length, then with two.
	short := append([]byte{0x00, 0x06}, []byte("abcd")...)
	got, err = ReadPDU(bytes.NewReader(short))
	if err != nil {
		t.Fatal(err)
	}
	if !got.FastPath || string(got.Body) != "abcd" {
		t.Errorf("short fast path: %+v", got)
	}
	body := bytes.Repeat([]byte{'x'}, 300)
	long := append([]byte{0x00, 0x81, 0x2f}, body...)
	got, err = ReadPDU(bytes.NewReader(long))
	if err != nil {
		t.Fatal(err)
	}
	if !got.FastPath || len(got.Body) != 300 {
		t.Errorf("long fast path: %d bytes", len(got.Body))
	}
	if !bytes.Equal(got.Raw, long) {
		t.Error("the raw pdu is not what arrived, so relaying it would change the stream")
	}
}

// A length that cannot be right is refused rather than used to make a
// slice.
func TestFramingLengthsAreChecked(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
	}{
		{"tpkt shorter than its own header", []byte{3, 0, 0, 2}},
		{"tpkt of nothing", []byte{3, 0, 0, 0}},
		{"fast path shorter than its header", []byte{0x00, 0x01}},
		{"fast path two byte length under its header", []byte{0x00, 0x80, 0x02}},
	}
	for _, c := range cases {
		if _, err := ReadPDU(bytes.NewReader(c.in)); !errors.Is(err, ErrFraming) {
			t.Errorf("%s was accepted (%v)", c.name, err)
		}
	}
	// A pdu whose body never arrives is a short read, not a framing
	// error: the peer may still be sending.
	if _, err := ReadPDU(bytes.NewReader([]byte{3, 0, 0, 20, 1, 2})); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("a truncated pdu: %v", err)
	}
	// And nothing at all is a clean end.
	if _, err := ReadPDU(bytes.NewReader(nil)); !errors.Is(err, io.EOF) {
		t.Errorf("an empty stream: %v", err)
	}
}

// An X.224 unit that is not a data unit is not read as one, and a
// length indicator past the end of the unit does not slice past it.
func TestX224PayloadIsChecked(t *testing.T) {
	if _, err := X224Payload([]byte{0x02, 0xE0, 0x80}); !errors.Is(err, ErrFraming) {
		t.Error("a connection request was read as a data unit")
	}
	if _, err := X224Payload([]byte{0x40, 0xF0, 0x80, 1, 2}); !errors.Is(err, ErrFraming) {
		t.Error("a length indicator past the unit was accepted")
	}
	if _, err := X224Payload([]byte{0x02}); !errors.Is(err, ErrFraming) {
		t.Error("a unit too short to have a header was accepted")
	}
}

// A payload too long for TPKT's own length field is refused rather
// than truncated into a different pdu.
func TestTPKTBoundsItsPayload(t *testing.T) {
	if _, err := TPKT(bytes.Repeat([]byte{0}, MaxPDU)); !errors.Is(err, ErrFraming) {
		t.Error("an oversize payload was framed")
	}
	if _, err := TPKT(bytes.Repeat([]byte{0}, MaxPDU-4)); err != nil {
		t.Errorf("the largest payload that fits was refused: %v", err)
	}
}

// The negotiation round-trips, including the routing token, which is
// the only identity available that early.
func TestConnectionRequestRoundTrip(t *testing.T) {
	want := ConnectionRequest{
		Cookie: "Cookie: mstshash=LAB\\alice", Protocols: ProtocolSSL | ProtocolHybrid,
		Flags: 0x01, HasNegotiation: true,
	}
	raw, err := want.Encode()
	if err != nil {
		t.Fatal(err)
	}
	pdu, err := ReadPDU(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseConnectionRequest(pdu.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("read %+v, want %+v", got, want)
	}
}

// A client old enough to send no negotiation is speaking the legacy
// protocol, which is a fact the gateway needs rather than an error.
func TestAConnectionRequestWithoutANegotiation(t *testing.T) {
	raw, err := ConnectionRequest{}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	pdu, _ := ReadPDU(bytes.NewReader(raw))
	got, err := ParseConnectionRequest(pdu.Body)
	if err != nil {
		t.Fatal(err)
	}
	if got.HasNegotiation || got.Protocols != ProtocolRDP {
		t.Errorf("read %+v", got)
	}
}

// A routing token a peer chooses the length of is bounded before it
// reaches a log line.
func TestTheRoutingTokenIsBounded(t *testing.T) {
	long := ConnectionRequest{Cookie: strings.Repeat("a", maxCookie+1)}
	if _, err := long.Encode(); !errors.Is(err, ErrFraming) {
		t.Error("an oversize routing token was encoded")
	}
	// And one that arrives oversize inside an otherwise valid unit is
	// refused at the parse rather than logged.
	body := append([]byte{0, x224CR, 0, 0, 0, 0, 0}, []byte(strings.Repeat("a", maxCookie+1)+"\r\n")...)
	if len(body)-1 > 0xFF {
		t.Fatalf("the test's own unit is %d bytes, which x.224 cannot carry", len(body))
	}
	body[0] = byte(len(body) - 1)
	if _, err := ParseConnectionRequest(body); !errors.Is(err, ErrFraming) {
		t.Error("an oversize routing token was parsed")
	}
}

// The answer round-trips both ways: a protocol, and a refusal.
func TestConnectionConfirmRoundTrip(t *testing.T) {
	for _, want := range []ConnectionConfirm{
		{Protocol: ProtocolSSL, HasNegotiation: true},
		{Failure: FailSSLRequiredByServer, HasNegotiation: true},
		{},
	} {
		raw, err := want.Encode()
		if err != nil {
			t.Fatal(err)
		}
		pdu, err := ReadPDU(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseConnectionConfirm(pdu.Body)
		if err != nil {
			t.Fatal(err)
		}
		if got.Protocol != want.Protocol || got.Failure != want.Failure ||
			got.HasNegotiation != want.HasNegotiation {
			t.Errorf("read %+v, want %+v", got, want)
		}
	}
}

func TestProtocolNames(t *testing.T) {
	for name, want := range map[string]uint32{"rdp": ProtocolRDP, "tls": ProtocolSSL, "nla": ProtocolHybrid} {
		got, ok := ProtocolByName(name)
		if !ok || got != want {
			t.Errorf("%q parsed as %d (%v)", name, got, ok)
		}
		if ProtocolName(want) != name {
			t.Errorf("%d is named %q", want, ProtocolName(want))
		}
	}
	if _, ok := ProtocolByName("rdstls"); ok {
		t.Error("a protocol this gateway does not mediate was accepted by name")
	}
	if !strings.Contains(ProtocolName(0x99), "99") {
		t.Errorf("an unknown protocol is named %q", ProtocolName(0x99))
	}
}
