package rdp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// A channel data unit round-trips, and a unit of another type is left
// alone rather than misread.
func TestSendDataRoundTrip(t *testing.T) {
	want := SendData{Request: true, Initiator: 1007, Channel: 1004, Priority: 0x70,
		Payload: bytes.Repeat([]byte{0xAB}, 300)}
	got, ok, err := ParseSendData(want.Encode())
	if err != nil || !ok {
		t.Fatalf("%v %v", ok, err)
	}
	if got.Channel != want.Channel || got.Initiator != want.Initiator ||
		got.Priority != want.Priority || !bytes.Equal(got.Payload, want.Payload) {
		t.Errorf("read %+v", got)
	}
	if !got.Request {
		t.Error("a client's unit was read as a server's")
	}
	srv := SendData{Channel: 1004, Payload: []byte{1}}
	if back, _, _ := ParseSendData(srv.Encode()); back.Request {
		t.Error("a server's unit was read as a client's")
	}

	// A join request is not channel data, and says so without an
	// error: a gateway forwards it untouched.
	if _, ok, err := ParseSendData([]byte{MCSChannelJoinRequest << 2, 0, 0, 0, 0}); ok || err != nil {
		t.Errorf("a join request was read as channel data (%v %v)", ok, err)
	}
	if _, ok, _ := ParseSendData(nil); ok {
		t.Error("an empty payload was read as channel data")
	}
}

// A data unit whose length runs past what arrived is refused.
func TestSendDataLengthIsChecked(t *testing.T) {
	short := []byte{mcsSendDataRequest << 2, 0x03, 0xEF, 0x03, 0xEC, 0x70}
	if _, _, err := ParseSendData(short); !errors.Is(err, ErrMCS) {
		t.Error("a unit with no length was accepted")
	}
	past := append(append([]byte(nil), short...), 0x81, 0xFF)
	if _, _, err := ParseSendData(past); !errors.Is(err, ErrMCS) {
		t.Error("a payload past the end was accepted")
	}
}

// The client info packet round-trips with its text in either
// encoding, and what this gateway does not decode comes back
// unchanged.
func TestClientInfoRoundTrip(t *testing.T) {
	for _, unicode := range []bool{true, false} {
		ci := &ClientInfo{
			CodePage: 0x409, Flags: InfoAutologon,
			Domain: "LAB", Username: "alice", Password: "hunter2",
			Shell: "", Dir: `C:\Users\alice`,
			Extra: bytes.Repeat([]byte{0xCD}, 40),
		}
		ci.SetUnicode(unicode)
		raw, err := ci.Encode()
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseClientInfo(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got.Domain != "LAB" || got.Username != "alice" || got.Password != "hunter2" ||
			got.Dir != `C:\Users\alice` || got.Shell != "" {
			t.Fatalf("unicode=%v read %+v", unicode, got)
		}
		if got.Unicode() != unicode {
			t.Errorf("unicode=%v read back as %v", unicode, got.Unicode())
		}
		if !bytes.Equal(got.Extra, ci.Extra) {
			t.Error("what this package does not decode did not survive")
		}
		again, err := got.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(again, raw) {
			t.Error("a round trip changed the packet")
		}
	}
}

// A credential with text outside ASCII survives, since a person's name
// is not always in it.
func TestClientInfoCarriesWideText(t *testing.T) {
	ci := &ClientInfo{Username: "renée", Password: "пароль", Domain: "研究所"}
	ci.SetUnicode(true)
	raw, err := ci.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseClientInfo(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Username != "renée" || got.Password != "пароль" || got.Domain != "研究所" {
		t.Errorf("read %q %q %q", got.Username, got.Password, got.Domain)
	}
}

// Every length in the packet is a peer's to choose, so each is
// checked before it is used.
func TestClientInfoLengthsAreChecked(t *testing.T) {
	if _, err := ParseClientInfo(make([]byte, 10)); !errors.Is(err, ErrMCS) {
		t.Error("a packet shorter than its own header was accepted")
	}
	// A field longer than the bound.
	b := make([]byte, 18)
	binary.LittleEndian.PutUint32(b[4:8], InfoUnicode)
	binary.LittleEndian.PutUint16(b[8:10], MaxInfoField+2)
	if _, err := ParseClientInfo(b); !errors.Is(err, ErrMCS) {
		t.Error("an oversize field was accepted")
	}
	// A field that fits the bound but not the packet.
	binary.LittleEndian.PutUint16(b[8:10], 64)
	if _, err := ParseClientInfo(b); !errors.Is(err, ErrMCS) {
		t.Error("a field past the packet was accepted")
	}
	// And on the way out.
	ci := &ClientInfo{Username: strings.Repeat("a", MaxInfoField+1)}
	if _, err := ci.Encode(); !errors.Is(err, ErrMCS) {
		t.Error("an oversize field was encoded")
	}
}

// The security header says what a packet is, which is how the client
// info packet is found among everything else on the channel.
func TestSecurityHeaderRoundTrip(t *testing.T) {
	h := SecurityHeader{Flags: SecInfoPkt, FlagsHi: 0}
	got, rest, err := ParseSecurityHeader(append(h.Encode(), 1, 2, 3))
	if err != nil {
		t.Fatal(err)
	}
	if got.Flags&SecInfoPkt == 0 || len(rest) != 3 {
		t.Errorf("read %+v with %d bytes behind", got, len(rest))
	}
	if _, _, err := ParseSecurityHeader([]byte{1, 2}); !errors.Is(err, ErrMCS) {
		t.Error("a header of two bytes was accepted")
	}
}
