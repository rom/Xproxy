package rdp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// buildConnect assembles a conference exchange half the way a client
// or server sends one, so the tests work against the real shape rather
// than against this package's own encoder alone.
func buildConnect(t *testing.T, response bool, blocks []byte) []byte {
	t.Helper()
	// The conference request or response, with the H.221 key in front
	// of the block area.
	inner := []byte{0x00, 0x08, 0x00, 0x10, 0x00, 0x01, 0xC0, 0x00}
	inner = append(inner, h221Duca...)
	inner = append(inner, perLength(len(blocks))...)
	inner = append(inner, blocks...)
	gcc := append(append([]byte(nil), t124Identifier...), perLength(len(inner))...)
	gcc = append(gcc, inner...)

	var body []byte
	field := func(tag byte, content []byte) {
		body = append(body, tag)
		body = append(body, berLength(len(content))...)
		body = append(body, content...)
	}
	params := bytes.Repeat([]byte{0x02, 0x01, 0x02}, 8) // eight small integers
	if response {
		field(0x0A, []byte{0x00}) // result: success
		field(0x02, []byte{0x00}) // called connect id
		field(0x30, params)       // domain parameters
	} else {
		field(0x04, []byte{0x01}) // calling domain selector
		field(0x04, []byte{0x01}) // called domain selector
		field(0x01, []byte{0xFF}) // upward flag
		field(0x30, params)       // target parameters
		field(0x30, params)       // minimum
		field(0x30, params)       // maximum
	}
	field(0x04, gcc)

	tag := tagConnectInitial
	if response {
		tag = tagConnectResponse
	}
	out := append(append([]byte(nil), tag...), berLength(len(body))...)
	out = append(out, body...)
	pdu, err := DataPDU(out)
	if err != nil {
		t.Fatal(err)
	}
	return pdu
}

// blockArea renders a block area from its blocks.
func blockArea(t *testing.T, blocks ...Block) []byte {
	t.Helper()
	var out []byte
	for _, b := range blocks {
		head := make([]byte, 4)
		binary.LittleEndian.PutUint16(head[0:2], b.Type)
		binary.LittleEndian.PutUint16(head[2:4], uint16(len(b.Data)+4))
		out = append(append(out, head...), b.Data...)
	}
	return out
}

// payloadOf strips the framing a test built.
func payloadOf(t *testing.T, pdu []byte) []byte {
	t.Helper()
	got, err := ReadPDU(bytes.NewReader(pdu))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := X224Payload(got.Body)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

// A client's half parses, and every block that is not the gateway's
// business comes back byte for byte.
func TestConnectInitialRoundTrip(t *testing.T) {
	chans, err := EncodeChannels([]Channel{
		{Name: "rdpdr", Options: ChannelOptionInitialized | ChannelOptionCompressRDP},
		{Name: "cliprdr", Options: ChannelOptionInitialized},
		{Name: "rdpsnd", Options: ChannelOptionInitialized},
	})
	if err != nil {
		t.Fatal(err)
	}
	core := bytes.Repeat([]byte{0xAB}, 216) // a core block this package does not decode
	raw := buildConnect(t, false, blockArea(t,
		Block{Type: BlockClientCore, Data: core},
		Block{Type: BlockClientNetwork, Data: chans},
		Block{Type: BlockClientCluster, Data: []byte{1, 2, 3, 4}}))

	c, err := ParseConnect(payloadOf(t, raw))
	if err != nil {
		t.Fatal(err)
	}
	blocks, err := c.Walk()
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 3 || blocks[0].Type != BlockClientCore || !bytes.Equal(blocks[0].Data, core) {
		t.Fatalf("blocks %+v", blocks)
	}
	got, err := ParseChannels(blocks[1].Data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Name != "rdpdr" || got[1].Name != "cliprdr" ||
		got[0].Options != ChannelOptionInitialized|ChannelOptionCompressRDP {
		t.Fatalf("channels %+v", got)
	}

	// Re-encoded unchanged, it is the same exchange.
	out, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, raw) {
		t.Errorf("a round trip changed the exchange:\n%x\n%x", raw, out)
	}
}

// Taking a channel out shortens every length around it, and what comes
// back out is the shorter list.
func TestChannelsCanBeTakenOut(t *testing.T) {
	chans, _ := EncodeChannels([]Channel{
		{Name: "rdpdr", Options: ChannelOptionInitialized},
		{Name: "cliprdr", Options: ChannelOptionInitialized},
		{Name: "rdpsnd", Options: ChannelOptionInitialized},
	})
	// A block area long enough that the lengths around it are in their
	// two byte form, so shortening actually exercises the encoder.
	raw := buildConnect(t, false, blockArea(t,
		Block{Type: BlockClientCore, Data: bytes.Repeat([]byte{0xAB}, 216)},
		Block{Type: BlockClientNetwork, Data: chans}))
	c, err := ParseConnect(payloadOf(t, raw))
	if err != nil {
		t.Fatal(err)
	}
	kept, err := EncodeChannels([]Channel{{Name: "rdpsnd", Options: ChannelOptionInitialized}})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Replace(BlockClientNetwork, kept); err != nil {
		t.Fatal(err)
	}
	out, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	again, err := ParseConnect(payloadOf(t, out))
	if err != nil {
		t.Fatalf("the shortened exchange does not parse: %v", err)
	}
	blocks, err := again.Walk()
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 2 {
		t.Fatalf("blocks %+v", blocks)
	}
	list, err := ParseChannels(blocks[1].Data)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Name != "rdpsnd" {
		t.Errorf("channels %+v", list)
	}
	if len(out) >= len(raw) {
		t.Errorf("the shortened exchange is %d bytes against %d", len(out), len(raw))
	}
}

// A server's half parses and round-trips the same way.
func TestConnectResponseRoundTrip(t *testing.T) {
	sc, err := ServerChannels{IOChannel: 1003, IDs: []uint16{1004, 1005, 1006}}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	raw := buildConnect(t, true, blockArea(t,
		Block{Type: BlockServerCore, Data: []byte{0x04, 0x00, 0x08, 0x00}},
		Block{Type: BlockServerNetwork, Data: sc},
		Block{Type: BlockServerSecurity, Data: bytes.Repeat([]byte{0}, 12)}))
	c, err := ParseConnect(payloadOf(t, raw))
	if err != nil {
		t.Fatal(err)
	}
	blocks, err := c.Walk()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseServerChannels(blocks[1].Data)
	if err != nil {
		t.Fatal(err)
	}
	if got.IOChannel != 1003 || len(got.IDs) != 3 || got.IDs[2] != 1006 {
		t.Fatalf("server channels %+v", got)
	}
	out, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, raw) {
		t.Error("a round trip changed the server's half")
	}
}

// Every length a peer chooses is checked before it is used to make a
// slice or to walk past the end of what arrived.
func TestConferenceLengthsAreChecked(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
	}{
		{"neither tag", []byte{0x30, 0x02, 0x01, 0x02}},
		{"a length of a length that is silly", append(append([]byte(nil), tagConnectInitial...), 0x88, 1, 2, 3)},
		{"a value past the end", append(append([]byte(nil), tagConnectInitial...), 0x82, 0xFF, 0xFF, 1)},
		{"an indefinite length", append(append([]byte(nil), tagConnectInitial...), 0x80, 1, 2)},
		{"nothing after the tag", tagConnectInitial},
	}
	for _, c := range cases {
		if _, err := ParseConnect(c.in); !errors.Is(err, ErrMCS) && !errors.Is(err, ErrFraming) {
			t.Errorf("%s was accepted (%v)", c.name, err)
		}
	}
	// A block whose length runs past the area is refused rather than
	// sliced past.
	c := &Connect{Blocks: []byte{0x01, 0xC0, 0xFF, 0xFF, 1, 2}}
	if _, err := c.Walk(); !errors.Is(err, ErrMCS) {
		t.Errorf("a block past the area was accepted (%v)", err)
	}
	// And a block that claims to be shorter than its own header.
	c = &Connect{Blocks: []byte{0x01, 0xC0, 0x02, 0x00}}
	if _, err := c.Walk(); !errors.Is(err, ErrMCS) {
		t.Errorf("a block shorter than its header was accepted (%v)", err)
	}
}

// A channel list a peer chooses the size of is bounded before anything
// is allocated for it.
func TestChannelListsAreBounded(t *testing.T) {
	many := binary.LittleEndian.AppendUint32(nil, 1000)
	if _, err := ParseChannels(many); !errors.Is(err, ErrMCS) {
		t.Error("a thousand channels were accepted")
	}
	// A count with nothing behind it.
	if _, err := ParseChannels(binary.LittleEndian.AppendUint32(nil, 4)); !errors.Is(err, ErrMCS) {
		t.Error("a count with no entries was accepted")
	}
	if _, err := ParseServerChannels([]byte{0xEB, 0x03, 0xFF, 0x00}); !errors.Is(err, ErrMCS) {
		t.Error("a server list with no entries was accepted")
	}
	// And on the way out.
	if _, err := EncodeChannels(make([]Channel, MaxChannels+1)); !errors.Is(err, ErrMCS) {
		t.Error("an oversize list was encoded")
	}
	if _, err := EncodeChannels([]Channel{{Name: strings.Repeat("a", ChannelNameLen)}}); !errors.Is(err, ErrMCS) {
		t.Error("a name that does not fit its field was encoded")
	}
}

// Channel names are compared the way the protocol's implementations
// compare them.
func TestChannelNamesIgnoreCase(t *testing.T) {
	if !EqualNames("RDPDR", "rdpdr") || !EqualNames("CliPrdr", "cliprdr") {
		t.Error("a name did not match its own spelling in another case")
	}
	if EqualNames("rdpdr", "rdpsnd") {
		t.Error("two different channels matched")
	}
	// A name shorter than its field comes back without the padding.
	list, err := ParseChannels(append(binary.LittleEndian.AppendUint32(nil, 1),
		append([]byte("rdpdr\x00\x00\x00"), 0, 0, 0, 0x80)...))
	if err != nil {
		t.Fatal(err)
	}
	if list[0].Name != "rdpdr" {
		t.Errorf("name %q", list[0].Name)
	}
}

// Replacing a block that is not there is an error rather than a silent
// no-op, since a policy that quietly did not apply is worse than one
// that refuses.
func TestReplacingAMissingBlockIsAnError(t *testing.T) {
	c := &Connect{Blocks: blockArea(t, Block{Type: BlockClientCore, Data: []byte{1, 2}})}
	if err := c.Replace(BlockClientNetwork, []byte{0}); !errors.Is(err, ErrMCS) {
		t.Errorf("replacing a missing block: %v", err)
	}
}
