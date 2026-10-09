package rdp

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/rdp"
)

// The bounds and the refusals on the two channels this gateway reads:
// the redirection channel, where the device announcement decides what a
// session may reach, and the session channel, where the one packet that
// carries a person arrives.
//
// All of it is driven by handing the decision a message rather than by
// putting a client in front of a desktop: a chunk that claims more than
// it carries, one the gateway cannot decompress, and one that would
// grow without end are not things a client library will send.

// policing is a session whose policy allows printers and nothing else.
func policing(t *testing.T) *session {
	t.Helper()
	srv := &server{engine: engine(t), cfg: config.Listener{Name: "desks"},
		v: &config.RDPListener{}, devices: map[uint32]bool{}}
	if d, ok := rdp.DeviceTypeByName("printer"); ok {
		srv.devices[d] = true
	}
	return &session{t: srv, ip: netip.MustParseAddr("192.0.2.9"),
		channelName: map[uint16]string{}, inert: map[uint16]bool{}, dynamic: newDynamicState()}
}

// onChannel wraps a payload as the data unit the decisions are given.
func onChannel(payload []byte) rdp.SendData {
	return rdp.SendData{Request: true, Initiator: 1001, Channel: 1004, Payload: payload}
}

// A chunk is eight octets of header and then the piece. Anything
// shorter is not a chunk, and a gateway that read one anyway would be
// deciding a redirection policy from whatever was in memory after it.
func TestADeviceAnnouncementThisGatewayCannotReadIsRefused(t *testing.T) {
	t.Run("a chunk too short to be one", func(t *testing.T) {
		se := policing(t)
		_, _, reason := se.decideDevices(onChannel([]byte{1, 2, 3}))
		if reason != "client_protocol" {
			t.Errorf("a truncated chunk ended %q, want client_protocol", reason)
		}
	})

	t.Run("a chunk the gateway cannot decompress", func(t *testing.T) {
		// A redirection policy that quietly did not apply is worse
		// than a session that ends.
		se := policing(t)
		chunk := rdp.ChannelChunk{Total: 4, Flags: rdp.ChannelFlagFirst | rdp.ChannelFlagLast |
			rdp.ChannelPacketCompressed, Data: []byte("zzzz")}
		_, _, reason := se.decideDevices(onChannel(chunk.Encode()))
		if reason != "channel_compressed" {
			t.Errorf("a compressed chunk ended %q, want channel_compressed", reason)
		}
	})

	t.Run("a message that would grow without end", func(t *testing.T) {
		se := policing(t)
		// Chunks that never set the last flag, until the message is
		// longer than any channel message this gateway will hold.
		piece := bytes.Repeat([]byte{0x41}, 8<<10)
		var reason string
		for i := 0; i < 16 && reason == ""; i++ {
			flags := uint32(0)
			if i == 0 {
				flags = rdp.ChannelFlagFirst
			}
			chunk := rdp.ChannelChunk{Total: maxChannelMessage * 2, Flags: flags, Data: piece}
			_, _, reason = se.decideDevices(onChannel(chunk.Encode()))
		}
		if reason != "channel_message_too_long" {
			t.Errorf("an endless message ended %q, want channel_message_too_long", reason)
		}
	})

	t.Run("an announcement that does not parse", func(t *testing.T) {
		se := policing(t)
		// The announcement's own header -- the core component and the
		// device-list packet id -- with a device count it does not
		// carry the devices for.
		msg := []byte{0x72, 0x44, 0x41, 0x44, 4, 0, 0, 0}
		chunk := rdp.ChannelChunk{Total: uint32(len(msg)),
			Flags: rdp.ChannelFlagFirst | rdp.ChannelFlagLast, Data: msg}
		_, _, reason := se.decideDevices(onChannel(chunk.Encode()))
		if reason != "client_protocol" {
			t.Errorf("a malformed announcement ended %q, want client_protocol", reason)
		}
	})

	t.Run("anything else on the channel passes through", func(t *testing.T) {
		se := policing(t)
		msg := []byte("not an announcement at all")
		chunk := rdp.ChannelChunk{Total: uint32(len(msg)),
			Flags: rdp.ChannelFlagFirst | rdp.ChannelFlagLast, Data: msg}
		out, _, reason := se.decideDevices(onChannel(chunk.Encode()))
		if reason != "" {
			t.Fatalf("an ordinary message on the channel ended %q", reason)
		}
		if !bytes.Contains(out, msg) {
			t.Error("the message did not reach the desktop unchanged")
		}
	})
}

// A message longer than one chunk goes out as several, each marked
// where it sits in the whole: a desktop that got one oversize chunk
// would see a protocol error rather than the message.
func TestAMessageTooBigForOneChunkIsSentAsSeveral(t *testing.T) {
	se := policing(t)
	msg := bytes.Repeat([]byte{0x42}, chunkSize*2+17)
	out, _, reason := se.sendMessage(onChannel(nil), msg)
	if reason != "" {
		t.Fatalf("sending a long message ended %q", reason)
	}
	// Three chunks' worth of payload, plus the three headers and the
	// data units around them.
	if len(out) < len(msg) {
		t.Errorf("the message went out as %d octets, less than the %d it holds", len(out), len(msg))
	}
}

// The client info packet is the only place a person appears in RDP, so
// an info packet the gateway cannot read is a credential it cannot
// check -- and a session it must not let past.
func TestAnInfoPacketThisGatewayCannotReadIsRefused(t *testing.T) {
	t.Run("too short for a security header", func(t *testing.T) {
		se := policing(t)
		// Not the packet this gateway is looking for, so it passes.
		out, _, reason := se.decideIO(onChannel([]byte{1}))
		if reason != "" {
			t.Fatalf("a short unit on the session channel ended %q", reason)
		}
		if len(out) == 0 {
			t.Error("the unit did not reach the desktop")
		}
	})

	t.Run("encrypted under the protocol's own scheme", func(t *testing.T) {
		se := policing(t)
		head := rdp.SecurityHeader{Flags: rdp.SecInfoPkt | rdp.SecEncrypt}
		_, _, reason := se.decideIO(onChannel(append(head.Encode(), 1, 2, 3)))
		if reason != "client_info_encrypted" {
			t.Errorf("an encrypted info packet ended %q, want client_info_encrypted", reason)
		}
	})

	t.Run("an info packet that does not parse", func(t *testing.T) {
		se := policing(t)
		head := rdp.SecurityHeader{Flags: rdp.SecInfoPkt}
		_, _, reason := se.decideIO(onChannel(append(head.Encode(), 1, 2, 3)))
		if reason != "client_protocol" {
			t.Errorf("a malformed info packet ended %q, want client_protocol", reason)
		}
	})
}

// The dynamic channel tables are bounded, and the two sides are bounded
// separately on purpose: a full table is not a reason to forget a
// refusal, because the refused side is what a decision is enforced
// from.
func TestTheDynamicChannelTablesAreBounded(t *testing.T) {
	s := newDynamicState()
	for i := 0; i < maxDynamicChannels; i++ {
		s.opened(uint32(i), "rdpdr")
	}
	s.opened(9999, "one too many")
	for _, n := range s.names() {
		if n == "one too many" {
			t.Error("a channel past the bound was recorded anyway")
		}
	}
	if s.dropped == 0 {
		t.Error("a channel dropped at the bound was not counted")
	}

	r := newDynamicState()
	for i := 0; i < maxDynamicChannels; i++ {
		r.refuse(uint32(i), "echo")
	}
	r.refuse(9999, "one too many")
	if r.dropped == 0 {
		t.Error("a refusal dropped at the bound was not counted")
	}
	// What was already refused stays refused: that is the half that is
	// enforced.
	if !r.isRefused(0) {
		t.Error("a refusal was forgotten when the table filled")
	}
}

// A channel that was closed is forgotten, refused or not: identifiers
// are reused, so a refusal kept for ever would refuse a later channel
// that happened to be given the same number.
func TestAClosedDynamicChannelIsForgotten(t *testing.T) {
	s := newDynamicState()
	s.refuse(7, "echo")
	if !s.isRefused(7) {
		t.Fatal("the refusal was not recorded")
	}
	s.closed(7)
	if s.isRefused(7) {
		t.Error("a closed channel is still refused, so its number cannot be reused")
	}
	s.opened(8, "rdpdr")
	s.closed(8)
	if len(s.names()) != 0 {
		t.Errorf("a closed channel is still open: %v", s.names())
	}
}

// onDynamic wraps a drdynvc message as the data unit the decisions are
// given, in one chunk.
func onDynamic(msg []byte) rdp.SendData {
	chunk := rdp.ChannelChunk{Total: uint32(len(msg)),
		Flags: rdp.ChannelFlagFirst | rdp.ChannelFlagLast, Data: msg}
	return rdp.SendData{Request: true, Initiator: 1001, Channel: 1005, Payload: chunk.Encode()}
}

// The dynamic channel extension carries its own creates and closes
// inside a virtual channel, so the same three things can go wrong with
// it -- a chunk that is not one, one the gateway cannot decompress, a
// message that would grow without end -- and then the extension's own
// message can be nonsense as well.
func TestADynamicChannelMessageThisGatewayCannotReadIsRefused(t *testing.T) {
	for _, dir := range []struct {
		name string
		run  func(*session, rdp.SendData) string
		want string
		// long is the reason an endless message ends with, which names
		// the side it came from because the two directions reassemble
		// separately.
		long string
	}{
		{
			name: "from the desktop",
			long: "upstream_channel_message_too_long",
			run: func(se *session, data rdp.SendData) string {
				_, reason := se.decideDynamicDown(data)
				return reason
			},
			want: "upstream_protocol",
		},
		{
			name: "from the client",
			long: "client_channel_message_too_long",
			run: func(se *session, data rdp.SendData) string {
				_, _, reason := se.decideDynamicUp(data)
				return reason
			},
			want: "client_protocol",
		},
	} {
		t.Run(dir.name, func(t *testing.T) {
			t.Run("a chunk too short to be one", func(t *testing.T) {
				se := policing(t)
				data := rdp.SendData{Request: true, Channel: 1005, Payload: []byte{1, 2, 3}}
				if reason := dir.run(se, data); reason != dir.want {
					t.Errorf("a truncated chunk ended %q, want %q", reason, dir.want)
				}
			})

			t.Run("a chunk the gateway cannot decompress", func(t *testing.T) {
				se := policing(t)
				chunk := rdp.ChannelChunk{Total: 4, Flags: rdp.ChannelFlagFirst |
					rdp.ChannelFlagLast | rdp.ChannelPacketCompressed, Data: []byte("zzzz")}
				data := rdp.SendData{Request: true, Channel: 1005, Payload: chunk.Encode()}
				if reason := dir.run(se, data); reason != "channel_compressed" {
					t.Errorf("a compressed chunk ended %q, want channel_compressed", reason)
				}
			})

			t.Run("a message that would grow without end", func(t *testing.T) {
				se := policing(t)
				piece := bytes.Repeat([]byte{0x41}, 8<<10)
				var reason string
				for i := 0; i < 16 && reason == ""; i++ {
					flags := uint32(0)
					if i == 0 {
						flags = rdp.ChannelFlagFirst
					}
					chunk := rdp.ChannelChunk{Total: maxChannelMessage * 2, Flags: flags, Data: piece}
					reason = dir.run(se, rdp.SendData{Request: true, Channel: 1005, Payload: chunk.Encode()})
				}
				if reason != dir.long {
					t.Errorf("an endless message ended %q, want %q", reason, dir.long)
				}
			})

			t.Run("a message the extension cannot read", func(t *testing.T) {
				se := policing(t)
				// A command this gateway knows with a length the
				// message does not carry.
				if reason := dir.run(se, onDynamic([]byte{rdp.DVCClose<<4 | 0x02, 1})); reason != dir.want {
					t.Errorf("a malformed drdynvc message ended %q, want %q", reason, dir.want)
				}
			})
		})
	}
}

// A channel the policy refused is answered in the protocol's own
// words, and then nothing travels on it in either direction: the client
// was never told it exists, so data on it is an altered client's doing.
func TestDataOnARefusedDynamicChannelGoesNowhere(t *testing.T) {
	se := policing(t)
	se.dynamic.refuse(7, "echo")

	// The desktop sending data on it: dropped, and counted.
	before := se.t.engine.Counters().RefusalCounts()["rdp"]["dynamic_channel_data"]
	out, reason := se.decideDynamicDown(onDynamic(dvcData(7)))
	if reason != "" || out != nil {
		t.Errorf("data on a refused channel ended %q with %d octets", reason, len(out))
	}
	// The client sending data on it: the same, and the session carries
	// on rather than ending -- an altered client is not a reason to
	// drop somebody's session.
	out, _, reason = se.decideDynamicUp(onDynamic(dvcData(7)))
	if reason != "" || out != nil {
		t.Errorf("client data on a refused channel ended %q with %d octets", reason, len(out))
	}
	if got := se.t.engine.Counters().RefusalCounts()["rdp"]["dynamic_channel_data"]; got != before+2 {
		t.Errorf("dynamic_channel_data counted %d, want %d", got, before+2)
	}

	// And a close forgets it, so the number can be reused.
	if _, reason := se.decideDynamicDown(onDynamic(dvcClose(7))); reason != "" {
		t.Errorf("a close on a refused channel ended %q", reason)
	}
	if se.dynamic.isRefused(7) {
		t.Error("the channel is still refused after it was closed")
	}
}

// dvcData is a data message on one channel, with no payload. The low
// nibble of the command byte is the width of the identifier, which is
// one octet here.
func dvcData(id uint32) []byte { return []byte{rdp.DVCData << 4, byte(id)} }

// dvcClose is a close of one channel.
func dvcClose(id uint32) []byte { return []byte{rdp.DVCClose << 4, byte(id)} }

// The legacy protocol's key exchange, which is the one place a client
// hands this gateway key material. Everything it sends there is read
// with this gateway's own key, so a message that does not parse, a
// sealed random that does not open and key material the method cannot
// use are three separate refusals -- and none of them may leave the
// session running with half a key schedule.
func TestAKeyExchangeThisGatewayCannotCompleteIsRefused(t *testing.T) {
	key, err := rdp.NewLegacyKey()
	if err != nil {
		t.Fatal(err)
	}
	exchanging := func(t *testing.T) *session {
		t.Helper()
		se := policing(t)
		se.t.legacyKey = key
		se.clientLegacy = &legacyLeg{method: rdp.Encryption128Bit,
			level: rdp.EncryptionLevelClientCompatible,
			ready: make(chan struct{})}
		return se
	}

	for _, c := range []struct {
		name    string
		payload []byte
	}{
		{"nothing at all", nil},
		{"a length and no key", []byte{0x48, 0, 0, 0}},
		// A length the message does not carry: the bound that stops a
		// claimed length being read past the buffer.
		{"a length longer than the message", append([]byte{0xff, 0x03, 0, 0}, 1, 2, 3)},
		// A sealed random of the right shape that this gateway's key
		// does not open to anything usable.
		{"a sealed random that is not one", append([]byte{0x48, 0, 0, 0}, bytes.Repeat([]byte{0xAA}, 0x48)...)},
	} {
		t.Run(c.name, func(t *testing.T) {
			se := exchanging(t)
			reason := se.clientExchange(c.payload)
			if reason == "" {
				t.Fatal("a key exchange that cannot be completed was accepted")
			}
			if se.clientLegacy.exchanged {
				t.Error("the leg is marked exchanged after a refusal")
			}
			if se.clientLegacy.in != nil || se.clientLegacy.out != nil {
				t.Error("a key schedule was left behind by a refused exchange")
			}
		})
	}
}
