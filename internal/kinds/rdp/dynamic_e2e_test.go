package rdp_test

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/rdp"
)

// The channels opened inside drdynvc, through the whole gateway.
//
// The first test here is the bypass, written down. Before this existed, a
// gateway whose static policy allowed only `drdynvc` -- which an operator must
// allow for a usable session on a current client -- carried a dynamic channel
// called `cliprdr` straight to the client, which is the channel the static list
// had just refused by name. That was verified by probe before any of this was
// built.

// dvcHead is a dynamic channel header octet: the command in the top four bits,
// and zeroes below it -- which is priority 0 and a one-byte identifier.
func dvcHead(cmd uint8) byte { return cmd << 4 }

// chunkOf wraps a message as a single-chunk channel PDU.
func chunkOf(msg []byte) []byte {
	c := rdp.ChannelChunk{Total: uint32(len(msg)),
		Flags: rdp.ChannelFlagFirst | rdp.ChannelFlagLast, Data: msg}
	return c.Encode()
}

// dynGateway is a gateway on a TLS leg in both directions, which is the shape
// that matters: the desktop-to-client direction was not inspected there at all.
func dynGateway(t *testing.T, extra string) (*proxy.Server, string, *desktop, *client) {
	t.Helper()
	cert, key, pool := certs(t)
	d := startDesktop(t, &desktop{protocol: rdp.ProtocolSSL, tlsCfg: serverTLS(t, cert, key)})
	s, addr := gateway(t, d, "        upstream_security: tls\n"+
		"        upstream_tls: {ca_file: "+cert+", server_name: gate.test}\n"+
		extra+
		"      tls: {certificates: [{cert_file: "+cert+", key_file: "+key+"}]}")
	cl := dial(t, addr)
	cl.negotiate(rdp.ProtocolSSL, pool)
	cl.conference("drdynvc")
	cl.update() // the desktop's first screen
	return s, addr, d, cl
}

// dynChannel is the identifier the gateway gave drdynvc: the conference hands
// them out in the order asked, starting at 1004.
const dynChannel = 1004

// nextDown reads one unit from the gateway and returns the dynamic channel PDU
// it carried, or nil when it carried something else.
func nextDown(t *testing.T, cl *client, wait time.Duration) *rdp.DVC {
	t.Helper()
	_ = cl.c.SetReadDeadline(time.Now().Add(wait))
	pdu, err := rdp.ReadPDU(cl.c)
	if err != nil {
		return nil
	}
	payload, err := rdp.X224Payload(pdu.Body)
	if err != nil {
		return nil
	}
	data, ok, err := rdp.ParseSendData(payload)
	if err != nil || !ok || data.Channel != dynChannel {
		return nil
	}
	chunk, err := rdp.ParseChannelChunk(data.Payload)
	if err != nil {
		return nil
	}
	dvc, err := rdp.ParseDVC(chunk.Data, rdp.FromServer)
	if err != nil {
		return nil
	}
	return dvc
}

// The bypass, closed. A dynamic channel the policy refuses never reaches the
// client, and the desktop is told so in the protocol's own words rather than
// left waiting for an answer.
func TestARefusedDynamicChannelNeverReachesTheClient(t *testing.T) {
	s, _, d, cl := dynGateway(t, "        channels:\n"+
		"          allow: [drdynvc]\n"+
		"          dynamic:\n"+
		"            allow: ['Microsoft::Windows::RDS::Graphics']\n")

	// The desktop opens the clipboard inside drdynvc. The static list refused
	// cliprdr; the dynamic policy does not name it either.
	d.push <- pushed{channel: dynChannel, payload: chunkOf(rdp.EncodeDVCCreateRequest(3, "cliprdr"))}
	if dvc := nextDown(t, cl, 500*time.Millisecond); dvc != nil {
		t.Fatalf("the client received a create for %q", dvc.Name)
	}
	waitFor(t, "the dynamic channel refusal", func() bool {
		return s.Stats().Refusals["rdp"]["dynamic_channel"] >= 1
	})

	// And the desktop got the answer a client with no such listener sends, so
	// it stops waiting on that channel.
	waitFor(t, "the desktop to be answered", func() bool {
		return len(d.seen(dynChannel)) > 0
	})
	chunk, err := rdp.ParseChannelChunk(d.seen(dynChannel))
	if err != nil {
		t.Fatalf("what reached the desktop is not a channel chunk: %v", err)
	}
	rsp, err := rdp.ParseDVC(chunk.Data, rdp.FromClient)
	if err != nil {
		t.Fatalf("the answer does not parse as a create response: %v", err)
	}
	if rsp.ChannelID != 3 || !rsp.HasStatus || rsp.Status >= 0 {
		t.Errorf("the desktop was answered %+v, want a negative status on channel 3", rsp)
	}
}

// A channel the policy allows goes through, and so does the data on it: the
// point of the policy is a usable session, and the graphics pipeline is what a
// modern client draws through.
func TestAnAllowedDynamicChannelAndItsDataGoThrough(t *testing.T) {
	s, _, d, cl := dynGateway(t, "        channels:\n"+
		"          allow: [drdynvc]\n"+
		"          dynamic:\n"+
		"            allow: ['Microsoft::Windows::RDS::Graphics', echo]\n")

	d.push <- pushed{channel: dynChannel, payload: chunkOf(rdp.EncodeDVCCreateRequest(7, "echo"))}
	dvc := nextDown(t, cl, 2*time.Second)
	if dvc == nil || dvc.Name != "echo" {
		t.Fatalf("the allowed channel did not reach the client: %+v", dvc)
	}
	// Data on it reaches the client too.
	dataPDU := []byte{dvcHead(rdp.DVCData), 0x07, 'h', 'i'}
	d.push <- pushed{channel: dynChannel, payload: chunkOf(dataPDU)}
	if got := nextDown(t, cl, 2*time.Second); got == nil || got.Cmd != rdp.DVCData {
		t.Fatalf("data on the allowed channel did not reach the client: %+v", got)
	}
	waitFor(t, "the channel to be counted", func() bool {
		return s.Stats().RDPDynamicChannelsSeen >= 1
	})
}

// Data on a channel the policy refused goes nowhere. The client was never told
// the channel exists, so it has no listener for it -- and forwarding the
// payload would be forwarding exactly what was refused.
func TestDataOnARefusedDynamicChannelIsDropped(t *testing.T) {
	s, _, d, cl := dynGateway(t, "        channels:\n"+
		"          allow: [drdynvc]\n"+
		"          dynamic: {allow: [echo]}\n")

	d.push <- pushed{channel: dynChannel, payload: chunkOf(rdp.EncodeDVCCreateRequest(9, "rdpdr"))}
	waitFor(t, "the refusal", func() bool {
		return s.Stats().Refusals["rdp"]["dynamic_channel"] >= 1
	})
	// The desktop sends data on the channel it thinks it opened.
	d.push <- pushed{channel: dynChannel, payload: chunkOf([]byte{dvcHead(rdp.DVCData), 0x09, 'x'})}
	if dvc := nextDown(t, cl, 500*time.Millisecond); dvc != nil {
		t.Fatalf("data on a refused channel reached the client: %+v", dvc)
	}
	waitFor(t, "the dropped data to be counted", func() bool {
		return s.Stats().Refusals["rdp"]["dynamic_channel_data"] >= 1
	})
}

// A create request split across two chunks is decided on the whole name. A
// gateway that decided on the first chunk would be deciding on half a name, and
// one that forwarded the chunks as they came would let the client see a channel
// the policy had not finished reading.
func TestACreateSplitAcrossChunksIsReassembledBeforeItIsDecided(t *testing.T) {
	s, _, d, cl := dynGateway(t, "        channels:\n"+
		"          allow: [drdynvc]\n"+
		"          dynamic: {allow: [echo]}\n")

	msg := rdp.EncodeDVCCreateRequest(11, "cliprdr")
	first := rdp.ChannelChunk{Total: uint32(len(msg)), Flags: rdp.ChannelFlagFirst, Data: msg[:3]}
	last := rdp.ChannelChunk{Total: uint32(len(msg)), Flags: rdp.ChannelFlagLast, Data: msg[3:]}
	d.push <- pushed{channel: dynChannel, payload: first.Encode()}
	// Nothing reaches the client on the strength of half a message.
	if dvc := nextDown(t, cl, 300*time.Millisecond); dvc != nil {
		t.Fatalf("a half message reached the client: %+v", dvc)
	}
	d.push <- pushed{channel: dynChannel, payload: last.Encode()}
	if dvc := nextDown(t, cl, 500*time.Millisecond); dvc != nil {
		t.Fatalf("the reassembled create reached the client: %+v", dvc)
	}
	waitFor(t, "the refusal of the reassembled name", func() bool {
		return s.Stats().Refusals["rdp"]["dynamic_channel"] >= 1
	})
}

// A close forgets the identifier, because the desktop reuses numbers. A gateway
// that kept a refusal for ever would refuse a later channel that happened to be
// given the same number -- and that later channel might be one the policy
// allows.
func TestAClosedDynamicChannelIdentifierIsForgotten(t *testing.T) {
	_, _, d, cl := dynGateway(t, "        channels:\n"+
		"          allow: [drdynvc]\n"+
		"          dynamic: {allow: [echo]}\n")

	// Refused on identifier 5, then closed, then the same identifier is used
	// for a channel the policy allows.
	d.push <- pushed{channel: dynChannel, payload: chunkOf(rdp.EncodeDVCCreateRequest(5, "cliprdr"))}
	if dvc := nextDown(t, cl, 400*time.Millisecond); dvc != nil {
		t.Fatalf("the refused create reached the client: %+v", dvc)
	}
	d.push <- pushed{channel: dynChannel, payload: chunkOf([]byte{dvcHead(rdp.DVCClose), 0x05})}
	nextDown(t, cl, 400*time.Millisecond) // the close itself is carried
	d.push <- pushed{channel: dynChannel, payload: chunkOf(rdp.EncodeDVCCreateRequest(5, "echo"))}
	dvc := nextDown(t, cl, 2*time.Second)
	if dvc == nil || dvc.Name != "echo" {
		t.Fatalf("the reused identifier was still refused: %+v", dvc)
	}
}

// The deny list wins, which is how an estate allows the pipeline a session
// needs and keeps redirection out of it.
func TestADynamicDenyListBeatsTheAllowList(t *testing.T) {
	s, _, d, cl := dynGateway(t, "        channels:\n"+
		"          allow: [drdynvc]\n"+
		"          dynamic:\n"+
		"            allow: [echo, rdpdr]\n"+
		"            deny: [rdpdr]\n")

	d.push <- pushed{channel: dynChannel, payload: chunkOf(rdp.EncodeDVCCreateRequest(2, "rdpdr"))}
	if dvc := nextDown(t, cl, 500*time.Millisecond); dvc != nil {
		t.Fatalf("a denied channel reached the client: %+v", dvc)
	}
	waitFor(t, "the refusal", func() bool {
		return s.Stats().Refusals["rdp"]["dynamic_channel"] >= 1
	})
}

// Names are matched without regard to case, as the static list is, because
// clients and desktops differ on the spelling of their own channels.
func TestDynamicChannelNamesAreMatchedWithoutCase(t *testing.T) {
	_, _, d, cl := dynGateway(t, "        channels:\n"+
		"          allow: [drdynvc]\n"+
		"          dynamic: {allow: ['microsoft::windows::rds::graphics']}\n")

	d.push <- pushed{channel: dynChannel,
		payload: chunkOf(rdp.EncodeDVCCreateRequest(4, "Microsoft::Windows::RDS::Graphics"))}
	dvc := nextDown(t, cl, 2*time.Second)
	if dvc == nil || dvc.Name != "Microsoft::Windows::RDS::Graphics" {
		t.Fatalf("a name differing only in case was refused: %+v", dvc)
	}
}

// A listener with no dynamic block carries the channels and counts them, and
// does not refuse them. Refusing by default would break every session that
// works today; the load warns instead, which is what makes the gap visible.
func TestWithNoDynamicPolicyTheChannelsAreCarriedAndCounted(t *testing.T) {
	s, _, d, cl := dynGateway(t, "        channels: {allow: [drdynvc]}\n")

	d.push <- pushed{channel: dynChannel, payload: chunkOf(rdp.EncodeDVCCreateRequest(3, "cliprdr"))}
	dvc := nextDown(t, cl, 2*time.Second)
	if dvc == nil || dvc.Name != "cliprdr" {
		t.Fatalf("a listener with no dynamic policy refused a channel: %+v", dvc)
	}
	waitFor(t, "the channel to be counted", func() bool {
		return s.Stats().RDPDynamicChannelsSeen >= 1
	})
	if n := s.Stats().Refusals["rdp"]["dynamic_channel"]; n != 0 {
		t.Errorf("%d refusals on a listener with no dynamic policy", n)
	}
}

// Shadow mode is a trial: the refusal is recorded and the channel carried.
func TestADynamicChannelPolicyInShadowModeRecordsWithoutRefusing(t *testing.T) {
	s, _, d, cl := dynGateway(t, "        channels:\n"+
		"          allow: [drdynvc]\n"+
		"          dynamic: {allow: [echo]}\n"+
		"      policy: {mode: shadow}\n")

	d.push <- pushed{channel: dynChannel, payload: chunkOf(rdp.EncodeDVCCreateRequest(3, "cliprdr"))}
	dvc := nextDown(t, cl, 2*time.Second)
	if dvc == nil || dvc.Name != "cliprdr" {
		t.Fatalf("a shadowed policy refused the channel: %+v", dvc)
	}
	waitFor(t, "the shadowed refusal", func() bool {
		return s.Stats().WouldRefusals["rdp"]["dynamic_channel"] >= 1
	})
	if n := s.Stats().Refusals["rdp"]["dynamic_channel"]; n != 0 {
		t.Errorf("a shadowed listener counted %d real refusals", n)
	}
}

// The four tests below exist because a mutation survived without them: each is
// a guard the suite could not tell the difference about.

// The client's side of drdynvc is inspected too. A client has no reason to send
// data on a channel it was never told exists, so one that does is not the
// client the desktop thinks it is talking to.
func TestDataFromTheClientOnARefusedDynamicChannelIsDropped(t *testing.T) {
	s, _, d, cl := dynGateway(t, "        channels:\n"+
		"          allow: [drdynvc]\n"+
		"          dynamic: {allow: [echo]}\n")

	d.push <- pushed{channel: dynChannel, payload: chunkOf(rdp.EncodeDVCCreateRequest(6, "cliprdr"))}
	waitFor(t, "the refusal", func() bool {
		return s.Stats().Refusals["rdp"]["dynamic_channel"] >= 1
	})
	before := len(d.seen(dynChannel))
	// The client sends data up on the channel it was never given.
	cl.send(dynChannel, chunkOf([]byte{dvcHead(rdp.DVCData), 0x06, 'u', 'p'}))
	waitFor(t, "the dropped upward data to be counted", func() bool {
		return s.Stats().Refusals["rdp"]["dynamic_channel_data"] >= 1
	})
	// And nothing of it reached the desktop beyond the refusal already sent.
	if n := len(d.seen(dynChannel)); n != before {
		t.Errorf("the desktop received %d more bytes on drdynvc", n-before)
	}
}

// A close forgets the identifier, so data on a number the desktop has reused is
// carried rather than being dropped on a decision about a channel that is gone.
func TestAfterACloseDataOnThatIdentifierIsCarriedAgain(t *testing.T) {
	s, _, d, cl := dynGateway(t, "        channels:\n"+
		"          allow: [drdynvc]\n"+
		"          dynamic: {allow: [echo]}\n")

	d.push <- pushed{channel: dynChannel, payload: chunkOf(rdp.EncodeDVCCreateRequest(8, "cliprdr"))}
	waitFor(t, "the refusal", func() bool {
		return s.Stats().Refusals["rdp"]["dynamic_channel"] >= 1
	})
	// Data on it is dropped while the refusal stands.
	d.push <- pushed{channel: dynChannel, payload: chunkOf([]byte{dvcHead(rdp.DVCData), 0x08, 'a'})}
	if dvc := nextDown(t, cl, 400*time.Millisecond); dvc != nil {
		t.Fatalf("data on the refused channel reached the client: %+v", dvc)
	}
	// The desktop closes it, which is the gateway's cue to forget the number.
	d.push <- pushed{channel: dynChannel, payload: chunkOf([]byte{dvcHead(rdp.DVCClose), 0x08})}
	if dvc := nextDown(t, cl, 2*time.Second); dvc == nil || dvc.Cmd != rdp.DVCClose {
		t.Fatalf("the close did not reach the client: %+v", dvc)
	}
	// Now data on that identifier is nobody's refused channel.
	d.push <- pushed{channel: dynChannel, payload: chunkOf([]byte{dvcHead(rdp.DVCData), 0x08, 'b'})}
	if dvc := nextDown(t, cl, 2*time.Second); dvc == nil || dvc.Cmd != rdp.DVCData {
		t.Fatalf("data on a forgotten identifier was still dropped: %+v", dvc)
	}
}

// A compressed drdynvc message is one this gateway cannot read, and a policy
// that quietly did not apply is worse than a session that ends.
func TestACompressedDynamicChannelMessageEndsTheSession(t *testing.T) {
	_, _, d, cl := dynGateway(t, "        channels:\n"+
		"          allow: [drdynvc]\n"+
		"          dynamic: {allow: [echo]}\n")

	msg := rdp.EncodeDVCCreateRequest(3, "cliprdr")
	chunk := rdp.ChannelChunk{Total: uint32(len(msg)),
		Flags: rdp.ChannelFlagFirst | rdp.ChannelFlagLast | rdp.ChannelPacketCompressed,
		Data:  msg}
	d.push <- pushed{channel: dynChannel, payload: chunk.Encode()}
	// The session has to *end*, not merely go quiet. Reading until any error
	// would pass on a read timeout too, which is what a refused-but-carried
	// session looks like -- so the error has to be the connection closing.
	_ = cl.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		_, err := rdp.ReadPDU(cl.c)
		if err == nil {
			continue
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatalf("the session stayed up after a compressed message: %v", err)
		}
		return
	}
}

// Both reassemblies work in one session. It cannot force the interleaving --
// nothing over the wire lets a test say "now, while the other one is half
// collected" -- so the buffers being separate is proved at unit level in
// reassembly_test.go, and this says the two paths coexist end to end.
func TestBothReassembliesWorkInOneSession(t *testing.T) {
	cert, key, pool := certs(t)
	d := startDesktop(t, &desktop{protocol: rdp.ProtocolSSL, tlsCfg: serverTLS(t, cert, key)})
	s, addr := gateway(t, d, "        upstream_security: tls\n"+
		"        upstream_tls: {ca_file: "+cert+", server_name: gate.test}\n"+
		"        channels:\n"+
		"          allow: [drdynvc, rdpdr]\n"+
		"          dynamic: {allow: [echo]}\n"+
		"        devices: {allow: [printer]}\n"+
		"      tls: {certificates: [{cert_file: "+cert+", key_file: "+key+"}]}")
	cl := dial(t, addr)
	cl.negotiate(rdp.ProtocolSSL, pool)
	cl.conference("drdynvc", "rdpdr")
	cl.update()

	// Start a device announcement travelling up, in two chunks, and leave it
	// half sent.
	announce, err := rdp.EncodeDeviceAnnounce([]rdp.Device{
		{Type: rdp.DevicePrinter, ID: 1, Name: "PRN1"}})
	if err != nil {
		t.Fatal(err)
	}
	first := rdp.ChannelChunk{Total: uint32(len(announce)),
		Flags: rdp.ChannelFlagFirst, Data: announce[:4]}
	cl.send(1005, first.Encode())

	// While it is half collected, a create comes down in two chunks.
	msg := rdp.EncodeDVCCreateRequest(3, "echo")
	dFirst := rdp.ChannelChunk{Total: uint32(len(msg)), Flags: rdp.ChannelFlagFirst, Data: msg[:2]}
	dLast := rdp.ChannelChunk{Total: uint32(len(msg)), Flags: rdp.ChannelFlagLast, Data: msg[2:]}
	d.push <- pushed{channel: dynChannel, payload: dFirst.Encode()}
	d.push <- pushed{channel: dynChannel, payload: dLast.Encode()}
	dvc := nextDown(t, cl, 2*time.Second)
	if dvc == nil || dvc.Name != "echo" {
		t.Fatalf("the create was corrupted by the other reassembly: %+v", dvc)
	}

	// And the announcement finishes correctly, with the printer intact.
	last := rdp.ChannelChunk{Total: uint32(len(announce)),
		Flags: rdp.ChannelFlagLast, Data: announce[4:]}
	cl.send(1005, last.Encode())
	waitFor(t, "the device announcement to arrive whole", func() bool {
		devices, saw := d.redirected()
		return saw && len(devices) == 1 && devices[0].Name == "PRN1"
	})
	if n := s.Stats().Refusals["rdp"]["dynamic_channel"]; n != 0 {
		t.Errorf("%d refusals in a session where everything was allowed", n)
	}
}
