package rdp

import (
	"context"
	"fmt"
	"strings"

	"github.com/rom/xproxy/internal/rdp"
)

// The conference exchange, where the client says which virtual
// channels it wants and the desktop answers with an identifier for
// each. It is the one place a gateway can decide what a session will
// be able to do, because every redirection RDP has rides one of these
// channels and nothing can be used that was not granted.
//
// How a channel is refused. The two lists have to line up: the desktop
// answers with one identifier per channel the client asked for, in the
// order it asked, and a client whose answer is a different length does
// not recover. So a refused channel is not taken out of the list --
// its name is replaced with one nothing speaks, which is the same
// number of bytes because the name field is fixed. The desktop
// registers a channel no software has a handler for, the identifiers
// still line up, and the gateway drops whatever the client sends on it
// anyway. The desktop never registers the real channel, which is the
// property worth having.

// inertName is what a refused channel is called instead. Seven
// characters is the most a name can be.
func inertName(i int) string { return fmt.Sprintf("xpdeny%d", i%10) }

// conference runs the exchange on both legs and applies the channel
// policy in the middle.
func (se *session) conference() string {
	t := se.t
	// The client's half.
	pdu, err := rdp.ReadPDU(se.client)
	if err != nil {
		return "client_conference"
	}
	payload, err := rdp.X224Payload(pdu.Body)
	if err != nil {
		return "client_conference"
	}
	conn, err := rdp.ParseConnect(payload)
	if err != nil {
		t.deny(se, "rdp_conference", err.Error())
		return "client_conference"
	}
	if reason := se.applyChannelPolicy(conn); reason != "" {
		return reason
	}
	// What the client said it can encrypt with, which the client's own
	// leg needs before the desktop's block is rewritten over it.
	clientMethods, reason := se.readClientMethods(conn)
	if reason != "" {
		return reason
	}
	if t.wantsLegacy() {
		// What the client said it can encrypt with is not what
		// matters on that leg any more: this gateway holds the keys
		// there, so it says what it can do itself.
		if reason := se.legacyClientSecurity(conn); reason != "" {
			return reason
		}
	}
	out, err := conn.Encode()
	if err != nil {
		return "client_conference"
	}
	if _, err := se.up.Write(out); err != nil {
		return "upstream_write"
	}

	// The desktop's half, which names the identifiers.
	pdu, err = rdp.ReadPDU(se.up)
	if err != nil {
		return "upstream_conference"
	}
	payload, err = rdp.X224Payload(pdu.Body)
	if err != nil {
		return "upstream_conference"
	}
	resp, err := rdp.ParseConnect(payload)
	if err != nil {
		return "upstream_conference"
	}
	if reason := se.readServerChannels(resp); reason != "" {
		return reason
	}
	answer := pdu.Raw
	rewrite := false
	if t.wantsLegacy() {
		// The key exchange with the desktop starts here, and the
		// block the client sees is rewritten, so this half is
		// re-encoded rather than forwarded.
		if reason := se.legacyServerSecurity(resp); reason != "" {
			return reason
		}
		rewrite = true
	}
	if se.clientProtocol == rdp.ProtocolRDP {
		// The client's leg has its own encryption, its own keys and its
		// own certificate, none of which the desktop knows about.
		if reason := se.clientLegacySecurity(resp, clientMethods); reason != "" {
			return reason
		}
		rewrite = true
	}
	if rewrite {
		if answer, err = resp.Encode(); err != nil {
			return "upstream_conference"
		}
	}
	if _, err := se.client.Write(answer); err != nil {
		return "write"
	}
	return ""
}

// readClientMethods takes what the client said it can encrypt with out
// of its half of the exchange. A client that sent no security block at
// all is one that cannot use the protocol's own encryption, which only
// matters when its leg is going to.
func (se *session) readClientMethods(conn *rdp.Connect) (uint32, string) {
	blocks, err := conn.Walk()
	if err != nil {
		return 0, "client_conference"
	}
	for _, b := range blocks {
		if b.Type != rdp.BlockClientSecurity {
			continue
		}
		methods, err := rdp.ParseClientSecurity(b.Data)
		if err != nil {
			se.t.deny(se, "rdp_client_security", err.Error())
			return 0, "client_conference"
		}
		return methods, ""
	}
	return 0, ""
}

// applyChannelPolicy reads the client's channel list and renames the
// ones the policy refuses.
func (se *session) applyChannelPolicy(conn *rdp.Connect) string {
	t := se.t
	blocks, err := conn.Walk()
	if err != nil {
		return "client_conference"
	}
	var list []rdp.Channel
	for _, b := range blocks {
		if b.Type != rdp.BlockClientNetwork {
			continue
		}
		if list, err = rdp.ParseChannels(b.Data); err != nil {
			t.deny(se, "rdp_channels", err.Error())
			return "client_conference"
		}
	}
	if list == nil {
		// A client that asked for no channels at all, which is a
		// session that can see the desktop and nothing else.
		return ""
	}
	out := make([]rdp.Channel, 0, len(list))
	refused := 0
	for i, c := range list {
		name := strings.ToLower(c.Name)
		se.asked = append(se.asked, name)
		if t.channels[name] {
			se.granted = append(se.granted, name)
			se.wanted = append(se.wanted, name)
			out = append(out, c)
			continue
		}
		// Refused: the desktop is asked for a channel nothing speaks,
		// so the identifiers still line up and no handler is
		// registered at the far end.
		se.wanted = append(se.wanted, "")
		out = append(out, rdp.Channel{Name: inertName(i), Options: c.Options})
		refused++
	}
	if refused > 0 {
		t.engine.Counters().RDPChannelsRefused.Add(uint64(refused)) //nolint:gosec // bounded by the channel list
		t.engine.Logs().SecurityEvent(context.Background(), "deny", "rdp_channel_refused",
			"listener", t.cfg.Name, "client_ip", se.ip.String(),
			"asked", strings.Join(se.asked, ","), "granted", strings.Join(se.granted, ","))
	}
	data, err := rdp.EncodeChannels(out)
	if err != nil {
		return "client_conference"
	}
	if err := conn.Replace(rdp.BlockClientNetwork, data); err != nil {
		return "client_conference"
	}
	return ""
}

// readServerChannels learns which identifier carries what, which is
// what the relay needs in order to drop the right traffic.
//
// The identifiers are the desktop's to choose, including the one the
// session itself runs on -- and every decision this gateway makes about
// the credential is made on that one. So a response that does not name
// it ends the session. Without that, an identifier of zero matched
// nothing the client ever sends, the credential packet went past
// unread, and the second factor was not checked: a desktop could turn
// the check off by leaving a block out of its answer.
func (se *session) readServerChannels(resp *rdp.Connect) string {
	blocks, err := resp.Walk()
	if err != nil {
		return "upstream_conference"
	}
	seen := false
	for _, b := range blocks {
		if b.Type != rdp.BlockServerNetwork {
			continue
		}
		sc, err := rdp.ParseServerChannels(b.Data)
		if err != nil {
			return "upstream_conference"
		}
		seen = true
		se.ioChannel = sc.IOChannel
		for i, id := range sc.IDs {
			if i < len(se.wanted) && se.wanted[i] != "" {
				se.channelName[id] = se.wanted[i]
			} else {
				// A channel the policy refused: whatever the client
				// sends here goes nowhere.
				se.inert[id] = true
			}
		}
	}
	if !seen || se.ioChannel == 0 {
		se.t.engine.Logs().SecurityEvent(context.Background(), "deny", "rdp_no_io_channel",
			"listener", se.t.cfg.Name, "client_ip", se.ip.String(), "target", se.target,
			"detail", "the desktop's conference response did not name the channel the session runs on")
		se.t.engine.Counters().RDPRefused.Add(1)
		se.t.engine.Counters().Refuse("rdp", "no_io_channel")
		return "upstream_no_io_channel"
	}
	return ""
}
