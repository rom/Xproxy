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
		t.deny(se.ip, "rdp_conference", err.Error())
		return "client_conference"
	}
	if reason := se.applyChannelPolicy(conn); reason != "" {
		return reason
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
	if _, err := se.client.Write(pdu.Raw); err != nil {
		return "write"
	}
	return ""
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
			t.deny(se.ip, "rdp_channels", err.Error())
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
func (se *session) readServerChannels(resp *rdp.Connect) string {
	blocks, err := resp.Walk()
	if err != nil {
		return "upstream_conference"
	}
	for _, b := range blocks {
		if b.Type != rdp.BlockServerNetwork {
			continue
		}
		sc, err := rdp.ParseServerChannels(b.Data)
		if err != nil {
			return "upstream_conference"
		}
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
	return ""
}
