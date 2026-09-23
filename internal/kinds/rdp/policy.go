package rdp

import (
	"context"
	"strings"

	"github.com/rom/xproxy/internal/rdp"
	"github.com/rom/xproxy/internal/textsafe"
)

// The two things on the client's side that are decisions: which
// redirected devices a session gets, and what the credential says.

// decideDevices filters the device announcement on the redirection
// channel. Nothing can be redirected that was not announced, so this
// one message decides whether a session has drives, printers, ports or
// smart cards -- without the gateway having to understand any of the
// traffic that follows.
func (se *session) decideDevices(data rdp.SendData) ([]byte, bool, string) {
	t := se.t
	chunk, err := rdp.ParseChannelChunk(data.Payload)
	if err != nil {
		t.deny(se.ip, "rdp_channel_chunk", err.Error())
		return nil, false, "client_protocol"
	}
	if chunk.Compressed() {
		// A message this gateway cannot read is one it cannot filter,
		// and a redirection policy that quietly did not apply is worse
		// than a session that ends.
		t.deny(se.ip, "rdp_channel_compressed", rdp.ChannelDeviceRedirection)
		return nil, false, "channel_compressed"
	}
	msg, done, reason := se.reassemble(chunk)
	if reason != "" {
		return nil, false, reason
	}
	if !done {
		// Still collecting: nothing goes to the desktop until the
		// whole message can be looked at.
		return nil, true, ""
	}
	if !rdp.IsDeviceAnnounce(msg) {
		// Anything else on this channel is the redirection protocol
		// doing its work, and passes through.
		return se.sendMessage(data, msg)
	}
	devices, err := rdp.ParseDeviceAnnounce(msg)
	if err != nil {
		t.deny(se.ip, "rdp_device_announce", err.Error())
		return nil, false, "client_protocol"
	}
	kept := make([]rdp.Device, 0, len(devices))
	refused := make([]string, 0, len(devices))
	for _, d := range devices {
		if t.devices[d.Type] {
			kept = append(kept, d)
			continue
		}
		refused = append(refused, rdp.DeviceTypeName(d.Type)+":"+textsafe.Clip64(d.Name))
	}
	if len(refused) > 0 {
		t.engine.Counters().RDPDevicesRefused.Add(uint64(len(refused))) //nolint:gosec // bounded by the device list
		t.engine.Logs().SecurityEvent(context.Background(), "deny", "rdp_device_refused",
			"listener", t.cfg.Name, "client_ip", se.ip.String(),
			"user", textsafe.Clip64(se.user), "target", se.target,
			"refused", strings.Join(refused, ","))
		se.rec.Mark("xproxy: refused " + strings.Join(refused, ", "))
	}
	out, err := rdp.EncodeDeviceAnnounce(kept)
	if err != nil {
		return nil, false, "client_protocol"
	}
	return se.sendMessage(data, out)
}

// reassemble collects a channel message across its chunks. It returns
// the whole message once the last chunk has arrived.
func (se *session) reassemble(chunk rdp.ChannelChunk) (msg []byte, done bool, reason string) {
	if chunk.Flags&rdp.ChannelFlagFirst != 0 {
		se.pending = se.pending[:0]
	}
	if len(se.pending)+len(chunk.Data) > maxChannelMessage {
		se.t.deny(se.ip, "rdp_channel_message", rdp.ChannelDeviceRedirection)
		return nil, false, "channel_message_too_long"
	}
	se.pending = append(se.pending, chunk.Data...)
	if chunk.Flags&rdp.ChannelFlagLast == 0 {
		return nil, false, ""
	}
	out := se.pending
	se.pending = nil
	return out, true, ""
}

// sendMessage puts a channel message back on the wire, in as many
// chunks as it needs.
func (se *session) sendMessage(data rdp.SendData, msg []byte) ([]byte, bool, string) {
	var out []byte
	for off := 0; ; {
		n := len(msg) - off
		if n > chunkSize {
			n = chunkSize
		}
		flags := uint32(0)
		if off == 0 {
			flags |= rdp.ChannelFlagFirst
		}
		if off+n >= len(msg) {
			flags |= rdp.ChannelFlagLast
		}
		chunk := rdp.ChannelChunk{
			Total: uint32(len(msg)), //nolint:gosec // bounded by maxChannelMessage
			Flags: flags, Data: msg[off : off+n],
		}
		pdu, _, reason := se.toTarget(data, chunk.Encode())
		if reason != "" {
			return nil, false, reason
		}
		out = append(out, pdu...)
		off += n
		if off >= len(msg) {
			break
		}
	}
	return out, false, ""
}

// decideIO looks at the session channel for the one packet that
// carries a person: the client info packet. Everything else on it is
// the session itself and passes through.
func (se *session) decideIO(data rdp.SendData) ([]byte, bool, string) {
	head, rest, err := rdp.ParseSecurityHeader(data.Payload)
	if err != nil {
		// Too short to be a packet with a security header: not the one
		// this gateway is looking for.
		return se.rewrapOrRaw(data)
	}
	if head.Flags&rdp.SecInfoPkt == 0 {
		return se.rewrapOrRaw(data)
	}
	if head.Flags&rdp.SecEncrypt != 0 {
		// Encrypted under the protocol's own scheme, which this
		// gateway does not hold the keys for on a TLS leg. A
		// credential it cannot read is one it cannot check.
		se.t.deny(se.ip, "rdp_info_encrypted", "")
		return nil, false, "client_info_encrypted"
	}
	info, err := rdp.ParseClientInfo(rest)
	if err != nil {
		se.t.deny(se.ip, "rdp_client_info", err.Error())
		return nil, false, "client_protocol"
	}
	if reason := se.credential(info); reason != "" {
		return nil, false, reason
	}
	body, err := info.Encode()
	if err != nil {
		return nil, false, "client_protocol"
	}
	return se.sendMessage2(data, append(head.Encode(), body...))
}

// rewrapOrRaw forwards a data unit with nothing of its own changed,
// which on a leg that encrypts still means encrypting it.
func (se *session) rewrapOrRaw(data rdp.SendData) ([]byte, bool, string) {
	return se.toTarget(data, data.Payload)
}

// sendMessage2 wraps one payload, which the session channel's packets
// do not chunk.
func (se *session) sendMessage2(data rdp.SendData, payload []byte) ([]byte, bool, string) {
	out, _, reason := se.toTarget(data, payload)
	if reason != "" {
		return nil, false, reason
	}
	return out, false, ""
}
