package rdp

import (
	"context"
	"strings"
	"sync"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/rdp"
	"github.com/rom/xproxy/internal/textsafe"
)

// The channels opened inside drdynvc.
//
// The static channel list in the conference exchange was the whole of this
// gateway's channel policy, and it had a hole with a specific shape. `drdynvc`
// is not a channel but a multiplexer: inside it, channels are opened by name at
// any point in a session. On a current Windows client the graphics pipeline,
// display control, geometry, camera, audio and device and clipboard redirection
// all ride there -- so allowing `drdynvc`, which an operator must do for a
// usable session, allowed every one of them unexamined, including the ones the
// static list had just refused by name.
//
// That was verified rather than assumed: a desktop opened a dynamic channel
// called `cliprdr` through a gateway whose static policy allowed only
// `drdynvc`, and the client received it.
//
// **The desktop opens them.** DYNVC_CREATE_REQ travels desktop to client with
// the name in it; the client answers with a creation status. So this policy
// runs on the desktop-to-client direction, which this gateway did not inspect
// at all on a TLS leg before now, and a refusal is written as the answer a
// client with no such listener would have sent rather than by dropping the
// create and leaving the desktop waiting.

// maxDynamicChannels bounds the dynamic channels one session remembers. A
// desktop opens a handful; one opening thousands is not a desktop, and the
// table is what a refusal on a later data PDU is looked up in.
const maxDynamicChannels = 256

// dynamicPolicy is the compiled policy for the channels inside drdynvc.
type dynamicPolicy struct {
	// written says an operator wrote the block at all. Without it the dynamic
	// channels are carried and counted rather than refused, because refusing
	// them by default would break every session that works today -- and the
	// load warns instead, so the gap is visible rather than silent.
	written     bool
	allow, deny map[string]bool
}

func compileDynamic(c *config.RDPChannelPolicy) *dynamicPolicy {
	p := &dynamicPolicy{allow: map[string]bool{}, deny: map[string]bool{}}
	if c == nil || c.Dynamic == nil {
		return p
	}
	p.written = true
	for _, n := range c.Dynamic.Allow {
		p.allow[strings.ToLower(strings.TrimSpace(n))] = true
	}
	for _, n := range c.Dynamic.Deny {
		p.deny[strings.ToLower(strings.TrimSpace(n))] = true
	}
	return p
}

// Allows says whether a dynamic channel of this name may be opened.
//
// A listener with no dynamic block allows every one of them, which is what
// every configuration written before this policy existed meant. The load warns
// about that rather than this refusing: refusing by default would break every
// session that works today.
func (p *dynamicPolicy) Allows(name string) bool {
	if p == nil || !p.written {
		return true
	}
	n := strings.ToLower(name)
	if p.deny[n] {
		return false
	}
	return p.allow[n]
}

// dynamicState is what one session knows about the channels inside its
// drdynvc: the names of the ones that were opened, and the identifiers of the
// ones that were refused, so that the data PDUs which follow can be dropped.
//
// It is guarded because the two directions run on their own goroutines: the
// desktop's create arrives on one and the client's data on the other.
type dynamicState struct {
	mu      sync.Mutex
	open    map[uint32]string
	refused map[uint32]string
	dropped uint64
}

func newDynamicState() *dynamicState {
	return &dynamicState{open: map[uint32]string{}, refused: map[uint32]string{}}
}

// opened records a channel the policy allowed.
func (s *dynamicState) opened(id uint32, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.open) >= maxDynamicChannels {
		s.dropped++
		return
	}
	s.open[id] = name
	delete(s.refused, id)
}

// refuse records a channel the policy refused, so the data that follows on it
// goes nowhere. A full table is not a reason to forget a refusal: the refused
// side is what a decision is enforced from, so it is bounded separately and
// the identifier stays.
func (s *dynamicState) refuse(id uint32, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.refused) >= maxDynamicChannels {
		s.dropped++
		return
	}
	s.refused[id] = name
	delete(s.open, id)
}

// closed forgets a channel, which is what a close PDU means. An identifier is
// reused once it is closed, so keeping a refusal for ever would refuse a later
// channel that happened to be given the same number.
func (s *dynamicState) closed(id uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.open, id)
	delete(s.refused, id)
}

// isRefused says whether an identifier belongs to a channel the policy refused,
// which is what the data PDUs on it are dropped on.
func (s *dynamicState) isRefused(id uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.refused[id]
	return ok
}

// names is the dynamic channels a session had, for the session log.
func (s *dynamicState) names() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.open))
	for _, n := range s.open {
		out = append(out, n)
	}
	return out
}

// refuseDynamic records a refused dynamic channel.
func (t *server) refuseDynamic(se *session, name string, id uint32) {
	t.engine.Counters().RDPChannelsRefused.Add(1)
	t.engine.Counters().Refuse("rdp", "dynamic_channel")
	t.engine.Logs().SecurityEvent(context.Background(), "deny", "rdp_dynamic_channel_refused",
		"listener", t.cfg.Name, "client_ip", se.ip.String(),
		"user", textsafe.Clip64(se.user), "target", se.target,
		"channel", textsafe.Clip64(name), "dynamic_channel_id", id)
	se.rec.Mark("xproxy: refused the dynamic channel " + textsafe.Clip64(name))
}

// decideDynamicDown decides a drdynvc message travelling from the desktop to
// the client, which is where a dynamic channel is opened.
//
// A create request names the channel; the policy decides it there, because that
// is the only place the name appears. A close forgets the identifier, so that a
// number the desktop reuses later is not still refused on an old decision.
// Everything else on this channel is the extension doing its work and passes
// through.
func (se *session) decideDynamicDown(data rdp.SendData) ([]byte, string) {
	t := se.t
	chunk, err := rdp.ParseChannelChunk(data.Payload)
	if err != nil {
		t.deny(se, "rdp_channel_chunk", err.Error())
		return nil, "upstream_protocol"
	}
	if chunk.Compressed() {
		// A message this gateway cannot read is one it cannot filter, and a
		// dynamic channel policy that quietly did not apply is worse than a
		// session that ends.
		t.deny(se, "rdp_channel_compressed", rdp.ChannelDynamic)
		return nil, "channel_compressed"
	}
	msg, done, reason := se.reassembleDown(chunk)
	if reason != "" {
		return nil, reason
	}
	if !done {
		// Still collecting. Nothing reaches the client until the whole
		// message can be looked at, which is what stops a create request
		// split across two chunks from arriving undecided.
		return nil, ""
	}
	dvc, err := rdp.ParseDVC(msg, rdp.FromServer)
	if err != nil {
		t.deny(se, "rdp_dynamic_channel", err.Error())
		return nil, "upstream_protocol"
	}
	switch {
	case dvc.Cmd == rdp.DVCClose && dvc.HasChannelID:
		se.dynamic.closed(dvc.ChannelID)
	case dvc.HasName:
		// A listener with no dynamic policy allows every name, so this one
		// branch covers both it and an allowed channel. It used to be two,
		// and the second was reachable only by an argument rather than by a
		// difference in what it did -- which a mutation showed by surviving.
		if !t.dynamic.Allows(dvc.Name) {
			if t.shadowed(se.ip, "dynamic_channel", dvc.Name) {
				// A trial: recorded as a refusal that did not happen, and the
				// channel carried. A bastion that refused a channel because a
				// new list was being trialled would be a trial with teeth.
				se.dynamic.opened(dvc.ChannelID, dvc.Name)
				break
			}
			t.refuseDynamic(se, dvc.Name, dvc.ChannelID)
			se.dynamic.refuse(dvc.ChannelID, dvc.Name)
			// Answered in the protocol's own words -- the status a client with
			// no listener of that name sends -- so the desktop stops waiting
			// and gives up on the channel rather than hanging on a create
			// nobody replied to. The create itself never reaches the client.
			if reason := se.answerDynamicRefusal(data, dvc.ChannelID); reason != "" {
				return nil, reason
			}
			return nil, ""
		}
		t.engine.Counters().RDPDynamicChannelsSeen.Add(1)
		se.dynamic.opened(dvc.ChannelID, dvc.Name)
	case dvc.HasChannelID:
		// Data on a channel that was refused goes nowhere: the client was
		// never told the channel exists, so it has no listener for it, and
		// forwarding the payload would be forwarding what the policy refused.
		if se.dynamic.isRefused(dvc.ChannelID) {
			t.engine.Counters().RDPChannelsRefused.Add(1)
			t.engine.Counters().Refuse("rdp", "dynamic_channel_data")
			return nil, ""
		}
	}
	return se.sendDown(data, msg)
}

// decideDynamicUp decides a drdynvc message travelling from the client to the
// desktop. The client answers creates and sends data; what it must not do is
// send data on a channel this gateway refused, which it would have no reason to
// do and which is what an altered client would try.
func (se *session) decideDynamicUp(data rdp.SendData) ([]byte, bool, string) {
	t := se.t
	chunk, err := rdp.ParseChannelChunk(data.Payload)
	if err != nil {
		t.deny(se, "rdp_channel_chunk", err.Error())
		return nil, false, "client_protocol"
	}
	if chunk.Compressed() {
		t.deny(se, "rdp_channel_compressed", rdp.ChannelDynamic)
		return nil, false, "channel_compressed"
	}
	msg, done, reason := se.reassembleUp(chunk)
	if reason != "" {
		return nil, false, reason
	}
	if !done {
		return nil, true, ""
	}
	dvc, err := rdp.ParseDVC(msg, rdp.FromClient)
	if err != nil {
		t.deny(se, "rdp_dynamic_channel", err.Error())
		return nil, false, "client_protocol"
	}
	if dvc.HasChannelID {
		if se.dynamic.isRefused(dvc.ChannelID) {
			t.engine.Counters().RDPChannelsRefused.Add(1)
			t.engine.Counters().Refuse("rdp", "dynamic_channel_data")
			return nil, true, ""
		}
	}
	return se.sendMessage(data, msg)
}

// answerDynamicRefusal writes the create response a client with no listener of
// that name would have sent, back to the desktop.
func (se *session) answerDynamicRefusal(data rdp.SendData, id uint32) string {
	msg := rdp.EncodeDVCCreateResponse(id, rdp.DVCCreateRefused)
	chunk := rdp.ChannelChunk{Total: uint32(len(msg)), //nolint:gosec // a few octets
		Flags: rdp.ChannelFlagFirst | rdp.ChannelFlagLast, Data: msg}
	out, _, reason := se.toTarget(data, chunk.Encode())
	if reason != "" {
		return reason
	}
	if err := se.writeUp(out); err != nil {
		return "upstream_closed"
	}
	return ""
}

// reassembleDown and reassembleUp collect a drdynvc message across its chunks,
// each in its own buffer. One buffer for both directions would splice the
// desktop's create onto the client's answer, since the two arrive on their own
// goroutines.
func (se *session) reassembleDown(chunk rdp.ChannelChunk) (msg []byte, done bool, reason string) {
	return se.collect(&se.dvcDown, chunk, "upstream")
}

func (se *session) reassembleUp(chunk rdp.ChannelChunk) (msg []byte, done bool, reason string) {
	return se.collect(&se.dvcUp, chunk, "client")
}

func (se *session) collect(buf *[]byte, chunk rdp.ChannelChunk, side string) (msg []byte, done bool, reason string) {
	if chunk.Flags&rdp.ChannelFlagFirst != 0 {
		*buf = (*buf)[:0]
	}
	if len(*buf)+len(chunk.Data) > maxChannelMessage {
		se.t.deny(se, "rdp_channel_message", rdp.ChannelDynamic)
		return nil, false, side + "_channel_message_too_long"
	}
	*buf = append(*buf, chunk.Data...)
	if chunk.Flags&rdp.ChannelFlagLast == 0 {
		return nil, false, ""
	}
	out := *buf
	*buf = nil
	return out, true, ""
}

// sendDown puts a drdynvc message back on the wire towards the client, in as
// many chunks as it needs.
func (se *session) sendDown(data rdp.SendData, msg []byte) ([]byte, string) {
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
		chunk := rdp.ChannelChunk{Total: uint32(len(msg)), //nolint:gosec // bounded by maxChannelMessage
			Flags: flags, Data: msg[off : off+n]}
		pdu, err := rewrap(data, chunk.Encode())
		if err != nil {
			return nil, "upstream_protocol"
		}
		out = append(out, pdu...)
		off += n
		if off >= len(msg) {
			break
		}
	}
	return out, ""
}
