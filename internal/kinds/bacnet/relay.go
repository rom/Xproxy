package bacnet

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/rom/xproxy/internal/admit"
	"github.com/rom/xproxy/internal/authorization"
	wire "github.com/rom/xproxy/internal/bacnet"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/safe"
	"github.com/rom/xproxy/internal/upstream"
)

// The datagram path. BACnet/IP is request and answer over UDP with no
// session and nothing to close, so the relay keeps one socket towards the
// building and pairs answers to questions by invoke identifier -- which it
// has to translate, because the standard makes that identifier unique only
// between one client and one device.

// serve runs the listener until it is shut down.
func (t *server) serve() {
	if !t.running.Enter() {
		// Shut down before it started, which a reload can do.
		return
	}
	defer t.running.Leave()
	device, err := t.deviceSocket()
	if err != nil {
		t.host.Logs().Error.Error("bacnet device socket could not be opened",
			"listener", t.name, "error", err.Error())
		return
	}
	defer func() { _ = device.Close() }()
	if t.running.Enter() {
		go func() {
			defer t.running.Leave()
			defer safe.Guard("bacnet device reader")
			t.readDevice(device)
		}()
	}
	buf := make([]byte, wire.MaxMessage+1)
	for {
		if t.running.Closing() {
			return
		}
		_ = t.pc.SetReadDeadline(time.Now().Add(time.Second))
		n, from, err := t.pc.ReadFrom(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return
		}
		if n > t.maxMessage() {
			// Refused unread. Reading it to find out what it asked for is
			// the work the bound exists to avoid, and no BACnet message
			// this listener will forward is longer than this.
			t.deny(netutil.AddrOf(from.String()), "message_too_large", strconv.Itoa(n))
			continue
		}
		raw := make([]byte, n)
		copy(raw, buf[:n])
		t.fromClient(device, raw, from)
	}
}

// deviceSocket opens the socket this relay speaks to the building from.
func (t *server) deviceSocket() (net.PacketConn, error) {
	var lc net.ListenConfig
	return lc.ListenPacket(context.Background(), "udp", ":0")
}

// admitClient is the two questions this relay asks about a client that has no
// identity: do the imported lists know this address, and does the estate's
// authorisation policy allow it here.
//
// BACnet names nobody -- a client is an address and, on a routed network, a
// network number and a MAC address -- so the policy decides on the address, the
// listener, the pool and the hour. Which services and which objects that client
// may touch is the `bacnet` policy's own business, because it is the thing that
// can say what a write to analog-output 3 means in a building.
//
// It is asked once per datagram, like this relay's own address lists, because
// BACnet/IP has no session to hang the answer on. A refusal goes through deny, so
// a client that keeps sending earns a ban the same way one refused by the address
// lists does -- which is what stops the record from being written at packet rate.
func (t *server) admitClient(ip netip.Addr) string {
	h := t.host
	return admit.Client(admit.Deps{
		Lists: h.ThreatIntel(),
		// A behaviour pack holding this address out, where one is.
		Quarantined: h.Packs().Quarantined,
		Policy:      h.Authorization(),
		Logs:        h.Logs(),
		Matched:     func() { h.Counters().ThreatIntelMatched.Add(1) },
		Blocked:     func() { h.Counters().ThreatIntelBlocked.Add(1) },
	}, authorization.Subject{
		Listener: t.name,
		Kind:     "bacnet",
		Client:   ip,
		Target:   t.m.Upstream,
		Action:   authorization.ActionConnect,
	}, admit.Gate{
		Shadowing: func() bool { return !t.enforcing() },
		Record: func(reason, rule, detail string) {
			h.Counters().WouldRefuse("bacnet", reason)
			h.Shadow().Record("bacnet", t.name, reason, rule, detail)
		},
		Deny: func(reason, _, detail string) { t.deny(ip, reason, detail) },
	})
}

// fromClient decides about one datagram from a client and, when it is
// allowed, forwards it into the building.
func (t *server) fromClient(device net.PacketConn, raw []byte, from net.Addr) {
	ip := netutil.AddrOf(from.String())
	if !t.policy.Client(ip) {
		t.deny(ip, "client_not_allowed", "")
		return
	}
	// The imported lists and the estate's authorisation policy, after this
	// listener's own address lists -- those are local policy about local
	// clients, and a feed must not overrule an allow rule an operator wrote --
	// and before anything reaches the building.
	if t.admitClient(ip) != "" {
		return
	}
	// The rate limit is a bound rather than policy, so it is never
	// shadowed: a relay that let a flood through because its policy was in
	// shadow mode would be a relay with no bound at all. On a building it
	// is also the only thing between a discovery sweep and every
	// controller in the estate answering it.
	if t.limiter != nil && !t.limiter.Allow(ip.String()) {
		t.host.Counters().Refuse("bacnet", "rate_limited")
		return
	}
	v, err := wire.ParseBVLC(raw)
	if err != nil {
		t.malformed(ip, err)
		return
	}
	if d := t.policy.Link(v.Function); !d.Allow {
		t.refused(ip, nil, d, v.Function.String())
		if t.enforcing() {
			return
		}
	}
	if v.Function == wire.FuncForwardedNPDU && v.HasOrigin && v.Origin.Addr() != ip {
		// The originating address is inside the payload, where whoever
		// sent the datagram chose it. A Forwarded-NPDU claiming to come
		// from somewhere other than the address it arrived from is either a
		// BBMD doing its job or somebody putting another host's address on
		// a broadcast; a relay cannot tell, and the one it is safe to
		// assume is the second.
		t.deny(ip, "forwarded_origin_mismatch", v.Origin.Addr().String())
		if t.enforcing() {
			return
		}
	}
	if !v.Function.CarriesNPDU() {
		// A link layer message with nothing inside it for the policy to
		// read: a BVLC-Result, or a BBMD function the link check let
		// through. It is forwarded as it stands.
		t.forward(device, raw, ip, from, v.Function, nil, nil, Decision{Allow: true})
		return
	}
	n, err := wire.ParseNPDU(v.Payload)
	if err != nil {
		t.malformed(ip, err)
		return
	}
	if d := t.policy.Network(n); !d.Allow {
		t.refused(ip, nil, d, d.Detail)
		if t.enforcing() {
			return
		}
	}
	if n.NetworkMessage {
		t.logNetwork(ip, n)
		t.forward(device, raw, ip, from, v.Function, &n, nil, Decision{Allow: true})
		return
	}
	a, err := wire.ParseAPDU(n.APDU)
	if err != nil {
		t.malformed(ip, err)
		return
	}
	targets, located := wire.Targets(a)
	req := request{client: ip, fn: v.Function, npdu: &n, apdu: &a,
		targets: targets, located: located, at: time.Now()}
	d := t.policy.Decide(req)
	if !d.Allow {
		t.refused(ip, &a, d, what(&a, targets))
		if t.enforcing() || d.Hard {
			t.answerRefusal(a, from)
			return
		}
	}
	// Engineering: a restart, a controller told to stop talking, a file into
	// the device. Reported whatever the policy said, and refused where this
	// listener requires an approved grant for it.
	if reason := t.decideEngineering(req); reason != "" {
		t.answerRefusal(a, from)
		return
	}
	// Behavioural detection, after the policy and on the messages that are
	// going on into the building: the models learn from what reached it, and a
	// message the policy refused never got there.
	if reason := t.decideAnomaly(req); reason != "" {
		t.answerRefusal(a, from)
		return
	}
	// The hop count is lowered rather than refused. It is what stops a
	// routing loop, and a message that arrives claiming more hops than this
	// relay allows is still a message the building should get -- with fewer
	// hops left, which is the safe direction.
	t.lowerHop(raw, n)
	t.forward(device, raw, ip, from, v.Function, &n, &a, d)
}

// lowerHop rewrites a hop count above the bound, in place.
//
// The offset is derived rather than searched for: the hop count follows the
// destination and source address fields, and the parsed header says how
// long those were.
func (t *server) lowerHop(raw []byte, n wire.NPDU) {
	if !n.HasDest || n.Hop <= t.policy.maxHop {
		return
	}
	at := len(raw) - len(n.APDU) - 1
	if at < 0 || at >= len(raw) || raw[at] != n.Hop {
		// The arithmetic and the message disagree, which means this relay
		// would be writing over something else. Leave it alone: a hop
		// count one too high is a smaller problem than a rewritten octet
		// in a message nobody has read again.
		return
	}
	raw[at] = t.policy.maxHop
	t.host.Counters().Refuse("bacnet", "hop_count_lowered")
}

// forward sends a decided datagram into the building and records what it
// needs to pair the answer.
func (t *server) forward(device net.PacketConn, raw []byte, ip netip.Addr, from net.Addr,
	fn wire.Function, n *wire.NPDU, a *wire.APDU, d Decision) {
	addr := t.deviceAddr(ip)
	if addr == nil {
		t.host.Counters().Refuse("bacnet", "no_upstream")
		return
	}
	out := raw
	now := time.Now()
	switch {
	case a != nil && a.Type == wire.PDUConfirmedRequest:
		e := &exchange{client: ip, from: from, device: addr.String(),
			clientID: a.InvokeID, service: a.Service.Name(), rule: d.Rule}
		mine, ok := t.pend.add(e, now)
		if !ok {
			// Every invoke identifier is outstanding, which means the
			// devices are not answering. Refusing keeps the pairing
			// reliable, and that pairing is the check that finds an answer
			// nobody asked for rather than a convenience.
			t.deny(ip, "too_many_pending", strconv.Itoa(t.pend.outstanding()))
			return
		}
		out = withInvokeID(raw, n, a, mine)
	case a != nil && a.HasInvokeID && !a.Type.Request():
		// A segment acknowledgement, or an abort or an error the client
		// sends about an exchange it started. All three name the identifier
		// the *client* chose, and the device is waiting for the one this
		// relay chose -- so a relay that forwarded them unchanged would
		// have every segmented reply stall after its first window.
		mine, ok := t.pend.translate(from, a.InvokeID, now)
		if !ok {
			// There is no exchange here to acknowledge. On a datagram
			// protocol that is either a client whose request has already
			// timed out or a stranger interfering with somebody else's
			// segmented transfer, and neither is forwarded.
			t.deny(ip, "no_such_exchange", a.Type.String())
			return
		}
		out = withInvokeID(raw, n, a, mine)
	case a != nil && a.Type == wire.PDUUnconfirmedRequest:
		// Nothing pairs an I-Am with the Who-Is that asked for it, so the
		// answers are matched to a client that broadcast recently and
		// bounded in number. That bound is this protocol's amplification
		// control.
		b := &broadcast{from: from, client: ip, left: t.maxReplies, deadline: now.Add(t.window)}
		if !t.pend.addBroadcast(b, now) {
			t.deny(ip, "too_many_broadcasts", "")
			return
		}
	case a == nil && n == nil && fn.LinkRequest():
		// A virtual link layer request: a distribution or foreign device
		// table read, a registration. Its answer is a BVLC-Result or a
		// table acknowledgement, and the link layer carries no identifier
		// to pair one by -- so it gets a window of exactly one reply,
		// which is what the request expects and no more than that. Without
		// it a listener with allow_bbmd on would forward the question and
		// drop the answer.
		b := &broadcast{from: from, client: ip, left: 1, deadline: now.Add(t.window)}
		if !t.pend.addBroadcast(b, now) {
			t.deny(ip, "too_many_broadcasts", "")
			return
		}
	}
	if _, err := device.WriteTo(out, addr); err != nil {
		t.host.Counters().Refuse("bacnet", "upstream_failed")
		t.host.Logs().Error.Warn("bacnet forward to device failed", "listener", t.name,
			"device", addr.String(), "error", err.Error())
		// The request never left, so no answer is coming and there is no
		// reason to hold its invoke identifier until the timeout: an
		// operator reading the outstanding count should see the requests
		// that are actually outstanding.
		if mine, held := allocated(out, n, a); held {
			t.pend.drop(mine)
		}
		return
	}
	if a != nil {
		t.logRequest(ip, a, d)
	}
}

// allocated reports the invoke identifier the relay put in a datagram it
// was about to send, so a send that failed can give it back.
func allocated(out []byte, n *wire.NPDU, a *wire.APDU) (uint8, bool) {
	if n == nil || a == nil || a.Type != wire.PDUConfirmedRequest || !a.HasInvokeID {
		return 0, false
	}
	at := len(out) - len(n.APDU) + a.InvokeOffset
	if at < 0 || at >= len(out) {
		return 0, false
	}
	return out[at], true
}

// withInvokeID returns the datagram with the relay's own invoke identifier
// written in.
//
// The offset comes from the parse rather than from a search: the
// application PDU aliases the datagram, and the parser recorded where in it
// the identifier sits.
func withInvokeID(raw []byte, n *wire.NPDU, a *wire.APDU, id uint8) []byte {
	if n == nil || a == nil || !a.HasInvokeID {
		return raw
	}
	at := len(raw) - len(n.APDU) + a.InvokeOffset
	if at < 0 || at >= len(raw) || raw[at] != a.InvokeID {
		// The arithmetic and the message disagree. Forwarding the
		// datagram unchanged means the answer will not pair and the client
		// will time out, which is the failure that loses nothing.
		return raw
	}
	out := make([]byte, len(raw))
	copy(out, raw)
	out[at] = id
	return out
}

// deviceAddr picks the device a message goes to.
func (t *server) deviceAddr(client netip.Addr) net.Addr {
	pool := t.host.Pool(t.m.Upstream)
	if pool == nil {
		return nil
	}
	e, _ := pool.Pick(client.String(), "", nil, upstream.CanaryAny)
	if e == nil {
		return nil
	}
	addr, err := net.ResolveUDPAddr("udp", e.Address)
	if err != nil {
		return nil
	}
	return addr
}

// readDevice reads what the building sends back.
func (t *server) readDevice(device net.PacketConn) {
	buf := make([]byte, wire.MaxMessage+1)
	for {
		if t.running.Closing() {
			return
		}
		_ = device.SetReadDeadline(time.Now().Add(time.Second))
		n, from, err := device.ReadFrom(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return
		}
		if n > t.maxMessage() {
			t.deny(netutil.AddrOf(from.String()), "reply_too_large", strconv.Itoa(n))
			continue
		}
		raw := make([]byte, n)
		copy(raw, buf[:n])
		t.fromDevice(raw, from)
	}
}

// fromDevice decides about one datagram from the building and delivers it
// to the client it belongs to.
func (t *server) fromDevice(raw []byte, from net.Addr) {
	ip := netutil.AddrOf(from.String())
	v, err := wire.ParseBVLC(raw)
	if err != nil {
		t.deny(ip, "malformed_reply", err.Error())
		return
	}
	if !v.Function.CarriesNPDU() {
		// A BVLC-Result or a table answer. It belongs to whatever the
		// relay last sent, and there is no identifier to pair it by, so it
		// goes to the clients with an outstanding broadcast if any and is
		// dropped otherwise -- a link layer answer to nobody is not
		// forwarded on the strength of arriving.
		t.fanOut(raw, ip, v.Function.String())
		return
	}
	n, err := wire.ParseNPDU(v.Payload)
	if err != nil {
		t.deny(ip, "malformed_reply", err.Error())
		return
	}
	if n.NetworkMessage {
		t.fanOut(raw, ip, n.MessageType.String())
		return
	}
	a, err := wire.ParseAPDU(n.APDU)
	if err != nil {
		t.deny(ip, "malformed_reply", err.Error())
		return
	}
	if a.Type.Request() {
		if a.Type == wire.PDUUnconfirmedRequest {
			// An I-Am, an I-Have, a COV notification: a device speaking of
			// its own accord. These are the answers to a broadcast and the
			// notifications a subscription asked for, and they are bounded.
			//
			// The service list applies here too, because it is a statement
			// about which services cross this listener rather than about
			// which a client may send. The one that matters is
			// timeSynchronization: a device -- or something on the plant
			// network wearing a device's address -- broadcasting one at a
			// client network is a clock set on every host that listens, and
			// it is not on the default list in either direction.
			if d, ok := t.policy.serviceCheck(a.Service); !ok {
				t.refused(ip, &a, d, "from the building: "+a.Service.Name())
				if t.enforcing() {
					return
				}
			}
			t.fanOut(raw, ip, a.Service.Name())
			return
		}
		// A confirmed request from the building towards a client. There is
		// no exchange it answers, and forwarding it would make this relay
		// the way into a client network rather than out of one.
		t.deny(ip, "wrong_direction", a.Service.Name())
		return
	}
	last := !a.Segmented || !a.MoreFollows
	e, expired := t.pend.take(a.InvokeID, from.String(), last, time.Now())
	if e == nil {
		// An answer nobody asked for. On a datagram protocol that is the
		// shape of an answer-spoofing attempt: a reply to a question the
		// client did ask, from somewhere else, arriving first.
		t.deny(ip, "unsolicited_reply", a.Type.String())
		return
	}
	if expired {
		t.host.Counters().Refuse("bacnet", "reply_after_timeout")
		return
	}
	out := withInvokeID(raw, &n, &a, e.clientID)
	if _, err := t.pc.WriteTo(out, e.from); err != nil {
		t.host.Counters().Refuse("bacnet", "client_write_failed")
		return
	}
	t.logReply(e, &a)
}

// fanOut delivers an unsolicited datagram to the clients that have an
// outstanding broadcast, spending one of each one's replies.
func (t *server) fanOut(raw []byte, ip netip.Addr, what string) {
	targets := t.pend.broadcastTargets(time.Now())
	if len(targets) == 0 {
		// Nothing asked, so nothing is told. This is the amplification
		// bound doing its work: an answer arriving outside anybody's
		// window is an answer this relay does not forward.
		t.host.Counters().Refuse("bacnet", "unsolicited_broadcast")
		return
	}
	for _, to := range targets {
		if _, err := t.pc.WriteTo(raw, to); err != nil {
			t.host.Counters().Refuse("bacnet", "client_write_failed")
		}
	}
	t.logBroadcastReply(ip, what, len(targets))
}

// answerRefusal tells a refused client no, in the protocol's own terms.
//
// Only a confirmed request has anything to answer: an unconfirmed request
// expects nothing back, so a refusal of one is silence whatever
// deny_response says. The protocol gives a relay nothing else to say.
func (t *server) answerRefusal(a wire.APDU, to net.Addr) {
	if t.reject == "drop" || a.Type != wire.PDUConfirmedRequest || !a.HasInvokeID {
		return
	}
	var apdu []byte
	if t.reject == "error" {
		// An Error-PDU: service, then error class 1 (services) and error
		// code 25 (service request denied), each an application-tagged
		// enumerated.
		apdu = []byte{0x50, a.InvokeID, a.Service.Choice, 0x91, 0x01, 0x91, 0x19}
	} else {
		// A Reject-PDU with reason 9, "other": the client stops rather
		// than retrying, which is what a refused client should do.
		apdu = []byte{0x60, a.InvokeID, 0x09}
	}
	msg := make([]byte, 0, 4+2+len(apdu))
	msg = append(msg, 0x81, byte(wire.FuncOriginalUnicast), 0, 0)
	msg = append(msg, 0x01, 0x00) // network layer: version 1, no addressing
	msg = append(msg, apdu...)
	binary.BigEndian.PutUint16(msg[2:4], uint16(len(msg))) //nolint:gosec // a refusal is a dozen octets, built here
	if _, err := t.pc.WriteTo(msg, to); err != nil {
		t.host.Counters().Refuse("bacnet", "client_write_failed")
	}
}

// what renders the subject of a request for a log line: the service, and
// the object and property when this relay found them.
func what(a *wire.APDU, targets []wire.Target) string {
	if a == nil || !a.HasService {
		return ""
	}
	s := a.Service.Name()
	if len(targets) == 0 {
		return s
	}
	s += " " + targets[0].Object.String()
	if targets[0].HasProperty {
		s += "." + targets[0].Property.String()
	}
	if len(targets) > 1 {
		s += " +" + strconv.Itoa(len(targets)-1)
	}
	return s
}
