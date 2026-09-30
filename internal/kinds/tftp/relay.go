package tftp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/rom/xproxy/internal/admit"
	"github.com/rom/xproxy/internal/authorization"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/safe"
	wire "github.com/rom/xproxy/internal/tftp"
	"github.com/rom/xproxy/internal/upstream"
)

// The request path. Everything arrives on the listener's own socket -- port 69
// -- and every datagram there is either a read request, a write request or
// something that does not belong on that port at all: once a transfer has
// started it runs between two ephemeral ports and never touches this socket
// again.

func (t *server) serveRequests() {
	buf := make([]byte, wire.MaxPacket+1)
	for {
		select {
		case <-t.done:
			return
		default:
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
		raw := make([]byte, n)
		copy(raw, buf[:n])
		t.request(raw, from)
	}
}

// admitClient is the two questions this relay asks about a client that has no
// identity: do the imported lists know this address, and does the estate's
// authorisation policy allow it here.
//
// TFTP names nobody at all -- it has no authentication of any kind, which is the
// whole reason a relay in front of it is worth having -- so the policy decides on
// the address, the listener, the pool and the hour. Which paths that client may
// read, and whether it may write at all, is the `tftp` policy's own business.
//
// It is asked once per request datagram, like this relay's own address lists,
// because the request is all there is: a transfer runs between two ephemeral
// ports afterwards and never comes back to this socket. A refusal goes through
// deny, so a client that keeps asking earns a ban the same way one refused by the
// address lists does.
func (t *server) admitClient(ip netip.Addr) string {
	h := t.host
	return admit.Client(admit.Deps{
		Lists:   h.ThreatIntel(),
		Policy:  h.Authorization(),
		Logs:    h.Logs(),
		Matched: func() { h.Counters().ThreatIntelMatched.Add(1) },
		Blocked: func() { h.Counters().ThreatIntelBlocked.Add(1) },
	}, authorization.Subject{
		Listener: t.cfg.Name,
		Kind:     "tftp",
		Client:   ip,
		Target:   t.m.Upstream,
		Action:   authorization.ActionConnect,
	}, admit.Gate{
		Shadowing: func() bool { return !t.enforcing() },
		Record: func(reason, rule, detail string) {
			h.Counters().WouldRefuse("tftp", reason)
			h.Shadow().Record("tftp", t.cfg.Name, reason, rule, detail)
		},
		Deny: func(reason, _, detail string) { t.deny(ip, reason, detail) },
	})
}

// request decides about one datagram on the listener's socket and, when it is
// allowed, starts a transfer for it.
func (t *server) request(raw []byte, from net.Addr) {
	c := t.host.Counters()
	ip := netutil.AddrOf(from.String())
	c.TFTPRequests.Add(1)
	if !t.policy.Client(ip) {
		c.TFTPRejected.Add(1)
		c.Refuse("tftp", "client_not_allowed")
		t.deny(ip, "client_not_allowed", "")
		return
	}
	// The imported lists and the estate's authorisation policy, after this
	// listener's own address lists -- those are local policy about local
	// clients, and a feed must not overrule an allow rule an operator wrote --
	// and before a transfer is started.
	if reason := t.admitClient(ip); reason != "" {
		c.TFTPRejected.Add(1)
		c.Refuse("tftp", reason)
		return
	}
	// The rate limit is a bound rather than policy, so it is never shadowed.
	// It is also the only thing standing between this listener and a flood of
	// requests each of which would open a socket.
	if t.limiter != nil && !t.limiter.Allow(ip.String()) {
		c.TFTPRateLimited.Add(1)
		c.Refuse("tftp", "rate_limited")
		return
	}
	p, err := wire.Parse(raw)
	if err != nil {
		c.TFTPMalformed.Add(1)
		c.Refuse("tftp", "malformed")
		t.deny(ip, "malformed", err.Error())
		t.answer(from, wire.ErrIllegalOp, "this is not a request")
		return
	}
	if !p.Op.Request() {
		// A data packet, an acknowledgement or an option acknowledgement on
		// the request port. RFC 1350 gives the request port one job, and a
		// packet sent there with any other opcode is either a client that
		// lost track of its own transfer identifier or somebody feeling
		// around. Either way there is no transfer here for it to belong to.
		c.TFTPUnsolicited.Add(1)
		c.Refuse("tftp", "not_a_request")
		t.deny(ip, "not_a_request", p.Op.String())
		t.answer(from, wire.ErrIllegalOp, "only a request belongs on this port")
		return
	}
	req := p.Request
	pa := wire.Classify(req.Filename)
	d := t.policy.Decide(request{client: ip, op: p.Op, path: pa, mode: req.Mode, at: time.Now()})
	// The learning run sees the request and the decision, before the refusal:
	// what a policy would have refused is the most useful line in the report,
	// and a run that only saw what got through would not have it.
	t.observeRequest(ip.String(), p.Op, pa, req.Mode, req, d.Allow, time.Now())
	if !d.Allow {
		t.refused(ip, p.Op, pa, req.Mode, d)
		if t.enforcing() || d.Hard {
			t.answer(from, refusalCode(d.Reason), "refused")
			return
		}
	}
	// Engineering: a write is an image or a configuration going where devices
	// boot from. Reported whatever the policy said, and refused where this
	// listener requires an approved work order for it.
	if reason := t.decideEngineering(ip, p.Op, pa); reason != "" {
		t.answer(from, wire.ErrAccessViolation, "no approved work order")
		return
	}
	// The bounds, applied by rewriting the request rather than refusing it.
	// These are never shadowed: a listener whose policy was in shadow mode
	// would otherwise be a working amplifier.
	out, ask, lowered, bad := t.bound(req, p.Op, d)
	if bad != "" {
		c.TFTPOversize.Add(1)
		c.Refuse("tftp", bad)
		t.deny(ip, bad, req.Filename)
		t.answer(from, wire.ErrOptionRefused, "an option is outside this relay's bounds")
		return
	}
	if lowered {
		c.TFTPLowered.Add(1)
	}
	addr := t.serverAddr(ip)
	if addr == nil {
		c.TFTPUpstreamFail.Add(1)
		t.answer(from, wire.ErrNotDefined, "no server available")
		return
	}
	cl, ok := from.(*net.UDPAddr)
	if !ok {
		c.TFTPMalformed.Add(1)
		c.Refuse("tftp", "not_udp")
		return
	}
	// The transfer runs at the protocol's own defaults until the server says
	// otherwise: a server that acknowledges no options sends 512-octet blocks
	// whatever the request asked for, and a relay that assumed the request
	// had been granted would read the first block as the last one.
	x := &transfer{t: t, client: cl, ip: ip, up: addr, op: p.Op, path: pa,
		mode: req.Mode, rule: d.Rule, block: wire.DefaultBlockSize,
		window: 1, ask: ask, maxBytes: d.MaxBytes, start: time.Now()}
	// The socket comes before the table, because a shutdown walks the table
	// and closes what it finds there.
	sock, err := socket()
	if err != nil {
		c.TFTPUpstreamFail.Add(1)
		t.host.Logs().Error.Warn("tftp transfer socket could not be opened",
			"listener", t.cfg.Name, "error", err.Error())
		t.answer(from, wire.ErrNotDefined, "no socket available")
		return
	}
	x.sock = sock
	if reason, admitted := t.admit(x); !admitted {
		_ = sock.Close()
		if reason != "duplicate" {
			c.TFTPRejected.Add(1)
			c.Refuse("tftp", reason)
			t.deny(ip, reason, "")
			t.answer(from, wire.ErrNotDefined, "too many transfers")
		}
		return
	}
	if p.Op == wire.OpRead {
		c.TFTPReads.Add(1)
	} else {
		c.TFTPWrites.Add(1)
	}
	t.observeTransfer(x)
	go func() {
		defer safe.Guard("tftp transfer")
		x.run(out)
	}()
}

// socket opens a transfer's own socket.
//
// One socket per transfer, and an unconnected one: the protocol moves to an
// ephemeral port pair after the first packet, so this socket is what the
// client sees as the server's transfer identifier and what the server sees as
// the client's. Unconnected because it speaks to two addresses, and bounded to
// exactly those two by the transfer itself.
func socket() (net.PacketConn, error) {
	var lc net.ListenConfig
	return lc.ListenPacket(context.Background(), "udp", ":0")
}

// bound rewrites a request to this listener's bounds, and reports the reason
// no rewriting could fix.
//
// Lowering rather than refusing is the whole point: a switch whose TFTP client
// asks for a window of sixty-four still gets its firmware, at a window of
// four, and nobody has to reconfigure a switch. What cannot be lowered is a
// declared transfer size past the bound -- the client has said in advance how
// much it intends to send, and the honest answer to "more than you may" is no.
func (t *server) bound(req *wire.Request, op wire.Op, d Decision) (out []byte, ask asked, lowered bool, bad string) {
	ask = asked{block: wire.DefaultBlockSize, window: 1}
	opts := make([]wire.Option, 0, len(req.Options))
	for _, o := range req.Options {
		v := o.Value
		switch o.Name {
		case wire.OptBlockSize:
			n, _, err := req.Number(o.Name)
			if err != nil {
				return nil, ask, false, "block_size_malformed"
			}
			if n < wire.MinBlockSize || n > wire.MaxBlockSize {
				// Outside what RFC 2348 defines. A server would read it
				// somehow, and this relay would then be bounding a number
				// the transfer is not using.
				return nil, ask, false, "block_size_invalid"
			}
			if d.MaxBlock > 0 && n > d.MaxBlock {
				n, lowered = d.MaxBlock, true
				v = strconv.Itoa(n)
			}
			ask.block = n
		case wire.OptWindowSize:
			n, _, err := req.Number(o.Name)
			if err != nil {
				return nil, ask, false, "window_size_malformed"
			}
			if n < 1 || n > wire.MaxWindowSize {
				return nil, ask, false, "window_size_invalid"
			}
			if d.MaxWindow > 0 && n > d.MaxWindow {
				n, lowered = d.MaxWindow, true
				v = strconv.Itoa(n)
			}
			ask.window = n
		case wire.OptTransferSize:
			n, _, err := req.Number(o.Name)
			if err != nil {
				return nil, ask, false, "transfer_size_malformed"
			}
			// On a write the client is declaring how much it is about to
			// send, which is a bound this relay can hold it to before the
			// first octet arrives rather than after too many have.
			if op == wire.OpWrite && d.MaxBytes > 0 && int64(n) > d.MaxBytes {
				return nil, ask, false, "transfer_too_large"
			}
		case wire.OptTimeout:
			if _, _, err := req.Number(o.Name); err != nil {
				return nil, ask, false, "timeout_malformed"
			}
		}
		opts = append(opts, wire.Option{Name: o.Name, Value: v})
	}
	raw, err := wire.EncodeRequest(op, req.Filename, req.Mode, opts)
	if err != nil {
		return nil, ask, false, "request_unencodable"
	}
	return raw, ask, lowered, ""
}

// serverAddr picks the server a transfer goes to.
func (t *server) serverAddr(client netip.Addr) *net.UDPAddr {
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

// answer sends an error packet from the listener's own socket, which is what
// a refused client sees. It is skipped when deny_response is drop.
func (t *server) answer(to net.Addr, code uint16, msg string) {
	if !t.answering() {
		return
	}
	_, _ = t.pc.WriteTo(wire.EncodeError(code, msg), to)
}

// refusalCode is the error code a refusal is reported with.
//
// A path or a direction the policy refuses is an access violation, which is
// what a server would say and what every client already prints. An option
// outside the bounds is RFC 2347's own option refusal, because that is the
// one a client may legitimately retry without the option.
func refusalCode(reason string) uint16 {
	switch reason {
	case "filename_too_long", "path_too_deep":
		return wire.ErrNotDefined
	}
	return wire.ErrAccessViolation
}

// run is one transfer: the request out, and then datagrams between exactly
// two addresses until one of them says the transfer is over or a bound says it
// is.
func (x *transfer) run(request []byte) {
	t := x.t
	c := t.host.Counters()
	defer func() {
		_ = x.sock.Close()
		t.release(x)
	}()
	if _, err := x.sock.WriteTo(request, x.up); err != nil {
		c.TFTPUpstreamFail.Add(1)
		t.host.Logs().Error.Warn("tftp request to server failed", "listener", t.cfg.Name,
			"server", x.up.String(), "error", err.Error())
		t.answer(x.client, wire.ErrNotDefined, "the server could not be reached")
		t.logTransfer(x, "upstream_failed")
		return
	}
	deadline := time.Now().Add(t.transferTimeout())
	buf := make([]byte, wire.MaxPacket+1)
	for {
		select {
		case <-t.done:
			t.logTransfer(x, "shutdown")
			return
		default:
		}
		until := time.Now().Add(t.idleTimeout())
		if until.After(deadline) {
			until = deadline
		}
		_ = x.sock.SetReadDeadline(until)
		n, from, err := x.sock.ReadFrom(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				if time.Now().Before(deadline) {
					c.TFTPTimedOut.Add(1)
					t.logTransfer(x, "idle")
				} else {
					c.TFTPTimedOut.Add(1)
					t.logTransfer(x, "expired")
				}
				return
			}
			t.logTransfer(x, "closed")
			return
		}
		if n > wire.MaxPacket {
			// Past the largest packet the standards define, so it is refused
			// unread: reading it to find out what it claims to be is the work
			// the bound exists to avoid.
			c.TFTPOversize.Add(1)
			c.Refuse("tftp", "packet_too_large")
			continue
		}
		reason, done := x.datagram(buf[:n], from)
		if done {
			t.logTransfer(x, reason)
			return
		}
	}
}

// datagram handles one datagram on a transfer's socket. It reports why the
// transfer ended, and whether it did.
func (x *transfer) datagram(raw []byte, from net.Addr) (string, bool) {
	t := x.t
	c := t.host.Counters()
	ua, ok := from.(*net.UDPAddr)
	if !ok {
		return "", false
	}
	switch {
	case sameAddr(ua, x.client):
		return x.fromClient(raw)
	case x.serverSpeaking(ua):
		return x.fromServer(raw)
	default:
		// A third address. On a protocol with no integrity protection this is
		// the whole attack: a data packet injected into a firmware transfer
		// is firmware, and it arrives with nothing to distinguish it but the
		// port it came from. So it is dropped and counted, and the client is
		// not told -- telling it would make this relay answer an address that
		// has no business here.
		c.TFTPUnsolicited.Add(1)
		c.Refuse("tftp", "wrong_source")
		return "", false
	}
}

// serverSpeaking says whether an address may speak for the server.
//
// The first packet from the server's address sets its transfer identifier and
// every later packet must come from that one port, which is RFC 1350's own
// rule read strictly: the standard says a packet from an unknown identifier
// gets an error 5 in reply, and this relay drops it instead, because replying
// is how a relay becomes a reflector.
func (x *transfer) serverSpeaking(ua *net.UDPAddr) bool {
	if !ua.IP.Equal(x.up.IP) {
		return false
	}
	if !x.sawServer {
		x.up = ua
		x.sawServer = true
		return true
	}
	return ua.Port == x.up.Port
}

// fromClient forwards what the client sends.
func (x *transfer) fromClient(raw []byte) (string, bool) {
	t := x.t
	c := t.host.Counters()
	p, err := wire.Parse(raw)
	if err != nil {
		c.TFTPMalformed.Add(1)
		c.Refuse("tftp", "malformed")
		x.toServer(wire.EncodeError(wire.ErrIllegalOp, "malformed"))
		return "client_malformed", true
	}
	switch p.Op {
	case wire.OpAck:
		if x.op != wire.OpRead {
			c.Refuse("tftp", "wrong_direction")
			return "wrong_direction", true
		}
		last := x.last
		x.toServer(raw)
		return "complete", last
	case wire.OpData:
		if x.op != wire.OpWrite {
			// Data from the client on a read. The client is the side that
			// asked to receive, so this is a client sending a file through a
			// transfer that was allowed as a read -- which is the direction
			// the policy decided about.
			c.Refuse("tftp", "wrong_direction")
			x.toServer(wire.EncodeError(wire.ErrIllegalOp, "this transfer is a read"))
			return "wrong_direction", true
		}
		if reason, over := x.account(p.Data); over {
			return reason, true
		}
		x.toServer(raw)
		return "", false
	case wire.OpError:
		x.toServer(raw)
		return "client_error", true
	default:
		// A request or an option acknowledgement on a transfer's socket. A
		// retransmitted request goes to the request port, not here, so this
		// is neither a retransmission nor anything the protocol defines for
		// this direction.
		c.Refuse("tftp", "not_in_transfer")
		t.deny(x.ip, "not_in_transfer", p.Op.String())
		x.toClient(wire.EncodeError(wire.ErrIllegalOp, "not part of this transfer"))
		return "not_in_transfer", true
	}
}

// fromServer forwards what the server sends.
func (x *transfer) fromServer(raw []byte) (string, bool) {
	t := x.t
	c := t.host.Counters()
	p, err := wire.Parse(raw)
	if err != nil {
		c.TFTPMalformed.Add(1)
		c.Refuse("tftp", "malformed_response")
		// The client is told, because it is waiting: a transfer that stopped
		// with no reason given is a device that retransmits for a minute.
		x.toClient(wire.EncodeError(wire.ErrNotDefined, "the server sent something unreadable"))
		return "server_malformed", true
	}
	switch p.Op {
	case wire.OpOAck:
		if reason := x.accept(p.OAck); reason != "" {
			c.TFTPOversize.Add(1)
			c.Refuse("tftp", reason)
			t.deny(x.ip, reason, x.path.Clean)
			x.toClient(wire.EncodeError(wire.ErrOptionRefused, "the server accepted an option this relay did not offer"))
			x.toServer(wire.EncodeError(wire.ErrOptionRefused, "outside the relay's bounds"))
			return reason, true
		}
		x.toClient(raw)
		return "", false
	case wire.OpData:
		if x.op != wire.OpRead {
			c.Refuse("tftp", "wrong_direction")
			return "wrong_direction", true
		}
		if p.Data.Length > x.block {
			// The server ignored the block size the transfer negotiated,
			// which is the shape of a server sending more than was asked for.
			c.TFTPOversize.Add(1)
			c.Refuse("tftp", "block_too_large")
			t.deny(x.ip, "block_too_large", itoa(p.Data.Length))
			x.toClient(wire.EncodeError(wire.ErrNotDefined, "the server sent an oversize block"))
			return "block_too_large", true
		}
		if reason, over := x.account(p.Data); over {
			return reason, true
		}
		x.toClient(raw)
		return "", false
	case wire.OpAck:
		if x.op != wire.OpWrite {
			c.Refuse("tftp", "wrong_direction")
			return "wrong_direction", true
		}
		last := x.last
		x.toClient(raw)
		return "complete", last
	case wire.OpError:
		x.toClient(raw)
		return "server_error", true
	default:
		c.Refuse("tftp", "not_in_transfer")
		x.toClient(wire.EncodeError(wire.ErrNotDefined, "the server sent a request"))
		return "not_in_transfer", true
	}
}

// account counts a data packet against the transfer's bound and notices the
// short packet that ends a transfer.
//
// The bound is the one that matters on a write: a write has no natural end,
// because the client stops when it stops. It is not shadowable, so the
// transfer is cut wherever the policy stands.
func (x *transfer) account(d *wire.Data) (string, bool) {
	c := x.t.host.Counters()
	x.bytes += int64(d.Length)
	x.packets++
	if x.op == wire.OpRead {
		c.TFTPBytesOut.Add(octets(d.Length))
	} else {
		c.TFTPBytesIn.Add(octets(d.Length))
	}
	if x.maxBytes > 0 && x.bytes > x.maxBytes {
		c.TFTPOversize.Add(1)
		c.Refuse("tftp", "transfer_too_large")
		x.t.deny(x.ip, "transfer_too_large", itoa64(x.bytes))
		x.toClient(wire.EncodeError(wire.ErrDiskFull, "the transfer is larger than this relay allows"))
		x.toServer(wire.EncodeError(wire.ErrDiskFull, "bounded by the relay"))
		return "transfer_too_large", true
	}
	if d.Length < x.block {
		// RFC 1350 ends a transfer with a packet shorter than the block size.
		// The transfer is over once its acknowledgement has gone the other
		// way, which is what the flag is for.
		x.last = true
	}
	return "", false
}

// accept reads the options the server granted and checks them against the
// bounds this relay asked for.
//
// A server that accepted a larger block or window than the request carried is
// not a server to argue with mid-transfer: the two ends would then disagree
// about how much is coming. So the transfer ends and both ends are told.
func (x *transfer) accept(opts []wire.Option) string {
	for _, o := range opts {
		switch o.Name {
		case wire.OptBlockSize:
			n, err := strconv.Atoi(o.Value)
			if err != nil || n < wire.MinBlockSize || n > wire.MaxBlockSize {
				return "oack_malformed"
			}
			if n > x.ask.block {
				// RFC 2348 lets a server answer with a value no larger than
				// the one it was offered. A larger one is either a broken
				// server or one trying to get past a bound that has already
				// been applied to the request.
				return "oack_block_too_large"
			}
			x.block = n
		case wire.OptWindowSize:
			n, err := strconv.Atoi(o.Value)
			if err != nil || n < 1 || n > wire.MaxWindowSize {
				return "oack_malformed"
			}
			if n > x.ask.window {
				return "oack_window_too_large"
			}
			x.window = n
		case wire.OptTransferSize:
			n, err := strconv.ParseInt(o.Value, 10, 64)
			if err != nil || n < 0 {
				return "oack_malformed"
			}
			// On a read this is the server telling the client how large the
			// file is, which is the one chance to refuse a transfer before it
			// starts rather than in the middle.
			if x.maxBytes > 0 && n > x.maxBytes {
				return "transfer_too_large"
			}
		}
	}
	return ""
}

func (x *transfer) toClient(raw []byte) {
	if _, err := x.sock.WriteTo(raw, x.client); err != nil {
		x.t.host.Logs().Error.Warn("tftp write to client failed", "listener", x.t.cfg.Name,
			"client", x.client.String(), "error", err.Error())
	}
}

func (x *transfer) toServer(raw []byte) {
	if _, err := x.sock.WriteTo(raw, x.up); err != nil {
		x.t.host.Counters().TFTPUpstreamFail.Add(1)
		x.t.host.Logs().Error.Warn("tftp write to server failed", "listener", x.t.cfg.Name,
			"server", x.up.String(), "error", err.Error())
	}
}

// sameAddr compares two datagram addresses. A transfer identifier is an
// address and a port together, so both are compared: the port is the whole of
// what identifies a TFTP transfer.
func sameAddr(a, b *net.UDPAddr) bool {
	return a != nil && b != nil && a.Port == b.Port && a.IP.Equal(b.IP)
}

// octets is a payload length as an unsigned count.
//
// Parse computes Length from a bounded slice, so it is never negative -- and
// the guard says so here rather than leaving the next reader to go and check.
func octets(n int) uint64 {
	if n < 0 {
		return 0
	}
	return uint64(n)
}

func itoa(n int) string     { return strconv.Itoa(n) }
func itoa64(n int64) string { return strconv.FormatInt(n, 10) }
