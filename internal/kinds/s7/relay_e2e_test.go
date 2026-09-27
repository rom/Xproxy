package s7

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	wire "github.com/rom/xproxy/internal/s7"
)

// The relay end to end, through the real engine, against a controller that
// keeps a record of what reached it.
//
// What reached the PLC is the assertion that matters. A test that checked only
// the client's answer would pass against a relay that refused a write and
// forwarded it anyway -- which is the bug that actually happens on this
// protocol, and the one that moves an actuator. So every refusal here is
// asserted twice: the client was told, and the controller never saw it.

// fakePLC is enough of an S7 CPU to complete the ISO handshake, negotiate a PDU
// length and acknowledge a job, and it records every operation that arrived.
type fakePLC struct {
	ln net.Listener
	// pduLength is what the CPU offers in its setup acknowledgement. A real
	// negotiation settles on the smaller of the two, so a CPU offering less
	// than the client asked for is the ordinary case.
	pduLength uint16
	// fault, when set, makes the CPU answer every job with an access fault,
	// which is what a password-protected controller does.
	fault bool

	mu  sync.Mutex
	saw []string
}

func startPLC(t *testing.T, p *fakePLC) *fakePLC {
	t.Helper()
	if p.pduLength == 0 {
		p.pduLength = 480
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p.ln = ln
	t.Cleanup(func() { _ = ln.Close() })
	go p.serve()
	return p
}

func (p *fakePLC) addr() string { return p.ln.Addr().String() }

func (p *fakePLC) serve() {
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.session(c)
	}
}

func (p *fakePLC) record(what string) {
	p.mu.Lock()
	p.saw = append(p.saw, what)
	p.mu.Unlock()
}

// got says whether the controller saw an operation by name.
func (p *fakePLC) got(what string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range p.saw {
		if s == what {
			return true
		}
	}
	return false
}

func (p *fakePLC) count(what string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, s := range p.saw {
		if s == what {
			n++
		}
	}
	return n
}

func (p *fakePLC) saws() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.saw...)
}

func (p *fakePLC) session(c net.Conn) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	r := wire.NewReader(c, 0)
	for {
		f, err := r.Next()
		if err != nil {
			return
		}
		cotp, err := wire.ParseCOTP(f.Payload)
		if err != nil {
			return
		}
		switch cotp.Type {
		case wire.COTPConnectionRequest:
			p.record("connect")
			_, _ = c.Write(connectionConfirm())
			continue
		case wire.COTPData, wire.COTPExpeditedData:
		default:
			p.record("cotp " + cotp.TypeName())
			continue
		}
		if wire.IsPlus(cotp.Data) {
			// An S7-1200 or S7-1500 speaking to TIA Portal. The fake
			// controller records what arrived and answers with a response
			// carrying the same function, which is enough for a test to say
			// whether the relay let the request through.
			plus, err := wire.ParsePlus(cotp.Data)
			if err != nil {
				return
			}
			name, _ := plus.FunctionName()
			p.record("plus " + name)
			if plus.HasFunction {
				_, _ = c.Write(plusFrame(wire.PlusResponse, plus.Function))
			}
			continue
		}
		pdu, err := wire.ParseS7(cotp.Data)
		if err != nil {
			return
		}
		if op, ok := pdu.Op(); ok {
			p.record(string(op))
		} else {
			p.record("unknown")
		}
		if _, _, length, ok := pdu.Setup(); ok {
			offer := p.pduLength
			if length < offer {
				offer = length
			}
			_, _ = c.Write(setupAck(pdu.PDURef, offer))
			continue
		}
		if p.fault {
			_, _ = c.Write(ackData(pdu.PDURef, 0x87, 0x00, []byte{pdu.Function, 0x00}, nil))
			continue
		}
		_, _ = c.Write(ackData(pdu.PDURef, 0, 0, []byte{pdu.Function, 0x01},
			[]byte{0xff, wire.TransportByte, 0x00, 0x08, 0x01}))
	}
}

// setupAck is the CPU's answer to the negotiation.
func setupAck(ref, pduLength uint16) []byte {
	return ackData(ref, 0, 0,
		join([]byte{wire.FnSetupComm, 0}, be16b(1), be16b(1), be16b(pduLength)), nil)
}

const s7YAML = `
version: 1
server:
  listeners:
    - name: plc
      address: "127.0.0.1:0"
      kind: s7
      s7:
%s
logging: {access: {enabled: false}}
upstreams:
  - {name: cpu, endpoints: [{address: %q}]}
`

func relayFor(t *testing.T, section, plcAddr string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(s7YAML, section, plcAddr))
	return s, proxytest.Addr(t, s, "plc")
}

// base allows what an HMI does and nothing else, which is the default posture.
const base = "        upstream: cpu\n" +
	"        default_action: allow\n"

// client is a minimal S7 client: the ISO handshake, the negotiation, and one
// job at a time.
type client struct {
	t *testing.T
	c net.Conn
	r *wire.Reader
}

func dial(t *testing.T, addr string) *client {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	return &client{t: t, c: c, r: wire.NewReader(c, 0)}
}

func (cl *client) write(b []byte) {
	cl.t.Helper()
	if _, err := cl.c.Write(b); err != nil {
		cl.t.Fatalf("write: %v", err)
	}
}

// next reads one frame and returns the S7 PDU inside it, or nil for a frame
// that carries no S7 -- a COTP disconnect, for instance.
func (cl *client) next() (*wire.PDU, *wire.COTP) {
	cl.t.Helper()
	f, err := cl.r.Next()
	if err != nil {
		cl.t.Fatalf("read: %v", err)
	}
	c, err := wire.ParseCOTP(f.Payload)
	if err != nil {
		cl.t.Fatalf("cotp: %v", err)
	}
	if c.Type != wire.COTPData && c.Type != wire.COTPExpeditedData {
		return nil, c
	}
	pdu, err := wire.ParseS7(c.Data)
	if err != nil {
		cl.t.Fatalf("s7: %v", err)
	}
	return pdu, c
}

// connect opens the transport connection to a rack and a slot, as a connection
// resource, and negotiates a PDU length.
func (cl *client) connect(resource uint8, rack, slot int) {
	cl.t.Helper()
	cl.write(connectionRequest(resource, rack, slot))
	if _, c := cl.next(); c.Type != wire.COTPConnectionConfirm {
		cl.t.Fatalf("the connection was answered with %s", c.TypeName())
	}
	cl.write(setupJob(1, 480))
	pdu, _ := cl.next()
	if _, _, n, ok := pdu.Setup(); !ok || n == 0 {
		cl.t.Fatalf("the negotiation was answered with %s", describe(pdu))
	}
}

// refused sends a job and asserts the answer is a refusal, returning the error
// class the client was told.
func (cl *client) refused(frame []byte) *wire.PDU {
	cl.t.Helper()
	cl.write(frame)
	pdu, _ := cl.next()
	if !pdu.HasError || pdu.ErrClass == 0 {
		cl.t.Fatalf("the answer carried no error: %s", describe(pdu))
	}
	return pdu
}

// allowed sends a job and asserts the answer is not an error.
func (cl *client) allowed(frame []byte) *wire.PDU {
	cl.t.Helper()
	cl.write(frame)
	pdu, _ := cl.next()
	if pdu.HasError && pdu.ErrClass != 0 {
		cl.t.Fatalf("the answer carried error class %#x", pdu.ErrClass)
	}
	return pdu
}

// The ordinary path: an HMI connects, negotiates and reads, and the controller
// sees all three.
func TestAnAllowedSessionReachesTheController(t *testing.T) {
	p := startPLC(t, &fakePLC{})
	_, addr := relayFor(t, base, p.addr())
	cl := dial(t, addr)
	cl.connect(wire.ResourceOP, 0, 2)
	cl.allowed(readJob(2, item(wire.TransportByte, 8, 1, wire.AreaDB, 0)))

	for _, want := range []string{"connect", "setup", "read"} {
		if !p.got(want) {
			t.Errorf("the controller never saw %s (saw %v)", want, p.saws())
		}
	}
}

// The default refuses everything that changes the PLC, and the refusal is the
// error class a protected CPU answers with.
func TestAWriteIsRefusedAndNeverReachesTheController(t *testing.T) {
	p := startPLC(t, &fakePLC{})
	_, addr := relayFor(t, base, p.addr())
	cl := dial(t, addr)
	cl.connect(wire.ResourcePG, 0, 2)

	pdu := cl.refused(writeJob(3, item(wire.TransportByte, 1, 1, wire.AreaDB, 0),
		wire.TransportByte, []byte{1}))
	if pdu.ErrClass != accessFault {
		t.Errorf("the client was told error class %#x, not an access fault", pdu.ErrClass)
	}
	if p.got("write") {
		t.Error("the write reached the controller")
	}
	// The connection carries on, which is the point of answering rather than
	// closing: a plant connection is a poll loop.
	cl.allowed(readJob(4, item(wire.TransportByte, 4, 1, wire.AreaDB, 0)))
	if !p.got("read") {
		t.Error("the read after the refusal never reached the controller")
	}
}

// A stop is the operation that stops a machine, so it is refused even on a
// listener whose default action is allow.
func TestAStopIsRefused(t *testing.T) {
	p := startPLC(t, &fakePLC{})
	_, addr := relayFor(t, base, p.addr())
	cl := dial(t, addr)
	cl.connect(wire.ResourcePG, 0, 2)
	cl.refused(stopJob(5))
	if p.got("stop") {
		t.Error("the stop reached the controller")
	}
}

// The rack and slot are decided from the connection request, before the PLC is
// dialled -- so a client that may not reach that CPU never takes one of its
// connection resources.
func TestAWrongSlotIsRefusedBeforeTheControllerIsDialled(t *testing.T) {
	p := startPLC(t, &fakePLC{})
	_, addr := relayFor(t, base+"        slots: [\"2\"]\n", p.addr())
	cl := dial(t, addr)
	cl.write(connectionRequest(wire.ResourcePG, 0, 3))
	if _, c := cl.next(); c.Type != wire.COTPDisconnectRequest {
		t.Errorf("the connection was answered with %s, not a disconnect", c.TypeName())
	}
	// Nothing at all reached the controller: not the connection request, and
	// so not a connection resource either.
	if len(p.saws()) != 0 {
		t.Errorf("the controller saw %v", p.saws())
	}
}

// The connection resource says what the client is, and it is the cheapest line
// in the section: a listener that admits only `op` has refused every
// engineering station.
func TestAProgrammingDeviceIsRefusedOnAnOperatorListener(t *testing.T) {
	p := startPLC(t, &fakePLC{})
	_, addr := relayFor(t, base+"        resources: [\"op\"]\n", p.addr())
	cl := dial(t, addr)
	cl.write(connectionRequest(wire.ResourcePG, 0, 2))
	if _, c := cl.next(); c.Type != wire.COTPDisconnectRequest {
		t.Errorf("the connection was answered with %s", c.TypeName())
	}
	if len(p.saws()) != 0 {
		t.Errorf("the controller saw %v", p.saws())
	}
}

// A data block outside the policy is refused, and the span is checked whole: a
// read that starts inside a range and ends outside it is a read of bytes the
// policy does not name.
func TestMemoryOutsideThePolicyIsRefused(t *testing.T) {
	p := startPLC(t, &fakePLC{})
	_, addr := relayFor(t, base+
		"        dbs: [\"1\", \"10-20\"]\n"+
		"        addresses: [\"0-99\"]\n", p.addr())
	cl := dial(t, addr)
	cl.connect(wire.ResourceOP, 0, 2)

	cl.allowed(readJob(2, item(wire.TransportByte, 10, 12, wire.AreaDB, 0)))
	cl.refused(readJob(3, item(wire.TransportByte, 10, 99, wire.AreaDB, 0)))
	// Bytes 90 to 109, which starts inside the range and ends outside it.
	cl.refused(readJob(4, item(wire.TransportByte, 20, 1, wire.AreaDB, 90)))

	if n := p.count("read"); n != 1 {
		t.Errorf("the controller saw %d reads, not 1 (%v)", n, p.saws())
	}
}

// The bounds: a read of a hundred items is one PDU that occupies the CPU for as
// long as a hundred reads.
func TestTheItemBoundIsEnforced(t *testing.T) {
	p := startPLC(t, &fakePLC{})
	_, addr := relayFor(t, base+"        max_items: 2\n", p.addr())
	cl := dial(t, addr)
	cl.connect(wire.ResourceOP, 0, 2)

	one := item(wire.TransportByte, 4, 1, wire.AreaDB, 0)
	cl.allowed(readJob(2, one, one))
	cl.refused(readJob(3, one, one, one))
	if n := p.count("read"); n != 1 {
		t.Errorf("the controller saw %d reads, not 1", n)
	}
}

// A function code nobody has documented is an operation with no policy, so it
// is refused rather than forwarded -- and answered, so the poll loop of a
// client whose firmware sends one thing this relay does not know goes on
// working for everything else.
func TestAnUnknownFunctionIsRefusedAndNotForwarded(t *testing.T) {
	p := startPLC(t, &fakePLC{})
	_, addr := relayFor(t, base, p.addr())
	cl := dial(t, addr)
	cl.connect(wire.ResourcePG, 0, 2)

	pdu := cl.refused(job(6, []byte{0x77, 0x00}, nil))
	if pdu.ErrClass != accessFault {
		t.Errorf("the client was told %#x", pdu.ErrClass)
	}
	if p.got("unknown") {
		t.Error("the unknown function reached the controller")
	}
	// And the connection is still good for the work the client came to do.
	cl.allowed(readJob(7, item(wire.TransportByte, 4, 1, wire.AreaDB, 0)))
	if !p.got("read") {
		t.Error("the read after the refusal never reached the controller")
	}
}

// A transport PDU type nobody here understands is the other case, and it does
// end the connection: forwarding it would be forwarding something to a
// controller with no policy applied to it at all.
func TestAnUnknownTransportTypeEndsTheConnection(t *testing.T) {
	p := startPLC(t, &fakePLC{})
	_, addr := relayFor(t, base, p.addr())
	cl := dial(t, addr)
	cl.connect(wire.ResourceOP, 0, 2)

	// A COTP PDU whose type is not one of the six this relay reads.
	cl.write(tpkt([]byte{0x02, 0x44, 0x80}))
	if _, err := cl.r.Next(); err == nil {
		t.Error("the connection carried on after a transport type with no name")
	}
	if n := len(p.saws()); n != 2 {
		t.Errorf("the controller saw %v", p.saws())
	}
}

// A user-data request is refused in the layer it arrived in: the same group and
// subfunction, with an error code saying the CPU does not offer it.
func TestSettingTheClockIsRefusedInItsOwnLayer(t *testing.T) {
	p := startPLC(t, &fakePLC{})
	_, addr := relayFor(t, base, p.addr())
	cl := dial(t, addr)
	cl.connect(wire.ResourcePG, 0, 2)

	cl.write(userData(7, wire.GroupTime, 0x02))
	pdu, _ := cl.next()
	u, ok := pdu.UserData()
	if !ok {
		t.Fatalf("the refusal was not user data: %s", describe(pdu))
	}
	if u.Group != wire.GroupTime || u.Sub != 0x02 {
		t.Errorf("the refusal named group %#x subfunction %#x", u.Group, u.Sub)
	}
	if !u.HasError || u.ErrCode != notImplemented {
		t.Errorf("the refusal carried error %#x", u.ErrCode)
	}
	if p.got("time_write") {
		t.Error("setting the clock reached the controller")
	}
	// Reading the clock is what an HMI does, and still works.
	cl.write(userData(8, wire.GroupTime, 0x01))
	cl.next()
	if !p.got("time_read") {
		t.Error("reading the clock never reached the controller")
	}
}

// read_only cannot be widened by a rule, because a read-only listener that one
// rule could write through is not a read-only listener.
func TestReadOnlyHoldsThroughTheEngine(t *testing.T) {
	p := startPLC(t, &fakePLC{})
	_, addr := relayFor(t, base+
		"        read_only: true\n"+
		"        rules:\n"+
		"          - {name: integrator, operations: [\"setup\", \"read\", \"write\", \"download\"]}\n", p.addr())
	cl := dial(t, addr)
	cl.connect(wire.ResourcePG, 0, 2)

	cl.allowed(readJob(2, item(wire.TransportByte, 4, 1, wire.AreaDB, 0)))
	cl.refused(writeJob(3, item(wire.TransportByte, 1, 1, wire.AreaDB, 0),
		wire.TransportByte, []byte{1}))
	cl.refused(downloadJob(4, "08", 10))
	if p.got("write") || p.got("download") {
		t.Errorf("the controller saw %v", p.saws())
	}
}

// Monitor mode carries what it evaluates -- except the operations that change
// the controller, because a write forwarded so that it could be written down is
// a moved actuator.
func TestMonitorModeStillRefusesTheOperationsThatChangeThePLC(t *testing.T) {
	p := startPLC(t, &fakePLC{})
	_, addr := relayFor(t, base+
		"        monitor_only: true\n"+
		"        dbs: [\"1\"]\n", p.addr())
	cl := dial(t, addr)
	cl.connect(wire.ResourcePG, 0, 2)

	// A read of a data block outside the policy: evaluated, recorded and
	// carried, because reading nothing changes.
	cl.allowed(readJob(2, item(wire.TransportByte, 4, 99, wire.AreaDB, 0)))
	if !p.got("read") {
		t.Error("monitor mode did not carry the read")
	}
	// A write: refused anyway.
	cl.refused(writeJob(3, item(wire.TransportByte, 1, 99, wire.AreaDB, 0),
		wire.TransportByte, []byte{1}))
	if p.got("write") {
		t.Error("monitor mode carried a write")
	}
}

// An upload is a read, and it is the one that takes the plant's control logic
// with it -- so it is off by default and named to be allowed.
func TestAnUploadIsOffUntilNamed(t *testing.T) {
	p := startPLC(t, &fakePLC{})
	_, addr := relayFor(t, base, p.addr())
	cl := dial(t, addr)
	cl.connect(wire.ResourcePG, 0, 2)
	cl.refused(uploadJob(2, "08", 10))
	if p.got("upload") {
		t.Error("the upload reached the controller")
	}

	p2 := startPLC(t, &fakePLC{})
	_, addr2 := relayFor(t, base+
		"        operations: [\"read\", \"setup\", \"upload\"]\n"+
		"        block_types: [\"db\"]\n", p2.addr())
	cl2 := dial(t, addr2)
	cl2.connect(wire.ResourcePG, 0, 2)
	cl2.allowed(uploadJob(2, "08", 10))
	if !p2.got("upload") {
		t.Error("the allowed upload never reached the controller")
	}
	// A function block is a different block type, and this listener named
	// only data blocks.
	cl2.refused(uploadJob(3, "0E", 1))
	if n := p2.count("upload"); n != 1 {
		t.Errorf("the controller saw %d uploads", n)
	}
}

// The negotiation is refused rather than rewritten, because rewriting it would
// make the relay a party to it.
func TestAnOversizePDUNegotiationIsRefused(t *testing.T) {
	p := startPLC(t, &fakePLC{})
	_, addr := relayFor(t, base+"        max_pdu_length: 240\n", p.addr())
	cl := dial(t, addr)
	cl.write(connectionRequest(wire.ResourcePG, 0, 2))
	cl.next()
	cl.refused(setupJob(1, 960))
	if p.got("setup") {
		t.Error("the negotiation reached the controller")
	}
}

// deny_response: close ends the connection instead of answering, for a
// listener whose operator would rather a refused client went away.
func TestDenyResponseCloseEndsTheConnection(t *testing.T) {
	p := startPLC(t, &fakePLC{})
	_, addr := relayFor(t, base+"        deny_response: close\n", p.addr())
	cl := dial(t, addr)
	cl.connect(wire.ResourcePG, 0, 2)
	cl.write(stopJob(2))
	if _, err := cl.r.Next(); err == nil {
		t.Error("the connection carried on after a refusal under deny_response: close")
	}
	if p.got("stop") {
		t.Error("the stop reached the controller")
	}
}

// What the controller refuses is read on the way back, because that is where
// the two policies disagree -- and on this protocol it usually means the CPU is
// password-protected and the client has not supplied one.
func TestTheControllersOwnRefusalIsRecorded(t *testing.T) {
	p := startPLC(t, &fakePLC{fault: true})
	_, addr := relayFor(t, base, p.addr())
	cl := dial(t, addr)
	cl.connect(wire.ResourceOP, 0, 2)
	// The read is allowed by this listener and faulted by the CPU, which is
	// the disagreement worth recording. The client sees the class the
	// controller sent rather than one this relay invented.
	cl.write(readJob(2, item(wire.TransportByte, 4, 1, wire.AreaDB, 0)))
	pdu, _ := cl.next()
	if !pdu.HasError || pdu.ErrClass != 0x87 {
		t.Errorf("the controller's error class did not reach the client: %#x", pdu.ErrClass)
	}
	if !p.got("read") {
		t.Error("the read never reached the controller")
	}
}

// The rate limit refuses the request and keeps the session, which is the
// modbus kind's choice and for the same reason: a limit is not a reason to end
// a plant connection.
func TestARateLimitedRequestIsRefusedAndTheSessionCarriesOn(t *testing.T) {
	p := startPLC(t, &fakePLC{})
	s, addr := relayFor(t, base+
		"        rate_limit: 1\n"+
		"        rate_burst: 1\n", p.addr())
	cl := dial(t, addr)
	cl.write(connectionRequest(wire.ResourceOP, 0, 2))
	cl.next()
	// The burst is one, and the negotiation spends it.
	cl.write(setupJob(1, 480))
	cl.next()
	read := readJob(2, item(wire.TransportByte, 4, 1, wire.AreaDB, 0))
	cl.write(read)
	// A rate limit is refused without an answer, so the counter is what says
	// the refusal happened -- and then the controller is what says it was not
	// forwarded anyway.
	waitFor(t, func() bool { return s.Stats().Refusals["s7"]["rate_limited"] > 0 })
	if p.got("read") {
		t.Errorf("the rate-limited read reached the controller (%v)", p.saws())
	}
	// And the session is still open: a limit is not a reason to end a plant
	// connection.
	if _, err := cl.c.Write(read); err != nil {
		t.Errorf("the session was closed by a rate limit: %v", err)
	}
}

// A refusal counts, and the reason reaches the counters under the listener's
// own name.
func TestARefusalCounts(t *testing.T) {
	p := startPLC(t, &fakePLC{})
	s, addr := relayFor(t, base, p.addr())
	cl := dial(t, addr)
	cl.connect(wire.ResourcePG, 0, 2)
	cl.refused(stopJob(2))

	waitFor(t, func() bool { return s.Stats().Refusals["s7"]["operation_not_allowed"] > 0 })
}

// waitFor holds until a condition does, which is how a counter written on the
// relay's own goroutine is read from the test's.
func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if ok() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !ok() {
		t.Error("the condition never held")
	}
}

// The per-client session bound, through the real engine and under concurrent
// dials. This is the bound the s7 listener most needs to hold: an S7-300 has
// sixteen connection resources altogether, so a client that takes more than its
// share denies the plant its own HMI.
//
// What this covers is that the bound is wired to the right setting, refuses at
// the right point and is counted under the reason an operator watches. It does
// *not* catch the check-then-act race the kinds used to have: a real dial and
// transport handshake take long enough that accepts do not collide tightly
// enough to expose it -- removing the lock from sesslimit.Enter leaves this test
// passing. The race is held by internal/sesslimit's own tests, which drive
// Enter directly with 512 goroutines spinning on a flag.
func TestThePerClientSessionBoundHoldsUnderParallelDials(t *testing.T) {
	p := startPLC(t, &fakePLC{})
	s, addr := relayFor(t, base+"        max_sessions_per_client: 2\n", p.addr())

	const dials = 64
	var opened sync.WaitGroup
	var held []net.Conn
	var mu sync.Mutex
	var gate sync.WaitGroup
	gate.Add(1)
	for i := 0; i < dials; i++ {
		opened.Add(1)
		go func() {
			defer opened.Done()
			gate.Wait()
			c, err := net.Dial("tcp", addr)
			if err != nil {
				return
			}
			// Reach the point past the bound check by completing the
			// transport handshake, then hold the connection open.
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := c.Write(connectionRequest(wire.ResourceOP, 0, 2)); err != nil {
				_ = c.Close()
				return
			}
			r := wire.NewReader(c, 0)
			if _, err := r.Next(); err != nil {
				_ = c.Close()
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}()
	}
	gate.Done()
	opened.Wait()
	t.Cleanup(func() {
		for _, c := range held {
			_ = c.Close()
		}
	})

	mu.Lock()
	n := len(held)
	mu.Unlock()
	if n > 2 {
		t.Errorf("max_sessions_per_client is 2 and %d sessions completed the handshake", n)
	}
	// And the refusals were counted under the reason an operator watches.
	waitFor(t, func() bool {
		return s.Stats().Refusals["s7"]["too_many_sessions_per_client"] > 0
	})
}
