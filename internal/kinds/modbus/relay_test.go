package modbus_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/modbus"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	"github.com/rom/xproxy/internal/testutil"
)

// seen is one request a device was sent, as the device read it.
type seen struct {
	unit     byte
	txn      uint16
	function byte
	address  uint16
	quantity uint16
	raw      []byte
}

// plc is a Modbus slave: it reads frames in its own framing, answers the
// ones the specification gives it an answer for, and records every one,
// so a test can say what did and did not reach the device.
type plc struct {
	ln      net.Listener
	framing wire.Framing

	mu    sync.Mutex
	got   []seen
	regs  map[uint16]uint16
	coils map[uint16]bool

	// replyUnit answers for another unit identifier than the one asked
	// for, which is the gateway bug a relay must not pass on.
	replyUnit *byte
	// replyTxn answers with a transaction identifier of its own, which
	// is what a gateway in the path renumbering them looks like.
	replyTxn *uint16
	// garbage answers something no master can read.
	garbage bool
	// silent reads and never answers, which is how a device that is
	// there but not answering behaves.
	silent bool
	// exception answers every request with this exception code.
	exception byte
	// vendorName, productCode and revision are what the device says about
	// itself when a master asks for its identification (function code 43,
	// MEI type 14). Empty leaves the function unimplemented, which is what
	// most of the installed base does.
	vendorName, productCode, revision string
}

func startPLC(t *testing.T, p *plc) *plc {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p.ln = ln
	p.regs = map[uint16]uint16{}
	p.coils = map[uint16]bool{}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.session(c)
		}
	}()
	return p
}

func (p *plc) addr() string { return p.ln.Addr().String() }

func (p *plc) requests() []seen {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]seen(nil), p.got...)
}

// saw reports the first request for a function code that reached the
// device.
func (p *plc) saw(fc byte) (seen, bool) {
	for _, s := range p.requests() {
		if s.function == fc {
			return s, true
		}
	}
	return seen{}, false
}

func (p *plc) session(c net.Conn) {
	defer func() { _ = c.Close() }()
	rd := wire.NewReader(c, p.framing, true)
	for {
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		f, raw, err := rd.ReadFrame()
		if err != nil {
			return
		}
		q, err := wire.ParseRequest(f.PDU)
		if err != nil {
			return
		}
		p.mu.Lock()
		p.got = append(p.got, seen{unit: f.Unit, txn: f.Transaction, function: q.Function,
			address: q.Address, quantity: q.Quantity, raw: append([]byte(nil), raw...)})
		p.mu.Unlock()
		if p.silent {
			continue
		}
		var pdu []byte
		switch {
		case p.garbage:
			// A read response whose byte count does not match the
			// quantity asked for: a frame the relay must not pass on.
			pdu = []byte{q.Function, 6, 0, 1, 0, 2, 0, 3}
		case p.exception != 0:
			pdu = wire.ExceptionPDU(q.Function, p.exception)
		default:
			pdu = p.answer(q, f.PDU)
		}
		unit := f.Unit
		if p.replyUnit != nil {
			unit = *p.replyUnit
		}
		txn := f.Transaction
		if p.replyTxn != nil {
			txn = *p.replyTxn
		}
		_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write(wire.Encode(p.framing, &wire.Frame{
			Transaction: txn, Unit: unit, PDU: pdu})); err != nil {
			return
		}
	}
}

// answer is the device's answer to one request, built the way the
// specification says: reads return what is held, writes echo.
func (p *plc) answer(q *wire.PDU, pdu []byte) []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch q.Function {
	case wire.FCReadCoils, wire.FCReadDiscreteInputs:
		n := (int(q.Quantity) + 7) / 8
		out := append([]byte{q.Function, byte(n)}, make([]byte, n)...)
		for i := 0; i < int(q.Quantity); i++ {
			if p.coils[q.Address+uint16(i)] {
				out[2+i/8] |= 1 << (i % 8)
			}
		}
		return out
	case wire.FCReadHoldingRegisters, wire.FCReadInputRegisters:
		out := []byte{q.Function, byte(2 * int(q.Quantity))}
		for i := 0; i < int(q.Quantity); i++ {
			v := p.regs[q.Address+uint16(i)]
			out = append(out, byte(v>>8), byte(v))
		}
		return out
	case wire.FCWriteSingleRegister:
		p.regs[q.Address] = q.Registers[0]
		return append([]byte(nil), pdu...)
	case wire.FCWriteSingleCoil:
		p.coils[q.Address] = len(q.Coils) > 0 && q.Coils[0]
		return append([]byte(nil), pdu...)
	case wire.FCWriteMultipleRegisters:
		for i, v := range q.Registers {
			p.regs[q.Address+uint16(i)] = v
		}
		return append([]byte(nil), pdu[:5]...)
	case wire.FCWriteMultipleCoils:
		for i, v := range q.Coils {
			p.coils[q.Address+uint16(i)] = v
		}
		return append([]byte(nil), pdu[:5]...)
	case wire.FCMaskWriteRegister:
		return append([]byte(nil), pdu...)
	case wire.FCReportServerID:
		return []byte{q.Function, 3, 0x01, 0xFF, 0x00}
	case wire.FCDiagnostic:
		return append([]byte(nil), pdu...)
	case wire.FCEncapsulatedInterface:
		if p.vendorName == "" || q.SubFunction != wire.MEIIdentification {
			break
		}
		// Basic identification, section 6.21: the identification code, the
		// conformity level, more-follows, the object id a walk would resume
		// at, the number of objects, and then the objects.
		out := []byte{q.Function, wire.MEIIdentification, 0x01, 0x81, 0x00, 0x00, 0x03}
		for _, o := range []struct {
			id    byte
			value string
		}{
			{wire.IDVendor, p.vendorName},
			{wire.IDProductCode, p.productCode},
			{wire.IDRevision, p.revision},
		} {
			out = append(out, o.id, byte(len(o.value)))
			out = append(out, o.value...)
		}
		return out
	}
	return wire.ExceptionPDU(q.Function, wire.ExIllegalFunction)
}

// master is the test's side of a session: one request at a time, and the
// answer read in the listener's framing.
type master struct {
	t       *testing.T
	conn    net.Conn
	rd      *wire.Reader
	framing wire.Framing
	txn     uint16
}

func dialMaster(t *testing.T, addr string, framing wire.Framing) *master {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return &master{t: t, conn: c, rd: wire.NewReader(c, framing, false), framing: framing}
}

func tlsMaster(t *testing.T, addr string, cfg *tls.Config) *master {
	t.Helper()
	c, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return &master{t: t, conn: c, rd: wire.NewReader(c, wire.FramingTCP, false), framing: wire.FramingTCP}
}

// ask sends one request and returns the answer's PDU.
func (m *master) ask(unit byte, pdu []byte) (*wire.PDU, error) {
	m.t.Helper()
	m.txn++
	_ = m.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := m.conn.Write(wire.Encode(m.framing, &wire.Frame{
		Transaction: m.txn, Unit: unit, PDU: pdu})); err != nil {
		return nil, err
	}
	return m.read(pdu[0])
}

// send writes a request without waiting for its answer, which is what a
// master with several requests in flight does.
func (m *master) send(unit byte, pdu []byte) {
	m.t.Helper()
	m.txn++
	_ = m.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := m.conn.Write(wire.Encode(m.framing, &wire.Frame{
		Transaction: m.txn, Unit: unit, PDU: pdu})); err != nil {
		m.t.Fatalf("write: %v", err)
	}
}

// raw writes bytes as they are, which is how a malformed frame is sent.
func (m *master) raw(b []byte) {
	m.t.Helper()
	_ = m.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := m.conn.Write(b); err != nil {
		m.t.Fatalf("write: %v", err)
	}
}

func (m *master) read(fc byte) (*wire.PDU, error) {
	_ = m.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	m.rd.Expect(fc)
	f, _, err := m.rd.ReadFrame()
	if err != nil {
		return nil, err
	}
	return wire.ParseResponse(f.PDU, &wire.PDU{Function: fc, Address: 0, Quantity: quantityOf(fc)})
}

// frame reads one answer and returns the frame, for the tests that are
// about the header rather than the PDU.
func (m *master) frame(fc byte) (*wire.Frame, error) {
	_ = m.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	m.rd.Expect(fc)
	f, _, err := m.rd.ReadFrame()
	return f, err
}

// quantityOf is the quantity the test's reads ask for, which a response
// parser needs to check a read answer against.
func quantityOf(fc byte) uint16 {
	switch fc {
	case wire.FCReadCoils, wire.FCReadDiscreteInputs, wire.FCReadHoldingRegisters,
		wire.FCReadInputRegisters, wire.FCReadWriteMultiple:
		return 2
	}
	return 1
}

// expectException reads the answer and checks it is the exception the
// relay is meant to refuse with.
func (m *master) expectException(what string, code byte) {
	m.t.Helper()
	p, err := m.read(wire.FCReadHoldingRegisters)
	if err != nil {
		m.t.Fatalf("%s: %v", what, err)
	}
	if !p.IsException || p.Exception != code {
		m.t.Fatalf("%s: got %+v, want exception %d", what, p, code)
	}
}

// expectClosed checks the relay ended the session rather than answering.
func (m *master) expectClosed(what string) {
	m.t.Helper()
	_ = m.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	if n, err := m.conn.Read(buf); err == nil {
		m.t.Fatalf("%s: session still open, read %d bytes", what, n)
	}
}

var (
	readTwo   = []byte{3, 0x00, 0x64, 0x00, 0x02} // read 2 registers at 100
	readCoils = []byte{1, 0x00, 0x00, 0x00, 0x02} // read 2 coils at 0
	setPoint  = []byte{6, 0x01, 0x90, 0x00, 0x32} // write 50 to register 400
	tooHigh   = []byte{6, 0x01, 0x90, 0x03, 0x84} // write 900 to register 400
	serverID  = []byte{17}                        // report server id
)

const modbusYAML = `
version: 1
server:
  listeners:
    - name: plant
      address: "127.0.0.1:0"
      kind: modbus
      modbus:
%s
logging: {access: {enabled: false}}
upstreams:
%s
`

// modbusServer starts a listener whose modbus section is the indented
// block given, with one upstream per device.
func modbusServer(t *testing.T, section string, devices map[string]*plc) (*proxy.Server, string) {
	t.Helper()
	var pools strings.Builder
	for name, p := range devices {
		fmt.Fprintf(&pools, "  - {name: %s, endpoints: [{address: %q}]}\n", name, p.addr())
	}
	s := proxytest.Start(t, fmt.Sprintf(modbusYAML, section, pools.String()))
	return s, proxytest.Addr(t, s, "plant")
}

// A reverse listener fronts a device: the master connects here, the
// relay dials the PLC, and the frames arrive at the device as they were
// sent.
func TestModbusReverseRelay(t *testing.T) {
	dev := startPLC(t, &plc{framing: wire.FramingTCP})
	dev.regs[100], dev.regs[101] = 0x1234, 0x5678
	s, addr := modbusServer(t, `        upstream: plc
        log_frames: true
        rules:
          - {name: reads, action: allow, access: [read, identify]}
          - {name: setpoints, action: allow, functions: [write_single_register],
             addresses: ["400-499"], values: [{registers: "400-499", min: 0, max: 100}]}`,
		map[string]*plc{"plc": dev})

	m := dialMaster(t, addr, wire.FramingTCP)
	p, err := m.ask(1, readTwo)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(p.Registers) != 2 || p.Registers[0] != 0x1234 || p.Registers[1] != 0x5678 {
		t.Fatalf("the device's registers did not come back: %+v", p.Registers)
	}
	if _, err := m.ask(1, setPoint); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := dev.regs[400]; got != 50 {
		t.Fatalf("the setpoint did not reach the device: %d", got)
	}
	if _, err := m.ask(1, serverID); err != nil {
		t.Fatalf("report server id: %v", err)
	}
	// A coil read comes back as bits rather than registers, and the
	// relay reads the byte count against the quantity that was asked
	// for, so it has to be exercised too.
	dev.coils[0], dev.coils[1] = true, false
	cp, err := m.ask(1, readCoils)
	if err != nil {
		t.Fatalf("read coils: %v", err)
	}
	if len(cp.Coils) != 2 || !cp.Coils[0] || cp.Coils[1] {
		t.Fatalf("the device's coils did not come back: %+v", cp.Coils)
	}

	// The bytes the device read are the bytes the master sent.
	r, ok := dev.saw(wire.FCWriteSingleRegister)
	if !ok {
		t.Fatal("the write did not reach the device")
	}
	if got := r.raw[len(r.raw)-5:]; string(got) != string(setPoint) {
		t.Fatalf("the relay rewrote the frame: % x", got)
	}
	sn := s.Stats()
	if sn.ModbusSessions != 1 || sn.ModbusRequests != 4 || sn.ModbusResponses != 4 {
		t.Fatalf("counters: sessions %d requests %d responses %d",
			sn.ModbusSessions, sn.ModbusRequests, sn.ModbusResponses)
	}
	if sn.ModbusDenied != 0 {
		t.Fatalf("a refusal that should not have happened: %d", sn.ModbusDenied)
	}
}

// A refused request is answered as the device's own exception, so the
// master's diagnostics say something true and the session carries on.
func TestModbusRefusalIsAnExceptionTheMasterUnderstands(t *testing.T) {
	dev := startPLC(t, &plc{framing: wire.FramingTCP})
	s, addr := modbusServer(t, `        upstream: plc
        read_only: true
        default_action: allow`, map[string]*plc{"plc": dev})

	m := dialMaster(t, addr, wire.FramingTCP)
	if _, err := m.ask(1, readTwo); err != nil {
		t.Fatalf("read on a read-only listener: %v", err)
	}
	m.send(1, setPoint)
	m.expectException("a write on a read-only listener", wire.ExIllegalFunction)
	if _, ok := dev.saw(wire.FCWriteSingleRegister); ok {
		t.Fatal("the refused write reached the device")
	}
	// The session is still usable: a refusal is not a disconnection.
	if _, err := m.ask(1, readTwo); err != nil {
		t.Fatalf("read after a refusal: %v", err)
	}
	sn := s.Stats()
	if sn.ModbusDenied != 1 {
		t.Fatalf("denied: %d", sn.ModbusDenied)
	}
	if got := s.Stats().Refusals["modbus"]["read_only"]; got != 1 {
		t.Fatalf("the refusal reason was not counted: %+v", sn.Refusals["modbus"])
	}
}

// A value outside the bound the rule set is refused with an illegal data
// value, which is what a master's engineer will see in the log.
func TestModbusValueBoundRefusesWithIllegalValue(t *testing.T) {
	dev := startPLC(t, &plc{framing: wire.FramingTCP})
	_, addr := modbusServer(t, `        upstream: plc
        rules:
          - {name: setpoints, action: allow, functions: [write_single_register],
             values: [{registers: "400-499", min: 0, max: 100}]}`, map[string]*plc{"plc": dev})
	m := dialMaster(t, addr, wire.FramingTCP)
	m.send(1, tooHigh)
	m.expectException("a setpoint of 900 where 100 is the bound", wire.ExIllegalValue)
	if len(dev.requests()) != 0 {
		t.Fatalf("the refused write reached the device: %+v", dev.requests())
	}
}

// The three refusal styles: an exception the master reads, no answer at
// all, or the end of the connection.
func TestModbusDenyResponses(t *testing.T) {
	for _, tc := range []struct{ name, mode string }{
		{"exception", "exception"},
		{"drop", "drop"},
		{"close", "close"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dev := startPLC(t, &plc{framing: wire.FramingTCP})
			_, addr := modbusServer(t, fmt.Sprintf(`        upstream: plc
        read_only: true
        default_action: allow
        deny_response: %s`, tc.mode), map[string]*plc{"plc": dev})
			m := dialMaster(t, addr, wire.FramingTCP)
			m.send(1, setPoint)
			switch tc.mode {
			case "exception":
				m.expectException("refused", wire.ExIllegalFunction)
			case "drop":
				_ = m.conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
				if _, _, err := m.rd.ReadFrame(); err == nil {
					t.Fatal("a dropped request was answered")
				}
			case "close":
				m.expectClosed("a refusal that closes the session")
			}
			if len(dev.requests()) != 0 {
				t.Fatal("the refused write reached the device")
			}
		})
	}
}

// A forward listener is the plant's controlled egress: the routes decide
// which destination each unit identifier may reach, and a unit with no
// route has nowhere to go.
func TestModbusForwardRoutesDecideTheDestination(t *testing.T) {
	a := startPLC(t, &plc{framing: wire.FramingTCP})
	b := startPLC(t, &plc{framing: wire.FramingTCP})
	a.regs[100] = 0x0A0A
	b.regs[100] = 0x0B0B
	_, addr := modbusServer(t, `        mode: forward
        routes:
          - {name: line-1, units: ["1-4"], upstream: cell_a}
          - {name: line-2, units: ["5"], upstream: cell_b}
        rules:
          - {name: reads, action: allow, access: [read]}`,
		map[string]*plc{"cell_a": a, "cell_b": b})

	m := dialMaster(t, addr, wire.FramingTCP)
	p, err := m.ask(2, readTwo)
	if err != nil {
		t.Fatalf("unit 2: %v", err)
	}
	if p.Registers[0] != 0x0A0A {
		t.Fatalf("unit 2 went to the wrong device: %04x", p.Registers[0])
	}
	if p, err = m.ask(5, readTwo); err != nil {
		t.Fatalf("unit 5: %v", err)
	}
	if p.Registers[0] != 0x0B0B {
		t.Fatalf("unit 5 went to the wrong device: %04x", p.Registers[0])
	}
	// A unit no route claims has no destination, and inventing one is
	// the one thing an egress gateway must not do.
	m.send(9, readTwo)
	m.expectException("a unit with no route", wire.ExGatewayPathUnavail)
	if len(a.requests()) != 1 || len(b.requests()) != 1 {
		t.Fatalf("the unrouted unit reached a device: a %d b %d", len(a.requests()), len(b.requests()))
	}
}

// A route may rewrite the unit identifier, which is what a gateway that
// presents unit 5 to a device answering only to unit 1 needs.
func TestModbusUnitOverrideRewritesTheIdentifier(t *testing.T) {
	dev := startPLC(t, &plc{framing: wire.FramingTCP})
	_, addr := modbusServer(t, `        upstream: plc
        routes:
          - {name: gateway, units: ["5"], upstream: plc, unit_override: 1}
        rules:
          - {name: reads, action: allow, access: [read]}`, map[string]*plc{"plc": dev})
	m := dialMaster(t, addr, wire.FramingTCP)
	if _, err := m.ask(5, readTwo); err != nil {
		t.Fatalf("read through the override: %v", err)
	}
	r := dev.requests()
	if len(r) != 1 || r[0].unit != 1 {
		t.Fatalf("the unit identifier was not rewritten: %+v", r)
	}
}

// One listener may read MBAP from the master and write RTU or ASCII to
// the device, which is what a serial device behind a terminal server
// needs -- and the other way round, for a serial master reaching a
// Modbus/TCP device.
func TestModbusFramingBridge(t *testing.T) {
	for _, tc := range []struct {
		name           string
		client, device wire.Framing
		clientName     string
		deviceName     string
	}{
		{"tcp to rtu", wire.FramingTCP, wire.FramingRTU, "tcp", "rtu"},
		{"tcp to ascii", wire.FramingTCP, wire.FramingASCII, "tcp", "ascii"},
		{"rtu to tcp", wire.FramingRTU, wire.FramingTCP, "rtu", "tcp"},
		{"ascii to tcp", wire.FramingASCII, wire.FramingTCP, "ascii", "tcp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dev := startPLC(t, &plc{framing: tc.device})
			dev.regs[100] = 0xBEEF
			_, addr := modbusServer(t, fmt.Sprintf(`        upstream: plc
        framing: %s
        upstream_framing: %s
        rules:
          - {name: reads, action: allow, access: [read]}
          - {name: writes, action: allow, access: [write]}`, tc.clientName, tc.deviceName),
				map[string]*plc{"plc": dev})
			m := dialMaster(t, addr, tc.client)
			p, err := m.ask(1, readTwo)
			if err != nil {
				t.Fatalf("read across the bridge: %v", err)
			}
			if len(p.Registers) == 0 || p.Registers[0] != 0xBEEF {
				t.Fatalf("the device's register did not come back: %+v", p.Registers)
			}
			if _, err := m.ask(1, setPoint); err != nil {
				t.Fatalf("write across the bridge: %v", err)
			}
			if got := dev.regs[400]; got != 50 {
				t.Fatalf("the write did not reach the device: %d", got)
			}
		})
	}
}

// The transaction identifier the master chose is the one it gets back,
// whatever the relay used towards the device.
func TestModbusTransactionIdentifierIsPreserved(t *testing.T) {
	dev := startPLC(t, &plc{framing: wire.FramingRTU})
	_, addr := modbusServer(t, `        upstream: plc
        upstream_framing: rtu
        rules: [{name: reads, action: allow, access: [read]}]`, map[string]*plc{"plc": dev})
	m := dialMaster(t, addr, wire.FramingTCP)
	m.txn = 0x4242
	m.send(1, readTwo)
	f, err := m.frame(wire.FCReadHoldingRegisters)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if f.Transaction != 0x4243 {
		t.Fatalf("transaction identifier %04x, want %04x", f.Transaction, 0x4243)
	}
}

// The transaction identifier the master chose is the one it gets back on
// the ordinary path too, where nothing else is re-encoded: a gateway that
// renumbered it would break every master with more than one request in
// flight.
func TestModbusTransactionIdentifierSurvivesTheDevicesOwn(t *testing.T) {
	theirs := uint16(0xFFFF)
	dev := startPLC(t, &plc{framing: wire.FramingTCP, replyTxn: &theirs})
	_, addr := modbusServer(t, `        upstream: plc
        default_action: allow`, map[string]*plc{"plc": dev})
	m := dialMaster(t, addr, wire.FramingTCP)
	m.txn = 0x0100
	m.send(1, readTwo)
	f, err := m.frame(wire.FCReadHoldingRegisters)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if f.Transaction != 0x0101 {
		t.Fatalf("transaction identifier %04x, want the master's %04x", f.Transaction, 0x0101)
	}
}

// A frame the relay cannot read is a frame it cannot decide about, and
// the device would read those bytes somehow.
func TestModbusMalformedFrameNeverReachesTheDevice(t *testing.T) {
	for _, tc := range []struct {
		name  string
		bytes []byte
	}{
		{"a protocol identifier that is not modbus", []byte{0, 1, 9, 9, 0, 6, 1, 3, 0, 100, 0, 2}},
		{"a length that covers nothing", []byte{0, 1, 0, 0, 0, 1, 1}},
		{"a function code the specification does not have", []byte{0, 1, 0, 0, 0, 3, 1, 99, 0}},
		{"a read quantity past the protocol's bound", []byte{0, 1, 0, 0, 0, 6, 1, 3, 0, 0, 0x08, 0x00}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dev := startPLC(t, &plc{framing: wire.FramingTCP})
			s, addr := modbusServer(t, `        upstream: plc
        default_action: allow`, map[string]*plc{"plc": dev})
			m := dialMaster(t, addr, wire.FramingTCP)
			m.raw(tc.bytes)
			// A frame whose function code or fields the relay could
			// read far enough to answer gets an exception; one whose
			// framing was wrong gets nothing. Either way the session
			// ends, because the stream cannot be trusted to resume at a
			// frame boundary.
			if p, err := m.read(wire.FCReadHoldingRegisters); err == nil && !p.IsException {
				t.Fatalf("a malformed frame was answered: %+v", p)
			}
			m.expectClosed("a malformed frame")
			if len(dev.requests()) != 0 {
				t.Fatalf("the malformed frame reached the device: %+v", dev.requests())
			}
			if s.Stats().ModbusMalformed == 0 {
				t.Fatal("the malformed frame was not counted")
			}
		})
	}
}

// A device answer the relay cannot read is not handed to the master: the
// two would read the same bytes differently, which is the whole class of
// bug this relay exists to prevent.
func TestModbusMalformedResponseIsNotPassedOn(t *testing.T) {
	dev := startPLC(t, &plc{framing: wire.FramingTCP, garbage: true})
	s, addr := modbusServer(t, `        upstream: plc
        default_action: allow`, map[string]*plc{"plc": dev})
	m := dialMaster(t, addr, wire.FramingTCP)
	m.send(1, readTwo)
	m.expectException("a response the relay cannot read", wire.ExServerFailure)
	if got := s.Stats().Refusals["modbus"]["malformed_response"]; got != 1 {
		t.Fatalf("the malformed response was not counted: %+v", s.Stats().Refusals["modbus"])
	}
}

// A device answering for another unit identifier is answering somebody
// else's request.
func TestModbusResponseUnitMismatch(t *testing.T) {
	other := byte(7)
	dev := startPLC(t, &plc{framing: wire.FramingTCP, replyUnit: &other})
	s, addr := modbusServer(t, `        upstream: plc
        default_action: allow`, map[string]*plc{"plc": dev})
	m := dialMaster(t, addr, wire.FramingTCP)
	m.send(1, readTwo)
	m.expectException("an answer for another unit", wire.ExServerFailure)
	if got := s.Stats().Refusals["modbus"]["response_unit_mismatch"]; got != 1 {
		t.Fatalf("the mismatch was not counted: %+v", s.Stats().Refusals["modbus"])
	}
}

// A device exception is the device's answer and is passed on as it is,
// counted as an exception rather than a refusal.
func TestModbusDeviceExceptionIsPassedOn(t *testing.T) {
	dev := startPLC(t, &plc{framing: wire.FramingTCP, exception: wire.ExIllegalAddress})
	s, addr := modbusServer(t, `        upstream: plc
        default_action: allow`, map[string]*plc{"plc": dev})
	m := dialMaster(t, addr, wire.FramingTCP)
	p, err := m.ask(1, readTwo)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !p.IsException || p.Exception != wire.ExIllegalAddress {
		t.Fatalf("the device's exception did not come back: %+v", p)
	}
	if sn := s.Stats(); sn.ModbusExceptions != 1 || sn.ModbusDenied != 0 {
		t.Fatalf("exceptions %d denied %d", sn.ModbusExceptions, sn.ModbusDenied)
	}
}

// A device that is there but not answering is the commonest fault in a
// plant, and the master hears it as a gateway exception rather than a
// hang.
func TestModbusSilentDeviceAnswersAsAGateway(t *testing.T) {
	dev := startPLC(t, &plc{framing: wire.FramingTCP, silent: true})
	s, addr := modbusServer(t, `        upstream: plc
        default_action: allow
        request_timeout: 300ms`, map[string]*plc{"plc": dev})
	m := dialMaster(t, addr, wire.FramingTCP)
	m.send(1, readTwo)
	m.expectException("a device that does not answer", wire.ExGatewayNoResponse)
	if s.Stats().ModbusUpstreamFailed == 0 {
		t.Fatal("the failed exchange was not counted")
	}
}

// A second request while the device has not answered the first is
// refused as a busy server rather than pipelined into a slave that has
// one scan.
func TestModbusPendingBoundAnswersBusy(t *testing.T) {
	dev := startPLC(t, &plc{framing: wire.FramingTCP, silent: true})
	s, addr := modbusServer(t, `        upstream: plc
        default_action: allow
        max_pending: 1
        request_timeout: 300ms`, map[string]*plc{"plc": dev})
	m := dialMaster(t, addr, wire.FramingTCP)
	m.send(1, readTwo)
	m.send(1, readTwo)
	// The answers arrive in the order the relay produced them: the
	// second request's refusal, then the first request's timeout.
	first, err := m.read(wire.FCReadHoldingRegisters)
	if err != nil {
		t.Fatalf("first answer: %v", err)
	}
	second, err := m.read(wire.FCReadHoldingRegisters)
	if err != nil {
		t.Fatalf("second answer: %v", err)
	}
	codes := map[byte]bool{first.Exception: true, second.Exception: true}
	if !first.IsException || !second.IsException || !codes[wire.ExServerBusy] || !codes[wire.ExGatewayNoResponse] {
		t.Fatalf("answers %+v and %+v, want a busy and a no-response", first, second)
	}
	if s.Stats().ModbusQueueFull == 0 {
		t.Fatal("the full queue was not counted")
	}
}

// The client list decides before anything else: a master outside it
// never gets to send a frame.
func TestModbusClientListDecidesFirst(t *testing.T) {
	dev := startPLC(t, &plc{framing: wire.FramingTCP})
	s, addr := modbusServer(t, `        upstream: plc
        default_action: allow
        allow_clients: ["10.0.0.0/8"]`, map[string]*plc{"plc": dev})
	m := dialMaster(t, addr, wire.FramingTCP)
	m.expectClosed("a master outside the allow list")
	if got := s.Stats().Refusals["modbus"]["client_not_allowed"]; got != 1 {
		t.Fatalf("the refusal was not counted: %+v", s.Stats().Refusals["modbus"])
	}
}

// Rate limiting is per client address, because a PLC's scan budget is
// finite and a master that asks faster than the device can answer is an
// outage.
func TestModbusRateLimit(t *testing.T) {
	dev := startPLC(t, &plc{framing: wire.FramingTCP})
	s, addr := modbusServer(t, `        upstream: plc
        default_action: allow
        rate_limit: 1
        rate_burst: 1`, map[string]*plc{"plc": dev})
	m := dialMaster(t, addr, wire.FramingTCP)
	for i := 0; i < 5; i++ {
		m.send(1, readTwo)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && s.Stats().ModbusRateLimited == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if s.Stats().ModbusRateLimited == 0 {
		t.Fatal("no request was rate limited")
	}
	if n := len(dev.requests()); n > 3 {
		t.Fatalf("%d requests reached the device past a limit of one a second", n)
	}
}

// The listener bounds live sessions, because a scan can open more
// connections than a plant has masters.
func TestModbusMaxConnections(t *testing.T) {
	dev := startPLC(t, &plc{framing: wire.FramingTCP})
	s, addr := modbusServer(t, `        upstream: plc
        default_action: allow
        max_connections: 1`, map[string]*plc{"plc": dev})
	m := dialMaster(t, addr, wire.FramingTCP)
	if _, err := m.ask(1, readTwo); err != nil {
		t.Fatalf("the first session: %v", err)
	}
	second := dialMaster(t, addr, wire.FramingTCP)
	second.expectClosed("a session past the bound")
	if s.Stats().ModbusRejected == 0 {
		t.Fatal("the rejected session was not counted")
	}
}

// Learning mode records what crosses the listener and, unless it is told
// to enforce, decides nothing: the only honest way to find out what a
// policy would have broken.
func TestModbusLearningModeObservesWithoutEnforcing(t *testing.T) {
	dev := startPLC(t, &plc{framing: wire.FramingTCP})
	dir := t.TempDir()
	report := filepath.Join(dir, "learned.yaml")
	s, addr := modbusServer(t, fmt.Sprintf(`        upstream: plc
        learn: {enabled: true, file: %s, interval: 10s}`, report), map[string]*plc{"plc": dev})
	m := dialMaster(t, addr, wire.FramingTCP)
	if _, err := m.ask(3, readTwo); err != nil {
		t.Fatalf("read while learning: %v", err)
	}
	// The default action is deny, and the frame went through anyway
	// because learning is observe-only.
	if _, ok := dev.saw(wire.FCReadHoldingRegisters); !ok {
		t.Fatal("learning mode refused a frame it was only meant to record")
	}
	if s.Stats().ModbusWouldDeny == 0 {
		t.Fatal("the refusal that did not happen was not counted")
	}
	// The report is written on the interval and at shutdown, and a
	// week's learning run is no use if the file is only there while the
	// process is.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	b, err := os.ReadFile(report)
	if err != nil {
		t.Fatalf("the learning report was not written: %v", err)
	}
	body := string(b)
	for _, want := range []string{"observed:", "rules:", "read_holding_registers", "127.0.0.1", "unit: 3", "100-101"} {
		if !strings.Contains(body, want) {
			t.Fatalf("the report does not name %q:\n%s", want, body)
		}
	}
}

// Enforcing while learning is a choice a listener has to make in
// writing, and when it is made the policy still decides.
func TestModbusLearningModeCanEnforce(t *testing.T) {
	dev := startPLC(t, &plc{framing: wire.FramingTCP})
	dir := t.TempDir()
	_, addr := modbusServer(t, fmt.Sprintf(`        upstream: plc
        learn: {enabled: true, enforce: true, file: %s}`, filepath.Join(dir, "l.yaml")),
		map[string]*plc{"plc": dev})
	m := dialMaster(t, addr, wire.FramingTCP)
	m.send(1, readTwo)
	m.expectException("a frame no rule allows while enforcing", wire.ExIllegalFunction)
	if len(dev.requests()) != 0 {
		t.Fatal("an enforcing learning run passed a refused frame")
	}
}

// The trace is the engineer's tool for "what is this master actually
// doing", one JSON object per frame.
func TestModbusTraceWritesALinePerFrame(t *testing.T) {
	dev := startPLC(t, &plc{framing: wire.FramingTCP})
	path := filepath.Join(t.TempDir(), "trace.jsonl")
	_, addr := modbusServer(t, fmt.Sprintf(`        upstream: plc
        default_action: allow
        trace: {file: %s, include_data: true}`, path), map[string]*plc{"plc": dev})
	m := dialMaster(t, addr, wire.FramingTCP)
	if _, err := m.ask(1, readTwo); err != nil {
		t.Fatalf("read: %v", err)
	}
	var body string
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil && strings.Count(b2s(b), "\n") >= 2 {
			body = b2s(b)
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if body == "" {
		t.Fatal("the trace was not written")
	}
	for _, want := range []string{`"direction":"request"`, `"direction":"response"`,
		`"function":"read_holding_registers"`, `"decision":"allow"`, `"data":"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("the trace does not carry %s:\n%s", want, body)
		}
	}
}

// Modbus/TCP Security: TLS with mutual authentication, and the role the
// client certificate carries decides what the session may do.
func TestModbusSecurityRoleAuthorisation(t *testing.T) {
	dev := startPLC(t, &plc{framing: wire.FramingTCP})
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	srvCert, srvKey := ca.Issue(t, dir, "relay.plant")
	engCert, engKey := issueWithRole(t, dir, ca, "engineer-1", "engineer")
	opCert, opKey := issueWithRole(t, dir, ca, "operator-1", "operator")
	plainCert, plainKey := ca.Issue(t, dir, "no-role")

	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: plant
      address: "127.0.0.1:0"
      kind: modbus
      tls:
        certificates: [{cert_file: %s, key_file: %s}]
        client_auth: require
        client_ca_file: %s
      modbus:
        upstream: plc
        tls_mode: implicit
        security: {mode: require, role_source: extension}
        rules:
          - {name: reads, action: allow, access: [read]}
          - {name: engineers, action: allow, roles: [engineer], access: [write]}
logging: {access: {enabled: false}}
upstreams:
  - {name: plc, endpoints: [{address: %q}]}
`, srvCert, srvKey, ca.Path, dev.addr())
	s := proxytest.Start(t, yaml)
	addr := proxytest.Addr(t, s, "plant")

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CertPEM)
	cfgFor := func(certFile, keyFile string) *tls.Config {
		pair, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			t.Fatal(err)
		}
		return &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{pair},
			ServerName: "relay.plant", MinVersion: tls.VersionTLS12}
	}

	// The engineer may write.
	eng := tlsMaster(t, addr, cfgFor(engCert, engKey))
	if _, err := eng.ask(1, setPoint); err != nil {
		t.Fatalf("an engineer's write: %v", err)
	}
	if got := dev.regs[400]; got != 50 {
		t.Fatalf("the engineer's write did not reach the device: %d", got)
	}
	// The operator may read and not write, because the writing rule
	// names a role the operator does not have.
	op := tlsMaster(t, addr, cfgFor(opCert, opKey))
	if _, err := op.ask(1, readTwo); err != nil {
		t.Fatalf("an operator's read: %v", err)
	}
	op.send(1, tooHigh)
	op.expectException("an operator's write", wire.ExIllegalFunction)
	// A certificate with no role at all cannot be authorised, and
	// require says so rather than guessing.
	none := tlsMaster(t, addr, cfgFor(plainCert, plainKey))
	none.expectClosed("a certificate with no role")
	if got := s.Stats().Refusals["modbus"]["no_role"]; got != 1 {
		t.Fatalf("the missing role was not counted: %+v", s.Stats().Refusals["modbus"])
	}
}

// A role can only come from a certificate, and a certificate can only
// come from TLS. A listener that asks for roles without TLS is a
// misconfiguration, and saying so is better than a mystery.
func TestModbusSecurityWithoutTLSIsRefused(t *testing.T) {
	dev := startPLC(t, &plc{framing: wire.FramingTCP})
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	srvCert, srvKey := ca.Issue(t, dir, "relay.plant")
	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: plant
      address: "127.0.0.1:0"
      kind: modbus
      tls:
        certificates: [{cert_file: %s, key_file: %s}]
        client_auth: require
        client_ca_file: %s
      modbus:
        upstream: plc
        default_action: allow
        tls_mode: none
        security: {mode: require}
logging: {access: {enabled: false}}
upstreams:
  - {name: plc, endpoints: [{address: %q}]}
`, srvCert, srvKey, ca.Path, dev.addr()))
	m := dialMaster(t, proxytest.Addr(t, s, "plant"), wire.FramingTCP)
	m.expectClosed("a role required without tls")
	if got := s.Stats().Refusals["modbus"]["security_requires_tls"]; got != 1 {
		t.Fatalf("the refusal was not counted: %+v", s.Stats().Refusals["modbus"])
	}
}

// The role may be read from the subject when the authority cannot issue
// the extension yet, which is the documented migration.
func TestModbusRoleFromSubject(t *testing.T) {
	dev := startPLC(t, &plc{framing: wire.FramingTCP})
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	srvCert, srvKey := ca.Issue(t, dir, "relay.plant")
	cert, key := ca.Issue(t, dir, "engineer")

	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: plant
      address: "127.0.0.1:0"
      kind: modbus
      tls:
        certificates: [{cert_file: %s, key_file: %s}]
        client_auth: require
        client_ca_file: %s
      modbus:
        upstream: plc
        security: {mode: require, role_source: cn, roles: [engineer]}
        rules: [{name: engineers, action: allow, roles: [engineer]}]
logging: {access: {enabled: false}}
upstreams:
  - {name: plc, endpoints: [{address: %q}]}
`, srvCert, srvKey, ca.Path, dev.addr()))
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CertPEM)
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	m := tlsMaster(t, proxytest.Addr(t, s, "plant"), &tls.Config{RootCAs: pool,
		Certificates: []tls.Certificate{pair}, ServerName: "relay.plant", MinVersion: tls.VersionTLS12})
	if _, err := m.ask(1, readTwo); err != nil {
		t.Fatalf("a read by the common name's role: %v", err)
	}
}

// issueWithRole signs a client certificate carrying the Modbus/TCP
// Security role extension, which is what an authority following the
// specification issues.
func issueWithRole(t *testing.T, dir string, ca *testutil.CA, name, role string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oid, value, err := wire.RoleExtension(role)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{{
			Id:       oid,
			Critical: false,
			Value:    value,
		}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, name+".pem")
	keyPath = filepath.Join(dir, name+"-key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func b2s(b []byte) string { return string(b) }

// The listener is in the roster as a relay kind, so its refusals are
// counted rather than dropped under RefusalsUntracked.
func TestModbusConfigDefaults(t *testing.T) {
	for _, framing := range []string{"rtu", "ascii"} {
		m := &config.ModbusListener{Framing: framing}
		if m.Pending() != 1 {
			t.Fatalf("%s has no transaction identifier, so one request is in flight, got %d",
				framing, m.Pending())
		}
	}
	for _, framing := range []string{"", "tcp"} {
		m := &config.ModbusListener{Framing: framing}
		if m.Pending() != 16 {
			t.Fatalf("MBAP defaults to sixteen, got %d", m.Pending())
		}
	}
	if m := (&config.ModbusListener{Framing: "rtu", MaxPending: 4}); m.Pending() != 4 {
		t.Fatalf("a listener that says four means four, got %d", m.Pending())
	}
	var absent *config.ModbusListener
	if !absent.Alerts() || absent.Logs() || absent.Pending() != 1 {
		t.Fatal("a listener with no modbus section has the safe answers")
	}
	m := &config.ModbusListener{}
	if !m.Alerts() {
		t.Fatal("refusals are alerted on by default")
	}
	off := false
	m.AlertOnDeny = &off
	if m.Alerts() {
		t.Fatal("turning the alerts off is a choice that has to work")
	}
}

// Shadow mode, end to end: the policy that would have refused a write
// records it and the write reaches the device, while a malformed frame is
// still refused -- which is the line that makes shadow mode safe to turn
// on at all.
func TestModbusShadowModeRecordsAndDoesNotEnforce(t *testing.T) {
	dev := startPLC(t, &plc{framing: wire.FramingTCP})
	yaml := fmt.Sprintf(`
version: 1
policy: {mode: shadow}
server:
  listeners:
    - name: plant
      address: "127.0.0.1:0"
      kind: modbus
      modbus:
        upstream: plc
        rules:
          - {name: reads, action: allow, access: [read]}
logging: {access: {enabled: false}}
upstreams:
  - {name: plc, endpoints: [{address: %q}]}
`, dev.addr())
	s := proxytest.Start(t, yaml)
	addr := proxytest.Addr(t, s, "plant")

	m := dialMaster(t, addr, wire.FramingTCP)
	// A write no rule allows: in shadow mode it reaches the device, and
	// the ledger says which rule would have refused it.
	if _, err := m.ask(1, setPoint); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := dev.regs[400]; got != 50 {
		t.Fatalf("the write did not reach the device: %d", got)
	}
	rep := s.Shadow().Report()
	if len(rep) != 1 || rep[0].Kind != "modbus" || rep[0].Listener != "plant" || rep[0].Count != 1 {
		t.Fatalf("the report does not name the write: %+v", rep)
	}
	if rep[0].Sample == "" {
		t.Errorf("the entry carries no example of what was asked for: %+v", rep[0])
	}
	if sn := s.Stats(); sn.ModbusWouldDeny != 1 || sn.ModbusDenied != 0 ||
		sn.WouldRefusals["modbus"][rep[0].Reason] != 1 {
		t.Errorf("counters: would_deny %d denied %d would_refusals %+v",
			sn.ModbusWouldDeny, sn.ModbusDenied, sn.WouldRefusals)
	}
	// A read the policy allows is not in the ledger: shadow mode records
	// refusals, not traffic.
	if _, err := m.ask(1, readTwo); err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := s.Shadow().Report(); len(got) != 1 {
		t.Errorf("an allowed frame was recorded: %+v", got)
	}
	// And the integrity refusal still refuses: a frame this relay cannot
	// parse is not a policy question, and forwarding it would mean
	// sending the device bytes nobody read.
	m.raw(wire.Encode(wire.FramingTCP, &wire.Frame{Transaction: 7, Unit: 1, PDU: []byte{0x06, 0x01}}))
	m.expectException("a truncated write in shadow mode", wire.ExIllegalFunction)
	if sn := s.Stats(); sn.Refusals["modbus"]["malformed"] == 0 {
		t.Errorf("a malformed frame was not refused in shadow mode: %+v", sn.Refusals["modbus"])
	}
}

// The value semantics through a real relay: the setpoint rule from the
// documentation, which is what a plant asks for in one sentence -- this
// register, this range, not in one jump, once a minute, and only after the
// permissive was set.
func TestModbusValueSemanticsEndToEnd(t *testing.T) {
	dev := startPLC(t, &plc{framing: wire.FramingTCP})
	dev.regs[400] = 500
	s, addr := modbusServer(t, `        upstream: plc
        rules:
          - {name: reads, action: allow, access: [read]}
          - name: permissive
            action: allow
            functions: [write_single_register]
            addresses: ["401"]
            values: [{registers: "401", min: 0, max: 1}]
          - name: setpoint
            action: allow
            functions: [write_single_register]
            addresses: ["400"]
            values:
              - registers: "400"
                min: 0
                max: 1500
                max_delta: 100
                rate: {max: 1, period: 1m}
                require_before: {registers: "401", equals: 1, within: 30s}`,
		map[string]*plc{"plc": dev})

	m := dialMaster(t, addr, wire.FramingTCP)
	// A read tells the relay what the registers hold, which is what the
	// delta is measured against. Two registers, because the test master's
	// reads always ask for two.
	if _, err := m.ask(1, []byte{3, 0x01, 0x90, 0x00, 0x02}); err != nil {
		t.Fatalf("read: %v", err)
	}
	// No permissive yet: the write is refused, and the master is told in
	// its own terms.
	m.raw(wire.Encode(wire.FramingTCP, &wire.Frame{Transaction: 2, Unit: 1,
		PDU: []byte{6, 0x01, 0x90, 0x02, 0x1C}})) // write 540 to 400
	m.expectException("a setpoint with no permissive", wire.ExIllegalValue)
	if got := dev.regs[400]; got != 500 {
		t.Fatalf("the refused write reached the device: %d", got)
	}
	// The permissive, then the setpoint: a nudge of 40 inside the delta.
	if _, err := m.ask(1, []byte{6, 0x01, 0x91, 0x00, 0x01}); err != nil {
		t.Fatalf("permissive: %v", err)
	}
	if _, err := m.ask(1, []byte{6, 0x01, 0x90, 0x02, 0x1C}); err != nil {
		t.Fatalf("setpoint after the permissive: %v", err)
	}
	if got := dev.regs[400]; got != 540 {
		t.Fatalf("the setpoint did not reach the device: %d", got)
	}
	// The second write inside the minute is refused for the rate, which
	// is a different exception because the same write would be accepted
	// later.
	m.raw(wire.Encode(wire.FramingTCP, &wire.Frame{Transaction: 5, Unit: 1,
		PDU: []byte{6, 0x01, 0x90, 0x02, 0x1D}}))
	m.expectException("a second setpoint inside the minute", wire.ExServerBusy)
	sn := s.Stats()
	if sn.Refusals["modbus"]["value_no_select"] == 0 || sn.Refusals["modbus"]["value_rate"] == 0 {
		t.Errorf("refusals %+v", sn.Refusals["modbus"])
	}
	if sn.ModbusValuePoints == 0 {
		t.Error("the value table is empty although writes and reads were relayed")
	}
}

// Behavioural detection through a real listener.
//
// The detector alerts and carries the frame, which is what a detector built on
// novelty has to do: the first legitimate maintenance write of the year is novel
// too. So the counters move, the events are written, and the device gets the
// write.
func TestAnUnusualCommandIsReportedAndCarried(t *testing.T) {
	dev := startPLC(t, &plc{framing: wire.FramingTCP})
	s, addr := modbusServer(t, `        upstream: plc
        default_action: allow
        anomaly:
          enabled: true
          settle: 0s`, map[string]*plc{"plc": dev})

	m := dialMaster(t, addr, wire.FramingTCP)
	if _, err := m.ask(1, readTwo); err != nil {
		t.Fatalf("read: %v", err)
	}
	if _, err := m.ask(1, setPoint); err != nil {
		t.Fatalf("the detector refused a write it was only meant to report: %v", err)
	}
	if _, ok := dev.saw(wire.FCWriteSingleRegister); !ok {
		t.Fatal("the reported write did not reach the device")
	}
	sn := s.Stats()
	if sn.ModbusDenied != 0 {
		t.Fatalf("an alert was counted as a refusal: %d", sn.ModbusDenied)
	}
	// With no settling window the read is novel too -- it is the first function
	// code this master has used -- so the function finding is two: the read and
	// the write. The address finding is one, because only the write has an
	// address the master drove.
	for want, times := range map[string]uint64{"anomaly_new_function": 2, "anomaly_new_write_address": 1} {
		if got := sn.Refusals["modbus"][want]; got != times {
			t.Errorf("%s was counted %d times, wanted %d: %+v", want, got, times, sn.Refusals["modbus"])
		}
	}
}

// And with action: deny it refuses, as the device's own exception.
//
// It refuses the *first* occurrence and records it, so the retry goes through.
// That is a deliberate limit and not an oversight: refusing every occurrence
// until somebody intervened would mean a plant that could not be driven after any
// novelty, with no mechanism here for the intervening. What deny buys is a hard
// stop on the first attempt and an operator's attention. It is not a block, and
// the policy is what blocks.
func TestTheDetectorCanBeAskedToRefuseTheFirstOccurrence(t *testing.T) {
	dev := startPLC(t, &plc{framing: wire.FramingTCP})
	s, addr := modbusServer(t, `        upstream: plc
        default_action: allow
        anomaly:
          enabled: true
          settle: 0s
          action: deny`, map[string]*plc{"plc": dev})

	m := dialMaster(t, addr, wire.FramingTCP)
	// With no settling window even the first read is novel, and that is exactly
	// what the configuration warning about settle: 0s says it would be.
	m.send(1, readTwo)
	m.expectException("the first read of a master with no settling window", wire.ExIllegalFunction)
	// The same read again: recorded by the refusal, so no longer novel.
	if _, err := m.ask(1, readTwo); err != nil {
		t.Fatalf("the second read was refused as well: %v", err)
	}
	m.send(1, setPoint)
	m.expectException("a write the detector had not seen this master make", wire.ExIllegalFunction)
	if _, ok := dev.saw(wire.FCWriteSingleRegister); ok {
		t.Fatal("the refused write reached the device")
	}
	// And the retry goes through to the device.
	if _, err := m.ask(1, setPoint); err != nil {
		t.Fatalf("the second write was refused as well: %v", err)
	}
	if _, ok := dev.saw(wire.FCWriteSingleRegister); !ok {
		t.Fatal("the retried write did not reach the device")
	}
	if sn := s.Stats(); sn.ModbusDenied != 2 {
		t.Fatalf("denied: %d, wanted the first read and the first write", sn.ModbusDenied)
	}
}

// A request the policy refuses is not recorded by the detector. Recording one
// would teach the detector that a refused probe is this master's normal traffic,
// so the probe that got through afterwards would look like business as usual.
func TestARefusedRequestTeachesTheDetectorNothing(t *testing.T) {
	dev := startPLC(t, &plc{framing: wire.FramingTCP})
	s, addr := modbusServer(t, `        upstream: plc
        read_only: true
        default_action: allow
        anomaly:
          enabled: true
          settle: 0s`, map[string]*plc{"plc": dev})

	m := dialMaster(t, addr, wire.FramingTCP)
	// The read-only listener refuses the write, and the detector never sees it.
	m.send(1, setPoint)
	m.expectException("a write on a read-only listener", wire.ExIllegalFunction)
	sn := s.Stats()
	if got := sn.Refusals["modbus"]["anomaly_new_write_address"]; got != 0 {
		t.Errorf("the detector recorded a request the policy refused: %+v", sn.Refusals["modbus"])
	}
	if got := sn.Refusals["modbus"]["read_only"]; got != 1 {
		t.Errorf("the policy's own refusal was counted %d times", got)
	}
}

// The detector's alerts do not reach the ban ladder.
//
// This is the load-bearing part of "it alerts". The signal is novelty, and a
// plant's master doing something novel is usually an engineer; a ban would drop
// its connections and take the process away from the control room over a function
// code nobody had used yet. The ban ladder is for a client doing something it may
// not do, which is what the rules decide.
//
// The trigger below fires on one modbus_denied, so a single observation would ban
// the master outright -- which is what makes the assertion worth anything.
func TestTheDetectorsAlertsDoNotBan(t *testing.T) {
	dev := startPLC(t, &plc{framing: wire.FramingTCP})
	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: plant
      address: "127.0.0.1:0"
      kind: modbus
      modbus:
        upstream: plc
        default_action: allow
        anomaly:
          enabled: true
          settle: 0s
logging: {access: {enabled: false}}
bans:
  triggers:
    - {name: any, reasons: [modbus_denied], threshold: 1, window: 1m, duration: 1h}
upstreams:
  - {name: plc, endpoints: [{address: %q}]}
`, dev.addr()))
	addr := proxytest.Addr(t, s, "plant")

	m := dialMaster(t, addr, wire.FramingTCP)
	if _, err := m.ask(1, readTwo); err != nil {
		t.Fatalf("read: %v", err)
	}
	if _, err := m.ask(1, setPoint); err != nil {
		t.Fatalf("write: %v", err)
	}
	// The alerts happened.
	sn := s.Stats()
	if got := sn.Refusals["modbus"]["anomaly_new_write_address"]; got == 0 {
		t.Fatalf("nothing was alerted on, so this test asserts nothing: %+v", sn.Refusals["modbus"])
	}
	// And the master is not banned.
	ip := netip.MustParseAddr("127.0.0.1")
	if bl := s.Bans(); bl != nil && bl.Banned(ip) {
		t.Error("an alert banned the plant's master")
	}
}

// Shadow mode and action: deny. The detector refuses nothing and the would-be
// refusal goes to the same ledger the policy's do, because a listener in shadow
// mode refusing something would make the mode worthless for the one thing it is
// for: finding out what enforcing would cost before enforcing.
func TestTheDetectorRefusesNothingInShadowMode(t *testing.T) {
	dev := startPLC(t, &plc{framing: wire.FramingTCP})
	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
policy: {mode: shadow}
server:
  listeners:
    - name: plant
      address: "127.0.0.1:0"
      kind: modbus
      modbus:
        upstream: plc
        default_action: allow
        anomaly:
          enabled: true
          settle: 0s
          action: deny
logging: {access: {enabled: false}}
upstreams:
  - {name: plc, endpoints: [{address: %q}]}
`, dev.addr()))
	addr := proxytest.Addr(t, s, "plant")

	m := dialMaster(t, addr, wire.FramingTCP)
	if _, err := m.ask(1, setPoint); err != nil {
		t.Fatalf("a write the detector would have refused was refused in shadow mode: %v", err)
	}
	if got := dev.regs[400]; got != 50 {
		t.Fatalf("the write did not reach the device: %d", got)
	}
	sn := s.Stats()
	if sn.ModbusDenied != 0 {
		t.Errorf("shadow mode refused %d frames", sn.ModbusDenied)
	}
	if sn.ModbusWouldDeny == 0 {
		t.Errorf("the would-be refusal was not counted: %+v", sn.WouldRefusals["modbus"])
	}
	// The detector's own findings are in the ledger, named as its own.
	var found bool
	for _, e := range s.Shadow().Report() {
		if e.Rule == "anomaly" {
			found = true
		}
	}
	if !found {
		t.Errorf("the ledger does not carry the detector's finding: %+v", s.Shadow().Report())
	}
}
