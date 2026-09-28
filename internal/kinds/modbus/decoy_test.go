package modbus_test

import (
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/kinds/modbus"
	wire "github.com/rom/xproxy/internal/modbus"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// The defect this exists for, stated as a test: a relay that answers
// honestly for every unit identifier draws the map of the estate. These
// are the answers the probe got before there was anything to do about it:
//
//	unit 1 read -> 2 registers, unit 2 -> 0x0a, unit 3 -> 0x0a, ...
//
// The scan is refused and the survey completes.
func TestARefusalWithoutDeceptionMapsTheUnits(t *testing.T) {
	dev := startPLC(t, &plc{framing: wire.FramingTCP})
	dev.regs[100] = 0x1234
	_, addr := modbusServer(t, `        read_only: true
        default_action: allow
        routes:
          - {name: line1, units: ["1"], upstream: plc}`, map[string]*plc{"plc": dev})

	m := dialMaster(t, addr, wire.FramingTCP)
	if p, err := m.ask(1, readTwo); err != nil || p.IsException {
		t.Fatalf("the routed unit did not answer: %+v %v", p, err)
	}
	for _, unit := range []byte{2, 3, 7, 200} {
		p, err := m.ask(unit, readTwo)
		if err != nil {
			t.Fatalf("unit %d: %v", unit, err)
		}
		if !p.IsException || p.Exception != wire.ExGatewayPathUnavail {
			t.Errorf("unit %d answered %+v; without deception every unit nothing is behind says 0x0a, "+
				"which is what makes a sweep a survey", unit, p)
		}
	}
}

// mode decoy is a honeypot: no upstream, no device, and every frame is
// answered by something that behaves like a PLC.
func TestDecoyModeAnswersAsADevice(t *testing.T) {
	s, addr := modbusServer(t, `        default_action: allow
        deception:
          mode: decoy
          profile: generic-plc
          units: ["1-4"]`, nil)

	m := dialMaster(t, addr, wire.FramingTCP)
	p, err := m.ask(1, readTwo)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if p.IsException {
		t.Fatalf("the decoy refused a read: %+v", p)
	}
	if len(p.Registers) != 2 {
		t.Fatalf("%d registers came back", len(p.Registers))
	}
	// A process does not jitter between two reads a moment apart. This is
	// the property that makes a decoy survive a second look.
	again, err := m.ask(1, readTwo)
	if err != nil {
		t.Fatal(err)
	}
	if again.Registers[0] != p.Registers[0] || again.Registers[1] != p.Registers[1] {
		t.Errorf("two reads of the same addresses disagreed: %v then %v", p.Registers, again.Registers)
	}
	// Reads of a discrete band come back as bits, and a band the profile
	// calls a counter never goes backwards.
	if _, err := m.ask(1, []byte{1, 0x03, 0xE8, 0x00, 0x08}); err != nil {
		t.Errorf("read coils: %v", err)
	}

	// A unit the decoy does not claim answers the way a gateway answers a
	// unit nothing is behind: a device on all 247 identifiers is not a
	// device anybody sells.
	if p, err := m.ask(9, readTwo); err != nil || !p.IsException {
		t.Errorf("unit 9: %+v %v, want an exception", p, err)
	}
	// A function code the profile does not implement answers the
	// exception the real device would.
	if p, err := m.ask(1, []byte{20, 0x07, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02}); err != nil {
		t.Errorf("read file record: %v", err)
	} else if !p.IsException || p.Exception != wire.ExIllegalFunction {
		t.Errorf("read file record answered %+v; a decoy that implements everything is a PLC nobody makes", p)
	}

	sn := s.Stats()
	if sn.ModbusDeceived == 0 {
		t.Error("nothing was counted as deceived")
	}
	if st := s.DeviceDecoys(); len(st) != 1 || st[0].Mode != "decoy" || st[0].Served == 0 {
		t.Errorf("the status view says %+v", st)
	} else if len(st[0].Visitors) != 1 || st[0].Visitors[0].Frames == 0 {
		t.Errorf("the status view has no visitor: %+v", st[0])
	}
}

// What a scanner fingerprints on: the server identity and the device
// identification objects. They have to carry what the section said, and
// the same thing every time -- a fabricated device whose serial number
// changes is one somebody has noticed.
func TestTheDecoyIdentifiesItselfAsConfigured(t *testing.T) {
	_, addr := modbusServer(t, `        default_action: allow
        deception:
          mode: decoy
          vendor: "Plant Systems AB"
          product: "PS-4000"
          revision: "R3.1"
          serial: "SN-00714"`, nil)

	m := dialMaster(t, addr, wire.FramingTCP)
	p, err := m.ask(1, serverID)
	if err != nil {
		t.Fatalf("report server id: %v", err)
	}
	if p.IsException {
		t.Fatalf("the decoy refused the identity request: %+v", p)
	}
	id := askRaw(t, m, 1, serverID)
	for _, want := range []string{"PS-4000", "SN-00714"} {
		if !strings.Contains(string(id), want) {
			t.Errorf("the server identity does not carry %q: %q", want, id)
		}
	}
	// 43/14, the encapsulated device identification: objects 0, 1 and 2
	// are the vendor, the product and the revision, which is what every
	// scanner asks for.
	obj := askRaw(t, m, 1, []byte{43, 14, 1, 0})
	for _, want := range []string{"Plant Systems AB", "PS-4000", "R3.1", "SN-00714"} {
		if !strings.Contains(string(obj), want) {
			t.Errorf("the device identification does not carry %q: %q", want, obj)
		}
	}
	// And it is stable: an inventory that read it twice would otherwise
	// have two devices.
	if again := askRaw(t, m, 1, []byte{43, 14, 1, 0}); string(again) != string(obj) {
		t.Error("the identity changed between two reads")
	}
}

// mode answer is the sharp one, and this is the rule that keeps it safe:
// a frame on its way to a real device is never answered from here.
func TestAnswerModeReplacesRefusalsAndNothingElse(t *testing.T) {
	dev := startPLC(t, &plc{framing: wire.FramingTCP})
	dev.regs[100], dev.regs[101] = 0x1234, 0x5678
	s, addr := modbusServer(t, `        upstream: plc
        read_only: true
        default_action: allow
        deception:
          mode: answer
          clients: ["127.0.0.0/8"]
          units: ["1-2"]`, map[string]*plc{"plc": dev})

	m := dialMaster(t, addr, wire.FramingTCP)
	// The allowed read comes from the device. This is the assertion the
	// whole feature has to keep: the values an operator sees are the
	// plant's.
	p, err := m.ask(1, readTwo)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(p.Registers) != 2 || p.Registers[0] != 0x1234 || p.Registers[1] != 0x5678 {
		t.Fatalf("the device's own registers did not come back: %+v", p.Registers)
	}
	// The refused write is answered as though it landed, and did not.
	w, err := m.ask(1, setPoint)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if w.IsException {
		t.Fatalf("the refused write answered an exception, so the refusal is still an oracle: %+v", w)
	}
	if _, ok := dev.saw(wire.FCWriteSingleRegister); ok {
		t.Fatal("the write reached the device")
	}
	if got := dev.regs[400]; got != 0 {
		t.Fatalf("the device's register moved: %d", got)
	}
	sn := s.Stats()
	if sn.ModbusDenied == 0 {
		t.Error("the refusal was not counted as a refusal; the audit trail has to stay honest")
	}
	if sn.ModbusDeceived != 1 {
		t.Errorf("deceived %d, want 1", sn.ModbusDeceived)
	}
}

// A client the section does not name gets the ordinary refusal, which is
// what keeps a plant's own master out of the fabrication.
func TestAClientOutsideTheListIsRefusedNormally(t *testing.T) {
	dev := startPLC(t, &plc{framing: wire.FramingTCP})
	_, addr := modbusServer(t, `        upstream: plc
        read_only: true
        default_action: allow
        deception:
          mode: answer
          clients: ["10.9.9.0/24"]`, map[string]*plc{"plc": dev})

	m := dialMaster(t, addr, wire.FramingTCP)
	p, err := m.ask(1, setPoint)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if !p.IsException || p.Exception != wire.ExIllegalFunction {
		t.Errorf("a client outside the list got %+v, want the ordinary exception", p)
	}
}

// A tripwire address is answered and raised. The answer is what keeps the
// visitor reading; the event is what an operator acts on.
func TestATripwireIsAnsweredAndRaised(t *testing.T) {
	s, addr := modbusServer(t, `        default_action: allow
        deception:
          mode: decoy
          tripwire: ["9000-9099"]`, nil)

	m := dialMaster(t, addr, wire.FramingTCP)
	if p, err := m.ask(1, []byte{3, 0x23, 0x28, 0x00, 0x02}); err != nil || p.IsException {
		t.Fatalf("the tripwire read was not answered: %+v %v", p, err)
	}
	if got := s.Stats().ModbusTripwire; got != 1 {
		t.Errorf("tripwire counter %d, want 1", got)
	}
	st := s.DeviceDecoys()
	if len(st) != 1 || st[0].Tripped != 1 {
		t.Fatalf("the status view says %+v", st)
	}
	if len(st[0].Visitors) != 1 || st[0].Visitors[0].Tripped != 1 {
		t.Errorf("the visitor does not carry the trip: %+v", st[0].Visitors)
	}
	// An ordinary read is not a trip.
	if _, err := m.ask(1, readTwo); err != nil {
		t.Fatal(err)
	}
	if got := s.Stats().ModbusTripwire; got != 1 {
		t.Errorf("an ordinary read tripped the wire: %d", got)
	}
}

// The status view is sorted by listener, so two reads of it differ only
// where something happened.
func TestTheDecoyStatusIsStable(t *testing.T) {
	s, _ := modbusServer(t, `        default_action: allow
        deception: {mode: decoy}`, nil)
	first, second := s.DeviceDecoys(), s.DeviceDecoys()
	if len(first) != 1 || len(second) != 1 || first[0].Listener != second[0].Listener {
		t.Errorf("%+v then %+v", first, second)
	}
	if first[0].Profile != "generic-plc" {
		t.Errorf("profile %q, want the default named", first[0].Profile)
	}
	if !first[0].Anyone {
		t.Error("a decoy with no client list does not say it answers anybody")
	}
}

// A listener with no deception section does not appear in the view at all.
func TestAListenerWithoutDeceptionIsNotInTheView(t *testing.T) {
	dev := startPLC(t, &plc{framing: wire.FramingTCP})
	s, _ := modbusServer(t, `        upstream: plc
        default_action: allow`, map[string]*plc{"plc": dev})
	if st := s.DeviceDecoys(); len(st) != 0 {
		t.Errorf("the view lists %+v", st)
	}
	var _ proxy.Decoy // the interface is optional, and this kind implements it
}

// askRaw sends one request and returns the answer's PDU as it arrived.
// The identity answers are strings inside a response body, so the test
// reads the bytes rather than the parse.
func askRaw(t *testing.T, m *master, unit byte, pdu []byte) []byte {
	t.Helper()
	m.txn++
	_ = m.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := m.conn.Write(wire.Encode(m.framing, &wire.Frame{
		Transaction: m.txn, Unit: unit, PDU: pdu})); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = m.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	m.rd.Expect(pdu[0])
	f, _, err := m.rd.ReadFrame()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return f.PDU
}

// The function list narrows what the fabricated device implements below
// what this package can build, which is how a decoy claims to be a meter
// rather than a controller: a device that answers coil reads is not a
// meter, and answering them would be the tell.
func TestTheFunctionListNarrowsTheDevice(t *testing.T) {
	_, addr := modbusServer(t, `        default_action: allow
        deception:
          mode: decoy
          functions: [read_holding_registers, report_server_id]`, nil)

	m := dialMaster(t, addr, wire.FramingTCP)
	if p, err := m.ask(1, readTwo); err != nil || p.IsException {
		t.Fatalf("the register read was not answered: %+v %v", p, err)
	}
	for _, tc := range []struct {
		what string
		pdu  []byte
	}{
		{"read coils", readCoils},
		{"read input registers", []byte{4, 0x00, 0x00, 0x00, 0x02}},
		{"write single register", setPoint},
	} {
		p, err := m.ask(1, tc.pdu)
		if err != nil {
			t.Fatalf("%s: %v", tc.what, err)
		}
		if !p.IsException || p.Exception != wire.ExIllegalFunction {
			t.Errorf("%s answered %+v; the section did not list it, so the device does not implement it",
				tc.what, p)
		}
	}
}

// With no serial configured the device still has one, and it is the same
// one every time: an inventory that read it twice would otherwise have
// two devices, and a serial that changes on restart is the tell.
func TestADecoyHasASerialEvenWhenNobodyGaveItOne(t *testing.T) {
	_, addr := modbusServer(t, `        default_action: allow
        deception: {mode: decoy, product: "PX-9"}`, nil)
	m := dialMaster(t, addr, wire.FramingTCP)
	first := string(askRaw(t, m, 1, serverID))
	if !strings.Contains(first, "PX-9") {
		t.Fatalf("the identity does not carry the product: %q", first)
	}
	digits := 0
	for _, r := range first {
		if r >= '0' && r <= '9' {
			digits++
		}
	}
	if digits < 8 {
		t.Errorf("the identity carries no serial number: %q", first)
	}
	if again := string(askRaw(t, m, 1, serverID)); again != first {
		t.Errorf("the identity changed between reads: %q then %q", first, again)
	}
	// And the device identification carries it as object 6, which is
	// where an inventory looks.
	if obj := askRaw(t, m, 1, []byte{43, 14, 1, 0}); !strings.Contains(string(obj), "PX-9") {
		t.Errorf("the device identification does not carry the product: %q", obj)
	}
}

// The answer that actually maps an estate is the one for a unit
// identifier nothing is behind. On a forward listener with one route,
// every other unit says 0x0a and the sweep is a survey; with deception it
// answers as a device instead.
func TestAnUnroutedUnitIsFabricated(t *testing.T) {
	dev := startPLC(t, &plc{framing: wire.FramingTCP})
	dev.regs[100] = 0x1234
	s, addr := modbusServer(t, `        mode: forward
        default_action: allow
        routes:
          - {name: line1, units: ["1"], upstream: plc}
        deception:
          mode: answer
          clients: ["127.0.0.0/8"]
          units: ["1-32"]`, map[string]*plc{"plc": dev})

	m := dialMaster(t, addr, wire.FramingTCP)
	// The routed unit is the device's own answer.
	p, err := m.ask(1, readTwo)
	if err != nil {
		t.Fatalf("unit 1: %v", err)
	}
	if len(p.Registers) == 0 || p.Registers[0] != 0x1234 {
		t.Fatalf("the device's own register did not come back: %+v", p.Registers)
	}
	// Every other unit answers as a device rather than as a gap in the
	// map. That is the whole point: the sweep completes and is wrong.
	for _, unit := range []byte{2, 7, 32} {
		p, err := m.ask(unit, readTwo)
		if err != nil {
			t.Fatalf("unit %d: %v", unit, err)
		}
		if p.IsException {
			t.Errorf("unit %d answered %+v, so the sweep still finds the edge of the estate", unit, p)
		}
		if len(p.Registers) != 2 {
			t.Errorf("unit %d answered %d registers", unit, len(p.Registers))
		}
	}
	// A unit outside what the decoy claims is still a gap, because a
	// gateway with 247 devices on it is not a gateway.
	if p, err := m.ask(200, readTwo); err != nil || !p.IsException {
		t.Errorf("unit 200: %+v %v, want an exception", p, err)
	}
	if got := s.Stats().ModbusDeceived; got != 3 {
		t.Errorf("deceived %d, want 3", got)
	}
}

// The validator refuses a profile name this package would not know, so the
// two lists have to be the same list. A profile in one and not the other
// is either a name that fails at load for no reason or one that loads and
// then does nothing.
func TestTheProfileNamesMatchTheValidator(t *testing.T) {
	kind := map[string]bool{}
	for _, n := range modbus.ProfileNames() {
		kind[n] = true
	}
	for _, n := range config.ModbusDecoyProfiles {
		if !kind[n] {
			t.Errorf("the validator accepts %q and this package does not have it", n)
		}
		delete(kind, n)
	}
	for n := range kind {
		t.Errorf("this package has %q and the validator would refuse it", n)
	}
	// And every one of them loads, which is the round trip.
	for _, n := range config.ModbusDecoyProfiles {
		if _, addr := modbusServer(t, "        default_action: allow\n"+
			"        deception: {mode: decoy, profile: "+n+"}", nil); addr == "" {
			t.Errorf("profile %q did not start", n)
		}
	}
}

// The tripwire feeds the ban ladder, which is the difference between it and an
// ordinary fabricated exchange: a client that read an address nothing legitimate
// reads has said something every other listener would want to act on, while
// banning the exchange itself would end the collection.
func TestATrippedFabricationReachesTheBanLadder(t *testing.T) {
	s := proxytest.Start(t, `
version: 1
server:
  listeners:
    - name: plant
      address: "127.0.0.1:0"
      kind: modbus
      modbus:
        default_action: allow
        deception:
          mode: decoy
          tripwire: ["9000-9099"]
logging: {access: {enabled: false}}
bans:
  action: reject
  triggers: [{name: traps, reasons: [modbus_tripwire], threshold: 1, window: 1m, duration: 1h}]
`)
	addr := proxytest.Addr(t, s, "plant")
	m := dialMaster(t, addr, wire.FramingTCP)
	if p, err := m.ask(1, []byte{3, 0x23, 0x28, 0x00, 0x02}); err != nil || p.IsException {
		t.Fatalf("the tripwire read was not answered: %+v %v", p, err)
	}
	awaitModbus(t, s, func(sn proxy.Snapshot) bool { return sn.BansActive >= 1 },
		"the tripwire did not reach the ban ladder")

	// An ordinary fabricated read does not: a second listener in the same
	// estate must not ban a client for having been answered.
	s2 := proxytest.Start(t, `
version: 1
server:
  listeners:
    - name: plant
      address: "127.0.0.1:0"
      kind: modbus
      modbus:
        default_action: allow
        deception: {mode: decoy}
logging: {access: {enabled: false}}
bans:
  action: reject
  triggers: [{name: traps, reasons: [modbus_tripwire], threshold: 1, window: 1m, duration: 1h}]
`)
	m2 := dialMaster(t, proxytest.Addr(t, s2, "plant"), wire.FramingTCP)
	if _, err := m2.ask(1, readTwo); err != nil {
		t.Fatal(err)
	}
	if n := s2.Stats().BansActive; n != 0 {
		t.Errorf("an ordinary fabricated exchange banned the client: %d", n)
	}
}

// awaitModbus polls a counter condition, because a ban is applied on the
// relay's own goroutine after the frame has gone out.
func awaitModbus(t *testing.T, s *proxy.Server, ok func(proxy.Snapshot) bool, what string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if ok(s.Stats()) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s: the counters never said so", what)
}
