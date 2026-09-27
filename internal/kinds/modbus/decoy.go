package modbus

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/deception"
	wire "github.com/rom/xproxy/internal/modbus"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/numrange"
	"github.com/rom/xproxy/internal/proxy"
)

// A device that is not there.
//
// See internal/deception for why this exists and for the rule that keeps
// it safe in a plant: a frame the policy allowed is never deceived. What
// is here is the Modbus half -- which function codes the fabricated device
// implements, what it says about itself, and how it answers each one.
//
// The answers are built from the specification rather than from a
// recording, because a scanner checks them against the specification: a
// read of two registers answers three plus four bytes with the byte count
// in front of them, a write echoes the request, and a function code the
// device does not implement answers exception 1. That last one is the
// point of the profile. A decoy that implements every function code in the
// standard is answering for a PLC nobody makes, and the completeness is
// what gives it away.

// profile is a fabricated device's shape.
type profile struct {
	// vendor, product, revision are what the device says about itself.
	vendor, product, revision string
	// functions are the codes it implements.
	functions []byte
	// bands are how its address space behaves.
	bands []deception.Band
}

// The built-in profiles. The identity strings are deliberately generic:
// the make a decoy should claim is the make the plant runs, which only the
// operator knows, so the section takes vendor, product and revision and
// these are what it looks like when nobody has said.
var profiles = map[string]profile{
	// generic-plc is a small programmable controller: coils and holding
	// registers, no file records, no diagnostics beyond the ones every
	// device answers.
	"generic-plc": {
		vendor: "Industrial Controls", product: "PLC-1200", revision: "V1.4.2",
		functions: []byte{
			wire.FCReadCoils, wire.FCReadDiscreteInputs, wire.FCReadHoldingRegisters,
			wire.FCReadInputRegisters, wire.FCWriteSingleCoil, wire.FCWriteSingleRegister,
			wire.FCWriteMultipleCoils, wire.FCWriteMultipleRegisters,
			wire.FCReadExceptionStatus, wire.FCReportServerID, wire.FCEncapsulatedInterface,
		},
		bands: []deception.Band{
			{Lo: 0, Hi: 999, Shape: deception.ShapeAnalogue, Min: 0, Max: 27648},
			{Lo: 1000, Hi: 1999, Shape: deception.ShapeDiscrete},
			{Lo: 2000, Hi: 2999, Shape: deception.ShapeCounter, Rate: 3},
			{Lo: 3000, Hi: 65535, Shape: deception.ShapeAnalogue, Min: 0, Max: 4095},
		},
	},
	// generic-rtu is a remote terminal unit at the end of a serial link:
	// reads, one writable register block, and the communications counters
	// a serial device keeps.
	"generic-rtu": {
		vendor: "Remote Telemetry", product: "RTU-32", revision: "2.1",
		functions: []byte{
			wire.FCReadCoils, wire.FCReadDiscreteInputs, wire.FCReadHoldingRegisters,
			wire.FCReadInputRegisters, wire.FCWriteSingleRegister, wire.FCWriteMultipleRegisters,
			wire.FCReadExceptionStatus, wire.FCDiagnostic, wire.FCGetCommEventCounter,
			wire.FCReportServerID,
		},
		bands: []deception.Band{
			{Lo: 0, Hi: 255, Shape: deception.ShapeAnalogue, Min: 0, Max: 4095},
			{Lo: 256, Hi: 511, Shape: deception.ShapeDiscrete},
			{Lo: 512, Hi: 65535, Shape: deception.ShapeAnalogue, Min: 0, Max: 1023},
		},
	},
	// generic-meter is an energy meter: almost everything is a totaliser
	// that only increases, and almost nothing is writable.
	"generic-meter": {
		vendor: "Metering Systems", product: "EM-3P", revision: "4.07",
		functions: []byte{
			wire.FCReadHoldingRegisters, wire.FCReadInputRegisters,
			wire.FCReportServerID, wire.FCEncapsulatedInterface,
		},
		bands: []deception.Band{
			{Lo: 0, Hi: 99, Shape: deception.ShapeAnalogue, Min: 21000, Max: 24500},
			{Lo: 100, Hi: 299, Shape: deception.ShapeCounter, Rate: 7},
			{Lo: 300, Hi: 65535, Shape: deception.ShapeCounter, Rate: 1},
		},
	},
}

// DefaultProfile is the profile a section that names none gets.
const DefaultProfile = "generic-plc"

// ProfileNames are the profiles validation accepts. It is here rather
// than in the configuration package so that adding one does not mean
// editing two files.
func ProfileNames() []string {
	out := make([]string, 0, len(profiles))
	for name := range profiles {
		out = append(out, name)
	}
	return out
}

// decoy is a compiled deception section.
type decoy struct {
	policy *deception.Policy
	values *deception.Values
	// whole says the listener is a honeypot: every frame is answered here
	// and nothing is dialled.
	whole bool
	// units the fabricated device answers for. A frame for any other unit
	// is answered the way a gateway answers a unit nothing is behind,
	// because a device on all 247 unit identifiers is not a device.
	units numrange.Set
	// functions it implements; everything else is an illegal function,
	// which is what the real device would say.
	functions map[byte]bool
	// tripwire addresses nobody has a reason to touch.
	tripwire numrange.Set

	vendor, product, revision, serial string
}

// newDecoy compiles the section. name seeds the fabricated values when
// the section names no seed, so the same listener is the same device
// after a restart.
func newDecoy(c *config.ModbusDeception, name string) (*decoy, error) {
	if c == nil || (c.Enabled != nil && !*c.Enabled) {
		return nil, nil
	}
	p, ok := profiles[c.Profile]
	if !ok {
		if c.Profile != "" {
			return nil, fmt.Errorf("deception.profile: %q is not a profile", c.Profile)
		}
		p = profiles[DefaultProfile]
	}
	d := &decoy{
		whole:    c.Mode == "decoy",
		vendor:   or(c.Vendor, p.vendor),
		product:  or(c.Product, p.product),
		revision: or(c.Revision, p.revision),
		serial:   c.Serial,
	}
	units := c.Units
	if len(units) == 0 {
		units = []string{"1"}
	}
	var err error
	if d.units, err = numrange.Parse("deception.units", units, 255); err != nil {
		return nil, err
	}
	if len(c.Tripwire) > 0 {
		if d.tripwire, err = numrange.Parse("deception.tripwire", c.Tripwire, 65535); err != nil {
			return nil, err
		}
	}
	if d.functions, err = decoyFunctions(c.Functions, p.functions); err != nil {
		return nil, err
	}
	bands, err := decoyBands(c.Bands, p.bands)
	if err != nil {
		return nil, err
	}
	seed := c.Seed
	if seed == 0 {
		seed = deception.SeedFor(name)
	}
	if d.serial == "" {
		// A serial number is what an inventory writes down, so the decoy
		// needs one and it has to be the same one every time.
		d.serial = fmt.Sprintf("%010d", seed%10_000_000_000)
	}
	d.values = deception.NewValues(seed, c.Period.D(), bands)
	d.policy = deception.NewPolicy(netutil.ParsePrefixes(c.Clients), c.MaxClients)
	return d, nil
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// decoyFunctions compiles the function list, by name or number.
func decoyFunctions(named []string, fallback []byte) (map[byte]bool, error) {
	out := map[byte]bool{}
	if len(named) == 0 {
		for _, fc := range fallback {
			out[fc] = true
		}
		return out, nil
	}
	for _, s := range named {
		s = strings.TrimSpace(s)
		if fc, ok := wire.FunctionCode(strings.ToLower(s)); ok {
			out[fc] = true
			continue
		}
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > 127 {
			return nil, fmt.Errorf("deception.functions: %q is not a function code", s)
		}
		out[byte(n)] = true
	}
	return out, nil
}

// decoyBands compiles the address bands.
func decoyBands(in []config.ModbusDecoyBand, fallback []deception.Band) ([]deception.Band, error) {
	if len(in) == 0 {
		return fallback, nil
	}
	out := make([]deception.Band, 0, len(in))
	for i := range in {
		b := &in[i]
		set, err := numrange.Parse("deception.bands.addresses", []string{b.Addresses}, 65535)
		if err != nil {
			return nil, err
		}
		if len(set) != 1 {
			return nil, fmt.Errorf("deception.bands.addresses: %q is not one range", b.Addresses)
		}
		shape := deception.Shape(b.Shape)
		switch shape {
		case deception.ShapeAnalogue, deception.ShapeDiscrete, deception.ShapeCounter:
		case "":
			shape = deception.ShapeAnalogue
		default:
			return nil, fmt.Errorf("deception.bands.shape: %q is not analogue, discrete or counter", b.Shape)
		}
		out = append(out, deception.Band{
			Lo: set[0].Lo, Hi: set[0].Hi, Shape: shape,
			Min: b.Min, Max: b.Max, Rate: b.Rate,
		})
	}
	return out, nil
}

// admits reports whether this client is lied to.
func (d *decoy) admits(ip netip.Addr) bool { return d != nil && d.policy.Admits(ip) }

// tripped reports whether a request touched something no legitimate
// master has a reason to touch.
func (d *decoy) tripped(pdu *wire.PDU) bool {
	if d == nil || len(d.tripwire) == 0 || !pdu.HasRange {
		return false
	}
	last, ok := pdu.Last()
	if !ok {
		return false
	}
	for addr := int(pdu.Address); addr <= int(last); addr++ {
		if d.tripwire.Has(addr) {
			return true
		}
	}
	return false
}

// answer builds the fabricated device's response, or says the device does
// not implement this function code -- in which case the caller answers the
// illegal-function exception the real device would have answered.
func (d *decoy) answer(unit byte, pdu *wire.PDU) ([]byte, bool) {
	if d == nil {
		return nil, false
	}
	if !d.units.Has(int(unit)) || !d.functions[pdu.Function] {
		return nil, false
	}
	fc := pdu.Function
	switch fc {
	case wire.FCReadCoils, wire.FCReadDiscreteInputs:
		return d.bits(unit, pdu), true
	case wire.FCReadHoldingRegisters, wire.FCReadInputRegisters:
		return d.registers(fc, unit, pdu.Address, pdu.Quantity), true
	case wire.FCWriteSingleCoil, wire.FCWriteSingleRegister:
		// A single write is answered by echoing it, which is what says
		// the value landed. Nothing landed: this is the whole point of
		// the mode, and the frame reached no device.
		return echo(fc, pdu), true
	case wire.FCWriteMultipleCoils, wire.FCWriteMultipleRegisters:
		return header4(fc, pdu.Address, pdu.Quantity), true
	case wire.FCMaskWriteRegister:
		return echoMask(pdu), true
	case wire.FCReadWriteMultiple:
		// The read half is answered and the write half is not performed,
		// which from outside is a device that did both.
		return d.registers(fc, unit, pdu.Address, pdu.Quantity), true
	case wire.FCReadExceptionStatus:
		// Eight bits of vendor-defined status. A device with no alarms
		// answers zero, and a device with every bit set is a device on
		// fire; one bit is a device that has been running a while.
		var status byte
		if d.values.Bit(unit, 0xE5) {
			status = 0x01
		}
		return []byte{fc, status}, true
	case wire.FCDiagnostic:
		// Echo the sub-function and its data, which is what the loopback
		// diagnostic is defined to do and what the others look like from
		// outside.
		out := []byte{fc, byte(pdu.SubFunction >> 8), byte(pdu.SubFunction)}
		return append(out, registerBytes(pdu.Registers)...), true
	case wire.FCGetCommEventCounter:
		// Status zero (not busy) and a counter that only increases.
		n := d.values.Register(unit, 0xF1)
		return []byte{fc, 0, 0, byte(n >> 8), byte(n)}, true
	case wire.FCReportServerID:
		return d.serverID(fc), true
	case wire.FCEncapsulatedInterface:
		if pdu.SubFunction != 0x0E {
			// MEI 13 is the CANopen request, which nothing here pretends
			// to be.
			return nil, false
		}
		return d.identification(fc, pdu), true
	}
	return nil, false
}

// bits answers a coil or discrete input read.
func (d *decoy) bits(unit byte, pdu *wire.PDU) []byte {
	n := int(pdu.Quantity)
	out := make([]byte, 2+(n+7)/8)
	out[0] = pdu.Function
	out[1] = byte((n + 7) / 8)
	for i := range n {
		if d.values.Bit(unit, int(pdu.Address)+i) {
			out[2+i/8] |= 1 << (i % 8)
		}
	}
	return out
}

// registers answers a register read, echoing the function code that was
// asked: holding registers, input registers and the read half of a
// read/write all answer in this shape.
func (d *decoy) registers(fc byte, unit byte, addr, quantity uint16) []byte {
	n := int(quantity)
	out := make([]byte, 0, 2+2*n)
	out = append(out, fc, byte(2*n))
	for i := range n {
		v := d.values.Register(unit, int(addr)+i)
		out = append(out, byte(v>>8), byte(v))
	}
	return out
}

// echo answers a single write by repeating it.
func echo(fc byte, pdu *wire.PDU) []byte {
	var v uint16
	switch {
	case len(pdu.Registers) > 0:
		v = pdu.Registers[0]
	case len(pdu.Coils) > 0 && pdu.Coils[0]:
		v = 0xFF00
	}
	return []byte{fc, byte(pdu.Address >> 8), byte(pdu.Address), byte(v >> 8), byte(v)}
}

// echoMask answers a mask write by repeating its two masks.
func echoMask(pdu *wire.PDU) []byte {
	out := []byte{wire.FCMaskWriteRegister, byte(pdu.Address >> 8), byte(pdu.Address)}
	return append(out, registerBytes(pdu.Registers)...)
}

// header4 is the address-and-quantity answer a multiple write gets.
func header4(fc byte, addr, quantity uint16) []byte {
	return []byte{fc, byte(addr >> 8), byte(addr), byte(quantity >> 8), byte(quantity)}
}

func registerBytes(regs []uint16) []byte {
	out := make([]byte, 0, 2*len(regs))
	for _, r := range regs {
		out = append(out, byte(r>>8), byte(r))
	}
	return out
}

// serverID answers function code 17: the identity a scanner reads first.
func (d *decoy) serverID(fc byte) []byte {
	id := d.product
	if d.serial != "" {
		id += " " + d.serial
	}
	body := append([]byte(id), 0xFF) // 0xFF: running
	out := []byte{fc, byte(len(body))}
	return append(out, body...)
}

// identification answers 43/14, the encapsulated device identification.
//
// The object layout is the specification's: a conformity level, a "more
// follows" octet, the next object identifier, the object count, then each
// object as identifier, length and value. Basic identification is objects
// 0 to 2, which is what every scanner asks for and what most devices
// implement.
func (d *decoy) identification(fc byte, pdu *wire.PDU) []byte {
	objects := [][2]any{{byte(0x00), d.vendor}, {byte(0x01), d.product}, {byte(0x02), d.revision}}
	if d.serial != "" {
		// Object 0x06 is the serial number in the regular stream, which
		// is where an inventory looks for one.
		objects = append(objects, [2]any{byte(0x06), d.serial})
	}
	out := []byte{fc, 0x0E, byte(pdu.Address & 0xFF), 0x81, 0x00, 0x00, byte(len(objects))}
	for _, o := range objects {
		id := o[0].(byte)
		v := o[1].(string)
		if len(v) > 255 {
			v = v[:255]
		}
		out = append(out, id, byte(len(v)))
		out = append(out, v...)
	}
	return out
}

// deceive answers one frame as the fabricated device, and reports whether
// it did.
//
// It is called only where the frame was not going to reach a device: a
// refusal, a unit identifier nothing is behind, or a listener that is
// nothing but a decoy. That is the invariant the whole feature rests on
// -- a frame on its way to a real PLC is never answered from here -- and
// it is a test rather than a comment.
func (se *session) deceive(frame *wire.Frame, pdu *wire.PDU, why string) bool {
	t := se.t
	d := t.decoy
	if d == nil || !d.admits(se.ip) {
		return false
	}
	body, ok := d.answer(frame.Unit, pdu)
	if !ok {
		return false
	}
	tripped := d.tripped(pdu)
	d.policy.Record(se.ip, tripped, time.Now())
	t.host.Counters().ModbusDeceived.Add(1)
	if tripped {
		t.host.Counters().ModbusTripwire.Add(1)
	}
	// Loud on the inside. This is the one answer that looks like success,
	// so the operator has to be able to see it happening -- and a
	// tripwire is the event worth waking somebody for, because nothing
	// legitimate reads those addresses.
	attrs := []any{
		"listener", t.cfg.Name, "client_ip", se.ip.String(), "unit", int(frame.Unit),
		"function", wire.FunctionName(pdu.Function), "reason", why,
		"mode", modeName(d.whole),
	}
	if pdu.HasRange {
		attrs = append(attrs, "address", int(pdu.Address), "quantity", int(pdu.Quantity))
	}
	event := "modbus_deceived"
	if tripped {
		event = "modbus_tripwire"
	}
	t.host.Logs().SecurityEvent(context.Background(), "deceive", event, attrs...)
	se.send(wire.Encode(t.framing, &wire.Frame{
		Transaction: frame.Transaction, Unit: frame.Unit, PDU: body}))
	return true
}

func modeName(whole bool) string {
	if whole {
		return "decoy"
	}
	return "answer"
}

// DecoyStatus is what this listener's decoy has seen, for the status view.
func (t *server) DecoyStatus() (proxy.DecoyStatus, bool) {
	d := t.decoy
	if d == nil {
		return proxy.DecoyStatus{}, false
	}
	st := proxy.DecoyStatus{
		Listener: t.cfg.Name, Kind: "modbus", Mode: modeName(d.whole),
		Profile: t.m.Deception.Profile, Served: d.policy.Served(),
		Tripped: d.policy.Tripped(), Anyone: d.policy.Anyone(),
	}
	if st.Profile == "" {
		st.Profile = DefaultProfile
	}
	for _, c := range d.policy.Clients(32) {
		st.Visitors = append(st.Visitors, proxy.DecoyVisitor{
			ClientIP: c.Addr.String(), FirstSeen: c.FirstSeen, LastSeen: c.LastSeen,
			Frames: c.Frames, Tripped: c.Tripped,
		})
	}
	return st, true
}
