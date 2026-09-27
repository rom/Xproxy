package s7

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/deception"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/numrange"
	"github.com/rom/xproxy/internal/proxy"
	wire "github.com/rom/xproxy/internal/s7"
)

// A controller that is not there.
//
// See internal/deception for why, and for the rule that keeps it safe on a
// plant: a request that was going to reach the controller is never answered
// by the fabrication. What is here is the S7comm half -- the connection, the
// negotiation, what a read of a data block is answered with, and what the
// system status list says the CPU is.
//
// The last of those is the one a scanner reads first. Nmap's s7-info, PLCScan
// and every asset-discovery tool built on Snap7 ask for two system status
// lists and print what comes back: the order number, the module type, the
// firmware and the plant designation. A relay that refused them told the
// scanner it was a relay; one that forwarded them told it what the controller
// is. This answers as a controller instead.

// plcProfile is a fabricated controller's identity and shape.
type plcProfile struct {
	order   string
	module  string
	version string
	pduLen  int
	blocks  []blockRun
	bands   []deception.Band
}

// blockRun is a run of data block numbers the fabrication has.
type blockRun struct {
	lo, hi int
	bytes  int
}

// The built-in profiles, both classic S7comm families.
//
// An S7-1200 or S7-1500 speaks S7comm-plus, so a decoy answering classic
// S7comm while claiming to be a 1500 is a contradiction a scanner sees in one
// exchange. The identities here are deliberately ordinary: a plant should
// replace them with the make it actually runs.
var plcProfiles = map[string]plcProfile{
	"generic-s7-300": {
		order: "6ES7 315-2EH14-0AB0", module: "CPU 315-2 PN/DP",
		version: "3.2.7", pduLen: 240,
		blocks: []blockRun{{lo: 1, hi: 8, bytes: 512}, {lo: 100, hi: 104, bytes: 1024}},
		bands: []deception.Band{
			{Lo: 0, Hi: 199, Shape: deception.ShapeAnalogue, Min: 0, Max: 27648},
			{Lo: 200, Hi: 299, Shape: deception.ShapeDiscrete},
			{Lo: 300, Hi: 399, Shape: deception.ShapeCounter, Rate: 7},
		},
	},
	"generic-s7-400": {
		order: "6ES7 416-3FS07-0AB0", module: "CPU 416F-3 PN/DP",
		version: "7.0.3", pduLen: 480,
		blocks: []blockRun{{lo: 1, hi: 32, bytes: 2048}, {lo: 200, hi: 216, bytes: 4096}},
		bands: []deception.Band{
			{Lo: 0, Hi: 499, Shape: deception.ShapeAnalogue, Min: 0, Max: 27648},
			{Lo: 500, Hi: 699, Shape: deception.ShapeDiscrete},
			{Lo: 700, Hi: 999, Shape: deception.ShapeCounter, Rate: 13},
		},
	},
}

// DefaultProfile is the profile a section that names none gets.
const DefaultProfile = "generic-s7-300"

// ProfileNames are the profiles this package has, for the test that keeps
// them in step with what the validator accepts.
func ProfileNames() []string {
	out := make([]string, 0, len(plcProfiles))
	for name := range plcProfiles {
		out = append(out, name)
	}
	return out
}

// DecoyShapes are the band shapes a block's bytes may take.
var DecoyShapes = []string{
	string(deception.ShapeAnalogue), string(deception.ShapeDiscrete), string(deception.ShapeCounter),
}

// decoy is a compiled deception section.
type decoy struct {
	policy *deception.Policy
	values *deception.Values
	// whole says the listener is a honeypot: nothing is dialled and every
	// frame is answered here.
	whole  bool
	blocks []blockRun
	// tripwire is the data block numbers nobody has a reason to read.
	tripwire numrange.Set
	profile  string
	// The identity, which is what a scanner reads.
	order, module, plant, serial, version string
	pduLen                                int
}

func newDecoy(c *config.S7Deception, name string) (*decoy, error) {
	if c == nil || (c.Enabled != nil && !*c.Enabled) {
		return nil, nil
	}
	p, ok := plcProfiles[c.Profile]
	if !ok {
		if c.Profile != "" {
			return nil, fmt.Errorf("deception.profile: %q is not a profile", c.Profile)
		}
		p = plcProfiles[DefaultProfile]
	}
	d := &decoy{
		whole:   c.Mode == "decoy",
		profile: c.Profile,
		order:   or(c.OrderNumber, p.order),
		module:  or(c.ModuleType, p.module),
		version: or(c.Version, p.version),
		plant:   c.Plant,
		pduLen:  p.pduLen,
	}
	if d.profile == "" {
		d.profile = DefaultProfile
	}
	if c.PDULength != 0 {
		d.pduLen = c.PDULength
	}
	var err error
	if len(c.Tripwire) > 0 {
		if d.tripwire, err = numrange.Parse("deception.tripwire", c.Tripwire, 65535); err != nil {
			return nil, err
		}
	}
	if d.blocks, err = decoyBlocks(c.Blocks, p.blocks); err != nil {
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
	period := c.Period.D()
	if period <= 0 {
		period = deception.DefaultPeriod
	}
	d.values = deception.NewValues(seed, period, bands)
	d.policy = deception.NewPolicy(netutil.ParsePrefixes(c.Clients), c.MaxClients)
	// A serial nobody chose is derived from the seed, so the controller has
	// one and keeps the same one across a restart: a CPU whose serial
	// number changes when the proxy is upgraded is a CPU somebody has
	// noticed.
	d.serial = c.Serial
	if d.serial == "" {
		d.serial = fmt.Sprintf("S C-%09d", seed%1_000_000_000)
	}
	return d, nil
}

// or is the first of two strings that is not empty.
func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// decoyBlocks compiles the data block runs.
func decoyBlocks(in []config.S7DecoyBlocks, fallback []blockRun) ([]blockRun, error) {
	if len(in) == 0 {
		return fallback, nil
	}
	out := make([]blockRun, 0, len(in))
	for i, b := range in {
		set, err := numrange.Parse(fmt.Sprintf("deception.blocks[%d].dbs", i), []string{b.DBs}, 65535)
		if err != nil {
			return nil, err
		}
		size := b.Bytes
		if size <= 0 {
			size = 512
		}
		for _, r := range set {
			out = append(out, blockRun{lo: r.Lo, hi: r.Hi, bytes: size})
		}
	}
	return out, nil
}

// decoyBands compiles the byte-address bands inside a block.
func decoyBands(in []config.S7DecoyBand, fallback []deception.Band) ([]deception.Band, error) {
	if len(in) == 0 {
		return fallback, nil
	}
	out := make([]deception.Band, 0, len(in))
	for i, b := range in {
		set, err := numrange.Parse(fmt.Sprintf("deception.bands[%d].addresses", i), []string{b.Addresses}, 1<<24-1)
		if err != nil {
			return nil, err
		}
		shape := deception.Shape(b.Shape)
		if b.Shape == "" {
			shape = deception.ShapeAnalogue
		}
		for _, r := range set {
			out = append(out, deception.Band{
				Lo: r.Lo, Hi: r.Hi, Shape: shape, Min: b.Min, Max: b.Max, Rate: b.Rate,
			})
		}
	}
	return out, nil
}

// admits says whether this client gets the fabrication.
func (d *decoy) admits(ip netip.Addr) bool { return d != nil && d.policy.Admits(ip) }

// blockFor finds the run a data block number is in.
func (d *decoy) blockFor(db uint16) (blockRun, bool) {
	for _, b := range d.blocks {
		if int(db) >= b.lo && int(db) <= b.hi {
			return b, true
		}
	}
	return blockRun{}, false
}

// tripped says whether a request touched a block nobody reads.
func (d *decoy) tripped(items []wire.Item) bool {
	if len(d.tripwire) == 0 {
		return false
	}
	for _, it := range items {
		if it.Area == wire.AreaDB && d.tripwire.Has(int(it.DB)) {
			return true
		}
	}
	return false
}

// The frames the fabrication writes.
//
// Everything below builds a PDU rather than editing one, which is what
// refuse.go does for the relay's own refusals. The reason is the same: a
// fabricated answer to a request the controller never saw has no original to
// copy, so it is built from the request's own reference and function so that
// a client's library pairs it with what it asked.

// connectConfirm answers a COTP connection request the way a CPU does: the
// references swapped, the class echoed, and the two TSAPs put back.
func connectConfirm(cr *wire.COTP) []byte {
	body := make([]byte, 0, 20)
	body = append(body, 0x00, wire.COTPConnectionConfirm)
	body = binary.BigEndian.AppendUint16(body, cr.SrcRef)
	// A source reference of this end's own choosing. A CPU picks one; any
	// value but zero will do, and echoing the client's would be two ends
	// with the same reference.
	body = binary.BigEndian.AppendUint16(body, cr.SrcRef^0x0100)
	body = append(body, cr.Class)
	if cr.TPDUSize != 0 {
		body = append(body, 0xC0, 0x01, cr.TPDUSize)
	}
	if len(cr.Calling) > 0 {
		body = append(body, 0xC1, byte(len(cr.Calling)))
		body = append(body, cr.Calling...)
	}
	if len(cr.Called) > 0 {
		body = append(body, 0xC2, byte(len(cr.Called)))
		body = append(body, cr.Called...)
	}
	body[0] = byte(len(body) - 1) // the length indicator counts itself out
	return tpkt(body)
}

// ackWith assembles an acknowledgement with a parameter and a data part.
func ackWith(ref uint16, param, data []byte) []byte {
	body := make([]byte, 0, 12+len(param)+len(data))
	body = append(body, wire.ProtocolID, byte(wire.AckData), 0, 0)
	body = binary.BigEndian.AppendUint16(body, ref)
	body = binary.BigEndian.AppendUint16(body, uint16(len(param))) //nolint:gosec // a parameter of a few octets
	body = binary.BigEndian.AppendUint16(body, uint16(len(data)))  //nolint:gosec // bounded by the negotiated PDU length
	body = append(body, 0x00, 0x00)                                // no error
	body = append(body, param...)
	body = append(body, data...)
	return tpktData(body)
}

// setupAnswer answers Setup Communication with the length this fabrication
// negotiates, which is the first thing every client asks and the first
// number it remembers.
func setupAnswer(pdu *wire.PDU, pduLen int) []byte {
	param := []byte{wire.FnSetupComm, 0x00}
	param = binary.BigEndian.AppendUint16(param, 1) // max AMQ calling
	param = binary.BigEndian.AppendUint16(param, 1) // max AMQ called
	param = binary.BigEndian.AppendUint16(param, u16(pduLen))
	return ackWith(pdu.PDURef, param, nil)
}

// u16 narrows a length to the two octets that carry it on the wire -- the
// negotiated PDU length, and the declared length of a system status list.
// Both are bounded long before they get here, by configuration and by the
// records built above, so the clamp never fires; it is what makes the
// narrowing safe to read.
func u16(n int) uint16 {
	if n < 0 {
		return 0
	}
	if n > 0xFFFF {
		return 0xFFFF
	}
	return uint16(n)
}

// The return codes of a data item in an answer.
const (
	itemOK       uint8 = 0xFF
	itemNoObject uint8 = 0x0A
	itemAddress  uint8 = 0x05
)

// The transport sizes an *answer's* data item declares, which are a
// different enumeration from a request's: on these two the length field is
// counted in bits.
const (
	answerBit  uint8 = 0x03
	answerByte uint8 = 0x04
)

// readAck answers a read with fabricated values, item by item.
//
// An item naming a block the fabrication does not have is answered the way a
// CPU answers one -- object does not exist -- and one running past the end of
// a block gets an address error. Claiming every block in a 16-bit space
// exists, and every length inside it, is not a controller.
func (d *decoy) readAck(pdu *wire.PDU, items []wire.Item) []byte {
	data := make([]byte, 0, 64)
	for i, it := range items {
		body, code := d.itemValue(it)
		data = append(data, code, answerByte)
		if code != itemOK {
			// A refused item carries no value, and its length is zero.
			data = append(data, 0x00, 0x00)
			continue
		}
		if it.Transport == wire.TransportBit {
			data[len(data)-1] = answerBit
		}
		data = binary.BigEndian.AppendUint16(data, uint16(len(body)*8)) //nolint:gosec // bounded by the PDU length
		data = append(data, body...)
		// A fill octet keeps the next item on an even boundary, which is
		// what the protocol does and what a client's reader steps by. The
		// last item takes none.
		if len(body)%2 == 1 && i != len(items)-1 {
			data = append(data, 0x00)
		}
	}
	param := []byte{wire.FnReadVar, byte(min(len(items), 255))}
	return ackWith(pdu.PDURef, param, data)
}

// itemValue is the octets one item reads back, or the reason it does not.
func (d *decoy) itemValue(it wire.Item) ([]byte, uint8) {
	if !it.Address {
		// A syntax this fabrication does not answer for: an alarm
		// subscription, a symbolic 1200 address, a drive parameter.
		return nil, itemNoObject
	}
	n := it.Bytes()
	if n <= 0 {
		return nil, itemNoObject
	}
	switch it.Area {
	case wire.AreaDB, wire.AreaInstanceDB:
		b, ok := d.blockFor(it.DB)
		if !ok {
			return nil, itemNoObject
		}
		if it.Last() >= b.bytes {
			return nil, itemAddress
		}
	case wire.AreaInputs, wire.AreaOutputs, wire.AreaFlags, wire.AreaTimer, wire.AreaCounter:
	default:
		// The peripheral area and the 200-family areas are not something
		// this claims to have.
		return nil, itemNoObject
	}
	if it.Transport == wire.TransportBit {
		out := make([]byte, n)
		for k := range out {
			if d.values.Bit(byte(it.DB), it.Byte()+k) {
				out[k] = 0x01
			}
		}
		return out, itemOK
	}
	out := make([]byte, 0, n)
	for at := it.Byte(); len(out) < n; at += 2 {
		v := d.values.Register(byte(it.DB), at)
		out = append(out, byte(v>>8), byte(v))
	}
	return out[:n], itemOK
}

// answerItems is the acknowledgement for a read or a write, whichever this
// is. Both call sites use it, because an answer carrying the other one's
// function is an answer a client's library will not pair with its request.
func (d *decoy) answerItems(pdu *wire.PDU, items []wire.Item) []byte {
	if pdu.Function == wire.FnWriteVar {
		return d.writeAck(pdu, items)
	}
	return d.readAck(pdu, items)
}

// writeAck answers a write as though it landed. Nothing was written: there
// is nothing here to write to.
func (d *decoy) writeAck(pdu *wire.PDU, items []wire.Item) []byte {
	data := make([]byte, 0, len(items))
	for _, it := range items {
		_, code := d.itemValue(it)
		data = append(data, code)
	}
	param := []byte{wire.FnWriteVar, byte(min(len(items), 255))}
	return ackWith(pdu.PDURef, param, data)
}

// userAck assembles a user-data response: the same group and subfunction,
// the response method, and no error.
func userAck(pdu *wire.PDU, u *wire.UserData, data []byte) []byte {
	param := []byte{
		0x00, 0x01, 0x12,
		0x08,
		0x12,
		wire.UserResponse<<4 | u.Group,
		u.Sub,
		u.Sequence,
		0x00,       // the data unit reference
		0x00,       // no more data follows
		0x00, 0x00, // no error
	}
	body := make([]byte, 0, 10+len(param)+len(data))
	body = append(body, wire.ProtocolID, byte(wire.Userdata), 0, 0)
	body = binary.BigEndian.AppendUint16(body, pdu.PDURef)
	body = binary.BigEndian.AppendUint16(body, uint16(len(param))) //nolint:gosec // twelve octets
	body = binary.BigEndian.AppendUint16(body, uint16(len(data)))  //nolint:gosec // a few dozen octets
	body = append(body, param...)
	body = append(body, data...)
	return tpktData(body)
}

// The system status lists a scanner reads, and the only two this fabrication
// claims to have.
const (
	szlModule    = 0x0011 // module identification: the order number
	szlComponent = 0x001C // component identification: the names
)

// szlRequest reads the list identifier and index a request asks for.
func szlRequest(pdu *wire.PDU) (id, index uint16, ok bool) {
	// The data part is a return code, a transport size, a length and then
	// the two fields.
	if len(pdu.Data) < 8 {
		return 0, 0, false
	}
	return binary.BigEndian.Uint16(pdu.Data[4:6]), binary.BigEndian.Uint16(pdu.Data[6:8]), true
}

// szlAck answers a system status list request with the fabricated identity.
//
// This is the exchange every asset scanner makes, so it is the one that has
// to be right: the record length and the record count are what a client steps
// by, and a list whose length does not agree with its records is a list no
// library will read.
func (d *decoy) szlAck(pdu *wire.PDU, u *wire.UserData, id, index uint16) []byte {
	var recLen int
	var records []byte
	switch id {
	case szlModule:
		recLen = 28
		records = d.moduleRecord(1)
	case szlComponent:
		recLen = 34
		for _, r := range d.componentRecords(index) {
			records = append(records, r...)
		}
	default:
		return nil
	}
	if len(records)%recLen != 0 {
		// A record set that is not a whole number of records is a list no
		// library will read. The switch above is what makes recLen
		// non-zero, so there is nothing else to check here.
		return nil
	}
	block := make([]byte, 0, 8+len(records))
	block = binary.BigEndian.AppendUint16(block, id)
	block = binary.BigEndian.AppendUint16(block, index)
	block = binary.BigEndian.AppendUint16(block, uint16(recLen))              //nolint:gosec // a constant above
	block = binary.BigEndian.AppendUint16(block, uint16(len(records)/recLen)) //nolint:gosec // bounded by the records built here
	block = append(block, records...)

	if len(block) > 0xFFFF {
		// The length field is two octets. The lists built here are a few
		// hundred, so this cannot happen; a list that could not declare
		// its own length is not one to send.
		return nil
	}
	data := make([]byte, 0, 4+len(block))
	data = append(data, itemOK, 0x09) // an octet string, counted in octets
	data = binary.BigEndian.AppendUint16(data, u16(len(block)))
	data = append(data, block...)
	return userAck(pdu, u, data)
}

// moduleRecord is one record of the module identification list: the order
// number and the firmware version.
func (d *decoy) moduleRecord(index uint16) []byte {
	rec := make([]byte, 0, 28)
	rec = binary.BigEndian.AppendUint16(rec, index)
	rec = append(rec, fixed(d.order, 20)...)
	rec = binary.BigEndian.AppendUint16(rec, 0) // the module type, which is not what a scanner reads
	major, minor, patch := version3(d.version)
	rec = append(rec, major, minor)
	rec = append(rec, patch, 0x00)
	return rec
}

// componentRecords is the component identification list: the names, one
// record per index. An index of zero asks for all of them, which is what a
// scanner sends.
func (d *decoy) componentRecords(index uint16) [][]byte {
	// The indices are the standard's own: 1 the plant designation of this
	// PLC, 2 the module name, 3 the plant identification, 4 the copyright,
	// 5 the module serial number, 7 the module type name.
	all := []struct {
		idx  uint16
		text string
	}{
		{1, or(d.plant, d.module)},
		{2, d.module},
		{3, d.plant},
		{4, "Original Siemens Equipment"},
		{5, d.serial},
		{7, d.module},
	}
	out := make([][]byte, 0, len(all))
	for _, r := range all {
		if index != 0 && r.idx != index {
			continue
		}
		rec := make([]byte, 0, 34)
		rec = binary.BigEndian.AppendUint16(rec, r.idx)
		rec = append(rec, fixed(r.text, 32)...)
		out = append(out, rec)
	}
	return out
}

// fixed is a string in a field of n octets, space-padded and truncated,
// which is how these lists carry text.
func fixed(s string, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = ' '
	}
	copy(out, s)
	return out
}

// version3 reads a "3.2.7" into its three numbers. Anything it cannot read
// is version zero, which is a controller that would not be believed -- so
// the profiles carry one and the validator checks what an operator writes.
func version3(s string) (major, minor, patch byte) {
	parts := strings.Split(s, ".")
	for i := 0; i < len(parts) && i < 3; i++ {
		var v int
		for _, c := range parts[i] {
			if c < '0' || c > '9' {
				return major, minor, patch
			}
			v = v*10 + int(c-'0')
			if v > 255 {
				return major, minor, patch
			}
		}
		switch i {
		case 0:
			major = byte(v)
		case 1:
			minor = byte(v)
		default:
			patch = byte(v)
		}
	}
	return major, minor, patch
}

// DecoyStatus is what this listener's fabricated controller has seen.
func (t *server) DecoyStatus() (proxy.DecoyStatus, bool) {
	d := t.decoy
	if d == nil {
		return proxy.DecoyStatus{}, false
	}
	mode := "answer"
	if d.whole {
		mode = "decoy"
	}
	st := proxy.DecoyStatus{
		Listener: t.cfg.Name, Kind: "s7", Mode: mode, Profile: d.profile,
		Served: d.policy.Served(), Tripped: d.policy.Tripped(), Anyone: d.policy.Anyone(),
	}
	for _, c := range d.policy.Clients(32) {
		st.Visitors = append(st.Visitors, proxy.DecoyVisitor{
			ClientIP: c.Addr.String(), FirstSeen: c.FirstSeen, LastSeen: c.LastSeen,
			Frames: c.Frames, Tripped: c.Tripped,
		})
	}
	return st, true
}

// recordDeception notes one fabricated answer where an operator looks.
func (t *server) recordDeception(ip netip.Addr, why string, tripped bool, attrs ...any) {
	t.decoy.policy.Record(ip, tripped, time.Now())
	t.host.Counters().S7Deceived.Add(1)
	event := "s7_deceived"
	if tripped {
		t.host.Counters().S7Tripwire.Add(1)
		event = "s7_tripwire"
	}
	out := []any{"listener", t.cfg.Name, "client_ip", ip.String(), "reason", why}
	out = append(out, attrs...)
	t.host.Logs().SecurityEvent(context.Background(), "deceive", event, out...)
}

// deceive answers a refused request as the fabricated controller, in
// mode answer, and says whether it did.
//
// It sits on the refusal path and nowhere else, which is the rule this
// feature is bounded by: a request that was going to reach the controller is
// never answered from here. The controller is real, so the worst case of a
// false positive is a client told a value nothing measured -- which is why
// only a read, a write and the identification lists are answered, and every
// other refused function keeps the access fault a protected CPU would send.
//
// A whole-listener decoy never reaches this path: it has no upstream, so
// nothing is relayed and every frame is answered in serveDecoy instead.
func (se *session) deceive(pdu *wire.PDU, why string) bool {
	t := se.t
	d := t.decoy
	if d == nil || !d.admits(se.ip) {
		return false
	}
	if pdu.Type == wire.Userdata {
		u, ok := pdu.UserData()
		if !ok || u.Group != wire.GroupCPU || u.Sub != 0x01 {
			return false
		}
		id, index, ok := szlRequest(pdu)
		if !ok {
			return false
		}
		answer := d.szlAck(pdu, u, id, index)
		if answer == nil {
			return false
		}
		t.recordDeception(se.ip, why, false, "szl_id", fmt.Sprintf("%#04x", id))
		_ = se.writeClient(answer)
		return true
	}
	// Items is what bounds this to a read and a write: it returns nothing
	// for every other function, so a refused stop, control or download
	// keeps the access fault a protected CPU sends. A fabrication that
	// acknowledged a stop would be telling a client a machine had stopped.
	items, ok := pdu.Items()
	if !ok || len(items) == 0 {
		return false
	}
	answer := d.answerItems(pdu, items)
	t.recordDeception(se.ip, why, d.tripped(items),
		"function", wire.TransportName(pdu.Function), "items", len(items))
	_ = se.writeClient(answer)
	return true
}

// serveDecoy is the whole session for a listener that is a fabricated
// controller: nothing is dialled, and every frame is answered here.
func (se *session) serveDecoy(cr *wire.COTP) string {
	t := se.t
	t.recordDeception(se.ip, "decoy_connect", false,
		"rack", se.sess().Rack, "slot", se.sess().Slot)
	if err := se.writeClient(connectConfirm(cr)); err != nil {
		return "closed"
	}
	for {
		if idle := t.sc.IdleTimeout.D(); idle > 0 {
			_ = se.client.SetReadDeadline(time.Now().Add(idle))
		}
		f, err := se.cliReader.Next()
		if err != nil {
			return "closed"
		}
		c, err := wire.ParseCOTP(f.Payload)
		if err != nil {
			t.deny(se.ip, "unreadable_frame", err.Error())
			return "unreadable_frame"
		}
		switch c.Type {
		case wire.COTPData, wire.COTPExpeditedData:
		case wire.COTPDisconnectRequest:
			return "closed"
		default:
			// Transport housekeeping with no S7 inside it, and nothing
			// behind this listener to forward it to.
			continue
		}
		if wire.IsPlus(c.Data) {
			// S7comm-plus on a listener answering as a classic CPU. A real
			// 300 or 400 does not speak it, and answering as though it did
			// would be the contradiction that ends the pretence.
			t.recordDeception(se.ip, "decoy_plus", false)
			_ = se.writeClient(disconnect(c.SrcRef, c.DstRef))
			return "s7plus_not_offered"
		}
		pdu, err := wire.ParseS7(c.Data)
		if err != nil {
			t.deny(se.ip, "unreadable_pdu", err.Error())
			return "unreadable_pdu"
		}
		if err := se.answerDecoy(pdu); err != nil {
			return "closed"
		}
	}
}

// answerDecoy answers one PDU as the fabricated controller.
func (se *session) answerDecoy(pdu *wire.PDU) error {
	t := se.t
	d := t.decoy
	if pdu.Type == wire.Userdata {
		u, ok := pdu.UserData()
		if !ok {
			return se.writeClient(errorAck(pdu))
		}
		if u.Group == wire.GroupCPU && u.Sub == 0x01 {
			if id, index, ok := szlRequest(pdu); ok {
				if answer := d.szlAck(pdu, u, id, index); answer != nil {
					t.recordDeception(se.ip, "decoy_szl", false,
						"szl_id", fmt.Sprintf("%#04x", id))
					return se.writeClient(answer)
				}
			}
		}
		// A user-data function this fabrication does not offer, answered
		// the way a CPU answers one it does not have.
		t.recordDeception(se.ip, "decoy_userdata", false, "group", wire.GroupName(u.Group))
		return se.writeClient(errorUserData(pdu, u))
	}
	if !pdu.HasFunction {
		return se.writeClient(errorAck(pdu))
	}
	switch pdu.Function {
	case wire.FnSetupComm:
		t.recordDeception(se.ip, "decoy_setup", false)
		se.negotiated(d.pduLen)
		return se.writeClient(setupAnswer(pdu, d.pduLen))
	case wire.FnReadVar, wire.FnWriteVar:
		items, ok := pdu.Items()
		if !ok {
			return se.writeClient(errorAck(pdu))
		}
		answer := d.answerItems(pdu, items)
		t.recordDeception(se.ip, "decoy_"+opName(pdu.Function), d.tripped(items),
			"items", len(items))
		return se.writeClient(answer)
	}
	// Every other job -- an upload, a download, a control, a stop -- is
	// answered with the access fault a protected CPU sends. A fabrication
	// that pretended to accept a download would have to have something to
	// download into.
	t.recordDeception(se.ip, "decoy_refused", false, "function", fmt.Sprintf("%#02x", pdu.Function))
	return se.writeClient(errorAck(pdu))
}

// opName names the two functions the fabrication answers with data.
func opName(fn uint8) string {
	if fn == wire.FnWriteVar {
		return "write"
	}
	return "read"
}
