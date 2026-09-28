package snmp

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/deception"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/proxy"
	wire "github.com/rom/xproxy/internal/snmp"
)

// An agent that is not there.
//
// See internal/deception for why. What is here is the SNMP half: the system
// group every scanner reads first, an interface table a walk can walk, and
// counters that only rise.
//
// Two things make this protocol different from the plant protocols beside
// it. The first is that a refusal is about a *credential*: a community
// string that is wrong is refused and one that is right is answered, so the
// refusal is the oracle a password list needs. The second is that a
// fabricated agent is a UDP service, and a UDP service that answers a small
// request with a large response is an amplifier -- so everything here is
// bounded by the listener's own amplification limits before it is built.

// The object identifiers this fabrication answers for. They are the ones
// every manager asks for: RFC 1213's system group and the interface table.
var (
	oidSysDescr    = wire.OID{1, 3, 6, 1, 2, 1, 1, 1, 0}
	oidSysObjectID = wire.OID{1, 3, 6, 1, 2, 1, 1, 2, 0}
	oidSysUpTime   = wire.OID{1, 3, 6, 1, 2, 1, 1, 3, 0}
	oidSysContact  = wire.OID{1, 3, 6, 1, 2, 1, 1, 4, 0}
	oidSysName     = wire.OID{1, 3, 6, 1, 2, 1, 1, 5, 0}
	oidSysLocation = wire.OID{1, 3, 6, 1, 2, 1, 1, 6, 0}
	oidSysServices = wire.OID{1, 3, 6, 1, 2, 1, 1, 7, 0}
	oidIfNumber    = wire.OID{1, 3, 6, 1, 2, 1, 2, 1, 0}
	oidIfEntry     = wire.OID{1, 3, 6, 1, 2, 1, 2, 2, 1}
)

// The interface table columns the fabrication has. They are the ones a
// monitoring system graphs and a scanner reads; a table with every column of
// RFC 2863 in it would be a device that implements more than most.
const (
	colIfIndex       = 1
	colIfDescr       = 2
	colIfType        = 3
	colIfMtu         = 4
	colIfSpeed       = 5
	colIfPhysAddress = 6
	colIfAdminStatus = 7
	colIfOperStatus  = 8
	colIfLastChange  = 9
	colIfInOctets    = 10
	colIfInErrors    = 14
	colIfOutOctets   = 16
	colIfOutErrors   = 20
)

// The declaration order is the one an operator reads in -- what the port is,
// how fast it is, whether it is up, then the traffic and then the errors --
// and not the order the protocol walks in. build sorts them, which is what
// makes a walk of the table lexicographic whatever order this list is
// written in.
var ifColumns = []uint32{
	colIfIndex, colIfDescr, colIfType, colIfMtu, colIfSpeed, colIfPhysAddress,
	colIfAdminStatus, colIfOperStatus, colIfLastChange,
	colIfInOctets, colIfOutOctets, colIfInErrors, colIfOutErrors,
}

// agentProfile is a fabricated device's identity and shape.
type agentProfile struct {
	descr    string
	objectID string
	services int64
	ports    int
	speed    uint32
}

// The built-in profiles. Both are deliberately ordinary, and the object
// identifier is the one a Linux-based appliance reports, which much of the
// installed base of managed switches is.
var agentProfiles = map[string]agentProfile{
	"generic-switch": {
		descr: "24-port managed Ethernet switch", objectID: "1.3.6.1.4.1.8072.3.2.10",
		services: 78, ports: 24, speed: 1_000_000_000,
	},
	"generic-router": {
		descr: "Industrial router", objectID: "1.3.6.1.4.1.8072.3.2.10",
		services: 78, ports: 4, speed: 1_000_000_000,
	},
}

// DefaultProfile is the profile a section that names none gets.
const DefaultProfile = "generic-switch"

// ProfileNames are the profiles this package has, for the test that keeps
// them in step with what the validator accepts.
func ProfileNames() []string {
	out := make([]string, 0, len(agentProfiles))
	for name := range agentProfiles {
		out = append(out, name)
	}
	return out
}

// object is one thing the fabrication answers for: a name, how to build its
// value, and which interface it belongs to where that matters.
type object struct {
	oid   wire.OID
	kind  objectKind
	port  int
	extra uint32
}

type objectKind uint8

const (
	kindSysDescr objectKind = iota
	kindSysObjectID
	kindSysUpTime
	kindSysContact
	kindSysName
	kindSysLocation
	kindSysServices
	kindIfNumber
	kindIfColumn
)

// decoy is a compiled deception section.
type decoy struct {
	policy *deception.Policy
	values *deception.Values
	// whole says the listener is a honeypot: nothing is forwarded and every
	// message is answered here.
	whole   bool
	profile string
	// objects are every name this fabrication answers for, in the
	// protocol's own order. A walk is a step through this slice, which is
	// why it is ordered once here rather than compared per request.
	objects []object
	// tripwire are the subtrees nobody has a reason to read.
	tripwire []wire.OID
	// The system group, and the shape.
	descr, contact, name, location string
	objectID                       wire.OID
	services                       int64
	ports                          int
	speed                          uint32
	// started is when this listener came up, which is what its uptime is
	// measured from: a device whose uptime does not advance is a device
	// nothing is running on.
	started time.Time
}

func newDecoy(c *config.SNMPDeception, name string) (*decoy, error) {
	if c == nil || (c.Enabled != nil && !*c.Enabled) {
		return nil, nil
	}
	p, ok := agentProfiles[c.Profile]
	if !ok {
		if c.Profile != "" {
			return nil, fmt.Errorf("deception.profile: %q is not a profile", c.Profile)
		}
		p = agentProfiles[DefaultProfile]
	}
	d := &decoy{
		whole:    c.Mode == "decoy",
		profile:  c.Profile,
		descr:    or(c.SysDescr, p.descr),
		contact:  c.SysContact,
		name:     or(c.SysName, name),
		location: c.SysLocation,
		services: p.services,
		ports:    p.ports,
		speed:    p.speed,
		started:  time.Now(),
	}
	if d.profile == "" {
		d.profile = DefaultProfile
	}
	if c.Interfaces > 0 {
		d.ports = c.Interfaces
	}
	var err error
	if d.objectID, err = wire.ParseOID(or(c.SysObjectID, p.objectID)); err != nil {
		return nil, fmt.Errorf("deception.sys_object_id: %w", err)
	}
	for i, s := range c.Tripwire {
		o, err := wire.ParseOID(s)
		if err != nil {
			return nil, fmt.Errorf("deception.tripwire[%d]: %w", i, err)
		}
		d.tripwire = append(d.tripwire, o)
	}
	seed := c.Seed
	if seed == 0 {
		seed = deception.SeedFor(name)
	}
	period := c.Period.D()
	if period <= 0 {
		period = deception.DefaultPeriod
	}
	// One band per kind of value, over the port numbers: the counters rise,
	// the error counts rise slowly, and the operational status is a bit that
	// mostly stays where it is.
	d.values = deception.NewValues(seed, period, []deception.Band{
		{Lo: 0, Hi: 1 << 20, Shape: deception.ShapeCounter, Rate: 4096},
	})
	d.policy = deception.NewPolicy(netutil.ParsePrefixes(c.Clients), c.MaxClients)
	d.objects = d.build()
	return d, nil
}

// or is the first of two strings that is not empty.
func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// build lays out every object this fabrication answers for, in order.
//
// The order is the protocol's: the system group, then the interface table
// column by column and index by index inside each column. That is what a
// walk steps through, and building it once means the walk is a step through
// a slice rather than an arithmetic guess about what comes next.
func (d *decoy) build() []object {
	out := make([]object, 0, 8+len(ifColumns)*d.ports)
	out = append(out,
		object{oid: oidSysDescr, kind: kindSysDescr},
		object{oid: oidSysObjectID, kind: kindSysObjectID},
		object{oid: oidSysUpTime, kind: kindSysUpTime},
		object{oid: oidSysContact, kind: kindSysContact},
		object{oid: oidSysName, kind: kindSysName},
		object{oid: oidSysLocation, kind: kindSysLocation},
		object{oid: oidSysServices, kind: kindSysServices},
		object{oid: oidIfNumber, kind: kindIfNumber},
	)
	for _, col := range ifColumns {
		for port := 1; port <= d.ports; port++ {
			oid := make(wire.OID, 0, len(oidIfEntry)+2)
			oid = append(oid, oidIfEntry...)
			oid = append(oid, col, uint32(port)) //nolint:gosec // ports are 1..256, checked at load
			out = append(out, object{oid: oid, kind: kindIfColumn, port: port, extra: col})
		}
	}
	slices.SortFunc(out, func(a, b object) int { return wire.Compare(a.oid, b.oid) })
	return out
}

// admits says whether this client gets the fabrication.
func (d *decoy) admits(ip netip.Addr) bool { return d != nil && d.policy.Admits(ip) }

// find locates an object by name, and says where a walk would continue from.
func (d *decoy) find(oid wire.OID) (int, bool) {
	at, found := slices.BinarySearchFunc(d.objects, oid,
		func(o object, want wire.OID) int { return wire.Compare(o.oid, want) })
	return at, found
}

// next is the index of the first object after a name, which is what GETNEXT
// answers with.
func (d *decoy) next(oid wire.OID) (int, bool) {
	at, found := d.find(oid)
	if found {
		at++
	}
	if at >= len(d.objects) {
		return 0, false
	}
	return at, true
}

// tripped says whether a request named something nobody reads.
func (d *decoy) tripped(m *wire.Message) bool {
	if len(d.tripwire) == 0 || m == nil || m.PDU == nil {
		return false
	}
	for _, b := range m.PDU.VarBinds {
		for _, t := range d.tripwire {
			if b.OID.Under(t) || b.OID.Equal(t) {
				return true
			}
		}
	}
	return false
}

// value builds one object's value, which is a function of the seed, the
// object and the clock. Nothing is stored: a walk of the whole table costs
// this listener no memory, and the same walk a minute later reads the
// counters further on.
func (d *decoy) value(o object) (wire.Tag, []byte) {
	switch o.kind {
	case kindSysDescr:
		return wire.TagOctetStr, []byte(d.descr)
	case kindSysObjectID:
		return wire.TagOID, wire.EncodeOID(d.objectID)
	case kindSysUpTime:
		return wire.TagTimeTicks, wire.Ticks(d.upTime())
	case kindSysContact:
		return wire.TagOctetStr, []byte(d.contact)
	case kindSysName:
		return wire.TagOctetStr, []byte(d.name)
	case kindSysLocation:
		return wire.TagOctetStr, []byte(d.location)
	case kindSysServices:
		return wire.TagInteger, wire.Int(d.services)
	case kindIfNumber:
		return wire.TagInteger, wire.Int(int64(d.ports))
	}
	return d.column(o)
}

// column builds one cell of the interface table.
func (d *decoy) column(o object) (wire.Tag, []byte) {
	port := byte(o.port) //nolint:gosec // ports are 1..256, checked at load
	switch o.extra {
	case colIfIndex:
		return wire.TagInteger, wire.Int(int64(o.port))
	case colIfDescr:
		return wire.TagOctetStr, []byte(fmt.Sprintf("GigabitEthernet0/%d", o.port))
	case colIfType:
		// ethernetCsmacd, which is what every port on a switch is.
		return wire.TagInteger, wire.Int(6)
	case colIfMtu:
		return wire.TagInteger, wire.Int(1500)
	case colIfSpeed:
		return wire.TagGauge32, wire.Gauge(d.speed)
	case colIfPhysAddress:
		return wire.TagOctetStr, d.mac(o.port)
	case colIfAdminStatus:
		// up: a port an operator has not shut down.
		return wire.TagInteger, wire.Int(1)
	case colIfOperStatus:
		// Most ports are up and a few are not, which is what a switch
		// looks like: a device whose every port is connected is a device
		// with nothing spare.
		if d.values.Bit(port, 0x0053) {
			return wire.TagInteger, wire.Int(1)
		}
		return wire.TagInteger, wire.Int(2)
	case colIfLastChange:
		// A port that came up shortly after the device did. The port number
		// is 1..256, bounded at load, and the clamp is what makes the
		// narrowing safe to read.
		return wire.TagTimeTicks, wire.Ticks(min(d.upTime(), 100*uint32(port)))
	case colIfInErrors, colIfOutErrors:
		// Errors rise, slowly. A port with no errors at all after a month
		// of uptime is a port nothing has been plugged into.
		return wire.TagCounter32, wire.Counter(uint32(d.values.Register(port, int(o.extra))) / 16)
	}
	// The octet counters, which only rise. The 16-bit sample is the low
	// half; the high half advances with the uptime, so a poller that reads
	// twice a minute apart sees the difference a gigabit port would make.
	base := uint32(d.values.Register(port, int(o.extra)))
	return wire.TagCounter32, wire.Counter(base + d.upTime()*4096)
}

// upTime is the listener's uptime in hundredths of a second, which is what
// this protocol counts in.
func (d *decoy) upTime() uint32 {
	ticks := time.Since(d.started).Milliseconds() / 10
	if ticks < 0 {
		return 0
	}
	// TimeTicks is 32 bits and wraps after 497 days, which is what a real
	// agent does too.
	return uint32(ticks % (1 << 32)) //nolint:gosec // reduced above
}

// mac is the physical address of one port, derived from the seed so that the
// device keeps the same one across a restart. The organisational prefix is
// derived with it: a fabricated switch whose ports all share one prefix is
// what a switch looks like, and which prefix it is is not something a
// manager checks.
func (d *decoy) mac(port int) []byte {
	v := d.values.Register(0, 0x4d41)
	out := []byte{0x00, byte(v >> 8), byte(v), 0x00, byte(port >> 8), byte(port)}
	return out
}

// DecoyStatus is what this listener's fabricated agent has seen.
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
		Listener: t.cfg.Name, Kind: "snmp", Mode: mode, Profile: d.profile,
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
func (t *server) recordDeception(ip netip.Addr, m *wire.Message, why string, tripped bool) {
	t.decoy.policy.Record(ip, tripped, time.Now())
	t.host.Counters().SNMPDeceived.Add(1)
	event := "snmp_deceived"
	if tripped {
		t.host.Counters().SNMPTripwire.Add(1)
		event = "snmp_tripwire"
	}
	attrs := []any{"listener", t.cfg.Name, "client_ip", ip.String(), "reason", why}
	if m != nil && m.PDU != nil {
		attrs = append(attrs, "pdu", m.PDU.Type.String(), "version", m.Version.String())
		if oids := oidsOf(m); len(oids) > 0 {
			attrs = append(attrs, "oid", oids[0])
		}
	}
	t.host.Logs().SecurityEvent(context.Background(), "deceive", event, attrs...)
}

// deceive answers one request as the fabricated agent and says whether it
// did.
//
// It sits where a refusal would be written and nowhere else, which is the
// rule this feature is bounded by: a request that was going to reach the
// agent is never answered from here.
//
// A version 3 message is never answered. Its response would have to carry a
// digest computed with a key this relay does not have, so a fabrication for
// it would be a message no manager accepts -- and an unauthenticated
// fabrication of an authenticated protocol is a worse tell than a refusal.
func (t *server) deceive(m *wire.Message, p *peer, why string) bool {
	d := t.decoy
	if d == nil || m == nil || m.PDU == nil || p == nil {
		return false
	}
	ip := p.ip
	if !d.admits(ip) {
		return false
	}
	answer, ok := t.fabricate(m)
	if !ok {
		return false
	}
	t.recordDeception(ip, m, why, d.tripped(m))
	if err := p.write(t, answer); err != nil {
		t.host.Logs().Error.Warn("snmp decoy answer failed", "listener", t.cfg.Name,
			"client", ip.String(), "error", err.Error())
	}
	return true
}

// fabricate builds the answer to one request, or says there is none to
// build.
func (t *server) fabricate(m *wire.Message) ([]byte, bool) {
	d := t.decoy
	if m.Version == wire.V3 || m.PDU == nil {
		return nil, false
	}
	switch m.PDU.Type {
	case wire.GetRequest, wire.GetNextRequest, wire.GetBulkRequest, wire.SetRequest:
	default:
		// A response, a report or a notification. Nothing is waiting on an
		// answer to any of them, and an agent sends none.
		return nil, false
	}
	binds, status, index := d.answerBinds(m, t.repetitionBound(m), t.varBindBound())
	var out []byte
	var err error
	if status != 0 {
		out, err = wire.AnswerError(m, status, index)
	} else {
		out, err = wire.Answer(m, binds)
	}
	if err != nil || len(out) == 0 {
		return nil, false
	}
	if max := t.maxResponse(); max > 0 && len(out) > max {
		// The response bound is the same one an agent's answer is held to,
		// and it applies here for the same reason: this is a UDP service
		// answering a small request, and the answer is the amplification.
		// Too large is answered with tooBig, which is what an agent sends
		// and what a manager retries in smaller pieces.
		t.host.Counters().SNMPAmplified.Add(1)
		out, err = wire.AnswerError(m, wire.StatusTooBig, 0)
		if err != nil {
			return nil, false
		}
	}
	return out, true
}

// answerBinds is the bindings the fabrication answers with, or the error it
// answers instead.
func (d *decoy) answerBinds(m *wire.Message, reps, maxBinds int) ([][]byte, int64, int64) {
	asked := m.PDU.VarBinds
	if len(asked) == 0 {
		return nil, 0, 0
	}
	switch m.PDU.Type {
	case wire.GetRequest, wire.SetRequest:
		// A SET is answered as though it took effect. Nothing was written:
		// there is nothing here to write to, which is the whole point of
		// the listener.
		out := make([][]byte, 0, len(asked))
		for i, b := range asked {
			at, found := d.find(b.OID)
			if !found {
				if m.Version == wire.V1 {
					// Version 1 has no per-binding exception, so the whole
					// response carries noSuchName and the index of the
					// binding it is about. That is what a v1 agent does.
					return nil, wire.StatusNoSuchName, int64(i + 1)
				}
				out = append(out, wire.Varbind(b.OID, wire.TagNoSuchObject, nil))
				continue
			}
			tag, val := d.value(d.objects[at])
			out = append(out, wire.Varbind(b.OID, tag, val))
		}
		return out, 0, 0
	case wire.GetNextRequest:
		out := make([][]byte, 0, len(asked))
		for i, b := range asked {
			at, ok := d.next(b.OID)
			if !ok {
				if m.Version == wire.V1 {
					return nil, wire.StatusNoSuchName, int64(i + 1)
				}
				out = append(out, wire.Varbind(b.OID, wire.TagEndOfMibView, nil))
				continue
			}
			o := d.objects[at]
			tag, val := d.value(o)
			out = append(out, wire.Varbind(o.oid, tag, val))
		}
		return out, 0, 0
	}
	return d.bulk(m, reps, maxBinds), 0, 0
}

// bulk answers a GETBULK: the non-repeaters once each, then the repeaters
// stepped forward, bounded by the listener's own repetition and binding
// limits.
//
// The bound is the reason this is not an amplifier. A GETBULK asking for a
// thousand repetitions of a dozen names is forty octets of request and half
// a megabyte of answer, which is what a reflection attack is made of, and a
// fabricated agent that honoured it would be the amplifier the listener
// exists to stop being.
func (d *decoy) bulk(m *wire.Message, reps, maxBinds int) [][]byte {
	asked := m.PDU.VarBinds
	nonRepeaters := int(m.PDU.NonRepeaters)
	if nonRepeaters < 0 {
		nonRepeaters = 0
	}
	if nonRepeaters > len(asked) {
		nonRepeaters = len(asked)
	}
	want := int(m.PDU.MaxRepetitions)
	if want < 0 {
		want = 0
	}
	if reps > 0 && want > reps {
		want = reps
	}
	out := make([][]byte, 0, len(asked))
	for _, b := range asked[:nonRepeaters] {
		at, ok := d.next(b.OID)
		if !ok {
			out = append(out, wire.Varbind(b.OID, wire.TagEndOfMibView, nil))
			continue
		}
		o := d.objects[at]
		tag, val := d.value(o)
		out = append(out, wire.Varbind(o.oid, tag, val))
	}
	// The repeaters are answered round by round, which is the order the
	// protocol says: one step of every repeater, then the next step of
	// every repeater.
	from := make([]wire.OID, 0, len(asked)-nonRepeaters)
	for _, b := range asked[nonRepeaters:] {
		from = append(from, b.OID)
	}
	for round := 0; round < want; round++ {
		done := 0
		for i := range from {
			at, ok := d.next(from[i])
			if !ok {
				out = append(out, wire.Varbind(from[i], wire.TagEndOfMibView, nil))
				done++
				continue
			}
			o := d.objects[at]
			tag, val := d.value(o)
			out = append(out, wire.Varbind(o.oid, tag, val))
			from[i] = o.oid
			if maxBinds > 0 && len(out) >= maxBinds {
				return out
			}
		}
		if done == len(from) {
			// Every repeater has reached the end of what this device has.
			// A real agent stops here rather than repeating end-of-view a
			// thousand times.
			break
		}
	}
	return out
}
