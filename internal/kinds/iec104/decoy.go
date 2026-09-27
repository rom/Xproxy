package iec104

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/deception"
	wire "github.com/rom/xproxy/internal/iec104"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/numrange"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/safe"
)

// A substation that is not there.
//
// See internal/deception for why, and for the rule that keeps it safe on a
// grid: a frame that was going to reach a station is never answered by the
// fabrication. What is here is the IEC 104 half -- the association
// handshake, what a general interrogation is answered with, and what a
// command is confirmed with.
//
// The protocol shapes this differently from Modbus. Modbus is a request
// and a response; this is an *association* with a handshake, sequence
// numbers, acknowledgements and unsolicited traffic. A decoy that answered
// only what it was asked would be a station nobody believes: a real one
// sends the end of initialisation when data transfer starts and reports
// spontaneously between interrogations, so this one does too.

// points is one run of addresses and what they are reported as.
type points struct {
	lo, hi int
	typ    wire.Type
	band   deception.Band
}

// stationProfile is a fabricated station's shape.
type stationProfile struct{ points []points }

// The built-in profiles. A substation has protection signals, analogue
// measurands and energy totals; an RTU has fewer of each. What matters is
// that the types are the ones the equipment actually reports: a station
// answering every measurement as a short float is a station nobody in
// this industry has.
var stationProfiles = map[string]stationProfile{
	"generic-substation": {points: []points{
		// Breaker and isolator positions, as double points: a real
		// substation reports those as two bits precisely so that "moving"
		// and "faulty" are distinguishable from open and closed.
		{lo: 1, hi: 16, typ: wire.MDpNA1, band: deception.Band{Shape: deception.ShapeDiscrete}},
		// Protection and alarm signals.
		{lo: 17, hi: 64, typ: wire.MSpNA1, band: deception.Band{Shape: deception.ShapeDiscrete}},
		// Measurands: currents, voltages, power. Scaled, which is what
		// most installed equipment sends.
		{lo: 101, hi: 148, typ: wire.MMeNB1, band: deception.Band{
			Shape: deception.ShapeAnalogue, Min: 0, Max: 27648}},
		// Energy totals, which only increase.
		{lo: 201, hi: 208, typ: wire.MItNA1, band: deception.Band{Shape: deception.ShapeCounter, Rate: 11}},
	}},
	"generic-rtu": {points: []points{
		{lo: 1, hi: 8, typ: wire.MSpNA1, band: deception.Band{Shape: deception.ShapeDiscrete}},
		{lo: 101, hi: 116, typ: wire.MMeNB1, band: deception.Band{
			Shape: deception.ShapeAnalogue, Min: 0, Max: 4095}},
		{lo: 201, hi: 202, typ: wire.MItNA1, band: deception.Band{Shape: deception.ShapeCounter, Rate: 3}},
	}},
}

// DefaultProfile is the profile a section that names none gets.
const DefaultProfile = "generic-substation"

// ProfileNames are the profiles this package has, for the test that keeps
// them in step with what the validator accepts.
func ProfileNames() []string {
	out := make([]string, 0, len(stationProfiles))
	for name := range stationProfiles {
		out = append(out, name)
	}
	return out
}

// decoyTypes are the types a point may be reported as. A type outside this
// is one nothing here can fabricate a value for, which is a configuration
// error rather than something to guess at.
var decoyTypes = map[string]wire.Type{
	"M_SP_NA_1": wire.MSpNA1, "M_DP_NA_1": wire.MDpNA1,
	"M_ME_NB_1": wire.MMeNB1, "M_ME_NC_1": wire.MMeNC1, "M_IT_NA_1": wire.MItNA1,
}

// DecoyTypeNames are those types, for the validator.
func DecoyTypeNames() []string {
	out := make([]string, 0, len(decoyTypes))
	for name := range decoyTypes {
		out = append(out, name)
	}
	return out
}

// decoy is a compiled deception section.
type decoy struct {
	policy *deception.Policy
	values *deception.Values
	// whole says the listener is a honeypot: nothing is dialled and every
	// frame is answered here.
	whole bool
	// commons are the common addresses the fabrication answers for.
	commons numrange.Set
	points  []points
	// tripwire addresses nobody has a reason to read.
	tripwire    numrange.Set
	spontaneous bool
	period      time.Duration
	profile     string
}

func newDecoy(c *config.IEC104Deception, name string) (*decoy, error) {
	if c == nil || (c.Enabled != nil && !*c.Enabled) {
		return nil, nil
	}
	p, ok := stationProfiles[c.Profile]
	if !ok {
		if c.Profile != "" {
			return nil, fmt.Errorf("deception.profile: %q is not a profile", c.Profile)
		}
		p = stationProfiles[DefaultProfile]
	}
	d := &decoy{
		whole:       c.Mode == "decoy",
		spontaneous: c.Spontaneous == nil || *c.Spontaneous,
		period:      c.Period.D(),
		profile:     c.Profile,
	}
	if d.profile == "" {
		d.profile = DefaultProfile
	}
	if d.period <= 0 {
		d.period = deception.DefaultPeriod
	}
	commons := c.CommonAddresses
	if len(commons) == 0 {
		commons = []string{"1"}
	}
	var err error
	if d.commons, err = numrange.Parse("deception.common_addresses", commons, 65535); err != nil {
		return nil, err
	}
	if len(c.Tripwire) > 0 {
		if d.tripwire, err = numrange.Parse("deception.tripwire", c.Tripwire, maxIOA); err != nil {
			return nil, err
		}
	}
	if d.points, err = decoyPoints(c.Points, p.points); err != nil {
		return nil, err
	}
	seed := c.Seed
	if seed == 0 {
		seed = deception.SeedFor(name)
	}
	bands := make([]deception.Band, 0, len(d.points))
	for _, pt := range d.points {
		b := pt.band
		b.Lo, b.Hi = pt.lo, pt.hi
		bands = append(bands, b)
	}
	d.values = deception.NewValues(seed, d.period, bands)
	d.policy = deception.NewPolicy(netutil.ParsePrefixes(c.Clients), c.MaxClients)
	return d, nil
}

// maxIOA is the largest information object address the protocol has: the
// field is three octets.
const maxIOA = 1<<24 - 1

// decoyPoints compiles the point list.
func decoyPoints(in []config.IEC104DecoyPoints, fallback []points) ([]points, error) {
	if len(in) == 0 {
		return fallback, nil
	}
	out := make([]points, 0, len(in))
	for i := range in {
		p := &in[i]
		set, err := numrange.Parse("deception.points.addresses", []string{p.Addresses}, maxIOA)
		if err != nil {
			return nil, err
		}
		if len(set) != 1 {
			return nil, fmt.Errorf("deception.points.addresses: %q is not one range", p.Addresses)
		}
		typ, ok := decoyTypes[strings.ToUpper(strings.TrimSpace(p.Type))]
		if !ok {
			return nil, fmt.Errorf("deception.points.type: %q is not a type this can fabricate", p.Type)
		}
		pt := points{lo: set[0].Lo, hi: set[0].Hi, typ: typ}
		switch typ {
		case wire.MSpNA1, wire.MDpNA1:
			pt.band = deception.Band{Shape: deception.ShapeDiscrete}
		case wire.MItNA1:
			pt.band = deception.Band{Shape: deception.ShapeCounter, Rate: p.Rate}
		default:
			pt.band = deception.Band{Shape: deception.ShapeAnalogue, Min: p.Min, Max: p.Max}
		}
		out = append(out, pt)
	}
	return out, nil
}

// admits reports whether this client is lied to.
func (d *decoy) admits(ip netip.Addr) bool { return d != nil && d.policy.Admits(ip) }

// tripped reports whether an ASDU named an address nobody reads.
func (d *decoy) tripped(a *wire.ASDU) bool {
	if d == nil || len(d.tripwire) == 0 || a == nil {
		return false
	}
	for _, ioa := range a.Addresses {
		if d.tripwire.Has(int(ioa)) {
			return true
		}
	}
	return false
}

// pointFor is the point run covering an address, and whether there is one.
func (d *decoy) pointFor(ioa uint32) (points, bool) {
	for _, p := range d.points {
		if int(ioa) >= p.lo && int(ioa) <= p.hi {
			return p, true
		}
	}
	return points{}, false
}

// object appends one information object as its type reports it.
func (d *decoy) object(dst []byte, common uint16, p points, ioa uint32) []byte {
	unit := byte(common)
	switch p.typ {
	case wire.MSpNA1:
		return wire.AppendSinglePoint(dst, ioa, d.values.Bit(unit, int(ioa)), wire.QualityGood)
	case wire.MDpNA1:
		// A double point is two bits: 1 is off, 2 is on. 0 and 3 are
		// "indeterminate", which a healthy substation does not report for
		// every isolator it owns.
		dst = wire.AppendIOA(dst, ioa)
		diq := byte(1)
		if d.values.Bit(unit, int(ioa)) {
			diq = 2
		}
		return append(dst, diq)
	case wire.MMeNC1:
		return wire.AppendFloat(dst, ioa, float32(d.values.Register(unit, int(ioa))), wire.QualityGood)
	case wire.MItNA1:
		// The sequence octet counts the reads of a total, so it moves with
		// the clock rather than standing still.
		seq := byte(d.values.Register(unit, int(ioa)) & 0x1F)
		return wire.AppendTotal(dst, ioa, int32(d.values.Register(unit, int(ioa))), seq)
	default:
		return wire.AppendScaled(dst, ioa, int16(d.values.Register(unit, int(ioa))), wire.QualityGood) //nolint:gosec // a scaled value is 16 bits
	}
}

// report builds one ASDU of consecutive points of one type, up to a bound
// that keeps the APDU inside the protocol's own length.
//
// The bound is the reason a real station splits an interrogation across
// many frames, and a decoy that sent one enormous frame would be a decoy
// that does not fit in the protocol.
func (d *decoy) report(common uint16, p points, from int, cause wire.Cause) (asdu []byte, next int) {
	size, _ := objectSizeFor(p.typ)
	per := 3 + size
	n := (wire.MaxLength - 4 - wire.ASDUHeaderLen) / per
	if n < 1 {
		n = 1
	}
	if from+n > p.hi+1 {
		n = p.hi + 1 - from
	}
	asdu = wire.AppendHead(nil, wire.Head{
		Type: p.typ, Objects: n, Cause: cause, Common: common,
	})
	for i := range n {
		asdu = d.object(asdu, common, p, ioaOf(from+i))
	}
	return asdu, from + n
}

// ioaOf narrows a point number to the protocol's three-octet information
// object address. The point runs are parsed against maxIOA, so the clamp
// never fires; it is what makes the narrowing safe to read.
func ioaOf(at int) uint32 {
	if at < 0 {
		return 0
	}
	if at > maxIOA {
		return maxIOA
	}
	return uint32(at)
}

// objectSizeFor is the element size of the types a decoy reports. The
// parser has its own table for every type in the standard; this is the
// handful this package builds, kept beside the builders so the two cannot
// drift apart unnoticed.
func objectSizeFor(t wire.Type) (int, bool) {
	switch t {
	case wire.MSpNA1, wire.MDpNA1:
		return 1, true
	case wire.MMeNB1:
		return 3, true
	case wire.MMeNC1:
		return 5, true
	case wire.MItNA1:
		return 5, true
	}
	return 0, false
}

// asked is one ASDU as it arrived: the parsed header, and the octets it
// arrived as. Both, because what the fabrication decides is decided on the
// header and what it answers with is the octets.
type asked struct {
	a   *wire.ASDU
	raw []byte
}

// askedOf takes the ASDU out of a frame.
func askedOf(frame *wire.Frame) asked {
	return asked{a: frame.ASDU, raw: frame.Raw[wire.APCILen:]}
}

// sender is where a fabricated ASDU goes.
//
// Two places: the association the decoy owns when the whole listener is a
// fabricated station, and the relay's own end of a real association when a
// refusal is being answered instead. Both number the frames they write --
// the second has to, because the control centre reading them is counting
// (apci.go) -- so what the decoy hands over is the ASDU and nothing else.
type sender interface {
	sendI(asdu []byte) error
}

// relayAnswer is the fabrication answering on a real association, in
// mode answer: the ASDU is wrapped in an APDU and numbered by the relay's
// own end of the association with that client.
type relayAnswer struct{ e *endpoint }

func (r relayAnswer) sendI(asdu []byte) error {
	if len(asdu) > wire.MaxLength-4 {
		return wire.ErrLength
	}
	raw := make([]byte, wire.APCILen+len(asdu))
	raw[0], raw[1] = wire.Start, byte(4+len(asdu))
	copy(raw[wire.APCILen:], asdu)
	return r.e.writeI(raw)
}

// association is the decoy's side of one connection: the sequence numbers
// and whether data transfer has been started.
//
// Writes are serialised because two of them are concurrent -- the frames
// answering the client, and the spontaneous reports a live station sends
// between them -- and two frames interleaved on the wire is not a frame.
type association struct {
	mu      sync.Mutex
	w       func([]byte) error
	send    uint16
	recv    uint16
	started bool
	// unacked counts frames received since the last acknowledgement, so
	// the decoy acknowledges on the protocol's own w rather than never.
	unacked int
	w0      int
}

func newAssociation(write func([]byte) error, w int) *association {
	if w <= 0 {
		w = 8
	}
	return &association{w: write, w0: w}
}

// sendI writes one ASDU as an I frame and counts it.
func (as *association) sendI(asdu []byte) error {
	as.mu.Lock()
	defer as.mu.Unlock()
	if err := as.w(wire.EncodeI(as.send, as.recv, asdu)); err != nil {
		return err
	}
	as.send = (as.send + 1) & 0x7FFF
	// An I frame carries the receive count, so it acknowledges as well.
	as.unacked = 0
	return nil
}

// sendU writes a control function.
func (as *association) sendU(c wire.Control) error {
	as.mu.Lock()
	defer as.mu.Unlock()
	return as.w(wire.EncodeU(c))
}

// received notes an I frame and acknowledges when the window says to.
func (as *association) received() error {
	as.mu.Lock()
	defer as.mu.Unlock()
	as.recv = (as.recv + 1) & 0x7FFF
	as.unacked++
	if as.unacked < as.w0 {
		return nil
	}
	as.unacked = 0
	return as.w(wire.EncodeS(as.recv))
}

func (as *association) transferStarted() bool {
	as.mu.Lock()
	defer as.mu.Unlock()
	return as.started
}

func (as *association) setStarted(on bool) {
	as.mu.Lock()
	as.started = on
	as.mu.Unlock()
}

// DecoyStatus is what this listener's fabricated station has seen.
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
		Listener: t.cfg.Name, Kind: "iec104", Mode: mode, Profile: d.profile,
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

// record notes one fabricated answer and says so where an operator looks.
func (t *server) recordDeception(ip netip.Addr, a *wire.ASDU, why string, tripped bool) {
	d := t.decoy
	d.policy.Record(ip, tripped, time.Now())
	t.host.Counters().IEC104Deceived.Add(1)
	event := "iec104_deceived"
	if tripped {
		t.host.Counters().IEC104Tripwire.Add(1)
		event = "iec104_tripwire"
	}
	attrs := []any{"listener", t.cfg.Name, "client_ip", ip.String(), "reason", why}
	if a != nil {
		attrs = append(attrs, "asdu_type", a.Type.String(), "cause", a.Cause.String(),
			"common_address", int(a.Common))
		if len(a.Addresses) > 0 {
			attrs = append(attrs, "ioa", int(a.Addresses[0]))
		}
	}
	t.host.Logs().SecurityEvent(context.Background(), "deceive", event, attrs...)
}

// serveDecoy is the whole session for a listener that is a fabricated
// station: no upstream is dialled, and every frame is answered here.
//
// The shape follows the standard's own order, because a client checks it:
// nothing at all is sent until STARTDT_act, the end of initialisation
// comes first once data transfer starts, and an interrogation is answered
// with a confirmation, then the data, then a termination.
func (se *session) serveDecoy() string {
	t := se.t
	d := t.decoy
	as := newAssociation(se.writeClient, t.m.W)
	if d.spontaneous {
		stop := make(chan struct{})
		defer close(stop)
		go func() {
			defer safe.Guard("iec104 decoy reports")
			d.spontaneousReports(as, stop)
		}()
	}
	max := t.m.MaxFrameBytes
	idle := t.m.IdleTimeout.D()
	if idle <= 0 {
		idle = 120 * time.Second
	}
	rd := wire.NewReader(se.client)
	for {
		if se.closed.Load() {
			return "closed"
		}
		_ = se.client.SetReadDeadline(time.Now().Add(idle))
		frame, err := rd.ReadFrame()
		if err != nil {
			if reason := se.readError(err, true); reason != "" {
				return reason
			}
			return "closed"
		}
		t.host.Counters().IEC104Frames.Add(1)
		if max > 0 && len(frame.Raw) > max {
			t.host.Counters().IEC104Malformed.Add(1)
			t.host.Counters().Refuse("iec104", "frame_too_long")
			t.deny(se.ip, "iec104_frame_too_long", itoa(len(frame.Raw)))
			return "iec104_frame_too_long"
		}
		if err := se.answerDecoy(as, frame); err != nil {
			return "closed"
		}
	}
}

// writeClient is the one place the decoy writes to the client, so that the
// answers and the spontaneous reports cannot interleave.
func (se *session) writeClient(b []byte) error {
	_, err := se.client.Write(b)
	if err != nil {
		se.closed.Store(true)
	}
	return err
}

// answerDecoy answers one frame as the fabricated station.
func (se *session) answerDecoy(as *association, frame *wire.Frame) error {
	t := se.t
	d := t.decoy
	switch frame.Format {
	case wire.FormatU:
		return se.answerControl(as, frame.Control)
	case wire.FormatS:
		// An acknowledgement. Nothing is owed in return.
		return nil
	}
	if err := as.received(); err != nil {
		return err
	}
	a := frame.ASDU
	if a == nil {
		return nil
	}
	q := askedOf(frame)
	se.watch.saw(a)
	tripped := d.tripped(a)
	t.recordDeception(se.ip, a, "decoy", tripped)
	// A common address this station is not is answered the way a station
	// answers one: negatively, with an unknown-common-address cause. A
	// fabrication that answered for every address would be one association
	// carrying twenty substations, which is not a substation.
	if !d.commons.Has(int(a.Common)) {
		return as.sendI(negativeOf(q, wire.CauseUnknownCommon))
	}
	switch a.Type {
	case wire.CIcNA1:
		return d.interrogate(as, q)
	case wire.CCiNA1:
		return d.counterInterrogate(as, q)
	case wire.CCsNA1, wire.CTsNA1, wire.CTsTA1:
		// Clock synchronisation and the test commands are confirmed with
		// what they carried, which is what the standard says and what a
		// client checks.
		return as.sendI(confirmOf(q, wire.CauseActCon))
	case wire.CRdNA1:
		return d.readOne(as, q)
	}
	if a.Cause.Commanding() {
		return d.command(as, q)
	}
	// Anything else from a controlling station is not something a station
	// has an answer for.
	return as.sendI(negativeOf(q, wire.CauseUnknownType))
}

// answerControl answers the association handshake.
func (se *session) answerControl(as *association, c wire.Control) error {
	d := se.t.decoy
	se.t.recordDeception(se.ip, nil, "control_"+c.String(), false)
	switch c {
	case wire.StartDTAct:
		if err := as.sendU(wire.StartDTCon); err != nil {
			return err
		}
		as.setStarted(true)
		// The end of initialisation, which a real station sends once data
		// transfer is up and which a client uses to know the station has
		// restarted. A decoy that never sent one would be a station that
		// has been running since before the client was born.
		return d.endOfInit(as)
	case wire.StopDTAct:
		as.setStarted(false)
		return as.sendU(wire.StopDTCon)
	case wire.TestFRAct:
		return as.sendU(wire.TestFRCon)
	}
	// A confirmation from the client is not something to confirm back.
	return nil
}

// endOfInit sends M_EI_NA_1: the station has initialised.
func (d *decoy) endOfInit(as *association) error {
	common := uint16(d.commons[0].Lo) //nolint:gosec // bounded by the parse above
	asdu := wire.AppendHead(nil, wire.Head{
		Type: wire.MEiNA1, Objects: 1, Cause: wire.CauseInitialised, Common: common,
	})
	asdu = wire.AppendIOA(asdu, 0)
	// Cause of initialisation: local power on, and no change of local
	// parameters.
	asdu = append(asdu, 0x00)
	return as.sendI(asdu)
}

// interrogate answers a general interrogation: the confirmation, then every
// point the station has, then the termination. That sequence is what a
// client waits for, and a decoy that sent the data without the termination
// would leave a control centre waiting for the rest.
func (d *decoy) interrogate(as sender, q asked) error {
	a := q.a
	if a.Cause != wire.CauseActivation {
		return as.sendI(confirmOf(q, wire.CauseActCon))
	}
	if err := as.sendI(confirmOf(q, wire.CauseActCon)); err != nil {
		return err
	}
	for _, p := range d.points {
		if p.typ == wire.MItNA1 {
			// Totals answer a counter interrogation rather than a general
			// one, which is the division the standard makes.
			continue
		}
		for at := p.lo; at <= p.hi; {
			asdu, next := d.report(a.Common, p, at, wire.CauseIntroGeneral)
			if err := as.sendI(asdu); err != nil {
				return err
			}
			at = next
		}
	}
	return as.sendI(confirmOf(q, wire.CauseActTerm))
}

// counterInterrogate answers a counter interrogation with the totals.
func (d *decoy) counterInterrogate(as sender, q asked) error {
	a := q.a
	if a.Cause != wire.CauseActivation {
		return as.sendI(confirmOf(q, wire.CauseActCon))
	}
	if err := as.sendI(confirmOf(q, wire.CauseActCon)); err != nil {
		return err
	}
	for _, p := range d.points {
		if p.typ != wire.MItNA1 {
			continue
		}
		for at := p.lo; at <= p.hi; {
			asdu, next := d.report(a.Common, p, at, wire.CauseReqCounter)
			if err := as.sendI(asdu); err != nil {
				return err
			}
			at = next
		}
	}
	return as.sendI(confirmOf(q, wire.CauseActTerm))
}

// readOne answers a read command for one address.
func (d *decoy) readOne(as sender, q asked) error {
	a := q.a
	if len(a.Addresses) == 0 {
		return as.sendI(negativeOf(q, wire.CauseUnknownAddress))
	}
	ioa := a.Addresses[0]
	p, ok := d.pointFor(ioa)
	if !ok {
		// An address this station does not have. Saying so is what a
		// station does, and it is also the one answer a decoy has to give
		// honestly: claiming every address in a 24-bit space exists is
		// not a substation.
		return as.sendI(negativeOf(q, wire.CauseUnknownAddress))
	}
	asdu := wire.AppendHead(nil, wire.Head{
		Type: p.typ, Objects: 1, Cause: wire.CauseRequest, Common: a.Common,
	})
	return as.sendI(d.object(asdu, a.Common, p, ioa))
}

// command confirms a command and does nothing.
//
// A selection is confirmed as a selection; an execute is confirmed and then
// terminated, which is the sequence that tells a control centre the
// breaker moved. Nothing moved.
func (d *decoy) command(as sender, q asked) error {
	a := q.a
	if a.Cause == wire.CauseDeactivation {
		return as.sendI(confirmOf(q, wire.CauseDeactCon))
	}
	if err := as.sendI(confirmOf(q, wire.CauseActCon)); err != nil {
		return err
	}
	if a.Select {
		// A selection is not a completion: the standard's own two-step
		// form ends here until an execute arrives.
		return nil
	}
	return as.sendI(confirmOf(q, wire.CauseActTerm))
}

// spontaneousReports sends unsolicited measurements while data transfer is
// started, which is what a live station does between interrogations.
func (d *decoy) spontaneousReports(as *association, stop <-chan struct{}) {
	tick := time.NewTicker(d.period)
	defer tick.Stop()
	common := uint16(d.commons[0].Lo) //nolint:gosec // bounded by the parse
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
		}
		if !as.transferStarted() {
			continue
		}
		// One report of one kind of point per period. A station that sent
		// its whole database every thirty seconds would be a station
		// nobody's bandwidth budget has.
		for _, p := range d.points {
			if p.typ == wire.MItNA1 {
				continue
			}
			asdu, _ := d.report(common, p, p.lo, wire.CauseSpontaneous)
			if err := as.sendI(asdu); err != nil {
				return
			}
			break
		}
	}
}

// confirmOf is the ASDU echoed back with a new cause and nothing else
// changed, which is what a confirmation is: the addresses, the qualifiers
// and the values are the ones the client sent.
func confirmOf(q asked, cause wire.Cause) []byte {
	return rebuild(q, cause, false)
}

// negativeOf is the same with the negative-confirm bit set.
func negativeOf(q asked, cause wire.Cause) []byte {
	return rebuild(q, cause, true)
}

func rebuild(q asked, cause wire.Cause, negative bool) []byte {
	// The octets that arrived, with two bits of one octet changed: the
	// cause and its negative-confirm bit. Re-encoding from the parsed
	// fields would mean inventing the elements the parser did not keep --
	// a qualifier of interrogation, a command's value, a setpoint -- and a
	// confirmation carrying a qualifier the centre did not send is the
	// tell, not the deception.
	out := make([]byte, len(q.raw))
	copy(out, q.raw)
	if len(out) < 3 {
		return out
	}
	out[2] = byte(cause) | (out[2] & 0x80) // keep the test bit
	if negative {
		out[2] |= 0x40
	}
	return out
}

// deceive answers a refused activation as the fabricated station, in
// mode answer, and says whether it did.
//
// There is no check for mode decoy here, because a whole-listener decoy
// never reaches this path: it has no upstream, so nothing is relayed and
// every frame is answered in serveDecoy instead.
//
// It sits on the refusal path and nowhere else, which is the whole of the
// rule this feature is bounded by: a frame that was going to reach the
// station is never answered from here. The station is real, so the worst
// case of a false positive is a control centre told "no" in a way that
// looks like "yes" -- never an operator reading a fabricated measurement
// off a real point.
//
// Only an activation is answered. There is nothing to confirm about a
// measurement, and a "confirmation of a measurement" is an ASDU no station
// would send, which is the tell rather than the deception.
func (se *session) deceive(frame *wire.Frame, why string) bool {
	d := se.t.decoy
	if d == nil || !d.admits(se.ip) {
		return false
	}
	a := frame.ASDU
	if a == nil || !a.Cause.Commanding() {
		return false
	}
	se.t.recordDeception(se.ip, a, why, d.tripped(a))
	if err := d.command(relayAnswer{&se.clientEnd}, askedOf(frame)); err != nil {
		se.closed.Store(true)
	}
	return true
}
