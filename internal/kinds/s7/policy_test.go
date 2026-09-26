package s7

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/s7"
)

// The policy on its own. Every case is driven through compile(), because a
// policy that only works when a test builds it by hand is one nobody can
// configure.

func compiled(t *testing.T, c *config.S7Listener) *policy {
	t.Helper()
	p, err := compile(c)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return p
}

// sess is a connection that has reached rack 0 slot 2 as a programming
// device, which is what an engineering station opens.
func sess(rack, slot int, resource uint8) *Session {
	return &Session{IP: netip.MustParseAddr("10.0.7.9"), Rack: rack, Slot: slot,
		Resource: resource, Addressed: true, At: time.Now()}
}

// pdu parses what the builders produce, out of the TPKT and COTP wrappers.
func pdu(t *testing.T, frame []byte) *wire.PDU {
	t.Helper()
	c, err := wire.ParseCOTP(frame[wire.TPKTHeader:])
	if err != nil {
		t.Fatal(err)
	}
	p, err := wire.ParseS7(c.Data)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The default posture: an HMI can do its work, and nothing can change the
// controller.
func TestTheDefaultReadsAndChangesNothing(t *testing.T) {
	p := compiled(t, &config.S7Listener{Upstream: "plc", DefaultAction: "allow"})
	s := sess(0, 2, wire.ResourcePG)
	for _, c := range []struct {
		name  string
		frame []byte
		allow bool
	}{
		{"the negotiation", setupJob(1, 480), true},
		{"a read", readJob(1, item(wire.TransportByte, 20, 1, wire.AreaDB, 0)), true},
		{"a system status list", userData(1, wire.GroupCPU, 0x01), true},
		{"the block list", userData(1, wire.GroupBlock, 0x01), true},
		{"reading the clock", userData(1, wire.GroupTime, 0x01), true},
		{"a cyclic subscription", userData(1, wire.GroupCyclic, 0x01), true},
		// Everything that changes the PLC.
		{"a write", writeJob(1, item(wire.TransportByte, 1, 1, wire.AreaDB, 0),
			wire.TransportByte, []byte{1}), false},
		{"a stop", stopJob(1), false},
		{"a control service", controlJob(1, "_INSE"), false},
		{"a download", downloadJob(1, "08", 10), false},
		{"setting the clock", userData(1, wire.GroupTime, 0x02), false},
		{"a password", userData(1, wire.GroupSecurity, 0x01), false},
		{"forcing a variable", userData(1, wire.GroupProgrammer, 0x08), false},
		{"a mode transition", userData(1, wire.GroupMode, 0x01), false},
		// And the read that takes the plant's logic with it.
		{"an upload", uploadJob(1, "08", 10), false},
	} {
		d := p.Request(s, pdu(t, c.frame))
		if d.Allow != c.allow {
			t.Errorf("%s: allow = %v (%s %s), want %v", c.name, d.Allow, d.Reason, d.Detail, c.allow)
		}
	}
}

// The operations that change the controller are refused even in monitor mode.
func TestWhatChangesThePLCIsNeverShadowed(t *testing.T) {
	p := compiled(t, &config.S7Listener{Upstream: "plc", MonitorOnly: true, DefaultAction: "allow"})
	s := sess(0, 2, wire.ResourcePG)
	for _, c := range []struct {
		name  string
		frame []byte
		hard  bool
	}{
		{"a write", writeJob(1, item(wire.TransportByte, 1, 1, wire.AreaDB, 0),
			wire.TransportByte, []byte{1}), true},
		{"a stop", stopJob(1), true},
		{"a download", downloadJob(1, "08", 1), true},
		{"forcing a variable", userData(1, wire.GroupProgrammer, 0x08), true},
		{"setting the clock", userData(1, wire.GroupTime, 0x02), true},
		{"a password", userData(1, wire.GroupSecurity, 0x01), true},
		// An upload changes nothing, so a trial run may see it happen --
		// which is what monitor mode is for.
		{"an upload", uploadJob(1, "08", 1), false},
		{"the numerical control layer", userData(1, wire.GroupNC, 0x01), false},
	} {
		d := p.Request(s, pdu(t, c.frame))
		if d.Allow {
			t.Errorf("%s was allowed", c.name)
			continue
		}
		if d.Hard != c.hard {
			t.Errorf("%s: hard = %v, want %v", c.name, d.Hard, c.hard)
		}
	}
}

// read_only is the commonest requirement on a plant, and a rule cannot widen
// it.
func TestReadOnlyCannotBeWidenedByARule(t *testing.T) {
	p := compiled(t, &config.S7Listener{Upstream: "plc", ReadOnly: true, DefaultAction: "allow",
		Rules: []config.S7Rule{{Name: "everything", Operations: []string{"read", "write", "stop"}}},
	})
	s := sess(0, 2, wire.ResourcePG)
	if d := p.Request(s, pdu(t, readJob(1, item(wire.TransportByte, 4, 1, wire.AreaDB, 0)))); !d.Allow {
		t.Errorf("a read was refused on a read-only listener: %s", d.Reason)
	}
	for _, c := range []struct {
		name  string
		frame []byte
	}{
		{"a write", writeJob(1, item(wire.TransportByte, 1, 1, wire.AreaDB, 0),
			wire.TransportByte, []byte{1})},
		{"a stop", stopJob(1)},
	} {
		d := p.Request(s, pdu(t, c.frame))
		if d.Allow || d.Reason != "read_only" || !d.Hard {
			t.Errorf("%s: allow=%v %s hard=%v", c.name, d.Allow, d.Reason, d.Hard)
		}
	}
}

// The memory boundary inside the CPU: the area, the data block and the byte
// range.
func TestTheAddressPolicyCoversTheWholeSpan(t *testing.T) {
	p := compiled(t, &config.S7Listener{Upstream: "plc", DefaultAction: "allow",
		Areas: []string{"db", "inputs"}, DBs: []string{"1-10"}, Addresses: []string{"0-99"}})
	s := sess(0, 2, wire.ResourcePG)
	read := func(count uint16, db uint16, area uint8, at int) Decision {
		return p.Request(s, pdu(t, readJob(1, item(wire.TransportByte, count, db, area, at))))
	}
	if d := read(20, 1, wire.AreaDB, 0); !d.Allow {
		t.Errorf("a read inside the policy was refused: %s %s", d.Reason, d.Detail)
	}
	// The span, not the start: a read of a hundred bytes from byte 50 ends
	// at 149, which is outside a range of 0 to 99.
	d := read(100, 1, wire.AreaDB, 50)
	if d.Allow || d.Reason != "address_not_allowed" {
		t.Errorf("a read running off the end of the range: allow=%v %s", d.Allow, d.Reason)
	}
	// A word count is two octets each, which is the arithmetic the span
	// rests on: sixty words from byte 0 is a hundred and twenty octets.
	if d := p.Request(s, pdu(t, readJob(1, item(wire.TransportWord, 60, 1, wire.AreaDB, 0)))); d.Allow {
		t.Error("sixty words passed a range of a hundred bytes")
	}
	if d := read(4, 11, wire.AreaDB, 0); d.Allow || d.Reason != "db_not_allowed" {
		t.Errorf("DB11 outside the list: allow=%v %s", d.Allow, d.Reason)
	}
	if d := read(4, 0, wire.AreaFlags, 0); d.Allow || d.Reason != "area_not_allowed" {
		t.Errorf("the flags outside the list: allow=%v %s", d.Allow, d.Reason)
	}
	// Every item of a multi-item read is checked, not the first.
	many := readJob(1,
		item(wire.TransportByte, 4, 1, wire.AreaDB, 0),
		item(wire.TransportByte, 4, 1, wire.AreaDB, 4),
		item(wire.TransportByte, 4, 99, wire.AreaDB, 0))
	if d := p.Request(s, pdu(t, many)); d.Allow || d.Detail != "DB99" {
		t.Errorf("the third item of a read: allow=%v %s %s", d.Allow, d.Reason, d.Detail)
	}
	// A deny list wins over an allow list, and `peripheral` is the one worth
	// denying: it is direct access to the I/O hardware, past the process
	// image the program reads.
	p2 := compiled(t, &config.S7Listener{Upstream: "plc", DefaultAction: "allow",
		Operations: []string{"read", "write"}, DenyAreas: []string{"peripheral"}})
	if d := p2.Request(s, pdu(t, readJob(1, item(wire.TransportByte, 1, 0, wire.AreaDirectPeriph, 0)))); d.Allow {
		t.Error("a read of the peripheral area was allowed")
	}
}

// write_addresses is how one listener allows a wide read and a narrow write.
func TestTheWriteRangeIsSeparateFromTheReadRange(t *testing.T) {
	p := compiled(t, &config.S7Listener{Upstream: "plc", DefaultAction: "allow",
		Operations:     []string{"read", "write"},
		Addresses:      []string{"0-999"},
		WriteAddresses: []string{"100-199"}})
	s := sess(0, 2, wire.ResourcePG)
	if d := p.Request(s, pdu(t, readJob(1, item(wire.TransportByte, 10, 1, wire.AreaDB, 500)))); !d.Allow {
		t.Errorf("a read inside the read range was refused: %s", d.Reason)
	}
	write := func(at int) Decision {
		return p.Request(s, pdu(t, writeJob(1, item(wire.TransportByte, 2, 1, wire.AreaDB, at),
			wire.TransportByte, []byte{1, 2})))
	}
	if d := write(100); !d.Allow {
		t.Errorf("a write inside the write range was refused: %s %s", d.Reason, d.Detail)
	}
	d := write(500)
	if d.Allow || d.Reason != "address_not_allowed" || !d.Hard {
		t.Errorf("a write outside the write range: allow=%v %s hard=%v", d.Allow, d.Reason, d.Hard)
	}
}

// The rack and the slot arrive in the connection request, before any S7
// request exists.
func TestTheConnectionRequestDecidesWhichControllerIsReached(t *testing.T) {
	p := compiled(t, &config.S7Listener{Upstream: "plc", Racks: []string{"0"},
		Slots: []string{"2"}, Resources: []string{"op"}})
	parse := func(frame []byte) *wire.COTP {
		c, err := wire.ParseCOTP(frame[wire.TPKTHeader:])
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	s := &Session{IP: netip.MustParseAddr("10.0.7.9"), At: time.Now()}
	if d := p.Connection(s, parse(connectionRequest(wire.ResourceOP, 0, 2))); !d.Allow {
		t.Errorf("the allowed CPU was refused: %s %s", d.Reason, d.Detail)
	}
	if !s.Addressed || s.Rack != 0 || s.Slot != 2 || s.Resource != wire.ResourceOP {
		t.Errorf("the session was addressed as %+v", s)
	}
	for _, c := range []struct {
		name     string
		resource uint8
		rack     int
		slot     int
		reason   string
	}{
		{"another rack", wire.ResourceOP, 1, 2, "rack_not_allowed"},
		{"another slot", wire.ResourceOP, 0, 3, "slot_not_allowed"},
		{"a programming device", wire.ResourcePG, 0, 2, "resource_not_allowed"},
	} {
		s := &Session{IP: netip.MustParseAddr("10.0.7.9"), At: time.Now()}
		d := p.Connection(s, parse(connectionRequest(c.resource, c.rack, c.slot)))
		if d.Allow || d.Reason != c.reason {
			t.Errorf("%s: allow=%v %s, want %s", c.name, d.Allow, d.Reason, c.reason)
		}
		if !d.Hard {
			t.Errorf("%s: the refusal was shadowable", c.name)
		}
	}
	// A frame that is not a connection request at all.
	s2 := &Session{IP: netip.MustParseAddr("10.0.7.9"), At: time.Now()}
	dt := parse(readJob(1, item(wire.TransportByte, 1, 1, wire.AreaDB, 0)))
	if d := p.Connection(s2, dt); d.Allow || d.Reason != "not_a_connection_request" {
		t.Errorf("a data PDU as the first frame: allow=%v %s", d.Allow, d.Reason)
	}
	// A TSAP this relay cannot read as a rack and a slot, with a policy
	// about racks in force: refused rather than read as rack zero.
	long := func() *wire.COTP {
		params := join([]byte{0xc2, 12}, []byte("SIMATIC-ROOT"))
		body := join(be16b(0), be16b(1), []byte{0x00}, params)
		return parse(tpkt(join([]byte{uint8(len(body) + 1), wire.COTPConnectionRequest}, body)))
	}()
	s3 := &Session{IP: netip.MustParseAddr("10.0.7.9"), At: time.Now()}
	if d := p.Connection(s3, long); d.Allow || d.Reason != "destination_unreadable" {
		t.Errorf("an unreadable TSAP: allow=%v %s", d.Allow, d.Reason)
	}
	// And with no policy about racks, a TSAP of another shape is ordinary:
	// plenty of equipment addresses a CPU by name.
	open := compiled(t, &config.S7Listener{Upstream: "plc"})
	s4 := &Session{IP: netip.MustParseAddr("10.0.7.9"), At: time.Now()}
	if d := open.Connection(s4, long); !d.Allow {
		t.Errorf("a named TSAP was refused with no rack policy: %s", d.Reason)
	}
}

func TestTheBoundsAreEnforced(t *testing.T) {
	p := compiled(t, &config.S7Listener{Upstream: "plc", DefaultAction: "allow",
		Operations: []string{"read", "write", "setup"},
		MaxItems:   2, MaxReadBytes: 64, MaxWriteBytes: 8, MaxPDULength: 480})
	s := sess(0, 2, wire.ResourcePG)
	three := readJob(1,
		item(wire.TransportByte, 1, 1, wire.AreaDB, 0),
		item(wire.TransportByte, 1, 1, wire.AreaDB, 1),
		item(wire.TransportByte, 1, 1, wire.AreaDB, 2))
	if d := p.Request(s, pdu(t, three)); d.Allow || d.Reason != "too_many_items" || !d.Hard {
		t.Errorf("three items against a bound of two: allow=%v %s hard=%v", d.Allow, d.Reason, d.Hard)
	}
	if d := p.Request(s, pdu(t, readJob(1, item(wire.TransportByte, 100, 1, wire.AreaDB, 0)))); d.Allow ||
		d.Reason != "too_many_bytes" {
		t.Errorf("a hundred octets against a read bound of 64: allow=%v %s", d.Allow, d.Reason)
	}
	big := writeJob(1, item(wire.TransportByte, 16, 1, wire.AreaDB, 0), wire.TransportByte,
		make([]byte, 16))
	if d := p.Request(s, pdu(t, big)); d.Allow || d.Reason != "too_many_bytes" {
		t.Errorf("sixteen octets against a write bound of eight: allow=%v %s", d.Allow, d.Reason)
	}
	// The negotiated PDU length, refused rather than rewritten.
	if d := p.Setup(480); !d.Allow {
		t.Errorf("the allowed length was refused: %s", d.Reason)
	}
	if d := p.Setup(960); d.Allow || d.Reason != "pdu_length_too_large" || !d.Hard {
		t.Errorf("960 against a bound of 480: allow=%v %s hard=%v", d.Allow, d.Reason, d.Hard)
	}
}

// A request this relay cannot read is refused rather than forwarded.
func TestWhatCannotBeReadIsRefused(t *testing.T) {
	p := compiled(t, &config.S7Listener{Upstream: "plc", DefaultAction: "allow",
		Operations: []string{"read", "write"}, Areas: []string{"db"}})
	s := sess(0, 2, wire.ResourcePG)

	// A function code nobody documents.
	unknown := job(1, []byte{0x77, 0x00}, nil)
	if d := p.Request(s, pdu(t, unknown)); d.Allow || d.Reason != "operation_unknown" || !d.Hard {
		t.Errorf("an unknown function: allow=%v %s hard=%v", d.Allow, d.Reason, d.Hard)
	}
	// An item list that does not lay out: a count of two with one item.
	short := job(1, join([]byte{wire.FnReadVar, 2}, item(wire.TransportByte, 1, 1, wire.AreaDB, 0)), nil)
	if d := p.Request(s, pdu(t, short)); d.Allow || d.Reason != "items_unreadable" || !d.Hard {
		t.Errorf("a short item list: allow=%v %s hard=%v", d.Allow, d.Reason, d.Hard)
	}
	// An item whose syntax is not the addressing form, with an address
	// policy in force: it is the one item the policy could not check.
	sym := job(1, join([]byte{wire.FnReadVar, 1},
		[]byte{0x12, 0x08, wire.SyntaxSym1200, 0, 0, 0, 0, 0, 0, 0}), nil)
	if d := p.Request(s, pdu(t, sym)); d.Allow || d.Reason != "item_not_addressable" {
		t.Errorf("a symbolic item: allow=%v %s", d.Allow, d.Reason)
	}
	// With no address policy at all, the same item is ordinary: a 1200
	// talking to itself does this all day.
	open := compiled(t, &config.S7Listener{Upstream: "plc", DefaultAction: "allow"})
	if d := open.Request(s, pdu(t, sym)); !d.Allow {
		t.Errorf("a symbolic item with no address policy was refused: %s", d.Reason)
	}
	// An acknowledgement from the client's side is not a request.
	ack := ackData(1, 0, 0, []byte{wire.FnReadVar, 1}, nil)
	if d := p.Request(s, pdu(t, ack)); d.Allow || d.Reason != "unexpected_message" {
		t.Errorf("an acknowledgement from a client: allow=%v %s", d.Allow, d.Reason)
	}
}

func TestTheBlockTypePolicy(t *testing.T) {
	p := compiled(t, &config.S7Listener{Upstream: "plc", DefaultAction: "allow",
		Operations: []string{"upload", "download"}, BlockTypes: []string{"db"}})
	s := sess(0, 2, wire.ResourcePG)
	if d := p.Request(s, pdu(t, uploadJob(1, "08", 10))); !d.Allow {
		t.Errorf("an upload of a data block was refused: %s %s", d.Reason, d.Detail)
	}
	// A function block is the program, and this listener names only data
	// blocks.
	d := p.Request(s, pdu(t, uploadJob(1, "0E", 1)))
	if d.Allow || d.Reason != "block_type_not_allowed" {
		t.Errorf("an upload of a function block: allow=%v %s", d.Allow, d.Reason)
	}
	// A download of one is refused hard, because a downloaded block is a
	// different program running.
	d2 := p.Request(s, pdu(t, downloadJob(1, "0E", 1)))
	if d2.Allow || !d2.Hard {
		t.Errorf("a download of a function block: allow=%v hard=%v", d2.Allow, d2.Hard)
	}
	// The PDUs that follow the first one carry data rather than a name, and
	// refusing them would refuse every transfer.
	rest := job(1, []byte{wire.FnDownloadBlock, 0x00}, []byte("program"))
	if d := p.Request(s, pdu(t, rest)); !d.Allow {
		t.Errorf("a transfer PDU with no block name was refused: %s", d.Reason)
	}
}

func TestARuleNarrowsAndWidensForItsOwnTraffic(t *testing.T) {
	p := compiled(t, &config.S7Listener{Upstream: "plc",
		Rules: []config.S7Rule{
			{
				Name: "integrator", Clients: []string{"10.0.7.9/32"},
				Operations: []string{"read", "write", "download", "setup"},
				Areas:      []string{"db"}, DBs: []string{"100-199"},
				Comment:  "change request CR-2291",
				Schedule: &config.ModbusSchedule{Days: []string{"sun"}, From: "02:00", To: "06:00"},
			},
			{Name: "everybody", Operations: []string{"read", "setup"}, Areas: []string{"db"}},
		},
	})
	within := sess(0, 2, wire.ResourcePG)
	within.At = time.Date(2026, 3, 1, 3, 0, 0, 0, time.UTC) // a Sunday, 03:00
	write := writeJob(1, item(wire.TransportByte, 1, 100, wire.AreaDB, 0), wire.TransportByte, []byte{1})
	d := p.Request(within, pdu(t, write))
	if !d.Allow || d.Rule != "integrator" {
		t.Errorf("the integrator's write in the window: allow=%v %s rule=%q", d.Allow, d.Reason, d.Rule)
	}
	if d.Comment != "change request CR-2291" {
		t.Errorf("the rule's comment was %q", d.Comment)
	}
	// The same write outside the window.
	outside := sess(0, 2, wire.ResourcePG)
	outside.At = time.Date(2026, 3, 3, 15, 0, 0, 0, time.UTC)
	if d := p.Request(outside, pdu(t, write)); d.Allow || d.Reason != "outside_schedule" {
		t.Errorf("outside the window: allow=%v %s", d.Allow, d.Reason)
	}
	// Another address gets the second rule, which allows reading and
	// nothing else.
	other := &Session{IP: netip.MustParseAddr("10.0.7.10"), Rack: 0, Slot: 2,
		Resource: wire.ResourcePG, Addressed: true, At: time.Now()}
	if d := p.Request(other, pdu(t, readJob(1, item(wire.TransportByte, 4, 1, wire.AreaDB, 0)))); !d.Allow {
		t.Errorf("another client's read was refused: %s %s", d.Reason, d.Detail)
	}
	if d := p.Request(other, pdu(t, write)); d.Allow {
		t.Error("another client's write was allowed")
	}
	// A rule that names racks never matches a connection whose address this
	// relay could not read.
	rackRule := compiled(t, &config.S7Listener{Upstream: "plc",
		Rules: []config.S7Rule{{Name: "cpu", Racks: []string{"0"}, Operations: []string{"read"}}}})
	unaddressed := &Session{IP: netip.MustParseAddr("10.0.7.9"), At: time.Now()}
	if d := rackRule.Request(unaddressed, pdu(t, readJob(1,
		item(wire.TransportByte, 4, 1, wire.AreaDB, 0)))); d.Allow {
		t.Error("a rule about rack 0 matched a connection with no rack")
	}
}

func TestACompileErrorIsAConfigurationError(t *testing.T) {
	for _, c := range []struct {
		name string
		cfg  *config.S7Listener
		want string
	}{
		{"an operation nobody defines", &config.S7Listener{Upstream: "plc",
			Operations: []string{"reed"}}, "not an S7 operation"},
		{"an area nobody defines", &config.S7Listener{Upstream: "plc",
			Areas: []string{"registers"}}, "not a memory area"},
		{"a resource nobody defines", &config.S7Listener{Upstream: "plc",
			Resources: []string{"engineer"}}, "not a connection resource"},
		{"a block type nobody defines", &config.S7Listener{Upstream: "plc",
			BlockTypes: []string{"ob"}}, "not a block type"},
		{"a rack outside its three bits", &config.S7Listener{Upstream: "plc",
			Racks: []string{"9"}}, "outside 0 to 7"},
		{"a slot outside its five", &config.S7Listener{Upstream: "plc",
			Slots: []string{"32"}}, "outside 0 to 31"},
		{"a range that starts after it ends", &config.S7Listener{Upstream: "plc",
			Addresses: []string{"100-10"}}, "starts after it ends"},
		{"a client address that is not one", &config.S7Listener{Upstream: "plc",
			AllowClients: []string{"10.0.0.1"}}, "allow_clients"},
		{"a default action nobody defines", &config.S7Listener{Upstream: "plc",
			DefaultAction: "maybe"}, "not allow or deny"},
		{"a rule action nobody defines", &config.S7Listener{Upstream: "plc",
			Rules: []config.S7Rule{{Name: "r", Action: "maybe"}}}, "not allow, deny or observe"},
	} {
		_, err := compile(c.cfg)
		if err == nil {
			t.Errorf("%s: compiled", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
}
