package s7

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	wire "github.com/rom/xproxy/internal/s7"
)

// A controller that is not there, end to end.
//
// The assertions are the same pair the rest of this file makes: what the client
// was told, and what the controller saw. For deception the second half is the
// important one -- a fabricated answer that also reached the PLC would be the
// worst of both -- so every test here that has a real controller behind it
// asserts the request never arrived.

// szlJob is a read of a system status list, which is the first thing every
// asset scanner asks for.
func szlJob(ref uint16, id, index uint16) []byte {
	param := join([]byte{0x00, 0x01, 0x12, 0x04},
		[]byte{0x11, wire.UserRequest<<4 | wire.GroupCPU, 0x01, 0x00})
	data := join([]byte{0xff, 0x09}, be16b(4), be16b(id), be16b(index))
	return tpktData(join([]byte{wire.ProtocolID, byte(wire.Userdata), 0, 0}, be16b(ref),
		be16b(uint16(len(param))), be16b(uint16(len(data))), param, data))
}

// decoyYAML is a listener that is nothing but a fabricated controller: no
// upstream, because there is nothing behind it.
const decoyYAML = `
version: 1
server:
  listeners:
    - name: spare
      address: "127.0.0.1:0"
      kind: s7
      s7:
%s
logging: {access: {enabled: false}}
`

func decoyFor(t *testing.T, section string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(decoyYAML, section))
	return s, proxytest.Addr(t, s, "spare")
}

// readItems reads the values out of a read acknowledgement, one per item.
func readItems(t *testing.T, pdu *wire.PDU) [][]byte {
	t.Helper()
	if len(pdu.Param) < 2 || pdu.Param[0] != wire.FnReadVar {
		t.Fatalf("not a read acknowledgement: %s", describe(pdu))
	}
	var out [][]byte
	b := pdu.Data
	for i := 0; i < int(pdu.Param[1]); i++ {
		if len(b) < 4 {
			t.Fatalf("item %d: a data item of %d octets", i, len(b))
		}
		code, transport, n := b[0], b[1], int(binary.BigEndian.Uint16(b[2:4]))
		if transport == answerBit || transport == answerByte {
			n = (n + 7) / 8
		}
		if code != itemOK {
			out = append(out, nil)
			b = b[4:]
			continue
		}
		if len(b) < 4+n {
			t.Fatalf("item %d: %d octets declared and %d left", i, n, len(b)-4)
		}
		out = append(out, b[4:4+n])
		b = b[4+n:]
		if n%2 == 1 && i != int(pdu.Param[1])-1 {
			b = b[1:] // the fill octet
		}
	}
	return out
}

// szlText is the text a system status list answer carries, which is what a
// scanner prints.
func szlText(t *testing.T, pdu *wire.PDU) string {
	t.Helper()
	if len(pdu.Data) < 12 {
		t.Fatalf("a system status list answer of %d octets", len(pdu.Data))
	}
	if pdu.Data[0] != itemOK {
		t.Fatalf("the answer's return code is %#x", pdu.Data[0])
	}
	return string(pdu.Data)
}

// A sweep of data block numbers is how this protocol gives up a controller,
// and the listener's own refusal is what draws the map. This is the
// disclosure written down, so the decoy below has something to be measured
// against.
func TestASweepOfDataBlocksMapsTheController(t *testing.T) {
	plc := startPLC(t, &fakePLC{})
	_, addr := relayFor(t, base+"        dbs: [\"1\"]\n", plc.addr())

	cl := dial(t, addr)
	cl.connect(0x02, 0, 2)
	// The block the policy names: answered.
	cl.allowed(readJob(2, item(wire.TransportByte, 4, 1, wire.AreaDB, 0)))
	// Every other block: refused, and the refusal is the answer a scanner
	// wanted.
	for _, db := range []uint16{2, 3, 100} {
		pdu := cl.refused(readJob(3, item(wire.TransportByte, 4, db, wire.AreaDB, 0)))
		if pdu.ErrClass != accessFault {
			t.Fatalf("DB%d was refused with error class %#x", db, pdu.ErrClass)
		}
	}
}

// And the decoy: every block it claims reads back, the blocks it does not
// claim answer the way a CPU answers one it does not have, and the two system
// status lists a scanner reads carry an identity.
func TestTheDecoyAnswersAsAController(t *testing.T) {
	s, addr := decoyFor(t, `        deception:
          mode: decoy
          profile: generic-s7-300
          order_number: "6ES7 315-2EH14-0AB0"
          plant: "CELL4"`)

	cl := dial(t, addr)
	cl.connect(0x02, 0, 2)

	// The negotiation settles on a length a classic CPU offers.
	cl.write(setupJob(2, 480))
	pdu, _ := cl.next()
	_, _, length, ok := pdu.Setup()
	if !ok {
		t.Fatalf("the negotiation was answered with %s", describe(pdu))
	}
	if length != 240 {
		t.Errorf("the fabrication negotiated %d, and this profile is a 300", length)
	}

	// A block it has, read twice inside one period: the same value, because
	// a register that reads differently twice in a row is not a process.
	first := readItems(t, cl.allowed(readJob(3, item(wire.TransportByte, 8, 1, wire.AreaDB, 0))))
	again := readItems(t, cl.allowed(readJob(4, item(wire.TransportByte, 8, 1, wire.AreaDB, 0))))
	if len(first) != 1 || len(first[0]) != 8 {
		t.Fatalf("the read answered %d items, the first of %d octets", len(first), len(first[0]))
	}
	if string(first[0]) != string(again[0]) {
		t.Errorf("DB1 read %x then %x inside one period", first[0], again[0])
	}

	// A block it does not have: object does not exist, which is what a CPU
	// says, and the honest limit on a fabrication -- a controller with 65535
	// data blocks is not a controller.
	missing := readItems(t, cl.allowed(readJob(5, item(wire.TransportByte, 4, 900, wire.AreaDB, 0))))
	if len(missing) != 1 || missing[0] != nil {
		t.Errorf("DB900 answered %x, and this fabrication does not have it", missing[0])
	}

	// A read past the end of a block it does have: an address error.
	over := cl.allowed(readJob(6, item(wire.TransportByte, 8, 1, wire.AreaDB, 4090)))
	if len(over.Data) < 1 || over.Data[0] != itemAddress {
		t.Errorf("a read past the end of DB1 answered %#x", over.Data[0])
	}

	// The two lists a scanner reads.
	id := szlText(t, cl.allowed(szlJob(7, szlModule, 1)))
	if !strings.Contains(id, "6ES7 315-2EH14-0AB0") {
		t.Errorf("the module identification list carries no order number: %q", id)
	}
	comp := szlText(t, cl.allowed(szlJob(8, szlComponent, 0)))
	for _, want := range []string{"CPU 315-2 PN/DP", "CELL4"} {
		if !strings.Contains(comp, want) {
			t.Errorf("the component identification list is missing %q: %q", want, comp)
		}
	}

	// A write is acknowledged and goes nowhere: there is nowhere for it to
	// go.
	w := cl.allowed(writeJob(9, item(wire.TransportByte, 2, 1, wire.AreaDB, 0),
		wire.TransportByte, []byte{0x01, 0x02}))
	if len(w.Data) != 1 || w.Data[0] != itemOK {
		t.Errorf("the write was answered %x", w.Data)
	}

	// And a function a fabrication cannot honestly offer: an upload has to
	// have something to upload.
	if pdu := cl.refused(uploadJob(10, "DB", 1)); pdu.ErrClass != accessFault {
		t.Errorf("an upload was refused with error class %#x", pdu.ErrClass)
	}

	await(t, s, func(sn proxy.Snapshot) bool { return sn.S7Deceived >= 8 }, "the fabricated answers")
	// The status view says who arrived.
	found := false
	for _, d := range s.DeviceDecoys() {
		if d.Listener == "spare" {
			found = true
			if d.Kind != "s7" || d.Mode != "decoy" {
				t.Errorf("the status view says kind %q mode %q", d.Kind, d.Mode)
			}
			if len(d.Visitors) == 0 {
				t.Error("the status view records no visitor")
			}
		}
	}
	if !found {
		t.Error("the fabricated controller is not in the status view")
	}
}

// await polls a counter condition, because the counters are incremented on the
// relay's own goroutines.
func await(t *testing.T, s *proxy.Server, ok func(proxy.Snapshot) bool, what string) {
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

// A value that never moves is a device nothing drives, and a totaliser that
// goes backwards is the tell that ends the pretence.
func TestTheDecoyValuesMoveAndTheTotalsOnlyRise(t *testing.T) {
	_, addr := decoyFor(t, `        deception:
          mode: decoy
          period: 1s
          blocks:
            - {dbs: "1-2", bytes: 64}
          bands:
            - {addresses: "0-31", shape: analogue, min: 0, max: 27648}
            - {addresses: "32-63", shape: counter, rate: 5}`)

	cl := dial(t, addr)
	cl.connect(0x02, 0, 2)
	cl.write(setupJob(2, 480))
	cl.next()

	read := func(ref uint16, at int) []byte {
		return readItems(t, cl.allowed(readJob(ref, item(wire.TransportByte, 8, 1, wire.AreaDB, at))))[0]
	}
	firstAnalogue, firstTotal := read(3, 0), read(4, 32)
	// Two blocks do not read the same, which they would if the value came
	// from the address alone.
	other := readItems(t, cl.allowed(readJob(5, item(wire.TransportByte, 8, 2, wire.AreaDB, 0))))[0]
	if string(other) == string(firstAnalogue) {
		t.Error("DB1 and DB2 read the same at the same address")
	}
	moved := false
	deadline := time.Now().Add(6 * time.Second)
	for ref := uint16(6); time.Now().Before(deadline) && !moved; ref += 2 {
		time.Sleep(300 * time.Millisecond)
		if string(read(ref, 0)) != string(firstAnalogue) {
			moved = true
		}
		later := read(ref+1, 32)
		for i := 0; i+2 <= len(later); i += 2 {
			now := binary.BigEndian.Uint16(later[i : i+2])
			was := binary.BigEndian.Uint16(firstTotal[i : i+2])
			// The totals are 16-bit and wrap, so a fall of more than half
			// the space is the wrap and anything else is a fall.
			if now < was && was-now < 0x8000 {
				t.Fatalf("a total went backwards: %d then %d", was, now)
			}
		}
	}
	if !moved {
		t.Error("no value moved between periods")
	}
}

// The tripwire: a data block nothing legitimate reads is answered, because the
// answer is what keeps the visitor reading, and raised as the event somebody
// acts on.
func TestTheS7TripwireIsAnsweredAndRaised(t *testing.T) {
	s, addr := decoyFor(t, `        deception:
          mode: decoy
          blocks:
            - {dbs: "1-8", bytes: 256}
            - {dbs: "666", bytes: 256}
          tripwire: ["666"]`)

	cl := dial(t, addr)
	cl.connect(0x02, 0, 2)
	cl.write(setupJob(2, 480))
	cl.next()
	got := readItems(t, cl.allowed(readJob(3, item(wire.TransportByte, 4, 666, wire.AreaDB, 0))))
	if len(got) != 1 || got[0] == nil {
		t.Fatal("a tripwire block was not answered")
	}
	await(t, s, func(sn proxy.Snapshot) bool { return sn.S7Tripwire >= 1 }, "the tripwire event")
}

// mode answer, and the rule the whole feature is bounded by: what was going to
// reach the controller still does, and what was going to be refused is
// answered by the fabrication instead and never arrives.
func TestAnsweredRefusalsReachNoController(t *testing.T) {
	plc := startPLC(t, &fakePLC{})
	s, addr := relayFor(t, base+`        dbs: ["1"]
        deception:
          mode: answer
          clients: ["127.0.0.0/8"]
          blocks:
            - {dbs: "1-16", bytes: 512}
          tripwire: ["9"]
`, plc.addr())

	cl := dial(t, addr)
	cl.connect(0x02, 0, 2)
	reads := plc.count("read")

	// Allowed: it reaches the controller.
	cl.allowed(readJob(2, item(wire.TransportByte, 4, 1, wire.AreaDB, 0)))
	waitFor(t, func() bool { return plc.count("read") == reads+1 })

	// Refused: answered by the fabrication, and the controller never sees
	// it.
	got := readItems(t, cl.allowed(readJob(3, item(wire.TransportByte, 4, 9, wire.AreaDB, 0))))
	if len(got) != 1 || got[0] == nil {
		t.Fatalf("a refused read was not answered by the fabrication: %x", got)
	}
	await(t, s, func(sn proxy.Snapshot) bool {
		return sn.S7Deceived >= 1 && sn.S7Tripwire >= 1
	}, "the deception and the tripwire")
	if plc.count("read") != reads+1 {
		t.Errorf("a deceived read reached the controller: %d reads", plc.count("read"))
	}
	// The refusal is still a refusal in the record: a deception that also
	// hid the refusal would hide the only signal an operator has.
	if n := s.Stats().Refusals["s7"]["db_not_allowed"]; n == 0 {
		t.Errorf("a deceived request was not counted as a refusal: %v", s.Stats().Refusals["s7"])
	}
}

// A client the section does not name gets the access fault, not the
// fabrication.
func TestAClientOutsideTheSectionStillGetsAnAccessFault(t *testing.T) {
	plc := startPLC(t, &fakePLC{})
	_, addr := relayFor(t, base+`        dbs: ["1"]
        deception:
          mode: answer
          clients: ["10.90.0.0/24"]
`, plc.addr())

	cl := dial(t, addr)
	cl.connect(0x02, 0, 2)
	if pdu := cl.refused(readJob(2, item(wire.TransportByte, 4, 9, wire.AreaDB, 0))); pdu.ErrClass != accessFault {
		t.Errorf("a client outside the section was answered with error class %#x", pdu.ErrClass)
	}
}

// A fabrication claiming to be a 300 or a 400 does not speak S7comm-plus: the
// families that do are the 1200 and the 1500, so answering it would be the
// contradiction that ends the pretence.
func TestTheDecoyDoesNotSpeakS7CommPlus(t *testing.T) {
	_, addr := decoyFor(t, "        deception: {mode: decoy}")

	cl := dial(t, addr)
	cl.connect(0x02, 0, 2)
	cl.write(plusFrame(wire.PlusRequest, 0x04bb))
	if _, c := cl.next(); c.Type != wire.COTPDisconnectRequest {
		t.Errorf("an S7comm-plus request was answered with %s", c.TypeName())
	}
}

// The validator refuses a profile or a shape this package would not know, so
// the lists have to be the same lists.
func TestTheS7DecoyNamesMatchTheValidator(t *testing.T) {
	same := func(what string, mine, theirs []string) {
		t.Helper()
		have := map[string]bool{}
		for _, n := range mine {
			have[n] = true
		}
		for _, n := range theirs {
			if !have[n] {
				t.Errorf("%s: the validator accepts %q and this package does not have it", what, n)
			}
			delete(have, n)
		}
		for n := range have {
			t.Errorf("%s: this package has %q and the validator would refuse it", what, n)
		}
	}
	same("profiles", ProfileNames(), config.S7DecoyProfiles)
	same("shapes", DecoyShapes, config.S7DecoyShapes)

	for _, n := range config.S7DecoyProfiles {
		if _, addr := decoyFor(t, "        deception: {mode: decoy, profile: "+n+"}"); addr == "" {
			t.Errorf("profile %q did not start", n)
		}
	}
}

// szlBlock reads a system status list answer apart: the identifier, the
// index, the record length and the records.
//
// The lengths are the part that has to be right. A client steps through the
// records by the length the answer declares, so a list whose count does not
// agree with what it carries is a list a library reads past the end of -- and
// the two lists here are exactly the exchange every scanner makes.
func szlBlock(t *testing.T, pdu *wire.PDU) (id, index uint16, records [][]byte) {
	t.Helper()
	if len(pdu.Data) < 12 {
		t.Fatalf("a system status list answer of %d octets", len(pdu.Data))
	}
	if pdu.Data[0] != itemOK {
		t.Fatalf("the answer's return code is %#x", pdu.Data[0])
	}
	declared := int(binary.BigEndian.Uint16(pdu.Data[2:4]))
	block := pdu.Data[4:]
	if declared != len(block) {
		t.Fatalf("the answer declares %d octets and carries %d", declared, len(block))
	}
	id = binary.BigEndian.Uint16(block[0:2])
	index = binary.BigEndian.Uint16(block[2:4])
	recLen := int(binary.BigEndian.Uint16(block[4:6]))
	count := int(binary.BigEndian.Uint16(block[6:8]))
	rest := block[8:]
	if recLen == 0 {
		t.Fatal("the answer declares a record length of zero")
	}
	if count*recLen != len(rest) {
		t.Fatalf("the answer declares %d records of %d octets and carries %d octets",
			count, recLen, len(rest))
	}
	for at := 0; at+recLen <= len(rest); at += recLen {
		records = append(records, rest[at:at+recLen])
	}
	return id, index, records
}

// The parts of the fabrication a scanner and a client library check and the
// first tests did not: the lengths of the identification lists, the areas the
// controller does not claim to have, and the refusals that stay refusals in
// answer mode.
func TestTheFabricationIsAnswerableInDetail(t *testing.T) {
	_, addr := decoyFor(t, `        deception:
          mode: decoy
          profile: generic-s7-300
          blocks:
            - {dbs: "1-4", bytes: 256}`)

	cl := dial(t, addr)
	cl.connect(0x02, 0, 2)
	cl.write(setupJob(2, 480))
	cl.next()

	// The module identification list: one record, and it is the one asked
	// for.
	id, index, records := szlBlock(t, cl.allowed(szlJob(3, szlModule, 1)))
	if id != szlModule || index != 1 {
		t.Errorf("the answer is for list %#04x index %d", id, index)
	}
	if len(records) != 1 || len(records[0]) != 28 {
		t.Fatalf("%d records, the first of %d octets", len(records), len(records[0]))
	}
	if got := binary.BigEndian.Uint16(records[0][0:2]); got != 1 {
		t.Errorf("the record is for index %d", got)
	}
	// The firmware version, which is what a scanner prints beside the order
	// number: 3.2.7 for this profile. It sits after the index, the
	// twenty-character order number and the module type, which is where the
	// three consecutive octets a scanner reads are.
	if v := records[0][24:27]; v[0] != 3 || v[1] != 2 || v[2] != 7 {
		t.Errorf("the version octets are %v, want 3 2 7", v)
	}
	if got := string(records[0][2:22]); strings.TrimSpace(got) != "6ES7 315-2EH14-0AB0" {
		t.Errorf("the order number reads %q", got)
	}

	// The component identification list, asked for as a whole: several
	// records, each the length the answer declares.
	_, _, comps := szlBlock(t, cl.allowed(szlJob(4, szlComponent, 0)))
	if len(comps) < 4 {
		t.Errorf("%d component records, and a CPU reports more", len(comps))
	}
	for i, r := range comps {
		if len(r) != 34 {
			t.Errorf("component record %d is %d octets", i, len(r))
		}
	}
	// And one index alone, which is the other way a client asks.
	_, idx, one := szlBlock(t, cl.allowed(szlJob(5, szlComponent, 5)))
	if idx != 5 || len(one) != 1 {
		t.Errorf("index 5 answered index %d with %d records", idx, len(one))
	}

	// A list it does not have gets the answer a CPU gives for a function it
	// does not offer, rather than a fabricated list.
	cl.write(szlJob(6, 0x0132, 4))
	pdu, _ := cl.next()
	if u, ok := pdu.UserData(); !ok || !u.HasError || u.ErrCode == 0 {
		t.Errorf("an unknown system status list was answered %s", describe(pdu))
	}

	// A block it does not have, and a block it does read past the end of:
	// two different answers, because they are two different things and a
	// client's library says which.
	missing := cl.allowed(readJob(7, item(wire.TransportByte, 4, 900, wire.AreaDB, 0)))
	if len(missing.Data) < 1 || missing.Data[0] != itemNoObject {
		t.Errorf("a block it does not have answered %#x, want object-does-not-exist", missing.Data[0])
	}
	over := cl.allowed(readJob(8, item(wire.TransportByte, 8, 1, wire.AreaDB, 250)))
	if len(over.Data) < 1 || over.Data[0] != itemAddress {
		t.Errorf("a read past the end answered %#x, want an address error", over.Data[0])
	}

	// The direct peripheral area is access to the I/O hardware past the
	// process image. A fabrication that claimed it would be claiming
	// hardware, so it answers the way a CPU answers an area it does not
	// offer.
	periph := cl.allowed(readJob(9, item(wire.TransportByte, 2, 0, wire.AreaDirectPeriph, 0)))
	if len(periph.Data) < 1 || periph.Data[0] != itemNoObject {
		t.Errorf("the peripheral area answered %#x", periph.Data[0])
	}
	// The process image and the flags are ordinary, and they do answer.
	flags := readItems(t, cl.allowed(readJob(10, item(wire.TransportByte, 2, 0, wire.AreaFlags, 0))))
	if len(flags) != 1 || flags[0] == nil {
		t.Errorf("the flags answered %x", flags)
	}
}

// In answer mode only a read, a write and the identification lists are
// fabricated. Every other refused function keeps the access fault a protected
// CPU sends, because a fabrication that acknowledged a stop would be telling a
// client a machine had stopped.
func TestAnsweredRefusalsCoverOnlyWhatAFabricationCanAnswer(t *testing.T) {
	plc := startPLC(t, &fakePLC{})
	_, addr := relayFor(t, base+`        deny_operations: [stop, control, download]
        deception:
          mode: answer
          clients: ["127.0.0.0/8"]
`, plc.addr())

	cl := dial(t, addr)
	cl.connect(0x02, 0, 2)
	for _, tc := range []struct {
		what  string
		frame []byte
	}{
		{"a stop", stopJob(2)},
		{"a control", controlJob(3, "_INSE")},
		{"a download", downloadJob(4, "DB", 1)},
	} {
		pdu := cl.refused(tc.frame)
		if pdu.ErrClass != accessFault {
			t.Errorf("%s was answered with error class %#x, want the access fault", tc.what, pdu.ErrClass)
		}
	}
	if plc.got("stop") || plc.got("plc_control") {
		t.Errorf("a refused operation reached the controller: %v", plc.saws())
	}
}

// A refused write, in answer mode, is answered as a write: acknowledged item
// by item, with the function the client asked about. An answer carrying the
// other function is one a client's library will not pair with its request, so
// the client would read a refusal as a protocol fault -- and learn that
// something in the path is not a controller.
func TestAnsweredWritesAreAnsweredAsWrites(t *testing.T) {
	plc := startPLC(t, &fakePLC{})
	s, addr := relayFor(t, base+`        read_only: true
        deception:
          mode: answer
          clients: ["127.0.0.0/8"]
          blocks:
            - {dbs: "1-16", bytes: 512}
`, plc.addr())

	cl := dial(t, addr)
	cl.connect(0x02, 0, 2)
	pdu := cl.allowed(writeJob(2, item(wire.TransportByte, 2, 1, wire.AreaDB, 0),
		wire.TransportByte, []byte{0x01, 0x02}))
	if len(pdu.Param) < 2 || pdu.Param[0] != wire.FnWriteVar {
		t.Fatalf("a write was answered with %s", describe(pdu))
	}
	if len(pdu.Data) != 1 || pdu.Data[0] != itemOK {
		t.Errorf("the write was answered %x", pdu.Data)
	}
	// And it went nowhere, which is the point: read_only refused it.
	if plc.got("write") {
		t.Errorf("a deceived write reached the controller: %v", plc.saws())
	}
	await(t, s, func(sn proxy.Snapshot) bool { return sn.S7Deceived >= 1 }, "the fabricated answer")
}
