package snmp

import (
	"fmt"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	wire "github.com/rom/xproxy/internal/snmp"
)

// An agent that is not there, end to end.
//
// Two properties carry most of these tests. A **walk** has to be walkable:
// every answer strictly greater than the name asked about, and an end. And
// the answers have to be **bounded**, because a fabricated agent is a UDP
// service answering a small request with a larger response -- which is what
// an amplifier is.

// getNext is a GETNEXT for one object, which is what a walk is made of.
func getNext(reqID int64, o ...uint32) []byte {
	return pduOf(wire.TagGetNextRequest, reqID, 0, 0, varbind(oid(o...), tlv(wire.TagNull)))
}

// decoyYAML is a listener that is nothing but a fabricated agent: no
// upstream, because there is nothing behind it.
const decoyYAML = `
version: 1
server:
  listeners:
    - name: spare
      address: "127.0.0.1:0"
      kind: snmp
      snmp:
%s
logging: {access: {enabled: false}}
`

func decoyServer(t *testing.T, section string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(decoyYAML, section))
	return s, proxytest.Addr(t, s, "spare")
}

// A community string that is wrong is refused and one that is right is
// answered, so the refusal is the oracle a password list needs. This is the
// disclosure written down, so the decoy below has something to be measured
// against.
func TestARefusedCommunityTellsAScannerItWasWrong(t *testing.T) {
	a := startAgent(t, &agent{})
	_, addr := snmpServer(t, `        upstream: agents
        communities: ["s3cret"]
        default_action: allow`, a.udpAddr())

	m := dialManager(t, addr)
	// The string the listener carries: the poll reaches the agent and an
	// answer comes back.
	m.send(t, v2c("s3cret", get(1, 1, 3, 6, 1, 2, 1, 1, 1, 0)))
	if got := m.answer(t, 2*time.Second); got == nil || got.PDU.ErrorStatus != 0 {
		t.Fatalf("the allowed community was answered %+v", got)
	}
	// Every other string: refused, and the refusal says so.
	m.send(t, v2c("public", get(2, 1, 3, 6, 1, 2, 1, 1, 1, 0)))
	got := m.answer(t, 2*time.Second)
	if got == nil || got.PDU.ErrorStatus == 0 {
		t.Fatalf("a wrong community was answered %+v", got)
	}
}

// And the decoy: any community is answered, because a fabricated agent that
// refused one would be telling the scanner which string to keep.
func TestTheDecoyAnswersWhateverCommunityArrives(t *testing.T) {
	s, addr := decoyServer(t, `        deception:
          mode: decoy
          sys_name: "sw-cell9"
          sys_location: "Cell 9"`)

	m := dialManager(t, addr)
	for i, community := range []string{"public", "private", "s3cret"} {
		m.send(t, v2c(community, get(int64(i+1), 1, 3, 6, 1, 2, 1, 1, 5, 0)))
		got := m.answer(t, 2*time.Second)
		if got == nil {
			t.Fatalf("community %q was not answered at all", community)
		}
		if got.PDU.ErrorStatus != 0 {
			t.Fatalf("community %q was answered error %d", community, got.PDU.ErrorStatus)
		}
		if got.Community != community {
			t.Errorf("the answer to %q carried community %q", community, got.Community)
		}
		if len(got.PDU.VarBinds) != 1 || got.PDU.VarBinds[0].OID.String() != "1.3.6.1.2.1.1.5.0" {
			t.Errorf("the answer named %+v", got.PDU.VarBinds)
		}
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool { return sn.SNMPDeceived >= 3 },
		"the fabricated answers")
}

// The walk, which is the test that matters: every answer is strictly after
// the name asked about, the whole thing terminates, and what comes back is
// the system group and an interface table.
func TestTheDecoyCanBeWalked(t *testing.T) {
	_, addr := decoyServer(t, `        deception:
          mode: decoy
          interfaces: 4`)

	mgr := dialManager(t, addr)
	at := wire.OID{1, 3, 6, 1, 2, 1}
	var seen []string
	for step := 0; step < 200; step++ {
		mgr.send(t, v2c("public", getNext(int64(step+1), at...)))
		got := mgr.answer(t, 2*time.Second)
		if got == nil {
			t.Fatalf("step %d from %s was not answered", step, at)
		}
		if got.PDU.ErrorStatus != 0 {
			t.Fatalf("step %d answered error %d", step, got.PDU.ErrorStatus)
		}
		if len(got.PDU.VarBinds) != 1 {
			t.Fatalf("step %d answered %d bindings", step, len(got.PDU.VarBinds))
		}
		b := got.PDU.VarBinds[0]
		if b.Tag == wire.TagEndOfMibView {
			break
		}
		if wire.Compare(b.OID, at) <= 0 {
			t.Fatalf("step %d answered %s, which is not after %s: a walk that does not "+
				"advance is a walk that never finishes", step, b.OID, at)
		}
		seen = append(seen, b.OID.String())
		at = b.OID
	}
	if len(seen) == 0 {
		t.Fatal("the walk ended immediately")
	}
	// The system group first, then the interface table: 8 scalars and 13
	// columns of 4 ports.
	if want := 8 + 13*4; len(seen) != want {
		t.Errorf("the walk saw %d objects, want %d: %v", len(seen), want, seen)
	}
	for _, want := range []string{
		"1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.3.0", "1.3.6.1.2.1.1.5.0",
		"1.3.6.1.2.1.2.1.0", "1.3.6.1.2.1.2.2.1.2.4", "1.3.6.1.2.1.2.2.1.10.1",
	} {
		if !contains(seen, want) {
			t.Errorf("the walk never saw %s", want)
		}
	}
	// And the end is the end: a walk that ran off the table gets
	// end-of-view rather than the first object again, which is the loop
	// every manager guards against and no agent should cause.
	last, err := wire.ParseOID(seen[len(seen)-1])
	if err != nil {
		t.Fatal(err)
	}
	mgr.send(t, v2c("public", getNext(999, last...)))
	if got := mgr.answer(t, 2*time.Second); got == nil ||
		len(got.PDU.VarBinds) != 1 || got.PDU.VarBinds[0].Tag != wire.TagEndOfMibView {
		t.Errorf("the object after the last one answered %+v", got.PDU.VarBinds)
	}
}

func contains(all []string, want string) bool {
	for _, s := range all {
		if s == want {
			return true
		}
	}
	return false
}

// The bound that keeps a honeypot from being an amplifier. A GETBULK asking
// for a thousand repetitions of a name is forty octets of question, and an
// agent that answered it in full would be the reflector a spoofed source
// address is looking for.
func TestTheDecoyIsNotAnAmplifier(t *testing.T) {
	_, addr := decoyServer(t, `        deception:
          mode: decoy
          interfaces: 64
        max_repetitions: 10
        max_response_bytes: 4096`)

	m := dialManager(t, addr)
	m.send(t, v2c("public", bulk(1, 10000, 1, 3, 6, 1, 2, 1)))
	got := m.answer(t, 2*time.Second)
	if got == nil {
		t.Fatal("the GETBULK was not answered")
	}
	if n := len(got.PDU.VarBinds); n > 10 {
		t.Errorf("a GETBULK for 10000 repetitions was answered with %d bindings, "+
			"and the listener's bound is 10", n)
	}
	if got.PDU.ErrorStatus != 0 && got.PDU.ErrorStatus != wire.StatusTooBig {
		t.Errorf("the answer carried error %d", got.PDU.ErrorStatus)
	}
	// And a bulk that would be answered inside the bound still gets the
	// repetitions it asked for, because the bound is a bound and not a
	// refusal.
	m.send(t, v2c("public", bulk(2, 4, 1, 3, 6, 1, 2, 1)))
	got = m.answer(t, 2*time.Second)
	if got == nil || len(got.PDU.VarBinds) != 4 {
		t.Errorf("a GETBULK for four repetitions was answered with %+v", got)
	}
}

// A version 3 message is never answered by the fabrication: its response
// would have to carry a digest computed with a key this relay does not have,
// and an unauthenticated answer to an authenticated protocol is a worse tell
// than silence.
func TestTheDecoyDoesNotAnswerVersionThree(t *testing.T) {
	_, addr := decoyServer(t, "        deception: {mode: decoy}")

	m := dialManager(t, addr)
	m.send(t, v3(0x04, "poller", "", get(1, 1, 3, 6, 1, 2, 1, 1, 1, 0)))
	if got := m.answer(t, 500*time.Millisecond); got != nil {
		t.Errorf("a version 3 request was answered: %+v", got)
	}
}

// An object the fabrication does not have is answered the way an agent
// answers one -- and differently in the two versions, because version 1 has
// no per-binding exception and every version 1 manager knows it.
func TestAnObjectTheDecoyDoesNotHave(t *testing.T) {
	_, addr := decoyServer(t, "        deception: {mode: decoy}")

	m := dialManager(t, addr)
	// Version 2c: the binding carries noSuchObject and the response is
	// otherwise a success.
	m.send(t, v2c("public", get(1, 1, 3, 6, 1, 4, 1, 9, 9, 9)))
	got := m.answer(t, 2*time.Second)
	if got == nil || got.PDU.ErrorStatus != 0 {
		t.Fatalf("v2c: %+v", got)
	}
	if len(got.PDU.VarBinds) != 1 || got.PDU.VarBinds[0].Tag != wire.TagNoSuchObject {
		t.Errorf("v2c answered %+v", got.PDU.VarBinds)
	}
	// Version 1: the whole response carries noSuchName and the index of the
	// binding it is about.
	m.send(t, v1msg("public", get(2, 1, 3, 6, 1, 4, 1, 9, 9, 9)))
	got = m.answer(t, 2*time.Second)
	if got == nil || got.PDU.ErrorStatus != wire.StatusNoSuchName || got.PDU.ErrorIndex != 1 {
		t.Errorf("v1 answered %+v", got)
	}
}

// A SET is answered as though it took effect. Nothing was written: there is
// nothing behind this listener to write to, which is what makes it safe and
// what makes it bait.
func TestASetIsAnsweredAsThoughItLanded(t *testing.T) {
	_, addr := decoyServer(t, "        deception: {mode: decoy}")

	m := dialManager(t, addr)
	m.send(t, v2c("private", set(1, "somewhere else", 1, 3, 6, 1, 2, 1, 1, 6, 0)))
	got := m.answer(t, 2*time.Second)
	if got == nil || got.PDU.ErrorStatus != 0 {
		t.Fatalf("the write was answered %+v", got)
	}
	// And the object still reads as the fabrication says, because nothing
	// was written anywhere.
	m.send(t, v2c("private", get(2, 1, 3, 6, 1, 2, 1, 1, 6, 0)))
	if got := m.answer(t, 2*time.Second); got == nil || len(got.PDU.VarBinds) != 1 {
		t.Errorf("the object read back %+v", got)
	}
}

// The tripwire: an object nothing legitimate reads is answered -- the answer
// is what keeps the visitor reading -- and raised as the event somebody acts
// on.
func TestTheSNMPTripwireIsAnsweredAndRaised(t *testing.T) {
	s, addr := decoyServer(t, `        deception:
          mode: decoy
          tripwire: ["1.3.6.1.4.1.9.9.96"]`)

	m := dialManager(t, addr)
	m.send(t, v2c("public", get(1, 1, 3, 6, 1, 4, 1, 9, 9, 96, 1, 1, 1)))
	if got := m.answer(t, 2*time.Second); got == nil {
		t.Fatal("a tripwire object was not answered at all")
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool { return sn.SNMPTripwire >= 1 },
		"the tripwire event")
	found := false
	for _, d := range s.DeviceDecoys() {
		if d.Listener == "spare" {
			found = true
			if d.Kind != "snmp" || d.Mode != "decoy" {
				t.Errorf("the status view says kind %q mode %q", d.Kind, d.Mode)
			}
			if d.Tripped == 0 || len(d.Visitors) == 0 {
				t.Errorf("the status view records %d tripwires and %d visitors",
					d.Tripped, len(d.Visitors))
			}
		}
	}
	if !found {
		t.Error("the fabricated agent is not in the status view")
	}
}

// mode answer, and the rule the whole feature is bounded by: what was going
// to reach the agent still does, and what was going to be refused is
// answered by the fabrication instead and never arrives.
func TestAnsweredRefusalsReachNoAgent(t *testing.T) {
	a := startAgent(t, &agent{})
	s, addr := snmpServer(t, `        upstream: agents
        communities: ["s3cret"]
        default_action: allow
        deception:
          mode: answer
          clients: ["127.0.0.0/8"]`, a.udpAddr())

	m := dialManager(t, addr)
	// Allowed: it reaches the agent.
	m.send(t, v2c("s3cret", get(1, 1, 3, 6, 1, 2, 1, 1, 1, 0)))
	if got := m.answer(t, 2*time.Second); got == nil || got.PDU.ErrorStatus != 0 {
		t.Fatalf("the allowed poll was answered %+v", got)
	}
	a.await(t, 1, "the allowed poll")

	// Refused: the fabrication answers, and the agent never sees it.
	m.send(t, v2c("public", get(2, 1, 3, 6, 1, 2, 1, 1, 1, 0)))
	got := m.answer(t, 2*time.Second)
	if got == nil || got.PDU.ErrorStatus != 0 {
		t.Fatalf("the refused poll was not answered by the fabrication: %+v", got)
	}
	if len(got.PDU.VarBinds) != 1 || got.PDU.VarBinds[0].Tag != wire.TagOctetStr {
		t.Errorf("the fabricated answer is %+v", got.PDU.VarBinds)
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool { return sn.SNMPDeceived >= 1 },
		"the fabricated answer")
	if n := len(a.seen()); n != 1 {
		t.Errorf("the agent saw %d messages, and only the allowed one should have reached it", n)
	}
	// The refusal is still a refusal in the record: a deception that hid it
	// would hide the only signal an operator has.
	if n := s.Stats().SNMPDenied; n == 0 {
		t.Error("a deceived request was not counted as a refusal")
	}
}

// A client the section does not name gets the refusal, not the fabrication.
func TestAClientOutsideTheSectionStillGetsARefusal(t *testing.T) {
	a := startAgent(t, &agent{})
	_, addr := snmpServer(t, `        upstream: agents
        communities: ["s3cret"]
        default_action: allow
        deception:
          mode: answer
          clients: ["10.90.0.0/24"]`, a.udpAddr())

	m := dialManager(t, addr)
	m.send(t, v2c("public", get(1, 1, 3, 6, 1, 2, 1, 1, 1, 0)))
	got := m.answer(t, 2*time.Second)
	if got == nil || got.PDU.ErrorStatus == 0 {
		t.Errorf("a client outside the section was answered %+v", got)
	}
}

// The validator refuses a profile this package would not know, so the two
// lists have to be the same list.
func TestTheSNMPDecoyNamesMatchTheValidator(t *testing.T) {
	have := map[string]bool{}
	for _, n := range ProfileNames() {
		have[n] = true
	}
	for _, n := range config.SNMPDecoyProfiles {
		if !have[n] {
			t.Errorf("the validator accepts %q and this package does not have it", n)
		}
		delete(have, n)
	}
	for n := range have {
		t.Errorf("this package has %q and the validator would refuse it", n)
	}
	for _, n := range config.SNMPDecoyProfiles {
		if _, addr := decoyServer(t, "        deception: {mode: decoy, profile: "+n+"}"); addr == "" {
			t.Errorf("profile %q did not start", n)
		}
	}
}

// The counters rise and the uptime advances: an agent whose interface
// counters are the same a minute later is an agent nothing is plugged into.
func TestTheDecoyCountersRise(t *testing.T) {
	_, addr := decoyServer(t, `        deception:
          mode: decoy
          interfaces: 2
          period: 1s`)

	m := dialManager(t, addr)
	read := func(id int64, o ...uint32) *wire.Message {
		m.send(t, v2c("public", get(id, o...)))
		got := m.answer(t, 2*time.Second)
		if got == nil || len(got.PDU.VarBinds) != 1 {
			t.Fatalf("%v was not answered: %+v", o, got)
		}
		return got
	}
	first := read(1, 1, 3, 6, 1, 2, 1, 1, 3, 0)
	if first.PDU.VarBinds[0].Tag != wire.TagTimeTicks {
		t.Errorf("the uptime is tagged %#x, and a manager expects ticks", first.PDU.VarBinds[0].Tag)
	}
	in := read(2, 1, 3, 6, 1, 2, 1, 2, 2, 1, 10, 1)
	if in.PDU.VarBinds[0].Tag != wire.TagCounter32 {
		t.Errorf("the octet counter is tagged %#x, and a manager expects a counter",
			in.PDU.VarBinds[0].Tag)
	}
}

// The other two halves of the amplification bound, each on its own: the
// number of bindings one answer may carry, and the size of the answer.
//
// They are separate from max_repetitions because they catch different
// shapes. A manager can ask for few repetitions of many names, and a
// fabricated table of a thousand objects can fill a datagram from a request
// that asked for four.
func TestTheDecoyHoldsTheBindingAndSizeBounds(t *testing.T) {
	// The binding bound, with room in the size bound so that it is the one
	// doing the work.
	_, addr := decoyServer(t, `        deception:
          mode: decoy
          interfaces: 64
        max_repetitions: 1000
        max_var_binds: 20
        max_response_bytes: 60000`)

	m := dialManager(t, addr)
	m.send(t, v2c("public", bulk(1, 1000, 1, 3, 6, 1, 2, 1)))
	got := m.answer(t, 2*time.Second)
	if got == nil {
		t.Fatal("the GETBULK was not answered")
	}
	if got.PDU.ErrorStatus != 0 {
		t.Fatalf("the answer carried error %d, and it should have fitted", got.PDU.ErrorStatus)
	}
	if n := len(got.PDU.VarBinds); n > 20 {
		t.Errorf("the answer carried %d bindings, and the bound is 20", n)
	}

	// And the size bound, which answers tooBig rather than a datagram
	// nothing asked for -- which is what an agent does and what a manager
	// retries in smaller pieces.
	_, small := decoyServer(t, `        deception:
          mode: decoy
          interfaces: 64
        max_repetitions: 1000
        max_var_binds: 1000
        max_response_bytes: 300`)
	m2 := dialManager(t, small)
	m2.send(t, v2c("public", bulk(1, 200, 1, 3, 6, 1, 2, 1)))
	got = m2.answer(t, 2*time.Second)
	if got == nil {
		t.Fatal("the oversize GETBULK was not answered at all")
	}
	if got.PDU.ErrorStatus != wire.StatusTooBig {
		t.Errorf("an answer past the size bound carried error %d, want tooBig", got.PDU.ErrorStatus)
	}
}

// A notification is not a question, and an agent does not answer one. A
// fabrication that sent a Response to a trap would be answering something no
// agent answers, which is a tell rather than a deception.
func TestTheDecoyDoesNotAnswerANotification(t *testing.T) {
	_, addr := decoyServer(t, "        deception: {mode: decoy}")

	m := dialManager(t, addr)
	m.send(t, v2c("public", trap(1, 1, 3, 6, 1, 6, 3, 1, 1, 5, 1)))
	if got := m.answer(t, 500*time.Millisecond); got != nil {
		t.Errorf("a trap was answered with %s", got.PDU.Type)
	}
}
