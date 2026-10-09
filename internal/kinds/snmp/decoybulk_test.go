package snmp

import (
	"testing"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/snmp"
)

// GETBULK against the decoy, which is where this protocol's amplification
// lives: one small request names a number of repetitions, and the answer is
// that number of objects per binding. A decoy that honoured whatever a
// request asked for would be a reflector somebody else points at a victim,
// and the fields it is asked in are signed integers off the network.

func bulkDecoy(t *testing.T) *decoy {
	t.Helper()
	on := true
	d, err := newDecoy(&config.SNMPDeception{Enabled: &on, Mode: "decoy", SysName: "sw-1"}, "snmp")
	if err != nil {
		t.Fatal(err)
	}
	if d == nil {
		t.Fatal("no decoy was built")
	}
	return d
}

func namedOID(t *testing.T, s string) wire.OID {
	t.Helper()
	o, err := wire.ParseOID(s)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

// bulkRequest is a GETBULK as it arrives: the non-repeater and repetition
// counts share the error fields' positions, so they are signed integers a
// client chose.
func bulkRequest(t *testing.T, nonRepeaters, reps int64, oids ...string) *wire.Message {
	t.Helper()
	binds := make([]wire.VarBind, 0, len(oids))
	for _, s := range oids {
		binds = append(binds, wire.VarBind{OID: namedOID(t, s)})
	}
	return &wire.Message{Version: wire.V2c, PDU: &wire.PDU{
		Type: wire.GetBulkRequest, RequestID: 1,
		NonRepeaters: nonRepeaters, MaxRepetitions: reps, VarBinds: binds,
	}}
}

// TestTheDecoyAnswersAGetBulkTheWayAnAgentDoes: the non-repeaters once each,
// then the repeaters round by round, which is the order RFC 3416 gives and
// the order a manager's walk depends on.
func TestTheDecoyAnswersAGetBulkTheWayAnAgentDoes(t *testing.T) {
	d := bulkDecoy(t)
	// One non-repeater and two repeaters, three rounds.
	m := bulkRequest(t, 1, 3, "1.3.6.1.2.1.1.1", "1.3.6.1.2.1.1.3", "1.3.6.1.2.1.2.2.1.1")
	out := d.bulk(m, 0, 0)
	if len(out) != 1+2*3 {
		t.Fatalf("a bulk of one non-repeater and two repeaters over three rounds answered %d bindings", len(out))
	}
	for i, b := range out {
		if len(b) == 0 {
			t.Errorf("binding %d is empty", i)
		}
	}
}

// TestTheRepetitionCountIsTheAmplificationBound: what the listener was
// configured to allow wins over what the request asked for. This is the
// whole of the reflection defence on this protocol.
func TestTheRepetitionCountIsTheAmplificationBound(t *testing.T) {
	d := bulkDecoy(t)
	// A request asking for a thousand rounds of one repeater, against a
	// listener that allows two.
	m := bulkRequest(t, 0, 1000, "1.3.6.1.2.1.1.1")
	if out := d.bulk(m, 2, 0); len(out) != 2 {
		t.Errorf("a thousand repetitions bounded at two answered %d bindings", len(out))
	}
	// And the response size bound stops it mid-round rather than after it.
	m = bulkRequest(t, 0, 1000, "1.3.6.1.2.1.1.1", "1.3.6.1.2.1.1.3")
	if out := d.bulk(m, 100, 5); len(out) != 5 {
		t.Errorf("a bulk bounded at five bindings answered %d", len(out))
	}
}

// TestACountThatIsNotACountIsReadAsNone: both fields are signed and come off
// the network. A negative repetition count once meant a loop that did not
// run, and a negative non-repeater count an index into a slice from the
// wrong end -- so each is read as none rather than trusted.
func TestACountThatIsNotACountIsReadAsNone(t *testing.T) {
	d := bulkDecoy(t)
	for _, tc := range []struct {
		name               string
		nonRepeaters, reps int64
		oids               []string
		want               int
	}{
		{name: "a negative repetition count", nonRepeaters: 0, reps: -5,
			oids: []string{"1.3.6.1.2.1.1.1"}, want: 0},
		{name: "a negative non-repeater count", nonRepeaters: -3, reps: 1,
			oids: []string{"1.3.6.1.2.1.1.1"}, want: 1},
		// More non-repeaters than there are bindings: the count is clamped
		// to what arrived rather than read past the end of it.
		{name: "more non-repeaters than bindings", nonRepeaters: 9, reps: 2,
			oids: []string{"1.3.6.1.2.1.1.1", "1.3.6.1.2.1.1.3"}, want: 2},
		{name: "no bindings at all", nonRepeaters: 2, reps: 4, oids: nil, want: 0},
	} {
		m := bulkRequest(t, tc.nonRepeaters, tc.reps, tc.oids...)
		if out := d.bulk(m, 0, 0); len(out) != tc.want {
			t.Errorf("%s answered %d bindings, want %d", tc.name, len(out), tc.want)
		}
	}
}

// TestAWalkOffTheEndOfTheDeviceSaysSoAndStops: a manager walking past the
// last object is told end-of-view once per repeater and the rounds stop. A
// real agent does that; repeating it a thousand times is both wrong and the
// amplification the bound above exists to prevent.
func TestAWalkOffTheEndOfTheDeviceSaysSoAndStops(t *testing.T) {
	d := bulkDecoy(t)
	// An OID past everything this device has.
	m := bulkRequest(t, 0, 50, "1.3.6.1.4.1.99999.1")
	out := d.bulk(m, 0, 0)
	if len(out) != 1 {
		t.Fatalf("a walk off the end answered %d bindings, want the one end-of-view", len(out))
	}
	// And with a non-repeater past the end as well, each is answered once.
	m = bulkRequest(t, 1, 50, "1.3.6.1.4.1.99999.1", "1.3.6.1.4.1.99999.2")
	if out := d.bulk(m, 0, 0); len(out) != 2 {
		t.Errorf("two bindings off the end answered %d", len(out))
	}
}
