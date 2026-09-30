package mms

import (
	"net/netip"
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/mms"
)

// The translation, which on this protocol is the richest of any kind: the
// object names carry the semantics, so the functional constraint belongs in the
// symbol and not only in the point.
func TestTheModelsSeeTheServiceAndTheFunctionalConstraint(t *testing.T) {
	now := time.Now()
	ip := netip.MustParseAddr("10.20.0.5")
	c := &conn{ip: ip}

	oper := wire.ParseItem("XCBR1$CO$Pos$Oper")
	oper.Kind = wire.NameDomain
	oper.Domain = "AA1J1Q01A1LD0"
	e := anomalyEvent(c, &wire.Message{HasService: true, Service: wire.SvcWrite},
		[]Operation{{Name: oper, Write: true}}, now)
	if e.Actor != ip || !e.Write {
		t.Errorf("a write reads as %+v", e)
	}
	if e.Point != oper.Key() {
		t.Errorf("point %q", e.Point)
	}
	if e.Device != "AA1J1Q01A1LD0" {
		t.Errorf("the logical device is %q", e.Device)
	}
	// $CO$ is a control write and $CF$ is a configuration change, and a model
	// that called both "Write" would have thrown away what the protocol says.
	if e.Symbol != wire.SvcWrite.String()+" CO" {
		t.Errorf("symbol %q", e.Symbol)
	}

	// A service with no objects is still a symbol: a client that has never
	// asked for a directory and now does is worth a line.
	bare := anomalyEvent(c, &wire.Message{HasService: true, Service: wire.SvcGetNameList}, nil, now)
	if bare.Symbol != wire.SvcGetNameList.String() || bare.Point != "" || bare.Write {
		t.Errorf("a service with no objects reads as %+v", bare)
	}

	// And the value models are inert here: an MMS data value is typed data
	// whose type is in the SCL this listener does not have.
	if e.HasValue || bare.HasValue {
		t.Error("a value the relay cannot have was reported")
	}
}

func TestNoBlockIsNoDetector(t *testing.T) {
	var s server
	if got := s.decideAnomaly(&conn{}, &wire.Message{}, nil); got != "" {
		t.Errorf("a listener with no anomaly block refused %q", got)
	}
}
