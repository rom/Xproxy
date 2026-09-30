package snmp

import (
	"net/netip"
	"testing"
	"time"
)

// The translation: what an SNMP message's PDU type, credential and first
// binding look like to the shared models.
func TestTheModelsSeeThePDUTypeAndTheOID(t *testing.T) {
	now := time.Now()
	ip := netip.MustParseAddr("10.0.0.7")

	// A GET on the system tree, under a community string.
	e := anomalyEvent(request{client: ip, msg: parse(v2c("public", get(1, 1, 3, 6, 1, 2, 1, 1, 1)))}, now)
	if e.Actor != ip || e.Write {
		t.Errorf("a get reads as %+v", e)
	}
	if e.Symbol != "get" {
		t.Errorf("symbol %q", e.Symbol)
	}
	if e.Device != "public" {
		t.Errorf("the credential is the device on this protocol, got %q", e.Device)
	}
	if e.Point != "1.3.6.1.2.1.1.1" {
		t.Errorf("point %q", e.Point)
	}

	// A SET is a write: on network and field equipment it is a configuration
	// change, which is what this protocol's writes are.
	e = anomalyEvent(request{client: ip,
		msg: parse(v2c("private", set(2, "x", 1, 3, 6, 1, 2, 1, 1, 5)))}, now)
	if !e.Write || e.Symbol != "set" || e.Device != "private" {
		t.Errorf("a set reads as %+v", e)
	}

	// A version 3 message's device is its USM user rather than a community.
	e = anomalyEvent(request{client: ip,
		msg: parse(v3(0, "poller", "", get(3, 1, 3, 6, 1, 2, 1, 1, 1)))}, now)
	if e.Device != "poller" {
		t.Errorf("a v3 message's device is %q", e.Device)
	}

	// The two value models are inert: a binding's tag is read and not
	// interpreted, because a policy about SNMP values would need a MIB.
	if e.HasValue {
		t.Error("a value the relay cannot have was reported")
	}
}

func TestNoBlockIsNoDetector(t *testing.T) {
	var s server
	if got := s.decideAnomaly(request{}); got != "" {
		t.Errorf("a listener with no anomaly block refused %q", got)
	}
}
