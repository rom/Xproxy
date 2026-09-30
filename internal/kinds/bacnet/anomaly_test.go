package bacnet

import (
	"net/netip"
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/bacnet"
)

// The translation is what is worth testing here: which of a BACnet request's
// fields the shared models see as a symbol, a device, a point and a write.
func TestTheModelsSeeTheServiceAndTheObject(t *testing.T) {
	now := time.Now()
	ip := netip.MustParseAddr("10.0.0.7")
	obj := wire.ObjectID{Type: wire.AnalogOutput, Instance: 3}

	writeSvc := wire.Service{Confirmed: true, Choice: wire.WriteProperty}
	write := request{client: ip, apdu: &wire.APDU{HasService: true, Service: writeSvc},
		targets: []wire.Target{{Object: obj, Property: wire.PropPresentValue, HasProperty: true}},
		located: true}
	e := anomalyEvent(write, now)
	if e.Actor != ip || e.Symbol != writeSvc.Name() || !e.Write {
		t.Errorf("a write reads as %+v", e)
	}
	if e.Device != obj.String() {
		t.Errorf("device %q", e.Device)
	}
	if want := obj.String() + "." + wire.PropPresentValue.String(); e.Point != want {
		t.Errorf("point %q, want %q", e.Point, want)
	}

	// A read of the same property is the same point and not a write.
	read := write
	read.apdu = &wire.APDU{HasService: true, Service: wire.Service{Confirmed: true, Choice: wire.ReadProperty}}
	if e := anomalyEvent(read, now); e.Write || e.Point == "" {
		t.Errorf("a read reads as %+v", e)
	}

	// A message with no application layer is still a symbol: the virtual link
	// function, which is what a BBMD registration arrives as.
	link := request{client: ip, fn: wire.FuncOriginalBroadcast}
	if e := anomalyEvent(link, now); e.Symbol != wire.FuncOriginalBroadcast.String() || e.Point != "" {
		t.Errorf("a link-layer message reads as %+v", e)
	}
	// And an unlocated target contributes no point, because a point this relay
	// could not find is one it must not claim to have seen.
	lost := write
	lost.located = false
	if e := anomalyEvent(lost, now); e.Point != "" {
		t.Errorf("an unlocated target produced point %q", e.Point)
	}
}

// The detector is off unless the block is, and a nil one is safe to ask.
func TestNoBlockIsNoDetector(t *testing.T) {
	var s server
	if got := s.decideAnomaly(request{}); got != "" {
		t.Errorf("a listener with no anomaly block refused %q", got)
	}
	if s.anomaly.On() {
		t.Error("a nil detector says it is on")
	}
}
