package coap

import (
	"net/netip"
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/coap"
)

// The translation: what a CoAP request's method, path and security name look
// like to the shared models.
func TestTheModelsSeeTheMethodAndThePath(t *testing.T) {
	now := time.Now()
	ip := netip.MustParseAddr("192.0.2.10")

	for _, c := range []struct {
		code  wire.Code
		write bool
	}{
		{wire.GET, false},
		{wire.PUT, true},
		{wire.POST, true},
		{wire.DELETE, true},
	} {
		m := &wire.Message{Code: c.code, Options: []wire.Option{
			{Number: wire.OptionURIPath, Value: []byte("3303")},
			{Number: wire.OptionURIPath, Value: []byte("0")},
			{Number: wire.OptionURIPath, Value: []byte("5700")},
		}}
		e := anomalyEvent(request{from: ip, msg: m, identity: "boiler-3", at: now}, now)
		if e.Actor != ip || e.Device != "boiler-3" {
			t.Errorf("%s reads as %+v", c.code, e)
		}
		if e.Symbol != c.code.String() {
			t.Errorf("%s: symbol %q", c.code, e.Symbol)
		}
		if e.Point != "/3303/0/5700" {
			t.Errorf("%s: point %q", c.code, e.Point)
		}
		if e.Write != c.write {
			t.Errorf("%s: write=%v", c.code, e.Write)
		}
		// The two value models are inert here: a CoAP payload is CBOR or a
		// vendor's own encoding, and this relay does not decode it.
		if e.HasValue {
			t.Errorf("%s carried a value the relay cannot have: %v", c.code, e.Value)
		}
	}
}

func TestNoBlockIsNoDetector(t *testing.T) {
	var s server
	if got := s.decideAnomaly(request{msg: &wire.Message{Code: wire.GET}}); got != "" {
		t.Errorf("a listener with no anomaly block refused %q", got)
	}
}
