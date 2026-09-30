package opcua

import (
	"net/netip"
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/opcua"
)

// The translation: what a service call's service, node and user look like to
// the shared models.
func TestTheModelsSeeTheServiceAndTheNode(t *testing.T) {
	now := time.Now()
	ip := netip.MustParseAddr("10.30.0.4")
	c := &conn{ip: ip}
	c.update(func(s *Session) { s.User = "line-hmi" })

	node := RefOf(wire.NodeId{Namespace: 2, Kind: wire.String, Text: "Line1.Setpoint"})
	e := anomalyEvent(c, &wire.ServiceCall{Service: wire.SvcWrite},
		[]Operation{{Node: node, Attr: wire.AttrValue, Write: true}}, now)
	if e.Actor != ip || !e.Write {
		t.Errorf("a write reads as %+v", e)
	}
	if e.Device != "line-hmi" {
		t.Errorf("the session's user is the device here, got %q", e.Device)
	}
	if e.Symbol != wire.SvcWrite.String() || e.Point != node.Key {
		t.Errorf("symbol %q point %q", e.Symbol, e.Point)
	}

	// A method call carries the method in the symbol, because "Call" on its own
	// says almost nothing and the method is what happened.
	method := RefOf(wire.NodeId{Namespace: 2, Kind: wire.String, Text: "Recipe.Load"})
	call := anomalyEvent(c, &wire.ServiceCall{Service: wire.SvcCall},
		[]Operation{{Node: node, Write: true, Method: &method}}, now)
	if call.Symbol != wire.SvcCall.String()+" "+method.Key {
		t.Errorf("a Call reads as symbol %q", call.Symbol)
	}

	// A service with no operations is still a symbol.
	bare := anomalyEvent(c, &wire.ServiceCall{Service: wire.SvcCreateSubscription}, nil, now)
	if bare.Symbol != wire.SvcCreateSubscription.String() || bare.Point != "" || bare.Write {
		t.Errorf("a service with no operations reads as %+v", bare)
	}
	// And the value models are inert: this relay reads a Write's nodes and
	// attributes, not the variant a value arrives as.
	if e.HasValue || call.HasValue {
		t.Error("a value the relay cannot have was reported")
	}
}

func TestNoBlockIsNoDetector(t *testing.T) {
	var s server
	if _, _, done := s.anomalyCheck(&conn{}, nil, &wire.ServiceCall{}, nil); done {
		t.Error("a listener with no anomaly block refused a call")
	}
}
