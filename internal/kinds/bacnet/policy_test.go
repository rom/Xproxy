package bacnet

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/bacnet"
	"github.com/rom/xproxy/internal/config"
)

func mustCompile(t *testing.T, c *config.BACnetListener) *policy {
	t.Helper()
	p, err := compile(c)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return p
}

// apdu builds a parsed request the policy can decide about, from the octets
// a client would send.
func apdu(t *testing.T, b []byte) (*wire.APDU, []wire.Target, bool) {
	t.Helper()
	a, err := wire.ParseAPDU(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	targets, located := wire.Targets(a)
	return &a, targets, located
}

func req(t *testing.T, b []byte) request {
	t.Helper()
	a, targets, located := apdu(t, b)
	return request{client: netip.MustParseAddr("127.0.0.1"), apdu: a,
		targets: targets, located: located, at: time.Now()}
}

// read and write build the two requests every test here starts from.
func read(o wire.ObjectID, p wire.PropertyID) []byte {
	b := []byte{0x00, 0x05, 0x01, wire.ReadProperty, 0x0C}
	b = append(b, o.Encode()...)
	return append(b, 0x19, byte(p))
}

func write(o wire.ObjectID, p wire.PropertyID, prio uint8) []byte {
	b := []byte{0x00, 0x05, 0x01, wire.WriteProperty, 0x0C}
	b = append(b, o.Encode()...)
	b = append(b, 0x19, byte(p))
	b = append(b, 0x3E, 0x44, 0x41, 0xA8, 0x00, 0x00, 0x3F)
	if prio > 0 {
		b = append(b, 0x49, prio)
	}
	return b
}

// An empty configuration carries reading and refuses everything that
// changes anything. This is the default that matters: a relay somebody put
// in front of a building without reading the manual.
func TestTheDefaultsCarryReadsAndRefuseChanges(t *testing.T) {
	p := mustCompile(t, &config.BACnetListener{Upstream: "devices", DefaultAction: "allow"})
	ai := wire.ObjectID{Type: wire.AnalogInput, Instance: 1}
	if d := p.Decide(req(t, read(ai, wire.PropPresentValue))); !d.Allow {
		t.Fatalf("a read was refused: %+v", d)
	}
	d := p.Decide(req(t, write(wire.ObjectID{Type: wire.AnalogOutput, Instance: 1}, wire.PropPresentValue, 0)))
	if d.Allow || d.Reason != "service_not_allowed" {
		t.Fatalf("a write was carried by the defaults: %+v", d)
	}
	// And the defaults refuse the link layer's own administration.
	for _, fn := range []wire.Function{wire.FuncRegisterForeignDevice, wire.FuncReadBDT,
		wire.FuncOriginalBroadcast, wire.FuncForwardedNPDU, wire.FuncSecureBVLL} {
		if d := p.Link(fn); d.Allow {
			t.Errorf("%s was carried by the defaults", fn)
		}
	}
	if d := p.Link(wire.FuncOriginalUnicast); !d.Allow {
		t.Error("an ordinary unicast was refused by the defaults")
	}
}

// The priority ladder, which is the control this protocol most needs. Lower
// is more privileged, and a bound of 8 refuses everything above it.
func TestTheCommandPriorityBoundRefusesTheLifeSafetySlots(t *testing.T) {
	p := mustCompile(t, &config.BACnetListener{Upstream: "d", DefaultAction: "allow",
		Services: []string{"writeProperty"}, MaxCommandPriority: 8})
	ao := wire.ObjectID{Type: wire.AnalogOutput, Instance: 1}
	for _, prio := range []uint8{1, 2, 3, 7} {
		d := p.Decide(req(t, write(ao, wire.PropPresentValue, prio)))
		if d.Allow {
			t.Errorf("a write at priority %d was carried", prio)
		}
		if !d.Hard {
			t.Errorf("a write at priority %d was refused softly, so shadow mode would carry it", prio)
		}
	}
	for _, prio := range []uint8{8, 9, 16, 0} {
		if d := p.Decide(req(t, write(ao, wire.PropPresentValue, prio))); !d.Allow {
			t.Errorf("a write at priority %d was refused: %+v", prio, d)
		}
	}
}

// A rule raises the bound for its own traffic, which is how the one
// workstation that really does command at a high priority is written down --
// and a rule that sets none takes the listener's rather than none at all.
func TestARuleCanRaiseThePriorityBoundAndOneWithoutASetOneDoesNot(t *testing.T) {
	p := mustCompile(t, &config.BACnetListener{Upstream: "d", DefaultAction: "allow",
		Services: []string{"writeProperty"}, MaxCommandPriority: 8,
		Rules: []config.BACnetRule{
			{Name: "fire-panel", Action: "allow", Clients: []string{"127.0.0.1"},
				Objects: []string{"binary-output"}, MaxCommandPriority: 2},
			{Name: "everything-else", Action: "allow"},
		}})
	bo := wire.ObjectID{Type: wire.BinaryOutput, Instance: 1}
	if d := p.Decide(req(t, write(bo, wire.PropPresentValue, 2))); !d.Allow {
		t.Fatalf("the fire panel's own rule did not raise the bound: %+v", d)
	}
	if d := p.Decide(req(t, write(bo, wire.PropPresentValue, 1))); d.Allow {
		t.Fatal("the rule raised the bound past its own setting")
	}
	// The second rule sets no bound, so the listener's still applies.
	ao := wire.ObjectID{Type: wire.AnalogOutput, Instance: 1}
	if d := p.Decide(req(t, write(ao, wire.PropPresentValue, 3))); d.Allow {
		t.Fatal("a rule with no bound of its own dropped the listener's")
	}
}

// The order of the checks. A bound must be found even when a policy choice
// would have refused the request anyway, because a bound is never shadowed
// and a soft refusal found first would hide it.
func TestABoundIsFoundEvenWhenAServiceRefusalWouldComeFirst(t *testing.T) {
	p := mustCompile(t, &config.BACnetListener{Upstream: "d", DefaultAction: "allow",
		Services: []string{"readProperty"}, MaxCommandPriority: 8})
	d := p.Decide(req(t, write(wire.ObjectID{Type: wire.AnalogOutput, Instance: 1},
		wire.PropPresentValue, 1)))
	if d.Allow {
		t.Fatal("carried")
	}
	if !d.Hard {
		t.Fatalf("refused as %q, which shadow mode would carry: the priority bound "+
			"is hidden behind the service refusal", d.Reason)
	}
	if d.Reason != "command_priority_too_high" {
		t.Fatalf("refused as %q", d.Reason)
	}
}

// out-of-service and the other properties whose value is the device's own
// behaviour: a write to one is refused even where the object and the service
// are allowed.
func TestASensitiveWriteIsRefusedWhereAnOrdinaryOneIsNot(t *testing.T) {
	p := mustCompile(t, &config.BACnetListener{Upstream: "d", DefaultAction: "allow",
		Services: []string{"writeProperty"}, Objects: []string{"analog-input"}})
	ai := wire.ObjectID{Type: wire.AnalogInput, Instance: 5}
	if d := p.Decide(req(t, write(ai, wire.PropOutOfService, 0))); d.Allow {
		t.Fatal("a write to out-of-service was carried")
	} else if d.Reason != "sensitive_write" {
		t.Fatalf("refused as %q", d.Reason)
	}
	if d := p.Decide(req(t, write(ai, wire.PropPresentValue, 0))); !d.Allow {
		t.Fatalf("an ordinary write was refused: %+v", d)
	}
	// And an estate that has decided otherwise can say so.
	yes := false
	p2 := mustCompile(t, &config.BACnetListener{Upstream: "d", DefaultAction: "allow",
		Services: []string{"writeProperty"}, Objects: []string{"analog-input"},
		DenySensitiveWrites: &yes})
	if d := p2.Decide(req(t, write(ai, wire.PropOutOfService, 0))); !d.Allow {
		t.Fatalf("deny_sensitive_writes: false did not carry it: %+v", d)
	}
}

// An object this relay could not find is a refusal when there are object
// rules, and not a refusal when there are none -- because a rule that does
// not exist cannot fail to apply.
func TestAnUnlocatedObjectIsRefusedOnlyWhereObjectRulesExist(t *testing.T) {
	// whoHas names an object or a name, so no fixed position describes it.
	whoHas := []byte{0x10, wire.WhoHas, 0x0C, 0x00, 0x00, 0x00, 0x01}
	with := mustCompile(t, &config.BACnetListener{Upstream: "d", DefaultAction: "allow",
		Services: []string{"who-Has"}, Objects: []string{"device"}})
	if d := with.Decide(req(t, whoHas)); d.Allow {
		t.Fatal("an unlocatable object was carried past an object rule")
	} else if d.Reason != "object_unlocatable" {
		t.Fatalf("refused as %q", d.Reason)
	}
	without := mustCompile(t, &config.BACnetListener{Upstream: "d", DefaultAction: "allow",
		Services: []string{"who-Has"}})
	if d := without.Decide(req(t, whoHas)); !d.Allow {
		t.Fatalf("refused with no object rules to apply: %+v", d)
	}
	// And an estate that would rather carry it can say so.
	no := false
	relaxed := mustCompile(t, &config.BACnetListener{Upstream: "d", DefaultAction: "allow",
		Services: []string{"who-Has"}, Objects: []string{"device"},
		RefuseUnlocatedObjects: &no})
	if d := relaxed.Decide(req(t, whoHas)); !d.Allow {
		t.Fatalf("refuse_unlocated_objects: false did not carry it: %+v", d)
	}
}

// Every object in a multiple request is checked, not the first. A request
// that reads one property from each of forty objects is one datagram.
func TestEveryObjectInAMultipleRequestIsChecked(t *testing.T) {
	p := mustCompile(t, &config.BACnetListener{Upstream: "d", DefaultAction: "allow",
		Services: []string{"readPropertyMultiple"}, Objects: []string{"analog-input"}})
	b := []byte{0x00, 0x05, 0x01, wire.ReadPropertyMultiple}
	b = append(b, 0x0C)
	b = append(b, (wire.ObjectID{Type: wire.AnalogInput, Instance: 1}).Encode()...)
	b = append(b, 0x1E, 0x09, 0x55, 0x1F)
	b = append(b, 0x0C)
	b = append(b, (wire.ObjectID{Type: wire.DeviceObject, Instance: 9}).Encode()...)
	b = append(b, 0x1E, 0x09, 0x4C, 0x1F)
	d := p.Decide(req(t, b))
	if d.Allow {
		t.Fatal("a second object outside the list was carried")
	}
	if !strings.Contains(d.Detail, "device:9") {
		t.Fatalf("the refusal names %q, and the object outside the list is device:9", d.Detail)
	}
}

// The instance ranges: a rule that covers instances 1 to 100 does not cover
// 101, and a request outside every rule takes the default.
func TestAnInstanceRangeBoundsWhichObjectsARuleCovers(t *testing.T) {
	p := mustCompile(t, &config.BACnetListener{Upstream: "d",
		Services: []string{"writeProperty"},
		Rules: []config.BACnetRule{
			{Name: "zones", Action: "allow", Objects: []string{"analog-value"},
				Instances: []string{"1-100", "500"}},
		}})
	for _, in := range []uint32{1, 50, 100, 500} {
		o := wire.ObjectID{Type: wire.AnalogValue, Instance: in}
		if d := p.Decide(req(t, write(o, wire.PropPresentValue, 0))); !d.Allow {
			t.Errorf("instance %d was refused: %+v", in, d)
		}
	}
	for _, in := range []uint32{0, 101, 499, 501} {
		o := wire.ObjectID{Type: wire.AnalogValue, Instance: in}
		if d := p.Decide(req(t, write(o, wire.PropPresentValue, 0))); d.Allow {
			t.Errorf("instance %d matched a rule that does not cover it", in)
		}
	}
}

// The network layer: where a message may be routed, what queue it claims,
// and whether the routers' own messages cross this relay.
func TestTheNetworkLayerDecisions(t *testing.T) {
	p := mustCompile(t, &config.BACnetListener{Upstream: "d", Networks: []int{5},
		MaxPriority: "urgent"})
	local := wire.NPDU{Version: 1}
	if d := p.Network(local); !d.Allow {
		t.Fatalf("a message for the local network was refused: %+v", d)
	}
	if d := p.Network(wire.NPDU{Version: 1, HasDest: true, DNET: 5}); !d.Allow {
		t.Fatalf("network 5 was refused: %+v", d)
	}
	if d := p.Network(wire.NPDU{Version: 1, HasDest: true, DNET: 9}); d.Allow {
		t.Fatal("network 9 was carried, and only 5 is named")
	}
	if d := p.Network(wire.NPDU{Version: 1, Priority: 3}); d.Allow {
		t.Fatal("a life safety priority was carried where urgent is the bound")
	} else if d.Detail != "life-safety" {
		t.Fatalf("the refusal names %q", d.Detail)
	}
	if d := p.Network(wire.NPDU{Version: 1, Priority: 1}); !d.Allow {
		t.Fatalf("urgent was refused where urgent is the bound: %+v", d)
	}
	// A network layer message: refused by default, and the routing ones
	// refused even when the rest are allowed.
	nm := wire.NPDU{Version: 1, NetworkMessage: true, MessageType: wire.NetWhoIsRouterToNetwork}
	if d := p.Network(nm); d.Allow {
		t.Fatal("a network layer message was carried by default")
	}
	yes := true
	allowed := mustCompile(t, &config.BACnetListener{Upstream: "d", Networks: []int{5},
		AllowNetworkMessages: &yes})
	if d := allowed.Network(nm); !d.Allow {
		t.Fatalf("who-is-router-to-network was refused: %+v", d)
	}
	init := wire.NPDU{Version: 1, NetworkMessage: true, MessageType: wire.NetInitializeRoutingTable}
	if d := allowed.Network(init); d.Allow {
		t.Fatal("initialize-routing-table was carried without allow_routing")
	}
	sec := wire.NPDU{Version: 1, NetworkMessage: true, MessageType: wire.NetSecurityPayload}
	if d := allowed.Network(sec); d.Allow {
		t.Fatal("a security payload was carried without allow_security_messages")
	}
	unknown := wire.NPDU{Version: 1, NetworkMessage: true, MessageType: wire.NetworkMessageType(0x40)}
	if d := allowed.Network(unknown); d.Allow {
		t.Fatal("a network message the standard does not define was carried")
	}
}

// A discovery sweep is bounded by range as well as by rate: a Who-Is with
// no range at all asks every device there is to answer at once.
func TestTheWhoIsRangeCanBeBounded(t *testing.T) {
	yes := true
	p := mustCompile(t, &config.BACnetListener{Upstream: "d", DefaultAction: "allow",
		MaxWhoIsRange: 100, RequireWhoIsRange: &yes})
	unbounded := []byte{0x10, wire.WhoIs}
	d := p.Decide(req(t, unbounded))
	if d.Allow || !d.Hard {
		t.Fatalf("an unbounded who-Is: %+v", d)
	}
	narrow := []byte{0x10, wire.WhoIs, 0x09, 0x0A, 0x19, 0x14}
	if d := p.Decide(req(t, narrow)); !d.Allow {
		t.Fatalf("a range of ten was refused: %+v", d)
	}
	wide := []byte{0x0A, wire.WhoIs}
	_ = wide
	broad := []byte{0x10, wire.WhoIs, 0x09, 0x00, 0x1A, 0x27, 0x10}
	if d := p.Decide(req(t, broad)); d.Allow {
		t.Fatal("a range of ten thousand was carried where the bound is a hundred")
	}
}

// An unknown service choice is refused, and it counts as a write so nothing
// that treats reads leniently can be reached through one.
func TestAnUnknownServiceIsRefused(t *testing.T) {
	p := mustCompile(t, &config.BACnetListener{Upstream: "d", DefaultAction: "allow"})
	d := p.Decide(req(t, []byte{0x00, 0x05, 0x01, 200}))
	if d.Allow {
		t.Fatal("a service choice no edition defines was carried")
	}
	if d.Reason != "service_unknown" {
		t.Fatalf("refused as %q", d.Reason)
	}
}

// A deny list wins over an allow list, on every one of the three.
func TestADenyListWinsOverAnAllowList(t *testing.T) {
	p := mustCompile(t, &config.BACnetListener{Upstream: "d", DefaultAction: "allow",
		Services: []string{"readProperty", "writeProperty"}, DenyServices: []string{"writeProperty"},
		Objects: []string{"analog-input", "device"}, DenyObjects: []string{"device"},
		Properties: []string{"present-value", "object-name"}, DenyProperties: []string{"object-name"}})
	ai := wire.ObjectID{Type: wire.AnalogInput, Instance: 1}
	dev := wire.ObjectID{Type: wire.DeviceObject, Instance: 1}
	if d := p.Decide(req(t, write(ai, wire.PropPresentValue, 0))); d.Allow || d.Reason != "service_denied" {
		t.Errorf("service deny list: %+v", d)
	}
	if d := p.Decide(req(t, read(dev, wire.PropPresentValue))); d.Allow || d.Reason != "object_denied" {
		t.Errorf("object deny list: %+v", d)
	}
	if d := p.Decide(req(t, read(ai, wire.PropObjectName))); d.Allow || d.Reason != "property_denied" {
		t.Errorf("property deny list: %+v", d)
	}
	if d := p.Decide(req(t, read(ai, wire.PropPresentValue))); !d.Allow {
		t.Errorf("the allowed combination was refused: %+v", d)
	}
}

// The client list is the only identity this protocol has, so it is checked
// on its own and before anything else.
func TestTheClientListIsCheckedOnItsOwn(t *testing.T) {
	p := mustCompile(t, &config.BACnetListener{Upstream: "d",
		AllowClients: []string{"10.0.0.0/8", "192.0.2.7"}, DenyClients: []string{"10.9.0.0/16"}})
	for _, s := range []string{"10.0.0.1", "192.0.2.7"} {
		if !p.Client(netip.MustParseAddr(s)) {
			t.Errorf("%s was refused", s)
		}
	}
	for _, s := range []string{"10.9.0.1", "127.0.0.1", "192.0.2.8"} {
		if p.Client(netip.MustParseAddr(s)) {
			t.Errorf("%s was allowed", s)
		}
	}
	// An empty allow list allows any, which validation warns about rather
	// than refusing: an estate has to be able to start somewhere.
	open := mustCompile(t, &config.BACnetListener{Upstream: "d"})
	if !open.Client(netip.MustParseAddr("203.0.113.9")) {
		t.Error("an empty allow list refused a client")
	}
}

// A schedule limits a rule to a window, which is what a change window is.
func TestAScheduleLimitsARuleToItsWindow(t *testing.T) {
	p := mustCompile(t, &config.BACnetListener{Upstream: "d",
		Services: []string{"writeProperty"},
		Rules: []config.BACnetRule{{Name: "change-window", Action: "allow",
			Schedule: &config.ModbusSchedule{Days: []string{"mon"}, From: "09:00", To: "17:00",
				Timezone: "UTC"}}}})
	ao := wire.ObjectID{Type: wire.AnalogOutput, Instance: 1}
	inside := request{client: netip.MustParseAddr("127.0.0.1"),
		at: time.Date(2026, 3, 2, 10, 0, 0, 0, time.UTC)}
	outside := inside
	outside.at = time.Date(2026, 3, 3, 10, 0, 0, 0, time.UTC)
	a, targets, located := apdu(t, write(ao, wire.PropPresentValue, 0))
	inside.apdu, inside.targets, inside.located = a, targets, located
	outside.apdu, outside.targets, outside.located = a, targets, located
	if d := p.Decide(inside); !d.Allow || d.Rule != "change-window" {
		t.Fatalf("inside the window: %+v", d)
	}
	if d := p.Decide(outside); d.Allow {
		t.Fatalf("outside the window: %+v", d)
	}
}

// An observe rule logs and keeps looking, which is how a rule is tried on
// live traffic before it decides anything.
func TestAnObserveRuleDecidesNothing(t *testing.T) {
	p := mustCompile(t, &config.BACnetListener{Upstream: "d",
		Services: []string{"writeProperty"},
		Rules: []config.BACnetRule{
			{Name: "watching", Action: "observe"},
			{Name: "refusing", Action: "deny"},
		}})
	d := p.Decide(req(t, write(wire.ObjectID{Type: wire.AnalogOutput, Instance: 1},
		wire.PropPresentValue, 0)))
	if d.Allow {
		t.Fatal("the observe rule decided")
	}
	if d.Rule != "refusing" {
		t.Fatalf("decided by %q", d.Rule)
	}
}

// A name no edition of the standard has is an error at load, not a rule
// that quietly matches nothing.
func TestAMisspeltNameIsRefusedAtLoad(t *testing.T) {
	cases := []*config.BACnetListener{
		{Upstream: "d", Services: []string{"writeProperties"}},
		{Upstream: "d", DenyServices: []string{"nonsense"}},
		{Upstream: "d", Objects: []string{"analog-outputs"}},
		{Upstream: "d", Properties: []string{"present_value"}},
		{Upstream: "d", MaxPriority: "important"},
		{Upstream: "d", AllowClients: []string{"10.0.0.0/33"}},
		{Upstream: "d", Rules: []config.BACnetRule{{Name: "r", Instances: []string{"100-1"}}}},
		{Upstream: "d", Rules: []config.BACnetRule{{Name: "r", Instances: []string{"abc"}}}},
		{Upstream: "d", Rules: []config.BACnetRule{{Name: "r", Clients: []string{"not-an-address"}}}},
		{Upstream: "d", Rules: []config.BACnetRule{{Name: "r",
			Schedule: &config.ModbusSchedule{Days: []string{"someday"}}}}},
	}
	for i, c := range cases {
		if _, err := compile(c); err == nil {
			t.Errorf("case %d compiled", i)
		}
	}
}

// The hop count bound is clamped rather than trusted, so a configuration
// the validator never saw cannot produce a bound that wrapped.
func TestTheHopBoundIsClamped(t *testing.T) {
	for _, tc := range []struct {
		in   int
		want uint8
	}{
		{0, 8}, {-1, 8}, {1, 1}, {255, 255}, {256, 255}, {1 << 20, 255},
	} {
		if got := hopBound(tc.in); got != tc.want {
			t.Errorf("hopBound(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// A segmented request is carried by default and refused when the estate
// wants every request decided whole.
func TestSegmentationCanBeRefused(t *testing.T) {
	seg := []byte{0x08, 0x05, 0x01, 0x00, 0x10, wire.ReadProperty, 0x0C, 0, 0, 0, 1, 0x19, 0x55}
	on := mustCompile(t, &config.BACnetListener{Upstream: "d", DefaultAction: "allow"})
	if d := on.Decide(req(t, seg)); !d.Allow {
		t.Fatalf("a segmented read was refused by default: %+v", d)
	}
	no := false
	off := mustCompile(t, &config.BACnetListener{Upstream: "d", DefaultAction: "allow",
		AllowSegmented: &no})
	if d := off.Decide(req(t, seg)); d.Allow {
		t.Fatal("allow_segmented: false carried a segmented request")
	}
}

// A reply shape with no service choice has nothing for the policy to decide
// about: the relay's pairing decides whether it is forwarded.
func TestAReplyWithNoServiceChoiceIsNotAPolicyQuestion(t *testing.T) {
	p := mustCompile(t, &config.BACnetListener{Upstream: "d"})
	if d := p.Decide(req(t, []byte{0x60, 0x01, 0x09})); !d.Allow {
		t.Fatalf("a reject: %+v", d)
	}
	if d := p.Decide(request{}); !d.Allow {
		t.Fatal("a request with no application message")
	}
}
