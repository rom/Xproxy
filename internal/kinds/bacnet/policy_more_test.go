package bacnet

import (
	"net/netip"
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/bacnet"
	"github.com/rom/xproxy/internal/config"
)

// A rule's own lists are compiled at load, the same as the listener's.
//
// A rule is where an exception is written down, and an exception written
// with a name the standard does not have is the dangerous kind of
// configuration error: the rule matches nothing, so the request it was
// meant to allow is refused and the request it was meant to refuse is
// decided by something else. Every list has to be checked, not only the
// ones at the top of the section.
func TestARulesOwnListsAreCheckedAtCompileToo(t *testing.T) {
	cases := []config.BACnetRule{
		{Name: "r", Objects: []string{"analog-inputs"}},
		{Name: "r", DenyObjects: []string{"nonsense"}},
		{Name: "r", Properties: []string{"present_value"}},
		{Name: "r", DenyProperties: []string{"out_of_service"}},
		{Name: "r", Services: []string{"writeProperties"}},
		// A range whose upper bound is not a number. The lower bound is,
		// so the error is the second parse rather than the first.
		{Name: "r", Instances: []string{"1-xyz"}},
	}
	for i, r := range cases {
		if _, err := compile(&config.BACnetListener{Upstream: "d",
			Rules: []config.BACnetRule{r}}); err == nil {
			t.Errorf("case %d compiled", i)
		}
	}
}

// A rule covers a request only when every list it sets matches it. A list
// it leaves empty matches anything, which is what makes a rule with one
// line in it mean that one line and not everything else as well.
func TestEveryListARuleSetsHasToMatchTheRequest(t *testing.T) {
	p := mustCompile(t, &config.BACnetListener{Upstream: "d", DefaultAction: "allow",
		Services: []string{"readProperty", "writeProperty"},
		Rules: []config.BACnetRule{{Name: "narrow", Action: "allow",
			Clients:  []string{"10.0.0.0/8"},
			Services: []string{"writeProperty"},
			Networks: []int{5},
			Objects:  []string{"analog-value"},
		}}})
	ru := p.rules[0]
	av := wire.ObjectID{Type: wire.AnalogValue, Instance: 1}

	// The client is not in the rule's networks.
	r := req(t, write(av, wire.PropPresentValue, 0))
	r.npdu = &wire.NPDU{HasDest: true, DNET: 5}
	if ru.matches(r) {
		t.Error("a rule matched a client outside its own networks")
	}

	// In the networks, but the service is not one of the rule's.
	r = req(t, read(av, wire.PropPresentValue))
	r.client = netip.MustParseAddr("10.0.0.4")
	r.npdu = &wire.NPDU{HasDest: true, DNET: 5}
	if ru.matches(r) {
		t.Error("a rule matched a service it does not name")
	}

	// The right service, but the message names no destination network, so
	// it is not for the network this rule is about.
	r = req(t, write(av, wire.PropPresentValue, 0))
	r.client = netip.MustParseAddr("10.0.0.4")
	if ru.matches(r) {
		t.Error("a rule with networks matched a message that names none")
	}
	r.npdu = &wire.NPDU{HasDest: true, DNET: 6}
	if ru.matches(r) {
		t.Error("a rule matched the wrong destination network")
	}

	// Everything matches except that this relay could not find the object
	// the request is about, so a rule written about object types cannot
	// say whether it covers it.
	r.npdu = &wire.NPDU{HasDest: true, DNET: 5}
	r.located, r.targets = false, nil
	if ru.matches(r) {
		t.Error("a rule about object types matched an unlocated request")
	}

	// And with all five satisfied it does match.
	r = req(t, write(av, wire.PropPresentValue, 0))
	r.client = netip.MustParseAddr("10.0.0.4")
	r.npdu = &wire.NPDU{HasDest: true, DNET: 5}
	if !ru.matches(r) {
		t.Error("the rule did not match a request inside every one of its lists")
	}
}

// A rule's object and property lists replace the listener's for the
// traffic it covers, and a refusal that came from a rule says which rule.
//
// Replacing rather than intersecting is what lets one workstation be
// given a wider set than the estate's default without widening the
// default, and naming the rule is what makes the refusal answerable: an
// operator reading "property_not_allowed" needs to know which line of the
// file to argue with.
func TestARulesListsReplaceTheListenersAndNameThemselves(t *testing.T) {
	p := mustCompile(t, &config.BACnetListener{Upstream: "d", DefaultAction: "allow",
		Services:   []string{"readProperty"},
		Objects:    []string{"analog-value", "binary-value"},
		Properties: []string{"present-value", "description", "object-name"},
		Rules: []config.BACnetRule{{Name: "zone-1", Action: "allow",
			Clients:        []string{"10.0.0.0/8"},
			Objects:        []string{"analog-value", "binary-value"},
			DenyObjects:    []string{"binary-value"},
			Properties:     []string{"present-value"},
			DenyProperties: []string{"description"},
		}}})
	from := netip.MustParseAddr("10.0.0.4")
	decide := func(b []byte) Decision {
		r := req(t, b)
		r.client = from
		return p.Decide(r)
	}

	av := wire.ObjectID{Type: wire.AnalogValue, Instance: 7}
	if d := decide(read(av, wire.PropPresentValue)); !d.Allow {
		t.Fatalf("a read inside every one of the rule's lists was refused: %+v", d)
	}

	// The rule's deny list refuses an object the listener allows.
	bv := wire.ObjectID{Type: wire.BinaryValue, Instance: 7}
	d := decide(read(bv, wire.PropPresentValue))
	if d.Allow || d.Reason != "object_denied" || d.Rule != "zone-1" {
		t.Errorf("the rule's deny list: %+v", d)
	}

	// Its property deny list does the same for a property the listener
	// allows, and its narrower allow list refuses one the listener names
	// and the rule does not.
	if d := decide(read(av, wire.PropDescription)); d.Allow ||
		d.Reason != "property_denied" || d.Rule != "zone-1" {
		t.Errorf("the rule's property deny list: %+v", d)
	}
	if d := decide(read(av, wire.PropObjectName)); d.Allow ||
		d.Reason != "property_not_allowed" || d.Rule != "zone-1" {
		t.Errorf("the rule's property allow list: %+v", d)
	}
}

// The instance range is applied per object as well as when the rule is
// matched.
//
// A request names as many objects as it likes, and the two checks are not
// the same question: matching asks whether this rule is the one that
// decides, and this one asks whether the object in front of it is inside
// the range the rule was written about. The second is what a
// readPropertyMultiple naming one object inside the range and one outside
// it comes down to, so it is checked here directly rather than through a
// request that the matching would turn away first.
func TestTheInstanceRangeIsAppliedToEachObject(t *testing.T) {
	p := mustCompile(t, &config.BACnetListener{Upstream: "d", DefaultAction: "allow",
		Services: []string{"readProperty"},
		Rules: []config.BACnetRule{{Name: "zone-1", Action: "allow",
			Objects: []string{"analog-value"}, Instances: []string{"1-100"}}}})
	ru := p.rules[0]
	inside := wire.Target{Object: wire.ObjectID{Type: wire.AnalogValue, Instance: 7}}
	if d, ok := p.objectOne(inside, false, ru); !ok {
		t.Errorf("an object inside the range was refused: %+v", d)
	}
	outside := wire.Target{Object: wire.ObjectID{Type: wire.AnalogValue, Instance: 4000}}
	d, ok := p.objectOne(outside, false, ru)
	if ok || d.Reason != "instance_not_allowed" || d.Rule != "zone-1" {
		t.Errorf("an object outside the range: %+v, %v", d, ok)
	}
}

// With no object or property rules anywhere and sensitive writes allowed,
// there is nothing for the object check to decide, and it says so instead
// of walking a request's objects to reach the same answer.
func TestAListenerWithNoObjectRulesSkipsTheObjectCheck(t *testing.T) {
	no := false
	p := mustCompile(t, &config.BACnetListener{Upstream: "d", DefaultAction: "allow",
		Services: []string{"writeProperty"}, DenySensitiveWrites: &no})
	av := wire.ObjectID{Type: wire.AnalogValue, Instance: 1}
	if d := p.Decide(req(t, write(av, wire.PropOutOfService, 0))); !d.Allow {
		t.Errorf("a sensitive write was refused where nothing refuses it: %+v", d)
	}
}

// The invoke identifier the relay wrote into a datagram, read back out of
// it.
//
// It is read back for one reason: a send to the device that failed leaves
// an exchange nobody will ever answer holding one of two hundred and
// fifty-six identifiers, and a relay that leaks them fills its own table
// and then refuses traffic it could have carried.
func TestTheRelayCanReadBackTheIdentifierItWrote(t *testing.T) {
	out := []byte{0, 1, 2, 3, 4, 42, 6, 7, 8, 9}
	n := &wire.NPDU{APDU: make([]byte, 6)}
	a := &wire.APDU{Type: wire.PDUConfirmedRequest, HasInvokeID: true, InvokeOffset: 1}

	if id, ok := allocated(out, n, a); !ok || id != 42 {
		t.Errorf("allocated = %d, %v, want 42, true", id, ok)
	}

	// Nothing was allocated for a message that carries no identifier, or
	// for one this relay never parsed.
	if _, ok := allocated(out, nil, a); ok {
		t.Error("an identifier was reported for a message with no network layer")
	}
	if _, ok := allocated(out, n, &wire.APDU{Type: wire.PDUUnconfirmedRequest}); ok {
		t.Error("an identifier was reported for an unconfirmed request")
	}

	// An offset the datagram cannot hold is not read. The arithmetic and
	// the message disagreeing is a bug somewhere above here, and reading
	// whatever octet it points at would give back an identifier that
	// belongs to a different exchange.
	long := &wire.NPDU{APDU: make([]byte, 40)}
	if _, ok := allocated(out, long, a); ok {
		t.Error("an identifier was read from outside the datagram")
	}
}

// Writing the relay's own identifier in, which is the other half of the
// same translation.
func TestWritingTheIdentifierInLeavesTheDatagramAloneWhenItCannot(t *testing.T) {
	raw := []byte{0, 1, 2, 3, 4, 42, 6, 7, 8, 9}
	n := &wire.NPDU{APDU: make([]byte, 6)}
	a := &wire.APDU{Type: wire.PDUConfirmedRequest, HasInvokeID: true,
		InvokeOffset: 1, InvokeID: 42}

	out := withInvokeID(raw, n, a, 9)
	if out[5] != 9 || raw[5] != 42 {
		t.Errorf("out[5] = %d and raw[5] = %d, want 9 and 42", out[5], raw[5])
	}

	// A message with no identifier is carried unchanged, and so is one
	// where the recorded offset does not hold the identifier the parse
	// reported: the client then times out, which is the failure that
	// loses nothing, rather than being handed an unrelated answer.
	if got := withInvokeID(raw, n, &wire.APDU{}, 9); &got[0] != &raw[0] {
		t.Error("a message with no invoke identifier was rewritten")
	}
	wrong := &wire.APDU{Type: wire.PDUConfirmedRequest, HasInvokeID: true,
		InvokeOffset: 1, InvokeID: 7}
	if got := withInvokeID(raw, n, wrong, 9); &got[0] != &raw[0] {
		t.Error("a datagram whose offset disagreed with the parse was rewritten")
	}
}

// The exchange table is swept on every change rather than on a timer, so
// an exchange nobody is waiting for any more is gone by the time the next
// request asks for an identifier.
func TestTheExchangeTableIsSweptByTheNextRequest(t *testing.T) {
	now := time.Now()
	p := newPending(4, 1, time.Minute)
	if _, ok := p.add(exch(9000, 1, "10.0.0.9:47808"), now); !ok {
		t.Fatal("the first exchange was refused")
	}
	if _, ok := p.add(exch(9001, 2, "10.0.0.9:47808"), now.Add(2*time.Minute)); !ok {
		t.Fatal("the second exchange was refused")
	}
	if n := p.outstanding(); n != 1 {
		t.Errorf("outstanding = %d, want 1: the expired exchange was kept", n)
	}
}

// A broadcast whose budget is already spent is dropped rather than looked
// at again, because the budget is the amplification bound and a bound
// re-checked for every answer costs work per amplified datagram.
func TestASpentBroadcastIsNotLookedAtAgain(t *testing.T) {
	now := time.Now()
	p := newPending(4, 4, time.Minute)
	spent := &broadcast{from: clientAt(9100), client: netip.MustParseAddr("127.0.0.1"),
		left: 0, deadline: now.Add(time.Minute)}
	if !p.addBroadcast(spent, now) {
		t.Fatal("the broadcast was refused")
	}
	if to := p.broadcastTargets(now); len(to) != 0 {
		t.Errorf("a spent broadcast was answered: %v", to)
	}
	if to := p.broadcastTargets(now); len(to) != 0 {
		t.Errorf("it was still in the table on the next answer: %v", to)
	}
}
