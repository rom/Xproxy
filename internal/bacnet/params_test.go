package bacnet

import "testing"

// The point of the table: in a COV notification the first object
// identifier in the parameters is the device that sent it and the third
// is the object that changed. A policy that read the first would be
// deciding about the wrong one -- and would allow a write to a plant item
// because the notification came from a device it trusts.
func TestTheObjectIsTakenFromItsOwnPlaceAndNotTheFirstOne(t *testing.T) {
	device := ObjectID{Type: DeviceObject, Instance: 4001}
	changed := ObjectID{Type: AnalogOutput, Instance: 7}
	params := concat(
		ctx(0, u32(18)...),          // subscriber process identifier
		ctx(1, device.Encode()...),  // the device that is telling us
		ctx(2, changed.Encode()...), // the object that changed
		ctx(3, u32(0)...),           // time remaining
	)
	a, err := ParseAPDU(confirmed(ConfirmedCOVNotification, params...))
	if err != nil {
		t.Fatal(err)
	}
	got, ok := Targets(a)
	if !ok || len(got) != 1 {
		t.Fatalf("targets %v %v", got, ok)
	}
	if got[0].Object != changed {
		t.Fatalf("object %s, want the one that changed (%s)", got[0].Object, changed)
	}
}

// subscribeCOV's first parameter is a process identifier, which is not an
// object at all. Reading it as one would produce an object identifier out
// of a number the client chose.
func TestAProcessIdentifierIsNotAnObject(t *testing.T) {
	monitored := ObjectID{Type: BinaryInput, Instance: 3}
	params := concat(ctx(0, 0, 0, 0, 99), ctx(1, monitored.Encode()...), ctx(2, 1), ctx(3, 0x3C))
	a, err := ParseAPDU(confirmed(SubscribeCOV, params...))
	if err != nil {
		t.Fatal(err)
	}
	got, ok := Targets(a)
	if !ok || len(got) != 1 || got[0].Object != monitored {
		t.Fatalf("targets %v %v, want %s", got, ok, monitored)
	}
	if got[0].HasProperty {
		t.Fatal("subscribeCOV names no single property")
	}
}

// readPropertyMultiple carries a list, and every object and every
// property in it is one the request is about. A relay that checked the
// first specification of forty would be checking one fortieth of the
// request.
func TestEveryObjectInAnAccessListIsReturned(t *testing.T) {
	a1 := ObjectID{Type: AnalogInput, Instance: 1}
	a2 := ObjectID{Type: AnalogOutput, Instance: 2}
	params := concat(
		ctx(0, a1.Encode()...), open(1), ctx(0, u32(uint32(PropPresentValue))...), ctx(0, u32(uint32(PropStatusFlags))...), closed(1),
		ctx(0, a2.Encode()...), open(1), ctx(0, u32(uint32(PropPresentValue))...), closed(1),
	)
	a, err := ParseAPDU(confirmed(ReadPropertyMultiple, params...))
	if err != nil {
		t.Fatal(err)
	}
	got, ok := Targets(a)
	if !ok {
		t.Fatal("an access list was not located")
	}
	want := []Target{
		{Object: a1, Property: PropPresentValue, HasProperty: true},
		{Object: a1, Property: PropStatusFlags, HasProperty: true},
		{Object: a2, Property: PropPresentValue, HasProperty: true},
	}
	if len(got) != len(want) {
		t.Fatalf("targets %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("target %d is %+v, want %+v", i, got[i], want[i])
		}
	}
}

// An array index inside a property reference is not a property. It sits
// at context tag 1 next to the identifier at 0, so a reader that took
// every number in the list would invent a property out of an index.
func TestAnArrayIndexIsNotAProperty(t *testing.T) {
	o := ObjectID{Type: DeviceObject, Instance: 1}
	params := concat(
		ctx(0, o.Encode()...), open(1),
		ctx(0, u32(uint32(PropObjectList))...), ctx(1, 3), // object-list[3]
		closed(1),
	)
	a, err := ParseAPDU(confirmed(ReadPropertyMultiple, params...))
	if err != nil {
		t.Fatal(err)
	}
	got, ok := Targets(a)
	if !ok || len(got) != 1 {
		t.Fatalf("targets %v %v", got, ok)
	}
	if got[0].Property != PropObjectList {
		t.Fatalf("property %s, want object-list", got[0].Property)
	}
}

// The application-tagged shapes. i-Have names two objects -- the device
// and the object it has -- and both are returned, because both are
// objects the message is about.
func TestAnApplicationTaggedObjectIsFound(t *testing.T) {
	f := ObjectID{Type: FileObject, Instance: 2}
	a, err := ParseAPDU(confirmed(AtomicWriteFile, concat(app(tagObjectID, f.Encode()...), app(tagUnsigned, 0))...))
	if err != nil {
		t.Fatal(err)
	}
	got, ok := Targets(a)
	if !ok || len(got) != 1 || got[0].Object != f {
		t.Fatalf("targets %v %v, want %s", got, ok, f)
	}
	dev := ObjectID{Type: DeviceObject, Instance: 9}
	obj := ObjectID{Type: AnalogValue, Instance: 4}
	ih, err := ParseAPDU(unconfirmed(IHave, concat(
		app(tagObjectID, dev.Encode()...), app(tagObjectID, obj.Encode()...),
		app(7, 0, 'A', 'H', 'U'))...))
	if err != nil {
		t.Fatal(err)
	}
	two, ok := Targets(ih)
	if !ok || len(two) != 2 || two[0].Object != dev || two[1].Object != obj {
		t.Fatalf("targets %v %v", two, ok)
	}
}

// The services this package cannot locate an object in say so, rather
// than reporting no object -- which a rule about objects would let past.
func TestAnUnlocatableServiceIsReportedAsUnlocatable(t *testing.T) {
	for _, s := range []Service{
		{Confirmed: true, Choice: CreateObject},
		{Confirmed: true, Choice: GetEnrollmentSummary},
		{Confirmed: true, Choice: SubscribeCOVPropertyMultiple},
		{Confirmed: true, Choice: AuditLogQuery},
		{Choice: WhoHas},
		{Choice: YouAre},
		{Confirmed: true, Choice: 200}, // a choice no edition defines
	} {
		var b []byte
		if s.Confirmed {
			b = confirmed(s.Choice, 0x0C, 0, 0, 0, 1)
		} else {
			b = unconfirmed(s.Choice, 0x0C, 0, 0, 0, 1)
		}
		a, err := ParseAPDU(b)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if _, ok := Targets(a); ok {
			t.Errorf("%s was reported as located", s)
		}
	}
}

// And the ones that genuinely name no object report that instead, because
// "about no object" and "I could not find the object" are different
// answers and a policy acts differently on them.
func TestAServiceWithNoObjectIsNotAFailureToFindOne(t *testing.T) {
	a, err := ParseAPDU(confirmed(ReinitializeDevice, concat(ctx(0, 1), ctx(1, 0, 'p', 'w'))...))
	if err != nil {
		t.Fatal(err)
	}
	got, ok := Targets(a)
	if !ok {
		t.Fatal("reinitializeDevice names no object, which is knowable")
	}
	if len(got) != 0 {
		t.Fatalf("targets %v, want none", got)
	}
}

// A request whose object should be at a fixed place and is not is a
// failure to locate rather than a request about no object. The difference
// is what stops an empty writeProperty getting past an object rule.
func TestAMissingObjectIsNotNoObject(t *testing.T) {
	a, err := ParseAPDU(confirmed(WriteProperty, ctx(1, u32(uint32(PropPresentValue))...)...))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := Targets(a); ok {
		t.Fatal("a writeProperty with no object identifier was located")
	}
}

// Who-Is without a range asks every device on the network to answer at
// once, which is the difference between a client talking to its own
// controller and a client sweeping the estate.
func TestWhoIsWithoutARangeIsUnbounded(t *testing.T) {
	a, err := ParseAPDU(unconfirmed(WhoIs))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, bounded := DeviceRange(a); bounded {
		t.Fatal("a who-Is with no parameters was read as bounded")
	}
	b, err := ParseAPDU(unconfirmed(WhoIs, concat(ctx(0, u32(100)...), ctx(1, u32(120)...))...))
	if err != nil {
		t.Fatal(err)
	}
	low, high, bounded := DeviceRange(b)
	if !bounded || low != 100 || high != 120 {
		t.Fatalf("range %d-%d bounded %v", low, high, bounded)
	}
	// A range that runs backwards is not a range.
	c, err := ParseAPDU(unconfirmed(WhoIs, concat(ctx(0, u32(120)...), ctx(1, u32(100)...))...))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, bounded := DeviceRange(c); bounded {
		t.Fatal("a backwards range was accepted")
	}
	// And the range of another service is not a Who-Is range.
	d, err := ParseAPDU(unconfirmed(WhoHas, concat(ctx(0, u32(1)...), ctx(1, u32(2)...))...))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, bounded := DeviceRange(d); bounded {
		t.Fatal("a who-Has was read as a who-Is")
	}
}

// The tag reader's own edges. Each of these is a way to make two parsers
// read different messages out of the same octets.
func TestTheTagReaderRefusesWhatItCannotReadOneWay(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
	}{
		{"a tag number under fifteen in the extended form", []byte{0xF8, 0x02, 0x00}},
		{"an opening marker on an application tag", []byte{0x06}},
		{"a closing marker on an application tag", []byte{0x07}},
		{"a boolean with a length", []byte{0x12}},
		{"a value longer than the message", []byte{0x0C, 0x01, 0x02}},
		{"an extended length with nothing after it", []byte{0x0D}},
		{"a two octet length that does not fit", []byte{0x0D, 0xFE, 0x00}},
		{"a four octet length that does not fit", []byte{0x0D, 0xFF, 0x00, 0x00}},
		{"a four octet length longer than any message", []byte{0x0D, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
		{"an extended tag number with nothing after it", []byte{0xF1}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := &reader{b: c.b}
			if _, err := r.next(); err == nil {
				t.Fatal("read without an error")
			}
		})
	}
	// A short length written the long way is accepted: both a device and
	// this relay read the same value from it, so there is nothing to
	// disagree about and refusing it would stop a clumsy encoder's
	// building working.
	r := &reader{b: []byte{0x0D, 0x02, 0xAA, 0xBB}}
	tg, err := r.next()
	if err != nil {
		t.Fatalf("a short extended length was refused: %v", err)
	}
	if len(tg.Data) != 2 || tg.Data[0] != 0xAA {
		t.Fatalf("tag %+v", tg)
	}
}

// An unbalanced constructed value ends the walk with an error rather than
// running off the end of the message.
func TestAnUnclosedConstructedValueIsNotWalkedPastTheEnd(t *testing.T) {
	o := ObjectID{Type: AnalogInput, Instance: 1}
	a, err := ParseAPDU(confirmed(ReadPropertyMultiple, concat(ctx(0, o.Encode()...), open(1), ctx(0, 85))...))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := Targets(a); ok {
		t.Fatal("an access list with no closing tag was located")
	}
}

// An object identifier that is not four octets is not an object
// identifier. The length is the sender's, so a policy that read three
// octets as an identifier would be deciding about an object nobody named.
func TestAnObjectIdentifierIsFourOctets(t *testing.T) {
	if _, err := DecodeObjectID([]byte{0, 0, 1}); err == nil {
		t.Fatal("three octets were read as an object identifier")
	}
	a, err := ParseAPDU(confirmed(ReadProperty, concat(ctx(0, 0, 0, 1), ctx(1, 85))...))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := Targets(a); ok {
		t.Fatal("a short object identifier was located")
	}
}

// The round trip, which is what says the twenty-two bit instance and the
// ten bit type are packed the way the standard packs them.
func TestAnObjectIdentifierRoundTrips(t *testing.T) {
	for _, o := range []ObjectID{
		{Type: AnalogInput, Instance: 0},
		{Type: DeviceObject, Instance: 4194302},
		{Type: 1023, Instance: maxInstance},
		{Type: NetworkPort, Instance: 1},
	} {
		got, err := DecodeObjectID(o.Encode())
		if err != nil {
			t.Fatal(err)
		}
		if got != o {
			t.Fatalf("%s came back as %s", o, got)
		}
	}
	if !(ObjectID{Type: DeviceObject, Instance: maxInstance}).Unassigned() {
		t.Fatal("the unassigned instance was not recognised")
	}
	if (ObjectID{Type: DeviceObject, Instance: 1}).Unassigned() {
		t.Fatal("a commissioned device was called unassigned")
	}
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// BACnet's own privilege ladder. A write at priority 1 takes a piece of
// plant away from the building management system, from the schedules and
// from the operator at the workstation, and holds it until whoever wrote
// it gives it back.
func TestTheMostPrivilegedPriorityIsTheOneReported(t *testing.T) {
	o := ObjectID{Type: AnalogOutput, Instance: 3}
	t.Run("stated", func(t *testing.T) {
		params := concat(ctx(0, o.Encode()...), ctx(1, u32(uint32(PropPresentValue))...),
			open(3), app(4, 0x41, 0xA8, 0x00, 0x00), closed(3), ctx(4, 1))
		a, err := ParseAPDU(confirmed(WriteProperty, params...))
		if err != nil {
			t.Fatal(err)
		}
		p, ok := CommandPriority(a)
		if !ok || p != 1 {
			t.Fatalf("priority %d %v, want 1", p, ok)
		}
	})
	t.Run("absent is the lowest there is", func(t *testing.T) {
		params := concat(ctx(0, o.Encode()...), ctx(1, u32(uint32(PropPresentValue))...),
			open(3), app(4, 0x41, 0xA8, 0x00, 0x00), closed(3))
		a, err := ParseAPDU(confirmed(WriteProperty, params...))
		if err != nil {
			t.Fatal(err)
		}
		p, ok := CommandPriority(a)
		if !ok || p != NoPriority {
			t.Fatalf("priority %d %v, want %d", p, ok, NoPriority)
		}
	})
	t.Run("a priority inside the value is not the requests", func(t *testing.T) {
		// A context tag 4 inside the constructed value, where a walk that
		// stepped through rather than over would find it.
		params := concat(ctx(0, o.Encode()...), ctx(1, u32(uint32(PropPresentValue))...),
			open(3), ctx(4, 1), closed(3))
		a, err := ParseAPDU(confirmed(WriteProperty, params...))
		if err != nil {
			t.Fatal(err)
		}
		p, ok := CommandPriority(a)
		if !ok || p != NoPriority {
			t.Fatalf("priority %d %v: a tag inside the value was read as the request's", p, ok)
		}
	})
	t.Run("the most privileged of several", func(t *testing.T) {
		params := concat(
			ctx(0, o.Encode()...), open(1),
			ctx(0, u32(uint32(PropPresentValue))...), open(2), app(4, 0x41, 0xA8, 0, 0), closed(2), ctx(3, 16),
			ctx(0, u32(uint32(PropRelinquishDefault))...), open(2), app(4, 0, 0, 0, 0), closed(2), ctx(3, 2),
			closed(1))
		a, err := ParseAPDU(confirmed(WritePropertyMultiple, params...))
		if err != nil {
			t.Fatal(err)
		}
		p, ok := CommandPriority(a)
		if !ok || p != 2 {
			t.Fatalf("priority %d %v, want 2 (the most privileged of the two)", p, ok)
		}
	})
	t.Run("out of range is not a priority", func(t *testing.T) {
		for _, bad := range []byte{0, 17, 255} {
			params := concat(ctx(0, o.Encode()...), ctx(1, u32(uint32(PropPresentValue))...), ctx(4, bad))
			a, err := ParseAPDU(confirmed(WriteProperty, params...))
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := CommandPriority(a); ok {
				t.Errorf("a priority of %d was accepted", bad)
			}
		}
	})
	t.Run("a read carries no priority", func(t *testing.T) {
		a, err := ParseAPDU(confirmed(ReadProperty, concat(ctx(0, o.Encode()...), ctx(1, 85))...))
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := CommandPriority(a); ok {
			t.Fatal("readProperty was read as carrying a priority")
		}
	})
}
