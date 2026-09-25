package bacnet

import (
	"strings"
	"testing"
)

// The tables in this package have to agree with each other, and comments
// saying they do are not worth having. This test is the agreement: the
// same kind of check found invented commands and wrong key positions in
// the Redis tables, and there is no reason to think a hand-typed table of
// forty-eight BACnet services is better.
func TestTheServiceTablesAgreeWithEachOther(t *testing.T) {
	every := map[Service]bool{}
	for c := range confirmedNames {
		every[Service{Confirmed: true, Choice: c}] = true
	}
	for c := range unconfirmedNames {
		every[Service{Choice: c}] = true
	}
	// Every service named in a table is a service the standard defines.
	for _, tbl := range []struct {
		name string
		m    map[Service]bool
	}{{"writing", writing}, {"dangerous", dangerous}, {"deprecated", deprecated}, {"objectless", objectless}} {
		for s := range tbl.m {
			if !every[s] {
				t.Errorf("%s names %s, which no edition of the standard has", tbl.name, s)
			}
		}
	}
	for s := range locate {
		if !every[s] {
			t.Errorf("locate names %s, which no edition of the standard has", s)
		}
	}
	// A service cannot both name no object and have one at a fixed place.
	for s := range objectless {
		if _, ok := locate[s]; ok {
			t.Errorf("%s is in both objectless and locate", s)
		}
	}
	// Everything dangerous or deprecated is either a write or, in the
	// case of the two withdrawn reads, something worse than one -- so no
	// dangerous service may be absent from the writing table unless it is
	// one of the three the standard withdrew.
	for s := range dangerous {
		if !s.Writes() && !s.Deprecated() {
			t.Errorf("%s is dangerous but not a write, and is not deprecated either", s)
		}
	}
	// Nothing in the default allow list changes anything. This is the one
	// that matters: a service that slipped into the defaults and turns
	// out to write would be every listener carrying it.
	for _, n := range DefaultServices() {
		s, ok := ParseService(n)
		if !ok {
			t.Fatalf("DefaultServices names %q, which ParseService does not know", n)
		}
		if s.Writes() {
			t.Errorf("%s is in the default allow list and it writes", n)
		}
		if s.Dangerous() {
			t.Errorf("%s is in the default allow list and it is dangerous", n)
		}
	}
	// And every name in every list parses back to the service it names.
	for _, n := range AllServices() {
		s, ok := ParseService(n)
		if !ok {
			t.Fatalf("%q does not parse", n)
		}
		if s.Name() != n {
			t.Errorf("%q parses to %s", n, s)
		}
		if !s.Known() {
			t.Errorf("%q parses to a service that is not known", n)
		}
	}
	if len(AllServices()) != len(every) {
		t.Errorf("AllServices lists %d of %d services", len(AllServices()), len(every))
	}
}

// A service number is not a service: confirmed 6 is atomicReadFile and
// unconfirmed 6 is timeSynchronization, one a read and the other a write
// of every clock on the network.
func TestTheSameChoiceNumberIsTwoDifferentServices(t *testing.T) {
	read := Service{Confirmed: true, Choice: 6}
	sync := Service{Choice: 6}
	if read.Name() == sync.Name() {
		t.Fatal("the two sixes have the same name")
	}
	if read.Writes() {
		t.Error("atomicReadFile was read as a write")
	}
	if !sync.Writes() || !sync.Dangerous() {
		t.Error("timeSynchronization is a write, and a dangerous one")
	}
}

// An unknown service choice counts as a write. A vendor shipping a
// proprietary choice in the standard's range is the ordinary case, and
// the only safe reading of a service whose effect is unknown is that it
// has one.
func TestAnUnknownServiceCountsAsAWrite(t *testing.T) {
	for _, s := range []Service{{Confirmed: true, Choice: 200}, {Choice: 99}} {
		if s.Known() {
			t.Fatalf("%s is not a service of the standard", s)
		}
		if !s.Writes() {
			t.Errorf("%s, which nothing knows, was read as a read", s)
		}
		if !strings.Contains(s.Name(), "service-") {
			t.Errorf("%s is rendered as if it had a name", s)
		}
	}
}

// The properties and object types a policy is written in have to survive
// the round trip through a configuration file, including the numeric form
// an estate with a vendor's proprietary type has no other way to write.
func TestObjectTypesAndPropertiesRoundTripThroughTheirNames(t *testing.T) {
	for _, n := range AllObjectTypes() {
		got, ok := ParseObjectType(n)
		if !ok {
			t.Fatalf("%q does not parse", n)
		}
		if got.String() != n {
			t.Errorf("%q parses to %s", n, got)
		}
	}
	if _, ok := ParseObjectType("analog-inputs"); ok {
		t.Error("a name the standard does not have was accepted")
	}
	if got, ok := ParseObjectType("  ANALOG-INPUT "); !ok || got != AnalogInput {
		t.Errorf("case and space: %s %v", got, ok)
	}
	if got, ok := ParseObjectType("500"); !ok || got != ObjectType(500) {
		t.Errorf("a proprietary type by number: %s %v", got, ok)
	}
	if _, ok := ParseObjectType("1024"); ok {
		t.Error("an object type past the ten bits it has was accepted")
	}
	if !ObjectType(500).Proprietary() || ObjectType(8).Proprietary() {
		t.Error("the proprietary range is wrong")
	}
	for _, n := range []string{"present-value", "out-of-service", "object-name", "program-change"} {
		p, ok := ParseProperty(n)
		if !ok || p.String() != n {
			t.Errorf("%q parses to %s (%v)", n, p, ok)
		}
		if !p.Named() {
			t.Errorf("%q is not named", n)
		}
	}
	if got, ok := ParseProperty("4194303"); ok && got != PropertyID(4194303) {
		t.Errorf("a property by number: %s", got)
	}
	if _, ok := ParseProperty("4194304"); ok {
		t.Error("a property past the twenty-two bits it has was accepted")
	}
	if !PropertyID(600).Proprietary() || PropertyID(85).Proprietary() {
		t.Error("the proprietary property range is wrong")
	}
	if !PropOutOfService.Sensitive() || PropPresentValue.Sensitive() {
		t.Error("out-of-service is sensitive and present-value is not")
	}
	if len(SensitiveProperties()) != len(sensitive) {
		t.Error("SensitiveProperties does not list them all")
	}
	if !PropAll.Wholesale() || PropPresentValue.Wholesale() {
		t.Error("the wholesale property identifiers are wrong")
	}
	if PropertyID(999).String() != "proprietary-property-999" {
		t.Errorf("an unnamed property renders as %q", PropertyID(999))
	}
	if PropertyID(199).String() != "property-199" {
		t.Errorf("an unnamed standard property renders as %q", PropertyID(199))
	}
}

// Commandable is the difference between somebody writing to a value a
// graphics page reads and somebody moving a piece of plant. The two are
// the same service with the same shape, so the object type is all a
// policy has to tell them apart.
func TestCommandableIsTheObjectTypesThatDriveSomething(t *testing.T) {
	for _, o := range []ObjectType{AnalogOutput, BinaryOutput, MultiStateOutput, 54, 55, 28, 53, 30, 57, 58, 59} {
		if !o.Commandable() {
			t.Errorf("%s does not drive anything?", o)
		}
	}
	for _, o := range []ObjectType{AnalogInput, AnalogValue, BinaryInput, DeviceObject, TrendLog, ScheduleObject} {
		if o.Commandable() {
			t.Errorf("%s was counted as driving something", o)
		}
	}
}

// The lists the documentation and a refusal message are built from have
// to be the tables themselves, or the document drifts from the code.
func TestTheNameListsComeFromTheTables(t *testing.T) {
	if len(DangerousServices()) != len(dangerous) {
		t.Fatalf("DangerousServices lists %d of %d", len(DangerousServices()), len(dangerous))
	}
	for _, n := range DangerousServices() {
		s, ok := ParseService(n)
		if !ok || !s.Dangerous() {
			t.Errorf("%q is listed as dangerous and is not", n)
		}
	}
	if !sorted(DangerousServices()) || !sorted(DefaultServices()) || !sorted(AllServices()) || !sorted(AllObjectTypes()) {
		t.Error("a list that a document is built from is not sorted")
	}
}

func sorted(s []string) bool {
	for i := 1; i < len(s); i++ {
		if s[i-1] > s[i] {
			return false
		}
	}
	return true
}
