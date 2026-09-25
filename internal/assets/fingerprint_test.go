package assets

import (
	"strings"
	"testing"
)

// TestBehaviourOutweighsSelfDescription is the whole weighting of the rule set,
// asserted rather than left to the numbers: a device that *answers* Modbus on a
// unit identifier is a controller whatever its vendor class claims, because
// answering is much harder to fake than a string.
func TestBehaviourOutweighsSelfDescription(t *testing.T) {
	a := &Asset{
		Protos:      map[string]uint64{"modbus": 5, "dhcp": 1},
		AsServer:    5,
		Units:       []int{1},
		VendorClass: "MSFT 5.0", // claims to be Windows
		Vendor:      "VMware",   // and claims to be a virtual machine
	}
	c := Classify(a, DefaultRules())
	if c.Role != RolePLC {
		t.Fatalf("role %q, want plc; evidence %v", c.Role, c.Why)
	}
	if c.Confidence < 70 {
		t.Errorf("confidence %d", c.Confidence)
	}
	// The weaker evidence is still in the list, because an engineer arguing
	// with the conclusion needs to see what was weighed.
	joined := strings.Join(c.Why, "; ")
	if !strings.Contains(joined, "Modbus") {
		t.Errorf("the strongest evidence is not first: %v", c.Why)
	}
	if len(c.Why) < 2 {
		t.Errorf("only one piece of evidence was kept: %v", c.Why)
	}
}

// TestTheControlProtocolRolesComeFromTheDirection: on Modbus the controller
// answers and the thing driving the process asks, which is most of the
// classification on an operational network.
func TestTheControlProtocolRolesComeFromTheDirection(t *testing.T) {
	for _, c := range []struct {
		what string
		a    *Asset
		want Role
	}{
		{what: "answers Modbus",
			a:    &Asset{Protos: map[string]uint64{"modbus": 1}, AsServer: 1, Units: []int{1}},
			want: RolePLC},
		{what: "writes Modbus registers",
			a:    &Asset{Protos: map[string]uint64{"modbus": 1}, AsClient: 1, Funcs: []int{0x10}},
			want: RoleHMI},
		{what: "reads many Modbus units and never writes",
			a: &Asset{Protos: map[string]uint64{"modbus": 1}, AsClient: 1,
				Units: []int{1, 2, 3, 4}, Funcs: []int{0x03}},
			want: RoleHistorian},
		{what: "reads a Modbus device identification",
			a: &Asset{Protos: map[string]uint64{"modbus": 1}, AsClient: 1,
				Funcs: []int{0x2b}},
			want: RoleEngineering},
		{what: "answers IEC 104",
			a:    &Asset{Protos: map[string]uint64{"iec104": 1}, AsServer: 1},
			want: RoleRTU},
		{what: "commands an IEC 104 station",
			a:    &Asset{Protos: map[string]uint64{"iec104": 1}, AsClient: 1},
			want: RoleSCADA},
		{what: "polls Modbus and republishes over MQTT",
			a: &Asset{Protos: map[string]uint64{"modbus": 1, "mqtt": 1}, AsClient: 1,
				Units: []int{1, 2, 3, 4}, Funcs: []int{0x03}},
			want: RoleGateway},
		{what: "answers Modbus and also publishes over MQTT",
			a: &Asset{Protos: map[string]uint64{"modbus": 1, "mqtt": 1}, AsServer: 1,
				Units: []int{1}},
			want: RolePLC},
		{what: "publishes Sparkplug",
			a:    &Asset{Protos: map[string]uint64{"mqtt": 1}, ClientID: "spBv1.0/plant/NDATA/node1"},
			want: RoleGateway},
	} {
		got := Classify(c.a, DefaultRules())
		if got.Role != c.want {
			t.Errorf("%s: role %q, want %q (%v)", c.what, got.Role, c.want, got.Why)
		}
	}
}

// TestTheLevelFollowsTheRole, because a segmentation review asks what is on this
// wire that does not belong at this level.
func TestTheLevelFollowsTheRole(t *testing.T) {
	for role, want := range map[Role]int{
		RoleSensor: 0, RoleDrive: 0,
		RolePLC: 1, RoleRTU: 1,
		RoleHMI: 2, RoleSCADA: 2, RoleGateway: 2,
		RoleHistorian: 3, RoleEngineering: 3,
		RolePrinter: 4, RoleCamera: 4, RolePhone: 4, RoleServer: 4, RoleWorkstation: 4,
		RoleSwitch: LevelUnknown, RoleRouter: LevelUnknown,
		RoleEmbedded: LevelUnknown, RoleUnknown: LevelUnknown,
	} {
		if got := role.Level(); got != want {
			t.Errorf("%s is level %d, want %d", role, got, want)
		}
	}
	// The network equipment has no level on purpose: it carries every level and
	// sits at none.
	if RoleSwitch.Level() != LevelUnknown {
		t.Error("a switch was given a Purdue level")
	}
}

// TestARoleIsNamedTheWayAConfigurationWritesIt.
func TestARoleIsNamedTheWayAConfigurationWritesIt(t *testing.T) {
	for _, r := range Roles() {
		got, ok := RoleOf(strings.ToUpper(" " + string(r) + " "))
		if !ok || got != r {
			t.Errorf("%q read as %q ok=%v", r, got, ok)
		}
		if r != RoleUnknown && !r.Known() {
			t.Errorf("%q is not known", r)
		}
	}
	if _, ok := RoleOf("plc-ish"); ok {
		t.Error("a role nobody defines was named")
	}
	if RoleUnknown.Known() || Role("").Known() || Role("nonsense").Known() {
		t.Error("an unnamed role reports as known")
	}
}

// TestTwoRulesOfEqualWeightDisagreeingIsSaidOutLoud rather than resolved
// silently, because a disputed conclusion is worth less than an undisputed one
// and an engineer should see which.
func TestTwoRulesOfEqualWeightDisagreeingIsSaidOutLoud(t *testing.T) {
	rules := []Rule{
		{Name: "first", Role: RolePLC, Confidence: 60, Match: func(*Asset) bool { return true }},
		{Name: "second", Role: RoleHMI, Confidence: 60, Match: func(*Asset) bool { return true }},
	}
	c := Classify(&Asset{}, rules)
	if !c.Ambiguous {
		t.Fatal("a disagreement was resolved silently")
	}
	if c.Role != RolePLC {
		t.Errorf("role %q: the rule set's own order should decide a tie", c.Role)
	}
	if c.Confidence != 50 {
		t.Errorf("confidence %d, want the claimed 60 reduced for the dispute", c.Confidence)
	}
	// Two rules of equal weight that *agree* are not a dispute.
	rules[1].Role = RolePLC
	if Classify(&Asset{}, rules).Ambiguous {
		t.Error("two rules agreeing were reported as ambiguous")
	}
}

// TestAnAssetNoRuleMatchesIsUnknownRatherThanGuessed. An inventory that says
// "unknown" invites somebody to look; one that guesses gets written into a
// segmentation policy.
func TestAnAssetNoRuleMatchesIsUnknownRatherThanGuessed(t *testing.T) {
	c := Classify(&Asset{Protos: map[string]uint64{"syslog": 3}}, DefaultRules())
	if c.Role != RoleUnknown || c.Level != LevelUnknown {
		t.Fatalf("classification %+v", c)
	}
	if c.Confidence != 0 || len(c.Why) != 0 {
		t.Errorf("an unknown asset carries %d confidence and %v", c.Confidence, c.Why)
	}
}

// TestTheVendorPrefixOnlyConcludesARoleWhereTheVendorMakesOneKindOfDevice, and
// never at a weight that could outvote behaviour.
func TestTheVendorPrefixOnlyConcludesARoleWhereTheVendorMakesOneKindOfDevice(t *testing.T) {
	for vendor, want := range map[string]Role{
		"Axis Communications": RoleCamera,
		"Polycom":             RolePhone,
		"Yealink":             RolePhone,
		"Zebra Technologies":  RolePrinter,
		"Raspberry Pi":        RoleEmbedded,
		"VMware":              RoleServer,
		"Moxa":                RoleGateway,
		// A vendor that makes controllers, drives, switches and software is
		// deliberately not a rule: naming it would put a role on a device on
		// the strength of three bytes anybody can set.
		"Siemens":                  RoleUnknown,
		"Allen-Bradley (Rockwell)": RoleUnknown,
		"Cisco":                    RoleUnknown,
	} {
		c := Classify(&Asset{Vendor: vendor, Protos: map[string]uint64{}}, DefaultRules())
		if c.Role != want {
			t.Errorf("%s: role %q, want %q", vendor, c.Role, want)
		}
		if want != RoleUnknown && c.Confidence > 50 {
			t.Errorf("%s: a vendor prefix is worth %d, which is too much", vendor, c.Confidence)
		}
	}
	// And behaviour beats it: a camera vendor's prefix on something answering
	// Modbus is a controller.
	c := Classify(&Asset{Vendor: "Axis Communications", AsServer: 1, Units: []int{1},
		Protos: map[string]uint64{"modbus": 1}}, DefaultRules())
	if c.Role != RolePLC {
		t.Errorf("a vendor prefix outvoted behaviour: %+v", c)
	}
}

// TestTheDescriptionRulesReadTheStringsDevicesActuallySend.
func TestTheDescriptionRulesReadTheStringsDevicesActuallySend(t *testing.T) {
	for _, c := range []struct {
		desc string
		want Role
	}{
		{"Cisco IOS Software, C2960X Software", RoleSwitch},
		{"Cisco NX-OS(tm) n9000", RoleSwitch},
		{"JUNOS 21.4R3", RoleRouter},
		{"RouterOS 7.11", RoleRouter},
		{"HP ETHERNET MULTI-ENVIRONMENT, JETDIRECT", RolePrinter},
		{"Brother NC-8300w printer", RolePrinter},
		{"SIMATIC S7-1200 CPU 1214C", RolePLC},
		{"ControlLogix 5580", RolePLC},
		{"PowerFlex 525 AC Drive", RoleDrive},
		{"Altivar ATV320", RoleDrive},
		{"a description that says nothing", RoleUnknown},
	} {
		got := Classify(&Asset{Description: c.desc, Protos: map[string]uint64{"snmp": 1}}, DefaultRules())
		if got.Role != c.want {
			t.Errorf("%q: role %q, want %q", c.desc, got.Role, c.want)
		}
	}
}

// TestWritingIsWhatSeparatesAnHMIFromAHistorian, because reading and writing is
// the distinction a process engineer cares about most.
func TestWritingIsWhatSeparatesAnHMIFromAHistorian(t *testing.T) {
	for _, f := range []int{0x05, 0x06, 0x0f, 0x10, 0x16, 0x17} {
		if !writesModbus([]int{f}) {
			t.Errorf("function %#02x is a write and was not read as one", f)
		}
	}
	for _, f := range []int{0x01, 0x02, 0x03, 0x04, 0x2b} {
		if writesModbus([]int{f}) {
			t.Errorf("function %#02x is a read and was read as a write", f)
		}
	}
	if writesModbus(nil) {
		t.Error("no functions at all read as a write")
	}
}
