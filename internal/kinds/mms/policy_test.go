package mms

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/mms"
)

// The policy on its own, without a session.
//
// The end-to-end tests next door build real BER and drive it through the relay,
// which is what proves the reader and the policy agree about what arrived. This
// file is about the policy's own judgements, and on this protocol they are the
// substance of the kind: what a functional constraint means for the plant, which
// services replace what is inside a protection relay rather than telling it what
// to do, and the interlock the devices themselves cannot be trusted to keep --
// `ctlModel` lives in `$CF$`, and `$CF$` is writable.

func policyOf(t *testing.T, c *config.MMSListener) *policy {
	t.Helper()
	p, err := compile(c)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

func yes() *bool  { b := true; return &b }
func nope() *bool { b := false; return &b }

var at = time.Date(2026, 3, 4, 12, 0, 0, 0, time.UTC)

// assoc is an association that completed both handshakes, which is the state
// every decision below is made in.
func assoc(apTitle string) Association {
	return Association{IP: ip("10.0.0.5"), APTitle: apTitle, Associated: true,
		Initiated: true, At: at}
}

// obj is one operation on a domain-specific name, parsed the way the reader
// parses what arrived.
func obj(name string, write bool) Operation {
	slash := strings.IndexByte(name, '/')
	n := wire.ParseItem(name[slash+1:])
	n.Kind, n.Domain = wire.NameDomain, name[:slash]
	return Operation{Name: n, Write: write}
}

// The defaults are the ones that matter here: what an operator gets by naming an
// upstream is a listener that reads and writes what an HMI writes, and carries
// nothing that replaces a relay's contents.
func TestTheDefaultClassesAndConstraintsAreWhatAnHMIDoes(t *testing.T) {
	p := policyOf(t, &config.MMSListener{Upstream: "ieds", DefaultAction: "allow"})

	// The classes a control centre and an HMI need are carried.
	for _, svc := range []wire.Service{wire.SvcRead, wire.SvcWrite, wire.SvcGetNameList,
		wire.SvcDefineNamedVariableList, wire.SvcFileRead, wire.SvcStatus,
		wire.SvcGetAlarmSummary} {
		if d := p.Request(assoc("hmi"), svc); !d.Allow {
			t.Errorf("%s is refused by default: %+v", svc, d)
		}
	}
	// And the ones that replace what is inside an IED, or reach its firmware,
	// are not -- each with the error class an IED would have used.
	for _, c := range []struct {
		svc    wire.Service
		reason string
	}{
		{wire.SvcStoreDomainContent, "domain_services_not_allowed"},
		{wire.SvcDeleteDomain, "domain_services_not_allowed"},
		{wire.SvcStart, "service_class_not_allowed"},
		{wire.SvcKill, "service_class_not_allowed"},
	} {
		d := p.Request(assoc("hmi"), c.svc)
		if d.Allow || d.Reason != c.reason {
			t.Errorf("%s decided %+v, want %s", c.svc, d, c.reason)
		}
		if d.ErrorClass != ErrClassService {
			t.Errorf("%s is refused with error class %d, want the service class", c.svc, d.ErrorClass)
		}
	}
	// A service this build has not classified is refused hard: forwarding it
	// would be forwarding something to a substation with no policy applied.
	d := p.Request(assoc("hmi"), wire.Service(200))
	if d.Allow || d.Reason != "service_unknown" || !d.Hard {
		t.Errorf("an unclassified service decided %+v", d)
	}
	// The write constraints an HMI writes, and the three it does not: SG and SE
	// change what the device will do in a fault, CF changes how it is told to.
	for _, fc := range []string{"ST", "MX", "SP", "SV", "BL", "CO"} {
		op := obj("LD0/XCBR1$"+fc+"$Pos$ctlVal", true)
		if d := p.Operations(assoc("hmi"), wire.SvcWrite, []Operation{op}); !d.Allow {
			t.Errorf("a write to %s is refused by default: %+v", fc, d)
		}
	}
	for _, fc := range []string{"SG", "SE", "CF"} {
		op := obj("LD0/XCBR1$"+fc+"$Pos$ctlModel", true)
		d := p.Operations(assoc("hmi"), wire.SvcWrite, []Operation{op})
		if d.Allow || d.Reason != "write_constraint_not_allowed" {
			t.Errorf("a write to %s decided %+v", fc, d)
		}
	}
	// Reading any of them is a read, and the read lists are not the write
	// lists: an estate that cannot see its setting groups cannot check them.
	for _, fc := range []string{"SG", "SE", "CF", "DC", "EX"} {
		op := obj("LD0/XCBR1$"+fc+"$Pos$ctlModel", false)
		if d := p.Operations(assoc("hmi"), wire.SvcRead, []Operation{op}); !d.Allow {
			t.Errorf("a read of %s is refused by default: %+v", fc, d)
		}
	}
}

// allow_domain_services and the class list have to agree, or turning the knob on
// would leave the services it names refused by the default list -- which reads
// as the knob not working.
func TestTheDomainServiceKnobAndTheDefaultClassListAgree(t *testing.T) {
	p := policyOf(t, &config.MMSListener{Upstream: "ieds", DefaultAction: "allow",
		AllowDomainServices: true})
	for _, svc := range []wire.Service{wire.SvcStoreDomainContent, wire.SvcDeleteDomain,
		wire.SvcRequestDomainDownload} {
		if d := p.Request(assoc("tool"), svc); !d.Allow {
			t.Errorf("%s is still refused with allow_domain_services: %+v", svc, d)
		}
	}
	// A listener that names its own classes is taken at its word, and the knob
	// does not widen a list somebody wrote.
	named := policyOf(t, &config.MMSListener{Upstream: "ieds", DefaultAction: "allow",
		ServiceClasses: []string{"read", "browse"}, AllowDomainServices: true})
	if d := named.Request(assoc("tool"), wire.SvcStoreDomainContent); d.Allow {
		t.Errorf("a named class list was widened by the knob: %+v", d)
	}
	if d := named.Request(assoc("tool"), wire.SvcWrite); d.Allow ||
		d.Reason != "service_class_not_allowed" {
		t.Errorf("a class outside the named list decided %+v", d)
	}
}

// read_only is about what a service does rather than what it is called, so it
// covers the deletes and the downloads without naming them.
func TestReadOnlyRefusesEveryServiceThatChangesADevice(t *testing.T) {
	p := policyOf(t, &config.MMSListener{Upstream: "ieds", DefaultAction: "allow",
		ReadOnly: true, AllowDomainServices: true})
	for _, svc := range []wire.Service{wire.SvcWrite, wire.SvcDeleteDomain,
		wire.SvcFileDelete, wire.SvcDefineNamedVariableList, wire.SvcStoreDomainContent} {
		d := p.Request(assoc("hmi"), svc)
		if d.Allow || d.Reason != "read_only" || !d.Hard {
			t.Errorf("%s against a read-only listener decided %+v", svc, d)
		}
	}
	for _, svc := range []wire.Service{wire.SvcRead, wire.SvcGetNameList, wire.SvcFileRead} {
		if d := p.Request(assoc("hmi"), svc); !d.Allow {
			t.Errorf("%s is refused by read_only: %+v", svc, d)
		}
	}
}

// The identity checks, which happen on the ACSE associate rather than on a
// request: by the time a request arrives the association is fixed.
func TestTheAssociationIsDecidedOnWhoItSaysItIs(t *testing.T) {
	p := policyOf(t, &config.MMSListener{Upstream: "ieds",
		APTitles: []string{"scada-*", "hmi1"}, DenyAPTitles: []string{"scada-test"},
		AEQualifiers: []string{"12", "20-30"}, RequireAPTitle: true,
		RefusePlaintextPasswords: true})

	for _, c := range []struct {
		name   string
		edit   func(*Association)
		reason string
		hard   bool
	}{
		{"no AP-title at all", func(a *Association) { a.APTitle = "" }, "no_ap_title", false},
		{"a denied AP-title", func(a *Association) { a.APTitle = "scada-test" },
			"ap_title_denied", true},
		{"an AP-title off the list", func(a *Association) { a.APTitle = "laptop" },
			"ap_title_not_allowed", false},
		{"no AE-qualifier where the list needs one", func(a *Association) { a.HasQualifier = false },
			"no_ae_qualifier", false},
		{"a qualifier outside the ranges", func(a *Association) { a.AEQualifier = 99 },
			"ae_qualifier_not_allowed", false},
		{"a password in the clear", func(a *Association) {
			a.Auth, a.AuthLength = wire.AuthPassword, 8
		}, "plaintext_password", true},
	} {
		a := assoc("scada-1")
		a.HasQualifier, a.AEQualifier = true, 25
		c.edit(&a)
		d := p.Associate(a)
		if d.Allow || d.Reason != c.reason {
			t.Errorf("%s decided %+v, want %s", c.name, d, c.reason)
		}
		if d.Hard != c.hard {
			t.Errorf("%s is hard=%v, want %v", c.name, d.Hard, c.hard)
		}
	}
	// A glob on the allow list, a qualifier inside a range, and no password:
	// the association every estate actually has.
	ok := assoc("scada-1")
	ok.HasQualifier, ok.AEQualifier = true, 12
	if d := p.Associate(ok); !d.Allow {
		t.Fatalf("a legitimate association was refused: %+v", d)
	}
	// The address lists are answered before any of it, because they are all a
	// connection is before it has said anything.
	net := policyOf(t, &config.MMSListener{Upstream: "ieds",
		AllowClients: []string{"10.0.0.0/24"}, DenyClients: []string{"10.0.0.9/32"}})
	for _, c := range []struct {
		addr   string
		allow  bool
		reason string
	}{
		{"10.0.0.5", true, ""},
		{"10.0.0.9", false, "client_denied"},
		{"10.9.9.9", false, "client_not_allowed"},
	} {
		d := net.Connect(Association{IP: ip(c.addr)})
		if d.Allow != c.allow || (!c.allow && (d.Reason != c.reason || !d.Hard)) {
			t.Errorf("%s decided %+v, want allow=%v %s", c.addr, d, c.allow, c.reason)
		}
	}
	// And the identity a log line carries says which part is missing rather
	// than leaving a blank column.
	if got := (Association{}).Identity(); got != "<no association>" {
		t.Errorf("an association that never completed is named %q", got)
	}
	if got := (Association{Associated: true}).Identity(); got != "<no ap-title>" {
		t.Errorf("an association with no AP-title is named %q", got)
	}
	if got := assoc("hmi1").Identity(); got != "hmi1" {
		t.Errorf("an association is named %q", got)
	}
}

// The object, domain and constraint lists, and the order between them: a deny
// list no rule overrides, then the allow lists, then what the constraint means.
func TestTheObjectListsAreReadInOrderAndADenyIsNotOverridable(t *testing.T) {
	p := policyOf(t, &config.MMSListener{Upstream: "ieds", DefaultAction: "allow",
		Domains:         []string{"AA1J1Q01A1LD0", "AA1J1Q01A1LD1"},
		DenyDomains:     []string{"AA1J1Q01A1LD9"},
		Objects:         []string{"*/MMXU1$MX$*", "*/XCBR1$*"},
		DenyObjects:     []string{"*/XCBR1$CO$Pos$Oper"},
		WriteObjects:    []string{"*/XCBR1$ST$*"},
		DenyConstraints: []string{"SE"}})

	for _, c := range []struct {
		name   string
		op     Operation
		reason string
		hard   bool
	}{
		{"a denied object", obj("AA1J1Q01A1LD0/XCBR1$CO$Pos$Oper", false),
			"object_denied", true},
		{"a denied domain", obj("AA1J1Q01A1LD9/XCBR1$ST$Pos$stVal", false),
			"domain_denied", true},
		{"a denied constraint", obj("AA1J1Q01A1LD0/XCBR1$SE$Pos$ctlVal", false),
			"constraint_denied", true},
		{"a domain off the list", obj("AA1J1Q02A1LD0/XCBR1$ST$Pos$stVal", false),
			"domain_not_allowed", false},
		{"an object off the list", obj("AA1J1Q01A1LD0/CSWI1$ST$Pos$stVal", false),
			"object_not_allowed", false},
		// The write list stands in for the object list on a write, so an
		// object readable here is not therefore writable.
		{"a write outside the write list", obj("AA1J1Q01A1LD0/MMXU1$MX$TotW$mag", true),
			"write_object_not_allowed", false},
	} {
		d := p.Operations(assoc("hmi"), wire.SvcRead, []Operation{c.op})
		if c.op.Write {
			d = p.Operations(assoc("hmi"), wire.SvcWrite, []Operation{c.op})
		}
		if d.Allow || d.Reason != c.reason {
			t.Errorf("%s decided %+v, want %s", c.name, d, c.reason)
		}
		if d.Hard != c.hard {
			t.Errorf("%s is hard=%v, want %v", c.name, d.Hard, c.hard)
		}
	}
	// What the lists do admit.
	for _, op := range []Operation{
		obj("AA1J1Q01A1LD0/MMXU1$MX$TotW$mag", false),
		obj("AA1J1Q01A1LD1/XCBR1$ST$Pos$stVal", false),
		obj("AA1J1Q01A1LD0/XCBR1$ST$Pos$stVal", true),
	} {
		svc := wire.SvcRead
		if op.Write {
			svc = wire.SvcWrite
		}
		if d := p.Operations(assoc("hmi"), svc, []Operation{op}); !d.Allow {
			t.Errorf("%s was refused: %+v", op.Name.Key(), d)
		}
	}
	// A request is one decision: twenty objects with one refused is a refused
	// request, because an IED that answered nineteen would leave the client
	// believing it had read twenty.
	many := []Operation{
		obj("AA1J1Q01A1LD0/MMXU1$MX$TotW$mag", false),
		obj("AA1J1Q01A1LD0/CSWI1$ST$Pos$stVal", false),
	}
	if d := p.Operations(assoc("hmi"), wire.SvcRead, many); d.Allow {
		t.Error("a request with one refused object was allowed as a whole")
	}
}

// A name with no functional constraint in it is a device's own variable or a
// client's named list, and the constraint rules say nothing about it -- except
// on a write, where a narrowed write list makes an unparsed name a refusal
// rather than a hole.
func TestAnUnparsedNameIsNotGivenTheConstraintARuleAllows(t *testing.T) {
	p := policyOf(t, &config.MMSListener{Upstream: "ieds", DefaultAction: "allow"})
	flat := Operation{Name: wire.Name{Kind: wire.NameVMD, Item: "VendorCounter"}}
	if d := p.Operations(assoc("hmi"), wire.SvcRead, []Operation{flat}); !d.Allow {
		t.Fatalf("reading a name with no constraint was refused: %+v", d)
	}
	flat.Write = true
	d := p.Operations(assoc("hmi"), wire.SvcWrite, []Operation{flat})
	if d.Allow || d.Reason != "constraint_unknown" {
		t.Fatalf("writing a name with no constraint decided %+v", d)
	}
	// A second segment that is not a functional constraint leaves the name
	// unparsed rather than inventing a constraint for it, so it takes the same
	// path: readable, and refused on a write where a write-constraint list is
	// in force.
	odd := obj("LD0/XCBR1$ZZ$Pos$stVal", false)
	if odd.Name.Parsed {
		t.Fatalf("%q was parsed as carrying a constraint", odd.Name.Item)
	}
	if d := p.Operations(assoc("hmi"), wire.SvcRead, []Operation{odd}); !d.Allow {
		t.Fatalf("reading a name in some other form was refused: %+v", d)
	}
	odd.Write = true
	if d := p.Operations(assoc("hmi"), wire.SvcWrite, []Operation{odd}); d.Allow {
		t.Fatalf("writing a name in some other form was allowed: %+v", d)
	}
}

// allow_operate is the switch between a listener that can move plant and one
// that cannot, and a rule may narrow it or widen it for its own traffic.
func TestOperateIsItsOwnDecisionAboveTheWriteConstraint(t *testing.T) {
	p := policyOf(t, &config.MMSListener{Upstream: "ieds", DefaultAction: "allow",
		AllowOperate: nope(),
		Rules: []config.MMSRule{{Name: "control-room", Clients: []string{"10.0.9.0/24"},
			AllowOperate: yes()}}})

	op := obj("LD0/XCBR1$CO$Pos$Oper", true)
	d := p.Operations(assoc("hmi"), wire.SvcWrite, []Operation{op})
	if d.Allow || d.Reason != "operate_not_allowed" {
		t.Fatalf("an operate against allow_operate: false decided %+v", d)
	}
	// A select is not an operate: a client that may select and not operate has
	// reserved a breaker without being able to move it.
	sel := obj("LD0/XCBR1$CO$Pos$SBOw", true)
	if d := p.Operations(assoc("hmi"), wire.SvcWrite, []Operation{sel}); !d.Allow {
		t.Fatalf("a select was refused as an operate: %+v", d)
	}
	// And the rule that is allowed to operate is.
	room := assoc("hmi")
	room.IP = ip("10.0.9.4")
	if d := p.Operations(room, wire.SvcWrite, []Operation{op}); !d.Allow || d.Rule != "control-room" {
		t.Fatalf("the rule that may operate was refused: %+v", d)
	}
}

// Select before operate is the decision the devices may not make: ctlModel
// lives in $CF$, and $CF$ is writable, so a listener that tracks the selection
// itself has put the interlock somewhere the configuration cannot reach.
func TestTheInterlockIsKeptWhereTheConfigurationCannotReachIt(t *testing.T) {
	p := policyOf(t, &config.MMSListener{Upstream: "ieds", DefaultAction: "allow",
		RequireSelectBeforeOperate: true, SelectTimeout: config.Duration(10 * time.Second)})

	if !p.RequiresSelect() || p.SelectTimeout() != 10*time.Second {
		t.Fatalf("the listener reports requireSelect=%v timeout=%v",
			p.RequiresSelect(), p.SelectTimeout())
	}
	oper := wire.ParseItem("XCBR1$CO$Pos$Oper")
	oper.Kind, oper.Domain = wire.NameDomain, "LD0"

	a := assoc("hmi")
	d := p.Operate(a, oper, at)
	if d.Allow || d.Reason != "not_selected" {
		t.Fatalf("an operate with no selection decided %+v", d)
	}
	// A selection is remembered against the object rather than the attribute,
	// because the select names SBOw and the operate that follows names Oper.
	sbow := wire.ParseItem("XCBR1$CO$Pos$SBOw")
	sbow.Kind, sbow.Domain = wire.NameDomain, "LD0"
	if selectKey(sbow) != selectKey(oper) {
		t.Fatalf("a select on %s is remembered as %q and the operate looks for %q",
			sbow.Key(), selectKey(sbow), selectKey(oper))
	}
	a.Selected = map[string]time.Time{selectKey(sbow): at.Add(10 * time.Second)}
	if d := p.Operate(a, oper, at); !d.Allow {
		t.Fatalf("an operate after its select was refused: %+v", d)
	}
	// A selection that has run out is not a selection.
	d = p.Operate(a, oper, at.Add(time.Minute))
	if d.Allow || d.Reason != "selection_expired" {
		t.Fatalf("an operate after the timeout decided %+v", d)
	}
	// A selection on another object is not this one's.
	other := wire.ParseItem("XCBR2$CO$Pos$Oper")
	other.Kind, other.Domain = wire.NameDomain, "LD0"
	if d := p.Operate(a, other, at); d.Allow {
		t.Fatalf("one object's selection allowed another's operate: %+v", d)
	}
	// Without the setting the check is not made at all, and a timeout nobody
	// configured is IEC 61850-7-2's own default for sboTimeout.
	off := policyOf(t, &config.MMSListener{Upstream: "ieds", DefaultAction: "allow"})
	if off.RequiresSelect() {
		t.Error("the interlock is on by default")
	}
	if off.SelectTimeout() != 30*time.Second {
		t.Errorf("the default select timeout is %v, want 30s", off.SelectTimeout())
	}
	if d := off.Operate(assoc("hmi"), oper, at); !d.Allow {
		t.Errorf("an operate was measured against an interlock nobody asked for: %+v", d)
	}
}

// The size bounds, which are about the request rather than about access.
func TestTheNameBoundsAreTheRequestsOwn(t *testing.T) {
	p := policyOf(t, &config.MMSListener{Upstream: "ieds", DefaultAction: "allow",
		MaxNames: 4, MaxWriteNames: 2})

	ops := func(n int, write bool) []Operation {
		out := make([]Operation, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, obj("LD0/MMXU1$MX$TotW$mag", write))
		}
		return out
	}
	if d := p.Bounds(wire.SvcRead, ops(4, false), false); !d.Allow {
		t.Fatalf("a read at the bound was refused: %+v", d)
	}
	d := p.Bounds(wire.SvcRead, ops(5, false), false)
	if d.Allow || d.Reason != "too_many_names" || d.ErrorClass != ErrClassResource {
		t.Fatalf("a read over the bound decided %+v", d)
	}
	// A write has its own, tighter bound.
	if d := p.Bounds(wire.SvcWrite, ops(3, true), false); d.Allow {
		t.Fatalf("a write over the write bound was allowed: %+v", d)
	}
	if d := p.Bounds(wire.SvcWrite, ops(2, true), false); !d.Allow {
		t.Fatalf("a write at the write bound was refused: %+v", d)
	}
	// More names than the reader kept is a refusal whatever the bound says: a
	// policy that decided on the names it could see would be allowing the ones
	// it could not.
	d = p.Bounds(wire.SvcRead, ops(1, false), true)
	if d.Allow || d.Reason != "too_many_names" || !d.Hard {
		t.Fatalf("a truncated request decided %+v", d)
	}
	// With no write bound the read bound applies to both.
	one := policyOf(t, &config.MMSListener{Upstream: "ieds", DefaultAction: "allow", MaxNames: 2})
	if d := one.Bounds(wire.SvcWrite, ops(3, true), false); d.Allow {
		t.Fatalf("a write past max_names was allowed: %+v", d)
	}
}

// The file services, which is how configuration and disturbance records move.
func TestTheFileListsDecideAPath(t *testing.T) {
	p := policyOf(t, &config.MMSListener{Upstream: "ieds", DefaultAction: "allow",
		Files: []string{"COMTRADE/*", "CID/*.cid"}, DenyFiles: []string{"COMTRADE/secret*"}})

	for _, c := range []struct {
		name, path, reason string
		hard               bool
	}{
		{"a path the relay could not read", "", "file_unreadable", true},
		{"a denied path", "COMTRADE/secret.dat", "file_denied", true},
		{"a path off the list", "/etc/passwd", "file_not_allowed", false},
	} {
		d := p.File(assoc("tool"), wire.SvcFileOpen, c.path)
		if d.Allow || d.Reason != c.reason || d.Hard != c.hard {
			t.Errorf("%s decided %+v, want %s hard=%v", c.name, d, c.reason, c.hard)
		}
	}
	for _, path := range []string{"COMTRADE/2026-03-04.cfg", "CID/relay1.cid"} {
		if d := p.File(assoc("tool"), wire.SvcFileRead, path); !d.Allow {
			t.Errorf("%s was refused: %+v", path, d)
		}
	}
	// On a deny-by-default listener a path no rule covers is refused as that
	// rather than as a path off a list nobody wrote.
	strict := policyOf(t, &config.MMSListener{Upstream: "ieds"})
	if d := strict.File(assoc("tool"), wire.SvcFileRead, "CID/relay1.cid"); d.Allow ||
		d.Reason != "no_rule" {
		t.Errorf("a file on a deny-by-default listener decided %+v", d)
	}
}

// The services that name a logical device rather than an object: a download, a
// delete, an enumeration.
func TestTheDomainListsDecideADeviceWideService(t *testing.T) {
	p := policyOf(t, &config.MMSListener{Upstream: "ieds", DefaultAction: "allow",
		Domains: []string{"AA1J1Q01A1LD0"}, DenyDomains: []string{"AA1J1Q01A1LD9"}})

	for _, c := range []struct {
		name, domain, reason string
		hard                 bool
	}{
		{"a denied domain", "AA1J1Q01A1LD9", "domain_denied", true},
		{"a domain off the list", "AA1J1Q02A1LD0", "domain_not_allowed", false},
	} {
		d := p.Domain(assoc("tool"), wire.SvcGetDomainAttributes, c.domain)
		if d.Allow || d.Reason != c.reason || d.Hard != c.hard {
			t.Errorf("%s decided %+v, want %s hard=%v", c.name, d, c.reason, c.hard)
		}
	}
	if d := p.Domain(assoc("tool"), wire.SvcGetDomainAttributes, "AA1J1Q01A1LD0"); !d.Allow {
		t.Errorf("a domain on the list was refused: %+v", d)
	}
	// A service naming no domain at all is not a domain decision.
	if d := p.Domain(assoc("tool"), wire.SvcGetNameList, ""); !d.Allow {
		t.Errorf("a service naming no domain was refused: %+v", d)
	}
	strict := policyOf(t, &config.MMSListener{Upstream: "ieds"})
	if d := strict.Domain(assoc("tool"), wire.SvcGetDomainAttributes, "LD0"); d.Allow ||
		d.Reason != "no_rule" {
		t.Errorf("a domain service on a deny-by-default listener decided %+v", d)
	}
}

// A rule selects on who is asking and what they are asking about, and a rule
// that names objects is not the rule that decides a request touching none of
// them.
func TestARuleSelectsOnTheRequestItWasWrittenFor(t *testing.T) {
	p := policyOf(t, &config.MMSListener{Upstream: "ieds",
		Rules: []config.MMSRule{
			{Name: "no-test-laptop", Action: "deny", Clients: []string{"10.0.9.9/32"}},
			{Name: "metering", Comment: "the revenue meters", APTitles: []string{"mdm"},
				Objects: []string{"*/MMXU1$MX$*"}},
			{Name: "night-work", APTitles: []string{"tool"},
				Schedule: &config.ModbusSchedule{From: "22:00", To: "06:00"}},
		}})

	laptop := assoc("mdm")
	laptop.IP = ip("10.0.9.9")
	d := p.Operations(laptop, wire.SvcRead, []Operation{obj("LD0/MMXU1$MX$TotW$mag", false)})
	if d.Allow || d.Reason != "rule_denied" || d.Detail != "no-test-laptop" {
		t.Fatalf("the deny rule did not win: %+v", d)
	}
	// The rule that names the objects decides them, and carries its own note
	// into the record a substation keeps.
	d = p.Operations(assoc("mdm"), wire.SvcRead, []Operation{obj("LD0/MMXU1$MX$TotW$mag", false)})
	if !d.Allow || d.Rule != "metering" || d.Comment != "the revenue meters" {
		t.Fatalf("the metering rule decided %+v", d)
	}
	// And it does not decide a request about something else, which on a
	// deny-by-default listener means that request is refused.
	d = p.Operations(assoc("mdm"), wire.SvcRead, []Operation{obj("LD0/XCBR1$ST$Pos$stVal", false)})
	if d.Allow || d.Reason != "no_rule" {
		t.Fatalf("a request outside the rule's objects decided %+v", d)
	}
	// A rule with a window selects only inside it. The schedule is read against
	// the wall clock rather than a clock a test can set, so the window is
	// written relative to today in UTC: a rule naming today covers this
	// request and a rule naming another day does not.
	today, other := utcDays()
	ops := []Operation{obj("LD0/XCBR1$ST$Pos$stVal", false)}
	in := policyOf(t, &config.MMSListener{Upstream: "ieds",
		Rules: []config.MMSRule{{Name: "window", Objects: []string{"*/*"},
			Schedule: &config.ModbusSchedule{Days: []string{today}, From: "00:00", To: "23:59"}}}})
	if d := in.Operations(assoc("tool"), wire.SvcRead, ops); !d.Allow || d.Rule != "window" {
		t.Fatalf("a rule whose window covers now decided %+v", d)
	}
	out := policyOf(t, &config.MMSListener{Upstream: "ieds",
		Rules: []config.MMSRule{{Name: "window", Objects: []string{"*/*"},
			Schedule: &config.ModbusSchedule{Days: []string{other}, From: "00:00", To: "23:59"}}}})
	if d := out.Operations(assoc("tool"), wire.SvcRead, ops); d.Allow || d.Reason != "no_rule" {
		t.Fatalf("a rule whose window names another day decided %+v", d)
	}
	// Describe, which is what a refusal names when a request had many objects.
	if got := describe(nil); got != "" {
		t.Errorf("describe(nil) = %q", got)
	}
	if got := describe([]Operation{obj("LD0/XCBR1$ST$Pos$stVal", false)}); got != "LD0/XCBR1$ST$Pos$stVal" {
		t.Errorf("describe of one object = %q", got)
	}
	got := describe([]Operation{obj("LD0/A$ST$a$b", false), obj("LD0/B$ST$a$b", false),
		obj("LD0/C$ST$a$b", false)})
	if got != "LD0/A$ST$a$b and 2 more" {
		t.Errorf("describe of three objects = %q", got)
	}
}

// utcDays names today in UTC and a day that is not today, for a schedule a test
// has to write against the wall clock.
func utcDays() (today, other string) {
	names := []string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}
	i := int(time.Now().UTC().Weekday())
	return names[i], names[(i+3)%7]
}

// An observe rule is reported and decides nothing, which is what lets a rule be
// tried on live traffic before it decides anything.
func TestAnObserveRuleIsReportedAndDecidesNothing(t *testing.T) {
	p := policyOf(t, &config.MMSListener{Upstream: "ieds", DefaultAction: "allow",
		Rules: []config.MMSRule{
			{Name: "watch-writes", Action: "observe", ServiceClasses: []string{"write"}},
			{Name: "no-breaker", Action: "deny", Objects: []string{"*/XCBR1$*"}},
		}})
	ops := []Operation{obj("LD0/XCBR1$ST$Pos$stVal", true)}
	d := p.Operations(assoc("hmi"), wire.SvcWrite, ops)
	if d.Allow || d.Reason != "rule_denied" || d.Detail != "no-breaker" {
		t.Fatalf("the observe rule shadowed the deny rule below it: %+v", d)
	}
	seen := p.ObserveRules(assoc("hmi"), wire.SvcWrite, ops)
	if len(seen) != 1 || seen[0].Name() != "watch-writes" || seen[0].Comment() != "" {
		t.Fatalf("the observe rules reported are %v", seen)
	}
	// And a request it does not select reports nothing.
	if seen := p.ObserveRules(assoc("hmi"), wire.SvcRead, ops); len(seen) != 0 {
		t.Fatalf("a read reported the write rule: %v", seen)
	}
}

// The glob matching every list here uses, over the form an IEC 61850 name is
// written in.
func TestThePatternsAreGlobsOverTheWholeName(t *testing.T) {
	pats := []string{"AA1J1Q01A1LD0/MMXU1$MX$*", "exact/name", "LD?/XCBR1$ST$Pos$stVal",
		"LD0/[AB]SWI1$ST$*"}
	for _, s := range []string{"AA1J1Q01A1LD0/MMXU1$MX$TotW$mag", "exact/name",
		"LD1/XCBR1$ST$Pos$stVal", "LD0/ASWI1$ST$Pos$stVal"} {
		if !matchedGlob(pats, s) {
			t.Errorf("%q matched none of the patterns", s)
		}
	}
	for _, s := range []string{"AA1J1Q01A1LD0/MMXU1$ST$TotW$mag", "exact/other",
		"LD10/XCBR1$ST$Pos$stVal", "LD0/CSWI1$ST$Pos$stVal"} {
		if matchedGlob(pats, s) {
			t.Errorf("%q matched a pattern it should not", s)
		}
	}
	// A pattern that will not compile matches nothing rather than everything.
	if matchedGlob([]string{"LD0/[unclosed"}, "LD0/[unclosed") {
		// It is equal to itself, which the first comparison catches, so the
		// interesting case is a different string.
		t.Log("an uncompilable pattern still matches itself exactly, which is the literal arm")
	}
	if matchedGlob([]string{"LD0/[unclosed"}, "LD0/x") {
		t.Error("an uncompilable pattern matched something else")
	}
	if matchedGlob(nil, "anything") {
		t.Error("an empty pattern list matched")
	}
	// The matching is path.Match, so a `*` does not cross a `/`: the pattern
	// that covers every domain-qualified object is `*/*`, and a bare `*` covers
	// only the names that have no domain in them. Worth knowing, because a rule
	// written `objects: ["*"]` to mean everything would select nothing.
	if matchedGlob([]string{"*"}, "LD0/XCBR1$ST$Pos$stVal") {
		t.Error("a bare * matched a domain-qualified name")
	}
	if !matchedGlob([]string{"*/*"}, "LD0/XCBR1$ST$Pos$stVal") {
		t.Error("*/* did not match a domain-qualified name")
	}
	if !matchedGlob([]string{"*"}, "VendorCounter") {
		t.Error("a bare * did not match a name with no domain")
	}
}

// The configuration names a class and a service by the spelling the reference
// uses, and a name that is not one is left out rather than guessed at.
func TestTheConfigurationNamesCompileToWhatTheyName(t *testing.T) {
	p := policyOf(t, &config.MMSListener{Upstream: "ieds", DefaultAction: "allow",
		Services:              []string{"read", "write", "not_a_service"},
		ServiceClasses:        []string{"read", "browse", "not_a_class"},
		FunctionalConstraints: []string{"ST", "MX"}})
	if len(p.services) != 2 || !p.services[wire.SvcRead] || !p.services[wire.SvcWrite] {
		t.Errorf("the service list compiled to %v", p.services)
	}
	if len(p.classes) != 2 || !p.classes[wire.ClassRead] || !p.classes[wire.ClassBrowse] {
		t.Errorf("the class list compiled to %v", p.classes)
	}
	if len(p.constraints) != 2 || !p.constraints[wire.FCStatus] {
		t.Errorf("the constraint list compiled to %v", p.constraints)
	}
	// classOf reads back every class the configuration may name, and nothing
	// else.
	for _, name := range []string{"browse", "read", "write", "report", "dataset",
		"control", "domain", "file", "session"} {
		if _, ok := classOf(name); !ok {
			t.Errorf("%q is not a class the configuration may name", name)
		}
	}
	if c, ok := classOf("unknown"); ok || c != wire.ClassUnknown {
		t.Errorf("classOf(\"unknown\") = %v, %v", c, ok)
	}
	// An AE-qualifier range that is not one is a load error rather than a
	// qualifier nobody matches.
	if _, err := compile(&config.MMSListener{Upstream: "ieds",
		AEQualifiers: []string{"twelve"}}); err == nil {
		t.Error("an unreadable AE-qualifier range compiled")
	}
	if _, err := compile(&config.MMSListener{Upstream: "ieds",
		Rules: []config.MMSRule{{Name: "r", AEQualifiers: []string{"1-"}}}}); err == nil {
		t.Error("an unreadable range inside a rule compiled")
	}
	if _, err := compile(&config.MMSListener{Upstream: "ieds",
		Rules: []config.MMSRule{{Name: "r",
			Schedule: &config.ModbusSchedule{Days: []string{"caturday"}}}}}); err == nil {
		t.Error("an unreadable schedule inside a rule compiled")
	}
}
