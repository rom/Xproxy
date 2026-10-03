package mms

import (
	"bytes"
	"strings"
	"testing"
)

// The names and the classifications, which are what a reader of a log line or
// an author of a rule sees.
//
// They are worth asserting rather than assuming. Every one of these strings is
// either a counter name, a word in a security event, or the spelling a
// configuration uses -- so a change to one is a change to somebody's
// dashboard or somebody's rule, and the unnamed form (`cotp(0x7f)`,
// `spdu(99)`) is what an investigation has to fall back on when an unexpected
// value arrives. The classifications below are stronger than naming: what a
// functional constraint does to the plant is the judgement the whole policy
// rests on.

func TestTheTransportAndSessionNamesCoverWhatArrives(t *testing.T) {
	for _, c := range []struct {
		t    uint8
		want string
	}{
		{CR, "connection_request"},
		{CC, "connection_confirm"},
		{DR, "disconnect_request"},
		{DC, "disconnect_confirm"},
		{DT, "data"},
		{ED, "expedited_data"},
		{AK, "data_ack"},
		{EA, "expedited_ack"},
		{RJ, "reject"},
		{ER, "error"},
		{0x7f, "cotp(0x7f)"},
	} {
		if got := TypeName(c.t); got != c.want {
			t.Errorf("TypeName(%#x) = %q, want %q", c.t, got, c.want)
		}
	}
	for _, c := range []struct {
		si   uint8
		want string
	}{
		// GiveTokens and DataTransfer share an identifier, which is why the
		// reader traverses the pair rather than choosing between them.
		{SPDUDataTransfer, "data_transfer"},
		{SPDUConnect, "connect"},
		{SPDUAccept, "accept"},
		{SPDURefuse, "refuse"},
		{SPDUFinish, "finish"},
		{SPDUDisconnect, "disconnect"},
		{SPDUAbort, "abort"},
		{SPDUNotFinished, "not_finished"},
		{99, "spdu(99)"},
	} {
		if got := SPDUName(c.si); got != c.want {
			t.Errorf("SPDUName(%d) = %q, want %q", c.si, got, c.want)
		}
	}
	for _, c := range []struct {
		tag  uint32
		want string
	}{
		{AARQ, "associate_request"},
		{AARE, "associate_response"},
		{RLRQ, "release_request"},
		{RLRE, "release_response"},
		{ABRT, "abort"},
		{9, "acse(9)"},
	} {
		if got := APDUName(c.tag); got != c.want {
			t.Errorf("APDUName(%d) = %q, want %q", c.tag, got, c.want)
		}
	}
}

// Every PDU this relay carries has a name, because one it could not name it
// would be forwarding blind.
func TestEveryPDUAndClassHasAName(t *testing.T) {
	for _, c := range []struct {
		p    PDU
		want string
	}{
		{ConfirmedRequest, "confirmed_request"},
		{ConfirmedResponse, "confirmed_response"},
		{ConfirmedError, "confirmed_error"},
		{Unconfirmed, "unconfirmed"},
		{Reject, "reject"},
		{CancelRequest, "cancel_request"},
		{CancelResponse, "cancel_response"},
		{CancelError, "cancel_error"},
		{InitiateRequest, "initiate_request"},
		{InitiateResponse, "initiate_response"},
		{InitiateError, "initiate_error"},
		{ConcludeRequest, "conclude_request"},
		{ConcludeResponse, "conclude_response"},
		{ConcludeError, "conclude_error"},
		{99, "pdu(99)"},
	} {
		if got := c.p.String(); got != c.want {
			t.Errorf("PDU(%d) is named %q, want %q", byte(c.p), got, c.want)
		}
	}
	for _, c := range []struct {
		class Class
		want  string
	}{
		{ClassBrowse, "browse"},
		{ClassRead, "read"},
		{ClassWrite, "write"},
		{ClassReport, "report"},
		{ClassDataSet, "dataset"},
		{ClassControl, "control"},
		{ClassDomain, "domain"},
		{ClassFile, "file"},
		{ClassSession, "session"},
		{ClassUnknown, "unknown"},
		{99, "unknown"},
	} {
		if got := c.class.String(); got != c.want {
			t.Errorf("Class(%d) is named %q, want %q", uint8(c.class), got, c.want)
		}
	}
	// The classification itself, on the services a policy is most often
	// written about.
	for _, c := range []struct {
		svc     Service
		class   Class
		changes bool
	}{
		{SvcRead, ClassRead, false},
		{SvcWrite, ClassWrite, true},
		{SvcGetNameList, ClassBrowse, false},
		{SvcFileDirectory, ClassFile, false},
		{SvcFileRead, ClassFile, false},
		{SvcFileDelete, ClassFile, true},
		{SvcDefineNamedVariableList, ClassDataSet, true},
		{SvcDeleteDomain, ClassDomain, true},
		{SvcStoreDomainContent, ClassDomain, true},
		{SvcStart, ClassControl, true},
		{SvcKill, ClassControl, true},
		// Reading an alarm summary is a read: what is in the report
		// machinery's own class is changing it.
		{SvcGetAlarmSummary, ClassRead, false},
		{SvcAlterEventEnrollment, ClassReport, true},
		{SvcStatus, ClassSession, false},
	} {
		if got := c.svc.Class(); got != c.class {
			t.Errorf("%s is classified %s, want %s", c.svc, got, c.class)
		}
		if got := c.svc.Changes(); got != c.changes {
			t.Errorf("%s changes=%v, want %v", c.svc, got, c.changes)
		}
		if !c.svc.Known() {
			t.Errorf("%s is not a service this build names", c.svc)
		}
		if n, ok := ServiceOf(c.svc.String()); !ok || n != c.svc {
			t.Errorf("%s does not round-trip through its own name", c.svc)
		}
	}
	// A service tag nothing defines is named rather than guessed at, and a
	// name nothing defines is refused rather than taken as a tag.
	unknown := Service(200)
	if unknown.Known() || unknown.Class() != ClassUnknown || unknown.Changes() {
		t.Errorf("an unnamed service reports known=%v class=%s changes=%v",
			unknown.Known(), unknown.Class(), unknown.Changes())
	}
	if !strings.Contains(unknown.String(), "200") {
		t.Errorf("an unnamed service is rendered %q, which does not say which it was", unknown)
	}
	if _, ok := ServiceOf("teleport"); ok {
		t.Error("a service name nothing defines was read as a service")
	}
	if len(ServiceNames()) == 0 {
		t.Error("the validator has no service names to offer")
	}
}

// The authentication forms an association request may carry. Two of them
// appear nowhere in IEC 61850-8-1 and are named anyway, because what a relay
// can say about one is that it was there.
func TestTheAuthenticationFormsAreNamed(t *testing.T) {
	for _, c := range []struct {
		kind AuthKind
		want string
	}{
		{AuthNone, "none"},
		{AuthPassword, "password"},
		{AuthBitString, "bitstring"},
		{AuthExternal, "external"},
		{AuthOther, "other"},
		{99, "auth(99)"},
	} {
		if got := c.kind.String(); got != c.want {
			t.Errorf("AuthKind(%d) is named %q, want %q", uint8(c.kind), got, c.want)
		}
	}
}

// What a functional constraint does to the plant, which is the judgement the
// write policy rests on: an operate reaches the primary plant, a setting
// group changes what the device will do in a fault, and a report control
// block changes only what the control centre is told.
func TestTheFunctionalConstraintsSayWhatAWriteReaches(t *testing.T) {
	for _, c := range []struct {
		fc                           FC
		what                         string
		operates, protects, observes bool
	}{
		{FCControl, "control", true, false, false},
		// `OR` is "operate received", a status attribute that says one
		// happened, so a write to it does not reach the plant -- `CO` is the
		// constraint that does.
		{FCOperate, "operate received", false, false, false},
		{FCSettingGroup, "setting group", false, true, false},
		{FCSettingEdit, "setting group being edited", false, true, false},
		{FCConfig, "configuration", false, true, false},
		{FCStatus, "status", false, false, false},
		{FCMeasurand, "measurand", false, false, false},
		{FCBuffered, "buffered report control", false, false, true},
		{FCUnbuffered, "unbuffered report control", false, false, true},
		{FCLog, "log control", false, false, true},
		{FCGoose, "GOOSE control", false, false, true},
		{FCSampled, "sampled value control", false, false, true},
	} {
		if !c.fc.Known() {
			t.Errorf("%s is not a constraint IEC 61850-7-2 defines", c.fc)
			continue
		}
		if got := c.fc.What(); got != c.what {
			t.Errorf("%s is described %q, want %q", c.fc, got, c.what)
		}
		if got := c.fc.Operates(); got != c.operates {
			t.Errorf("%s operates=%v, want %v", c.fc, got, c.operates)
		}
		if got := c.fc.Protects(); got != c.protects {
			t.Errorf("%s protects=%v, want %v", c.fc, got, c.protects)
		}
		if got := c.fc.Observability(); got != c.observes {
			t.Errorf("%s observability=%v, want %v", c.fc, got, c.observes)
		}
	}
	// A constraint nothing defines reaches nothing, and is described by what
	// arrived rather than by a guess.
	odd := FC("ZZ")
	if odd.Known() || odd.Operates() || odd.Protects() || odd.Observability() {
		t.Errorf("an undefined constraint reports known=%v operates=%v protects=%v observes=%v",
			odd.Known(), odd.Operates(), odd.Protects(), odd.Observability())
	}
	if got := odd.What(); !strings.Contains(got, "ZZ") {
		t.Errorf("an undefined constraint is described %q, which does not say which it was", got)
	}
	if len(FCs()) == 0 {
		t.Error("the validator has no constraints to offer")
	}
}

// The name a rule matches and a log line carries, in the three scopes the
// protocol has.
func TestANamesKeyIsTheFormARuleIsWrittenIn(t *testing.T) {
	for _, c := range []struct {
		name Name
		kind string
		key  string
	}{
		{Name{Kind: NameDomain, Domain: "AA1J1Q01A1LD0", Item: "XCBR1$CO$Pos$Oper"},
			"domain", "AA1J1Q01A1LD0/XCBR1$CO$Pos$Oper"},
		{Name{Kind: NameAA, Item: "MyList"}, "association", "@MyList"},
		{Name{Kind: NameVMD, Item: "VendorThing"}, "vmd", "VendorThing"},
		{Name{Kind: NameKind(9), Item: "x"}, "unknown", "x"},
	} {
		if got := c.name.Kind.String(); got != c.kind {
			t.Errorf("the scope is named %q, want %q", got, c.kind)
		}
		if got := c.name.Key(); got != c.key {
			t.Errorf("Key() = %q, want %q", got, c.key)
		}
		if c.name.String() != c.name.Key() {
			t.Errorf("String() = %q and Key() = %q, and a log line should carry the key",
				c.name.String(), c.name.Key())
		}
	}
	// And the parse, which is what makes a key into something a policy can
	// decide about: an item in the 61850 form yields its segments, and one
	// that is not says so rather than being guessed at.
	n := ParseItem("XCBR1$CO$Pos$Oper")
	if !n.Parsed || n.LogicalNode != "XCBR1" || n.FC != FCControl ||
		n.DataObject != "Pos" || n.Attribute != "Oper" {
		t.Errorf("a control attribute parsed to %+v", n)
	}
	if !n.Operates() {
		t.Error("an Oper on a control constraint does not reach the plant, which it does")
	}
	flat := ParseItem("VendorCounter")
	if flat.Parsed || flat.Item != "VendorCounter" {
		t.Errorf("a name that is not in the 61850 form parsed to %+v", flat)
	}
}

// The two bits of reader bookkeeping a caller asks for: the bound in force,
// and the octets a level has left.
func TestTheReaderReportsItsBoundAndWhatIsLeft(t *testing.T) {
	for _, c := range []struct {
		asked, want int
	}{
		{0, DefaultMaxFrame},
		{-1, DefaultMaxFrame},
		{1, MinFrame},
		{8192, 8192},
	} {
		if got := NewReader(bytes.NewReader(nil), c.asked).Max(); got != c.want {
			t.Errorf("a reader asked for %d has bound %d, want %d", c.asked, got, c.want)
		}
	}
	// Rest is the remaining octets as they arrived, which is what a caller
	// that forwards what it did not interpret needs.
	r := NewBER([]byte{0x02, 0x01, 0x07, 0x01, 0x01, 0xff})
	if r.Empty() {
		t.Fatal("a reader over six octets says it is empty")
	}
	if _, err := r.Next(); err != nil {
		t.Fatal(err)
	}
	if got := r.Rest(); !bytes.Equal(got, []byte{0x01, 0x01, 0xff}) {
		t.Errorf("Rest() = %#v after one element", got)
	}
	e, err := r.Next()
	if err != nil {
		t.Fatal(err)
	}
	// BER says any non-zero octet is true, so a BOOLEAN of 0xff is one.
	v, err := Bool(e)
	if err != nil || !v {
		t.Errorf("Bool(0xff) = %v, %v", v, err)
	}
	if v, err := Bool(Element{Data: []byte{0x00}}); err != nil || v {
		t.Errorf("Bool(0x00) = %v, %v", v, err)
	}
	if !r.Empty() || len(r.Rest()) != 0 {
		t.Error("a reader that read everything does not say so")
	}
	// A BOOLEAN is one octet, and anything else is an encoding this relay
	// refuses rather than reads the first octet of.
	for _, data := range [][]byte{nil, {0x01, 0x00}} {
		if _, err := Bool(Element{Data: data}); err == nil {
			t.Errorf("a BOOLEAN in %d octets was read", len(data))
		}
	}
}
