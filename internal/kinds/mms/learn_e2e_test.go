package mms

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/mms"
	"github.com/rom/xproxy/internal/proxy"
)

// Learning mode end to end: real traffic through the real engine, and the report that
// comes out of it.
//
// The assertions are about what the report *says*, because the report is the product.
// A learning mode that recorded perfectly and rendered a file nobody can adopt has
// done nothing, so every test here reads the YAML.

// learnRelay starts a listener learning into a file under the test's own directory.
func learnRelay(t *testing.T, section string, ied *fakeIED) (*proxy.Server, string, string) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "mms-learn.yaml")
	s, addr := relayFor(t, section+
		"        learn:\n"+
		"          enabled: true\n"+
		"          file: "+file+"\n"+
		"          interval: 10s\n", ied.addr())
	return s, addr, file
}

// report shuts the listener down, which is what writes the file, and hands back what
// it says. The client is closed first: shutdown waits for the associations it is
// relaying, and a test that left one open would wait out the whole bound.
func report(t *testing.T, s *proxy.Server, cl *client, file string) string {
	t.Helper()
	_ = cl.c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("the learning report was not written: %v", err)
	}
	return string(b)
}

// A run over ordinary traffic: the report names the identity, the logical device and a
// rule that permits what was seen.
func TestALearningRunProposesWhatWasSeen(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr, file := learnRelay(t, base, ied)
	cl := session(t, addr)

	cl.service(readBody(1,
		objectName("AA1J1Q01A1LD0", "MMXU1$MX$TotW$mag$f"),
		objectName("AA1J1Q01A1LD0", "XCBR1$ST$Pos$stVal")))
	ied.await(t, 1, "the read")

	out := report(t, s, cl, file)
	for _, want := range []string{
		"identity: 1.1.999.1",
		"services: read",
		"domain: AA1J1Q01A1LD0",
		`objects_seen: ["AA1J1Q01A1LD0/MMXU1$MX$TotW$mag$f", "AA1J1Q01A1LD0/XCBR1$ST$Pos$stVal"]`,
		"constraints: [MX, ST]",
		"authentication_seen: [none]  # observation only",
		"names_per_request: 2  # bound, not policy",
		// And the proposal is a rule somebody can paste in.
		"rules:\n",
		"- name: client-1",
		"action: allow",
		`ap_titles: ["1.1.999.1"]`,
		"services: [read]",
		`domains: ["AA1J1Q01A1LD0"]`,
		// Nothing operated the plant, so the rule says so rather than inheriting
		// whatever the listener allows.
		"allow_operate: false",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report is missing %q", want)
		}
	}
	// And the proposal names none of the things a learning run must not widen. Only
	// the rules section is searched: the preamble names them precisely to say it
	// will not propose them.
	_, rules, ok := strings.Cut(out, "\nrules:\n")
	if !ok {
		t.Fatalf("the report proposes nothing:\n%s", out)
	}
	for _, never := range []string{
		"max_names", "max_frame", "rate_limit", "refuse_plaintext_passwords",
		"max_pending_requests", "handshake_timeout",
	} {
		if strings.Contains(rules, never) {
			t.Errorf("the proposal names %q, which a learning run must never widen:\n%s",
				never, rules)
		}
	}
}

// The finding a reader of an MMS report has to see first.
func TestTheReportLeadsWithThePasswordFinding(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr, file := learnRelay(t, base, ied)
	cl := dial(t, addr)
	cl.connect()
	const secret = "zqx-7f3-kkw"
	cl.associate([]uint64{1, 1, 999, 1}, 12, secret)
	cl.initiate()
	awaitInitiate(t, ied)

	out := report(t, s, cl, file)
	for _, want := range []string{
		"carried a CLEARTEXT PASSWORD",
		"IEC 62351-4 replaces it",
		"turn on until the clients",
		"cleartext_passwords: 1",
		"authentication_seen: [password]",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report is missing %q:\n%s", want, out)
		}
	}
	// And nowhere in the file is the password itself. This is the invariant the
	// whole layer is written around, and a learning report is a file that gets
	// pasted into a ticket. Even a fragment of it would be too much, so the
	// assertion is on three characters.
	if strings.Contains(out, secret) || strings.Contains(out, secret[:3]) {
		t.Error("the password survived into the learning report")
	}
}

// And the other side of it: a run that saw no password says so, because "none of them
// did" is the finding an estate that has moved to IEC 62351-4 wants.
func TestTheReportSaysWhenNoPasswordCrossed(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr, file := learnRelay(t, base, ied)
	cl := session(t, addr)
	cl.service(readBody(1, objectName("LD0", "A1$ST$V$stVal")))
	ied.await(t, 1, "the read")

	out := report(t, s, cl, file)
	if !strings.Contains(out, "none of the 1 associations recorded carried a cleartext") {
		t.Errorf("the report does not say no password crossed:\n%s", out)
	}
	if strings.Contains(out, "CLEARTEXT PASSWORD") {
		t.Error("the report reported a password that did not cross")
	}
}

// The control finding: what operated the plant, and whether any of it selected first.
func TestTheReportSaysWhatOperatedThePlant(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr, file := learnRelay(t, base+
		"        write_constraints: [CO]\n", ied)
	cl := session(t, addr)

	cl.service(writeBody(1, objectName("AA1J1Q01A1LD0", "XCBR1$CO$Pos$SBOw")))
	cl.service(writeBody(2, objectName("AA1J1Q01A1LD0", "XCBR1$CO$Pos$Oper")))
	ied.await(t, 2, "the select and the operate")

	out := report(t, s, cl, file)
	for _, want := range []string{
		"1 requests operated the plant",
		"a breaker",
		"selects were recorded, so select-before-operate is in use",
		"operates: 1  # a breaker or a disconnector moved",
		"selects: 1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report is missing %q:\n%s", want, out)
		}
	}
}

// And the finding that says this estate operates directly, which is what decides
// whether require_select_before_operate is a bound the traffic already meets.
func TestTheReportSaysWhenAnOperateHadNoSelect(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr, file := learnRelay(t, base+
		"        write_constraints: [CO]\n", ied)
	cl := session(t, addr)
	cl.service(writeBody(1, objectName("AA1J1Q01A1LD0", "XCBR1$CO$Pos$Oper")))
	ied.await(t, 1, "the operate")

	out := report(t, s, cl, file)
	if !strings.Contains(out, "this estate operates\n#   directly") {
		t.Errorf("the report does not say the estate operates directly:\n%s", out)
	}
	if !strings.Contains(out, "would refuse every one of") {
		t.Error("the report does not say what requiring the select would cost")
	}
}

// The protection finding, which is the one a reader is most likely to be surprised by.
func TestTheReportSaysWhatTouchedAProtectionSetting(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr, file := learnRelay(t, base+
		"        write_constraints: [SG, SE]\n", ied)
	cl := session(t, addr)
	cl.service(writeBody(1, objectName("AA1J1Q01A1LD0", "PTOC1$SG$StrVal$setMag$f")))
	ied.await(t, 1, "the setting write")

	out := report(t, s, cl, file)
	for _, want := range []string{
		"1 requests wrote a setting group",
		"nothing moves until the fault they were meant to clear",
		"protection_writes: 1",
		"write_constraints: [SG]",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report is missing %q:\n%s", want, out)
		}
	}
}

// An identity the IED refused everything for gets no rule: a rule for it would permit
// a thing that cannot happen.
func TestAnIdentityTheIEDAlwaysRefusedGetsNoRule(t *testing.T) {
	ied := startIED(t, &fakeIED{errorEvery: ErrClassAccess})
	s, addr, file := learnRelay(t, base, ied)
	cl := session(t, addr)
	cl.service(readBody(1, objectName("AA1J1Q01A1LD0", "MMXU1$MX$TotW$mag$f")))
	until(t, s, func(s *proxy.Server) bool {
		return s.Stats().MMSServerErrors > 0
	}, "the IED's refusal")

	out := report(t, s, cl, file)
	if !strings.Contains(out, "the IED itself said no") {
		t.Errorf("the report does not say the IED refused it:\n%s", out)
	}
	if !strings.Contains(out, "every request was refused by the IED, so no rule is") {
		t.Errorf("a rule was proposed for an identity the IED always refused:\n%s", out)
	}
}

// A client that only associated gets no rule. Writing one would be writing an allow
// rule with nothing narrowed, since an omitted services key means the listener's own
// list.
func TestAnIdentityThatOnlyAssociatedGetsNoRule(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr, file := learnRelay(t, base, ied)
	cl := dial(t, addr)
	cl.connect()
	cl.associate([]uint64{1, 1, 999, 9}, 12, "")
	cl.initiate()
	awaitInitiate(t, ied)

	out := report(t, s, cl, file)
	if !strings.Contains(out, "identity: 1.1.999.9") {
		t.Errorf("the association was not recorded:\n%s", out)
	}
	if !strings.Contains(out, "nothing but the association was seen") {
		t.Errorf("the report does not say why there is no rule:\n%s", out)
	}
	if strings.Contains(out, "- name:") {
		t.Errorf("a rule was proposed for a client that only associated:\n%s", out)
	}
}

// A learning run is observe-only unless it says otherwise, which is what stops one
// being left on by accident.
func TestALearningRunDoesNotEnforceUnlessAsked(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr, _ := learnRelay(t, base+
		"        functional_constraints: [ST]\n", ied)
	cl := session(t, addr)

	// A constraint the policy does not name: recorded as a would-be refusal and
	// forwarded, because the run is measuring rather than deciding.
	cl.service(readBody(1, objectName("AA1J1Q01A1LD0", "MMXU1$MX$TotW$mag$f")))
	until(t, s, wouldRefuse("constraint_not_allowed"), "the would-be refusal")
	ied.await(t, 1, "the forwarded read")
	if got := s.Stats().Refusals["mms"]["constraint_not_allowed"]; got != 0 {
		t.Errorf("a learning run counted %d real refusals", got)
	}
}

// And enforces where the configuration says so, because a run on a live substation may
// need the policy in force while it measures.
func TestALearningRunEnforcesWhenAsked(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	file := filepath.Join(t.TempDir(), "mms-learn.yaml")
	s, addr := relayFor(t, base+
		"        functional_constraints: [ST]\n"+
		"        learn:\n"+
		"          enabled: true\n"+
		"          enforce: true\n"+
		"          file: "+file+"\n", ied.addr())
	cl := session(t, addr)

	answer := cl.service(readBody(1, objectName("AA1J1Q01A1LD0", "MMXU1$MX$TotW$mag$f")))
	if !isError(t, answer) {
		t.Error("an enforcing learning run did not refuse the read")
	}
	until(t, s, refused("constraint_not_allowed"), "the refusal")
	if ied.sawService(wire.SvcRead) {
		t.Errorf("an enforcing run forwarded the read: %v", ied.seen())
	}
	// And the refusal is in the report, because a run wants to know the policy and
	// the traffic disagree.
	out := report(t, s, cl, file)
	if !strings.Contains(out, "denied_by_policy: 1") {
		t.Errorf("the report does not record the refusal:\n%s", out)
	}
}

// A domain whose objects were more than the bound holds proposes the functional
// constraint rather than the first thirty-two of an unknown number, which would read
// as a complete list and be adopted as one.
func TestATruncatedObjectListProposesTheConstraint(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr, file := learnRelay(t, base, ied)
	cl := session(t, addr)

	names := make([][]byte, 0, maxLearnedObjects+4)
	for i := range maxLearnedObjects + 4 {
		names = append(names, objectName("AA1J1Q01A1LD0",
			"MMXU"+string(rune('A'+i%26))+string(rune('a'+i/26))+"$MX$TotW$mag$f"))
	}
	cl.service(readBody(1, names...))
	ied.await(t, 1, "the wide read")

	out := report(t, s, cl, file)
	if !strings.Contains(out, `objects: ["AA1J1Q01A1LD0/*$MX$*"]`) {
		t.Errorf("the proposal does not fall back to the constraint:\n%s", out)
	}
	if !strings.Contains(out, "more objects were seen than were recorded") {
		t.Error("the report does not say the list was truncated")
	}
}

// Two runs over the same traffic have to produce the same file, or a diff between two
// weeks means nothing: the rows and the rules are ordered by identity.
func TestTheReportIsOrderedByIdentityAndNotByArrival(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr, file := learnRelay(t, base, ied)

	// Deliberately the later identity first.
	for _, arc := range []uint64{9, 2} {
		c := dial(t, addr)
		c.connect()
		c.associate([]uint64{1, 1, 999, arc}, 12, "")
		c.initiate()
		c.service(readBody(1, objectName("AA1J1Q01A1LD0", "MMXU1$MX$TotW$mag$f")))
		_ = c.c.Close()
	}
	ied.await(t, 2, "both clients")

	cl := dial(t, addr)
	out := report(t, s, cl, file)
	_, rules, ok := strings.Cut(out, "\nrules:\n")
	if !ok {
		t.Fatalf("the report proposes nothing:\n%s", out)
	}
	two, nine := strings.Index(rules, "1.1.999.2"), strings.Index(rules, "1.1.999.9")
	if two < 0 || nine < 0 {
		t.Fatalf("both identities should have a rule:\n%s", rules)
	}
	if two > nine {
		t.Errorf("the rules are in arrival order rather than by identity:\n%s", rules)
	}
}

// A file service's path is recorded, and the proposal names it: an engineering station
// that fetched disturbance records should end up with a rule about COMTRADE and not
// about the whole filesystem.
func TestAFilePathIsRecordedAndProposed(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr, file := learnRelay(t, base, ied)
	cl := session(t, addr)
	cl.service(fileBody(1, wire.SvcFileOpen, "COMTRADE", "rec001.cfg"))
	ied.await(t, 1, "the file open")

	out := report(t, s, cl, file)
	for _, want := range []string{
		`files_seen: ["COMTRADE/rec001.cfg"]`,
		`files: ["COMTRADE/rec001.cfg"]`,
		"services: [file_open]",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report is missing %q:\n%s", want, out)
		}
	}
}

// An identity that sent no AP-title is labelled rather than left blank, and the rule
// proposed for it says it will match every client that sends none -- because a rule
// naming no AP-title is not a rule about one client.
func TestAnIdentityWithNoAPTitleIsLabelled(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr, file := learnRelay(t, base, ied)
	cl := dial(t, addr)
	cl.connect()
	cl.associate(nil, 12, "")
	cl.initiate()
	cl.service(readBody(1, objectName("AA1J1Q01A1LD0", "MMXU1$MX$TotW$mag$f")))
	ied.await(t, 1, "the read")

	out := report(t, s, cl, file)
	if !strings.Contains(out, "identity: <no ap-title>") {
		t.Errorf("the missing AP-title was not labelled:\n%s", out)
	}
	if !strings.Contains(out, "- name: unnamed-client") {
		t.Errorf("no rule was proposed for the unnamed client:\n%s", out)
	}
	if !strings.Contains(out, "it will\n    # match every association that sends none") {
		t.Errorf("the report does not say what that rule matches:\n%s", out)
	}
	// And it names no ap_titles, because there is none to name.
	if strings.Contains(out, `ap_titles: ["<no ap-title>"]`) {
		t.Error("the proposal named the placeholder as an AP-title")
	}
}
