package mms

import (
	"strings"
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/mms"
	"github.com/rom/xproxy/internal/proxy"
)

// Select before operate, which is the one check in this protocol a relay can make
// that the device may not.
//
// IEC 61850 leaves it to each object's `ctlModel`; `ctlModel` lives in `$CF$`; `$CF$`
// is writable. So a client with configuration access can set an object to
// direct-operate and then operate it, and the IED will do as it is told. A listener
// that tracks the selection itself has put the interlock somewhere the configuration
// cannot reach — and the *where* matters as much as the fact: the selection is
// recorded when the IED confirms it, not when the client asks for it.

const selectSection = "        upstream: ieds\n" +
	"        default_action: allow\n" +
	"        write_constraints: [CO]\n" +
	"        require_select_before_operate: true\n"

// An operate with no selection is refused, and the IED never sees it.
func TestAnOperateWithNoSelectionIsRefused(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr := relayFor(t, selectSection, ied.addr())
	cl := session(t, addr)

	answer := cl.service(writeBody(1, objectName("AA1J1Q01A1LD0", "XCBR1$CO$Pos$Oper")))
	if !isError(t, answer) {
		t.Error("the client was not told")
	}
	until(t, s, refused("not_selected"), "the refusal")
	if ied.sawService(wire.SvcWrite) {
		t.Errorf("the IED saw the unselected operate: %v", ied.seen())
	}
}

// A select then an operate on the same object is carried, because that is the
// sequence the standard defines.
func TestASelectThenAnOperateIsCarried(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	_, addr := relayFor(t, selectSection, ied.addr())
	cl := session(t, addr)

	cl.service(writeBody(1, objectName("AA1J1Q01A1LD0", "XCBR1$CO$Pos$SBOw")))
	ied.await(t, 1, "the select")
	cl.service(writeBody(2, objectName("AA1J1Q01A1LD0", "XCBR1$CO$Pos$Oper")))
	ied.await(t, 2, "the operate")
}

// The selection is recorded when the IED confirms it. A client that asked to select
// an object the IED refused holds none, so the operate that follows is refused --
// which is the difference between an interlock and a formality.
func TestASelectTheIEDRefusedGrantsNoSelection(t *testing.T) {
	ied := startIED(t, &fakeIED{errorEvery: ErrClassAccess})
	s, addr := relayFor(t, selectSection, ied.addr())
	cl := session(t, addr)

	// The select goes through this relay and the IED says no.
	cl.service(writeBody(1, objectName("AA1J1Q01A1LD0", "XCBR1$CO$Pos$SBOw")))
	until(t, s, func(s *proxy.Server) bool {
		return s.Stats().MMSServerErrors > 0
	}, "the IED's refusal of the select")

	// So the operate is refused here, before the IED is asked.
	answer := cl.service(writeBody(2, objectName("AA1J1Q01A1LD0", "XCBR1$CO$Pos$Oper")))
	if !isError(t, answer) {
		t.Error("the client was not told")
	}
	until(t, s, refused("not_selected"), "the refusal")
	if got := s.Stats().MMSSelections; got != 0 {
		t.Errorf("mms_selections is %d, want none: the IED refused the select", got)
	}
}

// A selection is for one object. Selecting one breaker does not licence operating the
// next one, which is the mistake a relay keyed on the association rather than the
// object would make.
func TestASelectionIsForOneObject(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr := relayFor(t, selectSection, ied.addr())
	cl := session(t, addr)

	cl.service(writeBody(1, objectName("AA1J1Q01A1LD0", "XCBR1$CO$Pos$SBOw")))
	ied.await(t, 1, "the select")

	answer := cl.service(writeBody(2, objectName("AA1J1Q01A1LD0", "XCBR2$CO$Pos$Oper")))
	if !isError(t, answer) {
		t.Error("operating the second breaker was carried on the first one's selection")
	}
	until(t, s, refused("not_selected"), "the refusal")
	if ied.sawService(wire.SvcWrite) && len(ied.seen()) > 1 {
		t.Errorf("the IED saw more than the select: %v", ied.seen())
	}
}

// And a selection expires. The standard's own sboTimeout is 30 seconds; a listener
// that never forgot one would licence an operate an hour after the operator walked
// away.
func TestASelectionExpires(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr := relayFor(t, selectSection+
		"        select_timeout: 1ms\n", ied.addr())
	cl := session(t, addr)

	cl.service(writeBody(1, objectName("AA1J1Q01A1LD0", "XCBR1$CO$Pos$SBOw")))
	ied.await(t, 1, "the select")
	// Past the timeout by construction: the selection was recorded with a
	// one-millisecond life.
	time.Sleep(20 * time.Millisecond)

	answer := cl.service(writeBody(2, objectName("AA1J1Q01A1LD0", "XCBR1$CO$Pos$Oper")))
	if !isError(t, answer) {
		t.Error("an expired selection carried the operate")
	}
	until(t, s, refused("selection_expired"), "the refusal")
}

// Without the knob the relay does not track selections at all, because an estate
// whose IEDs enforce ctlModel themselves does not need a second copy of the rule and
// a relay that guessed would refuse traffic the devices accept.
func TestWithoutTheKnobAnOperateNeedsNoSelection(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	_, addr := relayFor(t,
		"        upstream: ieds\n"+
			"        default_action: allow\n"+
			"        write_constraints: [CO]\n", ied.addr())
	cl := session(t, addr)

	cl.service(writeBody(1, objectName("AA1J1Q01A1LD0", "XCBR1$CO$Pos$Oper")))
	ied.await(t, 1, "the operate")
}

// The other survivors the mutation run found, each about a refusal that must stand
// whatever else is configured.

// A shadow listener records what it would have refused and forwards it -- except an
// association carrying a cleartext password, because forwarding that would be
// forwarding the credential.
func TestAShadowListenerStillRefusesACleartextPassword(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr := relayFor(t,
		"        upstream: ieds\n"+
			"        default_action: allow\n"+
			"        monitor_only: true\n"+
			"        refuse_plaintext_passwords: true\n", ied.addr())
	cl := dial(t, addr)
	cl.connect()
	if err := cl.associateQuiet([]uint64{1, 1, 999, 1}, 12, "substationsecret"); err == nil {
		t.Error("a monitor-only listener forwarded an association carrying a password")
	}
	until(t, s, refused("plaintext_password"), "the refusal")
	if len(ied.seen()) != 0 {
		t.Errorf("the IED saw %v", ied.seen())
	}
}

// A deny list is not something a rule can open. A listener that let one do so would
// have a deny list that means nothing, which is worse than not having one.
func TestNoRuleOpensADenyList(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr := relayFor(t,
		"        upstream: ieds\n"+
			"        default_action: allow\n"+
			"        deny_objects: [\"AA1J1Q01A1LD0/XCBR1$*\"]\n"+
			"        rules:\n"+
			"          - name: everything\n"+
			"            action: allow\n"+
			"            objects: [\"AA1J1Q01A1LD0/*\"]\n", ied.addr())
	cl := session(t, addr)

	answer := cl.service(readBody(1, objectName("AA1J1Q01A1LD0", "XCBR1$ST$Pos$stVal")))
	if !isError(t, answer) {
		t.Error("a rule opened a deny list")
	}
	until(t, s, refused("object_denied"), "the refusal")
	if ied.sawService(wire.SvcRead) {
		t.Errorf("the IED saw the denied read: %v", ied.seen())
	}
	// And the object outside the deny list is still carried, so the deny list is a
	// deny list rather than a broken allow list.
	cl.service(readBody(2, objectName("AA1J1Q01A1LD0", "MMXU1$MX$TotW$mag$f")))
	ied.await(t, 1, "the allowed read")
}

// A request naming more objects than the reader keeps is refused whole. Allowing it
// on the strength of the names that could be seen would be allowing the ones that
// could not.
func TestARequestPastTheReadersOwnBoundIsRefused(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr := relayFor(t,
		"        upstream: ieds\n"+
			"        default_action: allow\n"+
			"        objects: [\"LD0/*$ST$*\"]\n", ied.addr())
	cl := session(t, addr)

	names := make([][]byte, 0, wire.MaxNames+4)
	for range wire.MaxNames + 4 {
		names = append(names, objectName("LD0", "A1$ST$V$stVal"))
	}
	answer := cl.service(readBody(1, names...))
	if !isError(t, answer) {
		t.Error("the client was not told")
	}
	until(t, s, refused("too_many_names"), "the refusal")
	if ied.sawService(wire.SvcRead) {
		t.Errorf("the IED saw the oversized read: %v", ied.seen())
	}
}

// An observe rule matches, logs, and keeps looking. A listener that let one decide
// would have a rule that was supposed to be a dry run silently enforcing.
func TestAnObserveRuleDoesNotNarrowWhatIsCarried(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	_, addr := relayFor(t,
		"        upstream: ieds\n"+
			"        default_action: allow\n"+
			"        rules:\n"+
			"          - name: watch-one-bay\n"+
			"            action: observe\n"+
			"            objects: [\"AA1J1Q01A1LD0/*\"]\n", ied.addr())
	cl := session(t, addr)

	// An object the observe rule does not name. The rule does not even select this
	// request, so nothing about it depends on the observe handling.
	cl.service(readBody(1, objectName("AA1J1Q01A1LD1", "MMXU1$MX$TotW$mag$f")))
	ied.await(t, 1, "the read outside the observed set")
}

// And the case that actually distinguishes an observe rule from an allow one: a rule
// that *selects* the request and would narrow it. If observe decided, this write would
// be refused on the rule's constraint list; it is carried, because the rule watched
// and the listener's own lists decided.
func TestAnObserveRuleThatSelectsStillDecidesNothing(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr := relayFor(t,
		"        upstream: ieds\n"+
			"        default_action: allow\n"+
			"        write_constraints: [CO]\n"+
			"        rules:\n"+
			"          - name: watch-the-hmi\n"+
			"            action: observe\n"+
			"            ap_titles: [\"1.1.999.1\"]\n"+
			"            write_constraints: [ST]\n", ied.addr())
	cl := session(t, addr)

	cl.service(writeBody(1, objectName("AA1J1Q01A1LD0", "XCBR1$CO$Pos$Oper")))
	ied.await(t, 1, "the operate the observe rule only watched")
	if got := s.Stats().Refusals["mms"]["write_constraint_not_allowed"]; got != 0 {
		t.Errorf("an observe rule refused %d requests", got)
	}
}

// A response arriving from the client's direction is not something a client sends,
// and forwarding one would forward something the IED reads as a reply to a request it
// never made.
func TestAResponseFromTheClientIsRefused(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr := relayFor(t, base, ied.addr())
	cl := session(t, addr)

	if _, err := cl.serviceQuiet(
		ctx(uint32(wire.ConfirmedResponse), integer(1))); err == nil {
		t.Log("the relay answered rather than closing")
	}
	until(t, s, refused("unexpected_pdu"), "the refusal")
	if len(ied.seen()) != 0 {
		t.Errorf("the IED saw %v", ied.seen())
	}
}

// A write to a name with no functional constraint in it, on a listener whose write
// constraints are narrowed, is refused: the constraint rules say nothing about such a
// name, and treating it as though it carried the constraint the rule allows would be
// allowing something else.
func TestAWriteToANameWithNoConstraintIsRefusedWhereConstraintsAreNarrowed(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr := relayFor(t,
		"        upstream: ieds\n"+
			"        default_action: allow\n"+
			"        write_constraints: [ST]\n", ied.addr())
	cl := session(t, addr)

	// A vmd-specific name: no domain, no constraint.
	answer := cl.service(writeBody(1, ctxp(0, []byte("SomeDeviceVariable"))))
	if !isError(t, answer) {
		t.Error("the client was not told")
	}
	until(t, s, refused("constraint_unknown"), "the refusal")
	if ied.sawService(wire.SvcWrite) {
		t.Errorf("the IED saw the write: %v", ied.seen())
	}

	// And reading it is fine: the constraint rules are about writes here.
	cl2 := session(t, addr)
	cl2.service(readBody(2, ctxp(0, []byte("SomeDeviceVariable"))))
	ied.await(t, 1, "the read")
}

// A rule whose schedule is not in force does not select. The window is computed from
// the clock rather than hoped for, so the test says the same thing on every day of
// the week.
func TestARuleIsOnlyInForceInsideItsWindow(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	// A window on the day after tomorrow, which is never today.
	notToday := strings.ToLower(time.Now().UTC().AddDate(0, 0, 2).Format("Mon"))
	s, addr := relayFor(t,
		"        upstream: ieds\n"+
			"        default_action: deny\n"+
			"        rules:\n"+
			"          - name: window\n"+
			"            action: allow\n"+
			"            service_classes: [session, browse, read]\n"+
			"            schedule:\n"+
			"              days: ["+notToday+"]\n"+
			"              from: \"00:00\"\n"+
			"              to: \"23:59\"\n"+
			"              timezone: UTC\n", ied.addr())
	cl := session(t, addr)

	answer := cl.service(readBody(1, objectName("AA1J1Q01A1LD0", "MMXU1$MX$TotW$mag$f")))
	if !isError(t, answer) {
		t.Error("a rule outside its window carried the read")
	}
	until(t, s, refused("no_rule"), "the refusal")
	if ied.sawService(wire.SvcRead) {
		t.Errorf("the IED saw the read: %v", ied.seen())
	}
}
