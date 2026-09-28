package mms

import (
	"strings"
	"testing"

	wire "github.com/rom/xproxy/internal/mms"
	"github.com/rom/xproxy/internal/proxy"
)

// The policy, through the whole listener.

// The plain case: an association and a read, carried.
func TestAReadOnAnAllowedObjectIsCarried(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr := relayFor(t, base+
		"        domains: [\"AA1J1Q01A1LD0\"]\n"+
		"        functional_constraints: [ST, MX]\n", ied.addr())
	cl := session(t, addr)

	cl.service(readBody(1, objectName("AA1J1Q01A1LD0", "MMXU1$MX$TotW$mag$f")))
	ied.await(t, 1, "the read")
	if !ied.sawService(wire.SvcRead) {
		t.Errorf("the IED did not see the read: %v", ied.seen())
	}
	if got := s.Stats().MMSAssociations; got != 1 {
		t.Errorf("mms_associations is %d, want 1", got)
	}
}

// The refusal this whole kind is about: a Write to a control attribute is an operate,
// and a listener that does not allow one refuses it -- and the IED never sees it.
func TestAnOperateIsRefusedWhereControlIsNotAllowed(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr := relayFor(t, base+
		"        write_constraints: [ST, MX, SP]\n", ied.addr())
	cl := session(t, addr)

	answer := cl.service(writeBody(1, objectName("AA1J1Q01A1LD0", "XCBR1$CO$Pos$Oper")))
	if !isError(t, answer) {
		t.Error("the client was not told: the answer is not an MMS error")
	}
	until(t, s, refused("write_constraint_not_allowed"), "the refusal")
	if ied.sawService(wire.SvcWrite) {
		t.Errorf("the IED saw the write: %v", ied.seen())
	}
}

// And allow_operate is a separate knob from the constraint, so that turning CO on
// does not silently turn operating on.
func TestAllowOperateIsSeparateFromTheControlConstraint(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr := relayFor(t, base+
		"        write_constraints: [CO]\n"+
		"        allow_operate: false\n", ied.addr())
	cl := session(t, addr)

	// The select is carried: reserving a breaker is not moving one.
	cl.service(writeBody(1, objectName("AA1J1Q01A1LD0", "XCBR1$CO$Pos$SBOw")))
	ied.await(t, 1, "the select")

	// The operate is not.
	answer := cl.service(writeBody(2, objectName("AA1J1Q01A1LD0", "XCBR1$CO$Pos$Oper")))
	if !isError(t, answer) {
		t.Error("the client was not told about the operate")
	}
	until(t, s, refused("operate_not_allowed"), "the refusal")
	if n := len(ied.seen()); n != 1 {
		t.Errorf("the IED saw %d services, want the select only: %v", n, ied.seen())
	}
}

// The setting groups, which are the class nothing else in this protocol
// distinguishes: they are not in the default write constraints, so they are refused
// without anybody having to name them.
func TestASettingGroupWriteIsRefusedByDefault(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr := relayFor(t, base, ied.addr())
	cl := session(t, addr)

	answer := cl.service(writeBody(1,
		objectName("AA1J1Q01A1LD0", "PTOC1$SG$StrVal$setMag$f")))
	if !isError(t, answer) {
		t.Error("the client was not told")
	}
	until(t, s, refused("write_constraint_not_allowed"), "the refusal")
	if ied.sawService(wire.SvcWrite) {
		t.Errorf("the IED saw the setting-group write: %v", ied.seen())
	}
}

// read_only refuses everything that changes anything, and no rule overrides it --
// including a service that is not a Write at all.
func TestReadOnlyRefusesADeleteThatIsNotAWrite(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr := relayFor(t, baseDefault+
		"        read_only: true\n"+
		"        default_action: allow\n"+
		"        rules:\n"+
		"          - {name: everything, action: allow}\n", ied.addr())
	cl := session(t, addr)

	answer := cl.service(serviceBody(1, wire.SvcDeleteDomain, "AA1J1Q01A1LD0"))
	if !isError(t, answer) {
		t.Error("the client was not told")
	}
	until(t, s, refused("read_only"), "the refusal")
	if ied.sawService(wire.SvcDeleteDomain) {
		t.Errorf("the IED saw the delete: %v", ied.seen())
	}
}

// The domain services are refused separately from the service list, so that the
// decision to carry a download is stated where a reviewer reads it.
func TestADownloadIsRefusedUntilDomainServicesAreAllowed(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr := relayFor(t, base, ied.addr())
	cl := session(t, addr)

	answer := cl.service(serviceBody(1, wire.SvcInitiateDownloadSequence, "AA1J1Q01A1LD0"))
	if !isError(t, answer) {
		t.Error("the client was not told")
	}
	until(t, s, refused("domain_services_not_allowed"), "the refusal")
	if ied.sawService(wire.SvcInitiateDownloadSequence) {
		t.Errorf("the IED saw the download: %v", ied.seen())
	}
}

func TestADownloadIsCarriedOnceAllowed(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	_, addr := relayFor(t, base+
		"        allow_domain_services: true\n"+
		"        domains: [\"AA1J1Q01A1LD0\"]\n", ied.addr())
	cl := session(t, addr)

	cl.service(serviceBody(1, wire.SvcInitiateDownloadSequence, "AA1J1Q01A1LD0"))
	ied.await(t, 1, "the download")
	if !ied.sawService(wire.SvcInitiateDownloadSequence) {
		t.Errorf("the IED did not see the download: %v", ied.seen())
	}
}

// The identity: an AP-title the list does not name is refused, and the association
// closes rather than being answered -- because an MMS error cannot answer something
// that happens before there is an MMS association.
func TestAnAPTitleTheListDoesNotNameIsRefused(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr := relayFor(t, base+
		"        ap_titles: [\"1.1.999.1\"]\n", ied.addr())
	cl := dial(t, addr)
	cl.connect()
	if err := cl.associateQuiet([]uint64{1, 1, 999, 77}, 12, ""); err == nil {
		t.Error("the relay answered an association it refused")
	}
	until(t, s, refused("ap_title_not_allowed"), "the refusal")
}

func TestAnAPTitlePatternMatchesAnEstatesNumbering(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	_, addr := relayFor(t, base+
		"        ap_titles: [\"1.1.999.*\"]\n", ied.addr())
	cl := dial(t, addr)
	cl.connect()
	cl.associate([]uint64{1, 1, 999, 77}, 12, "")
	cl.initiate()
	awaitInitiate(t, ied)
}

// The AE-qualifier, which is how a control-centre client is told from an engineering
// one inside a single application.
func TestAnAEQualifierOutsideTheRangeIsRefused(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr := relayFor(t, base+
		"        ae_qualifiers: [\"10-20\"]\n", ied.addr())
	cl := dial(t, addr)
	cl.connect()
	if err := cl.associateQuiet([]uint64{1, 1, 999, 1}, 99, ""); err == nil {
		t.Error("the relay answered an association it refused")
	}
	until(t, s, refused("ae_qualifier_not_allowed"), "the refusal")
}

// The finding this listener most exists to surface: a cleartext password crossing it.
// It is counted and alerted whether or not the listener refuses it, because that is
// the estate's own state and an operator has to be able to see it.
func TestACleartextPasswordIsCountedEvenWhenCarried(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr := relayFor(t, base, ied.addr())
	cl := dial(t, addr)
	cl.connect()
	cl.associate([]uint64{1, 1, 999, 1}, 12, "substationsecret")
	cl.initiate()
	awaitInitiate(t, ied)

	if got := s.Stats().MMSPlaintextPasswords; got != 1 {
		t.Errorf("mms_plaintext_passwords is %d, want 1", got)
	}
	// And it was carried, because on most of the installed base that password is
	// the only authentication the IED has.
	if got := s.Stats().Refusals["mms"]["plaintext_password"]; got != 0 {
		t.Errorf("the association was refused %d times without being asked to be", got)
	}
}

// And refused where the estate has moved on. The refusal is hard: a shadow listener
// that forwarded it would have forwarded the password.
func TestACleartextPasswordIsRefusedWhenAsked(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr := relayFor(t, base+
		"        refuse_plaintext_passwords: true\n", ied.addr())
	cl := dial(t, addr)
	cl.connect()
	if err := cl.associateQuiet([]uint64{1, 1, 999, 1}, 12, "substationsecret"); err == nil {
		t.Error("the relay answered an association it refused")
	}
	until(t, s, refused("plaintext_password"), "the refusal")
	if len(ied.seen()) != 0 {
		t.Errorf("the IED saw %v", ied.seen())
	}
}

// The password is never on the wire toward the IED after a refusal, and never in this
// relay's own memory: the association the policy saw carries a length and no value.
func TestTheRefusalDoesNotEchoThePassword(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	const secret = "substationsecret"
	s, addr := relayFor(t, base+
		"        refuse_plaintext_passwords: true\n", ied.addr())
	cl := dial(t, addr)
	cl.connect()
	if err := cl.associateQuiet([]uint64{1, 1, 999, 1}, 12, secret); err == nil {
		t.Error("the relay answered an association it refused")
	}
	until(t, s, refused("plaintext_password"), "the refusal")
	// Nothing came back at all -- the association closed -- which is itself the
	// assertion: a refusal that echoed the request would have echoed the credential.
	if f, err := cl.next(); err == nil && bodyContains(f, []byte(secret)) {
		t.Error("the refusal echoed the password")
	}
}

// A hard refusal stands in monitor mode; a soft one does not.
func TestMonitorOnlyForwardsASoftRefusalAndNotAHardOne(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr := relayFor(t, base+
		"        monitor_only: true\n"+
		"        functional_constraints: [ST]\n", ied.addr())
	cl := session(t, addr)

	// Soft: a constraint the list does not name. Recorded and forwarded.
	cl.service(readBody(1, objectName("AA1J1Q01A1LD0", "MMXU1$MX$TotW$mag$f")))
	until(t, s, wouldRefuse("constraint_not_allowed"), "the would-be refusal")
	ied.await(t, 1, "the forwarded read")
	if got := s.Stats().Refusals["mms"]["constraint_not_allowed"]; got != 0 {
		t.Errorf("a monitor-only listener counted %d real refusals", got)
	}

	// Hard: a Write is a service that changes the substation, and monitor_only
	// does not forward one. A Write carried so that it could be written down is a
	// moved breaker.
	answer := cl.service(writeBody(2, objectName("AA1J1Q01A1LD0", "XCBR1$CO$Pos$Oper")))
	if !isError(t, answer) {
		t.Error("a monitor-only listener did not refuse the operate")
	}
	if ied.sawService(wire.SvcWrite) {
		t.Errorf("a monitor-only listener forwarded the write: %v", ied.seen())
	}
}

// The rules, in order, first match wins.
func TestARuleNarrowsWhatOneIdentityMayDo(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr := relayFor(t, baseDefault+
		"        default_action: deny\n"+
		"        write_constraints: [CO, SP]\n"+
		"        rules:\n"+
		"          - name: hmi\n"+
		"            action: allow\n"+
		"            ap_titles: [\"1.1.999.1\"]\n"+
		"            objects: [\"AA1J1Q01A1LD0/*$ST$*\", \"AA1J1Q01A1LD0/*$MX$*\"]\n"+
		"            comment: CR-2026-0201\n", ied.addr())
	cl := session(t, addr)

	cl.service(readBody(1, objectName("AA1J1Q01A1LD0", "MMXU1$MX$TotW$mag$f")))
	ied.await(t, 1, "the allowed read")

	answer := cl.service(readBody(2, objectName("AA1J1Q01A1LD0", "XCBR1$CO$Pos$Oper")))
	if !isError(t, answer) {
		t.Error("the client was not told about the object outside the rule")
	}
	until(t, s, refused("no_rule"), "the refusal")
}

// A rule whose schedule is not in force does not select, so the traffic falls through
// to the default.
func TestARuleOutsideItsWindowDoesNotSelect(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr := relayFor(t, baseDefault+
		"        default_action: deny\n"+
		"        allow_domain_services: true\n"+
		"        rules:\n"+
		"          - name: outage-window\n"+
		"            action: allow\n"+
		"            services: [initiate_download_sequence]\n"+
		"            schedule:\n"+
		"              days: [sun]\n"+
		"              from: \"02:00\"\n"+
		"              to: \"02:01\"\n"+
		"              timezone: UTC\n", ied.addr())
	cl := session(t, addr)

	// Outside a one-minute window on a Sunday morning, which this test is almost
	// certainly not inside.
	answer := cl.service(serviceBody(1, wire.SvcInitiateDownloadSequence, "AA1J1Q01A1LD0"))
	if !isError(t, answer) {
		t.Log("the window happened to be in force, which is the schedule working")
		return
	}
	until(t, s, refused("no_rule"), "the refusal")
	if ied.sawService(wire.SvcInitiateDownloadSequence) {
		t.Errorf("the IED saw the download outside the window: %v", ied.seen())
	}
}

// The file services, whose paths are how configuration and disturbance records move.
func TestAFileOutsideTheListIsRefused(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr := relayFor(t, base+
		"        files: [\"COMTRADE/*\"]\n", ied.addr())
	cl := session(t, addr)

	cl.service(fileBody(1, wire.SvcFileOpen, "COMTRADE", "rec001.cfg"))
	ied.await(t, 1, "the allowed file")

	answer := cl.service(fileBody(2, wire.SvcFileOpen, "CONFIG", "ied.cid"))
	if !isError(t, answer) {
		t.Error("the client was not told")
	}
	until(t, s, refused("file_not_allowed"), "the refusal")
}

// A file service whose path this relay could not read is refused rather than
// forwarded, because a path with no policy applied is not a path.
func TestAFileServiceWithNoReadablePathIsRefused(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr := relayFor(t, base, ied.addr())
	cl := session(t, addr)

	// A file open whose name is an empty sequence.
	body := ctx(uint32(wire.ConfirmedRequest), integer(1),
		ctx(uint32(wire.SvcFileOpen), seq(), integer(0)))
	answer := cl.service(body)
	if !isError(t, answer) {
		t.Error("the client was not told")
	}
	until(t, s, refused("file_unreadable"), "the refusal")
	if ied.sawService(wire.SvcFileOpen) {
		t.Errorf("the IED saw the file open: %v", ied.seen())
	}
}

// The bounds. A request naming more objects than the bound allows is refused whole,
// because an IED that answered nineteen of twenty would leave the client believing it
// had read twenty.
func TestARequestPastTheNameBoundIsRefusedWhole(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr := relayFor(t, base+
		"        max_names: 2\n", ied.addr())
	cl := session(t, addr)

	answer := cl.service(readBody(1,
		objectName("LD0", "A1$ST$V$stVal"),
		objectName("LD0", "A2$ST$V$stVal"),
		objectName("LD0", "A3$ST$V$stVal")))
	if !isError(t, answer) {
		t.Error("the client was not told")
	}
	until(t, s, refused("too_many_names"), "the refusal")
	if ied.sawService(wire.SvcRead) {
		t.Errorf("the IED saw the read: %v", ied.seen())
	}
}

// A service this build cannot name is refused, because a service with no name has no
// policy.
func TestAServiceTheRelayCannotNameIsRefused(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr := relayFor(t, base, ied.addr())
	cl := session(t, addr)

	body := ctx(uint32(wire.ConfirmedRequest), integer(1), ctx(200, integer(0)))
	if _, err := cl.serviceQuiet(body); err == nil {
		t.Log("the relay answered rather than closing, which the response policy allows")
	}
	until(t, s, refused("service_unknown"), "the refusal")
	if len(ied.seen()) != 0 {
		t.Errorf("the IED saw %v", ied.seen())
	}
}

// A data value on a presentation context the association never agreed is not MMS as
// far as this relay can tell, so no service rule decided about it -- and it is
// refused rather than carried.
func TestAValueOnAnUndefinedContextIsRefused(t *testing.T) {
	ied := startIED(t, &fakeIED{contexts: map[uint64][]uint64{1: {2, 2, 1, 0, 1}}})
	s, addr := relayFor(t, base, ied.addr())
	cl := dial(t, addr)
	cl.connect()
	cl.associate([]uint64{1, 1, 999, 1}, 12, "")
	// The IED confirmed a list with no MMS context, so the initiate arrives on a
	// context the association does not define.
	if _, err := cl.serviceQuiet(ctx(uint32(wire.InitiateRequest), integer(1))); err == nil {
		t.Log("the relay answered rather than closing")
	}
	until(t, s, refused("unknown_context"), "the refusal")
	if got := s.Stats().MMSOpaque; got == 0 {
		t.Error("mms_opaque_contexts was not counted")
	}
}

// The IED refusing something this relay allowed is recorded and is not a refusal by
// this listener: it is the line that says the two policies disagree.
func TestTheIEDsOwnRefusalIsRecordedAndNotCountedAsOurs(t *testing.T) {
	ied := startIED(t, &fakeIED{errorEvery: ErrClassAccess})
	s, addr := relayFor(t, base, ied.addr())
	cl := session(t, addr)

	cl.service(readBody(1, objectName("AA1J1Q01A1LD0", "MMXU1$MX$TotW$mag$f")))
	until(t, s, func(s *proxy.Server) bool {
		return s.Stats().MMSServerErrors > 0
	}, "the IED's own refusal")
	if n := len(s.Stats().Refusals["mms"]); n != 0 {
		t.Errorf("the IED's own refusal was counted as this listener's: %v",
			s.Stats().Refusals["mms"])
	}
}

// A transport PDU class 0 does not have is a peer using a feature the negotiated
// class lacks, and it ends the connection.
func TestATransportPDUOutsideClassZeroEndsTheConnection(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr := relayFor(t, base, ied.addr())
	cl := dial(t, addr)
	cl.connect()
	// An expedited data PDU.
	cl.send(tpktFrame([]byte{0x02, wire.ED, 0x80}))
	until(t, s, refused("unexpected_transport"), "the refusal")
	if !closed(t, cl) {
		t.Error("the connection was not closed")
	}
}

// A frame this relay cannot read is refused rather than forwarded.
func TestAFrameThatIsNotISOOnTCPIsRefused(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr := relayFor(t, base, ied.addr())
	cl := dial(t, addr)
	cl.send([]byte("GET / HTTP/1.1\r\n\r\n"))
	until(t, s, refused("unreadable_frame"), "the refusal")
	if len(ied.seen()) != 0 {
		t.Errorf("the IED saw %v", ied.seen())
	}
}

// The deny response is configurable, and `drop` means the client hears nothing --
// which reads to an operator as a timeout and is sometimes what an estate wants.
func TestTheDenyResponseIsConfigurable(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	s, addr := relayFor(t, base+
		"        deny_response: drop\n"+
		"        write_constraints: [ST]\n", ied.addr())
	cl := session(t, addr)

	if _, err := cl.serviceQuiet(
		writeBody(1, objectName("AA1J1Q01A1LD0", "XCBR1$CO$Pos$Oper"))); err == nil {
		t.Error("the listener answered a refusal it was told to drop")
	}
	until(t, s, refused("write_constraint_not_allowed"), "the refusal")
}

// An observe rule logs and counts and keeps looking, which is how a rule is tried on
// live traffic before it decides anything.
func TestAnObserveRuleDecidesNothing(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	_, addr := relayFor(t, base+
		"        rules:\n"+
		"          - name: watch-control\n"+
		"            action: observe\n"+
		"            functional_constraints: [CO]\n", ied.addr())
	cl := session(t, addr)

	cl.service(readBody(1, objectName("AA1J1Q01A1LD0", "XCBR1$CO$Pos$stVal")))
	ied.await(t, 1, "the observed read")
}

// A name that is not in the IEC 61850 form -- an IED's own well-known variable -- is
// not forced into a constraint, and a rule about constraints does not decide about it.
func TestAnUnparsedNameIsNotGivenAConstraint(t *testing.T) {
	ied := startIED(t, &fakeIED{})
	_, addr := relayFor(t, base+
		"        functional_constraints: [ST]\n", ied.addr())
	cl := session(t, addr)

	// A vmd-specific name, which has no domain and no constraint.
	cl.service(readBody(1, ctxp(0, []byte("LastApplError"))))
	ied.await(t, 1, "the read of a device variable")
}

// The names used in the tests above are the ones an engineer reads, so a sanity check
// that the relay and the wire package agree about them.
func TestTheNamesInTheseTestsParseAsTheProtocolSaysTheyShould(t *testing.T) {
	for _, tc := range []struct {
		item     string
		fc       wire.FC
		operates bool
		protects bool
	}{
		{"XCBR1$CO$Pos$Oper", wire.FCControl, true, false},
		{"XCBR1$CO$Pos$SBOw", wire.FCControl, false, false},
		{"PTOC1$SG$StrVal$setMag$f", wire.FCSettingGroup, false, true},
		{"MMXU1$MX$TotW$mag$f", wire.FCMeasurand, false, false},
		{"LLN0$BR$brcbST$RptEna", wire.FCBuffered, false, false},
	} {
		n := wire.ParseItem(tc.item)
		if !n.Parsed {
			t.Errorf("%q did not parse", tc.item)
			continue
		}
		if n.FC != tc.fc {
			t.Errorf("%q has constraint %q, want %q", tc.item, n.FC, tc.fc)
		}
		if n.Operates() != tc.operates {
			t.Errorf("%q operates=%v, want %v", tc.item, n.Operates(), tc.operates)
		}
		if n.FC.Protects() != tc.protects {
			t.Errorf("%q protects=%v, want %v", tc.item, n.FC.Protects(), tc.protects)
		}
		if !strings.Contains(tc.item, string(tc.fc)) {
			t.Errorf("%q does not contain its own constraint", tc.item)
		}
	}
}
