package mms

import (
	"errors"
	"testing"
)

// The answer side of MMS, and the parts of the association this package reads
// but nothing drove.
//
// A relay decides about requests, so the request readers are where the tests
// were. The answers still have to be read: a response is matched to its request
// by the invoke identifier, and a device's own refusal is a counter and a log
// line attributed to the right exchange. Reading them wrongly is not a policy
// failure but it is a report nobody can use.

// TestAResponseIsReadForItsIdentifierAndNothingElse: the request carried the
// names, so the response needs only the identifier that pairs it with one --
// and reading no further is the point, because the answer's body is values and
// this package does not keep values.
func TestAResponseIsReadForItsIdentifierAndNothingElse(t *testing.T) {
	// A confirmed response whose body also holds a Read result: the identifier
	// is taken and the rest left alone.
	body := ctx(uint32(ConfirmedResponse), integer(42),
		ctx(uint32(SvcRead), ctx(1, seq(ctxp(0, []byte{0x01})))))
	m, err := ParsePDU(body)
	if err != nil {
		t.Fatal(err)
	}
	if m.PDU != ConfirmedResponse {
		t.Errorf("PDU %v", m.PDU)
	}
	if !m.HasInvokeID || m.InvokeID != 42 {
		t.Errorf("invoke %d (%v)", m.InvokeID, m.HasInvokeID)
	}
	if m.HasService {
		t.Errorf("a response was given a service: %v", m.Service)
	}
	if len(m.Names) != 0 {
		t.Errorf("a response was read for names: %v", m.Names)
	}
}

// TestTheCancelAndRejectPDUsAreReadTheSameWay: each is about an exchange rather
// than an object, so each is read for the identifier of the exchange it is
// about. A reject with no identifier at all is not an error -- it is what a
// server sends when it could not read the request far enough to find one.
func TestTheCancelAndRejectPDUsAreReadTheSameWay(t *testing.T) {
	for _, p := range []PDU{Reject, CancelRequest, CancelResponse, CancelError} {
		m, err := ParsePDU(ctx(uint32(p), integer(7)))
		if err != nil {
			t.Fatalf("%v: %v", p, err)
		}
		if m.PDU != p || !m.HasInvokeID || m.InvokeID != 7 {
			t.Errorf("%v: %+v", p, m)
		}
	}
	m, err := ParsePDU(ctx(uint32(Reject), ctx(0, integer(1))))
	if err != nil {
		t.Fatal(err)
	}
	if m.HasInvokeID {
		t.Errorf("an identifier was invented: %d", m.InvokeID)
	}
}

// TestTheDevicesOwnRefusalIsReadAsAClassAndACode: this is what separates "the
// relay refused" from "the IED refused", which are different findings about
// different equipment -- and the second must not be counted against the policy.
func TestTheDevicesOwnRefusalIsReadAsAClassAndACode(t *testing.T) {
	// serviceError [0] { errorClass [0] { <class tag> code }, ... }
	body := ctx(uint32(ConfirmedError), integer(9),
		ctx(0, ctx(0, ctxp(3, []byte{0x05}))))
	m, err := ParsePDU(body)
	if err != nil {
		t.Fatal(err)
	}
	if m.PDU != ConfirmedError || !m.HasInvokeID || m.InvokeID != 9 {
		t.Fatalf("%+v", m)
	}
	if !m.HasError {
		t.Fatal("an error PDU carried no error")
	}
	// The class is the tag of the choice, and the code its contents.
	if m.ErrorClass != 3 {
		t.Errorf("class %d", m.ErrorClass)
	}
	if m.ErrorCode != 5 {
		t.Errorf("code %d", m.ErrorCode)
	}

	// An error whose serviceError carries an additionalCode INTEGER beside the
	// class: the code comes from it.
	body = ctx(uint32(ConfirmedError), integer(10),
		ctx(0, ctx(0, ctxp(1, []byte{})), integer(77)))
	m, err = ParsePDU(body)
	if err != nil {
		t.Fatal(err)
	}
	if m.ErrorClass != 1 || m.ErrorCode != 77 {
		t.Errorf("class %d code %d", m.ErrorClass, m.ErrorCode)
	}

	// An error with no identifier and no readable class is still an error PDU
	// rather than a parse failure: the exchange happened.
	m, err = ParsePDU(ctx(uint32(ConfirmedError), ctx(0, ctx(0))))
	if err != nil {
		t.Fatal(err)
	}
	if m.PDU != ConfirmedError || m.HasInvokeID || m.HasError {
		t.Errorf("%+v", m)
	}
}

// TestAServiceWhoseWholeBodyIsOneNameIsReadForThatName: the attribute and
// deletion services address one object each, and the name is the whole of what
// a policy decides about -- so a reader that stopped at the service would allow
// a delete of anything.
func TestAServiceWhoseWholeBodyIsOneNameIsReadForThatName(t *testing.T) {
	body := ctx(uint32(ConfirmedRequest), integer(1),
		ctx(uint32(SvcGetVariableAccessAttributes), objectName("Relay1", "MMXU1$MX$A")))
	m, err := ParsePDU(body)
	if err != nil {
		t.Fatal(err)
	}
	if m.Service != SvcGetVariableAccessAttributes {
		t.Fatalf("service %v", m.Service)
	}
	if len(m.Names) != 1 {
		t.Fatalf("names %v", m.Names)
	}
	if m.Names[0].Domain != "Relay1" || m.Names[0].Item != "MMXU1$MX$A" {
		t.Errorf("name %+v", m.Names[0])
	}

	// A vmd-specific name has no domain and is still a name.
	body = ctx(uint32(ConfirmedRequest), integer(2),
		ctx(uint32(SvcGetVariableAccessAttributes), vmdName("GLOBAL")))
	m, err = ParsePDU(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Names) != 1 || m.Names[0].Item != "GLOBAL" || m.Names[0].Domain != "" {
		t.Errorf("names %v", m.Names)
	}

	// A body whose context element holds neither is carried with no name rather
	// than with an empty one, because an empty name would match a pattern.
	body = ctx(uint32(ConfirmedRequest), integer(3),
		ctx(uint32(SvcGetVariableAccessAttributes), ctxp(0, []byte{})))
	m, err = ParsePDU(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Names) != 0 {
		t.Errorf("an empty identifier became a name: %v", m.Names)
	}
}

// TestDefiningAListRecordsItsNameAndItsMembers: both halves matter and for
// different reasons. The list's name is what a later Read addresses, so a
// policy that only saw the members would let a client build a list today and
// read it tomorrow under a name nobody wrote a rule about.
func TestDefiningAListRecordsItsNameAndItsMembers(t *testing.T) {
	members := ctx(1,
		seq(ctx(0, objectName("Relay1", "MMXU1$MX$A"))),
		seq(ctx(0, objectName("Relay1", "CSWI1$ST$Pos"))),
	)
	body := ctx(uint32(ConfirmedRequest), integer(4),
		ctx(uint32(SvcDefineNamedVariableList), objectName("Relay1", "MyList"), members))
	m, err := ParsePDU(body)
	if err != nil {
		t.Fatal(err)
	}
	if m.Service != SvcDefineNamedVariableList {
		t.Fatalf("service %v", m.Service)
	}
	if m.ListName == "" {
		t.Error("the list's own name was not recorded")
	}
	if len(m.Names) != 2 {
		t.Fatalf("members %v", m.Names)
	}
	if m.Names[0].Item != "MMXU1$MX$A" || m.Names[1].Item != "CSWI1$ST$Pos" {
		t.Errorf("members %+v", m.Names)
	}
}

// TestTheAssociationsUserInformationIsFoundInBothItsForms: the initiate PDU
// rides inside an EXTERNAL, and the two arms a stack may use carry the same
// thing. A relay that read one and not the other would see an association with
// no initiate in it and have to decide about nothing.
func TestTheAssociationsUserInformationIsFoundInBothItsForms(t *testing.T) {
	initiate := ctx(uint32(InitiateRequest), integer(1))
	for name, arm := range map[string][]byte{
		"single-ASN1-type": ctx(0, initiate),
		"octet-aligned":    ctxp(1, initiate),
	} {
		t.Run(name, func(t *testing.T) {
			aarq := app(AARQ, ctx(aarqUserInfo, external(arm)))
			a, err := ParseAssociate(aarq)
			if err != nil {
				t.Fatal(err)
			}
			if len(a.UserInfo) == 0 {
				t.Fatal("no user information")
			}
			// What came out is the initiate PDU, which has to parse as one.
			if _, err := ParsePDU(a.UserInfo); err != nil && name == "single-ASN1-type" {
				t.Errorf("the single-ASN1-type arm did not yield a PDU: %v", err)
			}
		})
	}

	// A shape this reader does not recognise yields no octets rather than an
	// error: the association happened, and whether to forward one whose
	// initiate could not be read is the caller's decision.
	aarq := app(AARQ, ctx(aarqUserInfo, external(ctxp(7, []byte{0x01}))))
	a, err := ParseAssociate(aarq)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.UserInfo) != 0 {
		t.Errorf("an unrecognised arm yielded octets: %x", a.UserInfo)
	}
	// And a primitive user-information is not a container at all.
	a, err = ParseAssociate(app(AARQ, ctxp(aarqUserInfo, []byte{0x01})))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.UserInfo) != 0 {
		t.Errorf("a primitive user-information yielded octets: %x", a.UserInfo)
	}
}

// TestEveryFormAnAuthenticationValueTakesIsNamed: the value itself is never
// kept, and what the policy decides on is which form it took -- so each form
// has to be told apart, including the two that are not a password and the one
// that is a password sent implicitly tagged.
func TestEveryFormAnAuthenticationValueTakesIsNamed(t *testing.T) {
	cases := []struct {
		name   string
		value  []byte
		want   AuthKind
		length int
	}{
		// Some stacks send the charstring implicitly tagged, so the contents of
		// the element are the password itself.
		{"implicit charstring", ctxp(aarqAuthValue, []byte("secret")), AuthPassword, 6},
		{"explicit charstring", ctx(aarqAuthValue, ctxp(0, []byte("hunter2"))), AuthPassword, 7},
		{"a GeneralString", ctx(aarqAuthValue, univ(TagGeneralStr, []byte("abcd"))), AuthPassword, 4},
		{"a VisibleString", ctx(aarqAuthValue, visible("abc")), AuthPassword, 3},
		{"a bit string", ctx(aarqAuthValue, ctxp(1, []byte{0x00, 0xff})), AuthBitString, 2},
		{"an external", ctx(aarqAuthValue, ctxp(2, []byte{0x01})), AuthExternal, 1},
		{"something else", ctx(aarqAuthValue, ctxp(9, []byte{0x01, 0x02})), AuthOther, 2},
		// An empty constructed value is a field that was sent and said nothing.
		{"nothing at all", ctx(aarqAuthValue), AuthNone, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, err := ParseAssociate(app(AARQ, c.value))
			if err != nil {
				t.Fatal(err)
			}
			if a.Auth != c.want {
				t.Errorf("auth %v, want %v", a.Auth, c.want)
			}
			if a.AuthLength != c.length {
				t.Errorf("length %d, want %d", a.AuthLength, c.length)
			}
		})
	}
}

// TestTheResponseSaysWhetherItAcceptedAndWhoAnswered: the AARE is where a
// relay learns the association exists, and the responding title is the
// identity the device answered as -- which is what a later finding is about.
func TestTheResponseSaysWhetherItAcceptedAndWhoAnswered(t *testing.T) {
	aare := app(AARE,
		ctx(aareAppContext, oid(1, 0, 9506, 2, 3)),
		ctx(aareResult, integer(0)),
		ctx(aareRespAPTitle, oid(1, 1, 999, 1)),
		ctx(aareRespAEQual, integer(12)),
		ctx(aareUserInfo, external(ctx(0, ctx(uint32(InitiateResponse), integer(1))))),
	)
	a, err := ParseAssociate(aare)
	if err != nil {
		t.Fatal(err)
	}
	if a.Tag != AARE {
		t.Fatalf("tag %d", a.Tag)
	}
	if !a.HasResult || a.Result != 0 {
		t.Errorf("result %d (%v)", a.Result, a.HasResult)
	}
	if a.Context.String() == "" {
		t.Error("no application context")
	}
	if a.CalledAPTitle.String() != "1.1.999.1" {
		t.Errorf("responding title %s", a.CalledAPTitle)
	}
	if !a.HasCalledAEQualifier || a.CalledAEQualifier != 12 {
		t.Errorf("qualifier %d (%v)", a.CalledAEQualifier, a.HasCalledAEQualifier)
	}
	if len(a.UserInfo) == 0 {
		t.Error("no user information")
	}

	// A refusal carries a result that is not zero, and that is the whole of
	// what this reader needs from it.
	a, err = ParseAssociate(app(AARE, ctx(aareResult, integer(1)), ctx(aareDiagnostic, ctx(1, integer(2)))))
	if err != nil {
		t.Fatal(err)
	}
	if !a.HasResult || a.Result != 1 {
		t.Errorf("a refusal read as %d (%v)", a.Result, a.HasResult)
	}
}

// TestTheTitlesAreReadInBothTheFormsStacksSend: explicitly tagged is the form
// the standard describes and implicitly tagged is the form some equipment
// sends, and an estate's rules are written about the title either way.
func TestTheTitlesAreReadInBothTheFormsStacksSend(t *testing.T) {
	// Implicit: the context tag is primitive and its octets are the identifier.
	a, err := ParseAssociate(app(AARQ,
		ctxp(aarqCallingAPName, oidBody(1, 1, 999, 2)),
		ctxp(aarqCallingAEQual, []byte{0x07}),
	))
	if err != nil {
		t.Fatal(err)
	}
	if a.CallingAPTitle.String() != "1.1.999.2" {
		t.Errorf("implicit title %s", a.CallingAPTitle)
	}
	if !a.HasCallingAEQualifier || a.CallingAEQualifier != 7 {
		t.Errorf("implicit qualifier %d (%v)", a.CallingAEQualifier, a.HasCallingAEQualifier)
	}

	// A title in the directory-name form rather than the identifier form is
	// carried as absent rather than guessed at: IEC 61850 uses identifiers.
	a, err = ParseAssociate(app(AARQ, ctx(aarqCalledAPTitle, seq(visible("cn=relay1")))))
	if err != nil {
		t.Fatal(err)
	}
	if a.CalledAPTitle != nil {
		t.Errorf("a directory name was read as an identifier: %s", a.CalledAPTitle)
	}
	// The same for a qualifier whose explicit wrapper holds no INTEGER.
	a, err = ParseAssociate(app(AARQ, ctx(aarqCalledAEQual, visible("one"))))
	if err != nil {
		t.Fatal(err)
	}
	if a.HasCalledAEQualifier {
		t.Errorf("a qualifier was invented: %d", a.CalledAEQualifier)
	}
}

// TestTheMechanismNameIsReadWhereAStackSendsOne: the mechanism is implicitly
// tagged, so its octets are the identifier, and it is the field that says
// whether a password was meant to be sent at all.
func TestTheMechanismNameIsReadWhereAStackSendsOne(t *testing.T) {
	a, err := ParseAssociate(app(AARQ, ctxp(aarqMechanism, oidBody(1, 0, 9506, 2, 3))))
	if err != nil {
		t.Fatal(err)
	}
	if a.Mechanism.String() != "1.0.9506.2.3" {
		t.Errorf("mechanism %s", a.Mechanism)
	}
}

// TestTheReleaseAndAbortAPDUsCarryNothingWorthAPolicy: they are read so the
// relay can say which they were, and no further -- a release is a release.
func TestTheReleaseAndAbortAPDUsCarryNothingWorthAPolicy(t *testing.T) {
	for _, tag := range []uint32{RLRQ, RLRE, ABRT} {
		a, err := ParseAssociate(app(tag, ctx(0, integer(0))))
		if err != nil {
			t.Fatalf("%d: %v", tag, err)
		}
		if a.Tag != tag {
			t.Errorf("tag %d, want %d", a.Tag, tag)
		}
		if a.Auth != AuthNone || a.Context != nil {
			t.Errorf("%d: %+v", tag, a)
		}
	}
}

// TestAnAPDUThatIsNotAnAssociationIsRefused: the shape is checked before the
// fields, because a reader that fell through to the field loop on anything
// would report an association about an APDU that was not one.
func TestAnAPDUThatIsNotAnAssociationIsRefused(t *testing.T) {
	// A context tag where an [APPLICATION n] belongs.
	if _, err := ParseAssociate(ctx(0, integer(1))); !errors.Is(err, ErrEncoding) {
		t.Errorf("a context-tagged APDU: %v", err)
	}
	// Primitive where constructed belongs.
	if _, err := ParseAssociate(tlv(ClassApplication, false, AARQ, []byte{0x01})); !errors.Is(err, ErrEncoding) {
		t.Errorf("a primitive APDU: %v", err)
	}
	// An application tag no edition of X.227 defines.
	if _, err := ParseAssociate(app(9, integer(1))); !errors.Is(err, ErrEncoding) {
		t.Errorf("APDU 9: %v", err)
	}
	if _, err := ParseAssociate(nil); err == nil {
		t.Error("nothing at all was accepted")
	}
}

// external renders an EXTERNAL, which is [UNIVERSAL 8] IMPLICIT SEQUENCE and
// so is written as a universal constructed tag rather than as a SEQUENCE.
func external(body ...[]byte) []byte { return tlv(ClassUniversal, true, 8, body...) }

// oidBody is the contents of an object identifier without its tag, which is
// what an implicitly tagged field carries.
func oidBody(arcs ...uint64) []byte {
	full := oid(arcs...)
	// oid() renders a universal primitive TLV with a one-octet length for the
	// sizes used here, so the contents start at the third octet.
	return full[2:]
}

// TestAFieldThatDoesNotParseIsAnErrorRatherThanAnAbsentField: every one of
// these fields is something a rule is written about -- a title, a qualifier, a
// result -- and a reader that swallowed a malformed one would report an
// association with no title, which is an association a title rule cannot
// refuse. Failing closed here is what makes the rules mean anything.
func TestAFieldThatDoesNotParseIsAnErrorRatherThanAnAbsentField(t *testing.T) {
	// An object identifier whose last arc never ends: the high bit of the final
	// octet says another follows and there is none.
	badOID := univ(TagOID, []byte{0x2b, 0x81})
	// An INTEGER wider than this reader will hold.
	badInt := univ(TagInteger, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9})

	cases := []struct {
		name string
		apdu []byte
	}{
		{"a calling title that does not decode", app(AARQ, ctx(aarqCallingAPName, badOID))},
		{"a called title that does not decode", app(AARQ, ctx(aarqCalledAPTitle, badOID))},
		{"an application context that does not decode", app(AARQ, ctx(aarqAppContext, badOID))},
		{"a calling qualifier too wide to hold", app(AARQ, ctx(aarqCallingAEQual, badInt))},
		{"a called qualifier too wide to hold", app(AARQ, ctx(aarqCalledAEQual, badInt))},
		{"an implicit mechanism that does not decode", app(AARQ, ctxp(aarqMechanism, []byte{0x2b, 0x81}))},
		{"a response context that does not decode", app(AARE, ctx(aareAppContext, badOID))},
		{"a result too wide to hold", app(AARE, ctx(aareResult, badInt))},
		{"a responding title that does not decode", app(AARE, ctx(aareRespAPTitle, badOID))},
		{"a responding qualifier too wide to hold", app(AARE, ctx(aareRespAEQual, badInt))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ParseAssociate(c.apdu); err == nil {
				t.Error("accepted")
			}
		})
	}
}

// TestAnInvokeIdentifierOutsideItsRangeIsRefusedWhereverItAppears: the
// identifier pairs a response with its request, and ISO 9506 bounds it to an
// unsigned 32-bit value. A reader that took a wider one would pair an answer
// with an exchange that never happened.
func TestAnInvokeIdentifierOutsideItsRangeIsRefusedWhereverItAppears(t *testing.T) {
	tooWide := univ(TagInteger, []byte{0x01, 0x00, 0x00, 0x00, 0x00})
	for _, p := range []PDU{ConfirmedResponse, ConfirmedError, Reject, CancelRequest} {
		if _, err := ParsePDU(ctx(uint32(p), tooWide)); err == nil {
			t.Errorf("%v accepted an identifier past unsigned 32 bits", p)
		}
	}
}
