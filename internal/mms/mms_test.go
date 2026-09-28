package mms

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// The layers, from the stream up. Each test is about a decision a relay has to make
// on the strength of what this package read.

func TestATPKTFrameIsReadWithItsOwnOctetsKept(t *testing.T) {
	body := cotpData(sessionData([]byte{0x61, 0x00}))
	r := NewReader(bytes.NewReader(tpkt(body)), 0)
	f, err := r.Next()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(f.Body, body) {
		t.Errorf("the body is %x, want %x", f.Body, body)
	}
	// The whole frame is kept, because the relay forwards what it read rather than
	// re-rendering it.
	if len(f.Raw) != len(body)+TPKTHeader {
		t.Errorf("the frame is %d octets, want %d", len(f.Raw), len(body)+TPKTHeader)
	}
}

// A length is two octets from a peer, so it is checked before it is used to
// allocate.
func TestAFrameLongerThanTheBoundIsRefusedBeforeItIsRead(t *testing.T) {
	// A header claiming 60000 octets, and nothing behind it.
	b := []byte{TPKTVersion, 0, 0xEA, 0x60}
	_, err := NewReader(bytes.NewReader(b), 4096).Next()
	if !errors.Is(err, ErrTooLong) {
		t.Fatalf("the error is %v, want %v", err, ErrTooLong)
	}
}

func TestAFrameShorterThanItsOwnHeaderIsRefused(t *testing.T) {
	_, err := NewReader(bytes.NewReader([]byte{TPKTVersion, 0, 0, 3}), 0).Next()
	if !errors.Is(err, ErrSize) {
		t.Fatalf("the error is %v, want %v", err, ErrSize)
	}
}

func TestSomethingThatIsNotISOOnTCPIsSaidToBeThat(t *testing.T) {
	_, err := NewReader(bytes.NewReader([]byte("GET / HTTP/1.1\r\n")), 0).Next()
	if !errors.Is(err, ErrVersion) {
		t.Fatalf("the error is %v, want %v", err, ErrVersion)
	}
}

// The BER reader's two bounds, which are what stop a nested encoding from being an
// amplifier.
func TestAnIndefiniteLengthIsRefusedRatherThanScannedFor(t *testing.T) {
	// A sequence with the indefinite form: 0x30 0x80 ... 0x00 0x00.
	_, err := NewBER([]byte{0x30, 0x80, 0x05, 0x00, 0x00, 0x00}).Next()
	if !errors.Is(err, ErrEncoding) {
		t.Fatalf("the error is %v, want %v", err, ErrEncoding)
	}
}

func TestALengthPastTheBufferIsRefusedRatherThanSliced(t *testing.T) {
	_, err := NewBER([]byte{0x30, 0x40, 0x01}).Next()
	if !errors.Is(err, ErrShort) {
		t.Fatalf("the error is %v, want %v", err, ErrShort)
	}
}

func TestNestingPastTheDepthBoundIsRefused(t *testing.T) {
	// A sequence nested deeper than MaxDepth. Built from the inside out.
	b := univ(TagNull, nil)
	for range MaxDepth + 4 {
		b = seq(b)
	}
	r := NewBER(b)
	var err error
	for range MaxDepth + 4 {
		var e Element
		if e, err = r.Next(); err != nil {
			break
		}
		if r, err = r.Sub(e); err != nil {
			break
		}
	}
	if !errors.Is(err, ErrEncoding) {
		t.Fatalf("the error is %v, want a refusal past %d levels", err, MaxDepth)
	}
}

// The high-tag-number form has to work, because MMS numbers fileDirectory 77 and the
// low form stops at 30. It is bounded rather than refused.
func TestAHighTagNumberIsReadBecauseMMSNeedsOne(t *testing.T) {
	e, err := NewBER(ctx(uint32(SvcFileDirectory), integer(1))).Next()
	if err != nil {
		t.Fatal(err)
	}
	if !e.Context(uint32(SvcFileDirectory)) {
		t.Errorf("the tag is class %#02x number %d, want context 77", e.Class, e.Tag)
	}
}

// And a tag a peer padded into the long form is refused, because that is two
// encodings of one tag and a rule matching on the tag would see only one of them.
func TestATagThatDidNotNeedTheLongFormIsRefused(t *testing.T) {
	// Context tag 4, written in the high form: 0xBF 0x04.
	_, err := NewBER([]byte{0xBF, 0x04, 0x00}).Next()
	if !errors.Is(err, ErrEncoding) {
		t.Fatalf("the error is %v, want %v", err, ErrEncoding)
	}
}

func TestATagNumberThatNeverEndsIsRefused(t *testing.T) {
	_, err := NewBER([]byte{0xBF, 0x81, 0x81}).Next()
	if !errors.Is(err, ErrEncoding) {
		t.Fatalf("the error is %v, want %v", err, ErrEncoding)
	}
}

func TestATagNumberPastTheBoundIsRefused(t *testing.T) {
	_, err := NewBER([]byte{0xBF, 0xFF, 0xFF, 0xFF, 0x7F, 0x00}).Next()
	if !errors.Is(err, ErrSize) {
		t.Fatalf("the error is %v, want %v", err, ErrSize)
	}
}

// An INTEGER wider than the program can hold is refused rather than truncated: the
// low bits of an invoke identifier are a different identifier.
func TestAnIntegerWiderThanSixtyFourBitsIsRefused(t *testing.T) {
	e := Element{Class: ClassUniversal, Tag: TagInteger,
		Data: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}}
	if _, err := Int(e); !errors.Is(err, ErrSize) {
		t.Fatalf("the error is %v, want %v", err, ErrSize)
	}
}

func TestANegativeCountIsRefusedWhereACountBelongs(t *testing.T) {
	e := Element{Class: ClassUniversal, Tag: TagInteger, Data: []byte{0xFF}}
	if _, err := Uint(e); !errors.Is(err, ErrEncoding) {
		t.Fatalf("the error is %v, want %v", err, ErrEncoding)
	}
}

// COTP, which is read to be traversed and bounded.
func TestACOTPHeaderLongerThanItsFrameIsRefused(t *testing.T) {
	_, err := ParseCOTP([]byte{0x40, DT, 0x80})
	if !errors.Is(err, ErrShort) {
		t.Fatalf("the error is %v, want %v", err, ErrShort)
	}
}

func TestAConnectionRequestsSelectorsAreRead(t *testing.T) {
	// A CR with a called and a calling selector, which is what an IED's stack
	// sends: both a single octet on most of the estate.
	params := []byte{paramTPDUSize, 1, 0x0A, paramCalling, 2, 0x00, 0x01,
		paramCalled, 2, 0x00, 0x01}
	body := append([]byte{0, 0, 0, 1, 0x00}, params...)
	frame := append([]byte{byte(len(body) + 1), CR}, body...)
	c, err := ParseCOTP(frame)
	if err != nil {
		t.Fatal(err)
	}
	if c.Type != CR {
		t.Errorf("the type is %s, want a connection request", TypeName(c.Type))
	}
	if got := TPDUBytes(c.TPDUSize); got != 1024 {
		t.Errorf("the negotiated size is %d, want 1024", got)
	}
	if !bytes.Equal(c.Called, []byte{0, 1}) {
		t.Errorf("the called selector is %x", c.Called)
	}
}

// A selector longer than X.224 allows is a length field being used as a length
// field, and it is refused.
func TestASelectorLongerThanTheBoundIsRefused(t *testing.T) {
	long := make([]byte, MaxSelector+1)
	params := append([]byte{paramCalled, byte(len(long))}, long...)
	body := append([]byte{0, 0, 0, 1, 0x00}, params...)
	frame := append([]byte{byte(len(body) + 1), CR}, body...)
	_, err := ParseCOTP(frame)
	if !errors.Is(err, ErrSize) {
		t.Fatalf("the error is %v, want %v", err, ErrSize)
	}
}

// The session layer's canonical pair, which is the shape every data frame has.
func TestTheGiveTokensAndDataTransferPairIsTraversed(t *testing.T) {
	payload := []byte{0x61, 0x03, 0x30, 0x01, 0x00}
	s, err := ParseSession(sessionData(payload))
	if err != nil {
		t.Fatal(err)
	}
	if s.Kind != SPDUDataTransfer {
		t.Errorf("the unit is %s, want a data transfer", SPDUName(s.Kind))
	}
	if !bytes.Equal(s.UserData, payload) {
		t.Errorf("the user data is %x, want %x", s.UserData, payload)
	}
}

func TestASessionUnitThisReaderDoesNotKnowIsRefused(t *testing.T) {
	_, err := ParseSession([]byte{99, 0})
	if !errors.Is(err, ErrEncoding) {
		t.Fatalf("the error is %v, want %v", err, ErrEncoding)
	}
}

func TestASessionUnitLongerThanItsPayloadIsRefused(t *testing.T) {
	_, err := ParseSession([]byte{SPDUConnect, 0x40, 0x01})
	if !errors.Is(err, ErrShort) {
		t.Fatalf("the error is %v, want %v", err, ErrShort)
	}
}

// The presentation layer, which is where the syntax is named. The context definition
// list is why an MMS payload can be told from an ACSE one.
func TestTheContextListSaysWhichIdentifierIsMMS(t *testing.T) {
	cp := set(ctx(cpNormalMode,
		ctx(cpContextList,
			seq(integer(1), oid(2, 2, 1, 0, 1), seq(oid(2, 1, 1))),
			seq(integer(3), oid(1, 0, 9506, 2, 1), seq(oid(2, 1, 1)))),
		app(1, seq(integer(1), ctx(0, []byte{0x60, 0x00})))))
	ctxs, user, err := ParseCP(cp)
	if err != nil {
		t.Fatal(err)
	}
	if got := ctxs[1]; !got.Equal(OIDACSE) {
		t.Errorf("context 1 is %s, want the ACSE syntax", got)
	}
	if got := ctxs[3]; !got.Equal(OIDMMSAbstract) {
		t.Errorf("context 3 is %s, want the MMS syntax", got)
	}
	if len(user) == 0 {
		t.Error("the connect carried no user data")
	}
}

// A data value on a context the association never defined is not MMS, and saying so
// is the point: forwarding it as MMS would be forwarding something with no policy
// applied to it.
func TestAValueOnAnUndefinedContextIsNotMMS(t *testing.T) {
	vals, err := ParsePDVs(pdv(7, []byte{0xA0, 0x00}), Contexts{3: OIDMMSAbstract})
	if err != nil {
		t.Fatal(err)
	}
	if len(vals) != 1 {
		t.Fatalf("got %d values", len(vals))
	}
	if vals[0].IsMMS() {
		t.Error("a value on context 7 was taken for MMS")
	}
	if vals[0].Syntax != nil {
		t.Errorf("an undefined context named the syntax %s", vals[0].Syntax)
	}
}

func TestMoreContextsThanTheBoundAllowsIsRefused(t *testing.T) {
	items := make([][]byte, 0, MaxContexts+2)
	for i := range MaxContexts + 2 {
		items = append(items, seq(integer(int64(i+1)), oid(2, 1, 1), seq(oid(2, 1, 1))))
	}
	cp := set(ctx(cpNormalMode, ctx(cpContextList, items...)))
	_, _, err := ParseCP(cp)
	if !errors.Is(err, ErrSize) {
		t.Fatalf("the error is %v, want %v", err, ErrSize)
	}
}

// An object identifier is decoded, and one this program cannot hold is refused
// rather than folded into a different identifier.
func TestAnObjectIdentifierIsDecoded(t *testing.T) {
	e, err := NewBER(oid(1, 1, 999, 1)).Next()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ReadOID(e)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != "1.1.999.1" {
		t.Errorf("the identifier is %s, want 1.1.999.1", got)
	}
}

func TestAnUnterminatedObjectIdentifierArcIsRefused(t *testing.T) {
	e := Element{Class: ClassUniversal, Tag: TagOID, Data: []byte{0x2A, 0x81, 0x81}}
	if _, err := ReadOID(e); !errors.Is(err, ErrEncoding) {
		t.Fatalf("the error is %v, want %v", err, ErrEncoding)
	}
}

func TestAnObjectIdentifierArcWiderThanSixtyFourBitsIsRefused(t *testing.T) {
	data := []byte{0x2A}
	for range 12 {
		data = append(data, 0xFF)
	}
	data = append(data, 0x01)
	e := Element{Class: ClassUniversal, Tag: TagOID, Data: data}
	if _, err := ReadOID(e); !errors.Is(err, ErrSize) {
		t.Fatalf("the error is %v, want %v", err, ErrSize)
	}
}

// ACSE: the identity, and the password this protocol sends in the clear.
func TestAnAssociateRequestNamesTheCallingApplication(t *testing.T) {
	aarq := app(AARQ,
		ctx(aarqAppContext, oid(1, 0, 9506, 2, 3)),
		ctx(aarqCalledAPTitle, oid(1, 1, 999, 1)),
		ctx(aarqCalledAEQual, integer(12)),
		ctx(aarqCallingAPName, oid(1, 1, 999, 2)),
		ctx(aarqCallingAEQual, integer(33)))
	a, err := ParseAssociate(aarq)
	if err != nil {
		t.Fatal(err)
	}
	if a.Tag != AARQ {
		t.Errorf("the APDU is %s, want an associate request", APDUName(a.Tag))
	}
	if got := a.CallingAPTitle.String(); got != "1.1.999.2" {
		t.Errorf("the calling title is %q", got)
	}
	if !a.HasCallingAEQualifier || a.CallingAEQualifier != 33 {
		t.Errorf("the calling qualifier is %d (present %v)",
			a.CallingAEQualifier, a.HasCallingAEQualifier)
	}
	if a.Auth != AuthNone {
		t.Errorf("an association with no authentication value reported %s", a.Auth)
	}
}

// The finding this layer exists for. The value's form and length are recorded and
// the value itself is not, because a relay that logged the password would be the
// second place it leaks.
func TestAClearTextPasswordIsSeenAndNotKept(t *testing.T) {
	const secret = "substationsecret"
	aarq := app(AARQ,
		ctx(aarqAppContext, oid(1, 0, 9506, 2, 3)),
		ctxp(aarqMechanism, []byte{0x2A, 0x86, 0x48}),
		ctx(aarqAuthValue, ctxp(0, []byte(secret))))
	a, err := ParseAssociate(aarq)
	if err != nil {
		t.Fatal(err)
	}
	if a.Auth != AuthPassword {
		t.Fatalf("the authentication form is %s, want a password", a.Auth)
	}
	if a.AuthLength != len(secret) {
		t.Errorf("the length is %d, want %d", a.AuthLength, len(secret))
	}
	// And nowhere in the parsed association is the secret itself.
	if strings.Contains(sprintAll(a), secret) {
		t.Error("the password survived into the parsed association")
	}
}

func TestAnAssociateResponseSaysWhetherItAccepted(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result int64
		want   bool
	}{
		{"accepted", 0, true},
		{"rejected permanently", 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			aare := app(AARE,
				ctx(aareAppContext, oid(1, 0, 9506, 2, 3)),
				ctx(aareResult, integer(tc.result)))
			a, err := ParseAssociate(aare)
			if err != nil {
				t.Fatal(err)
			}
			if a.Accepted() != tc.want {
				t.Errorf("Accepted is %v, want %v", a.Accepted(), tc.want)
			}
		})
	}
}

// The MMS layer. What a policy decides about is the service and the names.
func TestAReadNamesTheObjectsItAddressed(t *testing.T) {
	m, err := ParsePDU(readRequest(7,
		objectName("AA1J1Q01A1LD0", "MMXU1$MX$TotW$mag$f"),
		objectName("AA1J1Q01A1LD0", "XCBR1$ST$Pos$stVal")))
	if err != nil {
		t.Fatal(err)
	}
	if m.PDU != ConfirmedRequest || m.Service != SvcRead {
		t.Fatalf("the request is %s/%s", m.PDU, m.Service)
	}
	if !m.HasInvokeID || m.InvokeID != 7 {
		t.Errorf("the invoke identifier is %d (present %v)", m.InvokeID, m.HasInvokeID)
	}
	if len(m.Names) != 2 {
		t.Fatalf("the request named %d objects, want 2", len(m.Names))
	}
	if got := m.Names[0].Key(); got != "AA1J1Q01A1LD0/MMXU1$MX$TotW$mag$f" {
		t.Errorf("the first name is %q", got)
	}
	if m.Names[0].FC != FCMeasurand || m.Names[1].FC != FCStatus {
		t.Errorf("the constraints are %q and %q", m.Names[0].FC, m.Names[1].FC)
	}
}

// The distinction the whole kind is about: the same Write means a breaker or a
// measurement depending on the functional constraint.
func TestAWriteToAControlAttributeIsAnOperate(t *testing.T) {
	m, err := ParsePDU(writeRequest(9,
		objectName("AA1J1Q01A1LD0", "XCBR1$CO$Pos$Oper")))
	if err != nil {
		t.Fatal(err)
	}
	if m.Service != SvcWrite {
		t.Fatalf("the service is %s", m.Service)
	}
	if len(m.Names) != 1 {
		t.Fatalf("the write named %d objects", len(m.Names))
	}
	n := m.Names[0]
	if n.FC != FCControl {
		t.Fatalf("the constraint is %q, want CO", n.FC)
	}
	if !n.Operates() {
		t.Error("a write to Oper on a control constraint is not reported as an operate")
	}
	if n.Selects() {
		t.Error("an operate was reported as a select")
	}
	if !n.FC.Operates() {
		t.Error("the control constraint does not report that it reaches the plant")
	}
	if m.Values != 1 {
		t.Errorf("the write carried %d values, want 1", m.Values)
	}
}

// A select is not an operate, because a client that may reserve a breaker and not
// move it is a real and useful thing to configure.
func TestASelectIsNotAnOperate(t *testing.T) {
	m, err := ParsePDU(writeRequest(1,
		objectName("AA1J1Q01A1LD0", "XCBR1$CO$Pos$SBOw")))
	if err != nil {
		t.Fatal(err)
	}
	n := m.Names[0]
	if !n.Selects() {
		t.Error("SBOw is not reported as a select")
	}
	if n.Operates() {
		t.Error("SBOw is reported as an operate")
	}
}

// The setting groups, which are the class nothing else in this protocol
// distinguishes.
func TestASettingGroupWriteIsReportedAsProtection(t *testing.T) {
	m, err := ParsePDU(writeRequest(2,
		objectName("AA1J1Q01A1LD0", "PTOC1$SG$StrVal$setMag$f")))
	if err != nil {
		t.Fatal(err)
	}
	n := m.Names[0]
	if n.FC != FCSettingGroup {
		t.Fatalf("the constraint is %q", n.FC)
	}
	if !n.FC.Protects() {
		t.Error("a setting group write does not report that it changes protection")
	}
	if n.FC.Operates() {
		t.Error("a setting group write is reported as reaching the plant directly")
	}
}

// And the report control blocks, where a write changes what the control centre hears
// rather than what the plant does.
func TestAReportControlWriteIsReportedAsObservability(t *testing.T) {
	m, err := ParsePDU(writeRequest(3,
		objectName("AA1J1Q01A1LD0", "LLN0$BR$brcbST$RptEna")))
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Names[0].FC; !got.Observability() {
		t.Errorf("the constraint %q does not report that it changes observability", got)
	}
}

// A Read through a named variable list names no data objects, and the report has to
// say which: the list decides what is read.
func TestAReadThroughAListNamesTheListRatherThanTheObjects(t *testing.T) {
	b := ctx(uint32(ConfirmedRequest),
		integer(4),
		ctx(uint32(SvcRead), ctx(1, objectName("AA1J1Q01A1LD0", "LLN0$dsSet1"))))
	m, err := ParsePDU(b)
	if err != nil {
		t.Fatal(err)
	}
	if m.ListName != "AA1J1Q01A1LD0/LLN0$dsSet1" {
		t.Errorf("the list is %q", m.ListName)
	}
	if len(m.Names) != 0 {
		t.Errorf("a read through a list named %d objects", len(m.Names))
	}
}

// A GetNameList with a domain scope says which logical device is being enumerated,
// and one without says the client is asking for all of them.
func TestAGetNameListNamesItsScope(t *testing.T) {
	scoped := ctx(uint32(ConfirmedRequest), integer(5),
		ctx(uint32(SvcGetNameList),
			ctx(0, integer(9)),
			ctx(1, ctxp(1, []byte("AA1J1Q01A1LD0")))))
	m, err := ParsePDU(scoped)
	if err != nil {
		t.Fatal(err)
	}
	if m.Domain != "AA1J1Q01A1LD0" {
		t.Errorf("the scope is %q", m.Domain)
	}

	all := ctx(uint32(ConfirmedRequest), integer(6),
		ctx(uint32(SvcGetNameList),
			ctx(0, integer(9)),
			ctx(1, ctxp(0, nil))))
	m, err = ParsePDU(all)
	if err != nil {
		t.Fatal(err)
	}
	if m.Domain != "" {
		t.Errorf("a device-wide enumeration named the domain %q", m.Domain)
	}
}

// A download names the domain it is replacing, which is the operation an operator
// most wants a refusal for.
func TestADownloadNamesItsDomain(t *testing.T) {
	b := ctx(uint32(ConfirmedRequest), integer(11),
		ctx(uint32(SvcInitiateDownloadSequence), visible("AA1J1Q01A1LD0")))
	m, err := ParsePDU(b)
	if err != nil {
		t.Fatal(err)
	}
	if m.Service != SvcInitiateDownloadSequence {
		t.Fatalf("the service is %s", m.Service)
	}
	if m.Service.Class() != ClassDomain || !m.Service.Changes() {
		t.Errorf("a download is class %s, changes %v", m.Service.Class(), m.Service.Changes())
	}
	if m.Domain != "AA1J1Q01A1LD0" {
		t.Errorf("the domain is %q", m.Domain)
	}
}

// A file name is joined into a path, because that is the form a pattern is written
// in and an operator reads.
func TestAFileNameIsJoinedIntoAPath(t *testing.T) {
	b := ctx(uint32(ConfirmedRequest), integer(12),
		ctx(uint32(SvcFileOpen),
			seq(univ(TagGeneralStr, []byte("COMTRADE")), univ(TagGeneralStr, []byte("rec001.cfg"))),
			integer(0)))
	m, err := ParsePDU(b)
	if err != nil {
		t.Fatal(err)
	}
	if m.FileName != "COMTRADE/rec001.cfg" {
		t.Errorf("the file is %q", m.FileName)
	}
}

// A name that is not in the IEC 61850 form is reported as unparsed rather than
// forced into segments: an IED's own well-known variables are not in that form, and
// inventing a constraint for them would be deciding about something that is not
// there.
func TestANameThatIsNotInTheSubstationFormIsSaidToBeUnparsed(t *testing.T) {
	for _, item := range []string{"LastApplError", "SomeThing$XX$Value"} {
		n := ParseItem(item)
		if n.Parsed {
			t.Errorf("%q was parsed as a data object: %q/%q", item, n.LogicalNode, n.FC)
		}
		if n.Item != item {
			t.Errorf("the item is %q, want %q", n.Item, item)
		}
	}
}

// The other two arms of the name choice. A vmd-specific name is a device's own
// well-known variable and an aa-specific one is a client's own list, and neither has
// a domain -- so a rule about a logical device must not match them.
func TestAVMDSpecificNameHasNoDomain(t *testing.T) {
	m, err := ParsePDU(readRequest(1, vmdName("LastApplError")))
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Names) != 1 {
		t.Fatalf("the read named %d objects", len(m.Names))
	}
	n := m.Names[0]
	if n.Kind != NameVMD {
		t.Errorf("the kind is %s, want vmd", n.Kind)
	}
	if n.Domain != "" {
		t.Errorf("a device-scoped name carries the domain %q", n.Domain)
	}
	if got := n.Key(); got != "LastApplError" {
		t.Errorf("the key is %q", got)
	}
}

// An identifier longer than the bound comes back empty, not truncated: a truncated
// name is a different name, and a policy matching a different name is worse than one
// that cannot match.
func TestAnOverlongIdentifierIsEmptyRatherThanTruncated(t *testing.T) {
	long := strings.Repeat("A", MaxIdentifier+1)
	e := Element{Class: ClassUniversal, Tag: TagVisibleStr, Data: []byte(long)}
	if got := identifier(e); got != "" {
		t.Errorf("the identifier is %d octets, want none", len(got))
	}
}

// More names than the bound holds is reported, not silently cut: a policy that
// allowed the request on the names it could see would be allowing the ones it could
// not.
func TestMoreNamesThanTheBoundHoldsIsReported(t *testing.T) {
	names := make([][]byte, 0, MaxNames+4)
	for range MaxNames + 4 {
		names = append(names, objectName("LD0", "X1$ST$V$stVal"))
	}
	m, err := ParsePDU(readRequest(1, names...))
	if err != nil {
		t.Fatal(err)
	}
	if !m.NamesTruncated {
		t.Error("a request past the bound did not say so")
	}
	if len(m.Names) > MaxNames {
		t.Errorf("the reader kept %d names, past the bound of %d", len(m.Names), MaxNames)
	}
}

// Every service this build names round-trips through its configuration name, because
// a validator reads them back and a name that did not would be a rule nobody can
// write.
func TestEveryServiceRoundTripsThroughItsName(t *testing.T) {
	for _, name := range ServiceNames() {
		s, ok := ServiceOf(name)
		if !ok {
			t.Errorf("%q does not read back", name)
			continue
		}
		if s.String() != name {
			t.Errorf("%q read back as %q", name, s.String())
		}
		if !s.Known() {
			t.Errorf("%q is not known", name)
		}
		if s.Class() == ClassUnknown {
			t.Errorf("%q has no class", name)
		}
	}
}

// A service this build does not name says which number it was, because the refusal
// has to name it.
func TestAnUnnamedServiceSaysWhichNumberItWas(t *testing.T) {
	s := Service(200)
	if s.Known() {
		t.Fatal("service 200 is claimed as known")
	}
	if got := s.String(); got != "service(200)" {
		t.Errorf("the name is %q", got)
	}
	if s.Class() != ClassUnknown {
		t.Errorf("an unnamed service has class %s", s.Class())
	}
}

// sprintAll renders every field of an association, for the test that asserts a
// secret is not among them.
func sprintAll(a *Associate) string {
	var b strings.Builder
	b.WriteString(a.Context.String())
	b.WriteString(a.CallingAPTitle.String())
	b.WriteString(a.CalledAPTitle.String())
	b.WriteString(a.Mechanism.String())
	b.WriteString(a.Auth.String())
	b.Write(a.UserInfo)
	return b.String()
}
