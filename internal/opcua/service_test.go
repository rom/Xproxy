package opcua

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }

// call frames a service call body: the TypeId, the request header, and whatever the
// service itself carries.
func call(svc Service, body *builder) []byte {
	w := build().numeric(0, uint32(svc)).requestHeader(0x100)
	w.bytes(body.b)
	return w.b
}

func TestAServiceCallNamesTheServiceAndTheSession(t *testing.T) {
	body := call(SvcRead, build().f64(0).u32(0).array(0))
	c, err := ParseCall(body, true)
	if err != nil {
		t.Fatal(err)
	}
	if c.Service != SvcRead {
		t.Errorf("service %s", c.Service)
	}
	if c.Header.AuthenticationToken.Key() != "ns=0;i=256" {
		t.Errorf("token %s", c.Header.AuthenticationToken)
	}
	if !c.Service.Known() || c.Service.Writes() {
		t.Errorf("a read is classified as %v/%v", c.Service.Known(), c.Service.Writes())
	}
	if _, err := ParseRead(c.Body); err != nil {
		t.Errorf("the body after the header is not a read: %v", err)
	}
}

func TestARequestHeaderIsReadInFull(t *testing.T) {
	w := build().numeric(0, uint32(SvcWrite)).
		numeric(0, 0x200).
		i64(ToFileTime(testTime())).
		u32(77).
		u32(2).
		str("audit-1234").
		u32(30000).
		emptyExt().
		array(0)
	c, err := ParseCall(w.b, true)
	if err != nil {
		t.Fatal(err)
	}
	h := c.Header
	if h.AuthenticationToken.Numeric != 0x200 {
		t.Errorf("token %s", h.AuthenticationToken)
	}
	if !h.Timestamp.Equal(testTime()) {
		t.Errorf("timestamp %v", h.Timestamp)
	}
	if h.RequestHandle != 77 {
		t.Errorf("handle %d", h.RequestHandle)
	}
	if h.ReturnDiagnostics != 2 {
		t.Errorf("diagnostics %d", h.ReturnDiagnostics)
	}
	if h.AuditEntryID != "audit-1234" {
		t.Errorf("audit entry %q", h.AuditEntryID)
	}
	if h.TimeoutHint != 30000 {
		t.Errorf("timeout hint %d", h.TimeoutHint)
	}
}

func TestAResponseHeaderCarriesTheServiceResultAndTheStringTable(t *testing.T) {
	w := build().numeric(0, uint32(SvcReadReply)).
		i64(ToFileTime(testTime())).
		u32(77).
		u32(StatusBadUserAccessDenied).
		noDiag().
		array(2).str("first").str("second").
		emptyExt()
	c, err := ParseCall(w.b, false)
	if err != nil {
		t.Fatal(err)
	}
	if c.Service != SvcReadReply {
		t.Errorf("service %s", c.Service)
	}
	if c.Response.ServiceResult != StatusBadUserAccessDenied {
		t.Errorf("result %#x", c.Response.ServiceResult)
	}
	if len(c.Response.StringTable) != 2 || c.Response.StringTable[1] != "second" {
		t.Errorf("string table %v", c.Response.StringTable)
	}
}

func TestAStringTablePastTheBoundIsRefused(t *testing.T) {
	w := build().numeric(0, uint32(SvcReadReply)).
		i64(0).u32(1).u32(0).noDiag().i32(MaxStringTable + 1)
	if _, err := ParseCall(w.b, false); !errors.Is(err, ErrTooLong) {
		t.Errorf("err %v, want ErrTooLong", err)
	}
}

func TestAServiceFaultIsRecognisedAsAResponse(t *testing.T) {
	// A fault replaces the response's own TypeId, so a reader that did not know it
	// would report an unknown service for every refusal a server makes.
	w := build().numeric(0, uint32(SvcFault)).
		i64(0).u32(5).u32(StatusBadServiceUnsupported).noDiag().array(0).emptyExt()
	c, err := ParseCall(w.b, false)
	if err != nil {
		t.Fatal(err)
	}
	if c.Service != SvcFault || !c.Service.Known() {
		t.Errorf("service %s known %v", c.Service, c.Service.Known())
	}
	if c.Service.Request() {
		t.Error("a fault is classified as a request")
	}
}

func TestAVendorServiceIsNotMistakenForOneInNamespaceZero(t *testing.T) {
	// A service is a numeric identifier in namespace zero. A vendor's own service
	// lives in its own namespace and must not be read as whatever number it
	// happens to share with a standard one.
	w := build().byte(byte(Numeric)).u16(5).u32(uint32(SvcWrite)).requestHeader(1)
	c, err := ParseCall(w.b, true)
	if err != nil {
		t.Fatal(err)
	}
	if c.Service != 0 || c.Service.Known() {
		t.Errorf("service %s known %v", c.Service, c.Service.Known())
	}
	if c.TypeID.Namespace != 5 {
		t.Errorf("type id %s", c.TypeID)
	}
	// And an unknown service is classified as writing and as control, because
	// what it does is unknown and the safe answer for a read-only listener is no.
	if !c.Service.Writes() || !c.Service.Control() {
		t.Error("an unknown service is classified as harmless")
	}
}

func TestAStringTypeIdIsNotReadAsAServiceNumber(t *testing.T) {
	w := build().byte(byte(String)).u16(0).str("MyService").requestHeader(1)
	c, err := ParseCall(w.b, true)
	if err != nil {
		t.Fatal(err)
	}
	if c.Service != 0 {
		t.Errorf("service %s", c.Service)
	}
}

func TestTheServicesClassifyByWhatTheyDo(t *testing.T) {
	for _, tc := range []struct {
		s                        Service
		request, writes, control bool
	}{
		{SvcRead, true, false, false},
		{SvcBrowse, true, false, false},
		{SvcBrowseNext, true, false, false},
		{SvcGetEndpoints, true, false, false},
		{SvcWrite, true, true, false},
		{SvcCall, true, true, true},
		{SvcAddNodes, true, true, true},
		{SvcDeleteNodes, true, true, true},
		{SvcHistoryUpdate, true, true, true},
		{SvcHistoryRead, true, false, false},
		{SvcTransferSubscriptions, true, true, true},
		{SvcCreateSubscription, true, false, false},
		{SvcCreateMonitored, true, false, false},
		{SvcPublish, true, false, false},
		{SvcReadReply, false, false, false},
		{SvcWriteReply, false, false, false},
		{SvcFault, false, false, false},
	} {
		if got := tc.s.Request(); got != tc.request {
			t.Errorf("%s Request %v, want %v", tc.s, got, tc.request)
		}
		if got := tc.s.Writes(); got != tc.writes {
			t.Errorf("%s Writes %v, want %v", tc.s, got, tc.writes)
		}
		if got := tc.s.Control(); got != tc.control {
			t.Errorf("%s Control %v, want %v", tc.s, got, tc.control)
		}
	}
	// Control implies Writes for every service in the table: something that can
	// make the plant act is something that changes it, and a rule that allowed
	// writes but not control has to be able to rely on that.
	for s := range services {
		if s.Control() && !s.Writes() {
			t.Errorf("%s is control and not a write", s)
		}
	}
	// Writes and State are exclusive, and that is the distinction read_only rests
	// on: a service that changes the plant is a write, and one that changes the
	// server's own bookkeeping for this session is not. An HMI gets its values by
	// subscribing, so a read-only listener that refused every state change would
	// be a listener no HMI can use.
	for s := range services {
		if s.Writes() && s.State() {
			t.Errorf("%s is classified as both a write and a state change", s)
		}
	}
	for _, s := range []Service{
		SvcCreateSubscription, SvcModifySubscription, SvcSetPublishingMode,
		SvcDeleteSubscriptions, SvcCreateMonitored, SvcModifyMonitored,
		SvcSetMonitoringMode, SvcSetTriggering, SvcDeleteMonitored,
	} {
		if !s.State() {
			t.Errorf("%s is not classified as a session-state change", s)
		}
	}
	// And taking over another client's subscription is a write, not bookkeeping:
	// on a plant, taking over the stream an operator's screen is drawing from is
	// a change to what that operator sees.
	if !SvcTransferSubscriptions.Writes() || SvcTransferSubscriptions.State() {
		t.Error("transfer_subscriptions is classified as session bookkeeping")
	}
	// An unknown service is a write and not a state change: Writes() is what a
	// refusal is made on and must fail safe, State() is what a narrowing is made
	// on and must not silently grant anything.
	if got := Service(9999); !got.Writes() || got.State() {
		t.Errorf("an unknown service: Writes %v State %v", got.Writes(), got.State())
	}
	// Every response is classified as neither, because a response is the server's
	// answer and a rule about it is about its contents, not its effect.
	for s, i := range services {
		if !i.request && (i.writes || i.control) {
			t.Errorf("the response %s is classified as writing", s)
		}
	}
}

func TestAnUnknownServiceIsTreatedAsTheDangerousCase(t *testing.T) {
	for _, s := range []Service{0, 1, 9999, 12345} {
		if s.Known() {
			t.Errorf("%d is reported as known", uint32(s))
		}
		if !s.Writes() || !s.Control() {
			t.Errorf("%d: Writes %v Control %v, want both true", uint32(s), s.Writes(), s.Control())
		}
		if got := s.String(); !strings.HasPrefix(got, "service(") {
			t.Errorf("String %q", got)
		}
	}
}

func TestServiceOfReadsEveryServiceBackByName(t *testing.T) {
	// The table and its reverse have to agree, because a rule is written with a
	// name and matched against a number.
	for s, i := range services {
		got, ok := ServiceOf(i.name)
		if !ok || got != s {
			t.Errorf("ServiceOf(%q) = %s, %v; want %s", i.name, got, ok, s)
		}
		if got, ok := ServiceOf(strings.ToUpper(i.name)); !ok || got != s {
			t.Errorf("ServiceOf is case sensitive for %q", i.name)
		}
	}
	if _, ok := ServiceOf("teleport"); ok {
		t.Error("ServiceOf accepted a service that does not exist")
	}
}

func TestNoTwoServicesShareANumberOrAName(t *testing.T) {
	// A collision would silently make one of the two unreachable from a
	// configuration file, and the reverse table would decide which.
	if len(byName) != len(services) {
		t.Errorf("%d services and %d names", len(services), len(byName))
	}
	// Every request's paired response is a distinct entry three higher, which is
	// how the standard numbers them; a typo shows up as a missing pair.
	for s, i := range services {
		if !i.request || s == SvcFault {
			continue
		}
		if _, ok := services[s+3]; !ok {
			t.Errorf("%s has no response at %d", s, uint32(s)+3)
		}
	}
}

func TestAReadNamesTheNodesAndTheAttributes(t *testing.T) {
	body := build().f64(500).u32(2).array(2).
		numeric(3, 1001).u32(uint32(AttrValue)).null().u16(0).null().
		numeric(3, 1002).u32(uint32(AttrAccessLevel)).str("0:3").u16(0).null()
	q, err := ParseRead(body.b)
	if err != nil {
		t.Fatal(err)
	}
	if q.MaxAge != 500 || q.Timestamps != 2 {
		t.Errorf("%+v", q)
	}
	if len(q.Nodes) != 2 {
		t.Fatalf("%d nodes", len(q.Nodes))
	}
	if q.Nodes[0].Node.Key() != "ns=3;i=1001" || q.Nodes[0].Attr != AttrValue {
		t.Errorf("first %+v", q.Nodes[0])
	}
	if q.Nodes[1].Attr != AttrAccessLevel || q.Nodes[1].Range != "0:3" {
		t.Errorf("second %+v", q.Nodes[1])
	}
}

func TestAWriteNamesTheNodeTheAttributeAndTheValue(t *testing.T) {
	body := build().array(2).
		numeric(4, 20).u32(uint32(AttrValue)).null().
		byte(dvValue).byte(byte(TypeDouble)).f64(72.5).
		numeric(4, 21).u32(uint32(AttrAccessLevel)).null().
		byte(dvValue).byte(byte(TypeByte)).byte(3)
	w, err := ParseWrite(body.b)
	if err != nil {
		t.Fatal(err)
	}
	if len(w.Values) != 2 {
		t.Fatalf("%d values", len(w.Values))
	}
	if w.Values[0].Node.Key() != "ns=4;i=20" || w.Values[0].Value.Value.Num != 72.5 {
		t.Errorf("first %+v", w.Values[0])
	}
	// The second is the case a policy has to separate: a write to a permission
	// attribute is a privilege change however ordinary the node looks.
	if !w.Values[1].Attr.Permission() {
		t.Error("a write to the access level is not classified as a permission change")
	}
	if w.Values[0].Attr.Permission() {
		t.Error("a write to the value is classified as a permission change")
	}
}

func TestTheAttributesAreNamedAndTheGoverningOnesSeparated(t *testing.T) {
	for _, tc := range []struct {
		a                 Attribute
		name              string
		known, permission bool
	}{
		{AttrValue, "value", true, false},
		{AttrNodeID, "node_id", true, false},
		{AttrBrowseName, "browse_name", true, false},
		{AttrWriteMask, "write_mask", true, true},
		{AttrUserWriteMask, "user_write_mask", true, true},
		{AttrAccessLevel, "access_level", true, true},
		{AttrUserAccessLevel, "user_access_level", true, true},
		{AttrExecutable, "executable", true, true},
		{AttrUserExecutable, "user_executable", true, true},
		{AttrHistorizing, "historizing", true, true},
		{Attribute(99), "attribute(99)", false, false},
	} {
		if got := tc.a.String(); got != tc.name {
			t.Errorf("%d: String %q, want %q", uint32(tc.a), got, tc.name)
		}
		if got := tc.a.Known(); got != tc.known {
			t.Errorf("%s Known %v, want %v", tc.name, got, tc.known)
		}
		if got := tc.a.Permission(); got != tc.permission {
			t.Errorf("%s Permission %v, want %v", tc.name, got, tc.permission)
		}
	}
	for a, n := range attributeNames {
		got, ok := AttributeOf(n)
		if !ok || got != a {
			t.Errorf("AttributeOf(%q) = %s, %v", n, got, ok)
		}
	}
	if _, ok := AttributeOf("colour"); ok {
		t.Error("AttributeOf accepted an attribute that does not exist")
	}
}

func TestACallNamesBothTheObjectAndTheMethod(t *testing.T) {
	// A method exists on a type and is called on an instance, so allowing Reset
	// on one pump is not allowing it on every pump of that model.
	body := build().array(1).
		numeric(4, 100).numeric(4, 200).
		array(2).byte(byte(TypeDouble)).f64(1.5).byte(byte(TypeString)).str("fast")
	c, err := ParseCallRequest(body.b)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Methods) != 1 {
		t.Fatalf("%d methods", len(c.Methods))
	}
	m := c.Methods[0]
	if m.Object.Key() != "ns=4;i=100" || m.Method.Key() != "ns=4;i=200" {
		t.Errorf("%+v", m)
	}
	if len(m.Arguments) != 2 || m.Arguments[0].Num != 1.5 || m.Arguments[1].Text != "fast" {
		t.Errorf("arguments %+v", m.Arguments)
	}
}

func TestTooManyMethodArgumentsAreRefused(t *testing.T) {
	body := build().array(1).numeric(0, 1).numeric(0, 2).i32(MaxArguments + 1)
	if _, err := ParseCallRequest(body.b); !errors.Is(err, ErrTooLong) {
		t.Errorf("err %v, want ErrTooLong", err)
	}
}

func TestABrowseNamesWhereItStartsAndHowFarItWillGo(t *testing.T) {
	body := build().
		nullNode().i64(0).u32(0).
		u32(0).
		array(1).
		numeric(0, 85).u32(uint32(BrowseBoth)).numeric(0, 33).bool(true).u32(0).u32(63)
	b, err := ParseBrowse(body.b)
	if err != nil {
		t.Fatal(err)
	}
	if !b.View.Zero() {
		t.Errorf("view %s", b.View)
	}
	if b.MaxReferences != 0 {
		t.Errorf("max references %d", b.MaxReferences)
	}
	if len(b.Nodes) != 1 {
		t.Fatalf("%d nodes", len(b.Nodes))
	}
	n := b.Nodes[0]
	if n.Node.Key() != "ns=0;i=85" || n.Direction != BrowseBoth || !n.Subtypes {
		t.Errorf("%+v", n)
	}
	if got := n.Direction.String(); got != "both" {
		t.Errorf("direction %q", got)
	}
	for d, want := range map[BrowseDirection]string{
		BrowseForward: "forward", BrowseInverse: "inverse",
		BrowseBoth: "both", BrowseInvalid: "direction(3)",
	} {
		if got := d.String(); got != want {
			t.Errorf("%d: %q, want %q", uint32(d), got, want)
		}
	}
}

func TestACreateSessionNamesTheApplicationAndItsCertificate(t *testing.T) {
	cert := bytes.Repeat([]byte{0x30}, 500)
	body := build().
		str("urn:scada:client").
		str("urn:vendor:product").
		localized("SCADA client").
		u32(1).
		null().
		null().
		array(0).
		null().
		str("opc.tcp://relay:4840").
		str("session-7").
		bstr(bytes.Repeat([]byte{9}, 32)).
		bstr(cert).
		f64(600000).
		u32(0)
	c, err := ParseCreateSession(body.b)
	if err != nil {
		t.Fatal(err)
	}
	if c.ApplicationURI != "urn:scada:client" {
		t.Errorf("application uri %q", c.ApplicationURI)
	}
	if c.ProductURI != "urn:vendor:product" {
		t.Errorf("product uri %q", c.ProductURI)
	}
	if c.ApplicationName != "SCADA client" {
		t.Errorf("application name %q", c.ApplicationName)
	}
	if c.ApplicationType != 1 {
		t.Errorf("application type %d", c.ApplicationType)
	}
	if c.EndpointURL != "opc.tcp://relay:4840" {
		t.Errorf("endpoint %q", c.EndpointURL)
	}
	if c.SessionName != "session-7" {
		t.Errorf("session name %q", c.SessionName)
	}
	if !bytes.Equal(c.Certificate, cert) {
		t.Error("the certificate is not the octets that arrived")
	}
	if c.Timeout != 600000 {
		t.Errorf("timeout %v", c.Timeout)
	}
}

func TestAnActivateSessionNamesTheUser(t *testing.T) {
	token := build().str("username_policy").str("operator").
		bstr([]byte("hunter2")).null()
	body := build().
		str("http://www.w3.org/2000/09/xmldsig#rsa-sha1").bstr([]byte{1, 2, 3}).
		array(0).
		array(1).str("en-GB").
		numeric(0, uint32(TokenUserName)).byte(extByteString).bstr(token.b)
	a, err := ParseActivateSession(body.b)
	if err != nil {
		t.Fatal(err)
	}
	if a.Kind != TokenUserName {
		t.Errorf("kind %s", a.Kind)
	}
	if a.User != "operator" {
		t.Errorf("user %q", a.User)
	}
	if a.PolicyID != "username_policy" {
		t.Errorf("policy %q", a.PolicyID)
	}
	if a.PasswordLen != len("hunter2") {
		t.Errorf("password length %d", a.PasswordLen)
	}
	// The password itself is not retained anywhere on the structure: a relay has
	// no use for it and one that held it would be worth stealing.
	if strings.Contains(string(mustJSON(t, a)), "hunter2") {
		t.Error("the password survived parsing")
	}
	if !a.PlaintextPassword() {
		t.Error("a password with no encryption algorithm is not reported as plaintext")
	}
	if len(a.Locales) != 1 || a.Locales[0] != "en-GB" {
		t.Errorf("locales %v", a.Locales)
	}
}

func TestAnEncryptedPasswordIsNotReportedAsPlaintext(t *testing.T) {
	token := build().str("p").str("operator").bstr([]byte{1, 2, 3}).
		str("http://www.w3.org/2001/04/xmlenc#rsa-oaep")
	body := build().null().null().array(0).array(0).
		numeric(0, uint32(TokenUserName)).byte(extByteString).bstr(token.b)
	a, err := ParseActivateSession(body.b)
	if err != nil {
		t.Fatal(err)
	}
	if a.PlaintextPassword() {
		t.Error("an encrypted password is reported as plaintext")
	}
	if a.PasswordAlgorithm == "" {
		t.Error("the algorithm was not read")
	}
}

func TestAnAnonymousTokenNamesNoUserAndIsNotPlaintext(t *testing.T) {
	token := build().str("anonymous_policy")
	body := build().null().null().array(0).array(0).
		numeric(0, uint32(TokenAnonymous)).byte(extByteString).bstr(token.b)
	a, err := ParseActivateSession(body.b)
	if err != nil {
		t.Fatal(err)
	}
	if a.Kind != TokenAnonymous || a.User != "" {
		t.Errorf("%+v", a)
	}
	if a.PlaintextPassword() {
		t.Error("an anonymous token is reported as carrying a plaintext password")
	}
}

func TestAnX509AndAnIssuedTokenAreRecognised(t *testing.T) {
	for _, tc := range []struct {
		kind  TokenKind
		token *builder
	}{
		{TokenX509, build().str("cert_policy").bstr([]byte{0x30, 0x82})},
		{TokenIssued, build().str("jwt_policy").bstr([]byte("ey.ey.sig")).null()},
	} {
		body := build().null().null().array(0).array(0).
			numeric(0, uint32(tc.kind)).byte(extByteString).bstr(tc.token.b)
		a, err := ParseActivateSession(body.b)
		if err != nil {
			t.Fatalf("%s: %v", tc.kind, err)
		}
		if a.Kind != tc.kind {
			t.Errorf("kind %s, want %s", a.Kind, tc.kind)
		}
		if a.PlaintextPassword() {
			t.Errorf("%s is reported as carrying a plaintext password", tc.kind)
		}
	}
}

func TestAMalformedIdentityTokenIsAnErrorRatherThanAnUnknownUser(t *testing.T) {
	// "The user is unknown" and "there is no user" must not look alike: one is a
	// policy decision and the other is a message nobody can decide about.
	token := build().i32(100) // a string length with no string
	body := build().null().null().array(0).array(0).
		numeric(0, uint32(TokenUserName)).byte(extByteString).bstr(token.b)
	if _, err := ParseActivateSession(body.b); !errors.Is(err, ErrShort) {
		t.Errorf("err %v, want ErrShort", err)
	}
}

func TestAnIdentityTokenKindIsNamedAndReadBack(t *testing.T) {
	for _, tc := range []struct {
		k    TokenKind
		name string
	}{
		{TokenAnonymous, "anonymous"},
		{TokenUserName, "username"},
		{TokenX509, "x509"},
		{TokenIssued, "issued"},
	} {
		if got := tc.k.String(); got != tc.name {
			t.Errorf("String %q, want %q", got, tc.name)
		}
		if !tc.k.Known() {
			t.Errorf("%s is not known", tc.name)
		}
		got, ok := TokenOf(tc.name)
		if !ok || got != tc.k {
			t.Errorf("TokenOf(%q) = %s, %v", tc.name, got, ok)
		}
	}
	if TokenKind(1).Known() {
		t.Error("a token kind nobody defined is reported as known")
	}
	if got := TokenKind(1).String(); got != "token(1)" {
		t.Errorf("String %q", got)
	}
	if _, ok := TokenOf("kerberos"); ok {
		t.Error("TokenOf accepted a kind that is not one of the four")
	}
}

func TestTooManyLocalesAreRefused(t *testing.T) {
	body := build().null().null().array(0).i32(MaxLocales + 1)
	if _, err := ParseActivateSession(body.b); !errors.Is(err, ErrTooLong) {
		t.Errorf("err %v, want ErrTooLong", err)
	}
}

func TestACreateSubscriptionNamesTheRateTheServerWillBeAskedToSustain(t *testing.T) {
	body := build().f64(1).u32(1200).u32(20).u32(0).bool(true).byte(255)
	s, err := ParseSubscription(body.b)
	if err != nil {
		t.Fatal(err)
	}
	if s.Interval != 1 {
		t.Errorf("interval %v", s.Interval)
	}
	if s.Lifetime != 1200 || s.KeepAlive != 20 {
		t.Errorf("%+v", s)
	}
	if s.MaxNotifications != 0 {
		t.Errorf("max notifications %d", s.MaxNotifications)
	}
	if !s.Enabled || s.Priority != 255 {
		t.Errorf("%+v", s)
	}
}

func TestCreateMonitoredItemsNamesTheFanOut(t *testing.T) {
	body := build().u32(7).u32(2).array(2).
		numeric(3, 1).u32(uint32(AttrValue)).null().u16(0).null().
		u32(2).u32(1).f64(-1).nullNode().byte(extNone).u32(10).bool(true).
		numeric(3, 2).u32(uint32(AttrValue)).null().u16(0).null().
		u32(2).u32(2).f64(0).numeric(0, 583).byte(extByteString).bstr([]byte{1}).u32(1).bool(false)
	m, err := ParseMonitoredItems(body.b)
	if err != nil {
		t.Fatal(err)
	}
	if m.Subscription != 7 {
		t.Errorf("subscription %d", m.Subscription)
	}
	if len(m.Items) != 2 {
		t.Fatalf("%d items", len(m.Items))
	}
	if m.Items[0].Item.Node.Key() != "ns=3;i=1" || m.Items[0].Sampling != -1 {
		t.Errorf("first %+v", m.Items[0])
	}
	if m.Items[0].Queue != 10 || !m.Items[0].DiscardOldest {
		t.Errorf("first queue %+v", m.Items[0])
	}
	// The second carries a filter, whose type identifier is what says which kind
	// of filter a server was asked for.
	if m.Items[1].Filter.Key() != "ns=0;i=583" {
		t.Errorf("filter %s", m.Items[1].Filter)
	}
	if m.Items[1].Sampling != 0 {
		t.Errorf("second sampling %v", m.Items[1].Sampling)
	}
}

func TestEveryServiceBodyRefusesATruncatedMessage(t *testing.T) {
	// One test per parser would be five tests that say the same thing; the
	// property is that no parser returns a half-filled structure.
	for name, parse := range map[string]func([]byte) error{
		"read":            func(b []byte) error { _, err := ParseRead(b); return err },
		"write":           func(b []byte) error { _, err := ParseWrite(b); return err },
		"call":            func(b []byte) error { _, err := ParseCallRequest(b); return err },
		"browse":          func(b []byte) error { _, err := ParseBrowse(b); return err },
		"open channel":    func(b []byte) error { _, err := ParseOpenChannel(b); return err },
		"create session":  func(b []byte) error { _, err := ParseCreateSession(b); return err },
		"activate":        func(b []byte) error { _, err := ParseActivateSession(b); return err },
		"subscription":    func(b []byte) error { _, err := ParseSubscription(b); return err },
		"monitored items": func(b []byte) error { _, err := ParseMonitoredItems(b); return err },
		"call head":       func(b []byte) error { _, err := ParseCall(b, true); return err },
		"hello":           func(b []byte) error { _, err := ParseHello(b); return err },
		"error":           func(b []byte) error { _, err := ParseError(b); return err },
	} {
		if err := parse(nil); err == nil {
			t.Errorf("%s: an empty body was accepted", name)
		}
		if err := parse([]byte{0x01}); err == nil {
			t.Errorf("%s: a one-octet body was accepted", name)
		}
	}
}

// mustJSON renders a value so a test can assert a secret is not in it. It is a
// crude check and a deliberate one: it catches a field added later that carries the
// password along with everything else.
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := jsonMarshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
