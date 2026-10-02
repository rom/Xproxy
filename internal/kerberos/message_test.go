package kerberos

import (
	"errors"
	"testing"
	"time"
)

func TestAnASRequestIsReadDownToWhatAPolicyDecidesOn(t *testing.T) {
	t.Parallel()
	cname, sname := user("alice"), Principal{Type: NTSrvInst, Parts: []string{"krbtgt", "CORP.EXAMPLE"}}
	till := time.Date(2026, 10, 2, 22, 0, 0, 0, time.UTC)
	b := req{
		typ: MsgASReq, realm: "CORP.EXAMPLE", cname: &cname, sname: &sname,
		opts:   OptForwardable | OptRenewableOK,
		etypes: []EType{ETypeAES256SHA1, ETypeAES128SHA1, ETypeRC4HMAC},
		padata: []pa{{typ: PAEncTimestamp, value: []byte{9, 9}}, {typ: PAPACRequest, value: []byte{0x30, 0x00}}},
		till:   till, nonce: 12345,
	}.build()
	m, err := Parse(b)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if m.Type != MsgASReq || m.PVNO != 5 {
		t.Fatalf("message = %+v", m)
	}
	if m.Realm != "CORP.EXAMPLE" {
		t.Errorf("realm = %q", m.Realm)
	}
	if !m.HasClient || m.Client.String() != "alice" {
		t.Errorf("cname = %q", m.Client)
	}
	if !m.HasServer || m.Server.String() != "krbtgt/CORP.EXAMPLE" || !m.Server.IsKrbtgt() {
		t.Errorf("sname = %q", m.Server)
	}
	if !m.Options.Has(OptForwardable) || !m.Options.Has(OptRenewableOK) {
		t.Errorf("options = %v", m.Options)
	}
	if m.Options.Has(OptConstrainedDelegation) {
		t.Error("a bit nobody set is set")
	}
	if len(m.ETypes) != 3 || m.ETypes[0] != ETypeAES256SHA1 || m.ETypes[2] != ETypeRC4HMAC {
		t.Errorf("etypes = %v", m.ETypes)
	}
	if !m.Preauthenticated() {
		t.Error("an encrypted timestamp was not read as pre-authentication")
	}
	if !m.HasPAData(PAPACRequest) {
		t.Error("the PAC request was not recorded")
	}
	if m.Nonce != 12345 {
		t.Errorf("nonce = %d", m.Nonce)
	}
	if !m.HasTill || !m.Till.Equal(till) {
		t.Errorf("till = %v", m.Till)
	}
	if s := m.Summary(); s == "" {
		t.Error("Summary rendered nothing")
	}
}

func TestATagAndAMsgTypeThatDisagreeAreRefused(t *testing.T) {
	t.Parallel()
	// Two fields say the same thing, and a reader that believed only one
	// would be deciding about a message the KDC reads as another type.
	cname := user("alice")
	b := req{typ: MsgASReq, realm: "R", cname: &cname, etypes: []EType{ETypeAES256SHA1}}.build()
	// Rewrite the msg-type field's value, which the builder put at a known
	// place: it is the second context element of the outer sequence.
	for i := 0; i+2 < len(b); i++ {
		if b[i] == 0xa2 && b[i+1] == 0x03 && b[i+2] == 0x02 {
			b[i+4] = byte(MsgTGSReq)
			break
		}
	}
	if _, err := Parse(b); !errors.Is(err, ErrTypeMismatch) {
		t.Fatalf("err = %v, want ErrTypeMismatch", err)
	}
}

func TestARequestMustCarryARealmAndAnEncryptionType(t *testing.T) {
	t.Parallel()
	cname := user("alice")
	t.Run("no realm", func(t *testing.T) {
		t.Parallel()
		b := req{typ: MsgASReq, realm: "", cname: &cname, etypes: []EType{ETypeAES256SHA1}}.build()
		// An empty realm string is present but empty, which is the case a
		// policy keyed on realms must not read as "any realm".
		if _, err := Parse(b); !errors.Is(err, ErrNoRealm) {
			t.Fatalf("err = %v, want ErrNoRealm", err)
		}
	})
	t.Run("no encryption type", func(t *testing.T) {
		t.Parallel()
		// "No weak type was asked for" is true of an empty list, which is
		// why an empty list is refused rather than read.
		b := req{typ: MsgASReq, realm: "CORP", cname: &cname}.build()
		if _, err := Parse(b); !errors.Is(err, ErrNoETypes) {
			t.Fatalf("err = %v, want ErrNoETypes", err)
		}
	})
	t.Run("a protocol version that is not 5", func(t *testing.T) {
		t.Parallel()
		b := req{typ: MsgASReq, realm: "CORP", cname: &cname,
			etypes: []EType{ETypeAES256SHA1}, pvno: 4}.build()
		if _, err := Parse(b); !errors.Is(err, ErrPVNO) {
			t.Fatalf("err = %v, want ErrPVNO", err)
		}
	})
}

func TestOnlyWeakIsStrongerThanMentioningAWeakType(t *testing.T) {
	t.Parallel()
	cname, sname := user("svc"), svc("MSSQLSvc", "db.corp.example:1433")
	mixed := req{typ: MsgTGSReq, realm: "CORP", cname: &cname, sname: &sname,
		etypes: []EType{ETypeAES256SHA1, ETypeRC4HMAC}}.build()
	only := req{typ: MsgTGSReq, realm: "CORP", cname: &cname, sname: &sname,
		etypes: []EType{ETypeRC4HMAC}}.build()
	m, err := Parse(mixed)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	// A Windows client lists aes256 then rc4 and the KDC picks the first it
	// can, so merely listing RC4 is ordinary traffic.
	if m.OnlyWeakETypes() {
		t.Error("a mixed list reported as only-weak")
	}
	if len(m.WeakETypes()) != 1 || m.WeakETypes()[0] != ETypeRC4HMAC {
		t.Errorf("weak types = %v", m.WeakETypes())
	}
	m, err = Parse(only)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !m.OnlyWeakETypes() {
		t.Error("a list with nothing but RC4 in it was not reported as only-weak")
	}
	if m.Server.Service() != "MSSQLSvc" {
		t.Errorf("service class = %q", m.Server.Service())
	}
}

func TestS4UIsRecognisedInBothOfItsForms(t *testing.T) {
	t.Parallel()
	svcName := user("websvc")
	target := svc("cifs", "fileserver.corp.example")
	t.Run("S4U2Self names the impersonated user", func(t *testing.T) {
		t.Parallel()
		b := req{
			typ: MsgTGSReq, realm: "CORP.EXAMPLE", cname: &svcName, sname: &svcName,
			etypes: []EType{ETypeAES256SHA1},
			padata: []pa{
				{typ: PATGSReq, value: []byte{1}},
				{typ: PAForUser, value: forUserValue(user("administrator"), "CORP.EXAMPLE")},
			},
		}.build()
		m, err := Parse(b)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if !m.S4U2Self() {
			t.Fatal("PA-FOR-USER was not read as S4U2Self")
		}
		if !m.HasForUser || m.ForUser.String() != "administrator" {
			t.Fatalf("for-user = %q (has = %v)", m.ForUser, m.HasForUser)
		}
		if m.S4U2Proxy() {
			t.Error("S4U2Self was also read as S4U2Proxy")
		}
	})
	t.Run("S4U2Proxy needs both the option and a ticket", func(t *testing.T) {
		t.Parallel()
		// The option alone is a client setting a reserved bit, and an
		// additional ticket alone is a user-to-user request. It is the
		// pair that is a delegation.
		both := req{typ: MsgTGSReq, realm: "CORP.EXAMPLE", cname: &svcName, sname: &target,
			opts: OptConstrainedDelegation, etypes: []EType{ETypeAES256SHA1}, addTkts: 1}.build()
		m, err := Parse(both)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if !m.S4U2Proxy() {
			t.Fatal("the option and a ticket were not read as S4U2Proxy")
		}
		if m.AdditionalTickets != 1 {
			t.Errorf("additional tickets = %d", m.AdditionalTickets)
		}
		optOnly := req{typ: MsgTGSReq, realm: "CORP.EXAMPLE", cname: &svcName, sname: &target,
			opts: OptConstrainedDelegation, etypes: []EType{ETypeAES256SHA1}}.build()
		m, err = Parse(optOnly)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if m.S4U2Proxy() {
			t.Error("the option alone was read as S4U2Proxy")
		}
		tktOnly := req{typ: MsgTGSReq, realm: "CORP.EXAMPLE", cname: &svcName, sname: &target,
			etypes: []EType{ETypeAES256SHA1}, addTkts: 2}.build()
		m, err = Parse(tktOnly)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if m.S4U2Proxy() {
			t.Error("additional tickets alone were read as S4U2Proxy")
		}
		if m.AdditionalTickets != 2 {
			t.Errorf("additional tickets = %d, want 2", m.AdditionalTickets)
		}
	})
}

func TestAReplySaysWhichEncryptionTypeTheKDCActuallyUsed(t *testing.T) {
	t.Parallel()
	// The request's list is what the client will accept; the ticket's
	// enc-part type is what left. On a Kerberoast those differ, and the
	// second is the one that matters.
	b := rep{
		typ: MsgASRep, realm: "CORP.EXAMPLE", cname: user("alice"),
		sname: svc("MSSQLSvc", "db.corp.example"),
		// The ticket is encrypted in the service account's key, the
		// enc-part in the client's.
		ticketEType: ETypeRC4HMAC, encEType: ETypeAES256SHA1,
	}.build()
	m, err := Parse(b)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !m.HasTicketEType || m.TicketEType != ETypeRC4HMAC {
		t.Fatalf("ticket etype = %v (has = %v)", m.TicketEType, m.HasTicketEType)
	}
	if !m.HasEncPartEType || m.EncPartEType != ETypeAES256SHA1 {
		t.Fatalf("enc-part etype = %v", m.EncPartEType)
	}
	if !m.TicketEType.Weak() {
		t.Error("rc4-hmac is not reported as weak")
	}
	if m.EncPartEType.Weak() {
		t.Error("aes256 is reported as weak")
	}
	if !m.HasServer || m.Server.String() != "MSSQLSvc/db.corp.example" {
		t.Errorf("sname from the ticket = %q", m.Server)
	}
	if m.Realm != "CORP.EXAMPLE" {
		t.Errorf("crealm = %q", m.Realm)
	}
	// A reply that echoes no pre-authentication is the shape an
	// unprotected AS exchange has.
	if m.Preauthenticated() {
		t.Error("a reply with no padata reported pre-authentication")
	}
}

func TestAKRBErrorIsReadForItsCodeAndText(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 2, 9, 30, 0, 0, time.UTC)
	b := MarshalError(now, KDCErrPreauthRequired, "CORP.EXAMPLE",
		KrbtgtFor("CORP.EXAMPLE"), ErrorText("kdc", "etype_not_allowed"))
	m, err := Parse(b)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if m.Type != MsgError {
		t.Fatalf("type = %v", m.Type)
	}
	if m.ErrorCode != KDCErrPreauthRequired {
		t.Errorf("code = %d", m.ErrorCode)
	}
	if ErrorName(m.ErrorCode) != "preauth-required" {
		t.Errorf("name = %q", ErrorName(m.ErrorCode))
	}
	if m.Realm != "CORP.EXAMPLE" {
		t.Errorf("realm = %q", m.Realm)
	}
	if !m.HasServer || m.Server.String() != "krbtgt/CORP.EXAMPLE" {
		t.Errorf("sname = %q", m.Server)
	}
	if m.ErrorText == "" || m.Summary() == "" {
		t.Errorf("text = %q", m.ErrorText)
	}
	// A code nothing names still renders.
	if got := ErrorName(199); got != "krb-err(199)" {
		t.Errorf("ErrorName(199) = %q", got)
	}
}

func TestAnAPRequestIsReadAsFarAsItsTicket(t *testing.T) {
	t.Parallel()
	// This is what a password change looks like: there is no realm field
	// in an AP-REQ, so the ticket's realm is the only one the message has.
	b := apReq("CORP.EXAMPLE", Principal{Type: NTSrvInst, Parts: []string{"kadmin", "changepw"}})
	m, err := Parse(b)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if m.Type != MsgAPReq {
		t.Fatalf("type = %v", m.Type)
	}
	if m.Realm != "CORP.EXAMPLE" {
		t.Errorf("realm = %q", m.Realm)
	}
	if !m.HasServer || m.Server.String() != "kadmin/changepw" {
		t.Errorf("sname = %q", m.Server)
	}
	if !m.Type.Request() {
		t.Error("an AP-REQ is not reported as a request")
	}
}

func TestAMessageTypeAProxyDoesNotCarryIsRefused(t *testing.T) {
	t.Parallel()
	// [APPLICATION 20] is KRB-SAFE: a legitimate Kerberos message that
	// does not go to a KDC, so a proxy seeing one is carrying something
	// that is not its business.
	b := derTLV(classApplication|constructed, 20,
		derTLV(classUniversal|constructed, tagSequence, ctxInt(0, 5)))
	if _, err := Parse(b); !errors.Is(err, ErrUnknownType) {
		t.Fatalf("err = %v, want ErrUnknownType", err)
	}
	// And something that is not application-tagged at all.
	if _, err := Parse(derTLV(classUniversal|constructed, tagSequence, nil)); !errors.Is(err, ErrNotMessage) {
		t.Fatal("a bare SEQUENCE was accepted as a message")
	}
	// Octets after the outermost element are refused: they are a second
	// message this reader would not have seen and the KDC would.
	cname := user("a")
	good := req{typ: MsgASReq, realm: "R", cname: &cname, etypes: []EType{ETypeAES256SHA1}}.build()
	if _, err := Parse(append(good, 0x30, 0x00)); !errors.Is(err, ErrTrailing) {
		t.Fatal("trailing octets were accepted")
	}
}

func TestTheDERReaderRefusesWhatIsNotDER(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{
			"an indefinite length",
			[]byte{0x6a, 0x80, 0x30, 0x00, 0x00, 0x00},
			ErrIndefinite,
		},
		{
			// 0x81 0x05 is five octets written the long way; DER requires
			// the short form below 128. Accepting it would be accepting
			// two encodings of one length.
			"a non-minimal length",
			[]byte{0x6a, 0x81, 0x05, 0x30, 0x03, 0x02, 0x01, 0x05},
			ErrNonMinimal,
		},
		{
			"an element that ends past its buffer",
			[]byte{0x6a, 0x10, 0x30, 0x02},
			ErrShort,
		},
		{
			"the high-tag-number form",
			[]byte{0x7f, 0x81, 0x02, 0x00},
			ErrTag,
		},
		{
			"a length field wider than four octets",
			[]byte{0x6a, 0x85, 1, 1, 1, 1, 1},
			ErrShort,
		},
	}
	for _, c := range cases {
		if _, err := Parse(c.in); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
}

func TestANonMinimalIntegerIsRefused(t *testing.T) {
	t.Parallel()
	// A leading zero octet that adds no information is a second spelling
	// of a number a rule is written about.
	e := element{class: classUniversal, tag: tagInteger, data: []byte{0x00, 0x05}}
	if _, err := derInteger(e); !errors.Is(err, ErrNonMinimal) {
		t.Fatalf("err = %v, want ErrNonMinimal", err)
	}
	if _, err := derInteger(element{class: classUniversal, tag: tagInteger,
		data: []byte{1, 2, 3, 4, 5, 6}}); !errors.Is(err, ErrInteger) {
		t.Fatal("a six-octet integer was accepted")
	}
	if _, err := derInteger(element{class: classUniversal, tag: tagInteger}); !errors.Is(err, ErrInteger) {
		t.Fatal("an empty integer was accepted")
	}
	// A negative number is legitimate: Microsoft's own encryption types
	// are negative.
	v, err := derInteger(element{class: classUniversal, tag: tagInteger, data: []byte{0x80}})
	if err != nil || v != -128 {
		t.Fatalf("derInteger(0x80) = (%d, %v), want (-128, nil)", v, err)
	}
}

func TestAStringWithAControlCharacterIsRefused(t *testing.T) {
	t.Parallel()
	// A realm with a newline in it is a second line in a log file, and one
	// with an escape sequence is a terminal doing as it is told when
	// somebody reads the record back.
	cname := user("a")
	for _, bad := range []string{"CORP\nEXAMPLE", "CORP\x1b[2J"} {
		b := req{typ: MsgASReq, realm: bad, cname: &cname, etypes: []EType{ETypeAES256SHA1}}.build()
		if _, err := Parse(b); !errors.Is(err, ErrText) {
			t.Errorf("realm %q: err = %v, want ErrText", bad, err)
		}
	}
}

func TestADeepNestingIsRefusedRatherThanFollowed(t *testing.T) {
	t.Parallel()
	// A few dozen octets of nesting must not become a recursion as deep as
	// the reader will follow.
	b := []byte{0x02, 0x01, 0x05}
	for i := 0; i < maxDepth+4; i++ {
		b = derTLV(classContext|constructed, 0, b)
	}
	b = derTLV(classApplication|constructed, uint32(MsgASReq),
		derTLV(classUniversal|constructed, tagSequence, b))
	if _, err := Parse(b); err == nil {
		t.Fatal("a deeply nested message was accepted")
	}
}

func TestALifetimeIsReadFromTillAndFrom(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	cname := user("alice")
	t.Run("till alone measures from now", func(t *testing.T) {
		t.Parallel()
		b := req{typ: MsgASReq, realm: "R", cname: &cname, etypes: []EType{ETypeAES256SHA1},
			till: now.Add(10 * time.Hour)}.build()
		m, err := Parse(b)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		d, ok := m.Lifetime(now)
		if !ok || d != 10*time.Hour {
			t.Fatalf("lifetime = (%v, %v)", d, ok)
		}
	})
	t.Run("a postdated request measures from its own start", func(t *testing.T) {
		t.Parallel()
		b := req{typ: MsgASReq, realm: "R", cname: &cname, etypes: []EType{ETypeAES256SHA1},
			hasFrom: true, from: now.Add(time.Hour), till: now.Add(3 * time.Hour)}.build()
		m, err := Parse(b)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		d, ok := m.Lifetime(now)
		if !ok || d != 2*time.Hour {
			t.Fatalf("lifetime = (%v, %v), want 2h", d, ok)
		}
	})
	t.Run("a till in the past has no lifetime", func(t *testing.T) {
		t.Parallel()
		b := req{typ: MsgASReq, realm: "R", cname: &cname, etypes: []EType{ETypeAES256SHA1},
			till: now.Add(-time.Hour)}.build()
		m, err := Parse(b)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if _, ok := m.Lifetime(now); ok {
			t.Error("a till in the past produced a lifetime")
		}
	})
	t.Run("no till at all has no lifetime", func(t *testing.T) {
		t.Parallel()
		b := req{typ: MsgASReq, realm: "R", cname: &cname, etypes: []EType{ETypeAES256SHA1},
			omitTill: true}.build()
		m, err := Parse(b)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if _, ok := m.Lifetime(now); ok {
			t.Error("a request with no till produced a lifetime")
		}
	})
}

func TestTheNamesARuleIsWrittenWithRoundTrip(t *testing.T) {
	t.Parallel()
	for _, n := range MsgTypeNames() {
		m, ok := MsgTypeOf(n)
		if !ok || m.String() != n {
			t.Errorf("MsgTypeOf(%q) = (%v, %v)", n, m, ok)
		}
	}
	for _, n := range ETypeNames() {
		e, ok := ETypeOf(n)
		if !ok || e.String() != n {
			t.Errorf("ETypeOf(%q) = (%v, %v)", n, e, ok)
		}
	}
	for _, n := range OptionNames() {
		o, ok := OptionOf(n)
		if !ok || o == 0 {
			t.Errorf("OptionOf(%q) = (%v, %v)", n, o, ok)
		}
	}
	for _, n := range WeakETypes() {
		e, ok := ETypeOf(n)
		if !ok || !e.Weak() {
			t.Errorf("%q is listed weak and does not report weak", n)
		}
	}
	for _, spelling := range []string{"rc4", "aes256", "arcfour"} {
		if _, ok := ETypeOf(spelling); !ok {
			t.Errorf("ETypeOf(%q) was not accepted", spelling)
		}
	}
	if e, ok := ETypeOf("-128"); !ok || e != -128 {
		t.Errorf(`ETypeOf("-128") = (%v, %v)`, e, ok)
	}
	if _, ok := OptionOf("nonsense"); ok {
		t.Error("a nonsense option name was accepted")
	}
	if _, ok := MsgTypeOf("krb-safe"); ok {
		t.Error("a message type a proxy does not carry was accepted in a rule")
	}
	if got := Options(0).String(); got != "none" {
		t.Errorf("empty options render as %q", got)
	}
	if got := (OptForwardable | OptRenewable).String(); got != "forwardable,renewable" {
		t.Errorf("options render as %q", got)
	}
	if got := MsgType(99).String(); got != "msg-type(99)" {
		t.Errorf("MsgType(99) = %q", got)
	}
	if MsgType(99).Known() {
		t.Error("an unknown message type reports Known")
	}
	if got := PAType(999).String(); got != "padata(999)" {
		t.Errorf("PAType(999) = %q", got)
	}
	if got := EType(999).String(); got != "etype(999)" {
		t.Errorf("EType(999) = %q", got)
	}
	if !(Principal{}).Empty() {
		t.Error("a principal with no components does not report Empty")
	}
	if (Principal{Parts: []string{"a"}}).Empty() {
		t.Error("a principal with a component reports Empty")
	}
}

func TestPreauthIsOnlyTheTypesThatProveACredential(t *testing.T) {
	t.Parallel()
	for _, p := range []PAType{PAEncTimestamp, PAEncryptedChallenge, PAPKASReq} {
		if !p.Preauth() {
			t.Errorf("%v does not report Preauth", p)
		}
	}
	// A PAC request, an etype-info and a FAST cookie are not proof of
	// anything: a reader that counted them would read an unprotected AS
	// exchange as a protected one.
	for _, p := range []PAType{PAPACRequest, PAETypeInfo2, PAFXCookie, PAPWSalt} {
		if p.Preauth() {
			t.Errorf("%v reports Preauth", p)
		}
	}
}
