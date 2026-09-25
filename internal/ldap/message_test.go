package ldap

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// The builders. A test message is assembled from the encoder in this package
// rather than from a captured hexdump, so a test says what shape it is about
// -- and so a change that breaks the encoder breaks the reader's tests too,
// which is the pair that has to agree.

func seq(kids ...*packet) *packet { return node(classUniversal, tagSequence, kids...) }
func set(kids ...*packet) *packet { return node(classUniversal, tagSet, kids...) }
func app(tag byte, kids ...*packet) *packet {
	return node(classApplication, tag, kids...)
}
func appLeaf(tag byte, data string) *packet {
	return leaf(classApplication, tag, []byte(data))
}
func ctx(tag byte, kids ...*packet) *packet { return node(classContext, tag, kids...) }
func ctxLeaf(tag byte, data string) *packet {
	return leaf(classContext, tag, []byte(data))
}

func encode(p *packet) []byte { return p.encode(nil) }

// message wraps an operation in an LDAPMessage.
func message(id int, op *packet, controls ...*packet) []byte {
	m := seq(integer(id), op)
	if len(controls) > 0 {
		m.add(ctx(0, controls...))
	}
	return encode(m)
}

// simpleBind is the bind every application makes, and the three things it
// can be depending on what is in its two string fields.
func simpleBind(id int, name, password string) []byte {
	return message(id, app(0, integer(3), str(name), ctxLeaf(0, password)))
}

func saslBind(id int, mechanism string) []byte {
	return message(id, app(0, integer(3), str(""), ctx(3, str(mechanism))))
}

// searchRequest builds a SearchRequest with the eight fields it has.
func searchRequest(id int, base string, scope int, filter *packet, attrs ...string) []byte {
	list := seq()
	for _, a := range attrs {
		list.add(str(a))
	}
	return message(id, app(3, str(base), enumerated(scope), enumerated(0),
		integer(0), integer(0), boolean(false), filter, list))
}

func present(attr string) *packet { return ctxLeaf(7, attr) }
func equal(attr, value string) *packet {
	return ctx(3, str(attr), str(value))
}
func substrings(attr string, parts ...*packet) *packet {
	return ctx(4, str(attr), seq(parts...))
}
func initialPart(s string) *packet { return ctxLeaf(0, s) }
func anyPart(s string) *packet     { return ctxLeaf(1, s) }
func finalPart(s string) *packet   { return ctxLeaf(2, s) }

func entry(id int, name string, attrs ...string) []byte {
	list := seq()
	for _, a := range attrs {
		list.add(seq(str(a), set(str("value"))))
	}
	return message(id, app(4, str(name), list))
}

func result(id int, tag byte, code int) []byte {
	return message(id, app(tag, enumerated(code), str(""), str("")))
}

func parseOne(t *testing.T, raw []byte) *Message {
	t.Helper()
	m, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return m
}

// The bind, and the distinction this relay exists for on this protocol: a
// simple bind with a name and an empty password is an anonymous bind that
// a directory answers with success, and an application reads as "the
// password was right".
func TestTheFourThingsASimpleBindCanBe(t *testing.T) {
	for _, c := range []struct {
		name, password string
		want           Method
	}{
		{"", "", MethodAnonymous},
		{"cn=alice,dc=example,dc=com", "", MethodUnauthenticated},
		{"cn=alice,dc=example,dc=com", "s3cret", MethodSimple},
		{"", "s3cret", MethodSimple},
	} {
		m := parseOne(t, simpleBind(1, c.name, c.password))
		if m.Op != OpBindRequest || m.Bind == nil {
			t.Fatalf("%q/%q parsed as %s", c.name, c.password, m.Op)
		}
		if m.Bind.Method != c.want {
			t.Errorf("name %q password %q read as %s, wanted %s",
				c.name, c.password, m.Bind.Method, c.want)
		}
		if m.Bind.PasswordLength != len(c.password) {
			t.Errorf("password length %d", m.Bind.PasswordLength)
		}
	}
	// A SASL bind names its mechanism, which is the field a policy is
	// written about.
	m := parseOne(t, saslBind(2, "GSSAPI"))
	if m.Bind.Method != MethodSASL || m.Bind.Mechanism != "GSSAPI" {
		t.Errorf("sasl bind: %s %q", m.Bind.Method, m.Bind.Mechanism)
	}
	// And the version, because LDAPv2 is a different protocol wearing the
	// same tag.
	m = parseOne(t, message(3, app(0, integer(2), str(""), ctxLeaf(0, ""))))
	if m.Bind.Version != 2 {
		t.Errorf("version %d", m.Bind.Version)
	}
}

// The search, field by field. Each of these is something a policy names.
func TestTheSearchIsReadFieldByField(t *testing.T) {
	raw := searchRequest(7, "ou=people,dc=example,dc=com", ScopeSub,
		ctx(0, equal("objectClass", "person"), present("mail")),
		"cn", "mail")
	m := parseOne(t, raw)
	s := m.Search
	if s == nil {
		t.Fatal("no search")
	}
	if s.Base != "ou=people,dc=example,dc=com" || s.Scope != ScopeSub {
		t.Errorf("base %q scope %d", s.Base, s.Scope)
	}
	if got := s.BaseDN.String(); got != "ou=people,dc=example,dc=com" {
		t.Errorf("base dn %q", got)
	}
	if len(s.Attributes) != 2 || s.Attributes[0] != "cn" {
		t.Errorf("attributes %v", s.Attributes)
	}
	if s.AllAttributes() {
		t.Error("a search naming two attributes asks for all of them")
	}
	if s.Filter.Terms != 2 || s.Filter.Depth != 2 || s.Filter.Present != 1 {
		t.Errorf("filter %+v", s.Filter)
	}
	if len(s.Filter.Attributes) != 2 {
		t.Errorf("filter attributes %v", s.Filter.Attributes)
	}
	// The three ways a search asks for attributes it did not name, which is
	// why an attribute policy has to apply to the answer as well.
	for _, attrs := range [][]string{{}, {"*"}, {"cn", "+"}} {
		m := parseOne(t, searchRequest(8, "", ScopeBase, present("objectClass"), attrs...))
		if !m.Search.AllAttributes() {
			t.Errorf("%v does not ask for all attributes", attrs)
		}
	}
}

// A filter's shape is what a bound can be set on: how deep, how wide, and
// whether any term is one no index can serve.
func TestAFilterIsReadAsAShape(t *testing.T) {
	// (&(objectClass=person)(|(cn=*smith)(cn=jo*n))(!(mail=*)))
	f := ctx(0,
		equal("objectClass", "person"),
		ctx(1,
			substrings("cn", finalPart("smith")),
			substrings("cn", initialPart("jo"), finalPart("n")),
		),
		ctx(2, present("mail")),
	)
	shape, err := ReadFilter(f)
	if err != nil {
		t.Fatal(err)
	}
	if shape.Terms != 4 {
		t.Errorf("terms %d", shape.Terms)
	}
	if shape.Depth != 3 {
		t.Errorf("depth %d", shape.Depth)
	}
	if shape.Substrings != 2 || shape.LeadingWildcard != 1 {
		t.Errorf("substrings %d leading %d", shape.Substrings, shape.LeadingWildcard)
	}
	if shape.Present != 1 {
		t.Errorf("present %d", shape.Present)
	}
	want := []string{"objectclass", "cn", "mail"}
	if len(shape.Attributes) != len(want) {
		t.Fatalf("attributes %v", shape.Attributes)
	}
	for i, a := range want {
		if shape.Attributes[i] != a {
			t.Errorf("attribute %d is %q, wanted %q", i, shape.Attributes[i], a)
		}
	}
	// An attribute's transfer option is not part of its name: a policy about
	// userCertificate covers userCertificate;binary.
	// A substring with an `any` part in the middle is still anchored by its
	// initial part, so it is not the shape no index can serve.
	shape, err = ReadFilter(substrings("cn", initialPart("sm"), anyPart("it"), finalPart("h")))
	if err != nil {
		t.Fatal(err)
	}
	if shape.Substrings != 1 || shape.LeadingWildcard != 0 {
		t.Errorf("an anchored substring: %+v", shape)
	}
	shape, err = ReadFilter(present("userCertificate;binary"))
	if err != nil {
		t.Fatal(err)
	}
	if len(shape.Attributes) != 1 || shape.Attributes[0] != "usercertificate" {
		t.Errorf("attributes %v", shape.Attributes)
	}
	// An extensible match names its attribute in field [2]; Active
	// Directory's bit-and rule is how a disabled-account list is built.
	shape, err = ReadFilter(ctx(9,
		ctxLeaf(1, "1.2.840.113556.1.4.803"),
		ctxLeaf(2, "userAccountControl"),
		ctxLeaf(3, "2")))
	if err != nil {
		t.Fatal(err)
	}
	if shape.Extensible != 1 || len(shape.Attributes) != 1 {
		t.Errorf("extensible %+v", shape)
	}
	// An approximate match, which almost no directory implements.
	shape, err = ReadFilter(ctx(8, str("cn"), str("smith")))
	if err != nil || shape.Approx != 1 {
		t.Errorf("approx: %+v %v", shape, err)
	}
}

func TestTheFiltersThatAreNotFilters(t *testing.T) {
	for what, f := range map[string]*packet{
		"an empty and":                 ctx(0),
		"an empty or":                  ctx(1),
		"a not with two items":         ctx(2, present("a"), present("b")),
		"an assertion with one field":  ctx(3, str("cn")),
		"a substring with no parts":    ctx(4, str("cn"), seq()),
		"a substring with one field":   ctx(4, str("cn")),
		"an item that is not a filter": seq(str("cn")),
		"an item nobody defined":       ctx(15, str("cn")),
		"a presence item with no name": ctxLeaf(7, ""),
		"a presence item that nests":   ctx(7, str("cn")),
	} {
		if _, err := ReadFilter(f); err == nil {
			t.Errorf("%s was read as a filter", what)
		}
	}
	// And the depth bound, which is the reader's own rather than a policy's:
	// the reader will not walk a tree deeper than this whatever a listener
	// allows.
	deep := present("cn")
	for i := 0; i < MaxFilterDepth+2; i++ {
		deep = ctx(2, deep)
	}
	if _, err := ReadFilter(deep); !errors.Is(err, ErrCount) {
		t.Errorf("a filter nested past the bound read as %v", err)
	}
}

// The entry, read to its attribute names and no further: the values are the
// estate's data.
func TestAnEntryIsReadToItsAttributeNames(t *testing.T) {
	m := parseOne(t, entry(9, "cn=alice,ou=people,dc=example,dc=com",
		"cn", "mail", "userPassword"))
	if m.Entry == nil || m.Entry.Name != "cn=alice,ou=people,dc=example,dc=com" {
		t.Fatalf("entry %+v", m.Entry)
	}
	if len(m.Entry.Attributes) != 3 || m.Entry.Attributes[2] != "userPassword" {
		t.Errorf("attributes %v", m.Entry.Attributes)
	}
}

// The modify, read to which attributes change how. What they change *to* is
// not read: a password being set is interesting, and the password is not the
// relay's to hold.
func TestAModifyIsReadToItsAttributesAndChangeTypes(t *testing.T) {
	m := parseOne(t, message(10, app(6, str("cn=alice,dc=example,dc=com"), seq(
		seq(enumerated(2), seq(str("userPassword"), set(str("new")))),
		seq(enumerated(0), seq(str("member"), set(str("cn=admins")))),
	))))
	if m.Modify == nil {
		t.Fatal("no modify")
	}
	if len(m.Modify.Attributes) != 2 || m.Modify.Attributes[0] != "userPassword" {
		t.Errorf("attributes %v", m.Modify.Attributes)
	}
	if m.Modify.Operations[0] != 2 || m.Modify.Operations[1] != 0 {
		t.Errorf("operations %v", m.Modify.Operations)
	}
	if got := m.Modify.ObjectDN.String(); got != "cn=alice,dc=example,dc=com" {
		t.Errorf("object %q", got)
	}
}

// The single-object operations, and the one whose body *is* the name.
func TestTheSingleObjectOperationsNameTheirObject(t *testing.T) {
	// A delete's whole body is the DN, not a sequence containing it: a
	// reader that expected a sequence would refuse every delete.
	m := parseOne(t, message(11, appLeaf(10, "cn=bob,dc=example,dc=com")))
	if m.Op != OpDelRequest || m.Target != "cn=bob,dc=example,dc=com" {
		t.Errorf("delete: %s %q", m.Op, m.Target)
	}
	m = parseOne(t, message(12, app(8, str("cn=carol,dc=example,dc=com"), seq())))
	if m.Op != OpAddRequest || m.TargetDN.Depth() != 3 {
		t.Errorf("add: %s %v", m.Op, m.TargetDN)
	}
	m = parseOne(t, message(13, app(14, str("cn=dan,dc=example,dc=com"),
		seq(str("cn"), str("dan")))))
	if m.Op != OpCompareRequest || m.Target != "cn=dan,dc=example,dc=com" {
		t.Errorf("compare: %s %q", m.Op, m.Target)
	}
	m = parseOne(t, message(14, leaf(classApplication, 16, []byte{13})))
	if m.Op != OpAbandonRequest || m.Abandon != 13 {
		t.Errorf("abandon: %s %d", m.Op, m.Abandon)
	}
}

// The extended operations, which is where StartTLS and a password change
// both live.
func TestAnExtendedOperationIsReadByItsName(t *testing.T) {
	m := parseOne(t, message(15, app(23, ctxLeaf(0, OIDStartTLS))))
	if m.Extended == nil || m.Extended.OID != OIDStartTLS || m.Extended.HasValue {
		t.Errorf("starttls: %+v", m.Extended)
	}
	m = parseOne(t, message(16, app(23, ctxLeaf(0, OIDPasswordModify), ctxLeaf(1, "encoded"))))
	if m.Extended.OID != OIDPasswordModify || m.Extended.ValueLength != len("encoded") {
		t.Errorf("password modify: %+v", m.Extended)
	}
	// A response carries the result fields and names the operation in [10].
	m = parseOne(t, message(15, app(24, enumerated(0), str(""), str(""),
		ctxLeaf(10, OIDStartTLS))))
	if m.Result == nil || m.Result.Code != ResultSuccess {
		t.Errorf("response result %+v", m.Result)
	}
	if m.Extended.OID != OIDStartTLS {
		t.Errorf("response oid %q", m.Extended.OID)
	}
	// And an extended request with no name at all is not one.
	if _, err := Parse(message(17, app(23, ctxLeaf(1, "value")))); err == nil {
		t.Error("an extended request with no operation name was read")
	}
}

// A result, and the referral that makes one a redirection rather than an
// answer.
func TestAResultIsReadWithItsReferral(t *testing.T) {
	m := parseOne(t, result(18, 1, int(ResultInvalidCredentials)))
	if m.Op != OpBindResponse || m.Result.Code != ResultInvalidCredentials {
		t.Errorf("result %s %+v", m.Op, m.Result)
	}
	if got := m.Result.Code.String(); got != "invalidCredentials" {
		t.Errorf("code names itself %q", got)
	}
	m = parseOne(t, message(19, app(5, enumerated(10), str("dc=example,dc=com"),
		str("referral"), ctx(3, str("ldap://other.example.com")))))
	if !m.Result.Referral {
		t.Error("a referral was not noticed")
	}
	if m.Result.MatchedDN != "dc=example,dc=com" {
		t.Errorf("matched dn %q", m.Result.MatchedDN)
	}
}

// Controls, read to their name and criticality. The value is the control's
// own encoding.
func TestControlsAreReadByNameAndCriticality(t *testing.T) {
	const paged = "1.2.840.113556.1.4.319"
	m := parseOne(t, message(20, app(3, str(""), enumerated(0), enumerated(0),
		integer(0), integer(0), boolean(false), present("objectClass"), seq()),
		seq(str(paged), boolean(true), str("page")),
		seq(str("1.2.840.113556.1.4.1339"))))
	if len(m.Controls) != 2 {
		t.Fatalf("controls %+v", m.Controls)
	}
	if m.Controls[0].OID != paged || !m.Controls[0].Criticality {
		t.Errorf("first control %+v", m.Controls[0])
	}
	if m.Controls[0].ValueLength != 4 {
		t.Errorf("control value length %d", m.Controls[0].ValueLength)
	}
	if m.Controls[1].Criticality {
		t.Error("a control with no criticality field read as critical")
	}
}

// What must not parse. Each of these is a message a relay would otherwise
// have to decide about without having read it.
func TestTheMessagesThatAreNotMessages(t *testing.T) {
	for what, raw := range map[string][]byte{
		"nothing":                     {},
		"not a sequence":              encode(set(integer(1), app(2))),
		"one field":                   encode(seq(integer(1))),
		"an operation nobody defined": encode(seq(integer(1), app(30))),
		"an operation that is not an application tag": encode(seq(integer(1), seq())),
		"a bind with two fields":                      encode(seq(integer(1), app(0, integer(3), str("")))),
		"a bind authentication nobody defined":        encode(seq(integer(1), app(0, integer(3), str(""), ctx(9, str("x"))))),
		"a sasl bind with no mechanism":               encode(seq(integer(1), app(0, integer(3), str(""), ctx(3)))),
		"a search with seven fields": encode(seq(integer(1), app(3, str(""), enumerated(0),
			enumerated(0), integer(0), integer(0), boolean(false), present("cn")))),
		"a search scope nobody defined": searchRequest(1, "", 3, present("cn")),
		"an entry with one field":       encode(seq(integer(1), app(4, str("cn=a")))),
		"a modify change with one field": encode(seq(integer(1), app(6, str("cn=a"),
			seq(seq(enumerated(0)))))),
		"a result with two fields":       encode(seq(integer(1), app(1, enumerated(0), str("")))),
		"a control with no name":         encode(seq(integer(1), app(2), ctx(0, seq()))),
		"controls that are not controls": encode(seq(integer(1), app(2), ctx(5, seq(str("1.1"))))),
	} {
		if _, err := Parse(raw); err == nil {
			t.Errorf("%s parsed as a message", what)
		}
	}
	// Octets after the message: on a stream that is a framing this reader
	// did not agree to, and forwarding it would forward two messages as one.
	two := append(append([]byte{}, simpleBind(1, "", "")...), simpleBind(2, "", "")...)
	if _, err := Parse(two); err == nil {
		t.Error("two messages parsed as one")
	}
}

// The stream framing: the length is decided about before the octets it
// claims are read.
func TestTheReaderDecidesAboutALengthBeforeReadingIt(t *testing.T) {
	first := simpleBind(1, "cn=alice", "s3cret")
	second := searchRequest(2, "dc=example,dc=com", ScopeSub, present("objectClass"))
	rd := NewReader(bytes.NewReader(append(append([]byte{}, first...), second...)), 0)
	got, err := rd.Next()
	if err != nil || !bytes.Equal(got, first) {
		t.Fatalf("first message: %v", err)
	}
	got, err = rd.Next()
	if err != nil || !bytes.Equal(got, second) {
		t.Fatalf("second message: %v", err)
	}
	if _, err := rd.Next(); !errors.Is(err, io.EOF) {
		t.Errorf("the end of the stream read as %v", err)
	}

	// A length past the bound, with none of the octets it claims sent.
	rd = NewReader(bytes.NewReader([]byte{0x30, 0x83, 0x01, 0x00, 0x00}), 600)
	if _, err := rd.Next(); !errors.Is(err, ErrTooLong) {
		t.Errorf("an oversize length read as %v", err)
	}
	// Five length octets.
	rd = NewReader(bytes.NewReader([]byte{0x30, 0x85, 1, 1, 1, 1, 1}), 0)
	if _, err := rd.Next(); !errors.Is(err, ErrTooLong) {
		t.Errorf("a five-octet length read as %v", err)
	}
	// The indefinite form.
	rd = NewReader(bytes.NewReader([]byte{0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00}), 0)
	if _, err := rd.Next(); !errors.Is(err, ErrFraming) {
		t.Errorf("an indefinite length read as %v", err)
	}
	// Not a SEQUENCE at all: an HTTP request, which is what a scanner sends
	// to every open port it finds.
	rd = NewReader(bytes.NewReader([]byte("GET / HTTP/1.1\r\n")), 0)
	if _, err := rd.Next(); !errors.Is(err, ErrFraming) {
		t.Errorf("an HTTP request read as %v", err)
	}
	// A truncated body is an end of stream rather than a framing error: the
	// sender may simply have gone away mid-message.
	rd = NewReader(bytes.NewReader([]byte{0x30, 0x10, 0x02}), 0)
	if _, err := rd.Next(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("a truncated body read as %v", err)
	}
}

// The operation names an operator writes, and what each operation does.
func TestAnOperationIsNamedByWhatItDoes(t *testing.T) {
	for name, want := range map[string]Op{
		"bind": OpBindRequest, "search": OpSearchRequest, "modify": OpModifyRequest,
		"add": OpAddRequest, "delete": OpDelRequest, "del": OpDelRequest,
		"modify_dn": OpModifyDNRequest, "moddn": OpModifyDNRequest,
		"compare": OpCompareRequest, "abandon": OpAbandonRequest,
		"extended": OpExtendedRequest, "unbind": OpUnbindRequest,
		"  search  ": OpSearchRequest,
	} {
		got, ok := OpOf(name)
		if !ok || got != want {
			t.Errorf("%q named %s (%v)", name, got, ok)
		}
	}
	if _, ok := OpOf("dump"); ok {
		t.Error("an operation nobody defined was named")
	}
	for _, op := range []Op{OpModifyRequest, OpAddRequest, OpDelRequest, OpModifyDNRequest} {
		if !op.Writes() || !op.Request() {
			t.Errorf("%s does not write", op)
		}
	}
	for _, op := range []Op{OpSearchRequest, OpCompareRequest} {
		if !op.Reads() || op.Writes() {
			t.Errorf("%s: reads %v writes %v", op, op.Reads(), op.Writes())
		}
	}
	for _, op := range []Op{OpBindResponse, OpSearchResultEntry, OpSearchResultDone} {
		if op.Request() {
			t.Errorf("%s reads as a request", op)
		}
	}
	if got := Op(99).String(); got != "op(99)" {
		t.Errorf("an unknown operation names itself %q", got)
	}
	for name, want := range map[string]Method{
		"anonymous": MethodAnonymous, "unauthenticated": MethodUnauthenticated,
		"simple": MethodSimple, "sasl": MethodSASL,
	} {
		if got, ok := MethodOf(name); !ok || got != want {
			t.Errorf("%q named %s", name, got)
		}
	}
	if _, ok := MethodOf("kerberos"); ok {
		t.Error("a bind method nobody defined was named")
	}
}
