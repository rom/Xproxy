package tdswire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

// pkt builds one wire packet.
func pkt(typ, status byte, spid uint16, body []byte) []byte {
	out := []byte{typ, status}
	out = binary.BigEndian.AppendUint16(out, uint16(len(body)+HeaderLen))
	out = binary.BigEndian.AppendUint16(out, spid)
	out = append(out, 1, 0)
	return append(out, body...)
}

// The one big-endian field in a protocol that is little-endian everywhere else
// is exactly the field a reader gets backwards -- and read the wrong way round a
// length of 1 becomes a plausible-looking 256, so it loses framing quietly
// instead of failing loudly.
func TestTheLengthIsBigEndianAndIncludesTheHeader(t *testing.T) {
	body := []byte("hello")
	raw := pkt(TypeSQLBatch, StatusEOM, 7, body)
	if got := binary.BigEndian.Uint16(raw[2:4]); int(got) != len(body)+HeaderLen {
		t.Fatalf("length %d for %d body octets", got, len(body))
	}
	// Little-endian would put the low octet first, and for a 13-octet packet
	// that is 0x0d00 rather than 0x000d.
	if raw[2] != 0x00 || raw[3] != 0x0d {
		t.Fatalf("the length is not big-endian: %#02x %#02x", raw[2], raw[3])
	}
	rd := NewReader(bytes.NewReader(raw), MaxMessage)
	p, err := rd.Next()
	if err != nil {
		t.Fatal(err)
	}
	if p.Type != TypeSQLBatch || string(p.Payload) != "hello" || p.SPID != 7 {
		t.Fatalf("%+v", p)
	}
	if p.Packets != 1 {
		t.Fatalf("%d packets", p.Packets)
	}
}

// A length below the header is a packet shorter than its own header, and
// subtracting eight from it underflows.
func TestALengthBelowTheHeaderIsRefused(t *testing.T) {
	for _, n := range []int{0, 1, 7} {
		raw := []byte{TypeSQLBatch, StatusEOM}
		raw = binary.BigEndian.AppendUint16(raw, uint16(n))
		raw = append(raw, 0, 0, 1, 0)
		rd := NewReader(bytes.NewReader(raw), MaxMessage)
		if _, err := rd.Next(); !errors.Is(err, ErrShort) {
			t.Errorf("length %d: %v", n, err)
		}
	}
	// Exactly the header is an empty payload, which is legitimate: an ATTENTION
	// message has no body.
	rd := NewReader(bytes.NewReader(pkt(TypeAttention, StatusEOM, 0, nil)), MaxMessage)
	p, err := rd.Next()
	if err != nil || len(p.Payload) != 0 {
		t.Fatalf("an empty attention: %+v %v", p, err)
	}
}

// A message ends at the EOM status bit and nowhere else. Unlike MySQL there is no
// "a full packet means more follows" rule, so a reader that guessed from the
// length would split one message or join two.
func TestAMessageEndsAtEOMAndNotAtAShortPacket(t *testing.T) {
	// Two packets: a short one without EOM, then another with it.
	stream := append(pkt(TypeSQLBatch, StatusNormal, 0, []byte("one ")),
		pkt(TypeSQLBatch, StatusEOM, 0, []byte("two"))...)
	rd := NewReader(bytes.NewReader(stream), MaxMessage)
	p, err := rd.Next()
	if err != nil {
		t.Fatal(err)
	}
	if string(p.Payload) != "one two" {
		t.Fatalf("payload %q", p.Payload)
	}
	if p.Packets != 2 {
		t.Fatalf("%d packets", p.Packets)
	}
	// And two separate messages stay separate even though the first is short.
	stream = append(pkt(TypeSQLBatch, StatusEOM, 0, []byte("a")),
		pkt(TypeRPC, StatusEOM, 0, []byte("b"))...)
	rd = NewReader(bytes.NewReader(stream), MaxMessage)
	if p, err = rd.Next(); err != nil || string(p.Payload) != "a" {
		t.Fatalf("first: %q %v", p.Payload, err)
	}
	if p, err = rd.Next(); err != nil || p.Type != TypeRPC || string(p.Payload) != "b" {
		t.Fatalf("second: %+v %v", p, err)
	}
}

// A continuation of a different type is a message assembled from two, which
// neither peer sent.
func TestAContinuationOfADifferentTypeIsRefused(t *testing.T) {
	stream := append(pkt(TypeSQLBatch, StatusNormal, 0, []byte("x")),
		pkt(TypeRPC, StatusEOM, 0, []byte("y"))...)
	rd := NewReader(bytes.NewReader(stream), MaxMessage)
	if _, err := rd.Next(); !errors.Is(err, ErrTruncated) {
		t.Fatalf("%v", err)
	}
}

// The protocol puts no bound on a packet chain, so the relay does.
func TestAReassembledMessagePastTheBoundIsRefused(t *testing.T) {
	big := bytes.Repeat([]byte{'z'}, 4000)
	var stream []byte
	for i := 0; i < 4; i++ {
		stream = append(stream, pkt(TypeSQLBatch, StatusNormal, 0, big)...)
	}
	stream = append(stream, pkt(TypeSQLBatch, StatusEOM, 0, big)...)
	rd := NewReader(bytes.NewReader(stream), 8192)
	if _, err := rd.Next(); !errors.Is(err, ErrTooLong) {
		t.Fatalf("%v", err)
	}
}

// A connection pool asks for the session to be reset when it hands a connection
// to a different caller, and a relay should notice: the identity policy it
// applied may no longer describe who is using the connection.
func TestTheResetConnectionBitIsReported(t *testing.T) {
	raw := pkt(TypeSQLBatch, StatusEOM|StatusResetConnection, 0, []byte("x"))
	rd := NewReader(bytes.NewReader(raw), MaxMessage)
	p, err := rd.Next()
	if err != nil {
		t.Fatal(err)
	}
	if !p.Reset {
		t.Fatal("the reset bit was not reported")
	}
	rd = NewReader(bytes.NewReader(pkt(TypeSQLBatch, StatusEOM, 0, []byte("x"))), MaxMessage)
	if p, err = rd.Next(); err != nil || p.Reset {
		t.Fatalf("a reset reported where there was none: %+v", p)
	}
}

// Framing has to round-trip, and a payload larger than one packet has to split.
func TestFramingRoundTripsAndSplits(t *testing.T) {
	for _, n := range []int{0, 1, 100, 4088, 4089, 10000} {
		payload := bytes.Repeat([]byte{'p'}, n)
		raw := Frame(TypeSQLBatch, 3, payload, 4096)
		rd := NewReader(bytes.NewReader(raw), MaxMessage)
		p, err := rd.Next()
		if err != nil {
			t.Fatalf("%d octets: %v", n, err)
		}
		if !bytes.Equal(p.Payload, payload) {
			t.Fatalf("%d octets round-tripped to %d", n, len(p.Payload))
		}
		want := 1
		if n > 4088 {
			want = (n + 4087) / 4088
		}
		if p.Packets != want {
			t.Errorf("%d octets took %d packets, want %d", n, p.Packets, want)
		}
	}
	// A nonsense packet size falls back to the protocol's default rather than
	// producing packets a server cannot read.
	raw := Frame(TypeSQLBatch, 0, bytes.Repeat([]byte{'q'}, 100), 2)
	rd := NewReader(bytes.NewReader(raw), MaxMessage)
	if _, err := rd.Next(); err != nil {
		t.Fatalf("a nonsense packet size produced an unreadable packet: %v", err)
	}
}

// prelogin builds an option table.
func prelogin(opts ...PreLoginOption) []byte { return BuildPreLogin(opts) }

// The PRELOGIN encryption option is the whole negotiation, and it is the third
// protocol in a row where it happens in cleartext.
func TestThePreLoginEncryptionOptionIsRead(t *testing.T) {
	body := prelogin(
		PreLoginOption{Token: PreLoginVersion, Value: []byte{16, 0, 0, 0, 0, 0}},
		PreLoginOption{Token: PreLoginEncryption, Value: []byte{EncryptOff}},
		PreLoginOption{Token: PreLoginInstOpt, Value: []byte("MSSQLSERVER\x00")},
	)
	p, err := ParsePreLogin(body)
	if err != nil {
		t.Fatal(err)
	}
	if p.Encryption != EncryptOff || !p.HasEncryption {
		t.Fatalf("%+v", p)
	}
	if p.Instance != "MSSQLSERVER" {
		t.Fatalf("instance %q", p.Instance)
	}
	if len(p.Options) != 3 {
		t.Fatalf("%d options", len(p.Options))
	}
	// An absent option means plaintext, and the relay can tell that from
	// "asked for off" -- which matters, because one is an old client and the
	// other is a deliberate choice.
	body = prelogin(PreLoginOption{Token: PreLoginVersion, Value: []byte{16, 0}})
	if p, err = ParsePreLogin(body); err != nil {
		t.Fatal(err)
	}
	if p.HasEncryption {
		t.Fatal("an absent option was reported present")
	}
	if p.Encryption != EncryptNotSup {
		t.Fatalf("an absent option reads as %s", EncryptName(p.Encryption))
	}
}

// Only two of the four values mean the connection will be protected, and the
// two that do not read very differently from each other while having identical
// consequences on the wire.
func TestOnlyOnAndRequiredMeanEncrypted(t *testing.T) {
	for v, want := range map[byte]bool{
		EncryptOff: false, EncryptNotSup: false,
		EncryptOn: true, EncryptReq: true,
		EncryptClientCertOn: true, EncryptClientCertReq: true,
	} {
		if got := Encrypted(v); got != want {
			t.Errorf("%s: %v, want %v", EncryptName(v), got, want)
		}
		if EncryptName(v) == "" {
			t.Errorf("%#02x has no name", v)
		}
	}
	if EncryptName(0x42) == "" {
		t.Error("an unknown value has no name")
	}
}

// Both the offsets and the lengths in the option table are chosen by the peer.
func TestThePreLoginsThatAreNotPreLogins(t *testing.T) {
	for name, in := range map[string][]byte{
		"no terminator":              {PreLoginVersion, 0, 6, 0, 2},
		"nothing at all":             {},
		"a truncated entry":          {PreLoginVersion, 0, 6},
		"an offset past the end":     {PreLoginVersion, 0xff, 0xff, 0, 2, PreLoginTerminator},
		"a length past the end":      {PreLoginVersion, 0, 6, 0xff, 0xff, PreLoginTerminator},
		"an empty encryption option": {PreLoginEncryption, 0, 6, 0, 0, PreLoginTerminator},
		// Two values for the field the whole negotiation rests on: whichever
		// wins depends on whether a reader keeps the first or the last, so the
		// relay and the server could disagree about whether this connection is
		// to be encrypted.
		"a repeated encryption option": {
			PreLoginEncryption, 0, 11, 0, 1,
			PreLoginEncryption, 0, 12, 0, 1,
			PreLoginTerminator, EncryptReq, EncryptOff,
		},
		"any repeated option": {
			PreLoginVersion, 0, 11, 0, 1,
			PreLoginVersion, 0, 12, 0, 1,
			PreLoginTerminator, 1, 2,
		},
	} {
		if _, err := ParsePreLogin(in); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	// The option count is a number the peer chooses.
	var many []PreLoginOption
	for i := 0; i <= MaxPreLoginOptions; i++ {
		many = append(many, PreLoginOption{Token: byte(i % 0xfe), Value: []byte{1}})
	}
	if _, err := ParsePreLogin(BuildPreLogin(many)); !errors.Is(err, ErrTooMany) {
		t.Errorf("too many options: %v", err)
	}
}

// Making every client look like one that sent ENCRYPT_REQ is how the downgrade
// is defeated: the attack works by rewriting an *answer*, and a client whose
// request says "required" cannot be talked out of it.
func TestTheEncryptionOptionCanBeRewrittenAndAddedInOrder(t *testing.T) {
	// Present: it is replaced.
	body := prelogin(
		PreLoginOption{Token: PreLoginVersion, Value: []byte{16, 0}},
		PreLoginOption{Token: PreLoginEncryption, Value: []byte{EncryptOff}},
		PreLoginOption{Token: PreLoginInstOpt, Value: []byte("x\x00")},
	)
	p, err := ParsePreLogin(body)
	if err != nil {
		t.Fatal(err)
	}
	again, err := ParsePreLogin(BuildPreLogin(p.WithEncryption(EncryptReq)))
	if err != nil {
		t.Fatal(err)
	}
	if again.Encryption != EncryptReq {
		t.Fatalf("rewritten to %s", EncryptName(again.Encryption))
	}
	// Everything else survives, which is the half worth asserting: a rewrite
	// that lost the instance name would break a named-instance connection while
	// looking like it was helping.
	if again.Instance != "x" || len(again.Options) != 3 {
		t.Fatalf("%+v", again)
	}

	// Absent: it is added, and the table stays in ascending token order, which
	// the specification requires and some servers enforce.
	body = prelogin(
		PreLoginOption{Token: PreLoginVersion, Value: []byte{16, 0}},
		PreLoginOption{Token: PreLoginThreadID, Value: []byte{1, 2, 3, 4}},
	)
	if p, err = ParsePreLogin(body); err != nil {
		t.Fatal(err)
	}
	opts := p.WithEncryption(EncryptReq)
	if again, err = ParsePreLogin(BuildPreLogin(opts)); err != nil {
		t.Fatal(err)
	}
	if again.Encryption != EncryptReq || !again.HasEncryption {
		t.Fatalf("not added: %+v", again)
	}
	for i := 1; i < len(opts); i++ {
		if opts[i-1].Token > opts[i].Token {
			t.Fatalf("the option table is out of order: %#02x then %#02x",
				opts[i-1].Token, opts[i].Token)
		}
	}
}

// login7 builds a LOGIN7 body.
func login7(host, user, pass, app, srv, lib, lang, db string, integrated bool) []byte {
	fields := []string{host, user, pass, app, srv, "", lib, lang, db}
	const fixed = 36
	head := fixed + len(fields)*4
	var vals []byte
	offs := make([][2]uint16, len(fields))
	for i, s := range fields {
		enc := ToUCS2(s)
		if i == 2 {
			enc = Obfuscate(enc)
		}
		offs[i] = [2]uint16{uint16(head + len(vals)), uint16(len(enc) / 2)}
		vals = append(vals, enc...)
	}
	b := make([]byte, fixed)
	binary.LittleEndian.PutUint32(b[0:4], uint32(head+len(vals)))
	binary.LittleEndian.PutUint32(b[4:8], 0x74000004) // TDS 7.4
	if integrated {
		b[25] |= 0x80
	}
	for _, o := range offs {
		b = binary.LittleEndian.AppendUint16(b, o[0])
		b = binary.LittleEndian.AppendUint16(b, o[1])
	}
	return append(b, vals...)
}

func TestLogin7IsReadForItsIdentity(t *testing.T) {
	body := login7("WS01", "sa", "hunter2", "MyApp", "sqlhost", "ODBC", "us_english", "sales", false)
	l, err := ParseLogin7(body)
	if err != nil {
		t.Fatal(err)
	}
	if l.User != "sa" || l.Database != "sales" || l.Hostname != "WS01" ||
		l.AppName != "MyApp" || l.Library != "ODBC" {
		t.Fatalf("%+v", l)
	}
	if !l.HasPassword {
		t.Fatal("a password field was present and not noticed")
	}
	if l.Integrated {
		t.Fatal("a password login was read as integrated")
	}
	// Integrated security means the credential is an SSPI blob rather than the
	// password field, which is a different decision for a policy.
	body = login7("WS01", "", "", "MyApp", "sqlhost", "ODBC", "", "sales", true)
	if l, err = ParseLogin7(body); err != nil {
		t.Fatal(err)
	}
	if !l.Integrated || l.HasPassword {
		t.Fatalf("%+v", l)
	}
}

// The string lengths in LOGIN7 are counted in *characters*, not octets. A reader
// that treated them as octets would read half of every string -- and a different
// user name from the one the server reads.
func TestTheLoginStringLengthsAreCharactersAndNotOctets(t *testing.T) {
	body := login7("HOSTNAME", "administrator", "x", "app", "srv", "lib", "lang", "database", false)
	l, err := ParseLogin7(body)
	if err != nil {
		t.Fatal(err)
	}
	if l.User != "administrator" {
		t.Fatalf("user %q -- half of it would be %q", l.User, "adminis")
	}
	if l.Database != "database" {
		t.Fatalf("database %q", l.Database)
	}
}

func TestTheLogin7sThatAreNotLogins(t *testing.T) {
	good := login7("h", "u", "p", "a", "s", "l", "", "d", false)
	for name, in := range map[string][]byte{
		"nothing":             {},
		"only the fixed part": good[:36],
		"a truncated table":   good[:40],
	} {
		if _, err := ParseLogin7(in); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	// An offset past the body.
	bad := append([]byte(nil), good...)
	binary.LittleEndian.PutUint16(bad[36:38], 0xffff)
	if _, err := ParseLogin7(bad); !errors.Is(err, ErrTruncated) {
		t.Errorf("an offset past the body: %v", err)
	}
	// A pre-7.0 version claims a message this relay does not read.
	bad = append([]byte(nil), good...)
	binary.LittleEndian.PutUint32(bad[4:8], 0x00000070)
	if _, err := ParseLogin7(bad); !errors.Is(err, ErrVersion) {
		t.Errorf("a pre-7.0 version: %v", err)
	}
}

// The claim worth demonstrating rather than asserting in a comment: the LOGIN7
// password is an *encoding*, not encryption. It has no key, so anybody can
// reverse it.
func TestTheLoginPasswordIsAnEncodingAndNotEncryption(t *testing.T) {
	// The transformation is: XOR each octet with 0xA5, then swap its nibbles.
	// Reversing it needs no secret at all, which is the whole point.
	for _, pass := range []string{"hunter2", "", "P@ssw0rd!", strings.Repeat("x", 100)} {
		enc := Obfuscate(ToUCS2(pass))
		got, err := UCS2(Deobfuscate(enc))
		if err != nil {
			t.Fatalf("%q: %v", pass, err)
		}
		if got != pass {
			t.Fatalf("%q round-tripped to %q", pass, got)
		}
	}
	// And the known-answer case, so the constant is pinned rather than merely
	// self-consistent. 'a' is 0x61; 0x61 ^ 0xa5 is 0xc4; swapping its nibbles
	// gives 0x4c.
	if got := Obfuscate([]byte{0x61}); got[0] != 0x4c {
		t.Fatalf("the encoding of 0x61 is %#02x, want 0x4c", got[0])
	}
	if got := Deobfuscate([]byte{0x4c}); got[0] != 0x61 {
		t.Fatalf("decoding 0x4c gives %#02x, want 0x61", got[0])
	}
}

// nvarcharParam builds one unnamed NVARCHAR parameter in the short form.
func nvarcharParam(s string) []byte {
	enc := ToUCS2(s)
	out := []byte{0, 0, 0xe7}                                     // no name, no flags, NVARCHARTYPE
	out = binary.LittleEndian.AppendUint16(out, 8000)             // maximum length
	out = append(out, 0, 0, 0, 0, 0)                              // collation
	out = binary.LittleEndian.AppendUint16(out, uint16(len(enc))) //nolint:gosec // test data
	return append(out, enc...)
}

// intParam builds one unnamed INTN parameter, which is the shape the handle and
// option arguments of the prepare family take.
func intParam(v int32) []byte {
	out := []byte{0, 0, 0x26, 4, 4} // no name, no flags, INTNTYPE, max 4, actual 4
	return binary.LittleEndian.AppendUint32(out, uint32(v))
}

// rpcByName builds an RPC naming a procedure, with the parameters given.
func rpcByName(name string, withHeaders bool, params ...[]byte) []byte {
	enc := ToUCS2(name)
	body := binary.LittleEndian.AppendUint16(nil, uint16(len(enc)/2))
	body = append(body, enc...)
	body = binary.LittleEndian.AppendUint16(body, 0) // option flags
	for _, p := range params {
		body = append(body, p...)
	}
	if !withHeaders {
		return body
	}
	hdr := binary.LittleEndian.AppendUint32(nil, 4+18)
	hdr = append(hdr, bytes.Repeat([]byte{0}, 18)...)
	return append(hdr, body...)
}

// rpcByID builds an RPC naming a procedure by number.
func rpcByID(id uint16, params ...[]byte) []byte {
	body := binary.LittleEndian.AppendUint16(nil, 0xffff)
	body = binary.LittleEndian.AppendUint16(body, id)
	body = binary.LittleEndian.AppendUint16(body, 0) // option flags
	for _, p := range params {
		body = append(body, p...)
	}
	return body
}

// The two naming forms are the same call, and a policy that matched only the
// string would be bypassed by a client library that uses the number -- which
// most of them do.
func TestAProcedureIsNamedByNameOrByNumberAndBothCollapse(t *testing.T) {
	r, err := ParseRPC(rpcByName("sp_executesql", false, nvarcharParam("SELECT 1")))
	if err != nil {
		t.Fatal(err)
	}
	if r.Procedure() != "sp_executesql" || r.ByID {
		t.Fatalf("%+v", r)
	}
	if r, err = ParseRPC(rpcByID(SpExecuteSql, nvarcharParam("SELECT 1"))); err != nil {
		t.Fatal(err)
	}
	if !r.ByID || r.Procedure() != "sp_executesql" {
		t.Fatalf("by id: %+v -> %q", r, r.Procedure())
	}
	// The case is folded, so a policy compares one spelling.
	if r, err = ParseRPC(rpcByName("XP_CmdShell", false)); err != nil {
		t.Fatal(err)
	}
	if r.Procedure() != "xp_cmdshell" {
		t.Fatalf("%q", r.Procedure())
	}
	// A stream header block before the body is stepped over.
	if r, err = ParseRPC(rpcByName("sp_executesql", true, nvarcharParam("SELECT 1"))); err != nil {
		t.Fatal(err)
	}
	if r.Procedure() != "sp_executesql" {
		t.Fatalf("with headers: %q", r.Procedure())
	}
	// Every well-known identifier has a name, so a refusal can say what it
	// refused rather than printing a number.
	for id := uint16(1); id <= SpUnprepare; id++ {
		if ProcName(id) == "" {
			t.Errorf("procedure %d has no name", id)
		}
	}
	if ProcName(9999) == "" {
		t.Error("an unknown identifier has no name")
	}
}

func TestTheRPCsThatAreNotRPCs(t *testing.T) {
	for name, in := range map[string][]byte{
		"nothing":             {},
		"one octet":           {1},
		"a name past the end": {0xff, 0x00},
		"an id with no id":    {0xff, 0xff, 0x01},
		// An RPC that names no procedure is not one: a policy matching on the
		// procedure would have nothing to decide about.
		"a zero-length name": {0x00, 0x00, 0x00, 0x00},
		"a name of NULs":     {0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
	} {
		if _, err := ParseRPC(in); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	// An odd-length UCS-2 name cannot be one, and dropping the stray octet
	// would read a different name from the server's.
	odd := binary.LittleEndian.AppendUint16(nil, 2)
	odd = append(odd, 'a', 0, 'b')
	if _, err := ParseRPC(odd); err == nil {
		t.Error("an odd-length name was accepted")
	}
}

// SQLBATCH carries T-SQL as UCS-2, with the same optional header block.
func TestTheBatchTextIsDecodedFromUCS2(t *testing.T) {
	text := "SELECT 1"
	body := ToUCS2(text)
	got, err := SQLText(body)
	if err != nil || got != text {
		t.Fatalf("%q %v", got, err)
	}
	hdr := binary.LittleEndian.AppendUint32(nil, 4+18)
	hdr = append(hdr, bytes.Repeat([]byte{0}, 18)...)
	if got, err = SQLText(append(hdr, ToUCS2(text)...)); err != nil || got != text {
		t.Fatalf("with headers: %q %v", got, err)
	}
	// An odd length is refused rather than truncated.
	if _, err = SQLText([]byte{'a'}); !errors.Is(err, ErrOdd) {
		t.Errorf("odd: %v", err)
	}
	// And a non-BMP character round-trips, because a statement may legitimately
	// contain one and a surrogate pair read as two characters would be a
	// different string.
	emoji := "SELECT '\U0001F600'"
	if got, err = SQLText(ToUCS2(emoji)); err != nil || got != emoji {
		t.Fatalf("surrogate pair: %q %v", got, err)
	}
}

// The type and procedure vocabularies are what a configuration writes.
func TestTheNamesAConfigurationWritesRoundTrip(t *testing.T) {
	for _, n := range TypeNames() {
		typ, ok := TypeOf(n)
		if !ok {
			t.Errorf("%s is listed but not readable", n)
			continue
		}
		if got := TypeName(typ); got != n {
			t.Errorf("%s round-tripped to %s", n, got)
		}
	}
	if _, ok := TypeOf("nonsense"); ok {
		t.Error("a type that is not one was accepted")
	}
	if TypeName(0x7f) == "" {
		t.Error("an unknown type has no name")
	}
}

// The default type list is the security claim: what a client library sends.
func TestTheDefaultTypeListLeavesOutWhatTheRelayCannotRead(t *testing.T) {
	def := map[byte]bool{}
	for _, tp := range DefaultTypes() {
		def[tp] = true
	}
	// The pre-TDS7 login is a different message this relay does not read, so
	// forwarding one would mean forwarding octets it had not understood. Bulk
	// load is a job rather than an application's traffic, and its data stream
	// carries no policy.
	for _, tp := range []byte{TypeLogin, TypeBulkLoad} {
		if def[tp] {
			t.Errorf("%s is allowed by default", TypeName(tp))
		}
	}
	for _, tp := range []byte{TypeSQLBatch, TypeRPC, TypePreLogin, TypeLogin7,
		TypeTransactionManager, TypeAttention} {
		if !def[tp] {
			t.Errorf("%s is not allowed by default, which breaks every client", TypeName(tp))
		}
	}
}

// What the relay writes has to be readable by a client library, and its own text
// must not be able to break the framing.
func TestWhatTheRelayWritesIsWellFormed(t *testing.T) {
	raw := ErrorToken(PermissionDenied, "refused by xproxy: read_only\nand\x00more", "xproxy")
	if raw[0] != TokenError {
		t.Fatalf("token %#02x", raw[0])
	}
	n := int(binary.LittleEndian.Uint16(raw[1:3]))
	if n+3 > len(raw) {
		t.Fatalf("the token claims %d octets in %d", n, len(raw))
	}
	got, ok := ErrorNumber(raw)
	if !ok || got != PermissionDenied {
		t.Fatalf("number %d %v", got, ok)
	}
	// The message text is UCS-2 inside the token, so decode it back and check
	// the control characters are gone.
	msgLen := int(binary.LittleEndian.Uint16(raw[9:11])) * 2
	text, err := UCS2(raw[11 : 11+msgLen])
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{"\x00", "\n"} {
		if strings.Contains(text, c) {
			t.Errorf("a control character survived into %q", text)
		}
	}
	// A DONE follows, so the client stops waiting for results.
	if !bytes.Contains(raw, []byte{TokenDone}) {
		t.Error("no DONE token, so a client would wait for ever")
	}
	// It frames into a packet a reader can read back.
	framed := Frame(TypeTabularResult, 0, raw, 4096)
	rd := NewReader(bytes.NewReader(framed), MaxMessage)
	if p, err := rd.Next(); err != nil || p.Type != TypeTabularResult {
		t.Fatalf("the relay wrote a packet it cannot read: %+v %v", p, err)
	}
}

// The relay takes the end of the authentication exchange from the protocol rather
// than guessing, which is the lesson the MySQL kind learned the hard way.
func TestLoginAckIsTheProtocolsOwnSignal(t *testing.T) {
	if !LoginAck([]byte{TokenLoginAck, 1, 2}) {
		t.Error("a LOGINACK was not recognised")
	}
	if LoginAck([]byte{TokenError, 1, 2}) {
		t.Error("an error was read as a LOGINACK")
	}
	if LoginAck(nil) {
		t.Error("an empty payload was read as a LOGINACK")
	}
	// A LOGINACK further into a stream is deliberately not matched: walking the
	// token stream badly would produce false positives from row data, and the
	// case that matters is the first token of a login response.
	if LoginAck([]byte{TokenEnvChange, 0, 0, TokenLoginAck}) {
		t.Error("a byte inside another token was read as a LOGINACK")
	}
	if _, ok := ErrorNumber([]byte{TokenDone}); ok {
		t.Error("a DONE was read as an error")
	}
}

func TestClipBoundsAPeerChosenString(t *testing.T) {
	if got := Clip(strings.Repeat("a", MaxString*2)); len(got) > MaxString+3 {
		t.Fatalf("clipped to %d", len(got))
	}
	if Clip("short") != "short" {
		t.Fatal("a short string was changed")
	}
}

// A clipped string still has to be a string. The bound is in octets and the
// data is UTF-8, so a naive slice at the bound cuts a multi-byte character in
// half -- and the result is invalid UTF-8 that a JSON log writer rewrites, a
// terminal draws as a replacement character, and a comparison against a
// policy's spelling no longer matches. Cutting one character short is the
// harmless failure; cutting into a character is not.
func TestClipCutsOnARuneBoundary(t *testing.T) {
	// 3 octets per rune, and the bound is not a multiple of 3, so the octet at
	// the bound is in the middle of a character.
	got := Clip(strings.Repeat("\u5b57", MaxString))
	if !utf8.ValidString(got) {
		t.Fatalf("Clip produced invalid UTF-8: %q", got)
	}
	if len(got) > MaxString+3 {
		t.Fatalf("Clip returned %d octets, want at most %d", len(got), MaxString+3)
	}
	if strings.ContainsRune(got, utf8.RuneError) {
		t.Fatalf("Clip produced a replacement character: %q", got)
	}
}

// The whole claim of rpc.go: the statement an application actually runs arrives
// as a parameter of sp_executesql, not as a batch, so a relay that read only
// SQLBATCH would be inspecting the SET statements a driver emits on connect and
// nothing else.
func TestTheStatementInADynamicSQLCallIsRead(t *testing.T) {
	r, err := ParseRPC(rpcByName("sp_executesql", false,
		nvarcharParam("SELECT * FROM payroll WHERE id = @id"),
		nvarcharParam("@id int"),
		intParam(7)))
	if err != nil {
		t.Fatal(err)
	}
	if !r.HasStatement {
		t.Fatal("sp_executesql carried no statement")
	}
	if r.Statement != "SELECT * FROM payroll WHERE id = @id" {
		t.Fatalf("statement is %q", r.Statement)
	}
	// By number is the same call, and most drivers use the number.
	if r, err = ParseRPC(rpcByID(SpExecuteSql, nvarcharParam("DROP TABLE t"))); err != nil {
		t.Fatal(err)
	}
	if r.Statement != "DROP TABLE t" {
		t.Fatalf("by id: %q", r.Statement)
	}
}

// The prepare family puts the statement third or fourth, behind an output handle
// and a parameter declaration, so the positions come from the signatures rather
// than from "the first string-shaped thing".
func TestTheStatementIsFoundAtTheSignaturesPosition(t *testing.T) {
	for _, tc := range []struct {
		proc   string
		params [][]byte
	}{
		{"sp_prepare", [][]byte{intParam(0), nvarcharParam("@id int"),
			nvarcharParam("UPDATE t SET x = 1"), intParam(1)}},
		{"sp_prepexec", [][]byte{intParam(0), nvarcharParam("@id int"),
			nvarcharParam("UPDATE t SET x = 1")}},
		{"sp_cursorprepare", [][]byte{intParam(0), nvarcharParam(""),
			nvarcharParam("UPDATE t SET x = 1"), intParam(1)}},
		{"sp_cursorprepexec", [][]byte{intParam(0), intParam(0), nvarcharParam(""),
			nvarcharParam("UPDATE t SET x = 1")}},
		{"sp_cursoropen", [][]byte{intParam(0), nvarcharParam("UPDATE t SET x = 1")}},
	} {
		r, err := ParseRPC(rpcByName(tc.proc, false, tc.params...))
		if err != nil {
			t.Fatalf("%s: %v", tc.proc, err)
		}
		if r.Statement != "UPDATE t SET x = 1" {
			t.Fatalf("%s: statement is %q", tc.proc, r.Statement)
		}
	}
}

// A procedure with no statement in its signature has none read, and nothing is
// invented for it. sp_unprepare takes a handle; xp_cmdshell takes a command
// string that is not T-SQL and must not be classified as though it were.
func TestAProcedureWithNoStatementHasNoneRead(t *testing.T) {
	for _, proc := range []string{"sp_unprepare", "sp_execute", "xp_cmdshell",
		"sp_prepexecrpc", "sp_oacreate"} {
		r, err := ParseRPC(rpcByName(proc, false, nvarcharParam("SELECT 1")))
		if err != nil {
			t.Fatalf("%s: %v", proc, err)
		}
		if r.HasStatement || r.Statement != "" {
			t.Fatalf("%s: invented a statement %q", proc, r.Statement)
		}
	}
}

// A statement longer than 4000 characters does not fit NVARCHAR's short form, so
// a driver sends it partially length-prefixed -- in chunks, with the total
// sometimes declared as unknown. A reader that handled only the short form would
// refuse every long statement, which is every migration script.
func TestALongStatementArrivesInChunks(t *testing.T) {
	stmt := "SELECT '" + strings.Repeat("x", 9000) + "'"
	enc := ToUCS2(stmt)
	for _, tc := range []struct {
		name  string
		total uint64
	}{
		{"declared length", uint64(len(enc))},
		{"unknown length", 0xfffffffffffffffe},
	} {
		p := []byte{0, 0, 0xe7}
		p = binary.LittleEndian.AppendUint16(p, 0xffff) // PLP
		p = append(p, 0, 0, 0, 0, 0)                    // collation
		p = binary.LittleEndian.AppendUint64(p, tc.total)
		for i := 0; i < len(enc); i += 4000 {
			end := i + 4000
			if end > len(enc) {
				end = len(enc)
			}
			p = binary.LittleEndian.AppendUint32(p, uint32(end-i))
			p = append(p, enc[i:end]...)
		}
		p = binary.LittleEndian.AppendUint32(p, 0) // terminator
		r, err := ParseRPC(rpcByName("sp_executesql", false, p))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if r.Statement != stmt {
			t.Fatalf("%s: reassembled %d characters, want %d",
				tc.name, len(r.Statement), len(stmt))
		}
	}
}

// A NULL statement parameter is not a statement, and neither is an absent one.
// Both are refused, because a dynamic-SQL call the relay cannot read the
// statement out of is a call it has no opinion about -- and forwarding one would
// be forwarding the single message on this protocol that carries arbitrary SQL.
func TestAnUnreadableDynamicCallIsRefused(t *testing.T) {
	null := []byte{0, 0, 0xe7}
	null = binary.LittleEndian.AppendUint16(null, 8000)
	null = append(null, 0, 0, 0, 0, 0)
	null = binary.LittleEndian.AppendUint16(null, 0xffff) // NULL

	for _, tc := range []struct {
		name string
		body []byte
	}{
		{"no parameters at all", rpcByName("sp_executesql", false)},
		{"a NULL statement", rpcByName("sp_executesql", false, null)},
		{"an integer where the statement should be",
			rpcByName("sp_executesql", false, intParam(1))},
		{"too few parameters for the signature",
			rpcByName("sp_prepare", false, intParam(0), nvarcharParam(""))},
		{"a data type the reader does not know",
			rpcByName("sp_executesql", false, []byte{0, 0, 0xf1, 0})},
		{"a parameter that ends inside its value",
			rpcByName("sp_executesql", false, nvarcharParam("SELECT 1")[:12])},
	} {
		if _, err := ParseRPC(tc.body); err == nil {
			t.Fatalf("%s was accepted", tc.name)
		}
	}
	// And the type error says which type, so an operator whose driver sends
	// something unusual can report it rather than guess.
	_, err := ParseRPC(rpcByName("sp_executesql", false, []byte{0, 0, 0xf1, 0}))
	if !errors.Is(err, ErrParamType) {
		t.Fatalf("an unknown type gave %v, want ErrParamType", err)
	}
}

// A PLP value whose chunks say more than its declared total is a value two
// readers would disagree about. Neither number is believed.
func TestChunksThatExceedTheDeclaredTotalAreRefused(t *testing.T) {
	enc := ToUCS2("SELECT 1")
	p := []byte{0, 0, 0xe7}
	p = binary.LittleEndian.AppendUint16(p, 0xffff)
	p = append(p, 0, 0, 0, 0, 0)
	p = binary.LittleEndian.AppendUint64(p, 2) // two octets declared
	p = binary.LittleEndian.AppendUint32(p, uint32(len(enc)))
	p = append(p, enc...)
	p = binary.LittleEndian.AppendUint32(p, 0)
	if _, err := ParseRPC(rpcByName("sp_executesql", false, p)); err == nil {
		t.Fatal("a value whose chunks outran its declared total was accepted")
	}
}
