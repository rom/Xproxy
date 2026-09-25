package pgwire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

// startup builds a version 3 startup packet from key/value pairs.
func startup(code int32, kv ...string) []byte {
	var body []byte
	for _, s := range kv {
		body = append(body, s...)
		body = append(body, 0)
	}
	if code == Version3 {
		body = append(body, 0)
	}
	out := make([]byte, 8, 8+len(body))
	binary.BigEndian.PutUint32(out[:4], uint32(8+len(body)))
	binary.BigEndian.PutUint32(out[4:8], uint32(code)) //nolint:gosec // a protocol constant
	return append(out, body...)
}

// The first message on a connection is the one with no type octet, and the code
// in it is what says which of four completely different messages it is.
func TestTheFirstMessageIsReadByItsCodeAndNotItsType(t *testing.T) {
	s, err := ParseStartup(startup(Version3, "user", "alice", "database", "sales"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Code != Version3 || s.User() != "alice" || s.Database() != "sales" {
		t.Fatalf("%+v", s)
	}
	// The order is kept, because a forwarded packet has to be the one the
	// client sent.
	if len(s.Params) != 2 || s.Params[0].Key != "user" || s.Params[1].Key != "database" {
		t.Fatalf("params: %+v", s.Params)
	}

	// An SSLRequest is eight octets and nothing else.
	ssl := []byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}
	s, err = ParseStartup(ssl)
	if err != nil || s.Code != SSLRequest {
		t.Fatalf("ssl: %+v %v", s, err)
	}
	if binary.BigEndian.Uint32(ssl[4:]) != SSLRequest {
		t.Fatal("the test's own constant is wrong")
	}

	// GSSAPI encryption is the other pre-TLS negotiation, and a relay that
	// read it as a startup packet would forward a connection with no identity.
	gss := []byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x30}
	if s, err = ParseStartup(gss); err != nil || s.Code != GSSEncRequest {
		t.Fatalf("gssenc: %+v %v", s, err)
	}

	// A CancelRequest carries the only credential it has.
	cancel := []byte{0, 0, 0, 16, 0x04, 0xd2, 0x16, 0x2e, 0, 0, 0x30, 0x39, 0x11, 0x22, 0x33, 0x44}
	if s, err = ParseStartup(cancel); err != nil {
		t.Fatal(err)
	}
	if s.Code != CancelRequest || s.PID != 12345 || s.Secret != 0x11223344 {
		t.Fatalf("cancel: %+v", s)
	}
}

// The database defaults to the user name. A policy that read the parameter
// literally would never match the commonest connection string there is.
func TestTheDatabaseDefaultsToTheUserName(t *testing.T) {
	s, err := ParseStartup(startup(Version3, "user", "alice"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Database() != "alice" {
		t.Fatalf("database %q", s.Database())
	}
}

// replication is a startup parameter, not a statement, and it turns the
// connection into a copy of the whole server.
func TestReplicationIsReadFromTheStartupParameters(t *testing.T) {
	for _, tc := range []struct {
		val  string
		want bool
	}{
		{"true", true}, {"on", true}, {"1", true}, {"yes", true},
		{"TRUE", true}, {"database", true},
		{"false", false}, {"off", false}, {"0", false}, {"no", false}, {"", false},
	} {
		kv := []string{"user", "alice"}
		if tc.val != "" {
			kv = append(kv, "replication", tc.val)
		}
		s, err := ParseStartup(startup(Version3, kv...))
		if err != nil {
			t.Fatalf("%q: %v", tc.val, err)
		}
		if _, on := s.Replication(); on != tc.want {
			t.Errorf("replication=%q: %v, want %v", tc.val, on, tc.want)
		}
	}
}

// What must not parse. Each of these is a message a server would read
// differently from a relay that accepted it.
func TestTheStartupPacketsThatAreNotStartupPackets(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []byte
		want error
	}{
		// A length of zero or one is self-referential: the field says the
		// message is shorter than the field. Subtracting four gives a huge
		// unsigned number, which is the classic allocation bug.
		{"zero length", []byte{0, 0, 0, 0, 0, 3, 0, 0}, ErrShort},
		{"length of one", []byte{0, 0, 0, 1, 0, 3, 0, 0}, ErrShort},
		{"length of seven", []byte{0, 0, 0, 7, 0, 3, 0, 0}, ErrShort},
		{"nothing at all", []byte{}, ErrShort},
		{"only a length", []byte{0, 0, 0, 8}, ErrShort},
		// A length that disagrees with what is there.
		{"length past the data", []byte{0, 0, 0, 32, 0, 3, 0, 0}, ErrTruncated},
		// An SSLRequest with a body is not an SSLRequest.
		{"ssl with a body", []byte{0, 0, 0, 9, 0x04, 0xd2, 0x16, 0x2f, 1}, ErrTruncated},
		// A cancel request with the wrong number of fields.
		{"short cancel", []byte{0, 0, 0, 12, 0x04, 0xd2, 0x16, 0x2e, 0, 0, 0, 1}, ErrTruncated},
		// A version this relay does not speak. Version 2 (131072) is the
		// interesting one: it was removed from the server in 14 and its
		// startup packet is a different shape, so a relay that forwarded it
		// would be forwarding octets it had not read.
		{"version 2", []byte{0, 0, 0, 8, 0, 2, 0, 0}, ErrVersion},
		{"version 4", []byte{0, 0, 0, 8, 0, 4, 0, 0}, ErrVersion},
	} {
		_, err := ParseStartup(tc.in)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}

	// A parameter list that is not terminated, and one whose key has no value.
	raw := startup(Version3, "user", "alice")
	if _, err := ParseStartup(raw[:len(raw)-1]); err == nil {
		t.Error("an unterminated parameter list was accepted")
	}
	// Trailing rubbish after the terminator is refused rather than trimmed: a
	// server reads the message the sender framed, and a relay that trimmed
	// would decide about a shorter one.
	bad := append(startup(Version3, "user", "alice"), 'x')
	binary.BigEndian.PutUint32(bad[:4], uint32(len(bad)))
	if _, err := ParseStartup(bad); !errors.Is(err, ErrTruncated) {
		t.Errorf("trailing rubbish: %v", err)
	}
}

// The parameter count is a number the peer chooses.
func TestTooManyStartupParametersIsRefused(t *testing.T) {
	kv := make([]string, 0, (MaxStartupParams+2)*2)
	for i := 0; i <= MaxStartupParams; i++ {
		kv = append(kv, "k", "v")
	}
	if _, err := ParseStartup(startup(Version3, kv...)); !errors.Is(err, ErrTooMany) {
		t.Fatalf("%v", err)
	}
}

// msg frames one message the way the wire does.
func msg(typ byte, body ...byte) []byte {
	out := []byte{typ, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(out[1:5], uint32(len(body)+4))
	return append(out, body...)
}

// The length includes itself and excludes the type octet. Getting that
// arithmetic wrong by one loses the framing of every message after it.
func TestTheLengthIncludesItselfAndNotTheType(t *testing.T) {
	stream := bytes.NewReader(append(
		msg(MsgQuery, 'S', 'E', 'L', 'E', 'C', 'T', ' ', '1', 0),
		msg(MsgSync)...))
	rd := NewReader(stream, FromClient, 0)
	m, err := rd.Next()
	if err != nil {
		t.Fatal(err)
	}
	q, err := m.QueryText()
	if err != nil || q != "SELECT 1" {
		t.Fatalf("query %q %v", q, err)
	}
	// Sync has an empty body and a length of exactly four, which a reader that
	// required a body would refuse.
	if m, err = rd.Next(); err != nil {
		t.Fatal(err)
	}
	if m.Type != MsgSync || len(m.Body) != 0 {
		t.Fatalf("sync: %+v", m)
	}
	if m.Name() != "sync" {
		t.Fatalf("name %q", m.Name())
	}
}

// Five octets mean different things in each direction. A relay with one table
// would read a row of somebody's data as a request to describe a portal.
func TestTheSameOctetIsTwoMessages(t *testing.T) {
	for _, tc := range []struct {
		typ            byte
		client, server string
	}{
		{'D', "describe", "data_row"},
		{'S', "sync", "parameter_status"},
		{'C', "close", "command_complete"},
		{'E', "execute", "error_response"},
		{'H', "flush", "copy_out_response"},
	} {
		if got := (Message{Type: tc.typ, Dir: FromClient}).Name(); got != tc.client {
			t.Errorf("%q from client: %s, want %s", tc.typ, got, tc.client)
		}
		if got := (Message{Type: tc.typ, Dir: FromServer}).Name(); got != tc.server {
			t.Errorf("%q from server: %s, want %s", tc.typ, got, tc.server)
		}
	}
	// A type neither side defines is still named, so a refusal can say what it
	// refused rather than printing a raw octet into a log line.
	if got := (Message{Type: 0x7, Dir: FromClient}).Name(); got == "" {
		t.Error("an unknown type has no name")
	}
}

// A message past the bound is refused rather than allocated.
func TestAMessagePastTheBoundIsRefused(t *testing.T) {
	var hdr [5]byte
	hdr[0] = MsgQuery
	binary.BigEndian.PutUint32(hdr[1:5], 1<<30)
	rd := NewReader(bytes.NewReader(hdr[:]), FromClient, 4096)
	if _, err := rd.Next(); !errors.Is(err, ErrTooLong) {
		t.Fatalf("%v", err)
	}
	// And a length that cannot be one.
	binary.BigEndian.PutUint32(hdr[1:5], 3)
	rd = NewReader(bytes.NewReader(hdr[:]), FromClient, 4096)
	if _, err := rd.Next(); !errors.Is(err, ErrShort) {
		t.Fatalf("%v", err)
	}
}

// The extended query protocol is what every modern driver sends, so a relay
// that reads only Query reads nothing.
func TestParseAndBindAreReadBecauseThatIsWhatDriversSend(t *testing.T) {
	body := append([]byte("st1\x00SELECT $1\x00"), 0, 1, 0, 0, 0, 23)
	m := Message{Type: MsgParse, Dir: FromClient, Body: body}
	p, err := m.ReadParse()
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "st1" || p.Statement != "SELECT $1" || p.ParamTypes != 1 {
		t.Fatalf("%+v", p)
	}
	// A declared count that disagrees with what is there is the shape every
	// length-prefixed injection takes.
	short := append([]byte("st1\x00SELECT $1\x00"), 0, 9)
	if _, err = (Message{Type: MsgParse, Dir: FromClient, Body: short}).ReadParse(); !errors.Is(err, ErrTruncated) {
		t.Errorf("a lying parameter count: %v", err)
	}
	// An unterminated string field.
	if _, err = (Message{Type: MsgParse, Dir: FromClient, Body: []byte("st1")}).ReadParse(); !errors.Is(err, ErrNotTerminated) {
		t.Errorf("unterminated: %v", err)
	}

	bind := append([]byte("\x00st1\x00"), 0, 0, 0, 1)
	b, err := (Message{Type: MsgBind, Dir: FromClient, Body: bind}).ReadBind()
	if err != nil {
		t.Fatal(err)
	}
	if b.Portal != "" || b.Statement != "st1" || b.Params != 1 {
		t.Fatalf("%+v", b)
	}
	// Reading a message as the wrong type is an error rather than nonsense.
	if _, err = (Message{Type: MsgQuery, Dir: FromClient}).ReadParse(); err == nil {
		t.Error("a query read as a parse")
	}
	if _, err = (Message{Type: MsgParse, Dir: FromServer, Body: body}).ReadParse(); err == nil {
		t.Error("a backend message read as a frontend parse")
	}
}

// The relay reads the authentication exchange so it can refuse a method that
// puts a reusable credential on the wire.
func TestTheAuthenticationRequestIsReadAndNamed(t *testing.T) {
	for _, tc := range []struct {
		code int32
		name string
		weak bool
	}{
		{AuthOK, "ok", false},
		{AuthCleartextPassword, "password", true},
		{AuthMD5Password, "md5", true},
		{AuthSCMCredential, "scm", true},
		{AuthSASL, "scram", false},
		{AuthSASLContinue, "scram", false},
		{AuthSASLFinal, "scram", false},
		{AuthGSS, "gss", false},
		{AuthKerberosV5, "kerberos", false},
		{AuthSSPI, "sspi", false},
	} {
		if got := AuthName(tc.code); got != tc.name {
			t.Errorf("%d: %s, want %s", tc.code, got, tc.name)
		}
		if got := Weak(tc.code); got != tc.weak {
			t.Errorf("%d weak: %v, want %v", tc.code, got, tc.weak)
		}
		body := binary.BigEndian.AppendUint32(nil, uint32(tc.code)) //nolint:gosec // a protocol constant
		m := Message{Type: MsgAuthentication, Dir: FromServer, Body: body}
		got, err := m.AuthRequest()
		if err != nil || got != tc.code {
			t.Errorf("%d: read back %d %v", tc.code, got, err)
		}
	}
	// A code nobody defined is named rather than dropped, so a log line can
	// say what a server asked for.
	if AuthName(99) == "" {
		t.Error("an unknown method has no name")
	}
	if _, err := (Message{Type: MsgAuthentication, Dir: FromServer, Body: []byte{0}}).AuthRequest(); !errors.Is(err, ErrTruncated) {
		t.Error("a short authentication message was read")
	}
}

// The backend key is the whole of what a cancel request has to present, so the
// relay reads it to know what it is being asked to pass on.
func TestTheBackendKeyIsReadExactly(t *testing.T) {
	body := []byte{0, 0, 0x30, 0x39, 0x11, 0x22, 0x33, 0x44}
	pid, secret, err := (Message{Type: MsgBackendKeyData, Dir: FromServer, Body: body}).BackendKey()
	if err != nil || pid != 12345 || secret != 0x11223344 {
		t.Fatalf("%d %x %v", pid, secret, err)
	}
	// Exactly eight octets: a key data message of any other length is one this
	// relay has not understood.
	for _, n := range []int{0, 4, 7, 9} {
		if _, _, err = (Message{Type: MsgBackendKeyData, Dir: FromServer, Body: make([]byte, n)}).BackendKey(); err == nil {
			t.Errorf("%d octets accepted as a backend key", n)
		}
	}
}

// An error's SQLSTATE is what a client switches on, so the relay reads it to
// recognise an authentication failure without matching on message text.
func TestAnErrorResponseIsReadIntoItsFields(t *testing.T) {
	body := []byte("SFATAL\x00C28P01\x00Mpassword authentication failed\x00\x00")
	f, err := (Message{Type: MsgErrorResponse, Dir: FromServer, Body: body}).ReadError()
	if err != nil {
		t.Fatal(err)
	}
	if SQLState(f) != "28P01" {
		t.Fatalf("sqlstate %q", SQLState(f))
	}
	if ErrorText(f) != "password authentication failed" {
		t.Fatalf("text %q", ErrorText(f))
	}
	// An unterminated field list.
	if _, err = (Message{Type: MsgErrorResponse, Dir: FromServer, Body: []byte("SFATAL")}).ReadError(); !errors.Is(err, ErrNotTerminated) {
		t.Errorf("unterminated: %v", err)
	}
	// And an error with no fields at all still reads, because the terminator
	// is the whole message.
	if f, err = (Message{Type: MsgErrorResponse, Dir: FromServer, Body: []byte{0}}).ReadError(); err != nil || len(f) != 0 {
		t.Errorf("empty: %+v %v", f, err)
	}
}

// What the relay writes has to be readable by the client's own library, and its
// own text must not be able to break the framing.
func TestWhatTheRelayWritesIsWellFormed(t *testing.T) {
	// The relay's refusal quotes a statement's verb, which came off the
	// network. A NUL in it would truncate the field and a newline would split
	// a log line at the other end.
	raw := ErrorResponse("ERROR", "42501", "refused: \x00DROP\nTABLE\x1b]0;x\x07")
	if raw[0] != MsgErrorResponse {
		t.Fatalf("type %q", raw[0])
	}
	if int(binary.BigEndian.Uint32(raw[1:5])) != len(raw)-1 {
		t.Fatalf("length %d for %d octets", binary.BigEndian.Uint32(raw[1:5]), len(raw))
	}
	m := Message{Type: raw[0], Dir: FromServer, Body: raw[5:]}
	f, err := m.ReadError()
	if err != nil {
		t.Fatalf("the relay wrote an error it cannot read: %v", err)
	}
	if SQLState(f) != "42501" {
		t.Fatalf("sqlstate %q", SQLState(f))
	}
	text := ErrorText(f)
	for _, c := range []string{"\x00", "\n", "\x1b", "\x07"} {
		if bytes.Contains([]byte(text), []byte(c)) {
			t.Errorf("a control character survived into %q", text)
		}
	}
	// S and V must agree: clients added V in 9.6 and compare them.
	var sev, vsev string
	for _, fl := range f {
		switch fl.Code {
		case 'S':
			sev = fl.Val
		case 'V':
			vsev = fl.Val
		}
	}
	if sev != "ERROR" || vsev != "ERROR" {
		t.Fatalf("severity %q / %q", sev, vsev)
	}

	rfq := ReadyForQuery('I')
	if len(rfq) != 6 || rfq[0] != MsgReadyForQuery || rfq[5] != 'I' {
		t.Fatalf("ready for query: %q", rfq)
	}
	if int(binary.BigEndian.Uint32(rfq[1:5])) != 5 {
		t.Fatal("ready for query has the wrong length")
	}
}

// A message the relay has no opinion about must cross unchanged, or a server
// newer than this relay would see a request the client did not make.
func TestAMessageIsForwardedAsTheOctetsItWas(t *testing.T) {
	in := msg(MsgQuery, 'S', 'E', 'L', 'E', 'C', 'T', 0)
	rd := NewReader(bytes.NewReader(in), FromClient, 0)
	m, err := rd.Next()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m.Raw(), in) {
		t.Fatalf("round trip: %q != %q", m.Raw(), in)
	}
}

// The startup packet is forwarded as the octets the client sent, for the same
// reason.
func TestTheStartupPacketIsForwardedUnchanged(t *testing.T) {
	in := startup(Version3, "user", "alice", "application_name", "psql")
	rd := NewReader(bytes.NewReader(in), FromClient, 0)
	s, raw, err := rd.ReadStartup()
	if err != nil {
		t.Fatal(err)
	}
	if s.User() != "alice" {
		t.Fatalf("user %q", s.User())
	}
	if !bytes.Equal(raw, in) {
		t.Fatalf("round trip: %q != %q", raw, in)
	}
}

func TestClipBoundsAPeerChosenString(t *testing.T) {
	long := make([]byte, MaxString*2)
	for i := range long {
		long[i] = 'a'
	}
	if got := Clip(string(long)); len(got) > MaxString+3 {
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
