package mysqlwire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// The framing's two traps, which are the reason this reader exists rather than a
// loop over io.ReadFull.
func TestAFullPacketMeansMoreFollows(t *testing.T) {
	// A payload of exactly MaxPayload is a continuation, and the message ends
	// at the first packet that is shorter.
	big := bytes.Repeat([]byte{'a'}, MaxPayload)
	stream := append(Frame(0, big), Frame(1, []byte("tail"))...)
	// Frame() itself produced the right thing: a full packet, the empty
	// terminator, then the next message. Read it back as the reader sees it.
	rd := NewReader(bytes.NewReader(stream), MaxMessage)
	p, err := rd.Next()
	if err != nil {
		t.Fatal(err)
	}
	// Frame(0, big) is a full packet followed by an empty one, so the message
	// is exactly MaxPayload octets in two packets.
	if len(p.Payload) != MaxPayload || p.Packets != 2 {
		t.Fatalf("%d octets in %d packets", len(p.Payload), p.Packets)
	}
}

// A message whose length is an exact multiple of the maximum ends with an empty
// packet. A reader that stopped on "length zero" would end it one packet early,
// and one that stopped only on "not full" gets it right.
func TestAMessageThatIsAnExactMultipleEndsWithAnEmptyPacket(t *testing.T) {
	big := bytes.Repeat([]byte{'b'}, MaxPayload)
	framed := Frame(7, big)
	// Four octets of header, MaxPayload of payload, then four more octets of
	// header for the empty terminator.
	want := 4 + MaxPayload + 4
	if len(framed) != want {
		t.Fatalf("framed to %d octets, want %d", len(framed), want)
	}
	last := framed[len(framed)-4:]
	if last[0] != 0 || last[1] != 0 || last[2] != 0 {
		t.Fatalf("the terminator is not empty: %v", last)
	}
	if last[3] != 8 {
		t.Fatalf("the terminator's sequence is %d, want 8", last[3])
	}
}

// The sequence number is what makes a reassembled message the one the sender
// framed. A relay that ignored it could forward a chain with a gap in it.
func TestAPacketOutOfSequenceIsRefused(t *testing.T) {
	// Two messages, the second numbered wrongly.
	stream := append(Frame(0, []byte("one")), Frame(9, []byte("two"))...)
	rd := NewReader(bytes.NewReader(stream), MaxMessage)
	if _, err := rd.Next(); err != nil {
		t.Fatal(err)
	}
	if _, err := rd.Next(); !errors.Is(err, ErrSequence) {
		t.Fatalf("%v", err)
	}
	// And a continuation with a gap.
	big := bytes.Repeat([]byte{'c'}, MaxPayload)
	bad := append(Frame(0, big)[:4+MaxPayload], 0, 0, 0, 9)
	rd = NewReader(bytes.NewReader(bad), MaxMessage)
	if _, err := rd.Next(); !errors.Is(err, ErrSequence) {
		t.Fatalf("continuation: %v", err)
	}
}

// The protocol puts no bound on a continuation chain, so the relay does.
func TestAReassembledMessagePastTheBoundIsRefused(t *testing.T) {
	big := bytes.Repeat([]byte{'d'}, MaxPayload)
	stream := append(Frame(0, big), Frame(2, big)...)
	rd := NewReader(bytes.NewReader(stream), 4096)
	if _, err := rd.Next(); !errors.Is(err, ErrTooLong) {
		t.Fatalf("%v", err)
	}
}

// An empty payload has no command in it, and reading the next octet of whatever
// followed would be deciding about a command the client did not send.
func TestAnEmptyPayloadHasNoCommand(t *testing.T) {
	rd := NewReader(bytes.NewReader(Frame(0, nil)), MaxMessage)
	p, err := rd.Next()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, ok := p.Command(); ok {
		t.Fatal("an empty payload produced a command")
	}
	rd = NewReader(bytes.NewReader(Frame(0, []byte{ComQuery, 'S'})), MaxMessage)
	if p, err = rd.Next(); err != nil {
		t.Fatal(err)
	}
	c, rest, ok := p.Command()
	if !ok || c != ComQuery || string(rest) != "S" {
		t.Fatalf("%v %q %v", c, rest, ok)
	}
}

// greeting builds a server handshake v10.
func greeting(caps uint32, plugin string) []byte {
	b := []byte{10}
	b = append(b, "8.0.36"...)
	b = append(b, 0)
	b = binary.LittleEndian.AppendUint32(b, 42)    // connection id
	b = append(b, bytes.Repeat([]byte{'x'}, 8)...) // auth data part 1
	b = append(b, 0)                               // filler
	b = binary.LittleEndian.AppendUint16(b, uint16(caps&0xffff))
	b = append(b, 0x2d) // charset
	b = binary.LittleEndian.AppendUint16(b, 2)
	b = binary.LittleEndian.AppendUint16(b, uint16(caps>>16))
	b = append(b, 21)                             // auth plugin data length
	b = append(b, bytes.Repeat([]byte{0}, 10)...) // reserved
	if caps&CapSecureConnection != 0 {
		b = append(b, bytes.Repeat([]byte{'y'}, 13)...)
	}
	if caps&CapPluginAuth != 0 {
		b = append(b, plugin...)
		b = append(b, 0)
	}
	return b
}

const baseCaps = CapProtocol41 | CapSecureConnection | CapPluginAuth

func TestTheGreetingIsReadForItsCapabilitiesAndPlugin(t *testing.T) {
	g, err := ParseGreeting(greeting(baseCaps|CapSSL|CapLocalFiles, AuthCachingSHA2))
	if err != nil {
		t.Fatal(err)
	}
	if g.Version != "8.0.36" || g.ConnID != 42 || g.Plugin != AuthCachingSHA2 {
		t.Fatalf("%+v", g)
	}
	if !g.Offers(CapSSL) {
		t.Error("the ssl capability was not read")
	}
	if !g.Offers(CapLocalFiles) {
		t.Error("the local_files capability was not read")
	}
	if g.Offers(CapMultiStatements) {
		t.Error("a capability the server did not offer was read as offered")
	}
	// A server that does not offer TLS is the case a relay has to be able to
	// see, because that is the downgrade: with the flag cleared, a client never
	// asks.
	g, err = ParseGreeting(greeting(baseCaps, AuthNative))
	if err != nil {
		t.Fatal(err)
	}
	if g.Offers(CapSSL) {
		t.Fatal("ssl read as offered when it was not")
	}
}

// What must not parse as a greeting.
func TestTheGreetingsThatAreNotGreetings(t *testing.T) {
	for name, in := range map[string][]byte{
		"nothing":           {},
		"an error packet":   {0xff, 0x10, 0x04},
		"protocol 9":        {9, 'x', 0},
		"protocol 11":       {11, 'x', 0},
		"no version string": {10, 'x', 'y'},
		"truncated header":  append([]byte{10}, append([]byte("8.0"), 0, 1, 2)...),
	} {
		if _, err := ParseGreeting(in); err == nil {
			t.Errorf("%s was accepted as a greeting", name)
		}
	}
	// Protocol 9 is the interesting one: it is the pre-4.0 handshake, a
	// different shape, so a relay that guessed would be forwarding octets it
	// had not read.
	if _, err := ParseGreeting([]byte{9, 'x', 0}); !errors.Is(err, ErrProtocol) {
		t.Error("protocol 9 was not refused as a version")
	}
}

// login builds a client handshake response.
func login(caps uint32, user, db, plugin string, attrs map[string]string) []byte {
	b := binary.LittleEndian.AppendUint32(nil, caps)
	b = binary.LittleEndian.AppendUint32(b, 1<<24)
	b = append(b, 0x2d)
	b = append(b, bytes.Repeat([]byte{0}, 23)...)
	if caps&CapSSL != 0 && user == "" {
		return b // the short form sent before a TLS handshake
	}
	b = append(b, user...)
	b = append(b, 0)
	b = append(b, 20)                               // auth response length
	b = append(b, bytes.Repeat([]byte{'z'}, 20)...) // the verifier
	if caps&CapConnectWithDB != 0 {
		b = append(b, db...)
		b = append(b, 0)
	}
	if caps&CapPluginAuth != 0 {
		b = append(b, plugin...)
		b = append(b, 0)
	}
	if caps&CapConnectAttrs != 0 {
		var blob []byte
		for k, v := range attrs {
			blob = append(blob, byte(len(k)))
			blob = append(blob, k...)
			blob = append(blob, byte(len(v)))
			blob = append(blob, v...)
		}
		b = append(b, byte(len(blob)))
		b = append(b, blob...)
	}
	return b
}

func TestTheLoginIsReadForItsIdentityAndCapabilities(t *testing.T) {
	caps := baseCaps | CapConnectWithDB | CapConnectAttrs | CapMultiStatements
	l, err := ParseLogin(login(caps, "alice", "sales", AuthCachingSHA2,
		map[string]string{"_client_name": "libmysql"}))
	if err != nil {
		t.Fatal(err)
	}
	if l.User != "alice" || l.Database != "sales" || l.Plugin != AuthCachingSHA2 {
		t.Fatalf("%+v", l)
	}
	if !l.Wants(CapMultiStatements) {
		t.Error("multi_statements was not read")
	}
	if l.Attrs["_client_name"] != "libmysql" {
		t.Fatalf("attrs: %+v", l.Attrs)
	}
	if l.SSLOnly {
		t.Error("a full response was read as the short form")
	}
}

// The short form a client sends before its TLS handshake is 32 octets and
// nothing else. Reading it as a truncated full response would refuse every TLS
// client there is.
func TestTheShortFormBeforeTLSIsRecognised(t *testing.T) {
	l, err := ParseLogin(login(baseCaps|CapSSL, "", "", "", nil))
	if err != nil {
		t.Fatal(err)
	}
	if !l.SSLOnly {
		t.Fatal("the short form was not recognised")
	}
	if !l.Wants(CapSSL) {
		t.Fatal("the ssl capability was not read from the short form")
	}
	// Without the ssl flag, 32 octets and nothing else is genuinely truncated.
	if _, err = ParseLogin(login(baseCaps, "", "", "", nil)[:32]); err == nil {
		t.Fatal("a truncated response without the ssl flag was accepted")
	}
}

// A client that does not offer protocol 4.1 sends a different shape, and a relay
// that read it as a 4.1 response would decide about fields that are not there.
func TestALoginWithoutProtocol41IsRefused(t *testing.T) {
	if _, err := ParseLogin(login(CapSecureConnection, "alice", "", "", nil)); !errors.Is(err, ErrProtocol) {
		t.Fatalf("%v", err)
	}
}

// COM_CHANGE_USER re-authenticates mid-connection. A relay that did not read it
// would have a user policy that applied to the first message and nothing after.
func TestChangeUserIsReadSoTheIdentityPolicyKeepsApplying(t *testing.T) {
	payload := []byte("bob\x00")
	payload = append(payload, 20)
	payload = append(payload, bytes.Repeat([]byte{'z'}, 20)...)
	payload = append(payload, "hr\x00"...)
	payload = binary.LittleEndian.AppendUint16(payload, 0x2d)
	payload = append(payload, AuthNative...)
	payload = append(payload, 0)

	cu, err := ReadChangeUser(payload, baseCaps)
	if err != nil {
		t.Fatal(err)
	}
	if cu.User != "bob" || cu.Database != "hr" || cu.Plugin != AuthNative {
		t.Fatalf("%+v", cu)
	}
	// A payload that stops after the database is still a valid change-user.
	short := []byte("bob\x00")
	short = append(short, 0)
	short = append(short, "hr\x00"...)
	if cu, err = ReadChangeUser(short, baseCaps); err != nil || cu.User != "bob" || cu.Database != "hr" {
		t.Fatalf("short: %+v %v", cu, err)
	}
	if _, err = ReadChangeUser([]byte("nobodyterminatesthis"), baseCaps); err == nil {
		t.Error("an unterminated change-user was accepted")
	}
}

// COM_SET_OPTION is what makes a handshake-only capability policy decorative: it
// turns multi-statement support on after the handshake is over.
func TestSetOptionCanTurnMultiStatementsOnAfterTheHandshake(t *testing.T) {
	on, ok := SetOptionMultiStatements([]byte{0, 0})
	if !ok || !on {
		t.Fatalf("option 0 (on): %v %v", on, ok)
	}
	if on, ok = SetOptionMultiStatements([]byte{1, 0}); !ok || on {
		t.Fatalf("option 1 (off): %v %v", on, ok)
	}
	// A value nobody defined, and a payload too short to be one, are both
	// unreadable rather than guessed at.
	if _, ok = SetOptionMultiStatements([]byte{7, 0}); ok {
		t.Error("an undefined option value was read")
	}
	if _, ok = SetOptionMultiStatements([]byte{0}); ok {
		t.Error("a one-octet payload was read as an option")
	}
}

// The packet that asks the client for a file is the whole reason local_files
// matters, and a relay that did not recognise it would forward a file request as
// if it were data.
func TestTheLocalInfileRequestIsRecognised(t *testing.T) {
	payload := append([]byte{RespLocalInfile}, "/etc/passwd"...)
	path, ok := LocalInfilePath(payload)
	if !ok || path != "/etc/passwd" {
		t.Fatalf("%q %v", path, ok)
	}
	if _, ok = LocalInfilePath([]byte{RespOK}); ok {
		t.Error("an OK packet was read as a file request")
	}
	if _, ok = LocalInfilePath(nil); ok {
		t.Error("an empty payload was read as a file request")
	}
	// The path is clipped, because a hostile server chooses it and it goes in
	// a log line.
	long := append([]byte{RespLocalInfile}, bytes.Repeat([]byte{'a'}, MaxString*3)...)
	if path, _ = LocalInfilePath(long); len(path) > MaxString+3 {
		t.Fatalf("an unclipped path: %d octets", len(path))
	}
}

// The capability and command vocabularies are what a configuration writes, so a
// name has to round-trip.
func TestTheNamesAConfigurationWritesRoundTrip(t *testing.T) {
	for _, n := range CapNames() {
		bit, ok := CapOf(n)
		if !ok {
			t.Errorf("%s is listed but not readable", n)
			continue
		}
		if got := CapName(bit); got != n {
			t.Errorf("%s round-tripped to %s", n, got)
		}
	}
	if _, ok := CapOf("nonsense"); ok {
		t.Error("a capability that is not one was accepted")
	}
	for _, n := range CommandNames() {
		c, ok := CommandOf(n)
		if !ok {
			t.Errorf("%s is listed but not readable", n)
			continue
		}
		if got := CommandName(c); got != n {
			t.Errorf("%s round-tripped to %s", n, got)
		}
	}
	if _, ok := CommandOf("nonsense"); ok {
		t.Error("a command that is not one was accepted")
	}
	// A code nobody defined is still named, so a refusal can say what it
	// refused rather than printing a raw octet.
	if CommandName(0x7f) == "" {
		t.Error("an unknown command has no name")
	}
}

// The default command list is the security claim: what an application driver
// sends, and nothing administrative.
func TestTheDefaultCommandListLeavesOutTheAdministrativeOnes(t *testing.T) {
	def := map[byte]bool{}
	for _, c := range DefaultCommands() {
		def[c] = true
	}
	for _, c := range []byte{ComShutdown, ComDebug, ComProcessKill, ComBinlogDump,
		ComBinlogDumpGTID, ComRegisterSlave, ComTableDump, ComCreateDB, ComDropDB,
		ComRefresh, ComProcessInfo, ComClone, ComFieldList} {
		if def[c] {
			t.Errorf("%s is allowed by default", CommandName(c))
		}
	}
	for _, c := range []byte{ComQuery, ComStmtPrepare, ComStmtExecute, ComPing, ComQuit} {
		if !def[c] {
			t.Errorf("%s is not allowed by default, which breaks every driver", CommandName(c))
		}
	}
}

// The weak-plugin judgement is a deliberate line, so it is asserted in both
// directions.
func TestWeakAuthIsTheCleartextAndBrokenOnesOnly(t *testing.T) {
	for _, p := range []string{AuthClearText, AuthOld} {
		if !WeakAuth(p) {
			t.Errorf("%s is not counted weak", p)
		}
	}
	// mysql_native_password is deliberately not weak: its challenge-response
	// discloses no reusable secret, and calling it weak would make the setting
	// one operators turn off wholesale.
	for _, p := range []string{AuthNative, AuthCachingSHA2, AuthSHA256, AuthGSSAPI} {
		if WeakAuth(p) {
			t.Errorf("%s is counted weak", p)
		}
	}
}

// A length-encoded integer is the protocol's own encoding, and 0xfb is NULL
// rather than a length -- reading it as one gives a length of zero where the
// sender meant absent.
func TestTheLengthEncodedIntegerReader(t *testing.T) {
	for _, tc := range []struct {
		in   []byte
		want uint64
		ok   bool
	}{
		{[]byte{0}, 0, true},
		{[]byte{250}, 250, true},
		{[]byte{0xfc, 0x01, 0x01}, 257, true},
		{[]byte{0xfd, 1, 0, 0}, 1, true},
		{[]byte{0xfe, 1, 0, 0, 0, 0, 0, 0, 0}, 1, true},
		{[]byte{0xfb}, 0, false},    // NULL is not a length
		{[]byte{0xff}, 0, false},    // an error marker is not a length
		{[]byte{0xfc, 1}, 0, false}, // truncated
		{[]byte{}, 0, false},
		// Eight octets can express more than any bound allows, and the reader
		// refuses rather than trusting it.
		{[]byte{0xfe, 0, 0, 0, 0, 0, 0, 0, 1}, 0, false},
	} {
		got, _, err := lenEncInt(tc.in)
		if (err == nil) != tc.ok {
			t.Errorf("%v: err %v, want ok=%v", tc.in, err, tc.ok)
			continue
		}
		if tc.ok && got != tc.want {
			t.Errorf("%v: %d, want %d", tc.in, got, tc.want)
		}
	}
}

// What the relay writes has to be readable by a client library, and its own text
// must not be able to break the framing.
func TestWhatTheRelayWritesIsWellFormed(t *testing.T) {
	raw := ErrPacket(1, StatementDenied, "42000", "refused: \x00DROP\nTABLE\x1b]0;x\x07")
	// Header, then the payload.
	if len(raw) < 4 {
		t.Fatal("too short")
	}
	n := int(raw[0]) | int(raw[1])<<8 | int(raw[2])<<16
	if n != len(raw)-4 {
		t.Fatalf("length %d for %d payload octets", n, len(raw)-4)
	}
	if raw[3] != 1 {
		t.Fatalf("sequence %d", raw[3])
	}
	e, err := ReadError(raw[4:], CapProtocol41)
	if err != nil {
		t.Fatalf("the relay wrote an error it cannot read: %v", err)
	}
	if e.Code != StatementDenied || e.State != "42000" {
		t.Fatalf("%+v", e)
	}
	for _, c := range []string{"\x00", "\n", "\x1b", "\x07"} {
		if strings.Contains(e.Text, c) {
			t.Errorf("a control character survived into %q", e.Text)
		}
	}
	// A state that is not five characters is replaced rather than written
	// short, because a client reads a fixed five octets there.
	raw = ErrPacket(0, AccessDenied, "x", "no")
	if e, err = ReadError(raw[4:], CapProtocol41); err != nil || e.State != "HY000" {
		t.Fatalf("a short state: %+v %v", e, err)
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

// Stripping a capability from the greeting is how a client is stopped from
// negotiating something dangerous *without* breaking the connection.
func TestStrippingACapabilityFromTheGreeting(t *testing.T) {
	g := greeting(baseCaps|CapSSL|CapLocalFiles|CapMultiStatements|CapCompress, AuthCachingSHA2)
	cleared, err := StripCaps(g, CapLocalFiles|CapMultiStatements)
	if err != nil {
		t.Fatal(err)
	}
	if cleared != CapLocalFiles|CapMultiStatements {
		t.Fatalf("cleared %#x", cleared)
	}
	// Read it back: the two are gone and everything else is untouched. The
	// second part matters most -- a relay that cleared more than it meant to
	// would break TLS or authentication while looking like it was helping.
	parsed, err := ParseGreeting(g)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Offers(CapLocalFiles) || parsed.Offers(CapMultiStatements) {
		t.Fatal("a stripped capability is still offered")
	}
	for _, keep := range []uint32{CapSSL, CapCompress, CapProtocol41,
		CapSecureConnection, CapPluginAuth} {
		if !parsed.Offers(keep) {
			t.Errorf("%s was cleared and should not have been", CapName(keep))
		}
	}
	if parsed.Plugin != AuthCachingSHA2 || parsed.ConnID != 42 {
		t.Fatalf("the rest of the greeting changed: %+v", parsed)
	}

	// Only bits the server actually offered are reported as cleared, so a log
	// line says what changed rather than what was asked for.
	g2 := greeting(baseCaps, AuthNative)
	if cleared, err = StripCaps(g2, CapLocalFiles|CapMultiStatements); err != nil {
		t.Fatal(err)
	}
	if cleared != 0 {
		t.Fatalf("reported clearing %s from a greeting that offered neither", CapList(cleared))
	}
	// And a greeting it cannot read is an error rather than a silent no-op,
	// because a no-op here is a capability that crossed unstripped.
	if _, err = StripCaps([]byte{10, 'x'}, CapLocalFiles); err == nil {
		t.Error("an unterminated greeting was stripped silently")
	}
	if _, err = StripCaps(nil, CapLocalFiles); err == nil {
		t.Error("an empty greeting was stripped silently")
	}
}

func TestCapListNamesWhatIsSet(t *testing.T) {
	got := CapList(CapSSL | CapLocalFiles)
	if len(got) != 2 {
		t.Fatalf("%v", got)
	}
	joined := strings.Join(got, ",")
	if !strings.Contains(joined, "ssl") || !strings.Contains(joined, "local_files") {
		t.Fatalf("%v", got)
	}
	if len(CapList(0)) != 0 {
		t.Error("an empty mask named something")
	}
}
