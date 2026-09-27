package mysqlwire

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// The server's side of the wire, read back by this package's own reader and
// checked against the octets the protocol specifies.
//
// A fabricated server's packets have to be the ones a client library expects, and
// the two ways to be sure of that are to read them back with an independent
// parser and to write the bytes out. Both are done here; asserting that the
// builder agrees with itself would say nothing.

// The thresholds of a length-encoded integer, which are the protocol's own and
// are not powers of two: 251 is where the one-octet form stops, because 0xFB
// through 0xFF are markers. A writer using 255 produces a value the reader takes
// for NULL.
func TestLengthEncodedIntegersUseTheProtocolsOwnThresholds(t *testing.T) {
	for _, tc := range []struct {
		v    uint64
		want []byte
	}{
		{0, []byte{0}},
		{1, []byte{1}},
		{250, []byte{250}},
		// 251 is the first value that cannot be one octet, because 0xFB is the
		// NULL marker.
		{251, []byte{0xFC, 0xFB, 0x00}},
		{0xFFFF, []byte{0xFC, 0xFF, 0xFF}},
		{0x10000, []byte{0xFD, 0x00, 0x00, 0x01}},
		{0xFFFFFF, []byte{0xFD, 0xFF, 0xFF, 0xFF}},
		{0x1000000, []byte{0xFE, 0x00, 0x00, 0x00, 0x01, 0, 0, 0, 0}},
	} {
		if got := AppendLenEncInt(nil, tc.v); !bytes.Equal(got, tc.want) {
			t.Errorf("%d encoded as %x, want %x", tc.v, got, tc.want)
		}
		// And it reads back, which is the round trip through the parser this
		// package already has.
		back, _, err := lenEncInt(AppendLenEncInt(nil, tc.v))
		if err != nil {
			t.Errorf("%d: %v", tc.v, err)
		} else if back != tc.v {
			t.Errorf("%d read back as %d", tc.v, back)
		}
	}
	// A string is its length followed by its octets, and the length crossing the
	// 251 boundary is where a writer that used a fixed width goes wrong.
	for _, n := range []int{0, 1, 250, 251, 300, 70000} {
		s := strings.Repeat("x", n)
		got, rest, err := lenEncString(AppendLenEncString(nil, s))
		if err != nil {
			t.Errorf("a string of %d: %v", n, err)
			continue
		}
		if len(got) != n {
			t.Errorf("a string of %d read back as %d", n, len(got))
		}
		if len(rest) != 0 {
			t.Errorf("a string of %d left %d octets over", n, len(rest))
		}
	}
}

// The greeting, which is the only packet a server sends unprompted and the one
// every scanner reads.
func TestTheGreetingIsOneAClientCanRead(t *testing.T) {
	salt := []byte("abcdefghijklmnopqrst")
	raw := Greet(GreetingOptions{
		Version: "8.0.36-0ubuntu0.22.04.1", ThreadID: 4242, Salt: salt,
		Caps: CapProtocol41 | CapSecureConnection | CapPluginAuth, Charset: 255,
		AuthPlugin: "caching_sha2_password",
	})
	g, err := ParseGreeting(payloadOf(t, raw))
	if err != nil {
		t.Fatalf("the greeting does not parse: %v", err)
	}
	if g.Version != "8.0.36-0ubuntu0.22.04.1" {
		t.Errorf("version %q", g.Version)
	}
	if !g.Offers(CapProtocol41) || !g.Offers(CapSecureConnection) {
		t.Errorf("caps %08x: every client library written this century needs both", g.Caps)
	}
	if g.Offers(CapSSL) {
		t.Error("the greeting offered TLS without being asked to")
	}
	// The sequence number of a greeting is zero: it is the first packet of the
	// connection, and a client that read anything else reports a protocol error
	// before it has sent a thing.
	if raw[3] != 0 {
		t.Errorf("the greeting is packet %d", raw[3])
	}
	// A salt of the wrong length is replaced rather than sent, because a
	// challenge no client can answer is a connection that fails at the far end
	// for a reason nobody can see from here.
	short := Greet(GreetingOptions{Version: "8.0.36", Salt: []byte("abc"),
		Caps: CapProtocol41 | CapSecureConnection | CapPluginAuth})
	if _, err := ParseGreeting(payloadOf(t, short)); err != nil {
		t.Errorf("a greeting with a short salt does not parse: %v", err)
	}
	// A version string with a NUL in it would truncate the field it is in and
	// everything after it would be read as something else.
	dirty := Greet(GreetingOptions{Version: "8.0\x0036-evil", Salt: salt,
		Caps: CapProtocol41 | CapSecureConnection | CapPluginAuth})
	dg, err := ParseGreeting(payloadOf(t, dirty))
	if err != nil {
		t.Fatalf("a greeting with a NUL in its version does not parse: %v", err)
	}
	// The whole string survives, with the NUL replaced. A writer that passed it
	// through would have the version field end at the NUL and everything after
	// it -- the thread identifier, the challenge, the capabilities -- read as
	// something else, which is a greeting no client can use and a failure that
	// looks like a network fault from the far end.
	if dg.Version != "8.0 36-evil" {
		t.Errorf("the version read back as %q", dg.Version)
	}
	// The status flags, which sit at a fixed offset after the version's NUL, the
	// thread identifier, the first half of the challenge, the filler, the lower
	// capability half and the charset. The value is SERVER_STATUS_AUTOCOMMIT: a
	// client that read zero there would believe the connection was inside a
	// transaction nobody opened.
	p := payloadOf(t, raw)
	at := 1 + len("8.0.36-0ubuntu0.22.04.1") + 1 + 4 + 8 + 1 + 2 + 1
	if got := binary.LittleEndian.Uint16(p[at:]); got != 2 {
		t.Errorf("the greeting's status flags are %04x, want the autocommit bit", got)
	}
}

// OK and EOF, which are how a command ends.
func TestTheTerminatorsCarryTheStateAClientReads(t *testing.T) {
	ok := payloadOf(t, OKPacket(1, 3, 0, 0, ""))
	if ok[0] != RespOK {
		t.Errorf("an OK packet starts %02x", ok[0])
	}
	affected, rest, err := lenEncInt(ok[1:])
	if err != nil || affected != 3 {
		t.Errorf("affected rows read back as %d: %v", affected, err)
	}
	_, rest, err = lenEncInt(rest)
	if err != nil {
		t.Fatal(err)
	}
	// SERVER_STATUS_AUTOCOMMIT. A library that read zero here would believe the
	// connection was inside a transaction nobody opened.
	if status := binary.LittleEndian.Uint16(rest); status != 2 {
		t.Errorf("status flags %04x, want the autocommit bit", status)
	}
	eof := payloadOf(t, EOFPacket(1, 0))
	if eof[0] != RespEOF {
		t.Errorf("an EOF packet starts %02x", eof[0])
	}
	if len(eof) != 5 {
		t.Errorf("an EOF packet is %d octets, and the protocol's is five", len(eof))
	}
}

// A whole result set, in both of the shapes a client can ask for.
//
// CLIENT_DEPRECATE_EOF replaces the two EOF packets with nothing and an OK. A
// client that asked for the new shape and received the old one stops reading
// where it expected more, which is a stalled connection rather than an error.
func TestAResultSetIsTheShapeTheClientNegotiated(t *testing.T) {
	cols := []Column{
		{Name: "Variable_name", Table: "variables", Type: TypeVarString, Length: 64},
		{Name: "Value", Table: "variables", Type: TypeVarString, Length: 255},
	}
	rows := [][]*string{
		{Str("version"), Str("8.0.36")},
		{Str("datadir"), Str("/var/lib/mysql/")},
		{Str("secure_file_priv"), nil},
	}
	for _, deprecate := range []bool{false, true} {
		raw, next := ResultSet(1, cols, rows, deprecate)
		packets := splitPackets(t, raw)
		// The count, two definitions, three rows, plus the terminators.
		want := 1 + len(cols) + len(rows) + 1
		if !deprecate {
			want++ // both EOFs
		}
		if len(packets) != want {
			t.Fatalf("deprecate=%v: %d packets, want %d", deprecate, len(packets), want)
		}
		// The numbering is contiguous from where it was told to start, because a
		// client library checks it and a gap makes it report a protocol error
		// rather than the rows.
		for i, p := range packets {
			if got := p[3]; got != byte(1+i) {
				t.Errorf("deprecate=%v: packet %d is numbered %d", deprecate, i, got)
			}
		}
		if next != byte(1+len(packets)) {
			t.Errorf("deprecate=%v: the next sequence is %d after %d packets", deprecate, next, len(packets))
		}
		// The column count comes first and says two.
		if n, _, err := lenEncInt(packets[0][4:]); err != nil || n != 2 {
			t.Errorf("the column count read back as %d: %v", n, err)
		}
		// The terminator is the one the negotiation asked for.
		last := packets[len(packets)-1][4]
		if deprecate && last != RespOK {
			t.Errorf("with CLIENT_DEPRECATE_EOF the set ends %02x, want OK", last)
		}
		if !deprecate && last != RespEOF {
			t.Errorf("without CLIENT_DEPRECATE_EOF the set ends %02x, want EOF", last)
		}
		// A NULL is 0xFB and not an empty string, which a library distinguishes.
		rowStart := 1 + len(cols)
		if !deprecate {
			rowStart++
		}
		third := packets[rowStart+2][4:]
		_, rest, err := lenEncString(third)
		if err != nil {
			t.Fatal(err)
		}
		if len(rest) == 0 || rest[0] != 0xFB {
			t.Errorf("a NULL value was written as %x", rest)
		}
	}
	// An empty result set is a column count, the definitions and the
	// terminators, with no rows: what a SELECT that matched nothing returns, and
	// not the same thing as an error.
	raw, _ := ResultSet(1, cols, nil, false)
	if got := len(splitPackets(t, raw)); got != 1+len(cols)+2 {
		t.Errorf("an empty result set is %d packets", got)
	}
}

// A column definition, read back field by field: this is the packet a client
// library reads to decide how to convert every value after it.
func TestAColumnDefinitionIsTheProtocolFourOneForm(t *testing.T) {
	p := payloadOf(t, ColumnDef(2, Column{Name: "id", Table: "users", Type: TypeLongLong, Length: 20}))
	for i, want := range []string{"def", "", "users", "users", "id", "id"} {
		got, rest, err := lenEncString(p)
		if err != nil {
			t.Fatalf("field %d: %v", i, err)
		}
		if got != want {
			t.Errorf("field %d is %q, want %q", i, got, want)
		}
		p = rest
	}
	// The fixed-length block that follows is declared as twelve octets, and a
	// client reads exactly that many.
	if len(p) == 0 || p[0] != 0x0C {
		t.Fatalf("the fixed block is declared as %x", p)
	}
	if len(p) != 1+12 {
		t.Errorf("the fixed block is %d octets, and the protocol's is twelve", len(p)-1)
	}
	if got := p[1+2+4]; got != TypeLongLong {
		t.Errorf("the column type read back as %02x", got)
	}
	// A definition with nothing set still has a usable type and width, because a
	// column of type zero is one a library cannot convert.
	q := payloadOf(t, ColumnDef(2, Column{Name: "x"}))
	for i := 0; i < 6; i++ {
		_, q, _ = lenEncString(q)
	}
	if got := q[1+2+4]; got == 0 {
		t.Error("a column with no type declared type zero")
	}
}

// payloadOf reads the single packet in a frame and returns its payload.
func payloadOf(t *testing.T, raw []byte) []byte {
	t.Helper()
	p := splitPackets(t, raw)
	if len(p) != 1 {
		t.Fatalf("%d packets, want one", len(p))
	}
	return p[0][4:]
}

// splitPackets reads a stream of wire packets, which is a second implementation
// of the framing rather than a reuse of the one under test.
func splitPackets(t *testing.T, raw []byte) [][]byte {
	t.Helper()
	var out [][]byte
	for len(raw) > 0 {
		if len(raw) < 4 {
			t.Fatalf("%d octets left over, which is less than a header", len(raw))
		}
		n := int(raw[0]) | int(raw[1])<<8 | int(raw[2])<<16
		if len(raw) < 4+n {
			t.Fatalf("a packet declares %d octets and %d are left", n, len(raw)-4)
		}
		out = append(out, raw[:4+n])
		raw = raw[4+n:]
	}
	return out
}
