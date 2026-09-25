package tds

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	wire "github.com/rom/xproxy/internal/tdswire"
	"github.com/rom/xproxy/internal/testutil"
)

// fakeServer is a SQL Server: enough of one to negotiate PRELOGIN, accept a
// LOGIN7, and record every message, procedure and statement that reached it.
//
// What got through is the assertion that matters. A test that checked only the
// client's error would pass against a relay that answered the client with a
// refusal and forwarded the message anyway -- which is the bug that actually
// happens.
type fakeServer struct {
	ln net.Listener
	// encryption is what the server answers the relay's PRELOGIN with.
	encryption byte

	mu sync.Mutex
	// types is every message type the server saw, procs every procedure name,
	// stmts every batch text, and askedFor what the relay asked it to encrypt.
	types    []byte
	procs    []string
	stmts    []string
	askedFor byte
	logins   int
	users    []string
}

func startFake(t *testing.T, s *fakeServer) *fakeServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.ln = ln
	t.Cleanup(func() { _ = ln.Close() })
	go s.serve()
	return s
}

func (s *fakeServer) addr() string { return s.ln.Addr().String() }

func (s *fakeServer) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.session(c)
	}
}

func (s *fakeServer) session(c net.Conn) {
	defer func() { _ = c.Close() }()
	rd := wire.NewReader(c, wire.MaxMessage)
	p, err := rd.Next()
	if err != nil || p.Type != wire.TypePreLogin {
		return
	}
	pre, err := wire.ParsePreLogin(p.Payload)
	if err != nil {
		return
	}
	s.mu.Lock()
	s.askedFor = pre.Encryption
	s.mu.Unlock()
	answer := s.encryption
	out := wire.BuildPreLogin([]wire.PreLoginOption{
		{Token: wire.PreLoginVersion, Value: []byte{16, 0, 0x03, 0xe8, 0, 0}},
		{Token: wire.PreLoginEncryption, Value: []byte{answer}},
		{Token: wire.PreLoginInstOpt, Value: []byte{0}},
	})
	if _, err = c.Write(wire.Frame(wire.TypePreLogin, 77, out, 4096)); err != nil {
		return
	}
	// This fake never encrypts: the relay's upstream leg is set to disable in
	// every test that uses it, because a second TLS stack in the fixture would
	// be testing crypto/tls rather than the relay.
	for {
		p, err := rd.Next()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.types = append(s.types, p.Type)
		switch p.Type {
		case wire.TypeLogin7:
			s.logins++
			if l, err := wire.ParseLogin7(p.Payload); err == nil {
				s.users = append(s.users, l.User)
			}
		case wire.TypeSQLBatch:
			if txt, err := wire.SQLText(p.Payload); err == nil {
				s.stmts = append(s.stmts, txt)
			}
		case wire.TypeRPC:
			if r, err := wire.ParseRPC(p.Payload); err == nil {
				s.procs = append(s.procs, r.Procedure())
				if r.HasStatement {
					s.stmts = append(s.stmts, r.Statement)
				}
			}
		}
		s.mu.Unlock()
		// A DONE token is enough to make a client's read return.
		if _, err = c.Write(wire.Frame(wire.TypeTabularResult, 77,
			[]byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0}, 4096)); err != nil {
			return
		}
	}
}

func (s *fakeServer) saw() (types []byte, procs, stmts []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.types...),
		append([]string(nil), s.procs...), append([]string(nil), s.stmts...)
}

func (s *fakeServer) asked() byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.askedFor
}

const tdsYAML = `
version: 1
server:
  listeners:
    - name: db
      address: "127.0.0.1:0"
      kind: tds
      tds:
%s
logging: {access: {enabled: false}}
upstreams:
  - {name: sql, endpoints: [{address: %q}]}
`

func relayFor(t *testing.T, section, serverAddr string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(tdsYAML, section, serverAddr))
	return s, proxytest.Addr(t, s, "db")
}

// base is a listener with the transport security deliberately off on both legs.
//
// Every test using it is about the policy rather than the transport, and a
// fixture that ran two TLS stacks to check a statement classifier would be
// testing crypto/tls. allow_cleartext_password has to be named for the same
// reason: with it unset the relay refuses a plaintext login before any of these
// tests get as far as a statement, which is the right behaviour and is asserted
// on its own below.
const base = "        upstream: sql\n" +
	"        require_tls: false\n" +
	"        upstream_tls_mode: disable\n" +
	"        allow_cleartext_password: true\n" +
	"        default_action: allow\n"

// client is a minimal TDS client.
type client struct {
	c    net.Conn
	rd   *wire.Reader
	pre  *wire.PreLogin
	size int
}

// dial connects, sends PRELOGIN with the encryption value given, and reads the
// relay's answer -- which is the value the relay decided, not the one the server
// sent.
func dial(t *testing.T, addr string, asked byte) *client {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	body := wire.BuildPreLogin([]wire.PreLoginOption{
		{Token: wire.PreLoginVersion, Value: []byte{17, 0, 0, 0, 0, 0}},
		{Token: wire.PreLoginEncryption, Value: []byte{asked}},
	})
	if _, err = c.Write(wire.Frame(wire.TypePreLogin, 0, body, 4096)); err != nil {
		t.Fatal(err)
	}
	rd := wire.NewReader(c, wire.MaxMessage)
	p, err := rd.Next()
	if err != nil {
		t.Fatal(err)
	}
	pre, err := wire.ParsePreLogin(p.Payload)
	if err != nil {
		t.Fatal(err)
	}
	return &client{c: c, rd: rd, pre: pre, size: 4096}
}

// login sends a LOGIN7 and reads whatever comes back.
func (cl *client) login(t *testing.T, user, db, app string, pass bool, integrated bool) wire.Packet {
	t.Helper()
	pw := ""
	if pass {
		pw = "hunter2"
	}
	body := login7(user, pw, db, app, integrated)
	if _, err := cl.c.Write(wire.Frame(wire.TypeLogin7, 0, body, cl.size)); err != nil {
		t.Fatal(err)
	}
	p, err := cl.rd.Next()
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	return p
}

// send writes one message and reads the answer.
func (cl *client) send(t *testing.T, typ byte, body []byte) wire.Packet {
	t.Helper()
	if _, err := cl.c.Write(wire.Frame(typ, 0, body, cl.size)); err != nil {
		t.Fatal(err)
	}
	p, err := cl.rd.Next()
	if err != nil {
		t.Fatalf("send %s: %v", wire.TypeName(typ), err)
	}
	return p
}

// batch sends a SQLBATCH.
func (cl *client) batch(t *testing.T, sql string) wire.Packet {
	t.Helper()
	return cl.send(t, wire.TypeSQLBatch, wire.ToUCS2(sql))
}

// refusedWith says whether the answer is the relay's error token, and with what
// number.
func refusedWith(p wire.Packet) (int32, bool) {
	return wire.ErrorNumber(p.Payload)
}

// login7 builds a LOGIN7 body the way a client does.
func login7(user, pass, db, app string, integrated bool) []byte {
	fields := []string{"WS01", user, pass, app, "sqlhost", "", "ODBC", "us_english", db}
	const fixed = 36
	head := fixed + len(fields)*4
	var vals []byte
	offs := make([][2]uint16, len(fields))
	for i, s := range fields {
		enc := wire.ToUCS2(s)
		if i == 2 {
			enc = wire.Obfuscate(enc)
		}
		offs[i] = [2]uint16{uint16(head + len(vals)), uint16(len(enc) / 2)} //nolint:gosec // test data
		vals = append(vals, enc...)
	}
	b := make([]byte, fixed)
	binary.LittleEndian.PutUint32(b[0:4], uint32(head+len(vals))) //nolint:gosec // test data
	binary.LittleEndian.PutUint32(b[4:8], 0x74000004)             // TDS 7.4
	if integrated {
		b[25] |= 0x80
	}
	for _, o := range offs {
		b = binary.LittleEndian.AppendUint16(b, o[0])
		b = binary.LittleEndian.AppendUint16(b, o[1])
	}
	return append(b, vals...)
}

// rpc builds an RPC naming a procedure, with unnamed NVARCHAR parameters.
func rpc(proc string, params ...string) []byte {
	enc := wire.ToUCS2(proc)
	body := binary.LittleEndian.AppendUint16(nil, uint16(len(enc)/2)) //nolint:gosec // test data
	body = append(body, enc...)
	body = binary.LittleEndian.AppendUint16(body, 0) // option flags
	for _, s := range params {
		v := wire.ToUCS2(s)
		body = append(body, 0, 0, 0xe7)
		body = binary.LittleEndian.AppendUint16(body, 8000)
		body = append(body, 0, 0, 0, 0, 0)
		body = binary.LittleEndian.AppendUint16(body, uint16(len(v))) //nolint:gosec // test data
		body = append(body, v...)
	}
	return body
}

// The ordinary path, end to end: PRELOGIN, LOGIN7, a batch and a parameterised
// query all reach the server.
func TestAnAllowedSessionReachesTheServer(t *testing.T) {
	s := startFake(t, &fakeServer{encryption: wire.EncryptOff})
	_, addr := relayFor(t, base, s.addr())

	cl := dial(t, addr, wire.EncryptOff)
	cl.login(t, "app", "sales", "MyApp", true, false)
	cl.batch(t, "SELECT 1")
	cl.send(t, wire.TypeRPC, rpc("sp_executesql", "SELECT * FROM t"))

	types, procs, stmts := s.saw()
	if len(types) != 3 || types[0] != wire.TypeLogin7 ||
		types[1] != wire.TypeSQLBatch || types[2] != wire.TypeRPC {
		t.Fatalf("the server saw %v", types)
	}
	if len(procs) != 1 || procs[0] != "sp_executesql" {
		t.Fatalf("procedures: %v", procs)
	}
	if len(stmts) != 2 || stmts[0] != "SELECT 1" || stmts[1] != "SELECT * FROM t" {
		t.Fatalf("statements: %v", stmts)
	}
}

// The relay asks the *server* for encryption independently of what the client
// asked for, because the two legs are separate negotiations and a relay that
// matched the client's wish would speak cleartext onwards for every client that
// did.
func TestTheRelayAsksTheServerForEncryptionOnItsOwnAccount(t *testing.T) {
	// The fake answers "I cannot", which under `prefer` the relay accepts -- so
	// the assertion is about what it *asked* for, which is the half a client
	// cannot influence.
	s := startFake(t, &fakeServer{encryption: wire.EncryptNotSup})
	section := "        upstream: sql\n" +
		"        require_tls: false\n" +
		"        upstream_tls_mode: prefer\n" +
		"        allow_cleartext_password: true\n" +
		"        default_action: allow\n"
	_, addr := relayFor(t, section, s.addr())
	// The client asks for nothing at all.
	dial(t, addr, wire.EncryptOff)
	// Give the handshake a moment to reach the fake.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && s.asked() != wire.EncryptReq {
		time.Sleep(5 * time.Millisecond)
	}
	if got := s.asked(); got != wire.EncryptReq {
		t.Fatalf("the relay asked the server for %s, want required", wire.EncryptName(got))
	}
}

// With upstream_tls_mode at its default of require, a server that will not
// encrypt is refused rather than spoken to in the clear. A relay that terminated
// the client's TLS and carried on unencrypted would have moved the exposure
// rather than removed it -- and what crosses is a recoverable password.
func TestAServerThatWillNotEncryptIsRefused(t *testing.T) {
	s := startFake(t, &fakeServer{encryption: wire.EncryptNotSup})
	section := "        upstream: sql\n" +
		"        require_tls: false\n" +
		"        allow_cleartext_password: true\n" +
		"        default_action: allow\n"
	_, addr := relayFor(t, section, s.addr())
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	body := wire.BuildPreLogin([]wire.PreLoginOption{
		{Token: wire.PreLoginEncryption, Value: []byte{wire.EncryptOff}}})
	if _, err = c.Write(wire.Frame(wire.TypePreLogin, 0, body, 4096)); err != nil {
		t.Fatal(err)
	}
	rd := wire.NewReader(c, wire.MaxMessage)
	if _, err = rd.Next(); err == nil {
		t.Fatal("the relay answered a client although the server refused to encrypt")
	}
	types, _, _ := s.saw()
	if len(types) != 0 {
		t.Fatalf("something reached the server: %v", types)
	}
}

// The statement inside a parameterised query gets the same policy a batch gets.
// This is the assertion the whole kind turns on: a relay that read only SQLBATCH
// would forward every statement a real application runs.
func TestThePolicyReachesTheStatementInsideAParameterisedQuery(t *testing.T) {
	s := startFake(t, &fakeServer{encryption: wire.EncryptOff})
	_, addr := relayFor(t, base+"        read_only: true\n", s.addr())

	cl := dial(t, addr, wire.EncryptOff)
	cl.login(t, "app", "sales", "MyApp", true, false)
	// A read through sp_executesql goes.
	cl.send(t, wire.TypeRPC, rpc("sp_executesql", "SELECT 1"))
	// A write through sp_executesql does not, and the refusal is the protocol's
	// own error token so a driver reports it like the server's.
	p := cl.send(t, wire.TypeRPC, rpc("sp_executesql", "DELETE FROM payroll"))
	if n, ok := refusedWith(p); !ok || n != wire.PermissionDenied {
		t.Fatalf("answer was %v %d", ok, n)
	}
	// And the same statement as a batch is refused the same way, because it is
	// one policy reached by two routes.
	p = cl.batch(t, "DELETE FROM payroll")
	if n, ok := refusedWith(p); !ok || n != wire.PermissionDenied {
		t.Fatalf("batch: %v %d", ok, n)
	}

	_, _, stmts := s.saw()
	for _, st := range stmts {
		if strings.Contains(st, "DELETE") {
			t.Fatalf("a refused statement reached the server: %q", st)
		}
	}
	if len(stmts) != 1 || stmts[0] != "SELECT 1" {
		t.Fatalf("the server saw %v", stmts)
	}
}

// xp_cmdshell is the one everybody knows about, and the relay refuses it by
// default -- because the default procedure list is an allow list of what a driver
// calls rather than a deny list of what somebody remembered.
func TestAWayOutOfTheDatabaseIsRefusedByDefault(t *testing.T) {
	s := startFake(t, &fakeServer{encryption: wire.EncryptOff})
	_, addr := relayFor(t, base, s.addr())
	cl := dial(t, addr, wire.EncryptOff)
	cl.login(t, "sa", "master", "sqlcmd", true, false)

	for _, proc := range []string{"xp_cmdshell", "sp_oacreate", "xp_regwrite",
		"sp_addlinkedserver", "sp_configure"} {
		p := cl.send(t, wire.TypeRPC, rpc(proc, "whoami"))
		if n, ok := refusedWith(p); !ok || n != wire.PermissionDenied {
			t.Fatalf("%s: answer was %v %d", proc, ok, n)
		}
	}
	_, procs, _ := s.saw()
	if len(procs) != 0 {
		t.Fatalf("procedures reached the server: %v", procs)
	}
}

// Monitor mode enforces nothing -- except the decisions where forwarding the
// message and writing down that it was noticed is not a trial of anything.
func TestMonitorModeStillRefusesAShellCommand(t *testing.T) {
	s := startFake(t, &fakeServer{encryption: wire.EncryptOff})
	_, addr := relayFor(t, base+"        monitor_only: true\n"+
		"        read_only: true\n", s.addr())
	cl := dial(t, addr, wire.EncryptOff)
	cl.login(t, "sa", "master", "sqlcmd", true, false)

	// A write is noticed and forwarded: that is what monitor mode is for.
	cl.batch(t, "DELETE FROM payroll")
	// A procedure merely off the allow list is forwarded too.
	cl.send(t, wire.TypeRPC, rpc("sp_helpdb"))
	// A shell command is not.
	p := cl.send(t, wire.TypeRPC, rpc("xp_cmdshell", "whoami"))
	if n, ok := refusedWith(p); !ok || n != wire.PermissionDenied {
		t.Fatalf("xp_cmdshell: %v %d", ok, n)
	}

	_, procs, stmts := s.saw()
	if len(stmts) != 1 || stmts[0] != "DELETE FROM payroll" {
		t.Fatalf("statements: %v", stmts)
	}
	if len(procs) != 1 || procs[0] != "sp_helpdb" {
		t.Fatalf("procedures: %v", procs)
	}
}

// A login the policy refuses gets an error token with the number a client library
// reports as "you may not connect", and nothing of it reaches the server.
func TestARefusedLoginIsToldSoAndGoesNoFurther(t *testing.T) {
	s := startFake(t, &fakeServer{encryption: wire.EncryptOff})
	_, addr := relayFor(t, base+"        deny_users: [sa]\n", s.addr())
	cl := dial(t, addr, wire.EncryptOff)
	p := cl.login(t, "sa", "master", "sqlcmd", true, false)
	if n, ok := refusedWith(p); !ok || n != wire.LoginFailed {
		t.Fatalf("answer was %v %d", ok, n)
	}
	types, _, _ := s.saw()
	if len(types) != 0 {
		t.Fatalf("the login reached the server: %v", types)
	}
}

// A message type off the list is refused, and the message does not reach the
// server. bulk_load is the default case: its stream is not SQL, so no statement
// policy would ever look at it.
func TestAMessageTypeOffTheListGoesNoFurther(t *testing.T) {
	s := startFake(t, &fakeServer{encryption: wire.EncryptOff})
	_, addr := relayFor(t, base, s.addr())
	cl := dial(t, addr, wire.EncryptOff)
	cl.login(t, "app", "sales", "MyApp", true, false)
	p := cl.send(t, wire.TypeBulkLoad, []byte{1, 2, 3})
	if n, ok := refusedWith(p); !ok || n != wire.PermissionDenied {
		t.Fatalf("answer was %v %d", ok, n)
	}
	types, _, _ := s.saw()
	if len(types) != 1 || types[0] != wire.TypeLogin7 {
		t.Fatalf("the server saw %v", types)
	}
}

// A dynamic-SQL call whose statement the relay cannot read is refused rather than
// forwarded. It is the one message on this protocol that carries arbitrary SQL,
// so a relay that passed an unreadable one would be passing exactly what it
// exists to inspect.
func TestAnUnreadableDynamicCallGoesNoFurther(t *testing.T) {
	s := startFake(t, &fakeServer{encryption: wire.EncryptOff})
	_, addr := relayFor(t, base, s.addr())
	cl := dial(t, addr, wire.EncryptOff)
	cl.login(t, "app", "sales", "MyApp", true, false)
	// sp_executesql with no parameters at all.
	p := cl.send(t, wire.TypeRPC, rpc("sp_executesql"))
	if n, ok := refusedWith(p); !ok || n != wire.PermissionDenied {
		t.Fatalf("answer was %v %d", ok, n)
	}
	_, procs, _ := s.saw()
	if len(procs) != 0 {
		t.Fatalf("it reached the server: %v", procs)
	}
}

// require_tls with no certificate cannot serve anybody, so the listener refuses
// to start rather than failing every connection with a message in a log nobody
// is reading yet.
func TestRequireTLSWithoutACertificateRefusesToStart(t *testing.T) {
	s := startFake(t, &fakeServer{encryption: wire.EncryptOff})
	_, err := proxytest.TryStart(fmt.Sprintf(tdsYAML,
		"        upstream: sql\n        require_tls: true\n", s.addr()))
	if err == nil {
		t.Fatal("a listener requiring tls without a certificate started")
	}
	if !strings.Contains(err.Error(), "require_tls") {
		t.Fatalf("the error does not name the setting: %v", err)
	}
}

// deny_response: drop closes without an error token, for an estate that would
// rather a prober learn nothing.
func TestDropSaysNothing(t *testing.T) {
	s := startFake(t, &fakeServer{encryption: wire.EncryptOff})
	_, addr := relayFor(t, base+"        deny_response: drop\n"+
		"        read_only: true\n", s.addr())
	cl := dial(t, addr, wire.EncryptOff)
	cl.login(t, "app", "sales", "MyApp", true, false)
	if _, err := cl.c.Write(wire.Frame(wire.TypeSQLBatch, 0,
		wire.ToUCS2("DELETE FROM t"), cl.size)); err != nil {
		t.Fatal(err)
	}
	// Nothing comes back for the refused batch, so the next read must time out
	// rather than return a token.
	_ = cl.c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := cl.rd.Next(); err == nil {
		t.Fatal("drop sent an answer")
	} else if !isTimeout(err) {
		// A closed connection is also acceptable; what is not is a token.
		if !errors.Is(err, net.ErrClosed) && err.Error() != "EOF" {
			t.Logf("ended with %v, which is not an answer either", err)
		}
	}
	_, _, stmts := s.saw()
	if len(stmts) != 0 {
		t.Fatalf("the statement reached the server: %v", stmts)
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// A plaintext login carrying a password is refused, which is the single most
// valuable thing this kind does.
//
// The password field is XOR 0xa5 with the nibbles swapped. Anybody who read the
// packet has the password, so the refusal is hard: a monitor-mode listener that
// forwarded it and wrote down that it noticed would be recording a credential
// disclosure it had just permitted.
func TestAPlaintextPasswordIsRefusedEvenInMonitorMode(t *testing.T) {
	for _, extra := range []string{"", "        monitor_only: true\n"} {
		s := startFake(t, &fakeServer{encryption: wire.EncryptOff})
		section := "        upstream: sql\n" +
			"        require_tls: false\n" +
			"        upstream_tls_mode: disable\n" +
			"        default_action: allow\n" + extra
		_, addr := relayFor(t, section, s.addr())
		cl := dial(t, addr, wire.EncryptOff)
		p := cl.login(t, "app", "sales", "MyApp", true, false)
		if n, ok := refusedWith(p); !ok || n != wire.LoginFailed {
			t.Fatalf("extra=%q: answer was %v %d", extra, ok, n)
		}
		if types, _, _ := s.saw(); len(types) != 0 {
			t.Fatalf("extra=%q: the login reached the server: %v", extra, types)
		}
	}
}

// The TLS handshake on this protocol runs inside TDS packets and then stops, and
// the nesting inverts exactly once. This is the test for that: a real crypto/tls
// client handshaking through the encapsulation, and then a statement policy
// applied to what it sends over the encrypted connection.
//
// It also covers the case the whole kind exists for: the client asks for `off`
// and the relay answers `required`, so the connection that carries the password
// is encrypted whether the client meant it to be or not.
func TestTheHandshakeRunsInsideTDSPacketsAndThenStops(t *testing.T) {
	s := startFake(t, &fakeServer{encryption: wire.EncryptOff})
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "sql.test")
	section := "        upstream: sql\n" +
		"        require_tls: true\n" +
		"        upstream_tls_mode: disable\n" +
		"        read_only: true\n" +
		"        default_action: allow\n" +
		fmt.Sprintf("      tls: {certificates: [{cert_file: %s, key_file: %s}]}\n", cert, key)
	srv := proxytest.Start(t, fmt.Sprintf(tdsYAML, section, s.addr()))
	addr := proxytest.Addr(t, srv, "db")

	// The client asks for `off`, which is what a great deal of deployed software
	// sends.
	cl := dial(t, addr, wire.EncryptOff)
	if cl.pre.Encryption != wire.EncryptReq {
		t.Fatalf("the relay answered %s, want required", wire.EncryptName(cl.pre.Encryption))
	}

	// Now upgrade, with the handshake encapsulated the way the protocol says.
	tun := newTunnel(cl.c, 0, 4096, 1<<20)
	tc := tls.Client(tun, &tls.Config{ServerName: "sql.test", InsecureSkipVerify: true}) //nolint:gosec // the fixture's certificate is self-signed
	if err := tc.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	tun.HandshakeDone()
	cl.c, cl.rd = tc, wire.NewReader(tc, wire.MaxMessage)

	// And the rest of the connection is ordinary TDS inside TLS.
	cl.login(t, "app", "sales", "MyApp", true, false)
	cl.batch(t, "SELECT 1")
	p := cl.batch(t, "DELETE FROM payroll")
	if n, ok := refusedWith(p); !ok || n != wire.PermissionDenied {
		t.Fatalf("the write was answered %v %d", ok, n)
	}

	types, _, stmts := s.saw()
	if len(types) != 2 || types[0] != wire.TypeLogin7 || types[1] != wire.TypeSQLBatch {
		t.Fatalf("the server saw %v", types)
	}
	if len(stmts) != 1 || stmts[0] != "SELECT 1" {
		t.Fatalf("statements: %v", stmts)
	}
}

// A peer sending neither framing is refused rather than having whatever it sent
// fed to the TLS record layer.
func TestTheTunnelRefusesWhatIsNeitherFraming(t *testing.T) {
	for _, tc := range []struct {
		name string
		body []byte
		done bool
	}{
		{"a login7 during the handshake", wire.Frame(wire.TypeLogin7, 0, []byte{1, 2, 3}, 4096), false},
		{"a tls record before the handshake finished", []byte{0x17, 3, 3, 0, 4, 1, 2, 3, 4}, false},
		{"an octet that is no framing at all", []byte{0x99, 0, 0, 0, 0, 0, 0, 0}, true},
	} {
		a, b := net.Pipe()
		go func(body []byte) {
			_, _ = b.Write(body)
		}(tc.body)
		tun := newTunnel(a, 0, 4096, 1<<20)
		if tc.done {
			tun.HandshakeDone()
		}
		_, err := tun.Read(make([]byte, 16))
		if err == nil {
			t.Fatalf("%s was read as handshake data", tc.name)
		}
		if !strings.Contains(err.Error(), "neither") {
			t.Fatalf("%s: %v", tc.name, err)
		}
		_ = a.Close()
		_ = b.Close()
	}
}

// The window in which either framing is accepted, and the flip out of it.
//
// This is the case TLS 1.3 created: the peer's session ticket is an encapsulated
// message sent after its handshake completed, so it arrives after this side has
// stopped encapsulating its own writes. The ticket has to be read as an
// encapsulated packet and the record after it as a raw record, and the octet that
// decided which is which is still owed to the record layer.
func TestTheTunnelReadsEitherFramingUntilThePeerStops(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	record := []byte{0x17, 3, 3, 0, 4, 9, 9, 9, 9}
	go func() {
		// An encapsulated post-handshake message, then a raw record.
		_, _ = b.Write(wire.Frame(wire.TypePreLogin, 0, []byte{1, 2, 3, 4}, 4096))
		_, _ = b.Write(record)
	}()
	tun := newTunnel(a, 0, 4096, 1<<20)
	tun.HandshakeDone()

	// The encapsulated message, one octet at a time, so the buffer has to
	// survive being drained across calls.
	got := make([]byte, 4)
	for i := range got {
		if _, err := io.ReadFull(tun, got[i:i+1]); err != nil {
			t.Fatal(err)
		}
	}
	if got[0] != 1 || got[3] != 4 {
		t.Fatalf("the encapsulated message came back as %v", got)
	}
	// Then the raw record, whole -- including the content-type octet that told
	// the tunnel the encapsulation was over. Dropping it would leave the record
	// layer reading a record whose header began one octet in, which is a
	// connection that hangs and looks like a certificate problem.
	rest := make([]byte, len(record))
	if _, err := io.ReadFull(tun, rest); err != nil {
		t.Fatal(err)
	}
	if string(rest) != string(record) {
		t.Fatalf("the raw record came back as %v, want %v", rest, record)
	}
}

// A read that is waiting for the peer must not block a write.
//
// A relay reads one direction while writing the other, so a tunnel that held a
// lock across its underlying read would stall every answer behind a request that
// had not arrived. It is a deadlock that appears only once both directions are
// live, which is after the handshake -- so after every test of the handshake has
// passed.
func TestAWaitingReadDoesNotBlockAWrite(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	tun := newTunnel(a, 0, 4096, 1<<20)
	tun.HandshakeDone()

	reading := make(chan struct{})
	go func() {
		close(reading)
		_, _ = tun.Read(make([]byte, 16)) // blocks: nothing is coming
	}()
	<-reading
	time.Sleep(20 * time.Millisecond)

	wrote := make(chan error, 1)
	go func() {
		_, err := tun.Write([]byte{1, 2, 3, 4})
		wrote <- err
	}()
	// Drain the other end so the pipe write can complete.
	go func() { _, _ = io.ReadFull(b, make([]byte, 4)) }()
	select {
	case err := <-wrote:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a write was blocked behind a read that was waiting for the peer")
	}
}

// A handshake packet claiming more octets than the reassembly bound is refused
// before the relay allocates for it: a peer that has not yet presented a
// certificate must not be able to make it hold memory.
func TestTheTunnelBoundsAHandshakePacket(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	go func() {
		// A header claiming a 40000-octet body, with nothing behind it.
		hdr := []byte{wire.TypePreLogin, wire.StatusEOM, 0, 0, 0, 0, 1, 0}
		binary.BigEndian.PutUint16(hdr[2:4], 40000)
		_, _ = b.Write(hdr)
	}()
	tun := newTunnel(a, 0, 4096, 1024)
	if _, err := tun.Read(make([]byte, 16)); !errors.Is(err, wire.ErrTooLong) {
		t.Fatalf("%v, want ErrTooLong", err)
	}
}
