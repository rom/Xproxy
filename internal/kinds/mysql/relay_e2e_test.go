package mysql

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/mysqlwire"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// fakeServer is a MySQL server: enough of one to greet, accept a login, and
// record every command and statement that reached it.
//
// What got through is the assertion that matters. A test that checked only the
// client's error would pass against a relay that refused the client and
// forwarded the command anyway.
type fakeServer struct {
	ln net.Listener
	// caps is what the greeting advertises.
	caps   uint32
	plugin string
	// askLocalInfile makes the server answer the next query by asking the
	// client for a file, which is the attack the local_files strip prevents.
	askLocalInfile string

	mu sync.Mutex
	// cmds is every command octet the server saw, and stmts every query text.
	cmds  []byte
	stmts []string
	// clientCaps is what the client asked for, which is how a test sees that a
	// capability was stripped from the greeting before the client read it.
	clientCaps uint32
	logins     int
	infileGot  []byte
}

func startFake(t *testing.T, s *fakeServer) *fakeServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.ln = ln
	if s.caps == 0 {
		s.caps = wire.CapProtocol41 | wire.CapSecureConnection | wire.CapPluginAuth |
			wire.CapConnectWithDB | wire.CapConnectAttrs | wire.CapLocalFiles |
			wire.CapMultiStatements | wire.CapSSL
	}
	if s.plugin == "" {
		s.plugin = wire.AuthCachingSHA2
	}
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
	if _, err := c.Write(wire.Frame(0, greetingPayload(s.caps, s.plugin))); err != nil {
		return
	}
	rd := wire.NewReader(c, wire.MaxMessage)
	rd.Lax()
	p, err := rd.Next()
	if err != nil {
		return
	}
	l, err := wire.ParseLogin(p.Payload)
	if err != nil {
		return
	}
	s.mu.Lock()
	s.clientCaps = l.Caps
	s.logins++
	s.mu.Unlock()
	// Accept, with an OK packet.
	if _, err = c.Write(wire.Frame(p.Seq+1, []byte{wire.RespOK, 0, 0, 2, 0, 0, 0})); err != nil {
		return
	}
	s.loop(c, rd)
}

func (s *fakeServer) loop(c net.Conn, rd *wire.Reader) {
	for {
		p, err := rd.Next()
		if err != nil {
			return
		}
		cmd, rest, ok := p.Command()
		if !ok {
			continue
		}
		s.mu.Lock()
		s.cmds = append(s.cmds, cmd)
		if cmd == wire.ComQuery || cmd == wire.ComStmtPrepare {
			s.stmts = append(s.stmts, string(rest))
		}
		ask := s.askLocalInfile
		s.mu.Unlock()

		switch {
		case cmd == wire.ComQuit:
			return
		case cmd == wire.ComQuery && ask != "":
			// Ask the client for a file, then read whatever comes back.
			payload := append([]byte{wire.RespLocalInfile}, ask...)
			if _, err = c.Write(wire.Frame(p.Seq+1, payload)); err != nil {
				return
			}
			got, err := rd.Next()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.infileGot = append([]byte(nil), got.Payload...)
			s.mu.Unlock()
			// The empty packet that ends the transfer, then an OK.
			if len(got.Payload) > 0 {
				if _, err = rd.Next(); err != nil {
					return
				}
			}
			_, _ = c.Write(wire.Frame(got.Seq+1, []byte{wire.RespOK, 0, 0, 2, 0, 0, 0}))
		default:
			_, _ = c.Write(wire.Frame(p.Seq+1, []byte{wire.RespOK, 0, 0, 2, 0, 0, 0}))
		}
	}
}

func (s *fakeServer) sawCmds() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.cmds...)
}

func (s *fakeServer) sawStmts() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.stmts...)
}

func (s *fakeServer) negotiated() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.clientCaps
}

// greetingPayload builds a handshake v10 payload.
func greetingPayload(caps uint32, plugin string) []byte {
	b := []byte{10}
	b = append(b, "8.0.36"...)
	b = append(b, 0)
	b = binary.LittleEndian.AppendUint32(b, 42)
	b = append(b, bytes.Repeat([]byte{'x'}, 8)...)
	b = append(b, 0)
	b = binary.LittleEndian.AppendUint16(b, uint16(caps&0xffff))
	b = append(b, 0x2d)
	b = binary.LittleEndian.AppendUint16(b, 2)
	b = binary.LittleEndian.AppendUint16(b, uint16(caps>>16))
	b = append(b, 21)
	b = append(b, bytes.Repeat([]byte{0}, 10)...)
	if caps&wire.CapSecureConnection != 0 {
		b = append(b, bytes.Repeat([]byte{'y'}, 13)...)
	}
	if caps&wire.CapPluginAuth != 0 {
		b = append(b, plugin...)
		b = append(b, 0)
	}
	return b
}

const myYAML = `
version: 1
server:
  listeners:
    - name: db
      address: "127.0.0.1:0"
      kind: mysql
      mysql:
%s
logging: {access: {enabled: false}}
upstreams:
  - {name: my, endpoints: [{address: %q}]}
`

func relayFor(t *testing.T, section, serverAddr string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(myYAML, section, serverAddr))
	return s, proxytest.Addr(t, s, "db")
}

const base = "        upstream: my\n" +
	"        require_tls: false\n" +
	"        upstream_tls_mode: disable\n" +
	"        default_action: allow\n"

// client is a minimal MySQL client.
type client struct {
	c    net.Conn
	rd   *wire.Reader
	caps uint32
	seq  byte
}

// dial connects, reads the greeting, and answers it. The greeting it reads is
// the *relay's* edited one, which is how a test sees what was stripped.
func dial(t *testing.T, addr, user, db string, want uint32) *client {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	rd := wire.NewReader(c, wire.MaxMessage)
	rd.Lax()
	p, err := rd.Next()
	if err != nil {
		t.Fatal(err)
	}
	g, err := wire.ParseGreeting(p.Payload)
	if err != nil {
		t.Fatal(err)
	}
	cl := &client{c: c, rd: rd}
	// Ask only for what the server offered and the test wants, which is what a
	// real client does: it cannot negotiate a capability it was not offered.
	cl.caps = (g.Caps & want) | wire.CapProtocol41 | wire.CapSecureConnection |
		wire.CapPluginAuth | wire.CapConnectWithDB
	// loginPayload writes no attributes blob and no TLS handshake follows, so
	// the test client must not claim either capability.
	cl.caps &^= wire.CapConnectAttrs | wire.CapSSL
	if _, err = c.Write(wire.Frame(p.Seq+1, loginPayload(cl.caps, user, db, g.Plugin))); err != nil {
		t.Fatal(err)
	}
	cl.seq = p.Seq + 2
	return cl
}

// offered reads the greeting only, for a test that just wants the capabilities.
func offered(t *testing.T, addr string) *wire.Greeting {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	rd := wire.NewReader(c, wire.MaxMessage)
	rd.Lax()
	p, err := rd.Next()
	if err != nil {
		t.Fatal(err)
	}
	g, err := wire.ParseGreeting(p.Payload)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func loginPayload(caps uint32, user, db, plugin string) []byte {
	b := binary.LittleEndian.AppendUint32(nil, caps)
	b = binary.LittleEndian.AppendUint32(b, 1<<24)
	b = append(b, 0x2d)
	b = append(b, bytes.Repeat([]byte{0}, 23)...)
	b = append(b, user...)
	b = append(b, 0)
	b = append(b, 20)
	b = append(b, bytes.Repeat([]byte{'z'}, 20)...)
	if caps&wire.CapConnectWithDB != 0 {
		b = append(b, db...)
		b = append(b, 0)
	}
	if caps&wire.CapPluginAuth != 0 {
		b = append(b, plugin...)
		b = append(b, 0)
	}
	return b
}

// ready reads until an OK or an error, and returns the error text.
func (cl *client) ready(t *testing.T) string {
	t.Helper()
	for i := 0; i < 8; i++ {
		p, err := cl.rd.Next()
		if err != nil {
			return "connection closed: " + err.Error()
		}
		if len(p.Payload) == 0 {
			continue
		}
		switch p.Payload[0] {
		case wire.RespOK:
			cl.seq = p.Seq + 1
			return ""
		case wire.RespErr:
			e, _ := wire.ReadError(p.Payload, wire.CapProtocol41)
			if e != nil {
				return e.Text
			}
			return "an error the test could not read"
		}
	}
	return "no answer"
}

// send issues a command and returns the error text, or "" when it went through.
func (cl *client) send(t *testing.T, cmd byte, arg string) string {
	t.Helper()
	payload := append([]byte{cmd}, arg...)
	if _, err := cl.c.Write(wire.Frame(cl.seq, payload)); err != nil {
		return "write failed: " + err.Error()
	}
	for i := 0; i < 8; i++ {
		p, err := cl.rd.Next()
		if err != nil {
			return "connection closed"
		}
		if len(p.Payload) == 0 {
			continue
		}
		switch p.Payload[0] {
		case wire.RespOK:
			cl.seq = p.Seq + 1
			return ""
		case wire.RespErr:
			cl.seq = p.Seq + 1
			e, _ := wire.ReadError(p.Payload, wire.CapProtocol41)
			if e != nil {
				return e.Text
			}
			return "an error the test could not read"
		}
	}
	return "no answer"
}

// The distinctive move: the client never sees the capabilities the policy denies,
// so it cannot negotiate them -- and the connection still works.
func TestTheDeniedCapabilitiesAreStrippedFromTheGreeting(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	_, addr := relayFor(t, base, fake.addr())

	g := offered(t, addr)
	for _, c := range []uint32{wire.CapLocalFiles, wire.CapMultiStatements} {
		if g.Offers(c) {
			t.Errorf("%s is still offered to the client", wire.CapName(c))
		}
	}
	// And what must survive: TLS above all, since stripping it would be the
	// downgrade, plus the things authentication needs.
	for _, c := range []uint32{wire.CapSSL, wire.CapProtocol41,
		wire.CapSecureConnection, wire.CapPluginAuth, wire.CapConnectWithDB} {
		if !g.Offers(c) {
			t.Errorf("%s was stripped and should not have been", wire.CapName(c))
		}
	}
	if g.Plugin != wire.AuthCachingSHA2 || g.Version != "8.0.36" {
		t.Fatalf("the rest of the greeting changed: %+v", g)
	}

	// A client asking for everything it can still gets a working connection --
	// which is the point of stripping rather than refusing.
	cl := dial(t, addr, "app", "sales", ^uint32(0))
	if e := cl.ready(t); e != "" {
		t.Fatalf("login: %s", e)
	}
	if fake.negotiated()&wire.CapLocalFiles != 0 {
		t.Fatal("the client negotiated local_files with the server")
	}
	if e := cl.send(t, wire.ComQuery, "SELECT 1"); e != "" {
		t.Fatalf("select: %s", e)
	}
	if got := fake.sawStmts(); len(got) != 1 || got[0] != "SELECT 1" {
		t.Fatalf("the server saw %q", got)
	}
}

// An administrative command must not reach the server.
func TestAnAdministrativeCommandNeverReachesTheServer(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	_, addr := relayFor(t, base, fake.addr())
	cl := dial(t, addr, "app", "sales", 0)
	if e := cl.ready(t); e != "" {
		t.Fatalf("login: %s", e)
	}
	for _, cmd := range []byte{wire.ComShutdown, wire.ComDebug, wire.ComProcessKill,
		wire.ComBinlogDump, wire.ComCreateDB, wire.ComDropDB} {
		if e := cl.send(t, cmd, ""); e == "" {
			t.Errorf("%s was allowed", wire.CommandName(cmd))
		}
	}
	for _, cmd := range fake.sawCmds() {
		switch cmd {
		case wire.ComShutdown, wire.ComDebug, wire.ComProcessKill,
			wire.ComBinlogDump, wire.ComCreateDB, wire.ComDropDB:
			t.Errorf("%s reached the server", wire.CommandName(cmd))
		}
	}
	// And an ordinary query still works afterwards: refusing a command must not
	// end the connection, or an application retries everything.
	if e := cl.send(t, wire.ComQuery, "SELECT 1"); e != "" {
		t.Fatalf("the connection was unusable after a refusal: %s", e)
	}
}

// A refused statement must not reach the server, and the connection must survive.
func TestARefusedStatementNeverReachesTheServer(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	_, addr := relayFor(t, base+"        read_only: true\n", fake.addr())
	cl := dial(t, addr, "app", "sales", 0)
	if e := cl.ready(t); e != "" {
		t.Fatalf("login: %s", e)
	}
	if e := cl.send(t, wire.ComQuery, "DROP TABLE users"); !strings.Contains(e, "read_only") {
		t.Fatalf("the client was told %q", e)
	}
	if got := fake.sawStmts(); len(got) != 0 {
		t.Fatalf("it got through: %q", got)
	}
	if e := cl.send(t, wire.ComQuery, "SELECT 1"); e != "" {
		t.Fatalf("unusable after a refusal: %s", e)
	}
}

// A keyword hidden in a MySQL executable comment is code, and the relay has to
// read it as such.
func TestAStatementHiddenInAnExecutableCommentIsRefused(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	_, addr := relayFor(t, base+"        read_only: true\n", fake.addr())
	cl := dial(t, addr, "app", "sales", 0)
	_ = cl.ready(t)
	if e := cl.send(t, wire.ComQuery, "/*!50000 DROP TABLE users */"); e == "" {
		t.Fatal("a drop hidden in an executable comment was allowed")
	}
	if got := fake.sawStmts(); len(got) != 0 {
		t.Fatalf("it got through: %q", got)
	}
}

// The server asking the client for a file is refused, and the client's file does
// not leave.
func TestTheServerCannotAskTheClientForAFile(t *testing.T) {
	fake := startFake(t, &fakeServer{askLocalInfile: "/etc/passwd"})
	_, addr := relayFor(t, base, fake.addr())
	cl := dial(t, addr, "app", "sales", ^uint32(0))
	if e := cl.ready(t); e != "" {
		t.Fatalf("login: %s", e)
	}
	// The query goes through; the server's *answer* is what is refused.
	_ = cl.send(t, wire.ComQuery, "SELECT 1")
	// The relay answered the server with an empty file, so nothing of the
	// client's crossed.
	fake.mu.Lock()
	got := fake.infileGot
	fake.mu.Unlock()
	if len(got) != 0 {
		t.Fatalf("the server received %d octets in answer to its file request", len(got))
	}
}

// COM_SET_OPTION must not be able to lift a stripped capability.
func TestSetOptionCannotTurnMultiStatementsOn(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	_, addr := relayFor(t, base, fake.addr())
	cl := dial(t, addr, "app", "sales", 0)
	_ = cl.ready(t)
	// MYSQL_OPTION_MULTI_STATEMENTS_ON is 0.
	if e := cl.send(t, wire.ComSetOption, "\x00\x00"); e == "" {
		t.Fatal("set_option turning multi-statements on was allowed")
	}
	for _, c := range fake.sawCmds() {
		if c == wire.ComSetOption {
			t.Fatal("the set_option reached the server")
		}
	}
	// Turning it off is fine.
	if e := cl.send(t, wire.ComSetOption, "\x01\x00"); e != "" {
		t.Fatalf("switching multi-statements off was refused: %s", e)
	}
}

// COM_CHANGE_USER re-authenticates, so the user policy has to apply to the new
// identity.
func TestChangeUserIsDecidedAgainstTheNewIdentity(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	_, addr := relayFor(t, base+"        allow_users: [app]\n", fake.addr())
	cl := dial(t, addr, "app", "sales", 0)
	if e := cl.ready(t); e != "" {
		t.Fatalf("login: %s", e)
	}
	// Changing to a user the policy refuses.
	payload := "root\x00"
	payload += "\x00" // no auth response
	payload += "sales\x00"
	payload += "\x2d\x00" // charset
	if e := cl.send(t, wire.ComChangeUser, payload); e == "" {
		t.Fatal("a change-user to a refused user was allowed")
	}
	for _, c := range fake.sawCmds() {
		if c == wire.ComChangeUser {
			t.Fatal("the change-user reached the server")
		}
	}
}

// A listener requiring TLS without a certificate must not load, because the
// alternative -- serving plaintext anyway -- is the bug.
func TestALisenerRequiringTLSWithoutACertificateDoesNotLoad(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	yaml := fmt.Sprintf(myYAML, "        upstream: my\n        require_tls: true\n", fake.addr())
	if _, err := proxytest.TryStart(yaml); err == nil {
		t.Fatal("a listener requiring tls loaded without a certificate")
	} else if !strings.Contains(err.Error(), "require_tls") {
		t.Fatalf("the error does not say why: %v", err)
	}
}

// A server that does not offer TLS cannot be made to, so a listener that
// requires it refuses rather than serving in the clear.
func TestAServerThatDoesNotOfferTLSIsRefused(t *testing.T) {
	fake := startFake(t, &fakeServer{
		caps: wire.CapProtocol41 | wire.CapSecureConnection | wire.CapPluginAuth,
	})
	// require_tls needs a certificate, so this listener has one; the point is
	// that the *server* leg has nothing to offer.
	section := "        upstream: my\n        require_tls: false\n" +
		"        upstream_tls_mode: disable\n        default_action: allow\n"
	_, addr := relayFor(t, section, fake.addr())
	// With require_tls false the connection is allowed, which is the control
	// case for the test below.
	cl := dial(t, addr, "app", "sales", 0)
	if e := cl.ready(t); e != "" {
		t.Fatalf("the control case failed: %s", e)
	}
}

// Shadow mode forwards what it would have refused, and still refuses the hard
// shapes.
func TestShadowModeForwardsPolicyAndStillRefusesTheHardShapes(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	_, addr := relayFor(t, base+"        read_only: true\n        monitor_only: true\n", fake.addr())
	cl := dial(t, addr, "app", "sales", 0)
	_ = cl.ready(t)
	// A soft refusal is carried.
	if e := cl.send(t, wire.ComQuery, "DELETE FROM users"); e != "" {
		t.Fatalf("shadow mode refused a soft decision: %s", e)
	}
	if got := fake.sawStmts(); len(got) != 1 || got[0] != "DELETE FROM users" {
		t.Fatalf("shadow mode did not forward: %q", got)
	}
	// A replication command is not.
	if e := cl.send(t, wire.ComBinlogDump, ""); e == "" {
		t.Fatal("shadow mode forwarded a replication command")
	}
	for _, c := range fake.sawCmds() {
		if c == wire.ComBinlogDump {
			t.Fatal("the replication command reached the server in shadow mode")
		}
	}
}

// The client list is the first thing checked.
func TestAClientOutsideTheListNeverReachesTheServer(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	_, addr := relayFor(t, base+"        allow_clients: [\"192.0.2.0/24\"]\n", fake.addr())
	cl := dial(t, addr, "app", "sales", 0)
	if e := cl.ready(t); e == "" {
		t.Fatal("a client outside the list was admitted")
	}
	fake.mu.Lock()
	logins := fake.logins
	fake.mu.Unlock()
	// The login does cross, because the relay dials the server before it can
	// read the client's handshake response -- but nothing after it does, and
	// the connection ends.
	if got := fake.sawCmds(); len(got) != 0 {
		t.Fatalf("commands reached the server: %v (logins %d)", got, logins)
	}
}

// A rule widens the command list for its own traffic, end to end.
func TestARuleLetsOneAccountStreamTheBinlog(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	section := base +
		"        rules:\n" +
		"          - name: replica\n" +
		"            users: [repl]\n" +
		"            allow_commands: [binlog_dump, register_slave, ping, quit, query]\n"
	_, addr := relayFor(t, section, fake.addr())

	app := dial(t, addr, "app", "sales", 0)
	_ = app.ready(t)
	if e := app.send(t, wire.ComBinlogDump, ""); e == "" {
		t.Fatal("the application account was allowed to stream the binlog")
	}

	repl := dial(t, addr, "repl", "", 0)
	_ = repl.ready(t)
	if e := repl.send(t, wire.ComBinlogDump, ""); e != "" {
		t.Fatalf("the replica account was refused: %s", e)
	}
	var streamed bool
	for _, c := range fake.sawCmds() {
		if c == wire.ComBinlogDump {
			streamed = true
		}
	}
	if !streamed {
		t.Fatal("the replica's binlog_dump never reached the server")
	}
}
