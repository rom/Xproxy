package opcua

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/opcua"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// The relay end to end, through the real engine, against a server that keeps a
// record of what reached it.
//
// What reached the server is the assertion that matters. A test that checked only
// the client's answer would pass against a relay that refused a Write and forwarded
// it anyway — which is the bug that moves an actuator, and the one worth two
// assertions every time: the client was told, and the server never saw it.

// fakeServer is enough of an OPC UA server to complete the transport handshake and
// answer a service call, and it records every service that arrived.
type fakeServer struct {
	ln net.Listener
	// fault, when set, is the status code the server answers every service with,
	// which is what a server refusing something this relay allowed does.
	fault uint32
	// errorAfterHello, when set, makes the server answer the Hello with an ERR
	// instead of an ACK.
	errorAfterHello uint32

	mu  sync.Mutex
	saw []wire.Service
}

func startServer(t *testing.T, s *fakeServer) *fakeServer {
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
	r := wire.NewReader(c, 0)
	for {
		ch, err := r.Next()
		if err != nil {
			return
		}
		switch ch.Type {
		case wire.Hello:
			if s.errorAfterHello != 0 {
				_, _ = c.Write(wire.EncodeError(s.errorAfterHello, "no such endpoint"))
				return
			}
			_, _ = c.Write(ack())
			continue
		case wire.OpenSecureChannel:
			s.record(wire.SvcOpenChannel)
			// The answer's shape is not what is under test; what matters is that
			// the relay carried the request and passes the answer back.
			_, _ = c.Write(s.answer(ch, wire.SvcOpenChannelReply))
			continue
		}
		svc := s.serviceOf(ch)
		s.record(svc)
		_, _ = c.Write(s.answer(ch, svc+3))
	}
}

// serviceOf reads the service out of a MSG chunk the relay forwarded.
func (s *fakeServer) serviceOf(ch *wire.Chunk) wire.Service {
	_, off, err := wire.ParseSymmetric(ch.Body)
	if err != nil {
		return 0
	}
	_, off, err = wire.ParseSequence(ch.Raw, off)
	if err != nil {
		return 0
	}
	call, err := wire.ParseCall(ch.Raw[off:], true)
	if err != nil {
		return 0
	}
	return call.Service
}

// answer builds a response on the same channel and request identifier, which is
// what pairs it with the request.
func (s *fakeServer) answer(ch *wire.Chunk, svc wire.Service) []byte {
	var channel, token, request uint32
	if ch.Type == wire.OpenSecureChannel {
		if h, off, err := wire.ParseAsymmetric(ch.Body); err == nil {
			channel = h.SecureChannelID
			if sq, _, err := wire.ParseSequence(ch.Raw, off); err == nil {
				request = sq.RequestID
			}
		}
	} else if h, off, err := wire.ParseSymmetric(ch.Body); err == nil {
		channel, token = h.SecureChannelID, h.TokenID
		if sq, _, err := wire.ParseSequence(ch.Raw, off); err == nil {
			request = sq.RequestID
		}
	}
	status := s.fault
	id := svc
	if status != 0 {
		id = wire.SvcFault
	}
	body := build().node(0, uint32(id)).
		i64(wire.ToFileTime(time.Now())).u32(1).u32(status).
		noDiag().array(0).emptyExt()
	return build().u32(channel).u32(token).u32(1).u32(request).
		bytes(body.b).chunk(wire.Message, wire.Final)
}

func (s *fakeServer) record(svc wire.Service) {
	s.mu.Lock()
	s.saw = append(s.saw, svc)
	s.mu.Unlock()
}

func (s *fakeServer) seen() []wire.Service {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]wire.Service(nil), s.saw...)
}

// sawService says whether the server was reached by one.
func (s *fakeServer) sawService(svc wire.Service) bool {
	for _, got := range s.seen() {
		if got == svc {
			return true
		}
	}
	return false
}

// await waits for n services to arrive, which is how "the server was reached" is
// asserted without a sleep.
func (s *fakeServer) await(t *testing.T, n int, what string) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); ; {
		if len(s.seen()) >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: the server saw %v", what, s.seen())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

const relayYAML = `
version: 1
server:
  listeners:
    - name: plant
      address: "127.0.0.1:0"
      kind: opcua
      opcua:
%s
logging: {access: {enabled: false}}
upstreams:
  - {name: servers, endpoints: [{address: %q}]}
`

func relayFor(t *testing.T, section, server string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(relayYAML, section, server))
	return s, proxytest.Addr(t, s, "plant")
}

// The listener sections the tests compose from.
//
// They are kept apart rather than one string with overrides because YAML has no
// override: a second `default_action` in the same mapping is a parse error, not a
// replacement. So a test that decides its own default takes `head` and adds one.
const (
	// head is everything a test never varies: where the server is, which
	// policies and modes are carried, and that a certificate is not demanded —
	// the certificate rules have their own tests.
	head = "        upstream: servers\n" +
		"        security_modes: [none, sign, sign_and_encrypt]\n" +
		"        token_kinds: [anonymous, username, x509, issued]\n" +
		"        security_policies: [None, Basic256Sha256]\n" +
		"        require_client_certificate: false\n" +
		"        require_certificate_uri: false\n"
	// services is every service the tests exercise. The listener's own default
	// is what an HMI does, which excludes writing — so a test about writes has
	// to say so, which is the default behaving as documented.
	services = "        services: [open_secure_channel, close_secure_channel," +
		" create_session, activate_session, close_session, read, write, call," +
		" browse, create_subscription, create_monitored_items, publish]\n"
	// base is head with everything allowed, for the tests that are about
	// something else.
	base = head + "        default_action: allow\n" + services
	// baseServices is base without the service list, for a test that names its
	// own.
	baseServices = head + "        default_action: allow\n"
	// baseDefault is base without the default action, for a test that names its
	// own.
	baseDefault = head + services
)

// client is a connection to the relay that speaks UA TCP.
type client struct {
	t     *testing.T
	c     net.Conn
	r     *wire.Reader
	seq   uint32
	req   uint32
	chan_ uint32
}

func dial(t *testing.T, addr string) *client {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return &client{t: t, c: c, r: wire.NewReader(c, 0), chan_: 1}
}

func (cl *client) send(b []byte) {
	cl.t.Helper()
	if _, err := cl.c.Write(b); err != nil {
		cl.t.Fatalf("write: %v", err)
	}
}

// next reads the next message, or reports what happened instead.
func (cl *client) next() (*wire.Chunk, error) {
	if err := cl.c.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return nil, err
	}
	return cl.r.Next()
}

// handshake does the Hello and reads the answer.
func (cl *client) handshake(endpoint string) *wire.Chunk {
	cl.t.Helper()
	cl.send(hello(endpoint))
	ch, err := cl.next()
	if err != nil {
		cl.t.Fatalf("no answer to the hello: %v", err)
	}
	return ch
}

// channel opens a secure channel with a policy and a mode.
func (cl *client) channel(pol wire.SecurityPolicy, mode wire.MessageSecurityMode) *wire.Chunk {
	cl.t.Helper()
	cl.send(openChannel(pol, mode, 3600000))
	ch, err := cl.next()
	if err != nil {
		cl.t.Fatalf("no answer to the open secure channel: %v", err)
	}
	return ch
}

// service sends one service call on the channel and reads the answer.
func (cl *client) service(svc wire.Service, body *builder) *wire.Chunk {
	cl.t.Helper()
	cl.seq++
	cl.req++
	cl.send(msg(cl.chan_, 1, cl.seq, cl.req, call(svc, cl.req, body)))
	ch, err := cl.next()
	if err != nil {
		cl.t.Fatalf("no answer to %s: %v", svc, err)
	}
	return ch
}

// serviceQuiet sends one and returns whatever came back, including nothing.
func (cl *client) serviceQuiet(svc wire.Service, body *builder) (*wire.Chunk, error) {
	cl.t.Helper()
	cl.seq++
	cl.req++
	cl.send(msg(cl.chan_, 1, cl.seq, cl.req, call(svc, cl.req, body)))
	return cl.next()
}

// A plain connection that reaches the server: the Hello, the channel and a Read.
func TestTheHandshakeTheChannelAndAReadReachTheServer(t *testing.T) {
	up := startServer(t, &fakeServer{})
	_, addr := relayFor(t, base, up.addr())
	cl := dial(t, addr)

	if ch := cl.handshake("opc.tcp://127.0.0.1:4840"); ch.Type != wire.Acknowledge {
		t.Fatalf("the handshake answered %s", ch.Type)
	}
	if ch := cl.channel(wire.PolicyBasic256Sha256, wire.ModeSign); ch.Type != wire.Message {
		t.Fatalf("the channel answered %s", ch.Type)
	}
	if ch := cl.service(wire.SvcRead, readBody(op(n(3, 1001), wire.AttrValue))); ch.Type != wire.Message {
		t.Fatalf("the read answered %s", ch.Type)
	}
	up.await(t, 2, "the channel and the read")
	if !up.sawService(wire.SvcRead) {
		t.Errorf("the server saw %v", up.seen())
	}
}

// A connection that does not begin with a Hello is refused: the sizes would be
// unnegotiated, and no conforming implementation does it.
func TestAConnectionThatSkipsTheHelloIsRefused(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base, up.addr())
	cl := dial(t, addr)

	cl.send(msg(1, 1, 1, 1, call(wire.SvcRead, 1, readBody(op(n(0, 85), wire.AttrValue)))))
	ch, err := cl.next()
	if err != nil {
		t.Fatalf("no answer: %v", err)
	}
	if ch.Type != wire.Error {
		t.Fatalf("the relay answered %s, want ERR", ch.Type)
	}
	e, err := wire.ParseError(ch.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(e.Reason, "no_hello") {
		t.Errorf("the reason was %q", e.Reason)
	}
	until(t, s, refused("no_hello"), "the refusal")
	if len(up.seen()) != 0 {
		t.Errorf("the server was reached: %v", up.seen())
	}
}

// A Hello proposing a buffer larger than this relay will carry is refused, and it is
// refused rather than rewritten.
func TestABufferLargerThanTheRelayCarriesIsRefused(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base+"        max_chunk_size: 16384\n", up.addr())
	cl := dial(t, addr)

	cl.send(helloSized("opc.tcp://127.0.0.1:4840", 65536))
	ch, err := cl.next()
	if err != nil {
		t.Fatalf("no answer: %v", err)
	}
	if ch.Type != wire.Error {
		t.Fatalf("the relay answered %s", ch.Type)
	}
	until(t, s, refused("buffer_too_large"), "the refusal")
	if len(up.seen()) != 0 {
		t.Errorf("the server was reached: %v", up.seen())
	}
	// And a Hello inside the bound is carried, so the bound is a bound rather
	// than a refusal of everything.
	cl2 := dial(t, addr)
	cl2.send(helloSized("opc.tcp://127.0.0.1:4840", 8192))
	if ch, err := cl2.next(); err != nil || ch.Type != wire.Acknowledge {
		t.Fatalf("a hello inside the bound answered %v %v", ch, err)
	}
}

// An endpoint the listener does not name is refused.
func TestAnEndpointTheListenerDoesNotNameIsRefused(t *testing.T) {
	up := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base+
		"        endpoints: [\"opc.tcp://plant.example:4840/*\"]\n", up.addr())
	cl := dial(t, addr)
	cl.send(hello("opc.tcp://elsewhere:4840/UA/Server"))
	if ch, err := cl.next(); err != nil || ch.Type != wire.Error {
		t.Fatalf("the relay answered %v %v", ch, err)
	}
	until(t, s, refused("endpoint_not_allowed"), "the refusal")
	if len(up.seen()) != 0 {
		t.Errorf("the server was reached: %v", up.seen())
	}
}

// until waits for a counter to move, which is how a refusal that closes is
// observed.
func until(t *testing.T, s *proxy.Server, f func(proxy.Snapshot) bool, what string) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); ; {
		if f(s.Stats()) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: refusals %+v", what, s.Stats().Refusals["opcua"])
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func refused(reason string) func(proxy.Snapshot) bool {
	return func(st proxy.Snapshot) bool { return st.Refusals["opcua"][reason] > 0 }
}

func wouldRefuse(reason string) func(proxy.Snapshot) bool {
	return func(st proxy.Snapshot) bool { return st.WouldRefusals["opcua"][reason] > 0 }
}

// ended says a read error is the connection finishing.
func connEnded(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) ||
		errors.Is(err, io.ErrUnexpectedEOF) || isTimeout(err)
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
