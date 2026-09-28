package mms

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/mms"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// The listener, end to end, through the real engine.
//
// Every test asserts two things about a refusal: the client was told, and the IED
// never saw it. A test that checked only the client's answer would pass against a
// relay that refused a Write and forwarded it anyway -- which is the bug that moves a
// breaker, and the one worth two assertions every time.

// fakeIED is enough of an IEC 61850 server to complete the six-layer handshake and
// answer a confirmed request, and it records every service that arrived.
type fakeIED struct {
	ln net.Listener
	// errorEvery, when set, answers every confirmed request with a
	// confirmed-error carrying this class, which is an IED refusing something the
	// relay allowed.
	errorEvery int
	// refuseAssociation answers the association request with a rejected AARE.
	refuseAssociation bool
	// contexts, when set, is the presentation context list the IED confirms,
	// instead of the conventional {1: ACSE, 3: MMS}.
	contexts map[uint64][]uint64

	mu        sync.Mutex
	initiated bool
	saw       []wire.Service
	// invokes are the invoke identifiers seen, so a test can assert the answer was
	// matched to its request.
	invokes []uint64
}

func startIED(t *testing.T, s *fakeIED) *fakeIED {
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

func (s *fakeIED) addr() string { return s.ln.Addr().String() }

func (s *fakeIED) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.session(c)
	}
}

func (s *fakeIED) session(c net.Conn) {
	defer func() { _ = c.Close() }()
	r := wire.NewReader(c, 0)
	for {
		f, err := r.Next()
		if err != nil {
			return
		}
		out := s.answer(f)
		if out == nil {
			continue
		}
		if _, err := c.Write(out); err != nil {
			return
		}
	}
}

// answer produces the IED's reply to one frame, or nil where none is due.
func (s *fakeIED) answer(f *wire.Frame) []byte {
	cotp, err := wire.ParseCOTP(f.Body)
	if err != nil {
		return nil
	}
	switch cotp.Type {
	case wire.CR:
		return connectionConfirm()
	case wire.DT:
	default:
		return nil
	}
	sess, err := wire.ParseSession(cotp.Data)
	if err != nil || len(sess.UserData) == 0 {
		return nil
	}
	if sess.Kind == wire.SPDUConnect {
		return s.acceptFrame()
	}
	vals, err := wire.ParsePDVs(sess.UserData,
		wire.Contexts{1: wire.OIDACSE, 3: wire.OIDMMSAbstract})
	if err != nil {
		return nil
	}
	for _, v := range vals {
		if !v.IsMMS() {
			continue
		}
		m, err := wire.ParsePDU(v.Data)
		if err != nil {
			return nil
		}
		return s.answerMMS(m)
	}
	return nil
}

func (s *fakeIED) answerMMS(m *wire.Message) []byte {
	switch m.PDU {
	case wire.InitiateRequest:
		s.recordInitiate()
		return dataFrame(ctx(uint32(wire.InitiateResponse), integer(1)))
	case wire.ConfirmedRequest:
		s.record(m.Service, m.InvokeID)
		if s.errorEvery != 0 {
			return errorFrame(invokeOf(m), s.errorEvery, 1)
		}
		return dataFrame(ctx(uint32(wire.ConfirmedResponse), integer(int64(m.InvokeID))))
	}
	return nil
}

// recordInitiate notes the initiate without claiming it was a service, so that an
// assertion about which services arrived is not reading a service number of zero as
// `status`.
func (s *fakeIED) recordInitiate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.initiated = true
	s.invokes = append(s.invokes, 0)
}

func (s *fakeIED) record(svc wire.Service, invoke uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saw = append(s.saw, svc)
	s.invokes = append(s.invokes, invoke)
}

func (s *fakeIED) seen() []wire.Service {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]wire.Service(nil), s.saw...)
}

func (s *fakeIED) sawService(want wire.Service) bool {
	for _, got := range s.seen() {
		if got == want {
			return true
		}
	}
	return false
}

// await waits for the IED to have seen n messages, which is how a test asserts a
// forward rather than sleeping for one.
func (s *fakeIED) await(t *testing.T, n int, what string) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		if len(s.seen()) >= n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("the IED never saw %s: it saw %v", what, s.seen())
}

// acceptFrame is the presentation accept, carrying the context list and an AARE.
func (s *fakeIED) acceptFrame() []byte {
	contexts := s.contexts
	if contexts == nil {
		contexts = map[uint64][]uint64{1: {2, 2, 1, 0, 1}, 3: {1, 0, 9506, 2, 1}}
	}
	items := make([][]byte, 0, 2)
	for _, id := range []uint64{1, 3} {
		arcs, ok := contexts[id]
		if !ok {
			continue
		}
		items = append(items, seq(integer(int64(id)), oid(arcs...), seq(oid(2, 1, 1))))
	}
	result := int64(0)
	if s.refuseAssociation {
		result = 1
	}
	aare := app(1, ctx(1, oid(1, 0, 9506, 2, 3)), ctx(2, integer(result)))
	cp := set(ctx(2,
		ctx(4, items...),
		app(1, seq(integer(1), ctx(0, aare)))))
	session := append([]byte{wire.SPDUAccept, byte(len(cp) + 2), 193, byte(len(cp))}, cp...)
	return tpktFrame(append([]byte{0x02, wire.DT, 0x80}, session...))
}

// connectionConfirm is the COTP connection confirm.
func connectionConfirm() []byte {
	body := []byte{0x00, 0x01, 0x00, 0x02, 0x00,
		0xC0, 0x01, 0x0A, 0xC1, 0x02, 0x00, 0x01, 0xC2, 0x02, 0x00, 0x01}
	return tpktFrame(append([]byte{byte(len(body) + 1), wire.CC}, body...))
}

func tpktFrame(cotp []byte) []byte {
	out := []byte{wire.TPKTVersion, 0, 0, 0}
	binary.BigEndian.PutUint16(out[2:], uint16(len(cotp)+wire.TPKTHeader))
	return append(out, cotp...)
}

// The listener under test.

const relayYAML = `
server:
  listeners:
    - name: substation
      address: "127.0.0.1:0"
      kind: mms
      mms:
%s
logging: {access: {enabled: false}}
upstreams:
  - {name: ieds, endpoints: [{address: %q}]}
`

func relayFor(t *testing.T, section, ied string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(relayYAML, section, ied))
	return s, proxytest.Addr(t, s, "substation")
}

// The listener sections the tests compose from, kept apart because YAML has no
// override: a second `default_action` in one mapping is a parse error.
const (
	// head is what no test varies.
	head = "        upstream: ieds\n"
	// base allows everything, for the tests that are about something else.
	base = head + "        default_action: allow\n"
	// baseDefault is head without a default action, for a test that names its own.
	baseDefault = head
)

// client is a connection to the relay that speaks the whole stack.
type client struct {
	t *testing.T
	c net.Conn
	r *wire.Reader
}

func dial(t *testing.T, addr string) *client {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return &client{t: t, c: c, r: wire.NewReader(c, 0)}
}

func (cl *client) send(b []byte) {
	cl.t.Helper()
	if _, err := cl.c.Write(b); err != nil {
		cl.t.Fatalf("write: %v", err)
	}
}

// next reads the next frame, or says what happened instead.
func (cl *client) next() (*wire.Frame, error) {
	if err := cl.c.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return nil, err
	}
	return cl.r.Next()
}

// connect does the COTP exchange.
func (cl *client) connect() {
	cl.t.Helper()
	body := []byte{0x00, 0x00, 0x00, 0x01, 0x00,
		0xC0, 0x01, 0x0A, 0xC1, 0x02, 0x00, 0x01, 0xC2, 0x02, 0x00, 0x01}
	cl.send(tpktFrame(append([]byte{byte(len(body) + 1), wire.CR}, body...)))
	f, err := cl.next()
	if err != nil {
		cl.t.Fatalf("no connection confirm: %v", err)
	}
	cotp, err := wire.ParseCOTP(f.Body)
	if err != nil || cotp.Type != wire.CC {
		cl.t.Fatalf("the transport answered %v (%v)", f.Body, err)
	}
}

// associate sends the ACSE associate request with the given identity, and an optional
// cleartext password.
func (cl *client) associate(apTitle []uint64, qualifier int64, password string) *wire.Frame {
	cl.t.Helper()
	fields := [][]byte{ctx(1, oid(1, 0, 9506, 2, 3))}
	if len(apTitle) > 0 {
		fields = append(fields, ctx(6, oid(apTitle...)))
	}
	if qualifier >= 0 {
		fields = append(fields, ctx(7, integer(qualifier)))
	}
	if password != "" {
		fields = append(fields,
			ctxp(11, []byte{0x2A, 0x86, 0x48}),
			ctx(12, ctxp(0, []byte(password))))
	}
	aarq := app(0, fields...)
	cp := set(ctx(2,
		ctx(4,
			seq(integer(1), oid(2, 2, 1, 0, 1), seq(oid(2, 1, 1))),
			seq(integer(3), oid(1, 0, 9506, 2, 1), seq(oid(2, 1, 1)))),
		app(1, seq(integer(1), ctx(0, aarq)))))
	session := append([]byte{wire.SPDUConnect, byte(len(cp) + 2), 193, byte(len(cp))}, cp...)
	cl.send(tpktFrame(append([]byte{0x02, wire.DT, 0x80}, session...)))
	f, err := cl.next()
	if err != nil {
		cl.t.Fatalf("no association answer: %v", err)
	}
	return f
}

// associateQuiet sends the same and returns whatever came back, including nothing --
// which is what an association-level refusal looks like, since an MMS error cannot
// answer something that happens before there is an MMS association.
func (cl *client) associateQuiet(apTitle []uint64, qualifier int64, password string) error {
	cl.t.Helper()
	fields := [][]byte{ctx(1, oid(1, 0, 9506, 2, 3))}
	if len(apTitle) > 0 {
		fields = append(fields, ctx(6, oid(apTitle...)))
	}
	if qualifier >= 0 {
		fields = append(fields, ctx(7, integer(qualifier)))
	}
	if password != "" {
		fields = append(fields,
			ctxp(11, []byte{0x2A, 0x86, 0x48}),
			ctx(12, ctxp(0, []byte(password))))
	}
	aarq := app(0, fields...)
	cp := set(ctx(2,
		ctx(4,
			seq(integer(1), oid(2, 2, 1, 0, 1), seq(oid(2, 1, 1))),
			seq(integer(3), oid(1, 0, 9506, 2, 1), seq(oid(2, 1, 1)))),
		app(1, seq(integer(1), ctx(0, aarq)))))
	session := append([]byte{wire.SPDUConnect, byte(len(cp) + 2), 193, byte(len(cp))}, cp...)
	cl.send(tpktFrame(append([]byte{0x02, wire.DT, 0x80}, session...)))
	_, err := cl.next()
	return err
}

// initiate sends the MMS initiate, after which the association is up.
func (cl *client) initiate() {
	cl.t.Helper()
	cl.send(dataFrame(ctx(uint32(wire.InitiateRequest), integer(1))))
	if _, err := cl.next(); err != nil {
		cl.t.Fatalf("no initiate response: %v", err)
	}
}

// service sends one confirmed request and returns the answer.
func (cl *client) service(body []byte) *wire.Frame {
	cl.t.Helper()
	cl.send(dataFrame(body))
	f, err := cl.next()
	if err != nil {
		cl.t.Fatalf("no answer: %v", err)
	}
	return f
}

// serviceQuiet sends one and returns whatever came back, including nothing.
func (cl *client) serviceQuiet(body []byte) (*wire.Frame, error) {
	cl.t.Helper()
	cl.send(dataFrame(body))
	return cl.next()
}

// session opens a connection, associates and initiates, which is what most tests need
// before they say anything.
func session(t *testing.T, addr string) *client {
	t.Helper()
	cl := dial(t, addr)
	cl.connect()
	cl.associate([]uint64{1, 1, 999, 1}, 12, "")
	cl.initiate()
	return cl
}

// The builders. They are here rather than in the wire package's tests because these
// are the *listener's* tests and they need whole frames.

func tlvT(class byte, cons bool, tag uint32, body ...[]byte) []byte {
	var b []byte
	for _, p := range body {
		b = append(b, p...)
	}
	first := class
	if cons {
		first |= wire.Constructed
	}
	var id []byte
	if tag < 0x1F {
		id = []byte{first | byte(tag)}
	} else {
		id = append([]byte{first | 0x1F}, base128(uint64(tag))...)
	}
	id = append(id, berLen(len(b))...)
	return append(id, b...)
}

func base128(v uint64) []byte {
	if v == 0 {
		return []byte{0}
	}
	var out []byte
	for v > 0 {
		out = append([]byte{byte(v & 0x7F)}, out...)
		v >>= 7
	}
	for i := 0; i < len(out)-1; i++ {
		out[i] |= 0x80
	}
	return out
}

func ctx(tag uint32, body ...[]byte) []byte { return tlvT(wire.ClassContext, true, tag, body...) }
func ctxp(tag uint32, body []byte) []byte   { return tlvT(wire.ClassContext, false, tag, body) }
func app(tag uint32, body ...[]byte) []byte { return tlvT(wire.ClassApplication, true, tag, body...) }
func seq(body ...[]byte) []byte             { return tlvT(0, true, wire.TagSequence, body...) }
func set(body ...[]byte) []byte             { return tlvT(0, true, wire.TagSet, body...) }
func univ(tag uint32, body []byte) []byte   { return tlvT(0, false, tag, body) }
func visible(s string) []byte               { return univ(wire.TagVisibleStr, []byte(s)) }
func integer(v int64) []byte                { return univ(wire.TagInteger, berContent(v)) }

func oid(arcs ...uint64) []byte {
	if len(arcs) < 2 {
		panic("an object identifier has at least two arcs")
	}
	b := []byte{byte(arcs[0]*40 + arcs[1])}
	for _, a := range arcs[2:] {
		b = append(b, base128(a)...)
	}
	return univ(wire.TagOID, b)
}

// objectName renders a domain-specific ObjectName.
func objectName(domain, item string) []byte {
	return ctx(1, seq(visible(domain), visible(item)))
}

// readBody renders a confirmed Read of the given names.
func readBody(invoke int64, names ...[]byte) []byte {
	vars := make([][]byte, 0, len(names))
	for _, n := range names {
		vars = append(vars, seq(ctx(0, n)))
	}
	return ctx(uint32(wire.ConfirmedRequest), integer(invoke),
		ctx(uint32(wire.SvcRead), ctx(1, ctx(0, vars...))))
}

// writeBody renders a confirmed Write of one name and one value.
func writeBody(invoke int64, name []byte) []byte {
	return ctx(uint32(wire.ConfirmedRequest), integer(invoke),
		ctx(uint32(wire.SvcWrite),
			ctx(0, seq(ctx(0, name))),
			ctx(0, ctxp(5, []byte{0x01})))) // a boolean value, whose content is never read
}

// serviceBody renders a confirmed request for a service whose body is one identifier,
// which is the shape of the domain services.
func serviceBody(invoke int64, svc wire.Service, arg string) []byte {
	return ctx(uint32(wire.ConfirmedRequest), integer(invoke),
		ctx(uint32(svc), visible(arg)))
}

// fileBody renders a file service naming a path.
func fileBody(invoke int64, svc wire.Service, parts ...string) []byte {
	comps := make([][]byte, 0, len(parts))
	for _, p := range parts {
		comps = append(comps, univ(wire.TagGeneralStr, []byte(p)))
	}
	return ctx(uint32(wire.ConfirmedRequest), integer(invoke),
		ctx(uint32(svc), seq(comps...), integer(0)))
}

// The assertions.

// refused says the counter for this reason has been bumped.
func refused(reason string) func(*proxy.Server) bool {
	return func(s *proxy.Server) bool {
		return s.Stats().Refusals["mms"][reason] > 0
	}
}

// wouldRefuse says the shadow counter has.
func wouldRefuse(reason string) func(*proxy.Server) bool {
	return func(s *proxy.Server) bool {
		return s.Stats().WouldRefusals["mms"][reason] > 0
	}
}

// until waits for a condition, which is how a test asserts a counter without racing
// the goroutine that writes it.
func until(t *testing.T, s *proxy.Server, cond func(*proxy.Server) bool, what string) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		if cond(s) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s never happened; refusals %v, would-refuse %v", what,
		s.Stats().Refusals["mms"], s.Stats().WouldRefusals["mms"])
}

// isError says a frame carries an MMS confirmed-error, which is what a refusal looks
// like to a client.
func isError(t *testing.T, f *wire.Frame) bool {
	t.Helper()
	cotp, err := wire.ParseCOTP(f.Body)
	if err != nil || cotp.Type != wire.DT {
		return false
	}
	s, err := wire.ParseSession(cotp.Data)
	if err != nil {
		return false
	}
	vals, err := wire.ParsePDVs(s.UserData, wire.Contexts{3: wire.OIDMMSAbstract})
	if err != nil {
		return false
	}
	for _, v := range vals {
		m, err := wire.ParsePDU(v.Data)
		if err != nil {
			continue
		}
		if m.PDU == wire.ConfirmedError || m.PDU == wire.Reject {
			return true
		}
	}
	return false
}

// closed says the connection ended, which is what a layer below the service does
// instead of answering.
func closed(t *testing.T, cl *client) bool {
	t.Helper()
	_, err := cl.next()
	return err != nil
}

// bodyContains is for the tests that assert on the raw answer.
func bodyContains(f *wire.Frame, b []byte) bool { return bytes.Contains(f.Raw, b) }

// awaitInitiate waits for the IED to have seen the MMS initiate, which is how a test
// asserts that an association was carried without naming a service.
func awaitInitiate(t *testing.T, s *fakeIED) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		s.mu.Lock()
		ok := s.initiated
		s.mu.Unlock()
		if ok {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the IED never saw the initiate")
}
