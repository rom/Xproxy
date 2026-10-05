package simulate

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/proxy"
)

// An Input is one thing to send: bytes, at a listener, from a client address.
type Input struct {
	// Name is how the report refers to it: a line number, a request line, a
	// request identifier out of a capture file.
	Name string
	// Listener is the listener to send it to, by name. Empty means the only
	// listener the configuration has, which is the common case and saves an
	// operator writing it on every line.
	Listener string
	// Client is the address to appear to come from. On a listener that parses
	// a PROXY protocol header the simulation sends one, and the policy decides
	// on this address: an address-based allow list, which is most of what an OT
	// policy has to work with, is then actually exercised. On a listener that
	// does not, it only labels the outcome, and the report says so by name --
	// a simulation cannot forge a source address on a loopback connection, and
	// pretending otherwise would make an allow list look tested when it was not.
	Client string
	// Bytes is what to write.
	Bytes []byte
}

// An Outcome is what one configuration decided about one input.
type Outcome struct {
	Input string `json:"input"`
	// Listener is the listener it went to, and Kind that listener's protocol.
	Listener string `json:"listener"`
	Kind     string `json:"kind"`
	// Decision is allowed, refused, or error -- the last meaning the
	// simulation could not get an answer, which is not the same as a refusal
	// and must never be reported as one.
	Decision string `json:"decision"`
	// Reason is the refusal's reason where there was one, in the spelling the
	// security log uses.
	Reason string `json:"reason,omitempty"`
	// Status is the HTTP status where the listener speaks HTTP.
	Status int `json:"status,omitempty"`
	// Client is the address the input claimed to come from, where it named one.
	Client string `json:"client,omitempty"`
	// Relayed says the input reached the simulation's sink, which is the
	// positive evidence behind an "allowed": the listener did not merely fail
	// to refuse, it passed the traffic on.
	Relayed bool `json:"relayed,omitempty"`
	// Events are the security events this input produced, in order. A refusal
	// is one of them; an alert that did not refuse is worth seeing too, since
	// a rule that is about to start refusing usually alerts first.
	Events []Event `json:"events,omitempty"`
	// Err is why the decision is "error".
	Err string `json:"error,omitempty"`
}

// An Event is one security event, reduced to what a comparison needs.
type Event struct {
	Action string `json:"action"`
	Reason string `json:"reason"`
	// Severity and Detail are carried where the event has them.
	Severity string `json:"severity,omitempty"`
	Detail   string `json:"detail,omitempty"`
	Rule     string `json:"rule,omitempty"`
}

// Decisions.
const (
	Allowed = "allowed"
	Refused = "refused"
	Errored = "error"
)

// A Run is one configuration, started offline, ready to be asked.
type Run struct {
	srv    *proxy.Server
	cfg    *config.Config
	sink   *sink
	logs   *logging.Logs
	events *collector
	report Report
	// kinds maps a listener name to its kind and bound address.
	kinds map[string]string
	addrs map[string]string
	// proxies are the listeners that parse a PROXY protocol header, so a
	// client address can be delivered to them rather than only reported.
	proxies map[string]bool
	// noted are the listeners already named in a note about an ignored client
	// address, so a corpus of five hundred items says it once per listener.
	noted map[string]bool
}

// Start neutralises a configuration and starts it.
//
// dir is the simulation's own directory: the copied state and the throwaway
// certificates live there, and nothing outside it is written.
func Start(in *config.Config, dir string) (*Run, error) {
	cfg, rep, err := Offline(in, dir)
	if err != nil {
		return nil, err
	}
	r := &Run{cfg: cfg, report: rep, kinds: map[string]string{}, addrs: map[string]string{},
		proxies: map[string]bool{}, noted: map[string]bool{}}
	if r.sink, err = newSink(); err != nil {
		return nil, err
	}
	pointAtSink(cfg, r.sink.addr())
	if err := bindLocally(cfg, dir, &r.report); err != nil {
		r.sink.close()
		return nil, err
	}
	r.events = &collector{}
	r.logs = &logging.Logs{
		Access:   slog.New(&handler{c: r.events, stream: "access"}),
		Error:    slog.New(&handler{c: r.events, stream: "error"}),
		Security: slog.New(&handler{c: r.events, stream: "security"}),
		Audit:    slog.New(&handler{c: r.events, stream: "audit"}),
	}
	srv, err := proxy.New(cfg, r.logs)
	if err != nil {
		r.sink.close()
		return nil, fmt.Errorf("starting the simulation: %w", err)
	}
	if err := srv.Start(); err != nil {
		r.sink.close()
		return nil, fmt.Errorf("starting the simulation: %w", err)
	}
	r.srv = srv
	for name, addr := range srv.Addrs() {
		if strings.Contains(name, "/") {
			continue // an extra address of a listener, not a listener
		}
		r.addrs[name] = addr
	}
	for _, l := range cfg.Server.Listeners {
		kind := l.Kind
		if kind == "" {
			kind = "http"
		}
		r.kinds[l.Name] = kind
		r.proxies[l.Name] = l.ProxyProtocol
		r.report.Listeners = append(r.report.Listeners, l.Name)
	}
	sort.Strings(r.report.Listeners)
	return r, nil
}

// Report is what the simulation did to the configuration before running it.
func (r *Run) Report() Report { return r.report }

// Summary is the one-line form.
func (r *Run) Summary() string { return r.report.summary() }

// Close stops the simulation.
func (r *Run) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := r.srv.Shutdown(ctx)
	r.sink.close()
	return err
}

// Ask sends one input and reports what the configuration decided.
//
// Inputs are sent one at a time, and every security event between the write
// and the reply is attributed to that input. That is what makes the attribution
// exact, and it is also the simulation's one deliberate difference from real
// traffic: a rate limit or a correlation window sees a serial client rather
// than whatever concurrency the estate has. A policy that depends on
// concurrency is not one this answers.
func (r *Run) Ask(in Input) Outcome {
	name := in.Listener
	if name == "" && len(r.addrs) == 1 {
		for n := range r.addrs {
			name = n
		}
	}
	out := Outcome{Input: in.Name, Listener: name, Kind: r.kinds[name]}
	addr, ok := r.addrs[name]
	if !ok {
		out.Decision, out.Err = Errored, "no listener named "+name+" in this configuration"
		return out
	}
	out.Client = in.Client
	payload, err := r.asClient(in, name, addr)
	if err != nil {
		out.Decision, out.Err = Errored, err.Error()
		return out
	}
	from := r.events.mark()
	atSink := r.sink.mark()
	reply, status, err := exchange(addr, payload, r.kinds[name] == "http", func() bool {
		if r.sink.since(atSink) > 0 {
			return true
		}
		_, refused := refusal(r.events.since(from))
		return refused
	})
	out.Events = r.events.since(from)
	out.Status = status
	out.Relayed = r.sink.since(atSink) > 0
	switch {
	case err != nil && len(out.Events) == 0:
		// Nothing was decided and nothing came back: the simulation failed to
		// ask the question, which is not an answer to it.
		out.Decision, out.Err = Errored, err.Error()
		return out
	case err != nil:
		out.Err = err.Error()
	}
	if ev, refused := refusal(out.Events); refused {
		out.Decision, out.Reason = Refused, ev.Reason
		return out
	}
	// HTTP says it in the status as well, and a 4xx from the gateway is a
	// refusal even where the event stream is quiet (a route that does not
	// exist, a host nothing serves).
	if out.Kind == "http" && status >= 400 {
		out.Decision = Refused
		if out.Reason == "" {
			out.Reason = fmt.Sprintf("status_%d", status)
		}
		return out
	}
	// Nothing refused it, so the question is whether anything happened at all.
	// "Allowed" is asserted only on evidence: the listener relayed the input to
	// the sink, or it answered the client itself -- which is what a decoy, a
	// cache hit or a redirect does. A listener that neither refused, relayed
	// nor answered decided nothing: the input was incomplete, or it was
	// dropped somewhere that logs nothing. Calling that "allowed" would put a
	// hole in the report where the honest answer is a question mark, and the
	// whole value of this tool is that an operator can act on its output.
	if out.Relayed || len(reply) > 0 {
		out.Decision = Allowed
		return out
	}
	out.Decision = Errored
	if out.Err == "" {
		out.Err = "nothing was relayed, answered or refused: an incomplete input?"
	}
	return out
}

// asClient prepends a PROXY protocol header where the listener parses one, so
// that an input naming a client address is decided on that address rather than
// on the loopback address this program necessarily connects from.
//
// Where the listener does not parse one, the address is reported and nothing
// else, and the run says so once per listener. Saying it matters more than the
// feature does: an operator reading "allowed" for a frame they labelled with an
// address their allow list excludes would conclude the allow list does not work.
func (r *Run) asClient(in Input, listener, addr string) ([]byte, error) {
	if in.Client == "" {
		return in.Bytes, nil
	}
	if !r.proxies[listener] {
		if !r.noted[listener] {
			r.noted[listener] = true
			r.report.Notes = append(r.report.Notes, "listener "+listener+
				": a client address was given and could not be delivered, because the listener "+
				"does not parse a PROXY protocol header. The policy saw the loopback address, "+
				"so no rule about a client address was exercised")
		}
		return in.Bytes, nil
	}
	h, err := proxyHeader(in.Client, addr)
	if err != nil {
		return nil, err
	}
	return append(h, in.Bytes...), nil
}

// simClientPort is the source port in the header the simulation writes. The
// PROXY protocol requires one and no policy in this project is written about a
// client's ephemeral port, so it is a constant rather than a lie that varies.
const simClientPort = 54321

// proxyHeader writes a version 1 PROXY protocol header for one input.
//
// The destination is the loopback address of the client's own family rather
// than the address the listener is really on: the header's two addresses must
// agree on family or it is refused, and what the policy reads is the source.
func proxyHeader(client, server string) ([]byte, error) {
	src, err := netip.ParseAddr(client)
	if err != nil {
		return nil, fmt.Errorf("client %q: not an address", client)
	}
	src = src.Unmap()
	family, dst := "TCP4", netip.AddrFrom4([4]byte{127, 0, 0, 1})
	if !src.Is4() {
		family, dst = "TCP6", netip.IPv6Loopback()
	}
	port := uint16(0)
	if ap, err := netip.ParseAddrPort(server); err == nil {
		port = ap.Port()
	}
	return []byte(fmt.Sprintf("PROXY %s %s %s %d %d\r\n",
		family, src, dst, simClientPort, port)), nil
}

// refusal finds the event that refused, if one did.
//
// An "alert" is not a refusal: the whole point of the alert-only modes is that
// the operation went through. A simulation that read one as a refusal would
// tell an operator their new rule was already blocking things.
func refusal(events []Event) (Event, bool) {
	for _, e := range events {
		switch e.Action {
		case "deny", "refuse", "refused", "block", "blocked":
			return e, true
		}
	}
	return Event{}, false
}

// Timings of one exchange. maxWait is the longest an input may take before the
// simulation gives up on it; pollEvery is how often the evidence is checked.
// Both are small because there is no real origin anywhere in this: everything
// that answers is in this process.
const (
	dialTimeout = 2 * time.Second
	maxWait     = 3 * time.Second
	pollEvery   = 5 * time.Millisecond
	maxReply    = 1 << 20
)

// exchange writes one input and reads what comes back, stopping as soon as the
// answer is in rather than waiting out the deadline.
//
// Waiting matters here. A listener that speaks bytes answers only when the
// device does, and there is no device: the sink reads and says nothing. So the
// read would sit until the deadline on every single input, and a corpus of a
// hundred frames would take five minutes to tell an operator something the
// engine decided in microseconds. decided is the evidence the caller is waiting
// for -- the input reached the sink, or an event refused it -- and an HTTP
// response is its own evidence, so the head arriving ends the exchange.
//
// Only an input that produces nothing at all waits the full deadline, which is
// the one case where waiting is the point: it is the difference between "no" and
// "no answer".
func exchange(addr string, payload []byte, wantHTTP bool, decided func() bool) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(maxWait))
	if _, err := c.Write(payload); err != nil {
		return nil, 0, err
	}
	if tc, ok := c.(*net.TCPConn); ok && !wantHTTP {
		// A byte-stream kind may be waiting for more from the client; telling
		// it there is no more is what makes it decide and answer.
		_ = tc.CloseWrite()
	}
	rd := &progress{done: make(chan struct{})}
	go rd.read(c)
	deadline := time.After(maxWait)
	tick := time.NewTicker(pollEvery)
	defer tick.Stop()
	for {
		select {
		case <-rd.done:
			b, err := rd.result()
			return b, statusIf(wantHTTP, b), err
		case <-deadline:
			b, _ := rd.result()
			return b, statusIf(wantHTTP, b), nil
		case <-tick.C:
			b, _ := rd.result()
			if wantHTTP && headComplete(b) {
				return b, statusIf(wantHTTP, b), nil
			}
			if !wantHTTP && decided() {
				return b, 0, nil
			}
		}
	}
}

// progress is a read in flight: what has arrived so far, readable while the
// read is still going.
type progress struct {
	mu   sync.Mutex
	buf  []byte
	err  error
	done chan struct{}
}

func (p *progress) read(c net.Conn) {
	defer close(p.done)
	b := make([]byte, 16<<10)
	for {
		n, err := c.Read(b)
		if n > 0 {
			p.mu.Lock()
			if len(p.buf)+n > maxReply {
				n = maxReply - len(p.buf)
			}
			p.buf = append(p.buf, b[:n]...)
			over := len(p.buf) >= maxReply
			p.mu.Unlock()
			if over {
				break
			}
		}
		if err != nil {
			p.mu.Lock()
			if !isTimeout(err) && !errors.Is(err, io.EOF) {
				p.err = err
			}
			p.mu.Unlock()
			return
		}
	}
}

func (p *progress) result() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]byte, len(p.buf))
	copy(out, p.buf)
	return out, p.err
}

// headComplete is true once a whole HTTP response head has arrived. The body is
// not waited for: nothing in the report reads it, and the sink's own body is
// three words long.
func headComplete(b []byte) bool { return bytes.Contains(b, []byte("\r\n\r\n")) }

func statusIf(wantHTTP bool, b []byte) int {
	if !wantHTTP {
		return 0
	}
	return statusOf(b)
}

// statusOf reads the status line of an HTTP response, or 0.
func statusOf(b []byte) int {
	if len(b) < 12 || !strings.HasPrefix(string(b[:5]), "HTTP/") {
		return 0
	}
	f := strings.Fields(string(b[:min(len(b), 64)]))
	if len(f) < 2 {
		return 0
	}
	n := 0
	for _, r := range f[1] {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	return n
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// pointAtSink replaces every upstream endpoint with the sink.
//
// The pool names, the balancers and the per-route assignments are untouched,
// because a route's upstream is part of the policy: which pool a request goes
// to is a decision, and only where that pool actually is has changed.
func pointAtSink(cfg *config.Config, addr string) {
	ups := make([]config.Upstream, len(cfg.Upstreams))
	for i, u := range cfg.Upstreams {
		c := u
		c.Endpoints = []config.Endpoint{{Address: addr}}
		// A health check would mark the sink up or down on its own schedule
		// and make one run's answer depend on the timing of another.
		c.HealthCheck = nil
		c.Discovery = nil
		ups[i] = c
	}
	cfg.Upstreams = ups
}

// bindLocally puts every listener on a loopback port the kernel chooses, and
// gives a TLS listener a certificate of the simulation's own.
//
// The estate's certificate and key are not read: a simulation has no business
// opening the private key of a production listener, and the handshake it needs
// is one with itself.
func bindLocally(cfg *config.Config, dir string, rep *Report) error {
	// A simulation owes no client a drain. The estate's shutdown_timeout is
	// there so a deployment does not cut a session in half; here the only
	// sessions are the ones this program just made, and waiting the estate's ten
	// seconds for them at the end of every run would cost more than the whole
	// simulation. It decides nothing, so it is not in the report.
	if cfg.Server.ShutdownTimeout == 0 || time.Duration(cfg.Server.ShutdownTimeout) > simShutdown {
		cfg.Server.ShutdownTimeout = config.Duration(simShutdown)
	}
	// A PROXY protocol header is read only from a peer in trusted_proxies, and
	// the estate's list names its balancers rather than this program. Without
	// loopback in it every client address a corpus named would be silently
	// dropped -- which is the failure mode a simulator must not have, since the
	// answer would look like a policy decision. Named in the report, because it
	// is a change to a list whose whole job is to be short.
	for _, l := range cfg.Server.Listeners {
		if !l.ProxyProtocol {
			continue
		}
		cfg.TrustedProxies = append(cfg.TrustedProxies, "127.0.0.1/32", "::1/128")
		rep.Notes = append(rep.Notes, "loopback added to trusted_proxies, so the PROXY "+
			"protocol header carrying each input's client address is read")
		break
	}
	ls := make([]config.Listener, len(cfg.Server.Listeners))
	for i, l := range cfg.Server.Listeners {
		c := l
		c.Address = "127.0.0.1:0"
		if c.TLS != nil {
			cert, key, err := throwawayCert(dir, c.Name)
			if err != nil {
				return err
			}
			t := *c.TLS
			t.Certificates = []config.Certificate{{CertFile: cert, KeyFile: key}}
			t.ACME = nil
			t.ClientCAFile = ""
			t.ECH = nil
			c.TLS = &t
			rep.Notes = append(rep.Notes,
				"listener "+c.Name+": a throwaway certificate, not the estate's")
		}
		ls[i] = c
	}
	cfg.Server.Listeners = ls
	return nil
}

// simShutdown is how long the simulation waits for its own connections to end.
const simShutdown = 250 * time.Millisecond

// collector keeps the events in order behind a mutex, because the engine writes
// them from the goroutines serving the connection.
type collector struct {
	mu     sync.Mutex
	events []Event
}

func (c *collector) add(e Event) {
	c.mu.Lock()
	c.events = append(c.events, e)
	c.mu.Unlock()
}

func (c *collector) mark() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.events)
}

func (c *collector) since(n int) []Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	if n >= len(c.events) {
		return nil
	}
	out := make([]Event, len(c.events)-n)
	copy(out, c.events[n:])
	return out
}

// handler turns the engine's log records into events. Only the security stream
// carries decisions; the others are read for nothing but their errors, which
// is why an error record becomes an event too -- a listener that could not
// parse the input is the answer to the question, not a silence.
type handler struct {
	c      *collector
	stream string
	attrs  []slog.Attr
}

func (h *handler) Enabled(context.Context, slog.Level) bool { return true }

func (h *handler) Handle(_ context.Context, r slog.Record) error {
	if h.stream != "security" && r.Level < slog.LevelError {
		return nil
	}
	e := Event{Action: h.stream}
	if h.stream == "error" {
		e.Action, e.Reason = "error", r.Message
	}
	collect := func(a slog.Attr) bool {
		switch a.Key {
		case "action":
			e.Action = a.Value.String()
		case "reason":
			e.Reason = a.Value.String()
		case "severity":
			e.Severity = a.Value.String()
		case "detail", "operation":
			e.Detail = a.Value.String()
		case "rule", "id":
			e.Rule = a.Value.String()
		}
		return true
	}
	for _, a := range h.attrs {
		collect(a)
	}
	r.Attrs(collect)
	h.c.add(e)
	return nil
}

func (h *handler) WithAttrs(as []slog.Attr) slog.Handler {
	n := *h
	n.attrs = append(append([]slog.Attr{}, h.attrs...), as...)
	return &n
}

func (h *handler) WithGroup(string) slog.Handler { return h }

// sink is the origin every upstream points at: in this process, answering
// nothing that could be mistaken for a real service.
//
// It does two jobs. It answers HTTP, because a reverse proxy's response path is
// part of the policy and a request that never gets a response has not been
// through it. And it counts, per connection, whether anything arrived at all --
// which is the only positive evidence a simulation has that a listener relayed
// what it was given. Without it, a frame a listener silently dropped would read
// as one it allowed, and a policy simulation that answers "allowed" when it does
// not know is worse than one that refuses to answer.
//
// For everything that is not HTTP it reads and says nothing. It does not
// pretend to be a PLC, a mail server or a directory: synthesising a plausible
// reply for thirty protocols would mean answering questions this program cannot
// answer, so a policy that decides on what the device replied is outside what a
// simulation covers, and USAGE.md says so.
type sink struct {
	ln    net.Listener
	http  *http.Server
	conns chan net.Conn
	mu    sync.Mutex
	got   int // connections that delivered at least one byte
	done  chan struct{}
}

func newSink() (*sink, error) {
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("simulation sink: %w", err)
	}
	s := &sink{ln: ln, conns: make(chan net.Conn), done: make(chan struct{})}
	s.http = &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			// Enough of a response for the reverse proxy's response path to
			// run, and plainly not a real one.
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("X-Xproxy-Simulated", "1")
			w.WriteHeader(200)
			_, _ = io.WriteString(w, "simulated origin\n")
		}),
	}
	go func() { _ = s.http.Serve(handoff{c: s.conns, done: s.done}) }()
	go s.accept()
	return s, nil
}

func (s *sink) addr() string { return s.ln.Addr().String() }

// accept takes every connection, decides from its first bytes whether it is
// HTTP, and counts it as a delivery either way.
func (s *sink) accept() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.serve(c)
	}
}

func (s *sink) serve(c net.Conn) {
	_ = c.SetDeadline(time.Now().Add(sinkDeadline))
	br := bufio.NewReader(c)
	// Peek blocks until a byte arrives or the deadline passes, which is what
	// makes an empty connection -- a relay that dialled and then refused the
	// request -- distinguishable from one that carried something.
	head, _ := br.Peek(1)
	if len(head) == 0 {
		_ = c.Close()
		return
	}
	s.delivered()
	head, _ = br.Peek(min(br.Buffered(), 64))
	if !looksHTTP(head) {
		// Read what it has to say and close. The relay gets EOF where a device
		// would have answered, which is the honest form of "there is no device
		// here" -- and it has to come quickly: a relay blocked reading a device
		// that never replies keeps its session open, and the simulation would
		// then wait out that session's own idle timeout at the end of every run.
		s.drain(c, br)
		return
	}
	select {
	case s.conns <- &buffered{Conn: c, r: br}:
	case <-s.done:
		_ = c.Close()
	}
}

// drain reads a non-HTTP connection until it goes quiet, then closes it.
func (s *sink) drain(c net.Conn, br *bufio.Reader) {
	defer func() { _ = c.Close() }()
	b := make([]byte, 32<<10)
	for n := 0; n < maxSinkRead; {
		_ = c.SetReadDeadline(time.Now().Add(sinkIdle))
		got, err := br.Read(b)
		n += got
		if err != nil {
			return
		}
	}
}

// sinkIdle is how long the sink waits for more on a connection that is not
// HTTP before deciding there is no more and closing it.
const sinkIdle = 100 * time.Millisecond

// sinkDeadline bounds one connection at the sink. It is longer than the
// deadline Ask gives an input, so a slow relay is the caller's timeout rather
// than a connection the sink dropped underneath it.
const sinkDeadline = 30 * time.Second

// maxSinkRead bounds what one non-HTTP connection may deliver. A simulation
// sends a corpus item, not a file transfer.
const maxSinkRead = 8 << 20

// looksHTTP is true for the start of an HTTP/1 request line. It is deliberately
// narrow: anything it is unsure about is read as bytes rather than handed to an
// HTTP parser that would answer 400 to a Modbus frame and leave the relay
// logging a response error that had nothing to do with the policy.
func looksHTTP(b []byte) bool {
	for _, m := range [...]string{"GET ", "HEAD ", "POST ", "PUT ", "DELETE ",
		"CONNECT ", "OPTIONS ", "TRACE ", "PATCH ", "PRI "} {
		if len(b) >= len(m) && string(b[:len(m)]) == m {
			return true
		}
	}
	return false
}

// delivered records that one connection carried something.
func (s *sink) delivered() {
	s.mu.Lock()
	s.got++
	s.mu.Unlock()
}

// mark and since are the sink's half of the attribution Ask does: how many
// deliveries there had been before an input was sent, and how many it caused.
func (s *sink) mark() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.got
}

func (s *sink) since(n int) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.got - n
}

func (s *sink) close() {
	close(s.done)
	_ = s.ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = s.http.Shutdown(ctx)
}

// handoff is a net.Listener over a channel, so the one http.Server sees only
// the connections the sink decided were HTTP.
//
// Accept has to return once the sink is closing, and not only when a connection
// arrives: http.Server.Shutdown waits for Serve to return before it does, with
// no regard for its context, so an Accept that blocks for ever hangs the whole
// program at the end of a run.
type handoff struct {
	c    <-chan net.Conn
	done <-chan struct{}
}

func (h handoff) Accept() (net.Conn, error) {
	select {
	case c, ok := <-h.c:
		if !ok {
			return nil, net.ErrClosed
		}
		return c, nil
	case <-h.done:
		return nil, net.ErrClosed
	}
}

func (h handoff) Close() error   { return nil }
func (h handoff) Addr() net.Addr { return dummyAddr{} }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "tcp" }
func (dummyAddr) String() string  { return "127.0.0.1:0" }

// buffered is a connection whose first bytes have already been read.
type buffered struct {
	net.Conn
	r *bufio.Reader
}

func (b *buffered) Read(p []byte) (int, error) { return b.r.Read(p) }

// throwawayCert writes a self-signed certificate for one listener.
func throwawayCert(dir, name string) (certPath, keyPath string, err error) {
	certPath = filepath.Join(dir, "sim-"+safeName(name)+".pem")
	keyPath = filepath.Join(dir, "sim-"+safeName(name)+"-key.pem")
	if _, err := os.Stat(certPath); err == nil {
		return certPath, keyPath, nil
	}
	certPEM, keyPEM, err := selfSigned()
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

// safeName keeps a listener name to what a file name may hold.
func safeName(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
			out = append(out, c)
		default:
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "listener"
	}
	return string(out)
}
