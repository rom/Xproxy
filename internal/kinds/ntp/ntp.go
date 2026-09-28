// Package ntp serves a kind: ntp listener: an NTP and NTS security
// gateway that reads every packet and decides about it.
//
// Three jobs live on this port and only one of them is "forward a
// packet", so the package keeps them apart on purpose:
//
//   - forwarding time packets between clients and servers, which is a
//     relay with a policy;
//   - authenticating them, which is a key and a digest and belongs to
//     whoever holds the key -- symmetric keys this relay can check, and
//     NTS it deliberately cannot;
//   - keeping an accurate clock, which is the local time daemon's job and
//     not this relay's. A relay that tried to be a time source would be a
//     time source nobody calibrated.
//
// What a relay can do that a client cannot is compare. It sees several
// servers, it measures each one the same way, and it can refuse to pass
// on an answer from a server whose time disagrees with its peers or whose
// own dispersion says not to trust it. That is the point of putting one
// in front of a plant: the devices behind it will step their clocks to
// whatever they are told, and this is the last place anything reads what
// they are told.
//
// Two rules run through the data path. Packets are forwarded as the bytes
// that arrived -- never re-encoded -- because an NTS-protected packet
// re-encoded is a packet the client will reject, and an authenticated one
// re-encoded is worse. And every timeout, expiry and rate limit is
// measured on the monotonic clock: this is a relay for the protocol that
// changes the wall clock, so wall-clock arithmetic here would be a
// timeout that fires when the time is set.
package ntp

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/acceptgroup"
	"github.com/rom/xproxy/internal/admit"
	"github.com/rom/xproxy/internal/authorization"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/limits"
	wire "github.com/rom/xproxy/internal/ntp"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/safe"
	"github.com/rom/xproxy/internal/upstream"
)

// server is one kind: ntp listener.
type server struct {
	host    proxy.Host
	cfg     config.Listener
	n       *config.NTPListener
	pc      net.PacketConn
	policy  *Policy
	learner *Learner
	tracer  *Tracer
	monitor *Monitor
	// watch holds what each server looked like last time, so a source
	// that changed is a change rather than a new normal.
	watch *watcher
	// term is NTS termination, or nil when this listener passes NTS
	// through or refuses it. With it, the relay holds the client's keys
	// and "authenticated" means this relay checked.
	term *terminator
	// origin is the relay's own NTS association with the time source, or
	// nil when it asks the source in plain NTP.
	origin *originator

	// clients and prefixes are the two rate limits: one per address, one
	// per network, because a client behind a NAT and a subnet asking in
	// unison are different problems.
	clients  *limits.KeyedLimiter
	prefixes *limits.KeyedLimiter

	// start is the monotonic base every expiry in this listener is
	// measured from.
	start time.Time

	mu       sync.Mutex
	assoc    map[netip.AddrPort]*association
	pending  map[pendKey]*pending
	interlv  map[wire.Timestamp]*association
	backends []*backend
	rr       atomic.Uint64

	// running is what a shutdown waits for: the sweep, the monitor, the
	// reader per server and each opaque exchange. It is acceptgroup rather
	// than a bare WaitGroup because the engine can call Shutdown before
	// serve has run its first Add -- and a WaitGroup's Add must not race
	// its Wait. The race detector found this one through test/shutdown.
	running acceptgroup.Group
	done    chan struct{}
	once    sync.Once
}

// backend is one time server: its endpoint, and the one socket this
// listener uses towards it.
//
// The socket is connected, so the kernel drops anything from another
// address: an answer forged by a third party never reaches the table, let
// alone a client.
type backend struct {
	index int
	pool  *upstream.Pool
	ep    *upstream.Endpoint
	addr  netip.AddrPort
	conn  *net.UDPConn
	// health is what the monitor decided about this server's time.
	health atomic.Pointer[Health]
}

// association is one client's relationship with one backend.
//
// The backend selection is per association and it persists: a client that
// asked a different server every poll would see a different offset every
// poll, and the jitter it measured would be the relay's doing. This is why
// nothing here is round robin per packet.
type association struct {
	client  netip.AddrPort
	backend *backend
	// last is nanoseconds since the listener's monotonic base.
	last atomic.Int64
	// lastServerTransmit is what an interleaved answer echoes instead of
	// the client's own transmit timestamp.
	lastServerTransmit atomic.Uint64
	// requests and answers are this association's own totals, which the
	// per-packet log line carries: "this client's fortieth poll" is what
	// tells a routine poll from a device that has started asking every
	// second.
	requests, answers  atomic.Uint64
	nts, authenticated atomic.Bool
	version            atomic.Uint32
}

// pendKey identifies one outstanding request: the backend it went to and
// the transmit timestamp the client chose, which is the only thing in NTP
// that ties an answer to a question.
//
// The outstanding table is deliberately not the association table. A
// client may have several requests in flight, an answer may arrive after
// the association has moved to another backend, and a backend may answer
// something nobody asked. Keeping them apart is what makes each of those
// a counter rather than a confusion.
type pendKey struct {
	backend int
	origin  wire.Timestamp
}

type pending struct {
	client netip.AddrPort
	// sent is the monotonic nanoseconds when the relay forwarded it, and
	// sentAt the wall clock at the same moment: the first measures the
	// round trip, the second is what the server's timestamps are read
	// against.
	sent   int64
	sentAt wire.Timestamp
	nts    bool
	auth   bool
	assoc  *association
	// term is the verified NTS session, when this listener terminated the
	// client's NTS. The answer is built and authenticated with its keys, so
	// it has to live as long as the request does.
	term *session
	// source is the relay's own NTS session toward the time source, when it
	// holds one. The answer is verified against it.
	source *sourceSession
}

func newServer(host proxy.Host, cfg config.Listener, pc net.PacketConn) (*server, error) {
	n := cfg.NTP
	keys, err := loadKeys(n)
	if err != nil {
		return nil, err
	}
	pol, err := compile(n, keys)
	if err != nil {
		return nil, err
	}
	s := &server{host: host, cfg: cfg, n: n, pc: pc, policy: pol,
		start: time.Now(), assoc: map[netip.AddrPort]*association{},
		pending: map[pendKey]*pending{}, interlv: map[wire.Timestamp]*association{},
		done: make(chan struct{})}
	if n.RateLimit > 0 {
		burst := n.RateBurst
		if burst <= 0 {
			burst = n.RateLimit
		}
		s.clients = limits.NewKeyedLimiter(float64(n.RateLimit), burst, s.maxAssociations())
	}
	if n.PrefixRateLimit > 0 {
		burst := n.PrefixRateBurst
		if burst <= 0 {
			burst = n.PrefixRateLimit
		}
		s.prefixes = limits.NewKeyedLimiter(float64(n.PrefixRateLimit), burst, 65536)
	}
	if l := n.Learn; l != nil && l.Enabled {
		s.learner = NewLearner(cfg.Name, l.File, l.Interval.D(), l.MaxSubjects)
	}
	if tr := n.Trace; tr != nil {
		t, err := NewTracer(cfg.Name, tr.File, tr.MaxBytes, tr.Requests, tr.Responses)
		if err != nil {
			return nil, err
		}
		s.tracer = t
	}
	s.monitor = NewMonitor(s)
	s.watch = newWatcher(s)
	if nts := n.NTS; nts != nil && nts.Mode == "terminate" {
		s.term = newTerminator(host, nts.KeyListener)
		if nts.Source != nil {
			o, err := compileOriginator(host, cfg.Name, nts.Source, host.Secrets())
			if err != nil {
				return nil, err
			}
			s.origin = o
		}
	}
	return s, nil
}

// loadKeys reads the symmetric keys a listener names.
func loadKeys(n *config.NTPListener) (wire.Keys, error) {
	if n.Auth == nil || len(n.Auth.Keys) == 0 {
		return nil, nil
	}
	keys := wire.Keys{}
	for i := range n.Auth.Keys {
		k := &n.Auth.Keys[i]
		secret, err := loadKey(k)
		if err != nil {
			return nil, err
		}
		alg := k.Algorithm
		if alg == "" {
			alg = wire.AlgAESCMAC
		}
		keys[uint32(k.ID)] = wire.Key{ID: uint32(k.ID), Algorithm: alg, Secret: secret} //nolint:gosec // validated 1..65535
	}
	return keys, nil
}

// loadKey reads a key's secret: hexadecimal, or the ASCII a ntp.keys
// file carries, and nothing else. A key nobody can read is better than a
// key read wrongly -- half a key silently becomes an authentication
// nobody notices is failing.
func loadKey(k *config.NTPKey) ([]byte, error) {
	b, err := os.ReadFile(k.KeyFile) //nolint:gosec // the path is the operator's own configuration
	if err != nil {
		return nil, fmt.Errorf("ntp key %d: %w", k.ID, err)
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return nil, fmt.Errorf("ntp key %d: %s is empty", k.ID, k.KeyFile)
	}
	if len(s)%2 == 0 {
		if raw, err := hex.DecodeString(s); err == nil {
			return raw, nil
		}
	}
	return []byte(s), nil
}

func (s *server) maxAssociations() int {
	if s.n.MaxAssociations > 0 {
		return s.n.MaxAssociations
	}
	return 16384
}

func (s *server) maxOutstanding() int {
	if s.n.MaxOutstanding > 0 {
		return s.n.MaxOutstanding
	}
	return 4096
}

func (s *server) requestTimeout() time.Duration {
	if d := s.n.RequestTimeout.D(); d > 0 {
		return d
	}
	return 3 * time.Second
}

// nanos is now on the monotonic clock, as nanoseconds since this
// listener started. Every expiry in the package is this number, never a
// wall-clock one: the protocol being relayed is the one that moves the
// wall clock.
func (s *server) nanos() int64 { return int64(time.Since(s.start)) }

func (s *server) serve() {
	if s.origin != nil {
		// Established now rather than on the first request: a request that
		// waited for a TLS handshake would be a client waiting seconds for the
		// time.
		go s.origin.keep(s.done)
	}
	if s.learner != nil {
		s.learner.Start(func(err error) {
			s.host.Logs().Error.Warn("ntp learning report could not be written",
				"listener", s.cfg.Name, "error", err.Error())
		})
	}
	if !s.running.Enter() {
		// Shut down before it started, which a reload can do.
		return
	}
	defer s.running.Leave()
	for _, run := range []func(){s.sweep, s.monitor.run} {
		if !s.running.Enter() {
			break
		}
		go func() { defer s.running.Leave(); run() }()
	}
	buf := make([]byte, 65535)
	for {
		nb, addr, err := s.pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-s.done:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		ua, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}
		// The bytes are copied because the datagram is handled after the
		// buffer is reused, and because the copy is what gets forwarded:
		// the packet a server sees is the packet the client sent.
		pkt := make([]byte, nb)
		copy(pkt, buf[:nb])
		s.fromClient(ua.AddrPort(), pkt)
	}
}

// admitClient is the two questions this relay asks about a client that has no
// identity: do the imported lists know this address, and does the estate's
// authorisation policy allow it here.
//
// NTP names nobody. A client is an address, and even that is a datagram's claim
// about itself -- which is why this relay's own detection policy exists, and why
// the ban list is careful about what it attributes to an unverified source. So the
// policy decides on the address, the listener, the pool and the hour, and a rule
// naming users matches nobody on this kind. Which versions, modes and extension
// fields are carried, and what makes an answer implausible, stay with the `ntp`
// policy, which is the thing that can say what a stratum means.
//
// Asked once per datagram, like this listener's own client list, because a time
// server keeps no client state. A refusal goes through drop, so it is counted and
// a client that keeps sending earns a ban the same way one refused by the address
// list does.
func (s *server) admitClient(client netip.AddrPort) string {
	h := s.host
	ip := client.Addr().Unmap()
	return admit.Client(admit.Deps{
		Lists:   h.ThreatIntel(),
		Policy:  h.Authorization(),
		Logs:    h.Logs(),
		Matched: func() { h.Counters().ThreatIntelMatched.Add(1) },
		Blocked: func() { h.Counters().ThreatIntelBlocked.Add(1) },
	}, authorization.Subject{
		Listener: s.cfg.Name,
		Kind:     "ntp",
		Client:   ip,
		Target:   s.n.Upstream,
		Action:   authorization.ActionConnect,
	}, admit.Gate{
		Shadowing: func() bool { return !s.enforcing() },
		Record: func(reason, rule, detail string) {
			h.Counters().NTPWouldDeny.Add(1)
			h.Counters().WouldRefuse("ntp", reason)
			h.Shadow().Record("ntp", s.cfg.Name, reason, rule, detail)
		},
		Deny: func(reason, _, detail string) { s.drop(client, reason, detail) },
	})
}

// fromClient is the whole request path for one datagram.
func (s *server) fromClient(client netip.AddrPort, raw []byte) {
	defer safe.Guard("ntp request")
	c := s.host.Counters()
	c.NTPRequests.Add(1)
	if bl := s.host.Bans(); bl != nil && bl.Banned(client.Addr()) {
		c.NTPDropped.Add(1)
		c.Refuse("ntp", "banned")
		return
	}
	if !s.policy.ClientAllowed(client.Addr()) {
		if s.enforcing() {
			s.drop(client, "client_not_allowed", "")
			return
		}
		// A learning run exists to find out which clients there are, so
		// the list it is being written against cannot be the thing that
		// stops it seeing them.
		c.NTPWouldDeny.Add(1)
		c.WouldRefuse("ntp", "client_not_allowed")
		s.denyLog(client, "client_not_allowed", "recorded, not enforced")
		s.host.Shadow().Record("ntp", s.cfg.Name, "client_not_allowed", "", client.Addr().String())
	}
	// The imported lists and the estate's authorisation policy, after this
	// listener's own client list -- that is local policy about local clients, and
	// a feed must not overrule an allow rule an operator wrote.
	if s.admitClient(client) != "" {
		return
	}
	if !s.admitRate(client, raw) {
		return
	}
	k, err := wire.Classify(raw)
	if err != nil {
		s.drop(client, "malformed", err.Error())
		return
	}
	if d := s.policy.Dispatch(k); !d.Allow {
		s.refuse(client, d, raw, nil)
		return
	} else if d.Reason == "version5_passthrough" {
		// Version 5 is forwarded as opaque bytes on a socket of its own,
		// because this relay does not read version 5 and will not
		// correlate an answer by parsing one.
		c.NTPVersion5.Add(1)
		s.opaqueExchange(client, raw)
		return
	}
	pkt, err := wire.Parse(raw)
	if err != nil {
		// A packet the relay cannot read is a packet it cannot decide
		// about, and the device behind it would read those bytes
		// somehow.
		s.drop(client, "malformed", err.Error())
		return
	}
	req := request{client: client, kind: k, pkt: pkt, size: len(raw)}
	d := s.policy.Request(req)
	s.learner.Observe(req, d, time.Now())
	if !d.Allow {
		if s.enforcing() {
			s.refuse(client, d, raw, pkt)
			return
		}
		c.NTPWouldDeny.Add(1)
		c.WouldRefuse("ntp", d.Reason)
		s.audit(client, d, pkt, "would_deny")
		s.host.Shadow().Record("ntp", s.cfg.Name, d.Reason, "", d.Detail)
	}
	a, ok := s.association(client)
	if !ok {
		return
	}
	a.version.Store(uint32(pkt.Version))
	nts := pkt.NTS()
	if nts.Present {
		a.nts.Store(true)
		c.NTPNTSForwarded.Add(1)
	}
	if pkt.HasMAC {
		a.authenticated.Store(true)
	}
	s.tracer.Request(s.cfg.Name, client, pkt, d)
	var se *session
	out := pkt.Raw
	// sentNTS and sentAuth are what the request this relay sends carries, not
	// what the client's carried. The answer policy is written against them: an
	// answer with no NTS fields is a downgrade only if the request that asked
	// for it had them.
	sentNTS, sentAuth := nts.Present, pkt.HasMAC
	if s.term != nil && nts.Present {
		var reason string
		if se, reason = s.term.verify(pkt); reason != "" {
			// A packet whose authenticator does not verify is refused, not
			// forwarded with a note. That is the whole difference between
			// terminating and passing through: here the relay holds the keys,
			// so "it did not verify" is a fact rather than a guess.
			if s.enforcing() {
				s.refuse(client, deny(reason, "the NTS authenticator was not accepted"), raw, pkt)
				return
			}
			c.NTPWouldDeny.Add(1)
			c.WouldRefuse("ntp", reason)
			s.audit(client, deny(reason, ""), pkt, "would_deny")
			s.host.Shadow().Record("ntp", s.cfg.Name, reason, "", client.Addr().String())
		}
		if se != nil {
			// The request is re-originated: the extension fields were the
			// client's conversation with this relay, and the source is a time
			// server that does not have to speak NTS at all.
			out = requestForSource(pkt)
			sentNTS, sentAuth = false, false
		}
	}
	var us *sourceSession
	if s.origin != nil {
		// The relay's own association with the source. The header alone goes
		// into it: the fields this adds have to be the last thing in the packet,
		// and a client's own MAC or extension fields are not this relay's to
		// forward once it is authenticating the request itself.
		protected, sess, err := s.origin.protect(pkt.Raw)
		if err != nil {
			c.NTPDropped.Add(1)
			s.deny(client, ReasonSourceNotReady, err.Error())
			s.origin.ensure()
			return
		}
		out, us = protected, sess
		sentNTS, sentAuth = true, false
	}
	s.forward(a, req, out, se, us, sentNTS, sentAuth)
}

// admitRate applies the two rate limits. A client asking too often is
// answered with a kiss-o'-death when the listener says so, because that
// is what the protocol has for "slow down" and a client that gets it
// backs off; a drop teaches it nothing.
func (s *server) admitRate(client netip.AddrPort, raw []byte) bool {
	c := s.host.Counters()
	over := s.clients != nil && !s.clients.Allow(client.Addr().String())
	if !over && s.prefixes != nil {
		if p := s.prefixOf(client.Addr()); p.IsValid() && !s.prefixes.Allow(p.String()) {
			over = true
		}
	}
	if !over {
		return true
	}
	c.NTPRateLimited.Add(1)
	c.Refuse("ntp", "rate_limit")
	if k := s.n.KoD; k == nil || k.OnRateLimit == nil || *k.OnRateLimit {
		// A client that is asking too often is told to slow down in the
		// protocol's own words, because a drop teaches it nothing and it
		// asks again.
		s.kiss(client, raw, "RATE")
	}
	return false
}

// prefixOf is the network a rate limit counts by, which is how a subnet
// of clients asking in unison is one limit rather than many.
func (s *server) prefixOf(a netip.Addr) netip.Prefix {
	bits := s.n.RatePrefixLength
	if bits == 0 {
		if a.Is4() {
			bits = 24
		} else {
			bits = 56
		}
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return netip.Prefix{}
	}
	return p
}

// kiss answers with a stratum-0 packet carrying a four-character code:
// the protocol's own way of saying "not now". It is built here rather
// than forwarded, and it is the only packet this listener originates
// towards a client.
func (s *server) kiss(client netip.AddrPort, raw []byte, code string) {
	k, err := wire.Classify(raw)
	if err != nil || len(raw) < wire.HeaderLen {
		return
	}
	var origin wire.Timestamp
	if p, err := wire.Parse(raw); err == nil {
		origin = p.Transmit
	}
	now := wire.TimestampOf(time.Now())
	out := &wire.Packet{
		Leap: wire.LeapUnsynchronised, Version: k.Version, Mode: wire.ModeServer,
		Stratum: 0, Poll: 6, Precision: -20,
		Origin: origin, Receive: now, Transmit: now,
	}
	copy(out.ReferenceID[:], code)
	if _, err := s.pc.WriteTo(out.Bytes(), net.UDPAddrFromAddrPort(client)); err == nil {
		s.host.Counters().NTPKissSent.Add(1)
	}
}

// association finds or creates the client's association and its backend.
func (s *server) association(client netip.AddrPort) (*association, bool) {
	c := s.host.Counters()
	s.mu.Lock()
	a := s.assoc[client]
	if a == nil {
		if len(s.assoc) >= s.maxAssociations() {
			s.mu.Unlock()
			c.NTPDropped.Add(1)
			s.drop(client, "max_associations", "")
			return nil, false
		}
		a = &association{client: client}
		s.assoc[client] = a
		c.NTPAssociations.Add(1)
		c.NTPAssociationsOpen.Add(1)
	}
	s.mu.Unlock()
	a.last.Store(s.nanos())
	a.requests.Add(1)
	if a.backend == nil || !a.backend.usable() {
		b := s.pickBackend()
		if b == nil {
			c.NTPUpstreamUnavailable.Add(1)
			s.drop(client, "no_server", "")
			return nil, false
		}
		s.mu.Lock()
		a.backend = b
		s.mu.Unlock()
	}
	return a, true
}

// pickBackend chooses a server for a new association. The choice is made
// once and kept, and a server the monitor has marked unusable is not
// chosen -- with hysteresis, so a single slow answer does not move every
// client in the plant.
//
// It deliberately does not hash the client: a plant whose clients all sit
// in one subnet would land on one server, and the spread is what makes the
// comparison between servers worth having.
func (s *server) pickBackend() *backend {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.backends) == 0 {
		if err := s.openBackends(); err != nil {
			s.host.Logs().Error.Warn("ntp has no reachable server",
				"listener", s.cfg.Name, "error", err.Error())
			return nil
		}
	}
	usable := make([]*backend, 0, len(s.backends))
	for _, b := range s.backends {
		if b.usable() {
			usable = append(usable, b)
		}
	}
	if len(usable) == 0 {
		// Every server is suspect. Whether that means "stop" or "carry
		// on" is a decision the configuration makes, because a relay
		// that failed closed here would take the plant's clocks with it.
		if s.n.Quality != nil && s.n.Quality.OnAllSuspect == "refuse" {
			return nil
		}
		usable = s.backends
	}
	// The association is spread over the usable servers by a counter
	// rather than by the client's address, so a plant whose clients all
	// sit in one subnet does not land on one server.
	i := s.rr.Add(1) % uint64(len(usable))
	return usable[i]
}

// openBackends resolves the pool once and opens one connected socket per
// endpoint. It runs under the lock.
func (s *server) openBackends() error {
	pool := s.host.Pool(s.n.Upstream)
	if pool == nil {
		return fmt.Errorf("upstream %q has no pool", s.n.Upstream)
	}
	tried := map[*upstream.Endpoint]bool{}
	for i := 0; i < 16; i++ {
		e, _ := pool.Pick("ntp", "", tried, upstream.CanaryAny)
		if e == nil {
			break
		}
		tried[e] = true
		ap, err := resolveUDP(e.Address)
		if err != nil {
			s.host.Logs().Error.Warn("ntp server address could not be resolved",
				"listener", s.cfg.Name, "endpoint", e.Address, "error", err.Error())
			continue
		}
		if !s.policy.ServerAllowed(ap.Addr()) {
			// The egress list is what stops a pool whose name resolves
			// somewhere new from quietly becoming a new destination.
			s.host.Counters().Refuse("ntp", "server_not_allowed")
			s.host.Logs().SecurityEvent(context.Background(), "deny", "ntp_denied",
				"listener", s.cfg.Name, "proto", "ntp", "detail", "server_not_allowed",
				"server", ap.String())
			continue
		}
		conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(ap))
		if err != nil {
			pool.End(e, true, 0)
			continue
		}
		b := &backend{index: len(s.backends), pool: pool, ep: e, addr: ap, conn: conn}
		b.health.Store(&Health{State: StateUnknown})
		s.backends = append(s.backends, b)
		pool.Begin(e)
		if s.running.Enter() {
			go func() { defer s.running.Leave(); s.fromServer(b) }()
		}
	}
	if len(s.backends) == 0 {
		return errors.New("no usable server endpoint")
	}
	return nil
}

func resolveUDP(addr string) (netip.AddrPort, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return netip.AddrPort{}, err
	}
	ap, ok := netip.AddrFromSlice(ua.IP)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("ntp: %q has no address", addr)
	}
	return netip.AddrPortFrom(ap.Unmap(), uint16(ua.Port)), nil //nolint:gosec // a port
}

// usable says whether a backend may be chosen for a new association.
func (b *backend) usable() bool {
	if b == nil || b.conn == nil {
		return false
	}
	h := b.health.Load()
	return h == nil || h.State != StateSuspect && h.State != StateUnreachable
}

// forward sends the client's packet to its server, as the bytes that
// arrived, and remembers the exchange.
// forward sends one request to the association's server.
//
// out is what goes on the wire, which is the packet as it arrived except when
// this listener terminated NTS and re-originated it. se is the verified NTS
// session, kept with the outstanding request because the answer has to be
// authenticated with the same keys.
func (s *server) forward(a *association, r request, out []byte, se *session, us *sourceSession, nts, auth bool) {
	c := s.host.Counters()
	b := a.backend
	key := pendKey{backend: b.index, origin: r.pkt.Transmit}
	now := s.nanos()
	s.mu.Lock()
	if len(s.pending) >= s.maxOutstanding() {
		s.mu.Unlock()
		c.NTPDropped.Add(1)
		s.drop(r.client, "outstanding_full", "")
		return
	}
	// nts and auth are what the request this relay sent carried, decided by the
	// caller: a terminated request goes to the source as plain NTP unless this
	// relay has an association of its own, and an answer without NTS fields is
	// a downgrade only when the request that asked for it had them.
	s.pending[key] = &pending{client: r.client, sent: now, sentAt: wire.TimestampOf(time.Now()),
		nts: nts, auth: auth, assoc: a, term: se, source: us}
	s.mu.Unlock()
	if _, err := b.conn.Write(out); err != nil {
		s.mu.Lock()
		delete(s.pending, key)
		s.mu.Unlock()
		c.NTPUpstreamFailed.Add(1)
		s.host.Logs().Error.Warn("ntp could not send to the server",
			"listener", s.cfg.Name, "server", b.addr.String(), "error", err.Error())
		return
	}
	c.NTPForwarded.Add(1)
}

// fromServer reads one backend's socket.
func (s *server) fromServer(b *backend) {
	defer safe.Guard("ntp server reader")
	buf := make([]byte, 65535)
	for {
		select {
		case <-s.done:
			return
		default:
		}
		_ = b.conn.SetReadDeadline(time.Now().Add(time.Second))
		nb, err := b.conn.Read(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		raw := make([]byte, nb)
		copy(raw, buf[:nb])
		s.answer(b, raw)
	}
}

// answer is the whole response path for one datagram from a server.
func (s *server) answer(b *backend, raw []byte) {
	c := s.host.Counters()
	c.NTPResponses.Add(1)
	pkt, err := wire.Parse(raw)
	if err != nil {
		// An answer the relay cannot read is an answer it will not pass
		// on: the client would read those bytes differently, which is
		// the whole class of bug this relay exists to prevent.
		c.NTPMalformed.Add(1)
		s.deny(b.addr, "malformed_response", err.Error())
		return
	}
	now := s.nanos()
	key := pendKey{backend: b.index, origin: pkt.Origin}
	s.mu.Lock()
	p := s.pending[key]
	if p != nil {
		delete(s.pending, key)
	}
	var a *association
	if p == nil && s.policy.Interleaved() {
		// Interleaved mode: the answer echoes the server's own previous
		// transmit timestamp rather than the client's, so the
		// association is found by that instead. It is a separate table
		// because it is a separate relationship, and an answer that
		// matches neither is unsolicited.
		a = s.interlv[pkt.Origin]
	}
	s.mu.Unlock()
	if p == nil && a == nil {
		c.NTPUnsolicited.Add(1)
		s.deny(b.addr, "unsolicited", "no outstanding request with that origin timestamp")
		return
	}
	var resp response
	if p != nil {
		a = p.assoc
		t4 := wire.TimestampOf(time.Now())
		resp = response{server: b.addr, pkt: pkt,
			offset:   wire.Offset(p.sentAt, pkt, t4),
			delay:    time.Duration(now - p.sent),
			ntsAsked: p.nts, authAsked: p.auth, now: time.Now()}
	} else {
		// ntsAsked is about the request this relay sent, not the one the client
		// sent: when this listener terminates NTS the upstream request is plain
		// NTP, so an answer without NTS fields is what was asked for. The
		// answer is still refused below -- there is no verified session to
		// authenticate it to the client with -- and that is a clearer reason
		// than "the answer was stripped of NTS", which is not what happened.
		resp = response{server: b.addr, pkt: pkt, ntsAsked: a.nts.Load() && s.term == nil,
			authAsked: a.authenticated.Load(), interleaved: true, now: time.Now()}
		c.NTPInterleaved.Add(1)
	}
	if p != nil && p.source != nil {
		// The source's answer, under the keys this relay established with it. An
		// answer that does not verify is not an answer: it is refused before the
		// policy looks at the time in it, because the time in it is not the
		// source's until this succeeds.
		if err := s.origin.verify(pkt, p.source); err != nil {
			c.NTPNTSSourceUnverified.Add(1)
			c.NTPDenied.Add(1)
			c.Refuse("ntp", ReasonSourceUnverified)
			s.audit(a.client, deny(ReasonSourceUnverified, err.Error()), pkt, "deny")
			return
		}
	}
	s.monitor.Observe(b, resp)
	// What this server looked like last time, against what it looks like
	// now. It is checked before the per-packet policy because a source
	// that changed is worth saying even when the answer it sent is
	// otherwise acceptable -- which is the whole point of the check.
	changes := s.watch.Check(b.addr.String(), pkt, resp.offset)
	s.watch.Report(b.addr.String(), changes)
	d := s.policy.Response(resp)
	if d.Allow && len(changes) > 0 && s.watch.Refusing() {
		d = deny("source_changed", changes[0].Detail)
	}
	if d.Reason == "leap_unexpected" {
		c.NTPLeapUnexpected.Add(1)
		s.host.Logs().SecurityEvent(context.Background(), "alert", "ntp_leap_unexpected",
			"listener", s.cfg.Name, "proto", "ntp", "server", b.addr.String(),
			"client", a.client.String(), "detail", d.Detail)
	}
	if !d.Allow {
		if s.enforcing() {
			c.NTPDenied.Add(1)
			c.Refuse("ntp", d.Reason)
			s.audit(a.client, d, pkt, "deny")
			return
		}
		c.NTPWouldDeny.Add(1)
		c.WouldRefuse("ntp", d.Reason)
		s.audit(a.client, d, pkt, "would_deny")
		s.host.Shadow().Record("ntp", s.cfg.Name, d.Reason, "", d.Detail)
	}
	s.tracer.Response(s.cfg.Name, a.client, b.addr, pkt, d)
	out := raw
	if s.origin != nil && !a.nts.Load() {
		// A plain client behind a relay that authenticates its own requests: the
		// source's NTS fields are the relay's conversation with the source, and
		// forwarding them would hand a client extension fields it did not ask
		// for -- including this relay's own replacement cookies.
		out = raw[:wire.HeaderLen]
	}
	if s.term != nil && a.nts.Load() {
		switch {
		case p == nil || p.term == nil:
			// An interleaved answer is matched by the server's own previous
			// transmit timestamp rather than by the client's request, so there
			// is no session to authenticate it with. A plain answer to a client
			// that established keys would be the downgrade this mode exists to
			// prevent, so it is refused instead.
			c.NTPDenied.Add(1)
			c.Refuse("ntp", ReasonNoSession)
			s.audit(a.client, deny(ReasonNoSession, "no verified session for this answer"), pkt, "deny")
			return
		default:
			b2, err := s.term.answer(p.term, pkt)
			if err != nil {
				c.NTPSendFailed.Add(1)
				s.host.Logs().Error.Warn("ntp could not authenticate the answer to the client",
					"listener", s.cfg.Name, "client", a.client.String(), "error", err.Error())
				return
			}
			out = b2
		}
	}
	if _, err := s.pc.WriteTo(out, net.UDPAddrFromAddrPort(a.client)); err != nil {
		c.NTPSendFailed.Add(1)
		return
	}
	a.answers.Add(1)
	a.last.Store(now)
	if !pkt.Transmit.IsZero() {
		// Remember the server's transmit timestamp so an interleaved
		// answer to the next request can be matched.
		old := wire.Timestamp(a.lastServerTransmit.Swap(uint64(pkt.Transmit)))
		s.mu.Lock()
		if old != 0 {
			delete(s.interlv, old)
		}
		if len(s.interlv) < s.maxAssociations() {
			s.interlv[pkt.Transmit] = a
		}
		s.mu.Unlock()
	}
	c.NTPAnswered.Add(1)
	if s.n.LogPackets {
		s.logPacket(a, pkt, d, resp)
	}
}

// opaqueExchange forwards a packet this relay does not parse and waits
// for one answer on a socket of its own.
//
// It exists for version 5, which is experimental and whose layout is not
// version 4's. Correlating its answer would mean reading fields whose
// meaning is not settled, so the correlation is the socket: one
// transaction, one socket, one answer, closed either way.
func (s *server) opaqueExchange(client netip.AddrPort, raw []byte) {
	b := s.pickBackend()
	if b == nil {
		s.drop(client, "no_server", "")
		return
	}
	if !s.running.Enter() {
		return
	}
	go func() {
		defer s.running.Leave()
		defer safe.Guard("ntp opaque exchange")
		conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(b.addr))
		if err != nil {
			s.host.Counters().NTPUpstreamFailed.Add(1)
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(s.requestTimeout()))
		if _, err := conn.Write(raw); err != nil {
			s.host.Counters().NTPUpstreamFailed.Add(1)
			return
		}
		buf := make([]byte, 1500)
		nb, err := conn.Read(buf)
		if err != nil {
			return
		}
		_, _ = s.pc.WriteTo(buf[:nb], net.UDPAddrFromAddrPort(client))
		s.host.Counters().NTPAnswered.Add(1)
	}()
}

// probe sends the relay's own client-mode request to one server and
// returns the answer. The monitor uses it: a fresh transaction, with a
// transmit timestamp nobody else is using, so what comes back is an
// answer to this relay's own question rather than a copy of a client's.
func (s *server) probe(b *backend) (*wire.Packet, time.Duration, time.Duration, error) {
	conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(b.addr))
	if err != nil {
		return nil, 0, 0, err
	}
	defer func() { _ = conn.Close() }()
	out := &wire.Packet{Version: 4, Mode: wire.ModeClient, Poll: 6, Precision: -20}
	// The transmit timestamp is the correlation, so it is random in its
	// low bits rather than merely the clock: two probes a millisecond
	// apart must not collide, and an off-path guess must not match.
	ts := wire.TimestampOf(time.Now())
	out.Transmit = ts&^0xFFFFFFFF | wire.Timestamp(rand.Uint32()) //nolint:gosec // correlation, not a secret
	raw := out.Bytes()
	if s.n.Auth != nil && s.n.Auth.ProbeKeyID > 0 {
		if k, ok := s.policy.keys[uint32(s.n.Auth.ProbeKeyID)]; ok { //nolint:gosec // validated
			if signed, err := k.Sign(raw); err == nil {
				raw = signed
			}
		}
	}
	started := time.Now()
	_ = conn.SetDeadline(started.Add(s.requestTimeout()))
	if _, err := conn.Write(raw); err != nil {
		return nil, 0, 0, err
	}
	buf := make([]byte, 1500)
	nb, err := conn.Read(buf)
	if err != nil {
		return nil, 0, 0, err
	}
	rtt := time.Since(started)
	pkt, err := wire.Parse(buf[:nb])
	if err != nil {
		return nil, 0, 0, err
	}
	if !pkt.AnswersRequest(out.Transmit) {
		return nil, 0, 0, fmt.Errorf("ntp: the answer does not carry this probe's transmit timestamp")
	}
	t4 := wire.TimestampOf(time.Now())
	return pkt, wire.Offset(out.Transmit, pkt, t4), rtt, nil
}

// enforcing says whether the policy decides or only records. A learning
// run is observe-only unless it says otherwise.
func (s *server) enforcing() bool {
	if s.cfg.Shadowing() {
		return false
	}
	l := s.n.Learn
	if l == nil || !l.Enabled {
		return true
	}
	return l.Enforce
}

// sweep expires associations and outstanding requests on the monotonic
// clock.
func (s *server) sweep() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
		}
		idle := s.n.IdleTimeout.D()
		if idle <= 0 {
			idle = 30 * time.Minute
		}
		now := s.nanos()
		timeout := int64(s.requestTimeout())
		s.mu.Lock()
		for k, p := range s.pending {
			if now-p.sent > timeout {
				delete(s.pending, k)
				s.host.Counters().NTPTimedOut.Add(1)
			}
		}
		for addr, a := range s.assoc {
			if now-a.last.Load() > int64(idle) {
				delete(s.assoc, addr)
				if ts := wire.Timestamp(a.lastServerTransmit.Load()); ts != 0 {
					delete(s.interlv, ts)
				}
				s.host.Counters().NTPAssociationsOpen.Add(-1)
			}
		}
		s.mu.Unlock()
	}
}

func (s *server) shutdown(ctx context.Context) {
	s.once.Do(func() {
		close(s.done)
		_ = s.pc.Close()
		s.mu.Lock()
		for _, b := range s.backends {
			if b.conn != nil {
				_ = b.conn.Close()
			}
			if b.pool != nil && b.ep != nil {
				b.pool.End(b.ep, false, 0)
			}
		}
		s.mu.Unlock()
	})
	s.running.Close()
	s.running.Wait(ctx)
	if err := s.learner.Stop(); err != nil {
		s.host.Logs().Error.Warn("ntp learning report could not be written at shutdown",
			"listener", s.cfg.Name, "error", err.Error())
	}
	_ = s.tracer.Close()
}

// drop records a packet this relay will not forward.
//
// A datagram cannot be refused: there is no reply that means "no", and a
// reply to a forged source is an attack on whoever was named. So
// everything here is dropped and counted, with the reason in the security
// log -- the one exception being the kiss-o'-death, which is a reply the
// protocol defines and which goes only to a client that asked too often.
func (s *server) drop(client netip.AddrPort, reason, detail string) {
	s.host.Counters().NTPDropped.Add(1)
	s.deny(client, reason, detail)
}

func (s *server) deny(peer netip.AddrPort, reason, detail string) {
	s.host.Counters().Refuse("ntp", reason)
	s.denyLog(peer, reason, detail)
}

// denyLog is the log and the ban observation without the counter, for the
// paths that have already counted the refusal: a refusal counted twice is
// a refusal an operator cannot count.
func (s *server) denyLog(peer netip.AddrPort, reason, detail string) {
	if !s.n.Alerts() {
		return
	}
	attrs := []any{"listener", s.cfg.Name, "proto", "ntp",
		"client_ip", peer.Addr().String(), "detail", reason}
	if detail != "" {
		attrs = append(attrs, "reason_detail", detail)
	}
	s.host.Logs().SecurityEvent(context.Background(), "deny", "ntp_denied", attrs...)
	if bl := s.host.Bans(); bl != nil && peer.Addr().IsValid() {
		bl.Observe(peer.Addr(), "ntp_denied")
	}
}

// refuse is a policy refusal of a client's packet: counted, logged with
// what was in the packet, and answered with a kiss only where the
// listener says so.
func (s *server) refuse(client netip.AddrPort, d Decision, raw []byte, pkt *wire.Packet) {
	c := s.host.Counters()
	c.NTPDenied.Add(1)
	c.NTPDropped.Add(1)
	c.Refuse("ntp", d.Reason)
	if pkt != nil {
		s.audit(client, d, pkt, "deny")
	} else {
		s.denyLog(client, d.Reason, d.Detail)
	}
	if k := s.n.KoD; k != nil && k.OnDeny {
		s.kiss(client, raw, "DENY")
	}
}

// audit writes the security event for one decision, with what was in the
// packet: "a client was refused" is not an audit trail and "version 3
// from 10.0.0.9, mode client, stratum 2, reason version_not_allowed" is.
func (s *server) audit(client netip.AddrPort, d Decision, pkt *wire.Packet, kind string) {
	if !s.n.Alerts() {
		return
	}
	attrs := []any{"listener", s.cfg.Name, "proto", "ntp", "client_ip", client.Addr().String(),
		"version", pkt.Version, "mode", pkt.Mode.String(), "stratum", pkt.Stratum,
		"leap", pkt.Leap.String(), "detail", d.Reason}
	if d.Detail != "" {
		attrs = append(attrs, "reason_detail", d.Detail)
	}
	if n := pkt.NTS(); n.Present {
		attrs = append(attrs, "nts_fields", true)
	}
	if pkt.HasMAC {
		attrs = append(attrs, "key_id", pkt.KeyID)
	}
	s.host.Logs().SecurityEvent(context.Background(), kind, "ntp_denied", attrs...)
	if bl := s.host.Bans(); bl != nil && client.Addr().IsValid() && kind == "deny" {
		bl.Observe(client.Addr(), "ntp_denied")
	}
}

// logPacket writes the per-packet access line, which is what an estate
// asked to show "who asked us the time, and what did we tell them" needs.
func (s *server) logPacket(a *association, pkt *wire.Packet, d Decision, r response) {
	attrs := []any{"listener", s.cfg.Name, "client_ip", a.client.Addr().String(),
		"server", "", "version", pkt.Version, "mode", pkt.Mode.String(),
		"stratum", pkt.Stratum, "leap", pkt.Leap.String(), "refid", pkt.RefID(),
		"requests", a.requests.Load(), "answers", a.answers.Load(),
		"offset_ms", float64(r.offset.Microseconds()) / 1000,
		"delay_ms", float64(r.delay.Microseconds()) / 1000,
		"decision", decisionName(d)}
	if a.backend != nil {
		attrs[3] = a.backend.addr.String()
	}
	if a.nts.Load() {
		attrs = append(attrs, "nts_fields", true)
	}
	s.host.Logs().Access.Info("ntp", attrs...)
}

func decisionName(d Decision) string {
	if d.Allow {
		return "allow"
	}
	return "deny"
}
