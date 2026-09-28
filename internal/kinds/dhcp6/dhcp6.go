// Package dhcp6 serves a kind: dhcp6 listener: a DHCPv6 relay agent that reads
// what it relays.
//
// It is a separate kind from dhcp because DHCPv6 is a separate protocol, and the
// DHCPv4 kind's own documentation says so and gives the reasons. The threat is
// the same shape -- a machine asks what its network is and believes whatever
// answers -- so the interesting half of this kind faces upstream too. What
// differs is what an answer can carry, and there is more of it.
//
// Six things are deliberate.
//
// **A reply from an address this listener does not admit as a server is
// dropped.** The same check as the DHCPv4 kind's, and the same reasoning: every
// switch vendor sells it as DHCP snooping and implements it as a trusted port. A
// relay can do it by address and can also do the part a switch cannot, which is
// read what the answer says.
//
// **The dangerous options are a longer list than DHCPv4's.** The resolvers and
// the search list are the obvious pair. Past them: the boot file URL is what a
// machine boots, the captive portal option is a URL a client will open, the
// bootstrap server option is a configuration a switch will fetch and apply, the
// S46 transition containers put a host's *IPv4* traffic through a border relay of
// the sender's choosing, and the Server Unicast option tells a client to stop
// talking to the relay and address the server directly -- which turns off every
// policy this listener has. The default is to strip them and forward the rest,
// because a client that still gets its address and no longer gets a resolver it
// should not have is a client that works.
//
// **Prefix delegation is bounded, and it has no DHCPv4 equivalent.** A reply
// delegating ::/0 has handed a host the whole of IPv6 to route; a request for a
// /48 where the estate delegates /56s is a client asking for two hundred and
// fifty-six times what it should have. Both ends are checked, and a prefix
// outside the estate's is a refusal rather than a strip: there is no useful half
// of a delegation to keep.
//
// **A client does not get to say which segment it is on.** The Interface-ID,
// Remote-ID and Subscriber-ID options are a relay agent's statement on the
// client's behalf, so one arriving from a client is stripped and this relay adds
// its own. It is the DHCPv6 shape of RFC 3046's option 82 rule.
//
// **The starvation bound is keyed on the DUID.** Pool exhaustion is one host
// sending thousands of SOLICITs with a made-up identifier in each; a rate limit
// keyed on the source address would see one sender doing nothing unusual. The
// table that does the keying is itself bounded, because otherwise the flood of
// new identifiers would exhaust it instead.
//
// **RECONFIGURE is refused by name.** It is a message to a client that answers
// nothing, RFC 8415 s18.3.11 requires it to be authenticated with a key nobody
// deploys, and a client that accepts one can be made to re-ask a server of the
// sender's choosing.
//
// What this kind does not do is DHCPv4, which is the other listener, nor DHCPv6
// over any transport security: there is none, and a listener that took a
// certificate would be promising it.
package dhcp6

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/acceptgroup"
	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/dhcp6"
	"github.com/rom/xproxy/internal/limits"
	"github.com/rom/xproxy/internal/proxy"
)

// server is one kind: dhcp6 listener.
type server struct {
	host proxy.Host
	cfg  config.Listener
	m    *config.DHCP6Listener
	pc   net.PacketConn

	policy *Policy
	// limiter bounds messages per DUID rather than per source address, which
	// is the key starvation is measured in on this protocol.
	limiter *limits.KeyedLimiter

	// link is the address this relay puts in a RELAY-FORW's link address
	// field, parsed once.
	link netip.Addr

	// running is what a shutdown waits for: the reader towards the servers and
	// the sweep of pending requests. It is acceptgroup rather than a bare
	// WaitGroup because the engine can call Shutdown before serve has run its
	// first Add, and a WaitGroup's Add must not race its Wait.
	running acceptgroup.Group
	once    sync.Once
	done    chan struct{}

	// pend pairs a reply with the client that asked. On a protocol with no
	// session that pairing is the only thing that makes a reply decidable.
	pend *pending
}

func newServer(host proxy.Host, cfg config.Listener, pc net.PacketConn) (*server, error) {
	m := cfg.DHCP6
	s := &server{host: host, cfg: cfg, m: m, pc: pc, done: make(chan struct{})}
	var err error
	if s.policy, err = compile(m, time.Now); err != nil {
		return nil, err
	}
	if m.LinkAddress != "" {
		if s.link, err = netip.ParseAddr(m.LinkAddress); err != nil {
			return nil, err
		}
		s.link = s.link.Unmap()
	}
	if m.RateLimit > 0 {
		burst := m.RateBurst
		if burst <= 0 {
			burst = m.RateLimit
		}
		s.limiter = limits.NewKeyedLimiter(float64(m.RateLimit), burst, s.maxClients())
	}
	s.pend = newPending(s.maxPending(), s.requestTimeout())
	s.pend.onChange = func(n int) { host.Counters().DHCP6Pending.Store(int64(n)) }
	return s, nil
}

// The bounds, each with the default it has when the file says nothing.

func (s *server) maxPending() int {
	if n := s.m.MaxPending; n > 0 {
		return n
	}
	return 256
}

func (s *server) maxClients() int {
	if n := s.m.MaxClients; n > 0 {
		return n
	}
	return 8192
}

func (s *server) requestTimeout() time.Duration {
	if d := s.m.RequestTimeout.D(); d > 0 {
		return d
	}
	return 10 * time.Second
}

func (s *server) maxMessage() int {
	if n := s.m.MaxMessageBytes; n > 0 {
		return n
	}
	return 1500
}

func (s *server) maxHops() uint8 {
	if n := s.m.MaxRelayHops; n > 0 {
		return uint8(n) //nolint:gosec // validation bounds it to 32
	}
	return 4
}

// enforcing says whether this listener refuses for policy or only records what
// it would have refused.
func (s *server) enforcing() bool { return !s.cfg.Shadowing() }

func (s *server) alerts() bool { return s.m.Alerts() }

func (s *server) logLeases() bool { return s.m.Leases() }

func (s *server) serve() { s.serveMessages() }

func (s *server) shutdown(ctx context.Context) {
	s.once.Do(func() {
		close(s.done)
		if s.pc != nil {
			_ = s.pc.Close()
		}
	})
	s.running.Close()
	s.running.Wait(ctx)
	// And then without the bound. There is no session here to be stuck on: the
	// sockets are closed above, so the reader and the sweep end on the error
	// that follows and the wait is short whatever the context says.
	s.running.Wait(context.Background())
}

// exchange is one request in flight towards a server, and who is waiting.
type exchange struct {
	// client is the address to answer, and duid the identifier the request
	// carried. Both are kept: the address is where the reply goes and the
	// identifier is what the reply has to be about, because an answer naming a
	// different client is not an answer to this request.
	client netip.AddrPort
	duid   string
	xid    uint32
	// rule is the rule that allowed the request, carried so the reply's own
	// decision starts from the same rule rather than being matched again
	// against a message of a different type.
	rule string
	// asked is the client's option request list, for the log line: what a
	// device wanted is as interesting as what it was given.
	asked []byte
	at    time.Time
}

// key pairs a reply with its request: the transaction identifier and the client
// identifier together.
//
// Both, for the reason RFC 8415 s16 makes necessary: the identifier is three
// octets a client picks, so two clients on one segment collide often enough to
// matter, and a table keyed on it alone would deliver one client's answer to the
// other.
type key struct {
	xid  uint32
	duid string
}

// pending is the table of requests outstanding towards servers.
//
// Bounded and expiring, because the entries come off a multicast segment:
// anything can send a SOLICIT and nothing has to wait for the answer. A full
// table refuses the new request rather than forgetting an old one, because
// forgetting is what would make a reply undeliverable to the client that asked.
type pending struct {
	mu       sync.Mutex
	byKey    map[key]*exchange
	max      int
	ttl      time.Duration
	onChange func(int)
}

func newPending(max int, ttl time.Duration) *pending {
	return &pending{byKey: map[key]*exchange{}, max: max, ttl: ttl}
}

func (p *pending) add(e *exchange, now time.Time) bool {
	p.mu.Lock()
	p.expire(now)
	k := key{xid: e.xid, duid: e.duid}
	if _, dup := p.byKey[k]; !dup && len(p.byKey) >= p.max {
		p.mu.Unlock()
		return false
	}
	e.at = now
	p.byKey[k] = e
	n := len(p.byKey)
	p.mu.Unlock()
	if p.onChange != nil {
		p.onChange(n)
	}
	return true
}

// take finds the request a reply answers, without removing it.
//
// Without removing, because a DHCPv6 exchange can be two round trips --
// SOLICIT, ADVERTISE, REQUEST, REPLY -- and RFC 8415 s18.2.1 has the client
// choose a fresh transaction identifier for the REQUEST. So the entry is not
// reused across the pair, but a server may legitimately answer twice (a second
// ADVERTISE from another server behind the same relay), and a table that forgot
// on the first would drop the second. It expires on the timeout instead.
func (p *pending) take(k key, now time.Time) (*exchange, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expire(now)
	e, ok := p.byKey[k]
	return e, ok
}

func (p *pending) drop(k key) {
	p.mu.Lock()
	delete(p.byKey, k)
	n := len(p.byKey)
	p.mu.Unlock()
	if p.onChange != nil {
		p.onChange(n)
	}
}

// expire removes the entries nobody answered. The caller holds the lock.
func (p *pending) expire(now time.Time) {
	for k, e := range p.byKey {
		if now.Sub(e.at) > p.ttl {
			delete(p.byKey, k)
		}
	}
}

// sweep expires the entries nobody answered and republishes the size.
//
// The size is a gauge an operator reads, and expiry that only happened when a
// new request arrived would leave it sitting at whatever the last busy moment
// said -- which on a quiet segment is exactly when somebody is looking.
func (p *pending) sweep(now time.Time) {
	p.mu.Lock()
	before := len(p.byKey)
	p.expire(now)
	n := len(p.byKey)
	p.mu.Unlock()
	if n != before && p.onChange != nil {
		p.onChange(n)
	}
}

func (p *pending) len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.byKey)
}

// duidOf is the key a message is rated and paired by.
//
// A message with no client identifier has none, and "" is then the key: RFC 8415
// s16 says a SOLICIT without one is discarded, and this relay refuses it before
// this is reached -- but an INFORMATION-REQUEST legitimately has no identifier,
// and those share one bucket rather than each getting the whole rate.
func duidOf(m *wire.Message) string {
	d, ok := m.ClientDUID()
	if !ok {
		return ""
	}
	return d.String()
}
