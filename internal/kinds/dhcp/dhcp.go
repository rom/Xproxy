// Package dhcp serves a kind: dhcp listener: a DHCP relay agent that reads
// what it relays.
//
// DHCP is the one protocol where *answering* is the attack. A client broadcasts
// "who will configure me" and believes whatever answers first: its address, its
// **default route**, its **resolvers**, its **proxy** (option 252) and, on a
// machine that boots from the network, the **file it boots** (options 66 and
// 67). Nothing in the exchange authenticates anybody -- a transaction
// identifier and a hardware address, both visible to everyone on the segment --
// and the client has no address yet, so it cannot even be told apart by one.
//
// That shapes the whole kind, and it makes this the one relay here whose
// interesting half faces *upstream*. Five things are deliberate.
//
// **A reply from an address this listener does not admit as a server is
// dropped.** Every switch vendor sells this as DHCP snooping and implements it
// as a trusted port. A relay can do the same by address, and it can do the part
// a switch cannot: read what the answer *says*.
//
// **The options a server sends are a configuration, not data.** Option 121 and
// Microsoft's 249 are a routing table in a broadcast reply. Option 252 is a
// proxy. Options 66, 67 and 43 are what a machine boots. Each is an option some
// estate needs and a takeover in the others, so each is a decision -- and the
// default is to strip the dangerous ones and forward the rest, because a client
// that still gets its address and no longer gets a route it should not have is
// a client that works.
//
// **The addresses in a reply are checked against the estate's own.** An
// operator knows their gateways and their resolvers; a reply naming anything
// else is wrong whoever sent it, and that check catches a compromised *real*
// server as well as a rogue one.
//
// **A client does not get to say which segment it is on.** RFC 3046 §2.1 says a
// relay discards the agent information option from a client, because the option
// exists so that the relay -- not the client -- tells the server which circuit
// the request came from. So option 82 arriving from a client is stripped, and
// this relay adds its own.
//
// **The starvation bound is keyed on the hardware address.** Pool exhaustion is
// one host sending thousands of DISCOVERs with a made-up address in each; a
// rate limit keyed on the source address would see one sender doing nothing
// unusual. The table that does the keying is itself bounded, because otherwise
// the flood of new addresses would exhaust it instead.
//
// What this kind does not do is DHCPv6 (RFC 8415), which is a different packet
// format with a different relay mechanism, nor DHCPv4 over TLS: there is no such
// thing, and a listener that took a certificate would be promising it.
package dhcp

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/limits"
	"github.com/rom/xproxy/internal/proxy"
)

// server is one kind: dhcp listener.
type server struct {
	host proxy.Host
	cfg  config.Listener
	m    *config.DHCPListener
	pc   net.PacketConn

	policy *Policy
	// limiter bounds messages per hardware address rather than per source
	// address, which is the key starvation is measured in.
	limiter *limits.KeyedLimiter

	wg   sync.WaitGroup
	once sync.Once
	done chan struct{}

	// pend pairs a reply with the client that asked for it. On a protocol
	// with no session that pairing is the only thing that makes a reply
	// decidable at all.
	pend *pending
}

func newServer(host proxy.Host, cfg config.Listener, pc net.PacketConn) (*server, error) {
	m := cfg.DHCP
	s := &server{host: host, cfg: cfg, m: m, pc: pc, done: make(chan struct{})}
	var err error
	if s.policy, err = compile(m, time.Now); err != nil {
		return nil, err
	}
	if m.RateLimit > 0 {
		burst := m.RateBurst
		if burst <= 0 {
			burst = m.RateLimit
		}
		s.limiter = limits.NewKeyedLimiter(float64(m.RateLimit), burst, s.maxClients())
	}
	s.pend = newPending(s.maxPending(), s.requestTimeout())
	s.pend.onChange = func(n int) { host.Counters().DHCPPending.Store(int64(n)) }
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
	if n := s.m.MaxHops; n > 0 {
		return uint8(n) //nolint:gosec // validation bounds max_hops to 16
	}
	return 4
}

// enforcing says whether this listener refuses for policy or only records what
// it would have refused.
func (s *server) enforcing() bool { return !s.cfg.Shadowing() }

// alerts says whether a refusal writes a security event.
func (s *server) alerts() bool { return s.m.AlertOnDeny == nil || *s.m.AlertOnDeny }

// logLeases says whether an address handed out writes an access line.
func (s *server) logLeases() bool { return s.m.LogLeases == nil || *s.m.LogLeases }

// naking says whether a refused request is answered with a DHCPNAK. The default
// is to drop: a client that hears nothing retries, which is what it does anyway
// when no server answers, and a NAK is a way to stop a client dead.
func (s *server) naking() bool { return s.m.DenyResponse == "nak" }

func (s *server) serve() { s.serveMessages() }

func (s *server) shutdown(ctx context.Context) {
	s.once.Do(func() {
		close(s.done)
		if s.pc != nil {
			_ = s.pc.Close()
		}
	})
	finished := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(finished)
	}()
	select {
	case <-finished:
	case <-ctx.Done():
		<-finished
	}
}

// exchange is one request in flight towards a server, and who is waiting.
type exchange struct {
	// client is the address to answer, and hw the hardware address the
	// request carried. Both are kept: the address is where the reply goes and
	// the hardware address is what the reply has to be about, because an
	// answer whose chaddr is not the one that asked is not an answer to this
	// request.
	client netip.AddrPort
	hw     []byte
	xid    uint32
	// rule is the rule that allowed the request, carried so the reply's own
	// decision starts from the same rule rather than being matched again
	// against a message that has a different type.
	rule string
	// broadcast says the reply must go to the segment rather than to the
	// address the request came from, because the client has no address yet.
	broadcast bool
	// asked is the client's parameter list, for the log line: what a device
	// wanted is as interesting as what it was given.
	asked []byte
	at    time.Time
}

// key pairs a reply with its request. RFC 2131 §4.1 says a client keeps the
// transaction identifier for the whole exchange, so the identifier and the
// hardware address together are the pair -- and using both is what stops one
// client's reply from being delivered to another that happened to pick the same
// identifier.
type key struct {
	xid uint32
	hw  string
}

// pending is the table of requests outstanding towards servers.
//
// It is bounded and it expires, because the entries come off a broadcast
// segment: anything can send a DISCOVER and nothing has to wait for the answer.
// A full table refuses the new request rather than forgetting an old one,
// because forgetting is what would make a reply undeliverable to the client
// that actually asked.
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
	k := key{xid: e.xid, hw: string(e.hw)}
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

// take finds the request a reply answers.
//
// It does not remove the entry: a DHCP exchange is two round trips -- DISCOVER,
// OFFER, REQUEST, ACK -- and the REQUEST reuses the transaction identifier, so
// a table that forgot after the OFFER would have nothing to pair the ACK with.
// The entry expires on the timeout instead.
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
