// Package coap serves kind: coap -- a CoAP relay agent in front of a constrained
// network, reading every request and every answer.
//
// Six things about this listener are deliberate and worth reading before the code.
//
// **The request side carries the policy.** Unlike the DHCP relays, where the
// interesting half faces upstream because answering is the attack, a CoAP request
// says what is about to happen: a method, a path and a content format. The paths
// are the device's object model, so a positive policy is a sentence an estate can
// write about its own equipment -- which is why default_action is deny here and
// allow there.
//
// **A refusal is answered, not dropped.** A Confirmable request is retransmitted
// until something answers it, so a relay that dropped what it refused would turn
// one refused request into four or five, and leave the device's own logs showing a
// timeout where a refusal happened. The standard supplies the codes: 4.03 for a
// policy refusal, 4.02 for an option the relay cannot name, 5.02 for one it must
// not forward, 5.05 for proxying it will not do.
//
// **The amplification bound is never shadowed.** A four-octet GET can return a
// kilobyte, and /.well-known/core returns a list of everything on the device. A
// listener whose policy was being trialled would otherwise be a working amplifier
// with logging, so the size bounds and the response-to-request factor are
// enforced whatever the shadow switch says.
//
// **Proxy-Uri and Proxy-Scheme are refused by default**, and both, because they
// are two spellings of the same request. Carrying them makes the device an open
// forward proxy on a network that was segmented for a reason.
//
// **The token is the pairing.** A response is matched to its request by the token,
// not the message identifier -- a separate response arrives in a message of its
// own with an identifier of its own. So the pending table is keyed on the token
// and the client, and an answer whose token nobody sent is counted rather than
// delivered to whichever client is guessed.
//
// **In NoSec there is no identity at all.** Most of the field runs CoAP with no
// DTLS, so the source address is the whole of what a rule can name, and the
// validator says so rather than letting a deployment discover it.
package coap

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	wire "github.com/rom/xproxy/internal/coap"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/limits"
	"github.com/rom/xproxy/internal/proxy"
)

// server is one kind: coap listener.
type server struct {
	host   proxy.Host
	cfg    config.Listener
	m      *config.CoAPListener
	policy *Policy

	pc net.PacketConn
	// up is the socket this relay speaks to devices on. One socket for the
	// listener, because the token and the client are what pair an answer with
	// its request and a socket per exchange would be a file descriptor per
	// sensor reading.
	up net.PacketConn

	limiter *limits.KeyedLimiter
	pend    *pending
	obs     *observers

	// mid is this relay's own message identifier counter, for the messages it
	// originates: an answer to a Non-confirmable request it refused.
	midMu sync.Mutex
	mid   uint16

	done   chan struct{}
	closed sync.Once
	wg     sync.WaitGroup
}

func newServer(h proxy.Host, cfg config.Listener, pc net.PacketConn) (*server, error) {
	m := cfg.CoAP
	p, err := compile(m, time.Now)
	if err != nil {
		return nil, err
	}
	s := &server{host: h, cfg: cfg, m: m, policy: p, pc: pc, done: make(chan struct{})}
	if m.RateLimit > 0 {
		s.limiter = limits.NewKeyedLimiter(float64(m.RateLimit), burstOf(m), s.maxClients())
	}
	s.pend = newPending(s.maxPending(), s.requestTimeout())
	s.obs = newObservers(s.maxObservers())
	return s, nil
}

func burstOf(m *config.CoAPListener) int {
	if m.RateBurst > 0 {
		return m.RateBurst
	}
	return m.RateLimit
}

// The bounds, each with its default in one place.
func (s *server) maxPending() int   { return intOr(s.m.MaxPending, 256) }
func (s *server) maxClients() int   { return intOr(s.m.MaxClients, 8192) }
func (s *server) maxObservers() int { return intOr(s.m.MaxObservers, 256) }
func (s *server) maxMessage() int   { return intOr(s.m.MaxMessageBytes, 1152) }

func (s *server) requestTimeout() time.Duration {
	if d := s.m.RequestTimeout.D(); d > 0 {
		return d
	}
	return 10 * time.Second
}

func (s *server) enforcing() bool { return !s.cfg.Shadowing() }
func (s *server) alerts() bool    { return on(s.m.AlertOnDeny) }
func (s *server) answering() bool { return on(s.m.AnswerRefusals) }

// nextMID is the identifier for a message this relay originates.
func (s *server) nextMID() uint16 {
	s.midMu.Lock()
	defer s.midMu.Unlock()
	s.mid++
	return s.mid
}

// exchange is one request outstanding towards a device.
type exchange struct {
	// client is who asked, and device is who was asked. Both are kept: the
	// client is where the answer goes, and the device is half the key.
	client, device netip.AddrPort
	// token is the client's own. RFC 7252 pairs a response with its request by
	// the token, because a separate response arrives in a message of its own
	// with a different message identifier.
	token string
	// size is the request as it went out, for the amplification factor.
	size int
	rule string
	path string
	code wire.Code
	at   time.Time
	// observing says the request registered for notifications, so the pairing
	// outlives the first answer.
	observing bool
}

// key identifies an exchange: the device and the token.
//
// The device is in the key because it is known on both sides -- the request was
// sent to it and the answer came from it -- and because without it one device's
// answer could be delivered to a client that asked a different device.
//
// What this pairing cannot separate is two clients that chose the same token for
// concurrent requests to the same device. RFC 7252 s5.3.2 tells a client not to
// reuse a token that way, require_token closes the degenerate case of clients that
// send no token at all, and a relay that wanted certainty would have to rewrite
// the token on the way out -- which is what RFC 7252 s5.7.2 has a forward-proxy do,
// and which makes it a proxy that terminates the message layer rather than a relay
// that reads it. That is a different listener, and the reference says so rather
// than leaving an operator to find out.
type key struct {
	device netip.AddrPort
	token  string
}

func (e *exchange) key() key { return key{device: e.device, token: e.token} }

// pending pairs answers with the requests that asked for them.
type pending struct {
	mu    sync.Mutex
	max   int
	ttl   time.Duration
	table map[key]*exchange
}

func newPending(max int, ttl time.Duration) *pending {
	return &pending{max: max, ttl: ttl, table: map[key]*exchange{}}
}

func (p *pending) add(e *exchange, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	k := e.key()
	if _, dup := p.table[k]; !dup && len(p.table) >= p.max {
		return false
	}
	e.at = now
	p.table[k] = e
	return true
}

// take finds the exchange an answer belongs to. An observed registration is left
// in place, because a notification is another answer to the same request.
func (p *pending) take(k key, now time.Time) (*exchange, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.table[k]
	if !ok {
		return nil, false
	}
	if now.Sub(e.at) > p.ttl && !e.observing {
		delete(p.table, k)
		return nil, false
	}
	if !e.observing {
		delete(p.table, k)
	}
	return e, true
}

func (p *pending) drop(k key) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.table, k)
}

func (p *pending) len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.table)
}

// sweep drops the exchanges nobody answered. An observed registration is kept
// until the client deregisters or the notifications stop, which is the point of
// observing.
func (p *pending) sweep(now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, e := range p.table {
		if e.observing {
			continue
		}
		if now.Sub(e.at) > p.ttl {
			delete(p.table, k)
		}
	}
}

// observers bounds the registrations outstanding.
//
// It is a bound of its own rather than part of the pending table because a
// registration has no timeout: it lasts until the client deregisters or the
// device stops. Without a bound, "how many open-ended flows may exist" would be
// answered by whoever asked for the most.
type observers struct {
	mu  sync.Mutex
	max int
	set map[key]bool
}

func newObservers(max int) *observers {
	return &observers{max: max, set: map[key]bool{}}
}

func (o *observers) add(k key) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.set[k] {
		return true
	}
	if len(o.set) >= o.max {
		return false
	}
	o.set[k] = true
	return true
}

func (o *observers) remove(k key) {
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.set, k)
}

func (o *observers) len() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.set)
}

// shutdown closes both sockets and waits for the loops.
func (s *server) shutdown(ctx context.Context) {
	s.closed.Do(func() { close(s.done) })
	_ = s.pc.Close()
	if s.up != nil {
		_ = s.up.Close()
	}
	waited := make(chan struct{})
	go func() { s.wg.Wait(); close(waited) }()
	select {
	case <-waited:
	case <-ctx.Done():
	}
}
