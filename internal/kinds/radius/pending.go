package radius

import (
	"net"
	"net/netip"
	"sync"
	"time"

	wire "github.com/rom/xproxy/internal/radius"
)

// Pairing an answer with its question, on a protocol that gives a relay
// eight bits to pair with.
//
// A RADIUS reply is matched to its request by the source address and the
// one-octet identifier, and nothing else. This relay speaks to the servers
// from a socket of its own, so two switches that both use identifier 7
// would be indistinguishable on the way back -- and one switch's
// Access-Accept would be delivered to the other.
//
// So when this listener holds a secret it allocates an identifier of its
// own towards the server and translates it back on the answer, which is
// what every RADIUS proxy does for the same reason. Translating the
// identifier changes the packet, which invalidates both of its
// authenticators, which is why it can only be done with the secret in hand:
// the forwarded packet has to be re-signed.
//
// Without a secret the relay cannot re-sign, so it cannot translate, so it
// forwards the client's own identifier -- and then two clients using the
// same one at the same time is a collision it has to refuse rather than
// resolve. That is the shape of the whole kind: with the secret it is a
// proxy, and without it it is a filter with a bound.

// exchange is one request this relay is waiting for an answer to.
type exchange struct {
	client netip.Addr
	// from is the client's own address and port, which is where the answer
	// goes.
	from net.Addr
	// server is the address the request went to. An answer from anywhere
	// else is not this exchange's answer, whatever identifier it carries.
	server string
	// clientID is the identifier the client used and mine the one the relay
	// used towards the server. They are equal on a listener with no secret.
	clientID, mine uint8
	// clientAuth is the request authenticator the client sent and mineAuth
	// the one this relay sent, which are the two values the two legs' digests
	// are computed over.
	clientAuth, mineAuth [wire.AuthenticatorBytes]byte
	code                 wire.Code
	user                 string
	rule                 string
	at, deadline         time.Time
}

type pending struct {
	mu sync.Mutex
	// byMine is the exchanges this relay is waiting on, keyed by the
	// identifier it allocated towards the server.
	byMine map[uint8]*exchange
	// next is where the search for a free identifier starts, so a busy
	// listener does not rescan from zero every time.
	next      uint8
	max       int
	ttl       time.Duration
	translate bool
}

func newPending(maxOutstanding int, ttl time.Duration, translate bool) *pending {
	return &pending{byMine: map[uint8]*exchange{}, max: maxOutstanding,
		ttl: ttl, translate: translate}
}

// add records an exchange and returns the identifier to use towards the
// server.
//
// It returns false when there is no slot: on a translating listener that
// means every identifier is outstanding, which means the servers are not
// answering; on a non-translating one it means this client's own identifier
// is already in use by somebody else. The two are different facts and the
// caller reports them as different reasons.
func (p *pending) add(e *exchange, now time.Time) (uint8, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expire(now)
	e.at, e.deadline = now, now.Add(p.ttl)
	if !p.translate {
		if _, taken := p.byMine[e.clientID]; taken {
			return 0, false
		}
		e.mine = e.clientID
		p.byMine[e.mine] = e
		return e.mine, true
	}
	if len(p.byMine) >= p.max {
		return 0, false
	}
	for i := 0; i < 256; i++ {
		id := p.next
		p.next++
		if _, taken := p.byMine[id]; taken {
			continue
		}
		e.mine = id
		p.byMine[id] = e
		return id, true
	}
	return 0, false
}

// take claims the exchange an answer belongs to, or reports that there is
// none.
//
// The server address has to match. An answer carrying the right identifier
// from the wrong host is the shape of answer spoofing on a datagram
// protocol, and it is the one check that does not need the secret.
func (p *pending) take(id uint8, from string, now time.Time) (e *exchange, expired bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e = p.byMine[id]
	if e == nil {
		return nil, false
	}
	if e.server != from {
		return nil, false
	}
	delete(p.byMine, id)
	return e, now.After(e.deadline)
}

// drop gives an identifier back, for a request that never left.
func (p *pending) drop(id uint8) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.byMine, id)
}

// outstanding is how many requests are waiting, for the log line that says
// why a client was refused.
func (p *pending) outstanding() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.byMine)
}

// expire drops the exchanges nobody answered. It runs on every add rather
// than on a timer: the table is 256 entries, the scan is cheaper than a
// goroutine, and an exchange that has expired must not hold its identifier
// against the next request.
func (p *pending) expire(now time.Time) {
	for id, e := range p.byMine {
		if now.After(e.deadline) {
			delete(p.byMine, id)
		}
	}
}
