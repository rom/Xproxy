package bacnet

import (
	"net"
	"net/netip"
	"sync"
	"time"
)

// Pairing an answer with its question, on a protocol that gives a relay
// very little to pair with.
//
// A confirmed request carries an invoke identifier, and the standard makes
// it unique only between one client and one device. This relay speaks to
// the devices from a socket of its own, so two clients that both use invoke
// identifier 1 towards the same controller would be indistinguishable on
// the way back -- and the answer to one client's write would be delivered
// to the other. So the relay allocates an invoke identifier of its own
// towards the device and translates it back on the answer, which is what a
// BACnet router does for the same reason.
//
// An unconfirmed request has nothing to pair with at all. A Who-Is is
// answered by an I-Am from every device that hears it, each one sent of its
// own accord, so those answers are matched to the client that broadcast
// recently and are bounded in number: that bound is this protocol's
// amplification control, and it is the reason the window exists rather than
// a convenience.

// exchange is one confirmed request this relay is waiting for an answer to.
type exchange struct {
	client netip.Addr
	// from is the client's own address and port, which is where the answer
	// goes: a client picks an ephemeral port for its requests as often as
	// it uses 47808.
	from net.Addr
	// device is the address the request was sent to. An answer from
	// anywhere else is not this exchange's answer, whatever invoke
	// identifier it carries.
	device string
	// clientID is the identifier the client used, which the answer has to
	// carry back, and mine is the one the relay used towards the device.
	clientID uint8
	mine     uint8
	service  string
	rule     string
	at       time.Time
	deadline time.Time
}

// broadcast is one client's outstanding broadcast, and what is left of its
// reply budget.
type broadcast struct {
	from     net.Addr
	client   netip.Addr
	left     int
	deadline time.Time
}

// clientKey identifies an exchange from the client's side: its own
// address and the invoke identifier it chose. It is how a segment
// acknowledgement travelling the other way is translated, since the client
// knows only the identifier it used.
type clientKey struct {
	client string
	id     uint8
}

type pending struct {
	mu sync.Mutex
	// byMine is the exchanges this relay is waiting on, keyed by the
	// invoke identifier it allocated, and byClient the same exchanges
	// keyed the way the client knows them.
	byMine   map[uint8]*exchange
	byClient map[clientKey]*exchange
	// next is where the search for a free identifier starts, so a busy
	// listener does not rescan from zero every time.
	next  uint8
	max   int
	bcast []*broadcast
	// maxBcast bounds the outstanding broadcasts, so a client cannot fill
	// this table by broadcasting.
	maxBcast int
	// ttl is how long an exchange is held. A segment renews it: a
	// segmented reply is one exchange that takes as many datagrams as the
	// window needs, and a deadline measured from the request would expire
	// in the middle of a long trend log download.
	ttl time.Duration
}

func newPending(max, maxBroadcasts int, ttl time.Duration) *pending {
	return &pending{byMine: make(map[uint8]*exchange), byClient: make(map[clientKey]*exchange),
		max: max, maxBcast: maxBroadcasts, ttl: ttl}
}

// add allocates an invoke identifier for an exchange and records it.
//
// The allocation can fail, and that failure is a refusal rather than a
// reuse. There are two hundred and fifty-six identifiers; a listener with
// all of them outstanding is a listener whose devices are not answering,
// and reusing one would deliver somebody else's answer to the client that
// happens to hold it now.
func (p *pending) add(e *exchange, now time.Time) (uint8, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expireLocked(now)
	if len(p.byMine) >= p.max || len(p.byMine) >= 256 {
		return 0, false
	}
	ck := clientKey{client: e.from.String(), id: e.clientID}
	if old, dup := p.byClient[ck]; dup {
		// The same client has an exchange outstanding under the same
		// identifier. That is a retransmission or a client that has
		// reused an identifier early; either way the old exchange is the
		// one that is over, and keeping both would leave an entry nothing
		// will ever take.
		delete(p.byMine, old.mine)
		delete(p.byClient, ck)
	}
	for i := 0; i < 256; i++ {
		id := p.next
		p.next++
		if _, taken := p.byMine[id]; taken {
			continue
		}
		e.mine, e.at, e.deadline = id, now, now.Add(p.ttl)
		p.byMine[id] = e
		p.byClient[ck] = e
		return id, true
	}
	return 0, false
}

// translate finds the identifier this relay used for an exchange the
// client knows by its own.
//
// It is what carries a segmented exchange in the other direction: a
// segment acknowledgement, and an abort or an error a client sends, all
// name the identifier the *client* chose, and the device is waiting for
// the one the relay chose. A relay that forwarded those unchanged would
// have every segmented reply stall after its first window.
func (p *pending) translate(from net.Addr, clientID uint8, now time.Time) (uint8, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.byClient[clientKey{client: from.String(), id: clientID}]
	if !ok || now.After(e.deadline) {
		return 0, false
	}
	// The exchange is alive and being worked on, so its deadline is
	// renewed for the same reason a segment renews it on the way back.
	e.deadline = now.Add(p.ttl)
	return e.mine, true
}

// take finds the exchange an answer belongs to, and removes it when the
// answer is the last one.
//
// A segmented reply arrives as several datagrams carrying the same invoke
// identifier, so the exchange is kept until the segment that says no more
// follows. The expired return separates "nobody asked this" from "somebody
// asked and stopped waiting", which are different events: the first is what
// an answer-spoofing attempt looks like on a datagram protocol.
func (p *pending) take(id uint8, device string, last bool, now time.Time) (e *exchange, expired bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	got, ok := p.byMine[id]
	if !ok {
		return nil, false
	}
	if got.device != device {
		// The right identifier from the wrong device. On a datagram
		// protocol that is the shape of an answer somebody else sent
		// first, and it is not this exchange's answer.
		return nil, false
	}
	if now.After(got.deadline) {
		p.forgetLocked(got)
		return got, true
	}
	if last {
		p.forgetLocked(got)
		return got, false
	}
	// A segment, with more to come. The exchange is one exchange however
	// many datagrams it takes, so the deadline is renewed rather than
	// measured from the request -- otherwise a long trend log download
	// expires in the middle and the rest of it reads as an answer nobody
	// asked for.
	got.deadline = now.Add(p.ttl)
	return got, false
}

// drop releases an identifier for a request that never left.
func (p *pending) drop(id uint8) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e, ok := p.byMine[id]; ok {
		p.forgetLocked(e)
	}
}

// forgetLocked removes an exchange from both indexes. Removing it from one
// and not the other would leave an entry that translates a client's
// identifier to a device nobody is waiting on.
func (p *pending) forgetLocked(e *exchange) {
	delete(p.byMine, e.mine)
	delete(p.byClient, clientKey{client: e.from.String(), id: e.clientID})
}

// outstanding is how many exchanges are waiting, for the status view.
func (p *pending) outstanding() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.byMine)
}

// addBroadcast records a client's broadcast and its reply budget.
func (p *pending) addBroadcast(b *broadcast, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expireLocked(now)
	if len(p.bcast) >= p.maxBcast {
		return false
	}
	p.bcast = append(p.bcast, b)
	return true
}

// broadcastTargets returns the clients an unsolicited answer should reach,
// spending one of each one's replies.
//
// A client whose budget is exhausted is dropped from the table rather than
// left to be looked at again: the budget is the amplification bound, and a
// bound that is re-checked for every answer for the rest of the window is a
// bound that costs work per amplified datagram.
func (p *pending) broadcastTargets(now time.Time) []net.Addr {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expireLocked(now)
	out := make([]net.Addr, 0, len(p.bcast))
	kept := p.bcast[:0]
	for _, b := range p.bcast {
		if b.left <= 0 {
			continue
		}
		out = append(out, b.from)
		b.left--
		if b.left > 0 {
			kept = append(kept, b)
		}
	}
	p.bcast = kept
	return out
}

// expireLocked drops what nobody is waiting for any more. It runs on every
// change rather than on a timer, because a table that is only swept by a
// goroutine is a table that grows while the goroutine is asleep.
func (p *pending) expireLocked(now time.Time) {
	for _, e := range p.byMine {
		if now.After(e.deadline) {
			p.forgetLocked(e)
		}
	}
	kept := p.bcast[:0]
	for _, b := range p.bcast {
		if now.Before(b.deadline) {
			kept = append(kept, b)
		}
	}
	p.bcast = kept
}
