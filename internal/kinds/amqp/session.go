package amqp

import (
	"net"
	"net/netip"
	"sync"
	"time"

	wire "github.com/rom/xproxy/internal/amqpwire"
)

// One connection, and the state a policy on this protocol needs it to have.
//
// More than on any other relay kind here, because AMQP is the one where what
// an operation names is not in the frame that performs it.
//
// On 0-9-1 the state is modest: the version, the identity the SASL exchange
// carried, the virtual host the connection opened, and whether the broker has
// accepted a credential. The last of those is taken from the *broker's* side
// -- a 0-9-1 broker that refuses a password closes the connection instead of
// sending connection.tune, so the arrival of tune is the answer -- for the
// same reason the redis kind waits for the reply to an AUTH: a relay that
// took the attempt for the outcome would treat a wrong password as a login.
//
// On 1.0 there is a table, and it is the whole reason that version needs
// more code than the other. An attach names the address; every transfer
// after it carries a link handle and nothing else. So the handle a link was
// attached with is remembered, and a transfer is attributed to the address
// its handle was attached to -- which is what makes a message on this
// version attributable at all, in the log and in the message bound.
type session struct {
	t      *server
	ip     netip.Addr
	client net.Conn
	up     net.Conn

	cliReader *wire.Reader
	upReader  *wire.Reader

	cmu sync.Mutex
	umu sync.Mutex

	mu      sync.Mutex
	version wire.Version
	secure  bool
	authed  bool
	user    string
	mech    string
	vhost   string
	// channels is the 0-9-1 channels, or the 1.0 sessions, that are open.
	channels map[uint16]bool
	// links is what each 1.0 link handle was attached to, per channel,
	// because a handle is only unique within its session.
	links map[linkKey]*link
	// inflight is the message being assembled on a channel: the declared
	// size on 0-9-1, and the running total of a run of transfers on 1.0.
	inflight map[uint16]*message

	methods, denied int
}

// linkKey is a handle within a session, which is the only scope a 1.0 handle
// is unique in.
type linkKey struct {
	channel uint16
	handle  uint64
}

// link is what a handle was attached to.
type link struct {
	name    string
	role    string
	address string
	at      time.Time
}

// message is one message in flight on a channel.
type message struct {
	// declared is what a 0-9-1 content header said the body would be, and
	// carried is what has arrived. The two are kept apart because a body
	// that runs past what its header declared is a protocol violation and
	// not simply a large message.
	declared, carried uint64
	// address is the link address a 1.0 transfer run belongs to, for the
	// log line: a handle is not something an operator can act on.
	address string
	at      time.Time
}

func newSession(t *server, c net.Conn, ip netip.Addr) *session {
	return &session{t: t, ip: ip, client: c,
		channels: map[uint16]bool{}, links: map[linkKey]*link{},
		inflight: map[uint16]*message{}}
}

func (se *session) writeClient(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	se.cmu.Lock()
	defer se.cmu.Unlock()
	_, err := se.client.Write(b)
	return err
}

func (se *session) writeUp(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	se.umu.Lock()
	defer se.umu.Unlock()
	_, err := se.up.Write(b)
	return err
}

// sess builds the policy's view of this connection.
func (se *session) sess() *Session {
	se.mu.Lock()
	defer se.mu.Unlock()
	return &Session{IP: se.ip, Version: se.version, User: se.user, Vhost: se.vhost,
		Secure: se.secure, Authed: se.authed, At: time.Now()}
}

func (se *session) setVersion(v wire.Version) {
	se.mu.Lock()
	se.version = v
	se.mu.Unlock()
}

func (se *session) setSecure() {
	se.mu.Lock()
	se.secure = true
	se.mu.Unlock()
}

// expectAuth records the identity and mechanism an attempt carried. It is not
// an authentication: the broker's answer is.
func (se *session) expectAuth(mech, user string) {
	se.mu.Lock()
	se.mech = mech
	if user != "" {
		se.user = user
	}
	se.mu.Unlock()
}

// authOK is called when the broker's own answer says the credential was
// accepted.
func (se *session) authOK() {
	se.mu.Lock()
	se.authed = true
	se.mu.Unlock()
}

func (se *session) setVhost(v string) {
	se.mu.Lock()
	se.vhost = v
	se.mu.Unlock()
}

func (se *session) identity() (user, mech, vhost string) {
	se.mu.Lock()
	defer se.mu.Unlock()
	return se.user, se.mech, se.vhost
}

// openChannel records a channel and says whether it was within the bound.
func (se *session) openChannel(ch uint16, max int) bool {
	se.mu.Lock()
	defer se.mu.Unlock()
	if se.channels[ch] {
		return true
	}
	if len(se.channels) >= max {
		return false
	}
	se.channels[ch] = true
	return true
}

func (se *session) closeChannel(ch uint16) {
	se.mu.Lock()
	delete(se.channels, ch)
	delete(se.inflight, ch)
	for k := range se.links {
		if k.channel == ch {
			delete(se.links, k)
		}
	}
	se.mu.Unlock()
}

// attach records a link, and says whether it was within the bound.
func (se *session) attach(ch uint16, handle uint64, l *link, max int) bool {
	se.mu.Lock()
	defer se.mu.Unlock()
	k := linkKey{channel: ch, handle: handle}
	if _, dup := se.links[k]; dup {
		// A handle attached twice without a detach. The broker will refuse
		// it; the relay keeps the first, because the alternative is
		// letting a second attach quietly replace the address the
		// transfers already in flight are being judged against.
		return true
	}
	n := 0
	for k := range se.links {
		if k.channel == ch {
			n++
		}
	}
	if n >= max {
		return false
	}
	se.links[k] = l
	return true
}

func (se *session) detach(ch uint16, handle uint64) {
	se.mu.Lock()
	delete(se.links, linkKey{channel: ch, handle: handle})
	se.mu.Unlock()
}

// linkFor is what a handle was attached to, if this relay saw the attach.
func (se *session) linkFor(ch uint16, handle uint64) (*link, bool) {
	se.mu.Lock()
	defer se.mu.Unlock()
	l, ok := se.links[linkKey{channel: ch, handle: handle}]
	return l, ok
}

// declare records what a 0-9-1 content header said a message would be.
func (se *session) declare(ch uint16, size uint64) {
	se.mu.Lock()
	se.inflight[ch] = &message{declared: size, at: time.Now()}
	se.mu.Unlock()
}

// body adds octets to the message in flight and reports the total, and
// whether the body has run past what the header declared.
func (se *session) body(ch uint16, n int) (total uint64, over bool) {
	se.mu.Lock()
	defer se.mu.Unlock()
	m := se.inflight[ch]
	if m == nil {
		// A body frame with no content header before it. The broker will
		// refuse the channel; the relay reports it rather than counting
		// the octets against a message it never saw declared.
		return 0, true
	}
	m.carried += uint64(n) //nolint:gosec // n is a frame length, always positive
	if m.carried >= m.declared {
		total = m.carried
		over = m.carried > m.declared
		delete(se.inflight, ch)
		return total, over
	}
	return m.carried, false
}

// transfer adds octets to a 1.0 message and reports the running total. A
// message on that version is a run of transfers with `more` set, so the sum
// is the message and each frame on its own says nothing about its size.
func (se *session) transfer(ch uint16, address string, n int, more bool) uint64 {
	se.mu.Lock()
	defer se.mu.Unlock()
	m := se.inflight[ch]
	if m == nil {
		m = &message{address: address, at: time.Now()}
		se.inflight[ch] = m
	}
	m.carried += uint64(n) //nolint:gosec // n is a frame length, always positive
	total := m.carried
	if !more {
		delete(se.inflight, ch)
	}
	return total
}

// count records one method or performative and reports the total.
func (se *session) count() int {
	se.mu.Lock()
	defer se.mu.Unlock()
	se.methods++
	return se.methods
}

func (se *session) refusal() {
	se.mu.Lock()
	se.denied++
	se.mu.Unlock()
}
