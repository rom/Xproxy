package tacacs

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/capture"
	wire "github.com/rom/xproxy/internal/tacacs"
)

// One connection, and the sessions on it.
//
// TACACS+ is request and answer, one session at a time -- except that both
// ends may set TAC_PLUS_SINGLE_CONNECT_FLAG and multiplex, which every
// modern device does because the alternative is a TCP connection per
// command. So this relay keeps a table of live sessions keyed by the
// identifier in the header, and the two directions run as independent
// goroutines reading whole packets.
//
// The table is what makes the policy work at all. An authorization request
// carries the user name, so a command can be attributed on its own; an
// authentication CONTINUE carries nothing but the typed text and its
// lengths, so the only way to know whose password prompt it answers is to
// have remembered the START. That is what `sess` holds, and it is also why
// a session's state is never taken from the packet that is being decided:
// the user on a CONTINUE is the user the START named, not a name a later
// packet could claim.

// sess is one TACACS+ session.
type sess struct {
	id uint32
	// user, authenType, action and service are the session's own, from the
	// packet that started it.
	user       string
	port       string
	remAddr    string
	authenType wire.AuthenType
	action     wire.AuthenAction
	service    wire.AuthenService
	privLvl    uint8
	// rule is the rule that decided the session's first packet, so a
	// per-rule privilege bound applies to the server's answer.
	rule string
	// asked is the name the estate's authorization policy has already been
	// asked about on this session. It is a name rather than a flag because
	// `user` is set while a packet is parsed, so a flag derived from it
	// could not say whether the question had been put yet -- and because a
	// session whose later packets claim a different name has to be asked
	// again about that one.
	asked string
	// lastSeq is the sequence number last seen, so a packet that goes
	// backwards or repeats is refused rather than decided twice.
	lastSeq uint8
	at      time.Time

	// wmu guards wantUser, which is the one field here the two directions
	// both touch: the server's goroutine sets it when a reply asks for a
	// name, and the client's reads it when the next packet carries one.
	wmu sync.Mutex
	// wantUser says the server's last answer was GETUSER, so the user_msg of
	// the next CONTINUE is a user name -- the only circumstance in which this
	// relay reads that field. It follows the *last* answer rather than any
	// answer, so an exchange that moves on to GETPASS stops this relay reading
	// the typed text at all. See RFC 8907 §5.4.2: an ASCII login may name
	// nobody in its START and let the server prompt, which is the shape that
	// would otherwise walk past a user list.
	wantUser bool
}

// askedForUser records what the server's last answer asked for: a name, or
// something else.
//
// It assigns rather than only setting, and that is the point of taking the
// argument. A flag that was only ever turned on would stay on through the rest
// of the exchange: the server answers GETUSER, the client sends an empty
// answer, the server moves on to GETPASS, and the typed text of *that* packet
// -- the password -- would be read as a name, decided about as one and written
// to a log as one. The flag says what the question was, so each answer is read
// as an answer to the question actually asked.
func (s *sess) askedForUser(asked bool) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	s.wantUser = asked
}

// takeUserPrompt reports whether the next typed answer is a name, and clears
// the flag: one prompt is one answer, and a second CONTINUE on the same
// session is answering something else.
func (s *sess) takeUserPrompt() bool {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	was := s.wantUser
	s.wantUser = false
	return was
}

// conn is one TCP connection carrying one or more sessions.
type conn struct {
	t      *server
	ip     netip.Addr
	client net.Conn
	up     net.Conn

	// tap records the session for a pcapng capture, and is nil -- usable, and
	// doing nothing -- whenever no rule wants this one, which is the usual case.
	tap *capture.Tap

	cmu sync.Mutex
	umu sync.Mutex

	mu   sync.Mutex
	live map[uint32]*sess
	// started counts the sessions this connection has opened, which is what
	// max_sessions_per_connection bounds -- a count rather than the live
	// size, because a client that opens and abandons sessions in a loop
	// would otherwise never reach it.
	started int
}

func newConn(t *server, ip netip.Addr, client, up net.Conn, tap *capture.Tap) *conn {
	return &conn{t: t, ip: ip, client: client, up: up, tap: tap, live: map[uint32]*sess{}}
}

// session returns the session a header belongs to, creating it for a first
// packet, and reports why not where it refuses.
//
// A sequence number of 1 starts a session. Anything else must find one: a
// CONTINUE for a session this relay has not seen is either a client
// recovering from a restart or somebody guessing identifiers, and neither
// is a packet whose user name is known -- so it is refused rather than
// carried with an empty identity.
func (c *conn) session(h wire.Header) (*sess, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.live[h.SessionID]
	if h.Seq == 1 {
		if s != nil {
			// An identifier already in use. Starting a second session on it
			// would make the two indistinguishable, and the second one's
			// answers would be attributed to the first.
			return nil, "session_in_use"
		}
		if c.started >= c.t.maxPerConn() {
			return nil, "too_many_sessions"
		}
		c.started++
		s = &sess{id: h.SessionID, at: time.Now()}
		c.live[h.SessionID] = s
		return s, ""
	}
	if s == nil {
		return nil, "no_such_session"
	}
	if h.Seq <= s.lastSeq {
		// The sequence number is the protocol's own replay guard and it only
		// goes up. A packet that repeats or goes backwards is refused: a
		// relay that decided it twice would have the policy see one command
		// as two, and a relay that forwarded it would hand the server a
		// replay.
		return nil, "sequence_out_of_order"
	}
	return s, ""
}

// close drops a session, which happens when it ends and when it is refused.
func (c *conn) close(id uint32) {
	c.mu.Lock()
	delete(c.live, id)
	c.mu.Unlock()
}

// find returns a live session without creating one, for the reply leg.
func (c *conn) find(id uint32) *sess {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.live[id]
}

func (c *conn) writeClient(b []byte) error {
	c.cmu.Lock()
	defer c.cmu.Unlock()
	_, err := c.client.Write(b)
	return err
}

func (c *conn) writeUp(b []byte) error {
	c.umu.Lock()
	defer c.umu.Unlock()
	_, err := c.up.Write(b)
	return err
}

// readPacket reads one whole TACACS+ packet: the fixed header, then the body
// the header's length says is there.
//
// The length is checked against the listener's bound before the body is
// read, which is the only place that check is worth anything: the field is
// 32 bits wide, and a reader that allocated first would allocate four
// gigabytes for a twelve-octet packet.
func readPacket(r io.Reader, maxBody int) (wire.Header, []byte, error) {
	var hdr [wire.HeaderBytes]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return wire.Header{}, nil, err
	}
	h, err := wire.ParseHeader(hdr[:])
	if err != nil {
		return wire.Header{}, nil, err
	}
	if h.Length > maxBody {
		return h, nil, errBodyTooLarge
	}
	body := make([]byte, h.Length)
	if _, err := io.ReadFull(r, body); err != nil {
		return wire.Header{}, nil, err
	}
	return h, body, nil
}

// errBodyTooLarge is a header whose length is past the listener's bound. It
// is a value rather than a string so the caller's refusal reason is stable.
var errBodyTooLarge = errors.New("tacacs: body length past the listener's bound")

// writePacket writes a header and a body, with the length filled in from the
// body rather than from whatever the caller remembered.
func writePacket(h wire.Header, body []byte) []byte {
	h.Length = len(body)
	out := h.Marshal()
	return append(out, body...)
}
