package ldap

import (
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/authorization"
	"github.com/rom/xproxy/internal/capture"
	wire "github.com/rom/xproxy/internal/ldap"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/safe"
	"github.com/rom/xproxy/internal/sessions"
	"github.com/rom/xproxy/internal/textsafe"
	"github.com/rom/xproxy/internal/upstream"
)

// One session, and the state a policy on this protocol needs it to have.
//
// LDAP is asynchronous and multiplexed: a client may have several requests in
// flight on one connection and the responses come back carrying the message
// identifier of the request they answer. So a relay that wants to decide
// about an *answer* -- to count a search's entries, to remove an attribute
// from one, to cut a search that has returned enough -- has to remember what
// each outstanding identifier asked for. That table is this file's subject,
// and it is bounded, because its keys come off the network.
//
// The other piece of state is the identity. A connection starts unbound and
// becomes somebody when a bind succeeds, and "this client, bound as this
// service account, may search this subtree" is the most useful sentence a
// policy on this protocol can say. So the relay watches the bind *responses*
// as well as the requests: the directory decides whether the credential was
// right, and the relay records what it decided.

// session is one client connection.
type session struct {
	t      *server
	ip     netip.Addr
	client net.Conn
	up     net.Conn

	// tap records the session for a pcapng capture, and is nil -- usable, and
	// doing nothing -- whenever no rule wants this one, which is the usual case.
	tap *capture.Tap
	// secure says the connection to the client is protected.
	secure bool

	// cmu guards writing to the client and replacing the connection, which a
	// StartTLS upgrade does. Both directions write to the client -- the
	// directory's answers and the relay's own refusals -- and the upgrade
	// holds it for the whole handshake, because a write from the other
	// goroutine in the middle of one would put plaintext inside a TLS
	// record.
	cmu sync.Mutex

	mu sync.Mutex
	// bound is the identity the directory has accepted for this connection,
	// and pending the bind waiting for its answer.
	bound     wire.DN
	boundName string
	method    wire.Method
	// pendingBind is the name and method of a bind in flight, adopted as the
	// identity only when the directory answers success. A relay that
	// believed the request would let anyone claim to be anybody by binding
	// with the wrong password.
	pendingBind     wire.DN
	pendingBindName string
	pendingMethod   wire.Method
	// outstanding maps a message identifier to what it asked for.
	outstanding map[int]*exchange
	// binds and failures count what happened on this connection, for the
	// session line.
	binds, failures, requests, denied int
}

// writeClient writes to the client, serialised against the other direction
// and against a StartTLS upgrade.
func (se *session) writeClient(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	se.cmu.Lock()
	defer se.cmu.Unlock()
	_, err := se.client.Write(b)
	return err
}

// isSecure says whether the connection to the client is protected. It is read
// from both goroutines -- the directory's answers are logged with it -- and
// written by a StartTLS upgrade, so it goes through the lock.
func (se *session) isSecure() bool {
	se.mu.Lock()
	defer se.mu.Unlock()
	return se.secure
}

// clientConn is the connection as it is now, for the reader to be rebuilt
// against after an upgrade.
func (se *session) clientConn() net.Conn {
	se.cmu.Lock()
	defer se.cmu.Unlock()
	return se.client
}

// exchange is one request in flight towards the directory.
type exchange struct {
	op   wire.Op
	rule string
	// strip and allowOnly are the attribute policy for this search's
	// answers: strip removes what is named, allowOnly keeps only what is.
	strip     *attrSet
	allowOnly *attrSet
	// entries is how many this search may return, and seen how many it has.
	entries, seen int
	// cut says the bound was reached and the search has been completed with
	// sizeLimitExceeded, so the rest of its entries are dropped rather than
	// counted again.
	cut bool
	at  time.Time
}

func (t *server) handle(c net.Conn) {
	s := t.host
	start := time.Now()
	s.Counters().LDAPSessions.Add(1)
	s.Counters().LDAPSessionsOpen.Add(1)
	defer s.Counters().LDAPSessionsOpen.Add(-1)
	se := &session{t: t, client: c, ip: netutil.AddrOf(c.RemoteAddr().String()),
		outstanding: map[int]*exchange{}}
	// Opened before anything can refuse the session, because a refused session is
	// the one an operator most often wants and it never dials: after that point
	// there is nothing left to record. A nil tap wraps nothing and writes nothing.
	se.tap = t.host.Capture().Open("ldap", t.cfg.Name, "", c.RemoteAddr())
	defer se.tap.Close()
	se.client = se.tap.Client(c)
	var pool *upstream.Pool
	var ep *upstream.Endpoint
	defer func() {
		if se.up != nil {
			_ = se.up.Close()
		}
		if ep != nil && pool != nil {
			pool.End(ep, false, 0)
		}
		_ = c.Close()
	}()
	if !t.policy.Client(se.ip) {
		s.Counters().LDAPRejected.Add(1)
		s.Counters().Refuse("ldap", "client_not_allowed")
		t.deny(se, "client_not_allowed", "")
		t.logSession(se, start, "client_not_allowed")
		return
	}
	live := s.Sessions().Register(sessions.Info{
		Kind: "ldap", Listener: t.cfg.Name, Client: c.RemoteAddr().String(),
	}, func() { _ = c.Close() })
	defer live.Done()
	se.tap.Name(live.ID)
	// Implicit TLS: LDAPS, port 636, TLS from the first octet. The other
	// mode -- StartTLS -- is an extended operation and is handled in the
	// request loop, because the session has to read cleartext first.
	if t.m.TLSMode == "implicit" || (t.tlsCfg != nil && t.m.TLSMode == "") {
		tc := tls.Server(c, t.tlsCfg)
		_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
		if err := tc.HandshakeContext(context.Background()); err != nil {
			s.Counters().Refuse("ldap", "tls_handshake")
			t.deny(se, "tls_handshake", err.Error())
			t.logSession(se, start, "tls_handshake")
			return
		}
		_ = tc.SetDeadline(time.Time{})
		// The tap follows the protocol rather than the TLS records carrying it:
		// tls.Server reads the socket directly, so nothing recorded the
		// handshake, and from here the tap sees the plaintext inside it.
		se.client, se.secure = se.tap.Client(tc), true
	}
	var err error
	se.up, pool, ep, err = t.dialDirectory(se.ip.String())
	se.up = se.tap.Upstream(se.up)
	if err != nil {
		s.Counters().LDAPUpstreamFail.Add(1)
		t.logSession(se, start, "upstream_unavailable")
		return
	}
	if t.m.ProxyProtocol {
		if _, err := se.up.Write(netutil.ProxyV2Header(se.client.RemoteAddr(), se.client.LocalAddr())); err != nil {
			t.logSession(se, start, "proxy_header")
			return
		}
	}
	if ep != nil {
		if se.up, err = t.upgradeUpstream(se.up, ep.Address); err != nil {
			s.Counters().LDAPUpstreamFail.Add(1)
			s.Counters().Refuse("ldap", "upstream_tls")
			t.host.Logs().Error.Warn("ldap directory tls failed", "listener", t.cfg.Name,
				"endpoint", ep.Address, "error", err.Error())
			t.logSession(se, start, "upstream_tls")
			return
		}
		live.Annotate("", ep.Address, "")
	}
	reason := se.pump()
	se.closeOut()
	t.logSession(se, start, reason)
}

// pump relays the session in both directions, deciding about every message.
func (se *session) pump() string {
	var wg sync.WaitGroup
	reasons := make(chan string, 2)
	stop := func() {
		_ = se.client.Close()
		_ = se.up.Close()
	}
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer safe.Guard("ldap client reader")
		reasons <- se.fromClient()
		stop()
	}()
	go func() {
		defer wg.Done()
		defer safe.Guard("ldap directory reader")
		reasons <- se.fromDirectory()
		stop()
	}()
	wg.Wait()
	close(reasons)
	first := ""
	for r := range reasons {
		if r != "" && (first == "" || first == "closed") {
			first = r
		}
	}
	return first
}

// fromClient reads requests, decides about each, and forwards what is
// allowed.
func (se *session) fromClient() string {
	t := se.t
	s := t.host
	conn := se.clientConn()
	rd := wire.NewReader(conn, t.maxMessage())
	for {
		_ = conn.SetReadDeadline(time.Now().Add(t.idleTimeout()))
		raw, err := rd.Next()
		if err != nil {
			if reason := t.readError(err, se, "client"); reason != "" {
				return reason
			}
			return "closed"
		}
		s.Counters().LDAPRequests.Add(1)
		se.mu.Lock()
		se.requests++
		se.mu.Unlock()
		m, perr := wire.Parse(raw)
		if perr != nil {
			s.Counters().LDAPMalformed.Add(1)
			s.Counters().Refuse("ldap", "malformed")
			t.deny(se, "ldap_malformed", perr.Error())
			return "ldap_malformed"
		}
		if end, handled := se.check(m); end != "" {
			return end
		} else if handled {
			continue
		}
		if !m.Op.Request() {
			// A response arriving from the client is traffic going the wrong
			// way: this side asks and the directory answers.
			s.Counters().Refuse("ldap", "wrong_direction")
			t.deny(se, "ldap_wrong_direction", m.Op.String())
			return "ldap_wrong_direction"
		}
		if reason, handled := se.handleStartTLS(m); handled {
			if reason != "" {
				return reason
			}
			// The connection may have become a TLS one, and the reader is
			// bound to the connection it was made with: reading on through
			// the old one would read TLS records as LDAP messages.
			if now := se.clientConn(); now != conn {
				conn = now
				rd = wire.NewReader(conn, t.maxMessage())
			}
			continue
		}
		if end, ok := se.admit(m); !ok {
			if end != "" {
				return end
			}
			continue
		}
		if _, err := se.up.Write(raw); err != nil {
			return "closed"
		}
	}
}

// check is the part of a request that is never policy: the message
// identifier, the rate limits and the bounds. None of it is shadowed.
//
// It reports a reason to end the session with, or that it has dealt with the
// request itself and the loop should carry on. The two are different on
// purpose. A *request* rate limit refuses the one request and keeps the
// connection: LDAP clients hold pooled connections, and killing one on a rate
// spike makes the application reconnect and retry, which is more load rather
// than less. A *bind* rate limit ends the session, because that rate is a
// credential attack and leaving the connection open is leaving it somewhere to
// keep trying.
func (se *session) check(m *wire.Message) (end string, handled bool) {
	t := se.t
	s := t.host
	if m.ID == 0 {
		// Zero is reserved for the server's unsolicited notification. A
		// client sending it is either broken or trying to have the relay
		// pair an answer with a request nobody made.
		s.Counters().LDAPMalformed.Add(1)
		s.Counters().Refuse("ldap", "message_id_zero")
		t.deny(se, "ldap_message_id_zero", "")
		return "ldap_message_id_zero", false
	}
	if m.Op == wire.OpBindRequest && t.binds != nil && !t.binds.Allow(se.ip.String()) {
		s.Counters().LDAPRateLimited.Add(1)
		s.Counters().Refuse("ldap", "bind_rate_limited")
		t.deny(se, "ldap_bind_rate_limited", "")
		return "ldap_bind_rate_limited", false
	}
	if t.limiter != nil && !t.limiter.Allow(se.ip.String()) {
		s.Counters().LDAPRateLimited.Add(1)
		s.Counters().Refuse("ldap", "rate_limited")
		// The directory's own "busy", which is what this is: the relay has
		// as many requests from this address as it will carry per second.
		if out := wire.Answer(m.ID, m.Op, wire.ResultBusy, "too many requests"); out != nil {
			_ = se.writeClient(out)
		}
		return "", true
	}
	return "", false
}

// admit decides about one request and, when it is refused, answers it in the
// directory's own vocabulary. It reports whether the request may be
// forwarded.
func (se *session) admit(m *wire.Message) (string, bool) {
	t := se.t
	se.mu.Lock()
	req := request{client: se.ip, msg: m, bound: se.bound, boundName: se.boundName,
		method: se.method, secure: se.secure}
	se.mu.Unlock()
	// The estate's own authorisation policy, for a bind: it is the one request
	// that names an identity, and it is asked before the bind is forwarded so a
	// DN no rule covers never reaches the directory.
	if m.Bind != nil {
		if reason := se.admitByPolicy(m); reason != "" {
			return se.answer(m, Decision{Reason: reason}), false
		}
	}
	d := t.policy.Decide(req)
	se.count(m)
	if !d.Allow {
		se.refused(m, d)
		// A hard refusal holds whatever the policy mode says: see
		// Decision.Hard.
		if t.enforcing() || d.Hard {
			return se.answer(m, d), false
		}
	}
	// A bind's outcome is the directory's to decide; the relay records what
	// it was asked and adopts the identity only when the answer is success.
	if m.Bind != nil {
		se.mu.Lock()
		se.pendingBind, se.pendingBindName = m.Bind.DN, m.Bind.Name
		se.pendingMethod = m.Bind.Method
		se.binds++
		se.mu.Unlock()
	}
	if !se.remember(m, d) {
		return "", false
	}
	t.logRequest(se, m, d, "allow")
	return "", true
}

// admitByPolicy is the estate's authorisation policy, asked for a bind and
// nothing else: the reason to refuse, or empty to carry on.
//
// A bind is the only request that names an identity, so it is the only one the
// section can decide about. What an already-bound session may then read or write
// is the `ldap` policy's own business, which is the thing that can say what a
// search base or an attribute means -- and an anonymous session names nobody, so
// a rule about people cannot reach it either. `allow_anonymous` on this listener
// is where that decision belongs, and the protocol page says so, because an
// operator who believed the section covered anonymous reads would be wrong.
//
// The user is the DN the bind asserts, and the directory proves it afterwards --
// this relay deliberately waits for the directory's answer before adopting an
// identity, which is settle(). So the policy narrows what the directory would
// have allowed and never widens it: a deny rule is exact, an allow rule is a
// filter on a claim the directory still has to verify.
//
// The target is the upstream pool's name; the directory is chosen by balancer
// after this point.
func (se *session) admitByPolicy(m *wire.Message) string {
	t := se.t
	name := m.Bind.Name
	return t.host.Authorization().Ask(authorization.Subject{
		Listener: t.cfg.Name,
		Kind:     "ldap",
		Client:   se.ip,
		User:     name,
		Target:   t.m.Upstream,
		Action:   authorization.ActionConnect,
	}, textsafe.Clip64(name), authorization.Gate{
		Shadowing: func() bool { return !t.enforcing() },
		Record: func(reason, rule, detail string) {
			se.wouldRefuse(m, Decision{Reason: reason, Rule: rule, Detail: detail})
		},
		Deny: func(reason, rule, detail string) {
			se.enforcedRefusal(m, Decision{Reason: reason, Rule: rule, Detail: detail})
		},
	})
}

// remember records what an outstanding request asked for, so the answers can
// be decided about, and reports whether there was room.
//
// A full table refuses the request rather than forgetting an older one,
// because forgetting would mean forwarding a search whose entries then arrive
// with no attribute policy and no count against them -- which is worse than
// refusing, and invisible. The refusal is the directory's own `busy`, because
// that is what it is: the relay has as many answers in flight as it can
// decide about.
func (se *session) remember(m *wire.Message, d Decision) bool {
	if _, ok := wire.ResponseOp(m.Op); !ok {
		return true
	}
	e := &exchange{op: m.Op, rule: d.Rule, strip: d.Strip, allowOnly: d.allowOnly,
		entries: d.Entries, at: time.Now()}
	se.mu.Lock()
	if len(se.outstanding) >= se.t.maxOutstanding() {
		// A request the directory never answered holds a slot until the
		// request timeout, so the table is swept before it is called full.
		se.expireLocked(time.Now())
	}
	if len(se.outstanding) >= se.t.maxOutstanding() {
		se.mu.Unlock()
		se.t.host.Counters().Refuse("ldap", "too_many_outstanding")
		se.t.deny(se, "ldap_too_many_outstanding", "")
		if out := wire.Answer(m.ID, m.Op, wire.ResultBusy,
			"too many operations outstanding"); out != nil {
			_ = se.writeClient(out)
		}
		return false
	}
	se.outstanding[m.ID] = e
	se.mu.Unlock()
	se.t.host.Counters().LDAPOutstanding.Add(1)
	return true
}

// expireLocked drops requests the directory never answered within the
// request timeout, and takes them off the estate's outstanding count.
func (se *session) expireLocked(now time.Time) {
	ttl := se.t.requestTimeout()
	dropped := 0
	for id, e := range se.outstanding {
		if now.Sub(e.at) > ttl {
			delete(se.outstanding, id)
			dropped++
		}
	}
	if dropped > 0 {
		se.t.host.Counters().LDAPOutstanding.Add(int64(-dropped))
	}
}

// closeOut releases every slot this session still holds, so the estate's
// outstanding count is about requests in flight rather than about sessions
// that have ended.
func (se *session) closeOut() {
	se.mu.Lock()
	n := len(se.outstanding)
	se.outstanding = map[int]*exchange{}
	se.mu.Unlock()
	if n > 0 {
		se.t.host.Counters().LDAPOutstanding.Add(int64(-n))
	}
}

// count records what the request was: the three numbers that say whether
// somebody is trying passwords, reading the directory, or changing it.
func (se *session) count(m *wire.Message) {
	c := se.t.host.Counters()
	switch {
	case m.Op == wire.OpBindRequest:
		c.LDAPBinds.Add(1)
	case m.Op == wire.OpSearchRequest:
		c.LDAPSearches.Add(1)
	case m.Op.Writes():
		c.LDAPWrites.Add(1)
	}
}

// answer sends the refusal for a request, in whatever the listener's
// deny_response says, and reports the reason to end the session with when it
// says to end it.
func (se *session) answer(m *wire.Message, d Decision) string {
	t := se.t
	switch t.m.DenyResponse {
	case "drop":
		return ""
	case "close":
		// The notice of disconnection first, so the client knows it was
		// refused rather than dropped.
		_ = se.writeClient(wire.NoticeOfDisconnection(wire.ResultUnwillingToPerform, "refused"))
		return d.Reason
	}
	code := wire.ResultInsufficientAccess
	if t.m.DenyResponse == "unwilling" {
		code = wire.ResultUnwillingToPerform
	}
	// A refused bind is answered invalidCredentials whatever the deny
	// response says. It is the only code a client will treat as "this login
	// did not work" rather than as a server fault -- and a relay that
	// answered insufficientAccessRights to a bind would have applications
	// retrying for ever.
	if m.Op == wire.OpBindRequest {
		code = wire.ResultInvalidCredentials
		se.t.host.Counters().LDAPBindFailures.Add(1)
		se.mu.Lock()
		se.failures++
		se.mu.Unlock()
	}
	oid := ""
	if m.Extended != nil {
		oid = m.Extended.OID
	}
	if out := wire.AnswerFor(m.ID, m.Op, oid, code, "refused by policy"); out != nil {
		_ = se.writeClient(out)
	}
	return ""
}
