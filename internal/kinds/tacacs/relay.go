package tacacs

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/rom/xproxy/internal/admit"
	"github.com/rom/xproxy/internal/authorization"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/safe"
	wire "github.com/rom/xproxy/internal/tacacs"
	"github.com/rom/xproxy/internal/upstream"
)

// The relay.
//
// Two goroutines per connection, one each way, because a single-connect
// connection interleaves sessions and a lock-step relay would stall the
// moment a device pipelined two of them. Each direction reads a whole
// packet, de-obfuscates a copy of its body, decides about it, and writes the
// packet on -- re-obfuscating it where the two legs have different keys.
//
// The copy matters. A relay forwards the octets it received, so the parse
// cannot happen in the buffer that is about to be written: de-obfuscating in
// place would send the server a body in plaintext under a header that says
// it is not.

// handle serves one connection.
func (t *server) handle(client net.Conn) {
	defer func() { _ = client.Close() }()
	ip := netutil.AddrOf(client.RemoteAddr().String())
	if !t.policy.Client(ip) {
		t.deny(ip, "client_not_allowed", "")
		return
	}
	if t.admitClient(ip) != "" {
		return
	}
	if t.limiter != nil && !t.limiter.Allow(ip.String()) {
		t.host.Counters().Refuse("tacacs", "rate_limited")
		return
	}
	if ok, reason := t.gate.Enter(ip); !ok {
		t.host.Counters().Refuse("tacacs", reason)
		return
	}
	defer t.gate.Leave(ip)
	if _, isTLS := client.(*tls.Conn); boolOr(t.c.RequireTLS, false) && !isTLS {
		t.deny(ip, "tls_required", "")
		return
	}
	up, err := t.dial(ip)
	if err != nil {
		t.host.Counters().Refuse("tacacs", "upstream_failed")
		t.host.Logs().Error.Warn("tacacs upstream dial failed", "listener", t.name,
			"client_ip", ip.String(), "error", err.Error())
		return
	}
	defer func() { _ = up.Close() }()
	c := newConn(t, ip, client, up)
	deadline := time.Now().Add(t.lifetime)
	done := make(chan struct{})
	go func() {
		defer safe.Guard("tacacs reply reader")
		defer close(done)
		t.fromServer(c, deadline)
	}()
	t.fromClient(c, deadline)
	// Closing the upstream ends the reply goroutine's read, which is what
	// makes the wait below finite: a server that never answers must not hold
	// a goroutine for the life of the process.
	_ = up.Close()
	<-done
}

// dial opens the connection to a server, with TLS where the listener asks
// for it.
func (t *server) dial(client netip.Addr) (net.Conn, error) {
	pool := t.host.Pool(t.c.Upstream)
	if pool == nil {
		return nil, errNoUpstream
	}
	e, _ := pool.Pick(client.String(), "", nil, upstream.CanaryAny)
	if e == nil {
		return nil, errNoUpstream
	}
	const dialTimeout = 10 * time.Second
	d := net.Dialer{Timeout: dialTimeout}
	c, err := d.Dial("tcp", e.Address)
	if err != nil {
		return nil, err
	}
	if t.upTLSMode == "disable" {
		return c, nil
	}
	host, _, splitErr := net.SplitHostPort(e.Address)
	if splitErr != nil {
		host = e.Address
	}
	cfg := t.upTLSCfg.Clone()
	if cfg.ServerName == "" {
		cfg.ServerName = host
	}
	tc := tls.Client(c, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = c.Close()
		if t.upTLSMode == "prefer" {
			// prefer means try and fall back, which is what an estate
			// migrating its equipment needs. A fresh connection is dialled
			// because the handshake consumed the first one.
			return d.Dial("tcp", e.Address)
		}
		return nil, err
	}
	return tc, nil
}

var errNoUpstream = errors.New("tacacs: no upstream endpoint")

// admitClient is the two questions this relay asks about a device before it
// carries anything for it.
//
// Asked on the connection, where there is no name yet: TACACS+ begins with
// the device's first packet, and the user name is inside a body this relay
// may not even be able to read. The name, where there is one, gets its own
// question in admitUser.
func (t *server) admitClient(ip netip.Addr) string {
	h := t.host
	return admit.Client(admit.Deps{
		Lists:       h.ThreatIntel(),
		Quarantined: h.Packs().Quarantined,
		Policy:      h.Authorization(),
		Logs:        h.Logs(),
		Matched:     func() { h.Counters().ThreatIntelMatched.Add(1) },
		Blocked:     func() { h.Counters().ThreatIntelBlocked.Add(1) },
	}, authorization.Subject{
		Listener: t.name,
		Kind:     "tacacs",
		Client:   ip,
		Target:   t.c.Upstream,
		Action:   authorization.ActionConnect,
	}, admit.Gate{
		Shadowing: func() bool { return !t.enforcing() },
		Record: func(reason, rule, detail string) {
			h.Counters().WouldRefuse("tacacs", reason)
			h.Shadow().Record("tacacs", t.name, reason, rule, detail)
		},
		Deny: func(reason, _, detail string) { t.deny(ip, reason, detail) },
	})
}

// admitUser asks the estate's policy about the name, once per session, as
// soon as a packet carries one.
//
// The name is a claim rather than a proven identity: this is the request on
// its way to the server that will check the password, so a rule keyed on
// `users` here is a filter on who may *attempt* to log in to the equipment.
// That is worth having -- it is the control that keeps a contractor's
// account off the core routers even when the TACACS+ server would accept it
// -- and it is worth not overstating, which is why the action is `connect`
// rather than `session`: the authenticated session is the one thing this
// relay never sees, because the server proves the password and says only
// pass or fail.
func (t *server) admitUser(c *conn, user string) string {
	h := t.host
	return h.Authorization().Ask(authorization.Subject{
		Listener: t.name,
		Kind:     "tacacs",
		Client:   c.ip,
		User:     user,
		Target:   t.c.Upstream,
		Action:   authorization.ActionConnect,
	}, user, authorization.Gate{
		Shadowing: func() bool { return !t.enforcing() },
		Record: func(reason, rule, detail string) {
			h.Counters().WouldRefuse("tacacs", reason)
			h.Shadow().Record("tacacs", t.name, reason, rule, detail)
		},
		Deny: func(reason, _, detail string) { t.deny(c.ip, reason, detail) },
	})
}

// fromClient reads the device's packets and forwards the ones the policy
// allows.
func (t *server) fromClient(c *conn, deadline time.Time) {
	for {
		if t.sessions.Closing() {
			return
		}
		if err := c.client.SetReadDeadline(soonest(time.Now().Add(t.idle), deadline)); err != nil {
			return
		}
		h, body, err := readPacket(c.client, t.maxBody())
		if err != nil {
			t.readError(c, err, "request")
			return
		}
		if !t.oneRequest(c, h, body) {
			return
		}
	}
}

// oneRequest decides about one packet from the device and returns whether
// the connection continues.
func (t *server) oneRequest(c *conn, h wire.Header, body []byte) bool {
	if d := t.policy.Header(c.ip, h); !d.Allow {
		t.refused(c, nil, d)
		if t.enforcing() || d.Hard {
			t.refuse(c, h, d)
			return false
		}
	}
	s, why := c.session(h)
	if why != "" {
		t.deny(c.ip, why, h.Type.String())
		t.refuse(c, h, Decision{Reason: why})
		return false
	}
	s.lastSeq = h.Seq
	if !t.reading() {
		// Header-only mode. The session is counted and bounded and the body
		// goes on untouched, which is the whole of what a listener with no
		// key can honestly do.
		t.host.Counters().TACACSHeaderOnly.Add(1)
		return t.forward(c, h, body, nil, Decision{Allow: true})
	}
	req, ok := t.read(c, s, h, body)
	if !ok {
		return false
	}
	// The estate's policy, asked as soon as a packet carries a name and again
	// if a later one carries a different name. The comparison is against
	// `asked` rather than against `user`, because read() above has already set
	// `user` from the body it just parsed.
	if req.User != "" && s.asked != req.User {
		s.asked = req.User
		if t.admitUser(c, req.User) != "" {
			t.refuse(c, h, Decision{Reason: "authorization_denied"})
			return false
		}
	}
	d := t.policy.Decide(req)
	if !d.Allow {
		t.refused(c, &req, d)
		if t.enforcing() || d.Hard {
			t.refuse(c, h, d)
			return false
		}
	}
	if s.rule == "" {
		s.rule = d.Rule
	}
	// Engineering: a configuration command, a reload, a firmware copy.
	// Reported whatever the policy said, and refused where this listener
	// requires an approved grant for it.
	if reason := t.decideEngineering(c, req); reason != "" {
		t.refuse(c, h, Decision{Reason: reason})
		return false
	}
	// Behavioural detection, after the policy and on what is going on to the
	// server.
	if reason := t.decideAnomaly(req); reason != "" {
		t.refuse(c, h, Decision{Reason: reason})
		return false
	}
	t.count(req)
	t.logRequest(req, d)
	return t.forward(c, h, body, &req, d)
}

// read de-obfuscates a body and parses it into the policy's view.
func (t *server) read(c *conn, s *sess, h wire.Header, body []byte) (Request, bool) {
	plain := wire.Deobfuscated(h, t.key, body)
	req := Request{Client: c.ip, Exchange: h.Type, Seq: h.Seq, Session: h.SessionID,
		Unencrypted: h.Unencrypted(), At: time.Now(),
		User: s.user, Port: s.port, RemAddr: s.remAddr,
		AuthenType: s.authenType, Action: s.action, Service: s.service, PrivLvl: s.privLvl}
	var err error
	switch {
	case h.Type == wire.TypeAuthen && h.Seq == 1:
		var st wire.AuthenStart
		if st, err = wire.ParseAuthenStart(plain); err == nil {
			s.user, s.port, s.remAddr = st.User, st.Port, st.RemAddr
			s.authenType, s.action, s.service, s.privLvl = st.Type, st.Action, st.Service, st.PrivLvl
			req.User, req.Port, req.RemAddr = st.User, st.Port, st.RemAddr
			req.AuthenType, req.Action, req.Service, req.PrivLvl = st.Type, st.Action, st.Service, st.PrivLvl
			if st.DataBytes > 0 && st.Type.Plaintext() {
				t.host.Counters().TACACSPlaintextPasswords.Add(1)
			}
		}
	case h.Type == wire.TypeAuthen:
		// A CONTINUE: the typed answer, whose contents this relay keeps only
		// the length of -- with one exception, which is the case where the
		// server asked for a name. The session says who typed it.
		var cont wire.AuthenContinue
		if cont, err = wire.ParseAuthenContinue(plain); err == nil {
			switch {
			case cont.UserMsgBytes > 0 && s.takeUserPrompt():
				// The ASCII login of RFC 8907 §5.4.2: the START named nobody,
				// the server answered GETUSER, and the name arrives here. It
				// is read because the alternative is a user list with a
				// bypass anybody can take -- leave the START's user field
				// empty and type the name at the prompt -- and because
				// everything below this point, the estate's authorization
				// question included, is keyed on a name.
				var u string
				if u, err = wire.ContinueUserMsg(plain); err == nil {
					s.user, req.User = u, u
				}
			case cont.UserMsgBytes > 0 && s.authenType.Plaintext():
				// Not a name, so on a plaintext type it is the password.
				t.host.Counters().TACACSPlaintextPasswords.Add(1)
			}
		}
	case h.Type == wire.TypeAuthor:
		var ar wire.AuthorRequest
		if ar, err = wire.ParseAuthorRequest(plain); err == nil {
			s.user, s.privLvl = ar.User, ar.PrivLvl
			req.User, req.Port, req.RemAddr = ar.User, ar.Port, ar.RemAddr
			req.AuthenType, req.Service, req.Method, req.PrivLvl = ar.Type, ar.Service, ar.Method, ar.PrivLvl
			req.Args, req.Command, req.ServiceArg = ar.Args, ar.Args.Command(), ar.Args.Service()
		}
	case h.Type == wire.TypeAcct:
		var ac wire.AcctRequest
		if ac, err = wire.ParseAcctRequest(plain); err == nil {
			s.user = ac.User
			req.User, req.Port, req.RemAddr = ac.User, ac.Port, ac.RemAddr
			req.AuthenType, req.Service, req.Method, req.PrivLvl = ac.Type, ac.Service, ac.Method, ac.PrivLvl
			req.Args, req.Command, req.ServiceArg = ac.Args, ac.Args.Command(), ac.Args.Service()
			t.logAccounting(req, ac)
		}
	}
	if err != nil {
		// A body that will not parse is a body this relay cannot decide
		// about. On the key boundary it is also the shape of a wrong key:
		// with the wrong key every body is noise, and the first noise is a
		// parse failure.
		t.deny(c.ip, "malformed", err.Error())
		t.refuse(c, h, Decision{Reason: "malformed"})
		return req, false
	}
	return req, true
}

// count records the per-exchange numbers.
func (t *server) count(req Request) {
	switch req.Exchange {
	case wire.TypeAuthen:
		if req.Seq == 1 {
			t.host.Counters().TACACSSessions.Add(1)
		}
	case wire.TypeAuthor:
		t.host.Counters().TACACSCommands.Add(1)
	case wire.TypeAcct:
		t.host.Counters().TACACSAccounting.Add(1)
	}
}

// forward writes a decided packet to the server, re-obfuscating it where the
// two legs have different keys.
func (t *server) forward(c *conn, h wire.Header, body []byte, req *Request, _ Decision) bool {
	out := body
	if t.reading() && !sameKey(t.key, t.upKey) {
		// De-obfuscate with one key and obfuscate with the other, so a
		// device's key never reaches the server. The unencrypted flag is
		// left as it arrived: changing it would be telling the server
		// something about the packet that is not true of the packet it
		// receives.
		plain := wire.Deobfuscated(h, t.key, body)
		out = wire.Obfuscate(h, t.upKey, plain)
		if h.Unencrypted() {
			out = plain
		}
	}
	if err := c.writeUp(writePacket(h, out)); err != nil {
		t.host.Counters().Refuse("tacacs", "upstream_failed")
		return false
	}
	_ = req
	return true
}

// fromServer reads the server's answers and forwards the ones the policy
// allows.
func (t *server) fromServer(c *conn, deadline time.Time) {
	for {
		if t.sessions.Closing() {
			return
		}
		if err := c.up.SetReadDeadline(soonest(time.Now().Add(t.idle), deadline)); err != nil {
			return
		}
		h, body, err := readPacket(c.up, t.maxBody())
		if err != nil {
			t.readError(c, err, "reply")
			return
		}
		if h.FromClient() {
			// An odd sequence number on the upstream leg: the server sending
			// something only a client sends. Forwarding it would make this
			// relay the way into the equipment rather than out of it.
			t.deny(c.ip, "wrong_direction", h.Type.String())
			return
		}
		if !t.oneAnswer(c, h, body) {
			return
		}
	}
}

// oneAnswer decides about one packet from the server.
func (t *server) oneAnswer(c *conn, h wire.Header, body []byte) bool {
	s := c.find(h.SessionID)
	if s == nil {
		// An answer to a session this relay has no record of. On a
		// multiplexed connection that is either an answer arriving after the
		// session was refused or a server answering something nobody asked.
		t.deny(c.ip, "no_such_session", h.Type.String())
		return false
	}
	if !t.reading() {
		return t.forwardBack(c, h, body)
	}
	a, ok := t.readAnswer(c, s, h, body)
	if !ok {
		return false
	}
	if d := t.policy.Answer(a); !d.Allow {
		t.refusedAnswer(c, s, a, d)
		if t.enforcing() || d.Hard {
			t.refuse(c, h, d)
			return false
		}
	}
	if a.HasPrivilege {
		t.host.Counters().TACACSPrivilegeGrants.Add(1)
	}
	t.logAnswer(c, s, a)
	if a.Exchange == wire.TypeAuthen && (a.Status == "pass" || a.Status == "fail" ||
		a.Status == "error") {
		// The session is over either way, so its slot goes back now rather
		// than at the idle timeout: an operator reading the live count
		// should see the sessions that are actually live.
		defer c.close(h.SessionID)
	}
	return t.forwardBack(c, h, body)
}

// readAnswer de-obfuscates and parses a reply.
func (t *server) readAnswer(c *conn, s *sess, h wire.Header, body []byte) (Answer, bool) {
	plain := wire.Deobfuscated(h, t.upKey, body)
	a := Answer{Client: c.ip, Exchange: h.Type, Rule: s.rule, At: time.Now()}
	var err error
	switch h.Type {
	case wire.TypeAuthen:
		var r wire.AuthenReply
		if r, err = wire.ParseAuthenReply(plain); err == nil {
			a.Status = r.Status.String()
			a.Follow = r.Status == wire.AuthenFollow
			a.Pass = r.Status == wire.AuthenPass
			// Whether the server is prompting for a name. This is the only
			// thing that makes a CONTINUE's user_msg readable, which is why it
			// is taken from the reply rather than guessed from the request --
			// and why it is recorded for every answer rather than only for a
			// GETUSER: an exchange that has moved on to GETPASS must leave
			// this relay reading nothing.
			s.askedForUser(r.Status == wire.AuthenGetUser)
		}
	case wire.TypeAuthor:
		var r wire.AuthorResponse
		if r, err = wire.ParseAuthorResponse(plain); err == nil {
			a.Status = r.Status.String()
			a.Follow = r.Status == wire.AuthorFollow
			a.Pass = r.Status.Pass()
			if n, ok := r.Args.PrivLvl(); ok {
				a.Privilege, a.HasPrivilege = n, true
			}
		}
	case wire.TypeAcct:
		var r wire.AcctReply
		if r, err = wire.ParseAcctReply(plain); err == nil {
			a.Status = r.Status.String()
			a.Follow = r.Status == wire.AcctFollow
			a.Pass = r.Status == wire.AcctSuccess
		}
	}
	if err != nil {
		t.deny(c.ip, "malformed_reply", err.Error())
		return a, false
	}
	return a, true
}

// forwardBack writes an answer to the device, re-obfuscating it where the
// two legs have different keys.
func (t *server) forwardBack(c *conn, h wire.Header, body []byte) bool {
	out := body
	if t.reading() && !sameKey(t.key, t.upKey) {
		plain := wire.Deobfuscated(h, t.upKey, body)
		out = wire.Obfuscate(h, t.key, plain)
		if h.Unencrypted() {
			out = plain
		}
	}
	if err := c.writeClient(writePacket(h, out)); err != nil {
		t.host.Counters().Refuse("tacacs", "client_write_failed")
		return false
	}
	return true
}

// refuse tells a refused device no, in the protocol's own terms.
//
// The person refused is an engineer at a terminal, so the message says which
// proxy refused and why -- which is the difference between a policy they can
// work with and a router they report as broken. It is written with the
// *client's* key, because that is the leg it goes out on, and with the
// client's own sequence number plus one, because that is the answer the
// device is waiting for.
func (t *server) refuse(c *conn, h wire.Header, d Decision) {
	defer c.close(h.SessionID)
	if !t.fail || !t.reading() {
		// Without a key this relay cannot write a body the device will read,
		// so the honest refusal is to close the connection.
		return
	}
	msg := "refused by xproxy (" + t.name + ")"
	if d.Reason != "" {
		msg += ": " + d.Reason
	}
	var body []byte
	switch h.Type {
	case wire.TypeAuthen:
		body = wire.MarshalAuthenReply(wire.AuthenReply{Status: wire.AuthenFail, ServerMsg: msg})
	case wire.TypeAuthor:
		body = wire.MarshalAuthorResponse(wire.AuthorResponse{Status: wire.AuthorFail, ServerMsg: msg})
	case wire.TypeAcct:
		body = wire.MarshalAcctReply(wire.AcctReply{Status: wire.AcctError, ServerMsg: msg})
	default:
		return
	}
	out := h
	out.Seq = h.Seq + 1
	if out.Seq < h.Seq {
		// The sequence number wrapped, which RFC 8907 §4.1 says ends the
		// session. There is nothing to answer with.
		return
	}
	out.Length = len(body)
	if !h.Unencrypted() {
		body = wire.Obfuscate(out, t.key, body)
	}
	_ = c.writeClient(writePacket(out, body))
}

// readError turns a read failure into the right record: a clean close is not
// an incident, a timeout is an idle session, and anything else is worth a
// counter.
func (t *server) readError(c *conn, err error, what string) {
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return
	case errors.Is(err, errBodyTooLarge):
		t.deny(c.ip, "body_too_large", what)
	case errors.Is(err, net.ErrClosed):
		return
	default:
		var ne net.Error
		if errorsAsTimeout(err, &ne) {
			t.host.Counters().Refuse("tacacs", "idle_timeout")
			return
		}
		if errors.Is(err, wire.ErrVersion) || errors.Is(err, wire.ErrZeroSeq) ||
			errors.Is(err, wire.ErrLength) || errors.Is(err, wire.ErrShort) {
			t.deny(c.ip, "malformed", err.Error())
		}
	}
}

// sameKey reports whether the two legs share a key, so the common case
// forwards the octets that arrived rather than re-deriving them.
func sameKey(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// soonest is the earlier of two deadlines, which is how an idle timeout and
// a session lifetime are applied by one SetReadDeadline.
func soonest(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
