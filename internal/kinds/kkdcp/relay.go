package kkdcp

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/rom/xproxy/internal/admit"
	"github.com/rom/xproxy/internal/authorization"
	wire "github.com/rom/xproxy/internal/kerberos"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/upstream"
)

// The request path: an HTTPS POST in, a TCP exchange with the KDC, an HTTPS
// response out.
//
// The HTTP layer is kept deliberately narrow. This listener serves one path
// and one method, it reads a bounded body, and it answers everything else
// with a status and nothing else -- because an HTTPS endpoint whose job is to
// carry Kerberos has no business being a web server, and every feature it
// does not have is a feature nobody can reach.
//
// The Kerberos layer is where the work is, and the order matters: the
// envelope, the realm, the message, the policy, the KDC, and then the policy
// again on the answer. The realm check sits second because it is the one that
// stops this being an open relay, and it is answered before the inner message
// has been read: an envelope naming a realm this proxy does not serve is
// refused whatever is inside it.

// contentType is what MS-KKDCP's clients send and expect.
const contentType = "application/kerberos"

// maxBody bounds the HTTP body independently of the Kerberos message, with
// room for the envelope's own DER around it.
func (t *server) maxBody() int64 { return int64(t.maxMessage) + 1024 }

// handle serves one POST.
func (t *server) handle(w http.ResponseWriter, r *http.Request) {
	ip := netutil.AddrOf(r.RemoteAddr)
	if r.URL.Path != t.path {
		// Not this listener's path. A 404 with no body: a proxy that
		// described itself here would be telling a scanner what it is.
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "", http.StatusMethodNotAllowed)
		return
	}
	if t.limiter != nil && !t.limiter.Allow(ip.String()) {
		t.host.Counters().Refuse("kkdcp", "rate_limited")
		http.Error(w, "", http.StatusTooManyRequests)
		return
	}
	if ok, reason := t.gate.Enter(ip); !ok {
		t.host.Counters().Refuse("kkdcp", reason)
		http.Error(w, "", http.StatusServiceUnavailable)
		return
	}
	defer t.gate.Leave(ip)
	if t.admitClient(ip) != "" {
		http.Error(w, "", http.StatusForbidden)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, t.maxBody()))
	if err != nil {
		t.deny(ip, "body_too_large", err.Error())
		http.Error(w, "", http.StatusRequestEntityTooLarge)
		return
	}
	env, err := wire.ParseProxyMessage(body, t.maxMessage)
	if err != nil {
		t.deny(ip, "malformed_envelope", err.Error())
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	t.exchange(w, ip, env)
}

// admitClient is the two questions this relay asks about a client: do the
// imported lists know this address, and does the estate's authorisation
// policy allow it here.
//
// Asked per request rather than per connection, because a keep-alive
// connection carries several logins and a feed that lists an address between
// two of them should reach the second.
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
		Kind:     "kkdcp",
		Client:   ip,
		Target:   t.k.Upstream,
		Action:   authorization.ActionConnect,
	}, admit.Gate{
		Shadowing: func() bool { return !t.enforcing() },
		Record: func(reason, rule, detail string) {
			h.Counters().WouldRefuse("kkdcp", reason)
			h.Shadow().Record("kkdcp", t.name, reason, rule, detail)
		},
		Deny: func(reason, _, detail string) { t.deny(ip, reason, detail) },
	})
}

// exchange decides about one message, carries it to the KDC and answers.
func (t *server) exchange(w http.ResponseWriter, ip netip.Addr, env wire.ProxyMessage) {
	m, err := wire.Parse(env.Inner)
	if err != nil {
		t.deny(ip, "malformed_message", err.Error())
		http.Error(w, "", http.StatusBadRequest)
		return
	}
	req := t.request(ip, env, m)
	// The realm first, and never shadowed: forwarding a message for a realm
	// this proxy does not serve is the open relay, not a policy opinion
	// about one.
	if d := t.policy.Realm(req); !d.Allow {
		if d.Reason == "realm_mismatch" {
			t.host.Counters().KKDCPRealmMismatch.Add(1)
		}
		t.refused(req, d)
		t.answerRefusal(w, req)
		return
	}
	// A client past the pre-authentication failure bound is refused before
	// the policy looks at this request: the burst is the finding, and the
	// request in hand is the next attempt in it.
	if t.sprayed(req) {
		t.answerRefusal(w, req)
		return
	}
	d := t.policy.Decide(req)
	if !d.Allow {
		t.refused(req, d)
		if t.enforcing() || d.Hard {
			t.answerRefusal(w, req)
			return
		}
	}
	if t.enumeration(req) != "" {
		t.answerRefusal(w, req)
		return
	}
	if t.decideAnomaly(req) != "" {
		t.answerRefusal(w, req)
		return
	}
	t.host.Counters().KKDCPRequests.Add(1)
	t.logRequest(req, d)
	reply, err := t.ask(req, env.Inner)
	if err != nil {
		t.host.Counters().Refuse("kkdcp", "upstream_failed")
		t.host.Logs().Error.Warn("kkdcp upstream exchange failed", "listener", t.name,
			"client_ip", ip.String(), "error", err.Error())
		http.Error(w, "", http.StatusBadGateway)
		return
	}
	t.answer(w, req, m, reply, d.Rule)
}

// request builds the policy's view of one message.
func (t *server) request(ip netip.Addr, env wire.ProxyMessage, m wire.Message) Request {
	req := Request{Client: ip, TargetDomain: env.TargetDomain, Realm: m.Realm,
		Type: m.Type, Options: m.Options, ETypes: m.ETypes,
		OnlyWeak: m.OnlyWeakETypes(), Preauth: m.Preauthenticated(),
		S4U2Self: m.S4U2Self(), S4U2Proxy: m.S4U2Proxy(),
		Anonymous: m.Options.Has(wire.OptRequestAnonymous), At: time.Now()}
	if m.HasClient {
		req.Principal = m.Client.String()
	}
	if m.HasForUser {
		// On an S4U2Self request the principal that matters is the one being
		// impersonated, not the service asking: a policy keyed on principals
		// should see `administrator`, which is what the request is for.
		req.Principal = m.ForUser.String()
	}
	if m.HasServer {
		req.Service, req.ServiceClass = m.Server.String(), m.Server.Service()
	}
	if d, ok := m.Lifetime(req.At); ok {
		req.Lifetime, req.HasLifetime = d, true
	}
	if req.S4U2Self || req.S4U2Proxy {
		t.host.Counters().KKDCPDelegations.Add(1)
	}
	return req
}

// enumeration applies the distinct-service bound, which is the behavioural
// half of the Kerberoasting control.
//
// It is counted on a TGS-REQ only. An AS-REQ names the realm's krbtgt and
// nothing else, so counting those would count the same name over and over
// and never fire.
func (t *server) enumeration(req Request) string {
	if t.services == nil || req.Type != wire.MsgTGSReq || req.Service == "" {
		return ""
	}
	n, over := t.services.distinct(req.Client, req.Service, req.At)
	if !over {
		return ""
	}
	const reason = "service_ticket_enumeration"
	if !t.enforcing() {
		t.host.Counters().WouldRefuse("kkdcp", reason)
		t.host.Shadow().Record("kkdcp", t.name, reason, "", req.Service)
		return ""
	}
	t.deny(req.Client, reason, itoa(n)+" distinct services")
	return reason
}

// ask carries one message to the KDC over TCP and reads the answer.
//
// The framing is the protocol's own: four octets of length, then the message.
// It is a fresh connection per request rather than a pool, and that is
// deliberate: a KDC exchange is one round trip, the connection is cheap next
// to the cryptography at both ends, and a pooled connection shared between
// two clients would be a place where one client's reply could reach the
// other.
func (t *server) ask(req Request, msg []byte) ([]byte, error) {
	pool := t.k.Upstream
	if req.Type == wire.MsgAPReq && t.k.PasswordUpstream != "" {
		pool = t.k.PasswordUpstream
	}
	p := t.host.Pool(pool)
	if p == nil {
		return nil, errNoUpstream
	}
	e, _ := p.Pick(req.Client.String(), "", nil, upstream.CanaryAny)
	if e == nil {
		return nil, errNoUpstream
	}
	d := net.Dialer{Timeout: t.timeout}
	c, err := d.Dial("tcp", e.Address)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	if err := c.SetDeadline(time.Now().Add(t.timeout)); err != nil {
		return nil, err
	}
	if _, err := c.Write(wire.Frame(msg)); err != nil {
		return nil, err
	}
	var hdr [4]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > uint32(t.maxMessage) { //nolint:gosec // maxMessage is a configured bound, validated positive
		return nil, errReplyTooLarge
	}
	out := make([]byte, n)
	if _, err := io.ReadFull(c, out); err != nil {
		return nil, err
	}
	return out, nil
}

var (
	errNoUpstream    = errors.New("kkdcp: no upstream endpoint")
	errReplyTooLarge = errors.New("kkdcp: the KDC's reply is past this listener's bound")
)

// answer decides about the KDC's reply and sends it.
func (t *server) answer(w http.ResponseWriter, req Request, msg wire.Message, reply []byte, rule string) {
	m, err := wire.Parse(reply)
	if err != nil {
		// A reply this relay cannot read is not forwarded. The alternative is
		// carrying octets nobody has checked from a KDC to a client on the
		// open internet, which is the one thing a proxy here must not do.
		t.deny(req.Client, "malformed_reply", err.Error())
		http.Error(w, "", http.StatusBadGateway)
		return
	}
	a := t.reply(req, msg, m, rule)
	if d := t.policy.Answer(a); !d.Allow {
		t.refusedAnswer(req, a, d)
		if t.enforcing() || d.Hard {
			t.answerRefusal(w, req)
			return
		}
	}
	t.logAnswer(req, a)
	t.write(w, req, reply)
}

// reply builds the policy's view of one answer, and counts the three facts
// worth counting whatever the policy says about them.
//
// req carries the request's claims and msg the request itself, because one of
// the decisions below is about the two messages together rather than either on
// its own: whether the KDC acted on the pre-authentication the request said it
// brought.
func (t *server) reply(req Request, msg, m wire.Message, rule string) Answer {
	a := Answer{Client: req.Client, Type: m.Type, Rule: rule, At: time.Now()}
	if m.HasTicketEType {
		a.TicketEType, a.HasTicketEType = m.TicketEType, true
		if m.TicketEType.Weak() {
			t.host.Counters().KKDCPWeakTickets.Add(1)
		}
	}
	if m.Type == wire.MsgError {
		a.IsError, a.ErrorCode = true, m.ErrorCode
		if m.ErrorCode == wire.KDCErrPreauthFailed {
			t.host.Counters().KKDCPPreauthFailures.Add(1)
			t.spray(req)
		}
		return a
	}
	// A successful AS exchange whose pre-authentication the KDC cannot be seen
	// to have acted on: the account is exempt, and the reply's encrypted part
	// is an offline password-cracking target.
	//
	// The test is on what can be shown rather than on what the request said.
	// A request's padata is written by the client, so "it brought
	// pre-authentication" was a claim an AS-REP roaster could make by adding
	// one item the KDC would pass over -- which is why PreauthProven pairs the
	// claim with the KDC's own answer. See Message.PreauthMustVerify.
	if m.Type == wire.MsgASRep && req.Type == wire.MsgASReq && !msg.PreauthProven(m) {
		a.PreauthExempt = true
		t.host.Counters().KKDCPPreauthExempt.Add(1)
	}
	return a
}

// spray applies the pre-authentication failure bound.
//
// It records and alerts rather than refusing the reply in hand: the reply is
// a KRB-ERROR the client is entitled to, and withholding it would only make
// the sprayer's failures silent. What the bound does is refuse the *next*
// request from that address, which is what the count is read for in
// enumeration's sibling check below.
func (t *server) spray(req Request) {
	if t.failures == nil {
		return
	}
	n, over := t.failures.hit(req.Client, req.At)
	if !over {
		return
	}
	const reason = "preauth_failure_burst"
	if !t.enforcing() {
		t.host.Counters().WouldRefuse("kkdcp", reason)
		t.host.Shadow().Record("kkdcp", t.name, reason, "", req.Principal)
		return
	}
	t.deny(req.Client, reason, itoa(n)+" failures")
}

// sprayed reports whether a client is past the pre-authentication failure
// bound, which is asked on the way in: the burst is the reason to stop
// carrying this address's requests at all.
func (t *server) sprayed(req Request) bool {
	if t.failures == nil || !t.enforcing() {
		return false
	}
	return t.failures.count(req.Client) > t.k.MaxPreauthFailures
}

// write sends a reply, wrapped in the envelope the client expects.
func (t *server) write(w http.ResponseWriter, req Request, msg []byte) {
	// No target domain on the way back: MS-KKDCP's own clients do not send
	// one, and echoing the client's would be putting a field in a message
	// the standard does not define one for.
	out := wire.MarshalProxyMessage(msg, "")
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", itoa(len(out)))
	if _, err := w.Write(out); err != nil {
		t.host.Counters().Refuse("kkdcp", "client_write_failed")
		_ = req
	}
}

// answerRefusal tells a refused client no.
//
// A KRB-ERROR is the better answer and it is the default, because silence on
// this protocol is a client that falls back to port 88 -- where there is no
// relay -- and then reports a network fault to whoever is sitting at it. The
// error says no in the only language the client reads, and it carries
// KDC_ERR_POLICY: the request was well formed and the policy refused it,
// which is the truth, where KDC_ERR_C_PRINCIPAL_UNKNOWN would be a lie the
// client's own logs would repeat.
//
// It takes no Decision, and that is the point rather than an omission: there
// is nothing about *why* the refusal happened that belongs in an answer to
// whoever sent the request. On this protocol the name of the control that
// fired is usually the intelligence the control exists to deny, so the reason
// goes to the security log and the counters, which the caller has already
// done.
func (t *server) answerRefusal(w http.ResponseWriter, req Request) {
	if !t.errorReply {
		http.Error(w, "", http.StatusForbidden)
		return
	}
	realm := req.Realm
	if realm == "" {
		realm = req.TargetDomain
	}
	if realm == "" {
		// Nothing readable said which realm this was for, so there is no
		// KRB-ERROR to build: the realm and the service are required fields.
		http.Error(w, "", http.StatusForbidden)
		return
	}
	sname := wire.KrbtgtFor(realm)
	// The reason is deliberately not in the answer: see ErrorText. It is in
	// the security event and the counters, which is where it belongs -- on
	// this protocol the name of the control that fired is usually the thing
	// the control exists to withhold.
	msg := wire.MarshalError(time.Now(), wire.KDCErrPolicy, realm, sname,
		wire.ErrorText(t.name))
	t.write(w, req, msg)
}

// itoa is strconv.Itoa under a shorter name, used in enough places here that
// the import would otherwise be the noisiest line in three files.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
