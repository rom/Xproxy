package snmp

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/keysource"
	wire "github.com/rom/xproxy/internal/snmp"
)

// Originating version 3 toward the agent: terminating the manager's security
// and starting one of this relay's own.
//
// usm.go reads what the manager sent. This writes what the agent is asked, as
// a USM session belonging to the relay, and it is what makes the upgrade to v3
// possible at all. Before it, `upgrade_version: v3` was refused at load with
// the reason that there was no user, engine or key to authenticate with --
// which was true, and is what upstream_usm supplies.
//
// What it buys:
//
//   - A v1 or v2c poller reaches a v3-only agent. That is the deployment this
//     protocol needs most: the agents were replaced, the polling system was
//     not, and the alternative is v1 left enabled on the agent for ever.
//   - The manager stops holding the agent's pass phrase. It holds its own, or
//     a community string, or nothing; the credential that opens the agent
//     lives in one place.
//   - A level the manager cannot speak. authPriv toward the agent from a
//     manager that has no privacy at all.
//
// What it costs, said here as well as in the configuration: there is no
// end-to-end authentication between the manager and the agent any more. The
// manager authenticates to this relay and this relay authenticates to the
// agent, so this process is now a party to the security rather than a reader
// of it. An estate that wants USM end to end wants `usm_users` and no
// upgrade.
//
// # Discovery
//
// A USM message is authenticated against the *authoritative* engine's clock --
// the agent's -- so the relay cannot originate one until it knows the agent's
// engine identifier, boots and time. RFC 3414 s4 says how to learn them: send
// a request naming no engine, and the agent answers a Report that names itself
// and its clock.
//
// The discovery carries the manager's own request identifier in its scoped
// PDU. That is deliberate: the Report comes back carrying it, so the existing
// pairing finds the same pending request, and the relay has the manager's
// question in hand at the moment it learns what it needed to ask it properly.
// The report is then answered by re-originating rather than by being forwarded
// to a manager that never asked for one.

// errNoUpstreamEngine says the agent's engine is not known yet, and a
// discovery has been sent in this request's place.
var errNoUpstreamEngine = errors.New("snmp: the agent's engine is not known yet")

// originator is the identity this relay presents to the agent.
type originator struct {
	user  string
	level wire.SecurityLevel
	auth  wire.AuthAlgo
	priv  wire.PrivAlgo
	// authPass and privPass are kept because a key is localised per engine and
	// the engine is discovered, not configured.
	authPass, privPass string
	// pinned is a configured engine identifier; nil means discover it.
	pinned []byte
	// max bounds the engines keys are held for, as it does downstream: an
	// agent that answered with a different identifier every time would
	// otherwise buy a megabyte of hashing per answer.
	max int

	mu   sync.Mutex
	keys map[string]*usmKeys

	// msgID numbers this relay's own messages. It is this relay's counter and
	// nothing to do with the manager's: two managers asking at once must not
	// produce two messages the agent sees as one.
	msgID atomic.Int64

	// engines is what the relay knows about each agent it speaks to, by the
	// address it speaks to.
	engMu   sync.Mutex
	engines map[string]*upstreamEngine
	// Discovered and Originated count what happened, for the status view.
	Discovered, Originated atomic.Uint64
}

// upstreamEngine is one agent's engine as this relay last learned it.
type upstreamEngine struct {
	id    []byte
	boots int64
	time  int64
	// at is when the clock above was learned, so that the time sent can be
	// advanced by the seconds since. An agent's time advances whether or not
	// anybody is asking, and a relay that sent a stale one would have every
	// message refused as outside the replay window.
	at time.Time
	// asking is set while a discovery is outstanding, so that a burst of
	// requests to a cold agent sends one discovery rather than one each.
	asking time.Time
}

// maxUpstreamEngines bounds the agents remembered.
const maxUpstreamEngines = 1024

// discoveryRetry is how long a discovery is considered outstanding. Shorter
// than any manager's retry, so a lost discovery is retried rather than leaving
// an agent unreachable until a restart.
const discoveryRetry = 2 * time.Second

// compileOriginator builds the upstream identity from upstream_usm.
func compileOriginator(m *config.SNMPListener, secrets *keysource.Resolver) (*originator, error) {
	c := m.UpstreamUSM
	if c == nil {
		return nil, nil
	}
	o := &originator{user: c.Name, level: wire.AuthPriv, max: defaultUSMEngines,
		keys: map[string]*usmKeys{}, engines: map[string]*upstreamEngine{}}
	if c.Privacy == "" {
		o.level = wire.AuthNoPriv
	}
	if m.UpstreamSecurityLevel != "" {
		lvl, ok := wire.LevelOf(m.UpstreamSecurityLevel)
		if !ok {
			return nil, fmt.Errorf("upstream_security_level: %q is not a security level", m.UpstreamSecurityLevel)
		}
		o.level = lvl
	}
	if m.MaxUSMEngines > 0 {
		o.max = m.MaxUSMEngines
	}
	var ok bool
	if o.auth, ok = wire.AuthAlgoOf(c.Auth); !ok {
		return nil, fmt.Errorf("upstream_usm.auth: %q is not an authentication protocol", c.Auth)
	}
	var err error
	if o.authPass, err = secret(secrets, c.AuthSecret); err != nil {
		return nil, fmt.Errorf("upstream_usm.auth_secret: %w", err)
	}
	if c.Privacy != "" {
		if o.priv, ok = wire.PrivAlgoOf(c.Privacy); !ok {
			return nil, fmt.Errorf("upstream_usm.privacy: %q is not a privacy protocol", c.Privacy)
		}
		if o.privPass, err = secret(secrets, c.PrivacySecret); err != nil {
			return nil, fmt.Errorf("upstream_usm.privacy_secret: %w", err)
		}
	}
	if o.level == wire.AuthPriv && o.priv == "" {
		return nil, errors.New("upstream_security_level: authPriv needs upstream_usm.privacy")
	}
	if c.EngineID != "" {
		if o.pinned, err = parseEngineID(c.EngineID); err != nil {
			return nil, fmt.Errorf("upstream_usm.engine_id: %w", err)
		}
	}
	return o, nil
}

// keysFor localises this identity's keys for one engine, once.
func (o *originator) keysFor(engineID []byte) *usmKeys {
	o.mu.Lock()
	defer o.mu.Unlock()
	if k := o.keys[string(engineID)]; k != nil {
		return k
	}
	if len(o.keys) >= o.max {
		return nil
	}
	k := &usmKeys{auth: wire.PasswordToKey(o.auth, o.authPass, engineID)}
	if o.priv != "" {
		k.priv = wire.PasswordToKey(o.auth, o.privPass, engineID)
	}
	o.keys[string(engineID)] = k
	return k
}

// engineFor is what the relay knows about one agent, and whether a discovery
// should be sent instead of a request.
//
// The returned clock has its time advanced by the seconds since it was
// learned, which is what keeps a message inside the agent's replay window
// after a quiet hour.
func (o *originator) engineFor(addr string, now time.Time) (*upstreamEngine, bool) {
	o.engMu.Lock()
	defer o.engMu.Unlock()
	e := o.engines[addr]
	if e == nil {
		if o.pinned != nil {
			// A pinned engine still needs a clock, and the clock is only ever
			// the agent's, so discovery happens anyway -- but a report naming
			// a different engine will not be believed.
			e = &upstreamEngine{id: o.pinned}
		} else {
			e = &upstreamEngine{}
		}
		if len(o.engines) >= maxUpstreamEngines {
			// The bound is reached. Refusing to learn a new agent is better
			// than forgetting one that is being polled: the table is keyed by
			// the addresses an operator configured, so reaching this is a
			// configuration with more agents than the bound, not an attack.
			return nil, false
		}
		o.engines[addr] = e
	}
	if len(e.id) == 0 || e.at.IsZero() {
		// Nothing to originate with yet.
		if now.Sub(e.asking) < discoveryRetry {
			return nil, false // a discovery is already outstanding
		}
		e.asking = now
		return nil, true // send one
	}
	out := &upstreamEngine{id: e.id, boots: e.boots, at: e.at,
		time: e.time + int64(now.Sub(e.at).Seconds())}
	return out, false
}

// learn records what a report or a response said about an agent's engine.
//
// A clock that went backwards is not recorded: the agent's own boots counter
// is what says a restart happened, and a time that fell without it is either a
// reordered datagram or somebody replaying one.
func (o *originator) learn(addr string, h *wire.V3Header, now time.Time) {
	if h == nil || len(h.EngineID) == 0 {
		return
	}
	o.engMu.Lock()
	defer o.engMu.Unlock()
	e := o.engines[addr]
	if e == nil {
		if len(o.engines) >= maxUpstreamEngines {
			return
		}
		e = &upstreamEngine{}
		o.engines[addr] = e
	}
	if o.pinned != nil && string(h.EngineID) != string(o.pinned) {
		// The identifier was pinned and the agent calls itself something else.
		// Not learned: the point of pinning is that this is refused rather
		// than adopted.
		return
	}
	if len(e.id) != 0 && string(e.id) == string(h.EngineID) &&
		(h.EngineBoots < e.boots || (h.EngineBoots == e.boots && h.EngineTime < e.time)) {
		return
	}
	if len(e.id) == 0 {
		o.Discovered.Add(1)
	}
	e.id, e.boots, e.time, e.at = h.EngineID, h.EngineBoots, h.EngineTime, now
	e.asking = time.Time{}
	o.engines[addr] = e
}

// discovery is the unauthenticated message that asks an agent to name itself.
//
// It carries the manager's request identifier so that the report it draws pairs
// with the manager's pending request, and a get of sysDescr so that an agent
// which answers a discovery with data rather than a report still says something
// useful. RFC 3414 s4 wants the engine identifier empty and the message
// reportable; both are what makes the agent answer with a Report at all.
func (o *originator) discovery(requestID int64) ([]byte, error) {
	pdu, err := getPDU(requestID, sysDescr)
	if err != nil {
		return nil, err
	}
	scoped, err := wire.ScopedPDU(nil, "", pdu)
	if err != nil {
		return nil, err
	}
	return wire.BuildV3(wire.V3Build{
		MessageID: o.nextMsgID(), MaxSize: wire.MaxMessage, Reportable: true,
		Level: wire.NoAuthNoPriv, User: "", Scoped: scoped,
	})
}

// originate builds the agent's copy of one request.
func (o *originator) originate(pdu []byte, addr string, now time.Time) ([]byte, error) {
	eng, discover := o.engineFor(addr, now)
	if eng == nil {
		if discover {
			return nil, errNoUpstreamEngine
		}
		return nil, errors.New("snmp: no engine for this agent and no discovery to send")
	}
	keys := o.keysFor(eng.id)
	if keys == nil {
		return nil, fmt.Errorf("snmp: this identity holds keys for %d engines already", o.max)
	}
	scoped, err := wire.ScopedPDU(eng.id, "", pdu)
	if err != nil {
		return nil, err
	}
	out, err := wire.BuildV3(wire.V3Build{
		MessageID: o.nextMsgID(), MaxSize: wire.MaxMessage, Reportable: true,
		Level: o.level, EngineID: eng.id, User: o.user,
		EngineBoots: eng.boots, EngineTime: eng.time, Scoped: scoped,
		Auth: o.auth, AuthKey: keys.auth, Priv: o.priv, PrivKey: keys.priv,
	})
	if err != nil {
		return nil, err
	}
	o.Originated.Add(1)
	return out, nil
}

// nextMsgID is this relay's own message identifier, wrapped inside the range
// RFC 3412 gives the field (it is an INTEGER bounded to 2^31-1).
func (o *originator) nextMsgID() int64 {
	return o.msgID.Add(1) & 0x7fffffff
}

// readAgentV3 verifies and decrypts an agent's answer with this relay's own
// keys, attaching the scoped PDU so the ordinary response path can read it.
//
// It is the mirror of the downstream reader and it is separate on purpose: the
// keys are different, the engine is the agent's own, and a relay that tried one
// set of keys and then the other would be a relay that could not say which
// session an answer belonged to.
func (o *originator) readAgentV3(m *wire.Message, addr string, now time.Time) (string, string) {
	if m == nil || m.V3 == nil {
		return "", ""
	}
	// A report is unauthenticated by design -- it is the answer to a message
	// whose credentials the agent could not check -- so it is read for its
	// engine and nothing else.
	o.learn(addr, m.V3, now)
	if !m.V3.Level.Authenticated() {
		return "", ""
	}
	if m.V3.User != o.user {
		// An authenticated answer naming somebody else is not this session's.
		return reasonEngine, "user " + m.V3.User
	}
	keys := o.keysFor(m.V3.EngineID)
	if keys == nil {
		return reasonEngines, ""
	}
	if err := wire.Verify(m, keys.auth, o.auth); err != nil {
		return reasonAuthFailed, err.Error()
	}
	if !m.V3.ScopedPDUEncrypted {
		return "", ""
	}
	if len(keys.priv) == 0 {
		return reasonNoPrivKey, ""
	}
	plain, err := wire.Decrypt(m, keys.priv, o.priv)
	if err != nil {
		return reasonUnreadable, err.Error()
	}
	s, err := wire.ParseScoped(plain)
	if err != nil {
		return reasonUnreadable, err.Error()
	}
	m.PDU = s.PDU
	m.V3.ContextEngineID, m.V3.ContextName = s.ContextEngineID, s.ContextName
	return "", ""
}

// Engines is how many agents this identity has learned, for the status view.
func (o *originator) Engines() int {
	if o == nil {
		return 0
	}
	o.engMu.Lock()
	defer o.engMu.Unlock()
	return len(o.engines)
}

// getPDU encodes a GetRequest for one object, which is all a discovery needs.
func getPDU(requestID int64, oid string) ([]byte, error) {
	o, err := wire.ParseOID(oid)
	if err != nil {
		return nil, err
	}
	return wire.GetRequestPDU(requestID, o), nil
}

// sysDescr is the object a discovery asks for. Any object would do -- the
// report comes back either way -- and this is the one every agent has.
const sysDescr = "1.3.6.1.2.1.1.1.0"

// sendDiscovery writes the discovery for one agent.
func (t *server) sendDiscovery(agent net.PacketConn, addr net.Addr, requestID int64) bool {
	raw, err := t.orig.discovery(requestID)
	if err != nil {
		t.host.Logs().Error.Warn("snmp discovery build failed", "listener", t.cfg.Name,
			"agent", addr.String(), "error", err.Error())
		return false
	}
	if _, err := agent.WriteTo(raw, addr); err != nil {
		t.host.Counters().SNMPUpstreamFail.Add(1)
		return false
	}
	t.host.Counters().SNMPDiscoveries.Add(1)
	return true
}

// hold takes the pending slot for one request, which is what pairs its answer.
//
// It is shared by the ordinary forward and by the originating one. The
// originating path needs it *before* the message is sent, because the first
// thing sent may be a discovery whose report has to find this request waiting.
func (t *server) hold(m *wire.Message, p *peer, d Decision, asked int) bool {
	if m.PDU == nil || m.PDU.Type.Notification() {
		return true
	}
	ip := p.ip
	e := &exchange{client: ip, from: p.from, peer: p, requestID: m.PDU.RequestID,
		asked: asked, rule: d.Rule, version: m.Version, community: m.Community,
		tsm: echoOf(m)}
	if t.orig != nil && t.upgrade == wire.V3 {
		e.pdu = m.PDU.Raw
	}
	if t.pend.add(e, time.Now()) {
		return true
	}
	// The table is full of requests nobody answered. Refusing here keeps the
	// answer matching reliable, and that matching is the check that finds an
	// unsolicited response rather than a convenience.
	t.host.Counters().Refuse("snmp", "too_many_pending")
	t.deny(ip, "snmp_too_many_pending", "")
	return false
}

// originateUpstream sends the agent this relay's own version 3 message, or the
// discovery that has to come first.
func (t *server) originateUpstream(agent net.PacketConn, m *wire.Message, ip netip.Addr, d Decision) {
	s := t.host
	addr := t.agentAddr(ip)
	if addr == nil {
		s.Counters().SNMPUpstreamFail.Add(1)
		t.forget(m)
		return
	}
	if m.PDU == nil {
		// An encrypted v3 request this listener holds no key for. There is no
		// PDU to put in a message of this relay's own, and there will not be
		// one without the key: usm_users is what makes that work.
		s.Counters().Refuse("snmp", "upgrade_failed")
		t.deny(ip, "snmp_upgrade_failed", errSealed.Error())
		t.forget(m)
		return
	}
	out, err := t.orig.originate(m.PDU.Raw, addr.String(), time.Now())
	switch {
	case errors.Is(err, errNoUpstreamEngine):
		// The agent has not said who it is yet. The discovery carries this
		// request's identifier, so the report it draws pairs with the slot
		// taken above and the request is sent properly then.
		if !t.sendDiscovery(agent, addr, m.PDU.RequestID) {
			t.forget(m)
		}
		t.logMessage(ip, m, d, "manager")
		t.observeManager(ip, m)
		return
	case err != nil:
		s.Counters().Refuse("snmp", "upgrade_failed")
		t.deny(ip, "snmp_upgrade_failed", err.Error())
		t.forget(m)
		return
	}
	s.Counters().SNMPUpgraded.Add(1)
	s.Counters().SNMPOriginated.Add(1)
	t.logMessage(ip, m, d, "manager")
	t.observeManager(ip, m)
	if _, err := agent.WriteTo(out, addr); err != nil {
		s.Counters().SNMPUpstreamFail.Add(1)
		s.Logs().Error.Warn("snmp forward to agent failed", "listener", t.cfg.Name,
			"agent", addr.String(), "error", err.Error())
		t.forget(m)
	}
}

// resendAfterDiscovery is what a report is for: the agent has named its engine,
// so the request that was waiting can now be asked properly.
//
// The pending slot is kept rather than retaken -- the manager is still waiting
// on the same question -- and the report itself is not forwarded: the manager
// asked for data, not for a statement about engine identifiers.
func (t *server) resendAfterDiscovery(agent net.PacketConn, e *exchange) bool {
	if t.orig == nil || e == nil || len(e.pdu) == 0 {
		return false
	}
	addr := t.agentAddr(e.client)
	if addr == nil {
		t.host.Counters().SNMPUpstreamFail.Add(1)
		return false
	}
	out, err := t.orig.originate(e.pdu, addr.String(), time.Now())
	if err != nil {
		// Including a second errNoUpstreamEngine: the report did not name an
		// engine this relay would believe, which a pinned engine_id makes
		// deliberate. The manager's request is dropped and its own retry is
		// what tries again.
		t.host.Counters().Refuse("snmp", "upgrade_failed")
		t.deny(e.client, "snmp_upgrade_failed", err.Error())
		return false
	}
	if _, err := agent.WriteTo(out, addr); err != nil {
		t.host.Counters().SNMPUpstreamFail.Add(1)
		return false
	}
	t.host.Counters().SNMPUpgraded.Add(1)
	t.host.Counters().SNMPOriginated.Add(1)
	return true
}
