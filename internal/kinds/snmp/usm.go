package snmp

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/keysource"
	wire "github.com/rom/xproxy/internal/snmp"
)

// Reading version 3, with the user's keys.
//
// Without keys a v3 message is a header and an opaque payload: the user name,
// the engine, the security level, and nothing a rule can be written about. So
// every policy an operator wrote about operations and object identifiers
// applied to v1 and v2c and silently did not apply to v3 -- which is the
// version an operator is told to insist on. That is the wrong way round.
//
// With the user's pass phrases the digest can be verified and, at authPriv,
// the payload decrypted, and then the ordinary rules decide about a v3
// message exactly as they decide about a v2c one.
//
// Three things about this are deliberate.
//
// **Nothing is written.** The octets forwarded to the agent are the octets
// that arrived. There is no re-encryption and no re-signing, so a message
// this relay misread cannot be a message the agent receives differently, and
// the key is needed for reading only.
//
// **A downgrade is a refusal.** A user this listener holds keys for, sending
// at noAuthNoPriv, is a message whose digest cannot be checked from a user
// whose digest can be. Stripping the authentication flags is the cheapest
// forgery on this protocol, so it is refused rather than admitted as a lower
// security level.
//
// **Key derivation is bounded.** RFC 3414 s2.6 derives a key by hashing a
// megabyte of repeated pass phrase, deliberately, so that guessing a pass
// phrase costs a megabyte per guess. The engine identifier that decides
// *which* key is needed arrives in the message, so an unbounded relay would
// hash a megabyte for every identifier a sender cared to invent. Keys are
// derived once per engine, cached, and bounded per user.

// usmUser is one configured user: the pass phrases, and the keys derived from
// them for each engine this user has been seen with.
type usmUser struct {
	name     string
	engineID []byte // nil accepts whatever engine the message names
	auth     wire.AuthAlgo
	authPass string
	priv     wire.PrivAlgo
	privPass string
	max      int

	mu   sync.Mutex
	keys map[string]*usmKeys
}

// usmKeys is one engine's pair of localised keys.
type usmKeys struct {
	auth []byte
	priv []byte
}

// usm is the listener's set of users, and what it remembers about the clocks
// of the engines they name.
type usm struct {
	byName map[string]*usmUser
	window time.Duration
	now    func() time.Time

	mu     sync.Mutex
	clocks map[string]*engineClock
}

// engineClock is the highest clock this listener has seen from one engine, and
// when it saw it. Keeping the instant is what lets a quiet hour pass without
// the next message looking like a replay: the engine's time has advanced by
// roughly the wall clock's, so that is what it is compared against.
type engineClock struct {
	boots int64
	time  int64
	seen  time.Time
}

// maxEngineID is RFC 3411's bound on an engine identifier, which the parser
// already enforces; it is repeated here because a configured one has not been
// through the parser.
const maxEngineID = 32

// defaultUSMEngines is how many engines one user's keys are derived for.
// Eight covers a pool of agents behind one listener without letting a sender
// buy processor time by varying a field.
const defaultUSMEngines = 8

// compileUSM builds the reader from the listener's usm_users.
//
// The pass phrases are resolved here rather than per message: a missing secret
// is then a configuration that does not load, instead of a listener that
// refuses every v3 message at three in the morning. A rotated pass phrase
// needs a reload, which is what a compiled policy needs anyway.
func compileUSM(m *config.SNMPListener, secrets *keysource.Resolver) (*usm, error) {
	if len(m.USMUsers) == 0 {
		return nil, nil
	}
	u := &usm{byName: make(map[string]*usmUser, len(m.USMUsers)),
		window: 150 * time.Second, clocks: map[string]*engineClock{}, now: time.Now}
	if m.ReplayWindow != 0 {
		u.window = m.ReplayWindow.D()
	}
	for i := range m.USMUsers {
		c := &m.USMUsers[i]
		where := fmt.Sprintf("usm_users[%d]", i)
		user, err := compileUSMUser(c, where, m.MaxUSMEngines, secrets)
		if err != nil {
			return nil, err
		}
		if _, dup := u.byName[user.name]; dup {
			return nil, fmt.Errorf("%s: %q appears twice", where, user.name)
		}
		u.byName[user.name] = user
	}
	return u, nil
}

func compileUSMUser(c *config.SNMPUser, where string, max int, secrets *keysource.Resolver) (*usmUser, error) {
	if c.Name == "" {
		return nil, fmt.Errorf("%s.name: required", where)
	}
	if max <= 0 {
		max = defaultUSMEngines
	}
	u := &usmUser{name: c.Name, max: max, keys: map[string]*usmKeys{}}
	var ok bool
	if u.auth, ok = wire.AuthAlgoOf(c.Auth); !ok {
		return nil, fmt.Errorf("%s.auth: %q is not an authentication protocol", where, c.Auth)
	}
	var err error
	if u.authPass, err = secret(secrets, c.AuthSecret); err != nil {
		return nil, fmt.Errorf("%s.auth_secret: %w", where, err)
	}
	if c.Privacy != "" {
		if u.priv, ok = wire.PrivAlgoOf(c.Privacy); !ok {
			return nil, fmt.Errorf("%s.privacy: %q is not a privacy protocol", where, c.Privacy)
		}
		if u.privPass, err = secret(secrets, c.PrivacySecret); err != nil {
			return nil, fmt.Errorf("%s.privacy_secret: %w", where, err)
		}
		if n, have := u.priv.KeyLen(), u.auth.KeyLen(); have < n {
			// The privacy key is the authentication protocol's own
			// derivation truncated to the cipher's length, so a short hash
			// cannot key a wide cipher: AES-256 needs thirty-two octets and
			// MD5 produces sixteen. Refusing at load is the difference
			// between a configuration that does not start and a listener
			// that refuses every encrypted message it was built to read.
			return nil, fmt.Errorf("%s: %s keys are %d octets and %s needs %d; "+
				"pair a wider authentication protocol with it", where, u.auth, have, u.priv, n)
		}
	}
	if c.EngineID != "" {
		if u.engineID, err = parseEngineID(c.EngineID); err != nil {
			return nil, fmt.Errorf("%s.engine_id: %w", where, err)
		}
		// Pinned, so the one key this user will ever need is derived now
		// rather than on the first message: a megabyte of hashing belongs at
		// load where it costs nothing.
		u.keys[string(u.engineID)] = u.derive(u.engineID)
	}
	return u, nil
}

// secret resolves a pass phrase reference.
func secret(secrets *keysource.Resolver, ref string) (string, error) {
	if ref == "" {
		return "", errors.New("required")
	}
	if secrets == nil {
		return "", errors.New("no secret resolver is configured")
	}
	s, err := secrets.StringValue(ref)
	if err != nil {
		return "", err
	}
	if s == "" {
		return "", errors.New("resolved to nothing")
	}
	return s, nil
}

// parseEngineID reads an engine identifier written as hexadecimal, with or
// without the separators the tools print.
func parseEngineID(s string) ([]byte, error) {
	t := strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	t = strings.NewReplacer(":", "", "-", "", " ", "").Replace(t)
	b, err := hex.DecodeString(t)
	if err != nil {
		return nil, fmt.Errorf("%q is not hexadecimal: %w", s, err)
	}
	if len(b) == 0 || len(b) > maxEngineID {
		return nil, fmt.Errorf("an engine identifier is 1 to %d octets and this is %d", maxEngineID, len(b))
	}
	return b, nil
}

// derive localises this user's pass phrases to one engine.
func (u *usmUser) derive(engineID []byte) *usmKeys {
	k := &usmKeys{auth: wire.PasswordToKey(u.auth, u.authPass, engineID)}
	if u.priv != "" {
		// The privacy key uses the *authentication* protocol's derivation --
		// RFC 3414 has one derivation, not two -- truncated by the cipher.
		k.priv = wire.PasswordToKey(u.auth, u.privPass, engineID)
	}
	return k
}

// keysFor is this user's keys for one engine, derived on first sight and
// cached. It returns nil when the engine bound is already spent, which is
// refused rather than served: see the note on bounded derivation above.
func (u *usmUser) keysFor(engineID []byte) *usmKeys {
	u.mu.Lock()
	defer u.mu.Unlock()
	if k := u.keys[string(engineID)]; k != nil {
		return k
	}
	if len(u.keys) >= u.max {
		return nil
	}
	k := u.derive(engineID)
	u.keys[string(engineID)] = k
	return k
}

// engines is how many engines this user holds keys for, which a test reads.
func (u *usmUser) engines() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.keys)
}

// The reasons this file refuses a message. They are the labels the counters
// and the security log use, so they are stable.
const (
	reasonDowngrade  = "snmp_usm_downgrade"
	reasonEngine     = "snmp_usm_engine"
	reasonEngines    = "snmp_usm_engines"
	reasonAuthFailed = "snmp_auth_failed"
	reasonReplay     = "snmp_replay"
	reasonNoPrivKey  = "snmp_usm_no_privacy_key"
	reasonUnreadable = "snmp_unreadable"
)

// read verifies and, where it can, decrypts one version 3 message, attaching
// the scoped PDU to it so that the ordinary rules decide about it.
//
// It returns the refusal reason and its detail, or "" when the message is
// readable -- or when it is not this reader's business, which is every
// message from a user no key was configured for. A listener that holds one
// user's keys has not thereby taken responsibility for every other user; the
// `users` allow list is where an operator says which may send at all.
func (u *usm) read(m *wire.Message) (string, string) {
	if u == nil || m.Version != wire.V3 || m.V3 == nil {
		return "", ""
	}
	user := u.byName[m.V3.User]
	if user == nil {
		return "", ""
	}
	if m.V3.Level == wire.NoAuthNoPriv {
		// Keys exist for this user and this message carries nothing to check
		// them against. Dropping the flags is the cheapest forgery on this
		// protocol and the one a relay is best placed to see.
		return reasonDowngrade, m.V3.User
	}
	if user.engineID != nil && !bytes.Equal(m.V3.EngineID, user.engineID) {
		return reasonEngine, hex.EncodeToString(m.V3.EngineID)
	}
	keys := user.keysFor(m.V3.EngineID)
	if keys == nil {
		return reasonEngines, hex.EncodeToString(m.V3.EngineID)
	}
	if err := wire.Verify(m, keys.auth, user.auth); err != nil {
		return reasonAuthFailed, m.V3.User
	}
	// The clock, and only now: a message whose digest did not check out has
	// no clock worth remembering, and letting one move this engine's high
	// water mark would let a forgery lock out the real agent.
	if why := u.clock(m.V3); why != "" {
		return why, m.V3.User
	}
	if m.V3.Level != wire.AuthPriv {
		return "", ""
	}
	if keys.priv == nil {
		// Configured for authentication only, and the message is encrypted.
		// Forwarding it unread would make privacy the way round every rule
		// on this listener, which is the opposite of what holding keys is
		// for.
		return reasonNoPrivKey, m.V3.User
	}
	plain, err := wire.Decrypt(m, keys.priv, user.priv)
	if err != nil {
		return reasonUnreadable, err.Error()
	}
	s, err := wire.ParseScoped(plain)
	if err != nil {
		// The digest checked out, so these octets are the sender's own and
		// the cipher is the one configured; a payload that is not a scoped
		// PDU is then a malformed message rather than a wrong key.
		return reasonUnreadable, err.Error()
	}
	// Attached, so that Decide sees an operation and object identifiers
	// where it saw an opaque blob. ScopedPDUEncrypted stays set: the message
	// arrived encrypted and is forwarded encrypted, and anything reading
	// this header should be able to tell.
	m.PDU = s.PDU
	m.V3.ContextName = s.ContextName
	m.V3.ContextEngineID = s.ContextEngineID
	return "", ""
}

// clock is RFC 3414 s2.2.3's time window, from the outside.
//
// A non-authoritative engine keeps the highest boot count and clock it has
// seen from each authoritative engine and refuses a message that goes
// backwards: a lower boot count, or the same boot count with a clock more
// than the window behind. That is what makes a captured datagram unusable
// later, which is the one thing a digest alone does not give.
func (u *usm) clock(h *wire.V3Header) string {
	if u.window <= 0 {
		return ""
	}
	// The standard's own out-of-range value: a boot count at the top of the
	// range is an engine that has lost count, and its clock means nothing.
	const bootsMax = 2147483647
	if h.EngineBoots <= 0 || h.EngineBoots >= bootsMax {
		return reasonReplay
	}
	key := string(h.EngineID)
	now := u.now()
	u.mu.Lock()
	defer u.mu.Unlock()
	c := u.clocks[key]
	if c == nil {
		if len(u.clocks) >= maxClocks {
			// The table is bounded like every other per-peer table here. A
			// full one stops checking rather than refusing: the window is a
			// detection, and a relay that refused every message once a
			// bounded table filled would be a relay an attacker could close
			// by naming engines.
			return ""
		}
		u.clocks[key] = &engineClock{boots: h.EngineBoots, time: h.EngineTime, seen: now}
		return ""
	}
	switch {
	case h.EngineBoots < c.boots:
		return reasonReplay
	case h.EngineBoots > c.boots:
		// The agent restarted, which resets its clock. The high water mark
		// follows the boot count.
		c.boots, c.time, c.seen = h.EngineBoots, h.EngineTime, now
		return ""
	}
	// Same boot count: the engine's clock should have advanced by about as
	// much as ours has since the last message we believed.
	expect := c.time + int64(now.Sub(c.seen)/time.Second)
	if h.EngineTime < expect-int64(u.window/time.Second) {
		return reasonReplay
	}
	if h.EngineTime > c.time {
		c.time, c.seen = h.EngineTime, now
	}
	return ""
}

// maxClocks bounds the engines whose clocks are remembered.
const maxClocks = 1024

// inspect verifies and decrypts one message with the listener's keys, counting
// what happened.
//
// It returns a Decision so that the refusal travels the same path every other
// refusal on this listener travels: the counters, the security log, the shadow
// ledger and the deception all see it without a special case. Shadow mode
// applies, which is deliberate -- a wrong pass phrase would otherwise break
// every poll on the estate the moment this section is added, and shadow mode
// is what an operator trials it with. What shadow mode cannot do is make the
// message readable, so a v3 message this relay would have refused is forwarded
// exactly as it arrived and the rules below decide about its header alone.
func (t *server) inspect(m *wire.Message) Decision {
	if t.usm == nil || m.Version != wire.V3 {
		return Decision{Allow: true}
	}
	reason, detail := t.usm.read(m)
	c := t.host.Counters()
	if reason == "" {
		if m.V3 != nil && m.V3.User != "" && t.usm.byName[m.V3.User] != nil {
			c.SNMPVerified.Add(1)
			if m.V3.ScopedPDUEncrypted && m.PDU != nil {
				c.SNMPDecrypted.Add(1)
			}
		}
		return Decision{Allow: true}
	}
	switch reason {
	case reasonAuthFailed:
		c.SNMPAuthFailed.Add(1)
	case reasonReplay:
		c.SNMPReplayed.Add(1)
	}
	return Decision{Reason: reason, Detail: detail}
}
