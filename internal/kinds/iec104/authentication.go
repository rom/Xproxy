package iec104

import (
	"fmt"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/iec104"
)

// IEC 62351-5, and the honest limit of what a relay in the middle can say
// about it.
//
// IEC 60870-5-104 has no authentication at all: a controlling station is an
// address, and an address is what an attacker on the same segment chooses.
// IEC 60870-5-7 -- the application layer IEC 62351-5 specifies -- adds one over
// the existing ASDU machinery. The controlled station challenges a critical
// command with S_CH_NA_1, the controlling station answers with S_RP_NA_1
// carrying an HMAC over the challenge and the command, and only then is the
// command acted on. Aggressive mode carries the authentication with the command
// in S_AS_NA_1 instead of after it, for the cases where the extra round trip
// costs too much.
//
// **This relay recognises the exchange and carries it. It does not verify it.**
// Verifying means holding the update keys, and a relay holding them would be a
// second place to take them from; one that failed closed on a key it had got
// wrong would stop a control centre operating a grid. So no HMAC is computed
// here, no key is stored, and nothing about the *validity* of an authentication
// is asserted.
//
// What is asserted is weaker and still worth having:
//
//   - **The exchange is not refused.** Before these types were named, a listener
//     saw type 81 as an unknown type and its policy refused it -- which made the
//     standard's own authentication unusable through this relay. That is the
//     failure this file mostly exists to prevent, and it is why `security` is a
//     rule class of its own rather than folded into `system`.
//
//   - **Whether it happened is visible.** Completed exchanges are counted per
//     listener, so an operator can see that a substation which is using secure
//     authentication is, and an estate can find the associations that are not.
//
//   - **It can be required.** `require_authentication` refuses a command on an
//     association where the station has not positively confirmed a challenged
//     reply or aggressive-mode request inside a window. A relay cannot tell a
//     good HMAC from a bad one; it can tell a completed exchange from an
//     unsolicited authentication-shaped frame.

// authPolicy is the secure-authentication posture.
type authPolicy struct {
	// require refuses a command on an association with no authentication seen.
	require bool
	// window is how long an authentication counts for. The standard's own
	// session keys expire, and an authentication that never did would let one
	// exchange at connection time authorise every command for a week.
	window time.Duration
}

const defaultAuthWindow = 5 * time.Minute

func (p *authPolicy) on() bool { return p != nil && p.require }

func compileAuthentication(c *config.IEC104Authentication) (*authPolicy, error) {
	if c == nil {
		return &authPolicy{}, nil
	}
	p := &authPolicy{require: c.Require, window: c.Window.D()}
	if p.window < 0 {
		return nil, fmt.Errorf("authentication.window: must not be negative")
	}
	if p.window == 0 {
		p.window = defaultAuthWindow
	}
	return p, nil
}

// authState is what one association has shown.
//
// Per session and not per listener, deliberately. An authentication belongs to
// the association that performed it: crediting one connection's exchange to
// another would let an attacker who can open a socket ride on a legitimate
// control centre's authentication, which is the whole thing being defended
// against.
type authState struct {
	mu sync.Mutex
	// challenged is the common address for which the station has issued a
	// challenge. awaiting is the reply/request for which the station still owes
	// a positive confirmation. Keeping both prevents an unsolicited client ASDU
	// from being mistaken for evidence of an exchange.
	challenged map[uint16]bool
	awaiting   map[authExchange]bool
	// at is when authentication was last seen on this association, and seen
	// whether it ever was. Separate, because the zero time is a valid instant
	// and "never" has to be distinguishable from "long ago".
	at   time.Time
	seen bool
}

type authExchange struct {
	typeID wire.Type
	common uint16
}

// observe records the progress of one secure-authentication exchange. It
// returns true only when the station positively confirms a reply or an
// aggressive-mode request.
func (a *authState) observe(asdu *wire.ASDU, fromClient bool, now time.Time) bool {
	if asdu == nil || !asdu.Type.Secure() {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.challenged == nil {
		a.challenged = make(map[uint16]bool)
		a.awaiting = make(map[authExchange]bool)
	}
	key := authExchange{typeID: asdu.Type, common: asdu.Common}
	switch {
	case !fromClient && asdu.Type == wire.SChNA1:
		a.challenged[asdu.Common] = true
	case fromClient && asdu.Type == wire.SRpNA1 && a.challenged[asdu.Common]:
		delete(a.challenged, asdu.Common)
		a.awaiting[key] = true
	case fromClient && asdu.Type == wire.SAsNA1:
		a.awaiting[key] = true
	case !fromClient && asdu.Type.Authenticates() && asdu.Cause == wire.CauseActCon:
		if !a.awaiting[key] {
			return false
		}
		delete(a.awaiting, key)
		if asdu.Negative {
			return false
		}
		a.at, a.seen = now, true
		return true
	case !fromClient && asdu.Type == wire.SErNA1:
		clear(a.challenged)
		clear(a.awaiting)
	}
	return false
}

// fresh says whether an authentication has been seen inside the window.
func (a *authState) fresh(window time.Time) (bool, time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.seen {
		// Redundant against any real clock -- the zero time is before every
		// window bound a running relay computes -- and kept because "never
		// authenticated" and "authenticated a long time ago" are different
		// findings, and the caller distinguishes them in what it logs.
		return false, time.Time{}
	}
	return !a.at.Before(window), a.at
}

// decideAuthentication refuses a command on an association that has not shown an
// authentication exchange.
//
// Only a command travelling down is decided about, and only on an activation. A
// station's confirmation is not something a controlling station authenticates,
// and refusing it would leave a control centre waiting for the answer to a
// command this relay already let through.
//
// The refusal is **hard**: it is about a command, and a command forwarded so that
// the missing authentication could be written down is a moved actuator.
func (se *session) decideAuthentication(frame *wire.Frame, fromClient bool, now time.Time) (string, bool) {
	t := se.t
	a := frame.ASDU
	if a == nil {
		return "", true
	}
	// The exchange is recorded whether or not this listener requires it, and the
	// counter is the point: an estate decides whether to turn `require` on by
	// finding out which of its associations are already authenticating, and a
	// counter that only moved once the requirement was in force would be no help
	// at all in making that decision.
	//
	// The exchange itself is never held to the rule either: it establishes the
	// state that a subsequent command requires.
	if a.Type.Secure() {
		if se.authed.observe(a, fromClient, now) {
			t.host.Counters().IEC104Authentications.Add(1)
		}
		return "", true
	}
	if !t.auth.on() {
		return "", true
	}
	// Only a command travelling down, and only on an activation.
	//
	// `!fromClient` is belt on braces: decide() refuses a station sending an
	// activation as `station_command` before this runs, in both the enforcing and
	// the shadowing branch, so no station frame with a commanding cause reaches
	// here. It stays because this function should not depend on the ordering of a
	// check thirty lines away to be correct about whose frames it holds.
	if !fromClient || !a.Cause.Commanding() || (!a.Type.Command() && !a.Type.System()) {
		return "", true
	}
	ok, at := se.authed.fresh(now.Add(-t.auth.window))
	if ok {
		return "", true
	}
	detail := a.Type.String() + ": no IEC 60870-5-7 authentication on this association"
	if !at.IsZero() {
		detail = fmt.Sprintf("%s: last authenticated %s ago, outside the %s window",
			a.Type, now.Sub(at).Round(time.Second), t.auth.window)
	}
	t.deny(se.ip, "iec104_unauthenticated", detail)
	return "iec104_unauthenticated", false
}
