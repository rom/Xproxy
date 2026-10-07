package rdp

import (
	"context"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/access"
	"github.com/rom/xproxy/internal/authorization"
	"github.com/rom/xproxy/internal/mfa"
	"github.com/rom/xproxy/internal/rdp"
	"github.com/rom/xproxy/internal/textsafe"
)

// The credential. RDP carries it in one packet, once, and that packet
// is the only place in the protocol where a person appears. So it is
// where the second factor is checked and where the credential that
// opens the desktop is substituted.

// credential decides on the client info packet: it records who is
// connecting, checks the factor where one is configured, and puts the
// gateway's own credential in place of the person's where an operator
// asked for that.
func (se *session) credential(info *rdp.ClientInfo) string {
	t := se.t
	se.user, se.domain = info.Username, info.Domain
	se.tap.User(info.Username)
	if t.mfaGuard != nil {
		if reason := se.checkFactor(info); reason != "" {
			return reason
		}
	}
	// The grant is checked here, which on this protocol is the earliest
	// there is anybody to check: the client info packet is the only place a
	// person appears, and it arrives after the desktop has been dialled. So
	// the grant is checked against the machine already reached -- a grant
	// naming another one refuses rather than moving the session -- and the
	// desktop sees a TCP connection and no credential.
	// The estate's own policy is asked first, because it is the broader
	// question: whether this person may be on this desktop at all, rather than
	// whether somebody approved a window for them today.
	if reason := se.admitByPolicy(); reason != "" {
		return reason
	}
	if reason := se.admitByGrant(); reason != "" {
		return reason
	}
	if t.upUser != "" {
		// The person proved themselves to the gateway; the desktop is
		// opened with the gateway's own credential, so the desktop's
		// password is never the person's to learn or to reuse.
		info.Username, info.Password = t.upUser, t.upPassword
		if t.upDomain != "" {
			info.Domain = t.upDomain
		}
		// A credential the gateway supplied is one the client should
		// not be asked about again.
		info.Flags |= rdp.InfoAutologon
	}
	return ""
}

// checkFactor reads the one-time code out of the password field and
// verifies it.
//
// RDP has nowhere to ask a question: there is no prompt in the
// protocol, and by the time the credential arrives the client is
// waiting for a desktop rather than for a dialogue. So the code
// travels with the password, separated by a comma -- the same
// arrangement the ftp relay uses, and one that works with every client
// because it needs nothing of the client at all. The code is taken out
// before the password goes anywhere.
func (se *session) checkFactor(info *rdp.ClientInfo) string {
	t := se.t
	pass, code := splitCode(info.Password)
	if se.user == "" {
		se.factorFailed("no_identity")
		return "mfa_no_identity"
	}
	now := time.Now()
	switch {
	case !se.wantsFactor():
		return ""
	case code == "":
		se.factorFailed("no_code")
		return "mfa_no_code"
	case t.mfaGuard.Locked(se.user, now):
		se.factorFailed("locked")
		return "mfa_locked"
	case t.mfaGuard.Verify(se.user, code, now) != nil:
		se.factorFailed("wrong_code")
		return "mfa_failed"
	}
	// The code never reaches the desktop.
	info.Password = pass
	se.identityVerified = true
	t.engine.Counters().RDPMFAOK.Add(1)
	t.engine.Logs().SecurityEvent(context.Background(), "allow", "rdp_mfa",
		"listener", t.cfg.Name, "client_ip", se.ip.String(), "user", textsafe.Clip64(se.user))
	return ""
}

func (se *session) wantsFactor() bool {
	g := se.t.mfaGuard
	if g.Enrolled(se.user) {
		return true
	}
	return se.t.v.MFA.RequireEnrolment == nil || *se.t.v.MFA.RequireEnrolment
}

func (se *session) factorFailed(why string) {
	t := se.t
	t.engine.Counters().RDPMFAFailed.Add(1)
	// One record, through the funnel. This wrote a second event of its own
	// alongside it, which alert_on_deny could not silence and which the ban
	// ladder never saw.
	t.deny(se, "rdp_mfa_failed", textsafe.Clip64(se.user)+" "+why,
		"user", textsafe.Clip64(se.user), "reason", why)
}

// splitCode takes a one-time code off the end of a password. A
// password with no comma, or with something behind the comma that is
// not a code, is a password with no code in it -- which matters,
// because a password may legitimately contain a comma.
func splitCode(arg string) (pass, code string) {
	i := strings.LastIndex(arg, ",")
	if i < 0 {
		return arg, ""
	}
	code = strings.TrimSpace(arg[i+1:])
	if code == "" || len(code) > mfa.MaxCode {
		return arg, ""
	}
	// A code is digits, or the letters and digits of a recovery code.
	for _, r := range code {
		digit := r >= '0' && r <= '9'
		letter := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		if !digit && !letter && r != '-' {
			return arg, ""
		}
	}
	return arg[:i], code
}

// admitByPolicy is the estate's authorisation policy, asked where the grant is
// asked and for the same reason: this is the earliest point on this protocol
// where there is anybody to decide about.
//
// That point is later than on the other gate kinds, and the difference is worth
// knowing: the client info packet is the only place a person appears in RDP, and
// it arrives after the desktop has been dialled. So a refusal here means the
// desktop saw a TCP connection from the gateway and no credential -- nobody
// logged in, and nothing the person sent went any further.
//
// The target is the upstream pool's name rather than the machine already
// reached, so that a rule reads the same on an rdp listener as on the others;
// the per-machine question is the access grant's, which does check the machine
// this session actually got.
func (se *session) admitByPolicy() string {
	t := se.t
	user := se.user
	// When the gateway substitutes its own credential, the desktop will not
	// authenticate the name the client supplied. Do not let that unverified
	// claim satisfy a user rule. With no substituted credential the desktop
	// still proves the original credential; successful MFA proves it here.
	if t.upUser != "" && !se.identityVerified {
		user = ""
	}
	return t.engine.Authorization().Ask(authorization.Subject{
		Listener: t.cfg.Name,
		Kind:     "rdp",
		Client:   se.ip,
		User:     user,
		Target:   t.v.Upstream,
		Action:   authorization.ActionConnect,
	}, textsafe.Clip64(se.user), t.authzGate(se))
}

// admitByGrant is the just-in-time access decision. It runs after the factor,
// so a client that cannot answer one never spends a grant, and before the
// credential goes anywhere.
func (se *session) admitByGrant() string {
	t := se.t
	if t.grants == nil {
		return ""
	}
	// The desktop is already dialled, so the only machine this session can
	// be about is the one it reached.
	adm := t.grants.Check(se.user, t.v.Upstream, []string{se.target})
	if adm.Reason == "" {
		se.grant = adm.Grant
		if se.grant != nil {
			t.grants.Use(se.grant, se.sessionID())
			se.stopAtExpiry = access.CloseAtExpiry(se.grant, func() { _ = se.client.Close() })
		}
		return ""
	}
	if t.shadowed(se.ip, adm.Reason, textsafe.Clip64(se.user)) {
		return ""
	}
	t.engine.Counters().RDPRefused.Add(1)
	t.deny(se, adm.Reason, textsafe.Clip64(se.user))
	return adm.Reason
}

// sessionID is the live table's identifier for this session, or empty when the
// table refused to register it.
func (se *session) sessionID() string {
	if se.live == nil {
		return ""
	}
	return se.live.ID
}
