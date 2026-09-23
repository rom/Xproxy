package rdp

import (
	"context"
	"strings"
	"time"

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
	if t.mfaGuard != nil {
		if reason := se.checkFactor(info); reason != "" {
			return reason
		}
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
	t.deny(se.ip, "rdp_mfa_failed", textsafe.Clip64(se.user)+" "+why)
	t.engine.Logs().SecurityEvent(context.Background(), "deny", "rdp_mfa_failed",
		"listener", t.cfg.Name, "client_ip", se.ip.String(),
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
	if code == "" || len(code) > 16 {
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
