package ftp

import (
	"context"
	"strings"
	"time"

	wire "github.com/rom/xproxy/internal/ftp"
	"github.com/rom/xproxy/internal/mfa"
	"github.com/rom/xproxy/internal/textsafe"
)

// A second factor on FTP has to fit a protocol that has no prompt for
// it. RFC 959 gives exactly one place a third credential belongs:
// ACCT, which a server may ask for after PASS with a 332 reply. That
// is what this uses.
//
// The proxy answers 332 itself after the target accepts the password,
// and takes the code as the argument of the ACCT that follows. A
// client that has no ACCT of its own can instead put the code after
// the password, separated by a comma -- "PASS secret,123456" -- which
// is the convention every one-time-password FTP deployment has settled
// on, because it needs nothing of the client at all.
//
// Until the factor is verified the session is not logged in: every
// command but the ones that end it or get it there is refused.

// mfaState is where a session has got to with its second factor.
type mfaState int

const (
	// mfaNotNeeded is the ordinary case: no policy, or the user is not
	// enrolled and the policy allows that.
	mfaNotNeeded mfaState = iota
	// mfaWanted means the password was accepted and the code has not
	// been given yet.
	mfaWanted
	// mfaDone means the code was verified.
	mfaDone
)

// mfaPreAuth are the commands allowed between the password and the
// code: the one that carries the code, and the ones that end or
// describe the session. Everything else waits.
var mfaPreAuth = map[string]bool{
	"ACCT": true, "QUIT": true, "NOOP": true, "FEAT": true, "HELP": true,
	"STAT": true, "SYST": true, "REIN": true,
}

// splitCode takes a code appended to the password. It returns the
// password as the target should see it and the code, which is empty
// when none was appended.
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

// wantsFactor decides what the session owes after the target accepted
// the password. A user with no enrolment is refused where the policy
// requires one, because an optional second factor is one an attacker
// can decline by using an account that never enrolled.
func (se *session) wantsFactor() bool {
	g := se.t.mfaGuard
	if g == nil {
		return false
	}
	if g.Enrolled(se.user) {
		return true
	}
	return se.t.f.MFA.RequireEnrolment == nil || *se.t.f.MFA.RequireEnrolment
}

// verifyFactor checks one code and moves the session on. It returns
// the reply to send.
func (se *session) verifyFactor(code string) []byte {
	t := se.t
	g := t.mfaGuard
	user := se.user
	if code == "" {
		return wire.Line(501, "a one-time code is required")
	}
	if g.Locked(user, time.Now()) {
		se.mfaFail("locked")
		return wire.Line(530, "too many attempts; try again later")
	}
	if err := g.Verify(user, code, time.Now()); err != nil {
		se.mfaFail(err.Error())
		return wire.Line(530, "that code was not accepted")
	}
	se.mfa = mfaDone
	t.engine.Counters().FTPMFAOK.Add(1)
	t.engine.Logs().SecurityEvent(context.Background(), "allow", "ftp_mfa",
		"listener", t.cfg.Name, "client_ip", se.ip.String(), "user", textsafe.Clip64(user))
	return wire.Line(230, "second factor accepted")
}

// factorPrompt is what the 332 says. The operator's wording is used
// where there is one, because a client shows this line to a person.
func (se *session) factorPrompt() string {
	if p := se.t.f.MFA.Prompt; p != "" {
		return textsafe.Clip256(p)
	}
	return "one-time code required: send it with ACCT, or append it to the password after a comma"
}

// mfaFail records a refused factor. It feeds the ban ladder, because a
// client working through codes is doing the same thing as one working
// through passwords.
func (se *session) mfaFail(why string) {
	t := se.t
	t.engine.Counters().FTPMFAFailed.Add(1)
	t.deny(se, "ftp_mfa_failed", textsafe.Clip64(se.user)+" "+why)
	t.engine.Logs().SecurityEvent(context.Background(), "deny", "ftp_mfa_failed",
		"listener", t.cfg.Name, "client_ip", se.ip.String(),
		"user", textsafe.Clip64(se.user), "reason", why)
}
