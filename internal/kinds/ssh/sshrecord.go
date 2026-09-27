package ssh

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/keysource"
	"github.com/rom/xproxy/internal/sessionrec"
	"github.com/rom/xproxy/internal/textsafe"
)

// The bastion records what a session showed, under the policy in
// internal/sessionrec. What is specific to ssh is here: which sessions
// are recorded at all, what the file is called, and what the log says
// when it closes.

// newSSHRecorder returns the listener's or a principal's policy. The
// resolver is where an integrity key comes from, and is nil in a test
// that configures none.
func newSSHRecorder(c *config.SessionRecording, secrets *keysource.Resolver) *sessionrec.Policy {
	return sessionrec.New(c, sessionrec.WithSecrets(secrets))
}

// records reports whether this kind of session is written at all. An
// exec session is one command rather than a terminal, and a section
// may leave those out.
func records(p *sessionrec.Policy, exec bool) bool {
	if !p.Enabled() {
		return false
	}
	if exec && p.Config().Commands != nil && !*p.Config().Commands {
		return false
	}
	return true
}

// open starts one session's file. The header carries the terminal size,
// because a player that does not know the geometry draws the session at
// the wrong width and every line that wrapped wraps somewhere else.
func openSSHRecording(p *sessionrec.Policy, se *session, cols, rows int, term, command string) (*sessionrec.Recording, error) {
	env := map[string]string{}
	if term != "" {
		env["TERM"] = term
	}
	return p.Open(sessionrec.Header{
		Width: cols, Height: rows,
		Title:   sshRecordTitle(se),
		Command: command,
		Env:     env,
		Tag:     se.user,
	})
}

// sshRecordTitle names the session in the header, so a file found on
// its own says whose it is.
func sshRecordTitle(se *session) string {
	who := textsafe.Clip64(se.user)
	if se.principal != "" {
		who += " (" + se.principal + ")"
	}
	return fmt.Sprintf("%s@%s via %s", who, se.target, se.t.cfg.Name)
}

// closeSSHRecording writes the file out and says so in the log.
func closeSSHRecording(rec *sessionrec.Recording, se *session) {
	res := rec.Close()
	if res.File == "" {
		return
	}
	t := se.t
	t.engine.Counters().SSHRecorded.Add(1)
	t.engine.Logs().Access.Info("ssh_recording", "listener", t.cfg.Name, "client_ip", se.ip.String(),
		"user", textsafe.Clip64(se.user), "principal", se.principal, "target", se.target,
		"file", res.File, "chain", res.Chain, "bytes", res.Bytes, "truncated", res.Truncated)
	if res.Truncated {
		attrs := []any{"listener", t.cfg.Name, "file", res.File}
		if res.Err != nil {
			attrs = append(attrs, "err", res.Err.Error())
		}
		t.engine.Logs().Error.Warn("ssh recording is short of the session", attrs...)
	}
}

// sshPTYRequest reads a pty-req payload (RFC 4254 section 6.2): the
// terminal type and the size in characters. The pixel dimensions and
// the terminal modes that follow are not this proxy's business and are
// forwarded untouched.
func sshPTYRequest(payload []byte) (term string, cols, rows int, ok bool) {
	term, rest, ok := sshString(payload)
	if !ok || len(rest) < 8 {
		return "", 0, 0, false
	}
	return term, int(binary.BigEndian.Uint32(rest)), int(binary.BigEndian.Uint32(rest[4:])), true
}

// sshWindowChange reads a window-change payload (RFC 4254 section 6.7).
func sshWindowChange(payload []byte) (cols, rows int, ok bool) {
	if len(payload) < 8 {
		return 0, 0, false
	}
	return int(binary.BigEndian.Uint32(payload)), int(binary.BigEndian.Uint32(payload[4:])), true
}

// sshRecordFailed reports a file that could not be created. Recording
// is a control an operator asked for, so failing to write one is worth
// an error rather than a silent session.
func (se *session) sshRecordFailed(err error) {
	se.t.engine.Logs().Error.Warn("ssh session recording could not be opened",
		"listener", se.t.cfg.Name, "user", textsafe.Clip64(se.user), "err", err.Error())
	se.t.engine.Logs().SecurityEvent(context.Background(), "allow", "ssh_recording_failed",
		"listener", se.t.cfg.Name, "client_ip", se.ip.String(), "user", textsafe.Clip64(se.user))
}
