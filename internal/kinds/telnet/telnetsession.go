package telnet

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/sessionrec"
	wire "github.com/rom/xproxy/internal/telnet"
	"github.com/rom/xproxy/internal/textsafe"
)

// The recording and the second factor, which are the two things this
// gateway adds to a protocol that has neither.

// openRecording starts the file once the target is known.
func (se *session) openRecording() {
	if !se.t.recorder.Enabled() {
		return
	}
	who := textsafe.Clip64(se.user)
	if who == "" {
		who = "anonymous"
	}
	rec, err := se.t.recorder.Open(sessionrec.Header{
		Width: se.cols, Height: se.rows,
		Title: fmt.Sprintf("%s@%s via %s", who, se.target, se.t.cfg.Name),
		Env:   map[string]string{"TERM": "vt100", "XPROXY_PROTOCOL": "telnet"},
		Tag:   who,
	})
	if err != nil {
		se.t.engine.Logs().Error.Warn("telnet session recording could not be opened",
			"listener", se.t.cfg.Name, "user", who, "err", err.Error())
		se.t.engine.Logs().SecurityEvent(context.Background(), "allow", "telnet_recording_failed",
			"listener", se.t.cfg.Name, "client_ip", se.ip.String(), "user", who)
		return
	}
	se.rec = rec
}

// recordOutput keeps what the target showed.
func (se *session) recordOutput(b []byte) { se.rec.Out(b) }

// recordInput keeps what was typed, and only where the policy asked
// for it: a telnet input stream carries every password typed into the
// target's own login, which the proxy never sees otherwise.
func (se *session) recordInput(b []byte) {
	if cfg := se.t.recorder.Config(); cfg != nil && cfg.Input {
		se.rec.In(b)
	}
}

// closeRecording writes the file out and says so in the log.
func (se *session) closeRecording() {
	res := se.rec.Close()
	if res.File == "" {
		return
	}
	t := se.t
	t.engine.Counters().TelnetRecorded.Add(1)
	t.engine.Logs().Access.Info("telnet_recording", "listener", t.cfg.Name, "client_ip", se.ip.String(),
		"user", textsafe.Clip64(se.user), "target", se.target,
		"file", res.File, "chain", res.Chain, "bytes", res.Bytes, "truncated", res.Truncated)
	if res.Truncated {
		attrs := []any{"listener", t.cfg.Name, "file", res.File}
		if res.Err != nil {
			attrs = append(attrs, "err", res.Err.Error())
		}
		t.engine.Logs().Error.Warn("telnet recording is short of the session", attrs...)
	}
}

// maxPromptLine bounds what the proxy will read while it is asking its
// own questions. A client that sends a megabyte instead of a name is
// not answering the question.
const maxPromptLine = 256

// askFactor runs the proxy's own exchange before the target is
// dialled: a login name, then a one-time code. Telnet has no
// authentication for a proxy to read, so this is a prompt written into
// the stream and an answer read back out of it.
//
// The name is the one the factor is checked against. The target's own
// login happens afterwards and is not touched: the person may well type
// a different name there, and whether the two agree is the target's
// business rather than this proxy's.
func (se *session) askFactor() string {
	t := se.t
	name, reason := se.prompt("login: ", true)
	if reason != "" {
		return reason
	}
	se.user = name
	se.tap.User(name)
	se.live.Annotate(name, "", "")
	code, reason := se.prompt(se.factorPrompt(), false)
	if reason != "" {
		return reason
	}
	now := time.Now()
	switch {
	case !se.wantsFactor():
		// No enrolment and the policy allows that.
	case t.mfaGuard.Locked(se.user, now):
		se.factorFailed("locked")
		se.say("too many attempts; try again later\r\n")
		return "mfa_locked"
	case t.mfaGuard.Verify(se.user, code, now) != nil:
		se.factorFailed("wrong_code")
		se.say("that code was not accepted\r\n")
		return "mfa_failed"
	default:
		t.engine.Counters().TelnetMFAOK.Add(1)
		t.engine.Logs().SecurityEvent(context.Background(), "allow", "telnet_mfa",
			"listener", t.cfg.Name, "client_ip", se.ip.String(), "user", textsafe.Clip64(se.user))
	}
	return ""
}

// wantsFactor reports whether this name owes a code. A name with no
// enrolment is refused where the policy requires one, because an
// optional second factor is one an attacker can decline by using an
// account that never enrolled.
func (se *session) wantsFactor() bool {
	g := se.t.mfaGuard
	if g.Enrolled(se.user) {
		return true
	}
	return se.t.t.MFA.RequireEnrolment == nil || *se.t.t.MFA.RequireEnrolment
}

func (se *session) factorPrompt() string {
	if p := se.t.t.MFA.Prompt; p != "" {
		return textsafe.Clip256(p)
	}
	return "one-time code: "
}

func (se *session) factorFailed(why string) {
	t := se.t
	t.engine.Counters().TelnetMFAFailed.Add(1)
	t.deny(se.ip, "telnet_mfa_failed", textsafe.Clip64(se.user)+" "+why)
	t.engine.Logs().SecurityEvent(context.Background(), "deny", "telnet_mfa_failed",
		"listener", t.cfg.Name, "client_ip", se.ip.String(),
		"user", textsafe.Clip64(se.user), "reason", why)
}

// say writes one of the proxy's own lines.
func (se *session) say(s string) {
	_, _ = se.client.Write(wire.EscapeData([]byte(s)))
}

// prompt asks a question and reads one line. The client is still
// speaking telnet, so the answer is parsed rather than read raw: a
// client that negotiates while it answers would otherwise have its
// negotiation read as part of the name.
//
// echo says whether what is typed is sent back. A code is not echoed,
// for the same reason a password is not.
func (se *session) prompt(question string, echo bool) (string, string) {
	t := se.t
	if !echo {
		// The proxy takes over echoing for this line and does none,
		// which is what keeps the code off the screen. It goes before
		// the question, not after: a client that is still echoing when
		// the first characters are typed has already shown them.
		_, _ = se.client.Write(wire.Negotiation(wire.WILL, wire.OptEcho))
	}
	se.say(question)
	deadline := time.Now().Add(promptTimeout(t))
	_ = se.client.SetReadDeadline(deadline)
	defer func() { _ = se.client.SetReadDeadline(time.Time{}) }()

	if se.asked == nil {
		se.asked = newAsked(se.client, t.t.MaxSubnegotiation)
	}
	r := se.asked
	var line []byte
	finish := func() (string, string) {
		se.say("\r\n")
		if !echo {
			_, _ = se.client.Write(wire.Negotiation(wire.WONT, wire.OptEcho))
		}
		return strings.TrimSpace(string(line)), ""
	}
	malformed := func(why string) (string, string) {
		t.engine.Counters().TelnetRefused.Add(1)
		t.deny(se.ip, "telnet_prompt", why)
		return "", "prompt_malformed"
	}
	for {
		// What arrived and was not consumed by the last question is this
		// question's first input.
		for len(r.pending) > 0 {
			c := r.pending[0]
			r.pending = r.pending[1:]
			switch c {
			case '\r':
				if len(line) > 0 {
					// The terminator is CR LF on the wire, so the LF that
					// comes with it belongs to this line and not to the
					// next question.
					if len(r.pending) > 0 && r.pending[0] == '\n' {
						r.pending = r.pending[1:]
					}
					return finish()
				}
			case '\n':
				return finish()
			case 0x7f, 0x08: // backspace
				if len(line) > 0 {
					line = line[:len(line)-1]
					if echo {
						se.say("\b \b")
					}
				}
			default:
				if len(line) >= maxPromptLine {
					return malformed(fmt.Sprintf("telnet: answer longer than %d bytes", maxPromptLine))
				}
				if c >= 0x20 {
					line = append(line, c)
					if echo {
						se.say(string(rune(c)))
					}
				}
			}
		}
		// A read that came with an error still had its data fed and drained
		// above, so the error is acted on only once there is nothing left to
		// read from: a client that wrote its last line and hung up has
		// written a line.
		if r.err != nil {
			return "", "prompt_closed"
		}
		n, err := r.br.Read(r.buf)
		if n > 0 {
			ferr := r.p.Feed(r.buf[:n], func(e wire.Event) error {
				switch e.Kind {
				case wire.Data:
					// Bounded without a bound of its own: pending is
					// drained before the next read, so it never holds
					// more than one read's worth, and what a line may
					// grow to is maxPromptLine's business.
					r.pending = append(r.pending, e.Data...)
				case wire.Negotiate:
					// The proxy is the only thing here so far, and it
					// agrees to nothing while it is asking.
					if ref, ok := wire.Refusal(e.Cmd, e.Opt); ok {
						_, _ = se.client.Write(ref)
					}
				}
				return nil
			})
			if ferr != nil {
				return malformed(ferr.Error())
			}
		}
		r.err = err
	}
}

// asked reads the answers to the proxy's own questions. One per session, not one
// per question: a payload is pasted or piped in a single write, and a reader that
// threw away everything after the first terminator would collect the first line of
// it and lose every line after -- which is the part worth having on a fabricated
// device, and is a mangled name and code on a real one.
type asked struct {
	p  *wire.Parser
	br *bufio.Reader
	// buf is where a read lands; pending is the data the parser has decoded
	// and no question has consumed yet.
	buf     []byte
	pending []byte
	// err is what the last read said, acted on once pending is empty.
	err error
}

func newAsked(c net.Conn, maxSubnegotiation int) *asked {
	return &asked{
		p:   wire.NewParser(maxSubnegotiation),
		br:  bufio.NewReaderSize(c, 1024),
		buf: make([]byte, 256),
	}
}

// promptTimeout is how long the proxy waits for its own questions to
// be answered. It is the idle timeout, which is the number an operator
// already set for how long a silent session is kept.
func promptTimeout(t *server) time.Duration {
	if t.t.IdleTimeout > 0 {
		return t.t.IdleTimeout.D()
	}
	return 5 * time.Minute
}
