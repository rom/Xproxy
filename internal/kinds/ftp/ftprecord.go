package ftp

import (
	"fmt"

	wire "github.com/rom/xproxy/internal/ftp"
	"github.com/rom/xproxy/internal/sessionrec"
	"github.com/rom/xproxy/internal/textsafe"
)

// An ftp session is a dialogue: commands one way, replies the other.
// That is what the recording holds, in the same asciicast format the
// bastion writes, so the same player replays it and an operator sees
// the session as the person drove it.
//
// What it does not hold is the files. A transfer leaves a mark saying
// what moved, how much of it and how it ended; the bytes themselves
// stay out, because a copy of every file that crossed the proxy is a
// second copy of the data to look after, and the recording is meant to
// answer what was done rather than to be an archive.

// preLoginEvent is a line held until there is a login to name the file
// after.
type preLoginEvent struct {
	in   bool
	data []byte
}

// maxPreLogin bounds what is held before the file exists. A session
// that never logs in writes nothing, so this is memory a client can
// make the proxy hold without ever authenticating: it is small, and
// past it the held lines are dropped with a note in the file rather
// than growing.
const maxPreLogin = 64

// hold keeps a line until the recording exists. The login exchange is
// the part of an ftp session most worth having, and it happens before
// there is a name to call the file: so it is buffered rather than lost,
// and a connection that never logs in still writes no file.
func (se *session) hold(in bool, b []byte) {
	if !se.t.recorder.Enabled() || se.rec != nil {
		return
	}
	if len(se.preLogin) >= maxPreLogin {
		se.preLoginDropped++
		return
	}
	se.preLogin = append(se.preLogin, preLoginEvent{in: in, data: append([]byte(nil), b...)})
}

// openRecording starts the file for a session, once there is a login
// to name it after, and replays what was held before it. Before the
// login there is nothing worth a file: a connection that never
// authenticates is in the access log already.
func (se *session) openRecording() {
	if se.rec != nil || !se.t.recorder.Enabled() {
		return
	}
	rec, err := se.t.recorder.Open(sessionrec.Header{
		// Eighty by twenty-four is what a terminal player assumes, and
		// an ftp dialogue has no geometry of its own.
		Width: 80, Height: 24,
		Title: fmt.Sprintf("%s@%s via %s", textsafe.Clip64(se.user), se.target, se.t.cfg.Name),
		Env:   map[string]string{"XPROXY_PROTOCOL": "ftp"},
		Tag:   se.user,
	})
	if err != nil {
		se.t.engine.Logs().Error.Warn("ftp session recording could not be opened",
			"listener", se.t.cfg.Name, "user", textsafe.Clip64(se.user), "err", err.Error())
		return
	}
	se.rec = rec
	for _, e := range se.preLogin {
		if e.in {
			rec.In(e.data)
		} else {
			rec.Out(e.data)
		}
	}
	if se.preLoginDropped > 0 {
		rec.Mark(fmt.Sprintf("xproxy: %d lines before the login were dropped at max_pre_login", se.preLoginDropped))
	}
	se.preLogin, se.preLoginDropped = nil, 0
}

// recordCommand writes what the client sent. A password is not written
// down: the recording says the command happened and keeps the secret
// out, because a recording an operator cannot safely keep is one that
// gets turned off.
func (se *session) recordCommand(c wire.Command) {
	arg := c.Arg
	if wire.Secret[c.Verb] {
		arg = "<redacted>"
	}
	line := c.Verb
	if arg != "" {
		line += " " + arg
	}
	if se.rec == nil {
		se.hold(true, []byte(line+"\r\n"))
		return
	}
	se.rec.In([]byte(line + "\r\n"))
}

// recordLine writes a reply the proxy made up itself, so a refusal the
// target never saw is still in the session as the client saw it.
func (se *session) recordLine(b []byte) {
	if se.rec == nil {
		se.hold(false, b)
		return
	}
	se.rec.Out(b)
}

// recordTransfer notes a transfer beside the dialogue: what moved,
// which way, how much and how it ended.
func (se *session) recordTransfer(verb, path string, n int64, cut string) {
	if se.rec == nil {
		return
	}
	how := "completed"
	if cut != "" {
		how = "cut: " + cut
	}
	se.rec.Mark(fmt.Sprintf("%s %s (%d bytes, %s)", verb, textsafe.Clip256(path), n, how))
}

// closeRecording writes the file out and says so in the log.
func (se *session) closeRecording() {
	res := se.rec.Close()
	if res.File == "" {
		return
	}
	t := se.t
	t.engine.Counters().FTPRecorded.Add(1)
	t.engine.Logs().Access.Info("ftp_recording", "listener", t.cfg.Name, "client_ip", se.ip.String(),
		"user", textsafe.Clip64(se.user), "target", se.target,
		"file", res.File, "bytes", res.Bytes, "truncated", res.Truncated)
	if res.Truncated {
		attrs := []any{"listener", t.cfg.Name, "file", res.File}
		if res.Err != nil {
			attrs = append(attrs, "err", res.Err.Error())
		}
		t.engine.Logs().Error.Warn("ftp recording is short of the session", attrs...)
	}
}
