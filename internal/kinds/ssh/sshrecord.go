package ssh

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/asciicast"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/textsafe"
)

// sshRecorder is a recording policy and the directory it writes to. One
// exists per listener, and per principal that has its own section, so
// the file count it prunes to is the count that section asked for.
type sshRecorder struct {
	cfg *config.SSHRecording
	// mu guards files, which is the list this recorder wrote and is
	// therefore the list it may remove from. Files another process put
	// in the directory are not this one's to delete.
	mu    sync.Mutex
	files []string
}

func newSSHRecorder(c *config.SSHRecording) *sshRecorder {
	if c == nil || (c.Enabled != nil && !*c.Enabled) {
		return nil
	}
	return &sshRecorder{cfg: c}
}

// records reports whether this kind of session is written at all.
func (r *sshRecorder) records(exec bool) bool {
	if r == nil {
		return false
	}
	if exec && r.cfg.Commands != nil && !*r.cfg.Commands {
		return false
	}
	return true
}

// sshRecording is one session's file.
type sshRecording struct {
	r    *sshRecorder
	name string

	mu        sync.Mutex
	f         *os.File
	bw        *bufio.Writer
	w         *asciicast.Writer
	written   int64
	truncated bool
	err       error
}

// open creates the file and writes the header. The header carries the
// terminal size, because a player that does not know the geometry
// draws the session at the wrong width and every line that wrapped
// wraps somewhere else.
func (r *sshRecorder) open(se *session, cols, rows int, term, command string) (*sshRecording, error) {
	if r == nil {
		return nil, nil
	}
	name := filepath.Join(r.cfg.Directory, fmt.Sprintf("%s-%s-%s.cast",
		r.cfg.FilePrefix, time.Now().UTC().Format("20060102-150405.000"), sshFileTag(se)))
	// The file holds everything the session showed, so it is the proxy
	// user's alone from the moment it exists.
	f, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // operator configured directory, proxy generated name
	if err != nil {
		return nil, err
	}
	bw := bufio.NewWriterSize(f, 32<<10)
	env := map[string]string{}
	if term != "" {
		env["TERM"] = term
	}
	w, err := asciicast.NewWriter(bw, asciicast.Header{
		Width: cols, Height: rows,
		Title:   sshRecordTitle(se),
		Command: command,
		Env:     env,
	})
	if err != nil {
		_ = f.Close()
		_ = os.Remove(name)
		return nil, err
	}
	rec := &sshRecording{r: r, name: name, f: f, bw: bw, w: w}
	r.mu.Lock()
	r.files = append(r.files, name)
	r.pruneLocked()
	r.mu.Unlock()
	return rec, nil
}

// pruneLocked removes the oldest files this recorder wrote, beyond the
// count it was told to keep.
func (r *sshRecorder) pruneLocked() {
	for len(r.files) > r.cfg.MaxFiles {
		oldest := r.files[0]
		r.files = r.files[1:]
		_ = os.Remove(oldest)
	}
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

// sshFileTag is the part of a file name that comes from the session. It
// is built from values the client chooses, so it is reduced to what is
// safe in a file name rather than trusted: a login of "../../etc/x"
// must not decide where the proxy writes.
func sshFileTag(se *session) string {
	out := make([]rune, 0, 32)
	for _, r := range textsafe.Clip64(se.user) {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
		if len(out) == 32 {
			break
		}
	}
	if len(out) == 0 {
		return "unknown"
	}
	return string(out)
}

// out records what the session printed.
func (rec *sshRecording) out(b []byte) { rec.event(asciicast.Output, b) }

// in records what was typed, and is called only where the policy asked
// for it.
func (rec *sshRecording) in(b []byte) { rec.event(asciicast.Input, b) }

func (rec *sshRecording) event(kind string, b []byte) {
	if rec == nil || len(b) == 0 {
		return
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.f == nil || rec.truncated {
		return
	}
	// The bound is on the session's bytes rather than the file's, which
	// is the number an operator can reason about: the file is somewhat
	// larger, by the escaping and the timestamps.
	if rec.written+int64(len(b)) > rec.r.cfg.MaxFileBytes {
		rec.truncated = true
		_ = rec.w.Mark("xproxy: recording stopped at max_file_bytes; the session continued")
		_ = rec.bw.Flush()
		return
	}
	rec.written += int64(len(b))
	if err := rec.w.Event(kind, b); err != nil {
		rec.failLocked(err)
	}
}

// resize records a new terminal size.
func (rec *sshRecording) resize(cols, rows int) {
	if rec == nil {
		return
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.f == nil || rec.truncated {
		return
	}
	if err := rec.w.Resized(cols, rows); err != nil {
		rec.failLocked(err)
	}
}

// failLocked gives up on a file that cannot be written, and marks it
// short. A recording that is silently missing its middle is worse than
// one that stops, because it still looks like the whole session, and
// the close writes the truncated flag to the log either way.
func (rec *sshRecording) failLocked(err error) {
	rec.truncated = true
	rec.err = err
	if rec.bw != nil {
		_ = rec.bw.Flush()
	}
}

// close flushes and closes the file, and reports the name written.
func (rec *sshRecording) close(se *session) {
	if rec == nil {
		return
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.f == nil {
		return
	}
	_ = rec.w.Flush()
	_ = rec.bw.Flush()
	_ = rec.f.Close()
	rec.f = nil
	t := se.t
	t.engine.Counters().SSHRecorded.Add(1)
	t.engine.Logs().Access.Info("ssh_recording", "listener", t.cfg.Name, "client_ip", se.ip.String(),
		"user", textsafe.Clip64(se.user), "principal", se.principal, "target", se.target,
		"file", rec.name, "bytes", rec.written, "truncated", rec.truncated)
	if rec.truncated {
		attrs := []any{"listener", t.cfg.Name, "file", rec.name}
		if rec.err != nil {
			attrs = append(attrs, "err", rec.err.Error())
		}
		t.engine.Logs().Error.Warn("ssh recording is short of the session", attrs...)
	}
}

// sshRecordWriter tees what is delivered into a recording. It writes to
// the real destination first and records what was actually written, so
// the file holds what the far side received rather than what the proxy
// meant to send.
type sshRecordWriter struct {
	dst   io.Writer
	rec   *sshRecording
	input bool
}

func (t sshRecordWriter) Write(p []byte) (int, error) {
	n, err := t.dst.Write(p)
	if n > 0 {
		if t.input {
			t.rec.in(p[:n])
		} else {
			t.rec.out(p[:n])
		}
	}
	return n, err
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
