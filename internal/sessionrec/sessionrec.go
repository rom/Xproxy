// Package sessionrec writes a recording of one proxied session to a
// file, under a policy an operator configured.
//
// Four kinds record: the ssh bastion, the ftp relay, telnet and the
// graphical gates. What they have in common is all of this -- a
// directory the proxy does not create, a file per session named after
// the person, a byte bound so one session cannot fill a disk, and a
// count of files to keep -- and what differs is only what a session is
// made of. So the policy, the file and the bounds live here, and each
// kind decides what to feed in and what to log at the end.
//
// The file is asciicast v2 (see internal/asciicast) for a session made
// of text, which a terminal player replays directly. A graphical
// session records its protocol stream instead, through the same bounds,
// with the stream's own framing inside the event data.
package sessionrec

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/asciicast"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/textsafe"
)

// Policy is a recording section and the files it has written. One
// exists per listener, and per principal that has a section of its own,
// so the count it prunes to is the count that section asked for.
type Policy struct {
	cfg *config.SessionRecording
	// mu guards files, which is the list this policy wrote and is
	// therefore the list it may remove from. Files another process put
	// in the directory are not this one's to delete.
	mu    sync.Mutex
	files []string
}

// New returns a policy, or nil when the section is absent or turned
// off. Every method is safe on a nil policy, so a caller that records
// nothing writes no conditionals.
func New(c *config.SessionRecording) *Policy {
	if c == nil || (c.Enabled != nil && !*c.Enabled) {
		return nil
	}
	return &Policy{cfg: c}
}

// Enabled reports whether anything is recorded at all.
func (p *Policy) Enabled() bool { return p != nil }

// Config exposes the section, for the few decisions only the kind can
// make -- whether a command without a terminal is recorded, say.
func (p *Policy) Config() *config.SessionRecording {
	if p == nil {
		return nil
	}
	return p.cfg
}

// Header is what a file says about itself before the first event.
type Header struct {
	// Width and Height are the terminal size for a text session. A
	// player that does not know the geometry draws the session at the
	// wrong width and every line that wrapped wraps somewhere else. A
	// graphical session puts its framebuffer size here.
	Width, Height int
	// Title names the session, so a file found on its own says whose
	// it is.
	Title string
	// Command is the one command an exec session ran, where there was
	// one.
	Command string
	// Env carries TERM, and for a graphical session the protocol and
	// variant, so a player knows what the event data holds.
	Env map[string]string
	// Tag goes in the file name after the timestamp. It comes from
	// values the client chooses, so Open reduces it to what is safe in
	// a file name rather than trusting it: a login of "../../etc/x"
	// must not decide where the proxy writes.
	Tag string
	// Ext is the file extension, ".cast" when empty.
	Ext string
}

// maxNameAttempts bounds the search for a free name. Reaching it means
// a thousand sessions for one user inside one millisecond, which is not
// a collision any more but a directory that needs looking at.
const maxNameAttempts = 1000

// Recording is one session's file.
type Recording struct {
	p    *Policy
	name string

	mu        sync.Mutex
	f         *os.File
	bw        *bufio.Writer
	w         *asciicast.Writer
	written   int64
	truncated bool
	err       error
}

// Open creates the file and writes the header. It returns nil, nil when
// the policy records nothing, so the caller need not branch.
func (p *Policy) Open(h Header) (*Recording, error) {
	if p == nil {
		return nil, nil
	}
	ext := h.Ext
	if ext == "" {
		ext = ".cast"
	}
	// The name carries the time to the millisecond and the person, which
	// is not unique: two sessions for one user inside the same
	// millisecond is ordinary on a busy bastion, and O_EXCL would then
	// fail and leave the second session unrecorded. A suffix is added
	// for as long as the name is taken, so a collision costs a retry
	// rather than a recording.
	base := filepath.Join(p.cfg.Directory, fmt.Sprintf("%s-%s-%s",
		p.cfg.FilePrefix, time.Now().UTC().Format("20060102-150405.000"), FileTag(h.Tag)))
	var name string
	var f *os.File
	var err error
	for i := 0; ; i++ {
		name = base + ext
		if i > 0 {
			name = fmt.Sprintf("%s-%d%s", base, i, ext)
		}
		// The file holds everything the session showed, so it is the
		// proxy user's alone from the moment it exists.
		f, err = os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // operator configured directory, proxy generated name
		if err == nil {
			break
		}
		if !errors.Is(err, fs.ErrExist) || i == maxNameAttempts {
			return nil, err
		}
	}
	bw := bufio.NewWriterSize(f, 32<<10)
	w, err := asciicast.NewWriter(bw, asciicast.Header{
		Width: h.Width, Height: h.Height,
		Title:   h.Title,
		Command: h.Command,
		Env:     h.Env,
	})
	if err != nil {
		_ = f.Close()
		_ = os.Remove(name)
		return nil, err
	}
	rec := &Recording{p: p, name: name, f: f, bw: bw, w: w}
	p.mu.Lock()
	p.files = append(p.files, name)
	p.pruneLocked()
	p.mu.Unlock()
	return rec, nil
}

// pruneLocked removes the oldest files this policy wrote, beyond the
// count it was told to keep.
func (p *Policy) pruneLocked() {
	for len(p.files) > p.cfg.MaxFiles {
		oldest := p.files[0]
		p.files = p.files[1:]
		_ = os.Remove(oldest)
	}
}

// FileTag reduces a name the client chose to what is safe in a file
// name.
func FileTag(s string) string {
	out := make([]rune, 0, 32)
	for _, r := range textsafe.Clip64(s) {
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

// Name is the file this recording writes to.
func (rec *Recording) Name() string {
	if rec == nil {
		return ""
	}
	return rec.name
}

// Out records what the session showed the person.
func (rec *Recording) Out(b []byte) { rec.event(asciicast.Output, b) }

// In records what the person sent, and is called only where the policy
// asked for it.
func (rec *Recording) In(b []byte) { rec.event(asciicast.Input, b) }

func (rec *Recording) event(kind string, b []byte) {
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
	if rec.written+int64(len(b)) > rec.p.cfg.MaxFileBytes {
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

// Mark writes a note into the timeline: a transfer that happened beside
// the control channel, a factor that was asked for, a channel that was
// refused. It is not bounded by max_file_bytes, because the proxy
// chooses these and there are few of them.
func (rec *Recording) Mark(text string) {
	if rec == nil {
		return
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.f == nil {
		return
	}
	if err := rec.w.Mark(text); err != nil {
		rec.failLocked(err)
	}
}

// Resize records a new terminal or framebuffer size.
func (rec *Recording) Resize(cols, rows int) {
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
// the close reports the truncated flag either way.
func (rec *Recording) failLocked(err error) {
	rec.truncated = true
	rec.err = err
	if rec.bw != nil {
		_ = rec.bw.Flush()
	}
}

// Result is what a finished recording has to say for the log. The kind
// writes the log line, because only it knows what to call the person
// and the target.
type Result struct {
	File      string
	Bytes     int64
	Truncated bool
	Err       error
}

// Close flushes and closes the file. The zero Result means nothing was
// recorded.
func (rec *Recording) Close() Result {
	if rec == nil {
		return Result{}
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.f == nil {
		return Result{}
	}
	_ = rec.w.Flush()
	_ = rec.bw.Flush()
	_ = rec.f.Close()
	rec.f = nil
	return Result{File: rec.name, Bytes: rec.written, Truncated: rec.truncated, Err: rec.err}
}

// Writer tees what is delivered into a recording. It writes to the real
// destination first and records what was actually written, so the file
// holds what the far side received rather than what the proxy meant to
// send.
type Writer struct {
	Dst   io.Writer
	Rec   *Recording
	Input bool
}

func (t Writer) Write(p []byte) (int, error) {
	n, err := t.Dst.Write(p)
	if n > 0 {
		if t.Input {
			t.Rec.In(p[:n])
		} else {
			t.Rec.Out(p[:n])
		}
	}
	return n, err
}
