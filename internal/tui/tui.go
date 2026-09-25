package tui

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/term"

	"github.com/rom/xproxy/internal/mgmt"
)

// mgmtSeries is the series payload type used by the renderer.
type mgmtSeries = mgmt.SeriesResponse

// Actions the TUI can trigger.
type Actions struct {
	Ban   func(target, duration, reason string) error
	Unban func(target string) error
	// MFAUnlock lets a person who ran out of tries start again, and
	// MFARemove takes their second factor away. Enrolment is not here:
	// it hands back a secret and ten recovery codes that exist once,
	// which belongs on a page that can hold them (the GUI) or in
	// `xproxyctl mfa enrol`, not in a status line.
	MFAUnlock func(listener, user string) error
	MFARemove func(listener, user string) error
}

// Options configure Run.
type Options struct {
	Refresh time.Duration
	Color   bool
	// In and Out default to stdin and stdout.
	In  *os.File
	Out io.Writer
}

// Run takes over the terminal until the user quits. It returns the error
// that ended the session, or nil on quit.
func Run(src Source, act Actions, o Options) error {
	if o.In == nil {
		o.In = os.Stdin
	}
	if o.Out == nil {
		o.Out = os.Stdout
	}
	if o.Refresh <= 0 {
		o.Refresh = 2 * time.Second
	}
	fd := int(o.In.Fd())
	if !term.IsTerminal(fd) {
		return fmt.Errorf("stdin is not a terminal")
	}
	old, err := term.MakeRaw(fd)
	if err != nil {
		return err
	}
	defer func() { _ = term.Restore(fd, old) }()
	sty := Plain
	if o.Color {
		sty = ANSI
	}
	// Alternate screen, hide cursor.
	_, _ = io.WriteString(o.Out, "\x1b[?1049h\x1b[?25l")
	defer func() { _, _ = io.WriteString(o.Out, "\x1b[?25h\x1b[?1049l") }()

	keys := make(chan []byte, 16)
	go func() {
		// The buffer holds a paste, not a keystroke: a read returns
		// whatever the driver had ready, and an address pasted into the
		// ban prompt is longer than a handful of bytes. A read cut in
		// the middle of an escape sequence cannot be put back together
		// without a timer, so the buffer is sized to make the cut rare
		// rather than to save the memory.
		buf := make([]byte, 256)
		for {
			n, err := o.In.Read(buf)
			if err != nil {
				close(keys)
				return
			}
			b := make([]byte, n)
			copy(b, buf[:n])
			keys <- b
		}
	}()

	st := State{Refresh: o.Refresh}
	fetch := func() Data {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return src.Fetch(ctx)
	}
	data := fetch()
	draw := func() {
		st.Width, st.Height, _ = term.GetSize(fd)
		lines := Render(data, st, sty)
		var b strings.Builder
		b.WriteString("\x1b[H")
		for i, l := range lines {
			b.WriteString(l)
			b.WriteString("\x1b[K")
			if i < len(lines)-1 {
				b.WriteString("\r\n")
			}
		}
		_, _ = io.WriteString(o.Out, b.String())
	}
	draw()
	ticker := time.NewTicker(st.Refresh)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if !st.Paused {
				data = fetch()
				if st.Selected >= len(data.Bans) {
					st.Selected = max(len(data.Bans)-1, 0)
				}
				draw()
			}
		case chunk, ok := <-keys:
			if !ok {
				return nil
			}
			// One read can hold several keys, so each is applied in
			// turn. The fetch a key asks for is done once at the end:
			// a key held down under autorepeat arrives as a run of the
			// same byte, and that is one person asking to refresh, not
			// sixteen.
			refresh := false
			for _, k := range splitKeys(chunk) {
				quit, want := handleKey(&st, k, &data, act)
				if quit {
					return nil
				}
				refresh = refresh || want
			}
			if refresh {
				data = fetch()
				if st.Selected >= len(data.Bans) {
					st.Selected = max(len(data.Bans)-1, 0)
				}
				ticker.Reset(st.Refresh)
			}
			draw()
		}
	}
}

// splitKeys cuts one read from the terminal into the keys it holds.
//
// A terminal does not deliver one key per read. Bytes arrive in whatever
// grouping the driver had ready, so a person typing quickly, a key
// repeating under autorepeat and any paste all put several keys in one
// read -- and a paste is the ordinary way an address gets into the ban
// prompt. Handing the whole read to handleKey treats that grouping as a
// single key nothing is bound to, which drops every byte of it.
//
// An escape sequence is the one thing that has to stay whole: the three
// bytes of a cursor key are one key, and cutting them apart would turn
// the first into the Escape that cancels the prompt.
//
// The cut is within one read, because that is how a terminal delivers a
// key. An escape sequence split across two reads cannot be told from an
// Escape followed by typing without waiting to see what comes next, and
// that wait would delay the Escape key itself -- which is the key a
// person presses to get out.
func splitKeys(b []byte) [][]byte {
	out := make([][]byte, 0, len(b))
	for i := 0; i < len(b); {
		n := keyLen(b[i:])
		out = append(out, b[i:i+n])
		i += n
	}
	return out
}

// keyLen is the length of the key at the front of b, which is never
// empty.
func keyLen(b []byte) int {
	if b[0] != 0x1b {
		// A rune, so that a multi-byte character is one key rather than
		// a run of bytes each of which is nothing on its own.
		if r, n := utf8.DecodeRune(b); r != utf8.RuneError || n > 1 {
			return n
		}
		return 1
	}
	switch {
	case len(b) > 1 && b[1] == '[':
		// CSI: parameter and intermediate bytes up to one final byte.
		for j := 2; j < len(b); j++ {
			if b[j] >= 0x40 && b[j] <= 0x7e {
				return j + 1
			}
		}
		return len(b)
	case len(b) > 1 && b[1] == 'O':
		// SS3, which is how the cursor keys arrive from a terminal in
		// application mode.
		return min(3, len(b))
	}
	// Escape on its own.
	return 1
}

// handleKey applies one key press. It returns whether to quit and whether
// to refresh data now.
func handleKey(st *State, k []byte, d *Data, act Actions) (quit, refresh bool) {
	s := string(k)
	if st.Prompt != "" {
		switch s {
		case "\r", "\n":
			msg := st.submit(d, act)
			st.Prompt, st.Input = "", ""
			st.Message = msg
			return false, true
		case "\x1b", "\x03":
			st.Prompt, st.Input, st.Message = "", "", "cancelled"
			return false, false
		case "\x7f", "\b":
			if len(st.Input) > 0 {
				st.Input = st.Input[:len(st.Input)-1]
			}
		default:
			if len(s) == 1 && s[0] >= ' ' && s[0] < 0x7f && len(st.Input) < 200 {
				st.Input += s
			}
		}
		return false, false
	}
	st.Message = ""
	switch s {
	case "q", "\x03":
		return true, false
	case "\t", "\x1b[C", "l":
		st.show((st.View + 1) % viewCount)
	case "\x1b[Z", "\x1b[D", "h":
		st.show((st.View + viewCount - 1) % viewCount)
	case "1", "2", "3", "4", "5", "6", "7", "8", "9":
		if v := View(s[0] - '1'); v < viewCount {
			st.show(v)
		}
	case "0":
		// The tenth view, by the usual convention of a row of digits.
		if viewCount > 9 {
			st.show(9)
		}
	case "r":
		return false, true
	case "p":
		st.Paused = !st.Paused
	case "+", "=":
		st.Refresh = min(st.Refresh*2, time.Minute)
		return false, true
	case "-":
		st.Refresh = max(st.Refresh/2, 500*time.Millisecond)
		return false, true
	case "j", "\x1b[B":
		if st.Selected < rowCount(st, d)-1 {
			st.Selected++
		}
	case "k", "\x1b[A":
		if st.Selected > 0 {
			st.Selected--
		}
	case "u":
		switch {
		case st.View == ViewBans && st.Selected < len(d.Bans):
			st.Prompt = "unban " + d.Bans[st.Selected].Target + "? (y/N)"
		case st.View == ViewMFA:
			if r, ok := selectedMFA(st, d); ok {
				st.Prompt = "unlock " + r.user.User + " on " + r.listener + "? (y/N)"
			}
		}
	case "b":
		if st.View == ViewBans {
			st.Prompt = "ban <address|cidr> [duration] [reason]:"
		}
	case "x":
		if st.View == ViewMFA {
			if r, ok := selectedMFA(st, d); ok {
				st.Prompt = "remove the second factor of " + r.user.User + " on " + r.listener + "? (y/N)"
			}
		}
	}
	return false, false
}

// show moves to a view, putting the cursor back at the top. Two views
// select through lists of different things, so an index carried over
// from the other one would point at somebody unrelated.
func (st *State) show(v View) {
	if st.View != v {
		st.Selected = 0
	}
	st.View = v
}

// rowCount is how many rows the current view can select through, which
// is what bounds the cursor.
func rowCount(st *State, d *Data) int {
	switch st.View {
	case ViewBans:
		return len(d.Bans)
	case ViewMFA:
		return len(mfaRows(*d))
	default:
		return 0
	}
}

// selectedMFA is the enrolment the cursor is on, if there is one.
func selectedMFA(st *State, d *Data) (mfaRow, bool) {
	rows := mfaRows(*d)
	if st.Selected < 0 || st.Selected >= len(rows) {
		return mfaRow{}, false
	}
	return rows[st.Selected], true
}

// submit executes the active prompt.
func (st *State) submit(d *Data, act Actions) string {
	switch {
	case strings.HasPrefix(st.Prompt, "unban "):
		if strings.ToLower(strings.TrimSpace(st.Input)) != "y" {
			return "cancelled"
		}
		target := d.Bans[st.Selected].Target
		if act.Unban == nil {
			return "unban not available"
		}
		if err := act.Unban(target); err != nil {
			return "unban failed: " + err.Error()
		}
		return "unbanned " + target
	case strings.HasPrefix(st.Prompt, "unlock "):
		return st.mfaSubmit(d, act.MFAUnlock, "unlock", "unlocked")
	case strings.HasPrefix(st.Prompt, "remove the second factor "):
		return st.mfaSubmit(d, act.MFARemove, "remove", "removed the second factor of")
	case strings.HasPrefix(st.Prompt, "ban "):
		f := strings.Fields(st.Input)
		if len(f) == 0 {
			return "cancelled"
		}
		dur, reason := "1h", "tui"
		if len(f) > 1 {
			dur = f[1]
		}
		if len(f) > 2 {
			reason = strings.Join(f[2:], " ")
		}
		if act.Ban == nil {
			return "ban not available"
		}
		if err := act.Ban(f[0], dur, reason); err != nil {
			return "ban failed: " + err.Error()
		}
		return "banned " + f[0] + " for " + dur
	}
	return ""
}

// mfaSubmit answers a yes-or-no prompt about the selected enrolment.
// It resolves the row again at this point rather than remembering it
// from the key press: the view refreshes while the prompt is up, and
// acting on a stale row would name one person and change another.
func (st *State) mfaSubmit(d *Data, fn func(listener, user string) error, verb, done string) string {
	if strings.ToLower(strings.TrimSpace(st.Input)) != "y" {
		return "cancelled"
	}
	r, ok := selectedMFA(st, d)
	if !ok {
		return verb + ": nothing selected"
	}
	if fn == nil {
		return verb + " not available"
	}
	if err := fn(r.listener, r.user.User); err != nil {
		return verb + " failed: " + err.Error()
	}
	return done + " " + r.user.User + " on " + r.listener
}
