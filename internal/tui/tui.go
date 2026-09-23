package tui

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

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
		buf := make([]byte, 16)
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
		case k, ok := <-keys:
			if !ok {
				return nil
			}
			quit, refresh := handleKey(&st, k, &data, act)
			if quit {
				return nil
			}
			if refresh {
				data = fetch()
				ticker.Reset(st.Refresh)
			}
			draw()
		}
	}
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
