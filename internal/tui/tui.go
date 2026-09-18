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
		st.View = (st.View + 1) % viewCount
	case "\x1b[Z", "\x1b[D", "h":
		st.View = (st.View + viewCount - 1) % viewCount
	case "1", "2", "3", "4", "5", "6":
		st.View = View(s[0] - '1')
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
		if st.View == ViewBans && st.Selected < len(d.Bans)-1 {
			st.Selected++
		}
	case "k", "\x1b[A":
		if st.View == ViewBans && st.Selected > 0 {
			st.Selected--
		}
	case "u":
		if st.View == ViewBans && st.Selected < len(d.Bans) {
			st.Prompt = "unban " + d.Bans[st.Selected].Target + "? (y/N)"
		}
	case "b":
		if st.View == ViewBans {
			st.Prompt = "ban <address|cidr> [duration] [reason]:"
		}
	}
	return false, false
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
