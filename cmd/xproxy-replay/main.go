// Command xproxy-replay reads a session recording and shows it.
//
// The gateways record three shapes of session into one container: a
// terminal, an RFB stream and an RDP stream. A terminal recording is
// replayable by anything that writes bytes to a terminal -- which is
// also how a recording attacks the reviewer, so xproxyctl session play
// filters it -- and the two graphical ones are protocol streams that no
// terminal can show at all. This program is the other half of that
// promise: it decodes what the gateway deliberately did not, and it says
// what it could not decode instead of drawing something nobody sent.
//
//	xproxy-replay session.cast                    # a terminal session, replayed
//	xproxy-replay -summary session.rfb.cast       # what the stream did
//	xproxy-replay -html out.html s.rfb.cast       # a page that plays it
//	xproxy-replay -png frames/ s.rfb.cast         # one PNG per update
//	xproxy-replay -at 12s -png . s.rfb.cast       # the screen at 12 seconds
//
// It opens no sockets, runs nothing and writes only where it is told.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/rom/xproxy/internal/asciicast"
	"github.com/rom/xproxy/internal/replay"
	"github.com/rom/xproxy/internal/termsafe"
	"github.com/rom/xproxy/internal/textsafe"
	"github.com/rom/xproxy/internal/version"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("xproxy-replay", flag.ContinueOnError)
	fs.SetOutput(errOut)
	summary := fs.Bool("summary", false, "print what the stream did rather than replaying it")
	pngDir := fs.String("png", "", "write one PNG per update into this directory (it must exist)")
	page := fs.String("html", "", "write a self-contained page that plays the session")
	at := fs.Duration("at", 0, "with -png, write only the screen as it was at this point")
	every := fs.Int("every", 1, "keep one frame in this many updates")
	maxFrames := fs.Int("max-frames", replay.MaxFrames, "stop after this many frames")
	speed := fs.Float64("speed", 1, "multiply the recorded timing when replaying a terminal")
	input := fs.Bool("input", false, "include what the client sent, where the recording holds it")
	plain := fs.Bool("plain", false, "drop every escape sequence rather than keeping the ones that draw")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		_, _ = fmt.Fprintln(out, "xproxy-replay", version.String())
		return 0
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprintln(errOut, "usage: xproxy-replay [-summary] [-html FILE] [-png DIR] [-at D] [-input] FILE")
		return 2
	}
	rec, err := replay.Open(fs.Arg(0))
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	defer func() { _ = rec.Close() }()

	switch {
	case *pngDir != "" || *page != "":
		return render(rec, *pngDir, *page, *at, *every, *maxFrames, out, errOut)
	case *summary:
		return describe(rec, out, errOut)
	case rec.Kind == replay.KindTerminal:
		return terminal(rec, *speed, *input, *plain, out, errOut)
	default:
		// A graphical recording written to a terminal would be protocol
		// bytes on somebody's screen. The summary is what there is to
		// say without a decoder's output going somewhere.
		_, _ = fmt.Fprintf(errOut, "%s holds a %s stream: use -html, -png or -summary\n", rec.Path, rec.Kind)
		return describe(rec, out, errOut)
	}
}

// terminal replays a session of text through the escape-sequence filter,
// which is the same policy xproxyctl session play applies: a recording
// carries whatever the far end sent, and handing that to the reviewer's
// terminal is the one way reading a recording can hurt.
func terminal(rec *replay.Recording, speed float64, withInput, plain bool, out, errOut io.Writer) int {
	mode := termsafe.Safe
	if plain {
		mode = termsafe.Plain
	}
	w := termsafe.New(out, mode)
	var last time.Duration
	err := rec.Each(func(ev replay.Event) error {
		switch ev.Kind {
		case asciicast.Output:
		case asciicast.Input:
			if !withInput {
				return nil
			}
		case asciicast.Marker:
			_, _ = fmt.Fprintf(w, "\n-- %s --\n", textsafe.Clip256(termsafe.Filtered(string(ev.Data), termsafe.Plain)))
			return nil
		default:
			return nil
		}
		if speed > 0 && ev.At > last {
			wait := time.Duration(float64(ev.At-last) / speed)
			if wait > 2*time.Second {
				wait = 2 * time.Second
			}
			time.Sleep(wait)
		}
		last = ev.At
		_, err := w.Write(ev.Data)
		return err
	})
	if err != nil {
		_ = w.Flush()
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	if err := w.Flush(); err != nil {
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	return 0
}

// describe prints the timeline: what the stream carried, in what
// encodings, and every mark the recorder left in it.
func describe(rec *replay.Recording, out, errOut io.Writer) int {
	bw := bufio.NewWriter(out)
	defer func() { _ = bw.Flush() }()
	var (
		events, in, outBytes int
		span                 time.Duration
		fb                   *replay.Framebuffer
		dec                  *replay.Decoder
		notes                []string
	)
	if rec.Kind == replay.KindRFB {
		pf, ok := rec.PixelFormat()
		if !ok {
			notes = append(notes, "the recording carries no pixel format; reading it as 32-bit true colour")
		}
		var err error
		fb, err = replay.NewFramebuffer(rec.Header.Width, rec.Header.Height, pf)
		if err != nil {
			_, _ = fmt.Fprintln(errOut, "error:", err)
			return 1
		}
		dec = replay.NewDecoder(fb)
	}
	err := rec.Each(func(ev replay.Event) error {
		events++
		span = ev.At
		switch ev.Kind {
		case asciicast.Marker:
			notes = append(notes, fmt.Sprintf("%8s  %s", ev.At.Round(time.Millisecond), textsafe.Clip256(termsafe.Filtered(string(ev.Data), termsafe.Plain))))
		case asciicast.Input:
			in += len(ev.Data)
		case asciicast.Output:
			outBytes += len(ev.Data)
			if dec == nil {
				return nil
			}
			ups, err := dec.Feed(ev.Data)
			if err != nil {
				notes = append(notes, fmt.Sprintf("%8s  stream stopped being readable: %v", ev.At.Round(time.Millisecond), err))
				dec = nil
				return nil
			}
			for _, u := range ups {
				for _, r := range u.Rects {
					_, _ = fmt.Fprintf(bw, "%8s  %4d,%-4d %4dx%-4d %-12s %6d bytes%s\n",
						ev.At.Round(time.Millisecond), r.X, r.Y, r.W, r.H,
						replay.EncodingName(r.Encoding), r.Bytes, decodedNote(r.Decoded))
				}
			}
		}
		return nil
	})
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	_, _ = fmt.Fprintln(bw, rec.Describe(events, span))
	_, _ = fmt.Fprintf(bw, "server-to-client %d bytes, client-to-server %d bytes\n", outBytes, in)
	if fb != nil {
		w, h := fb.Size()
		_, _ = fmt.Fprintf(bw, "framebuffer %dx%d, %d updates", w, h, fb.Updates)
		for name, n := range fb.Rects {
			_, _ = fmt.Fprintf(bw, ", %s x%d", name, n)
		}
		_, _ = fmt.Fprintln(bw)
		if fb.Undecoded > 0 {
			_, _ = fmt.Fprintf(bw, "%d rectangles were not decoded, so the picture is incomplete\n", fb.Undecoded)
		}
		if dec != nil && dec.Pending() > 0 {
			_, _ = fmt.Fprintf(bw, "%d bytes at the end are a message the recording cuts off\n", dec.Pending())
		}
		if fb.Cut != "" {
			_, _ = fmt.Fprintf(bw, "the last clipboard the desktop sent: %q\n", textsafe.Clip256(fb.Cut))
		}
	}
	for _, n := range notes {
		_, _ = fmt.Fprintln(bw, n)
	}
	return 0
}

func decodedNote(ok bool) string {
	if ok {
		return ""
	}
	return "  (not decoded)"
}

// render decodes the stream into frames and writes them where asked.
func render(rec *replay.Recording, pngDir, page string, at time.Duration, every, maxFrames int, out, errOut io.Writer) int {
	if rec.Kind != replay.KindRFB {
		_, _ = fmt.Fprintf(errOut, "error: %s holds a %s stream, whose pixels this player does not decode; use -summary\n", rec.Path, rec.Kind)
		return 1
	}
	pf, ok := rec.PixelFormat()
	fb, err := replay.NewFramebuffer(rec.Header.Width, rec.Header.Height, pf)
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	if !ok {
		_, _ = fmt.Fprintln(errOut, "note: the recording carries no pixel format; reading it as 32-bit true colour")
	}
	dec := replay.NewDecoder(fb)
	frames := &replay.FrameSet{Max: maxFrames, Every: every}
	var notes []string
	stopped := false
	err = rec.Each(func(ev replay.Event) error {
		switch ev.Kind {
		case asciicast.Marker:
			notes = append(notes, fmt.Sprintf("%s  %s", ev.At.Round(time.Millisecond), textsafe.Clip256(termsafe.Filtered(string(ev.Data), termsafe.Plain))))
		case asciicast.Output:
			if stopped {
				return nil
			}
			ups, ferr := dec.Feed(ev.Data)
			if ferr != nil {
				notes = append(notes, fmt.Sprintf("%s  stream stopped being readable: %v", ev.At.Round(time.Millisecond), ferr))
				stopped = true
				return nil
			}
			for range ups {
				if at > 0 {
					// One frame is asked for: keep overwriting until the
					// moment passes, so the last one kept is the screen
					// as it was then.
					if ev.At > at {
						stopped = true
						return nil
					}
					frames.Frames = nil
					frames.Max = 1
				}
				if aerr := frames.Add(ev.At, fb, ""); aerr != nil {
					return aerr
				}
			}
		}
		return nil
	})
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	if fb.Undecoded > 0 {
		notes = append(notes, fmt.Sprintf("%d rectangles were in an encoding this player does not decode; the picture is incomplete", fb.Undecoded))
	}
	if len(frames.Frames) == 0 {
		_, _ = fmt.Fprintln(errOut, "error: the recording holds no framebuffer update this player could decode")
		return 1
	}
	if pngDir != "" {
		names, werr := frames.WritePNGs(pngDir)
		if werr != nil {
			_, _ = fmt.Fprintln(errOut, "error:", werr)
			return 1
		}
		_, _ = fmt.Fprintf(out, "%d frames written to %s\n", len(names), pngDir)
	}
	if page != "" {
		f, cerr := os.Create(page) //nolint:gosec // the file an operator asked to write is the argument
		if cerr != nil {
			_, _ = fmt.Fprintln(errOut, "error:", cerr)
			return 1
		}
		if werr := frames.WritePage(f, rec.Describe(0, 0), notes); werr != nil {
			_ = f.Close()
			_, _ = fmt.Fprintln(errOut, "error:", werr)
			return 1
		}
		if cerr := f.Close(); cerr != nil {
			_, _ = fmt.Fprintln(errOut, "error:", cerr)
			return 1
		}
		_, _ = fmt.Fprintf(out, "%d frames written to %s\n", len(frames.Frames), page)
	}
	for _, n := range notes {
		_, _ = fmt.Fprintln(out, n)
	}
	return 0
}
