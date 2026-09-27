package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/rom/xproxy/internal/asciicast"
	"github.com/rom/xproxy/internal/keysource"
	"github.com/rom/xproxy/internal/recenc"
	"github.com/rom/xproxy/internal/replay"
	"github.com/rom/xproxy/internal/termsafe"
	"github.com/rom/xproxy/internal/textsafe"
)

// Reading a recorded session back.
//
// A recording is the bytes the session showed, and a terminal is an
// interpreter of exactly those bytes. Handing one to a player that
// writes them straight out is running a program somebody else wrote on
// the reviewer's terminal: it can set their clipboard (OSC 52), retitle
// their window, or -- with a device report -- make the terminal write on
// its own input, which in a shell is a command line.
//
// So the tool that reads a recording filters it. The file itself stays
// exactly as it was written, because a record an operator cannot trust
// is not a record.

// sessionUsage is one line, so the error path and the help agree.
const sessionUsage = "usage: xproxyctl session list [-key REF] DIR | show [-safe] [-input] [-key REF] FILE | " +
	"play [-speed N] [-plain] [-key REF] FILE"

func sessionCmd(args []string, raw, out, errOut io.Writer, asJSON bool) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(errOut, sessionUsage)
		return 2
	}
	switch args[0] {
	case "list":
		return sessionList(args[1:], out, errOut, asJSON)
	case "show":
		return sessionShow(args[1:], raw, errOut)
	case "play":
		return sessionPlay(args[1:], raw, errOut)
	}
	_, _ = fmt.Fprintln(errOut, sessionUsage)
	return 2
}

// recording is what the listing shows about one file.
type recording struct {
	File    string    `json:"file"`
	Bytes   int64     `json:"bytes"`
	Started time.Time `json:"started"`
	Title   string    `json:"title,omitempty"`
	Width   int       `json:"width,omitempty"`
	Height  int       `json:"height,omitempty"`
	Error   string    `json:"error,omitempty"`
	// Encrypted says the file on the disk is ciphertext, whether or not
	// this listing had the key to look inside it.
	Encrypted bool `json:"encrypted,omitempty"`
}

// recordingKey resolves a -key reference the same way xproxy-replay does:
// a path or env:NAME, and a vault reference says what to do instead, since
// this command holds no vault configuration.
func recordingKey(ref string) ([]byte, error) {
	if ref == "" {
		return nil, nil
	}
	r, err := keysource.Parse(ref)
	if err != nil {
		return nil, err
	}
	if r.Scheme == keysource.SchemeVault {
		return nil, fmt.Errorf("-key %s: this command reads no vault; fetch the key and pass it as a file or in the environment", ref)
	}
	return keysource.New(nil, 0, nil).Bytes(ref)
}

func sessionList(args []string, out, errOut io.Writer, asJSON bool) int {
	fs := flag.NewFlagSet("session list", flag.ContinueOnError)
	fs.SetOutput(errOut)
	keyRef := fs.String("key", "", "the key encrypted recordings were written under, as a path or env:NAME")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprintln(errOut, sessionUsage)
		return 2
	}
	dir := fs.Arg(0)
	key, err := recordingKey(*keyRef)
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	// Both kinds live in one directory: a listener that had encryption
	// turned on keeps the recordings it wrote before, and a listing that
	// showed only one kind would be a listing somebody trusted.
	names, err := filepath.Glob(filepath.Join(dir, "*.cast"))
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	enc, err := filepath.Glob(filepath.Join(dir, "*.cast"+recenc.Ext))
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	names = append(names, enc...)
	sort.Strings(names)
	list := make([]recording, 0, len(names))
	for _, name := range names {
		r := recording{File: filepath.Base(name)}
		if st, err := os.Stat(name); err == nil {
			r.Bytes = st.Size()
		}
		func() {
			f, err := os.Open(name) //nolint:gosec // the path is the directory an operator named
			if err != nil {
				r.Error = err.Error()
				return
			}
			defer func() { _ = f.Close() }()
			// What the file is comes from its first octets rather than its
			// name, so a recording somebody renamed while archiving it is
			// still read as what it is.
			br := bufio.NewReader(f)
			if head, err := br.Peek(len(recenc.Magic)); err == nil {
				r.Encrypted = recenc.Looks(head)
			}
			src, err := replay.Plaintext(br, key)
			if errors.Is(err, replay.ErrEncrypted) {
				// Not an error in the file: a file this listing cannot read
				// without a key. Saying which it is keeps "encrypted" from
				// looking like "corrupt".
				return
			}
			if err != nil {
				r.Error = err.Error()
				return
			}
			rd, err := asciicast.NewReader(src)
			if err != nil {
				r.Error = err.Error()
				return
			}
			// The title came from the session: a desktop's name, a login,
			// a target. It is printed, so it is filtered -- and filtered
			// before it is clipped, because clipping turns an escape into
			// a question mark and leaves the rest of the sequence behind
			// as text nobody asked to read.
			r.Title = textsafe.Clip256(termsafe.Filtered(rd.Header.Title, termsafe.Plain))
			r.Width, r.Height = rd.Header.Width, rd.Header.Height
			if rd.Header.Timestamp > 0 {
				r.Started = time.Unix(rd.Header.Timestamp, 0).UTC()
			}
		}()
		list = append(list, r)
	}
	if asJSON {
		return printJSON(out, list)
	}
	if len(list) == 0 {
		_, _ = fmt.Fprintln(out, "no recordings in", args[0])
		return 0
	}
	for _, r := range list {
		if r.Error != "" {
			_, _ = fmt.Fprintf(out, "%s\t%d bytes\tunreadable: %s\n", r.File, r.Bytes, r.Error)
			continue
		}
		if r.Encrypted && r.Title == "" && r.Width == 0 {
			_, _ = fmt.Fprintf(out, "%s\t%d bytes\tencrypted: pass -key to read it\n", r.File, r.Bytes)
			continue
		}
		when := "unknown"
		if !r.Started.IsZero() {
			when = r.Started.Format(time.RFC3339)
		}
		_, _ = fmt.Fprintf(out, "%s\t%d bytes\t%s\t%dx%d\t%s\n", r.File, r.Bytes, when, r.Width, r.Height, r.Title)
	}
	return 0
}

// sessionShow prints what the session showed, with no timing.
func sessionShow(args []string, raw, errOut io.Writer) int {
	fs := flag.NewFlagSet("session show", flag.ContinueOnError)
	fs.SetOutput(errOut)
	safe := fs.Bool("safe", false, "keep the colours and cursor movement; encode the sequences that reach outside the window")
	input := fs.Bool("input", false, "include what was typed, where the recording holds it")
	keyRef := fs.String("key", "", "the key an encrypted recording was written under, as a path or env:NAME")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprintln(errOut, sessionUsage)
		return 2
	}
	mode := termsafe.Plain
	if *safe {
		mode = termsafe.Safe
	}
	return show(fs.Arg(0), *keyRef, raw, errOut, mode, *input, 0)
}

// sessionPlay replays with the timing the session had.
func sessionPlay(args []string, raw, errOut io.Writer) int {
	fs := flag.NewFlagSet("session play", flag.ContinueOnError)
	fs.SetOutput(errOut)
	speed := fs.Float64("speed", 1, "multiply the recorded timing")
	plain := fs.Bool("plain", false, "drop every escape sequence rather than keeping the ones that draw")
	keyRef := fs.String("key", "", "the key an encrypted recording was written under, as a path or env:NAME")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		_, _ = fmt.Fprintln(errOut, sessionUsage)
		return 2
	}
	if *speed <= 0 {
		_, _ = fmt.Fprintln(errOut, "session play: -speed must be positive")
		return 2
	}
	mode := termsafe.Safe
	if *plain {
		mode = termsafe.Plain
	}
	return show(fs.Arg(0), *keyRef, raw, errOut, mode, false, *speed)
}

// show reads a recording and writes it through the filter. speed of zero
// is no waiting, which is what the show command does.
func show(name, keyRef string, raw, errOut io.Writer, mode termsafe.Mode, withInput bool, speed float64) int {
	key, err := recordingKey(keyRef)
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	f, err := os.Open(name) //nolint:gosec // the recording an operator asked to read is the argument
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	defer func() { _ = f.Close() }()
	src, err := replay.Plaintext(f, key)
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "error:", err)
		if errors.Is(err, replay.ErrEncrypted) {
			_, _ = fmt.Fprintln(errOut, "pass -key with the reference the recording section named")
		}
		return 1
	}
	rd, err := asciicast.NewReader(src)
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	// A graphical session's recording is a protocol stream, not text.
	// Writing it to a terminal would be bytes on somebody's screen and
	// nothing they could read, so it is refused here and the program that
	// does decode it is named.
	if proto := rd.Header.Env["XPROXY_PROTOCOL"]; proto == "rfb" || proto == "rdp" {
		_, _ = fmt.Fprintf(errOut, "%s holds a %s stream, which a terminal cannot show: use xproxy-replay\n", name, proto)
		return 1
	}
	// The filter writes to the terminal directly rather than through the
	// tool's own control-character stripper: it is the stronger policy of
	// the two, and in Safe mode it has to be able to emit the sequences
	// that draw.
	w := termsafe.New(raw, mode)
	var last time.Duration
	for {
		ev, err := rd.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			_ = w.Flush()
			_, _ = fmt.Fprintln(errOut, "error:", err)
			return 1
		}
		switch ev.Kind {
		case asciicast.Output:
		case asciicast.Input:
			if !withInput {
				continue
			}
		case asciicast.Marker:
			// A note the recorder added, not the session: it is this
			// project's own text, and it is still filtered, because a
			// marker can carry a name a peer chose.
			_, _ = fmt.Fprintf(w, "\n-- %s --\n", textsafe.Clip256(termsafe.Filtered(ev.Data, termsafe.Plain)))
			continue
		default:
			continue
		}
		if speed > 0 && ev.At > last {
			wait := time.Duration(float64(ev.At-last) / speed)
			// A recording of a session somebody left open overnight has
			// gaps of hours in it. Waiting them out is not a replay.
			if wait > 2*time.Second {
				wait = 2 * time.Second
			}
			time.Sleep(wait)
		}
		last = ev.At
		if _, err := w.Write([]byte(ev.Data)); err != nil {
			_, _ = fmt.Fprintln(errOut, "error:", err)
			return 1
		}
	}
	if err := w.Flush(); err != nil {
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	return 0
}
