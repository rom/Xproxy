package asciicast_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/asciicast"
)

// lines splits a recording into its header and its events.
func lines(t *testing.T, b []byte) (map[string]any, [][]any) {
	t.Helper()
	parts := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	var hdr map[string]any
	if err := json.Unmarshal([]byte(parts[0]), &hdr); err != nil {
		t.Fatalf("header %q: %v", parts[0], err)
	}
	out := make([][]any, 0, len(parts)-1)
	for _, p := range parts[1:] {
		var ev []any
		if err := json.Unmarshal([]byte(p), &ev); err != nil {
			t.Fatalf("event %q: %v", p, err)
		}
		if len(ev) != 3 {
			t.Fatalf("event %q has %d fields", p, len(ev))
		}
		out = append(out, ev)
	}
	return hdr, out
}

// Every line is its own JSON value, which is what makes a recording cut
// short by a crash still playable up to where it stops.
func TestWriterFormat(t *testing.T) {
	var buf bytes.Buffer
	w, err := asciicast.NewWriter(&buf, asciicast.Header{Width: 120, Height: 40,
		Title: "alice@10.0.0.1", Command: "uptime", Env: map[string]string{"TERM": "xterm-256color"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Event(asciicast.Output, []byte("load average: 0.1\r\n")); err != nil {
		t.Fatal(err)
	}
	if err := w.Resized(80, 24); err != nil {
		t.Fatal(err)
	}
	if err := w.Event(asciicast.Input, []byte("q")); err != nil {
		t.Fatal(err)
	}
	if err := w.Mark("cut here"); err != nil {
		t.Fatal(err)
	}

	hdr, evs := lines(t, buf.Bytes())
	if hdr["version"] != float64(2) || hdr["width"] != float64(120) || hdr["height"] != float64(40) {
		t.Fatalf("header = %v", hdr)
	}
	if hdr["title"] != "alice@10.0.0.1" || hdr["command"] != "uptime" {
		t.Fatalf("header = %v", hdr)
	}
	if hdr["timestamp"] == nil {
		t.Error("no timestamp, so a player cannot say when this was")
	}
	want := []struct{ kind, data string }{
		{"o", "load average: 0.1\r\n"},
		{"r", "80x24"},
		{"i", "q"},
		{"m", "cut here"},
	}
	if len(evs) != len(want) {
		t.Fatalf("%d events, want %d", len(evs), len(want))
	}
	last := -1.0
	for i, ev := range evs {
		at, ok := ev[0].(float64)
		if !ok {
			t.Fatalf("event %d has no time", i)
		}
		if at < last {
			t.Errorf("event %d goes backwards in time", i)
		}
		last = at
		if ev[1] != want[i].kind || ev[2] != want[i].data {
			t.Errorf("event %d = %v %v, want %s %q", i, ev[1], ev[2], want[i].kind, want[i].data)
		}
	}
}

// A session can print anything, and a quote or a control character
// written raw would end the line early and make the rest of the
// recording unreadable.
func TestWriterEscapes(t *testing.T) {
	var buf bytes.Buffer
	w, err := asciicast.NewWriter(&buf, asciicast.Header{})
	if err != nil {
		t.Fatal(err)
	}
	nasty := "\"]\n[0.0, \"o\", \"forged\"]\n\x1b[31m\x00\\"
	if err := w.Event(asciicast.Output, []byte(nasty)); err != nil {
		t.Fatal(err)
	}
	_, evs := lines(t, buf.Bytes())
	if len(evs) != 1 {
		t.Fatalf("%d events, want 1: a session wrote its own event line", len(evs))
	}
	if evs[0][2] != nasty {
		t.Errorf("data = %q, want %q", evs[0][2], nasty)
	}
}

// Terminal output arrives in whatever sizes the network produced, so a
// multi-byte character is regularly split across two reads. Writing
// each half on its own would put two replacement characters in the file
// where the session had one character.
func TestWriterCarriesSplitRunes(t *testing.T) {
	var buf bytes.Buffer
	w, err := asciicast.NewWriter(&buf, asciicast.Header{})
	if err != nil {
		t.Fatal(err)
	}
	full := []byte("naïve 日本語")
	for i := 0; i < len(full); i++ {
		if err := w.Event(asciicast.Output, full[i:i+1]); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	_, evs := lines(t, buf.Bytes())
	var got strings.Builder
	for _, ev := range evs {
		s, ok := ev[2].(string)
		if !ok {
			t.Fatalf("event data is not a string: %v", ev[2])
		}
		got.WriteString(s)
	}
	if got.String() != string(full) {
		t.Errorf("reassembled %q, want %q", got.String(), string(full))
	}
	if strings.Contains(got.String(), "�") {
		t.Error("a character split across reads became replacement characters")
	}
}

// The two directions are recorded by different goroutines, and each
// carries its own partial character: a half of an output character must
// not be completed by the next byte typed.
func TestWriterCarriesPerDirection(t *testing.T) {
	var buf bytes.Buffer
	w, err := asciicast.NewWriter(&buf, asciicast.Header{})
	if err != nil {
		t.Fatal(err)
	}
	jp := []byte("日")
	if err := w.Event(asciicast.Output, jp[:1]); err != nil {
		t.Fatal(err)
	}
	if err := w.Event(asciicast.Input, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := w.Event(asciicast.Output, jp[1:]); err != nil {
		t.Fatal(err)
	}
	_, evs := lines(t, buf.Bytes())
	if len(evs) != 2 {
		t.Fatalf("%d events, want 2", len(evs))
	}
	if evs[0][1] != "i" || evs[0][2] != "x" {
		t.Errorf("first event = %v", evs[0])
	}
	if evs[1][1] != "o" || evs[1][2] != "日" {
		t.Errorf("second event = %v", evs[1])
	}
}

// Bytes that are not a character at all, and never will be, are not
// held for ever: they are written as what a text format can say about
// them.
func TestWriterFlushesInvalidBytes(t *testing.T) {
	var buf bytes.Buffer
	w, err := asciicast.NewWriter(&buf, asciicast.Header{})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Event(asciicast.Output, []byte{0xff}); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	_, evs := lines(t, buf.Bytes())
	if len(evs) != 1 || evs[0][2] != "�" {
		t.Fatalf("events = %v", evs)
	}
}

// A header with nothing filled in still says something a player can
// use, because a recording with no geometry is drawn at the wrong
// width.
func TestHeaderDefaults(t *testing.T) {
	var buf bytes.Buffer
	if _, err := asciicast.NewWriter(&buf, asciicast.Header{}); err != nil {
		t.Fatal(err)
	}
	hdr, _ := lines(t, buf.Bytes())
	if hdr["width"] != float64(80) || hdr["height"] != float64(24) {
		t.Fatalf("header = %v", hdr)
	}
}

// A resize and a marker are the two things a recording says that the session
// did not print: the geometry changed, and the recorder had something to add --
// that the session was cut at a bound, for instance. A player needs the first
// to stop clipping what follows, and whoever replays the file needs the second
// to know the recording is not the whole story.
func TestResizeAndMarkerAreTheirOwnEvents(t *testing.T) {
	var buf bytes.Buffer
	w, err := asciicast.NewWriter(&buf, asciicast.Header{Width: 80, Height: 24})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Resized(132, 43); err != nil {
		t.Fatal(err)
	}
	if err := w.Mark("xproxy: cut at the byte bound"); err != nil {
		t.Fatal(err)
	}
	// Neither a size that makes no sense nor an empty note is written: a
	// zero-column terminal is a bug in the caller, and an empty marker is
	// a line that says nothing.
	for _, c := range []struct{ cols, rows int }{{0, 24}, {80, 0}, {-1, -1}} {
		if err := w.Resized(c.cols, c.rows); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Mark(""); err != nil {
		t.Fatal(err)
	}
	_, events := lines(t, buf.Bytes())
	if len(events) != 2 {
		t.Fatalf("%d events, want 2:\n%s", len(events), buf.String())
	}
	if events[0][1] != "r" || events[0][2] != "132x43" {
		t.Errorf("resize event = %v", events[0])
	}
	if events[1][1] != "m" || events[1][2] != "xproxy: cut at the byte bound" {
		t.Errorf("marker event = %v", events[1])
	}
}

// A nil writer is what a session with no recording configured holds, and every
// path writes to it without testing first.
func TestANilWriterTakesEverything(t *testing.T) {
	var w *asciicast.Writer
	if err := w.Event(asciicast.Output, []byte("x")); err != nil {
		t.Error(err)
	}
	if err := w.Resized(80, 24); err != nil {
		t.Error(err)
	}
	if err := w.Mark("note"); err != nil {
		t.Error(err)
	}
	if err := w.Flush(); err != nil {
		t.Error(err)
	}
}

// failingWriter accepts the header and then fails, which is the disk filling up
// or the file being closed under the recorder.
type failingWriter struct {
	n     int
	after int
}

func (f *failingWriter) Write(b []byte) (int, error) {
	f.n++
	if f.n > f.after {
		return 0, errors.New("no space left on device")
	}
	return len(b), nil
}

// The first write failure is kept and returned to every later call, rather than
// each one trying again: a recording whose disk has filled is not going to
// start working, and a session must not be held up once per keystroke finding
// that out. What matters for the session is that the error is reported and the
// session itself carries on -- the recording is evidence, not the service.
func TestAWriteFailureIsStickyAcrossEveryPath(t *testing.T) {
	f := &failingWriter{after: 1} // the header goes, nothing after it does
	w, err := asciicast.NewWriter(f, asciicast.Header{})
	if err != nil {
		t.Fatal(err)
	}
	first := w.Event(asciicast.Output, []byte("printed"))
	if first == nil {
		t.Fatal("a failing writer accepted an event")
	}
	for _, c := range []struct {
		name string
		call func() error
	}{
		{"event", func() error { return w.Event(asciicast.Output, []byte("more")) }},
		{"resize", func() error { return w.Resized(100, 40) }},
		{"marker", func() error { return w.Mark("note") }},
		{"flush", func() error { return w.Flush() }},
	} {
		if err := c.call(); err == nil {
			t.Errorf("%s: a second call after a failure succeeded", c.name)
		} else if err.Error() != first.Error() {
			t.Errorf("%s: error = %v, want the first one (%v)", c.name, err, first)
		}
	}
}

// A header the writer cannot even write is a recording that never starts, and
// the caller is told at once rather than finding out on the first keystroke.
func TestAHeaderThatCannotBeWrittenIsAnError(t *testing.T) {
	if _, err := asciicast.NewWriter(&failingWriter{after: 0}, asciicast.Header{}); err == nil {
		t.Error("a writer that refuses the header returned a recorder")
	}
}

// Flush writes the half character a stream ended in the middle of, and after
// that there is nothing left to flush: a second call is not a second line.
func TestFlushIsIdempotent(t *testing.T) {
	var buf bytes.Buffer
	w, err := asciicast.NewWriter(&buf, asciicast.Header{})
	if err != nil {
		t.Fatal(err)
	}
	// The first two bytes of a three-byte character: held back as carry.
	if err := w.Event(asciicast.Output, []byte{0xe2, 0x82}); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	after := buf.Len()
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != after {
		t.Errorf("a second flush wrote %d more bytes", buf.Len()-after)
	}
}
