package asciicast_test

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/asciicast"
)

// What the writer wrote, the reader reads: the round trip is the whole
// contract between the recorder and whatever replays a session.
func TestWriterAndReaderAgree(t *testing.T) {
	var buf bytes.Buffer
	w, err := asciicast.NewWriter(&buf, asciicast.Header{Width: 100, Height: 40, Title: "lab-console"})
	if err != nil {
		t.Fatal(err)
	}
	// Including the bytes that would end a line early if they were not
	// escaped, since a recording of a hostile session is the case.
	want := []string{"hello\r\n", "\x1b[31mred\x1b[0m", "\"]\n[0.0, \"o\", \"forged\"]\n"}
	for _, s := range want {
		if err := w.Event(asciicast.Output, []byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Mark("factor verified"); err != nil {
		t.Fatal(err)
	}
	if err := w.Resized(120, 50); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}

	r, err := asciicast.NewReader(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if r.Header.Width != 100 || r.Header.Height != 40 || r.Header.Title != "lab-console" {
		t.Errorf("header %+v", r.Header)
	}
	var out []string
	var kinds []string
	for {
		ev, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		kinds = append(kinds, ev.Kind)
		if ev.Kind == asciicast.Output {
			out = append(out, ev.Data)
		}
		if ev.At < 0 || ev.At > time.Minute {
			t.Errorf("event at %s", ev.At)
		}
	}
	if strings.Join(out, "|") != strings.Join(want, "|") {
		t.Errorf("output %q, want %q", out, want)
	}
	if strings.Join(kinds, "") != "ooomr" {
		t.Errorf("kinds %q, want the three outputs, the marker and the resize", kinds)
	}
}

// A file that is not a recording is refused where it is opened, rather
// than producing events nobody can place.
func TestABadFileIsRefused(t *testing.T) {
	for name, body := range map[string]string{
		"empty":           "",
		"not JSON":        "hello\n",
		"a wrong version": `{"version": 1, "width": 80, "height": 24}` + "\n",
		"no version":      `{"width": 80}` + "\n",
		"an event first":  `[0.0, "o", "hi"]` + "\n",
	} {
		if _, err := asciicast.NewReader(strings.NewReader(body)); err == nil {
			t.Errorf("%s was accepted as a recording", name)
		}
	}
}

// A line that does not parse stops the reading with an error naming it,
// rather than being skipped: a recording is a record, and a reader that
// quietly dropped part of one would be worse than one that stopped.
func TestABadLineStopsTheReading(t *testing.T) {
	body := `{"version": 2, "width": 80, "height": 24}` + "\n" +
		`[0.0, "o", "before"]` + "\n" +
		`[0.1, "o"]` + "\n" +
		`[0.2, "o", "after"]` + "\n"
	r, err := asciicast.NewReader(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if ev, err := r.Next(); err != nil || ev.Data != "before" {
		t.Fatalf("first event %q: %v", ev.Data, err)
	}
	_, err = r.Next()
	if err == nil {
		t.Fatal("a two field event was accepted")
	}
	if !strings.Contains(err.Error(), "line 3") {
		t.Errorf("the error does not name the line: %v", err)
	}
}

// An empty line in the middle is skipped, because a recorder killed
// between a write and a flush can leave one.
func TestAnEmptyLineIsSkipped(t *testing.T) {
	body := `{"version": 2, "width": 80, "height": 24}` + "\n\n" + `[0.0, "o", "hi"]` + "\n"
	r, err := asciicast.NewReader(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if ev, err := r.Next(); err != nil || ev.Data != "hi" {
		t.Fatalf("event %q: %v", ev.Data, err)
	}
}
