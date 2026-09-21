package asciicast

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// FuzzRecordingStaysParseable. A session recording is evidence: it is
// read back by somebody after an incident, by a tool that expects
// asciicast v2, which is one JSON value per line. The bytes in it came
// off a terminal, so they are whatever the session produced -- escape
// sequences, partial UTF-8, NULs, newlines, a line that is itself a
// JSON array. None of that may end a line early or produce a line that
// will not parse, or the recording of the session somebody wants to
// read is the one that will not open.
func FuzzRecordingStaysParseable(f *testing.F) {
	f.Add([]byte("hello\n"))
	f.Add([]byte("\x1b[31mred\x1b[0m"))
	f.Add([]byte(`["fake", "event"]`))
	f.Add([]byte("\x00\xff\xfe"))
	f.Add([]byte("line\nbreak\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		var buf bytes.Buffer
		w, err := NewWriter(&buf, Header{Width: 80, Height: 24})
		if err != nil {
			t.Fatal(err)
		}
		if err := w.Event("o", data); err != nil {
			t.Fatalf("writing terminal output failed: %v", err)
		}
		if err := w.Event("i", data); err != nil {
			t.Fatalf("writing terminal input failed: %v", err)
		}
		if err := w.Flush(); err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
		// Data that is empty, or is nothing but the first bytes of a
		// character, writes no event at all, which is what it should
		// do: an empty event is noise in a recording and half a
		// character is not one yet.
		if len(lines) == 0 {
			t.Fatal("nothing was written, not even a header")
		}
		var hdr map[string]any
		if err := json.Unmarshal([]byte(lines[0]), &hdr); err != nil {
			t.Fatalf("the header line is not JSON: %v (%q)", err, lines[0])
		}
		if v, _ := hdr["version"].(float64); v != 2 {
			t.Fatalf("header version %v", hdr["version"])
		}
		for _, line := range lines[1:] {
			var ev []any
			if err := json.Unmarshal([]byte(line), &ev); err != nil {
				t.Fatalf("an event line is not JSON: %v (%q)", err, line)
			}
			if len(ev) != 3 {
				t.Fatalf("an event has %d fields: %q", len(ev), line)
			}
			if _, ok := ev[0].(float64); !ok {
				t.Fatalf("the timestamp is not a number: %q", line)
			}
			kind, ok := ev[1].(string)
			if !ok || (kind != "o" && kind != "i" && kind != "r" && kind != "m") {
				t.Fatalf("event kind %v: %q", ev[1], line)
			}
			if _, ok := ev[2].(string); !ok {
				t.Fatalf("the payload is not a string: %q", line)
			}
		}
	})
}

// TestPartialRuneIsHeldBack: terminal output arrives in whatever sizes
// the kernel hands over, so a character can be split across two reads.
// A recorder that writes the half it has produces a replacement
// character in the recording for a character the session never
// contained.
func TestPartialRuneIsHeldBack(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, Header{Width: 80, Height: 24})
	if err != nil {
		t.Fatal(err)
	}
	euro := []byte("€") // three bytes
	if err := w.Event("o", euro[:2]); err != nil {
		t.Fatal(err)
	}
	if err := w.Event("o", euro[2:]); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "€") {
		t.Fatalf("a character split across two reads did not survive: %q", buf.String())
	}
	if strings.Contains(buf.String(), "�") {
		t.Fatalf("a replacement character reached the recording: %q", buf.String())
	}
}
