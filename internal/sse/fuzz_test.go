package sse

import (
	"errors"
	"io"
	"strings"
	"testing"
	"unicode/utf8"
)

// Every byte of an event stream comes from the upstream application, and on a
// route with a guard this reader sees all of them before the client does. So
// the invariant the fuzzer holds is the one the policy depends on: whatever
// arrives, the reader either refuses it by name or returns an event whose
// recorded sizes are the sizes of what it actually holds.
func FuzzReadEvent(f *testing.F) {
	for _, s := range []string{
		"data: x\n\n",
		"event: a\ndata: b\nid: c\nretry: 1\n\n",
		": comment\n\n",
		"data\n\n",
		"\xEF\xBB\xBFdata: bom\n\n",
		"data: a\rdata: b\r\r",
		"id: \x00\ndata: x\n\n",
		"retry: 99999999999999999999\n\n",
		"data: \xff\n\n",
		"data: a\r\ndata: b\r\n\r\n",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		r := NewReader(strings.NewReader(in))
		for i := 0; i < 64; i++ {
			e, err := r.ReadEvent()
			if err != nil {
				if errors.Is(err, io.EOF) {
					return
				}
				// Every refusal is one of the named ones: a reader that
				// returned an unnamed error would give the kind nothing to
				// turn into a refusal reason.
				for _, known := range []error{
					ErrLineTooLong, ErrEventTooLong, ErrTooManyField,
					ErrNameTooLong, ErrIDTooLong, ErrControl, ErrNotUTF8,
				} {
					if errors.Is(err, known) {
						return
					}
				}
				t.Fatalf("unnamed error %v on %q", err, in)
			}
			if len(e.Name) > MaxName {
				t.Fatalf("name %d bytes past the bound on %q", len(e.Name), in)
			}
			if len(e.ID) > MaxID {
				t.Fatalf("id %d bytes past the bound on %q", len(e.ID), in)
			}
			if e.Fields > MaxFields {
				t.Fatalf("fields %d past the bound on %q", e.Fields, in)
			}
			if len(e.Data)+len(e.Name)+len(e.ID) > MaxEventBytes {
				t.Fatalf("event past the bound on %q", in)
			}
			if e.ID != "" && strings.IndexByte(e.ID, 0) >= 0 {
				t.Fatalf("an identifier with a NUL was carried from %q", in)
			}
			if e.RetrySet && e.Retry < 0 {
				t.Fatalf("retry %d is negative, from %q", e.Retry, in)
			}
		}
	})
}

// An event this reader produced and wrote out again has to read back as the
// same event. That is what lets the proxy re-emit rather than splice, and a
// round trip that lost a field would be a client shown something the
// application did not send.
func FuzzWriteRoundTrip(f *testing.F) {
	f.Add("price", "42", "7", int64(1000))
	f.Add("", "a\nb", "", int64(0))
	f.Add("tick", "", "id", int64(-5))
	f.Fuzz(func(t *testing.T, name, data, id string, retry int64) {
		// Only events this reader could itself have produced: the writer's
		// contract is about what it emits, and a name with a newline in it is
		// not something ReadEvent can return.
		if len(name) > MaxName || len(id) > MaxID || len(data)+len(name)+len(id) > MaxEventBytes {
			return
		}
		if strings.ContainsAny(name, "\r\n") || strings.ContainsAny(id, "\r\n") ||
			strings.Contains(data, "\r") || hasControl([]byte(name)) ||
			strings.IndexByte(id, 0) >= 0 {
			return
		}
		// An event stream is UTF-8 by definition and the reader refuses one
		// that is not, so a field this reader could never have produced is not
		// a round trip it owes.
		if !utf8.ValidString(name) || !utf8.ValidString(data) || !utf8.ValidString(id) {
			return
		}
		// An unset retry carries no value, so the value is zeroed with it:
		// comparing a number that was never written would be a test about the
		// harness rather than about the writer.
		in := Event{Name: name, Data: data, ID: id, HasID: id != "", RetrySet: retry >= 0}
		if in.RetrySet {
			in.Retry = retry
		}
		var b strings.Builder
		if err := in.Write(&b); err != nil {
			t.Fatal(err)
		}
		out, err := NewReader(strings.NewReader(b.String())).ReadEvent()
		if err != nil {
			t.Fatalf("wrote %q and could not read it back: %v", b.String(), err)
		}
		if out.Name != in.Name || out.Data != in.Data || out.ID != in.ID || out.HasID != in.HasID {
			t.Fatalf("wrote %+v as %q, read %+v", in, b.String(), out)
		}
		if out.RetrySet != in.RetrySet || out.Retry != in.Retry {
			t.Fatalf("retry: wrote %d/%v, read %d/%v (%q)", in.Retry, in.RetrySet, out.Retry, out.RetrySet, b.String())
		}
	})
}

func FuzzStream(f *testing.F) {
	f.Add("text/event-stream")
	f.Add("text/event-stream; charset=utf-8")
	f.Add("")
	f.Fuzz(func(t *testing.T, ct string) {
		// Stream must agree with itself about a type whose parameters are
		// stripped: a guard that attached on one spelling and not the other
		// would be a guard a sender chooses.
		if i := strings.IndexByte(ct, ';'); i >= 0 {
			if Stream(ct) != Stream(ct[:i]) {
				t.Fatalf("Stream disagrees about %q with and without its parameters", ct)
			}
		}
	})
}
