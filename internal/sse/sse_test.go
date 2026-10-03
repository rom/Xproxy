package sse

import (
	"errors"
	"io"
	"strings"
	"testing"
)

// read every event a stream carries, so a test can state a stream and its
// events rather than driving the reader by hand.
func events(t *testing.T, in string) ([]Event, error) {
	t.Helper()
	r := NewReader(strings.NewReader(in))
	var out []Event
	for {
		e, err := r.ReadEvent()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		out = append(out, e)
	}
}

func TestAnEventIsTheFieldsBeforeABlankLine(t *testing.T) {
	got, err := events(t, "event: price\ndata: 42\nid: 7\n\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("%d events, want 1: %+v", len(got), got)
	}
	e := got[0]
	if e.Name != "price" || e.Data != "42" || e.ID != "7" || !e.HasID {
		t.Errorf("event = %+v", e)
	}
	if e.Fields != 3 {
		t.Errorf("fields = %d, want 3", e.Fields)
	}
}

// All three terminators, which is the thing most likely to be got wrong: the
// standard's newline is CRLF, LF *or a bare CR*, and a reader that waited for
// an LF after a CR would hold a whole event and deliver nothing.
func TestAllThreeLineTerminatorsEndALine(t *testing.T) {
	for _, nl := range []struct{ name, s string }{
		{"LF", "\n"}, {"CRLF", "\r\n"}, {"bare CR", "\r"},
	} {
		got, err := events(t, "event: tick"+nl.s+"data: 1"+nl.s+nl.s)
		if err != nil {
			t.Fatalf("%s: %v", nl.name, err)
		}
		if len(got) != 1 || got[0].Name != "tick" || got[0].Data != "1" {
			t.Errorf("%s: %+v", nl.name, got)
		}
	}
}

// A CR that is not followed by LF must not swallow the next line's first byte.
func TestABareCRDoesNotEatTheNextLine(t *testing.T) {
	got, err := events(t, "data: a\rdata: b\r\r")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Data != "a\nb" {
		t.Fatalf("%+v", got)
	}
}

func TestAFieldWithNoColonHasAnEmptyValue(t *testing.T) {
	// `data` alone is a data field with nothing in it, not a malformed line.
	// Every browser treats it that way and a proxy that refused it would
	// break a stream the application considers fine.
	got, err := events(t, "data\ndata: x\n\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Data != "\nx" {
		t.Fatalf("%+v", got)
	}
}

func TestExactlyOneSpaceAfterTheColonIsStripped(t *testing.T) {
	got, err := events(t, "data:  two spaces\ndata:none\n\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("%+v", got)
	}
	if want := " two spaces\nnone"; got[0].Data != want {
		t.Errorf("data = %q, want %q", got[0].Data, want)
	}
}

func TestDataAccumulatesAcrossLinesWithoutATrailingNewline(t *testing.T) {
	got, err := events(t, "data: a\ndata: b\ndata: c\n\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Data != "a\nb\nc" {
		t.Fatalf("data = %q", got[0].Data)
	}
}

func TestACommentCarriesNoDataAndIsCounted(t *testing.T) {
	// A comment is how a stream stays alive through an intermediary that
	// would time it out, so an event that is only comments is dispatched
	// rather than swallowed: a silent stream and a busy one must not look
	// the same to a policy.
	got, err := events(t, ": keepalive\n\ndata: x\n\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("%d events, want 2: %+v", len(got), got)
	}
	if got[0].Comments != 1 || got[0].Data != "" || got[0].Name != "" {
		t.Errorf("the keepalive came out as %+v", got[0])
	}
}

func TestTheLeadingBOMIsStrippedOnceAndOnlyAtTheStart(t *testing.T) {
	got, err := events(t, "\xEF\xBB\xBFdata: first\n\ndata: \xEF\xBB\xBFsecond\n\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("%+v", got)
	}
	if got[0].Data != "first" {
		t.Errorf("the leading BOM was not stripped: %q", got[0].Data)
	}
	if got[1].Data != "\xEF\xBB\xBFsecond" {
		t.Errorf("a BOM mid-stream is data and was removed: %q", got[1].Data)
	}
}

func TestAnIdentifierWithANULIsIgnoredFieldAndAll(t *testing.T) {
	// The one value the standard says to drop rather than carry.
	got, err := events(t, "id: a\x00b\ndata: x\n\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("%+v", got)
	}
	if got[0].HasID || got[0].ID != "" {
		t.Errorf("the identifier was carried: %+v", got[0])
	}
}

func TestAnEmptyIdentifierIsNotTheSameAsNoIdentifier(t *testing.T) {
	// `id:` with nothing after it clears the client's stored identifier, so
	// it has to be distinguishable from an event that named no id at all.
	with, err := events(t, "id:\ndata: x\n\n")
	if err != nil {
		t.Fatal(err)
	}
	without, err := events(t, "data: x\n\n")
	if err != nil {
		t.Fatal(err)
	}
	if !with[0].HasID || with[0].ID != "" {
		t.Errorf("an empty id: came out as %+v", with[0])
	}
	if without[0].HasID {
		t.Errorf("an absent id came out as present: %+v", without[0])
	}
}

func TestRetryIsDigitsOrItIsIgnored(t *testing.T) {
	for _, c := range []struct {
		in   string
		want int64
		set  bool
	}{
		{"retry: 2500", 2500, true},
		{"retry: 0", 0, true},
		{"retry: 1.5", 0, false},
		{"retry: soon", 0, false},
		{"retry: -1", 0, false},
		{"retry:", 0, false},
	} {
		got, err := events(t, c.in+"\ndata: x\n\n")
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		if got[0].RetrySet != c.set || got[0].Retry != c.want {
			t.Errorf("%q -> retry=%d set=%v, want %d/%v", c.in, got[0].Retry, got[0].RetrySet, c.want, c.set)
		}
	}
}

func TestAnUnknownFieldNameIsIgnoredAndCounted(t *testing.T) {
	// The standard says ignore it. Counting it is this project's addition: a
	// stream using a field name the standard does not define is either a
	// newer standard or somebody's channel, and the two are worth telling
	// apart by looking.
	got, err := events(t, "data: x\nchannel: hidden\nwhatever\n\n")
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Unknown != 2 {
		t.Errorf("unknown = %d, want 2 (%+v)", got[0].Unknown, got[0])
	}
	if got[0].Data != "x" {
		t.Errorf("an unknown field reached the data: %q", got[0].Data)
	}
}

func TestAnIncompleteEventAtEndOfStreamIsDiscarded(t *testing.T) {
	// The blank line never came, so there is no event. The standard is
	// explicit about this and it matters to a proxy: forwarding a partial
	// event would present half an application's answer as the whole of it.
	got, err := events(t, "data: complete\n\ndata: cut off")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Data != "complete" {
		t.Fatalf("%+v", got)
	}
}

func TestTheDefaultEventNameIsMessage(t *testing.T) {
	got, _ := events(t, "data: x\n\n")
	if got[0].Name != "" {
		t.Errorf("name = %q, want empty so a rule can tell absent from message", got[0].Name)
	}
	if got[0].Named() != "message" {
		t.Errorf("Named() = %q", got[0].Named())
	}
}

func TestTheBoundsRefuseRatherThanTruncate(t *testing.T) {
	long := strings.Repeat("x", MaxLine+10)
	if _, err := events(t, "data: "+long+"\n\n"); !errors.Is(err, ErrLineTooLong) {
		t.Errorf("a line past the bound: %v", err)
	}
	if _, err := events(t, "event: "+strings.Repeat("e", MaxName+1)+"\n\n"); !errors.Is(err, ErrNameTooLong) {
		t.Errorf("a name past the bound: %v", err)
	}
	if _, err := events(t, "id: "+strings.Repeat("i", MaxID+1)+"\n\n"); !errors.Is(err, ErrIDTooLong) {
		t.Errorf("an id past the bound: %v", err)
	}
	var many strings.Builder
	for i := 0; i <= MaxFields; i++ {
		many.WriteString("data: x\n")
	}
	if _, err := events(t, many.String()+"\n"); !errors.Is(err, ErrTooManyField) {
		t.Errorf("a field count past the bound: %v", err)
	}
}

func TestAControlCharacterInAnEventNameIsRefused(t *testing.T) {
	if _, err := events(t, "event: a\x01b\ndata: x\n\n"); !errors.Is(err, ErrControl) {
		t.Errorf("err = %v, want ErrControl", err)
	}
	// A tab is not a control character for this purpose: it is whitespace an
	// application may legitimately have in a name, and refusing it would be
	// stricter than anything downstream.
	if _, err := events(t, "event: a\tb\ndata: x\n\n"); err != nil {
		t.Errorf("a tab in a name was refused: %v", err)
	}
}

func TestAStreamThatIsNotUTF8IsRefused(t *testing.T) {
	// An event stream is UTF-8 by definition, and a policy that matched on
	// text would otherwise be matching on something a client decodes
	// differently.
	if _, err := events(t, "data: \xff\xfe\n\n"); !errors.Is(err, ErrNotUTF8) {
		t.Errorf("err = %v, want ErrNotUTF8", err)
	}
}

func TestSetMaxCannotRaiseABoundAboveTheBuffer(t *testing.T) {
	// A bound that silently did not apply would be worse than no bound, so
	// SetMax clamps to the buffer the reader was built with.
	r := NewReader(strings.NewReader(""))
	r.SetMax(MaxLine * 4)
	if r.max != MaxLine {
		t.Errorf("max = %d, want it clamped to %d", r.max, MaxLine)
	}
	r.SetMax(128)
	if r.max != 128 {
		t.Errorf("max = %d, want 128", r.max)
	}
	r.SetMax(0)
	if r.max != MaxLine {
		t.Errorf("max = %d, want the ceiling back", r.max)
	}
}

func TestStreamRecognisesTheMediaTypeWithItsParameters(t *testing.T) {
	for _, s := range []string{
		"text/event-stream",
		"text/event-stream; charset=utf-8",
		"Text/Event-Stream",
		"  text/event-stream  ; charset=utf-8",
	} {
		if !Stream(s) {
			t.Errorf("Stream(%q) = false", s)
		}
	}
	for _, s := range []string{"text/plain", "application/json", "", "text/event-streamx"} {
		if Stream(s) {
			t.Errorf("Stream(%q) = true", s)
		}
	}
}

// Writing an event back out is what makes the framing decision happen once: the
// octets the client reads are the proxy's, so a sender's bare CR and its
// ambiguous blank lines cannot be resolved differently downstream.
func TestAnEventRoundTripsThroughWrite(t *testing.T) {
	in := []Event{
		{Name: "price", Data: "42", ID: "7", HasID: true},
		{Data: "a\nb"},
		{Name: "tick"},
		{Data: "x", Retry: 1000, RetrySet: true},
	}
	var b strings.Builder
	for _, e := range in {
		if err := e.Write(&b); err != nil {
			t.Fatal(err)
		}
	}
	got, err := events(t, b.String())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(in) {
		t.Fatalf("%d events back, want %d: %q", len(got), len(in), b.String())
	}
	for i := range in {
		if got[i].Name != in[i].Name || got[i].Data != in[i].Data ||
			got[i].ID != in[i].ID || got[i].HasID != in[i].HasID ||
			got[i].Retry != in[i].Retry || got[i].RetrySet != in[i].RetrySet {
			t.Errorf("event %d: wrote %+v, read %+v", i, in[i], got[i])
		}
	}
}

// A data payload with newlines in it has to come out as several data fields,
// because a raw newline would end the event early -- which would turn one
// event into two and hand the client a fragment as a whole message.
func TestWriteSplitsADataPayloadOnItsNewlines(t *testing.T) {
	var b strings.Builder
	if err := (Event{Data: "one\ntwo\nthree"}).Write(&b); err != nil {
		t.Fatal(err)
	}
	want := "data: one\ndata: two\ndata: three\n\n"
	if b.String() != want {
		t.Errorf("wrote %q, want %q", b.String(), want)
	}
}
