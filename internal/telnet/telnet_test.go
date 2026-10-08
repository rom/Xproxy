package telnet

import (
	"bytes"
	"errors"
	"testing"
)

// collect runs a parse and returns what it found, with the aliased
// buffers copied so they survive the next Feed.
func collect(t *testing.T, p *Parser, chunks ...[]byte) []Event {
	t.Helper()
	var out []Event
	for _, c := range chunks {
		err := p.Feed(c, func(e Event) error {
			e.Data = append([]byte(nil), e.Data...)
			out = append(out, e)
			return nil
		})
		if err != nil {
			t.Fatalf("feed: %v", err)
		}
	}
	return out
}

// The framing of RFC 854: data is what is not a command, IAC begins a
// command, and IAC IAC is one literal 255.
func TestFramingSeparatesDataFromCommands(t *testing.T) {
	in := []byte("ls")
	in = append(in, IAC, IAC)           // a literal 255 in the data
	in = append(in, " -l"...)           //
	in = append(in, IAC, DO, OptNAWS)   // a negotiation
	in = append(in, IAC, WILL, OptEcho) //
	in = append(in, IAC, AYT)           // a command with no option
	in = append(in, IAC, SB, OptNAWS, 0, 80, 0, 24, IAC, SE)
	in = append(in, "\r\n"...)

	got := collect(t, NewParser(0), in)
	want := []Event{
		{Kind: Data, Data: append([]byte("ls"), append([]byte{IAC}, " -l"...)...)},
		{Kind: Negotiate, Cmd: DO, Opt: OptNAWS},
		{Kind: Negotiate, Cmd: WILL, Opt: OptEcho},
		{Kind: Command, Cmd: AYT},
		{Kind: Subneg, Opt: OptNAWS, Data: []byte{0, 80, 0, 24}},
		{Kind: Data, Data: []byte("\r\n")},
	}
	if len(got) != len(want) {
		t.Fatalf("%d events, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i].Kind != want[i].Kind || got[i].Cmd != want[i].Cmd || got[i].Opt != want[i].Opt || !bytes.Equal(got[i].Data, want[i].Data) {
			t.Errorf("event %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// A command split across reads is ordinary on a slow link, and a
// parser that forgets where it was turns one command into data.
func TestACommandSplitAcrossReadsIsStillOneCommand(t *testing.T) {
	full := []byte{'a', IAC, SB, OptNAWS, 0, 80, 0, 24, IAC, SE, 'b'}
	// Every split point, one byte at a time and in two pieces.
	for cut := 0; cut <= len(full); cut++ {
		p := NewParser(0)
		got := collect(t, p, full[:cut], full[cut:])
		var subs, data int
		var payload []byte
		for _, e := range got {
			switch e.Kind {
			case Subneg:
				subs++
				payload = e.Data
			case Data:
				data += len(e.Data)
			}
		}
		if subs != 1 || !bytes.Equal(payload, []byte{0, 80, 0, 24}) {
			t.Errorf("cut at %d: %d subnegotiations, payload %v", cut, subs, payload)
		}
		if data != 2 {
			t.Errorf("cut at %d: %d data bytes, want 2", cut, data)
		}
	}
	// And one byte at a time throughout.
	p := NewParser(0)
	chunks := make([][]byte, len(full))
	for i := range full {
		chunks[i] = full[i : i+1]
	}
	got := collect(t, p, chunks...)
	subs := 0
	for _, e := range got {
		if e.Kind == Subneg {
			subs++
		}
	}
	if subs != 1 {
		t.Errorf("byte at a time: %d subnegotiations, want 1", subs)
	}
}

// A peer that begins a subnegotiation and never ends it would grow the
// buffer for as long as it keeps sending.
func TestAnEndlessSubnegotiationIsRefused(t *testing.T) {
	p := NewParser(64)
	in := append([]byte{IAC, SB, OptTerminalType}, bytes.Repeat([]byte{'x'}, 200)...)
	err := p.Feed(in, func(Event) error { return nil })
	if !errors.Is(err, ErrSubnegotiationTooLong) {
		t.Fatalf("err %v, want the bound", err)
	}
}

// An IAC inside a subnegotiation is IAC IAC or IAC SE. Anything else
// is undefined, and guessing is how a proxy and a target come to
// disagree about where a command ends.
func TestAnUndefinedIACInsideASubnegotiationIsRefused(t *testing.T) {
	p := NewParser(0)
	err := p.Feed([]byte{IAC, SB, OptNAWS, 1, IAC, WILL, OptEcho}, func(Event) error { return nil })
	if err == nil {
		t.Fatal("IAC WILL inside a subnegotiation was accepted")
	}
}

// Escaping is what puts arbitrary bytes into the stream, and it must
// round-trip through the parser.
func TestEscapedDataRoundTrips(t *testing.T) {
	raw := []byte{0, 1, IAC, 2, IAC, IAC, 3, 255}
	var got []byte
	p := NewParser(0)
	if err := p.Feed(EscapeData(raw), func(e Event) error {
		if e.Kind == Data {
			got = append(got, e.Data...)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, raw) {
		t.Errorf("round trip gave %v, want %v", got, raw)
	}
}

// A refusal answers the right way round: what a peer offers is
// declined with DONT, what it asks for with WONT. The other way round
// is a negotiation loop.
func TestRefusalAnswersTheRightWayRound(t *testing.T) {
	for _, tc := range []struct {
		cmd, want byte
	}{
		{WILL, DONT}, {WONT, DONT}, {DO, WONT}, {DONT, WONT},
	} {
		got, ok := Refusal(tc.cmd, OptEcho)
		if !ok || !bytes.Equal(got, []byte{IAC, tc.want, OptEcho}) {
			t.Errorf("Refusal(%s) = %v, want IAC %s echo", CommandName(tc.cmd), got, CommandName(tc.want))
		}
	}
	if _, ok := Refusal(AYT, 0); ok {
		t.Error("a command that is not a negotiation was given a refusal")
	}
}

func TestNAWSReadsAWindow(t *testing.T) {
	if c, r, ok := NAWS([]byte{0, 132, 0, 43}); !ok || c != 132 || r != 43 {
		t.Errorf("NAWS = %d %d %v", c, r, ok)
	}
	if _, _, ok := NAWS([]byte{0, 80}); ok {
		t.Error("a short window was accepted")
	}
}

func TestOptionNames(t *testing.T) {
	if o, ok := OptionByName("naws"); !ok || o != OptNAWS {
		t.Errorf("naws = %d %v", o, ok)
	}
	if _, ok := OptionByName("nosuchoption"); ok {
		t.Error("an invented option resolved")
	}
	if OptionName(OptNewEnviron) != "new-environ" || OptionName(200) != "option-200" {
		t.Errorf("names: %q %q", OptionName(OptNewEnviron), OptionName(200))
	}
	if Named(200) {
		t.Error("an option with no name is named")
	}
}

// Whatever arrives, the parser either reports an error or accounts for
// every byte: the data it emits plus the commands it found have to be
// the stream it was given, or a proxy relaying what it parsed is
// relaying something else.
func FuzzParser(f *testing.F) {
	f.Add([]byte("hello"))
	f.Add([]byte{IAC, IAC})
	f.Add([]byte{IAC, DO, OptNAWS, 'x'})
	f.Add([]byte{IAC, SB, OptNAWS, 0, 80, 0, 24, IAC, SE})
	f.Add([]byte{IAC, SB, OptTerminalType, 0, IAC, IAC, 1, IAC, SE})
	f.Fuzz(func(t *testing.T, in []byte) {
		p := NewParser(0)
		var rebuilt []byte
		err := p.Feed(in, func(e Event) error {
			switch e.Kind {
			case Data:
				rebuilt = append(rebuilt, EscapeData(e.Data)...)
			case Negotiate:
				rebuilt = append(rebuilt, Negotiation(e.Cmd, e.Opt)...)
			case Command:
				rebuilt = append(rebuilt, IAC, e.Cmd)
			case Subneg:
				rebuilt = append(rebuilt, Subnegotiation(e.Opt, e.Data)...)
			}
			return nil
		})
		if err != nil {
			return // refused, which is an answer
		}
		// What is left mid-command is not yet an event, so only a
		// stream the parser finished can be compared whole.
		if p.st != stData {
			return
		}
		if !bytes.Equal(rebuilt, in) {
			t.Fatalf("re-encoding changed the stream:\n in  %v\n out %v", in, rebuilt)
		}
	})
}

// Every command RFC 854 defines has a name, and one it does not is still
// named.
//
// These names are what a policy refusal and an access line say, so a command
// arriving as a number nobody recognises reads as `command-200` rather than
// disappearing from the record: an option negotiation this proxy cannot name
// is exactly the thing worth seeing in a log.
func TestCommandNames(t *testing.T) {
	for _, c := range []struct {
		code byte
		want string
	}{
		{IAC, "IAC"}, {DONT, "DONT"}, {DO, "DO"}, {WONT, "WONT"}, {WILL, "WILL"},
		{SB, "SB"}, {GA, "GA"}, {EL, "EL"}, {EC, "EC"}, {AYT, "AYT"}, {AO, "AO"},
		{IP, "IP"}, {BRK, "BRK"}, {DM, "DM"}, {NOP, "NOP"}, {SE, "SE"},
	} {
		if got := CommandName(c.code); got != c.want {
			t.Errorf("CommandName(%d) = %q, want %q", c.code, got, c.want)
		}
	}
	// Outside the table: the number survives into the record.
	for _, code := range []byte{0, 1, 200, 239} {
		if got, want := CommandName(code), "command-"+itoa(code); got != want {
			t.Errorf("CommandName(%d) = %q, want %q", code, got, want)
		}
	}
}

func itoa(b byte) string {
	if b == 0 {
		return "0"
	}
	var d []byte
	for ; b > 0; b /= 10 {
		d = append([]byte{'0' + b%10}, d...)
	}
	return string(d)
}
