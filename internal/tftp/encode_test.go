package tftp

import (
	"strings"
	"testing"
)

func TestAnErrorPacketRoundTrips(t *testing.T) {
	raw := EncodeError(ErrAccessViolation, "path refused")
	p, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.Op != OpError || p.ErrorCode != ErrAccessViolation || p.ErrorMessage != "path refused" {
		t.Fatalf("got %v code %d message %q", p.Op, p.ErrorCode, p.ErrorMessage)
	}
}

// TestARefusalDoesNotCarryTheNameThatCausedIt is the same rule as the
// classifier's detail, one hop further out: the refusal goes back to the peer
// and into its log, so a filename with an escape sequence in it must not be
// what this relay writes there.
func TestARefusalDoesNotCarryTheNameThatCausedIt(t *testing.T) {
	raw := EncodeError(ErrAccessViolation, "refused \x1b[2J\r\nOK boot.bin")
	p, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(p.ErrorMessage); i++ {
		if c := p.ErrorMessage[i]; c < 0x20 || c == 0x7f {
			t.Fatalf("the message carries octet %#02x: %q", c, p.ErrorMessage)
		}
	}
	long := EncodeError(ErrNotDefined, strings.Repeat("a", 4096))
	if len(long) > MaxErrorMessage+16 {
		t.Fatalf("a refusal of %d octets", len(long))
	}
	if _, err := Parse(long); err != nil {
		t.Fatal(err)
	}
}

func TestARewrittenRequestSaysWhatTheRelayMeantAndNothingElse(t *testing.T) {
	// This is the path a bound takes when it is applied rather than
	// enforced: the client asked for a window of 64 and the transfer runs
	// with 4.
	raw, err := EncodeRequest(OpRead, "firmware/boot.bin", ModeOctet, []Option{
		{Name: OptBlockSize, Value: "1428"},
		{Name: OptWindowSize, Value: "4"},
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.Op != OpRead || p.Request.Filename != "firmware/boot.bin" || p.Request.Mode != ModeOctet {
		t.Fatalf("got %v %q %q", p.Op, p.Request.Filename, p.Request.Mode)
	}
	if len(p.Request.Options) != 2 || p.Request.Options[0].Name != OptBlockSize {
		t.Fatalf("options %v", p.Request.Options)
	}
	if v, _ := p.Request.Get(OptWindowSize); v != "4" {
		t.Fatalf("window size %q", v)
	}
	// RFC 2347 requires an option acknowledgement to answer in the request's
	// order, so the order a relay writes has to be the order it was given.
	oack, err := EncodeOAck(p.Request.Options)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(oack)
	if err != nil {
		t.Fatal(err)
	}
	if len(back.OAck) != 2 || back.OAck[0].Name != OptBlockSize || back.OAck[1].Name != OptWindowSize {
		t.Fatalf("acknowledged %v", back.OAck)
	}
}

// TestAFieldWithANULIsNotWritten holds the encoder to the rule the parser
// holds a peer to. A NUL in a value would end the field early, so the packet
// would say something other than what the relay decided -- which is the bug
// this relay exists to stop.
func TestAFieldWithANULIsNotWritten(t *testing.T) {
	for _, c := range []struct {
		what       string
		name, mode string
		opts       []Option
		wantErr    bool
	}{
		{what: "a filename", name: "boot\x00.bin", mode: ModeOctet, wantErr: true},
		{what: "a mode", name: "boot.bin", mode: "oct\x00et", wantErr: true},
		{what: "an option name", name: "b", mode: ModeOctet, opts: []Option{{Name: "bl\x00ksize", Value: "8"}}, wantErr: true},
		{what: "an option value", name: "b", mode: ModeOctet, opts: []Option{{Name: OptBlockSize, Value: "8\x00"}}, wantErr: true},
		{what: "an option with no name", name: "b", mode: ModeOctet, opts: []Option{{Value: "8"}}, wantErr: true},
		{what: "a well formed request", name: "b", mode: ModeOctet, opts: []Option{{Name: OptBlockSize, Value: "8"}}},
	} {
		_, err := EncodeRequest(OpRead, c.name, c.mode, c.opts)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err=%v, wantErr=%v", c.what, err, c.wantErr)
		}
	}
	if _, err := EncodeRequest(OpRead, strings.Repeat("a", MaxFilename+1), ModeOctet, nil); err == nil {
		t.Fatal("a filename longer than the bound was written")
	}
	var many []Option
	for i := 0; i <= MaxOptions; i++ {
		many = append(many, Option{Name: "opt", Value: "1"})
	}
	if _, err := EncodeRequest(OpRead, "b", ModeOctet, many); err == nil {
		t.Fatal("more options than the bound were written")
	}
	if _, err := EncodeOAck(many); err == nil {
		t.Fatal("more acknowledged options than the bound were written")
	}
}

func TestOnlyARequestOpcodeIsWrittenAsARequest(t *testing.T) {
	for _, op := range []Op{OpData, OpAck, OpError, OpOAck, Op(42)} {
		if _, err := EncodeRequest(op, "b", ModeOctet, nil); err == nil {
			t.Errorf("%v was written as a request", op)
		}
	}
	if _, err := EncodeRequest(OpWrite, "b", ModeOctet, nil); err != nil {
		t.Fatal(err)
	}
}

func TestAnAcknowledgementIsWrittenAsFourOctets(t *testing.T) {
	raw := EncodeAck(7)
	p, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 4 || p.Op != OpAck || p.Ack != 7 {
		t.Fatalf("%d octets, %v of block %d", len(raw), p.Op, p.Ack)
	}
}

// FuzzParse feeds arbitrary datagrams to the reader. Every one of them is a
// packet this relay reads before anything has authenticated anything, because
// the protocol has nothing to authenticate with.
func FuzzParse(f *testing.F) {
	f.Add(req(OpRead, "boot.bin", "octet"))
	f.Add(req(OpWrite, "cfg", "octet", "blksize", "1428"))
	f.Add([]byte{0, 4, 0, 1})
	f.Add([]byte{0, 5, 0, 2, 0})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Parse(data)
		if err != nil {
			if p != nil {
				t.Fatalf("an error came with a packet for %v", data)
			}
			return
		}
		if p == nil {
			t.Fatalf("no error and no packet for %v", data)
		}
		if !p.Op.Known() {
			t.Fatalf("an opcode no standard defines was accepted: %v", p.Op)
		}
		if p.Op.Request() {
			if p.Request == nil || p.Request.Filename == "" || p.Request.Mode == "" {
				t.Fatalf("a request with nothing in it: %#v", p.Request)
			}
			if len(p.Request.Options) > MaxOptions {
				t.Fatalf("%d options", len(p.Request.Options))
			}
			// Whatever arrived, the classification answers, and the answer
			// is one a policy can act on.
			if c := Classify(p.Request.Filename); c.Class == ClassPlain && c.Clean == "" {
				t.Fatalf("%q is plain and cleans to nothing", p.Request.Filename)
			}
		}
	})
}
