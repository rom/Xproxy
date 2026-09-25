package tftp

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// req builds a request packet the way a client does, so a test can say what
// it means rather than what it looks like.
func req(op Op, name, mode string, opts ...string) []byte {
	out := binary.BigEndian.AppendUint16(nil, uint16(op))
	out = append(out, name...)
	out = append(out, 0)
	out = append(out, mode...)
	out = append(out, 0)
	for _, s := range opts {
		out = append(out, s...)
		out = append(out, 0)
	}
	return out
}

func TestARequestIsReadAsAFilenameAModeAndOptions(t *testing.T) {
	p, err := Parse(req(OpRead, "firmware/boot.bin", "octet", "blksize", "1428", "windowsize", "16"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Op != OpRead || p.Request == nil {
		t.Fatalf("got %v with request %v", p.Op, p.Request)
	}
	if p.Request.Filename != "firmware/boot.bin" || p.Request.Mode != ModeOctet {
		t.Fatalf("got %q in mode %q", p.Request.Filename, p.Request.Mode)
	}
	n, ok, err := p.Request.Number(OptWindowSize)
	if err != nil || !ok || n != 16 {
		t.Fatalf("window size %d present=%v err=%v", n, ok, err)
	}
	if _, ok, _ := p.Request.Number(OptTransferSize); ok {
		t.Fatal("an option that was not sent reads as present")
	}
}

func TestTheModeAndTheOptionNamesAreCaseInsensitive(t *testing.T) {
	// RFC 1350 §5 and RFC 2347: both are case-insensitive. A relay that
	// compared them exactly would refuse the client that shouts, and a
	// policy that refused "mail" would miss the one that wrote "Mail".
	p, err := Parse(req(OpWrite, "cfg", "MAIL", "BlkSize", "512"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Request.Mode != ModeMail {
		t.Fatalf("mode %q", p.Request.Mode)
	}
	if v, ok := p.Request.Get(OptBlockSize); !ok || v != "512" {
		t.Fatalf("block size %q present=%v", v, ok)
	}
}

func TestAFilenameThatRunsPastItsFieldIsRefused(t *testing.T) {
	// No terminating zero. Reading such a field "to the end of the packet"
	// is one server's answer and refusing it is another's, and a filename
	// is exactly where the two differ.
	raw := binary.BigEndian.AppendUint16(nil, uint16(OpRead))
	raw = append(raw, "firmware/boot.bin"...)
	if _, err := Parse(raw); err == nil {
		t.Fatal("an unterminated filename parsed")
	}
	// A mode field with no terminator is the same shape one field on.
	raw = binary.BigEndian.AppendUint16(nil, uint16(OpRead))
	raw = append(raw, "boot.bin"...)
	raw = append(raw, 0)
	raw = append(raw, "octet"...)
	if _, err := Parse(raw); err == nil {
		t.Fatal("an unterminated mode parsed")
	}
}

func TestAnAcknowledgementIsExactlyTwoOctets(t *testing.T) {
	if _, err := Parse([]byte{0, 4, 0, 1}); err != nil {
		t.Fatalf("a well formed acknowledgement was refused: %v", err)
	}
	for _, body := range [][]byte{{0}, {0, 1, 0}, {}} {
		raw := append([]byte{0, 4}, body...)
		if _, err := Parse(raw); err == nil {
			t.Fatalf("an acknowledgement of %d octets parsed", len(body))
		}
	}
}

func TestAPacketThisRelayCannotNameIsRefused(t *testing.T) {
	for _, raw := range [][]byte{
		{},
		{0},
		{0, 9, 0, 0},                             // an opcode no standard defines
		append([]byte{0, 1}, make([]byte, 0)...), // a request with nothing in it
		{0, 3, 0},                                // data with half a block number
		{0, 5, 0},                                // an error with half a code
		append([]byte{0, 5, 0, 1}, "no zero"...), // an unterminated message
		append([]byte{0, 5, 0, 1, 0}, 'x'),       // octets after the message
		make([]byte, MaxPacket+1),
	} {
		if _, err := Parse(raw); err == nil {
			t.Fatalf("%v parsed", raw)
		}
	}
}

func TestADataPacketKeepsItsLengthAndNotItsPayload(t *testing.T) {
	raw := append([]byte{0, 3, 0, 7}, bytes.Repeat([]byte{'x'}, 512)...)
	p, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.Data.Block != 7 || p.Data.Length != 512 {
		t.Fatalf("block %d of %d octets", p.Data.Block, p.Data.Length)
	}
}

func TestAnErrorPacketIsReadAndNamed(t *testing.T) {
	raw := append([]byte{0, 5, 0, 2}, "Access violation"...)
	raw = append(raw, 0)
	p, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.ErrorCode != ErrAccessViolation || p.ErrorMessage != "Access violation" {
		t.Fatalf("code %d message %q", p.ErrorCode, p.ErrorMessage)
	}
	if ErrorName(ErrAccessViolation) != "accessViolation" {
		t.Fatalf("name %q", ErrorName(ErrAccessViolation))
	}
	if !strings.Contains(ErrorName(99), "99") {
		t.Fatalf("an unnamed code hides its number: %q", ErrorName(99))
	}
}

func TestAnOptionAcknowledgementIsReadAsTheBoundsTheTransferRunsUnder(t *testing.T) {
	raw := append([]byte{0, 6}, "blksize\x001428\x00windowsize\x004\x00"...)
	p, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.OAck) != 2 || p.OAck[0].Name != OptBlockSize || p.OAck[1].Value != "4" {
		t.Fatalf("options %v", p.OAck)
	}
}

func TestAnOptionWhoseValueIsNotANumberIsRefusedRatherThanIgnored(t *testing.T) {
	// A server would read "1428x" somehow -- as 1428, as zero, as an error.
	// A relay that ignored it would be bounding a number the server is not
	// using.
	p, err := Parse(req(OpRead, "x", "octet", "blksize", "1428x"))
	if err != nil {
		t.Fatal(err)
	}
	if _, present, err := p.Request.Number(OptBlockSize); !present || err == nil {
		t.Fatalf("present=%v err=%v", present, err)
	}
	p, err = Parse(req(OpRead, "x", "octet", "windowsize", "-4"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.Request.Number(OptWindowSize); err == nil {
		t.Fatal("a negative window size was accepted")
	}
}

func TestTooManyOptionsIsRefused(t *testing.T) {
	var opts []string
	for i := 0; i <= MaxOptions; i++ {
		opts = append(opts, "opt", "1")
	}
	if _, err := Parse(req(OpRead, "x", "octet", opts...)); err == nil {
		t.Fatal("a request with more options than the bound parsed")
	}
	if _, err := Parse(req(OpRead, "x", "octet", "", "1")); err == nil {
		t.Fatal("an option with no name parsed")
	}
	long := strings.Repeat("a", MaxFilename+1)
	if _, err := Parse(req(OpRead, long, "octet")); err == nil {
		t.Fatal("a filename longer than the bound parsed")
	}
}

func TestAnOpcodeIsNamedTheWayARuleWritesIt(t *testing.T) {
	for _, c := range []struct {
		in   string
		want Op
	}{
		{"read", OpRead}, {"RRQ", OpRead}, {" get ", OpRead},
		{"write", OpWrite}, {"wrq", OpWrite}, {"put", OpWrite},
		{"data", OpData}, {"ack", OpAck}, {"error", OpError}, {"oack", OpOAck},
	} {
		got, ok := OpOf(c.in)
		if !ok || got != c.want {
			t.Errorf("%q read as %v ok=%v", c.in, got, ok)
		}
	}
	if _, ok := OpOf("delete"); ok {
		t.Fatal("an opcode nobody defines was named")
	}
	if !OpRead.Request() || OpData.Request() {
		t.Fatal("a request is the opcode that begins a transfer")
	}
	if !strings.Contains(Op(42).String(), "42") {
		t.Fatalf("an unknown opcode hides its number: %q", Op(42))
	}
}
