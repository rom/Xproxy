package modbus

import (
	"errors"
	"testing"
)

// The point of the sub-function table is that one function code is two
// things, and this is the pair that says so: the same code 8, once as a
// counter poll a maintenance tool makes all day and once as the frame that
// takes a device off the bus.
func TestOneDiagnosticCodeIsTwoDifferentThings(t *testing.T) {
	poll, err := ParseRequest([]byte{FCDiagnostic, 0x00, 0x0B, 0x00, 0x00})
	if err != nil {
		t.Fatalf("a bus message count poll did not parse: %v", err)
	}
	if poll.SubName() != "return_bus_message_count" {
		t.Errorf("sub-function 11 is named %q", poll.SubName())
	}
	if e, ok := poll.SubEffect(); !ok || e != SubRead || e.Unsafe() {
		t.Errorf("reading a counter is %q, unsafe %t", e, e.Unsafe())
	}

	listenOnly, err := ParseRequest([]byte{FCDiagnostic, 0x00, 0x04, 0x00, 0x00})
	if err != nil {
		t.Fatalf("a force listen only did not parse: %v", err)
	}
	if listenOnly.SubName() != "force_listen_only" {
		t.Errorf("sub-function 4 is named %q", listenOnly.SubName())
	}
	e, ok := listenOnly.SubEffect()
	if !ok || e != SubControl {
		t.Errorf("forcing listen-only mode is %q", e)
	}
	if !e.Unsafe() {
		t.Error("forcing a device into listen-only mode is not classified as unsafe, " +
			"so a rule allowing function code 8 would allow it")
	}
}

// A sub-function nobody here knows is a thing to write a rule about, and
// its name says which namespace it came from: sub-function 4 of a
// diagnostic and UMAS command 4 are not the same thing.
func TestASubFunctionThisPackageDoesNotKnowIsNamedInItsOwnNamespace(t *testing.T) {
	for _, c := range []struct {
		fc   byte
		sub  uint16
		name string
	}{
		{FCDiagnostic, 37, "sub_37"},
		{FCUMAS, 130, "umas_130"},
		{FCEncapsulatedInterface, 9, "mei_9"},
	} {
		if got := SubName(c.fc, c.sub); got != c.name {
			t.Errorf("SubName(%d, %d) = %q, want %q", c.fc, c.sub, got, c.name)
		}
		e, ok := SubEffectOf(c.fc, c.sub)
		if !ok {
			t.Errorf("function code %d reports no sub-functions", c.fc)
		}
		if e != SubUnknown || !e.Unsafe() {
			t.Errorf("an unrecognised sub-function of %d is %q, unsafe %t", c.fc, e, e.Unsafe())
		}
	}
	// A function code with no sub-function at all is the other answer, and
	// the distinction is what lets a rule about an effect refuse to match
	// a register read rather than matching it as "unknown".
	if e, ok := SubEffectOf(FCReadHoldingRegisters, 0); ok {
		t.Errorf("reading holding registers reports a sub-function effect %q", e)
	}
}

// Every name this package produces is a name it reads back. The learning
// report writes one into a rule, and an operator writes one from a trace,
// so a name that did not round-trip would be a rule that fails to compile
// on the shift after enforcement went on.
func TestEverySubFunctionNameRoundTrips(t *testing.T) {
	for fc, subs := range subFunctions {
		for sub := range subs {
			name := SubName(fc, sub)
			got, ok := SubCode(fc, name)
			if !ok || got != sub {
				t.Errorf("SubCode(%d, %q) = %d, %t; want %d", fc, name, got, ok, sub)
			}
		}
		// And the generated form, for a sub-function the table does not
		// have a name for.
		for _, sub := range []uint16{37, 99} {
			if got, ok := SubCode(fc, SubName(fc, sub)); !ok || got != sub {
				t.Errorf("SubCode(%d, %q) = %d, %t", fc, SubName(fc, sub), got, ok)
			}
		}
	}
	// A name from another namespace is not a name in this one.
	if _, ok := SubCode(FCDiagnostic, "umas_4"); ok {
		t.Error("a UMAS command number was accepted as a diagnostic sub-function")
	}
	if _, ok := SubCode(FCDiagnostic, "stop_plc"); ok {
		t.Error("a UMAS command name was accepted as a diagnostic sub-function")
	}
	// A UMAS command is a byte, so a number that does not fit in one is
	// refused here rather than compiled into a rule that cannot match.
	if _, ok := SubCode(FCUMAS, "300"); ok {
		t.Error("300 was accepted as a UMAS command")
	}
	if _, ok := SubCode(FCReadHoldingRegisters, "0"); ok {
		t.Error("a function code with no sub-functions accepted one")
	}
}

// UMAS is the vendor half of the finding: function code 90 carries a PLC
// stop and a program download, and a relay that called the whole code
// "vendor" could not tell one from a variable read.
func TestAUMASFrameIsParsedDownToItsCommand(t *testing.T) {
	// 5A <session> <command> <payload>: stop the PLC.
	stop, err := ParseRequest([]byte{FCUMAS, 0x21, 0x41, 0x00})
	if err != nil {
		t.Fatalf("a UMAS stop did not parse: %v", err)
	}
	if !stop.Known {
		t.Error("function code 90 is still an unknown code")
	}
	if FunctionName(FCUMAS) != "umas" {
		t.Errorf("function code 90 is named %q", FunctionName(FCUMAS))
	}
	if !stop.HasSession || stop.Session != 0x21 {
		t.Errorf("the session byte is %d, present %t", stop.Session, stop.HasSession)
	}
	if stop.SubName() != "stop_plc" {
		t.Errorf("command 0x41 is named %q", stop.SubName())
	}
	if e, _ := stop.SubEffect(); e != SubControl || !e.Unsafe() {
		t.Errorf("stopping a PLC is %q, unsafe %t", e, e.Unsafe())
	}
	if stop.ByteCount != 1 {
		t.Errorf("the payload is %d bytes, want 1", stop.ByteCount)
	}

	// A program block going either way is the effect that matters most,
	// and a block read out of a PLC is classified with the one written in:
	// it changes nothing and it is the step before a change that is
	// tailored to what the plant actually runs.
	for _, c := range []struct {
		cmd  byte
		name string
	}{{0x31, "upload_block"}, {0x34, "download_block"}} {
		p, err := ParseRequest([]byte{FCUMAS, 0x21, c.cmd})
		if err != nil {
			t.Fatalf("UMAS 0x%02x did not parse: %v", c.cmd, err)
		}
		if p.SubName() != c.name {
			t.Errorf("command 0x%02x is named %q, want %q", c.cmd, p.SubName(), c.name)
		}
		if e, _ := p.SubEffect(); e != SubProgram || !e.Unsafe() {
			t.Errorf("%s is %q, unsafe %t", c.name, e, e.Unsafe())
		}
	}

	// A frame that ends before the command does is not a frame to decide
	// about.
	if _, err := ParseRequest([]byte{FCUMAS, 0x21}); !errors.Is(err, ErrShort) {
		t.Errorf("a UMAS frame with no command parsed: %v", err)
	}
}

// Whatever a UMAS command is, the frame counts as a write. Not because
// every command changes something -- read_variables does not -- but
// because what these codes mean is published research and not a
// specification, and a read-only listener cannot vouch for a reading like
// that.
func TestAUMASFrameCountsAsAWriteWhateverItsCommand(t *testing.T) {
	for _, cmd := range []byte{0x22, 0x23, 0x41, 0x90} {
		p, err := ParseRequest([]byte{FCUMAS, 0x21, cmd})
		if err != nil {
			t.Fatalf("UMAS 0x%02x: %v", cmd, err)
		}
		if !p.Writes() {
			t.Errorf("UMAS command 0x%02x does not count as a write", cmd)
		}
		if p.SafeUnderReadOnly() {
			t.Errorf("UMAS command 0x%02x would pass a read-only listener", cmd)
		}
	}
}

// The encapsulated interface is the third code with a second code inside
// it, and the two MEI types are not the same kind of thing: one asks the
// device what it is and the other is a tunnel carrying a second protocol.
func TestTheCANopenTunnelIsNotClassifiedAsAnIdentificationRequest(t *testing.T) {
	ident, err := ParseRequest([]byte{FCEncapsulatedInterface, 14, 1, 0})
	if err != nil {
		t.Fatalf("a device identification request did not parse: %v", err)
	}
	if e, _ := ident.SubEffect(); e != SubRead || e.Unsafe() {
		t.Errorf("reading the device identification is %q, unsafe %t", e, e.Unsafe())
	}
	tunnel, err := ParseRequest([]byte{FCEncapsulatedInterface, 13, 0})
	if err != nil {
		t.Fatalf("a CANopen request did not parse: %v", err)
	}
	if tunnel.SubName() != "canopen" {
		t.Errorf("MEI type 13 is named %q", tunnel.SubName())
	}
	e, _ := tunnel.SubEffect()
	if e != SubUnknown || !e.Unsafe() {
		t.Errorf("a tunnel carrying whatever CANopen carries is %q, unsafe %t", e, e.Unsafe())
	}
}

// SubNames is what the validator's error message and the configuration
// reference are written from, so it has to be in an order a reader can
// use and it has to be complete.
func TestTheKnownSubFunctionsAreListedInOrder(t *testing.T) {
	for fc, subs := range subFunctions {
		names := SubNames(fc)
		if len(names) != len(subs) {
			t.Errorf("function code %d has %d sub-functions and lists %d", fc, len(subs), len(names))
		}
		var last int
		for _, name := range names {
			n, ok := SubCode(fc, name)
			if !ok {
				t.Fatalf("SubNames(%d) produced %q, which SubCode refuses", fc, name)
			}
			if int(n) < last {
				t.Errorf("SubNames(%d) is out of order at %q", fc, name)
			}
			last = int(n)
		}
	}
	if SubNames(FCReadHoldingRegisters) == nil {
		t.Error("SubNames of a code with no sub-functions should be an empty list, not nil")
	}
	if SubMax(FCReadHoldingRegisters) != -1 {
		t.Errorf("SubMax of a code with no sub-functions is %d", SubMax(FCReadHoldingRegisters))
	}
}

// Every effect the policy can name is an effect this package produces a
// name for, and the other way round: a name in the documentation that
// ParseSubEffect refused would be a rule nobody could write.
func TestEveryEffectNameParses(t *testing.T) {
	for _, e := range SubEffects() {
		got, ok := ParseSubEffect(string(e))
		if !ok || got != e {
			t.Errorf("ParseSubEffect(%q) = %q, %t", e, got, ok)
		}
	}
	if _, ok := ParseSubEffect("destructive"); ok {
		t.Error("ParseSubEffect accepted a name that is not an effect")
	}
	// Every effect in the tables is one of the named ones.
	named := map[SubEffect]bool{}
	for _, e := range SubEffects() {
		named[e] = true
	}
	for fc, subs := range subFunctions {
		for sub, t2 := range subs {
			if !named[t2.Effect] {
				t.Errorf("function code %d sub-function %d has effect %q, which is not in SubEffects()",
					fc, sub, t2.Effect)
			}
		}
	}
}
