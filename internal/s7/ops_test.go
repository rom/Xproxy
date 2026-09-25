package s7

import (
	"strings"
	"testing"
)

// The user-data layer and the vocabulary it maps onto, which is where most
// of this protocol's dangerous operations live.
func TestTheUserDataLayerIsRead(t *testing.T) {
	// Reading a system status list: the request an inventory is built from.
	p, err := ParseS7(s7user(1, 0x11, UserRequest<<4|GroupCPU, 0x01, 0, []byte{0xff, 0x09}))
	if err != nil {
		t.Fatal(err)
	}
	u, ok := p.UserData()
	if !ok {
		t.Fatal("the user-data parameter did not lay out")
	}
	if u.Group != GroupCPU || u.Sub != 0x01 || !u.Request() {
		t.Errorf("userdata = %+v", u)
	}
	if u.Name() != "cpu.read_szl" {
		t.Errorf("name = %q", u.Name())
	}
	if op, ok := p.Op(); !ok || op != OpSZL {
		t.Errorf("op = %q, %v", op, ok)
	}

	for _, c := range []struct {
		name  string
		group uint8
		sub   uint8
		op    Op
		named string
	}{
		{"setting the clock", GroupTime, 0x02, OpTimeWrite, "time.set_clock"},
		{"reading the clock", GroupTime, 0x01, OpTimeRead, "time.read_clock"},
		{"supplying a password", GroupSecurity, 0x01, OpSecurity, "security.set_password"},
		{"forcing a variable", GroupProgrammer, 0x08, OpProgrammer, "programmer.force"},
		{"setting a breakpoint", GroupProgrammer, 0x0c, OpProgrammer, "programmer.breakpoint"},
		{"a mode transition", GroupMode, 0x01, OpMode, "mode_transition.stop"},
		{"listing blocks", GroupBlock, 0x01, OpBlocks, "block.list_blocks"},
		{"subscribing to cyclic data", GroupCyclic, 0x01, OpCyclic, "cyclic.subscribe"},
		{"the message service", GroupCPU, 0x02, OpDiagnostics, "cpu.message_service"},
		{"block communication", GroupPBC, 0x01, OpPBC, "pbc.0x1"},
		{"numerical control", GroupNC, 0x01, OpNC, "nc.0x1"},
	} {
		p, err := ParseS7(s7user(1, 0x11, UserRequest<<4|c.group, c.sub, 0, nil))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		u, ok := p.UserData()
		if !ok {
			t.Errorf("%s: the parameter did not lay out", c.name)
			continue
		}
		if u.Name() != c.named {
			t.Errorf("%s: name = %q, want %q", c.name, u.Name(), c.named)
		}
		op, ok := p.Op()
		if !ok || op != c.op {
			t.Errorf("%s: op = %q, %v, want %q", c.name, op, ok, c.op)
		}
	}
}

func TestUserDataThatDoesNotLayOutIsNotAnOperation(t *testing.T) {
	for _, c := range []struct {
		name  string
		param []byte
	}{
		{"no marker", []byte{0x00, 0x02, 0x12, 0x04, 0x11, 0x44, 0x01, 0x00}},
		{"a parameter length past the frame", []byte{0x00, 0x01, 0x12, 0x40, 0x11, 0x44, 0x01, 0x00}},
		{"a parameter length below the minimum", []byte{0x00, 0x01, 0x12, 0x02, 0x11, 0x44, 0x01, 0x00}},
		{"too short", []byte{0x00, 0x01, 0x12, 0x04}},
	} {
		b := cat([]byte{ProtocolID, uint8(Userdata), 0, 0}, be16(1),
			be16(uint16(len(c.param))), be16(0), c.param)
		p, err := ParseS7(b)
		if err != nil {
			continue
		}
		if _, ok := p.UserData(); ok {
			t.Errorf("%s: the parameter laid out", c.name)
		}
		if _, ok := p.Op(); ok {
			t.Errorf("%s: it was named an operation", c.name)
		}
	}
	// A group outside the nine, and a time subfunction outside the four:
	// both unknown rather than guessed at, and the time one matters because
	// the group can set a clock.
	for _, c := range []struct{ group, sub uint8 }{{0x09, 0x01}, {GroupTime, 0x77}} {
		p, _ := ParseS7(s7user(1, 0x11, UserRequest<<4|c.group, c.sub, 0, nil))
		if op, ok := p.Op(); ok {
			t.Errorf("group %#x sub %#x was named %q", c.group, c.sub, op)
		}
	}
}

func TestEveryFunctionCodeMapsOntoTheVocabulary(t *testing.T) {
	for _, c := range []struct {
		fn uint8
		op Op
	}{
		{FnReadVar, OpRead},
		{FnWriteVar, OpWrite},
		{FnSetupComm, OpSetup},
		{FnStartUpload, OpUpload},
		{FnUpload, OpUpload},
		{FnEndUpload, OpUpload},
		{FnRequestDownload, OpDownload},
		{FnDownloadBlock, OpDownload},
		{FnDownloadEnded, OpDownload},
		{FnPLCControl, OpControl},
		{FnPLCStop, OpStop},
		{FnCPUServices, OpCPUServices},
	} {
		p, err := ParseS7(s7job(1, []byte{c.fn}, nil))
		if err != nil {
			t.Fatal(err)
		}
		op, ok := p.Op()
		if !ok || op != c.op {
			t.Errorf("%s: op = %q, %v, want %q", p.FunctionName(), op, ok, c.op)
		}
	}
	// A function code nobody documents is not an operation this relay has a
	// policy for.
	p, _ := ParseS7(s7job(1, []byte{0x77}, nil))
	if op, ok := p.Op(); ok {
		t.Errorf("function 0x77 was named %q", op)
	}
}

// The classifications, asserted against each other rather than described in
// a comment.
func TestTheVocabularyIsConsistent(t *testing.T) {
	names := map[string]bool{}
	for _, n := range Ops() {
		if names[n] {
			t.Errorf("%q is listed twice", n)
		}
		names[n] = true
		op, ok := OpOf(n)
		if !ok || string(op) != n {
			t.Errorf("%q does not round trip", n)
		}
		if strings.ContainsAny(n, " .") {
			t.Errorf("%q is not a policy word", n)
		}
	}
	if _, ok := OpOf("not_an_operation"); ok {
		t.Error("a name nobody defines is an operation")
	}
	// Nothing in the default list changes the PLC, which is the whole of
	// what makes it a default worth having.
	for _, o := range DefaultOps() {
		if Writes(o) {
			t.Errorf("the default list allows %q, which changes the PLC", o)
		}
		if _, ok := OpOf(string(o)); !ok {
			t.Errorf("the default list names %q, which is not an operation", o)
		}
	}
	// An application can still do its work.
	for _, want := range []Op{OpSetup, OpRead, OpSZL} {
		found := false
		for _, o := range DefaultOps() {
			if o == want {
				found = true
			}
		}
		if !found {
			t.Errorf("the default list does not allow %q, so a client cannot work", want)
		}
	}
	// The refusals that monitor mode keeps are exactly the writing set: on
	// this protocol a forwarded write is a moved actuator, a stopped CPU or
	// a changed program, and a report afterwards undoes none of them.
	for _, o := range ops {
		if Dangerous(o) != Writes(o) {
			t.Errorf("%q: dangerous = %v, writes = %v", o, Dangerous(o), Writes(o))
		}
	}
	// And the operations an engineering station needs are all outside the
	// default, which is the sentence the documentation makes.
	for _, o := range []Op{OpWrite, OpDownload, OpUpload, OpControl, OpStop, OpProgrammer,
		OpSecurity, OpTimeWrite, OpMode} {
		for _, d := range DefaultOps() {
			if o == d {
				t.Errorf("%q is in the default list", o)
			}
		}
	}
	// Every group name and every function name is a real one.
	for _, n := range GroupNames() {
		if code, ok := GroupOf(n); !ok || GroupName(code) != n {
			t.Errorf("group %q does not round trip", n)
		}
	}
	for _, n := range FunctionNames() {
		if !strings.Contains(n, "_") && n != "upload" {
			t.Errorf("function name %q is not in the protocol's spelling", n)
		}
	}
	for _, n := range []string{"pg", "op", "basic"} {
		if code, ok := ResourceOf(n); !ok || ResourceName(code) != n {
			t.Errorf("resource %q does not round trip", n)
		}
	}
}
