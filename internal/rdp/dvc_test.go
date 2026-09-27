package rdp

import (
	"testing"
)

// The dynamic channel header, which is one octet carrying three fields and the
// thing every decision about a dynamic channel is read from.

// dvcHeader builds the header octet the way the protocol lays it out: the
// command in the top four bits, two bits whose meaning depends on it, and the
// identifier width in the bottom two.
func dvcHeader(cmd, sp, cbID uint8) byte { return cmd<<4 | sp<<2 | cbID }

func TestTheDVCHeaderIsReadFieldByField(t *testing.T) {
	t.Parallel()
	// The spec's own worked example: a header octet of 0x10 is a create with
	// priority 0 and a one-byte identifier.
	d, err := ParseDVC([]byte{0x10, 0x03, 'e', 'c', 'h', 'o', 0x00}, FromServer)
	if err != nil {
		t.Fatalf("ParseDVC: %v", err)
	}
	if d.Cmd != DVCCreate {
		t.Errorf("cmd %#x", d.Cmd)
	}
	if d.Sp != 0 {
		t.Errorf("sp %d", d.Sp)
	}
	if !d.HasChannelID || d.ChannelID != 3 {
		t.Errorf("channel %d (has %v)", d.ChannelID, d.HasChannelID)
	}
	if !d.HasName || d.Name != "echo" {
		t.Errorf("name %q (has %v)", d.Name, d.HasName)
	}
}

// The identifier is one, two or four bytes, and the fourth value of the width
// field is defined as invalid rather than as a width. A PDU whose own header
// says its length field is invalid is not one to route a decision from.
func TestTheIdentifierWidthIsReadAndTheInvalidOneRefused(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		cbID uint8
		body []byte
		want uint32
	}{
		{0x00, []byte{0x07}, 7},
		{0x01, []byte{0x34, 0x12}, 0x1234},
		{0x02, []byte{0x78, 0x56, 0x34, 0x12}, 0x12345678},
	} {
		in := append([]byte{dvcHeader(DVCData, 0, c.cbID)}, c.body...)
		d, err := ParseDVC(in, FromClient)
		if err != nil {
			t.Fatalf("width %d: %v", c.cbID, err)
		}
		if d.ChannelID != c.want {
			t.Errorf("width %d: channel %#x, want %#x", c.cbID, d.ChannelID, c.want)
		}
	}
	if _, err := ParseDVC([]byte{dvcHeader(DVCData, 0, 0x03), 0, 0, 0, 0}, FromClient); err == nil {
		t.Error("the invalid identifier width parsed")
	}
	// And a PDU too short for the width its header claims.
	if _, err := ParseDVC([]byte{dvcHeader(DVCData, 0, 0x02), 0x01}, FromClient); err == nil {
		t.Error("a PDU too short for its identifier parsed")
	}
}

// The capability negotiation and the two soft-sync PDUs are about the whole
// static channel rather than about one dynamic channel, so they carry no
// identifier. A parser that read one anyway would take a version number for a
// channel.
func TestThePDUsThatNameNoChannel(t *testing.T) {
	t.Parallel()
	for what, cmd := range map[string]uint8{
		"a capability request": DVCCapability,
		"a soft sync request":  DVCSoftSyncRequest,
		"a soft sync response": DVCSoftSyncResponse,
	} {
		d, err := ParseDVC([]byte{dvcHeader(cmd, 0, 0), 0x00, 0x02, 0x00}, FromServer)
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		if d.HasChannelID {
			t.Errorf("%s was given a channel identifier %d", what, d.ChannelID)
		}
		if d.HasName {
			t.Errorf("%s was given a name %q", what, d.Name)
		}
	}
}

// Command 0x01 is two different PDUs depending on which way it travels: a
// create *request* from the desktop carries a name, a create *response* from
// the client carries a status. Nothing in the octets says which, so the side
// does -- and a parser that guessed would read a status as a name.
func TestACreateIsTwoPDUsTheSideTellsApart(t *testing.T) {
	t.Parallel()
	req := []byte{dvcHeader(DVCCreate, 0, 0), 0x05, 'r', 'd', 'p', 'd', 'r', 0x00}
	d, err := ParseDVC(req, FromServer)
	if err != nil {
		t.Fatalf("a create request: %v", err)
	}
	if !d.HasName || d.Name != "rdpdr" || d.HasStatus {
		t.Errorf("the request read as %+v", d)
	}

	// The same command from the client is a response: an identifier and a
	// signed status, where negative is a failure.
	rsp := append([]byte{dvcHeader(DVCCreate, 0, 0), 0x05}, 0x01, 0x40, 0x00, 0x80)
	d, err = ParseDVC(rsp, FromClient)
	if err != nil {
		t.Fatalf("a create response: %v", err)
	}
	if d.HasName {
		t.Errorf("the response was given a name %q", d.Name)
	}
	if !d.HasStatus || d.Status >= 0 {
		t.Errorf("status %d, want a negative one", d.Status)
	}
	// A response with nothing where its status should be is malformed rather
	// than a response with a status of zero, which would read as success.
	if _, err := ParseDVC([]byte{dvcHeader(DVCCreate, 0, 0), 0x05}, FromClient); err == nil {
		t.Error("a create response with no status parsed")
	}
}

// A channel name is null-terminated, and a name with no terminator is refused
// rather than taken to the end of the PDU: the terminator is how the protocol
// says where the name ends, and a gateway that invented an ending would decide
// a policy about a name the client reads differently.
func TestAChannelNameMustBeATerminatedName(t *testing.T) {
	t.Parallel()
	head := []byte{dvcHeader(DVCCreate, 0, 0), 0x05}
	for what, body := range map[string][]byte{
		"no terminator":       []byte("rdpdr"),
		"an empty name":       {0x00},
		"nothing at all":      {},
		"a control character": append([]byte("rdp\x01dr"), 0x00),
		"a tab":               append([]byte("rdp\tdr"), 0x00),
	} {
		if _, err := ParseDVC(append(append([]byte(nil), head...), body...), FromServer); err == nil {
			t.Errorf("%s parsed as a channel name", what)
		}
	}
	// And a name longer than any listener has is not a name.
	long := make([]byte, MaxDVCName+2)
	for i := range long {
		long[i] = 'a'
	}
	if _, err := ParseDVC(append(append([]byte(nil), head...), append(long, 0x00)...), FromServer); err == nil {
		t.Error("an over-long name parsed")
	}
}

// The refusal this gateway writes has to be the answer the desktop expects, so
// it round-trips through the parser that reads a real client's.
func TestTheRefusalIsAnAnswerAClientCouldHaveSent(t *testing.T) {
	t.Parallel()
	for _, id := range []uint32{0, 7, 0xFF, 0x100, 0xFFFF, 0x10000, 0xFFFFFFFF} {
		out := EncodeDVCCreateResponse(id, DVCCreateRefused)
		d, err := ParseDVC(out, FromClient)
		if err != nil {
			t.Fatalf("channel %#x: the refusal does not parse: %v", id, err)
		}
		if d.Cmd != DVCCreate || d.ChannelID != id {
			t.Errorf("channel %#x round-tripped to %+v", id, d)
		}
		if !d.HasStatus || d.Status != DVCCreateRefused || d.Status >= 0 {
			t.Errorf("channel %#x: status %d, want the negative refusal", id, d.Status)
		}
	}
}

// The create request encoder is the other half of that, and a name has to
// survive the trip for a test to mean anything.
func TestACreateRequestRoundTrips(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"echo", "rdpdr", "Microsoft::Windows::RDS::Graphics"} {
		for _, id := range []uint32{1, 0x200, 0x30000} {
			d, err := ParseDVC(EncodeDVCCreateRequest(id, name), FromServer)
			if err != nil {
				t.Fatalf("%q on %#x: %v", name, id, err)
			}
			if d.Name != name || d.ChannelID != id {
				t.Errorf("%q on %#x round-tripped to %q on %#x", name, id, d.Name, d.ChannelID)
			}
		}
	}
}

// Every command has a name, because a refusal an administrator cannot read is
// one they cannot act on.
func TestEveryCommandHasAName(t *testing.T) {
	t.Parallel()
	for cmd, want := range map[uint8]string{
		DVCCreate: "create", DVCDataFirst: "data_first", DVCData: "data",
		DVCClose: "close", DVCCapability: "capability",
		DVCDataFirstCompressed: "data_first_compressed",
		DVCDataCompressed:      "data_compressed",
		DVCSoftSyncRequest:     "soft_sync_request",
		DVCSoftSyncResponse:    "soft_sync_response",
	} {
		if got := DVCCmdName(cmd); got != want {
			t.Errorf("%#x: %q, want %q", cmd, got, want)
		}
	}
	if got := DVCCmdName(0x0F); got != "cmd_0xf" {
		t.Errorf("an undefined command named %q", got)
	}
}

// FuzzParseDVC drives the header parser with arbitrary octets. The invariant
// that matters is the last one: a name only ever comes back for a create
// request from the desktop, because that is the only PDU that carries one --
// and a policy that got a name from anywhere else would be deciding about a
// string it had made up.
func FuzzParseDVC(f *testing.F) {
	f.Add([]byte{0x10, 0x03, 'e', 'c', 'h', 'o', 0x00})
	f.Add([]byte{0x30, 0x03, 0x01, 0x02})
	f.Add([]byte{0x50, 0x00, 0x02, 0x00})
	f.Add([]byte{0x13, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, in []byte) {
		for _, side := range []DVCSide{FromServer, FromClient} {
			d, err := ParseDVC(in, side)
			if err != nil {
				if d != nil {
					t.Fatalf("both a PDU and an error for %x", in)
				}
				continue
			}
			if d.Cmd > 0x0F || d.Sp > 0x03 {
				t.Fatalf("cmd %#x sp %d out of their fields: %x", d.Cmd, d.Sp, in)
			}
			if DVCCmdName(d.Cmd) == "" {
				t.Fatalf("a command with no name: %x", in)
			}
			if d.HasChannelID && !dvcHasChannelID(d.Cmd) {
				t.Fatalf("an identifier on %s: %x", DVCCmdName(d.Cmd), in)
			}
			if d.HasName {
				if side != FromServer || d.Cmd != DVCCreate {
					t.Fatalf("a name on a %s from %v: %x", DVCCmdName(d.Cmd), side, in)
				}
				if d.Name == "" || len(d.Name) > MaxDVCName {
					t.Fatalf("a name of %d characters: %x", len(d.Name), in)
				}
				for _, c := range []byte(d.Name) {
					if c < 0x20 || c == 0x7f {
						t.Fatalf("a control character in a name: %x", in)
					}
				}
			}
			if d.HasStatus && (side != FromClient || d.Cmd != DVCCreate) {
				t.Fatalf("a status on a %s from %v: %x", DVCCmdName(d.Cmd), side, in)
			}
		}
	})
}
