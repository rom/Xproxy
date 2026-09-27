package rdp

import (
	"encoding/binary"
	"fmt"
)

// Dynamic virtual channels: MS-RDPEDYC, the extension that carries most of
// what a modern RDP session actually does.
//
// The static channel list in the conference exchange is what a gateway policy
// has always been written about: a client asks for `cliprdr`, `rdpdr`,
// `rdpsnd`, and the policy says yes or no to each by name. But one of those
// static channels, `drdynvc`, is a *multiplexer*: inside it channels are opened
// and closed by name at any time during the session, and the graphics pipeline,
// display control, geometry tracking, camera, audio and -- the point -- device
// and clipboard redirection all ride there on a current Windows client.
//
// So a gateway that read only the static list had a hole with a specific shape.
// Allowing `drdynvc` -- which an operator must do for a usable session on
// anything recent -- allowed every dynamic channel inside it, unexamined and
// unlogged. A clipboard or drive channel refused by name in the static list
// could be opened again inside the one that was allowed.
//
// **Two things about this protocol decide the design, and both are the reverse
// of the obvious guess.**
//
// The *server* opens a dynamic channel, not the client: DYNVC_CREATE_REQ
// travels from the desktop to the client, carrying the channel's name, and the
// client answers with a creation status. So the name a policy decides about
// appears in the desktop-to-client direction, which is the direction a gateway
// has least reason to be reading -- and a gateway that inspected only what the
// client sends would never see a channel name at all.
//
// And Cmd 0x01 means two different PDUs depending on which way it is going: a
// create *request* from the server carries a name, a create *response* from the
// client carries a 32-bit status. Nothing in the octets distinguishes them, so
// the parser is told which side sent the PDU rather than guessing.
//
// Reference: MS-RDPEDYC sections 2.2.1 to 2.2.5.

// DVCSide says who sent a PDU, which is what tells a create request from a
// create response.
type DVCSide int

// The two sides.
const (
	// FromServer is the desktop's side: it sends create requests, closes and
	// capability requests.
	FromServer DVCSide = iota
	// FromClient is the client's side: it answers them.
	FromClient
)

// The Cmd values of the DVC header (MS-RDPEDYC 2.2, the Cmd field).
const (
	DVCCreate              uint8 = 0x01
	DVCDataFirst           uint8 = 0x02
	DVCData                uint8 = 0x03
	DVCClose               uint8 = 0x04
	DVCCapability          uint8 = 0x05
	DVCDataFirstCompressed uint8 = 0x06
	DVCDataCompressed      uint8 = 0x07
	DVCSoftSyncRequest     uint8 = 0x08
	DVCSoftSyncResponse    uint8 = 0x09
)

// DVCCmdName names a command, or reports the number for one the standard does
// not define.
func DVCCmdName(cmd uint8) string {
	switch cmd {
	case DVCCreate:
		return "create"
	case DVCDataFirst:
		return "data_first"
	case DVCData:
		return "data"
	case DVCClose:
		return "close"
	case DVCCapability:
		return "capability"
	case DVCDataFirstCompressed:
		return "data_first_compressed"
	case DVCDataCompressed:
		return "data_compressed"
	case DVCSoftSyncRequest:
		return "soft_sync_request"
	case DVCSoftSyncResponse:
		return "soft_sync_response"
	}
	return fmt.Sprintf("cmd_%#x", cmd)
}

// MaxDVCName bounds a dynamic channel name. The names the protocol's own
// listeners use are well under this -- the longest Microsoft ships is around
// forty characters -- so a name longer than this is not a name.
const MaxDVCName = 128

// DVC is one dynamic-channel PDU, read as far as a policy needs.
type DVC struct {
	// Cmd is what this PDU is.
	Cmd uint8
	// Sp is the two bits whose meaning depends on Cmd: a priority class on a
	// create, unused elsewhere.
	Sp uint8
	// ChannelID identifies the dynamic channel, and HasChannelID says this
	// PDU carries one -- a capability negotiation and a soft sync do not.
	ChannelID    uint32
	HasChannelID bool
	// Name is the channel name a create request carries, and HasName says
	// there was one. Only a create request from the *server* has a name.
	Name    string
	HasName bool
	// Status is the creation status a create response carries, signed as the
	// standard defines it: negative is a failure.
	Status    int32
	HasStatus bool
}

// dvcChannelIDLen is what the cbId bits say the identifier's width is.
//
// The value 3 is defined as invalid rather than as a width, so it is refused:
// a PDU whose own header says its length field is invalid is not a PDU to
// route a policy decision from.
func dvcChannelIDLen(cbID uint8) (int, bool) {
	switch cbID {
	case 0x00:
		return 1, true
	case 0x01:
		return 2, true
	case 0x02:
		return 4, true
	}
	return 0, false
}

// dvcHasChannelID says whether a command's optional fields begin with one.
// The capability negotiation and the two soft-sync PDUs are about the whole
// static channel rather than about one dynamic channel, so they carry none.
func dvcHasChannelID(cmd uint8) bool {
	switch cmd {
	case DVCCreate, DVCDataFirst, DVCData, DVCClose,
		DVCDataFirstCompressed, DVCDataCompressed:
		return true
	}
	return false
}

// ParseDVC reads one dynamic-channel PDU. side says who sent it, because a
// create request and a create response share a command value and only the
// sender tells them apart.
func ParseDVC(b []byte, side DVCSide) (*DVC, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("%w: an empty dynamic channel PDU", ErrMCS)
	}
	// The header is one octet: the command in the top four bits, two bits
	// whose meaning depends on it, and the width of the identifier in the
	// bottom two.
	head := b[0]
	d := &DVC{Cmd: head >> 4, Sp: (head >> 2) & 0x03}
	rest := b[1:]
	if !dvcHasChannelID(d.Cmd) {
		// A capability negotiation or a soft sync. Neither names a channel,
		// so there is nothing here for a policy about names to decide.
		return d, nil
	}
	n, ok := dvcChannelIDLen(head & 0x03)
	if !ok {
		return nil, fmt.Errorf("%w: a dynamic channel PDU with an invalid identifier width", ErrMCS)
	}
	if len(rest) < n {
		return nil, fmt.Errorf("%w: a %s PDU with %d bytes for a %d byte identifier",
			ErrMCS, DVCCmdName(d.Cmd), len(rest), n)
	}
	switch n {
	case 1:
		d.ChannelID = uint32(rest[0])
	case 2:
		d.ChannelID = uint32(binary.LittleEndian.Uint16(rest[:2]))
	case 4:
		d.ChannelID = binary.LittleEndian.Uint32(rest[:4])
	}
	d.HasChannelID = true
	rest = rest[n:]
	if d.Cmd != DVCCreate {
		return d, nil
	}
	if side == FromClient {
		// A create response: the identifier and a signed status.
		if len(rest) < 4 {
			return nil, fmt.Errorf("%w: a create response with %d bytes for its status", ErrMCS, len(rest))
		}
		d.Status = int32(binary.LittleEndian.Uint32(rest[:4])) //nolint:gosec // the standard's signed HRESULT
		d.HasStatus = true
		return d, nil
	}
	// A create request: the identifier and a null-terminated name.
	name, ok := dvcName(rest)
	if !ok {
		return nil, fmt.Errorf("%w: a create request whose channel name is not a terminated name", ErrMCS)
	}
	d.Name, d.HasName = name, true
	return d, nil
}

// dvcName reads the null-terminated name of a create request.
//
// A name with no terminator is refused rather than taken to the end of the
// PDU: the terminator is how the protocol says where the name ends, and a
// gateway that invented an ending would be deciding a policy about a name the
// client will read differently. The same goes for a control character, which
// no listener name has and which would make a refusal unreadable in a log.
func dvcName(b []byte) (string, bool) {
	i := indexZero(b)
	if i < 0 || i > MaxDVCName {
		return "", false
	}
	name := b[:i]
	if len(name) == 0 {
		return "", false
	}
	for _, c := range name {
		if c < 0x20 || c == 0x7f {
			return "", false
		}
	}
	return string(name), true
}

// EncodeDVCCreateResponse builds the answer a client sends to a create
// request: the same identifier, and a status.
//
// A gateway uses it to refuse a channel in the protocol's own words. The
// alternative -- dropping the create request on the floor -- leaves the
// desktop waiting for an answer that never comes, and a redirection that hangs
// is harder for an administrator to explain than one that was refused.
func EncodeDVCCreateResponse(id uint32, status int32) []byte {
	cb, n := uint8(0x00), 1
	switch {
	case id > 0xFFFF:
		cb, n = 0x02, 4
	case id > 0xFF:
		cb, n = 0x01, 2
	}
	out := []byte{DVCCreate<<4 | cb}
	switch n {
	case 1:
		out = append(out, byte(id))
	case 2:
		out = binary.LittleEndian.AppendUint16(out, uint16(id)) //nolint:gosec // bounded above
	case 4:
		out = binary.LittleEndian.AppendUint32(out, id)
	}
	return binary.LittleEndian.AppendUint32(out, uint32(status)) //nolint:gosec // the standard's signed HRESULT
}

// DVCCreateRefused is the status this gateway answers a refused channel with.
//
// E_NOTIMPL is what a client with no listener of that name reports, which is
// exactly the situation the desktop is being told about: as far as it can tell,
// this client does not implement that channel. A status invented for the
// occasion would be one no desktop has a message for.
const DVCCreateRefused int32 = -2147467263 // 0x80004001 E_NOTIMPL

// EncodeDVCCreateRequest builds a create request, which only a test and a
// desktop have reason to do. It is here so that the encoder and the parser are
// read together rather than one of them living in a test file.
func EncodeDVCCreateRequest(id uint32, name string) []byte {
	cb, n := uint8(0x00), 1
	switch {
	case id > 0xFFFF:
		cb, n = 0x02, 4
	case id > 0xFF:
		cb, n = 0x01, 2
	}
	out := []byte{DVCCreate<<4 | cb}
	switch n {
	case 1:
		out = append(out, byte(id))
	case 2:
		out = binary.LittleEndian.AppendUint16(out, uint16(id)) //nolint:gosec // bounded above
	case 4:
		out = binary.LittleEndian.AppendUint32(out, id)
	}
	out = append(out, name...)
	return append(out, 0x00)
}
