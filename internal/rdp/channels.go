package rdp

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// The channel list. A client announces the virtual channels it wants
// in its network block, and the server answers with an identifier for
// each, in the same order. Every redirection RDP has -- drives,
// printers, serial and parallel ports, smart cards, the clipboard,
// audio -- rides one of these, so the list is where a gateway decides
// what a session can do.

// MaxChannels bounds a channel list. The protocol's own ceiling is
// thirty one static channels; a peer asking for more is not a peer to
// negotiate with.
const MaxChannels = 31

// ChannelNameLen is the fixed width of a channel name: seven
// characters and a terminator.
const ChannelNameLen = 8

// The channel option flags of MS-RDPBCGR 2.2.1.3.4.1. Only the ones
// this gateway reasons about are named.
const (
	ChannelOptionInitialized   = 0x80000000
	ChannelOptionEncryptRDP    = 0x40000000
	ChannelOptionCompressRDP   = 0x00800000
	ChannelOptionShowProtocol  = 0x00200000
	ChannelOptionRemoteControl = 0x00100000
)

// The channels with a meaning worth naming, which is what a policy is
// written in terms of.
const (
	ChannelDeviceRedirection = "rdpdr"   // drives, printers, ports, smart cards
	ChannelClipboard         = "cliprdr" // the clipboard, including file copy
	ChannelSound             = "rdpsnd"  // audio out
	ChannelAudioIn           = "audin"   // the microphone
	ChannelDynamic           = "drdynvc" // dynamic channels, which carry more of the above
	ChannelRemoteApp         = "rail"    // seamless applications
	ChannelMultiTransport    = "rdpemt"  // side band transports
	ChannelEcho              = "echo"    // a round trip measurement
)

// Channel is one entry of the list.
type Channel struct {
	Name    string
	Options uint32
}

// ParseChannels reads a client's network block.
func ParseChannels(data []byte) ([]Channel, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("%w: a network block of %d bytes", ErrMCS, len(data))
	}
	n := int(binary.LittleEndian.Uint32(data[0:4]))
	if n > MaxChannels {
		return nil, fmt.Errorf("%w: %d channels, over the %d the protocol allows", ErrMCS, n, MaxChannels)
	}
	if 4+n*12 > len(data) {
		return nil, fmt.Errorf("%w: %d channels with %d bytes for them", ErrMCS, n, len(data)-4)
	}
	out := make([]Channel, 0, n)
	for i := 0; i < n; i++ {
		b := data[4+i*12:]
		out = append(out, Channel{
			Name:    channelName(b[:ChannelNameLen]),
			Options: binary.LittleEndian.Uint32(b[ChannelNameLen : ChannelNameLen+4]),
		})
	}
	return out, nil
}

// channelName trims the fixed field at its terminator. A name is
// compared case-insensitively everywhere else, because clients differ
// on the spelling of their own channels.
func channelName(b []byte) string {
	if i := indexZero(b); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func indexZero(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}

// EncodeChannels renders a network block.
func EncodeChannels(chans []Channel) ([]byte, error) {
	if len(chans) > MaxChannels {
		return nil, fmt.Errorf("%w: %d channels, over the %d the protocol allows", ErrMCS, len(chans), MaxChannels)
	}
	out := binary.LittleEndian.AppendUint32(nil, uint32(len(chans))) //nolint:gosec // bounded above
	for _, c := range chans {
		if len(c.Name) >= ChannelNameLen {
			return nil, fmt.Errorf("%w: channel name %q is over %d characters", ErrMCS, c.Name, ChannelNameLen-1)
		}
		field := make([]byte, ChannelNameLen)
		copy(field, c.Name)
		out = append(out, field...)
		out = binary.LittleEndian.AppendUint32(out, c.Options)
	}
	return out, nil
}

// ServerChannels is the server's answer: the identifier of the channel
// that carries the session itself, and one identifier per channel the
// client asked for, in the order it asked.
type ServerChannels struct {
	IOChannel uint16
	IDs       []uint16
}

// ParseServerChannels reads a server's network block.
func ParseServerChannels(data []byte) (ServerChannels, error) {
	var s ServerChannels
	if len(data) < 4 {
		return s, fmt.Errorf("%w: a server network block of %d bytes", ErrMCS, len(data))
	}
	s.IOChannel = binary.LittleEndian.Uint16(data[0:2])
	n := int(binary.LittleEndian.Uint16(data[2:4]))
	if n > MaxChannels {
		return s, fmt.Errorf("%w: %d channel ids, over the %d the protocol allows", ErrMCS, n, MaxChannels)
	}
	if 4+n*2 > len(data) {
		return s, fmt.Errorf("%w: %d channel ids with %d bytes for them", ErrMCS, n, len(data)-4)
	}
	s.IDs = make([]uint16, 0, n)
	for i := 0; i < n; i++ {
		s.IDs = append(s.IDs, binary.LittleEndian.Uint16(data[4+i*2:]))
	}
	return s, nil
}

// Encode renders a server network block. The list is padded to a whole
// number of four byte words, which is what the protocol asks for and
// what clients expect to find.
func (s ServerChannels) Encode() ([]byte, error) {
	if len(s.IDs) > MaxChannels {
		return nil, fmt.Errorf("%w: %d channel ids, over the %d the protocol allows", ErrMCS, len(s.IDs), MaxChannels)
	}
	out := binary.LittleEndian.AppendUint16(nil, s.IOChannel)
	out = binary.LittleEndian.AppendUint16(out, uint16(len(s.IDs))) //nolint:gosec // bounded above
	for _, id := range s.IDs {
		out = binary.LittleEndian.AppendUint16(out, id)
	}
	if len(s.IDs)%2 != 0 {
		out = append(out, 0, 0)
	}
	return out, nil
}

// EqualNames compares two channel names the way the protocol's own
// implementations do, which is without regard to case.
func EqualNames(a, b string) bool { return strings.EqualFold(a, b) }
