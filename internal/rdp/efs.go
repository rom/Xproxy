package rdp

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// Device redirection, which is what makes a remote desktop session a
// way to move files and reach hardware. Every redirected device --
// a drive, a printer, a serial or parallel port, a smart card -- is
// announced by the client on the rdpdr channel, and nothing can be
// used that was not announced. So a gateway that filters the
// announcement decides which of them exist, per device kind, without
// having to understand the traffic that follows.

// The virtual channel chunk flags of MS-RDPBCGR 2.2.6.1.1.
const (
	ChannelFlagFirst        = 0x00000001
	ChannelFlagLast         = 0x00000002
	ChannelFlagShowProto    = 0x00000010
	ChannelPacketCompressed = 0x00200000
)

// ChannelChunk is one piece of a virtual channel message: how long the
// whole message is, the flags that say where this piece sits in it,
// and the piece itself.
type ChannelChunk struct {
	Total uint32
	Flags uint32
	Data  []byte
}

// ParseChannelChunk reads one.
func ParseChannelChunk(b []byte) (ChannelChunk, error) {
	if len(b) < 8 {
		return ChannelChunk{}, fmt.Errorf("%w: a channel chunk of %d bytes", ErrMCS, len(b))
	}
	return ChannelChunk{
		Total: binary.LittleEndian.Uint32(b[0:4]),
		Flags: binary.LittleEndian.Uint32(b[4:8]),
		Data:  b[8:],
	}, nil
}

// Encode renders a chunk.
func (c ChannelChunk) Encode() []byte {
	out := binary.LittleEndian.AppendUint32(nil, c.Total)
	out = binary.LittleEndian.AppendUint32(out, c.Flags)
	return append(out, c.Data...)
}

// Compressed says whether the chunk's data is compressed, which a
// gateway cannot look inside without decompressing it.
func (c ChannelChunk) Compressed() bool { return c.Flags&ChannelPacketCompressed != 0 }

// The device redirection header of MS-RDPEFS 2.2.1.1.
const (
	rdpdrComponentCore = 0x4472 // "rD", the core component
	// PakidDeviceListAnnounce is the packet this gateway filters, and
	// PakidDeviceListRemove the one that takes a device away again.
	PakidDeviceListAnnounce = 0x4441
	PakidDeviceListRemove   = 0x444D
)

// The device types of MS-RDPEFS 2.2.1.3, which is what a policy names.
const (
	DeviceSerial     = 0x00000001
	DeviceParallel   = 0x00000002
	DevicePrinter    = 0x00000004
	DeviceFilesystem = 0x00000008
	DeviceSmartcard  = 0x00000020
)

// DeviceTypeName names one for a log line and for configuration.
func DeviceTypeName(t uint32) string {
	switch t {
	case DeviceSerial:
		return "serial"
	case DeviceParallel:
		return "parallel"
	case DevicePrinter:
		return "printer"
	case DeviceFilesystem:
		return "drive"
	case DeviceSmartcard:
		return "smartcard"
	}
	return fmt.Sprintf("device-%#x", t)
}

// DeviceTypeByName is the reverse.
func DeviceTypeByName(s string) (uint32, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "serial":
		return DeviceSerial, true
	case "parallel":
		return DeviceParallel, true
	case "printer":
		return DevicePrinter, true
	case "drive", "drives", "filesystem":
		return DeviceFilesystem, true
	case "smartcard":
		return DeviceSmartcard, true
	}
	return 0, false
}

// Device is one announced redirection.
type Device struct {
	Type uint32
	ID   uint32
	// Name is the eight byte name the client gives it, which is what
	// appears in the log when one is refused.
	Name string
	Data []byte
}

// MaxDevices bounds an announcement. A client with more redirected
// devices than this is not a client to reason about.
const MaxDevices = 64

// maxDeviceData bounds one device's own data.
const maxDeviceData = 8192

// IsDeviceAnnounce says whether a reassembled rdpdr message is the
// announcement this gateway filters.
func IsDeviceAnnounce(msg []byte) bool {
	if len(msg) < 4 {
		return false
	}
	return binary.LittleEndian.Uint16(msg[0:2]) == rdpdrComponentCore &&
		binary.LittleEndian.Uint16(msg[2:4]) == PakidDeviceListAnnounce
}

// ParseDeviceAnnounce reads the announcement's device list.
func ParseDeviceAnnounce(msg []byte) ([]Device, error) {
	if !IsDeviceAnnounce(msg) {
		return nil, fmt.Errorf("%w: not a device announcement", ErrMCS)
	}
	if len(msg) < 8 {
		return nil, fmt.Errorf("%w: an announcement of %d bytes", ErrMCS, len(msg))
	}
	n := int(binary.LittleEndian.Uint32(msg[4:8]))
	if n > MaxDevices {
		return nil, fmt.Errorf("%w: %d devices, over the %d bound", ErrMCS, n, MaxDevices)
	}
	rest := msg[8:]
	out := make([]Device, 0, n)
	for i := 0; i < n; i++ {
		if len(rest) < 20 {
			return nil, fmt.Errorf("%w: a device header of %d bytes", ErrMCS, len(rest))
		}
		d := Device{
			Type: binary.LittleEndian.Uint32(rest[0:4]),
			ID:   binary.LittleEndian.Uint32(rest[4:8]),
			Name: channelName(rest[8:16]),
		}
		size := int(binary.LittleEndian.Uint32(rest[16:20]))
		if size > maxDeviceData || 20+size > len(rest) {
			return nil, fmt.Errorf("%w: device data of %d bytes with %d there", ErrMCS, size, len(rest)-20)
		}
		d.Data = rest[20 : 20+size]
		out = append(out, d)
		rest = rest[20+size:]
	}
	return out, nil
}

// EncodeDeviceAnnounce renders an announcement carrying these devices,
// which is what the gateway forwards once the denied ones are gone. An
// empty list is a valid announcement and the one a session gets when
// every redirection it asked for is refused.
func EncodeDeviceAnnounce(devices []Device) ([]byte, error) {
	if len(devices) > MaxDevices {
		return nil, fmt.Errorf("%w: %d devices, over the %d bound", ErrMCS, len(devices), MaxDevices)
	}
	out := binary.LittleEndian.AppendUint16(nil, rdpdrComponentCore)
	out = binary.LittleEndian.AppendUint16(out, PakidDeviceListAnnounce)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(devices))) //nolint:gosec // bounded above
	for _, d := range devices {
		if len(d.Data) > maxDeviceData {
			return nil, fmt.Errorf("%w: device data of %d bytes", ErrMCS, len(d.Data))
		}
		out = binary.LittleEndian.AppendUint32(out, d.Type)
		out = binary.LittleEndian.AppendUint32(out, d.ID)
		name := make([]byte, 8)
		copy(name, d.Name)
		out = append(out, name...)
		out = binary.LittleEndian.AppendUint32(out, uint32(len(d.Data))) //nolint:gosec // bounded above
		out = append(out, d.Data...)
	}
	return out, nil
}
