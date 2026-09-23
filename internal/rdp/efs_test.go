package rdp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestChannelChunkRoundTrip(t *testing.T) {
	c := ChannelChunk{Total: 40, Flags: ChannelFlagFirst | ChannelFlagLast, Data: []byte("rdpdr message")}
	got, err := ParseChannelChunk(c.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if got.Total != 40 || got.Flags != c.Flags || string(got.Data) != "rdpdr message" {
		t.Errorf("read %+v", got)
	}
	if got.Compressed() {
		t.Error("an uncompressed chunk was read as compressed")
	}
	c.Flags |= ChannelPacketCompressed
	if back, _ := ParseChannelChunk(c.Encode()); !back.Compressed() {
		t.Error("a compressed chunk was read as plain")
	}
	if _, err := ParseChannelChunk([]byte{1, 2, 3}); !errors.Is(err, ErrMCS) {
		t.Error("a chunk shorter than its header was accepted")
	}
}

// The announcement round-trips, and what is left after a filter is an
// announcement of the devices that survived.
func TestDeviceAnnounceRoundTrip(t *testing.T) {
	want := []Device{
		{Type: DeviceFilesystem, ID: 1, Name: "C:", Data: []byte("share\x00")},
		{Type: DeviceSerial, ID: 2, Name: "COM1"},
		{Type: DevicePrinter, ID: 3, Name: "PRN1", Data: bytes.Repeat([]byte{0xAA}, 64)},
		{Type: DeviceSmartcard, ID: 4, Name: "SCARD"},
	}
	msg, err := EncodeDeviceAnnounce(want)
	if err != nil {
		t.Fatal(err)
	}
	if !IsDeviceAnnounce(msg) {
		t.Fatal("what was encoded is not recognised as an announcement")
	}
	got, err := ParseDeviceAnnounce(msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("%d devices", len(got))
	}
	for i := range want {
		if got[i].Type != want[i].Type || got[i].ID != want[i].ID ||
			got[i].Name != want[i].Name || !bytes.Equal(got[i].Data, want[i].Data) {
			t.Errorf("device %d: %+v, want %+v", i, got[i], want[i])
		}
	}

	// Keeping only the printer leaves an announcement of one device.
	only, err := EncodeDeviceAnnounce(got[2:3])
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseDeviceAnnounce(only)
	if err != nil {
		t.Fatal(err)
	}
	if len(back) != 1 || back[0].Type != DevicePrinter {
		t.Errorf("after the filter: %+v", back)
	}

	// Refusing every one of them is an announcement of none, which is
	// a session with no redirection rather than a broken channel.
	none, err := EncodeDeviceAnnounce(nil)
	if err != nil {
		t.Fatal(err)
	}
	if devices, err := ParseDeviceAnnounce(none); err != nil || len(devices) != 0 {
		t.Errorf("an empty announcement: %+v (%v)", devices, err)
	}
}

// Something that is not an announcement is not filtered as one.
func TestOnlyTheAnnouncementIsFiltered(t *testing.T) {
	other := binary.LittleEndian.AppendUint16(nil, rdpdrComponentCore)
	other = binary.LittleEndian.AppendUint16(other, PakidDeviceListRemove)
	if IsDeviceAnnounce(other) {
		t.Error("a removal was read as an announcement")
	}
	if _, err := ParseDeviceAnnounce(other); !errors.Is(err, ErrMCS) {
		t.Error("a removal was parsed as an announcement")
	}
	if IsDeviceAnnounce([]byte{1, 2}) {
		t.Error("two bytes were read as an announcement")
	}
}

// Every length in the announcement is the client's to choose, so each
// is checked before it is used.
func TestDeviceAnnounceLengthsAreChecked(t *testing.T) {
	head := binary.LittleEndian.AppendUint16(nil, rdpdrComponentCore)
	head = binary.LittleEndian.AppendUint16(head, PakidDeviceListAnnounce)

	many := binary.LittleEndian.AppendUint32(append([]byte(nil), head...), 1000)
	if _, err := ParseDeviceAnnounce(many); !errors.Is(err, ErrMCS) {
		t.Error("a thousand devices were accepted")
	}
	one := binary.LittleEndian.AppendUint32(append([]byte(nil), head...), 1)
	if _, err := ParseDeviceAnnounce(one); !errors.Is(err, ErrMCS) {
		t.Error("a device with no header was accepted")
	}
	// A device whose data length runs past the message.
	dev := make([]byte, 20)
	binary.LittleEndian.PutUint32(dev[0:4], DeviceFilesystem)
	binary.LittleEndian.PutUint32(dev[16:20], 0xFFFF)
	if _, err := ParseDeviceAnnounce(append(one, dev...)); !errors.Is(err, ErrMCS) {
		t.Error("device data past the message was accepted")
	}
	// And on the way out.
	if _, err := EncodeDeviceAnnounce(make([]Device, MaxDevices+1)); !errors.Is(err, ErrMCS) {
		t.Error("an oversize announcement was encoded")
	}
	if _, err := EncodeDeviceAnnounce([]Device{{Data: make([]byte, maxDeviceData+1)}}); !errors.Is(err, ErrMCS) {
		t.Error("oversize device data was encoded")
	}
}

func TestDeviceTypeNames(t *testing.T) {
	for name, want := range map[string]uint32{
		"drive": DeviceFilesystem, "serial": DeviceSerial, "parallel": DeviceParallel,
		"printer": DevicePrinter, "smartcard": DeviceSmartcard,
	} {
		got, ok := DeviceTypeByName(name)
		if !ok || got != want {
			t.Errorf("%q parsed as %d (%v)", name, got, ok)
		}
	}
	if DeviceTypeName(DeviceFilesystem) != "drive" {
		t.Errorf("the filesystem type is named %q", DeviceTypeName(DeviceFilesystem))
	}
	if _, ok := DeviceTypeByName("webcam"); ok {
		t.Error("a device type this gateway cannot name was accepted")
	}
}
