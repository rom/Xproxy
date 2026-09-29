package modbus_test

import (
	"bytes"
	"testing"

	wire "github.com/rom/xproxy/internal/modbus"
)

// An identification exchange through the relay, in every framing.
//
// This is the frame the inventory's firmware version comes from, and the relay
// reads both directions of it: a response it cannot parse is not handed to the
// master at all. The RTU and ASCII framings measure this response by walking
// its object list, so they are the ones worth driving -- a length rule that is
// a field out ends the frame with the objects still on the wire, and the
// device's answer then reads as malformed and is refused.
func TestAnIdentificationExchangeSurvivesEveryFraming(t *testing.T) {
	for _, framing := range []wire.Framing{wire.FramingTCP, wire.FramingRTU, wire.FramingASCII} {
		t.Run(framing.String(), func(t *testing.T) {
			dev := startPLC(t, &plc{framing: framing,
				vendorName: "Schneider Electric", productCode: "BMXP342020", revision: "V3.10"})
			// A rule that lets the master read and ask what the device is,
			// which is what an estate's own policy says: identification is a
			// read, and a plant that polls for it is a plant whose inventory
			// stays current.
			_, addr := modbusServer(t, `        upstream: plc
        framing: `+framing.String()+`
        rules:
          - {name: master, access: [read, identify]}`, map[string]*plc{"plc": dev})

			m := dialMaster(t, addr, framing)
			p, err := m.ask(1, []byte{wire.FCEncapsulatedInterface, wire.MEIIdentification, 0x01, 0x00})
			if err != nil {
				t.Fatalf("the identification request: %v", err)
			}
			if p.IsException {
				t.Fatalf("the device's answer came back as an exception: %+v", p)
			}
			if p.Identity == nil {
				t.Fatal("the answer was not read as an identification")
			}
			if p.Identity.Revision != "V3.10" {
				t.Errorf("revision %q, which is the version the advisory matching compares",
					p.Identity.Revision)
			}
			if p.Identity.Vendor != "Schneider Electric" || p.Identity.ProductCode != "BMXP342020" {
				t.Errorf("identity %+v", p.Identity)
			}
			// And the device saw the request, rather than the relay answering
			// it out of something it remembered.
			if _, ok := dev.saw(wire.FCEncapsulatedInterface); !ok {
				t.Error("the identification request did not reach the device")
			}
		})
	}
}

// The response a device sends when it has more objects than fitted, which is
// how a walk is continued. The relay has to measure that frame too.
func TestAWalkedIdentificationResponseIsMeasured(t *testing.T) {
	// Built by hand rather than from the fake device, because more-follows is
	// what makes this frame different and the device answers basic
	// identification in one.
	pdu := []byte{wire.FCEncapsulatedInterface, wire.MEIIdentification, 0x02, 0x81, 0xFF, 0x04, 0x02,
		wire.IDVendor, 0x04, 'A', 'c', 'm', 'e', wire.IDProductCode, 0x03, 'X', '-', '1'}
	req, err := wire.ParseRequest([]byte{wire.FCEncapsulatedInterface, wire.MEIIdentification, 0x02, 0x00})
	if err != nil {
		t.Fatal(err)
	}
	for _, framing := range []wire.Framing{wire.FramingTCP, wire.FramingRTU, wire.FramingASCII} {
		raw := wire.Encode(framing, &wire.Frame{Transaction: 7, Unit: 1, PDU: pdu})
		// A second frame immediately after it, so a length rule that is wrong
		// by a field reads into it and the checksum says so.
		raw = append(raw, wire.Encode(framing, &wire.Frame{Transaction: 8, Unit: 1,
			PDU: []byte{0xAB, 0x02}})...)
		rd := wire.NewReader(bytes.NewReader(raw), framing, false)
		rd.Expect(wire.FCEncapsulatedInterface)
		f, _, err := rd.ReadFrame()
		if err != nil {
			t.Fatalf("%s: %v", framing, err)
		}
		if !bytes.Equal(f.PDU, pdu) {
			t.Fatalf("%s: pdu % x, want % x", framing, f.PDU, pdu)
		}
		got, err := wire.ParseResponse(f.PDU, req)
		if err != nil {
			t.Fatalf("%s: %v", framing, err)
		}
		if got.Identity == nil || !got.Identity.More || got.Identity.Next != 0x04 {
			t.Errorf("%s: the walk's continuation was not read: %+v", framing, got.Identity)
		}
	}
}
