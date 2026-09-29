package modbus

import (
	"net/netip"
	"testing"

	wire "github.com/rom/xproxy/internal/modbus"
)

// What a device's identification answer becomes in the inventory.
//
// Function code 43 with MEI type 14 is the one place in this protocol where a
// device names its vendor, its product and its firmware revision, and that
// revision is the version the advisory matching compares. So what the three
// fields turn into matters: a model string that does not resemble the way a
// vendor's advisory names the product is a device that never matches anything.
func TestWhatADeviceSaysAboutItselfBecomes(t *testing.T) {
	ip := netip.MustParseAddr("10.30.9.11")
	for _, c := range []struct {
		what     string
		id       wire.DeviceIdentity
		model    string
		maker    string
		firmware string
		ok       bool
	}{
		{
			// A Modicon's basic identification. The product code is the
			// orderable part and is what Schneider's own advisories name, so
			// it goes in beside the model rather than instead of it.
			what: "a model name and a product code",
			id: wire.DeviceIdentity{Vendor: "Schneider Electric", ProductCode: "BMXP342020",
				Revision: "V3.10", Model: "Modicon M340"},
			model: "Modicon M340 BMXP342020", maker: "Schneider Electric",
			firmware: "V3.10", ok: true,
		},
		{
			// Regular identification, where the family name is all there is.
			what: "a product name and no model name",
			id: wire.DeviceIdentity{Vendor: "Siemens", ProductCode: "6ES7", Revision: "V4.2.1",
				Product: "SIMATIC S7-1200 CPU 1212C"},
			model: "SIMATIC S7-1200 CPU 1212C 6ES7", maker: "Siemens",
			firmware: "V4.2.1", ok: true,
		},
		{
			what:  "a product code and nothing else",
			id:    wire.DeviceIdentity{Vendor: "Acme", ProductCode: "AC-500"},
			model: "AC-500", maker: "Acme", ok: true,
		},
		{
			// A device that answered the function and said nothing an
			// inventory can use. There is no record to make, and making one
			// from the unit identifier alone would be inventing a product.
			what: "an answer with none of the fields",
			id:   wire.DeviceIdentity{VendorURL: "https://example.test", Conformity: 1},
		},
		{
			what: "an answer with only vendor-specific objects",
			id:   wire.DeviceIdentity{Private: 4},
		},
	} {
		got, ok := identityObservation("line", ip, 1, &c.id)
		if ok != c.ok {
			t.Errorf("%s: usable %v, want %v", c.what, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		if got.Model != c.model {
			t.Errorf("%s: model %q, want %q", c.what, got.Model, c.model)
		}
		if got.Maker != c.maker {
			t.Errorf("%s: maker %q, want %q", c.what, got.Maker, c.maker)
		}
		if got.Firmware != c.firmware {
			t.Errorf("%s: firmware %q, want %q", c.what, got.Firmware, c.firmware)
		}
		if !got.Server {
			t.Errorf("%s: the end that answered was not recorded as the server", c.what)
		}
		if got.Proto != "modbus" || got.Listener != "line" || got.Addr != ip {
			t.Errorf("%s: observation %+v", c.what, got)
		}
	}
}

// The product code is not repeated when it is also the model name, which is
// what a device that has only one name for itself answers with.
func TestTheProductCodeIsNotRepeated(t *testing.T) {
	got, ok := identityObservation("line", netip.MustParseAddr("10.30.9.12"), 1,
		&wire.DeviceIdentity{Vendor: "Acme", ProductCode: "AC-500", Model: "AC-500",
			Revision: "V1.2"})
	if !ok {
		t.Fatal("an identification with a model and a revision is usable")
	}
	if got.Model != "AC-500" {
		t.Errorf("model %q", got.Model)
	}
}
