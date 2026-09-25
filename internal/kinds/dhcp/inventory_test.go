package dhcp

import (
	"net/netip"
	"testing"
	"time"

	wire "github.com/rom/xproxy/internal/dhcp"
	"github.com/rom/xproxy/internal/proxy"
)

// TestALeaseBecomesAnAssetInTheInventory is the wiring test: the value of the
// inventory is that the DHCP relay is the only listener that sees a hardware
// address and an address together, so everything else's address-only sighting
// can attach to the same device.
func TestALeaseBecomesAnAssetInTheInventory(t *testing.T) {
	fs := startServer(t, &fakeServer{})
	// The inventory is a global section rather than a listener one, because one
	// device is one record across every listener.
	yaml := "asset_inventory: {enabled: true, max_assets: 64}\n"
	s, addr := relayWithGlobal(t, base, "", fs.addr(), yaml)
	c := dial(t, addr, 0x08, 0x00, 0x06, 0x11, 0x22, 0x33)
	c.send(wire.Discover, 0x4242, func(m *wire.Message) {
		m.Set(wire.OptHostname, []byte("plc-1"))
		m.Set(wire.OptVendorClass, []byte("Siemens SIMATIC"))
	})
	if _, ok := c.recv(); !ok {
		t.Fatal("no offer came back")
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Assets != nil && sn.Assets.Assets > 0
	}, "the lease became an asset")

	inv := s.Assets()
	if inv == nil {
		t.Fatal("the server has no inventory")
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if got, ok := inv.Get("08:00:06:11:22:33"); ok {
			// The vendor comes from the built-in seed list, the host name and
			// the vendor class from the request, and the address from the
			// lease -- which is the whole point of doing this on the DHCP
			// listener.
			if got.Vendor != "Siemens" {
				t.Errorf("vendor %q", got.Vendor)
			}
			if got.Hostname != "plc-1" {
				t.Errorf("hostname %q", got.Hostname)
			}
			if got.VendorClass != "Siemens SIMATIC" {
				t.Errorf("vendor class %q", got.VendorClass)
			}
			if len(got.Addrs) == 0 || got.Addrs[0] != "10.20.0.55" {
				t.Errorf("addresses %v, want the leased one", got.Addrs)
			}
			if !got.Speaks("dhcp") {
				t.Errorf("protocols %v", got.Protos)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("the device is not in the inventory: %+v", inv.List())
}

// TestNoInventoryMeansNoObservations, because an inventory is a record of
// somebody's estate and a proxy that kept one without being asked would be
// making a decision about their data for them.
func TestNoInventoryMeansNoObservations(t *testing.T) {
	fs := startServer(t, &fakeServer{})
	s, addr := relayFor(t, base, fs.addr())
	c := dial(t, addr)
	c.send(wire.Discover, 0x4343, nil)
	if _, ok := c.recv(); !ok {
		t.Fatal("no offer came back")
	}
	if s.Assets() != nil {
		t.Fatal("an inventory exists without being configured")
	}
	if sn := s.Stats(); sn.Assets != nil {
		t.Errorf("the status view reports an inventory: %+v", sn.Assets)
	}
	if sn := s.Stats(); sn.AssetObservations != 0 {
		t.Errorf("%d observations were recorded", sn.AssetObservations)
	}
}

// TestAnAddressOnlySightingAttachesToTheLeasedDevice is the merge the inventory
// exists for: a Modbus listener knows an address, a DHCP listener knows both,
// and one device should be one record.
func TestAnAddressOnlySightingAttachesToTheLeasedDevice(t *testing.T) {
	fs := startServer(t, &fakeServer{})
	yaml := "asset_inventory: {enabled: true}\n"
	s, addr := relayWithGlobal(t, base, "", fs.addr(), yaml)
	c := dial(t, addr, 0x08, 0x00, 0x06, 0x44, 0x55, 0x66)
	c.send(wire.Discover, 0x4444, nil)
	if _, ok := c.recv(); !ok {
		t.Fatal("no offer came back")
	}
	awaitCounter(t, s, func(sn proxy.Snapshot) bool {
		return sn.Assets != nil && sn.Assets.Assets > 0
	}, "the lease became an asset")
	inv := s.Assets()
	before := inv.Len()
	// Something else on the network reports the same address with no hardware
	// address, the way every listener but this one does.
	s.ObserveAsset(assetObservation(netip.MustParseAddr("10.20.0.55")))
	if inv.Len() != before {
		t.Fatalf("%d assets, was %d: the sighting did not merge", inv.Len(), before)
	}
	got, ok := inv.Get("08:00:06:44:55:66")
	if !ok {
		t.Fatal("the leased device is gone")
	}
	if !got.Speaks("modbus") || !got.Speaks("dhcp") {
		t.Errorf("one device is not one record: %v", got.Protos)
	}
	if got.Class.Role == "" {
		t.Error("the merged record was not classified")
	}
}
