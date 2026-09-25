package dhcp

import (
	"encoding/hex"
	"net/netip"
	"os"
	"testing"
)

// TestProbeHexIsAValidInform builds the DHCPINFORM the examples use as a UDP
// health-check probe and checks it parses.
//
// It is a test rather than a generator because the example's hex has to keep
// being a valid message: a probe a server ignores is a health check that marks
// every endpoint down.
func TestProbeHexIsAValidInform(t *testing.T) {
	m := &Message{Op: BootRequest, HType: HTypeEthernet, XID: 0xabcdef00,
		CHAddr: []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		CIAddr: netip.MustParseAddr("10.20.0.1"),
		YIAddr: netip.MustParseAddr("0.0.0.0"),
		SIAddr: netip.MustParseAddr("0.0.0.0"),
		GIAddr: netip.MustParseAddr("10.20.0.1"),
		Type:   Inform}
	m.Set(OptParameterList, []byte{OptSubnetMask})
	raw, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(raw); err != nil {
		t.Fatalf("the probe does not parse: %v", err)
	}
	if os.Getenv("DHCP_PROBE_HEX") != "" {
		t.Log(hex.EncodeToString(raw))
	}
}
