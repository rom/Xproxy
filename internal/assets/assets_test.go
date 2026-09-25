package assets

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

var epoch = time.Date(2026, 3, 4, 9, 0, 0, 0, time.UTC)

// clock is a test clock that only moves when a test moves it.
type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }

func newInv(t *testing.T, o Options) (*Inventory, *clock) {
	t.Helper()
	c := &clock{t: epoch}
	o.Now = c.now
	return New(o), c
}

func hw(s string) []byte {
	b := normalHWString(s)
	if b == "" {
		panic("bad hardware address in a test: " + s)
	}
	out := make([]byte, 0, 6)
	for _, part := range strings.Split(b, ":") {
		var v byte
		for i := 0; i < 2; i++ {
			c := part[i]
			switch {
			case c >= '0' && c <= '9':
				v = v<<4 | (c - '0')
			default:
				v = v<<4 | (c - 'a' + 10)
			}
		}
		out = append(out, v)
	}
	return out
}

// TestAnObservationWithNoIdentityIsCountedAndNotInvented: a listener that saw a
// malformed packet has nothing to key on, and inventing an asset for it would
// fill the inventory with the traffic it could not read.
func TestAnObservationWithNoIdentityIsCountedAndNotInvented(t *testing.T) {
	inv, _ := newInv(t, Options{})
	for _, o := range []Observation{
		{Proto: "modbus"},
		{Proto: "dhcp", Addr: netip.MustParseAddr("0.0.0.0")},
		{Proto: "modbus", Addr: netip.MustParseAddr("127.0.0.1")},
		{Proto: "dhcp", Hardware: []byte{0, 0, 0, 0, 0, 0}},
		{Proto: "dhcp", Hardware: []byte{1, 2}},
	} {
		if a := inv.Observe(o); a != nil {
			t.Errorf("%+v produced asset %s", o, a.ID)
		}
	}
	if inv.Len() != 0 {
		t.Fatalf("%d assets", inv.Len())
	}
	if inv.Counts().Refused != 5 {
		t.Fatalf("refused %d, want 5", inv.Counts().Refused)
	}
	// An unspecified address *with* a hardware address is a booting DHCP
	// client, which is the most useful observation this package gets.
	a := inv.Observe(Observation{Proto: "dhcp", Hardware: hw("02:11:22:33:44:55"),
		Addr: netip.MustParseAddr("0.0.0.0")})
	if a == nil {
		t.Fatal("a booting client was refused")
	}
	if a.ID != "02:11:22:33:44:55" {
		t.Errorf("identifier %q", a.ID)
	}
	if len(a.Addrs) != 0 {
		t.Errorf("the unspecified address was recorded: %v", a.Addrs)
	}
}

// TestTheHardwareAddressAndTheAddressMergeIntoOneAsset is the whole reason the
// inventory has two indexes: a DHCP listener knows both, and every other
// listener knows only the address.
func TestTheHardwareAddressAndTheAddressMergeIntoOneAsset(t *testing.T) {
	inv, c := newInv(t, Options{})
	// Modbus sees an address and nothing else.
	inv.Observe(Observation{Proto: "modbus", Listener: "plant",
		Addr: netip.MustParseAddr("10.0.0.5"), Server: true, Units: []int{1}})
	if inv.Len() != 1 {
		t.Fatalf("%d assets after the first sighting", inv.Len())
	}
	c.add(time.Minute)
	// Then DHCP binds that address to a hardware address.
	a := inv.Observe(Observation{Proto: "dhcp", Listener: "segment",
		Addr: netip.MustParseAddr("10.0.0.5"), Hardware: hw("08:00:06:11:22:33"),
		Hostname: "plc-1"})
	if inv.Len() != 1 {
		t.Fatalf("%d assets after the lease: the two sightings did not merge", inv.Len())
	}
	if a.Hardware != "08:00:06:11:22:33" || a.Vendor != "Siemens" {
		t.Errorf("hardware %q vendor %q", a.Hardware, a.Vendor)
	}
	// The identifier does not change when the hardware address arrives: an
	// operator's own notes are keyed on it.
	if a.ID != "10.0.0.5" {
		t.Errorf("identifier %q changed under the record", a.ID)
	}
	// The Modbus evidence survived the merge, which is what makes the
	// classification possible at all.
	if !a.Speaks("modbus") || !a.Speaks("dhcp") || len(a.Units) != 1 {
		t.Errorf("the merged asset lost evidence: %+v", a)
	}
	if a.Hostname != "plc-1" {
		t.Errorf("hostname %q", a.Hostname)
	}
	// And a later address-only sighting finds it through either index.
	c.add(time.Minute)
	inv.Observe(Observation{Proto: "modbus", Addr: netip.MustParseAddr("10.0.0.5"), Server: true})
	if inv.Len() != 1 {
		t.Fatalf("%d assets", inv.Len())
	}
	if got, ok := inv.Get("08:00:06:11:22:33"); !ok || got.ID != a.ID {
		t.Error("the asset cannot be looked up by hardware address")
	}
	if got, ok := inv.Get("10.0.0.5"); !ok || got.ID != a.ID {
		t.Error("the asset cannot be looked up by address")
	}
	if _, ok := inv.Get("10.0.0.9"); ok {
		t.Error("an address nothing was seen at resolved")
	}
}

// TestTheHardwareAddressWinsWhenBothAreKnown: an address DHCP has since given to
// another device must not carry the first device's history.
func TestTheHardwareAddressWinsWhenBothAreKnown(t *testing.T) {
	inv, c := newInv(t, Options{})
	first := hw("08:00:06:11:22:33")
	second := hw("00:00:bc:44:55:66")
	addr := netip.MustParseAddr("10.0.0.5")
	inv.Observe(Observation{Proto: "dhcp", Addr: addr, Hardware: first, Hostname: "plc-1"})
	c.add(time.Hour)
	a := inv.Observe(Observation{Proto: "dhcp", Addr: addr, Hardware: second, Hostname: "plc-2"})
	if inv.Len() != 2 {
		t.Fatalf("%d assets: the second device inherited the first one's record", inv.Len())
	}
	if a.Hostname != "plc-2" || a.Vendor != "Allen-Bradley (Rockwell)" {
		t.Errorf("the second asset is %+v", a)
	}
	// The address now resolves to the second device, and the first one keeps
	// its own record and its own history.
	if got, _ := inv.Get("10.0.0.5"); got.Hardware != "00:00:bc:44:55:66" {
		t.Errorf("the address resolves to %q", got.Hardware)
	}
	if got, _ := inv.Get("08:00:06:11:22:33"); got.Hostname != "plc-1" {
		t.Errorf("the first device's record was overwritten: %+v", got)
	}
}

// TestAnAddressTakenByAnotherDeviceSplitsTheRecords is the finding an inventory
// exists to produce on a static estate -- and the reason the records split
// rather than merge. One entry describing two machines would overwrite the older
// machine's vendor, role and history with the newer one's, which is exactly the
// history an incident needs.
func TestAnAddressTakenByAnotherDeviceSplitsTheRecords(t *testing.T) {
	var got []Change
	inv, c := newInv(t, Options{OnChange: func(a *Asset, ch Change) {
		got = append(got, ch)
	}})
	addr := netip.MustParseAddr("10.0.0.9")
	// Seen first by a listener that knew only the address, then bound to a
	// hardware address by DHCP: one device, one record.
	inv.Observe(Observation{Proto: "modbus", Addr: addr, Server: true, Units: []int{1}})
	c.add(time.Minute)
	first := inv.Observe(Observation{Proto: "dhcp", Addr: addr,
		Hardware: hw("08:00:06:11:22:33"), Hostname: "plc-1"})
	if inv.Len() != 1 {
		t.Fatalf("%d assets: the lease did not merge with the sighting", inv.Len())
	}
	got = nil
	c.add(time.Hour)
	// Now a different device turns up at the same address.
	second := inv.Observe(Observation{Proto: "dhcp", Addr: addr,
		Hardware: hw("00:00:bc:44:55:66"), Hostname: "laptop"})
	if inv.Len() != 2 {
		t.Fatalf("%d assets: the two devices share a record", inv.Len())
	}
	if second.ID == first.ID {
		t.Errorf("the second device got the first one's identifier %q", second.ID)
	}
	if second.Hostname != "laptop" || second.Vendor != "Allen-Bradley (Rockwell)" {
		t.Errorf("the second record is %+v", second)
	}
	// The first device keeps everything: its name, its vendor, its role and its
	// Modbus evidence.
	kept, ok := inv.Get("08:00:06:11:22:33")
	if !ok {
		t.Fatal("the first device's record is gone")
	}
	if kept.Hostname != "plc-1" || kept.Vendor != "Siemens" || kept.Class.Role != RolePLC {
		t.Errorf("the first record was overwritten: %+v", kept)
	}
	// And it is told that its address was claimed, because "stopped appearing"
	// is not a finding anybody reads.
	if !kinds(kept.Changes)[ChangeAddrTaken] {
		t.Errorf("the first record was not told: %+v", kept.Changes)
	}
	if !kinds(got)[ChangeAddrTaken] {
		t.Errorf("the change was not reported: %+v", got)
	}
	for _, ch := range kept.Changes {
		if ch.What == ChangeAddrTaken && (ch.From != "10.0.0.9" || ch.To != "00:00:bc:44:55:66") {
			t.Errorf("the note says %q -> %q", ch.From, ch.To)
		}
	}
	if inv.Counts().Findings == 0 {
		t.Error("the finding was not counted")
	}
}

// TestADeviceThatAppearsAtANewAddressIsRecorded, which is ordinary on a DHCP
// segment and worth having on a static one.
func TestADeviceThatAppearsAtANewAddressIsRecorded(t *testing.T) {
	inv, c := newInv(t, Options{})
	h := hw("08:00:06:11:22:33")
	inv.Observe(Observation{Proto: "dhcp", Hardware: h, Addr: netip.MustParseAddr("10.0.0.5")})
	c.add(time.Hour)
	a := inv.Observe(Observation{Proto: "dhcp", Hardware: h, Addr: netip.MustParseAddr("10.0.0.6")})
	if !kinds(a.Changes)[ChangeAddr] {
		t.Fatalf("the move was not recorded: %+v", a.Changes)
	}
	if inv.Len() != 1 {
		t.Fatalf("%d assets: a device that moved address became two", inv.Len())
	}
	if a.Addrs[0] != "10.0.0.6" || len(a.Addrs) != 2 {
		t.Errorf("addresses %v", a.Addrs)
	}
	// Both addresses still resolve to it, because a log line from an hour ago
	// carries the old one.
	if got, ok := inv.Get("10.0.0.5"); !ok || got.ID != a.ID {
		t.Error("the old address no longer resolves")
	}
}

func kinds(cs []Change) map[string]bool {
	out := map[string]bool{}
	for _, c := range cs {
		out[c.What] = true
	}
	return out
}

// TestARoleThatChangedIsAChange: a controller that starts behaving like an
// engineering station is the most interesting line an inventory can produce.
func TestARoleThatChangedIsAChange(t *testing.T) {
	var got []Change
	inv, c := newInv(t, Options{OnChange: func(a *Asset, ch Change) { got = append(got, ch) }})
	addr := netip.MustParseAddr("10.0.0.5")
	// It answers Modbus: a controller.
	a := inv.Observe(Observation{Proto: "modbus", Addr: addr, Server: true, Units: []int{1}})
	if a.Class.Role != RolePLC {
		t.Fatalf("role %q, want plc (%v)", a.Class.Role, a.Class.Why)
	}
	if a.Class.Level != 1 {
		t.Errorf("level %d, want 1", a.Class.Level)
	}
	c.add(time.Hour)
	// Now its SNMP description says it is a switch, which outranks the Modbus
	// rule only if the confidence says so -- it does not, so the role holds.
	a = inv.Observe(Observation{Proto: "snmp", Addr: addr,
		Description: "Cisco IOS Software, C2960 Software"})
	if a.Class.Role != RolePLC {
		t.Errorf("a weaker rule changed the role to %q", a.Class.Role)
	}
	if !kinds(got)[ChangeRole] {
		// Nothing should have changed yet.
		if len(got) != 0 {
			t.Logf("changes so far: %+v", got)
		}
	}
	// A device that starts writing to registers is behaving like something
	// else. This is the change worth raising.
	inv2, _ := newInv(t, Options{})
	b := inv2.Observe(Observation{Proto: "modbus", Addr: addr, Server: false, Units: []int{1, 2, 3, 4}})
	if b.Class.Role != RoleHistorian {
		t.Fatalf("role %q, want historian (%v)", b.Class.Role, b.Class.Why)
	}
	b = inv2.Observe(Observation{Proto: "modbus", Addr: addr, Server: false, Funcs: []int{0x10}})
	if b.Class.Role != RoleHMI {
		t.Fatalf("role %q, want hmi (%v)", b.Class.Role, b.Class.Why)
	}
	if !kinds(b.Changes)[ChangeRole] {
		t.Errorf("the role change was not recorded: %+v", b.Changes)
	}
}

// TestABaselineTurnsTheInventoryIntoADetection.
func TestABaselineTurnsTheInventoryIntoADetection(t *testing.T) {
	var got []Change
	inv, c := newInv(t, Options{OnChange: func(a *Asset, ch Change) { got = append(got, ch) }})
	inv.Observe(Observation{Proto: "modbus", Addr: netip.MustParseAddr("10.0.0.5"), Server: true})
	inv.Observe(Observation{Proto: "modbus", Addr: netip.MustParseAddr("10.0.0.6"), Server: true})
	if n, frozen := inv.Frozen(); frozen || n != 0 {
		t.Fatal("an inventory reports a baseline it does not have")
	}
	if n := inv.Freeze(); n != 2 {
		t.Fatalf("froze %d", n)
	}
	if n, frozen := inv.Frozen(); !frozen || n != 2 {
		t.Fatalf("baseline %d frozen=%v", n, frozen)
	}
	got = nil
	c.add(time.Minute)
	// Something in the baseline is not new.
	a := inv.Observe(Observation{Proto: "modbus", Addr: netip.MustParseAddr("10.0.0.5"), Server: true})
	if a.New || len(got) != 0 {
		t.Errorf("a known asset was reported as new: %v", got)
	}
	// Something else is.
	b := inv.Observe(Observation{Proto: "modbus", Addr: netip.MustParseAddr("10.0.0.9"), Server: true})
	if !b.New {
		t.Error("an asset outside the baseline is not marked new")
	}
	if !kinds(got)[ChangeNew] {
		t.Errorf("the new asset raised %v", got)
	}
	if inv.Counts().New != 1 {
		t.Errorf("new count %d", inv.Counts().New)
	}
	inv.Thaw()
	if _, frozen := inv.Frozen(); frozen {
		t.Error("the baseline survived a thaw")
	}
	c.add(time.Minute)
	if d := inv.Observe(Observation{Proto: "modbus", Addr: netip.MustParseAddr("10.0.0.10"),
		Server: true}); d.New {
		t.Error("an asset is new with no baseline to be new against")
	}
}

// TestTheBoundEvictsTheOldestRatherThanRefusing, which is the opposite of the
// pairing tables in the relay kinds and for a stated reason: forgetting here
// loses history, and refusing would stop the inventory noticing the estate at
// exactly the moment something is filling it up.
func TestTheBoundEvictsTheOldestRatherThanRefusing(t *testing.T) {
	inv, c := newInv(t, Options{Max: 3})
	for i := 0; i < 3; i++ {
		c.add(time.Minute)
		inv.Observe(Observation{Proto: "modbus",
			Addr: netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)}), Server: true})
	}
	if inv.Len() != 3 {
		t.Fatalf("%d assets", inv.Len())
	}
	c.add(time.Minute)
	a := inv.Observe(Observation{Proto: "modbus",
		Addr: netip.MustParseAddr("10.0.0.99"), Server: true})
	if a == nil {
		t.Fatal("a new asset was refused instead of the oldest being dropped")
	}
	if inv.Len() != 3 {
		t.Fatalf("%d assets after the bound", inv.Len())
	}
	if _, ok := inv.Get("10.0.0.1"); ok {
		t.Error("the oldest asset survived")
	}
	if _, ok := inv.Get("10.0.0.99"); !ok {
		t.Error("the newest asset was not kept")
	}
	if inv.Counts().Dropped != 1 {
		t.Errorf("dropped %d", inv.Counts().Dropped)
	}
}

// TestAnAssetNobodyHasSeenExpires, so that a decommissioned device leaves the
// inventory instead of being reported for ever.
func TestAnAssetNobodyHasSeenExpires(t *testing.T) {
	inv, c := newInv(t, Options{TTL: time.Hour})
	inv.Observe(Observation{Proto: "modbus", Addr: netip.MustParseAddr("10.0.0.5"),
		Hardware: hw("08:00:06:11:22:33"), Server: true})
	c.add(30 * time.Minute)
	inv.Observe(Observation{Proto: "modbus", Addr: netip.MustParseAddr("10.0.0.6"), Server: true})
	if inv.Len() != 2 {
		t.Fatalf("%d assets", inv.Len())
	}
	c.add(45 * time.Minute)
	// The first is past its time, the second is not.
	inv.Observe(Observation{Proto: "modbus", Addr: netip.MustParseAddr("10.0.0.6"), Server: true})
	if inv.Len() != 1 {
		t.Fatalf("%d assets after the first expired", inv.Len())
	}
	if _, ok := inv.Get("08:00:06:11:22:33"); ok {
		t.Error("an expired asset is still reachable by hardware address")
	}
	if _, ok := inv.Get("10.0.0.5"); ok {
		t.Error("an expired asset is still reachable by address")
	}
	if inv.Counts().Expired != 1 {
		t.Errorf("expired %d", inv.Counts().Expired)
	}
}

// TestALaterObservationNeverErasesWhatAnEarlierOneKnew: a Modbus sighting that
// knows no host name must not delete the one DHCP saw.
func TestALaterObservationNeverErasesWhatAnEarlierOneKnew(t *testing.T) {
	inv, c := newInv(t, Options{})
	addr := netip.MustParseAddr("10.0.0.5")
	inv.Observe(Observation{Proto: "dhcp", Addr: addr, Hardware: hw("08:00:06:11:22:33"),
		Hostname: "plc-1", VendorClass: "Siemens SIMATIC", BootFile: "boot.bin"})
	c.add(time.Minute)
	a := inv.Observe(Observation{Proto: "modbus", Addr: addr, Server: true, Units: []int{1}})
	if a.Hostname != "plc-1" || a.VendorClass != "Siemens SIMATIC" || a.BootFile != "boot.bin" {
		t.Fatalf("a later observation erased what was known: %+v", a)
	}
	// And a value that really did change is kept.
	c.add(time.Minute)
	a = inv.Observe(Observation{Proto: "dhcp", Addr: addr, Hostname: "plc-1-renamed"})
	if a.Hostname != "plc-1-renamed" {
		t.Errorf("hostname %q", a.Hostname)
	}
}

// TestEveryPeerChosenStringIsClipped, because an inventory is read by people and
// a vendor class with a control sequence in it is a log injection with a user
// interface in front of it.
func TestEveryPeerChosenStringIsClipped(t *testing.T) {
	inv, _ := newInv(t, Options{})
	nasty := "plc\r\nadmin\x1b[2J" + strings.Repeat("x", 400)
	a := inv.Observe(Observation{Proto: "dhcp", Hardware: hw("08:00:06:11:22:33"),
		Hostname: nasty, VendorClass: nasty, Description: nasty, ClientID: nasty,
		BootFile: nasty, UserAgent: nasty, Model: nasty, Firmware: nasty,
		UserClass: nasty})
	for name, v := range map[string]string{
		"hostname": a.Hostname, "vendor_class": a.VendorClass,
		"description": a.Description, "client_id": a.ClientID,
		"boot_file": a.BootFile, "user_agent": a.UserAgent,
		"model": a.Model, "firmware": a.Firmware, "user_class": a.UserClass,
	} {
		if len(v) > MaxString+8 {
			t.Errorf("%s is %d octets", name, len(v))
		}
		for i := 0; i < len(v); i++ {
			if c := v[i]; c < 0x20 || c == 0x7f {
				t.Errorf("%s carries octet %#02x", name, c)
			}
		}
	}
}

// TestTheBoundedListsStayBounded, because everything in them comes off the
// network.
func TestTheBoundedListsStayBounded(t *testing.T) {
	inv, c := newInv(t, Options{})
	h := hw("08:00:06:11:22:33")
	for i := 0; i < MaxAddrs*3; i++ {
		c.add(time.Minute)
		inv.Observe(Observation{Proto: "dhcp", Hardware: h,
			Addr: netip.AddrFrom4([4]byte{10, 0, byte(i / 256), byte(i % 256)})})
	}
	a, _ := inv.Get("08:00:06:11:22:33")
	if len(a.Addrs) > MaxAddrs {
		t.Errorf("%d addresses", len(a.Addrs))
	}
	if len(a.Changes) > MaxChanges {
		t.Errorf("%d changes", len(a.Changes))
	}
	// The newest address is first, because that is the one an operator wants.
	if a.Addrs[0] != "10.0.0.23" {
		t.Errorf("newest address %q", a.Addrs[0])
	}
	for i := 0; i < MaxProtos*2; i++ {
		inv.Observe(Observation{Proto: "modbus", Hardware: h,
			Units: []int{i}, Funcs: []int{i}, Objects: []int{i},
			OIDs: []string{"1.3.6.1.2.1." + string(rune('a'+i%26))}})
	}
	a, _ = inv.Get("08:00:06:11:22:33")
	for name, n := range map[string]int{"units": len(a.Units), "funcs": len(a.Funcs),
		"objects": len(a.Objects), "oids": len(a.OIDs)} {
		if n > MaxProtos {
			t.Errorf("%s has %d entries", name, n)
		}
	}
}

// TestAListedAssetCannotBeEditedThroughTheCopy, because the inventory hands out
// records to a management endpoint and a caller that could change one would be
// changing the estate's inventory by reading it.
func TestAListedAssetCannotBeEditedThroughTheCopy(t *testing.T) {
	inv, _ := newInv(t, Options{})
	inv.Observe(Observation{Proto: "modbus", Addr: netip.MustParseAddr("10.0.0.5"),
		Server: true, Units: []int{1}, Listener: "plant"})
	list := inv.List()
	if len(list) != 1 {
		t.Fatalf("%d assets listed", len(list))
	}
	list[0].Hostname = "changed"
	list[0].Units[0] = 99
	list[0].Protos["modbus"] = 1000
	list[0].Class.Role = RoleEngineering
	again := inv.List()
	if again[0].Hostname == "changed" || again[0].Units[0] == 99 ||
		again[0].Protos["modbus"] == 1000 || again[0].Class.Role == RoleEngineering {
		t.Fatal("editing a listed asset changed the inventory")
	}
}

// TestListIsNewestFirst, which is the order an operator wants: what has just
// appeared is what they are looking for.
func TestListIsNewestFirst(t *testing.T) {
	inv, c := newInv(t, Options{})
	for i := 1; i <= 3; i++ {
		c.add(time.Minute)
		inv.Observe(Observation{Proto: "modbus",
			Addr: netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}), Server: true})
	}
	list := inv.List()
	if len(list) != 3 || list[0].ID != "10.0.0.3" || list[2].ID != "10.0.0.1" {
		t.Fatalf("order: %s %s %s", list[0].ID, list[1].ID, list[2].ID)
	}
}

// TestAnObserverThatKnowsOutranksTheRules.
func TestAnObserverThatKnowsOutranksTheRules(t *testing.T) {
	inv, c := newInv(t, Options{})
	addr := netip.MustParseAddr("10.0.0.5")
	a := inv.Observe(Observation{Proto: "modbus", Addr: addr, Server: true,
		Units: []int{1}, Role: RoleEngineering})
	if a.Class.Role != RoleEngineering || a.Class.Confidence != 100 {
		t.Fatalf("classification %+v", a.Class)
	}
	c.add(time.Minute)
	// And the rules do not argue with it afterwards.
	a = inv.Observe(Observation{Proto: "modbus", Addr: addr, Server: true, Units: []int{2}})
	if a.Class.Role != RoleEngineering {
		t.Errorf("the rules overrode an observer that knew: %+v", a.Class)
	}
}

// TestTheCountsAddUp, because they are what the metrics export.
func TestTheCountsAddUp(t *testing.T) {
	inv, c := newInv(t, Options{})
	inv.Observe(Observation{Proto: "modbus", Addr: netip.MustParseAddr("10.0.0.5"),
		Server: true, Units: []int{1}})
	c.add(time.Minute)
	inv.Observe(Observation{Proto: "dhcp", Hardware: hw("b8:27:eb:11:22:33")})
	c.add(time.Minute)
	inv.Observe(Observation{Proto: "modbus", Addr: netip.MustParseAddr("10.0.0.9")})
	got := inv.Counts()
	if got.Assets != 3 {
		t.Fatalf("assets %d", got.Assets)
	}
	if got.ByRole[RolePLC] != 1 || got.ByRole[RoleEmbedded] != 1 {
		t.Errorf("by role %v", got.ByRole)
	}
	if got.Unknown != 1 || got.ByRole[RoleUnknown] != 1 {
		t.Errorf("unknown %d, by role %v", got.Unknown, got.ByRole)
	}
}
