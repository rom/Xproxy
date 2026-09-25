package assets

import (
	"strings"
	"testing"
)

func TestAPrefixIsReadHoweverItIsWritten(t *testing.T) {
	v := NewVendors()
	for _, form := range []string{"08:00:06", "08-00-06", "080006", "08.00.06", " 08:00:06 ", "08:00:06:11:22:33"} {
		if err := v.Add(form, "Siemens"); err != nil {
			t.Fatalf("%q: %v", form, err)
		}
	}
	if v.Len() != 1 {
		t.Fatalf("%d prefixes from six spellings of one", v.Len())
	}
	if got := v.Lookup([]byte{0x08, 0x00, 0x06, 1, 2, 3}); got != "Siemens" {
		t.Errorf("lookup %q", got)
	}
	// Case does not matter, because it does not matter in the registry either.
	if got := v.LookupPrefix("08:00:06"); got != "Siemens" {
		t.Errorf("prefix lookup %q", got)
	}
	if got := v.LookupPrefix("AB:CD:EF"); got != "" {
		t.Errorf("an unknown prefix resolved to %q", got)
	}
	for _, bad := range []string{"", "08", "08:00", "zz:00:06", "8:0:6", "not a prefix"} {
		if err := v.Add(bad, "x"); err == nil {
			t.Errorf("%q was accepted as a prefix", bad)
		}
		if got := v.LookupPrefix(bad); got != "" {
			t.Errorf("%q resolved to %q", bad, got)
		}
	}
	if err := v.Add("08:00:07", ""); err == nil {
		t.Error("a prefix with no vendor name was accepted")
	}
	// A hardware address too short to have a vendor has none.
	if got := v.Lookup([]byte{1, 2}); got != "" {
		t.Errorf("two octets resolved to %q", got)
	}
}

// TestAVendorListLoadsAndAMalformedLineIsAnError, because a list an operator
// trusted and which silently dropped half its entries is worse than one that
// would not load.
func TestAVendorListLoadsAndAMalformedLineIsAnError(t *testing.T) {
	v := NewVendors()
	n, err := v.Load(strings.NewReader(`
# a comment, and a blank line above
08:00:06  Siemens AG
00-00-BC,Allen-Bradley
001D9C	Rockwell Automation
`), 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 || v.Len() != 3 {
		t.Fatalf("loaded %d, holding %d", n, v.Len())
	}
	if got := v.LookupPrefix("00:1d:9c"); got != "Rockwell Automation" {
		t.Errorf("tab-separated entry read as %q", got)
	}
	if got := v.LookupPrefix("00:00:bc"); got != "Allen-Bradley" {
		t.Errorf("comma-separated entry read as %q", got)
	}
	if _, err := v.Load(strings.NewReader("08:00:06\n"), 0); err == nil {
		t.Error("a line with no vendor name loaded")
	}
	if _, err := v.Load(strings.NewReader("nonsense vendor\n"), 0); err == nil {
		t.Error("a line with no prefix loaded")
	}
	// The bound is on entries, because a forty-megabyte list is a mistake
	// somebody should hear about.
	var big strings.Builder
	for i := 0; i < 10; i++ {
		big.WriteString("08:00:0")
		big.WriteByte(byte('0' + i))
		big.WriteString(" v\n")
	}
	if _, err := NewVendors().Load(strings.NewReader(big.String()), 4); err == nil {
		t.Error("a list past the bound loaded")
	}
}

// TestTheSeedListIsSmallAndWellFormed. It is a seed, not a registry: its job is
// to be checkable by hand, and the classification does not depend on any entry
// being right.
func TestTheSeedListIsSmallAndWellFormed(t *testing.T) {
	v := SeedVendors()
	if v.Len() < 20 {
		t.Errorf("the seed list has %d entries, which is fewer than it was", v.Len())
	}
	if v.Len() > 200 {
		t.Errorf("the seed list has grown to %d entries; it is meant to be checkable by hand, and an estate that wants the registry loads it", v.Len())
	}
	for prefix, name := range seed {
		if got, err := normalPrefix(prefix); err != nil || got != prefix {
			t.Errorf("seed prefix %q is not in normal form (%q, %v)", prefix, got, err)
		}
		if strings.TrimSpace(name) != name || name == "" {
			t.Errorf("seed vendor %q for %s", name, prefix)
		}
	}
}

// TestAnAllZeroHardwareAddressIsNotAnAddress: it is the field a listener filled
// in with nothing, and an inventory keyed on it would have one record for every
// device that did not say.
func TestAnAllZeroHardwareAddressIsNotAnAddress(t *testing.T) {
	if got := normalHW([]byte{0, 0, 0, 0, 0, 0}); got != "" {
		t.Errorf("all zeroes read as %q", got)
	}
	if got := normalHW([]byte{0, 0, 1}); got != "00:00:01" {
		t.Errorf("a low address read as %q", got)
	}
	if got := normalHW([]byte{1, 2}); got != "" {
		t.Errorf("two octets read as %q", got)
	}
	for _, bad := range []string{"", "01", "01:02", "zz:02:03", "01:2:03"} {
		if got := normalHWString(bad); got != "" {
			t.Errorf("%q read as %q", bad, got)
		}
	}
	if got := normalHWString("08-00-06-11-22-33"); got != "08:00:06:11:22:33" {
		t.Errorf("hyphens read as %q", got)
	}
}
