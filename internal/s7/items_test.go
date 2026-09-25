package s7

import (
	"reflect"
	"strings"
	"testing"
)

// The items are the addresses a policy is written about, so each layout is
// driven against the frames a real client sends and every field is asserted.
func TestTheItemsOfAReadAreRead(t *testing.T) {
	p, err := ParseS7(s7job(1, readParam(FnReadVar,
		itemSpec(TransportByte, 20, 1, AreaDB, 8*4),
		itemSpec(TransportWord, 10, 100, AreaDB, 0),
		itemSpec(TransportBit, 1, 0, AreaFlags, 8*3+2)), nil))
	if err != nil {
		t.Fatal(err)
	}
	items, ok := p.Items()
	if !ok {
		t.Fatal("the items did not lay out")
	}
	if len(items) != 3 {
		t.Fatalf("%d items", len(items))
	}
	// Twenty bytes of DB1 from byte 4.
	if got := items[0]; !got.Address || got.Area != AreaDB || got.DB != 1 ||
		got.Byte() != 4 || got.Bytes() != 20 || got.Last() != 23 {
		t.Errorf("item 0 = %+v (byte %d, %d octets)", got, got.Byte(), got.Bytes())
	}
	// Ten words is twenty octets, which is the arithmetic a range check
	// rests on.
	if got := items[1]; got.Bytes() != 20 || got.Last() != 19 || AreaName(got.Area) != "db" {
		t.Errorf("item 1 = %+v (%d octets)", got, got.Bytes())
	}
	// A bit address: byte 3, bit 2.
	if got := items[2]; got.Byte() != 3 || got.BitOffset() != 2 || got.Bytes() != 1 {
		t.Errorf("item 2 = %+v", got)
	}
	if TransportName(items[2].Transport) != "bit" {
		t.Errorf("transport = %q", TransportName(items[2].Transport))
	}
}

// A write's values are in the other half of the PDU, and the two lists have
// to be walked together.
func TestTheValuesOfAWriteAreMatchedToTheirItems(t *testing.T) {
	p, err := ParseS7(s7job(1,
		readParam(FnWriteVar,
			itemSpec(TransportByte, 3, 1, AreaDB, 0),
			itemSpec(TransportWord, 1, 1, AreaDB, 8*8),
			itemSpec(TransportBit, 1, 0, AreaOutputs, 8*2+1)),
		cat(dataItem(TransportByte, []byte{1, 2, 3}), // odd, so a fill octet follows
			dataItem(TransportWord, []byte{0x12, 0x34}),
			dataItem(TransportBit, []byte{1}))))
	if err != nil {
		t.Fatal(err)
	}
	items, ok := p.Items()
	if !ok {
		t.Fatal("the items did not lay out")
	}
	if len(items) != 3 {
		t.Fatalf("%d items", len(items))
	}
	for i, want := range [][]byte{{1, 2, 3}, {0x12, 0x34}, {1}} {
		if !items[i].HasValue || !reflect.DeepEqual(items[i].Value, want) {
			t.Errorf("value %d = %v, want %v", i, items[i].Value, want)
		}
	}
	// The fill octet after the odd-length item is the part that catches a
	// reader out: without skipping it, the second item's value would be
	// the fill and the third would be nothing.
	if items[1].ValueTransport != TransportWord {
		t.Errorf("the second value's transport read as %#x", items[1].ValueTransport)
	}
}

// An item this package cannot place is not an item with a default address.
func TestAnItemThatIsNotAnAddressSaysSo(t *testing.T) {
	// A 1200-family symbolic item: a legal specification whose address is
	// not an area and a byte.
	sym := cat([]byte{0x12, 0x08, SyntaxSym1200, 0, 0, 0, 0, 0, 0, 0})
	p, err := ParseS7(s7job(1, cat([]byte{FnReadVar, 1}, sym), nil))
	if err != nil {
		t.Fatal(err)
	}
	items, ok := p.Items()
	if !ok {
		t.Fatal("the specification did not lay out")
	}
	if len(items) != 1 || items[0].Address {
		t.Fatalf("items = %+v", items)
	}
	if items[0].Syntax != SyntaxSym1200 {
		t.Errorf("syntax = %#x", items[0].Syntax)
	}
	// And the area of a non-address item is not a real area, so a policy
	// that read one would be checking a list against zero.
	if AreaName(items[0].Area) != "0x0" {
		t.Errorf("area name = %q", AreaName(items[0].Area))
	}
}

func TestItemsThatDoNotLayOutAreRefusedRatherThanShortened(t *testing.T) {
	full := readParam(FnReadVar,
		itemSpec(TransportByte, 4, 1, AreaDB, 0),
		itemSpec(TransportByte, 4, 2, AreaDB, 0))
	for n := 0; n < len(full); n++ {
		p, err := ParseS7(s7job(1, full[:n], nil))
		if err != nil {
			continue
		}
		items, ok := p.Items()
		if ok && len(items) != 2 {
			t.Errorf("%d octets of a two-item read gave %d items", n, len(items))
		}
	}
	// A count that says three and two items that follow.
	three := cat([]byte{FnReadVar, 3},
		itemSpec(TransportByte, 4, 1, AreaDB, 0), itemSpec(TransportByte, 4, 2, AreaDB, 0))
	p, _ := ParseS7(s7job(1, three, nil))
	if _, ok := p.Items(); ok {
		t.Error("a count of three with two items laid out")
	}
	// A specification type that is not 0x12: everything after it is at an
	// unknown offset.
	bad := cat([]byte{FnReadVar, 1}, []byte{0x13, 0x0a, SyntaxAny, TransportByte, 0, 4, 0, 1, AreaDB, 0, 0, 0})
	p2, _ := ParseS7(s7job(1, bad, nil))
	if _, ok := p2.Items(); ok {
		t.Error("a specification with the wrong type octet laid out")
	}
	// A write whose data half holds fewer items than its parameter half.
	w, _ := ParseS7(s7job(1, readParam(FnWriteVar,
		itemSpec(TransportByte, 1, 1, AreaDB, 0), itemSpec(TransportByte, 1, 1, AreaDB, 8)),
		dataItem(TransportByte, []byte{1})))
	if _, ok := w.Items(); ok {
		t.Error("a write with one value for two items laid out")
	}
	// And a function that has no items at all.
	s, _ := ParseS7(s7job(1, []byte{FnSetupComm, 0, 0, 1, 0, 1, 1, 224}, nil))
	if _, ok := s.Items(); ok {
		t.Error("a setup job reported items")
	}
}

func TestTheAreaAndTransportNamesRoundTrip(t *testing.T) {
	for _, n := range AreaNames() {
		code, ok := AreaOf(n)
		if !ok {
			t.Errorf("area %q is listed and not found", n)
			continue
		}
		if AreaName(code) != n {
			t.Errorf("%#x is named %q and %q", code, n, AreaName(code))
		}
	}
	if _, ok := AreaOf("not_an_area"); ok {
		t.Error("a name nobody defines has an area code")
	}
	// The transports whose count is not in octets are the ones a length
	// bound depends on, so each is pinned.
	for _, c := range []struct {
		transport uint8
		count     uint16
		want      int
	}{
		{TransportByte, 10, 10},
		{TransportChar, 10, 10},
		{TransportWord, 10, 20},
		{TransportInt, 10, 20},
		{TransportDWord, 10, 40},
		{TransportDInt, 10, 40},
		{TransportReal, 10, 40},
		{TransportBit, 1, 1},
		{TransportBit, 9, 2},
		{TransportTimer, 2, 4},
		{TransportCntr, 2, 4},
		{TransportDT, 1, 8},
	} {
		it := Item{Transport: c.transport, Count: c.count}
		if got := it.Bytes(); got != c.want {
			t.Errorf("%s x %d = %d octets, want %d",
				TransportName(c.transport), c.count, got, c.want)
		}
	}
	if !strings.HasPrefix(TransportName(0x77), "0x") {
		t.Errorf("an unknown transport was named %q", TransportName(0x77))
	}
}
