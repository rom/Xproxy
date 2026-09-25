package s7

import (
	"bytes"
	"testing"
)

// Fuzzing is the primary bug-finder here, because every layer has a length
// that came off the network: TPKT's, COTP's length indicator, the S7
// header's two, an item specification's, and a write value's. The properties
// asserted are the ones a relay depends on.

// FuzzFrames drives all three layers the way the relay does.
func FuzzFrames(f *testing.F) {
	f.Add(tpkt(cotpCR(0, 1, 0x0a, tsap(ResourcePG, 0, 0), tsap(ResourcePG, 0, 2))))
	f.Add(tpkt(cotpData(s7job(1, readParam(FnReadVar,
		itemSpec(TransportByte, 20, 1, AreaDB, 0)), nil))))
	f.Add(tpkt(cotpData(s7job(1, readParam(FnWriteVar,
		itemSpec(TransportByte, 3, 1, AreaDB, 0)), dataItem(TransportByte, []byte{1, 2, 3})))))
	f.Add(tpkt(cotpData(s7user(1, 0x11, UserRequest<<4|GroupCPU, 0x01, 0, nil))))
	f.Add(tpkt(cotpData(s7ack(1, 0x85, 0x04, []byte{FnReadVar, 1}, nil))))

	f.Fuzz(func(t *testing.T, in []byte) {
		r := NewReader(bytes.NewReader(in), 4096)
		for i := 0; i < 32; i++ {
			fr, err := r.Next()
			if err != nil {
				return
			}
			if len(fr.Raw) > r.Max() {
				t.Fatalf("a frame of %d octets passed a bound of %d", len(fr.Raw), r.Max())
			}
			if len(fr.Payload) >= len(fr.Raw) {
				t.Fatalf("a payload of %d octets in a frame of %d", len(fr.Payload), len(fr.Raw))
			}
			c, err := ParseCOTP(fr.Payload)
			if err != nil {
				continue
			}
			// Nothing a COTP PDU reports is longer than the frame it came
			// in, and its data is inside its payload.
			if len(c.Data) > len(fr.Payload) || len(c.Called) > len(fr.Payload) ||
				len(c.Calling) > len(fr.Payload) {
				t.Fatalf("a COTP field is longer than its frame: %+v", c)
			}
			if _, _, slot, ok := c.Destination(); ok && slot > 31 {
				t.Fatalf("a slot of %d came out of two octets", slot)
			}
			if c.Type != COTPData && c.Type != COTPExpeditedData {
				continue
			}
			readPDU(t, c.Data)
		}
	})
}

// readPDU does to an S7 PDU what the relay does.
func readPDU(t *testing.T, b []byte) {
	t.Helper()
	p, err := ParseS7(b)
	if err != nil {
		return
	}
	// The two halves are inside what arrived, which is what the header's
	// lengths are checked for.
	if len(p.Param)+len(p.Data) > len(b) {
		t.Fatalf("%d parameter and %d data octets out of %d", len(p.Param), len(p.Data), len(b))
	}
	op, known := p.Op()
	if !known && op != "" {
		t.Fatalf("an unknown operation came back named %q", op)
	}
	if known {
		if _, ok := OpOf(string(op)); !ok {
			t.Fatalf("%q is not in the vocabulary", op)
		}
	}
	items, ok := p.Items()
	if !ok && len(items) != 0 {
		t.Fatal("items came back with ok false")
	}
	for _, it := range items {
		if it.Value != nil && len(it.Value) > len(b) {
			t.Fatalf("a value of %d octets came out of %d", len(it.Value), len(b))
		}
		if it.Bytes() < 0 || it.Last() < it.Byte() {
			t.Fatalf("an item covers %d octets from %d to %d", it.Bytes(), it.Byte(), it.Last())
		}
	}
	if name, ok := p.Service(); ok && len(name) > len(b) {
		t.Fatalf("a service name of %d octets came out of %d", len(name), len(b))
	}
	if _, number, ok := p.Block(); ok && (number < 0 || number > 99999) {
		t.Fatalf("a block number of %d", number)
	}
	if u, ok := p.UserData(); ok {
		if u.Group > 0x0f || u.Type > 0x0f {
			t.Fatalf("a group of %#x and a type of %#x came out of one octet", u.Group, u.Type)
		}
		if u.Name() == "" {
			t.Fatal("a user-data operation has no name")
		}
	}
	p.Setup()
	p.FunctionName()
}
