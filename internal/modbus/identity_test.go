package modbus

import (
	"errors"
	"strings"
	"testing"
)

// The one response in this protocol where a device says what it is.
func TestADeviceNamesItself(t *testing.T) {
	req, err := ParseRequest([]byte{FCEncapsulatedInterface, MEIIdentification, 0x01, 0x00})
	if err != nil {
		t.Fatalf("the request: %v", err)
	}
	pdu := []byte{FCEncapsulatedInterface, MEIIdentification, 0x01, 0x83, 0x00, 0x00, 0x03}
	for _, o := range []struct {
		id    byte
		value string
	}{
		{IDVendor, "Schneider Electric"},
		{IDProductCode, "BMXP342020"},
		{IDRevision, "V3.10"},
	} {
		pdu = append(pdu, o.id, byte(len(o.value)))
		pdu = append(pdu, o.value...)
	}
	res, err := ParseResponse(pdu, req)
	if err != nil {
		t.Fatalf("the response: %v", err)
	}
	if res.Identity == nil {
		t.Fatal("the identification was not read")
	}
	id := res.Identity
	if id.Vendor != "Schneider Electric" || id.ProductCode != "BMXP342020" || id.Revision != "V3.10" {
		t.Errorf("identity %+v", id)
	}
	if id.Empty() {
		t.Error("an identity with a vendor, a product code and a revision is not empty")
	}
	if id.Conformity != 0x83 {
		t.Errorf("conformity %#x", id.Conformity)
	}
	if id.More {
		t.Error("more-follows was nought and was read as set")
	}
}

// The objects this does not keep, and the ones it will not believe.
func TestWhatAnIdentificationResponseDoesNotBecome(t *testing.T) {
	req, err := ParseRequest([]byte{FCEncapsulatedInterface, MEIIdentification, 0x02, 0x00})
	if err != nil {
		t.Fatal(err)
	}
	// A vendor-specific object and a reserved one are counted, not kept: they
	// are whatever a vendor decided, and an inventory made of them would be an
	// inventory of one vendor's tooling.
	pdu := []byte{FCEncapsulatedInterface, MEIIdentification, 0x02, 0x01, 0xFF, 0x08, 0x02,
		0x90, 0x01, 'x', 0x40, 0x01, 'y'}
	res, err := ParseResponse(pdu, req)
	if err != nil {
		t.Fatalf("the response: %v", err)
	}
	if res.Identity.Private != 1 || res.Identity.Reserved != 1 {
		t.Errorf("private %d reserved %d", res.Identity.Private, res.Identity.Reserved)
	}
	if !res.Identity.More || res.Identity.Next != 0x08 {
		t.Errorf("a walk that continues was not recorded: %+v", res.Identity)
	}
	if !res.Identity.Empty() {
		t.Error("an identity with nothing an inventory uses is empty")
	}

	// A device that declares more objects than it sent, or sends more than it
	// declared, is refused rather than half-read. Half a string in an
	// inventory called a firmware version is the outcome worth preventing.
	for _, c := range []struct {
		what string
		pdu  []byte
	}{
		{"two objects declared and one sent",
			[]byte{FCEncapsulatedInterface, MEIIdentification, 0x01, 0x01, 0x00, 0x00, 0x02,
				0x00, 0x01, 'A'}},
		{"an object longer than the bytes that arrived",
			[]byte{FCEncapsulatedInterface, MEIIdentification, 0x01, 0x01, 0x00, 0x00, 0x01,
				0x00, 0x09, 'A'}},
		{"an object past the declared count",
			[]byte{FCEncapsulatedInterface, MEIIdentification, 0x01, 0x01, 0x00, 0x00, 0x01,
				0x00, 0x01, 'A', 0x01, 0x01, 'B'}},
	} {
		if _, err := ParseResponse(c.pdu, req); !errors.Is(err, ErrIdentity) {
			t.Errorf("%s: %v, want a malformed-identification error", c.what, err)
		}
	}

	// A CANopen answer shares the function code and is a tunnel rather than a
	// statement, so it carries no identity and is not an error.
	canopen, err := ParseRequest([]byte{FCEncapsulatedInterface, 13, 0x01, 0x00})
	if err == nil {
		res, err := ParseResponse([]byte{FCEncapsulatedInterface, 13, 0x01, 0x02}, canopen)
		if err != nil {
			t.Fatalf("a CANopen response: %v", err)
		}
		if res.Identity != nil {
			t.Error("a CANopen tunnel was read as a device naming itself")
		}
	}
}

// The strings are the device's own, so they are bounded and made safe to log: a
// product name with a control sequence in it is a device doing something other
// than reporting a product name.
func TestTheStringsADeviceSendsAreNotTrusted(t *testing.T) {
	req, err := ParseRequest([]byte{FCEncapsulatedInterface, MEIIdentification, 0x01, 0x00})
	if err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("A", 200)
	nasty := "PLC\x1b[2Jwiped"
	pdu := []byte{FCEncapsulatedInterface, MEIIdentification, 0x01, 0x01, 0x00, 0x00, 0x02}
	pdu = append(pdu, IDVendor, byte(len(long)))
	pdu = append(pdu, long...)
	pdu = append(pdu, IDProduct, byte(len(nasty)))
	pdu = append(pdu, nasty...)
	res, err := ParseResponse(pdu, req)
	if err != nil {
		t.Fatalf("the response: %v", err)
	}
	if len(res.Identity.Vendor) > MaxIDValue+3 {
		t.Errorf("a %d-character vendor name was kept whole", len(res.Identity.Vendor))
	}
	if strings.Contains(res.Identity.Product, "\x1b") {
		t.Errorf("an escape sequence survived into %q", res.Identity.Product)
	}
}
