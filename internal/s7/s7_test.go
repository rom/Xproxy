package s7

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

// The framing first: three layers, each of which has a length field that
// came off the network.
func TestFramesAreReadAndBounded(t *testing.T) {
	job := s7job(1, readParam(FnReadVar, itemSpec(TransportByte, 4, 1, AreaDB, 0)), nil)
	stream := cat(tpkt(cotpData(job)), tpkt(cotpData(job)))
	r := NewReader(bytes.NewReader(stream), 0)
	for i := 0; i < 2; i++ {
		f, err := r.Next()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(f.Raw, tpkt(cotpData(job))) {
			t.Error("the frame's own octets were not kept")
		}
		c, err := ParseCOTP(f.Payload)
		if err != nil {
			t.Fatal(err)
		}
		if c.Type != COTPData || !c.EOT {
			t.Errorf("cotp = %+v", c)
		}
		p, err := ParseS7(c.Data)
		if err != nil {
			t.Fatal(err)
		}
		if p.Type != Job || p.FunctionName() != "read_var" {
			t.Errorf("pdu = %+v", p)
		}
	}
	if _, err := r.Next(); !errors.Is(err, io.EOF) {
		t.Errorf("the end of the stream was reported as %v", err)
	}
}

func TestTheFramingRefusesWhatCannotBeAFrame(t *testing.T) {
	for _, c := range []struct {
		name string
		b    []byte
		want string
	}{
		{"not ISO-on-TCP", []byte{0x16, 0x03, 0x01, 0x00}, "TPKT version"},
		{"a length inside the header", []byte{3, 0, 0, 3}, "shorter than its own header"},
		{"a length over the bound", cat([]byte{3, 0}, be16(9000)), "over the"},
	} {
		r := NewReader(bytes.NewReader(c.b), 4096)
		_, err := r.Next()
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
	// Every truncation of a good frame is an error rather than a frame.
	full := tpkt(cotpData(s7job(1, readParam(FnReadVar), nil)))
	for n := 1; n < len(full); n++ {
		r := NewReader(bytes.NewReader(full[:n]), 0)
		if _, err := r.Next(); err == nil {
			t.Fatalf("%d octets of a %d octet frame were read as a frame", n, len(full))
		}
	}
	// And the bound is never below what a COTP header needs.
	if got := NewReader(bytes.NewReader(nil), 2).Max(); got != MinFrame {
		t.Errorf("a bound of 2 was kept as %d", got)
	}
}

// The connection request is where the address is, and the address is the
// rack and the slot.
func TestTheConnectionRequestCarriesTheRackAndSlot(t *testing.T) {
	b := cotpCR(0, 0x0100, 0x0a, tsap(ResourcePG, 0, 0), tsap(ResourcePG, 0, 2))
	c, err := ParseCOTP(b)
	if err != nil {
		t.Fatal(err)
	}
	if c.Type != COTPConnectionRequest || c.TypeName() != "connection_request" {
		t.Errorf("cotp = %+v", c)
	}
	if c.SrcRef != 0x0100 || c.DstRef != 0 {
		t.Errorf("references = %#x %#x", c.SrcRef, c.DstRef)
	}
	if got := TPDUBytes(c.TPDUSize); got != 1024 {
		t.Errorf("tpdu size = %d", got)
	}
	resource, rack, slot, ok := c.Destination()
	if !ok || resource != ResourcePG || rack != 0 || slot != 2 {
		t.Errorf("destination = %#x rack %d slot %d, %v", resource, rack, slot, ok)
	}
	if ResourceName(resource) != "pg" {
		t.Errorf("resource name = %q", ResourceName(resource))
	}
	// A rack and slot at the top of their ranges, because the packing is a
	// shift and a mask and the two are easy to swap.
	c2, _ := ParseCOTP(cotpCR(0, 1, 0x0a, tsap(ResourceOP, 0, 0), tsap(ResourceOP, 7, 31)))
	if _, rack, slot, _ := c2.Destination(); rack != 7 || slot != 31 {
		t.Errorf("rack %d slot %d, want 7 and 31", rack, slot)
	}
	// A TSAP of another length is a legal COTP address and not a Siemens
	// one, so it is reported as unknown rather than as rack zero.
	c3, _ := ParseCOTP(cotpCR(0, 1, 0x0a, []byte("PG"), []byte("SIMATIC-ROOT")))
	if _, _, _, ok := c3.Destination(); ok {
		t.Error("a twelve-octet TSAP was read as a rack and a slot")
	}
}

func TestTheCOTPHeaderRefusesWhatItCannotRead(t *testing.T) {
	for _, c := range []struct {
		name string
		b    []byte
		want string
	}{
		{"nothing", nil, "no length and type"},
		{"a length indicator past the frame", []byte{0x20, COTPData, 0x80}, "past the end"},
		{"a data header with no sequence octet", []byte{0x01, COTPData}, "no sequence octet"},
		{"a connection header too short", []byte{0x03, COTPConnectionRequest, 0, 0}, "too short"},
		{"a parameter past the frame", cat([]byte{0x09, COTPConnectionRequest, 0, 0, 0, 1, 0},
			[]byte{paramCalled, 40, 1}), "runs past"},
	} {
		if _, err := ParseCOTP(c.b); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
	// A PDU type this package does not read is returned as itself, with no
	// claims about its contents: the policy refuses it.
	c, err := ParseCOTP([]byte{0x02, 0x99, 0x00})
	if err != nil {
		t.Fatal(err)
	}
	if c.Known() {
		t.Error("type 0x99 is one of the ones this package reads")
	}
	if c.TypeName() != "0x99" {
		t.Errorf("type name = %q", c.TypeName())
	}
	// And a size parameter outside the standard's range is no size.
	if got := TPDUBytes(0x20); got != 0 {
		t.Errorf("an impossible tpdu size read as %d", got)
	}
}

// The S7 header: two lengths, both from the network.
func TestTheS7HeaderIsRead(t *testing.T) {
	p, err := ParseS7(s7job(0x1234, readParam(FnWriteVar), []byte("value")))
	if err != nil {
		t.Fatal(err)
	}
	if p.Type != Job || p.PDURef != 0x1234 || p.FunctionName() != "write_var" {
		t.Errorf("pdu = %+v", p)
	}
	if string(p.Data) != "value" {
		t.Errorf("data = %q", p.Data)
	}
	if p.HasError {
		t.Error("a job carried an error field")
	}

	// An acknowledgement's error octets are between the header and the
	// parameters, which is the offset a reader gets wrong.
	a, err := ParseS7(s7ack(0x1234, 0x85, 0x04, []byte{FnReadVar, 1}, []byte("d")))
	if err != nil {
		t.Fatal(err)
	}
	if !a.HasError || a.ErrClass != 0x85 || a.ErrCode != 0x04 {
		t.Errorf("error = %#x %#x, %v", a.ErrClass, a.ErrCode, a.HasError)
	}
	if ErrorClassName(a.ErrClass) != "supplies" || ErrorClassName(0x87) != "access_fault" {
		t.Errorf("class names = %q %q", ErrorClassName(a.ErrClass), ErrorClassName(0x87))
	}
	if a.FunctionName() != "read_var" || string(a.Data) != "d" {
		t.Errorf("ack = %+v", a)
	}
	// An error class of zero is no error, which is not the same as a PDU
	// carrying none.
	z, _ := ParseS7(s7ack(1, 0, 0, []byte{FnReadVar}, nil))
	if !z.HasError || ErrorClassName(z.ErrClass) != "no_error" {
		t.Errorf("a successful acknowledgement read as %+v", z)
	}

	for _, c := range []struct {
		name string
		b    []byte
		want string
	}{
		{"too short", []byte{ProtocolID, 1, 0, 0, 0}, "shorter than its own fields"},
		{"not S7", []byte{0x33, 1, 0, 0, 0, 1, 0, 0, 0, 0}, "protocol identifier"},
		{"lengths past the frame", cat([]byte{ProtocolID, 1, 0, 0, 0, 1}, be16(40), be16(0)),
			"and carries"},
		{"an acknowledgement with no error field", cat([]byte{ProtocolID, uint8(AckData), 0, 0, 0, 1},
			be16(0), be16(0)), "no error field"},
	} {
		if _, err := ParseS7(c.b); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
	// A function code nobody documents is named by its number, not guessed
	// at.
	u, _ := ParseS7(s7job(1, []byte{0x77}, nil))
	if u.KnownFunction() {
		t.Error("function 0x77 is in the catalogue")
	}
	if u.FunctionName() != "0x77" {
		t.Errorf("function name = %q", u.FunctionName())
	}
	// And a job with no parameter at all has no function, which is a
	// different answer from function zero.
	n, _ := ParseS7(s7job(1, nil, nil))
	if n.HasFunction || n.FunctionName() != "none" {
		t.Errorf("a parameterless job read as %+v", n)
	}
}

func TestTheNegotiatedPDULengthIsRead(t *testing.T) {
	p, err := ParseS7(s7job(1, cat([]byte{FnSetupComm, 0}, be16(1), be16(1), be16(480)), nil))
	if err != nil {
		t.Fatal(err)
	}
	calling, called, length, ok := p.Setup()
	if !ok || calling != 1 || called != 1 || length != 480 {
		t.Errorf("setup = %d %d %d, %v", calling, called, length, ok)
	}
	// And a setup job too short to hold the field says so rather than
	// reporting a length of zero as a negotiation.
	short, _ := ParseS7(s7job(1, []byte{FnSetupComm, 0, 0, 1}, nil))
	if _, _, _, ok := short.Setup(); ok {
		t.Error("a truncated setup was read as a negotiation")
	}
	// Another function is not a setup.
	other, _ := ParseS7(s7job(1, readParam(FnReadVar), nil))
	if _, _, _, ok := other.Setup(); ok {
		t.Error("a read was read as a setup")
	}
}

// The control services, which are the difference between "the CPU was
// restarted" and "a block was deleted".
func TestTheControlServiceNameIsRead(t *testing.T) {
	// PLC stop: five reserved octets, a length and the name.
	stop := cat([]byte{FnPLCStop, 0, 0, 0, 0, 0, 9}, []byte("P_PROGRAM"))
	p, err := ParseS7(s7job(1, stop, nil))
	if err != nil {
		t.Fatal(err)
	}
	name, ok := p.Service()
	if !ok || name != "P_PROGRAM" {
		t.Errorf("stop service = %q, %v", name, ok)
	}
	// PLC control: seven reserved octets, a parameter block and then the
	// name.
	block := []byte{0xfd, 0x00, 0x00, 0x09}
	ctl := cat([]byte{FnPLCControl, 0, 0, 0, 0, 0, 0, 0}, be16(uint16(len(block))), block,
		[]byte{5}, []byte("_INSE"))
	p2, err := ParseS7(s7job(1, ctl, nil))
	if err != nil {
		t.Fatal(err)
	}
	if name, ok := p2.Service(); !ok || name != "_INSE" {
		t.Errorf("control service = %q, %v", name, ok)
	}
	// A truncated one is unknown rather than a shorter name.
	for n := 1; n < len(ctl); n++ {
		p3, err := ParseS7(s7job(1, ctl[:n], nil))
		if err != nil {
			continue
		}
		if name, ok := p3.Service(); ok && name != "_INSE" {
			t.Errorf("%d octets of a control job gave the service %q", n, name)
		}
	}
	// And a read has no service name.
	p4, _ := ParseS7(s7job(1, readParam(FnReadVar), nil))
	if _, ok := p4.Service(); ok {
		t.Error("a read carried a service name")
	}
}

func TestTheBlockADownloadNamesIsRead(t *testing.T) {
	// A request to download data block 10.
	param := cat([]byte{FnRequestDownload, 0, 0, 0, 0, 0, 0, 0}, blockName("08", 10))
	p, err := ParseS7(s7job(1, param, nil))
	if err != nil {
		t.Fatal(err)
	}
	kind, number, ok := p.Block()
	if !ok || kind != "db" || number != 10 {
		t.Errorf("block = %q %d, %v", kind, number, ok)
	}
	// An upload of a function block.
	up := cat([]byte{FnStartUpload, 0, 0, 0, 0, 0, 0, 0}, blockName("0E", 1))
	p2, _ := ParseS7(s7job(1, up, nil))
	if kind, number, ok := p2.Block(); !ok || kind != "fb" || number != 1 {
		t.Errorf("block = %q %d, %v", kind, number, ok)
	}
	// A name whose digits are not digits is not a block.
	bad := cat([]byte{FnRequestDownload, 0, 0, 0, 0, 0, 0, 0}, []byte("_08ABCDEP"))
	p3, _ := ParseS7(s7job(1, bad, nil))
	if _, _, ok := p3.Block(); ok {
		t.Error("a name with letters where the number goes was read as a block")
	}
	// And a function that names no block says so.
	p4, _ := ParseS7(s7job(1, readParam(FnReadVar), nil))
	if _, _, ok := p4.Block(); ok {
		t.Error("a read named a block")
	}
}
