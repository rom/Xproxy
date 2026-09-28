package coap

import (
	"bytes"
	"testing"
)

// FuzzParse is the guarantee the relay rests on: whatever arrives on UDP 5683,
// reading it neither panics nor reports more than it read.
//
// The invariant checked on a message that parses is that it writes back to the
// octets it was read from. That is stronger than "did not crash" and it is the
// property a relay actually needs: a message whose re-encoding differs is one
// where the relay's view and the device's view of the same datagram disagree, and
// a policy decided on the relay's view would be deciding about a different
// request than the one the device answers.
func FuzzParse(f *testing.F) {
	f.Add(hdr(Confirmable, GET, 1, 0))
	f.Add(append(hdr(Confirmable, GET, 0x1234, 0), 0xb4, 't', 'e', 'm', 'p'))
	f.Add(append(hdr(NonConfirmable, POST, 2, 0), 0xb4, 't', 'e', 'm', 'p',
		PayloadMarker, 'o', 'n'))
	f.Add(hdr(Acknowledgement, Empty, 3, 0))
	f.Add(hdr(Reset, Empty, 4, 0))
	f.Add(append(hdr(Confirmable, GET, 5, 0), 0xd3, 0x16, 'x', 'y', 'z')) // proxy_uri
	f.Add(append(hdr(Confirmable, GET, 6, 0), 0x61, 0x00))                // observe
	f.Add(append(hdr(Confirmable, GET, 7, 0), 0xd1, 0x0a, 0x0e))          // block2
	f.Add(append(hdr(Confirmable, GET, 8, 2), 0xab, 0xcd, 0xb1, '.'))

	f.Fuzz(func(t *testing.T, raw []byte) {
		m, err := Parse(raw)
		if err != nil {
			return
		}
		// Nothing was read past the end, which re-encoding proves.
		out, err := Encode(m)
		if err != nil {
			t.Fatalf("parsed %x but would not write it back: %v", raw, err)
		}
		if !bytes.Equal(out, raw) {
			t.Fatalf("parsed %x and wrote back %x", raw, out)
		}
		// Every accessor runs on whatever came through, because the relay calls
		// them on exactly this input and a panic in one is a panic a datagram
		// can cause.
		_ = m.Path()
		_ = m.Query()
		_ = m.SuspiciousPath()
		_ = m.Numbers()
		_ = m.Repeated()
		_ = m.UnknownCritical()
		_ = m.UnknownUnSafe()
		_ = m.Proxying()
		_ = m.ProxyURI()
		_ = m.ProxyScheme()
		_ = m.URIHost()
		_ = m.URIPort()
		_ = m.Registering()
		_ = m.Deregistering()
		_ = m.IsWellKnownCore()
		_ = m.TransferSize()
		_ = m.ETags()
		_, _ = m.ContentFormat()
		_, _ = m.Accept()
		_, _ = m.MaxAge()
		_, _ = m.Size1()
		_, _ = m.Size2()
		_, _ = m.Observe()
		_, _ = m.HopLimit()
		_, _, _ = m.Block1()
		_, _, _ = m.Block2()
		_ = m.ValidateOptions()
		_ = m.Code.String()
		_ = m.Type.String()

		// And a clone that has had an option taken out of it still writes.
		c := m.Clone()
		c.Remove(OptionProxyURI)
		c.Remove(OptionObserve)
		if _, err := Encode(c); err != nil {
			t.Fatalf("an edited copy of %x would not write back: %v", raw, err)
		}
	})
}

// FuzzBlock is the arithmetic a transfer bound depends on, at every input.
func FuzzBlock(f *testing.F) {
	f.Add([]byte(nil))
	f.Add([]byte{0x0e})
	f.Add([]byte{0xff, 0xf6})
	f.Add([]byte{0xff, 0xff, 0xf6})
	f.Fuzz(func(t *testing.T, v []byte) {
		b, err := ParseBlock(v)
		if err != nil {
			return
		}
		if b.Size() < 16 || b.Size() > 1024 {
			t.Fatalf("%x is %d octets a block", v, b.Size())
		}
		if b.Offset() < 0 || b.End() < b.Offset() {
			t.Fatalf("%x has offset %d and end %d", v, b.Offset(), b.End())
		}
		// The value renders to the same block. It does not have to render to the
		// same octets: RFC 7252 s3.2 leaves the leading zeros of a numeric option
		// out, so one zero octet and no octets are the same block written two
		// ways, and the rendering is the canonical one of the two.
		out := b.AppendTo(nil)
		again, err := ParseBlock(out)
		if err != nil {
			t.Fatalf("%x rendered to %x, which does not parse: %v", v, out, err)
		}
		if again != b {
			t.Fatalf("%x is %+v and rendered to %x, which is %+v", v, b, out, again)
		}
		if len(out) > 0 && out[0] == 0 {
			t.Fatalf("%x rendered to %x, which is not canonical", v, out)
		}
	})
}
