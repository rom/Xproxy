package rdp

import (
	"bytes"
	"testing"
)

// The sixth audit round, over the parsers this package added after the
// fifth. Everything here reads bytes a client or a desktop chose, so
// every length in them is somebody else's to pick: the questions are
// whether a length can be believed, whether one can be made to
// allocate, and whether anything panics rather than returning an
// error.
//
// The rule these targets hold to is the one the earlier rounds used: a
// parser may return an error for anything, but it may not panic, may
// not allocate on a length it has not checked against what arrived,
// and may not loop forever.

func FuzzReadPDU(f *testing.F) {
	f.Add([]byte{0x03, 0x00, 0x00, 0x0b, 0x02, 0xf0, 0x80, 0x01, 0x02, 0x03, 0x04})
	f.Add([]byte{0x00, 0x10, 0x01, 0x02})
	f.Add([]byte{0x00, 0x80, 0x20, 0x01})
	f.Add([]byte{0x03, 0x00, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, b []byte) {
		pdu, err := ReadPDU(bytes.NewReader(b))
		if err != nil {
			return
		}
		// What came back has to be inside what arrived: a framing that
		// claims more than it has is the classic way a proxy is made
		// to read somebody else's memory.
		if len(pdu.Raw) > len(b) {
			t.Fatalf("a pdu of %d bytes out of %d", len(pdu.Raw), len(b))
		}
		if len(pdu.Body) > len(pdu.Raw) {
			t.Fatalf("a body of %d bytes in a pdu of %d", len(pdu.Body), len(pdu.Raw))
		}
		// Anything that parsed is forwarded by the gateway, so it has
		// to survive being read again.
		if _, err := ReadPDU(bytes.NewReader(pdu.Raw)); err != nil {
			t.Fatalf("a pdu this parser produced does not parse: %v", err)
		}
	})
}

func FuzzParseConnect(f *testing.F) {
	f.Add([]byte{0x7f, 0x65, 0x10, 0x04, 0x01, 0x00})
	f.Add([]byte{0x7f, 0x66, 0x10, 0x0a, 0x01, 0x00})
	f.Fuzz(func(t *testing.T, b []byte) {
		conn, err := ParseConnect(b)
		if err != nil {
			return
		}
		blocks, err := conn.Walk()
		if err != nil {
			return
		}
		for _, blk := range blocks {
			if len(blk.Data) > len(b) {
				t.Fatalf("a block of %d bytes out of %d", len(blk.Data), len(b))
			}
		}
		// Re-encoding is what the gateway does to every conference
		// unit it rewrites, so it must not fail on anything that
		// parsed, and the result must parse again.
		out, err := conn.Encode()
		if err != nil {
			return
		}
		body, err := X224Payload(out[4:])
		if err != nil {
			t.Fatalf("a re-encoded connect unit is not a data unit: %v", err)
		}
		if _, err := ParseConnect(body); err != nil {
			t.Fatalf("a re-encoded connect unit does not parse: %v", err)
		}
	})
}

func FuzzParseChannels(f *testing.F) {
	f.Add([]byte{0x01, 0x00, 0x00, 0x00, 'r', 'd', 'p', 'd', 'r', 0, 0, 0, 0x00, 0x00, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, b []byte) {
		list, err := ParseChannels(b)
		if err != nil {
			return
		}
		// A channel list is bounded by what arrived: eight bytes of
		// name and four of options each.
		if len(list)*12 > len(b) {
			t.Fatalf("%d channels out of %d bytes", len(list), len(b))
		}
		out, err := EncodeChannels(list)
		if err != nil {
			return
		}
		again, err := ParseChannels(out)
		if err != nil || len(again) != len(list) {
			t.Fatalf("a re-encoded channel list gave %d channels (%v)", len(again), err)
		}
	})
}

func FuzzParseServerChannels(f *testing.F) {
	f.Add([]byte{0xeb, 0x03, 0x01, 0x00, 0xec, 0x03})
	f.Fuzz(func(t *testing.T, b []byte) {
		sc, err := ParseServerChannels(b)
		if err != nil {
			return
		}
		if len(sc.IDs)*2 > len(b) {
			t.Fatalf("%d identifiers out of %d bytes", len(sc.IDs), len(b))
		}
	})
}

func FuzzParseClientInfo(f *testing.F) {
	f.Add(bytes.Repeat([]byte{0}, 40))
	// A packet in wide text, which is the case where the decoded
	// strings are longer than the bytes they came in.
	f.Add([]byte("00000000x\x000\x000\x00\v\x000\x00" + string(bytes.Repeat([]byte{'0'}, 280))))
	f.Fuzz(func(t *testing.T, b []byte) {
		info, err := ParseClientInfo(b)
		if err != nil {
			return
		}
		// The five strings together are bounded by what arrived, but
		// not by its length: wide text decodes to UTF-8, where a two
		// byte unit becomes at most three bytes. So the bound is half
		// as much again, and anything past that means a length was
		// believed rather than checked.
		n := len(info.Domain) + len(info.Username) + len(info.Password) + len(info.Shell) + len(info.Dir)
		if n > 3*len(b)/2+8 {
			t.Fatalf("%d bytes of text out of %d", n, len(b))
		}
		out, err := info.Encode()
		if err != nil {
			return
		}
		again, err := ParseClientInfo(out)
		if err != nil {
			t.Fatalf("a re-encoded client info packet does not parse: %v", err)
		}
		if again.Username != info.Username || again.Password != info.Password || again.Domain != info.Domain {
			t.Fatalf("the credential changed through a round trip: %q %q %q", again.Domain, again.Username, again.Password)
		}
	})
}

func FuzzParseDeviceAnnounce(f *testing.F) {
	f.Add([]byte{'r', 'D', 'A', 'D', 0x01, 0x00, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, b []byte) {
		if !IsDeviceAnnounce(b) {
			return
		}
		devices, err := ParseDeviceAnnounce(b)
		if err != nil {
			return
		}
		if len(devices)*20 > len(b)+20 {
			t.Fatalf("%d devices out of %d bytes", len(devices), len(b))
		}
		out, err := EncodeDeviceAnnounce(devices)
		if err != nil {
			return
		}
		again, err := ParseDeviceAnnounce(out)
		if err != nil || len(again) != len(devices) {
			t.Fatalf("a re-encoded announcement gave %d devices (%v)", len(again), err)
		}
	})
}

func FuzzParseServerSecurity(f *testing.F) {
	f.Add(append([]byte{0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}, bytes.Repeat([]byte{0}, 40)...))
	f.Fuzz(func(t *testing.T, b []byte) {
		sec, err := ParseServerSecurity(b)
		if err != nil {
			return
		}
		if len(sec.Random) > len(b) {
			t.Fatalf("a random of %d bytes out of %d", len(sec.Random), len(b))
		}
		if sec.PublicKey != nil && sec.PublicKey.N.BitLen() > 8192 {
			t.Fatalf("a key of %d bits", sec.PublicKey.N.BitLen())
		}
	})
}

func FuzzParseSendData(f *testing.F) {
	f.Add([]byte{0x64, 0x00, 0x07, 0x03, 0xeb, 0x70, 0x04, 0x01, 0x02, 0x03, 0x04})
	f.Fuzz(func(t *testing.T, b []byte) {
		data, ok, err := ParseSendData(b)
		if err != nil || !ok {
			return
		}
		if len(data.Payload) > len(b) {
			t.Fatalf("a payload of %d bytes out of %d", len(data.Payload), len(b))
		}
		if _, err := DataPDU(data.Encode()); err != nil {
			return
		}
	})
}

func FuzzParseChannelChunk(f *testing.F) {
	f.Add([]byte{0x04, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 1, 2, 3, 4})
	f.Fuzz(func(t *testing.T, b []byte) {
		chunk, err := ParseChannelChunk(b)
		if err != nil {
			return
		}
		if len(chunk.Data) > len(b) {
			t.Fatalf("a chunk of %d bytes out of %d", len(chunk.Data), len(b))
		}
	})
}

func FuzzParseConnectionRequest(f *testing.F) {
	f.Add([]byte{0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, b []byte) {
		cr, err := ParseConnectionRequest(b)
		if err != nil {
			return
		}
		if len(cr.Cookie) > len(b) {
			t.Fatalf("a cookie of %d bytes out of %d", len(cr.Cookie), len(b))
		}
		if _, err := cr.Encode(); err != nil {
			return
		}
	})
}

func FuzzParseSecurityExchange(f *testing.F) {
	f.Add(append([]byte{0x48, 0x00, 0x00, 0x00}, bytes.Repeat([]byte{0xAA}, 72)...))
	f.Fuzz(func(t *testing.T, b []byte) {
		sealed, err := ParseSecurityExchange(b)
		if err != nil {
			return
		}
		if len(sealed) > len(b) {
			t.Fatalf("a sealed value of %d bytes out of %d", len(sealed), len(b))
		}
	})
}

// FuzzReadTSRequest covers the CredSSP envelope, which is the first
// thing a desktop sends back inside the tunnel and is read before
// anything has been authenticated.
func FuzzReadTSRequest(f *testing.F) {
	f.Add([]byte{0x30, 0x06, 0xa0, 0x03, 0x02, 0x01, 0x06})
	f.Add([]byte{0x30, 0x80, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, b []byte) {
		req, err := readTSRequest(bytes.NewReader(b))
		if err != nil {
			return
		}
		for _, tok := range req.NegoTokens {
			if len(tok.Token) > len(b) {
				t.Fatalf("a token of %d bytes out of %d", len(tok.Token), len(b))
			}
		}
		if len(req.PubKeyAuth) > len(b) || len(req.AuthInfo) > len(b) || len(req.ClientNonce) > len(b) {
			t.Fatal("a field longer than the request it came in")
		}
	})
}

// TestAShortLengthIndicatorIsNotASlice is the regression for the
// panic the sixth round's fuzzing found: a connection request whose
// X.224 length indicator is shorter than the fixed header it is
// supposed to cover. The unit is li+1 bytes, the header is seven, and
// taking the options out of it was body[7:li+1] -- a slice whose start
// is past its end, which panics rather than erring.
//
// It is the first packet of a connection, from a peer that has proved
// nothing, and the same shape was in the parser that reads what a
// desktop answers: a hostile or simply broken upstream could do it
// too.
func TestAShortLengthIndicatorIsNotASlice(t *testing.T) {
	for li := 0; li < 8; li++ {
		for _, typ := range []byte{x224CR, x224CC} {
			body := append([]byte{byte(li), typ}, bytes.Repeat([]byte{0x30}, 6)...)
			var err error
			if typ == x224CR {
				_, err = ParseConnectionRequest(body)
			} else {
				_, err = ParseConnectionConfirm(body)
			}
			// Six is the smallest indicator that covers the header.
			if li >= 6 {
				if err != nil {
					t.Errorf("type %#02x li %d was refused: %v", typ, li, err)
				}
				continue
			}
			if err == nil {
				t.Errorf("type %#02x li %d was accepted", typ, li)
			}
		}
	}
	// And the whole unit, as it arrives on the wire, through the reader
	// the listener actually calls.
	pdu, err := TPKT(append([]byte{0x00, x224CR}, bytes.Repeat([]byte{0x30}, 6)...))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ReadPDU(bytes.NewReader(pdu))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseConnectionRequest(got.Body); err == nil {
		t.Fatal("a unit with a length indicator of zero was accepted")
	}
}
