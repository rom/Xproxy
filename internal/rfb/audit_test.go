package rfb

import (
	"bytes"
	"testing"
)

// The sixth audit round over this package, which is where a VNC
// session's handshake is read. Everything here runs before anything
// has been authenticated -- most of it before the security type has
// even been agreed -- and several of the readers are reimplementations
// of vendors' own types, where the shape came from a description
// rather than from a specification.
//
// The invariant is the one the earlier rounds used: a reader may refuse
// anything, but it may not panic, may not allocate on a length it has
// not checked against a bound, and may not return more than the bound
// it advertises.

func FuzzReadSecurityList(f *testing.F) {
	f.Add([]byte{0x02, 0x01, 0x02})
	f.Add([]byte{0x00, 0x00, 0x00, 0x00, 0x04, 'n', 'o', 'p', 'e'})
	f.Fuzz(func(t *testing.T, b []byte) {
		types, err := ReadSecurityList(bytes.NewReader(b))
		if err != nil {
			return
		}
		if len(types) > MaxSecurityTypes || len(types) > len(b) {
			t.Fatalf("%d security types out of %d bytes", len(types), len(b))
		}
	})
}

func FuzzReadString(f *testing.F) {
	f.Add([]byte{0x00, 0x00, 0x00, 0x03, 'a', 'b', 'c'})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := ReadString(bytes.NewReader(b), MaxReason)
		if err != nil {
			return
		}
		if len(s) > MaxReason || len(s) > len(b) {
			t.Fatalf("a string of %d bytes out of %d", len(s), len(b))
		}
	})
}

func FuzzReadServerInit(f *testing.F) {
	f.Add(append(bytes.Repeat([]byte{0x01}, 24), 0x00, 0x00, 0x00, 0x02, 0x68, 0x69))
	f.Fuzz(func(t *testing.T, b []byte) {
		init, err := ReadServerInit(bytes.NewReader(b))
		if err != nil {
			return
		}
		if len(init.Name) > MaxName || len(init.Name) > len(b) {
			t.Fatalf("a desktop name of %d bytes out of %d", len(init.Name), len(b))
		}
		// What comes back is forwarded to the client, so it has to
		// re-encode and read back the same.
		again, err := ReadServerInit(bytes.NewReader(init.Encode()))
		if err != nil {
			t.Fatalf("a re-encoded server init does not parse: %v", err)
		}
		if again.Name != init.Name || again.Width != init.Width || again.Height != init.Height {
			t.Fatalf("a server init changed through a round trip")
		}
	})
}

func FuzzReadSubtypes(f *testing.F) {
	f.Add([]byte{0x02, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01})
	f.Fuzz(func(t *testing.T, b []byte) {
		subs, err := ReadSubtypes(bytes.NewReader(b))
		if err != nil {
			return
		}
		if len(subs) > MaxSubtypes || len(subs)*4 > len(b) {
			t.Fatalf("%d subtypes out of %d bytes", len(subs), len(b))
		}
	})
}

func FuzzReadTightCapabilities(f *testing.F) {
	f.Add([]byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 'V', 'N', 'C', 'S', 'T', 'D', 'V', 'N', 'O', 'A', 'U', 'T', 'H', '_'})
	f.Fuzz(func(t *testing.T, b []byte) {
		caps, err := ReadTightCapabilities(bytes.NewReader(b))
		if err != nil {
			return
		}
		if len(caps) > TightMaxCapabilities || len(caps)*16 > len(b) {
			t.Fatalf("%d capabilities out of %d bytes", len(caps), len(b))
		}
	})
}

func FuzzReadRSAAESKey(f *testing.F) {
	f.Add(append([]byte{0x00, 0x00, 0x08, 0x00}, bytes.Repeat([]byte{0x01}, 512)...))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, key, err := ReadRSAAESKey(bytes.NewReader(b))
		if err != nil {
			return
		}
		if key == nil {
			t.Fatal("no error and no key")
		}
		if bits := key.N.BitLen(); bits > RSAAESMaxKeyBits {
			t.Fatalf("a key of %d bits", bits)
		}
	})
}

func FuzzReadARDParams(f *testing.F) {
	f.Add(append([]byte{0x00, 0x02, 0x00, 0x80}, bytes.Repeat([]byte{0x03}, 256)...))
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := ReadARDParams(bytes.NewReader(b))
		if err != nil {
			return
		}
		if len(p.Prime) > ARDMaxPrimeBytes || len(p.Pub) > ARDMaxPrimeBytes {
			t.Fatalf("a prime of %d and a public value of %d bytes", len(p.Prime), len(p.Pub))
		}
	})
}

func FuzzReadMSLogonParams(f *testing.F) {
	f.Add(bytes.Repeat([]byte{0x07}, 24))
	f.Fuzz(func(t *testing.T, b []byte) {
		if _, err := ReadMSLogonParams(bytes.NewReader(b)); err != nil {
			return
		}
	})
}

func FuzzReadVersions(f *testing.F) {
	f.Add([]byte("RFB 003.008\n"))
	f.Add([]byte("RFB 000.000\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if v, err := ReadVersion(bytes.NewReader(b)); err == nil {
			// The twelve bytes a version goes out as have to read
			// back: the gateway sends this to the other leg.
			again, err := ParseVersion(v.Handshake())
			if err != nil || again != v {
				t.Fatalf("a version this reader produced does not parse: %q (%v)", v.String(), err)
			}
		}
		_, _ = ReadVeNCryptVersion(bytes.NewReader(b))
		_, _ = ParseVersion(b)
	})
}

func FuzzReadPlain(f *testing.F) {
	f.Add([]byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 'a', 'b', 'p', 'w', 'd'})
	f.Fuzz(func(t *testing.T, b []byte) {
		user, pass, err := ReadPlain(bytes.NewReader(b), 1024)
		if err != nil {
			return
		}
		if len(user)+len(pass) > len(b) {
			t.Fatalf("%d bytes of credential out of %d", len(user)+len(pass), len(b))
		}
	})
}

func FuzzReadRSAAESCredential(f *testing.F) {
	f.Add([]byte{0x02, 0x02, 'a', 'b', 'c', 'd'})
	f.Fuzz(func(t *testing.T, b []byte) {
		user, pass, err := ReadRSAAESCredential(bytes.NewReader(b))
		if err != nil {
			return
		}
		if len(user) > 255 || len(pass) > 255 {
			t.Fatalf("a credential of %d and %d bytes", len(user), len(pass))
		}
	})
}

func FuzzReadTightInteraction(f *testing.F) {
	f.Add([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, b []byte) {
		if _, err := ReadTightInteraction(bytes.NewReader(b)); err != nil {
			return
		}
	})
}

func FuzzReadSecurityResult(f *testing.F) {
	f.Add([]byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 'n', 'o'})
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, v := range []Version{{3, 3}, {3, 7}, {3, 8}} {
			ok, reason, err := ReadSecurityResult(bytes.NewReader(b), v)
			if err != nil {
				continue
			}
			if ok && reason != "" {
				t.Fatalf("a success with a reason: %q", reason)
			}
			if len(reason) > MaxReason {
				t.Fatalf("a reason of %d bytes", len(reason))
			}
		}
	})
}
