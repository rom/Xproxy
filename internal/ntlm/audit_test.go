package ntlm

import (
	"bytes"
	"testing"
)

// The sixth audit round over this package. The challenge is what a
// desktop sends back inside the tunnel before anything is proved, and
// its target information is a list of attribute-value pairs whose
// lengths are the peer's to choose.

func FuzzParseChallenge(f *testing.F) {
	// A minimal well-formed challenge: the signature, the type, and
	// the fixed fields.
	good := append([]byte("NTLMSSP\x00"), 0x02, 0x00, 0x00, 0x00)
	good = append(good, bytes.Repeat([]byte{0}, 44)...)
	f.Add(good)
	f.Add([]byte("NTLMSSP\x00"))
	f.Add(bytes.Repeat([]byte{0xFF}, 64))
	f.Fuzz(func(t *testing.T, b []byte) {
		ch, err := ParseChallenge(b)
		if err != nil {
			return
		}
		// Everything taken out of it has to be inside it. A length or
		// an offset believed rather than checked is how a parser reads
		// past its own buffer.
		if len(ch.TargetInfo) > len(b) {
			t.Fatalf("target information of %d bytes out of %d", len(ch.TargetInfo), len(b))
		}
		if len(ch.ServerChallenge) != 8 {
			t.Fatalf("a challenge of %d bytes", len(ch.ServerChallenge))
		}
		// The name is wide text decoded to UTF-8, where a two byte
		// unit becomes at most three, so the bound is half as much
		// again rather than the length itself. Asserting it at all is
		// the point: a decoder that expanded without a bound would be
		// an amplifier for anything that reaches it.
		if len(ch.TargetName) > 3*len(b)/2+8 {
			t.Fatalf("a target name of %d bytes out of %d", len(ch.TargetName), len(b))
		}
	})
}
