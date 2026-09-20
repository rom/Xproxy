package ldap

import (
	"bytes"
	"testing"
)

// FuzzReadTLV feeds arbitrary bytes to the BER reader that consumes
// everything a directory server sends. A hostile or compromised
// directory is exactly the position this filter has to survive: the
// proxy connects out to it and parses whatever comes back, on a
// goroutine serving a client request.
func FuzzReadTLV(f *testing.F) {
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x01})
	f.Add([]byte{0x30, 0x84, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := readTLV(bytes.NewReader(data))
		if err != nil {
			return
		}
		if len(b) > len(data) {
			t.Fatalf("readTLV returned %d bytes from an input of %d", len(b), len(data))
		}
	})
}

// FuzzParseFilter feeds arbitrary text to the RFC 4515 filter parser.
// Filters are built from configuration templates with a user name
// substituted in, so the text can carry whatever a login form accepted.
func FuzzParseFilter(f *testing.F) {
	f.Add("(uid=alice)")
	f.Add("(&(objectClass=person)(uid=alice))")
	f.Add("(|(a=1)(!(b=2)))")
	f.Add("")
	f.Add("(((((((((((((((((((((a=1)))))))))))))))))))))")
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 4096 {
			return
		}
		p, err := ParseFilter(s)
		if err != nil {
			if p != nil {
				t.Fatalf("an error came with a packet for %q", s)
			}
			return
		}
		if p == nil {
			t.Fatalf("no error and no packet for %q", s)
		}
	})
}
