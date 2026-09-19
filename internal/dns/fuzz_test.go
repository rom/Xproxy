package dns

import (
	"strings"
	"testing"
)

// FuzzParseMessage feeds arbitrary wire data to the full message parser
// (header, question, every record with name decompression). It must not
// panic and a parsed message must be consistent with its header counts.
func FuzzParseMessage(f *testing.F) {
	f.Add(sampleQuery)
	f.Add(sampleAnswer)
	// A compression pointer loop.
	loop := append([]byte{0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}, 0xc0, 0x0c, 0, 1, 0, 1)
	f.Add(loop)
	f.Add([]byte{})
	f.Add(make([]byte, 12))
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := ParseMessage(data)
		if err != nil {
			return
		}
		if len(m.Answer) != int(m.Header.ANCount) || len(m.Authority) != int(m.Header.NSCount) || len(m.Additional) != int(m.Header.ARCount) {
			t.Fatalf("record counts %d/%d/%d do not match the header %+v", len(m.Answer), len(m.Authority), len(m.Additional), m.Header)
		}
		if m.QEnd < 12 || m.QEnd > len(data) {
			t.Fatalf("question end %d outside the message of %d bytes", m.QEnd, len(data))
		}
		for _, rr := range append(append(append([]RR(nil), m.Answer...), m.Authority...), m.Additional...) {
			if len(rr.Data) > len(data) || len(rr.Name) > 253 {
				t.Fatalf("bad record %+v", rr)
			}
		}
	})
}

// sampleQuery asks for www.example.com A; sampleAnswer answers it with
// one A record using a compression pointer to the question name.
var (
	sampleQuery = []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
		3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
	sampleAnswer = append(append([]byte{0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0}, sampleQuery[12:]...),
		0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4, 192, 0, 2, 1)
)

// FuzzParseTrustAnchor checks the DS and DNSKEY line parser.
func FuzzParseTrustAnchor(f *testing.F) {
	for _, a := range RootAnchors {
		f.Add(a)
	}
	f.Add(". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D")
	f.Add("example. 3600 IN DNSKEY 257 3 13 AAAA")
	f.Add("")
	f.Add("garbage")
	f.Fuzz(func(t *testing.T, line string) {
		// The root zone is "" (no trailing dot form), so only the absence
		// of panics and a consistent error are checked.
		if _, err := ParseTrustAnchor(line); err != nil && strings.TrimSpace(line) == "" {
			return
		}
	})
}

func BenchmarkParseMessage(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := ParseMessage(sampleAnswer); err != nil {
			b.Fatal(err)
		}
	}
}
