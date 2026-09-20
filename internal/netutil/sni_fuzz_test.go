package netutil

import (
	"strings"
	"testing"
)

// FuzzClientHelloSNI feeds arbitrary bytes to the ClientHello peeker.
// It runs on the layer 4 connection goroutine and, through the QUIC
// assembler, on the QUIC listener's read loop, where a panic ends the
// process rather than the flow: a bounds bug here is a remote kill
// switch. The parser must return a name or an error, never panic, and
// the name it returns must be one it could serve as a routing key.
// seedHello builds the smallest ClientHello that carries a server name,
// so the fuzzer starts from a shape it can mutate rather than from
// random bytes that never reach the extension loop.
func seedHello(name string) []byte {
	u16 := func(n int) []byte { return []byte{byte(n >> 8), byte(n)} } //nolint:gosec // lengths are small by construction

	sni := append([]byte{0}, u16(len(name))...) // host_name
	sni = append(sni, name...)
	serverNameList := append(u16(len(sni)), sni...)
	ext := append([]byte{0x00, 0x00}, u16(len(serverNameList))...) // extension type server_name
	ext = append(ext, serverNameList...)
	extensions := append(u16(len(ext)), ext...)

	body := make([]byte, 34) // legacy_version(2) + random(32)
	body = append(body, 0)   // session id length
	body = append(body, u16(2)...)
	body = append(body, 0x13, 0x01) // one cipher suite
	body = append(body, 1, 0)       // one compression method: null
	body = append(body, extensions...)

	hs := append([]byte{0x01, byte(len(body) >> 16)}, u16(len(body))...) //nolint:gosec // as above
	hs = append(hs, body...)
	rec := append([]byte{0x16, 0x03, 0x01}, u16(len(hs))...)
	return append(rec, hs...)
}

func FuzzClientHelloSNI(f *testing.F) {
	// A synthetic hello carrying a name, and the truncation that used
	// to read past its end.
	f.Add(seedHello("example.test"))
	f.Add([]byte{})
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x00})
	body := make([]byte, 34)
	hs := append([]byte{0x01, 0x00, 0x00, byte(len(body))}, body...)
	f.Add(append([]byte{0x16, 0x03, 0x01, 0x00, byte(len(hs))}, hs...))
	f.Fuzz(func(t *testing.T, data []byte) {
		name, err := ClientHelloSNI(data)
		if err != nil {
			if name != "" {
				t.Fatalf("an error came with the name %q", name)
			}
			return
		}
		if name == "" {
			return // a hello without a server name
		}
		if len(name) > 253 {
			t.Fatalf("name of %d bytes accepted", len(name))
		}
		if strings.ContainsAny(name, " \x00/\\") {
			t.Fatalf("name %q carries a byte that must never reach a routing key", name)
		}
		if strings.ToLower(name) != name {
			t.Fatalf("name %q was not folded, so two spellings would route apart", name)
		}
		if strings.HasSuffix(name, ".") {
			t.Fatalf("name %q kept its root dot", name)
		}
	})
}
