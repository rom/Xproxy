package ntske

import (
	"crypto/tls"
	"testing"

	"github.com/rom/xproxy/internal/config"
	ke "github.com/rom/xproxy/internal/ntske"
	"github.com/rom/xproxy/internal/proxytest"
)

// keep_keys is what a rotation keeps, and it is the setting that decides how far
// back a client's cookies may reach. A listener that ignored it would refuse
// every cookie in the estate at each rotation -- and the symptom would be a
// thousand clients re-establishing keys at the same moment, once a day, which is
// not a symptom anybody reads as "a configuration setting was dropped".
func TestTheConfiguredKeyHistoryIsWhatRotationKeeps(t *testing.T) {
	host, err := proxytest.TryStart(`
version: 1
server:
  listeners:
    - name: main
      address: "127.0.0.1:0"
logging: {access: {enabled: false}}
upstreams:
  - {name: web, endpoints: [{address: "127.0.0.1:1"}]}
routes:
  - {name: default, upstream: web}
`)
	if err != nil {
		t.Fatal(err)
	}
	const keep = 3
	n := keep
	cfg := config.Listener{Name: "ke", NTSKE: &config.NTSKEListener{
		Terminate: &config.NTSKETerminate{Cookies: 1, KeepKeys: &n},
	}}
	term, err := newTerminator(host, cfg, &tls.Config{MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	session := &ke.Keys{C2S: make([]byte, ke.KeyLen), S2C: make([]byte, ke.KeyLen)}
	cookie, err := term.keys.Seal(ke.AEADAESSIVCMAC256, session)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < keep; i++ {
		if err := term.keys.Rotate(); err != nil {
			t.Fatal(err)
		}
		if _, _, err := term.keys.Open(cookie); err != nil {
			t.Fatalf("after %d of %d rotations the cookie no longer opens: %v", i+1, keep, err)
		}
	}
	if err := term.keys.Rotate(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := term.keys.Open(cookie); err == nil {
		t.Fatalf("a cookie %d rotations old still opens with a history of %d", keep+1, keep)
	}
}
