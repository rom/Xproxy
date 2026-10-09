package http

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/ech"
	"github.com/rom/xproxy/internal/testutil"
)

// The management views of the TLS policy: what each listener offers, what
// clients actually agreed to, which certificates are running out and which
// listeners accept an Encrypted Client Hello.
//
// They are computed when they are asked rather than on a timer, so what they
// say is the state of the listeners as they stand: a certificate that expires
// while nothing reloads is still reported, and a listener that names no key
// agreement groups reports the ones it does offer rather than an empty list.
// A status view that answered from the configuration file instead would be
// one an operator cannot use to tell what is being served.

// echKeys writes an ECH configuration and its private key and returns the
// two paths, as `xproxyctl ech keygen` would.
func echKeys(t *testing.T, dir, publicName string) (string, string) {
	t.Helper()
	cfg, priv, err := ech.Generate(publicName, 1)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := cfg.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "ech.config")
	keyPath := filepath.Join(dir, "ech.key")
	if err := os.WriteFile(cfgPath, enc, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, priv, 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, keyPath
}

func TestTheTLSStatusViewsAnswerForTheListenersAsTheyAre(t *testing.T) {
	a := newBackend(t, "a")
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "tls.test")
	echCfg, echKey := echKeys(t, dir, "tls.test")
	s, _ := startServer(t, fmt.Sprintf(`
version: 1
server:
  session_tickets: {secret_file: %[1]s/tickets.key, rotate: 1h}
  listeners:
    - name: edge
      address: "127.0.0.1:0"
      tls:
        min_version: "1.3"
        key_exchange: [X25519MLKEM768, X25519]
        expiry: {warn: 336h}
        ech: {keys: [{config_file: %[2]s, key_file: %[3]s}]}
        certificates: [{cert_file: %[4]s, key_file: %[5]s}]
    - name: plain
      address: "127.0.0.1:0"
      tls:
        certificates: [{cert_file: %[4]s, key_file: %[5]s}]
    - name: main
      address: "127.0.0.1:0"
logging: {access: {enabled: false}}
upstreams:
  - {name: app, endpoints: [{address: %[6]s}]}
routes:
  - {name: app, paths: [/], upstream: app}
`, dir, echCfg, echKey, cert, key, a.addr()))

	// One real handshake, so the negotiated side of the view has something
	// in it that a client actually chose.
	if code, _, err := tlsGet(s.Addrs()["edge"], "/"); err != nil || code != http.StatusOK {
		t.Fatalf("https through the edge listener: %d %v", code, err)
	}

	kx := s.KeyExchange()
	if got := kx.Groups["edge"]; len(got) != 2 || got[0] != "X25519MLKEM768" {
		t.Errorf("the groups edge offers are %v, want the two it names in order", got)
	}
	// A listener that names none offers the default list, and that is what
	// the view has to say: an empty entry would read as "offers nothing".
	if len(kx.Groups["plain"]) == 0 {
		t.Error("a listener that names no groups reported none")
	}
	if got, ok := kx.Groups["main"]; ok {
		t.Errorf("a listener with no tls section reported groups %v", got)
	}
	if len(kx.Negotiated) == 0 {
		t.Error("a completed handshake was not counted under its group")
	}

	// The test certificates are good for an hour, which is inside any
	// warning window worth setting.
	exp := s.ExpiringCertificates()
	if len(exp["edge"]) != 1 {
		t.Errorf("the expiring list for edge is %v", exp["edge"])
	} else if !strings.Contains(exp["edge"][0], "tls.test") {
		t.Errorf("the warning does not name the certificate: %q", exp["edge"][0])
	}
	// A listener with no expiry section asked for no warning, and is left
	// out rather than reported as fine.
	if w, ok := exp["plain"]; ok {
		t.Errorf("a listener with no expiry section was reported: %v", w)
	}

	// Same rule for ECH: a listener without the section is absent rather
	// than reported as disabled, so an empty map means no listener takes it.
	echSt := s.ECH()
	if echSt["edge"] == nil {
		t.Errorf("the ECH view holds %v, want the listener that accepts it", echSt)
	}
	if _, ok := echSt["plain"]; ok {
		t.Error("a listener without the section was reported as accepting ECH")
	}

	tk := s.Tickets()
	if tk == nil || !tk.Enabled || tk.Keys == 0 || tk.Fingerprint == "" {
		t.Errorf("the session ticket status is %+v", tk)
	}

	// And all of it is in the exposition, at zero where it has to be: a
	// series that appears only once something has happened cannot be
	// alerted on, because there is nothing to compare against.
	var buf bytes.Buffer
	if err := s.WriteMetrics(&buf); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		`xproxy_tls_ech_total{listener="edge",outcome="accepted"} 0`,
		`xproxy_tls_ech_total{listener="edge",outcome="not_used"} 1`,
		`xproxy_tls_ech_total{listener="edge",outcome="refused"} 0`,
		`xproxy_tls_key_exchange_total{group="`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("exposition lacks %q", want)
		}
	}
}

// A ticket key set is shared state: every node of a cluster has to hold the
// same one, so the status view names the set rather than only saying that
// tickets are on. Without the fingerprint an operator cannot tell a
// deployment where resumption works from one where it silently does not.
func TestTheTicketKeySetIsNamedInTheStatus(t *testing.T) {
	a := newBackend(t, "a")
	dir := t.TempDir()
	secret := filepath.Join(dir, "tickets.key")
	s, url := startServer(t, fmt.Sprintf(`
version: 1
server:
  session_tickets: {secret_file: %s, rotate: 2h}
  listeners:
    - {name: main, address: "127.0.0.1:0"}
logging: {access: {enabled: false}}
upstreams:
  - {name: app, endpoints: [{address: %s}]}
routes:
  - {name: app, paths: [/], upstream: app}
`, secret, a.addr()))

	// The keyring was created, owner readable only: it is the material
	// every resumed session on every node is decrypted with.
	info, err := os.Stat(secret)
	if err != nil {
		t.Fatalf("the keyring was not created: %v", err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("the keyring is mode %o", mode)
	}
	tk := s.Tickets()
	if tk == nil || tk.Rotate != "2h0m0s" || tk.MasterKeys == 0 {
		t.Fatalf("the ticket status is %+v", tk)
	}
	// Two keys per master: the current epoch encrypts, the one before it
	// still decrypts, which is what makes a rotation invisible to clients.
	if tk.Keys != 2*tk.MasterKeys {
		t.Errorf("%d keys for %d master keys", tk.Keys, tk.MasterKeys)
	}
	// And the proxy is still serving plain HTTP beside all of it.
	resp, err := http.Get(url + "/") //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET / gave %d", resp.StatusCode)
	}
}
