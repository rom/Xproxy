package sandbox

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/config"
)

const rulesYAML = `
version: 1
server:
  listeners:
    - {name: main, address: "127.0.0.1:0"}
    - {name: tls, address: "127.0.0.1:0", tls: {certificates: [{cert_file: /srv/certs/a.pem, key_file: /srv/certs/a.key}]}}
management: {socket: /run/xproxy/mgmt.sock, history_dir: /var/lib/xproxy/history}
logging:
  directory: /var/log/xproxy
bans: {state_file: /var/lib/xproxy/bans.db}
access: {ledger: /var/lib/xproxy/access/grants.log}
capture: {enabled: true, directory: /var/lib/xproxy/capture}
waf:
  default_profile: p
  profiles:
    - {name: p, crs: {dir: /opt/crs}, directive_files: [/etc/xproxy/waf/excl.conf]}
acme: {directory: https://acme.example/directory, email: a@example.com, accept_terms: true, state_dir: /var/lib/xproxy/acme}
geoip: {database: /usr/share/GeoIP/GeoLite2-Country.mmdb}
upstreams:
  - name: u
    scheme: https
    tls: {ca_file: /etc/pki/upstream/ca.pem}
    endpoints: [{address: "127.0.0.1:1"}]
routes:
  - {name: files, paths: [/static/], static: {root: /srv/www}}
  - {name: r, upstream: u}
sandbox:
  landlock: {read_paths: [/opt/extra], write_paths: [/var/spool/xproxy]}
`

// parse loads the fixture without file checks and appends a wasm filter
// after validation, because the wasm kind compiles its module at load and
// no module exists here.
func parse(t *testing.T, yaml string) *config.Config {
	t.Helper()
	cfg, err := config.ParseWith([]byte(yaml), false)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Filters = append(cfg.Filters, config.FilterConfig{Name: "w", Kind: "wasm",
		Options: map[string]any{"module": "/opt/xproxy/filters/f.wasm", "config": "/not/a/path"}})
	return cfg
}

func TestDerive(t *testing.T) {
	cfg := parse(t, rulesYAML)
	// Includes are resolved at parse time against real files; set the
	// resolved form directly.
	cfg.Includes = []string{"/etc/xproxy/conf.d/*.yaml"}
	cfg.IncludedFiles = []string{"/etc/xproxy/conf.d/10-a.yaml"}
	r := Derive(cfg, "/etc/xproxy/xproxy.yaml")
	// URL paths never become rules: routes[].paths, doh_path and the
	// health check path all start with a slash.
	for _, p := range append(r.Read, r.Write...) {
		if p == "/" || p == "/static" {
			t.Fatalf("URL path leaked into the rules: %v %v", r.Read, r.Write)
		}
	}
	if slices.Contains(r.Write, "/run/systemd/journal") {
		t.Fatal("connect-only socket produced a write rule")
	}
	if slices.Contains(r.Read, "/not") {
		t.Fatal("a non path filter option produced a rule")
	}
	// `directory` is a write rule for logging and capture, but the ACME
	// one of that name is a URL and must not produce a rule of any kind.
	for _, p := range append(r.Read, r.Write...) {
		if strings.Contains(p, "acme.example") || strings.HasPrefix(p, "https:") {
			t.Fatalf("the ACME directory URL became a rule: %s", p)
		}
	}
	wantRead := []string{"/etc/xproxy", "/etc/xproxy/conf.d", "/srv/certs", "/opt/crs", "/etc/xproxy/waf",
		"/usr/share/GeoIP", "/opt/xproxy/filters", "/etc/pki/upstream", "/srv/www", "/opt/extra", "/etc/hosts", "/etc/ssl"}
	for _, p := range wantRead {
		if !slices.Contains(r.Read, p) {
			t.Errorf("read rules lack %s: %v", p, r.Read)
		}
	}
	// The capture directory is written to, not read: the proxy creates
	// a file in it for every recording window. A read rule here means a
	// capture that is configured, switched on, and silently writes
	// nothing under the sandbox that is on by default.
	// The access ledger is appended to for the life of the process, so its
	// directory is a write rule. A read rule there is a daemon that refuses
	// every session until somebody works out that the sandbox, not the
	// policy, was the reason.
	wantWrite := []string{"/run/xproxy", "/var/lib/xproxy/history", "/var/log/xproxy",
		"/var/lib/xproxy", "/var/lib/xproxy/acme", "/var/spool/xproxy",
		"/var/lib/xproxy/capture", "/var/lib/xproxy/access"}
	for _, p := range wantWrite {
		if !slices.Contains(r.Write, p) {
			t.Errorf("write rules lack %s: %v", p, r.Write)
		}
	}
	for _, p := range r.Read {
		if slices.Contains(r.Write, p) {
			t.Errorf("%s is both read and write", p)
		}
		if !strings.HasPrefix(p, "/") || strings.HasSuffix(p, ".pem") || strings.HasSuffix(p, ".wasm") {
			t.Errorf("read rule is not a directory: %s", p)
		}
	}
	if !slices.IsSorted(r.Read) || !slices.IsSorted(r.Write) {
		t.Fatal("rules not sorted")
	}
	// Absolute paths only: a relative or empty value never becomes a rule.
	cfg.Sandbox.Landlock.ReadPaths = append(cfg.Sandbox.Landlock.ReadPaths, "relative/x", "")
	r2 := Derive(cfg, "")
	for _, p := range r2.Read {
		if !strings.HasPrefix(p, "/") {
			t.Fatalf("relative rule %q", p)
		}
	}
	if slices.Contains(r2.Read, ".") {
		t.Fatal("empty config path produced a rule")
	}
}

func TestGlobBase(t *testing.T) {
	cases := map[string]string{
		"/etc/xproxy/conf.d/*.yaml": "/etc/xproxy/conf.d",
		"/etc/xproxy/*/x.yaml":      "/etc/xproxy",
		"/etc/xproxy/a.yaml":        "/etc/xproxy",
		"/etc/xproxy/[ab]/*.yaml":   "/etc/xproxy",
	}
	for in, want := range cases {
		if got := globBase(in); got != want {
			t.Errorf("%s: got %s want %s", in, got, want)
		}
	}
}

func TestCheck(t *testing.T) {
	cfg := parse(t, rulesYAML)
	r := Derive(cfg, "/etc/xproxy/xproxy.yaml")
	st := &Status{Landlocked: true, ReadPaths: r.Read, WritePaths: r.Write}
	if err := st.Check(cfg, "/etc/xproxy/xproxy.yaml"); err != nil {
		t.Fatalf("same configuration refused: %v", err)
	}
	// A new file under an admitted directory is fine; one elsewhere is not.
	inside := parse(t, strings.Replace(rulesYAML, "/srv/certs/a.pem", "/srv/certs/b.pem", 1))
	if err := st.Check(inside, "/etc/xproxy/xproxy.yaml"); err != nil {
		t.Fatalf("file under an admitted directory refused: %v", err)
	}
	deeper := parse(t, strings.Replace(rulesYAML, "/srv/certs/a.pem", "/srv/certs/2026/b.pem", 1))
	if err := st.Check(deeper, "/etc/xproxy/xproxy.yaml"); err != nil {
		t.Fatalf("subdirectory of an admitted directory refused: %v", err)
	}
	outside := parse(t, strings.Replace(rulesYAML, "/srv/certs/a.pem", "/srv/other/b.pem", 1))
	err := st.Check(outside, "/etc/xproxy/xproxy.yaml")
	if err == nil || !errors.Is(err, ErrOutsideRules) || !strings.Contains(err.Error(), "/srv/other (read)") {
		t.Fatalf("outside read accepted: %v", err)
	}
	// A read directory does not admit writes.
	writeOutside := parse(t, strings.Replace(rulesYAML, "state_dir: /var/lib/xproxy/acme", "state_dir: /srv/www/acme", 1))
	err = st.Check(writeOutside, "/etc/xproxy/xproxy.yaml")
	if err == nil || !strings.Contains(err.Error(), "/srv/www/acme (write)") {
		t.Fatalf("write under a read directory accepted: %v", err)
	}
	// Without Landlock everything passes, as does a nil status.
	var none *Status
	if err := none.Check(outside, ""); err != nil {
		t.Fatal(err)
	}
	if err := (&Status{}).Check(outside, ""); err != nil {
		t.Fatal(err)
	}
}

func TestBeneathAny(t *testing.T) {
	roots := []string{"/etc/xproxy", "/var/log/xproxy/"}
	yes := []string{"/etc/xproxy", "/etc/xproxy/a", "/var/log/xproxy/x.log"}
	no := []string{"/etc/xproxy2", "/etc", "/var/log", "/var/log/xproxyfoo"}
	for _, p := range yes {
		if !beneathAny(p, roots) {
			t.Errorf("%s should be beneath", p)
		}
	}
	for _, p := range no {
		if beneathAny(p, roots) {
			t.Errorf("%s should not be beneath", p)
		}
	}
}

// Key custody produces three kinds of rule, and getting any of them wrong is a
// daemon that starts and then fails in a way that looks like something else.
func TestDeriveKeyCustody(t *testing.T) {
	const custodyYAML = `
version: 1
server:
  listeners:
    - name: edge
      address: "127.0.0.1:0"
      tls:
        certificates:
          - cert_file: /srv/certs/legacy.pem
            key_file: /srv/certs/legacy.key
          - cert_file: /srv/certs/ref.pem
            key: file:/srv/keys/ref.key
          - cert_file: /srv/certs/vaulted.pem
            key: vault:secret/tls/edge#key
          - cert_file: /srv/certs/hsm.pem
            signer: {socket: /run/xproxy-signer/signer.sock, key: edge}
secrets:
  vault:
    address: https://vault.internal:8200
    token_file: /etc/xproxy/vault/token
    ca_file: /etc/pki/vault/ca.pem
management: {socket: /run/xproxy/mgmt.sock}
upstreams:
  - name: u
    endpoints: [{address: "127.0.0.1:1"}]
routes:
  - {name: r, upstream: u}
`
	cfg, err := config.ParseWith([]byte(custodyYAML), false)
	if err != nil {
		t.Fatal(err)
	}
	r := Derive(cfg, "/etc/xproxy/xproxy.yaml")
	// The signer's socket is a WRITE rule. Connecting to a Unix socket needs
	// write permission under Landlock, so a read rule here gives a daemon
	// whose every handshake on that certificate fails with permission
	// denied -- and the error names the socket, not the sandbox.
	if !slices.Contains(r.Write, "/run/xproxy-signer") {
		t.Errorf("the signer socket did not produce a write rule: write=%v read=%v", r.Write, r.Read)
	}
	if slices.Contains(r.Read, "/run/xproxy-signer") {
		t.Errorf("the signer socket produced a read rule, which is not enough to connect: %v", r.Read)
	}
	// A file: reference is a key on this machine like any other, so its
	// directory is readable. The walk cannot classify it, because the key is
	// spelt `key` and a reference may just as well be env: or vault:.
	if !slices.Contains(r.Read, "/srv/keys") {
		t.Errorf("a file: key reference did not produce a read rule: %v", r.Read)
	}
	// The vault's token and CA are read. These need no rule of their own --
	// token_file and ca_file are spelt like paths, so the ordinary walk
	// covers them -- but they are asserted here because they are part of
	// what a vault-backed key needs and nothing else checks them.
	for _, p := range []string{"/etc/xproxy/vault", "/etc/pki/vault"} {
		if !slices.Contains(r.Read, p) {
			t.Errorf("read rules lack %s: %v", p, r.Read)
		}
		if slices.Contains(r.Write, p) {
			t.Errorf("%s is a write rule; the token and the CA are only read: %v", p, r.Write)
		}
	}
	// A vault reference is not a path and must not become one. "secret" is
	// a Vault mount, and a rule for /secret or for "secret" relative to
	// anything would be a rule nobody meant.
	for _, p := range append(append([]string{}, r.Read...), r.Write...) {
		if strings.Contains(p, "secret/tls") || p == "/secret" {
			t.Errorf("a vault reference became a path rule: %s", p)
		}
	}
}

// A network feed needs its trust anchor readable and nothing else: the URL,
// the collection id and the credential reference are not paths, and a rule
// derived from one of them would be a rule nobody meant.
func TestDeriveFeedPaths(t *testing.T) {
	const feedYAML = `
version: 1
server:
  listeners: [{name: edge, address: "127.0.0.1:0"}]
threat_intel:
  lists:
    - name: community
      kind: domain
      taxii: {api_root: "https://taxii.example/api1/", collection: 91a7b528-80eb}
      http: {token: "env:TAXII_TOKEN", ca_file: /etc/pki/feeds/ca.pem}
    - name: local
      file: /var/lib/xproxy/intel/deny.txt
management: {socket: /run/xproxy/mgmt.sock}
upstreams:
  - name: u
    endpoints: [{address: "127.0.0.1:1"}]
routes:
  - {name: r, upstream: u}
`
	cfg, err := config.ParseWith([]byte(feedYAML), false)
	if err != nil {
		t.Fatal(err)
	}
	r := Derive(cfg, "/etc/xproxy/xproxy.yaml")
	// The trust anchor is spelt like a path, so the ordinary walk reads it.
	// It is asserted here because a feed whose CA is unreachable fails every
	// fetch with a TLS error that names the certificate, not the sandbox.
	if !slices.Contains(r.Read, "/etc/pki/feeds") {
		t.Errorf("a feed's ca_file did not produce a read rule: %v", r.Read)
	}
	if slices.Contains(r.Write, "/etc/pki/feeds") {
		t.Errorf("a feed's ca_file produced a write rule: %v", r.Write)
	}
	// The file source's directory is reachable.
	if !slices.Contains(r.Read, "/var/lib/xproxy/intel") && !slices.Contains(r.Write, "/var/lib/xproxy/intel") {
		t.Errorf("a list file did not produce a rule: read=%v write=%v", r.Read, r.Write)
	}
	// And nothing that is not a path became one.
	for _, p := range append(append([]string{}, r.Read...), r.Write...) {
		if strings.Contains(p, "taxii.example") || strings.Contains(p, "api1") ||
			strings.Contains(p, "TAXII_TOKEN") || strings.Contains(p, "91a7b528") {
			t.Errorf("a feed setting that is not a path became a rule: %s", p)
		}
	}
}
