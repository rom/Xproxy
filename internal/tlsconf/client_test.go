package tlsconf

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/testutil"
)

// The client side of TLS decides what the proxy will talk to. Its
// options are the ones an operator reaches for when a handshake fails,
// which is exactly when a wrong answer is dangerous.

func TestClientOptions(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	certFile, keyFile := ca.Issue(t, dir, "client")
	caPEM := filepath.Join(dir, "ca.pem")

	// Nothing configured: a safe default, and no reloadable.
	tc, rl, err := Client(nil)
	if err != nil {
		t.Fatal(err)
	}
	if tc.MinVersion != tls.VersionTLS12 || tc.Renegotiation != tls.RenegotiateNever || rl != nil {
		t.Fatalf("defaults: %+v %v", tc, rl != nil)
	}
	if tc.InsecureSkipVerify {
		t.Fatal("verification is off by default")
	}

	// A pinned authority, a server name and a client certificate.
	tc, rl, err = Client(&config.UpstreamTLS{CAFile: caPEM, ServerName: "origin.test",
		ClientCertFile: certFile, ClientKeyFile: keyFile, MinVersion: "1.3"})
	if err != nil {
		t.Fatal(err)
	}
	if tc.RootCAs == nil || tc.ServerName != "origin.test" || tc.MinVersion != tls.VersionTLS13 {
		t.Fatalf("configured: %+v", tc)
	}
	if rl == nil || tc.GetClientCertificate == nil {
		t.Fatal("no client certificate was loaded")
	}
	got, err := tc.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil || len(got.Certificate) == 0 {
		t.Fatalf("client certificate: %v", err)
	}
	// Reloading picks up a replaced file.
	if err := rl.Load(); err != nil {
		t.Fatal(err)
	}
	// A nil reloadable is safe to reload.
	var none *ClientReloadable
	if err := none.Load(); err != nil {
		t.Errorf("reloading nothing: %v", err)
	}

	// Refusals: files that are not there, and a CA file that is not one.
	notPEM := filepath.Join(dir, "not.pem")
	if err := os.WriteFile(notPEM, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, cfg := range map[string]*config.UpstreamTLS{
		"a missing ca file":                    {CAFile: filepath.Join(dir, "none.pem")},
		"a ca file with no certificates":       {CAFile: notPEM},
		"a missing client certificate":         {ClientCertFile: filepath.Join(dir, "none.crt"), ClientKeyFile: keyFile},
		"a client certificate that is not one": {ClientCertFile: notPEM, ClientKeyFile: notPEM},
		"a certificate without its key":        {ClientCertFile: certFile, ClientKeyFile: filepath.Join(dir, "none.key")},
		"a pin that is not base64":             {SPKIPins: []string{"!!!!"}},
		"a pin of the wrong length":            {SPKIPins: []string{base64.StdEncoding.EncodeToString(make([]byte, 31))}},
		"an empty pin":                         {SPKIPins: []string{""}},
		"a hex pin":                            {SPKIPins: []string{strings.Repeat("ab", 32)}},
	} {
		if _, _, err := Client(cfg); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}

	// Verification is only skipped when both flags are set: one of them
	// alone must not turn it off.
	for _, cfg := range []*config.UpstreamTLS{
		{InsecureSkipVerify: true},
		{AllowInsecure: true},
	} {
		tc, _, err := Client(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if tc.InsecureSkipVerify {
			t.Errorf("verification was skipped for %+v", cfg)
		}
	}
	tc, _, err = Client(&config.UpstreamTLS{InsecureSkipVerify: true, AllowInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	if !tc.InsecureSkipVerify {
		t.Error("the double opt-in did not take effect")
	}
}

// TestSPKIPinning covers the check that replaces certificate
// verification for an upstream whose key an operator pinned.
func TestSPKIPinning(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	certFile, _ := ca.Issue(t, dir, "origin.test")
	leaf := loadLeaf(t, certFile)
	otherFile, _ := ca.Issue(t, dir, "other.test")
	other := loadLeaf(t, otherFile)

	pin := SPKIPin(leaf)
	if len(pin) != 44 || strings.ContainsAny(pin, " \r\n") {
		t.Fatalf("pin %q", pin)
	}
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	if pin != base64.StdEncoding.EncodeToString(sum[:]) {
		t.Fatal("the pin is not the digest of the public key")
	}

	tc, _, err := Client(&config.UpstreamTLS{SPKIPins: []string{pin}})
	if err != nil {
		t.Fatal(err)
	}
	if tc.VerifyConnection == nil {
		t.Fatal("no connection check was installed")
	}
	if err := tc.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}); err != nil {
		t.Errorf("the pinned certificate was refused: %v", err)
	}
	// Another certificate from the same authority does not match: the
	// pin is on the key, not on the issuer.
	err = tc.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{other}})
	if err == nil {
		t.Error("another certificate satisfied the pin")
	}
	if !strings.Contains(err.Error(), "spki_pin") {
		t.Errorf("the error does not name the option: %v", err)
	}
	// A handshake with no peer certificate at all.
	if err := tc.VerifyConnection(tls.ConnectionState{}); err == nil {
		t.Error("a connection with no certificate satisfied the pin")
	}
	// Several pins: any of them is enough, which is how a key rotation
	// is rolled out.
	tc, _, err = Client(&config.UpstreamTLS{SPKIPins: []string{SPKIPin(other), pin}})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []*x509.Certificate{leaf, other} {
		if err := tc.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{c}}); err != nil {
			t.Errorf("a listed pin was refused: %v", err)
		}
	}
	// Only the leaf counts: a pin matching an intermediate must not
	// admit a leaf nobody pinned.
	chain := []*x509.Certificate{other, leaf}
	if err := tc.VerifyConnection(tls.ConnectionState{PeerCertificates: chain}); err != nil {
		t.Errorf("the leaf of the chain was not used: %v", err)
	}
}

func loadLeaf(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(data)
	if blk == nil {
		t.Fatal("not PEM")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestVersionName(t *testing.T) {
	cases := map[uint16]string{
		tls.VersionTLS13: "1.3",
		tls.VersionTLS12: "1.2",
	}
	for v, want := range cases {
		if got := VersionName(v); got != want {
			t.Errorf("VersionName(%#x) = %q want %q", v, got, want)
		}
	}
	// Anything else still renders as something short and printable.
	for _, v := range []uint16{0, 0x0301, 0x0302, 0xffff} {
		got := VersionName(v)
		if got == "" || strings.ContainsAny(got, " \t\r\n\"") {
			t.Errorf("VersionName(%#x) = %q", v, got)
		}
	}
}

// TestLoadPool covers the certificate pool behind every CA file option.
func TestLoadPool(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	caPEM := filepath.Join(dir, "ca.pem")
	_ = ca
	pool, err := loadPool(caPEM)
	if err != nil || pool == nil {
		t.Fatalf("a real CA file: %v", err)
	}
	empty := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	text := filepath.Join(dir, "text.pem")
	if err := os.WriteFile(text, []byte("no certificates here"), 0o600); err != nil {
		t.Fatal(err)
	}
	truncated := filepath.Join(dir, "truncated.pem")
	data, err := os.ReadFile(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(truncated, data[:len(data)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"a missing file":   filepath.Join(dir, "none.pem"),
		"an empty file":    empty,
		"text":             text,
		"a truncated file": truncated,
		"a directory":      dir,
	} {
		if _, err := loadPool(path); err == nil {
			t.Errorf("%s was accepted as a certificate pool", name)
		}
	}
}

// TestParseLogList covers the certificate transparency log list, which
// decides whose signature counts as proof a certificate was logged.
func TestParseLogList(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	certFile, _ := ca.Issue(t, dir, "log.test")
	leaf := loadLeaf(t, certFile)
	keyDER, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString(keyDER)
	id := base64.StdEncoding.EncodeToString(make([]byte, 32))
	doc := `{"operators":[{"logs":[{"log_id":"` + id + `","key":"` + key + `"}],
		"tiled_logs":[{"log_id":"` + base64.StdEncoding.EncodeToString(append(make([]byte, 31), 1)) + `","key":"` + key + `"}]}]}`
	ll, err := ParseLogList([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if ll.Logs != 2 {
		t.Fatalf("%d logs", ll.Logs)
	}
	var want [32]byte
	if _, ok := ll.Key(want); !ok {
		t.Error("the log key is not in the list")
	}
	var missing [32]byte
	missing[0] = 0xff
	if _, ok := ll.Key(missing); ok {
		t.Error("a log nobody listed has a key")
	}
	// A nil list answers for no log rather than panicking.
	var nilList *LogList
	if _, ok := nilList.Key(want); ok {
		t.Error("a nil log list had a key")
	}

	bad := map[string]string{
		"empty":                        "",
		"not json":                     "<html>",
		"a json array":                 "[1,2]",
		"no operators":                 `{}`,
		"no logs":                      `{"operators":[{"logs":[]}]}`,
		"a log id that is not base64":  `{"operators":[{"logs":[{"log_id":"!!!!","key":"` + key + `"}]}]}`,
		"a log id of the wrong length": `{"operators":[{"logs":[{"log_id":"` + base64.StdEncoding.EncodeToString(make([]byte, 16)) + `","key":"` + key + `"}]}]}`,
		"a key that is not base64":     `{"operators":[{"logs":[{"log_id":"` + id + `","key":"!!!!"}]}]}`,
		"a key that is not a key":      `{"operators":[{"logs":[{"log_id":"` + id + `","key":"` + base64.StdEncoding.EncodeToString([]byte("hello")) + `"}]}]}`,
	}
	for name, body := range bad {
		if ll, err := ParseLogList([]byte(body)); err == nil {
			t.Errorf("%s was accepted, giving %d logs", name, ll.Logs)
		}
	}
	// LoadLogList reads the same document from a file, and reports a
	// file it cannot read.
	path := filepath.Join(dir, "logs.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	if ll, err := LoadLogList(path); err != nil || ll.Logs != 2 {
		t.Errorf("LoadLogList: %v", err)
	}
	if _, err := LoadLogList(filepath.Join(dir, "none.json")); err == nil {
		t.Error("a missing log list was loaded")
	}
}

// TestServerCertificateSelection covers the certificate a listener
// answers a handshake with, including the two places an attacker
// chooses the input: the server name and the ALPN list.
func TestServerCertificateSelection(t *testing.T) {
	dir := t.TempDir()
	c1, k1 := testutil.WriteCert(t, dir, "a.test")
	c2, k2 := testutil.WriteCert(t, dir, "b.test")
	cfg := &config.TLS{Certificates: []config.Certificate{{CertFile: c1, KeyFile: k1}, {CertFile: c2, KeyFile: k2}}}
	tc, r, err := Server(cfg, []config.Protocol{config.ProtocolH1})
	if err != nil {
		t.Fatal(err)
	}
	hello := func(name string, protos ...string) *tls.ClientHelloInfo {
		return &tls.ClientHelloInfo{ServerName: name, SupportedProtos: protos,
			SupportedVersions: []uint16{tls.VersionTLS13}, CipherSuites: []uint16{tls.TLS_AES_128_GCM_SHA256},
			SupportedCurves:  []tls.CurveID{tls.X25519, tls.CurveP256},
			SignatureSchemes: []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256}}
	}
	// A name nobody has a certificate for still gets an answer (the
	// first certificate), because refusing here leaks which names the
	// proxy fronts.
	for _, name := range []string{"", "nobody.test", "A.TEST", "*.test", "a.test.", strings.Repeat("a", 300) + ".test"} {
		cert, err := tc.GetCertificate(hello(name))
		if err != nil || cert == nil {
			t.Errorf("the name %q gave %v", name, err)
		}
	}
	// The earliest expiry of the loaded certificates is reported.
	if r.NotAfter().IsZero() {
		t.Error("no expiry was reported")
	}
	// A tls-alpn-01 handshake is answered from the challenge hook, and
	// only from it: without a pending challenge the handshake fails
	// rather than serving the real certificate to the validator.
	var asked string
	r.Challenge = func(name string) (*tls.Certificate, bool) {
		asked = name
		if name == "a.test" {
			return &tls.Certificate{}, true
		}
		return nil, false
	}
	if _, err := tc.GetCertificate(hello("a.test", ACMEALPN)); err != nil {
		t.Errorf("a pending challenge: %v", err)
	}
	if asked != "a.test" {
		t.Errorf("the hook was asked for %q", asked)
	}
	if _, err := tc.GetCertificate(hello("other.test", ACMEALPN)); err == nil {
		t.Error("a handshake for a name with no challenge was answered")
	}
	// An ALPN list that merely contains the challenge protocol among
	// others still goes to the hook: that is what a validator sends.
	if _, err := tc.GetCertificate(hello("a.test", "h2", ACMEALPN)); err != nil {
		t.Errorf("a challenge among other protocols: %v", err)
	}
	r.Challenge = nil

	// Managed certificates are served alongside the file ones.
	managedCert, err := tls.LoadX509KeyPair(c2, k2)
	if err != nil {
		t.Fatal(err)
	}
	r.Managed = func() []tls.Certificate { return []tls.Certificate{managedCert} }
	if _, err := tc.GetCertificate(hello("b.test")); err != nil {
		t.Errorf("with managed certificates: %v", err)
	}
	r.Managed = func() []tls.Certificate { return nil }
	if _, err := tc.GetCertificate(hello("b.test")); err != nil {
		t.Errorf("with an empty managed list: %v", err)
	}

	// A listener with no certificates at all is a handshake failure, not
	// a panic; and its expiry is the zero time.
	empty := &Reloadable{}
	if err := empty.Load(); err != nil {
		t.Fatal(err)
	}
	if _, err := empty.getCertificate(hello("a.test")); err == nil {
		t.Error("a listener with no certificates answered a handshake")
	}
	if !empty.NotAfter().IsZero() {
		t.Error("a listener with no certificates reported an expiry")
	}
	// The fingerprint hook never changes the configuration, and is safe
	// for a hello with no connection behind it.
	cfgOut, err := r.recordFingerprint(hello("a.test"))
	if err != nil || cfgOut != nil {
		t.Errorf("recordFingerprint: %v %v", cfgOut, err)
	}
}

// TestServerOptionRefusals covers the listener options, where a typo
// must not silently produce a weaker listener.
func TestServerOptionRefusals(t *testing.T) {
	dir := t.TempDir()
	c1, k1 := testutil.WriteCert(t, dir, "a.test")
	certs := []config.Certificate{{CertFile: c1, KeyFile: k1}}
	notPEM := filepath.Join(dir, "not.pem")
	if err := os.WriteFile(notPEM, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := map[string]*config.TLS{
		"a certificate that is not there":  {Certificates: []config.Certificate{{CertFile: filepath.Join(dir, "none.crt"), KeyFile: k1}}},
		"a key that is not there":          {Certificates: []config.Certificate{{CertFile: c1, KeyFile: filepath.Join(dir, "none.key")}}},
		"a certificate that is not one":    {Certificates: []config.Certificate{{CertFile: notPEM, KeyFile: notPEM}}},
		"an insecure cipher suite":         {Certificates: certs, CipherSuites: []string{"TLS_RSA_WITH_RC4_128_SHA"}},
		"a cipher suite nobody defines":    {Certificates: certs, CipherSuites: []string{"TLS_MADE_UP"}},
		"a client ca that is not there":    {Certificates: certs, ClientAuth: "require", ClientCAFile: filepath.Join(dir, "none.pem")},
		"a client ca with no certificates": {Certificates: certs, ClientAuth: "require", ClientCAFile: notPEM},
		"a ct log list that is not there":  {Certificates: certs, CT: &config.CT{LogListFile: filepath.Join(dir, "none.json")}},
		"a ct log list that is not one":    {Certificates: certs, CT: &config.CT{LogListFile: notPEM}},
	}
	for name, cfg := range bad {
		if _, _, err := Server(cfg, nil); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	// A listener with no certificates is valid: the managed ones may
	// arrive later.
	if _, _, err := Server(&config.TLS{}, nil); err != nil {
		t.Errorf("a listener awaiting managed certificates: %v", err)
	}
}

// TestOCSPFetchFailures drives one fetch at a time against responders
// that are broken or hostile. A staple is served to every client of the
// listener, so a response that is not the right one must never be kept.
func TestOCSPFetchFailures(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	good := newResponder(t, ca)
	on := true
	newStap := func(certs []tls.Certificate) *stapler {
		return newStapler(config.OCSPStapling{Enabled: &on, Timeout: config.Duration(2 * time.Second), Refresh: config.Duration(time.Hour)},
			func() []tls.Certificate { return certs }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	}
	load := func(certPath, keyPath string) tls.Certificate {
		t.Helper()
		c, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			t.Fatal(err)
		}
		if c.Leaf == nil {
			c.Leaf, _ = x509.ParseCertificate(c.Certificate[0])
		}
		return c
	}

	// A certificate that names no responder.
	plainCert, plainKey := testutil.WriteCert(t, dir, "plain.test")
	c := load(plainCert, plainKey)
	st := newStap(nil).fetch(t.Context(), &c)
	if st.status != "none" || st.err == "" {
		t.Errorf("a certificate with no responder: %+v", st)
	}

	// A certificate whose chain file has no issuer.
	noIssuer, noIssuerKey, _ := issueWithOCSP(t, ca, dir, "noissuer.test", good.srv.URL)
	c = load(noIssuer, noIssuerKey)
	full := c.Certificate
	c.Certificate = c.Certificate[:1]
	st = newStap(nil).fetch(t.Context(), &c)
	if st.err == "" || !strings.Contains(st.err, "issuer") {
		t.Errorf("a chain without its issuer: %+v", st)
	}
	c.Certificate = full

	// Responders that answer something else.
	for name, h := range map[string]http.HandlerFunc{
		"an http error":        func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) },
		"an empty body":        func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) },
		"html":                 func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "<html>hi</html>") },
		"a truncated response": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte{0x30, 0x03, 0x0a}) },
		"a megabyte of rubbish": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(make([]byte, 1<<20))
		},
		"a redirect": func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, good.srv.URL, http.StatusFound) },
	} {
		srv := httptest.NewServer(h)
		certPath, keyPath, _ := issueWithOCSP(t, ca, dir, "www.test", srv.URL)
		c := load(certPath, keyPath)
		st := newStap(nil).fetch(t.Context(), &c)
		srv.Close()
		if st.err == "" {
			t.Errorf("%s was accepted as a staple: %+v", name, st)
		}
		if len(st.der) != 0 {
			t.Errorf("%s produced %d bytes to staple", name, len(st.der))
		}
		if st.status == "good" {
			t.Errorf("%s was reported as good", name)
		}
	}

	// A responder for another certificate: the answer parses but is not
	// about this certificate, so it must not be stapled.
	otherDir := t.TempDir()
	otherCA := testutil.WriteCA(t, otherDir)
	otherResponder := newResponder(t, otherCA)
	certPath, keyPath, _ := issueWithOCSP(t, ca, dir, "www.test", otherResponder.srv.URL)
	c = load(certPath, keyPath)
	st = newStap(nil).fetch(t.Context(), &c)
	if st.err == "" || len(st.der) != 0 {
		t.Errorf("a response signed by another authority: %+v", st)
	}

	// A responder that is not there at all.
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	certPath, keyPath, _ = issueWithOCSP(t, ca, dir, "www.test", deadURL)
	dead.Close()
	c = load(certPath, keyPath)
	st = newStap(nil).fetch(t.Context(), &c)
	if st.err == "" {
		t.Errorf("a responder that is not there: %+v", st)
	}

	// current() serves nothing for a staple that has expired or was
	// never fetched, and leafKey refuses a certificate with no bytes.
	s := newStap(nil)
	if s.current(&c) != nil {
		t.Error("a certificate with no staple was given one")
	}
	if _, ok := leafKey(nil); ok {
		t.Error("a nil certificate has a key")
	}
	if _, ok := leafKey(&tls.Certificate{}); ok {
		t.Error("an empty certificate has a key")
	}
	key, ok := leafKey(&c)
	if !ok {
		t.Fatal("a real certificate has no key")
	}
	s.mu.Lock()
	s.staples[key] = &staple{der: []byte("x"), nextUpdate: time.Now().Add(-time.Minute)}
	s.mu.Unlock()
	if s.current(&c) != nil {
		t.Error("an expired staple was served")
	}
	s.mu.Lock()
	s.staples[key] = &staple{der: []byte("x"), nextUpdate: time.Now().Add(time.Hour)}
	s.mu.Unlock()
	if s.current(&c) == nil {
		t.Error("a valid staple was not served")
	}

	// due(): missing, past half its validity, older than the refresh
	// interval, and fresh.
	now := time.Now()
	s = newStap(nil)
	cases := map[string]struct {
		st   *staple
		want bool
	}{
		"expired":            {&staple{thisUpdate: now.Add(-3 * time.Hour), nextUpdate: now.Add(-time.Hour), fetched: now}, true},
		"past half":          {&staple{thisUpdate: now.Add(-2 * time.Hour), nextUpdate: now.Add(time.Hour), fetched: now}, true},
		"fresh":              {&staple{thisUpdate: now.Add(-time.Minute), nextUpdate: now.Add(5 * time.Hour), fetched: now}, false},
		"older than refresh": {&staple{thisUpdate: now.Add(-time.Minute), nextUpdate: now.Add(5 * time.Hour), fetched: now.Add(-2 * time.Hour)}, true},
	}
	for name, tc := range cases {
		if got := s.due(tc.st, now); got != tc.want {
			t.Errorf("due(%s) = %v", name, got)
		}
	}
	// A stapler that was never started closes without waiting.
	s.close()
	s.close()
}
