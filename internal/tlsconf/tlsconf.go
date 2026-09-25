// Package tlsconf builds crypto/tls configurations from xproxy configuration
// with hardened defaults: TLS 1.2 minimum, no insecure suites, no
// renegotiation, session tickets rotated by the runtime, X25519 preferred,
// and certificate reload without restart.
package tlsconf

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// Reloadable holds certificates that can be swapped atomically. Managed
// certificates (ACME) come from a source consulted on every lookup, and a
// challenge hook can answer tls-alpn-01 validations.
type Reloadable struct {
	certs atomic.Pointer[[]tls.Certificate]
	cfgs  []config.Certificate
	// Managed returns additional certificates (for example from ACME).
	Managed func() []tls.Certificate
	// Challenge returns a validation certificate for a server name when a
	// tls-alpn-01 challenge is pending.
	Challenge func(serverName string) (*tls.Certificate, bool)
	// Fingerprints, when set, records the JA3 and JA4 fingerprint of every
	// ClientHello by remote address (see Compute).
	Fingerprints *FingerprintTable
	// QUIC marks the config as serving HTTP/3 (JA4 prefix "q").
	QUIC bool
	// Refuse, when set, is asked about every ClientHello before the
	// handshake completes. A non-empty reason aborts it: the client
	// gets a failed negotiation and nothing to fingerprint, and the
	// proxy spends no key exchange on a client it was going to refuse
	// anyway.
	Refuse func(remote net.Addr, fp Fingerprint) string

	// ech holds the Encrypted Client Hello keys, swapped by a reload;
	// echCfg is what to re-read them from. The counters sit here rather
	// than in the key set so a key rotation does not reset them.
	ech         atomic.Pointer[echKeys]
	echCfg      *config.ECH
	echAccepted atomic.Uint64
	echRejected atomic.Uint64
	echRefused  atomic.Uint64

	// ocsp, ct and expiry come from the listener's tls section.
	ocsp    *config.OCSPStapling
	ct      *config.CT
	expiry  *config.CertExpiry
	logs    *LogList
	stapler *stapler
	ctMu    sync.Mutex
	ctState map[[32]byte]CTStatus
}

// CertInfo is the management view of one served certificate.
type CertInfo struct {
	Names     []string   `json:"names"`
	Subject   string     `json:"subject"`
	Issuer    string     `json:"issuer"`
	NotBefore time.Time  `json:"not_before"`
	NotAfter  time.Time  `json:"not_after"`
	Managed   bool       `json:"managed"`
	OCSP      OCSPStatus `json:"ocsp"`
	CT        CTStatus   `json:"ct"`
}

// StartStapling begins fetching OCSP responses when the listener enables
// it. Safe to call once per Reloadable.
func (r *Reloadable) StartStapling(log *slog.Logger) {
	if !r.ocsp.IsEnabled() || r.stapler != nil {
		return
	}
	r.stapler = newStapler(*r.ocsp, r.allCertificates, log.With("component", "ocsp"))
	r.stapler.start()
}

// Close stops background work.
func (r *Reloadable) Close() {
	if r.stapler != nil {
		r.stapler.close()
	}
}

// allCertificates lists file and managed certificates.
func (r *Reloadable) allCertificates() []tls.Certificate {
	var all []tls.Certificate
	if certs := r.certs.Load(); certs != nil {
		all = append(all, *certs...)
	}
	if r.Managed != nil {
		all = append(all, r.Managed()...)
	}
	return all
}

// withStaple returns c with the current OCSP response attached, or c.
func (r *Reloadable) withStaple(c *tls.Certificate) *tls.Certificate {
	if r.stapler == nil {
		return c
	}
	der := r.stapler.current(c)
	if der == nil {
		return c
	}
	cp := *c
	cp.OCSPStaple = der
	return &cp
}

// Certificates describes every served certificate with its staple and
// CT state.
func (r *Reloadable) Certificates() []CertInfo {
	var out []CertInfo
	add := func(c tls.Certificate, managed bool) {
		leaf := c.Leaf
		if leaf == nil && len(c.Certificate) > 0 {
			leaf, _ = x509.ParseCertificate(c.Certificate[0])
		}
		if leaf == nil {
			return
		}
		info := CertInfo{Names: leaf.DNSNames, Subject: leaf.Subject.CommonName, Issuer: leaf.Issuer.CommonName,
			NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, Managed: managed, OCSP: OCSPStatus{Status: "disabled"}}
		if r.stapler != nil {
			info.OCSP = r.stapler.status(&c)
		}
		key := sha256.Sum256(c.Certificate[0])
		r.ctMu.Lock()
		st, ok := r.ctState[key]
		r.ctMu.Unlock()
		if !ok {
			st = ctCheck(leaf, issuerOf(&c), r.logs, 0)
		}
		info.CT = st
		out = append(out, info)
	}
	if certs := r.certs.Load(); certs != nil {
		for _, c := range *certs {
			add(c, false)
		}
	}
	if r.Managed != nil {
		for _, c := range r.Managed() {
			add(c, true)
		}
	}
	return out
}

// issuerOf returns the second certificate of the chain, if any.
func issuerOf(c *tls.Certificate) *x509.Certificate {
	if len(c.Certificate) < 2 {
		return nil
	}
	issuer, err := x509.ParseCertificate(c.Certificate[1])
	if err != nil {
		return nil
	}
	return issuer
}

// ErrRefused aborts a handshake the Refuse hook turned down. The text
// reaches no client: a TLS handshake that fails carries an alert, not a
// message, which is the point of refusing here.
var ErrRefused = errors.New("handshake refused")

// ErrECHRequired aborts a handshake that did not use Encrypted Client
// Hello on a listener that requires it.
var ErrECHRequired = errors.New("encrypted client hello is required on this listener")

// recordFingerprint is installed as GetConfigForClient. It observes the
// hello, and asks Refuse whether this client gets a handshake at all.
func (r *Reloadable) recordFingerprint(h *tls.ClientHelloInfo) (*tls.Config, error) {
	if h.Conn == nil || h.Conn.RemoteAddr() == nil {
		return nil, nil //nolint:nilnil // nil config keeps the parent config
	}
	fp := Compute(h, r.QUIC)
	if r.Fingerprints != nil {
		r.Fingerprints.Put(h.Conn.RemoteAddr().String(), fp)
	}
	if r.Refuse != nil {
		if reason := r.Refuse(h.Conn.RemoteAddr(), fp); reason != "" {
			return nil, fmt.Errorf("%w: %s", ErrRefused, reason)
		}
	}
	return nil, nil //nolint:nilnil // nil config keeps the parent config
}

// ACMEALPN is the ALPN protocol of tls-alpn-01 (RFC 8737).
const ACMEALPN = "acme-tls/1"

// Load parses all configured certificate pairs. An empty list is valid
// when managed certificates are configured.
func (r *Reloadable) Load() error {
	certs := make([]tls.Certificate, 0, len(r.cfgs))
	for _, c := range r.cfgs {
		cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
		if err != nil {
			return fmt.Errorf("load certificate %s: %w", c.CertFile, err)
		}
		if cert.Leaf == nil && len(cert.Certificate) > 0 {
			if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
				cert.Leaf = leaf
			}
		}
		certs = append(certs, cert)
	}
	// Expiry. A certificate already past its validity is refused here
	// rather than served, when the listener asked for that: refusing at
	// load is the one place where refusing is strictly better than
	// serving, because on a reload the certificate already in use keeps
	// working and the operator gets a message naming the file. A
	// certificate that expires later, while the proxy is running, is
	// reported by Expiring rather than unloaded -- a listener that stops
	// answering is worse than one answering with a certificate the client
	// will reject for itself.
	if err := r.checkExpiry(certs, time.Now()); err != nil {
		return err
	}
	// Certificate Transparency: every file certificate is checked
	// against the policy; a failure is fatal only with enforce.
	state := map[[32]byte]CTStatus{}
	required := 0
	if r.ct != nil {
		required = r.ct.Require
	}
	for i := range certs {
		c := &certs[i]
		if c.Leaf == nil {
			continue
		}
		st := ctCheck(c.Leaf, issuerOf(c), r.logs, required)
		state[sha256.Sum256(c.Certificate[0])] = st
		if !st.OK && r.ct != nil && r.ct.Enforce {
			return fmt.Errorf("certificate %s: certificate transparency: %s", r.cfgs[i].CertFile, st.Error)
		}
	}
	r.ctMu.Lock()
	r.ctState = state
	r.ctMu.Unlock()
	r.certs.Store(&certs)
	if err := r.ReloadECH(); err != nil {
		return err
	}
	if r.stapler != nil {
		r.stapler.wake()
	}
	return nil
}

// CTWarnings lists the file certificates that fall short of the CT
// policy without enforce (empty when all pass or no policy is set).
func (r *Reloadable) CTWarnings() []string {
	r.ctMu.Lock()
	defer r.ctMu.Unlock()
	var out []string
	for _, st := range r.ctState {
		if !st.OK {
			out = append(out, st.Error)
		}
	}
	return out
}

// NotAfter returns the earliest expiry among the loaded file certificates,
// or the zero time when none is loaded. Managed certificates report their
// own expiry through the ACME status.
func (r *Reloadable) NotAfter() time.Time {
	var earliest time.Time
	if certs := r.certs.Load(); certs != nil {
		for _, c := range *certs {
			if c.Leaf == nil {
				continue
			}
			if earliest.IsZero() || c.Leaf.NotAfter.Before(earliest) {
				earliest = c.Leaf.NotAfter
			}
		}
	}
	return earliest
}

// checkExpiry applies the expiry policy to a set about to be installed.
func (r *Reloadable) checkExpiry(certs []tls.Certificate, now time.Time) error {
	if r.expiry == nil || !r.expiry.RefuseExpired {
		return nil
	}
	for i := range certs {
		leaf := certs[i].Leaf
		if leaf == nil {
			continue
		}
		if now.After(leaf.NotAfter) {
			name := leaf.Subject.CommonName
			if i < len(r.cfgs) {
				name = r.cfgs[i].CertFile
			}
			return fmt.Errorf("certificate %s expired on %s", name, leaf.NotAfter.Format(time.RFC3339))
		}
	}
	return nil
}

// Expiring lists the served certificates that have expired or are inside
// the warning window, worst first. It is what the daemon reports and what
// the management view shows; it is not a refusal, because a certificate
// expiring under a running proxy is news rather than a reason to stop
// answering.
func (r *Reloadable) Expiring(now time.Time) []string {
	if r.expiry == nil || r.expiry.Warn == 0 {
		return nil
	}
	var out []string
	type due struct {
		left time.Duration
		text string
	}
	var found []due
	for _, c := range r.allCertificates() {
		leaf := c.Leaf
		if leaf == nil && len(c.Certificate) > 0 {
			leaf, _ = x509.ParseCertificate(c.Certificate[0])
		}
		if leaf == nil {
			continue
		}
		left := leaf.NotAfter.Sub(now)
		if left > r.expiry.Warn.D() {
			continue
		}
		name := leaf.Subject.CommonName
		if name == "" && len(leaf.DNSNames) > 0 {
			name = leaf.DNSNames[0]
		}
		if now.After(leaf.NotAfter) {
			found = append(found, due{left, fmt.Sprintf("certificate %s expired on %s", name, leaf.NotAfter.Format(time.RFC3339))})
			continue
		}
		found = append(found, due{left, fmt.Sprintf("certificate %s expires on %s, in %s", name, leaf.NotAfter.Format(time.RFC3339), left.Round(time.Hour))})
	}
	sort.Slice(found, func(i, j int) bool { return found[i].left < found[j].left })
	for _, f := range found {
		out = append(out, f.text)
	}
	return out
}

// getCertificate selects a certificate by SNI, falling back to the first
// file certificate. A tls-alpn-01 handshake is answered from the
// challenge hook before anything else.
func (r *Reloadable) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if r.Challenge != nil {
		for _, p := range hello.SupportedProtos {
			if p == ACMEALPN {
				if c, ok := r.Challenge(hello.ServerName); ok {
					return c, nil
				}
				return nil, errors.New("no pending tls-alpn-01 challenge for " + hello.ServerName)
			}
		}
	}
	var all []tls.Certificate
	if certs := r.certs.Load(); certs != nil {
		all = *certs
	}
	if r.Managed != nil {
		if m := r.Managed(); len(m) > 0 {
			all = append(append([]tls.Certificate{}, all...), m...)
		}
	}
	if len(all) == 0 {
		return nil, errors.New("no certificates loaded")
	}
	if len(all) == 1 {
		return r.withStaple(&all[0]), nil
	}
	for i := range all {
		if err := hello.SupportsCertificate(&all[i]); err == nil {
			return r.withStaple(&all[i]), nil
		}
	}
	return r.withStaple(&all[0]), nil
}

// Server builds a server tls.Config for a listener. The returned Reloadable
// can be used to hot reload certificates.
func Server(cfg *config.TLS, protocols []config.Protocol) (*tls.Config, *Reloadable, error) {
	r := &Reloadable{cfgs: cfg.Certificates, ocsp: cfg.OCSPStapling, ct: cfg.CT, echCfg: cfg.ECH, expiry: cfg.Expiry}
	if cfg.CT != nil && cfg.CT.LogListFile != "" {
		ll, err := LoadLogList(cfg.CT.LogListFile)
		if err != nil {
			return nil, nil, fmt.Errorf("ct log_list_file: %w", err)
		}
		r.logs = ll
	}
	if err := r.Load(); err != nil {
		return nil, nil, err
	}
	groups, err := config.CurveIDs(cfg.KeyExchange)
	if err != nil {
		return nil, nil, err
	}
	// The keys were read by Load above; this is only the question of
	// whether the listener has any.
	keys := r.ech.Load()
	tc := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		GetCertificate:           r.getCertificate,
		GetConfigForClient:       r.recordFingerprint,
		CurvePreferences:         groups,
		Renegotiation:            tls.RenegotiateNever,
		SessionTicketsDisabled:   false,
		PreferServerCipherSuites: true,
	}
	if cfg.MinVersion == "1.3" {
		tc.MinVersion = tls.VersionTLS13
	}
	if len(cfg.CipherSuites) > 0 {
		ids, err := suiteIDs(cfg.CipherSuites)
		if err != nil {
			return nil, nil, err
		}
		tc.CipherSuites = ids
	} else {
		tc.CipherSuites = DefaultCipherSuites()
	}
	// ALPN follows server preference order: offer h2 before http/1.1.
	for _, p := range protocols {
		if p == config.ProtocolH2 {
			tc.NextProtos = append(tc.NextProtos, "h2")
		}
	}
	for _, p := range protocols {
		if p == config.ProtocolH1 {
			tc.NextProtos = append(tc.NextProtos, "http/1.1")
		}
	}
	if len(cfg.ACME) > 0 {
		tc.NextProtos = append(tc.NextProtos, ACMEALPN)
	}
	if keys != nil {
		// ECH needs TLS 1.3; a 1.2 handshake has no encrypted hello to
		// carry it, so the listener's floor rises rather than the
		// feature quietly not applying.
		tc.MinVersion = tls.VersionTLS13
		tc.GetEncryptedClientHelloKeys = r.ECHKeys
		tc.VerifyConnection = r.verifyECH
	}
	switch cfg.ClientAuth {
	case "request", "require":
		pool, err := loadPool(cfg.ClientCAFile)
		if err != nil {
			return nil, nil, err
		}
		tc.ClientCAs = pool
		if cfg.ClientAuth == "require" {
			tc.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			tc.ClientAuth = tls.VerifyClientCertIfGiven
		}
	}
	return tc, r, nil
}

// DefaultCipherSuites is the TLS 1.2 allow list: AEAD suites with forward
// secrecy only.
func DefaultCipherSuites() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}
}

func suiteIDs(names []string) ([]uint16, error) {
	byName := map[string]uint16{}
	for _, cs := range tls.CipherSuites() {
		byName[cs.Name] = cs.ID
	}
	out := make([]uint16, 0, len(names))
	for _, n := range names {
		id, ok := byName[n]
		if !ok {
			return nil, fmt.Errorf("unknown or insecure cipher suite %q", n)
		}
		out = append(out, id)
	}
	return out, nil
}

func loadPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path) //nolint:gosec // CA path from validated configuration
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("CA file %s contains no certificates", path)
	}
	return pool, nil
}

// ClientReloadable holds an upstream client certificate that can be
// re-read without rebuilding the transport.
type ClientReloadable struct {
	cert     atomic.Pointer[tls.Certificate]
	certFile string
	keyFile  string
}

// Load re-reads the client certificate pair.
func (r *ClientReloadable) Load() error {
	if r == nil || r.certFile == "" {
		return nil
	}
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return fmt.Errorf("load upstream client certificate %s: %w", r.certFile, err)
	}
	r.cert.Store(&cert)
	return nil
}

// Client builds the tls.Config used towards an upstream. The returned
// ClientReloadable is nil when no client certificate is configured.
func Client(cfg *config.UpstreamTLS) (*tls.Config, *ClientReloadable, error) {
	tc := &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: config.DefaultKeyExchange(),
		Renegotiation:    tls.RenegotiateNever,
	}
	if cfg == nil {
		return tc, nil, nil
	}
	groups, err := config.CurveIDs(cfg.KeyExchange)
	if err != nil {
		return nil, nil, err
	}
	tc.CurvePreferences = groups
	if cfg.MinVersion == "1.3" {
		tc.MinVersion = tls.VersionTLS13
	}
	tc.ServerName = cfg.ServerName
	if cfg.CAFile != "" {
		pool, err := loadPool(cfg.CAFile)
		if err != nil {
			return nil, nil, err
		}
		tc.RootCAs = pool
	}
	var rl *ClientReloadable
	if cfg.ClientCertFile != "" {
		rl = &ClientReloadable{certFile: cfg.ClientCertFile, keyFile: cfg.ClientKeyFile}
		if err := rl.Load(); err != nil {
			return nil, nil, err
		}
		tc.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if c := rl.cert.Load(); c != nil {
				return c, nil
			}
			return &tls.Certificate{}, nil
		}
	}
	if len(cfg.SPKIPins) > 0 {
		pins := make([][32]byte, 0, len(cfg.SPKIPins))
		for _, p := range cfg.SPKIPins {
			raw, err := base64.StdEncoding.DecodeString(p)
			if err != nil || len(raw) != 32 {
				return nil, nil, fmt.Errorf("bad spki pin %q", p)
			}
			var d [32]byte
			copy(d[:], raw)
			pins = append(pins, d)
		}
		tc.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no peer certificate")
			}
			got := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
			for _, p := range pins {
				if p == got {
					return nil
				}
			}
			return fmt.Errorf("upstream public key does not match any spki_pin (got %s)", base64.StdEncoding.EncodeToString(got[:]))
		}
	}
	if cfg.InsecureSkipVerify && cfg.AllowInsecure {
		tc.InsecureSkipVerify = true //nolint:gosec // explicitly double opted in by config
	}
	return tc, rl, nil
}

// SPKIPin returns the pin (base64 SHA-256 of the SubjectPublicKeyInfo) of
// a certificate, for operators generating configuration.
func SPKIPin(cert *x509.Certificate) string {
	d := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(d[:])
}

// VersionName returns a short TLS version name for logging.
func VersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "1.3"
	case tls.VersionTLS12:
		return "1.2"
	default:
		return strings.TrimPrefix(tls.VersionName(v), "TLS ")
	}
}
