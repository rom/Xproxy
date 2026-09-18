package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/acme/jose"
	"github.com/rom/xproxy/internal/config"
)

// HTTP01Path and ALPNProto are re-exported for the proxy.
const (
	HTTP01Path = jose.HTTP01Path
	ALPNProto  = jose.ALPNProto
)

// idPeAcmeIdentifier is the tls-alpn-01 certificate extension.
var idPeAcmeIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}

// Manager obtains and renews one certificate per host group.
type Manager struct {
	cfg    config.ACME
	groups [][]string
	log    *slog.Logger
	client *Client

	mu       sync.Mutex
	certs    map[string]*managed // keyed by group name (first host)
	http01   map[string]string   // token -> key authorization
	alpn     map[string]*tls.Certificate
	current  atomic.Pointer[[]tls.Certificate]
	onChange func()

	stop chan struct{}
	wg   sync.WaitGroup
	now  func() time.Time
}

type managed struct {
	name      string
	hosts     []string
	cert      *tls.Certificate
	notAfter  time.Time
	lastError string
	lastTry   time.Time
	inflight  chan struct{} // non-nil while an order is running
	lastErr   error         // outcome of the last finished order
	issued    uint64
}

// CertStatus is the management view of one managed certificate.
type CertStatus struct {
	Name      string    `json:"name"`
	Hosts     []string  `json:"hosts"`
	Present   bool      `json:"present"`
	NotAfter  time.Time `json:"not_after,omitempty"`
	Issuer    string    `json:"issuer,omitempty"`
	Renewing  bool      `json:"renewing"`
	LastError string    `json:"last_error,omitempty"`
	Issued    uint64    `json:"issued"`
}

// New prepares a manager: loads or creates the account key and any
// certificates already on disk. Nothing is contacted until Start.
func New(cfg config.ACME, groups [][]string, log *slog.Logger) (*Manager, error) {
	m := &Manager{cfg: cfg, groups: groups, log: log.With("component", "acme"), certs: map[string]*managed{}, http01: map[string]string{}, alpn: map[string]*tls.Certificate{}, stop: make(chan struct{}), now: time.Now}
	if err := os.MkdirAll(filepath.Join(cfg.StateDir, "certs"), 0o700); err != nil {
		return nil, fmt.Errorf("acme state dir: %w", err)
	}
	key, err := loadOrCreateAccountKey(filepath.Join(cfg.StateDir, "account.key"))
	if err != nil {
		return nil, err
	}
	c, err := NewClient(cfg.Directory, cfg.CAFile, key)
	if err != nil {
		return nil, err
	}
	if kid, err := os.ReadFile(filepath.Join(cfg.StateDir, "account.url")); err == nil { //nolint:gosec // state directory
		c.SetKID(strings.TrimSpace(string(kid)))
	}
	m.client = c
	for _, g := range groups {
		mg := &managed{name: g[0], hosts: g}
		m.certs[mg.name] = mg
		if cert, err := m.loadCert(mg); err == nil {
			mg.cert, mg.notAfter = cert, cert.Leaf.NotAfter
		}
	}
	m.publish()
	return m, nil
}

// OnChange registers a callback run after certificates change.
func (m *Manager) OnChange(fn func()) { m.onChange = fn }

func loadOrCreateAccountKey(path string) (*ecdsa.PrivateKey, error) {
	if data, err := os.ReadFile(path); err == nil { //nolint:gosec // state directory
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, errors.New("acme account key is not PEM")
		}
		return x509.ParseECPrivateKey(block.Bytes)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, _ := x509.MarshalECPrivateKey(key)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, fmt.Errorf("acme account key: %w", err)
	}
	return key, nil
}

func (m *Manager) certPaths(mg *managed) (string, string) {
	base := filepath.Join(m.cfg.StateDir, "certs", mg.name)
	return base + ".pem", base + "-key.pem"
}

func (m *Manager) loadCert(mg *managed) (*tls.Certificate, error) {
	cp, kp := m.certPaths(mg)
	cert, err := tls.LoadX509KeyPair(cp, kp)
	if err != nil {
		return nil, err
	}
	if cert.Leaf == nil {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, err
		}
		cert.Leaf = leaf
	}
	return &cert, nil
}

// publish refreshes the certificate snapshot served to listeners.
func (m *Manager) publish() {
	names := make([]string, 0, len(m.certs))
	for n := range m.certs {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []tls.Certificate
	for _, n := range names {
		if c := m.certs[n].cert; c != nil {
			out = append(out, *c)
		}
	}
	m.current.Store(&out)
	if m.onChange != nil {
		m.onChange()
	}
}

// Certificates returns the current managed certificates.
func (m *Manager) Certificates() []tls.Certificate {
	if p := m.current.Load(); p != nil {
		return *p
	}
	return nil
}

// HTTP01 answers an http-01 challenge request for token.
func (m *Manager) HTTP01(token string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ka, ok := m.http01[token]
	return ka, ok
}

// TLSALPN01 returns the challenge certificate for a server name during a
// tls-alpn-01 validation.
func (m *Manager) TLSALPN01(serverName string) (*tls.Certificate, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.alpn[strings.ToLower(serverName)]
	return c, ok
}

// Start begins issuance for missing certificates and the renewal loop.
func (m *Manager) Start() {
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.check()
		t := time.NewTicker(m.cfg.CheckInterval.D())
		defer t.Stop()
		for {
			select {
			case <-m.stop:
				return
			case <-t.C:
				m.check()
			}
		}
	}()
}

// Stop ends the renewal loop.
func (m *Manager) Stop() {
	select {
	case <-m.stop:
	default:
		close(m.stop)
	}
	m.wg.Wait()
}

// Renew forces renewal of every group (management API).
func (m *Manager) Renew(ctx context.Context) error {
	var first error
	for _, name := range m.names() {
		if err := m.obtain(ctx, name); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (m *Manager) names() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	names := make([]string, 0, len(m.certs))
	for n := range m.certs {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// check issues or renews what is due, with a one hour back-off after a
// failure.
func (m *Manager) check() {
	now := m.now()
	for _, name := range m.names() {
		m.mu.Lock()
		mg := m.certs[name]
		due := mg.cert == nil || mg.notAfter.Sub(now) < m.cfg.RenewBefore.D()
		backoff := mg.lastError != "" && now.Sub(mg.lastTry) < time.Hour
		m.mu.Unlock()
		if !due || backoff {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		if err := m.obtain(ctx, name); err != nil {
			m.log.Error("certificate issuance failed", "group", name, "err", err.Error())
		}
		cancel()
	}
}

// obtain runs one order for a group and installs the result. A caller that
// arrives while an order for the same group is already running joins it and
// returns that order's outcome instead of starting a second one.
func (m *Manager) obtain(ctx context.Context, name string) (err error) {
	m.mu.Lock()
	mg := m.certs[name]
	if ch := mg.inflight; ch != nil {
		m.mu.Unlock()
		select {
		case <-ch:
			m.mu.Lock()
			err = mg.lastErr
			m.mu.Unlock()
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	done := make(chan struct{})
	mg.inflight = done
	mg.lastTry = m.now()
	hosts := append([]string{}, mg.hosts...)
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		mg.inflight = nil
		mg.lastErr = err
		if err != nil {
			mg.lastError = err.Error()
		} else {
			mg.lastError = ""
		}
		m.mu.Unlock()
		close(done)
	}()

	if m.client.KID() == "" {
		if err := m.client.Register(ctx, m.cfg.Email); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(m.cfg.StateDir, "account.url"), []byte(m.client.KID()), 0o600); err != nil {
			return err
		}
		m.log.Info("acme account registered", "account", m.client.KID())
	}
	order, err := m.client.NewOrder(ctx, hosts)
	if err != nil {
		return err
	}
	for _, authzURL := range order.Authorizations {
		if err := m.solve(ctx, authzURL); err != nil {
			return err
		}
	}
	order, err = m.client.WaitOrder(ctx, order.URL, "ready", "valid")
	if err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: hosts[0]}, DNSNames: hosts}, key)
	if err != nil {
		return err
	}
	if order.Status == "ready" {
		if err := m.client.Finalize(ctx, order, csr); err != nil {
			return err
		}
	}
	order, err = m.client.WaitOrder(ctx, order.URL, "valid")
	if err != nil {
		return err
	}
	if order.Certificate == "" {
		return errors.New("acme: valid order without certificate URL")
	}
	chain, err := m.client.Certificate(ctx, order.Certificate)
	if err != nil {
		return err
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(chain, keyPEM)
	if err != nil {
		return fmt.Errorf("acme: issued chain does not match key: %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}
	cert.Leaf = leaf
	for _, h := range hosts {
		if err := leaf.VerifyHostname(h); err != nil {
			return fmt.Errorf("acme: issued certificate does not cover %s", h)
		}
	}
	cp, kp := m.certPaths(mg)
	if err := os.WriteFile(kp+".tmp", keyPEM, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(cp+".tmp", chain, 0o600); err != nil {
		return err
	}
	if err := os.Rename(kp+".tmp", kp); err != nil {
		return err
	}
	if err := os.Rename(cp+".tmp", cp); err != nil {
		return err
	}
	m.mu.Lock()
	mg.cert, mg.notAfter = &cert, leaf.NotAfter
	mg.issued++
	m.mu.Unlock()
	m.publish()
	m.log.Info("certificate issued", "group", name, "hosts", strings.Join(hosts, ","), "not_after", leaf.NotAfter.Format(time.RFC3339), "issuer", leaf.Issuer.CommonName)
	return nil
}

// solve completes one authorization with the configured challenge type.
func (m *Manager) solve(ctx context.Context, authzURL string) error {
	authz, err := m.client.GetAuthorization(ctx, authzURL)
	if err != nil {
		return err
	}
	if authz.Status == "valid" {
		return nil
	}
	var ch *Challenge
	for i := range authz.Challenges {
		if authz.Challenges[i].Type == m.cfg.Challenge {
			ch = &authz.Challenges[i]
		}
	}
	if ch == nil {
		return fmt.Errorf("acme: CA offers no %s challenge for %s", m.cfg.Challenge, authz.Identifier.Value)
	}
	keyAuth := jose.KeyAuthorization(ch.Token, &m.client.key.PublicKey)
	host := strings.ToLower(authz.Identifier.Value)
	switch m.cfg.Challenge {
	case "http-01":
		m.mu.Lock()
		m.http01[ch.Token] = keyAuth
		m.mu.Unlock()
		defer func() {
			m.mu.Lock()
			delete(m.http01, ch.Token)
			m.mu.Unlock()
		}()
	case "tls-alpn-01":
		cert, err := alpnCertificate(host, keyAuth)
		if err != nil {
			return err
		}
		m.mu.Lock()
		m.alpn[host] = cert
		m.mu.Unlock()
		defer func() {
			m.mu.Lock()
			delete(m.alpn, host)
			m.mu.Unlock()
		}()
	}
	if err := m.client.Accept(ctx, ch); err != nil {
		return err
	}
	return m.client.WaitAuthorization(ctx, authzURL)
}

// alpnCertificate builds the self-signed tls-alpn-01 validation
// certificate (RFC 8737).
func alpnCertificate(host, keyAuth string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(keyAuth))
	ext, err := asn1.Marshal(sum[:])
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(time.Now().UnixNano()),
		Subject:         pkix.Name{CommonName: host},
		DNSNames:        []string{host},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(24 * time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: idPeAcmeIdentifier, Critical: true, Value: ext}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	leaf, _ := x509.ParseCertificate(der)
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// Status returns the state of every managed certificate.
func (m *Manager) Status() []CertStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]CertStatus, 0, len(m.certs))
	for _, name := range sortedKeys(m.certs) {
		mg := m.certs[name]
		st := CertStatus{Name: mg.name, Hosts: mg.hosts, Present: mg.cert != nil, Renewing: mg.inflight != nil, LastError: mg.lastError, Issued: mg.issued}
		if mg.cert != nil && mg.cert.Leaf != nil {
			st.NotAfter = mg.cert.Leaf.NotAfter
			st.Issuer = mg.cert.Leaf.Issuer.CommonName
		}
		out = append(out, st)
	}
	return out
}

func sortedKeys(m map[string]*managed) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
