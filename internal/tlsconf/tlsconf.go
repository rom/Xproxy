// Package tlsconf builds crypto/tls configurations from xproxy configuration
// with hardened defaults: TLS 1.2 minimum, no insecure suites, no
// renegotiation, session tickets rotated by the runtime, X25519 preferred,
// and certificate reload without restart.
package tlsconf

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"

	"github.com/rom/xproxy/internal/config"
)

// Reloadable holds certificates that can be swapped atomically.
type Reloadable struct {
	certs atomic.Pointer[[]tls.Certificate]
	cfgs  []config.Certificate
}

// Load parses all configured certificate pairs.
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
	r.certs.Store(&certs)
	return nil
}

// getCertificate selects a certificate by SNI, falling back to the first.
func (r *Reloadable) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	certs := r.certs.Load()
	if certs == nil || len(*certs) == 0 {
		return nil, errors.New("no certificates loaded")
	}
	if len(*certs) == 1 {
		return &(*certs)[0], nil
	}
	for i := range *certs {
		if err := hello.SupportsCertificate(&(*certs)[i]); err == nil {
			return &(*certs)[i], nil
		}
	}
	return &(*certs)[0], nil
}

// Server builds a server tls.Config for a listener. The returned Reloadable
// can be used to hot reload certificates.
func Server(cfg *config.TLS, protocols []config.Protocol) (*tls.Config, *Reloadable, error) {
	r := &Reloadable{cfgs: cfg.Certificates}
	if err := r.Load(); err != nil {
		return nil, nil, err
	}
	tc := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		GetCertificate:           r.getCertificate,
		CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
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

// Client builds the tls.Config used towards an upstream.
func Client(cfg *config.UpstreamTLS) (*tls.Config, error) {
	tc := &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
		Renegotiation:    tls.RenegotiateNever,
	}
	if cfg == nil {
		return tc, nil
	}
	tc.ServerName = cfg.ServerName
	if cfg.CAFile != "" {
		pool, err := loadPool(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		tc.RootCAs = pool
	}
	if cfg.ClientCertFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.ClientCertFile, cfg.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load upstream client certificate: %w", err)
		}
		tc.Certificates = []tls.Certificate{cert}
	}
	if cfg.InsecureSkipVerify && cfg.AllowInsecure {
		tc.InsecureSkipVerify = true //nolint:gosec // explicitly double opted in by config
	}
	return tc, nil
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
