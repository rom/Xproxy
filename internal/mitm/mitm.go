// Package mitm issues the certificates a TLS-intercepting proxy
// presents to its clients.
//
// Interception is the one feature here that makes the proxy less safe
// if it is built carelessly, because it takes a connection the client
// verified end to end and replaces it with two connections the client
// cannot see past. Two things follow, and this package and its caller
// hold to both:
//
// The proxy verifies the real server itself, with the ordinary rules,
// and a client only ever sees a forged certificate for a server whose
// own certificate verified. An interception proxy that skips that turns
// every client's verified connection into an unverified one and tells
// the client it is fine — which is worse than no proxy at all, because
// the padlock is still there.
//
// And the signing key is the most dangerous file in the estate. Anyone
// holding it can impersonate every site to every client that trusts the
// CA. It is loaded once, kept in memory, and never written anywhere by
// this proxy.
package mitm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

// CA is the signing identity a proxy forges certificates with.
type CA struct {
	cert *x509.Certificate
	key  crypto.Signer
	// leafTTL is how long an issued certificate is valid. It is short:
	// a forged certificate that outlives the proxy that made it is a
	// certificate somebody else can still be holding.
	leafTTL time.Duration

	mu    sync.Mutex
	cache map[string]*tls.Certificate
	order []string
	max   int
}

// Options configure a CA.
type Options struct {
	CertFile string
	KeyFile  string
	// LeafTTL is the validity of an issued certificate. Default 24h.
	LeafTTL time.Duration
	// MaxCache bounds the issued certificates kept in memory. Default
	// 1024.
	MaxCache int
}

// Load reads the signing certificate and key.
func Load(o Options) (*CA, error) {
	if o.CertFile == "" || o.KeyFile == "" {
		return nil, errors.New("mitm: ca_cert_file and ca_key_file are required")
	}
	pair, err := tls.LoadX509KeyPair(o.CertFile, o.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("mitm: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("mitm: %w", err)
	}
	if !leaf.IsCA || leaf.KeyUsage&x509.KeyUsageCertSign == 0 {
		// A certificate that cannot sign cannot be a signing CA, and
		// finding that out per connection is finding it out too late.
		return nil, errors.New("mitm: ca_cert_file is not a CA certificate that may sign certificates")
	}
	if time.Now().After(leaf.NotAfter) {
		return nil, fmt.Errorf("mitm: the CA certificate expired on %s", leaf.NotAfter.Format(time.RFC3339))
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("mitm: the CA key cannot sign")
	}
	if err := keyFilePrivate(o.KeyFile); err != nil {
		return nil, err
	}
	ttl := o.LeafTTL
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	maxCache := o.MaxCache
	if maxCache <= 0 {
		maxCache = 1024
	}
	return &CA{cert: leaf, key: signer, leafTTL: ttl,
		cache: map[string]*tls.Certificate{}, max: maxCache}, nil
}

// keyFilePrivate refuses a signing key anybody can read. Holding it is
// holding the ability to impersonate every site to every client that
// trusts this CA, so the check is worth failing the load over.
func keyFilePrivate(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("mitm: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("mitm: %s is mode %v; a signing key readable by others is the whole estate's problem",
			path, info.Mode().Perm())
	}
	return nil
}

// Subject is the CA's own subject, for the logs and for the operator
// who has to recognise it in a trust store.
func (c *CA) Subject() string { return c.cert.Subject.String() }

// NotAfter is when the CA stops working, which is worth knowing before
// it happens rather than after.
func (c *CA) NotAfter() time.Time { return c.cert.NotAfter }

// Leaf returns a certificate for a server name, issuing and caching one
// if needed. real is the certificate the proxy verified for that name;
// what it carries is copied so the client sees the same names it would
// have seen, rather than a certificate that happens to be valid for
// something else.
func (c *CA) Leaf(name string, real *x509.Certificate) (*tls.Certificate, error) {
	key := cacheKey(name, real)
	c.mu.Lock()
	if got, ok := c.cache[key]; ok {
		if leaf := got.Leaf; leaf == nil || time.Now().Before(leaf.NotAfter.Add(-time.Minute)) {
			c.mu.Unlock()
			return got, nil
		}
		delete(c.cache, key)
	}
	c.mu.Unlock()

	out, err := c.issue(name, real)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.cache[key]; !ok {
		if len(c.order) >= c.max {
			// The oldest issued goes. The table is a cache, not a
			// record: nothing is lost but the work of issuing again.
			oldest := c.order[0]
			c.order = c.order[1:]
			delete(c.cache, oldest)
		}
		c.order = append(c.order, key)
	}
	c.cache[key] = out
	return out, nil
}

// cacheKey is the name plus what the real certificate said, so a server
// that changes its names is not served from a certificate built for the
// old ones.
func cacheKey(name string, real *x509.Certificate) string {
	if real == nil {
		return name + "\x00"
	}
	sum := sha256.Sum256(real.Raw)
	return name + "\x00" + string(sum[:8])
}

func (c *CA) issue(name string, real *x509.Certificate) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		// A minute back, because a client whose clock is a little
		// behind should not see a certificate from the future.
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(c.leafTTL),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(name); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{name}
	}
	if real != nil {
		// The names the real certificate carried, so a client that
		// checks one of its other names still finds it. Nothing else is
		// copied: not the issuer, not the extensions, not the validity,
		// because a forged certificate should look like what it is to
		// anybody who looks.
		tmpl.DNSNames = mergeNames(tmpl.DNSNames, real.DNSNames)
		tmpl.IPAddresses = mergeIPs(tmpl.IPAddresses, real.IPAddresses)
		if real.Subject.CommonName != "" {
			tmpl.Subject.CommonName = real.Subject.CommonName
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, key.Public(), c.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{der, c.cert.Raw},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

func mergeNames(into, from []string) []string {
	seen := map[string]bool{}
	for _, n := range into {
		seen[n] = true
	}
	for _, n := range from {
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		into = append(into, n)
		if len(into) >= 64 {
			// A certificate with hundreds of names is one somebody is
			// using to make this proxy do work.
			break
		}
	}
	return into
}

func mergeIPs(into, from []net.IP) []net.IP {
	seen := map[string]bool{}
	for _, ip := range into {
		seen[ip.String()] = true
	}
	for _, ip := range from {
		if seen[ip.String()] {
			continue
		}
		seen[ip.String()] = true
		into = append(into, ip)
		if len(into) >= 64 {
			break
		}
	}
	return into
}

// Cached is how many certificates are held, for the status views.
func (c *CA) Cached() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.cache)
}

// ClientHelloName reads the server name out of a TLS ClientHello
// without consuming it, and reports whether the bytes are a ClientHello
// at all.
//
// It matters because a CONNECT tunnel does not have to carry TLS. A
// proxy that assumes it does will answer a handshake to something that
// was speaking SSH or a database protocol, and break it for no reason.
// What cannot be read here is passed through untouched rather than
// guessed at.
func ClientHelloName(b []byte) (name string, isHello bool) {
	// A TLS record: handshake (22), version, length.
	if len(b) < 9 || b[0] != 22 {
		return "", false
	}
	recLen := int(binary.BigEndian.Uint16(b[3:5]))
	if recLen < 4 || len(b) < 5+4 {
		return "", false
	}
	body := b[5:]
	if len(body) > recLen {
		body = body[:recLen]
	}
	if body[0] != 1 { // client_hello
		return "", false
	}
	// It is a ClientHello. The name is a bonus: a hello split across
	// records, or one with no SNI, is still a hello.
	hsLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	hs := body[4:]
	if len(hs) > hsLen {
		hs = hs[:hsLen]
	}
	return sniFrom(hs), true
}

// sniFrom walks a ClientHello body to its server_name extension. It
// returns "" for anything it cannot read, because a name guessed at is
// a name the certificate would be wrong for.
func sniFrom(b []byte) string {
	if len(b) < 34 {
		return ""
	}
	b = b[34:] // version and random
	if len(b) < 1 {
		return ""
	}
	n := int(b[0]) // session id
	if b = b[1:]; len(b) < n+2 {
		return ""
	}
	b = b[n:]
	n = int(binary.BigEndian.Uint16(b)) // cipher suites
	if b = b[2:]; len(b) < n+1 {
		return ""
	}
	b = b[n:]
	n = int(b[0]) // compression methods
	if b = b[1:]; len(b) < n+2 {
		return ""
	}
	b = b[n:]
	extLen := int(binary.BigEndian.Uint16(b))
	if b = b[2:]; len(b) < extLen {
		return ""
	}
	b = b[:extLen]
	for len(b) >= 4 {
		typ := binary.BigEndian.Uint16(b)
		size := int(binary.BigEndian.Uint16(b[2:]))
		if b = b[4:]; len(b) < size {
			return ""
		}
		if typ != 0 { // server_name
			b = b[size:]
			continue
		}
		ext := b[:size]
		if len(ext) < 5 {
			return ""
		}
		// A server name list: length, then entries of type and length.
		ext = ext[2:]
		if ext[0] != 0 { // host_name
			return ""
		}
		nameLen := int(binary.BigEndian.Uint16(ext[1:]))
		ext = ext[3:]
		if len(ext) < nameLen {
			return ""
		}
		return string(ext[:nameLen])
	}
	return ""
}
