// Package fipsmode reports and enforces the runtime's FIPS 140-3 mode.
//
// Go's standard library carries a FIPS 140-3 module of its own, switched on with
// the fips140 GODEBUG. When it is on, the cryptography this proxy uses comes
// from that module and the algorithms outside it are refused by the library
// rather than by this code.
//
// So this package deliberately does not carry a list of approved algorithms.
// Such a list is a claim about somebody else's validation certificate, it goes
// out of date, and getting it wrong in either direction is bad: too strict
// refuses a configuration that would have worked, and too lax tells an operator
// they are compliant when they are not.
//
// What it does instead is ask the runtime:
//
//   - Enabled reports whether the module is in use.
//   - Require refuses to serve when an estate said it must be and it is not,
//     with the remedy in the message rather than in a manual.
//   - Probe runs a real handshake per configured key exchange group and cipher
//     suite and reports the ones this runtime will not do. That answers "will my
//     TLS configuration work under FIPS" by trying it, at start, instead of
//     leaving it to be discovered by the first client that offers one of them.
package fipsmode

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/fips140"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"sort"
	"sync"
	"time"
)

// Enabled reports whether the Go FIPS 140-3 module is in use.
func Enabled() bool { return fips140.Enabled() }

// Status is what the management view and the exposition say.
type Status struct {
	// Enabled is the runtime's own answer.
	Enabled bool `json:"enabled"`
	// Required is what the configuration asked for.
	Required bool `json:"required"`
	// Refused lists the configured algorithms this runtime will not do, as
	// the probe found them. Empty after a probe that found none, and absent
	// when no probe ran.
	Refused []string `json:"refused,omitempty"`
	// Probed says whether the handshake probe ran, so an empty Refused is not
	// read as "everything works" when nothing was tried.
	Probed bool `json:"probed"`
}

// Require refuses when the estate said FIPS mode is required and the runtime is
// not in it.
//
// The message carries the remedy because this is the error somebody meets at
// three in the morning during an audit: the mode is a property of how the
// binary was built and started, not of this configuration file, and nothing
// this proxy can do at runtime turns it on.
func Require(required bool) error {
	if !required || Enabled() {
		return nil
	}
	return errors.New("fips.required: this runtime is not in FIPS 140-3 mode. " +
		"The mode comes from the Go toolchain and the fips140 GODEBUG, not from this file: " +
		"start the daemon with GODEBUG=fips140=on (or fips140=only), or build it with a toolchain " +
		"whose FIPS module is enabled by default. Setting required: false says the estate does not need it")
}

// probeTimeout bounds one handshake. A probe that hangs must not hold a start,
// and a refused algorithm must not cost a deadline: the loser's side is closed
// as soon as the other end has failed, so this is the bound on a hang rather
// than the cost of a refusal.
const probeTimeout = 5 * time.Second

// Probe tries a real handshake for each group and each suite, and returns the
// names this runtime refused.
//
// A handshake over a pipe rather than a table of algorithm names: the question
// is what *this* build of *this* runtime in *this* mode will actually do, and
// the only honest way to answer it is to do it.
func Probe(groups []tls.CurveID, suites []uint16) ([]string, error) {
	cert, err := probeCertificate()
	if err != nil {
		return nil, err
	}
	var (
		mu      sync.Mutex
		refused []string
	)
	note := func(what string) {
		mu.Lock()
		refused = append(refused, what)
		mu.Unlock()
	}
	for _, g := range groups {
		// TLS 1.3 for the groups: that is where a key exchange group is
		// negotiated on its own, without a cipher suite deciding it too.
		if err := handshake(cert, tls.VersionTLS13, []tls.CurveID{g}, nil); err != nil {
			note("key_exchange " + groupName(g))
		}
	}
	for _, s := range suites {
		// TLS 1.2 for the suites, because a TLS 1.3 suite is not
		// configurable and a 1.2 suite is exactly what the configuration
		// names.
		if err := handshake(cert, tls.VersionTLS12, nil, []uint16{s}); err != nil {
			note("cipher_suite " + tls.CipherSuiteName(s))
		}
	}
	sort.Strings(refused)
	return refused, nil
}

// handshake completes one TLS handshake over a pipe with exactly the algorithms
// given, and returns why it failed.
func handshake(cert tls.Certificate, version uint16, groups []tls.CurveID, suites []uint16) error {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = server.Close() }()
	deadline := time.Now().Add(probeTimeout)
	_ = client.SetDeadline(deadline)
	_ = server.SetDeadline(deadline)

	// The version is pinned to the one under test on both ends, TLS 1.2
	// included: the whole point is to find out what this runtime does with a
	// 1.2 cipher suite the configuration names, which cannot be asked at 1.3.
	// Nothing here reaches a network -- it is a pipe inside this process --
	// and the certificate lives for the length of the probe.
	sc := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: version, MaxVersion: version, //nolint:gosec // the version under test is the question
		CurvePreferences: groups, CipherSuites: suites}
	cc := &tls.Config{RootCAs: probePool(cert), ServerName: probeName, MinVersion: version, MaxVersion: version, //nolint:gosec // as above
		CurvePreferences: groups, CipherSuites: suites}

	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		s := tls.Server(server, sc)
		errc <- s.HandshakeContext(ctx)
	}()
	c := tls.Client(client, cc)
	cerr := c.HandshakeContext(ctx)
	if cerr != nil {
		// The client has decided. Closing both ends unblocks the server
		// rather than leaving it to its deadline, which is what made a
		// refused algorithm cost seconds instead of nothing.
		_ = client.Close()
		_ = server.Close()
		<-errc
		return cerr
	}
	return <-errc
}

// probeName is the certificate's name; it never leaves the process.
const probeName = "fips-probe.invalid"

var (
	probeOnce sync.Once
	probeCert tls.Certificate
	probePEM  *x509.CertPool
	probeErr  error
)

// probeCertificate makes the throwaway P-256 certificate the probe handshakes
// with. P-256 because it is the curve a FIPS module has if it has any, so a
// failure is about the algorithm under test rather than about the certificate.
func probeCertificate() (tls.Certificate, error) {
	probeOnce.Do(func() {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			probeErr = fmt.Errorf("fips probe: %w", err)
			return
		}
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: probeName},
			DNSNames:              []string{probeName},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			IsCA:                  true,
			BasicConstraintsValid: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
		if err != nil {
			probeErr = fmt.Errorf("fips probe: %w", err)
			return
		}
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			probeErr = fmt.Errorf("fips probe: %w", err)
			return
		}
		pool := x509.NewCertPool()
		pool.AddCert(leaf)
		probeCert = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
		probePEM = pool
	})
	return probeCert, probeErr
}

func probePool(tls.Certificate) *x509.CertPool { return probePEM }

// groupName is a key exchange group as the configuration spells it.
func groupName(id tls.CurveID) string {
	switch id {
	case tls.X25519MLKEM768:
		return "X25519MLKEM768"
	case tls.X25519:
		return "X25519"
	case tls.CurveP256:
		return "P-256"
	case tls.CurveP384:
		return "P-384"
	case tls.CurveP521:
		return "P-521"
	}
	return fmt.Sprintf("group-%d", uint16(id))
}
