// Package acmetest is a small ACME CA for tests: directory, nonces,
// accounts (JWS verified), orders, authorizations with http-01 and
// tls-alpn-01 challenges validated against a target address, finalisation
// with CSR signing and certificate download.
package acmetest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/acme/jose"
)

// CA is the fake authority.
type CA struct {
	Server *httptest.Server
	// CAPath is the PEM file of the HTTPS certificate for pinning.
	CAPath string
	// Target is where challenges are validated: host:port of the proxy's
	// plaintext listener for http-01 and TLS listener for tls-alpn-01.
	HTTPTarget string
	TLSTarget  string
	// Lifetime of issued certificates.
	Lifetime time.Duration

	key    *ecdsa.PrivateKey
	cert   *x509.Certificate
	mu     sync.Mutex
	nonces map[string]bool
	accts  map[string]*ecdsa.PublicKey // kid -> key
	orders map[string]*order
	authzs map[string]*authz
	certs  map[string][]byte
	seq    int
	Issued int
}

type order struct {
	status  string
	hosts   []string
	authzs  []string
	certURL string
	kid     string
}

type authz struct {
	host    string
	status  string
	token   string
	kid     string
	orderID string
}

// New starts a CA. dir receives the CA certificate file.
func New(t testing.TB, dir string) *CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "acmetest CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca := &CA{key: key, Lifetime: 90 * 24 * time.Hour, nonces: map[string]bool{}, accts: map[string]*ecdsa.PublicKey{}, orders: map[string]*order{}, authzs: map[string]*authz{}, certs: map[string][]byte{}}
	ca.cert, _ = x509.ParseCertificate(der)
	mux := http.NewServeMux()
	mux.HandleFunc("/directory", ca.directory)
	mux.HandleFunc("/new-nonce", ca.newNonce)
	mux.HandleFunc("/new-account", ca.newAccount)
	mux.HandleFunc("/new-order", ca.newOrder)
	mux.HandleFunc("/order/", ca.getOrder)
	mux.HandleFunc("/authz/", ca.getAuthz)
	mux.HandleFunc("/chall/", ca.challenge)
	mux.HandleFunc("/finalize/", ca.finalize)
	mux.HandleFunc("/cert/", ca.certificate)
	ca.Server = httptest.NewTLSServer(mux)
	ca.CAPath = filepath.Join(dir, "acme-ca.pem")
	if err := os.WriteFile(ca.CAPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ca.Server.Close)
	return ca
}

// Directory returns the directory URL.
func (ca *CA) Directory() string { return ca.Server.URL + "/directory" }

// IssuerPool returns a pool trusting issued certificates.
func (ca *CA) IssuerPool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.cert)
	return p
}

func (ca *CA) next(prefix string) string {
	ca.seq++
	return fmt.Sprintf("%s%d", prefix, ca.seq)
}

func (ca *CA) nonce(w http.ResponseWriter) {
	b := make([]byte, 16)
	rand.Read(b)
	n := base64.RawURLEncoding.EncodeToString(b)
	ca.mu.Lock()
	ca.nonces[n] = true
	ca.mu.Unlock()
	w.Header().Set("Replay-Nonce", n)
}

func (ca *CA) problem(w http.ResponseWriter, status int, typ, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"type": "urn:ietf:params:acme:error:" + typ, "detail": detail, "status": status})
}

func (ca *CA) directory(w http.ResponseWriter, r *http.Request) {
	u := ca.Server.URL
	json.NewEncoder(w).Encode(map[string]any{"newNonce": u + "/new-nonce", "newAccount": u + "/new-account", "newOrder": u + "/new-order", "meta": map[string]string{"termsOfService": u + "/terms"}})
}

func (ca *CA) newNonce(w http.ResponseWriter, r *http.Request) {
	ca.nonce(w)
	w.WriteHeader(http.StatusOK)
}

// verify checks the JWS, the nonce and the URL, returning the header,
// payload and account key.
func (ca *CA) verify(w http.ResponseWriter, r *http.Request) (map[string]any, []byte, string, bool) {
	raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var env struct {
		Protected string `json:"protected"`
	}
	json.Unmarshal(raw, &env)
	hb, _ := base64.RawURLEncoding.DecodeString(env.Protected)
	var hdr map[string]any
	if err := json.Unmarshal(hb, &hdr); err != nil {
		ca.problem(w, 400, "malformed", "bad protected header")
		return nil, nil, "", false
	}
	var pub *ecdsa.PublicKey
	kid, _ := hdr["kid"].(string)
	if j, ok := hdr["jwk"].(map[string]any); ok {
		pub, _ = jose.PublicKeyFromJWK(j)
	} else {
		ca.mu.Lock()
		pub = ca.accts[kid]
		ca.mu.Unlock()
		if pub == nil {
			ca.problem(w, 401, "accountDoesNotExist", "unknown account")
			return nil, nil, "", false
		}
	}
	if pub == nil {
		ca.problem(w, 400, "malformed", "no key")
		return nil, nil, "", false
	}
	h, payload, err := jose.Verify(raw, pub)
	if err != nil {
		ca.problem(w, 400, "malformed", err.Error())
		return nil, nil, "", false
	}
	nonce, _ := h["nonce"].(string)
	ca.mu.Lock()
	okNonce := ca.nonces[nonce]
	delete(ca.nonces, nonce)
	ca.mu.Unlock()
	if !okNonce {
		ca.nonce(w)
		ca.problem(w, 400, "badNonce", "bad nonce")
		return nil, nil, "", false
	}
	if u, _ := h["url"].(string); u != ca.Server.URL+r.URL.Path {
		ca.problem(w, 400, "malformed", "url mismatch")
		return nil, nil, "", false
	}
	ca.nonce(w)
	if kid == "" {
		kid = ca.thumbKID(pub)
	}
	return h, payload, kid, true
}

func (ca *CA) thumbKID(pub *ecdsa.PublicKey) string {
	return ca.Server.URL + "/acct/" + jose.Thumbprint(pub)[:16]
}

func (ca *CA) newAccount(w http.ResponseWriter, r *http.Request) {
	h, payload, kid, ok := ca.verify(w, r)
	if !ok {
		return
	}
	var body struct {
		TOS bool `json:"termsOfServiceAgreed"`
	}
	json.Unmarshal(payload, &body)
	if !body.TOS {
		ca.problem(w, 400, "userActionRequired", "terms not agreed")
		return
	}
	pub, _ := jose.PublicKeyFromJWK(h["jwk"].(map[string]any))
	ca.mu.Lock()
	_, existed := ca.accts[kid]
	ca.accts[kid] = pub
	ca.mu.Unlock()
	w.Header().Set("Location", kid)
	status := http.StatusCreated
	if existed {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"status": "valid"})
}

func (ca *CA) newOrder(w http.ResponseWriter, r *http.Request) {
	_, payload, kid, ok := ca.verify(w, r)
	if !ok {
		return
	}
	var body struct {
		Identifiers []struct{ Type, Value string } `json:"identifiers"`
	}
	json.Unmarshal(payload, &body)
	ca.mu.Lock()
	id := ca.next("o")
	o := &order{status: "pending", kid: kid}
	for _, ident := range body.Identifiers {
		o.hosts = append(o.hosts, ident.Value)
		aid := ca.next("a")
		tok := make([]byte, 16)
		rand.Read(tok)
		ca.authzs[aid] = &authz{host: ident.Value, status: "pending", token: base64.RawURLEncoding.EncodeToString(tok), kid: kid, orderID: id}
		o.authzs = append(o.authzs, ca.Server.URL+"/authz/"+aid)
	}
	ca.orders[id] = o
	ca.mu.Unlock()
	w.Header().Set("Location", ca.Server.URL+"/order/"+id)
	w.WriteHeader(http.StatusCreated)
	ca.writeOrder(w, id, o)
}

func (ca *CA) writeOrder(w http.ResponseWriter, id string, o *order) {
	ids := []map[string]string{}
	for _, h := range o.hosts {
		ids = append(ids, map[string]string{"type": "dns", "value": h})
	}
	resp := map[string]any{"status": o.status, "identifiers": ids, "authorizations": o.authzs, "finalize": ca.Server.URL + "/finalize/" + id}
	if o.certURL != "" {
		resp["certificate"] = o.certURL
	}
	json.NewEncoder(w).Encode(resp)
}

func (ca *CA) getOrder(w http.ResponseWriter, r *http.Request) {
	_, _, _, ok := ca.verify(w, r)
	if !ok {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/order/")
	ca.mu.Lock()
	o := ca.orders[id]
	ca.mu.Unlock()
	if o == nil {
		ca.problem(w, 404, "malformed", "no order")
		return
	}
	ca.writeOrder(w, id, o)
}

func (ca *CA) getAuthz(w http.ResponseWriter, r *http.Request) {
	_, _, _, ok := ca.verify(w, r)
	if !ok {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/authz/")
	ca.mu.Lock()
	a := ca.authzs[id]
	ca.mu.Unlock()
	if a == nil {
		ca.problem(w, 404, "malformed", "no authz")
		return
	}
	chs := []map[string]string{}
	for _, typ := range []string{"http-01", "tls-alpn-01"} {
		chs = append(chs, map[string]string{"type": typ, "url": ca.Server.URL + "/chall/" + id + "/" + typ, "token": a.token, "status": a.status})
	}
	json.NewEncoder(w).Encode(map[string]any{"identifier": map[string]string{"type": "dns", "value": a.host}, "status": a.status, "challenges": chs})
}

func (ca *CA) challenge(w http.ResponseWriter, r *http.Request) {
	_, _, kid, ok := ca.verify(w, r)
	if !ok {
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/chall/"), "/")
	ca.mu.Lock()
	a := ca.authzs[parts[0]]
	pub := ca.accts[kid]
	ca.mu.Unlock()
	if a == nil || len(parts) != 2 {
		ca.problem(w, 404, "malformed", "no challenge")
		return
	}
	keyAuth := jose.KeyAuthorization(a.token, pub)
	var err error
	switch parts[1] {
	case "http-01":
		err = ca.validateHTTP01(a.host, a.token, keyAuth)
	case "tls-alpn-01":
		err = ca.validateTLSALPN01(a.host, keyAuth)
	default:
		err = fmt.Errorf("unsupported challenge")
	}
	ca.mu.Lock()
	if err != nil {
		a.status = "invalid"
		ca.orders[a.orderID].status = "invalid"
	} else {
		a.status = "valid"
		allValid := true
		for _, au := range ca.authzs {
			if au.orderID == a.orderID && au.status != "valid" {
				allValid = false
			}
		}
		if allValid {
			ca.orders[a.orderID].status = "ready"
		}
	}
	ca.mu.Unlock()
	resp := map[string]any{"type": parts[1], "url": ca.Server.URL + r.URL.Path, "token": a.token, "status": a.status}
	if err != nil {
		resp["error"] = map[string]any{"type": "urn:ietf:params:acme:error:unauthorized", "detail": err.Error()}
	}
	json.NewEncoder(w).Encode(resp)
}

func (ca *CA) validateHTTP01(host, token, keyAuth string) error {
	if ca.HTTPTarget == "" {
		return fmt.Errorf("no http target")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+ca.HTTPTarget+jose.HTTP01Path+token, http.NoBody)
	req.Host = host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != 200 || strings.TrimSpace(string(body)) != keyAuth {
		return fmt.Errorf("http-01: status %d body %q", resp.StatusCode, body)
	}
	return nil
}

func (ca *CA) validateTLSALPN01(host, keyAuth string) error {
	if ca.TLSTarget == "" {
		return fmt.Errorf("no tls target")
	}
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 3 * time.Second}, Config: &tls.Config{ServerName: host, NextProtos: []string{jose.ALPNProto}, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}} //nolint:gosec // validation connection by design
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := d.DialContext(ctx, "tcp", ca.TLSTarget)
	if err != nil {
		return err
	}
	defer conn.Close()
	cs := conn.(*tls.Conn).ConnectionState()
	if cs.NegotiatedProtocol != jose.ALPNProto {
		return fmt.Errorf("tls-alpn-01: negotiated %q", cs.NegotiatedProtocol)
	}
	if len(cs.PeerCertificates) != 1 {
		return fmt.Errorf("tls-alpn-01: %d certificates", len(cs.PeerCertificates))
	}
	leaf := cs.PeerCertificates[0]
	if err := leaf.VerifyHostname(host); err != nil {
		return err
	}
	want := sha256.Sum256([]byte(keyAuth))
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}) {
			var got []byte
			if _, err := asn1.Unmarshal(ext.Value, &got); err != nil {
				return err
			}
			if !ext.Critical || !bytes.Equal(got, want[:]) {
				return fmt.Errorf("tls-alpn-01: wrong key authorization")
			}
			return nil
		}
	}
	return fmt.Errorf("tls-alpn-01: extension missing")
}

func (ca *CA) finalize(w http.ResponseWriter, r *http.Request) {
	_, payload, _, ok := ca.verify(w, r)
	if !ok {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/finalize/")
	var body struct {
		CSR string `json:"csr"`
	}
	json.Unmarshal(payload, &body)
	der, _ := base64.RawURLEncoding.DecodeString(body.CSR)
	csr, err := x509.ParseCertificateRequest(der)
	ca.mu.Lock()
	defer ca.mu.Unlock()
	o := ca.orders[id]
	if o == nil || o.status != "ready" || err != nil || csr.CheckSignature() != nil {
		ca.problem(w, 403, "orderNotReady", "order not ready or bad csr")
		return
	}
	for _, h := range o.hosts {
		found := false
		for _, n := range csr.DNSNames {
			if n == h {
				found = true
			}
		}
		if !found {
			ca.problem(w, 400, "badCSR", "csr does not cover "+h)
			return
		}
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: csr.Subject, DNSNames: csr.DNSNames, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(ca.Lifetime),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		ca.problem(w, 500, "serverInternal", err.Error())
		return
	}
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})...)
	cid := ca.next("c")
	ca.certs[cid] = chain
	o.status = "valid"
	o.certURL = ca.Server.URL + "/cert/" + cid
	ca.Issued++
	ca.writeOrder(w, id, o)
}

func (ca *CA) certificate(w http.ResponseWriter, r *http.Request) {
	_, _, _, ok := ca.verify(w, r)
	if !ok {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/cert/")
	ca.mu.Lock()
	chain := ca.certs[id]
	ca.mu.Unlock()
	if chain == nil {
		ca.problem(w, 404, "malformed", "no certificate")
		return
	}
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.Write(chain)
}

// Serial helper for tests to compare issued counts.
func (ca *CA) IssuedCount() int {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	return ca.Issued
}
