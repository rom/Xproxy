package tlsconf

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/testutil"
)

// sctList encodes SCTs as the extension value: OCTET STRING of the TLS
// encoded list.
func sctList(scts ...[]byte) []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16LengthPrefixed(func(list *cryptobyte.Builder) {
		for _, s := range scts {
			list.AddUint16LengthPrefixed(func(one *cryptobyte.Builder) { one.AddBytes(s) })
		}
	})
	raw, _ := b.Bytes()
	out, _ := asn1.Marshal(raw)
	return out
}

// buildSCT signs a precert entry for leaf with the log key.
func buildSCT(t *testing.T, logKey *ecdsa.PrivateKey, logID [32]byte, leaf, issuer *x509.Certificate, ts uint64) []byte {
	t.Helper()
	tbs, err := precertTBS(leaf)
	if err != nil {
		t.Fatal(err)
	}
	ikh := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)
	b := cryptobyte.NewBuilder(nil)
	b.AddUint8(0)
	b.AddUint8(0)
	b.AddUint64(ts)
	b.AddUint16(1)
	b.AddBytes(ikh[:])
	b.AddUint24LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(tbs) })
	b.AddUint16LengthPrefixed(func(*cryptobyte.Builder) {})
	signed, _ := b.Bytes()
	sum := sha256.Sum256(signed)
	sig, err := ecdsa.SignASN1(rand.Reader, logKey, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	out := cryptobyte.NewBuilder(nil)
	out.AddUint8(0)
	out.AddBytes(logID[:])
	out.AddUint64(ts)
	out.AddUint16(0)
	out.AddUint8(4)
	out.AddUint8(3)
	out.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(sig) })
	raw, _ := out.Bytes()
	return raw
}

func TestCertificateTransparency(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	logKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub, _ := x509.MarshalPKIXPublicKey(&logKey.PublicKey)
	logID := sha256.Sum256(pub)
	listJSON, _ := json.Marshal(map[string]any{"operators": []any{map[string]any{"name": "test", "logs": []any{
		map[string]any{"log_id": base64.StdEncoding.EncodeToString(logID[:]), "key": base64.StdEncoding.EncodeToString(pub)}}}}})
	logs, err := ParseLogList(listJSON)
	if err != nil || logs.Logs != 1 {
		t.Fatalf("log list: %v", err)
	}
	// Two passes: the SCT signs the TBS without the SCT extension, which
	// does not depend on the extension's content, so a first certificate
	// with a placeholder of the right size yields the bytes to sign.
	ts := uint64(time.Now().UnixMilli())                            //nolint:gosec // positive
	placeholder := buildSCT(t, logKey, logID, ca.Cert, ca.Cert, ts) // any SCT of the right length
	ext := pkix.Extension{Id: sctExtensionOID, Value: sctList(placeholder)}
	certPath, keyPath, first := issueWithOCSP(t, ca, dir, "ct.test", "", ext)
	real := buildSCT(t, logKey, logID, first, ca.Cert, ts)
	// Reissue with the same serial and template but the real SCT: the
	// TBS minus the extension is the same whatever the extension holds
	// (DER signature lengths vary), so the signature verifies.
	ext.Value = sctList(real)
	leaf := reissue(t, ca, first, ext)

	scts, err := VerifySCTs(leaf, ca.Cert, logs)
	if err != nil || len(scts) != 1 || !scts[0].Verified || scts[0].Error != "" {
		t.Fatalf("verify: %v %+v", err, scts)
	}
	if scts[0].LogID != base64.StdEncoding.EncodeToString(logID[:]) || scts[0].Timestamp.UnixMilli() != int64(ts) { //nolint:gosec // positive
		t.Fatalf("fields %+v", scts[0])
	}
	// Unknown log, missing issuer and a tampered signature.
	if scts, _ := VerifySCTs(leaf, ca.Cert, &LogList{keys: map[[32]byte]crypto.PublicKey{}}); len(scts) != 1 || scts[0].Verified || !strings.Contains(scts[0].Error, "not in the list") {
		t.Fatalf("unknown log: %+v", scts)
	}
	if scts, _ := VerifySCTs(leaf, nil, logs); scts[0].Verified || !strings.Contains(scts[0].Error, "issuer") {
		t.Fatalf("no issuer: %+v", scts)
	}
	bad := append([]byte(nil), real...)
	bad[len(bad)-1] ^= 1
	ext.Value = sctList(bad)
	tampered := reissue(t, ca, first, ext)
	if scts, _ := VerifySCTs(tampered, ca.Cert, logs); scts[0].Verified || !strings.Contains(scts[0].Error, "does not verify") {
		t.Fatalf("tampered: %+v", scts)
	}
	// Policy: require 1 verified passes; require 2 fails; enforce makes
	// Load fail; without a log list presence counts.
	st := ctCheck(leaf, ca.Cert, logs, 1)
	if !st.OK || st.Verified != 1 {
		t.Fatalf("policy 1: %+v", st)
	}
	if st := ctCheck(leaf, ca.Cert, logs, 2); st.OK || !strings.Contains(st.Error, "1 of 1") {
		t.Fatalf("policy 2: %+v", st)
	}
	if st := ctCheck(leaf, ca.Cert, nil, 1); !st.OK || st.Embedded != 1 {
		t.Fatalf("presence policy: %+v", st)
	}
	if st := ctCheck(ca.Cert, nil, nil, 1); st.OK || !strings.Contains(st.Error, "0 embedded") {
		t.Fatalf("no scts: %+v", st)
	}
	rl := &Reloadable{cfgs: []config.Certificate{{CertFile: certPath, KeyFile: keyPath}}, ct: &config.CT{Require: 2, Enforce: true}}
	if err := rl.Load(); err == nil || !strings.Contains(err.Error(), "certificate transparency") {
		t.Fatalf("enforce: %v", err)
	}
	rl.ct.Enforce = false
	if err := rl.Load(); err != nil || len(rl.CTWarnings()) != 1 {
		t.Fatalf("warn: %v %v", err, rl.CTWarnings())
	}
	// Malformed extension.
	broken := reissue(t, ca, first, pkix.Extension{Id: sctExtensionOID, Value: []byte{1, 2, 3}})
	if _, err := ParseSCTs(broken); err == nil {
		t.Fatal("malformed extension parsed")
	}
	if _, err := ParseLogList([]byte(`{"operators":[]}`)); err == nil {
		t.Fatal("empty log list accepted")
	}
	_ = putUint64
}

// reissue signs a certificate with base's serial and names and the given
// extension.
func reissue(t *testing.T, ca *testutil.CA, base *x509.Certificate, ext pkix.Extension) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: base.SerialNumber, Subject: base.Subject, DNSNames: base.DNSNames, IPAddresses: base.IPAddresses,
		NotBefore: base.NotBefore, NotAfter: base.NotAfter, KeyUsage: base.KeyUsage, ExtKeyUsage: base.ExtKeyUsage,
		ExtraExtensions: []pkix.Extension{ext},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, base.PublicKey, ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return leaf
}
