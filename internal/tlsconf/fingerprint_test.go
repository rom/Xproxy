package tlsconf

import (
	"crypto/tls"
	"regexp"
	"testing"
)

func TestFingerprint(t *testing.T) {
	h := &tls.ClientHelloInfo{
		ServerName:        "example.test",
		CipherSuites:      []uint16{0x0a0a, 0x1301, 0x1302, 0xc02b, 0xc02f},
		SupportedCurves:   []tls.CurveID{0x2a2a, tls.X25519, tls.CurveP256},
		SupportedPoints:   []uint8{0},
		SignatureSchemes:  []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256, tls.PSSWithSHA256},
		SupportedProtos:   []string{"h2", "http/1.1"},
		SupportedVersions: []uint16{0x3a3a, tls.VersionTLS13, tls.VersionTLS12},
		Extensions:        []uint16{0x0a0a, 0, 23, 65281, 10, 11, 16, 13, 43},
	}
	fp := Compute(h, false)
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(fp.JA3) {
		t.Fatalf("ja3 %q", fp.JA3)
	}
	// t + 13 + d (SNI) + 04 ciphers (GREASE dropped) + 08 extensions + h2
	// first/last chars "h2".
	if !regexp.MustCompile(`^t13d0408h2_[0-9a-f]{12}_[0-9a-f]{12}$`).MatchString(fp.JA4) {
		t.Fatalf("ja4 %q", fp.JA4)
	}
	if fp.Ciphers != 4 || !fp.SNI || fp.Version != tls.VersionTLS13 || fp.ExtCount != 8 {
		t.Fatalf("summary %+v", fp)
	}
	// GREASE values do not change the fingerprint; order of ciphers does
	// for JA3 but not for JA4's hash.
	h2 := *h
	h2.CipherSuites = []uint16{0x1301, 0x1302, 0xc02b, 0xc02f}
	h2.SupportedVersions = []uint16{tls.VersionTLS13, tls.VersionTLS12}
	if fp2 := Compute(&h2, false); fp2.JA3 != fp.JA3 || fp2.JA4 != fp.JA4 {
		t.Fatal("GREASE changed the fingerprint")
	}
	h3 := h2
	h3.CipherSuites = []uint16{0xc02f, 0xc02b, 0x1302, 0x1301}
	fp3 := Compute(&h3, true)
	if fp3.JA3 == fp.JA3 {
		t.Fatal("cipher order should change JA3")
	}
	if fp3.JA4[1:] != fp.JA4[1:] || fp3.JA4[0] != 'q' {
		t.Fatalf("JA4 should be order independent and marked q for QUIC: %s vs %s", fp3.JA4, fp.JA4)
	}
	// No SNI, no ALPN, TLS 1.2.
	h4 := &tls.ClientHelloInfo{CipherSuites: []uint16{0xc02f}, SupportedVersions: []uint16{tls.VersionTLS12}}
	if fp4 := Compute(h4, false); fp4.JA4[:10] != "t12i0100"+"00" {
		t.Fatalf("minimal hello ja4 %q", fp4.JA4)
	}

	tab := NewFingerprintTable(2)
	tab.Put("a", fp)
	tab.Put("b", fp)
	tab.Put("c", fp)
	if tab.Len() != 2 {
		t.Fatalf("table not bounded: %d", tab.Len())
	}
	if _, ok := tab.Get("a"); ok {
		t.Fatal("oldest entry not evicted")
	}
	tab.Delete("b")
	if _, ok := tab.Get("b"); ok {
		t.Fatal("delete")
	}
}
