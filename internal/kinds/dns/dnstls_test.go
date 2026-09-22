package dns_test

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"testing"

	wire "github.com/rom/xproxy/internal/dns"
	_ "github.com/rom/xproxy/internal/kinds/dns"
	"github.com/rom/xproxy/internal/proxytest"
	"github.com/rom/xproxy/internal/testutil"
)

func TestEncryptedDNSListener(t *testing.T) {
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "wire.test")
	// The upstream is a plain dns listener of the same proxy answering
	// from a sinkhole block, so no external resolver is needed.
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: plain
      address: "127.0.0.1:0"
      kind: dns
      dns: {upstreams: ["127.0.0.1:1"], block: [blocked.test], block_action: sinkhole, sinkhole_ipv4: 10.9.9.9, timeout: 1s}
    - name: main
      address: "127.0.0.1:0"
      kind: dns
      tls: {certificates: [{cert_file: %s, key_file: %s}]}
      dns: {upstreams: ["127.0.0.1:1"], block: [blocked.test], block_action: sinkhole, sinkhole_ipv4: 10.9.9.9, timeout: 1s, doh_path: /q}
logging: {access: {enabled: false}}
`, cert, key)
	s := proxytest.Start(t, yaml)
	addr := s.Addrs()["main"]
	q, err := wire.Query(3, "blocked.test", wire.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"dot"}}) //nolint:gosec // test
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := wire.WriteTCP(c, q); err != nil {
		t.Fatal(err)
	}
	resp, err := wire.ReadTCP(c, wire.MaxMessage)
	if err != nil {
		t.Fatal(err)
	}
	if h, _ := wire.ParseHeader(resp); h.ID != 3 || h.Rcode() != wire.RcodeNoError || h.ANCount != 1 || !bytes.Contains(resp, []byte{10, 9, 9, 9}) {
		t.Fatalf("dot answer %v %x", h, resp)
	}
	h2 := &http.Client{Transport: &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // test
	r, err := h2.Post("https://"+addr+"/q", "application/dns-message", bytes.NewReader(q))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if r.StatusCode != 200 || !bytes.Contains(body, []byte{10, 9, 9, 9}) {
		t.Fatalf("doh: %d %x", r.StatusCode, body)
	}
	var enc *wire.Status
	for _, st := range s.DNS() {
		if st.Listener == "main" {
			cp := st
			enc = &cp
		}
	}
	if enc == nil || !enc.Encrypted || enc.DoHPath != "/q" || enc.QueriesDoT != 1 || enc.QueriesDoH != 1 {
		t.Fatalf("status %+v", enc)
	}
	if certs := s.Certificates()["main"]; len(certs) != 1 {
		t.Fatalf("certificates %+v", certs)
	}
}
