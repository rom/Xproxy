package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/webtransport-go"
	"github.com/rom/xproxy/internal/h3"
	"github.com/rom/xproxy/internal/testutil"
)

func TestWebTransportRelay(t *testing.T) {
	dir := t.TempDir()
	ca := testutil.WriteCA(t, dir)
	bcert, bkey := ca.Issue(t, dir, "backend.test")
	lcert, lkey := ca.Issue(t, dir, "wt.test")
	// Backend: a WebTransport echo server that also reports the headers
	// it saw through a datagram.
	var backendSrv *h3.Server
	seen := make(chan http.Header, 1)
	backendAddr := h3Backend(t, bcert, bkey, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isWebTransport(r) {
			http.Error(w, "not webtransport", 400)
			return
		}
		select {
		case seen <- r.Header.Clone():
		default:
		}
		sess, err := backendSrv.Upgrade(w, r)
		if err != nil {
			return
		}
		go func() {
			for {
				str, err := sess.AcceptStream(context.Background())
				if err != nil {
					return
				}
				go func() {
					b, _ := io.ReadAll(str)
					_, _ = str.Write(append([]byte("echo:"), b...))
					_ = str.Close()
				}()
			}
		}()
		go func() {
			for {
				str, err := sess.AcceptUniStream(context.Background())
				if err != nil {
					return
				}
				b, _ := io.ReadAll(str)
				out, err := sess.OpenUniStreamSync(context.Background())
				if err != nil {
					return
				}
				_, _ = out.Write(append([]byte("uni:"), b...))
				_ = out.Close()
			}
		}()
		for {
			d, err := sess.ReceiveDatagram(context.Background())
			if err != nil {
				return
			}
			_ = sess.SendDatagram(append([]byte("dgram:"), d...))
		}
	}), true)
	backendSrv = lastH3Backend
	yaml := `
version: 1
server:
  listeners:
    - name: main
      address: "127.0.0.1:0"
      protocols: [h1, h3]
      h3: {webtransport: true, validate_addresses: under_load}
      tls:
        certificates: [{cert_file: %s, key_file: %s}]
upstreams:
  - name: wt
    scheme: https
    h3: true
    endpoints: [{address: "%s"}]
    tls: {server_name: backend.test, ca_file: %s}
    timeouts: {connect: 2s}
  - name: plain
    scheme: https
    h3: true
    endpoints: [{address: "%s"}]
    tls: {server_name: backend.test, ca_file: %s}
routes:
  - {name: closed, paths: ["/closed"], upstream: plain}
  - {name: denied, paths: ["/denied"], upstream: wt, webtransport: true, deny_cidrs: ["0.0.0.0/0", "::/0"]}
  - {name: wt, paths: ["/"], upstream: wt, webtransport: true, request_headers: {set: {X-Tenant: acme}}}
`
	s, _ := startServer(t, fmt.Sprintf(yaml, lcert, lkey, backendAddr, ca.Path, backendAddr, ca.Path))
	udp := s.Addrs()["main/udp"]
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CertPEM)
	d := &webtransport.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "wt.test", NextProtos: []string{http3.NextProtoH3}, MinVersion: tls.VersionTLS13},
		QUICConfig:      &quic.Config{EnableDatagrams: true, EnableStreamResetPartialDelivery: true, HandshakeIdleTimeout: 3 * time.Second},
	}
	defer d.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, sess, err := d.Dial(ctx, "https://"+udp+"/session?x=1", http.Header{"Origin": {"https://app.test"}})
	if err != nil {
		if resp != nil {
			t.Logf("response headers: %v", resp.Header)
		}
		t.Fatalf("dial through the proxy: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("connect status %d", resp.StatusCode)
	}
	hdr := <-seen
	if hdr.Get("X-Tenant") != "acme" || hdr.Get("Origin") != "https://app.test" || hdr.Get("X-Request-Id") == "" || hdr.Get("X-Forwarded-For") == "" {
		t.Fatalf("upstream headers: %v", hdr)
	}
	// Bidirectional stream.
	str, err := sess.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = str.Write([]byte("ping"))
	_ = str.Close()
	if b, _ := io.ReadAll(str); string(b) != "echo:ping" {
		t.Fatalf("stream echo %q", b)
	}
	// Unidirectional both ways.
	uni, err := sess.OpenUniStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = uni.Write([]byte("one-way"))
	_ = uni.Close()
	in, err := sess.AcceptUniStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := io.ReadAll(in); string(b) != "uni:one-way" {
		t.Fatalf("uni echo %q", b)
	}
	// Datagram.
	if err := sess.SendDatagram([]byte("dg")); err != nil {
		t.Fatal(err)
	}
	if dg, err := sess.ReceiveDatagram(ctx); err != nil || string(dg) != "dgram:dg" {
		t.Fatalf("datagram %q %v", dg, err)
	}
	_ = sess.CloseWithError(0, "done")
	if s.Stats().WebTransportSessions != 1 {
		t.Fatalf("sessions %d", s.Stats().WebTransportSessions)
	}
	// A route without webtransport refuses the session.
	d2 := &webtransport.Transport{TLSClientConfig: d.TLSClientConfig, QUICConfig: d.QUICConfig}
	defer d2.Close()
	if _, _, err := d2.Dial(ctx, "https://"+udp+"/closed", nil); err == nil {
		t.Fatal("session on a route without webtransport accepted")
	}
	// The CONNECT passes the route's controls like any request: a route
	// that denies every client refuses the session (it used to be relayed
	// right after route matching, before ACLs, limits and filters).
	d3 := &webtransport.Transport{TLSClientConfig: d.TLSClientConfig, QUICConfig: d.QUICConfig}
	defer d3.Close()
	if resp, _, err := d3.Dial(ctx, "https://"+udp+"/denied", nil); err == nil {
		t.Fatal("session on a route that denies every client accepted")
	} else if resp != nil && resp.StatusCode != 403 {
		t.Fatalf("denied route answered %d", resp.StatusCode)
	}
	if s.Stats().WebTransportSessions != 1 {
		t.Fatalf("sessions after refused dials: %d", s.Stats().WebTransportSessions)
	}
}
