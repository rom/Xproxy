package ntp_test

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/rom/xproxy/internal/kinds/ntske"
	wire "github.com/rom/xproxy/internal/ntp"
	ke "github.com/rom/xproxy/internal/ntske"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	"github.com/rom/xproxy/internal/testutil"
)

// A time source that speaks NTS itself, so that the relay's own association with
// it can be exercised: a key establishment server on TCP and a time server on
// UDP, sharing one cookie key set the way the two halves of a real NTS server do.
//
// This is the other end of re-origination. The relay terminates the client's NTS
// and starts its own toward this, and what has to be true is that neither
// association's keys are the other's and that both ends verify.
type ntsSource struct {
	keys *ke.CookieKeys
	ln   net.Listener
	pc   *net.UDPConn
	cert string

	verified, unverified atomic.Int64
	// The shape of its answers, for the cases where a source is wrong.
	noCookies bool
	wrongID   bool
	noAuth    bool
}

func startNTSSource(t *testing.T, s *ntsSource) *ntsSource {
	t.Helper()
	dir := t.TempDir()
	certPath, keyPath := testutil.WriteCert(t, dir, "source.test")
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	s.cert = certPath
	if s.keys, err = ke.NewCookieKeys(1); err != nil {
		t.Fatal(err)
	}
	s.ln, err = tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{pair},
		NextProtos:   []string{ke.ALPN},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	s.pc, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.ln.Close(); _ = s.pc.Close() })
	go s.serveKE()
	go s.serveTime()
	return s
}

func (s *ntsSource) keAddr() string   { return s.ln.Addr().String() }
func (s *ntsSource) timeAddr() string { return s.pc.LocalAddr().String() }

// serveKE hands out cookies, the way the relay's own key establishment listener
// does for its clients.
func (s *ntsSource) serveKE() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = c.Close() }()
			tc, ok := c.(*tls.Conn)
			if !ok {
				return
			}
			_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
			if err := tc.Handshake(); err != nil {
				return
			}
			buf := make([]byte, 0, 1024)
			tmp := make([]byte, 512)
			var q *ke.Request
			for q == nil {
				n, rerr := tc.Read(tmp)
				buf = append(buf, tmp[:n]...)
				if n > 0 {
					got, perr := ke.ParseRequest(buf)
					switch {
					case perr == nil:
						q = got
					case errors.Is(perr, ke.ErrTruncated), errors.Is(perr, ke.ErrNoEnd):
					default:
						return
					}
				}
				if rerr != nil && q == nil {
					return
				}
			}
			proto, aead, ok := ke.Negotiate(q)
			if !ok {
				_, _ = tc.Write(ke.NoTermsMessage())
				return
			}
			keys, err := ke.DeriveFromTLS(tc, proto, aead)
			if err != nil {
				return
			}
			resp := &ke.Response{NextProtocol: proto, AEAD: aead}
			for i := 0; i < ke.CookiesPerResponse; i++ {
				cookie, err := s.keys.Seal(aead, keys)
				if err != nil {
					return
				}
				resp.Cookies = append(resp.Cookies, cookie)
			}
			_, _ = tc.Write(resp.AppendTo(nil))
		}()
	}
}

// serveTime verifies each request and answers with an authenticator of its own.
func (s *ntsSource) serveTime() {
	buf := make([]byte, 2048)
	for {
		n, from, err := s.pc.ReadFromUDP(buf)
		if err != nil {
			return
		}
		raw := append([]byte(nil), buf[:n]...)
		pkt, err := wire.Parse(raw)
		if err != nil {
			continue
		}
		cookies := wire.NTSCookies(pkt.Extensions)
		if len(cookies) == 0 {
			s.unverified.Add(1)
			continue
		}
		aead, keys, err := s.keys.Open(cookies[0])
		if err != nil {
			s.unverified.Add(1)
			continue
		}
		if _, err := pkt.OpenNTS(keys.C2S); err != nil {
			s.unverified.Add(1)
			continue
		}
		s.verified.Add(1)
		out, err := s.answer(pkt, aead, keys)
		if err != nil {
			continue
		}
		_, _ = s.pc.WriteToUDP(out, from)
	}
}

func (s *ntsSource) answer(req *wire.Packet, aead uint16, keys *ke.Keys) ([]byte, error) {
	now := time.Now()
	p := &wire.Packet{
		Version: req.Version, Mode: wire.ModeServer, Stratum: 1, Poll: req.Poll, Precision: -20,
		Reference: wire.TimestampOf(now.Add(-time.Minute)), Origin: req.Transmit,
		Receive: wire.TimestampOf(now), Transmit: wire.TimestampOf(now.Add(time.Millisecond)),
	}
	copy(p.ReferenceID[:], "GPS")
	uid := req.NTS().UniqueID
	if s.wrongID {
		uid = make([]byte, len(uid))
	}
	if len(uid) > 0 {
		p.Extensions = append(p.Extensions, wire.Extension{Type: wire.EFUniqueIdentifier, Body: uid})
	}
	if s.noAuth {
		return p.Bytes(), nil
	}
	var inner []wire.Extension
	if !s.noCookies {
		want := 1 + req.NTS().Placeholders
		for i := 0; i < want; i++ {
			cookie, err := s.keys.Seal(aead, keys)
			if err != nil {
				return nil, err
			}
			inner = append(inner, wire.NTSCookieField(cookie))
		}
	}
	return wire.SealNTS(p.Bytes(), keys.S2C, inner)
}

const sourceYAML = `
version: 1
server:
  listeners:
    - name: ke
      address: "127.0.0.1:0"
      kind: ntske
      tls: {certificates: [{cert_file: %q, key_file: %q}]}
      ntske:
        allow_clients: ["127.0.0.0/8"]
        terminate: {cookies: 8}
    - name: time
      address: "127.0.0.1:0"
      kind: ntp
      ntp:
        upstream: clocks
        versions: [4]
        nts:
          mode: terminate
          key_listener: ke
          source:
            ke_address: %q
            server_name: source.test
            ca_file: %q
%s
logging: {access: {enabled: false}}
upstreams:
  - name: clocks
    endpoints: [{address: %q}]
`

// sourceServer starts the relay with both halves and an NTS-speaking source.
func sourceServer(t *testing.T, extra string, src *ntsSource, keAddress string) (*proxy.Server, string, string) {
	t.Helper()
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "ke.test")
	ca := src.cert
	if keAddress == "" {
		keAddress = src.keAddr()
	}
	srv := proxytest.Start(t, fmt.Sprintf(sourceYAML, cert, key, keAddress, ca, extra, src.timeAddr()))
	t.Setenv("XPROXY_TEST_KE_CERT", cert)
	return srv, proxytest.Addr(t, srv, "ke"), proxytest.Addr(t, srv, "time")
}

func waitFor(t *testing.T, what string, f func() bool) {
	t.Helper()
	for deadline := time.Now().Add(15 * time.Second); ; {
		if f() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Two associations in series, and neither one's keys are the other's: the client
// authenticates to the relay, the relay authenticates to the source, and both
// ends verify what they are sent.
func TestNTSIsReOriginatedTowardTheSource(t *testing.T) {
	src := startNTSSource(t, &ntsSource{})
	s, keAddr, timeAddr := sourceServer(t, "", src, "")
	waitFor(t, "keys with the source", func() bool {
		return s.Stats().NTPNTSSourceEstablished > 0
	})

	cookies, keys := establishKE(t, keAddr)
	raw, uid := ntsAsk(t, cookies[0], 1, keys.C2S)
	c := dialNTP(t, timeAddr)
	c.raw(raw)
	got, _, err := c.read(5 * time.Second)
	if err != nil {
		t.Fatalf("no answer: %v", err)
	}

	// The source saw an authenticated request and verified it.
	if src.verified.Load() == 0 {
		t.Fatal("the source never verified a request from the relay")
	}
	if src.unverified.Load() != 0 {
		t.Fatalf("the source refused %d requests", src.unverified.Load())
	}
	// The client's answer verifies under the client's own key, and the client's
	// cookies are not the relay's.
	inner, err := got.OpenNTS(keys.S2C)
	if err != nil {
		t.Fatalf("the client's answer did not verify: %v", err)
	}
	if !bytes.Equal(got.NTS().UniqueID, uid) {
		t.Error("the answer does not carry the identifier the client sent")
	}
	fresh := wire.NTSCookies(inner)
	if len(fresh) != 2 {
		t.Fatalf("%d replacement cookies for a cookie and a placeholder", len(fresh))
	}
	for _, cookie := range fresh {
		if _, _, err := src.keys.Open(cookie); err == nil {
			t.Fatal("a cookie the client was given opens with the source's keys, so the two associations share keys")
		}
	}
	sn := s.Stats()
	if sn.NTPNTSSourceVerified == 0 || sn.NTPNTSVerified == 0 {
		t.Errorf("source verified %d, client verified %d", sn.NTPNTSSourceVerified, sn.NTPNTSVerified)
	}
	if sn.NTPNTSSourceUnverified != 0 {
		t.Errorf("the relay refused %d answers", sn.NTPNTSSourceUnverified)
	}
}

// A plain client behind a relay that authenticates its own requests gets a plain
// answer. The source's NTS fields are the relay's conversation with the source,
// and they carry the relay's own replacement cookies.
func TestAPlainClientGetsNoneOfTheRelaysNTS(t *testing.T) {
	src := startNTSSource(t, &ntsSource{})
	s, _, timeAddr := sourceServer(t, "", src, "")
	waitFor(t, "keys with the source", func() bool {
		return s.Stats().NTPNTSSourceEstablished > 0
	})
	c := dialNTP(t, timeAddr)
	got, raw := c.ask(request(4, wire.ModeClient))
	if got.NTS().Present {
		t.Fatal("a plain client was handed the relay's NTS fields")
	}
	if len(raw) != wire.HeaderLen {
		t.Fatalf("a plain client got %d octets, want a bare header", len(raw))
	}
	if src.verified.Load() == 0 {
		t.Fatal("the relay's own request to the source was not authenticated")
	}
}

// An answer from the source that does not verify is not an answer. The reasons
// are separate because they are different failures: one is a packet that was
// tampered with, the other is an answer to a different question.
func TestTheRelayRefusesASourceAnswerItCannotVerify(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  *ntsSource
	}{
		{"an answer with no authenticator", &ntsSource{noAuth: true}},
		{"an answer echoing another identifier", &ntsSource{wrongID: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := startNTSSource(t, tc.src)
			s, keAddr, timeAddr := sourceServer(t, "", src, "")
			waitFor(t, "keys with the source", func() bool {
				return s.Stats().NTPNTSSourceEstablished > 0
			})
			cookies, keys := establishKE(t, keAddr)
			raw, _ := ntsAsk(t, cookies[0], 0, keys.C2S)
			c := dialNTP(t, timeAddr)
			c.raw(raw)
			c.expectSilence("an answer the relay could not verify")
			waitFor(t, "the refusal", func() bool {
				return s.Stats().Refusals["ntp"]["nts_source_unverified"] > 0
			})
			if s.Stats().NTPNTSSourceUnverified == 0 {
				t.Error("the counter did not move")
			}
		})
	}
}

// A source whose key establishment cannot be reached is a source this relay
// cannot ask for the time. The request is dropped rather than sent in plain NTP:
// a relay that quietly downgraded its own request would be doing the thing this
// configuration exists to prevent.
func TestARequestBeforeTheRelayHasKeysIsDropped(t *testing.T) {
	src := startNTSSource(t, &ntsSource{})
	// A key establishment address nothing is listening on.
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := dead.Addr().String()
	_ = dead.Close()

	s, _, timeAddr := sourceServer(t, "", src, addr)
	c := dialNTP(t, timeAddr)
	c.send(request(4, wire.ModeClient))
	c.expectSilence("a request with no keys for the source")
	waitFor(t, "the refusal", func() bool {
		return s.Stats().Refusals["ntp"]["nts_source_not_ready"] > 0
	})
	waitFor(t, "the failure to be counted", func() bool {
		return s.Stats().NTPNTSSourceFailed > 0
	})
	if s.Stats().NTPNTSSourceEstablished != 0 {
		t.Error("keys were established with a server that is not there")
	}
	// And nothing reached the source in the clear.
	if src.verified.Load() != 0 || src.unverified.Load() != 0 {
		t.Fatalf("the source saw %d verified and %d unverified requests",
			src.verified.Load(), src.unverified.Load())
	}
}

// A source that answers without a replacement cookie is stingy rather than
// wrong: the answer is still verified and passed on, and the pool recovers
// through the placeholders on the next request.
func TestASourceThatSendsNoReplacementCookieIsStillBelieved(t *testing.T) {
	src := startNTSSource(t, &ntsSource{noCookies: true})
	s, keAddr, timeAddr := sourceServer(t, "", src, "")
	waitFor(t, "keys with the source", func() bool {
		return s.Stats().NTPNTSSourceEstablished > 0
	})
	cookies, keys := establishKE(t, keAddr)
	raw, _ := ntsAsk(t, cookies[0], 0, keys.C2S)
	c := dialNTP(t, timeAddr)
	c.raw(raw)
	if _, _, err := c.read(5 * time.Second); err != nil {
		t.Fatalf("no answer: %v", err)
	}
	if s.Stats().NTPNTSSourceVerified == 0 {
		t.Error("the answer was not counted as verified")
	}
	if s.Stats().NTPNTSSourceUnverified != 0 {
		t.Error("an answer with no replacement cookie was refused")
	}
}

// The relay's cookies run down when answers are lost, and the pool is
// re-established rather than exhausted. A relay that ran out would stop asking
// for the time, and nothing about that looks like a key problem from outside.
func TestTheRelayEstablishesKeysAgainWhenTheCookiesRunLow(t *testing.T) {
	src := startNTSSource(t, &ntsSource{noCookies: true})
	s, keAddr, timeAddr := sourceServer(t, `        request_timeout: 1s`, src, "")
	waitFor(t, "keys with the source", func() bool {
		return s.Stats().NTPNTSSourceEstablished > 0
	})
	cookies, keys := establishKE(t, keAddr)
	c := dialNTP(t, timeAddr)
	// Eight exchanges with no replacement cookies spends the pool.
	for i := 0; i < len(cookies); i++ {
		raw, _ := ntsAsk(t, cookies[i], 0, keys.C2S)
		c.raw(raw)
		_, _, _ = c.read(2 * time.Second)
	}
	waitFor(t, "a second key establishment", func() bool {
		return s.Stats().NTPNTSSourceEstablished > 1
	})
}

// The state file and the certificate paths are the estate's, so a configuration
// naming one that is not there does not load.
func TestTheSourceConfigurationIsChecked(t *testing.T) {
	src := startNTSSource(t, &ntsSource{})
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "ke.test")
	yaml := fmt.Sprintf(sourceYAML, cert, key, src.keAddr(),
		filepath.Join(dir, "absent-ca.pem"), "", src.timeAddr())
	if _, err := proxytest.TryStart(yaml); err == nil {
		t.Fatal("a configuration naming a certificate authority that is not there loaded")
	}
	// And one whose file is there but holds no certificate is refused at start.
	empty := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(empty, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	yaml = fmt.Sprintf(sourceYAML, cert, key, src.keAddr(), empty, "", src.timeAddr())
	srv, err := proxytest.TryStart(yaml)
	if err == nil {
		err = srv.Start()
	}
	if err == nil {
		t.Fatal("a certificate authority file with no certificates in it started")
	}
}
