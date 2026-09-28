package ntp_test

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/rom/xproxy/internal/kinds/ntske"
	wire "github.com/rom/xproxy/internal/ntp"
	ke "github.com/rom/xproxy/internal/ntske"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	"github.com/rom/xproxy/internal/testutil"
)

// Terminating NTS end to end: a key establishment listener that issues the
// cookies, a time listener that opens them, and behind it a time server that
// has never heard of NTS.

const termYAML = `
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
%s
logging: {access: {enabled: false}}
upstreams:
  - name: clocks
    endpoints: [{address: %q}]
`

// termServer starts both halves against one time server.
func termServer(t *testing.T, section string, up *timeServer) (srv *proxy.Server, keAddr, timeAddr string) {
	t.Helper()
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "ke.test")
	srv = proxytest.Start(t, fmt.Sprintf(termYAML, cert, key, section, up.addr()))
	t.Setenv("XPROXY_TEST_KE_CERT", cert)
	return srv, proxytest.Addr(t, srv, "ke"), proxytest.Addr(t, srv, "time")
}

// establishKE is a key establishment as a client does it, over TLS with the
// application protocol, and the keys the client derives from its own end.
func establishKE(t *testing.T, addr string) ([][]byte, *ke.Keys) {
	t.Helper()
	pem, err := os.ReadFile(os.Getenv("XPROXY_TEST_KE_CERT"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("the certificate did not load")
	}
	c, err := tls.Dial("tcp", addr, &tls.Config{
		RootCAs: pool, ServerName: "ke.test",
		NextProtos: []string{"ntske/1"}, MinVersion: tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write(ke.ClientRequest().AppendTo(nil)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 1024)
	for {
		n, rerr := c.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if n > 0 {
			resp, perr := ke.ParseResponse(buf)
			if perr == nil {
				keys, err := ke.DeriveFromTLS(c, resp.NextProtocol, resp.AEAD)
				if err != nil {
					t.Fatal(err)
				}
				return resp.Cookies, keys
			}
			if !errors.Is(perr, ke.ErrTruncated) && !errors.Is(perr, ke.ErrNoEnd) {
				t.Fatal(perr)
			}
		}
		if rerr != nil {
			t.Fatalf("no response: %v", rerr)
		}
	}
}

// ntsAsk builds a protected request: a unique identifier, a cookie, the
// placeholders that ask for replacements, and the authenticator over all of it.
func ntsAsk(t *testing.T, cookie []byte, placeholders int, c2s []byte) (raw, uniqueID []byte) {
	t.Helper()
	uid, err := wire.NTSUniqueIDField()
	if err != nil {
		t.Fatal(err)
	}
	p := request(4, wire.ModeClient)
	p.Extensions = []wire.Extension{uid, wire.NTSCookieField(cookie)}
	for i := 0; i < placeholders; i++ {
		p.Extensions = append(p.Extensions, wire.NTSPlaceholderField(len(cookie)))
	}
	out, err := wire.SealNTS(p.Bytes(), c2s, nil)
	if err != nil {
		t.Fatal(err)
	}
	return out, uid.Body
}

// requestWithTransmit finds what the time server received for one request, by
// the transmit timestamp that is the only thing tying the two together.
func requestWithTransmit(up *timeServer, want wire.Timestamp) ([]byte, bool) {
	raws := up.bytes()
	for _, raw := range raws {
		p, err := wire.Parse(raw)
		if err != nil {
			continue
		}
		if p.Transmit == want {
			return raw, true
		}
	}
	return nil, false
}

// The whole of the mode: the client's request is verified here, the source is
// asked in plain NTP, and the answer the client gets is authenticated with the
// client's own key and carries replacement cookies it can spend next time.
func TestNTSTerminationAuthenticatesTheAnswer(t *testing.T) {
	up := startTimeServer(t, &timeServer{})
	s, keAddr, timeAddr := termServer(t, `        upstream: clocks
        nts: {mode: terminate, key_listener: ke}`, up)

	cookies, keys := establishKE(t, keAddr)
	if len(cookies) != 8 {
		t.Fatalf("%d cookies from key establishment", len(cookies))
	}
	raw, uid := ntsAsk(t, cookies[0], 2, keys.C2S)
	sent, err := wire.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	c := dialNTP(t, timeAddr)
	c.raw(raw)
	got, _, err := c.read(3 * time.Second)
	if err != nil {
		t.Fatalf("no answer: %v", err)
	}

	// The source was asked in plain NTP: a header and nothing else. It has
	// never heard of NTS, which is the point of this mode.
	upRaw, ok := requestWithTransmit(up, sent.Transmit)
	if !ok {
		t.Fatal("the source never saw the request")
	}
	if len(upRaw) != wire.HeaderLen {
		t.Fatalf("the source was sent %d octets, want a bare header of %d", len(upRaw), wire.HeaderLen)
	}

	// The answer is the client's: its own identifier, and an authenticator only
	// the holder of its server-to-client key could have made.
	fields := got.NTS()
	if !bytes.Equal(fields.UniqueID, uid) {
		t.Error("the answer does not carry the identifier the request did")
	}
	if !fields.Authenticator {
		t.Fatal("the answer carries no authenticator")
	}
	inner, err := got.OpenNTS(keys.S2C)
	if err != nil {
		t.Fatalf("the answer did not verify under the client's key: %v", err)
	}
	// The client-to-server key must not verify it: the two directions are
	// different keys, which is what stops an answer being replayed as a request.
	if _, err := got.OpenNTS(keys.C2S); err == nil {
		t.Error("the answer verified under the request's key too")
	}
	fresh := wire.NTSCookies(inner)
	if len(fresh) != 3 {
		t.Fatalf("%d replacement cookies, want one per cookie and placeholder", len(fresh))
	}
	// Nothing about them was visible on the wire.
	for _, cookie := range fresh {
		if bytes.Contains(got.Raw[:got.MACStart], cookie) {
			t.Error("a replacement cookie is on the wire in the clear")
		}
	}
	// And they are spendable: a second request with a fresh cookie verifies.
	next, _ := ntsAsk(t, fresh[0], 0, keys.C2S)
	c.raw(next)
	if _, _, err := c.read(3 * time.Second); err != nil {
		t.Fatalf("a replacement cookie was not accepted: %v", err)
	}

	sn := s.Stats()
	if sn.NTPNTSVerified != 2 {
		t.Errorf("verified: %d", sn.NTPNTSVerified)
	}
	if sn.NTPNTSCookiesIssued != 4 {
		t.Errorf("cookies issued: %d", sn.NTPNTSCookiesIssued)
	}
	if sn.NTPNTSUnverified != 0 || sn.NTPNTSCookieUnknown != 0 {
		t.Errorf("unverified %d unknown %d", sn.NTPNTSUnverified, sn.NTPNTSCookieUnknown)
	}
}

// The time the client is told is the source's own, octet for octet. A relay that
// adjusted a field of it would be inventing time, and the client would have no
// way to tell.
func TestNTSTerminationDoesNotTouchTheTime(t *testing.T) {
	up := startTimeServer(t, &timeServer{stratum: 3, refid: [4]byte{'G', 'P', 'S', 0}})
	_, keAddr, timeAddr := termServer(t, `        upstream: clocks
        nts: {mode: terminate, key_listener: ke}`, up)

	cookies, keys := establishKE(t, keAddr)
	raw, _ := ntsAsk(t, cookies[0], 0, keys.C2S)
	sent, err := wire.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	c := dialNTP(t, timeAddr)
	c.raw(raw)
	got, gotRaw, err := c.read(3 * time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got.Stratum != 3 || !bytes.Equal(got.ReferenceID[:], []byte{'G', 'P', 'S', 0}) {
		t.Errorf("stratum %d reference id %q", got.Stratum, got.ReferenceID)
	}
	if got.Origin != sent.Transmit {
		t.Error("the answer does not echo the client's transmit timestamp")
	}
	if got.Mode != wire.ModeServer || got.Version != 4 {
		t.Errorf("mode %s version %d", got.Mode, got.Version)
	}
	// The authenticator is appended to the source's header and changes nothing
	// before it: the first forty-eight octets the client sees are the source's
	// own statement about its clock.
	if len(gotRaw) <= wire.HeaderLen {
		t.Fatalf("the answer is %d octets, so it carries no authenticator", len(gotRaw))
	}
	auth, err := got.NTSAuth()
	if err != nil {
		t.Fatal(err)
	}
	if auth.Offset < wire.HeaderLen {
		t.Errorf("the authenticator begins at %d", auth.Offset)
	}
}

// Everything a client can get wrong, and the separate refusals each one
// deserves: they mean different things to an operator, and one counter for all
// of them would say only that NTS is not working.
func TestNTSTerminationRefusals(t *testing.T) {
	up := startTimeServer(t, &timeServer{})
	s, keAddr, timeAddr := termServer(t, `        upstream: clocks
        nts: {mode: terminate, key_listener: ke}`, up)
	cookies, keys := establishKE(t, keAddr)

	t.Run("an authenticator that does not verify", func(t *testing.T) {
		raw, _ := ntsAsk(t, cookies[0], 0, keys.C2S)
		raw[len(raw)-1] ^= 0x01
		c := dialNTP(t, timeAddr)
		c.raw(raw)
		c.expectSilence("a forged authenticator")
		if got := s.Stats().Refusals["ntp"][ntsUnverified]; got == 0 {
			t.Fatalf("refusals: %+v", s.Stats().Refusals["ntp"])
		}
		if s.Stats().NTPNTSUnverified == 0 {
			t.Error("the unverified counter did not move")
		}
	})

	t.Run("a packet altered after it was authenticated", func(t *testing.T) {
		raw, _ := ntsAsk(t, cookies[1], 0, keys.C2S)
		// The stratum, which is in the header and therefore covered.
		raw[1] ^= 0x04
		c := dialNTP(t, timeAddr)
		c.raw(raw)
		c.expectSilence("an altered header")
	})

	t.Run("a cookie this relay never issued", func(t *testing.T) {
		forged := append([]byte(nil), cookies[2]...)
		forged[0] ^= 0xff // another key identifier
		raw, _ := ntsAsk(t, forged, 0, keys.C2S)
		c := dialNTP(t, timeAddr)
		c.raw(raw)
		c.expectSilence("a forged cookie")
		if got := s.Stats().Refusals["ntp"][ntsCookieUnknown]; got == 0 {
			t.Fatalf("refusals: %+v", s.Stats().Refusals["ntp"])
		}
		if s.Stats().NTPNTSCookieUnknown == 0 {
			t.Error("the unknown-cookie counter did not move")
		}
	})

	t.Run("NTS fields with no authenticator", func(t *testing.T) {
		uid, err := wire.NTSUniqueIDField()
		if err != nil {
			t.Fatal(err)
		}
		p := request(4, wire.ModeClient)
		p.Extensions = []wire.Extension{uid, wire.NTSCookieField(cookies[3])}
		c := dialNTP(t, timeAddr)
		c.raw(p.Bytes())
		c.expectSilence("a cookie with no authenticator")
		if got := s.Stats().Refusals["ntp"][ntsNoAuthenticator]; got == 0 {
			t.Fatalf("refusals: %+v", s.Stats().Refusals["ntp"])
		}
	})

	t.Run("an authenticator with no cookie", func(t *testing.T) {
		uid, err := wire.NTSUniqueIDField()
		if err != nil {
			t.Fatal(err)
		}
		p := request(4, wire.ModeClient)
		p.Extensions = []wire.Extension{uid}
		raw, err := wire.SealNTS(p.Bytes(), keys.C2S, nil)
		if err != nil {
			t.Fatal(err)
		}
		c := dialNTP(t, timeAddr)
		c.raw(raw)
		c.expectSilence("an authenticator with nothing to look up keys by")
		if got := s.Stats().Refusals["ntp"][ntsNoCookie]; got == 0 {
			t.Fatalf("refusals: %+v", s.Stats().Refusals["ntp"])
		}
	})
}

// The refusal names, spelled out here so the test is checking the strings an
// operator will read rather than a constant that could change under it.
const (
	ntsUnverified      = "nts_unverified"
	ntsCookieUnknown   = "nts_cookie_unknown"
	ntsNoAuthenticator = "nts_no_authenticator"
	ntsNoCookie        = "nts_no_cookie"
)

// A plain NTP client is still served by a terminating listener: termination is
// about the packets that carry NTS, and an estate that wanted only NTS says so
// with nts.require.
func TestNTSTerminationLeavesPlainClientsAlone(t *testing.T) {
	up := startTimeServer(t, &timeServer{})
	_, _, timeAddr := termServer(t, `        upstream: clocks
        nts: {mode: terminate, key_listener: ke}`, up)
	c := dialNTP(t, timeAddr)
	got, _ := c.ask(request(4, wire.ModeClient))
	if got.Mode != wire.ModeServer {
		t.Fatalf("mode %s", got.Mode)
	}
	if got.NTS().Present {
		t.Error("a plain client was answered with NTS fields")
	}
}

// With require, a plain client is refused and an NTS client is served -- and the
// refusal is the ordinary one, because "this estate is NTS only" is a policy
// about the request rather than about the cryptography.
func TestNTSTerminationWithRequire(t *testing.T) {
	up := startTimeServer(t, &timeServer{})
	s, keAddr, timeAddr := termServer(t, `        upstream: clocks
        nts: {mode: terminate, key_listener: ke, require: true}`, up)
	c := dialNTP(t, timeAddr)
	c.send(request(4, wire.ModeClient))
	c.expectSilence("a plain client on an NTS-only listener")
	if got := s.Stats().Refusals["ntp"]["nts_required"]; got == 0 {
		t.Fatalf("refusals: %+v", s.Stats().Refusals["ntp"])
	}
	cookies, keys := establishKE(t, keAddr)
	raw, _ := ntsAsk(t, cookies[0], 0, keys.C2S)
	c2 := dialNTP(t, timeAddr)
	c2.raw(raw)
	if _, _, err := c2.read(3 * time.Second); err != nil {
		t.Fatalf("an NTS client was not served: %v", err)
	}
}

// A request stuffed with placeholders asks for more cookies than one exchange
// may have. The answer is bounded at eight, which is what keeps this listener
// from being an amplifier: without the bound a small request would buy a large
// answer.
func TestNTSTerminationBoundsTheCookiesItIssues(t *testing.T) {
	up := startTimeServer(t, &timeServer{})
	s, keAddr, timeAddr := termServer(t, `        upstream: clocks
        nts: {mode: terminate, key_listener: ke}
        max_packet_bytes: 4096
        max_extensions: 32`, up)
	cookies, keys := establishKE(t, keAddr)
	raw, _ := ntsAsk(t, cookies[0], 20, keys.C2S)
	c := dialNTP(t, timeAddr)
	c.raw(raw)
	got, _, err := c.read(3 * time.Second)
	if err != nil {
		t.Fatalf("no answer: %v", err)
	}
	inner, err := got.OpenNTS(keys.S2C)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(wire.NTSCookies(inner)); n != wire.MaxNTSCookies {
		t.Fatalf("%d cookies for a request asking for 21, want the bound of %d", n, wire.MaxNTSCookies)
	}
	if s.Stats().NTPNTSCookiesIssued != uint64(wire.MaxNTSCookies) {
		t.Errorf("issued %d", s.Stats().NTPNTSCookiesIssued)
	}
}

// An interleaved answer is matched by the source's own previous transmit
// timestamp rather than by the client's request, so there is no verified session
// to authenticate it with. Handing the client a plain answer would be the
// downgrade this mode exists to prevent, so it is refused.
func TestNTSTerminationRefusesAnAnswerItCannotAuthenticate(t *testing.T) {
	up := startTimeServer(t, &timeServer{interleave: true})
	s, keAddr, timeAddr := termServer(t, `        upstream: clocks
        nts: {mode: terminate, key_listener: ke}`, up)
	cookies, keys := establishKE(t, keAddr)

	// The first exchange sets the source's last transmit timestamp; the second
	// is the one it answers interleaved.
	c := dialNTP(t, timeAddr)
	first, _ := ntsAsk(t, cookies[0], 0, keys.C2S)
	c.raw(first)
	if _, _, err := c.read(3 * time.Second); err != nil {
		t.Fatalf("the first exchange did not complete: %v", err)
	}
	second, _ := ntsAsk(t, cookies[1], 0, keys.C2S)
	c.raw(second)
	c.expectSilence("an interleaved answer to an NTS client")
	if got := s.Stats().Refusals["ntp"]["nts_no_session"]; got != 1 {
		t.Fatalf("refusals: %+v", s.Stats().Refusals["ntp"])
	}
}
