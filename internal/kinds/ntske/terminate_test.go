package ntske_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/logging"

	_ "github.com/rom/xproxy/internal/kinds/ntske"
	ke "github.com/rom/xproxy/internal/ntske"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
	"github.com/rom/xproxy/internal/testutil"
)

const terminatingYAML = `
version: 1
server:
  listeners:
    - name: ke
      address: "127.0.0.1:0"
      kind: ntske
      tls: {certificates: [{cert_file: %q, key_file: %q}]}
      ntske:
        allow_clients: ["127.0.0.0/8"]
        log_sessions: true
        terminate:
%s
logging: {access: {enabled: false}}
`

// terminating starts a listener that answers key establishment itself.
func terminating(t *testing.T, cert, key, terminate string) (*proxy.Server, string) {
	t.Helper()
	s := proxytest.Start(t, fmt.Sprintf(terminatingYAML, cert, key, terminate))
	return s, proxytest.Addr(t, s, "ke")
}

// establish is a whole key establishment as a client does it: the handshake
// with the application protocol, the request, and the response.
func establish(t *testing.T, addr, cert, name string, q *ke.Request) (*ke.Response, *ke.Keys, error) {
	t.Helper()
	cfg := clientConfig(t, cert, name, "ntske/1")
	c, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: %w", err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write(q.AppendTo(nil)); err != nil {
		return nil, nil, err
	}
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 1024)
	for {
		n, rerr := c.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if n > 0 {
			resp, perr := ke.ParseResponse(buf)
			if perr == nil {
				// The client derives the same two keys from its own end of the
				// same TLS connection. Nothing about them crossed the wire.
				keys, err := ke.DeriveFromTLS(c, resp.NextProtocol, resp.AEAD)
				if err != nil {
					return nil, nil, err
				}
				return resp, keys, nil
			}
			if !errors.Is(perr, ke.ErrTruncated) && !errors.Is(perr, ke.ErrNoEnd) {
				return nil, nil, perr
			}
		}
		if rerr != nil {
			return nil, nil, rerr
		}
	}
}

// The whole point of terminating: the cookies the client is handed carry the
// keys the client derived, sealed under a key only this relay holds. The time
// listener beside it can open one; nobody else can.
func TestTerminatingIssuesCookiesForTheDerivedKeys(t *testing.T) {
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "ke.test")
	s, addr := terminating(t, cert, key, `          server: time.test
          port: 123`)

	resp, keys, err := establish(t, addr, cert, "ke.test", ke.ClientRequest())
	if err != nil {
		t.Fatal(err)
	}
	if resp.NextProtocol != ke.NextProtoNTPv4 || resp.AEAD != ke.AEADAESSIVCMAC256 {
		t.Fatalf("terms %d/%d", resp.NextProtocol, resp.AEAD)
	}
	if len(resp.Cookies) != 8 {
		t.Fatalf("%d cookies, want 8", len(resp.Cookies))
	}
	if resp.Server != "time.test" || !resp.HasPort || resp.Port != 123 {
		t.Errorf("the client was sent to %q port %d", resp.Server, resp.Port)
	}
	holder := s.NTSCookieKeys("ke")
	if holder == nil {
		t.Fatal("the listener holds no cookie keys, so the time listener could open nothing")
	}
	for i, cookie := range resp.Cookies {
		aead, got, err := holder.Open(cookie)
		if err != nil {
			t.Fatalf("cookie %d does not open: %v", i, err)
		}
		if aead != ke.AEADAESSIVCMAC256 {
			t.Errorf("cookie %d names algorithm %d", i, aead)
		}
		if !bytes.Equal(got.C2S, keys.C2S) || !bytes.Equal(got.S2C, keys.S2C) {
			t.Fatalf("cookie %d carries keys the client did not derive", i)
		}
		// Every cookie is different, so holding several does not make a client
		// followable from one exchange to the next.
		for j := 0; j < i; j++ {
			if bytes.Equal(cookie, resp.Cookies[j]) {
				t.Errorf("cookies %d and %d are identical", i, j)
			}
		}
	}
	// Nothing about the session keys is on the wire.
	for _, cookie := range resp.Cookies {
		if bytes.Contains(cookie, keys.C2S) || bytes.Contains(cookie, keys.S2C) {
			t.Fatal("a cookie carries a session key in the clear")
		}
	}
	sn := s.Stats()
	if sn.NTSKETerminated != 1 || sn.NTSKECookies != 8 {
		t.Errorf("counters: terminated %d cookies %d", sn.NTSKETerminated, sn.NTSKECookies)
	}
	if sn.NTSKERelayed != 0 {
		t.Errorf("a terminating listener relayed %d sessions", sn.NTSKERelayed)
	}
}

// A listener with nothing to say about where to spend the cookies says nothing,
// because a record repeating the address the client already used is one the
// client has to compare rather than ignore.
func TestTerminatingSaysNothingItDoesNotHaveToSay(t *testing.T) {
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "ke.test")
	_, addr := terminating(t, cert, key, `          cookies: 2`)
	resp, _, err := establish(t, addr, cert, "ke.test", ke.ClientRequest())
	if err != nil {
		t.Fatal(err)
	}
	if resp.Server != "" || resp.HasPort {
		t.Errorf("the response redirects to %q port %d", resp.Server, resp.Port)
	}
	if len(resp.Cookies) != 2 {
		t.Errorf("%d cookies, want the 2 configured", len(resp.Cookies))
	}
}

// A client that offers an algorithm this relay cannot seal a cookie with is not
// refused with an error: the request was fine, the terms are not available, and
// those are different things to tell a client.
func TestTerminatingRefusesTermsItCannotMeet(t *testing.T) {
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "ke.test")
	s, addr := terminating(t, cert, key, `          cookies: 8`)

	for _, tc := range []struct {
		name string
		q    *ke.Request
	}{
		{"an algorithm this relay does not have", &ke.Request{
			NextProtocols: []uint16{ke.NextProtoNTPv4}, AEADs: []uint16{16, 17}}},
		{"a protocol this relay does not speak", &ke.Request{
			NextProtocols: []uint16{7}, AEADs: []uint16{ke.AEADAESSIVCMAC256}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := establish(t, addr, cert, "ke.test", tc.q)
			if !errors.Is(err, ke.ErrNoTerms) {
				t.Fatalf("got %v, want %v", err, ke.ErrNoTerms)
			}
		})
	}
	if got := s.Stats().NTSKENoTerms; got != 2 {
		t.Errorf("no-terms counter: %d", got)
	}
	if got := s.Stats().Refusals["ntske"]["no_terms"]; got != 2 {
		t.Errorf("refusals: %+v", s.Stats().Refusals["ntske"])
	}
}

// A critical record this implementation does not know is refused with the code
// the standard has for exactly that, rather than with "bad request": the client
// sent something well formed that this server cannot honour, and it is the
// difference between an extension not supported and a client with a bug.
func TestTerminatingAnswersABadRequestWithTheRightCode(t *testing.T) {
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "ke.test")
	s, addr := terminating(t, cert, key, `          cookies: 8`)

	for _, tc := range []struct {
		name    string
		msg     []byte
		want    uint16
		refusal string
	}{
		{
			"an unknown critical record",
			func() []byte {
				var out []byte
				out = ke.Record{Critical: true, Type: ke.RecNextProtocol,
					Body: []byte{0, 0}}.AppendTo(out)
				out = ke.Record{Critical: true, Type: ke.RecAEADAlgorithm,
					Body: []byte{0, 15}}.AppendTo(out)
				out = ke.Record{Critical: true, Type: 900, Body: []byte("?")}.AppendTo(out)
				return ke.Record{Critical: true, Type: ke.RecEndOfMessage}.AppendTo(out)
			}(),
			ke.ErrUnrecognisedCritical,
			"unknown_critical_record",
		},
		{
			"a request that offers nothing",
			ke.Record{Critical: true, Type: ke.RecEndOfMessage}.AppendTo(nil),
			ke.ErrBadRequest,
			"bad_request",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := tls.Dial("tcp", addr, clientConfig(t, cert, "ke.test", "ntske/1"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			if _, err := c.Write(tc.msg); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 256)
			n, err := c.Read(buf)
			if err != nil && n == 0 {
				t.Fatalf("no answer: %v", err)
			}
			_, perr := ke.ParseResponse(buf[:n])
			var kerr *ke.KEError
			if !errors.As(perr, &kerr) {
				t.Fatalf("the answer was %v", perr)
			}
			if kerr.Code != tc.want {
				t.Errorf("error code %d, want %d", kerr.Code, tc.want)
			}
			// Polled rather than read once: the answer is written before the
			// refusal is counted, so a client that read its error has not
			// waited for the counter. The first failure of this assertion
			// printed a map that already held the count it had just found
			// missing.
			for deadline := time.Now().Add(10 * time.Second); ; {
				if s.Stats().Refusals["ntske"][tc.refusal] != 0 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("refusals: %+v", s.Stats().Refusals["ntske"])
				}
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
}

// A client that completes the handshake and says nothing is holding a handshake
// slot, which is the expensive thing this port has. It is closed and counted.
func TestTerminatingClosesAClientThatSaysNothing(t *testing.T) {
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "ke.test")
	s, addr := terminating(t, cert, key, `          cookies: 8
          rotate_every: 1h`)

	c, err := tls.Dial("tcp", addr, clientConfig(t, cert, "ke.test", "ntske/1"))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if n, err := c.Read(buf); err == nil && n > 0 {
		t.Fatalf("a silent client was answered with %q", buf[:n])
	}
	_ = c.Close()
	for deadline := time.Now().Add(10 * time.Second); ; {
		if s.Stats().Refusals["ntske"]["no_request"] == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("refusals: %+v", s.Stats().Refusals["ntske"])
		}
		time.Sleep(10 * time.Millisecond)
	}
	if s.Stats().NTSKEHandshakes != 0 {
		t.Errorf("the handshake slot was not released: %d", s.Stats().NTSKEHandshakes)
	}
}

// The name list applies to the terminating side too, and there it means more
// than on the relaying side: the name was one the client verified a certificate
// for, rather than one read out of a ClientHello anybody could have written.
func TestTerminatingAppliesTheNameList(t *testing.T) {
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "ke.test")
	s := proxytest.Start(t, fmt.Sprintf(`
version: 1
server:
  listeners:
    - name: ke
      address: "127.0.0.1:0"
      kind: ntske
      tls: {certificates: [{cert_file: %q, key_file: %q}]}
      ntske:
        server_names: ["other.test"]
        terminate: {cookies: 1}
logging: {access: {enabled: false}}
`, cert, key))
	addr := proxytest.Addr(t, s, "ke")
	// The exchange itself completes -- the name is checked after it, because
	// the certificate is what makes the name worth checking -- and the refusal
	// is recorded.
	if _, _, err := establish(t, addr, cert, "ke.test", ke.ClientRequest()); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(10 * time.Second); ; {
		if s.Stats().Refusals["ntske"]["server_name_not_allowed"] == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("refusals: %+v", s.Stats().Refusals["ntske"])
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The cookie keys are written at the first start, not at the first rotation. A
// restart before then would otherwise refuse every cookie already issued, which
// is what the state file exists to prevent -- and the first day is when it would
// happen.
func TestTerminatingWritesItsKeysAtOnce(t *testing.T) {
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "ke.test")
	state := filepath.Join(dir, "cookies.json")
	s, addr := terminating(t, cert, key, fmt.Sprintf(`          cookies: 1
          state: %q`, state))
	resp, _, err := establish(t, addr, cert, "ke.test", ke.ClientRequest())
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(state)
	if err != nil {
		t.Fatalf("the state file was not written: %v", err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("the state file is mode %v", fi.Mode().Perm())
	}
	// And the set in that file is the set that sealed the cookie, which is what
	// makes a restart survivable.
	restored, err := ke.NewCookieKeys(2)
	if err != nil {
		t.Fatal(err)
	}
	if err := restored.Load(state); err != nil {
		t.Fatal(err)
	}
	if _, _, err := restored.Open(resp.Cookies[0]); err != nil {
		t.Fatalf("a cookie issued before the restart does not open after it: %v", err)
	}
	_ = s
}

// A state file that is there and wrong stops the listener rather than being
// ignored: carrying on with fresh keys would do the thing the file exists to
// prevent, quietly, and an operator who moved a file would never find out.
func TestTerminatingRefusesABrokenStateFile(t *testing.T) {
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "ke.test")
	state := filepath.Join(dir, "cookies.json")
	if err := os.WriteFile(state, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	yaml := fmt.Sprintf(terminatingYAML, cert, key,
		fmt.Sprintf("          state: %q", state))
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	srv, err := proxy.New(cfg, logging.Discard())
	if err == nil {
		err = srv.Start()
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = srv.Shutdown(ctx)
			t.Fatal("the listener started on a state file it could not read")
		}
	}
	if !errors.Is(err, ke.ErrState) {
		t.Fatalf("got %v, want %v", err, ke.ErrState)
	}
}

// The application protocol is not negotiable on this port. A client that offers
// another one does not get a handshake at all, and one that offers none is not
// an NTS client whatever else it is.
func TestTerminatingInsistsOnTheApplicationProtocol(t *testing.T) {
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "ke.test")
	s, addr := terminating(t, cert, key, `          cookies: 1`)

	if c, err := tls.Dial("tcp", addr, clientConfig(t, cert, "ke.test", "h2")); err == nil {
		_ = c.Close()
		t.Fatal("a client offering another application protocol completed the handshake")
	}
	c, err := tls.Dial("tcp", addr, clientConfig(t, cert, "ke.test"))
	if err != nil {
		// Some stacks refuse a client that names nothing at the handshake; that
		// is the same refusal one step earlier.
		t.Logf("a client naming no application protocol did not handshake: %v", err)
	} else {
		defer func() { _ = c.Close() }()
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := c.Write(ke.ClientRequest().AppendTo(nil)); err == nil {
			buf := make([]byte, 64)
			if n, err := c.Read(buf); err == nil && n > 0 {
				t.Fatalf("a client naming no application protocol was answered with %q", buf[:n])
			}
		}
	}
	for deadline := time.Now().Add(10 * time.Second); ; {
		if s.Stats().NTSKENotNTS > 0 || s.Stats().Refusals["ntske"]["handshake_failed"] > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("nothing was counted: %+v", s.Stats().Refusals["ntske"])
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A request that arrives in pieces is one request. A server that answered the
// first piece would be agreeing to terms nobody had finished proposing.
func TestTerminatingWaitsForTheWholeRequest(t *testing.T) {
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "ke.test")
	_, addr := terminating(t, cert, key, `          cookies: 4`)

	c, err := tls.Dial("tcp", addr, clientConfig(t, cert, "ke.test", "ntske/1"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	msg := ke.ClientRequest().AppendTo(nil)
	// The first record and nothing else: well formed as far as it goes, and not
	// a message.
	if _, err := c.Write(msg[:8]); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 512)
	if n, err := c.Read(buf); err == nil && n > 0 {
		t.Fatalf("half a request was answered with %q", buf[:n])
	}
	_ = c.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := c.Write(msg[8:]); err != nil {
		t.Fatal(err)
	}
	// And now the whole of it is there, so the exchange completes.
	whole := make([]byte, 0, 4096)
	for {
		n, rerr := c.Read(buf)
		whole = append(whole, buf[:n]...)
		if n > 0 {
			resp, perr := ke.ParseResponse(whole)
			if perr == nil {
				if len(resp.Cookies) != 4 {
					t.Fatalf("%d cookies", len(resp.Cookies))
				}
				return
			}
			if !errors.Is(perr, ke.ErrTruncated) && !errors.Is(perr, ke.ErrNoEnd) {
				t.Fatal(perr)
			}
		}
		if rerr != nil {
			t.Fatalf("the rest of the request was not answered: %v", rerr)
		}
	}
}
