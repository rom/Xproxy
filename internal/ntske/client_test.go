package ntske

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/testutil"
)

// keServer is a key establishment server built from this package's own server
// half, so that the client half is tested against the thing it will meet rather
// than against a recording of it.
type keServer struct {
	ln    net.Listener
	keys  *CookieKeys
	reply func(*Request, *Keys) []byte
	alpn  []string
	// roots is the certificate a client has to trust to reach this server.
	roots *x509.CertPool
}

func startKE(t *testing.T, s *keServer) *keServer {
	t.Helper()
	dir := t.TempDir()
	certPath, keyPath := testutil.WriteCert(t, dir, "ke.test")
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	pem, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("the certificate did not load")
	}
	s.roots = pool
	if s.alpn == nil {
		s.alpn = []string{ALPN}
	}
	if s.keys == nil {
		if s.keys, err = NewCookieKeys(1); err != nil {
			t.Fatal(err)
		}
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{pair},
		NextProtos:   s.alpn,
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	s.ln = ln
	t.Cleanup(func() { _ = ln.Close() })
	go s.serve()
	return s
}

func (s *keServer) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.one(c)
	}
}

func (s *keServer) one(c net.Conn) {
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
	var q *Request
	for q == nil {
		n, rerr := tc.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if n > 0 {
			got, perr := ParseRequest(buf)
			switch {
			case perr == nil:
				q = got
			case errors.Is(perr, ErrTruncated), errors.Is(perr, ErrNoEnd):
			default:
				_, _ = tc.Write(ErrorMessage(ErrBadRequest))
				return
			}
		}
		if rerr != nil && q == nil {
			return
		}
	}
	proto, aead, ok := Negotiate(q)
	if !ok {
		_, _ = tc.Write(NoTermsMessage())
		return
	}
	keys, err := DeriveFromTLS(tc, proto, aead)
	if err != nil {
		_, _ = tc.Write(ErrorMessage(ErrInternalServer))
		return
	}
	if s.reply != nil {
		_, _ = tc.Write(s.reply(q, keys))
		return
	}
	resp := &Response{NextProtocol: proto, AEAD: aead}
	for i := 0; i < CookiesPerResponse; i++ {
		cookie, err := s.keys.Seal(aead, keys)
		if err != nil {
			return
		}
		resp.Cookies = append(resp.Cookies, cookie)
	}
	_, _ = tc.Write(resp.AppendTo(nil))
}

func (s *keServer) client(t *testing.T) *Client {
	t.Helper()
	return &Client{Address: s.ln.Addr().String(), Timeout: 10 * time.Second,
		TLS: &tls.Config{RootCAs: s.roots, ServerName: "ke.test", MinVersion: tls.VersionTLS13}}
}

// The two halves meet: what the server issues is what the client establishes,
// and the keys are the ones both ends derived from the same TLS connection
// without either sending them.
func TestTheClientEstablishesKeysAndCookies(t *testing.T) {
	s := startKE(t, &keServer{})
	got, err := s.client(t).Establish(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.AEAD != AEADAESSIVCMAC256 {
		t.Errorf("algorithm %d", got.AEAD)
	}
	if len(got.Cookies) != CookiesPerResponse {
		t.Fatalf("%d cookies", len(got.Cookies))
	}
	if len(got.Keys.C2S) != KeyLen || len(got.Keys.S2C) != KeyLen {
		t.Fatalf("keys of %d and %d octets", len(got.Keys.C2S), len(got.Keys.S2C))
	}
	if bytes.Equal(got.Keys.C2S, got.Keys.S2C) {
		t.Error("the two directions are the same key")
	}
	if got.At.IsZero() {
		t.Error("the exchange is not dated, so a caller cannot tell old cookies from exhausted ones")
	}
	// The server's own view: every cookie opens to the keys the client holds.
	for i, cookie := range got.Cookies {
		aead, keys, err := s.keys.Open(cookie)
		if err != nil {
			t.Fatalf("cookie %d: %v", i, err)
		}
		if aead != got.AEAD || !bytes.Equal(keys.C2S, got.Keys.C2S) || !bytes.Equal(keys.S2C, got.Keys.S2C) {
			t.Fatalf("cookie %d carries other keys", i)
		}
	}
}

// A bare host takes the key establishment port, because that is the port the
// standard assigns and an operator writing a host name means that one.
func TestABareHostTakesTheKeyEstablishmentPort(t *testing.T) {
	c := &Client{Address: "time.example"}
	_, err := c.Establish(context.Background())
	if err == nil {
		t.Fatal("a host that does not exist resolved")
	}
	// The error names where it tried, which is how an operator finds out that
	// the port was assumed.
	if !bytes.Contains([]byte(err.Error()), []byte("time.example:"+DefaultPort)) {
		t.Fatalf("the error does not name the port it tried: %v", err)
	}
}

func TestTheClientRefusesAServerThatIsNotOne(t *testing.T) {
	t.Run("no application protocol", func(t *testing.T) {
		// A TLS server that negotiates nothing is not a key establishment
		// server, whatever else is listening on the port.
		s := startKE(t, &keServer{alpn: []string{}})
		if _, err := s.client(t).Establish(context.Background()); err == nil {
			t.Fatal("a server that negotiated no application protocol was accepted")
		}
	})
	t.Run("an error record", func(t *testing.T) {
		s := startKE(t, &keServer{reply: func(*Request, *Keys) []byte {
			return ErrorMessage(ErrInternalServer)
		}})
		_, err := s.client(t).Establish(context.Background())
		var ke *KEError
		if !errors.As(err, &ke) || ke.Code != ErrInternalServer {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("no terms in common", func(t *testing.T) {
		s := startKE(t, &keServer{reply: func(*Request, *Keys) []byte { return NoTermsMessage() }})
		if _, err := s.client(t).Establish(context.Background()); !errors.Is(err, ErrNoTerms) {
			t.Fatalf("got %v, want %v", err, ErrNoTerms)
		}
	})
	t.Run("terms this relay did not offer", func(t *testing.T) {
		s := startKE(t, &keServer{reply: func(*Request, *Keys) []byte {
			// An algorithm the client cannot seal a cookie with. A client that
			// accepted it would hold keys it could never spend.
			r := &Response{NextProtocol: NextProtoNTPv4, AEAD: 30, Cookies: [][]byte{[]byte("c")}}
			return r.AppendTo(nil)
		}})
		if _, err := s.client(t).Establish(context.Background()); !errors.Is(err, ErrRequest) {
			t.Fatalf("got %v, want %v", err, ErrRequest)
		}
	})
	t.Run("no cookies", func(t *testing.T) {
		s := startKE(t, &keServer{reply: func(*Request, *Keys) []byte {
			r := &Response{NextProtocol: NextProtoNTPv4, AEAD: AEADAESSIVCMAC256}
			return r.AppendTo(nil)
		}})
		if _, err := s.client(t).Establish(context.Background()); !errors.Is(err, ErrRequest) {
			t.Fatalf("got %v, want %v", err, ErrRequest)
		}
	})
	t.Run("nothing at all", func(t *testing.T) {
		s := startKE(t, &keServer{reply: func(*Request, *Keys) []byte { return nil }})
		if _, err := s.client(t).Establish(context.Background()); err == nil {
			t.Fatal("a server that said nothing was accepted")
		}
	})
	t.Run("half a message", func(t *testing.T) {
		s := startKE(t, &keServer{reply: func(*Request, *Keys) []byte {
			whole := (&Response{NextProtocol: NextProtoNTPv4, AEAD: AEADAESSIVCMAC256,
				Cookies: [][]byte{[]byte("cookie")}}).AppendTo(nil)
			return whole[:len(whole)-4] // no End of Message
		}})
		if _, err := s.client(t).Establish(context.Background()); !errors.Is(err, ErrTruncated) {
			t.Fatalf("got %v, want %v", err, ErrTruncated)
		}
	})
}

// The certificate is the whole of what a client authenticates, so a server whose
// certificate the client does not trust is a server it does not talk to.
func TestTheClientAuthenticatesTheServer(t *testing.T) {
	s := startKE(t, &keServer{})
	c := s.client(t)
	c.TLS = &tls.Config{ServerName: "ke.test", MinVersion: tls.VersionTLS13} // no roots
	if _, err := c.Establish(context.Background()); err == nil {
		t.Fatal("a server with an untrusted certificate was accepted")
	}
}

// A caller that lowered the minimum version, deliberately or by copying a
// configuration, does not get to: RFC 8915 requires TLS 1.3, and the keys come
// from an exporter earlier versions define differently.
func TestTheClientInsistsOnTLS13(t *testing.T) {
	s := startKE(t, &keServer{})
	c := s.client(t)
	c.TLS.MinVersion = tls.VersionTLS10
	got, err := c.Establish(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Cookies) == 0 {
		t.Fatal("no cookies")
	}
}

func TestEstablishingRefusesWhatItCannotDo(t *testing.T) {
	if _, err := (&Client{}).Establish(context.Background()); err == nil {
		t.Error("established keys with no address")
	}
	// A deadline that has passed is a deadline: the dial does not get a free
	// attempt because the caller's context was already done.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := startKE(t, &keServer{})
	if _, err := s.client(t).Establish(ctx); err == nil {
		t.Error("established keys under a cancelled context")
	}
}
