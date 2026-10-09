package forward

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
)

// The two halves of the plain path a request can be refused on after it
// is understood -- a body nobody declared the size of, and a chain the
// client wrote itself -- and the HTTP/2 form of CONNECT, where there is
// no connection to hijack and the stream is the tunnel.

// origin is an HTTP server the proxy can reach, which keeps the headers
// of the last request it was given.
type origin struct {
	*httptest.Server
	got chan http.Header
}

func startOrigin(t *testing.T) *origin {
	t.Helper()
	o := &origin{got: make(chan http.Header, 8)}
	o.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case o.got <- r.Header.Clone():
		default:
		}
		_, _ = io.ReadAll(r.Body)
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(o.Close)
	return o
}

func (o *origin) port(t *testing.T) int {
	t.Helper()
	_, p, err := net.SplitHostPort(strings.TrimPrefix(o.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// A client's own X-Forwarded-For is never relayed: a chain the client
// wrote is a chain the client chose, and passing it on would let
// anybody claim to have come from anywhere.
func TestAClientsOwnForwardedChainIsNotRelayed(t *testing.T) {
	o := startOrigin(t)
	_, f := plainProxyPorts(t, strconv.Itoa(o.port(t)), "        allow_private: true\n")

	u, _ := url.Parse(o.URL + "/")
	r := &http.Request{Method: http.MethodGet, URL: u, Host: u.Host,
		Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{}, RemoteAddr: "198.51.100.7:40000"}
	r.Header.Set("X-Forwarded-For", "10.9.9.9, 10.8.8.8")
	w := httptest.NewRecorder()
	f.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("the request was answered %d: %s", w.Code, w.Body.String())
	}
	select {
	case got := <-o.got:
		if v := got.Get("X-Forwarded-For"); strings.Contains(v, "10.9.9.9") {
			t.Errorf("the client's own chain reached the origin: %q", v)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the origin never saw the request")
	}
}

// A request whose body has no declared length is read up to the bound
// the rule names and no further: a rule that refuses bodies over a size
// cannot be evaded by not saying the size.
func TestAnUndeclaredBodyIsCutAtTheBoundTheRuleNames(t *testing.T) {
	o := startOrigin(t)
	port := o.port(t)
	s, f := plainProxyPorts(t, strconv.Itoa(port), "        allow_private: true\n")

	// The policy is applied by hand rather than through the YAML so
	// the rule can name a bound small enough to hit with a short body.
	fc := &config.ForwardListener{
		Ports: []int{port}, AllowPrivate: true,
		Rules: []config.ForwardRule{
			{Name: "no-big-uploads", Action: "deny", RequestBytesOver: 16},
			{Name: "everything-else", Action: "allow"},
		},
	}
	if err := f.apply(fc); err != nil {
		t.Fatal(err)
	}
	_ = s

	u, _ := url.Parse(o.URL + "/upload")
	r := &http.Request{Method: http.MethodPost, URL: u, Host: u.Host,
		Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header:        http.Header{"Content-Type": []string{"application/octet-stream"}},
		Body:          io.NopCloser(strings.NewReader(strings.Repeat("x", 4096))),
		ContentLength: -1, // chunked: the length is not declared
		RemoteAddr:    "198.51.100.7:40000",
	}
	w := httptest.NewRecorder()
	f.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("an undeclared body over the bound was answered %d, want 403", w.Code)
	}
}

// CONNECT over HTTP/2, where there is no connection to hijack: the
// stream itself is the tunnel, and the adapter around it has to behave
// like a connection -- addresses, deadlines and all -- or the code
// above it cannot tell the two transports apart.
func TestACONNECTOverHTTP2TunnelsThroughTheStream(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = echo.Close() })
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 1024)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						_, _ = c.Write(append([]byte("echo:"), buf[:n]...))
					}
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	port := echo.Addr().(*net.TCPAddr).Port
	_, f := plainProxyPorts(t, strconv.Itoa(port), "        allow_private: true\n")

	reqR, reqW := io.Pipe()
	respR, respW := io.Pipe()
	w := &masqueWriter{hdr: http.Header{}, w: respW}
	authority := "127.0.0.1:" + strconv.Itoa(port)
	req := &http.Request{Method: http.MethodConnect,
		ProtoMajor: 2, ProtoMinor: 0, Proto: "HTTP/2.0",
		URL:    &url.URL{Opaque: authority, Host: authority},
		Host:   authority,
		Body:   reqR,
		Header: http.Header{}, RemoteAddr: "198.51.100.7:40000"}
	go func() {
		f.ServeHTTP(w, req)
		w.close()
	}()

	if _, err := reqW.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("echo:hello"))
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(respR, buf)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("nothing came back through the stream: %v", err)
		}
		if string(buf) != "echo:hello" {
			t.Errorf("the stream carried %q", buf)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the tunnel never answered")
	}
	_ = reqW.Close()
	_ = respR.Close()
}
