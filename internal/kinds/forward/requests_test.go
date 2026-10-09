package forward

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/passwd"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/proxytest"
)

// A forward proxy is reachable by whoever can reach the port, and what
// arrives is an HTTP request of somebody else's choosing. Each refusal
// here is a status rather than a dropped connection, because a proxy
// that drops cannot be told from a proxy that is broken -- and a client
// that cannot tell will retry.

// plainProxy starts a forward listener and returns the handler, which
// is what these tests drive: net/http's own client will not send most
// of what a proxy has to refuse.
func plainProxy(t *testing.T, extra string) (*proxy.Server, *forwardServer) {
	t.Helper()
	return plainProxyPorts(t, "80, 443", extra)
}

func plainProxyPorts(t *testing.T, ports, extra string) (*proxy.Server, *forwardServer) {
	t.Helper()
	yaml := `
version: 1
server:
  listeners:
    - name: fwd
      address: "127.0.0.1:0"
      kind: forward
      forward:
        ports: [PORTS]
EXTRA
logging:
  access: {enabled: false}
upstreams:
  - name: unused
    endpoints: [{address: 127.0.0.1:1}]
routes: []
`
	yaml = strings.Replace(yaml, "PORTS", ports, 1)
	s := proxytest.Start(t, strings.Replace(yaml, "EXTRA", extra, 1))
	return s, forwardOf(t, s)
}

// ask drives one request through the handler and returns the recorder.
func ask(f *forwardServer, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	f.ServeHTTP(w, r)
	return w
}

// proxyGet is a request as a client sends it to a proxy: absolute URL,
// no body.
func proxyGet(raw string) *http.Request {
	u, _ := url.Parse(raw)
	return &http.Request{Method: http.MethodGet, URL: u, Host: u.Host,
		Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{}, RemoteAddr: "198.51.100.7:40000"}
}

// proxyConnect is a CONNECT as a client sends it: an authority and
// nothing else.
func proxyConnect(authority string) *http.Request {
	return &http.Request{Method: http.MethodConnect,
		URL: &url.URL{Opaque: authority, Host: authority}, Host: authority,
		Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{}, RemoteAddr: "198.51.100.7:40000"}
}

func TestARequestAProxyCannotServeIsRefusedWithAStatus(t *testing.T) {
	_, f := plainProxy(t, "        allow_private: true\n")

	for _, c := range []struct {
		name string
		req  *http.Request
		want int
	}{
		{
			// A proxy request carries an absolute URL. A relative one
			// is a request meant for an origin server, which this is
			// not.
			name: "a request that is not absolute",
			req: &http.Request{Method: http.MethodGet, URL: &url.URL{Path: "/"},
				Proto: "HTTP/1.1", ProtoMajor: 1, Header: http.Header{}, RemoteAddr: "198.51.100.7:40000"},
			want: http.StatusBadRequest,
		},
		{
			// https through a plain proxy request means asking the
			// proxy to be the TLS client, which is what CONNECT is
			// for: the two are different things and conflating them
			// would be the proxy terminating TLS nobody asked it to.
			name: "a scheme that is not http",
			req:  proxyGet("https://example.test/"),
			want: http.StatusBadRequest,
		},
		{
			// Port 80 is on the list, so what is refused here is the
			// empty host rather than the port -- and an empty host is
			// a destination the policy will not pass rather than a
			// request the proxy cannot read, so it is a 403.
			name: "no host at all",
			req:  proxyGet("http://:80/just-a-path"),
			want: http.StatusForbidden,
		},
		{
			name: "a port that is not on the list",
			req:  proxyGet("http://example.test:9999/"),
			want: http.StatusForbidden,
		},
		{
			name: "an authority that is not host and port",
			req:  proxyConnect("not:a:port"),
			want: http.StatusBadRequest,
		},
		{
			name: "a CONNECT port that is not on the list",
			req:  proxyConnect("example.test:9999"),
			want: http.StatusForbidden,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := ask(f, c.req)
			if w.Code != c.want {
				t.Errorf("status %d, want %d", w.Code, c.want)
			}
		})
	}
}

// A destination inside the estate is refused unless the listener says
// otherwise: a forward proxy that reaches private addresses is an
// instrument for reaching the inside of the network from the outside.
func TestAPrivateDestinationIsRefusedUnlessTheListenerAllowsIt(t *testing.T) {
	_, f := plainProxy(t, "")
	if w := ask(f, proxyConnect("127.0.0.1:443")); w.Code != http.StatusForbidden {
		t.Errorf("a private destination gave %d, want 403", w.Code)
	}

	// With allow_private the same destination is refused for a
	// different reason, or reached: either way not for being private.
	_, allowed := plainProxy(t, "        allow_private: true\n")
	if w := ask(allowed, proxyConnect("127.0.0.1:443")); w.Code == http.StatusForbidden {
		t.Errorf("a private destination was still refused with allow_private: %s", w.Body.String())
	}
}

// A CONNECT that gets past the policy still needs a connection the
// proxy can take over. Neither failure may leave the client waiting on
// a tunnel that was never opened.
func TestACONNECTThatCannotBeCompletedIsAnswered(t *testing.T) {
	// A port nothing is listening on: the dial is what fails.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	_, f := plainProxyPorts(t, strconv.Itoa(port), "        allow_private: true\n")
	if w := ask(f, proxyConnect("127.0.0.1:"+strconv.Itoa(port))); w.Code != http.StatusBadGateway {
		t.Errorf("a destination that does not answer gave %d, want 502", w.Code)
	}

	// A destination that does answer, through a response writer that
	// cannot be hijacked: there is no connection to splice, and the
	// proxy says so rather than half-opening a tunnel.
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = echo.Close() }()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	open := echo.Addr().(*net.TCPAddr).Port
	_, f2 := plainProxyPorts(t, strconv.Itoa(open), "        allow_private: true\n")
	w := ask(f2, proxyConnect("127.0.0.1:"+strconv.Itoa(open)))
	if w.Code == http.StatusOK {
		t.Errorf("a tunnel was reported open through a writer that cannot be hijacked")
	}
}

// A listener that asks for a credential refuses what arrives without
// one, and says how to come back: a 407 with the realm is what makes a
// client ask the person.
func TestAProxyThatAsksForACredentialSaysHowToGiveIt(t *testing.T) {
	hash, err := passwd.HashWithIterations("correct horse battery", 1000)
	if err != nil {
		t.Fatal(err)
	}
	users := filepath.Join(t.TempDir(), "proxy.htpasswd")
	if err := os.WriteFile(users, []byte("alice:"+hash+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, f := plainProxy(t, "        allow_private: true\n        auth: {users_file: "+users+", realm: lab}\n")

	w := ask(f, proxyGet("http://example.test/"))
	if w.Code != http.StatusProxyAuthRequired {
		t.Fatalf("an unauthenticated request gave %d, want 407", w.Code)
	}
	if !strings.Contains(w.Header().Get("Proxy-Authenticate"), `realm="lab"`) {
		t.Errorf("the challenge does not name the realm: %q", w.Header().Get("Proxy-Authenticate"))
	}

	// A credential that is not even Basic, and one that is Basic and
	// wrong: both are refused the same way.
	for _, cred := range []string{"Bearer something", "Basic !!!not-base64", "Basic " + basic("alice", "wrong")} {
		r := proxyGet("http://example.test/")
		r.Header.Set("Proxy-Authorization", cred)
		if w := ask(f, r); w.Code != http.StatusProxyAuthRequired {
			t.Errorf("%q gave %d, want 407", cred, w.Code)
		}
	}

	// And the right one is let through to whatever the destination
	// does, which here is a refusal for another reason -- not 407.
	r := proxyGet("http://example.test/")
	r.Header.Set("Proxy-Authorization", "Basic "+basic("alice", "correct horse battery"))
	if w := ask(f, r); w.Code == http.StatusProxyAuthRequired {
		t.Error("the right credential was refused")
	}
}

func basic(user, pass string) string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	in := []byte(user + ":" + pass)
	var out []byte
	for i := 0; i < len(in); i += 3 {
		var b [3]byte
		n := copy(b[:], in[i:])
		out = append(out, chars[b[0]>>2], chars[(b[0]&0x03)<<4|b[1]>>4])
		if n > 1 {
			out = append(out, chars[(b[1]&0x0f)<<2|b[2]>>6])
		} else {
			out = append(out, '=')
		}
		if n > 2 {
			out = append(out, chars[b[2]&0x3f])
		} else {
			out = append(out, '=')
		}
	}
	return string(out)
}

// The lists this listener compiles at load are refused there: a rule
// that cannot be compiled is a policy that would not be applied, and a
// listener that started with one would be a listener with a hole in it.
func TestTheRulesAreCompiledWhenTheListenerIsBuilt(t *testing.T) {
	s, _ := plainProxy(t, "        allow_private: true\n")
	for _, c := range []struct {
		name, want string
		fc         config.ForwardListener
	}{
		{
			name: "an allow rule with no destination in it",
			fc:   config.ForwardListener{Allow: []string{"."}},
			want: "allow",
		},
		{
			name: "a deny rule with no destination in it",
			fc:   config.ForwardListener{Deny: []string{""}},
			want: "deny",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := &forwardServer{host: s, name: "fwd"}
			err := f.apply(&c.fc)
			if err == nil {
				t.Fatalf("the listener was built with %s", c.name)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("the refusal says %q, which does not name %q", err, c.want)
			}
		})
	}
}
