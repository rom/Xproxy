package http

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/testutil"
)

func TestReloadListeners(t *testing.T) {
	a := newBackend(t, "a")
	dir := t.TempDir()
	cert, key := testutil.WriteCert(t, dir, "tls.test")
	tpl := `
version: 1
server:
  shutdown_timeout: 2s
  listeners:
    - %s
%s
upstreams:
  - name: u
    endpoints: [{address: "` + a.addr() + `"}]
routes:
  - name: r
    upstream: u
`
	main := `{name: main, address: "127.0.0.1:0"}`
	parse := func(mainLine, extra string) *config.Config {
		t.Helper()
		cfg, err := config.Parse([]byte(fmt.Sprintf(tpl, mainLine, extra)))
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	s, url := startServer(t, fmt.Sprintf(tpl, main, ""))
	addr := s.Addrs()["main"]

	// Added: bound and served by the reload.
	extra := `    - {name: extra, address: "127.0.0.1:0"}`
	if err := s.Reload(parse(main, extra)); err != nil {
		t.Fatal(err)
	}
	extraAddr := s.Addrs()["extra"]
	if extraAddr == "" {
		t.Fatal("extra listener not bound")
	}
	if _, body := get(t, "http://"+extraAddr+"/"); body != "a:/" {
		t.Fatal(body)
	}

	// Rebuilt on the same address: the accept socket is kept, so the
	// address does not change; the idle keep-alive connection of the old
	// generation is closed by the drain.
	idle, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	_, _ = fmt.Fprintf(idle, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	if resp, err := http.ReadResponse(bufio.NewReader(idle), nil); err != nil || resp.StatusCode != 200 {
		t.Fatalf("keep-alive request: %v %v", err, resp)
	} else {
		_ = resp.Body.Close()
	}
	if err := s.Reload(parse(`{name: main, address: "127.0.0.1:0", redirect_to_https: true}`, extra)); err != nil {
		t.Fatal(err)
	}
	if got := s.Addrs()["main"]; got != addr {
		t.Fatalf("address changed on rebuild: %s -> %s", addr, got)
	}
	// On its own connection: the pooled one belongs to the generation
	// the rebuild is draining, and reusing it would be a race with the
	// close rather than a test of the new listener.
	if code := fresh(t, url+"/"); code != 308 {
		t.Fatalf("rebuilt listener: %d", code)
	}
	_ = idle.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := idle.Read(make([]byte, 1)); err == nil {
		t.Fatal("old generation's idle connection not closed")
	}

	// Renamed on the same address: the socket follows the name.
	if err := s.Reload(parse(`{name: web, address: "127.0.0.1:0"}`, extra)); err != nil {
		t.Fatal(err)
	}
	if got := s.Addrs()["web"]; got != addr || s.Addrs()["main"] != "" {
		t.Fatalf("rename: %v", s.Addrs())
	}
	// The shared transport may still hold a keep-alive connection served
	// by the redirecting generation, which drains asynchronously.
	http.DefaultTransport.(*http.Transport).CloseIdleConnections()
	if _, body := get(t, url+"/"); body != "a:/" {
		t.Fatal(body)
	}

	// Removed: the socket closes once its connections drained.
	if err := s.Reload(parse(`{name: web, address: "127.0.0.1:0"}`, "")); err != nil {
		t.Fatal(err)
	}
	if s.Addrs()["extra"] != "" {
		t.Fatal("removed listener still listed")
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", extraAddr, time.Second)
		if err != nil {
			break
		}
		_ = c.Close()
		if time.Now().After(deadline) {
			t.Fatal("removed listener still accepts")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// A listener that cannot be bound fails the reload; the set is
	// unchanged and nothing leaks.
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	err = s.Reload(parse(`{name: web, address: "127.0.0.1:0"}`, `    - {name: clash, address: "`+busy.Addr().String()+`"}`))
	if err == nil || !strings.Contains(err.Error(), "clash") {
		t.Fatalf("busy address: %v", err)
	}
	if len(s.Addrs()) != 1 || s.Stats().ReloadFailures != 1 {
		t.Fatalf("after failed reload: %v %+v", s.Addrs(), s.Stats())
	}
	if _, body := get(t, url+"/"); body != "a:/" {
		t.Fatal(body)
	}

	// A listener with a UDP socket cannot be rebuilt on the same address.
	h3 := `    - {name: quic, address: "127.0.0.1:0", protocols: [h1, h3], tls: {certificates: [{cert_file: ` + cert + `, key_file: ` + key + `}]}}`
	if err := s.Reload(parse(`{name: web, address: "127.0.0.1:0"}`, h3)); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(parse(`{name: web, address: "127.0.0.1:0"}`, strings.Replace(h3, "[h1, h3]", "[h1, h2, h3]", 1))); err == nil || !strings.Contains(err.Error(), "restart required") {
		t.Fatalf("h3 rebuild: %v", err)
	}
	// Its certificate files still reload in place.
	if err := s.Reload(parse(`{name: web, address: "127.0.0.1:0"}`, h3)); err != nil {
		t.Fatal(err)
	}
	if s.Stats().Reloads != 6 || s.Stats().ReloadFailures != 2 {
		t.Fatalf("%+v", s.Stats())
	}
}

// fresh makes one request on a connection of its own and returns the
// status, so a reload draining a pooled connection cannot be mistaken
// for the answer.
func fresh(t *testing.T, url string) int {
	t.Helper()
	c := &http.Client{
		Transport:     &http.Transport{DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer c.CloseIdleConnections()
	// A rebuild keeps the accept socket and drains the old generation,
	// so a connection can be accepted by the server that is closing and
	// come back as EOF before the new one is serving. That is the
	// handover working, not a failure, so a couple of attempts are
	// allowed before it counts as one.
	var resp *http.Response
	var err error
	for attempt := 0; attempt < 5; attempt++ {
		resp, err = c.Get(url) //nolint:noctx // a test request with the client's own timeout
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("get %s: %v", url, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}
