package proxy

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/icap/icaptest"
)

const icapYAML = `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
trusted_proxies: [127.0.0.0/8]
bans:
  action: reject
  triggers: [{name: malware, reasons: [icap], threshold: 2, window: 1m, duration: 1h}]
icap:
  services:
    - name: av
      url: %s
      max_body: 4096
      body_limit_action: reject
      fail: closed
    - name: dead
      url: icap://127.0.0.1:1/scan
      connect_timeout: 200ms
      fail: %s
upstreams:
  - name: a
    endpoints: [{address: "%s"}]
routes:
  - {name: upload, hosts: [upload.test],  icap: {service: av}, upstream: a}
  - {name: both,   hosts: [both.test],    icap: {service: av, request: true, response: true}, upstream: a}
  - {name: dead,   hosts: [dead.test],    icap: {service: dead}, upstream: a}
  - {name: open,   hosts: [open.test],    upstream: a}
`

func post(t *testing.T, url, host, ip, body string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", url, strings.NewReader(body))
	req.Host = host
	req.Header.Set("X-Forwarded-For", ip)
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b := make([]byte, 8192)
	n, _ := resp.Body.Read(b)
	return resp, string(b[:n])
}

func TestICAPIntegration(t *testing.T) {
	backend := newBackend(t, "a")
	fake := icaptest.New(t, 64)
	s, url := startServer(t, fmt.Sprintf(icapYAML, fake.URL(), "closed", backend.addr()))

	// Clean upload passes and the body reaches the backend intact.
	resp, body := post(t, url+"/files", "upload.test", "198.51.100.60", "clean document "+strings.Repeat("z", 200))
	if resp.StatusCode != 200 || body != "a:/files" || !strings.HasPrefix(backend.last.Load().Header.Get("X-Test-Body"), "clean document") {
		t.Fatalf("clean: %d %q", resp.StatusCode, body)
	}
	// Infected upload is answered with the scanner's block page.
	resp, body = post(t, url+"/files", "upload.test", "198.51.100.61", "EICAR-STANDARD-ANTIVIRUS-TEST-FILE")
	if resp.StatusCode != 403 || body != "<html>blocked by scanner</html>" || resp.Header.Get("X-Virus") != "found" || resp.Header.Get("Content-Type") != "text/html" {
		t.Fatalf("blocked: %d %q %v", resp.StatusCode, body, resp.Header)
	}
	// Modified request: path and headers rewritten, host and forwarding
	// headers protected.
	resp, body = post(t, url+"/modify", "upload.test", "198.51.100.62", "original")
	last := backend.last.Load()
	if resp.StatusCode != 200 || body != "a:/modified" || last.Header.Get("X-Scanned") != "yes" || last.Header.Get("X-Test-Body") != "clean" || !strings.HasPrefix(last.Header.Get("X-Forwarded-For"), "198.51.100.62") || last.Host != "upload.test" {
		t.Fatalf("modified: %d %q host=%s %v", resp.StatusCode, body, last.Host, last.Header)
	}
	// Body over the service limit is rejected.
	resp, _ = post(t, url+"/files", "upload.test", "198.51.100.63", strings.Repeat("x", 5000))
	if resp.StatusCode != 413 {
		t.Fatalf("over limit: %d", resp.StatusCode)
	}
	// Response scanning: clean body passes intact, /virus response is blocked.
	resp, body = getAs(t, url+"/download", "both.test", "198.51.100.64")
	if resp.StatusCode != 200 || body != "a:/download" {
		t.Fatalf("respmod clean: %d %q", resp.StatusCode, body)
	}
	resp, body = getAs(t, url+"/virus", "both.test", "198.51.100.64")
	if resp.StatusCode != 403 || !strings.Contains(body, "blocked by scanner") {
		t.Fatalf("respmod blocked: %d %q", resp.StatusCode, body)
	}
	// Fail closed on an unreachable service.
	resp, _ = getAs(t, url+"/", "dead.test", "198.51.100.65")
	if resp.StatusCode != 502 {
		t.Fatalf("fail closed: %d", resp.StatusCode)
	}
	// Repeated blocks trigger a ban.
	post(t, url+"/files", "upload.test", "198.51.100.61", "EICAR")
	if !s.Bans().Banned(mustAddr("198.51.100.61")) {
		t.Fatal("icap blocks did not trigger a ban")
	}
	st := s.Stats()
	if st.DeniedICAP < 4 {
		t.Fatalf("stats %+v", st)
	}
	sts := s.ICAP()
	if len(sts) != 2 || sts[0].Name != "av" || !sts[0].Reachable || sts[0].Replacements < 2 || sts[1].Reachable {
		t.Fatalf("icap status %+v", sts)
	}
	fake.Mu.Lock()
	previews := fake.Previews
	fake.Mu.Unlock()
	if previews == 0 {
		t.Fatal("preview was never used")
	}
}

func TestICAPFailOpen(t *testing.T) {
	backend := newBackend(t, "a")
	fake := icaptest.New(t, 0)
	_, url := startServer(t, fmt.Sprintf(icapYAML, fake.URL(), "open", backend.addr()))
	resp, body := getAs(t, url+"/", "dead.test", "198.51.100.70")
	if resp.StatusCode != 200 || body != "a:/" {
		t.Fatalf("fail open: %d %q", resp.StatusCode, body)
	}
}
