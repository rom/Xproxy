package simulate

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/capture"
	"github.com/rom/xproxy/internal/config"
)

// The reader is checked against the writer, because a reader tested against
// files it wrote itself proves nothing about the ones it has to read.
func TestReadingBackWhatTheCaptureWrote(t *testing.T) {
	dir := t.TempDir()
	// Through the loader, so the defaults the writer relies on -- the file
	// prefix, the snap length, the bounds -- are the ones a daemon would have.
	cfg, err := config.Parse([]byte(`version: 1
capture:
  enabled: true
  directory: ` + dir + `
  rules: [{name: all}]
server:
  listeners: [{name: edge, address: "127.0.0.1:0"}]
upstreams:
  - {name: u, endpoints: [{address: "127.0.0.1:9"}]}
routes:
  - {name: r, upstream: u}
`))
	if err != nil {
		t.Fatal(err)
	}
	c, err := capture.New(cfg.Capture)
	if err != nil {
		t.Fatal(err)
	}
	c.SetActive(true, time.Minute)
	req := "GET /admin?id=1%27+OR+1%3D1-- HTTP/1.1\r\nHost: shop.example.com\r\n\r\n"
	c.Write(&capture.Exchange{
		Start:     time.Now(),
		Client:    netip.MustParseAddrPort("203.0.113.9:51234"),
		Server:    netip.MustParseAddrPort("10.0.0.1:443"),
		RequestID: "01JABCDEF",
		Route:     "shop",
		Status:    403,
		Denied:    "waf:942100",
		Request:   []byte(req),
		Response:  []byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"),
	})
	// A second exchange, over IPv6, so the reader's other address path runs.
	c.Write(&capture.Exchange{
		Start:     time.Now(),
		Client:    netip.MustParseAddrPort("[2001:db8::9]:51235"),
		Server:    netip.MustParseAddrPort("[2001:db8::1]:443"),
		RequestID: "01JABCDEG",
		Route:     "shop",
		Status:    200,
		Request:   []byte("GET /about HTTP/1.1\r\nHost: shop.example.com\r\n\r\n"),
	})
	c.SetActive(false, 0)

	files, err := filepath.Glob(filepath.Join(dir, "*.pcapng"))
	if err != nil || len(files) != 1 {
		t.Fatalf("capture files %v %v", files, err)
	}
	f, err := os.Open(files[0])
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	flows, err := ReadCapture(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 2 {
		t.Fatalf("flows %d: %+v", len(flows), flows)
	}
	first := flows[0]
	if string(first.Request) != req {
		t.Errorf("request round trip:\n got %q\nwant %q", first.Request, req)
	}
	if first.Client.Addr().String() != "203.0.113.9" {
		t.Errorf("client %s: the SYN decides which end is the client", first.Client)
	}
	if first.RequestID() != "01JABCDEF" || first.Route() != "shop" ||
		first.Status() != 403 || first.Denied() != "waf:942100" {
		t.Errorf("the comment did not survive: %q", first.Comment)
	}
	if flows[1].Status() != 200 || !strings.Contains(string(flows[1].Request), "/about") {
		t.Errorf("the second flow: %+v", flows[1])
	}

	// And the flows become inputs the simulation can send.
	in := CaptureInputs(flows, "edge")
	if len(in) != 2 || in[0].Name != "01JABCDEF" || in[0].Listener != "edge" {
		t.Errorf("inputs %+v", in)
	}
}

// A file that is not one of ours is refused by name rather than half read.
func TestACaptureFileTheReaderDoesNotUnderstand(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", "empty, or not a pcapng"},
		{"not pcapng", "\x0a\x0d\x0d\x0a\x1c\x00\x00\x00nonsense-magic--", "not a pcapng section header"},
		{"a block before the header", "\x06\x00\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00", "before any section header"},
	} {
		_, err := ReadCapture(strings.NewReader(tc.in))
		if err == nil {
			t.Errorf("%s: accepted", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v does not say %q", tc.name, err, tc.want)
		}
	}
}
