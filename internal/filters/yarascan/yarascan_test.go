package yarascan

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/filter/filtertest"
)

const rules = `
rule marker : test {
  strings:
    $a = "TOP-SECRET-MARKER"
  condition:
    $a
}
`

func build(t *testing.T, extra map[string]any) filter.Filter {
	t.Helper()
	p := filepath.Join(t.TempDir(), "rules.yar")
	if err := os.WriteFile(p, []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := map[string]any{"rules_file": p}
	for k, v := range extra {
		opts[k] = v
	}
	f, err := filtertest.Build("yara", "uploads", opts)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return f
}

func post(body string) *http.Request {
	r, _ := http.NewRequest(http.MethodPost, "https://app.test/upload", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/octet-stream")
	r.ContentLength = int64(len(body))
	return r
}

func resp(body string) *http.Response {
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/octet-stream"}},
		Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body))}
}

func TestBlocksRequestBody(t *testing.T) {
	f := build(t, nil)
	res := filtertest.Run(f, post("a file with TOP-SECRET-MARKER inside"), nil)
	if !res.Request.Deny || res.Request.Status != http.StatusForbidden {
		t.Fatalf("verdict %+v", res.Request)
	}
	if !strings.Contains(res.Request.Detail, "marker") {
		t.Fatalf("detail %q", res.Request.Detail)
	}
}

func TestRegistrationDeclaresBufferedBody(t *testing.T) {
	if !filter.BuffersBody("yara") {
		t.Fatal("yara must charge the process-wide buffered-body budget")
	}
}

// A clean body goes through, and the body the upstream reads is the
// body the client sent.
func TestPassesCleanBody(t *testing.T) {
	f := build(t, nil)
	r := post("an ordinary file")
	res := filtertest.Run(f, r, nil)
	if res.Request.Deny {
		t.Fatalf("clean body denied: %+v", res.Request)
	}
	got, err := io.ReadAll(r.Body)
	if err != nil || string(got) != "an ordinary file" {
		t.Fatalf("body was changed: %q %v", got, err)
	}
}

// A response carrying what a rule names is refused as a gateway error:
// the client did not ask for what the origin sent.
func TestBlocksResponseBody(t *testing.T) {
	f := build(t, nil)
	res := filtertest.Run(f, post("clean"), resp("payload TOP-SECRET-MARKER"))
	if !res.Response.Deny || res.Response.Status != http.StatusBadGateway {
		t.Fatalf("verdict %+v", res.Response)
	}
}

func TestLogAction(t *testing.T) {
	f := build(t, map[string]any{"action": "log"})
	r := post("a file with TOP-SECRET-MARKER inside")
	res := filtertest.Run(f, r, nil)
	if res.Request.Deny {
		t.Fatalf("log mode should forward: %+v", res.Request)
	}
	got, _ := io.ReadAll(r.Body)
	if !strings.Contains(string(got), "TOP-SECRET-MARKER") {
		t.Fatal("the body should still be forwarded under log")
	}
	if !hasAttr(res.Attrs, "yara") {
		t.Fatalf("attrs %v", res.Attrs)
	}
}

// Only the listed directions are scanned.
func TestScanRequestOnly(t *testing.T) {
	f := build(t, map[string]any{"scan": []any{"request"}})
	res := filtertest.Run(f, post("clean"), resp("payload TOP-SECRET-MARKER"))
	if res.Response.Deny {
		t.Fatalf("the response should not have been scanned: %+v", res.Response)
	}
}

// content_types narrows what is looked at, and the type is what the
// sender claims.
func TestContentTypes(t *testing.T) {
	f := build(t, map[string]any{"content_types": []any{"application/zip"}})
	if res := filtertest.Run(f, post("has TOP-SECRET-MARKER"), nil); res.Request.Deny {
		t.Fatal("an unlisted type should not be scanned")
	}
	r := post("has TOP-SECRET-MARKER")
	r.Header.Set("Content-Type", "application/zip")
	if res := filtertest.Run(f, r, nil); !res.Request.Deny {
		t.Fatal("a listed type should be scanned")
	}
}

// A body past the bound is scanned to the bound and forwarded whole,
// and the log says it was only partly scanned.
func TestPartialScan(t *testing.T) {
	f := build(t, map[string]any{"max_bytes": 4096})
	body := strings.Repeat("x", 5000) + "TOP-SECRET-MARKER"
	r := post(body)
	res := filtertest.Run(f, r, nil)
	if res.Request.Deny {
		t.Fatalf("a marker past the bound should not be found: %+v", res.Request)
	}
	got, err := io.ReadAll(r.Body)
	if err != nil || len(got) != len(body) {
		t.Fatalf("the whole body should still be forwarded: %d of %d, %v", len(got), len(body), err)
	}
	if !hasAttr(res.Attrs, "yara_partial") {
		t.Fatalf("attrs %v", res.Attrs)
	}
}

func TestOptionsRefused(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "rules.yar")
	if err := os.WriteFile(good, []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "bad.yar")
	if err := os.WriteFile(bad, []byte("rule r { condition: pe.x > 1 }"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := map[string]map[string]any{
		"no rules":       {},
		"both sources":   {"rules_file": good, "rules_dir": dir},
		"missing file":   {"rules_file": filepath.Join(dir, "nope.yar")},
		"bad rules":      {"rules_file": bad},
		"bad action":     {"rules_file": good, "action": "maybe"},
		"bad direction":  {"rules_file": good, "scan": []any{"sideways"}},
		"tiny max_bytes": {"rules_file": good, "max_bytes": 10},
	}
	for name, opts := range cases {
		if _, err := filtertest.Build("yara", "x", opts); err == nil {
			t.Errorf("%s: should not build", name)
		}
	}
}

func hasAttr(attrs []any, key string) bool {
	for i := 0; i+1 < len(attrs); i += 2 {
		if k, ok := attrs[i].(string); ok && k == key {
			return true
		}
	}
	return false
}

// The filter names itself with the instance name an operator wrote, not the
// kind. Two yara filters on one route -- one over uploads, one over downloads
// -- are told apart in the refusal's reason and in the counters by this name,
// so a filter that reported the kind would make both of them read as "yara".
func TestTheFilterCarriesTheNameItWasBuiltUnder(t *testing.T) {
	if got := build(t, nil).Name(); got != "uploads" {
		t.Errorf("Name = %q, want the instance name", got)
	}
	res := filtertest.Run(build(t, nil), post("a file with TOP-SECRET-MARKER inside"), nil)
	if res.Request.Reason != "uploads" {
		t.Errorf("the refusal's reason = %q, want the instance name", res.Request.Reason)
	}
}

// A response body the scanner read part of is handed on complete.
//
// The scanner reads up to max_bytes to scan them and then has to give the
// client a body that is still the whole body: the bytes it buffered, then the
// one it peeked to find out there was more, then the rest of the stream. A
// reader that lost the peeked byte would corrupt every response longer than
// the bound -- silently, and only for large files.
func TestABodyScannedInPartIsStillDeliveredWhole(t *testing.T) {
	// 4096 is the smallest bound the options allow, and the body is longer
	// than it so the scan really does stop part way.
	body := strings.Repeat("0123456789abcdef", 320) // 5120 bytes
	f := build(t, map[string]any{"max_bytes": 4096})
	r := resp(body)
	res := filtertest.Run(f, post("clean"), r)
	if res.Response.Deny {
		t.Fatalf("a clean body was refused: %+v", res.Response)
	}
	got, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body {
		t.Errorf("the body came back as %q, want %q", got, body)
	}
	// Closing the rejoined body closes the stream underneath it, which is
	// the response's own: a filter that lost the closer would leak a
	// connection per large response.
	if err := r.Body.Close(); err != nil {
		t.Errorf("closing the rejoined body: %v", err)
	}
}

// A response with no body at all is not a body to scan.
//
// A 204 and a HEAD reply both arrive here with http.NoBody, and a scanner that
// treated either as an empty file would charge a scan and a counter against a
// response that carried nothing.
func TestAResponseWithNoBodyIsNotScanned(t *testing.T) {
	f := build(t, nil)
	for _, c := range []struct {
		name string
		body io.ReadCloser
	}{
		{"no body", nil},
		{"http.NoBody", http.NoBody},
	} {
		r := resp("")
		r.Body = c.body
		res := filtertest.Run(f, post("clean"), r)
		if res.Response.Deny {
			t.Errorf("%s: refused: %+v", c.name, res.Response)
		}
	}
}
