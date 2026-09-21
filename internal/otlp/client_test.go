package otlp

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The OTLP client posts what the proxy knows about itself and its
// traffic to a collector somebody else runs. It must not follow that
// collector anywhere, must not wait on it forever, and must not report
// success for a body it refused.

// TestPostRoundTrip covers the plain path and the headers a collector
// keys on.
func TestPostRoundTrip(t *testing.T) {
	var got struct {
		body     []byte
		ct, ua   string
		enc, key string
		method   string
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.method = r.Method
		got.ct = r.Header.Get("Content-Type")
		got.ua = r.Header.Get("User-Agent")
		got.enc = r.Header.Get("Content-Encoding")
		got.key = r.Header.Get("X-Api-Key")
		got.body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, err := New(Config{Endpoint: srv.URL, Headers: map[string]string{"X-Api-Key": "secret"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Post(context.Background(), []byte(`{"resourceSpans":[]}`)); err != nil {
		t.Fatal(err)
	}
	if got.method != http.MethodPost || got.ct != "application/json" {
		t.Fatalf("method %q content type %q", got.method, got.ct)
	}
	if !strings.HasPrefix(got.ua, "xproxy-otlp/") {
		t.Fatalf("user agent %q", got.ua)
	}
	if got.enc != "" {
		t.Fatalf("an uncompressed post declared %q", got.enc)
	}
	if got.key != "secret" {
		t.Fatalf("the configured header arrived as %q", got.key)
	}
	if string(got.body) != `{"resourceSpans":[]}` {
		t.Fatalf("body %q", got.body)
	}

	// The defaults a caller does not set.
	if c.Config().ServiceName != "xproxy" || c.Config().Timeout <= 0 {
		t.Fatalf("defaults: %+v", c.Config())
	}
}

// TestCompressedPost covers the gzip form, which is what a collector
// over a wide area link wants.
func TestCompressedPost(t *testing.T) {
	var body []byte
	var enc string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		enc = r.Header.Get("Content-Encoding")
		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		body, _ = io.ReadAll(gz)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, err := New(Config{Endpoint: srv.URL, Compress: true})
	if err != nil {
		t.Fatal(err)
	}
	payload := strings.Repeat(`{"k":"v"},`, 1000)
	if err := c.Post(context.Background(), []byte(payload)); err != nil {
		t.Fatal(err)
	}
	if enc != "gzip" {
		t.Fatalf("content encoding %q", enc)
	}
	if string(body) != payload {
		t.Fatalf("the collector received %d of %d bytes", len(body), len(payload))
	}
}

// TestCollectorFailures covers what the collector can answer. A push
// that failed must say so: the caller counts failures and an operator
// reads them in `xproxyctl telemetry`.
func TestCollectorFailures(t *testing.T) {
	var status atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(int(status.Load()))
	}))
	defer srv.Close()
	c, err := New(Config{Endpoint: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []int{200, 201, 204} {
		status.Store(int64(code))
		if err := c.Post(context.Background(), []byte("{}")); err != nil {
			t.Errorf("HTTP %d reported %v", code, err)
		}
	}
	for _, code := range []int{400, 401, 403, 404, 413, 429, 500, 502, 503} {
		status.Store(int64(code))
		err := c.Post(context.Background(), []byte("{}"))
		if err == nil {
			t.Errorf("HTTP %d reported success", code)
			continue
		}
		if !strings.Contains(err.Error(), "HTTP") {
			t.Errorf("HTTP %d: the error does not carry the status: %v", code, err)
		}
	}
}

// TestRedirectsAreNotFollowed is the trust boundary: the body carries
// what the proxy knows about its traffic, and a collector that answers
// 302 must not be able to send it somewhere else.
func TestRedirectsAreNotFollowed(t *testing.T) {
	var elsewhere atomic.Int64
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elsewhere.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()

	c, err := New(Config{Endpoint: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Post(context.Background(), []byte(`{"telemetry":"ours"}`)); err == nil {
		t.Fatal("a redirect was followed and reported as success")
	}
	if n := elsewhere.Load(); n != 0 {
		t.Fatalf("the body was posted to the redirect target %d times", n)
	}
}

// TestTimeoutAndCancellation covers a collector that does not answer.
// The exporter runs on its own goroutine, but a push that never
// returned would hold the batch and every span behind it.
func TestTimeoutAndCancellation(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		<-block
	}))
	defer srv.Close()
	defer close(block)

	c, err := New(Config{Endpoint: srv.URL, Timeout: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := c.Post(context.Background(), []byte("{}")); err == nil {
		t.Fatal("a collector that never answered reported success")
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("the post waited %v for a 200ms timeout", took)
	}

	// And a context the caller cancels.
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	done := make(chan error, 1)
	go func() { done <- c.Post(ctx, []byte("{}")) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a cancelled post reported success")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a cancelled post did not return")
	}
}

// TestEndpointRejections covers the endpoints a configuration can name
// but the client cannot use.
func TestEndpointRejections(t *testing.T) {
	c, err := New(Config{Endpoint: "://not a url"})
	if err != nil {
		return // refused at construction, which is also correct
	}
	if err := c.Post(context.Background(), []byte("{}")); err == nil {
		t.Fatal("a malformed endpoint posted successfully")
	}
	unreachable, err := New(Config{Endpoint: "http://127.0.0.1:1/v1/traces", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := unreachable.Post(context.Background(), []byte("{}")); err == nil {
		t.Fatal("a closed port posted successfully")
	}
}

// TestCAFile covers the pinned certificate authority, which is what a
// deployment uses when its collector is internal.
func TestCAFile(t *testing.T) {
	dir := t.TempDir()
	notPEM := filepath.Join(dir, "not.pem")
	if err := os.WriteFile(notPEM, []byte("this is not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{Endpoint: "https://collector.invalid", CAFile: notPEM}); err == nil {
		t.Fatal("a ca_file with no certificates was accepted")
	}
	if _, err := New(Config{Endpoint: "https://collector.invalid", CAFile: filepath.Join(dir, "absent.pem")}); err == nil {
		t.Fatal("a missing ca_file was accepted")
	}

	// A real one is loaded and then actually used: the collector's own
	// certificate verifies, and a client without the CA does not.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	ca := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(ca, pemOf(srv.Certificate().Raw), 0o600); err != nil {
		t.Fatal(err)
	}
	pinned, err := New(Config{Endpoint: srv.URL, CAFile: ca, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := pinned.Post(context.Background(), []byte("{}")); err != nil {
		t.Fatalf("with the collector's own CA: %v", err)
	}
	plain, err := New(Config{Endpoint: srv.URL, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := plain.Post(context.Background(), []byte("{}")); err == nil {
		t.Fatal("a collector whose certificate does not verify was accepted")
	}
}

// pemOf wraps a DER certificate for a ca_file.
func pemOf(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// TestAttributes covers the resource description every export carries,
// which is how a collector tells one proxy from another.
func TestAttributes(t *testing.T) {
	c, err := New(Config{Endpoint: "http://collector.invalid", ServiceName: "edge", Version: "1.2.3",
		Attributes: map[string]string{"region": "eu-north", "cluster": "a"}})
	if err != nil {
		t.Fatal(err)
	}
	res := c.Resource()
	byKey := map[string]string{}
	keys := make([]string, 0, len(res))
	for _, kv := range res {
		if kv.Value.StringValue != nil {
			byKey[kv.Key] = *kv.Value.StringValue
		}
		keys = append(keys, kv.Key)
	}
	if byKey["service.name"] != "edge" || byKey["service.version"] != "1.2.3" {
		t.Fatalf("resource %v", byKey)
	}
	if byKey["region"] != "eu-north" || byKey["cluster"] != "a" {
		t.Fatalf("the configured attributes are %v", byKey)
	}
	if _, ok := byKey["host.name"]; !ok {
		t.Log("no host name in the resource")
	}
	// The operator's own attributes are in a stable order, so two
	// exports of the same configuration are byte identical.
	again := c.Resource()
	for i := range res {
		if res[i].Key != again[i].Key {
			t.Fatalf("the resource order changed: %v then %v", keys, again)
		}
	}
	// Without a version the field is absent rather than empty.
	bare, err := New(Config{Endpoint: "http://collector.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	for _, kv := range bare.Resource() {
		if kv.Key == "service.version" {
			t.Fatal("an unset version was exported as an attribute")
		}
	}
}

// TestValueKinds covers the attribute constructors, including the one
// the protocol spells differently: a 64 bit integer travels as a
// string, because JSON numbers are doubles.
func TestValueKinds(t *testing.T) {
	if v := String("k", "v"); v.Value.StringValue == nil || *v.Value.StringValue != "v" {
		t.Fatal("String")
	}
	for _, n := range []int64{0, 1, -1, 1 << 53, 1<<63 - 1, -1 << 63} {
		v := Int("k", n)
		if v.Value.IntValue == nil {
			t.Fatalf("Int(%d) produced no value", n)
		}
		// Round trips through JSON as the exact integer, which is the
		// whole reason it is a string.
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), `"`+*v.Value.IntValue+`"`) {
			t.Fatalf("Int(%d) encoded as %s", n, b)
		}
	}
	if v := Bool("k", true); v.Value.BoolValue == nil || !*v.Value.BoolValue {
		t.Fatal("Bool")
	}
	if v := Float("k", 1.5); v.Value.DoubleValue == nil || *v.Value.DoubleValue != 1.5 {
		t.Fatal("Float")
	}
	// An attribute encodes with exactly one of the value fields set.
	b, err := json.Marshal(String("k", "v"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "intValue") || strings.Contains(string(b), "boolValue") {
		t.Fatalf("a string attribute encoded as %s", b)
	}
}

// TestNanos covers the timestamp format, which is nanoseconds as a
// string for the same reason integers are.
func TestNanos(t *testing.T) {
	at := time.Unix(1700000000, 123456789)
	if got := Nanos(at); got != "1700000000123456789" {
		t.Fatalf("Nanos = %q", got)
	}
	if got := Nanos(time.Unix(0, 0)); got != "0" {
		t.Fatalf("the epoch is %q", got)
	}
}
