package proxy

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/rom/xproxy/internal/upstream"
)

func TestGRPCWeb(t *testing.T) {
	var serving atomic.Bool
	serving.Store(true)
	backend := grpcBackend(t, &serving)
	yaml := `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
upstreams:
  - name: g
    h2c: true
    endpoints: [{address: "%s"}]
routes:
  - name: web
    hosts: [rpc.test]
    grpc: {web: true, web_origins: ["https://app.test"]}
    upstream: g
  - name: plain
    hosts: [plain.test]
    grpc: {}
    upstream: g
`
	_, url := startServer(t, fmt.Sprintf(yaml, strings.TrimPrefix(backend.URL, "http://")))
	call := func(host, ct, path string, body []byte, hdr ...string) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, url+path, bytes.NewReader(body))
		req.Host = host
		req.Header.Set("Content-Type", ct)
		req.Header.Set("X-Grpc-Web", "1")
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	msg := []byte("hello")
	frame := upstream.FrameGRPC(msg)

	// Binary variant over HTTP/1.1: the echo frame then a trailer frame.
	resp := call("rpc.test", "application/grpc-web+proto", "/echo.Echo/Say", frame, "Origin", "https://app.test")
	out, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/grpc-web+proto" || resp.ProtoMajor != 1 {
		t.Fatalf("binary: %d %s %s", resp.StatusCode, resp.Header.Get("Content-Type"), resp.Proto)
	}
	if !bytes.HasPrefix(out, frame) {
		t.Fatalf("data frame missing: %q", out)
	}
	trailer := out[len(frame):]
	if len(trailer) < 5 || trailer[0] != 0x80 || int(binary.BigEndian.Uint32(trailer[1:5])) != len(trailer)-5 || !strings.Contains(string(trailer[5:]), "grpc-status: 0\r\n") {
		t.Fatalf("trailer frame: %q", trailer)
	}
	if resp.Header.Get("Access-Control-Allow-Origin") != "https://app.test" || !strings.Contains(resp.Header.Get("Access-Control-Expose-Headers"), "grpc-status") {
		t.Fatalf("cors headers: %v", resp.Header)
	}
	if resp.Header.Get("X-Served-By") != "backend" {
		t.Fatal("upstream headers lost")
	}

	// Text variant: base64 in, base64 frames out.
	resp = call("rpc.test", "application/grpc-web-text", "/echo.Echo/Say", []byte(base64.StdEncoding.EncodeToString(frame)))
	out, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/grpc-web-text" || resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("text: %d %v %q", resp.StatusCode, resp.Header, out)
	}
	decoded, err := decodeGRPCWebText(out)
	if err != nil || !bytes.HasPrefix(decoded, frame) || !strings.Contains(string(decoded[len(frame):]), "grpc-status: 0") {
		t.Fatalf("text response %q -> %q %v", out, decoded, err)
	}
	// Two padded chunks in one body decode as two frames.
	two := base64.StdEncoding.EncodeToString(frame) + base64.StdEncoding.EncodeToString(upstream.FrameGRPC([]byte("x")))
	if d, err := decodeGRPCWebText([]byte(two)); err != nil || len(d) != len(frame)+6 {
		t.Fatalf("two chunks: %q %v", d, err)
	}

	// A trailers-only error from the backend becomes a trailer frame too.
	resp = call("rpc.test", "application/grpc-web+proto", "/echo.Echo/Fail", frame)
	out, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || len(out) < 5 || out[0] != 0x80 || !strings.Contains(string(out), "grpc-status: 5\r\n") || !strings.Contains(string(out), "grpc-message: not found") {
		t.Fatalf("failure: %d %q", resp.StatusCode, out)
	}

	// Preflight from an allowed and a foreign origin.
	pre := func(origin string) *http.Response {
		req, _ := http.NewRequest(http.MethodOptions, url+"/echo.Echo/Say", nil)
		req.Host = "rpc.test"
		req.Header.Set("Origin", origin)
		req.Header.Set("Access-Control-Request-Method", "POST")
		req.Header.Set("Access-Control-Request-Headers", "content-type,x-grpc-web,x-user-agent")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp
	}
	if r := pre("https://app.test"); r.StatusCode != 204 || r.Header.Get("Access-Control-Allow-Origin") != "https://app.test" || r.Header.Get("Access-Control-Allow-Headers") != "content-type,x-grpc-web,x-user-agent" || r.Header.Get("Access-Control-Allow-Methods") != "POST, OPTIONS" {
		t.Fatalf("preflight: %d %v", r.StatusCode, r.Header)
	}
	if r := pre("https://evil.test"); r.StatusCode != 403 {
		t.Fatalf("foreign preflight: %d", r.StatusCode)
	}

	// A route without web refuses gRPC-web, in gRPC-web form.
	resp = call("plain.test", "application/grpc-web+proto", "/echo.Echo/Say", frame)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Grpc-Status") != "2" || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/grpc-web") {
		t.Fatalf("web on a plain grpc route: %d %v", resp.StatusCode, resp.Header)
	}
}
