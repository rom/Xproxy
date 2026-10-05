package grpcguard

import (
	"encoding/base64"
	"encoding/binary"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/filter/filtertest"
)

func field(num int32, typ uint64, body []byte) []byte {
	out := binary.AppendUvarint(nil, uint64(num)<<3|typ)
	if typ == 2 {
		out = binary.AppendUvarint(out, uint64(len(body)))
	}
	return append(out, body...)
}

func str(num int32, s string) []byte { return field(num, 2, []byte(s)) }
func varint(num int32, v uint64) []byte {
	return field(num, 0, binary.AppendUvarint(nil, v))
}

func frame(compressed bool, payload []byte) []byte {
	out := make([]byte, 5, 5+len(payload))
	if compressed {
		out[0] = 1
	}
	binary.BigEndian.PutUint32(out[1:], uint32(len(payload)))
	return append(out, payload...)
}

func call(body []byte) *http.Request {
	r, _ := http.NewRequest("POST", "http://api.test/pkg.Orders/Create", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/grpc")
	r.ContentLength = int64(len(body))
	return r
}

func build(t *testing.T, opts filter.Options) filter.Filter {
	t.Helper()
	f, err := filtertest.Build("grpc_guard", "rpc", opts)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// An ordinary call goes through, and the body the backend receives is
// the body the client sent.
func TestAllowsOrdinaryCall(t *testing.T) {
	f := build(t, filter.Options{})
	body := frame(false, append(str(1, "an order"), varint(2, 3)...))
	r := call(body)
	v := filtertest.Run(f, r, nil).Request
	if v.Deny {
		t.Fatalf("denied: %+v", v)
	}
	got, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Fatalf("the body was changed: %q want %q", got, body)
	}
}

// A body that is not gRPC is not this filter's business.
func TestIgnoresOtherContentTypes(t *testing.T) {
	f := build(t, filter.Options{"max_depth": 1})
	r, _ := http.NewRequest("POST", "http://api.test/x", strings.NewReader("not grpc at all"))
	r.Header.Set("Content-Type", "application/json")
	if v := filtertest.Run(f, r, nil).Request; v.Deny {
		t.Fatalf("a JSON body was judged as gRPC: %+v", v)
	}
}

// The bound is on one message, which is the number the backend lives
// with; the whole body can be larger.
func TestMaxMessageBytes(t *testing.T) {
	f := build(t, filter.Options{"max_message_bytes": 1024})
	big := frame(false, str(1, strings.Repeat("x", 2000)))
	v := filtertest.Run(f, call(big), nil).Request
	if !v.Deny || v.Status != http.StatusRequestEntityTooLarge {
		t.Fatalf("a message over the bound: %+v", v)
	}
	// Several small messages are not one large one.
	var many []byte
	for i := 0; i < 8; i++ {
		many = append(many, frame(false, str(1, strings.Repeat("y", 500)))...)
	}
	if v := filtertest.Run(f, call(many), nil).Request; v.Deny {
		t.Fatalf("messages inside the bound were refused: %+v", v)
	}
}

func TestMaxMessages(t *testing.T) {
	f := build(t, filter.Options{"max_messages": 3})
	var body []byte
	for i := 0; i < 5; i++ {
		body = append(body, frame(false, varint(1, uint64(i)))...)
	}
	v := filtertest.Run(f, call(body), nil).Request
	if !v.Deny || !strings.Contains(v.Reason, "too_many_messages") {
		t.Fatalf("%+v", v)
	}
}

// A client that finished sends whole frames. One that stopped in the
// middle of a length it declared is a client whose message nobody has.
func TestShortFrame(t *testing.T) {
	f := build(t, filter.Options{})
	var body []byte
	body = append(body, frame(false, str(1, "complete"))...)
	body = append(body, frame(false, str(1, "cut off"))[:6]...)
	v := filtertest.Run(f, call(body), nil).Request
	if !v.Deny || !strings.Contains(v.Reason, "short_frame") {
		t.Fatalf("%+v", v)
	}
}

// A message nested a thousand deep costs the backend's parser far more
// than it costs the sender to write.
func TestNestingBomb(t *testing.T) {
	f := build(t, filter.Options{"max_depth": 8})
	payload := str(1, "bottom")
	for i := 0; i < 64; i++ {
		payload = field(1, 2, payload)
	}
	v := filtertest.Run(f, call(frame(false, payload)), nil).Request
	if !v.Deny || !strings.Contains(v.Reason, "too_deep") {
		t.Fatalf("%+v", v)
	}
}

func TestFieldBomb(t *testing.T) {
	f := build(t, filter.Options{"max_fields": 100})
	var payload []byte
	for i := 0; i < 500; i++ {
		payload = append(payload, varint(1, uint64(i))...)
	}
	v := filtertest.Run(f, call(frame(false, payload)), nil).Request
	if !v.Deny || !strings.Contains(v.Reason, "too_many_fields") {
		t.Fatalf("%+v", v)
	}
}

// A payload that is not protobuf at all is refused rather than guessed
// at: the bounds mean nothing on bytes the walker could not read.
func TestMalformedMessage(t *testing.T) {
	f := build(t, filter.Options{})
	v := filtertest.Run(f, call(frame(false, []byte{0x0a, 0x40, 'a'})), nil).Request
	if !v.Deny || !strings.Contains(v.Reason, "malformed") {
		t.Fatalf("%+v", v)
	}
}

// Patterns run over the strings inside a message, which is the whole
// reason to read one.
func TestDenyPatterns(t *testing.T) {
	f := build(t, filter.Options{
		"deny_patterns":    []any{"(?i)BEGIN (RSA )?PRIVATE KEY"},
		"allow_compressed": false,
	})
	clean := frame(false, str(1, "an ordinary order"))
	if v := filtertest.Run(f, call(clean), nil).Request; v.Deny {
		t.Fatalf("a clean message was refused: %+v", v)
	}
	dirty := frame(false, field(3, 2, field(1, 2, []byte("-----BEGIN RSA PRIVATE KEY-----"))))
	v := filtertest.Run(f, call(dirty), nil).Request
	if !v.Deny || v.Status != http.StatusForbidden {
		t.Fatalf("%+v", v)
	}
	if !strings.Contains(v.Detail, "3.1") {
		t.Errorf("the refusal does not name the field: %q", v.Detail)
	}
}

// Saying so beats finding out: patterns cannot run over bytes this
// filter does not decompress, so the pair is refused at load.
func TestDenyPatternsNeedClearMessages(t *testing.T) {
	_, err := filtertest.Build("grpc_guard", "rpc", filter.Options{
		"deny_patterns": []any{"secret"},
	})
	if err == nil {
		t.Fatal("deny_patterns with compression allowed was accepted")
	}
	if !strings.Contains(err.Error(), "allow_compressed") {
		t.Fatalf("err = %v", err)
	}
}

func TestCompressedRefusedWhenNotAllowed(t *testing.T) {
	f := build(t, filter.Options{"allow_compressed": false})
	v := filtertest.Run(f, call(frame(true, []byte{1, 2, 3})), nil).Request
	if !v.Deny || !strings.Contains(v.Reason, "compressed") {
		t.Fatalf("%+v", v)
	}
	// Allowed, it passes without being walked: there is nothing honest
	// to say about bytes that have not been decompressed.
	f2 := build(t, filter.Options{"allow_compressed": true, "max_depth": 1})
	if v := filtertest.Run(f2, call(frame(true, []byte{0xff, 0xff})), nil).Request; v.Deny {
		t.Fatalf("a compressed message was judged: %+v", v)
	}
}

// Under action: log the call goes on and only the record is made, which
// is how a bound is tried out before it decides anything.
func TestLogOnly(t *testing.T) {
	f := build(t, filter.Options{"max_depth": 2, "action": "log"})
	payload := str(1, "x")
	for i := 0; i < 8; i++ {
		payload = field(1, 2, payload)
	}
	r := call(frame(false, payload))
	if v := filtertest.Run(f, r, nil).Request; v.Deny {
		t.Fatalf("action: log denied: %+v", v)
	}
	if _, err := io.ReadAll(r.Body); err != nil {
		t.Fatalf("the body was not replayable: %v", err)
	}
}

// Beyond max_scan_bytes the rest is forwarded unread, and the access
// line says so rather than leaving it to be noticed.
func TestPartialScan(t *testing.T) {
	f := build(t, filter.Options{"max_scan_bytes": 2048, "max_message_bytes": 1 << 20})
	body := frame(false, str(1, strings.Repeat("z", 8192)))
	r := call(body)
	res := filtertest.Run(f, r, nil)
	if res.Request.Deny {
		t.Fatalf("denied: %+v", res.Request)
	}
	got, err := io.ReadAll(r.Body)
	if err != nil || len(got) != len(body) {
		t.Fatalf("the body was truncated: %d of %d (%v)", len(got), len(body), err)
	}
	var partial bool
	for i := 0; i+1 < len(res.Attrs); i += 2 {
		if res.Attrs[i] == "grpc_partial" {
			partial = true
		}
	}
	if !partial {
		t.Errorf("the partial scan was not recorded: %v", res.Attrs)
	}
}

// A gRPC-web call is inspected, because the upstream receives plain gRPC.
//
// The translation happens in the reverse proxy's rewrite hook, after the filter
// chain, so a guard that only matched `application/grpc` saw `grpc-web+proto`,
// returned Continue, and the upstream got the identical frames with none of the
// bounds or content rules applied. One header was the whole bypass.
func TestAGRPCWebCallIsInspected(t *testing.T) {
	secret := "-----BEGIN RSA PRIVATE KEY-----"
	body := frame(false, []byte(secret))
	for _, tc := range []struct {
		name string
		ct   string
		body []byte
	}{
		{"gRPC", "application/grpc", body},
		{"gRPC with a subtype", "application/grpc+proto", body},
		{"gRPC-web", "application/grpc-web+proto", body},
		{"gRPC-web with a parameter", "application/grpc-web+proto; charset=utf-8", body},
		{"gRPC-web-text", "application/grpc-web-text",
			[]byte(base64.StdEncoding.EncodeToString(body))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := build(t, filter.Options{"deny_patterns": []any{"BEGIN RSA PRIVATE KEY"}, "allow_compressed": false})
			r, _ := http.NewRequest("POST", "http://api.test/pkg.Orders/Create",
				strings.NewReader(string(tc.body)))
			r.Header.Set("Content-Type", tc.ct)
			r.ContentLength = int64(len(tc.body))
			if v := filtertest.Run(f, r, nil).Request; !v.Deny {
				t.Errorf("a %s body carrying a private key was not refused", tc.name)
			}
		})
	}
}
