package originsig

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSignAndVerify(t *testing.T) {
	old := []byte("0123456789abcdef0123456789abcdef")
	cur := []byte("fedcba9876543210fedcba9876543210")
	s, err := New("", []string{"X-Tenant"}, [][]byte{cur, old})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	out := httptest.NewRequest("POST", "http://pool/api/items?x=1&y=2", nil)
	out.Host = "app.internal"
	out.Header.Set("X-Tenant", "acme")
	s.Sign(out, now, "203.0.113.9", "req-1", "")
	sig := out.Header.Get(DefaultHeader)
	if sig == "" || sig[:3] != "v1;" {
		t.Fatalf("signature %q", sig)
	}
	// The origin sees the same request with the proxy's forwarding headers.
	in := httptest.NewRequest("POST", "http://app.internal/api/items?x=1&y=2", nil)
	in.Host = "app.internal"
	in.Header.Set(DefaultHeader, sig)
	in.Header.Set("X-Real-Ip", "203.0.113.9")
	in.Header.Set("X-Request-Id", "req-1")
	in.Header.Set("X-Tenant", "acme")
	keys := [][]byte{cur, old}
	if err := Verify(in, "", []string{"X-Tenant"}, keys, 5*time.Minute, now.Add(time.Minute)); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// The previous key still verifies what it signed (rotation grace).
	older, _ := New("", []string{"X-Tenant"}, [][]byte{old})
	older.Sign(out, now, "203.0.113.9", "req-1", "")
	in.Header.Set(DefaultHeader, out.Header.Get(DefaultHeader))
	if err := Verify(in, "", []string{"X-Tenant"}, keys, 5*time.Minute, now); err != nil {
		t.Fatalf("previous key: %v", err)
	}
	s.Sign(out, now, "203.0.113.9", "req-1", "")
	in.Header.Set(DefaultHeader, out.Header.Get(DefaultHeader))
	cases := []struct {
		name   string
		mutate func()
		want   error
	}{
		{"expired", func() {}, ErrExpired},
		{"tampered path", func() { in.URL.Path = "/api/other" }, ErrMismatch},
		{"tampered client", func() { in.Header.Set("X-Real-Ip", "10.0.0.1") }, ErrMismatch},
		{"tampered included header", func() { in.Header.Set("X-Tenant", "other") }, ErrMismatch},
		{"tampered method", func() { in.Method = "DELETE" }, ErrMismatch},
		{"unknown key", func() {}, ErrUnknownKey},
		{"missing", func() { in.Header.Del(DefaultHeader) }, ErrMissing},
		{"malformed", func() { in.Header.Set(DefaultHeader, "v1;garbage") }, ErrMalformed},
	}
	for _, c := range cases {
		fresh := in.Clone(in.Context())
		in2 := fresh
		verifyKeys := keys
		at := now.Add(time.Minute)
		switch c.name {
		case "expired":
			at = now.Add(10 * time.Minute)
		case "unknown key":
			verifyKeys = [][]byte{[]byte("another-key-another-key-another-")}
		}
		saved := in
		in = in2
		c.mutate()
		err := Verify(in, "", []string{"X-Tenant"}, verifyKeys, 5*time.Minute, at)
		in = saved
		if !errors.Is(err, c.want) {
			t.Errorf("%s: got %v want %v", c.name, err, c.want)
		}
	}
	if _, err := New("", nil, [][]byte{[]byte("short")}); err == nil {
		t.Fatal("short key accepted")
	}
	if KeyID(cur) == KeyID(old) || len(KeyID(cur)) != 8 {
		t.Fatal("key ids")
	}
}

// Without a body digest a signature proves that a request passed
// through the proxy, not what it carried: anything that can reach the
// origin can replay a captured header set with a body of its own while
// the timestamp is inside the TTL.
func TestBodyDigestBindsTheBody(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	key := bytes.Repeat([]byte{7}, 32)
	s, err := New("", nil, [][]byte{key})
	if err != nil {
		t.Fatal(err)
	}
	s.Digest = true
	body := []byte(`{"amount":1}`)
	out := httptest.NewRequest("POST", "http://pool/pay", bytes.NewReader(body))
	out.Host = "app.internal"
	s.Sign(out, now, "203.0.113.9", "req-1", BodyDigest(body))
	sig := out.Header.Get(DefaultHeader)
	if !strings.HasSuffix(sig, ";bd=1") || out.Header.Get("Content-Digest") == "" {
		t.Fatalf("signature %q, digest %q", sig, out.Header.Get("Content-Digest"))
	}
	in := func(b []byte) *http.Request {
		r := httptest.NewRequest("POST", "http://app.internal/pay", bytes.NewReader(b))
		r.Host = "app.internal"
		r.Header.Set(DefaultHeader, sig)
		r.Header.Set("X-Real-Ip", "203.0.113.9")
		r.Header.Set("X-Request-Id", "req-1")
		return r
	}
	r := in(body)
	if err := Verify(r, "", nil, [][]byte{key}, 5*time.Minute, now); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// Verify leaves the body readable for the handler behind it.
	if got, _ := io.ReadAll(r.Body); !bytes.Equal(got, body) {
		t.Fatalf("body after verification: %q", got)
	}
	// The same headers with another body do not verify.
	if err := Verify(in([]byte(`{"amount":1000000}`)), "", nil, [][]byte{key}, 5*time.Minute, now); err == nil {
		t.Fatal("a replayed header set with a different body verified")
	}
	// Stripping the bd marker does not turn the check off: the digest is
	// part of what was signed.
	stripped := in(body)
	stripped.Header.Set(DefaultHeader, strings.TrimSuffix(sig, ";bd=1"))
	if err := Verify(stripped, "", nil, [][]byte{key}, 5*time.Minute, now); err == nil {
		t.Fatal("dropping bd=1 turned the body digest off")
	}
}
