package originsig

import (
	"errors"
	"net/http/httptest"
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
	s.Sign(out, now, "203.0.113.9", "req-1")
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
	older.Sign(out, now, "203.0.113.9", "req-1")
	in.Header.Set(DefaultHeader, out.Header.Get(DefaultHeader))
	if err := Verify(in, "", []string{"X-Tenant"}, keys, 5*time.Minute, now); err != nil {
		t.Fatalf("previous key: %v", err)
	}
	s.Sign(out, now, "203.0.113.9", "req-1")
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
