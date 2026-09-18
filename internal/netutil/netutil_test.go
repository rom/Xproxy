package netutil

import (
	"net/http"
	"net/netip"
	"strings"
	"testing"
)

func TestClientIP(t *testing.T) {
	trusted := ParsePrefixes([]string{"10.0.0.0/8"})
	mk := func(remote string, xff ...string) *http.Request {
		r := &http.Request{RemoteAddr: remote, Header: http.Header{}}
		for _, v := range xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		return r
	}
	cases := []struct {
		r    *http.Request
		want string
	}{
		{mk("1.2.3.4:5"), "1.2.3.4"},
		{mk("1.2.3.4:5", "9.9.9.9"), "1.2.3.4"}, // untrusted peer, header ignored
		{mk("10.1.1.1:5", "9.9.9.9"), "9.9.9.9"},
		{mk("10.1.1.1:5", "8.8.8.8, 9.9.9.9"), "9.9.9.9"},
		{mk("10.1.1.1:5", "8.8.8.8, 10.2.2.2"), "8.8.8.8"},
		{mk("10.1.1.1:5", "garbage, 10.2.2.2"), "10.1.1.1"},
		{mk("10.1.1.1:5", "10.2.2.2"), "10.1.1.1"},
		{mk("[::ffff:10.1.1.1]:5", "2001:db8::1"), "2001:db8::1"},
		{mk("10.1.1.1:5", "8.8.8.8", "9.9.9.9"), "9.9.9.9"},
	}
	for i, c := range cases {
		got := ClientIP(c.r, trusted)
		if got != netip.MustParseAddr(c.want) {
			t.Errorf("case %d: got %v want %v", i, got, c.want)
		}
	}
	if ClientIP(mk("1.2.3.4:5", "9.9.9.9"), nil).String() != "1.2.3.4" {
		t.Error("no trusted proxies must ignore XFF")
	}
}

func TestCleanPath(t *testing.T) {
	cases := map[string]string{
		"":                  "/",
		"/":                 "/",
		"/a/../b":           "/b",
		"/a/./b/":           "/a/b/",
		"//a//b":            "/a/b",
		"a":                 "/a",
		"/admin/../public":  "/public",
		"/../../etc/passwd": "/etc/passwd",
		"/x/":               "/x/",
	}
	for in, want := range cases {
		if got := CleanPath(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestHost(t *testing.T) {
	cases := map[string]string{
		"Example.COM":      "example.com",
		"example.com:8443": "example.com",
		"example.com.":     "example.com",
		"[::1]:443":        "[::1]",
		"[::1":             "",
		"bad host":         "",
		"":                 "",
		"a\r\nb":           "",
	}
	for in, want := range cases {
		if got := Host(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func FuzzCleanPath(f *testing.F) {
	f.Add("/a/../b")
	f.Fuzz(func(t *testing.T, s string) {
		out := CleanPath(s)
		if out == "" || out[0] != '/' {
			t.Fatalf("bad output %q for %q", out, s)
		}
	})
}

func FuzzHost(f *testing.F) {
	f.Add("example.com:443")
	f.Fuzz(func(t *testing.T, s string) {
		_ = Host(s)
	})
}

// TestHostEdges pins boundaries mutation testing found unobserved.
func TestHostEdges(t *testing.T) {
	long := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	if len(long) != 253 {
		t.Fatalf("length %d", len(long))
	}
	cases := map[string]string{
		":80":              "",
		"az09-_.example":   "az09-_.example",
		"A.Z":              "a.z",
		long:               long,
		long + "a":         "",
		"[":                "",
		"[::1]:443":        "[::1]",
		"[::1]":            "[::1]",
		"example.com:8080": "example.com",
		"a{b}.example":     "",
	}
	for in, want := range cases {
		if got := Host(in); got != want {
			t.Errorf("Host(%q) = %q, want %q", in, got, want)
		}
	}
}
