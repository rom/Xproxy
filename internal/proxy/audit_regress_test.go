package proxy

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// Regression tests for the findings of the security audit.

// TestOriginCheckRejectsRetargetingPath: an operator-supplied probe path is
// built structurally, so "@host" or "?..." cannot retarget the probe.
func TestOriginCheckRejectsRetargetingPath(t *testing.T) {
	secretFile := filepath.Join(t.TempDir(), "origin.secret")
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	defer origin.Close()
	s, _ := startServer(t, "version: 1\nserver:\n  listeners: [{name: main, address: \"127.0.0.1:0\"}]\nlogging: {access: {enabled: false}}\nupstreams:\n  - name: locked\n    origin_signature: {secret_file: "+secretFile+"}\n    endpoints: [{address: \""+hostOf(origin)+"\"}]\nroutes:\n  - {name: r, upstream: locked}\n")
	for _, bad := range []string{"@evil.test/", "?x=1", "/a#b", "nope"} {
		res, err := s.OriginCheck("locked", "", bad)
		if err != nil {
			t.Fatal(err)
		}
		if len(res) != 1 || res[0].Verdict != "unreachable" || !strings.Contains(res[0].UnsignedError, "must start with /") {
			t.Fatalf("path %q: %+v", bad, res)
		}
	}
}

// TestCORSAnyWithCredentialsFailsClosed: the runtime never reflects an
// arbitrary origin with credentials, even if such a policy were compiled.
func TestCORSAnyWithCredentialsFailsClosed(t *testing.T) {
	cc := &compiledCORS{any: true, credentials: true, exact: map[string]bool{}}
	if v, ok := cc.allowedOrigin("https://evil.test"); ok || v != "" {
		t.Fatalf("reflected %q %v", v, ok)
	}
	cc.credentials = false
	if v, ok := cc.allowedOrigin("https://evil.test"); !ok || v != "*" {
		t.Fatalf("any without credentials: %q %v", v, ok)
	}
}

// TestShadowHeaderDiffRedactsSecrets: differing cookie or token headers are
// reported without their values.
func TestShadowHeaderDiffRedactsSecrets(t *testing.T) {
	d := headerDiff(map[string]string{"Set-Cookie": "sid=live"}, map[string]string{"Set-Cookie": "sid=shadow"})
	if strings.Contains(d, "sid=") || !strings.Contains(d, "redacted") {
		t.Fatalf("cookie value leaked: %q", d)
	}
	d = headerDiff(map[string]string{"Content-Type": "a"}, map[string]string{"Content-Type": "b"})
	if !strings.Contains(d, `live="a"`) {
		t.Fatalf("plain header not shown: %q", d)
	}
}
