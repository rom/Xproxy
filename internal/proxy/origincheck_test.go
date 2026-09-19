package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/originsig"
	"github.com/rom/xproxy/internal/secret"
)

const originCheckYAML = `
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
upstreams:
  - name: locked
    origin_signature: {secret_file: %s}
    endpoints: [{address: "%s"}]
routes:
  - {name: r, upstream: locked}
`

func TestOriginCheck(t *testing.T) {
	secretFile := filepath.Join(t.TempDir(), "origin.secret")
	ring, err := secret.LoadOrCreate(secretFile)
	if err != nil {
		t.Fatal(err)
	}
	keys := ring.All()

	// An enforcing origin: it verifies the signature and refuses without one.
	enforcing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := originsig.Verify(r, "", nil, keys, 5*time.Minute, time.Now()); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer enforcing.Close()

	s, _ := startServer(t, fmt.Sprintf(originCheckYAML, secretFile, hostOf(enforcing)))
	res, err := s.OriginCheck("locked", "", "/")
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 {
		t.Fatalf("results %+v", res)
	}
	if res[0].Verdict != "enforced" {
		t.Fatalf("verdict %+v", res[0])
	}
	if res[0].UnsignedStatus != 401 || res[0].SignedStatus != 200 {
		t.Fatalf("statuses %+v", res[0])
	}
}

func TestOriginCheckNotEnforced(t *testing.T) {
	secretFile := filepath.Join(t.TempDir(), "origin.secret")
	// An origin that serves everything, signed or not.
	open := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer open.Close()

	s, _ := startServer(t, fmt.Sprintf(originCheckYAML, secretFile, hostOf(open)))
	res, err := s.OriginCheck("", "", "/")
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || res[0].Verdict != "not_enforced" {
		t.Fatalf("verdict %+v", res)
	}

	// Naming an upstream without a signature is an error.
	if _, err := s.OriginCheck("nope", "", "/"); err == nil {
		t.Fatal("unknown upstream accepted")
	}
}

func hostOf(s *httptest.Server) string {
	return s.Listener.Addr().String()
}
