package http

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/filters/apikey"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/mfa"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/scim"
)

// scimFiles writes the files a provisioning endpoint needs and returns
// the directory and the token.
func scimFiles(t *testing.T) (dir, token string) {
	t.Helper()
	dir = t.TempDir()
	token = "provisioning-token-0123456789"
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mfa.users"), []byte("# enrolments\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "api-keys"), []byte("# keys\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, token
}

func scimYAML(t *testing.T, backend, dir, section string) string {
	t.Helper()
	return fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
upstreams:
  - {name: app, endpoints: [{address: %s}]}
routes:
  # A route that would match the provisioning path if the endpoint did
  # not answer first, which is the thing being checked.
  - {name: app, upstream: app}
scim:
  token_file: %s/token
  state_file: %s/scim-users
  mfa_users_file: %s/mfa.users
  keys_file: %s/api-keys
  key_scopes: [orders:read]
%s`, backend, dir, dir, dir, dir, section)
}

// End to end through a listener: the provider creates a user, the
// credentials land in the files the rest of the proxy reads, and the
// route that would otherwise match the path never sees the request.
func TestTheProvisioningEndpointAnswersBeforeRouting(t *testing.T) {
	b := newBackend(t, "app")
	dir, token := scimFiles(t)
	srv, url := startServer(t, scimYAML(t, b.addr(), dir, "  client_cidrs: [127.0.0.0/8]\n"))

	req, _ := http.NewRequest(http.MethodPost, url+"/scim/v2/Users",
		strings.NewReader(fmt.Sprintf(`{"schemas":["%s"],"userName":"alice"}`, scim.SchemaUser)))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", scim.ContentType)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create answered %d: %s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Content-Type"); got != scim.ContentType {
		t.Errorf("content type %q, want %s", got, scim.ContentType)
	}
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "/scim/v2/Users/") {
		t.Errorf("Location %q", loc)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	id, _ := doc["id"].(string)
	if id == "" {
		t.Fatalf("no id: %s", body)
	}
	// The backend never saw any of it.
	if n := b.hits.Load(); n != 0 {
		t.Errorf("the backend was reached %d times by a provisioning request", n)
	}
	// The credentials are in the files.
	users, err := mfa.LoadProvisioning(filepath.Join(dir, "mfa.users"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := users.Get("alice"); !ok {
		t.Error("no enrolment was written")
	}
	keys, err := apikey.Load(filepath.Join(dir, "api-keys"))
	if err != nil || len(keys) != 1 {
		t.Fatalf("keys %v, err %v", keys, err)
	}
	if st := srv.Stats(); st.SCIMRequests != 1 || st.SCIMDenied != 0 {
		t.Errorf("counters: %d requests, %d denied", st.SCIMRequests, st.SCIMDenied)
	}

	// The leaver, over the wire.
	req, _ = http.NewRequest(http.MethodDelete, url+"/scim/v2/Users/"+id, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete answered %d", resp.StatusCode)
	}
	users, err = mfa.LoadProvisioning(filepath.Join(dir, "mfa.users"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := users.Get("alice"); ok {
		t.Error("the enrolment survived the delete")
	}
	keys, _ = apikey.Load(filepath.Join(dir, "api-keys"))
	if len(keys) != 1 || keys[0].State != "revoked" {
		t.Errorf("keys after the delete: %v", keys)
	}
}

// A client the selectors do not admit is answered 404 and not routed on:
// the path belongs to the endpoint, and a proxied application must not
// receive a request meant for the control plane.
func TestAClientOutsideTheListIsNotRoutedOn(t *testing.T) {
	b := newBackend(t, "app")
	dir, token := scimFiles(t)
	srv, url := startServer(t, scimYAML(t, b.addr(), dir, "  client_cidrs: [10.0.0.0/8]\n"))
	req, _ := http.NewRequest(http.MethodGet, url+"/scim/v2/Users", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("a client outside the list answered %d, want 404", resp.StatusCode)
	}
	if n := b.hits.Load(); n != 0 {
		t.Errorf("the request reached the backend %d times", n)
	}
	if st := srv.Stats(); st.SCIMDenied != 1 {
		t.Errorf("refusals counted: %d", st.SCIMDenied)
	}
}

// A request with no token, or the wrong one, is refused and counted, and
// the ban list hears about it: somebody trying tokens against a
// provisioning endpoint is not a client making a mistake twice.
func TestAWrongTokenIsRefusedAndObserved(t *testing.T) {
	b := newBackend(t, "app")
	dir, _ := scimFiles(t)
	// A trigger with a threshold of two, so the second attempt is a ban:
	// the claim is that the refusal reaches the ban list at all.
	bans := fmt.Sprintf(`
bans:
  state_file: %s/bans.db
  triggers:
    - {name: scim-probing, reasons: [scim], threshold: 2, window: 5m, duration: 10m}
`, dir)
	srv, url := startServer(t, scimYAML(t, b.addr(), dir, "  client_cidrs: [127.0.0.0/8]\n")+bans)
	for _, auth := range []string{"", "Bearer wrong-token-wrong-token"} {
		req, _ := http.NewRequest(http.MethodGet, url+"/scim/v2/Users", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("auth %q answered %d: %s", auth, resp.StatusCode, body)
		}
	}
	if st := srv.Stats(); st.SCIMDenied != 2 {
		t.Errorf("refusals counted: %d", st.SCIMDenied)
	}
	if active, _ := srv.Bans().Stats(); active == 0 {
		t.Error("guessing tokens against the provisioning endpoint did not reach the ban list")
	}
}

// The host selector decides too, and a host it does not name falls to
// the same refusal rather than to the routes.
func TestTheHostSelectorDecides(t *testing.T) {
	b := newBackend(t, "app")
	dir, token := scimFiles(t)
	_, url := startServer(t, scimYAML(t, b.addr(), dir,
		"  hosts: [admin.test]\n  client_cidrs: [127.0.0.0/8]\n"))
	get := func(host string) int {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, url+"/scim/v2/Users", nil)
		req.Host = host
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if code := get("admin.test"); code != http.StatusOK {
		t.Errorf("the named host answered %d, want 200", code)
	}
	if code := get("app.test"); code != http.StatusNotFound {
		t.Errorf("another host answered %d, want 404", code)
	}
}

// A configuration the endpoint cannot serve fails the load rather than
// the first provisioning request.
func TestTheEndpointFailsTheLoadWhenItCannotServe(t *testing.T) {
	b := newBackend(t, "app")
	dir, _ := scimFiles(t)
	short := filepath.Join(dir, "short-token")
	if err := os.WriteFile(short, []byte("tiny\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	yaml := strings.Replace(scimYAML(t, b.addr(), dir, ""), dir+"/token", short, 1)
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	if _, err := proxy.New(cfg, logging.Discard()); err == nil || !strings.Contains(err.Error(), "at least 16") {
		t.Errorf("a short token loaded: %v", err)
	}
}
