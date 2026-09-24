package scim

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/filters/apikey"
	"github.com/rom/xproxy/internal/mfa"
)

const token = "a-provisioning-token-16+"

func tokenHash(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

// harness is an endpoint over real files: a state file, an enrolment
// file and a keys file, so a test says what is in them afterwards rather
// than what a fake was asked to do.
type harness struct {
	h         *Handler
	p         *Provisioner
	state     string
	usersFile string
	keysFile  string
	users     *mfa.Store
}

func newHarness(t *testing.T, secrets bool) *harness {
	t.Helper()
	dir := t.TempDir()
	usersFile := filepath.Join(dir, "mfa.users")
	if err := os.WriteFile(usersFile, []byte("# enrolments\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	keysFile := filepath.Join(dir, "api-keys")
	if err := os.WriteFile(keysFile, []byte("# keys\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	users, err := mfa.LoadProvisioning(usersFile)
	if err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "scim-users")
	p, err := NewProvisioner(Options{StateFile: state, MFA: users, KeysFile: keysFile,
		Issuer: "estate", KeyScopes: []string{"orders:read"}, KeyTTL: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(Config{Base: "/scim/v2", TokenHash: tokenHash(token), ReturnSecrets: secrets}, p)
	if err != nil {
		t.Fatal(err)
	}
	return &harness{h: h, p: p, state: state, usersFile: usersFile, keysFile: keysFile, users: users}
}

// do sends one request with the token unless withoutToken is set.
func (hh *harness) do(t *testing.T, method, path, body string, hdr ...string) (int, map[string]any, Outcome) {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, "http://admin.test"+path, nil)
	} else {
		r = httptest.NewRequest(method, "http://admin.test"+path, strings.NewReader(body))
	}
	r.Header.Set("Authorization", "Bearer "+token)
	for i := 0; i+1 < len(hdr); i += 2 {
		if hdr[i+1] == "" {
			r.Header.Del(hdr[i])
			continue
		}
		r.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	out := hh.h.Serve(w, r)
	var doc map[string]any
	if w.Body.Len() > 0 {
		if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
			t.Fatalf("%s %s: body is not JSON: %v: %s", method, path, err, w.Body.String())
		}
	}
	return w.Code, doc, out
}

func userBody(name string, extra string) string {
	return fmt.Sprintf(`{"schemas":["%s"],"userName":%q%s}`, SchemaUser, name, extra)
}

// The whole point, end to end: the joiner is provisioned, the leaver's
// credentials are gone.
func TestAJoinerIsProvisionedAndALeaverIsNot(t *testing.T) {
	hh := newHarness(t, true)
	code, doc, out := hh.do(t, http.MethodPost, "/scim/v2/Users", userBody("alice@example.com", `,"externalId":"dir-1"`))
	if code != http.StatusCreated {
		t.Fatalf("create answered %d: %v", code, doc)
	}
	if out.Op != "create" || out.User != "alice@example.com" {
		t.Errorf("outcome %+v", out)
	}
	id, _ := doc["id"].(string)
	if id == "" {
		t.Fatal("the create returned no id")
	}
	ext, _ := doc[SchemaExtension].(map[string]any)
	if ext == nil {
		t.Fatalf("no extension attributes: %v", doc)
	}
	if enrolled, _ := ext["mfaEnrolled"].(bool); !enrolled {
		t.Error("the user was created without an enrolment")
	}
	secrets, _ := ext["secrets"].(map[string]any)
	if secrets == nil {
		t.Fatal("the create returned no secrets although they are enabled")
	}
	if uri, _ := secrets["otpauthUri"].(string); !strings.HasPrefix(uri, "otpauth://totp/estate:alice@example.com?") {
		t.Errorf("otpauth URI %q", uri)
	}
	plain, _ := secrets["apiKey"].(string)
	if !strings.HasPrefix(plain, apikey.KeyPrefix) {
		t.Errorf("api key %q", plain)
	}
	// The credentials are in the files the rest of the proxy reads.
	if _, ok := hh.users.Get("alice@example.com"); !ok {
		t.Error("the enrolment file has no entry for the user")
	}
	keys, err := apikey.Load(hh.keysFile)
	if err != nil || len(keys) != 1 || keys[0].State != "active" {
		t.Fatalf("keys %v, err %v", keys, err)
	}
	if got := keys[0].Scopes; len(got) != 1 || got[0] != "orders:read" {
		t.Errorf("scopes %v, want the configured default", got)
	}

	// The leaver: one PATCH, and nothing is left.
	code, doc, out = hh.do(t, http.MethodPatch, "/scim/v2/Users/"+id,
		fmt.Sprintf(`{"schemas":["%s"],"Operations":[{"op":"replace","value":{"active":false}}]}`, SchemaPatchOp))
	if code != http.StatusOK {
		t.Fatalf("patch answered %d: %v", code, doc)
	}
	if out.Op != "patch" || out.User != "alice@example.com" {
		t.Errorf("outcome %+v", out)
	}
	if active, _ := doc["active"].(bool); active {
		t.Error("the user is still active after a deactivation")
	}
	if _, ok := hh.users.Get("alice@example.com"); ok {
		t.Error("the enrolment survived the deactivation")
	}
	keys, err = apikey.Load(hh.keysFile)
	if err != nil || len(keys) != 1 || keys[0].State != "revoked" {
		t.Fatalf("after deactivation: keys %v, err %v", keys, err)
	}
	// And the resource is still there to be read, which is what the
	// state file is for.
	code, doc, _ = hh.do(t, http.MethodGet, "/scim/v2/Users/"+id, "")
	if code != http.StatusOK {
		t.Fatalf("get after deactivation answered %d: %v", code, doc)
	}
	ext, _ = doc[SchemaExtension].(map[string]any)
	if enrolled, _ := ext["mfaEnrolled"].(bool); enrolled {
		t.Error("the resource still reports an enrolment")
	}
	if ids, _ := ext["apiKeyIds"].([]any); len(ids) != 0 {
		t.Errorf("the resource still reports active keys: %v", ids)
	}
}

// A delete deprovisions and forgets.
func TestADeleteDeprovisionsAndForgets(t *testing.T) {
	hh := newHarness(t, false)
	_, doc, _ := hh.do(t, http.MethodPost, "/scim/v2/Users", userBody("bob", ""))
	id, _ := doc["id"].(string)
	code, _, out := hh.do(t, http.MethodDelete, "/scim/v2/Users/"+id, "")
	if code != http.StatusNoContent {
		t.Fatalf("delete answered %d", code)
	}
	if out.User != "bob" {
		t.Errorf("the log does not name who was deprovisioned: %+v", out)
	}
	if _, ok := hh.users.Get("bob"); ok {
		t.Error("the enrolment survived the delete")
	}
	keys, _ := apikey.Load(hh.keysFile)
	if len(keys) != 1 || keys[0].State != "revoked" {
		t.Errorf("keys after delete: %v", keys)
	}
	if code, _, _ := hh.do(t, http.MethodGet, "/scim/v2/Users/"+id, ""); code != http.StatusNotFound {
		t.Errorf("the deleted resource answered %d, want 404", code)
	}
}

// Secrets are not in a response unless the configuration says so: they
// end up in the provider's logs, which is a decision an operator makes.
func TestSecretsAreWithheldUnlessConfigured(t *testing.T) {
	hh := newHarness(t, false)
	_, doc, _ := hh.do(t, http.MethodPost, "/scim/v2/Users", userBody("carol", ""))
	ext, _ := doc[SchemaExtension].(map[string]any)
	if _, ok := ext["secrets"]; ok {
		t.Errorf("the response carries secrets: %v", ext)
	}
	// The credentials were still made: withholding them is not not doing
	// the work.
	if _, ok := hh.users.Get("carol"); !ok {
		t.Error("no enrolment was made")
	}
}

// Without the token nothing happens at all, and the store is not even
// asked: a provisioning endpoint is not a place to learn which names
// exist.
func TestWithoutTheTokenNothingIsAnswered(t *testing.T) {
	hh := newHarness(t, false)
	r := httptest.NewRequest(http.MethodGet, "http://admin.test/scim/v2/Users", nil)
	w := httptest.NewRecorder()
	out := hh.h.Serve(w, r)
	if w.Code != http.StatusUnauthorized || out.Denied != "no_token" {
		t.Errorf("no token: %d %+v", w.Code, out)
	}
	if got := w.Header().Get("WWW-Authenticate"); !strings.HasPrefix(got, "Bearer ") {
		t.Errorf("no challenge header: %q", got)
	}
	r = httptest.NewRequest(http.MethodGet, "http://admin.test/scim/v2/Users", nil)
	r.Header.Set("Authorization", "Bearer "+token+"x")
	w = httptest.NewRecorder()
	out = hh.h.Serve(w, r)
	if w.Code != http.StatusUnauthorized || out.Denied != "bad_token" {
		t.Errorf("wrong token: %d %+v", w.Code, out)
	}
	// A token that is a prefix of the right one is not the right one.
	r = httptest.NewRequest(http.MethodGet, "http://admin.test/scim/v2/Users", nil)
	r.Header.Set("Authorization", "Bearer "+token[:len(token)-1])
	w = httptest.NewRecorder()
	if out = hh.h.Serve(w, r); w.Code != http.StatusUnauthorized {
		t.Errorf("a short token answered %d %+v", w.Code, out)
	}
}

// The same name twice is a conflict, not a second enrolment that
// replaces the first: the directory learns that the user is there.
func TestASecondCreateOfTheSameNameConflicts(t *testing.T) {
	hh := newHarness(t, false)
	if code, _, _ := hh.do(t, http.MethodPost, "/scim/v2/Users", userBody("dave", "")); code != http.StatusCreated {
		t.Fatalf("first create answered %d", code)
	}
	code, doc, _ := hh.do(t, http.MethodPost, "/scim/v2/Users", userBody("dave", ""))
	if code != http.StatusConflict {
		t.Fatalf("second create answered %d: %v", code, doc)
	}
	if got, _ := doc["scimType"].(string); got != TypeUniqueness {
		t.Errorf("scimType %q, want %s", got, TypeUniqueness)
	}
}

// A list is filtered by name, and a filter this endpoint cannot read is
// refused rather than answered with everybody -- which is the trap: a
// provider filtering on externalId would read the first user of the list
// as its match.
func TestTheListFilterIsReadOrRefused(t *testing.T) {
	hh := newHarness(t, false)
	for _, name := range []string{"eve", "frank"} {
		if code, _, _ := hh.do(t, http.MethodPost, "/scim/v2/Users", userBody(name, "")); code != http.StatusCreated {
			t.Fatalf("create %s answered %d", name, code)
		}
	}
	code, doc, _ := hh.do(t, http.MethodGet, `/scim/v2/Users?filter=userName+eq+%22eve%22`, "")
	if code != http.StatusOK {
		t.Fatalf("filtered list answered %d: %v", code, doc)
	}
	if total, _ := doc["totalResults"].(float64); total != 1 {
		t.Errorf("totalResults %v, want 1", total)
	}
	for _, f := range []string{
		// Another attribute.
		`externalId+eq+%22dir-1%22`,
		// Another operator.
		`userName+co+%22ev%22`,
		// A second comparison, which this endpoint does not apply: a
		// filter half read is a filter answered wrongly.
		`userName+eq+%22eve%22+and+active+eq+true`,
		// Not a quoted value.
		`userName+eq+eve`,
		// An empty name matches nobody and is not what the provider
		// meant.
		`userName+eq+%22%22`,
	} {
		code, doc, _ = hh.do(t, http.MethodGet, "/scim/v2/Users?filter="+f, "")
		if code != http.StatusBadRequest {
			t.Errorf("filter %s answered %d: %v", f, code, doc)
			continue
		}
		if got, _ := doc["scimType"].(string); got != TypeInvalidFilter {
			t.Errorf("filter %s: scimType %q, want %s", f, got, TypeInvalidFilter)
		}
	}
	// The whole list, paged.
	code, doc, _ = hh.do(t, http.MethodGet, "/scim/v2/Users?count=1", "")
	if code != http.StatusOK {
		t.Fatalf("list answered %d", code)
	}
	if total, _ := doc["totalResults"].(float64); total != 2 {
		t.Errorf("totalResults %v, want 2", total)
	}
	if per, _ := doc["itemsPerPage"].(float64); per != 1 {
		t.Errorf("itemsPerPage %v, want the page asked for", per)
	}
	res, _ := doc["Resources"].([]any)
	if len(res) != 1 {
		t.Fatalf("%d resources on a page of one", len(res))
	}
	code, doc, _ = hh.do(t, http.MethodGet, "/scim/v2/Users?count=1&startIndex=2", "")
	if code != http.StatusOK {
		t.Fatalf("second page answered %d", code)
	}
	res, _ = doc["Resources"].([]any)
	if len(res) != 1 {
		t.Fatalf("%d resources on the second page", len(res))
	}
	first, _ := res[0].(map[string]any)
	if name, _ := first["userName"].(string); name != "frank" {
		t.Errorf("the second page holds %q, want frank", name)
	}
}

// What cannot be changed here says so, rather than answering 200 and
// changing nothing: a rename would leave the credentials keyed on the
// old name.
func TestAnImmutableAttributeIsRefused(t *testing.T) {
	hh := newHarness(t, false)
	_, doc, _ := hh.do(t, http.MethodPost, "/scim/v2/Users", userBody("grace", ""))
	id, _ := doc["id"].(string)
	code, doc, _ := hh.do(t, http.MethodPut, "/scim/v2/Users/"+id, userBody("grace2", ""))
	if code != http.StatusBadRequest {
		t.Fatalf("a rename answered %d: %v", code, doc)
	}
	if got, _ := doc["scimType"].(string); got != TypeMutability {
		t.Errorf("scimType %q, want %s", got, TypeMutability)
	}
	code, doc, _ = hh.do(t, http.MethodPatch, "/scim/v2/Users/"+id,
		fmt.Sprintf(`{"schemas":["%s"],"Operations":[{"op":"replace","path":"userName","value":"grace2"}]}`, SchemaPatchOp))
	if code != http.StatusBadRequest {
		t.Fatalf("a patched rename answered %d: %v", code, doc)
	}
	// Named as what it is: the attribute exists and cannot be changed,
	// which is a different thing from a path this endpoint never heard
	// of, and the provider's operator reads the difference.
	if got, _ := doc["scimType"].(string); got != TypeMutability {
		t.Errorf("a patched rename: scimType %q, want %s", got, TypeMutability)
	}
	// The same, with the schema URN in front of the attribute, which is
	// how some providers spell a path.
	code, doc, _ = hh.do(t, http.MethodPatch, "/scim/v2/Users/"+id,
		fmt.Sprintf(`{"schemas":["%s"],"Operations":[{"op":"replace","path":"%s:userName","value":"grace2"}]}`, SchemaPatchOp, SchemaUser))
	if code != http.StatusBadRequest {
		t.Errorf("a qualified rename answered %d: %v", code, doc)
	}
	if got, _ := doc["scimType"].(string); got != TypeMutability {
		t.Errorf("a qualified rename: scimType %q, want %s", got, TypeMutability)
	}
	// And the user is untouched.
	if _, ok := hh.users.Get("grace"); !ok {
		t.Error("the original enrolment is gone")
	}
}

// Reactivating mints fresh credentials, because the old secret is gone:
// this is documented, and it is what the test holds.
func TestReactivationMintsNewCredentials(t *testing.T) {
	hh := newHarness(t, true)
	_, doc, _ := hh.do(t, http.MethodPost, "/scim/v2/Users", userBody("heidi", ""))
	id, _ := doc["id"].(string)
	ext, _ := doc[SchemaExtension].(map[string]any)
	secrets, _ := ext["secrets"].(map[string]any)
	firstKey, _ := secrets["apiKey"].(string)

	off := fmt.Sprintf(`{"schemas":["%s"],"Operations":[{"op":"replace","path":"active","value":false}]}`, SchemaPatchOp)
	if code, _, _ := hh.do(t, http.MethodPatch, "/scim/v2/Users/"+id, off); code != http.StatusOK {
		t.Fatalf("deactivation answered %d", code)
	}
	on := fmt.Sprintf(`{"schemas":["%s"],"Operations":[{"op":"replace","path":"active","value":true}]}`, SchemaPatchOp)
	code, doc, _ := hh.do(t, http.MethodPatch, "/scim/v2/Users/"+id, on)
	if code != http.StatusOK {
		t.Fatalf("reactivation answered %d: %v", code, doc)
	}
	ext, _ = doc[SchemaExtension].(map[string]any)
	secrets, _ = ext["secrets"].(map[string]any)
	secondKey, _ := secrets["apiKey"].(string)
	if secondKey == "" || secondKey == firstKey {
		t.Errorf("reactivation returned %q, want a key that is not the revoked one", secondKey)
	}
	if _, ok := hh.users.Get("heidi"); !ok {
		t.Error("reactivation did not enrol the user again")
	}
	keys, _ := apikey.Load(hh.keysFile)
	active := 0
	for _, k := range keys {
		if k.State == "active" {
			active++
		}
	}
	if active != 1 || len(keys) != 2 {
		t.Errorf("%d keys, %d active: the revoked one must stay as the record", len(keys), active)
	}
}

// The state file is the record, and it is read back: a restart, or
// another process, sees the same users.
func TestTheStateFileIsTheRecord(t *testing.T) {
	hh := newHarness(t, false)
	if code, _, _ := hh.do(t, http.MethodPost, "/scim/v2/Users", userBody("ivan", "")); code != http.StatusCreated {
		t.Fatal("create failed")
	}
	data, err := os.ReadFile(hh.state)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "|ivan|") {
		t.Errorf("the state file does not hold the user: %s", data)
	}
	if info, err := os.Stat(hh.state); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("state file mode %v (err %v), want 0600", info.Mode().Perm(), err)
	}
	// A second provisioner over the same file reads it.
	p2, err := NewProvisioner(Options{StateFile: hh.state, MFA: hh.users, KeysFile: hh.keysFile})
	if err != nil {
		t.Fatal(err)
	}
	users, err := p2.List("")
	if err != nil || len(users) != 1 || users[0].UserName != "ivan" {
		t.Fatalf("second reader saw %v (err %v)", users, err)
	}
}

// The discovery endpoints a provider fetches before it provisions.
func TestDiscoveryDescribesWhatIsImplemented(t *testing.T) {
	hh := newHarness(t, false)
	code, doc, out := hh.do(t, http.MethodGet, "/scim/v2/ServiceProviderConfig", "")
	if code != http.StatusOK || out.Op != "discovery" {
		t.Fatalf("service provider config: %d %+v", code, out)
	}
	patch, _ := doc["patch"].(map[string]any)
	if supported, _ := patch["supported"].(bool); !supported {
		t.Error("PATCH is implemented and the configuration says it is not")
	}
	bulk, _ := doc["bulk"].(map[string]any)
	if supported, _ := bulk["supported"].(bool); supported {
		t.Error("bulk is not implemented and the configuration says it is")
	}
	filter, _ := doc["filter"].(map[string]any)
	if maxResults, _ := filter["maxResults"].(float64); maxResults != DefaultMaxResults {
		t.Errorf("maxResults %v, want the configured bound", maxResults)
	}
	if code, doc, _ = hh.do(t, http.MethodGet, "/scim/v2/ResourceTypes", ""); code != http.StatusOK {
		t.Fatalf("resource types: %d", code)
	}
	if total, _ := doc["totalResults"].(float64); total != 1 {
		t.Errorf("resource types: %v", doc)
	}
	if code, doc, _ = hh.do(t, http.MethodGet, "/scim/v2/Schemas", ""); code != http.StatusOK {
		t.Fatalf("schemas: %d", code)
	}
	if total, _ := doc["totalResults"].(float64); total != 2 {
		t.Errorf("schemas: %v", doc)
	}
}

// What the endpoint refuses by shape, each with the status the RFC gives
// it.
func TestBadRequestsAreRefusedByName(t *testing.T) {
	hh := newHarness(t, false)
	_, doc, _ := hh.do(t, http.MethodPost, "/scim/v2/Users", userBody("judy", ""))
	id, _ := doc["id"].(string)
	for _, tc := range []struct {
		name, method, path, body string
		want                     int
		scimType                 string
	}{
		{"no such endpoint", http.MethodGet, "/scim/v2/Groups", "", http.StatusNotFound, ""},
		{"no such user", http.MethodGet, "/scim/v2/Users/0000", "", http.StatusNotFound, ""},
		{"method on the collection", http.MethodDelete, "/scim/v2/Users", "", http.StatusMethodNotAllowed, ""},
		{"method on a user", http.MethodPost, "/scim/v2/Users/" + id, "", http.StatusMethodNotAllowed, ""},
		{"no body", http.MethodPost, "/scim/v2/Users", "", http.StatusBadRequest, TypeInvalidSyntax},
		{"not a user resource", http.MethodPost, "/scim/v2/Users", `{"schemas":["wrong"],"userName":"x"}`, http.StatusBadRequest, TypeInvalidValue},
		{"an attribute nobody reads", http.MethodPost, "/scim/v2/Users",
			fmt.Sprintf(`{"schemas":["%s"],"userName":"x","roles":["admin"]}`, SchemaUser), http.StatusBadRequest, TypeInvalidSyntax},
		{"no userName", http.MethodPost, "/scim/v2/Users", fmt.Sprintf(`{"schemas":["%s"]}`, SchemaUser), http.StatusBadRequest, TypeInvalidValue},
		{"a name the files cannot hold", http.MethodPost, "/scim/v2/Users", userBody("a|b", ""), http.StatusBadRequest, TypeInvalidValue},
		{"a patch that is not one", http.MethodPatch, "/scim/v2/Users/" + id, `{"schemas":["wrong"]}`, http.StatusBadRequest, TypeInvalidValue},
		{"a patch of nothing", http.MethodPatch, "/scim/v2/Users/" + id,
			fmt.Sprintf(`{"schemas":["%s"],"Operations":[]}`, SchemaPatchOp), http.StatusBadRequest, TypeInvalidValue},
		{"a patch whose value names nothing", http.MethodPatch, "/scim/v2/Users/" + id,
			fmt.Sprintf(`{"schemas":["%s"],"Operations":[{"op":"replace","value":{}}]}`, SchemaPatchOp), http.StatusBadRequest, TypeInvalidValue},
		{"a patch with a path this endpoint keeps nothing for", http.MethodPatch, "/scim/v2/Users/" + id,
			fmt.Sprintf(`{"schemas":["%s"],"Operations":[{"op":"replace","value":{"emails":[]}}]}`, SchemaPatchOp), http.StatusBadRequest, TypeInvalidPath},
		{"active as something that is not a boolean", http.MethodPatch, "/scim/v2/Users/" + id,
			fmt.Sprintf(`{"schemas":["%s"],"Operations":[{"op":"replace","path":"active","value":7}]}`, SchemaPatchOp), http.StatusBadRequest, TypeInvalidValue},
		{"an operation this endpoint does not apply", http.MethodPatch, "/scim/v2/Users/" + id,
			fmt.Sprintf(`{"schemas":["%s"],"Operations":[{"op":"add","path":"active","value":true}]}`, SchemaPatchOp), http.StatusBadRequest, TypeInvalidSyntax},
		{"a path this endpoint does not know", http.MethodPatch, "/scim/v2/Users/" + id,
			fmt.Sprintf(`{"schemas":["%s"],"Operations":[{"op":"replace","path":"nickName","value":"j"}]}`, SchemaPatchOp), http.StatusBadRequest, TypeInvalidPath},
		{"a count that is not a number", http.MethodGet, "/scim/v2/Users?count=many", "", http.StatusBadRequest, TypeInvalidValue},
	} {
		code, doc, out := hh.do(t, tc.method, tc.path, tc.body)
		if code != tc.want {
			t.Errorf("%s: answered %d, want %d (%v)", tc.name, code, tc.want, doc)
			continue
		}
		if out.Denied == "" {
			t.Errorf("%s: the refusal is not reported: %+v", tc.name, out)
		}
		if tc.scimType != "" {
			if got, _ := doc["scimType"].(string); got != tc.scimType {
				t.Errorf("%s: scimType %q, want %s", tc.name, got, tc.scimType)
			}
		}
		if schemas, _ := doc["schemas"].([]any); len(schemas) != 1 || schemas[0] != SchemaError {
			t.Errorf("%s: the error is not a SCIM error object: %v", tc.name, doc)
		}
	}
}

// A body over the bound is refused rather than read: the endpoint is not
// a place to send a megabyte.
func TestAnOversizeBodyIsRefused(t *testing.T) {
	hh := newHarness(t, false)
	big := userBody("kate", `,"displayName":"`+strings.Repeat("x", MaxBody)+`"`)
	code, doc, _ := hh.do(t, http.MethodPost, "/scim/v2/Users", big)
	if code != http.StatusRequestEntityTooLarge {
		t.Errorf("an oversize body answered %d: %v", code, doc)
	}
}

// The location a provider follows comes from the configuration when
// there is one, because this proxy does not believe a client's own
// forwarding headers for it.
func TestTheLocationComesFromTheConfiguration(t *testing.T) {
	hh := newHarness(t, false)
	code, doc, _ := hh.do(t, http.MethodPost, "/scim/v2/Users", userBody("leo", ""))
	if code != http.StatusCreated {
		t.Fatal("create failed")
	}
	meta, _ := doc["meta"].(map[string]any)
	if loc, _ := meta["location"].(string); !strings.HasPrefix(loc, "http://admin.test/scim/v2/Users/") {
		t.Errorf("location %q, want one built from the request", loc)
	}
	ext, err := New(Config{Base: "/scim/v2", TokenHash: tokenHash(token),
		ExternalURL: "https://admin.example.com/scim/v2"}, hh.p)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "http://admin.test/scim/v2/Users", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()
	ext.Serve(w, r)
	var list map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	res, _ := list["Resources"].([]any)
	if len(res) == 0 {
		t.Fatal("no resources")
	}
	first, _ := res[0].(map[string]any)
	meta, _ = first["meta"].(map[string]any)
	if loc, _ := meta["location"].(string); !strings.HasPrefix(loc, "https://admin.example.com/scim/v2/Users/") {
		t.Errorf("location %q, want the configured base", loc)
	}
}

// Covers is the path test the listener uses, and a path that merely
// starts with the same characters is not this endpoint.
func TestCoversIsTheBaseAndWhatIsUnderIt(t *testing.T) {
	hh := newHarness(t, false)
	for path, want := range map[string]bool{
		"/scim/v2":             true,
		"/scim/v2/Users":       true,
		"/scim/v2/Users/abc":   true,
		"/scim/v2x":            false,
		"/scim/v2x/Users":      false,
		"/scim":                false,
		"/other/scim/v2/Users": false,
	} {
		if got := hh.h.Covers(path); got != want {
			t.Errorf("Covers(%q) = %v, want %v", path, got, want)
		}
	}
}

// Options this endpoint cannot serve are refused when it is built, not
// when the first request arrives.
func TestTheEndpointIsCheckedWhenItIsBuilt(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "users")
	for _, tc := range []struct {
		name string
		opts Options
		want string
	}{
		{"no state file", Options{KeysFile: "/k"}, "no state file"},
		{"a relative state file", Options{StateFile: "users", KeysFile: "/k"}, "absolute"},
		{"nothing to provision", Options{StateFile: state}, "nothing to provision"},
	} {
		if _, err := NewProvisioner(tc.opts); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %v, want one about %q", tc.name, err, tc.want)
		}
	}
	p, err := NewProvisioner(Options{StateFile: state, KeysFile: filepath.Join(dir, "keys")})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		cfg  Config
		want string
	}{
		{"no token", Config{Base: "/scim/v2"}, "no token"},
		{"the root", Config{Base: "/", TokenHash: tokenHash(token)}, "root"},
	} {
		if _, err := New(tc.cfg, p); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %v, want one about %q", tc.name, err, tc.want)
		}
	}
	if _, err := New(Config{Base: "/scim/v2", TokenHash: tokenHash(token)}, nil); err == nil {
		t.Error("a handler with no store was built")
	}
}

// A state file that cannot be read is an error, not an empty store: an
// endpoint that answers "no such user" to a directory because it could
// not read its own file would have it provision everybody again.
func TestAnUnreadableStateFileIsAnError(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "users")
	if err := os.WriteFile(state, []byte("not|enough|fields\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := NewProvisioner(Options{StateFile: state, KeysFile: filepath.Join(dir, "keys")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.List(""); err == nil {
		t.Fatal("a broken state file read as an empty store")
	}
	// And it is a 500, not a 400: the client did nothing wrong.
	h, err := New(Config{Base: "/scim/v2", TokenHash: tokenHash(token)}, p)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "http://admin.test/scim/v2/Users", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	out := h.Serve(w, r)
	if w.Code != http.StatusInternalServerError || out.Denied != "error" {
		t.Errorf("answered %d %+v, want a 500", w.Code, out)
	}
	var doc map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	// The detail is the one sentence, not the cause: a provisioning
	// client has no business learning which file could not be read, and
	// the cause belongs in this proxy's error log.
	if got, _ := doc["detail"].(string); got != "the request could not be completed" {
		t.Errorf("detail %q, want the generic sentence", got)
	}
	if strings.Contains(w.Body.String(), state) {
		t.Errorf("the response names the file: %s", w.Body.String())
	}
}

// A key id is derived from a name the key file cannot hold, and two
// provisionings of the same name do not collide.
func TestAKeyIDIsDerivedFromTheName(t *testing.T) {
	first, err := KeyID("alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	second, err := KeyID("alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Error("two provisionings of one name derived the same key id")
	}
	for _, id := range []string{first, second} {
		if len(id) > 32 || len(id) == 0 {
			t.Errorf("key id %q is %d characters", id, len(id))
		}
		for _, r := range id {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' {
				t.Errorf("key id %q holds %q, which the key file refuses", id, string(r))
			}
		}
	}
	// A name with nothing usable in it still gets an id.
	odd, err := KeyID("@@@")
	if err != nil || !strings.HasPrefix(odd, "user-") {
		t.Errorf("KeyID(%q) = %q, err %v", "@@@", odd, err)
	}
}
