package mfagate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/filter"
)

// key is a test authenticator: enough of one to complete both ceremonies,
// because there is no other way to produce an assertion and because
// writing it is what proves the gate checks the bytes the specification
// describes.
type key struct {
	priv  *ecdsa.PrivateKey
	id    []byte
	count uint32
	rpID  string
}

func newKey(t *testing.T, rpID string) *key {
	t.Helper()
	p, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	return &key{priv: p, id: id, count: 1, rpID: rpID}
}

func cborHead(major byte, v uint64) []byte {
	switch {
	case v < 24:
		return []byte{major<<5 | byte(v)}
	case v < 1<<8:
		return []byte{major<<5 | 24, byte(v)}
	case v < 1<<16:
		return []byte{major<<5 | 25, byte(v >> 8), byte(v)}
	}
	b := []byte{major<<5 | 26}
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func cInt(n int64) []byte {
	if n >= 0 {
		return cborHead(0, uint64(n))
	}
	return cborHead(1, uint64(-1-n))
}
func cBytes(b []byte) []byte { return append(cborHead(2, uint64(len(b))), b...) }
func cText(s string) []byte  { return append(cborHead(3, uint64(len(s))), s...) }

func (k *key) cose() []byte {
	x := k.priv.X.FillBytes(make([]byte, 32))
	y := k.priv.Y.FillBytes(make([]byte, 32))
	var b []byte
	b = append(b, 0xa5)
	b = append(b, cInt(1)...)
	b = append(b, cInt(2)...) // EC2
	b = append(b, cInt(3)...)
	b = append(b, cInt(-7)...) // ES256
	b = append(b, cInt(-1)...)
	b = append(b, cInt(1)...) // P-256
	b = append(b, cInt(-2)...)
	b = append(b, cBytes(x)...)
	b = append(b, cInt(-3)...)
	b = append(b, cBytes(y)...)
	return b
}

func (k *key) authData(attested bool) []byte {
	h := sha256.Sum256([]byte(k.rpID))
	out := append([]byte{}, h[:]...)
	flags := byte(0x01 | 0x04) // present and verified
	if attested {
		flags |= 0x40
	}
	out = append(out, flags)
	var c [4]byte
	binary.BigEndian.PutUint32(c[:], k.count)
	out = append(out, c[:]...)
	if attested {
		out = append(out, make([]byte, 16)...)
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(k.id)))
		out = append(out, l[:]...)
		out = append(out, k.id...)
		out = append(out, k.cose()...)
	}
	return out
}

func (k *key) attestation() []byte {
	var b []byte
	b = append(b, 0xa3)
	b = append(b, cText("fmt")...)
	b = append(b, cText("none")...)
	b = append(b, cText("attStmt")...)
	b = append(b, 0xa0)
	b = append(b, cText("authData")...)
	b = append(b, cBytes(k.authData(true))...)
	return b
}

func clientData(t *testing.T, typ, origin, challenge string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": origin, "crossOrigin": false})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (k *key) sign(t *testing.T, cd []byte) (ad, sig []byte) {
	t.Helper()
	ad = k.authData(false)
	sum := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), sum[:]...))
	s, err := ecdsa.SignASN1(rand.Reader, k.priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return ad, s
}

func u64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// keyGate is a gate with a WebAuthn policy and a credentials file.
func keyGate(t *testing.T, register bool) (*gate, []byte, string) {
	t.Helper()
	dir := t.TempDir()
	creds := filepath.Join(dir, "webauthn")
	g, secret := build(t, map[string]any{
		"webauthn": map[string]any{
			"rp_id":            "app.example.test",
			"origins":          []any{"https://app.example.test"},
			"credentials_file": creds,
			"register":         register,
		},
	})
	return g, secret, creds
}

// postJSON drives one ceremony request.
func postJSON(t *testing.T, g *gate, endpoint string, body any, cookie *http.Cookie) filter.Verdict {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = strings.NewReader(string(b))
	}
	r, _ := http.NewRequest(http.MethodPost, "https://app.example.test/reports?xproxy_mfa="+endpoint, rd)
	r.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	return run(t, g, r, "alice")
}

// decode reads a verdict's JSON body.
func decode(t *testing.T, v filter.Verdict) map[string]any {
	t.Helper()
	if v.Response == nil {
		t.Fatal("no response body")
	}
	b, _ := io.ReadAll(v.Response.Body)
	out := map[string]any{}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("body %q: %v", b, err)
	}
	return out
}

// A key is registered using the factor the user already has, and then
// authenticates. Both halves matter: a gate that registered nothing would
// pass every negative test below.
func TestAKeyIsRegisteredWithTheFactorYouHaveAndThenWorks(t *testing.T) {
	g, secret, creds := keyGate(t, true)
	// Registration needs a verified factor, so the code comes first.
	v := run(t, g, post("/reports?xproxy_mfa=verify", form(code(t, secret), "/reports")), "alice")
	cookie := setCookie(v)
	if cookie == nil {
		t.Fatalf("no cookie from the code: %+v", v)
	}

	k := newKey(t, "app.example.test")
	opts := decode(t, postJSON(t, g, "webauthn-register-options", nil, cookie))
	cd := clientData(t, "webauthn.create", "https://app.example.test", opts["challenge"].(string))
	v = postJSON(t, g, "webauthn-register", map[string]any{
		"challenge_id": opts["challenge_id"], "attestation_object": u64(k.attestation()),
		"client_data_json": u64(cd), "label": "yubikey",
	}, cookie)
	if got := decode(t, v); got["ok"] != true {
		t.Fatalf("registration: %+v (%v)", got, v.Status)
	}
	// The file is the record.
	data, err := os.ReadFile(creds)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "alice:") || !strings.Contains(string(data), "yubikey") {
		t.Fatalf("credential file: %q", data)
	}

	// Now authenticate with the key alone, no cookie.
	k.count = 2
	opts = decode(t, postJSON(t, g, "webauthn-options", nil, nil))
	if list, _ := opts["credentials"].([]any); len(list) != 1 || list[0] != u64(k.id) {
		t.Fatalf("the allow list did not name the key: %v", opts["credentials"])
	}
	cd = clientData(t, "webauthn.get", "https://app.example.test", opts["challenge"].(string))
	ad, sig := k.sign(t, cd)
	v = postJSON(t, g, "webauthn", map[string]any{
		"challenge_id": opts["challenge_id"], "credential_id": u64(k.id),
		"authenticator_data": u64(ad), "client_data_json": u64(cd), "signature": u64(sig), "next": "/reports",
	}, nil)
	got := decode(t, v)
	if got["ok"] != true || got["next"] != "/reports" {
		t.Fatalf("assertion: %+v", got)
	}
	if setCookie(v) == nil {
		t.Fatal("no cookie from the key")
	}
	// And the sign count was written, which is what makes the clone check
	// survive a restart.
	data, _ = os.ReadFile(creds)
	if !strings.Contains(string(data), ":2:") {
		t.Fatalf("the sign count was not recorded: %q", data)
	}
}

// Registration requires a factor already verified. Without that it is a
// way to add a second factor to an account whose password has just been
// stolen.
func TestRegisteringAKeyNeedsTheFactorYouAlreadyHave(t *testing.T) {
	g, _, _ := keyGate(t, true)
	for _, endpoint := range []string{"webauthn-register-options", "webauthn-register"} {
		v := postJSON(t, g, endpoint, map[string]any{}, nil)
		if v.Status != http.StatusUnauthorized {
			t.Errorf("%s without a verified factor: %d, want 401", endpoint, v.Status)
		}
		if got := decode(t, v); got["error"] != "verify_first" {
			t.Errorf("%s: %v", endpoint, got)
		}
	}
	// And with register off the endpoints are not there at all: the
	// request falls through to the ordinary challenge.
	off, secret, _ := keyGate(t, false)
	v := run(t, off, post("/reports?xproxy_mfa=verify", form(code(t, secret), "/")), "alice")
	cookie := setCookie(v)
	v = postJSON(t, off, "webauthn-register-options", nil, cookie)
	if v.Status == http.StatusOK {
		t.Error("registration was offered with register off")
	}
}

// Every way a ceremony can fail to be this ceremony. One message for all
// of them, because which step refused a key is what an attacker probes
// for.
func TestACeremonyThatIsNotThisOneIsRefused(t *testing.T) {
	g, secret, _ := keyGate(t, true)
	cookie := setCookie(run(t, g, post("/reports?xproxy_mfa=verify", form(code(t, secret), "/")), "alice"))
	k := newKey(t, "app.example.test")
	opts := decode(t, postJSON(t, g, "webauthn-register-options", nil, cookie))
	cd := clientData(t, "webauthn.create", "https://app.example.test", opts["challenge"].(string))
	if got := decode(t, postJSON(t, g, "webauthn-register", map[string]any{
		"challenge_id": opts["challenge_id"], "attestation_object": u64(k.attestation()),
		"client_data_json": u64(cd),
	}, cookie)); got["ok"] != true {
		t.Fatalf("registration: %v", got)
	}

	fresh := func() (string, string) {
		o := decode(t, postJSON(t, g, "webauthn-options", nil, nil))
		return o["challenge_id"].(string), o["challenge"].(string)
	}
	try := func(id string, cd, ad, sig []byte, credID []byte) filter.Verdict {
		return postJSON(t, g, "webauthn", map[string]any{
			"challenge_id": id, "credential_id": u64(credID),
			"authenticator_data": u64(ad), "client_data_json": u64(cd), "signature": u64(sig),
		}, nil)
	}
	k.count = 5

	// A look-alike origin: the anti-phishing property, and the reason to
	// have a key at all.
	id, ch := fresh()
	cd = clientData(t, "webauthn.get", "https://app.example.test.evil.test", ch)
	ad, sig := k.sign(t, cd)
	if v := try(id, cd, ad, sig, k.id); v.Status != http.StatusUnauthorized {
		t.Error("a look-alike origin was accepted")
	}

	// A challenge nobody issued, and one already spent.
	cd = clientData(t, "webauthn.get", "https://app.example.test", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	ad, sig = k.sign(t, cd)
	if v := try("deadbeefdeadbeefdeadbeefdeadbeef", cd, ad, sig, k.id); v.Status != http.StatusUnauthorized {
		t.Error("a challenge nobody issued was accepted")
	}
	id, ch = fresh()
	cd = clientData(t, "webauthn.get", "https://app.example.test", ch)
	k.count++
	ad, sig = k.sign(t, cd)
	if v := try(id, cd, ad, sig, k.id); v.Status != http.StatusOK {
		t.Fatalf("the honest ceremony was refused: %d", v.Status)
	}
	if v := try(id, cd, ad, sig, k.id); v.Status != http.StatusUnauthorized {
		t.Error("a replayed assertion was accepted")
	}

	// Another account's credential identifier. The identifier is public,
	// so this must not be a way in.
	other := newKey(t, "app.example.test")
	id, ch = fresh()
	cd = clientData(t, "webauthn.get", "https://app.example.test", ch)
	other.count = 99
	ad, sig = other.sign(t, cd)
	if v := try(id, cd, ad, sig, other.id); v.Status != http.StatusUnauthorized {
		t.Error("an unregistered credential was accepted")
	}

	// A sign count that went backwards, which is what a clone looks like.
	id, ch = fresh()
	cd = clientData(t, "webauthn.get", "https://app.example.test", ch)
	k.count = 1
	ad, sig = k.sign(t, cd)
	if v := try(id, cd, ad, sig, k.id); v.Status != http.StatusUnauthorized {
		t.Error("a sign count that went backwards was accepted")
	}

	// And a body that is not a ceremony at all.
	r, _ := http.NewRequest(http.MethodPost, "https://app.example.test/x?xproxy_mfa=webauthn", strings.NewReader("{"))
	if v := run(t, g, r, "alice"); v.Status != http.StatusBadRequest {
		t.Errorf("a malformed body: %d, want 400", v.Status)
	}
}

// The page offers the key only to somebody who has one. A button that
// always fails is noise, and offering it to everybody says who has a key.
func TestThePageOffersAKeyOnlyToSomebodyWhoHasOne(t *testing.T) {
	g, secret, _ := keyGate(t, true)
	v := run(t, g, get("/reports"), "alice")
	body, _ := io.ReadAll(v.Response.Body)
	if strings.Contains(string(body), "security key") {
		t.Error("a key was offered to a user with none registered")
	}
	// Register one, then ask again.
	cookie := setCookie(run(t, g, post("/reports?xproxy_mfa=verify", form(code(t, secret), "/")), "alice"))
	k := newKey(t, "app.example.test")
	opts := decode(t, postJSON(t, g, "webauthn-register-options", nil, cookie))
	cd := clientData(t, "webauthn.create", "https://app.example.test", opts["challenge"].(string))
	if got := decode(t, postJSON(t, g, "webauthn-register", map[string]any{
		"challenge_id": opts["challenge_id"], "attestation_object": u64(k.attestation()),
		"client_data_json": u64(cd),
	}, cookie)); got["ok"] != true {
		t.Fatalf("registration: %v", got)
	}
	v = run(t, g, get("/reports"), "alice")
	body, _ = io.ReadAll(v.Response.Body)
	page := string(body)
	if !strings.Contains(page, "security key") {
		t.Error("the key was not offered after registering one")
	}
	// The code form is still there: a key is an alternative, not a
	// replacement, and a machine with no key attached still needs a way in.
	if !strings.Contains(page, `name="code"`) {
		t.Error("the code form went away")
	}
}

// A gate without the section behaves exactly as before, and the endpoints
// are not reachable.
func TestWithoutTheSectionNothingChanges(t *testing.T) {
	g, secret := build(t, nil)
	if g.webauthnOn() {
		t.Fatal("webauthn is on without the section")
	}
	v := postJSON(t, g, "webauthn-options", nil, nil)
	if v.Status != http.StatusUnauthorized || v.Detail != "mfa_challenge" {
		t.Fatalf("the endpoint answered something: %+v", v)
	}
	// The ordinary flow still works.
	if setCookie(run(t, g, post("/x?xproxy_mfa=verify", form(code(t, secret), "/")), "alice")) == nil {
		t.Fatal("the code flow broke")
	}
}

// The settings that cannot work are refused at load, where somebody sees
// them.
func TestTheKeyPolicyIsValidated(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name string
		w    map[string]any
		want string
	}{
		{"no rp_id", map[string]any{"origins": []any{"https://a.test"}, "credentials_file": "/tmp/c"}, "rp_id is required"},
		{"an rp_id that is a URL", map[string]any{"rp_id": "https://a.test", "origins": []any{"https://a.test"}, "credentials_file": "/tmp/c"}, "host name, not a URL"},
		{"no origins", map[string]any{"rp_id": "a.test", "credentials_file": "/tmp/c"}, "origins is required"},
		{"a plain http origin", map[string]any{"rp_id": "a.test", "origins": []any{"http://a.test"}, "credentials_file": "/tmp/c"}, "must be an https origin"},
		{"an origin with a path", map[string]any{"rp_id": "a.test", "origins": []any{"https://a.test/login"}, "credentials_file": "/tmp/c"}, "carries a path"},
		{"a relative credentials file", map[string]any{"rp_id": "a.test", "origins": []any{"https://a.test"}, "credentials_file": "c"}, "absolute path is required"},
	} {
		_, err := parse(filter.Options{"file": filepath.Join(dir, "mfa"),
			"cookie_secret_file": filepath.Join(dir, "k"), "webauthn": tc.w})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %v, want one containing %q", tc.name, err, tc.want)
		}
	}
	// localhost is allowed, because that is where the API works without
	// TLS and where somebody develops against it.
	if _, err := parse(filter.Options{"file": filepath.Join(dir, "mfa"),
		"cookie_secret_file": filepath.Join(dir, "k"),
		"webauthn":           map[string]any{"rp_id": "localhost", "origins": []any{"http://localhost:8080"}, "credentials_file": "/tmp/c"},
	}); err != nil {
		t.Errorf("localhost was refused: %v", err)
	}
}

// form is the code form a verify post carries.
func form(code, next string) url.Values {
	return url.Values{"code": {code}, "next": {next}}
}
