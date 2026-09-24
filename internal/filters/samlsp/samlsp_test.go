package samlsp

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/filter/filtertest"
	"github.com/rom/xproxy/internal/saml"
	"github.com/rom/xproxy/internal/saml/samltest"
)

const (
	spEntity = "https://app.example.com/saml/metadata"
	spBase   = "https://app.example.com"
	acsURL   = spBase + "/saml/acs"
	idpSSO   = "https://idp.example.com/sso"
	idpID    = "urn:example:idp"
)

// harness is a filter wired to a test identity provider.
type harness struct {
	t   *testing.T
	f   filter.Filter
	idp *samltest.IDP
	dir string
}

func build(t *testing.T, extra map[string]any) *harness {
	t.Helper()
	idp, err := samltest.New(idpID, idpSSO)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile := filepath.Join(dir, "idp.pem")
	if err := os.WriteFile(certFile, idp.CertPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := map[string]any{
		"entity_id":          spEntity,
		"idp_entity_id":      idpID,
		"idp_sso_url":        idpSSO,
		"idp_cert_file":      certFile,
		"cookie_secret_file": filepath.Join(dir, "cookie.key"),
		"external_url":       spBase,
		"forward_headers":    map[string]string{"X-Remote-User": "nameid", "X-Remote-Email": "mail"},
		"groups_attribute":   "groups",
		"policy_attributes":  []string{"department"},
		"log_attributes":     []string{"mail"},
	}
	for k, v := range extra {
		if v == nil {
			delete(opts, k)
			continue
		}
		opts[k] = v
	}
	f, err := filtertest.Build("saml_sp", "sso", filter.Options(opts))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return &harness{t: t, f: f, idp: idp, dir: dir}
}

func request(method, target string) *http.Request {
	r := httptest.NewRequest(method, target, http.NoBody)
	r.Host = "app.example.com"
	return r
}

// run runs one exchange with an identity set attached, as the data plane
// does, and returns the verdict and the identity.
func (h *harness) run(r *http.Request) (filter.Verdict, *filter.Identity, []any) {
	h.t.Helper()
	ctx, id := filter.WithIdentity(r.Context())
	in := h.f.Begin(ctx, &filter.Info{RequestID: "test", Route: "test", Host: r.Host, Path: r.URL.Path, Method: r.Method, TLS: true})
	v := in.Request(r.WithContext(ctx))
	return v, id, in.End()
}

// login walks the redirect to the provider and returns the request
// identifier it carried with the state cookie the browser holds.
func (h *harness) login(target string) (*samltest.AuthnRequest, *http.Cookie) {
	h.t.Helper()
	v, _, _ := h.run(request(http.MethodGet, target))
	if v.Status != http.StatusFound || v.Response == nil {
		h.t.Fatalf("a request without a session got %d, not a redirect", v.Status)
	}
	req, err := samltest.ReadRedirect(v.Response.Header.Get("Location"))
	if err != nil {
		h.t.Fatalf("the redirect to the provider: %v", err)
	}
	state := cookieNamed(h.t, v.Response, "XPSAML_state")
	if state == nil || state.Value == "" {
		h.t.Fatal("the login set no state cookie")
	}
	return req, state
}

// post presents a response at the consumer service with the state cookie.
func (h *harness) post(encoded string, state *http.Cookie, relay string) (filter.Verdict, *filter.Identity) {
	h.t.Helper()
	form := url.Values{"SAMLResponse": {encoded}}
	if relay != "" {
		form.Set("RelayState", relay)
	}
	r := httptest.NewRequest(http.MethodPost, acsURL, strings.NewReader(form.Encode()))
	r.Host = "app.example.com"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if state != nil {
		r.AddCookie(state)
	}
	v, id, _ := h.run(r)
	return v, id
}

func cookieNamed(t *testing.T, resp *http.Response, name string) *http.Cookie {
	t.Helper()
	for _, c := range (&http.Response{Header: resp.Header}).Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// signIn is the whole flow: redirect, signed response, session cookie.
func (h *harness) signIn(o samltest.Options) (*http.Cookie, filter.Verdict) {
	h.t.Helper()
	req, state := h.login("https://app.example.com/reports?page=2")
	if o.ACS == "" {
		o.ACS = acsURL
	}
	if o.Audience == "" {
		o.Audience = spEntity
	}
	if o.InResponseTo == "" {
		o.InResponseTo = req.ID
	}
	if o.NameID == "" {
		o.NameID = "alice@example.com"
	}
	encoded, err := h.idp.Encoded(o)
	if err != nil {
		h.t.Fatal(err)
	}
	v, _ := h.post(encoded, state, req.RelayState)
	if v.Response == nil {
		return nil, v
	}
	return cookieNamed(h.t, v.Response, "XPSAML"), v
}

func TestARequestWithoutASessionGoesToTheProvider(t *testing.T) {
	h := build(t, map[string]any{"force_authn": true})
	req, state := h.login("https://app.example.com/reports?page=2")
	if req.Destination != idpSSO {
		t.Errorf("destination %q", req.Destination)
	}
	if req.ACS != acsURL {
		t.Errorf("consumer url %q", req.ACS)
	}
	if req.Issuer != spEntity {
		t.Errorf("issuer %q", req.Issuer)
	}
	if !req.ForceAuthn {
		t.Error("force_authn was configured and not asked for")
	}
	if req.RelayState == "" {
		t.Error("no relay state was sent")
	}
	if !state.HttpOnly || !state.Secure || state.SameSite != http.SameSiteLaxMode {
		t.Errorf("state cookie flags: HttpOnly=%v Secure=%v SameSite=%v", state.HttpOnly, state.Secure, state.SameSite)
	}
}

func TestASignedAssertionSetsTheSession(t *testing.T) {
	h := build(t, nil)
	cookie, v := h.signIn(samltest.Options{
		Attributes: map[string][]string{"mail": {"alice@example.com"}, "groups": {"staff", "admins"}, "department": {"ops"}},
	})
	if v.Status != http.StatusFound {
		t.Fatalf("the consumer service answered %d (%s)", v.Status, v.Detail)
	}
	if got := v.Response.Header.Get("Location"); got != "/reports?page=2" {
		t.Errorf("the browser was sent to %q, not back where it came from", got)
	}
	if cookie == nil || cookie.Value == "" {
		t.Fatal("no session cookie was set")
	}
	if !cookie.HttpOnly || !cookie.Secure {
		t.Errorf("session cookie flags: HttpOnly=%v Secure=%v", cookie.HttpOnly, cookie.Secure)
	}
	// And the session is what the next request is let through on.
	r := request(http.MethodGet, "https://app.example.com/reports")
	r.AddCookie(cookie)
	r.Header.Set("X-Remote-User", "root") // a client supplied identity header
	v2, id, attrs := h.run(r)
	if v2.Deny {
		t.Fatalf("a request with a session was denied: %s", v2.Detail)
	}
	if got := r.Header.Get("X-Remote-User"); got != "alice@example.com" {
		t.Errorf("forwarded user %q", got)
	}
	if got := r.Header.Get("X-Remote-Email"); got != "alice@example.com" {
		t.Errorf("forwarded mail %q", got)
	}
	if got := r.Header.Get("Cookie"); strings.Contains(got, "XPSAML") {
		t.Errorf("the session cookie was forwarded upstream: %q", got)
	}
	if got := id.Get("saml"); got != "alice@example.com" {
		t.Errorf("identity %q", got)
	}
	if got := id.Groups(); len(got) != 2 || got[0] != "admins" && got[0] != "staff" {
		t.Errorf("groups %v", got)
	}
	if got := fmt.Sprint(attrs); !strings.Contains(got, "alice@example.com") {
		t.Errorf("access log attributes %v", attrs)
	}
}

func TestAClientSuppliedIdentityHeaderNeverReachesTheUpstream(t *testing.T) {
	// The assertion carries no mail attribute, so nothing sets
	// X-Remote-Email -- and the header the client sent must be gone all
	// the same, or the upstream reads an identity the client chose.
	h := build(t, nil)
	cookie, v := h.signIn(samltest.Options{Attributes: map[string][]string{"groups": {"staff"}}})
	if cookie == nil {
		t.Fatalf("no session cookie (%d %s)", v.Status, v.Detail)
	}
	r := request(http.MethodGet, "https://app.example.com/reports")
	r.AddCookie(cookie)
	r.Header.Set("X-Remote-Email", "attacker@example.com")
	if v2, _, _ := h.run(r); v2.Deny {
		t.Fatalf("the request was denied: %s", v2.Detail)
	}
	if got := r.Header.Get("X-Remote-Email"); got != "" {
		t.Errorf("the upstream would read X-Remote-Email: %q", got)
	}
	// And on a request with no session at all, which is answered by a
	// redirect rather than forwarded.
	r2 := request(http.MethodGet, "https://app.example.com/reports")
	r2.Header.Set("X-Remote-User", "root")
	if _, _, _ = h.run(r2); r2.Header.Get("X-Remote-User") != "" {
		t.Errorf("an unauthenticated request kept its identity header: %q", r2.Header.Get("X-Remote-User"))
	}
}

func TestTheReturnURLCannotLeaveThisHost(t *testing.T) {
	for _, target := range []string{
		"https://app.example.com//evil.example.com/path",
		"https://app.example.com/" + strings.Repeat("a", 4096),
	} {
		h := build(t, nil)
		req, state := h.login(target)
		encoded, err := h.idp.Encoded(samltest.Options{ACS: acsURL, Audience: spEntity, InResponseTo: req.ID, NameID: "alice@example.com"})
		if err != nil {
			t.Fatal(err)
		}
		v, _ := h.post(encoded, state, req.RelayState)
		if v.Response == nil {
			t.Fatalf("login did not complete: %d %s", v.Status, v.Detail)
		}
		loc := v.Response.Header.Get("Location")
		if strings.HasPrefix(loc, "//") || strings.Contains(loc, "evil.example.com") || len(loc) > 2048 {
			t.Errorf("after logging in from %q the browser is sent to %q", target, loc)
		}
	}
}

func TestTheSessionNeverOutlivesTheAssertion(t *testing.T) {
	h := build(t, map[string]any{"session_ttl": "8h"})
	cookie, _ := h.signIn(samltest.Options{Lifetime: 2 * time.Minute})
	if cookie == nil {
		t.Fatal("no session cookie")
	}
	if cookie.MaxAge > 130 || cookie.MaxAge < 90 {
		t.Errorf("the session lasts %ds, though the provider allowed 120s", cookie.MaxAge)
	}
}

func TestAResponseNobodyCanUseTwice(t *testing.T) {
	h := build(t, nil)
	req, state := h.login("https://app.example.com/")
	encoded, err := h.idp.Encoded(samltest.Options{ACS: acsURL, Audience: spEntity, InResponseTo: req.ID, NameID: "alice@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := h.post(encoded, state, req.RelayState); v.Status != http.StatusFound {
		t.Fatalf("the first use answered %d (%s)", v.Status, v.Detail)
	}
	v, _ := h.post(encoded, state, req.RelayState)
	if v.Status != http.StatusUnauthorized || v.Detail != "replay" {
		t.Fatalf("the second use answered %d (%s)", v.Status, v.Detail)
	}
}

func TestTheConsumerServiceRefusesWhatItShould(t *testing.T) {
	for _, tc := range []struct {
		name     string
		detail   string
		opts     samltest.Options
		mangle   func(string) string
		relay    string
		noCookie bool
	}{
		{name: "an unsigned assertion", detail: "signature", opts: samltest.Options{Sign: "none"}},
		{name: "another audience", detail: "refused", opts: samltest.Options{Audience: "urn:somebody-else"}},
		{name: "another consumer service", detail: "refused", opts: samltest.Options{ACS: "https://evil.example.com/acs"}},
		{name: "another login attempt", detail: "refused", opts: samltest.Options{InResponseTo: "_not-the-one-we-sent"}},
		{name: "an expired assertion", detail: "refused", opts: samltest.Options{Now: time.Now().Add(-2 * time.Hour)}},
		{name: "a provider that refused", detail: "provider_status", opts: samltest.Options{
			Status: "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed", StatusMessage: "wrong password"}},
		{name: "a tampered name identifier", detail: "signature",
			mangle: func(s string) string { return strings.Replace(s, "alice@example.com", "rooot@example.com", 1) }},
		{name: "something that is not a response", detail: "profile",
			mangle: func(string) string { return `<samlp:Other xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>` }},
		{name: "a document type declaration", detail: "profile",
			mangle: func(s string) string {
				return strings.Replace(s, `<?xml version="1.0" encoding="UTF-8"?>`, `<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>`, 1)
			}},
		{name: "no state cookie", detail: "state_missing", noCookie: true},
		{name: "a relay state from another exchange", detail: "relay_state", relay: "not-the-one-we-sent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := build(t, nil)
			req, state := h.login("https://app.example.com/")
			o := tc.opts
			if o.ACS == "" {
				o.ACS = acsURL
			}
			if o.Audience == "" {
				o.Audience = spEntity
			}
			if o.InResponseTo == "" {
				o.InResponseTo = req.ID
			}
			if o.NameID == "" {
				o.NameID = "alice@example.com"
			}
			raw, err := h.idp.Response(o)
			if err != nil {
				t.Fatal(err)
			}
			doc := string(raw)
			if tc.mangle != nil {
				doc = tc.mangle(doc)
			}
			encoded := encode(doc)
			relay := req.RelayState
			if tc.relay != "" {
				relay = tc.relay
			}
			cookie := state
			if tc.noCookie {
				cookie = nil
			}
			v, id := h.post(encoded, cookie, relay)
			if !v.Deny || v.Status < 400 {
				t.Fatalf("%s was accepted (%d %s)", tc.name, v.Status, v.Detail)
			}
			if v.Detail != tc.detail {
				t.Errorf("detail %q, want %q", v.Detail, tc.detail)
			}
			if got := id.Get("saml"); got != "" {
				t.Errorf("a refused response left the identity %q", got)
			}
		})
	}
}

func encode(doc string) string {
	return base64.StdEncoding.EncodeToString([]byte(doc))
}

func TestTheConsumerServiceTakesOnlyAPostedForm(t *testing.T) {
	h := build(t, nil)
	for _, tc := range []struct {
		name, method, contentType, body string
		status                          int
		detail                          string
	}{
		{"a GET", http.MethodGet, "", "", http.StatusMethodNotAllowed, "acs_method"},
		{"a JSON body", http.MethodPost, "application/json", `{}`, http.StatusUnsupportedMediaType, "acs_content_type"},
		{"an empty form", http.MethodPost, "application/x-www-form-urlencoded", "", http.StatusBadRequest, "acs_no_response"},
		{"a response that is not base64", http.MethodPost, "application/x-www-form-urlencoded", "SAMLResponse=%21%21%21", http.StatusBadRequest, "acs_base64"},
		{"a body over the bound", http.MethodPost, "application/x-www-form-urlencoded",
			"SAMLResponse=" + strings.Repeat("A", maxACSBody+1), http.StatusRequestEntityTooLarge, "acs_body_size"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, acsURL, strings.NewReader(tc.body))
			r.Host = "app.example.com"
			if tc.contentType != "" {
				r.Header.Set("Content-Type", tc.contentType)
			}
			v, _, _ := h.run(r)
			if v.Status != tc.status || v.Detail != tc.detail {
				t.Errorf("%s answered %d (%s), want %d (%s)", tc.name, v.Status, v.Detail, tc.status, tc.detail)
			}
		})
	}
}

func TestAnAttributeRequirementIsEnforced(t *testing.T) {
	h := build(t, map[string]any{"require_attributes": map[string]string{"department": "ops"}})
	_, v := h.signIn(samltest.Options{Attributes: map[string][]string{"department": {"sales"}}})
	if v.Status != http.StatusForbidden || v.Detail != "attribute:department" {
		t.Fatalf("a login without the required attribute answered %d (%s)", v.Status, v.Detail)
	}
	h2 := build(t, map[string]any{"require_attributes": map[string]string{"department": "ops"}})
	cookie, v2 := h2.signIn(samltest.Options{Attributes: map[string][]string{"department": {"ops"}}})
	if v2.Status != http.StatusFound || cookie == nil {
		t.Fatalf("a login with the required attribute answered %d (%s)", v2.Status, v2.Detail)
	}
}

func TestANameIdentifierFormatOutsideThePolicyIsRefused(t *testing.T) {
	h := build(t, map[string]any{"name_id_formats": []string{saml.NameIDPersistent}})
	_, v := h.signIn(samltest.Options{NameIDFormat: saml.NameIDEmail})
	if v.Status != http.StatusUnauthorized || v.Detail != "refused" {
		t.Fatalf("a format outside the policy answered %d (%s)", v.Status, v.Detail)
	}
}

func TestASignatureOnTheResponseSatisfiesThatSetting(t *testing.T) {
	h := build(t, map[string]any{"signed_element": "response"})
	cookie, v := h.signIn(samltest.Options{Sign: "response"})
	if v.Status != http.StatusFound || cookie == nil {
		t.Fatalf("a signed response answered %d (%s)", v.Status, v.Detail)
	}
	h2 := build(t, map[string]any{"signed_element": "response"})
	_, v2 := h2.signIn(samltest.Options{Sign: "assertion"})
	if v2.Detail != "signature" {
		t.Fatalf("an assertion signature where the response was required: %d (%s)", v2.Status, v2.Detail)
	}
	h3 := build(t, map[string]any{"signed_element": "either"})
	if cookie, v3 := h3.signIn(samltest.Options{Sign: "response"}); v3.Status != http.StatusFound || cookie == nil {
		t.Fatalf("either: a signed response answered %d (%s)", v3.Status, v3.Detail)
	}
}

func TestASessionSealedForAnotherProviderDoesNotOpen(t *testing.T) {
	// Two filters sharing one cookie secret file: a session from one is
	// not a session for the other, because the entity identifiers are
	// part of what the cookie is sealed under.
	dir := t.TempDir()
	secretFile := filepath.Join(dir, "cookie.key")
	h := build(t, map[string]any{"cookie_secret_file": secretFile})
	cookie, v := h.signIn(samltest.Options{})
	if cookie == nil {
		t.Fatalf("no session cookie (%d %s)", v.Status, v.Detail)
	}
	other := build(t, map[string]any{"cookie_secret_file": secretFile, "idp_entity_id": "urn:another:idp"})
	r := request(http.MethodGet, "https://app.example.com/reports")
	r.AddCookie(cookie)
	v2, _, _ := other.run(r)
	if v2.Detail != "login" {
		t.Fatalf("a session from another provider was accepted: %d (%s)", v2.Status, v2.Detail)
	}
}

func TestTheMetadataEndpointDescribesThisServiceProvider(t *testing.T) {
	h := build(t, nil)
	v, _, _ := h.run(request(http.MethodGet, spBase+"/saml/metadata"))
	if v.Status != http.StatusOK || v.Response == nil {
		t.Fatalf("the metadata endpoint answered %d", v.Status)
	}
	if got := v.Response.Header.Get("Content-Type"); got != "application/samlmetadata+xml" {
		t.Errorf("content type %q", got)
	}
	body := make([]byte, 4096)
	n, _ := v.Response.Body.Read(body)
	doc := string(body[:n])
	for _, want := range []string{spEntity, acsURL, `WantAssertionsSigned="true"`} {
		if !strings.Contains(doc, want) {
			t.Errorf("the metadata does not carry %s:\n%s", want, doc)
		}
	}
	v2, _, _ := h.run(request(http.MethodDelete, spBase+"/saml/metadata"))
	if v2.Status != http.StatusMethodNotAllowed {
		t.Errorf("a DELETE of the metadata answered %d", v2.Status)
	}
}

func TestLogoutClearsTheSession(t *testing.T) {
	h := build(t, map[string]any{"logout_redirect": "/goodbye"})
	cookie, _ := h.signIn(samltest.Options{})
	r := request(http.MethodGet, spBase+"/saml/logout")
	r.AddCookie(cookie)
	v, _, _ := h.run(r)
	if v.Status != http.StatusFound {
		t.Fatalf("logout answered %d", v.Status)
	}
	if got := v.Response.Header.Get("Location"); got != "/goodbye" {
		t.Errorf("logout sent the browser to %q", got)
	}
	cleared := cookieNamed(t, v.Response, "XPSAML")
	if cleared == nil || cleared.MaxAge >= 0 {
		t.Fatalf("logout did not clear the session cookie: %+v", cleared)
	}
}

func TestTheProviderCanBeNamedByItsMetadata(t *testing.T) {
	idp, err := samltest.New(idpID, idpSSO)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	mdFile := filepath.Join(dir, "idp.xml")
	if err := os.WriteFile(mdFile, idp.MetadataXML(), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := filtertest.Build("saml_sp", "sso", filter.Options{
		"entity_id":          spEntity,
		"idp_metadata_file":  mdFile,
		"cookie_secret_file": filepath.Join(dir, "cookie.key"),
		"external_url":       spBase,
	})
	if err != nil {
		t.Fatalf("a filter configured from metadata: %v", err)
	}
	h := &harness{t: t, f: f, idp: idp, dir: dir}
	req, state := h.login("https://app.example.com/")
	if req.Destination != idpSSO {
		t.Errorf("the endpoint from the metadata is %q", req.Destination)
	}
	encoded, err := idp.Encoded(samltest.Options{ACS: acsURL, Audience: spEntity, InResponseTo: req.ID, NameID: "alice@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := h.post(encoded, state, req.RelayState); v.Status != http.StatusFound {
		t.Fatalf("a response signed by the key in the metadata answered %d (%s)", v.Status, v.Detail)
	}
}

func TestAnotherProvidersKeyIsNotThisProvidersKey(t *testing.T) {
	h := build(t, nil)
	other, err := samltest.New(idpID, idpSSO)
	if err != nil {
		t.Fatal(err)
	}
	req, state := h.login("https://app.example.com/")
	encoded, err := other.Encoded(samltest.Options{ACS: acsURL, Audience: spEntity, InResponseTo: req.ID, NameID: "root@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	v, _ := h.post(encoded, state, req.RelayState)
	if v.Detail != "signature" {
		t.Fatalf("a response signed by another key answered %d (%s)", v.Status, v.Detail)
	}
}

func TestTheConfigurationIsCheckedAtLoad(t *testing.T) {
	dir := t.TempDir()
	idp, err := samltest.New(idpID, idpSSO)
	if err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(dir, "idp.pem")
	if err := os.WriteFile(certFile, idp.CertPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	junk := filepath.Join(dir, "junk.pem")
	if err := os.WriteFile(junk, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := func() map[string]any {
		return map[string]any{
			"entity_id": spEntity, "idp_entity_id": idpID, "idp_sso_url": idpSSO,
			"idp_cert_file": certFile, "cookie_secret_file": filepath.Join(dir, "cookie.key"),
		}
	}
	for _, tc := range []struct {
		name string
		edit func(map[string]any)
		want string
	}{
		{"no entity id", func(o map[string]any) { delete(o, "entity_id") }, "entity_id is required"},
		{"no issuer", func(o map[string]any) { delete(o, "idp_entity_id") }, "idp_entity_id is required"},
		{"no endpoint", func(o map[string]any) { delete(o, "idp_sso_url") }, "idp_sso_url is required"},
		{"a plain http endpoint", func(o map[string]any) { o["idp_sso_url"] = "http://idp.example.com/sso" }, "must be an https URL"},
		{"no signing certificate", func(o map[string]any) { delete(o, "idp_cert_file") }, "signing certificate is required"},
		{"a certificate file that is not one", func(o map[string]any) { o["idp_cert_file"] = junk }, "no PEM certificate"},
		{"a missing certificate file", func(o map[string]any) { o["idp_cert_file"] = filepath.Join(dir, "absent.pem") }, "no such file"},
		{"no cookie secret", func(o map[string]any) { delete(o, "cookie_secret_file") }, "cookie_secret_file is required"},
		{"paths that collide", func(o map[string]any) { o["acs_path"] = "/saml/metadata" }, "must differ"},
		{"a path that is not one", func(o map[string]any) { o["acs_path"] = "saml/acs" }, "is not a path"},
		{"an off site logout redirect", func(o map[string]any) { o["logout_redirect"] = "//evil.example.com/" }, "must be a path on this host"},
		{"a session that never ends", func(o map[string]any) { o["session_ttl"] = "8760h" }, "session_ttl"},
		{"skew beyond reason", func(o map[string]any) { o["clock_skew"] = "1h" }, "clock_skew"},
		{"an assertion age beyond reason", func(o map[string]any) { o["max_assertion_age"] = "48h" }, "max_assertion_age"},
		{"an unknown signed element", func(o map[string]any) { o["signed_element"] = "anything" }, "signed_element"},
		{"an external url with a path", func(o map[string]any) { o["external_url"] = "https://app.example.com/app" }, "external_url"},
		{"a header that is not one", func(o map[string]any) { o["forward_headers"] = map[string]string{"X: Y": "nameid"} }, "forward_headers"},
		{"a replay table of no size", func(o map[string]any) { o["replay_max"] = -1 }, "replay_max"},
		{"metadata that is not metadata", func(o map[string]any) { o["idp_metadata_file"] = junk }, "idp_metadata_file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := base()
			tc.edit(opts)
			_, err := filtertest.Build("saml_sp", "sso", filter.Options(opts))
			if err == nil {
				t.Fatalf("%s was accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
	if _, err := filtertest.Build("saml_sp", "sso", filter.Options(base())); err != nil {
		t.Fatalf("a good configuration was refused: %v", err)
	}
}

func TestTheDerivedConsumerURLNeedsATrustedPeer(t *testing.T) {
	// Without external_url the consumer URL is derived from the request,
	// and the forwarding header only counts from a trusted peer: a client
	// that could set the scheme could name the URL the provider posts the
	// assertion to.
	h := build(t, map[string]any{"external_url": nil})
	r := httptest.NewRequest(http.MethodGet, "http://app.example.com/reports", http.NoBody)
	r.Host = "app.example.com"
	r.Header.Set("X-Forwarded-Proto", "https")
	ctx, _ := filter.WithIdentity(r.Context())
	in := h.f.Begin(ctx, &filter.Info{Host: r.Host, Path: r.URL.Path, Method: r.Method})
	v := in.Request(r.WithContext(ctx))
	req, err := samltest.ReadRedirect(v.Response.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if req.ACS != "http://app.example.com/saml/acs" {
		t.Errorf("an untrusted peer's X-Forwarded-Proto was believed: %q", req.ACS)
	}
	r2 := httptest.NewRequest(http.MethodGet, "http://app.example.com/reports", http.NoBody)
	r2.Host = "app.example.com"
	r2.Header.Set("X-Forwarded-Proto", "https")
	ctx2, _ := filter.WithIdentity(r2.Context())
	in2 := h.f.Begin(ctx2, &filter.Info{Host: r2.Host, Path: r2.URL.Path, Method: r2.Method, TrustedPeer: true})
	v2 := in2.Request(r2.WithContext(ctx2))
	req2, err := samltest.ReadRedirect(v2.Response.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if req2.ACS != acsURL {
		t.Errorf("a trusted peer's X-Forwarded-Proto was ignored: %q", req2.ACS)
	}
}

func TestTheStatusViewReportsWhatHappened(t *testing.T) {
	h := build(t, nil)
	if _, v := h.signIn(samltest.Options{}); v.Status != http.StatusFound {
		t.Fatalf("login: %d %s", v.Status, v.Detail)
	}
	st := h.f.(*samlFilter).Status()
	if st.Accepted != 1 || st.Logins != 1 || st.Seen != 1 {
		t.Errorf("status %+v", st)
	}
	if st.IDPEntityID != idpID || st.Certs != 1 {
		t.Errorf("status %+v", st)
	}
}
