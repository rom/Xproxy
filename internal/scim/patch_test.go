package scim

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Every shape of PATCH a real identity provider sends.
//
// RFC 7644 leaves a provider two ways to say the same thing -- a path
// with a value, or a value object with no path -- and they send both,
// with the attribute name sometimes prefixed by the core schema URN and
// sometimes carrying a boolean as a string. A deactivation that is
// answered 200 and does nothing is the failure that matters here: the
// directory believes the leaver's credentials are gone.
func TestEveryPatchShapeAProviderSends(t *testing.T) {
	patch := func(ops string) string {
		return fmt.Sprintf(`{"schemas":["%s"],"Operations":[%s]}`, SchemaPatchOp, ops)
	}
	for _, tc := range []struct {
		name, ops string
		check     func(t *testing.T, doc map[string]any)
	}{
		{
			"externalId by path",
			`{"op":"replace","path":"externalId","value":"e-17"}`,
			func(t *testing.T, doc map[string]any) {
				if got, _ := doc["externalId"].(string); got != "e-17" {
					t.Errorf("externalId = %q", got)
				}
			},
		},
		{
			"displayName by path",
			`{"op":"replace","path":"displayName","value":"Judy Q"}`,
			func(t *testing.T, doc map[string]any) {
				if got, _ := doc["displayName"].(string); got != "Judy Q" {
					t.Errorf("displayName = %q", got)
				}
			},
		},
		{
			// A provider that sends the core URN before the attribute,
			// which RFC 7644 section 3.5.2 allows.
			"a path under the core schema URN",
			`{"op":"replace","path":"` + SchemaUser + `:displayName","value":"Judy R"}`,
			func(t *testing.T, doc map[string]any) {
				if got, _ := doc["displayName"].(string); got != "Judy R" {
					t.Errorf("displayName = %q", got)
				}
			},
		},
		{
			// And one that sends false as a string, which is a real
			// provider and a leaver either way.
			"active as a string",
			`{"op":"replace","path":"active","value":"false"}`,
			func(t *testing.T, doc map[string]any) {
				if active, _ := doc["active"].(bool); active {
					t.Error("the user is still active")
				}
			},
		},
		{
			"a value object naming two attributes",
			`{"op":"replace","value":{"externalId":"e-18","displayName":"Judy S"}}`,
			func(t *testing.T, doc map[string]any) {
				if got, _ := doc["externalId"].(string); got != "e-18" {
					t.Errorf("externalId = %q", got)
				}
				if got, _ := doc["displayName"].(string); got != "Judy S" {
					t.Errorf("displayName = %q", got)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hh := newHarness(t, false)
			_, doc, _ := hh.do(t, http.MethodPost, "/scim/v2/Users", userBody("judy", ""))
			id, _ := doc["id"].(string)
			code, doc, _ := hh.do(t, http.MethodPatch, "/scim/v2/Users/"+id, patch(tc.ops))
			if code != http.StatusOK {
				t.Fatalf("answered %d: %v", code, doc)
			}
			tc.check(t, doc)
		})
	}
}

// What a patch is refused for, with the SCIM type the provider reads to
// tell a retry from a mistake.
func TestEveryReasonAPatchIsRefused(t *testing.T) {
	hh := newHarness(t, false)
	_, doc, _ := hh.do(t, http.MethodPost, "/scim/v2/Users", userBody("kurt", ""))
	id, _ := doc["id"].(string)
	patch := func(ops string) string {
		return fmt.Sprintf(`{"schemas":["%s"],"Operations":[%s]}`, SchemaPatchOp, ops)
	}
	many := make([]string, 0, 33)
	for i := 0; i < 33; i++ {
		many = append(many, `{"op":"replace","path":"active","value":false}`)
	}
	for _, tc := range []struct {
		name, body, scimType string
		want                 int
	}{
		{"a body that is not a patch at all", `{"Operations":`, TypeInvalidSyntax, http.StatusBadRequest},
		{"more operations than are applied", patch(strings.Join(many, ",")), TypeTooMany, http.StatusBadRequest},
		{"replace with neither a path nor a value", patch(`{"op":"replace"}`), TypeInvalidValue, http.StatusBadRequest},
		{"a URN that is not the user schema", patch(`{"op":"replace","path":"urn:example:User:active","value":false}`), TypeInvalidPath, http.StatusBadRequest},
		{"externalId as a number", patch(`{"op":"replace","path":"externalId","value":7}`), TypeInvalidValue, http.StatusBadRequest},
		{"displayName as a number", patch(`{"op":"replace","path":"displayName","value":7}`), TypeInvalidValue, http.StatusBadRequest},
		{"a rename", patch(`{"op":"replace","path":"userName","value":"kurt2"}`), TypeMutability, http.StatusBadRequest},
		{"a value object naming something else", patch(`{"op":"replace","value":{"nickName":"k"}}`), TypeInvalidPath, http.StatusBadRequest},
	} {
		code, doc, out := hh.do(t, http.MethodPatch, "/scim/v2/Users/"+id, tc.body)
		if code != tc.want {
			t.Errorf("%s: answered %d, want %d (%v)", tc.name, code, tc.want, doc)
			continue
		}
		if got, _ := doc["scimType"].(string); got != tc.scimType {
			t.Errorf("%s: scimType %q, want %s", tc.name, got, tc.scimType)
		}
		if out.Denied == "" {
			t.Errorf("%s: the refusal is not reported", tc.name)
		}
	}
}

// A filter longer than the endpoint reads, which is refused rather than
// matched against.
func TestAnOversizeFilterIsRefused(t *testing.T) {
	hh := newHarness(t, false)
	long := `userName eq "` + strings.Repeat("x", 300) + `"`
	code, doc, _ := hh.do(t, http.MethodGet, "/scim/v2/Users?filter="+strings.ReplaceAll(long, " ", "%20"), "")
	if code != http.StatusBadRequest {
		t.Fatalf("answered %d: %v", code, doc)
	}
	if got, _ := doc["scimType"].(string); got != TypeInvalidFilter {
		t.Errorf("scimType %q, want %s", got, TypeInvalidFilter)
	}
}

// errReader fails on the first read, which is what a connection that
// dies mid-body looks like to a handler.
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("the connection went away") }

// A request whose body cannot be read, and one with no body at all.
//
// Neither comes from a well-behaved client, and both reach a handler:
// Request.Body is nil on a server request that middleware rebuilt, and
// a read fails when the connection dies between the headers and the
// body. The answer is a SCIM error, not a panic.
func TestABodyThatCannotBeRead(t *testing.T) {
	hh := newHarness(t, false)
	for _, tc := range []struct {
		name string
		body io.ReadCloser
	}{
		{"no body at all", nil},
		{"a body that fails on read", io.NopCloser(errReader{})},
	} {
		r := httptest.NewRequest(http.MethodPost, "http://admin.test/scim/v2/Users", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		r.Body = tc.body
		w := httptest.NewRecorder()
		out := hh.h.Serve(w, r)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: answered %d", tc.name, w.Code)
		}
		if out.Denied == "" {
			t.Errorf("%s: the refusal is not reported", tc.name)
		}
	}
}

// The location a provider is told to come back to is the endpoint's own
// scheme when the configuration does not name one -- and a TLS request
// is https, which matters because a provider that follows an http
// location sends the next bearer token in clear.
func TestTheLocationFollowsTheSchemeItWasAskedOn(t *testing.T) {
	hh := newHarness(t, false)
	r := httptest.NewRequest(http.MethodPost, "https://admin.test/scim/v2/Users", strings.NewReader(userBody("lena", "")))
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	hh.h.Serve(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("answered %d: %s", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, "https://admin.test/scim/v2/Users/") {
		t.Errorf("Location = %q", loc)
	}
}

// An error object with no SCIM type still reads as one.
func TestAnErrorWithoutASCIMTypeStillSaysWhatHappened(t *testing.T) {
	e := Errorf(http.StatusNotFound, "", "no such user")
	if got := e.Error(); !strings.Contains(got, "no such user") {
		t.Errorf("Error() = %q", got)
	}
	typed := Errorf(http.StatusBadRequest, TypeInvalidValue, "a name the files cannot hold")
	if got := typed.Error(); !strings.Contains(got, TypeInvalidValue) {
		t.Errorf("Error() = %q, want it to name the type", got)
	}
}
