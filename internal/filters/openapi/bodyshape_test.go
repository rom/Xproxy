package openapi

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/filter/filtertest"
)

// shapeSpec marks the server-controlled fields readOnly -- which is what
// every generated description does -- and declares a form body beside a
// JSON one.
const shapeSpec = `
openapi: 3.0.3
info: {title: Shapes, version: "1"}
servers: [{url: https://api.example.com/v1}]
components:
  schemas:
    Audit:
      type: object
      properties:
        createdBy: {type: string, readOnly: true}
    Profile:
      allOf:
        - $ref: "#/components/schemas/Audit"
        - type: object
          required: [name]
          properties:
            id: {type: integer, readOnly: true}
            role: {type: string, readOnly: true}
            name: {type: string, minLength: 2}
            tags:
              type: array
              items:
                type: object
                properties:
                  label: {type: string}
                  slug: {type: string, readOnly: true}
            meta:
              type: object
              additionalProperties: {type: object, properties: {ref: {type: string, readOnly: true}}}
paths:
  /profiles:
    post:
      requestBody:
        required: true
        content:
          application/json: {schema: {$ref: "#/components/schemas/Profile"}}
  /login:
    post:
      requestBody:
        required: true
        content:
          application/x-www-form-urlencoded:
            schema:
              type: object
              required: [user, remember]
              additionalProperties: false
              properties:
                user: {type: string, format: email}
                remember: {type: boolean}
                attempts: {type: integer, minimum: 1, maximum: 3}
                scopes: {type: array, items: {type: string, enum: [read, write]}}
  /either:
    post:
      requestBody:
        content:
          application/json:
            schema:
              oneOf:
                - type: object
                  required: [kind]
                  properties: {kind: {type: string, enum: [issued]}, token: {type: string, readOnly: true}}
                - type: object
                  required: [kind]
                  properties: {kind: {type: string, enum: [offered]}, token: {type: string}}
`

func shapeFilter(t *testing.T, opts filter.Options) filter.Filter {
	t.Helper()
	all := filter.Options{"spec_file": write(t, shapeSpec)}
	for k, v := range opts {
		all[k] = v
	}
	f, err := filtertest.Build("openapi", "shapes", all)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func post(t *testing.T, f filter.Filter, target, ct, body string) filter.Verdict {
	t.Helper()
	r, _ := http.NewRequest("POST", "http://api.example.com"+target, strings.NewReader(body))
	r.ContentLength = int64(len(body))
	r.Header.Set("Content-Type", ct)
	return filtertest.Run(f, r, nil).Request
}

// OpenAPI says a readOnly property MUST NOT be sent in a request, and the
// reason is mass assignment: an application that binds the whole body
// onto its model lets the client choose the fields the server was meant
// to own. The description already names them.
func TestAReadOnlyFieldMayNotBeSent(t *testing.T) {
	f := shapeFilter(t, filter.Options{"read_only": "deny"})
	// The honest request, which must still work: this is a filter and not
	// a refusal of every body with fields in it.
	if v := post(t, f, "/v1/profiles", "application/json", `{"name":"ada","tags":[{"label":"x"}]}`); v.Deny {
		t.Fatalf("an honest body was refused: %+v", v)
	}
	for _, tc := range []struct{ body, where string }{
		{`{"name":"ada","id":7}`, "body.id"},
		{`{"name":"ada","role":"admin"}`, "body.role"},
		// Through an allOf, which is a conjunction: the readOnly applies
		// to the value whatever else matches.
		{`{"name":"ada","createdBy":"root"}`, "body.createdBy"},
		// Inside an array's items.
		{`{"name":"ada","tags":[{"label":"x"},{"label":"y","slug":"mine"}]}`, "body.tags[1].slug"},
		// Through additionalProperties.
		{`{"name":"ada","meta":{"anything":{"ref":"r"}}}`, "body.meta.anything.ref"},
	} {
		v := post(t, f, "/v1/profiles", "application/json", tc.body)
		if !v.Deny || v.Status != http.StatusBadRequest || !strings.HasPrefix(v.Detail, "read_only:"+tc.where) {
			t.Errorf("%s: got %+v, want 400 read_only:%s", tc.body, v, tc.where)
		}
	}
}

// allow is the default, because a client that GETs an object and PUTs it
// back sends the server's own fields and that is how a great many REST
// clients are written. log is the middle: the request goes on and the
// access log says what was sent, which is how an operator finds out
// whether deny would break their clients.
func TestReadOnlyHasThreeAnswers(t *testing.T) {
	body := `{"name":"ada","id":7}`
	if v := post(t, shapeFilter(t, nil), "/v1/profiles", "application/json", body); v.Deny {
		t.Fatalf("the default refused a readOnly field: %+v", v)
	}
	logging := shapeFilter(t, filter.Options{"read_only": "log"})
	r, _ := http.NewRequest("POST", "http://api.example.com/v1/profiles", strings.NewReader(body))
	r.ContentLength = int64(len(body))
	r.Header.Set("Content-Type", "application/json")
	res := filtertest.Run(logging, r, nil)
	if res.Request.Deny {
		t.Fatalf("log refused the request: %+v", res.Request)
	}
	found := false
	for i := 0; i+1 < len(res.Attrs); i += 2 {
		if res.Attrs[i] == "openapi_read_only" && strings.Contains(res.Attrs[i+1].(string), "body.id") {
			found = true
		}
	}
	if !found {
		t.Fatalf("log recorded nothing: %v", res.Attrs)
	}
}

// anyOf and oneOf are alternatives, so a property that is readOnly in one
// branch says nothing certain about the value in hand. Refusing on the
// strength of a branch the value may not be matching would refuse correct
// requests, so those branches are deliberately not followed.
func TestAnAlternativeBranchDoesNotDecideReadOnly(t *testing.T) {
	f := shapeFilter(t, filter.Options{"read_only": "deny"})
	// The body matches the second branch alone, where token is writable;
	// the first branch marks it readOnly and is not consulted.
	if v := post(t, f, "/v1/either", "application/json", `{"kind":"offered","token":"t"}`); v.Deny {
		t.Fatalf("a oneOf branch refused the body: %+v", v)
	}
}

// A form body has a schema in the description like any other, and a form
// carries strings, so each field is coerced by what the schema says it
// is -- the same treatment the query parameters get, for the same reason.
func TestAFormBodyIsCheckedAgainstItsSchema(t *testing.T) {
	f := shapeFilter(t, nil)
	const ct = "application/x-www-form-urlencoded"
	form := func(vals url.Values) string { return vals.Encode() }

	ok := form(url.Values{"user": {"a@b.test"}, "remember": {"true"}, "attempts": {"2"}, "scopes": {"read", "write"}})
	if v := post(t, f, "/v1/login", ct, ok); v.Deny {
		t.Fatalf("a valid form was refused: %+v", v)
	}
	// The charset parameter must not change the decision.
	if v := post(t, f, "/v1/login", ct+"; charset=utf-8", ok); v.Deny {
		t.Fatalf("a valid form with a charset was refused: %+v", v)
	}
	for _, tc := range []struct{ body, where string }{
		{form(url.Values{"remember": {"true"}}), "body.user"},
		{form(url.Values{"user": {"nobody"}, "remember": {"true"}}), "body.user"},
		{form(url.Values{"user": {"a@b.test"}}), "body.remember"},
		{form(url.Values{"user": {"a@b.test"}, "remember": {"perhaps"}}), "body.remember"},
		{form(url.Values{"user": {"a@b.test"}, "remember": {"true"}, "attempts": {"9"}}), "body.attempts"},
		{form(url.Values{"user": {"a@b.test"}, "remember": {"true"}, "attempts": {"abc"}}), "body.attempts"},
		{form(url.Values{"user": {"a@b.test"}, "remember": {"true"}, "scopes": {"read", "delete"}}), "body.scopes"},
		{form(url.Values{"user": {"a@b.test"}, "remember": {"true"}, "extra": {"1"}}), "body.extra"},
	} {
		v := post(t, f, "/v1/login", ct, tc.body)
		if !v.Deny || v.Status != http.StatusBadRequest || !strings.HasPrefix(v.Detail, "schema:"+tc.where) {
			t.Errorf("%s: got %+v, want 400 schema:%s", tc.body, v, tc.where)
		}
	}
	// A media type the operation does not declare is still refused
	// rather than validated as a form.
	if v := post(t, f, "/v1/login", "application/json", `{"user":"a@b.test"}`); !v.Deny || v.Status != http.StatusUnsupportedMediaType {
		t.Fatalf("an undeclared media type: %+v", v)
	}
}

// The body the application receives is the one the client sent: a
// validated form is not a re-encoded one, because the proxy's idea of
// how to write a form is not necessarily the application's.
func TestTheFormReachesTheApplicationUnchanged(t *testing.T) {
	f := shapeFilter(t, nil)
	const body = "user=a%40b.test&remember=true&remember=false"
	r, _ := http.NewRequest("POST", "http://api.example.com/v1/login", strings.NewReader(body))
	r.ContentLength = int64(len(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res := filtertest.Run(f, r, nil)
	if res.Request.Deny {
		t.Fatalf("denied: %+v", res.Request)
	}
	got := readAll(t, r)
	if got != body {
		t.Fatalf("body reached the application as %q, want %q", got, body)
	}
}

func readAll(t *testing.T, r *http.Request) string {
	t.Helper()
	if r.Body == nil {
		return ""
	}
	var b strings.Builder
	buf := make([]byte, 512)
	for {
		n, err := r.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			return b.String()
		}
	}
}
