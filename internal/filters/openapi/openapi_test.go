package openapi

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/filter/filtertest"
)

const spec = `
openapi: 3.0.3
info: {title: Orders, version: "1"}
servers: [{url: https://api.example.com/v1}]
components:
  schemas:
    Item:
      type: object
      required: [sku, qty]
      additionalProperties: false
      properties:
        sku: {type: string, pattern: "^[A-Z]{3}-[0-9]{4}$"}
        qty: {type: integer, minimum: 1, maximum: 100}
        note: {type: string, maxLength: 10, nullable: true}
    Order:
      type: object
      required: [customer, items]
      properties:
        customer: {type: string, format: email}
        items: {type: array, minItems: 1, maxItems: 3, items: {$ref: "#/components/schemas/Item"}}
        priority: {type: string, enum: [low, high]}
        address:
          oneOf:
            - {type: object, required: [street], properties: {street: {type: string}}}
            - {type: string}
paths:
  /orders:
    parameters:
      - {name: X-Tenant, in: header, required: true, schema: {type: string, minLength: 2}}
    get:
      parameters:
        - {name: limit, in: query, schema: {type: integer, minimum: 1, maximum: 50}}
        - {name: status, in: query, schema: {type: array, items: {type: string, enum: [open, closed]}}}
    post:
      requestBody:
        required: true
        content:
          application/json: {schema: {$ref: "#/components/schemas/Order"}}
          text/csv: {}
  /orders/{id}:
    get:
      parameters:
        - {name: id, in: path, schema: {type: string, format: uuid}}
    delete: {}
  /orders/latest:
    get: {}
`

func write(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "spec.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestValidation(t *testing.T) {
	f, err := filtertest.Build("openapi", "orders", filter.Options{"spec_file": write(t, spec), "strict_query": true})
	if err != nil {
		t.Fatal(err)
	}
	do := func(method, target, body string, hdr ...string) filter.Verdict {
		t.Helper()
		var rd io.Reader
		if body != "" {
			rd = strings.NewReader(body)
		}
		r, _ := http.NewRequest(method, "http://api.example.com"+target, rd)
		if body != "" {
			r.ContentLength = int64(len(body))
		}
		r.Header.Set("X-Tenant", "acme")
		for i := 0; i+1 < len(hdr); i += 2 {
			r.Header.Set(hdr[i], hdr[i+1])
		}
		return filtertest.Run(f, r, nil).Request
	}
	ok := func(v filter.Verdict, what string) {
		t.Helper()
		if v.Deny {
			body := ""
			if v.Response != nil {
				b, _ := io.ReadAll(v.Response.Body)
				body = string(b)
			}
			t.Fatalf("%s: denied %+v %s", what, v, body)
		}
	}
	bad := func(v filter.Verdict, status int, detail, what string) {
		t.Helper()
		if !v.Deny || v.Status != status || !strings.HasPrefix(v.Detail, detail) {
			t.Fatalf("%s: got %+v want %d %s", what, v, status, detail)
		}
	}
	order := `{"customer":"a@b.test","items":[{"sku":"ABC-1234","qty":2,"note":null}],"priority":"high","address":"Main St"}`
	ok(do("GET", "/v1/orders?limit=10&status=open&status=closed", ""), "list")
	ok(do("POST", "/v1/orders", order, "Content-Type", "application/json; charset=utf-8"), "create")
	ok(do("POST", "/v1/orders", "sku,qty\n", "Content-Type", "text/csv"), "csv body not inspected")
	ok(do("GET", "/v1/orders/latest", ""), "concrete path beats the template")
	ok(do("GET", "/v1/orders/123e4567-e89b-12d3-a456-426614174000", ""), "uuid path parameter")
	ok(do("HEAD", "/v1/orders?limit=1", ""), "head falls back to get")

	bad(do("GET", "/v1/nope", ""), 404, "unknown_path", "unknown path")
	bad(do("GET", "/other/orders", ""), 404, "unknown_path", "outside the base path")
	v := do("PATCH", "/v1/orders", "")
	bad(v, 405, "method", "undefined method")
	if v.Headers["Allow"] != "GET, POST" {
		t.Fatalf("allow header %v", v.Headers)
	}
	bad(do("GET", "/v1/orders?limit=500", ""), 400, "schema:query.limit", "query maximum")
	bad(do("GET", "/v1/orders?limit=abc", ""), 400, "schema:query.limit", "query type")
	bad(do("GET", "/v1/orders?status=pending", ""), 400, "schema:query.status", "array item enum")
	bad(do("GET", "/v1/orders?debug=1", ""), 400, "schema:query.debug", "strict query")
	r, _ := http.NewRequest("GET", "http://api.example.com/v1/orders", nil)
	bad(filtertest.Run(f, r, nil).Request, 400, "schema:header.X-Tenant", "required header")
	bad(do("GET", "/v1/orders/not-a-uuid", ""), 400, "schema:path.id", "path format")
	bad(do("POST", "/v1/orders", "", "Content-Type", "application/json"), 400, "schema:body", "required body")
	bad(do("POST", "/v1/orders", order, "Content-Type", "application/xml"), 415, "media_type", "undeclared media type")
	bad(do("POST", "/v1/orders", "{not json", "Content-Type", "application/json"), 400, "schema:body", "malformed json")
	bad(do("POST", "/v1/orders", `{"customer":"nobody","items":[]}`, "Content-Type", "application/json"), 400, "schema:body.customer", "email format and empty list")
	bad(do("POST", "/v1/orders", `{"customer":"a@b.test","items":[{"sku":"bad","qty":0,"extra":1}]}`, "Content-Type", "application/json"), 400, "schema:body.items[0]", "item rules")
	bad(do("POST", "/v1/orders", `{"customer":"a@b.test","items":[{"sku":"ABC-1234","qty":1}],"priority":"urgent"}`, "Content-Type", "application/json"), 400, "schema:body.priority", "enum")
	bad(do("POST", "/v1/orders", `{"customer":"a@b.test","items":[{"sku":"ABC-1234","qty":1}],"address":5}`, "Content-Type", "application/json"), 400, "schema:body.address", "oneOf")
	// The details name every problem, bounded.
	v = do("POST", "/v1/orders", `{"items":[{"qty":"two"}]}`, "Content-Type", "application/json")
	b, _ := io.ReadAll(v.Response.Body)
	for _, want := range []string{`"path":"body.customer"`, `"path":"body.items[0].sku"`, `"path":"body.items[0].qty"`} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("details missing %s: %s", want, b)
		}
	}
	// A body too large is refused before parsing; the body is readable after validation.
	big, err := filtertest.Build("openapi", "orders", filter.Options{"spec_file": write(t, spec), "max_body_bytes": 32})
	if err != nil {
		t.Fatal(err)
	}
	r, _ = http.NewRequest("POST", "http://api.example.com/v1/orders", strings.NewReader(order))
	r.ContentLength = int64(len(order))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Tenant", "acme")
	if v := filtertest.Run(big, r, nil).Request; !v.Deny || v.Status != 413 {
		t.Fatalf("large body: %+v", v)
	}
	r, _ = http.NewRequest("POST", "http://api.example.com/v1/orders", strings.NewReader(order))
	r.ContentLength = int64(len(order))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Tenant", "acme")
	filtertest.Run(f, r, nil)
	if got, _ := io.ReadAll(r.Body); string(got) != order {
		t.Fatal("body not restored")
	}
	// unknown_paths: allow passes undocumented paths through.
	lax, _ := filtertest.Build("openapi", "orders", filter.Options{"spec_file": write(t, spec), "unknown_paths": "allow"})
	r, _ = http.NewRequest("GET", "http://api.example.com/health", nil)
	if v := filtertest.Run(lax, r, nil).Request; v.Deny {
		t.Fatalf("allow: %+v", v)
	}
}

func TestSpecErrors(t *testing.T) {
	bad := map[string]string{
		"swagger":  "swagger: '2.0'\npaths: {}\n",
		"no paths": "openapi: 3.1.0\ninfo: {title: x, version: '1'}\n",
		"bad path": "openapi: 3.1.0\npaths: {orders: {get: {}}}\n",
		"template": "openapi: 3.1.0\npaths: {/a/{id: {get: {}}}\n",
		"garbage":  "::: not yaml\n\t- [",
	}
	for name, content := range bad {
		if _, err := filtertest.Build("openapi", "o", filter.Options{"spec_file": write(t, content)}); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	for i, o := range []filter.Options{{}, {"spec_file": "relative.yaml"}, {"spec_file": write(t, spec), "unknown_paths": "maybe"}, {"spec_file": write(t, spec), "base_path": "v1/"}, {"spec_file": write(t, spec), "max_body_bytes": 0.5}} {
		if _, err := filtertest.Build("openapi", "o", o); err == nil {
			t.Errorf("options case %d accepted", i)
		}
	}
	// JSON specs and an explicit base path.
	js := `{"openapi":"3.1.0","paths":{"/ping":{"get":{}}}}`
	f, err := filtertest.Build("openapi", "o", filter.Options{"spec_file": write(t, js), "base_path": "/api"})
	if err != nil {
		t.Fatal(err)
	}
	r, _ := http.NewRequest("GET", "http://x/api/ping", nil)
	if v := filtertest.Run(f, r, nil).Request; v.Deny {
		t.Fatalf("json spec: %+v", v)
	}
}
