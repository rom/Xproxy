package graphql

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/filter/filtertest"
)

func post(query string) *http.Request {
	body := `{"query":` + jsonString(query) + `,"variables":{"n":50}}`
	r, _ := http.NewRequest("POST", "http://api.test/graphql", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.ContentLength = int64(len(body))
	return r
}

func jsonString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return `"` + s + `"`
}

func TestBounds(t *testing.T) {
	f, err := filtertest.Build("graphql", "gql", filter.Options{"max_depth": 3, "max_complexity": 50, "max_aliases": 2, "max_batch": 2, "introspection": false, "max_query_bytes": 512})
	if err != nil {
		t.Fatal(err)
	}
	ok := func(q string) {
		t.Helper()
		if v := filtertest.Run(f, post(q), nil).Request; v.Deny {
			t.Fatalf("%s: denied %+v", q, v)
		}
	}
	denied := func(q, detail string) {
		t.Helper()
		v := filtertest.Run(f, post(q), nil).Request
		if !v.Deny || v.Detail != detail || v.Status != 400 || v.Response == nil {
			t.Fatalf("%s: got %+v want %s", q, v, detail)
		}
		body, _ := io.ReadAll(v.Response.Body)
		if !strings.Contains(string(body), `"errors"`) || v.Response.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("%s: response %s", q, body)
		}
	}
	ok(`{ me { name } }`)
	ok(`query Q($n: Int) { me { friends(first: 3) { name } } }`)
	ok(`{ me { friends { posts { title } } } }`)                          // depth 3
	denied(`{ me { friends { posts { comments { text } } } } }`, "depth") // depth 4
	denied(`{ me { friends(first: 100) { name } } }`, "complexity")       // 1 + 1 + 100
	denied(`{ me { friends(first: $n) { name } } }`, "complexity")        // the request says n is 50
	ok(`{ a: me { name } b: me { name } }`)                               // 2 aliases
	denied(`{ a: me { name } b: me { name } c: me { name } }`, "aliases") // 3 aliases
	denied(`{ __schema { types { name } } }`, "introspection")
	denied(`{ me { name `, "syntax")
	denied(`fragment F on User { friends { ...F } } { me { ...F } }`, "depth") // cycle
	ok(`fragment N on User { name } { me { ...N ... on Admin { level } } }`)
	ok(`mutation M @deprecated(reason: "x") { save(input: {a: [1, 2, {b: "q)"}], s: """block ) """}) { id } }`)
	denied(strings.Repeat("{ a ", 200)+strings.Repeat("}", 200), "size")

	// Batches.
	batch := func(n int) *http.Request {
		ops := make([]string, n)
		for i := range ops {
			ops[i] = `{"query":"{ me { name } }"}`
		}
		body := "[" + strings.Join(ops, ",") + "]"
		r, _ := http.NewRequest("POST", "http://api.test/graphql", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		return r
	}
	if v := filtertest.Run(f, batch(2), nil).Request; v.Deny {
		t.Fatalf("batch of 2: %+v", v)
	}
	if v := filtertest.Run(f, batch(3), nil).Request; !v.Deny || v.Detail != "batch" {
		t.Fatalf("batch of 3: %+v", v)
	}
	// GET and application/graphql bodies; non GraphQL traffic passes.
	get, _ := http.NewRequest("GET", "http://api.test/graphql?query="+strings.ReplaceAll(`{ me { friends { posts { comments { text } } } } }`, " ", "%20"), nil)
	if v := filtertest.Run(f, get, nil).Request; !v.Deny || v.Detail != "depth" {
		t.Fatalf("GET: %+v", v)
	}
	raw, _ := http.NewRequest("POST", "http://api.test/graphql", strings.NewReader(`{ __type(name: "User") { name } }`))
	raw.Header.Set("Content-Type", "application/graphql")
	if v := filtertest.Run(f, raw, nil).Request; !v.Deny || v.Detail != "introspection" {
		t.Fatalf("application/graphql: %+v", v)
	}
	other, _ := http.NewRequest("POST", "http://api.test/upload", strings.NewReader("data"))
	other.Header.Set("Content-Type", "text/plain")
	if v := filtertest.Run(f, other, nil).Request; v.Deny {
		t.Fatal("non GraphQL request denied")
	}
	// The body is readable again after inspection.
	r := post(`{ me { name } }`)
	filtertest.Run(f, r, nil)
	if b, _ := io.ReadAll(r.Body); !strings.Contains(string(b), "me") {
		t.Fatal("body consumed")
	}
}

func TestValidate(t *testing.T) {
	bad := []filter.Options{
		{"max_depth": 0},
		{"max_complexity": -1},
		{"max_batch": 0},
		{"max_query_bytes": 10},
		{"list_args": []any{"1bad"}},
		{"bogus": true},
	}
	for i, o := range bad {
		if _, err := filtertest.Build("graphql", "g", o); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	if _, err := filtertest.Build("graphql", "g", nil); err != nil {
		t.Fatalf("defaults rejected: %v", err)
	}
}

// The active set stops a fragment that refers to itself, not one that is
// referred to twice: fragment f0 spreading f1 twice, f1 spreading f2
// twice and so on doubles the work per level, so a query of a couple of
// kilobytes expands to a billion visits with no cycle in it and every
// configured bound respected.
func TestFragmentExpansionIsBounded(t *testing.T) {
	var b strings.Builder
	const levels = 40
	b.WriteString("query { ...f0 }\n")
	for i := 0; i < levels; i++ {
		fmt.Fprintf(&b, "fragment f%d on T { ...f%d ...f%d }\n", i, i+1, i+1)
	}
	fmt.Fprintf(&b, "fragment f%d on T { id }\n", levels)
	f, err := filtertest.Build("graphql", "gql", filter.Options{"max_depth": 10, "max_query_bytes": 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan filter.Verdict, 1)
	go func() { done <- filtertest.Run(f, post(b.String()), nil).Request }()
	select {
	case v := <-done:
		if !v.Deny {
			t.Fatalf("a %d-byte fragment bomb was allowed: %+v", b.Len(), v)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("the %d-byte query did not come back: the expansion is unbounded", b.Len())
	}
}
