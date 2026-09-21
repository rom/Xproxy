package graphql

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/filter/filtertest"
)

// A GraphQL query is a program the client writes and the origin runs.
// This filter is what decides, before the origin sees it, whether the
// program is one the origin can afford — so the interesting inputs are
// the ones that are cheap to write and expensive to answer, and the
// ones that are not really GraphQL at all.

// guard builds the filter with the bounds a test wants.
func guardFor(t *testing.T, opts filter.Options) filter.Filter {
	t.Helper()
	base := filter.Options{
		"max_depth": 10, "max_complexity": 1000, "max_aliases": 20,
		"max_batch": 5, "introspection": false, "max_query_bytes": 64 << 10,
	}
	for k, v := range opts {
		base[k] = v
	}
	f, err := filtertest.Build("graphql", "gql", base)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// within runs a query and requires the filter to answer inside a
// budget. Everything here is a small document; a filter that took
// seconds over one would be the denial of service it exists to prevent.
func within(t *testing.T, f filter.Filter, query string, budget time.Duration) filter.Verdict {
	t.Helper()
	type result struct{ v filter.Verdict }
	done := make(chan result, 1)
	go func() {
		done <- result{filtertest.Run(f, post(query), nil).Request}
	}()
	select {
	case r := <-done:
		return r.v
	case <-time.After(budget):
		t.Fatalf("the filter did not answer within %v for a %d byte query", budget, len(query))
		return filter.Verdict{}
	}
}

// TestFragmentBombs covers the expansion attack in its several shapes.
// A fragment that spreads the next one twice doubles the work per
// level, so a couple of kilobytes reach a billion visits with no cycle
// in the document and every configured bound respected.
func TestFragmentBombs(t *testing.T) {
	f := guardFor(t, nil)

	// The classic: 30 levels, each spreading the next twice.
	var b strings.Builder
	b.WriteString("{ ...f0 }\n")
	const depth = 30
	for i := 0; i < depth; i++ {
		if i == depth-1 {
			fmt.Fprintf(&b, "fragment f%d on Q { name }\n", i)
			continue
		}
		fmt.Fprintf(&b, "fragment f%d on Q { ...f%d ...f%d }\n", i, i+1, i+1)
	}
	query := b.String()
	if len(query) > 4096 {
		t.Fatalf("the bomb is %d bytes; it is meant to be small", len(query))
	}
	if v := within(t, f, query, 10*time.Second); !v.Deny {
		t.Fatal("a fragment bomb was passed to the origin")
	}

	// The same shape spread four times per level, which is smaller
	// still for the same expansion.
	b.Reset()
	b.WriteString("{ ...g0 }\n")
	for i := 0; i < 16; i++ {
		if i == 15 {
			fmt.Fprintf(&b, "fragment g%d on Q { name }\n", i)
			continue
		}
		fmt.Fprintf(&b, "fragment g%d on Q { ...g%d ...g%d ...g%d ...g%d }\n", i, i+1, i+1, i+1, i+1)
	}
	if v := within(t, f, b.String(), 10*time.Second); !v.Deny {
		t.Fatal("a wider fragment bomb was passed to the origin")
	}

	// A cycle: two fragments spreading each other. It never finishes,
	// so it must be refused rather than walked.
	cycle := "{ ...a }\nfragment a on Q { ...b }\nfragment b on Q { ...a }\n"
	if v := within(t, f, cycle, 10*time.Second); !v.Deny {
		t.Fatal("a fragment cycle was passed to the origin")
	}

	// A fragment that spreads itself.
	self := "{ ...s }\nfragment s on Q { name ...s }\n"
	if v := within(t, f, self, 10*time.Second); !v.Deny {
		t.Fatal("a self-spreading fragment was passed to the origin")
	}

	// A spread naming a fragment the document does not define is not an
	// expansion at all; whatever the verdict, it must be quick.
	within(t, f, "{ ...missing }", 5*time.Second)
}

// TestDeepNesting covers depth on the field side rather than through
// fragments, including a document deep enough to be a stack problem for
// a recursive parser.
func TestDeepNesting(t *testing.T) {
	f := guardFor(t, nil)
	for _, n := range []int{50, 1000, 20000} {
		t.Run(fmt.Sprintf("depth%d", n), func(t *testing.T) {
			query := "{" + strings.Repeat(" a {", n) + " name" + strings.Repeat(" }", n) + " }"
			v := within(t, f, query, 20*time.Second)
			if !v.Deny {
				t.Fatalf("a %d deep query was passed to the origin", n)
			}
		})
	}
}

// TestAliasMultiplication covers the other cheap multiplier: the same
// field asked for many times under different names. The origin does
// the work once per alias.
func TestAliasMultiplication(t *testing.T) {
	f := guardFor(t, filter.Options{"max_aliases": 10})
	var b strings.Builder
	b.WriteString("{")
	for i := 0; i < 5000; i++ {
		fmt.Fprintf(&b, " a%d: expensiveField { name }", i)
	}
	b.WriteString(" }")
	v := within(t, f, b.String(), 20*time.Second)
	if !v.Deny {
		t.Fatal("5000 aliases were passed to the origin")
	}
	if v.Detail != "aliases" && v.Detail != "complexity" && v.Detail != "size" {
		t.Fatalf("refused as %q", v.Detail)
	}
}

// TestListArgumentMultiplication covers the pagination argument, where
// one number turns one row into a million. `max_list` caps how much a
// single argument may multiply the cost — it is a cost model, not a
// page-size limit, and it has to be: a client can move the number into
// a variable, whose value this filter never sees, so a literal refused
// above the cap would be a refusal one edit avoids. What the cap does
// buy is that the nesting of paginated fields still multiplies, and
// that is what makes the expensive queries expensive.
func TestListArgumentMultiplication(t *testing.T) {
	f := guardFor(t, filter.Options{"max_complexity": 1000, "max_list": 100})
	denied := []string{
		`{ users(first: 100) { friends(first: 100) { posts(first: 100) { title } } } }`,
		`{ users(first: $n) { friends(first: $n) { posts(first: $n) { title } } } }`,
		`{ users(first: 100) { a: friends(first: 100) { name } b: friends(first: 100) { name } } }`,
	}
	for _, q := range denied {
		t.Run(q[:min(40, len(q))], func(t *testing.T) {
			if v := within(t, f, q, 10*time.Second); !v.Deny {
				t.Fatal("passed to the origin")
			}
		})
	}
	// A modest page size is fine.
	if v := within(t, f, `{ users(first: 10) { name } }`, 10*time.Second); v.Deny {
		t.Fatalf("a ten row page was refused: %+v", v)
	}
	// One enormous literal is scored as the cap, so whether it passes
	// depends on the budget rather than on the number the client wrote.
	tight := guardFor(t, filter.Options{"max_complexity": 50, "max_list": 100})
	if v := within(t, tight, `{ users(first: 1000000) { name } }`, 10*time.Second); !v.Deny {
		t.Fatal("a million row page was passed to an origin with a budget of 50")
	}
	loose := guardFor(t, filter.Options{"max_complexity": 1000, "max_list": 100})
	if v := within(t, loose, `{ users(first: 1000000) { name } }`, 10*time.Second); v.Deny {
		t.Fatalf("the cap was not applied: %+v", v)
	}
}

// TestMalformedDocuments covers the inputs that are not GraphQL. A
// parser that walked off the end of one of these would do so on an
// unauthenticated request body.
func TestMalformedDocuments(t *testing.T) {
	f := guardFor(t, nil)
	queries := []string{
		"", " ", "{", "}", "{{{{", "}}}}", "{ a", "a }", "query", "query {",
		"fragment", "fragment f", "fragment f on", "fragment f on Q {",
		"{ a(", "{ a(b", "{ a(b:", "{ a(b: }", "{ a(b: [1,2 }", `{ a(b: "unterminated }`,
		"{ ... }", "{ ...on }", "{ ... on Q }", "{ a @ }", "{ a @dir( }",
		"\x00", "{ \x00 }", "{ a\x00b }", "{ \u00e9 }", "{ a\u200bb }",
		strings.Repeat("{", 10000),
		strings.Repeat("(", 10000),
		"{ a" + strings.Repeat(" @d", 10000) + " }",
		"{ a(" + strings.Repeat("b: 1, ", 10000) + ") }",
		"{ " + strings.Repeat("a ", 100000) + "}",
	}
	for i, q := range queries {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic on %.40q: %v", q, r)
				}
			}()
			within(t, f, q, 20*time.Second)
		})
	}
}

// TestIntrospectionIsRefusedInEveryForm covers the schema query, which
// is how an attacker learns what the API offers. With introspection
// off, none of its spellings may pass.
func TestIntrospectionIsRefusedInEveryForm(t *testing.T) {
	f := guardFor(t, filter.Options{"introspection": false})
	for _, q := range []string{
		`{ __schema { types { name } } }`,
		`{ __type(name: "User") { fields { name } } }`,
		`query { a: __schema { queryType { name } } }`,
		`{ me { name } __schema { types { name } } }`,
		`{ ...f }` + "\n" + `fragment f on Q { __schema { types { name } } }`,
		`{ ... on Q { __schema { types { name } } } }`,
	} {
		t.Run(q[:min(30, len(q))], func(t *testing.T) {
			v := within(t, f, q, 10*time.Second)
			if !v.Deny {
				t.Fatal("introspection reached the origin")
			}
		})
	}
	// __typename is not introspection: every client sends it.
	if v := within(t, f, `{ me { __typename name } }`, 10*time.Second); v.Deny {
		t.Fatalf("__typename was refused: %+v", v)
	}
	// And with introspection allowed, the schema query passes.
	on := guardFor(t, filter.Options{"introspection": true})
	if v := within(t, on, `{ __schema { types { name } } }`, 10*time.Second); v.Deny {
		t.Fatalf("introspection was refused though it is enabled: %+v", v)
	}
}

// TestDenialsAreGraphQLErrors requires a refusal to be a document the
// client's own library can read, since a GraphQL client does not expect
// an HTML error page.
func TestDenialsAreGraphQLErrors(t *testing.T) {
	f := guardFor(t, filter.Options{"max_depth": 2})
	v := within(t, f, `{ a { b { c { d } } } }`, 10*time.Second)
	if !v.Deny || v.Response == nil {
		t.Fatalf("verdict %+v", v)
	}
	if got := v.Response.Header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("content type %q", got)
	}
	if v.Status != 400 {
		t.Fatalf("status %d", v.Status)
	}
}

// TestNonQueryRequestsPassThrough covers the requests this filter has
// no opinion about: a GET, another content type, an empty body. A
// filter that refused them would break the rest of the API.
func TestNonQueryRequestsPassThrough(t *testing.T) {
	f := guardFor(t, nil)
	get, _ := httpNewRequest("GET", "http://api.test/graphql", "")
	if v := filtertest.Run(f, get, nil).Request; v.Deny {
		t.Fatalf("a GET was refused: %+v", v)
	}
	form, _ := httpNewRequest("POST", "http://api.test/graphql", "a=1")
	form.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if v := filtertest.Run(f, form, nil).Request; v.Deny {
		t.Fatalf("a form post was refused: %+v", v)
	}
}

// httpNewRequest is a small helper for the pass-through cases.
func httpNewRequest(method, url, body string) (*http.Request, error) {
	r, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	r.ContentLength = int64(len(body))
	return r, nil
}
