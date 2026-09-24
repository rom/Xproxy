package graphql

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/filter/filtertest"
)

// body posts a query with the variables and operation name a request
// would carry.
func body(query, name string, vars string) *http.Request {
	b := `{"query":` + jsonString(query) + `,"operationName":` + jsonString(name)
	if vars != "" {
		b += `,"variables":` + vars
	}
	b += `}`
	r, _ := http.NewRequest("POST", "http://api.test/graphql", strings.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	r.ContentLength = int64(len(b))
	return r
}

func get(query, name, vars string) *http.Request {
	q := url.Values{"query": {query}}
	if name != "" {
		q.Set("operationName", name)
	}
	if vars != "" {
		q.Set("variables", vars)
	}
	r, _ := http.NewRequest("GET", "http://api.test/graphql?"+q.Encode(), nil)
	return r
}

func build(t *testing.T, opts filter.Options) filter.Filter {
	t.Helper()
	f, err := filtertest.Build("graphql", "gql", opts)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func allowed(t *testing.T, f filter.Filter, r *http.Request, what string) {
	t.Helper()
	if v := filtertest.Run(f, r, nil).Request; v.Deny {
		t.Fatalf("%s: denied %+v", what, v)
	}
}

func refused(t *testing.T, f filter.Filter, r *http.Request, detail, what string) {
	t.Helper()
	v := filtertest.Run(f, r, nil).Request
	if !v.Deny || v.Detail != detail {
		t.Fatalf("%s: got %+v, want detail %s", what, v, detail)
	}
}

// GET is for queries. The GraphQL over HTTP specification says so, and
// the reason is that a GET is what a link, an image tag, a prefetch and a
// crawler all produce: a mutation reachable that way is a mutation
// anybody can fire from another origin, with the browser attaching the
// cookies. No configuration makes that safe, so nothing turns it off.
func TestAMutationMayNotArriveByGET(t *testing.T) {
	f := build(t, filter.Options{})
	refused(t, f, get(`mutation M { deleteAccount(id: 1) { ok } }`, "", ""), "get_mutation", "a mutation by GET")
	refused(t, f, get(`subscription S { events { id } }`, "", ""), "get_mutation", "a subscription by GET")
	// The same operations by POST are allowed by default, and the same
	// query by GET is what GET is for.
	allowed(t, f, get(`query Q { me { name } }`, "", ""), "a query by GET")
	allowed(t, f, get(`{ me { name } }`, "", ""), "the shorthand form by GET")
	allowed(t, f, body(`mutation M { deleteAccount(id: 1) { ok } }`, "", ""), "a mutation by POST")
	// A mutation named inside a document whose selected operation is a
	// query is still a mutation the server could run.
	refused(t, f, get(`query Q { me { name } } mutation M { x { ok } }`, "Q", ""), "get_mutation", "a mutation beside the selected query")
}

// What an operation does is a policy question of its own: a read-only
// endpoint is a thing an operator should be able to say out loud.
func TestMutationsAndSubscriptionsCanBeRefusedOutright(t *testing.T) {
	f := build(t, filter.Options{"mutations": "deny", "subscriptions": "deny"})
	refused(t, f, body(`mutation M { pay(amount: 1) { ok } }`, "", ""), "mutation", "a mutation on a read-only endpoint")
	refused(t, f, body(`subscription S { ticks { at } }`, "", ""), "subscription", "a subscription")
	allowed(t, f, body(`query Q { me { name } }`, "", ""), "a query")
	// The default is allow, since most endpoints take both.
	open := build(t, filter.Options{})
	allowed(t, open, body(`mutation M { pay(amount: 1) { ok } }`, "", ""), "a mutation by default")
}

// An allow list of operation names is the strongest thing this filter can
// offer a closed client set: the queries are known, so anything else is
// not a query this API serves. It only means something if an anonymous
// operation cannot walk past it, which is why naming a list requires
// names.
func TestOnlyTheOperationsOnTheListMayRun(t *testing.T) {
	f := build(t, filter.Options{"allow_operations": []any{"GetMe", "ListOrders"}})
	allowed(t, f, body(`query GetMe { me { name } }`, "GetMe", ""), "a listed operation")
	allowed(t, f, body(`query ListOrders { orders { id } }`, "ListOrders", ""), "the other listed operation")
	refused(t, f, body(`query Probe { __typename }`, "Probe", ""), "operation", "an operation not on the list")
	// An anonymous operation is on no list, and a list that let it
	// through would be a list in name only.
	refused(t, f, body(`{ me { name } }`, "", ""), "unnamed", "an anonymous operation")
	// require_operation_name on its own, without a list.
	named := build(t, filter.Options{"require_operation_name": true})
	allowed(t, named, body(`query Q { me { name } }`, "Q", ""), "a named operation")
	refused(t, named, body(`{ me { name } }`, "", ""), "unnamed", "an anonymous operation")
}

// A directive is evaluated per field it decorates, so a field carrying a
// thousand of them is a thousand evaluations before anything resolves.
// The count is of the query text, which is the number an operator can
// look at their own query and predict.
func TestDirectivesAreBounded(t *testing.T) {
	f := build(t, filter.Options{"max_directives": 3})
	allowed(t, f, body(`query Q($c: Boolean!) { a @include(if: $c) b @skip(if: $c) }`, "Q", `{"c":true}`), "two directives")
	many := "query Q($c: Boolean!) { a" + strings.Repeat(" @include(if: $c)", 8) + " }"
	refused(t, f, body(many, "Q", `{"c":true}`), "directives", "eight directives")
	// Directives on the operation and inside a fragment are counted too.
	refused(t, f, body(`query Q @a @b @c @d { x }`, "Q", ""), "directives", "directives on the operation")
}

// Depth says nothing about breadth: an operation asking for two hundred
// root fields is two hundred resolvers at depth one.
func TestBreadthIsBoundedAsWellAsDepth(t *testing.T) {
	f := build(t, filter.Options{"max_root_fields": 5, "max_complexity": 100000})
	wide := "query Q { "
	for i := 0; i < 40; i++ {
		wide += "f" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + " "
	}
	wide += "}"
	refused(t, f, body(wide, "Q", ""), "root_fields", "forty root fields")
	allowed(t, f, body(`query Q { a b c d e }`, "Q", ""), "five root fields")
	// Depth is unaffected: a narrow deep query is judged by depth.
	allowed(t, f, body(`query Q { a { b { c } } }`, "Q", ""), "a narrow query")
}

// A pagination argument given as a variable is a real number the server
// will use. Scoring it as the cap refuses a query that costs nothing,
// which is how a complexity bound gets turned off by the operator it kept
// annoying. A variable the request does not carry is still the worst case.
func TestAVariableIsWorthReadingBeforeAssumingTheWorst(t *testing.T) {
	f := build(t, filter.Options{"max_complexity": 60, "max_list": 1000})
	q := `query Q($n: Int) { me { friends(first: $n) { name } } }`
	allowed(t, f, body(q, "Q", `{"n":10}`), "ten friends")
	refused(t, f, body(q, "Q", `{"n":500}`), "complexity", "five hundred friends")
	// No variables at all, a variable of another type, a negative one and
	// a fractional one are each the worst case rather than a free pass.
	for _, vars := range []string{"", `{}`, `{"n":"10"}`, `{"n":-5}`, `{"n":1.5}`, `{"n":null}`} {
		refused(t, f, body(q, "Q", vars), "complexity", "variables "+vars)
	}
	// And the literal still wins when it is larger than the variable.
	refused(t, f, body(`query Q($n: Int) { me { a: friends(first: 500) { name } b: friends(first: $n) { name } } }`, "Q", `{"n":1}`),
		"complexity", "a large literal beside a small variable")
}

// A document may carry a client's whole query file and select one
// operation from it. Only that one runs, so only that one is measured --
// otherwise a client is refused for the cost of queries it did not send.
func TestOnlyTheSelectedOperationIsMeasured(t *testing.T) {
	f := build(t, filter.Options{"max_depth": 3, "introspection": false})
	doc := `query Cheap { me { name } }
query Expensive { me { friends { posts { comments { text } } } } }`
	allowed(t, f, body(doc, "Cheap", ""), "the cheap operation was selected")
	refused(t, f, body(doc, "Expensive", ""), "depth", "the expensive operation was selected")
	// With no name the server picks, so every operation is measured.
	refused(t, f, body(doc, "", ""), "depth", "no operation selected")
	// The same for introspection: a document that also contains an
	// introspection query is judged by the operation that will run.
	intro := `query Cheap { me { name } }
query Intro { __schema { types { name } } }`
	allowed(t, f, body(intro, "Cheap", ""), "introspection in an operation that does not run")
	refused(t, f, body(intro, "Intro", ""), "introspection", "introspection selected")
}

// A persisted query carries no text: there is nothing to parse, nothing
// to measure, and every bound here walks past it. Allowing that is the
// default because the origin only runs documents it already has, but a
// deployment reached through this filter should be able to say that an
// unreadable query is not an allowed one.
func TestAQueryThisFilterCannotReadCanBeRefused(t *testing.T) {
	persisted := `{"operationName":"GetMe","extensions":{"persistedQuery":{"version":1,"sha256Hash":"abc"}}}`
	send := func(f filter.Filter, b string) filter.Verdict {
		r, _ := http.NewRequest("POST", "http://api.test/graphql", strings.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
		r.ContentLength = int64(len(b))
		return filtertest.Run(f, r, nil).Request
	}
	open := build(t, filter.Options{})
	if v := send(open, persisted); v.Deny {
		t.Fatalf("the default refused a persisted query: %+v", v)
	}
	closed := build(t, filter.Options{"persisted": "deny"})
	if v := send(closed, persisted); !v.Deny || v.Detail != "persisted" {
		t.Fatalf("got %+v, want detail persisted", v)
	}
	// A request with a query in it is unaffected, and a body that is not
	// a GraphQL request at all is still not this filter's business.
	if v := send(closed, `{"query":"{ me { name } }"}`); v.Deny {
		t.Fatalf("a readable query was refused: %+v", v)
	}
	if v := send(closed, `{"hello":"world"}`); v.Deny {
		t.Fatalf("somebody else's JSON was refused: %+v", v)
	}
}

// The batch path carries the same policy as the single one: a batch is
// the obvious place to hide the operation the policy refuses.
func TestABatchIsJudgedOperationByOperation(t *testing.T) {
	f := build(t, filter.Options{"max_batch": 3, "mutations": "deny"})
	send := func(b string) filter.Verdict {
		r, _ := http.NewRequest("POST", "http://api.test/graphql", strings.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
		r.ContentLength = int64(len(b))
		return filtertest.Run(f, r, nil).Request
	}
	if v := send(`[{"query":"query A { me { name } }"},{"query":"query B { x }"}]`); v.Deny {
		t.Fatalf("an honest batch was refused: %+v", v)
	}
	v := send(`[{"query":"query A { me { name } }"},{"query":"mutation M { pay { ok } }"}]`)
	if !v.Deny || v.Detail != "mutation" {
		t.Fatalf("got %+v, want detail mutation", v)
	}
	// Each entry's own variables apply to its own query.
	f2 := build(t, filter.Options{"max_batch": 3, "max_complexity": 60})
	sendTo := func(b string) filter.Verdict {
		r, _ := http.NewRequest("POST", "http://api.test/graphql", strings.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
		r.ContentLength = int64(len(b))
		return filtertest.Run(f2, r, nil).Request
	}
	q := `query Q($n: Int) { me { friends(first: $n) { name } } }`
	if v := sendTo(`[{"query":` + jsonString(q) + `,"variables":{"n":5}},{"query":` + jsonString(q) + `,"variables":{"n":9}}]`); v.Deny {
		t.Fatalf("two cheap operations were refused: %+v", v)
	}
	if v := sendTo(`[{"query":` + jsonString(q) + `,"variables":{"n":5}},{"query":` + jsonString(q) + `,"variables":{"n":900}}]`); !v.Deny || v.Detail != "complexity" {
		t.Fatalf("got %+v, want complexity for the second entry", v)
	}
}

func TestPolicyOptionsAreValidated(t *testing.T) {
	for _, tc := range []struct {
		opts filter.Options
		want string
	}{
		{filter.Options{"mutations": "maybe"}, "mutations: must be allow or deny"},
		{filter.Options{"subscriptions": "maybe"}, "subscriptions: must be allow or deny"},
		{filter.Options{"persisted": "maybe"}, "persisted: must be allow or deny"},
		{filter.Options{"allow_operations": []any{"not a name"}}, "is not a GraphQL name"},
		{filter.Options{"max_directives": -1}, "max_directives"},
		{filter.Options{"max_root_fields": 0}, "max_root_fields"},
	} {
		if _, err := filtertest.Build("graphql", "gql", tc.opts); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: error %v, want one containing %q", tc.opts, err, tc.want)
		}
	}
}
