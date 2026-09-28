package flow

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/filter/filtertest"
)

// checkout is the flow the tests use: a cart, then an address, then a payment.
var checkout = []any{
	map[string]any{
		"name": "checkout",
		"steps": []any{
			map[string]any{"name": "cart", "methods": []any{"POST"}, "paths": []any{"/api/cart"}},
			map[string]any{"name": "address", "methods": []any{"POST"}, "paths": []any{"/api/checkout/address"},
				"after": []any{"cart"}},
			map[string]any{"name": "pay", "methods": []any{"POST"}, "paths": []any{"/api/checkout/pay"},
				"after": []any{"address"}},
		},
	},
}

func build(t *testing.T, opts filter.Options) *Filter {
	t.Helper()
	if _, ok := opts["flows"]; !ok {
		opts["flows"] = checkout
	}
	f, err := filtertest.Build("flow", "checkout", opts)
	if err != nil {
		t.Fatal(err)
	}
	// A built filter joins the status registry, as one built by a generation
	// does; closing it is what that generation's teardown does.
	t.Cleanup(func() { _ = f.(*Filter).Close() })
	return f.(*Filter)
}

// post sends one request, from an address that stands in for one caller.
//
// The address goes in the filter.Info the data plane builds and not in
// RemoteAddr: a filter reads the client from there, because behind a trusted
// proxy the connection's peer is the balancer and not the client.
func post(f *Filter, from, path string) filtertest.Result {
	return do(f, from, http.MethodPost, path)
}

func do(f *Filter, from, method, path string) filtertest.Result {
	r := httptest.NewRequest(method, "http://shop.test"+path, nil)
	info := &filter.Info{ClientIP: netip.MustParseAddr(from)}
	return filtertest.RunWithInfo(f, info, r, nil)
}

// The flow followed in order is not touched.
func TestAFlowInOrderIsAllowed(t *testing.T) {
	f := build(t, filter.Options{"action": "block"})
	for _, p := range []string{"/api/cart", "/api/checkout/address", "/api/checkout/pay"} {
		if res := post(f, "10.0.0.1", p); res.Request.Deny {
			t.Fatalf("%s was refused in a flow followed in order: %+v", p, res.Request)
		}
	}
	if st := f.Status(); st.Steps != 3 || st.Flagged != 0 {
		t.Errorf("steps %d flagged %d, wanted 3 and 0", st.Steps, st.Flagged)
	}
}

// And the request that skips a step is the one this filter exists for. Every
// request in it is individually valid: the right method, the right path, a well
// formed body. Only the order is wrong.
func TestASkippedStepIsRefused(t *testing.T) {
	f := build(t, filter.Options{"action": "block"})
	res := post(f, "10.0.0.2", "/api/checkout/pay")
	if !res.Request.Deny || res.Request.Reason != "flow" {
		t.Fatalf("a payment with no cart and no address was allowed: %+v", res.Request)
	}
	if !strings.Contains(res.Request.Detail, "checkout.pay") ||
		!strings.Contains(res.Request.Detail, ReasonOutOfOrder) {
		t.Errorf("the refusal does not say what was out of order: %q", res.Request.Detail)
	}
	// It names the step that was missing, because "out of order" is not an
	// answer an operator can act on and "the address step was never seen" is.
	if !strings.Contains(res.Request.Detail, "address") {
		t.Errorf("the refusal does not name the missing step: %q", res.Request.Detail)
	}
	// 409 Conflict: the request is well formed and the caller is entitled to
	// make it, but not in the state they are in. 403 would say they may never.
	if res.Request.Status != http.StatusConflict {
		t.Errorf("status %d, wanted 409", res.Request.Status)
	}
}

// Only the immediate dependency is required, so a flow is a chain rather than a
// set: reaching the address step needs the cart, and reaching the payment needs
// the address -- which needed the cart.
func TestTheDependencyIsTheStepBeforeIt(t *testing.T) {
	f := build(t, filter.Options{"action": "block"})
	// The cart, then straight to the payment: the address is missing.
	if res := post(f, "10.0.0.3", "/api/cart"); res.Request.Deny {
		t.Fatal("the entry step was refused")
	}
	res := post(f, "10.0.0.3", "/api/checkout/pay")
	if !res.Request.Deny || !strings.Contains(res.Request.Detail, "address") {
		t.Fatalf("a payment that skipped the address was allowed: %+v", res.Request)
	}
}

// A step is recorded even when it is refused.
//
// A refused step that was not recorded would be refused on every retry, and a
// caller who genuinely lost their earlier step -- to a restart, to the other
// relay in a pair -- could never get through at all: the flow would be
// permanently broken for them rather than broken once.
func TestARefusedStepIsStillRecorded(t *testing.T) {
	f := build(t, filter.Options{"action": "block"})
	if res := post(f, "10.0.0.4", "/api/checkout/address"); !res.Request.Deny {
		t.Fatal("an address with no cart was allowed")
	}
	// The address step is now on record, so the payment after it goes through.
	if res := post(f, "10.0.0.4", "/api/checkout/pay"); res.Request.Deny {
		t.Fatalf("the payment after a refused address was refused too: %+v", res.Request)
	}
}

// One caller's steps are not another's. Two callers reaching the payment, one of
// whom filled a cart, is one refusal.
func TestProgressIsPerCaller(t *testing.T) {
	f := build(t, filter.Options{"action": "block"})
	post(f, "10.0.0.5", "/api/cart")
	post(f, "10.0.0.5", "/api/checkout/address")
	if res := post(f, "10.0.0.5", "/api/checkout/pay"); res.Request.Deny {
		t.Fatalf("the caller who followed the flow was refused: %+v", res.Request)
	}
	if res := post(f, "10.0.0.6", "/api/checkout/pay"); !res.Request.Deny {
		t.Fatal("a second caller was let through on the first caller's cart")
	}
}

// A step outside the window counts as never taken, which is what makes the
// window a window rather than a memory.
func TestAStepOutsideTheWindowIsNotAStep(t *testing.T) {
	f := build(t, filter.Options{"action": "block", "window": "10m"})
	base := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	f.now = func() time.Time { return base }
	post(f, "10.0.0.7", "/api/cart")
	f.now = func() time.Time { return base.Add(5 * time.Minute) }
	if res := post(f, "10.0.0.7", "/api/checkout/address"); res.Request.Deny {
		t.Fatalf("a cart five minutes old did not count: %+v", res.Request)
	}
	// An hour later the address has expired too.
	f.now = func() time.Time { return base.Add(time.Hour) }
	if res := post(f, "10.0.0.7", "/api/checkout/pay"); !res.Request.Deny {
		t.Fatal("an address an hour old still counted inside a ten minute window")
	}
}

// once refuses a second visit, which is the double-submit control.
func TestAOnceOnlyStepRefusesTheSecondVisit(t *testing.T) {
	flows := []any{map[string]any{
		"name": "checkout",
		"steps": []any{
			map[string]any{"name": "cart", "methods": []any{"POST"}, "paths": []any{"/api/cart"}},
			map[string]any{"name": "pay", "methods": []any{"POST"}, "paths": []any{"/api/checkout/pay"},
				"after": []any{"cart"}, "once": true},
		},
	}}
	f := build(t, filter.Options{"action": "block", "flows": flows})
	post(f, "10.0.0.8", "/api/cart")
	if res := post(f, "10.0.0.8", "/api/checkout/pay"); res.Request.Deny {
		t.Fatalf("the first payment was refused: %+v", res.Request)
	}
	res := post(f, "10.0.0.8", "/api/checkout/pay")
	if !res.Request.Deny || !strings.Contains(res.Request.Detail, ReasonRepeated) {
		t.Fatalf("the second payment was allowed: %+v", res.Request)
	}
}

// And once is off by default, because a step reached twice is usually a customer
// who pressed the button again after a timeout, and the second press is the one
// that works.
func TestAStepIsRepeatableByDefault(t *testing.T) {
	f := build(t, filter.Options{"action": "block"})
	post(f, "10.0.0.9", "/api/cart")
	post(f, "10.0.0.9", "/api/checkout/address")
	for i := 0; i < 3; i++ {
		if res := post(f, "10.0.0.9", "/api/checkout/pay"); res.Request.Deny {
			t.Fatalf("payment %d was refused: %+v", i+1, res.Request)
		}
	}
}

// Traffic the operator did not describe is not touched. A filter that decided
// about every request would be a second, accidental positive security policy.
func TestARequestThatIsNoStepIsNotJudged(t *testing.T) {
	f := build(t, filter.Options{"action": "block"})
	if res := do(f, "10.0.0.20", http.MethodGet, "/api/products"); res.Request.Deny {
		t.Fatalf("a request outside every flow was refused: %+v", res.Request)
	}
	if st := f.Status(); st.Requests != 0 {
		t.Errorf("a request outside every flow was counted: %d", st.Requests)
	}
}

// The path match is on whole segments, so a neighbouring endpoint is not inside
// somebody's flow: /api/cartridges is not /api/cart.
func TestThePathMatchIsOnWholeSegments(t *testing.T) {
	f := build(t, filter.Options{"action": "block"})
	if res := post(f, "10.0.0.10", "/api/cartridges"); res.Request.Deny {
		t.Fatalf("a neighbouring path was judged as a step: %+v", res.Request)
	}
	// It was not judged, and it was not counted either: the filter saw a request
	// that is no step of any flow.
	if st := f.Status(); st.Requests != 0 {
		t.Errorf("a neighbouring path was counted as a step: %d", st.Requests)
	}
	// And it did not satisfy the cart. The step to ask about is the one that
	// depends on the cart -- the address. Asking about the payment instead would
	// pass whatever happened here, because the payment depends on the address and
	// the address was never taken.
	if res := post(f, "10.0.0.10", "/api/checkout/address"); !res.Request.Deny {
		t.Fatal("/api/cartridges satisfied the cart step")
	}
}

// The method narrows a step: a GET of the cart page is not filling a cart.
func TestTheMethodNarrowsAStep(t *testing.T) {
	f := build(t, filter.Options{"action": "block"})
	if res := do(f, "10.0.0.11", http.MethodGet, "/api/cart"); res.Request.Deny {
		t.Fatalf("a GET of the cart was judged: %+v", res.Request)
	}
	if res := post(f, "10.0.0.11", "/api/checkout/address"); !res.Request.Deny {
		t.Fatal("a GET of the cart satisfied a step whose method is POST")
	}
}

// log is the default action: the finding is recorded and the request goes on.
// The flow is declared rather than learned, so refusing is honest -- but a flow
// declared slightly wrong refuses real customers, and the relay cannot see the
// steps a caller took before it was in the path.
func TestTheDefaultActionRecordsAndCarries(t *testing.T) {
	f := build(t, filter.Options{})
	res := post(f, "10.0.0.12", "/api/checkout/pay")
	if res.Request.Deny {
		t.Fatalf("the default action refused: %+v", res.Request)
	}
	if st := f.Status(); st.Flagged != 1 || st.Blocked != 0 {
		t.Errorf("flagged %d blocked %d, wanted 1 and 0", st.Flagged, st.Blocked)
	}
	// And the access log carries it, because an alert nobody can find is not one.
	if got := strings.Join(fields(res.Attrs), " "); !strings.Contains(got, "checkout.pay") {
		t.Errorf("the access log does not carry the finding: %v", res.Attrs)
	}
}

func fields(in []any) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		out = append(out, fmt.Sprint(v))
	}
	return out
}

// The caller is the identity when the chain established one, and only the
// address when it did not.
//
// This is what makes the filter worth enforcing. Keyed on an address, one NAT
// gateway's cart would satisfy another user's payment -- every customer behind
// one corporate egress would share a flow. Keyed on the identity, a flow
// followed through one account is one caller whatever addresses it arrives from.
func TestTheCallerIsTheIdentityWhenThereIsOne(t *testing.T) {
	f := build(t, filter.Options{"action": "block"})
	// Two accounts on one address: the second must not inherit the first's cart.
	asUser := func(user, method, path string) filtertest.Result {
		r := httptest.NewRequest(method, "http://shop.test"+path, nil)
		ctx, id := filter.WithIdentity(r.Context())
		_ = id
		filter.SetIdentity(ctx, "oidc", user)
		r = r.WithContext(ctx)
		info := &filter.Info{ClientIP: netip.MustParseAddr("203.0.113.9")}
		return filtertest.RunWithInfo(f, info, r, nil)
	}
	asUser("alice", http.MethodPost, "/api/cart")
	asUser("alice", http.MethodPost, "/api/checkout/address")
	if res := asUser("alice", http.MethodPost, "/api/checkout/pay"); res.Request.Deny {
		t.Fatalf("alice followed the flow and was refused: %+v", res.Request)
	}
	if res := asUser("bob", http.MethodPost, "/api/checkout/pay"); !res.Request.Deny {
		t.Fatal("bob paid on alice's cart, from the same address")
	}
	// And one account from two addresses is still one caller.
	asUser("carol", http.MethodPost, "/api/cart")
	r := httptest.NewRequest(http.MethodPost, "http://shop.test/api/checkout/address", nil)
	ctx, _ := filter.WithIdentity(r.Context())
	filter.SetIdentity(ctx, "oidc", "carol")
	elsewhere := &filter.Info{ClientIP: netip.MustParseAddr("198.51.100.44")}
	if res := filtertest.RunWithInfo(f, elsewhere, r.WithContext(ctx), nil); res.Request.Deny {
		t.Errorf("carol's flow broke when her address changed: %+v", res.Request)
	}
}

// The caller bound is a bound, and reaching it is counted. A caller dropped
// mid-flow arrives at its next step looking like one that skipped a step, which
// is exactly why the number is in the status view rather than only in the code.
func TestTheCallerBoundIsCounted(t *testing.T) {
	f := build(t, filter.Options{"max_callers": 16})
	for i := 0; i < 24; i++ {
		post(f, fmt.Sprintf("10.1.0.%d", i), "/api/cart")
	}
	st := f.Status()
	if st.Callers > 16 {
		t.Errorf("the table holds %d callers against a bound of 16", st.Callers)
	}
	if st.Dropped == 0 {
		t.Error("callers were turned out of the table and none were counted")
	}
}

// The configuration a flow cannot be written wrong in silence.
func TestTheFlowsThatAreRefused(t *testing.T) {
	step := func(m map[string]any) []any { return []any{m} }
	for _, c := range []struct {
		name string
		opts filter.Options
		want string
	}{
		{"no flows", filter.Options{"flows": []any{}}, "at least one is required"},
		{"a flow with no steps", filter.Options{"flows": []any{map[string]any{"name": "f"}}}, "steps"},
		{"a step with no paths", filter.Options{"flows": []any{map[string]any{"name": "f",
			"steps": step(map[string]any{"name": "s"})}}}, "paths"},
		{"a step whose path is relative", filter.Options{"flows": []any{map[string]any{"name": "f",
			"steps": step(map[string]any{"name": "s", "paths": []any{"api/cart"}})}}}, "must start with /"},
		{"a dependency that is not a step", filter.Options{"flows": []any{map[string]any{"name": "f",
			"steps": step(map[string]any{"name": "s", "paths": []any{"/a"}, "after": []any{"nowhere"}})}}},
			"not a step of this flow"},
		{"a step that depends on itself", filter.Options{"flows": []any{map[string]any{"name": "f",
			"steps": step(map[string]any{"name": "s", "paths": []any{"/a"}, "after": []any{"s"}})}}},
			"cannot depend on itself"},
		// A forward dependency is a flow no caller can ever complete, and it
		// would look like an attack on every legitimate request.
		{"a dependency written below", filter.Options{"flows": []any{map[string]any{"name": "f",
			"steps": []any{
				map[string]any{"name": "first", "paths": []any{"/a"}, "after": []any{"second"}},
				map[string]any{"name": "second", "paths": []any{"/b"}},
			}}}}, "nothing could ever reach it"},
		{"an unknown action", filter.Options{"action": "refuse"}, "must be log, challenge or block"},
		{"a window nobody could complete a flow in", filter.Options{"window": "0s"}, "between 1s and 24h"},
		{"two flows with one name", filter.Options{"flows": []any{
			map[string]any{"name": "f", "steps": step(map[string]any{"name": "s", "paths": []any{"/a"}})},
			map[string]any{"name": "f", "steps": step(map[string]any{"name": "t", "paths": []any{"/b"}})},
		}}, "used twice"},
		{"a lower case method", filter.Options{"flows": []any{map[string]any{"name": "f",
			"steps": step(map[string]any{"name": "s", "paths": []any{"/a"}, "methods": []any{"post"}})}}},
			"must be upper case"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, ok := c.opts["flows"]; !ok {
				c.opts["flows"] = checkout
			}
			_, err := filtertest.Build("flow", "checkout", c.opts)
			if err == nil {
				t.Fatal("the configuration was accepted")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("the refusal does not say %q: %v", c.want, err)
			}
		})
	}
}

// A well formed flow builds, which is the other half of the table above: a
// validator that refused everything would pass every case in it.
//
// The first step has no dependency and cannot have one -- its only candidates are
// itself and a step written below it, and both are refused above -- so a flow
// that validates always has a way in.
func TestAWellFormedFlowBuilds(t *testing.T) {
	_, err := filtertest.Build("flow", "checkout", filter.Options{"flows": []any{map[string]any{
		"name": "loop",
		"steps": []any{
			map[string]any{"name": "a", "paths": []any{"/a"}},
			map[string]any{"name": "b", "paths": []any{"/b"}, "after": []any{"a"}},
		},
	}}})
	if err != nil {
		t.Fatalf("a flow with an entry step was refused: %v", err)
	}
}
