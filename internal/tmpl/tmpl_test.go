package tmpl

import (
	"errors"
	"testing"
)

type mapResolver map[string]string

func (m mapResolver) Resolve(name, arg string) (string, bool) {
	k := name
	if arg != "" {
		k += ":" + arg
	}
	v, ok := m[k]
	return v, ok
}

func TestParseAndExpand(t *testing.T) {
	r := mapResolver{"client_ip": "203.0.113.9", "header:X-Tenant": "acme", "1": "users", "id": "42", "route": "api"}
	cases := map[string]string{
		"static":                               "static",
		"ip=${client_ip}":                      "ip=203.0.113.9",
		"${header:X-Tenant}/${1}/${id}":        "acme/users/42",
		"cost $$5 for ${route}":                "cost $5 for api",
		"missing ${header:X-None} stays empty": "missing  stays empty",
		"a $ sign alone":                       "a $ sign alone",
		"${route}${route}":                     "apiapi",
	}
	for in, want := range cases {
		tp, err := Parse(in, "id")
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if got := tp.Expand(r); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
		if (tp.Static() && in != want && in != "a $ sign alone") || (!tp.Static() && in == want) {
			t.Errorf("%q: static=%v", in, tp.Static())
		}
	}
	if tp, _ := Parse("cost $$5"); !tp.Static() || tp.Expand(nil) != "cost $5" {
		t.Fatal("escaped dollar in a static template")
	}
}

func TestParseErrors(t *testing.T) {
	bad := []string{"${nope}", "${header}", "${client_ip:x}", "${10}", "${0}", "${unterminated", "${}", "${name}"}
	for _, in := range bad {
		if _, err := Parse(in); err == nil {
			t.Errorf("%q accepted", in)
		} else if in != "${unterminated" && in != "${}" && !errors.Is(err, ErrUnknown) {
			t.Errorf("%q: %v", in, err)
		}
	}
	if _, err := Parse("${name}", "name"); err != nil {
		t.Fatalf("named capture: %v", err)
	}
}

func TestLenient(t *testing.T) {
	tp, err := ParseLenient(`<script>const x = ` + "`${notavar}`" + `;</script> ${status} ${unterminated`)
	if err != nil {
		t.Fatal(err)
	}
	got := tp.Expand(mapResolver{"status": "404"})
	if got != "<script>const x = `${notavar}`;</script> 404 ${unterminated" {
		t.Fatalf("lenient: %q", got)
	}
	var nilT *Template
	if nilT.Expand(nil) != "" || !nilT.Static() || nilT.Raw() != "" {
		t.Fatal("nil template")
	}
}
