package filter

import (
	"context"
	"net/http"
	"testing"
)

type nop struct{}

func (nop) Name() string                          { return "nop" }
func (nop) Begin(context.Context, *Info) Instance { return nop{} }
func (nop) Request(*http.Request) Verdict         { return Continue }
func (nop) Response(*http.Response) Verdict       { return Continue }
func (nop) End() []any                            { return nil }

func TestRegistry(t *testing.T) {
	k := Kind{Name: "test_kind", Description: "t", Validate: func(Options) error { return nil },
		New: func(string, Options, Env) (Filter, error) { return nop{}, nil }}
	Register(k)
	if _, ok := Lookup("test_kind"); !ok {
		t.Fatal("not found")
	}
	found := false
	for _, n := range KindNames() {
		if n == "test_kind" {
			found = true
		}
	}
	if !found {
		t.Fatal("not listed")
	}
	for _, bad := range []Kind{{Name: "Bad", Validate: k.Validate, New: k.New}, {Name: "", Validate: k.Validate, New: k.New}, {Name: "test_kind", Validate: k.Validate, New: k.New}, {Name: "x"}} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("kind %q accepted", bad.Name)
				}
			}()
			Register(bad)
		}()
	}
}

func TestOptionsDecode(t *testing.T) {
	type cfg struct {
		Name  string   `json:"name"`
		N     int      `json:"n"`
		List  []string `json:"list"`
		Inner struct {
			On bool `json:"on"`
		} `json:"inner"`
	}
	var c cfg
	o := Options{"name": "a", "n": 3, "list": []any{"x", "y"}, "inner": map[any]any{"on": true}}
	if err := o.Decode(&c); err != nil {
		t.Fatal(err)
	}
	if c.Name != "a" || c.N != 3 || len(c.List) != 2 || !c.Inner.On {
		t.Fatalf("%+v", c)
	}
	if err := (Options{"nope": 1}).Decode(&c); err == nil {
		t.Fatal("unknown key accepted")
	}
	if err := (Options(nil)).Decode(&c); err != nil {
		t.Fatal(err)
	}
}
