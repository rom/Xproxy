package graphql

import (
	"net/http"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/filter/filtertest"
)

// TestContentTypeCaseInsensitive: media types are matched like every
// GraphQL server matches them, so "Application/JSON" and the
// graphql-response+json variants are bounded too.
func TestContentTypeCaseInsensitive(t *testing.T) {
	f, err := filtertest.Build("graphql", "gql", filter.Options{"max_depth": 2})
	if err != nil {
		t.Fatal(err)
	}
	deep := `{ a { b { c { d } } } }`
	for _, ct := range []string{"application/json", "Application/JSON", "application/JSON; charset=utf-8", "application/graphql-response+json", "application/graphql+json"} {
		body := `{"query":` + jsonString(deep) + `}`
		r, _ := http.NewRequest("POST", "http://api.test/graphql", strings.NewReader(body))
		r.Header.Set("Content-Type", ct)
		r.ContentLength = int64(len(body))
		if v := filtertest.Run(f, r, nil).Request; !v.Deny || v.Detail != "depth" {
			t.Errorf("%s: %+v", ct, v)
		}
	}
	r, _ := http.NewRequest("POST", "http://api.test/graphql", strings.NewReader(deep))
	r.Header.Set("Content-Type", "Application/GraphQL")
	if v := filtertest.Run(f, r, nil).Request; !v.Deny || v.Detail != "depth" {
		t.Errorf("raw graphql: %+v", v)
	}
}
