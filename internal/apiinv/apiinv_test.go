package apiinv

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInventory(t *testing.T) {
	tb := New()
	tb.Configure(Config{Enabled: true, MaxEndpoints: 100, ZombieAfter: 24 * time.Hour}, nil)
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	obs := func(host, method, path string, status int, auth string, docu Tri, tmpl string) {
		tb.Observe(Observation{Host: host, Method: method, Path: path, Route: "api", Status: status, Auth: auth, RequestType: "application/json", Documented: docu, Template: tmpl}, now)
	}
	obs("api.test", "GET", "/v1/users/*", 200, "bearer", Yes, "")
	obs("api.test", "GET", "/v1/users/*", 404, "bearer", Yes, "")
	obs("api.test", "POST", "/v1/users", 201, "bearer", Yes, "")
	obs("api.test", "GET", "/v1/debug", 200, "none", No, "")
	obs("api.test", "GET", "/v2/users/*", 200, "bearer", Yes, "")
	obs("api.test", "GET", "/health", 200, "none", Unknown, "")
	docs := map[string][]Operation{"api": {{Method: "GET", Path: "/v1/users/*"}, {Method: "POST", Path: "/v1/users"}, {Method: "DELETE", Path: "/v1/users/*"}, {Method: "GET", Path: "/v2/users/*"}}}
	rep := tb.Report("all", 0, docs, now)
	if !rep.Enabled || rep.Endpoints != 5 || rep.Shadow != 1 || rep.Zombie != 1 || rep.Superseded != 1 {
		t.Fatalf("report %+v", rep)
	}
	byKey := map[string]Endpoint{}
	for _, e := range rep.Items {
		byKey[e.Method+" "+e.Path] = e
	}
	if u := byKey["GET /v1/users/*"]; u.Requests != 2 || u.Status2xx != 1 || u.Status4xx != 1 || u.Version != "v1" || !u.Superseded || u.Documented != "yes" || len(u.Auth) != 1 || u.Auth[0] != "bearer" {
		t.Fatalf("users %+v", u)
	}
	if d := byKey["GET /v1/debug"]; !d.Shadow || d.Documented != "no" {
		t.Fatalf("debug %+v", d)
	}
	if z := byKey["DELETE /v1/users/*"]; !z.Zombie || z.Requests != 0 || z.Route != "api" {
		t.Fatalf("zombie %+v", z)
	}
	if h := byKey["GET /health"]; h.Documented != "" || h.Shadow || h.Version != "" {
		t.Fatalf("health %+v", h)
	}
	if v2 := byKey["GET /v2/users/*"]; v2.Superseded || v2.Version != "v2" {
		t.Fatalf("v2 %+v", v2)
	}
	// Views.
	if s := tb.Report("shadow", 0, docs, now); len(s.Items) != 1 || s.Items[0].Path != "/v1/debug" {
		t.Fatalf("shadow view %+v", s.Items)
	}
	if z := tb.Report("zombie", 0, docs, now); len(z.Items) != 1 {
		t.Fatalf("zombie view %+v", z.Items)
	}
	if v := tb.Report("versions", 0, docs, now); len(v.Items) != 5 {
		t.Fatalf("versions view %d", len(v.Items))
	}
	if d := tb.Report("undocumented", 0, docs, now); len(d.Items) != 2 {
		t.Fatalf("undocumented view %d", len(d.Items))
	}
	if top := tb.Report("all", 2, docs, now); len(top.Items) != 2 || top.Items[0].Requests != 2 {
		t.Fatalf("top %+v", top.Items)
	}
	// A documented endpoint silent for longer than zombie_after becomes a zombie.
	later := now.Add(48 * time.Hour)
	if z := tb.Report("zombie", 0, docs, later); len(z.Items) != 4 {
		t.Fatalf("stale zombies %d", len(z.Items))
	}
	// Save and load.
	path := filepath.Join(t.TempDir(), "inventory.json")
	if err := tb.Save(path); err != nil {
		t.Fatal(err)
	}
	tb2 := New()
	tb2.Configure(Config{Enabled: true, MaxEndpoints: 100, ZombieAfter: 24 * time.Hour, StateFile: path}, nil)
	if rep2 := tb2.Report("all", 0, nil, now); rep2.Endpoints != 5 || !rep2.Since.Equal(rep.Since) {
		t.Fatalf("loaded %+v", rep2)
	}
	// Bound.
	small := New()
	small.Configure(Config{Enabled: true, MaxEndpoints: 100}, nil)
	for i := 0; i < 150; i++ {
		small.Observe(Observation{Host: "h", Method: "GET", Path: "/p" + string(rune('a'+i%26)) + string(rune('a'+i/26))}, now)
	}
	if r := small.Report("all", 0, nil, now); r.Endpoints != 100 || r.Dropped != 50 {
		t.Fatalf("bound %d dropped %d", r.Endpoints, r.Dropped)
	}
	off := New()
	off.Observe(Observation{Host: "h", Method: "GET", Path: "/x"}, now)
	if r := off.Report("all", 0, nil, now); r.Enabled || r.Endpoints != 0 {
		t.Fatal("disabled table recorded")
	}
	if v, base := versionOf("/api/v3/items/*"); v != "v3" || base != "/api/{v}/items/*" {
		t.Fatalf("versionOf %q %q", v, base)
	}
}

func TestObserveBoundsMediaTypes(t *testing.T) {
	tb := New()
	tb.Configure(Config{Enabled: true, MaxEndpoints: 1}, nil)
	tb.Observe(Observation{
		Host: "api.test", Method: "POST", Path: "/upload",
		RequestType:  strings.Repeat("x", MaxMediaTypeBytes+1),
		ResponseType: "application/json",
	}, time.Now())

	items := tb.Report("all", 0, nil, time.Now()).Items
	if len(items) != 1 || len(items[0].ReqTypes) != 0 || len(items[0].RespTypes) != 1 {
		t.Fatalf("unexpected bounded media types: %+v", items)
	}
}
