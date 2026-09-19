package apiinv

import (
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestSkeleton(t *testing.T) {
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	rep := Report{View: "undocumented", Since: now.Add(-time.Hour), Items: []Endpoint{
		{Host: "api.example.com", Method: "GET", Path: "/users/*/orders/*", Route: "api", Requests: 40, Status2xx: 38, Status4xx: 2, Auth: []string{"bearer"}, RespTypes: []string{"application/json"}, FirstSeen: now.Add(-time.Hour), LastSeen: now, Shadow: true, Documented: "no"},
		{Host: "api.example.com", Method: "POST", Path: "/users/*/orders", Route: "api", Requests: 5, Status2xx: 5, Auth: []string{"api_key", "cookie"}, ReqTypes: []string{"application/json"}, RespTypes: []string{"application/json"}, Version: "v2"},
		{Host: "eu.example.com", Method: "GET", Path: "/users/*/orders/*", Route: "api-eu", Requests: 2, Status5xx: 2, Auth: []string{"basic"}},
		{Host: "api.example.com", Method: "DELETE", Path: "/*", Requests: 1},
	}}
	doc := Skeleton(rep, "", now)
	if doc["openapi"] != "3.0.3" {
		t.Fatalf("version %v", doc["openapi"])
	}
	paths := doc["paths"].(map[string]any)
	item, ok := paths["/users/{usersId}/orders/{ordersId}"].(map[string]any)
	if !ok {
		t.Fatalf("paths %v", paths)
	}
	if params := item["parameters"].([]any); len(params) != 2 || params[0].(map[string]any)["name"] != "usersId" || params[1].(map[string]any)["name"] != "ordersId" {
		t.Fatalf("parameters %v", item["parameters"])
	}
	get := item["get"].(map[string]any)
	ext := get["x-xproxy"].(map[string]any)
	if ext["requests"] != uint64(42) || len(ext["hosts"].([]any)) != 2 || ext["route"] != "api" || ext["documented"] != false {
		t.Fatalf("merged extension %v", ext)
	}
	resp := get["responses"].(map[string]any)
	if _, ok := resp["2XX"].(map[string]any)["content"].(map[string]any)["application/json"]; !ok || resp["4XX"] == nil || resp["5XX"] == nil {
		t.Fatalf("responses %v", resp)
	}
	if sec := get["security"].([]any); len(sec) != 2 {
		t.Fatalf("security %v", sec)
	}
	post := paths["/users/{usersId}/orders"].(map[string]any)["post"].(map[string]any)
	if post["requestBody"] == nil || post["x-xproxy"].(map[string]any)["version"] != "v2" {
		t.Fatalf("post %v", post)
	}
	if _, ok := paths["/{id}"].(map[string]any)["delete"]; !ok {
		t.Fatalf("root parameter path %v", paths)
	}
	schemes := doc["components"].(map[string]any)["securitySchemes"].(map[string]any)
	for _, name := range []string{"bearerAuth", "apiKey", "cookieAuth", "basicAuth"} {
		if schemes[name] == nil {
			t.Fatalf("scheme %s missing: %v", name, schemes)
		}
	}
	servers := doc["servers"].([]any)
	if len(servers) != 2 || servers[0].(map[string]any)["url"] != "https://api.example.com" {
		t.Fatalf("servers %v", servers)
	}
	// The YAML round trips and reads as a document.
	out, err := SkeletonYAML(rep, "Orders", now)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := yaml.Unmarshal(out, &back); err != nil || back["info"].(map[string]any)["title"] != "Orders" || !strings.Contains(string(out), "x-xproxy") {
		t.Fatalf("yaml %v\n%s", err, out)
	}
	// Empty reports are still documents.
	if d := Skeleton(Report{}, "", now); len(d["paths"].(map[string]any)) != 0 || d["servers"] != nil || d["components"] != nil {
		t.Fatalf("empty %v", d)
	}
	for in, want := range map[string]string{"/a-b/*": "/a-b/{aBId}", "/*/*": "/{id}/{id2}", "/x/*/y/*/x/*": "/x/{xId}/y/{yId}/x/{xId2}", "/_/*": "/_/{paramId}"} {
		if got := openAPIPath(in); got != want {
			t.Errorf("%s -> %s want %s", in, got, want)
		}
	}
}
