package proxy

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

const inventorySpec = `openapi: 3.0.3
info: {title: Orders, version: "1"}
paths:
  /v1/orders:
    get: {responses: {"200": {description: ok}}}
    post: {responses: {"201": {description: created}}}
  /v1/orders/{id}:
    get:
      parameters: [{name: id, in: path, required: true, schema: {type: string}}]
      responses: {"200": {description: ok}}
    delete:
      parameters: [{name: id, in: path, required: true, schema: {type: string}}]
      responses: {"204": {description: gone}}
`

func TestAPIInventoryIntegration(t *testing.T) {
	a := newBackend(t, "a")
	dir := t.TempDir()
	spec := filepath.Join(dir, "orders.yaml")
	if err := os.WriteFile(spec, []byte(inventorySpec), 0o600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "inventory.json")
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners:
    - {name: main, address: "127.0.0.1:0"}
logging:
  access: {enabled: false}
api_inventory: {state_file: %s, zombie_after: 1h}
filters:
  - name: orders-spec
    kind: openapi
    options: {spec_file: %s, unknown_paths: allow}
upstreams:
  - name: app
    endpoints: [{address: %s}]
routes:
  - {name: api, hosts: [api.test], upstream: app, filters: [orders-spec]}
  - {name: web, hosts: [www.test], upstream: app}
  - {name: static, hosts: [static.test], respond: {status: 204}}
`, state, spec, a.addr())
	s, url := startServer(t, yaml)
	get(t, url+"/v1/orders?page=1", "Host", "api.test", "Authorization", "Bearer x.y.z")
	get(t, url+"/v1/orders/42", "Host", "api.test", "Authorization", "Bearer x.y.z")
	get(t, url+"/v1/orders/43", "Host", "api.test", "Cookie", "sid=1")
	get(t, url+"/v1/admin/export", "Host", "api.test")
	get(t, url+"/v2/orders/7", "Host", "api.test")
	get(t, url+"/products/99", "Host", "www.test")
	get(t, url+"/anything", "Host", "static.test")
	rep := s.APIInventory("all", 0)
	if !rep.Enabled {
		t.Fatal("inventory disabled")
	}
	byKey := map[string]int{}
	var orders, admin, v2, products, static int
	for i, e := range rep.Items {
		byKey[e.Method+" "+e.Host+e.Path] = i
		switch {
		case e.Path == "/v1/orders/{id}" && e.Method == "GET":
			orders = i + 1
		case e.Path == "/v1/admin/export":
			admin = i + 1
		case e.Path == "/v2/orders/*":
			v2 = i + 1
		case e.Path == "/products/*":
			products = i + 1
		case e.Host == "static.test":
			static = i + 1
		}
	}
	if orders == 0 || admin == 0 || v2 == 0 || products == 0 || static != 0 {
		t.Fatalf("items %+v", rep.Items)
	}
	o := rep.Items[orders-1]
	if o.Requests != 2 || o.Documented != "yes" || o.Route != "api" || len(o.Auth) != 2 || o.Version != "v1" {
		t.Fatalf("orders %+v", o)
	}
	if ad := rep.Items[admin-1]; !ad.Shadow || ad.Documented != "no" {
		t.Fatalf("admin %+v", ad)
	}
	if v := rep.Items[v2-1]; !v.Shadow || v.Version != "v2" {
		t.Fatalf("v2 %+v", v)
	}
	if p := rep.Items[products-1]; p.Documented != "" || p.Shadow || p.Route != "web" {
		t.Fatalf("products %+v", p)
	}
	if rep.Zombie != 2 {
		t.Fatalf("zombies %d (POST /v1/orders and DELETE /v1/orders/{id} expected)", rep.Zombie)
	}
	if z := s.APIInventory("zombie", 0); len(z.Items) != 2 || z.Items[0].Requests != 0 {
		t.Fatalf("zombie view %+v", z.Items)
	}
	// State persists across a shutdown.
	if err := s.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(state); err != nil {
		t.Fatalf("state file: %v", err)
	}
	s2, _ := startServer(t, yaml)
	if rep2 := s2.APIInventory("all", 0); rep2.Endpoints != rep.Endpoints {
		t.Fatalf("restored %d endpoints, want %d", rep2.Endpoints, rep.Endpoints)
	}
	_ = http.StatusOK
}
