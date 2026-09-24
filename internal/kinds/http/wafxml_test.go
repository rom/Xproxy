package http

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// docs/CONFIG.md says which XML targets the engine populates -- the
// attribute values and the character data, not an evaluated XPath -- and
// what to use for a named element instead. Both halves are driven here,
// because "XPath is supported" is exactly the kind of claim that costs an
// operator a rule they believe is running.
func TestTheXMLTargetsAreTheTwoTheEngineFills(t *testing.T) {
	b := newBackend(t, "app")
	yaml := fmt.Sprintf(`
version: 1
server:
  listeners: [{name: main, address: "127.0.0.1:0"}]
logging: {access: {enabled: false}}
waf:
  default_mode: block
  request_body_limit: 8192
  profiles:
    - name: default
      directives: |
        SecRequestBodyAccess On
        SecRule REQUEST_HEADERS:Content-Type "@rx xml" \
            "id:9200,phase:1,pass,nolog,ctl:requestBodyProcessor=XML"
        SecRule XML://@* "@streq drop-tables" \
            "id:9201,phase:2,deny,status:403,msg:'an attribute the rule reads'"
        SecRule XML:/* "@rx (?i)union\s+select" \
            "id:9202,phase:2,deny,status:406,msg:'character data the rule reads'"
        SecRule XML:/invoice/total "@rx ." \
            "id:9203,phase:2,deny,status:418,msg:'a path the engine does not evaluate'"
upstreams:
  - {name: app, endpoints: [{address: %s}]}
routes:
  - {name: app, hosts: [app.test], upstream: app}
`, b.addr())
	_, target := startServer(t, yaml)
	post := func(body string) int {
		t.Helper()
		r, _ := http.NewRequest(http.MethodPost, target+"/invoices", strings.NewReader(body))
		r.Host = "app.test"
		r.Header.Set("Content-Type", "application/xml")
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	// The attribute collection is populated, so a rule over it fires.
	if code := post(`<invoice action="drop-tables"><total>10</total></invoice>`); code != http.StatusForbidden {
		t.Errorf("an attribute rule answered %d, want 403", code)
	}
	// So is the character data.
	if code := post(`<invoice><note>1 UNION SELECT password FROM users</note></invoice>`); code != http.StatusNotAcceptable {
		t.Errorf("a character data rule answered %d, want 406", code)
	}
	// And a path the engine does not evaluate selects nothing, so the
	// 418 rule never fires: an ordinary document is served.
	if code := post(`<invoice><total>10</total></invoice>`); code != http.StatusOK {
		t.Errorf("an ordinary document answered %d, want 200 (a path rule must not be believed to work)", code)
	}
}
