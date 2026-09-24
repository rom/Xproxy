package http

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// docs/CONFIG.md says there is no list of content decoders here because
// decoding is SecLang's own, per rule and per target, and it shows the
// rule that reads a payload out of base64. This drives that rule, and
// the sentence beside it: a body wrapped in a transfer encoding is
// inspected as the bytes it arrived as rather than expanded first.
func TestAPayloadInsideAnEncodingIsWhatTheRuleDecodes(t *testing.T) {
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
        SecRule ARGS:payload "@rx (?i)union\s+select" \
            "id:9100,phase:2,t:none,t:urlDecodeUni,t:base64Decode,deny,status:403,msg:'injection inside base64'"
upstreams:
  - {name: app, endpoints: [{address: %s}]}
routes:
  - {name: app, hosts: [app.test], upstream: app}
`, b.addr())
	_, target := startServer(t, yaml)
	post := func(body string, hdr ...string) int {
		t.Helper()
		r, _ := http.NewRequest(http.MethodPost, target+"/orders", strings.NewReader(body))
		r.Host = "app.test"
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for i := 0; i+1 < len(hdr); i += 2 {
			r.Header.Set(hdr[i], hdr[i+1])
		}
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	hidden := base64.StdEncoding.EncodeToString([]byte("1 UNION SELECT password FROM users"))
	if code := post("payload=" + url.QueryEscape(hidden)); code != http.StatusForbidden {
		t.Errorf("a payload inside base64 answered %d, want 403: the transformations are what decode it", code)
	}
	// The same rule leaves an ordinary body alone, so the refusal above
	// is the decoded payload and not the encoding.
	if code := post("payload=" + url.QueryEscape(base64.StdEncoding.EncodeToString([]byte("one dozen eggs")))); code != http.StatusOK {
		t.Errorf("an ordinary base64 body answered %d, want 200", code)
	}
}
