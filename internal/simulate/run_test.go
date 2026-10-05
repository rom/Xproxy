package simulate

import (
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/config"
	_ "github.com/rom/xproxy/internal/kinds/http" // the kind under simulation
)

func parse(t *testing.T, yaml string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

const wafYAML = `version: 1
waf:
  default_mode: block
  profiles:
    - {name: default, crs: {paranoia_level: 1}}
server:
  listeners: [{name: edge, address: "0.0.0.0:443"}]
upstreams:
  - {name: app, endpoints: [{address: "10.0.0.1:8080"}]}
routes:
  - {name: all, paths: ["/"], upstream: app, waf: {profile: default, mode: block}}
`

// The whole point, in one test: a request the WAF refuses is reported as
// refused, a request it does not is reported as allowed, and nothing was sent
// to 10.0.0.1.
func TestASimulationDecidesWithoutAnUpstream(t *testing.T) {
	r, err := Start(parse(t, wafYAML), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := r.Close(); err != nil {
			t.Error(err)
		}
	}()

	ok := r.Ask(Input{Name: "a plain request", Bytes: request("GET", "/about", "shop.example.com", "")})
	if ok.Decision != Allowed {
		t.Errorf("a plain request: %+v", ok)
	}
	if ok.Status != 200 {
		t.Errorf("status %d: the sink answers so the response path runs", ok.Status)
	}

	bad := r.Ask(Input{Name: "an injection", Bytes: request("GET", "/?id=1%27+OR+1%3D1--", "shop.example.com", "")})
	if bad.Decision != Refused {
		t.Fatalf("an injection was not refused: %+v", bad)
	}
	if !strings.HasPrefix(bad.Reason, "waf") {
		t.Errorf("reason %q: the WAF refused it", bad.Reason)
	}
	if bad.Status != 403 {
		t.Errorf("status %d", bad.Status)
	}
}

// The configuration is rewritten, and the caller's copy is not.
func TestOfflineLeavesTheCallersConfigurationAlone(t *testing.T) {
	cfg := parse(t, `version: 1
cluster: {node_id: sim, listen: "unix:/run/xproxy-cluster/sim.sock", peers: ["unix:/run/xproxy-cluster/other.sock"]}
capture: {directory: /var/lib/xproxy/capture}
server:
  listeners: [{name: edge, address: "0.0.0.0:443"}]
upstreams:
  - {name: app, endpoints: [{address: "10.0.0.1:8080"}]}
routes:
  - {name: all, paths: ["/"], upstream: app}
`)
	out, rep, err := Offline(cfg, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Cluster == nil || cfg.Capture == nil {
		t.Fatal("Offline modified the configuration it was given")
	}
	if out.Cluster != nil || out.Capture != nil {
		t.Errorf("cluster %v capture %v: both reach outside this process", out.Cluster, out.Capture)
	}
	want := []string{"capture", "cluster"}
	if strings.Join(rep.SwitchedOff, " ") != strings.Join(want, " ") {
		t.Errorf("switched off %v, want %v", rep.SwitchedOff, want)
	}
	if out.Management.Socket != "" {
		t.Error("a simulation must not bind the estate's management socket")
	}
}

// request builds a raw HTTP/1.1 request.
func request(method, target, host, body string) []byte {
	var b strings.Builder
	b.WriteString(method + " " + target + " HTTP/1.1\r\nHost: " + host + "\r\n")
	if body != "" {
		b.WriteString("Content-Length: " + itoa(len(body)) + "\r\n")
	}
	b.WriteString("Connection: close\r\n\r\n" + body)
	return []byte(b.String())
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d [20]byte
	i := len(d)
	for n > 0 {
		i--
		d[i] = byte('0' + n%10)
		n /= 10
	}
	return string(d[i:])
}
