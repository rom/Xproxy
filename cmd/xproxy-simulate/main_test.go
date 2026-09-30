package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/xproxy/internal/listener"
	"github.com/rom/xproxy/internal/proxy"
)

// The simulate command needs no daemon: it starts the engine itself. So the
// harness is three files.
func simulateHarness(t *testing.T) (before, after, corpus string) {
	t.Helper()
	dir := t.TempDir()
	common := `
cluster: {node_id: sim, listen: "unix:/run/xproxy-cluster/a.sock", peers: ["unix:/run/xproxy-cluster/b.sock"]}
server:
  listeners: [{name: edge, address: "0.0.0.0:443"}]
upstreams:
  - {name: app, endpoints: [{address: "10.0.0.1:8080"}]}
routes:
  - {name: all, paths: ["/"], upstream: app%s}
`
	before = filepath.Join(dir, "before.yaml")
	after = filepath.Join(dir, "after.yaml")
	corpus = filepath.Join(dir, "requests.http")
	write := func(path, body string) {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(before, "version: 1"+strings_Replace(common, "%s", ""))
	write(after, "version: 1\nwaf:\n  default_mode: block\n  profiles:\n    - {name: default, crs: {paranoia_level: 1}}"+
		strings_Replace(common, "%s", ", waf: {profile: default, mode: block}"))
	write(corpus, `# what the scanner flagged, and one request that has to keep working
>>> name="the injection"
GET /?id=1%27+OR+1%3D1-- HTTP/1.1
Host: shop.example.com
Connection: close

>>> name="the daily report"
GET /reports/daily HTTP/1.1
Host: shop.example.com
Connection: close
`)
	return before, after, corpus
}

// strings_Replace keeps the harness readable without importing fmt for one
// substitution.
func strings_Replace(s, old, new string) string { return strings.Replace(s, old, new, 1) }

func TestTheSimulateCommand(t *testing.T) {
	before, after, corpus := simulateHarness(t)
	for _, tc := range []struct {
		name string
		args []string
		code int
		want []string
	}{
		// The flag is required, and the refusal explains what it asserts.
		{"without the assertion", []string{"-a", before, "-requests", corpus}, 2,
			[]string{"-offline is required", "starts this configuration in this process"}},
		// One configuration: what it decides, item by item.
		{"one configuration", []string{"-offline", "-a", before, "-requests", corpus}, 0,
			[]string{"switched off: cluster", "DECISION", "allowed", "the injection"}},
		// Two: the short list of what moved, and a non-zero exit.
		{"two configurations", []string{"-offline", "-a", before, "-b", after, "-requests", corpus}, 1,
			[]string{"2 inputs, 1 the same, 1 changed", "1 newly refused",
				"CHANGE", "newly refused", "the injection", "waf"}},
		// The same configuration twice decides the same thing, and exits 0.
		{"no change", []string{"-offline", "-a", before, "-b", before, "-requests", corpus}, 0,
			[]string{"every decision the same"}},
		{"json", []string{"-json", "-offline", "-a", before, "-b", after, "-requests", corpus}, 1,
			[]string{`"how": "newly refused"`, `"switched_off"`}},
		// The mistakes worth a clear answer.
		{"no traffic named", []string{"-offline", "-a", before}, 2,
			[]string{"name the traffic"}},
		{"two kinds of traffic", []string{"-offline", "-a", before,
			"-requests", corpus, "-frames", corpus}, 2, []string{"name one of"}},
		{"a pcap with no listener", []string{"-offline", "-a", before, "-pcap", corpus}, 2,
			[]string{"-pcap needs -listener"}},
		{"a corpus that is not there", []string{"-offline", "-a", before,
			"-requests", filepath.Join(t.TempDir(), "nothing")}, 2, []string{"no such file"}},
		{"a configuration that is not there", []string{"-offline",
			"-a", filepath.Join(t.TempDir(), "nothing.yaml"), "-requests", corpus}, 1,
			[]string{"nothing.yaml"}},
		{"an extra argument", []string{"-offline", "extra"}, 2,
			[]string{"usage: xproxy-simulate"}},
	} {
		var out, errOut bytes.Buffer
		code := run(tc.args, &out, &errOut)
		if code != tc.code {
			t.Errorf("%s: code %d want %d\n%s%s", tc.name, code, tc.code, out.String(), errOut.String())
			continue
		}
		text := out.String() + errOut.String()
		for _, want := range tc.want {
			if !strings.Contains(text, want) {
				t.Errorf("%s: %q not in\n%s", tc.name, want, text)
			}
		}
	}
}

// Every kind the project has must be linked into this binary. Without it the
// program refuses a configuration it should be able to answer about -- "kind
// http is served by xproxy, not by this daemon" -- which is the right answer
// inside a daemon and the wrong one here, where the whole point is that the
// file may name any role's listeners. The daemons each link their own share
// deliberately; this one links the lot, and this test is what keeps a kind
// added later from being left out of it.
func TestEveryKindIsLinkedIn(t *testing.T) {
	linked := make(map[string]bool, len(proxy.Registered()))
	for _, k := range proxy.Registered() {
		linked[k] = true
	}
	for _, k := range listener.Kinds() {
		if !linked[k] {
			t.Errorf("kind %q is not linked into xproxy-simulate: add its blank import", k)
		}
	}
}
