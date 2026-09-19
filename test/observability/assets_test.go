// Package observability checks the Grafana dashboards and Prometheus
// alert rules shipped under deploy/ against the metrics the proxy
// exports, so the assets cannot name a family the binary does not have.
package observability

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var metricRE = regexp.MustCompile(`\bxproxy_[a-z0-9_]+`)

// exported collects the metric families named in the exporter source.
func exported(t *testing.T) map[string]bool {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("..", "..", "internal", "proxy", "metrics.go"))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, m := range regexp.MustCompile(`e\.(?:Counter|Gauge|Histogram)\("(xproxy_[a-z0-9_]+)"`).FindAllSubmatch(src, -1) {
		out[string(m[1])] = true
	}
	if len(out) < 50 {
		t.Fatalf("only %d families found in metrics.go", len(out))
	}
	return out
}

func family(name string) string {
	for _, suf := range []string{"_bucket", "_sum", "_count"} {
		if strings.HasSuffix(name, suf) {
			return strings.TrimSuffix(name, suf)
		}
	}
	return name
}

func checkNames(t *testing.T, where string, text string, known map[string]bool) {
	t.Helper()
	seen := map[string]bool{}
	for _, m := range metricRE.FindAllString(text, -1) {
		f := family(m)
		if seen[f] {
			continue
		}
		seen[f] = true
		if !known[f] {
			t.Errorf("%s: metric %s is not exported by the proxy", where, m)
		}
	}
	if len(seen) == 0 && !strings.Contains(text, "go_") && !strings.Contains(text, "process_") {
		t.Errorf("%s: no xproxy metrics referenced", where)
	}
}

func TestDashboards(t *testing.T) {
	known := exported(t)
	files, _ := filepath.Glob(filepath.Join("..", "..", "deploy", "grafana", "*.json"))
	if len(files) != 2 {
		t.Fatalf("dashboards: %v", files)
	}
	uids := map[string]bool{}
	for _, f := range files {
		data, err := os.ReadFile(f) //nolint:gosec // test input
		if err != nil {
			t.Fatal(err)
		}
		var d struct {
			UID    string `json:"uid"`
			Title  string `json:"title"`
			Inputs []struct {
				Name     string `json:"name"`
				PluginID string `json:"pluginId"`
			} `json:"__inputs"`
			SchemaVersion int `json:"schemaVersion"`
			Templating    struct {
				List []struct {
					Name string `json:"name"`
				} `json:"list"`
			} `json:"templating"`
			Panels []struct {
				ID      int    `json:"id"`
				Type    string `json:"type"`
				Title   string `json:"title"`
				GridPos struct {
					X, Y, W, H int
				} `json:"gridPos"`
				Targets []struct {
					Expr  string `json:"expr"`
					RefID string `json:"refId"`
				} `json:"targets"`
			} `json:"panels"`
		}
		if err := json.Unmarshal(data, &d); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		name := filepath.Base(f)
		if d.UID == "" || d.Title == "" || d.SchemaVersion < 36 || uids[d.UID] {
			t.Errorf("%s: uid %q title %q schema %d", name, d.UID, d.Title, d.SchemaVersion)
		}
		uids[d.UID] = true
		if len(d.Inputs) != 1 || d.Inputs[0].Name != "DS_PROMETHEUS" || d.Inputs[0].PluginID != "prometheus" {
			t.Errorf("%s: data source input %+v", name, d.Inputs)
		}
		if len(d.Templating.List) == 0 || d.Templating.List[0].Name != "instance" {
			t.Errorf("%s: instance variable missing", name)
		}
		if len(d.Panels) < 10 {
			t.Errorf("%s: only %d panels", name, len(d.Panels))
		}
		ids := map[int]bool{}
		for _, p := range d.Panels {
			if p.Title == "" || ids[p.ID] || p.GridPos.W <= 0 || p.GridPos.H <= 0 || p.GridPos.X+p.GridPos.W > 24 {
				t.Errorf("%s: panel %q id %d grid %+v", name, p.Title, p.ID, p.GridPos)
			}
			ids[p.ID] = true
			if len(p.Targets) == 0 {
				t.Errorf("%s: panel %q has no query", name, p.Title)
			}
			for _, tg := range p.Targets {
				if tg.Expr == "" || tg.RefID == "" {
					t.Errorf("%s: panel %q target %+v", name, p.Title, tg)
				}
				if !strings.Contains(tg.Expr, `instance=~"$instance"`) {
					t.Errorf("%s: panel %q query ignores the instance variable: %s", name, p.Title, tg.Expr)
				}
				checkNames(t, name+" panel "+p.Title, tg.Expr, known)
			}
		}
	}
}

func TestAlertRules(t *testing.T) {
	known := exported(t)
	data, err := os.ReadFile(filepath.Join("..", "..", "deploy", "prometheus", "xproxy-alerts.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Groups []struct {
			Name  string `yaml:"name"`
			Rules []struct {
				Alert       string            `yaml:"alert"`
				Expr        string            `yaml:"expr"`
				For         string            `yaml:"for"`
				Labels      map[string]string `yaml:"labels"`
				Annotations map[string]string `yaml:"annotations"`
			} `yaml:"rules"`
		} `yaml:"groups"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Groups) != 3 {
		t.Fatalf("groups: %d", len(doc.Groups))
	}
	names := map[string]bool{}
	var all []string
	for _, g := range doc.Groups {
		if !strings.HasPrefix(g.Name, "xproxy.") {
			t.Errorf("group %q", g.Name)
		}
		for _, r := range g.Rules {
			if r.Alert == "" || !strings.HasPrefix(r.Alert, "Xproxy") || names[r.Alert] {
				t.Errorf("rule name %q", r.Alert)
			}
			names[r.Alert] = true
			all = append(all, r.Alert)
			if sev := r.Labels["severity"]; sev != "page" && sev != "warn" {
				t.Errorf("%s: severity %q", r.Alert, sev)
			}
			if r.Annotations["summary"] == "" || r.Annotations["description"] == "" {
				t.Errorf("%s: summary and description are required", r.Alert)
			}
			if strings.Count(r.Expr, "(") != strings.Count(r.Expr, ")") {
				t.Errorf("%s: unbalanced parentheses in %q", r.Alert, r.Expr)
			}
			if r.Alert != "XproxyDown" {
				checkNames(t, r.Alert, r.Expr, known)
			}
		}
	}
	sort.Strings(all)
	for _, want := range []string{"XproxyDown", "XproxyNoHealthyEndpoint", "XproxyHigh5xxRatio", "XproxyCertificateExpiring", "XproxyReloadFailed", "XproxyLogDrops", "XproxyAttackSurge"} {
		if !names[want] {
			t.Errorf("rule %s missing from %v", want, all)
		}
	}
}
