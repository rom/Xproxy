package config

import (
	"fmt"
	"reflect"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Change is one difference between two configurations.
type Change struct {
	Section string `json:"section"`
	Name    string `json:"name,omitempty"`
	Kind    string `json:"kind"` // added, removed or changed
}

// Changes is the result of comparing two configurations: a list of
// section level changes, a summary per section, the items that need a
// restart to take effect, and a unified text diff of the two documents.
type Changes struct {
	From          string   `json:"from"`
	To            string   `json:"to"`
	Same          bool     `json:"same"`
	Changes       []Change `json:"changes"`
	Summary       []string `json:"summary"`
	RestartNeeded []string `json:"restart_needed"`
	// Drains lists listeners a reload rebuilds or removes, whose open
	// connections are drained for shutdown_timeout.
	Drains    []string `json:"drains"`
	Text      string   `json:"text,omitempty"`
	Truncated bool     `json:"truncated,omitempty"`
}

// maxDiffCells bounds the line diff's work (lines of a times lines of b).
const maxDiffCells = 25_000_000

// Dump renders a configuration as one self-contained YAML document:
// included fragments are already expanded, so `includes` is cleared and
// the result loads as a main file.
func Dump(c *Config) ([]byte, error) {
	cp := *c
	cp.Includes = nil
	cp.IncludedFiles = nil
	return yaml.Marshal(&cp)
}

// Diff compares two configurations. Named lists (listeners, upstreams,
// routes, rate limits, filters) are compared item by item; every other
// section as a whole.
func Diff(from, to *Config, fromLabel, toLabel string) *Changes {
	ch := &Changes{From: fromLabel, To: toLabel, Changes: []Change{}, Summary: []string{}, RestartNeeded: []string{}, Drains: []string{}}
	counts := map[string]map[string]int{}
	add := func(section, name, kind string) {
		ch.Changes = append(ch.Changes, Change{Section: section, Name: name, Kind: kind})
		if counts[section] == nil {
			counts[section] = map[string]int{}
		}
		counts[section][kind]++
	}
	named := func(section string, a, b map[string]string) {
		for name, av := range a {
			bv, ok := b[name]
			switch {
			case !ok:
				add(section, name, "removed")
			case av != bv:
				add(section, name, "changed")
			}
		}
		for name := range b {
			if _, ok := a[name]; !ok {
				add(section, name, "added")
			}
		}
	}
	named("server.listeners", listenerMap(from), listenerMap(to))
	named("upstreams", upstreamMap(from), upstreamMap(to))
	named("routes", routeMap(from), routeMap(to))
	named("rate_limits", rateLimitMap(from), rateLimitMap(to))
	named("filters", filterMap(from), filterMap(to))
	for _, sec := range wholeSections(from, to) {
		if sec.a != sec.b {
			kind := "changed"
			switch {
			case sec.a == "" || sec.a == "null\n":
				kind = "added"
			case sec.b == "" || sec.b == "null\n":
				kind = "removed"
			}
			add(sec.name, "", kind)
		}
	}
	sort.SliceStable(ch.Changes, func(i, j int) bool {
		if ch.Changes[i].Section != ch.Changes[j].Section {
			return ch.Changes[i].Section < ch.Changes[j].Section
		}
		return ch.Changes[i].Name < ch.Changes[j].Name
	})
	sections := make([]string, 0, len(counts))
	for s := range counts {
		sections = append(sections, s)
	}
	sort.Strings(sections)
	for _, s := range sections {
		var parts []string
		for _, kind := range []string{"added", "removed", "changed"} {
			if n := counts[s][kind]; n > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", n, kind))
			}
		}
		ch.Summary = append(ch.Summary, s+": "+strings.Join(parts, ", "))
	}
	for _, c := range ch.Changes {
		switch {
		case c.Section == "server.listeners" && c.Kind == "changed":
			switch listenerChange(from, to, c.Name) {
			case listenerRestart:
				ch.RestartNeeded = append(ch.RestartNeeded, "listener "+c.Name+" changed on the same address with a UDP socket (h3, quic or dns)")
			case listenerRebuild:
				ch.Drains = append(ch.Drains, "listener "+c.Name+" rebuilt (connections drained)")
			}
		case c.Section == "server.listeners" && c.Kind == "removed":
			ch.Drains = append(ch.Drains, "listener "+c.Name+" removed (connections drained)")
		case c.Section == "management" && from.Management.Socket != to.Management.Socket:
			ch.RestartNeeded = append(ch.RestartNeeded, "management.socket")
		case c.Section == "cluster" && clusterNeedsRestart(from, to):
			ch.RestartNeeded = append(ch.RestartNeeded, "cluster listen, node_id or tls")
		case c.Section == "acme":
			ch.RestartNeeded = append(ch.RestartNeeded, "acme")
		}
	}
	ch.Same = len(ch.Changes) == 0
	if !ch.Same {
		a, _ := Dump(from)
		b, _ := Dump(to)
		ch.Text, ch.Truncated = unifiedDiff(string(a), string(b), fromLabel, toLabel)
	}
	if !reflect.DeepEqual(from.Server.SessionTickets, to.Server.SessionTickets) {
		ch.RestartNeeded = append(ch.RestartNeeded, "server.session_tickets")
	}
	return ch
}

func marshal(v any) string {
	b, err := yaml.Marshal(v)
	if err != nil {
		return "!" + err.Error()
	}
	return string(b)
}

func listenerMap(c *Config) map[string]string {
	m := map[string]string{}
	for i := range c.Server.Listeners {
		m[c.Server.Listeners[i].Name] = marshal(&c.Server.Listeners[i])
	}
	return m
}

func upstreamMap(c *Config) map[string]string {
	m := map[string]string{}
	for i := range c.Upstreams {
		m[c.Upstreams[i].Name] = marshal(&c.Upstreams[i])
	}
	return m
}

func routeMap(c *Config) map[string]string {
	m := map[string]string{}
	for i := range c.Routes {
		m[c.Routes[i].Name] = marshal(&c.Routes[i])
	}
	return m
}

func rateLimitMap(c *Config) map[string]string {
	m := map[string]string{}
	for i := range c.RateLimits {
		m[c.RateLimits[i].Name] = marshal(&c.RateLimits[i])
	}
	return m
}

func filterMap(c *Config) map[string]string {
	m := map[string]string{}
	for i := range c.Filters {
		m[c.Filters[i].Name] = marshal(&c.Filters[i])
	}
	return m
}

type wholeSection struct{ name, a, b string }

// wholeSections renders the sections compared as units.
func wholeSections(from, to *Config) []wholeSection {
	one := func(c *Config) map[string]string {
		srv := c.Server
		srv.Listeners = nil
		return map[string]string{
			"version":         marshal(c.Version),
			"trusted_proxies": marshal(c.TrustedProxies),
			"server":          marshal(&srv),
			"management":      marshal(&c.Management),
			"logging":         marshal(&c.Logging),
			"compression":     marshal(c.Compression),
			"cache":           marshal(c.Cache),
			"geoip":           marshal(c.GeoIP),
			"waf":             marshal(c.WAF),
			"bans":            marshal(c.Bans),
			"cluster":         marshal(c.Cluster),
			"jwt":             marshal(c.JWT),
			"icap":            marshal(c.ICAP),
			"acme":            marshal(c.ACME),
			"shedding":        marshal(c.Shedding),
			"challenge":       marshal(c.Challenge),
			"metrics":         marshal(&c.Metrics),
			"ingress":         marshal(c.Ingress),
		}
	}
	a, b := one(from), one(to)
	names := make([]string, 0, len(a))
	for n := range a {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]wholeSection, 0, len(names))
	for _, n := range names {
		out = append(out, wholeSection{n, a[n], b[n]})
	}
	return out
}

// listenerNeedsRestart reports whether a listener changed in anything
// but the certificate file contents (which reload-certs handles).
type listenerChangeKind int

const (
	listenerInPlace listenerChangeKind = iota // certificate files, forward or dns policy
	listenerRebuild                           // rebuilt by the reload, connections drained
	listenerRestart                           // needs a restart
)

// listenerChange classifies a change of the named listener the way
// Server.Reload treats it.
func listenerChange(from, to *Config, name string) listenerChangeKind {
	var a, b *Listener
	for i := range from.Server.Listeners {
		if from.Server.Listeners[i].Name == name {
			a = &from.Server.Listeners[i]
		}
	}
	for i := range to.Server.Listeners {
		if to.Server.Listeners[i].Name == name {
			b = &to.Server.Listeners[i]
		}
	}
	if a == nil || b == nil {
		return listenerInPlace
	}
	norm := func(l Listener) Listener {
		l.Forward = nil
		if l.DNS != nil {
			l.DNS = &DNSListener{DoHPath: l.DNS.DoHPath}
		}
		if l.TLS != nil {
			t := *l.TLS
			t.Certificates = nil
			l.TLS = &t
		}
		return l
	}
	na, nb := norm(*a), norm(*b)
	if marshal(&na) == marshal(&nb) {
		return listenerInPlace
	}
	if a.Address == b.Address && ListenerHasUDP(*a) {
		return listenerRestart
	}
	return listenerRebuild
}

// ListenerHasUDP reports whether the listener binds a UDP socket besides
// its TCP one: HTTP/3, the QUIC relay of a tcp listener or plain dns.
func ListenerHasUDP(lc Listener) bool {
	switch lc.Kind {
	case "tcp":
		return lc.TCP != nil && lc.TCP.QUIC
	case "dns":
		return lc.TLS == nil
	}
	for _, p := range lc.Protocols {
		if p == ProtocolH3 {
			return true
		}
	}
	return false
}

func clusterNeedsRestart(from, to *Config) bool {
	if from.Cluster == nil || to.Cluster == nil {
		return true
	}
	return from.Cluster.Listen != to.Cluster.Listen || from.Cluster.NodeID != to.Cluster.NodeID || marshal(&from.Cluster.TLS) != marshal(&to.Cluster.TLS)
}

// unifiedDiff renders a unified diff of two texts with three lines of
// context. It reports truncation when the inputs are too large to
// compare line by line.
func unifiedDiff(a, b, fromLabel, toLabel string) (string, bool) {
	al := strings.Split(strings.TrimSuffix(a, "\n"), "\n")
	bl := strings.Split(strings.TrimSuffix(b, "\n"), "\n")
	if len(al)*len(bl) > maxDiffCells {
		return "", true
	}
	// LCS table.
	n, m := len(al), len(bl)
	dp := make([][]int32, n+1)
	for i := range dp {
		dp[i] = make([]int32, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if al[i] == bl[j] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else {
				dp[i][j] = max(dp[i+1][j], dp[i][j+1])
			}
		}
	}
	type op struct {
		kind byte // ' ', '-', '+'
		text string
		ai   int // position in a (for hunk headers)
		bi   int
	}
	var ops []op
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case al[i] == bl[j]:
			ops = append(ops, op{' ', al[i], i, j})
			i++
			j++
		case dp[i+1][j] >= dp[i][j+1]:
			ops = append(ops, op{'-', al[i], i, j})
			i++
		default:
			ops = append(ops, op{'+', bl[j], i, j})
			j++
		}
	}
	for ; i < n; i++ {
		ops = append(ops, op{'-', al[i], i, j})
	}
	for ; j < m; j++ {
		ops = append(ops, op{'+', bl[j], i, j})
	}
	const ctx = 3
	var sb strings.Builder
	fmt.Fprintf(&sb, "--- %s\n+++ %s\n", fromLabel, toLabel)
	k := 0
	for k < len(ops) {
		// Find the next change.
		for k < len(ops) && ops[k].kind == ' ' {
			k++
		}
		if k >= len(ops) {
			break
		}
		start := max(k-ctx, 0)
		end := k
		// Extend the hunk while changes are within 2*ctx of each other.
		for end < len(ops) {
			next := end
			for next < len(ops) && ops[next].kind != ' ' {
				next++
			}
			gap := next
			for gap < len(ops) && ops[gap].kind == ' ' && gap-next < 2*ctx {
				gap++
			}
			if gap < len(ops) && ops[gap].kind != ' ' {
				end = gap
				continue
			}
			end = min(next+ctx, len(ops))
			break
		}
		aStart, bStart := ops[start].ai+1, ops[start].bi+1
		aCount, bCount := 0, 0
		for _, o := range ops[start:end] {
			if o.kind != '+' {
				aCount++
			}
			if o.kind != '-' {
				bCount++
			}
		}
		fmt.Fprintf(&sb, "@@ -%d,%d +%d,%d @@\n", aStart, aCount, bStart, bCount)
		for _, o := range ops[start:end] {
			sb.WriteByte(o.kind)
			sb.WriteString(o.text)
			sb.WriteByte('\n')
		}
		k = end
	}
	return sb.String(), false
}
