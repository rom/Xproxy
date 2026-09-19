package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/sandbox"
)

// View identifies a screen.
type View int

// Screens in tab order.
const (
	ViewOverview View = iota
	ViewUpstreams
	ViewBans
	ViewCluster
	ViewGraphs
	ViewLog
	ViewRoutes
	ViewWAF
	ViewTLS
	viewCount
)

var viewNames = [...]string{"Overview", "Upstreams", "Bans", "Cluster", "Graphs", "Log", "Routes", "WAF", "TLS"}

// Style holds ANSI sequences; Plain has none (NO_COLOR, tests).
type Style struct {
	Reset, Bold, Dim, Red, Green, Yellow, Cyan, Inverse string
}

// Plain renders without escapes.
var Plain = Style{}

// ANSI renders with colours.
var ANSI = Style{Reset: "\x1b[0m", Bold: "\x1b[1m", Dim: "\x1b[2m", Red: "\x1b[31m", Green: "\x1b[32m", Yellow: "\x1b[33m", Cyan: "\x1b[36m", Inverse: "\x1b[7m"}

// State is what the renderer needs besides Data.
type State struct {
	View     View
	Width    int
	Height   int
	Refresh  time.Duration
	Selected int    // selected row in list views
	Prompt   string // active prompt text, "" when none
	Input    string // prompt input
	Message  string // transient status line
	Paused   bool
}

// Render draws a full frame as lines, exactly Height long and each at
// most Width cells wide.
func Render(d Data, st State, sty Style) []string {
	w, h := st.Width, st.Height
	if w < 40 {
		w = 40
	}
	if h < 8 {
		h = 8
	}
	lines := []string{header(d, st, sty, w)}
	body := h - 3
	var content []string
	switch st.View {
	case ViewUpstreams:
		content = renderUpstreams(d, sty)
	case ViewBans:
		content = renderBans(d, st, sty)
	case ViewCluster:
		content = renderCluster(d, sty)
	case ViewGraphs:
		content = renderGraphs(d, sty, w, body)
	case ViewLog:
		content = renderLog(d, body)
	case ViewRoutes:
		content = renderRoutes(d, sty)
	case ViewWAF:
		content = renderWAF(d, sty)
	case ViewTLS:
		content = renderTLS(d, sty)
	default:
		content = renderOverview(d, sty, w)
	}
	if len(d.Errors) > 0 && st.View != ViewLog {
		keys := make([]string, 0, len(d.Errors))
		for k := range d.Errors {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			content = append(content, sty.Red+"! "+k+": "+d.Errors[k]+sty.Reset)
		}
	}
	// Scroll long list views so the selection stays visible.
	if len(content) > body {
		off := 0
		if st.View == ViewBans && st.Selected+2 >= body {
			off = st.Selected + 3 - body
		}
		if off > len(content)-body {
			off = len(content) - body
		}
		content = content[off : off+body]
	}
	for len(content) < body {
		content = append(content, "")
	}
	for _, c := range content {
		lines = append(lines, clip(c, w))
	}
	lines = append(lines, footer(st, sty, w), promptLine(st, sty, w))
	return lines
}

func header(d Data, st State, sty Style, w int) string {
	var tabs []string
	for i := View(0); i < viewCount; i++ {
		name := fmt.Sprintf("%d %s", i+1, viewNames[i])
		if i == st.View {
			name = sty.Inverse + " " + name + " " + sty.Reset
		} else {
			name = " " + name + " "
		}
		tabs = append(tabs, name)
	}
	left := strings.Join(tabs, "")
	right := ""
	if d.Status != nil {
		right = fmt.Sprintf("gen %d  up %s  ", d.Status.Generation, (time.Duration(d.Status.Stats.UptimeSeconds) * time.Second).Round(time.Second))
	}
	if st.Paused {
		right += sty.Yellow + "PAUSED " + sty.Reset
	}
	right += d.At.Format("15:04:05")
	return pad(left, right, w)
}

func footer(st State, sty Style, w int) string {
	keys := "1-9/tab views  r refresh  p pause  +/- interval  q quit"
	if st.View == ViewBans {
		keys = "j/k select  u unban  b ban  " + keys
	}
	return sty.Dim + clip(keys, w) + sty.Reset
}

func promptLine(st State, sty Style, w int) string {
	if st.Prompt != "" {
		return clip(sty.Bold+st.Prompt+sty.Reset+" "+st.Input+"_", w)
	}
	if st.Message != "" {
		return clip(sty.Cyan+st.Message+sty.Reset, w)
	}
	return clip(fmt.Sprintf("refresh every %s", st.Refresh), w)
}

func renderOverview(d Data, sty Style, w int) []string {
	if d.Status == nil {
		return []string{sty.Red + "management API unavailable" + sty.Reset}
	}
	s := d.Status.Stats
	out := make([]string, 0, 32)
	out = append(out, sty.Bold+"xproxy "+d.Status.Version+sty.Reset+fmt.Sprintf("  pid %d  routes %d  upstreams %d", d.Status.PID, d.Status.Routes, d.Status.Upstreams))
	names := make([]string, 0, len(d.Status.Listeners))
	for n := range d.Status.Listeners {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		out = append(out, fmt.Sprintf("  listener %-14s %s", n, d.Status.Listeners[n]))
	}
	out = append(out, "")
	col := func(k string, v any) string { return fmt.Sprintf("%-22s %12v", k, v) }
	rows := [][2]string{
		{col("requests", s.Requests), col("open connections", s.OpenConnections)},
		{col("2xx", s.Responses2xx), col("in flight", s.InFlight)},
		{col("3xx", s.Responses3xx), col("rejected conns", s.RejectedConns)},
		{col("4xx", s.Responses4xx), col("bans active", s.BansActive)},
		{col("5xx", s.Responses5xx), col("cluster connected", fmt.Sprintf("%d/%d", s.ClusterConnected, s.ClusterPeers))},
		{col("bytes out", humanBytes(s.BytesOut)), col("load level", fmt.Sprintf("%.2f", s.LoadLevel))},
		{col("denied rate limit", s.DeniedRateLimit), col("upstream latency", fmt.Sprintf("%.1f ms", s.UpstreamLatencyMS))},
		{col("denied waf", s.DeniedWAF), col("shed", s.Shed)},
		{col("denied ban", s.DeniedBan), col("challenges passed", s.ChallengesPassed)},
		{col("denied jwt", s.DeniedJWT), col("upstream errors", s.UpstreamErrors)},
		{col("denied acl", s.DeniedACL), col("upstream timeouts", s.UpstreamTimeouts)},
		{col("waf detected", s.WAFDetected), col("log drops", s.LogSyslogDropped+s.LogJournalDropped)},
	}
	for _, r := range rows {
		out = append(out, "  "+r[0]+"    "+r[1])
	}
	if len(s.SheddingClasses) > 0 {
		out = append(out, "", sty.Yellow+"  shedding: "+strings.Join(s.SheddingClasses, ", ")+sty.Reset)
	}
	out = append(out, "", "  sandbox    "+sandboxLine(d.Status.Sandbox, sty))
	if t := d.Telemetry; t != nil && (t.Metrics != nil || t.Traces != nil || t.Logs != nil || t.SIEM != nil) {
		var parts []string
		if t.Metrics != nil {
			parts = append(parts, fmt.Sprintf("metrics sent %d failed %d", t.Metrics.Sent, t.Metrics.Failed))
		}
		if t.Traces != nil {
			parts = append(parts, fmt.Sprintf("traces sampled %d sent %d failed %d", t.Traces.Sampled, t.Traces.Sent, t.Traces.Failed))
		}
		if t.Logs != nil {
			parts = append(parts, fmt.Sprintf("logs sent %d dropped %d", t.Logs.Sent, t.Logs.Dropped))
		}
		if t.SIEM != nil {
			parts = append(parts, fmt.Sprintf("siem %s sent %d dropped %d", t.SIEM.Format, t.SIEM.Sent, t.SIEM.Dropped))
		}
		out = append(out, "  telemetry  "+strings.Join(parts, "  "))
	}
	for _, l := range d.DNS {
		out = append(out, fmt.Sprintf("  dns %-8s queries %d (udp %d tcp %d dot %d doh %d) hits %d blocked %d servfail %d", l.Listener, l.Queries, l.QueriesUDP, l.QueriesTCP, l.QueriesDoT, l.QueriesDoH, l.CacheHits, l.Blocked, l.ServFail))
		if l.DNSSEC != nil {
			out = append(out, fmt.Sprintf("  %-12s dnssec secure %d insecure %d bogus %d indeterminate %d", "", l.DNSSEC.Secure, l.DNSSEC.Insecure, l.DNSSEC.Bogus, l.DNSSEC.Indeterminate))
		}
	}
	if d.Series != nil && len(d.Series.Points) > 1 {
		out = append(out, "", "  "+sparkRow("req/s", seriesValues(d.Series, "requests"), w-12, sty))
		out = append(out, "  "+sparkRow("denied", seriesValues(d.Series, "denied"), w-12, sty))
	}
	return out
}

func renderUpstreams(d Data, sty Style) []string {
	if d.Upstreams == nil {
		return []string{"no upstream data"}
	}
	names := make([]string, 0, len(d.Upstreams))
	for n := range d.Upstreams {
		names = append(names, n)
	}
	sort.Strings(names)
	out := []string{sty.Bold + fmt.Sprintf("  %-16s %-28s %6s %8s %8s %6s %10s %8s", "UPSTREAM", "ENDPOINT", "WEIGHT", "HEALTHY", "EJECTED", "ACTIVE", "REQUESTS", "ERRORS") + sty.Reset}
	for _, n := range names {
		for _, e := range d.Upstreams[n] {
			health := sty.Green + "yes    " + sty.Reset
			if !e.Healthy {
				health = sty.Red + "NO     " + sty.Reset
			}
			ej := "no     "
			if e.Ejected {
				ej = sty.Yellow + "YES    " + sty.Reset
			}
			out = append(out, fmt.Sprintf("  %-16s %-28s %6d %s %s %6d %10d %8d", n, e.Address, e.Weight, health, ej, e.Active, e.Requests, e.Errors))
		}
		if p, ok := d.Pools[n]; ok && (p.Circuit != nil || p.Queue != nil || p.Canary != nil || p.Discovery != nil || p.SlowStart != "") {
			var parts []string
			if c := p.Circuit; c != nil {
				col := sty.Green
				if c.State != "closed" {
					col = sty.Yellow
				}
				parts = append(parts, fmt.Sprintf("circuit %s%s%s failures %d opens %d rejected %d", col, c.State, sty.Reset, c.Failures, c.Opens, c.Rejected))
			}
			if q := p.Queue; q != nil {
				parts = append(parts, fmt.Sprintf("in flight %d/%d queued %d/%d timeouts %d full %d", q.InFlight, q.MaxConcurrent, q.Waiting, q.QueueSize, q.Timeouts, q.Full))
			}
			if c := p.Canary; c != nil {
				parts = append(parts, fmt.Sprintf("canary %.0f%% requests %d fallbacks %d", c.Percent, c.Requests, c.Fallbacks))
			}
			if dsc := p.Discovery; dsc != nil {
				line := fmt.Sprintf("discovery %s %s: %d endpoints, %d resolutions, %d changes, %d errors", dsc.Type, dsc.Name, dsc.Endpoints, dsc.Resolutions, dsc.Changes, dsc.Errors)
				if dsc.LastError != "" {
					line += "  " + sty.Red + dsc.LastError + sty.Reset
				}
				parts = append(parts, line)
			}
			if p.SlowStart != "" {
				parts = append(parts, "slow start "+p.SlowStart)
			}
			for _, part := range parts {
				out = append(out, sty.Dim+"  "+strings.Repeat(" ", 16)+" "+part+sty.Reset)
			}
		}
	}
	return out
}

// sandboxLine summarises the hardening status for the overview.
func sandboxLine(sb *sandbox.Status, sty Style) string {
	if sb == nil {
		return sty.Dim + "not reported" + sty.Reset
	}
	if !sb.Enabled {
		return sty.Yellow + "disabled" + sty.Reset
	}
	var applied, other []string
	for _, m := range sb.Mechanism {
		if m.State == sandbox.StateApplied {
			applied = append(applied, m.Name)
		} else {
			other = append(other, m.Name+"="+m.State)
		}
	}
	line := sty.Green + strings.Join(applied, ",") + sty.Reset
	if len(other) > 0 {
		line += "  " + sty.Yellow + strings.Join(other, " ") + sty.Reset
	}
	return line
}

func renderRoutes(d Data, sty Style) []string {
	q := d.Quotas
	if q == nil {
		return []string{"no usage data"}
	}
	out := []string{sty.Bold + fmt.Sprintf("  %-20s %-10s %-14s %9s %8s %8s %8s %8s %8s %10s", "ROUTE", "TENANT", "UPSTREAM", "REQUESTS", "2XX", "4XX", "5XX", "DENIED", "RATE-LIM", "BYTES-OUT") + sty.Reset}
	for _, r := range q.Routes {
		out = append(out, fmt.Sprintf("  %-20s %-10s %-14s %9d %8d %8d %8d %8d %8d %10s", clip(r.Route, 20), clip(orDash(r.Tenant), 10), clip(orDash(r.Upstream), 14), r.Requests, r.Status2xx, r.Status4xx, r.Status5xx, r.Denied, r.RateLimited, humanBytes(r.BytesOut)))
	}
	if len(q.Tenants) > 0 {
		out = append(out, "", sty.Bold+fmt.Sprintf("  %-20s %6s %9s %8s %8s %10s %10s", "TENANT", "ROUTES", "REQUESTS", "DENIED", "RATE-LIM", "BYTES-IN", "BYTES-OUT")+sty.Reset)
		for _, t := range q.Tenants {
			out = append(out, fmt.Sprintf("  %-20s %6d %9d %8d %8d %10s %10s", clip(t.Tenant, 20), t.Routes, t.Requests, t.Denied, t.RateLimited, humanBytes(t.BytesIn), humanBytes(t.BytesOut)))
		}
	}
	if len(q.RateLimits) > 0 {
		out = append(out, "", sty.Bold+fmt.Sprintf("  %-16s %-14s %7s %6s %6s %9s %8s  %s", "POLICY", "KEY", "RATE", "BURST", "KEYS", "ALLOWED", "DENIED", "TOP")+sty.Reset)
		for _, p := range q.RateLimits {
			tops := make([]string, 0, len(p.Top))
			for _, u := range p.Top {
				tops = append(tops, fmt.Sprintf("%s=%.0f", u.Key, u.Total))
			}
			out = append(out, fmt.Sprintf("  %-16s %-14s %7.1f %6d %6d %9d %8d  %s", clip(p.Policy, 16), clip(p.Key, 14), p.Rate, p.Burst, p.Keys, p.Allowed, p.Denied, strings.Join(tops, " ")))
		}
	}
	return out
}

func renderWAF(d Data, sty Style) []string {
	w := d.WAF
	if w == nil {
		return []string{"no WAF data"}
	}
	if !w.Enabled && w.Requests == 0 {
		return []string{"WAF not configured"}
	}
	out := []string{fmt.Sprintf("  requests %d  blocked %s%d%s  detected %s%d%s  rules seen %d", w.Requests, sty.Red, w.Blocked, sty.Reset, sty.Yellow, w.Detected, sty.Reset, w.TotalRules)}
	if l := w.Learning; l != nil {
		state := "off"
		if l.Enabled {
			state = "on"
		}
		out = append(out, fmt.Sprintf("  learning %s  min hits %d  entries %d/%d  dropped %d  proposals %d", state, l.MinHits, l.Entries, l.MaxEntries, l.Dropped, len(l.Proposals)))
	}
	if len(w.Profiles) > 0 {
		out = append(out, "", sty.Bold+fmt.Sprintf("  %-16s %-14s %-24s %-8s %s", "PROFILE", "MODES", "RULE SET", "VERSION", "FILES")+sty.Reset)
		for _, p := range w.Profiles {
			out = append(out, fmt.Sprintf("  %-16s %-14s %-24s %-8s %d", clip(p.Name, 16), strings.Join(p.Modes, ","), clip(orDash(p.CRS), 24), orDash(p.Version), p.RuleFiles))
		}
	}
	if len(w.Routes) > 0 {
		var rs []string
		for _, r := range w.Routes {
			rs = append(rs, r.Route+"="+r.Profile+"/"+r.Mode)
		}
		out = append(out, "", "  routes: "+strings.Join(rs, "  "))
	}
	out = append(out, "", sty.Bold+fmt.Sprintf("  %-8s %8s %7s %8s %-9s %s", "RULE", "MATCHES", "BLOCKS", "DETECTS", "SEVERITY", "MESSAGE")+sty.Reset)
	if len(w.Rules) == 0 {
		out = append(out, "  no rule matches recorded")
	}
	for _, r := range w.Rules {
		out = append(out, fmt.Sprintf("  %-8d %8d %7d %8d %-9s %s", r.ID, r.Matches, r.Blocks, r.Detects, clip(orDash(r.Severity), 9), r.Message))
	}
	if l := w.Learning; l != nil && len(l.Proposals) > 0 {
		out = append(out, "", sty.Bold+fmt.Sprintf("  %-8s %-28s %-16s %6s %7s  %s", "RULE", "TARGET", "ROUTE", "HITS", "CLIENTS", "MESSAGE")+sty.Reset)
		for _, p := range l.Proposals {
			out = append(out, fmt.Sprintf("  %-8d %-28s %-16s %6d %7d  %s", p.Rule, clip(p.Target, 28), clip(orDash(p.Route), 16), p.Hits, p.Clients, p.Message))
		}
		out = append(out, sty.Dim+"  xproxyctl waf exclusions prints the directives"+sty.Reset)
	}
	return out
}

func renderTLS(d Data, sty Style) []string {
	if d.TLS == nil {
		return []string{"no certificate data"}
	}
	names := make([]string, 0, len(d.TLS))
	for n := range d.TLS {
		names = append(names, n)
	}
	sort.Strings(names)
	out := []string{sty.Bold + fmt.Sprintf("  %-12s %-30s %-20s %-12s %-6s %-10s %s", "LISTENER", "NAMES", "ISSUER", "EXPIRES", "SOURCE", "OCSP", "CT") + sty.Reset}
	if len(names) == 0 {
		out = append(out, "  no TLS listeners")
	}
	for _, n := range names {
		for _, c := range d.TLS[n] {
			left := time.Until(c.NotAfter).Round(24 * time.Hour)
			days := fmt.Sprintf("%dd", int(left.Hours()/24))
			col := sty.Green
			if left < 7*24*time.Hour {
				col = sty.Red
			} else if left < 30*24*time.Hour {
				col = sty.Yellow
			}
			src := "file"
			if c.Managed {
				src = "acme"
			}
			ocsp := c.OCSP.Status
			if ocsp == "" {
				ocsp = "-"
			}
			ct := "-"
			if c.CT.Required > 0 {
				ct = fmt.Sprintf("%d/%d", c.CT.Verified, c.CT.Required)
				if !c.CT.OK {
					ct = sty.Yellow + ct + " failed" + sty.Reset
				}
			} else if c.CT.Embedded > 0 {
				ct = fmt.Sprintf("%d scts", c.CT.Embedded)
			}
			out = append(out, fmt.Sprintf("  %-12s %-30s %-20s %s%-12s%s %-6s %-10s %s", clip(n, 12), clip(strings.Join(c.Names, ","), 30), clip(orDash(c.Issuer), 20), col, days, sty.Reset, src, clip(ocsp, 10), ct))
		}
	}
	return out
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func renderBans(d Data, st State, sty Style) []string {
	out := []string{sty.Bold + fmt.Sprintf("  %-40s %-12s %-18s %5s  %s", "TARGET", "EXPIRES", "SOURCE", "COUNT", "REASON") + sty.Reset}
	if len(d.Bans) == 0 {
		return append(out, "  no active bans")
	}
	for i, e := range d.Bans {
		mark := "  "
		if i == st.Selected {
			mark = sty.Inverse + "> "
		}
		line := fmt.Sprintf("%s%-40s %-12s %-18s %5d  %s", mark, e.Target, time.Until(e.Until).Round(time.Second), e.Source, e.Count, e.Reason)
		if i == st.Selected {
			line += sty.Reset
		}
		out = append(out, line)
	}
	return out
}

func renderCluster(d Data, sty Style) []string {
	if d.Cluster == nil {
		return []string{"cluster not configured"}
	}
	c := d.Cluster
	out := []string{
		fmt.Sprintf("  node %s  listen %s", sty.Bold+c.NodeID+sty.Reset, c.Listen),
		fmt.Sprintf("  rates sent %d received %d (keys %d)  bans sent %d received %d  rejected %d dropped %d", c.RatesSent, c.RatesReceived, c.KeysReceived, c.BansSent, c.BansReceived, c.Rejected, c.Dropped),
		"",
		sty.Bold + fmt.Sprintf("  %-28s %-10s %-10s %9s %10s  %s", "PEER", "CONNECTED", "SINCE", "MESSAGES", "RECONNECTS", "LAST ERROR") + sty.Reset,
	}
	for _, p := range c.Peers {
		conn := sty.Red + "no        " + sty.Reset
		since := ""
		if p.Connected {
			conn = sty.Green + "yes       " + sty.Reset
			since = time.Since(p.ConnectedAt).Round(time.Second).String()
		}
		out = append(out, fmt.Sprintf("  %-28s %s %-10s %9d %10d  %s", p.Address, conn, since, p.MessagesOut, p.Reconnects, p.LastError))
	}
	if len(c.Inbound) > 0 {
		out = append(out, "", sty.Bold+fmt.Sprintf("  %-28s %-12s %-12s %-10s %s", "INBOUND", "NODE", "CERT", "SEEN", "MESSAGES")+sty.Reset)
		for _, in := range c.Inbound {
			out = append(out, fmt.Sprintf("  %-28s %-12s %-12s %-10s %d", in.Remote, in.NodeID, in.CertName, time.Since(in.LastSeen).Round(time.Second).String()+" ago", in.MessagesIn))
		}
	}
	return out
}

func renderGraphs(d Data, sty Style, w, h int) []string {
	if d.Series == nil || len(d.Series.Points) < 2 {
		return []string{"no samples yet"}
	}
	out := make([]string, 0, 14)
	span := d.Series.Points[len(d.Series.Points)-1].Time.Sub(d.Series.Points[0].Time).Round(time.Second)
	out = append(out, fmt.Sprintf("  last %s, %d points every %.0fs", span, len(d.Series.Points), d.Series.IntervalSeconds))
	for _, name := range []string{"requests", "responses_4xx", "responses_5xx", "denied", "shed", "bytes_out", "open_connections", "in_flight", "load_level", "upstream_latency_ms", "bans_active", "upstream_errors"} {
		vals := seriesValues(d.Series, name)
		if vals == nil {
			continue
		}
		out = append(out, "  "+sparkRow(name, vals, w-32, sty))
		if len(out) >= h {
			break
		}
	}
	return out
}

func renderLog(d Data, h int) []string {
	if len(d.LogLines) == 0 {
		return []string{"  no security events (or the log file is not readable from here)"}
	}
	lines := d.LogLines
	if len(lines) > h {
		lines = lines[len(lines)-h:]
	}
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		out = append(out, "  "+compactLogLine(l))
	}
	return out
}

// compactLogLine turns a JSON security line into a short readable form
// without parsing dependencies: it keeps a few known fields in order.
func compactLogLine(l string) string {
	pick := func(key string) string {
		i := strings.Index(l, `"`+key+`":`)
		if i < 0 {
			return ""
		}
		rest := l[i+len(key)+3:]
		if strings.HasPrefix(rest, `"`) {
			rest = rest[1:]
			if j := strings.IndexByte(rest, '"'); j >= 0 {
				return rest[:j]
			}
			return rest
		}
		j := strings.IndexAny(rest, ",}")
		if j < 0 {
			return rest
		}
		return rest[:j]
	}
	ts := pick("time")
	if len(ts) >= 19 {
		ts = ts[11:19]
	}
	parts := []string{ts, pick("action"), pick("reason"), pick("client_ip"), pick("method"), pick("host"), pick("path")}
	if m := pick("msg"); m != "security" && m != "" && pick("action") == "" {
		parts = append(parts, m, pick("target"))
	}
	var b strings.Builder
	for _, p := range parts {
		if p == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(p)
	}
	return b.String()
}

// seriesValues returns the values of one named series.
func seriesValues(s *mgmtSeries, name string) []float64 {
	idx := -1
	for i, n := range s.Names {
		if n == name {
			idx = i
		}
	}
	if idx < 0 {
		return nil
	}
	out := make([]float64, 0, len(s.Points))
	for _, p := range s.Points {
		if idx < len(p.Values) {
			out = append(out, p.Values[idx])
		}
	}
	return out
}

var sparkChars = []rune("▁▂▃▄▅▆▇█")

// sparkRow renders "name  ▁▂▃ max" fitted to width cells.
func sparkRow(name string, vals []float64, width int, sty Style) string {
	if width < 10 {
		width = 10
	}
	if len(vals) > width {
		vals = vals[len(vals)-width:]
	}
	maxV := 0.0
	for _, v := range vals {
		if v > maxV {
			maxV = v
		}
	}
	var sb strings.Builder
	for _, v := range vals {
		i := 0
		if maxV > 0 {
			i = int(v / maxV * float64(len(sparkChars)-1))
		}
		if i < 0 {
			i = 0
		}
		if i >= len(sparkChars) {
			i = len(sparkChars) - 1
		}
		sb.WriteRune(sparkChars[i])
	}
	last := 0.0
	if len(vals) > 0 {
		last = vals[len(vals)-1]
	}
	return fmt.Sprintf("%-20s %s%s%s %s (max %s)", name, sty.Cyan, sb.String(), sty.Reset, fmtNum(last), fmtNum(maxV))
}

func fmtNum(v float64) string {
	switch {
	case v >= 1e6:
		return fmt.Sprintf("%.1fM", v/1e6)
	case v >= 1e3:
		return fmt.Sprintf("%.1fk", v/1e3)
	case v == float64(int64(v)):
		return fmt.Sprintf("%d", int64(v))
	default:
		return fmt.Sprintf("%.2f", v)
	}
}

func humanBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

// escState tracks CSI sequences: ESC, then an optional '[' and parameter
// bytes, ended by a final byte in 0x40..0x7e.
type escState int

const (
	escNone  escState = iota
	escStart          // just saw ESC
	escCSI            // inside ESC [ ... waiting for the final byte
)

func (e escState) step(r rune) (next escState, visible bool) {
	switch e {
	case escStart:
		if r == '[' {
			return escCSI, false
		}
		return escNone, false // two-byte escape
	case escCSI:
		if r >= 0x40 && r <= 0x7e {
			return escNone, false
		}
		return escCSI, false
	default:
		if r == 0x1b {
			return escStart, false
		}
		return escNone, true
	}
}

// visibleLen counts cells ignoring ANSI escapes.
func visibleLen(s string) int {
	n := 0
	st := escNone
	for _, r := range s {
		var vis bool
		st, vis = st.step(r)
		if vis {
			n++
		}
	}
	return n
}

// clip cuts a line to width visible cells, keeping escapes intact and
// closing with a reset when any escape was present.
func clip(s string, width int) string {
	if visibleLen(s) <= width {
		return s
	}
	var b strings.Builder
	n := 0
	st := escNone
	hadEsc := false
	for _, r := range s {
		var vis bool
		st, vis = st.step(r)
		if !vis {
			hadEsc = true
			b.WriteRune(r)
			continue
		}
		if n >= width-1 {
			b.WriteRune('…')
			break
		}
		b.WriteRune(r)
		n++
	}
	if hadEsc {
		b.WriteString("\x1b[0m")
	}
	return b.String()
}

// pad joins left and right with spaces to width.
func pad(left, right string, width int) string {
	gap := width - visibleLen(left) - visibleLen(right)
	if gap < 1 {
		return clip(left+" "+right, width)
	}
	return left + strings.Repeat(" ", gap) + right
}
