// Command xproxyctl manages a running xproxy through its Unix socket.
//
// Usage:
//
//	xproxyctl [-socket PATH] [-config PATH] [-json] COMMAND
//
// Commands:
//
//	status         show version, listeners and counters
//	stats          show counters
//	upstreams      show endpoint health and load
//	config         print the active configuration
//	validate       validate the configuration file without applying it
//	reload         validate and apply the configuration file (-dry-run shows the changes)
//	diff [FROM] [TO]  compare configurations: active, file or a history id (default active file)
//	history        list recorded configurations
//	rollback ID    apply a recorded configuration
//	rotate-secret FILE  add a fresh primary key to a secret file (-keep 2 old keys)
//	tls            served certificates with expiry, OCSP staple and Certificate Transparency state
//	reload-certs   re-read TLS certificate files
//	reopen-logs    reopen log files after rotation
//	tail STREAM    follow a log stream (access, error, security, audit)
//	bans           list active bans
//	ban TARGET     ban an address or CIDR (-duration 1h -reason text)
//	unban TARGET   remove a ban
//	cluster        show cluster peers and counters
//	spki FILE      print the spki_pins value for a PEM certificate
//	tui            full-screen live view (-refresh 2s, -no-color)
//	acme           show managed certificates; "acme renew" forces renewal
//	icap           show ICAP services and counters
//	filters        list middleware kinds and configured filters
//	geoip          show the country database and lookup counters
//	honeypot       list clients marked by honeypots; honeypot forget IP removes one
//	dns            show dns listener counters; "dns purge" empties the caches
//	ingress        show the Kubernetes ingress controller status
//	otlp           show the OpenTelemetry metrics exporter status
//	telemetry      show every OpenTelemetry exporter: metrics, traces, logs
//	cache          show cache statistics; "cache purge [HOST [PATH-PREFIX]]" removes entries
//	htpasswd FILE NAME  add or replace a basic_auth user (password on stdin)
//	quotas         usage per tenant, route and rate limit policy (-top 10)
//	metrics        print the Prometheus exposition
//	series         print sampled series (-since 10m -last 20)
//	version        print version
package main

import (
	"bufio"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/config/schema"
	_ "github.com/rom/xproxy/internal/filters" // built-in filter kinds for validate
	"github.com/rom/xproxy/internal/filters/apikey"
	"github.com/rom/xproxy/internal/mgmt"
	"github.com/rom/xproxy/internal/passwd"
	"github.com/rom/xproxy/internal/paths"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/sandbox"
	"github.com/rom/xproxy/internal/secret"
	"github.com/rom/xproxy/internal/tlsconf"
	"github.com/rom/xproxy/internal/tui"
	"github.com/rom/xproxy/internal/upstream"
	"github.com/rom/xproxy/internal/version"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("xproxyctl", flag.ContinueOnError)
	fs.SetOutput(errOut)
	socket := fs.String("socket", paths.Socket, "management socket")
	cfgPath := fs.String("config", paths.ConfigFile, "configuration file (validate, tail)")
	asJSON := fs.Bool("json", false, "machine readable output")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		usage(errOut)
		return 2
	}
	c := mgmt.NewClient(*socket)
	fail := func(err error) int {
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	switch fs.Arg(0) {
	case "version":
		_, _ = fmt.Fprintln(out, "xproxyctl", version.String())
		return 0
	case "validate":
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			return fail(err)
		}
		_, _ = fmt.Fprintf(out, "%s: OK (%d listeners, %d upstreams, %d routes)\n", *cfgPath, len(cfg.Server.Listeners), len(cfg.Upstreams), len(cfg.Routes))
		return 0
	case "status":
		st, err := c.Status()
		if err != nil {
			return fail(err)
		}
		if *asJSON {
			return printJSON(out, st)
		}
		_, _ = fmt.Fprintf(out, "xproxy %s  pid %d  generation %d\n", st.Version, st.PID, st.Generation)
		_, _ = fmt.Fprintf(out, "uptime %s  routes %d  upstreams %d\n", (time.Duration(st.Stats.UptimeSeconds) * time.Second).String(), st.Routes, st.Upstreams)
		names := make([]string, 0, len(st.Listeners))
		for n := range st.Listeners {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			_, _ = fmt.Fprintf(out, "listener %-12s %s\n", n, st.Listeners[n])
		}
		printStats(out, st.Stats)
		if sb := st.Sandbox; sb != nil {
			_, _ = fmt.Fprintln(out, "sandbox", sandboxSummary(sb))
		}
		return 0
	case "stats":
		st, err := c.Status()
		if err != nil {
			return fail(err)
		}
		if *asJSON {
			return printJSON(out, st.Stats)
		}
		printStats(out, st.Stats)
		return 0
	case "upstreams":
		b, err := c.Raw("/v1/upstreams")
		if err != nil {
			return fail(err)
		}
		if *asJSON {
			_, _ = out.Write(b)
			return 0
		}
		var ups map[string][]upstream.Stats
		if err := json.Unmarshal(b, &ups); err != nil {
			return fail(err)
		}
		pools := map[string]upstream.PoolStatus{}
		if pb, err := c.Raw("/v1/pools"); err == nil {
			_ = json.Unmarshal(pb, &pools)
		}
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "UPSTREAM\tENDPOINT\tWEIGHT\tCANARY\tHEALTHY\tEJECTED\tACTIVE\tREQUESTS\tERRORS\tRAMP\tLATENCY-MS\tSOURCE")
		names := make([]string, 0, len(ups))
		for n := range ups {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			for _, e := range ups[n] {
				src := "static"
				if e.Discovered {
					src = "dns"
				}
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%d\t%v\t%v\t%v\t%d\t%d\t%d\t%.0f%%\t%g\t%s\n", n, e.Address, e.Weight, e.Canary, e.Healthy, e.Ejected, e.Active, e.Requests, e.Errors, e.Ramp*100, e.LatencyMS, src)
			}
		}
		_ = tw.Flush()
		// Discovery and slow start per pool, when configured.
		for _, n := range names {
			ps, ok := pools[n]
			if !ok {
				continue
			}
			if d := ps.Discovery; d != nil {
				line := fmt.Sprintf("%s: discovery %s %s every %s, %d endpoints, %d resolutions, %d changes, %d errors", n, d.Type, d.Name, d.Interval, d.Endpoints, d.Resolutions, d.Changes, d.Errors)
				if d.LastError != "" {
					line += ", last error: " + d.LastError
				}
				_, _ = fmt.Fprintln(out, line)
			}
			if ps.SlowStart != "" {
				_, _ = fmt.Fprintf(out, "%s: slow start %s\n", n, ps.SlowStart)
			}
		}
		// Pool level state: circuit breakers and queues, when configured.
		shown := false
		for _, n := range names {
			ps, ok := pools[n]
			if !ok || (ps.Circuit == nil && ps.Queue == nil) {
				continue
			}
			if !shown {
				_, _ = fmt.Fprintln(out)
				_, _ = fmt.Fprintln(tw, "UPSTREAM\tCIRCUIT\tFAILURES\tOPENS\tREFUSED\tIN-FLIGHT\tWAITING\tQUEUED\tTIMEOUTS\tFULL")
				shown = true
			}
			circuit, failures, opens, refused := "-", "-", "-", "-"
			if cs := ps.Circuit; cs != nil {
				circuit, failures, opens, refused = cs.State, fmt.Sprintf("%d/%d", cs.Failures, cs.Threshold), fmt.Sprint(cs.Opens), fmt.Sprint(cs.Rejected)
				if cs.State == upstream.CircuitOpen {
					circuit += " until " + cs.Until.Local().Format("15:04:05")
				}
			}
			inFlight, waiting, queued, timeouts, full := "-", "-", "-", "-", "-"
			if q := ps.Queue; q != nil {
				inFlight, waiting, queued, timeouts, full = fmt.Sprintf("%d/%d", q.InFlight, q.MaxConcurrent), fmt.Sprintf("%d/%d", q.Waiting, q.QueueSize), fmt.Sprint(q.Queued), fmt.Sprint(q.Timeouts), fmt.Sprint(q.Full)
			}
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", n, circuit, failures, opens, refused, inFlight, waiting, queued, timeouts, full)
		}
		_ = tw.Flush()
		return 0
	case "quotas":
		qfs := flag.NewFlagSet("quotas", flag.ContinueOnError)
		qfs.SetOutput(errOut)
		top := qfs.Int("top", 10, "consumers listed per rate limit policy")
		if err := qfs.Parse(fs.Args()[1:]); err != nil {
			return 2
		}
		b, err := c.Raw(fmt.Sprintf("/v1/quotas?top=%d", *top))
		if err != nil {
			return fail(err)
		}
		if *asJSON {
			_, _ = out.Write(b)
			return 0
		}
		var q proxy.QuotaReport
		if err := json.Unmarshal(b, &q); err != nil {
			return fail(err)
		}
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		if len(q.Tenants) > 0 {
			_, _ = fmt.Fprintln(tw, "TENANT\tROUTES\tREQUESTS\tDENIED\tRATE-LIMITED\tBYTES-IN\tBYTES-OUT")
			for _, t := range q.Tenants {
				_, _ = fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\t%d\t%d\n", t.Tenant, t.Routes, t.Requests, t.Denied, t.RateLimited, t.BytesIn, t.BytesOut)
			}
			_ = tw.Flush()
			_, _ = fmt.Fprintln(out)
		}
		_, _ = fmt.Fprintln(tw, "ROUTE\tTENANT\tUPSTREAM\tREQUESTS\t2XX\t3XX\t4XX\t5XX\tDENIED\tRATE-LIMITED\tBYTES-IN\tBYTES-OUT\tP50-MS\tP95-MS\tP99-MS")
		for _, r := range q.Routes {
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%g\t%g\t%g\n", r.Route, dash(r.Tenant), dash(r.Upstream), r.Requests, r.Status2xx, r.Status3xx, r.Status4xx, r.Status5xx, r.Denied, r.RateLimited, r.BytesIn, r.BytesOut, r.LatencyP50MS, r.LatencyP95MS, r.LatencyP99MS)
		}
		_ = tw.Flush()
		if len(q.RateLimits) > 0 {
			_, _ = fmt.Fprintln(out)
			_, _ = fmt.Fprintln(tw, "POLICY\tKEY\tALGORITHM\tLIMIT\tMODE\tKEYS\tALLOWED\tDENIED\tTOP CONSUMERS (key=total/left)")
			for _, p := range q.RateLimits {
				tops := make([]string, 0, len(p.Top))
				for _, u := range p.Top {
					tops = append(tops, fmt.Sprintf("%s=%.0f/%.1f", u.Key, u.Total, u.Tokens))
				}
				limit := fmt.Sprintf("%g/s burst %d", p.Rate, p.Burst)
				if p.Algorithm == "sliding_window" {
					limit = fmt.Sprintf("%d per %s", p.Limit, p.Window)
				}
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%s\n", p.Policy, p.Key, p.Algorithm, limit, p.Distributed, p.Keys, p.Allowed, p.Denied, dash(strings.Join(tops, " ")))
			}
			_ = tw.Flush()
		}
		if len(q.Upstreams) > 0 {
			_, _ = fmt.Fprintln(out)
			_, _ = fmt.Fprintln(tw, "UPSTREAM\tREQUESTS\tERRORS\tACTIVE")
			for _, u := range q.Upstreams {
				_, _ = fmt.Fprintf(tw, "%s\t%d\t%d\t%d\n", u.Upstream, u.Requests, u.Errors, u.Active)
			}
			_ = tw.Flush()
		}
		return 0
	case "config":
		b, err := c.Raw("/v1/config")
		if err != nil {
			return fail(err)
		}
		_, _ = out.Write(b)
		return 0
	case "reload":
		rf := flag.NewFlagSet("reload", flag.ContinueOnError)
		rf.SetOutput(errOut)
		dry := rf.Bool("dry-run", false, "show what the file would change without applying it")
		if err := rf.Parse(fs.Args()[1:]); err != nil {
			return 2
		}
		if _, err := config.Load(*cfgPath); err != nil {
			_, _ = fmt.Fprintln(errOut, "refusing to reload: local validation failed")
			return fail(err)
		}
		if *dry {
			var ch config.Changes
			if err := c.Do("POST", "/v1/reload?dry_run=1", nil, &ch); err != nil {
				return fail(err)
			}
			if *asJSON {
				b, _ := json.MarshalIndent(ch, "", "  ")
				_, _ = out.Write(append(b, '\n'))
				return 0
			}
			printChanges(out, &ch)
			return 0
		}
		if err := c.Post("/v1/reload"); err != nil {
			return fail(err)
		}
		_, _ = fmt.Fprintln(out, "reloaded")
		return 0
	case "waf":
		return cmdWAF(c, fs.Args()[1:], *asJSON, out, errOut)
	case "sandbox":
		b, err := c.Raw("/v1/sandbox")
		if err != nil {
			return fail(err)
		}
		if *asJSON {
			_, _ = out.Write(b)
			return 0
		}
		var sb sandbox.Status
		if err := json.Unmarshal(b, &sb); err != nil {
			return fail(err)
		}
		_, _ = fmt.Fprintf(out, "platform %s  enabled %v  strict %v", sb.Platform, sb.Enabled, sb.Strict)
		if !sb.AppliedAt.IsZero() {
			_, _ = fmt.Fprintf(out, "  applied %s", sb.AppliedAt.Local().Format(time.RFC3339))
		}
		_, _ = fmt.Fprintln(out)
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "MECHANISM\tSTATE\tDETAIL")
		for _, m := range sb.Mechanism {
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\n", m.Name, m.State, dash(m.Detail))
		}
		_ = tw.Flush()
		if sb.Landlocked {
			_, _ = fmt.Fprintf(out, "landlock ABI %d\n", sb.LandlockABI)
			for _, p := range sb.ReadPaths {
				_, _ = fmt.Fprintf(out, "  read   %s\n", p)
			}
			for _, p := range sb.WritePaths {
				_, _ = fmt.Fprintf(out, "  write  %s\n", p)
			}
		}
		return 0
	case "tls":
		if fs.NArg() > 1 && fs.Arg(1) == "tickets" {
			b, err := c.Raw("/v1/tls/tickets")
			if err != nil {
				return fail(err)
			}
			if *asJSON {
				_, _ = out.Write(b)
				return 0
			}
			var ts tlsconf.TicketStatus
			if err := json.Unmarshal(b, &ts); err != nil {
				return fail(err)
			}
			_, _ = fmt.Fprintf(out, "session tickets: epoch %d (since %s, next rotation %s, every %s)\n", ts.Epoch, ts.EpochStarted.Local().Format(time.RFC3339), ts.NextRotation.Local().Format(time.RFC3339), ts.Rotate)
			_, _ = fmt.Fprintf(out, "keys %d from %d master key(s)  fingerprint %s  rotations %d\n", ts.Keys, ts.MasterKeys, ts.Fingerprint, ts.Rotations)
			for p, fp := range ts.Peers {
				state := "agrees"
				if fp != ts.Fingerprint {
					state = "MISMATCH"
				}
				_, _ = fmt.Fprintf(out, "peer %s %s (%s)\n", p, state, fp)
			}
			return 0
		}
		b, err := c.Raw("/v1/tls")
		if err != nil {
			return fail(err)
		}
		if *asJSON {
			_, _ = out.Write(b)
			return 0
		}
		var certs map[string][]tlsconf.CertInfo
		if err := json.Unmarshal(b, &certs); err != nil {
			return fail(err)
		}
		names := make([]string, 0, len(certs))
		for n := range certs {
			names = append(names, n)
		}
		sort.Strings(names)
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "LISTENER\tNAMES\tISSUER\tEXPIRES\tSOURCE\tOCSP\tCT")
		for _, n := range names {
			for _, ci := range certs[n] {
				source := "file"
				if ci.Managed {
					source = "acme"
				}
				ocspCol := ci.OCSP.Status
				if ci.OCSP.Error != "" && ci.OCSP.Status != "disabled" {
					ocspCol += " (" + ci.OCSP.Error + ")"
				} else if !ci.OCSP.NextUpdate.IsZero() {
					ocspCol += " until " + ci.OCSP.NextUpdate.Local().Format("01-02 15:04")
				}
				ctCol := fmt.Sprintf("%d scts", ci.CT.Embedded)
				if ci.CT.Verified > 0 {
					ctCol = fmt.Sprintf("%d/%d verified", ci.CT.Verified, ci.CT.Embedded)
				}
				if !ci.CT.OK {
					ctCol += " FAIL: " + ci.CT.Error
				}
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", n, strings.Join(ci.Names, ","), dash(ci.Issuer), ci.NotAfter.Local().Format(time.RFC3339), source, ocspCol, ctCol)
			}
		}
		_ = tw.Flush()
		return 0
	case "rotate-secret":
		rs := flag.NewFlagSet("rotate-secret", flag.ContinueOnError)
		rs.SetOutput(errOut)
		keep := rs.Int("keep", 2, "previous keys kept for verification")
		if err := rs.Parse(fs.Args()[1:]); err != nil || rs.NArg() != 1 {
			_, _ = fmt.Fprintln(errOut, "usage: xproxyctl rotate-secret [-keep 2] FILE")
			return 2
		}
		ring, err := secret.Rotate(rs.Arg(0), *keep)
		if err != nil {
			return fail(err)
		}
		_, _ = fmt.Fprintf(out, "%s: new primary key, %d key(s) in the ring; run xproxyctl reload to apply\n", rs.Arg(0), ring.Len())
		return 0
	case "diff":
		from, to := "active", "file"
		if a := fs.Args(); len(a) > 1 {
			to = a[1]
			if len(a) > 2 {
				from, to = a[1], a[2]
			}
		}
		var ch config.Changes
		if err := c.Do("GET", "/v1/diff?from="+url.QueryEscape(from)+"&to="+url.QueryEscape(to), nil, &ch); err != nil {
			return fail(err)
		}
		if *asJSON {
			b, _ := json.MarshalIndent(ch, "", "  ")
			_, _ = out.Write(append(b, '\n'))
			return 0
		}
		printChanges(out, &ch)
		if ch.Same {
			return 0
		}
		return 1
	case "history":
		b, err := c.Raw("/v1/history")
		if err != nil {
			return fail(err)
		}
		if *asJSON {
			_, _ = out.Write(b)
			return 0
		}
		var entries []config.Entry
		if err := json.Unmarshal(b, &entries); err != nil {
			return fail(err)
		}
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "ID\tGENERATION\tAPPLIED\tNOTE\tSIZE")
		for _, e := range entries {
			_, _ = fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%d\n", e.ID, e.Generation, e.Applied.Local().Format(time.RFC3339), e.Note, e.Size)
		}
		_ = tw.Flush()
		return 0
	case "rollback":
		if fs.NArg() != 2 {
			_, _ = fmt.Fprintln(errOut, "usage: xproxyctl rollback ID   (an id from xproxyctl history)")
			return 2
		}
		if err := c.Post("/v1/rollback?id=" + url.QueryEscape(fs.Arg(1))); err != nil {
			return fail(err)
		}
		_, _ = fmt.Fprintln(out, "rolled back to", fs.Arg(1))
		return 0
	case "reload-certs":
		if err := c.Post("/v1/reload-certs"); err != nil {
			return fail(err)
		}
		_, _ = fmt.Fprintln(out, "certificates reloaded")
		return 0
	case "reopen-logs":
		if err := c.Post("/v1/logs/reopen"); err != nil {
			return fail(err)
		}
		_, _ = fmt.Fprintln(out, "logs reopened")
		return 0
	case "tail":
		if fs.NArg() != 2 {
			usage(errOut)
			return 2
		}
		return tail(*cfgPath, fs.Arg(1), out, errOut)
	case "tui":
		tf := flag.NewFlagSet("tui", flag.ContinueOnError)
		tf.SetOutput(errOut)
		refresh := tf.Duration("refresh", 2*time.Second, "refresh interval")
		noColor := tf.Bool("no-color", os.Getenv("NO_COLOR") != "", "disable colours")
		if err := tf.Parse(fs.Args()[1:]); err != nil {
			return 2
		}
		cfg, _ := config.Load(*cfgPath) // optional: only for the log path
		src := tui.NewSource(c, cfg)
		act := tui.Actions{
			Ban:   func(target, dur, reason string) error { _, err := c.Ban(target, dur, reason); return err },
			Unban: c.Unban,
		}
		if err := tui.Run(src, act, tui.Options{Refresh: *refresh, Color: !*noColor}); err != nil {
			return fail(err)
		}
		return 0
	case "acme":
		if fs.NArg() == 2 && fs.Arg(1) == "renew" {
			if err := c.Post("/v1/acme/renew"); err != nil {
				return fail(err)
			}
			_, _ = fmt.Fprintln(out, "renewal completed")
			return 0
		}
		sts, err := c.ACME()
		if err != nil {
			return fail(err)
		}
		if *asJSON {
			return printJSON(out, sts)
		}
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "CERTIFICATE\tHOSTS\tPRESENT\tEXPIRES\tISSUER\tISSUED\tRENEWING\tLAST ERROR")
		for _, st := range sts {
			exp := ""
			if st.Present {
				exp = st.NotAfter.Format("2006-01-02")
			}
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%v\t%s\t%s\t%d\t%v\t%s\n", st.Name, strings.Join(st.Hosts, ","), st.Present, exp, st.Issuer, st.Issued, st.Renewing, st.LastError)
		}
		_ = tw.Flush()
		return 0
	case "cache":
		if fs.NArg() >= 2 && fs.Arg(1) == "purge" {
			host, prefix := "", ""
			if fs.NArg() >= 3 {
				host = fs.Arg(2)
			}
			if fs.NArg() >= 4 {
				prefix = fs.Arg(3)
			}
			n, err := c.CachePurge(host, prefix)
			if err != nil {
				return fail(err)
			}
			_, _ = fmt.Fprintf(out, "purged %d entries\n", n)
			return 0
		}
		var b []byte
		if err := c.Do("GET", "/v1/cache", nil, &b); err != nil {
			return fail(err)
		}
		_, _ = out.Write(b)
		return 0
	case "geoip":
		var b []byte
		if err := c.Do("GET", "/v1/geoip", nil, &b); err != nil {
			return fail(err)
		}
		_, _ = out.Write(b)
		return 0
	case "otlp":
		var b []byte
		if err := c.Do("GET", "/v1/otlp", nil, &b); err != nil {
			return fail(err)
		}
		_, _ = out.Write(b)
		return 0
	case "telemetry":
		b, err := c.Raw("/v1/telemetry")
		if err != nil {
			return fail(err)
		}
		if *asJSON {
			_, _ = out.Write(b)
			return 0
		}
		var v mgmt.TelemetryView
		if err := json.Unmarshal(b, &v); err != nil {
			return fail(err)
		}
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "SIGNAL\tENDPOINT\tSENT\tDROPPED\tPUSHES\tFAILED\tQUEUED\tLAST ERROR")
		if m := v.Metrics; m != nil {
			_, _ = fmt.Fprintf(tw, "metrics\t%s\t%d\t-\t%d\t%d\t-\t%s\n", m.Endpoint, m.Sent, m.Sent+m.Failed, m.Failed, dash(m.LastError))
		}
		if t := v.Traces; t != nil {
			_, _ = fmt.Fprintf(tw, "traces\t%s\t%d\t%d\t%d\t%d\t%d\t%s\n", dash(t.Endpoint), t.Sent, t.Dropped, t.Pushes, t.Failed, t.Queued, dash(t.LastError))
			_, _ = fmt.Fprintf(tw, "  spans\tstarted %d, sampled %d, sample %g%%, propagate %v\t\t\t\t\t\t\n", t.Started, t.Sampled, t.SamplePercent, t.Propagate)
		}
		if l := v.Logs; l != nil {
			_, _ = fmt.Fprintf(tw, "logs\t%s\t%d\t%d\t%d\t%d\t%d\t%s\n", l.Endpoint, l.Sent, l.Dropped, l.Pushes, l.Failed, l.Queued, dash(l.LastError))
		}
		if s := v.SIEM; s != nil {
			_, _ = fmt.Fprintf(tw, "siem (%s)\t%s\t%d\t%d\t%d\t%d\t%d\t%s\n", s.Format, s.Endpoint, s.Sent, s.Dropped, s.Pushes, s.Failed, s.Queued, dash(s.LastError))
		}
		if v.Metrics == nil && v.Traces == nil && v.Logs == nil && v.SIEM == nil {
			_, _ = fmt.Fprintln(tw, "(no OpenTelemetry exporter or SIEM sink configured)")
		}
		_ = tw.Flush()
		return 0
	case "ingress":
		var b []byte
		if err := c.Do("GET", "/v1/ingress", nil, &b); err != nil {
			return fail(err)
		}
		_, _ = out.Write(b)
		return 0
	case "dns":
		if fs.NArg() >= 2 && fs.Arg(1) == "purge" {
			var res struct {
				Purged int `json:"purged"`
			}
			if err := c.Do("DELETE", "/v1/dns", nil, &res); err != nil {
				return fail(err)
			}
			_, _ = fmt.Fprintf(out, "purged %d entries\n", res.Purged)
			return 0
		}
		var b []byte
		if err := c.Do("GET", "/v1/dns", nil, &b); err != nil {
			return fail(err)
		}
		_, _ = out.Write(b)
		return 0
	case "patches":
		ps, err := c.Patches()
		if err != nil {
			return fail(err)
		}
		if *asJSON {
			return printJSON(out, ps)
		}
		if len(ps) == 0 {
			_, _ = fmt.Fprintln(out, "no virtual patches configured")
			return 0
		}
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "PATCH\tSTATE\tACTION\tSTATUS\tHITS\tLAST HIT\tEXPIRES\tDESCRIPTION")
		for _, p := range ps {
			state := "active"
			switch {
			case !p.Enabled:
				state = "disabled"
			case p.Expired:
				state = "expired"
			}
			expires := "-"
			if !p.Expires.IsZero() {
				expires = p.Expires.Local().Format("2006-01-02")
			}
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%s\t%s\t%s\n", p.ID, state, p.Action, p.Status, p.Hits, ago(p.LastHit), expires, p.Description)
		}
		_ = tw.Flush()
		return 0
	case "honeypot":
		if fs.NArg() >= 3 && fs.Arg(1) == "forget" {
			var res struct {
				Removed bool `json:"removed"`
			}
			if err := c.Do("DELETE", "/v1/honeypot?ip="+url.QueryEscape(fs.Arg(2)), nil, &res); err != nil {
				return fail(err)
			}
			_, _ = fmt.Fprintf(out, "removed: %v\n", res.Removed)
			return 0
		}
		var hv struct {
			Marks  []proxy.Mark `json:"marks"`
			Decoys []string     `json:"decoys"`
		}
		if err := c.Do("GET", "/v1/honeypot", nil, &hv); err != nil {
			return fail(err)
		}
		if *asJSON {
			return printJSON(out, hv)
		}
		_, _ = fmt.Fprintf(out, "decoys: %s\n\n", strings.Join(hv.Decoys, ", "))
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "ADDRESS\tROUTE\tHITS\tFIRST\tLAST\tEXPIRES")
		for _, m := range hv.Marks {
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\t%s\n", m.Address, m.Route, m.Hits, m.First.Format(time.RFC3339), m.Last.Format(time.RFC3339), m.Expires.Format(time.RFC3339))
		}
		_ = tw.Flush()
		return 0
	case "filters":
		fv, err := c.Filters()
		if err != nil {
			return fail(err)
		}
		if *asJSON {
			return printJSON(out, fv)
		}
		_, _ = fmt.Fprintf(out, "middleware API version %d\n\nKINDS\n", fv.APIVersion)
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		for _, k := range fv.Kinds {
			_, _ = fmt.Fprintf(tw, "  %s\t%s\n", k.Name, k.Description)
		}
		_ = tw.Flush()
		_, _ = fmt.Fprintln(out, "\nCONFIGURED")
		tw = tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "  NAME\tKIND\tSTAGE\tROUTES\tDENIED")
		for _, f := range fv.Filters {
			_, _ = fmt.Fprintf(tw, "  %s\t%s\t%s\t%d\t%d\n", f.Name, f.Kind, f.Stage, f.Routes, f.Denied)
		}
		_ = tw.Flush()
		return 0
	case "apikey":
		return apikeyCmd(fs.Args()[1:], out, errOut)
	case "htpasswd":
		if fs.NArg() < 3 {
			_, _ = fmt.Fprintln(errOut, "usage: xproxyctl htpasswd FILE NAME   (password read from stdin, one line)")
			return 2
		}
		return htpasswd(fs.Arg(1), fs.Arg(2), os.Stdin, out, errOut)
	case "icap":
		sts, err := c.ICAP()
		if err != nil {
			return fail(err)
		}
		if *asJSON {
			return printJSON(out, sts)
		}
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "SERVICE\tURL\tREACHABLE\tPREVIEW\tREQUESTS\tUNMODIFIED\tMODIFIED\tREPLACED\tERRORS\tBYPASSED\tISTAG")
		for _, st := range sts {
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%v\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%s\n", st.Name, st.URL, st.Reachable, st.Preview, st.Requests, st.Unmodified, st.Modified, st.Replacements, st.Errors, st.Bypassed, st.ISTag)
		}
		_ = tw.Flush()
		return 0
	case "metrics":
		b, err := c.Metrics()
		if err != nil {
			return fail(err)
		}
		_, _ = out.Write(b)
		return 0
	case "series":
		sf := flag.NewFlagSet("series", flag.ContinueOnError)
		sf.SetOutput(errOut)
		since := sf.Duration("since", 10*time.Minute, "how far back")
		last := sf.Int("last", 30, "at most this many points")
		if err := sf.Parse(fs.Args()[1:]); err != nil {
			return 2
		}
		sr, err := c.Series(*since, *last)
		if err != nil {
			return fail(err)
		}
		if *asJSON {
			return printJSON(out, sr)
		}
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprint(tw, "TIME")
		for _, n := range sr.Names {
			_, _ = fmt.Fprintf(tw, "\t%s", n)
		}
		_, _ = fmt.Fprintln(tw)
		for _, p := range sr.Points {
			_, _ = fmt.Fprint(tw, p.Time.Local().Format("15:04:05"))
			for _, v := range p.Values {
				_, _ = fmt.Fprintf(tw, "\t%.2f", v)
			}
			_, _ = fmt.Fprintln(tw)
		}
		_ = tw.Flush()
		return 0
	case "spki":
		if fs.NArg() != 2 {
			_, _ = fmt.Fprintln(errOut, "usage: xproxyctl spki CERT.pem")
			return 2
		}
		data, err := os.ReadFile(fs.Arg(1)) //nolint:gosec // operator supplied path
		if err != nil {
			return fail(err)
		}
		block, _ := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			return fail(errors.New("no PEM certificate found"))
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fail(err)
		}
		_, _ = fmt.Fprintf(out, "%s  # %s, expires %s\n", tlsconf.SPKIPin(cert), cert.Subject.CommonName, cert.NotAfter.Format("2006-01-02"))
		return 0
	case "fleet":
		st, err := c.FleetStatus()
		if err != nil {
			return fail(err)
		}
		if *asJSON {
			return printJSON(out, st)
		}
		if !st.Enabled {
			_, _ = fmt.Fprintln(out, "fleet: not configured")
			return 0
		}
		_, _ = fmt.Fprintf(out, "controller %s  node %s  dir %s  interval %s  apply %s  assigned %v\n", st.Controller, st.NodeID, st.Dir, st.Interval, onOff(st.Apply), st.Assigned)
		_, _ = fmt.Fprintf(out, "polls %d  reports %d  applies %d  failures %d  last poll %s  last report %s\n", st.Polls, st.Reports, st.Applies, st.Failures, ago(st.LastPoll), ago(st.LastReport))
		if st.Applied.Digest != "" {
			_, _ = fmt.Fprintf(out, "applied %s ok=%v at %s", st.Applied.Digest, st.Applied.OK, st.Applied.At.Local().Format(time.RFC3339))
			if st.Applied.Error != "" {
				_, _ = fmt.Fprintf(out, "  error: %s", st.Applied.Error)
			}
			_, _ = fmt.Fprintln(out)
		} else {
			_, _ = fmt.Fprintln(out, "no bundle applied yet")
		}
		if st.PendingDigest != "" {
			_, _ = fmt.Fprintf(out, "pending %s (apply is off)\n", st.PendingDigest)
		}
		if st.LastError != "" {
			_, _ = fmt.Fprintf(out, "last error: %s\n", st.LastError)
		}
		return 0
	case "cluster":
		st, err := c.ClusterStatus()
		if err != nil {
			return fail(err)
		}
		if *asJSON {
			return printJSON(out, st)
		}
		_, _ = fmt.Fprintf(out, "node %s  listen %s\n", st.NodeID, st.Listen)
		_, _ = fmt.Fprintf(out, "rates sent %d received %d (keys %d)  bans sent %d received %d  rejected %d dropped %d\n",
			st.RatesSent, st.RatesReceived, st.KeysReceived, st.BansSent, st.BansReceived, st.Rejected, st.Dropped)
		_, _ = fmt.Fprintf(out, "members %s  exact decisions asked %d answered %d served %d local fallbacks %d\n",
			strings.Join(st.Members, ","), st.ExactAsked, st.ExactDecided, st.ExactServed, st.ExactFallbacks)
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "PEER\tCONNECTED\tSINCE\tMESSAGES\tRECONNECTS\tLAST ERROR")
		for _, p := range st.Peers {
			since := ""
			if p.Connected {
				since = time.Since(p.ConnectedAt).Round(time.Second).String()
			}
			_, _ = fmt.Fprintf(tw, "%s\t%v\t%s\t%d\t%d\t%s\n", p.Address, p.Connected, since, p.MessagesOut, p.Reconnects, p.LastError)
		}
		_ = tw.Flush()
		if len(st.Inbound) > 0 {
			tw = tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(tw, "INBOUND\tNODE\tCERT\tLAST SEEN\tMESSAGES")
			for _, in := range st.Inbound {
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s ago\t%d\n", in.Remote, in.NodeID, in.CertName, time.Since(in.LastSeen).Round(time.Second), in.MessagesIn)
			}
			_ = tw.Flush()
		}
		return 0
	case "bans":
		es, err := c.Bans()
		if err != nil {
			return fail(err)
		}
		if *asJSON {
			return printJSON(out, es)
		}
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "TARGET\tEXPIRES IN\tSOURCE\tCOUNT\tREASON")
		for _, e := range es {
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\n", e.Target, time.Until(e.Until).Round(time.Second), e.Source, e.Count, e.Reason)
		}
		_ = tw.Flush()
		return 0
	case "ban":
		bf := flag.NewFlagSet("ban", flag.ContinueOnError)
		bf.SetOutput(errOut)
		dur := bf.String("duration", "1h", "ban duration")
		reason := bf.String("reason", "manual", "reason recorded with the ban")
		if err := bf.Parse(fs.Args()[1:]); err != nil || bf.NArg() != 1 {
			_, _ = fmt.Fprintln(errOut, "usage: xproxyctl ban [-duration 1h] [-reason text] ADDRESS|CIDR")
			return 2
		}
		e, err := c.Ban(bf.Arg(0), *dur, *reason)
		if err != nil {
			return fail(err)
		}
		_, _ = fmt.Fprintf(out, "banned %s until %s\n", e.Target, e.Until.Format(time.RFC3339))
		return 0
	case "unban":
		if fs.NArg() != 2 {
			_, _ = fmt.Fprintln(errOut, "usage: xproxyctl unban ADDRESS|CIDR")
			return 2
		}
		if err := c.Unban(fs.Arg(1)); err != nil {
			return fail(err)
		}
		_, _ = fmt.Fprintf(out, "unbanned %s\n", fs.Arg(1))
		return 0
	case "schema":
		_, _ = out.Write(schema.JSON)
		return 0
	case "completion":
		if fs.NArg() == 2 {
			if script, ok := completionScript(fs.Arg(1)); ok {
				_, _ = io.WriteString(out, script)
				return 0
			}
		}
		_, _ = fmt.Fprintln(errOut, "usage: xproxyctl completion bash|zsh|fish")
		return 2
	case "help":
		help(out)
		return 0
	default:
		usage(errOut)
		return 2
	}
}

func printJSON(out io.Writer, v any) int {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
	return 0
}

func printStats(out io.Writer, s interface{}) {
	b, _ := json.Marshal(s)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	keys := make([]string, 0, len(m))
	for k := range m {
		if k == "started_at" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	for _, k := range keys {
		switch v := m[k].(type) {
		case float64:
			_, _ = fmt.Fprintf(tw, "%s\t%.0f\n", k, v)
		default:
			_, _ = fmt.Fprintf(tw, "%s\t%v\n", k, v)
		}
	}
	_ = tw.Flush()
}

// htpasswd adds or replaces name in a basic_auth users file with a PBKDF2
// hash of the password read from stdin. The file is written 0600 through a
// temporary file so a reader never sees a partial line.
func htpasswd(path, name string, in io.Reader, out, errOut io.Writer) int {
	if name == "" || strings.ContainsAny(name, ":\r\n") {
		_, _ = fmt.Fprintln(errOut, "error: user name must not contain ':'")
		return 2
	}
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	hash, err := passwd.Hash(strings.TrimRight(line, "\r\n"))
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	var lines []string
	if data, err := os.ReadFile(path); err == nil { //nolint:gosec // operator supplied path
		for _, l := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
			if l == "" || strings.HasPrefix(strings.TrimSpace(l), "#") || !strings.HasPrefix(l, name+":") {
				lines = append(lines, l)
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	lines = append(lines, name+":"+hash)
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp") // O_EXCL, never follows a link
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	if _, err := tmp.WriteString(strings.Join(lines, "\n") + "\n"); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		_ = os.Remove(tmp.Name())
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	_, _ = fmt.Fprintf(out, "user %s written to %s\n", name, path)
	return 0
}

// tail follows a log stream file, printing new lines as they appear. It is
// a plain follow: log lines are already JSON.
func tail(cfgPath, stream string, out, errOut io.Writer) int {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	var s config.LogStream
	switch stream {
	case "access":
		s = cfg.Logging.Access
	case "error":
		s = cfg.Logging.Error
	case "security":
		s = cfg.Logging.Security
	case "audit":
		s = cfg.Logging.Audit
	default:
		_, _ = fmt.Fprintln(errOut, "error: unknown stream", stream)
		return 2
	}
	path := filepath.Join(cfg.Logging.Directory, s.File)
	f, err := os.Open(path) //nolint:gosec // path derived from the operator's configuration
	if err != nil {
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	buf := make([]byte, 64<<10)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			_, _ = out.Write(buf[:n])
		}
		if err == io.EOF {
			time.Sleep(250 * time.Millisecond)
			// Follow rotation: reopen if the inode changed.
			if st, err := os.Stat(path); err == nil {
				if cur, err2 := f.Stat(); err2 == nil && !os.SameFile(st, cur) {
					_ = f.Close()
					if f, err = os.Open(path); err != nil { //nolint:gosec // same operator-owned path
						_, _ = fmt.Fprintln(errOut, "error:", err)
						return 1
					}
				}
			}
			continue
		}
		if err != nil {
			_, _ = fmt.Fprintln(errOut, "error:", err)
			return 1
		}
	}
}

// dash prints "-" for an empty cell.
// cmdWAF implements "xproxyctl waf [rules|proposals|exclusions|reset]".
func cmdWAF(c *mgmt.Client, args []string, asJSON bool, out, errOut io.Writer) int {
	wfs := flag.NewFlagSet("waf", flag.ContinueOnError)
	wfs.SetOutput(errOut)
	top := wfs.Int("top", 20, "rules listed")
	if err := wfs.Parse(args); err != nil {
		return 2
	}
	fail := func(err error) int {
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	sub := wfs.Arg(0)
	switch sub {
	case "exclusions":
		b, err := c.Raw("/v1/waf/exclusions")
		if err != nil {
			return fail(err)
		}
		_, _ = out.Write(b)
		return 0
	case "reset":
		if err := c.Post("/v1/waf/reset"); err != nil {
			return fail(err)
		}
		_, _ = fmt.Fprintln(out, "waf statistics reset")
		return 0
	case "", "rules", "proposals", "anomalies":
	default:
		_, _ = fmt.Fprintln(errOut, "usage: xproxyctl waf [-top N] [rules|proposals|anomalies|exclusions|reset]")
		return 2
	}
	b, err := c.Raw(fmt.Sprintf("/v1/waf?top=%d", *top))
	if err != nil {
		return fail(err)
	}
	if asJSON {
		_, _ = out.Write(b)
		return 0
	}
	var rep proxy.WAFReport
	if err := json.Unmarshal(b, &rep); err != nil {
		return fail(err)
	}
	if !rep.Enabled {
		_, _ = fmt.Fprintln(out, "waf: not configured")
		if rep.Requests == 0 {
			return 0
		}
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	if sub == "" {
		_, _ = fmt.Fprintf(out, "since %s  requests %d  blocked %d  detected %d  rules seen %d\n",
			rep.Since.Local().Format(time.RFC3339), rep.Requests, rep.Blocked, rep.Detected, rep.TotalRules)
		if l := rep.Learning; l != nil {
			_, _ = fmt.Fprintf(out, "learning %s  min_hits %d  entries %d/%d  dropped %d  proposals %d\n",
				onOff(l.Enabled), l.MinHits, l.Entries, l.MaxEntries, l.Dropped, len(l.Proposals))
		}
		if rep.SchemaViolations > 0 {
			_, _ = fmt.Fprintf(out, "schema violations %d\n", rep.SchemaViolations)
		}
		if a := rep.Anomaly; a != nil && a.Enabled {
			_, _ = fmt.Fprintf(out, "anomaly %s  window %s  action %s  clients %d  windows %d  flagged %d (total %d)  acted %d\n",
				onOff(a.Enabled), a.Window, a.Action, a.Clients, a.Windows, a.Flagged, a.FlaggedTotal, a.Acted)
		}
		if len(rep.Profiles) > 0 {
			_, _ = fmt.Fprintln(tw, "PROFILE	MODES	CRS	VERSION	RULE-FILES	PLUGINS	SCHEMAS")
			for _, p := range rep.Profiles {
				_, _ = fmt.Fprintf(tw, "%s	%s	%s	%s	%d	%s	%s\n", p.Name, strings.Join(p.Modes, ","), dash(p.CRS), dash(p.Version), p.RuleFiles,
					dash(strings.Join(p.Plugins, ",")), dash(strings.Join(p.Schemas, ",")))
			}
			_ = tw.Flush()
		}
		if len(rep.Routes) > 0 {
			_, _ = fmt.Fprintln(tw, "ROUTE	PROFILE	MODE	ENFORCED")
			for _, r := range rep.Routes {
				enforced := fmt.Sprintf("%d%%", r.BlockPercent)
				if len(r.BlockCIDRs) > 0 {
					enforced += " + " + strings.Join(r.BlockCIDRs, ",")
				}
				_, _ = fmt.Fprintf(tw, "%s	%s	%s	%s\n", r.Route, r.Profile, r.Mode, enforced)
			}
			_ = tw.Flush()
		}
	}
	if sub == "" || sub == "rules" {
		if len(rep.Rules) == 0 {
			_, _ = fmt.Fprintln(out, "no rule matches recorded")
		} else {
			_, _ = fmt.Fprintln(tw, "RULE	MATCHES	BLOCKS	DETECTS	SEVERITY	LAST-SEEN	MESSAGE")
			for _, r := range rep.Rules {
				_, _ = fmt.Fprintf(tw, "%d	%d	%d	%d	%s	%s	%s\n", r.ID, r.Matches, r.Blocks, r.Detects, dash(r.Severity), r.LastSeen.Local().Format(time.RFC3339), r.Message)
			}
			_ = tw.Flush()
		}
	}
	if sub == "proposals" || (sub == "" && rep.Learning != nil && len(rep.Learning.Proposals) > 0) {
		if rep.Learning == nil || len(rep.Learning.Proposals) == 0 {
			_, _ = fmt.Fprintln(out, "no exclusion proposals")
			return 0
		}
		_, _ = fmt.Fprintln(tw, "RULE	TARGET	ROUTE	HITS	CLIENTS	LAST-SEEN	MESSAGE")
		for _, p := range rep.Learning.Proposals {
			_, _ = fmt.Fprintf(tw, "%d	%s	%s	%d	%d	%s	%s\n", p.Rule, p.Target, dash(p.Route), p.Hits, p.Clients, p.LastSeen.Local().Format(time.RFC3339), p.Message)
		}
		_ = tw.Flush()
		_, _ = fmt.Fprintln(out, "review the directives with: xproxyctl waf exclusions")
	}
	if sub == "anomalies" || (sub == "" && rep.Anomaly != nil && len(rep.Anomaly.Top) > 0) {
		a := rep.Anomaly
		if a == nil || !a.Enabled {
			_, _ = fmt.Fprintln(out, "anomaly detection is not enabled")
			return 0
		}
		if len(a.Baseline) > 0 {
			_, _ = fmt.Fprintln(tw, "FEATURE	MEAN	STDDEV")
			for _, b := range a.Baseline {
				_, _ = fmt.Fprintf(tw, "%s	%.3f	%.3f\n", b.Feature, b.Mean, b.StdDev)
			}
			_ = tw.Flush()
		} else {
			_, _ = fmt.Fprintf(out, "no baseline yet (%d windows closed, %d clients scored; a window needs at least %d clients with %d requests)\n", a.Windows, a.Scored, 8, a.MinRequests)
		}
		if len(a.Top) == 0 {
			_, _ = fmt.Fprintln(out, "no flagged clients")
			return 0
		}
		_, _ = fmt.Fprintln(tw, "CLIENT	SCORE	FEATURE	VALUE	MEAN	SINCE	EXPIRES")
		for _, c := range a.Top {
			_, _ = fmt.Fprintf(tw, "%s	%.1f	%s	%.3f	%.3f	%s	%s\n", c.Client, c.Score, c.Feature, c.Value, c.Mean, c.Since.Local().Format(time.RFC3339), c.Expires.Local().Format(time.RFC3339))
		}
		_ = tw.Flush()
	}
	return 0
}

// sandboxSummary is the one line form used by status: applied mechanisms
// first, then the rest with their state.
func sandboxSummary(sb *sandbox.Status) string {
	if !sb.Enabled {
		return "disabled"
	}
	var applied, other []string
	for _, m := range sb.Mechanism {
		if m.State == sandbox.StateApplied {
			applied = append(applied, m.Name)
		} else {
			other = append(other, m.Name+"="+m.State)
		}
	}
	s := "applied " + dash(strings.Join(applied, ","))
	if len(other) > 0 {
		s += "  " + strings.Join(other, " ")
	}
	return s
}

// ago renders a time as a relative age, "-" for the zero time.
func ago(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return time.Since(t).Round(time.Second).String() + " ago"
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func dash(v string) string {
	if v == "" {
		return "-"
	}
	return v
}

// printChanges renders a configuration comparison.
func printChanges(out io.Writer, ch *config.Changes) {
	if ch.Same {
		_, _ = fmt.Fprintf(out, "%s and %s are identical\n", ch.From, ch.To)
		return
	}
	_, _ = fmt.Fprintf(out, "%s -> %s\n", ch.From, ch.To)
	for _, line := range ch.Summary {
		_, _ = fmt.Fprintln(out, " ", line)
	}
	for _, c := range ch.Changes {
		if c.Name != "" {
			_, _ = fmt.Fprintf(out, "  %-8s %s %s\n", c.Kind, c.Section, c.Name)
		} else {
			_, _ = fmt.Fprintf(out, "  %-8s %s\n", c.Kind, c.Section)
		}
	}
	if len(ch.RestartNeeded) > 0 {
		_, _ = fmt.Fprintln(out, "restart needed for:")
		for _, r := range ch.RestartNeeded {
			_, _ = fmt.Fprintln(out, " ", r)
		}
	}
	if len(ch.Drains) > 0 {
		_, _ = fmt.Fprintln(out, "applied on reload with a connection drain:")
		for _, r := range ch.Drains {
			_, _ = fmt.Fprintln(out, " ", r)
		}
	}
	if ch.Truncated {
		_, _ = fmt.Fprintln(out, "(text diff omitted: documents too large)")
	} else if ch.Text != "" {
		_, _ = fmt.Fprintln(out)
		_, _ = fmt.Fprint(out, ch.Text)
	}
}

// apikeyCmd manages the keys file of api_key filters.
func apikeyCmd(args []string, out, errOut io.Writer) int {
	usage := func() int {
		_, _ = fmt.Fprintln(errOut, "usage: xproxyctl apikey add ID [-file PATH] [-scopes a,b] [-expires 90d|2027-01-01T00:00:00Z] [-note TEXT]")
		_, _ = fmt.Fprintln(errOut, "       xproxyctl apikey rotate ID [-file PATH] [-grace 24h]")
		_, _ = fmt.Fprintln(errOut, "       xproxyctl apikey revoke|remove ID [-file PATH]")
		_, _ = fmt.Fprintln(errOut, "       xproxyctl apikey list [-file PATH]")
		return 2
	}
	if len(args) < 1 {
		return usage()
	}
	sub := args[0]
	fs := flag.NewFlagSet("xproxyctl apikey "+sub, flag.ContinueOnError)
	fs.SetOutput(errOut)
	file := fs.String("file", filepath.Join(filepath.Dir(paths.ConfigFile), "api-keys"), "keys file")
	scopes := fs.String("scopes", "", "scopes granted, comma separated")
	expires := fs.String("expires", "", "expiry: a duration (90d, 720h) or an RFC 3339 time; default never")
	note := fs.String("note", "", "free text (owner, ticket)")
	grace := fs.Duration("grace", 24*time.Hour, "how long the previous secret stays valid after a rotation")
	rest := args[1:]
	id := ""
	if sub != "list" {
		if len(rest) < 1 || strings.HasPrefix(rest[0], "-") {
			return usage()
		}
		id, rest = rest[0], rest[1:]
	}
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	fail := func(err error) int {
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	switch sub {
	case "add":
		var exp time.Time
		if *expires != "" {
			if t, err := time.Parse(time.RFC3339, *expires); err == nil {
				exp = t
			} else if d, err := parseDays(*expires); err == nil {
				exp = time.Now().Add(d)
			} else {
				return fail(fmt.Errorf("expires: %q is neither a duration nor an RFC 3339 time", *expires))
			}
		}
		var sc []string
		for _, s := range strings.Split(*scopes, ",") {
			if s = strings.TrimSpace(s); s != "" {
				sc = append(sc, s)
			}
		}
		plain, err := apikey.Add(*file, id, sc, exp, *note)
		if err != nil {
			return fail(err)
		}
		_, _ = fmt.Fprintf(out, "%s\n", plain)
		_, _ = fmt.Fprintf(errOut, "key %s added to %s; the plaintext above is shown once and never stored\n", id, *file)
		return 0
	case "rotate":
		plain, err := apikey.Rotate(*file, id, *grace)
		if err != nil {
			return fail(err)
		}
		_, _ = fmt.Fprintf(out, "%s\n", plain)
		_, _ = fmt.Fprintf(errOut, "key %s rotated; the previous secret works for %s\n", id, grace.String())
		return 0
	case "revoke":
		if err := apikey.Revoke(*file, id); err != nil {
			return fail(err)
		}
		_, _ = fmt.Fprintf(out, "key %s revoked\n", id)
		return 0
	case "remove":
		if err := apikey.Remove(*file, id); err != nil {
			return fail(err)
		}
		_, _ = fmt.Fprintf(out, "key %s removed\n", id)
		return 0
	case "list":
		keys, err := apikey.Load(*file)
		if err != nil {
			return fail(err)
		}
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "ID\tSTATE\tEXPIRES\tSCOPES\tPREVIOUS-UNTIL\tCREATED\tNOTE")
		for _, k := range keys {
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", k.ID, k.State, timeOrNever(k.Expires), dash(strings.Join(k.Scopes, ",")), timeOrNever(k.PrevUntil), timeOrNever(k.Created), dash(k.Note))
		}
		_ = tw.Flush()
		return 0
	}
	return usage()
}

// parseDays parses a Go duration or a number of days ("90d").
func parseDays(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil || n <= 0 {
			return 0, errors.New("bad day count")
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, errors.New("bad duration")
	}
	return d, nil
}

func timeOrNever(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}
