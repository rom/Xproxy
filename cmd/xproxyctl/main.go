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
//	reload         validate and apply the configuration file
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
//	htpasswd FILE NAME  add or replace a basic_auth user (password on stdin)
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
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/rom/xproxy/internal/config"
	_ "github.com/rom/xproxy/internal/filters" // built-in filter kinds for validate
	"github.com/rom/xproxy/internal/mgmt"
	"github.com/rom/xproxy/internal/passwd"
	"github.com/rom/xproxy/internal/tlsconf"
	"github.com/rom/xproxy/internal/tui"
	"github.com/rom/xproxy/internal/upstream"
	"github.com/rom/xproxy/internal/version"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func usage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "usage: xproxyctl [-socket PATH] [-config PATH] [-json] COMMAND")
	_, _ = fmt.Fprintln(w, "commands: status stats upstreams config validate reload reload-certs reopen-logs tail bans ban unban cluster acme icap filters geoip htpasswd spki metrics series tui version")
}

func run(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("xproxyctl", flag.ContinueOnError)
	fs.SetOutput(errOut)
	socket := fs.String("socket", "/run/xproxy/mgmt.sock", "management socket")
	cfgPath := fs.String("config", "/etc/xproxy/xproxy.yaml", "configuration file (validate, tail)")
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
		tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "UPSTREAM\tENDPOINT\tWEIGHT\tHEALTHY\tEJECTED\tACTIVE\tREQUESTS\tERRORS")
		names := make([]string, 0, len(ups))
		for n := range ups {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			for _, e := range ups[n] {
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%d\t%v\t%v\t%d\t%d\t%d\n", n, e.Address, e.Weight, e.Healthy, e.Ejected, e.Active, e.Requests, e.Errors)
			}
		}
		_ = tw.Flush()
		return 0
	case "config":
		b, err := c.Raw("/v1/config")
		if err != nil {
			return fail(err)
		}
		_, _ = out.Write(b)
		return 0
	case "reload":
		if _, err := config.Load(*cfgPath); err != nil {
			_, _ = fmt.Fprintln(errOut, "refusing to reload: local validation failed")
			return fail(err)
		}
		if err := c.Post("/v1/reload"); err != nil {
			return fail(err)
		}
		_, _ = fmt.Fprintln(out, "reloaded")
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
	case "geoip":
		var b []byte
		if err := c.Do("GET", "/v1/geoip", nil, &b); err != nil {
			return fail(err)
		}
		_, _ = out.Write(b)
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
