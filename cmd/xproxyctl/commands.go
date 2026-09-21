package main

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// command describes one xproxyctl command for the usage text, the help
// listing and the shell completion scripts.
type command struct {
	name    string
	args    string   // synopsis after the name
	summary string   // one line, no colon
	words   []string // fixed words accepted as the first argument
	flags   []string // flags of the command
	files   bool     // an argument is a file path
}

var commandTable = []command{
	{name: "status", summary: "Version, pid, generation, listeners and counters"},
	{name: "stats", summary: "Counters only"},
	{name: "upstreams", summary: "Endpoints with health, ejection, active requests and error counts"},
	{name: "quotas", args: "[-top N]", summary: "Usage per tenant, route, rate limit policy and upstream", flags: []string{"-top"}},
	{name: "waf", args: "[rules|proposals|anomalies|exclusions|reset] [-top N]", summary: "WAF profiles, rule statistics, learned exclusions, flagged clients", words: []string{"rules", "proposals", "anomalies", "exclusions", "reset"}, flags: []string{"-top"}},
	{name: "sandbox", summary: "In-process hardening state and the file rules in force"},
	{name: "config", summary: "Active configuration as YAML with defaults filled in"},
	{name: "validate", summary: "Validate the configuration file locally"},
	{name: "reload", args: "[-dry-run]", summary: "Validate locally, then reload the daemon; -dry-run shows the changes", flags: []string{"-dry-run"}},
	{name: "diff", args: "[FROM] [TO]", summary: "Compare active, file or a history id; exit 1 when they differ", words: []string{"active", "file"}},
	{name: "history", summary: "Recorded configurations"},
	{name: "rollback", args: "ID", summary: "Apply a recorded configuration"},
	{name: "rotate-secret", args: "[-keep N] FILE", summary: "Add a fresh primary key to a secret file", flags: []string{"-keep"}, files: true},
	{name: "tls", args: "[tickets]", summary: "Served certificates with OCSP and CT state; tickets shows the session ticket keys", words: []string{"tickets"}},
	{name: "reload-certs", summary: "Re-read certificate files"},
	{name: "reopen-logs", summary: "Reopen log files"},
	{name: "tail", args: "STREAM", summary: "Follow the access, error, security or audit log", words: []string{"access", "error", "security", "audit"}},
	{name: "bans", summary: "Active bans"},
	{name: "ban", args: "[-duration D] [-reason TEXT] TARGET", summary: "Ban an address or CIDR", flags: []string{"-duration", "-reason"}},
	{name: "unban", args: "TARGET", summary: "Remove a ban"},
	{name: "cluster", summary: "Peers, connections and gossip counters"},
	{name: "fleet", summary: "Fleet agent state (controller, applied bundle, poll and report counters)"},
	{name: "accounts", args: "[-top N]", summary: "Account guard state (endpoints, active blocks, campaigns, action counters)", flags: []string{"-top"}},
	{name: "botscore", args: "[-top N]", summary: "Learning-mode bot_score baselines and suggested thresholds per route", flags: []string{"-top"}},
	{name: "maintenance", args: "[on|off]", summary: "Show or set maintenance mode", words: []string{"on", "off"}},
	{name: "origin-check", args: "[upstream] [-host H] [-path P]", summary: "Probe origins directly to verify origin-lock is enforced", flags: []string{"-host", "-path"}},
	{name: "acme", args: "[renew]", summary: "Managed certificates; renew forces renewal", words: []string{"renew"}},
	{name: "icap", summary: "ICAP services with reachability and counters"},
	{name: "filters", summary: "Registered filter kinds and configured filters"},
	{name: "geoip", summary: "Country database and lookup counters"},
	{name: "cache", args: "[purge [HOST [PATH-PREFIX]]]", summary: "Response cache counters; purge removes entries", words: []string{"purge"}},
	{name: "honeypot", args: "[forget IP]", summary: "Clients marked by honeypot routes", words: []string{"forget"}},
	{name: "patches", summary: "Virtual patches with state, hits and expiry"},
	{name: "capture", args: "[status|start [-duration D]|stop]", summary: "Packet capture of proxied exchanges as pcapng", words: []string{"status", "start", "stop"}, flags: []string{"-duration"}},
	{name: "api", args: "[all|shadow|zombie|versions|documented|undocumented] [-top N] [-openapi [-title T]]", summary: "API inventory discovered from traffic, with shadow, zombie and superseded endpoints, or an OpenAPI skeleton of a view", words: []string{"all", "shadow", "zombie", "versions", "documented", "undocumented"}, flags: []string{"-top", "-openapi", "-title"}},
	{name: "dns", args: "[purge]", summary: "DNS listener counters; purge empties the caches", words: []string{"purge"}},
	{name: "ingress", summary: "Kubernetes ingress controller status"},
	{name: "otlp", summary: "OpenTelemetry metrics exporter status"},
	{name: "telemetry", summary: "Every OpenTelemetry exporter with counters"},
	{name: "htpasswd", args: "FILE NAME", summary: "Add or replace a basic_auth user (password on stdin)", files: true},
	{name: "apikey", args: "add|rotate|revoke|remove|list [ID] [-file PATH] [-scopes a,b] [-expires 90d] [-note TEXT] [-grace 24h]", summary: "Manage api_key filter keys (issue, rotate with grace, revoke, remove, list)", words: []string{"add", "rotate", "revoke", "remove", "list"}, flags: []string{"-file", "-scopes", "-expires", "-note", "-grace"}, files: true},
	{name: "spki", args: "CERT.pem", summary: "Print the spki_pins value of a certificate", files: true},
	{name: "metrics", summary: "Print the Prometheus exposition"},
	{name: "series", args: "[-since D] [-last N]", summary: "Print sampled series", flags: []string{"-since", "-last"}},
	{name: "tui", args: "[-refresh D] [-no-color]", summary: "Full-screen live view", flags: []string{"-refresh", "-no-color"}},
	{name: "schema", summary: "Print the JSON schema of the configuration"},
	{name: "completion", args: "bash|zsh|fish", summary: "Print a shell completion script for xproxyctl and xproxy", words: []string{"bash", "zsh", "fish"}},
	{name: "help", summary: "List the commands"},
	{name: "version", summary: "Print version"},
}

func commandNames() []string {
	names := make([]string, 0, len(commandTable))
	for _, c := range commandTable {
		names = append(names, c.name)
	}
	return names
}

func usage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "usage: xproxyctl [-socket PATH] [-config PATH] [-json] COMMAND")
	_, _ = fmt.Fprintln(w, "commands:", strings.Join(commandNames(), " "))
	_, _ = fmt.Fprintln(w, "xproxyctl help lists them with a summary; see xproxyctl(8)")
}

func help(w io.Writer) {
	_, _ = fmt.Fprintln(w, "usage: xproxyctl [-socket PATH] [-config PATH] [-json] COMMAND [ARGS]")
	_, _ = fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	for _, c := range commandTable {
		_, _ = fmt.Fprintf(tw, "  %s %s\t%s\n", c.name, c.args, c.summary)
	}
	_ = tw.Flush()
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "-json switches the status views to machine readable output.")
}
