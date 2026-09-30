package main

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/rom/xproxy/internal/attack"
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
	{name: "ready", args: "[-require-upstreams] [-require-undegraded] [-step-down REASON] [-step-up]", summary: "Whether this node should be carrying traffic; exit 0 yes, 1 no, 2 could not ask", flags: []string{"-require-upstreams", "-require-undegraded", "-step-down", "-step-up"}},
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
	{name: "drain", args: "[POOL [ADDRESS]] [-restore]", summary: "Stop new work to an endpoint or a whole pool while what is running finishes; with no argument, what is drained", flags: []string{"-restore"}},
	{name: "origin-check", args: "[upstream] [-host H] [-path P]", summary: "Probe origins directly to verify origin-lock is enforced", flags: []string{"-host", "-path"}},
	{name: "acme", args: "[renew]", summary: "Managed certificates; renew forces renewal", words: []string{"renew"}},
	{name: "icap", summary: "ICAP services with reachability and counters"},
	{name: "filters", summary: "Registered filter kinds and configured filters"},
	{name: "geoip", summary: "Country database and lookup counters"},
	{name: "cache", args: "[purge [HOST [PATH-PREFIX]]]", summary: "Response cache counters; purge removes entries", words: []string{"purge"}},
	{name: "honeypot", args: "[forget IP]", summary: "Clients marked by honeypot routes", words: []string{"forget"}},
	{name: "patches", summary: "Virtual patches with state, hits and expiry"},
	{name: "correlation", summary: "The cross-listener window -- how much of it is in use, what its bounds have pushed out, and what cluster peers have contributed"},
	{name: "techniques", args: "[-catalogue]", summary: "What the refusals meant in MITRE ATT&CK for ICS terms, most seen first; -catalogue lists every technique this proxy can observe, seen or not", flags: []string{"-catalogue"}},
	{name: "policy", args: "[report|reset] [-top N]", summary: "What the listeners in shadow mode would have refused, most frequent first; reset empties the ledger", words: []string{"report", "reset"}, flags: []string{"-top"}},
	{name: "assets", args: "[-role R] [-listener L] [-proto P] [-vendor V] [-new] [-changed] [-top N] [-long] | show KEY | baseline [-forget] | advisories [-state S] [-documents] [-long]", summary: "The devices this proxy has seen, what it thinks each one is, the baseline of what the estate is supposed to have, and what the vendors' published advisories say about the firmware each one reports", words: []string{"show", "baseline", "advisories"}, flags: []string{"-role", "-listener", "-proto", "-vendor", "-new", "-changed", "-top", "-long", "-forget", "-state", "-documents"}},
	{name: "access", args: "[-state S] | show ID | ask -subject NAME -listener L -target T -reason WHY -for 2h [-uses N] | approve|deny|revoke ID [-note TEXT] [-by NAME]", summary: "Just-in-time access -- the grants a gate listener admits sessions against, and asking for, approving, refusing or withdrawing one", words: []string{"show", "ask", "approve", "deny", "revoke"}, flags: []string{"-state", "-subject", "-listener", "-target", "-reason", "-for", "-start", "-uses", "-by", "-note"}},
	{name: "sessions", args: "[-kill ID] [-kill-matching -kind K -listener L -user U]", summary: "List the sessions this daemon is serving now, and close one or a set of them", flags: []string{"-kill", "-kill-matching", "-kind", "-listener", "-user"}},
	{name: "session", args: "list DIR | show [-safe] [-input] FILE | play [-speed N] [-plain] FILE", summary: "Read a recorded gate session back, with the escape sequences that reach outside the window taken out", words: []string{"list", "show", "play"}, flags: []string{"-safe", "-input", "-speed", "-plain"}, files: true},
	{name: "capture", args: "[status|start [-duration D]|stop]", summary: "Packet capture of proxied exchanges as pcapng", words: []string{"status", "start", "stop"}, flags: []string{"-duration"}},
	{name: "api", args: "[all|shadow|zombie|versions|documented|undocumented] [-top N] [-openapi [-title T]]", summary: "API inventory discovered from traffic, with shadow, zombie and superseded endpoints, or an OpenAPI skeleton of a view", words: []string{"all", "shadow", "zombie", "versions", "documented", "undocumented"}, flags: []string{"-top", "-openapi", "-title"}},
	{name: "dns", args: "[purge]", summary: "DNS listener counters; purge empties the caches", words: []string{"purge"}},
	{name: "ingress", summary: "Kubernetes ingress controller status"},
	{name: "otlp", summary: "OpenTelemetry metrics exporter status"},
	{name: "telemetry", summary: "Every OpenTelemetry exporter with counters"},
	{name: "htpasswd", args: "FILE NAME", summary: "Add or replace a basic_auth user (password on stdin)", files: true},
	{name: "apikey", args: "add|rotate|revoke|remove|list [ID] [-file PATH] [-scopes a,b] [-expires 90d] [-note TEXT] [-grace 24h]", summary: "Manage api_key filter keys (issue, rotate with grace, revoke, remove, list)", words: []string{"add", "rotate", "revoke", "remove", "list"}, flags: []string{"-file", "-scopes", "-expires", "-note", "-grace"}, files: true},
	{name: "spki", args: "CERT.pem", summary: "Print the spki_pins value of a certificate, and the same key as a coap public_keys fingerprint", files: true},
	{name: "mfa", args: "enrol -user NAME [-issuer NAME] [-recovery N] | verify -file F -user NAME -code CODE | list -file F", summary: "Second factor enrolment, verification and listing", words: []string{"enrol", "verify", "list"}, flags: []string{"-user", "-issuer", "-digits", "-period", "-algo", "-recovery", "-file", "-code", "-skew"}, files: true},
	{name: "ech", args: "keygen -public-name NAME [-id N] [-dir D] | show CONFIG... | record [-name NAME] [-ttl N] CONFIG...", summary: "Encrypted Client Hello keys and the HTTPS record to publish", words: []string{"keygen", "show", "record"}, flags: []string{"-public-name", "-id", "-dir", "-name", "-ttl"}, files: true},
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

// techniqueRow is one line of the techniques view: what was seen, and
// what it is called where an operations centre catalogues it.
type techniqueRow struct {
	ID     string `json:"technique"`
	Name   string `json:"name"`
	Tactic string `json:"tactic"`
	Count  uint64 `json:"count"`
	Why    string `json:"why,omitempty"`
}

// techniqueRows orders what a daemon reported. Most seen first, because
// that is the question an operator has; the catalogue form is by
// identifier, because that is a list rather than a ranking.
func techniqueRows(seen map[string]uint64, catalogue bool) []techniqueRow {
	if catalogue {
		out := make([]techniqueRow, 0, len(attack.All()))
		for _, t := range attack.All() {
			out = append(out, techniqueRow{ID: t.ID, Name: t.Name,
				Tactic: string(t.Tactic()), Count: seen[t.ID], Why: t.Why})
		}
		return out
	}
	out := make([]techniqueRow, 0, len(seen))
	for id, n := range seen {
		t, ok := attack.Get(id)
		if !ok {
			// A daemon of another version reporting a technique this
			// binary does not know: shown rather than dropped, because
			// the count is real and hiding it would be worse than an
			// empty name.
			out = append(out, techniqueRow{ID: id, Count: n})
			continue
		}
		out = append(out, techniqueRow{ID: t.ID, Name: t.Name,
			Tactic: string(t.Tactic()), Count: n, Why: t.Why})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].ID < out[j].ID
	})
	return out
}
