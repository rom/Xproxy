// Command xproxy-fleet is the fleet controller: it serves every node the
// configuration bundle assigned to it and collects the nodes' status.
//
// Usage:
//
//	xproxy-fleet serve -dir DIR -listen ADDR -cert PEM -key PEM -ca PEM [-any-name] [-scan 2s] [-admin-socket PATH]
//	xproxy-fleet nodes [-admin-socket PATH] [-json]
//	xproxy-fleet node ID [-admin-socket PATH] [-json]
//	xproxy-fleet bundle ID [-admin-socket PATH]
//	xproxy-fleet validate [-dir DIR]
//	xproxy-fleet scan [-admin-socket PATH]
//	xproxy-fleet version
//
// The directory holds common/ (files every node receives), nodes/<id>/
// (a node's own files, which override common ones; nodes/<id>/xproxy.yaml
// is the node's configuration) and status/ (the last report per node).
// Editing the files is the push: the controller rescans every -scan
// interval and the agents, which long poll, apply the change within
// seconds. Agents authenticate with a client certificate from -ca whose
// name must equal their node id unless -any-name is given.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"
	"unicode"

	_ "github.com/rom/xproxy/internal/filters" // built-in filter kinds, for validation
	"github.com/rom/xproxy/internal/fleet"
	"github.com/rom/xproxy/internal/version"
)

const defaultDir = "/var/lib/xproxy-fleet"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func usage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "usage: xproxy-fleet serve|nodes|node|bundle|validate|scan|version [flags]")
}

func run(args []string, out, errOut io.Writer) int {
	if len(args) < 1 {
		usage(errOut)
		return 2
	}
	fail := func(err error) int {
		_, _ = fmt.Fprintln(errOut, "error:", err)
		return 1
	}
	switch args[0] {
	case "version", "-version", "--version":
		_, _ = fmt.Fprintln(out, "xproxy-fleet", version.String())
		return 0
	case "serve":
		return serve(args[1:], errOut, fail)
	case "nodes":
		return nodes(args[1:], out, errOut, fail)
	case "node", "bundle":
		return node(args[0], args[1:], out, errOut, fail)
	case "scan":
		return scan(args[1:], out, errOut, fail)
	case "validate":
		return validate(args[1:], out, errOut, fail)
	default:
		usage(errOut)
		return 2
	}
}

func serve(args []string, errOut io.Writer, fail func(error) int) int {
	fs := flag.NewFlagSet("xproxy-fleet serve", flag.ContinueOnError)
	fs.SetOutput(errOut)
	dir := fs.String("dir", defaultDir, "controller directory (common/, nodes/, status/)")
	listen := fs.String("listen", ":8447", "node listener address (mutual TLS)")
	certFile := fs.String("cert", "", "controller certificate (PEM)")
	keyFile := fs.String("key", "", "controller key (PEM)")
	caFile := fs.String("ca", "", "CA that issues the node certificates (PEM)")
	anyName := fs.Bool("any-name", false, "accept any certificate from the CA for any node id; prefer -name-map, and expect a warning on every authorisation while this is on")
	nameMapFile := fs.String("name-map", "", "file of \"node_id certificate_name\" lines: the named certificate may act for that node id, one exception at a time instead of -any-name")
	scan := fs.Duration("scan", 2*time.Second, "how often the directory is rescanned")
	adminSock := fs.String("admin-socket", "", "operator socket for nodes, node, bundle and scan (default DIR/fleet.sock)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *certFile == "" || *keyFile == "" || *caFile == "" {
		return fail(errors.New("-cert, -key and -ca are required"))
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	nameMap, err := readNameMap(*nameMapFile)
	if err != nil {
		return fail(err)
	}
	c, err := fleet.New(*dir, *scan, !*anyName, nameMap, log)
	if err != nil {
		return fail(err)
	}
	tc, err := fleet.ServerTLS(*certFile, *keyFile, *caFile)
	if err != nil {
		return fail(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	lc := &net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", *listen)
	if err != nil {
		return fail(err)
	}
	nodeSrv := &http.Server{Handler: c.NodeHandler(), TLSConfig: tc, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 5 * time.Minute, MaxHeaderBytes: 64 << 10}
	sock := *adminSock
	if sock == "" {
		sock = filepath.Join(c.Dir(), "fleet.sock")
	}
	_ = os.Remove(sock)
	old := syscall.Umask(0o077)
	al, err := lc.Listen(ctx, "unix", sock)
	syscall.Umask(old)
	if err != nil {
		return fail(err)
	}
	if err := os.Chmod(sock, 0o660); err != nil { //nolint:gosec // the operator group uses the socket
		return fail(err)
	}
	adminSrv := &http.Server{Handler: c.AdminHandler(), ReadHeaderTimeout: 10 * time.Second}
	go c.Run(ctx)
	errs := make(chan error, 2)
	go func() { errs <- nodeSrv.ServeTLS(ln, "", "") }()
	go func() { errs <- adminSrv.Serve(al) }()
	log.Info("fleet controller started", "dir", c.Dir(), "listen", ln.Addr().String(), "admin_socket", sock, "version", version.String())
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sig:
	case err := <-errs:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fail(err)
		}
	}
	sctx, scancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer scancel()
	_ = nodeSrv.Shutdown(sctx)
	_ = adminSrv.Shutdown(sctx)
	_ = os.Remove(sock)
	return 0
}

func adminClient(sock string) *http.Client {
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}}}
}

func adminGet(sock, method, path string, out any) error {
	req, err := http.NewRequestWithContext(context.Background(), method, "http://fleet"+path, http.NoBody)
	if err != nil {
		return err
	}
	resp, err := adminClient(sock).Do(req)
	if err != nil {
		return fmt.Errorf("controller socket %s: %w", sock, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode != 200 {
		return fmt.Errorf("controller answered HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if raw, ok := out.(*[]byte); ok {
		*raw = body
		return nil
	}
	return json.Unmarshal(body, out)
}

func adminFlags(name string, args []string, errOut io.Writer) (*string, *bool, error) {
	fs := flag.NewFlagSet("xproxy-fleet "+name, flag.ContinueOnError)
	fs.SetOutput(errOut)
	sock := fs.String("admin-socket", filepath.Join(defaultDir, "fleet.sock"), "controller operator socket")
	asJSON := fs.Bool("json", false, "machine readable output")
	return sock, asJSON, fs.Parse(args)
}

func nodes(args []string, out, errOut io.Writer, fail func(error) int) int {
	sock, asJSON, err := adminFlags("nodes", args, errOut)
	if err != nil {
		return 2
	}
	var ov fleet.Overview
	if err := adminGet(*sock, http.MethodGet, "/v1/fleet/nodes", &ov); err != nil {
		return fail(err)
	}
	if *asJSON {
		b, _ := json.MarshalIndent(ov, "", "  ")
		_, _ = out.Write(append(b, '\n'))
		return 0
	}
	printNodes(out, ov)
	return 0
}

func printNodes(out io.Writer, ov fleet.Overview) {
	_, _ = fmt.Fprintf(out, "directory %s  scans %d", ov.Dir, ov.Scans)
	if ov.ScanError != "" {
		_, _ = fmt.Fprintf(out, "  scan error: %s", ov.ScanError)
	}
	_, _ = fmt.Fprintln(out)
	if len(ov.Nodes) == 0 {
		_, _ = fmt.Fprintln(out, "no nodes: add nodes/<id>/xproxy.yaml under the directory and point an agent at this controller")
		return
	}
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "NODE\tSTATE\tASSIGNED\tAPPLIED\tVERSION\tLAST SEEN\tREQUESTS\t5XX\tDENIED\tUPSTREAMS\tERROR")
	for _, n := range ov.Nodes {
		state := "in sync"
		switch {
		case !n.Seen:
			state = "never seen"
		case n.Stale:
			state = "stale"
		case !n.Assigned:
			state = "unassigned"
		case n.Status.Pending != "":
			state = "pending"
		case !n.Status.Applied.OK && n.Status.Applied.Error != "":
			state = "failed"
		case !n.InSync:
			state = "behind"
		}
		seen := "-"
		if n.Seen {
			seen = time.Since(n.LastSeen).Round(time.Second).String() + " ago"
		}
		errText := n.ScanErr
		if errText == "" && !n.Status.Applied.OK {
			errText = n.Status.Applied.Error
		}
		if len(errText) > 60 {
			errText = errText[:60] + "..."
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%d/%d\t%s\n", n.NodeID, state, dash(short(n.Digest)), dash(short(n.Status.Applied.Digest)),
			dash(n.Status.Version), seen, n.Status.Requests, n.Status.Responses5xx, n.Status.Denied, n.Status.UpstreamsHealthy, n.Status.UpstreamsTotal, dash(errText))
	}
	_ = tw.Flush()
}

func node(what string, args []string, out, errOut io.Writer, fail func(error) int) int {
	if len(args) < 1 || strings.HasPrefix(args[0], "-") {
		_, _ = fmt.Fprintf(errOut, "usage: xproxy-fleet %s ID [-admin-socket PATH] [-json]\n", what)
		return 2
	}
	id := args[0]
	sock, asJSON, err := adminFlags(what, args[1:], errOut)
	if err != nil {
		return 2
	}
	path := "/v1/fleet/nodes/" + url.PathEscape(id)
	if what == "bundle" {
		path += "/bundle"
	}
	var raw []byte
	if err := adminGet(*sock, http.MethodGet, path, &raw); err != nil {
		return fail(err)
	}
	if *asJSON || what == "bundle" {
		var pretty any
		if json.Unmarshal(raw, &pretty) == nil {
			raw, _ = json.MarshalIndent(pretty, "", "  ")
		}
		_, _ = out.Write(append(raw, '\n'))
		return 0
	}
	var n fleet.NodeView
	if err := json.Unmarshal(raw, &n); err != nil {
		return fail(err)
	}
	st := n.Status
	_, _ = fmt.Fprintf(out, "node %s  assigned %s (%d files)  applied %s ok=%v", n.NodeID, dash(short(n.Digest)), n.Files, dash(short(st.Applied.Digest)), st.Applied.OK)
	if st.Applied.Error != "" {
		_, _ = fmt.Fprintf(out, "  error: %s", dash(st.Applied.Error))
	}
	_, _ = fmt.Fprintln(out)
	if n.ScanErr != "" {
		_, _ = fmt.Fprintf(out, "scan error: %s\n", n.ScanErr)
	}
	if !n.Seen {
		_, _ = fmt.Fprintln(out, "never reported")
		return 0
	}
	_, _ = fmt.Fprintf(out, "version %s  host %s  generation %d  uptime %s  last seen %s ago  from %s (%s)  tags %s\n",
		dash(st.Version), dash(st.Hostname), st.Generation, (time.Duration(st.Uptime) * time.Second).String(), time.Since(n.LastSeen).Round(time.Second), dash(n.Remote), dash(n.CertName), dash(strings.Join(st.Tags, ",")))
	_, _ = fmt.Fprintf(out, "requests %d  5xx %d  denied %d  open connections %d  in flight %d  upstreams %d/%d healthy  endpoints %d/%d healthy  bans %d\n",
		st.Requests, st.Responses5xx, st.Denied, st.OpenConnections, st.InFlight, st.UpstreamsHealthy, st.UpstreamsTotal, st.EndpointsHealthy, st.EndpointsTotal, st.BansActive)
	if !st.CertExpiry.IsZero() {
		_, _ = fmt.Fprintf(out, "earliest certificate expiry %s (%s)\n", st.CertExpiry.Format(time.RFC3339), time.Until(st.CertExpiry).Round(time.Hour))
	}
	return 0
}

func scan(args []string, out, errOut io.Writer, fail func(error) int) int {
	sock, asJSON, err := adminFlags("scan", args, errOut)
	if err != nil {
		return 2
	}
	var ov fleet.Overview
	if err := adminGet(*sock, http.MethodPost, "/v1/fleet/scan", &ov); err != nil {
		return fail(err)
	}
	if *asJSON {
		b, _ := json.MarshalIndent(ov, "", "  ")
		_, _ = out.Write(append(b, '\n'))
		return 0
	}
	printNodes(out, ov)
	return 0
}

func validate(args []string, out, errOut io.Writer, fail func(error) int) int {
	fs := flag.NewFlagSet("xproxy-fleet validate", flag.ContinueOnError)
	fs.SetOutput(errOut)
	dir := fs.String("dir", defaultDir, "controller directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	problems, ids, err := fleet.ValidateDir(*dir)
	if err != nil {
		return fail(err)
	}
	for _, id := range ids {
		if p, bad := problems[id]; bad {
			_, _ = fmt.Fprintf(out, "%s: %s\n", id, p)
		} else {
			_, _ = fmt.Fprintf(out, "%s: ok\n", id)
		}
	}
	if len(ids) == 0 {
		_, _ = fmt.Fprintf(out, "no nodes under %s/nodes\n", *dir)
	}
	if len(problems) > 0 {
		_, _ = fmt.Fprintf(errOut, "%d of %d node bundles invalid\n", len(problems), len(ids))
		return 1
	}
	return 0
}

// dash renders a value for the table, or "-" when it is empty.
//
// Everything it prints came from an agent, which is a machine the
// controller does not trust in this direction: a compromised node that
// puts an escape sequence in its host name, version or error would
// otherwise clear the operator's screen, repaint other nodes' rows or
// set the terminal title, and a hundred kilobyte value would push the
// rest of the fleet off the display. The terminal interface was
// hardened for exactly this; the fleet command was not.
func dash(s string) string {
	s = printable(s)
	if s == "" {
		return "-"
	}
	if len(s) > 200 {
		return s[:197] + "..."
	}
	return s
}

// printable drops every rune a terminal would act on rather than show.
func printable(s string) string {
	return strings.Map(func(r rune) rune {
		if r == ' ' || unicode.IsPrint(r) {
			return r
		}
		return -1
	}, s)
}

func short(d string) string {
	if len(d) > 12 {
		return d[:12]
	}
	return d
}

// readNameMap reads the explicit node id to certificate name exceptions:
// one "node_id certificate_name" pair per line, "#" comments and blank
// lines ignored. It exists so a deployment whose certificate names and
// node ids differ can name the exceptions instead of turning the
// binding off for every node with -any-name.
func readNameMap(path string) (map[string]string, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path) //nolint:gosec // an operator supplied path
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for n, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 2 {
			return nil, fmt.Errorf("%s:%d: want \"node_id certificate_name\"", path, n+1)
		}
		out[f[0]] = f[1]
	}
	return out, nil
}
