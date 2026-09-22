// Package daemon is the body of xproxy, xgate and xrelay.
//
// The three programs differ in exactly two ways: the listener kinds they
// link, and the role they serve. Everything else -- loading the
// configuration, the sandbox, the management socket, the metrics
// listener, the fleet agent, history and rollback, the signal handling
// and the systemd protocol -- is one implementation here, so a change to
// how a daemon starts is a change in one place rather than three.
//
// A daemon reads a configuration that describes the whole estate. It
// validates all of it, which is what lets one file (or one set of
// includes) be shared: a listener kind a sibling serves is checked as
// carefully here as at home, so a mistake in the gate's SSH policy is
// caught by whichever daemon reloads first. It binds only the listeners
// its own role owns, and says in the log which ones it left to whom.
package daemon

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/rom/xproxy/internal/config"
	_ "github.com/rom/xproxy/internal/filters" // built-in filter kinds
	"github.com/rom/xproxy/internal/fleet"
	"github.com/rom/xproxy/internal/ingress"
	"github.com/rom/xproxy/internal/listener"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/metrics"
	"github.com/rom/xproxy/internal/mgmt"
	"github.com/rom/xproxy/internal/paths"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/sandbox"
	"github.com/rom/xproxy/internal/version"
)

// Run is a daemon's main. role picks the listener kinds this binary
// serves, and names it in messages and defaults.
func Run(role listener.Role, args []string) int {
	prog := role.Daemon()
	fs := flag.NewFlagSet(prog, flag.ContinueOnError)
	cfgPath := fs.String("config", paths.ConfigFileFor(prog), "configuration file")
	validate := fs.Bool("validate", false, "validate the configuration and exit")
	allowRoot := fs.Bool("allow-root", false, "start even when the effective user is root (the shipped unit does not need this)")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Println(prog, version.String())
		return 0
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if *validate {
		// Validation covers the whole file, siblings' listeners
		// included, and says how much of it this daemon would bind.
		mine, theirs := split(role, cfg)
		fmt.Printf("%s: OK (%d listeners, %d served by %s, %d left to a sibling, %d upstreams, %d routes)\n",
			*cfgPath, len(cfg.Server.Listeners), mine, prog, theirs, len(cfg.Upstreams), len(cfg.Routes))
		for _, a := range cfg.Advice() {
			fmt.Printf("  warning: %s\n", a)
		}
		return 0
	}

	logging.Version = version.Version
	logs, err := logging.Open(cfg.Logging)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer logs.Close()
	slog.SetDefault(logs.Error)
	logs.Error.Info("starting", "version", version.String(), "config", *cfgPath, "pid", os.Getpid(), "uid", os.Getuid(),
		"kinds", strings.Join(proxy.Registered(), ","))
	// A warning nobody reads is not a control. The shipped unit runs as
	// its own user with socket activation for the privileged ports, so
	// root is a mistake rather than a requirement; an operator who means
	// it says so on the command line.
	if os.Getuid() == 0 && !*allowRoot {
		logs.Security.Error("refusing to run as root: use systemd socket activation and a dedicated user, or pass -allow-root")
		fmt.Fprintf(os.Stderr, "%s: refusing to run as root; use socket activation and User=%s, or pass -allow-root\n", prog, prog)
		return 1
	}
	if os.Getuid() == 0 {
		logs.Security.Warn("running as root because -allow-root was given; the shipped unit does not need it")
	}
	// Configurations that load but weaken the deployment are said out
	// loud at every start, not only by the validate command.
	for _, a := range cfg.Advice() {
		logs.Security.Warn("configuration advice", "advice", a)
	}

	// From here on the configuration is this daemon's share of the file.
	cfg = own(role, cfg, logs)

	// Ingress controller mode: the running configuration is the file plus
	// what the cluster's Ingress resources translate to.
	var ctrl *ingress.Controller
	var reload func() error
	effective := func(c *config.Config) (*config.Config, error) {
		if ctrl == nil {
			return c, nil
		}
		snap, certs := ctrl.Snapshot()
		return ingress.Merge(c, snap, certs)
	}
	if cfg.Ingress != nil && cfg.Ingress.Enabled {
		c, err := ingress.New(*cfg.Ingress, logs.Error, func() { _ = reload() })
		if err != nil {
			logs.Error.Error("ingress controller failed", "err", err.Error())
			return 1
		}
		ctrl = c
		ctx, cancel := context.WithTimeout(context.Background(), cfg.Ingress.Timeout.D()*4)
		if _, err := ctrl.Sync(ctx); err != nil {
			logs.Error.Warn("initial ingress sync failed; serving the file configuration until the API answers", "err", err.Error())
		}
		cancel()
		merged, err := effective(cfg)
		if err != nil {
			logs.Error.Error("ingress merge failed", "err", err.Error())
			return 1
		}
		cfg = merged
	}

	srv, err := proxy.New(cfg, logs)
	if err != nil {
		logs.Error.Error("initialisation failed", "err", err.Error())
		return 1
	}
	if err := srv.Start(); err != nil {
		logs.Error.Error("start failed", "err", err.Error())
		return 1
	}
	if ctrl != nil {
		ctrl.Start()
		defer ctrl.Stop()
	}

	// Configuration history: every applied generation is recorded so that
	// it can be listed, compared and rolled back.
	var history *config.History
	if dir := cfg.Management.HistoryDir; dir != "" {
		h, err := config.NewHistory(dir, cfg.Management.HistoryKeep)
		if err != nil {
			logs.Error.Warn("configuration history disabled", "err", err.Error())
		} else {
			history = h
		}
	}
	record := func(c *config.Config, note string) {
		if history == nil {
			return
		}
		if _, err := history.Record(c, srv.Generation(), *cfgPath, note); err != nil {
			logs.Error.Warn("configuration history write failed", "err", err.Error())
		}
	}
	record(cfg, "start")

	// sb is the sandbox status once applied; a reload must stay within
	// its file system rules.
	var sb *sandbox.Status
	// candidate loads the file the way a reload would, without applying it.
	candidate := func() (*config.Config, error) {
		c, err := config.Load(*cfgPath)
		if err != nil {
			return nil, err
		}
		c = own(role, c, nil)
		c, err = effective(c)
		if err != nil {
			return nil, err
		}
		if err := sb.Check(c, *cfgPath); err != nil {
			return nil, err
		}
		return c, nil
	}
	apply := func(c *config.Config, note string) error {
		if err := srv.Reload(c); err != nil {
			logs.Error.Error("reload failed", "err", err.Error())
			return err
		}
		record(c, note)
		return nil
	}
	reload = func() error {
		c, err := candidate()
		if err != nil {
			logs.Error.Error("reload rejected", "err", err.Error())
			return err
		}
		return apply(c, "reload")
	}
	reopen := func() error { logs.Reopen(); logs.Audit.Info("logs reopened"); return nil }
	// resolve names a configuration for diff: the running one, the file on
	// disk, or a history entry.
	resolve := func(name string) (*config.Config, error) {
		switch name {
		case "active", "":
			return srv.Config(), nil
		case "file":
			return candidate()
		}
		if history == nil {
			return nil, config.ErrNoHistory
		}
		c, _, err := history.Load(name)
		return c, err
	}

	actions := mgmt.Actions{
		Reload:      reload,
		ReloadCerts: srv.ReloadCertificates,
		ReopenLogs:  reopen,
		DryRun: func() (*config.Changes, error) {
			c, err := candidate()
			if err != nil {
				return nil, err
			}
			return config.Diff(srv.Config(), c, "active", "file"), nil
		},
		Diff: func(from, to string) (*config.Changes, error) {
			a, err := resolve(from)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", from, err)
			}
			b, err := resolve(to)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", to, err)
			}
			return config.Diff(a, b, from, to), nil
		},
		History: func() ([]config.Entry, error) {
			if history == nil {
				return nil, config.ErrNoHistory
			}
			return history.List()
		},
		Rollback: func(id string) error {
			if history == nil {
				return config.ErrNoHistory
			}
			c, _, err := history.Load(id)
			if err != nil {
				logs.Error.Error("rollback rejected", "id", id, "err", err.Error())
				return err
			}
			// The same sandbox check a reload gets: an old configuration
			// naming files outside the Landlock rules is refused cleanly
			// rather than failing half way through the apply.
			if err := sb.Check(c, *cfgPath); err != nil {
				logs.Error.Error("rollback rejected", "id", id, "err", err.Error())
				return err
			}
			return apply(c, "rollback "+id)
		},
	}
	if ctrl != nil {
		actions.Ingress = func() any { return ctrl.Status() }
	}
	actions.Sandbox = func() *sandbox.Status { return sb }
	if cfg.Fleet != nil {
		ag, err := fleet.NewAgent(*cfg.Fleet, *cfgPath, fleet.Hooks{Apply: reload, Status: func() fleet.NodeStatus { return nodeStatus(srv, sb) }}, logs.Error)
		if err != nil {
			logs.Error.Error("fleet agent failed", "err", err.Error())
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = srv.Shutdown(ctx)
			return 1
		}
		ag.Start()
		defer ag.Stop()
		actions.Fleet = func() any { return ag.Status() }
	}
	var otlp *metrics.OTLPExporter
	if o := cfg.Metrics.OTLP; o != nil {
		ex, err := metrics.NewOTLPExporter(metrics.OTLPConfig{Endpoint: o.Endpoint, Interval: o.Interval.D(), Timeout: o.Timeout.D(), Headers: o.Headers,
			CAFile: o.CAFile, ServiceName: o.ServiceName, Attributes: o.Attributes, Compress: *o.Compress, Version: version.Version},
			srv.Collect, logs.Error.With("component", "otlp"))
		if err != nil {
			logs.Error.Error("otlp exporter failed", "err", err.Error())
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = srv.Shutdown(ctx)
			return 1
		}
		otlp = ex
		otlp.Start()
		defer otlp.Stop()
		actions.OTLP = otlp.Status
	}
	m := mgmt.New(cfg.Management, srv, logs, actions)
	if err := m.Start(); err != nil {
		logs.Error.Error("management start failed", "err", err.Error())
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		return 1
	}
	ml, err := mgmt.NewMetricsListener(cfg.Metrics, srv, logs)
	if err == nil {
		err = ml.Start()
	}
	if err != nil {
		logs.Error.Error("metrics listener failed", "err", err.Error())
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = m.Shutdown(ctx)
		_ = srv.Shutdown(ctx)
		return 1
	}
	// Everything is open: confine the process. The sandbox is the last
	// step before READY so that a strict failure is a failed start, not a
	// running daemon with fewer controls than configured.
	sb, err = sandbox.Apply(cfg, *cfgPath, logs.Security)
	if err != nil {
		logs.Error.Error("sandbox failed", "err", err.Error())
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = m.Shutdown(ctx)
		_ = ml.Shutdown(ctx)
		_ = srv.Shutdown(ctx)
		return 1
	}
	sdNotify("READY=1")

	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGTERM, syscall.SIGINT)
	for sig := range sigs {
		switch sig {
		case syscall.SIGHUP:
			// Type=notify-reload requires the monotonic time stamp.
			sdNotify(fmt.Sprintf("RELOADING=1\nMONOTONIC_USEC=%d", monotonicUSec()))
			_ = reload()
			sdNotify("READY=1")
		case syscall.SIGUSR1:
			_ = reopen()
		default:
			sdNotify("STOPPING=1")
			logs.Error.Info("shutting down", "signal", sig.String())
			ctx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout.D())
			defer cancel()
			_ = m.Shutdown(ctx)
			_ = ml.Shutdown(ctx)
			if err := srv.Shutdown(ctx); err != nil {
				logs.Error.Warn("shutdown incomplete", "err", err.Error())
				return 1
			}
			logs.Error.Info("stopped")
			return 0
		}
	}
	return 0
}

// sdNotify sends a systemd notification if NOTIFY_SOCKET is set.
func sdNotify(state string) {
	path := os.Getenv("NOTIFY_SOCKET")
	if path == "" {
		return
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	_, _ = conn.Write([]byte(state))
}

// nodeStatus summarises the node for the fleet controller.
func nodeStatus(srv *proxy.Server, sb *sandbox.Status) fleet.NodeStatus {
	sn := srv.Stats()
	st := fleet.NodeStatus{Version: version.Version, Uptime: sn.UptimeSeconds, Generation: srv.Generation(),
		Requests: sn.Requests, Responses5xx: sn.Responses5xx, OpenConnections: sn.OpenConnections, InFlight: sn.InFlight, BansActive: sn.BansActive}
	st.Denied = sn.DeniedACL + sn.DeniedRateLimit + sn.DeniedConcurrency + sn.DeniedBodySize + sn.DeniedURILength + sn.DeniedNoRoute +
		sn.DeniedBadHost + sn.DeniedBan + sn.DeniedWAF + sn.DeniedJWT + sn.DeniedICAP + sn.DeniedFilter + sn.DeniedGeo
	for _, eps := range srv.Upstreams() {
		st.UpstreamsTotal++
		healthy := 0
		for _, ep := range eps {
			st.EndpointsTotal++
			if ep.Healthy && !ep.Ejected {
				healthy++
			}
		}
		st.EndpointsHealthy += healthy
		if healthy > 0 {
			st.UpstreamsHealthy++
		}
	}
	for _, certs := range srv.Certificates() {
		for _, c := range certs {
			if !c.NotAfter.IsZero() && (st.CertExpiry.IsZero() || c.NotAfter.Before(st.CertExpiry)) {
				st.CertExpiry = c.NotAfter
			}
		}
	}
	if sb != nil {
		if sb.Enabled {
			st.Sandbox = "enabled"
		} else {
			st.Sandbox = "disabled"
		}
	}
	return st
}

// split counts the listeners a role serves and the ones it leaves to a
// sibling.
func split(role listener.Role, cfg *config.Config) (mine, theirs int) {
	for _, lc := range cfg.Server.Listeners {
		if role.Serves(lc.Kind) {
			mine++
		} else {
			theirs++
		}
	}
	return mine, theirs
}

// own returns the configuration this daemon serves: the same file with
// the listeners of other roles taken out.
//
// They are taken out rather than refused. The whole file is validated,
// so a shared estate configuration is checked in full by every daemon
// that reads it; what a daemon will not do is bind a socket for a
// protocol whose code it did not link. Which listeners went where is
// said in the log, because "my SSH bastion is not answering" should be
// a question the log has already answered.
func own(role listener.Role, cfg *config.Config, logs *logging.Logs) *config.Config {
	kept := make([]config.Listener, 0, len(cfg.Server.Listeners))
	left := make([]string, 0, len(cfg.Server.Listeners))
	for _, lc := range cfg.Server.Listeners {
		if role.Serves(lc.Kind) {
			kept = append(kept, lc)
			continue
		}
		owner, _ := listener.RoleOf(lc.Kind)
		left = append(left, lc.Name+" (kind "+lc.Kind+", "+owner.Daemon()+")")
	}
	if len(left) == 0 {
		return cfg
	}
	out := *cfg
	out.Server.Listeners = kept
	if logs != nil {
		logs.Error.Info("listeners left to a sibling daemon",
			"count", len(left), "listeners", strings.Join(left, ", "))
	}
	return &out
}
