// Command xproxy is the data plane daemon.
//
// Usage:
//
//	xproxy -config /etc/xproxy/xproxy.yaml
//	xproxy -config file.yaml -validate
//	xproxy -version
//
// Signals: SIGHUP reloads the configuration, SIGUSR1 reopens log files,
// SIGTERM and SIGINT shut down gracefully.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/mgmt"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/version"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("xproxy", flag.ContinueOnError)
	cfgPath := fs.String("config", "/etc/xproxy/xproxy.yaml", "configuration file")
	validate := fs.Bool("validate", false, "validate the configuration and exit")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Println("xproxy", version.String())
		return 0
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if *validate {
		fmt.Printf("%s: OK (%d listeners, %d upstreams, %d routes)\n", *cfgPath, len(cfg.Server.Listeners), len(cfg.Upstreams), len(cfg.Routes))
		return 0
	}

	logs, err := logging.Open(cfg.Logging)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer logs.Close()
	logs.Error.Info("starting", "version", version.String(), "config", *cfgPath, "pid", os.Getpid(), "uid", os.Getuid())
	if os.Getuid() == 0 {
		logs.Security.Warn("running as root; use systemd socket activation and a dedicated user instead")
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

	reload := func() error {
		c, err := config.Load(*cfgPath)
		if err != nil {
			logs.Error.Error("reload rejected", "err", err.Error())
			return err
		}
		if err := srv.Reload(c); err != nil {
			logs.Error.Error("reload failed", "err", err.Error())
			return err
		}
		return nil
	}
	reopen := func() error { logs.Reopen(); logs.Audit.Info("logs reopened"); return nil }

	m := mgmt.New(cfg.Management, srv, logs, mgmt.Actions{
		Reload:      reload,
		ReloadCerts: srv.ReloadCertificates,
		ReopenLogs:  reopen,
	})
	if err := m.Start(); err != nil {
		logs.Error.Error("management start failed", "err", err.Error())
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		return 1
	}
	sdNotify("READY=1")

	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGHUP, syscall.SIGUSR1, syscall.SIGTERM, syscall.SIGINT)
	for sig := range sigs {
		switch sig {
		case syscall.SIGHUP:
			sdNotify("RELOADING=1")
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
