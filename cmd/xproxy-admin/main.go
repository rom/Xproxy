// Command xproxy-admin is the web GUI for xproxy. It is a separate process
// that serves embedded static assets on a loopback address, a Unix socket
// or a mutual TLS listener, authenticates viewers and operators from a
// users file, and forwards every action to the management socket.
//
// Usage:
//
//	xproxy-admin serve [-listen 127.0.0.1:8443] [-socket PATH] [-config PATH] [-users PATH]
//	                   [-tls-cert PATH -tls-key PATH [-client-ca PATH]] [-restart-cmd "systemctl restart xproxy.service"]
//	xproxy-admin user add NAME -role viewer|operator [-cert-only]
//	xproxy-admin user del NAME
//	xproxy-admin user list
//	xproxy-admin passwd NAME
//	xproxy-admin version
//
// Passwords are read from the terminal without echo, or from standard
// input when it is not a terminal (one line).
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/rom/xproxy/internal/admin"
	_ "github.com/rom/xproxy/internal/filters" // built-in filter kinds
	"github.com/rom/xproxy/internal/version"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func usage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "usage: xproxy-admin serve|user|passwd|version [flags]")
}

func run(args []string, in io.Reader, out, errOut io.Writer) int {
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
		_, _ = fmt.Fprintln(out, "xproxy-admin", version.String())
		return 0
	case "serve":
		return serve(args[1:], errOut, fail)
	case "user":
		return user(args[1:], in, out, errOut, fail)
	case "passwd":
		return passwd(args[1:], in, out, errOut, fail)
	default:
		usage(errOut)
		return 2
	}
}

func serve(args []string, errOut io.Writer, fail func(error) int) int {
	fs := flag.NewFlagSet("xproxy-admin serve", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var o admin.Options
	fs.StringVar(&o.Listen, "listen", "127.0.0.1:8443", "listen address (host:port or unix:/path); non-loopback needs -tls-cert, -tls-key and -client-ca")
	fs.StringVar(&o.Socket, "socket", "/run/xproxy/mgmt.sock", "management socket of the data plane")
	fs.StringVar(&o.ConfigFile, "config", "/etc/xproxy/xproxy.yaml", "data plane configuration file (edited by operators; empty disables editing and logs)")
	fs.StringVar(&o.UsersFile, "users", "/etc/xproxy/admin-users", "users file")
	fs.StringVar(&o.TLS.CertFile, "tls-cert", "", "server certificate (PEM)")
	fs.StringVar(&o.TLS.KeyFile, "tls-key", "", "server key (PEM)")
	fs.StringVar(&o.TLS.ClientCAFile, "client-ca", "", "require client certificates from this CA; the common name logs the user in")
	restart := fs.String("restart-cmd", "", `command for the restart action, without a shell (for example "systemctl restart xproxy.service"); empty disables it`)
	fs.DurationVar(&o.SessionIdle, "session-idle", 30*time.Minute, "session idle timeout")
	fs.DurationVar(&o.SessionMax, "session-max", 12*time.Hour, "session absolute lifetime")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *restart != "" {
		o.RestartCommand = strings.Fields(*restart)
	}
	s, err := admin.New(o)
	if err != nil {
		return fail(err)
	}
	if err := s.Start(); err != nil {
		return fail(err)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		return fail(err)
	}
	return 0
}

func user(args []string, in io.Reader, out, errOut io.Writer, fail func(error) int) int {
	if len(args) < 1 {
		_, _ = fmt.Fprintln(errOut, "usage: xproxy-admin user add|del|list [NAME] [-users PATH] [-role viewer|operator] [-cert-only]")
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("xproxy-admin user "+sub, flag.ContinueOnError)
	fs.SetOutput(errOut)
	path := fs.String("users", "/etc/xproxy/admin-users", "users file")
	role := fs.String("role", "viewer", "viewer or operator")
	certOnly := fs.Bool("cert-only", false, "no password; the user logs in with a client certificate")
	rest := args[1:]
	name := ""
	if sub != "list" {
		if len(rest) < 1 || strings.HasPrefix(rest[0], "-") {
			_, _ = fmt.Fprintln(errOut, "error: user name required")
			return 2
		}
		name, rest = rest[0], rest[1:]
	}
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	users, err := admin.LoadUsers(*path)
	if err != nil {
		return fail(err)
	}
	switch sub {
	case "list":
		for _, u := range users.List() {
			full, _ := users.Lookup(u.Name)
			kind := "password"
			if full.CertOnly() {
				kind = "certificate"
			}
			_, _ = fmt.Fprintf(out, "%s\t%s\t%s\n", u.Name, u.Role, kind)
		}
		return 0
	case "add":
		r, err := admin.ParseRole(*role)
		if err != nil {
			return fail(err)
		}
		hash := "x509"
		if !*certOnly {
			pw, err := readPassword(in, out, true)
			if err != nil {
				return fail(err)
			}
			if hash, err = admin.HashPassword(pw); err != nil {
				return fail(err)
			}
		}
		if err := users.Set(admin.User{Name: name, Role: r, Hash: hash}); err != nil {
			return fail(err)
		}
		_, _ = fmt.Fprintf(out, "user %s (%s) written to %s\n", name, r, *path)
		return 0
	case "del":
		if err := users.Delete(name); err != nil {
			return fail(err)
		}
		_, _ = fmt.Fprintf(out, "user %s removed\n", name)
		return 0
	}
	_, _ = fmt.Fprintln(errOut, "error: unknown subcommand", sub)
	return 2
}

func passwd(args []string, in io.Reader, out, errOut io.Writer, fail func(error) int) int {
	fs := flag.NewFlagSet("xproxy-admin passwd", flag.ContinueOnError)
	fs.SetOutput(errOut)
	path := fs.String("users", "/etc/xproxy/admin-users", "users file")
	if len(args) < 1 || strings.HasPrefix(args[0], "-") {
		_, _ = fmt.Fprintln(errOut, "error: user name required")
		return 2
	}
	name := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	users, err := admin.LoadUsers(*path)
	if err != nil {
		return fail(err)
	}
	u, ok := users.Lookup(name)
	if !ok {
		return fail(fmt.Errorf("no user %q", name))
	}
	pw, err := readPassword(in, out, true)
	if err != nil {
		return fail(err)
	}
	hash, err := admin.HashPassword(pw)
	if err != nil {
		return fail(err)
	}
	u.Hash = hash
	if err := users.Set(u); err != nil {
		return fail(err)
	}
	_, _ = fmt.Fprintf(out, "password of %s updated; existing sessions end at the next restart of xproxy-admin\n", name)
	return 0
}

// readPassword prompts on a terminal (twice when confirm is set) or reads
// one line from a non-terminal stdin.
func readPassword(in io.Reader, out io.Writer, confirm bool) (string, error) {
	if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		_, _ = fmt.Fprint(out, "Password: ")
		b, err := term.ReadPassword(int(f.Fd()))
		_, _ = fmt.Fprintln(out)
		if err != nil {
			return "", err
		}
		if confirm {
			_, _ = fmt.Fprint(out, "Repeat: ")
			c, err := term.ReadPassword(int(f.Fd()))
			_, _ = fmt.Fprintln(out)
			if err != nil {
				return "", err
			}
			if string(b) != string(c) {
				return "", errors.New("passwords do not match")
			}
		}
		return string(b), nil
	}
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return "", errors.New("empty password")
	}
	return line, nil
}
