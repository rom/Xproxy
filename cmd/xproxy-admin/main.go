// Command xproxy-admin is the web GUI for xproxy. It is a separate process
// that serves embedded static assets on a loopback address, a Unix socket
// or a mutual TLS listener, authenticates viewers and operators from a
// users file, and forwards every action to the management socket.
//
// Usage:
//
//	xproxy-admin serve [-listen 127.0.0.1:8443] [-socket PATH] [-config PATH] [-users PATH]
//	                   [-tls-cert PATH -tls-key PATH [-client-ca PATH]] [-restart-cmd "systemctl restart xproxy.service"]
//	xproxy-admin serve -validate
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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/rom/xproxy/internal/admin"
	_ "github.com/rom/xproxy/internal/filters" // built-in filter kinds
	"github.com/rom/xproxy/internal/paths"
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
		return serve(args[1:], out, errOut, fail)
	case "user":
		return user(args[1:], in, out, errOut, fail)
	case "passwd":
		return passwd(args[1:], in, out, errOut, fail)
	default:
		usage(errOut)
		return 2
	}
}

func serve(args []string, out, errOut io.Writer, fail func(error) int) int {
	fs := flag.NewFlagSet("xproxy-admin serve", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var o admin.Options
	fs.StringVar(&o.Listen, "listen", "127.0.0.1:8443", "listen address (host:port or unix:/path); non-loopback needs -tls-cert, -tls-key and -client-ca")
	fs.StringVar(&o.Socket, "socket", paths.Socket, "management socket of the data plane")
	fs.StringVar(&o.ConfigFile, "config", paths.ConfigFile, "data plane configuration file (edited by operators; empty disables editing and logs)")
	fs.StringVar(&o.UsersFile, "users", paths.UsersFile, "users file")
	fs.StringVar(&o.TLS.CertFile, "tls-cert", "", "server certificate (PEM)")
	fs.StringVar(&o.TLS.KeyFile, "tls-key", "", "server key (PEM)")
	fs.StringVar(&o.TLS.ClientCAFile, "client-ca", "", "require client certificates from this CA; the common name logs the user in")
	restart := fs.String("restart-cmd", "", `command for the restart action, without a shell (for example "systemctl restart xproxy.service"); empty disables it`)
	fs.DurationVar(&o.SessionIdle, "session-idle", 30*time.Minute, "session idle timeout")
	fs.DurationVar(&o.SessionMax, "session-max", 12*time.Hour, "session absolute lifetime")
	var oidc admin.OIDCOptions
	fs.StringVar(&oidc.Issuer, "oidc-issuer", "", "OpenID Connect issuer URL; enables single sign-on")
	fs.StringVar(&oidc.ClientID, "oidc-client-id", "", "OIDC client id")
	fs.StringVar(&oidc.ClientSecretFile, "oidc-client-secret-file", "", "file holding the OIDC client secret")
	fs.StringVar(&oidc.ExternalURL, "oidc-external-url", "", "address users reach the GUI at, for the redirect URI (default: from the request)")
	fs.StringVar(&oidc.CAFile, "oidc-ca", "", "CA that signs the provider's certificate (default: system pool)")
	scopes := fs.String("oidc-scopes", "openid,profile,email", "scopes requested, comma separated")
	fs.StringVar(&oidc.UserClaim, "oidc-user-claim", "email", "ID token claim that names the user")
	fs.StringVar(&oidc.RoleClaim, "oidc-role-claim", "groups", "ID token claim matched against -oidc-operators and -oidc-viewers")
	operators := fs.String("oidc-operators", "", "role claim values that grant the operator role, comma separated")
	viewers := fs.String("oidc-viewers", "", `role claim values that grant the viewer role, comma separated ("*" accepts every user)`)
	check := fs.Bool("validate", false, "check the options, the users file, the certificates and the restart command, then exit without binding")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *restart != "" {
		o.RestartCommand = strings.Fields(*restart)
	}
	if oidc.Issuer != "" {
		oidc.Scopes = splitList(*scopes)
		oidc.Operators = splitList(*operators)
		oidc.Viewers = splitList(*viewers)
		o.OIDC = &oidc
	}
	s, err := admin.New(o)
	if err != nil {
		return fail(err)
	}
	if *check {
		if err := validate(o, out); err != nil {
			return fail(err)
		}
		return 0
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

// validate checks everything the GUI needs before it binds anything, and says
// what it found.
//
// admin.New has already settled the options against each other -- a non-loopback
// address without mutual TLS, a certificate without a key, a users file that
// will not parse. What it does not do is touch the files: a certificate and key
// that do not pair, a client CA that is not a certificate, a configuration file
// the GUI cannot read, or a restart command that is not on the system are all
// found at the first use rather than at start-up, and the first use of the
// restart command is an operator pressing the button during an incident.
//
// So this loads each of them. It is the same shape as `xsigner -validate`, for
// the same reason: the GUI is the one process here that an operator reaches for
// when something is already wrong.
func validate(o admin.Options, out io.Writer) error {
	users, err := admin.LoadUsers(o.UsersFile)
	if err != nil {
		return err
	}
	var operators, viewers, certOnly int
	for _, u := range users.List() {
		switch u.Role {
		case admin.RoleOperator:
			operators++
		case admin.RoleViewer:
			viewers++
		}
		if u.CertOnly() {
			certOnly++
		}
	}
	if o.TLS.CertFile != "" {
		if _, err := tls.LoadX509KeyPair(o.TLS.CertFile, o.TLS.KeyFile); err != nil {
			return fmt.Errorf("tls: %w", err)
		}
	}
	if o.TLS.ClientCAFile != "" {
		pem, err := os.ReadFile(o.TLS.ClientCAFile)
		if err != nil {
			return fmt.Errorf("client CA: %w", err)
		}
		if !x509.NewCertPool().AppendCertsFromPEM(pem) {
			return fmt.Errorf("client CA: %s holds no certificate", o.TLS.ClientCAFile)
		}
	}
	// The configuration file is read, not validated: the data plane owns that
	// decision and says so through the management socket. What matters here is
	// whether this process can read the file it offers to edit.
	if o.ConfigFile != "" {
		if _, err := os.ReadFile(o.ConfigFile); err != nil {
			return fmt.Errorf("config: %w", err)
		}
	}
	if len(o.RestartCommand) > 0 {
		if _, err := exec.LookPath(o.RestartCommand[0]); err != nil {
			return fmt.Errorf("restart-cmd: %w", err)
		}
	}
	_, _ = fmt.Fprintf(out, "%s: OK (%d users: %d operator, %d viewer, %d certificate only)\n",
		o.UsersFile, len(users.List()), operators, viewers, certOnly)
	what := "password"
	if o.TLS.ClientCAFile != "" {
		what = "password and client certificate"
	}
	if o.OIDC.Enabled() {
		what += " and single sign-on"
	}
	_, _ = fmt.Fprintf(out, "%s: %s, login by %s\n", o.Listen, tlsState(o), what)
	if o.ConfigFile == "" {
		_, _ = fmt.Fprintln(out, "  warning: no -config, so the GUI cannot edit the configuration or show the logs")
	}
	if len(o.RestartCommand) == 0 {
		_, _ = fmt.Fprintln(out, "  note: no -restart-cmd, so the restart action is disabled")
	}
	return nil
}

func tlsState(o admin.Options) string {
	switch {
	case o.TLS.ClientCAFile != "":
		return "mutual TLS"
	case o.TLS.CertFile != "":
		return "TLS"
	case strings.HasPrefix(o.Listen, "unix:"):
		return "a Unix socket"
	default:
		return "plaintext on the loopback"
	}
}

func user(args []string, in io.Reader, out, errOut io.Writer, fail func(error) int) int {
	if len(args) < 1 {
		_, _ = fmt.Fprintln(errOut, "usage: xproxy-admin user add|del|list [NAME] [-users PATH] [-role viewer|operator] [-cert-only]")
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("xproxy-admin user "+sub, flag.ContinueOnError)
	fs.SetOutput(errOut)
	path := fs.String("users", paths.UsersFile, "users file")
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
	path := fs.String("users", paths.UsersFile, "users file")
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

// splitList splits a comma separated flag value, dropping empty items.
func splitList(v string) []string {
	var out []string
	for _, x := range strings.Split(v, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}
