// Command xsigner holds private keys so that the proxies do not have to.
//
// It listens on a Unix socket and answers signature requests: the proxy sends a
// digest and gets a signature back, and the key never crosses the socket. What
// that buys is custody -- anything that can read the proxy's memory, a core dump,
// a debugger, a read primitive in a bug, gets nothing, because there is nothing
// there to get. An attacker who owns the proxy can ask for signatures while they
// own it, which is bounded in time; walking away with the key is not.
//
// It is also where cgo belongs. A PKCS#11 module is a vendor C library and the
// daemons are built with CGO_ENABLED=0 on purpose, so an HSM, a TPM or a
// smartcard is reached from here rather than from the thing that terminates TLS
// for the estate. This build serves keys it can read as PEM -- from a file, the
// environment or a vault; the protocol is documented in docs/SIGNER.md so that a
// helper for anything else can be written in whatever language the device has
// bindings for.
//
// Usage:
//
//	xsigner -config /etc/xproxy/xsigner.yaml
//	xsigner -config file.yaml -validate
//	xsigner -config file.yaml -print-keys   # the public keys that loaded
//	xsigner -version
//
// Signals: SIGTERM and SIGINT shut down; a signature in flight fails rather than
// holding the shutdown, because a handshake waiting on a socket has already lost.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/rom/xproxy/internal/keysource"
	"github.com/rom/xproxy/internal/signerd"
	"github.com/rom/xproxy/internal/unixsock"
	xversion "github.com/rom/xproxy/internal/version"
	"gopkg.in/yaml.v3"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("xsigner", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var (
		cfgPath   = fs.String("config", "/etc/xproxy/xsigner.yaml", "configuration file")
		validate  = fs.Bool("validate", false, "check the configuration and the keys, then exit")
		printKeys = fs.Bool("print-keys", false, "print the public key of each key that loaded, then exit")
		version   = fs.Bool("version", false, "print the version and exit")
	)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *version {
		_, _ = fmt.Fprintln(out, xversion.String())
		return 0
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "xsigner: %v\n", err)
		return 1
	}
	keys, err := cfg.load()
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "xsigner: %v\n", err)
		return 1
	}
	if *printKeys {
		return printPublicKeys(out, errOut, keys)
	}
	if *validate {
		names := make([]string, 0, len(keys))
		for _, k := range keys {
			names = append(names, k.Name)
		}
		sort.Strings(names)
		_, _ = fmt.Fprintf(out, "xsigner: %s is valid; %d key(s): %s\n", *cfgPath, len(keys), strings.Join(names, ", "))
		return 0
	}

	log := slog.New(slog.NewJSONHandler(errOut, &slog.HandlerOptions{Level: slog.LevelInfo}))
	srv, err := signerd.New(keys, log)
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "xsigner: %v\n", err)
		return 1
	}
	// The handler goes on before the socket: a signal that arrives while the
	// socket is being bound would otherwise kill the process by default, and
	// with the socket already in the file system that leaves a path the next
	// start has to reason about.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(stop)

	ln, err := unixsock.Listen(cfg.Socket, cfg.mode())
	if err != nil {
		_, _ = fmt.Fprintf(errOut, "xsigner: %v\n", err)
		return 1
	}
	names := srv.Names()
	sort.Strings(names)
	log.Info("xsigner listening", "socket", cfg.Socket, "mode", fmt.Sprintf("%#o", uint32(cfg.mode())),
		"keys", strings.Join(names, ","), "version", xversion.String())

	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := srv.Serve(ln); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Error("the listener stopped", "error", err.Error())
		}
	}()
	sig := <-stop
	log.Info("xsigner shutting down", "signal", sig.String(),
		"signatures", srv.Signatures.Load(), "refusals", srv.Refusals.Load(), "malformed", srv.Malformed.Load())
	_ = ln.Close()
	srv.Close()
	<-done
	return 0
}

// A config is what this helper needs: a socket to listen on and the keys to hold.
//
// It is a file of its own rather than a section of the proxy's configuration
// because the two processes are meant to be separable: this one runs as a
// different user, with its own sandbox, and an operator who can read the proxy's
// configuration should not thereby learn where the keys come from.
type config struct {
	// Socket is the Unix socket to listen on. Absolute.
	Socket string `yaml:"socket"`
	// SocketMode is the socket's permission mode, default 0600. The socket's
	// permissions are the whole authentication here: anything that can
	// connect can have anything signed by these keys, because a digest says
	// nothing about what it is a digest of.
	SocketMode string `yaml:"socket_mode"`
	// Secrets is where a vault: reference resolves from, if any key uses one.
	Secrets *secrets `yaml:"secrets"`
	// Keys are the keys this helper holds.
	Keys []keyConfig `yaml:"keys"`
}

type keyConfig struct {
	// Name is what a request names this key by.
	Name string `yaml:"name"`
	// Key is a reference to the private key in PEM: a path, file:, env: or
	// vault:mount/path#field.
	Key string `yaml:"key"`
}

type secrets struct {
	Vault *vaultConfig `yaml:"vault"`
}

type vaultConfig struct {
	Address    string `yaml:"address"`
	Mount      string `yaml:"mount"`
	KVVersion  int    `yaml:"kv_version"`
	TokenFile  string `yaml:"token_file"`
	TokenEnv   string `yaml:"token_env"`
	Namespace  string `yaml:"namespace"`
	CAFile     string `yaml:"ca_file"`
	ServerName string `yaml:"server_name"`
}

// loadConfig reads and checks the file. Unknown keys are errors, as in the
// proxy's own format: a mistyped key that loaded silently would be a setting an
// operator believes is in force.
func loadConfig(path string) (*config, error) {
	data, err := os.ReadFile(path) //nolint:gosec // the path is this process's own argument
	if err != nil {
		return nil, err
	}
	var c config
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := c.check(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

func (c *config) check() error {
	if !filepath.IsAbs(c.Socket) {
		return errors.New("socket: an absolute path is required")
	}
	if c.SocketMode != "" {
		m, err := parseMode(c.SocketMode)
		if err != nil {
			return fmt.Errorf("socket_mode: %w", err)
		}
		// A socket anything on the machine can write to is a signing oracle
		// for every key this helper holds. It is refused rather than warned
		// about, because there is no deployment where it is right.
		if m&0o002 != 0 {
			return fmt.Errorf("socket_mode: %s is world writable, which makes this a signing oracle for anything on the machine", c.SocketMode)
		}
	}
	if len(c.Keys) == 0 {
		return errors.New("keys: at least one is required")
	}
	seen := map[string]bool{}
	for i, k := range c.Keys {
		name := strings.TrimSpace(k.Name)
		switch {
		case name == "":
			return fmt.Errorf("keys[%d].name: required, because a request names a key", i)
		case seen[name]:
			return fmt.Errorf("keys[%d].name: %q appears twice", i, name)
		case strings.TrimSpace(k.Key) == "":
			return fmt.Errorf("keys[%d].key: required", i)
		}
		seen[name] = true
		ref, err := keysource.Parse(k.Key)
		if err != nil {
			return fmt.Errorf("keys[%d].key: %w", i, err)
		}
		switch {
		case ref.Scheme == keysource.SchemeFile && !filepath.IsAbs(ref.Target):
			return fmt.Errorf("keys[%d].key: %q must be an absolute path", i, ref.Target)
		case ref.Scheme == keysource.SchemeVault && (c.Secrets == nil || c.Secrets.Vault == nil):
			return fmt.Errorf("keys[%d].key: %s is a vault reference and there is no secrets.vault section", i, k.Key)
		}
	}
	if v := vaultOf(c); v != nil {
		if !strings.HasPrefix(v.Address, "https://") {
			// No insecure escape hatch here, unlike the proxy's own vault
			// client: this process exists to hold private keys, and reading
			// them over plain HTTP would undo the reason it exists.
			return errors.New("secrets.vault.address: must be an https:// URL")
		}
		if (v.TokenFile == "") == (v.TokenEnv == "") {
			return errors.New("secrets.vault: exactly one of token_file or token_env")
		}
	}
	return nil
}

func vaultOf(c *config) *vaultConfig {
	if c.Secrets == nil {
		return nil
	}
	return c.Secrets.Vault
}

// mode is the socket's permission mode, 0600 unless the file says otherwise.
func (c *config) mode() os.FileMode {
	if c.SocketMode == "" {
		return 0o600
	}
	m, err := parseMode(c.SocketMode)
	if err != nil {
		return 0o600
	}
	return m
}

// parseMode reads an octal mode as written in a configuration file.
func parseMode(s string) (os.FileMode, error) {
	t := strings.TrimSpace(s)
	if t == "" {
		return 0, errors.New("empty")
	}
	var m uint32
	for _, c := range t {
		if c < '0' || c > '7' {
			return 0, fmt.Errorf("%q is not an octal mode", s)
		}
		m = m*8 + uint32(c-'0')
		if m > 0o777 {
			return 0, fmt.Errorf("%q is not an octal mode", s)
		}
	}
	return os.FileMode(m), nil
}

// load resolves every key reference and parses the material.
//
// Everything is resolved before the socket is bound: a helper that started and
// then could not answer for one of its keys would be found out by a handshake
// rather than by an operator.
func (c *config) load() ([]signerd.Key, error) {
	var vault *keysource.Vault
	if v := vaultOf(c); v != nil {
		ref := ""
		switch {
		case v.TokenEnv != "":
			ref = keysource.SchemeEnv + ":" + v.TokenEnv
		case v.TokenFile != "":
			ref = keysource.SchemeFile + ":" + v.TokenFile
		}
		var err error
		vault, err = keysource.NewVault(keysource.VaultConfig{
			Address: v.Address, Mount: v.Mount, KVVersion: v.KVVersion, TokenRef: ref,
			Namespace: v.Namespace, CAFile: v.CAFile, ServerName: v.ServerName,
		})
		if err != nil {
			return nil, fmt.Errorf("secrets.vault: %w", err)
		}
	}
	// No TTL: this process resolves each key once at start. A rotation is a
	// restart of the helper, which is a different and simpler thing than the
	// proxy's own refresh -- the proxy re-proves the key against the
	// certificate on its next refresh, so a helper restarted with a new key
	// is noticed rather than silently serving the wrong one.
	res := keysource.New(vault, 0, nil)
	out := make([]signerd.Key, 0, len(c.Keys))
	for _, k := range c.Keys {
		pemBytes, err := res.Bytes(k.Key)
		if err != nil {
			return nil, fmt.Errorf("key %q: %w", k.Name, err)
		}
		signer, err := parsePrivateKey(pemBytes)
		if err != nil {
			// The reference is named, never the material.
			return nil, fmt.Errorf("key %q from %s: %w", k.Name, k.Key, err)
		}
		out = append(out, signerd.Key{Name: strings.TrimSpace(k.Name), Signer: signer})
	}
	return out, nil
}

// parsePrivateKey reads the first private key in a PEM, in any of the three
// encodings a key on disk may be in.
func parsePrivateKey(pemBytes []byte) (crypto.Signer, error) {
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, errors.New("no private key in the PEM")
		}
		if !strings.Contains(block.Type, "PRIVATE KEY") {
			continue
		}
		if len(block.Headers) > 0 && block.Headers["Proc-Type"] != "" {
			// An encrypted legacy PEM. Refusing is better than prompting: a
			// helper started by systemd has nowhere to prompt, and a
			// passphrase in the configuration is not a passphrase.
			return nil, errors.New("the key is encrypted; decrypt it, or keep it in a vault instead")
		}
		key, err := parseDER(block.Type, block.Bytes)
		if err != nil {
			return nil, err
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("a %T cannot sign", key)
		}
		return signer, nil
	}
}

func parseDER(typ string, der []byte) (any, error) {
	switch typ {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(der)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(der)
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(der)
	}
	// An unusual label, so try each in turn rather than refusing: what
	// matters is whether the bytes parse.
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	return nil, fmt.Errorf("a %q block is not a private key this build reads", typ)
}

// printPublicKeys writes each key's public half, so that an operator can check
// what this helper loaded against the certificate that will use it.
//
// It is the answer to the one question the protocol cannot answer from the
// proxy's side without a certificate in hand: which key is behind this name.
func printPublicKeys(out, errOut io.Writer, keys []signerd.Key) int {
	sorted := append([]signerd.Key(nil), keys...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	for _, k := range sorted {
		der, err := x509.MarshalPKIXPublicKey(k.Signer.Public())
		if err != nil {
			_, _ = fmt.Fprintf(errOut, "xsigner: key %q: %v\n", k.Name, err)
			return 1
		}
		_, _ = fmt.Fprintf(out, "# %s (%s)\n", k.Name, describe(k.Signer.Public()))
		if err := pem.Encode(out, &pem.Block{Type: "PUBLIC KEY", Bytes: der}); err != nil {
			_, _ = fmt.Fprintf(errOut, "xsigner: %v\n", err)
			return 1
		}
	}
	return 0
}

// describe names a key's type and size, which is what an operator compares
// against the certificate.
func describe(pub crypto.PublicKey) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519"
	}
	return fmt.Sprintf("%T", pub)
}
