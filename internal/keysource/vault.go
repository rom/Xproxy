package keysource

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// HashiCorp Vault, read over its HTTP API.
//
// Only reading a secret is implemented, and deliberately: this proxy is a
// consumer of secrets, not a manager of them. Writing, leases, dynamic
// credentials and the rest belong to whatever provisions the estate; a proxy
// that could write to the vault would be a proxy whose compromise rewrites the
// estate's secrets.
//
// The token comes from a file rather than from this document, for the same
// reason every other credential here does: the configuration is dumped by the
// management API, kept in the history and diffed. A token in the environment is
// accepted because a container runtime often has nowhere else to put one, and
// warned about because the environment of a process is readable by more than
// the process.

// vaultTimeout bounds one read. A vault that is slow must not hold a reload.
const vaultTimeout = 10 * time.Second

// maxVaultBody bounds a response.
const maxVaultBody = 4 << 20

// Vault reads secrets from a Vault server.
type Vault struct {
	addr    string
	mount   string
	kv      int
	client  *http.Client
	tokenMu sync.RWMutex
	token   string
	// tokenRef is where the token came from, so it can be read again when it
	// is rotated underneath the process.
	tokenRef  string
	namespace string
}

// VaultConfig is what a Vault client needs.
type VaultConfig struct {
	// Address is the API base, https unless Insecure.
	Address string
	// Mount is the KV mount used when a reference names none; the default
	// "secret".
	Mount string
	// KVVersion is 2 (the default) or 1. They differ in the request path and
	// in where the fields are in the answer, and guessing between them
	// returns "not found" for a secret that is there.
	KVVersion int
	// TokenRef is a reference (file: or env:) to the token. It is resolved on
	// every failure to read, so a rotated token is picked up without a
	// restart.
	TokenRef string
	// Namespace is the Vault Enterprise namespace header, if any.
	Namespace string
	// CAFile pins the server's authority; empty uses the system pool.
	CAFile string
	// ServerName overrides the name verified in the certificate.
	ServerName string
	// Insecure allows http:// and skips verification. It needs the caller's
	// own opt-in as well; nothing here turns it on by itself.
	Insecure bool
}

// NewVault builds a client and reads the token once, so that a wrong path or an
// unreadable file fails the load rather than the first handshake.
func NewVault(cfg VaultConfig) (*Vault, error) {
	addr := strings.TrimRight(strings.TrimSpace(cfg.Address), "/")
	if addr == "" {
		return nil, errors.New("vault: address is required")
	}
	u, err := url.Parse(addr)
	if err != nil {
		return nil, fmt.Errorf("vault address: %w", err)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !cfg.Insecure {
			return nil, errors.New("vault address: http reads the token and every secret in clear; " +
				"use https, or say insecure: true and mean it")
		}
	default:
		return nil, fmt.Errorf("vault address: scheme %q is not http or https", u.Scheme)
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: cfg.ServerName} //nolint:gosec // TLS 1.2 floor
	if cfg.Insecure {
		tc.InsecureSkipVerify = true //nolint:gosec // the caller opted in explicitly
	}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile) //nolint:gosec // a path from the configuration
		if err != nil {
			return nil, fmt.Errorf("vault ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("vault ca_file %s: no certificate in it", cfg.CAFile)
		}
		tc.RootCAs = pool
	}
	kv := cfg.KVVersion
	if kv == 0 {
		kv = 2
	}
	if kv != 1 && kv != 2 {
		return nil, fmt.Errorf("vault kv_version: %d is not 1 or 2", kv)
	}
	v := &Vault{
		addr: addr, mount: strings.Trim(firstNonEmpty(cfg.Mount, "secret"), "/"), kv: kv,
		tokenRef: cfg.TokenRef, namespace: cfg.Namespace,
		client: &http.Client{
			Timeout: vaultTimeout,
			// No environment proxy: a vault address is reached directly or
			// not at all, and a proxy in the environment of this process is
			// a machine in the middle of every secret it holds.
			Transport: &http.Transport{Proxy: nil, TLSClientConfig: tc,
				MaxIdleConns: 2, IdleConnTimeout: 30 * time.Second},
		},
	}
	if err := v.loadToken(); err != nil {
		return nil, err
	}
	return v, nil
}

// SetClientForTest replaces the HTTP client, for a test with a stub server.
func (v *Vault) SetClientForTest(c *http.Client) { v.client = c }

// loadToken reads the token from its reference.
func (v *Vault) loadToken() error {
	ref, err := Parse(v.tokenRef)
	if err != nil {
		return fmt.Errorf("vault token: %w", err)
	}
	var raw []byte
	switch ref.Scheme {
	case SchemeFile:
		if raw, err = os.ReadFile(ref.Target); err != nil { //nolint:gosec // a path from the configuration
			return fmt.Errorf("vault token %s: %w", ref, err)
		}
	case SchemeEnv:
		s, ok := os.LookupEnv(ref.Target)
		if !ok {
			return fmt.Errorf("vault token %s: the variable is not set", ref)
		}
		raw = []byte(s)
	default:
		return fmt.Errorf("vault token: %s is not a file or env reference", ref)
	}
	t := strings.TrimSpace(string(raw))
	if t == "" {
		return fmt.Errorf("vault token %s: empty", ref)
	}
	v.tokenMu.Lock()
	v.token = t
	v.tokenMu.Unlock()
	return nil
}

// Read fetches one field of one secret.
//
// The path may name a mount of its own ("kv/tls/edge" with mount "kv"), or use
// the configured mount when it does not look like one; the rule is the first
// segment, which is how an operator writes it either way.
func (v *Vault) Read(path, field string) ([]byte, error) {
	body, err := v.get(v.secretURL(path))
	if err != nil {
		// A 403 is usually a token that was rotated underneath the process,
		// so the token is read again and the request retried once. Any more
		// than once and a bad token becomes a loop against somebody else's
		// server.
		if errors.Is(err, errForbidden) && v.loadToken() == nil {
			body, err = v.get(v.secretURL(path))
		}
		if err != nil {
			return nil, err
		}
	}
	var doc struct {
		Data struct {
			Data     map[string]any `json:"data"`
			Metadata struct {
				Version int `json:"version"`
			} `json:"metadata"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("vault %s: answer is not the JSON this API returns: %w", path, err)
	}
	fields := doc.Data.Data
	if v.kv == 1 {
		// KV v1 puts the fields directly under data, so the nested map above
		// is empty and the outer one is what matters. Decoding twice is
		// cheaper than two request paths and two structs.
		var flat struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(body, &flat); err != nil {
			return nil, fmt.Errorf("vault %s: %w", path, err)
		}
		fields = flat.Data
	}
	raw, ok := fields[field]
	if !ok {
		// The available field names are safe to name and the values are not:
		// an operator who wrote the wrong field needs to know which exist.
		return nil, fmt.Errorf("vault %s: no field %q in this secret (it has %s)", path, field, names(fields))
	}
	switch t := raw.(type) {
	case string:
		return []byte(t), nil
	case float64:
		return []byte(strings.TrimSuffix(fmt.Sprintf("%v", t), ".0")), nil
	case bool:
		return []byte(fmt.Sprint(t)), nil
	}
	return nil, fmt.Errorf("vault %s: field %q is not a string", path, field)
}

// errForbidden is a 403 from the vault, which is worth telling apart because it
// is what a rotated token looks like.
var errForbidden = errors.New("vault: forbidden")

// secretURL builds the read URL for a path under the KV version in use.
func (v *Vault) secretURL(path string) string {
	p := strings.Trim(path, "/")
	mount, rest := v.mount, p
	if first, after, ok := strings.Cut(p, "/"); ok && first == v.mount {
		mount, rest = first, after
	}
	if v.kv == 1 {
		return v.addr + "/v1/" + mount + "/" + rest
	}
	return v.addr + "/v1/" + mount + "/data/" + rest
}

// get makes one authenticated request.
func (v *Vault) get(u string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), vaultTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("vault: %w", err)
	}
	v.tokenMu.RLock()
	req.Header.Set("X-Vault-Token", v.token)
	v.tokenMu.RUnlock()
	if v.namespace != "" {
		req.Header.Set("X-Vault-Namespace", v.namespace)
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxVaultBody))
	if err != nil {
		return nil, fmt.Errorf("vault: %w", err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return body, nil
	case http.StatusForbidden:
		return nil, errForbidden
	case http.StatusNotFound:
		// Vault answers 404 both for a path that is not there and for a
		// secret whose latest version was deleted, and the difference
		// matters to whoever is fixing it.
		return nil, fmt.Errorf("vault: %s not found (a wrong path, a wrong kv_version, or a deleted version)", u)
	}
	// The body of an error carries Vault's own messages, which are about
	// policies and paths rather than secret values.
	return nil, fmt.Errorf("vault: %s answered %d: %s", u, resp.StatusCode, clip(body))
}

// names lists a secret's field names for an error message.
func names(fields map[string]any) string {
	out := make([]string, 0, len(fields))
	for k := range fields {
		out = append(out, k)
	}
	if len(out) == 0 {
		return "no fields"
	}
	return strings.Join(out, ", ")
}

// clip bounds an error body so a misdirected request cannot put a megabyte in a
// log line.
func clip(b []byte) string {
	const max = 256
	s := strings.TrimSpace(string(b))
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
