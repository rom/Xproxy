// Package acme obtains and renews certificates from an ACME CA (RFC 8555)
// on the standard library (docs/AMR.md, AMR-029). Supported: ES256 account
// keys, http-01 and tls-alpn-01 challenges, ECDSA P-256 certificate keys,
// persisted account and certificates, renewal on a timer.
package acme

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/acme/jose"
)

// Limits on CA responses.
const (
	maxResponseBytes = 1 << 20
	maxNonces        = 16
	pollAttempts     = 30
)

// Client talks to one ACME directory with one account key.
type Client struct {
	directoryURL string
	http         *http.Client
	key          *ecdsa.PrivateKey
	kid          string

	mu     sync.Mutex
	dir    *Directory
	nonces []string
}

// Directory is the ACME directory document.
type Directory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
	RevokeCert string `json:"revokeCert"`
	Meta       struct {
		TermsOfService string `json:"termsOfService"`
	} `json:"meta"`
}

// Problem is an RFC 7807 error from the CA.
type Problem struct {
	Type   string `json:"type"`
	Detail string `json:"detail"`
	Status int    `json:"status"`
}

func (p *Problem) Error() string { return fmt.Sprintf("acme: %s (%s)", p.Detail, p.Type) }

// Order is an ACME order.
type Order struct {
	URL            string
	Status         string       `json:"status"`
	Identifiers    []Identifier `json:"identifiers"`
	Authorizations []string     `json:"authorizations"`
	Finalize       string       `json:"finalize"`
	Certificate    string       `json:"certificate"`
	Error          *Problem     `json:"error"`
}

// Identifier is an order identifier.
type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Authorization is an ACME authorization.
type Authorization struct {
	Identifier Identifier  `json:"identifier"`
	Status     string      `json:"status"`
	Challenges []Challenge `json:"challenges"`
	Wildcard   bool        `json:"wildcard"`
}

// Challenge is one challenge of an authorization.
type Challenge struct {
	Type   string   `json:"type"`
	URL    string   `json:"url"`
	Token  string   `json:"token"`
	Status string   `json:"status"`
	Error  *Problem `json:"error"`
}

// NewClient creates a client. caFile optionally pins the directory
// server's CA (for private CAs and tests).
func NewClient(directoryURL, caFile string, key *ecdsa.PrivateKey) (*Client, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile) //nolint:gosec // validated configuration path
		if err != nil {
			return nil, fmt.Errorf("acme ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("acme ca file contains no certificates")
		}
		tc.RootCAs = pool
	}
	return &Client{
		directoryURL: directoryURL,
		key:          key,
		http: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
			TLSClientConfig: tc, Proxy: nil, MaxIdleConns: 4, ResponseHeaderTimeout: 20 * time.Second, DisableCompression: true,
		}},
	}, nil
}

// SetKID sets the account URL (after registration or from storage).
func (c *Client) SetKID(kid string) { c.kid = kid }

// KID returns the account URL.
func (c *Client) KID() string { return c.kid }

// Directory fetches and caches the directory.
func (c *Client) Directory(ctx context.Context) (*Directory, error) {
	c.mu.Lock()
	if c.dir != nil {
		d := c.dir
		c.mu.Unlock()
		return d, nil
	}
	c.mu.Unlock()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.directoryURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "xproxy-acme/1")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("acme directory: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var d Directory
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&d); err != nil {
		return nil, fmt.Errorf("acme directory: %w", err)
	}
	if d.NewNonce == "" || d.NewAccount == "" || d.NewOrder == "" {
		return nil, errors.New("acme directory is incomplete")
	}
	c.mu.Lock()
	c.dir = &d
	c.mu.Unlock()
	return &d, nil
}

func (c *Client) nonce(ctx context.Context) (string, error) {
	c.mu.Lock()
	if n := len(c.nonces); n > 0 {
		v := c.nonces[n-1]
		c.nonces = c.nonces[:n-1]
		c.mu.Unlock()
		return v, nil
	}
	c.mu.Unlock()
	d, err := c.Directory(ctx)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, d.NewNonce, http.NoBody)
	if err != nil {
		return "", err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("acme nonce: %w", err)
	}
	_ = resp.Body.Close()
	n := resp.Header.Get("Replay-Nonce")
	if n == "" {
		return "", errors.New("acme: no nonce in response")
	}
	return n, nil
}

func (c *Client) storeNonce(h http.Header) {
	if n := h.Get("Replay-Nonce"); n != "" {
		c.mu.Lock()
		if len(c.nonces) < maxNonces {
			c.nonces = append(c.nonces, n)
		}
		c.mu.Unlock()
	}
}

// post sends a signed request. payload nil means POST-as-GET. A badNonce
// problem is retried once with a fresh nonce.
func (c *Client) post(ctx context.Context, url string, payload []byte, out any) (http.Header, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		nonce, err := c.nonce(ctx)
		if err != nil {
			return nil, err
		}
		body, err := jose.Sign(c.key, c.kid, nonce, url, payload)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/jose+json")
		req.Header.Set("User-Agent", "xproxy-acme/1")
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, fmt.Errorf("acme post %s: %w", url, err)
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
		_ = resp.Body.Close()
		if err != nil {
			return nil, err
		}
		c.storeNonce(resp.Header)
		if resp.StatusCode >= 400 {
			p := &Problem{Status: resp.StatusCode, Detail: http.StatusText(resp.StatusCode)}
			_ = json.Unmarshal(data, p)
			if p.Type == "urn:ietf:params:acme:error:badNonce" && attempt == 0 {
				lastErr = p
				continue
			}
			return resp.Header, p
		}
		if out != nil {
			switch o := out.(type) {
			case *[]byte:
				*o = data
			default:
				if len(data) > 0 {
					if err := json.Unmarshal(data, out); err != nil {
						return resp.Header, fmt.Errorf("acme: bad response from %s: %w", url, err)
					}
				}
			}
		}
		return resp.Header, nil
	}
	return nil, lastErr
}

// Register creates or finds the account and stores its URL.
func (c *Client) Register(ctx context.Context, email string) error {
	d, err := c.Directory(ctx)
	if err != nil {
		return err
	}
	payload := map[string]any{"termsOfServiceAgreed": true}
	if email != "" {
		payload["contact"] = []string{"mailto:" + email}
	}
	pb, _ := json.Marshal(payload)
	c.kid = ""
	h, err := c.post(ctx, d.NewAccount, pb, nil)
	if err != nil {
		return err
	}
	loc := h.Get("Location")
	if loc == "" {
		return errors.New("acme: account response without Location")
	}
	c.kid = loc
	return nil
}

// NewOrder requests a certificate for the identifiers.
func (c *Client) NewOrder(ctx context.Context, hosts []string) (*Order, error) {
	d, err := c.Directory(ctx)
	if err != nil {
		return nil, err
	}
	ids := make([]Identifier, len(hosts))
	for i, h := range hosts {
		ids[i] = Identifier{Type: "dns", Value: h}
	}
	pb, _ := json.Marshal(map[string]any{"identifiers": ids})
	var o Order
	h, err := c.post(ctx, d.NewOrder, pb, &o)
	if err != nil {
		return nil, err
	}
	o.URL = h.Get("Location")
	return &o, nil
}

// GetOrder fetches an order.
func (c *Client) GetOrder(ctx context.Context, url string) (*Order, error) {
	var o Order
	if _, err := c.post(ctx, url, nil, &o); err != nil {
		return nil, err
	}
	o.URL = url
	return &o, nil
}

// GetAuthorization fetches an authorization.
func (c *Client) GetAuthorization(ctx context.Context, url string) (*Authorization, error) {
	var a Authorization
	if _, err := c.post(ctx, url, nil, &a); err != nil {
		return nil, err
	}
	return &a, nil
}

// Accept tells the CA a challenge is ready for validation.
func (c *Client) Accept(ctx context.Context, ch *Challenge) error {
	_, err := c.post(ctx, ch.URL, []byte("{}"), nil)
	return err
}

// WaitOrder polls until the order reaches one of the statuses.
func (c *Client) WaitOrder(ctx context.Context, url string, statuses ...string) (*Order, error) {
	for i := 0; i < pollAttempts; i++ {
		o, err := c.GetOrder(ctx, url)
		if err != nil {
			return nil, err
		}
		for _, s := range statuses {
			if o.Status == s {
				return o, nil
			}
		}
		if o.Status == "invalid" {
			if o.Error != nil {
				return nil, o.Error
			}
			return nil, errors.New("acme: order invalid")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(pollDelay(i)):
		}
	}
	return nil, errors.New("acme: order did not complete in time")
}

// WaitAuthorization polls until an authorization is valid or fails.
func (c *Client) WaitAuthorization(ctx context.Context, url string) error {
	for i := 0; i < pollAttempts; i++ {
		a, err := c.GetAuthorization(ctx, url)
		if err != nil {
			return err
		}
		switch a.Status {
		case "valid":
			return nil
		case "invalid", "revoked", "expired", "deactivated":
			for _, ch := range a.Challenges {
				if ch.Error != nil {
					return fmt.Errorf("acme: %s challenge for %s failed: %w", ch.Type, a.Identifier.Value, ch.Error)
				}
			}
			return fmt.Errorf("acme: authorization for %s is %s", a.Identifier.Value, a.Status)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pollDelay(i)):
		}
	}
	return errors.New("acme: authorization did not complete in time")
}

func pollDelay(i int) time.Duration {
	d := time.Duration(500+250*i) * time.Millisecond
	if d > 5*time.Second {
		d = 5 * time.Second
	}
	return d
}

// Finalize submits the CSR.
func (c *Client) Finalize(ctx context.Context, o *Order, csrDER []byte) error {
	pb, _ := json.Marshal(map[string]string{"csr": jose.B64(csrDER)})
	_, err := c.post(ctx, o.Finalize, pb, nil)
	return err
}

// Certificate downloads the issued chain (PEM).
func (c *Client) Certificate(ctx context.Context, url string) ([]byte, error) {
	var pem []byte
	if _, err := c.post(ctx, url, nil, &pem); err != nil {
		return nil, err
	}
	if !bytes.Contains(pem, []byte("BEGIN CERTIFICATE")) {
		return nil, errors.New("acme: certificate response is not PEM")
	}
	return pem, nil
}
