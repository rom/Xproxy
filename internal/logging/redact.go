package logging

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"strings"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/secret"
)

// Redactor rewrites personal data in log attributes before any sink sees
// them (AMR-014). It is a pure function of the configuration plus, for hash
// mode, a per-installation key, so the same client yields the same
// pseudonym across restarts and nodes that share the key file.
type Redactor struct {
	clientIP  string
	userAgent string
	referer   string
	claims    string
	drop      map[string]bool
	key       []byte
}

// NewRedactor builds a redactor; it loads or creates the hash key when
// needed.
func NewRedactor(cfg *config.Redaction) (*Redactor, error) {
	r := &Redactor{clientIP: cfg.ClientIP, userAgent: cfg.UserAgent, referer: cfg.Referer, claims: cfg.Claims, drop: map[string]bool{}}
	for _, f := range cfg.DropFields {
		r.drop[f] = true
	}
	if cfg.ClientIP == "hash" || cfg.Claims == "hash" {
		k, err := loadOrCreateKey(cfg.HashSecretFile)
		if err != nil {
			return nil, err
		}
		r.key = k
	}
	return r, nil
}

// loadOrCreateKey returns the primary key of the hash secret (a raw key
// or a keyring). Only the primary is used: a pseudonym must be stable, so
// rotating this secret starts a new series of pseudonyms.
func loadOrCreateKey(path string) ([]byte, error) {
	ring, err := secret.LoadOrCreate(path)
	if err != nil {
		return nil, fmt.Errorf("redaction hash secret: %w", err)
	}
	return ring.Primary(), nil
}

func (r *Redactor) hash(s string) string {
	m := hmac.New(sha256.New, r.key)
	m.Write([]byte(s))
	return "h:" + hex.EncodeToString(m.Sum(nil)[:8])
}

// TruncateIP masks an address to its /24 (IPv4) or /48 (IPv6) prefix.
func TruncateIP(s string) string {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return "?"
	}
	a = a.Unmap()
	bits := 24
	if a.Is6() {
		bits = 48
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return "?"
	}
	return p.Masked().Addr().String() + "/" + fmt.Sprint(bits)
}

// ClientAddress applies the client_ip rule to an address outside a log
// attribute. The trace exporter uses it: a span's client.address is not
// a log line, so nothing took it through the redactor, and a deployment
// that turned redaction on to pseudonymise addresses still shipped the
// full address to its trace collector — next to a trace id the access
// log also carries, which reverses the pseudonymisation by design.
func (r *Redactor) ClientAddress(s string) string {
	if r == nil {
		return s
	}
	switch r.clientIP {
	case "truncate":
		return TruncateIP(s)
	case "hash":
		return r.hash(s)
	}
	return s
}

// Attr applies the rules to one attribute. It returns the attribute to log
// and false when the attribute must be dropped.
func (r *Redactor) Attr(a slog.Attr) (slog.Attr, bool) {
	key := a.Key
	if r.drop[key] {
		return a, false
	}
	switch {
	case key == "client_ip":
		switch r.clientIP {
		case "truncate":
			return slog.String(key, TruncateIP(a.Value.String())), true
		case "hash":
			return slog.String(key, r.hash(a.Value.String())), true
		}
	case key == "user_agent":
		if r.userAgent == "drop" {
			return a, false
		}
	case key == "referer":
		switch r.referer {
		case "drop":
			return a, false
		case "origin":
			v := a.Value.String()
			if v == "" {
				return a, true
			}
			if u, err := url.Parse(v); err == nil && u.Scheme != "" && u.Host != "" {
				return slog.String(key, u.Scheme+"://"+u.Host), true
			}
			return slog.String(key, "?"), true
		}
	// Every attribute that names a person, not just the JWT ones. The
	// setting exists so a deployment can pseudonymise identities; the
	// basic and LDAP user name, the OIDC subject and the API key id are
	// identities too, and they sat in the clear next to a hashed or
	// truncated address on the same line.
	case strings.HasPrefix(key, "jwt_") && key != "jwt_provider",
		strings.HasPrefix(key, "oidc_") && key != "oidc_provider" && key != "oidc_filter",
		key == "client_cn", key == "auth_user", key == "api_key", key == "basic_user":
		switch r.claims {
		case "drop":
			return a, false
		case "hash":
			return slog.String(key, r.hash(a.Value.String())), true
		}
	}
	return a, true
}

// redactHandler applies a Redactor to every record before delegating.
type redactHandler struct {
	next slog.Handler
	r    *Redactor
}

// WithRedaction wraps h so that records pass through r first.
func WithRedaction(h slog.Handler, r *Redactor) slog.Handler {
	if r == nil {
		return h
	}
	return &redactHandler{next: h, r: r}
}

func (h *redactHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.next.Enabled(ctx, l)
}

func (h *redactHandler) Handle(ctx context.Context, rec slog.Record) error {
	out := slog.NewRecord(rec.Time, rec.Level, rec.Message, rec.PC)
	rec.Attrs(func(a slog.Attr) bool {
		if a2, ok := h.r.Attr(a); ok {
			out.AddAttrs(a2)
		}
		return true
	})
	return h.next.Handle(ctx, out)
}

func (h *redactHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	kept := make([]slog.Attr, 0, len(attrs))
	for _, a := range attrs {
		if a2, ok := h.r.Attr(a); ok {
			kept = append(kept, a2)
		}
	}
	return &redactHandler{next: h.next.WithAttrs(kept), r: h.r}
}

func (h *redactHandler) WithGroup(name string) slog.Handler {
	return &redactHandler{next: h.next.WithGroup(name), r: h.r}
}
