// Package samlsp is a built-in filter kind that logs browsers in as a
// SAML 2.0 service provider and keeps the result in an encrypted session
// cookie. A request without a session is redirected to the identity
// provider with an authentication request; the provider posts a signed
// response back to the assertion consumer service, which verifies it
// against the configured signing key, checks every window and name in
// it, and sets the cookie. Later requests carry chosen attributes to the
// upstream as headers.
//
//	filters:
//	  - name: sso
//	    kind: saml_sp
//	    options:
//	      entity_id: https://app.example.com/saml/metadata
//	      idp_metadata_file: /etc/xproxy/idp-metadata.xml
//	      cookie_secret_file: /etc/xproxy/saml.cookie   # 32+ bytes, created 0600 if absent
//	      external_url: https://app.example.com
//	      forward_headers: {X-Remote-User: nameid, X-Remote-Email: mail}
//	      groups_attribute: groups
//
// The profile is the one internal/saml implements, and its narrowness is
// deliberate: POST binding for responses, no encrypted assertions, one
// assertion per response, exclusive canonicalization, SHA-256 and above,
// the signing key from the configuration rather than from the document.
package samlsp

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/filter"
	"github.com/rom/xproxy/internal/saml"
	"github.com/rom/xproxy/internal/secret"
)

// Config is the options schema.
type Config struct {
	EntityID         string `json:"entity_id"`
	IDPMetadataFile  string `json:"idp_metadata_file"`
	IDPEntityID      string `json:"idp_entity_id"`
	IDPSSOURL        string `json:"idp_sso_url"`
	IDPCertFile      string `json:"idp_cert_file"`
	CookieSecretFile string `json:"cookie_secret_file"`
	ACSPath          string `json:"acs_path"`
	MetadataPath     string `json:"metadata_path"`
	LogoutPath       string `json:"logout_path"`
	LogoutRedirect   string `json:"logout_redirect"`
	ExternalURL      string `json:"external_url"`
	CookieName       string `json:"cookie_name"`
	CookieDomain     string `json:"cookie_domain"`
	SessionTTL       string `json:"session_ttl"`
	ClockSkew        string `json:"clock_skew"`
	MaxAssertionAge  string `json:"max_assertion_age"`
	// SignedElement says what the signature must cover: the assertion
	// (the default), the response, or either.
	SignedElement string `json:"signed_element"`
	// NameIDFormats are the accepted formats; empty accepts any.
	NameIDFormats []string `json:"name_id_formats"`
	// RequestedNameIDFormat is what the authentication request asks for.
	RequestedNameIDFormat string `json:"request_name_id_format"`
	ForceAuthn            bool   `json:"force_authn"`
	// ForwardHeaders maps a header name to an attribute name, or to one
	// of the assertion's own fields: nameid, nameid_format,
	// session_index.
	ForwardHeaders map[string]string `json:"forward_headers"`
	// RequireAttributes must all be present with these values.
	RequireAttributes map[string]string `json:"require_attributes"`
	// GroupsAttribute carries the groups a policy may decide on.
	GroupsAttribute string `json:"groups_attribute"`
	// PolicyAttributes are recorded on the identity for a policy to read.
	PolicyAttributes []string `json:"policy_attributes"`
	// LogAttributes are copied to the access log as saml_<name>.
	LogAttributes []string `json:"log_attributes"`
	// ReplayMax bounds the one-time table of assertion identifiers.
	ReplayMax int  `json:"replay_max"`
	AllowHTTP bool `json:"allow_http"`

	ttl   time.Duration
	skew  time.Duration
	age   time.Duration
	certs []*x509.Certificate
	keys  []crypto.PublicKey
}

// nameID and its neighbours are the fields of an assertion a header may
// carry beside the attributes.
const (
	fieldNameID       = "nameid"
	fieldNameIDFormat = "nameid_format"
	fieldSessionIndex = "session_index"
)

// maxACSBody bounds the form posted to the assertion consumer service. A
// base64 SAML response at the package's own bound is about 350 KiB; this
// leaves room for the form around it and nothing else.
const maxACSBody = 512 << 10

const (
	stateSuffix = "_state"
	stateTTL    = 10 * time.Minute
	maxCookie   = 4096
)

func parse(opts filter.Options) (*Config, error) {
	var c Config
	if err := opts.Decode(&c); err != nil {
		return nil, err
	}
	var errs []error
	if c.EntityID == "" {
		errs = append(errs, errors.New("entity_id is required: it is the audience every assertion must name"))
	} else if len(c.EntityID) > 1024 {
		errs = append(errs, errors.New("entity_id is longer than 1024 bytes"))
	}
	// The provider can be named field by field or taken from the
	// metadata document it publishes; an explicit field wins, so a
	// metadata file with a stale endpoint can be corrected in place.
	if c.IDPMetadataFile != "" {
		b, err := readBounded(c.IDPMetadataFile)
		if err != nil {
			errs = append(errs, fmt.Errorf("idp_metadata_file: %w", err))
		} else if md, err := saml.ParseIDPMetadata(b); err != nil {
			errs = append(errs, fmt.Errorf("idp_metadata_file: %w", err))
		} else {
			if c.IDPEntityID == "" {
				c.IDPEntityID = md.EntityID
			}
			if c.IDPSSOURL == "" {
				c.IDPSSOURL = md.SSOURL
			}
			if c.IDPCertFile == "" {
				c.certs = md.Certs
			}
		}
	}
	if c.IDPCertFile != "" {
		b, err := readBounded(c.IDPCertFile)
		if err != nil {
			errs = append(errs, fmt.Errorf("idp_cert_file: %w", err))
		} else if certs, err := parseCerts(b); err != nil {
			errs = append(errs, fmt.Errorf("idp_cert_file: %w", err))
		} else {
			c.certs = certs
		}
	}
	if len(c.certs) == 0 {
		errs = append(errs, errors.New("the identity provider's signing certificate is required: set idp_cert_file or idp_metadata_file"))
	}
	for _, cert := range c.certs {
		c.keys = append(c.keys, cert.PublicKey)
	}
	if c.IDPEntityID == "" {
		errs = append(errs, errors.New("idp_entity_id is required: it is the issuer every assertion must name"))
	}
	switch u, err := url.Parse(c.IDPSSOURL); {
	case c.IDPSSOURL == "":
		errs = append(errs, errors.New("idp_sso_url is required"))
	case err != nil || u.Host == "" || !schemeOK(u.Scheme, c.AllowHTTP):
		errs = append(errs, errors.New("idp_sso_url must be an https URL (http only with allow_http)"))
	}
	if c.CookieSecretFile == "" {
		errs = append(errs, errors.New("cookie_secret_file is required"))
	}
	if c.ACSPath == "" {
		c.ACSPath = "/saml/acs"
	}
	if c.MetadataPath == "" {
		c.MetadataPath = "/saml/metadata"
	}
	if c.LogoutPath == "" {
		c.LogoutPath = "/saml/logout"
	}
	for _, p := range []string{c.ACSPath, c.MetadataPath, c.LogoutPath} {
		if !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "?#") {
			errs = append(errs, fmt.Errorf("%q is not a path", p))
		}
	}
	if c.ACSPath == c.MetadataPath || c.ACSPath == c.LogoutPath || c.MetadataPath == c.LogoutPath {
		errs = append(errs, errors.New("acs_path, metadata_path and logout_path must differ"))
	}
	if c.LogoutRedirect == "" {
		c.LogoutRedirect = "/"
	}
	if !strings.HasPrefix(c.LogoutRedirect, "/") || strings.HasPrefix(c.LogoutRedirect, "//") {
		errs = append(errs, errors.New("logout_redirect must be a path on this host"))
	}
	if c.ExternalURL != "" {
		eu, err := url.Parse(c.ExternalURL)
		if err != nil || eu.Host == "" || !schemeOK(eu.Scheme, c.AllowHTTP) || eu.Path != "" || eu.RawQuery != "" {
			errs = append(errs, errors.New("external_url must be scheme://host with no path"))
		}
	}
	if c.CookieName == "" {
		c.CookieName = "XPSAML"
	}
	if strings.ContainsAny(c.CookieName, " ;=\r\n") {
		errs = append(errs, errors.New("cookie_name is not a cookie name"))
	}
	c.ttl = 8 * time.Hour
	if c.SessionTTL != "" {
		d, err := time.ParseDuration(c.SessionTTL)
		if err != nil || d < time.Minute || d > 30*24*time.Hour {
			errs = append(errs, errors.New("session_ttl: must be a duration between 1m and 720h"))
		} else {
			c.ttl = d
		}
	}
	c.skew = 30 * time.Second
	if c.ClockSkew != "" {
		d, err := time.ParseDuration(c.ClockSkew)
		if err != nil || d < 0 || d > 5*time.Minute {
			errs = append(errs, errors.New("clock_skew: must be a duration between 0 and 5m"))
		} else {
			c.skew = d
		}
	}
	c.age = time.Hour
	if c.MaxAssertionAge != "" {
		d, err := time.ParseDuration(c.MaxAssertionAge)
		if err != nil || d < time.Minute || d > 24*time.Hour {
			errs = append(errs, errors.New("max_assertion_age: must be a duration between 1m and 24h"))
		} else {
			c.age = d
		}
	}
	switch c.SignedElement {
	case "":
		c.SignedElement = "assertion"
	case "assertion", "response", "either":
	default:
		errs = append(errs, errors.New("signed_element must be assertion, response or either"))
	}
	for h, name := range c.ForwardHeaders {
		if h == "" || strings.ContainsAny(h, " :\r\n") || name == "" {
			errs = append(errs, fmt.Errorf("forward_headers: %q: %q is not a header and attribute pair", h, name))
		}
	}
	for name := range c.RequireAttributes {
		if name == "" {
			errs = append(errs, errors.New("require_attributes: empty attribute name"))
		}
	}
	if c.GroupsAttribute == "" {
		c.GroupsAttribute = "groups"
	}
	if c.ReplayMax == 0 {
		c.ReplayMax = 65536
	}
	if c.ReplayMax < 1 || c.ReplayMax > 10_000_000 {
		errs = append(errs, errors.New("replay_max: must be between 1 and 10000000"))
	}
	for _, f := range c.NameIDFormats {
		if f == "" {
			errs = append(errs, errors.New("name_id_formats: empty format"))
		}
	}
	return &c, errors.Join(errs...)
}

func schemeOK(scheme string, allowHTTP bool) bool {
	return scheme == "https" || (scheme == "http" && allowHTTP)
}

// readBounded reads a configuration file of at most a megabyte.
func readBounded(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // validated configuration path
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil {
		return nil, err
	}
	if len(b) > 1<<20 {
		return nil, errors.New("larger than 1 MiB")
	}
	return b, nil
}

// parseCerts reads one or more PEM certificates.
func parseCerts(b []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := b
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, cert)
		if len(out) > 8 {
			return nil, errors.New("more than eight certificates")
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no PEM certificate found")
	}
	return out, nil
}

type samlFilter struct {
	name string
	cfg  *Config
	log  *slog.Logger
	aead cipher.AEAD
	// olderAEADs open cookies sealed under keys rotated out of the
	// primary slot.
	olderAEADs []cipher.AEAD
	seen       *saml.Seen

	// counters
	Logins, Logouts, Accepted, Failures, Replays atomic.Uint64
}

func newFilter(name string, c *Config, log *slog.Logger) (*samlFilter, error) {
	ring, err := secret.LoadOrCreate(c.CookieSecretFile)
	if err != nil {
		return nil, fmt.Errorf("cookie secret: %w", err)
	}
	aeads := make([]cipher.AEAD, 0, ring.Len())
	for _, key := range ring.All() {
		digest := sha256.Sum256(key)
		block, err := aes.NewCipher(digest[:])
		if err != nil {
			return nil, err
		}
		a, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		aeads = append(aeads, a)
	}
	now := time.Now()
	for _, cert := range c.certs {
		// A pinned key is its own trust anchor, so an expired
		// certificate around it is not a reason to refuse a signature --
		// but it is a reason to say so, because the provider is about to
		// rotate and nothing else will mention it.
		switch {
		case now.After(cert.NotAfter):
			log.Warn("saml identity provider certificate has expired; its key is still pinned",
				"subject", cert.Subject.String(), "not_after", cert.NotAfter.Format(time.RFC3339))
		case now.Add(30 * 24 * time.Hour).After(cert.NotAfter):
			log.Warn("saml identity provider certificate expires soon",
				"subject", cert.Subject.String(), "not_after", cert.NotAfter.Format(time.RFC3339))
		}
	}
	return &samlFilter{name: name, cfg: c, log: log, aead: aeads[0], olderAEADs: aeads[1:], seen: saml.NewSeen(c.ReplayMax)}, nil
}

func (f *samlFilter) Name() string { return f.name }

func (f *samlFilter) Begin(_ context.Context, info *filter.Info) filter.Instance {
	return &instance{f: f, info: info}
}

type instance struct {
	f    *samlFilter
	info *filter.Info
	user string
	log  []any
}

// session is the encrypted cookie payload.
type session struct {
	NameID string              `json:"n"`
	Format string              `json:"f,omitempty"`
	Index  string              `json:"s,omitempty"`
	Exp    int64               `json:"e"`
	Iat    int64               `json:"i"`
	Attrs  map[string][]string `json:"a,omitempty"`
}

// loginState is the short lived state cookie of a login in progress: the
// identifier of the request this proxy sent, which the response must
// answer, and where the browser was going.
type loginState struct {
	RequestID string `json:"r"`
	Return    string `json:"u"`
	Exp       int64  `json:"e"`
}

func (in *instance) Request(r *http.Request) filter.Verdict {
	f := in.f
	for h := range f.cfg.ForwardHeaders {
		r.Header.Del(h) // never trust a client supplied identity header
	}
	switch r.URL.Path {
	case f.cfg.ACSPath:
		return f.consume(r, in)
	case f.cfg.MetadataPath:
		return f.metadata(r, in)
	case f.cfg.LogoutPath:
		return f.logout(r, in)
	}
	if s, ok := f.session(r); ok {
		in.user = s.NameID
		filter.SetIdentity(r.Context(), "saml", s.NameID)
		filter.SetAttrs(r.Context(), "saml", f.attrsOf(s))
		for h, name := range f.cfg.ForwardHeaders {
			if v := s.value(name); v != "" {
				r.Header.Set(h, v)
			}
		}
		for _, name := range f.cfg.LogAttributes {
			if v := s.value(name); v != "" {
				in.log = append(in.log, "saml_"+name, v)
			}
		}
		f.stripCookies(r)
		return filter.Continue
	}
	return f.login(r, in)
}

// value reads one field or attribute of a session.
func (s *session) value(name string) string {
	switch name {
	case fieldNameID:
		return s.NameID
	case fieldNameIDFormat:
		return s.Format
	case fieldSessionIndex:
		return s.Index
	}
	if v := s.Attrs[name]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// attrsOf is what a policy may decide on: the groups the provider put
// this session in and the attributes the configuration named. It reads
// only the session this proxy sealed, never a header.
func (f *samlFilter) attrsOf(s *session) filter.Attrs {
	a := filter.Attrs{Groups: s.Attrs[f.cfg.GroupsAttribute]}
	for _, name := range f.cfg.PolicyAttributes {
		v := s.value(name)
		if v == "" {
			continue
		}
		if a.Claims == nil {
			a.Claims = map[string]string{}
		}
		a.Claims[name] = v
	}
	return a
}

// policy is the service provider policy for this request. The consumer
// URL depends on how the browser reaches this proxy, which is why
// external_url exists: unset, it is derived, and a derived URL is one
// the provider has to agree with.
func (f *samlFilter) policy(r *http.Request, info *filter.Info) *saml.Policy {
	c := f.cfg
	p := &saml.Policy{
		EntityID: c.EntityID, ACS: f.base(r, info) + c.ACSPath,
		IDPEntityID: c.IDPEntityID, IDPSSOURL: c.IDPSSOURL, Keys: c.keys,
		Skew: c.skew, MaxAge: c.age, NameIDFormats: c.NameIDFormats,
		ForceAuthn: c.ForceAuthn, RequestedNameIDFormat: c.RequestedNameIDFormat,
	}
	switch c.SignedElement {
	case "assertion":
		p.RequireAssertionSignature = true
	case "response":
		p.RequireResponseSignature = true
	}
	return p
}

// login sends the browser to the identity provider with a fresh request
// identifier, and keeps that identifier in a sealed state cookie: the
// response is bound to it, so an assertion minted for another login
// attempt is not this browser's.
func (f *samlFilter) login(r *http.Request, in *instance) filter.Verdict {
	f.Logins.Add(1)
	p := f.policy(r, in.info)
	id := saml.NewID()
	ret := r.URL.RequestURI()
	if !strings.HasPrefix(ret, "/") || strings.HasPrefix(ret, "//") || len(ret) > 2048 {
		ret = "/"
	}
	st, err := f.seal(loginState{RequestID: id, Return: ret, Exp: time.Now().Add(stateTTL).Unix()}, "state")
	if err != nil || len(st) > maxCookie {
		f.Failures.Add(1)
		return filter.Verdict{Deny: true, Status: http.StatusInternalServerError, Reason: f.name, Detail: "seal"}
	}
	loc, err := p.RedirectURL(p.AuthnRequest(id, time.Now()), stateDigest(st))
	if err != nil {
		f.Failures.Add(1)
		return filter.Verdict{Deny: true, Status: http.StatusInternalServerError, Reason: f.name, Detail: "request"}
	}
	resp := &http.Response{StatusCode: http.StatusFound, Header: http.Header{}}
	resp.Header.Set("Location", loc)
	resp.Header.Set("Cache-Control", "no-store")
	resp.Header.Add("Set-Cookie", f.cookie(f.cfg.CookieName+stateSuffix, st, int(stateTTL.Seconds()), f.secure(r, in.info)).String())
	return filter.Verdict{Deny: true, Silent: true, Status: http.StatusFound, Reason: f.name, Detail: "login", Response: resp}
}

// consume is the assertion consumer service: it reads the posted
// response, verifies it and sets the session cookie.
func (f *samlFilter) consume(r *http.Request, in *instance) filter.Verdict {
	fail := func(status int, detail string) filter.Verdict {
		f.Failures.Add(1)
		return filter.Verdict{Deny: true, Status: status, Reason: f.name, Detail: detail}
	}
	if r.Method != http.MethodPost {
		// Only the POST binding is accepted. A response in a query
		// string is a response in a browser history, a proxy log and a
		// Referer header.
		return fail(http.StatusMethodNotAllowed, "acs_method")
	}
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
		return fail(http.StatusUnsupportedMediaType, "acs_content_type")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxACSBody+1))
	if err != nil {
		return fail(http.StatusBadRequest, "acs_body")
	}
	if len(body) > maxACSBody {
		return fail(http.StatusRequestEntityTooLarge, "acs_body_size")
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return fail(http.StatusBadRequest, "acs_form")
	}
	encoded := form.Get("SAMLResponse")
	if encoded == "" {
		return fail(http.StatusBadRequest, "acs_no_response")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return fail(http.StatusBadRequest, "acs_base64")
	}
	sc, err := r.Cookie(f.cfg.CookieName + stateSuffix)
	if err != nil || len(sc.Value) > maxCookie {
		// No state cookie: either the login started on another node with
		// another key, or this is a response nobody here asked for.
		return fail(http.StatusBadRequest, "state_missing")
	}
	var ls loginState
	if err := f.open(sc.Value, "state", &ls); err != nil || ls.Exp < time.Now().Unix() {
		return fail(http.StatusBadRequest, "state_invalid")
	}
	if rs := form.Get("RelayState"); rs != "" && rs != stateDigest(sc.Value) {
		// The relay state is not the binding -- InResponseTo against the
		// sealed request identifier is -- but a provider that returns it
		// changed says something is wrong with this exchange.
		return fail(http.StatusBadRequest, "relay_state")
	}
	now := time.Now()
	login, err := f.policy(r, in.info).Accept(raw, ls.RequestID, now)
	if err != nil {
		f.log.Warn("saml response refused", "err", err.Error())
		switch {
		case errors.Is(err, saml.ErrStatus):
			return fail(http.StatusUnauthorized, "provider_status")
		case errors.Is(err, saml.ErrSignature):
			return fail(http.StatusUnauthorized, "signature")
		case errors.Is(err, saml.ErrProfile):
			return fail(http.StatusBadRequest, "profile")
		default:
			return fail(http.StatusUnauthorized, "refused")
		}
	}
	// One assertion, one login. The window an assertion declares is a
	// window in which anyone holding a copy could present it.
	if !f.seen.Admit(login.AssertionID, login.NotOnOrAfter, now) {
		f.Replays.Add(1)
		f.log.Warn("saml assertion presented twice", "assertion", login.AssertionID)
		return fail(http.StatusUnauthorized, "replay")
	}
	for name, want := range f.cfg.RequireAttributes {
		if got := login.Attr(name); got != want {
			f.log.Warn("saml attribute requirement not met", "attribute", name, "name_id", login.NameID)
			return fail(http.StatusForbidden, "attribute:"+name)
		}
	}
	exp := now.Add(f.cfg.ttl)
	if !login.NotOnOrAfter.IsZero() && login.NotOnOrAfter.Before(exp) {
		// The provider said how long this authentication is good for.
		// A session that outlived it would be this proxy extending
		// somebody else's decision.
		exp = login.NotOnOrAfter
	}
	s := session{NameID: login.NameID, Format: login.NameIDFormat, Index: login.SessionIndex,
		Iat: now.Unix(), Exp: exp.Unix(), Attrs: f.keep(login)}
	sealed, err := f.seal(s, "session")
	if err != nil || len(sealed) > maxCookie {
		return fail(http.StatusInternalServerError, "session_size")
	}
	f.Accepted.Add(1)
	in.user = login.NameID
	secure := f.secure(r, in.info)
	resp := &http.Response{StatusCode: http.StatusFound, Header: http.Header{}}
	resp.Header.Set("Location", ls.Return)
	resp.Header.Set("Cache-Control", "no-store")
	resp.Header.Add("Set-Cookie", f.cookie(f.cfg.CookieName, sealed, int(time.Until(exp).Seconds()), secure).String())
	resp.Header.Add("Set-Cookie", f.cookie(f.cfg.CookieName+stateSuffix, "", -1, secure).String())
	return filter.Verdict{Deny: true, Silent: true, Status: http.StatusFound, Reason: f.name, Detail: "login_complete", Response: resp,
		Attrs: []any{"saml_name_id", login.NameID}}
}

// keep is the subset of the assertion's attributes the session carries:
// what a header, a log field, a policy or a requirement names, and
// nothing else. A cookie is four kilobytes and an assertion can carry
// far more than that.
func (f *samlFilter) keep(login *saml.Login) map[string][]string {
	want := map[string]bool{f.cfg.GroupsAttribute: true}
	for _, name := range f.cfg.ForwardHeaders {
		want[name] = true
	}
	for _, name := range f.cfg.LogAttributes {
		want[name] = true
	}
	for _, name := range f.cfg.PolicyAttributes {
		want[name] = true
	}
	for name := range f.cfg.RequireAttributes {
		want[name] = true
	}
	out := map[string][]string{}
	for name := range want {
		if v, ok := login.Attributes[name]; ok && len(v) > 0 {
			out[name] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// metadata serves this service provider's metadata, so the provider can
// be configured from it rather than by hand.
func (f *samlFilter) metadata(r *http.Request, in *instance) filter.Verdict {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return filter.Verdict{Deny: true, Status: http.StatusMethodNotAllowed, Reason: f.name, Detail: "metadata_method"}
	}
	doc := f.policy(r, in.info).Metadata()
	resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{}}
	resp.Header.Set("Content-Type", "application/samlmetadata+xml")
	resp.Body = io.NopCloser(strings.NewReader(string(doc)))
	return filter.Verdict{Deny: true, Silent: true, Status: http.StatusOK, Reason: f.name, Detail: "metadata", Response: resp}
}

// logout clears the session here. There is no single logout binding in
// this profile: signing out at the provider is the provider's own page,
// and a logout request arriving unauthenticated over a cross site POST
// is a way to sign other people out.
func (f *samlFilter) logout(r *http.Request, in *instance) filter.Verdict {
	f.Logouts.Add(1)
	resp := &http.Response{StatusCode: http.StatusFound, Header: http.Header{}}
	resp.Header.Set("Location", f.cfg.LogoutRedirect)
	resp.Header.Set("Cache-Control", "no-store")
	secure := f.secure(r, in.info)
	resp.Header.Add("Set-Cookie", f.cookie(f.cfg.CookieName, "", -1, secure).String())
	resp.Header.Add("Set-Cookie", f.cookie(f.cfg.CookieName+stateSuffix, "", -1, secure).String())
	return filter.Verdict{Deny: true, Silent: true, Status: http.StatusFound, Reason: f.name, Detail: "logout", Response: resp}
}

// session decodes and checks the session cookie.
func (f *samlFilter) session(r *http.Request) (*session, bool) {
	c, err := r.Cookie(f.cfg.CookieName)
	if err != nil || len(c.Value) > maxCookie {
		return nil, false
	}
	var s session
	if err := f.open(c.Value, "session", &s); err != nil {
		return nil, false
	}
	now := time.Now().Unix()
	if s.NameID == "" || s.Exp <= now || s.Iat > now+60 {
		return nil, false
	}
	return &s, true
}

func (f *samlFilter) base(r *http.Request, info *filter.Info) string {
	if f.cfg.ExternalURL != "" {
		return f.cfg.ExternalURL
	}
	scheme := "http"
	if f.secure(r, info) {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// secure decides the scheme of the URLs this filter builds. The
// forwarding header counts only from a trusted peer: any client can send
// X-Forwarded-Proto, and the consumer URL derived from it is what the
// provider is told to post the assertion to. Set external_url and none
// of this is guessed.
func (f *samlFilter) secure(r *http.Request, info *filter.Info) bool {
	if f.cfg.ExternalURL != "" {
		return strings.HasPrefix(f.cfg.ExternalURL, "https://")
	}
	if info.TLS {
		return true
	}
	return info.TrustedPeer && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func (f *samlFilter) cookie(name, value string, maxAge int, secure bool) *http.Cookie {
	return &http.Cookie{Name: name, Value: value, Path: "/", Domain: f.cfg.CookieDomain, MaxAge: maxAge,
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode}
}

// stripCookies removes the filter's cookies from the forwarded request.
func (f *samlFilter) stripCookies(r *http.Request) {
	cookies := r.Cookies()
	r.Header.Del("Cookie")
	for _, c := range cookies {
		if c.Name == f.cfg.CookieName || c.Name == f.cfg.CookieName+stateSuffix {
			continue
		}
		r.AddCookie(c)
	}
}

// aad is the additional data every cookie is sealed under: the purpose,
// so a state cookie can never be replayed as a session, and both entity
// identifiers, so two filters sharing a cookie_secret_file cannot open
// each other's sessions and a login through one provider does not
// satisfy another.
func (f *samlFilter) aad(purpose string) []byte {
	return []byte(purpose + "\x00" + f.cfg.EntityID + "\x00" + f.cfg.IDPEntityID)
}

func (f *samlFilter) seal(v any, purpose string) (string, error) {
	plain, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, f.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(f.aead.Seal(nonce, nonce, plain, f.aad(purpose))), nil
}

func (f *samlFilter) open(s, purpose string, v any) error {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(raw) < f.aead.NonceSize() {
		return errors.New("bad cookie")
	}
	ns := f.aead.NonceSize()
	aad := f.aad(purpose)
	plain, err := f.aead.Open(nil, raw[:ns], raw[ns:], aad)
	for _, a := range f.olderAEADs {
		if err == nil {
			break
		}
		plain, err = a.Open(nil, raw[:ns], raw[ns:], aad)
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(plain, v)
}

// stateDigest binds the relay state to the state cookie without sending
// the cookie itself through the provider.
func stateDigest(cookie string) string {
	digest := sha256.Sum256([]byte(cookie))
	return base64.RawURLEncoding.EncodeToString(digest[:])[:22]
}

func (in *instance) Response(*http.Response) filter.Verdict { return filter.Continue }

func (in *instance) End() []any {
	if in.user != "" {
		return append([]any{"saml_user", in.user}, in.log...)
	}
	return in.log
}

// Status is the management view.
type Status struct {
	EntityID    string `json:"entity_id"`
	IDPEntityID string `json:"idp_entity_id"`
	ACSPath     string `json:"acs_path"`
	Certs       int    `json:"certs"`
	Logins      uint64 `json:"logins"`
	Accepted    uint64 `json:"accepted"`
	Failures    uint64 `json:"failures"`
	Replays     uint64 `json:"replays"`
	Logouts     uint64 `json:"logouts"`
	Seen        int    `json:"seen"`
}

// Status reports the configured provider and the counters.
func (f *samlFilter) Status() Status {
	return Status{EntityID: f.cfg.EntityID, IDPEntityID: f.cfg.IDPEntityID, ACSPath: f.cfg.ACSPath,
		Certs: len(f.cfg.certs), Logins: f.Logins.Load(), Accepted: f.Accepted.Load(),
		Failures: f.Failures.Load(), Replays: f.Replays.Load(), Logouts: f.Logouts.Load(), Seen: f.seen.Len()}
}

func init() {
	filter.Register(filter.Kind{
		Name:        "saml_sp",
		Description: "SAML 2.0 service provider login with an encrypted session cookie.",
		BuffersBody: true,
		Validate: func(opts filter.Options) error {
			_, err := parse(opts)
			return err
		},
		New: func(name string, opts filter.Options, env filter.Env) (filter.Filter, error) {
			c, err := parse(opts)
			if err != nil {
				return nil, err
			}
			return newFilter(name, c, env.Log)
		},
	})
}
