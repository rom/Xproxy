package http

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"strings"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/mfa"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/scim"
)

// The SCIM endpoint is answered before routing, like the virtual
// security.txt: the provider needs no route, and no route can take the
// endpoint away by matching the path first. Its own selectors decide who
// reaches it -- the listener, the host and the client network -- because
// an endpoint that creates and destroys credentials is not something to
// leave to a route's access list.

// scimEndpoint is the compiled section.
type scimEndpoint struct {
	h *scim.Handler
	// hosts are exact names, suffixes are wildcard patterns without the
	// star, and both are lower case.
	hosts     map[string]bool
	suffixes  []string
	listeners map[string]bool
	clients   []netip.Prefix
}

// newSCIM compiles the section: the token, the stores and the selectors.
func newSCIM(cfg *config.Config) (*scimEndpoint, error) {
	c := cfg.SCIM
	token, err := readToken(c.TokenFile)
	if err != nil {
		return nil, err
	}
	var users *mfa.Store
	if c.MFAUsersFile != "" {
		if users, err = mfa.LoadProvisioning(c.MFAUsersFile); err != nil {
			return nil, fmt.Errorf("scim.mfa_users_file: %w", err)
		}
	}
	store, err := scim.NewProvisioner(scim.Options{
		StateFile: c.StateFile,
		MFA:       users,
		Issuer:    c.Issuer,
		KeysFile:  c.KeysFile,
		KeyScopes: c.KeyScopes,
		KeyTTL:    c.TTL(),
	})
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(token))
	h, err := scim.New(scim.Config{
		Base:          c.Base(),
		TokenHash:     hex.EncodeToString(sum[:]),
		MaxResults:    c.Results(),
		ReturnSecrets: c.Secrets(),
		ExternalURL:   c.ExternalURL,
	}, store)
	if err != nil {
		return nil, err
	}
	e := &scimEndpoint{h: h}
	if len(c.Hosts) > 0 {
		e.hosts = map[string]bool{}
		for _, host := range c.Hosts {
			h := strings.ToLower(host)
			if strings.HasPrefix(h, "*.") {
				e.suffixes = append(e.suffixes, h[1:])
				continue
			}
			e.hosts[h] = true
		}
	}
	if len(c.Listeners) > 0 {
		e.listeners = map[string]bool{}
		for _, l := range c.Listeners {
			e.listeners[l] = true
		}
	}
	for _, cidr := range c.ClientCIDRs {
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("scim.client_cidrs: %q: %w", cidr, err)
		}
		e.clients = append(e.clients, p)
	}
	return e, nil
}

// readToken reads the bearer token: one line, with the surrounding
// whitespace a file written by an editor carries. An empty file is an
// error rather than an endpoint every request authenticates against.
func readToken(path string) (string, error) {
	data, err := os.ReadFile(path) //nolint:gosec // a path from the configuration
	if err != nil {
		return "", fmt.Errorf("scim.token_file: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if len(token) < 16 {
		return "", fmt.Errorf("scim.token_file: %s holds %d characters; use at least 16 of secret", path, len(token))
	}
	return token, nil
}

// covers reports whether this request reaches the endpoint at all: the
// path, then the selectors. A path under the base that the selectors
// refuse is not answered here and not routed either -- see serveSCIM.
func (e *scimEndpoint) covers(path string) bool {
	return e != nil && e.h.Covers(path)
}

func (e *scimEndpoint) selects(host string, client netip.Addr, listener string) bool {
	if e.listeners != nil && !e.listeners[listener] {
		return false
	}
	if len(e.clients) > 0 && !netutil.Contains(e.clients, client) {
		return false
	}
	if e.hosts == nil && len(e.suffixes) == 0 {
		return true
	}
	h := strings.ToLower(host)
	if e.hosts[h] {
		return true
	}
	for _, suf := range e.suffixes {
		if strings.HasSuffix(h, suf) && len(h) > len(suf) {
			return true
		}
	}
	return false
}

// serveSCIM answers a provisioning request, and reports whether it did.
//
// A request on the endpoint's path that the selectors do not admit is
// refused here rather than routed on: the path belongs to this endpoint,
// and passing it to a route would tell a client which paths are the
// interesting ones and hand a proxied application a request meant for
// the control plane.
func (s *engine) serveSCIM(rw *responseWriter, r *http.Request, st *reqState, listener string) bool {
	e := s.rt.Load().scim
	if !e.covers(st.path) {
		return false
	}
	st.route = "_scim"
	if !e.selects(st.host, st.clientIP, listener) {
		s.stats.SCIMDenied.Add(1)
		st.denied = "scim:not_allowed"
		s.logs.SecurityEvent(r.Context(), "deny", "scim",
			"request_id", st.id, "client_ip", st.clientIP.String(), "method", r.Method,
			"host", r.Host, "path", st.path, "detail", "not_allowed")
		s.plainStatus(rw, r, http.StatusNotFound)
		return true
	}
	out := e.h.Serve(rw, r)
	s.stats.SCIMRequests.Add(1)
	st.extra = append(st.extra, "scim", out.Op)
	if out.User != "" {
		st.extra = append(st.extra, "scim_user", out.User)
	}
	if out.Denied == "" {
		// A change to the credentials is an administrative event, logged
		// whether or not anything else is: it is the record of who was
		// provisioned and when.
		if out.Op == "create" || out.Op == "replace" || out.Op == "patch" || out.Op == "delete" {
			s.logs.SecurityEvent(r.Context(), "scim", out.Op,
				"request_id", st.id, "client_ip", st.clientIP.String(),
				"scim_user", out.User, "status", out.Status)
		}
		return true
	}
	s.stats.SCIMDenied.Add(1)
	st.denied = "scim:" + out.Denied
	s.logs.SecurityEvent(r.Context(), "deny", "scim",
		"request_id", st.id, "client_ip", st.clientIP.String(), "method", r.Method,
		"host", r.Host, "path", st.path, "status", out.Status, "detail", out.Denied,
		"scim_user", out.User)
	// A bad token on a provisioning endpoint is somebody trying keys, so
	// the ban list hears about it.
	if bl := s.host.Bans(); bl != nil && (out.Denied == "bad_token" || out.Denied == "no_token") {
		bl.ObserveClient(st.clientIP, st.ja4, "scim")
	}
	return true
}
