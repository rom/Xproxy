package admin

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/mgmt"
	"github.com/rom/xproxy/internal/tlsconf"
	"github.com/rom/xproxy/internal/version"
)

//go:embed static
var staticFS embed.FS

// Options configure the GUI server.
type Options struct {
	// Listen is "host:port" or "unix:/path". A TCP address that is not on a
	// loopback interface requires TLS with client certificates.
	Listen string
	// Socket is the data plane's management socket.
	Socket string
	// ConfigFile is the data plane configuration the GUI may edit.
	ConfigFile string
	// UsersFile is the users file (see LoadUsers).
	UsersFile string
	// TLS serves HTTPS when CertFile is set; ClientCAFile enables mutual TLS
	// and certificate login (common name equals the user name).
	TLS TLSOptions
	// RestartCommand is run, without a shell, for the restart action. Empty
	// disables the action.
	RestartCommand []string
	// SessionIdle and SessionMax bound a session (defaults 30m and 12h).
	SessionIdle time.Duration
	SessionMax  time.Duration
	// Log receives the audit and error events (JSON to stderr by default).
	Log *slog.Logger
}

// TLSOptions are the listener's certificate settings.
type TLSOptions struct {
	CertFile     string
	KeyFile      string
	ClientCAFile string
}

// Server is the GUI process.
type Server struct {
	o        Options
	users    *Users
	sessions *sessions
	limiter  *loginLimiter
	client   *mgmt.Client
	log      *slog.Logger
	mux      *http.ServeMux
	srv      *http.Server
	ln       net.Listener
	tlsOn    bool
	verify   chan struct{} // bounds concurrent password checks
	mu       sync.Mutex    // serialises configuration file writes
}

// New validates the options and prepares the server; nothing listens yet.
func New(o Options) (*Server, error) {
	if o.Log == nil {
		o.Log = slog.New(slog.NewJSONHandler(os.Stderr, nil))
	}
	if o.SessionIdle <= 0 {
		o.SessionIdle = 30 * time.Minute
	}
	if o.SessionMax <= 0 {
		o.SessionMax = 12 * time.Hour
	}
	if o.Listen == "" {
		return nil, errors.New("listen address required")
	}
	if o.Socket == "" {
		return nil, errors.New("management socket path required")
	}
	if o.UsersFile == "" {
		return nil, errors.New("users file required")
	}
	if (o.TLS.CertFile == "") != (o.TLS.KeyFile == "") {
		return nil, errors.New("tls: cert and key go together")
	}
	if o.TLS.ClientCAFile != "" && o.TLS.CertFile == "" {
		return nil, errors.New("tls: client CA requires a server certificate")
	}
	if !strings.HasPrefix(o.Listen, "unix:") {
		host, _, err := net.SplitHostPort(o.Listen)
		if err != nil {
			return nil, fmt.Errorf("listen: %w", err)
		}
		if !isLoopbackHost(host) && (o.TLS.CertFile == "" || o.TLS.ClientCAFile == "") {
			return nil, errors.New("listen: a non-loopback address requires TLS with a client CA (mutual TLS); use 127.0.0.1, a Unix socket or an SSH tunnel otherwise")
		}
	}
	users, err := LoadUsers(o.UsersFile)
	if err != nil {
		return nil, err
	}
	s := &Server{
		o:        o,
		users:    users,
		sessions: newSessions(o.SessionIdle, o.SessionMax),
		limiter:  newLoginLimiter(5, 5*time.Minute),
		client:   mgmt.NewClient(o.Socket),
		log:      o.Log.With("component", "admin"),
		mux:      http.NewServeMux(),
		tlsOn:    o.TLS.CertFile != "",
		verify:   make(chan struct{}, 4),
	}
	s.routes()
	return s, nil
}

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(h)
	return err == nil && a.IsLoopback()
}

// Handler returns the HTTP handler (for tests and embedding).
func (s *Server) Handler() http.Handler { return s.secure(s.mux) }

// Start listens and serves in the background.
func (s *Server) Start() error {
	var ln net.Listener
	var err error
	lc := net.ListenConfig{}
	if p, ok := strings.CutPrefix(s.o.Listen, "unix:"); ok {
		_ = os.Remove(p)
		old := umask(0o077)
		ln, err = lc.Listen(context.Background(), "unix", p)
		umask(old)
		if err == nil {
			// Group access like the management socket: the GUI is reached by
			// members of the xproxy group through the socket or a tunnel.
			err = os.Chmod(p, 0o660) //nolint:gosec // socket, deliberately group accessible
		}
	} else {
		ln, err = lc.Listen(context.Background(), "tcp", s.o.Listen)
	}
	if err != nil {
		return err
	}
	if s.tlsOn {
		tc, err := s.tlsConfig()
		if err != nil {
			_ = ln.Close()
			return err
		}
		ln = tls.NewListener(ln, tc)
	}
	s.ln = ln
	s.srv = &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
	go func() {
		if err := s.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("serve", "err", err.Error())
		}
	}()
	s.log.Info("xproxy-admin listening", "addr", s.Addr(), "tls", s.tlsOn, "client_ca", s.o.TLS.ClientCAFile != "", "version", version.String())
	return nil
}

// Addr is the bound address.
func (s *Server) Addr() string {
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

// Shutdown stops serving.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.srv == nil {
		return nil
	}
	err := s.srv.Shutdown(ctx)
	if p, ok := strings.CutPrefix(s.o.Listen, "unix:"); ok {
		_ = os.Remove(p)
	}
	return err
}

func (s *Server) tlsConfig() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(s.o.TLS.CertFile, s.o.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("tls: %w", err)
	}
	tc := &tls.Config{
		MinVersion:       tls.VersionTLS12,
		Certificates:     []tls.Certificate{cert},
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
		CipherSuites:     tlsconf.DefaultCipherSuites(),
		Renegotiation:    tls.RenegotiateNever,
		NextProtos:       []string{"h2", "http/1.1"},
	}
	if s.o.TLS.ClientCAFile != "" {
		pem, err := os.ReadFile(s.o.TLS.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("tls client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("tls client CA: no certificates in file")
		}
		tc.ClientCAs = pool
		tc.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return tc, nil
}

// ---- routing and middleware ----

func (s *Server) routes() {
	m := s.mux
	m.HandleFunc("GET /api/health", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]any{"ok": true}) })
	m.HandleFunc("POST /api/login", s.login)
	m.HandleFunc("POST /api/logout", s.logout)
	m.HandleFunc("GET /api/me", s.me)

	// Read-only pass-through to the management API.
	for name, path := range map[string]string{
		"status": "/v1/status", "stats": "/v1/stats", "upstreams": "/v1/upstreams", "bans": "/v1/bans",
		"cluster": "/v1/cluster", "acme": "/v1/acme", "icap": "/v1/icap", "active-config": "/v1/config",
	} {
		m.HandleFunc("GET /api/"+name, s.passthrough(path, "application/json"))
	}
	m.HandleFunc("GET /api/metrics", s.passthrough("/metrics", "text/plain; version=0.0.4; charset=utf-8"))
	m.HandleFunc("GET /api/series", s.series)
	m.HandleFunc("GET /api/users", s.listUsers)

	// Actions.
	m.HandleFunc("POST /api/bans", s.addBan)
	m.HandleFunc("DELETE /api/bans", s.removeBan)
	m.HandleFunc("POST /api/reload", s.action("reload", "/v1/reload"))
	m.HandleFunc("POST /api/reload-certs", s.action("reload-certs", "/v1/reload-certs"))
	m.HandleFunc("POST /api/reopen-logs", s.action("reopen-logs", "/v1/logs/reopen"))
	m.HandleFunc("POST /api/acme/renew", s.action("acme-renew", "/v1/acme/renew"))
	m.HandleFunc("POST /api/restart", s.restart)

	// Configuration file.
	m.HandleFunc("GET /api/config/file", s.getConfigFile)
	m.HandleFunc("POST /api/config/validate", s.validateConfig)
	m.HandleFunc("PUT /api/config/file", s.putConfigFile)

	// Logs.
	m.HandleFunc("GET /api/logs/{stream}", s.logTail)
	m.HandleFunc("GET /api/logs/{stream}/follow", s.logFollow)

	sub, _ := fs.Sub(staticFS, "static")
	files := http.FileServerFS(sub)
	m.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			w.Header().Set("Cache-Control", "no-store")
			r.URL.Path = "/"
		} else {
			w.Header().Set("Cache-Control", "private, max-age=3600")
		}
		files.ServeHTTP(w, r)
	})
}

// secure sets the security headers, authenticates and authorises.
func (s *Server) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		if s.tlsOn {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		h.Set("Cache-Control", "no-store")
		if r.URL.Path == "/api/health" || r.URL.Path == "/api/login" {
			if r.Method != http.MethodGet && !s.sameOrigin(r) {
				writeJSON(w, 403, map[string]any{"error": "cross-site request refused"})
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		sess, ok := s.authenticate(w, r)
		if !ok {
			writeJSON(w, 401, map[string]any{"error": "not logged in"})
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !s.sameOrigin(r) {
				writeJSON(w, 403, map[string]any{"error": "cross-site request refused"})
				return
			}
			if sess.Role != RoleOperator && r.URL.Path != "/api/logout" {
				s.audit(r, sess, "denied", "path", r.URL.Path, "method", r.Method)
				writeJSON(w, 403, map[string]any{"error": "operator role required"})
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionKey{}, sess)))
	})
}

type sessionKey struct{}

func sessionFrom(r *http.Request) Session {
	s, _ := r.Context().Value(sessionKey{}).(Session)
	return s
}

// sameOrigin is the cross-site request forgery check for state changes:
// the custom header (which browsers only send after a CORS preflight, and
// there is no CORS policy allowing one), the fetch metadata when the
// browser sends it, and the Origin header when present.
func (s *Server) sameOrigin(r *http.Request) bool {
	if r.Header.Get("X-Xproxy-Admin") != "1" {
		return false
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return false
	}
	if o := r.Header.Get("Origin"); o != "" && o != "null" {
		u, err := url.Parse(o)
		if err != nil || !strings.EqualFold(u.Host, r.Host) {
			return false
		}
	}
	return true
}

func (s *Server) cookieName() string {
	if s.tlsOn {
		return "__Host-xproxy_admin"
	}
	return "xproxy_admin"
}

func (s *Server) setCookie(w http.ResponseWriter, tok string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: s.cookieName(), Value: tok, Path: "/", HttpOnly: true, Secure: s.tlsOn,
		SameSite: http.SameSiteStrictMode, MaxAge: maxAge,
	})
}

// authenticate resolves the session cookie, or logs a client certificate in.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (Session, bool) {
	if c, err := r.Cookie(s.cookieName()); err == nil {
		if sess, ok := s.sessions.get(c.Value); ok {
			return sess, true
		}
	}
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		cn := r.TLS.PeerCertificates[0].Subject.CommonName
		if u, ok := s.users.Lookup(cn); ok {
			tok, err := s.sessions.create(u.Name, u.Role, "certificate")
			if err == nil {
				s.setCookie(w, tok, int(s.o.SessionMax.Seconds()))
				sess, _ := s.sessions.get(tok)
				s.audit(r, sess, "login")
				return sess, true
			}
		}
	}
	return Session{}, false
}

func (s *Server) audit(r *http.Request, sess Session, action string, kv ...any) {
	attrs := append([]any{"action", action, "user", sess.User, "role", string(sess.Role), "source", sourceOf(r)}, kv...)
	s.log.Info("admin action", attrs...)
}

func sourceOf(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		if r.RemoteAddr == "" || r.RemoteAddr == "@" {
			return "local"
		}
		return r.RemoteAddr
	}
	return h
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 4<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("bad request body: %w", err)
	}
	return nil
}

// ---- authentication handlers ----

type loginRequest struct {
	User     string `json:"user"`
	Password string `json:"password"`
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	src := sourceOf(r)
	if blocked, wait := s.limiter.blocked(src); blocked {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeJSON(w, 429, map[string]any{"error": "too many failed logins; try again later"})
		return
	}
	var req loginRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	u, ok := s.users.Lookup(req.User)
	valid := false
	if ok && !u.CertOnly() {
		select {
		case s.verify <- struct{}{}:
			valid = VerifyPassword(u.Hash, req.Password)
			<-s.verify
		case <-r.Context().Done():
			return
		}
	} else {
		// Same cost for unknown users so timing does not reveal names.
		VerifyPassword(dummyHash, req.Password)
	}
	if !valid {
		s.limiter.fail(src)
		s.log.Warn("admin login failed", "user", req.User, "source", src)
		writeJSON(w, 401, map[string]any{"error": "invalid user or password"})
		return
	}
	s.limiter.reset(src)
	tok, err := s.sessions.create(u.Name, u.Role, "password")
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	s.setCookie(w, tok, int(s.o.SessionMax.Seconds()))
	sess, _ := s.sessions.get(tok)
	s.audit(r, sess, "login")
	writeJSON(w, 200, s.meView(sess))
}

// dummyHash is verified for unknown users so that the response time does
// not depend on whether the user exists.
var dummyHash = func() string {
	h, err := HashPassword("not-a-real-password-0000")
	if err != nil {
		panic(err)
	}
	return h
}()

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(s.cookieName()); err == nil {
		s.sessions.drop(c.Value)
	}
	s.setCookie(w, "", -1)
	s.audit(r, sessionFrom(r), "logout")
	writeJSON(w, 200, map[string]any{"ok": true})
}

type meView struct {
	User        string `json:"user"`
	Role        Role   `json:"role"`
	Via         string `json:"via"`
	Version     string `json:"version"`
	ConfigFile  string `json:"config_file"`
	CanRestart  bool   `json:"can_restart"`
	CanEditFile bool   `json:"can_edit_file"`
}

func (s *Server) meView(sess Session) meView {
	return meView{User: sess.User, Role: sess.Role, Via: sess.Via, Version: version.String(), ConfigFile: s.o.ConfigFile,
		CanRestart: len(s.o.RestartCommand) > 0 && sess.Role == RoleOperator, CanEditFile: s.o.ConfigFile != "" && sess.Role == RoleOperator}
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.meView(sessionFrom(r)))
}

func (s *Server) listUsers(w http.ResponseWriter, _ *http.Request) {
	type uv struct {
		Name     string `json:"name"`
		Role     Role   `json:"role"`
		CertOnly bool   `json:"cert_only"`
	}
	list := s.users.List()
	out := make([]uv, 0, len(list))
	for _, u := range list {
		x, _ := s.users.Lookup(u.Name)
		out = append(out, uv{Name: u.Name, Role: u.Role, CertOnly: x.CertOnly()})
	}
	writeJSON(w, 200, out)
}

// ---- management pass-through ----

func (s *Server) mgmtError(w http.ResponseWriter, err error) {
	writeJSON(w, 502, map[string]any{"error": err.Error()})
}

func (s *Server) passthrough(path, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		var body []byte
		if err := s.client.Do(http.MethodGet, path, nil, &body); err != nil {
			s.mgmtError(w, err)
			return
		}
		w.Header().Set("Content-Type", contentType)
		_, _ = w.Write(body)
	}
}

func (s *Server) series(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	since := q.Get("since")
	if since == "" {
		since = "30m"
	}
	if _, err := time.ParseDuration(since); err != nil {
		writeJSON(w, 400, map[string]any{"error": "since: " + err.Error()})
		return
	}
	limit := 0
	if l := q.Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 1 || n > 100000 {
			writeJSON(w, 400, map[string]any{"error": "limit: 1 to 100000"})
			return
		}
		limit = n
	}
	path := "/v1/series?since=" + url.QueryEscape(since)
	if limit > 0 {
		path += "&limit=" + strconv.Itoa(limit)
	}
	var body []byte
	if err := s.client.Do(http.MethodGet, path, nil, &body); err != nil {
		s.mgmtError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// action forwards a POST with no body and audits it.
func (s *Server) action(name, path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := sessionFrom(r)
		if err := s.client.Do(http.MethodPost, path, nil, nil); err != nil {
			s.audit(r, sess, name, "ok", false, "err", err.Error())
			writeJSON(w, 409, map[string]any{"error": err.Error()})
			return
		}
		s.audit(r, sess, name, "ok", true)
		writeJSON(w, 200, map[string]any{"ok": true})
	}
}

func (s *Server) addBan(w http.ResponseWriter, r *http.Request) {
	var req mgmt.BanRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	sess := sessionFrom(r)
	req.Reason = strings.TrimSpace(req.Reason)
	if req.Reason == "" {
		req.Reason = "manual"
	}
	req.Reason = "admin:" + sess.User + ": " + req.Reason
	var out json.RawMessage
	if err := s.client.Do(http.MethodPost, "/v1/bans", req, &out); err != nil {
		s.audit(r, sess, "ban", "target", req.Target, "ok", false, "err", err.Error())
		writeJSON(w, 409, map[string]any{"error": err.Error()})
		return
	}
	s.audit(r, sess, "ban", "target", req.Target, "duration", req.Duration, "ok", true)
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
}

func (s *Server) removeBan(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		writeJSON(w, 400, map[string]any{"error": "target required"})
		return
	}
	sess := sessionFrom(r)
	if err := s.client.Do(http.MethodDelete, "/v1/bans?target="+url.QueryEscape(target), nil, nil); err != nil {
		s.audit(r, sess, "unban", "target", target, "ok", false, "err", err.Error())
		writeJSON(w, 409, map[string]any{"error": err.Error()})
		return
	}
	s.audit(r, sess, "unban", "target", target, "ok", true)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) restart(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	if len(s.o.RestartCommand) == 0 {
		writeJSON(w, 501, map[string]any{"error": "restart is not enabled (-restart-cmd)"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.o.RestartCommand[0], s.o.RestartCommand[1:]...) //nolint:gosec // operator configured command, no shell
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	out, err := cmd.CombinedOutput()
	msg := strings.TrimSpace(string(out))
	if len(msg) > 4096 {
		msg = msg[:4096]
	}
	if err != nil {
		s.audit(r, sess, "restart", "ok", false, "err", err.Error(), "output", msg)
		writeJSON(w, 409, map[string]any{"error": err.Error(), "output": msg})
		return
	}
	s.audit(r, sess, "restart", "ok", true)
	writeJSON(w, 200, map[string]any{"ok": true, "output": msg})
}

// ---- configuration file ----

type configFileView struct {
	Path string `json:"path"`
	Text string `json:"text"`
	ETag string `json:"etag"`
	Mode string `json:"mode"`
}

type configFileRequest struct {
	Text string `json:"text"`
	ETag string `json:"etag"`
}

const maxConfigBytes = 8 << 20

func etagOf(b []byte) string {
	return fmt.Sprintf("%x", sha256sum(b))
}

func (s *Server) getConfigFile(w http.ResponseWriter, _ *http.Request) {
	if s.o.ConfigFile == "" {
		writeJSON(w, 404, map[string]any{"error": "no configuration file configured"})
		return
	}
	b, err := os.ReadFile(s.o.ConfigFile)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	mode := ""
	if st, err := os.Stat(s.o.ConfigFile); err == nil {
		mode = fmt.Sprintf("%04o", st.Mode().Perm())
	}
	writeJSON(w, 200, configFileView{Path: s.o.ConfigFile, Text: string(b), ETag: etagOf(b), Mode: mode})
}

type validation struct {
	OK       bool     `json:"ok"`
	Problems []string `json:"problems,omitempty"`
	Routes   int      `json:"routes,omitempty"`
	Upstream int      `json:"upstreams,omitempty"`
}

func validate(text string) validation {
	cfg, err := config.ParseWith([]byte(text), true)
	if err != nil {
		return validation{Problems: splitProblems(err)}
	}
	return validation{OK: true, Routes: len(cfg.Routes), Upstream: len(cfg.Upstreams)}
}

// splitProblems turns the aggregated validation error into lines.
func splitProblems(err error) []string {
	lines := strings.Split(err.Error(), "\n")
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		l = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), "- "))
		if l == "" || strings.HasSuffix(l, "problems:") || strings.HasSuffix(l, "problem:") {
			continue
		}
		out = append(out, l)
	}
	if len(out) == 0 {
		out = []string{err.Error()}
	}
	return out
}

func (s *Server) validateConfig(w http.ResponseWriter, r *http.Request) {
	var req configFileRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if len(req.Text) > maxConfigBytes {
		writeJSON(w, 413, map[string]any{"error": "configuration too large"})
		return
	}
	writeJSON(w, 200, validate(req.Text))
}

// putConfigFile validates and writes the file atomically, keeping the
// previous content in ".bak" next to it. The etag guards against two
// operators overwriting each other.
func (s *Server) putConfigFile(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	if s.o.ConfigFile == "" {
		writeJSON(w, 404, map[string]any{"error": "no configuration file configured"})
		return
	}
	var req configFileRequest
	if err := readJSON(r, &req); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if len(req.Text) > maxConfigBytes {
		writeJSON(w, 413, map[string]any{"error": "configuration too large"})
		return
	}
	v := validate(req.Text)
	if !v.OK {
		s.audit(r, sess, "config-save", "ok", false, "problems", len(v.Problems))
		writeJSON(w, 422, v)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, err := os.ReadFile(s.o.ConfigFile)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	if req.ETag != "" && req.ETag != etagOf(cur) {
		writeJSON(w, 409, map[string]any{"error": "the file changed since it was loaded; reload the editor and merge"})
		return
	}
	if err := writeFileAtomic(s.o.ConfigFile, []byte(req.Text), cur); err != nil {
		s.audit(r, sess, "config-save", "ok", false, "err", err.Error())
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	s.audit(r, sess, "config-save", "ok", true, "bytes", len(req.Text))
	writeJSON(w, 200, configFileView{Path: s.o.ConfigFile, Text: req.Text, ETag: etagOf([]byte(req.Text))})
}

// writeFileAtomic writes data to a temporary file in the same directory,
// keeps a copy of the previous content in path+".bak" and renames the
// temporary file over the target. The file mode is preserved.
func writeFileAtomic(path string, data, previous []byte) error {
	mode := os.FileMode(0o640)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	dir := filepath.Dir(path)
	if previous != nil {
		// O_NOFOLLOW: the backup name must be a regular file, never a link
		// planted by another member of the group into a file we can write.
		bf, err := os.OpenFile(path+".bak", os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscall.O_NOFOLLOW, mode) //nolint:gosec // next to the configuration file
		if err != nil {
			return fmt.Errorf("backup: %w", err)
		}
		if _, err := bf.Write(previous); err != nil {
			_ = bf.Close()
			return fmt.Errorf("backup: %w", err)
		}
		if err := bf.Close(); err != nil {
			return fmt.Errorf("backup: %w", err)
		}
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp") // O_EXCL: never follows an existing link
	if err != nil {
		return err
	}
	name := tmp.Name()
	cleanup := func() { _ = tmp.Close(); _ = os.Remove(name) }
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}

// ---- logs ----

// logPath resolves a stream name to its file from the data plane
// configuration.
func (s *Server) logPath(stream string) (string, error) {
	if s.o.ConfigFile == "" {
		return "", errors.New("no configuration file configured")
	}
	cfg, err := config.Load(s.o.ConfigFile)
	if err != nil {
		return "", err
	}
	var st config.LogStream
	switch stream {
	case "access":
		st = cfg.Logging.Access
	case "error":
		st = cfg.Logging.Error
	case "security":
		st = cfg.Logging.Security
	case "audit":
		st = cfg.Logging.Audit
	default:
		return "", fmt.Errorf("unknown stream %q", stream)
	}
	if st.File == "" {
		return "", fmt.Errorf("stream %q has no file", stream)
	}
	return filepath.Join(cfg.Logging.Directory, st.File), nil
}

func (s *Server) logTail(w http.ResponseWriter, r *http.Request) {
	path, err := s.logPath(r.PathValue("stream"))
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	n := 200
	if l := r.URL.Query().Get("lines"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 5000 {
			n = v
		}
	}
	lines, err := tailLines(path, n)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"path": path, "lines": lines})
}

// tailLines returns the last n lines of a file, reading at most 1 MiB.
func tailLines(path string, n int) ([]string, error) {
	f, err := os.Open(path) //nolint:gosec // path from the operator's configuration
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	const window = 1 << 20
	start := st.Size() - window
	if start < 0 {
		start = 0
	}
	buf := make([]byte, st.Size()-start)
	if _, err := f.ReadAt(buf, start); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	lines := strings.Split(strings.TrimRight(string(buf), "\n"), "\n")
	if start > 0 && len(lines) > 0 {
		lines = lines[1:] // first line is probably partial
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	if len(lines) == 1 && lines[0] == "" {
		lines = nil
	}
	if lines == nil {
		lines = []string{}
	}
	return lines, nil
}

// logFollow streams new lines as server-sent events until the client goes
// away or an hour passes. Rotation is followed by inode.
func (s *Server) logFollow(w http.ResponseWriter, r *http.Request) {
	path, err := s.logPath(r.PathValue("stream"))
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, 500, map[string]any{"error": "streaming unsupported"})
		return
	}
	f, err := os.Open(path) //nolint:gosec // path from the operator's configuration
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(200)
	_, _ = io.WriteString(w, ": follow "+path+"\n\n")
	fl.Flush()
	ctx, cancel := context.WithTimeout(r.Context(), time.Hour)
	defer cancel()
	rc := http.NewResponseController(w)
	buf := make([]byte, 64<<10)
	var partial []byte
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			partial = append(partial, buf[:n]...)
			for {
				i := strings.IndexByte(string(partial), '\n')
				if i < 0 {
					break
				}
				line := partial[:i]
				partial = partial[i+1:]
				_ = rc.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if _, err := fmt.Fprintf(w, "data: %s\n\n", line); err != nil {
					return
				}
			}
			fl.Flush()
			continue
		}
		if rerr != nil && !errors.Is(rerr, io.EOF) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			_ = rc.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := io.WriteString(w, ": keepalive\n\n"); err != nil {
				return
			}
			fl.Flush()
			if st, err := os.Stat(path); err == nil {
				if cur, err2 := f.Stat(); err2 == nil && !os.SameFile(st, cur) {
					_ = f.Close()
					if f, err = os.Open(path); err != nil { //nolint:gosec // same operator-owned path
						return
					}
				}
			}
		}
	}
}
