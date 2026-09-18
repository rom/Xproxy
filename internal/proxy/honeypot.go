package proxy

import (
	"errors"
	"io"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/cluster"
)

// Decoys are the built-in honeypot bodies. Each looks like a real page
// of the named kind to a scanner and contains nothing an operator would
// mind being read.
var decoys = map[string]struct{ contentType, body string }{
	"wp-login": {"text/html; charset=utf-8", `<!DOCTYPE html>
<html lang="en-US"><head><meta charset="UTF-8"><title>Log In &lsaquo; WordPress</title>
<link rel="stylesheet" href="/wp-admin/css/login.min.css"></head>
<body class="login login-action-login wp-core-ui"><div id="login"><h1><a href="https://wordpress.org/">Powered by WordPress</a></h1>
<form name="loginform" id="loginform" action="/wp-login.php" method="post">
<p><label for="user_login">Username or Email Address</label><input type="text" name="log" id="user_login" class="input" size="20"></p>
<p><label for="user_pass">Password</label><input type="password" name="pwd" id="user_pass" class="input" size="20"></p>
<p class="submit"><input type="submit" name="wp-submit" id="wp-submit" class="button button-primary" value="Log In"><input type="hidden" name="redirect_to" value="/wp-admin/"></p>
</form></div></body></html>
`},
	"env": {"text/plain; charset=utf-8", `APP_NAME=Laravel
APP_ENV=production
APP_KEY=base64:ZGVjb3kta2V5LW5vdC1yZWFsLWRvLW5vdC11c2UtMDAwMDA=
APP_DEBUG=false
APP_URL=http://localhost
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=app
DB_USERNAME=app
DB_PASSWORD=decoy-Passw0rd
REDIS_HOST=127.0.0.1
MAIL_MAILER=smtp
AWS_ACCESS_KEY_ID=AKIADECOY000000EXAMPLE
AWS_SECRET_ACCESS_KEY=decoy/secret/not/real/0000000000000000
`},
	"git-config": {"text/plain; charset=utf-8", `[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = git@git.example.internal:platform/web.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
`},
	"phpinfo": {"text/html; charset=utf-8", `<!DOCTYPE html><html><head><title>phpinfo()</title></head><body>
<div class="center"><table><tr class="h"><td><h1 class="p">PHP Version 7.4.33</h1></td></tr></table>
<table><tr><td class="e">System </td><td class="v">Linux web01 5.4.0-150-generic #167-Ubuntu SMP x86_64 </td></tr>
<tr><td class="e">Server API </td><td class="v">FPM/FastCGI </td></tr>
<tr><td class="e">Loaded Configuration File </td><td class="v">/etc/php/7.4/fpm/php.ini </td></tr>
<tr><td class="e">allow_url_fopen </td><td class="v">On </td></tr><tr><td class="e">display_errors </td><td class="v">Off </td></tr>
</table></div></body></html>
`},
	"admin-login": {"text/html; charset=utf-8", `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Administration</title>
<meta name="viewport" content="width=device-width, initial-scale=1"></head>
<body><main><h1>Administration</h1><form method="post" action="/admin/login">
<label>User <input name="username" autocomplete="username"></label>
<label>Password <input type="password" name="password" autocomplete="current-password"></label>
<button type="submit">Sign in</button></form></main></body></html>
`},
	"robots": {"text/plain; charset=utf-8", `User-agent: *
Disallow: /admin/
Disallow: /backup/
Disallow: /private/
Disallow: /wp-admin/
Disallow: /.git/
`},
}

// readBounded reads a file of at most limit bytes.
func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // operator supplied path from the configuration
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("file larger than the bound")
	}
	return b, nil
}

// DecoyNames lists the built-in decoys.
func DecoyNames() []string {
	names := make([]string, 0, len(decoys))
	for n := range decoys {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Mark is a client that hit a honeypot.
type Mark struct {
	Address string    `json:"address"`
	Route   string    `json:"route"`
	Hits    int       `json:"hits"`
	First   time.Time `json:"first"`
	Last    time.Time `json:"last"`
	Expires time.Time `json:"expires"`
}

const maxMarks = 65536

// marks remembers clients that touched a honeypot so that their later
// requests on other routes are labelled. It is bounded and sweeps expired
// entries lazily.
type marks struct {
	mu sync.Mutex
	m  map[netip.Addr]*Mark
}

func newMarks() *marks { return &marks{m: map[netip.Addr]*Mark{}} }

func (m *marks) add(ip netip.Addr, route string, ttl time.Duration, now time.Time) {
	if !ip.IsValid() {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.m[ip]; ok {
		e.Hits++
		e.Last = now
		e.Route = route
		e.Expires = now.Add(ttl)
		return
	}
	if len(m.m) >= maxMarks {
		m.sweep(now)
		if len(m.m) >= maxMarks {
			return // full of live marks: keep what we have rather than grow
		}
	}
	m.m[ip] = &Mark{Address: ip.String(), Route: route, Hits: 1, First: now, Last: now, Expires: now.Add(ttl)}
}

func (m *marks) sweep(now time.Time) {
	for ip, e := range m.m {
		if now.After(e.Expires) {
			delete(m.m, ip)
		}
	}
}

func (m *marks) marked(ip netip.Addr, now time.Time) bool {
	if !ip.IsValid() {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.m[ip]
	if !ok {
		return false
	}
	if now.After(e.Expires) {
		delete(m.m, ip)
		return false
	}
	return true
}

func (m *marks) list(now time.Time) []Mark {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweep(now)
	out := make([]Mark, 0, len(m.m))
	for _, e := range m.m {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Last.After(out[j].Last) })
	return out
}

func (m *marks) remove(ip netip.Addr) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.m[ip]
	delete(m.m, ip)
	return ok
}

// HoneypotMarks lists clients currently marked by a honeypot, most recent
// first.
func (s *Server) HoneypotMarks() []Mark { return s.marks.list(time.Now()) }

// UnmarkHoneypot forgets a marked client.
func (s *Server) UnmarkHoneypot(ip netip.Addr) bool {
	ok := s.marks.remove(ip.Unmap())
	if ok {
		s.publishEvent(cluster.Event{Kind: eventHoneypotUnmark, Key: ip.Unmap().String(), Until: time.Now().Add(time.Minute)})
	}
	return ok
}

// honeypot serves a decoy. The client is recorded as a security event,
// marked for the configured time and counted towards the honeypot ban
// reason; the response itself looks like the real thing. An optional
// delay holds the connection in a tarpit slot, never in a concurrency
// slot.
func (s *Server) honeypot(rw *responseWriter, r *http.Request, st *reqState, cr *compiledRoute, release func()) {
	hp := cr.cfg.Honeypot
	now := time.Now()
	s.stats.HoneypotHits.Add(1)
	st.denied = "honeypot"
	s.logs.SecurityEvent(r.Context(), "honeypot", "honeypot",
		"request_id", st.id, "client_ip", st.clientIP.String(), "method", r.Method,
		"host", r.Host, "path", r.URL.Path, "query_len", len(r.URL.RawQuery), "route", st.route,
		"user_agent", r.UserAgent(), "referer", r.Referer(), "decoy", hp.Decoy)
	s.marks.add(st.clientIP, cr.cfg.Name, hp.Mark.D(), now)
	s.publishEvent(cluster.Event{Kind: eventHoneypotMark, Key: st.clientIP.String(), Route: cr.cfg.Name, Until: now.Add(hp.Mark.D())})
	if bl := s.bans.Load(); bl != nil {
		bl.Observe(st.clientIP, "honeypot")
	}
	if hp.Delay > 0 {
		release() // a held decoy must not occupy a request slot (see max_tarpits)
		if tpRelease, ok := s.tarpits.Acquire(); ok {
			select {
			case <-time.After(hp.Delay.D()):
			case <-r.Context().Done():
				tpRelease()
				s.stats.ClientAborts.Add(1)
				rw.status = 499
				rw.wrote = true
				return
			}
			tpRelease()
		} else {
			s.stats.TarpitOverflow.Add(1)
		}
	}
	h := rw.Header()
	h.Set("Content-Type", cr.honeypotType)
	h.Set("Cache-Control", "no-store")
	applyHeaderOps(h, cr.cfg.ResponseHeaders)
	rw.WriteHeader(hp.Status)
	if r.Method != http.MethodHead {
		_, _ = rw.Write(cr.honeypotBody)
	}
}
