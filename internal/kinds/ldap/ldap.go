// Package ldap serves a kind: ldap listener: an LDAP and LDAPS relay in
// front of a directory.
//
// A directory is the one service in an estate that knows who everybody is,
// and LDAP is how everything asks. That makes it two things at once: the
// authentication path for every application that has not moved to OIDC, and
// the most complete map of an organisation that exists anywhere on its
// network -- every person, every group, every service account, every machine,
// with the group memberships that say who is an administrator.
//
// Five things are deliberate in the data path.
//
// **A bind with a name and an empty password is refused by default.** RFC
// 4513 §5.1.2 calls it an unauthenticated bind and says it is anonymous; a
// great many directories answer it with *success*; and a great many
// applications are written as "bind as the user, and if it worked the
// password was right". That is an authentication bypass in the application,
// reachable with an empty string, and the directory cannot tell the
// difference. The relay can.
//
// **A password in the clear is refused by default.** LDAP on port 389 with a
// simple bind puts a directory password on the wire in plaintext, and the
// client library that did it will not tell anyone. require_tls is the line
// that stops it, and it is not shadowable: by the time a policy could be
// consulted the password has already gone past.
//
// **The attribute policy applies to the answer, not only to the question.** A
// search that asks for "*" never names userPassword and the directory sends
// it anyway. So a denied attribute is *removed from the entry* on its way
// back -- which is the half a request-side access list cannot do -- while a
// request that names one plainly is refused, because stripping it would
// answer a plain question with a silence the client cannot tell from an empty
// directory.
//
// **A subtree is a suffix compared one relative name at a time.** A string
// suffix test admits dc=notexample,dc=com under example,dc=com, and a string
// prefix test admits ou=peoplex under ou=people. Directory names are a tree
// and are compared as one.
//
// **The entries are counted and the filter is measured.** An unbounded
// subtree search with (objectClass=*) is how a directory is copied, and a
// filter of a hundred substring terms with leading wildcards is a hundred
// full scans of a request two hundred octets long. Both are bounded, and the
// search is cut with the directory's own sizeLimitExceeded so the client
// knows it got part of an answer.
package ldap

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/config"
	wire "github.com/rom/xproxy/internal/ldap"
	"github.com/rom/xproxy/internal/limits"
	"github.com/rom/xproxy/internal/proxy"
	"github.com/rom/xproxy/internal/safe"
	"github.com/rom/xproxy/internal/tlsconf"
	"github.com/rom/xproxy/internal/upstream"
)

// server is one kind: ldap listener.
type server struct {
	host   proxy.Host
	cfg    config.Listener
	m      *config.LDAPListener
	ln     net.Listener
	tlsCfg *tls.Config
	upTLS  *tls.Config

	policy  *Policy
	limiter *limits.KeyedLimiter
	binds   *limits.KeyedLimiter

	open atomic.Int64
	wg   sync.WaitGroup
	mu   sync.Mutex
	once sync.Once
	cons map[net.Conn]struct{}
	done chan struct{}
}

func newServer(host proxy.Host, cfg config.Listener, ln net.Listener, tc *tls.Config) (*server, error) {
	m := cfg.LDAP
	t := &server{host: host, cfg: cfg, m: m, ln: ln, tlsCfg: tc,
		cons: map[net.Conn]struct{}{}, done: make(chan struct{})}
	var err error
	if t.policy, err = compile(m, time.Now); err != nil {
		return nil, err
	}
	if m.UpstreamTLSMode == "implicit" || m.UpstreamTLSMode == "starttls" {
		uc, _, err := tlsconf.Client(m.UpstreamTLS)
		if err != nil {
			return nil, fmt.Errorf("ldap upstream_tls: %w", err)
		}
		t.upTLS = uc
	}
	if m.RateLimit > 0 {
		t.limiter = limits.NewKeyedLimiter(float64(m.RateLimit), burstOf(m.RateBurst, m.RateLimit), 65536)
	}
	if m.BindRateLimit > 0 {
		t.binds = limits.NewKeyedLimiter(float64(m.BindRateLimit),
			burstOf(m.BindRateBurst, m.BindRateLimit), 65536)
	}
	return t, nil
}

func burstOf(burst, rate int) int {
	if burst > 0 {
		return burst
	}
	return rate
}

func (t *server) maxOutstanding() int {
	if n := t.m.MaxOutstanding; n > 0 {
		return n
	}
	return 32
}

func (t *server) maxConnections() int {
	if n := t.m.MaxConnections; n > 0 {
		return n
	}
	return 256
}

func (t *server) maxMessage() int {
	if n := t.m.MaxMessageBytes; n > 0 {
		return n
	}
	return 1 << 18
}

func (t *server) idleTimeout() time.Duration {
	if d := t.m.IdleTimeout.D(); d > 0 {
		return d
	}
	return 300 * time.Second
}

func (t *server) requestTimeout() time.Duration {
	if d := t.m.RequestTimeout.D(); d > 0 {
		return d
	}
	return 30 * time.Second
}

func (t *server) connectTimeout() time.Duration {
	if d := t.m.ConnectTimeout.D(); d > 0 {
		return d
	}
	return 5 * time.Second
}

// enforcing says whether this listener refuses for policy or only records
// what it would have refused.
func (t *server) enforcing() bool { return t.enforcement().Enforcing() }

// enforcement folds this listener's reasons not to enforce into one answer, so
// that the precedence, and the name a status view reports, are the same on
// every kind.
func (t *server) enforcement() config.Enforcement {
	e := config.Enforcement{Shadow: t.cfg.Shadowing()}
	return e
}

// alerts says whether a refusal writes a security event.
func (t *server) alerts() bool { return t.m.AlertOnDeny == nil || *t.m.AlertOnDeny }

func (t *server) logBinds() bool  { return t.m.LogBinds == nil || *t.m.LogBinds }
func (t *server) logWrites() bool { return t.m.LogWrites == nil || *t.m.LogWrites }

func (t *server) serve() {
	for {
		c, err := t.ln.Accept()
		if err != nil {
			select {
			case <-t.done:
				return
			default:
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			var opErr *net.OpError
			if errors.As(err, &opErr) && strings.Contains(err.Error(), "closed") {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if t.open.Add(1) > int64(t.maxConnections()) {
			t.open.Add(-1)
			t.host.Counters().LDAPRejected.Add(1)
			t.host.Counters().Refuse("ldap", "max_connections")
			_ = c.Close()
			continue
		}
		if !t.track(c) {
			t.open.Add(-1)
			_ = c.Close()
			return
		}
		go func() {
			defer t.wg.Done()
			defer t.open.Add(-1)
			defer t.untrack(c)
			defer safe.Guard("ldap session")
			t.handle(c)
		}()
	}
}

func (t *server) shutdown(ctx context.Context) {
	t.once.Do(func() {
		t.mu.Lock()
		close(t.done)
		t.mu.Unlock()
		if t.ln != nil {
			_ = t.ln.Close()
		}
	})
	finished := make(chan struct{})
	go func() {
		t.wg.Wait()
		close(finished)
	}()
	select {
	case <-finished:
	case <-ctx.Done():
		t.mu.Lock()
		for c := range t.cons {
			_ = c.Close()
		}
		t.mu.Unlock()
		<-finished
	}
}

func (t *server) track(c net.Conn) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	select {
	case <-t.done:
		return false
	default:
	}
	t.cons[c] = struct{}{}
	t.wg.Add(1)
	return true
}

func (t *server) untrack(c net.Conn) {
	t.mu.Lock()
	delete(t.cons, c)
	t.mu.Unlock()
}

// dialDirectory opens a connection to the directory.
func (t *server) dialDirectory(key string) (net.Conn, *upstream.Pool, *upstream.Endpoint, error) {
	pool := t.host.Pool(t.m.Upstream)
	if pool == nil {
		return nil, nil, nil, fmt.Errorf("upstream %q has no pool", t.m.Upstream)
	}
	tried := map[*upstream.Endpoint]bool{}
	for attempt := 0; attempt < 3; attempt++ {
		e, _ := pool.Pick(key, "", tried, upstream.CanaryAny)
		if e == nil {
			break
		}
		tried[e] = true
		d := net.Dialer{Timeout: t.connectTimeout()}
		c, err := d.DialContext(context.Background(), "tcp", e.Address)
		pool.Begin(e)
		if err != nil {
			pool.End(e, true, 0)
			t.host.Logs().Error.Warn("ldap directory dial failed", "listener", t.cfg.Name,
				"endpoint", e.Address, "error", err.Error())
			continue
		}
		return c, pool, e, nil
	}
	return nil, pool, nil, errors.New("no reachable directory endpoint")
}

// upgradeUpstream wraps the directory connection in TLS, either from the
// first octet or after a StartTLS this relay performs on the client's behalf.
func (t *server) upgradeUpstream(up net.Conn, address string) (net.Conn, error) {
	if t.upTLS == nil {
		return up, nil
	}
	c := t.upTLS.Clone()
	if c.ServerName == "" && !c.InsecureSkipVerify {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			host = address
		}
		c.ServerName = host
	}
	if t.m.UpstreamTLSMode == "starttls" {
		if err := startTLSUpstream(up, t.maxMessage(), t.requestTimeout()); err != nil {
			return nil, err
		}
	}
	tc := tls.Client(up, c)
	if err := tc.HandshakeContext(context.Background()); err != nil {
		return nil, err
	}
	return tc, nil
}

// startTLSUpstream asks the directory for StartTLS and waits for its answer,
// which is the one exchange this relay makes on its own behalf rather than
// relaying.
func startTLSUpstream(up net.Conn, max int, timeout time.Duration) error {
	_ = up.SetDeadline(time.Now().Add(timeout))
	defer func() { _ = up.SetDeadline(time.Time{}) }()
	if _, err := up.Write(wire.StartTLSRequest(1)); err != nil {
		return err
	}
	rd := wire.NewReader(up, max)
	raw, err := rd.Next()
	if err != nil {
		return err
	}
	m, err := wire.Parse(raw)
	if err != nil {
		return err
	}
	if m.Op != wire.OpExtendedResponse || m.Result == nil {
		return fmt.Errorf("ldap: the directory answered StartTLS with %s", m.Op)
	}
	if m.Result.Code != wire.ResultSuccess {
		return fmt.Errorf("ldap: the directory refused StartTLS: %s", m.Result.Code)
	}
	return nil
}
