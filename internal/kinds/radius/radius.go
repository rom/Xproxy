package radius

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/rom/xproxy/internal/acceptgroup"
	"github.com/rom/xproxy/internal/anomaly"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/limits"
	"github.com/rom/xproxy/internal/proxy"
	wire "github.com/rom/xproxy/internal/radius"
)

// server is one kind: radius listener.
type server struct {
	host proxy.Host
	cfg  config.Listener
	r    *config.RADIUSListener
	name string

	// pc is the socket the equipment sends to, and up the one this relay
	// speaks to the servers from. There is one of each: RADIUS pairs an
	// answer to a question by source address and identifier, so a socket
	// per exchange would be a file descriptor per login.
	pc net.PacketConn

	policy  *policy
	pend    *pending
	limiter *limits.KeyedLimiter
	anomaly *anomaly.Detector

	// secret is what arriving packets are verified with, and upSecret what
	// forwarded ones are signed with. upSecret is secret unless the
	// configuration gave a second one, which is what makes this listener a
	// secret boundary.
	secret, upSecret []byte

	logRequests bool
	alertOnDeny bool
	reject      bool
	timeout     time.Duration

	running acceptgroup.Group
}

func newServer(host proxy.Host, cfg config.Listener, pc net.PacketConn) (*server, error) {
	r := cfg.RADIUS
	p, err := compile(r)
	if err != nil {
		return nil, fmt.Errorf("listener %s: %w", cfg.Name, err)
	}
	t := &server{
		host: host, cfg: cfg, r: r, name: cfg.Name, pc: pc, policy: p,
		logRequests: boolOr(r.LogRequests, true),
		alertOnDeny: boolOr(r.AlertOnDeny, true),
		reject:      r.DenyResponse != "drop",
		timeout:     or(r.RequestTimeout.D(), 10*time.Second),
	}
	if t.secret, err = loadSecret(r.SecretFile); err != nil {
		return nil, fmt.Errorf("listener %s: secret_file: %w", cfg.Name, err)
	}
	if t.upSecret = t.secret; r.UpstreamSecretFile != "" {
		if t.upSecret, err = loadSecret(r.UpstreamSecretFile); err != nil {
			return nil, fmt.Errorf("listener %s: upstream_secret_file: %w", cfg.Name, err)
		}
	}
	t.pend = newPending(or(r.MaxPending, 256), t.timeout, len(t.secret) > 0)
	if r.RateLimit > 0 {
		burst := r.RateBurst
		if burst <= 0 {
			burst = r.RateLimit
		}
		t.limiter = limits.NewKeyedLimiter(float64(r.RateLimit), burst, 4096)
	}
	if t.anomaly, err = anomaly.FromConfig(r.Anomaly, time.Now()); err != nil {
		return nil, err
	}
	return t, nil
}

// loadSecret reads a shared secret file: one line, with the trailing
// newline an editor leaves removed.
//
// Nothing else is trimmed. A RADIUS secret may legitimately contain
// spaces, and a loader that trimmed them would authenticate with a
// different secret than the one in the file -- which presents as every
// packet failing its digest, with no indication why.
func loadSecret(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path) //nolint:gosec // the path is the operator's own configuration
	if err != nil {
		return nil, err
	}
	b = bytes.TrimRight(b, "\r\n")
	if len(b) == 0 {
		return nil, fmt.Errorf("%s is empty", path)
	}
	return b, nil
}

// reading reports whether this listener can verify and re-sign, which is
// the difference between a relay that authenticates what it carries and one
// that only filters it.
func (t *server) reading() bool { return len(t.secret) > 0 }

// enforcing reports whether this listener acts on its policy or only
// records what it would have done.
func (t *server) enforcing() bool { return !t.r.MonitorOnly && !t.cfg.Shadowing() }

// maxMessage is the largest datagram this listener will read.
func (t *server) maxMessage() int {
	return min(or(t.r.MaxMessageBytes, wire.MaxMessage), wire.MaxMessage)
}

func (t *server) shutdown(ctx context.Context) {
	t.running.Close()
	t.running.Wait(ctx)
	_ = t.pc.Close()
}

// boolOr reads an optional boolean with a default.
func boolOr(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

// or returns a value or a default when it is zero.
func or[T comparable](v, def T) T {
	var zero T
	if v == zero {
		return def
	}
	return v
}

// lower copies a list of names folded for comparison, which is how every
// name list on this protocol is matched: RADIUS user names are
// case-insensitive on every server that fronts Active Directory, and a
// policy that was not would admit `Bob` and refuse `bob`.
func lower(in []string) map[string]bool {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]bool, len(in))
	for _, s := range in {
		out[strings.ToLower(strings.TrimSpace(s))] = true
	}
	return out
}
