package bacnet

import (
	"context"
	"net"
	"time"

	"github.com/rom/xproxy/internal/acceptgroup"

	"github.com/rom/xproxy/internal/anomaly"
	wire "github.com/rom/xproxy/internal/bacnet"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/limits"
	"github.com/rom/xproxy/internal/proxy"
)

// server is one kind: bacnet listener.
type server struct {
	host proxy.Host
	cfg  config.Listener
	m    *config.BACnetListener
	name string

	// pc is the socket clients send to, and device the one this relay
	// speaks to the building from. There is one of each: BACnet pairs an
	// answer to a question by invoke identifier rather than by port, so a
	// socket per exchange would be a file descriptor per poll.
	pc net.PacketConn

	policy  *policy
	pend    *pending
	limiter *limits.KeyedLimiter
	// anomaly is the behavioural models, nil when the block is off.
	anomaly *anomaly.Detector

	logRequests bool
	alertOnDeny bool
	reject      string
	timeout     time.Duration
	window      time.Duration
	maxReplies  int

	// running tracks the two goroutines this listener runs and the
	// shutdown that waits for them. It is acceptgroup rather than a bare
	// WaitGroup for the reason that package exists: a listener can be shut
	// down at the moment it starts, and a WaitGroup's Add must not race its
	// Wait -- the failure is not a warning but a goroutine that either is
	// or is not waited for, reading a socket the process is about to close.
	running acceptgroup.Group
}

func newServer(host proxy.Host, cfg config.Listener, pc net.PacketConn) (*server, error) {
	m := cfg.BACnet
	p, err := compile(m)
	if err != nil {
		return nil, err
	}
	t := &server{
		host: host, cfg: cfg, m: m, name: cfg.Name, pc: pc, policy: p,
		logRequests: boolOr(m.LogRequests, true),
		alertOnDeny: boolOr(m.AlertOnDeny, true),
		reject:      responseMode(m.DenyResponse),
		timeout:     or(m.RequestTimeout.D(), 10*time.Second),
		window:      or(m.BroadcastReplyWindow.D(), 5*time.Second),
		maxReplies:  or(m.MaxBroadcastReplies, 64),
	}
	// The outstanding broadcasts are bounded at a sixteenth of the
	// confirmed requests: a broadcast costs the estate far more than a
	// unicast does, so the table that holds them is smaller on purpose.
	t.pend = newPending(or(m.MaxPending, 512), max(or(m.MaxPending, 512)/16, 8), t.timeout)
	if m.RateLimit > 0 {
		burst := m.RateBurst
		if burst <= 0 {
			burst = m.RateLimit
		}
		t.limiter = limits.NewKeyedLimiter(float64(m.RateLimit), burst, 4096)
	}
	if t.anomaly, err = anomaly.FromConfig(m.Anomaly, time.Now()); err != nil {
		return nil, err
	}
	return t, nil
}

// responseMode resolves how a refusal is answered.
func responseMode(s string) string {
	switch s {
	case "error", "drop":
		return s
	default:
		return "reject"
	}
}

// maxMessage is the largest datagram this listener will read.
func (t *server) maxMessage() int { return min(t.policy.maxMessage, wire.MaxMessage) }

// enforcing reports whether this listener acts on its policy or only
// records what it would have done.
func (t *server) enforcing() bool { return !t.cfg.Shadowing() }

func (t *server) shutdown(ctx context.Context) {
	t.running.Close()
	t.running.Wait(ctx)
	_ = t.pc.Close()
}
