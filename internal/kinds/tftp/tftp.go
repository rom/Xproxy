// Package tftp serves a kind: tftp listener: a TFTP relay in front of the
// servers that move firmware, configurations and boot images around an
// estate.
//
// TFTP is the protocol under provisioning. A switch pulls its firmware over
// it, a machine with no operating system yet pulls a boot image, a telephone
// pulls its configuration, and a network engineer pushes a running
// configuration off a router with it. It has no authentication of any kind:
// no user, no password, no token, no transport security, and no extension
// that adds one. A request is a filename and a mode, and a server that
// receives one answers it.
//
// Nothing about that can be fixed in the servers, because the clients are
// switches and telephones and boot ROMs. So the relay is the only place a
// policy can live, and four things are deliberate in this one.
//
// **The filename is read as a path and classified.** There is no identity to
// decide by, so the decision is the address it came from and the path it
// asked for -- and a path is where this protocol has been exploited for forty
// years. The shapes are refused rather than the spellings: see
// internal/tftp's Class, and note that three of those shapes are refusals no
// shadow mode defers, because they mean this relay and the server behind it
// are reading different filenames.
//
// **A write is a different decision from a read, and the default is no.** A
// write is a device putting a file onto the server, which is how a
// configuration leaves an estate and how firmware arrives in it.
//
// **The amplification is bounded by rewriting rather than refusing.** A
// twenty-octet read request yields a whole file to whatever address the
// datagram claimed to come from, and RFC 7440's window size multiplies it: a
// window of sixty-four is sixty-four data packets per acknowledgement. A
// request asking for more than the bound is rewritten to the bound and
// forwarded, because a device whose TFTP client nobody can reconfigure is the
// normal case in an estate and a bound that only refuses is a bound somebody
// turns off. The transfer's total size is bounded too, and that is the bound
// that matters on a write: a write has no natural end, because the client
// stops when it stops.
//
// **A transfer gets a socket of its own, and only two addresses may use it.**
// TFTP moves to an ephemeral port pair after the first packet: the server
// answers from a new port, and the rest of the transfer runs between that
// port and the client's. So a transfer here is one unconnected socket that
// speaks to exactly two addresses -- the client's transfer identifier and the
// first port the server answered from -- and a datagram from anywhere else is
// dropped and counted rather than forwarded. On a protocol with no integrity
// protection, that third address is the whole attack: a packet injected into
// a firmware transfer is firmware.
//
// What this relay does not do is interpret a transfer's contents. What is
// inside a firmware image is the estate's business; that the image is one the
// policy allows, of a size the policy allows, to a path the policy allows, is
// the relay's.
package tftp

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/limits"
	"github.com/rom/xproxy/internal/proxy"
	wire "github.com/rom/xproxy/internal/tftp"
)

// server is one kind: tftp listener.
type server struct {
	host proxy.Host
	cfg  config.Listener
	m    *config.TFTPListener
	pc   net.PacketConn

	policy  *Policy
	limiter *limits.KeyedLimiter

	wg   sync.WaitGroup
	once sync.Once
	done chan struct{}

	// live is the transfer table, keyed by the client's transfer
	// identifier. It is what makes a retransmitted request recognisable as
	// one, and what the concurrency bounds count.
	mu    sync.Mutex
	live  map[string]*transfer
	perIP map[netip.Addr]int
}

func newServer(host proxy.Host, cfg config.Listener, pc net.PacketConn) (*server, error) {
	m := cfg.TFTP
	t := &server{host: host, cfg: cfg, m: m, pc: pc, done: make(chan struct{}),
		live: map[string]*transfer{}, perIP: map[netip.Addr]int{}}
	var err error
	if t.policy, err = compile(m, time.Now); err != nil {
		return nil, err
	}
	if m.RateLimit > 0 {
		burst := m.RateBurst
		if burst <= 0 {
			burst = m.RateLimit
		}
		t.limiter = limits.NewKeyedLimiter(float64(m.RateLimit), burst, 65536)
	}
	return t, nil
}

// The bounds, each with the default it has when the file says nothing. They
// are read through methods rather than filled in at load so that a zero in
// the configuration means "the default" everywhere, including in the tests
// that build a listener by hand.

func (t *server) maxTransfers() int {
	if n := t.m.MaxTransfers; n > 0 {
		return n
	}
	return 64
}

func (t *server) maxPerClient() int {
	if n := t.m.MaxTransfersPerClient; n > 0 {
		return n
	}
	return 8
}

func (t *server) transferTimeout() time.Duration {
	if d := t.m.TransferTimeout.D(); d > 0 {
		return d
	}
	return 5 * time.Minute
}

func (t *server) idleTimeout() time.Duration {
	if d := t.m.IdleTimeout.D(); d > 0 {
		return d
	}
	return 15 * time.Second
}

// enforcing says whether this listener refuses for policy or only records
// what it would have refused.
func (t *server) enforcing() bool { return !t.cfg.Shadowing() }

// alerts says whether a refusal writes a security event.
func (t *server) alerts() bool { return t.m.AlertOnDeny == nil || *t.m.AlertOnDeny }

// logTransfers says whether a finished transfer writes an access line.
func (t *server) logTransfers() bool { return t.m.LogTransfers == nil || *t.m.LogTransfers }

// answering says whether a refusal is told to the client. drop leaves the
// client retransmitting until it times out, which is why error is the
// default: a device that is told no stops.
func (t *server) answering() bool { return t.m.DenyResponse != "drop" }

func (t *server) serve() { t.serveRequests() }

func (t *server) shutdown(ctx context.Context) {
	t.once.Do(func() {
		close(t.done)
		if t.pc != nil {
			_ = t.pc.Close()
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
		// A transfer can be minutes long, so a shutdown that waited for one
		// to finish would be a shutdown that hangs. The sockets are closed
		// and each transfer ends on the read error that follows.
		t.mu.Lock()
		for _, x := range t.live {
			_ = x.sock.Close()
		}
		t.mu.Unlock()
		<-finished
	}
}

// admit puts a transfer in the table, or says why it may not start.
//
// The two bounds are separate because they answer different questions. The
// listener bound is about this process: each transfer holds a socket, and a
// file descriptor table is a real resource. The per-client bound is about one
// device: a client with eight transfers in flight is a client that has
// stopped reading its answers, and on a protocol with no session there is
// nothing else that would notice.
func (t *server) admit(x *transfer) (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	select {
	case <-t.done:
		return "shutting_down", false
	default:
	}
	key := x.client.String()
	if _, dup := t.live[key]; dup {
		// The same transfer identifier is already transferring. This is a
		// retransmitted request, which happens whenever the first answer was
		// lost: the transfer's own socket will answer it, so the duplicate is
		// dropped rather than started again.
		return "duplicate", false
	}
	if len(t.live) >= t.maxTransfers() {
		return "too_many_transfers", false
	}
	if t.perIP[x.ip] >= t.maxPerClient() {
		return "too_many_per_client", false
	}
	t.live[key] = x
	t.perIP[x.ip]++
	t.wg.Add(1)
	c := t.host.Counters()
	c.TFTPTransfers.Add(1)
	c.TFTPTransfersOpen.Add(1)
	return "", true
}

// release takes a finished transfer out of the table.
func (t *server) release(x *transfer) {
	t.mu.Lock()
	key := x.client.String()
	if t.live[key] == x {
		delete(t.live, key)
	}
	if n := t.perIP[x.ip]; n <= 1 {
		delete(t.perIP, x.ip)
	} else {
		t.perIP[x.ip] = n - 1
	}
	t.mu.Unlock()
	t.host.Counters().TFTPTransfersOpen.Add(-1)
	t.wg.Done()
}

// transfer is one TFTP transfer in flight: its own socket, the two addresses
// allowed to use it, and the bounds it runs under.
type transfer struct {
	t    *server
	sock net.PacketConn
	// client is the client's transfer identifier: the address its first
	// request came from, and the only address this transfer answers.
	client *net.UDPAddr
	ip     netip.Addr
	// up is the server's address. It starts as the request port and becomes
	// the server's transfer identifier when it first answers; only that one
	// port may speak for the server afterwards.
	up        *net.UDPAddr
	sawServer bool

	op   wire.Op
	path wire.Path
	mode string
	rule string

	// block and window are what the transfer is actually running at: the
	// protocol's own defaults until an option acknowledgement grants
	// something else. block is what says a data packet is the last one,
	// because RFC 1350 ends a transfer with a short one.
	block  int
	window int
	// ask is what the forwarded request asked for, after the bounds were
	// applied to it. It is the ceiling an option acknowledgement is checked
	// against: a server may answer with less and never with more.
	ask asked

	maxBytes int64
	bytes    int64
	packets  int64
	// last is whether a short data packet has gone past, so the
	// acknowledgement that follows it ends the transfer.
	last  bool
	start time.Time
}

// asked is what a forwarded request asked for, after this relay's bounds were
// applied to it.
type asked struct {
	block, window int
}
