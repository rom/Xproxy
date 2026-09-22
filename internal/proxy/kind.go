package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sort"
	"sync"

	"github.com/rom/xproxy/internal/ban"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/dns"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/tlsconf"
	"github.com/rom/xproxy/internal/upstream"
)

// Host is what a listener kind needs from the server that hosts it.
//
// It is small on purpose. A kind reads counters, writes log records,
// consults the ban list, finds its upstream pool and offers bytes to the
// packet capture — and that is the whole of it. Everything else a kind
// does is its own protocol's business, which is why a kind can live in
// its own package and its own binary.
//
// *Server implements it. Nothing else needs to, except a test that wants
// a kind without a server around it.
type Host interface {
	// Logs are the access, security, audit and error streams.
	Logs() *logging.Logs
	// Counters are the process-wide counters.
	Counters() *Stats
	// Bans is the ban list, or nil when the configuration has none.
	Bans() *ban.List
	// Pool returns a configured upstream pool by name, or nil.
	Pool(name string) *upstream.Pool
	// Limits are the server-wide bounds a listener inherits.
	Limits() config.Limits
}

// Instance is a listener kind's running data plane: one bound socket,
// serving until it is shut down.
type Instance interface {
	// Serve accepts until the socket closes. The engine calls it on a
	// goroutine of its own and expects it to return when serving ends.
	Serve()
	// Shutdown stops accepting and drains what is in flight, within
	// the deadline on ctx.
	Shutdown(ctx context.Context)
}

// Closer is an instance with resources to release after it has drained.
type Closer interface{ Close() }

// Applier is an instance whose policy can be replaced where it stands,
// so a reload does not have to rebind the socket and drop what is
// connected to it.
type Applier interface {
	Apply(lc config.Listener) error
}

// Setup is what the engine hands a kind at build time. Everything in it
// has already been through the parts of binding that are the same for
// every kind: the accept socket is limited and, where the listener asked
// for it, unwrapped from the PROXY protocol; the TLS configuration is
// built, attached to the ticket keyring and the fingerprint table, and
// its stapling has started.
type Setup struct {
	// Host is the server.
	Host Host
	// Config is this listener's section of the configuration.
	Config config.Listener
	// Net is the accept socket, wrapped.
	Net net.Listener
	// TLS is built from the listener's tls section, or nil when it has
	// none. A kind that speaks an in-band upgrade — STARTTLS, AUTH TLS
	// — takes it and terminates the handshake itself, because the
	// session has to read cleartext first and owns the deadline while
	// it does. A kind whose TLS is implicit wraps Net with it.
	TLS *tls.Config
	// Packet opens a datagram socket on this listener's address,
	// honouring socket activation. suffix distinguishes a second
	// socket on one listener (DNS over QUIC beside DNS over TLS).
	// A kind that wants no datagrams never calls it.
	Packet func(suffix string) (net.PacketConn, error)
}

// Kind is one listener kind: its name in the configuration, what the
// engine prepares before building one, and how one is built.
//
// A kind is registered from its own package's init, and a daemon links
// the kinds it serves. That is the whole of the mechanism that decides
// what code is in which binary.
type Kind struct {
	// Name is the "kind:" value.
	Name string
	// TLS asks the engine to build a *tls.Config from the listener's
	// tls section and put it in Setup.
	TLS bool
	// New builds the instance. On error the engine releases the socket.
	New func(*Setup) (Instance, error)
}

var (
	kindMu sync.RWMutex
	kinds  = map[string]Kind{}
)

// Register adds a kind. It panics on a name the roster does not know or
// on a second registration of one, because both are build-time mistakes
// in a binary's own import list rather than anything an operator did.
func Register(k Kind) {
	if k.Name == "" || k.New == nil {
		panic("proxy: a listener kind needs a name and a constructor")
	}
	kindMu.Lock()
	defer kindMu.Unlock()
	if _, dup := kinds[k.Name]; dup {
		panic(fmt.Sprintf("proxy: listener kind %q registered twice", k.Name))
	}
	kinds[k.Name] = k
}

// kindFor returns a registered kind.
func kindFor(name string) (Kind, bool) {
	kindMu.RLock()
	defer kindMu.RUnlock()
	k, ok := kinds[name]
	return k, ok
}

// Registered are the kinds this binary linked, sorted. The startup log
// says what they are, so "why is my listener not answering" is a
// question the log has already answered.
func Registered() []string {
	kindMu.RLock()
	defer kindMu.RUnlock()
	out := make([]string, 0, len(kinds))
	for n := range kinds {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Logs implements Host.
func (s *Server) Logs() *logging.Logs { return s.logs }

// Counters implements Host. Stats, without the s, is the management
// snapshot; this is the live set a listener adds to.
func (s *Server) Counters() *Stats { return s.stats }

// Pool implements Host.
func (s *Server) Pool(name string) *upstream.Pool {
	rt := s.rt.Load()
	if rt == nil {
		return nil
	}
	return rt.pools[name]
}

// Limits implements Host.
func (s *Server) Limits() config.Limits { return s.cfg().Server.Limits }

// listenerTLS builds the TLS configuration a listener kind is given:
// the certificates, the ticket keyring, the fingerprint table, the
// handshake refusal hook and the stapling loop. Every kind that takes
// TLS wants all of it, which is why it is here rather than repeated
// once per kind.
func (s *Server) listenerTLS(lc config.Listener) (*tls.Config, *tlsconf.Reloadable, error) {
	tc, rl, err := tlsconf.Server(lc.TLS, nil)
	if err != nil {
		return nil, nil, err
	}
	s.tickets.Attach(tc)
	rl.Fingerprints = s.fingerprints
	rl.Refuse = s.refuseHandshake
	rl.StartStapling(s.logs.Error)
	return tc, rl, nil
}

// DNSInstance is a kind that answers DNS. The status and purge views ask
// for the server rather than knowing which kind it came from, so the
// engine keeps no import of a kind's package.
type DNSInstance interface{ DNSServer() *dns.Server }

// FlowCounter is a kind that relays datagram flows and can say how many
// are open, for the counter snapshot.
type FlowCounter interface{ OpenFlows() int64 }

// attachKind gives the engine's status views a handle on a kind that
// offers one. A kind that implements none of these is simply not in
// them, which is the right answer for a kind with nothing to report.
func (s *Server) attachKind(bl *boundListener, inst Instance) {
	if d, ok := inst.(DNSInstance); ok {
		bl.dns = d.DNSServer()
	}
}
