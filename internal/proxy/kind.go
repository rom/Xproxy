package proxy

import (
	"time"

	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sort"
	"sync"

	"github.com/rom/xproxy/internal/acme"
	"github.com/rom/xproxy/internal/ban"
	"github.com/rom/xproxy/internal/capture"
	"github.com/rom/xproxy/internal/cluster"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/dns"
	"github.com/rom/xproxy/internal/icap"
	"github.com/rom/xproxy/internal/intel"
	"github.com/rom/xproxy/internal/limits"
	"github.com/rom/xproxy/internal/listener"
	"github.com/rom/xproxy/internal/logging"
	"github.com/rom/xproxy/internal/mfa"
	"github.com/rom/xproxy/internal/sessions"
	"github.com/rom/xproxy/internal/shadow"
	"github.com/rom/xproxy/internal/tlsconf"
	"github.com/rom/xproxy/internal/upstream"
)

// Host is what a listener kind needs from the server that hosts it.
//
// It is small on purpose. Most kinds use the first five: counters, log
// records, the ban list, an upstream pool and the server-wide bounds.
// Everything else a kind does is its own protocol's business, which is
// why a kind can live in its own package and its own binary.
//
// The rest are the process-wide facilities a kind may not build for
// itself, because a second one would be wrong rather than merely
// wasteful: one fingerprint table, one connection limiter, one ACME
// manager, one packet capture, one cluster connection.
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
	// ThreatIntel is the imported lists of addresses and fingerprints,
	// or nil when the configuration has none.
	ThreatIntel() *intel.Set
	// Pool returns a configured upstream pool by name, or nil.
	Pool(name string) *upstream.Pool
	// ICAPService returns a scanning service from icap.services by
	// name, or nil. The engine owns these rather than the data plane,
	// because the kinds that hand a file to a scanner are not all in
	// the daemon that has a plane: ftp is in xrelay, sftp in xgate.
	ICAPService(name string) *icap.Service
	// Limits are the server-wide bounds a listener inherits.
	Limits() config.Limits

	// Fingerprints holds the TLS fingerprint of every open connection,
	// keyed by remote address. A kind that terminates TLS removes its
	// connections' entries as they close.
	Fingerprints() *tlsconf.FingerprintTable
	// ConnLimiter is the accept-path bound, for a transport that
	// accepts outside the engine's own accept loop (QUIC).
	ConnLimiter() *limits.ConnLimiter
	// ACME is the certificate manager, or nil when none is configured.
	ACME() *acme.Manager
	// Capture is the pcapng recorder, or nil while nothing is
	// recording.
	Capture() *capture.Capturer
	// PublishEvent shares a fact with the cluster peers, if any.
	PublishEvent(cluster.Event)
	// AttachTickets puts the shared session ticket keys on a TLS
	// configuration a kind built itself.
	AttachTickets(*tls.Config)
	// RefuseHandshake is the ClientHello policy, for a kind that builds
	// its own TLS configuration: the reason to refuse this client, or
	// "" to carry on.
	RefuseHandshake(remote net.Addr, fp tlsconf.Fingerprint) string
	// DNSServer returns the resolver of a bound dns listener by name,
	// or nil. One kind answers DNS over HTTPS on an http route with the
	// policy and cache of a dns listener, and the engine holds the
	// listener set, so the lookup is here rather than between the two
	// kinds, which are not linked together in every daemon.
	DNSServer(listener string) *dns.Server
	// Sessions is the table of live sessions, which every kind that holds
	// one for longer than a request registers with, so an operator can
	// list them and close one. Never nil, so a kind writes no
	// conditionals around it.
	Sessions() *sessions.Table
	// Shadow is the ledger a listener in shadow mode writes what it would
	// have refused to. Never nil, so a kind writes no conditionals around
	// it; a listener that enforces never reaches it.
	Shadow() *shadow.Ledger
	// TakeRemote asks the cluster owner of a rate limit key to decide.
	// decided is false without a cluster, without an owner or when the
	// answer did not come in time, and the caller falls back to the
	// local limiter.
	TakeRemote(policy, key string, n float64) (allowed, decided bool)
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

// ExtraAddrs is an instance listening on more than the accept socket
// the engine bound: the HTTP/3 endpoint beside an http listener, and
// DNS over QUIC beside DNS over TLS. The keys are suffixes, appended to
// the listener's name in the address view.
type ExtraAddrs interface{ Addrs() map[string]string }

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
	// Plane is the process's data plane, for the one kind whose
	// listeners share a compiled generation rather than each holding
	// their own. It is nil for every other kind, and in a daemon that
	// linked no plane.
	Plane Plane
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
	// ProxyHeader asks the engine to read an inbound PROXY protocol
	// header from every connection, where the listener configured one,
	// and present the client address it carries as the peer.
	//
	// A kind that reads the first bytes of the connection itself — to
	// route by server name, or because the protocol is not a stream at
	// all — leaves this false and gets the connection as it arrived.
	ProxyHeader bool
	// Datagram says the kind's only socket is a datagram one, so the
	// engine binds no accept socket for it and opens the packet socket
	// itself, handing it to the first Setup.Packet("") call. Without
	// this the engine would hold a TCP port nothing ever accepts on,
	// where a client that connected would hang instead of being
	// refused.
	//
	// Nothing that applies to accepted connections applies to such a
	// listener -- the shared connection limiter, the inbound PROXY
	// header, the TLS configuration -- because there are no
	// connections. Its own bounds are its whole admission policy.
	Datagram bool
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
	tc, rl, err := tlsconf.Server(lc.TLS, lc.Protocols)
	if err != nil {
		return nil, nil, err
	}
	s.tickets.Attach(tc)
	if s.acme != nil && len(lc.TLS.ACME) > 0 {
		rl.Managed = s.acme.Certificates
		rl.Challenge = s.acme.TLSALPN01
	}
	rl.Fingerprints = s.fingerprints
	rl.Refuse = s.refuseHandshake
	for _, w := range rl.CTWarnings() {
		s.logs.Security.Warn("certificate transparency", "listener", lc.Name, "issue", w)
	}
	for _, w := range rl.Expiring(time.Now()) {
		// At load and at every reload, because those are the moments an
		// operator is watching. The continuous answer is the status view's.
		s.logs.Security.Warn("certificate expiry", "listener", lc.Name, "issue", w)
	}
	rl.StartStapling(s.logs.Error)
	return tc, rl, nil
}

// DNSInstance is a kind that answers DNS. The status and purge views ask
// for the server rather than knowing which kind it came from, so the
// engine keeps no import of a kind's package.
type DNSInstance interface{ DNSServer() *dns.Server }

// FlowCounter is a kind that relays datagram flows and can say how many
// are open, for the counter snapshot.
type FlowCounter interface{ OpenFlows() int }

// MFAHolder is a kind whose listener asks for a second factor. The
// control plane lists and changes enrolments through it, so that
// adding or removing one is a thing an operator does rather than a
// file they have to find, and so that the state this process keeps --
// who is locked out -- can be seen and cleared.
//
// It is an optional interface for the same reason FlowCounter is: the
// engine asks its listeners rather than knowing which kinds have a
// factor, and keeps no import of a kind's package.
type MFAHolder interface{ MFAGuard() *mfa.Guard }

// MasqueStatus is one listener's MASQUE state. The type lives here
// rather than with the kind that fills it in, so the management view
// can render it without linking the forward proxy.
type MasqueStatus struct {
	Listener    string `json:"listener"`
	UDP         bool   `json:"udp"`
	IP          bool   `json:"ip"`
	Sessions    int64  `json:"sessions"`
	MaxSessions int    `json:"max_sessions"`
	UDPTotal    uint64 `json:"udp_total"`
	IPTotal     uint64 `json:"ip_total"`
	Refused     uint64 `json:"refused"`
	// Device is the tunnel device CONNECT-IP forwards through, empty
	// when none is configured.
	Device string `json:"device,omitempty"`
}

// MasqueReporter is a kind that proxies UDP or IP over extended
// CONNECT. It returns nil when the listener has no MASQUE section, so
// the view lists only the listeners that have one.
type MasqueReporter interface{ MasqueStatus() *MasqueStatus }

// Masque reports the MASQUE state of every listener that has one.
func (s *Server) Masque() []MasqueStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]MasqueStatus, 0, len(s.listeners))
	for _, bl := range s.listeners {
		r, ok := bl.inst.(MasqueReporter)
		if !ok {
			continue
		}
		if st := r.MasqueStatus(); st != nil {
			st.Listener = bl.cfg.Name
			out = append(out, *st)
		}
	}
	return out
}

// attachKind gives the engine's status views a handle on a kind that
// offers one. A kind that implements none of these is simply not in
// them, which is the right answer for a kind with nothing to report.
func (s *Server) attachKind(bl *boundListener, inst Instance) {
	if d, ok := inst.(DNSInstance); ok {
		bl.dns = d.DNSServer()
	}
}

// daemonFor names the program that serves a kind, for the error a
// daemon gives when it is handed a listener belonging to a sibling.
func daemonFor(kind string) string {
	if r, ok := listener.RoleOf(kind); ok {
		return r.Daemon()
	}
	return "no daemon in this project"
}

// Fingerprints implements Host.
func (s *Server) Fingerprints() *tlsconf.FingerprintTable { return s.fingerprints }

// ConnLimiter implements Host.
func (s *Server) ConnLimiter() *limits.ConnLimiter { return s.connLimiter }

// AttachTickets implements Host: the shared keys, where a keyring is
// configured, on a TLS configuration the kind built.
func (s *Server) AttachTickets(tc *tls.Config) { s.tickets.Attach(tc) }

// RefuseHandshake implements Host.
func (s *Server) RefuseHandshake(remote net.Addr, fp tlsconf.Fingerprint) string {
	return s.refuseHandshake(remote, fp)
}

// DNSServer implements Host.
func (s *Server) DNSServer(listener string) *dns.Server {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, bl := range s.listeners {
		if bl.dns != nil && bl.cfg.Name == listener {
			return bl.dns
		}
	}
	return nil
}

// TakeRemote implements Host.
func (s *Server) TakeRemote(policy, key string, n float64) (allowed, decided bool) {
	node := s.cluster.Load()
	if node == nil {
		return false, false
	}
	return node.Take(policy, key, n)
}
