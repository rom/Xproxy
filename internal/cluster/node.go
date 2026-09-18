package cluster

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/ban"
	"github.com/rom/xproxy/internal/config"
	"github.com/rom/xproxy/internal/limits"
)

// RateSource is the local rate limiting state the node reads and updates.
type RateSource interface {
	// Flush returns tokens consumed per policy and key since the last call.
	Flush(limit int) map[string]map[string]float64
	// Report applies a peer's consumption of one policy.
	Report(peer, policy string, reports []limits.PeerReport)
}

// BanStore is the local ban list.
type BanStore interface {
	Entries() []ban.Entry
	Apply(e ban.Entry, removed bool, peer string) error
	OnChange(fn func(e ban.Entry, removed bool))
}

// Node is the cluster endpoint of one proxy.
type Node struct {
	id    string
	log   *slog.Logger
	rates RateSource

	mu       sync.Mutex
	cfg      *config.Cluster
	bans     BanStore
	peers    map[string]*peer
	inbound  map[*inbound]struct{}
	ln       net.Listener
	tlsSrv   *tls.Config
	tlsCli   *tls.Config
	interval time.Duration
	tick     *time.Ticker

	banQueue chan banChange
	seq      atomic.Uint64
	stop     chan struct{}
	stopped  atomic.Bool
	wg       sync.WaitGroup

	ratesSent, ratesRecv, keysRecv, bansSent, bansRecv, rejected, dropped atomic.Uint64
}

type banChange struct {
	e       ban.Entry
	removed bool
}

// New prepares a node. Start must be called with the listener.
func New(cfg *config.Cluster, rates RateSource, log *slog.Logger) (*Node, error) {
	n := &Node{
		id:       cfg.NodeID,
		log:      log.With("component", "cluster", "node", cfg.NodeID),
		rates:    rates,
		cfg:      cfg,
		peers:    map[string]*peer{},
		inbound:  map[*inbound]struct{}{},
		interval: cfg.GossipInterval.D(),
		banQueue: make(chan banChange, banQueueSize),
		stop:     make(chan struct{}),
	}
	srv, cli, err := buildTLS(&cfg.TLS)
	if err != nil {
		return nil, err
	}
	n.tlsSrv, n.tlsCli = srv, cli
	return n, nil
}

// buildTLS creates the server and client configurations: TLS 1.3, the
// cluster CA on both sides, client certificates required, optional name
// restriction.
func buildTLS(t *config.ClusterTLS) (*tls.Config, *tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("cluster certificate: %w", err)
	}
	caPEM, err := os.ReadFile(t.CAFile) //nolint:gosec // validated configuration path
	if err != nil {
		return nil, nil, fmt.Errorf("cluster CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, nil, errors.New("cluster CA file contains no certificates")
	}
	allowed := map[string]bool{}
	for _, n := range t.AllowedNames {
		allowed[n] = true
	}
	verify := func(cs tls.ConnectionState) error {
		if len(allowed) == 0 {
			return nil
		}
		if len(cs.PeerCertificates) == 0 {
			return errors.New("no peer certificate")
		}
		leaf := cs.PeerCertificates[0]
		if allowed[leaf.Subject.CommonName] {
			return nil
		}
		for _, d := range leaf.DNSNames {
			if allowed[d] {
				return nil
			}
		}
		return fmt.Errorf("peer certificate %q is not in allowed_names", leaf.Subject.CommonName)
	}
	srv := &tls.Config{
		MinVersion:       tls.VersionTLS13,
		Certificates:     []tls.Certificate{cert},
		ClientCAs:        pool,
		ClientAuth:       tls.RequireAndVerifyClientCert,
		VerifyConnection: verify,
		NextProtos:       []string{"xproxy-cluster/1"},
	}
	cli := &tls.Config{
		MinVersion:       tls.VersionTLS13,
		Certificates:     []tls.Certificate{cert},
		RootCAs:          pool,
		VerifyConnection: verify,
		NextProtos:       []string{"xproxy-cluster/1"},
	}
	return srv, cli, nil
}

// ID returns the node identifier.
func (n *Node) ID() string { return n.id }

// AttachBans connects a ban list; local changes are broadcast and peer
// changes applied. Passing nil detaches.
func (n *Node) AttachBans(b BanStore) {
	n.mu.Lock()
	n.bans = b
	n.mu.Unlock()
	if b != nil && n.cfg.SharesBans() {
		b.OnChange(func(e ban.Entry, removed bool) {
			select {
			case n.banQueue <- banChange{e: e, removed: removed}:
			default:
				n.dropped.Add(1)
			}
		})
	}
}

// Start begins accepting on ln and dialling peers.
func (n *Node) Start(ln net.Listener) {
	n.mu.Lock()
	n.ln = ln
	n.tick = time.NewTicker(n.interval)
	for _, addr := range n.cfg.Peers {
		n.addPeerLocked(addr)
	}
	n.mu.Unlock()
	n.wg.Add(2)
	go n.acceptLoop(ln)
	go n.gossipLoop()
	n.log.Info("cluster listening", "address", ln.Addr().String(), "peers", len(n.cfg.Peers))
}

// Reconfigure applies a new peer list, interval and sharing flags. TLS and
// listen address changes require a restart and are rejected by the caller.
func (n *Node) Reconfigure(cfg *config.Cluster) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.cfg = cfg
	if d := cfg.GossipInterval.D(); d != n.interval {
		n.interval = d
		if n.tick != nil {
			n.tick.Reset(d)
		}
	}
	want := map[string]bool{}
	for _, addr := range cfg.Peers {
		want[addr] = true
		if _, ok := n.peers[addr]; !ok {
			n.addPeerLocked(addr)
		}
	}
	for addr, p := range n.peers {
		if !want[addr] {
			p.close()
			delete(n.peers, addr)
		}
	}
}

func (n *Node) addPeerLocked(addr string) {
	p := &peer{addr: addr, node: n, stop: make(chan struct{})}
	n.peers[addr] = p
	n.wg.Add(1)
	go p.loop()
}

// Stop closes everything.
func (n *Node) Stop() {
	if !n.stopped.CompareAndSwap(false, true) {
		return
	}
	close(n.stop)
	n.mu.Lock()
	if n.ln != nil {
		_ = n.ln.Close()
	}
	for _, p := range n.peers {
		p.close()
	}
	for in := range n.inbound {
		_ = in.conn.Close()
	}
	if n.tick != nil {
		n.tick.Stop()
	}
	n.mu.Unlock()
	n.wg.Wait()
}

// Addr returns the listener address.
func (n *Node) Addr() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.ln == nil {
		return ""
	}
	return n.ln.Addr().String()
}

// ---- outbound --------------------------------------------------------------

type peer struct {
	addr string
	node *Node
	stop chan struct{}
	once sync.Once

	mu          sync.Mutex
	conn        net.Conn
	w           *bufio.Writer
	connectedAt time.Time
	lastErr     string
	out         atomic.Uint64
	reconnects  atomic.Uint64
}

func (p *peer) close() {
	p.once.Do(func() { close(p.stop) })
	p.mu.Lock()
	if p.conn != nil {
		_ = p.conn.Close()
	}
	p.mu.Unlock()
}

func (p *peer) loop() {
	defer p.node.wg.Done()
	backoff := time.Second
	for {
		select {
		case <-p.stop:
			return
		case <-p.node.stop:
			return
		default:
		}
		conn, err := p.dial()
		if err != nil {
			p.mu.Lock()
			p.lastErr = err.Error()
			p.mu.Unlock()
			p.node.log.Warn("peer dial failed", "peer", p.addr, "err", err.Error())
			select {
			case <-time.After(backoff):
			case <-p.stop:
				return
			case <-p.node.stop:
				return
			}
			backoff = min(backoff*2, 30*time.Second)
			continue
		}
		backoff = time.Second
		p.mu.Lock()
		p.conn = conn
		p.w = bufio.NewWriterSize(conn, 64<<10)
		p.connectedAt = time.Now()
		p.lastErr = ""
		p.mu.Unlock()
		p.node.log.Info("peer connected", "peer", p.addr)
		if err := p.send(&message{T: typeHello, Node: p.node.id, Ver: ProtocolVersion}); err == nil {
			p.node.sendSnapshot(p)
		}
		// Drain reads so a close is noticed; peers never send us anything
		// meaningful on the connection we dialled.
		buf := make([]byte, 512)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(24 * time.Hour))
			if _, rerr := conn.Read(buf); rerr != nil {
				break
			}
		}
		p.mu.Lock()
		p.conn = nil
		p.w = nil
		p.mu.Unlock()
		p.reconnects.Add(1)
		select {
		case <-p.stop:
			return
		case <-p.node.stop:
			return
		default:
		}
		p.node.log.Warn("peer disconnected", "peer", p.addr)
	}
}

func (p *peer) dial() (net.Conn, error) {
	host, _, err := net.SplitHostPort(p.addr)
	if err != nil {
		return nil, err
	}
	tc := p.node.tlsCli.Clone()
	tc.ServerName = host
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: tc}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return d.DialContext(ctx, "tcp", p.addr)
}

// send writes one message; errors close the connection so the loop
// reconnects.
func (p *peer) send(m *message) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conn == nil {
		return errors.New("not connected")
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if len(b) > MaxMessageBytes {
		return errors.New("message too large")
	}
	_ = p.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = p.w.Write(append(b, '\n'))
	if err == nil {
		err = p.w.Flush()
	}
	if err != nil {
		p.lastErr = err.Error()
		_ = p.conn.Close()
		return err
	}
	p.out.Add(1)
	return nil
}

// sendSnapshot sends all active bans to a freshly connected peer.
func (n *Node) sendSnapshot(p *peer) {
	n.mu.Lock()
	b := n.bans
	share := n.cfg.SharesBans()
	n.mu.Unlock()
	if b == nil || !share {
		return
	}
	entries := b.Entries()
	for start := 0; start < len(entries); start += MaxBansPerMessage {
		end := min(start+MaxBansPerMessage, len(entries))
		if err := p.send(&message{T: typeBans, Node: n.id, Seq: n.seq.Add(1), Bans: entries[start:end]}); err != nil {
			return
		}
		n.bansSent.Add(uint64(end - start)) //nolint:gosec // bounded by MaxBansPerMessage
	}
}

// gossipLoop flushes consumption and ban changes to every peer each
// interval, and pings idle peers so the receiver's read deadline holds.
func (n *Node) gossipLoop() {
	defer n.wg.Done()
	last := time.Now()
	for {
		n.mu.Lock()
		tick := n.tick
		n.mu.Unlock()
		select {
		case <-n.stop:
			return
		case <-tick.C:
		}
		now := time.Now()
		elapsed := now.Sub(last)
		last = now
		n.mu.Lock()
		cfg := n.cfg
		peers := make([]*peer, 0, len(n.peers))
		for _, p := range n.peers {
			peers = append(peers, p)
		}
		n.mu.Unlock()
		if len(peers) == 0 {
			// Still flush so counters do not accumulate forever.
			if cfg.SharesRateLimits() {
				n.rates.Flush(cfg.MaxKeysPerReport)
			}
			n.drainBans(nil)
			continue
		}
		sent := false
		if cfg.SharesRateLimits() {
			rates := n.rates.Flush(cfg.MaxKeysPerReport)
			if len(rates) > 0 {
				m := &message{T: typeRates, Node: n.id, Seq: n.seq.Add(1), IntervalMS: max(elapsed.Milliseconds(), 1), Rates: rates}
				for _, p := range peers {
					if p.send(m) == nil {
						n.ratesSent.Add(1)
					}
				}
				sent = true
			}
		}
		if n.drainBans(peers) {
			sent = true
		}
		if !sent {
			m := &message{T: typePing, Node: n.id}
			for _, p := range peers {
				_ = p.send(m)
			}
		}
	}
}

// drainBans sends queued ban changes; it returns whether anything was sent.
func (n *Node) drainBans(peers []*peer) bool {
	var added []ban.Entry
	var removed []string
	for len(added)+len(removed) < MaxBansPerMessage {
		select {
		case c := <-n.banQueue:
			if c.removed {
				removed = append(removed, c.e.Target)
			} else {
				added = append(added, c.e)
			}
			continue
		default:
		}
		break
	}
	if len(added)+len(removed) == 0 || len(peers) == 0 {
		return false
	}
	m := &message{T: typeBans, Node: n.id, Seq: n.seq.Add(1), Bans: added, Removed: removed}
	for _, p := range peers {
		if p.send(m) == nil {
			n.bansSent.Add(uint64(len(added) + len(removed))) //nolint:gosec // bounded by MaxBansPerMessage
		}
	}
	return true
}

// ---- inbound ---------------------------------------------------------------

type inbound struct {
	conn     net.Conn
	remote   string
	certName string
	nodeID   atomic.Pointer[string]
	since    time.Time
	lastSeen atomic.Int64
	in       atomic.Uint64
}

func (n *Node) acceptLoop(ln net.Listener) {
	defer n.wg.Done()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		n.mu.Lock()
		full := len(n.inbound) >= MaxInbound
		n.mu.Unlock()
		if full {
			n.rejected.Add(1)
			_ = c.Close()
			continue
		}
		n.wg.Add(1)
		go n.serve(c)
	}
}

func (n *Node) serve(raw net.Conn) {
	defer n.wg.Done()
	tc := tls.Server(raw, n.tlsSrv)
	_ = tc.SetDeadline(time.Now().Add(10 * time.Second))
	hctx, hcancel := context.WithTimeout(context.Background(), 10*time.Second)
	err := tc.HandshakeContext(hctx)
	hcancel()
	if err != nil {
		n.rejected.Add(1)
		n.log.Warn("cluster handshake rejected", "remote", raw.RemoteAddr().String(), "err", err.Error())
		_ = tc.Close()
		return
	}
	_ = tc.SetDeadline(time.Time{})
	cs := tc.ConnectionState()
	in := &inbound{conn: tc, remote: raw.RemoteAddr().String(), since: time.Now()}
	if len(cs.PeerCertificates) > 0 {
		in.certName = cs.PeerCertificates[0].Subject.CommonName
	}
	in.lastSeen.Store(time.Now().UnixNano())
	n.mu.Lock()
	n.inbound[in] = struct{}{}
	n.mu.Unlock()
	defer func() {
		n.mu.Lock()
		delete(n.inbound, in)
		n.mu.Unlock()
		_ = tc.Close()
	}()

	r := bufio.NewReaderSize(tc, 64<<10)
	for {
		n.mu.Lock()
		stale := n.cfg.PeerStale.D()
		n.mu.Unlock()
		_ = tc.SetReadDeadline(time.Now().Add(stale + 5*time.Second))
		line, err := readLine(r, MaxMessageBytes)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) && !n.stopped.Load() {
				n.log.Info("cluster peer connection closed", "remote", in.remote, "node", deref(in.nodeID.Load()), "err", err.Error())
			}
			return
		}
		in.in.Add(1)
		in.lastSeen.Store(time.Now().UnixNano())
		var m message
		if err := json.Unmarshal(line, &m); err != nil {
			n.log.Warn("cluster message rejected", "remote", in.remote, "err", "bad json")
			return
		}
		if err := n.handle(in, &m); err != nil {
			n.log.Warn("cluster message rejected", "remote", in.remote, "type", m.T, "err", err.Error())
			return
		}
	}
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// readLine reads one newline terminated line of at most limit bytes.
func readLine(r *bufio.Reader, limit int) ([]byte, error) {
	var out []byte
	for {
		chunk, isPrefix, err := r.ReadLine()
		if err != nil {
			return nil, err
		}
		out = append(out, chunk...)
		if len(out) > limit {
			return nil, errors.New("message exceeds size limit")
		}
		if !isPrefix {
			return out, nil
		}
	}
}

func (n *Node) handle(in *inbound, m *message) error {
	switch m.T {
	case typeHello:
		if m.Ver != ProtocolVersion {
			return fmt.Errorf("protocol version %d not supported", m.Ver)
		}
		if m.Node == "" || len(m.Node) > 64 {
			return errors.New("bad node id")
		}
		id := m.Node
		in.nodeID.Store(&id)
		n.log.Info("cluster peer joined", "remote", in.remote, "node", id, "cert", in.certName)
		return nil
	case typePing:
		return nil
	case typeRates:
		peerID := deref(in.nodeID.Load())
		if peerID == "" {
			return errors.New("rates before hello")
		}
		n.mu.Lock()
		share := n.cfg.SharesRateLimits()
		n.mu.Unlock()
		if !share {
			return nil
		}
		if m.IntervalMS <= 0 || m.IntervalMS > 120_000 {
			return errors.New("bad interval")
		}
		secs := float64(m.IntervalMS) / 1000
		total := 0
		for policy, keys := range m.Rates {
			total += len(keys)
			if total > 65536 {
				return errors.New("too many keys")
			}
			reports := make([]limits.PeerReport, 0, len(keys))
			for k, count := range keys {
				if len(k) == 0 || len(k) > 300 || count < 0 || count > 1e12 {
					continue
				}
				reports = append(reports, limits.PeerReport{Key: k, Rate: count / secs})
			}
			n.rates.Report(peerID, policy, reports)
		}
		n.ratesRecv.Add(1)
		n.keysRecv.Add(uint64(total)) //nolint:gosec // bounded above
		return nil
	case typeBans:
		peerID := deref(in.nodeID.Load())
		if peerID == "" {
			return errors.New("bans before hello")
		}
		if len(m.Bans)+len(m.Removed) > MaxBansPerMessage {
			return errors.New("too many bans")
		}
		n.mu.Lock()
		b := n.bans
		share := n.cfg.SharesBans()
		n.mu.Unlock()
		if b == nil || !share {
			return nil
		}
		for _, e := range m.Bans {
			if len(e.Reason) > 256 {
				e.Reason = e.Reason[:256]
			}
			_ = b.Apply(e, false, peerID) // malformed targets are skipped
		}
		for _, t := range m.Removed {
			_ = b.Apply(ban.Entry{Target: t}, true, peerID)
		}
		n.bansRecv.Add(uint64(len(m.Bans) + len(m.Removed))) //nolint:gosec // bounded above
		return nil
	default:
		return fmt.Errorf("unknown message type %q", m.T)
	}
}

// Status returns the management view.
func (n *Node) Status() Status {
	n.mu.Lock()
	defer n.mu.Unlock()
	st := Status{
		NodeID:        n.id,
		RatesSent:     n.ratesSent.Load(),
		RatesReceived: n.ratesRecv.Load(),
		KeysReceived:  n.keysRecv.Load(),
		BansSent:      n.bansSent.Load(),
		BansReceived:  n.bansRecv.Load(),
		Rejected:      n.rejected.Load(),
		Dropped:       n.dropped.Load(),
		Peers:         []PeerStatus{},
		Inbound:       []InboundStatus{},
	}
	if n.ln != nil {
		st.Listen = n.ln.Addr().String()
	}
	for _, p := range n.peers {
		p.mu.Lock()
		st.Peers = append(st.Peers, PeerStatus{
			Address: p.addr, Connected: p.conn != nil, ConnectedAt: p.connectedAt,
			LastError: p.lastErr, MessagesOut: p.out.Load(), Reconnects: p.reconnects.Load(),
		})
		p.mu.Unlock()
	}
	for in := range n.inbound {
		st.Inbound = append(st.Inbound, InboundStatus{
			Remote: in.remote, NodeID: deref(in.nodeID.Load()), CertName: in.certName,
			Since: in.since, LastSeen: time.Unix(0, in.lastSeen.Load()), MessagesIn: in.in.Load(),
		})
	}
	return st
}

// ConnectedPeers returns how many outbound connections are up.
func (n *Node) ConnectedPeers() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	c := 0
	for _, p := range n.peers {
		p.mu.Lock()
		if p.conn != nil {
			c++
		}
		p.mu.Unlock()
	}
	return c
}
