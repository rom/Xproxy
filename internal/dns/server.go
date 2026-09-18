package dns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/limits"
	"github.com/rom/xproxy/internal/netutil"
)

// Policy is the reloadable part of a listener: block list, client
// access, upstreams, cache bounds and rate limit.
type Policy struct {
	Block        *BlockList
	BlockAction  string // nxdomain, refuse or sinkhole
	Sinkhole4    []byte
	Sinkhole6    []byte
	SinkholeTTL  uint32
	AllowClients []netip.Prefix
	Resolver     *Resolver
	MinTTL       time.Duration
	MaxTTL       time.Duration
	NegativeTTL  time.Duration
	RateLimit    *limits.KeyedLimiter // nil disables
	LogQueries   bool
}

// Hooks connect the server to the proxy's logs and ban list.
type Hooks struct {
	// Access receives one "dns" line per query when LogQueries is set.
	Access func(attrs ...any)
	// Event records a security event for a client (blocked names).
	Event func(client netip.Addr, reason string, attrs ...any)
	// Banned reports clients whose datagrams are dropped.
	Banned func(client netip.Addr) bool
}

// Server answers DNS over one UDP socket and one TCP listener.
type Server struct {
	Name   string
	udp    net.PacketConn
	tcp    net.Listener
	cache  *Cache
	policy atomic.Pointer[Policy]
	hooks  Hooks
	sem    chan struct{}

	mu   sync.Mutex
	cons map[net.Conn]struct{}
	wg   sync.WaitGroup
	once sync.Once
	done chan struct{}

	Queries, Hits, Blocked, Refused, Dropped, ServFail, Truncated, FormErr atomic.Uint64
}

// Status is the management view of a listener.
type Status struct {
	Listener     string   `json:"listener"`
	Queries      uint64   `json:"queries"`
	CacheHits    uint64   `json:"cache_hits"`
	CacheEntries int      `json:"cache_entries"`
	Blocked      uint64   `json:"blocked"`
	BlockEntries int      `json:"block_entries"`
	Refused      uint64   `json:"refused"`
	Dropped      uint64   `json:"dropped"`
	ServFail     uint64   `json:"servfail"`
	Truncated    uint64   `json:"truncated"`
	FormErr      uint64   `json:"formerr"`
	Upstreams    []string `json:"upstreams"`
	UpstreamFail uint64   `json:"upstream_failures"`
}

// New creates a server on the given sockets (either may be nil) with a
// cache of cacheEntries and at most inFlight queries being handled.
func New(name string, udp net.PacketConn, tcp net.Listener, cacheEntries, inFlight int, p *Policy, hooks Hooks) *Server {
	s := &Server{Name: name, udp: udp, tcp: tcp, cache: NewCache(cacheEntries), hooks: hooks,
		sem: make(chan struct{}, max(inFlight, 1)), cons: map[net.Conn]struct{}{}, done: make(chan struct{})}
	s.policy.Store(p)
	return s
}

// Apply swaps the policy (reload). The cache is kept and resized.
func (s *Server) Apply(p *Policy, cacheEntries int) {
	s.policy.Store(p)
	s.cache.Resize(cacheEntries)
}

// Purge empties the cache.
func (s *Server) Purge() int { return s.cache.Purge() }

// Status reports counters.
func (s *Server) Status() Status {
	p := s.policy.Load()
	st := Status{Listener: s.Name, Queries: s.Queries.Load(), CacheHits: s.Hits.Load(), CacheEntries: s.cache.Len(),
		Blocked: s.Blocked.Load(), Refused: s.Refused.Load(), Dropped: s.Dropped.Load(), ServFail: s.ServFail.Load(),
		Truncated: s.Truncated.Load(), FormErr: s.FormErr.Load()}
	if p != nil {
		if p.Block != nil {
			st.BlockEntries = p.Block.Len()
		}
		if p.Resolver != nil {
			st.Upstreams = p.Resolver.servers
			st.UpstreamFail = p.Resolver.Failures.Load()
		}
	}
	return st
}

// Serve runs the UDP and TCP loops until Shutdown.
func (s *Server) Serve() {
	if s.udp != nil {
		s.wg.Add(1)
		go s.serveUDP()
	}
	if s.tcp != nil {
		s.wg.Add(1)
		go s.serveTCP()
	}
}

func (s *Server) serveUDP() {
	defer s.wg.Done()
	buf := make([]byte, 4096)
	for {
		n, addr, err := s.udp.ReadFrom(buf)
		if err != nil {
			select {
			case <-s.done:
				return
			default:
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if n < headerLen {
			continue
		}
		client := clientOf(addr)
		select {
		case s.sem <- struct{}{}:
		default:
			s.Dropped.Add(1)
			continue
		}
		query := make([]byte, n)
		copy(query, buf[:n])
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.sem }()
			if resp := s.Handle(query, client, false); resp != nil {
				_, _ = s.udp.WriteTo(resp, addr)
			}
		}()
	}
}

func (s *Server) serveTCP() {
	defer s.wg.Done()
	for {
		c, err := s.tcp.Accept()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		s.track(c, true)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.track(c, false)
			s.serveConn(c)
		}()
	}
}

func (s *Server) serveConn(c net.Conn) {
	defer func() { _ = c.Close() }()
	client := clientOf(c.RemoteAddr())
	for i := 0; i < 1000; i++ { // queries per connection
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		query, err := ReadTCP(c, MaxMessage)
		if err != nil {
			return
		}
		select {
		case s.sem <- struct{}{}:
		default:
			s.Dropped.Add(1)
			return
		}
		resp := s.Handle(query, client, true)
		<-s.sem
		if resp == nil {
			return
		}
		_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if err := WriteTCP(c, resp); err != nil {
			return
		}
	}
}

func (s *Server) track(c net.Conn, add bool) {
	s.mu.Lock()
	if add {
		s.cons[c] = struct{}{}
	} else {
		delete(s.cons, c)
	}
	s.mu.Unlock()
}

// Shutdown closes the sockets, waits up to ctx for queries in flight,
// then closes remaining TCP connections.
func (s *Server) Shutdown(ctx context.Context) {
	s.once.Do(func() {
		close(s.done)
		if s.udp != nil {
			_ = s.udp.Close()
		}
		if s.tcp != nil {
			_ = s.tcp.Close()
		}
	})
	finished := make(chan struct{})
	go func() { s.wg.Wait(); close(finished) }()
	select {
	case <-finished:
	case <-ctx.Done():
		s.mu.Lock()
		for c := range s.cons {
			_ = c.Close()
		}
		s.mu.Unlock()
		<-finished
	}
}

func clientOf(a net.Addr) netip.Addr {
	switch x := a.(type) {
	case *net.UDPAddr:
		return x.AddrPort().Addr().Unmap()
	case *net.TCPAddr:
		return x.AddrPort().Addr().Unmap()
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

// Handle answers one query; nil means drop without a response.
func (s *Server) Handle(query []byte, client netip.Addr, tcp bool) []byte {
	start := time.Now()
	s.Queries.Add(1)
	h, err := ParseHeader(query)
	if err != nil || h.Response() {
		s.Dropped.Add(1)
		return nil
	}
	if s.hooks.Banned != nil && s.hooks.Banned(client) {
		s.Dropped.Add(1)
		return nil
	}
	p := s.policy.Load()
	if p.RateLimit != nil && !p.RateLimit.Allow(client.String()) {
		s.Dropped.Add(1)
		return nil
	}
	proto := "udp"
	if tcp {
		proto = "tcp"
	}
	if h.QDCount != 1 {
		s.FormErr.Add(1)
		return s.finish(query, headerLen, h, Question{}, client, proto, start, "formerr", Reply(query[:headerLen], headerLen, h, RcodeFormErr))
	}
	q, qEnd, err := ParseQuestion(query)
	if err != nil {
		s.FormErr.Add(1)
		return s.finish(query, headerLen, h, Question{}, client, proto, start, "formerr", Reply(query[:headerLen], headerLen, h, RcodeFormErr))
	}
	if len(p.AllowClients) > 0 && !netutil.Contains(p.AllowClients, client) {
		s.Refused.Add(1)
		return s.finish(query, qEnd, h, q, client, proto, start, "refused", Reply(query, qEnd, h, RcodeRefused))
	}
	if h.Opcode() != 0 {
		return s.finish(query, qEnd, h, q, client, proto, start, "notimp", Reply(query, qEnd, h, RcodeNotImp))
	}
	if p.Block != nil && p.Block.Match(q.Name) {
		s.Blocked.Add(1)
		if s.hooks.Event != nil {
			s.hooks.Event(client, "dns_blocked", "listener", s.Name, "name", q.Name, "type", TypeName(q.Type), "proto", proto)
		}
		var resp []byte
		switch p.BlockAction {
		case "refuse":
			resp = Reply(query, qEnd, h, RcodeRefused)
		case "sinkhole":
			addr := p.Sinkhole4
			if q.Type == TypeAAAA {
				addr = p.Sinkhole6
			}
			resp = Sinkhole(query, qEnd, h, q, addr, p.SinkholeTTL)
		default:
			resp = Reply(query, qEnd, h, RcodeNXDomain)
		}
		return s.finish(query, qEnd, h, q, client, proto, start, "blocked", resp)
	}
	now := time.Now()
	if h.RecursionDesired() {
		if resp, rEnd := s.cache.Get(q, h.ID, now); resp != nil {
			s.Hits.Add(1)
			return s.finish(query, qEnd, h, q, client, proto, start, "cache", s.fit(query, qEnd, h, resp, rEnd, tcp))
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), p.Resolver.timeout*time.Duration(max(len(p.Resolver.servers), 1)))
	resp, err := p.Resolver.Exchange(ctx, query, qEnd, q, tcp)
	cancel()
	if err != nil {
		s.ServFail.Add(1)
		return s.finish(query, qEnd, h, q, client, proto, start, "servfail", Reply(query, qEnd, h, RcodeServFail))
	}
	rh, _ := ParseHeader(resp)
	_, rEnd, qerr := ParseQuestion(resp)
	if qerr == nil && !rh.Truncated() && h.RecursionDesired() {
		var ttl time.Duration
		switch rh.Rcode() {
		case RcodeNoError:
			if minTTL, ok := MinTTL(resp, rEnd, rh); ok {
				ttl = min(max(time.Duration(minTTL)*time.Second, p.MinTTL), p.MaxTTL)
			} else {
				ttl = p.NegativeTTL
			}
		case RcodeNXDomain:
			ttl = p.NegativeTTL
		}
		if ttl > 0 {
			s.cache.Put(q, resp, rEnd, rh, ttl, now)
		}
	}
	if qerr != nil {
		rEnd = qEnd
	}
	return s.finish(query, qEnd, h, q, client, proto, start, "upstream", s.fit(query, qEnd, h, resp, rEnd, tcp))
}

// fit truncates a UDP response that exceeds what the client can take.
func (s *Server) fit(query []byte, qEnd int, h Header, resp []byte, rEnd int, tcp bool) []byte {
	if tcp || len(resp) <= EDNSSize(query, qEnd, h) {
		return resp
	}
	s.Truncated.Add(1)
	return Truncate(resp, rEnd)
}

func (s *Server) finish(_ []byte, _ int, _ Header, q Question, client netip.Addr, proto string, start time.Time, source string, resp []byte) []byte {
	if p := s.policy.Load(); p != nil && p.LogQueries && s.hooks.Access != nil {
		rcode := -1
		if rh, err := ParseHeader(resp); err == nil {
			rcode = rh.Rcode()
		}
		s.hooks.Access("listener", s.Name, "client_ip", client.String(), "proto", proto, "name", q.Name, "type", TypeName(q.Type),
			"rcode", rcode, "source", source, "bytes", len(resp), "duration_ms", float64(time.Since(start).Microseconds())/1000)
	}
	return resp
}

// TypeName renders a record type.
func TypeName(t uint16) string {
	switch t {
	case TypeA:
		return "A"
	case TypeNS:
		return "NS"
	case TypeCNAME:
		return "CNAME"
	case TypeSOA:
		return "SOA"
	case TypePTR:
		return "PTR"
	case TypeMX:
		return "MX"
	case TypeTXT:
		return "TXT"
	case TypeAAAA:
		return "AAAA"
	case TypeOPT:
		return "OPT"
	case TypeANY:
		return "ANY"
	case 33:
		return "SRV"
	case 65:
		return "HTTPS"
	}
	return "TYPE" + strconv.Itoa(int(t))
}
