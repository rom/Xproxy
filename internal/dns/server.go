package dns

import (
	"context"
	"errors"
	"github.com/rom/xproxy/internal/bound"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xproxy/internal/limits"
	"github.com/rom/xproxy/internal/netutil"
	"github.com/rom/xproxy/internal/safe"
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
	// DNSSEC validates upstream answers when set.
	DNSSEC *Validator
	// Local answers SVCB and HTTPS records this resolver owns: the
	// discovery name of RFC 9462, and any record an operator publishes
	// here (an ECH configuration, most usefully).
	Local *LocalRecords
	// Tunnel watches for data leaving in the query names themselves.
	Tunnel *Detector
}

// Hooks connect the server to the proxy's logs and ban list.
type Hooks struct {
	// Access receives one "dns" line per query when LogQueries is set.
	Access func(attrs ...any)
	// Event records a security event for a client (blocked names).
	//
	// verified says whether the client address completed a round trip.
	// A UDP datagram proves nothing about its source, so an event from
	// one must not be attributed to the address it claims: counting it
	// towards a ban lets anybody have a third party banned by spoofing
	// them, and logging one per datagram is a log flood at packet rate.
	Event func(client netip.Addr, reason string, verified bool, attrs ...any)
	// Banned reports clients whose datagrams are dropped.
	Banned func(client netip.Addr) bool
}

// Server answers DNS over one UDP socket and one TCP listener. When the
// TCP listener is a TLS listener (Encrypted), connections are DNS over
// TLS by default and DNS over HTTPS when their ALPN is HTTP.
type Server struct {
	Name   string
	udp    net.PacketConn
	tcp    net.Listener
	cache  *Cache
	policy atomic.Pointer[Policy]
	hooks  Hooks
	sem    chan struct{}
	// Encrypted marks a TLS listener; DoHPath is the RFC 8484 path.
	Encrypted bool
	// QUIC marks a listener that also answers DNS over QUIC beside the
	// TLS port. It is reported rather than used: the DoQ server is a
	// separate object, and this is how the status view says one exists
	// without holding it.
	QUIC    bool
	DoHPath string
	doh     *chanListener
	dohSrv  *http.Server

	mu   sync.Mutex
	cons map[net.Conn]struct{}
	wg   sync.WaitGroup
	once sync.Once
	done chan struct{}

	Queries, Hits, Blocked, Refused, Dropped, ServFail, Truncated, FormErr atomic.Uint64
	// Per transport counters.
	UDP, TCP, DoT, DoH, DoQ atomic.Uint64
	// Local counts answers served from the local record set.
	Local atomic.Uint64
	// Tunnels counts detections and TunnelBlocked the queries refused
	// because of one.
	Tunnels, TunnelBlocked atomic.Uint64
	// dropNotice warns when queries are dropped for lack of workers.
	dropNotice bound.Notice
}

// drop counts and warns about a query refused because every worker slot
// was taken.
func (s *Server) drop() {
	s.Dropped.Add(1)
	s.dropNotice.Hit(nil, "dns listener dropping queries: every worker slot is busy", "table", "dns_workers", "listener", s.Name)
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
	Encrypted    bool     `json:"encrypted"`
	DoHPath      string   `json:"doh_path,omitempty"`
	QueriesUDP   uint64   `json:"queries_udp"`
	QueriesTCP   uint64   `json:"queries_tcp"`
	QueriesDoT   uint64   `json:"queries_dot"`
	QueriesDoH   uint64   `json:"queries_doh"`
	QueriesDoQ   uint64   `json:"queries_doq"`
	QueriesLocal uint64   `json:"queries_local"`
	// LocalNames are the names answered from the local record set.
	LocalNames []string `json:"local_names,omitempty"`
	// DoQ reports whether DNS over QUIC is served on this listener.
	DoQ    bool          `json:"doq"`
	DNSSEC *DNSSECStatus `json:"dnssec,omitempty"`
	// Tunnel reports the tunnelling detector when one is configured.
	Tunnel *TunnelStatus `json:"tunnel,omitempty"`
}

// TunnelStatus is the management view of the tunnelling detector.
type TunnelStatus struct {
	Action     string `json:"action"`
	Detections uint64 `json:"detections"`
	Blocked    uint64 `json:"blocked"`
	Tracked    int    `json:"tracked"`
	Evicted    uint64 `json:"evicted"`
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
	old := s.policy.Swap(p)
	s.cache.Resize(cacheEntries)
	if old != nil && old.Resolver != nil && old.Resolver != p.Resolver {
		old.Resolver.Close() // idle encrypted connections of the previous policy
	}
}

// Close releases the policy's resolver connections (after Shutdown).
func (s *Server) Close() {
	if p := s.policy.Load(); p != nil && p.Resolver != nil {
		p.Resolver.Close()
	}
}

// Purge empties the cache.
func (s *Server) Purge() int { return s.cache.Purge() }

// Status reports counters.
func (s *Server) Status() Status {
	p := s.policy.Load()
	st := Status{Listener: s.Name, Queries: s.Queries.Load(), CacheHits: s.Hits.Load(), CacheEntries: s.cache.Len(),
		Blocked: s.Blocked.Load(), Refused: s.Refused.Load(), Dropped: s.Dropped.Load(), ServFail: s.ServFail.Load(),
		Truncated: s.Truncated.Load(), FormErr: s.FormErr.Load(), Encrypted: s.Encrypted, DoQ: s.QUIC,
		QueriesUDP: s.UDP.Load(), QueriesTCP: s.TCP.Load(), QueriesDoT: s.DoT.Load(), QueriesDoH: s.DoH.Load(), QueriesDoQ: s.DoQ.Load(), QueriesLocal: s.Local.Load()}
	if p != nil {
		st.LocalNames = p.Local.Names()
	}
	if s.Encrypted {
		st.DoHPath = s.DoHPath
		if st.DoHPath == "" {
			st.DoHPath = DefaultDoHPath
		}
	}
	if p != nil {
		if p.DNSSEC != nil {
			d := p.DNSSEC.Status()
			st.DNSSEC = &d
		}
		if p.Block != nil {
			st.BlockEntries = p.Block.Len()
		}
		if p.Resolver != nil {
			st.Upstreams = p.Resolver.Servers()
			st.UpstreamFail = p.Resolver.Failures.Load()
		}
		if t := p.Tunnel; t != nil {
			ts := t.Snapshot()
			st.Tunnel = &ts
		}
	}
	return st
}

// Serve runs the UDP and TCP loops until Shutdown. On an encrypted
// listener it also runs the DoH http server behind the ALPN demultiplexer.
func (s *Server) Serve() {
	if s.udp != nil {
		s.wg.Add(1)
		go s.serveUDP()
	}
	if s.tcp != nil {
		if s.Encrypted {
			s.doh = newChanListener(s.tcp.Addr())
			s.dohSrv = &http.Server{Handler: s, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
				WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 16 << 10,
				HTTP2: &http.HTTP2Config{MaxConcurrentStreams: cap(s.sem)}}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				_ = s.dohSrv.Serve(s.doh)
			}()
		}
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
			s.drop()
			continue
		}
		query := make([]byte, n)
		copy(query, buf[:n])
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-s.sem }()
			// One malformed datagram must not end the process: parsing
			// runs on attacker-controlled bytes (see safe.Guard).
			defer safe.Guard("dns udp query")
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
			defer safe.Guard("dns tcp connection")
			s.serveConn(c)
		}()
	}
}

func (s *Server) serveConn(c net.Conn) {
	if s.Encrypted && !s.demux(c) {
		return // handed to the DoH server, or failed the handshake
	}
	defer func() { _ = c.Close() }()
	client := clientOf(c.RemoteAddr())
	proto := "tcp"
	if s.Encrypted {
		proto = "dot"
	}
	for i := 0; i < 1000; i++ { // queries per connection
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		query, err := ReadTCP(c, MaxMessage)
		if err != nil {
			return
		}
		select {
		case s.sem <- struct{}{}:
		default:
			s.drop()
			return
		}
		resp := s.handle(query, client, true, proto)
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
		if s.dohSrv != nil {
			_ = s.dohSrv.Shutdown(ctx)
			_ = s.doh.Close()
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

// Handle answers one query; nil means drop without a response. tcp
// says the client used a stream transport (the answer is not truncated).
func (s *Server) Handle(query []byte, client netip.Addr, tcp bool) []byte {
	proto := "udp"
	if tcp {
		proto = "tcp"
	}
	return s.handle(query, client, tcp, proto)
}

func (s *Server) handle(query []byte, client netip.Addr, tcp bool, proto string) []byte {
	start := time.Now()
	s.Queries.Add(1)
	switch proto {
	case "udp":
		s.UDP.Add(1)
	case "tcp":
		s.TCP.Add(1)
	case "dot":
		s.DoT.Add(1)
	case "doh":
		s.DoH.Add(1)
	case "doq":
		// counted by the DoQ server, which sees the stream
	}
	h, err := ParseHeader(query)
	if err != nil || h.Response() {
		s.drop()
		return nil
	}
	if s.hooks.Banned != nil && s.hooks.Banned(client) {
		s.drop()
		return nil
	}
	p := s.policy.Load()
	if p.RateLimit != nil && !p.RateLimit.Allow(client.String()) {
		s.drop()
		return nil
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
	// An ANY query over UDP is an amplifier's favourite: one small
	// question, every record the name has. RFC 8482 lets a resolver
	// refuse to expand it; answering with TC set costs the client a TCP
	// round trip, which a spoofed source cannot complete, and costs a
	// real client almost nothing.
	if q.Type == TypeANY && !tcp {
		s.Truncated.Add(1)
		return s.finish(query, qEnd, h, q, client, proto, start, "any_truncated", Truncate(Reply(query, qEnd, h, RcodeNoError), qEnd))
	}
	// A name this resolver owns is answered from the local set and
	// never forwarded: an upstream answer would contradict it, and for
	// the discovery name there is no upstream that could answer
	// truthfully at all.
	if recs, owned := p.Local.Lookup(q); owned {
		s.Local.Add(1)
		return s.finish(query, qEnd, h, q, client, proto, start, "local",
			s.fit(query, qEnd, h, AnswerLocal(query, qEnd, h, q, recs), len(query), tcp))
	}
	if p.Block != nil && p.Block.Match(q.Name) {
		s.Blocked.Add(1)
		if s.hooks.Event != nil {
			s.hooks.Event(client, "dns_blocked", proto != "udp", "listener", s.Name, "name", q.Name, "type", TypeName(q.Type), "proto", proto)
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
	// A domain this client was caught tunnelling under stays refused
	// for the cooldown. It is checked here rather than after the answer
	// because the point of blocking is that the query does not reach
	// the name server the tunnel is delegated to.
	if dom, blocked := p.Tunnel.Blocks(client, q.Name, start); blocked {
		s.TunnelBlocked.Add(1)
		s.Blocked.Add(1)
		if s.hooks.Event != nil {
			s.hooks.Event(client, "dns_tunnel", proto != "udp", "listener", s.Name,
				"domain", dom, "name", q.Name, "type", TypeName(q.Type), "proto", proto, "detail", "cooldown")
		}
		return s.finish(query, qEnd, h, q, client, proto, start, "tunnel", Reply(query, qEnd, h, RcodeNXDomain))
	}
	now := time.Now()
	var qm *Message // parsed client query, only with validation on
	if p.DNSSEC != nil {
		qm, _ = ParseMessage(query)
	}
	if h.RecursionDesired() {
		if resp, rEnd := s.cache.Get(q, h.ID, now); resp != nil {
			s.Hits.Add(1)
			if qm != nil {
				resp = s.finalizeDNSSEC(resp, qm, h)
				if _, e, err := ParseQuestion(resp); err == nil {
					rEnd = e
				}
			}
			return s.finish(query, qEnd, h, q, client, proto, start, "cache", s.fit(query, qEnd, h, resp, rEnd, tcp))
		}
	}
	// Upstream transport is the resolver's business: UDP first with TCP
	// on truncation for plain servers whatever the client used, so a
	// stream client (TCP, DoH) does not force a TCP dial per query.
	budget := p.Resolver.timeout * time.Duration(max(len(p.Resolver.servers), 1))
	if p.DNSSEC != nil {
		budget *= 4 // chain lookups
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	upQuery := query
	if p.DNSSEC != nil {
		upQuery = withDO(query) // the upstream must return signatures
	}
	resp, err := p.Resolver.Exchange(ctx, upQuery, qEnd, q, len(query) > maxUDP)
	if err != nil {
		s.ServFail.Add(1)
		return s.finish(query, qEnd, h, q, client, proto, start, "servfail", Reply(query, qEnd, h, RcodeServFail))
	}
	source := "upstream"
	cacheable := true
	if p.DNSSEC != nil {
		var res Result
		res, resp = p.DNSSEC.Validate(ctx, query, qEnd, h, resp)
		source = "upstream:" + res.String()
		// The cache is shared by every client of the listener and its
		// key records nothing about CD, DO or the validation result, so
		// only an answer this node stands behind may enter it. A client
		// that sets CD is asking to see an answer the proxy would refuse
		// ("I will check it myself"); it must not also get to install
		// that answer for everybody else, which is the whole of DNSSEC
		// undone by one bit from any client that can reach the port.
		cacheable = res == Secure || res == Insecure
		if res == Bogus && h.Flags&flagCD == 0 {
			s.ServFail.Add(1)
			if s.hooks.Event != nil {
				s.hooks.Event(client, "dns_bogus", proto != "udp", "listener", s.Name, "name", q.Name, "type", TypeName(q.Type), "proto", proto)
			}
			return s.finish(query, qEnd, h, q, client, proto, start, source, resp)
		}
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
		if ttl > 0 && cacheable {
			s.cache.Put(q, resp, rEnd, rh, ttl, now)
		}
	}
	if qerr != nil {
		rEnd = qEnd
	}
	if qm != nil {
		resp = s.finalizeDNSSEC(resp, qm, h)
		if _, e, err := ParseQuestion(resp); err == nil {
			rEnd = e
		}
	}
	return s.finish(query, qEnd, h, q, client, proto, start, source, s.fit(query, qEnd, h, resp, rEnd, tcp))
}

// finalizeDNSSEC shapes a validated response for the client: AD only
// when the client asked (AD or DO set), signatures only with DO.
func (s *Server) finalizeDNSSEC(resp []byte, qm *Message, h Header) []byte {
	do, _ := clientDO(qm)
	out := StripDNSSEC(resp, qm)
	if !do && h.Flags&flagAD == 0 && len(out) >= 4 {
		if out[2]&(flagAD>>8) != 0 {
			if len(out) == len(resp) && &out[0] == &resp[0] {
				out = append([]byte(nil), out...)
			}
			out[2] &^= flagAD >> 8
		}
	}
	return out
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
	p := s.policy.Load()
	rcode := -1
	if rh, err := ParseHeader(resp); err == nil {
		rcode = rh.Rcode()
	}
	// Every answered query is measured, whatever answered it: a tunnel
	// whose names were cached, or refused, or failed upstream, is still
	// a tunnel, and a detector that only saw the queries that reached an
	// upstream would be one a client could hide from by being noisy.
	// The two exceptions are the paths that produced no question to
	// measure and the refusal this detector itself caused.
	if p != nil && p.Tunnel != nil && source != "tunnel" && source != "formerr" {
		if det, ok := p.Tunnel.Observe(client, q, rcode, start); ok {
			s.Tunnels.Add(1)
			if s.hooks.Event != nil {
				s.hooks.Event(client, "dns_tunnel", proto != "udp", "listener", s.Name,
					"domain", det.Domain, "signals", strings.Join(det.Reasons, ","),
					"queries", det.Queries, "payload_bytes", det.Payload, "proto", proto)
			}
		}
	}
	if p != nil && p.LogQueries && s.hooks.Access != nil {
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
	case TypeSRV:
		return "SRV"
	case TypeDNAME:
		return "DNAME"
	case TypeDS:
		return "DS"
	case TypeRRSIG:
		return "RRSIG"
	case TypeNSEC:
		return "NSEC"
	case TypeDNSKEY:
		return "DNSKEY"
	case TypeNSEC3:
		return "NSEC3"
	case TypeNSEC3PARAM:
		return "NSEC3PARAM"
	case 65:
		return "HTTPS"
	}
	return "TYPE" + strconv.Itoa(int(t))
}
