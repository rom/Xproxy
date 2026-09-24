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
	// Answers screens where an upstream answer points, which is where
	// rebinding and the metadata endpoint live. nil allows anything.
	Answers *AnswerPolicy
	// ECS is strip (the default) or forward: what happens to a client's
	// EDNS Client Subnet option on the way upstream.
	ECS string
	// ServeStale is how long past its TTL an answer is kept so it can
	// be served when the upstream has nothing (RFC 8767). 0 disables.
	ServeStale time.Duration
	// StaleTTL is the TTL a stale answer carries. Default 30s, which is
	// what RFC 8767 section 4 recommends.
	StaleTTL time.Duration
	// Prefetch refreshes an entry that is nearly expired when a query
	// arrives for it, so a popular name is answered from the cache
	// rather than waiting on the upstream once per TTL.
	Prefetch bool
	// PrefetchThreshold is the share of the TTL that must be left for a
	// query to trigger a refresh. Default 0.1.
	PrefetchThreshold float64
	// Cookies is off, respond (the default) or require: what this
	// listener does with DNS cookies (RFC 7873).
	Cookies string
	// CookieLifetime is how long a server cookie stays valid. Default 1h.
	CookieLifetime time.Duration
	// Denials remembers validated non-existence so a name in a gap an
	// NSEC already proved empty is answered without asking again
	// (RFC 8198). nil disables it; it needs DNSSEC.
	Denials *Denials
	// DNS64 answers an AAAA query for an IPv4-only name with the address
	// embedded in a translation prefix (RFC 6147). nil disables it.
	DNS64 *DNS64
	// Views answer the same name differently by who asked: see views.go.
	// The first view whose networks contain the client wins; a client in
	// none of them gets the listener's own records and block list.
	Views []*View
}

// staleSeconds is the TTL a stale answer carries, in seconds.
func staleSeconds(p *Policy) uint32 {
	d := p.StaleTTL
	if d <= 0 {
		d = 30 * time.Second
	}
	return uint32(d / time.Second) //nolint:gosec // bounded by validation
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
	// Refuse records one refused or dropped query by its reason. The
	// per-listener counters say how many queries a listener refused;
	// this says which policy did it, which is the difference between
	// knowing that queries are being dropped and knowing that they are
	// being dropped because every worker slot is busy.
	Refuse func(reason string)
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
	// prefetch bounds the refreshes running at once, separately from
	// sem: a refresh is work nobody is waiting for.
	prefetch chan struct{}
	// jar issues the DNS cookies. Its secret belongs to the process
	// rather than to the policy, so a reload does not invalidate every
	// cookie the listener has handed out.
	jar *cookieJar
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
	// Local counts answers served from the local record set, and Viewed
	// the queries a split-horizon view answered rather than the
	// listener's own policy. Synthesised counts the AAAA answers DNS64
	// built from an A record.
	Local, Viewed, Synthesised atomic.Uint64
	// NSECDenied counts the NXDOMAIN answers synthesised from a
	// validated NSEC gap (RFC 8198).
	NSECDenied atomic.Uint64
	// Tunnels counts detections and TunnelBlocked the queries refused
	// because of one.
	Tunnels, TunnelBlocked atomic.Uint64
	// AnswerDenied counts answers refused for where they pointed and
	// AnswerStripped those that had records removed; ECSStripped counts
	// the queries whose client subnet option was not forwarded.
	AnswerDenied, AnswerStripped, ECSStripped atomic.Uint64
	// Stale counts answers served after they expired because the
	// upstream had nothing, and Prefetched the refreshes started before
	// an entry expired.
	Stale, Prefetched atomic.Uint64
	// CookiesIssued counts the cookies handed out, CookiesVerified the
	// UDP queries whose source a cookie proved, and CookiesRefused the
	// queries turned back for the want of one.
	CookiesIssued, CookiesVerified, CookiesRefused atomic.Uint64
	// dropNotice warns when queries are dropped for lack of workers.
	dropNotice bound.Notice
}

// drop counts a query that is not answered at all, by reason. The
// warning is for the one reason an operator can act on by changing the
// configuration: a listener out of worker slots is a listener whose
// max_in_flight is too low for its traffic.
func (s *Server) drop(reason string) {
	s.Dropped.Add(1)
	s.refuse(reason)
	if reason == DropWorkersBusy {
		s.dropNotice.Hit(nil, "dns listener dropping queries: every worker slot is busy", "table", "dns_workers", "listener", s.Name)
	}
}

// The reasons a query is dropped without an answer. They are named
// because they are also metric label values: a spelling change here is
// visible in somebody's dashboard.
const (
	// DropWorkersBusy is max_in_flight: every worker slot was taken.
	DropWorkersBusy = "workers_busy"
	// DropMalformed is a datagram that is not a question: an
	// unparseable header, or a response sent to a resolver.
	DropMalformed = "malformed"
	// DropBanned is a client the ban list holds.
	DropBanned = "banned"
	// DropRateLimit is the per-client query rate.
	DropRateLimit = "rate_limit"
)

// refuse records one refusal by reason, for the operational counters.
func (s *Server) refuse(reason string) {
	if s.hooks.Refuse != nil {
		s.hooks.Refuse(reason)
	}
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
	// UpstreamResumed counts encrypted upstream connections that
	// resumed a TLS session instead of running a full handshake, and
	// UpstreamResumption reports whether they may.
	UpstreamResumed    uint64 `json:"upstream_resumed"`
	UpstreamResumption bool   `json:"upstream_resumption"`
	Encrypted          bool   `json:"encrypted"`
	DoHPath            string `json:"doh_path,omitempty"`
	QueriesUDP         uint64 `json:"queries_udp"`
	QueriesTCP         uint64 `json:"queries_tcp"`
	QueriesDoT         uint64 `json:"queries_dot"`
	QueriesDoH         uint64 `json:"queries_doh"`
	QueriesDoQ         uint64 `json:"queries_doq"`
	QueriesLocal       uint64 `json:"queries_local"`
	// Views are the split-horizon views in order, and QueriesViewed the
	// queries one of them answered.
	Views         []string `json:"views,omitempty"`
	QueriesViewed uint64   `json:"queries_viewed"`
	// QueriesSynthesised counts the AAAA answers DNS64 built from an A
	// record, and QueriesNSEC the NXDOMAIN answers taken from a
	// validated NSEC gap; DenialsHeld is the size of that store.
	QueriesSynthesised uint64 `json:"queries_synthesised"`
	QueriesNSEC        uint64 `json:"queries_nsec"`
	DenialsHeld        int    `json:"denials_held"`
	// AnswerDenied and AnswerStripped report the answer policy, and
	// ECSStripped the client subnet options removed.
	AnswerDenied   uint64 `json:"answer_denied"`
	AnswerStripped uint64 `json:"answer_stripped"`
	ECSStripped    uint64 `json:"ecs_stripped"`
	// Stale reports the answers served past their TTL (RFC 8767) and
	// Prefetched the refreshes started before an entry expired.
	Stale      uint64 `json:"stale"`
	Prefetched uint64 `json:"prefetched"`
	// Cookies reports the DNS cookie exchange (RFC 7873).
	CookiesIssued   uint64 `json:"cookies_issued"`
	CookiesVerified uint64 `json:"cookies_verified"`
	CookiesRefused  uint64 `json:"cookies_refused"`
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
		sem: make(chan struct{}, max(inFlight, 1)), prefetch: make(chan struct{}, maxPrefetch),
		cons: map[net.Conn]struct{}{}, done: make(chan struct{})}
	s.policy.Store(p)
	s.cache.SetStale(p.ServeStale)
	// A jar the listener cannot make is a listener without cookies
	// rather than a listener that will not start: the only way this
	// fails is the system random source, and the rest of the resolver
	// works without it.
	if jar, err := newCookieJar(p.CookieLifetime); err == nil {
		s.jar = jar
	}
	return s
}

// Apply swaps the policy (reload). The cache is kept and resized.
func (s *Server) Apply(p *Policy, cacheEntries int) {
	old := s.policy.Swap(p)
	s.cache.Resize(cacheEntries)
	s.cache.SetStale(p.ServeStale)
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
func (s *Server) Purge() int {
	n := s.cache.Purge()
	if p := s.policy.Load(); p != nil {
		n += p.Denials.Purge()
	}
	return n
}

// Status reports counters.
func (s *Server) Status() Status {
	p := s.policy.Load()
	st := Status{Listener: s.Name, Queries: s.Queries.Load(), CacheHits: s.Hits.Load(), CacheEntries: s.cache.Len(),
		Blocked: s.Blocked.Load(), Refused: s.Refused.Load(), Dropped: s.Dropped.Load(), ServFail: s.ServFail.Load(),
		Truncated: s.Truncated.Load(), FormErr: s.FormErr.Load(), Encrypted: s.Encrypted, DoQ: s.QUIC,
		QueriesUDP: s.UDP.Load(), QueriesTCP: s.TCP.Load(), QueriesDoT: s.DoT.Load(), QueriesDoH: s.DoH.Load(), QueriesDoQ: s.DoQ.Load(), QueriesLocal: s.Local.Load(),
		AnswerDenied: s.AnswerDenied.Load(), AnswerStripped: s.AnswerStripped.Load(), ECSStripped: s.ECSStripped.Load(),
		Stale: s.Stale.Load(), Prefetched: s.Prefetched.Load(),
		CookiesIssued: s.CookiesIssued.Load(), CookiesVerified: s.CookiesVerified.Load(), CookiesRefused: s.CookiesRefused.Load(),
		QueriesViewed: s.Viewed.Load(), QueriesSynthesised: s.Synthesised.Load(),
		QueriesNSEC: s.NSECDenied.Load()}
	if p != nil {
		st.LocalNames = p.Local.Names()
		st.Views = p.ViewNames()
		st.DenialsHeld = p.Denials.Len()
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
			st.UpstreamResumed = p.Resolver.Resumed.Load()
			st.UpstreamResumption = p.Resolver.SessionResumption()
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
				WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 16 << 10}
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
			s.drop(DropWorkersBusy)
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
			s.drop(DropWorkersBusy)
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
	// A stream transport has already proved the peer's address by
	// getting here; a datagram has proved nothing until a cookie says
	// otherwise.
	a := &asked{client: client, proto: proto, start: start, stream: tcp, verified: tcp}
	h, err := ParseHeader(query)
	if err != nil || h.Response() {
		s.drop(DropMalformed)
		return nil
	}
	if s.hooks.Banned != nil && s.hooks.Banned(client) {
		s.drop(DropBanned)
		return nil
	}
	p := s.policy.Load()
	if p.RateLimit != nil && !p.RateLimit.Allow(client.String()) {
		s.drop(DropRateLimit)
		return nil
	}
	if h.QDCount != 1 {
		s.FormErr.Add(1)
		s.refuse("formerr")
		return s.finish(a, Question{}, "formerr", Reply(query[:headerLen], headerLen, h, RcodeFormErr))
	}
	q, qEnd, err := ParseQuestion(query)
	if err != nil {
		s.FormErr.Add(1)
		s.refuse("formerr")
		return s.finish(a, Question{}, "formerr", Reply(query[:headerLen], headerLen, h, RcodeFormErr))
	}
	if len(p.AllowClients) > 0 && !netutil.Contains(p.AllowClients, client) {
		s.Refused.Add(1)
		s.refuse("client_not_allowed")
		return s.finish(a, q, "refused", Reply(query, qEnd, h, RcodeRefused))
	}
	if h.Opcode() != 0 {
		s.refuse("opcode")
		return s.finish(a, q, "notimp", Reply(query, qEnd, h, RcodeNotImp))
	}
	// The cookie is settled before any work is done for this query,
	// because the work is what a spoofed source is trying to buy: a
	// large answer for somebody else's link, a lookup at this proxy's
	// expense, a security event against an address it does not hold.
	verdict, cookie := s.cookies(p, query, qEnd, h, client, tcp, time.Now())
	a.cookie = cookie
	switch verdict {
	case cookieOK:
		a.verified = true
		if !tcp {
			s.CookiesVerified.Add(1)
		}
	case cookieNew:
		s.CookiesIssued.Add(1)
	case cookieBad:
		// BADCOOKIE carries the cookie to come back with, so a
		// cookie-aware client retries once and succeeds. Nothing is
		// looked up for it: that is the whole saving.
		s.CookiesIssued.Add(1)
		s.CookiesRefused.Add(1)
		s.Refused.Add(1)
		s.refuse("cookie_required")
		// The reply is built here rather than left to finish, because
		// the extended rcode lives in the OPT record the cookie goes
		// into and has to be written after it.
		resp := badCookieReply(query, qEnd, h, cookie)
		a.cookie = nil
		return s.finish(a, q, "badcookie", resp)
	case cookieAbsent:
		// Nothing to echo, so there is no retry to invite: this client
		// does not speak cookies and this listener requires them.
		s.CookiesRefused.Add(1)
		s.Refused.Add(1)
		s.refuse("cookie_missing")
		return s.finish(a, q, "refused", Reply(query, qEnd, h, RcodeRefused))
	case cookieMalformed:
		s.FormErr.Add(1)
		s.refuse("cookie_malformed")
		return s.finish(a, q, "formerr", Reply(query, qEnd, h, RcodeFormErr))
	}
	// An ANY query over UDP is an amplifier's favourite: one small
	// question, every record the name has. RFC 8482 lets a resolver
	// refuse to expand it; answering with TC set costs the client a TCP
	// round trip, which a spoofed source cannot complete, and costs a
	// real client almost nothing.
	if q.Type == TypeANY && !tcp {
		s.Truncated.Add(1)
		s.refuse("any_over_udp")
		return s.finish(a, q, "any_truncated", Truncate(Reply(query, qEnd, h, RcodeNoError), qEnd))
	}
	// Which answers this client gets: a view's, where one covers it.
	// Everything a view decides happens here, before anything is asked
	// upstream, which is what lets the cache stay shared (views.go).
	ans := p.answersFor(p.viewFor(client))
	a.view = ans.view
	if ans.view != "" {
		s.Viewed.Add(1)
	}
	// A name this resolver owns is answered from the local set and
	// never forwarded: an upstream answer would contradict it, and for
	// the discovery name there is no upstream that could answer
	// truthfully at all.
	if recs, owned := ans.local.Lookup(q); owned {
		s.Local.Add(1)
		return s.finish(a, q, "local",
			s.fit(a, query, qEnd, h, AnswerLocal(query, qEnd, h, q, recs), len(query)))
	}
	if ans.block != nil && ans.block.Match(q.Name) {
		s.Blocked.Add(1)
		s.refuse("blocked")
		if s.hooks.Event != nil {
			s.hooks.Event(client, "dns_blocked", a.verified, "listener", s.Name, "name", q.Name, "type", TypeName(q.Type), "proto", proto, "view", ans.view)
		}
		var resp []byte
		switch ans.action {
		case "refuse":
			resp = Reply(query, qEnd, h, RcodeRefused)
		case "sinkhole":
			addr := ans.sinkhole4
			if q.Type == TypeAAAA {
				addr = ans.sinkhole6
			}
			resp = Sinkhole(query, qEnd, h, q, addr, p.SinkholeTTL)
		default:
			resp = Reply(query, qEnd, h, RcodeNXDomain)
		}
		return s.finish(a, q, "blocked", resp)
	}
	// A domain this client was caught tunnelling under stays refused
	// for the cooldown. It is checked here rather than after the answer
	// because the point of blocking is that the query does not reach
	// the name server the tunnel is delegated to.
	if dom, blocked := p.Tunnel.Blocks(client, q.Name, start); blocked {
		s.TunnelBlocked.Add(1)
		s.Blocked.Add(1)
		s.refuse("tunnel")
		if s.hooks.Event != nil {
			s.hooks.Event(client, "dns_tunnel", a.verified, "listener", s.Name,
				"domain", dom, "name", q.Name, "type", TypeName(q.Type), "proto", proto, "detail", "cooldown")
		}
		return s.finish(a, q, "tunnel", Reply(query, qEnd, h, RcodeNXDomain))
	}
	now := time.Now()
	var qm *Message // parsed client query, only with validation on
	if p.DNSSEC != nil {
		qm, _ = ParseMessage(query)
	}
	if h.RecursionDesired() {
		if resp, rEnd := s.cache.Get(q, h.ID, now); resp != nil {
			s.Hits.Add(1)
			source := "cache"
			// The policy is screened again on the way out, not only on
			// the way in. A reload may deny a range the entry was stored
			// under, and an entry the policy would refuse must not
			// outlive the reload that refused it.
			if sc := s.screen(p, query, qEnd, h, q, resp, rEnd); sc.action != "" {
				s.cache.Drop(q)
				s.answerEvent(client, proto, q, sc)
				return s.finish(a, q, "cache:answer:"+sc.action,
					s.fit(a, query, qEnd, h, sc.resp, sc.rEnd))
			}
			s.maybePrefetch(p, q, now)
			// An AAAA answer with nothing in it is where DNS64 has work
			// to do, and a cached one is no different from a fresh one.
			if out, outEnd, ok := s.dns64(context.Background(), p, query, qEnd, h, q, client, proto, now, resp, rEnd, tcp); ok {
				return s.finish(a, q, source+":dns64", s.fit(a, query, qEnd, h, out, outEnd))
			}
			if qm != nil {
				resp = s.finalizeDNSSEC(resp, qm, h)
				if _, e, err := ParseQuestion(resp); err == nil {
					rEnd = e
				}
			}
			return s.finish(a, q, source, s.fit(a, query, qEnd, h, resp, rEnd))
		}
	}
	// A name a validated NSEC already put inside an empty gap needs no
	// upstream query at all (RFC 8198). Only for a client that did not
	// ask for signatures: a synthesised NXDOMAIN carries none, and a
	// client that set DO asked for something this cannot give.
	if p.Denials != nil && qm != nil && h.RecursionDesired() && h.Flags&flagCD == 0 {
		if do, _ := clientDO(qm); !do && p.Denials.Covers(q, now) {
			s.NSECDenied.Add(1)
			return s.finish(a, q, "nsec", s.fit(a, query, qEnd, h, Reply(query, qEnd, h, RcodeNXDomain), qEnd))
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
	// The client's subnet, if it sent one, does not go upstream: the
	// cache key has no subnet in it, so a per-subnet answer would be
	// stored for every client of this listener. withDO has already
	// replaced the OPT record, so this only has work to do without
	// validation.
	if p.ECS != ECSForward && HasECS(upQuery, qEnd, h) {
		if stripped := StripECS(upQuery); len(stripped) > 0 {
			upQuery = stripped
			s.ECSStripped.Add(1)
		}
	}
	lk := s.ask(ctx, p, query, upQuery, qEnd, h, q, client, proto, now, len(query) > maxUDP)
	if lk.failed(p) {
		// The upstream has nothing to say. An expired answer this
		// resolver already holds is worth more than a SERVFAIL
		// (RFC 8767): the name almost certainly still resolves where it
		// did a minute ago, and a client that cannot be told that
		// cannot reach the upstream itself either.
		if resp, rEnd := s.cache.Stale(q, h.ID, now, staleSeconds(p)); resp != nil {
			s.Stale.Add(1)
			return s.finish(a, q, "stale", s.fit(a, query, qEnd, h, resp, rEnd))
		}
		if lk.err != nil {
			s.ServFail.Add(1)
			return s.finish(a, q, "servfail", Reply(query, qEnd, h, RcodeServFail))
		}
	}
	if lk.bogus {
		s.ServFail.Add(1)
		if s.hooks.Event != nil {
			s.hooks.Event(client, "dns_bogus", a.verified, "listener", s.Name, "name", q.Name, "type", TypeName(q.Type), "proto", proto)
		}
		return s.finish(a, q, lk.source, lk.resp)
	}
	resp, rEnd := lk.resp, lk.rEnd
	if out, outEnd, ok := s.dns64(ctx, p, query, qEnd, h, q, client, proto, now, resp, rEnd, len(query) > maxUDP); ok {
		// The reply is built from the client's question, so it carries no
		// signatures and no AD bit to shape (RFC 6147 section 5.5).
		return s.finish(a, q, lk.source+":dns64", s.fit(a, query, qEnd, h, out, outEnd))
	}
	if lk.synthetic {
		qm = nil // a synthetic answer carries no signatures to shape
	}
	if qm != nil {
		resp = s.finalizeDNSSEC(resp, qm, h)
		if _, e, err := ParseQuestion(resp); err == nil {
			rEnd = e
		}
	}
	return s.finish(a, q, lk.source, s.fit(a, query, qEnd, h, resp, rEnd))
}

// maxPrefetch bounds the refreshes running at once. A prefetch is work
// nobody is waiting for, so it gets a budget of its own rather than a
// share of max_in_flight: a resolver that answered clients more slowly
// because it was busy refreshing would have the feature backwards.
const maxPrefetch = 64

// defaultPrefetchThreshold is the share of the TTL below which a query
// triggers a refresh.
const defaultPrefetchThreshold = 0.1

// maybePrefetch refreshes an entry that a query has just been answered
// from and that is nearly expired, so the name stays answered from the
// cache instead of one client per TTL waiting on the upstream.
//
// The refresh is claimed on the cache entry, so a burst of queries for
// the same nearly-expired name starts one refresh and not a hundred --
// which is the stampede this feature exists to prevent and would
// otherwise cause.
func (s *Server) maybePrefetch(p *Policy, q Question, now time.Time) {
	if !p.Prefetch || q.Class != ClassIN {
		return
	}
	threshold := p.PrefetchThreshold
	if threshold <= 0 {
		threshold = defaultPrefetchThreshold
	}
	left, ok := s.cache.Remaining(q, now)
	if !ok || left > threshold {
		return
	}
	select {
	case <-s.done:
		return
	default:
	}
	// The claim is taken before the slot, so a full prefetch budget does
	// not leave a claim behind that nothing will release.
	if !s.cache.Refreshing(q) {
		return
	}
	select {
	case s.prefetch <- struct{}{}:
	default:
		s.cache.Refreshed(q)
		return
	}
	s.Prefetched.Add(1)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() { <-s.prefetch }()
		defer safe.Guard("dns prefetch")
		s.refresh(p, q)
	}()
}

// refresh asks the upstream for a question already in the cache and
// lets ask store what comes back. The query is this proxy's own: a
// fresh id, the same question, and no client to answer.
func (s *Server) refresh(p *Policy, q Question) {
	query, err := Query(0, q.Name, q.Type)
	if err != nil {
		s.cache.Refreshed(q)
		return
	}
	_, qEnd, err := ParseQuestion(query)
	if err != nil {
		s.cache.Refreshed(q)
		return
	}
	qh, err := ParseHeader(query)
	if err != nil {
		s.cache.Refreshed(q)
		return
	}
	upQuery := query
	if p.DNSSEC != nil {
		upQuery = withDO(query)
	}
	budget := p.Resolver.timeout * time.Duration(max(len(p.Resolver.servers), 1))
	if p.DNSSEC != nil {
		budget *= 4
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	// No client and no proto: a refusal here is not somebody's query
	// being refused, and attributing it to the client whose query
	// happened to trigger the refresh would put a security event against
	// an address that did nothing.
	lk := s.ask(ctx, p, query, upQuery, qEnd, qh, q, netip.Addr{}, "prefetch", time.Now(), false)
	if lk.err != nil || lk.bogus {
		// A refresh that came back with nothing leaves the entry as it
		// was, to expire or be served stale on its own terms, and
		// releases the claim so the next query may try again.
		s.cache.Refreshed(q)
	}
}

// lookup is what one upstream exchange came to: the answer to send, the
// label for the log, and the two outcomes the caller has to act on.
type lookup struct {
	resp   []byte
	rEnd   int
	source string
	// err is an upstream that answered nothing at all.
	err error
	// bogus says validation rejected the answer and the client did not
	// ask to see it anyway.
	bogus bool
	// synthetic says resp is this proxy's own answer rather than the
	// upstream's, so there are no signatures in it to shape.
	synthetic bool
	// rcode is the upstream answer's code, or -1 when there was none.
	rcode int
}

// failed reports a lookup a stale answer may stand in for: no answer at
// all, or a SERVFAIL on a listener that is not validating.
//
// A SERVFAIL counts only without validation, deliberately. With
// validation on it is the code a resolver returns for an answer it
// rejected, and covering that with an expired answer of our own would
// undo the validation: the client would be handed, as a last resort, the
// very answer somebody decided not to trust. Without validation a
// SERVFAIL is what a broken or overloaded upstream says, which is
// exactly the outage RFC 8767 is about.
func (lk lookup) failed(p *Policy) bool {
	if lk.err != nil {
		return true
	}
	return p.DNSSEC == nil && lk.rcode == RcodeServFail
}

// ask exchanges with the upstream, validates, screens where the answer
// points and caches what is left. Everything the client sees -- the
// bogus refusal, the DNSSEC shaping, truncation -- stays with the
// caller, which is what lets a prefetch and a client's query take the
// same path into the cache and a different one back out.
func (s *Server) ask(ctx context.Context, p *Policy, query, upQuery []byte, qEnd int, h Header,
	q Question, client netip.Addr, proto string, now time.Time, stream bool) lookup {
	resp, err := p.Resolver.Exchange(ctx, upQuery, qEnd, q, stream)
	if err != nil {
		return lookup{err: err}
	}
	out := lookup{source: "upstream", rcode: -1}
	cacheable := true
	if p.DNSSEC != nil {
		var res Result
		res, resp = p.DNSSEC.Validate(ctx, query, qEnd, h, resp)
		out.source = "upstream:" + res.String()
		// The cache is shared by every client of the listener and its
		// key records nothing about CD, DO or the validation result, so
		// only an answer this node stands behind may enter it. A client
		// that sets CD is asking to see an answer the proxy would refuse
		// ("I will check it myself"); it must not also get to install
		// that answer for everybody else, which is the whole of DNSSEC
		// undone by one bit from any client that can reach the port.
		cacheable = res == Secure || res == Insecure
		if res == Bogus && h.Flags&flagCD == 0 {
			out.resp, out.rEnd, out.bogus = resp, qEnd, true
			return out
		}
		// A validated NXDOMAIN carries the NSEC records that prove it, and
		// they prove more than the one name that was asked for (RFC 8198).
		// Learned here and nowhere else: the proof is only worth keeping
		// because this is the point at which it has been validated.
		if res == Secure && p.Denials != nil && rcodeOf(resp) == RcodeNXDomain {
			if m, perr := ParseMessage(resp); perr == nil {
				p.Denials.Learn(q, m, now, p.MaxTTL)
			}
		}
	}
	rh, _ := ParseHeader(resp)
	out.rcode = rh.Rcode()
	_, rEnd, qerr := ParseQuestion(resp)
	// Where the answer points is screened before it is cached, so an
	// answer this listener refuses never becomes one it serves.
	if qerr == nil {
		if sc := s.screen(p, query, qEnd, h, q, resp, rEnd); sc.action != "" {
			s.answerEvent(client, proto, q, sc)
			resp, rEnd = sc.resp, sc.rEnd
			out.source += ":answer:" + sc.action
			out.synthetic = true
			if sc.action == AnswerStrip {
				// What is left is what this listener stands behind, so
				// it is what the cache keeps.
				rh, _ = ParseHeader(resp)
			} else {
				cacheable = false
			}
		}
	}
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
	out.resp, out.rEnd = resp, rEnd
	return out
}

// rcodeOf is the response code of a message, or -1 when it has no header.
func rcodeOf(resp []byte) int {
	h, err := ParseHeader(resp)
	if err != nil {
		return -1
	}
	return h.Rcode()
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
//
// A cookie the answer still owes is reserved against the budget rather
// than added past it: the cookie goes on after the fit, and a datagram
// that fits only until the cookie is appended does not fit.
func (s *Server) fit(a *asked, query []byte, qEnd int, h Header, resp []byte, rEnd int) []byte {
	if a.stream {
		return resp
	}
	budget := EDNSSize(query, qEnd, h) - cookieRoom(a.cookie)
	if len(resp) <= budget {
		return resp
	}
	s.Truncated.Add(1)
	return Truncate(resp, rEnd)
}

// asked is the per-query state that more than one step needs: who
// asked, over what, whether the address has been proved, and the cookie
// the answer owes them.
type asked struct {
	client netip.Addr
	proto  string
	start  time.Time
	// stream says the transport is a stream, so the answer is not
	// truncated to a datagram size.
	stream bool
	// verified says the client address completed a round trip: a stream
	// transport, or a UDP query carrying a DNS cookie this listener
	// issued. It decides whether a security event may be attributed to
	// the address the datagram claims.
	verified bool
	// cookie is the COOKIE option value the answer carries, or nil.
	cookie []byte
	// view is the split-horizon view that answered, or "".
	view string
}

func (s *Server) finish(a *asked, q Question, source string, resp []byte) []byte {
	client, proto, start := a.client, a.proto, a.start
	if len(a.cookie) > 0 {
		resp = AddCookie(resp, a.cookie)
	}
	p := s.policy.Load()
	// The extended form, so a BADCOOKIE is logged as 23 rather than as
	// the seven the header alone carries.
	rcode := ExtendedRcode(resp)
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
				s.hooks.Event(client, "dns_tunnel", a.verified, "listener", s.Name,
					"domain", det.Domain, "signals", strings.Join(det.Reasons, ","),
					"queries", det.Queries, "payload_bytes", det.Payload, "proto", proto)
			}
		}
	}
	if p != nil && p.LogQueries && s.hooks.Access != nil {
		attrs := []any{"listener", s.Name, "client_ip", client.String(), "proto", proto, "name", q.Name, "type", TypeName(q.Type),
			"rcode", rcode, "source", source, "bytes", len(resp), "duration_ms", float64(time.Since(start).Microseconds()) / 1000}
		if a.view != "" {
			attrs = append(attrs, "view", a.view)
		}
		s.hooks.Access(attrs...)
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
