package dns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/rom/xproxy/internal/safe"
)

// DNS over QUIC (RFC 9250).
//
// DoT and DoH both carry DNS over TCP, so they inherit its head of line
// blocking: one slow answer holds up every query behind it on the same
// connection, which is exactly the shape of a resolver's traffic. DoQ
// puts each query on its own QUIC stream, so the answers are
// independent, and it keeps the privacy properties of DoT — same
// certificate, same server name — without the HTTP layer DoH adds.
//
// The wire format is the TCP one: a two byte length followed by the
// message, one query and one answer per stream, and the stream is
// closed in each direction when its message is done. The one
// difference that matters is the message id: RFC 9250 requires it to be
// zero, because the stream already identifies the exchange and a
// non-zero id would leak a little about the client's implementation.

// ALPNDoQ is the protocol name RFC 9250 assigns.
const ALPNDoQ = "doq"

// doqMaxQuery bounds a query read from a stream. A DNS message is at
// most 65535 bytes by the length prefix; nothing legitimate is near it.
const doqMaxQuery = 8 << 10

// DoQ application error codes (RFC 9250 section 4.3).
const (
	doqNoError       = 0x0
	doqInternalError = 0x1
	doqProtocolError = 0x2
	doqRequestCancel = 0x3
	doqExcessiveLoad = 0x4
	doqUnspecified   = 0x5
)

// doqStreamTimeout bounds one exchange on a stream.
const doqStreamTimeout = 10 * time.Second

// DoQServer serves DNS over QUIC for one listener.
type DoQServer struct {
	s    *Server
	tr   *quic.Transport
	ln   *quic.Listener
	done chan struct{}
	once sync.Once
	wg   sync.WaitGroup

	// Conns counts accepted QUIC connections; Streams counts queries.
	Conns, Streams, Errors atomic.Uint64
}

// NewDoQ prepares a DoQ server on an existing UDP socket. The TLS
// config is the listener's, with the DoQ ALPN added — a DoQ client and
// a DoT client are the same client with a different transport, so they
// share a certificate.
func NewDoQ(s *Server, pc net.PacketConn, tc *tls.Config, idle time.Duration, maxStreams int) (*DoQServer, error) {
	if s == nil || pc == nil || tc == nil {
		return nil, errors.New("doq: incomplete options")
	}
	q := &DoQServer{s: s, done: make(chan struct{})}
	q.tr = &quic.Transport{Conn: pc}
	conf := tc.Clone()
	// A DoQ connection must not be mistaken for HTTP/3 or anything
	// else: the ALPN is the only thing separating them on one port.
	conf.NextProtos = []string{ALPNDoQ}
	qc := &quic.Config{
		HandshakeIdleTimeout: 5 * time.Second,
		MaxIdleTimeout:       idle,
		MaxIncomingStreams:   int64(maxStreams),
		// A resolver has no use for unidirectional streams, and a
		// client opening them is not speaking DoQ.
		MaxIncomingUniStreams: 0,
		Allow0RTT:             false,
		KeepAlivePeriod:       0,
	}
	ln, err := q.tr.Listen(conf, qc)
	if err != nil {
		_ = q.tr.Close()
		return nil, fmt.Errorf("doq listen: %w", err)
	}
	q.ln = ln
	return q, nil
}

// Addr is the listening address.
func (q *DoQServer) Addr() net.Addr { return q.ln.Addr() }

// Serve accepts connections until Close.
func (q *DoQServer) Serve() {
	q.wg.Add(1)
	go func() {
		defer q.wg.Done()
		for {
			conn, err := q.ln.Accept(context.Background())
			if err != nil {
				select {
				case <-q.done:
					return
				default:
				}
				if errors.Is(err, quic.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
			q.Conns.Add(1)
			q.wg.Add(1)
			go func() {
				defer q.wg.Done()
				q.serveConn(conn)
			}()
		}
	}()
}

func (q *DoQServer) serveConn(conn *quic.Conn) {
	defer func() { _ = conn.CloseWithError(doqNoError, "") }()
	client := netip.Addr{}
	if a, err := netip.ParseAddrPort(conn.RemoteAddr().String()); err == nil {
		client = a.Addr().Unmap()
	}
	for {
		st, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		select {
		case <-q.done:
			_ = conn.CloseWithError(doqNoError, "shutting down")
			return
		default:
		}
		// The same worker bound as every other transport: a client that
		// opens a thousand streams does not get a thousand goroutines.
		select {
		case q.s.sem <- struct{}{}:
		default:
			q.s.drop(DropWorkersBusy)
			st.CancelRead(doqExcessiveLoad)
			st.CancelWrite(doqExcessiveLoad)
			continue
		}
		q.wg.Add(1)
		go func() {
			defer q.wg.Done()
			defer func() { <-q.s.sem }()
			defer safe.Guard("doq query")
			q.serveStream(st, client)
		}()
	}
}

// serveStream reads one query, answers it, and closes the stream. RFC
// 9250 is explicit that a stream carries exactly one exchange.
func (q *DoQServer) serveStream(st *quic.Stream, client netip.Addr) {
	defer func() { _ = st.Close() }()
	_ = st.SetDeadline(time.Now().Add(doqStreamTimeout))
	var length [2]byte
	if _, err := io.ReadFull(st, length[:]); err != nil {
		st.CancelRead(doqProtocolError)
		return
	}
	n := int(binary.BigEndian.Uint16(length[:]))
	if n < headerLen || n > doqMaxQuery {
		q.Errors.Add(1)
		st.CancelRead(doqProtocolError)
		return
	}
	query := make([]byte, n)
	if _, err := io.ReadFull(st, query); err != nil {
		st.CancelRead(doqProtocolError)
		return
	}
	// RFC 9250 section 4.2.1: the id must be zero on the wire. A client
	// that sends one anyway is answered with the same id it used, since
	// refusing the query would break more than it protects, but the
	// answer this server sends always carries zero.
	if id := binary.BigEndian.Uint16(query[:2]); id != 0 {
		q.Errors.Add(1)
	}
	q.Streams.Add(1)
	q.s.DoQ.Add(1)
	// The query is handled as a stream query (TCP semantics): no UDP
	// size limit applies, since QUIC does the fragmenting.
	resp := q.s.handle(query, client, true, "doq")
	if resp == nil {
		return
	}
	SetID(resp, 0)
	out := make([]byte, 2+len(resp))
	binary.BigEndian.PutUint16(out, uint16(len(resp))) //nolint:gosec // a DNS message is bounded by the prefix
	copy(out[2:], resp)
	if _, err := st.Write(out); err != nil {
		q.Errors.Add(1)
	}
}

// Close stops accepting and drops the connections.
func (q *DoQServer) Close() error {
	q.once.Do(func() { close(q.done) })
	err := q.ln.Close()
	_ = q.tr.Close()
	q.wg.Wait()
	return err
}

// exchangeQUIC sends one query to a quic:// upstream. Connections are
// reused: the handshake is the expensive part, and a resolver makes
// many queries to the same server.
func (r *Resolver) exchangeQUIC(ctx context.Context, s *upstreamServer, query []byte) ([]byte, error) {
	conn, err := r.quicConn(ctx, s)
	if err != nil {
		return nil, err
	}
	st, err := conn.OpenStreamSync(ctx)
	if err != nil {
		// The cached connection is dead; drop it and try once more, so
		// an idle timeout on the server side is not an answer lost.
		s.dropQUIC(conn)
		if conn, err = r.quicConn(ctx, s); err != nil {
			return nil, err
		}
		if st, err = conn.OpenStreamSync(ctx); err != nil {
			return nil, err
		}
	}
	defer func() { _ = st.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = st.SetDeadline(dl)
	}
	// The id is zero on the wire; the caller matches on the question.
	out := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(out, uint16(len(query))) //nolint:gosec // bounded by the caller
	copy(out[2:], query)
	if _, err := st.Write(out); err != nil {
		s.dropQUIC(conn)
		return nil, err
	}
	// Half close: the server knows the query is complete, which is what
	// lets it answer without waiting for an idle timeout.
	if err := st.Close(); err != nil {
		s.dropQUIC(conn)
		return nil, err
	}
	var length [2]byte
	if _, err := io.ReadFull(st, length[:]); err != nil {
		s.dropQUIC(conn)
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(length[:]))
	if n < headerLen || n > MaxMessage {
		return nil, fmt.Errorf("doq: answer of %d bytes", n)
	}
	resp := make([]byte, n)
	if _, err := io.ReadFull(st, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// quicConn returns a live connection to the upstream, dialling one when
// the cached connection is missing or closed.
func (r *Resolver) quicConn(ctx context.Context, s *upstreamServer) (*quic.Conn, error) {
	s.mu.Lock()
	conn := s.quic
	s.mu.Unlock()
	if conn != nil {
		select {
		case <-conn.Context().Done():
			s.dropQUIC(conn)
		default:
			return conn, nil
		}
	}
	tc := r.tlsConf.Clone()
	tc.NextProtos = []string{ALPNDoQ}
	tc.ServerName = s.host
	conn, err := quic.DialAddr(ctx, s.addr, tc, &quic.Config{
		HandshakeIdleTimeout: r.timeout,
		MaxIdleTimeout:       30 * time.Second,
		KeepAlivePeriod:      0,
		Allow0RTT:            false,
	})
	if err != nil {
		return nil, fmt.Errorf("doq dial %s: %w", s.addr, err)
	}
	s.mu.Lock()
	if s.quic != nil {
		// Another goroutine won the race; keep one connection.
		old := conn
		conn = s.quic
		s.mu.Unlock()
		_ = old.CloseWithError(doqNoError, "")
		return conn, nil
	}
	s.quic = conn
	s.mu.Unlock()
	return conn, nil
}

// dropQUIC forgets a connection that failed.
func (s *upstreamServer) dropQUIC(conn *quic.Conn) {
	s.mu.Lock()
	if s.quic == conn {
		s.quic = nil
	}
	s.mu.Unlock()
	if conn != nil {
		_ = conn.CloseWithError(doqUnspecified, "")
	}
}
