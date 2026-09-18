package dns

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"time"
)

// Resolver forwards queries to upstream servers. Every query goes out
// with a fresh transaction id on a fresh socket (random source port),
// and the answer must echo the id and the question.
type Resolver struct {
	servers []string
	timeout time.Duration
	next    atomic.Uint32
	dialer  net.Dialer
	// Failures counts upstream attempts that did not answer.
	Failures atomic.Uint64
}

// NewResolver takes host:port servers and a per attempt timeout.
func NewResolver(servers []string, timeout time.Duration) *Resolver {
	return &Resolver{servers: servers, timeout: timeout, dialer: net.Dialer{Timeout: timeout}}
}

// Exchange sends query and returns the response with the client's id
// restored. tcp forces TCP (a client that asked over TCP, or a retry
// after truncation); over UDP a truncated answer is retried over TCP.
func (r *Resolver) Exchange(ctx context.Context, query []byte, qEnd int, q Question, tcp bool) ([]byte, error) {
	if len(r.servers) == 0 {
		return nil, errNoUpstream
	}
	var idb [2]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return nil, err
	}
	id := binary.BigEndian.Uint16(idb[:])
	clientID := binary.BigEndian.Uint16(query)
	out := make([]byte, len(query))
	copy(out, query)
	SetID(out, id)
	start := int(r.next.Add(1) - 1)
	lastErr := errNoUpstream
	for i := 0; i < len(r.servers); i++ {
		server := r.servers[(start+i)%len(r.servers)]
		actx, cancel := context.WithTimeout(ctx, r.timeout)
		var resp []byte
		var err error
		if tcp {
			resp, err = r.exchangeTCP(actx, server, out)
		} else {
			resp, err = r.exchangeUDP(actx, server, out)
			if err == nil {
				if h, herr := ParseHeader(resp); herr == nil && h.Truncated() {
					resp, err = r.exchangeTCP(actx, server, out)
				}
			}
		}
		cancel()
		if err != nil {
			r.Failures.Add(1)
			lastErr = err
			if ctx.Err() != nil {
				break
			}
			continue
		}
		if !r.matches(resp, id, q) {
			r.Failures.Add(1)
			lastErr = errors.New("dns: answer does not match the question")
			continue
		}
		SetID(resp, clientID)
		return resp, nil
	}
	return nil, lastErr
}

func (r *Resolver) matches(resp []byte, id uint16, q Question) bool {
	h, err := ParseHeader(resp)
	if err != nil || h.ID != id || !h.Response() || h.QDCount != 1 {
		return false
	}
	rq, _, err := ParseQuestion(resp)
	return err == nil && rq == q
}

func (r *Resolver) exchangeUDP(ctx context.Context, server string, query []byte) ([]byte, error) {
	c, err := r.dialer.DialContext(ctx, "udp", server)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if _, err := c.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		if n >= headerLen && binary.BigEndian.Uint16(buf) == binary.BigEndian.Uint16(query) {
			return append([]byte(nil), buf[:n]...), nil
		}
		// A stray datagram for another id: keep waiting for ours.
	}
}

func (r *Resolver) exchangeTCP(ctx context.Context, server string, query []byte) ([]byte, error) {
	c, err := r.dialer.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if err := WriteTCP(c, query); err != nil {
		return nil, err
	}
	return ReadTCP(c, MaxMessage)
}

// WriteTCP writes a length prefixed message.
func WriteTCP(w io.Writer, msg []byte) error {
	if len(msg) > MaxMessage {
		return errors.New("dns: message too large")
	}
	buf := make([]byte, 2, 2+len(msg))
	binary.BigEndian.PutUint16(buf, uint16(len(msg))) //nolint:gosec // bounded above
	_, err := w.Write(append(buf, msg...))
	return err
}

// ReadTCP reads one length prefixed message of at most limit bytes.
func ReadTCP(rd io.Reader, limit int) ([]byte, error) {
	var lb [2]byte
	if _, err := io.ReadFull(rd, lb[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(lb[:]))
	if n < headerLen || n > limit {
		return nil, errors.New("dns: bad message length")
	}
	msg := make([]byte, n)
	if _, err := io.ReadFull(rd, msg); err != nil {
		return nil, err
	}
	return msg, nil
}
