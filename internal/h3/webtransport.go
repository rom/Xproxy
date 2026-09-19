package h3

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
)

// DialWebTransport opens a WebTransport session to address (host:port)
// for url (whose host is the authority sent to the upstream) with the
// request headers hdr. tc is the client TLS configuration (server name,
// roots, client certificate).
func DialWebTransport(ctx context.Context, tc *tls.Config, address, url string, hdr http.Header, handshake time.Duration) (*http.Response, *webtransport.Session, error) {
	tlsCfg := tc.Clone()
	tlsCfg.NextProtos = []string{http3.NextProtoH3}
	d := &webtransport.Transport{
		TLSClientConfig: tlsCfg,
		QUICConfig: &quic.Config{
			HandshakeIdleTimeout:             handshake,
			EnableDatagrams:                  true,
			EnableStreamResetPartialDelivery: true,
			MaxIncomingStreams:               1024,
			MaxIncomingUniStreams:            1024,
		},
		DialAddr: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			return quic.DialAddr(ctx, address, tlsCfg, cfg)
		},
	}
	return d.Dial(ctx, url, hdr)
}

// RelayStats counts what a relay moved.
type RelayStats struct {
	Streams, UniStreams, Datagrams atomic.Uint64
}

// RelayWebTransport copies streams and datagrams between two sessions
// in both directions until one of them ends; the other is then closed
// with the same code. It returns when both are done.
func RelayWebTransport(ctx context.Context, client, upstream *webtransport.Session, st *RelayStats) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	pair := func(from, to *webtransport.Session) {
		wg.Add(3)
		go func() { defer wg.Done(); relayStreams(ctx, from, to, st) }()
		go func() { defer wg.Done(); relayUniStreams(ctx, from, to, st) }()
		go func() { defer wg.Done(); relayDatagrams(ctx, from, to, st) }()
	}
	pair(client, upstream)
	pair(upstream, client)
	// The first session to end takes the other with it.
	select {
	case <-client.Context().Done():
		_ = upstream.CloseWithError(sessionCode(client.Context().Err()), "")
	case <-upstream.Context().Done():
		_ = client.CloseWithError(sessionCode(upstream.Context().Err()), "")
	case <-ctx.Done():
		_ = client.CloseWithError(0, "")
		_ = upstream.CloseWithError(0, "")
	}
	cancel()
	wg.Wait()
}

func sessionCode(err error) webtransport.SessionErrorCode {
	var se *webtransport.SessionError
	if errors.As(err, &se) {
		return se.ErrorCode
	}
	return 0
}

func relayStreams(ctx context.Context, from, to *webtransport.Session, st *RelayStats) {
	for {
		in, err := from.AcceptStream(ctx)
		if err != nil {
			return
		}
		out, err := to.OpenStreamSync(ctx)
		if err != nil {
			in.CancelRead(1)
			in.CancelWrite(1)
			return
		}
		st.Streams.Add(1)
		go pipeStream(in, out)
	}
}

// pipeStream copies a bidirectional stream both ways; a close or reset
// on one side is mirrored on the other.
func pipeStream(a, b *webtransport.Stream) {
	var wg sync.WaitGroup
	wg.Add(2)
	copyDir := func(dst, src *webtransport.Stream) {
		defer wg.Done()
		_, err := io.Copy(dst, src)
		var se *webtransport.StreamError
		switch {
		case err == nil:
			_ = dst.Close()
		case errors.As(err, &se):
			dst.CancelWrite(se.ErrorCode)
			src.CancelRead(se.ErrorCode)
		default:
			dst.CancelWrite(0)
		}
	}
	go copyDir(b, a)
	go copyDir(a, b)
	wg.Wait()
}

func relayUniStreams(ctx context.Context, from, to *webtransport.Session, st *RelayStats) {
	for {
		in, err := from.AcceptUniStream(ctx)
		if err != nil {
			return
		}
		out, err := to.OpenUniStreamSync(ctx)
		if err != nil {
			in.CancelRead(1)
			return
		}
		st.UniStreams.Add(1)
		go func() {
			_, err := io.Copy(out, in)
			var se *webtransport.StreamError
			switch {
			case err == nil:
				_ = out.Close()
			case errors.As(err, &se):
				out.CancelWrite(se.ErrorCode)
			default:
				out.CancelWrite(0)
			}
		}()
	}
}

func relayDatagrams(ctx context.Context, from, to *webtransport.Session, st *RelayStats) {
	for {
		b, err := from.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		if to.SendDatagram(b) == nil {
			st.Datagrams.Add(1)
		}
	}
}
