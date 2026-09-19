package h3

import (
	"crypto/tls"
	"errors"
	"net/http"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// ClientTransport is an HTTP/3 client transport for upstream pools.
type ClientTransport struct {
	tr *http3.Transport
}

// ClientOptions tune the upstream transport.
type ClientOptions struct {
	// TLS is the client configuration (server name, roots, client
	// certificate); it is cloned and given the h3 ALPN.
	TLS *tls.Config
	// Handshake bounds the QUIC handshake; Idle closes an idle
	// connection; ResponseHeader bounds the wait for response headers.
	Handshake, Idle, ResponseHeader time.Duration
}

// NewClientTransport builds the transport. Connections are opened per
// authority on first use and reused; 0-RTT is never used.
func NewClientTransport(o ClientOptions) *ClientTransport {
	tc := o.TLS.Clone()
	tc.NextProtos = []string{http3.NextProtoH3}
	qc := &quic.Config{
		HandshakeIdleTimeout:  o.Handshake,
		MaxIdleTimeout:        o.Idle,
		MaxIncomingStreams:    -1,
		MaxIncomingUniStreams: 16,
		KeepAlivePeriod:       0,
	}
	return &ClientTransport{tr: &http3.Transport{
		TLSClientConfig:        tc,
		QUICConfig:             qc,
		DisableCompression:     true,
		MaxResponseHeaderBytes: 64 << 10,
	}}
}

// RoundTrip sends the request over HTTP/3.
func (c *ClientTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	ctx := r.Context()
	if c.tr.QUICConfig != nil && r.Header.Get("Te") != "" {
		r = r.Clone(ctx)
		r.Header.Del("Te") // hop by hop, not valid in HTTP/3
	}
	return c.tr.RoundTrip(r)
}

// CloseIdleConnections closes every idle QUIC connection.
func (c *ClientTransport) CloseIdleConnections() { c.tr.CloseIdleConnections() }

// Close closes all connections.
func (c *ClientTransport) Close() error { return c.tr.Close() }

// IsTransportError reports whether err came from the QUIC layer (no
// response was received), which a caller may retry over TCP.
func IsTransportError(err error) bool {
	if err == nil {
		return false
	}
	var qerr *quic.TransportError
	var aerr *quic.ApplicationError
	var ierr *quic.IdleTimeoutError
	var herr *quic.HandshakeTimeoutError
	var serr *quic.StatelessResetError
	return errorsAs(err, &qerr) || errorsAs(err, &aerr) || errorsAs(err, &ierr) || errorsAs(err, &herr) || errorsAs(err, &serr)
}

func errorsAs(err error, target any) bool { return errors.As(err, target) }
