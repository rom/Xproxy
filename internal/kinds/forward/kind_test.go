package forward

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"testing"

	"github.com/rom/xproxy/internal/proxy"
)

// A forward listener is stopped by closing its front and then shutting
// the HTTP server down, so Serve ends with net.ErrClosed from the
// accept or with http.ErrServerClosed from the shutdown, depending on
// which goroutine wins. Neither is a failure. The engine's own serve()
// carried both guards before the forward proxy became a kind of its
// own, and the move kept only one: every clean stop and every reload of
// a forward listener then logged at ERROR, which is how an operator
// learns to ignore the error log.
func TestServeErrorIgnoresBothWaysAListenerEnds(t *testing.T) {
	closed := &net.OpError{Op: "accept", Net: "tcp", Err: net.ErrClosed}
	for _, tc := range []struct {
		name string
		err  error
		want bool // want a log line
	}{
		{"a clean shutdown", http.ErrServerClosed, false},
		{"the front closed under the server", closed, false},
		{"either one wrapped", fmt.Errorf("serve: %w", closed), false},
		{"nothing went wrong", nil, false},
		{"a real failure", errors.New("too many open files"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := serveError(tc.err) != nil; got != tc.want {
				t.Errorf("serveError(%v) logs = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// A forward listener relays CONNECT and SOCKS tunnels, which are
// counted by forward_tunnels_open. It must not also implement
// proxy.FlowCounter: the engine folds that into quic_flows_open, which
// before the carve counted only a tcp listener's QUIC flows, so a
// CONNECT tunnel would be reported as an open QUIC flow and counted
// twice over.
func TestForwardIsNotAFlowCounter(t *testing.T) {
	var i any = &instance{}
	if _, ok := i.(proxy.FlowCounter); ok {
		t.Error("the forward instance implements proxy.FlowCounter: its tunnels would land in quic_flows_open")
	}
}
