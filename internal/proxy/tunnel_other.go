//go:build !linux

package proxy

// openTunnel is Linux only: the tun device CONNECT-IP forwards through
// has no portable equivalent, and a platform without one refuses the
// request with a reason rather than pretending.
func openTunnel(string, []string, []string) (tunnel, error) { return nil, errNoTunnel }
