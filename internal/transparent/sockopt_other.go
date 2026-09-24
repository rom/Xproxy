//go:build !linux

package transparent

import (
	"net"
	"net/netip"
)

// This platform has neither IP_TRANSPARENT nor SO_ORIGINAL_DST. The
// package still builds so that configuration validation can refuse the
// settings with a reason rather than the whole daemon failing to
// compile.

func originalDST(net.Conn) (netip.AddrPort, error) { return netip.AddrPort{}, ErrNoOriginalDestination }

// Dialer returns the base dialler unchanged: without IP_TRANSPARENT
// there is no way to dial as somebody else, and pretending otherwise
// would produce a connection from the proxy's own address that the
// operator believed came from the client.
func Dialer(base *net.Dialer, _ netip.Addr) *net.Dialer { return base }

// Available reports that this build cannot do it.
func Available() bool { return false }

// Check refuses, with the reason.
func Check() error { return ErrUnsupported }
