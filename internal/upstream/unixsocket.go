package upstream

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// A Unix domain socket endpoint, for the services that live beside the
// proxy rather than across a network: an application server on the same
// host, a local scanner, a sidecar. A socket is the better way to reach
// one -- there is no port for anything else on the machine to connect
// to, file permissions decide who may, and nothing is routable.
//
// Two things have to be kept apart to make one work behind an HTTP
// client, and conflating them is the whole difficulty:
//
//   - What is dialled: a path, with the "unix" network.
//   - What goes in the URL: a host, because that is what a URL has, and
//     what net/http keys its idle connection pool by.
//
// So an endpoint keeps the configured spelling for logs and status, a
// path to dial, and a synthetic authority for the URL. The authority is
// derived from the path and ends in .invalid (RFC 6761), a name that
// must never resolve -- if a dialler ever ignored the socket and
// resolved it instead, the failure is immediate and obvious rather than
// a connection to somebody else's machine.

// unixPrefix marks an endpoint address as a socket path. It is the same
// spelling a listener address uses.
const unixPrefix = "unix:"

// SocketPath returns the socket path of an endpoint address and whether
// it is one.
func SocketPath(address string) (string, bool) {
	p, ok := strings.CutPrefix(address, unixPrefix)
	if !ok || p == "" {
		return "", false
	}
	return p, true
}

// urlAuthority is the host a socket endpoint wears in a URL: stable for
// a given path, unique between paths, and unresolvable.
func urlAuthority(path string) string {
	sum := sha256.Sum256([]byte(path))
	return hex.EncodeToString(sum[:8]) + ".socket.invalid:80"
}

// Socket is the path this endpoint dials, empty for a network endpoint.
func (e *Endpoint) Socket() string { return e.socket }

// URLHost is the authority to put in a URL for this endpoint: the
// address itself for a network endpoint, a synthetic authority for a
// socket.
func (e *Endpoint) URLHost() string {
	if e.socket != "" {
		return e.urlHost
	}
	return e.Address
}

// Dial says what to dial this endpoint with: the network and the
// address, as a net.Dialer wants them.
func (e *Endpoint) Dial() (network, address string) {
	if e.socket != "" {
		return "unix", e.socket
	}
	return "tcp", e.Address
}
