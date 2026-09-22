//go:build !linux && !darwin

package cluster

import (
	"errors"
	"net"
)

// peerCredAvailable reports whether this platform can answer who is
// at the other end of a Unix socket.
const peerCredAvailable = false

// peerCred is unavailable here. A local cluster then rests on the
// socket's permissions alone, and refuses to start when allow_uids asks
// for a check this platform cannot make.
func peerCred(net.Conn) (uid, gid, pid int, err error) {
	return 0, 0, 0, errors.New("peer credentials are not available on this platform")
}
