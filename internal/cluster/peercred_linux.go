package cluster

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// peerCredAvailable reports whether this platform can answer who is
// at the other end of a Unix socket.
const peerCredAvailable = true

// peerCred reads the user and group of the process at the other end of a
// Unix socket. The kernel fills these in at connect time from the
// peer's own credentials, so nothing the peer sends can change them:
// this is the one identity in the protocol that is not a claim.
func peerCred(c net.Conn) (uid, gid, pid int, err error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, 0, 0, errors.New("not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, 0, 0, err
	}
	var cred *unix.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, 0, 0, err
	}
	if cerr != nil {
		return 0, 0, 0, cerr
	}
	return int(cred.Uid), int(cred.Gid), int(cred.Pid), nil
}
