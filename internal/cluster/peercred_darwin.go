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
// Unix socket. macOS answers the user and group but not the process id,
// which is reported as zero.
func peerCred(c net.Conn) (uid, gid, pid int, err error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, 0, 0, errors.New("not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, 0, 0, err
	}
	var cred *unix.Xucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return 0, 0, 0, err
	}
	if cerr != nil {
		return 0, 0, 0, cerr
	}
	gid = 0
	if cred.Ngroups > 0 {
		gid = int(cred.Groups[0])
	}
	return int(cred.Uid), gid, 0, nil
}
