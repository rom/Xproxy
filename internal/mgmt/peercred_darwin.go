package mgmt

import "golang.org/x/sys/unix"

// peerCredentials reads LOCAL_PEERCRED (effective uid and the group list)
// and LOCAL_PEERPID of the peer.
func peerCredentials(fd int) PeerCred {
	x, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return PeerCred{}
	}
	c := PeerCred{UID: x.Uid, OK: true}
	if x.Ngroups > 0 {
		c.GID = x.Groups[0]
	}
	if pid, err := unix.GetsockoptInt(fd, unix.SOL_LOCAL, unix.LOCAL_PEERPID); err == nil {
		c.PID = int32(pid) //nolint:gosec // pid_t is 32 bits
	}
	return c
}
