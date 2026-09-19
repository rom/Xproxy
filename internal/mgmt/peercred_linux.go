package mgmt

import "golang.org/x/sys/unix"

// peerCredentials reads SO_PEERCRED: uid, gid and pid of the peer at
// connect time.
func peerCredentials(fd int) PeerCred {
	u, err := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil {
		return PeerCred{}
	}
	return PeerCred{UID: u.Uid, GID: u.Gid, PID: u.Pid, OK: true}
}
