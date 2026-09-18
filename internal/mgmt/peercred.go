package mgmt

import (
	"context"
	"net"
	"syscall"
)

// PeerCred identifies the process at the other end of a Unix socket, taken
// from the kernel (SO_PEERCRED) so it cannot be spoofed by the client.
type PeerCred struct {
	UID uint32
	GID uint32
	PID int32
	OK  bool
}

type peerKey struct{}

func peerFromContext(ctx context.Context) PeerCred {
	p, _ := ctx.Value(peerKey{}).(PeerCred)
	return p
}

// connContext is installed as http.Server.ConnContext and stores the
// credentials of every accepted connection.
func connContext(ctx context.Context, c net.Conn) context.Context {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return ctx
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return ctx
	}
	var cred PeerCred
	_ = raw.Control(func(fd uintptr) {
		u, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err == nil {
			cred = PeerCred{UID: u.Uid, GID: u.Gid, PID: u.Pid, OK: true}
		}
	})
	return context.WithValue(ctx, peerKey{}, cred)
}
