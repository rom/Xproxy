package mgmt

import (
	"context"
	"net"
)

// PeerCred identifies the process at the other end of a Unix socket, taken
// from the kernel (SO_PEERCRED on Linux, LOCAL_PEERCRED on macOS) so it
// cannot be spoofed by the client.
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
	_ = raw.Control(func(fd uintptr) { cred = peerCredentials(int(fd)) })
	return context.WithValue(ctx, peerKey{}, cred)
}
