package proxy

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// activated holds sockets passed by systemd.
type activated struct {
	streams map[string]net.Listener
	packets map[string]net.PacketConn
}

// activatedListeners returns listeners passed by systemd socket activation
// (sd_listen_fds semantics), keyed by their LISTEN_FDNAMES name when given
// and by local address otherwise. Stream sockets become listeners and
// datagram sockets become packet connections (for HTTP/3). It returns an
// empty set when not socket activated.
//
// Socket activation is the preferred deployment: the service never needs
// CAP_NET_BIND_SERVICE or root, and systemd can restart the proxy without
// losing the listening socket.
func activatedListeners() (*activated, error) {
	out := &activated{streams: map[string]net.Listener{}, packets: map[string]net.PacketConn{}}
	pidStr := os.Getenv("LISTEN_PID")
	nStr := os.Getenv("LISTEN_FDS")
	if pidStr == "" || nStr == "" {
		return out, nil
	}
	defer func() {
		_ = os.Unsetenv("LISTEN_PID")
		_ = os.Unsetenv("LISTEN_FDS")
		_ = os.Unsetenv("LISTEN_FDNAMES")
	}()
	pid, err := strconv.Atoi(pidStr)
	if err != nil || pid != os.Getpid() {
		return out, nil
	}
	n, err := strconv.Atoi(nStr)
	if err != nil || n < 0 || n > 1024 {
		return nil, fmt.Errorf("bad LISTEN_FDS %q", nStr)
	}
	names := strings.Split(os.Getenv("LISTEN_FDNAMES"), ":")
	const firstFD = 3
	for i := 0; i < n; i++ {
		f := os.NewFile(uintptr(firstFD+i), "listen-fd-"+strconv.Itoa(i)) //nolint:gosec // fd numbers from systemd
		if f == nil {
			return nil, fmt.Errorf("fd %d is not open", firstFD+i)
		}
		key := ""
		if i < len(names) && names[i] != "" && names[i] != "unknown" {
			key = names[i]
		}
		if ln, err := net.FileListener(f); err == nil {
			if key == "" {
				key = ln.Addr().String()
			}
			out.streams[key] = ln
		} else if pc, err2 := net.FilePacketConn(f); err2 == nil {
			if key == "" {
				key = pc.LocalAddr().String()
			}
			out.packets[key] = pc
		} else {
			_ = f.Close()
			return nil, fmt.Errorf("fd %d: not a stream or datagram socket: %w", firstFD+i, err)
		}
		_ = f.Close() // the net package dups the descriptor
	}
	return out, nil
}

// packetFor returns an activated datagram socket named name+"-udp" or
// matching address, or binds a new UDP socket.
func packetFor(a *activated, name, address string) (net.PacketConn, bool, error) {
	if pc, ok := a.packets[name+"-udp"]; ok {
		delete(a.packets, name+"-udp")
		return pc, true, nil
	}
	for key, pc := range a.packets {
		if sameAddress(key, address) {
			delete(a.packets, key)
			return pc, true, nil
		}
	}
	lc := net.ListenConfig{}
	pc, err := lc.ListenPacket(context.Background(), "udp", address)
	if err != nil {
		return nil, false, err
	}
	return pc, false, nil
}

// listenerFor returns an activated listener matching name or address, or
// opens a new TCP listener.
func listenerFor(a *activated, name, address string) (net.Listener, bool, error) {
	if ln, ok := a.streams[name]; ok {
		delete(a.streams, name)
		return ln, true, nil
	}
	// Match by address: normalise ":443" to "[::]:443" as the kernel reports.
	for key, ln := range a.streams {
		if sameAddress(key, address) {
			delete(a.streams, key)
			return ln, true, nil
		}
	}
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", address)
	if err != nil {
		return nil, false, err
	}
	return ln, false, nil
}

func sameAddress(a, b string) bool {
	ah, ap, err1 := net.SplitHostPort(a)
	bh, bp, err2 := net.SplitHostPort(b)
	if err1 != nil || err2 != nil || ap != bp {
		return false
	}
	norm := func(h string) string {
		if h == "" || h == "::" || h == "0.0.0.0" {
			return "*"
		}
		return h
	}
	return norm(ah) == norm(bh)
}
