package proxy

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// activatedListeners returns listeners passed by systemd socket activation
// (sd_listen_fds semantics), keyed by their LISTEN_FDNAMES name when given
// and by local address otherwise. It returns nil when not socket activated.
//
// Socket activation is the preferred deployment: the service never needs
// CAP_NET_BIND_SERVICE or root, and systemd can restart the proxy without
// losing the listening socket.
func activatedListeners() (map[string]net.Listener, error) {
	pidStr := os.Getenv("LISTEN_PID")
	nStr := os.Getenv("LISTEN_FDS")
	if pidStr == "" || nStr == "" {
		return nil, nil
	}
	defer func() {
		_ = os.Unsetenv("LISTEN_PID")
		_ = os.Unsetenv("LISTEN_FDS")
		_ = os.Unsetenv("LISTEN_FDNAMES")
	}()
	pid, err := strconv.Atoi(pidStr)
	if err != nil || pid != os.Getpid() {
		return nil, nil
	}
	n, err := strconv.Atoi(nStr)
	if err != nil || n < 0 || n > 1024 {
		return nil, fmt.Errorf("bad LISTEN_FDS %q", nStr)
	}
	names := strings.Split(os.Getenv("LISTEN_FDNAMES"), ":")
	out := make(map[string]net.Listener, n)
	const firstFD = 3
	for i := 0; i < n; i++ {
		f := os.NewFile(uintptr(firstFD+i), "listen-fd-"+strconv.Itoa(i))
		if f == nil {
			return nil, fmt.Errorf("fd %d is not open", firstFD+i)
		}
		ln, err := net.FileListener(f)
		_ = f.Close() // net.FileListener dups the descriptor
		if err != nil {
			return nil, fmt.Errorf("fd %d: %w", firstFD+i, err)
		}
		key := ""
		if i < len(names) && names[i] != "" && names[i] != "unknown" {
			key = names[i]
		}
		if key == "" {
			key = ln.Addr().String()
		}
		out[key] = ln
	}
	return out, nil
}

// listenerFor returns an activated listener matching name or address, or
// opens a new TCP listener.
func listenerFor(activated map[string]net.Listener, name, address string) (net.Listener, bool, error) {
	if ln, ok := activated[name]; ok {
		delete(activated, name)
		return ln, true, nil
	}
	// Match by address: normalise ":443" to "[::]:443" as the kernel reports.
	for key, ln := range activated {
		if sameAddress(key, address) {
			delete(activated, key)
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
