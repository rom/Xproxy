// Package unixsock binds a listening Unix domain socket the way a
// daemon has to: refusing to take over one that is still in use,
// clearing one left behind by a process that died, and never letting
// the socket exist in the file system with wider permissions than it
// will end up with.
//
// Two sockets in this proxy are authenticated by their permissions
// rather than by a credential on the wire — the management socket and
// the local cluster socket — so the order of those steps is the
// security property, and it is written once here rather than twice.
package unixsock

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"
)

// Listen binds path with the given permission mode.
//
// A path that answers a connection belongs to a process that is still
// running, and taking it would silently split a daemon in two, so it is
// an error. A path that does not answer is a socket left by a process
// that died and is removed, because refusing would mean a daemon never
// starts again after one unclean stop. Anything at the path that is not
// a socket is left alone and reported: removing it would be this
// process deleting a file on the strength of a typing mistake.
//
// The socket is created under a umask that permits nothing beyond the
// owner and then widened to mode, so there is no instant at which it is
// in the file system more open than it should be. A chmod after a
// default bind has exactly that instant, and on a socket whose
// permissions are its authentication that instant is the whole
// vulnerability.
func Listen(path string, mode os.FileMode) (net.Listener, error) {
	if path == "" {
		return nil, errors.New("unixsock: no path")
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		d := net.Dialer{Timeout: time.Second}
		if c, err := d.DialContext(context.Background(), "unix", path); err == nil {
			_ = c.Close()
			return nil, fmt.Errorf("%s is already in use", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("removing the stale socket %s: %w", path, err)
		}
	}
	old := umask(0o077)
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "unix", path)
	umask(old)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, mode); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("setting the mode of %s: %w", path, err)
	}
	// Remove the socket on Close, which is what an ordinary shutdown
	// wants and what makes the next start clean.
	if ul, ok := ln.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(true)
	}
	return ln, nil
}
