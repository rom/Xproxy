//go:build !unix

package unixsock

// umask has no meaning where there is no umask; a Unix socket is not
// bound on such a platform either.
func umask(int) int { return 0 }
