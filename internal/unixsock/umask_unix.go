//go:build unix

package unixsock

import "syscall"

func umask(mask int) int { return syscall.Umask(mask) }
