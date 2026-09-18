package admin

import (
	"crypto/sha256"
	"syscall"
)

func sha256sum(b []byte) [32]byte { return sha256.Sum256(b) }

func umask(m int) int { return syscall.Umask(m) }
