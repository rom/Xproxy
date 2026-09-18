package mgmt

import "syscall"

func syscallUmask(mask int) int { return syscall.Umask(mask) }
