package secret

import "syscall"

// syscallUmaskForTest sets the process umask and returns the previous
// one, so a test can prove a file's mode comes from the code rather
// than from the environment it happened to run in.
func syscallUmaskForTest(mask int) int { return syscall.Umask(mask) }
