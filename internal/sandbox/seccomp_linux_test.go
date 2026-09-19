package sandbox

import (
	"testing"

	"golang.org/x/sys/unix"
)

// runBPF interprets the subset of classic BPF the filter uses against a
// synthetic seccomp_data with the given syscall number and architecture.
func runBPF(t *testing.T, prog []unix.SockFilter, nr, arch uint32) uint32 {
	t.Helper()
	var acc uint32
	for pc := 0; pc < len(prog); pc++ {
		in := prog[pc]
		switch in.Code {
		case bpfLD:
			switch in.K {
			case seccompDataNR:
				acc = nr
			case seccompDataArch:
				acc = arch
			default:
				t.Fatalf("load from offset %d", in.K)
			}
		case bpfJEQ:
			if acc == in.K {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case bpfJGE:
			if acc >= in.K {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case bpfRET:
			return in.K
		default:
			t.Fatalf("unexpected instruction %#x at %d", in.Code, pc)
		}
	}
	t.Fatal("program fell off the end")
	return 0
}

func TestSeccompProgram(t *testing.T) {
	if auditArch == 0 {
		t.Skip("no filter for this architecture")
	}
	nrs := denied()
	prog := program(auditArch, nrs, x32Check)
	if len(prog) > 4096 || len(prog) < 2*len(nrs)+5 {
		t.Fatalf("program length %d for %d syscalls", len(prog), len(nrs))
	}
	for i := 1; i < len(nrs); i++ {
		if nrs[i] <= nrs[i-1] {
			t.Fatalf("deny list not sorted and unique at %d: %v", i, nrs)
		}
	}
	errno := uint32(unix.SECCOMP_RET_ERRNO) | uint32(unix.EPERM)
	for _, n := range nrs {
		if got := runBPF(t, prog, uint32(n), auditArch); got != errno { //nolint:gosec // test data
			t.Errorf("syscall %d: got %#x want EPERM", n, got)
		}
	}
	allowed := []int{unix.SYS_READ, unix.SYS_WRITE, unix.SYS_MMAP, unix.SYS_MPROTECT, unix.SYS_MUNMAP, unix.SYS_CLONE,
		unix.SYS_FUTEX, unix.SYS_EPOLL_PWAIT, unix.SYS_OPENAT, unix.SYS_CLOSE, unix.SYS_SOCKET, unix.SYS_CONNECT,
		unix.SYS_ACCEPT4, unix.SYS_SENDMSG, unix.SYS_RECVMSG, unix.SYS_GETRANDOM, unix.SYS_NANOSLEEP, unix.SYS_MADVISE,
		unix.SYS_RT_SIGRETURN, unix.SYS_RT_SIGACTION, unix.SYS_SIGALTSTACK, unix.SYS_EXIT_GROUP, unix.SYS_PRCTL,
		unix.SYS_GETTID, unix.SYS_TGKILL, unix.SYS_FSTAT, unix.SYS_FCNTL, unix.SYS_IOCTL, unix.SYS_SETSOCKOPT,
		unix.SYS_LANDLOCK_RESTRICT_SELF, unix.SYS_SECCOMP, unix.SYS_CAPGET}
	for _, n := range allowed {
		if got := runBPF(t, prog, uint32(n), auditArch); got != unix.SECCOMP_RET_ALLOW { //nolint:gosec // test data
			t.Errorf("syscall %d: got %#x want ALLOW", n, got)
		}
	}
	// A foreign architecture is killed whatever the number.
	if got := runBPF(t, prog, unix.SYS_READ, auditArch^1); got != unix.SECCOMP_RET_KILL_PROCESS {
		t.Fatalf("foreign arch: got %#x", got)
	}
	if x32Check {
		if got := runBPF(t, prog, unix.SYS_READ|x32Bit, auditArch); got != unix.SECCOMP_RET_KILL_PROCESS {
			t.Fatalf("x32: got %#x", got)
		}
	}
	// Every denied number is in the list exactly once and the essential
	// ones are present.
	set := map[int]bool{}
	for _, n := range nrs {
		set[n] = true
	}
	for _, must := range []int{unix.SYS_PTRACE, unix.SYS_EXECVE, unix.SYS_MOUNT, unix.SYS_UNSHARE, unix.SYS_BPF, unix.SYS_SETUID, unix.SYS_INIT_MODULE} {
		if !set[must] {
			t.Errorf("syscall %d missing from the deny list", must)
		}
	}
	for _, never := range allowed {
		if set[never] {
			t.Errorf("syscall %d must not be denied", never)
		}
	}
}

func TestItoa(t *testing.T) {
	for n, want := range map[int]string{0: "0", 7: "7", 42: "42", 1000: "1000"} {
		if got := itoa(n); got != want {
			t.Errorf("%d: %s", n, got)
		}
	}
}
