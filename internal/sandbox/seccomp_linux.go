package sandbox

import (
	"sort"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/rom/xproxy/internal/config"
)

// deniedCommon are the system calls refused on every Linux architecture.
// The list is a deny list: everything the Go runtime, the network stack
// and the WebAssembly engine need stays allowed, and the calls below are
// those a compromised proxy could use to escalate, persist, observe other
// processes or change the machine. Each returns EPERM.
var deniedCommon = []int{
	// tracing and memory of other processes
	unix.SYS_PTRACE, unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV, unix.SYS_KCMP,
	unix.SYS_PIDFD_GETFD, unix.SYS_PERF_EVENT_OPEN, unix.SYS_USERFAULTFD, unix.SYS_PROCESS_MADVISE,
	// kernel, modules, boot
	unix.SYS_INIT_MODULE, unix.SYS_FINIT_MODULE, unix.SYS_DELETE_MODULE, unix.SYS_KEXEC_LOAD,
	unix.SYS_KEXEC_FILE_LOAD, unix.SYS_REBOOT, unix.SYS_BPF, unix.SYS_ACCT, unix.SYS_SYSLOG,
	unix.SYS_VHANGUP, unix.SYS_SETHOSTNAME, unix.SYS_SETDOMAINNAME,
	// mounts and namespaces
	unix.SYS_MOUNT, unix.SYS_UMOUNT2, unix.SYS_PIVOT_ROOT, unix.SYS_CHROOT, unix.SYS_SWAPON,
	unix.SYS_SWAPOFF, unix.SYS_UNSHARE, unix.SYS_SETNS, unix.SYS_OPEN_TREE, unix.SYS_MOVE_MOUNT,
	unix.SYS_FSOPEN, unix.SYS_FSCONFIG, unix.SYS_FSMOUNT, unix.SYS_FSPICK, unix.SYS_MOUNT_SETATTR,
	unix.SYS_OPEN_BY_HANDLE_AT, unix.SYS_NAME_TO_HANDLE_AT, unix.SYS_QUOTACTL, unix.SYS_FANOTIFY_INIT,
	unix.SYS_FANOTIFY_MARK, unix.SYS_LOOKUP_DCOOKIE, unix.SYS_NFSSERVCTL,
	// clock and time
	unix.SYS_SETTIMEOFDAY, unix.SYS_CLOCK_SETTIME, unix.SYS_CLOCK_ADJTIME, unix.SYS_ADJTIMEX,
	// keyrings, io_uring, memory policy
	unix.SYS_ADD_KEY, unix.SYS_REQUEST_KEY, unix.SYS_KEYCTL, unix.SYS_IO_URING_SETUP,
	unix.SYS_IO_URING_ENTER, unix.SYS_IO_URING_REGISTER, unix.SYS_MBIND, unix.SYS_MIGRATE_PAGES,
	unix.SYS_MOVE_PAGES, unix.SYS_SET_MEMPOLICY, unix.SYS_GET_MEMPOLICY, unix.SYS_MEMFD_SECRET,
	// identity: never changes after start
	unix.SYS_SETUID, unix.SYS_SETGID, unix.SYS_SETREUID, unix.SYS_SETREGID, unix.SYS_SETRESUID,
	unix.SYS_SETRESGID, unix.SYS_SETGROUPS, unix.SYS_SETFSUID, unix.SYS_SETFSGID, unix.SYS_CAPSET,
	// new programs and processes: xproxy never executes anything
	unix.SYS_EXECVE, unix.SYS_EXECVEAT, unix.SYS_CLONE3, unix.SYS_PERSONALITY, unix.SYS_MKNODAT,
}

// deniedErrno overrides the errno a particular call is refused with.
//
// clone3 has to be ENOSYS rather than EPERM, and it is not a nicety. glibc's
// pthread_create calls clone3 first and falls back to plain clone -- which this
// filter allows -- only on ENOSYS. Refused with EPERM it does not fall back: it
// fails, and a process linked against glibc cannot create a thread at all. The
// Go runtime calls clone directly, so a CGO_ENABLED=0 build never noticed; a
// cgo-linked one aborts with "runtime/cgo: pthread_create failed: Operation not
// permitted" the moment anything wants an OS thread after the sandbox is on,
// which is how this was found -- the race-enabled test binary is a cgo binary.
//
// Nothing is given away by the change. clone is allowed either way, so refusing
// clone3 was never what stopped a new process; execve and execveat are, and they
// stay EPERM.
var deniedErrno = map[int]uintptr{
	unix.SYS_CLONE3: uintptr(unix.ENOSYS),
}

// errnoFor is the errno a refused call returns.
func errnoFor(nr int) uintptr {
	if e, ok := deniedErrno[nr]; ok {
		return e
	}
	return uintptr(unix.EPERM)
}

// deniedArchitecture lists calls that exist on this architecture only
// (set in the per architecture files); auditArch is the seccomp
// architecture token, 0 when the filter is not built for this
// architecture.

// denied returns the sorted, de-duplicated deny list.
func denied() []int {
	seen := map[int]bool{}
	var out []int
	for _, n := range append(append([]int(nil), deniedCommon...), deniedArchitecture...) {
		if n >= 0 && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Ints(out)
	return out
}

// BPF helpers.
const (
	bpfLD  = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS
	bpfJEQ = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
	bpfJGE = unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K
	bpfRET = unix.BPF_RET | unix.BPF_K

	seccompDataNR   = 0
	seccompDataArch = 4
	// x32 system calls carry this bit on x86_64.
	x32Bit = 0x40000000
)

func stmt(code uint16, k uint32) unix.SockFilter { return unix.SockFilter{Code: code, K: k} }
func jump(code uint16, k uint32, jt, jf uint8) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
}

// program builds the filter: kill on a foreign architecture (and on the
// x32 ABI where it exists), an errno for every denied number -- EPERM unless
// deniedErrno says otherwise -- and allow the rest.
func program(arch uint32, nrs []int, x32 bool) []unix.SockFilter {
	p := []unix.SockFilter{
		stmt(bpfLD, seccompDataArch),
		jump(bpfJEQ, arch, 1, 0),
		stmt(bpfRET, unix.SECCOMP_RET_KILL_PROCESS),
		stmt(bpfLD, seccompDataNR),
	}
	if x32 {
		p = append(p, jump(bpfJGE, x32Bit, 0, 1), stmt(bpfRET, unix.SECCOMP_RET_KILL_PROCESS))
	}
	for _, n := range nrs {
		p = append(p, jump(bpfJEQ, uint32(n), 0, 1), stmt(bpfRET, unix.SECCOMP_RET_ERRNO|uint32(errnoFor(n)))) //nolint:gosec // syscall numbers and errnos are small
	}
	return append(p, stmt(bpfRET, unix.SECCOMP_RET_ALLOW))
}

// seccomp installs the filter for every thread of the process.
func seccomp(sb *config.Sandbox, st *Status) Mechanism {
	m := Mechanism{Name: "seccomp"}
	if sb.Seccomp.Enabled != nil && !*sb.Seccomp.Enabled {
		m.State = StateDisabled
		return m
	}
	if auditArch == 0 {
		m.State, m.Detail = StateUnavailable, "no filter for this architecture"
		return m
	}
	nrs := denied()
	prog := program(auditArch, nrs, x32Check)
	if len(prog) > 4096 {
		m.State, m.Detail = StateFailed, "filter too long"
		return m
	}
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}                                                                        //nolint:gosec // bounded above
	_, _, e := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&fprog))) //nolint:gosec // raw syscall on a stack struct
	if e != 0 {
		if e == unix.ENOSYS || e == unix.EINVAL {
			m.State, m.Detail = StateUnavailable, errnoDetail("seccomp", e)
			return m
		}
		m.State, m.Detail = StateFailed, errnoDetail("seccomp", e)
		return m
	}
	st.Denied = len(nrs)
	m.State = StateApplied
	m.Detail = "filter installed on every thread, " + itoa(len(nrs)) + " system calls refused"
	return m
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
