package sandbox

import "golang.org/x/sys/unix"

const (
	auditArch = unix.AUDIT_ARCH_X86_64
	x32Check  = true
)

// deniedArchitecture: legacy and x86 only calls.
var deniedArchitecture = []int{
	unix.SYS_FORK, unix.SYS_VFORK, unix.SYS_IOPL, unix.SYS_IOPERM, unix.SYS_USELIB, unix.SYS_CREATE_MODULE,
	unix.SYS_GET_KERNEL_SYMS, unix.SYS_QUERY_MODULE, unix.SYS_MKNOD, unix.SYS_MODIFY_LDT, unix.SYS_SYSFS,
	unix.SYS_USTAT, unix.SYS__SYSCTL,
}
