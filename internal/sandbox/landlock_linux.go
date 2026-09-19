package sandbox

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/rom/xproxy/internal/config"
)

// Landlock access rights by the ABI version that introduced them.
const (
	fsABI1 = unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_READ_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR | unix.LANDLOCK_ACCESS_FS_MAKE_DIR | unix.LANDLOCK_ACCESS_FS_MAKE_REG |
		unix.LANDLOCK_ACCESS_FS_MAKE_SOCK | unix.LANDLOCK_ACCESS_FS_MAKE_FIFO | unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM
	fsABI2 = unix.LANDLOCK_ACCESS_FS_REFER
	fsABI3 = unix.LANDLOCK_ACCESS_FS_TRUNCATE
	fsABI5 = unix.LANDLOCK_ACCESS_FS_IOCTL_DEV

	readAccess  = unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR
	writeAccess = readAccess | unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_MAKE_REG |
		unix.LANDLOCK_ACCESS_FS_REMOVE_FILE | unix.LANDLOCK_ACCESS_FS_MAKE_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
		unix.LANDLOCK_ACCESS_FS_MAKE_SOCK | unix.LANDLOCK_ACCESS_FS_REFER | unix.LANDLOCK_ACCESS_FS_TRUNCATE

	// fileAccess are the rights that may appear in a rule on a regular
	// file or device; a directory rule may carry every right.
	fileAccess = unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
		unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_TRUNCATE | unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
)

// landlockABI asks the kernel for its Landlock ABI version; 0 when the
// syscall is missing or the LSM is not enabled.
func landlockABI() int {
	r, _, e := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if e != 0 {
		return 0
	}
	return int(r) //nolint:gosec // small positive integer
}

// handledFS returns the file system rights the running kernel knows.
func handledFS(abi int) uint64 {
	h := uint64(fsABI1)
	if abi >= 2 {
		h |= fsABI2
	}
	if abi >= 3 {
		h |= fsABI3
	}
	if abi >= 5 {
		h |= fsABI5
	}
	return h
}

// landlock installs the file system rules and, when configured and
// supported, refuses further TCP binds.
func landlock(sb *config.Sandbox, rules Rules, st *Status, nnp bool, log *slog.Logger) Mechanism {
	m := Mechanism{Name: "landlock"}
	if sb.Landlock.Enabled != nil && !*sb.Landlock.Enabled {
		m.State = StateDisabled
		return m
	}
	abi := landlockABI()
	st.LandlockABI = abi
	if abi == 0 {
		m.State, m.Detail = StateUnavailable, "kernel without Landlock (needs 5.13 or newer with the LSM enabled)"
		return m
	}
	if !nnp {
		m.State, m.Detail = StateFailed, "no_new_privs could not be set"
		return m
	}
	handled := handledFS(abi)
	attr := unix.LandlockRulesetAttr{Access_fs: handled}
	bind := abi >= 4 && (sb.Landlock.Bind == nil || *sb.Landlock.Bind)
	if bind {
		attr.Access_net = unix.LANDLOCK_ACCESS_NET_BIND_TCP
	}
	fd, _, e := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0) //nolint:gosec // raw syscall on a stack struct
	if e != 0 {
		m.State, m.Detail = StateFailed, errnoDetail("landlock_create_ruleset", e)
		return m
	}
	rs := int(fd) //nolint:gosec // file descriptor
	defer func() { _ = unix.Close(rs) }()

	var read, write, missing []string
	add := func(p string, access uint64) error {
		pfd, err := unix.Open(p, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) {
				missing = append(missing, p) // configured but absent: nothing to admit
				return nil
			}
			return fmt.Errorf("%s: %w", p, err)
		}
		defer func() { _ = unix.Close(pfd) }()
		var fst unix.Stat_t
		if err := unix.Fstat(pfd, &fst); err == nil && fst.Mode&unix.S_IFMT != unix.S_IFDIR {
			access &= fileAccess
		}
		pa := unix.LandlockPathBeneathAttr{Allowed_access: access & handled, Parent_fd: int32(pfd)}                                               //nolint:gosec // file descriptor
		_, _, e := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, uintptr(rs), unix.LANDLOCK_RULE_PATH_BENEATH, uintptr(unsafe.Pointer(&pa)), 0, 0, 0) //nolint:gosec // raw syscall on a stack struct
		if e != 0 {
			return fmt.Errorf("%s: landlock_add_rule: %w", p, e)
		}
		return nil
	}
	for _, p := range rules.Read {
		if err := add(p, readAccess); err != nil {
			m.State, m.Detail = StateFailed, err.Error()
			return m
		}
		if _, err := os.Lstat(p); err == nil {
			read = append(read, p)
		}
	}
	for _, p := range rules.Write {
		if err := add(p, writeAccess); err != nil {
			m.State, m.Detail = StateFailed, err.Error()
			return m
		}
		if _, err := os.Lstat(p); err == nil {
			write = append(write, p)
		}
	}
	if _, _, e := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(rs), 0, 0); e != 0 {
		m.State, m.Detail = StateFailed, errnoDetail("landlock_restrict_self", e)
		return m
	}
	// Check works on the derived rule list, present or not, so that a
	// reload naming a not yet created file under an admitted directory
	// passes while one outside is refused.
	st.ReadPaths, st.WritePaths, st.Landlocked = rules.Read, rules.Write, true
	st.MissingPaths = missing
	for _, p := range missing {
		if !isSystemPath(p) {
			log.Warn("sandbox: configured path does not exist; it is not admitted by the Landlock rules", "path", p)
		}
	}
	m.State = StateApplied
	m.Detail = fmt.Sprintf("ABI %d, %d read and %d write rules present", abi, len(read), len(write))
	if bind {
		m.Detail += ", TCP bind refused"
	} else if abi >= 4 {
		m.Detail += ", TCP bind allowed"
	}
	return m
}
