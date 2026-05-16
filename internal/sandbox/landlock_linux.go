//go:build linux

package sandbox

// Landlock confinement.
//
// We invoke the three landlock syscalls directly because x/sys/unix at the
// version we depend on exposes the structs and constants but not Go-level
// wrappers. The ABI is stable since Linux 5.13.

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// abiVersion probes the kernel for the highest supported Landlock ABI by
// passing size=0 to landlock_create_ruleset. Returns 0 if Landlock is
// unavailable.
func abiVersion() int {
	const LANDLOCK_CREATE_RULESET_VERSION = 0x1
	r, _, errno := syscall.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, uintptr(LANDLOCK_CREATE_RULESET_VERSION))
	if errno != 0 {
		return 0
	}
	return int(r)
}

// applyLandlock builds and applies a Landlock ruleset that allows:
//   - read on confDir (recursive)
//   - read+write on writePaths (recursive)
// All other filesystem access is denied for the calling process and its
// children. Returns an error on kernels < 5.13.
func applyLandlock(confDir string, writePaths []string) error {
	abi := abiVersion()
	if abi == 0 {
		return errors.New("Landlock not available (need Linux 5.13+)")
	}

	// Pick the access mask supported by this ABI. Bits added in later ABI
	// versions are filtered out (kernel rejects unknown bits otherwise).
	access := uint64(
		unix.LANDLOCK_ACCESS_FS_EXECUTE |
			unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
			unix.LANDLOCK_ACCESS_FS_READ_FILE |
			unix.LANDLOCK_ACCESS_FS_READ_DIR |
			unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
			unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
			unix.LANDLOCK_ACCESS_FS_MAKE_CHAR |
			unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
			unix.LANDLOCK_ACCESS_FS_MAKE_REG |
			unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
			unix.LANDLOCK_ACCESS_FS_MAKE_FIFO |
			unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
			unix.LANDLOCK_ACCESS_FS_MAKE_SYM,
	)
	if abi >= 2 {
		access |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		access |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}

	attr := unix.LandlockRulesetAttr{Access_fs: access}
	rulesetFD, _, errno := syscall.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if errno != 0 {
		return fmt.Errorf("landlock_create_ruleset: %w", errno)
	}
	defer syscall.Close(int(rulesetFD))

	readAccess := uint64(unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR)
	writeAccess := readAccess |
		unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_REG |
		unix.LANDLOCK_ACCESS_FS_REMOVE_FILE
	if abi >= 3 {
		writeAccess |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}

	addRule := func(path string, mask uint64) error {
		fd, err := syscall.Open(path, unix.O_PATH|syscall.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("open %s: %w", path, err)
		}
		defer syscall.Close(fd)
		pathAttr := unix.LandlockPathBeneathAttr{
			Allowed_access: mask,
			Parent_fd:      int32(fd),
		}
		_, _, errno := syscall.Syscall6(unix.SYS_LANDLOCK_ADD_RULE,
			rulesetFD, uintptr(unix.LANDLOCK_RULE_PATH_BENEATH),
			uintptr(unsafe.Pointer(&pathAttr)), 0, 0, 0)
		if errno != 0 {
			return fmt.Errorf("landlock_add_rule(%s): %w", path, errno)
		}
		return nil
	}

	if confDir != "" {
		if err := addRule(confDir, readAccess); err != nil {
			return err
		}
	}
	for _, p := range writePaths {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			// Allowing a non-existent path doesn't make sense; skip silently.
			continue
		}
		if err := addRule(p, writeAccess); err != nil {
			return err
		}
	}

	// Required precondition for landlock_restrict_self() from an
	// unprivileged process (or after a setuid).
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl(NO_NEW_PRIVS): %w", err)
	}
	_, _, errno = syscall.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, rulesetFD, 0, 0)
	if errno != 0 {
		return fmt.Errorf("landlock_restrict_self: %w", errno)
	}
	return nil
}
