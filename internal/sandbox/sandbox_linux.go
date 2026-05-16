//go:build linux

package sandbox

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// Apply applies the sandbox. On Linux:
//   - LevelNormal: chdir(ConfDir) and setuid(User)
//   - LevelHigh:   Normal plus Landlock filesystem confinement —
//                  read-only on ConfDir, read/write on WritePaths, deny all
//                  else. Requires Linux 5.13+; older kernels degrade to
//                  Normal with a warning returned via Warnings.
//
// Note that Landlock cannot govern netlink, AF_PACKET, or routing-table
// changes, so the reconciler must complete its kernel-network setup before
// Apply is called.
func Apply(opts Options) error {
	if opts.Level == LevelOff {
		return nil
	}
	// Landlock must come BEFORE setuid: it requires the process to be alive
	// to install rules, but it is enforced for the remainder of the process
	// lifetime regardless of uid.
	if opts.Level == LevelHigh {
		if err := applyLandlock(opts.ConfDir, opts.WritePaths); err != nil {
			return fmt.Errorf("landlock: %w", err)
		}
	}
	if opts.ConfDir != "" {
		if err := os.Chdir(opts.ConfDir); err != nil {
			return fmt.Errorf("chdir %s: %w", opts.ConfDir, err)
		}
	}
	if opts.User != "" {
		if err := setuidTo(opts.User); err != nil {
			return fmt.Errorf("setuid: %w", err)
		}
	}
	return nil
}

func setuidTo(name string) error {
	u, err := user.Lookup(name)
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return err
	}
	if err := syscall.Setgid(gid); err != nil {
		return err
	}
	return syscall.Setuid(uid)
}
