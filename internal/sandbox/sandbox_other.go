//go:build !linux

package sandbox

import "errors"

// Apply is a no-op on non-Linux platforms; only LevelOff is accepted.
func Apply(opts Options) error {
	if opts.Level != LevelOff {
		return errors.New("sandbox: Linux only; set Sandbox=off on this platform")
	}
	return nil
}
