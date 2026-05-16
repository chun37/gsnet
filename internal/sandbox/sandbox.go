// Package sandbox drops privileges and restricts filesystem access after
// gsnetd finishes the operations that require root (creating WG/VXLAN
// interfaces, binding low ports, opening AF_PACKET sockets, etc.).
//
// Three levels, matching tinc's Sandbox option:
//
//	Off     no restrictions
//	Normal  setuid(non-root) + chdir(confDir); kernel-network ops still possible
//	        for an attacker with CAP_NET_ADMIN but everything else is reduced
//	High    Off plus Landlock filesystem restrictions (Linux 5.13+); read-only
//	        access to confDir only, no write/exec elsewhere
//
// Apply is idempotent within a process — calling it twice does nothing useful
// the second time.
package sandbox

// Level matches the config knob.
type Level int

const (
	LevelOff Level = iota
	LevelNormal
	LevelHigh
)

// ParseLevel parses a config value (off/normal/high, case-insensitive).
func ParseLevel(s string) (Level, error) {
	switch s {
	case "", "off":
		return LevelOff, nil
	case "normal":
		return LevelNormal, nil
	case "high":
		return LevelHigh, nil
	default:
		return LevelOff, errUnknownLevel(s)
	}
}

type errUnknownLevel string

func (e errUnknownLevel) Error() string {
	return "sandbox: unknown level " + string(e) + " (want off, normal, high)"
}

// Options carries Apply parameters in one place to avoid argument sprawl.
type Options struct {
	Level      Level
	User       string // unix user to setuid to; empty = no change
	ConfDir    string // chrooted/landlocked to read-only this path
	WritePaths []string // additional paths the daemon may write to (e.g. run dir for pidfile)
}
