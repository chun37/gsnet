package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/chun/gsnet/internal/config"
	"github.com/chun/gsnet/internal/keys"
	"github.com/chun/gsnet/internal/nodename"
	"github.com/chun/gsnet/internal/subnet"
)

// FsckLevel categorizes a finding's severity.
type FsckLevel int

const (
	FsckOK FsckLevel = iota
	FsckWarning
	FsckError
)

// FsckFinding is one diagnostic from fsck.
type FsckFinding struct {
	Level   FsckLevel
	Path    string // file path, if applicable
	Message string
}

func (f FsckFinding) String() string {
	tag := "OK"
	switch f.Level {
	case FsckWarning:
		tag = "WARNING"
	case FsckError:
		tag = "ERROR"
	}
	if f.Path != "" {
		return fmt.Sprintf("%s: %s: %s", tag, f.Path, f.Message)
	}
	return fmt.Sprintf("%s: %s", tag, f.Message)
}

// Fsck inspects a gsnet config tree and reports problems. It does not modify
// the filesystem; the caller decides which findings to act on.
//
// Checks:
//   - gsnet.conf exists and parses
//   - Name is present and valid
//   - Ed25519 private key file exists, parses, has 0600 perms
//   - WireGuard private key file exists, parses, has 0600 perms
//   - hosts/<Name> exists and contains the matching Ed25519/WG public keys
//   - all Subnet entries parse
//   - every ConnectTo target has a hosts/<target> file
//   - directory and file permissions
func Fsck(p Paths) []FsckFinding {
	var out []FsckFinding
	add := func(lvl FsckLevel, path, msg string) {
		out = append(out, FsckFinding{Level: lvl, Path: path, Message: msg})
	}

	confPath := p.ConfFile()
	st, err := os.Stat(confPath)
	if err != nil {
		add(FsckError, confPath, fmt.Sprintf("cannot stat: %v", err))
		return out
	}
	if st.IsDir() {
		add(FsckError, confPath, "expected file, found directory")
		return out
	}

	entries, err := config.LoadDirectory(confPath)
	if err != nil {
		add(FsckError, confPath, fmt.Sprintf("parse: %v", err))
		return out
	}

	name, ok := entries.GetFirst("Name")
	if !ok {
		add(FsckError, confPath, "Name is required")
	} else if err := nodename.Validate(name); err != nil {
		add(FsckError, confPath, fmt.Sprintf("Name invalid: %v", err))
	}

	// Subnet entries.
	for _, s := range entries.GetAll("Subnet") {
		if _, err := subnet.Parse(s); err != nil {
			add(FsckError, confPath, fmt.Sprintf("Subnet %q invalid: %v", s, err))
		}
	}

	// Key files.
	edPath := p.Ed25519Private()
	out = append(out, checkPrivateKey(edPath, "Ed25519", func(b []byte) error {
		_, err := keys.ParseEd25519PrivatePEM(b)
		return err
	})...)

	wgPath := p.WGPrivate()
	out = append(out, checkPrivateKey(wgPath, "WireGuard", func(b []byte) error {
		_, err := keys.ParseWireGuardPrivate(strings.TrimSpace(string(b)))
		return err
	})...)

	// hosts/<Name> consistency with private keys.
	if name != "" {
		hostPath := p.HostFile(name)
		hostBytes, err := os.ReadFile(hostPath)
		if err != nil {
			add(FsckError, hostPath, fmt.Sprintf("missing: %v", err))
		} else {
			hostEntries, err := config.Parse(strings.NewReader(string(hostBytes)))
			if err != nil {
				add(FsckError, hostPath, fmt.Sprintf("parse: %v", err))
			} else {
				out = append(out, checkHostMatchesPrivate(hostPath, hostEntries, edPath, wgPath)...)
			}
		}
	}

	// ConnectTo targets must have matching host files.
	hostsDir := p.HostsDir()
	for _, target := range entries.GetAll("ConnectTo") {
		if err := nodename.Validate(target); err != nil {
			add(FsckError, confPath, fmt.Sprintf("ConnectTo %q invalid name: %v", target, err))
			continue
		}
		hostPath := filepath.Join(hostsDir, target)
		if _, err := os.Stat(hostPath); err != nil {
			add(FsckError, hostPath, fmt.Sprintf("ConnectTo %q referenced but %s missing", target, hostPath))
		}
	}

	return out
}

func checkPrivateKey(path, label string, parse func([]byte) error) []FsckFinding {
	var out []FsckFinding
	st, err := os.Stat(path)
	if err != nil {
		out = append(out, FsckFinding{Level: FsckError, Path: path, Message: fmt.Sprintf("%s key missing: %v", label, err)})
		return out
	}
	if perm := st.Mode().Perm(); perm&0o077 != 0 {
		out = append(out, FsckFinding{Level: FsckWarning, Path: path, Message: fmt.Sprintf("%s key has loose permissions %o; expected 0600", label, perm)})
	}
	b, err := os.ReadFile(path)
	if err != nil {
		out = append(out, FsckFinding{Level: FsckError, Path: path, Message: fmt.Sprintf("%s key read: %v", label, err)})
		return out
	}
	if err := parse(b); err != nil {
		out = append(out, FsckFinding{Level: FsckError, Path: path, Message: fmt.Sprintf("%s key parse: %v", label, err)})
	}
	return out
}

func checkHostMatchesPrivate(hostPath string, hostEntries config.Entries, edPath, wgPath string) []FsckFinding {
	var out []FsckFinding

	edBytes, err := os.ReadFile(edPath)
	if err == nil {
		priv, err := keys.ParseEd25519PrivatePEM(edBytes)
		if err == nil {
			want := priv.Public().String()
			got, _ := hostEntries.GetFirst("Ed25519PublicKey")
			if strings.TrimSpace(got) != want {
				out = append(out, FsckFinding{Level: FsckError, Path: hostPath, Message: "Ed25519PublicKey does not match the local private key"})
			}
		}
	}

	wgBytes, err := os.ReadFile(wgPath)
	if err == nil {
		priv, err := keys.ParseWireGuardPrivate(strings.TrimSpace(string(wgBytes)))
		if err == nil {
			want := priv.Public().String()
			got, _ := hostEntries.GetFirst("WGPublicKey")
			if strings.TrimSpace(got) != want {
				out = append(out, FsckFinding{Level: FsckError, Path: hostPath, Message: "WGPublicKey does not match the local private key"})
			}
		}
	}

	return out
}
