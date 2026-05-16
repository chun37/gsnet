// Package script runs gsnet hook scripts (gsnet-up, gsnet-down,
// hosts/<NAME>-up, etc.) with a fixed environment-variable contract that
// scripts can rely on.
package script

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Env is the set of environment variables passed to hook scripts.
// Empty values are not passed.
type Env struct {
	Netname       string
	Name          string
	Device        string
	Interface     string
	Node          string
	RemoteAddress string
	RemotePort    string
	Subnet        string
	Weight        string
	InvitationFile string
	InvitationURL  string
}

// ToOSEnv returns the process environment merged with the gsnet hook variables.
func (e Env) ToOSEnv() []string {
	out := os.Environ()
	add := func(k, v string) {
		if v != "" {
			out = append(out, k+"="+v)
		}
	}
	add("NETNAME", e.Netname)
	add("NAME", e.Name)
	add("DEVICE", e.Device)
	add("INTERFACE", e.Interface)
	add("NODE", e.Node)
	add("REMOTEADDRESS", e.RemoteAddress)
	add("REMOTEPORT", e.RemotePort)
	add("SUBNET", e.Subnet)
	add("WEIGHT", e.Weight)
	add("INVITATION_FILE", e.InvitationFile)
	add("INVITATION_URL", e.InvitationURL)
	return out
}

// Runner executes hook scripts from a config directory.
type Runner struct {
	// ConfDir is the per-netname config root (where gsnet-up lives).
	ConfDir string
	// Extension is appended to the script name (e.g. ".py").
	Extension string
	// Interpreter, if non-empty, is prepended to the command (e.g. "/usr/bin/python3").
	Interpreter string
}

// Run executes the script named name (e.g. "gsnet-up", "hosts/alice-up") if it
// exists and is executable. Missing scripts are a no-op; non-zero exits return
// an error with the script's combined output.
func (r *Runner) Run(ctx context.Context, name string, env Env) error {
	path := filepath.Join(r.ConfDir, filepath.FromSlash(name)) + r.Extension
	st, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if !isExecutable(st) {
		return nil
	}
	var cmd *exec.Cmd
	if r.Interpreter != "" {
		cmd = exec.CommandContext(ctx, r.Interpreter, path)
	} else {
		cmd = exec.CommandContext(ctx, path)
	}
	cmd.Env = env.ToOSEnv()
	cmd.Dir = r.ConfDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("script %s: %w; output: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func isExecutable(fi os.FileInfo) bool {
	return fi.Mode()&0o111 != 0
}
