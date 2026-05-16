package script

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRun_MissingIsNoOp(t *testing.T) {
	r := &Runner{ConfDir: t.TempDir()}
	if err := r.Run(context.Background(), "gsnet-up", Env{}); err != nil {
		t.Errorf("missing script returned error: %v", err)
	}
}

func TestRun_ExecutesAndPassesEnv(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("posix-only test")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "gsnet-up")
	body := "#!/bin/sh\necho $NAME > " + filepath.Join(dir, "out.txt") + "\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	r := &Runner{ConfDir: dir}
	if err := r.Run(context.Background(), "gsnet-up", Env{Name: "alice"}); err != nil {
		t.Fatal(err)
	}
	out, err := os.ReadFile(filepath.Join(dir, "out.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(out); got != "alice\n" {
		t.Errorf("script wrote %q, want %q", got, "alice\n")
	}
}

func TestRun_NonExecutableIsNoOp(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "gsnet-up")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 7\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &Runner{ConfDir: dir}
	if err := r.Run(context.Background(), "gsnet-up", Env{}); err != nil {
		t.Errorf("non-executable script returned error: %v", err)
	}
}

func TestRun_NonZeroExitIsError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip()
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "gsnet-up")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 42\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := &Runner{ConfDir: dir}
	if err := r.Run(context.Background(), "gsnet-up", Env{}); err == nil {
		t.Errorf("non-zero exit did not return error")
	}
}
