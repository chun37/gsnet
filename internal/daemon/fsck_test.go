package daemon

import (
	"os"
	"strings"
	"testing"
)

func TestFsck_CleanTreeHasNoErrors(t *testing.T) {
	root := t.TempDir()
	p := Paths{ConfRoot: root, Netname: "vpn"}
	if err := Init(p, "alice"); err != nil {
		t.Fatal(err)
	}
	findings := Fsck(p)
	for _, f := range findings {
		if f.Level == FsckError {
			t.Errorf("unexpected error: %s", f)
		}
	}
}

func TestFsck_DetectsMissingName(t *testing.T) {
	root := t.TempDir()
	p := Paths{ConfRoot: root, Netname: "vpn"}
	if err := Init(p, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.ConfFile(), []byte("# empty\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	findings := Fsck(p)
	if !hasError(findings, "Name is required") {
		t.Errorf("did not detect missing Name: %+v", findings)
	}
}

func TestFsck_DetectsInvalidSubnet(t *testing.T) {
	root := t.TempDir()
	p := Paths{ConfRoot: root, Netname: "vpn"}
	_ = Init(p, "alice")
	appendLine(t, p.ConfFile(), "Subnet = not-a-subnet")
	findings := Fsck(p)
	if !hasError(findings, "Subnet") {
		t.Errorf("did not detect invalid subnet: %+v", findings)
	}
}

func TestFsck_DetectsConnectToWithoutHost(t *testing.T) {
	root := t.TempDir()
	p := Paths{ConfRoot: root, Netname: "vpn"}
	_ = Init(p, "alice")
	appendLine(t, p.ConfFile(), "ConnectTo = ghost")
	findings := Fsck(p)
	if !hasError(findings, "ConnectTo \"ghost\"") {
		t.Errorf("did not flag dangling ConnectTo: %+v", findings)
	}
}

func TestFsck_DetectsKeyPermissionWarning(t *testing.T) {
	root := t.TempDir()
	p := Paths{ConfRoot: root, Netname: "vpn"}
	_ = Init(p, "alice")
	if err := os.Chmod(p.Ed25519Private(), 0o644); err != nil {
		t.Fatal(err)
	}
	findings := Fsck(p)
	if !hasLevel(findings, FsckWarning, "loose permissions") {
		t.Errorf("did not warn on loose perms: %+v", findings)
	}
}

func TestFsck_DetectsHostFileMismatch(t *testing.T) {
	root := t.TempDir()
	p := Paths{ConfRoot: root, Netname: "vpn"}
	_ = Init(p, "alice")
	if err := os.WriteFile(p.HostFile("alice"), []byte("Ed25519PublicKey = wronghash\nWGPublicKey = wrongkey\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	findings := Fsck(p)
	if !hasError(findings, "Ed25519PublicKey does not match") {
		t.Errorf("did not detect Ed25519 mismatch: %+v", findings)
	}
}

func hasLevel(findings []FsckFinding, lvl FsckLevel, needle string) bool {
	for _, f := range findings {
		if f.Level == lvl && strings.Contains(f.Message, needle) {
			return true
		}
	}
	return false
}

func hasError(findings []FsckFinding, needle string) bool {
	return hasLevel(findings, FsckError, needle)
}

func appendLine(t *testing.T, path, line string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(b, []byte(line+"\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
}
