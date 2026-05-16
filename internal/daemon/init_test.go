package daemon

import (
	"os"
	"strings"
	"testing"
)

func TestInit_CreatesExpectedFiles(t *testing.T) {
	root := t.TempDir()
	p := Paths{ConfRoot: root, Netname: "vpn"}
	if err := Init(p, "alice"); err != nil {
		t.Fatal(err)
	}
	checks := []string{
		p.ConfFile(),
		p.Ed25519Private(),
		p.WGPrivate(),
		p.HostsDir(),
		p.HostFile("alice"),
		p.InvitationsDir(),
	}
	for _, c := range checks {
		if _, err := os.Stat(c); err != nil {
			t.Errorf("%s missing: %v", c, err)
		}
	}
	conf, _ := os.ReadFile(p.ConfFile())
	if !strings.Contains(string(conf), "Name = alice") {
		t.Errorf("gsnet.conf missing Name = alice: %q", conf)
	}
	host, _ := os.ReadFile(p.HostFile("alice"))
	if !strings.Contains(string(host), "Ed25519PublicKey") {
		t.Errorf("hosts/alice missing Ed25519PublicKey: %s", host)
	}
	if !strings.Contains(string(host), "WGPublicKey") {
		t.Errorf("hosts/alice missing WGPublicKey")
	}
}

func TestInit_RejectsInvalidName(t *testing.T) {
	root := t.TempDir()
	p := Paths{ConfRoot: root, Netname: "vpn"}
	if err := Init(p, "bad-name"); err == nil {
		t.Errorf("Init with invalid name succeeded")
	}
}

func TestInit_RefusesOverwrite(t *testing.T) {
	root := t.TempDir()
	p := Paths{ConfRoot: root, Netname: "vpn"}
	if err := Init(p, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := Init(p, "alice"); err == nil {
		t.Errorf("second Init succeeded, want exclusive-create failure")
	}
}
