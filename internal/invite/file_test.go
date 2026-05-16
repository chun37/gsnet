package invite

import (
	"reflect"
	"strings"
	"testing"
)

const sampleFile = `Name = client
Netname = myvpn
ConnectTo = server
#--------------------------------------#
Name = server
Ed25519PublicKey = abc123def
Address = server.example.com
`

func TestParseFile(t *testing.T) {
	f, err := ParseFile(strings.NewReader(sampleFile))
	if err != nil {
		t.Fatal(err)
	}
	if f.Invitee.Name != "client" {
		t.Errorf("Invitee.Name = %q, want client", f.Invitee.Name)
	}
	if f.Netname != "myvpn" {
		t.Errorf("Netname = %q, want myvpn", f.Netname)
	}
	if !reflect.DeepEqual(f.Invitee.ConnectTo, []string{"server"}) {
		t.Errorf("Invitee.ConnectTo = %v, want [server]", f.Invitee.ConnectTo)
	}
	if len(f.Hosts) != 1 {
		t.Fatalf("Hosts count = %d, want 1", len(f.Hosts))
	}
	if f.Hosts[0].Name != "server" {
		t.Errorf("Hosts[0].Name = %q, want server", f.Hosts[0].Name)
	}
	if f.Hosts[0].Address != "server.example.com" {
		t.Errorf("Hosts[0].Address = %q, want server.example.com", f.Hosts[0].Address)
	}
}

func TestParseFile_MissingInviteeName(t *testing.T) {
	src := "ConnectTo = server\n"
	if _, err := ParseFile(strings.NewReader(src)); err == nil {
		t.Errorf("ParseFile without Name succeeded, want error")
	}
}

func TestParseFile_IfconfigHint(t *testing.T) {
	src := "Name = me\nIfconfig = 10.0.0.5/24\nIfconfig = dhcp6\n"
	f, err := ParseFile(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := f.Invitee.Ifconfig, []string{"10.0.0.5/24", "dhcp6"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Ifconfig = %v, want %v", got, want)
	}
}

func TestParseFile_RouteHint(t *testing.T) {
	src := "Name = me\nRoute = 192.168.0.0/16\nRoute = 10.0.0.0/8 10.0.0.1\n"
	f, err := ParseFile(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.168.0.0/16", "10.0.0.0/8 10.0.0.1"}
	if !reflect.DeepEqual(f.Invitee.Route, want) {
		t.Errorf("Route = %v, want %v", f.Invitee.Route, want)
	}
}

func TestRender_RoundTrip(t *testing.T) {
	f, err := ParseFile(strings.NewReader(sampleFile))
	if err != nil {
		t.Fatal(err)
	}
	rendered := f.Render()
	reparsed, err := ParseFile(strings.NewReader(rendered))
	if err != nil {
		t.Fatalf("re-parse of rendered output failed: %v", err)
	}
	if reparsed.Invitee.Name != f.Invitee.Name {
		t.Errorf("after round-trip Invitee.Name = %q, want %q", reparsed.Invitee.Name, f.Invitee.Name)
	}
	if reparsed.Netname != f.Netname {
		t.Errorf("after round-trip Netname = %q, want %q", reparsed.Netname, f.Netname)
	}
	if len(reparsed.Hosts) != len(f.Hosts) {
		t.Errorf("Hosts count differs after round-trip")
	}
}
