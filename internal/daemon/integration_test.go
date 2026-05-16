package daemon

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chun/gsnet/internal/config"
	"github.com/chun/gsnet/internal/control"
	"github.com/chun/gsnet/internal/dataplane/fake"
	"github.com/chun/gsnet/internal/invite"
	"github.com/chun/gsnet/internal/keys"
	"github.com/chun/gsnet/internal/transport"
)

// allocPort returns a free TCP port by binding to :0 and immediately closing.
// Race-y but good enough for tests.
func allocPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

// startNode initializes a node (if not already), augments its config and
// hosts/<self> with the loopback Address+Port, and starts the daemon.
func startNode(t *testing.T, root, name string, gPort int, connectTo []string) (*Daemon, context.CancelFunc, <-chan error) {
	t.Helper()
	p := Paths{ConfRoot: root, Netname: "vpn"}
	if _, err := os.Stat(p.ConfFile()); os.IsNotExist(err) {
		if err := Init(p, name); err != nil {
			t.Fatal(err)
		}
	}
	confEntries, err := config.ParseFile(p.ConfFile())
	if err != nil {
		t.Fatal(err)
	}
	if _, has := confEntries.GetFirst("Address"); !has {
		confEntries = append(confEntries, config.Entry{Key: "Address", Value: "127.0.0.1"})
	}
	if _, has := confEntries.GetFirst("Port"); !has {
		confEntries = append(confEntries, config.Entry{Key: "Port", Value: fmt.Sprint(gPort)})
	}
	for _, c := range connectTo {
		confEntries = append(confEntries, config.Entry{Key: "ConnectTo", Value: c})
	}
	if err := os.WriteFile(p.ConfFile(), []byte(confEntries.Render()), 0o644); err != nil {
		t.Fatal(err)
	}
	hostEntries, err := config.ParseFile(p.HostFile(name))
	if err != nil {
		t.Fatal(err)
	}
	if _, has := hostEntries.GetFirst("Address"); !has {
		hostEntries = append(hostEntries, config.Entry{Key: "Address", Value: "127.0.0.1"})
	}
	if _, has := hostEntries.GetFirst("Port"); !has {
		hostEntries = append(hostEntries, config.Entry{Key: "Port", Value: fmt.Sprint(gPort)})
	}
	if err := os.WriteFile(p.HostFile(name), []byte(hostEntries.Render()), 0o644); err != nil {
		t.Fatal(err)
	}

	runDir := filepath.Join(root, "run")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatal(err)
	}

	d := &Daemon{
		Paths:      p,
		RunDir:     runDir,
		Reconciler: fake.New(),
		GossipAddr: fmt.Sprintf("127.0.0.1:%d", gPort),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(p.ControlSocket(runDir)); err == nil {
			return d, cancel, done
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	t.Fatalf("node %s did not start within deadline", name)
	return nil, nil, nil
}

func copyHostFile(t *testing.T, srcPaths, dstPaths Paths, name string) {
	t.Helper()
	data, err := os.ReadFile(srcPaths.HostFile(name))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dstPaths.HostsDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dstPaths.HostFile(name), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func dialControlForTest(t *testing.T, p Paths, runDir string) *control.Client {
	t.Helper()
	pidBytes, err := os.ReadFile(p.PIDFile(runDir))
	if err != nil {
		t.Fatal(err)
	}
	pf, err := control.ParsePIDFile(string(pidBytes))
	if err != nil {
		t.Fatal(err)
	}
	cl, err := control.Dial(p.ControlSocket(runDir), pf.Cookie)
	if err != nil {
		t.Fatal(err)
	}
	return cl
}

func dumpUntilTerm(t *testing.T, cl *control.Client, req control.RequestType) []string {
	t.Helper()
	first, err := cl.Send(req)
	if err != nil {
		t.Fatal(err)
	}
	terminator := fmt.Sprintf("%d %d", control.ClassRequest, req)
	line := strings.TrimRight(first, "\r\n")
	var lines []string
	for {
		if line == terminator {
			return lines
		}
		lines = append(lines, line)
		next, err := cl.ReadLine()
		if err != nil {
			t.Fatal(err)
		}
		line = strings.TrimRight(next, "\r\n")
	}
}

// pollUntil polls dump fn until expected substring is present, or fails the test on timeout.
func pollUntilSubnet(t *testing.T, cl *control.Client, subnet, owner string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		lines := dumpUntilTerm(t, cl, control.ReqDumpSubnets)
		for _, l := range lines {
			if strings.Contains(l, subnet) && strings.Contains(l, owner) {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("never observed subnet %s owned by %s", subnet, owner)
}

// TestTwoNodes_GossipPropagation exercises the simplest path: two daemons,
// host files mirrored manually, alice announces a subnet, bob observes it.
func TestTwoNodes_GossipPropagation(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	rootA := t.TempDir()
	rootB := t.TempDir()
	portA := allocPort(t)
	portB := allocPort(t)

	pA := Paths{ConfRoot: rootA, Netname: "vpn"}
	pB := Paths{ConfRoot: rootB, Netname: "vpn"}

	dA, cancelA, doneA := startNode(t, rootA, "alice", portA, nil)
	defer func() {
		cancelA()
		<-doneA
	}()

	copyHostFile(t, pA, pB, "alice")
	dB, cancelB, doneB := startNode(t, rootB, "bob", portB, []string{"alice"})
	defer func() {
		cancelB()
		<-doneB
	}()
	copyHostFile(t, pB, pA, "bob")
	_ = pB

	confA, _ := config.ParseFile(pA.ConfFile())
	confA = append(confA, config.Entry{Key: "Subnet", Value: "10.42.1.0/24"})
	if err := os.WriteFile(pA.ConfFile(), []byte(confA.Render()), 0o644); err != nil {
		t.Fatal(err)
	}
	clA := dialControlForTest(t, pA, dA.RunDir)
	defer clA.Close()
	if _, err := clA.Send(control.ReqReload); err != nil {
		t.Fatal(err)
	}

	clB := dialControlForTest(t, dB.Paths, dB.RunDir)
	defer clB.Close()
	pollUntilSubnet(t, clB, "10.42.1.0/24", "alice", 5*time.Second)
}

// TestTwoNodes_InviteJoinEndToEnd exercises the full join flow without
// manual host-file copying.
func TestTwoNodes_InviteJoinEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	rootA := t.TempDir()
	rootB := t.TempDir()
	portA := allocPort(t)
	portB := allocPort(t)

	dA, cancelA, doneA := startNode(t, rootA, "alice", portA, nil)
	defer func() {
		cancelA()
		<-doneA
	}()
	pA := dA.Paths

	cookie, keyHash := makeInvitation(t, pA, "bob")

	bobAddr := fmt.Sprintf("127.0.0.1:%d", portA)
	if err := runJoin(rootB, bobAddr, cookie, keyHash); err != nil {
		t.Fatalf("join: %v", err)
	}

	dB, cancelB, doneB := startNode(t, rootB, "bob", portB, []string{"alice"})
	defer func() {
		cancelB()
		<-doneB
	}()

	confB, _ := config.ParseFile(dB.Paths.ConfFile())
	confB = append(confB, config.Entry{Key: "Subnet", Value: "10.99.0.0/16"})
	if err := os.WriteFile(dB.Paths.ConfFile(), []byte(confB.Render()), 0o644); err != nil {
		t.Fatal(err)
	}
	clB := dialControlForTest(t, dB.Paths, dB.RunDir)
	defer clB.Close()
	if _, err := clB.Send(control.ReqReload); err != nil {
		t.Fatal(err)
	}

	clA := dialControlForTest(t, pA, dA.RunDir)
	defer clA.Close()
	pollUntilSubnet(t, clA, "10.99.0.0/16", "bob", 8*time.Second)
}

// makeInvitation writes an invitation file for the given invitee in the
// inviter's invitations directory and returns the cookie and the inviter's
// keyhash (so the test can pass it to runJoin for signature verification).
func makeInvitation(t *testing.T, p Paths, inviteeName string) (cookie, keyHash string) {
	t.Helper()
	cookie = "test-cookie-" + fmt.Sprint(time.Now().UnixNano())
	body := fmt.Sprintf("Name = %s\nNetname = vpn\nConnectTo = alice\n#---#\nName = alice\nAddress = 127.0.0.1\n", inviteeName)
	aliceHost, err := os.ReadFile(p.HostFile("alice"))
	if err != nil {
		t.Fatal(err)
	}
	body += string(aliceHost)
	if err := os.MkdirAll(p.InvitationsDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p.InvitationsDir(), cookie), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	// Extract alice's Ed25519PublicKey to compute the keyhash.
	es, err := config.Parse(strings.NewReader(string(aliceHost)))
	if err != nil {
		t.Fatal(err)
	}
	v, ok := es.GetFirst("Ed25519PublicKey")
	if !ok {
		t.Fatal("alice's host file has no Ed25519PublicKey")
	}
	pub, err := keys.ParseEd25519PublicBase64(strings.TrimSpace(v))
	if err != nil {
		t.Fatal(err)
	}
	return cookie, pub.Hash()
}

// runJoin mirrors the production cmdJoin in cmd/gsnet without importing it.
func runJoin(rootB, addr, cookie, keyHash string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	body, err := transport.InviteGet(ctx, addr, cookie, keyHash)
	if err != nil {
		return fmt.Errorf("InviteGet: %w", err)
	}
	file, err := invite.ParseFile(strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("parse invitation: %w", err)
	}

	edPriv, _ := keys.GenerateEd25519()
	wgPriv, _ := keys.GenerateWireGuard()

	myHost := config.Entries{
		{Key: "Ed25519PublicKey", Value: edPriv.Public().String()},
		{Key: "WGPublicKey", Value: wgPriv.Public().String()},
	}.Render()
	if _, err := transport.InviteJoin(ctx, addr, cookie, file.Invitee.Name, []byte(myHost), keyHash); err != nil {
		return fmt.Errorf("InviteJoin: %w", err)
	}

	p := Paths{ConfRoot: rootB, Netname: file.Netname}
	if err := os.MkdirAll(p.HostsDir(), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(p.InvitationsDir(), 0o700); err != nil {
		return err
	}
	edPEM, _ := edPriv.MarshalPEM()
	if err := os.WriteFile(p.Ed25519Private(), edPEM, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(p.WGPrivate(), []byte(wgPriv.String()+"\n"), 0o600); err != nil {
		return err
	}
	conf := config.Entries{{Key: "Name", Value: file.Invitee.Name}}
	for _, ct := range file.Invitee.ConnectTo {
		conf = append(conf, config.Entry{Key: "ConnectTo", Value: ct})
	}
	if err := os.WriteFile(p.ConfFile(), []byte(conf.Render()), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(p.HostFile(file.Invitee.Name), []byte(myHost), 0o644); err != nil {
		return err
	}
	inviter := file.Hosts[0]
	inviterHost := config.Entries{}
	if inviter.Address != "" {
		inviterHost = append(inviterHost, config.Entry{Key: "Address", Value: inviter.Address})
	}
	inviterHost = append(inviterHost, inviter.Other...)
	return os.WriteFile(p.HostFile(inviter.Name), []byte(inviterHost.Render()), 0o644)
}
