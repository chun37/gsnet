package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/chun/gsnet/internal/dataplane/fake"
)

// startMinimal brings up just enough daemon state to exercise buildState and
// the gossip plane. It does NOT bind a TCP listener for the gossip transport
// — discovery / gossip propagation is exercised by feeding envelopes via
// d.plane directly.
func startMinimal(t *testing.T, p Paths) (*Daemon, context.CancelFunc, <-chan error) {
	t.Helper()
	runDir := filepath.Join(p.ConfRoot, "run")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	port := allocPortMinimal(t)
	d := &Daemon{
		Paths:      p,
		RunDir:     runDir,
		Reconciler: fake.New(),
		GossipAddr: fmt.Sprintf("127.0.0.1:%d", port),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	// Wait for the control socket to appear so d.plane is initialized.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(p.ControlSocket(runDir)); err == nil {
			return d, cancel, done
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	t.Fatal("daemon did not start in time")
	return nil, nil, nil
}

func allocPortMinimal(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

func mkdirAll(p string, perm os.FileMode) error { return os.MkdirAll(p, perm) }
func writeFile(p string, b []byte, perm os.FileMode) error {
	return os.WriteFile(p, b, perm)
}
func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }
