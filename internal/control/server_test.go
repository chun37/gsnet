package control

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestServerClient_Roundtrip(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "ctl.sock")
	cookie := "test-cookie"

	var mu sync.Mutex
	handled := make(map[RequestType]int)

	srv := &Server{
		NodeName: "alice",
		Cookie:   cookie,
		Handler: HandlerFunc(func(_ context.Context, m Message, w io.Writer) error {
			mu.Lock()
			handled[m.Type]++
			mu.Unlock()
			fmt.Fprintf(w, "%d %d 0\n", ClassRequest, m.Type)
			return nil
		}),
	}
	if err := srv.Listen(socket); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		_ = srv.Serve(ctx)
		close(done)
	}()

	cl, err := Dial(socket, cookie)
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	if cl.ServerName != "alice" {
		t.Errorf("ServerName = %q, want alice", cl.ServerName)
	}

	resp, err := cl.Send(ReqDumpNodes)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(resp, fmt.Sprintf("%d %d", ClassRequest, ReqDumpNodes)) {
		t.Errorf("response = %q", resp)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Serve did not return")
	}

	mu.Lock()
	if handled[ReqDumpNodes] != 1 {
		t.Errorf("handler called %d times for ReqDumpNodes, want 1", handled[ReqDumpNodes])
	}
	mu.Unlock()
}

func TestServerClient_AuthRejected(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "ctl.sock")
	srv := &Server{NodeName: "alice", Cookie: "real-cookie"}
	if err := srv.Listen(socket); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx)

	if _, err := Dial(socket, "wrong-cookie"); err == nil {
		t.Errorf("Dial with wrong cookie succeeded, want error")
	}
}
