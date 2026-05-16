package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chun/gsnet/internal/gossip"
	"github.com/chun/gsnet/internal/keys"
)

func TestGossip_BroadcastBetweenTwoServers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var aReceived, bReceived []gossip.Envelope
	var mu sync.Mutex

	a := &Server{Addr: "127.0.0.1:0", OnGossip: func(e gossip.Envelope) {
		mu.Lock()
		aReceived = append(aReceived, e)
		mu.Unlock()
	}}
	b := &Server{Addr: "127.0.0.1:0", OnGossip: func(e gossip.Envelope) {
		mu.Lock()
		bReceived = append(bReceived, e)
		mu.Unlock()
	}}

	if err := a.Start(); err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if err := b.Start(); err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	go a.Serve(ctx)
	go b.Serve(ctx)

	if err := a.Dial(ctx, b.LocalAddr().String()); err != nil {
		t.Fatal(err)
	}

	env := gossip.Envelope{
		ID:      "alice/1",
		Origin:  "alice",
		Kind:    gossip.KindPing,
		TS:      gossip.TSNow(),
		Payload: json.RawMessage(`{}`),
	}
	if err := a.Broadcast(env); err != nil {
		t.Fatal(err)
	}
	// Allow goroutines to process.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		got := len(bReceived)
		mu.Unlock()
		if got > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bReceived) != 1 || bReceived[0].ID != "alice/1" {
		t.Errorf("b did not receive envelope, got %+v", bReceived)
	}
}

func TestInvite_GetAndJoin_Encrypted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	edPriv, err := keys.GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	keyHash := edPriv.Public().Hash()

	// Invitation file must include the inviter's Ed25519PublicKey in a block
	// after a '#' separator (block 2+). The client uses this to verify the
	// inviter's identity.
	inviteFile := fmt.Sprintf(
		"Name = bob\nNetname = vpn\nConnectTo = alice\n#-----#\nName = alice\nEd25519PublicKey = %s\n",
		edPriv.Public().String(),
	)

	srv := &Server{
		Addr:   "127.0.0.1:0",
		EdPriv: edPriv,
		InviteGet: func(cookie string) ([]byte, error) {
			if cookie != "abc" {
				return nil, fmt.Errorf("invalid cookie")
			}
			return []byte(inviteFile), nil
		},
		InviteJoin: func(cookie, name string, body []byte) ([]byte, error) {
			if cookie != "abc" || name != "bob" {
				return nil, fmt.Errorf("mismatch")
			}
			return []byte(inviteFile + "\n# stored: " + string(body)), nil
		},
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go srv.Serve(ctx)

	addr := srv.LocalAddr().String()

	got, err := InviteGet(ctx, addr, "abc", keyHash)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "Name = bob") {
		t.Errorf("InviteGet body = %q", got)
	}

	joinResp, err := InviteJoin(ctx, addr, "abc", "bob", []byte("WGPublicKey = xxx\n"), keyHash)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(joinResp), "stored: WGPublicKey = xxx") {
		t.Errorf("InviteJoin reply = %q", joinResp)
	}

	if _, err := InviteGet(ctx, addr, "wrong", keyHash); err == nil {
		t.Errorf("InviteGet with wrong cookie succeeded")
	}

	// Wrong keyhash → reject (simulates MITM with different Ed25519 key).
	if _, err := InviteGet(ctx, addr, "abc", "bogus-hash"); err == nil {
		t.Errorf("InviteGet with wrong keyhash succeeded")
	}
}
