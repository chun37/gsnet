package gossip

import (
	"sync"
	"testing"

	"github.com/chun/gsnet/internal/graph"
	"github.com/chun/gsnet/internal/keys"
)

type memTransport struct {
	mu        sync.Mutex
	sent      []Envelope
	broadcast []Envelope
}

func (m *memTransport) Send(peer string, e Envelope) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, e)
	return nil
}

func (m *memTransport) Broadcast(e Envelope) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.broadcast = append(m.broadcast, e)
	return nil
}

func TestPlane_AnnounceAddsToGraph(t *testing.T) {
	g := graph.New()
	tr := &memTransport{}
	p := NewPlane("alice", g, tr)

	if err := p.AnnounceAddEdge("bob", 10); err != nil {
		t.Fatal(err)
	}
	if !g.HasEdge("alice", "bob") {
		t.Errorf("edge alice-bob not in graph after Announce")
	}
	if len(tr.broadcast) != 1 {
		t.Errorf("Broadcast called %d times, want 1", len(tr.broadcast))
	}
}

func TestPlane_DedupReceive(t *testing.T) {
	g := graph.New()
	tr := &memTransport{}
	p := NewPlane("alice", g, tr)

	env := Envelope{
		ID:     NewID("bob", 1),
		Origin: "bob",
		Kind:   KindAddEdge,
	}
	// Provide a valid payload so apply() succeeds.
	env.Payload = []byte(`{"from":"bob","to":"carol","weight":10}`)

	if err := p.Receive(env); err != nil {
		t.Fatal(err)
	}
	if err := p.Receive(env); err != nil {
		t.Fatal(err)
	}
	if !g.HasEdge("bob", "carol") {
		t.Errorf("edge missing")
	}
	if len(tr.broadcast) != 1 {
		t.Errorf("dedup failed: Broadcast called %d times, want 1", len(tr.broadcast))
	}
}

func TestPlane_AppliesSubnet(t *testing.T) {
	g := graph.New()
	tr := &memTransport{}
	p := NewPlane("alice", g, tr)
	if err := p.AnnounceAddSubnet("192.168.1.0/24"); err != nil {
		t.Fatal(err)
	}
	owner, ok := g.SubnetOwner("192.168.1.0/24")
	if !ok || owner != "alice" {
		t.Errorf("subnet owner = %q, %v; want alice,true", owner, ok)
	}
}

func TestPlane_SignAndVerify_GoodSig(t *testing.T) {
	priv, _ := keys.GenerateEd25519()

	sender := NewPlane("alice", graph.New(), &memTransport{})
	sender.SetSigner(priv)

	receiver := NewPlane("bob", graph.New(), &memTransport{})
	receiver.SetVerifier(func(origin string) (keys.Ed25519Public, bool) {
		if origin == "alice" {
			return priv.Public(), true
		}
		return keys.Ed25519Public{}, false
	})

	// sender mints a signed envelope by calling Announce; capture it.
	captured := &captureTransport{}
	sender2 := NewPlane("alice", graph.New(), captured)
	sender2.SetSigner(priv)
	if err := sender2.AnnounceAddEdge("bob", 10); err != nil {
		t.Fatal(err)
	}
	if len(captured.out) != 1 {
		t.Fatalf("expected 1 envelope, got %d", len(captured.out))
	}
	if err := receiver.Receive(captured.out[0]); err != nil {
		t.Errorf("valid signature rejected: %v", err)
	}
}

func TestPlane_SignAndVerify_BadSig(t *testing.T) {
	good, _ := keys.GenerateEd25519()
	wrong, _ := keys.GenerateEd25519()

	captured := &captureTransport{}
	sender := NewPlane("alice", graph.New(), captured)
	sender.SetSigner(good)
	_ = sender.AnnounceAddEdge("bob", 10)

	receiver := NewPlane("bob", graph.New(), &memTransport{})
	receiver.SetVerifier(func(origin string) (keys.Ed25519Public, bool) {
		return wrong.Public(), true
	})
	if err := receiver.Receive(captured.out[0]); err == nil {
		t.Errorf("bad signature accepted, want error")
	}
}

type captureTransport struct {
	out []Envelope
}

func (c *captureTransport) Send(string, Envelope) error { return nil }
func (c *captureTransport) Broadcast(e Envelope) error  { c.out = append(c.out, e); return nil }

func TestPlane_StableIDDedupBounded(t *testing.T) {
	g := graph.New()
	tr := &captureTransport{}
	p := NewPlane("alice", g, tr)
	for i := 0; i < 100; i++ {
		if err := p.AnnounceAddSubnet("10.0.0.0/24"); err != nil {
			t.Fatal(err)
		}
	}
	if got := p.OutboxSize(); got != 1 {
		t.Errorf("OutboxSize after 100 announces of the same subnet = %d, want 1", got)
	}
	if got := p.SeenSize(); got != 1 {
		t.Errorf("SeenSize = %d, want 1 (single stable ID)", got)
	}
}

func TestPlane_StableID_DelOverwritesAdd(t *testing.T) {
	g := graph.New()
	tr := &captureTransport{}
	p := NewPlane("alice", g, tr)
	_ = p.AnnounceAddSubnet("10.0.0.0/24")
	if _, ok := g.SubnetOwner("10.0.0.0/24"); !ok {
		t.Errorf("subnet not present after Add")
	}
	_ = p.AnnounceDelSubnet("10.0.0.0/24")
	if _, ok := g.SubnetOwner("10.0.0.0/24"); ok {
		t.Errorf("subnet still present after Del")
	}
	if p.OutboxSize() != 1 {
		t.Errorf("OutboxSize = %d, want 1 (Del overwrites Add)", p.OutboxSize())
	}
}

func TestPlane_ResendOutbox_ReplaysAll(t *testing.T) {
	g := graph.New()
	tr := &captureTransport{}
	p := NewPlane("alice", g, tr)
	_ = p.AnnounceAddSubnet("10.0.0.0/24")
	_ = p.AnnounceAddSubnet("172.16.0.0/12")
	_ = p.AnnounceAddEdge("bob", 10)
	tr.out = nil // reset
	if err := p.ResendOutbox(); err != nil {
		t.Fatal(err)
	}
	if len(tr.out) != 3 {
		t.Errorf("ResendOutbox broadcast %d envelopes, want 3", len(tr.out))
	}
}

func TestPlane_NewerTSOverridesOlder(t *testing.T) {
	g := graph.New()
	tr := &captureTransport{}
	p := NewPlane("bob", g, tr)
	// Receive Add with TS=200.
	env1 := Envelope{ID: "alice/subnet/10.0.0.0/24", Origin: "alice", Kind: KindAddSubnet, TS: 200,
		Payload: []byte(`{"owner":"alice","subnet":"10.0.0.0/24"}`)}
	if err := p.Receive(env1); err != nil {
		t.Fatal(err)
	}
	// Older Del with TS=100 should be dropped.
	env2 := Envelope{ID: "alice/subnet/10.0.0.0/24", Origin: "alice", Kind: KindDelSubnet, TS: 100,
		Payload: []byte(`{"owner":"alice","subnet":"10.0.0.0/24"}`)}
	if err := p.Receive(env2); err != nil {
		t.Fatal(err)
	}
	if _, ok := g.SubnetOwner("10.0.0.0/24"); !ok {
		t.Errorf("older Del incorrectly applied")
	}
	// Newer Del with TS=300 should win.
	env3 := Envelope{ID: "alice/subnet/10.0.0.0/24", Origin: "alice", Kind: KindDelSubnet, TS: 300,
		Payload: []byte(`{"owner":"alice","subnet":"10.0.0.0/24"}`)}
	if err := p.Receive(env3); err != nil {
		t.Fatal(err)
	}
	if _, ok := g.SubnetOwner("10.0.0.0/24"); ok {
		t.Errorf("newer Del not applied")
	}
}

func TestPlane_OnMessageObserver(t *testing.T) {
	g := graph.New()
	tr := &memTransport{}
	p := NewPlane("alice", g, tr)

	got := 0
	p.OnMessage(func(_ Envelope) { got++ })

	_ = p.AnnounceAddEdge("bob", 10)
	if got != 1 {
		t.Errorf("listener called %d times, want 1", got)
	}
}
