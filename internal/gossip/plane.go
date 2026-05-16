package gossip

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/chun/gsnet/internal/graph"
	"github.com/chun/gsnet/internal/keys"
)

// Transport is the abstraction over actual network delivery. The gossip plane
// only cares about send-to-one and broadcast-to-all-peers semantics.
type Transport interface {
	Send(peer string, env Envelope) error
	Broadcast(env Envelope) error
}

// Plane is the gossip control plane.
//
// Anti-entropy design (v2):
//
//   - Every fact (a Hello, an edge, a subnet) has a STABLE envelope ID of the
//     form "<origin>/<kind>/<key>". Re-announcing the same fact uses the same
//     ID, only the TS increases.
//   - Receivers dedup by ID *and* TS: a newer TS for an existing ID supersedes
//     the previous version; older or equal TS is dropped.
//   - This means the dedup table is bounded by the number of distinct facts in
//     the network (not by message-rate × time).
//   - Locally-originated facts are kept in an "outbox" indexed by ID. The
//     heartbeat re-broadcasts the entire outbox so a newly-connected peer
//     eventually receives all of our state.
//   - Del messages replace Add messages in the outbox (same ID, different
//     kind, newer TS) so deletions propagate just like additions.
type Plane struct {
	NodeName string
	G        *graph.Graph

	transport Transport

	mu        sync.Mutex
	seen      map[string]int64 // ID → highest TS observed
	outbox    map[string]Envelope
	listener  func(Envelope)
	edPriv    *keys.Ed25519Private
	pubKeyFor func(origin string) (keys.Ed25519Public, bool)
	pubKeys   map[string]keys.Ed25519Public
	endpoints map[string]string // origin → "host:port" learned from Hello
}

func NewPlane(nodeName string, g *graph.Graph, t Transport) *Plane {
	return &Plane{
		NodeName:  nodeName,
		G:         g,
		transport: t,
		seen:      make(map[string]int64),
		outbox:    make(map[string]Envelope),
		pubKeys:   make(map[string]keys.Ed25519Public),
		endpoints: make(map[string]string),
	}
}

// EndpointOf returns the most recently advertised "host:port" for origin
// (from a Hello message). Empty string if unknown.
func (p *Plane) EndpointOf(origin string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.endpoints[origin]
}

// SetSigner installs the Ed25519 private key used to sign outgoing envelopes.
func (p *Plane) SetSigner(priv keys.Ed25519Private) {
	p.mu.Lock()
	defer p.mu.Unlock()
	cp := priv
	p.edPriv = &cp
}

// SetVerifier installs the lookup used to verify incoming envelopes.
func (p *Plane) SetVerifier(f func(origin string) (keys.Ed25519Public, bool)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pubKeyFor = f
}

// OnMessage installs an observer for every accepted-and-applied envelope.
func (p *Plane) OnMessage(f func(Envelope)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.listener = f
}

// originate mints, signs, stores in outbox, applies locally, and broadcasts.
// id is the stable ID for this fact.
func (p *Plane) originate(id string, kind Kind, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	env := Envelope{
		ID:      id,
		Origin:  p.NodeName,
		Kind:    kind,
		TS:      TSNow(),
		Payload: body,
	}
	p.sign(&env)

	p.mu.Lock()
	p.outbox[id] = env
	p.seen[id] = env.TS
	p.mu.Unlock()

	p.apply(env)
	return p.transport.Broadcast(env)
}

// Receive ingests an envelope from the network. Dropped if signature is
// invalid or if a same-or-newer message with the same ID has already been seen.
//
// The order is: verify first, then atomic claim-or-drop. The claim acts as a
// compare-and-swap: only the first goroutine to observe a higher TS wins,
// ensuring apply()+Broadcast() runs exactly once per (id, ts).
func (p *Plane) Receive(env Envelope) error {
	if !p.verify(env) {
		return fmt.Errorf("gossip: signature verification failed for %s from %s", env.Kind, env.Origin)
	}
	if !p.claim(env.ID, env.TS) {
		return nil
	}
	p.apply(env)
	return p.transport.Broadcast(env)
}

// claim atomically records (id, ts) in `seen` if and only if ts strictly
// exceeds the previously-stored TS (or no prior entry exists). Returns true
// when the caller has won the claim and should proceed to apply+broadcast.
func (p *Plane) claim(id string, ts int64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if prev, ok := p.seen[id]; ok && ts <= prev {
		return false
	}
	p.seen[id] = ts
	return true
}

// ResendOutbox re-broadcasts every locally-originated fact. Intended for
// heartbeat and post-reconnect catch-up.
func (p *Plane) ResendOutbox() error {
	p.mu.Lock()
	envs := make([]Envelope, 0, len(p.outbox))
	for _, e := range p.outbox {
		envs = append(envs, e)
	}
	p.mu.Unlock()
	for _, e := range envs {
		if err := p.transport.Broadcast(e); err != nil {
			return err
		}
	}
	return nil
}

// OutboxSize returns the number of facts currently held in the local outbox.
// Exposed for diagnostics and tests.
func (p *Plane) OutboxSize() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.outbox)
}

// SeenSize returns the size of the dedup table. Useful for verifying it stays
// bounded over time.
func (p *Plane) SeenSize() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.seen)
}

func (p *Plane) sign(env *Envelope) {
	p.mu.Lock()
	priv := p.edPriv
	p.mu.Unlock()
	if priv == nil {
		return
	}
	env.Signature = priv.Sign(env.SigningBytes())
}

func (p *Plane) verify(env Envelope) bool {
	p.mu.Lock()
	pubLookup := p.pubKeyFor
	learned, learnedOK := p.pubKeys[env.Origin]
	p.mu.Unlock()

	if pubLookup == nil && !learnedOK {
		return true
	}
	var pub keys.Ed25519Public
	if pubLookup != nil {
		if v, ok := pubLookup(env.Origin); ok {
			pub = v
		}
	}
	if len(pub.Raw()) == 0 && learnedOK {
		pub = learned
	}
	if len(pub.Raw()) == 0 {
		return false
	}
	return pub.Verify(env.SigningBytes(), env.Signature)
}

func (p *Plane) rememberPubKey(name string, pub keys.Ed25519Public) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pubKeys[name] = pub
}

func (p *Plane) apply(env Envelope) {
	switch env.Kind {
	case KindAddNode:
		var h Hello
		if err := json.Unmarshal(env.Payload, &h); err != nil {
			return
		}
		p.G.AddNode(h.Name)
		if pub, err := keys.ParseEd25519PublicBase64ish(h.Ed25519Public); err == nil {
			p.rememberPubKey(h.Name, pub)
		}
		if h.Endpoint != "" {
			p.mu.Lock()
			p.endpoints[h.Name] = h.Endpoint
			p.mu.Unlock()
		}
	case KindDelNode:
		var h Hello
		if err := json.Unmarshal(env.Payload, &h); err != nil || h.Name == "" {
			return
		}
		for _, e := range p.G.Edges() {
			if e.From == h.Name || e.To == h.Name {
				p.G.DelEdge(e.From, e.To)
			}
		}
	case KindAddEdge:
		var e AddEdge
		if err := json.Unmarshal(env.Payload, &e); err != nil {
			return
		}
		p.G.AddEdge(graph.Edge{From: e.From, To: e.To, Weight: e.Weight})
	case KindDelEdge:
		var e DelEdge
		if err := json.Unmarshal(env.Payload, &e); err != nil {
			return
		}
		p.G.DelEdge(e.From, e.To)
	case KindAddSubnet:
		var s AddSubnet
		if err := json.Unmarshal(env.Payload, &s); err != nil {
			return
		}
		p.G.AddSubnet(s.Owner, s.Subnet)
	case KindDelSubnet:
		var s DelSubnet
		if err := json.Unmarshal(env.Payload, &s); err != nil {
			return
		}
		p.G.DelSubnet(s.Owner, s.Subnet)
	}
	p.mu.Lock()
	listener := p.listener
	p.mu.Unlock()
	if listener != nil {
		listener(env)
	}
}

// Run blocks until ctx is canceled.
func (p *Plane) Run(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

// Stable IDs:
//   hello       → "<origin>/hello"
//   add/delEdge → "<origin>/edge/<to>"        — same ID for Add and Del
//   add/delSub  → "<origin>/subnet/<subnet>"  — same ID for Add and Del
// Del messages overwrite their corresponding Add in the outbox.

func (p *Plane) AnnounceHello(h Hello) error {
	return p.originate(p.NodeName+"/hello", KindAddNode, h)
}

func (p *Plane) AnnounceAddEdge(to string, weight int) error {
	return p.originate(p.NodeName+"/edge/"+to, KindAddEdge, AddEdge{From: p.NodeName, To: to, Weight: weight})
}

func (p *Plane) AnnounceDelEdge(to string) error {
	return p.originate(p.NodeName+"/edge/"+to, KindDelEdge, DelEdge{From: p.NodeName, To: to})
}

func (p *Plane) AnnounceAddSubnet(subnet string) error {
	return p.originate(p.NodeName+"/subnet/"+subnet, KindAddSubnet, AddSubnet{Owner: p.NodeName, Subnet: subnet})
}

func (p *Plane) AnnounceDelSubnet(subnet string) error {
	return p.originate(p.NodeName+"/subnet/"+subnet, KindDelSubnet, DelSubnet{Owner: p.NodeName, Subnet: subnet})
}

// ErrPeerUnknown is returned by transports that don't know the destination.
var ErrPeerUnknown = fmt.Errorf("gossip: unknown peer")
