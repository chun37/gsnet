package daemon

import (
	"net/netip"
	"testing"

	"github.com/chun/gsnet/internal/config"
	"github.com/chun/gsnet/internal/gossip"
	"github.com/chun/gsnet/internal/keys"
)

// TestBuildState_GossipEndpointOverridesHostFile is the unit half of the
// "hole punching" story: when a peer publishes a fresh endpoint via gossip
// (after STUN/UPnP discovered its public IP), the daemon's data-plane state
// uses that endpoint instead of the static hosts/<peer>.Address.
//
// WireGuard's PersistentKeepalive then opens NAT pinholes from both sides;
// no explicit punch coordinator is required for common (cone) NATs.
func TestBuildState_GossipEndpointOverridesHostFile(t *testing.T) {
	root := t.TempDir()
	p := Paths{ConfRoot: root, Netname: "vpn"}
	if err := Init(p, "alice"); err != nil {
		t.Fatal(err)
	}
	// hosts/bob with a stale loopback address.
	bobPriv, _ := keys.GenerateEd25519()
	bobWG, _ := keys.GenerateWireGuard()
	hostBody := config.Entries{
		{Key: "Address", Value: "127.0.0.1"},
		{Key: "Port", Value: "1"},
		{Key: "Ed25519PublicKey", Value: bobPriv.Public().String()},
		{Key: "WGPublicKey", Value: bobWG.Public().String()},
	}.Render()
	if err := writeHostFile(p, "bob", hostBody); err != nil {
		t.Fatal(err)
	}

	d, cancel, done := startMinimal(t, p)
	defer func() { cancel(); <-done }()

	// Simulate a Hello from bob carrying a fresh endpoint.
	hello := gossip.Hello{
		Name:          "bob",
		Ed25519Public: bobPriv.Public().Raw(),
		WGPublic:      bobWG.Public().String(),
		Endpoint:      "203.0.113.42:51820",
	}
	if err := injectHelloAs(d, "bob", bobPriv, hello); err != nil {
		t.Fatal(err)
	}

	state := d.buildState()
	var bobPeer bool
	for _, pe := range state.Peers {
		if pe.Name == "bob" {
			bobPeer = true
			want := netip.MustParseAddrPort("203.0.113.42:51820")
			if pe.Endpoint != want {
				t.Errorf("peer endpoint = %v, want %v (gossip-learned)", pe.Endpoint, want)
			}
		}
	}
	if !bobPeer {
		t.Errorf("buildState did not include bob")
	}
}

// TestBuildState_GossipPopulatesInnerAndUnderlay covers the workflow where a
// peer's overlay (Inner) and underlay (Underlay) addresses are not present
// in hosts/<peer> — that file is only seeded with public keys at invite/join
// time — but arrive later via the peer's gossip Hello. buildState must use
// the gossip-learned values; otherwise switch/hub mode silently produces
// empty AllowedIPs and no FDB entries.
func TestBuildState_GossipPopulatesInnerAndUnderlay(t *testing.T) {
	root := t.TempDir()
	p := Paths{ConfRoot: root, Netname: "vpn"}
	if err := Init(p, "alice"); err != nil {
		t.Fatal(err)
	}
	// hosts/bob with public keys only — typical post-join state.
	bobPriv, _ := keys.GenerateEd25519()
	bobWG, _ := keys.GenerateWireGuard()
	hostBody := config.Entries{
		{Key: "Ed25519PublicKey", Value: bobPriv.Public().String()},
		{Key: "WGPublicKey", Value: bobWG.Public().String()},
	}.Render()
	if err := writeHostFile(p, "bob", hostBody); err != nil {
		t.Fatal(err)
	}

	d, cancel, done := startMinimal(t, p)
	defer func() { cancel(); <-done }()

	hello := gossip.Hello{
		Name:          "bob",
		Ed25519Public: bobPriv.Public().Raw(),
		WGPublic:      bobWG.Public().String(),
		InnerAddr:     "10.42.0.2/24",
		UnderlayAddr:  "172.16.0.2/24",
	}
	if err := injectHelloAs(d, "bob", bobPriv, hello); err != nil {
		t.Fatal(err)
	}

	state := d.buildState()
	var bobPeer bool
	for _, pe := range state.Peers {
		if pe.Name != "bob" {
			continue
		}
		bobPeer = true
		if got, want := pe.InnerAddr, netip.MustParseAddr("10.42.0.2"); got != want {
			t.Errorf("peer InnerAddr = %v, want %v (gossip-learned)", got, want)
		}
		if got, want := pe.UnderlayAddr, netip.MustParseAddr("172.16.0.2"); got != want {
			t.Errorf("peer UnderlayAddr = %v, want %v (gossip-learned)", got, want)
		}
		// AllowedIPs in switch mode tracks the underlay /32.
		if len(pe.AllowedIPs) != 1 ||
			pe.AllowedIPs[0] != netip.PrefixFrom(netip.MustParseAddr("172.16.0.2"), 32) {
			t.Errorf("peer AllowedIPs = %v, want [172.16.0.2/32]", pe.AllowedIPs)
		}
	}
	if !bobPeer {
		t.Errorf("buildState did not include bob")
	}
}

// TestBuildState_HostFileFallbackForInnerAndUnderlay confirms that if no
// gossip Hello has arrived yet, hosts/<peer> entries are still honored.
// (Allows export/import-driven setups and lets reconciliation start before
// the first Hello is delivered.)
func TestBuildState_HostFileFallbackForInnerAndUnderlay(t *testing.T) {
	root := t.TempDir()
	p := Paths{ConfRoot: root, Netname: "vpn"}
	if err := Init(p, "alice"); err != nil {
		t.Fatal(err)
	}
	bobPriv, _ := keys.GenerateEd25519()
	bobWG, _ := keys.GenerateWireGuard()
	hostBody := config.Entries{
		{Key: "Ed25519PublicKey", Value: bobPriv.Public().String()},
		{Key: "WGPublicKey", Value: bobWG.Public().String()},
		{Key: "InnerAddress", Value: "10.42.0.2"},
		{Key: "UnderlayAddress", Value: "172.16.0.2"},
	}.Render()
	if err := writeHostFile(p, "bob", hostBody); err != nil {
		t.Fatal(err)
	}

	d, cancel, done := startMinimal(t, p)
	defer func() { cancel(); <-done }()
	// Bob is in the graph only after some envelope arrives; inject a minimal
	// Hello (no Inner/Underlay) so buildState iterates over him.
	if err := injectHelloAs(d, "bob", bobPriv, gossip.Hello{
		Name:          "bob",
		Ed25519Public: bobPriv.Public().Raw(),
		WGPublic:      bobWG.Public().String(),
	}); err != nil {
		t.Fatal(err)
	}

	state := d.buildState()
	var bobPeer bool
	for _, pe := range state.Peers {
		if pe.Name != "bob" {
			continue
		}
		bobPeer = true
		if got, want := pe.UnderlayAddr, netip.MustParseAddr("172.16.0.2"); got != want {
			t.Errorf("peer UnderlayAddr = %v, want %v (hosts fallback)", got, want)
		}
	}
	if !bobPeer {
		t.Errorf("buildState did not include bob")
	}
}

func writeHostFile(p Paths, name, body string) error {
	if err := mkdirAll(p.HostsDir(), 0o700); err != nil {
		return err
	}
	return writeFile(p.HostFile(name), []byte(body), 0o644)
}

// injectHelloAs constructs a signed Hello envelope as if it came from `as`,
// then feeds it into the daemon's gossip plane via Receive.
func injectHelloAs(d *Daemon, as string, asPriv keys.Ed25519Private, h gossip.Hello) error {
	body, _ := jsonMarshal(h)
	env := gossip.Envelope{
		ID:      as + "/hello",
		Origin:  as,
		Kind:    gossip.KindAddNode,
		TS:      gossip.TSNow(),
		Payload: body,
	}
	env.Signature = asPriv.Sign(env.SigningBytes())
	return d.plane.Receive(env)
}
