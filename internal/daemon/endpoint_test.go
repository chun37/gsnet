package daemon

import (
	"net/netip"
	"strings"
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
	// The daemon installs a verifier that consults hosts/<peer>; ensure the
	// host file ed25519 matches the signing key.
	if !strings.Contains(as, "/") {
		// hosts/<as> is already in place from the test setup.
	}
	return d.plane.Receive(env)
}
