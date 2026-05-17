//go:build linux && netns

// Build with: go test -tags netns ./internal/dataplane/linux/
//
// Requires CAP_NET_ADMIN (run as root or with `sudo -E go test ...`). The
// test creates a pair of network namespaces, brings up WG+VXLAN in each, and
// verifies the FDB and WG peer setup actually applies on the kernel.
//
// The default build skips this file so unprivileged CI runs stay green.
package linux

import (
	"net/netip"
	"os"
	"runtime"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/chun/gsnet/internal/dataplane"
)

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("netns tests require CAP_NET_ADMIN (run as root)")
	}
}

func withNetns(t *testing.T, fn func()) {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	orig, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	defer orig.Close()
	ns, err := netns.New() // creates AND switches into a new netns
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = netns.Set(orig)
		_ = ns.Close()
	}()
	fn()
}

func TestReconcile_InNetNS(t *testing.T) {
	requireRoot(t)
	withNetns(t, func() {
		r, err := New()
		if err != nil {
			t.Fatal(err)
		}
		defer r.Shutdown()

		priv, _ := wgtypes.GeneratePrivateKey()
		peerPriv, _ := wgtypes.GeneratePrivateKey()
		inner := netip.MustParsePrefix("10.42.0.1/24")
		peerInner := netip.MustParseAddr("10.42.0.2")
		underlay := netip.MustParsePrefix("172.16.0.1/24")
		peerUnderlay := netip.MustParseAddr("172.16.0.2")

		state := dataplane.State{
			WGPrivate:         priv,
			WGInterface:       "wg-test",
			WGListenPort:      51820,
			VXLANInterface:    "vx-test",
			VXLANID:           42,
			VXLANPort:         4789,
			LocalInnerAddr:    inner,
			LocalUnderlayAddr: underlay,
			MTU:               1450,
			Peers: []dataplane.Peer{
				{
					Name:         "bob",
					WGPublic:     peerPriv.PublicKey(),
					InnerAddr:    peerInner,
					UnderlayAddr: peerUnderlay,
					AllowedIPs: []netip.Prefix{
						netip.PrefixFrom(peerUnderlay, peerUnderlay.BitLen()),
					},
				},
			},
		}
		if err := r.Reconcile(state); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}

		// Verify WG interface exists and has the peer.
		wgLink, err := netlink.LinkByName("wg-test")
		if err != nil {
			t.Fatalf("LinkByName(wg-test): %v", err)
		}
		if !linkIsUp(wgLink) {
			t.Errorf("wg-test is not up")
		}
		// Verify VXLAN interface exists.
		if _, err := netlink.LinkByName("vx-test"); err != nil {
			t.Errorf("LinkByName(vx-test): %v", err)
		}

		// Verify FDB has a ff:ff:ff:ff:ff:ff entry pointing at the peer's
		// underlay address (the VXLAN encap destination, not the overlay).
		vxLink, _ := netlink.LinkByName("vx-test")
		neighs, err := netlink.NeighList(vxLink.Attrs().Index, 0)
		if err != nil {
			t.Fatalf("NeighList: %v", err)
		}
		found := false
		for _, n := range neighs {
			if n.HardwareAddr.String() == "ff:ff:ff:ff:ff:ff" && n.IP.String() == peerUnderlay.String() {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("FDB missing broadcast entry for %s", peerUnderlay)
		}

		// Idempotency: Reconcile again should not error.
		if err := r.Reconcile(state); err != nil {
			t.Errorf("Reconcile (second call): %v", err)
		}
	})
}

func linkIsUp(l netlink.Link) bool {
	return l.Attrs().Flags&1 != 0 // IFF_UP
}
