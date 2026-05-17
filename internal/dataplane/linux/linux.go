// Package linux is the gsnet data-plane reconciler for Linux. It uses:
//
//   - wgctrl-go to configure a WireGuard interface (peers, keys, listen port).
//   - vishvananda/netlink to create the VXLAN device on top of WireGuard and
//     to maintain its FDB (unicast head-end replication: one FDB entry per
//     remote peer mapping the broadcast MAC ff:ff:ff:ff:ff:ff to the peer's
//     inner WireGuard IP).
//
// The reconciler is idempotent: it compares the desired State to what's on
// the host and applies the diff.
//
// Build tag: linux only. The netlink and wgctrl packages also work elsewhere
// but the actual operations (link types, FDB) are Linux specific.
package linux

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/chun/gsnet/internal/dataplane"
)

// New constructs a Linux reconciler. It does not perform any privileged
// operations until Reconcile is called.
func New() (*Reconciler, error) {
	c, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wgctrl.New: %w", err)
	}
	return &Reconciler{wg: c}, nil
}

// Reconciler implements dataplane.Reconciler.
type Reconciler struct {
	wg *wgctrl.Client

	mu   sync.Mutex
	last *dataplane.State
}

// Stats returns per-peer WireGuard counters by mapping WG public keys to
// node names from the most recent Reconcile call.
func (r *Reconciler) Stats() ([]dataplane.TrafficStats, error) {
	r.mu.Lock()
	last := r.last
	r.mu.Unlock()
	if last == nil {
		return nil, nil
	}
	dev, err := r.wg.Device(last.WGInterface)
	if err != nil {
		return nil, err
	}
	nameByKey := make(map[string]string, len(last.Peers))
	for _, p := range last.Peers {
		nameByKey[p.WGPublic.String()] = p.Name
	}
	out := make([]dataplane.TrafficStats, 0, len(dev.Peers))
	for _, peer := range dev.Peers {
		name, ok := nameByKey[peer.PublicKey.String()]
		if !ok {
			name = peer.PublicKey.String()
		}
		out = append(out, dataplane.TrafficStats{
			Peer:          name,
			RxBytes:       uint64(peer.ReceiveBytes),
			TxBytes:       uint64(peer.TransmitBytes),
			LastHandshake: peer.LastHandshakeTime.UnixNano(),
		})
	}
	return out, nil
}

func (r *Reconciler) Shutdown() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.wg != nil {
		return r.wg.Close()
	}
	return nil
}

// Reconcile is the single entry point. It is idempotent and safe to call
// repeatedly. It does not delete interfaces it didn't create (caller-owned)
// but it will fully reset peers and FDB entries to match the desired state.
//
// Mode affects which kernel objects are created:
//   - ModeSwitch: WG + VXLAN + FDB with kernel MAC learning
//   - ModeHub:    WG + VXLAN + FDB but Learning=false (every frame flooded)
//   - ModeRouter: WG only; peer AllowedIPs encode the subnet routing table
func (r *Reconciler) Reconcile(s dataplane.State) error {
	if s.WGInterface == "" {
		return errors.New("dataplane: WGInterface is required")
	}
	if err := r.ensureWGInterface(s); err != nil {
		return fmt.Errorf("ensureWGInterface: %w", err)
	}
	if err := r.configureWGPeers(s); err != nil {
		return fmt.Errorf("configureWGPeers: %w", err)
	}
	if s.Mode != dataplane.ModeRouter {
		if s.VXLANInterface == "" {
			return errors.New("dataplane: VXLANInterface is required for switch/hub mode")
		}
		if !s.LocalInnerAddr.IsValid() {
			return errors.New("dataplane: LocalInnerAddr is required for switch/hub mode")
		}
		if !s.LocalUnderlayAddr.IsValid() {
			return errors.New("dataplane: LocalUnderlayAddr is required for switch/hub mode")
		}
		if err := r.ensureVXLAN(s); err != nil {
			return fmt.Errorf("ensureVXLAN: %w", err)
		}
		if err := r.reconcileFDB(s); err != nil {
			return fmt.Errorf("reconcileFDB: %w", err)
		}
	}

	r.mu.Lock()
	cp := s
	r.last = &cp
	r.mu.Unlock()
	return nil
}

func (r *Reconciler) ensureWGInterface(s dataplane.State) error {
	link, err := netlink.LinkByName(s.WGInterface)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if !errors.As(err, &notFound) {
			return err
		}
		la := netlink.NewLinkAttrs()
		la.Name = s.WGInterface
		if s.MTU > 0 {
			la.MTU = s.MTU
		}
		if err := netlink.LinkAdd(&netlink.GenericLink{LinkAttrs: la, LinkType: "wireguard"}); err != nil {
			return fmt.Errorf("LinkAdd wireguard: %w", err)
		}
		link, err = netlink.LinkByName(s.WGInterface)
		if err != nil {
			return err
		}
	}
	if s.MTU > 0 && link.Attrs().MTU != s.MTU {
		if err := netlink.LinkSetMTU(link, s.MTU); err != nil {
			return fmt.Errorf("LinkSetMTU %s: %w", s.WGInterface, err)
		}
	}
	if s.LocalUnderlayAddr.IsValid() {
		addr := &netlink.Addr{IPNet: prefixToIPNetP(s.LocalUnderlayAddr)}
		if err := netlink.AddrReplace(link, addr); err != nil {
			return fmt.Errorf("AddrReplace wg %s: %w", s.WGInterface, err)
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("LinkSetUp %s: %w", s.WGInterface, err)
	}
	return nil
}

func (r *Reconciler) configureWGPeers(s dataplane.State) error {
	// We want a single ConfigureDevice call that:
	//   - adds new peers,
	//   - updates existing peers' AllowedIPs / endpoint,
	//   - removes peers that disappeared from desired state.
	// We must NOT use ReplacePeers=true unconditionally: that removes every
	// peer first and re-adds them, which destroys the kernel WG session state
	// (handshake, replay counter) every time we reconcile. With gsnet's
	// reconcile-on-every-gossip-envelope cadence that means a fresh handshake
	// on every heartbeat — and during the handshake window data packets get
	// dropped, looking like flaky/intermittent connectivity.
	desired := make(map[wgtypes.Key]dataplane.Peer, len(s.Peers))
	for _, p := range s.Peers {
		desired[p.WGPublic] = p
	}

	peers := make([]wgtypes.PeerConfig, 0, len(s.Peers))
	for _, p := range s.Peers {
		pc := wgtypes.PeerConfig{
			PublicKey:         p.WGPublic,
			ReplaceAllowedIPs: true,
		}
		for _, allowed := range p.AllowedIPs {
			pc.AllowedIPs = append(pc.AllowedIPs, prefixToIPNet(allowed))
		}
		if p.Endpoint.IsValid() {
			pc.Endpoint = &net.UDPAddr{
				IP:   p.Endpoint.Addr().AsSlice(),
				Port: int(p.Endpoint.Port()),
			}
		}
		ka := 25 * time.Second
		pc.PersistentKeepaliveInterval = &ka
		peers = append(peers, pc)
	}

	// Generate Remove entries for any peer currently on the device that's no
	// longer in `desired`.
	if dev, err := r.wg.Device(s.WGInterface); err == nil {
		for _, existing := range dev.Peers {
			if _, keep := desired[existing.PublicKey]; keep {
				continue
			}
			peers = append(peers, wgtypes.PeerConfig{
				PublicKey: existing.PublicKey,
				Remove:    true,
			})
		}
	}

	cfg := wgtypes.Config{
		PrivateKey: &s.WGPrivate,
		ListenPort: intp(s.WGListenPort),
		Peers:      peers,
	}
	return r.wg.ConfigureDevice(s.WGInterface, cfg)
}

func (r *Reconciler) ensureVXLAN(s dataplane.State) error {
	wgLink, err := netlink.LinkByName(s.WGInterface)
	if err != nil {
		return fmt.Errorf("LinkByName %s: %w", s.WGInterface, err)
	}

	link, err := netlink.LinkByName(s.VXLANInterface)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if !errors.As(err, &notFound) {
			return err
		}
		la := netlink.NewLinkAttrs()
		la.Name = s.VXLANInterface
		la.ParentIndex = wgLink.Attrs().Index
		if s.MTU > 0 {
			la.MTU = s.MTU - 50 // VXLAN+UDP+IP overhead
		}
		// Learning is on for switch mode (kernel populates FDB on inbound
		// frames); off for hub mode where every frame should be flooded to
		// every peer. Static broadcast-MAC entries are installed in both
		// modes for head-end replication; the reconciler ignores
		// non-broadcast FDB rows so kernel-learned entries are not
		// disturbed.
		// Pin the device MAC to a deterministic value derived from our WG
		// public key. Every peer can compute it the same way, so they can
		// install matching unicast FDB entries without an extra gossip
		// round-trip (see reconcileFDB).
		la.HardwareAddr = vxlanMACFromKey(s.WGPrivate.PublicKey())
		vx := &netlink.Vxlan{
			LinkAttrs:    la,
			VxlanId:      int(s.VXLANID),
			Port:         int(s.VXLANPort),
			Learning:     s.Mode != dataplane.ModeHub,
			VtepDevIndex: wgLink.Attrs().Index,
			SrcAddr:      net.IP(s.LocalUnderlayAddr.Addr().AsSlice()),
		}
		if err := netlink.LinkAdd(vx); err != nil {
			return fmt.Errorf("LinkAdd vxlan: %w", err)
		}
		link, err = netlink.LinkByName(s.VXLANInterface)
		if err != nil {
			return err
		}
	}
	// Re-pin the MAC on existing links in case it drifted (e.g. created
	// before this code, or kernel re-randomised after a link recreate).
	wantMAC := vxlanMACFromKey(s.WGPrivate.PublicKey())
	if link.Attrs().HardwareAddr.String() != wantMAC.String() {
		if err := netlink.LinkSetHardwareAddr(link, wantMAC); err != nil {
			return fmt.Errorf("LinkSetHardwareAddr %s: %w", s.VXLANInterface, err)
		}
	}

	if s.MTU > 0 {
		want := s.MTU - 50
		if link.Attrs().MTU != want {
			if err := netlink.LinkSetMTU(link, want); err != nil {
				return fmt.Errorf("LinkSetMTU vxlan %s: %w", s.VXLANInterface, err)
			}
		}
	}
	addr := &netlink.Addr{IPNet: prefixToIPNetP(s.LocalInnerAddr)}
	if err := netlink.AddrReplace(link, addr); err != nil {
		return fmt.Errorf("AddrReplace: %w", err)
	}
	return netlink.LinkSetUp(link)
}

// fdbKey is a (MAC, underlay-IP) pair identifying a single FDB row.
type fdbKey struct {
	mac string
	ip  string
}

// reconcileFDB ensures the VXLAN FDB has, per peer, both:
//   - a head-end-replication entry (broadcast MAC → peer underlay IP), so
//     ARP requests / unknown unicast can flood to every known peer;
//   - a unicast entry (peer's deterministic VXLAN MAC → peer underlay IP),
//     so post-ARP unicast frames go directly to the right peer without
//     relying on kernel MAC learning (which we've observed to be flaky
//     for VXLAN-over-WireGuard).
//
// Both MAC families are managed by this reconciler. Other (kernel-learned
// or operator-installed) FDB rows are left alone.
func (r *Reconciler) reconcileFDB(s dataplane.State) error {
	link, err := netlink.LinkByName(s.VXLANInterface)
	if err != nil {
		return err
	}

	bcast := broadcastMAC().String()
	managedMACs := map[string]struct{}{bcast: {}}

	desired := make(map[fdbKey]struct{})
	for _, p := range s.Peers {
		// FDB destination must be the peer's WG-underlay IP (the VXLAN
		// outer destination) — not the overlay InnerAddr, which would
		// route back into the VXLAN device itself (ELOOP).
		if !p.UnderlayAddr.IsValid() {
			continue
		}
		ip := p.UnderlayAddr.String()
		desired[fdbKey{mac: bcast, ip: ip}] = struct{}{}
		peerMAC := vxlanMACFromKey(p.WGPublic)
		desired[fdbKey{mac: peerMAC.String(), ip: ip}] = struct{}{}
		managedMACs[peerMAC.String()] = struct{}{}
	}

	existing, err := netlink.NeighList(link.Attrs().Index, syscall.AF_BRIDGE)
	if err != nil {
		return fmt.Errorf("NeighList: %w", err)
	}
	have := make(map[fdbKey]struct{})
	for _, n := range existing {
		mac := n.HardwareAddr.String()
		if _, ok := managedMACs[mac]; !ok {
			continue
		}
		have[fdbKey{mac: mac, ip: n.IP.String()}] = struct{}{}
	}

	for k := range desired {
		if _, ok := have[k]; ok {
			continue
		}
		parsed, _ := netip.ParseAddr(k.ip)
		mac, _ := net.ParseMAC(k.mac)
		entry := &netlink.Neigh{
			LinkIndex:    link.Attrs().Index,
			Family:       syscall.AF_BRIDGE,
			State:        netlink.NUD_PERMANENT,
			Flags:        netlink.NTF_SELF,
			IP:           net.IP(parsed.AsSlice()),
			HardwareAddr: mac,
		}
		if err := netlink.NeighAppend(entry); err != nil {
			return fmt.Errorf("NeighAppend %s -> %s: %w", k.mac, k.ip, err)
		}
	}
	for k := range have {
		if _, ok := desired[k]; ok {
			continue
		}
		parsed, _ := netip.ParseAddr(k.ip)
		mac, _ := net.ParseMAC(k.mac)
		entry := &netlink.Neigh{
			LinkIndex:    link.Attrs().Index,
			Family:       syscall.AF_BRIDGE,
			IP:           net.IP(parsed.AsSlice()),
			HardwareAddr: mac,
		}
		if err := netlink.NeighDel(entry); err != nil {
			return fmt.Errorf("NeighDel %s -> %s: %w", k.mac, k.ip, err)
		}
	}
	return nil
}

// vxlanMACFromKey derives a deterministic MAC address from a WireGuard
// public key. The locally-administered bit is set and the multicast bit is
// cleared per IEEE 802 conventions. Two peers that know each other's
// public key (already required for WG) can therefore agree on each other's
// VXLAN MAC without needing an additional gossip envelope.
func vxlanMACFromKey(pub wgtypes.Key) net.HardwareAddr {
	h := sha256.Sum256(pub[:])
	mac := make(net.HardwareAddr, 6)
	copy(mac, h[:6])
	mac[0] = (mac[0] | 0x02) & 0xfe // set local-admin, clear multicast
	return mac
}

func broadcastMAC() net.HardwareAddr {
	return net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
}

func prefixToIPNet(p netip.Prefix) net.IPNet {
	return net.IPNet{
		IP:   net.IP(p.Addr().AsSlice()),
		Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen()),
	}
}

func addrToHostNet(a netip.Addr) *net.IPNet {
	return &net.IPNet{
		IP:   net.IP(a.AsSlice()),
		Mask: net.CIDRMask(a.BitLen(), a.BitLen()),
	}
}

func prefixToIPNetP(p netip.Prefix) *net.IPNet {
	return &net.IPNet{
		IP:   net.IP(p.Addr().AsSlice()),
		Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen()),
	}
}

func intp(v int) *int { return &v }
