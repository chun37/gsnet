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

// reconcileFDB ensures the VXLAN FDB has exactly one "broadcast" entry per
// known remote peer (head-end replication). Any entry not in the desired set
// is removed.
func (r *Reconciler) reconcileFDB(s dataplane.State) error {
	link, err := netlink.LinkByName(s.VXLANInterface)
	if err != nil {
		return err
	}

	desired := make(map[string]struct{})
	for _, p := range s.Peers {
		// FDB destination must be the peer's WG-underlay IP (the VXLAN
		// outer destination) — not the overlay InnerAddr, which would
		// route back into the VXLAN device itself (ELOOP).
		if !p.UnderlayAddr.IsValid() {
			continue
		}
		desired[p.UnderlayAddr.String()] = struct{}{}
	}

	existing, err := netlink.NeighList(link.Attrs().Index, syscall.AF_BRIDGE)
	if err != nil {
		return fmt.Errorf("NeighList: %w", err)
	}
	have := make(map[string]struct{})
	for _, n := range existing {
		// FDB entries appear in AF_BRIDGE; filter by MAC ff:ff:ff:ff:ff:ff
		if n.HardwareAddr.String() != broadcastMAC().String() {
			continue
		}
		have[n.IP.String()] = struct{}{}
	}

	for ip := range desired {
		if _, ok := have[ip]; ok {
			continue
		}
		parsed, _ := netip.ParseAddr(ip)
		entry := &netlink.Neigh{
			LinkIndex:    link.Attrs().Index,
			Family:       syscall.AF_BRIDGE,
			State:        netlink.NUD_PERMANENT,
			Flags:        netlink.NTF_SELF,
			IP:           net.IP(parsed.AsSlice()),
			HardwareAddr: broadcastMAC(),
		}
		if err := netlink.NeighAppend(entry); err != nil {
			return fmt.Errorf("NeighAppend %s: %w", ip, err)
		}
	}
	for ip := range have {
		if _, ok := desired[ip]; ok {
			continue
		}
		parsed, _ := netip.ParseAddr(ip)
		entry := &netlink.Neigh{
			LinkIndex:    link.Attrs().Index,
			Family:       syscall.AF_BRIDGE,
			IP:           net.IP(parsed.AsSlice()),
			HardwareAddr: broadcastMAC(),
		}
		if err := netlink.NeighDel(entry); err != nil {
			return fmt.Errorf("NeighDel %s: %w", ip, err)
		}
	}
	return nil
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
