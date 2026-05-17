// Package dataplane defines the gsnet data-plane interface. Implementations
// translate a declarative desired state (peers + their subnets/endpoints)
// into the actual WireGuard tunnels and VXLAN FDB entries the kernel needs.
//
// This package only defines the interface and shared types. The Linux netlink
// implementation lives in the linux subpackage; a fake implementation for
// tests lives in fake.
package dataplane

import (
	"net/netip"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Peer describes one remote node from the data-plane's point of view.
type Peer struct {
	Name         string
	WGPublic     wgtypes.Key
	Endpoint     netip.AddrPort // best-known outer endpoint; zero value = unknown
	InnerAddr    netip.Addr     // peer's overlay address (assigned to the VXLAN device on the peer)
	UnderlayAddr netip.Addr     // peer's WG-underlay address (FDB destination + WG AllowedIPs)
	AllowedIPs   []netip.Prefix // WG AllowedIPs (typically the peer's underlay address as /32 or /128)
}

// Mode determines how the data plane forwards packets.
type Mode int

const (
	// ModeSwitch (default) builds a VXLAN-on-WireGuard L2 overlay with kernel
	// MAC learning + static head-end-replication broadcast entries.
	ModeSwitch Mode = iota

	// ModeHub is like ModeSwitch but disables MAC learning, so every frame is
	// flooded to every peer (no FDB). Useful for very small networks or for
	// debugging.
	ModeHub

	// ModeRouter skips VXLAN entirely. Packets are L3 only, routed by the
	// kernel via WireGuard AllowedIPs that reflect each peer's declared
	// subnets. No L2 broadcast.
	ModeRouter
)

// State is the desired complete data-plane state. The reconciler diffs this
// against what the kernel currently has and applies the delta.
type State struct {
	// Forwarding mode.
	Mode Mode

	// Local identity
	WGPrivate wgtypes.Key

	// WireGuard interface
	WGInterface  string
	WGListenPort int

	// VXLAN interface on top of WG (ignored in ModeRouter).
	VXLANInterface string
	VXLANID        uint32
	VXLANPort      uint16
	// LocalInnerAddr is this node's address on the VXLAN overlay
	// (assigned to the VXLAN device, with mask for subnet route).
	LocalInnerAddr netip.Prefix
	// LocalUnderlayAddr is this node's WG-underlay address (assigned to
	// the WireGuard interface, used as the VXLAN encap source IP and as
	// the destination peers reach via WG AllowedIPs). Required in
	// switch/hub mode to break the VXLAN-over-WG routing loop.
	LocalUnderlayAddr netip.Prefix
	MTU               int

	// Remote peers
	Peers []Peer
}

// Reconciler applies a desired State to the host. Reconcile is idempotent.
type Reconciler interface {
	Reconcile(s State) error
	Shutdown() error
}

// TrafficStats is the per-peer cumulative byte/packet count since the peer
// was first configured. Returned by Reporter implementations.
type TrafficStats struct {
	Peer          string
	RxBytes       uint64
	TxBytes       uint64
	LastHandshake int64 // unix nanos; 0 = never
}

// Reporter is an optional interface implemented by reconcilers that expose
// runtime stats. The control plane uses it for `gsnet top`.
type Reporter interface {
	Stats() ([]TrafficStats, error)
}
