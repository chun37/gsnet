package daemon

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/chun/gsnet/internal/stun"
	"github.com/chun/gsnet/internal/upnp"
)

// endpointStore holds the most recently discovered public endpoint for this
// node. It is updated by the discovery loop and read by announceLocal so the
// next Hello includes it.
type endpointStore struct {
	mu sync.Mutex
	ap netip.AddrPort
}

func (e *endpointStore) Get() netip.AddrPort {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.ap
}

func (e *endpointStore) Set(ap netip.AddrPort) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.ap == ap {
		return false
	}
	e.ap = ap
	return true
}

// runDiscovery is the daemon's NAT discovery loop. It probes STUN and/or
// UPnP-IGD based on config and pushes any new endpoint into endpointStore.
// On each change it triggers a Hello re-announce so peers learn the new
// endpoint without waiting for the heartbeat.
//
// Both probes are best-effort: failures are logged and retried at the
// configured refresh interval. The loop exits when ctx is canceled.
func (d *Daemon) runDiscovery(ctx context.Context) {
	l := d.snapshot()
	stunServers := l.Conf.GetAll("STUN")
	upnpRaw, _ := l.Conf.GetFirst("UPnP")
	upnpMode := strings.ToLower(upnpRaw)
	if upnpMode == "" {
		upnpMode = "no"
	}
	refresh := 60 * time.Second
	if v, ok := l.Conf.GetFirst("UPnPRefreshPeriod"); ok {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			refresh = time.Duration(n) * time.Second
		}
	}
	if len(stunServers) == 0 && upnpMode == "no" {
		return // nothing to do
	}

	var igd *upnp.IGD
	// First sweep is immediate; subsequent ones throttled.
	ticker := time.NewTicker(refresh)
	defer ticker.Stop()
	for {
		newEP := d.discoverOnce(ctx, stunServers, upnpMode, &igd)
		if newEP.IsValid() && d.endpoint.Set(newEP) {
			d.logger().Printf("discovered endpoint %s", newEP)
			_ = d.announceLocal()
		}
		select {
		case <-ctx.Done():
			// Best-effort: tear down the UPnP mapping on exit.
			if igd != nil {
				cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				_ = igd.DeletePortMapping(cleanupCtx, "UDP", l.WGListenPort)
				cancel()
			}
			return
		case <-ticker.C:
		}
	}
}

func (d *Daemon) discoverOnce(ctx context.Context, stunServers []string, upnpMode string, igd **upnp.IGD) netip.AddrPort {
	l := d.snapshot()
	port := uint16(l.WGListenPort)

	// UPnP first — it yields both IP and port (matches WG listen port).
	if upnpMode == "yes" || upnpMode == "udponly" {
		ep := d.refreshUPnP(ctx, igd, int(port))
		if ep.IsValid() {
			return ep
		}
	}

	// STUN fallback — yields IP only. Combine with our local WG listen port.
	for _, srv := range stunServers {
		ap, err := stun.QueryOnEphemeralPort(srv, 3*time.Second)
		if err != nil {
			d.logger().Printf("STUN %s: %v", srv, err)
			continue
		}
		return netip.AddrPortFrom(ap.Addr(), port)
	}
	return netip.AddrPort{}
}

func (d *Daemon) refreshUPnP(ctx context.Context, igd **upnp.IGD, wgPort int) netip.AddrPort {
	if *igd == nil {
		dctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		g, err := upnp.Discover(dctx, 3*time.Second)
		if err != nil {
			d.logger().Printf("UPnP discover: %v", err)
			return netip.AddrPort{}
		}
		*igd = g
	}
	addCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := (*igd).AddPortMapping(addCtx, "UDP", wgPort, wgPort, "gsnet", 3600); err != nil {
		d.logger().Printf("UPnP AddPortMapping: %v", err)
		*igd = nil // force re-discovery next round
		return netip.AddrPort{}
	}
	// The mapping installs externalPort==wgPort. The external IP comes from
	// the IGD's WAN address. UPnP exposes that via GetExternalIPAddress; we
	// short-circuit by reusing the IGD's WAN-side IP if reachable, or by
	// asking STUN if available. As a fallback, return zero — caller will
	// then try STUN.
	if ext, err := getExternalIP(ctx, *igd); err == nil && ext.IsValid() {
		return netip.AddrPortFrom(ext, uint16(wgPort))
	}
	return netip.AddrPort{}
}

// getExternalIP queries the IGD for its WAN-side address via the
// GetExternalIPAddress action. Not all routers respond; callers must handle
// errors gracefully.
func getExternalIP(ctx context.Context, igd *upnp.IGD) (netip.Addr, error) {
	ip, err := igd.GetExternalIPAddress(ctx)
	if err != nil {
		return netip.Addr{}, err
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("upnp: bad external IP %q: %w", ip, err)
	}
	return addr, nil
}
