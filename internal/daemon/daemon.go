package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/chun/gsnet/internal/config"
	"github.com/chun/gsnet/internal/control"
	"github.com/chun/gsnet/internal/dataplane"
	"github.com/chun/gsnet/internal/gossip"
	"github.com/chun/gsnet/internal/graph"
	"github.com/chun/gsnet/internal/invite"
	"github.com/chun/gsnet/internal/keys"
	"github.com/chun/gsnet/internal/sandbox"
	"github.com/chun/gsnet/internal/script"
	"github.com/chun/gsnet/internal/subnet"
	"github.com/chun/gsnet/internal/transport"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Daemon orchestrates the gsnet runtime: config reload, gossip plane,
// data-plane reconciliation, control socket, and hook scripts.
type Daemon struct {
	Paths      Paths
	RunDir     string
	Reconciler dataplane.Reconciler

	// GossipAddr is the TCP address the daemon listens on for gossip + invite.
	// Use ":0" to bind a random port (test only); default is ":51820".
	GossipAddr string

	// Logger is optional; defaults to stderr.
	Logger *log.Logger

	// Loaded at startup / reload.
	mu     sync.RWMutex
	loaded loaded

	g        *graph.Graph
	plane    *gossip.Plane
	tport    *transport.Server
	endpoint endpointStore
}

type loaded struct {
	NodeName string
	Conf     config.Entries

	EdPriv keys.Ed25519Private
	WGPriv keys.WGPrivate

	Mode         dataplane.Mode
	WGInterface  string
	WGListenPort int
	VXLANIface   string
	VXLANID      uint32
	VXLANPort    uint16
	MTU          int
	InnerAddr    netip.Addr

	Subnets []subnet.Subnet
}

func (d *Daemon) logger() *log.Logger {
	if d.Logger != nil {
		return d.Logger
	}
	return log.New(os.Stderr, "gsnet: ", log.LstdFlags)
}

// Run blocks until ctx is canceled or a fatal error occurs.
func (d *Daemon) Run(ctx context.Context) error {
	if err := d.load(); err != nil {
		return fmt.Errorf("initial load: %w", err)
	}
	d.g = graph.New()

	d.tport = &transport.Server{
		Addr:       d.gossipAddr(),
		EdPriv:     d.loaded.EdPriv,
		InviteGet:  d.handleInviteGet,
		InviteJoin: d.handleInviteJoin,
	}
	d.tport.SetLogger(d.logger().Printf)
	if err := d.tport.Start(); err != nil {
		return fmt.Errorf("transport listen: %w", err)
	}

	d.plane = gossip.NewPlane(d.loaded.NodeName, d.g, d.tport)
	d.plane.SetSigner(d.loaded.EdPriv)
	d.plane.SetVerifier(d.lookupPubKey)
	d.plane.OnMessage(func(_ gossip.Envelope) {
		if err := d.applyReconcile(); err != nil {
			d.logger().Printf("reconcile: %v", err)
		}
	})
	d.tport.OnGossip = func(env gossip.Envelope) {
		if err := d.plane.Receive(env); err != nil {
			d.logger().Printf("plane.Receive: %v", err)
		}
	}

	if err := d.announceLocal(); err != nil {
		return err
	}
	if err := d.applyReconcile(); err != nil {
		d.logger().Printf("initial reconcile: %v", err)
	}
	if err := d.runUp(ctx); err != nil {
		d.logger().Printf("tinc-up: %v", err)
	}

	cookie, err := control.NewCookie()
	if err != nil {
		return err
	}
	pidPath := d.Paths.PIDFile(d.RunDir)
	pid := control.PIDFile{PID: os.Getpid(), Cookie: cookie}
	if err := os.WriteFile(pidPath, []byte(pid.Encode()), 0o600); err != nil {
		return err
	}
	defer os.Remove(pidPath)

	srv := &control.Server{
		NodeName: d.loaded.NodeName,
		Cookie:   cookie,
		Handler:  d.controlHandler(),
	}
	sockPath := d.Paths.ControlSocket(d.RunDir)
	if err := srv.Listen(sockPath); err != nil {
		return err
	}
	defer os.Remove(sockPath)

	subCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Drop privileges before entering the long-running loop. Reconcile and
	// listener creation are already done by this point.
	if err := d.applySandbox(); err != nil {
		return fmt.Errorf("sandbox: %w", err)
	}

	go d.signalLoop(subCtx)
	go d.plane.Run(subCtx)
	go d.tport.Serve(subCtx)
	go d.dialConnectTo(subCtx)
	go d.heartbeat(subCtx)
	go d.runDiscovery(subCtx)

	err = srv.Serve(subCtx)
	_ = d.tport.Close()
	if rdErr := d.runDown(); rdErr != nil {
		d.logger().Printf("tinc-down: %v", rdErr)
	}
	if shErr := d.Reconciler.Shutdown(); shErr != nil {
		d.logger().Printf("reconciler shutdown: %v", shErr)
	}
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func (d *Daemon) gossipAddr() string {
	if d.GossipAddr != "" {
		return d.GossipAddr
	}
	return ":51820"
}

// LocalGossipAddr exposes the bound listener address (used by tests with ":0").
func (d *Daemon) LocalGossipAddr() string {
	if d.tport == nil || d.tport.LocalAddr() == nil {
		return ""
	}
	return d.tport.LocalAddr().String()
}

func (d *Daemon) load() error {
	entries, err := config.LoadDirectory(d.Paths.ConfFile())
	if err != nil {
		return err
	}
	l := loaded{Conf: entries}

	name, ok := entries.GetFirst("Name")
	if !ok {
		return errors.New("config: Name is required")
	}
	l.NodeName = name

	edBytes, err := os.ReadFile(d.Paths.Ed25519Private())
	if err != nil {
		return fmt.Errorf("read ed25519 private key: %w", err)
	}
	l.EdPriv, err = keys.ParseEd25519PrivatePEM(edBytes)
	if err != nil {
		return err
	}
	wgBytes, err := os.ReadFile(d.Paths.WGPrivate())
	if err != nil {
		return fmt.Errorf("read wg private key: %w", err)
	}
	l.WGPriv, err = keys.ParseWireGuardPrivate(strings.TrimSpace(string(wgBytes)))
	if err != nil {
		return err
	}

	if v, ok := entries.GetFirst("Mode"); ok {
		switch strings.ToLower(v) {
		case "switch", "":
			l.Mode = dataplane.ModeSwitch
		case "hub":
			l.Mode = dataplane.ModeHub
		case "router":
			l.Mode = dataplane.ModeRouter
		default:
			return fmt.Errorf("unknown Mode %q (want switch, hub, router)", v)
		}
	}

	l.WGInterface = firstNonEmpty(entries, "WGInterface", "Interface", "wg-"+l.NodeName)
	l.VXLANIface = firstNonEmpty(entries, "VXLANInterface", "VXLAN", l.NodeName)
	if v, ok := entries.GetFirst("Port"); ok {
		if p, err := strconv.Atoi(v); err == nil {
			l.WGListenPort = p
		}
	}
	if l.WGListenPort == 0 {
		l.WGListenPort = 51820
	}
	l.VXLANPort = 4789
	if v, ok := entries.GetFirst("VXLANPort"); ok {
		if p, err := strconv.Atoi(v); err == nil {
			l.VXLANPort = uint16(p)
		}
	}
	l.VXLANID = 42
	if v, ok := entries.GetFirst("VXLANID"); ok {
		if p, err := strconv.Atoi(v); err == nil {
			l.VXLANID = uint32(p)
		}
	}
	l.MTU = 1450

	if v, ok := entries.GetFirst("InnerAddress"); ok {
		a, err := netip.ParseAddr(v)
		if err != nil {
			return fmt.Errorf("InnerAddress %q: %w", v, err)
		}
		l.InnerAddr = a
	}

	for _, s := range entries.GetAll("Subnet") {
		sub, err := subnet.Parse(s)
		if err != nil {
			return fmt.Errorf("Subnet %q: %w", s, err)
		}
		l.Subnets = append(l.Subnets, sub)
	}

	d.mu.Lock()
	d.loaded = l
	d.mu.Unlock()
	return nil
}

func firstNonEmpty(entries config.Entries, keys ...string) string {
	for _, k := range keys[:len(keys)-1] {
		if v, ok := entries.GetFirst(k); ok && v != "" {
			return v
		}
	}
	return keys[len(keys)-1]
}

func (d *Daemon) snapshot() loaded {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.loaded
}

func (d *Daemon) announceLocal() error {
	l := d.snapshot()
	hello := gossip.Hello{
		Name:          l.NodeName,
		Ed25519Public: l.EdPriv.Public().Raw(),
		WGPublic:      l.WGPriv.Public().String(),
	}
	if ep := d.endpoint.Get(); ep.IsValid() {
		hello.Endpoint = ep.String()
	}
	if err := d.plane.AnnounceHello(hello); err != nil {
		return err
	}
	for _, s := range l.Subnets {
		if err := d.plane.AnnounceAddSubnet(s.String()); err != nil {
			return err
		}
	}
	return nil
}

func (d *Daemon) applyReconcile() error {
	if d.Reconciler == nil {
		return nil
	}
	state := d.buildState()
	return d.Reconciler.Reconcile(state)
}

func (d *Daemon) buildState() dataplane.State {
	l := d.snapshot()
	state := dataplane.State{
		Mode:           l.Mode,
		WGPrivate:      l.WGPriv.WGKey(),
		WGInterface:    l.WGInterface,
		WGListenPort:   l.WGListenPort,
		VXLANInterface: l.VXLANIface,
		VXLANID:        l.VXLANID,
		VXLANPort:      l.VXLANPort,
		LocalInnerAddr: l.InnerAddr,
		MTU:            l.MTU,
	}
	for _, peer := range d.g.Nodes() {
		if peer == l.NodeName {
			continue
		}
		hostEntries, err := config.ParseFile(d.Paths.HostFile(peer))
		if err != nil {
			continue
		}
		pubStr, ok := hostEntries.GetFirst("WGPublicKey")
		if !ok {
			continue
		}
		wgPub, err := wgtypes.ParseKey(pubStr)
		if err != nil {
			continue
		}
		// Endpoint precedence: gossip-learned (NAT-discovered) > hosts/<peer> Address.
		var ep netip.AddrPort
		if learned := d.plane.EndpointOf(peer); learned != "" {
			if parsed, err := netip.ParseAddrPort(learned); err == nil {
				ep = parsed
			}
		}
		if !ep.IsValid() {
			if a, ok := hostEntries.GetFirst("Address"); ok {
				port := l.WGListenPort
				if p, ok := hostEntries.GetFirst("Port"); ok {
					if pi, err := strconv.Atoi(p); err == nil {
						port = pi
					}
				}
				if addrParsed, err := netip.ParseAddr(a); err == nil {
					ep = netip.AddrPortFrom(addrParsed, uint16(port))
				}
			}
		}
		var inner netip.Addr
		if v, ok := hostEntries.GetFirst("InnerAddress"); ok {
			if parsed, err := netip.ParseAddr(v); err == nil {
				inner = parsed
			}
		}
		allowed := d.allowedIPsFor(l.Mode, peer, inner)
		state.Peers = append(state.Peers, dataplane.Peer{
			Name:       peer,
			WGPublic:   wgPub,
			Endpoint:   ep,
			InnerAddr:  inner,
			AllowedIPs: allowed,
		})
	}
	return state
}

// allowedIPsFor returns the AllowedIPs to install on a WireGuard peer entry.
// In switch/hub mode this is just the peer's inner VXLAN address; in router
// mode it expands to all subnets the peer owns in the gossip graph (so the
// kernel will route their traffic to this WG peer).
func (d *Daemon) allowedIPsFor(mode dataplane.Mode, peer string, inner netip.Addr) []netip.Prefix {
	if mode != dataplane.ModeRouter {
		if inner.IsValid() {
			return []netip.Prefix{netip.PrefixFrom(inner, inner.BitLen())}
		}
		return nil
	}
	var out []netip.Prefix
	for _, s := range d.g.NodeSubnets(peer) {
		sub, err := subnet.Parse(s)
		if err != nil || sub.MAC != nil {
			continue
		}
		out = append(out, sub.Prefix)
	}
	return out
}

func (d *Daemon) signalLoop(ctx context.Context) {
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, syscall.SIGHUP, syscall.SIGALRM)
	defer signal.Stop(sigs)
	for {
		select {
		case <-ctx.Done():
			return
		case sig := <-sigs:
			switch sig {
			case syscall.SIGHUP:
				if err := d.load(); err != nil {
					d.logger().Printf("reload: %v", err)
				} else {
					_ = d.announceLocal()
					d.logger().Printf("reloaded config")
				}
				_ = d.applyReconcile()
			case syscall.SIGALRM:
				_ = d.applyReconcile()
			}
		}
	}
}

func (d *Daemon) controlHandler() control.Handler {
	return control.HandlerFunc(func(_ context.Context, m control.Message, w io.Writer) error {
		switch m.Type {
		case control.ReqStop:
			fmt.Fprintf(w, "%d %d 0\n", control.ClassRequest, m.Type)
			os.Exit(0)
		case control.ReqReload:
			if err := d.load(); err != nil {
				fmt.Fprintf(w, "%d %d %s\n", control.ClassRequest, m.Type, err)
				return nil
			}
			if err := d.announceLocal(); err != nil {
				fmt.Fprintf(w, "%d %d %s\n", control.ClassRequest, m.Type, err)
				return nil
			}
			_ = d.applyReconcile()
			fmt.Fprintf(w, "%d %d 0\n", control.ClassRequest, m.Type)
		case control.ReqDumpNodes:
			for _, n := range d.g.Nodes() {
				fmt.Fprintf(w, "%d %d %s\n", control.ClassRequest, m.Type, n)
			}
			fmt.Fprintf(w, "%d %d\n", control.ClassRequest, m.Type)
		case control.ReqDumpEdges:
			for _, e := range d.g.Edges() {
				fmt.Fprintf(w, "%d %d %s %s %d\n", control.ClassRequest, m.Type, e.From, e.To, e.Weight)
			}
			fmt.Fprintf(w, "%d %d\n", control.ClassRequest, m.Type)
		case control.ReqDumpSubnets:
			for s, owner := range d.g.AllSubnets() {
				fmt.Fprintf(w, "%d %d %s %s\n", control.ClassRequest, m.Type, s, owner)
			}
			fmt.Fprintf(w, "%d %d\n", control.ClassRequest, m.Type)
		case control.ReqDumpTraffic:
			if rep, ok := d.Reconciler.(dataplane.Reporter); ok {
				stats, err := rep.Stats()
				if err == nil {
					for _, st := range stats {
						fmt.Fprintf(w, "%d %d %s %d %d %d\n",
							control.ClassRequest, m.Type,
							st.Peer, st.RxBytes, st.TxBytes, st.LastHandshake)
					}
				}
			}
			fmt.Fprintf(w, "%d %d\n", control.ClassRequest, m.Type)
		case control.ReqPurge:
			// Simplistic: drop unreachable nodes.
			reach := d.g.Reachable(d.snapshot().NodeName)
			for _, n := range d.g.Nodes() {
				if _, ok := reach[n]; !ok {
					// We don't currently have a "remove node" graph op; settle for clearing edges.
					for _, e := range d.g.Edges() {
						if e.From == n || e.To == n {
							d.g.DelEdge(e.From, e.To)
						}
					}
				}
			}
			fmt.Fprintf(w, "%d %d 0\n", control.ClassRequest, m.Type)
		default:
			fmt.Fprintf(w, "%d %d 0\n", control.ClassRequest, m.Type)
		}
		return nil
	})
}

// lookupPubKey resolves a peer's Ed25519 public key from hosts/<name>.
// Used by gossip.Plane to verify incoming envelopes.
func (d *Daemon) lookupPubKey(name string) (keys.Ed25519Public, bool) {
	if name == d.snapshot().NodeName {
		return d.snapshot().EdPriv.Public(), true
	}
	entries, err := config.ParseFile(d.Paths.HostFile(name))
	if err != nil {
		return keys.Ed25519Public{}, false
	}
	v, ok := entries.GetFirst("Ed25519PublicKey")
	if !ok {
		return keys.Ed25519Public{}, false
	}
	pub, err := keys.ParseEd25519PublicBase64(strings.TrimSpace(v))
	if err != nil {
		return keys.Ed25519Public{}, false
	}
	return pub, true
}

// dialConnectTo runs at startup and re-connects to all peers listed under
// ConnectTo whenever the link drops. Backoff is fixed at 5 seconds for now.
func (d *Daemon) dialConnectTo(ctx context.Context) {
	l := d.snapshot()
	peers := l.Conf.GetAll("ConnectTo")
	for _, peer := range peers {
		go d.maintainPeer(ctx, peer)
	}
}

func (d *Daemon) maintainPeer(ctx context.Context, peerName string) {
	backoff := 500 * time.Millisecond
	const maxBackoff = 30 * time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		ok := d.tryDialPeer(ctx, peerName)
		var wait time.Duration
		if ok {
			wait = maxBackoff
		} else {
			wait = backoff
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func (d *Daemon) tryDialPeer(ctx context.Context, peerName string) bool {
	entries, err := config.ParseFile(d.Paths.HostFile(peerName))
	if err != nil {
		return false
	}
	addr, ok := entries.GetFirst("Address")
	if !ok {
		return false
	}
	port := d.snapshot().WGListenPort
	if v, ok := entries.GetFirst("Port"); ok {
		if p, err := strconv.Atoi(v); err == nil {
			port = p
		}
	}
	target := fmt.Sprintf("%s:%d", addr, port)
	if err := d.tport.Dial(ctx, target); err != nil {
		d.logger().Printf("Dial %s (%s): %v", peerName, target, err)
		return false
	}
	d.logger().Printf("Connected to %s (%s)", peerName, target)
	_ = d.announceLocal()
	return true
}

// handleInviteGet reads invitations/<cookie> and returns it.
func (d *Daemon) handleInviteGet(cookie string) ([]byte, error) {
	path := filepath.Join(d.Paths.InvitationsDir(), cookie)
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("unknown invitation")
	}
	return body, nil
}

// handleInviteJoin consumes the cookie (single-use) and writes hosts/<name>
// from the body the invitee sent, then returns the invitation file.
func (d *Daemon) handleInviteJoin(cookie, inviteeName string, hostConfig []byte) ([]byte, error) {
	path := filepath.Join(d.Paths.InvitationsDir(), cookie)
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("unknown invitation")
	}
	// Verify the invitee name matches the invitation's first block.
	parsed, err := invite.ParseFile(strings.NewReader(string(file)))
	if err != nil {
		return nil, fmt.Errorf("corrupt invitation: %w", err)
	}
	if parsed.Invitee.Name != inviteeName {
		return nil, fmt.Errorf("invitee name mismatch: invitation expects %q", parsed.Invitee.Name)
	}
	if err := os.MkdirAll(d.Paths.HostsDir(), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(d.Paths.HostFile(inviteeName), hostConfig, 0o644); err != nil {
		return nil, err
	}
	_ = os.Remove(path) // single-use invitation
	// Tell the gossip plane about the newly-known peer's pubkey.
	es, err := config.Parse(strings.NewReader(string(hostConfig)))
	if err == nil {
		if pubStr, ok := es.GetFirst("Ed25519PublicKey"); ok {
			if pub, err := keys.ParseEd25519PublicBase64(strings.TrimSpace(pubStr)); err == nil {
				_ = pub
				d.plane.AnnounceHello(gossip.Hello{
					Name:          inviteeName,
					Ed25519Public: pub.Raw(),
				})
			}
		}
	}
	return file, nil
}

// heartbeat re-broadcasts the local outbox at a fixed interval so that
// peers eventually receive any state they may have missed. Because the
// outbox keeps the original envelopes with stable IDs, this is cheap on the
// receivers (their dedup-by-TS catches all but actual updates).
func (d *Daemon) applySandbox() error {
	l := d.snapshot()
	levelStr, _ := l.Conf.GetFirst("Sandbox")
	level, err := sandbox.ParseLevel(strings.ToLower(levelStr))
	if err != nil {
		return err
	}
	user, _ := l.Conf.GetFirst("User")
	return sandbox.Apply(sandbox.Options{
		Level:      level,
		User:       user,
		ConfDir:    d.Paths.NetDir(),
		WritePaths: []string{d.RunDir, d.Paths.InvitationsDir()},
	})
}

func (d *Daemon) heartbeat(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = d.plane.ResendOutbox()
		}
	}
}

func (d *Daemon) runUp(ctx context.Context) error {
	r := &script.Runner{ConfDir: d.Paths.NetDir()}
	return r.Run(ctx, "tinc-up", d.scriptEnv())
}

func (d *Daemon) runDown() error {
	r := &script.Runner{ConfDir: d.Paths.NetDir()}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return r.Run(ctx, "tinc-down", d.scriptEnv())
}

func (d *Daemon) scriptEnv() script.Env {
	l := d.snapshot()
	return script.Env{
		Netname:   d.Paths.Netname,
		Name:      l.NodeName,
		Device:    l.VXLANIface,
		Interface: l.VXLANIface,
	}
}
