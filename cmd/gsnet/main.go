// gsnet is the gsnet VPN control CLI.
//
// Usage:
//
//	gsnet [-n NETNAME] [-c CONFDIR] [-r RUNDIR] COMMAND [args...]
//
// Commands implemented:
//
//	init <name>         create config + keypairs
//	get  <key>          read a config variable
//	set  <key> <value>  set a config variable
//	add  <key> <value>  add a config variable (keeps duplicates)
//	del  <key> [value]  remove config variable(s)
//	dump nodes          list reachable nodes (via control socket)
//	dump edges          list edges
//	dump subnets        list subnets
//	export              print local host config
//	import              read host config from stdin and store under hosts/<name>
//	stop                stop the running daemon
//	reload              reload the daemon's configuration
//	purge               purge unreachable nodes
//	pid                 show daemon PID
//	invite <name>       prepare an invitation (writes to invitations/ and prints URL)
//	join <url>          join a VPN using an invitation URL
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/chun/gsnet/internal/config"
	"github.com/chun/gsnet/internal/control"
	"github.com/chun/gsnet/internal/daemon"
	"github.com/chun/gsnet/internal/invite"
	"github.com/chun/gsnet/internal/keys"
	"github.com/chun/gsnet/internal/nodename"
	gpcap "github.com/chun/gsnet/internal/pcap"
	"github.com/chun/gsnet/internal/transport"
)

func main() {
	var (
		netname = flag.String("n", "", "network name")
		conf    = flag.String("c", "/etc/gsnet", "config root directory")
		runDir  = flag.String("r", "/run", "runtime directory")
		batch   = flag.Bool("b", false, "non-interactive mode")
	)
	flag.Parse()
	_ = batch

	paths := daemon.Paths{ConfRoot: *conf, Netname: *netname}
	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(2)
	}

	cmd, rest := args[0], args[1:]
	if err := dispatch(cmd, rest, paths, *runDir); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func dispatch(cmd string, args []string, paths daemon.Paths, runDir string) error {
	switch cmd {
	case "init":
		return cmdInit(paths, args)
	case "get":
		return cmdGet(paths, args)
	case "set":
		return cmdSet(paths, args)
	case "add":
		return cmdAdd(paths, args)
	case "del":
		return cmdDel(paths, args)
	case "export":
		return cmdExport(paths)
	case "import":
		return cmdImport(paths, os.Stdin)
	case "invite":
		return cmdInvite(paths, args)
	case "join":
		return cmdJoin(paths, args)
	case "dump":
		return cmdDump(paths, runDir, args)
	case "fsck":
		return cmdFsck(paths)
	case "pcap":
		return cmdPcap(paths, args)
	case "top":
		return cmdTop(paths, runDir, args)
	case "stop", "reload", "retry", "purge", "pid":
		return cmdSimple(paths, runDir, cmd, args)
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func cmdTop(p daemon.Paths, runDir string, args []string) error {
	interval := 1 * time.Second
	once := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-i":
			if i+1 >= len(args) {
				return fmt.Errorf("top: -i needs seconds")
			}
			i++
			s, err := strconv.ParseFloat(args[i], 64)
			if err != nil {
				return err
			}
			interval = time.Duration(s * float64(time.Second))
		case "--once":
			once = true
		default:
			return fmt.Errorf("top: unknown arg %q", args[i])
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sigs; cancel() }()

	for {
		cl, err := dialControl(p, runDir)
		if err != nil {
			return err
		}
		if !once {
			fmt.Print("\x1b[2J\x1b[H") // clear + home
		}
		fmt.Printf("%-20s %12s %12s %s\n", "PEER", "RX_BYTES", "TX_BYTES", "LAST_HANDSHAKE")
		first, err := cl.Send(control.ReqDumpTraffic)
		if err != nil {
			cl.Close()
			return err
		}
		terminator := fmt.Sprintf("%d %d", control.ClassRequest, control.ReqDumpTraffic)
		line := strings.TrimRight(first, "\r\n")
		for {
			if line == terminator {
				break
			}
			// "18 13 <peer> <rx> <tx> <hs>"
			fields := strings.Fields(line)
			if len(fields) >= 6 {
				peer := fields[2]
				rx := fields[3]
				tx := fields[4]
				hs := fields[5]
				fmt.Printf("%-20s %12s %12s %s\n", peer, rx, tx, formatHandshake(hs))
			}
			next, err := cl.ReadLine()
			if err != nil {
				cl.Close()
				return err
			}
			line = strings.TrimRight(next, "\r\n")
		}
		cl.Close()
		if once {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(interval):
		}
	}
}

func formatHandshake(nanos string) string {
	if nanos == "0" || nanos == "" {
		return "never"
	}
	n, err := strconv.ParseInt(nanos, 10, 64)
	if err != nil || n == 0 {
		return "never"
	}
	age := time.Since(time.Unix(0, n)).Round(time.Second)
	return fmt.Sprintf("%s ago", age)
}

func cmdPcap(p daemon.Paths, args []string) error {
	snaplen := uint32(65535)
	iface := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-s":
			if i+1 >= len(args) {
				return fmt.Errorf("pcap: -s needs a value")
			}
			i++
			n, err := strconv.ParseUint(args[i], 10, 32)
			if err != nil {
				return err
			}
			snaplen = uint32(n)
		case "-i":
			if i+1 >= len(args) {
				return fmt.Errorf("pcap: -i needs an interface")
			}
			i++
			iface = args[i]
		default:
			return fmt.Errorf("pcap: unknown arg %q", args[i])
		}
	}
	if iface == "" {
		// Default to the VXLAN interface configured for this netname.
		entries, err := config.LoadDirectory(p.ConfFile())
		if err != nil {
			return err
		}
		if v, ok := entries.GetFirst("VXLANInterface"); ok {
			iface = v
		} else if v, ok := entries.GetFirst("Interface"); ok {
			iface = v
		} else if v, ok := entries.GetFirst("Name"); ok {
			iface = v
		}
	}
	if iface == "" {
		return fmt.Errorf("pcap: no interface; use -i")
	}
	ctx, cancel := context.WithCancel(context.Background())
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sigs; cancel() }()
	return gpcap.Capture(ctx, iface, snaplen, os.Stdout)
}

func cmdFsck(p daemon.Paths) error {
	findings := daemon.Fsck(p)
	errors := 0
	for _, f := range findings {
		fmt.Println(f.String())
		if f.Level == daemon.FsckError {
			errors++
		}
	}
	if errors > 0 {
		return fmt.Errorf("%d error(s)", errors)
	}
	return nil
}

func cmdInit(p daemon.Paths, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("init <name>")
	}
	return daemon.Init(p, args[0])
}

func cmdGet(p daemon.Paths, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("get <key>")
	}
	entries, err := config.LoadDirectory(p.ConfFile())
	if err != nil {
		return err
	}
	for _, v := range entries.GetAll(args[0]) {
		fmt.Println(v)
	}
	return nil
}

func cmdSet(p daemon.Paths, args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("set <key> <value>")
	}
	return mutateConf(p, args[0], args[1], true)
}

func cmdAdd(p daemon.Paths, args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("add <key> <value>")
	}
	return mutateConf(p, args[0], args[1], false)
}

func cmdDel(p daemon.Paths, args []string) error {
	if len(args) < 1 || len(args) > 2 {
		return fmt.Errorf("del <key> [value]")
	}
	key := args[0]
	var value string
	if len(args) == 2 {
		value = args[1]
	}
	entries, err := config.ParseFile(p.ConfFile())
	if err != nil {
		return err
	}
	var kept config.Entries
	for _, e := range entries {
		if strings.EqualFold(e.Key, key) {
			if value == "" || e.Value == value {
				continue
			}
		}
		kept = append(kept, e)
	}
	return os.WriteFile(p.ConfFile(), []byte(kept.Render()), 0o644)
}

func mutateConf(p daemon.Paths, key, value string, replace bool) error {
	entries, err := config.ParseFile(p.ConfFile())
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if replace {
		var kept config.Entries
		for _, e := range entries {
			if strings.EqualFold(e.Key, key) {
				continue
			}
			kept = append(kept, e)
		}
		entries = kept
	}
	entries = append(entries, config.Entry{Key: key, Value: value})
	return os.WriteFile(p.ConfFile(), []byte(entries.Render()), 0o644)
}

func cmdExport(p daemon.Paths) error {
	entries, err := config.LoadDirectory(p.ConfFile())
	if err != nil {
		return err
	}
	name, ok := entries.GetFirst("Name")
	if !ok {
		return fmt.Errorf("Name not set in %s", p.ConfFile())
	}
	host, err := os.ReadFile(p.HostFile(name))
	if err != nil {
		return err
	}
	fmt.Printf("Name = %s\n%s", name, host)
	return nil
}

func cmdImport(p daemon.Paths, r io.Reader) error {
	br := bufio.NewReader(r)
	var name string
	var lines []string
	for {
		line, err := br.ReadString('\n')
		if line != "" {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
				if k, v, ok := strings.Cut(trimmed, "="); ok && strings.EqualFold(strings.TrimSpace(k), "Name") {
					if name != "" {
						if err := writeHost(p, name, lines); err != nil {
							return err
						}
						lines = nil
					}
					name = strings.TrimSpace(v)
					continue
				}
			}
			lines = append(lines, line)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	if name != "" {
		return writeHost(p, name, lines)
	}
	return nil
}

func writeHost(p daemon.Paths, name string, lines []string) error {
	if err := os.MkdirAll(p.HostsDir(), 0o700); err != nil {
		return err
	}
	return os.WriteFile(p.HostFile(name), []byte(strings.Join(lines, "")), 0o644)
}

func cmdInvite(p daemon.Paths, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("invite <name>")
	}
	invitee := args[0]
	if err := nodename.Validate(invitee); err != nil {
		return err
	}
	entries, err := config.LoadDirectory(p.ConfFile())
	if err != nil {
		return err
	}
	selfName, ok := entries.GetFirst("Name")
	if !ok {
		return fmt.Errorf("local node name not configured")
	}
	addr, _ := entries.GetFirst("Address")
	port := 51820
	if v, ok := entries.GetFirst("Port"); ok {
		fmt.Sscanf(v, "%d", &port)
	}

	edBytes, err := os.ReadFile(p.Ed25519Private())
	if err != nil {
		return err
	}
	edPriv, err := keys.ParseEd25519PrivatePEM(edBytes)
	if err != nil {
		return err
	}

	cookie, err := invite.NewCookie()
	if err != nil {
		return err
	}
	url := invite.BuildURL(addr, port, edPriv.Public(), cookie)

	if err := os.MkdirAll(p.InvitationsDir(), 0o700); err != nil {
		return err
	}
	file := invite.File{
		Netname: p.Netname,
		Invitee: invite.Block{
			Name:      invitee,
			ConnectTo: []string{selfName},
		},
	}
	selfHost, _ := os.ReadFile(p.HostFile(selfName))
	hostBlock := invite.Block{Name: selfName, Address: addr}
	if len(selfHost) > 0 {
		es, _ := config.Parse(strings.NewReader(string(selfHost)))
		for _, e := range es {
			hostBlock.Other = append(hostBlock.Other, e)
		}
	}
	file.Hosts = append(file.Hosts, hostBlock)

	out := file.Render()
	invPath := filepath.Join(p.InvitationsDir(), cookie)
	if err := os.WriteFile(invPath, []byte(out), 0o600); err != nil {
		return err
	}
	fmt.Println(url.String())
	return nil
}

func cmdJoin(p daemon.Paths, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("join <url>")
	}
	u, err := invite.ParseURL(args[0])
	if err != nil {
		return err
	}
	addr := fmt.Sprintf("%s:%d", u.Host, u.Port)

	// Generate our keypairs first; the inviter will store the public halves
	// in hosts/<our-name>.
	edPriv, err := keys.GenerateEd25519()
	if err != nil {
		return err
	}
	wgPriv, err := keys.GenerateWireGuard()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Step 1: fetch the invitation file (verifies cookie exists, gives us
	// the proposed Name from the first block).
	body, err := transport.InviteGet(ctx, addr, u.Cookie, u.KeyHash)
	if err != nil {
		return fmt.Errorf("invite get: %w", err)
	}
	file, err := invite.ParseFile(strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("parse invitation: %w", err)
	}

	// Verify inviter's keyhash matches the URL.
	if len(file.Hosts) == 0 {
		return fmt.Errorf("invitation has no inviter host block")
	}
	inviter := file.Hosts[0]
	pubStr := ""
	for _, e := range inviter.Other {
		if strings.EqualFold(e.Key, "Ed25519PublicKey") {
			pubStr = strings.TrimSpace(e.Value)
			break
		}
	}
	if pubStr == "" {
		return fmt.Errorf("invitation: inviter has no Ed25519PublicKey")
	}
	inviterPub, err := keys.ParseEd25519PublicBase64(pubStr)
	if err != nil {
		return fmt.Errorf("parse inviter pubkey: %w", err)
	}
	if inviterPub.Hash() != u.KeyHash {
		return fmt.Errorf("invitation keyhash mismatch: URL=%s, file=%s", u.KeyHash, inviterPub.Hash())
	}

	// Step 2: send our public host config + the cookie to register ourselves.
	myHost := config.Entries{
		{Key: "Ed25519PublicKey", Value: edPriv.Public().String()},
		{Key: "WGPublicKey", Value: wgPriv.Public().String()},
	}.Render()
	if _, err := transport.InviteJoin(ctx, addr, u.Cookie, file.Invitee.Name, []byte(myHost), u.KeyHash); err != nil {
		return fmt.Errorf("invite join: %w", err)
	}

	// Step 3: write local config tree.
	netname := file.Netname
	if netname == "" {
		netname = p.Netname
	}
	finalPaths := daemon.Paths{ConfRoot: p.ConfRoot, Netname: netname}

	if err := os.MkdirAll(finalPaths.HostsDir(), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(finalPaths.InvitationsDir(), 0o700); err != nil {
		return err
	}

	edPEM, _ := edPriv.MarshalPEM()
	if err := os.WriteFile(finalPaths.Ed25519Private(), edPEM, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(finalPaths.WGPrivate(), []byte(wgPriv.String()+"\n"), 0o600); err != nil {
		return err
	}

	// gsnet.conf: Name + ConnectTo from the invitation.
	conf := config.Entries{{Key: "Name", Value: file.Invitee.Name}}
	for _, ct := range file.Invitee.ConnectTo {
		conf = append(conf, config.Entry{Key: "ConnectTo", Value: ct})
	}
	if err := os.WriteFile(finalPaths.ConfFile(), []byte(conf.Render()), 0o644); err != nil {
		return err
	}

	// hosts/<self> with our pubkey.
	if err := os.WriteFile(finalPaths.HostFile(file.Invitee.Name), []byte(myHost), 0o644); err != nil {
		return err
	}

	// hosts/<inviter> from the invitation's inviter block.
	inviterHost := config.Entries{}
	if inviter.Address != "" {
		inviterHost = append(inviterHost, config.Entry{Key: "Address", Value: inviter.Address})
	}
	inviterHost = append(inviterHost, inviter.Other...)
	if err := os.WriteFile(finalPaths.HostFile(inviter.Name), []byte(inviterHost.Render()), 0o644); err != nil {
		return err
	}

	fmt.Printf("joined network %q as %q via %s\n", netname, file.Invitee.Name, inviter.Name)
	return nil
}

func cmdDump(p daemon.Paths, runDir string, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("dump nodes|edges|subnets|connections|graph|invitations")
	}
	var req control.RequestType
	switch args[0] {
	case "nodes", "reachable":
		req = control.ReqDumpNodes
	case "edges":
		req = control.ReqDumpEdges
	case "subnets":
		req = control.ReqDumpSubnets
	case "connections":
		req = control.ReqDumpConnections
	case "graph":
		req = control.ReqDumpGraph
	case "invitations":
		req = control.ReqDumpInvitations
	default:
		return fmt.Errorf("unknown dump kind %q", args[0])
	}
	return runControlDump(p, runDir, req)
}

func cmdSimple(p daemon.Paths, runDir, name string, _ []string) error {
	var req control.RequestType
	switch name {
	case "stop":
		req = control.ReqStop
	case "reload":
		req = control.ReqReload
	case "retry":
		req = control.ReqRetry
	case "purge":
		req = control.ReqPurge
	case "pid":
		ctx := context.Background()
		_ = ctx
		pidPath := p.PIDFile(runDir)
		pidBytes, err := os.ReadFile(pidPath)
		if err != nil {
			return err
		}
		pf, err := control.ParsePIDFile(string(pidBytes))
		if err != nil {
			return err
		}
		fmt.Println(pf.PID)
		return nil
	default:
		return fmt.Errorf("internal: simple cmd %s", name)
	}
	cl, err := dialControl(p, runDir)
	if err != nil {
		return err
	}
	defer cl.Close()
	_, err = cl.Send(req)
	return err
}

func runControlDump(p daemon.Paths, runDir string, req control.RequestType) error {
	cl, err := dialControl(p, runDir)
	if err != nil {
		return err
	}
	defer cl.Close()
	first, err := cl.Send(req)
	if err != nil {
		return err
	}
	terminator := fmt.Sprintf("%d %d", control.ClassRequest, req)
	line := strings.TrimRight(first, "\r\n")
	for {
		if line == terminator {
			return nil
		}
		fmt.Println(line)
		next, err := cl.ReadLine()
		if err != nil {
			return err
		}
		line = strings.TrimRight(next, "\r\n")
	}
}

func dialControl(p daemon.Paths, runDir string) (*control.Client, error) {
	pidBytes, err := os.ReadFile(p.PIDFile(runDir))
	if err != nil {
		return nil, err
	}
	pf, err := control.ParsePIDFile(string(pidBytes))
	if err != nil {
		return nil, err
	}
	return control.Dial(p.ControlSocket(runDir), pf.Cookie)
}
