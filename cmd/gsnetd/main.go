// gsnetd is the gsnet VPN daemon.
//
// Usage:
//
//	gsnetd [-n NETNAME] [-c CONFDIR] [-r RUNDIR] [-l GOSSIPADDR] [-D] [--fake]
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/chun/gsnet/internal/daemon"
	"github.com/chun/gsnet/internal/dataplane"
	"github.com/chun/gsnet/internal/dataplane/fake"
	dplinux "github.com/chun/gsnet/internal/dataplane/linux"
)

func main() {
	var (
		netn    = flag.String("n", "", "network name")
		conf    = flag.String("c", "/etc/gsnet", "config root directory")
		runDir  = flag.String("r", "/run", "runtime directory")
		gAddr   = flag.String("l", ":51820", "gossip+invite TCP listen address")
		_       = flag.Bool("D", false, "do not detach (currently always true)")
		useFake = flag.Bool("fake", false, "use the in-memory dataplane reconciler")
	)
	flag.Parse()

	paths := daemon.Paths{ConfRoot: *conf, Netname: *netn}

	var rec dataplane.Reconciler
	if *useFake {
		rec = fake.New()
	} else {
		r, err := dplinux.New()
		if err != nil {
			log.Fatalf("dataplane init: %v", err)
		}
		rec = r
	}

	d := &daemon.Daemon{
		Paths:      paths,
		RunDir:     *runDir,
		Reconciler: rec,
		GossipAddr: *gAddr,
		Logger:     log.New(os.Stderr, "gsnetd: ", log.LstdFlags),
	}

	ctx, cancel := context.WithCancel(context.Background())
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		cancel()
	}()

	if err := d.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
