// Package daemon glues together config, gossip, dataplane, and scripts into
// a single gsnet daemon process.
package daemon

import (
	"path/filepath"
)

// Paths bundles the canonical filesystem layout for a netname.
// All paths are derived from a single (ConfRoot, Netname) pair so we have a
// single source of truth for "where does X live".
//
//	<ConfRoot>/                       (e.g. /etc/gsnet)
//	  <Netname>/
//	    gsnet.conf                    primary config
//	    conf.d/                       optional fragments
//	    hosts/<Name>                  per-peer host config
//	    invitations/                  outstanding invitations
//	    tinc-up, tinc-down, ...       hook scripts
//	    ed25519_key.priv              control-plane private key
//	    wg.priv                       data-plane private key
type Paths struct {
	ConfRoot string
	Netname  string
}

func (p Paths) NetDir() string {
	if p.Netname == "" {
		return p.ConfRoot
	}
	return filepath.Join(p.ConfRoot, p.Netname)
}
func (p Paths) ConfFile() string       { return filepath.Join(p.NetDir(), "gsnet.conf") }
func (p Paths) HostsDir() string       { return filepath.Join(p.NetDir(), "hosts") }
func (p Paths) HostFile(name string) string {
	return filepath.Join(p.HostsDir(), name)
}
func (p Paths) InvitationsDir() string { return filepath.Join(p.NetDir(), "invitations") }
func (p Paths) Ed25519Private() string { return filepath.Join(p.NetDir(), "ed25519_key.priv") }
func (p Paths) WGPrivate() string      { return filepath.Join(p.NetDir(), "wg.priv") }

// PIDFile is the runtime PID/cookie file.
func (p Paths) PIDFile(runDir string) string {
	if p.Netname == "" {
		return filepath.Join(runDir, "gsnet.pid")
	}
	return filepath.Join(runDir, "gsnet."+p.Netname+".pid")
}

// ControlSocket is the runtime UNIX control socket.
func (p Paths) ControlSocket(runDir string) string {
	if p.Netname == "" {
		return filepath.Join(runDir, "gsnet.socket")
	}
	return filepath.Join(runDir, "gsnet."+p.Netname+".socket")
}
