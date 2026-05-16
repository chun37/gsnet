package daemon

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/chun/gsnet/internal/config"
	"github.com/chun/gsnet/internal/keys"
	"github.com/chun/gsnet/internal/nodename"
)

// Init creates the initial configuration tree for a node.
//
// Concretely it:
//   - Creates <NetDir>/{hosts,invitations} with mode 0700
//   - Generates Ed25519 (control plane) and WireGuard (data plane) keypairs
//   - Writes gsnet.conf with Name=<name>
//   - Writes hosts/<name> with the public Ed25519 PEM and WireGuard public key
func Init(p Paths, name string) error {
	if err := nodename.Validate(name); err != nil {
		return err
	}
	if err := os.MkdirAll(p.HostsDir(), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(p.InvitationsDir(), 0o700); err != nil {
		return err
	}

	edPriv, err := keys.GenerateEd25519()
	if err != nil {
		return err
	}
	edPEM, err := edPriv.MarshalPEM()
	if err != nil {
		return err
	}
	if err := writeFileExclusive(p.Ed25519Private(), edPEM, 0o600); err != nil {
		return err
	}

	wgPriv, err := keys.GenerateWireGuard()
	if err != nil {
		return err
	}
	if err := writeFileExclusive(p.WGPrivate(), []byte(wgPriv.String()+"\n"), 0o600); err != nil {
		return err
	}

	conf := config.Entries{{Key: "Name", Value: name}}.Render()
	if err := writeFileExclusive(p.ConfFile(), []byte(conf), 0o644); err != nil {
		return err
	}

	hostEntries := config.Entries{
		{Key: "Ed25519PublicKey", Value: edPriv.Public().String()},
		{Key: "WGPublicKey", Value: wgPriv.Public().String()},
	}.Render()
	if err := writeFileExclusive(p.HostFile(name), []byte(hostEntries), 0o644); err != nil {
		return err
	}
	return nil
}

func writeFileExclusive(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	return nil
}
