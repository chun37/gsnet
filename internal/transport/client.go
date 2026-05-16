package transport

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/chun/gsnet/internal/config"
	"github.com/chun/gsnet/internal/invite"
	"github.com/chun/gsnet/internal/keys"
)

// InviteGet fetches an invitation file from the inviter's TCP endpoint and
// verifies the inviter's identity. expectedKeyHash is the keyhash from the
// invitation URL; if non-empty, the response is rejected unless the inviter's
// Ed25519 public key (embedded in the invitation file) hashes to it AND signs
// the ephemeral handshake.
func InviteGet(ctx context.Context, addr, cookie, expectedKeyHash string) ([]byte, error) {
	eph, err := invite.NewEphemeral()
	if err != nil {
		return nil, err
	}
	cmd := fmt.Sprintf("INVITE2 GET %s %s\n", cookie, invite.EphemeralPubToBase64(eph.Pub))
	return roundtrip(ctx, addr, cmd, eph, cookie, expectedKeyHash)
}

// InviteJoin sends the invitee's public host config (plaintext, base64) and
// returns the decrypted invitation file body.
func InviteJoin(ctx context.Context, addr, cookie, inviteeName string, hostConfig []byte, expectedKeyHash string) ([]byte, error) {
	eph, err := invite.NewEphemeral()
	if err != nil {
		return nil, err
	}
	cmd := fmt.Sprintf("INVITE2 JOIN %s %s %s\n%s\n",
		cookie, inviteeName, invite.EphemeralPubToBase64(eph.Pub),
		base64.StdEncoding.EncodeToString(hostConfig),
	)
	return roundtrip(ctx, addr, cmd, eph, cookie, expectedKeyHash)
}

func roundtrip(ctx context.Context, addr, command string, eph invite.Ephemeral, cookie, expectedKeyHash string) ([]byte, error) {
	d := net.Dialer{Timeout: 10 * time.Second}
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer nc.Close()
	deadline, hasDeadline := ctx.Deadline()
	if !hasDeadline {
		deadline = time.Now().Add(15 * time.Second)
	}
	_ = nc.SetDeadline(deadline)

	if _, err := io.WriteString(nc, command); err != nil {
		return nil, err
	}

	r := bufio.NewReader(nc)
	statusLine, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	statusLine = strings.TrimRight(statusLine, "\r\n")
	if !strings.HasPrefix(statusLine, "OK ") {
		return nil, fmt.Errorf("invite: server replied %q", statusLine)
	}
	return parseEncryptedReply(r, eph, cookie, expectedKeyHash, statusLine)
}

// parseEncryptedReply consumes "OK <server_pub> <sig>\n<ciphertext>\n" given
// that the OK line has already been read into statusLine.
func parseEncryptedReply(r *bufio.Reader, eph invite.Ephemeral, cookie, expectedKeyHash, statusLine string) ([]byte, error) {
	parts := strings.Fields(strings.TrimPrefix(statusLine, "OK "))
	if len(parts) != 2 {
		return nil, fmt.Errorf("invite: malformed OK %q", statusLine)
	}
	serverPub, err := invite.EphemeralPubFromBase64(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invite: bad server pub: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invite: bad sig b64: %w", err)
	}
	ctLine, err := r.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read ct: %w", err)
	}
	ct, err := base64.StdEncoding.DecodeString(strings.TrimRight(ctLine, "\r\n"))
	if err != nil {
		return nil, fmt.Errorf("invite: bad ct b64: %w", err)
	}
	key, err := eph.DeriveKey(serverPub, cookie)
	if err != nil {
		return nil, err
	}
	pt, err := invite.Open(key, ct)
	if err != nil {
		return nil, fmt.Errorf("invite: decrypt failed (wrong cookie, MITM, or server impersonation)")
	}

	// The decrypted plaintext is an invitation file containing the inviter's
	// long-term Ed25519 public key. We verify:
	//   (a) hash(inviter_pub) == expectedKeyHash from the URL
	//   (b) Ed25519(inviter_pub, sig_payload, sig) is valid
	inviterPub, found := findInviterEd25519Pub(pt)
	if !found {
		return nil, fmt.Errorf("invite: server response missing Ed25519PublicKey")
	}
	if expectedKeyHash != "" && inviterPub.Hash() != expectedKeyHash {
		return nil, fmt.Errorf("invite: keyhash mismatch (URL=%s, server=%s)", expectedKeyHash, inviterPub.Hash())
	}
	if !inviterPub.Verify(sigPayload(serverPub, cookie), sig) {
		return nil, fmt.Errorf("invite: signature verification failed")
	}
	return pt, nil
}

// findInviterEd25519Pub locates the inviter's Ed25519PublicKey by parsing the
// invitation file. The first Hosts block is the inviter (block 0 is the
// invitee, parsed separately into File.Invitee).
func findInviterEd25519Pub(file []byte) (keys.Ed25519Public, bool) {
	f, err := invite.ParseFile(bytes.NewReader(file))
	if err != nil || len(f.Hosts) == 0 {
		return keys.Ed25519Public{}, false
	}
	pubStr, ok := config.Entries(f.Hosts[0].Other).GetFirst("Ed25519PublicKey")
	if !ok {
		return keys.Ed25519Public{}, false
	}
	pub, err := keys.ParseEd25519PublicBase64(strings.TrimSpace(pubStr))
	if err != nil {
		return keys.Ed25519Public{}, false
	}
	return pub, true
}
