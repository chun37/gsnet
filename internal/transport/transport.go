// Package transport is the TCP-based control-plane transport for gsnet.
//
// One TCP listener carries two distinct protocols, demultiplexed by the first
// line of each connection:
//
//   GOSSIP\n         — line-delimited JSON gossip envelopes both ways
//   INVITE GET <cookie>\n  — fetch the invitation file for <cookie>
//   INVITE JOIN <cookie> <inviteeName>\n<host-config-body>
//                     — register the invitee's host config and receive the
//                       invitation file (the inviter creates hosts/<inviteeName>
//                       from the body).
//
// All bytes are UTF-8. Lines are terminated by '\n'.
//
// Authentication of gossip is end-to-end via Envelope.Signature, set and
// checked by package gossip. The transport itself is unauthenticated TCP;
// invalid envelopes are dropped by the receiving Plane.
//
// Invitation cookies are the only auth on INVITE.
package transport

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/chun/gsnet/internal/gossip"
	"github.com/chun/gsnet/internal/invite"
	"github.com/chun/gsnet/internal/keys"
)

// Server is a TCP transport instance.
type Server struct {
	// Addr is the listen address (e.g. ":51820" or "0.0.0.0:51820").
	Addr string

	// EdPriv is the inviter's long-term signing key. Used by INVITE2 to sign
	// the ephemeral pubkey returned to the client, proving that the keyhash
	// from the URL matches this server. Required for the invite endpoints to
	// function.
	EdPriv keys.Ed25519Private

	// OnGossip is called for each inbound envelope.
	OnGossip func(env gossip.Envelope)

	// InviteGet returns the invitation file for the given cookie, or an error.
	InviteGet func(cookie string) ([]byte, error)

	// InviteJoin records the invitee's host-config body and returns the
	// invitation file to send back. The body is decrypted plaintext.
	InviteJoin func(cookie, inviteeName string, hostConfig []byte) ([]byte, error)

	listener net.Listener

	mu    sync.Mutex
	conns map[*conn]struct{}
	wg    sync.WaitGroup

	logf func(format string, args ...any)
}

type conn struct {
	netConn      net.Conn
	w            *bufio.Writer
	mu           sync.Mutex // serializes writes
	outboundAddr string     // non-empty for connections we initiated; used for dedup
}

// Start binds the listener. It does not block; call Serve to accept.
func (s *Server) Start() error {
	l, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	s.listener = l
	s.conns = make(map[*conn]struct{})
	if s.logf == nil {
		s.logf = func(string, ...any) {}
	}
	return nil
}

// LocalAddr returns the bound address (useful for ":0").
func (s *Server) LocalAddr() net.Addr {
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// Serve accepts inbound connections until ctx is canceled or the listener errors.
func (s *Server) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		_ = s.listener.Close()
		s.closeAll()
	}()
	for {
		nc, err := s.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				s.wg.Wait()
				return nil
			}
			return err
		}
		c := &conn{netConn: nc, w: bufio.NewWriter(nc)}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer nc.Close()
			// Connections are only added to the gossip broadcast pool after
			// they identify as GOSSIP, so invite-only connections don't
			// receive stray envelopes that would corrupt their reply stream.
			if err := s.handleInbound(ctx, c); err != nil && !errors.Is(err, io.EOF) && ctx.Err() == nil {
				s.logf("inbound: %v", err)
			}
			s.untrack(c)
		}()
	}
}

func (s *Server) track(c *conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conns[c] = struct{}{}
}

func (s *Server) untrack(c *conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, c)
}

func (s *Server) closeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.conns {
		_ = c.netConn.Close()
	}
}

// SetLogger installs a logging function (defaults to a no-op).
func (s *Server) SetLogger(logf func(string, ...any)) { s.logf = logf }

func (s *Server) handleInbound(ctx context.Context, c *conn) error {
	r := bufio.NewReader(c.netConn)
	first, err := r.ReadString('\n')
	if err != nil {
		return err
	}
	line := strings.TrimRight(first, "\r\n")
	switch {
	case line == "GOSSIP":
		s.track(c)
		return s.handleGossip(ctx, c, r)
	case strings.HasPrefix(line, "INVITE2 GET "):
		return s.handleInvite2Get(c, strings.TrimPrefix(line, "INVITE2 GET "))
	case strings.HasPrefix(line, "INVITE2 JOIN "):
		return s.handleInvite2Join(c, r, strings.TrimPrefix(line, "INVITE2 JOIN "))
	default:
		return fmt.Errorf("transport: unknown command line %q", line)
	}
}

func (s *Server) handleGossip(ctx context.Context, c *conn, r *bufio.Reader) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line, err := r.ReadBytes('\n')
		if err != nil {
			return err
		}
		var env gossip.Envelope
		if err := json.Unmarshal(line, &env); err != nil {
			s.logf("gossip: bad envelope: %v", err)
			continue
		}
		if s.OnGossip != nil {
			s.OnGossip(env)
		}
	}
}

// handleInvite2Get implements the ECDH-encrypted invitation fetch.
// Wire format:
//   client → server : INVITE2 GET <cookie> <client_eph_pub_b64>\n
//   server → client : OK <server_eph_pub_b64> <sig_b64>\n<ciphertext_b64>\n
// where sig = Ed25519(server_eph_pub || cookie).
func (s *Server) handleInvite2Get(c *conn, rest string) error {
	parts := strings.Fields(rest)
	if len(parts) != 2 {
		return s.writeAndClose(c, "ERR malformed GET\n")
	}
	cookie, clientPubB64 := parts[0], parts[1]
	if s.InviteGet == nil {
		return s.writeAndClose(c, "ERR invite not enabled\n")
	}
	clientPub, err := invite.EphemeralPubFromBase64(clientPubB64)
	if err != nil {
		return s.errReply(c, err)
	}
	body, err := s.InviteGet(cookie)
	if err != nil {
		return s.errReply(c, err)
	}
	return s.encryptAndReply(c, cookie, clientPub, body)
}

// handleInvite2Join handles JOIN. The body the invitee sends contains only
// their just-generated public keys, so it travels in plaintext (base64). The
// response (the invitation file) is encrypted with the ECDH-derived key.
// Wire format:
//   client → server : INVITE2 JOIN <cookie> <inviteeName> <client_eph_pub_b64>\n
//                     <plaintext_host_config_b64>\n
//   server → client : OK <server_eph_pub_b64> <sig_b64>\n<encrypted_invitation_b64>\n
func (s *Server) handleInvite2Join(c *conn, r *bufio.Reader, rest string) error {
	parts := strings.Fields(rest)
	if len(parts) != 3 {
		return s.writeAndClose(c, "ERR malformed JOIN\n")
	}
	cookie, inviteeName, clientPubB64 := parts[0], parts[1], parts[2]
	if s.InviteJoin == nil {
		return s.writeAndClose(c, "ERR invite not enabled\n")
	}
	clientPub, err := invite.EphemeralPubFromBase64(clientPubB64)
	if err != nil {
		return s.errReply(c, err)
	}
	bodyLine, err := r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}
	hostConfig, err := base64.StdEncoding.DecodeString(strings.TrimRight(bodyLine, "\r\n"))
	if err != nil {
		return s.writeAndClose(c, fmt.Sprintf("ERR base64: %s\n", err))
	}
	body, err := s.InviteJoin(cookie, inviteeName, hostConfig)
	if err != nil {
		return s.errReply(c, err)
	}
	return s.encryptAndReply(c, cookie, clientPub, body)
}

func (s *Server) encryptAndReply(c *conn, cookie string, clientPub [32]byte, plaintext []byte) error {
	server, err := invite.NewEphemeral()
	if err != nil {
		return s.errReply(c, err)
	}
	key, err := server.DeriveKey(clientPub, cookie)
	if err != nil {
		return s.errReply(c, err)
	}
	ct, err := invite.Seal(key, plaintext)
	if err != nil {
		return s.errReply(c, err)
	}
	sig := s.EdPriv.Sign(sigPayload(server.Pub, cookie))
	reply := fmt.Sprintf("OK %s %s\n%s\n",
		invite.EphemeralPubToBase64(server.Pub),
		base64.StdEncoding.EncodeToString(sig),
		base64.StdEncoding.EncodeToString(ct),
	)
	return s.writeAndClose(c, reply)
}

// sigPayload is the byte string the inviter signs and the invitee verifies.
// Layout: "gsnet-invite-v1" || server_eph_pub (32B) || cookie.
func sigPayload(serverPub [32]byte, cookie string) []byte {
	out := make([]byte, 0, 32+len(cookie)+16)
	out = append(out, "gsnet-invite-v1"...)
	out = append(out, 0)
	out = append(out, serverPub[:]...)
	out = append(out, 0)
	out = append(out, cookie...)
	return out
}

func (s *Server) writeAndClose(c *conn, msg string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := io.WriteString(c.w, msg)
	if err != nil {
		return err
	}
	return c.w.Flush()
}

func (s *Server) errReply(c *conn, err error) error {
	return s.writeAndClose(c, "ERR "+err.Error()+"\n")
}

// Broadcast writes env to every currently-connected gossip peer.
// Connections that fail are dropped silently.
func (s *Server) Broadcast(env gossip.Envelope) error {
	data, err := json.Marshal(env)
	if err != nil {
		return err
	}
	line := append(data, '\n')

	s.mu.Lock()
	conns := make([]*conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()

	for _, c := range conns {
		c.mu.Lock()
		_, werr := c.w.Write(line)
		if werr == nil {
			werr = c.w.Flush()
		}
		c.mu.Unlock()
		if werr != nil {
			_ = c.netConn.Close()
		}
	}
	return nil
}

// Send is provided to satisfy gossip.Transport. The TCP transport currently
// has no peer→conn mapping (a conn knows its outbound dial address, not the
// remote node's logical name), so Send falls back to Broadcast. Per-peer
// targeted delivery would need a peer registration handshake; for now the
// extra fan-out is harmless because envelopes are signed and idempotent.
func (s *Server) Send(_ string, env gossip.Envelope) error { return s.Broadcast(env) }

// Dial opens an outbound gossip connection to addr (host:port) and registers
// it with the server so subsequent Broadcasts include it. If an outbound
// connection to addr already exists and is live, Dial is a no-op — this
// prevents `maintainPeer` from accumulating duplicate connections on each
// retry tick.
func (s *Server) Dial(ctx context.Context, addr string) error {
	if s.hasOutbound(addr) {
		return nil
	}
	d := net.Dialer{Timeout: 10 * time.Second}
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(nc, "GOSSIP\n"); err != nil {
		_ = nc.Close()
		return err
	}
	c := &conn{netConn: nc, w: bufio.NewWriter(nc), outboundAddr: addr}
	s.track(c)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer s.untrack(c)
		defer nc.Close()
		r := bufio.NewReader(nc)
		for {
			if ctx.Err() != nil {
				return
			}
			line, err := r.ReadBytes('\n')
			if err != nil {
				return
			}
			var env gossip.Envelope
			if err := json.Unmarshal(line, &env); err != nil {
				continue
			}
			if s.OnGossip != nil {
				s.OnGossip(env)
			}
		}
	}()
	return nil
}

func (s *Server) hasOutbound(addr string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.conns {
		if c.outboundAddr == addr {
			return true
		}
	}
	return false
}

// Close stops the listener and waits for active connections to drain.
func (s *Server) Close() error {
	if s.listener != nil {
		_ = s.listener.Close()
	}
	s.closeAll()
	s.wg.Wait()
	return nil
}
