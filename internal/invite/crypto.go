package invite

// Encrypted invitation transport.
//
// Each invitation session establishes an ephemeral X25519 key pair on both
// sides, derives a 32-byte shared secret via ECDH, and uses HKDF-SHA256 with
// the cookie as salt to expand it into a ChaCha20-Poly1305 key. The inviter
// signs (server_eph_pub || cookie) with its long-term Ed25519 key so that
// the invitee can verify the keyhash from the invitation URL against the
// signing key — preventing MITM.
//
// Nonce: a fresh ephemeral key per session means a fixed all-zero nonce is
// safe — there is no key reuse across messages, so nonce uniqueness is
// trivially satisfied.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	x25519PubLen = 32
	hkdfInfo     = "gsnet-invite-v1"
)

// Ephemeral is one side's X25519 keypair for a single invitation session.
type Ephemeral struct {
	Pub  [x25519PubLen]byte
	priv [x25519PubLen]byte
}

// NewEphemeral generates a fresh X25519 keypair.
func NewEphemeral() (Ephemeral, error) {
	var e Ephemeral
	if _, err := rand.Read(e.priv[:]); err != nil {
		return Ephemeral{}, err
	}
	pub, err := curve25519.X25519(e.priv[:], curve25519.Basepoint)
	if err != nil {
		return Ephemeral{}, err
	}
	copy(e.Pub[:], pub)
	return e, nil
}

// DeriveKey computes the AEAD key from this side's private and the peer's pub.
func (e Ephemeral) DeriveKey(peerPub [x25519PubLen]byte, cookie string) ([]byte, error) {
	shared, err := curve25519.X25519(e.priv[:], peerPub[:])
	if err != nil {
		return nil, err
	}
	h := hkdf.New(sha256.New, shared, []byte(cookie), []byte(hkdfInfo))
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, key); err != nil {
		return nil, err
	}
	return key, nil
}

// Seal encrypts plaintext with key. The output is the raw AEAD ciphertext
// (no nonce prefix — a fixed zero nonce is implied; safe because the key is
// per-session).
func Seal(key, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	return aead.Seal(nil, nonce, plaintext, nil), nil
}

// Open decrypts a ciphertext produced by Seal.
func Open(key, ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	return aead.Open(nil, nonce, ciphertext, nil)
}

// EphemeralPubFromBase64 parses a base64-encoded X25519 public key.
func EphemeralPubFromBase64(s string) ([x25519PubLen]byte, error) {
	var out [x25519PubLen]byte
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return out, err
	}
	if len(b) != x25519PubLen {
		return out, fmt.Errorf("ephemeral pub: wrong length %d", len(b))
	}
	copy(out[:], b)
	return out, nil
}

// EphemeralPubToBase64 formats an X25519 public key for the wire.
func EphemeralPubToBase64(pub [x25519PubLen]byte) string {
	return base64.StdEncoding.EncodeToString(pub[:])
}
