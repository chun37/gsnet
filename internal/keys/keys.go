// Package keys manages cryptographic key material for gsnet.
//
// Two distinct keypair kinds are used:
//
//   - Ed25519: control-plane node identity. Used to sign gossip messages,
//     authenticate invitation exchanges, and as the "fingerprint" published in
//     invitation URLs (keyhash).
//   - Curve25519 (WireGuard): data-plane peer key. Used by WireGuard for
//     authenticated encryption and key exchange between peers.
//
// Both keys are generated independently. The Ed25519 public key is the
// authoritative node identifier; the WG public key is exchanged out-of-band
// (via the gossip plane, signed by Ed25519) so peers can configure their
// WireGuard interfaces.
package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Ed25519Private wraps a private Ed25519 key.
type Ed25519Private struct {
	raw ed25519.PrivateKey
}

// Ed25519Public wraps a public Ed25519 key.
type Ed25519Public struct {
	raw ed25519.PublicKey
}

func GenerateEd25519() (Ed25519Private, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Ed25519Private{}, fmt.Errorf("generate ed25519: %w", err)
	}
	return Ed25519Private{raw: priv}, nil
}

func (p Ed25519Private) Public() Ed25519Public {
	return Ed25519Public{raw: p.raw.Public().(ed25519.PublicKey)}
}

func (p Ed25519Private) Sign(msg []byte) []byte {
	return ed25519.Sign(p.raw, msg)
}

func (p Ed25519Private) MarshalPEM() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(p.raw)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func ParseEd25519PrivatePEM(b []byte) (Ed25519Private, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return Ed25519Private{}, fmt.Errorf("no PEM block")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return Ed25519Private{}, err
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return Ed25519Private{}, fmt.Errorf("not an ed25519 key")
	}
	return Ed25519Private{raw: priv}, nil
}

func (p Ed25519Public) Verify(msg, sig []byte) bool {
	if len(p.raw) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(p.raw, msg, sig)
}

func (p Ed25519Public) MarshalPEM() ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(p.raw)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

func ParseEd25519PublicPEM(b []byte) (Ed25519Public, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return Ed25519Public{}, fmt.Errorf("no PEM block")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return Ed25519Public{}, err
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return Ed25519Public{}, fmt.Errorf("not an ed25519 key")
	}
	return Ed25519Public{raw: pub}, nil
}

// Hash returns the URL-safe base64-encoded SHA-256 of the public key.
// Used as the "keyhash" in invitation URLs.
func (p Ed25519Public) Hash() string {
	h := sha256.Sum256(p.raw)
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func (p Ed25519Public) Raw() []byte {
	return append([]byte(nil), p.raw...)
}

// String returns the standard-base64-encoded raw public key, suitable for
// single-line representation in host config files.
func (p Ed25519Public) String() string {
	return base64.StdEncoding.EncodeToString(p.raw)
}

// ParseEd25519PublicBase64 reverses String().
func ParseEd25519PublicBase64(s string) (Ed25519Public, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return Ed25519Public{}, err
	}
	if len(b) != ed25519.PublicKeySize {
		return Ed25519Public{}, fmt.Errorf("ed25519 public key: wrong length %d", len(b))
	}
	return Ed25519Public{raw: ed25519.PublicKey(b)}, nil
}

// ParseEd25519PublicBase64ish accepts either the raw-byte form (gossip Hello
// embeds 32 raw bytes) or a base64 string representation.
func ParseEd25519PublicBase64ish(b []byte) (Ed25519Public, error) {
	if len(b) == ed25519.PublicKeySize {
		return Ed25519Public{raw: ed25519.PublicKey(append([]byte(nil), b...))}, nil
	}
	return ParseEd25519PublicBase64(string(b))
}

// WGPrivate wraps a WireGuard private key.
type WGPrivate struct {
	raw wgtypes.Key
}

// WGPublic wraps a WireGuard public key.
type WGPublic struct {
	raw wgtypes.Key
}

func GenerateWireGuard() (WGPrivate, error) {
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return WGPrivate{}, err
	}
	return WGPrivate{raw: k}, nil
}

func (p WGPrivate) Public() WGPublic { return WGPublic{raw: p.raw.PublicKey()} }
func (p WGPrivate) WGKey() wgtypes.Key { return p.raw }
func (p WGPrivate) String() string     { return p.raw.String() }

func (p WGPublic) WGKey() wgtypes.Key { return p.raw }
func (p WGPublic) String() string     { return p.raw.String() }

func ParseWireGuardPrivate(s string) (WGPrivate, error) {
	k, err := wgtypes.ParseKey(s)
	if err != nil {
		return WGPrivate{}, err
	}
	return WGPrivate{raw: k}, nil
}

func ParseWireGuardPublic(s string) (WGPublic, error) {
	k, err := wgtypes.ParseKey(s)
	if err != nil {
		return WGPublic{}, err
	}
	return WGPublic{raw: k}, nil
}
