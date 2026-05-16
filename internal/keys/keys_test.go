package keys

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
)

func TestGenerateEd25519_Roundtrip(t *testing.T) {
	priv, err := GenerateEd25519()
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public()
	if got := len(pub.Raw()); got != ed25519.PublicKeySize {
		t.Fatalf("public key length = %d, want %d", got, ed25519.PublicKeySize)
	}

	msg := []byte("hello gsnet")
	sig := priv.Sign(msg)
	if !pub.Verify(msg, sig) {
		t.Errorf("Verify(correct sig) = false, want true")
	}
	if pub.Verify([]byte("tampered"), sig) {
		t.Errorf("Verify(wrong msg) = true, want false")
	}
}

func TestEd25519_PEM_Roundtrip(t *testing.T) {
	priv, _ := GenerateEd25519()
	pemBytes, err := priv.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(pemBytes), "PRIVATE KEY") {
		t.Errorf("PEM does not contain PRIVATE KEY block: %s", pemBytes)
	}

	parsed, err := ParseEd25519PrivatePEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed.raw, priv.raw) {
		t.Errorf("parsed private key differs from original")
	}
}

func TestEd25519PublicKey_PEM_Roundtrip(t *testing.T) {
	priv, _ := GenerateEd25519()
	pub := priv.Public()
	pemBytes, err := pub.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseEd25519PublicPEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed.raw, pub.raw) {
		t.Errorf("parsed public key differs")
	}
}

func TestEd25519PublicKey_Hash_Deterministic(t *testing.T) {
	priv, _ := GenerateEd25519()
	pub := priv.Public()
	h1 := pub.Hash()
	h2 := pub.Hash()
	if h1 != h2 {
		t.Errorf("Hash not deterministic: %s vs %s", h1, h2)
	}
	if len(h1) == 0 {
		t.Errorf("Hash is empty")
	}
}

func TestEd25519PublicKey_Hash_Distinguishes(t *testing.T) {
	a, _ := GenerateEd25519()
	b, _ := GenerateEd25519()
	if a.Public().Hash() == b.Public().Hash() {
		t.Errorf("two random keys hash to same value")
	}
}

func TestGenerateWireGuard_Roundtrip(t *testing.T) {
	priv, err := GenerateWireGuard()
	if err != nil {
		t.Fatal(err)
	}
	if priv.WGKey().PublicKey() != priv.Public().WGKey() {
		t.Errorf("WG public key derivation inconsistent")
	}
	s := priv.String()
	parsed, err := ParseWireGuardPrivate(s)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.String() != s {
		t.Errorf("WG private round-trip differs: %q vs %q", parsed.String(), s)
	}
}
