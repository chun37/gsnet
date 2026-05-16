package invite

import (
	"bytes"
	"testing"
)

func TestEphemeral_ECDH_AgreesOnKey(t *testing.T) {
	a, err := NewEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewEphemeral()
	if err != nil {
		t.Fatal(err)
	}
	kA, err := a.DeriveKey(b.Pub, "cookie")
	if err != nil {
		t.Fatal(err)
	}
	kB, err := b.DeriveKey(a.Pub, "cookie")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(kA, kB) {
		t.Errorf("derived keys differ")
	}
}

func TestEphemeral_DifferentCookieDifferentKey(t *testing.T) {
	a, _ := NewEphemeral()
	b, _ := NewEphemeral()
	k1, _ := a.DeriveKey(b.Pub, "cookie1")
	k2, _ := a.DeriveKey(b.Pub, "cookie2")
	if bytes.Equal(k1, k2) {
		t.Errorf("different cookies produced identical keys")
	}
}

func TestSeal_Open_Roundtrip(t *testing.T) {
	a, _ := NewEphemeral()
	b, _ := NewEphemeral()
	key, _ := a.DeriveKey(b.Pub, "abc")
	pt := []byte("hello invitation contents")
	ct, err := Seal(key, pt)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(key, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Errorf("round-trip mismatch")
	}
}

func TestOpen_RejectsWrongKey(t *testing.T) {
	a, _ := NewEphemeral()
	b, _ := NewEphemeral()
	c, _ := NewEphemeral()
	key, _ := a.DeriveKey(b.Pub, "abc")
	wrong, _ := a.DeriveKey(c.Pub, "abc")
	ct, _ := Seal(key, []byte("secret"))
	if _, err := Open(wrong, ct); err == nil {
		t.Errorf("Open with wrong key succeeded")
	}
}

func TestPubBase64_Roundtrip(t *testing.T) {
	a, _ := NewEphemeral()
	encoded := EphemeralPubToBase64(a.Pub)
	decoded, err := EphemeralPubFromBase64(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != a.Pub {
		t.Errorf("pub round-trip differs")
	}
}
